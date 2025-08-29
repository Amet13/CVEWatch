package nvd

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"cvewatch/internal/config"
	"cvewatch/internal/types"
)

// NVDClient handles communication with the NVD API
type NVDClient struct {
	httpClient *http.Client
	config     *types.AppConfig
	configMgr  *config.ConfigManager
	apiKey     string
}

// NewNVDClient creates a new NVD client
func NewNVDClient(config *types.AppConfig, configMgr *config.ConfigManager, apiKey string) *NVDClient {
	timeout := time.Duration(config.NVD.Timeout) * time.Second

	return &NVDClient{
		httpClient: &http.Client{
			Timeout: timeout,
		},
		config:    config,
		configMgr: configMgr,
		apiKey:    apiKey,
	}
}

// SearchCVEs searches for CVEs based on the given criteria
func (n *NVDClient) SearchCVEs(request *types.SearchRequest) (*types.SearchResult, error) {
	startTime := time.Now()
	
	searchURL := n.buildSearchURL(request)
	
	resp, err := n.executeSearchRequest(searchURL)
	if err != nil {
		return nil, err
	}
	defer n.closeResponseBody(resp)
	
	nvdResp, err := n.parseResponse(resp)
	if err != nil {
		return nil, err
	}
	
	filteredCVEs := n.filterCVEsByProducts(nvdResp.Vulnerabilities, request)
	queryTime := time.Since(startTime).String()
	
	return n.buildSearchResult(filteredCVEs, request, queryTime), nil
}

// buildSearchURL constructs the search URL with query parameters
func (n *NVDClient) buildSearchURL(request *types.SearchRequest) string {
	params := url.Values{}
	
	if request.Date != "" {
		startDate := request.Date + "T00:00:00.000Z"
		endDate := request.Date + "T23:59:59.999Z"
		params.Set("pubStartDate", startDate)
		params.Set("pubEndDate", endDate)
	}
	
	params.Set("resultsPerPage", strconv.Itoa(request.MaxResults))
	
	if n.apiKey != "" {
		params.Set("apiKey", n.apiKey)
	}
	
	return n.config.NVD.BaseURL + "?" + params.Encode()
}

// executeSearchRequest executes the HTTP request with retry logic
func (n *NVDClient) executeSearchRequest(searchURL string) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(n.config.NVD.Timeout)*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	n.setRequestHeaders(req)
	
	return n.executeWithRetry(req)
}

// setRequestHeaders sets the required headers for the request
func (n *NVDClient) setRequestHeaders(req *http.Request) {
	req.Header.Set("User-Agent", n.config.Security.UserAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	for key, value := range n.config.Security.RequestHeaders {
		req.Header.Set(key, value)
	}
}

// executeWithRetry executes the request with retry logic
func (n *NVDClient) executeWithRetry(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	
	for attempt := 1; attempt <= n.config.NVD.RetryAttempts; attempt++ {
		resp, err = n.httpClient.Do(req)
		if err == nil {
			break
		}
		
		if attempt < n.config.NVD.RetryAttempts {
			time.Sleep(time.Duration(n.config.NVD.RetryDelay) * time.Second)
			
			continue
		}
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CVE data after %d attempts: %w", n.config.NVD.RetryAttempts, err)
	}
	
	return resp, nil
}

// closeResponseBody safely closes the response body
func (n *NVDClient) closeResponseBody(resp *http.Response) {
	if err := resp.Body.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", err)
	}
}

// parseResponse parses the HTTP response into an NVD response
func (n *NVDClient) parseResponse(resp *http.Response) (*types.NVDResponse, error) {
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status %d: %s", resp.StatusCode, resp.Status)
	}
	
	reader := n.getResponseReader(resp)
	
	var nvdResp types.NVDResponse
	if err := json.NewDecoder(reader).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %w", err)
	}
	
	return &nvdResp, nil
}

// getResponseReader returns an appropriate reader for the response
func (n *NVDClient) getResponseReader(resp *http.Response) io.Reader {
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			// Fallback to regular body if gzip fails
			return resp.Body
		}

		return gzReader
	}

	return resp.Body
}

// buildSearchResult constructs the final search result
func (n *NVDClient) buildSearchResult(filteredCVEs []types.CVE, request *types.SearchRequest, queryTime string) *types.SearchResult {
	return &types.SearchResult{
		CVEs:       filteredCVEs,
		TotalFound: len(filteredCVEs),
		Date:       request.Date,
		MinCVSS:    request.MinCVSS,
		MaxCVSS:    request.MaxCVSS,
		Products:   request.Products,
		QueryTime:  queryTime,
	}
}

// filterCVEsByProducts filters CVEs based on product keywords and CVSS scores
func (n *NVDClient) filterCVEsByProducts(vulnerabilities []types.Vulnerability, request *types.SearchRequest) []types.CVE {
	filteredCVEs := make([]types.CVE, 0, len(vulnerabilities))

	for _, vuln := range vulnerabilities {
		cve := vuln.CVE

		// Check CVSS score
		if !n.matchesCVSSRange(cve, request) {
			continue
		}

		// Check if CVE matches any product
		if !n.matchesProduct(cve, request.Products) {
			continue
		}

		filteredCVEs = append(filteredCVEs, cve)
	}

	return filteredCVEs
}

// matchesCVSSRange checks if a CVE's CVSS score falls within the specified range
func (n *NVDClient) matchesCVSSRange(cve types.CVE, request *types.SearchRequest) bool {
	// Get the highest CVSS score (prefer v3.1 over v2)
	var score float64

	switch {
	case len(cve.Metrics.CVSSMetricV31) > 0:
		score = cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
	case len(cve.Metrics.CVSSMetricV2) > 0:
		score = cve.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
	default:
		score = 0
	}

	// Check minimum CVSS
	if request.MinCVSS > 0 && score < request.MinCVSS {
		return false
	}

	// Check maximum CVSS
	if request.MaxCVSS > 0 && score > request.MaxCVSS {
		return false
	}

	return true
}

// matchesProduct checks if a CVE matches any of the specified products
func (n *NVDClient) matchesProduct(cve types.CVE, productNames []string) bool {
	description := n.getEnglishDescription(cve)
	if description == "" {
		return false
	}
	
	return n.matchesAnyProduct(cve, productNames, description)
}

// getEnglishDescription extracts the English description from a CVE
func (n *NVDClient) getEnglishDescription(cve types.CVE) string {
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			return strings.ToLower(desc.Value)
		}
	}

	return ""
}

// matchesAnyProduct checks if the CVE matches any of the specified products
func (n *NVDClient) matchesAnyProduct(cve types.CVE, productNames []string, description string) bool {
	for _, productName := range productNames {
		if n.matchesSingleProduct(cve, productName, description) {
			return true
		}
	}

	return false
}

// matchesSingleProduct checks if the CVE matches a specific product
func (n *NVDClient) matchesSingleProduct(cve types.CVE, productName, description string) bool {
	product := n.configMgr.GetProductByName(productName)
	if product == nil {
		return false
	}
	
	return n.matchesProductKeywords(product, description) || 
		   n.matchesProductCPEPatterns(cve, product)
}

// matchesProductKeywords checks if the description matches any product keywords
func (n *NVDClient) matchesProductKeywords(product *types.Product, description string) bool {
	for _, keyword := range product.Keywords {
		if strings.Contains(description, strings.ToLower(keyword)) {
			return true
		}
	}

	return false
}

// matchesProductCPEPatterns checks if the CVE matches any CPE patterns
func (n *NVDClient) matchesProductCPEPatterns(cve types.CVE, product *types.Product) bool {
	if len(product.CPEPatterns) == 0 {
		return false
	}
	
	for _, cpePattern := range product.CPEPatterns {
		if n.matchesCPEPattern(cve, cpePattern) {
			return true
		}
	}

	return false
}

// matchesCPEPattern checks if a CVE matches a CPE pattern
func (n *NVDClient) matchesCPEPattern(cve types.CVE, cpePattern string) bool {
	for _, config := range cve.Configurations {
		for _, node := range config.Nodes {
			for _, cpeMatch := range node.CPEMatch {
				if cpeMatch.Vulnerable && n.cpeMatchesPattern(cpeMatch.Criteria, cpePattern) {
					return true
				}
			}
		}
	}

	return false
}

// cpeMatchesPattern checks if a CPE string matches a pattern
func (n *NVDClient) cpeMatchesPattern(cpe, pattern string) bool {
	// Simple pattern matching for CPE strings
	// This could be enhanced with proper CPE parsing
	if pattern == "*" {
		return true
	}

	// Split CPE into components
	cpeParts := strings.Split(cpe, ":")
	patternParts := strings.Split(pattern, ":")

	if len(cpeParts) != len(patternParts) {
		return false
	}

	for i, patternPart := range patternParts {
		if patternPart != "*" && patternPart != cpeParts[i] {
			return false
		}
	}

	return true
}

// GetCVEDetails fetches detailed information for a specific CVE
func (n *NVDClient) GetCVEDetails(cveID string) (*types.CVE, error) {
	searchURL := n.buildCVEDetailsURL(cveID)
	
	resp, err := n.fetchCVEDetails(searchURL)
	if err != nil {
		return nil, err
	}
	defer n.closeResponseBody(resp)
	
	if err := n.checkResponseStatus(resp); err != nil {
		return nil, err
	}
	
	nvdResp, err := n.parseCVEDetailsResponse(resp)
	if err != nil {
		return nil, err
	}
	
	return n.extractCVEDetails(nvdResp, cveID)
}

// buildCVEDetailsURL constructs the URL for fetching CVE details
func (n *NVDClient) buildCVEDetailsURL(cveID string) string {
	searchURL := fmt.Sprintf("%s?cveId=%s", n.config.NVD.BaseURL, cveID)
	if n.apiKey != "" {
		searchURL += "&apiKey=" + n.apiKey
	}

	return searchURL
}

// fetchCVEDetails executes the HTTP request to fetch CVE details
func (n *NVDClient) fetchCVEDetails(searchURL string) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(n.config.NVD.Timeout)*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	n.setRequestHeaders(req)
	
	resp, err := n.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CVE details: %w", err)
	}
	
	return resp, nil
}

// checkResponseStatus verifies the response status is OK
func (n *NVDClient) checkResponseStatus(resp *http.Response) error {
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("NVD API returned status %d: %s", resp.StatusCode, resp.Status)
	}

	return nil
}

// parseCVEDetailsResponse parses the CVE details response
func (n *NVDClient) parseCVEDetailsResponse(resp *http.Response) (*types.NVDResponse, error) {
	reader := n.getResponseReader(resp)
	
	var nvdResp types.NVDResponse
	if err := json.NewDecoder(reader).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %w", err)
	}
	
	return &nvdResp, nil
}

// extractCVEDetails extracts the CVE from the response
func (n *NVDClient) extractCVEDetails(nvdResp *types.NVDResponse, cveID string) (*types.CVE, error) {
	if len(nvdResp.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE not found: %s", cveID)
	}
	
	return &nvdResp.Vulnerabilities[0].CVE, nil
}

// GetRateLimitInfo returns information about current rate limiting
func (n *NVDClient) GetRateLimitInfo() map[string]interface{} {
	info := map[string]interface{}{
		"rate_limit":     n.config.NVD.RateLimit,
		"timeout":        n.config.NVD.Timeout,
		"retry_attempts": n.config.NVD.RetryAttempts,
		"retry_delay":    n.config.NVD.RetryDelay,
	}

	if n.apiKey != "" {
		info["api_key_configured"] = true
		info["rate_limit_with_key"] = n.config.NVD.RateLimit
	} else {
		info["api_key_configured"] = false
		info["rate_limit_without_key"] = 100 // Default NVD rate limit without API key
	}

	return info
}
