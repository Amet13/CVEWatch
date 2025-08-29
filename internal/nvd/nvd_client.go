package nvd

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

	// Build search parameters
	params := url.Values{}

	// Date range (search for CVEs published on the specified date)
	// NVD API expects dates in ISO 8601 format
	if request.Date != "" {
		startDate := request.Date + "T00:00:00.000Z"
		endDate := request.Date + "T23:59:59.999Z"
		params.Set("pubStartDate", startDate)
		params.Set("pubEndDate", endDate)
	}

	// Results limit
	params.Set("resultsPerPage", strconv.Itoa(request.MaxResults))

	// Add API key if provided
	if n.apiKey != "" {
		params.Set("apiKey", n.apiKey)
	}

	// Build search URL
	searchURL := n.config.NVD.BaseURL + "?" + params.Encode()

	// Create request with context
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(n.config.NVD.Timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers from configuration
	req.Header.Set("User-Agent", n.config.Security.UserAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	for key, value := range n.config.Security.RequestHeaders {
		req.Header.Set(key, value)
	}

	// Execute request with retry logic
	var resp *http.Response
	for attempt := 1; attempt <= n.config.NVD.RetryAttempts; attempt++ {
		resp, err = n.httpClient.Do(req)
		if err == nil {
			break
		}

		if attempt < n.config.NVD.RetryAttempts {
			time.Sleep(time.Duration(n.config.NVD.RetryDelay) * time.Second)
			continue
		}

		return nil, fmt.Errorf("failed to fetch CVE data after %d attempts: %w", n.config.NVD.RetryAttempts, err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status %d: %s", resp.StatusCode, resp.Status)
	}

	// Parse JSON response
	var nvdResp types.NVDResponse

	// Handle gzipped responses
	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	if err := json.NewDecoder(reader).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %w", err)
	}

	// Filter CVEs by products and CVSS scores
	filteredCVEs := n.filterCVEsByProducts(nvdResp.Vulnerabilities, request)

	queryTime := time.Since(startTime).String()

	result := &types.SearchResult{
		CVEs:       filteredCVEs,
		TotalFound: len(filteredCVEs),
		Date:       request.Date,
		MinCVSS:    request.MinCVSS,
		MaxCVSS:    request.MaxCVSS,
		Products:   request.Products,
		QueryTime:  queryTime,
	}

	return result, nil
}

// filterCVEsByProducts filters CVEs based on product keywords and CVSS scores
func (n *NVDClient) filterCVEsByProducts(vulnerabilities []types.Vulnerability, request *types.SearchRequest) []types.CVE {
	var filteredCVEs []types.CVE

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

	if len(cve.Metrics.CVSSMetricV31) > 0 {
		score = cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
	} else if len(cve.Metrics.CVSSMetricV2) > 0 {
		score = cve.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
	} else {
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
	// Get the English description
	var description string
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			description = strings.ToLower(desc.Value)
			break
		}
	}

	if description == "" {
		return false
	}

	// Check if any of the specified products match
	for _, productName := range productNames {
		product := n.configMgr.GetProductByName(productName)
		if product == nil {
			continue
		}

		// Check keywords
		for _, keyword := range product.Keywords {
			if strings.Contains(description, strings.ToLower(keyword)) {
				return true
			}
		}

		// Check CPE patterns if enabled
		if len(product.CPEPatterns) > 0 {
			for _, cpePattern := range product.CPEPatterns {
				if n.matchesCPEPattern(cve, cpePattern) {
					return true
				}
			}
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
	searchURL := fmt.Sprintf("%s?cveId=%s", n.config.NVD.BaseURL, cveID)

	if n.apiKey != "" {
		searchURL += "&apiKey=" + n.apiKey
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(n.config.NVD.Timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", n.config.Security.UserAgent)
	for key, value := range n.config.Security.RequestHeaders {
		req.Header.Set(key, value)
	}

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CVE details: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status %d: %s", resp.StatusCode, resp.Status)
	}

	var nvdResp types.NVDResponse

	// Handle gzipped responses
	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	if err := json.NewDecoder(reader).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %w", err)
	}

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
