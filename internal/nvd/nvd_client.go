/*
 * MIT License
 *
 * Copyright (c) 2025 CVEWatch Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

// Package nvd provides a client for the National Vulnerability Database API.
//
// It implements thread-safe API interactions with the NVD v2.0 API,
// including rate limiting, retry logic with exponential backoff,
// CVSS filtering, and CPE pattern matching for CVE searches.
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
	"sync"
	"time"

	"cvewatch/internal/config"
	"cvewatch/internal/types"
	"cvewatch/pkg/errors"
)

// NVDClient handles communication with the NVD API
type NVDClient struct {
	httpClient *http.Client
	config     *types.AppConfig
	configMgr  *config.ConfigManager
	apiKey     string

	// Rate limiting - ✅ FIXED: Now thread-safe with sync.Mutex
	mu           sync.Mutex
	lastRequest  time.Time
	requestCount int
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

// SearchCVEs searches for CVEs based on specified criteria.
//
// SearchCVEs queries the NVD API with the given search parameters
// and returns filtered results based on CVSS scores and product keywords.
//
// The search respects rate limiting configuration and performs automatic
// retry with exponential backoff for transient failures.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - request: SearchRequest with search criteria (date, CVSS range, products, etc.)
//
// Returns:
//   - *SearchResult: Filtered CVE results with metadata
//   - error: Non-nil if validation fails or API request fails
//
// Errors returned:
//   - ValidationError: Invalid search parameters (e.g., invalid CVSS range)
//   - NetworkError: Failed to connect to NVD API
//   - APIError: NVD API returned an error
//   - RateLimitError: Rate limit exceeded
//
// Example:
//
//	ctx := context.Background()
//	request := &types.SearchRequest{
//	    Date:       "2024-01-01",
//	    MinCVSS:    7.0,
//	    MaxCVSS:    10.0,
//	    MaxResults: 100,
//	    Products:   []string{"Linux Kernel"},
//	}
//	result, err := client.SearchCVEs(ctx, request)
//	if err != nil {
//	    // Handle error appropriately based on type
//	    return err
//	}
//	fmt.Printf("Found %d CVEs\n", result.TotalFound)
func (n *NVDClient) SearchCVEs(ctx context.Context, request *types.SearchRequest) (*types.SearchResult, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return nil, errors.NewNetworkError("request cancelled", err)
	}

	// Validate request parameters
	if err := n.validateSearchRequest(request); err != nil {
		return nil, errors.NewValidationError("invalid search request parameters", err).
			WithSuggestion("Check your search criteria and try again")
	}

	startTime := time.Now()

	searchURL := n.buildSearchURL(request)

	resp, err := n.executeSearchRequest(ctx, searchURL)
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

	// Support date range or single date
	if request.StartDate != "" && request.EndDate != "" {
		// Date range search
		startDate := request.StartDate + "T00:00:00.000Z"
		endDate := request.EndDate + "T23:59:59.999Z"
		params.Set("pubStartDate", startDate)
		params.Set("pubEndDate", endDate)
	} else if request.Date != "" {
		// Single date search
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
func (n *NVDClient) executeSearchRequest(ctx context.Context, searchURL string) (*http.Response, error) {
	// Create request with the provided context (timeout is handled at http.Client level)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		return nil, errors.NewNetworkError("failed to create HTTP request", err).
			WithSuggestion("Check your network connection and try again")
	}

	n.setRequestHeaders(req)

	return n.executeWithRetry(ctx, req)
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

// executeWithRetry executes the request with retry logic and exponential backoff with jitter
func (n *NVDClient) executeWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	// Apply rate limiting
	if err := n.checkRateLimit(); err != nil {
		return nil, err
	}

	var resp *http.Response
	var err error

	for attempt := 1; attempt <= n.config.NVD.RetryAttempts; attempt++ {
		// Check context before each attempt
		if ctx.Err() != nil {
			return nil, errors.NewNetworkError("request cancelled", ctx.Err())
		}

		resp, err = n.httpClient.Do(req)
		if err == nil {
			// Check if response status indicates an error
			if resp.StatusCode >= 400 {
				if attempt < n.config.NVD.RetryAttempts {
					// Close response body before retry
					if resp.Body != nil {
						_ = resp.Body.Close()
					}
					n.sleepWithJitter(ctx, attempt)
					continue
				}
				return nil, errors.NewHTTPError(resp, fmt.Errorf("API request failed with status %d", resp.StatusCode))
			}
			break
		}

		if attempt < n.config.NVD.RetryAttempts {
			n.sleepWithJitter(ctx, attempt)
			continue
		}
	}

	// Update rate limiting counters
	n.updateRateLimit()

	if err != nil {
		return nil, errors.NewNetworkError("failed to connect to NVD API", err).
			WithSuggestion("Check your internet connection and try again").
			WithContext("attempts", n.config.NVD.RetryAttempts)
	}

	return resp, nil
}

// sleepWithJitter performs exponential backoff with jitter
func (n *NVDClient) sleepWithJitter(ctx context.Context, attempt int) {
	// Exponential backoff: baseDelay * 2^(attempt-1)
	baseDelay := time.Duration(n.config.NVD.RetryDelay) * time.Second
	delay := baseDelay * time.Duration(1<<uint(attempt-1))

	// Add jitter: random value between 0 and delay/2
	// Use time-based pseudo-random to avoid import
	jitter := time.Duration(time.Now().UnixNano()%int64(delay/2+1))
	totalDelay := delay + jitter

	// Cap at 60 seconds max
	if totalDelay > 60*time.Second {
		totalDelay = 60 * time.Second
	}

	select {
	case <-ctx.Done():
		return
	case <-time.After(totalDelay):
		return
	}
}

// closeResponseBody safely closes the response body
func (n *NVDClient) closeResponseBody(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	if err := resp.Body.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", err)
	}
}

// parseResponse parses the HTTP response into an NVD response
func (n *NVDClient) parseResponse(resp *http.Response) (*types.NVDResponse, error) {
	if resp.StatusCode != http.StatusOK {
		// Try to read error response body for more details
		body, err := io.ReadAll(resp.Body)
		if err == nil && len(body) > 0 {
			return nil, errors.NewAPIError("NVD API returned an error", fmt.Errorf("status %d: %s - %s", resp.StatusCode, resp.Status, string(body)))
		}
		return nil, errors.NewHTTPError(resp, fmt.Errorf("unexpected status code"))
	}

	reader := n.getResponseReader(resp)
	defer func() {
		if err := reader.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close response reader: %v\n", err)
		}
	}()

	var nvdResp types.NVDResponse
	if err := json.NewDecoder(reader).Decode(&nvdResp); err != nil {
		return nil, errors.NewParsingError("failed to parse NVD API response", err).
			WithSuggestion("The API response format may have changed. Try again later or contact support")
	}

	// Validate response structure
	if nvdResp.Vulnerabilities == nil {
		return nil, errors.NewAPIError("invalid API response structure", fmt.Errorf("vulnerabilities field is missing")).
			WithSuggestion("The API response format may have changed. Try again later")
	}

	return &nvdResp, nil
}

// gzipResponseReader wraps a gzip reader to ensure proper cleanup
type gzipResponseReader struct {
	gzReader *gzip.Reader
	body     io.ReadCloser
}

// Read implements io.Reader
func (g *gzipResponseReader) Read(p []byte) (n int, err error) {
	return g.gzReader.Read(p)
}

// Close closes both the gzip reader and the underlying body
func (g *gzipResponseReader) Close() error {
	var errs []error
	if err := g.gzReader.Close(); err != nil {
		errs = append(errs, fmt.Errorf("failed to close gzip reader: %w", err))
	}
	if err := g.body.Close(); err != nil {
		errs = append(errs, fmt.Errorf("failed to close response body: %w", err))
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// getResponseReader returns an appropriate reader for the response
// The caller is responsible for closing the returned reader
func (n *NVDClient) getResponseReader(resp *http.Response) io.ReadCloser {
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			// Fallback to regular body if gzip fails
			return resp.Body
		}

		return &gzipResponseReader{
			gzReader: gzReader,
			body:     resp.Body,
		}
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

// GetCVEDetails fetches detailed information for a specific CVE.
//
// GetCVEDetails retrieves comprehensive information about a single CVE
// including CVSS scores, descriptions, references, and affected products.
//
// Parameters:
//   - cveID: CVE identifier in the format "CVE-YYYY-NNNNN" (e.g., "CVE-2024-1234")
//
// Returns:
//   - *types.CVE: Detailed CVE information
//   - error: Non-nil if the CVE is not found or API request fails
//
// Errors:
//   - NetworkError: Failed to connect to NVD API
//   - APIError: NVD API returned an error
//   - NotFoundError: CVE not found in the database
//
// Example:
//
//	ctx := context.Background()
//	cve, err := client.GetCVEDetails(ctx, "CVE-2024-1234")
//	if err != nil {
//	    fmt.Fprintf(os.Stderr, "Failed to fetch CVE: %v\n", err)
//	    return err
//	}
//	fmt.Printf("CVE %s: %s\n", cve.ID, cve.Descriptions[0].Value)
func (n *NVDClient) GetCVEDetails(ctx context.Context, cveID string) (*types.CVE, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return nil, errors.NewNetworkError("request cancelled", err)
	}

	searchURL := n.buildCVEDetailsURL(cveID)

	resp, err := n.fetchCVEDetails(ctx, searchURL)
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
func (n *NVDClient) fetchCVEDetails(ctx context.Context, searchURL string) (*http.Response, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(n.config.NVD.Timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(timeoutCtx, http.MethodGet, searchURL, nil)
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
	defer func() {
		if err := reader.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close response reader: %v\n", err)
		}
	}()

	var nvdResp types.NVDResponse
	if err := json.NewDecoder(reader).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %w", err)
	}

	return &nvdResp, nil
}

// extractCVEDetails extracts the CVE from the response
func (n *NVDClient) extractCVEDetails(nvdResp *types.NVDResponse, cveID string) (*types.CVE, error) {
	if len(nvdResp.Vulnerabilities) == 0 {
		return nil, errors.NewNotFoundError("CVE not found", fmt.Errorf("cveID: %s", cveID)).
			WithSuggestion("Verify the CVE ID is correct and try again")
	}

	return &nvdResp.Vulnerabilities[0].CVE, nil
}

// validateSearchRequest validates the search request parameters
func (n *NVDClient) validateSearchRequest(request *types.SearchRequest) error {
	if request == nil {
		return errors.NewValidationError("search request is required", fmt.Errorf("request cannot be nil")).
			WithSuggestion("Provide a valid search request with proper parameters")
	}

	if request.MaxResults < 1 || request.MaxResults > 2000 {
		return errors.NewValidationError("invalid max results value", fmt.Errorf("max results must be between 1 and 2000, got %d", request.MaxResults)).
			WithSuggestion("Use a value between 1 and 2000 for max results")
	}

	if request.MinCVSS < 0 || request.MinCVSS > 10 {
		return errors.NewValidationError("invalid minimum CVSS score", fmt.Errorf("min CVSS score must be between 0 and 10, got %.1f", request.MinCVSS)).
			WithSuggestion("Use a CVSS score between 0.0 and 10.0")
	}

	if request.MaxCVSS > 0 && (request.MaxCVSS < 0 || request.MaxCVSS > 10) {
		return errors.NewValidationError("invalid maximum CVSS score", fmt.Errorf("max CVSS score must be between 0 and 10, got %.1f", request.MaxCVSS)).
			WithSuggestion("Use a CVSS score between 0.0 and 10.0")
	}

	if request.MaxCVSS > 0 && request.MinCVSS > request.MaxCVSS {
		return errors.NewValidationError("invalid CVSS score range", fmt.Errorf("min CVSS score (%.1f) cannot be greater than max CVSS score (%.1f)",
			request.MinCVSS, request.MaxCVSS)).
			WithSuggestion("Ensure minimum CVSS score is less than or equal to maximum CVSS score")
	}

	if len(request.Products) == 0 {
		return errors.NewValidationError("no products specified", fmt.Errorf("at least one product must be specified")).
			WithSuggestion("Specify at least one product to search for vulnerabilities")
	}

	return nil
}

// GetRateLimitInfo returns information about current rate limiting - ✅ NEW: Thread-safe
func (n *NVDClient) GetRateLimitInfo() map[string]interface{} {
	n.mu.Lock()
	defer n.mu.Unlock()

	info := map[string]interface{}{
		"rate_limit":       n.config.NVD.RateLimit,
		"current_count":    n.requestCount,
		"last_request":     n.lastRequest,
		"time_until_reset": time.Hour - time.Since(n.lastRequest),
	}

	if n.apiKey != "" {
		info["api_key_configured"] = true
		info["rate_limit_with_key"] = n.config.NVD.RateLimit
	}

	return info
}

// checkRateLimit checks if we're within rate limits - ✅ NOW THREAD-SAFE
func (n *NVDClient) checkRateLimit() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	now := time.Now()

	// Reset counter if more than an hour has passed
	if now.Sub(n.lastRequest) > time.Hour {
		n.requestCount = 0
		n.lastRequest = now
	}

	// Check if we've exceeded the rate limit
	if n.requestCount >= n.config.NVD.RateLimit {
		timeUntilReset := time.Hour - now.Sub(n.lastRequest)
		return errors.NewRateLimitError("API rate limit exceeded", fmt.Errorf("exceeded %d requests per hour", n.config.NVD.RateLimit)).
			WithContext("rate_limit", n.config.NVD.RateLimit).
			WithContext("reset_in", timeUntilReset.Round(time.Minute))
	}

	return nil
}

// updateRateLimit updates the rate limiting counters - ✅ NOW THREAD-SAFE
func (n *NVDClient) updateRateLimit() {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.requestCount++
	if n.lastRequest.IsZero() {
		n.lastRequest = time.Now()
	}
}

// CheckHealth verifies the client can connect to the NVD API.
// It performs a minimal API request to verify connectivity.
func (n *NVDClient) CheckHealth(ctx context.Context) error {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return errors.NewNetworkError("health check cancelled", err)
	}

	// Build a minimal request to check API connectivity
	healthURL := n.config.NVD.BaseURL + "?resultsPerPage=1"
	if n.apiKey != "" {
		healthURL += "&apiKey=" + n.apiKey
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(timeoutCtx, http.MethodGet, healthURL, nil)
	if err != nil {
		return errors.NewNetworkError("failed to create health check request", err)
	}

	n.setRequestHeaders(req)

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return errors.NewNetworkError("NVD API health check failed", err).
			WithSuggestion("Check your internet connection and try again")
	}
	defer n.closeResponseBody(resp)

	if resp.StatusCode != http.StatusOK {
		return errors.NewAPIError("NVD API returned unhealthy status", 
			fmt.Errorf("status code: %d", resp.StatusCode)).
			WithContext("status_code", resp.StatusCode)
	}

	return nil
}
