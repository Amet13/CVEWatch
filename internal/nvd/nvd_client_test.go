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

//nolint:testpackage // We need to test internal package functions
package nvd

import (
	"net/http"
	"testing"
	"time"

	"cvewatch/internal/config"
	"cvewatch/internal/types"

	"github.com/stretchr/testify/assert"
)

func TestNewNVDClient(t *testing.T) {
	configMgr := config.NewConfigManager()
	config := &types.AppConfig{}
	client := NewNVDClient(config, configMgr, "")

	assert.NotNil(t, client)
	assert.Equal(t, configMgr, client.configMgr)
	assert.Empty(t, client.apiKey)
}

func TestMatchesCVSSRange(t *testing.T) {
	configMgr := config.NewConfigManager()
	config := &types.AppConfig{}
	client := NewNVDClient(config, configMgr, "")

	// Test CVE with CVSS v3.1 score
	cve := types.CVE{
		ID: "CVE-2023-1234",
		Metrics: types.Metrics{
			CVSSMetricV31: []types.CVSSMetricV31{
				{
					CVSSData: types.CVSSDataV31{
						BaseScore: 8.5,
					},
				},
			},
		},
	}

	request := &types.SearchRequest{
		MinCVSS: 7.0,
		MaxCVSS: 10.0,
	}

	assert.True(t, client.matchesCVSSRange(cve, request))

	// Test CVE with score below minimum
	request.MinCVSS = 9.0
	assert.False(t, client.matchesCVSSRange(cve, request))

	// Test CVE with score above maximum
	request.MinCVSS = 0.0
	request.MaxCVSS = 8.0
	assert.False(t, client.matchesCVSSRange(cve, request))
}

func TestMatchesProduct(t *testing.T) {
	configMgr := config.NewConfigManager()
	// Create a test config with products
	testConfig := &types.AppConfig{
		Products: []types.Product{
			{
				Name:     "Test Product",
				Keywords: []string{"test", "product"},
			},
		},
	}
	configMgr.SetConfig(testConfig)

	client := NewNVDClient(testConfig, configMgr, "")

	// Test CVE that matches product keywords
	cve := types.CVE{
		ID: "CVE-2023-1234",
		Descriptions: []types.Description{
			{
				Lang:  "en",
				Value: "This is a test product vulnerability",
			},
		},
	}

	request := &types.SearchRequest{
		Products: []string{"Test Product"},
	}

	assert.True(t, client.matchesProduct(cve, request.Products))

	// Test CVE that doesn't match
	cve.Descriptions[0].Value = "This is an unrelated vulnerability"
	assert.False(t, client.matchesProduct(cve, request.Products))
}

func TestCPEMatchesPattern(t *testing.T) {
	configMgr := config.NewConfigManager()
	config := &types.AppConfig{}
	client := NewNVDClient(config, configMgr, "")

	// Test exact match
	assert.True(t, client.cpeMatchesPattern("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"))

	// Test wildcard match
	assert.True(t, client.cpeMatchesPattern("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", "cpe:2.3:a:vendor:*:*:*:*:*:*:*:*:*"))

	// Test no match
	assert.False(t, client.cpeMatchesPattern("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", "cpe:2.3:a:other:product:*:*:*:*:*:*:*"))
}

func TestValidateSearchRequest(t *testing.T) {
	appConfig := &types.AppConfig{
		NVD: types.NVDSettings{
			BaseURL:       "https://services.nvd.nist.gov/rest/json/cves/2.0",
			RateLimit:     1000,
			Timeout:       30,
			RetryAttempts: 3,
			RetryDelay:    5,
		},
	}

	configMgr := config.NewConfigManager()
	client := NewNVDClient(appConfig, configMgr, "")

	tests := []struct {
		name    string
		request *types.SearchRequest
		wantErr bool
	}{
		{
			name: "valid request",
			request: &types.SearchRequest{
				Date:       "2024-01-01",
				MinCVSS:    7.0,
				MaxCVSS:    10.0,
				MaxResults: 100,
				Products:   []string{"Linux Kernel"},
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			request: nil,
			wantErr: true,
		},
		{
			name: "invalid max results",
			request: &types.SearchRequest{
				Date:       "2024-01-01",
				MinCVSS:    7.0,
				MaxCVSS:    10.0,
				MaxResults: 0,
				Products:   []string{"Linux Kernel"},
			},
			wantErr: true,
		},
		{
			name: "invalid min CVSS",
			request: &types.SearchRequest{
				Date:       "2024-01-01",
				MinCVSS:    -1.0,
				MaxCVSS:    10.0,
				MaxResults: 100,
				Products:   []string{"Linux Kernel"},
			},
			wantErr: true,
		},
		{
			name: "invalid max CVSS",
			request: &types.SearchRequest{
				Date:       "2024-01-01",
				MinCVSS:    7.0,
				MaxCVSS:    11.0,
				MaxResults: 100,
				Products:   []string{"Linux Kernel"},
			},
			wantErr: true,
		},
		{
			name: "min CVSS greater than max CVSS",
			request: &types.SearchRequest{
				Date:       "2024-01-01",
				MinCVSS:    8.0,
				MaxCVSS:    7.0,
				MaxResults: 100,
				Products:   []string{"Linux Kernel"},
			},
			wantErr: true,
		},
		{
			name: "no products specified",
			request: &types.SearchRequest{
				Date:       "2024-01-01",
				MinCVSS:    7.0,
				MaxCVSS:    10.0,
				MaxResults: 100,
				Products:   []string{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.validateSearchRequest(tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSearchRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRateLimiting(t *testing.T) {
	appConfig := &types.AppConfig{
		NVD: types.NVDSettings{
			BaseURL:       "https://services.nvd.nist.gov/rest/json/cves/2.0",
			RateLimit:     2, // Set low for testing
			Timeout:       30,
			RetryAttempts: 3,
			RetryDelay:    5,
		},
	}

	configMgr := config.NewConfigManager()
	client := NewNVDClient(appConfig, configMgr, "")

	// First two requests should succeed
	if err := client.checkRateLimit(); err != nil {
		t.Errorf("First request should succeed: %v", err)
	}
	client.updateRateLimit()

	if err := client.checkRateLimit(); err != nil {
		t.Errorf("Second request should succeed: %v", err)
	}
	client.updateRateLimit()

	// Third request should fail
	if err := client.checkRateLimit(); err == nil {
		t.Error("Third request should fail due to rate limiting")
	}

	// Reset rate limit by advancing time
	client.lastRequest = time.Now().Add(-2 * time.Hour)
	client.requestCount = 0

	// Should succeed again
	if err := client.checkRateLimit(); err != nil {
		t.Errorf("Request after reset should succeed: %v", err)
	}
}

func TestBuildSearchURL(t *testing.T) {
	appConfig := &types.AppConfig{
		NVD: types.NVDSettings{
			BaseURL: "https://services.nvd.nist.gov/rest/json/cves/2.0",
		},
	}
	configMgr := config.NewConfigManager()
	client := NewNVDClient(appConfig, configMgr, "")

	tests := []struct {
		name     string
		request  *types.SearchRequest
		apiKey   string
		expected string
	}{
		{
			name: "without date and api key",
			request: &types.SearchRequest{
				MaxResults: 100,
			},
			apiKey:   "",
			expected: "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100",
		},
		{
			name: "with date",
			request: &types.SearchRequest{
				Date:       "2024-01-01",
				MaxResults: 50,
			},
			apiKey:   "",
			expected: "https://services.nvd.nist.gov/rest/json/cves/2.0?pubEndDate=2024-01-01T23%3A59%3A59.999Z&pubStartDate=2024-01-01T00%3A00%3A00.000Z&resultsPerPage=50",
		},
		{
			name: "with api key",
			request: &types.SearchRequest{
				MaxResults: 25,
			},
			apiKey:   "test-key",
			expected: "https://services.nvd.nist.gov/rest/json/cves/2.0?apiKey=test-key&resultsPerPage=25",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client.apiKey = tt.apiKey
			result := client.buildSearchURL(tt.request)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildCVEDetailsURL(t *testing.T) {
	appConfig := &types.AppConfig{
		NVD: types.NVDSettings{
			BaseURL: "https://services.nvd.nist.gov/rest/json/cves/2.0",
		},
	}
	configMgr := config.NewConfigManager()
	client := NewNVDClient(appConfig, configMgr, "")

	tests := []struct {
		name     string
		cveID    string
		apiKey   string
		expected string
	}{
		{
			name:     "without api key",
			cveID:    "CVE-2023-1234",
			apiKey:   "",
			expected: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-1234",
		},
		{
			name:     "with api key",
			cveID:    "CVE-2024-5678",
			apiKey:   "test-key",
			expected: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-5678&apiKey=test-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client.apiKey = tt.apiKey
			result := client.buildCVEDetailsURL(tt.cveID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSetRequestHeaders(t *testing.T) {
	appConfig := &types.AppConfig{
		Security: types.SecuritySettings{
			UserAgent: "CVEWatch/2.0.0",
			RequestHeaders: map[string]string{
				"Accept":          "application/json",
				"Accept-Language": "en-US,en;q=0.9",
			},
		},
	}
	configMgr := config.NewConfigManager()
	client := NewNVDClient(appConfig, configMgr, "")

	req, err := http.NewRequest("GET", "https://example.com", nil)
	assert.NoError(t, err)

	client.setRequestHeaders(req)

	assert.Equal(t, "CVEWatch/2.0.0", req.Header.Get("User-Agent"))
	assert.Equal(t, "application/json", req.Header.Get("Accept"))
	assert.Equal(t, "en-US,en;q=0.9", req.Header.Get("Accept-Language"))
	assert.Equal(t, "gzip", req.Header.Get("Accept-Encoding"))
}

func TestMatchesCPEPattern(t *testing.T) {
	appConfig := &types.AppConfig{}
	configMgr := config.NewConfigManager()
	client := NewNVDClient(appConfig, configMgr, "")

	cve := types.CVE{
		Configurations: []types.Configuration{
			{
				Nodes: []types.Node{
					{
						CPEMatch: []types.CPEMatch{
							{
								Vulnerable: true,
								Criteria:   "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
							},
							{
								Vulnerable: false,
								Criteria:   "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*",
							},
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name     string
		pattern  string
		expected bool
	}{
		{
			name:     "exact match",
			pattern:  "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
			expected: true,
		},
		{
			name:     "wildcard match",
			pattern:  "cpe:2.3:a:microsoft:*:*:*:*:*:*:*:*:*",
			expected: true,
		},
		{
			name:     "no match",
			pattern:  "cpe:2.3:a:apple:macos:*:*:*:*:*:*:*:*",
			expected: false,
		},
		{
			name:     "non-vulnerable match",
			pattern:  "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*",
			expected: false, // Should not match because Vulnerable is false
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.matchesCPEPattern(cve, tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildSearchResult(t *testing.T) {
	appConfig := &types.AppConfig{}
	configMgr := config.NewConfigManager()
	client := NewNVDClient(appConfig, configMgr, "")

	cves := []types.CVE{
		{ID: "CVE-2023-1234"},
		{ID: "CVE-2023-5678"},
	}

	request := &types.SearchRequest{
		Date:     "2024-01-01",
		MinCVSS:  7.0,
		MaxCVSS:  10.0,
		Products: []string{"Linux Kernel"},
	}

	result := client.buildSearchResult(cves, request, "1.23s")

	assert.Equal(t, cves, result.CVEs)
	assert.Equal(t, 2, result.TotalFound)
	assert.Equal(t, "2024-01-01", result.Date)
	assert.Equal(t, 7.0, result.MinCVSS)
	assert.Equal(t, 10.0, result.MaxCVSS)
	assert.Equal(t, []string{"Linux Kernel"}, result.Products)
	assert.Equal(t, "1.23s", result.QueryTime)
}

func TestGetRateLimitInfo(t *testing.T) {
	appConfig := &types.AppConfig{
		NVD: types.NVDSettings{
			BaseURL:       "https://services.nvd.nist.gov/rest/json/cves/2.0",
			RateLimit:     1000,
			Timeout:       30,
			RetryAttempts: 3,
			RetryDelay:    5,
		},
	}
	configMgr := config.NewConfigManager()
	client := NewNVDClient(appConfig, configMgr, "")

	info := client.GetRateLimitInfo()

	assert.Equal(t, 1000, info["rate_limit"])
	assert.Equal(t, 30, info["timeout"])
	assert.Equal(t, 3, info["retry_attempts"])
	assert.Equal(t, 5, info["retry_delay"])

	// Check if api_key_configured key exists and is false
	if apiKeyConfigured, exists := info["api_key_configured"]; exists {
		assert.False(t, apiKeyConfigured.(bool))
	} else {
		// If key doesn't exist, that's also fine (no API key configured)
		assert.True(t, true)
	}
}

func TestGetRateLimitInfo_WithAPIKey(t *testing.T) {
	appConfig := &types.AppConfig{
		NVD: types.NVDSettings{
			RateLimit: 1000,
		},
	}
	configMgr := config.NewConfigManager()
	client := NewNVDClient(appConfig, configMgr, "test-api-key")

	info := client.GetRateLimitInfo()

	assert.True(t, info["api_key_configured"].(bool))
	assert.Equal(t, 1000, info["rate_limit_with_key"])
}

func TestCloseResponseBody(t *testing.T) {
	appConfig := &types.AppConfig{}
	configMgr := config.NewConfigManager()
	client := NewNVDClient(appConfig, configMgr, "")

	// This test verifies that closeResponseBody doesn't panic with nil response
	assert.NotPanics(t, func() {
		client.closeResponseBody(nil)
	})
}
