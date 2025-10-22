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

package nvd

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"cvewatch/internal/types"
)

// TestHelper creates test fixtures and helpers
type TestHelper struct {
	t      *testing.T
	config *types.AppConfig
}

// NewTestHelper creates a new test helper instance
func NewTestHelper(t *testing.T) *TestHelper {
	t.Helper()
	return &TestHelper{
		t: t,
		config: &types.AppConfig{
			App: types.AppSettings{
				Name:     "CVEWatch-Test",
				Version:  "test",
				LogLevel: "info",
				Timeout:  30,
			},
			NVD: types.NVDSettings{
				BaseURL:       "https://services.nvd.nist.gov/rest/json/cves/2.0",
				RateLimit:     100,
				Timeout:       30,
				RetryAttempts: 1,
				RetryDelay:    1,
			},
		},
	}
}

// CreateValidSearchRequest creates a valid search request for testing
func (th *TestHelper) CreateValidSearchRequest() *types.SearchRequest {
	return &types.SearchRequest{
		Date:       "2024-01-01",
		MinCVSS:    0.0,
		MaxCVSS:    10.0,
		MaxResults: 100,
		Products:   []string{"Linux Kernel"},
	}
}

// CreateSampleCVE creates a sample CVE for testing
func (th *TestHelper) CreateSampleCVE() types.CVE {
	return types.CVE{
		ID:        "CVE-2024-1234",
		Published: "2024-01-01T00:00:00Z",
		Modified:  "2024-01-02T00:00:00Z",
		Status:    "PUBLISHED",
		Descriptions: []types.Description{
			{
				Lang:  "en",
				Value: "A test vulnerability description for linux kernel",
			},
		},
		Metrics: types.Metrics{
			CVSSMetricV31: []types.CVSSMetricV31{
				{
					CVSSData: types.CVSSDataV31{
						BaseScore:    7.5,
						BaseSeverity: "HIGH",
						VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
					},
				},
			},
		},
	}
}

// TestValidateSearchRequest_ValidRequests tests validation of valid search requests
func TestValidateSearchRequest_ValidRequests(t *testing.T) {
	th := NewTestHelper(t)
	client := NewNVDClient(th.config, nil, "")

	tests := []struct {
		name    string
		request *types.SearchRequest
	}{
		{
			name:    "Minimal valid request",
			request: th.CreateValidSearchRequest(),
		},
		{
			name: "Request with CVSS filtering",
			request: &types.SearchRequest{
				MaxResults: 100,
				MinCVSS:    5.0,
				MaxCVSS:    8.0,
				Products:   []string{"Linux Kernel"},
			},
		},
		{
			name: "Request with max results at limit",
			request: &types.SearchRequest{
				MaxResults: 2000,
				MinCVSS:    0.0,
				MaxCVSS:    10.0,
				Products:   []string{"Linux Kernel"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.validateSearchRequest(tt.request)
			assert.NoError(t, err)
		})
	}
}

// TestValidateSearchRequest_InvalidParameters tests validation of invalid search requests
func TestValidateSearchRequest_InvalidParameters(t *testing.T) {
	th := NewTestHelper(t)
	client := NewNVDClient(th.config, nil, "")

	tests := []struct {
		name    string
		request *types.SearchRequest
		wantErr bool
	}{
		{
			name: "Invalid min CVSS (negative)",
			request: &types.SearchRequest{
				MaxResults: 100,
				MinCVSS:    -1.0,
				MaxCVSS:    8.0,
				Products:   []string{"Linux Kernel"},
			},
			wantErr: true,
		},
		{
			name: "Invalid max CVSS (too high)",
			request: &types.SearchRequest{
				MaxResults: 100,
				MinCVSS:    5.0,
				MaxCVSS:    11.0,
				Products:   []string{"Linux Kernel"},
			},
			wantErr: true,
		},
		{
			name: "MinCVSS greater than MaxCVSS",
			request: &types.SearchRequest{
				MaxResults: 100,
				MinCVSS:    8.0,
				MaxCVSS:    5.0,
				Products:   []string{"Linux Kernel"},
			},
			wantErr: true,
		},
		{
			name: "Invalid max results (too high)",
			request: &types.SearchRequest{
				MaxResults: 3000,
				MinCVSS:    5.0,
				MaxCVSS:    8.0,
				Products:   []string{"Linux Kernel"},
			},
			wantErr: true,
		},
		{
			name: "Invalid max results (too low)",
			request: &types.SearchRequest{
				MaxResults: 0,
				MinCVSS:    5.0,
				MaxCVSS:    8.0,
				Products:   []string{"Linux Kernel"},
			},
			wantErr: true,
		},
		{
			name: "No products specified",
			request: &types.SearchRequest{
				MaxResults: 100,
				MinCVSS:    5.0,
				MaxCVSS:    8.0,
				Products:   []string{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.validateSearchRequest(tt.request)
			assert.Error(t, err, "expected error for test: %s", tt.name)
		})
	}
}

// TestMatchesCVSSRange_WithinRange tests CVSS filtering for values within range
func TestMatchesCVSSRange_WithinRange(t *testing.T) {
	th := NewTestHelper(t)
	client := NewNVDClient(th.config, nil, "")
	cve := th.CreateSampleCVE() // CVSS 7.5

	tests := []struct {
		name     string
		minCVSS  float64
		maxCVSS  float64
		expected bool
	}{
		{
			name:     "Within tight range",
			minCVSS:  7.0,
			maxCVSS:  8.0,
			expected: true,
		},
		{
			name:     "At minimum boundary",
			minCVSS:  7.5,
			maxCVSS:  8.0,
			expected: true,
		},
		{
			name:     "At maximum boundary",
			minCVSS:  7.0,
			maxCVSS:  7.5,
			expected: true,
		},
		{
			name:     "Within wide range",
			minCVSS:  0.0,
			maxCVSS:  10.0,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &types.SearchRequest{
				MinCVSS: tt.minCVSS,
				MaxCVSS: tt.maxCVSS,
			}
			result := client.matchesCVSSRange(cve, request)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestMatchesCVSSRange_OutsideRange tests CVSS filtering for values outside range
func TestMatchesCVSSRange_OutsideRange(t *testing.T) {
	th := NewTestHelper(t)
	client := NewNVDClient(th.config, nil, "")
	cve := th.CreateSampleCVE() // CVSS 7.5

	tests := []struct {
		name     string
		minCVSS  float64
		maxCVSS  float64
		expected bool
	}{
		{
			name:     "Below minimum",
			minCVSS:  8.0,
			maxCVSS:  10.0,
			expected: false,
		},
		{
			name:     "Above maximum",
			minCVSS:  0.0,
			maxCVSS:  7.0,
			expected: false,
		},
		{
			name:     "Completely below range",
			minCVSS:  0.1,
			maxCVSS:  1.0,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &types.SearchRequest{
				MinCVSS: tt.minCVSS,
				MaxCVSS: tt.maxCVSS,
			}
			result := client.matchesCVSSRange(cve, request)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestCPEPatternMatching_ExactMatch tests exact CPE pattern matching
func TestCPEPatternMatching_ExactMatch(t *testing.T) {
	th := NewTestHelper(t)
	client := NewNVDClient(th.config, nil, "")

	tests := []struct {
		name     string
		cpe      string
		pattern  string
		expected bool
	}{
		{
			name:     "Exact match",
			cpe:      "cpe:2.3:o:linux:linux:5.10.0:*:*:*:*:*:*:*",
			pattern:  "cpe:2.3:o:linux:linux:5.10.0:*:*:*:*:*:*:*",
			expected: true,
		},
		{
			name:     "Identical with wildcards",
			cpe:      "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*",
			pattern:  "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.cpeMatchesPattern(tt.cpe, tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestCPEPatternMatching_WildcardMatch tests wildcard CPE pattern matching
func TestCPEPatternMatching_WildcardMatch(t *testing.T) {
	th := NewTestHelper(t)
	client := NewNVDClient(th.config, nil, "")

	tests := []struct {
		name     string
		cpe      string
		pattern  string
		expected bool
	}{
		{
			name:     "Vendor wildcard match",
			cpe:      "cpe:2.3:o:linux:linux:5.10.0:*:*:*:*:*:*:*",
			pattern:  "cpe:2.3:o:*:linux:*:*:*:*:*:*:*:*",
			expected: true,
		},
		{
			name:     "Product wildcard match",
			cpe:      "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*",
			pattern:  "cpe:2.3:a:openssl:*:1.1.1:*:*:*:*:*:*:*",
			expected: true,
		},
		{
			name:     "Version wildcard match",
			cpe:      "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*",
			pattern:  "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.cpeMatchesPattern(tt.cpe, tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestCPEPatternMatching_NoMatch tests CPE pattern matching that should fail
func TestCPEPatternMatching_NoMatch(t *testing.T) {
	th := NewTestHelper(t)
	client := NewNVDClient(th.config, nil, "")

	tests := []struct {
		name     string
		cpe      string
		pattern  string
		expected bool
	}{
		{
			name:     "Different product type",
			cpe:      "cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*",
			pattern:  "cpe:2.3:o:*:linux:*:*:*:*:*:*:*:*",
			expected: false,
		},
		{
			name:     "Different vendor",
			cpe:      "cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*",
			pattern:  "cpe:2.3:a:apache:*:*:*:*:*:*:*:*:*",
			expected: false,
		},
		{
			name:     "Mismatched specific versions",
			cpe:      "cpe:2.3:a:openssl:openssl:1.1.0:*:*:*:*:*:*:*",
			pattern:  "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.cpeMatchesPattern(tt.cpe, tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRateLimiting_ThreadSafety tests thread-safety of rate limiter
func TestRateLimiting_ThreadSafety(t *testing.T) {
	th := NewTestHelper(t)
	th.config.NVD.RateLimit = 1000
	client := NewNVDClient(th.config, nil, "")

	numGoroutines := 10
	operationsPerGoroutine := 50
	var wg sync.WaitGroup

	// Concurrent rate limit checks and updates
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				_ = client.checkRateLimit()
				client.updateRateLimit()
			}
		}()
	}

	wg.Wait()

	// Verify final count is correct
	info := client.GetRateLimitInfo()
	expectedCount := numGoroutines * operationsPerGoroutine
	assert.Equal(t, expectedCount, info["current_count"].(int))
}

// TestRateLimiting_Exceeded tests rate limit exceeded scenario
func TestRateLimiting_Exceeded(t *testing.T) {
	th := NewTestHelper(t)
	th.config.NVD.RateLimit = 5
	client := NewNVDClient(th.config, nil, "")

	// Fill up the rate limit
	for i := 0; i < 5; i++ {
		err := client.checkRateLimit()
		require.NoError(t, err)
		client.updateRateLimit()
	}

	// Next call should fail
	err := client.checkRateLimit()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rate limit exceeded")
}

// TestGetRateLimitInfo tests rate limit info retrieval
func TestGetRateLimitInfo(t *testing.T) {
	th := NewTestHelper(t)
	client := NewNVDClient(th.config, nil, "")

	info := client.GetRateLimitInfo()

	assert.NotNil(t, info)
	assert.Equal(t, th.config.NVD.RateLimit, info["rate_limit"])
	assert.Equal(t, 0, info["current_count"].(int))

	// Update and check again
	client.updateRateLimit()
	info = client.GetRateLimitInfo()
	assert.Equal(t, 1, info["current_count"].(int))
}
