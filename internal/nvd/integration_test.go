/*
 * MIT License
 *
 * Copyright (c) 2025 CVEWatch Contributors
 */

package nvd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cvewatch/internal/config"
	"cvewatch/internal/types"
)

// MockNVDServer creates a test server that simulates NVD API responses
type MockNVDServer struct {
	*httptest.Server
	Responses map[string]mockResponse
}

type mockResponse struct {
	StatusCode int
	Body       interface{}
	Delay      time.Duration
}

// NewMockNVDServer creates a new mock NVD server
func NewMockNVDServer(t *testing.T) *MockNVDServer {
	t.Helper()

	mock := &MockNVDServer{
		Responses: make(map[string]mockResponse),
	}

	mock.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for API key header
		apiKey := r.Header.Get("apiKey")
		if apiKey != "" {
			// API key present - could add rate limiting logic here
		}

		// For NVD API, the base URL includes the path, so we match on empty path
		// or just look for any request to the root
		path := r.URL.Path
		if path == "/" || path == "" {
			path = "/"
		}

		// Get the response for this path
		response, ok := mock.Responses[path]
		if !ok {
			// Default response for unknown paths
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}

		// Simulate delay if specified
		if response.Delay > 0 {
			time.Sleep(response.Delay)
		}

		// Set content type
		w.Header().Set("Content-Type", "application/json")

		// Write status code
		w.WriteHeader(response.StatusCode)

		// Write body
		if response.Body != nil {
			json.NewEncoder(w).Encode(response.Body)
		}
	}))

	return mock
}

// SetResponse sets a mock response for a path
func (m *MockNVDServer) SetResponse(path string, statusCode int, body interface{}) {
	m.Responses[path] = mockResponse{
		StatusCode: statusCode,
		Body:       body,
	}
}

// SetResponseWithDelay sets a mock response with delay for a path
func (m *MockNVDServer) SetResponseWithDelay(path string, statusCode int, body interface{}, delay time.Duration) {
	m.Responses[path] = mockResponse{
		StatusCode: statusCode,
		Body:       body,
		Delay:      delay,
	}
}

// createTestClient creates a test NVD client with a mock server URL
func createTestClient(baseURL string, rateLimit int, retryAttempts int) *NVDClient {
	testConfig := &types.AppConfig{
		App: types.AppSettings{
			Name:     "CVEWatch-Test",
			Version:  "test",
			LogLevel: "error",
			Timeout:  30,
		},
		NVD: types.NVDSettings{
			BaseURL:       baseURL,
			RateLimit:     rateLimit,
			Timeout:       10,
			RetryAttempts: retryAttempts,
			RetryDelay:    1,
		},
		Search: types.SearchSettings{
			DefaultDate:       "2024-01-01",
			DefaultMinCVSS:    0.0,
			DefaultMaxCVSS:    10.0,
			DefaultMaxResults: 10,
			DateFormat:        "2006-01-02",
		},
		Products: []types.Product{
			{
				Name:        "test",
				Keywords:    []string{"test"},
				Description: "Test product",
			},
		},
		Output: types.OutputSettings{
			DefaultFormat: "simple",
			Colors:        false,
		},
	}

	configManager := config.NewConfigManager()
	configManager.SetConfig(testConfig)
	return NewNVDClient(testConfig, configManager, "")
}

// TestNVDClientIntegration_SearchCVEs tests the full search flow
func TestNVDClientIntegration_SearchCVEs(t *testing.T) {
	// Create mock server
	mock := NewMockNVDServer(t)
	defer mock.Close()

	// Set up mock response
	mockCVEResponse := types.NVDResponse{
		ResultsPerPage: 1,
		StartIndex:     0,
		TotalResults:   1,
		Format:         "NVD_CVE",
		Version:        "2.0",
		Vulnerabilities: []types.Vulnerability{
			{
				CVE: types.CVE{
					ID:        "CVE-2024-0001",
					Published: "2024-01-01T00:00:00.000",
					Modified:  "2024-01-02T00:00:00.000",
					Descriptions: []types.Description{
						{Lang: "en", Value: "Test vulnerability description"},
					},
					Metrics: types.Metrics{
						CVSSMetricV31: []types.CVSSMetricV31{
							{
								Type:   "Primary",
								Source: "nvd@nist.gov",
								CVSSData: types.CVSSDataV31{
									Version:      "3.1",
									VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
									BaseScore:    9.8,
									BaseSeverity: "CRITICAL",
								},
							},
						},
					},
				},
			},
		},
	}

	mock.SetResponse("/", http.StatusOK, mockCVEResponse)

	// Create client with mock server URL
	client := createTestClient(mock.URL, 100, 1)

	// Create search request
	request := &types.SearchRequest{
		Date:       "2024-01-01",
		Products:   []string{"test"},
		MaxResults: 10,
	}

	// Execute search
	ctx := context.Background()
	result, err := client.SearchCVEs(ctx, request)
	if err != nil {
		t.Fatalf("SearchCVEs failed: %v", err)
	}

	// Verify response
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.TotalFound != 1 {
		t.Errorf("Expected TotalFound=1, got %d", result.TotalFound)
	}
}

// TestNVDClientIntegration_GetCVEDetails tests fetching specific CVE details
func TestNVDClientIntegration_GetCVEDetails(t *testing.T) {
	mock := NewMockNVDServer(t)
	defer mock.Close()

	mockCVEResponse := types.NVDResponse{
		ResultsPerPage: 1,
		StartIndex:     0,
		TotalResults:   1,
		Format:         "NVD_CVE",
		Version:        "2.0",
		Vulnerabilities: []types.Vulnerability{
			{
				CVE: types.CVE{
					ID:        "CVE-2024-0001",
					Published: "2024-01-01T00:00:00.000",
					Modified:  "2024-01-02T00:00:00.000",
					Descriptions: []types.Description{
						{Lang: "en", Value: "Specific CVE details"},
					},
				},
			},
		},
	}

	mock.SetResponse("/", http.StatusOK, mockCVEResponse)

	client := createTestClient(mock.URL, 100, 1)

	ctx := context.Background()
	cve, err := client.GetCVEDetails(ctx, "CVE-2024-0001")
	if err != nil {
		t.Fatalf("GetCVEDetails failed: %v", err)
	}

	if cve == nil {
		t.Fatal("Expected non-nil CVE")
	}
	if cve.ID != "CVE-2024-0001" {
		t.Errorf("Expected CVE ID 'CVE-2024-0001', got '%s'", cve.ID)
	}
}

// TestNVDClientIntegration_CVENotFound tests handling of non-existent CVEs
func TestNVDClientIntegration_CVENotFound(t *testing.T) {
	mock := NewMockNVDServer(t)
	defer mock.Close()

	// Return empty result for non-existent CVE
	mockCVEResponse := types.NVDResponse{
		ResultsPerPage:  0,
		StartIndex:      0,
		TotalResults:    0,
		Vulnerabilities: []types.Vulnerability{},
	}

	mock.SetResponse("/", http.StatusOK, mockCVEResponse)

	client := createTestClient(mock.URL, 100, 1)

	ctx := context.Background()
	cve, err := client.GetCVEDetails(ctx, "CVE-9999-99999")

	// Should return nil with no error for not found
	if err != nil && cve == nil {
		// This is acceptable - either nil,nil or error
		return
	}
	if cve != nil {
		t.Errorf("Expected nil CVE for non-existent ID, got %+v", cve)
	}
}

// TestNVDClientIntegration_RateLimiting tests rate limiting behavior
func TestNVDClientIntegration_RateLimiting(t *testing.T) {
	mock := NewMockNVDServer(t)
	defer mock.Close()

	mockCVEResponse := types.NVDResponse{
		ResultsPerPage:  0,
		StartIndex:      0,
		TotalResults:    0,
		Vulnerabilities: []types.Vulnerability{},
	}

	mock.SetResponse("/", http.StatusOK, mockCVEResponse)

	// Create client with high rate limit for testing (100 per hour should be enough)
	client := createTestClient(mock.URL, 100, 1)

	ctx := context.Background()
	request := &types.SearchRequest{
		Date:       "2024-01-01",
		Products:   []string{"test"},
		MaxResults: 10,
	}

	// Make a few requests to test rate limiting mechanism
	for i := 0; i < 3; i++ {
		_, err := client.SearchCVEs(ctx, request)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
	}

	// Verify rate limit info is available
	info := client.GetRateLimitInfo()
	if info == nil {
		t.Fatal("Expected non-nil rate limit info")
	}
	t.Logf("Rate limit info: %+v", info)
}

// TestNVDClientIntegration_ServerError tests handling of server errors
func TestNVDClientIntegration_ServerError(t *testing.T) {
	mock := NewMockNVDServer(t)
	defer mock.Close()

	mock.SetResponse("/", http.StatusInternalServerError, map[string]string{
		"error": "internal server error",
	})

	// Create client with only 1 retry to speed up test
	client := createTestClient(mock.URL, 100, 1)

	ctx := context.Background()
	request := &types.SearchRequest{
		Date:       "2024-01-01",
		Products:   []string{"test"},
		MaxResults: 10,
	}

	_, err := client.SearchCVEs(ctx, request)
	if err == nil {
		t.Fatal("Expected error for server error response")
	}
}

// TestNVDClientIntegration_ContextCancellation tests context cancellation
func TestNVDClientIntegration_ContextCancellation(t *testing.T) {
	mock := NewMockNVDServer(t)
	defer mock.Close()

	// Set a delayed response
	mock.SetResponseWithDelay("/", http.StatusOK, types.NVDResponse{}, 5*time.Second)

	client := createTestClient(mock.URL, 100, 1)

	// Create a context that will be cancelled
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	request := &types.SearchRequest{
		Date:       "2024-01-01",
		Products:   []string{"test"},
		MaxResults: 10,
	}
	_, err := client.SearchCVEs(ctx, request)

	if err == nil {
		t.Fatal("Expected error due to context cancellation")
	}
}

// TestNVDClientIntegration_CheckHealth tests the health check endpoint
func TestNVDClientIntegration_CheckHealth(t *testing.T) {
	mock := NewMockNVDServer(t)
	defer mock.Close()

	mock.SetResponse("/", http.StatusOK, types.NVDResponse{
		TotalResults: 0,
	})

	client := createTestClient(mock.URL, 100, 1)

	ctx := context.Background()
	err := client.CheckHealth(ctx)
	if err != nil {
		t.Fatalf("CheckHealth failed: %v", err)
	}
}

// TestNVDClientIntegration_CheckHealthFailure tests health check failure
func TestNVDClientIntegration_CheckHealthFailure(t *testing.T) {
	mock := NewMockNVDServer(t)
	defer mock.Close()

	mock.SetResponse("/", http.StatusServiceUnavailable, map[string]string{
		"error": "service unavailable",
	})

	client := createTestClient(mock.URL, 100, 1)

	ctx := context.Background()
	err := client.CheckHealth(ctx)
	if err == nil {
		t.Fatal("Expected health check to fail")
	}
}

// TestNVDClientIntegration_GetRateLimitInfo tests rate limit info
func TestNVDClientIntegration_GetRateLimitInfo(t *testing.T) {
	mock := NewMockNVDServer(t)
	defer mock.Close()

	client := createTestClient(mock.URL, 100, 1)

	info := client.GetRateLimitInfo()
	if info == nil {
		t.Fatal("Expected non-nil rate limit info")
	}
}

// TestMockCVEClient implements the CVEClient interface for unit testing
type TestMockCVEClient struct {
	SearchCVEsFunc    func(ctx context.Context, request *types.SearchRequest) (*types.SearchResult, error)
	GetCVEDetailsFunc func(ctx context.Context, cveID string) (*types.CVE, error)
	GetRateLimitFunc  func() map[string]interface{}
	CheckHealthFunc   func(ctx context.Context) error
}

func (m *TestMockCVEClient) SearchCVEs(ctx context.Context, request *types.SearchRequest) (*types.SearchResult, error) {
	if m.SearchCVEsFunc != nil {
		return m.SearchCVEsFunc(ctx, request)
	}
	return &types.SearchResult{}, nil
}

func (m *TestMockCVEClient) GetCVEDetails(ctx context.Context, cveID string) (*types.CVE, error) {
	if m.GetCVEDetailsFunc != nil {
		return m.GetCVEDetailsFunc(ctx, cveID)
	}
	return &types.CVE{}, nil
}

func (m *TestMockCVEClient) GetRateLimitInfo() map[string]interface{} {
	if m.GetRateLimitFunc != nil {
		return m.GetRateLimitFunc()
	}
	return map[string]interface{}{}
}

func (m *TestMockCVEClient) CheckHealth(ctx context.Context) error {
	if m.CheckHealthFunc != nil {
		return m.CheckHealthFunc(ctx)
	}
	return nil
}

// TestMockCVEClient_InterfaceCompliance ensures mock implements interface
func TestMockCVEClient_InterfaceCompliance(t *testing.T) {
	var _ CVEClient = (*TestMockCVEClient)(nil)
	var _ CVEClient = (*NVDClient)(nil)
}
