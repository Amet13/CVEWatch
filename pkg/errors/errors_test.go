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

package errors

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCVEWatchError_Error(t *testing.T) {
	// Test error without cause
	err := &CVEWatchError{
		Message: "test error",
	}
	assert.Equal(t, "test error", err.Error())

	// Test error with cause
	cause := errors.New("underlying error")
	err = &CVEWatchError{
		Message: "test error",
		Cause:   cause,
	}
	assert.Contains(t, err.Error(), "test error")
	assert.Contains(t, err.Error(), "underlying error")
}

func TestCVEWatchError_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := &CVEWatchError{
		Message: "test error",
		Cause:   cause,
	}

	assert.Equal(t, cause, err.Unwrap())
}

func TestCVEWatchError_WithSuggestion(t *testing.T) {
	err := &CVEWatchError{
		Message: "test error",
	}

	result := err.WithSuggestion("try this")
	assert.Equal(t, "try this", result.Suggestion)
	assert.Equal(t, err, result) // Should return the same instance
}

func TestCVEWatchError_WithCode(t *testing.T) {
	err := &CVEWatchError{
		Message: "test error",
	}

	result := err.WithCode("ERR_001")
	assert.Equal(t, "ERR_001", result.Code)
	assert.Equal(t, err, result)
}

func TestCVEWatchError_WithContext(t *testing.T) {
	err := &CVEWatchError{
		Message: "test error",
	}

	result := err.WithContext("key", "value")
	assert.Equal(t, "value", result.Context["key"])
	assert.Equal(t, err, result)
}

func TestNewNetworkError(t *testing.T) {
	cause := errors.New("connection failed")
	err := NewNetworkError("network error", cause)

	assert.Equal(t, ErrorTypeNetwork, err.Type)
	assert.Equal(t, "network error", err.Message)
	assert.Equal(t, cause, err.Cause)
}

func TestNewValidationError(t *testing.T) {
	cause := errors.New("invalid input")
	err := NewValidationError("validation failed", cause)

	assert.Equal(t, ErrorTypeValidation, err.Type)
	assert.Equal(t, "validation failed", err.Message)
	assert.Equal(t, cause, err.Cause)
}

func TestNewConfigurationError(t *testing.T) {
	cause := errors.New("config not found")
	err := NewConfigurationError("configuration error", cause)

	assert.Equal(t, ErrorTypeConfiguration, err.Type)
	assert.Equal(t, "configuration error", err.Message)
	assert.Equal(t, cause, err.Cause)
}

func TestNewAPIError(t *testing.T) {
	cause := errors.New("api failure")
	err := NewAPIError("API error", cause)

	assert.Equal(t, ErrorTypeAPI, err.Type)
	assert.Equal(t, "API error", err.Message)
	assert.Equal(t, cause, err.Cause)
}

func TestNewParsingError(t *testing.T) {
	cause := errors.New("parse failed")
	err := NewParsingError("parsing error", cause)

	assert.Equal(t, ErrorTypeParsing, err.Type)
	assert.Equal(t, "parsing error", err.Message)
	assert.Equal(t, cause, err.Cause)
}

func TestNewRateLimitError(t *testing.T) {
	cause := errors.New("rate limited")
	err := NewRateLimitError("rate limit exceeded", cause)

	assert.Equal(t, ErrorTypeRateLimit, err.Type)
	assert.Equal(t, "rate limit exceeded", err.Message)
	assert.Equal(t, cause, err.Cause)
	assert.Contains(t, err.Suggestion, "Try again later")
}

func TestNewHTTPError(t *testing.T) {
	// Create a mock HTTP response
	testURL, _ := url.Parse("https://example.com/api")
	req := &http.Request{URL: testURL}
	resp := &http.Response{
		StatusCode: 429,
		Status:     "429 Too Many Requests",
		Request:    req,
	}

	cause := errors.New("rate limited")
	err := NewHTTPError(resp, cause)

	assert.Equal(t, ErrorTypeAPI, err.Type)
	assert.Contains(t, err.Message, "HTTP 429")
	assert.Equal(t, cause, err.Cause)
	assert.Contains(t, err.Suggestion, "Rate limit exceeded")
	assert.Equal(t, "HTTP_429", err.Code)
	assert.Equal(t, 429, err.Context["status_code"])
	assert.Equal(t, "https://example.com/api", err.Context["url"])
}

func TestHTTPErrorSuggestions(t *testing.T) {
	testCases := []struct {
		statusCode         int
		expectedSuggestion string
	}{
		{401, "Check your API key configuration"},
		{403, "Your API key may not have sufficient permissions"},
		{404, "The requested resource was not found"},
		{429, "Rate limit exceeded"},
		{500, "The NVD API is experiencing issues"},
		{502, "The NVD API is experiencing issues"},
		{503, "The NVD API is experiencing issues"},
		{504, "The NVD API is experiencing issues"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Status%d", tc.statusCode), func(t *testing.T) {
			testURL, _ := url.Parse("https://example.com/api")
			req := &http.Request{URL: testURL}
			resp := &http.Response{
				StatusCode: tc.statusCode,
				Request:    req,
			}

			err := NewHTTPError(resp, nil)
			assert.Contains(t, err.Suggestion, tc.expectedSuggestion)
		})
	}
}

func TestIsNetworkError(t *testing.T) {
	networkErr := NewNetworkError("network error", nil)
	validationErr := NewValidationError("validation error", nil)
	regularErr := errors.New("regular error")

	assert.True(t, IsNetworkError(networkErr))
	assert.False(t, IsNetworkError(validationErr))
	assert.False(t, IsNetworkError(regularErr))
}

func TestIsRateLimitError(t *testing.T) {
	rateLimitErr := NewRateLimitError("rate limit error", nil)
	networkErr := NewNetworkError("network error", nil)
	regularErr := errors.New("regular error")

	assert.True(t, IsRateLimitError(rateLimitErr))
	assert.False(t, IsRateLimitError(networkErr))
	assert.False(t, IsRateLimitError(regularErr))
}

func TestIsValidationError(t *testing.T) {
	validationErr := NewValidationError("validation error", nil)
	networkErr := NewNetworkError("network error", nil)
	regularErr := errors.New("regular error")

	assert.True(t, IsValidationError(validationErr))
	assert.False(t, IsValidationError(networkErr))
	assert.False(t, IsValidationError(regularErr))
}

func TestIsConfigurationError(t *testing.T) {
	configErr := NewConfigurationError("config error", nil)
	networkErr := NewNetworkError("network error", nil)
	regularErr := errors.New("regular error")

	assert.True(t, IsConfigurationError(configErr))
	assert.False(t, IsConfigurationError(networkErr))
	assert.False(t, IsConfigurationError(regularErr))
}

func TestFormatError(t *testing.T) {
	// Test CVEWatchError formatting
	cveErr := NewAPIError("API error", errors.New("connection failed")).
		WithSuggestion("Check your connection").
		WithCode("ERR_API_001").
		WithContext("endpoint", "/api/v1/data")

	formatted := FormatError(cveErr)
	assert.Contains(t, formatted, "❌ Error: API error")
	assert.Contains(t, formatted, "💡 Suggestion: Check your connection")
	assert.Contains(t, formatted, "endpoint: /api/v1/data")
	assert.Contains(t, formatted, "🔍 Details: connection failed")

	// Test regular error formatting
	regularErr := errors.New("regular error")
	formatted = FormatError(regularErr)
	assert.Contains(t, formatted, "❌ Error: regular error")
}

func TestWrapError(t *testing.T) {
	cause := errors.New("underlying error")
	err := WrapError(cause, "wrapped message")

	assert.Equal(t, ErrorTypeUnknown, err.Type)
	assert.Equal(t, "wrapped message", err.Message)
	assert.Equal(t, cause, err.Cause)
}

func TestGetErrorType(t *testing.T) {
	cveErr := NewNetworkError("network error", nil)
	regularErr := errors.New("regular error")

	assert.Equal(t, ErrorTypeNetwork, GetErrorType(cveErr))
	assert.Equal(t, ErrorTypeUnknown, GetErrorType(regularErr))
}

func TestGetErrorCode(t *testing.T) {
	cveErr := NewAPIError("API error", nil).WithCode("ERR_001")
	regularErr := errors.New("regular error")

	assert.Equal(t, "ERR_001", GetErrorCode(cveErr))
	assert.Equal(t, "", GetErrorCode(regularErr))
}

func TestGetErrorSuggestion(t *testing.T) {
	cveErr := NewRateLimitError("rate limit error", nil)
	regularErr := errors.New("regular error")

	assert.Contains(t, GetErrorSuggestion(cveErr), "Try again later")
	assert.Equal(t, "", GetErrorSuggestion(regularErr))
}
