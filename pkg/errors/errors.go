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

// Package errors provides structured error handling for CVEWatch.
//
// It defines custom error types with contextual information, suggestions,
// and error categorization for better error handling and user communication.
package errors

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrorType represents different categories of errors
type ErrorType int

// Error type constants
const (
	ErrorTypeNetwork ErrorType = iota
	ErrorTypeValidation
	ErrorTypeConfiguration
	ErrorTypeAPI
	ErrorTypeParsing
	ErrorTypeRateLimit
	ErrorTypeNotFound
	ErrorTypeUnknown
)

// CVEWatchError represents a structured error with additional context
type CVEWatchError struct {
	Type       ErrorType
	Message    string
	Cause      error
	Suggestion string
	Code       string
	Context    map[string]interface{}
}

// Error implements the error interface
func (e *CVEWatchError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap returns the underlying error
func (e *CVEWatchError) Unwrap() error {
	return e.Cause
}

// WithSuggestion adds a suggestion to the error
func (e *CVEWatchError) WithSuggestion(suggestion string) *CVEWatchError {
	e.Suggestion = suggestion
	return e
}

// WithCode adds an error code to the error
func (e *CVEWatchError) WithCode(code string) *CVEWatchError {
	e.Code = code
	return e
}

// WithContext adds context information to the error
func (e *CVEWatchError) WithContext(key string, value interface{}) *CVEWatchError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

func newError(errorType ErrorType, message string, cause error) *CVEWatchError {
	return &CVEWatchError{
		Type:    errorType,
		Message: message,
		Cause:   cause,
	}
}

func asCVEWatchError(err error) (*CVEWatchError, bool) {
	var cveErr *CVEWatchError
	if errors.As(err, &cveErr) {
		return cveErr, true
	}

	return nil, false
}

func isErrorType(err error, expectedType ErrorType) bool {
	cveErr, ok := asCVEWatchError(err)
	return ok && cveErr.Type == expectedType
}

// NewNetworkError creates a new network-related error
func NewNetworkError(message string, cause error) *CVEWatchError {
	return newError(ErrorTypeNetwork, message, cause)
}

// NewValidationError creates a new validation-related error
func NewValidationError(message string, cause error) *CVEWatchError {
	return newError(ErrorTypeValidation, message, cause)
}

// NewConfigurationError creates a new configuration-related error
func NewConfigurationError(message string, cause error) *CVEWatchError {
	return newError(ErrorTypeConfiguration, message, cause)
}

// NewAPIError creates a new API-related error
func NewAPIError(message string, cause error) *CVEWatchError {
	return newError(ErrorTypeAPI, message, cause)
}

// NewParsingError creates a new parsing-related error
func NewParsingError(message string, cause error) *CVEWatchError {
	return newError(ErrorTypeParsing, message, cause)
}

// NewRateLimitError creates a new rate limiting error
func NewRateLimitError(message string, cause error) *CVEWatchError {
	return &CVEWatchError{
		Type:       ErrorTypeRateLimit,
		Message:    message,
		Cause:      cause,
		Suggestion: "Try again later or consider using an API key for higher rate limits",
	}
}

// NewNotFoundError creates a new not found error
func NewNotFoundError(message string, cause error) *CVEWatchError {
	return &CVEWatchError{
		Type:       ErrorTypeNotFound,
		Message:    message,
		Cause:      cause,
		Suggestion: "Verify the resource identifier and try again",
	}
}

// NewHTTPError creates an error from HTTP response
func NewHTTPError(resp *http.Response, cause error) *CVEWatchError {
	message := fmt.Sprintf("HTTP %d %s", resp.StatusCode, resp.Status)

	var suggestion string
	switch resp.StatusCode {
	case 401:
		suggestion = "Check your API key configuration"
	case 403:
		suggestion = "Your API key may not have sufficient permissions"
	case 404:
		suggestion = "The requested resource was not found"
	case 429:
		suggestion = "Rate limit exceeded. Try again later or use an API key"
	case 500, 502, 503, 504:
		suggestion = "The NVD API is experiencing issues. Try again later"
	}

	return &CVEWatchError{
		Type:       ErrorTypeAPI,
		Message:    message,
		Cause:      cause,
		Suggestion: suggestion,
		Code:       fmt.Sprintf("HTTP_%d", resp.StatusCode),
		Context: map[string]interface{}{
			"status_code": resp.StatusCode,
			"url":         resp.Request.URL.String(),
		},
	}
}

// IsNetworkError checks if an error is a network-related error
func IsNetworkError(err error) bool {
	return isErrorType(err, ErrorTypeNetwork)
}

// IsRateLimitError checks if an error is a rate limiting error
func IsRateLimitError(err error) bool {
	return isErrorType(err, ErrorTypeRateLimit)
}

// IsValidationError checks if an error is a validation error
func IsValidationError(err error) bool {
	return isErrorType(err, ErrorTypeValidation)
}

// IsConfigurationError checks if an error is a configuration error
func IsConfigurationError(err error) bool {
	return isErrorType(err, ErrorTypeConfiguration)
}

// IsNotFoundError checks if an error is a not found error
func IsNotFoundError(err error) bool {
	return isErrorType(err, ErrorTypeNotFound)
}

// FormatError formats an error with user-friendly output
func FormatError(err error) string {
	if cveErr, ok := asCVEWatchError(err); ok {
		var builder strings.Builder

		// Main error message
		fmt.Fprintf(&builder, "❌ Error: %s\n", cveErr.Message)

		// Add suggestion if available
		if cveErr.Suggestion != "" {
			fmt.Fprintf(&builder, "💡 Suggestion: %s\n", cveErr.Suggestion)
		}

		// Add context information
		if len(cveErr.Context) > 0 {
			builder.WriteString("📋 Context:\n")
			for key, value := range cveErr.Context {
				fmt.Fprintf(&builder, "   %s: %v\n", key, value)
			}
		}

		// Add underlying error
		if cveErr.Cause != nil {
			fmt.Fprintf(&builder, "🔍 Details: %v\n", cveErr.Cause)
		}

		return builder.String()
	}

	// Fallback for non-CVEWatch errors
	return fmt.Sprintf("❌ Error: %v", err)
}

// WrapError wraps an existing error with additional context
func WrapError(err error, message string) *CVEWatchError {
	return &CVEWatchError{
		Type:    ErrorTypeUnknown,
		Message: message,
		Cause:   err,
	}
}

// GetErrorType returns the type of error
func GetErrorType(err error) ErrorType {
	if cveErr, ok := asCVEWatchError(err); ok {
		return cveErr.Type
	}
	return ErrorTypeUnknown
}

// GetErrorCode returns the error code if available
func GetErrorCode(err error) string {
	if cveErr, ok := asCVEWatchError(err); ok {
		return cveErr.Code
	}
	return ""
}

// GetErrorSuggestion returns the suggestion if available
func GetErrorSuggestion(err error) string {
	if cveErr, ok := asCVEWatchError(err); ok {
		return cveErr.Suggestion
	}
	return ""
}
