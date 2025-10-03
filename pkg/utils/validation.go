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

package utils

import (
	"regexp"
	"strconv"
	"strings"
)

// IsValidCVEID checks if a string is a valid CVE ID format
func IsValidCVEID(cveID string) bool {
	if cveID == "" {
		return false
	}

	// Sanitize input - remove any whitespace
	cveID = strings.TrimSpace(cveID)

	// Basic CVE ID format validation: CVE-YYYY-NNNNN+
	if len(cveID) < 13 { // Minimum: CVE-1999-0001
		return false
	}

	// Check if it starts with "CVE-"
	if !strings.HasPrefix(cveID, "CVE-") {
		return false
	}

	// Check for valid format: CVE-YYYY-NNNNN (4+ digits)
	parts := strings.Split(cveID, "-")
	if len(parts) != 3 {
		return false
	}

	// Check year format (should be 4 digits)
	if len(parts[1]) != 4 {
		return false
	}

	// Check if year is numeric and within reasonable range
	year, err := strconv.Atoi(parts[1])
	if err != nil || year < 1999 || year > 2100 {
		return false
	}

	// Check if number part is numeric and positive (minimum 4 digits, no maximum)
	// Modern CVE IDs can have 4-7+ digits (e.g., CVE-2023-1234567)
	if len(parts[2]) < 4 {
		return false
	}
	seq, err := strconv.Atoi(parts[2])
	if err != nil || seq < 0 {
		return false
	}

	return true
}

// IsValidDate checks if a string is a valid date in YYYY-MM-DD format
func IsValidDate(date string) bool {
	if date == "" {
		return true // Empty date is valid (will use default)
	}

	pattern := `^\d{4}-\d{2}-\d{2}$`
	matched, err := regexp.MatchString(pattern, date)
	if err != nil {
		return false
	}

	return matched
}

// IsValidCVSSScore checks if a CVSS score is within valid range
func IsValidCVSSScore(score float64) bool {
	return score >= 0.0 && score <= 10.0
}

// IsValidMaxResults checks if max results is within valid range
func IsValidMaxResults(maxResults int) bool {
	return maxResults >= 1 && maxResults <= 2000
}

// IsValidOutputFormat checks if output format is valid
func IsValidOutputFormat(format string) bool {
	validFormats := []string{"simple", "json", "yaml", "table", "csv"}
	for _, valid := range validFormats {
		if format == valid {
			return true
		}
	}

	return false
}

// IsValidDateRange checks if a date range is valid (start <= end)
func IsValidDateRange(startDate, endDate string) bool {
	if startDate == "" || endDate == "" {
		return true // Empty dates are valid
	}

	// Both dates must be valid formats
	if !IsValidDate(startDate) || !IsValidDate(endDate) {
		return false
	}

	// Simple string comparison works for YYYY-MM-DD format
	return startDate <= endDate
}

// SanitizeCVEID sanitizes a CVE ID by trimming whitespace and converting to uppercase
func SanitizeCVEID(cveID string) string {
	return strings.ToUpper(strings.TrimSpace(cveID))
}
