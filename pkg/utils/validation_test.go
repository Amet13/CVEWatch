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
package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidCVEID(t *testing.T) {
	// Test valid CVE IDs
	assert.True(t, IsValidCVEID("CVE-2021-44228"))
	assert.True(t, IsValidCVEID("CVE-2023-1234"))
	assert.True(t, IsValidCVEID("CVE-2024-56789"))

	// Test invalid CVE IDs
	assert.False(t, IsValidCVEID("CVE-2021"))
	assert.False(t, IsValidCVEID("CVE-2021-"))
	assert.False(t, IsValidCVEID("cve-2021-44228"))
	assert.False(t, IsValidCVEID("CVE-2021-44228-extra"))
	assert.False(t, IsValidCVEID(""))
	assert.False(t, IsValidCVEID("invalid"))
}

func TestIsValidDate(t *testing.T) {
	// Test valid dates
	assert.True(t, IsValidDate("2024-01-01"))
	assert.True(t, IsValidDate("2023-12-31"))
	assert.True(t, IsValidDate("2025-02-29"))

	// Test invalid dates
	assert.False(t, IsValidDate("2024/01/01"))
	assert.False(t, IsValidDate("01-01-2024"))
	assert.False(t, IsValidDate("2024-1-1"))
	assert.False(t, IsValidDate("invalid"))

	// Test empty date (should be valid)
	assert.True(t, IsValidDate(""))
}

func TestIsValidCVSSScore(t *testing.T) {
	// Test valid scores
	assert.True(t, IsValidCVSSScore(0.0))
	assert.True(t, IsValidCVSSScore(5.5))
	assert.True(t, IsValidCVSSScore(10.0))

	// Test invalid scores
	assert.False(t, IsValidCVSSScore(-0.1))
	assert.False(t, IsValidCVSSScore(10.1))
	assert.False(t, IsValidCVSSScore(15.0))
}

func TestIsValidMaxResults(t *testing.T) {
	// Test valid max results
	assert.True(t, IsValidMaxResults(1))
	assert.True(t, IsValidMaxResults(100))
	assert.True(t, IsValidMaxResults(2000))

	// Test invalid max results
	assert.False(t, IsValidMaxResults(0))
	assert.False(t, IsValidMaxResults(-1))
	assert.False(t, IsValidMaxResults(2001))
}

func TestIsValidOutputFormat(t *testing.T) {
	// Test valid formats
	assert.True(t, IsValidOutputFormat("simple"))
	assert.True(t, IsValidOutputFormat("json"))
	assert.True(t, IsValidOutputFormat("yaml"))
	assert.True(t, IsValidOutputFormat("table"))
	assert.True(t, IsValidOutputFormat("csv"))

	// Test invalid formats
	assert.False(t, IsValidOutputFormat("xml"))
	assert.False(t, IsValidOutputFormat("html"))
	assert.False(t, IsValidOutputFormat(""))
	assert.False(t, IsValidOutputFormat("invalid"))
}

func TestIsValidDateRange(t *testing.T) {
	tests := []struct {
		name      string
		startDate string
		endDate   string
		want      bool
	}{
		{"valid range same day", "2024-01-01", "2024-01-01", true},
		{"valid range sequential", "2024-01-01", "2024-01-02", true},
		{"valid range month span", "2024-01-15", "2024-02-15", true},
		{"valid range year span", "2023-12-31", "2024-01-01", true},
		{"invalid range reversed", "2024-01-02", "2024-01-01", false},
		{"invalid range far apart reversed", "2024-12-31", "2024-01-01", false},
		{"empty start date", "", "2024-01-01", true},
		{"empty end date", "2024-01-01", "", true},
		{"both empty", "", "", true},
		{"invalid start date format", "2024/01/01", "2024-01-02", false},
		{"invalid end date format", "2024-01-01", "2024/01/02", false},
		{"valid wide range", "2023-01-01", "2024-12-31", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidDateRange(tt.startDate, tt.endDate)
			assert.Equal(t, tt.want, got, "IsValidDateRange(%q, %q)", tt.startDate, tt.endDate)
		})
	}
}

func TestSanitizeCVEID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"already uppercase", "CVE-2023-1234", "CVE-2023-1234"},
		{"lowercase", "cve-2023-1234", "CVE-2023-1234"},
		{"mixed case", "CvE-2023-1234", "CVE-2023-1234"},
		{"with leading space", " CVE-2023-1234", "CVE-2023-1234"},
		{"with trailing space", "CVE-2023-1234 ", "CVE-2023-1234"},
		{"with both spaces", "  CVE-2023-1234  ", "CVE-2023-1234"},
		{"with tab", "\tCVE-2023-1234", "CVE-2023-1234"},
		{"with newline", "CVE-2023-1234\n", "CVE-2023-1234"},
		{"lowercase with spaces", "  cve-2023-1234  ", "CVE-2023-1234"},
		{"empty string", "", ""},
		{"only spaces", "   ", ""},
		{"modern CVE ID", "cve-2023-123456", "CVE-2023-123456"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeCVEID(tt.input)
			assert.Equal(t, tt.want, got, "SanitizeCVEID(%q)", tt.input)
		})
	}
}
