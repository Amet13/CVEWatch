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

	// Basic CVE ID format validation: CVE-YYYY-NNNNN
	if len(cveID) < 8 {
		return false
	}

	// Check if it starts with "CVE-"
	if cveID[:4] != "CVE-" {
		return false
	}

	// Check for valid format: CVE-YYYY-NNNNN
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

	// Check if number part is numeric and positive
	seq, err := strconv.Atoi(parts[2])
	if err != nil || seq < 1 {
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
	matched, _ := regexp.MatchString(pattern, date)

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
