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
