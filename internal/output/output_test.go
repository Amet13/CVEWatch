package output

import (
	"testing"

	"cvewatch/internal/types"

	"github.com/stretchr/testify/assert"
)

func TestNewOutputFormatter(t *testing.T) {
	config := &types.AppConfig{}
	formatter := NewOutputFormatter("simple", config)
	assert.NotNil(t, formatter)
}

func TestGetCVSSScore(t *testing.T) {
	config := &types.AppConfig{}
	formatter := NewOutputFormatter("simple", config)

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

	score := formatter.getCVSSScore(cve)
	assert.Equal(t, 8.5, score)

	// Test CVE with CVSS v2 score (should prefer v3.1)
	cve.Metrics.CVSSMetricV2 = []types.CVSSMetricV2{
		{
			CVSSData: types.CVSSDataV2{
				BaseScore: 7.0,
			},
		},
	}
	score = formatter.getCVSSScore(cve)
	assert.Equal(t, 8.5, score) // Should still prefer v3.1

	// Test CVE with only CVSS v2 score
	cve.Metrics.CVSSMetricV31 = nil
	score = formatter.getCVSSScore(cve)
	assert.Equal(t, 7.0, score)

	// Test CVE with no CVSS score
	cve.Metrics.CVSSMetricV2 = nil
	score = formatter.getCVSSScore(cve)
	assert.Equal(t, 0.0, score)
}

func TestGetSeverity(t *testing.T) {
	config := &types.AppConfig{}
	formatter := NewOutputFormatter("simple", config)

	assert.Equal(t, "CRITICAL", formatter.getSeverity(9.5))
	assert.Equal(t, "HIGH", formatter.getSeverity(8.0))
	assert.Equal(t, "MEDIUM", formatter.getSeverity(5.0))
	assert.Equal(t, "LOW", formatter.getSeverity(2.0))
	assert.Equal(t, "NONE", formatter.getSeverity(0.0))
}

func TestGetEnglishDescription(t *testing.T) {
	config := &types.AppConfig{}
	formatter := NewOutputFormatter("simple", config)

	// Test CVE with English description
	cve := types.CVE{
		ID: "CVE-2023-1234",
		Descriptions: []types.Description{
			{
				Lang:  "en",
				Value: "English description",
			},
			{
				Lang:  "es",
				Value: "Spanish description",
			},
		},
	}

	desc := formatter.getEnglishDescription(cve)
	assert.Equal(t, "English description", desc)

	// Test CVE with no English description
	cve.Descriptions[0].Lang = "es"
	desc = formatter.getEnglishDescription(cve)
	assert.Equal(t, "No description available", desc)

	// Test CVE with no descriptions
	cve.Descriptions = nil
	desc = formatter.getEnglishDescription(cve)
	assert.Equal(t, "No description available", desc)
}

func TestExtractProductName(t *testing.T) {
	config := &types.AppConfig{}
	formatter := NewOutputFormatter("simple", config)

	// Test valid CPE string
	cpe := "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
	productName := formatter.extractProductName(cpe)
	assert.Equal(t, "microsoft windows", productName)

	// Test CPE string with wildcards
	cpe = "cpe:2.3:a:*:product:*:*:*:*:*:*:*"
	productName = formatter.extractProductName(cpe)
	assert.Equal(t, "", productName) // Should return empty for wildcard vendor

	// Test invalid CPE string
	cpe = "invalid:cpe:format"
	productName = formatter.extractProductName(cpe)
	assert.Equal(t, "", productName)
}

func TestTruncateString(t *testing.T) {
	config := &types.AppConfig{}
	formatter := NewOutputFormatter("simple", config)

	// Test string shorter than max length
	result := formatter.truncateString("short", 10)
	assert.Equal(t, "short", result)

	// Test string equal to max length
	result = formatter.truncateString("exactly", 7)
	assert.Equal(t, "exactly", result)

	// Test string longer than max length
	result = formatter.truncateString("very long string", 10)
	assert.Equal(t, "very lo...", result)
}
