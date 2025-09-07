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
package output

import (
	"strings"
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
	assert.InDelta(t, 8.5, score, 0.01)

	// Test CVE with CVSS v2 score (should prefer v3.1)
	cve.Metrics.CVSSMetricV2 = []types.CVSSMetricV2{
		{
			CVSSData: types.CVSSDataV2{
				BaseScore: 7.0,
			},
		},
	}
	score = formatter.getCVSSScore(cve)
	assert.InDelta(t, 8.5, score, 0.01) // Should still prefer v3.1

	// Test CVE with only CVSS v2 score
	cve.Metrics.CVSSMetricV31 = nil
	score = formatter.getCVSSScore(cve)
	assert.InDelta(t, 7.0, score, 0.01)

	// Test CVE with no CVSS score
	cve.Metrics.CVSSMetricV2 = nil
	score = formatter.getCVSSScore(cve)
	assert.InDelta(t, 0.0, score, 0.01)
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
	assert.Empty(t, productName) // Should return empty for wildcard vendor

	// Test invalid CPE string
	cpe = "invalid:cpe:format"
	productName = formatter.extractProductName(cpe)
	assert.Empty(t, productName)
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

	// Test edge case with max length 0
	result = formatter.truncateString("test", 0)
	assert.Equal(t, "", result)

	// Test edge case with max length 3 (minimum for truncation)
	result = formatter.truncateString("test", 3)
	assert.Equal(t, "...", result)
}

func TestGetAffectedProducts(t *testing.T) {
	config := &types.AppConfig{
		Output: types.OutputSettings{
			TruncateLength: 100,
		},
	}
	formatter := NewOutputFormatter("simple", config)

	// Test CVE with CPE matches
	cve := types.CVE{
		ID: "CVE-2023-1234",
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
							{
								Vulnerable: true,
								Criteria:   "cpe:2.3:a:apache:http_server:2.4:*:*:*:*:*:*:*",
							},
						},
					},
				},
			},
		},
	}

	products := formatter.getAffectedProducts(cve)
	assert.Contains(t, products, "microsoft windows")
	assert.Contains(t, products, "apache http_server")
	// Should not contain non-vulnerable products
	assert.NotContains(t, products, "microsoft office")

	// Test CVE with no configurations
	cve.Configurations = nil
	products = formatter.getAffectedProducts(cve)
	assert.Equal(t, "Unknown", products)

	// Test CVE with empty configurations
	cve.Configurations = []types.Configuration{}
	products = formatter.getAffectedProducts(cve)
	assert.Equal(t, "Unknown", products)
}

func TestGetAffectedProducts_DuplicateRemoval(t *testing.T) {
	config := &types.AppConfig{
		Output: types.OutputSettings{
			TruncateLength: 100,
		},
	}
	formatter := NewOutputFormatter("simple", config)

	// Test CVE with duplicate CPE matches
	cve := types.CVE{
		ID: "CVE-2023-1234",
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
								Vulnerable: true,
								Criteria:   "cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*", // Same product
							},
						},
					},
				},
			},
		},
	}

	products := formatter.getAffectedProducts(cve)
	// Should contain only one instance of "microsoft windows"
	assert.Equal(t, 1, len(strings.Split(products, ", ")))
	assert.Contains(t, products, "microsoft windows")
}

func TestFormatOutput_JSON(t *testing.T) {
	config := &types.AppConfig{
		Output: types.OutputSettings{
			DefaultFormat: "json",
		},
	}
	formatter := NewOutputFormatter("json", config)

	result := &types.SearchResult{
		CVEs: []types.CVE{
			{
				ID: "CVE-2023-1234",
			},
		},
		Date:       "2024-01-01",
		MinCVSS:    7.0,
		MaxCVSS:    10.0,
		Products:   []string{"Linux Kernel"},
		TotalFound: 1,
		QueryTime:  "1.23s",
	}

	// This test would require capturing stdout, so we'll just ensure it doesn't panic
	assert.NotPanics(t, func() {
		err := formatter.FormatOutput(result)
		assert.NoError(t, err)
	})
}

func TestFormatOutput_YAML(t *testing.T) {
	config := &types.AppConfig{
		Output: types.OutputSettings{
			DefaultFormat: "yaml",
		},
	}
	formatter := NewOutputFormatter("yaml", config)

	result := &types.SearchResult{
		CVEs:       []types.CVE{},
		Date:       "2024-01-01",
		MinCVSS:    0.0,
		MaxCVSS:    0.0,
		Products:   []string{"Test Product"},
		TotalFound: 0,
		QueryTime:  "0.50s",
	}

	assert.NotPanics(t, func() {
		err := formatter.FormatOutput(result)
		assert.NoError(t, err)
	})
}

func TestFormatOutput_Table(t *testing.T) {
	config := &types.AppConfig{
		Output: types.OutputSettings{
			DefaultFormat: "table",
		},
	}
	formatter := NewOutputFormatter("table", config)

	result := &types.SearchResult{
		CVEs: []types.CVE{
			{
				ID: "CVE-2023-1234",
				Descriptions: []types.Description{
					{Lang: "en", Value: "Test vulnerability description"},
				},
				Published: "2023-01-01T00:00:00.000Z",
				References: []types.Reference{
					{URL: "https://example.com/cve-2023-1234"},
				},
				Metrics: types.Metrics{
					CVSSMetricV31: []types.CVSSMetricV31{
						{
							CVSSData: types.CVSSDataV31{
								BaseScore: 8.5,
							},
						},
					},
				},
			},
		},
		Date:       "2024-01-01",
		MinCVSS:    7.0,
		MaxCVSS:    10.0,
		Products:   []string{"Test Product"},
		TotalFound: 1,
		QueryTime:  "1.00s",
	}

	assert.NotPanics(t, func() {
		err := formatter.FormatOutput(result)
		assert.NoError(t, err)
	})
}

func TestFormatOutput_CSV(t *testing.T) {
	config := &types.AppConfig{
		Output: types.OutputSettings{
			DefaultFormat: "csv",
		},
	}
	formatter := NewOutputFormatter("csv", config)

	result := &types.SearchResult{
		CVEs: []types.CVE{
			{
				ID:        "CVE-2023-1234",
				Published: "2023-01-01T00:00:00.000Z",
				Modified:  "2023-01-02T00:00:00.000Z",
				Status:    "Modified",
				Descriptions: []types.Description{
					{Lang: "en", Value: "Test vulnerability description"},
				},
				References: []types.Reference{
					{URL: "https://example.com/cve-2023-1234"},
				},
				Metrics: types.Metrics{
					CVSSMetricV31: []types.CVSSMetricV31{
						{
							CVSSData: types.CVSSDataV31{
								BaseScore: 8.5,
							},
						},
					},
				},
			},
		},
		Date:       "2024-01-01",
		MinCVSS:    7.0,
		MaxCVSS:    10.0,
		Products:   []string{"Test Product"},
		TotalFound: 1,
		QueryTime:  "1.00s",
	}

	assert.NotPanics(t, func() {
		err := formatter.FormatOutput(result)
		assert.NoError(t, err)
	})
}

func TestFormatOutput_EmptyResult(t *testing.T) {
	config := &types.AppConfig{
		Output: types.OutputSettings{
			DefaultFormat: "simple",
		},
	}
	formatter := NewOutputFormatter("simple", config)

	result := &types.SearchResult{
		CVEs:       []types.CVE{},
		Date:       "2024-01-01",
		MinCVSS:    7.0,
		MaxCVSS:    10.0,
		Products:   []string{"Test Product"},
		TotalFound: 0,
		QueryTime:  "0.50s",
	}

	assert.NotPanics(t, func() {
		err := formatter.FormatOutput(result)
		assert.NoError(t, err)
	})
}

func TestFormatOutput_InvalidFormat(t *testing.T) {
	config := &types.AppConfig{
		Output: types.OutputSettings{
			DefaultFormat: "invalid",
		},
	}
	formatter := NewOutputFormatter("invalid", config)

	result := &types.SearchResult{
		CVEs:       []types.CVE{},
		Date:       "2024-01-01",
		MinCVSS:    7.0,
		MaxCVSS:    10.0,
		Products:   []string{"Test Product"},
		TotalFound: 0,
		QueryTime:  "0.50s",
	}

	// Should fall back to simple format for invalid format
	assert.NotPanics(t, func() {
		err := formatter.FormatOutput(result)
		assert.NoError(t, err)
	})
}

// Benchmark functions for performance testing

func BenchmarkGetCVSSScore(b *testing.B) {
	config := &types.AppConfig{}
	formatter := NewOutputFormatter("simple", config)

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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		formatter.getCVSSScore(cve)
	}
}

func BenchmarkGetSeverity(b *testing.B) {
	config := &types.AppConfig{}
	formatter := NewOutputFormatter("simple", config)

	scores := []float64{2.0, 5.0, 7.5, 9.0}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, score := range scores {
			formatter.getSeverity(score)
		}
	}
}

func BenchmarkGetEnglishDescription(b *testing.B) {
	config := &types.AppConfig{}
	formatter := NewOutputFormatter("simple", config)

	cve := types.CVE{
		ID: "CVE-2023-1234",
		Descriptions: []types.Description{
			{Lang: "es", Value: "Descripción en español"},
			{Lang: "en", Value: "English description for testing"},
			{Lang: "fr", Value: "Description en français"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		formatter.getEnglishDescription(cve)
	}
}

func BenchmarkTruncateString(b *testing.B) {
	config := &types.AppConfig{}
	formatter := NewOutputFormatter("simple", config)

	longString := "This is a very long string that should be truncated to a reasonable length for display purposes in the terminal output"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		formatter.truncateString(longString, 50)
	}
}

func BenchmarkExtractProductName(b *testing.B) {
	config := &types.AppConfig{}
	formatter := NewOutputFormatter("simple", config)

	cpes := []string{
		"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
		"cpe:2.3:a:apache:http_server:2.4:*:*:*:*:*:*:*",
		"cpe:2.3:a:canonical:ubuntu_linux:20.04:*:*:*:*:*:*:*",
		"cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, cpe := range cpes {
			formatter.extractProductName(cpe)
		}
	}
}

func BenchmarkGetAffectedProducts(b *testing.B) {
	config := &types.AppConfig{
		Output: types.OutputSettings{
			TruncateLength: 100,
		},
	}
	formatter := NewOutputFormatter("simple", config)

	cve := types.CVE{
		ID: "CVE-2023-1234",
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
								Vulnerable: true,
								Criteria:   "cpe:2.3:a:apache:http_server:2.4:*:*:*:*:*:*:*",
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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		formatter.getAffectedProducts(cve)
	}
}
