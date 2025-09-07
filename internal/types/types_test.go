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

package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCVE_JSONMarshaling(t *testing.T) {
	// Create a sample CVE
	cve := CVE{
		ID:        "CVE-2023-1234",
		Published: "2023-01-01T00:00:00.000Z",
		Modified:  "2023-01-02T00:00:00.000Z",
		Status:    "Modified",
		Descriptions: []Description{
			{
				Lang:  "en",
				Value: "Test vulnerability description",
			},
		},
		References: []Reference{
			{
				URL:       "https://example.com/cve-2023-1234",
				RefSource: "MISC",
			},
		},
		Metrics: Metrics{
			CVSSMetricV31: []CVSSMetricV31{
				{
					Source: "nvd@nist.gov",
					Type:   "Primary",
					CVSSData: CVSSDataV31{
						Version:               "3.1",
						VectorString:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						BaseScore:             9.8,
						BaseSeverity:          "CRITICAL",
						AttackVector:          "NETWORK",
						AttackComplexity:      "LOW",
						PrivilegesRequired:    "NONE",
						UserInteraction:       "NONE",
						Scope:                 "UNCHANGED",
						ConfidentialityImpact: "HIGH",
						IntegrityImpact:       "HIGH",
						AvailabilityImpact:    "HIGH",
					},
				},
			},
		},
		Configurations: []Configuration{
			{
				Nodes: []Node{
					{
						Operator: "OR",
						CPEMatch: []CPEMatch{
							{
								Vulnerable: true,
								Criteria:   "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
							},
						},
					},
				},
			},
		},
		Weaknesses: []Weakness{
			{
				Source: "nvd@nist.gov",
				Type:   "Primary",
				Description: []Description{
					{
						Lang:  "en",
						Value: "CWE-79",
					},
				},
			},
		},
	}

	// Test marshaling
	data, err := json.Marshal(cve)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// Test unmarshaling
	var unmarshaled CVE
	err = json.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)
	assert.Equal(t, cve.ID, unmarshaled.ID)
	assert.Equal(t, cve.Status, unmarshaled.Status)
	assert.Equal(t, len(cve.Descriptions), len(unmarshaled.Descriptions))
}

func TestNVDResponse_JSONMarshaling(t *testing.T) {
	response := NVDResponse{
		ResultsPerPage: 100,
		StartIndex:     0,
		TotalResults:   150,
		Format:         "NVD_CVE",
		Version:        "2.0",
		Timestamp:      "2023-01-01T00:00:00.000",
		Vulnerabilities: []Vulnerability{
			{
				CVE: CVE{
					ID: "CVE-2023-1234",
				},
			},
		},
	}

	// Test marshaling
	data, err := json.Marshal(response)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// Test unmarshaling
	var unmarshaled NVDResponse
	err = json.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)
	assert.Equal(t, response.TotalResults, unmarshaled.TotalResults)
	assert.Equal(t, response.Version, unmarshaled.Version)
	assert.Equal(t, len(response.Vulnerabilities), len(unmarshaled.Vulnerabilities))
}

func TestSearchResult_JSONMarshaling(t *testing.T) {
	result := SearchResult{
		CVEs: []CVE{
			{
				ID: "CVE-2023-1234",
			},
		},
		TotalFound: 1,
		Date:       "2024-01-01",
		MinCVSS:    7.0,
		MaxCVSS:    10.0,
		Products:   []string{"Linux Kernel"},
		QueryTime:  "1.23s",
	}

	// Test marshaling
	data, err := json.Marshal(result)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// Test unmarshaling
	var unmarshaled SearchResult
	err = json.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)
	assert.Equal(t, result.TotalFound, unmarshaled.TotalFound)
	assert.Equal(t, result.Date, unmarshaled.Date)
	assert.Equal(t, result.MinCVSS, unmarshaled.MinCVSS)
	assert.Equal(t, result.MaxCVSS, unmarshaled.MaxCVSS)
}

func TestAppConfig_JSONMarshaling(t *testing.T) {
	config := AppConfig{
		App: AppSettings{
			Name:     "CVEWatch",
			Version:  "2.0.0",
			LogLevel: "info",
			Timeout:  60,
		},
		NVD: NVDSettings{
			BaseURL:       "https://services.nvd.nist.gov/rest/json/cves/2.0",
			RateLimit:     1000,
			Timeout:       30,
			RetryAttempts: 3,
			RetryDelay:    5,
		},
		Search: SearchSettings{
			DefaultDate:       "today",
			DefaultMinCVSS:    0.0,
			DefaultMaxCVSS:    10.0,
			DefaultMaxResults: 100,
			DateFormat:        "2006-01-02",
		},
		Output: OutputSettings{
			DefaultFormat:  "simple",
			Formats:        []string{"simple", "json", "yaml", "table", "csv"},
			Colors:         true,
			TruncateLength: 100,
		},
		Security: SecuritySettings{
			EnableSSLVerification: true,
			UserAgent:             "CVEWatch/2.0.0",
			RequestHeaders: map[string]string{
				"Accept": "application/json",
			},
		},
		Products: []Product{
			{
				Name:        "Linux Kernel",
				Keywords:    []string{"linux", "kernel"},
				CPEPatterns: []string{"cpe:2.3:o:*:linux:*:*:*:*:*:*:*"},
				Description: "Linux operating system kernel",
				Priority:    "high",
			},
		},
	}

	// Test marshaling
	data, err := json.Marshal(config)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// Test unmarshaling
	var unmarshaled AppConfig
	err = json.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)
	assert.Equal(t, config.App.Name, unmarshaled.App.Name)
	assert.Equal(t, config.App.Version, unmarshaled.App.Version)
	assert.Equal(t, len(config.Products), len(unmarshaled.Products))
}

func TestCommandLineFlags_Validation(t *testing.T) {
	// Test default values
	flags := CommandLineFlags{}
	assert.Empty(t, flags.Date)
	assert.Equal(t, 0.0, flags.MinCVSS)
	assert.Equal(t, 0.0, flags.MaxCVSS)
	assert.Empty(t, flags.OutputFormat)
	assert.Equal(t, 0, flags.MaxResults)
	assert.Empty(t, flags.APIKey)
	assert.False(t, flags.Verbose)
	assert.False(t, flags.Quiet)
	assert.False(t, flags.IncludeCPE)
	assert.False(t, flags.IncludeRefs)
}

func TestSearchRequest_Validation(t *testing.T) {
	// Test empty request
	request := SearchRequest{}
	assert.Empty(t, request.Date)
	assert.Equal(t, 0.0, request.MinCVSS)
	assert.Equal(t, 0.0, request.MaxCVSS)
	assert.Empty(t, request.Products)
	assert.Equal(t, 0, request.MaxResults)
	assert.Empty(t, request.APIKey)
	assert.False(t, request.IncludeCPE)
	assert.False(t, request.IncludeRefs)
	assert.Empty(t, request.OutputFormat)
}

func TestCVSSDataV31_Validation(t *testing.T) {
	data := CVSSDataV31{
		Version:               "3.1",
		VectorString:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		BaseScore:             9.8,
		BaseSeverity:          "CRITICAL",
		AttackVector:          "NETWORK",
		AttackComplexity:      "LOW",
		PrivilegesRequired:    "NONE",
		UserInteraction:       "NONE",
		Scope:                 "UNCHANGED",
		ConfidentialityImpact: "HIGH",
		IntegrityImpact:       "HIGH",
		AvailabilityImpact:    "HIGH",
	}

	assert.Equal(t, "3.1", data.Version)
	assert.Equal(t, 9.8, data.BaseScore)
	assert.Equal(t, "CRITICAL", data.BaseSeverity)
}

func TestCVSSDataV2_Validation(t *testing.T) {
	data := CVSSDataV2{
		Version:               "2.0",
		VectorString:          "AV:N/AC:L/Au:N/C:C/I:C/A:C",
		BaseScore:             10.0,
		BaseSeverity:          "HIGH",
		AccessVector:          "NETWORK",
		AccessComplexity:      "LOW",
		Authentication:        "NONE",
		ConfidentialityImpact: "COMPLETE",
		IntegrityImpact:       "COMPLETE",
		AvailabilityImpact:    "COMPLETE",
	}

	assert.Equal(t, "2.0", data.Version)
	assert.Equal(t, 10.0, data.BaseScore)
	assert.Equal(t, "HIGH", data.BaseSeverity)
}

func TestReference_Structure(t *testing.T) {
	ref := Reference{
		URL:       "https://example.com/cve-2023-1234",
		Name:      "CVE-2023-1234",
		RefSource: "MISC",
		Tags:      []string{"Vendor Advisory"},
	}

	assert.Equal(t, "https://example.com/cve-2023-1234", ref.URL)
	assert.Equal(t, "CVE-2023-1234", ref.Name)
	assert.Equal(t, "MISC", ref.RefSource)
	assert.Contains(t, ref.Tags, "Vendor Advisory")
}

func TestConfiguration_Structure(t *testing.T) {
	config := Configuration{
		Nodes: []Node{
			{
				Operator: "OR",
				CPEMatch: []CPEMatch{
					{
						Vulnerable: true,
						Criteria:   "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
					},
				},
			},
		},
	}

	assert.Equal(t, "OR", config.Nodes[0].Operator)
	assert.True(t, config.Nodes[0].CPEMatch[0].Vulnerable)
	assert.Equal(t, "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*", config.Nodes[0].CPEMatch[0].Criteria)
}

func TestWeakness_Structure(t *testing.T) {
	weakness := Weakness{
		Source: "nvd@nist.gov",
		Type:   "Primary",
		Description: []Description{
			{
				Lang:  "en",
				Value: "CWE-79",
			},
		},
	}

	assert.Equal(t, "nvd@nist.gov", weakness.Source)
	assert.Equal(t, "Primary", weakness.Type)
	assert.Equal(t, "CWE-79", weakness.Description[0].Value)
	assert.Equal(t, "en", weakness.Description[0].Lang)
}
