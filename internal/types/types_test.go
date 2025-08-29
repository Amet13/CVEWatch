package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCVEStruct(t *testing.T) {
	// Test CVE struct creation
	cve := CVE{
		ID: "CVE-2023-1234",
		Descriptions: []Description{
			{
				Lang:  "en",
				Value: "Test description",
			},
		},
		Published: "2023-01-01T00:00:00Z",
		Modified:  "2023-01-01T00:00:00Z",
		Status:    "Modified",
	}

	assert.Equal(t, "CVE-2023-1234", cve.ID)
	assert.Equal(t, 1, len(cve.Descriptions))
	assert.Equal(t, "en", cve.Descriptions[0].Lang)
	assert.Equal(t, "Test description", cve.Descriptions[0].Value)
}

func TestMetricsStruct(t *testing.T) {
	// Test Metrics struct creation
	metrics := Metrics{
		CVSSMetricV31: []CVSSMetricV31{
			{
				Source: "nvd@nist.gov",
				Type:   "Primary",
				CVSSData: CVSSDataV31{
					BaseScore:    8.5,
					BaseSeverity: "HIGH",
					VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				},
			},
		},
	}

	assert.Equal(t, 1, len(metrics.CVSSMetricV31))
	assert.Equal(t, "nvd@nist.gov", metrics.CVSSMetricV31[0].Source)
	assert.Equal(t, 8.5, metrics.CVSSMetricV31[0].CVSSData.BaseScore)
	assert.Equal(t, "HIGH", metrics.CVSSMetricV31[0].CVSSData.BaseSeverity)
}

func TestProductStruct(t *testing.T) {
	// Test Product struct creation
	product := Product{
		Name:        "Test Product",
		Keywords:    []string{"test", "product"},
		CPEPatterns: []string{"cpe:2.3:a:vendor:product:*:*:*:*:*:*:*"},
		Description: "Test product description",
		Priority:    "high",
	}

	assert.Equal(t, "Test Product", product.Name)
	assert.Equal(t, 2, len(product.Keywords))
	assert.Equal(t, "high", product.Priority)
	assert.Equal(t, "Test product description", product.Description)
}

func TestNVDResponseStruct(t *testing.T) {
	// Test NVDResponse struct creation
	response := NVDResponse{
		ResultsPerPage: 10,
		StartIndex:     0,
		TotalResults:   100,
		Format:         "NVD_CVE",
		Version:        "2.0",
		Timestamp:      "2023-01-01T00:00:00Z",
		Vulnerabilities: []Vulnerability{
			{
				CVE: CVE{
					ID: "CVE-2023-1234",
				},
			},
		},
	}

	assert.Equal(t, 10, response.ResultsPerPage)
	assert.Equal(t, 100, response.TotalResults)
	assert.Equal(t, "2.0", response.Version)
	assert.Equal(t, 1, len(response.Vulnerabilities))
}
