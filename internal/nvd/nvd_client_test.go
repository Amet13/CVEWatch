//nolint:testpackage // We need to test internal package functions
package nvd

import (
	"testing"

	"cvewatch/internal/config"
	"cvewatch/internal/types"

	"github.com/stretchr/testify/assert"
)

func TestNewNVDClient(t *testing.T) {
	configMgr := config.NewConfigManager()
	config := &types.AppConfig{}
	client := NewNVDClient(config, configMgr, "")

	assert.NotNil(t, client)
	assert.Equal(t, configMgr, client.configMgr)
	assert.Empty(t, client.apiKey)
}

func TestMatchesCVSSRange(t *testing.T) {
	configMgr := config.NewConfigManager()
	config := &types.AppConfig{}
	client := NewNVDClient(config, configMgr, "")

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

	request := &types.SearchRequest{
		MinCVSS: 7.0,
		MaxCVSS: 10.0,
	}

	assert.True(t, client.matchesCVSSRange(cve, request))

	// Test CVE with score below minimum
	request.MinCVSS = 9.0
	assert.False(t, client.matchesCVSSRange(cve, request))

	// Test CVE with score above maximum
	request.MinCVSS = 0.0
	request.MaxCVSS = 8.0
	assert.False(t, client.matchesCVSSRange(cve, request))
}

func TestMatchesProduct(t *testing.T) {
	configMgr := config.NewConfigManager()
	// Create a test config with products
	testConfig := &types.AppConfig{
		Products: []types.Product{
			{
				Name:     "Test Product",
				Keywords: []string{"test", "product"},
			},
		},
	}
	configMgr.SetConfig(testConfig)

	client := NewNVDClient(testConfig, configMgr, "")

	// Test CVE that matches product keywords
	cve := types.CVE{
		ID: "CVE-2023-1234",
		Descriptions: []types.Description{
			{
				Lang:  "en",
				Value: "This is a test product vulnerability",
			},
		},
	}

	request := &types.SearchRequest{
		Products: []string{"Test Product"},
	}

	assert.True(t, client.matchesProduct(cve, request.Products))

	// Test CVE that doesn't match
	cve.Descriptions[0].Value = "This is an unrelated vulnerability"
	assert.False(t, client.matchesProduct(cve, request.Products))
}

func TestCPEMatchesPattern(t *testing.T) {
	configMgr := config.NewConfigManager()
	config := &types.AppConfig{}
	client := NewNVDClient(config, configMgr, "")

	// Test exact match
	assert.True(t, client.cpeMatchesPattern("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"))

	// Test wildcard match
	assert.True(t, client.cpeMatchesPattern("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", "cpe:2.3:a:vendor:*:*:*:*:*:*:*:*:*"))

	// Test no match
	assert.False(t, client.cpeMatchesPattern("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", "cpe:2.3:a:other:product:*:*:*:*:*:*:*"))
}
