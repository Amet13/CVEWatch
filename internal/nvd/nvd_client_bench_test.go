package nvd

import (
	"cvewatch/internal/config"
	"cvewatch/internal/types"
	"testing"
)

func BenchmarkNewNVDClient(b *testing.B) {
	cm := config.NewConfigManager()
	config := &types.AppConfig{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewNVDClient(config, cm, "")
	}
}

func BenchmarkMatchesCVSSRange(b *testing.B) {
	cm := config.NewConfigManager()
	config := &types.AppConfig{}
	client := NewNVDClient(config, cm, "")

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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.matchesCVSSRange(cve, request)
	}
}

func BenchmarkCPEMatchesPattern(b *testing.B) {
	cm := config.NewConfigManager()
	config := &types.AppConfig{}
	client := NewNVDClient(config, cm, "")

	cpe := "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
	pattern := "cpe:2.3:a:vendor:*:*:*:*:*:*:*:*:*"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.cpeMatchesPattern(cpe, pattern)
	}
}

func BenchmarkMatchesProduct(b *testing.B) {
	cm := config.NewConfigManager()
	config := &types.AppConfig{}
	client := NewNVDClient(config, cm, "")

	cve := types.CVE{
		ID: "CVE-2023-1234",
		Descriptions: []types.Description{
			{
				Lang:  "en",
				Value: "This is a test product vulnerability",
			},
		},
	}

	products := []string{"Test Product"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.matchesProduct(cve, products)
	}
}
