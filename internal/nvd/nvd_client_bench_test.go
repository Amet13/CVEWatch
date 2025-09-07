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
	for range b.N {
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
	for range b.N {
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
	for range b.N {
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
	for range b.N {
		client.matchesProduct(cve, products)
	}
}
