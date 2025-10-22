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

package nvd

import (
	"testing"

	"cvewatch/internal/types"
)

// BenchmarkValidateSearchRequest benchmarks search request validation
func BenchmarkValidateSearchRequest(b *testing.B) {
	th := NewTestHelper(&testing.T{})
	client := NewNVDClient(th.config, nil, "")
	request := th.CreateValidSearchRequest()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.validateSearchRequest(request)
	}
}

// BenchmarkMatchesCVSSRange benchmarks CVSS range matching
func BenchmarkMatchesCVSSRange(b *testing.B) {
	th := NewTestHelper(&testing.T{})
	client := NewNVDClient(th.config, nil, "")
	cve := th.CreateSampleCVE()

	request := &types.SearchRequest{
		MinCVSS: 5.0,
		MaxCVSS: 9.0,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.matchesCVSSRange(cve, request)
	}
}

const testCPE = "cpe:2.3:o:linux:linux:5.10.0:*:*:*:*:*:*:*"

// BenchmarkCPEMatching_Exact benchmarks exact CPE pattern matching
func BenchmarkCPEMatching_Exact(b *testing.B) {
	th := NewTestHelper(&testing.T{})
	client := NewNVDClient(th.config, nil, "")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.cpeMatchesPattern(testCPE, "cpe:2.3:o:linux:linux:5.10.0:*:*:*:*:*:*:*")
	}
}

// BenchmarkCPEMatching_Wildcard benchmarks wildcard CPE pattern matching
func BenchmarkCPEMatching_Wildcard(b *testing.B) {
	th := NewTestHelper(&testing.T{})
	client := NewNVDClient(th.config, nil, "")

	cpe := "cpe:2.3:o:linux:linux:5.10.0:*:*:*:*:*:*:*"
	pattern := "cpe:2.3:o:*:linux:*:*:*:*:*:*:*:*"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.cpeMatchesPattern(cpe, pattern)
	}
}

// BenchmarkRateLimiting benchmarks rate limit checking
func BenchmarkRateLimiting(b *testing.B) {
	th := NewTestHelper(&testing.T{})
	client := NewNVDClient(th.config, nil, "")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.checkRateLimit()
	}
}

// BenchmarkGetRateLimitInfo benchmarks rate limit info retrieval
func BenchmarkGetRateLimitInfo(b *testing.B) {
	th := NewTestHelper(&testing.T{})
	client := NewNVDClient(th.config, nil, "")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.GetRateLimitInfo()
	}
}
