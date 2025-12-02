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
	"context"

	"cvewatch/internal/types"
)

// CVEClient defines the interface for CVE data operations.
// This interface allows for easy mocking in tests and potential
// alternative implementations (e.g., cached client, mock client).
type CVEClient interface {
	// SearchCVEs searches for CVEs based on specified criteria.
	// The context can be used for cancellation and timeout control.
	SearchCVEs(ctx context.Context, request *types.SearchRequest) (*types.SearchResult, error)

	// GetCVEDetails fetches detailed information for a specific CVE.
	// The context can be used for cancellation and timeout control.
	GetCVEDetails(ctx context.Context, cveID string) (*types.CVE, error)

	// GetRateLimitInfo returns information about current rate limiting status.
	GetRateLimitInfo() map[string]interface{}

	// CheckHealth verifies the client can connect to the NVD API.
	CheckHealth(ctx context.Context) error
}

// Ensure NVDClient implements CVEClient interface
var _ CVEClient = (*NVDClient)(nil)
