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
package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionFunctions(t *testing.T) {
	// Test that version functions return expected values
	assert.NotEmpty(t, GetVersion())
	assert.NotEmpty(t, GetBuildTime())
	assert.NotEmpty(t, GetGitCommit())

	// Test IsDevelopment function
	// In test environment, this should be true since we're not building with ldflags
	assert.True(t, IsDevelopment())
}

func TestVersionConsistency(t *testing.T) {
	// Test that all version functions return the same values consistently
	version1 := GetVersion()
	version2 := GetVersion()
	assert.Equal(t, version1, version2)

	buildTime1 := GetBuildTime()
	buildTime2 := GetBuildTime()
	assert.Equal(t, buildTime1, buildTime2)

	gitCommit1 := GetGitCommit()
	gitCommit2 := GetGitCommit()
	assert.Equal(t, gitCommit1, gitCommit2)
}
