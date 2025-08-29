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
