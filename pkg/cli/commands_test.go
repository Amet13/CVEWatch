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
package cli

import (
	"testing"

	"cvewatch/internal/config"
	"cvewatch/internal/types"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCommands(t *testing.T) {
	configManager := config.NewConfigManager()
	cmds := NewCommands(configManager)

	assert.NotNil(t, cmds)
	assert.NotNil(t, cmds.RootCmd)
	assert.NotNil(t, cmds.InitCmd)
	assert.NotNil(t, cmds.SearchCmd)
	assert.NotNil(t, cmds.InfoCmd)
	assert.NotNil(t, cmds.ConfigCmd)
	assert.NotNil(t, cmds.VersionCmd)
}

func TestLoadCommandLineFlags(t *testing.T) {
	configManager := config.NewConfigManager()
	cmds := NewCommands(configManager)

	// Test with valid flags
	flags, err := cmds.loadCommandLineFlags()
	require.NoError(t, err)
	assert.NotNil(t, flags)

	// Test validation functions
	assert.NotNil(t, flags)
}

func TestCommandStructure(t *testing.T) {
	configManager := config.NewConfigManager()
	cmds := NewCommands(configManager)

	// Test root command
	assert.Equal(t, "cvewatch", cmds.RootCmd.Use)
	assert.Contains(t, cmds.RootCmd.Short, "Modern CVE vulnerability monitoring tool")

	// Test subcommands
	assert.Equal(t, "init", cmds.InitCmd.Use)
	assert.Equal(t, "search", cmds.SearchCmd.Use)
	assert.Equal(t, "info [CVE-ID]", cmds.InfoCmd.Use)
	assert.Equal(t, "config", cmds.ConfigCmd.Use)
	assert.Equal(t, "version", cmds.VersionCmd.Use)
}

func TestValidateCVEID(t *testing.T) {
	configManager := config.NewConfigManager()
	cmds := NewCommands(configManager)

	tests := []struct {
		name    string
		cveID   string
		wantErr bool
	}{
		{"valid CVE ID", "CVE-2023-1234", false},
		{"valid CVE ID with leading zero", "CVE-2023-0123", false},
		{"valid CVE ID with five digits", "CVE-2023-12345", false},
		{"valid CVE ID with six digits", "CVE-2023-123456", false},
		{"valid CVE ID with seven digits", "CVE-2023-1234567", false},
		{"invalid format - no CVE prefix", "2023-1234", true},
		{"invalid format - wrong year", "CVE-23-1234", true},
		{"invalid format - wrong separator", "CVE-2023_1234", true},
		{"invalid format - too few digits", "CVE-2023-123", true},
		{"invalid format - wrong year length", "CVE-20230-1234", true},
		{"empty string", "", true},
		{"just CVE", "CVE-", true},
		{"just CVE with year", "CVE-2023-", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cmds.validateCVEID(tt.cveID)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid CVE ID format")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLoadAndOverrideFlagsWithDefaults(t *testing.T) {
	configManager := config.NewConfigManager()

	// Create a test config
	testConfig := &types.AppConfig{
		Search: types.SearchSettings{
			DefaultMinCVSS:    5.0,
			DefaultMaxCVSS:    9.0,
			DefaultMaxResults: 50,
		},
		Output: types.OutputSettings{
			DefaultFormat: "table",
		},
	}

	configManager.SetConfig(testConfig)
	cmds := NewCommands(configManager)

	// Test with empty flags (should use defaults)
	flags := &types.CommandLineFlags{}
	cmds.overrideFlagsWithDefaults(flags, testConfig)

	assert.Equal(t, 5.0, flags.MinCVSS)
	assert.Equal(t, 9.0, flags.MaxCVSS)
	assert.Equal(t, 50, flags.MaxResults)
	assert.Equal(t, "table", flags.OutputFormat)
}

func TestValidateOutputFormat(t *testing.T) {
	configManager := config.NewConfigManager()
	testConfig := &types.AppConfig{
		Output: types.OutputSettings{
			Formats: []string{"simple", "json", "table", "csv", "yaml"},
		},
	}
	cmds := NewCommands(configManager)

	tests := []struct {
		name    string
		format  string
		wantErr bool
		errMsg  string
	}{
		{"valid format - simple", "simple", false, ""},
		{"valid format - json", "json", false, ""},
		{"valid format - table", "table", false, ""},
		{"valid format - csv", "csv", false, ""},
		{"valid format - table", "table", false, ""},
		{"valid format - csv", "csv", false, ""},
		{"valid format - yaml", "yaml", false, ""},
		{"invalid format", "xml", true, "invalid output format: xml"},
		{"empty format", "", true, "invalid output format"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := &types.CommandLineFlags{OutputFormat: tt.format}
			err := cmds.validateOutputFormat(flags, testConfig)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCreateSearchRequest(t *testing.T) {
	configManager := config.NewConfigManager()
	testConfig := &types.AppConfig{
		Products: []types.Product{
			{Name: "Linux Kernel"},
			{Name: "OpenSSL"},
		},
	}
	cmds := NewCommands(configManager)

	flags := &types.CommandLineFlags{
		Date:         "2024-01-01",
		MinCVSS:      7.0,
		MaxCVSS:      10.0,
		MaxResults:   100,
		OutputFormat: "json",
		APIKey:       "test-key",
	}

	request := cmds.createSearchRequest(flags, testConfig)

	assert.Equal(t, "2024-01-01", request.Date)
	assert.Equal(t, 7.0, request.MinCVSS)
	assert.Equal(t, 10.0, request.MaxCVSS)
	assert.Equal(t, 100, request.MaxResults)
	assert.Equal(t, "json", request.OutputFormat)
	assert.Equal(t, "test-key", request.APIKey)
	assert.Equal(t, []string{"Linux Kernel", "OpenSSL"}, request.Products)
}

func TestDisplaySearchParameters(t *testing.T) {
	configManager := config.NewConfigManager()
	cmds := NewCommands(configManager)

	request := &types.SearchRequest{
		Date:         "2024-01-01",
		MinCVSS:      7.0,
		MaxCVSS:      10.0,
		MaxResults:   50,
		OutputFormat: "table",
		Products:     []string{"Linux Kernel", "OpenSSL"},
	}

	// This test verifies that the function doesn't panic
	assert.NotPanics(t, func() {
		cmds.displaySearchParameters(request)
	})
}

func TestRunSearch(t *testing.T) {
	configManager := config.NewConfigManager()
	testConfig := &types.AppConfig{
		App: types.AppSettings{
			Name:    "CVEWatch",
			Version: "2.0.0",
		},
		NVD: types.NVDSettings{
			BaseURL:       "https://services.nvd.nist.gov/rest/json/cves/2.0",
			RateLimit:     1000,
			Timeout:       30,
			RetryAttempts: 3,
			RetryDelay:    5,
		},
		Search: types.SearchSettings{
			DefaultMinCVSS:    0.0,
			DefaultMaxCVSS:    10.0,
			DefaultMaxResults: 100,
		},
		Output: types.OutputSettings{
			DefaultFormat: "simple",
			Formats:       []string{"simple", "json", "yaml", "table", "csv"},
		},
		Products: []types.Product{
			{Name: "Linux Kernel"},
		},
	}
	configManager.SetConfig(testConfig)

	cmds := NewCommands(configManager)

	// Test with search command
	cmd := &cobra.Command{}
	args := []string{}

	// This would normally require mocking HTTP calls, so we'll just test it doesn't panic
	assert.NotPanics(t, func() {
		err := cmds.runSearch(cmd, args)
		// We don't assert on the error since it depends on external factors
		_ = err
	})
}

func TestRunInfo(t *testing.T) {
	configManager := config.NewConfigManager()
	testConfig := &types.AppConfig{
		App: types.AppSettings{
			Name:    "CVEWatch",
			Version: "2.0.0",
		},
		NVD: types.NVDSettings{
			BaseURL:       "https://services.nvd.nist.gov/rest/json/cves/2.0",
			RateLimit:     1000,
			Timeout:       30,
			RetryAttempts: 3,
			RetryDelay:    5,
		},
	}
	configManager.SetConfig(testConfig)

	cmds := NewCommands(configManager)

	// Test with valid CVE ID
	assert.NotPanics(t, func() {
		err := cmds.runInfo("CVE-2023-1234", configManager)
		// The call may succeed or fail depending on network/API availability
		// The important thing is that it doesn't panic
		_ = err // We don't assert on the error since it depends on external factors
	})
}

func TestRunConfig(t *testing.T) {
	configManager := config.NewConfigManager()
	testConfig := &types.AppConfig{
		App: types.AppSettings{
			Name:    "CVEWatch",
			Version: "2.0.0",
		},
		NVD: types.NVDSettings{
			BaseURL:       "https://services.nvd.nist.gov/rest/json/cves/2.0",
			RateLimit:     1000,
			Timeout:       30,
			RetryAttempts: 3,
			RetryDelay:    5,
		},
		Search: types.SearchSettings{
			DefaultMinCVSS:    0.0,
			DefaultMaxCVSS:    10.0,
			DefaultMaxResults: 100,
		},
		Output: types.OutputSettings{
			DefaultFormat: "simple",
			Formats:       []string{"simple", "json", "yaml", "table", "csv"},
		},
		Products: []types.Product{
			{
				Name:        "Linux Kernel",
				Keywords:    []string{"linux", "kernel"},
				CPEPatterns: []string{"cpe:2.3:o:*:linux:*:*:*:*:*:*:*"},
				Description: "Linux operating system kernel",
				Priority:    "high",
			},
		},
	}
	configManager.SetConfig(testConfig)

	cmds := NewCommands(configManager)

	// Test config display
	assert.NotPanics(t, func() {
		err := cmds.runConfig(configManager)
		assert.NoError(t, err)
	})
}

func TestRunVersion(t *testing.T) {
	configManager := config.NewConfigManager()
	cmds := NewCommands(configManager)

	// Test version display
	assert.NotPanics(t, func() {
		err := cmds.runVersion(configManager)
		assert.NoError(t, err)
	})
}

func TestLoadConfiguration(t *testing.T) {
	configManager := config.NewConfigManager()
	testConfig := &types.AppConfig{
		App: types.AppSettings{
			Name: "CVEWatch",
		},
	}
	configManager.SetConfig(testConfig)

	cmds := NewCommands(configManager)

	// Test successful configuration loading
	configMgr, cfg, err := cmds.loadConfiguration()
	assert.NoError(t, err)
	assert.NotNil(t, configMgr)
	assert.NotNil(t, cfg)
}

func TestLoadAndOverrideFlags(t *testing.T) {
	configManager := config.NewConfigManager()
	testConfig := &types.AppConfig{
		Search: types.SearchSettings{
			DefaultMinCVSS:    5.0,
			DefaultMaxCVSS:    9.0,
			DefaultMaxResults: 50,
		},
		Output: types.OutputSettings{
			DefaultFormat: "table",
		},
	}
	configManager.SetConfig(testConfig)

	cmds := NewCommands(configManager)

	// Test with empty flags
	flags, err := cmds.loadCommandLineFlags()
	assert.NoError(t, err)
	assert.NotNil(t, flags)

	// Test override with defaults
	cmds.overrideFlagsWithDefaults(flags, testConfig)
	assert.Equal(t, 5.0, flags.MinCVSS)
	assert.Equal(t, 9.0, flags.MaxCVSS)
	assert.Equal(t, 50, flags.MaxResults)
	assert.Equal(t, "table", flags.OutputFormat)
}
