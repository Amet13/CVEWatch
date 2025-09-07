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
package config

import (
	"os"
	"testing"

	"cvewatch/internal/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfigManager(t *testing.T) {
	configMgr := NewConfigManager()
	assert.NotNil(t, configMgr)
	assert.NotNil(t, configMgr.viper)
}

func TestGetDefaultProducts(t *testing.T) {
	products := getDefaultProducts()
	assert.NotEmpty(t, products)

	// Check that we have the expected products
	productNames := make(map[string]bool)
	for _, p := range products {
		productNames[p.Name] = true
	}

	assert.True(t, productNames["Linux Kernel"])
	assert.True(t, productNames["OpenSSL"])
	assert.True(t, productNames["Apache HTTP Server"])
	assert.True(t, productNames["PHP"])
	assert.True(t, productNames["Python"])
}

func TestConfigManagerMethods(t *testing.T) {
	configMgr := NewConfigManager()

	// Test GetProductByName with nil config
	product := configMgr.GetProductByName("nonexistent")
	assert.Nil(t, product)

	// Test GetProductsByPriority with nil config
	products := configMgr.GetProductsByPriority("high")
	assert.Empty(t, products)

	// Test GetConfig with nil config
	config := configMgr.GetConfig()
	assert.Nil(t, config)
}

func TestCreateDefaultConfig(t *testing.T) {
	configMgr := NewConfigManager()

	// Create a temporary directory for testing
	tempDir := t.TempDir()
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Errorf("failed to remove temp dir: %v", err)
		}
	}()

	// Create the default config
	err := configMgr.CreateDefaultConfig()
	require.NoError(t, err)

	// Verify the config was created
	assert.NotNil(t, configMgr.config)
	assert.Equal(t, "CVEWatch", configMgr.config.App.Name)
	assert.Equal(t, "2.0.0", configMgr.config.App.Version)
	assert.Equal(t, "https://services.nvd.nist.gov/rest/json/cves/2.0", configMgr.config.NVD.BaseURL)

	// Verify products were created
	assert.NotEmpty(t, configMgr.config.Products)

	// Verify output settings
	assert.NotEmpty(t, configMgr.config.Output.Formats)
	assert.Contains(t, configMgr.config.Output.Formats, "simple")
	assert.Contains(t, configMgr.config.Output.Formats, "json")

	// Verify security settings
	assert.NotEmpty(t, configMgr.config.Security.UserAgent)
	assert.NotEmpty(t, configMgr.config.Security.RequestHeaders)
}

func TestValidateConfig(t *testing.T) {
	configMgr := NewConfigManager()

	t.Run("valid config", func(t *testing.T) {
		validConfig := createValidTestConfig()
		err := configMgr.validateConfig(validConfig)
		assert.NoError(t, err)
	})

	t.Run("invalid config - missing NVD base URL", func(t *testing.T) {
		invalidConfig := createInvalidTestConfig()
		err := configMgr.validateConfig(invalidConfig)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "NVD settings: base URL cannot be empty")
	})
}

// createValidTestConfig creates a valid test configuration
func createValidTestConfig() *types.AppConfig {
	return &types.AppConfig{
		App:      createValidAppSettings(),
		NVD:      createValidNVDSettings(),
		Search:   createValidSearchSettings(),
		Output:   createValidOutputSettings(),
		Security: createValidSecuritySettings(),
		Products: createValidProducts(),
	}
}

// createValidAppSettings creates valid app settings for testing
func createValidAppSettings() types.AppSettings {
	return types.AppSettings{
		Name:     "Test",
		Version:  "1.0.0",
		LogLevel: "info",
		Timeout:  30,
	}
}

// createValidNVDSettings creates valid NVD settings for testing
func createValidNVDSettings() types.NVDSettings {
	return types.NVDSettings{
		BaseURL:       "https://test.example.com",
		RateLimit:     1000,
		Timeout:       30,
		RetryAttempts: 3,
		RetryDelay:    5,
	}
}

// createValidSearchSettings creates valid search settings for testing
func createValidSearchSettings() types.SearchSettings {
	return types.SearchSettings{
		DefaultDate:       "today",
		DefaultMinCVSS:    0.0,
		DefaultMaxCVSS:    10.0,
		DefaultMaxResults: 100,
		DateFormat:        "2006-01-02",
	}
}

// createValidOutputSettings creates valid output settings for testing
func createValidOutputSettings() types.OutputSettings {
	return types.OutputSettings{
		DefaultFormat:  "simple",
		Formats:        []string{"simple", "json"},
		Colors:         true,
		TruncateLength: 100,
	}
}

// createValidSecuritySettings creates valid security settings for testing
func createValidSecuritySettings() types.SecuritySettings {
	return types.SecuritySettings{
		EnableSSLVerification: true,
		UserAgent:             "Test/1.0",
		RequestHeaders:        map[string]string{"Accept": "application/json"},
	}
}

// createValidProducts creates valid products for testing
func createValidProducts() []types.Product {
	return []types.Product{
		{
			Name:        "Test Product",
			Keywords:    []string{"test"},
			CPEPatterns: []string{"cpe:2.3:a:test:product:*:*:*:*:*:*:*"},
			Description: "Test product",
			Priority:    "medium",
		},
	}
}

// createInvalidTestConfig creates an invalid test configuration
func createInvalidTestConfig() *types.AppConfig {
	return &types.AppConfig{
		App: createValidAppSettings(),
		NVD: types.NVDSettings{
			BaseURL: "", // Invalid: empty base URL
		},
	}
}

func TestLoadCommandLineFlags(t *testing.T) {
	// Test with valid flags
	flags, err := LoadCommandLineFlags()
	require.NoError(t, err)
	assert.NotNil(t, flags)

	// Test basic validation
	assert.GreaterOrEqual(t, flags.MinCVSS, 0.0)
	assert.LessOrEqual(t, flags.MaxCVSS, 10.0)
	assert.GreaterOrEqual(t, flags.MaxResults, 1)
	assert.LessOrEqual(t, flags.MaxResults, 2000)
}
