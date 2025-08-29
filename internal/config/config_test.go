package config

import (
	"os"
	"testing"

	"cvewatch/internal/types"

	"github.com/stretchr/testify/assert"
)

func TestNewConfigManager(t *testing.T) {
	cm := NewConfigManager()
	assert.NotNil(t, cm)
	assert.NotNil(t, cm.viper)
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
	cm := NewConfigManager()

	// Test GetProductByName with nil config
	product := cm.GetProductByName("nonexistent")
	assert.Nil(t, product)

	// Test GetProductsByPriority with nil config
	products := cm.GetProductsByPriority("high")
	assert.Empty(t, products)

	// Test GetConfig with nil config
	config := cm.GetConfig()
	assert.Nil(t, config)
}

func TestCreateDefaultConfig(t *testing.T) {
	cm := NewConfigManager()

	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "TestCreateDefaultConfig")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create the default config
	err = cm.CreateDefaultConfig()
	assert.NoError(t, err)

	// Verify the config was created
	assert.NotNil(t, cm.config)
	assert.Equal(t, "CVEWatch", cm.config.App.Name)
	assert.Equal(t, "2.0.0", cm.config.App.Version)
	assert.Equal(t, "https://services.nvd.nist.gov/rest/json/cves/2.0", cm.config.NVD.BaseURL)

	// Verify products were created
	assert.NotEmpty(t, cm.config.Products)

	// Verify output settings
	assert.NotEmpty(t, cm.config.Output.Formats)
	assert.Contains(t, cm.config.Output.Formats, "simple")
	assert.Contains(t, cm.config.Output.Formats, "json")

	// Verify security settings
	assert.NotEmpty(t, cm.config.Security.UserAgent)
	assert.NotEmpty(t, cm.config.Security.RequestHeaders)
}

func TestValidateConfig(t *testing.T) {
	cm := NewConfigManager()

	// Test with valid config
	validConfig := &types.AppConfig{
		App: types.AppSettings{
			Name:     "Test",
			Version:  "1.0.0",
			LogLevel: "info",
			Timeout:  30,
		},
		NVD: types.NVDSettings{
			BaseURL:       "https://test.example.com",
			RateLimit:     1000,
			Timeout:       30,
			RetryAttempts: 3,
			RetryDelay:    5,
		},
		Search: types.SearchSettings{
			DefaultDate:       "today",
			DefaultMinCVSS:    0.0,
			DefaultMaxCVSS:    10.0,
			DefaultMaxResults: 100,
			DateFormat:        "2006-01-02",
		},
		Output: types.OutputSettings{
			DefaultFormat:  "simple",
			Formats:        []string{"simple", "json"},
			Colors:         true,
			TruncateLength: 100,
		},
		Security: types.SecuritySettings{
			EnableSSLVerification: true,
			UserAgent:             "Test/1.0",
			RequestHeaders:        map[string]string{"Accept": "application/json"},
		},
		Products: []types.Product{
			{
				Name:        "Test Product",
				Keywords:    []string{"test"},
				CPEPatterns: []string{"cpe:2.3:a:test:product:*:*:*:*:*:*:*"},
				Description: "Test product",
				Priority:    "medium",
			},
		},
	}

	err := cm.validateConfig(validConfig)
	assert.NoError(t, err)

	// Test with invalid config (missing NVD base URL)
	invalidConfig := &types.AppConfig{
		App: types.AppSettings{
			Name:     "Test",
			Version:  "1.0.0",
			LogLevel: "info",
			Timeout:  30,
		},
		NVD: types.NVDSettings{
			BaseURL: "", // Invalid: empty base URL
		},
	}

	err = cm.validateConfig(invalidConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "NVD base URL cannot be empty")
}

func TestLoadCommandLineFlags(t *testing.T) {
	// Test with valid flags
	flags, err := LoadCommandLineFlags()
	assert.NoError(t, err)
	assert.NotNil(t, flags)

	// Test basic validation
	assert.GreaterOrEqual(t, flags.MinCVSS, 0.0)
	assert.LessOrEqual(t, flags.MaxCVSS, 10.0)
	assert.GreaterOrEqual(t, flags.MaxResults, 1)
	assert.LessOrEqual(t, flags.MaxResults, 2000)
}
