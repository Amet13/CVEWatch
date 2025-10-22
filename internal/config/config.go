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

// Package config manages application configuration loading and validation.
//
// It supports multiple configuration sources including YAML files,
// environment variables, and default values. Configuration is validated
// and provides helpful error messages for invalid settings.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cvewatch/internal/types"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// ConfigManager handles application configuration.
//
// It manages loading configuration from YAML files, environment variables,
// and provides sensible defaults. The manager validates all settings before use.
type ConfigManager struct {
	config *types.AppConfig
	viper  *viper.Viper
}

// NewConfigManager creates a new configuration manager with defaults.
//
// Returns:
//   - *ConfigManager: A new configuration manager instance
func NewConfigManager() *ConfigManager {
	return &ConfigManager{
		viper: viper.New(),
	}
}

// SetConfig sets the configuration directly (useful for testing).
//
// Parameters:
//   - config: The configuration to set
func (cm *ConfigManager) SetConfig(config *types.AppConfig) {
	cm.config = config
}

// LoadConfig loads configuration from file and environment variables.
//
// Loads configuration in the following order (later overrides earlier):
// 1. Default values
// 2. Configuration file (YAML)
// 3. Environment variables
//
// Parameters:
//   - configFile: Path to configuration file (empty string uses default search paths)
//
// Returns:
//   - error: Non-nil if configuration loading or validation fails
func (cm *ConfigManager) LoadConfig(configFile string) error {
	cm.setDefaults()
	cm.setupViper(configFile)
	cm.setupEnvironment()

	if err := cm.readConfigFile(); err != nil {
		return err
	}

	return nil
}

// setupViper configures viper for config file discovery
func (cm *ConfigManager) setupViper(configFile string) {
	if configFile != "" {
		cm.viper.SetConfigFile(configFile)

		return
	}

	// Look for config files in common locations
	cm.viper.SetConfigName("config")
	cm.viper.SetConfigType("yaml")
	cm.viper.AddConfigPath(".")
	cm.viper.AddConfigPath("$HOME/.cvewatch")
	cm.viper.AddConfigPath("/etc/cvewatch")

	// Try to find default config in home directory
	cm.tryFindDefaultConfig()
}

// tryFindDefaultConfig attempts to find a default config file
func (cm *ConfigManager) tryFindDefaultConfig() {
	if homeDir, err := os.UserHomeDir(); err == nil {
		defaultConfigPath := filepath.Join(homeDir, ".cvewatch", "config.yaml")
		if _, err := os.Stat(defaultConfigPath); err == nil {
			cm.viper.SetConfigFile(defaultConfigPath)
		}
	}
}

// setupEnvironment configures environment variable handling
func (cm *ConfigManager) setupEnvironment() {
	cm.viper.SetEnvPrefix("CVEWATCH")
	cm.viper.AutomaticEnv()
}

// readConfigFile reads and processes the configuration file
func (cm *ConfigManager) readConfigFile() error {
	if err := cm.viper.ReadInConfig(); err != nil {
		return cm.handleConfigReadError(err)
	}

	return cm.processConfigFile()
}

// handleConfigReadError handles errors when reading config files
func (cm *ConfigManager) handleConfigReadError(err error) error {
	var notFoundErr viper.ConfigFileNotFoundError
	if errors.As(err, &notFoundErr) {
		return cm.createAndValidateDefaultConfig()
	}

	return fmt.Errorf("failed to read config file: %w", err)
}

// createAndValidateDefaultConfig creates a default config and validates it
func (cm *ConfigManager) createAndValidateDefaultConfig() error {
	if err := cm.CreateDefaultConfig(); err != nil {
		return err
	}

	return cm.validateConfig(cm.config)
}

// processConfigFile processes the successfully read config file
func (cm *ConfigManager) processConfigFile() error {
	configFile := cm.viper.ConfigFileUsed()
	if configFile != "" {
		return cm.loadFromFile(configFile)
	}

	return cm.loadFromViper()
}

// loadFromFile loads configuration from a specific file
func (cm *ConfigManager) loadFromFile(configFile string) error {
	data, err := os.ReadFile(filepath.Clean(configFile))
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var config types.AppConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := cm.validateConfig(&config); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	cm.config = &config

	return nil
}

// loadFromViper loads configuration from viper fallback
func (cm *ConfigManager) loadFromViper() error {
	var fallbackConfig types.AppConfig
	if err := cm.viper.Unmarshal(&fallbackConfig); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := cm.validateConfig(&fallbackConfig); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	cm.config = &fallbackConfig

	return nil
}

// setDefaults sets default configuration values
func (cm *ConfigManager) setDefaults() {
	cm.viper.SetDefault("app.name", "CVEWatch")
	cm.viper.SetDefault("app.version", "2.0.0")
	cm.viper.SetDefault("app.logLevel", "info")
	cm.viper.SetDefault("app.timeout", 60)

	cm.viper.SetDefault("nvd.baseUrl", "https://services.nvd.nist.gov/rest/json/cves/2.0")
	cm.viper.SetDefault("nvd.rateLimit", 1000)
	cm.viper.SetDefault("nvd.timeout", 30)
	cm.viper.SetDefault("nvd.retryAttempts", 3)
	cm.viper.SetDefault("nvd.retryDelay", 5)

	cm.viper.SetDefault("search.defaultDate", "today")
	cm.viper.SetDefault("search.defaultMinCvss", 0.0)
	cm.viper.SetDefault("search.defaultMaxCvss", 10.0)
	cm.viper.SetDefault("search.defaultMaxResults", 100)
	cm.viper.SetDefault("search.dateFormat", "2006-01-02")

	cm.viper.SetDefault("output.defaultFormat", "simple")
	cm.viper.SetDefault("output.colors", true)
	cm.viper.SetDefault("output.truncateLength", 100)

	cm.viper.SetDefault("security.enableSslVerification", true)
	cm.viper.SetDefault("security.userAgent", "CVEWatch/2")
}

// CreateDefaultConfig creates a default configuration file
func (cm *ConfigManager) CreateDefaultConfig() error {
	defaultConfig := cm.buildDefaultConfig()

	configDir := cm.getConfigDirectory()

	if err := cm.createConfigDirectory(configDir); err != nil {
		return err
	}

	configFile, err := cm.writeDefaultConfig(configDir, defaultConfig)
	if err != nil {
		return err
	}

	cm.config = defaultConfig
	cm.notifyConfigCreated(configFile)

	return nil
}

// buildDefaultConfig creates the default configuration structure
func (cm *ConfigManager) buildDefaultConfig() *types.AppConfig {
	return &types.AppConfig{
		App:      cm.getDefaultAppSettings(),
		NVD:      cm.getDefaultNVDSettings(),
		Search:   cm.getDefaultSearchSettings(),
		Output:   cm.getDefaultOutputSettings(),
		Security: cm.getDefaultSecuritySettings(),
		Products: getDefaultProducts(),
	}
}

// getDefaultAppSettings returns default application settings
func (cm *ConfigManager) getDefaultAppSettings() types.AppSettings {
	return types.AppSettings{
		Name:     "CVEWatch",
		Version:  "2.0.0",
		LogLevel: "info",
		Timeout:  60,
	}
}

// getDefaultNVDSettings returns default NVD API settings
func (cm *ConfigManager) getDefaultNVDSettings() types.NVDSettings {
	return types.NVDSettings{
		BaseURL:       "https://services.nvd.nist.gov/rest/json/cves/2.0",
		RateLimit:     1000,
		Timeout:       30,
		RetryAttempts: 3,
		RetryDelay:    5,
	}
}

// getDefaultSearchSettings returns default search settings
func (cm *ConfigManager) getDefaultSearchSettings() types.SearchSettings {
	return types.SearchSettings{
		DefaultDate:       "today",
		DefaultMinCVSS:    0.0,
		DefaultMaxCVSS:    10.0,
		DefaultMaxResults: 100,
		DateFormat:        "2006-01-02",
	}
}

// getDefaultOutputSettings returns default output settings
func (cm *ConfigManager) getDefaultOutputSettings() types.OutputSettings {
	return types.OutputSettings{
		DefaultFormat:  "simple",
		Formats:        []string{"simple", "json", "table", "csv", "yaml"},
		Colors:         true,
		TruncateLength: 100,
	}
}

// getDefaultSecuritySettings returns default security settings
func (cm *ConfigManager) getDefaultSecuritySettings() types.SecuritySettings {
	return types.SecuritySettings{
		EnableSSLVerification: true,
		UserAgent:             "Mozilla/5.0 (compatible; CVEWatch/2; +https://github.com/Amet13/CVEWatch)",
		RequestHeaders: map[string]string{
			"Accept":          "application/json",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate",
			"Connection":      "keep-alive",
		},
	}
}

// getConfigDirectory determines the configuration directory path
func (cm *ConfigManager) getConfigDirectory() string {
	configDir := "$HOME/.cvewatch"
	if expanded, err := os.UserHomeDir(); err == nil {
		configDir = filepath.Join(expanded, ".cvewatch")
	}

	return configDir
}

// createConfigDirectory creates the configuration directory
func (cm *ConfigManager) createConfigDirectory(configDir string) error {
	if err := os.MkdirAll(configDir, 0750); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	return nil
}

// writeDefaultConfig writes the default configuration to file
func (cm *ConfigManager) writeDefaultConfig(configDir string, defaultConfig *types.AppConfig) (string, error) {
	configFile := filepath.Join(configDir, "config.yaml")
	data, err := yaml.Marshal(defaultConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal default config: %w", err)
	}

	if err := os.WriteFile(configFile, data, 0o600); err != nil {
		return "", fmt.Errorf("failed to write default config: %w", err)
	}

	// Ensure proper permissions even if umask was set
	if err := os.Chmod(configFile, 0o600); err != nil {
		return "", fmt.Errorf("failed to set config file permissions: %w", err)
	}

	return configFile, nil
}

// notifyConfigCreated notifies that the configuration file was created
func (cm *ConfigManager) notifyConfigCreated(configFile string) {
	fmt.Fprintf(os.Stderr, "Created default configuration file: %s\n", configFile)
}

// validateConfig validates the configuration
func (cm *ConfigManager) validateConfig(config *types.AppConfig) error {
	if err := cm.validateAppSettings(config.App); err != nil {
		return fmt.Errorf("app settings: %w", err)
	}

	if err := cm.validateNVDSettings(config.NVD); err != nil {
		return fmt.Errorf("NVD settings: %w", err)
	}

	if err := cm.validateSearchSettings(config.Search); err != nil {
		return fmt.Errorf("search settings: %w", err)
	}

	if err := cm.validateProducts(config.Products); err != nil {
		return fmt.Errorf("products: %w", err)
	}

	return nil
}

// validateAppSettings validates application-specific settings
func (cm *ConfigManager) validateAppSettings(app types.AppSettings) error {
	if app.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}
	if app.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}

	return nil
}

// validateNVDSettings validates NVD API settings
func (cm *ConfigManager) validateNVDSettings(nvd types.NVDSettings) error {
	if nvd.BaseURL == "" {
		return fmt.Errorf("base URL cannot be empty")
	}

	// Validate URL format
	if !strings.HasPrefix(nvd.BaseURL, "https://") {
		return fmt.Errorf("base URL must use HTTPS: %s", nvd.BaseURL)
	}

	if nvd.RateLimit <= 0 {
		return fmt.Errorf("rate limit must be positive")
	}
	if nvd.RateLimit > 10000 {
		return fmt.Errorf("rate limit cannot exceed 10000 requests per hour")
	}

	if nvd.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if nvd.Timeout > 300 {
		return fmt.Errorf("timeout cannot exceed 300 seconds")
	}

	if nvd.RetryAttempts < 0 || nvd.RetryAttempts > 10 {
		return fmt.Errorf("retry attempts must be between 0 and 10")
	}

	if nvd.RetryDelay < 0 || nvd.RetryDelay > 60 {
		return fmt.Errorf("retry delay must be between 0 and 60 seconds")
	}

	return nil
}

// validateSearchSettings validates search configuration
func (cm *ConfigManager) validateSearchSettings(search types.SearchSettings) error {
	if search.DefaultMinCVSS < 0 || search.DefaultMinCVSS > 10 {
		return fmt.Errorf("default min CVSS must be between 0 and 10")
	}
	if search.DefaultMaxCVSS < 0 || search.DefaultMaxCVSS > 10 {
		return fmt.Errorf("default max CVSS must be between 0 and 10")
	}
	if search.DefaultMinCVSS > search.DefaultMaxCVSS {
		return fmt.Errorf("default min CVSS cannot be greater than default max CVSS")
	}
	if search.DefaultMaxResults <= 0 || search.DefaultMaxResults > 2000 {
		return fmt.Errorf("default max results must be between 1 and 2000")
	}

	return nil
}

// validateProducts validates product configurations
func (cm *ConfigManager) validateProducts(products []types.Product) error {
	if len(products) == 0 {
		return fmt.Errorf("at least one product must be configured")
	}

	for idx, product := range products {
		if err := cm.validateProduct(idx, product); err != nil {
			return err
		}
	}

	return nil
}

// validateProduct validates a single product configuration
func (cm *ConfigManager) validateProduct(idx int, product types.Product) error {
	if product.Name == "" {
		return fmt.Errorf("product %d: name cannot be empty", idx+1)
	}
	if len(product.Keywords) == 0 {
		return fmt.Errorf("product %d: at least one keyword must be specified", idx+1)
	}
	if product.Priority == "" {
		return fmt.Errorf("product %d: priority must be specified", idx+1)
	}

	return nil
}

// GetConfig returns the current configuration
func (cm *ConfigManager) GetConfig() *types.AppConfig {
	return cm.config
}

// GetProductByName returns a product by name
func (cm *ConfigManager) GetProductByName(name string) *types.Product {
	if cm.config == nil {
		return nil
	}
	for _, product := range cm.config.Products {
		if product.Name == name {
			return &product
		}
	}

	return nil
}

// GetProductsByPriority returns products by priority
func (cm *ConfigManager) GetProductsByPriority(priority string) []types.Product {
	var products []types.Product
	if cm.config == nil {
		return products
	}
	for _, product := range cm.config.Products {
		if product.Priority == priority {
			products = append(products, product)
		}
	}

	return products
}

// getDefaultProducts returns default product configurations
func getDefaultProducts() []types.Product {
	return []types.Product{
		{
			Name:        "Linux Kernel",
			Keywords:    []string{"linux", "kernel", "linux kernel"},
			CPEPatterns: []string{"cpe:2.3:o:*:linux:*:*:*:*:*:*:*"},
			Description: "Linux operating system kernel",
			Priority:    "high",
		},
		{
			Name:        "OpenSSL",
			Keywords:    []string{"openssl", "ssl", "tls", "cryptography"},
			CPEPatterns: []string{"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*"},
			Description: "OpenSSL cryptography library",
			Priority:    "critical",
		},
		{
			Name:        "Apache HTTP Server",
			Keywords:    []string{"apache", "httpd", "web server", "http server"},
			CPEPatterns: []string{"cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*"},
			Description: "Apache HTTP web server",
			Priority:    "high",
		},
		{
			Name:        "PHP",
			Keywords:    []string{"php", "web", "scripting", "language"},
			CPEPatterns: []string{"cpe:2.3:a:php:php:*:*:*:*:*:*:*"},
			Description: "PHP scripting language",
			Priority:    "high",
		},
		{
			Name:        "Python",
			Keywords:    []string{"python", "scripting", "programming", "language"},
			CPEPatterns: []string{"cpe:2.3:a:python:python:*:*:*:*:*:*:*"},
			Description: "Python programming language",
			Priority:    "medium",
		},
	}
}

// LoadCommandLineFlags loads and validates command line flags
func LoadCommandLineFlags() (*types.CommandLineFlags, error) {
	flags := loadFlagsFromViper()
	setDefaultFlags(flags)

	if err := validateDateFlag(flags); err != nil {
		return nil, fmt.Errorf("date validation: %w", err)
	}

	if err := validateCVSSFlags(flags); err != nil {
		return nil, fmt.Errorf("CVSS validation: %w", err)
	}

	if err := validateMaxResultsFlag(flags); err != nil {
		return nil, fmt.Errorf("max results validation: %w", err)
	}

	return flags, nil
}

// loadFlagsFromViper loads all flags from viper configuration
func loadFlagsFromViper() *types.CommandLineFlags {
	return &types.CommandLineFlags{
		Date:         viper.GetString("date"),
		MinCVSS:      viper.GetFloat64("min-cvss"),
		MaxCVSS:      viper.GetFloat64("max-cvss"),
		OutputFormat: viper.GetString("output"),
		MaxResults:   viper.GetInt("max-results"),
		APIKey:       viper.GetString("api-key"),
		Verbose:      viper.GetBool("verbose"),
		Quiet:        viper.GetBool("quiet"),
		IncludeCPE:   viper.GetBool("include-cpe"),
		IncludeRefs:  viper.GetBool("include-refs"),
	}
}

// setDefaultFlags sets default values for flags if not provided
func setDefaultFlags(flags *types.CommandLineFlags) {
	if flags.MaxResults == 0 {
		flags.MaxResults = 100
	}
	if flags.OutputFormat == "" {
		flags.OutputFormat = "simple"
	}

	// Set default date to today if not specified, but allow empty dates for testing
	if flags.Date == "" && !viper.IsSet("date") {
		flags.Date = time.Now().Format("2006-01-02")
	}
}

// validateDateFlag validates the date format if specified
func validateDateFlag(flags *types.CommandLineFlags) error {
	if flags.Date == "" {
		return nil
	}

	if _, err := time.Parse("2006-01-02", flags.Date); err != nil {
		return fmt.Errorf("invalid date format: %s (expected YYYY-MM-DD)", flags.Date)
	}

	return nil
}

// validateCVSSFlags validates CVSS score ranges
func validateCVSSFlags(flags *types.CommandLineFlags) error {
	if flags.MinCVSS < 0 || flags.MinCVSS > 10 {
		return fmt.Errorf("invalid minimum CVSS score: %f (must be between 0 and 10)", flags.MinCVSS)
	}

	if flags.MaxCVSS > 0 && (flags.MaxCVSS < 0 || flags.MaxCVSS > 10) {
		return fmt.Errorf("invalid maximum CVSS score: %f (must be between 0 and 10)", flags.MaxCVSS)
	}

	if flags.MaxCVSS > 0 && flags.MinCVSS > flags.MaxCVSS {
		return fmt.Errorf("minimum CVSS score (%f) cannot be greater than maximum CVSS score (%f)", flags.MinCVSS, flags.MaxCVSS)
	}

	return nil
}

// validateMaxResultsFlag validates the max results flag
func validateMaxResultsFlag(flags *types.CommandLineFlags) error {
	if flags.MaxResults < 1 || flags.MaxResults > 2000 {
		return fmt.Errorf("invalid max results: %d (must be between 1 and 2000)", flags.MaxResults)
	}

	return nil
}
