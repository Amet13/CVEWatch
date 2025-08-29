package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"cvewatch/internal/types"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// ConfigManager handles application configuration
type ConfigManager struct {
	config *types.AppConfig
	viper  *viper.Viper
}

// NewConfigManager creates a new configuration manager
func NewConfigManager() *ConfigManager {
	return &ConfigManager{
		viper: viper.New(),
	}
}

// SetConfig sets the configuration directly (useful for testing)
func (cm *ConfigManager) SetConfig(config *types.AppConfig) {
	cm.config = config
}

// LoadConfig loads configuration from file and environment variables
func (cm *ConfigManager) LoadConfig(configFile string) error {
	// Set default configuration
	cm.setDefaults()

	// Set config file
	if configFile != "" {
		cm.viper.SetConfigFile(configFile)
	} else {
		// Look for config files in common locations
		cm.viper.SetConfigName("config")
		cm.viper.SetConfigType("yaml")
		cm.viper.AddConfigPath(".")
		cm.viper.AddConfigPath("$HOME/.cvewatch")
		cm.viper.AddConfigPath("/etc/cvewatch")

		// If no specific config file is specified, try to find the default one
		if homeDir, err := os.UserHomeDir(); err == nil {
			defaultConfigPath := filepath.Join(homeDir, ".cvewatch", "config.yaml")
			if _, err := os.Stat(defaultConfigPath); err == nil {
				// Default config exists, set it as the config file
				cm.viper.SetConfigFile(defaultConfigPath)
			}
		}
	}

	// Read environment variables
	cm.viper.SetEnvPrefix("CVEWATCH")
	cm.viper.AutomaticEnv()

	// Try to read config file
	if err := cm.viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Create default config if none exists
			if err := cm.CreateDefaultConfig(); err != nil {
				return err
			}
			// After creating default config, validate it
			return cm.validateConfig(cm.config)
		}
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// If we got here, we have a config file, so unmarshal it
	// Since viper unmarshaling seems to have issues, let's use direct YAML unmarshaling
	configFile = cm.viper.ConfigFileUsed()
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			return fmt.Errorf("failed to read config file: %w", err)
		}

		var config types.AppConfig
		if err := yaml.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("failed to unmarshal config: %w", err)
		}

		// Validate configuration
		if err := cm.validateConfig(&config); err != nil {
			return fmt.Errorf("config validation failed: %w", err)
		}

		cm.config = &config
		return nil
	}

	// Fallback to viper unmarshaling if no config file was used
	var fallbackConfig types.AppConfig
	if err := cm.viper.Unmarshal(&fallbackConfig); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
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
	cm.viper.SetDefault("app.log_level", "info")
	cm.viper.SetDefault("app.timeout", 60)

	cm.viper.SetDefault("nvd.base_url", "https://services.nvd.nist.gov/rest/json/cves/1.1")
	cm.viper.SetDefault("nvd.rate_limit", 1000)
	cm.viper.SetDefault("nvd.timeout", 30)
	cm.viper.SetDefault("nvd.retry_attempts", 3)
	cm.viper.SetDefault("nvd.retry_delay", 5)

	cm.viper.SetDefault("search.default_date", "today")
	cm.viper.SetDefault("search.default_min_cvss", 0.0)
	cm.viper.SetDefault("search.default_max_cvss", 10.0)
	cm.viper.SetDefault("search.default_max_results", 100)
	cm.viper.SetDefault("search.date_format", "2006-01-02")

	cm.viper.SetDefault("output.default_format", "simple")
	cm.viper.SetDefault("output.colors", true)
	cm.viper.SetDefault("output.truncate_length", 100)

	cm.viper.SetDefault("security.enable_ssl_verification", true)
	cm.viper.SetDefault("security.user_agent", "CVEWatch/2.0.0")
}

// CreateDefaultConfig creates a default configuration file
func (cm *ConfigManager) CreateDefaultConfig() error {
	defaultConfig := &types.AppConfig{
		App: types.AppSettings{
			Name:     "CVEWatch",
			Version:  "2.0.0",
			LogLevel: "info",
			Timeout:  60,
		},
		NVD: types.NVDSettings{
			BaseURL:       "https://services.nvd.nist.gov/rest/json/cves/2.0",
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
			Formats:        []string{"simple", "json", "table", "csv", "yaml"},
			Colors:         true,
			TruncateLength: 100,
		},
		Security: types.SecuritySettings{
			EnableSSLVerification: true,
			UserAgent:             "Mozilla/5.0 (compatible; CVEWatch/2.0.0; +https://github.com/yourusername/cvewatch)",
			RequestHeaders: map[string]string{
				"Accept":          "application/json",
				"Accept-Language": "en-US,en;q=0.9",
				"Accept-Encoding": "gzip, deflate",
				"Connection":      "keep-alive",
			},
		},
		Products: getDefaultProducts(),
	}

	// Create config directory if it doesn't exist
	configDir := "$HOME/.cvewatch"
	if expanded, err := os.UserHomeDir(); err == nil {
		configDir = filepath.Join(expanded, ".cvewatch")
	}

	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write default config
	configFile := filepath.Join(configDir, "config.yaml")
	data, err := yaml.Marshal(defaultConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal default config: %w", err)
	}

	if err := os.WriteFile(configFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write default config: %w", err)
	}

	fmt.Printf("Created default configuration file: %s\n", configFile)

	// Set the config directly instead of trying to unmarshal
	cm.config = defaultConfig
	return nil
}

// validateConfig validates the configuration
func (cm *ConfigManager) validateConfig(config *types.AppConfig) error {
	// Validate app settings
	if config.App.Name == "" {
		return fmt.Errorf("app name cannot be empty")
	}
	if config.App.Timeout <= 0 {
		return fmt.Errorf("app timeout must be positive")
	}

	// Validate NVD settings
	if config.NVD.BaseURL == "" {
		return fmt.Errorf("NVD base URL cannot be empty")
	}
	if config.NVD.RateLimit <= 0 {
		return fmt.Errorf("NVD rate limit must be positive")
	}
	if config.NVD.Timeout <= 0 {
		return fmt.Errorf("NVD timeout must be positive")
	}

	// Validate search settings
	if config.Search.DefaultMinCVSS < 0 || config.Search.DefaultMinCVSS > 10 {
		return fmt.Errorf("default min CVSS must be between 0 and 10")
	}
	if config.Search.DefaultMaxCVSS < 0 || config.Search.DefaultMaxCVSS > 10 {
		return fmt.Errorf("default max CVSS must be between 0 and 10")
	}
	if config.Search.DefaultMinCVSS > config.Search.DefaultMaxCVSS {
		return fmt.Errorf("default min CVSS cannot be greater than default max CVSS")
	}
	if config.Search.DefaultMaxResults <= 0 || config.Search.DefaultMaxResults > 2000 {
		return fmt.Errorf("default max results must be between 1 and 2000")
	}

	// Validate products
	if len(config.Products) == 0 {
		return fmt.Errorf("at least one product must be configured")
	}

	for i, product := range config.Products {
		if product.Name == "" {
			return fmt.Errorf("product %d: name cannot be empty", i+1)
		}
		if len(product.Keywords) == 0 {
			return fmt.Errorf("product %d: at least one keyword must be specified", i+1)
		}
		if product.Priority == "" {
			return fmt.Errorf("product %d: priority must be specified", i+1)
		}
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
	flags := &types.CommandLineFlags{
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

	// Set defaults if not provided
	if flags.MaxResults == 0 {
		flags.MaxResults = 100
	}
	if flags.OutputFormat == "" {
		flags.OutputFormat = "simple"
	}

	// Set default date to today if not specified, but allow empty dates for testing
	// Check if the date was explicitly set to empty string
	if flags.Date == "" && !viper.IsSet("date") {
		flags.Date = time.Now().Format("2006-01-02")
	}

	// Validate date format only if date is specified
	if flags.Date != "" {
		if _, err := time.Parse("2006-01-02", flags.Date); err != nil {
			return nil, fmt.Errorf("invalid date format: %s (expected YYYY-MM-DD)", flags.Date)
		}
	}

	// Validate CVSS score ranges
	if flags.MinCVSS < 0 || flags.MinCVSS > 10 {
		return nil, fmt.Errorf("invalid minimum CVSS score: %f (must be between 0 and 10)", flags.MinCVSS)
	}
	if flags.MaxCVSS > 0 && (flags.MaxCVSS < 0 || flags.MaxCVSS > 10) {
		return nil, fmt.Errorf("invalid maximum CVSS score: %f (must be between 0 and 10)", flags.MaxCVSS)
	}
	if flags.MaxCVSS > 0 && flags.MinCVSS > flags.MaxCVSS {
		return nil, fmt.Errorf("minimum CVSS score (%f) cannot be greater than maximum CVSS score (%f)", flags.MinCVSS, flags.MaxCVSS)
	}

	// Validate max results
	if flags.MaxResults < 1 || flags.MaxResults > 2000 {
		return nil, fmt.Errorf("invalid max results: %d (must be between 1 and 2000)", flags.MaxResults)
	}

	return flags, nil
}
