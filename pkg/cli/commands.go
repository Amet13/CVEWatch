package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"cvewatch/internal/config"
	"cvewatch/internal/nvd"
	"cvewatch/internal/output"
	"cvewatch/internal/types"
	"cvewatch/pkg/utils"
	"cvewatch/pkg/version"
)

// Commands holds all CLI commands
type Commands struct {
	RootCmd    *cobra.Command
	InitCmd    *cobra.Command
	SearchCmd  *cobra.Command
	InfoCmd    *cobra.Command
	ConfigCmd  *cobra.Command
	VersionCmd *cobra.Command
}

// NewCommands creates and configures all CLI commands
func NewCommands(configManager *config.ConfigManager) *Commands {
	cmds := &Commands{}

	// Root command
	cmds.RootCmd = &cobra.Command{
		Use:   "cvewatch",
		Short: "Modern CVE vulnerability monitoring tool using NVD API",
		Long: `CVEWatch is a modern, fast tool for monitoring Common Vulnerabilities and Exposures (CVE) 
using the official National Vulnerability Database (NVD) API.

Features:
- Search CVEs by date, CVSS score, and product keywords
- Multiple output formats (JSON, YAML, table, CSV, simple text)
- Product-based filtering with keyword and CPE pattern matching
- Official NVD data source with retry logic and rate limiting
- YAML-based configuration with environment variable support
- Priority-based product monitoring and CPE pattern matching`,
		RunE: cmds.runSearch,
	}

	// Initialize flags
	cmds.setupFlags()

	// Create subcommands
	cmds.createCommands(configManager)

	// Add subcommands
	cmds.RootCmd.AddCommand(cmds.InitCmd)
	cmds.RootCmd.AddCommand(cmds.SearchCmd)
	cmds.RootCmd.AddCommand(cmds.InfoCmd)
	cmds.RootCmd.AddCommand(cmds.ConfigCmd)
	cmds.RootCmd.AddCommand(cmds.VersionCmd)

	return cmds
}

// setupFlags configures all command line flags
func (cmds *Commands) setupFlags() {
	// Command line flags
	cmds.RootCmd.PersistentFlags().StringP("config", "c", "", "Configuration file path")
	cmds.RootCmd.PersistentFlags().StringP("date", "d", "", "Date in format YYYY-MM-DD (default: today)")
	cmds.RootCmd.PersistentFlags().Float64P("min-cvss", "m", 0.0, "Minimum CVSS score (0-10)")
	cmds.RootCmd.PersistentFlags().Float64P("max-cvss", "M", 0.0, "Maximum CVSS score (0-10)")
	cmds.RootCmd.PersistentFlags().StringP("output", "o", "simple", "Output format: simple, json, yaml, table, csv")
	cmds.RootCmd.PersistentFlags().IntP("max-results", "r", 100, "Maximum number of results (1-2000)")
	cmds.RootCmd.PersistentFlags().StringP("api-key", "k", "", "NVD API key (optional, increases rate limits)")
	cmds.RootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")
	cmds.RootCmd.PersistentFlags().BoolP("quiet", "q", false, "Suppress non-error output")
	cmds.RootCmd.PersistentFlags().BoolP("include-cpe", "", false, "Include CPE information in output")
	cmds.RootCmd.PersistentFlags().BoolP("include-refs", "", false, "Include reference information in output")

	// Bind flags to viper
	_ = viper.BindPFlag("config", cmds.RootCmd.PersistentFlags().Lookup("config"))
	_ = viper.BindPFlag("date", cmds.RootCmd.PersistentFlags().Lookup("date"))
	_ = viper.BindPFlag("min-cvss", cmds.RootCmd.PersistentFlags().Lookup("min-cvss"))
	_ = viper.BindPFlag("max-cvss", cmds.RootCmd.PersistentFlags().Lookup("max-cvss"))
	_ = viper.BindPFlag("output", cmds.RootCmd.PersistentFlags().Lookup("output"))
	_ = viper.BindPFlag("max-results", cmds.RootCmd.PersistentFlags().Lookup("max-results"))
	_ = viper.BindPFlag("api-key", cmds.RootCmd.PersistentFlags().Lookup("api-key"))
	_ = viper.BindPFlag("verbose", cmds.RootCmd.PersistentFlags().Lookup("verbose"))
	_ = viper.BindPFlag("quiet", cmds.RootCmd.PersistentFlags().Lookup("quiet"))
	_ = viper.BindPFlag("include-cpe", cmds.RootCmd.PersistentFlags().Lookup("include-cpe"))
	_ = viper.BindPFlag("include-refs", cmds.RootCmd.PersistentFlags().Lookup("include-refs"))
}

// createCommands creates all subcommands
func (cmds *Commands) createCommands(configManager *config.ConfigManager) {
	// Init command
	cmds.InitCmd = &cobra.Command{
		Use:   "init",
		Short: "Initialize a new configuration file",
		Long:  `Create a new configuration file with default product definitions for monitoring.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return configManager.CreateDefaultConfig()
		},
	}

	// Search command
	cmds.SearchCmd = &cobra.Command{
		Use:   "search",
		Short: "Search for CVEs",
		Long:  `Search for Common Vulnerabilities and Exposures based on specified criteria.`,
		RunE:  cmds.runSearch,
	}

	// Info command
	cmds.InfoCmd = &cobra.Command{
		Use:   "info [CVE-ID]",
		Short: "Get detailed information about a specific CVE",
		Long:  `Fetch detailed information about a specific CVE from the NVD database.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmds.runInfo(args[0], configManager)
		},
	}

	// Config command
	cmds.ConfigCmd = &cobra.Command{
		Use:   "config",
		Short: "Show configuration information",
		Long:  `Display current configuration settings and product information.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmds.runConfig(configManager)
		},
	}

	// Version command
	cmds.VersionCmd = &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Long:  `Display CVEWatch version and build information.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmds.runVersion(configManager)
		},
	}
}

// runSearch executes the search command
func (cmds *Commands) runSearch(cmd *cobra.Command, args []string) error {
	configManager, config, err := cmds.loadConfiguration()
	if err != nil {
		return err
	}

	flags, err := cmds.loadAndOverrideFlags(config)
	if err != nil {
		return err
	}

	if err := cmds.validateOutputFormat(flags, config); err != nil {
		return err
	}

	searchRequest := cmds.createSearchRequest(flags, config)

	if !viper.GetBool("quiet") {
		cmds.displaySearchParameters(searchRequest)
	}

	result, err := cmds.executeSearch(config, configManager, searchRequest)
	if err != nil {
		return err
	}

	return cmds.outputResults(flags, config, result)
}

// loadConfiguration loads and validates the configuration
func (cmds *Commands) loadConfiguration() (*config.ConfigManager, *types.AppConfig, error) {
	configFile := viper.GetString("config")
	configManager := config.NewConfigManager()
	if err := configManager.LoadConfig(configFile); err != nil {
		if strings.Contains(err.Error(), "config file not found") {
			return nil, nil, fmt.Errorf("configuration file not found. Run 'cvewatch init' to create a default configuration")
		}
		return nil, nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	config := configManager.GetConfig()
	if config == nil {
		return nil, nil, fmt.Errorf("configuration is empty or invalid")
	}

	return configManager, config, nil
}

// loadAndOverrideFlags loads command line flags and overrides defaults
func (cmds *Commands) loadAndOverrideFlags(config *types.AppConfig) (*types.CommandLineFlags, error) {
	flags, err := cmds.loadCommandLineFlags()
	if err != nil {
		return nil, fmt.Errorf("invalid command line flags: %w", err)
	}

	cmds.overrideFlagsWithDefaults(flags, config)

	return flags, nil
}

// overrideFlagsWithDefaults overrides flags with configuration defaults
func (cmds *Commands) overrideFlagsWithDefaults(flags *types.CommandLineFlags, config *types.AppConfig) {
	if !viper.IsSet("min-cvss") {
		flags.MinCVSS = config.Search.DefaultMinCVSS
	}

	if !viper.IsSet("max-cvss") {
		flags.MaxCVSS = config.Search.DefaultMaxCVSS
	}

	if !viper.IsSet("max-results") {
		flags.MaxResults = config.Search.DefaultMaxResults
	}

	if !viper.IsSet("output") {
		flags.OutputFormat = config.Output.DefaultFormat
	}
}

// validateOutputFormat validates the output format
func (cmds *Commands) validateOutputFormat(flags *types.CommandLineFlags, config *types.AppConfig) error {
	validFormats := make(map[string]bool)
	for _, format := range config.Output.Formats {
		validFormats[format] = true
	}

	if !validFormats[flags.OutputFormat] {
		return fmt.Errorf("invalid output format: %s (valid formats: %s)",
			flags.OutputFormat, strings.Join(config.Output.Formats, ", "))
	}

	return nil
}

// createSearchRequest creates the search request from flags
func (cmds *Commands) createSearchRequest(flags *types.CommandLineFlags, config *types.AppConfig) *types.SearchRequest {
	// Get product names from configuration
	productNames := make([]string, 0, len(config.Products))
	for _, product := range config.Products {
		productNames = append(productNames, product.Name)
	}

	return &types.SearchRequest{
		Date:         flags.Date,
		MinCVSS:      flags.MinCVSS,
		MaxCVSS:      flags.MaxCVSS,
		MaxResults:   flags.MaxResults,
		OutputFormat: flags.OutputFormat,
		APIKey:       flags.APIKey,
		Products:     productNames,
	}
}

// displaySearchParameters displays the search parameters
func (cmds *Commands) displaySearchParameters(searchRequest *types.SearchRequest) {
	fmt.Printf("🔍 Searching for vulnerabilities on %s\n", searchRequest.Date)
	fmt.Printf("📦 Monitoring %d products\n", len(searchRequest.Products))
	fmt.Printf("🎯 Minimum CVSS score: %.1f\n", searchRequest.MinCVSS)
	fmt.Printf("🎯 Maximum CVSS score: %.1f\n", searchRequest.MaxCVSS)
	fmt.Printf("📊 Output format: %s\n", searchRequest.OutputFormat)
	fmt.Printf("📈 Max results: %d\n\n", searchRequest.MaxResults)
}

// executeSearch executes the CVE search
func (cmds *Commands) executeSearch(config *types.AppConfig, configManager *config.ConfigManager, searchRequest *types.SearchRequest) (*types.SearchResult, error) {
	nvdClient := nvd.NewNVDClient(config, configManager, searchRequest.APIKey)
	result, err := nvdClient.SearchCVEs(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search CVEs: %w", err)
	}

	return result, nil
}

// outputResults formats and outputs the search results
func (cmds *Commands) outputResults(flags *types.CommandLineFlags, config *types.AppConfig, result *types.SearchResult) error {
	formatter := output.NewOutputFormatter(flags.OutputFormat, config)
	if err := formatter.FormatOutput(result); err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	if !viper.GetBool("quiet") {
		formatter.PrintSummary(result)
	}

	return nil
}

// runInfo executes the info command
func (cmds *Commands) runInfo(cveID string, configManager *config.ConfigManager) error {
	if err := cmds.validateCVEID(cveID); err != nil {
		return err
	}

	config, err := cmds.loadInfoConfiguration(configManager)
	if err != nil {
		return err
	}

	cve, err := cmds.fetchCVEDetails(config, configManager, cveID)
	if err != nil {
		return err
	}

	cmds.displayCVEInfo(cveID, cve)

	return nil
}

// validateCVEID validates the CVE ID format
func (cmds *Commands) validateCVEID(cveID string) error {
	if !utils.IsValidCVEID(cveID) {
		return fmt.Errorf("invalid CVE ID format: %s", cveID)
	}

	return nil
}

// loadInfoConfiguration loads configuration for info command
func (cmds *Commands) loadInfoConfiguration(configManager *config.ConfigManager) (*types.AppConfig, error) {
	if err := configManager.LoadConfig(""); err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	return configManager.GetConfig(), nil
}

// fetchCVEDetails fetches CVE details from NVD
func (cmds *Commands) fetchCVEDetails(config *types.AppConfig, configManager *config.ConfigManager, cveID string) (*types.CVE, error) {
	apiKey := viper.GetString("api-key")
	nvdClient := nvd.NewNVDClient(config, configManager, apiKey)
	cve, err := nvdClient.GetCVEDetails(cveID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CVE details: %w", err)
	}

	return cve, nil
}

// displayCVEInfo displays comprehensive CVE information
func (cmds *Commands) displayCVEInfo(cveID string, cve *types.CVE) {
	fmt.Printf("🔍 Fetching details for %s...\n\n", cveID)

	cmds.displayBasicInfo(cve)
	cmds.displayCVSSInfo(cve)
	cmds.displayDescription(cve)
	cmds.displayReferences(cve)
}

// displayBasicInfo displays basic CVE information
func (cmds *Commands) displayBasicInfo(cve *types.CVE) {
	fmt.Printf("CVE ID: %s\n", cve.ID)
	fmt.Printf("Status: %s\n", cve.Status)
	fmt.Printf("Published: %s\n", cve.Published)
	fmt.Printf("Modified: %s\n", cve.Modified)
}

// displayCVSSInfo displays CVSS scoring information
func (cmds *Commands) displayCVSSInfo(cve *types.CVE) {
	if len(cve.Metrics.CVSSMetricV31) > 0 {
		metric := cve.Metrics.CVSSMetricV31[0]
		fmt.Printf("CVSS v3.1 Score: %.1f (%s)\n", metric.CVSSData.BaseScore, metric.CVSSData.BaseSeverity)
		fmt.Printf("Vector: %s\n", metric.CVSSData.VectorString)
	} else if len(cve.Metrics.CVSSMetricV2) > 0 {
		metric := cve.Metrics.CVSSMetricV2[0]
		fmt.Printf("CVSS v2 Score: %.1f (%s)\n", metric.CVSSData.BaseScore, metric.CVSSData.BaseSeverity)
		fmt.Printf("Vector: %s\n", metric.CVSSData.VectorString)
	}
}

// displayDescription displays the English description
func (cmds *Commands) displayDescription(cve *types.CVE) {
	description := cmds.getEnglishDescription(cve)
	fmt.Printf("\nDescription:\n%s\n", description)
}

// getEnglishDescription extracts the English description
func (cmds *Commands) getEnglishDescription(cve *types.CVE) string {
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			return desc.Value
		}
	}

	return ""
}

// displayReferences displays CVE references
func (cmds *Commands) displayReferences(cve *types.CVE) {
	if len(cve.References) == 0 {
		return
	}

	fmt.Printf("\nReferences:\n")
	for i, ref := range cve.References {
		fmt.Printf("%d. %s\n", i+1, ref.URL)
		if ref.Name != "" {
			fmt.Printf("   Name: %s\n", ref.Name)
		}
	}
}

// runConfig executes the config command
func (cmds *Commands) runConfig(configManager *config.ConfigManager) error {
	if err := configManager.LoadConfig(""); err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	config := configManager.GetConfig()

	fmt.Printf("CVEWatch Configuration\n")
	fmt.Printf("=====================\n\n")

	fmt.Printf("Application:\n")
	fmt.Printf("  Name: %s\n", config.App.Name)
	fmt.Printf("  Version: %s\n", config.App.Version)
	fmt.Printf("  Log Level: %s\n", config.App.LogLevel)
	fmt.Printf("  Timeout: %d seconds\n\n", config.App.Timeout)

	fmt.Printf("NVD API:\n")
	fmt.Printf("  Base URL: %s\n", config.NVD.BaseURL)
	fmt.Printf("  Rate Limit: %d requests/hour\n", config.NVD.RateLimit)
	fmt.Printf("  Timeout: %d seconds\n", config.NVD.Timeout)
	fmt.Printf("  Retry Attempts: %d\n", config.NVD.RetryAttempts)
	fmt.Printf("  Retry Delay: %d seconds\n\n", config.NVD.RetryDelay)

	fmt.Printf("Search Settings:\n")
	fmt.Printf("  Default Date: %s\n", config.Search.DefaultDate)
	fmt.Printf("  Default Min CVSS: %.1f\n", config.Search.DefaultMinCVSS)
	fmt.Printf("  Default Max CVSS: %.1f\n", config.Search.DefaultMaxCVSS)
	fmt.Printf("  Default Max Results: %d\n\n", config.Search.DefaultMaxResults)

	fmt.Printf("Output Settings:\n")
	fmt.Printf("  Default Format: %s\n", config.Output.DefaultFormat)
	fmt.Printf("  Available Formats: %s\n", strings.Join(config.Output.Formats, ", "))
	fmt.Printf("  Colors: %t\n", config.Output.Colors)
	fmt.Printf("  Truncate Length: %d\n\n", config.Output.TruncateLength)

	fmt.Printf("Products (%d):\n", len(config.Products))
	for _, product := range config.Products {
		fmt.Printf("  %s (%s priority)\n", product.Name, product.Priority)
		fmt.Printf("    Keywords: %s\n", strings.Join(product.Keywords, ", "))
		if len(product.CPEPatterns) > 0 {
			fmt.Printf("    CPE Patterns: %s\n", strings.Join(product.CPEPatterns, ", "))
		}
		fmt.Printf("    Description: %s\n\n", product.Description)
	}

	return nil
}

// runVersion executes the version command
func (cmds *Commands) runVersion(_ *config.ConfigManager) error {

	fmt.Printf("CVEWatch %s\n", version.GetVersion())
	fmt.Printf("A modern CVE vulnerability monitoring tool\n")
	fmt.Printf("Built with Go and using the official NVD API\n")

	// Show build information
	fmt.Printf("\nBuild Information:\n")
	fmt.Printf("  Version: %s\n", version.GetVersion())
	fmt.Printf("  Build Time: %s\n", version.GetBuildTime())
	fmt.Printf("  Git Commit: %s\n", version.GetGitCommit())

	return nil
}

// loadCommandLineFlags loads and validates command line flags
func (cmds *Commands) loadCommandLineFlags() (*types.CommandLineFlags, error) {
	flags := &types.CommandLineFlags{
		Date:         viper.GetString("date"),
		MinCVSS:      viper.GetFloat64("min-cvss"),
		MaxCVSS:      viper.GetFloat64("max-cvss"),
		MaxResults:   viper.GetInt("max-results"),
		OutputFormat: viper.GetString("output"),
		APIKey:       viper.GetString("api-key"),
	}

	// Validate date format if provided
	if flags.Date != "" && !utils.IsValidDate(flags.Date) {
		return nil, fmt.Errorf("invalid date format: %s (expected YYYY-MM-DD)", flags.Date)
	}

	// Validate CVSS scores
	if !utils.IsValidCVSSScore(flags.MinCVSS) {
		return nil, fmt.Errorf("invalid min CVSS score: %.1f (must be between 0.0 and 10.0)", flags.MinCVSS)
	}
	if !utils.IsValidCVSSScore(flags.MaxCVSS) {
		return nil, fmt.Errorf("invalid max CVSS score: %.1f (must be between 0.0 and 10.0)", flags.MaxCVSS)
	}

	// Validate max results
	if !utils.IsValidMaxResults(flags.MaxResults) {
		return nil, fmt.Errorf("invalid max results: %d (must be between 1 and 2000)", flags.MaxResults)
	}

	// Validate output format
	if !utils.IsValidOutputFormat(flags.OutputFormat) {
		return nil, fmt.Errorf("invalid output format: %s", flags.OutputFormat)
	}

	return flags, nil
}
