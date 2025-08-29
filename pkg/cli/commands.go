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
	// Load configuration
	configFile := viper.GetString("config")
	configManager := config.NewConfigManager()
	if err := configManager.LoadConfig(configFile); err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	config := configManager.GetConfig()

	// Load and validate command line flags
	flags, err := cmds.loadCommandLineFlags()
	if err != nil {
		return fmt.Errorf("invalid command line flags: %w", err)
	}

	// Override defaults with command line values if specified
	if viper.IsSet("min-cvss") {
		flags.MinCVSS = viper.GetFloat64("min-cvss")
	} else {
		flags.MinCVSS = config.Search.DefaultMinCVSS
	}

	if viper.IsSet("max-cvss") {
		flags.MaxCVSS = viper.GetFloat64("max-cvss")
	} else {
		flags.MaxCVSS = config.Search.DefaultMaxCVSS
	}

	if viper.IsSet("max-results") {
		flags.MaxResults = viper.GetInt("max-results")
	} else {
		flags.MaxResults = config.Search.DefaultMaxResults
	}

	if viper.IsSet("output") {
		flags.OutputFormat = viper.GetString("output")
	} else {
		flags.OutputFormat = config.Output.DefaultFormat
	}

	// Validate output format
	validFormats := make(map[string]bool)
	for _, format := range config.Output.Formats {
		validFormats[format] = true
	}
	if !validFormats[flags.OutputFormat] {
		return fmt.Errorf("invalid output format: %s (valid formats: %s)",
			flags.OutputFormat, strings.Join(config.Output.Formats, ", "))
	}

	// Create search request
	searchRequest := &types.SearchRequest{
		Date:         flags.Date,
		MinCVSS:      flags.MinCVSS,
		MaxCVSS:      flags.MaxCVSS,
		MaxResults:   flags.MaxResults,
		OutputFormat: flags.OutputFormat,
		APIKey:       flags.APIKey,
		Products:     []string{"Linux Kernel", "OpenSSL", "Apache HTTP Server", "PHP", "Python"},
	}

	// Display search parameters
	if !viper.GetBool("quiet") {
		fmt.Printf("🔍 Searching for vulnerabilities on %s\n", searchRequest.Date)
		fmt.Printf("📦 Monitoring %d products\n", len(searchRequest.Products))
		fmt.Printf("🎯 Minimum CVSS score: %.1f\n", searchRequest.MinCVSS)
		fmt.Printf("🎯 Maximum CVSS score: %.1f\n", searchRequest.MaxCVSS)
		fmt.Printf("📊 Output format: %s\n", searchRequest.OutputFormat)
		fmt.Printf("📈 Max results: %d\n\n", searchRequest.MaxResults)
	}

	// Create NVD client and search for vulnerabilities
	nvdClient := nvd.NewNVDClient(config, configManager, searchRequest.APIKey)
	result, err := nvdClient.SearchCVEs(searchRequest)
	if err != nil {
		return fmt.Errorf("failed to search CVEs: %w", err)
	}

	// Output results
	formatter := output.NewOutputFormatter(flags.OutputFormat, config)
	if err := formatter.FormatOutput(result); err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	// Print summary
	if !viper.GetBool("quiet") {
		formatter.PrintSummary(result)
	}

	return nil
}

// runInfo executes the info command
func (cmds *Commands) runInfo(cveID string, configManager *config.ConfigManager) error {
	// Validate CVE ID format
	if !utils.IsValidCVEID(cveID) {
		return fmt.Errorf("invalid CVE ID format: %s", cveID)
	}

	// Load configuration
	if err := configManager.LoadConfig(""); err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	config := configManager.GetConfig()

	// Create NVD client and fetch CVE details
	apiKey := viper.GetString("api-key")
	nvdClient := nvd.NewNVDClient(config, configManager, apiKey)
	cve, err := nvdClient.GetCVEDetails(cveID)
	if err != nil {
		return fmt.Errorf("failed to fetch CVE details: %w", err)
	}

	// Display CVE information
	fmt.Printf("🔍 Fetching details for %s...\n\n", cveID)
	fmt.Printf("CVE ID: %s\n", cve.ID)
	fmt.Printf("Status: %s\n", cve.Status)
	fmt.Printf("Published: %s\n", cve.Published)
	fmt.Printf("Modified: %s\n", cve.Modified)

	// CVSS information
	if len(cve.Metrics.CVSSMetricV31) > 0 {
		fmt.Printf("CVSS v3.1 Score: %.1f (%s)\n", cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore, cve.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity)
		fmt.Printf("Vector: %s\n", cve.Metrics.CVSSMetricV31[0].CVSSData.VectorString)
	} else if len(cve.Metrics.CVSSMetricV2) > 0 {
		fmt.Printf("CVSS v2 Score: %.1f (%s)\n", cve.Metrics.CVSSMetricV2[0].CVSSData.BaseScore, cve.Metrics.CVSSMetricV2[0].CVSSData.BaseSeverity)
		fmt.Printf("Vector: %s\n", cve.Metrics.CVSSMetricV2[0].CVSSData.VectorString)
	}

	// Get English description
	description := ""
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			description = desc.Value
			break
		}
	}
	fmt.Printf("\nDescription:\n%s\n", description)

	// References
	if len(cve.References) > 0 {
		fmt.Printf("\nReferences:\n")
		for i, ref := range cve.References {
			fmt.Printf("%d. %s\n", i+1, ref.URL)
			if ref.Name != "" {
				fmt.Printf("   Name: %s\n", ref.Name)
			}
		}
	}

	return nil
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
func (cmds *Commands) runVersion(configManager *config.ConfigManager) error {

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
