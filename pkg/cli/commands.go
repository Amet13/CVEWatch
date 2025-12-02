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

// Package cli provides command-line interface commands for CVEWatch.
//
// It implements the main user-facing commands: search, info, config, version, health, watch, and init.
// Commands are built using the Cobra framework for a professional CLI experience.
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

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
	HealthCmd  *cobra.Command
	WatchCmd   *cobra.Command
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
	cmds.RootCmd.AddCommand(cmds.HealthCmd)
	cmds.RootCmd.AddCommand(cmds.WatchCmd)

	return cmds
}

// setupFlags configures all command line flags
func (cmds *Commands) setupFlags() {
	// Command line flags
	cmds.RootCmd.PersistentFlags().StringP("config", "c", "", "Configuration file path")
	cmds.RootCmd.PersistentFlags().StringP("date", "d", "", "Date in format YYYY-MM-DD (default: today)")
	cmds.RootCmd.PersistentFlags().StringP("start-date", "s", "", "Start date for range search (YYYY-MM-DD)")
	cmds.RootCmd.PersistentFlags().StringP("end-date", "e", "", "End date for range search (YYYY-MM-DD)")
	cmds.RootCmd.PersistentFlags().Float64P("min-cvss", "m", 0.0, "Minimum CVSS score (0-10)")
	cmds.RootCmd.PersistentFlags().Float64P("max-cvss", "M", 0.0, "Maximum CVSS score (0-10)")
	cmds.RootCmd.PersistentFlags().StringP("output", "o", "simple", "Output format: simple, json, yaml, table, csv")
	cmds.RootCmd.PersistentFlags().IntP("max-results", "r", 100, "Maximum number of results (1-2000)")
	cmds.RootCmd.PersistentFlags().StringP("api-key", "k", "", "NVD API key (optional, increases rate limits)")
	cmds.RootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")
	cmds.RootCmd.PersistentFlags().BoolP("quiet", "q", false, "Suppress non-error output")
	cmds.RootCmd.PersistentFlags().BoolP("include-cpe", "", false, "Include CPE information in output")
	cmds.RootCmd.PersistentFlags().BoolP("include-refs", "", false, "Include reference information in output")
	cmds.RootCmd.PersistentFlags().DurationP("interval", "i", 1*time.Hour, "Watch mode polling interval")

	// Bind flags to viper
	_ = viper.BindPFlag("config", cmds.RootCmd.PersistentFlags().Lookup("config"))
	_ = viper.BindPFlag("date", cmds.RootCmd.PersistentFlags().Lookup("date"))
	_ = viper.BindPFlag("start-date", cmds.RootCmd.PersistentFlags().Lookup("start-date"))
	_ = viper.BindPFlag("end-date", cmds.RootCmd.PersistentFlags().Lookup("end-date"))
	_ = viper.BindPFlag("min-cvss", cmds.RootCmd.PersistentFlags().Lookup("min-cvss"))
	_ = viper.BindPFlag("max-cvss", cmds.RootCmd.PersistentFlags().Lookup("max-cvss"))
	_ = viper.BindPFlag("output", cmds.RootCmd.PersistentFlags().Lookup("output"))
	_ = viper.BindPFlag("max-results", cmds.RootCmd.PersistentFlags().Lookup("max-results"))
	_ = viper.BindPFlag("api-key", cmds.RootCmd.PersistentFlags().Lookup("api-key"))
	_ = viper.BindPFlag("verbose", cmds.RootCmd.PersistentFlags().Lookup("verbose"))
	_ = viper.BindPFlag("quiet", cmds.RootCmd.PersistentFlags().Lookup("quiet"))
	_ = viper.BindPFlag("include-cpe", cmds.RootCmd.PersistentFlags().Lookup("include-cpe"))
	_ = viper.BindPFlag("include-refs", cmds.RootCmd.PersistentFlags().Lookup("include-refs"))
	_ = viper.BindPFlag("interval", cmds.RootCmd.PersistentFlags().Lookup("interval"))
}

// createCommands creates all subcommands
func (cmds *Commands) createCommands(configManager *config.ConfigManager) {
	// Init command
	cmds.InitCmd = &cobra.Command{
		Use:   "init",
		Short: "Initialize a new configuration file",
		Long:  `Create a new configuration file with default product definitions for monitoring.`,
		RunE: func(_ *cobra.Command, _ []string) error {
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
		RunE: func(_ *cobra.Command, args []string) error {
			return cmds.runInfo(args[0], configManager)
		},
	}

	// Config command
	cmds.ConfigCmd = &cobra.Command{
		Use:   "config",
		Short: "Show configuration information",
		Long:  `Display current configuration settings and product information.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmds.runConfig(configManager)
		},
	}

	// Version command
	cmds.VersionCmd = &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Long:  `Display CVEWatch version and build information.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmds.runVersion(configManager)
		},
	}

	// Health command
	cmds.HealthCmd = &cobra.Command{
		Use:   "health",
		Short: "Check NVD API connectivity",
		Long:  `Verify that CVEWatch can connect to the NVD API and check rate limit status.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cmds.runHealth(configManager)
		},
	}

	// Watch command
	cmds.WatchCmd = &cobra.Command{
		Use:   "watch",
		Short: "Continuously monitor for new CVEs",
		Long:  `Watch for new CVE vulnerabilities at a specified interval. Press Ctrl+C to stop.`,
		RunE:  cmds.runWatch,
	}
}

// runSearch executes the search command
func (cmds *Commands) runSearch(_ *cobra.Command, _ []string) error {
	// Create context with cancellation support
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

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

	result, err := cmds.executeSearch(ctx, config, configManager, searchRequest)
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
		StartDate:    flags.StartDate,
		EndDate:      flags.EndDate,
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
	if searchRequest.StartDate != "" && searchRequest.EndDate != "" {
		fmt.Printf("🔍 Searching for vulnerabilities from %s to %s\n", searchRequest.StartDate, searchRequest.EndDate)
	} else {
		fmt.Printf("🔍 Searching for vulnerabilities on %s\n", searchRequest.Date)
	}
	fmt.Printf("📦 Monitoring %d products\n", len(searchRequest.Products))
	fmt.Printf("🎯 Minimum CVSS score: %.1f\n", searchRequest.MinCVSS)
	fmt.Printf("🎯 Maximum CVSS score: %.1f\n", searchRequest.MaxCVSS)
	fmt.Printf("📊 Output format: %s\n", searchRequest.OutputFormat)
	fmt.Printf("📈 Max results: %d\n\n", searchRequest.MaxResults)
}

// executeSearch executes the CVE search
func (cmds *Commands) executeSearch(ctx context.Context, config *types.AppConfig, configManager *config.ConfigManager, searchRequest *types.SearchRequest) (*types.SearchResult, error) {
	nvdClient := nvd.NewNVDClient(config, configManager, searchRequest.APIKey)
	result, err := nvdClient.SearchCVEs(ctx, searchRequest)
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
	// Create context with cancellation support
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := cmds.validateCVEID(cveID); err != nil {
		return err
	}

	config, err := cmds.loadInfoConfiguration(configManager)
	if err != nil {
		return err
	}

	cve, err := cmds.fetchCVEDetails(ctx, config, configManager, cveID)
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
func (cmds *Commands) fetchCVEDetails(ctx context.Context, config *types.AppConfig, configManager *config.ConfigManager, cveID string) (*types.CVE, error) {
	apiKey := viper.GetString("api-key")
	nvdClient := nvd.NewNVDClient(config, configManager, apiKey)
	cve, err := nvdClient.GetCVEDetails(ctx, cveID)
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
		StartDate:    viper.GetString("start-date"),
		EndDate:      viper.GetString("end-date"),
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

	// Validate start/end date formats
	if flags.StartDate != "" && !utils.IsValidDate(flags.StartDate) {
		return nil, fmt.Errorf("invalid start date format: %s (expected YYYY-MM-DD)", flags.StartDate)
	}
	if flags.EndDate != "" && !utils.IsValidDate(flags.EndDate) {
		return nil, fmt.Errorf("invalid end date format: %s (expected YYYY-MM-DD)", flags.EndDate)
	}

	// Validate date range
	if flags.StartDate != "" && flags.EndDate != "" {
		if !utils.IsValidDateRange(flags.StartDate, flags.EndDate) {
			return nil, fmt.Errorf("invalid date range: start date must be before or equal to end date")
		}
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

// runHealth executes the health check command
func (cmds *Commands) runHealth(configManager *config.ConfigManager) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Println("🏥 Checking NVD API health...")

	if err := configManager.LoadConfig(""); err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	config := configManager.GetConfig()
	apiKey := viper.GetString("api-key")
	nvdClient := nvd.NewNVDClient(config, configManager, apiKey)

	if err := nvdClient.CheckHealth(ctx); err != nil {
		fmt.Println("❌ NVD API health check failed")
		return err
	}

	fmt.Println("✅ NVD API is healthy and accessible")

	// Display rate limit info
	info := nvdClient.GetRateLimitInfo()
	fmt.Println("\n📊 Rate Limit Status:")
	fmt.Printf("  Rate Limit: %v requests/hour\n", info["rate_limit"])
	fmt.Printf("  Current Count: %v\n", info["current_count"])
	if apiKey != "" {
		fmt.Println("  API Key: Configured ✓")
	} else {
		fmt.Println("  API Key: Not configured (lower rate limits apply)")
	}

	return nil
}

// runWatch executes the watch command for continuous monitoring
func (cmds *Commands) runWatch(_ *cobra.Command, _ []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	configManager, config, err := cmds.loadConfiguration()
	if err != nil {
		return err
	}

	flags, err := cmds.loadAndOverrideFlags(config)
	if err != nil {
		return err
	}

	interval := viper.GetDuration("interval")
	if interval < 1*time.Minute {
		interval = 1 * time.Minute
		fmt.Println("⚠️  Minimum interval is 1 minute, adjusting...")
	}

	fmt.Printf("👁️  Starting watch mode (interval: %s)\n", interval)
	fmt.Println("Press Ctrl+C to stop watching")

	// Track seen CVEs to avoid duplicates
	seenCVEs := make(map[string]bool)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run immediately on start
	cmds.runWatchIteration(ctx, config, configManager, flags, seenCVEs)

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\n👋 Stopping watch mode...")
			return nil
		case <-ticker.C:
			cmds.runWatchIteration(ctx, config, configManager, flags, seenCVEs)
		}
	}
}

// runWatchIteration executes a single watch iteration
func (cmds *Commands) runWatchIteration(ctx context.Context, config *types.AppConfig, configManager *config.ConfigManager, flags *types.CommandLineFlags, seenCVEs map[string]bool) {
	// Use today's date for each iteration
	searchRequest := cmds.createSearchRequest(flags, config)
	searchRequest.Date = time.Now().Format("2006-01-02")

	result, err := cmds.executeSearch(ctx, config, configManager, searchRequest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Search failed: %v\n", err)
		return
	}

	// Filter to only new CVEs
	newCVEs := make([]types.CVE, 0)
	for _, cve := range result.CVEs {
		if !seenCVEs[cve.ID] {
			seenCVEs[cve.ID] = true
			newCVEs = append(newCVEs, cve)
		}
	}

	if len(newCVEs) > 0 {
		fmt.Printf("\n🚨 Found %d new CVEs at %s:\n", len(newCVEs), time.Now().Format("15:04:05"))
		for _, cve := range newCVEs {
			score := cmds.getCVSSScore(cve)
			fmt.Printf("  • %s (CVSS: %.1f)\n", cve.ID, score)
		}
	} else {
		fmt.Printf("⏰ [%s] No new CVEs found\n", time.Now().Format("15:04:05"))
	}
}

// getCVSSScore returns the CVSS score for a CVE
func (cmds *Commands) getCVSSScore(cve types.CVE) float64 {
	if len(cve.Metrics.CVSSMetricV31) > 0 {
		return cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
	}
	if len(cve.Metrics.CVSSMetricV2) > 0 {
		return cve.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
	}
	return 0.0
}
