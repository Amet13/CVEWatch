// Package main is the entry point for the CVEWatch application.
package main

import (
	"fmt"
	"os"

	"cvewatch/internal/config"
	"cvewatch/pkg/cli"
	"cvewatch/pkg/errors"

	// Import version package to ensure version variables are linked
	_ "cvewatch/pkg/version"
)

func main() {
	// Initialize configuration manager
	configManager := config.NewConfigManager()

	// Create CLI commands
	commands := cli.NewCommands(configManager)

	// Execute the root command
	if err := commands.RootCmd.Execute(); err != nil {
		// Use enhanced error formatting for better user experience
		fmt.Fprintln(os.Stderr, errors.FormatError(err))
		os.Exit(1)
	}
}
