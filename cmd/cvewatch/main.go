package main

import (
	"fmt"
	"os"

	"cvewatch/internal/config"
	"cvewatch/pkg/cli"

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
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
