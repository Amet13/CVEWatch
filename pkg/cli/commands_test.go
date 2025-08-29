package cli

import (
	"testing"

	"cvewatch/internal/config"

	"github.com/stretchr/testify/assert"
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
	assert.NoError(t, err)
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
