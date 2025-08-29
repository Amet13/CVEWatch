package version

// Version information - these will be set during build
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// GetVersion returns the version string
func GetVersion() string {
	return Version
}

// GetBuildTime returns the build time string
func GetBuildTime() string {
	return BuildTime
}

// GetGitCommit returns the git commit string
func GetGitCommit() string {
	return GitCommit
}

// IsDevelopment returns true if this is a development build
func IsDevelopment() bool {
	return Version == "dev"
}
