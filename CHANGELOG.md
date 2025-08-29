# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-08-29

### Added

- Complete rewrite from Python to Go
- Modern CLI interface using Cobra framework
- YAML-based configuration system using Viper
- Integration with NVD API v2.0
- Multiple output formats (JSON, YAML, CSV, table, simple text)
- Advanced filtering by CVSS score and date range
- Product-based monitoring with keyword and CPE pattern matching
- Retry logic and rate limiting for API calls
- Gzip response handling
- Comprehensive error handling
- Cross-platform support (Linux, macOS, Windows)

### Changed

- Project renamed from `vulncontrol` to `cvewatch`
- Replaced discontinued cvedetails.com API with official NVD API
- Modernized configuration approach from `products.txt` to YAML
- Improved data structures and API response handling
- Enhanced security with SSL verification and secure headers

### Removed

- Python codebase
- Telegram integration
- Old `products.txt` configuration
- Dependency on discontinued external APIs

### Technical Improvements

- Go 1.22+ compatibility
- Modern Go modules and dependency management
- Comprehensive unit testing with testify
- Code quality tools and linting
- Production-ready build process
- Optimized binary sizes with build flags

## [1.0.0] - 2023-11-16 (Legacy Python Version)

### Added

- Initial Python-based vulnerability monitoring tool
- Integration with cvedetails.com API
- Basic CVE search and filtering
- Telegram notification system
- Simple text-based configuration

### Deprecated

- This version was discontinued due to API shutdown
- Replaced by Go rewrite (v2.0.0)

---

## Version History

- **v2.0.0** - Complete Go rewrite with modern architecture
- **v1.0.0** - Legacy Python version (discontinued)

## Migration Guide

### From v1.0.0 (Python) to v2.0.0 (Go)

1. **Installation**: Install Go 1.21+ and build from source
2. **Configuration**: Run `cvewatch init` to create new YAML config
3. **Commands**: Update scripts to use new CLI syntax
4. **API**: No more API key required for basic usage
5. **Output**: New output formats available for better integration

### Breaking Changes

- Configuration file format changed from text to YAML
- Command-line interface completely redesigned
- API endpoints changed from cvedetails.com to NVD
- Telegram integration removed
- Python dependencies no longer required

## Contributing

When contributing to this project, please update this changelog with your changes following the established format.
