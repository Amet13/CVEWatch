# CVEWatch 🔍

A modern, fast, and efficient Common Vulnerability and Exposure (CVE) monitoring tool built in Go. CVEWatch provides real-time vulnerability monitoring using the official National Vulnerability Database (NVD) API with advanced filtering, multiple output formats, and comprehensive product monitoring.

## ✨ Features

- **🔍 Real-time CVE Monitoring**: Search and monitor vulnerabilities using the official NVD API
- **📊 Multiple Output Formats**: Support for JSON, YAML, CSV, table, and simple text formats
- **🎯 Advanced Filtering**: Filter by CVSS score, date range, and product keywords
- **🏗️ Product-based Monitoring**: Monitor specific software products with keyword and CPE pattern matching
- **⚡ High Performance**: Built in Go for speed and efficiency
- **🔄 Retry Logic**: Robust API interaction with automatic retry and rate limiting
- **📝 YAML Configuration**: Modern YAML-based configuration with environment variable support
- **🔒 Security Focused**: Built-in security checks and SSL verification
- **📱 Cross-platform**: Runs on Linux, macOS, and Windows

## 🚀 Quick Start

### Prerequisites

- Go 1.21 or later
- Internet connection for NVD API access

### Installation

#### Option 1: Build from source

```bash
git clone https://github.com/yourusername/cvewatch.git
cd cvewatch
make build
```

#### Option 2: Install directly

```bash
make install
```

### First Run

1. **Initialize configuration**:

   ```bash
   cvewatch init
   ```

2. **Search for vulnerabilities**:

   ```bash
   cvewatch search --date 2024-01-01 --min-cvss 7.0
   ```

3. **Get CVE details**:
   ```bash
   cvewatch info CVE-2023-1234
   ```

## 📖 Usage

### Commands

#### `cvewatch init`

Creates a default configuration file with predefined product monitoring rules.

#### `cvewatch search [flags]`

Search for CVEs based on specified criteria.

**Flags:**

- `--date, -d`: Date in YYYY-MM-DD format (default: today)
- `--min-cvss, -m`: Minimum CVSS score (0-10)
- `--max-cvss, -M`: Maximum CVSS score (0-10)
- `--max-results, -r`: Maximum number of results (1-2000)
- `--output, -o`: Output format (simple, json, yaml, table, csv)
- `--api-key, -k`: NVD API key (optional, increases rate limits)

#### `cvewatch info [CVE-ID]`

Get detailed information about a specific CVE.

#### `cvewatch config`

Display current configuration and product information.

#### `cvewatch version`

Show version and build information.

### Examples

```bash
# Search for high-severity vulnerabilities from yesterday
cvewatch search --date 2024-01-01 --min-cvss 7.0 --max-results 10

# Search for vulnerabilities affecting Linux kernel
cvewatch search --min-cvss 5.0 --output json

# Get detailed information about a specific CVE
cvewatch info CVE-2023-1234

# Search with custom date range and output format
cvewatch search --date 2024-01-01 --min-cvss 8.0 --output table
```

## ⚙️ Configuration

CVEWatch uses a YAML configuration file located at `~/.cvewatch/config.yaml`. The configuration includes:

### Application Settings

- Application name and version
- Log level and timeout settings
- Security configuration

### NVD API Settings

- Base URL and rate limiting
- Timeout and retry configuration
- API key configuration

### Product Monitoring

- Product names and descriptions
- Keyword matching rules
- CPE pattern matching
- Priority levels

### Output Settings

- Default output format
- Color and truncation settings
- Available output formats

### Example Configuration

```yaml
app:
  name: CVEWatch
  version: 2.0.0
  log_level: info
  timeout: 60

nvd:
  base_url: https://services.nvd.nist.gov/rest/json/cves/2.0
  rate_limit: 1000
  timeout: 30
  retry_attempts: 3
  retry_delay: 5

products:
  - name: Linux Kernel
    keywords: [linux, kernel, linux kernel]
    cpe_patterns: [cpe:2.3:o:*:linux:*:*:*:*:*:*:*]
    description: Linux operating system kernel
    priority: high

output:
  default_format: simple
  formats: [simple, json, table, csv, yaml]
  colors: true
  truncate_length: 100
```

## 🧪 Development

### Prerequisites

- Go 1.21+
- Make
- golangci-lint (optional)

### Setup Development Environment

```bash
make dev-setup
```

### Common Commands

```bash
make build          # Build the application
make test           # Run all tests
make test-coverage  # Run tests with coverage
make lint           # Run linters
make format         # Format code
make clean          # Clean build artifacts
make release        # Build for multiple platforms
```

### Running Tests

```bash
# Run all tests
go test -v ./...

# Run tests with race detection
go test -race -v ./...

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

## 🔧 API Integration

CVEWatch integrates with the NVD API v2.0 to fetch vulnerability data. The API provides:

- Real-time CVE information
- CVSS scoring data
- CPE configuration details
- Reference links and descriptions
- Publication and modification dates

### Rate Limiting

- Without API key: 100 requests per hour
- With API key: 1000 requests per hour

### API Endpoints

- Base URL: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- Search endpoint: `/rest/json/cves/2.0`
- CVE details: `/rest/json/cves/2.0?cveId={CVE-ID}`

## 📊 Output Formats

### Simple Text

Human-readable format with clear vulnerability information and summaries.

### JSON

Structured JSON output for programmatic processing and integration.

### YAML

YAML format for configuration and data exchange.

### Table

Formatted table output for easy reading and analysis.

### CSV

Comma-separated values for spreadsheet analysis and reporting.

## 🚨 Security Features

- SSL/TLS verification enabled by default
- Secure HTTP headers
- Rate limiting and retry logic
- Input validation and sanitization
- Secure configuration file handling

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Code Quality

- All code must pass linting checks
- Tests are required for new functionality
- Follow Go coding standards
- Use meaningful commit messages

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [NVD](https://nvd.nist.gov/) for providing the vulnerability database
- [Go](https://golang.org/) for the excellent programming language
- [Cobra](https://github.com/spf13/cobra) for the CLI framework
- [Viper](https://github.com/spf13/viper) for configuration management

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/cvewatch/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/cvewatch/discussions)
- **Documentation**: [Wiki](https://github.com/yourusername/cvewatch/wiki)

## 🔄 Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes and releases.

---

**CVEWatch** - Making vulnerability monitoring simple, fast, and effective. 🔍✨
