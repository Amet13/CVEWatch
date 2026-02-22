<div align="center">
  <img src="logo.png" alt="CVEWatch Logo" width="200" style="border-radius: 20px;">
  <h1>CVEWatch</h1>
  <p><strong>A modern, fast, and efficient CVE monitoring tool</strong></p>
  <p>
    <a href="https://github.com/Amet13/CVEWatch/actions/workflows/ci.yml">
      <img src="https://github.com/Amet13/CVEWatch/actions/workflows/ci.yml/badge.svg" alt="CI/CD Status">
    </a>
    <a href="https://github.com/Amet13/CVEWatch/releases">
      <img src="https://img.shields.io/github/v/release/Amet13/CVEWatch?label=version" alt="Latest Release">
    </a>
    <a href="https://github.com/Amet13/CVEWatch/blob/main/LICENSE">
      <img src="https://img.shields.io/badge/License-MIT-green" alt="MIT License">
    </a>
    <a href="https://goreportcard.com/report/github.com/Amet13/CVEWatch">
      <img src="https://goreportcard.com/badge/github.com/Amet13/CVEWatch" alt="Go Report Card">
    </a>
  </p>
</div>

CVEWatch provides real-time vulnerability monitoring using the official National Vulnerability Database (NVD) API with advanced filtering, multiple output formats, and comprehensive product monitoring.

## ✨ Features

- **🔍 Real-time CVE Monitoring**: Search and monitor vulnerabilities using the official NVD API
- **👁️ Watch Mode**: Continuous monitoring with configurable intervals for new CVEs
- **💾 Caching Layer**: File-based caching to reduce API calls and improve performance
- **📊 Multiple Output Formats**: Support for JSON, YAML, CSV, table, and simple text formats
- **🎯 Advanced Filtering**: Filter by CVSS score, date range, and product keywords
- **🏗️ Product-based Monitoring**: Monitor specific software products with keyword and CPE pattern matching
- **⚡ High Performance**: Built in Go for speed and efficiency
- **🔄 Retry Logic**: Robust API interaction with automatic retry, exponential backoff, and jitter
- **📝 YAML Configuration**: Modern YAML-based configuration with environment variable support
- **🔒 Security Focused**: Built-in security checks and SSL verification
- **📱 Cross-platform**: Runs on Linux, macOS, and Windows
- **🏥 Health Check**: Built-in API connectivity verification

## 🚀 Quick Start

### Prerequisites

- Go 1.25 or later
- Internet connection for NVD API access
- NVD API key (optional, but recommended for higher rate limits)

### Installation

#### Option 1: Download Latest Release (Recommended)

Download the latest release for your platform from [GitHub Releases](https://github.com/Amet13/CVEWatch/releases/latest)

#### Option 2: Build from source

```bash
git clone https://github.com/Amet13/CVEWatch.git
cd cvewatch
task build
```

#### Option 3: Install directly

```bash
task install
```

### Verify Installation

After installation, verify CVEWatch is working:

```bash
cvewatch version
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

4. **Check API health**:
   ```bash
   cvewatch health
   ```

5. **Watch for new CVEs**:
   ```bash
   cvewatch watch --interval 5m
   ```

## 📖 Usage

### Commands

#### `cvewatch init`

Creates a default configuration file with predefined product monitoring rules.

#### `cvewatch search [flags]`

Search for CVEs based on specified criteria.

**Flags:**

- `--date, -d`: Date in YYYY-MM-DD format (default: today)
- `--start-date`: Start date for range search (YYYY-MM-DD)
- `--end-date`: End date for range search (YYYY-MM-DD)
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

#### `cvewatch health`

Check NVD API connectivity and display status information.

#### `cvewatch watch [flags]`

Continuously monitor for new CVEs at specified intervals.

**Flags:**

- `--interval, -i`: Check interval (e.g., 5m, 1h) (default: 5m)
- `--min-cvss, -m`: Minimum CVSS score (0-10)
- `--max-cvss, -M`: Maximum CVSS score (0-10)
- `--output, -o`: Output format (simple, json, yaml, table, csv)

#### `cvewatch cache [flags]`

Inspect local cache statistics and optionally clean expired entries.

**Flags:**

- `--clean`: Remove expired cache entries before showing stats

### Examples

```bash
# Search for high-severity vulnerabilities from yesterday
cvewatch search --date 2024-01-01 --min-cvss 7.0 --max-results 10

# Search with date range
cvewatch search --start-date 2024-01-01 --end-date 2024-06-30 --min-cvss 7.0

# Search for vulnerabilities affecting Linux kernel
cvewatch search --min-cvss 5.0 --output json

# Get detailed information about a specific CVE
cvewatch info CVE-2023-1234

# Check NVD API health
cvewatch health

# Watch for new critical CVEs every 5 minutes
cvewatch watch --interval 5m --min-cvss 9.0

# Show cache stats and clean expired entries
cvewatch cache --clean

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

### Cache Settings

- Enable/disable local response caching
- Cache directory configuration
- Cache TTL tuning for freshness vs API load

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
  logLevel: info
  timeout: 60

nvd:
  baseUrl: https://services.nvd.nist.gov/rest/json/cves/2.0
  rateLimit: 1000
  timeout: 30
  retryAttempts: 3
  retryDelay: 5

cache:
  enabled: true
  dir: ""
  ttl: 15

products:
  - name: Linux Kernel
    keywords: [linux, kernel, linux kernel]
    cpePatterns: [cpe:2.3:o:*:linux:*:*:*:*:*:*:*]
    description: Linux operating system kernel
    priority: high

output:
  defaultFormat: simple
  formats: [simple, json, table, csv, yaml]
  colors: true
  truncateLength: 100
```

## 🧪 Development

### Prerequisites

- Go 1.25+
- Task (https://taskfile.dev)
- golangci-lint
- pre-commit hooks (optional)

### Setup Development Environment

```bash
task dev-setup
```

### Common Commands

```bash
task build          # Build the application
task test           # Run all tests
task test-coverage  # Run tests with coverage
task lint           # Run linters
task format         # Format code
task clean          # Clean build artifacts
task release        # Build for multiple platforms
task security-scan  # Run security scanning
task vuln-check     # Check dependencies for known vulnerabilities
task pre-commit     # Run all pre-commit checks
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
- SBOM artifacts generated for releases

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details on:

- Code of Conduct
- Development setup
- How to submit issues
- How to create pull requests
- Coding standards

## 🛟 Support

For usage help and troubleshooting, see [SUPPORT.md](SUPPORT.md).

## 🔐 Security Policy

To report vulnerabilities privately, follow [SECURITY.md](SECURITY.md).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
