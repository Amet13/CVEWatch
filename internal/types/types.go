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

// Package types defines all data structures used throughout CVEWatch.
//
// It provides types for configuration, API requests/responses, CVE data,
// and command-line arguments. These types mirror the NVD API v2.0 structure.
package types

// AppConfig represents the main application configuration
type AppConfig struct {
	App      AppSettings      `yaml:"app"`
	NVD      NVDSettings      `yaml:"nvd"`
	Search   SearchSettings   `yaml:"search"`
	Products []Product        `yaml:"products"`
	Output   OutputSettings   `yaml:"output"`
	Security SecuritySettings `yaml:"security"`
}

// AppSettings represents application-level settings
type AppSettings struct {
	Name     string `yaml:"name"`
	Version  string `yaml:"version"`
	LogLevel string `yaml:"logLevel"`
	Timeout  int    `yaml:"timeout"`
}

// NVDSettings represents NVD API configuration
type NVDSettings struct {
	BaseURL       string `yaml:"baseUrl"`
	RateLimit     int    `yaml:"rateLimit"`
	Timeout       int    `yaml:"timeout"`
	RetryAttempts int    `yaml:"retryAttempts"`
	RetryDelay    int    `yaml:"retryDelay"`
}

// SearchSettings represents default search parameters
type SearchSettings struct {
	DefaultDate       string  `yaml:"defaultDate"`
	DefaultMinCVSS    float64 `yaml:"defaultMinCvss"`
	DefaultMaxCVSS    float64 `yaml:"defaultMaxCvss"`
	DefaultMaxResults int     `yaml:"defaultMaxResults"`
	DateFormat        string  `yaml:"dateFormat"`
}

// OutputSettings represents output configuration
type OutputSettings struct {
	DefaultFormat  string   `yaml:"defaultFormat"`
	Formats        []string `yaml:"formats"`
	Colors         bool     `yaml:"colors"`
	TruncateLength int      `yaml:"truncateLength"`
}

// SecuritySettings represents security configuration
type SecuritySettings struct {
	EnableSSLVerification bool              `yaml:"enableSslVerification"`
	UserAgent             string            `yaml:"userAgent"`
	RequestHeaders        map[string]string `yaml:"requestHeaders"`
}

// Product represents a software product to monitor
type Product struct {
	Name        string   `yaml:"name"`
	Keywords    []string `yaml:"keywords"`
	CPEPatterns []string `yaml:"cpePatterns"`
	Description string   `yaml:"description"`
	Priority    string   `yaml:"priority"`
}

// CVE represents a Common Vulnerability and Exposure entry from NVD.
//
// This type mirrors the NVD API v2.0 response structure and contains
// all available information about a single vulnerability including
// CVSS scores, descriptions, references, affected products, and weaknesses.
type CVE struct {
	// CVE identifier in the format CVE-YYYY-NNNNN (e.g., "CVE-2024-1234")
	ID string `json:"id"`

	// Descriptions in multiple languages
	Descriptions []Description `json:"descriptions"`

	// CVSS scoring information (v2 and/or v3.1)
	Metrics Metrics `json:"metrics"`

	// Publication date in ISO 8601 format (e.g., "2024-01-01T00:00:00Z")
	Published string `json:"published"`

	// Last modification date in ISO 8601 format
	Modified string `json:"lastModified"`

	// Publication status (e.g., "PUBLISHED", "UNDERREVIEW", "REJECTED")
	Status string `json:"vulnStatus"`

	// Reference links to advisories, patches, and other resources
	References []Reference `json:"references"`

	// CPE configurations indicating affected products
	Configurations []Configuration `json:"configurations"`

	// Weakness classifications (CWE - Common Weakness Enumeration)
	Weaknesses []Weakness `json:"weaknesses"`
}

// Description represents a CVE description
type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// Metrics represents the metrics section from NVD API v2.0
type Metrics struct {
	CVSSMetricV31 []CVSSMetricV31 `json:"cvssMetricV31,omitempty"`
	CVSSMetricV2  []CVSSMetricV2  `json:"cvssMetricV2,omitempty"`
}

// CVSSMetricV31 represents CVSS v3.1 metric data
type CVSSMetricV31 struct {
	Source   string      `json:"source"`
	Type     string      `json:"type"`
	CVSSData CVSSDataV31 `json:"cvssData"`
}

// CVSSMetricV2 represents CVSS v2 metric data
type CVSSMetricV2 struct {
	Source   string     `json:"source"`
	Type     string     `json:"type"`
	CVSSData CVSSDataV2 `json:"cvssData"`
}

// CVSSDataV31 represents CVSS v3.1 scoring data
type CVSSDataV31 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
}

// CVSSDataV2 represents CVSS v2 scoring data
type CVSSDataV2 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
	AccessVector          string  `json:"accessVector"`
	AccessComplexity      string  `json:"accessComplexity"`
	Authentication        string  `json:"authentication"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
}

// Reference represents a reference link for a CVE
type Reference struct {
	URL       string   `json:"url"`
	Name      string   `json:"name"`
	RefSource string   `json:"refsource"`
	Tags      []string `json:"tags"`
}

// Configuration represents CVE configuration information
type Configuration struct {
	Nodes []Node `json:"nodes"`
}

// Node represents a configuration node
type Node struct {
	Operator string     `json:"operator"`
	CPEMatch []CPEMatch `json:"cpeMatch"`
}

// CPEMatch represents a CPE match
type CPEMatch struct {
	Vulnerable bool   `json:"vulnerable"`
	Criteria   string `json:"criteria"`
}

// Weakness represents CVE weakness information
type Weakness struct {
	Source      string        `json:"source"`
	Type        string        `json:"type"`
	Description []Description `json:"description"`
}

// NVDResponse represents the response from NVD API v2.0
type NVDResponse struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Format          string          `json:"format"`
	Version         string          `json:"version"`
	Timestamp       string          `json:"timestamp"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability represents a single vulnerability from NVD API v2.0
type Vulnerability struct {
	CVE CVE `json:"cve"`
}

// SearchResult represents a search result with metadata
type SearchResult struct {
	CVEs       []CVE
	TotalFound int
	Date       string
	MinCVSS    float64
	MaxCVSS    float64
	Products   []string
	QueryTime  string
}

// SearchRequest represents a search request to the NVD API.
//
// All fields except Products are optional and will use configuration defaults
// if not provided. Products must contain at least one product name.
//
// The search will be filtered by CVSS score range and date if provided.
// Results are further filtered based on product keywords and CPE patterns.
type SearchRequest struct {
	// Date in YYYY-MM-DD format. If empty, uses today's date.
	Date string

	// StartDate in YYYY-MM-DD format for range queries. Optional.
	StartDate string

	// EndDate in YYYY-MM-DD format for range queries. Optional.
	EndDate string

	// Minimum CVSS score (0.0-10.0). If 0, no minimum filter applied.
	MinCVSS float64

	// Maximum CVSS score (0.0-10.0). If 0, no maximum filter applied.
	MaxCVSS float64

	// Product names to filter by. Must not be empty.
	Products []string

	// Maximum number of results to return (1-2000).
	MaxResults int

	// Optional NVD API key for higher rate limits.
	APIKey string

	// Output format (simple, json, yaml, table, csv).
	OutputFormat string

	// Include CPE information in filtered results.
	IncludeCPE bool

	// Include reference links in results.
	IncludeRefs bool
}

// CommandLineFlags represents command line arguments
type CommandLineFlags struct {
	Date         string
	MinCVSS      float64
	MaxCVSS      float64
	OutputFormat string
	MaxResults   int
	APIKey       string
	Quiet        bool
	Verbose      bool
	IncludeCPE   bool
	IncludeRefs  bool
}
