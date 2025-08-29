package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"cvewatch/internal/types"

	"gopkg.in/yaml.v3"
)

// OutputFormatter handles different output formats
type OutputFormatter struct {
	format string
	config *types.AppConfig
}

// NewOutputFormatter creates a new output formatter
func NewOutputFormatter(format string, config *types.AppConfig) *OutputFormatter {
	return &OutputFormatter{
		format: format,
		config: config,
	}
}

// FormatOutput formats and displays the CVE results
func (o *OutputFormatter) FormatOutput(result *types.SearchResult) error {
	switch o.format {
	case "json":
		return o.outputJSON(result)
	case "yaml":
		return o.outputYAML(result)
	case "table":
		return o.outputTable(result)
	case "csv":
		return o.outputCSV(result)
	default:
		return o.outputSimple(result)
	}
}

// outputSimple outputs results in simple text format
func (o *OutputFormatter) outputSimple(result *types.SearchResult) error {
	if len(result.CVEs) == 0 {
		fmt.Printf("No vulnerabilities found for %s\n", result.Date)
		return nil
	}

	fmt.Printf("Found %d vulnerabilities for %s:\n\n", len(result.CVEs), result.Date)

	for i, cve := range result.CVEs {
		score := o.getCVSSScore(cve)
		severity := o.getSeverity(score)

		fmt.Printf("%d. %s - CVSS: %.1f (%s)\n", i+1, cve.ID, score, severity)

		// Get English description
		description := o.getEnglishDescription(cve)
		fmt.Printf("   Description: %s\n", o.truncateString(description, o.config.Output.TruncateLength))
		fmt.Printf("   Published: %s\n", cve.Published)

		if len(cve.References) > 0 {
			fmt.Printf("   Reference: %s\n", cve.References[0].URL)
		}

		// Show CPE information if available
		if len(cve.Configurations) > 0 {
			fmt.Printf("   Affected Products: %s\n", o.getAffectedProducts(cve))
		}

		fmt.Println()
	}

	return nil
}

// outputJSON outputs results in JSON format
func (o *OutputFormatter) outputJSON(result *types.SearchResult) error {
	output := map[string]interface{}{
		"search_date":     result.Date,
		"min_cvss":        result.MinCVSS,
		"max_cvss":        result.MaxCVSS,
		"products":        result.Products,
		"total_found":     result.TotalFound,
		"query_time":      result.QueryTime,
		"vulnerabilities": result.CVEs,
	}

	return json.NewEncoder(os.Stdout).Encode(output)
}

// outputYAML outputs results in YAML format
func (o *OutputFormatter) outputYAML(result *types.SearchResult) error {
	output := map[string]interface{}{
		"search_date":     result.Date,
		"min_cvss":        result.MinCVSS,
		"max_cvss":        result.MaxCVSS,
		"products":        result.Products,
		"total_found":     result.TotalFound,
		"query_time":      result.QueryTime,
		"vulnerabilities": result.CVEs,
	}

	return yaml.NewEncoder(os.Stdout).Encode(output)
}

// outputTable outputs results in a formatted table
func (o *OutputFormatter) outputTable(result *types.SearchResult) error {
	if len(result.CVEs) == 0 {
		fmt.Printf("No vulnerabilities found for %s\n", result.Date)
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	// Header
	fmt.Fprintln(w, "CVE ID\tCVSS\tSeverity\tPublished\tDescription\tReference")
	fmt.Fprintln(w, "-------\t-----\t--------\t---------\t-----------\t----------")

	// Data rows
	for _, cve := range result.CVEs {
		score := o.getCVSSScore(cve)
		severity := o.getSeverity(score)
		description := o.getEnglishDescription(cve)
		description = o.truncateString(description, 50)

		reference := ""
		if len(cve.References) > 0 {
			reference = cve.References[0].URL
		}

		fmt.Fprintf(w, "%s\t%.1f\t%s\t%s\t%s\t%s\n",
			cve.ID,
			score,
			severity,
			cve.Published,
			description,
			reference)
	}

	return nil
}

// outputCSV outputs results in CSV format
func (o *OutputFormatter) outputCSV(result *types.SearchResult) error {
	if len(result.CVEs) == 0 {
		fmt.Printf("No vulnerabilities found for %s\n", result.Date)
		return nil
	}

	writer := csv.NewWriter(os.Stdout)
	defer writer.Flush()

	// Header
	header := []string{"CVE ID", "CVSS Score", "Severity", "Published", "Modified", "Status", "Description", "Reference", "Affected Products"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Data rows
	for _, cve := range result.CVEs {
		score := o.getCVSSScore(cve)
		severity := o.getSeverity(score)
		description := o.getEnglishDescription(cve)
		affectedProducts := o.getAffectedProducts(cve)

		reference := ""
		if len(cve.References) > 0 {
			reference = cve.References[0].URL
		}

		row := []string{
			cve.ID,
			strconv.FormatFloat(score, 'f', 1, 64),
			severity,
			cve.Published,
			cve.Modified,
			cve.Status,
			description,
			reference,
			affectedProducts,
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	return nil
}

// getCVSSScore returns the CVSS score for a CVE (preferring v3.1 over v2)
func (o *OutputFormatter) getCVSSScore(cve types.CVE) float64 {
	if len(cve.Metrics.CVSSMetricV31) > 0 {
		return cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
	}
	if len(cve.Metrics.CVSSMetricV2) > 0 {
		return cve.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
	}
	return 0.0
}

// getSeverity returns the severity level for a CVSS score
func (o *OutputFormatter) getSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score >= 0.1:
		return "LOW"
	default:
		return "NONE"
	}
}

// getEnglishDescription returns the English description of a CVE
func (o *OutputFormatter) getEnglishDescription(cve types.CVE) string {
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			return desc.Value
		}
	}
	return "No description available"
}

// getAffectedProducts returns a string representation of affected products
func (o *OutputFormatter) getAffectedProducts(cve types.CVE) string {
	var products []string

	for _, config := range cve.Configurations {
		for _, node := range config.Nodes {
			for _, cpeMatch := range node.CPEMatch {
				if cpeMatch.Vulnerable {
					// Extract product name from CPE
					if productName := o.extractProductName(cpeMatch.Criteria); productName != "" {
						products = append(products, productName)
					}
				}
			}
		}
	}

	if len(products) == 0 {
		return "Unknown"
	}

	// Remove duplicates and join
	uniqueProducts := make(map[string]bool)
	var uniqueList []string
	for _, product := range products {
		if !uniqueProducts[product] {
			uniqueProducts[product] = true
			uniqueList = append(uniqueList, product)
		}
	}

	return strings.Join(uniqueList, ", ")
}

// extractProductName extracts a readable product name from a CPE string
func (o *OutputFormatter) extractProductName(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) >= 5 {
		vendor := parts[3]
		product := parts[4]
		if vendor != "*" && product != "*" {
			return fmt.Sprintf("%s %s", vendor, product)
		}
	}
	return ""
}

// truncateString truncates a string to the specified length
func (o *OutputFormatter) truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// PrintSummary prints a summary of the results
func (o *OutputFormatter) PrintSummary(result *types.SearchResult) {
	fmt.Printf("\n--- Summary ---\n")
	fmt.Printf("Search Date: %s\n", result.Date)
	fmt.Printf("Products Monitored: %d\n", len(result.Products))
	fmt.Printf("Vulnerabilities Found: %d\n", result.TotalFound)
	fmt.Printf("Query Time: %s\n", result.QueryTime)

	if result.MinCVSS > 0 {
		fmt.Printf("Minimum CVSS Score: %.1f\n", result.MinCVSS)
	}
	if result.MaxCVSS > 0 {
		fmt.Printf("Maximum CVSS Score: %.1f\n", result.MaxCVSS)
	}

	if len(result.CVEs) > 0 {
		// Count by severity
		critical, high, medium, low := 0, 0, 0, 0
		for _, cve := range result.CVEs {
			score := o.getCVSSScore(cve)
			switch {
			case score >= 9.0:
				critical++
			case score >= 7.0:
				high++
			case score >= 4.0:
				medium++
			case score >= 0.1:
				low++
			}
		}

		fmt.Printf("\nSeverity Breakdown:\n")
		fmt.Printf("  Critical (9.0+): %d\n", critical)
		fmt.Printf("  High (7.0-8.9): %d\n", high)
		fmt.Printf("  Medium (4.0-6.9): %d\n", medium)
		fmt.Printf("  Low (0.1-3.9): %d\n", low)
	}

	fmt.Println()
}
