package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

// SBOMEntry represents the structure of an SBOM entry.
type SBOMEntry struct {
	Name        string `json:"name"`
	License     string `json:"licenseDeclared"`
	Supplier    string `json:"supplier"`
	VersionInfo string `json:"versionInfo"`
}

// SBOMDocument represents the structure of the entire SBOM JSON document.
type SBOMDocument struct {
	Packages []SBOMEntry `json:"packages"`
}

// FieldMapping represents the mapping of JSON keys to the required fields.
type FieldMapping struct {
	FieldMap map[string]string // Key: JSON key, Value: Column name for the Markdown table
}

// readJSON reads and parses the JSON file, returning a slice of SBOMEntry.
func readJSON(filePath string) ([]SBOMEntry, error) {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var sbomDoc SBOMDocument
	if err := json.Unmarshal(file, &sbomDoc); err != nil {
		return nil, err
	}

	return sbomDoc.Packages, nil
}

// generateMarkdown generates a Markdown table from a slice of SBOMEntry.
func generateMarkdown(entries []SBOMEntry, title string, mapping FieldMapping) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("## %s\n\n", title))

	// Generate table header
	sb.WriteString("|")
	for _, columnName := range mapping.FieldMap {
		sb.WriteString(fmt.Sprintf(" %s |", columnName))
	}
	sb.WriteString("\n")

	// Generate table separator
	sb.WriteString("|")
	for range mapping.FieldMap {
		sb.WriteString("---|")
	}
	sb.WriteString("\n")

	// Generate table rows
	for _, entry := range entries {
		sb.WriteString("|")
		sb.WriteString(fmt.Sprintf(" %s | %s | %s | %s |\n",
			entry.Name, entry.License, entry.Supplier, entry.VersionInfo))
	}

	sb.WriteString("\n")
	return sb.String()
}

func main() {
	// Command-line argument parsing
	sbomFilePath := flag.String("sbom", "", "Path to the SBOM JSON file")

	flag.Parse()

	if *sbomFilePath == "" {
		fmt.Println("Error: SBOM JSON file path must be provided.")
		flag.Usage()
		return
	}

	// Read and parse the SBOM JSON file
	sbomEntries, err := readJSON(*sbomFilePath)
	if err != nil {
		fmt.Println("Error reading SBOM JSON:", err)
		return
	}

	// Define the mapping from struct fields to Markdown headers
	sbomMapping := FieldMapping{
		FieldMap: map[string]string{
			"VersionInfo": "Version",
			"Name":        "Package Name",
			"License":     "License",
			"Supplier":    "Source",
		},
	}

	// Generate the Markdown content
	var markdownContent strings.Builder
	markdownContent.WriteString(generateMarkdown(sbomEntries, "SBOM Insights", sbomMapping))

	// Write the Markdown content to a file
	err = os.WriteFile("./ansible-attestations/insights.md", []byte(markdownContent.String()), 0o644)
	if err != nil {
		fmt.Println("Error writing Markdown file:", err)
		return
	}

	fmt.Println("Markdown file 'insights.md' generated successfully.")
}
