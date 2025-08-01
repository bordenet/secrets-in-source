// secrets-gap-analysis.go
// This script compares the results of Trufflehog and Passhog scans to identify common and unique secrets detected by each tool.

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type SourceMetadata struct {
	Data struct {
		Filesystem struct {
			File string `json:"file"`
			Line int    `json:"line"`
		} `json:"Filesystem"`
	} `json:"Data"`
}

type TrufflehogResult struct {
	SourceMetadata SourceMetadata `json:"SourceMetadata"`
	Raw            string         `json:"Raw"`
}

type PasshogResult struct {
	File   string
	Line   int
	Secret string
}

var (
	subjectStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("226"))
	pathStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("69"))
	fileNameStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("81"))
	secretStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	tableStyle    = lipgloss.NewStyle().Border(lipgloss.NormalBorder()).Padding(1, 2).Width(240)
	excludeDirs   = []string{".git", ".github", "node_modules", "vendor", ".idea", ".vscode", "stella_deploy", "secrets_in_source"}
)

func main() {
	trufflehogFile := flag.String("t", "", "Path to the trufflehog JSON file")
	passhogFile := flag.String("p", "", "Path to the passhog text file")
	commonReport := flag.Bool("c", false, "Display common matches report")
	verboseReport := flag.Bool("v", false, "Display verbose report")
	flag.Parse()

	if *trufflehogFile == "" || *passhogFile == "" {
		fmt.Println("Usage: secrets-gap-analysis -t <trufflehog.json> -p <passhog.txt> [-c] [-v]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	trufflehogResults := parseTrufflehogFile(*trufflehogFile)
	passhogResults := parsePasshogFile(*passhogFile)

	trufflehogOnly, passhogOnly, matches, commonMatches := compareResults(trufflehogResults, passhogResults)

	if *verboseReport {
		fmt.Println(subjectStyle.Render("Trufflehog Eligible Results:"))
		printTable(trufflehogResults, nil)

		fmt.Println(subjectStyle.Render("\nPasshog Results:"))
		printTable(nil, passhogResults)
	}

	fmt.Println(subjectStyle.Render("\nSecrets only in Trufflehog:"))
	fmt.Printf("Total secrets detected: %d\n", len(trufflehogOnly))
	printTable(trufflehogOnly, nil)

	fmt.Println(subjectStyle.Render("\nSecrets only in Passhog:"))
	fmt.Printf("Total secrets detected: %d\n", len(passhogOnly))
	printTable(nil, passhogOnly)

	generateTopFilesReport(trufflehogOnly, passhogOnly)
	generateMatchPercentageReport(trufflehogResults, passhogResults, trufflehogOnly, passhogOnly, matches, commonMatches)

	if *commonReport {
		fmt.Printf(subjectStyle.Render("\nCommon Matches:\t\t\t%d\n"), len(commonMatches))
		printCommonMatches(commonMatches)
	}
}

func parseTrufflehogFile(filename string) []TrufflehogResult {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var results []TrufflehogResult
	uniqueRecords := make(map[string]bool)

	for scanner.Scan() {
		var result TrufflehogResult
		err := json.Unmarshal(scanner.Bytes(), &result)
		if err != nil {
			continue
		}

		if isExcluded(result.SourceMetadata.Data.Filesystem.File) {
			continue
		}

		recordKey := fmt.Sprintf("%s:%d:%s", result.SourceMetadata.Data.Filesystem.File, result.SourceMetadata.Data.Filesystem.Line, result.Raw)
		if !uniqueRecords[recordKey] {
			results = append(results, result)
			uniqueRecords[recordKey] = true
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	return results
}

func parsePasshogFile(filename string) []PasshogResult {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var results []PasshogResult
	uniqueRecords := make(map[string]bool)
	re := regexp.MustCompile(`\x1b\[[0-9;]*m`)

	for scanner.Scan() {
		line := re.ReplaceAllString(scanner.Text(), "")
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		file := strings.TrimSpace(parts[0])
		lineAndSecret := strings.TrimSpace(parts[1])
		lineParts := strings.SplitN(lineAndSecret, " ", 2)
		if len(lineParts) != 2 {
			continue
		}

		lineNumber, err := strconv.Atoi(strings.TrimSpace(lineParts[0]))
		if err != nil {
			continue
		}
		secret := strings.TrimSpace(lineParts[1])

		recordKey := fmt.Sprintf("%s:%d:%s", file, lineNumber, secret)
		if !uniqueRecords[recordKey] {
			results = append(results, PasshogResult{File: file, Line: lineNumber, Secret: secret})
			uniqueRecords[recordKey] = true
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	return results
}

func compareResults(trufflehogResults []TrufflehogResult, passhogResults []PasshogResult) ([]TrufflehogResult, []PasshogResult, int, map[string][]int) {
	passhogMap := make(map[string]PasshogResult)
	for _, result := range passhogResults {
		key := fmt.Sprintf("%s:%d", result.File, result.Line)
		passhogMap[key] = result
	}

	var trufflehogOnly []TrufflehogResult
	var matches int
	commonMatches := make(map[string][]int)
	for _, result := range trufflehogResults {
		trufflehogFile := result.SourceMetadata.Data.Filesystem.File
		trufflehogLine := result.SourceMetadata.Data.Filesystem.Line
		isCommon := false

		for key, passhogResult := range passhogMap {
			if strings.Contains(trufflehogFile, passhogResult.File) && trufflehogLine == passhogResult.Line {
				isCommon = true
				matches++
				commonMatches[trufflehogFile] = append(commonMatches[trufflehogFile], trufflehogLine)
				delete(passhogMap, key)
				break
			}
		}

		if !isCommon {
			trufflehogOnly = append(trufflehogOnly, result)
		}
	}

	var passhogOnly []PasshogResult
	for _, result := range passhogMap {
		passhogOnly = append(passhogOnly, result)
	}

	return trufflehogOnly, passhogOnly, matches, commonMatches
}

func generateTopFilesReport(trufflehogOnly []TrufflehogResult, passhogOnly []PasshogResult) {
	trufflehogFileCount := make(map[string]int)
	for _, result := range trufflehogOnly {
		trufflehogFileCount[result.SourceMetadata.Data.Filesystem.File]++
	}

	passhogFileCount := make(map[string]int)
	for _, result := range passhogOnly {
		passhogFileCount[result.File]++
	}

	fmt.Println(subjectStyle.Render("\nTop-20 files where Passhog did not find secrets found by Trufflehog:"))
	printTopFiles(trufflehogFileCount)

	fmt.Println(subjectStyle.Render("\nTop-20 files where Passhog had false positives:"))
	printTopFiles(passhogFileCount)
}

func printTopFiles(fileCount map[string]int) {
	type fileCountPair struct {
		File  string
		Count int
	}

	var fileCountPairs []fileCountPair
	for file, count := range fileCount {
		fileCountPairs = append(fileCountPairs, fileCountPair{File: file, Count: count})
	}

	sort.Slice(fileCountPairs, func(i, j int) bool {
		return fileCountPairs[i].Count > fileCountPairs[j].Count
	})

	for i := 0; i < len(fileCountPairs) && i < 20; i++ {
		fmt.Printf("%s, Count: %d\n", fileNameStyle.Render(fileCountPairs[i].File), fileCountPairs[i].Count)
	}
}

func generateMatchPercentageReport(trufflehogResults []TrufflehogResult, passhogResults []PasshogResult, trufflehogOnly []TrufflehogResult, passhogOnly []PasshogResult, matches int, commonMatches map[string][]int) {
	totalTrufflehog := len(trufflehogResults)
	totalPasshog := len(passhogResults)
	falsePositives := len(passhogOnly)

	matchPercentage := float64(matches) / float64(totalTrufflehog) * 100
	falsePositivePercentage := float64(falsePositives) / float64(totalPasshog) * 100

	passhogRecordsStyle := fileNameStyle
	if float64(totalPasshog) > float64(totalTrufflehog)*1.1 {
		passhogRecordsStyle = passhogRecordsStyle.Foreground(lipgloss.Color("160")) // Dark red
	}

	horizontalLine := strings.Repeat("-", 48)

	fmt.Println(tableStyle.Width(48).Render(fmt.Sprintf(
		"%-30s %10d\n%-30s %s\n%s\n%-30s %10d\n%-30s %10d\n%s\n%-30s %10.2f%%\n%-30s %10.2f%%",
		"Trufflehog records:", totalTrufflehog,
		"Passhog records:", passhogRecordsStyle.Render(fmt.Sprintf("%10d", totalPasshog)),
		horizontalLine,
		"Files w/ Secrets Matched:", len(commonMatches),
		"Total Num Secrets Matched:", matches,
		horizontalLine,
		"Match Percentage:", matchPercentage,
		"False Positive Rate:", falsePositivePercentage,
	)))
}

func firstLine(s string) string {
	if idx := strings.Index(s, "\n"); idx != -1 {
		return s[:idx]
	}
	return s
}

func printTable(trufflehogResults []TrufflehogResult, passhogResults []PasshogResult) {
	var rows []string
	if trufflehogResults != nil {
		for _, result := range trufflehogResults {
			relativePath, fileName := splitPath(result.SourceMetadata.Data.Filesystem.File)
			row := fmt.Sprintf("%s/%s, Line: %d, Secret: %s", pathStyle.Render(relativePath), fileNameStyle.Render(fileName), result.SourceMetadata.Data.Filesystem.Line, secretStyle.Render(truncate(firstLine(result.Raw), 100)))
			rows = append(rows, row)
		}
	} else if passhogResults != nil {
		for _, result := range passhogResults {
			relativePath, fileName := splitPath(result.File)
			row := fmt.Sprintf("%s/%s, Line: %d, Secret: %s", pathStyle.Render(relativePath), fileNameStyle.Render(fileName), result.Line, secretStyle.Render(truncate(firstLine(result.Secret), 100)))
			rows = append(rows, row)
		}
	}

	table := tableStyle.Render(strings.Join(rows, "\n"))
	fmt.Println(table)
}

func listSecretsByFile(trufflehogResults []TrufflehogResult, passhogResults []PasshogResult) {
	if trufflehogResults != nil {
		fileCount := make(map[string]int)
		for _, result := range trufflehogResults {
			fileCount[result.SourceMetadata.Data.Filesystem.File]++
		}
		printFileCount(fileCount)
	} else if passhogResults != nil {
		fileCount := make(map[string]int)
		for _, result := range passhogResults {
			fileCount[result.File]++
		}
		printFileCount(fileCount)
	}
}

func printFileCount(fileCount map[string]int) {
	for file, count := range fileCount {
		fmt.Printf("%s, Count: %d\n", fileNameStyle.Render(file), count)
	}
}

func printCommonMatches(commonMatches map[string][]int) {
	for file, lines := range commonMatches {
		fmt.Printf("%s, Matches: %d (%v)\n", fileNameStyle.Render(file), len(lines), lines)
	}
}

func splitPath(fullPath string) (string, string) {
	idx := strings.LastIndex(fullPath, "/")
	if idx == -1 {
		return "", fullPath
	}
	return fullPath[:idx], fullPath[idx+1:]
}

func truncate(s string, maxLength int) string {
	if len(s) > maxLength {
		return s[:maxLength] + "..."
	}
	return s
}

func isExcluded(filePath string) bool {
	for _, dir := range excludeDirs {
		if strings.Contains(filePath, dir) {
			return true
		}
	}
	return false
}
