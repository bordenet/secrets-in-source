// secrets-gap-analysis.go
// This script compares the results of Trufflehog and Fasthog scans to identify common and unique secrets detected by each tool.

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

type FasthogResult struct {
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
	fasthogFile := flag.String("p", "", "Path to the fasthog text file")
	commonReport := flag.Bool("c", false, "Display common matches report")
	verboseReport := flag.Bool("v", false, "Display verbose report")
	flag.Parse()

	if *trufflehogFile == "" || *fasthogFile == "" {
		fmt.Println("Usage: secrets-gap-analysis -t <trufflehog.json> -p <fasthog.txt> [-c] [-v]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	trufflehogResults := parseTrufflehogFile(*trufflehogFile)
	fasthogResults := parseFasthogFile(*fasthogFile)

	trufflehogOnly, fasthogOnly, matches, commonMatches := compareResults(trufflehogResults, fasthogResults)

	if *verboseReport {
		fmt.Println(subjectStyle.Render("Trufflehog Eligible Results:"))
		printTable(trufflehogResults, nil)

		fmt.Println(subjectStyle.Render("\nFasthog Results:"))
		printTable(nil, fasthogResults)
	}

	fmt.Println(subjectStyle.Render("\nSecrets only in Trufflehog:"))
	fmt.Printf("Total secrets detected: %d\n", len(trufflehogOnly))
	printTable(trufflehogOnly, nil)

	fmt.Println(subjectStyle.Render("\nSecrets only in Fasthog:"))
	fmt.Printf("Total secrets detected: %d\n", len(fasthogOnly))
	printTable(nil, fasthogOnly)

	generateTopFilesReport(trufflehogOnly, fasthogOnly)
	generateMatchPercentageReport(trufflehogResults, fasthogResults, trufflehogOnly, fasthogOnly, matches, commonMatches)

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
	defer func() {
		_ = file.Close() // Best effort close
	}()

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

func parseFasthogFile(filename string) []FasthogResult {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer func() {
		_ = file.Close() // Best effort close
	}()

	scanner := bufio.NewScanner(file)
	var results []FasthogResult
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
			results = append(results, FasthogResult{File: file, Line: lineNumber, Secret: secret})
			uniqueRecords[recordKey] = true
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	return results
}

func compareResults(trufflehogResults []TrufflehogResult, fasthogResults []FasthogResult) ([]TrufflehogResult, []FasthogResult, int, map[string][]int) {
	fasthogMap := make(map[string]FasthogResult)
	for _, result := range fasthogResults {
		key := fmt.Sprintf("%s:%d", result.File, result.Line)
		fasthogMap[key] = result
	}

	var trufflehogOnly []TrufflehogResult
	var matches int
	commonMatches := make(map[string][]int)
	for _, result := range trufflehogResults {
		trufflehogFile := result.SourceMetadata.Data.Filesystem.File
		trufflehogLine := result.SourceMetadata.Data.Filesystem.Line
		isCommon := false

		for key, fasthogResult := range fasthogMap {
			if strings.Contains(trufflehogFile, fasthogResult.File) && trufflehogLine == fasthogResult.Line {
				isCommon = true
				matches++
				commonMatches[trufflehogFile] = append(commonMatches[trufflehogFile], trufflehogLine)
				delete(fasthogMap, key)
				break
			}
		}

		if !isCommon {
			trufflehogOnly = append(trufflehogOnly, result)
		}
	}

	var fasthogOnly []FasthogResult
	for _, result := range fasthogMap {
		fasthogOnly = append(fasthogOnly, result)
	}

	return trufflehogOnly, fasthogOnly, matches, commonMatches
}

func generateTopFilesReport(trufflehogOnly []TrufflehogResult, fasthogOnly []FasthogResult) {
	trufflehogFileCount := make(map[string]int)
	for _, result := range trufflehogOnly {
		trufflehogFileCount[result.SourceMetadata.Data.Filesystem.File]++
	}

	fasthogFileCount := make(map[string]int)
	for _, result := range fasthogOnly {
		fasthogFileCount[result.File]++
	}

	fmt.Println(subjectStyle.Render("\nTop-20 files where Fasthog did not find secrets found by Trufflehog:"))
	printTopFiles(trufflehogFileCount)

	fmt.Println(subjectStyle.Render("\nTop-20 files where Fasthog had false positives:"))
	printTopFiles(fasthogFileCount)
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

func generateMatchPercentageReport(trufflehogResults []TrufflehogResult, fasthogResults []FasthogResult, trufflehogOnly []TrufflehogResult, fasthogOnly []FasthogResult, matches int, commonMatches map[string][]int) {
	totalTrufflehog := len(trufflehogResults)
	totalFasthog := len(fasthogResults)
	falsePositives := len(fasthogOnly)

	matchPercentage := float64(matches) / float64(totalTrufflehog) * 100
	falsePositivePercentage := float64(falsePositives) / float64(totalFasthog) * 100

	fasthogRecordsStyle := fileNameStyle
	if float64(totalFasthog) > float64(totalTrufflehog)*1.1 {
		fasthogRecordsStyle = fasthogRecordsStyle.Foreground(lipgloss.Color("160")) // Dark red
	}

	horizontalLine := strings.Repeat("-", 48)

	fmt.Println(tableStyle.Width(48).Render(fmt.Sprintf(
		"%-30s %10d\n%-30s %s\n%s\n%-30s %10d\n%-30s %10d\n%s\n%-30s %10.2f%%\n%-30s %10.2f%%",
		"Trufflehog records:", totalTrufflehog,
		"Fasthog records:", fasthogRecordsStyle.Render(fmt.Sprintf("%10d", totalFasthog)),
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

func printTable(trufflehogResults []TrufflehogResult, fasthogResults []FasthogResult) {
	var rows []string
	if trufflehogResults != nil {
		for _, result := range trufflehogResults {
			relativePath, fileName := splitPath(result.SourceMetadata.Data.Filesystem.File)
			row := fmt.Sprintf("%s/%s, Line: %d, Secret: %s", pathStyle.Render(relativePath), fileNameStyle.Render(fileName), result.SourceMetadata.Data.Filesystem.Line, secretStyle.Render(truncate(firstLine(result.Raw), 100)))
			rows = append(rows, row)
		}
	} else {
		for _, result := range fasthogResults {
			relativePath, fileName := splitPath(result.File)
			row := fmt.Sprintf("%s/%s, Line: %d, Secret: %s", pathStyle.Render(relativePath), fileNameStyle.Render(fileName), result.Line, secretStyle.Render(truncate(firstLine(result.Secret), 100)))
			rows = append(rows, row)
		}
	}

	table := tableStyle.Render(strings.Join(rows, "\n"))
	fmt.Println(table)
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
