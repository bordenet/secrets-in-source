// Package main implements fasthog, a secrets detection tool for source code repositories.
//
// Fasthog scans directories for potential secrets and credentials using configurable
// regular expression patterns. It employs a two-stage detection approach with fast
// preliminary patterns and strict validation patterns, while filtering out known
// false positives.
//
// Usage:
//
//	fasthog <directory> [--types=<extensions>] [--output=<file>]
//
// Arguments:
//
//	directory              Directory to scan for secrets
//	--types=<extensions>   Comma-separated file extensions to scan (e.g., py,js,yml)
//	--output=<file>        Write results to specified file
//
// Example:
//
//	fasthog /path/to/repo --types=py,js --output=results.txt
//
// The tool uses concurrent processing to scan multiple files in parallel,
// with the number of workers matching the available CPU cores.
package main

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"

	"fmt"
	"io/fs"
	"os"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/pflag"
)

//go:embed *.regex
var regexFS embed.FS

// UI styles for terminal output formatting.
var (
	styleFile        = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("4")).Render
	styleLineNo      = lipgloss.NewStyle().Foreground(lipgloss.Color("#888")).Render
	styleMatch       = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render
	styleTableHeader = lipgloss.NewStyle().Bold(true).Underline(true).Render
	styleTableRow    = lipgloss.NewStyle().Render
)

// defaultExcludeDirs contains directory names to skip during scanning.
var defaultExcludeDirs = []string{
	".git", ".github", "node_modules", "vendor", ".idea", ".vscode",
}

// defaultExtensions contains file extensions to scan when no specific types are provided.
var defaultExtensions = []string{
	".js", ".json", ".py", ".cs", ".go", ".java", ".sh", ".tf", ".yml", ".yaml",
	".env", "env", ".ENV", "ENV", ".key", ".backup", ".tfstate", ".ts", ".txt",
	".md", ".properties",
}

// OutputFormat represents the supported output formats for fasthog.
type OutputFormat string

const (
	OutputFormatText OutputFormat = "text"
	OutputFormatJSON OutputFormat = "json"
)

// Match represents a single detected secret occurrence.
type Match struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	LineSnippet string `json:"line_snippet"`
	MatchText   string `json:"match_text"`
}

// FileMatchCount represents the number of matches found in a single file.
type FileMatchCount struct {
	File  string `json:"file"`
	Count int    `json:"match_count"`
}

// ScanSummary captures aggregate information about a scan.
type ScanSummary struct {
	TotalMatches        int `json:"total_matches"`
	TotalFilesWithMatch int `json:"total_files_with_matches"`
	TotalFilesScanned   int `json:"total_files_scanned"`
}

// JSONResult is the top-level structure emitted when using JSON output format.
type JSONResult struct {
	Directory  string           `json:"directory"`
	Extensions []string         `json:"extensions"`
	StartTime  time.Time        `json:"start_time"`
	DurationMs int64            `json:"duration_ms"`
	Matches    []Match          `json:"matches"`
	Summary    ScanSummary      `json:"summary"`
	TopFiles   []FileMatchCount `json:"top_files"`
}

// parseOutputFormat converts a user-supplied string into an OutputFormat value.
func parseOutputFormat(format string) (OutputFormat, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", string(OutputFormatText):
		return OutputFormatText, nil
	case string(OutputFormatJSON):
		return OutputFormatJSON, nil
	default:
		return "", fmt.Errorf("invalid output format %q (supported: text, json)", format)
	}
}

// scanOptions controls the behaviour of the core scanning engine.
type scanOptions struct {
	Directory   string
	Extensions  []string
	ExcludeDirs []string

	ExcludePatterns *regexp.Regexp
	FastPatterns    *regexp.Regexp
	SlowPatterns    *regexp.Regexp

	// OnCurrentFile, if non-nil, is invoked whenever a file is about to be scanned.
	// index is zero-based, total is the total number of files to scan.
	OnCurrentFile func(path string, index, total int)

	// OnMatch, if non-nil, is invoked whenever a matching line is found.
	OnMatch func(path string, lineNo int, line string, match string)
}

// scanResult captures the structured output from a scan.
type scanResult struct {
	Matches    []Match
	MatchFiles map[string]int
	Filenames  []string
}

// mergeExcludeDirs returns the union of defaultExcludeDirs and any additional
// directories supplied in extra, preserving order and avoiding duplicates.
func mergeExcludeDirs(extra []string) []string {
	if len(extra) == 0 {
		out := make([]string, len(defaultExcludeDirs))
		copy(out, defaultExcludeDirs)
		return out
	}

	seen := make(map[string]struct{}, len(defaultExcludeDirs)+len(extra))
	var merged []string

	for _, d := range defaultExcludeDirs {
		if _, ok := seen[d]; !ok {
			seen[d] = struct{}{}
			merged = append(merged, d)
		}
	}

	for _, d := range extra {
		if _, ok := seen[d]; !ok {
			seen[d] = struct{}{}
			merged = append(merged, d)
		}
	}

	return merged
}

// scanDirectory walks the target directory and applies the supplied patterns,
// returning structured matches and per-file counts. This function is intentionally
// UI-agnostic so it can be reused by both the TUI and JSON output paths.
func scanDirectory(opts scanOptions) scanResult {
	result := scanResult{
		MatchFiles: make(map[string]int),
	}

	root := os.DirFS(opts.Directory)
	excludeDirs := mergeExcludeDirs(opts.ExcludeDirs)

	// Collect the list of files to scan.
	var filenames []string
	_ = fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !hasExtension(path, opts.Extensions) {
			return nil
		}

		parts := strings.Split(path, "/")
		for _, excludeDir := range excludeDirs {
			if slices.Contains(parts, excludeDir) {
				return nil
			}
		}

		filenames = append(filenames, path)
		return nil
	})

	result.Filenames = filenames

	var (
		mu        sync.Mutex
		semaphore = make(chan struct{}, runtime.NumCPU())
		wg        sync.WaitGroup
	)

	for i, path := range filenames {
		semaphore <- struct{}{}
		wg.Add(1)

		if opts.OnCurrentFile != nil {
			opts.OnCurrentFile(path, i, len(filenames))
		}

		go func(path string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			f, err := root.Open(path) // https://go.dev/blog/loopvar-preview
			if err != nil {
				panic(fmt.Errorf("unable to open file %s: %w", path, err))
			}
			defer func() {
				if closeErr := f.Close(); closeErr != nil {
					panic(fmt.Errorf("failed to close file %s: %w", path, closeErr))
				}
			}()

			scanner := bufio.NewScanner(f)
			lineNo := 0
			for scanner.Scan() {
				lineNo++
				line := scanner.Text()
				if len(line) <= 8 {
					continue
				}
				if opts.FastPatterns.MatchString(line) {
					if match := opts.SlowPatterns.FindString(line); match != "" && !opts.ExcludePatterns.MatchString(line) {
						if opts.OnMatch != nil {
							opts.OnMatch(path, lineNo, line, match)
						}
						mu.Lock()
						result.Matches = append(result.Matches, Match{
							File:        path,
							Line:        lineNo,
							LineSnippet: strings.TrimSpace(line),
							MatchText:   match,
						})
						result.MatchFiles[path]++
						mu.Unlock()
					}
				}
			}
		}(path)
	}

	wg.Wait()
	return result
}

// buildUsage constructs the primary usage/help text for the CLI.
func buildUsage() string {
	return `Usage: fasthog <directory> [flags]

Flags:
  --types string     Comma-separated file extensions to include (e.g., yml,yaml,sh)
  --output string    Path where output should be written
  --format string    Output format: text or json (default "text")
  --json             Shortcut for --format=json
  --config string    Path to config file (default: fasthog.yaml if present)
`
}

// validateDirectory ensures that the provided path exists and is a directory.
func validateDirectory(directory string) error {
	info, err := os.Stat(directory)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("directory does not exist: %s", directory)
		}
		return fmt.Errorf("cannot access directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", directory)
	}
	return nil
}

// PatternFiles describes optional overrides for the default regex pattern files.
type PatternFiles struct {
	Direct  string
	Fast    string
	Strict  string
	Exclude string
}

// OutputConfig holds configuration related to the scan output.
type OutputConfig struct {
	Path   string
	Format string
}

// Config represents the contents of a fasthog configuration file.
// It intentionally models only the fields we currently support; unknown fields
// in the YAML are ignored to allow forward compatibility.
type Config struct {
	Directory   string
	Extensions  []string
	ExcludeDirs []string
	Patterns    PatternFiles
	Output      OutputConfig
}

// loadConfig parses a minimal YAML configuration file. It supports the subset
// of YAML we need:
//
//	directory: path
//	extensions:
//	  - .go
//	  - py
//	exclude_dirs:
//	  - build
//	output:
//	  path: results.txt
//	  format: json
//	patterns:
//	  direct: direct_matches.regex
//	  fast: fast_patterns.regex
//	  strict: strict_patterns.regex
//	  exclude: exclude_patterns.regex
//
// List values must use the "- item" form; inline YAML lists are not supported.
func loadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("unable to read config file %s: %w", path, err)
	}

	var cfg Config
	var currentSection string

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			currentSection = ""
			key, value := splitKeyValue(trimmed)
			switch key {
			case "directory":
				cfg.Directory = value
			case "extensions":
				currentSection = "extensions"
			case "exclude_dirs":
				currentSection = "exclude_dirs"
			case "output":
				currentSection = "output"
			case "patterns":
				currentSection = "patterns"
			default:
				// Ignore unknown top-level keys for forward compatibility.
			}
			continue
		}

		trimmedIndent := strings.TrimSpace(line)

		switch currentSection {
		case "extensions":
			if strings.HasPrefix(trimmedIndent, "- ") {
				val := strings.TrimSpace(strings.TrimPrefix(trimmedIndent, "- "))
				if val != "" {
					if !strings.HasPrefix(val, ".") {
						val = "." + val
					}
					cfg.Extensions = append(cfg.Extensions, val)
				}
			}
		case "exclude_dirs":
			if strings.HasPrefix(trimmedIndent, "- ") {
				val := strings.TrimSpace(strings.TrimPrefix(trimmedIndent, "- "))
				if val != "" {
					cfg.ExcludeDirs = append(cfg.ExcludeDirs, val)
				}
			}
		case "output":
			key, value := splitKeyValue(trimmed)
			switch key {
			case "path":
				cfg.Output.Path = value
			case "format":
				cfg.Output.Format = value
			}
		case "patterns":
			key, value := splitKeyValue(trimmed)
			switch key {
			case "direct":
				cfg.Patterns.Direct = value
			case "fast":
				cfg.Patterns.Fast = value
			case "strict":
				cfg.Patterns.Strict = value
			case "exclude":
				cfg.Patterns.Exclude = value
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return Config{}, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	return cfg, nil
}

// determineExtensions applies precedence rules to compute the effective
// extension set used for scanning: CLI flag > config > defaults.
//
// If the --types flag is set but contains only whitespace/commas (no valid
// extensions), the function falls through to config or defaults. This allows
// graceful handling of malformed input without breaking the scan.
func determineExtensions(extensionsFlag string, flagChanged bool, cfg Config) []string {
	if flagChanged && extensionsFlag != "" {
		parts := strings.Split(extensionsFlag, ",")
		extensions := make([]string, 0, len(parts))
		for _, ext := range parts {
			ext = strings.TrimSpace(ext)
			if ext == "" {
				continue
			}
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			extensions = append(extensions, ext)
		}
		// If CLI flag was set but all values were invalid (whitespace/commas),
		// fall through to config or defaults rather than failing.
		if len(extensions) > 0 {
			return extensions
		}
	}

	if len(cfg.Extensions) > 0 {
		return append([]string(nil), cfg.Extensions...)
	}

	return defaultExtensions
}

// determineOutputFormat applies precedence between the --format flag,
// the --json flag, and any configured output format.
func determineOutputFormat(formatFlag string, formatFlagChanged bool, jsonFlag bool, jsonFlagChanged bool, cfg Config) (OutputFormat, error) {
	formatValue := formatFlag
	if jsonFlag {
		formatValue = string(OutputFormatJSON)
	}

	if !formatFlagChanged && !jsonFlagChanged && cfg.Output.Format != "" {
		formatValue = cfg.Output.Format
	}

	return parseOutputFormat(formatValue)
}

// determineOutputPath applies precedence between the --output flag and
// any configured output path.
func determineOutputPath(outputFlag string, flagChanged bool, cfg Config) string {
	if !flagChanged && outputFlag == "" && cfg.Output.Path != "" {
		return cfg.Output.Path
	}

	return outputFlag
}

// splitKeyValue splits a "key: value" YAML line into key and value components.
func splitKeyValue(s string) (key, value string) {
	parts := strings.SplitN(s, ":", 2)
	key = strings.TrimSpace(parts[0])
	if len(parts) == 2 {
		value = strings.TrimSpace(parts[1])
	}
	return key, value
}

// loadEffectivePatterns loads the regex patterns used for scanning, applying
// any file overrides specified in patternFiles. When no overrides are
// provided, the embedded default patterns are used.
func loadEffectivePatterns(patternFiles PatternFiles) (exclude, fast, slow *regexp.Regexp, err error) {
	overrideFS := os.DirFS(".")

	// Exclude patterns.
	if patternFiles.Exclude != "" {
		exclude, err = loadRegexes(overrideFS, patternFiles.Exclude)
		if err != nil {
			err = fmt.Errorf("failed to load exclude patterns from %s: %w", patternFiles.Exclude, err)
			return
		}
	} else {
		exclude, err = loadRegexes(regexFS, "exclude_patterns.regex")
		if err != nil {
			err = fmt.Errorf("failed to load exclude patterns: %w", err)
			return
		}
	}

	// Fast patterns.
	if patternFiles.Fast != "" {
		fast, err = loadRegexes(overrideFS, patternFiles.Fast)
		if err != nil {
			err = fmt.Errorf("failed to load fast patterns from %s: %w", patternFiles.Fast, err)
			return
		}
	} else {
		fast, err = loadRegexes(regexFS, "direct_matches.regex", "fast_patterns.regex")
		if err != nil {
			err = fmt.Errorf("failed to load fast patterns: %w", err)
			return
		}
	}

	// Slow (strict) patterns. If either direct or strict overrides are supplied,
	// they fully replace the embedded slow patterns.
	if patternFiles.Direct != "" || patternFiles.Strict != "" {
		var paths []string
		if patternFiles.Direct != "" {
			paths = append(paths, patternFiles.Direct)
		}
		if patternFiles.Strict != "" {
			paths = append(paths, patternFiles.Strict)
		}

		slow, err = loadRegexes(overrideFS, paths...)
		if err != nil {
			err = fmt.Errorf("failed to load strict patterns from override files: %w", err)
			return
		}
	} else {
		slow, err = loadRegexes(regexFS, "direct_matches.regex", "strict_patterns.regex")
		if err != nil {
			err = fmt.Errorf("failed to load strict patterns: %w", err)
			return
		}
	}

	return
}

// shellReplacer replaces bash escape sequences in regex files to maintain
// compatibility with the original shell script implementation.
var shellReplacer = strings.NewReplacer(`\\`, `\`, `\"`, `"`)

// loadRegexes loads and compiles regular expressions from one or more embedded files.
// It combines all patterns into a single compiled regex for efficient matching.
// Lines starting with '#' are treated as comments and ignored.
func loadRegexes(filesystem fs.FS, paths ...string) (*regexp.Regexp, error) {
	var regexes string
	for _, path := range paths {
		b, err := fs.ReadFile(filesystem, path)
		if err != nil {
			return nil, fmt.Errorf("unable to load regexes from %s: %w", path, err)
		}
		for _, line := range bytes.Split(b, []byte("\n")) {
			if len(line) == 0 || line[0] == '#' {
				continue
			}
			if len(regexes) > 0 {
				regexes += "|"
			}
			regexes += "(" + string(line) + ")"
		}
	}

	regexes = shellReplacer.Replace(regexes)
	compiled, err := regexp.Compile(regexes)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex patterns: %w", err)
	}
	return compiled, nil
}

// hasExtension checks if a file path has one of the specified extensions.
func hasExtension(path string, extensions []string) bool {
	return slices.ContainsFunc(extensions, func(ext string) bool {
		return strings.HasSuffix(strings.ToLower(path), ext)
	})
}

// UI message types for the Bubble Tea interface.

// msgCurrentFile indicates progress through the file list.
type msgCurrentFile struct {
	path    string
	percent float64
}

// msgMatch indicates a secret was found.
type msgMatch struct{}

// msgDone indicates scanning is complete.
type msgDone struct{}

// model holds the UI state for the progress display.
type model struct {
	currentFile string
	percent     float64
	matches     int
	progress    progress.Model
}

// Init initializes the model. Required by tea.Model interface.
func (m model) Init() tea.Cmd {
	return nil
}

// Update handles UI events and updates the model state.
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.progress.Width = msg.Width
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		}
	case msgCurrentFile:
		m.currentFile = msg.path
		m.percent = msg.percent
	case msgMatch:
		m.matches++
	case msgDone:
		m.percent = 100.0
		return m, tea.Quit
	}
	return m, nil
}

// View renders the UI display showing current progress and match count.
func (m model) View() string {
	matchCount := fmt.Sprintf("%d", m.matches)
	currentFile := m.currentFile
	space := m.progress.Width - len("Matches: "+matchCount) - 15
	if len(currentFile) > space {
		currentFile = "..." + currentFile[max(0, len(currentFile)-space+3):]
	}
	currentFile += strings.Repeat(" ", max(0, space-len(currentFile)))
	s := "Current file: " + styleFile(currentFile) + " Matches: " + styleMatch(matchCount) + "\n"
	s += m.progress.ViewAs(m.percent) + "\n"
	return s
}

func main() {
	var outputPath string
	pflag.StringVar(&outputPath, "output", "", "Path where output should be written")

	var extensionsList string
	pflag.StringVar(&extensionsList, "types", "", "Comma-separated list of file extensions to include (e.g., yml,yaml,sh)")

	var formatFlag string
	pflag.StringVar(&formatFlag, "format", string(OutputFormatText), "Output format: text or json")

	var jsonFlag bool
	pflag.BoolVar(&jsonFlag, "json", false, "Shortcut for --format=json")

	var configPath string
	pflag.StringVar(&configPath, "config", "", "Path to configuration file (YAML; optional)")

	pflag.Parse()

	remainingArgs := pflag.Args()

	if len(remainingArgs) < 1 {
		fmt.Println(buildUsage())
		os.Exit(1)
	}

	directory := remainingArgs[0]

	// Load configuration file, if any.
	var fileCfg Config
	if configPath != "" {
		cfg, err := loadConfig(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config file %s: %v\n", configPath, err)
			os.Exit(1)
		}
		fileCfg = cfg
	} else {
		if _, err := os.Stat("fasthog.yaml"); err == nil {
			cfg, err := loadConfig("fasthog.yaml")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading config file fasthog.yaml: %v\n", err)
				os.Exit(1)
			}
			fileCfg = cfg
		}
	}

	// Determine extensions: CLI > config > defaults.
	extensions := determineExtensions(extensionsList, pflag.Lookup("types").Changed, fileCfg)

	// Determine additional excluded directories from config.
	excludeDirs := append([]string(nil), fileCfg.ExcludeDirs...)

	// Determine output format: CLI (--json or --format) > config > default(text).
	outputFormat, err := determineOutputFormat(
		formatFlag,
		pflag.Lookup("format").Changed,
		jsonFlag,
		pflag.Lookup("json").Changed,
		fileCfg,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	// Determine output path: CLI > config.
	outputPath = determineOutputPath(outputPath, pflag.Lookup("output").Changed, fileCfg)

	if outputFormat == OutputFormatText {
		fmt.Printf("Directory: %s\n", directory)
		if pflag.Lookup("types").Changed || len(fileCfg.Extensions) > 0 {
			fmt.Printf("Extensions: %v\n", extensions)
		} else {
			fmt.Println("Extensions: Using defaults")
		}
		if outputPath != "" {
			fmt.Printf("Output: %s\n", outputPath)
		}
	}

	var runErr error
	switch outputFormat {
	case OutputFormatJSON:
		runErr = runFasthogJSON(directory, extensions, excludeDirs, fileCfg.Patterns, outputPath)
	case OutputFormatText:
		fallthrough
	default:
		runErr = runFasthog(directory, extensions, excludeDirs, fileCfg.Patterns, outputPath)
	}

	if runErr != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", runErr)
		os.Exit(1)
	}
}

// runFasthogJSON executes the secrets scanning process and emits JSON output.
// It is intentionally non-interactive: no TUI, no ANSI, and only JSON on stdout.
func runFasthogJSON(directory string, extensions []string, excludeDirs []string, patternFiles PatternFiles, outputPath string) error {
	if err := validateDirectory(directory); err != nil {
		return err
	}

	excludePatterns, fastPatterns, slowPatterns, err := loadEffectivePatterns(patternFiles)
	if err != nil {
		return err
	}

	startedAt := time.Now().UTC()

	opts := scanOptions{
		Directory:       directory,
		Extensions:      extensions,
		ExcludeDirs:     excludeDirs,
		ExcludePatterns: excludePatterns,
		FastPatterns:    fastPatterns,
		SlowPatterns:    slowPatterns,
	}

	scanRes := scanDirectory(opts)

	summary := ScanSummary{
		TotalMatches:      len(scanRes.Matches),
		TotalFilesScanned: len(scanRes.Filenames),
	}
	for _, count := range scanRes.MatchFiles {
		if count > 0 {
			summary.TotalFilesWithMatch++
		}
	}

	topFiles := make([]FileMatchCount, 0, len(scanRes.MatchFiles))
	for file, count := range scanRes.MatchFiles {
		topFiles = append(topFiles, FileMatchCount{File: file, Count: count})
	}
	sort.Slice(topFiles, func(i, j int) bool {
		if topFiles[i].Count == topFiles[j].Count {
			return topFiles[i].File < topFiles[j].File
		}
		return topFiles[i].Count > topFiles[j].Count
	})

	result := JSONResult{
		Directory:  directory,
		Extensions: extensions,
		StartTime:  startedAt,
		DurationMs: time.Since(startedAt).Milliseconds(),
		Matches:    scanRes.Matches,
		Summary:    summary,
		TopFiles:   topFiles,
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode JSON output: %w", err)
	}

	// Write JSON to stdout. This must be the only output in JSON mode.
	if _, err := os.Stdout.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write JSON to stdout: %w", err)
	}

	if outputPath != "" {
		if err := os.WriteFile(outputPath, append(data, '\n'), 0o644); err != nil {
			return fmt.Errorf("failed to write JSON output to %s: %w", outputPath, err)
		}
	}

	return nil
}

// runFasthog executes the secrets scanning process on the specified directory.
// It returns an error if the scan fails.
func runFasthog(directory string, extensions []string, excludeDirs []string, patternFiles PatternFiles, outputPath string) error {
	start := time.Now()

	if err := validateDirectory(directory); err != nil {
		return err
	}

	excludePatterns, fastPatterns, slowPatterns, err := loadEffectivePatterns(patternFiles)
	if err != nil {
		return err
	}

	p := tea.NewProgram(model{
		progress: progress.New(progress.WithDefaultGradient()),
	})

	var (
		matches []string
		mu      sync.Mutex
	)

	resultsCh := make(chan scanResult, 1)

	go func() {
		opts := scanOptions{
			Directory:       directory,
			Extensions:      extensions,
			ExcludeDirs:     excludeDirs,
			ExcludePatterns: excludePatterns,
			FastPatterns:    fastPatterns,
			SlowPatterns:    slowPatterns,
			OnCurrentFile: func(path string, index, total int) {
				percent := 0.0
				if total > 0 {
					percent = float64(index) / float64(total)
				}
				p.Send(msgCurrentFile{path: path, percent: percent})
			},
			OnMatch: func(path string, lineNo int, line, match string) {
				styled := strings.TrimSpace(strings.Replace(line, match, styleMatch(match), 1))
				mu.Lock()
				matches = append(matches, styleFile(path)+styleLineNo(fmt.Sprintf(":%.4d", lineNo))+" "+styled)
				mu.Unlock()
				p.Send(msgMatch{})
			},
		}

		scanRes := scanDirectory(opts)
		resultsCh <- scanRes
		p.Send(msgDone{})
	}()

	if _, err := p.Run(); err != nil {
		return fmt.Errorf("UI error: %w", err)
	}

	scanRes := <-resultsCh
	filenames := scanRes.Filenames

	fmt.Println("\nResults:")
	slices.Sort(matches)
	for _, match := range matches {
		fmt.Println(match)
	}

	if len(filenames) > 10 {
		type fileCount struct {
			path  string
			count int
		}
		var fileCounts []fileCount
		for path, count := range scanRes.MatchFiles {
			fileCounts = append(fileCounts, fileCount{path: path, count: count})
		}
		sort.Slice(fileCounts, func(i, j int) bool {
			return fileCounts[i].count > fileCounts[j].count
		})

		fmt.Println(styleTableHeader("\nSecrets | File Path" + strings.Repeat(" ", 48)))
		for i, fc := range fileCounts {
			if i >= 10 {
				break
			}
			fmt.Println(styleTableRow(fmt.Sprintf("%-7d | %-9s", fc.count, fc.path)))
		}
	}

	filesWithMatches := 0
	for _, count := range scanRes.MatchFiles {
		if count > 0 {
			filesWithMatches++
		}
	}

	fmt.Printf("\nCompleted in %s: %d matches across %d of %d files\n",
		time.Since(start).Truncate(time.Millisecond), len(matches), filesWithMatches, len(filenames))

	if outputPath != "" {
		if err := writeResults(matches, outputPath); err != nil {
			return fmt.Errorf("failed to write results: %w", err)
		}
		fmt.Printf("Results written to %s\n", outputPath)
	}

	return nil
}

// writeResults writes scan results to a file, stripping ANSI color codes.
func writeResults(matches []string, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() {
		_ = file.Close() // Best effort close
	}()

	writer := bufio.NewWriter(file)

	// Regex to strip ANSI color codes
	ansiStripper := regexp.MustCompile(`\x1b\[[0-9;]*m`)

	for _, match := range matches {
		cleanMatch := ansiStripper.ReplaceAllString(match, "")
		if _, err := writer.WriteString(cleanMatch + "\n"); err != nil {
			return fmt.Errorf("failed to write match: %w", err)
		}
	}

	return writer.Flush()
}
