// Package main implements passhog, a secrets detection tool for source code repositories.
//
// Passhog scans directories for potential secrets and credentials using configurable
// regular expression patterns. It employs a two-stage detection approach with fast
// preliminary patterns and strict validation patterns, while filtering out known
// false positives.
//
// Usage:
//
//	passhog <directory> [--types=<extensions>] [--output=<file>]
//
// Arguments:
//
//	directory              Directory to scan for secrets
//	--types=<extensions>   Comma-separated file extensions to scan (e.g., py,js,yml)
//	--output=<file>        Write results to specified file
//
// Example:
//
//	passhog /path/to/repo --types=py,js --output=results.txt
//
// The tool uses concurrent processing to scan multiple files in parallel,
// with the number of workers matching the available CPU cores.
package main

import (
	"bufio"
	"bytes"
	"embed"
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

	pflag.Parse()

	remainingArgs := pflag.Args()

	if len(remainingArgs) < 1 {
		fmt.Println("Usage: passhog <directory> [--types=<extensions>] [--output=<file>]")
		fmt.Println("  <directory>   Directory to scan for secrets")
		fmt.Println("  [--types]     Comma-separated file extensions (e.g., yml,yaml,sh)")
		fmt.Println("  [--output]    Output file for results")
		os.Exit(1)
	}

	directory := remainingArgs[0]

	// Parse extensions or use defaults
	extensions := defaultExtensions
	if extensionsList != "" {
		extensions = strings.Split(extensionsList, ",")
		for i, ext := range extensions {
			if !strings.HasPrefix(ext, ".") {
				extensions[i] = "." + ext
			}
		}
	}

	fmt.Printf("Directory: %s\n", directory)
	if extensionsList != "" {
		fmt.Printf("Extensions: %v\n", extensions)
	} else {
		fmt.Println("Extensions: Using defaults")
	}
	if outputPath != "" {
		fmt.Printf("Output: %s\n", outputPath)
	}

	if err := runPasshog(directory, extensions, outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// runPasshog executes the secrets scanning process on the specified directory.
// It returns an error if the scan fails.
func runPasshog(directory string, extensions []string, outputPath string) error {
	start := time.Now()

	// Validate directory exists and is accessible
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

	// Load and compile regex patterns
	excludePatterns, err := loadRegexes(regexFS, "exclude_patterns.regex")
	if err != nil {
		return fmt.Errorf("failed to load exclude patterns: %w", err)
	}
	fastPatterns, err := loadRegexes(regexFS, "direct_matches.regex", "fast_patterns.regex")
	if err != nil {
		return fmt.Errorf("failed to load fast patterns: %w", err)
	}
	slowPatterns, err := loadRegexes(regexFS, "direct_matches.regex", "strict_patterns.regex")
	if err != nil {
		return fmt.Errorf("failed to load strict patterns: %w", err)
	}

	// Set up the UI
	p := tea.NewProgram(model{
		progress: progress.New(progress.WithDefaultGradient()),
	})

	var matches []string
	matchFiles := make(map[string]int)
	var filenames []string

	// Walk the filesystem and collect files to scan
	go func() {
		root := os.DirFS(directory)
		_ = fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !hasExtension(path, extensions) {
				return nil
			}
			parts := strings.Split(path, "/")
			for _, excludeDir := range defaultExcludeDirs {
				if slices.Contains(parts, excludeDir) {
					return nil
				}
			}
			filenames = append(filenames, path)
			return nil
		})

		mu := sync.Mutex{}
		semaphore := make(chan struct{}, runtime.NumCPU())
		wg := sync.WaitGroup{}
		for n, path := range filenames {
			// Run up to num CPU file scanners in parallel. Once the semaphore is full,
			// this will block until one of the goroutines finishes and releases a slot.
			semaphore <- struct{}{}
			wg.Add(1)
			p.Send(msgCurrentFile{path, float64(n) / float64(len(filenames))})
			go func(path string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Let the next one start by clearing an entry.

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
					if fastPatterns.MatchString(line) {
						if match := slowPatterns.FindString(line); match != "" && !excludePatterns.MatchString(line) {
							styled := strings.TrimSpace(strings.Replace(line, match, styleMatch(match), 1))
							mu.Lock()
							matches = append(matches, styleFile(path)+styleLineNo(fmt.Sprintf(":%.4d", lineNo))+" "+styled)
							matchFiles[path]++
							mu.Unlock()
							p.Send(msgMatch{})
						}
					}
				}
			}(path)
		}

		// Ensure all goroutines are done.
		wg.Wait()
		p.Send(msgDone{})
	}()

	// Start the UI loop
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("UI error: %w", err)
	}

	// Display results
	fmt.Println("\nResults:")
	slices.Sort(matches)
	for _, match := range matches {
		fmt.Println(match)
	}

	// Print top 10 files with most secrets if applicable
	if len(filenames) > 10 {
		type fileCount struct {
			path  string
			count int
		}
		var fileCounts []fileCount
		for path, count := range matchFiles {
			fileCounts = append(fileCounts, fileCount{path, count})
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

	fmt.Printf("\nCompleted in %s: %d matches across %d of %d files\n",
		time.Since(start).Truncate(time.Millisecond), len(matches), len(matchFiles), len(filenames))

	// Write results to file if specified
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
