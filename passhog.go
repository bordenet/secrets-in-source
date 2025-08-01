// Passhog is a quick-and-dirty secrets-in-source detection tool that scans a
// directory for files with certain extensions and then scans those files for
// secrets using a set of regular expressions. It is a Go port of the original
// passhog.sh script.
//
// Usage: passhog <directory> [--types=<extensions list>] [--output=<output_file>]
//
//	<directory>   The directory to scan for files.
//	[--types=<extensions list>]  Optional comma-separated list of file extensions to include (e.g., yml,yaml,sh).
//	[--output=<file.txt>]    Optional output file to save results.
//
// Example:
//
//	go run passhog.go /path/to/directory --types=js,py,sh --output=results.txt
//
// The script will scan the directory for files with the specified extensions
// and then scan those files for secrets using a set of regular expressions.
// The results will be printed to the console.
// Passhog.go will also print the top 10 files with the most secrets found.
//
// Spot a false-positive? Help us fine-tune the regexes by submitting a PR to
// the passhog repository.
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

// UI styles
var (
	styleFile        = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("4")).Render
	styleLineNo      = lipgloss.NewStyle().Foreground(lipgloss.Color("#888")).Render
	styleMatch       = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render
	styleTableHeader = lipgloss.NewStyle().Bold(true).Underline(true).Render
	styleTableRow    = lipgloss.NewStyle().Render
)

var excludeDirs = []string{
	".git", ".github", "node_modules", "vendor", ".idea", ".vscode", "stella_deploy", "secrets_in_source",
}

var extensions = []string{
	".js", ".json", ".py", ".cs", ".go", ".java", ".sh", ".tf", ".yml", ".yaml", ".env", "env", ".ENV", "ENV", ".key", ".bookingengine", ".backup", ".tfstate", ".ts", ".txt", ".md", ".properties",
}

func hasExtension(path string) bool {
	return slices.ContainsFunc(extensions, func(ext string) bool {
		return strings.HasSuffix(strings.ToLower(path), ext)
	})
}

// shellReplacer replaces bash escape sequences present in the regex files with
// their original characters to try and match the behavior of passhog.sh.
var shellReplacer = strings.NewReplacer(`\\`, `\`, `\"`, `"`)

// Load and combine regexes from one or more files into one pre-compiled regex.
func loadRegexes(filesystem fs.FS, paths ...string) *regexp.Regexp {
	regexes := ""
	for _, path := range paths {
		b, err := fs.ReadFile(filesystem, path)
		if err != nil {
			panic(fmt.Errorf("unable to load regexes from %s: %w", path, err))
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

	// fmt.Println(paths, regexes)
	regexes = shellReplacer.Replace(regexes)
	return regexp.MustCompile(regexes)
}

// UI messages for handling updates.
type (
	msgCurrentFile struct {
		path    string
		percent float64
	}
	msgMatch struct{}
	msgDone  struct{}
)

// model is for handling updates and drawing the UI.
type model struct {
	currentFile string
	percent     float64
	matches     int
	progress    progress.Model
	width       int
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Handle a UI event, update the model, and after this it will redraw.
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

func (m model) View() string {
	// Draw the UI. This gets called after every update event, including before quit.
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
	// Define a custom flag for output that properly handles the --output=value format
	var outputPath string
	pflag.StringVar(&outputPath, "output", "", "Path where output should be written")

	// Initialize extensions as empty
	var extensionsList string
	pflag.StringVar(&extensionsList, "types", "", "Comma-separated list of file extensions to include (e.g., yml,yaml,sh)")

	// Parse flags but don't require them to be in a specific order
	pflag.Parse()

	// After parsing flags, the remaining args will be in pflag.Args()
	remainingArgs := pflag.Args()

	if len(remainingArgs) < 1 {
		fmt.Println("Usage: go run passhog.go <directory> [--types=<extensions>] [--output=<output_file>]")
		fmt.Println("  <directory>   The directory to scan for files.")
		fmt.Println("  [--types]     Optional comma-separated list of file extensions to include (e.g., yml,yaml,sh).")
		fmt.Println("  [--output]    Optional output file to save results.")
		os.Exit(1)
	}

	// The first non-flag argument is always the directory
	directory := remainingArgs[0]

	// Parse extensions if provided
	if extensionsList != "" {
		extensions = strings.Split(extensionsList, ",")
		for i, ext := range extensions {
			if !strings.HasPrefix(ext, ".") {
				extensions[i] = "." + ext
			}
		}
	}

	// Print the parsed arguments for verification
	fmt.Printf("Directory: %s\n", directory)
	if len(extensions) > 0 {
		fmt.Printf("Extensions: %v\n", extensions)
	} else {
		fmt.Println("Extensions: None specified, will scan all files")
	}
	if outputPath != "" {
		fmt.Printf("Output Path: %s\n", outputPath)
	} else {
		fmt.Println("Output Path: None specified, will print to stdout")
	}

	// Run the actual passhog scan
	runPasshog(directory, extensions, outputPath)
}

// Function to run the actual passhog scan
func runPasshog(directory string, extensions []string, outputPath string) {
	start := time.Now()

	// Load regexes.
	excludePatterns := loadRegexes(regexFS, "exclude_patterns.regex")
	fastPatterns := loadRegexes(regexFS, "direct_matches.regex", "fast_patterns.regex")
	slowPatterns := loadRegexes(regexFS, "direct_matches.regex", "strict_patterns.regex")

	// Set up the UI.
	p := tea.NewProgram(model{
		progress: progress.New(progress.WithDefaultGradient()),
	})

	matches := []string{}
	matchFiles := map[string]int{}
	filenames := []string{}

	// Walk the filesystem and test the files in a goroutine separate from the UI.
	go func() {
		root := os.DirFS(directory)
		fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && hasExtension(path) {
				parts := strings.Split(path, "/")
				for _, excludeDir := range excludeDirs {
					if slices.Contains(parts, excludeDir) {
						return nil
					}
				}
				filenames = append(filenames, path)
			}
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
				defer f.Close()

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

	// Start the UI loop.
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nResults:")
	slices.Sort(matches)
	for _, match := range matches {
		fmt.Println(match)
	}

	// Print the top 10 files in a table format if more than 10 files were scanned
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

	fmt.Printf("\nDone in %s with %d matches across %d of %d checked files\n", time.Since(start).Truncate(time.Millisecond), len(matches), len(matchFiles), len(filenames))

	// If output file is specified, write results to the file
	if outputPath != "" {
		file, err := os.Create(outputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		writer := bufio.NewWriter(file)
		re := regexp.MustCompile(`\x1b\[[0-9;]*m`) // Regex to strip ANSI characters

		for _, match := range matches {
			_, err := writer.WriteString(re.ReplaceAllString(match, "") + "\n")
			if err != nil {
				fmt.Fprintf(os.Stderr, "error writing to output file: %v\n", err)
				os.Exit(1)
			}
		}

		writer.Flush()
		fmt.Printf("Results written to %s\n", outputPath)
	}
}
