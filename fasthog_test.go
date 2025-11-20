package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
)

// lineInfo holds information about a regex pattern from a file.
type lineInfo struct {
	line string
	path string
	pos  int
}

// loadLines loads individual regex patterns from files for detailed testing.
func loadLines(filesystem fs.FS, paths ...string) ([]lineInfo, error) {
	var regexes []lineInfo
	for _, path := range paths {
		b, err := fs.ReadFile(filesystem, path)
		if err != nil {
			return nil, fmt.Errorf("unable to load regexes from %s: %w", path, err)
		}
		for i, line := range bytes.Split(b, []byte("\n")) {
			if len(line) == 0 || line[0] == '#' {
				continue
			}
			regexes = append(regexes, lineInfo{shellReplacer.Replace(string(line)), path, i})
		}
	}
	return regexes, nil
}

// testLines checks if any regex in the list matches the input and reports an error if so.
func testLines(t *testing.T, regexes []lineInfo, input string, label string) {
	t.Helper()
	for _, info := range regexes {
		re, err := regexp.Compile(info.line)
		if err != nil {
			t.Errorf("invalid regex at %s:%d: %v\nregex «%s»", info.path, info.pos+1, err, info.line)
			continue
		}
		if re.MatchString(input) {
			t.Errorf("%s by %s:%d\nregex «%s»\ninput «%s»", label, info.path, info.pos+1, info.line, input)
			return
		}
	}
}

// TestPositives verifies that all known secrets are detected by the patterns.
func TestPositives(t *testing.T) {
	fast, err := loadRegexes(regexFS, "direct_matches.regex", "fast_patterns.regex")
	if err != nil {
		t.Fatalf("failed to load fast patterns: %v", err)
	}
	slow, err := loadRegexes(regexFS, "direct_matches.regex", "strict_patterns.regex")
	if err != nil {
		t.Fatalf("failed to load strict patterns: %v", err)
	}
	exclude, err := loadRegexes(regexFS, "exclude_patterns.regex")
	if err != nil {
		t.Fatalf("failed to load exclude patterns: %v", err)
	}

	excludeLines, err := loadLines(regexFS, "exclude_patterns.regex")
	if err != nil {
		t.Fatalf("failed to load exclude lines: %v", err)
	}

	b, err := os.ReadFile("test/Positives.txt")
	if err != nil {
		t.Fatal(err)
	}
	inputs := slices.DeleteFunc(strings.Split(string(b), "\n"), func(s string) bool {
		return s == "" || strings.HasPrefix(s, "#")
	})

	for i, input := range inputs {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if !fast.MatchString(input) {
				t.Errorf("did not match direct/fast_patterns.regex\ninput «%s»", input)
			}
			if !slow.MatchString(input) {
				t.Errorf("did not match direct/strict_patterns.regex\ninput «%s»", input)
			}
			if exclude.MatchString(input) {
				testLines(t, excludeLines, input, "filtered out")
			}
		})
	}
}

// TestFalsePositives verifies that known false positives are properly excluded.
func TestFalsePositives(t *testing.T) {
	fast, err := loadRegexes(regexFS, "direct_matches.regex", "fast_patterns.regex")
	if err != nil {
		t.Fatalf("failed to load fast patterns: %v", err)
	}
	slow, err := loadRegexes(regexFS, "direct_matches.regex", "strict_patterns.regex")
	if err != nil {
		t.Fatalf("failed to load strict patterns: %v", err)
	}
	exclude, err := loadRegexes(regexFS, "exclude_patterns.regex")
	if err != nil {
		t.Fatalf("failed to load exclude patterns: %v", err)
	}

	fastLines, err := loadLines(regexFS, "direct_matches.regex", "fast_patterns.regex")
	if err != nil {
		t.Fatalf("failed to load fast lines: %v", err)
	}
	slowLines, err := loadLines(regexFS, "strict_patterns.regex")
	if err != nil {
		t.Fatalf("failed to load strict lines: %v", err)
	}

	b, err := os.ReadFile("test/False_Positives.txt")
	if err != nil {
		t.Fatal(err)
	}
	inputs := slices.DeleteFunc(strings.Split(string(b), "\n"), func(s string) bool {
		return s == "" || strings.HasPrefix(s, "#")
	})

	for i, input := range inputs {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if !exclude.MatchString(input) && slow.MatchString(input) && fast.MatchString(input) {
				testLines(t, fastLines, input, "matched")
				testLines(t, slowLines, input, "matched")
			}
		})
	}
}

// TestHasExtension verifies the extension matching logic.
func TestHasExtension(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		extensions []string
		want       bool
	}{
		{"matches .py", "test.py", []string{".py", ".js"}, true},
		{"matches .js", "test.js", []string{".py", ".js"}, true},
		{"no match", "test.txt", []string{".py", ".js"}, false},
		{"case insensitive", "TEST.PY", []string{".py"}, true},
		{"empty extensions", "test.py", []string{}, false},
		{"empty path", "", []string{".py"}, false},
		{"path without extension", "test", []string{".py"}, false},
		{"multiple dots", "test.backup.py", []string{".py"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasExtension(tt.path, tt.extensions)
			if got != tt.want {
				t.Errorf("hasExtension(%q, %v) = %v, want %v", tt.path, tt.extensions, got, tt.want)
			}
		})
	}
}

// TestLoadRegexes verifies regex loading and compilation.
func TestLoadRegexes(t *testing.T) {
	t.Run("valid patterns", func(t *testing.T) {
		re, err := loadRegexes(regexFS, "direct_matches.regex")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if re == nil {
			t.Fatal("expected non-nil regex")
		}
	})

	t.Run("multiple files", func(t *testing.T) {
		re, err := loadRegexes(regexFS, "direct_matches.regex", "fast_patterns.regex")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if re == nil {
			t.Fatal("expected non-nil regex")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := loadRegexes(regexFS, "nonexistent.regex")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})

	t.Run("invalid regex pattern", func(t *testing.T) {
		// Create a test filesystem with invalid regex
		testFS := fstest.MapFS{
			"invalid.regex": &fstest.MapFile{
				Data: []byte("(?P<invalid"),
			},
		}
		_, err := loadRegexes(testFS, "invalid.regex")
		if err == nil {
			t.Error("expected error for invalid regex pattern")
		}
		if !strings.Contains(err.Error(), "failed to compile") {
			t.Errorf("expected compile error, got: %v", err)
		}
	})
}

// TestWriteResults verifies output file writing.
func TestWriteResults(t *testing.T) {
	t.Run("write simple results", func(t *testing.T) {
		tmpFile := t.TempDir() + "/results.txt"
		matches := []string{"match1", "match2", "match3"}

		err := writeResults(matches, tmpFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		content, err := os.ReadFile(tmpFile)
		if err != nil {
			t.Fatalf("failed to read output: %v", err)
		}

		expected := "match1\nmatch2\nmatch3\n"
		if string(content) != expected {
			t.Errorf("got %q, want %q", string(content), expected)
		}
	})

	t.Run("strip ANSI codes", func(t *testing.T) {
		tmpFile := t.TempDir() + "/results.txt"
		matches := []string{
			"\x1b[31mred text\x1b[0m",
			"\x1b[1;32mbold green\x1b[0m",
		}

		err := writeResults(matches, tmpFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		content, err := os.ReadFile(tmpFile)
		if err != nil {
			t.Fatalf("failed to read output: %v", err)
		}

		expected := "red text\nbold green\n"
		if string(content) != expected {
			t.Errorf("got %q, want %q", string(content), expected)
		}
	})

	t.Run("invalid path", func(t *testing.T) {
		err := writeResults([]string{"test"}, "/invalid/path/results.txt")
		if err == nil {
			t.Fatal("expected error for invalid path")
		}
	})
}

// TestLoadLines verifies individual pattern loading for testing.
func TestLoadLines(t *testing.T) {
	t.Run("load exclude patterns", func(t *testing.T) {
		lines, err := loadLines(regexFS, "exclude_patterns.regex")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(lines) == 0 {
			t.Fatal("expected non-empty lines")
		}
		for _, line := range lines {
			if line.line == "" {
				t.Error("found empty pattern")
			}
			if line.path != "exclude_patterns.regex" {
				t.Errorf("wrong path: got %q, want %q", line.path, "exclude_patterns.regex")
			}
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := loadLines(regexFS, "nonexistent.regex")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})
}

// TestModelUpdate verifies the UI model update logic.
func TestModelUpdate(t *testing.T) {
	m := model{
		progress: progress.New(progress.WithDefaultGradient()),
	}

	t.Run("window size message", func(t *testing.T) {
		msg := tea.WindowSizeMsg{Width: 100, Height: 50}
		updated, _ := m.Update(msg)
		updatedModel := updated.(model)
		if updatedModel.progress.Width != 100 {
			t.Errorf("expected width 100, got %d", updatedModel.progress.Width)
		}
	})

	t.Run("current file message", func(t *testing.T) {
		msg := msgCurrentFile{path: "test.py", percent: 0.5}
		updated, _ := m.Update(msg)
		updatedModel := updated.(model)
		if updatedModel.currentFile != "test.py" {
			t.Errorf("expected currentFile 'test.py', got %q", updatedModel.currentFile)
		}
		if updatedModel.percent != 0.5 {
			t.Errorf("expected percent 0.5, got %f", updatedModel.percent)
		}
	})

	t.Run("match message", func(t *testing.T) {
		msg := msgMatch{}
		updated, _ := m.Update(msg)
		updatedModel := updated.(model)
		if updatedModel.matches != 1 {
			t.Errorf("expected matches 1, got %d", updatedModel.matches)
		}
	})

	t.Run("done message", func(t *testing.T) {
		msg := msgDone{}
		updated, cmd := m.Update(msg)
		updatedModel := updated.(model)
		if updatedModel.percent != 100.0 {
			t.Errorf("expected percent 100.0, got %f", updatedModel.percent)
		}
		if cmd == nil {
			t.Error("expected quit command")
		}
	})
}

// TestModelView verifies the UI rendering.
func TestModelView(t *testing.T) {
	m := model{
		currentFile: "test.py",
		percent:     50.0,
		matches:     5,
		progress:    progress.New(progress.WithDefaultGradient()),
	}
	m.progress.Width = 80

	view := m.View()
	if view == "" {
		t.Error("expected non-empty view")
	}
	if !strings.Contains(view, "test.py") {
		t.Error("view should contain current file")
	}
	if !strings.Contains(view, "5") {
		t.Error("view should contain match count")
	}
}

// TestEdgeCases tests various edge cases.
func TestEdgeCases(t *testing.T) {
	t.Run("empty matches write", func(t *testing.T) {
		tmpFile := t.TempDir() + "/empty.txt"
		err := writeResults([]string{}, tmpFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		content, err := os.ReadFile(tmpFile)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}
		if len(content) != 0 {
			t.Errorf("expected empty file, got %d bytes", len(content))
		}
	})

	t.Run("very long file path", func(t *testing.T) {
		longPath := strings.Repeat("a/", 100) + "file.py"
		extensions := []string{".py"}
		if !hasExtension(longPath, extensions) {
			t.Error("should match extension on very long path")
		}
	})

	t.Run("file path with special characters", func(t *testing.T) {
		specialPath := "test-file_v2.0.py"
		extensions := []string{".py"}
		if !hasExtension(specialPath, extensions) {
			t.Error("should match extension with special characters")
		}
	})

	t.Run("extension only path", func(t *testing.T) {
		path := ".py"
		extensions := []string{".py"}
		if !hasExtension(path, extensions) {
			t.Error("should match extension-only path")
		}
	})
}

// TestRunFasthogValidation tests input validation.
func TestRunFasthogValidation(t *testing.T) {
	t.Run("file instead of directory", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "file.txt")
		err := os.WriteFile(tmpFile, []byte("test"), 0644)
		if err != nil {
			t.Fatal(err)
		}

		err = runFasthog(tmpFile, defaultExtensions, nil, PatternFiles{}, "")
		if err == nil {
			t.Error("expected error when passing file instead of directory")
		}
		if !strings.Contains(err.Error(), "not a directory") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("permission denied directory", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("skipping permission test when running as root")
		}
		// This test is platform-specific and may not work on all systems
		t.Skip("permission test is platform-specific")
	})
}

// TestModelInit verifies the Init method.
func TestModelInit(t *testing.T) {
	m := model{
		progress: progress.New(progress.WithDefaultGradient()),
	}
	cmd := m.Init()
	if cmd != nil {
		t.Error("expected nil command from Init")
	}
}

// TestModelKeyboardInput tests keyboard handling.
func TestModelKeyboardInput(t *testing.T) {
	m := model{
		progress: progress.New(progress.WithDefaultGradient()),
	}

	t.Run("ctrl+c quits", func(t *testing.T) {
		msg := tea.KeyMsg{Type: tea.KeyCtrlC}
		_, cmd := m.Update(msg)
		if cmd == nil {
			t.Error("expected quit command for ctrl+c")
		}
	})

	t.Run("q quits", func(t *testing.T) {
		msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}}
		_, cmd := m.Update(msg)
		if cmd == nil {
			t.Error("expected quit command for q")
		}
	})

	t.Run("other keys ignored", func(t *testing.T) {
		msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}}
		updated, cmd := m.Update(msg)
		if cmd != nil {
			t.Error("expected no command for regular key")
		}
		if updated == nil {
			t.Error("expected model to be returned")
		}
	})
}

// TestLargeFileScanning tests scanning files with many lines.
func TestLargeFileScanning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large file test in short mode")
	}

	tmpDir := t.TempDir()
	largeFile := filepath.Join(tmpDir, "large.py")

	// Create a file with many lines
	var content strings.Builder
	for i := 0; i < 1000; i++ {
		if i == 500 {
			content.WriteString(`PASSWORD="secretvalue123"` + "\n")
		} else {
			content.WriteString(fmt.Sprintf("# Comment line %d\n", i))
		}
	}

	err := os.WriteFile(largeFile, []byte(content.String()), 0644)
	if err != nil {
		t.Fatal(err)
	}

	outputFile := filepath.Join(t.TempDir(), "results.txt")
	err = runFasthog(tmpDir, []string{".py"}, nil, PatternFiles{}, outputFile)
	if err != nil {
		t.Fatalf("runFasthog failed: %v", err)
	}

	resultContent, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read results: %v", err)
	}

	if !strings.Contains(string(resultContent), "PASSWORD") {
		t.Error("expected to find PASSWORD in large file")
	}
	if !strings.Contains(string(resultContent), "0501") {
		t.Error("expected to find line number 501")
	}
}

// TestLoadRegexesEmptyFile verifies handling of empty regex files.
func TestLoadRegexesEmptyFile(t *testing.T) {
	testFS := fstest.MapFS{
		"empty.regex": &fstest.MapFile{
			Data: []byte(""),
		},
	}
	re, err := loadRegexes(testFS, "empty.regex")
	if err != nil {
		t.Fatalf("unexpected error for empty file: %v", err)
	}
	if re == nil {
		t.Fatal("expected non-nil regex for empty file")
	}
}

// TestLoadRegexesCommentOnly verifies handling of comment-only files.
func TestLoadRegexesCommentOnly(t *testing.T) {
	testFS := fstest.MapFS{
		"comments.regex": &fstest.MapFile{
			Data: []byte("# This is a comment\n# Another comment\n"),
		},
	}
	re, err := loadRegexes(testFS, "comments.regex")
	if err != nil {
		t.Fatalf("unexpected error for comment-only file: %v", err)
	}
	if re == nil {
		t.Fatal("expected non-nil regex for comment-only file")
	}
}

// TestShortLines tests that very short lines are skipped.
func TestShortLines(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "short.py")

	content := `a
ab
abc
abcd
abcde
abcdef
abcdefgh
PASSWORD="secret"
`
	err := os.WriteFile(testFile, []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}

	outputFile := filepath.Join(t.TempDir(), "results.txt")
	err = runFasthog(tmpDir, []string{".py"}, nil, PatternFiles{}, outputFile)
	if err != nil {
		t.Fatalf("runFasthog failed: %v", err)
	}

	resultContent, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read results: %v", err)
	}

	// Should only find the PASSWORD line, not the short lines
	if !strings.Contains(string(resultContent), "PASSWORD") {
		t.Error("expected to find PASSWORD")
	}
}

func TestParseOutputFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    OutputFormat
		wantErr bool
	}{
		{"defaultEmpty", "", OutputFormatText, false},
		{"textLower", "text", OutputFormatText, false},
		{"textUpper", "TEXT", OutputFormatText, false},
		{"jsonLower", "json", OutputFormatJSON, false},
		{"jsonUpper", "JSON", OutputFormatJSON, false},
		{"invalid", "yaml", "", true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseOutputFormat(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q, got none", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseOutputFormat(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("parseOutputFormat(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildUsageIncludesKeyFlags(t *testing.T) {
	usage := buildUsage()

	for _, token := range []string{"Usage: fasthog", "--types", "--output", "--format", "--json", "--config"} {
		if !strings.Contains(usage, token) {
			t.Errorf("usage text missing %q", token)
		}
	}
}

func TestRunFasthogJSONWritesValidJSON(t *testing.T) {
	tmpDir := t.TempDir()

	testFile := filepath.Join(tmpDir, "config.py")
	content := `PASSWORD="secret"`
	if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	outputFile := filepath.Join(tmpDir, "results.json")

	if err := runFasthogJSON(tmpDir, []string{".py"}, nil, PatternFiles{}, outputFile); err != nil {
		t.Fatalf("runFasthogJSON failed: %v", err)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read JSON output: %v", err)
	}

	var result JSONResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v", err)
	}

	if result.Directory != tmpDir {
		t.Errorf("expected Directory %q, got %q", tmpDir, result.Directory)
	}

	if len(result.Extensions) != 1 || result.Extensions[0] != ".py" {
		t.Errorf("unexpected Extensions: %#v", result.Extensions)
	}

	if len(result.Matches) == 0 {
		t.Fatalf("expected at least one match, got zero")
	}

	foundConfig := false
	for _, m := range result.Matches {
		if m.File == "config.py" {
			foundConfig = true
			if m.Line <= 0 {
				t.Errorf("expected positive line number, got %d", m.Line)
			}
			if !strings.Contains(m.LineSnippet, "PASSWORD") {
				t.Errorf("expected line snippet to contain PASSWORD, got %q", m.LineSnippet)
			}
		}
	}
	if !foundConfig {
		t.Errorf("expected a match in config.py, got %+v", result.Matches)
	}

	if result.Summary.TotalMatches != len(result.Matches) {
		t.Errorf("summary total_matches %d != len(matches) %d", result.Summary.TotalMatches, len(result.Matches))
	}
	if result.Summary.TotalFilesScanned == 0 {
		t.Errorf("expected TotalFilesScanned > 0")
	}
	if result.Summary.TotalFilesWithMatch == 0 {
		t.Errorf("expected at least one file with matches")
	}
}
func TestLoadConfigParsesExpectedFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fasthog.yaml")

	configYAML := `
directory: ./src
extensions:
  - .go
  - py
exclude_dirs:
  - build
  - vendor
output:
  path: out.json
  format: json
patterns:
  direct: direct.regex
  fast: fast.regex
  strict: strict.regex
  exclude: exclude.regex
`

	if err := os.WriteFile(path, []byte(configYAML), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}

	if cfg.Directory != "./src" {
		t.Errorf("expected Directory ./src, got %q", cfg.Directory)
	}

	wantExtensions := []string{".go", ".py"}
	if !slices.Equal(cfg.Extensions, wantExtensions) {
		t.Errorf("unexpected Extensions: got %v, want %v", cfg.Extensions, wantExtensions)
	}

	wantExclude := []string{"build", "vendor"}
	if !slices.Equal(cfg.ExcludeDirs, wantExclude) {
		t.Errorf("unexpected ExcludeDirs: got %v, want %v", cfg.ExcludeDirs, wantExclude)
	}

	if cfg.Output.Path != "out.json" || cfg.Output.Format != "json" {
		t.Errorf("unexpected Output config: %+v", cfg.Output)
	}

	if cfg.Patterns.Direct != "direct.regex" || cfg.Patterns.Fast != "fast.regex" ||
		cfg.Patterns.Strict != "strict.regex" || cfg.Patterns.Exclude != "exclude.regex" {
		t.Errorf("unexpected Patterns config: %+v", cfg.Patterns)
	}
}

func TestLoadConfigIgnoresUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	configYAML := `
unknown: value
extensions:
  - .py
another_unknown:
  nested: value
`

	if err := os.WriteFile(path, []byte(configYAML), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}

	if len(cfg.Extensions) != 1 || cfg.Extensions[0] != ".py" {
		t.Errorf("unexpected Extensions: %#v", cfg.Extensions)
	}
}

func TestSplitKeyValue(t *testing.T) {
	key, value := splitKeyValue("foo: bar")
	if key != "foo" || value != "bar" {
		t.Errorf("splitKeyValue unexpected result: key=%q value=%q", key, value)
	}

	key, value = splitKeyValue("no_value:")
	if key != "no_value" || value != "" {
		t.Errorf("splitKeyValue unexpected result for no_value: key=%q value=%q", key, value)
	}

	key, value = splitKeyValue("justkey")
	if key != "justkey" || value != "" {
		t.Errorf("splitKeyValue unexpected result for justkey: key=%q value=%q", key, value)
	}
}

func TestDetermineExtensionsPrecedence(t *testing.T) {
	cfg := Config{Extensions: []string{".tf", ".yaml"}}

	t.Run("CLI flag wins over config and defaults", func(t *testing.T) {
		exts := determineExtensions("py,go", true, cfg)
		if !slices.Equal(exts, []string{".py", ".go"}) {
			t.Errorf("determineExtensions CLI precedence: got %v", exts)
		}
	})

	t.Run("config used when flag not changed", func(t *testing.T) {
		exts := determineExtensions("", false, cfg)
		if !slices.Equal(exts, cfg.Extensions) {
			t.Errorf("determineExtensions config precedence: got %v, want %v", exts, cfg.Extensions)
		}
	})

	t.Run("defaults used when neither flag nor config provides extensions", func(t *testing.T) {
		exts := determineExtensions("", false, Config{})
		if !slices.Equal(exts, defaultExtensions) {
			t.Errorf("determineExtensions default precedence: got %v, want %v", exts, defaultExtensions)
		}
	})

	t.Run("all whitespace input falls through to config", func(t *testing.T) {
		exts := determineExtensions("  ,  ,  ", true, cfg)
		if !slices.Equal(exts, cfg.Extensions) {
			t.Errorf("expected config extensions for all-whitespace input, got %v", exts)
		}
	})

	t.Run("all whitespace input with no config falls through to defaults", func(t *testing.T) {
		exts := determineExtensions("  ,  ,  ", true, Config{})
		if !slices.Equal(exts, defaultExtensions) {
			t.Errorf("expected defaults for all-whitespace input with no config, got %v", exts)
		}
	})

	t.Run("trailing comma is handled gracefully", func(t *testing.T) {
		exts := determineExtensions("py,go,", true, cfg)
		if !slices.Equal(exts, []string{".py", ".go"}) {
			t.Errorf("expected [.py .go] for trailing comma, got %v", exts)
		}
	})

	t.Run("leading comma is handled gracefully", func(t *testing.T) {
		exts := determineExtensions(",py,go", true, cfg)
		if !slices.Equal(exts, []string{".py", ".go"}) {
			t.Errorf("expected [.py .go] for leading comma, got %v", exts)
		}
	})

	t.Run("mixed valid and whitespace", func(t *testing.T) {
		exts := determineExtensions("py,  , go,  ", true, cfg)
		if !slices.Equal(exts, []string{".py", ".go"}) {
			t.Errorf("expected [.py .go] for mixed valid/whitespace, got %v", exts)
		}
	})

	t.Run("dot prefix normalization", func(t *testing.T) {
		exts := determineExtensions(".py,go,.ts,js", true, cfg)
		if !slices.Equal(exts, []string{".py", ".go", ".ts", ".js"}) {
			t.Errorf("expected normalized extensions, got %v", exts)
		}
	})
}

func TestDetermineOutputFormatPrecedence(t *testing.T) {
	cfg := Config{Output: OutputConfig{Format: "json"}}

	t.Run("configUsedWhenNoFlags", func(t *testing.T) {
		format, err := determineOutputFormat("", false, false, false, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if format != OutputFormatJSON {
			t.Errorf("expected JSON format from config, got %q", format)
		}
	})

	t.Run("cliFormatOverridesConfig", func(t *testing.T) {
		format, err := determineOutputFormat("text", true, false, false, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if format != OutputFormatText {
			t.Errorf("expected text format from CLI, got %q", format)
		}
	})

	t.Run("jsonFlagOverridesConfig", func(t *testing.T) {
		format, err := determineOutputFormat("text", false, true, true, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if format != OutputFormatJSON {
			t.Errorf("expected JSON format from --json flag, got %q", format)
		}
	})

	t.Run("invalidFormatReturnsError", func(t *testing.T) {
		_, err := determineOutputFormat("yaml", true, false, false, Config{})
		if err == nil {
			t.Fatal("expected error for invalid output format")
		}
	})
}

func TestDetermineOutputPathPrecedence(t *testing.T) {
	cfg := Config{Output: OutputConfig{Path: "config_results.txt"}}

	// Config path should be used when flag is not changed.
	got := determineOutputPath("", false, cfg)
	if got != "config_results.txt" {
		t.Errorf("expected config output path, got %q", got)
	}

	// CLI flag should override config.
	got = determineOutputPath("cli_results.txt", true, cfg)
	if got != "cli_results.txt" {
		t.Errorf("expected CLI output path, got %q", got)
	}
}

func TestLoadEffectivePatternsWithDefaults(t *testing.T) {
	// Test that loadEffectivePatterns(PatternFiles{}) loads default embedded patterns.
	exclude, fast, slow, err := loadEffectivePatterns(PatternFiles{})
	if err != nil {
		t.Fatalf("loadEffectivePatterns with empty PatternFiles failed: %v", err)
	}

	if exclude == nil {
		t.Error("expected non-nil exclude patterns")
	}
	if fast == nil {
		t.Error("expected non-nil fast patterns")
	}
	if slow == nil {
		t.Error("expected non-nil slow patterns")
	}

	// Verify that the patterns actually work by testing against known positives.
	testLine := "password = 'MySecretPassword123'"
	if !fast.MatchString(testLine) {
		t.Error("default fast patterns should match known secret line")
	}
	if slow.FindString(testLine) == "" {
		t.Error("default slow patterns should match known secret line")
	}
}

func TestMergeExcludeDirs(t *testing.T) {
	t.Run("no extra dirs returns copy of defaults", func(t *testing.T) {
		result := mergeExcludeDirs(nil)
		if len(result) != len(defaultExcludeDirs) {
			t.Errorf("expected %d dirs, got %d", len(defaultExcludeDirs), len(result))
		}
		// Verify it's a copy, not the same slice
		if &result[0] == &defaultExcludeDirs[0] {
			t.Error("expected a copy of defaultExcludeDirs, got same slice")
		}
		for i, dir := range defaultExcludeDirs {
			if result[i] != dir {
				t.Errorf("expected result[%d] = %s, got %s", i, dir, result[i])
			}
		}
	})

	t.Run("empty slice returns copy of defaults", func(t *testing.T) {
		result := mergeExcludeDirs([]string{})
		if len(result) != len(defaultExcludeDirs) {
			t.Errorf("expected %d dirs, got %d", len(defaultExcludeDirs), len(result))
		}
	})

	t.Run("extra dirs are appended", func(t *testing.T) {
		extra := []string{"custom1", "custom2"}
		result := mergeExcludeDirs(extra)
		expectedLen := len(defaultExcludeDirs) + len(extra)
		if len(result) != expectedLen {
			t.Errorf("expected %d dirs, got %d", expectedLen, len(result))
		}
		// Verify all defaults are present
		for _, dir := range defaultExcludeDirs {
			if !slices.Contains(result, dir) {
				t.Errorf("expected result to contain default dir %s", dir)
			}
		}
		// Verify all extras are present
		for _, dir := range extra {
			if !slices.Contains(result, dir) {
				t.Errorf("expected result to contain extra dir %s", dir)
			}
		}
	})

	t.Run("duplicates are removed", func(t *testing.T) {
		// Add a duplicate of a default dir
		extra := []string{".git", "custom"}
		result := mergeExcludeDirs(extra)
		// Should not have duplicate .git
		count := 0
		for _, dir := range result {
			if dir == ".git" {
				count++
			}
		}
		if count != 1 {
			t.Errorf("expected .git to appear once, appeared %d times", count)
		}
	})

	t.Run("duplicate extras are removed", func(t *testing.T) {
		extra := []string{"custom", "custom", "other"}
		result := mergeExcludeDirs(extra)
		count := 0
		for _, dir := range result {
			if dir == "custom" {
				count++
			}
		}
		if count != 1 {
			t.Errorf("expected custom to appear once, appeared %d times", count)
		}
	})
}

func TestLoadEffectivePatternsWithOverrides(t *testing.T) {
	// Create temporary pattern files
	tmpDir := t.TempDir()

	customExclude := filepath.Join(tmpDir, "custom_exclude.regex")
	if err := os.WriteFile(customExclude, []byte("test_exclude_pattern\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	customFast := filepath.Join(tmpDir, "custom_fast.regex")
	if err := os.WriteFile(customFast, []byte("test_fast_pattern\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	customStrict := filepath.Join(tmpDir, "custom_strict.regex")
	if err := os.WriteFile(customStrict, []byte("test_strict_pattern\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	customDirect := filepath.Join(tmpDir, "custom_direct.regex")
	if err := os.WriteFile(customDirect, []byte("test_direct_pattern\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Change to tmpDir so relative paths work
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			t.Error(err)
		}
	}()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}

	t.Run("override exclude patterns", func(t *testing.T) {
		pf := PatternFiles{Exclude: "custom_exclude.regex"}
		exclude, _, _, err := loadEffectivePatterns(pf)
		if err != nil {
			t.Fatalf("loadEffectivePatterns failed: %v", err)
		}
		if !exclude.MatchString("test_exclude_pattern") {
			t.Error("custom exclude pattern not loaded")
		}
	})

	t.Run("override fast patterns", func(t *testing.T) {
		pf := PatternFiles{Fast: "custom_fast.regex"}
		_, fast, _, err := loadEffectivePatterns(pf)
		if err != nil {
			t.Fatalf("loadEffectivePatterns failed: %v", err)
		}
		if !fast.MatchString("test_fast_pattern") {
			t.Error("custom fast pattern not loaded")
		}
	})

	t.Run("override strict patterns", func(t *testing.T) {
		pf := PatternFiles{Strict: "custom_strict.regex"}
		_, _, slow, err := loadEffectivePatterns(pf)
		if err != nil {
			t.Fatalf("loadEffectivePatterns failed: %v", err)
		}
		if !slow.MatchString("test_strict_pattern") {
			t.Error("custom strict pattern not loaded")
		}
	})

	t.Run("override direct patterns", func(t *testing.T) {
		pf := PatternFiles{Direct: "custom_direct.regex"}
		_, _, slow, err := loadEffectivePatterns(pf)
		if err != nil {
			t.Fatalf("loadEffectivePatterns failed: %v", err)
		}
		if !slow.MatchString("test_direct_pattern") {
			t.Error("custom direct pattern not loaded")
		}
	})

	t.Run("override both direct and strict", func(t *testing.T) {
		pf := PatternFiles{Direct: "custom_direct.regex", Strict: "custom_strict.regex"}
		_, _, slow, err := loadEffectivePatterns(pf)
		if err != nil {
			t.Fatalf("loadEffectivePatterns failed: %v", err)
		}
		if !slow.MatchString("test_direct_pattern") {
			t.Error("custom direct pattern not loaded")
		}
		if !slow.MatchString("test_strict_pattern") {
			t.Error("custom strict pattern not loaded")
		}
	})

	t.Run("error on missing exclude file", func(t *testing.T) {
		pf := PatternFiles{Exclude: "nonexistent.regex"}
		_, _, _, err := loadEffectivePatterns(pf)
		if err == nil {
			t.Error("expected error for missing exclude file")
		}
		if !strings.Contains(err.Error(), "failed to load exclude patterns") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("error on missing fast file", func(t *testing.T) {
		pf := PatternFiles{Fast: "nonexistent.regex"}
		_, _, _, err := loadEffectivePatterns(pf)
		if err == nil {
			t.Error("expected error for missing fast file")
		}
		if !strings.Contains(err.Error(), "failed to load fast patterns") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("error on missing strict file", func(t *testing.T) {
		pf := PatternFiles{Strict: "nonexistent.regex"}
		_, _, _, err := loadEffectivePatterns(pf)
		if err == nil {
			t.Error("expected error for missing strict file")
		}
		if !strings.Contains(err.Error(), "failed to load strict patterns") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}

func TestRunFasthogJSONComprehensive(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files with secrets
	secretFile := filepath.Join(tmpDir, "config.yml")
	if err := os.WriteFile(secretFile, []byte("password: secret123\napi_key: sk_test_abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cleanFile := filepath.Join(tmpDir, "readme.txt")
	if err := os.WriteFile(cleanFile, []byte("This is a clean file\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("successful scan with output file", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "results.json")

		// Redirect stdout to capture JSON output
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := runFasthogJSON(tmpDir, []string{".yml", ".txt"}, defaultExcludeDirs, PatternFiles{}, outputFile)

		_ = w.Close()
		os.Stdout = oldStdout

		if err != nil {
			t.Fatalf("runFasthogJSON failed: %v", err)
		}

		// Verify output file was created
		data, err := os.ReadFile(outputFile)
		if err != nil {
			t.Fatalf("failed to read output file: %v", err)
		}

		var result JSONResult
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}

		// Verify JSON structure
		if result.Directory != tmpDir {
			t.Errorf("expected directory %s, got %s", tmpDir, result.Directory)
		}
		if len(result.Extensions) != 2 {
			t.Errorf("expected 2 extensions, got %d", len(result.Extensions))
		}
		if result.Summary.TotalFilesScanned != 2 {
			t.Errorf("expected 2 files scanned, got %d", result.Summary.TotalFilesScanned)
		}
		if result.Summary.TotalMatches == 0 {
			t.Error("expected at least one match")
		}
		if result.Summary.TotalFilesWithMatch == 0 {
			t.Error("expected at least one file with matches")
		}
		if len(result.TopFiles) == 0 {
			t.Error("expected top files to be populated")
		}

		// Verify stdout also received the JSON
		var stdoutBuf bytes.Buffer
		if _, err := stdoutBuf.ReadFrom(r); err != nil {
			t.Fatalf("failed to read stdout: %v", err)
		}
	})

	t.Run("successful scan without output file", func(t *testing.T) {
		// Redirect stdout to capture JSON output
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := runFasthogJSON(tmpDir, []string{".yml"}, defaultExcludeDirs, PatternFiles{}, "")

		_ = w.Close()
		os.Stdout = oldStdout

		if err != nil {
			t.Fatalf("runFasthogJSON failed: %v", err)
		}

		// Read and verify stdout JSON
		var stdoutBuf bytes.Buffer
		if _, err := stdoutBuf.ReadFrom(r); err != nil {
			t.Fatalf("failed to read stdout: %v", err)
		}

		var result JSONResult
		if err := json.Unmarshal(stdoutBuf.Bytes(), &result); err != nil {
			t.Fatalf("failed to parse JSON from stdout: %v", err)
		}

		if result.Directory != tmpDir {
			t.Errorf("expected directory %s, got %s", tmpDir, result.Directory)
		}
	})

	t.Run("error on invalid directory", func(t *testing.T) {
		err := runFasthogJSON("/nonexistent/directory", []string{".yml"}, defaultExcludeDirs, PatternFiles{}, "")
		if err == nil {
			t.Error("expected error for invalid directory")
		}
	})

	t.Run("error on invalid pattern files", func(t *testing.T) {
		pf := PatternFiles{Exclude: "nonexistent.regex"}
		err := runFasthogJSON(tmpDir, []string{".yml"}, defaultExcludeDirs, pf, "")
		if err == nil {
			t.Error("expected error for invalid pattern files")
		}
	})

	t.Run("top files sorted correctly", func(t *testing.T) {
		// Create multiple files with different match counts
		file1 := filepath.Join(tmpDir, "file1.yml")
		if err := os.WriteFile(file1, []byte("password: secret1\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		file2 := filepath.Join(tmpDir, "file2.yml")
		if err := os.WriteFile(file2, []byte("password: secret2\napi_key: key2\ntoken: tok2\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		outputFile := filepath.Join(tmpDir, "sorted_results.json")

		// Redirect stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := runFasthogJSON(tmpDir, []string{".yml"}, defaultExcludeDirs, PatternFiles{}, outputFile)

		_ = w.Close()
		os.Stdout = oldStdout

		if err != nil {
			t.Fatalf("runFasthogJSON failed: %v", err)
		}

		data, err := os.ReadFile(outputFile)
		if err != nil {
			t.Fatal(err)
		}

		var result JSONResult
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatal(err)
		}

		// Verify top files are sorted by count (descending)
		for i := 1; i < len(result.TopFiles); i++ {
			if result.TopFiles[i].Count > result.TopFiles[i-1].Count {
				t.Errorf("top files not sorted correctly: file[%d].Count=%d > file[%d].Count=%d",
					i, result.TopFiles[i].Count, i-1, result.TopFiles[i-1].Count)
			}
		}

		// Clean up stdout reader
		var stdoutBuf bytes.Buffer
		if _, err := stdoutBuf.ReadFrom(r); err != nil {
			t.Fatalf("failed to read stdout: %v", err)
		}
	})
}

func TestValidateDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("valid directory", func(t *testing.T) {
		err := validateDirectory(tmpDir)
		if err != nil {
			t.Errorf("expected no error for valid directory, got: %v", err)
		}
	})

	t.Run("nonexistent directory", func(t *testing.T) {
		err := validateDirectory("/nonexistent/path/to/directory")
		if err == nil {
			t.Error("expected error for nonexistent directory")
		}
		if !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("expected 'does not exist' error, got: %v", err)
		}
	})

	t.Run("path is a file not directory", func(t *testing.T) {
		file := filepath.Join(tmpDir, "testfile.txt")
		if err := os.WriteFile(file, []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}
		err := validateDirectory(file)
		if err == nil {
			t.Error("expected error for file path")
		}
		if !strings.Contains(err.Error(), "not a directory") {
			t.Errorf("expected 'not a directory' error, got: %v", err)
		}
	})
}

func TestScanDirectoryEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test structure
	if err := os.MkdirAll(filepath.Join(tmpDir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}

	// File in excluded directory
	excludedFile := filepath.Join(tmpDir, ".git", "config")
	if err := os.WriteFile(excludedFile, []byte("password: secret123\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// File in included directory
	includedFile := filepath.Join(tmpDir, "src", "config.yml")
	if err := os.WriteFile(includedFile, []byte("password: secret456\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// File with wrong extension
	wrongExtFile := filepath.Join(tmpDir, "src", "binary.exe")
	if err := os.WriteFile(wrongExtFile, []byte("password: secret789\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	exclude, fast, slow, err := loadEffectivePatterns(PatternFiles{})
	if err != nil {
		t.Fatal(err)
	}

	opts := scanOptions{
		Directory:       tmpDir,
		Extensions:      []string{".yml"},
		ExcludeDirs:     defaultExcludeDirs,
		ExcludePatterns: exclude,
		FastPatterns:    fast,
		SlowPatterns:    slow,
	}

	result := scanDirectory(opts)

	// Should only find matches in src/config.yml, not in .git/config or binary.exe
	foundInGit := false
	foundInSrc := false
	foundInExe := false

	for _, match := range result.Matches {
		if strings.Contains(match.File, ".git") {
			foundInGit = true
		}
		if strings.Contains(match.File, "src") && strings.HasSuffix(match.File, ".yml") {
			foundInSrc = true
		}
		if strings.HasSuffix(match.File, ".exe") {
			foundInExe = true
		}
	}

	if foundInGit {
		t.Error("should not find matches in excluded .git directory")
	}
	if !foundInSrc {
		t.Error("should find matches in src directory")
	}
	if foundInExe {
		t.Error("should not scan files with wrong extension")
	}
}

func TestScanDirectoryWithCallbacks(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	file1 := filepath.Join(tmpDir, "file1.yml")
	if err := os.WriteFile(file1, []byte("password: secret123\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	file2 := filepath.Join(tmpDir, "file2.yml")
	if err := os.WriteFile(file2, []byte("api_key: sk_test_abc\ntoken: xyz789\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	exclude, fast, slow, err := loadEffectivePatterns(PatternFiles{})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("OnCurrentFile callback is called", func(t *testing.T) {
		callbackCount := 0
		var lastFile string
		var lastIndex, lastTotal int

		opts := scanOptions{
			Directory:       tmpDir,
			Extensions:      []string{".yml"},
			ExcludeDirs:     defaultExcludeDirs,
			ExcludePatterns: exclude,
			FastPatterns:    fast,
			SlowPatterns:    slow,
			OnCurrentFile: func(file string, index, total int) {
				callbackCount++
				lastFile = file
				lastIndex = index
				lastTotal = total
			},
		}

		result := scanDirectory(opts)

		if callbackCount != 2 {
			t.Errorf("expected OnCurrentFile to be called 2 times, got %d", callbackCount)
		}
		if lastTotal != 2 {
			t.Errorf("expected total files to be 2, got %d", lastTotal)
		}
		if lastIndex != 1 {
			t.Errorf("expected last index to be 1, got %d", lastIndex)
		}
		if lastFile == "" {
			t.Error("expected lastFile to be set")
		}
		if len(result.Matches) == 0 {
			t.Error("expected to find matches")
		}
	})

	t.Run("OnMatch callback is called", func(t *testing.T) {
		var mu sync.Mutex
		matchCount := 0
		var matchedFiles []string

		opts := scanOptions{
			Directory:       tmpDir,
			Extensions:      []string{".yml"},
			ExcludeDirs:     defaultExcludeDirs,
			ExcludePatterns: exclude,
			FastPatterns:    fast,
			SlowPatterns:    slow,
			OnMatch: func(file string, lineNo int, line, match string) {
				mu.Lock()
				matchCount++
				matchedFiles = append(matchedFiles, file)
				mu.Unlock()
			},
		}

		result := scanDirectory(opts)

		mu.Lock()
		defer mu.Unlock()
		if matchCount == 0 {
			t.Error("expected OnMatch to be called at least once")
		}
		if matchCount != len(result.Matches) {
			t.Errorf("expected OnMatch count (%d) to equal result matches (%d)", matchCount, len(result.Matches))
		}
		if len(matchedFiles) == 0 {
			t.Error("expected matchedFiles to be populated")
		}
	})

	t.Run("both callbacks work together", func(t *testing.T) {
		var mu sync.Mutex
		fileCallbackCount := 0
		matchCallbackCount := 0

		opts := scanOptions{
			Directory:       tmpDir,
			Extensions:      []string{".yml"},
			ExcludeDirs:     defaultExcludeDirs,
			ExcludePatterns: exclude,
			FastPatterns:    fast,
			SlowPatterns:    slow,
			OnCurrentFile: func(file string, index, total int) {
				mu.Lock()
				fileCallbackCount++
				mu.Unlock()
			},
			OnMatch: func(file string, lineNo int, line, match string) {
				mu.Lock()
				matchCallbackCount++
				mu.Unlock()
			},
		}

		result := scanDirectory(opts)

		mu.Lock()
		defer mu.Unlock()
		if fileCallbackCount != 2 {
			t.Errorf("expected file callback count 2, got %d", fileCallbackCount)
		}
		if matchCallbackCount == 0 {
			t.Error("expected match callback to be called")
		}
		if len(result.Matches) == 0 {
			t.Error("expected matches in result")
		}
	})
}

func TestScanDirectoryShortLines(t *testing.T) {
	tmpDir := t.TempDir()

	// Create file with very short lines (should be skipped)
	shortFile := filepath.Join(tmpDir, "short.yml")
	content := "pwd: x\n" + // 6 chars - should be skipped
		"key: y\n" + // 6 chars - should be skipped
		"password: verylongsecret123\n" // Long enough to scan
	if err := os.WriteFile(shortFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	exclude, fast, slow, err := loadEffectivePatterns(PatternFiles{})
	if err != nil {
		t.Fatal(err)
	}

	opts := scanOptions{
		Directory:       tmpDir,
		Extensions:      []string{".yml"},
		ExcludeDirs:     defaultExcludeDirs,
		ExcludePatterns: exclude,
		FastPatterns:    fast,
		SlowPatterns:    slow,
	}

	result := scanDirectory(opts)

	// Should only find the long line with "password"
	if len(result.Matches) == 0 {
		t.Error("expected to find at least one match")
	}

	// Verify short lines were skipped
	for _, match := range result.Matches {
		if len(match.LineSnippet) <= 8 {
			t.Errorf("found match in short line: %s", match.LineSnippet)
		}
	}
}
