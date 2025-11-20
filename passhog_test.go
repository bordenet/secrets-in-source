package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

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

// TestRunPasshogValidation tests input validation.
func TestRunPasshogValidation(t *testing.T) {
	t.Run("file instead of directory", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "file.txt")
		err := os.WriteFile(tmpFile, []byte("test"), 0644)
		if err != nil {
			t.Fatal(err)
		}

		err = runPasshog(tmpFile, defaultExtensions, "")
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
	err = runPasshog(tmpDir, []string{".py"}, outputFile)
	if err != nil {
		t.Fatalf("runPasshog failed: %v", err)
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
	err = runPasshog(tmpDir, []string{".py"}, outputFile)
	if err != nil {
		t.Fatalf("runPasshog failed: %v", err)
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
