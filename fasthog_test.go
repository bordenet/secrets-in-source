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
			t.Fatal("expect