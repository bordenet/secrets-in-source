package main

import (
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkLoadRegexes measures regex loading and compilation performance.
func BenchmarkLoadRegexes(b *testing.B) {
	b.Run("exclude_patterns", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := loadRegexes(regexFS, "exclude_patterns.regex")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("fast_patterns", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := loadRegexes(regexFS, "direct_matches.regex", "fast_patterns.regex")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("strict_patterns", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := loadRegexes(regexFS, "direct_matches.regex", "strict_patterns.regex")
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkHasExtension measures extension matching performance.
func BenchmarkHasExtension(b *testing.B) {
	extensions := defaultExtensions
	paths := []string{
		"test.py",
		"test.js",
		"test.go",
		"test.txt",
		"test.unknown",
		"very/long/path/to/some/file.py",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, path := range paths {
			hasExtension(path, extensions)
		}
	}
}

// BenchmarkRegexMatching measures pattern matching performance.
func BenchmarkRegexMatching(b *testing.B) {
	fast, err := loadRegexes(regexFS, "direct_matches.regex", "fast_patterns.regex")
	if err != nil {
		b.Fatal(err)
	}
	slow, err := loadRegexes(regexFS, "direct_matches.regex", "strict_patterns.regex")
	if err != nil {
		b.Fatal(err)
	}
	exclude, err := loadRegexes(regexFS, "exclude_patterns.regex")
	if err != nil {
		b.Fatal(err)
	}

	testLines := []string{
		`PASSWORD="mysecretpassword123"`,
		`AWS_SECRET_ACCESS_KEY=abcdefghijklmnop`,
		`api_key: "sk_live_1234567890abcdef"`,
		`const password = "test123"`,
		`password: str = None`,
		`ADMIN_PASSWORD: "${ADMIN_PASSWORD}"`,
	}

	b.Run("fast_patterns", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, line := range testLines {
				fast.MatchString(line)
			}
		}
	})

	b.Run("strict_patterns", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, line := range testLines {
				slow.MatchString(line)
			}
		}
	})

	b.Run("exclude_patterns", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, line := range testLines {
				exclude.MatchString(line)
			}
		}
	})

	b.Run("full_pipeline", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, line := range testLines {
				if fast.MatchString(line) {
					if match := slow.FindString(line); match != "" && !exclude.MatchString(line) {
						_ = match
					}
				}
			}
		}
	})
}

// BenchmarkWriteResults measures output writing performance.
func BenchmarkWriteResults(b *testing.B) {
	matches := make([]string, 1000)
	for i := range matches {
		matches[i] = "test/file.py:0042 PASSWORD=\"secret123\""
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tmpFile := filepath.Join(b.TempDir(), "bench_results.txt")
		err := writeResults(matches, tmpFile)
		if err != nil {
			b.Fatal(err)
		}
		_ = os.Remove(tmpFile) // Best effort cleanup
	}
}

// BenchmarkScanSmallDirectory measures scanning performance on a small directory.
func BenchmarkScanSmallDirectory(b *testing.B) {
	// Create a temporary directory with a few files
	tmpDir := b.TempDir()
	for i := 0; i < 10; i++ {
		content := `
import os
PASSWORD = "test123"
api_key = "sk_test_abc123"
`
		filename := filepath.Join(tmpDir, "file"+string(rune('0'+i))+".py")
		err := os.WriteFile(filename, []byte(content), 0644)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		outputFile := filepath.Join(b.TempDir(), "bench_output.txt")
		err := runPasshog(tmpDir, []string{".py"}, outputFile)
		if err != nil {
			b.Fatal(err)
		}
		_ = os.Remove(outputFile) // Best effort cleanup
	}
}
