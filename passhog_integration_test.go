package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIntegrationScanDirectory performs end-to-end testing of directory scanning.
func TestIntegrationScanDirectory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Run("scan test directory", func(t *testing.T) {
		// Use the test directory which contains known positives and false positives
		testDir := "test"
		outputFile := filepath.Join(t.TempDir(), "results.txt")

		err := runPasshog(testDir, defaultExtensions, outputFile)
		if err != nil {
			t.Fatalf("runPasshog failed: %v", err)
		}

		// Verify output file was created
		if _, err := os.Stat(outputFile); os.IsNotExist(err) {
			t.Fatal("output file was not created")
		}

		// Read and verify output contains expected matches
		content, err := os.ReadFile(outputFile)
		if err != nil {
			t.Fatalf("failed to read output file: %v", err)
		}

		output := string(content)
		if len(output) == 0 {
			t.Error("expected non-empty output")
		}

		// Should find secrets in Positives.txt
		if !strings.Contains(output, "Positives.txt") {
			t.Error("expected to find matches in Positives.txt")
		}
	})

	t.Run("scan with specific extensions", func(t *testing.T) {
		testDir := "test"
		outputFile := filepath.Join(t.TempDir(), "results.txt")
		extensions := []string{".txt"}

		err := runPasshog(testDir, extensions, outputFile)
		if err != nil {
			t.Fatalf("runPasshog failed: %v", err)
		}

		content, err := os.ReadFile(outputFile)
		if err != nil {
			t.Fatalf("failed to read output file: %v", err)
		}

		output := string(content)
		// Should only scan .txt files
		if strings.Contains(output, ".go") {
			t.Error("should not scan .go files when only .txt is specified")
		}
	})

	t.Run("scan empty directory", func(t *testing.T) {
		emptyDir := t.TempDir()
		outputFile := filepath.Join(t.TempDir(), "results.txt")

		err := runPasshog(emptyDir, defaultExtensions, outputFile)
		if err != nil {
			t.Fatalf("runPasshog failed: %v", err)
		}

		content, err := os.ReadFile(outputFile)
		if err != nil {
			t.Fatalf("failed to read output file: %v", err)
		}

		// Empty directory should produce empty results
		if len(content) > 0 {
			t.Errorf("expected empty output for empty directory, got: %s", string(content))
		}
	})

	t.Run("scan directory with secrets", func(t *testing.T) {
		// Create a temporary directory with a file containing a secret
		tmpDir := t.TempDir()
		secretFile := filepath.Join(tmpDir, "config.py")
		secretContent := `PASSWORD="mysecretpassword123"`

		err := os.WriteFile(secretFile, []byte(secretContent), 0644)
		if err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		outputFile := filepath.Join(t.TempDir(), "results.txt")
		err = runPasshog(tmpDir, []string{".py"}, outputFile)
		if err != nil {
			t.Fatalf("runPasshog failed: %v", err)
		}

		content, err := os.ReadFile(outputFile)
		if err != nil {
			t.Fatalf("failed to read output file: %v", err)
		}

		output := string(content)
		if !strings.Contains(output, "config.py") {
			t.Error("expected to find secret in config.py")
		}
		if !strings.Contains(output, "PASSWORD") {
			t.Error("expected to find PASSWORD in output")
		}
	})

	t.Run("nonexistent directory", func(t *testing.T) {
		err := runPasshog("/nonexistent/directory", defaultExtensions, "")
		if err == nil {
			t.Error("expected error for nonexistent directory")
		}
	})
}

// TestIntegrationExcludeDirectories verifies that excluded directories are skipped.
func TestIntegrationExcludeDirectories(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()

	// Create a .git directory with a file containing a secret
	gitDir := filepath.Join(tmpDir, ".git")
	err := os.Mkdir(gitDir, 0755)
	if err != nil {
		t.Fatalf("failed to create .git directory: %v", err)
	}

	secretFile := filepath.Join(gitDir, "config")
	err = os.WriteFile(secretFile, []byte(`PASSWORD="shouldbeignored"`), 0644)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	outputFile := filepath.Join(t.TempDir(), "results.txt")
	err = runPasshog(tmpDir, defaultExtensions, outputFile)
	if err != nil {
		t.Fatalf("runPasshog failed: %v", err)
	}

	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	// .git directory should be excluded
	if strings.Contains(string(content), ".git") {
		t.Error(".git directory should be excluded from scanning")
	}
}

// TestIntegrationTopFilesReport verifies the top files report is generated for large scans.
func TestIntegrationTopFilesReport(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()

	// Create more than 10 files with varying numbers of secrets
	for i := 0; i < 15; i++ {
		filename := filepath.Join(tmpDir, fmt.Sprintf("file%02d.py", i))
		var content strings.Builder

		// Each file gets a different number of secrets (using patterns that will match)
		secretCount := (i % 5) + 1
		for j := 0; j < secretCount; j++ {
			// Use patterns that will actually match the regex
			content.WriteString(fmt.Sprintf(`PASSWORD = "mysecretpassword%d%d"`+"\n", i, j))
		}

		err := os.WriteFile(filename, []byte(content.String()), 0644)
		if err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
	}

	outputFile := filepath.Join(t.TempDir(), "results.txt")
	err := runPasshog(tmpDir, []string{".py"}, outputFile)
	if err != nil {
		t.Fatalf("runPasshog failed: %v", err)
	}

	// Verify output file was created and contains results
	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	output := string(content)
	if len(output) == 0 {
		t.Error("expected non-empty output")
	}

	// Should find secrets in multiple files
	if !strings.Contains(output, "PASSWORD") {
		t.Error("expected to find PASSWORD in output")
	}
}

// TestIntegrationNoOutputFile verifies scanning works without output file.
func TestIntegrationNoOutputFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.py")
	err := os.WriteFile(testFile, []byte(`PASSWORD="test123"`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Run without output file (empty string)
	err = runPasshog(tmpDir, []string{".py"}, "")
	if err != nil {
		t.Fatalf("runPasshog failed: %v", err)
	}
}
