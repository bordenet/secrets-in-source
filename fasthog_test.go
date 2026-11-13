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
