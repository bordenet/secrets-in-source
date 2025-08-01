package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

type lineInfo struct {
	line string
	path string
	pos  int
}

func loadLines(filesystem fs.FS, paths ...string) []lineInfo {
	regexes := []lineInfo{}
	for _, path := range paths {
		b, err := fs.ReadFile(filesystem, path)
		if err != nil {
			panic(fmt.Errorf("unable to load regexes from %s: %w", path, err))
		}
		for i, line := range bytes.Split(b, []byte("\n")) {
			if len(line) == 0 || line[0] == '#' {
				continue
			}
			regexes = append(regexes, lineInfo{shellReplacer.Replace(string(line)), path, i})
		}
	}
	return regexes
}

func testLines(t *testing.T, regexes []lineInfo, input string, label string) {
	for _, info := range regexes {
		if regexp.MustCompile(info.line).MatchString(input) {
			t.Errorf("%s by %s:%d\nregex «%s»\ninput «%s»", label, info.path, info.pos+1, info.line, input)
			return
		}
	}
}

func TestPositives(t *testing.T) {
	fast := loadRegexes(regexFS, "direct_matches.regex", "fast_patterns.regex")
	slow := loadRegexes(regexFS, "direct_matches.regex", "strict_patterns.regex")
	exclude := loadRegexes(regexFS, "exclude_patterns.regex")

	excludeLines := loadLines(regexFS, "exclude_patterns.regex")

	b, err := os.ReadFile("test/Positives.txt")
	if err != nil {
		t.Fatal(err)
	}
	inputs := slices.DeleteFunc(strings.Split(string(b), "\n"), func(s string) bool { return s == "" || strings.HasPrefix(s, "#") })
	for i, input := range inputs {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if !fast.MatchString(input) {
				t.Fatalf("did not match direct/fast_patterns.regex\ninput «%s»", input)
			}
			if !slow.MatchString(input) {
				t.Fatalf("did not match direct/strict_patterns.regex\ninput «%s»", input)
			}
			if exclude.MatchString(input) {
				testLines(t, excludeLines, input, "filtered out")
			}
		})
	}
}

func TestFalsePositives(t *testing.T) {
	fast := loadRegexes(regexFS, "direct_matches.regex", "fast_patterns.regex")
	slow := loadRegexes(regexFS, "direct_matches.regex", "strict_patterns.regex")
	exclude := loadRegexes(regexFS, "exclude_patterns.regex")

	fastLines := loadLines(regexFS, "direct_matches.regex", "fast_patterns.regex")
	slowLines := loadLines(regexFS, "strict_patterns.regex")

	b, err := os.ReadFile("test/False_Positives.txt")
	if err != nil {
		t.Fatal(err)
	}
	inputs := slices.DeleteFunc(strings.Split(string(b), "\n"), func(s string) bool { return s == "" || strings.HasPrefix(s, "#") })
	for i, input := range inputs {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			if !exclude.MatchString(input) && slow.MatchString(input) && fast.MatchString(input) {
				testLines(t, fastLines, input, "matched")
				testLines(t, slowLines, input, "matched")
			}
		})
	}
}
