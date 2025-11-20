# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive test suite with unit, integration, and benchmark tests
- GitHub Actions CI/CD pipeline with multi-platform testing
- golangci-lint configuration with 30+ enabled linters
- Makefile for build automation
- Structured error handling throughout codebase
- Input validation for directory scanning
- CONTRIBUTING.md with development guidelines
- CHANGELOG.md for tracking changes
- Comprehensive README with professional documentation

### Changed
- Refactored global variables to function parameters for better testability
- Improved error handling with proper error wrapping
- Enhanced godoc comments for all exported functions and types
- Updated module path to public GitHub repository
- Improved .gitignore with comprehensive patterns

### Fixed
- Error handling in regex loading functions
- Directory validation before scanning
- File path handling edge cases

## [1.0.0] - Initial Release

### Added
- Concurrent secrets scanning using goroutines
- Two-stage detection pipeline (fast + strict patterns)
- False positive filtering with exclude patterns
- Terminal UI with progress tracking
- Support for multiple file extensions
- Optional file output for scan results
- Embedded regex pattern files
- Test suite with positive and false positive test cases
- TruffleHog comparison tool

### Features
- Scans local directories for hardcoded secrets
- Configurable regex patterns for different secret types
- Cross-platform support (Linux, macOS, Windows)
- Parallel processing using CPU cores
- Line-by-line buffered reading for memory efficiency
- ANSI color-coded terminal output
- Top files report for large scans

[Unreleased]: https://github.com/mattbordenet/passhog/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/mattbordenet/passhog/releases/tag/v1.0.0

