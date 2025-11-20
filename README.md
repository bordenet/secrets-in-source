# passhog

[![CI](https://github.com/bordenet/secrets-in-source/actions/workflows/ci.yml/badge.svg)](https://github.com/bordenet/secrets-in-source/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/bordenet/secrets-in-source/branch/main/graph/badge.svg)](https://codecov.io/gh/bordenet/secrets-in-source)
[![Go Version](https://img.shields.io/github/go-mod/go-version/bordenet/secrets-in-source)](https://go.dev/)
[![License](https://img.shields.io/github/license/bordenet/secrets-in-source)](./LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/bordenet/secrets-in-source)](https://goreportcard.com/report/github.com/bordenet/secrets-in-source)

A concurrent secrets scanner for source code repositories. Passhog detects hardcoded credentials, API keys, and other sensitive information using configurable regex patterns.

## Features

- **Concurrent scanning**: Leverages multiple CPU cores for parallel file processing
- **Two-stage detection**: Fast preliminary screening followed by thorough pattern matching
- **False positive filtering**: Configurable exclusion patterns to reduce noise
- **Multiple output formats**: Terminal UI with progress tracking and optional file output
- **Extensible patterns**: Customizable regex files for different secret types
- **Cross-platform**: Builds for Linux, macOS, and Windows

## Installation

### Prerequisites

- Go 1.22 or later ([download](https://go.dev/dl/))

### Install from source

```bash
git clone https://github.com/bordenet/secrets-in-source.git
cd secrets-in-source
go install
```

Ensure `~/go/bin` is in your `PATH` to run the installed binary.

### Build from source

```bash
git clone https://github.com/bordenet/secrets-in-source.git
cd secrets-in-source
make build
```

The binary will be created in the current directory.

### Cross-compilation

Build for different platforms:

```bash
# Windows
GOOS=windows GOARCH=amd64 go build -o passhog.exe

# Linux
GOOS=linux GOARCH=amd64 go build -o passhog

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o passhog
```

## Usage

### Basic scanning

```bash
# Scan a directory
passhog /path/to/repository

# Scan specific file types
passhog /path/to/repository --types=py,js,go

# Save results to file
passhog /path/to/repository --output=results.txt

# Combine options
passhog /path/to/repository --types=yml,yaml,env,tf --output=results.txt
```

### Running from source

```bash
go run passhog.go /path/to/repository
```

### Examples

```bash
# Scan Python and C# files
passhog ~/projects/myapp --types=py,cs --output=secrets_report.txt

# Scan infrastructure files
passhog ~/terraform --types=tf,yml,yaml,env

# Scan entire codebase with default extensions
passhog ~/repositories/myproject
```

### Example Output

```
Directory: /path/to/repository
Extensions: [.py .js .yml .yaml .env]
Output: results.txt
Current file: config/database.yml  Matches: 3
███████████████████████████████████ 100%

Results:
config/database.yml:0012 password: "mySecretPassword123"
src/api/keys.js:0045 const API_KEY = "sk_live_1234567890abcdef"
.env:0003 DATABASE_URL=postgres://user:pass@localhost/db

Completed in 1.2s: 3 matches across 3 of 127 files
Results written to results.txt
```

## Architecture

### Scanning Process

Passhog uses a two-stage detection pipeline:

1. **Fast screening**: Initial pass with lightweight patterns (`fast_patterns.regex`)
2. **Strict validation**: Thorough analysis with comprehensive patterns (`strict_patterns.regex`)
3. **False positive filtering**: Exclusion of known benign patterns (`exclude_patterns.regex`)

### Performance Optimizations

- **Precompiled patterns**: Regex patterns are compiled once at startup
- **Concurrent processing**: Parallel file scanning using worker pools (up to `runtime.NumCPU()` workers)
- **Streaming I/O**: Line-by-line buffered reading to optimize memory usage
- **In-memory processing**: No temporary files or external process invocations

## Pattern Files

Passhog uses multiple regex pattern files for flexible detection:

| File | Purpose |
|------|---------|
| `direct_matches.regex` | High-confidence patterns for common secrets |
| `fast_patterns.regex` | Lightweight patterns for initial screening |
| `strict_patterns.regex` | Comprehensive patterns for thorough detection |
| `exclude_patterns.regex` | Patterns to filter false positives |

### Customizing Patterns

Edit the `.regex` files to add or modify detection patterns. Each file contains one regex pattern per line. Empty lines and lines starting with `#` are ignored.

## Testing

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
make test-coverage

# Run benchmarks
make bench
```

### Test Cases

The test suite validates pattern accuracy using:

- `test/Positives.txt`: Known secrets that must be detected
- `test/False_Positives.txt`: Benign patterns that should not trigger alerts

### Adding Test Cases

**For false positives:**

1. Add the pattern to `test/False_Positives.txt`
2. Update `exclude_patterns.regex` to filter it
3. Run `go test` to verify

**For missed secrets:**

1. Add the secret to `test/Positives.txt`
2. Update `fast_patterns.regex` and/or `strict_patterns.regex`
3. Run `go test` to verify detection

## Comparison with TruffleHog

A gap analysis tool is provided in the `test` directory to compare results with TruffleHog:

```bash
# Generate TruffleHog results
trufflehog filesystem ~/repositories --json --concurrency=36 > trufflehog.json

# Generate passhog results
passhog ~/repositories --output=passhog.txt

# Compare results
cd test
go run secrets_gap_analysis.go -t ../trufflehog.json -p ../passhog.txt
```

**Note**: Passhog does not currently parse compressed archives (.zip, .tar.gz, etc.).

## Development

### Building

```bash
# Build binary
make build

# Install locally
make install

# Run linters
make lint

# Format code
make fmt

# Run all checks
make check
```

### Project Structure

```
.
├── passhog.go              # Main application
├── *_test.go               # Test files
├── *.regex                 # Pattern definition files
├── test/
│   ├── Positives.txt       # Known secrets for testing
│   ├── False_Positives.txt # Benign patterns for testing
│   └── secrets_gap_analysis.go  # TruffleHog comparison tool
├── .github/workflows/      # CI/CD configuration
└── Makefile                # Build automation
```

## Contributing

Contributions are welcome. Please:

1. Add test cases for new patterns
2. Ensure all tests pass (`go test ./...`)
3. Run linters (`make lint`)
4. Update documentation as needed

## License

This project is licensed under the MIT License – see the [LICENSE](./LICENSE) file for details.

## Acknowledgments

Originally developed as a bash script, migrated to Go in collaboration with [danielgtaylor](https://github.com/danielgtaylor).
