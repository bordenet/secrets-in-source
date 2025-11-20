# Contributing to passhog

Thank you for your interest in contributing to passhog. This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and professional in all interactions
- Focus on constructive feedback
- Welcome newcomers and help them get started

## Getting Started

### Prerequisites

- Go 1.22 or later
- Git
- Make (optional, but recommended)

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/mattbordenet/passhog.git
cd passhog

# Install dependencies
go mod download

# Run tests to verify setup
go test ./...
```

## Development Workflow

### Making Changes

1. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the code style guidelines below

3. **Add tests** for new functionality or bug fixes

4. **Run the test suite**:
   ```bash
   go test ./...
   ```

5. **Run linters**:
   ```bash
   make lint
   # or
   golangci-lint run
   ```

6. **Format your code**:
   ```bash
   make fmt
   # or
   gofmt -w .
   ```

### Code Style

- Follow standard Go conventions and idioms
- Use `gofmt` for formatting
- Write clear, descriptive variable and function names
- Add godoc comments for all exported functions and types
- Keep functions focused and reasonably sized
- Handle errors explicitly; avoid panics except in truly exceptional cases

### Testing Requirements

All contributions must include appropriate tests:

- **Unit tests** for new functions and methods
- **Integration tests** for end-to-end functionality
- **Test cases** in `test/Positives.txt` or `test/False_Positives.txt` for new patterns

#### Test Coverage

- Aim for high test coverage on new code
- Run coverage reports: `make test-coverage`
- View coverage: `go tool cover -html=coverage.out`

### Adding Detection Patterns

When adding new regex patterns:

1. **Add test cases first**:
   - For secrets that should be detected: add to `test/Positives.txt`
   - For false positives to exclude: add to `test/False_Positives.txt`

2. **Update pattern files**:
   - Add to `fast_patterns.regex` for initial screening
   - Add to `strict_patterns.regex` for thorough detection
   - Add to `exclude_patterns.regex` to filter false positives

3. **Verify with tests**:
   ```bash
   go test -v
   ```

4. **Document the pattern** in your pull request description

### Commit Messages

Write clear, concise commit messages:

```
Add detection for Azure connection strings

- Add pattern to strict_patterns.regex
- Add test cases to Positives.txt
- Update documentation
```

Format:
- First line: Brief summary (50 chars or less)
- Blank line
- Detailed description if needed
- List specific changes with bullet points

## Pull Request Process

1. **Update documentation** if you've changed functionality

2. **Ensure all tests pass**:
   ```bash
   make check
   ```

3. **Create a pull request** with:
   - Clear description of changes
   - Reference to any related issues
   - Test results showing all tests pass

4. **Respond to feedback** from reviewers promptly

5. **Squash commits** if requested before merging

## Reporting Issues

### Bug Reports

Include:
- Go version (`go version`)
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error messages

### Feature Requests

Include:
- Clear description of the feature
- Use case and motivation
- Proposed implementation approach (if applicable)

### Security Issues

**Do not** open public issues for security vulnerabilities. Instead, email the maintainers directly.

## Questions?

- Open a discussion on GitHub
- Check existing issues and pull requests
- Review the README and documentation

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

