.PHONY: help build test test-verbose test-coverage lint fmt vet clean install run bench

# Default target
help:
	@echo "Available targets:"
	@echo "  build          - Build the passhog binary"
	@echo "  test           - Run tests"
	@echo "  test-verbose   - Run tests with verbose output"
	@echo "  test-coverage  - Run tests with coverage report"
	@echo "  bench          - Run benchmarks"
	@echo "  lint           - Run linters (requires golangci-lint)"
	@echo "  fmt            - Format code"
	@echo "  vet            - Run go vet"
	@echo "  clean          - Remove build artifacts"
	@echo "  install        - Install passhog to GOPATH/bin"
	@echo "  run            - Run passhog (requires DIR variable)"

# Build the binary
build:
	go build -o passhog .

# Run tests
test:
	go test -race ./...

# Run tests with verbose output
test-verbose:
	go test -v -race ./...

# Run tests with coverage
test-coverage:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"
	@go tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'

# Run benchmarks
bench:
	go test -bench=. -benchmem ./...

# Run linters
lint:
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed. Install from https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run

# Format code
fmt:
	go fmt ./...

# Run go vet
vet:
	go vet ./...

# Clean build artifacts
clean:
	rm -f passhog passhog.exe
	rm -f coverage.out coverage.html
	rm -f *.test
	rm -f passhog_results*.txt

# Install to GOPATH/bin
install:
	go install .

# Run passhog (example: make run DIR=/path/to/scan)
run:
	@if [ -z "$(DIR)" ]; then \
		echo "Usage: make run DIR=/path/to/scan"; \
		exit 1; \
	fi
	go run . $(DIR)

# Run all quality checks
check: fmt vet test lint
	@echo "All quality checks passed!"

