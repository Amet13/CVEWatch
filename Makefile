# CVEWatch Makefile
# A modern CVE vulnerability monitoring tool

.PHONY: help build test clean lint format check-fmt install uninstall

# Default target
help:
	@echo "CVEWatch - Available targets:"
	@echo "  build      - Build the application"
	@echo "  test       - Run all tests"
	@echo "  test-race  - Run tests with race detection"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  clean      - Clean build artifacts"
	@echo "  lint       - Run linters (requires golangci-lint)"
	@echo "  format     - Format code with gofmt"
	@echo "  check-fmt  - Check if code is properly formatted"
	@echo "  install    - Install the application"
	@echo "  uninstall  - Uninstall the application"
	@echo "  release    - Build release binaries for multiple platforms"
	@echo "  changelog  - Generate changelog (VERSION=v2.1.0)"

# Build the application
build:
	@echo "Building CVEWatch..."
	$(eval VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev"))
	$(eval BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S'))
	$(eval GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown"))
	go build -ldflags="-X 'cvewatch/pkg/version.Version=$(VERSION)' -X 'cvewatch/pkg/version.BuildTime=$(BUILD_TIME)' -X 'cvewatch/pkg/version.GitCommit=$(GIT_COMMIT)' -s -w" -o cvewatch ./cmd/cvewatch

# Build for current platform (useful for development)
build-native:
	@echo "Building CVEWatch for current platform..."
	go build -o cvewatch ./cmd/cvewatch

# Run all tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with race detection
test-race:
	@echo "Running tests with race detection..."
	go test -race -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"
	@echo "Coverage summary:"
	go tool cover -func=coverage.out | tail -1

# Run benchmarks
benchmark:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f cvewatch
	rm -f cvewatch-*
	rm -f *.exe
	rm -f coverage.out
	rm -f coverage.html
	go clean

# Run linters (requires golangci-lint)
lint:
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --no-config; \
	elif command -v ~/go/bin/golangci-lint >/dev/null 2>&1; then \
		~/go/bin/golangci-lint run --no-config; \
	else \
		echo "golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	fi

# Format code
format:
	@echo "Formatting code..."
	go fmt ./...
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	elif command -v ~/go/bin/goimports >/dev/null 2>&1; then \
		~/go/bin/goimports -w .; \
	else \
		echo "goimports not found. Install with: go install golang.org/x/tools/cmd/goimports@latest"; \
		exit 1; \
	fi

# Check if code is properly formatted
check-fmt:
	@echo "Checking code formatting..."
	@if [ -n "$$(gofmt -l .)" ]; then \
		echo "Code is not properly formatted. Run 'make format' to fix."; \
		exit 1; \
	fi
	@echo "Code is properly formatted."

# Install the application
install: build
	@echo "Installing CVEWatch..."
	@if [ -w /usr/local/bin ]; then \
		sudo cp cvewatch /usr/local/bin/; \
		echo "CVEWatch installed to /usr/local/bin/"; \
	else \
		echo "Installing to ~/.local/bin/"; \
		mkdir -p ~/.local/bin; \
		cp cvewatch ~/.local/bin/; \
		echo "CVEWatch installed to ~/.local/bin/"; \
		echo "Add ~/.local/bin to your PATH if not already there"; \
	fi

# Uninstall the application
uninstall:
	@echo "Uninstalling CVEWatch..."
	@if [ -f /usr/local/bin/cvewatch ]; then \
		sudo rm -f /usr/local/bin/cvewatch; \
		echo "CVEWatch removed from /usr/local/bin/"; \
	fi
	@if [ -f ~/.local/bin/cvewatch ]; then \
		rm -f ~/.local/bin/cvewatch; \
		echo "CVEWatch removed from ~/.local/bin/"; \
	fi

# Build release binaries for multiple platforms
release: clean
	@echo "Building release binaries..."
	@echo "Version: $(shell git describe --tags --always --dirty)"
	@echo "Build Time: $(shell date -u '+%Y-%m-%d %H:%M:%S UTC')"
	@echo "Git Commit: $(shell git rev-parse --short HEAD)"
	
	# Linux
	GOOS=linux GOARCH=amd64 go build \
		-ldflags="-s -w \
		-X 'cvewatch/pkg/version.Version=$(shell git describe --tags --always --dirty)' \
		-X 'cvewatch/pkg/version.BuildTime=$(shell date -u '+%Y-%m-%d %H:%M:%S UTC')' \
		-X 'cvewatch/pkg/version.GitCommit=$(shell git rev-parse --short HEAD)'" \
		-o cvewatch-linux-amd64 ./cmd/cvewatch
	GOOS=linux GOARCH=arm64 go build \
		-ldflags="-s -w \
		-X 'cvewatch/pkg/version.Version=$(shell git describe --tags --always --dirty)' \
		-X 'cvewatch/pkg/version.BuildTime=$(shell date -u '+%Y-%m-%d %H:%M:%S UTC')' \
		-X 'cvewatch/pkg/version.GitCommit=$(shell git rev-parse --short HEAD)'" \
		-o cvewatch-linux-arm64 ./cmd/cvewatch
	
	# macOS
	GOOS=darwin GOARCH=amd64 go build \
		-ldflags="-s -w \
		-X 'cvewatch/pkg/version.Version=$(shell git describe --tags --always --dirty)' \
		-X 'cvewatch/pkg/version.BuildTime=$(shell date -u '+%Y-%m-%d %H:%M:%S UTC')' \
		-X 'cvewatch/pkg/version.GitCommit=$(shell git rev-parse --short HEAD)'" \
		-o cvewatch-darwin-amd64 ./cmd/cvewatch
	GOOS=darwin GOARCH=arm64 go build \
		-ldflags="-s -w \
		-X 'cvewatch/pkg/version.Version=$(shell git describe --tags --always --dirty)' \
		-X 'cvewatch/pkg/version.BuildTime=$(shell date -u '+%Y-%m-%d %H:%M:%S UTC')' \
		-X 'cvewatch/pkg/version.GitCommit=$(shell git rev-parse --short HEAD)'" \
		-o cvewatch-darwin-arm64 ./cmd/cvewatch
	
	# Windows
	GOOS=windows GOARCH=amd64 go build \
		-ldflags="-s -w \
		-X 'cvewatch/pkg/version.Version=$(shell git describe --tags --always --dirty)' \
		-X 'cvewatch/pkg/version.BuildTime=$(shell date -u '+%Y-%m-%d %H:%M:%S UTC')' \
		-X 'cvewatch/pkg/version.GitCommit=$(shell git rev-parse --short HEAD)'" \
		-o cvewatch-windows-amd64.exe ./cmd/cvewatch
	GOOS=windows GOARCH=arm64 go build \
		-ldflags="-s -w \
		-X 'cvewatch/pkg/version.Version=$(shell git describe --tags --always --dirty)' \
		-X 'cvewatch/pkg/version.BuildTime=$(shell date -u '+%Y-%m-%d %H:%M:%S UTC')' \
		-X 'cvewatch/pkg/version.GitCommit=$(shell git rev-parse --short HEAD)'" \
		-o cvewatch-windows-arm64.exe ./cmd/cvewatch
	
	@echo "Release binaries built:"
	@ls -la cvewatch-*

# Development setup
dev-setup:
	@echo "Setting up development environment..."
	go mod download
	go mod verify
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	@if ! command -v goimports >/dev/null 2>&1; then \
		echo "Installing goimports..."; \
		go install golang.org/x/tools/cmd/goimports@latest; \
	fi
	@echo "Development environment ready."



# Security scanning
security-scan:
	@echo "Running security scan..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	elif command -v ~/go/bin/gosec >/dev/null 2>&1; then \
		~/go/bin/gosec ./...; \
	else \
		echo "gosec not found. Skipping security scan."; \
		echo "Install with: go install github.com/securego/gosec/v2/cmd/gosec@latest"; \
	fi

# Pre-commit checks
pre-commit: check-fmt test lint security-scan
	@echo "All pre-commit checks passed!"
