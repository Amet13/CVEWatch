# CVEWatch Makefile
# A modern CVE vulnerability monitoring tool

.PHONY: help build build-native test test-race test-coverage benchmark clean lint format check-fmt install uninstall release release-snapshot release-check dev-setup security-scan pre-commit ci-quality ci-test ci-build ci-cross-build ci-release deps deps-tidy

# Default target
help:
	@echo "CVEWatch - Available targets:"
	@echo "  deps       - Download and verify dependencies"
	@echo "  deps-tidy  - Tidy and verify go.mod/go.sum"
	@echo "  build      - Build the application"
	@echo "  build-native - Build for current platform"
	@echo "  test       - Run all tests"
	@echo "  test-race  - Run tests with race detection"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  benchmark  - Run benchmarks"
	@echo "  clean      - Clean build artifacts"
	@echo "  lint       - Run linters (requires golangci-lint)"
	@echo "  format     - Format code with gofmt and goimports"
	@echo "  check-fmt  - Check if code is properly formatted"
	@echo "  security-scan - Run security scanner (gosec)"
	@echo "  install    - Install the application"
	@echo "  uninstall  - Uninstall the application"
	@echo "  release    - Create release with GoReleaser"
	@echo "  release-snapshot - Create snapshot release"
	@echo "  release-check - Validate GoReleaser configuration"
	@echo "  dev-setup - Set up development environment"
	@echo "  pre-commit - Run all pre-commit checks"
	@echo "  ci-quality - Run CI quality checks"
	@echo "  ci-test    - Run CI test suite"
	@echo "  ci-build   - Run CI build"
	@echo "  ci-cross-build - Run CI cross-platform build"
	@echo "  ci-release - Run CI release"

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
	rm -f cvewatch.exe
	rm -f coverage.out
	rm -f coverage.html
	rm -f security-report.json
	rm -f benchmark.txt
	# Remove all cvewatch-* files including cross-platform builds
	-find . -maxdepth 1 -name "cvewatch-*" -type f -exec rm -f {} \; 2>/dev/null || true
	# Remove all .exe files
	-find . -maxdepth 1 -name "*.exe" -type f -exec rm -f {} \; 2>/dev/null || true
	go clean

# Run linters (requires golangci-lint)
lint:
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	elif command -v ~/go/bin/golangci-lint >/dev/null 2>&1; then \
		~/go/bin/golangci-lint run; \
	else \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
		golangci-lint run; \
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

# Release using GoReleaser
release:
	@echo "Creating release with GoReleaser..."
	@if ! command -v goreleaser >/dev/null 2>&1; then \
		echo "Installing GoReleaser..."; \
		go install github.com/goreleaser/goreleaser/v2@latest; \
	fi
	goreleaser release --clean

# Release snapshot (for testing)
release-snapshot:
	@echo "Creating snapshot release..."
	@if ! command -v goreleaser >/dev/null 2>&1; then \
		echo "Installing GoReleaser..."; \
		go install github.com/goreleaser/goreleaser/v2@latest; \
	fi
	goreleaser release --snapshot --clean

# Check GoReleaser configuration
release-check:
	@echo "Validating GoReleaser configuration..."
	@if ! command -v goreleaser >/dev/null 2>&1; then \
		echo "Installing GoReleaser..."; \
		go install github.com/goreleaser/goreleaser/v2@latest; \
	fi
	goreleaser check

# Dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download

deps-tidy:
	@echo "Tidying go.mod and go.sum..."
	go mod tidy
	go mod verify
	@if [ -n "$$(git diff --name-only go.mod go.sum)" ]; then \
		echo "go.mod or go.sum is not tidy. Run 'make deps-tidy' to fix."; \
		exit 1; \
	else \
		echo "go.mod and go.sum are tidy."; \
	fi

# Development setup
dev-setup: deps deps-tidy
	@echo "Setting up development environment..."
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	@if ! command -v goimports >/dev/null 2>&1; then \
		echo "Installing goimports..."; \
		go install golang.org/x/tools/cmd/goimports@latest; \
	fi
	@if ! command -v gosec >/dev/null 2>&1; then \
		echo "Installing gosec..."; \
		go install github.com/securego/gosec/v2/cmd/gosec@latest; \
	fi
	@echo "Development environment ready."

# Security scanning
security-scan:
	@echo "Running security scan..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec -fmt=json -out=security-report.json -severity=medium -confidence=medium ./...; \
		echo "Security scan completed. Report saved to security-report.json"; \
	elif command -v ~/go/bin/gosec >/dev/null 2>&1; then \
		~/go/bin/gosec -fmt=json -out=security-report.json -severity=medium -confidence=medium ./...; \
		echo "Security scan completed. Report saved to security-report.json"; \
	else \
		echo "Installing gosec..."; \
		go install github.com/securego/gosec/v2/cmd/gosec@latest; \
		gosec -fmt=json -out=security-report.json -severity=medium -confidence=medium ./...; \
		echo "Security scan completed. Report saved to security-report.json"; \
	fi

# Pre-commit checks
pre-commit: check-fmt test lint security-scan
	@echo "All pre-commit checks passed!"

# CI Quality Checks (equivalent to CI quality job)
ci-quality: deps-tidy check-fmt lint security-scan
	@echo "All CI quality checks passed!"

# CI Test Suite (equivalent to CI test job)
ci-test: deps test-race test-coverage benchmark
	@echo "All CI tests passed!"

# CI Build (equivalent to CI build job)
ci-build: deps build
	@echo "Testing installation..."
	@if [ -w /usr/local/bin ]; then \
		sudo cp cvewatch /usr/local/bin/ 2>/dev/null || true; \
		/usr/local/bin/cvewatch version 2>/dev/null || true; \
	else \
		mkdir -p ~/.local/bin 2>/dev/null || true; \
		cp cvewatch ~/.local/bin/ 2>/dev/null || true; \
		~/.local/bin/cvewatch version 2>/dev/null || true; \
	fi

# CI Cross-platform Build (equivalent to CI cross-build job)
ci-cross-build: deps
	@echo "Building for multiple platforms..."
	@for os in linux darwin windows; do \
		for arch in amd64 arm64; do \
			if [ "$$os" = "windows" ] && [ "$$arch" = "arm64" ]; then \
				continue; \
			fi; \
			echo "Building for $$os/$$arch..."; \
			BINARY_NAME=cvewatch; \
			if [ "$$os" = "windows" ]; then \
				BINARY_NAME=cvewatch.exe; \
			fi; \
			GOOS=$$os GOARCH=$$arch go build -ldflags="-s -w" -o $${BINARY_NAME}-$$os-$$arch ./cmd/cvewatch; \
		done; \
	done
	@echo "Cross-platform builds completed!"

# CI Release (equivalent to CI release job)
ci-release: release
	@echo "CI release completed!"
