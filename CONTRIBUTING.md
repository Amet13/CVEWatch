# Contributing to CVEWatch

Thank you for your interest in contributing to CVEWatch! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Code Style](#code-style)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)
- [Feature Requests](#feature-requests)
- [Questions and Discussion](#questions-and-discussion)

## Code of Conduct

This project is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally
3. **Set up the development environment** (see below)
4. **Create a feature branch** for your changes
5. **Make your changes** following our guidelines
6. **Test your changes** thoroughly
7. **Submit a pull request**

## Development Setup

### Prerequisites

- Go 1.22 or later
- Git
- Make (optional, but recommended)

### Quick Setup

```bash
# Clone your fork
git clone https://github.com/Amet13/CVEWatch.git
cd cvewatch

# Run the development setup script
./scripts/dev-setup.sh

# Or manually:
go mod download
go mod tidy
make build
make test
```

### Manual Setup

```bash
# Install dependencies
go mod download
go mod tidy

# Install development tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/google/go-licenses@latest

# Build and test
make build
make test
```

## Contributing Guidelines

### Before You Start

1. **Check existing issues** to see if your idea is already being worked on
2. **Discuss major changes** in an issue before starting work
3. **Keep changes focused** - one feature or fix per pull request
4. **Follow existing patterns** in the codebase

### What We're Looking For

- **Bug fixes** - especially security-related issues
- **Performance improvements** - faster execution, lower memory usage
- **New features** - that align with the project's goals
- **Documentation** - improvements to README, code comments, etc.
- **Tests** - additional test coverage
- **Code quality** - refactoring, better error handling, etc.

### What We're NOT Looking For

- **Breaking changes** without discussion
- **Major architectural changes** without prior agreement
- **Features that don't align** with the project's scope
- **Changes that reduce** test coverage or code quality

## Code Style

### Go Code

- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use `gofmt` for formatting
- Use `go vet` for static analysis
- Follow the project's existing naming conventions
- Add comments for exported functions and types

### General Guidelines

- **Keep functions small** and focused
- **Use meaningful names** for variables and functions
- **Handle errors properly** - don't ignore them
- **Add logging** for important operations
- **Use constants** for magic numbers
- **Prefer composition** over inheritance

### Example

```go
// Good
func (c *Client) FetchVulnerabilities(ctx context.Context, product string) ([]Vulnerability, error) {
    if product == "" {
        return nil, errors.New("product name cannot be empty")
    }

    // ... implementation
}

// Bad
func (c *Client) get(c string) ([]V, error) {
    // ... implementation without error handling
}
```

## Testing

### Test Requirements

- **All new code** must include tests
- **Bug fixes** must include tests that reproduce the bug
- **Maintain or improve** test coverage
- **Run all tests** before submitting a pull request

### Running Tests

```bash
# Run all tests
make test

# Run tests with race detection
make test-race

# Run tests with coverage
make test-coverage

# Run specific test
go test ./internal/nvd -v

# Run tests in a specific package
go test ./pkg/utils -v
```

### Test Guidelines

- **Use descriptive test names** that explain what is being tested
- **Test both success and failure cases**
- **Use table-driven tests** for multiple scenarios
- **Mock external dependencies** when appropriate
- **Test edge cases** and error conditions

### Example Test

```go
func TestFetchVulnerabilities(t *testing.T) {
    tests := []struct {
        name        string
        product     string
        expectError bool
    }{
        {"valid product", "apache", false},
        {"empty product", "", true},
        {"whitespace product", "   ", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            client := NewClient()
            _, err := client.FetchVulnerabilities(context.Background(), tt.product)

            if tt.expectError && err == nil {
                t.Error("expected error but got none")
            }
            if !tt.expectError && err != nil {
                t.Errorf("unexpected error: %v", err)
            }
        })
    }
}
```

## Pull Request Process

### Before Submitting

1. **Ensure tests pass** locally
2. **Run linting** and fix any issues
3. **Update documentation** if needed
4. **Squash commits** if you have many small commits
5. **Write a clear description** of your changes

### Pull Request Template

```markdown
## Description

Brief description of what this PR does.

## Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing

- [ ] All tests pass locally
- [ ] Added tests for new functionality
- [ ] Updated tests for changed functionality

## Checklist

- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
```

### Review Process

1. **Automated checks** must pass (CI/CD)
2. **Code review** by maintainers
3. **Address feedback** and make requested changes
4. **Maintainer approval** required for merge
5. **Squash and merge** when ready

## Reporting Issues

### Bug Reports

When reporting bugs, please include:

- **Clear description** of the problem
- **Steps to reproduce** the issue
- **Expected behavior** vs actual behavior
- **Environment details** (OS, Go version, etc.)
- **Configuration** (relevant parts of config.yaml)
- **Logs** or error messages
- **Screenshots** if applicable

### Issue Template

```markdown
## Bug Description

Brief description of the bug.

## Steps to Reproduce

1. Step 1
2. Step 2
3. Step 3

## Expected Behavior

What you expected to happen.

## Actual Behavior

What actually happened.

## Environment

- OS: [e.g., macOS 12.0, Ubuntu 20.04]
- Go Version: [e.g., 1.22.0]
- CVEWatch Version: [e.g., 2.0.0]

## Configuration

Relevant parts of your config.yaml (remove sensitive information).

## Logs

Relevant log output or error messages.

## Additional Information

Any other context about the problem.
```

## Feature Requests

### Before Requesting

1. **Check existing issues** to see if it's already requested
2. **Search the codebase** to see if it's already implemented
3. **Consider the scope** - is it within the project's goals?

### Feature Request Template

```markdown
## Feature Description

Brief description of the feature you'd like to see.

## Use Case

Describe the problem this feature would solve or the workflow it would improve.

## Proposed Solution

If you have ideas about how to implement this, describe them here.

## Alternatives Considered

Describe any alternative solutions you've considered.

## Additional Context

Any other context, screenshots, or examples.
```

## Questions and Discussion

### Getting Help

- **GitHub Discussions**: For general questions and discussions
- **GitHub Issues**: For bugs and feature requests
- **Pull Requests**: For code-related discussions

### Best Practices

- **Search first** before asking
- **Be specific** about your question
- **Provide context** about your environment
- **Show what you've tried** already
- **Be patient** - maintainers are volunteers

## Recognition

Contributors will be recognized in:

- **README.md** contributors section
- **Release notes** for significant contributions
- **GitHub contributors** page
- **Project documentation**

## Getting Help

If you need help with contributing:

1. **Check the documentation** first
2. **Search existing issues** and discussions
3. **Ask in GitHub Discussions**
4. **Open an issue** if you can't find an answer

## Thank You

Thank you for contributing to CVEWatch! Your contributions help make the project better for everyone.

---

**Note**: These guidelines are living documents and may be updated as the project evolves. Please check back regularly for updates.
