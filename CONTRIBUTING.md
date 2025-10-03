# Contributing to CVEWatch

Thank you for considering contributing to CVEWatch! We welcome contributions from the community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code. Please be respectful and constructive in all interactions.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
3. Create a new branch for your feature or bug fix
4. Make your changes
5. Test your changes thoroughly
6. Submit a pull request

## Development Setup

### Prerequisites

- Go 1.25 or later
- Make
- Git

### Setup Steps

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/CVEWatch.git
cd CVEWatch

# Add upstream remote
git remote add upstream https://github.com/Amet13/CVEWatch.git

# Install development dependencies
make dev-setup

# Verify everything works
make test
make build
```

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected behavior** vs **actual behavior**
- **Version information** (`cvewatch version`)
- **Environment details** (OS, Go version)
- **Logs or error messages** if applicable

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:

- **Clear description** of the enhancement
- **Use cases** and why it would be useful
- **Examples** of how it would work
- **Possible implementation** details (optional)

### Code Contributions

1. **Pick an issue** or create one to discuss your proposed changes
2. **Create a branch** with a descriptive name:
   - `feature/add-xxx` for new features
   - `fix/issue-123` for bug fixes
   - `docs/update-readme` for documentation
3. **Write code** following our style guidelines
4. **Add tests** for new functionality
5. **Update documentation** if needed
6. **Run quality checks** (`make pre-commit`)
7. **Submit a pull request**

## Code Style Guidelines

### Go Code Style

- Follow standard Go conventions and idioms
- Use `gofmt` and `goimports` for formatting
- Write clear, self-documenting code
- Add comments for exported functions and complex logic
- Keep functions small and focused
- Prefer descriptive names over comments

### Commit Message Guidelines

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `perf`: Performance improvements
- `ci`: CI/CD changes
- `sec`: Security fixes

**Examples:**

```
feat(search): add support for date range queries

Implement date range filtering to allow users to search CVEs
across multiple days instead of a single date.

Closes #42
```

```
fix(validation): support modern CVE ID formats

Update CVE ID validation to accept IDs with more than 5 digits,
as modern CVE identifiers can have 6+ digits.

Fixes #123
```

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run tests with race detection
make test-race

# Run tests with coverage
make test-coverage

# View coverage report
open coverage.html
```

### Writing Tests

- Write unit tests for all new functionality
- Aim for >80% code coverage
- Use table-driven tests when appropriate
- Mock external dependencies
- Test error cases and edge cases

Example test structure:

```go
func TestFunctionName(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
        wantErr  bool
    }{
        {"valid input", "input1", "output1", false},
        {"invalid input", "bad", "", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := FunctionName(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("unexpected error: %v", err)
            }
            if result != tt.expected {
                t.Errorf("got %v, want %v", result, tt.expected)
            }
        })
    }
}
```

## Pull Request Process

1. **Update documentation** for any user-facing changes
2. **Update CHANGELOG** if applicable
3. **Ensure all tests pass** (`make test`)
4. **Run linters** (`make lint`)
5. **Run security scan** (`make security-scan`)
6. **Keep PR focused** - one feature/fix per PR
7. **Provide clear description** of changes
8. **Link related issues** using keywords (Fixes #123)
9. **Be responsive** to review feedback
10. **Squash commits** before merging if requested

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] All tests pass locally
- [ ] No new linter warnings
- [ ] Commit messages follow conventions
- [ ] PR description is clear and complete

## Code Review Process

- All submissions require review by maintainers
- We aim to review PRs within 3-5 business days
- Address review feedback promptly
- Expect 1-2 rounds of review for most PRs
- Be patient and respectful during review

## Development Workflow

### Before Starting

1. Sync your fork with upstream:

```bash
git fetch upstream
git checkout main
git merge upstream/main
```

2. Create a feature branch:

```bash
git checkout -b feature/my-feature
```

### During Development

1. Make small, logical commits
2. Run tests frequently: `make test`
3. Run linters: `make lint`
4. Keep your branch updated with main

### Before Submitting PR

1. Run full pre-commit checks:

```bash
make pre-commit
```

2. Ensure your branch is up to date:

```bash
git fetch upstream
git rebase upstream/main
```

3. Push to your fork:

```bash
git push origin feature/my-feature
```

## Performance Considerations

- Profile code for performance-critical paths
- Use benchmarks for performance-sensitive code:

```bash
go test -bench=. -benchmem ./...
```

- Consider memory allocations and garbage collection
- Test with realistic data volumes

## Security

- Never commit sensitive data (API keys, passwords, etc.)
- Report security vulnerabilities privately (see SECURITY.md)
- Follow secure coding practices
- Run security scans: `make security-scan`

## Questions?

- Open an issue for general questions
- Tag maintainers in discussions
- Join community discussions

## License

By contributing to CVEWatch, you agree that your contributions will be licensed under the MIT License.

## Recognition

Contributors will be recognized in:

- Release notes
- GitHub contributors list
- README acknowledgments (for significant contributions)

Thank you for contributing to CVEWatch! 🎉
