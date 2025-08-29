#!/bin/bash

# CVEWatch Development Setup Script
# This script sets up the development environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Setting up CVEWatch development environment...${NC}"
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}Error: Go is not installed${NC}"
    echo "Please install Go from https://golang.org/dl/"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
echo -e "${GREEN}✓ Go ${GO_VERSION} detected${NC}"

# Check Go version (minimum 1.22)
GO_MAJOR=$(echo "$GO_VERSION" | cut -d. -f1)
GO_MINOR=$(echo "$GO_VERSION" | cut -d. -f2)

if [ "$GO_MAJOR" -lt 1 ] || ([ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 22 ]); then
    echo -e "${RED}Error: Go 1.22 or later is required${NC}"
    echo "Current version: ${GO_VERSION}"
    exit 1
fi

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo -e "${RED}Error: Git is not installed${NC}"
    echo "Please install Git from https://git-scm.com/"
    exit 1
fi

echo -e "${GREEN}✓ Git detected${NC}"

# Check if make is installed
if ! command -v make &> /dev/null; then
    echo -e "${YELLOW}Warning: Make is not installed${NC}"
    echo "Some Makefile targets may not work"
    echo "Install make:"
    echo "  macOS: brew install make"
    echo "  Ubuntu/Debian: sudo apt-get install make"
    echo "  CentOS/RHEL: sudo yum install make"
else
    echo -e "${GREEN}✓ Make detected${NC}"
fi

# Check if golangci-lint is installed
if ! command -v golangci-lint &> /dev/null; then
    echo -e "${YELLOW}Installing golangci-lint...${NC}"
    if command -v curl &> /dev/null; then
        curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.55.2
        echo -e "${GREEN}✓ golangci-lint installed${NC}"
    else
        echo -e "${RED}Error: curl is not installed${NC}"
        echo "Please install curl or install golangci-lint manually"
        echo "Manual installation: https://golangci-lint.run/usage/install/"
    fi
else
    echo -e "${GREEN}✓ golangci-lint detected${NC}"
fi

# Check if govulncheck is installed
if ! command -v govulncheck &> /dev/null; then
    echo -e "${YELLOW}Installing govulncheck...${NC}"
    go install golang.org/x/vuln/cmd/govulncheck@latest
    echo -e "${GREEN}✓ govulncheck installed${NC}"
else
    echo -e "${GREEN}✓ govulncheck detected${NC}"
fi

# Check if go-licenses is installed
if ! command -v go-licenses &> /dev/null; then
    echo -e "${YELLOW}Installing go-licenses...${NC}"
    go install github.com/google/go-licenses@latest
    echo -e "${GREEN}✓ go-licenses installed${NC}"
else
    echo -e "${GREEN}✓ go-licenses detected${NC}"
fi

# Initialize Go modules if not already done
if [ ! -f "go.mod" ]; then
    echo -e "${YELLOW}Initializing Go modules...${NC}"
    go mod init cvewatch
    echo -e "${GREEN}✓ Go modules initialized${NC}"
fi

# Download dependencies
echo -e "${YELLOW}Downloading Go dependencies...${NC}"
go mod download
go mod tidy
echo -e "${GREEN}✓ Dependencies downloaded${NC}"

# Create default configuration if it doesn't exist
if [ ! -f "config.yaml" ]; then
    echo -e "${YELLOW}Creating default configuration...${NC}"
    ./cvewatch init
    echo -e "${GREEN}✓ Default configuration created${NC}"
fi

# Create .gitignore if it doesn't exist
if [ ! -f ".gitignore" ]; then
    echo -e "${YELLOW}Creating .gitignore...${NC}"
    cat > .gitignore << EOF
# Binaries
cvewatch
cvewatch.exe
build/
releases/

# Configuration
config.yaml

# Go
*.exe
*.exe~
*.dll
*.so
*.dylib
*.test
*.out

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Logs
*.log

# Coverage
coverage.out
coverage.html
EOF
    echo -e "${GREEN}✓ .gitignore created${NC}"
fi

# Set up git hooks if .git directory exists
if [ -d ".git" ]; then
    echo -e "${YELLOW}Setting up git hooks...${NC}"
    
    # Create pre-commit hook
    mkdir -p .git/hooks
    cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Pre-commit hook for CVEWatch

echo "Running pre-commit checks..."

# Run go fmt
if ! go fmt ./...; then
    echo "Error: go fmt failed"
    exit 1
fi

# Run go vet
if ! go vet ./...; then
    echo "Error: go vet failed"
    exit 1
fi

# Run tests
if ! go test ./...; then
    echo "Error: tests failed"
    exit 1
fi

echo "Pre-commit checks passed"
EOF
    
    chmod +x .git/hooks/pre-commit
    echo -e "${GREEN}✓ Git hooks configured${NC}"
fi

# Run initial tests
echo -e "${YELLOW}Running initial tests...${NC}"
if go test ./...; then
    echo -e "${GREEN}✓ All tests passed${NC}"
else
    echo -e "${RED}✗ Some tests failed${NC}"
    echo "Please fix the failing tests before proceeding"
fi

echo ""
echo -e "${GREEN}Development environment setup complete!${NC}"
echo ""
echo -e "${BLUE}Available commands:${NC}"
echo "  make build      - Build the application"
echo "  make test       - Run tests"
echo "  make lint       - Run linter"
echo "  make format     - Format code"
echo "  ./cvewatch      - Run the application"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "1. Review the configuration in config.yaml"
echo "2. Add your products to the configuration"
echo "3. Start developing!"
