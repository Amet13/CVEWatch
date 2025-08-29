#!/bin/bash

# CVEWatch Cleanup Script
# This script cleans up build artifacts and temporary files

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Cleaning up CVEWatch project...${NC}"
echo ""

# Function to safely remove directory
safe_remove_dir() {
    local dir="$1"
    if [ -d "$dir" ]; then
        echo -e "${YELLOW}Removing directory: $dir${NC}"
        rm -rf "$dir"
        echo -e "${GREEN}✓ Removed: $dir${NC}"
    else
        echo -e "${YELLOW}Directory not found: $dir${NC}"
    fi
}

# Function to safely remove file
safe_remove_file() {
    local file="$1"
    if [ -f "$file" ]; then
        echo -e "${YELLOW}Removing file: $file${NC}"
        rm -f "$file"
        echo -e "${GREEN}✓ Removed: $file${NC}"
    else
        echo -e "${YELLOW}File not found: $file${NC}"
    fi
}

# Remove build artifacts
echo -e "${BLUE}Cleaning build artifacts...${NC}"
safe_remove_dir "build"
safe_remove_dir "releases"

# Remove Go build cache
echo -e "${BLUE}Cleaning Go build cache...${NC}"
if command -v go &> /dev/null; then
    go clean -cache
    go clean -modcache
    echo -e "${GREEN}✓ Go cache cleaned${NC}"
else
    echo -e "${YELLOW}Go not found, skipping cache cleanup${NC}"
fi

# Remove test artifacts
echo -e "${BLUE}Cleaning test artifacts...${NC}"
safe_remove_file "coverage.out"
safe_remove_file "coverage.html"
safe_remove_file "*.test"
safe_remove_file "*.out"

# Remove temporary files
echo -e "${BLUE}Cleaning temporary files...${NC}"
find . -name "*.tmp" -type f -delete 2>/dev/null || true
find . -name "*.temp" -type f -delete 2>/dev/null || true
find . -name "*~" -type f -delete 2>/dev/null || true
find . -name ".#*" -type f -delete 2>/dev/null || true

# Remove OS-specific files
echo -e "${BLUE}Cleaning OS-specific files...${NC}"
find . -name ".DS_Store" -type f -delete 2>/dev/null || true
find . -name "Thumbs.db" -type f -delete 2>/dev/null || true
find . -name "ehthumbs.db" -type f -delete 2>/dev/null || true

# Remove IDE files
echo -e "${BLUE}Cleaning IDE files...${NC}"
safe_remove_dir ".vscode"
safe_remove_dir ".idea"
safe_remove_dir "*.swp"
safe_remove_dir "*.swo"

# Remove old Python files if they exist
echo -e "${BLUE}Cleaning old Python files...${NC}"
find . -name "*.py" -type f -delete 2>/dev/null || true
find . -name "*.pyc" -type f -delete 2>/dev/null || true
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
safe_remove_file "requirements.txt"
safe_remove_file "Pipfile"
safe_remove_file "Pipfile.lock"

# Remove old configuration files
echo -e "${BLUE}Cleaning old configuration files...${NC}"
safe_remove_file "products.txt"
safe_remove_file "config.ini"
safe_remove_file ".env"

# Remove old documentation
echo -e "${BLUE}Cleaning old documentation...${NC}"
safe_remove_file "README_GO.md"
safe_remove_file "README_PYTHON.md"

# Remove old images
echo -e "${BLUE}Cleaning old images...${NC}"
find . -name "*.png" -type f -delete 2>/dev/null || true
find . -name "*.jpg" -type f -delete 2>/dev/null || true
find . -name "*.jpeg" -type f -delete 2>/dev/null || true
find . -name "*.gif" -type f -delete 2>/dev/null || true
find . -name "*.svg" -type f -delete 2>/dev/null || true

# Remove old scripts
echo -e "${BLUE}Cleaning old scripts...${NC}"
find . -name "*.py" -type f -delete 2>/dev/null || true
find . -name "*.sh" -type f -not -path "./scripts/*" -delete 2>/dev/null || true

# Remove empty directories
echo -e "${BLUE}Removing empty directories...${NC}"
find . -type d -empty -delete 2>/dev/null || true

# Clean up git if available
if [ -d ".git" ]; then
    echo -e "${BLUE}Cleaning git...${NC}"
    git gc --aggressive --prune=now 2>/dev/null || true
    echo -e "${GREEN}✓ Git cleaned${NC}"
fi

echo ""
echo -e "${GREEN}Cleanup completed successfully!${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "1. Run 'make build' to rebuild the project"
echo "2. Run 'make test' to verify everything works"
echo "3. Run './scripts/dev-setup.sh' to set up development environment"
