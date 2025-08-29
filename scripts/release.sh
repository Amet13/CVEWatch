#!/bin/bash

# CVEWatch Release Script
# This script creates a new release with proper tagging and artifacts

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo -e "${RED}Error: Not in a git repository${NC}"
    exit 1
fi

# Check if working directory is clean
if ! git diff-index --quiet HEAD --; then
    echo -e "${RED}Error: Working directory is not clean. Please commit or stash your changes.${NC}"
    exit 1
fi

# Get current version from git tags
CURRENT_VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
echo -e "${GREEN}Current version: ${CURRENT_VERSION}${NC}"

# Prompt for new version
echo -e "${YELLOW}Enter new version (e.g., v2.1.0):${NC}"
read -r NEW_VERSION

# Validate version format
if [[ ! $NEW_VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "${RED}Error: Invalid version format. Use format vX.Y.Z${NC}"
    exit 1
fi

# Check if version already exists
if git tag -l | grep -q "^${NEW_VERSION}$"; then
    echo -e "${RED}Error: Version ${NEW_VERSION} already exists${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}Creating release ${NEW_VERSION}...${NC}"

# Update version in go.mod if it exists
if [ -f "go.mod" ]; then
    echo -e "${YELLOW}Updating go.mod version...${NC}"
    # Note: go.mod version is typically managed by go mod edit
    echo "Version will be updated in go.mod during build"
fi

# Build the application
echo -e "${YELLOW}Building application...${NC}"
./scripts/build.sh

# Create release directory
RELEASE_DIR="releases/${NEW_VERSION}"
mkdir -p "$RELEASE_DIR"

# Copy build artifacts
echo -e "${YELLOW}Copying build artifacts...${NC}"
cp build/* "$RELEASE_DIR/"

# Create release notes
echo -e "${YELLOW}Creating release notes...${NC}"
cat > "$RELEASE_DIR/RELEASE_NOTES.md" << EOF
# CVEWatch ${NEW_VERSION}

## Release Date
$(date -u '+%Y-%m-%d')

## Changes
- [List your changes here]

## Installation
Download the appropriate binary for your platform from this release.

## Checksums
EOF

# Generate checksums
echo -e "${YELLOW}Generating checksums...${NC}"
cd "$RELEASE_DIR"
for file in cvewatch*; do
    if [ -f "$file" ]; then
        sha256sum "$file" >> RELEASE_NOTES.md
    fi
done
cd - > /dev/null

# Create zip archive
echo -e "${YELLOW}Creating release archive...${NC}"
cd releases
zip -r "cvewatch-${NEW_VERSION}.zip" "$NEW_VERSION"
cd - > /dev/null

# Commit changes
echo -e "${YELLOW}Committing changes...${NC}"
git add .
git commit -m "Release ${NEW_VERSION}"

# Create tag
echo -e "${YELLOW}Creating git tag...${NC}"
git tag -a "$NEW_VERSION" -m "Release ${NEW_VERSION}"

# Push changes and tag
echo -e "${YELLOW}Pushing to remote...${NC}"
git push origin main
git push origin "$NEW_VERSION"

echo ""
echo -e "${GREEN}Release ${NEW_VERSION} created successfully!${NC}"
echo -e "${YELLOW}Release artifacts are in: ${RELEASE_DIR}${NC}"
echo -e "${YELLOW}Release archive: releases/cvewatch-${NEW_VERSION}.zip${NC}"
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "1. Review the release notes in ${RELEASE_DIR}/RELEASE_NOTES.md"
echo "2. Update the release notes with actual changes"
echo "3. Create a GitHub release with the tag ${NEW_VERSION}"
echo "4. Upload the release archive to GitHub"
