#!/bin/bash

# CVEWatch Build Script
# This script builds the CVEWatch application for multiple platforms

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Version and build info
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS="-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -s -w"

echo -e "${GREEN}Building CVEWatch ${VERSION}${NC}"
echo -e "${YELLOW}Build time: ${BUILD_TIME}${NC}"
echo ""

# Create build directory
BUILD_DIR="build"
mkdir -p "$BUILD_DIR"

# Build for current platform
echo -e "${GREEN}Building for current platform...${NC}"
go build -ldflags="$LDFLAGS" -o "$BUILD_DIR/cvewatch" ./cmd/cvewatch
echo -e "${GREEN}✓ Built: $BUILD_DIR/cvewatch${NC}"

# Build for multiple platforms
echo ""
echo -e "${GREEN}Building for multiple platforms...${NC}"

# Linux
echo -e "${YELLOW}Building for Linux...${NC}"
GOOS=linux GOARCH=amd64 go build -ldflags="$LDFLAGS" -o "$BUILD_DIR/cvewatch-linux-amd64" ./cmd/cvewatch
GOOS=linux GOARCH=arm64 go build -ldflags="$LDFLAGS" -o "$BUILD_DIR/cvewatch-linux-arm64" ./cmd/cvewatch
echo -e "${GREEN}✓ Built: $BUILD_DIR/cvewatch-linux-amd64${NC}"
echo -e "${GREEN}✓ Built: $BUILD_DIR/cvewatch-linux-arm64${NC}"

# macOS
echo -e "${YELLOW}Building for macOS...${NC}"
GOOS=darwin GOARCH=amd64 go build -ldflags="$LDFLAGS" -o "$BUILD_DIR/cvewatch-darwin-amd64" ./cmd/cvewatch
GOOS=darwin GOARCH=arm64 go build -ldflags="$LDFLAGS" -o "$BUILD_DIR/cvewatch-darwin-arm64" ./cmd/cvewatch
echo -e "${GREEN}✓ Built: $BUILD_DIR/cvewatch-darwin-amd64${NC}"
echo -e "${GREEN}✓ Built: $BUILD_DIR/cvewatch-darwin-arm64${NC}"

# Windows
echo -e "${YELLOW}Building for Windows...${NC}"
GOOS=windows GOARCH=amd64 go build -ldflags="$LDFLAGS" -o "$BUILD_DIR/cvewatch-windows-amd64.exe" ./cmd/cvewatch
GOOS=windows GOARCH=arm64 go build -ldflags="$LDFLAGS" -o "$BUILD_DIR/cvewatch-windows-arm64.exe" ./cmd/cvewatch
echo -e "${GREEN}✓ Built: $BUILD_DIR/cvewatch-windows-amd64.exe${NC}"
echo -e "${GREEN}✓ Built: $BUILD_DIR/cvewatch-windows-arm64.exe${NC}"

echo ""
echo -e "${GREEN}Build completed successfully!${NC}"
echo -e "${YELLOW}Build artifacts are in the '$BUILD_DIR' directory${NC}"

# List all built files
echo ""
echo -e "${GREEN}Build artifacts:${NC}"
ls -la "$BUILD_DIR"/
