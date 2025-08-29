#!/bin/bash

# CVEWatch Changelog Generator
# This script generates a changelog based on git commits

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -v, --version VERSION    Specify version for changelog"
    echo "  -o, --output FILE        Output file (default: CHANGELOG.md)"
    echo "  -p, --previous TAG       Previous tag to compare against"
    echo "  -f, --format FORMAT      Output format: markdown, json, yaml (default: markdown)"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -v v2.1.0                    # Generate changelog for v2.1.0"
    echo "  $0 -v v2.1.0 -p v2.0.0         # Generate changelog from v2.0.0 to v2.1.0"
    echo "  $0 -v v2.1.0 -o RELEASE_NOTES.md # Output to specific file"
}

# Default values
VERSION=""
OUTPUT_FILE="CHANGELOG.md"
PREVIOUS_TAG=""
FORMAT="markdown"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -p|--previous)
            PREVIOUS_TAG="$2"
            shift 2
            ;;
        -f|--format)
            FORMAT="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Check if version is provided
if [[ -z "$VERSION" ]]; then
    print_error "Version is required. Use -v or --version option."
    show_usage
    exit 1
fi

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    print_error "Not in a git repository"
    exit 1
fi

print_status "Generating changelog for version $VERSION"

# Get commit range
if [[ -n "$PREVIOUS_TAG" ]]; then
    print_status "Comparing commits from $PREVIOUS_TAG to HEAD"
    COMMIT_RANGE="$PREVIOUS_TAG..HEAD"
else
    # Try to find the previous tag automatically
    PREVIOUS_TAG=$(git describe --tags --abbrev=0 HEAD~1 2>/dev/null || echo "")
    if [[ -n "$PREVIOUS_TAG" ]]; then
        print_status "Found previous tag: $PREVIOUS_TAG"
        COMMIT_RANGE="$PREVIOUS_TAG..HEAD"
    else
        print_warning "No previous tag found, using all commits"
        COMMIT_RANGE=""
    fi
fi

# Get commits
if [[ -n "$COMMIT_RANGE" ]]; then
    COMMITS=$(git log --pretty=format:"%H|%s|%an|%ad" --date=short --no-merges $COMMIT_RANGE)
else
    COMMITS=$(git log --pretty=format:"%H|%s|%an|%ad" --date=short --no-merges)
fi

# Categorize commits
FEATURES=""
FIXES=""
BREAKING=""
DOCS=""
CHORES=""
PERF=""
TEST=""
REFACTOR=""
STYLE=""

print_status "Categorizing commits..."

while IFS='|' read -r hash subject author date; do
    # Skip empty lines
    [[ -z "$hash" ]] && continue
    
    # Categorize based on subject
    if [[ "$subject" =~ ^feat ]]; then
        FEATURES+="- $subject ($hash) - $author, $date"$'\n'
    elif [[ "$subject" =~ ^fix ]]; then
        FIXES+="- $subject ($hash) - $author, $date"$'\n'
    elif [[ "$subject" =~ ^breaking ]]; then
        BREAKING+="- $subject ($hash) - $author, $date"$'\n'
    elif [[ "$subject" =~ ^docs ]]; then
        DOCS+="- $subject ($hash) - $author, $date"$'\n'
    elif [[ "$subject" =~ ^chore ]]; then
        CHORES+="- $subject ($hash) - $author, $date"$'\n'
    elif [[ "$subject" =~ ^perf ]]; then
        PERF+="- $subject ($hash) - $author, $date"$'\n'
    elif [[ "$subject" =~ ^test ]]; then
        TEST+="- $subject ($hash) - $author, $date"$'\n'
    elif [[ "$subject" =~ ^refactor ]]; then
        REFACTOR+="- $subject ($hash) - $author, $date"$'\n'
    elif [[ "$subject" =~ ^style ]]; then
        STYLE+="- $subject ($hash) - $author, $date"$'\n'
    else
        # Default to features for unrecognized types
        FEATURES+="- $subject ($hash) - $author, $date"$'\n'
    fi
done <<< "$COMMITS"

# Generate changelog content
print_status "Generating changelog content..."

CHANGELOG_CONTENT=""

# Add version header
CHANGELOG_CONTENT+="# Changelog"$'\n'$'\n'
CHANGELOG_CONTENT+="## [$VERSION] - $(date '+%Y-%m-%d')"$'\n'$'\n'

# Add categorized sections
if [[ -n "$FEATURES" ]]; then
    CHANGELOG_CONTENT+="## ✨ New Features"$'\n'
    CHANGELOG_CONTENT+="$FEATURES"$'\n'
fi

if [[ -n "$FIXES" ]]; then
    CHANGELOG_CONTENT+="## 🐛 Bug Fixes"$'\n'
    CHANGELOG_CONTENT+="$FIXES"$'\n'
fi

if [[ -n "$BREAKING" ]]; then
    CHANGELOG_CONTENT+="## ⚠️ Breaking Changes"$'\n'
    CHANGELOG_CONTENT+="$BREAKING"$'\n'
fi

if [[ -n "$PERF" ]]; then
    CHANGELOG_CONTENT+="## 🚀 Performance Improvements"$'\n'
    CHANGELOG_CONTENT+="$PERF"$'\n'
fi

if [[ -n "$REFACTOR" ]]; then
    CHANGELOG_CONTENT+="## 🔧 Refactoring"$'\n'
    CHANGELOG_CONTENT+="$REFACTOR"$'\n'
fi

if [[ -n "$TEST" ]]; then
    CHANGELOG_CONTENT+="## 🧪 Testing"$'\n'
    CHANGELOG_CONTENT+="$TEST"$'\n'
fi

if [[ -n "$DOCS" ]]; then
    CHANGELOG_CONTENT+="## 📚 Documentation"$'\n'
    CHANGELOG_CONTENT+="$DOCS"$'\n'
fi

if [[ -n "$STYLE" ]]; then
    CHANGELOG_CONTENT+="## 💅 Code Style"$'\n'
    CHANGELOG_CONTENT+="$STYLE"$'\n'
fi

if [[ -n "$CHORES" ]]; then
    CHANGELOG_CONTENT+="## 🛠️ Maintenance"$'\n'
    CHANGELOG_CONTENT+="$CHORES"$'\n'
fi

# Add full changelog section
CHANGELOG_CONTENT+="## 📋 Full Changelog"$'\n'$'\n'

# Get full commit list
if [[ -n "$COMMIT_RANGE" ]]; then
    FULL_COMMITS=$(git log --pretty=format:"- %s (%h) - %an, %ad" --date=short --no-merges $COMMIT_RANGE)
else
    FULL_COMMITS=$(git log --pretty=format:"- %s (%h) - %an, %ad" --date=short --no-merges)
fi

CHANGELOG_CONTENT+="$FULL_COMMITS"$'\n'

# Output based on format
case "$FORMAT" in
    markdown)
        echo "$CHANGELOG_CONTENT" > "$OUTPUT_FILE"
        print_success "Changelog written to $OUTPUT_FILE"
        ;;
    json)
        # Convert to JSON format
        JSON_CONTENT=$(echo "$CHANGELOG_CONTENT" | python3 -c "
import sys, json
content = sys.stdin.read()
lines = content.strip().split('\n')
sections = {}
current_section = ''
current_content = []

for line in lines:
    if line.startswith('## '):
        if current_section and current_content:
            sections[current_section] = current_content
        current_section = line[3:].strip()
        current_content = []
    elif line.startswith('- ') and current_section:
        current_content.append(line[2:].strip())
    elif line.strip() and not line.startswith('#') and current_section:
        current_content.append(line.strip())

if current_section and current_content:
    sections[current_section] = current_content

print(json.dumps({'version': '$VERSION', 'date': '$(date '+%Y-%m-%d')', 'sections': sections}, indent=2))
" 2>/dev/null || echo "{}")
        echo "$JSON_CONTENT" > "$OUTPUT_FILE"
        print_success "JSON changelog written to $OUTPUT_FILE"
        ;;
    yaml)
        # Convert to YAML format
        YAML_CONTENT=$(echo "$CHANGELOG_CONTENT" | python3 -c "
import sys, yaml
content = sys.stdin.read()
lines = content.strip().split('\n')
sections = {}
current_section = ''
current_content = []

for line in lines:
    if line.startswith('## '):
        if current_section and current_content:
            sections[current_section] = current_content
        current_section = line[3:].strip()
        current_content = []
    elif line.startswith('- ') and current_section:
        current_content.append(line[2:].strip())
    elif line.strip() and not line.startswith('#') and current_section:
        current_content.append(line.strip())

if current_section and current_content:
    sections[current_section] = current_content

print(yaml.dump({'version': '$VERSION', 'date': '$(date '+%Y-%m-%d')', 'sections': sections}, default_flow_style=False))
" 2>/dev/null || echo "version: $VERSION")
        echo "$YAML_CONTENT" > "$OUTPUT_FILE"
        print_success "YAML changelog written to $OUTPUT_FILE"
        ;;
    *)
        print_error "Unsupported format: $FORMAT"
        exit 1
        ;;
esac

print_status "Changelog generation complete!"
print_status "Output file: $OUTPUT_FILE"
print_status "Format: $FORMAT"
print_status "Version: $VERSION"
if [[ -n "$PREVIOUS_TAG" ]]; then
    print_status "Previous tag: $PREVIOUS_TAG"
fi
