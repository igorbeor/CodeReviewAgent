#!/bin/bash

# Code Review Agent Setup Script
# This script installs the Code Review Agent in any project

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CURRENT_DIR="$(pwd)"

# Check if we're in the CodeReviewAgent directory
if [ "$SCRIPT_DIR" == "$CURRENT_DIR" ]; then
    print_error "Please run this script from your target project directory"
    echo ""
    echo "Usage:"
    echo "  cd /path/to/your/project"
    echo "  /path/to/CodeReviewAgent/setup.sh"
    echo ""
    exit 1
fi

# Banner
print_header "Code Review Agent Setup"

echo "This script will install the Code Review Agent in:"
echo "  ${BLUE}$CURRENT_DIR${NC}"
echo ""
echo "Source directory:"
echo "  ${BLUE}$SCRIPT_DIR${NC}"
echo ""

# Check if .claude directory already exists
if [ -d ".claude" ]; then
    print_warning ".claude directory already exists"
    read -p "Overwrite existing configuration? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Setup cancelled"
        exit 0
    fi
    rm -rf .claude
    print_success "Removed existing .claude directory"
fi

# Copy .claude directory
print_info "Copying Skills and Subagent configuration..."
cp -r "$SCRIPT_DIR/.claude" .
print_success "Skills installed"

# Check if CLAUDE.md exists in target project
if [ -f ".claude/CLAUDE.md" ]; then
    print_warning "CLAUDE.md already exists in target"
    read -p "Replace with template? (y/N): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ -f "$SCRIPT_DIR/templates/CLAUDE.template.md" ]; then
            cp "$SCRIPT_DIR/templates/CLAUDE.template.md" ".claude/CLAUDE.md"
            print_success "CLAUDE.md replaced with template"
        else
            print_warning "Template not found, keeping existing CLAUDE.md"
        fi
    fi
else
    # Copy template if it exists
    if [ -f "$SCRIPT_DIR/templates/CLAUDE.template.md" ]; then
        cp "$SCRIPT_DIR/templates/CLAUDE.template.md" ".claude/CLAUDE.md"
        print_success "CLAUDE.md template copied"
    else
        print_warning "CLAUDE.template.md not found, you'll need to create CLAUDE.md manually"
    fi
fi

# Detect project type
print_header "Project Detection"

PROJECT_TYPE="unknown"
TECH_STACK=""

# Check for Python
if [ -f "requirements.txt" ] || [ -f "pyproject.toml" ] || [ -f "setup.py" ]; then
    PROJECT_TYPE="python"
    TECH_STACK="Python"
    print_success "Detected: Python project"
fi

# Check for Node.js
if [ -f "package.json" ]; then
    if [ "$PROJECT_TYPE" == "python" ]; then
        PROJECT_TYPE="fullstack"
        TECH_STACK="Python + JavaScript/TypeScript"
    else
        PROJECT_TYPE="javascript"
        TECH_STACK="JavaScript/TypeScript"
    fi
    print_success "Detected: Node.js project"

    # Detect framework
    if grep -q "\"react\"" package.json 2>/dev/null; then
        print_info "Framework: React"
    fi
    if grep -q "\"@angular/core\"" package.json 2>/dev/null; then
        print_info "Framework: Angular"
    fi
    if grep -q "\"vue\"" package.json 2>/dev/null; then
        print_info "Framework: Vue"
    fi
    if grep -q "\"next\"" package.json 2>/dev/null; then
        print_info "Framework: Next.js"
    fi
fi

# Check for Go
if [ -f "go.mod" ]; then
    PROJECT_TYPE="go"
    TECH_STACK="Go"
    print_success "Detected: Go project"
fi

# Check for Ruby
if [ -f "Gemfile" ]; then
    PROJECT_TYPE="ruby"
    TECH_STACK="Ruby"
    print_success "Detected: Ruby project"
fi

if [ "$PROJECT_TYPE" == "unknown" ]; then
    print_warning "Could not detect project type automatically"
fi

# Create .gitignore entry if needed
print_header "Git Configuration"

if [ -f ".gitignore" ]; then
    if ! grep -q "^\.claude/$" .gitignore 2>/dev/null; then
        read -p "Add .claude/ to .gitignore? (Y/n): " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            echo "" >> .gitignore
            echo "# Code Review Agent" >> .gitignore
            echo ".claude/" >> .gitignore
            print_success "Added .claude/ to .gitignore"
        fi
    else
        print_info ".claude/ already in .gitignore"
    fi
fi

# Completion message
print_header "Setup Complete!"

echo "Code Review Agent is now installed in your project!"
echo ""
echo "Next steps:"
echo ""
echo "1. ${YELLOW}Customize CLAUDE.md${NC}"
echo "   Edit .claude/CLAUDE.md to match your project's standards"
echo "   ${BLUE}vim .claude/CLAUDE.md${NC}"
echo ""
echo "2. ${YELLOW}Test the installation${NC}"
echo "   ${BLUE}claude \"Review this file\" path/to/your/file${NC}"
echo ""
echo "3. ${YELLOW}Available Skills:${NC}"
echo "   • code-review       - Code quality and best practices"
echo "   • security-review   - Security vulnerabilities"
echo "   • performance-review - Performance optimization"
echo ""
echo "4. ${YELLOW}Usage examples:${NC}"
echo "   ${BLUE}claude \"Review my latest changes\"${NC}"
echo "   ${BLUE}claude \"Check for security issues in api/\"${NC}"
echo "   ${BLUE}claude \"Find performance problems\"${NC}"
echo ""

if [ "$PROJECT_TYPE" != "unknown" ]; then
    echo "5. ${YELLOW}Project-specific tips for $TECH_STACK:${NC}"

    if [ "$PROJECT_TYPE" == "python" ]; then
        echo "   • Update CLAUDE.md with your Python style guide"
        echo "   • Specify FastAPI/Django/Flask patterns"
        echo "   • Set test coverage requirements"
    elif [ "$PROJECT_TYPE" == "javascript" ]; then
        echo "   • Update CLAUDE.md with your ESLint config"
        echo "   • Specify React/Angular/Vue patterns"
        echo "   • Set bundle size limits"
    elif [ "$PROJECT_TYPE" == "fullstack" ]; then
        echo "   • Update CLAUDE.md for both backend and frontend"
        echo "   • Specify API contracts and validation"
        echo "   • Define performance SLAs"
    fi
    echo ""
fi

echo "Documentation:"
echo "  ${BLUE}$SCRIPT_DIR/docs/README.md${NC}"
echo "  ${BLUE}$SCRIPT_DIR/docs/USAGE.md${NC}"
echo ""

print_success "Happy coding! 🚀"
echo ""
