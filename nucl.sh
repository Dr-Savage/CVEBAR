#!/bin/bash
set -e

# Configuration with hardcoded repository details
CACHE_DIR="$HOME/.nuclei-cli"
DB_FILE="$CACHE_DIR/db.json"
VERSION_FILE="$CACHE_DIR/version"
REPO_OWNER="projectdiscovery"
REPO_NAME="nuclei-templates"
FULL_REPO="$REPO_OWNER/$REPO_NAME"
BASE_URL="https://api.github.com/repos/$FULL_REPO"
STROBES_API="https://intel.strobes.co/api/vulnerabilities"

# Check dependencies
check_deps() {
    for cmd in curl jq; do
        if ! command -v $cmd &> /dev/null; then
            echo "Error: $cmd not found. Please install it first."
            exit 1
        fi
    done
}

# Initialize environment
init() {
    mkdir -p "$CACHE_DIR"
    check_version
}

# Check database version
check_version() {
    echo "Checking version..."
    remote_version=$(curl -sf "https://raw.githubusercontent.com/$FULL_REPO/main/README.md" | sha256sum | cut -d' ' -f1)
    
    if [ ! -f "$DB_FILE" ] || [ "$(cat "$VERSION_FILE" 2>/dev/null)" != "$remote_version" ]; then
        echo "Updating database..."
        response=$(curl -sf "$BASE_URL/git/trees/main?recursive=1")
        
        if [ -z "$response" ]; then
            echo "Error: Failed to fetch GitHub API response"
            exit 1
        fi
        
        echo "$response" | jq '.tree' > "$DB_FILE"
        echo "$remote_version" > "$VERSION_FILE"
    fi
}

# Search templates with hardcoded repository URL
search_templates() {
    local pattern="$1"
    echo "Searching templates for: $pattern"
    
    if [ ! -s "$DB_FILE" ]; then
        echo "Error: Database file missing or empty"
        return
    fi
    
    jq -r --arg pattern "$pattern" '
        .[] | 
        select(.path | test($pattern; "i")) | 
        "  Template: https://github.com/projectdiscovery/nuclei-templates/blob/main/\(.path)"
    ' "$DB_FILE"
}

# Search exploit references from Strobes
search_exploits() {
    local cve="$1"
    echo "Searching exploits for: $cve"
    
    response=$(curl -sf "$STROBES_API/$cve")
    
    if [ -z "$response" ]; then
        echo "  No exploit references found"
        return
    fi
    
    echo "$response" | jq '.exploits.references[] | select(.type == "EXPLOIT_REF") | "  Exploit: \(.source) | \(.type) | \(.url)"'
}

# Combined CVE analysis
cve_analysis() {
    read -p "Enter CVEs separated by spaces: " input
    
    for cve in $input; do
        echo -e "\n=== Analysis for $cve ==="
        search_exploits "$cve"
        search_templates "$cve"
    done
}

# Main interface
main() {
    check_deps
    init
    
    echo -e "\nNuclei CLI Assistant - Type 'help' for options, 'exit' to quit"
    
    while true; do
        read -p "> " cmd args
        
        case $cmd in
            cve)
                if [ -z "$args" ]; then
                    cve_analysis
                else
                    for cve in $args; do
                        echo -e "\n=== Analysis for $cve ==="
                        search_exploits "$cve"
                        search_templates "$cve"
                    done
                fi
                ;;
            templates)
                if [ -z "$args" ]; then
                    read -p "Enter template search pattern: " pattern
                    search_templates "$pattern"
                else
                    search_templates "$args"
                fi
                ;;
            issues)
                if [ -z "$args" ]; then
                    read -p "Enter GitHub issues query: " query
                else
                    query="$args"
                fi
                echo -e "\nGitHub Issues:"
                curl -sf "$BASE_URL/issues?q=$query" | jq -r '.[] | "#\(.number) - \(.title) [\(.state)] - \(.html_url)"' || echo "  No issues found"
                ;;
            help|options)
                echo -e "\nAvailable commands:"
                echo "  cve         - Analyze CVEs (e.g., cve CVE-2014-0160 CVE-2021-44228)"
                echo "  templates   - Search templates by pattern (e.g., templates xss)"
                echo "  issues      - Search GitHub issues (e.g., issues 'SSL verification')"
                echo "  help        - Show this help message"
                echo "  exit/quit   - Exit the program"
                ;;
            exit|quit)
                echo "Exiting..."
                exit 0
                ;;
            *)
                echo "Unknown command: $cmd"
                ;;
        esac
    done
}

main "$@"
