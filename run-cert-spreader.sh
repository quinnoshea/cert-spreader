#!/bin/bash
#
# Certificate Spreader Wrapper Script
# ===================================
#
# This script provides a secure way to run cert-spreader.py with automatic
# secret management. It loads environment variables from secrets.env and
# automatically cleans them up when the script finishes.
#
# WHY USE THIS WRAPPER?
# - Automatically loads secrets from secrets.env file
# - Cleans up environment variables when done (security)
# - Handles errors and interruptions gracefully
# - Provides consistent execution environment
#
# USAGE:
#   ./run-cert-spreader.sh [arguments for cert-spreader.py]
#
# EXAMPLES:
#   ./run-cert-spreader.sh --dry-run
#   ./run-cert-spreader.sh --verbose
#   ./run-cert-spreader.sh --deploy-only --dry-run
#
# PREREQUISITES:
# - secrets.env file must exist (copy from secrets.env.example)
# - cert-spreader.py must be in the same directory
# - Python script dependencies must be installed

# Exit on any error, undefined variables, or pipe failures
set -euo pipefail

# Get the directory where this script is located
# This ensures we can find secrets.env and cert-spreader.py regardless of
# where the script is called from
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_FILE="$SCRIPT_DIR/secrets.env"
PYTHON_SCRIPT="$SCRIPT_DIR/cert-spreader.py"

# Color codes for output (optional, makes output more readable)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Check if required files exist
check_prerequisites() {
    if [[ ! -f "$SECRETS_FILE" ]]; then
        print_status "$RED" "Error: secrets.env file not found at $SECRETS_FILE"
        print_status "$YELLOW" "Please create it by copying secrets.env.example:"
        print_status "$BLUE" "  cp secrets.env.example secrets.env"
        print_status "$BLUE" "  nano secrets.env  # Fill in your actual values"
        exit 1
    fi

    if [[ ! -f "$PYTHON_SCRIPT" ]]; then
        print_status "$RED" "Error: cert-spreader.py not found at $PYTHON_SCRIPT"
        exit 1
    fi

    # Check if secrets.env has been customized (not just the example)
    if grep -q "your-actual-proxmox-api-token-here" "$SECRETS_FILE" 2>/dev/null; then
        print_status "$YELLOW" "Warning: secrets.env appears to contain example values"
        print_status "$YELLOW" "Make sure you've filled in your actual credentials"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Function to cleanup secrets on exit
# This function is called automatically when the script exits,
# even if it's interrupted with Ctrl+C or encounters an error
cleanup_secrets() {
    print_status "$BLUE" "Cleaning up environment variables..."
    
    # List of all environment variables we might have set
    local vars_to_unset=(
        "CERT_SPREADER_PROXMOX_USER"
        "CERT_SPREADER_PROXMOX_TOKEN"
        "CERT_SPREADER_PLEX_PASSWORD"
        "CERT_SPREADER_DOMAIN"
        "CERT_SPREADER_USERNAME"
        "CERT_SPREADER_CERT_DIR"
    )
    
    # Unset each variable (2>/dev/null ignores errors if variable doesn't exist)
    for var in "${vars_to_unset[@]}"; do
        unset "$var" 2>/dev/null || true
    done
    
    print_status "$GREEN" "Environment cleanup complete"
}

# Function to display help information
show_help() {
    cat <<EOF
Certificate Spreader Wrapper Script

USAGE:
    $0 [OPTIONS]

This wrapper script automatically loads secrets from secrets.env and runs
cert-spreader.py with automatic cleanup of environment variables.

OPTIONS:
    All options are passed directly to cert-spreader.py:
    
    --dry-run           Simulate deployment without making changes
    --deploy-only       Deploy certificates but skip service restarts
    --services-only     Skip certificate deployment, only restart services
    --verbose, -v       Enable verbose logging
    --config FILE       Use alternative config file
    --skip-validation   Skip certificate validation checks
    --help             Show cert-spreader.py help

EXAMPLES:
    $0 --dry-run                    # Test run without changes
    $0 --verbose --dry-run          # Test run with detailed output
    $0 --deploy-only               # Deploy certs only
    $0 --config test.yml --dry-run # Use different config file

SETUP:
    1. Copy secrets template: cp secrets.env.example secrets.env
    2. Edit secrets file: nano secrets.env
    3. Make wrapper executable: chmod +x run-cert-spreader.sh
    4. Run: ./run-cert-spreader.sh --dry-run

EOF
}

# Check if help was requested
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    show_help
    exit 0
fi

# Set up cleanup trap
# This ensures cleanup_secrets() runs when the script exits for any reason:
# - Normal completion
# - Error/failure
# - User interruption (Ctrl+C)
# - SIGTERM signal
trap cleanup_secrets EXIT INT TERM

print_status "$BLUE" "Certificate Spreader Wrapper Starting..."

# Check prerequisites
check_prerequisites

print_status "$GREEN" "Loading secrets from $SECRETS_FILE..."

# Source the secrets file to load environment variables
# The 'source' command executes the file in the current shell,
# making the exported variables available to this script and any child processes
source "$SECRETS_FILE"

# Verify that key variables were loaded (optional security check)
if [[ -z "${CERT_SPREADER_PROXMOX_TOKEN:-}" ]]; then
    print_status "$YELLOW" "Warning: CERT_SPREADER_PROXMOX_TOKEN not found in secrets.env"
    print_status "$YELLOW" "Proxmox certificate updates may fail"
fi

print_status "$BLUE" "Running cert-spreader.py with arguments: $*"

# Execute the Python script with all command-line arguments passed through
# "$@" preserves all arguments exactly as they were passed to this script
python3 "$PYTHON_SCRIPT" "$@"

# Check the exit status of the Python script
exit_code=$?

if [[ $exit_code -eq 0 ]]; then
    print_status "$GREEN" "Certificate Spreader completed successfully!"
else
    print_status "$RED" "Certificate Spreader failed with exit code $exit_code"
fi

print_status "$BLUE" "Environment variables will be cleaned up automatically..."

# The cleanup_secrets function will be called automatically due to the trap
# we set up earlier, so we don't need to call it manually here

exit $exit_code