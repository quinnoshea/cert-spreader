#!/bin/bash
set -euo pipefail

echo "Certificate Spreader - Testing Complex Conditionals & Regex"
echo "Arguments: $*"

# Basic variables
CONFIG_FILE="config.conf"
DRY_RUN=false

# Arrays
declare -ag HOST_SERVICES=()
HOSTS="server1 server2 server3"

# Parameter expansion
SSH_OPTS="${SSH_OPTS:--o ConnectTimeout=10}"
LOG_FILE="${LOG_FILE:-/var/log/cert-spreader.log}"

# Function with complex conditionals
validate_input() {
    local input="$1"

    # Nested if statements
    if [[ -n "$input" ]]; then
        if [[ "$input" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            echo "Valid domain format: $input"
            return 0
        else
            echo "Invalid domain format: $input"
            return 1
        fi
    else
        echo "Empty input"
        return 1
    fi
}

# Case statement
parse_argument() {
    local arg="$1"
    case "$arg" in
        --dry-run)
            DRY_RUN=true
            echo "Dry run mode enabled"
            ;;
        --help|-h)
            usage
            ;;
        *.conf)
            CONFIG_FILE="$arg"
            echo "Config file: $CONFIG_FILE"
            ;;
        *)
            echo "Unknown argument: $arg"
            return 1
            ;;
    esac
}

# While loop with complex condition
test_while() {
    local counter=0
    while [[ $counter -lt 3 ]]; do
        echo "Counter: $counter"
        counter=$((counter + 1))
    done
}

# Function with regex and parameter validation
check_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]]; then
        if [[ $port -gt 0 ]] && [[ $port -lt 65536 ]]; then
            echo "Valid port: $port"
            return 0
        fi
    fi
    echo "Invalid port: $port"
    return 1
}

usage() {
    echo "Usage: $0 [options]"
    echo "Config: ${CONFIG_FILE:-config.conf}"
    exit 0
}

# Test complex conditionals
if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    usage
fi

# Test regex validation
validate_input "example.com"
validate_input "invalid_domain"

# Test case statement
parse_argument "--dry-run"

# Test while loop
test_while

# Test port validation
check_port "22"
check_port "invalid"

echo "Complex conditionals and regex test completed"
exit 0
