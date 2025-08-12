#!/bin/bash
set -euo pipefail

echo "Certificate Spreader - Testing Arrays & Parameter Expansion"
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

# Simple function with parameter expansion
usage() {
    echo "Usage: $0 [options]"
    echo "Config: ${CONFIG_FILE:-config.conf}"
    exit 0
}

# Function with array usage
test_array() {
    local test_array=("item1" "item2" "item3")
    echo "Array length: ${#test_array[@]}"
    for item in "${test_array[@]}"; do
        echo "Item: $item"
    done
}

# Simple conditional
if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    usage
fi

# Test array function
test_array

echo "Arrays and parameter expansion test completed"
exit 0
