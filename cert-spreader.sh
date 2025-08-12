#!/bin/bash
set -euo pipefail

echo "Certificate Spreader - Testing Version"
echo "Arguments: $*"

# Basic variables
CONFIG_FILE="config.conf"
DRY_RUN=false

# Simple function
usage() {
    echo "Usage: $0 [options]"
    exit 0
}

# Simple conditional
if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    usage
fi

echo "Basic test completed"
exit 0
