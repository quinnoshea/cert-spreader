#!/bin/bash
# SHEBANG: This line tells the system to use bash to interpret this script
# It must be the very first line of the script

# SET OPTIONS: Configure bash behavior for safer script execution
set -euo pipefail
# -e: Exit immediately if any command fails (non-zero exit code)
# -u: Treat unset variables as errors (prevents typos in variable names)
# -o pipefail: Make pipelines fail if any command in the pipeline fails

# STARTUP INFO: Show what arguments were passed to the script
# $@ represents all command line arguments passed to the script
echo "Starting cert-spreader with arguments: $@"

# SCRIPT DESCRIPTION:
# Certificate Spreader - Simplified Version with Configuration File
# Purpose: Deploy Let's Encrypt certificates to multiple hosts after renewal
# This script automates the process of distributing SSL certificates to various servers

# VARIABLE DECLARATIONS:
# In bash, variables are created simply by assigning values
# No need to declare type - bash treats everything as strings by default

# Default configuration file path
# This will be used if no config file is specified on command line
CONFIG_FILE="config.conf"

# STANDARDIZED ERROR CODES
readonly ERR_SUCCESS=0          # Success
readonly ERR_CONFIG=1           # Configuration error
readonly ERR_CERT=2             # Certificate error
readonly ERR_NETWORK=3          # Network/connectivity error
readonly ERR_PERMISSION=4       # Permission error
readonly ERR_VALIDATION=5       # Validation error
readonly ERR_USAGE=6            # Usage/argument error

# COMMAND LINE FLAGS:
# These boolean flags control script behavior
# In bash, we use true/false strings to represent boolean values
DRY_RUN=false          # Show what would be done without making changes
CERT_ONLY=false        # Only deploy certificates, skip service restarts
SERVICES_ONLY=false    # Only restart services, skip certificate deployment
PROXMOX_ONLY=false     # Only update Proxmox certificates
PERMISSIONS_FIX=false  # Only fix certificate file permissions

# GLOBAL ARRAYS:
# Arrays in bash are declared with 'declare' command
# -a means it's an indexed array (as opposed to associative array with -A)
# -g makes it global (accessible from functions)
# () creates an empty array
declare -ag HOST_SERVICES=()   # Array to store host:port:services configurations
declare -ag PROXMOX_NODES=()   # Array to store Proxmox node names
declare -ag DEPLOYED_HOSTS=()  # Array to track hosts where certificates were actually deployed
LOCAL_CERT_CHANGED=false       # Track if local certificates changed

# USAGE FUNCTION:
# Functions in bash are defined with: function_name() { commands; }
# This function displays help text when user asks for help or makes an error
usage() {
    # HERE DOCUMENT (heredoc): A way to output multiple lines of text
    # << EOF means "read lines until you see 'EOF' on its own line"
    # The text between << EOF and EOF is treated as input to the 'cat' command
    cat << EOF
Usage: $0 [config-file] [options]

Options:
    --dry-run        Show what would be done without making changes
    --cert-only      Only deploy certificates, skip service restarts
    --services-only  Only restart services, skip certificate deployment
    --proxmox-only   Only update Proxmox certificates, skip everything else
    --permissions-fix Only fix certificate file permissions, skip everything else
    --help          Show this help message

If no config file is specified, 'config.conf' will be used

Examples:
    $0                          # Use config.conf, deploy certs and restart services
    $0 --dry-run               # Show what would be done
    $0 --cert-only             # Deploy certificates only
    $0 --services-only         # Restart services only
    $0 --proxmox-only          # Update Proxmox certificates only
    $0 --permissions-fix       # Fix certificate permissions only
    $0 custom.conf --dry-run   # Use custom config in dry-run mode
EOF
    exit $ERR_SUCCESS
}

# ARGUMENT PARSING FUNCTION:
# This function processes command line arguments passed to the script
# It demonstrates several important bash concepts:
# - Function parameters: $1, $2, etc. are positional parameters
# - $# is the number of arguments
# - $@ is all arguments as separate words
# - while loops and case statements for processing options
parse_args() {
    
    # WHILE LOOP: Continue processing while there are arguments left
    # [[ $# -gt 0 ]] means "while number of arguments is greater than 0"
    # [[ ]] is bash's improved test command (better than [ ])
    while [[ $# -gt 0 ]]; do
        
        # CASE STATEMENT: Like switch/case in other languages
        # Each pattern is checked against $1 (current argument)
        case $1 in
            --dry-run)
                # Set the DRY_RUN flag to true
                DRY_RUN=true
                shift  # Remove this argument from the list (move to next)
                ;;
            --cert-only)
                CERT_ONLY=true
                shift
                ;;
            --services-only)
                SERVICES_ONLY=true
                shift
                ;;
            --proxmox-only)
                PROXMOX_ONLY=true
                shift
                ;;
            --permissions-fix)
                PERMISSIONS_FIX=true
                shift
                ;;
            --help|-h)
                # Multiple patterns separated by | (OR)
                usage  # Call the usage function and exit
                ;;
            -*)
                # Pattern for any argument starting with - (unknown option)
                # >&2 means redirect output to stderr (file descriptor 2)
                echo "Unknown option: $1" >&2
                echo "Use --help for usage information" >&2
                exit $ERR_USAGE
                ;;
            *)
                # Default case: anything that doesn't match above patterns
                # If it doesn't start with -, assume it's a config file
                # Filter out spurious single-digit arguments that might come from shell redirection
                if [[ "$1" =~ ^[0-9]$ ]]; then
                    echo "Warning: Ignoring spurious numeric argument: $1" >&2
                    shift
                    continue
                fi
                if [[ "$1" != *.conf ]]; then
                    # Pattern matching: *.conf means "ends with .conf"
                    echo "Config file should have .conf extension: $1" >&2
                    exit $ERR_USAGE
                fi
                CONFIG_FILE="$1"  # Store the config file name
                shift
                ;;
        esac
    done  # End of while loop
    
    # FLAG VALIDATION:
    # Ensure only one exclusive flag is set at a time
    # 'local' creates a variable that only exists within this function
    local exclusive_flags=0
    
    # PARAMETER EXPANSION: ${CERT_ONLY:-unset}
    # This means: use value of CERT_ONLY, or "unset" if CERT_ONLY is empty/unset
    
    # LOGICAL AND (&&): If first condition is true, execute second command
    # ARITHMETIC EXPANSION: $((expression)) performs arithmetic
    [[ "$CERT_ONLY" == true ]] && exclusive_flags=$((exclusive_flags + 1))
    [[ "$SERVICES_ONLY" == true ]] && exclusive_flags=$((exclusive_flags + 1))
    [[ "$PROXMOX_ONLY" == true ]] && exclusive_flags=$((exclusive_flags + 1))
    [[ "$PERMISSIONS_FIX" == true ]] && exclusive_flags=$((exclusive_flags + 1))
    
    # Check if more than one exclusive flag was set
    if [[ $exclusive_flags -gt 1 ]]; then
        echo "ERROR: Only one of --cert-only, --services-only, --proxmox-only, or --permissions-fix can be used at a time" >&2
        exit $ERR_USAGE
    fi
}  # End of function

# CONFIGURATION LOADING FUNCTION:
# This function loads settings from a configuration file
# It demonstrates file testing, sourcing external files, and parameter validation
load_config() {
    # FILE TEST: [[ ! -f "$CONFIG_FILE" ]] checks if file does NOT exist
    # -f tests for regular file existence
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "ERROR: Configuration file '$CONFIG_FILE' not found" >&2
        echo "Copy config.example.conf to $CONFIG_FILE and customize it" >&2
        exit $ERR_CONFIG
    fi
    
    # SOURCE COMMAND: 'source' executes another script in the current shell context
    # This allows the config file to set variables that we can use here
    # Alternative syntax: . "$CONFIG_FILE" (dot command does the same thing)
    source "$CONFIG_FILE"
    
    # VARIABLE VALIDATION:
    # Create an array of required variable names
    local required_vars=(DOMAIN CERT_DIR HOSTS)
    
    # ARRAY ITERATION: "${array[@]}" expands to all array elements
    for var in "${required_vars[@]}"; do
        # INDIRECT VARIABLE REFERENCE: ${!var} gets the value of the variable named in $var
        # For example, if var="DOMAIN", then ${!var} gets the value of $DOMAIN
        # :-} provides empty string as default if variable is unset
        # -z tests if string is empty
        if [[ -z "${!var:-}" ]]; then
            echo "ERROR: Required variable '$var' not set in $CONFIG_FILE" >&2
            exit $ERR_CONFIG
        fi
    done
    
    # SET DEFAULT VALUES:
    # Parameter expansion with default values: ${VAR:-default}
    # If VAR is unset or empty, use the default value after :-
    SSH_OPTS="${SSH_OPTS:--o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new}"
    LOG_FILE="${LOG_FILE:-/var/log/cert-spreader.log}"
    PLEX_CERT_ENABLED="${PLEX_CERT_ENABLED:-false}"
    ZNC_CERT_ENABLED="${ZNC_CERT_ENABLED:-false}"
    
    # FILE PERMISSION DEFAULTS:
    # These can be overridden in the configuration file
    FILE_PERMISSIONS="${FILE_PERMISSIONS:-644}"          # Default permissions for certificate files
    PRIVKEY_PERMISSIONS="${PRIVKEY_PERMISSIONS:-600}"    # More restrictive permissions for private key
    DIRECTORY_PERMISSIONS="${DIRECTORY_PERMISSIONS:-755}" # Directory permissions
    FILE_OWNER="${FILE_OWNER:-root}"                     # Default file owner
    FILE_GROUP="${FILE_GROUP:-root}"                     # Default file group
    
    # ENHANCED CONFIGURATION VALIDATION
    validate_config
}

# ENHANCED CONFIGURATION VALIDATION FUNCTION:
# This function performs deeper validation of configuration values
validate_config() {
    local validation_errors=0
    
    # Validate certificate directory exists and is readable
    if [[ ! -d "$CERT_DIR" ]]; then
        echo "ERROR: Certificate directory does not exist: $CERT_DIR" >&2
        validation_errors=$((validation_errors + 1))
    elif [[ ! -r "$CERT_DIR" ]]; then
        echo "ERROR: Certificate directory is not readable: $CERT_DIR" >&2
        validation_errors=$((validation_errors + 1))
    fi
    
    # Validate domain format (basic check)
    if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo "WARNING: DOMAIN format may be invalid: $DOMAIN" >&2
    fi
    
    # Validate HOSTS is not empty
    if [[ -z "$HOSTS" ]]; then
        echo "ERROR: HOSTS variable is empty - no hosts to deploy to" >&2
        validation_errors=$((validation_errors + 1))
    fi
    
    # Validate HOST_SERVICES array format if it exists
    if [[ ${#HOST_SERVICES[@]} -gt 0 ]]; then
        for host_config in "${HOST_SERVICES[@]}"; do
            if [[ ! "$host_config" =~ ^[^:]+:[0-9]+:.+ ]]; then
                echo "ERROR: Invalid HOST_SERVICES format: $host_config" >&2
                echo "Expected format: hostname:port:service1,service2" >&2
                validation_errors=$((validation_errors + 1))
            fi
        done
    fi
    
    # Validate Proxmox configuration if enabled
    if [[ -n "${PROXMOX_USER:-}" && -n "${PROXMOX_TOKEN:-}" ]]; then
        if [[ ! "$PROXMOX_USER" =~ ^[^!]+![^!]+$ ]]; then
            echo "ERROR: PROXMOX_USER must be in 'user@realm!tokenid' format" >&2
            validation_errors=$((validation_errors + 1))
        fi
    fi
    
    # Exit if any validation errors were found
    if [[ $validation_errors -gt 0 ]]; then
        echo "Configuration validation failed with $validation_errors error(s)" >&2
        exit $ERR_VALIDATION
    fi
}

# LOGGING FUNCTION:
# This function handles all log output with timestamps
# It demonstrates command substitution, pipes, and conditional logic
log() {
    # FUNCTION PARAMETERS: $1 is the first parameter passed to the function
    local msg="$1"
    
    # COMMAND SUBSTITUTION: $(command) runs command and captures its output
    # The 'date' command formats current date/time according to the format string
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # CONDITIONAL BRANCHING: Different behavior based on DRY_RUN flag
    if [[ "$DRY_RUN" == true ]]; then
        # PIPE (|): Sends output of first command as input to second command
        # tee: Outputs to both stdout AND appends to file (-a flag)
        echo "[DRY-RUN] [$timestamp] $msg" | tee -a "$LOG_FILE"
    else
        echo "[$timestamp] $msg" | tee -a "$LOG_FILE"
        # logger: System logging utility - sends message to system log
        # -t sets a tag for the log entry
        logger -t cert-spreader "$msg"
    fi
}

# DEPENDENCY CHECK FUNCTIONS:
# Check if required external commands are available
check_command_available() {
    local command="$1"
    
    if command -v "$command" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

check_keytool_available() {
    if ! check_command_available "keytool"; then
        return 1
    fi
    
    # Test keytool functionality with a simple command
    if keytool -help >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# SSH COMMAND CONSTRUCTION FUNCTION:
# This function builds SSH commands with consistent options and port handling
# This eliminates duplication and ensures consistent SSH behavior
build_ssh_command() {
    local host="$1"           # Hostname (without domain)
    local port="${2:-22}"     # SSH port with default
    local command="${3:-}"    # Optional command to execute
    
    # Start with base SSH command and options
    local ssh_cmd="ssh $SSH_OPTS"
    
    # Add custom port if not default
    if [[ "$port" != "22" ]]; then
        ssh_cmd="$ssh_cmd -p $port"
    fi
    
    # Add host and command
    ssh_cmd="$ssh_cmd root@$host.$DOMAIN"
    if [[ -n "$command" ]]; then
        ssh_cmd="$ssh_cmd '$command'"
    fi
    
    echo "$ssh_cmd"
}

# CERTIFICATE CHANGE DETECTION FUNCTION:
# This function checks if a certificate has changed by comparing hashes
# This enables idempotency - only deploy if certificate actually changed
# Demonstrates parameter defaults, command substitution, and hash comparison
cert_changed() {
    local host="$1"  # First parameter: hostname
    
    # PARAMETER DEFAULT: ${2:-22} means "use $2, or 22 if $2 is empty/unset"
    local port="${2:-22}"  # Second parameter with default value
    
    # CALCULATE LOCAL HASH:
    # sha256sum generates SHA-256 hash of file
    # head -c 64 extracts first 64 characters (the hash)
    local local_hash=$(sha256sum "$CERT_DIR/fullchain.pem" | head -c 64)
    
    # CALCULATE REMOTE HASH:
    # Use our SSH command builder and run sha256sum on remote host
    # 2>/dev/null suppresses error messages
    # || echo "none" provides fallback if command fails
    local ssh_cmd=$(build_ssh_command "$host" "$port" "sha256sum $CERT_DIR/fullchain.pem 2>/dev/null | head -c 64")
    local remote_hash=$(eval "$ssh_cmd" || echo "none")
    
    # COMPARISON: Return true (0) if hashes are different, false (1) if same
    # This is the return value of the function - bash functions return the exit code of last command
    [[ "$local_hash" != "$remote_hash" ]]
}

# CERTIFICATE DEPLOYMENT FUNCTION:
# This function deploys certificates to a single remote host using rsync
# It demonstrates rsync usage, SSH options, and error handling
deploy_to_host() {
    local host="$1"           # Target hostname
    local port="${2:-22}"     # SSH port with default
    
    # BUILD RSYNC SSH COMMAND:
    # rsync uses SSH for secure file transfer
    # -e flag specifies the remote shell command to use
    local rsync_ssh="ssh $SSH_OPTS"
    
    # Add custom port if not default
    if [[ "$port" != "22" ]]; then
        rsync_ssh="$rsync_ssh -p $port"
    fi
    
    # IDEMPOTENCY CHECK: Only deploy if certificate has changed
    # ! negates the return value (if cert_changed returns true, this becomes false)
    if ! cert_changed "$host" "$port"; then
        log "Skipping $host (certificate unchanged)"
        return 0  # Return success (0) - nothing to do
    fi
    
    log "Deploying certificates to $host"
    
    # DRY RUN MODE: Show what would be done without doing it
    if [[ "$DRY_RUN" == true ]]; then
        log "Would deploy certificates to $host using: rsync -aL -e '$rsync_ssh' '$CERT_DIR/' 'root@$host.$DOMAIN:$CERT_DIR/'"
        # Track this host as deployed for dry-run service restart simulation
        DEPLOYED_HOSTS+=("$host")
        return 0
    fi
    
    # ACTUAL DEPLOYMENT:
    # rsync flags: -a (archive mode), -L (follow symlinks)
    # Format: rsync source/ destination/
    # Trailing slashes are important in rsync!
    if ! rsync -aL -e "$rsync_ssh" "$CERT_DIR/" "root@$host.$DOMAIN:$CERT_DIR/"; then
        log "ERROR: Failed to deploy certificates to $host"
        return $ERR_NETWORK  # Return network error code
    fi
    
    log "Successfully deployed certificates to $host"
    # Track this host as having certificates deployed
    DEPLOYED_HOSTS+=("$host")
    return $ERR_SUCCESS  # Return success
}

# SERVICE RESTART FUNCTION:
# This function restarts services on remote hosts after certificate deployment
# It demonstrates array processing, string manipulation, and SSH command execution
restart_services() {
    log "Processing service restarts"
    
    # ARRAY LENGTH CHECK: ${#array[@]} gives the number of elements in array
    if [[ ${#HOST_SERVICES[@]} -eq 0 ]]; then
        log "No HOST_SERVICES configured, skipping service restarts"
        return 0
    fi
    
    # Check if any hosts had certificates deployed
    if [[ ${#DEPLOYED_HOSTS[@]} -eq 0 ]]; then
        log "No certificates were deployed, skipping service restarts"
        return 0
    fi
    
    # ARRAY ITERATION: Process each host configuration
    for host_config in "${HOST_SERVICES[@]}"; do
        # STRING SPLITTING: IFS (Internal Field Separator) controls how strings are split
        # read -r prevents backslash interpretation
        # <<< is a "here string" - feeds the string as input to read command
        # This splits "host:port:service1,service2" into separate variables
        IFS=':' read -r host port services <<< "$host_config"
        
        # CHECK IF THIS HOST HAD CERTIFICATES DEPLOYED:
        # Only restart services on hosts where certificates were actually deployed
        local host_deployed=false
        for deployed_host in "${DEPLOYED_HOSTS[@]}"; do
            if [[ "$deployed_host" == "$host" ]]; then
                host_deployed=true
                break
            fi
        done
        
        if [[ "$host_deployed" == false ]]; then
            log "Skipping service restart on $host (certificates not deployed)"
            continue
        fi
        
        if [[ "$DRY_RUN" == true ]]; then
            log "Would restart services on $host:$port - $services"
            continue  # Skip to next iteration of loop
        fi
        
        log "Restarting services on $host: $services"
        
        # BUILD SYSTEMCTL COMMAND WITH FALLBACK:
        # Try reload first, then restart if reload fails
        local service_cmd=""
        
        # SPLIT SERVICES: Convert comma-separated services into array
        # -a flag makes service_array an indexed array
        IFS=',' read -ra service_array <<< "$services"
        
        # BUILD COMMAND STRING: Try reload, fallback to restart
        for service in "${service_array[@]}"; do
            service_cmd+="(systemctl reload $service || systemctl restart $service) && "
        done
        
        # STRING MANIPULATION: Remove trailing " && "
        # ${variable%% pattern} removes longest match of pattern from end
        service_cmd=${service_cmd%% && }
        
        # EXECUTE REMOTE COMMAND:
        # Use our SSH command builder for consistency
        local ssh_cmd=$(build_ssh_command "$host" "$port" "$service_cmd")
        
        # CONDITIONAL EXECUTION: if command succeeds, then... else...
        if eval "$ssh_cmd"; then
            log "Successfully restarted services on $host"
        else
            log "WARNING: Failed to restart services on $host"
        fi
    done
}

# PROXMOX CERTIFICATE UPDATE FUNCTION:
# This function updates certificates on Proxmox VE nodes using the REST API
# It demonstrates regex matching, API calls with curl, and URL encoding
update_proxmox() {
    # PREREQUISITE CHECKS: Ensure credentials are configured
    # -z tests if string is empty
    if [[ -z "${PROXMOX_USER:-}" || -z "${PROXMOX_TOKEN:-}" ]]; then
        log "Proxmox credentials not configured, skipping Proxmox updates"
        return 0
    fi
    
    if [[ ${#PROXMOX_NODES[@]} -eq 0 ]]; then
        log "No Proxmox nodes configured, skipping Proxmox updates"
        return 0
    fi
    
    log "Updating Proxmox certificates"
    
    # READ CERTIFICATE FILES:
    # cat command reads entire file content
    # $() captures the output in variables
    local privkey=$(cat "$CERT_DIR/privkey.pem")
    local fullchain=$(cat "$CERT_DIR/fullchain.pem")
    
    # REGEX PATTERN MATCHING:
    # =~ is the regex match operator in bash
    # ^([^!]+)!(.+)$ breaks down as:
    #   ^ = start of string
    #   ([^!]+) = capture group 1: one or more non-! characters
    #   ! = literal exclamation mark
    #   (.+) = capture group 2: one or more characters
    #   $ = end of string
    if [[ "$PROXMOX_USER" =~ ^([^!]+)!(.+)$ ]]; then
        # BASH_REMATCH array contains regex capture groups
        # [1] = first capture group, [2] = second capture group
        local user_realm="${BASH_REMATCH[1]}"
        local token_id="${BASH_REMATCH[2]}"
    else
        log "ERROR: PROXMOX_USER must be in 'user@realm!tokenid' format"
        return $ERR_CONFIG
    fi
    
    # PROCESS EACH PROXMOX NODE:
    for node in "${PROXMOX_NODES[@]}"; do
        local node_url="https://$node.$DOMAIN:8006"
        
        if [[ "$DRY_RUN" == true ]]; then
            log "Would update Proxmox node $node at $node_url"
            continue
        fi
        
        # CONNECTIVITY CHECK:
        # curl flags: --connect-timeout (connection timeout), -s (silent), -k (ignore SSL errors)
        # >/dev/null 2>&1 redirects both stdout and stderr to null (suppress output)
        if ! curl --connect-timeout 30 -s -k "$node_url" >/dev/null 2>&1; then
            log "$node unreachable, skipping"
            continue
        fi
        
        log "Updating $node certificates"
        
        # PROXMOX API CALL:
        # This is a complex curl command making an HTTP POST to Proxmox API
        # \ at end of lines allows command to continue on next line
        if curl --connect-timeout 30 -v -k -X POST "$node_url/api2/json/nodes/$node/certificates/custom" \
            -H "Authorization: PVEAPIToken=${user_realm}!${token_id}=${PROXMOX_TOKEN}" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            --data-urlencode "key=${privkey}" \
            --data-urlencode "restart=1" \
            --data-urlencode "force=1" \
            --data-urlencode "node=$node" \
            --data-urlencode "certificates=${fullchain}" \
            2>&1 | logger -t cert-spreader; then
            log "Successfully updated $node certificates"
        else
            log "WARNING: $node update failed"
        fi
    done
}

# FLEXIBLE CERTIFICATE GENERATION:
# This function creates certificates based on user configuration
# Supports PKCS12/PFX and concatenated certificate formats
generate_service_certificates() {
    log "Generating custom certificates"
    
    # Process array-based custom certificates first
    if [[ ${#CUSTOM_CERTIFICATES[@]} -gt 0 ]]; then
        for cert_config in "${CUSTOM_CERTIFICATES[@]}"; do
            generate_custom_certificate "$cert_config"
        done
    fi
    
    # Process individual configuration settings
    if [[ "${PKCS12_ENABLED:-false}" == true ]]; then
        generate_pkcs12_certificate "${PKCS12_FILENAME:-certificate.pfx}" "${PKCS12_PASSWORD:-}"
    fi
    
    if [[ "${CONCATENATED_ENABLED:-false}" == true ]]; then
        generate_concatenated_certificate "${CONCATENATED_FILENAME:-combined.pem}" "${CONCATENATED_DHPARAM_FILE:-}"
    fi
}

# CUSTOM CERTIFICATE GENERATOR:
# Parses configuration string and generates appropriate certificate
generate_custom_certificate() {
    local cert_config="$1"
    
    # Parse configuration: "type:param:filename"
    IFS=':' read -r cert_type param filename <<< "$cert_config"
    
    # Set default filename if not provided
    if [[ -z "$filename" ]]; then
        filename=$(get_default_filename "$cert_type")
    fi
    
    case "$cert_type" in
        pkcs12)
            generate_pkcs12_certificate "$filename" "$param"
            ;;
        concatenated)
            generate_concatenated_certificate "$filename" "$param"
            ;;
        der)
            generate_der_certificate "$filename"
            ;;
        pkcs7|p7b)
            generate_pkcs7_certificate "$filename"
            ;;
        crt)
            generate_crt_certificate "$filename"
            ;;
        pem)
            generate_pem_certificate "$filename"
            ;;
        bundle)
            generate_bundle_certificate "$filename"
            ;;
        jks)
            generate_jks_certificate "$filename" "$param"
            ;;
        *)
            log "ERROR: Unknown certificate type: $cert_type"
            log "Supported types: pkcs12, concatenated, der, pkcs7, p7b, crt, pem, bundle, jks"
            ;;
    esac
}

# GET DEFAULT FILENAME:
# Returns appropriate default filename for certificate type
get_default_filename() {
    local cert_type="$1"
    
    case "$cert_type" in
        pkcs12)     echo "certificate.pfx" ;;
        concatenated) echo "combined.pem" ;;
        der)        echo "certificate.der" ;;
        pkcs7|p7b)  echo "certificate.p7b" ;;
        crt)        echo "certificate.crt" ;;
        pem)        echo "certificate.pem" ;;
        bundle)     echo "ca-bundle.pem" ;;
        jks)        echo "certificate.jks" ;;
        *)          echo "certificate.$cert_type" ;;
    esac
}

# PKCS12/PFX CERTIFICATE GENERATOR:
# Creates PKCS12 format certificates with optional password
generate_pkcs12_certificate() {
    local filename="$1"
    local password="$2"
    
    log "Generating PKCS12 certificate: $filename"
    local cert_path="$CERT_DIR/$filename"
    
    if [[ "$DRY_RUN" == true ]]; then
        log "Would generate PKCS12 certificate: $cert_path"
        return
    fi
    
    # Build OpenSSL command
    local openssl_cmd="openssl pkcs12 -export -out '$cert_path' -inkey '$CERT_DIR/privkey.pem' -in '$CERT_DIR/cert.pem' -certfile '$CERT_DIR/fullchain.pem'"
    
    # Add password if provided
    if [[ -n "$password" ]]; then
        openssl_cmd="$openssl_cmd -passout 'pass:$password'"
    else
        openssl_cmd="$openssl_cmd -passout 'pass:'"
    fi
    
    # Execute command
    if eval "$openssl_cmd" 2>&1 | logger -t cert-spreader; then
        chmod "$FILE_PERMISSIONS" "$cert_path"
        chown "$FILE_OWNER:$FILE_GROUP" "$cert_path"
        log "Generated PKCS12 certificate: $filename"
        LOCAL_CERT_CHANGED=true
    else
        log "ERROR: Failed to generate PKCS12 certificate: $filename"
    fi
}

# CONCATENATED CERTIFICATE GENERATOR:
# Creates concatenated certificate (private key + certificate + chain + optional DH params)
generate_concatenated_certificate() {
    local filename="$1"
    local dhparam_file="$2"
    
    log "Generating concatenated certificate: $filename"
    local cert_path="$CERT_DIR/$filename"
    
    if [[ "$DRY_RUN" == true ]]; then
        log "Would generate concatenated certificate: $cert_path"
        return
    fi
    
    # Create concatenated certificate
    if cat "$CERT_DIR/privkey.pem" "$CERT_DIR/fullchain.pem" > "$cert_path"; then
        # Add DH parameters if file exists
        if [[ -n "$dhparam_file" && -f "$dhparam_file" ]]; then
            cat "$dhparam_file" >> "$cert_path"
            log "Added DH parameters from: $dhparam_file"
        fi
        
        chmod "$FILE_PERMISSIONS" "$cert_path"
        chown "$FILE_OWNER:$FILE_GROUP" "$cert_path"
        log "Generated concatenated certificate: $filename"
        LOCAL_CERT_CHANGED=true
    else
        log "ERROR: Failed to generate concatenated certificate: $filename"
    fi
}

# DER CERTIFICATE GENERATOR:
# Creates DER format certificates for Java/Android devices
generate_der_certificate() {
    local filename="$1"
    local cert_path="$CERT_DIR/$filename"
    
    log "Generating DER certificate: $filename"
    
    if [[ "$DRY_RUN" == true ]]; then
        log "Would generate DER certificate: $cert_path"
        return 0
    fi
    
    # Convert PEM to DER format
    if openssl x509 -in "$CERT_DIR/cert.pem" -outform der -out "$cert_path"; then
        chmod "$FILE_PERMISSIONS" "$cert_path"
        chown "$FILE_OWNER:$FILE_GROUP" "$cert_path"
        log "Generated DER certificate: $filename"
        LOCAL_CERT_CHANGED=true
    else
        log "ERROR: Failed to generate DER certificate: $filename"
    fi
}

# PKCS#7 CERTIFICATE GENERATOR:
# Creates PKCS#7 format certificates for Windows/Java trust chains
generate_pkcs7_certificate() {
    local filename="$1"
    local cert_path="$CERT_DIR/$filename"
    
    log "Generating PKCS#7 certificate: $filename"
    
    if [[ "$DRY_RUN" == true ]]; then
        log "Would generate PKCS#7 certificate: $cert_path"
        return 0
    fi
    
    # Create PKCS#7 certificate bundle
    if openssl crl2pkcs7 -certfile "$CERT_DIR/fullchain.pem" -out "$cert_path" -nocrl; then
        chmod "$FILE_PERMISSIONS" "$cert_path"
        chown "$FILE_OWNER:$FILE_GROUP" "$cert_path"
        log "Generated PKCS#7 certificate: $filename"
        LOCAL_CERT_CHANGED=true
    else
        log "ERROR: Failed to generate PKCS#7 certificate: $filename"
    fi
}

# CRT CERTIFICATE GENERATOR:
# Creates individual CRT certificate file
generate_crt_certificate() {
    local filename="$1"
    local cert_path="$CERT_DIR/$filename"
    
    log "Generating CRT certificate: $filename"
    
    if [[ "$DRY_RUN" == true ]]; then
        log "Would generate CRT certificate: $cert_path"
        return 0
    fi
    
    # Copy cert.pem to .crt file
    if cp "$CERT_DIR/cert.pem" "$cert_path"; then
        chmod "$FILE_PERMISSIONS" "$cert_path"
        chown "$FILE_OWNER:$FILE_GROUP" "$cert_path"
        log "Generated CRT certificate: $filename"
        LOCAL_CERT_CHANGED=true
    else
        log "ERROR: Failed to generate CRT certificate: $filename"
    fi
}

# PEM CERTIFICATE GENERATOR:
# Creates individual PEM certificate file
generate_pem_certificate() {
    local filename="$1"
    local cert_path="$CERT_DIR/$filename"
    
    log "Generating PEM certificate: $filename"
    
    if [[ "$DRY_RUN" == true ]]; then
        log "Would generate PEM certificate: $cert_path"
        return 0
    fi
    
    # Copy fullchain.pem to custom filename
    if cp "$CERT_DIR/fullchain.pem" "$cert_path"; then
        chmod "$FILE_PERMISSIONS" "$cert_path"
        chown "$FILE_OWNER:$FILE_GROUP" "$cert_path"
        log "Generated PEM certificate: $filename"
        LOCAL_CERT_CHANGED=true
    else
        log "ERROR: Failed to generate PEM certificate: $filename"
    fi
}

# BUNDLE CERTIFICATE GENERATOR:
# Creates CA bundle certificate file
generate_bundle_certificate() {
    local filename="$1"
    local cert_path="$CERT_DIR/$filename"
    
    log "Generating CA bundle certificate: $filename"
    
    if [[ "$DRY_RUN" == true ]]; then
        log "Would generate CA bundle certificate: $cert_path"
        return 0
    fi
    
    # Copy chain.pem (CA bundle) to custom filename
    if [[ -f "$CERT_DIR/chain.pem" ]]; then
        if cp "$CERT_DIR/chain.pem" "$cert_path"; then
            chmod "$FILE_PERMISSIONS" "$cert_path"
            chown "$FILE_OWNER:$FILE_GROUP" "$cert_path"
            log "Generated CA bundle certificate: $filename"
            LOCAL_CERT_CHANGED=true
        else
            log "ERROR: Failed to generate CA bundle certificate: $filename"
        fi
    else
        log "WARNING: chain.pem not found, cannot generate CA bundle: $filename"
    fi
}

# JKS CERTIFICATE GENERATOR:
# Creates Java KeyStore (JKS) certificates via PKCS#12 intermediate conversion
generate_jks_certificate() {
    local filename="$1"
    local password="$2"
    local cert_path="$CERT_DIR/$filename"
    
    log "Generating JKS certificate: $filename"
    
    if [[ "$DRY_RUN" == true ]]; then
        log "Would generate JKS certificate: $cert_path"
        return 0
    fi
    
    # Check keytool availability first
    if ! check_keytool_available; then
        log "ERROR: JKS generation requires Java keytool (install Java JDK/JRE)"
        log "Alternative: Generate PKCS#12 with 'pkcs12:$password:${filename%.jks}.pfx' and convert manually"
        log "Conversion command: keytool -importkeystore -srckeystore ${filename%.jks}.pfx -srcstoretype PKCS12 -destkeystore $filename -deststoretype JKS"
        return 1
    fi
    
    # Validate password requirement
    if [[ -z "$password" ]]; then
        log "ERROR: JKS certificates require a password. Use format: 'jks:password:$filename'"
        return 1
    fi
    
    # Generate secure temporary PKCS#12 filename
    local temp_p12_name=".temp_$(date +%s)_$$.p12"
    local temp_p12_path="$CERT_DIR/$temp_p12_name"
    
    # Cleanup function for error handling
    cleanup_temp_p12() {
        if [[ -f "$temp_p12_path" ]]; then
            rm -f "$temp_p12_path"
            log "Cleaned up intermediate file: $temp_p12_name"
        fi
    }
    
    # Set trap for cleanup on exit/error
    trap cleanup_temp_p12 EXIT
    
    # Step 1: Generate intermediate PKCS#12 file
    log "Creating intermediate PKCS#12 for JKS conversion"
    
    if openssl pkcs12 -export \
        -out "$temp_p12_path" \
        -inkey "$CERT_DIR/privkey.pem" \
        -in "$CERT_DIR/cert.pem" \
        -certfile "$CERT_DIR/fullchain.pem" \
        -name "certificate" \
        -passout "pass:$password" 2>/dev/null; then
        
        log "Intermediate PKCS#12 created successfully"
    else
        log "ERROR: Failed to generate intermediate PKCS#12 for JKS conversion"
        cleanup_temp_p12
        trap - EXIT
        return 1
    fi
    
    # Step 2: Convert PKCS#12 to JKS using keytool
    log "Converting PKCS#12 to JKS format"
    
    if keytool -importkeystore \
        -srckeystore "$temp_p12_path" \
        -srcstoretype PKCS12 \
        -destkeystore "$cert_path" \
        -deststoretype JKS \
        -srcalias "certificate" \
        -destalias "certificate" \
        -srcstorepass "$password" \
        -deststorepass "$password" \
        -noprompt 2>/dev/null; then
        
        # Set proper permissions and ownership
        chmod "$FILE_PERMISSIONS" "$cert_path"
        chown "$FILE_OWNER:$FILE_GROUP" "$cert_path"
        
        log "Generated JKS certificate: $filename"
        LOCAL_CERT_CHANGED=true
        
        # Cleanup and remove trap
        cleanup_temp_p12
        trap - EXIT
        return 0
    else
        log "ERROR: Failed to convert PKCS#12 to JKS format"
        cleanup_temp_p12
        trap - EXIT
        return 1
    fi
}

# CONSOLIDATED PERMISSIONS CHECK FUNCTION:
# This unified function checks permissions and ownership for both files and directories
# Consolidates the previous separate file and directory permission functions
check_permissions() {
    local path="$1"                         # Path to file or directory to check
    local expected_perms="$2"               # Expected permissions in octal (e.g., "644")
    local expected_owner="${3:-$FILE_OWNER:$FILE_GROUP}"  # Expected owner with configurable default
    
    # DETERMINE PATH TYPE AND CHECK EXISTENCE:
    local path_type=""
    if [[ -f "$path" ]]; then
        path_type="file"
    elif [[ -d "$path" ]]; then
        path_type="directory"
    else
        return 1  # Return error if path doesn't exist or is neither file nor directory
    fi
    
    # GET CURRENT PERMISSIONS AND OWNERSHIP:
    # stat -c "%a" outputs permissions in octal format (e.g., 644)
    # stat -c "%U:%G" outputs owner:group format
    local current_perms=$(stat -c "%a" "$path")
    local current_owner=$(stat -c "%U:%G" "$path")
    
    # COMPOUND BOOLEAN CHECK:
    # Return true (0) if both permissions and ownership match expected values
    [[ "$current_perms" == "$expected_perms" && "$current_owner" == "$expected_owner" ]]
}

# DYNAMIC CERTIFICATE FILE DISCOVERY AND SECURITY FUNCTION:
# This function discovers certificate files dynamically and secures them
# More flexible than hardcoded arrays - adapts to different certificate setups
discover_and_secure_cert_files() {
    # Define standard certificate file patterns and their permissions
    # Using associative array with configurable permissions
    declare -A cert_file_perms=(
        ["privkey.pem"]="$PRIVKEY_PERMISSIONS"     # Private key with configurable permissions
        ["cert.pem"]="$FILE_PERMISSIONS"           # Certificate 
        ["fullchain.pem"]="$FILE_PERMISSIONS"      # Full certificate chain
        ["chain.pem"]="$FILE_PERMISSIONS"          # Intermediate chain (optional)
    )
    
    # Process each certificate file type
    for filename in "${!cert_file_perms[@]}"; do
        local filepath="$CERT_DIR/$filename"
        local expected_perms="${cert_file_perms[$filename]}"
        
        # Only process files that actually exist
        if [[ -f "$filepath" ]]; then
            if ! check_permissions "$filepath" "$expected_perms" "$FILE_OWNER:$FILE_GROUP"; then
                if [[ "$DRY_RUN" == true ]]; then
                    log "Would secure file: $filename ($expected_perms, $FILE_OWNER:$FILE_GROUP)"
                else
                    chmod "$expected_perms" "$filepath"
                    chown "$FILE_OWNER:$FILE_GROUP" "$filepath"
                    log "Secured file: $filename ($expected_perms, $FILE_OWNER:$FILE_GROUP)"
                fi
                changes_needed=true
            else
                log "File permissions OK: $filename ($expected_perms, $FILE_OWNER:$FILE_GROUP)"
            fi
        fi
    done
    
    # Discover and secure any additional .pem files in the directory
    # This catches custom certificate files that might exist
    for pem_file in "$CERT_DIR"/*.pem; do
        # Check if glob found actual files (avoid processing literal *.pem)
        [[ -f "$pem_file" ]] || continue
        
        local filename=$(basename "$pem_file")
        
        # Skip files we already processed above
        [[ -n "${cert_file_perms[$filename]:-}" ]] && continue
        
        # Default permissions for discovered .pem files
        local default_perms="$FILE_PERMISSIONS"
        if [[ "$filename" == *"key"* || "$filename" == *"private"* ]]; then
            default_perms="$PRIVKEY_PERMISSIONS"  # Use private key permissions for key files
        fi
        
        if ! check_permissions "$pem_file" "$default_perms" "$FILE_OWNER:$FILE_GROUP"; then
            if [[ "$DRY_RUN" == true ]]; then
                log "Would secure discovered file: $filename ($default_perms, $FILE_OWNER:$FILE_GROUP)"
            else
                chmod "$default_perms" "$pem_file"
                chown "$FILE_OWNER:$FILE_GROUP" "$pem_file"
                log "Secured discovered file: $filename ($default_perms, $FILE_OWNER:$FILE_GROUP)"
            fi
            changes_needed=true
        else
            log "Discovered file permissions OK: $filename ($default_perms, $FILE_OWNER:$FILE_GROUP)"
        fi
    done
}

# CERTIFICATE PERMISSIONS SECURITY FUNCTION:
# This function ensures all certificate files have proper permissions for security
# It demonstrates arrays of structured data, permission management, and security best practices
secure_cert_permissions() {
    log "Checking and securing certificate directory permissions"
    
    # TRACK CHANGES: Boolean flag to track if any changes were needed
    local changes_needed=false
    
    if [[ "$DRY_RUN" == true ]]; then
        log "Checking permissions in dry-run mode..."
    fi
    
    # SECURE CERTIFICATE DIRECTORY:
    # First, ensure the certificate directory itself has correct permissions
    if [[ -d "$CERT_DIR" ]]; then
        # Use our consolidated permissions function to check directory permissions
        if ! check_permissions "$CERT_DIR" "$DIRECTORY_PERMISSIONS" "$FILE_OWNER:$FILE_GROUP"; then
            if [[ "$DRY_RUN" == true ]]; then
                log "Would secure directory: $CERT_DIR ($DIRECTORY_PERMISSIONS, $FILE_OWNER:$FILE_GROUP)"
            else
                # PERMISSION COMMANDS:
                # chmod changes file/directory permissions
                # chown changes file/directory ownership
                chmod "$DIRECTORY_PERMISSIONS" "$CERT_DIR"
                chown "$FILE_OWNER:$FILE_GROUP" "$CERT_DIR"  # Set owner to configured user/group
                log "Secured directory: $CERT_DIR ($DIRECTORY_PERMISSIONS, $FILE_OWNER:$FILE_GROUP)"
            fi
            changes_needed=true
        else
            log "Directory permissions OK: $CERT_DIR ($DIRECTORY_PERMISSIONS, $FILE_OWNER:$FILE_GROUP)"
        fi
    else
        log "WARNING: Certificate directory does not exist: $CERT_DIR"
        return $ERR_CERT
    fi
    
    # SECURE INDIVIDUAL CERTIFICATE FILES:
    # Use dynamic discovery to find certificate files and set appropriate permissions
    # This approach is more flexible than hardcoded arrays
    discover_and_secure_cert_files
    
    # SECURE CUSTOM CERTIFICATES:
    # Handle custom certificates based on configuration
    secure_custom_certificates
    
    # SUMMARY LOGGING:
    if [[ "$changes_needed" == false ]]; then
        log "All certificate permissions already correct"
    else
        if [[ "$DRY_RUN" == false ]]; then
            log "Certificate directory permissions secured"
        fi
    fi
}

# SECURE CUSTOM CERTIFICATES FUNCTION:
# This function secures custom certificate files based on configuration
secure_custom_certificates() {
    local custom_files=()
    
    # Collect filenames from individual settings
    if [[ "${PKCS12_ENABLED:-false}" == true ]]; then
        custom_files+=("${PKCS12_FILENAME:-certificate.pfx}")
    fi
    
    if [[ "${CONCATENATED_ENABLED:-false}" == true ]]; then
        custom_files+=("${CONCATENATED_FILENAME:-combined.pem}")
    fi
    
    # Collect filenames from custom certificate array
    if [[ ${#CUSTOM_CERTIFICATES[@]} -gt 0 ]]; then
        for cert_config in "${CUSTOM_CERTIFICATES[@]}"; do
            IFS=':' read -r cert_type param filename <<< "$cert_config"
            if [[ -n "$filename" ]]; then
                custom_files+=("$filename")
            else
                custom_files+=("custom-${cert_type}.pem")
            fi
        done
    fi
    
    
    # Secure each custom certificate file
    for filename in "${custom_files[@]}"; do
        local filepath="$CERT_DIR/$filename"
        if [[ -f "$filepath" ]]; then
            if ! check_permissions "$filepath" "$FILE_PERMISSIONS" "$FILE_OWNER:$FILE_GROUP"; then
                if [[ "$DRY_RUN" == true ]]; then
                    log "Would secure custom certificate: $filename ($FILE_PERMISSIONS, $FILE_OWNER:$FILE_GROUP)"
                else
                    chmod "$FILE_PERMISSIONS" "$filepath"
                    chown "$FILE_OWNER:$FILE_GROUP" "$filepath"
                    log "Secured custom certificate: $filename ($FILE_PERMISSIONS, $FILE_OWNER:$FILE_GROUP)"
                fi
                changes_needed=true
            else
                log "Custom certificate permissions OK: $filename ($FILE_PERMISSIONS, $FILE_OWNER:$FILE_GROUP)"
            fi
        fi
    done
}


# MAIN FUNCTION:
# This is the primary orchestration function that coordinates all script operations
# It demonstrates complex conditional logic, error handling, and script flow control
main() {
    # ARGUMENT PROCESSING:
    # "$@" passes all command line arguments to the parse_args function
    # This preserves arguments exactly as they were passed to the script
    parse_args "$@"
    
    # CONFIGURATION LOADING:
    # Load settings from configuration file
    load_config
    
    # STARTUP LOGGING:
    log "=== Certificate Spreader Started ==="
    log "Mode: DRY_RUN=$DRY_RUN, CERT_ONLY=$CERT_ONLY, SERVICES_ONLY=$SERVICES_ONLY, PROXMOX_ONLY=$PROXMOX_ONLY, PERMISSIONS_FIX=$PERMISSIONS_FIX"
    
    # SPECIAL MODE: PERMISSIONS-FIX ONLY
    # This mode only fixes permissions and exits (doesn't do certificate operations)
    if [[ "$PERMISSIONS_FIX" == true ]]; then
        log "Running in permissions-fix only mode"
        secure_cert_permissions
        log "=== Certificate Spreader Completed Successfully ==="
        return $ERR_SUCCESS  # Early exit - don't do anything else
    fi
    
    # CERTIFICATE FILE VALIDATION:
    # Ensure required certificate files exist before proceeding
    # Skip this check in services-only mode since we won't be touching certificates
    if [[ "$SERVICES_ONLY" != true ]]; then
        # ARRAY OF REQUIRED FILES:
        for file in privkey.pem fullchain.pem cert.pem; do
            # FILE SIZE TEST: -s checks if file exists and is not empty
            if [[ ! -s "$CERT_DIR/$file" ]]; then
                log "ERROR: Certificate file missing or empty: $CERT_DIR/$file"
                exit $ERR_CERT  # Exit with error - can't proceed without certificates
            fi
        done
    fi
    
    # CERTIFICATE PROCESSING PHASE:
    # Generate service certificates, secure permissions, and deploy
    # Skip this entire phase in certain modes
    if [[ "$SERVICES_ONLY" != true && "$PROXMOX_ONLY" != true && "$PERMISSIONS_FIX" != true ]]; then
        # Generate certificates in formats needed by specific services
        generate_service_certificates
        
        # Ensure all certificate files have proper security permissions
        secure_cert_permissions
        
        # RELOAD LOCAL NGINX:
        # Only reload nginx if certificates have changed
        if [[ "$LOCAL_CERT_CHANGED" == true ]]; then
            log "Reloading local nginx"
            if [[ "$DRY_RUN" == true ]]; then
                log "Would reload local nginx"
            else
                # SYSTEMCTL: System service control command
                # reload is gentler than restart - reloads config without dropping connections
                # 2>&1 | logger redirects output to system log
                systemctl reload nginx 2>&1 | logger -t cert-spreader
            fi
        else
            log "Skipping local nginx reload (certificates unchanged)"
        fi
        
        
        # CERTIFICATE DEPLOYMENT TO REMOTE HOSTS:
        local failed_hosts=()  # Array to track deployment failures
        
        # WORD SPLITTING: $HOSTS is split on whitespace into individual hostnames
        # This is intentional word splitting (usually we'd quote variables)
        for host in $HOSTS; do
            # DETERMINE SSH PORT FOR THIS HOST:
            # Check if this host has a custom SSH port defined in HOST_SERVICES
            local host_port=22  # Default SSH port
            
            # SEARCH HOST_SERVICES ARRAY:
            for host_config in "${HOST_SERVICES[@]}"; do
                IFS=':' read -r config_host config_port config_services <<< "$host_config"
                if [[ "$config_host" == "$host" ]]; then
                    host_port="$config_port"
                    break  # Found the host, stop searching
                fi
            done
            
            # DEPLOY TO THIS HOST:
            # If deployment fails, add to failed_hosts array
            if ! deploy_to_host "$host" "$host_port"; then
                # ARRAY APPENDING: += adds element to array
                failed_hosts+=("$host")
            fi
        done
        
        # Set local cert changed flag if any hosts had certificates deployed
        if [[ ${#DEPLOYED_HOSTS[@]} -gt 0 ]]; then
            LOCAL_CERT_CHANGED=true
        fi
        
        # ERROR HANDLING FOR FAILED DEPLOYMENTS:
        if [[ ${#failed_hosts[@]} -gt 0 ]]; then
            # ARRAY EXPANSION: ${array[*]} expands all elements as single word
            # (different from ${array[@]} which expands as separate words)
            log "ERROR: Failed to deploy to hosts: ${failed_hosts[*]}"
            
            # Continue with remaining operations instead of exiting
            # Log the failures but don't stop the script from completing other tasks
            if [[ "$CERT_ONLY" != true ]]; then
                log "Continuing with service restarts despite deployment failures"
            fi
        fi
    fi
    
    # SERVICE MANAGEMENT PHASE:
    # Restart services and update Proxmox nodes
    # Skip this phase in cert-only mode
    if [[ "$CERT_ONLY" != true ]]; then
        # RESTART SERVICES (unless proxmox-only mode)
        if [[ "$PROXMOX_ONLY" != true ]]; then
            restart_services
        fi
        
        # UPDATE PROXMOX NODES (unless services-only mode)
        if [[ "$SERVICES_ONLY" != true ]]; then
            update_proxmox
        fi
    fi
    
    # SUCCESS LOGGING:
    log "=== Certificate Spreader Completed Successfully ==="
}

# SCRIPT EXECUTION:
# This line actually runs the main function with all script arguments
# "$@" preserves all arguments exactly as passed to the script
# This is the entry point that starts everything
main "$@"