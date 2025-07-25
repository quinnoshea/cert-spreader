#!/bin/bash
# SHEBANG: This line tells the system to use bash to interpret this script
# It must be the very first line of the script

# SET OPTIONS: Configure bash behavior for safer script execution
set -euo pipefail
# -e: Exit immediately if any command fails (non-zero exit code)
# -u: Treat unset variables as errors (prevents typos in variable names)
# -o pipefail: Make pipelines fail if any command in the pipeline fails

# DEBUG OUTPUT: Show what arguments were passed to the script
# $@ represents all command line arguments passed to the script
echo "DEBUG: Script started with args: $@"

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
    exit 0
}

# ARGUMENT PARSING FUNCTION:
# This function processes command line arguments passed to the script
# It demonstrates several important bash concepts:
# - Function parameters: $1, $2, etc. are positional parameters
# - $# is the number of arguments
# - $@ is all arguments as separate words
# - while loops and case statements for processing options
parse_args() {
    echo "DEBUG: In parse_args with $# args: $@"
    
    # WHILE LOOP: Continue processing while there are arguments left
    # [[ $# -gt 0 ]] means "while number of arguments is greater than 0"
    # [[ ]] is bash's improved test command (better than [ ])
    while [[ $# -gt 0 ]]; do
        echo "DEBUG: Processing arg: $1"  # $1 is the first remaining argument
        
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
                echo "DEBUG: Setting PERMISSIONS_FIX=true"
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
                usage
                ;;
            *)
                # Default case: anything that doesn't match above patterns
                # If it doesn't start with -, assume it's a config file
                if [[ "$1" != *.conf ]]; then
                    # Pattern matching: *.conf means "ends with .conf"
                    echo "Config file should have .conf extension: $1" >&2
                    exit 1  # Exit with error code 1
                fi
                CONFIG_FILE="$1"  # Store the config file name
                shift
                ;;
        esac
        echo "DEBUG: End of case, remaining args: $#"
    done  # End of while loop
    echo "DEBUG: Exited while loop, starting flag validation"
    
    # FLAG VALIDATION:
    # Ensure only one exclusive flag is set at a time
    # 'local' creates a variable that only exists within this function
    local exclusive_flags=0
    
    # PARAMETER EXPANSION: ${CERT_ONLY:-unset}
    # This means: use value of CERT_ONLY, or "unset" if CERT_ONLY is empty/unset
    echo "DEBUG: Checking CERT_ONLY=${CERT_ONLY:-unset}"
    
    # LOGICAL AND (&&): If first condition is true, execute second command
    # ARITHMETIC EXPANSION: $((expression)) performs arithmetic
    [[ "$CERT_ONLY" == true ]] && exclusive_flags=$((exclusive_flags + 1))
    echo "DEBUG: After CERT_ONLY check, exclusive_flags=$exclusive_flags"
    [[ "$SERVICES_ONLY" == true ]] && exclusive_flags=$((exclusive_flags + 1))
    [[ "$PROXMOX_ONLY" == true ]] && exclusive_flags=$((exclusive_flags + 1))
    echo "DEBUG: Checking PERMISSIONS_FIX=${PERMISSIONS_FIX:-unset}"
    [[ "$PERMISSIONS_FIX" == true ]] && exclusive_flags=$((exclusive_flags + 1))
    echo "DEBUG: After all checks, exclusive_flags=$exclusive_flags"
    
    # Check if more than one exclusive flag was set
    if [[ $exclusive_flags -gt 1 ]]; then
        echo "ERROR: Only one of --cert-only, --services-only, --proxmox-only, or --permissions-fix can be used at a time" >&2
        exit 1
    fi
    echo "DEBUG: parse_args completed successfully"
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
        exit 1
    fi
    
    # SOURCE COMMAND: 'source' executes another script in the current shell context
    # This allows the config file to set variables that we can use here
    # Alternative syntax: . "$CONFIG_FILE" (dot command does the same thing)
    source "$CONFIG_FILE"
    
    # VARIABLE VALIDATION:
    # Create an array of required variable names
    local required_vars=(DOMAIN CERT_DIR BACKUP_HOST HOSTS)
    
    # ARRAY ITERATION: "${array[@]}" expands to all array elements
    for var in "${required_vars[@]}"; do
        # INDIRECT VARIABLE REFERENCE: ${!var} gets the value of the variable named in $var
        # For example, if var="DOMAIN", then ${!var} gets the value of $DOMAIN
        # :-} provides empty string as default if variable is unset
        # -z tests if string is empty
        if [[ -z "${!var:-}" ]]; then
            echo "ERROR: Required variable '$var' not set in $CONFIG_FILE" >&2
            exit 1
        fi
    done
    
    # SET DEFAULT VALUES:
    # Parameter expansion with default values: ${VAR:-default}
    # If VAR is unset or empty, use the default value after :-
    SSH_OPTS="${SSH_OPTS:--o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new}"
    LOG_FILE="${LOG_FILE:-/var/log/cert-spreader.log}"
    PLEX_CERT_ENABLED="${PLEX_CERT_ENABLED:-false}"
    ZNC_CERT_ENABLED="${ZNC_CERT_ENABLED:-false}"
    
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

# CERTIFICATE CHANGE DETECTION FUNCTION:
# This function checks if a certificate has changed by comparing hashes
# This enables idempotency - only deploy if certificate actually changed
# Demonstrates parameter defaults, command substitution, and hash comparison
cert_changed() {
    local host="$1"  # First parameter: hostname
    
    # PARAMETER DEFAULT: ${2:-22} means "use $2, or 22 if $2 is empty/unset"
    local port="${2:-22}"  # Second parameter with default value
    
    # BUILD SSH COMMAND: Start with base SSH options
    local ssh_cmd="ssh $SSH_OPTS"
    
    # ADD PORT if different from default
    if [[ "$port" != "22" ]]; then
        ssh_cmd="$ssh_cmd -p $port"
    fi
    
    # CALCULATE LOCAL HASH:
    # sha256sum generates SHA-256 hash of file
    # cut -d' ' -f1 extracts first field (the hash) using space as delimiter
    local local_hash=$(sha256sum "$CERT_DIR/fullchain.pem" | cut -d' ' -f1)
    
    # CALCULATE REMOTE HASH:
    # Run sha256sum on remote host via SSH
    # 2>/dev/null suppresses error messages
    # || echo "none" provides fallback if command fails
    local remote_hash=$($ssh_cmd "root@$host.$DOMAIN" "sha256sum $CERT_DIR/fullchain.pem 2>/dev/null | cut -d' ' -f1" || echo "none")
    
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
        return 0
    fi
    
    # ACTUAL DEPLOYMENT:
    # rsync flags: -a (archive mode), -L (follow symlinks)
    # Format: rsync source/ destination/
    # Trailing slashes are important in rsync!
    if ! rsync -aL -e "$rsync_ssh" "$CERT_DIR/" "root@$host.$DOMAIN:$CERT_DIR/"; then
        log "ERROR: Failed to deploy certificates to $host"
        return 1  # Return error code
    fi
    
    log "Successfully deployed certificates to $host"
    return 0  # Return success
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
    
    # ARRAY ITERATION: Process each host configuration
    for host_config in "${HOST_SERVICES[@]}"; do
        # STRING SPLITTING: IFS (Internal Field Separator) controls how strings are split
        # read -r prevents backslash interpretation
        # <<< is a "here string" - feeds the string as input to read command
        # This splits "host:port:service1,service2" into separate variables
        IFS=':' read -r host port services <<< "$host_config"
        
        if [[ "$DRY_RUN" == true ]]; then
            log "Would restart services on $host:$port - $services"
            continue  # Skip to next iteration of loop
        fi
        
        log "Restarting services on $host: $services"
        
        # BUILD SYSTEMCTL COMMAND:
        # Create a compound command to reload multiple services
        local service_cmd=""
        
        # SPLIT SERVICES: Convert comma-separated services into array
        # -a flag makes service_array an indexed array
        IFS=',' read -ra service_array <<< "$services"
        
        # BUILD COMMAND STRING: Create "systemctl reload service1 && systemctl reload service2"
        for service in "${service_array[@]}"; do
            service_cmd+="systemctl reload $service && "
        done
        
        # STRING MANIPULATION: Remove trailing " && "
        # ${variable%% pattern} removes longest match of pattern from end
        service_cmd=${service_cmd%% && }
        
        # EXECUTE REMOTE COMMAND:
        local ssh_cmd="ssh $SSH_OPTS"
        if [[ "$port" != "22" ]]; then
            ssh_cmd="$ssh_cmd -p $port"
        fi
        
        # CONDITIONAL EXECUTION: if command succeeds, then... else...
        if $ssh_cmd "root@$host.$DOMAIN" "$service_cmd"; then
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
        return 1
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

# SERVICE-SPECIFIC CERTIFICATE GENERATION:
# This function creates certificates in formats required by specific services
# It demonstrates OpenSSL usage and file concatenation
generate_service_certificates() {
    log "Generating service-specific certificates"
    
    # PLEX CERTIFICATE GENERATION:
    # Plex media server requires PKCS12 format certificates
    if [[ "${PLEX_CERT_ENABLED:-false}" == true ]]; then
        local plex_password="${PLEX_CERT_PASSWORD:-PASSWORD}"
        log "Generating Plex PKCS12 certificate"
        
        if [[ "$DRY_RUN" == true ]]; then
            log "Would generate Plex certificate: $CERT_DIR/plex-certificate.pfx"
        else
            # OPENSSL PKCS12 COMMAND:
            # -export: create PKCS12 file
            # -out: output file
            # -inkey: private key file
            # -in: certificate file
            # -certfile: certificate chain file
            # -passout: password for the PKCS12 file
            # 2>&1 | logger: redirect output to system log
            openssl pkcs12 -export -out "$CERT_DIR/plex-certificate.pfx" \
                -inkey "$CERT_DIR/privkey.pem" \
                -in "$CERT_DIR/cert.pem" \
                -certfile "$CERT_DIR/fullchain.pem" \
                -passout "pass:$plex_password" 2>&1 | logger -t cert-spreader
            
            # SET FILE PERMISSIONS: chmod changes file permissions
            # 755 = owner: read/write/execute, group/others: read/execute
            chmod 755 "$CERT_DIR/plex-certificate.pfx"
            log "Generated Plex certificate"
        fi
    fi
    
    # ZNC CERTIFICATE GENERATION:
    # ZNC IRC bouncer needs private key and certificate in single file
    if [[ "${ZNC_CERT_ENABLED:-false}" == true ]]; then
        log "Generating ZNC certificate"
        
        if [[ "$DRY_RUN" == true ]]; then
            log "Would generate ZNC certificate: $CERT_DIR/znc.pem"
        else
            # FILE CONCATENATION:
            # cat multiple files and redirect output (>) to create combined file
            # ZNC expects private key + certificate chain + optional DH parameters
            if [[ -f "${ZNC_DHPARAM_FILE:-}" ]]; then
                # Include Diffie-Hellman parameters if file exists
                cat "$CERT_DIR/privkey.pem" "$CERT_DIR/fullchain.pem" "$ZNC_DHPARAM_FILE" > "$CERT_DIR/znc.pem"
            else
                # Just private key + certificate chain
                cat "$CERT_DIR/privkey.pem" "$CERT_DIR/fullchain.pem" > "$CERT_DIR/znc.pem"
            fi
            log "Generated ZNC certificate"
        fi
    fi
}

# FILE PERMISSIONS CHECK FUNCTION:
# This helper function checks if a file has correct permissions and ownership
# It demonstrates the 'stat' command and compound boolean conditions
check_file_permissions() {
    local filepath="$1"         # Path to file to check
    local expected_perms="$2"   # Expected permissions in octal (e.g., "644")
    local expected_owner="${3:-root:root}"  # Expected owner with default
    
    # FILE EXISTENCE CHECK: -f tests for regular file
    if [[ ! -f "$filepath" ]]; then
        return 1  # Return error code if file doesn't exist
    fi
    
    # GET CURRENT PERMISSIONS:
    # stat -c "%a" outputs permissions in octal format (e.g., 644)
    # %a format specifier gets file permissions in octal
    local current_perms=$(stat -c "%a" "$filepath")
    
    # GET CURRENT OWNERSHIP:
    # %U gets owner username, %G gets group name
    local current_owner=$(stat -c "%U:%G" "$filepath")
    
    # COMPOUND BOOLEAN CHECK:
    # && is logical AND - both conditions must be true
    # This returns true (0) if both permissions and ownership match expected values
    [[ "$current_perms" == "$expected_perms" && "$current_owner" == "$expected_owner" ]]
}

# DIRECTORY PERMISSIONS CHECK FUNCTION:
# Similar to file permissions check, but for directories
# Same logic as check_file_permissions but uses -d test for directories
check_dir_permissions() {
    local dirpath="$1"          # Path to directory to check
    local expected_perms="$2"   # Expected permissions in octal
    local expected_owner="${3:-root:root}"  # Expected owner with default
    
    # DIRECTORY EXISTENCE CHECK: -d tests for directory
    if [[ ! -d "$dirpath" ]]; then
        return 1  # Return error if directory doesn't exist
    fi
    
    # Same stat commands as for files - stat works on both files and directories
    local current_perms=$(stat -c "%a" "$dirpath")
    local current_owner=$(stat -c "%U:%G" "$dirpath")
    
    # Return true if both permissions and ownership match
    [[ "$current_perms" == "$expected_perms" && "$current_owner" == "$expected_owner" ]]
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
        # Use our helper function to check directory permissions
        if ! check_dir_permissions "$CERT_DIR" "755" "root:root"; then
            if [[ "$DRY_RUN" == true ]]; then
                log "Would secure directory: $CERT_DIR (755, root:root)"
            else
                # PERMISSION COMMANDS:
                # chmod changes file/directory permissions
                # chown changes file/directory ownership
                chmod 755 "$CERT_DIR"      # rwxr-xr-x (owner: read/write/execute, others: read/execute)
                chown root:root "$CERT_DIR"  # Set owner to root user, root group
                log "Secured directory: $CERT_DIR (755, root:root)"
            fi
            changes_needed=true
        else
            log "Directory permissions OK: $CERT_DIR (755, root:root)"
        fi
    else
        log "WARNING: Certificate directory does not exist: $CERT_DIR"
        return 1
    fi
    
    # SECURE INDIVIDUAL CERTIFICATE FILES:
    # Array containing filename:permissions pairs
    # This is a structured way to define multiple files with their required permissions
    local cert_files=(
        "privkey.pem:644"      # Private key - readable by services (NOTE: Usually 600, but this app needs 644)
        "cert.pem:644"         # Certificate - readable by services
        "fullchain.pem:644"    # Full chain - readable by services  
        "chain.pem:644"        # Intermediate chain - if it exists
    )
    
    # PROCESS EACH CERTIFICATE FILE:
    for file_perm in "${cert_files[@]}"; do
        # SPLIT STRING: Extract filename and permissions from "filename:perms" format
        IFS=':' read -r filename perms <<< "$file_perm"
        local filepath="$CERT_DIR/$filename"
        
        # Only process files that actually exist
        if [[ -f "$filepath" ]]; then
            if ! check_file_permissions "$filepath" "$perms" "root:root"; then
                if [[ "$DRY_RUN" == true ]]; then
                    log "Would secure file: $filename ($perms, root:root)"
                else
                    chmod "$perms" "$filepath"        # Set file permissions
                    chown root:root "$filepath"       # Set file ownership
                    log "Secured file: $filename ($perms, root:root)"
                fi
                changes_needed=true
            else
                log "File permissions OK: $filename ($perms, root:root)"
            fi
        fi
    done
    
    # SECURE SERVICE-SPECIFIC CERTIFICATES:
    # Handle Plex certificate if enabled
    if [[ "${PLEX_CERT_ENABLED:-false}" == true && -f "$CERT_DIR/plex-certificate.pfx" ]]; then
        if ! check_file_permissions "$CERT_DIR/plex-certificate.pfx" "644" "root:root"; then
            if [[ "$DRY_RUN" == true ]]; then
                log "Would secure Plex certificate: plex-certificate.pfx (644, root:root)"
            else
                chmod 644 "$CERT_DIR/plex-certificate.pfx"
                chown root:root "$CERT_DIR/plex-certificate.pfx"
                log "Secured Plex certificate: plex-certificate.pfx (644, root:root)"
            fi
            changes_needed=true
        else
            log "Plex certificate permissions OK: plex-certificate.pfx (644, root:root)"
        fi
    fi
    
    # Handle ZNC certificate if enabled (more restrictive permissions for ZNC)
    if [[ "${ZNC_CERT_ENABLED:-false}" == true && -f "$CERT_DIR/znc.pem" ]]; then
        if ! check_file_permissions "$CERT_DIR/znc.pem" "600" "root:root"; then
            if [[ "$DRY_RUN" == true ]]; then
                log "Would secure ZNC certificate: znc.pem (600, root:root)"
            else
                chmod 600 "$CERT_DIR/znc.pem"    # 600 = rw------- (only owner can read/write)
                chown root:root "$CERT_DIR/znc.pem"
                log "Secured ZNC certificate: znc.pem (600, root:root)"
            fi
            changes_needed=true
        else
            log "ZNC certificate permissions OK: znc.pem (600, root:root)"
        fi
    fi
    
    # SUMMARY LOGGING:
    if [[ "$changes_needed" == false ]]; then
        log "All certificate permissions already correct"
    else
        if [[ "$DRY_RUN" == false ]]; then
            log "Certificate directory permissions secured"
        fi
    fi
}

# BACKUP FUNCTION:
# This function backs up certificates and configurations to a remote host
# It demonstrates rsync with exclusions and directory testing
perform_backups() {
    log "Backing up certificates to $BACKUP_HOST"
    
    if [[ "$DRY_RUN" == true ]]; then
        log "Would backup certificates to $BACKUP_HOST:${SSL_BACKUP_DIR:-/backup/ssl}"
        # DIRECTORY TEST: -d checks if path exists and is a directory
        if [[ -d /etc/nginx ]]; then
            log "Would backup nginx configs to $BACKUP_HOST:${NGINX_BACKUP_DIR:-/backup/nginx}"
        fi
        return 0
    fi
    
    # BACKUP SSL CERTIFICATES:
    # rsync with SSH transport to remote backup host
    # 2>&1 | logger redirects all output to system log
    if ! rsync -aL -e "ssh $SSH_OPTS" "$CERT_DIR/" "root@$BACKUP_HOST.$DOMAIN:${SSL_BACKUP_DIR:-/backup/ssl}/" 2>&1 | logger -t cert-spreader; then
        log "WARNING: Certificate backup failed"
    fi
    
    # BACKUP NGINX CONFIGS (if nginx directory exists):
    if [[ -d /etc/nginx ]]; then
        # RSYNC WITH EXCLUSIONS:
        # --exclude 'pattern' skips files/directories matching pattern
        # This excludes the modules directory which may contain large files
        if ! rsync -aL --exclude 'modules/*' -e "ssh $SSH_OPTS" /etc/nginx/ "root@$BACKUP_HOST.$DOMAIN:${NGINX_BACKUP_DIR:-/backup/nginx}/" 2>&1 | logger -t cert-spreader; then
            log "WARNING: Nginx config backup failed"
        fi
    fi
}

# MAIN FUNCTION:
# This is the primary orchestration function that coordinates all script operations
# It demonstrates complex conditional logic, error handling, and script flow control
main() {
    # ARGUMENT PROCESSING:
    # "$@" passes all command line arguments to the parse_args function
    # This preserves arguments exactly as they were passed to the script
    parse_args "$@"
    echo "DEBUG: After parse_args - PERMISSIONS_FIX=$PERMISSIONS_FIX"
    
    # CONFIGURATION LOADING:
    # Load settings from configuration file
    load_config
    echo "DEBUG: After load_config"
    
    # STARTUP LOGGING:
    log "=== Certificate Spreader Started ==="
    log "Mode: DRY_RUN=$DRY_RUN, CERT_ONLY=$CERT_ONLY, SERVICES_ONLY=$SERVICES_ONLY, PROXMOX_ONLY=$PROXMOX_ONLY, PERMISSIONS_FIX=$PERMISSIONS_FIX"
    
    # SPECIAL MODE: PERMISSIONS-FIX ONLY
    # This mode only fixes permissions and exits (doesn't do certificate operations)
    echo "DEBUG: Checking PERMISSIONS_FIX: $PERMISSIONS_FIX"
    if [[ "$PERMISSIONS_FIX" == true ]]; then
        echo "DEBUG: Entering permissions-fix mode"
        log "Running in permissions-fix only mode"
        secure_cert_permissions
        log "=== Certificate Spreader Completed Successfully ==="
        return 0  # Early exit - don't do anything else
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
                exit 1  # Exit with error - can't proceed without certificates
            fi
        done
    fi
    
    # CERTIFICATE PROCESSING PHASE:
    # Generate service certificates, secure permissions, backup, and deploy
    # Skip this entire phase in certain modes
    if [[ "$SERVICES_ONLY" != true && "$PROXMOX_ONLY" != true && "$PERMISSIONS_FIX" != true ]]; then
        # Generate certificates in formats needed by specific services
        generate_service_certificates
        
        # Ensure all certificate files have proper security permissions
        secure_cert_permissions
        
        # RELOAD LOCAL NGINX:
        # Restart the local nginx service to pick up new certificates
        log "Reloading local nginx"
        if [[ "$DRY_RUN" == true ]]; then
            log "Would reload local nginx"
        else
            # SYSTEMCTL: System service control command
            # reload is gentler than restart - reloads config without dropping connections
            # 2>&1 | logger redirects output to system log
            systemctl reload nginx 2>&1 | logger -t cert-spreader
        fi
        
        # BACKUP OPERATIONS:
        perform_backups
        
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
        
        # ERROR HANDLING FOR FAILED DEPLOYMENTS:
        if [[ ${#failed_hosts[@]} -gt 0 ]]; then
            # ARRAY EXPANSION: ${array[*]} expands all elements as single word
            # (different from ${array[@]} which expands as separate words)
            log "ERROR: Failed to deploy to hosts: ${failed_hosts[*]}"
            
            # Only exit if we're not in cert-only mode
            # In cert-only mode, we don't care about service restarts
            if [[ "$CERT_ONLY" != true ]]; then
                log "Skipping service restarts due to deployment failures"
                exit 1
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