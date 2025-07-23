#!/bin/bash
set -euo pipefail

# Certificate Spreader - Simplified Version with Configuration File
# Deploy Let's Encrypt certificates to multiple hosts after renewal

# Default configuration file
CONFIG_FILE="${1:-config.conf}"

# Command line flags
DRY_RUN=false
CERT_ONLY=false
SERVICES_ONLY=false
PROXMOX_ONLY=false
PERMISSIONS_FIX=false

# Usage function
usage() {
    cat << EOF
Usage: $0 [config-file] [options]

Options:
    --dry-run        Show what would be done without making changes
    --cert-only      Only deploy certificates, skip service restarts
    --services-only  Only restart services, skip certificate deployment
    --proxmox-only   Only update Proxmox certificates, skip everything else
    --permissions-fix Only fix certificate file permissions, skip everything else
    --help          Show this help message

If no config file is specified, 'config.conf' will be used.

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

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                shift
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
                usage
                ;;
            -*)
                echo "Unknown option: $1" >&2
                usage
                ;;
            *)
                # If it doesn't start with -, assume it's a config file
                if [[ "$1" != *.conf ]]; then
                    echo "Config file should have .conf extension: $1" >&2
                    exit 1
                fi
                CONFIG_FILE="$1"
                shift
                ;;
        esac
    done
    
    # Validate flag combinations
    local exclusive_flags=0
    [[ "$CERT_ONLY" == true ]] && ((exclusive_flags++))
    [[ "$SERVICES_ONLY" == true ]] && ((exclusive_flags++))
    [[ "$PROXMOX_ONLY" == true ]] && ((exclusive_flags++))
    [[ "$PERMISSIONS_FIX" == true ]] && ((exclusive_flags++))
    
    if [[ $exclusive_flags -gt 1 ]]; then
        echo "ERROR: Only one of --cert-only, --services-only, --proxmox-only, or --permissions-fix can be used at a time" >&2
        exit 1
    fi
}

# Load configuration file
load_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "ERROR: Configuration file '$CONFIG_FILE' not found" >&2
        echo "Copy config.example.conf to $CONFIG_FILE and customize it" >&2
        exit 1
    fi
    
    # Source the configuration file
    source "$CONFIG_FILE"
    
    # Validate required variables
    local required_vars=(DOMAIN CERT_DIR BACKUP_HOST HOSTS)
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            echo "ERROR: Required variable '$var' not set in $CONFIG_FILE" >&2
            exit 1
        fi
    done
    
    # Set defaults for optional variables
    SSH_OPTS="${SSH_OPTS:--o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new}"
    LOG_FILE="${LOG_FILE:-/var/log/cert-spreader.log}"
    PLEX_CERT_ENABLED="${PLEX_CERT_ENABLED:-false}"
    ZNC_CERT_ENABLED="${ZNC_CERT_ENABLED:-false}"
    CERT_FILE_MODE="${CERT_FILE_MODE:-644}"
    PRIVKEY_FILE_MODE="${PRIVKEY_FILE_MODE:-600}"
}

log() {
    local msg="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    if [[ "$DRY_RUN" == true ]]; then
        echo "[DRY-RUN] [$timestamp] $msg" | tee -a "$LOG_FILE"
    else
        echo "[$timestamp] $msg" | tee -a "$LOG_FILE"
        logger -t cert-spreader "$msg"
    fi
}

# Check if certificate has changed (idempotency)
cert_changed() {
    local host="$1"
    local port="${2:-22}"
    local ssh_cmd="ssh $SSH_OPTS"
    
    if [[ "$port" != "22" ]]; then
        ssh_cmd="$ssh_cmd -p $port"
    fi
    
    local local_hash=$(sha256sum "$CERT_DIR/fullchain.pem" | cut -d' ' -f1)
    local remote_hash=$($ssh_cmd "root@$host.$DOMAIN" "sha256sum $CERT_DIR/fullchain.pem 2>/dev/null | cut -d' ' -f1" || echo "none")
    
    [[ "$local_hash" != "$remote_hash" ]]
}

# Deploy certificates to a single host
deploy_to_host() {
    local host="$1"
    local port="${2:-22}"
    local rsync_ssh="ssh $SSH_OPTS"
    
    if [[ "$port" != "22" ]]; then
        rsync_ssh="$rsync_ssh -p $port"
    fi
    
    if ! cert_changed "$host" "$port"; then
        log "Skipping $host (certificate unchanged)"
        return 0
    fi
    
    log "Deploying certificates to $host"
    
    if [[ "$DRY_RUN" == true ]]; then
        log "Would deploy certificates to $host using: rsync -aL -e '$rsync_ssh' '$CERT_DIR/' 'root@$host.$DOMAIN:$CERT_DIR/'"
        return 0
    fi
    
    if ! rsync -aL -e "$rsync_ssh" "$CERT_DIR/" "root@$host.$DOMAIN:$CERT_DIR/"; then
        log "ERROR: Failed to deploy certificates to $host"
        return 1
    fi
    
    log "Successfully deployed certificates to $host"
    return 0
}

# Restart services based on HOST_SERVICES configuration
restart_services() {
    log "Processing service restarts"
    
    if [[ ${#HOST_SERVICES[@]} -eq 0 ]]; then
        log "No HOST_SERVICES configured, skipping service restarts"
        return 0
    fi
    
    for host_config in "${HOST_SERVICES[@]}"; do
        IFS=':' read -r host port services <<< "$host_config"
        
        if [[ "$DRY_RUN" == true ]]; then
            log "Would restart services on $host:$port - $services"
            continue
        fi
        
        log "Restarting services on $host: $services"
        
        # Build systemctl command
        local service_cmd=""
        IFS=',' read -ra service_array <<< "$services"
        for service in "${service_array[@]}"; do
            service_cmd+="systemctl reload $service && "
        done
        service_cmd=${service_cmd%% && }  # Remove trailing &&
        
        # Execute command
        local ssh_cmd="ssh $SSH_OPTS"
        if [[ "$port" != "22" ]]; then
            ssh_cmd="$ssh_cmd -p $port"
        fi
        
        if $ssh_cmd "root@$host.$DOMAIN" "$service_cmd"; then
            log "Successfully restarted services on $host"
        else
            log "WARNING: Failed to restart services on $host"
        fi
    done
}

# Update Proxmox certificates
update_proxmox() {
    if [[ -z "${PROXMOX_USER:-}" || -z "${PROXMOX_TOKEN:-}" ]]; then
        log "Proxmox credentials not configured, skipping Proxmox updates"
        return 0
    fi
    
    if [[ ${#PROXMOX_NODES[@]} -eq 0 ]]; then
        log "No Proxmox nodes configured, skipping Proxmox updates"
        return 0
    fi
    
    log "Updating Proxmox certificates"
    
    local privkey=$(cat "$CERT_DIR/privkey.pem")
    local fullchain=$(cat "$CERT_DIR/fullchain.pem")
    
    # Extract user@realm and tokenid from PROXMOX_USER
    if [[ "$PROXMOX_USER" =~ ^([^!]+)!(.+)$ ]]; then
        local user_realm="${BASH_REMATCH[1]}"
        local token_id="${BASH_REMATCH[2]}"
    else
        log "ERROR: PROXMOX_USER must be in 'user@realm!tokenid' format"
        return 1
    fi
    
    for node in "${PROXMOX_NODES[@]}"; do
        local node_url="https://$node.$DOMAIN:8006"
        
        if [[ "$DRY_RUN" == true ]]; then
            log "Would update Proxmox node $node at $node_url"
            continue
        fi
        
        # Check if node is reachable
        if ! curl --connect-timeout 30 -s -k "$node_url" >/dev/null 2>&1; then
            log "$node unreachable, skipping"
            continue
        fi
        
        log "Updating $node certificates"
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

# Generate service-specific certificates
generate_service_certificates() {
    log "Generating service-specific certificates"
    
    # Generate Plex PKCS12 certificate
    if [[ "${PLEX_CERT_ENABLED:-false}" == true ]]; then
        local plex_password="${PLEX_CERT_PASSWORD:-Password1!}"
        log "Generating Plex PKCS12 certificate"
        
        if [[ "$DRY_RUN" == true ]]; then
            log "Would generate Plex certificate: $CERT_DIR/plex-certificate.pfx"
        else
            openssl pkcs12 -export -out "$CERT_DIR/plex-certificate.pfx" \
                -inkey "$CERT_DIR/privkey.pem" \
                -in "$CERT_DIR/cert.pem" \
                -certfile "$CERT_DIR/fullchain.pem" \
                -passout "pass:$plex_password" 2>&1 | logger -t cert-spreader
            
            chmod 755 "$CERT_DIR/plex-certificate.pfx"
            log "Generated Plex certificate"
        fi
    fi
    
    # Generate ZNC certificate
    if [[ "${ZNC_CERT_ENABLED:-false}" == true ]]; then
        log "Generating ZNC certificate"
        
        if [[ "$DRY_RUN" == true ]]; then
            log "Would generate ZNC certificate: $CERT_DIR/znc.pem"
        else
            if [[ -f "${ZNC_DHPARAM_FILE:-}" ]]; then
                cat "$CERT_DIR/privkey.pem" "$CERT_DIR/fullchain.pem" "$ZNC_DHPARAM_FILE" > "$CERT_DIR/znc.pem"
            else
                cat "$CERT_DIR/privkey.pem" "$CERT_DIR/fullchain.pem" > "$CERT_DIR/znc.pem"
            fi
            log "Generated ZNC certificate"
        fi
    fi
}

# Check if file has correct permissions and ownership (idempotency helper)
check_file_permissions() {
    local filepath="$1"
    local expected_perms="$2"
    local expected_owner="${3:-root:root}"
    
    if [[ ! -f "$filepath" ]]; then
        return 1  # File doesn't exist
    fi
    
    # Get current permissions (in octal format)
    local current_perms=$(stat -c "%a" "$filepath")
    
    # Get current ownership
    local current_owner=$(stat -c "%U:%G" "$filepath")
    
    # Check if permissions and ownership match expected values
    [[ "$current_perms" == "$expected_perms" && "$current_owner" == "$expected_owner" ]]
}

# Check if directory has correct permissions and ownership (idempotency helper)
check_dir_permissions() {
    local dirpath="$1"
    local expected_perms="$2"
    local expected_owner="${3:-root:root}"
    
    if [[ ! -d "$dirpath" ]]; then
        return 1  # Directory doesn't exist
    fi
    
    # Get current permissions (in octal format)
    local current_perms=$(stat -c "%a" "$dirpath")
    
    # Get current ownership
    local current_owner=$(stat -c "%U:%G" "$dirpath")
    
    # Check if permissions and ownership match expected values
    [[ "$current_perms" == "$expected_perms" && "$current_owner" == "$expected_owner" ]]
}

# Secure certificate directory permissions per Let's Encrypt standards
secure_cert_permissions() {
    log "Checking and securing certificate directory permissions"
    
    local changes_needed=false
    
    if [[ "$DRY_RUN" == true ]]; then
        log "Checking permissions in dry-run mode..."
    fi
    
    # Check and secure the certificate directory itself
    if [[ -d "$CERT_DIR" ]]; then
        if ! check_dir_permissions "$CERT_DIR" "755" "root:root"; then
            if [[ "$DRY_RUN" == true ]]; then
                log "Would secure directory: $CERT_DIR (755, root:root)"
            else
                chmod 755 "$CERT_DIR"
                chown root:root "$CERT_DIR"
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
    
    # Check and secure individual certificate files with appropriate permissions
    local cert_files=(
        "privkey.pem:600"      # Private key - most restrictive
        "cert.pem:644"         # Certificate - readable by services
        "fullchain.pem:644"    # Full chain - readable by services  
        "chain.pem:644"        # Intermediate chain - if it exists
    )
    
    for file_perm in "${cert_files[@]}"; do
        IFS=':' read -r filename perms <<< "$file_perm"
        local filepath="$CERT_DIR/$filename"
        
        if [[ -f "$filepath" ]]; then
            if ! check_file_permissions "$filepath" "$perms" "root:root"; then
                if [[ "$DRY_RUN" == true ]]; then
                    log "Would secure file: $filename ($perms, root:root)"
                else
                    chmod "$perms" "$filepath"
                    chown root:root "$filepath"
                    log "Secured file: $filename ($perms, root:root)"
                fi
                changes_needed=true
            else
                log "File permissions OK: $filename ($perms, root:root)"
            fi
        fi
    done
    
    # Check and secure service-specific certificates with appropriate permissions
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
    
    if [[ "${ZNC_CERT_ENABLED:-false}" == true && -f "$CERT_DIR/znc.pem" ]]; then
        if ! check_file_permissions "$CERT_DIR/znc.pem" "600" "root:root"; then
            if [[ "$DRY_RUN" == true ]]; then
                log "Would secure ZNC certificate: znc.pem (600, root:root)"
            else
                chmod 600 "$CERT_DIR/znc.pem"
                chown root:root "$CERT_DIR/znc.pem"
                log "Secured ZNC certificate: znc.pem (600, root:root)"
            fi
            changes_needed=true
        else
            log "ZNC certificate permissions OK: znc.pem (600, root:root)"
        fi
    fi
    
    if [[ "$changes_needed" == false ]]; then
        log "All certificate permissions already correct"
    else
        if [[ "$DRY_RUN" == false ]]; then
            log "Certificate directory permissions secured"
        fi
    fi
}

# Backup certificates and configs
perform_backups() {
    log "Backing up certificates to $BACKUP_HOST"
    
    if [[ "$DRY_RUN" == true ]]; then
        log "Would backup certificates to $BACKUP_HOST:${SSL_BACKUP_DIR:-/backup/ssl}"
        if [[ -d /etc/nginx ]]; then
            log "Would backup nginx configs to $BACKUP_HOST:${NGINX_BACKUP_DIR:-/backup/nginx}"
        fi
        return 0
    fi
    
    # Backup SSL certificates
    if ! rsync -aL -e "ssh $SSH_OPTS" "$CERT_DIR/" "root@$BACKUP_HOST.$DOMAIN:${SSL_BACKUP_DIR:-/backup/ssl}/" 2>&1 | logger -t cert-spreader; then
        log "WARNING: Certificate backup failed"
    fi
    
    # Backup nginx configs if directory exists
    if [[ -d /etc/nginx ]]; then
        if ! rsync -aL --exclude 'modules/*' -e "ssh $SSH_OPTS" /etc/nginx/ "root@$BACKUP_HOST.$DOMAIN:${NGINX_BACKUP_DIR:-/backup/nginx}/" 2>&1 | logger -t cert-spreader; then
            log "WARNING: Nginx config backup failed"
        fi
    fi
}

main() {
    # Parse command line arguments (pass all args to parse function)
    parse_args "$@"
    
    # Load configuration
    load_config
    
    log "=== Certificate Spreader Started ==="
    log "Mode: DRY_RUN=$DRY_RUN, CERT_ONLY=$CERT_ONLY, SERVICES_ONLY=$SERVICES_ONLY, PROXMOX_ONLY=$PROXMOX_ONLY, PERMISSIONS_FIX=$PERMISSIONS_FIX"
    
    # Handle permissions-fix only mode
    if [[ "$PERMISSIONS_FIX" == true ]]; then
        log "Running in permissions-fix only mode"
        secure_cert_permissions
        log "=== Certificate Spreader Completed Successfully ==="
        return 0
    fi
    
    # Validate certificate files exist (unless services-only mode)
    if [[ "$SERVICES_ONLY" != true ]]; then
        for file in privkey.pem fullchain.pem cert.pem; do
            if [[ ! -s "$CERT_DIR/$file" ]]; then
                log "ERROR: Certificate file missing or empty: $CERT_DIR/$file"
                exit 1
            fi
        done
    fi
    
    # Generate service-specific certificates (unless services-only, proxmox-only, or permissions-fix mode)
    if [[ "$SERVICES_ONLY" != true && "$PROXMOX_ONLY" != true && "$PERMISSIONS_FIX" != true ]]; then
        generate_service_certificates
        
        # Secure certificate permissions
        secure_cert_permissions
        
        # Reload local nginx
        log "Reloading local nginx"
        if [[ "$DRY_RUN" == true ]]; then
            log "Would reload local nginx"
        else
            systemctl reload nginx 2>&1 | logger -t cert-spreader
        fi
        
        # Perform backups
        perform_backups
        
        # Deploy certificates to all hosts
        local failed_hosts=()
        for host in $HOSTS; do
            # Check if this host has custom port in HOST_SERVICES
            local host_port=22
            for host_config in "${HOST_SERVICES[@]}"; do
                IFS=':' read -r config_host config_port config_services <<< "$host_config"
                if [[ "$config_host" == "$host" ]]; then
                    host_port="$config_port"
                    break
                fi
            done
            
            if ! deploy_to_host "$host" "$host_port"; then
                failed_hosts+=("$host")
            fi
        done
        
        if [[ ${#failed_hosts[@]} -gt 0 ]]; then
            log "ERROR: Failed to deploy to hosts: ${failed_hosts[*]}"
            if [[ "$CERT_ONLY" != true ]]; then
                log "Skipping service restarts due to deployment failures"
                exit 1
            fi
        fi
    fi
    
    # Restart services and update Proxmox (unless cert-only mode)
    if [[ "$CERT_ONLY" != true ]]; then
        # Restart services (unless proxmox-only mode)
        if [[ "$PROXMOX_ONLY" != true ]]; then
            restart_services
        fi
        
        # Update Proxmox (unless services-only mode)
        if [[ "$SERVICES_ONLY" != true ]]; then
            update_proxmox
        fi
    fi
    
    log "=== Certificate Spreader Completed Successfully ==="
}

# Run main function with all arguments
main "$@"