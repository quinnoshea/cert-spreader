#!/usr/bin/env bash
set -euo pipefail

# === Certificate Deployment Script ===
# Purpose: Deploy Let's Encrypt certificates to multiple hosts and services
# Last Updated: May 15, 2025
# Improvements: certificate validation, rollback, backup verification,
#               enhanced CLI, retries, idempotency, logrotate,
#               DOMAIN var, auto-install dependencies with dry-run reporting

###########################
# === Configuration ===
###########################
DOMAIN="batkave.net"

CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
REMOTE_CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
DHPARAM_FILE="/etc/nginx/ssl/dhparam.pem"

LOG_FILE="/var/log/cert-deploy.log"
LOG_TAG="cert-deploy"
LOCKFILE="/var/run/cert-deploy.lock"

LOGROTATE_CONF="/etc/logrotate.d/cert-deploy"
LOGROTATE_INTERVAL="weekly"
LOGROTATE_ROTATE=4
LOGROTATE_COMPRESS="compress"
LOGROTATE_MISSINGOK="missingok"
LOGROTATE_NOTIFEMPTY="notifempty"
LOGROTATE_CREATE="create 0644 root root"
LOGROTATE_MAXSIZE=""

SSH_KEY="/root/.ssh/id_ed25519"
SSH_TIMEOUT=10
SSH_OPTS="-o ConnectTimeout=$SSH_TIMEOUT \
          -o ControlMaster=auto \
          -o ControlPersist=5m \
          -o StrictHostKeyChecking=accept-new"
BACKUP_DIR="/mnt/nfs/data/sshkeys/nginx-configs"
SSL_BACKUP_DIR="/mnt/nfs/data/sshkeys/ssl"
TEMP_BACKUP_DIR="/tmp/cert-backup"
ROLLBACK_DIR="/var/backups/certs-rollback"

USERNAME="endfro"

PROXMOX_USER="endfro@pve!letsencrypt"
PROXMOX_TOKEN="e0c4a89d-5fc9-4788-9b7a-0d2c7985ad95"
PROXMOX01_URL="https://proxmox01.$DOMAIN:8006"
PROXMOX02_URL="https://proxmox02.$DOMAIN:8006"

HOSTS="azrael ftp odroid-m1 qbittorrent tautulli calibre-web joker alfred dns01 dns02"
BACKUP_HOST="joker"
HOST_SERVICES=(
  "joker:22:nginx.service qbittorrent-nox.service"
  "tautulli:22:tautulli.service"
  # "clayface:22:nginx.service"
  "odroid-m1:22:nginx.service postfix.service dovecot.service"
  # "riddler:22:nginx.service"
  "ftp:22:sftpgo.service"
  # "madhatter:22:vsftpd.service"
  "azrael:22:plexmediaserver.service"
  "alfred:42022:znc.service"
  "calibre-web:22:cps.service"
  "qbittorrent:22:qbittorrent-nox.service"
  "dns01:22:dns.service"
  "dns02:22:dns.service"
)

DRY_RUN=0
MAX_PARALLEL=5
FRAGILE_HOSTS=()
SERVICES_ONLY=0
DEPLOY_ONLY=0
FORCE=0
ROLLBACK=0

declare -A HOST_DEPLOY_STATUS
declare -A ORIGINAL_CERT_HASH

###########################
# === Helpers & Logging ===
###########################
usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

  --dry-run             : simulate only
  --max-parallel <N>    : concurrent deploy/restart (default: \$MAX_PARALLEL)
  --services-only       : skip cert deployment
  --deploy-only         : skip service + Proxmox updates
  --force               : bypass cert validation failures
  --rollback            : rollback failed hosts only
  --help                : show this message
EOF
  exit 0
}

log() {
  local LEVEL=$1 MSG=$2 TS
  TS=$(date '+%F %T')
  local logfile="${LOG_FILE:-/tmp/cert-deploy.fallback.log}"
  local tag="${LOG_TAG:-cert-deploy}"
  printf "[%s] [%s] %s\n" "$TS" "$LEVEL" "$MSG" >>"$logfile"
  logger -t "$tag" "[$LEVEL] $MSG"
  if [[ $LEVEL == ERROR || $LEVEL == CRITICAL ]]; then
    echo "[$LEVEL] $MSG" >&2
  else
    echo "[$LEVEL] $MSG"
  fi
}

handle_error() {
  log ERROR "$1"
  rm -f "$LOCKFILE"
  exit "${2:-1}"
}

retry() {
  # retry <attempts> <sleep_secs> <cmd> [args...]
  local max=$1 sleep_s=$2; shift 2
  local i=1
  until "$@"; do
    (( i >= max )) && return 1
    ((i++))
    sleep "$sleep_s"
  done
}

# Ping helper: retries 3× and logs PASS/FAIL
ping_host() {
  local host="$1" i
  for i in 1 2 3; do
    if ping -c1 -W2 "$host" &>/dev/null; then
      log INFO "Ping $host: PASS"
      return 0
    fi
    sleep 1
  done
  log WARN "Ping $host: FAIL"
  return 1
}

###########################
# === Logrotate Setup  ===
###########################
setup_logrotate() {
  [[ $EUID -ne 0 ]] && { log WARN "not root; skipping logrotate"; return; }
  cat >"$LOGROTATE_CONF" <<EOF
$LOG_FILE {
    $LOGROTATE_INTERVAL
    rotate $LOGROTATE_ROTATE
$( [[ -n $LOGROTATE_MAXSIZE ]] && echo "    maxsize $LOGROTATE_MAXSIZE" )
    $LOGROTATE_MISSINGOK
    $LOGROTATE_NOTIFEMPTY
    $LOGROTATE_COMPRESS
    $LOGROTATE_CREATE
}
EOF
  log INFO "logrotate config written to $LOGROTATE_CONF"
}

###########################
# === CLI Parsing ========
###########################
while [[ $# -gt 0 ]]; do
  case $1 in
    --dry-run)         DRY_RUN=1; shift ;;
    --max-parallel)    MAX_PARALLEL=$2; shift 2 ;;
    --services-only)   SERVICES_ONLY=1; shift ;;
    --deploy-only)     DEPLOY_ONLY=1; shift ;;
    --force)           FORCE=1; shift ;;
    --rollback)        ROLLBACK=1; shift ;;
    --help)            usage ;;
    *) echo "Unknown: $1" >&2; usage ;;
  esac
done

log INFO "DRY_RUN setting: $DRY_RUN"

log INFO "BACKUP_HOST is set to: $BACKUP_HOST"

###########################
# === Single Instance  ===
###########################
if [[ -e $LOCKFILE ]]; then
  if kill -0 "$(cat "$LOCKFILE")" &>/dev/null; then
    handle_error "already running (PID $(cat "$LOCKFILE"))"
  else
    log WARN "stale lockfile; removing"
    rm -f "$LOCKFILE"
  fi
fi
echo $$ >"$LOCKFILE"
trap 'rm -f "$LOCKFILE"; exit' INT TERM EXIT

setup_logrotate

###########################
# === Environment Check===
###########################
validate_environment() {
  local tools=(rsync ssh openssl curl logger nc ping sha256sum jq sed grep awk)
  local missing=()
  for t in "${tools[@]}"; do
    command -v "$t" &>/dev/null || missing+=("$t")
  done
  if (( ${#missing[@]} )); then
    log INFO "missing tools: ${missing[*]}"
    declare -A pkg=( [jq]=jq [rsync]=rsync [openssl]=openssl [curl]=curl [logger]=util-linux [nc]=netcat [ping]=iputils-ping [sha256sum]=coreutils [sed]=sed [grep]=grep [awk]=gawk [ssh]=openssh-client )
    local pm_update pm_install cmd
    if command -v apt-get &>/dev/null; then pm_update="apt-get update"; pm_install="apt-get install -y"
    elif command -v yum &>/dev/null; then pm_install="yum install -y"
    elif command -v dnf &>/dev/null; then pm_install="dnf install -y"
    elif command -v zypper &>/dev/null; then pm_install="zypper install -y"
    fi
    local to_install=()
    for t in "${missing[@]}"; do [[ -n "${pkg[$t]:-}" ]] && to_install+=("${pkg[$t]}"); done
    if (( DRY_RUN )); then
      [[ -n $pm_update ]] && log INFO "[DRY-RUN] would: sudo $pm_update && sudo $pm_install ${to_install[*]}"
      [[ -z $pm_update ]] && log INFO "[DRY-RUN] would install: ${to_install[*]}"
    else
      if [[ -n $pm_install && -x "$(command -v sudo)" ]]; then
        [[ -n $pm_update ]] && sudo $pm_update
        sudo $pm_install "${to_install[@]}" || handle_error "install failed"
      else
        handle_error "cannot install dependencies"
      fi
    fi
    for t in "${missing[@]}"; do command -v "$t" &>/dev/null || handle_error "still missing: $t"; done
    log INFO "dependencies satisfied"
  else
    log INFO "environment OK"
  fi
}

###########################
# === Remote Deps ========
###########################
check_remote_dependencies() {
  local host=$1 port=$2 missing=""
  for tool in rsync openssl sha256sum; do
    if ! ssh -q $SSH_OPTS \
             -i"$SSH_KEY" -p"$port" \
             root@"${host}.${DOMAIN}" \
             "command -v $tool" &>/dev/null; then
      missing+=" $tool"
    fi
  done
  if [[ -n $missing ]]; then
    log WARN "$host missing:$missing"
    return 1
  fi
  log INFO "remote deps OK on $host"
}

###########################
# === Cert Validation ====
###########################
validate_certificates() {
  log INFO "validating certificates"
  for f in privkey.pem fullchain.pem cert.pem; do
    [[ -s $CERT_DIR/$f ]] || handle_error "$CERT_DIR/$f missing or empty"
  done

  local now exp not_before days_left s e
  now=$(date +%s)
  exp=$(openssl x509 -enddate -noout -in "$CERT_DIR/cert.pem" | cut -d= -f2)
  e=$(date -d "$exp" +%s)
  days_left=$(( (e - now)/86400 ))
  not_before=$(openssl x509 -startdate -noout -in "$CERT_DIR/cert.pem" | cut -d= -f2)
  s=$(date -d "$not_before" +%s)

  if (( now < s )); then
    log ERROR "certificate not valid until $not_before"
    if (( FORCE )); then
      log WARN "--force, proceeding"
    elif (( DRY_RUN )); then
      log WARN "[DRY-RUN] skipping not‑yet‑valid error"
    else
      return 1
    fi
  fi

  if (( days_left < 0 )); then
    log ERROR "certificate expired $((-days_left)) days ago"
    if (( FORCE )); then
      log WARN "--force, proceeding"
    elif (( DRY_RUN )); then
      log WARN "[DRY-RUN] skipping expired‑cert error"
    else
      return 1
    fi
  elif (( days_left < 7 )); then
    log WARN "certificate expires in $days_left days"
  else
    log INFO "certificate valid for $days_left days"
  fi

  # Chain verification (works for ECDSA & RSA)
  if ! openssl verify \
       -CAfile /etc/ssl/certs/ca-certificates.crt \
       -untrusted "$CERT_DIR/fullchain.pem" \
       "$CERT_DIR/cert.pem" &>/dev/null; then
    log ERROR "chain verification failed"
    if (( FORCE )); then
      log WARN "--force, proceeding"
    elif (( DRY_RUN )); then
      log WARN "[DRY-RUN] skipping chain verify error"
    else
      return 1
    fi
  else
    log INFO "chain OK"
  fi

  # Public‐key fingerprint comparison (works for RSA, ECDSA, etc)
  local cert_fp key_fp
  cert_fp=$(openssl x509 -in "$CERT_DIR/cert.pem" -pubkey -noout 2>/dev/null \
            | openssl pkey -pubin -outform DER 2>/dev/null \
            | sha256sum)
  key_fp=$(openssl pkey -in "$CERT_DIR/privkey.pem" -pubout -outform DER 2>/dev/null \
          | sha256sum)

  if [[ "$cert_fp" != "$key_fp" ]]; then
    log ERROR "public key mismatch between certificate and private key"
    if (( FORCE )); then
      log WARN "--force, proceeding"
    elif (( DRY_RUN )); then
      log WARN "[DRY-RUN] skipping key mismatch error"
    else
      return 1
    fi
  else
    log INFO "public key matches private key"
  fi

  return 0
}

###########################
# === Read Certs ========
###########################
read_certs() {
  PRIVKEY=$(<"$CERT_DIR/privkey.pem")
  FULLCHAIN=$(<"$CERT_DIR/fullchain.pem")
  CERT=$(<"$CERT_DIR/cert.pem")
  DHPARAM=$( [[ -f $DHPARAM_FILE ]] && cat "$DHPARAM_FILE" || echo "" )
}

# === Service-specific certificate bundling ===
generate_service_certs() {
  log INFO "Creating plex-certificate.pfx"
  /usr/bin/openssl pkcs12 -export \
    -inkey "$CERT_DIR/privkey.pem" \
    -in    "$CERT_DIR/cert.pem" \
    -certfile "$CERT_DIR/fullchain.pem" \
    -out   "$CERT_DIR/plex-certificate.pfx" \
    -passout pass:Password1! \
  2>&1 | /usr/bin/logger -t cert-deploy

  log INFO "Assembling znc.pem"
  cat "$CERT_DIR/privkey.pem" >  "$CERT_DIR/znc.pem"
  cat "$CERT_DIR/fullchain.pem" >> "$CERT_DIR/znc.pem"
  cat "$DHPARAM_FILE"          >> "$CERT_DIR/znc.pem"

  log INFO "Creating pihole.pem"
  cat "$CERT_DIR/fullchain.pem" "$CERT_DIR/privkey.pem" > "/etc/letsencrypt/live/$DOMAIN/pihole.pem"
}

###########################
# === Backup & Rollback ==
###########################
backup_current_certs() {
  local host=$1 ts path
  ts=$(date +%Y%m%d%H%M%S); path="$ROLLBACK_DIR/$host/$ts"; mkdir -p "$path"
  if [[ $host == local ]]; then cp -a "$CERT_DIR"/* "$path/"
  else ssh -i"$SSH_KEY" -p22 -oStrictHostKeyChecking=accept-new root@"${host}.${DOMAIN}" "mkdir -p /var/backups/certs/$ts && cp -a $REMOTE_CERT_DIR/* /var/backups/certs/$ts/"
    rsync -a -e "ssh -i $SSH_KEY -p22" "root@${host}.${DOMAIN}:${REMOTE_CERT_DIR}/." "$path/." || true
  fi
}

verify_nginx_backup() {
  mkdir -p "$TEMP_BACKUP_DIR"
  rsync -a -e "ssh -i $SSH_KEY" "${BACKUP_HOST}.${DOMAIN}:${BACKUP_DIR}/." "$TEMP_BACKUP_DIR/" || {
    log ERROR "nginx backup fetch failed"; rm -rf "$TEMP_BACKUP_DIR"; return 1; }
  local missing=0 size
  for cf in default.conf ${DOMAIN}.conf; do [[ -f "$TEMP_BACKUP_DIR/conf.d/$cf" ]] || { log WARN "missing $cf"; ((missing++)); } done
  size=$(du -sm "$TEMP_BACKUP_DIR" | awk '{print $1}')
  (( size < 1 )) && { log ERROR "backup too small"; rm -rf "$TEMP_BACKUP_DIR"; return 1; }
  rm -rf "$TEMP_BACKUP_DIR"
  (( missing )) && log WARN "backup incomplete" || log INFO "backup OK"
}

prepare_rollback() {
  ORIGINAL_CERT_HASH=(); local sum
  sum=$(sha256sum "$CERT_DIR/fullchain.pem" | cut -d' ' -f1)
  ORIGINAL_CERT_HASH[local]=$sum; backup_current_certs local
  for h in $HOSTS $BACKUP_HOST; do
    sum=$(ssh -i"$SSH_KEY" -p22 -oStrictHostKeyChecking=accept-new root@"${h}.${DOMAIN}" "sha256sum $REMOTE_CERT_DIR/fullchain.pem 2>/dev/null | cut -d' ' -f1" || echo none)
    ORIGINAL_CERT_HASH[$h]=$sum; backup_current_certs "$h"
  done
}

perform_rollback() {
  local host=$1 latest
  latest=$(find "$ROLLBACK_DIR/$host" -type d -name "[0-9]*" | sort | tail -n1)
  [[ -z $latest ]] && { log ERROR "no backup for $host"; return; }
  if [[ $host == local ]]; then cp -a "$latest"/* "$CERT_DIR/"; log INFO "local rollback done"
  else rsync -a -e "ssh -i $SSH_KEY -p22" "$latest/." "root@${host}.${DOMAIN}:${REMOTE_CERT_DIR}/."; log INFO "rolled back $host"; fi
}

execute_rollback() {
  for h in $HOSTS $BACKUP_HOST; do [[ "${HOST_DEPLOY_STATUS[$h]:-}" == failed ]] && perform_rollback "$h"; done
}

###########################
# === Deploy Helpers =====
###########################
verify_remote_cert() {
  local host=$1 port=$2 expect=$3
  local got
    if ! got=$(ssh -q $SSH_OPTS \
                  -i"$SSH_KEY" -p"$port" \
                  root@"${host}.${DOMAIN}" \
                  "sha256sum $REMOTE_CERT_DIR/fullchain.pem 2>/dev/null | cut -d' ' -f1"); then
    return 1
  fi
  [[ $got == $expect ]]
}

deploy_to_host() {
  local host=$1 port=${2:-22}
  log INFO "deploy to $host"
  HOST_DEPLOY_STATUS[$host]=pending

  if ! ping_host "${host}.${DOMAIN}"; then
    HOST_DEPLOY_STATUS[$host]=failed
    return
  fi

  check_remote_dependencies "$host" "$port" \
    || { HOST_DEPLOY_STATUS[$host]=failed; return; }

  # idempotency: skip if unchanged
  local local_sum remote_sum
  local_sum=$(sha256sum "$CERT_DIR/fullchain.pem" | cut -d' ' -f1)
  remote_sum=$(ssh -q -oConnectTimeout="$SSH_TIMEOUT" \
                  -i"$SSH_KEY" -p"$port" \
                  -oStrictHostKeyChecking=accept-new \
                  root@"${host}.${DOMAIN}" \
                  "sha256sum $REMOTE_CERT_DIR/fullchain.pem 2>/dev/null | cut -d' ' -f1" \
             || echo none)

  if [[ $local_sum == $remote_sum ]]; then
    log INFO "skip $host (cert unchanged)"
    HOST_DEPLOY_STATUS[$host]=skipped
    return
  fi

  if (( DRY_RUN )); then
    log INFO "[DRY-RUN] would rsync to $host"
    HOST_DEPLOY_STATUS[$host]=dry-run
    return
  fi

  # mkdir -p, quiet but log on failure
  if ! ssh -q $SSH_OPTS \
           -i"$SSH_KEY" -p"$port" \
           root@"${host}.${DOMAIN}" \
           "mkdir -p $REMOTE_CERT_DIR"; then
    log ERROR "mkdir on $host failed"
    HOST_DEPLOY_STATUS[$host]=failed
    return
  fi

  retry 3 2 rsync -aL -e "ssh -q $SSH_OPTS -i $SSH_KEY -p$port" \
    "${CERT_DIR}/." "root@${host}.${DOMAIN}:${REMOTE_CERT_DIR}/." \
    || { log ERROR "rsync to $host failed"; HOST_DEPLOY_STATUS[$host]=failed; return; }

  if ! verify_remote_cert "$host" "$port" "$local_sum"; then
    log ERROR "verify on $host failed"
    HOST_DEPLOY_STATUS[$host]=failed
    return
  fi

  # --- sync file permissions ---
  for f in privkey.pem fullchain.pem cert.pem; do
    perms=$(stat -c "%a" "$CERT_DIR/$f")
    if ssh -q $SSH_OPTS \
            -i"$SSH_KEY" -p"$port" \
            root@"${host}.${DOMAIN}" \
            "chmod $perms $REMOTE_CERT_DIR/$f"; then
      log INFO "set perms $perms on $host:$REMOTE_CERT_DIR/$f"
    else
      log WARN "failed to set perms on $host:$REMOTE_CERT_DIR/$f"
    fi
  done

  log INFO "deployed to $host"
  HOST_DEPLOY_STATUS[$host]=success
}

# This should be defined earlier in your script
wait_for_free_slot() {
  local max_parallel=${MAX_PARALLEL:-5}  # Default to 5 parallel processes if not set
  
  while [[ $(jobs -r | wc -l) -ge $max_parallel ]]; do
    sleep 1
  done
}

# This should also be defined earlier in your script
wait_all() {
  log INFO "Waiting for all background processes to complete"
  wait
  log INFO "All processes completed"
}

# Your fixed deploy_all function
deploy_all() {
  log INFO "starting deploy_all function"
  # Check DRY_RUN status
  log INFO "DRY_RUN status: $DRY_RUN"
  local RESULT_FILE
  
  # Initialize PIDS array if not already initialized
  PIDS=()
  
  # Check HOST_DEPLOY_STATUS
  log INFO "BACKUP_HOST: $BACKUP_HOST"

  
  # Always deploy to BACKUP_HOST first
  deploy_to_host "$BACKUP_HOST" 22
  
  if [[ ( "${HOST_DEPLOY_STATUS[$BACKUP_HOST]}" == "success" || "${HOST_DEPLOY_STATUS[$BACKUP_HOST]}" == "skipped" ) && $DRY_RUN -eq 0 ]]; then
    # 0) Make sure backup directories exist with proper permissions
    log INFO "Conditions met, proceeding with backup operations (Status: ${HOST_DEPLOY_STATUS[$BACKUP_HOST]})"
    ssh -q $SSH_OPTS -i"$SSH_KEY" root@"${BACKUP_HOST}.${DOMAIN}" \
      "mkdir -p ${SSL_BACKUP_DIR} ${BACKUP_DIR}" \
    && log INFO "backup directories confirmed on ${BACKUP_HOST}" \
    || log WARN "failed to create backup directories on ${BACKUP_HOST}"
 
    # 1) backup certs (dereferenced) to SSL_BACKUP_DIR
    log INFO "backup certificates to $BACKUP_HOST"
    rsync -pEvaLu -e "ssh -q $SSH_OPTS -i $SSH_KEY" \
      "${CERT_DIR}/." \
      "root@${BACKUP_HOST}.${DOMAIN}:${SSL_BACKUP_DIR}/." \
    2>&1 | logger -t cert-deploy || log WARN "cert backup to $BACKUP_HOST failed"
 
    # 2) backup nginx configs to BACKUP_DIR
    log INFO "backup nginx configs to $BACKUP_HOST"
    rsync -pEvaLu --exclude 'modules/*' \
      -e "ssh -q $SSH_OPTS -i $SSH_KEY" \
      /etc/nginx/. \
      "root@${BACKUP_HOST}.${DOMAIN}:${BACKUP_DIR}/." \
    2>&1 | logger -t cert-deploy || log WARN "nginx backup to $BACKUP_HOST failed"
 
    # 3) fix ownership on backup host for both directories
    log INFO "setting ownership to ${USERNAME}:${USERNAME} on $BACKUP_HOST backups"
    ssh -q $SSH_OPTS -i"$SSH_KEY" root@"${BACKUP_HOST}.${DOMAIN}" \
      "chown -R ${USERNAME}:${USERNAME} ${SSL_BACKUP_DIR} ${BACKUP_DIR}" \
    && log INFO "ownership set on ${BACKUP_HOST}" \
    || log WARN "failed to set ownership on ${BACKUP_HOST}"
  else
    log WARN "Conditions NOT met for backup. Status: ${HOST_DEPLOY_STATUS[$BACKUP_HOST]:-unknown}, DRY_RUN: $DRY_RUN"
  fi
  
  # ——— parallel deploy to remaining hosts ———
  RESULT_FILE=$(mktemp)
  log INFO "HOSTS contains: $HOSTS"
  for h in $HOSTS; do
    [[ $h == $BACKUP_HOST ]] && continue
    # if this host is marked fragile, do it serially
    if [[ " ${FRAGILE_HOSTS[*]} " == *" $h "* ]]; then
      log INFO "serial deploy for fragile host $h"
      deploy_to_host "$h" 22
      echo "$h:${HOST_DEPLOY_STATUS[$h]:-unknown}" >>"$RESULT_FILE"
    else
      if (( DRY_RUN )); then
        deploy_to_host "$h" 22
        echo "$h:${HOST_DEPLOY_STATUS[$h]:-unknown}" >>"$RESULT_FILE"
      else
        wait_for_free_slot
        (
          deploy_to_host "$h" 22
          echo "$h:${HOST_DEPLOY_STATUS[$h]:-unknown}"
        ) >>"$RESULT_FILE" &
        PIDS+=( $! )
      fi
    fi
  done
  
  # wait for all background deploys to finish
  wait_all

  # read each “host:status” line back into the global array
  while IFS=: read -r host status; do
    HOST_DEPLOY_STATUS[$host]=$status
  done <"$RESULT_FILE"
  rm -f "$RESULT_FILE"

  # ——— Retry any failed hosts serially ———
  local serial_retry=()
  for h in $HOSTS; do
    # Skip the backup host, it's already handled
    [[ $h == $BACKUP_HOST ]] && continue
    if [[ "${HOST_DEPLOY_STATUS[$h]:-}" == "failed" ]]; then
      serial_retry+=( "$h" )
    fi
  done
  if (( ${#serial_retry[@]} )); then
    log WARN "Retrying failed hosts one-by-one: ${serial_retry[*]}"
    for h in "${serial_retry[@]}"; do
      deploy_to_host "$h" 22
    done
  fi
  
  log INFO "deploy_all done"
}

###########################
# === Proxmox Pre-check ===
###########################
# Returns 0 if Proxmox node cert is out-of-date, 1 if up-to-date or unreachable
check_proxmox_out_of_date() {
  local node="$1"
  local url_var="${node^^}_URL"
  local host_port="${!url_var#https://}"
  host_port="${host_port%/}"

  log INFO "Checking Proxmox $node certificate via TLS fingerprint"

  # Fetch remote cert via openssl s_client
  local remote_fp local_fp
  if ! remote_fp=$( \
       openssl s_client -connect "$host_port" -showcerts </dev/null 2>/dev/null \
       | openssl x509 -noout -pubkey \
       | openssl pkey -pubin -outform DER \
       | sha256sum | cut -d' ' -f1); then
    log INFO "Proxmox $node unreachable or TLS fetch failed, skipping check"
    return 1
  fi

  # Compute local fingerprint
  local_fp=$(openssl x509 -in "$CERT_DIR/cert.pem" -pubkey -noout \
             | openssl pkey -pubin -outform DER \
             | sha256sum | cut -d' ' -f1)

  if [[ "$remote_fp" == "$local_fp" ]]; then
    log INFO "Proxmox $node certificate up to date (fp $local_fp)"
    return 1
  else
    log INFO "Proxmox $node certificate out-of-date (local $local_fp vs remote $remote_fp)"
    return 0
  fi
}

###########################
# === Service Restarts ====
###########################

# Check if a service supports reload
should_restart() {
  local host=$1 port=$2 svc=$3
  ssh -i"$SSH_KEY" -p"$port" -oStrictHostKeyChecking=accept-new \
    root@"${host}.${DOMAIN}" \
    "systemctl show $svc --property=CanReload" \
    | grep -q 'CanReload=yes'
}

# Reload local nginx
restart_services() {
  log INFO "reloading local nginx"
  (( DRY_RUN )) && return
  if systemctl is-active --quiet nginx; then
    systemctl reload nginx && log INFO "nginx reloaded" || log WARN "failed to reload nginx"
  else
    log WARN "nginx not running"
  fi
}

# Remote service restart/reload
restart_remote_services() {
  local hc=$1 host port services action cmd
  IFS=: read host port services <<<"$hc"
  log INFO "processing services on $host: $services"

  if ! ping_host "${host}.${DOMAIN}"; then
    return
  fi

  if (( DRY_RUN )); then
    for svc in $services; do
      if should_restart "$host" "$port" "$svc"; then action="restart"; else action="reload"; fi
      log INFO "[DRY-RUN] would $action $svc on $host"
    done
    return
  fi

  cmd=""
  for svc in $services; do
    if should_restart "$host" "$port" "$svc"; then
      cmd+="systemctl reload  $svc && "
    else
      cmd+="systemctl restart $svc && "
    fi
  done
  cmd=${cmd% && }

  ssh -q $SSH_OPTS -i"$SSH_KEY" -p"$port" \
    root@"${host}.${DOMAIN}" "$cmd" \
    && log INFO "services on $host reloaded/restarted successfully" \
    || log ERROR "services on $host failed to reload/restart"
}

# Parallel remote restarts
restart_all_remote() {
  log INFO "starting remote restarts"
  for hc in "${HOST_SERVICES[@]}"; do
    IFS=: read host port services <<<"$hc"
    # only restart if we did deploy a new cert
    # if this host is fragile, do not background
    if [[ " ${FRAGILE_HOSTS[*]} " == *" $host "* ]]; then
      log INFO "serial restart for fragile host $host"
      restart_remote_services "$hc"
    elif [[ "${HOST_DEPLOY_STATUS[$host]:-}" == "success" ]]; then
      wait_for_free_slot
      restart_remote_services "$hc" &
      PIDS+=( $! )
    else
      log INFO "skip service restart on $host (status: ${HOST_DEPLOY_STATUS[$host]:-})"
    fi
  done
  wait_all
  log INFO "remote restarts done"
}

###########################
# === Proxmox Update  ====
###########################
update_proxmox() {
  log INFO "Updating Proxmox certificates"

  # Extract user@realm and tokenid from PROXMOX_USER (expects format user@realm!tokenid)
  if [[ "$PROXMOX_USER" =~ ^([^!]+)!(.+)$ ]]; then
    local user_realm="${BASH_REMATCH[1]}"
    local token_id="${BASH_REMATCH[2]}"
  else
    handle_error "PROXMOX_USER must be in 'user@realm!tokenid' format"
  fi

  if (( DRY_RUN )); then
    for node in proxmox01 proxmox02; do
      HOST_DEPLOY_STATUS["$node"]="dry-run"
    done
    log INFO "[DRY-RUN] Would update Proxmox certificates for nodes proxmox01, proxmox02"
    return
  fi

  for node in proxmox01 proxmox02; do
    local url_var="${node^^}_URL"
    local base_url="${!url_var}"
    local api_url="${base_url}/api2/json/nodes/${node}/certificates/custom"

    log INFO "Checking reachability of ${node} (${base_url})"
    if ! curl --silent --show-error --connect-timeout 5 -k "$base_url" >/dev/null; then
      log WARN "${node} unreachable, skipping"
      HOST_DEPLOY_STATUS["${node}"]="failed"
      continue
    fi

    log INFO "Posting new certificates to ${node}"

    # Build curl command array
    local curl_args=(
      --silent --show-error --fail -k -v
      -X POST "$api_url"
      -H "Authorization: PVEAPIToken=${user_realm}!${token_id}=${PROXMOX_TOKEN}"
      -H "Content-Type: application/x-www-form-urlencoded"
      --data-urlencode "key=${PRIVKEY}"
      --data-urlencode "certificates=${FULLCHAIN}"
      --data-urlencode "restart=1"
      --data-urlencode "force=1"
      --data-urlencode "node=${node}"
    )

    # Capture output for troubleshooting
    local resp
    if resp=$(curl "${curl_args[@]}" 2>&1); then
      log INFO "Proxmox ${node} updated successfully"
      # Optionally clear any previous 'failed' tag
      HOST_DEPLOY_STATUS["${node}"]="success"
    else
      log ERROR "Proxmox ${node} update failed (HTTP/1.1 401 or other)."
      # Log a snippet of the response around the error to help debug
      log ERROR "Response snippet: $(echo "$resp" | sed -n '1,20p')"
      HOST_DEPLOY_STATUS["${node}"]="failed"
    fi
  done
}

###########################
# === Parallel Control ===
###########################
PIDS=()
wait_for_free_slot() {
  while (( ${#PIDS[@]} >= MAX_PARALLEL )); do
    for i in "${!PIDS[@]}"; do kill -0 "${PIDS[i]}" &>/dev/null || unset 'PIDS[i]'; done
    PIDS=( "${PIDS[@]}" ); sleep 0.2
  done
}
wait_all() { for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null; done; PIDS=(); }

###########################
# === Main Entry Point ===
###########################
main() {
  touch "$LOG_FILE"
  log INFO "=== START ==="

  validate_environment
  deploy_all
  read_certs
  generate_service_certs
  validate_certificates || { (( FORCE )) || handle_error "certificate validation failed"; }

  if (( ROLLBACK )); then
    prepare_rollback
    execute_rollback
    rm -f "$LOCKFILE"
    exit 0
  fi

  if (( SERVICES_ONLY == 0 )); then
    deploy_all
  fi

  if (( DEPLOY_ONLY == 0 )); then
    restart_services
    restart_all_remote
  fi

  # 3) Proxmox pre-check: mark each node pending/skipped, then conditionally update
  local do_deploy=0
  for node in proxmox01 proxmox02; do
    if check_proxmox_out_of_date "$node"; then
      HOST_DEPLOY_STATUS["$node"]="pending"
      (( do_deploy++ ))
    else
      HOST_DEPLOY_STATUS["$node"]="skipped"
    fi
  done

  if (( do_deploy > 0 )); then
    update_proxmox
  else
    log INFO "All Proxmox certificates are current or unreachable; skipping Proxmox update"
  fi

  # === Summary ===
  log INFO "=== SUMMARY BLOCK ENTERED ==="
  for h in $BACKUP_HOST $HOSTS proxmox01 proxmox02; do
    log INFO "$h status: ${HOST_DEPLOY_STATUS[$h]:-unset}"
  done

  local deployed=0 skipped=0 dryrun=0 failed=0
  for h in $BACKUP_HOST $HOSTS proxmox01 proxmox02; do
    case "${HOST_DEPLOY_STATUS[$h]:-}" in
      success)   (( deployed++ )) ;;
      skipped)   (( skipped++ )) ;;
      dry-run)   (( dryrun++ )) ;;
      failed)    (( failed++ )) ;;
    esac
  done

  log INFO "SUMMARY: deployed=$deployed skipped=$skipped dry-run=$dryrun failed=$failed"
  echo "[SUMMARY] Deployed: $deployed, Skipped: $skipped, Dry-run: $dryrun, Failed: $failed"

  if (( failed > 0 )); then
    local flist=""
    for h in $BACKUP_HOST $HOSTS proxmox01 proxmox02; do
      [[ "${HOST_DEPLOY_STATUS[$h]}" == "failed" ]] && flist+="$h "
    done
    log WARN "Failed hosts: $flist"
    echo "[FAILURES] Hosts with errors: $flist"
  fi

  if (( deployed == 0 && skipped == 0 && dryrun == 0 && failed == 0 )); then
    log WARN "No deployments attempted. Did you forget to run in a mode that triggers action?"
    echo "[SUMMARY] No actions were executed. Check flags or dry-run mode."
  fi

  rm -f "$LOCKFILE"
}

main "$@"
