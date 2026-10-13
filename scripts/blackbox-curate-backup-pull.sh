#!/usr/bin/env bash
# ============================================================================
# Agent Blackbox — curator-state backup, PULLED by the administering Mac
# ============================================================================
# Each curator node keeps state nothing else has in ONE directory, its curate
# home ($BLACKBOX_HOME/curate): provenance.jsonl (the only map from provenance
# ids to report subjects), proposals, budget, consent, the keep-alive store,
# the signing log, the publish ledger, lab/ and the sources/ caches. This
# script copies that whole directory from every node into an encrypted archive
# on this Mac, nightly, under launchd (blackbox-curate-backup.plist.template).
#
# Trust direction (proposal F-052): the Mac PULLS over Tailscale SSH with the
# administration key it already holds. The node holds no credential to the
# Mac, and the ONLY command run on a node is `tar -C <parent> -czf - curate`,
# which writes the archive to stdout and nothing to the node's disk.
# `--dry-run` prints that command per node without connecting.
#
# Encryption at rest (F-037, D33): archives are CMS (AES-256-GCM, authenticated)
# encrypted to a RECIPIENT CERTIFICATE. The certificate is public material, so
# this unattended job holds no secret at all; the matching private key is
# passphrase-protected (or, under D33, on a hardware token) and is needed only
# by blackbox-curate-backup-restore.sh. The script refuses a certificate file
# that contains a private key, and any certificate kept inside a curate home.
#
# One-time key setup (the passphrase is typed at openssl's own prompt, never
# on a command line; keep backup-key.pem OFF this Mac, e.g. on a USB stick):
#   openssl req -x509 -newkey rsa:4096 -days 3650 -subj "/CN=blackbox-curate-backup" \
#       -keyout backup-key.pem -out backup-recipient.pem
#
# Configuration (environment; launchd sets these in the plist):
#   BLACKBOX_BACKUP_NODES      file, one node per line: <name> <ssh-target> [<curate path>]
#                              (path default ~/.hermes/blackbox/curate; '#' comments)
#   BLACKBOX_BACKUP_RECIPIENT  the recipient certificate (PEM)               [required]
#   BLACKBOX_BACKUP_DIR        archive folder        (default ~/BlackboxCurateBackups)
#   BLACKBOX_BACKUP_KEEP       archives kept per node                      (default 30)
#   BLACKBOX_HOME / HERMES_HOME   locate THIS Mac's curate home for the key check
#
# Usage: blackbox-curate-backup-pull.sh [--dry-run]
# Exit: 0 every node pulled; 1 at least one node failed; 2 bad configuration.
#
# Written for bash 3.2 (macOS /bin/bash) and parse-tested under bash 5
# (LES-037/038): no mapfile, no associative arrays, no ${v//pat/rep}.
# ============================================================================

set -euo pipefail
umask 077

DRY_RUN=0
SAFE_PATH_PATTERN='^(~/)?[A-Za-z0-9._/-]+$'
SAFE_NAME_PATTERN='^[A-Za-z0-9._-]+$'
SAFE_TARGET_PATTERN='^[A-Za-z0-9._@-]+$'
DEFAULT_REMOTE_CURATE_HOME='~/.hermes/blackbox/curate'

log() { printf '[curate-backup] %s\n' "$*"; }
die_config() { printf '[curate-backup] ERROR: %s\n' "$*" >&2; exit 2; }

usage() {
    sed -n '2,/^# =====/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'
}

# Physical absolute path of a file or directory that may not exist yet
# (its nearest existing ancestor is resolved, the rest appended).
physical_path() {
    local path="$1" suffix=""
    case "$path" in /*) ;; *) path="$PWD/$path" ;; esac
    while [ ! -d "$path" ]; do
        suffix="/$(basename "$path")$suffix"
        path="$(dirname "$path")"
    done
    printf '%s%s\n' "$(cd "$path" && pwd -P)" "$suffix"
}

# True when $1 is $2 or lies below it.
is_inside() {
    local child parent
    child="$(physical_path "$1")"
    parent="$(physical_path "$2")"
    case "$child/" in "$parent"/*) return 0 ;; esac
    return 1
}

local_curate_home() {
    local hermes_home="${HERMES_HOME:-$HOME/.hermes}"
    printf '%s/curate\n' "${BLACKBOX_HOME:-$hermes_home/blackbox}"
}

# The one command a node ever runs: the curate home as a gzip tar on stdout.
# Validated characters only (no quoting needed); a leading ~/ is left for the
# node's shell to expand to the node user's home.
remote_read_command() {
    local curate_path="$1"
    printf 'tar -C %s -czf - curate\n' "$(dirname "$curate_path")"
}

require_openssl_3() {
    command -v openssl >/dev/null 2>&1 || die_config "openssl not found (install OpenSSL 3; macOS's LibreSSL lacks CMS AES-GCM)"
    case "$(openssl version)" in
        "OpenSSL 3"*) ;;
        *) die_config "need OpenSSL 3 for CMS AES-256-GCM, found: $(openssl version) — put Homebrew's openssl first on PATH" ;;
    esac
}

check_recipient() {
    local cert="${BLACKBOX_BACKUP_RECIPIENT:-}"
    [ -n "$cert" ] || die_config "BLACKBOX_BACKUP_RECIPIENT is not set (the recipient certificate)"
    [ -f "$cert" ] || die_config "recipient certificate not found: $cert"
    if is_inside "$cert" "$(local_curate_home)"; then
        die_config "the backup key must live outside the curate home ($(local_curate_home)): $cert"
    fi
    if is_inside "$cert" "$BACKUP_DIR"; then
        die_config "the backup key must not sit beside the archives ($BACKUP_DIR): $cert"
    fi
    if grep -q 'PRIVATE KEY' "$cert"; then
        die_config "the recipient file holds a private key — give only the certificate; the private key stays off this Mac"
    fi
    openssl x509 -in "$cert" -noout 2>/dev/null || die_config "not a PEM certificate: $cert"
}

# Prints "name<TAB>target<TAB>path" per valid line; exits 2 on any bad line.
read_nodes() {
    local nodes_file="${BLACKBOX_BACKUP_NODES:-}" name target path extra line_number=0
    [ -n "$nodes_file" ] || die_config "BLACKBOX_BACKUP_NODES is not set (the node list file)"
    [ -f "$nodes_file" ] || die_config "node list not found: $nodes_file"
    while read -r name target path extra || [ -n "$name" ]; do
        line_number=$((line_number + 1))
        case "$name" in ''|'#'*) continue ;; esac
        path="${path:-$DEFAULT_REMOTE_CURATE_HOME}"
        [ -z "$extra" ] || die_config "$nodes_file:$line_number: too many fields"
        [[ "$name" =~ $SAFE_NAME_PATTERN ]] || die_config "$nodes_file:$line_number: bad node name '$name'"
        [[ "$target" =~ $SAFE_TARGET_PATTERN ]] && [ "${target#-}" = "$target" ] \
            || die_config "$nodes_file:$line_number: bad ssh target '$target'"
        [[ "$path" =~ $SAFE_PATH_PATTERN ]] || die_config "$nodes_file:$line_number: bad curate path '$path'"
        case "/$path/" in */../*) die_config "$nodes_file:$line_number: '..' not allowed in '$path'" ;; esac
        [ "$(basename "$path")" = "curate" ] || die_config "$nodes_file:$line_number: the path must be a curate home (…/curate): '$path'"
        printf '%s\t%s\t%s\n' "$name" "$target" "$path"
    done < "$nodes_file"
}

# Drops all but the newest $KEEP archives of one node (names sort by time).
prune_archives() {
    local node_dir="$1" name="$2" count excess
    count="$(find "$node_dir" -maxdepth 1 -name "$name-*.tar.gz.cms" | wc -l | tr -d ' ')"
    excess=$((count - KEEP))
    [ "$excess" -gt 0 ] || return 0
    find "$node_dir" -maxdepth 1 -name "$name-*.tar.gz.cms" | sort | head -n "$excess" |
        while read -r old; do rm -f -- "$old"; log "$name: pruned $(basename "$old")"; done
}

pull_node() {
    local name="$1" target="$2" path="$3" command node_dir stamp partial archive
    command="$(remote_read_command "$path")"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "$name: would run on $target (read-only): $command"
        return 0
    fi
    node_dir="$BACKUP_DIR/$name"
    mkdir -p "$node_dir"
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    archive="$node_dir/$name-$stamp.tar.gz.cms"
    partial="$archive.partial"
    # ssh: never prompt, never forward the agent or X, no stdin to the node.
    if ssh -T -n -o BatchMode=yes -o ForwardAgent=no -o ForwardX11=no \
            -o ClearAllForwardings=yes -o ConnectTimeout=20 "$target" "$command" |
        openssl cms -encrypt -binary -stream -aes-256-gcm -outform DER \
            -recip "$BLACKBOX_BACKUP_RECIPIENT" -out "$partial" \
        && [ -s "$partial" ]; then
        mv -- "$partial" "$archive"
        log "$name: saved $(basename "$archive") ($(wc -c < "$archive" | tr -d ' ') bytes)"
        prune_archives "$node_dir" "$name"
        return 0
    fi
    rm -f -- "$partial"
    log "$name: FAILED — no archive written (ssh to $target, the remote tar, or encryption failed)" >&2
    return 1
}

main() {
    case "${1:-}" in
        '') ;;
        --dry-run) DRY_RUN=1 ;;
        -h|--help) usage; exit 0 ;;
        *) die_config "unknown argument: $1 (try --help)" ;;
    esac
    BACKUP_DIR="${BLACKBOX_BACKUP_DIR:-$HOME/BlackboxCurateBackups}"
    KEEP="${BLACKBOX_BACKUP_KEEP:-30}"
    [[ "$KEEP" =~ ^[1-9][0-9]*$ ]] || die_config "BLACKBOX_BACKUP_KEEP must be a positive integer: $KEEP"
    if is_inside "$BACKUP_DIR" "$(local_curate_home)"; then
        die_config "the archive folder must live outside the curate home: $BACKUP_DIR"
    fi
    require_openssl_3
    check_recipient
    local nodes failures=0 name target path
    nodes="$(read_nodes)"
    [ -n "$nodes" ] || die_config "no nodes listed in $BLACKBOX_BACKUP_NODES"

    if [ "$DRY_RUN" -eq 0 ]; then
        PULL_LOCK="$BACKUP_DIR/.pull.lock"
        mkdir -p "$BACKUP_DIR"
        mkdir "$PULL_LOCK" 2>/dev/null || die_config "another pull is running (remove $PULL_LOCK if it is stale)"
        trap 'rmdir "$PULL_LOCK" 2>/dev/null || true' EXIT
    fi
    while IFS="$(printf '\t')" read -r name target path; do
        pull_node "$name" "$target" "$path" < /dev/null || failures=$((failures + 1))
    done <<< "$nodes"
    if [ "$failures" -gt 0 ]; then
        log "$failures node(s) failed" >&2
        exit 1
    fi
    log "done"
}

main "$@"
