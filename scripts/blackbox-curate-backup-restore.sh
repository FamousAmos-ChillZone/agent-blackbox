#!/usr/bin/env bash
# ============================================================================
# Agent Blackbox — restore one curator-state backup into an EMPTY curate home
# ============================================================================
# Counterpart of blackbox-curate-backup-pull.sh (proposal §03.1, F-037; the
# restore target is "restore into an empty curate home ≤ 4 h").
#
#   blackbox-curate-backup-restore.sh --archive <file.tar.gz.cms> \
#       --key <backup-key.pem> --target <curate home>
#
# The target must be absent or an empty directory — a restore never merges into
# or overwrites live curator state. The private key must not live inside the
# target or this machine's curate home. Its passphrase is asked for by openssl
# itself at the terminal; for an unattended restore test, BLACKBOX_RESTORE_PASSIN may
# name an openssl pass source of the form env:VAR, file:PATH or fd:N
# (pass:<literal> is refused: it would put the passphrase on a command line).
# This script never prints, logs or stores the passphrase or the key.
#
# Safety: the archive is authenticated (AES-256-GCM) and fully decrypted to a
# private temporary file BEFORE anything is extracted, so a tampered or
# truncated archive extracts nothing. Every member must sit under curate/ with
# no absolute path or '..', and the result must contain no links.
#
# Exit: 0 restored; 1 decryption/extraction failed; 2 bad arguments.
# Written for bash 3.2 and parse-tested under bash 5 (LES-037/038).
# ============================================================================

set -euo pipefail
umask 077

log() { printf '[curate-restore] %s\n' "$*"; }
fail() { printf '[curate-restore] ERROR: %s\n' "$*" >&2; exit "${2:-1}"; }

usage() {
    sed -n '2,/^# =====/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'
}

# Same helpers as the pull script: physical path of a maybe-missing path, and
# containment. Kept as copies because the two scripts ship standalone.
physical_path() {
    local path="$1" suffix=""
    case "$path" in /*) ;; *) path="$PWD/$path" ;; esac
    while [ ! -d "$path" ]; do
        suffix="/$(basename "$path")$suffix"
        path="$(dirname "$path")"
    done
    printf '%s%s\n' "$(cd "$path" && pwd -P)" "$suffix"
}

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

passin_arguments() {
    local source="${BLACKBOX_RESTORE_PASSIN:-}"
    case "$source" in
        '') ;;
        env:*|file:*|fd:*) printf '%s\n' "-passin" "$source" ;;
        *) fail "BLACKBOX_RESTORE_PASSIN must be env:VAR, file:PATH or fd:N" 2 ;;
    esac
}

# Every member under curate/, none absolute, none with a '..' component.
check_members() {
    local listing="$1" member
    while read -r member; do
        case "$member" in
            curate|curate/|curate/*) ;;
            *) fail "archive member outside curate/: $member" ;;
        esac
        case "/$member/" in */../*) fail "archive member with '..': $member" ;; esac
    done < "$listing"
}

main() {
    local archive="" key="" target=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --archive) archive="${2:-}"; shift 2 || fail "--archive needs a file" 2 ;;
            --key) key="${2:-}"; shift 2 || fail "--key needs a file" 2 ;;
            --target) target="${2:-}"; shift 2 || fail "--target needs a directory" 2 ;;
            -h|--help) usage; exit 0 ;;
            *) fail "unknown argument: $1 (try --help)" 2 ;;
        esac
    done
    [ -n "$archive" ] && [ -n "$key" ] && [ -n "$target" ] || fail "--archive, --key and --target are all required" 2
    [ -f "$archive" ] || fail "archive not found: $archive" 2
    [ -f "$key" ] || fail "key not found: $key" 2
    if [ -e "$target" ]; then
        [ -d "$target" ] || fail "target exists and is not a directory: $target" 2
        [ -z "$(ls -A "$target")" ] || fail "target is not empty — restore only into an empty curate home: $target" 2
    fi
    is_inside "$key" "$target" && fail "the backup key must live outside the target curate home" 2
    is_inside "$key" "$(local_curate_home)" && fail "the backup key must live outside the curate home ($(local_curate_home))" 2
    case "$(openssl version 2>/dev/null)" in
        "OpenSSL 3"*) ;;
        *) fail "need OpenSSL 3 (macOS's LibreSSL cannot read CMS AES-GCM)" 2 ;;
    esac

    local parent work passin
    parent="$(dirname "$(physical_path "$target")")"
    mkdir -p "$parent"
    work="$(mktemp -d "$parent/.curate-restore.XXXXXX")"
    RESTORE_WORK="$work"  # global: the EXIT trap runs after main's locals are gone
    trap 'rm -rf "$RESTORE_WORK"' EXIT
    passin="$(passin_arguments)"

    # Decrypt fully first: GCM's tag is checked only at the end of the stream.
    # shellcheck disable=SC2086  # passin is either empty or two safe words
    if ! openssl cms -decrypt -binary -inform DER -inkey "$key" $passin \
            -in "$archive" -out "$work/archive.tar.gz" 2>"$work/openssl.err"; then
        sed -n '1,5p' "$work/openssl.err" >&2
        fail "could not decrypt $archive (wrong key or passphrase, or the archive is damaged/tampered)"
    fi
    tar -tzf "$work/archive.tar.gz" > "$work/members" || fail "the decrypted archive is not a readable tar.gz"
    check_members "$work/members"
    mkdir "$work/extract"
    tar -xpzf "$work/archive.tar.gz" -C "$work/extract" || fail "extraction failed"
    [ -d "$work/extract/curate" ] || fail "the archive holds no curate/ directory"
    [ -z "$(find "$work/extract" -type l)" ] || fail "the archive holds links; a curate home has none — refused"

    [ -d "$target" ] && rmdir "$target"
    mv "$work/extract/curate" "$target"
    log "restored $(find "$target" -type f | wc -l | tr -d ' ') files into $target"
}

main "$@"
