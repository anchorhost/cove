#!/bin/bash

# ====================================================
#  Cove - Main Script
#  Contains global configurations, helper functions,
#  and the main command routing logic.
# ====================================================

# Ensure Homebrew/user bin dirs are on PATH. Callers like launchd and
# systemd hand down a minimal PATH (/usr/bin:/bin:/usr/sbin:/sbin), which
# means the dashboard's shell_exec of cove fails to find gum/wp/frankenphp.
# We only prepend dirs that actually exist and aren't already on PATH.
for _cove_bin in /opt/homebrew/bin /opt/nanobrew/bin /opt/nanobrew/prefix/bin /usr/local/bin /usr/local/sbin "$HOME/.local/bin"; do
    if [ -d "$_cove_bin" ] && [[ ":$PATH:" != *":$_cove_bin:"* ]]; then
        PATH="$_cove_bin:$PATH"
    fi
done
unset _cove_bin
export PATH

# --- OS & Package Manager Detection ---
OS=""
PKG_MANAGER=""
# macOS package/service manager. Either "brew" (Homebrew, the default) or
# "nb" (nanobrew). nanobrew reuses Homebrew's formulas/bottles and supports
# `nb install` + `nb services`, so Cove can drive it through the same code
# paths. Left empty on Linux. See setup_environment for the detection rules.
MAC_BREW=""
SUDO_CMD="sudo"
IS_WSL=false
BIN_DIR="/usr/local/bin"

setup_environment() {
    local os_name
    os_name=$(uname -s)

    # --- Check for MacOS ---
    if [ "$os_name" = "Darwin" ]; then
        OS="macos"
        PKG_MANAGER="brew"
        SUDO_CMD=""

        # Pick the macOS package/service manager. Homebrew stays the default
        # whenever it's present (its mariadb post_install hook initializes the
        # data dir for us). nanobrew is used when the user forces it via
        # COVE_PKG_MANAGER=nanobrew|nb, or when only `nb` is installed.
        case "${COVE_PKG_MANAGER:-}" in
            nanobrew|nb)
                MAC_BREW="nb"
                ;;
            brew|homebrew)
                MAC_BREW="brew"
                ;;
            *)
                if command -v brew &>/dev/null; then
                    MAC_BREW="brew"
                elif command -v nb &>/dev/null; then
                    MAC_BREW="nb"
                else
                    MAC_BREW="brew" # default; install will guide the user
                fi
                ;;
        esac

        # Architecture detection for MacOS Homebrew paths
        if [ "$(uname -m)" = "arm64" ]; then
            BIN_DIR="/opt/homebrew/bin"
        else
            BIN_DIR="/usr/local/bin"
        fi

        return 0 # Success, exit function
    fi

    # --- Check for Linux ---
    if [ "$os_name" = "Linux" ]; then
        OS="linux"
        BIN_DIR="/usr/local/bin" # Standard for Linux
        
        # Check if running in WSL
        if grep -qEi "(Microsoft|WSL)" /proc/version 2>/dev/null; then
            IS_WSL=true
        fi
        
        if [ ! -f /etc/os-release ]; then
            echo "❌ ERROR: Cannot detect Linux distribution." >&2
            exit 1
        fi
        # shellcheck source=/dev/null
        . /etc/os-release
        if [[ "$ID" == "ubuntu" || "$ID" == "debian" || "$ID_LIKE" == *"debian"* ]]; then
            PKG_MANAGER="apt"
        elif [[ "$ID" == "fedora" || "$ID" == "centos" || "$ID" == "rhel" || "$ID_LIKE" == *"fedora"* || "$ID_LIKE" == *"rhel"* ]]; then
            PKG_MANAGER="dnf"
        else
            echo "❌ ERROR: Unsupported Linux distribution: $ID." >&2
            echo "Supported: Ubuntu, Debian, Fedora, CentOS, RHEL and derivatives." >&2
            exit 1
        fi
        
        if [ "$(id -u)" -eq 0 ]; then
            SUDO_CMD=""
        fi
        return 0 # Success, exit function
    fi
    
    # --- If neither of the above, it's an unsupported OS ---
    echo "❌ ERROR: Unsupported OS: $os_name" >&2
    exit 1
}

# macOS service control across Homebrew (`brew services`) and nanobrew
# (`nb services`). nanobrew has no `restart` subcommand, so emulate it with
# stop+start. Mirrors `brew services <action> <svc>` for every caller.
pkg_service() {
    local action="$1"   # start | stop | restart | list
    local svc="$2"      # service name (omitted for list)

    # Collect args without a trailing empty string — `brew services list ""`
    # treats "" as a service filter and returns nothing.
    local -a args=("$action")
    [ -n "$svc" ] && args+=("$svc")

    if [ "$MAC_BREW" = "nb" ]; then
        if [ "$action" = "restart" ]; then
            nb services stop "$svc" &>/dev/null
            nb services start "$svc"
            return $?
        fi
        nb services "${args[@]}"
        return $?
    fi

    brew services "${args[@]}"
}

# Block until MariaDB accepts connections, or give up after $1 seconds.
mariadb_wait_ready() {
    local max="${1:-10}" i=0
    while ! mysqladmin ping --silent &>/dev/null; do
        sleep 1
        i=$((i + 1))
        [ "$i" -ge "$max" ] && return 1
    done
    return 0
}

# Start MariaDB on macOS via the active package manager. Homebrew's mariadb
# formula initializes the data directory in its post_install hook, but
# nanobrew skips Ruby post_install hooks — so on a fresh nanobrew install the
# service starts yet never accepts connections. Detect that, run
# mariadb-install-db ourselves, and restart. The Homebrew path is unchanged.
start_macos_mariadb() {
    pkg_service restart mariadb || return 1

    if [ "$MAC_BREW" = "nb" ] && ! mariadb_wait_ready 8; then
        echo "   - Initializing MariaDB data directory (nanobrew post_install fallback)..."
        if command -v mariadb-install-db &>/dev/null; then
            mariadb-install-db &>/dev/null || true
        fi
        pkg_service restart mariadb || return 1
    fi
    return 0
}

setup_environment
# --- End OS Detection ---

# --- Configuration ---
COVE_DIR="$HOME/Cove"
CONFIG_FILE="$COVE_DIR/config"
CADDYFILE_PATH="$COVE_DIR/Caddyfile"
PHP_INI_FILE="$COVE_DIR/php.ini"

APP_DIR="$COVE_DIR/App"
SITES_DIR="$COVE_DIR/Sites"
LOGS_DIR="$COVE_DIR/Logs"

# App Sub-directories
GUI_DIR="$APP_DIR/gui"
ADMINER_DIR="$APP_DIR/adminer"
CUSTOM_CADDY_DIR="$APP_DIR/directives"

# Per-site PHP version switching (native php-fpm behind FrankenPHP).
RUN_DIR="$COVE_DIR/run"          # unix sockets: php-<ver>.sock
PHP_FPM_DIR="$COVE_DIR/php-fpm"  # generated php-fpm configs: <ver>/php-fpm.conf

PROTECTED_NAMES="cove"
COVE_VERSION="1.15"
# Bundled Whoops release. Pinned here so cove install and cove upgrade deploy
# the same version. 2.15.3 fatally broke under FrankenPHP's PHP 8.5 (web SAPI),
# 500-ing every site via the auto_prepend bootstrap; 2.18.0 is compatible.
WHOOPS_VERSION="2.18.0"
# Version of the injected one-time-login MU-plugin (captaincore-helper.php).
# MUST match the `Version:` header in build_mu_plugin's heredoc — refresh_all_mu_plugins
# compares the two to decide which sites need the plugin re-pushed on upgrade.
# Bump whenever the mu-plugin code changes so existing sites pick it up.
MU_PLUGIN_VERSION="0.6.1"
# Version of the macOS menu bar companion app (menubar/, embedded at compile
# time). Bump whenever anything under menubar/ changes — post-upgrade compares
# this against the installed bundle's CFBundleShortVersionString to decide
# whether an enabled menu bar needs a rebuild. Opt-in: never auto-installed.
MENUBAR_VERSION="1.1"
CADDY_CMD="frankenphp"

# Note: BIN_DIR is set in setup_environment() based on OS and architecture

# Export PHPRC so every PHP invocation (frankenphp php-cli, frankenphp -r, and
# any nested wp-cli call) picks up our memory_limit / display_errors / error
# reporting overrides from $PHP_INI_FILE. The file is written by `cove install`;
# until then PHPRC points at a non-existent path, which PHP silently ignores.
export PHPRC="$PHP_INI_FILE"

# --- Port Configuration ---
# Defaults; overridden by HTTP_PORT/HTTPS_PORT entries in $CONFIG_FILE if present.
HTTP_PORT=80
HTTPS_PORT=443
if [ -f "$CONFIG_FILE" ]; then
    _cove_saved_http=$(grep '^HTTP_PORT=' "$CONFIG_FILE" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d "'\"")
    _cove_saved_https=$(grep '^HTTPS_PORT=' "$CONFIG_FILE" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d "'\"")
    [ -n "$_cove_saved_http" ] && HTTP_PORT="$_cove_saved_http"
    [ -n "$_cove_saved_https" ] && HTTPS_PORT="$_cove_saved_https"
    unset _cove_saved_http _cove_saved_https
fi

# Returns ":8453" when HTTPS_PORT is non-default, otherwise empty.
https_port_suffix() {
    if [ "$HTTPS_PORT" = "443" ]; then
        echo ""
    else
        echo ":$HTTPS_PORT"
    fi
}

# Builds https URL with port suffix when non-default (e.g. "https://foo.localhost:8453").
url_for() {
    echo "https://${1}$(https_port_suffix)"
}

# Idempotent config writer: replaces any existing KEY= line before appending.
config_set() {
    local key="$1" val="$2"
    mkdir -p "$(dirname "$CONFIG_FILE")"
    local tmp
    tmp=$(mktemp)
    if [ -f "$CONFIG_FILE" ]; then
        grep -v "^${key}=" "$CONFIG_FILE" > "$tmp" 2>/dev/null || true
    fi
    echo "${key}='${val}'" >> "$tmp"
    mv "$tmp" "$CONFIG_FILE"
}

# Emit a base64-encoded random password. Uses openssl when present, falls
# back to /dev/urandom otherwise — Fedora Workstation doesn't ship openssl
# in its base install, and a missing openssl used to yield an empty $db_pass
# that then became a MariaDB user with *no* password.
cove_random_password() {
    local bytes="${1:-16}"
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 "$bytes"
    else
        head -c "$bytes" /dev/urandom | base64 | tr -d '\n'
    fi
}

# Reads a directive from ~/Cove/php.ini (last-wins, ini-style), trims
# surrounding whitespace/quotes, and returns the fallback if the key is
# missing or the ini file doesn't exist yet. Used by regenerate_caddyfile
# so `cove memory set` only needs to edit one source of truth.
cove_ini_get() {
    local key="$1" fallback="$2" val=""
    if [ -f "$PHP_INI_FILE" ]; then
        val=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$PHP_INI_FILE" 2>/dev/null \
            | tail -1 \
            | sed -E "s|^[[:space:]]*${key}[[:space:]]*=[[:space:]]*||" \
            | tr -d '"' \
            | sed -E 's/[[:space:]]+$//')
    fi
    echo "${val:-$fallback}"
}

# Default FrankenPHP worker-thread count: 4x CPU cores, floor of 16,
# then capped at 1 thread per GB of RAM. FrankenPHP's own default
# (2x cores) is small enough that a handful of long-running requests
# — an SSE long-poll, a slow loopback, a wedged cron — can occupy
# every worker, and then EVERY site on the box hangs even though the
# server is healthy (the watchdog then SIGKILLs a starved-but-fine
# process). Extra threads help with that, but under ZTS each extra
# worker is another concurrent compile into the shared OPcache arena,
# so a 16 GB laptop must not get the 32 workers 4x-cores would pick
# (the zend_mm_panic abort class under a Playwright suite).
# Overridable via `num_threads = N` in ~/Cove/php.ini (cove_ini_get).
cove_num_threads() {
    local cores n ram_gb=0 mem_bytes mem_kb
    cores=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)
    case "$cores" in (*[!0-9]*|'') cores=4;; esac
    n=$(( cores * 4 ))
    [ "$n" -lt 16 ] && n=16

    mem_bytes=$(sysctl -n hw.memsize 2>/dev/null || true)
    case "$mem_bytes" in (''|*[!0-9]*) mem_bytes=0;; esac
    if [ "$mem_bytes" -gt 0 ]; then
        ram_gb=$(( mem_bytes / 1024 / 1024 / 1024 ))
    elif [ -r /proc/meminfo ]; then
        mem_kb=$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || true)
        case "$mem_kb" in (''|*[!0-9]*) mem_kb=0;; esac
        [ "$mem_kb" -gt 0 ] && ram_gb=$(( mem_kb / 1024 / 1024 ))
    fi
    if [ "$ram_gb" -gt 0 ] && [ "$n" -gt "$ram_gb" ]; then
        n=$ram_gb
        [ "$n" -lt 8 ] && n=8
    fi
    echo "$n"
}

# --- Per-site PHP version helpers ---
# A site pinned to an older PHP carries a single-line `php_version` file in its
# site dir (peer of mappings/lan_config). FrankenPHP stays the front door for
# every site; pinned sites are handed to a native Homebrew php-fpm over a unix
# socket via php_fastcgi. See sync_php_fpm_services / emit_site_php_handler.

# Normalize "php@8.2" / "8.2.29" / "8.2" → "8.2". Echoes nothing on garbage.
normalize_php_version() {
    local ver="${1#php@}"
    if [[ "$ver" =~ ^([578]\.[0-9]+)(\.[0-9]+)?$ ]]; then
        echo "${BASH_REMATCH[1]}"
    fi
}

# Echo the pinned version for a site dir, or nothing when unpinned.
site_php_version() {
    cat "$1/php_version" 2>/dev/null
}

# Homebrew prefix for php@<ver> (e.g. /opt/homebrew/opt/php@8.2), but only
# when its php-fpm binary actually exists. Empty on nanobrew/Linux or when the
# formula isn't installed — callers treat empty as "no native PHP available"
# and fall back to FrankenPHP.
php_fpm_prefix_for() {
    local ver="$1"
    if [ "$OS" != "macos" ] || [ "$MAC_BREW" != "brew" ]; then
        return 0
    fi
    local prefix
    prefix=$(brew --prefix "php@$ver" 2>/dev/null)
    if [ -n "$prefix" ] && [ -x "$prefix/sbin/php-fpm" ]; then
        echo "$prefix"
    fi
}

php_fpm_sock_for() {
    echo "$RUN_DIR/php-$1.sock"
}

# The PHP version FrankenPHP bundles (e.g. "8.5.2"), parsed from its banner.
frankenphp_php_version() {
    frankenphp version 2>/dev/null | sed -n 's/.*PHP \([0-9][0-9.]*\).*/\1/p'
}

# Returns the process name(s) listening on $1 for display purposes, or empty
# if the process isn't visible (e.g. owned by another uid on macOS). Do NOT
# use this for availability checks — use port_is_free for that.
port_listening_app() {
    local port="$1"
    if command -v lsof &>/dev/null; then
        lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null \
            | awk 'NR>1 {print $1}' | sort -u | paste -sd, -
    elif command -v ss &>/dev/null; then
        ss -tlnH "sport = :$port" 2>/dev/null \
            | grep -oE 'users:\(\("[^"]+"' | sed 's/.*"\(.*\)"$/\1/' \
            | sort -u | paste -sd, -
    fi
}

# True when nothing is accepting connections on $1. Uses bash /dev/tcp so it
# works regardless of who owns the listener (lsof is uid-scoped on macOS and
# cannot see root-owned sockets from a regular user). Probes both IPv4 and
# IPv6 loopback because some servers (e.g. Python's http.server) bind v6-only
# by default and the v4 probe alone would miss them.
port_is_free() {
    local port="$1"
    if (exec 3<>/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then
        return 1
    fi
    if (exec 3<>/dev/tcp/::1/"$port") 2>/dev/null; then
        return 1
    fi
    return 0
}

# True if the process listening on $1 is one of our own services (Caddy /
# FrankenPHP). Used so reinstalls don't flag their own services as conflicts.
port_is_own() {
    local app
    app=$(port_listening_app "$1")
    [ -n "$app" ] && { [[ "$app" == *"$CADDY_CMD"* ]] || [[ "$app" == *frankenph* ]]; }
}

# True if $1 is occupied by something that isn't one of our own services.
port_has_conflict() {
    port_is_free "$1" && return 1
    port_is_own "$1" && return 1
    return 0
}

# True when there's no TTY to prompt on — scripted callers, CI, an AI agent
# driving the CLI, the dashboard's shell_exec, systemd. Every interactive
# prompt in Cove should be reachable via flags; this is the switch that picks
# the flag-only path.
is_noninteractive() { [ ! -t 0 ]; }

# Bail out of an unavoidable prompt with a message that names the flag to pass
# instead of letting gum abort with the opaque "could not open a new TTY".
# $1 = what was being asked for, $2 = the flag(s) that supply it.
require_interactive() {
    local what="$1" hint="$2"
    is_noninteractive || return 0
    gum style --foreground red "❌ $what requires an interactive terminal." >&2
    echo "   Running headless? Pass $hint" >&2
    exit 1
}

# Interactive prompt that asks for HTTP and HTTPS ports, validates each, and
# re-prompts until both are free. Sets HTTP_PORT / HTTPS_PORT globals on
# success. Called by the install and `cove ports` flows.
prompt_custom_ports() {
    local suggest_http="${1:-8090}" suggest_https="${2:-8453}"
    local candidate
    while true; do
        candidate=$(gum input --value "$suggest_http" --prompt "HTTP port: ")
        if [[ ! "$candidate" =~ ^[0-9]+$ ]] || [ "$candidate" -lt 1 ] || [ "$candidate" -gt 65535 ]; then
            gum style --foreground red "   ❌ Invalid port number."
            continue
        fi
        if ! port_is_free "$candidate"; then
            gum style --foreground red "   ❌ Port $candidate is in use by: $(port_listening_app "$candidate")"
            continue
        fi
        HTTP_PORT="$candidate"
        break
    done
    while true; do
        candidate=$(gum input --value "$suggest_https" --prompt "HTTPS port: ")
        if [[ ! "$candidate" =~ ^[0-9]+$ ]] || [ "$candidate" -lt 1 ] || [ "$candidate" -gt 65535 ]; then
            gum style --foreground red "   ❌ Invalid port number."
            continue
        fi
        if [ "$candidate" = "$HTTP_PORT" ]; then
            gum style --foreground red "   ❌ HTTPS port must differ from HTTP port."
            continue
        fi
        if ! port_is_free "$candidate"; then
            gum style --foreground red "   ❌ Port $candidate is in use by: $(port_listening_app "$candidate")"
            continue
        fi
        HTTPS_PORT="$candidate"
        break
    done
}

# Build the https:// URL for a hostname given an HTTPS port. Omits the port
# suffix when $2 equals 443 so stored URLs match the "no suffix" form.
port_url_for() {
    local host="$1" port="$2"
    if [ "$port" = "443" ]; then
        echo "https://$host"
    else
        echo "https://$host:$port"
    fi
}

# Walk every WordPress site under $SITES_DIR and run `wp search-replace` to
# migrate stored URLs from OLD_HTTPS port to NEW_HTTPS port. Updates each
# hostname the site answers on (base + entries in site/mappings) so custom
# mappings don't get left stale. Pass "--dry-run" as the third argument to
# preview replacement counts without committing.
#
# No-op if OLD_HTTPS == NEW_HTTPS or if $SITES_DIR has no WordPress sites.
# Returns 0 even if individual sites fail — per-site errors are reported
# in the output and summarised at the end.
update_wp_site_urls_for_port_change() {
    local old_https="$1" new_https="$2" dry_run_flag="${3:-}"
    local dry_run=false
    [ "$dry_run_flag" = "--dry-run" ] && dry_run=true

    [ "$old_https" = "$new_https" ] && return 0
    [ -d "$SITES_DIR" ] || return 0

    local wp_cmd
    local total_sites=0 updated_sites=0 failed_hosts=0
    local site_path site_name hostname mapping old_url new_url
    local -a hostnames

    for site_path in "$SITES_DIR"/*; do
        [ -d "$site_path" ] || continue
        [ -f "$site_path/public/wp-config.php" ] || continue
        total_sites=$((total_sites + 1))
        site_name=$(basename "$site_path")
        wp_cmd=$(get_wp_cmd "$site_path")

        hostnames=("$site_name")
        if [ -f "$site_path/mappings" ]; then
            while IFS= read -r mapping || [ -n "$mapping" ]; do
                [ -n "$mapping" ] && hostnames+=("$mapping")
            done < "$site_path/mappings"
        fi

        local any_updated=false
        for hostname in "${hostnames[@]}"; do
            old_url=$(port_url_for "$hostname" "$old_https")
            new_url=$(port_url_for "$hostname" "$new_https")
            [ "$old_url" = "$new_url" ] && continue

            local -a sr_args
            sr_args=(--all-tables --skip-plugins --skip-themes --format=count)
            $dry_run && sr_args+=(--dry-run)

            local output rc count
            output=$( (cd "$site_path/public" && $wp_cmd search-replace "$old_url" "$new_url" "${sr_args[@]}") 2>&1 )
            rc=$?
            if [ $rc -eq 0 ]; then
                count=$(echo "$output" | tr -d '[:space:]')
                [[ "$count" =~ ^[0-9]+$ ]] || count=0
                if $dry_run; then
                    echo "   • ${hostname}: would replace ${count} occurrence(s)"
                else
                    echo "   • ${hostname}: replaced ${count} occurrence(s)"
                fi
                any_updated=true
            else
                gum style --foreground red "   ❌ ${hostname}: search-replace failed"
                failed_hosts=$((failed_hosts + 1))
            fi
        done
        $any_updated && updated_sites=$((updated_sites + 1))
    done

    echo ""
    if $dry_run; then
        echo "🔍 Dry run: $updated_sites of $total_sites WordPress site(s) would be updated."
    else
        echo "📊 $updated_sites of $total_sites WordPress site(s) updated."
    fi
    if [ $failed_hosts -gt 0 ]; then
        gum style --foreground yellow "⚠️  $failed_hosts hostname replacement(s) failed."
    fi
    return 0
}

# Download the pinned Whoops release into $APP_DIR/whoops. Shared by cove
# install and cove upgrade so both stay on WHOOPS_VERSION — upgrade previously
# never refreshed Whoops, so upgraders whose FrankenPHP jumped to PHP 8.5 kept
# an incompatible 2.15.3 and 500-ed every site.
deploy_whoops() {
    echo "✨ Downloading Whoops error handler (v$WHOOPS_VERSION)..."
    local tmp
    tmp=$(mktemp -d)
    if curl -sL "https://github.com/filp/whoops/archive/refs/tags/${WHOOPS_VERSION}.tar.gz" | tar -xz -C "$tmp" --strip-components=1 \
        && [ -f "$tmp/src/Whoops/Run.php" ]; then
        rm -rf "$APP_DIR/whoops"
        mkdir -p "$APP_DIR/whoops"
        cp -R "$tmp"/. "$APP_DIR/whoops/"
    else
        echo "   ⚠️  Whoops download failed; leaving the existing copy in place." >&2
        rm -rf "$tmp"
        return 1
    fi
    rm -rf "$tmp"
}

# --- Whoops Bootstrap Generation ---
create_whoops_bootstrap() {
    echo "📜 Creating Whoops bootstrap file..."
    cat > "$APP_DIR/whoops_bootstrap.php" << 'EOM'
<?php
// This script is automatically included before any other PHP script.
// It registers a simple PSR-4 autoloader for the Whoops library.

spl_autoload_register(function ($class) {
    $prefix = 'Whoops\\';
    $base_dir = __DIR__ . '/whoops/src/Whoops/';
    
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }
    
    $relative_class = substr($class, $len);
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';

    if (file_exists($file)) {
        require $file;
    }
});

// Whoops is a dev-time convenience (pretty error pages), not essential to
// serving a request — so it must never be able to take a site down. A bundled
// Whoops incompatible with the running PHP (e.g. 2.15.3 under PHP 8.5) threw a
// TypeError from register() here, and because this file is auto_prepend'd to
// every request it 500-ed every site at once. Catch anything so a failure
// degrades to "no pretty pages" instead of a site-wide outage; the underlying
// error still lands in the PHP error log.
try {
    $whoops = new \Whoops\Run;

    // Only fatal errors and uncaught exceptions should get the full-screen
    // Whoops page. Everything non-fatal is silenced:
    // E_USER_NOTICE is used by WordPress's _doing_it_wrong() function.
    // E_USER_WARNING is triggered by WP_HTTP (wp_version_check, update checks,
    // API calls) whenever a request to api.wordpress.org or a plugin update
    // endpoint fails — a transient runtime condition, not a bug to page on.
    // E_WARNING covers PHP's "Cannot modify header information - headers
    // already sent", which fires whenever a plugin echoes output before core
    // sends its Content-Type header — harmless and silent on a normal host.
    // Note: Whoops swallows silenced errors entirely (its error handler
    // returns true, so PHP's own log_errors handling never runs) — these
    // levels do NOT reach debug.log.
    $whoops->silenceErrorsInPaths(
        '/.*/', // A regex that matches all file paths
        E_DEPRECATED | E_USER_DEPRECATED | E_NOTICE | E_USER_NOTICE | E_WARNING | E_USER_WARNING
    );

    // The PrettyPageHandler will now only be triggered for fatal errors.
    $whoops->pushHandler(new \Whoops\Handler\PrettyPageHandler);
    $whoops->register();
} catch (\Throwable $e) {
    error_log('Cove: Whoops failed to initialize, continuing without it: ' . $e->getMessage());
}
EOM
}

# --- Helper Functions ---

# Inject the mu-plugin for one-time logins
inject_mu_plugin() {
    local public_dir="$1"
    if [ -z "$public_dir" ] || [ ! -d "$public_dir" ]; then
        return 1 # Exit if no valid directory is provided
    fi

    # Heredoc containing the mu-plugin code
read -r -d '' build_mu_plugin << 'heredoc'
<?php
/**
 * Plugin Name: CaptainCore Helper
 * Plugin URI: https://captaincore.io
 * Description: Collection of helper functions for CaptainCore
 * Version: 0.6.1
 * Author: CaptainCore
 * Author URI: https://captaincore.io
 * Text Domain: captaincore-helper
 */

/**
 * Registers AJAX callback for quick logins
 */
function captaincore_quick_login_action_callback() {

	$post = json_decode( file_get_contents( 'php://input' ) );
	// Error if token not valid. Use hash_equals with a string cast: a loose
	// `!=` let a JSON `{"token":true}` coerce to `true != <hash>` → false and
	// bypass the check entirely, minting an admin login link unauthenticated.
	if ( ! isset( $post->token ) || ! is_string( $post->token ) || ! hash_equals( md5( AUTH_KEY ), $post->token ) ) {
		wp_die( '', '', [ 'response' => 404 ] );
	}

	$post->user_login = str_replace( "%20", " ", $post->user_login );
	$user     = get_user_by( 'login', $post->user_login );
	$password = wp_generate_password();
	// Short token: sha1 is 40 hex chars; 7 is still 16^7 ≈ 268M combinations,
	// plenty for a one-time-use local-dev login link, and short enough to fit
	// a narrow terminal without wrapping.
	$token    = substr( sha1( $password ), 0, 7 );

	update_user_meta( $user->ID, 'cove_login_token', $token );
	// Stamp the mint time so the token can expire — see the TTL check in
	// captaincore_login_handle_token(). Without it an unused link stayed a
	// valid standing credential forever.
	update_user_meta( $user->ID, 'cove_login_token_time', time() );
	$query_args = [
			'user_id'          => $user->ID,
			'cove_login_token' => $token,
		];
	$login_url    = wp_login_url();
		$one_time_url = add_query_arg( $query_args, $login_url );

	echo $one_time_url;
	wp_die();

}

add_action( 'wp_ajax_nopriv_captaincore_quick_login', 'captaincore_quick_login_action_callback' );
/**
 * Login a request in as a user if the token is valid.
 */
function captaincore_login_handle_token() {

	global $pagenow;
	if ( 'wp-login.php' !== $pagenow || empty( $_GET['user_id'] ) || empty( $_GET['cove_login_token'] ) ) {
		return;
	}

	if ( is_user_logged_in() ) {
		$error = sprintf( __( 'Invalid one-time login token, but you are logged in as \'%1$s\'. <a href="%2$s">Go to the dashboard instead</a>?', 'captaincore-login' ), wp_get_current_user()->user_login, admin_url() );
	} else {
		$error = sprintf( __( 'Invalid one-time login token. <a href="%s">Try signing in instead</a>?', 'captaincore-login' ), wp_login_url() );
	}

	// Use a generic error message to ensure user ids can't be sniffed
	$user = get_user_by( 'id', (int) $_GET['user_id'] );
	if ( ! $user ) {
		wp_die( $error );
	}

	$token      = get_user_meta( $user->ID, 'cove_login_token', true );
	$token_time = (int) get_user_meta( $user->ID, 'cove_login_token_time', true );

	// Expire stale/unused tokens (15 min) so a cove login link that was never
	// clicked can't be replayed later as a standing credential.
	if ( '' === $token || ( time() - $token_time ) > 15 * MINUTE_IN_SECONDS ) {
		delete_user_meta( $user->ID, 'cove_login_token' );
		delete_user_meta( $user->ID, 'cove_login_token_time' );
		wp_die( $error );
	}

	if ( ! hash_equals( $token, (string) $_GET['cove_login_token'] ) ) {
		wp_die( $error );
	}

	delete_user_meta( $user->ID, 'cove_login_token' );
	delete_user_meta( $user->ID, 'cove_login_token_time' );
	wp_set_auth_cookie( $user->ID, 1 );
	wp_safe_redirect( admin_url() );
	exit;
}

add_action( 'init', 'captaincore_login_handle_token' );

if (defined('WP_CLI') && WP_CLI) {

    /**
     * Generates a one-time login link for a user based on user ID, email, or login.
     *
     * ## OPTIONS
     *
     * <user_identifier>
     * : The user ID, email, or login of the user to generate the login link for.
     *
     * ## EXAMPLES
     *
     * wp user login 123
     * wp user login user@example.com
     * wp user login myusername
     *
     * @param array $args The command arguments.
     */
    function captaincore_generate_login_link( $args ) {

        $user_identifier = $args[0];
        // Determine if the identifier is a user ID, email, or login
        if (is_numeric($user_identifier)) {
            $user = get_user_by('ID', $user_identifier);
        } elseif (is_email($user_identifier)) {
            $user = get_user_by('email', $user_identifier);
        } else {
            $user = get_user_by('login', $user_identifier);
        }

        // Check if the user exists
        if (!$user) {
            WP_CLI::error("User not found: $user_identifier");
            return;
        }

        // Generate tokens. Short token (7 hex chars from sha1) keeps the
        // one-time URL readable on narrow terminals while still leaving
        // ~268M combinations for a one-time-use local-dev link.
        $password = wp_generate_password();
        $token    = substr( sha1( $password ), 0, 7 );

        // Update user meta with the new token. Stamp the mint time too — the
        // token validator expires anything without a recent cove_login_token_time
        // (see captaincore_login_handle_token), so omitting it here made every
        // `wp user login` / `cove add` link read as already expired.
        update_user_meta( $user->ID, 'cove_login_token', $token );
        update_user_meta( $user->ID, 'cove_login_token_time', time() );
        // Construct the one-time login URL
        $query_args = [
            'user_id'          => $user->ID,
            'cove_login_token' => $token,
        ];
        $login_url    = wp_login_url();
        $one_time_url = add_query_arg($query_args, $login_url);
        // Output the URL to the CLI
        WP_CLI::log("$one_time_url");
    }

    WP_CLI::add_command( 'user login', 'captaincore_generate_login_link' );
}

/**
 * Disable auto-update email notifications for plugins.
 */
add_filter( 'auto_plugin_update_send_email', '__return_false' );

/**
 * Disable auto-update email notifications for themes.
 */
add_filter( 'auto_theme_update_send_email', '__return_false' );

/**
 * Dynamic URL override for Tailscale/LAN/Share access.
 * When accessed via a non-localhost domain, override home and siteurl
 * to use the current host so CSS/JS/images load correctly.
 */
function cove_maybe_override_site_url( $value ) {
    // Only run in front-end context with a valid HTTP_HOST
    if ( defined( 'WP_CLI' ) && WP_CLI ) {
        return $value;
    }
    
    $host = isset( $_SERVER['HTTP_HOST'] ) ? $_SERVER['HTTP_HOST'] : '';
    
    // Skip if no host or if it ends with .localhost (normal local access)
    if ( empty( $host ) || preg_match( '/\.localhost(:\d+)?$/', $host ) ) {
        return $value;
    }
    
    // Override to current host for Tailscale, LAN, or public share access
    $scheme = ( ! empty( $_SERVER['HTTPS'] ) && $_SERVER['HTTPS'] !== 'off' ) ? 'https' : 'http';
    return $scheme . '://' . $host;
}
add_filter( 'option_home', 'cove_maybe_override_site_url' );
add_filter( 'option_siteurl', 'cove_maybe_override_site_url' );

/**
 * Force the GD image editor instead of Imagick.
 *
 * FrankenPHP embeds a ZTS PHP (built by static-php-cli) with the imagick
 * extension baked in. The first time any request constructs an Imagick
 * object, ImageMagick's MagickWandGenesis() installs its own SIGSEGV /
 * SIGBUS / SIGABRT handlers WITHOUT the SA_ONSTACK flag. Go — FrankenPHP's
 * runtime — owns SIGSEGV for goroutine stack-growth guard pages, so the
 * very next stack-growth signal trips "fatal error: non-Go code set up
 * signal handler without SA_ONSTACK flag" and the whole server aborts. On
 * WordPress every thumbnail/resize/upload instantiates Imagick (it's the
 * default editor when available), so an image-heavy site under load crashes
 * FrankenPHP repeatedly. Never instantiating Imagick avoids the handler
 * install entirely; GD covers every core WordPress image need. A site that
 * truly needs Imagick (and accepts the crash risk) can opt out with
 * add_filter( 'cove_force_gd_editor', '__return_false' ).
 */
add_filter( 'wp_image_editors', function ( $editors ) {
	if ( ! apply_filters( 'cove_force_gd_editor', true ) ) {
		return $editors;
	}
	return array( 'WP_Image_Editor_GD' );
}, 999 );

/**
 * Don't let a plugin/theme install stampede wp.org mid-response.
 *
 * After WP_Upgrader finishes — success or "folder already exists" — it
 * fires upgrader_process_complete, and core's own listeners immediately
 * ping api.wordpress.org (wp_update_plugins / wp_update_themes /
 * wp_version_check). On a site with a large plugin list that is a
 * multi-second fan-out the install JSON does not need. Unhook those
 * three; cron will refresh updates. License phone-homes and other
 * outbound HTTP are left alone. OPcache resets are blocked separately
 * by disable_functions=opcache_reset in the Caddyfile. Opt out with
 * add_filter( 'cove_skip_upgrader_http', '__return_false' ).
 */
add_action( 'upgrader_process_complete', function () {
	if ( ! apply_filters( 'cove_skip_upgrader_http', true ) ) {
		return;
	}
	remove_action( 'upgrader_process_complete', 'wp_version_check', 10 );
	remove_action( 'upgrader_process_complete', 'wp_update_plugins', 10 );
	remove_action( 'upgrader_process_complete', 'wp_update_themes', 10 );
}, 0 );
heredoc

    local mu_plugins_dir="$public_dir/wp-content/mu-plugins"
    mkdir -p "$mu_plugins_dir"
    echo "$build_mu_plugin" > "$mu_plugins_dir/captaincore-helper.php"
    echo "   - ✅ Injected one-time login MU-plugin."
}

# Re-push the one-time-login MU-plugin to every WordPress site whose deployed
# copy is out of date. cove login re-injects lazily, but only for sites you log
# into — this proactively updates the rest, which matters because the plugin
# carries security-sensitive code (the nopriv login handler) and runtime filters
# (option_home/siteurl) that are live regardless of whether anyone triggers a
# login. Gated on the Version: header so unchanged sites aren't rewritten.
refresh_all_mu_plugins() {
    echo "🔌 Refreshing one-time-login MU-plugin (v$MU_PLUGIN_VERSION) across sites..."
    local total=0 updated=0 site public deployed ver
    for site in "$SITES_DIR"/*.localhost; do
        [ -d "$site" ] || continue
        public="$site/public"
        [ -f "$public/wp-config.php" ] || continue   # WordPress sites only
        total=$((total + 1))
        deployed="$public/wp-content/mu-plugins/captaincore-helper.php"
        ver=""
        if [ -f "$deployed" ]; then
            ver=$(grep -m1 -E '^[[:space:]]*\*[[:space:]]*Version:' "$deployed" \
                | sed -E 's/.*Version:[[:space:]]*//; s/[[:space:]]*$//')
        fi
        if [ "$ver" != "$MU_PLUGIN_VERSION" ]; then
            inject_mu_plugin "$public" >/dev/null && updated=$((updated + 1))
        fi
    done
    echo "   - ✅ MU-plugin current on $total WordPress site(s); updated $updated."
}

# Write a Cove-branded landing index.php into a plain site's public dir.
# The heredoc below is the user's PHP — it reads $_SERVER['HTTP_HOST'] and
# __FILE__ at request time, so it self-identifies wherever it's served from.
write_plain_site_landing() {
    local public_dir="$1"
    if [ -z "$public_dir" ] || [ ! -d "$public_dir" ]; then
        return 1
    fi

read -r -d '' build_landing << 'LANDING_EOF'
<?php
$host = $_SERVER['HTTP_HOST'] ?? 'localhost';
$file = __FILE__;
$dir  = dirname(__FILE__);
$home = getenv('HOME') ?: '';
$display_dir = ($home && str_starts_with($dir, $home)) ? '~' . substr($dir, strlen($home)) : $dir;
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light">
<title><?= htmlspecialchars($host) ?></title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64' stroke-linecap='round' stroke-linejoin='round'><defs><clipPath id='c'><circle cx='32' cy='32' r='28'/></clipPath></defs><g clip-path='url(%23c)'><rect width='64' height='64' fill='%23f6f1e8'/><rect y='32' width='64' height='32' fill='%233a97a9'/><path d='M 4 32 C 4 22, 12 12, 22 12 C 30 12, 34 18, 42 16 C 50 14, 58 18, 60 24 L 60 32 Z' fill='%2358b293'/><line x1='2' y1='32' x2='62' y2='32' stroke='%231c4c58' stroke-width='2.5' fill='none'/><g stroke='%231c4c58' stroke-width='2.6' fill='none'><path d='M 10 42 Q 18 38, 26 42 T 42 42 T 56 42'/><path d='M 14 50 Q 22 46, 30 50 T 46 50 T 56 50'/></g></g><circle cx='32' cy='32' r='28' stroke='%231c4c58' stroke-width='3' fill='none'/></svg>">
<link href="https://fonts.googleapis.com/css2?family=Fraunces:ital,opsz,wght@0,9..144,400..600;1,9..144,400..600&family=Geist:wght@400;500;600&family=Geist+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg: #fbfaf7; --bg-elev: #ffffff; --bg-sunk: #f4f2ec;
  --border: #e8e4da; --text: #1a1c1b; --text-soft: #3a3d3a;
  --muted: #6b6f6a; --dim: #9a9d97;
  /* sRGB fallback first; the oklch override on the next line is ignored by
     browsers without oklch() support (Firefox <113, Chrome <111, Safari <16.4)
     so the hex value wins — otherwise the whole declaration would be invalid
     and --accent would fall back to its initial value (unset). */
  --accent: #3a97a9;       --accent-ink: #1c4c58;
  --accent: oklch(62% 0.11 190); --accent-ink: oklch(35% 0.08 190);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1210; --bg-elev: #161a17; --bg-sunk: #0b0e0c;
    --border: #252925; --text: #edeee9; --text-soft: #c6c9c1;
    --muted: #8a8e85; --dim: #5d615a;
    --accent: #4db0c2;       --accent-ink: #83d2e0;
    --accent: oklch(72% 0.12 190); --accent-ink: oklch(82% 0.10 190);
  }
}
html { background: var(--bg); }
body {
  font-family: 'Geist', -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
  color: var(--text); background: var(--bg);
  min-height: 100vh; display: grid; place-items: center;
  padding: 2rem; -webkit-font-smoothing: antialiased;
  font-feature-settings: "ss01", "cv11";
}
main { max-width: 560px; text-align: center; }
.mark { width: 56px; height: 56px; margin: 0 auto 1.75rem; display: block; }
h1 {
  font-family: 'Fraunces', 'Times New Roman', serif;
  font-style: italic; font-weight: 500;
  font-size: clamp(2.25rem, 5vw, 3.25rem);
  letter-spacing: -0.025em; line-height: 1.02;
  margin-bottom: 0.55rem;
}
.host {
  font-family: 'Geist Mono', ui-monospace, 'SF Mono', Menlo, monospace;
  font-size: 0.9rem; color: var(--muted); margin-bottom: 1.75rem;
}
p { color: var(--text-soft); line-height: 1.55; font-size: 1.02rem; margin-bottom: 1rem; }
.path {
  display: inline-block;
  font-family: 'Geist Mono', ui-monospace, 'SF Mono', Menlo, monospace;
  font-size: 0.82rem;
  padding: 0.45rem 0.8rem;
  background: var(--bg-sunk); border: 1px solid var(--border);
  border-radius: 7px; color: var(--text-soft);
  margin: 0.25rem 0 2rem; word-break: break-all;
}
.actions { display: inline-flex; gap: 0.5rem; flex-wrap: wrap; justify-content: center; }
.pill {
  display: inline-flex; align-items: center; gap: 0.45em;
  padding: 0.55rem 1.05rem; border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--bg-elev); color: var(--text-soft);
  font-family: 'Geist Mono', ui-monospace, 'SF Mono', Menlo, monospace;
  font-size: 0.85rem; text-decoration: none;
  transition: border-color 120ms, color 120ms, background 120ms;
}
.pill:hover { border-color: var(--accent); color: var(--accent-ink); background: var(--bg-sunk); }
.pill.primary { background: var(--accent); border-color: var(--accent); color: #0a1a1c; }
.pill.primary:hover { filter: brightness(1.08); background: var(--accent); color: #0a1a1c; }
footer {
  margin-top: 3rem;
  font-family: 'Geist Mono', ui-monospace, 'SF Mono', Menlo, monospace;
  font-size: 0.72rem; color: var(--dim); letter-spacing: 0.05em;
}
footer a { color: var(--muted); text-decoration: none; border-bottom: 1px solid var(--border); }
footer a:hover { color: var(--text); }
</style>
</head>
<body>
<main>
  <svg class="mark" viewBox="0 0 64 64" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <defs><clipPath id="c"><circle cx="32" cy="32" r="28"/></clipPath></defs>
    <g clip-path="url(#c)">
      <rect width="64" height="64" fill="#f6f1e8"/>
      <rect y="32" width="64" height="32" fill="#3a97a9"/>
      <path d="M 4 32 C 4 22, 12 12, 22 12 C 30 12, 34 18, 42 16 C 50 14, 58 18, 60 24 L 60 32 Z" fill="#58b293"/>
      <line x1="2" y1="32" x2="62" y2="32" stroke="#1c4c58" stroke-width="2.5" fill="none"/>
      <g stroke="#1c4c58" stroke-width="2.6" fill="none">
        <path d="M 10 42 Q 18 38, 26 42 T 42 42 T 56 42"/>
        <path d="M 14 50 Q 22 46, 30 50 T 46 50 T 56 50"/>
      </g>
    </g>
    <circle cx="32" cy="32" r="28" stroke="#1c4c58" stroke-width="3" fill="none"/>
  </svg>
  <h1>Hello.</h1>
  <div class="host"><?= htmlspecialchars($host) ?></div>
  <p>Your site is ready. Start building by editing files in:</p>
  <div class="path"><?= htmlspecialchars($display_dir) ?></div>
  <div class="actions">
    <a class="pill primary" href="https://cove.localhost/">Cove dashboard</a>
    <a class="pill" href="https://cove.run/" target="_blank" rel="noopener">cove.run ↗</a>
  </div>
  <footer>Served by <a href="https://cove.run" target="_blank" rel="noopener">Cove</a></footer>
</main>
</body>
</html>
LANDING_EOF

    echo "$build_landing" > "$public_dir/index.php"
    echo "   - ✅ Wrote Cove landing page."
}

# Load configuration from ~/Cove/config
source_config() {
    if [ -f "$CONFIG_FILE" ]; then
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
    else
        echo "❌ Error: Cove config file not found. Please run 'cove install'."
        exit 1
    fi
}

# Function to check for required dependencies
check_dependencies() {
    # Check for Caddy/FrankenPHP
    if ! command -v "$CADDY_CMD" &> /dev/null && ! [ -x "$CADDY_CMD" ]; then
        gum style --foreground red "❌ Caddy/FrankenPHP not found. Please run 'cove install'."
        exit 1
    fi

    # Check for other dependencies
    for pkg_cmd in mariadb mailpit "wp:wp-cli" gum; do
        local pkg=${pkg_cmd##*:}
        local cmd=${pkg_cmd%%:*}
        if ! command -v $cmd &> /dev/null; then
            gum style --foreground red "❌ Dependency '$cmd' not found. Please run 'cove install'."
            exit 1
        fi
    done
}

# --- Helper Functions ---

# Helper function to get WP-CLI command. Routes wp-cli through FrankenPHP's
# bundled PHP via `frankenphp php-cli` so that we use one PHP runtime for both
# web (Caddy) and CLI — no separate brew `php` install needed. PHP settings
# (memory_limit, display_errors, error_reporting) come from $PHP_INI_FILE,
# which `cove install` writes alongside ~/Cove/config. PHPRC is exported once
# at script init below so every PHP invocation in any subshell picks it up.
#
# `frankenphp php-cli` does NOT support PHP CLI flags like -d or -c. PHPRC
# is the only mechanism for setting ini values, hence the dedicated ini file.
#
# --allow-root is needed in WSL/Docker where the script runs as root.

# True when a file is something PHP can run: it starts with `<?php`, or its
# shebang invokes php (`#!/usr/bin/env php`, `#!/opt/homebrew/bin/php`). The
# wp-cli phar begins with exactly such a shebang.
wp_file_is_php() {
    local first
    first=$(head -n1 "$1" 2>/dev/null)
    case "$first" in
        '<?php'*|'#!'*php*) return 0 ;;
    esac
    return 1
}

# Resolve the `wp` on PATH to a file PHP can actually execute.
#
# get_wp_cmd hands the result to `frankenphp php-cli <path>` (or a pinned
# native php), so it has to be wp-cli itself — the phar. It often isn't: a
# common setup wraps wp in a shell script that pins a PHP binary or silences
# deprecations. Handed to php-cli, that wrapper is not PHP, so PHP prints it
# as literal text and exits 0 — every wp call "succeeds" while doing nothing,
# and `cove add` created an empty site and reported it installed (#8).
# Follow symlinks by hand (macOS readlink grew -f only in 12.3), and when the
# target is a shell wrapper, pull out the phar it execs. Prints the wrapper
# itself when it can't see through it, so the caller can run it directly.
resolve_wp_phar() {
    local p
    p=$(command -v wp 2>/dev/null) || return 1
    local hops=0 target
    while [ -L "$p" ] && [ "$hops" -lt 20 ]; do
        target=$(readlink "$p")
        case "$target" in
            /*) p="$target" ;;
            *)  p="$(dirname "$p")/$target" ;;
        esac
        hops=$((hops + 1))
    done
    if [ ! -f "$p" ] || wp_file_is_php "$p"; then
        echo "$p"
        return 0
    fi
    local candidate
    while read -r candidate; do
        candidate="${candidate/#\~/$HOME}"
        if [ -f "$candidate" ] && wp_file_is_php "$candidate"; then
            echo "$candidate"
            return 0
        fi
    done < <(grep -oE "[~/][^[:space:]'\"]*\.phar" "$p" 2>/dev/null)
    echo "$p"
}

get_wp_cmd() {
    # Optional $1: a site dir. A site pinned to an older PHP (php_version
    # file) runs wp-cli under that same native php binary — version-gated
    # plugins and core requirement checks must see the PHP the site actually
    # serves with. Native php honors the exported PHPRC too, so the ini story
    # is identical to the frankenphp path. Missing binary degrades to
    # FrankenPHP rather than failing.
    local site_dir="$1"
    local wp_path
    wp_path=$(resolve_wp_phar)
    local root_flag=""
    if [ "$(id -u)" -eq 0 ]; then
        root_flag=" --allow-root"
    fi
    # A wrapper we could not see through has to run on its own: it pins a PHP
    # of its choosing, and feeding it to php-cli is the exact bug resolve_wp_phar
    # exists to prevent. A pinned site can't use it either — same reason.
    if [ -n "$wp_path" ] && [ -f "$wp_path" ] && ! wp_file_is_php "$wp_path"; then
        echo "$wp_path$root_flag"
        return 0
    fi
    if [ -n "$site_dir" ]; then
        local pinned prefix
        pinned=$(site_php_version "$site_dir")
        if [ -n "$pinned" ]; then
            prefix=$(php_fpm_prefix_for "$pinned")
            if [ -n "$prefix" ] && [ -x "$prefix/bin/php" ]; then
                echo "$prefix/bin/php $wp_path$root_flag"
                return 0
            fi
        fi
    fi
    local frank
    frank=$(command -v frankenphp)
    echo "$frank php-cli $wp_path$root_flag"
}

# Read a site's WordPress version straight out of wp-includes/version.php.
# Deliberately not `wp core version`: that boots WordPress, which costs ~200ms
# per site and fails outright on a site whose database or plugins are broken —
# exactly the sites you most want listed. Parsing the constant is a few
# milliseconds and works on a site that cannot currently serve a request.
cove_wp_version() {
    local public_dir="$1"
    local version_file="$public_dir/wp-includes/version.php"
    [ -f "$version_file" ] || return 1
    local version
    version=$(sed -n "s/^\$wp_version = '\([^']*\)'.*/\1/p" "$version_file" | head -1)
    [ -n "$version" ] || return 1
    echo "$version"
}

# Where the dashboard caches wp.org's stable-check data. Shared with the CLI so
# `cove list` and `cove core` can flag insecure versions without a network call
# of their own; absent or stale is always tolerable, never fatal.
COVE_WPVER_CACHE="$COVE_DIR/cache/wp-versions.json"

# Safely single-quote a value for interpolation into a remote shell command.
# Interior single quotes become the standard '\'' escape sequence, so the
# result can be dropped into ssh "... $(shell_quote "$v") ..." without injection.
shell_quote() {
    printf "'%s'" "${1//\'/\'\\\'\'}"
}

# Helper function to get the correct MariaDB service name on Linux
# Different distros may use 'mariadb', 'mysql', or 'mysqld' as the service name
get_mariadb_service_name() {
    if [ "$OS" == "macos" ]; then
        echo "mariadb"
        return
    fi
    # Check which service name exists on this system
    if systemctl list-unit-files mariadb.service 2>/dev/null | grep -q mariadb; then
        echo "mariadb"
    elif systemctl list-unit-files mysql.service 2>/dev/null | grep -q mysql; then
        echo "mysql"
    elif systemctl list-unit-files mysqld.service 2>/dev/null | grep -q mysqld; then
        echo "mysqld"
    else
        # Default to mariadb
        echo "mariadb"
    fi
}

# Manage /etc/hosts file for local domains
update_etc_hosts() {
    echo "🔎 Checking /etc/hosts for required entries..."

    # An array of all hostnames Cove will manage
    local required_hosts=("cove.localhost" "db.cove.localhost" "mail.cove.localhost")

    # Also find all site-specific hostnames
    if [ -d "$SITES_DIR" ]; then
        for site_path in "$SITES_DIR"/*; do
            if [ -d "$site_path" ]; then
                local host_site_name
                host_site_name=$(basename "$site_path")

                # Same skip as regenerate_caddyfile: a dir with no public/
                # and no custom directive isn't a servable site (e.g. the
                # logs/-only skeleton left by a reload racing a delete) —
                # adding its hosts entry back would undo the delete's cleanup.
                if [ ! -d "$site_path/public" ] && [ ! -f "$CUSTOM_CADDY_DIR/$host_site_name" ]; then
                    continue
                fi
                required_hosts+=("$host_site_name")

                # Check for additional mappings
                if [ -f "$site_path/mappings" ]; then
                    while IFS= read -r mapping || [ -n "$mapping" ]; do
                        # Skip empty lines
                        if [ -n "$mapping" ]; then
                            required_hosts+=("$mapping")
                        fi
                    done < "$site_path/mappings"
                fi
            fi
        done
    fi

    local missing_hosts=()
    for host in "${required_hosts[@]}"; do
        # Use grep -q to quietly check if the entry exists
        if ! grep -q "127.0.0.1[[:space:]]\+$host" /etc/hosts; then
            missing_hosts+=("$host")
        fi
    done

    if [ ${#missing_hosts[@]} -gt 0 ]; then
        echo "   - Adding missing entries to /etc/hosts (requires sudo)..."
        # printf '%s\n' (not echo -e) so a backslash sequence in a host value
        # can never expand into an extra root-written line. Defense-in-depth
        # behind validate_hostname at the mapping/proxy write sites.
        printf '127.0.0.1 %s\n' "${missing_hosts[@]}" | sudo tee -a /etc/hosts > /dev/null
        echo "   - ✅ Done."
    else
        echo "   - ✅ All entries are present."
    fi
}

# Probe Caddy's admin API to see if the server is running.
# Uses bash's built-in /dev/tcp so we don't depend on nc/curl being installed.
# Pin MariaDB's default collations so database dumps stay portable.
#
# MariaDB 11.5+ ships `character_set_collations` mapping utf8mb3/utf8mb4 to
# the new uca1400 collations. Any table created from a dump (or by a plugin)
# that says `DEFAULT CHARSET=utf8mb4` with no COLLATE clause — MySQL 8 dumps
# omit it, and so do most plugins' CREATE TABLEs — silently becomes
# utf8mb4_uca1400_ai_ci on import. The next `cove db backup` / `cove push`
# then fails on every MariaDB 10.x / MySQL host with "Unknown collation".
# WordPress core tables are unaffected (wpdb always writes an explicit
# COLLATE), which is why the breakage only shows up on plugin tables and
# on sites pulled in from another environment.
#
# Writes a Cove-managed drop-in mapping both charsets back to the classic
# *_unicode_ci collations every server understands. The `loose-` prefix keeps
# MariaDB 10.x (Debian/Ubuntu LTS), which lacks the variable, booting.
#
# Returns 0 when the file was written or changed (caller should restart
# MariaDB), 1 when it was already current, 2 when no config dir was found.
mariadb_config_dir() {
    if [ "$OS" = "macos" ]; then
        # Homebrew's my.cnf lives at <prefix>/etc/my.cnf and includes
        # <prefix>/etc/my.cnf.d. Derive the prefix from BIN_DIR so the Intel
        # (/usr/local) and Apple Silicon (/opt/homebrew) layouts both work.
        echo "${BIN_DIR%/bin}/etc/my.cnf.d"
        return 0
    fi
    local d
    for d in /etc/mysql/mariadb.conf.d /etc/my.cnf.d /etc/mysql/conf.d; do
        [ -d "$d" ] && { echo "$d"; return 0; }
    done
    return 1
}

write_mariadb_config() {
    local conf_dir
    conf_dir=$(mariadb_config_dir) || return 2
    local conf_file="$conf_dir/cove.cnf"
    [ "$OS" = "linux" ] && [ "$conf_dir" = "/etc/mysql/mariadb.conf.d" ] && conf_file="$conf_dir/99-cove.cnf"

    local content
    content=$(cat <<'CNF'
# Managed by Cove — rewritten on `cove install` and `cove upgrade`.
# Put your own overrides in a separate file in this directory.
[mariadbd]
# MariaDB 11.5+ defaults new utf8/utf8mb4 tables to the uca1400 collations,
# which older MariaDB and every MySQL reject on import ("Unknown collation").
# Pin the classic collations so `cove db backup` / `cove push` dumps import
# anywhere. `loose-` keeps MariaDB 10.x, which lacks this variable, booting.
loose-character_set_collations = utf8mb3=utf8mb3_unicode_ci,utf8mb4=utf8mb4_unicode_ci
CNF
)

    if [ -f "$conf_file" ] && [ "$(cat "$conf_file" 2>/dev/null)" = "$content" ]; then
        return 1
    fi

    if [ "$OS" = "macos" ]; then
        mkdir -p "$conf_dir" || return 2
        printf '%s\n' "$content" > "$conf_file" || return 2
        # Make sure the server actually reads the drop-in dir. Homebrew's
        # stock my.cnf already carries the !includedir line; nanobrew or a
        # hand-rolled my.cnf may not.
        local my_cnf="${conf_dir%/my.cnf.d}/my.cnf"
        if ! grep -qs "^!includedir[[:space:]]*$conf_dir" "$my_cnf" 2>/dev/null; then
            printf '\n!includedir %s\n' "$conf_dir" >> "$my_cnf" || return 2
        fi
    else
        printf '%s\n' "$content" | $SUDO_CMD tee "$conf_file" >/dev/null || return 2
    fi
    echo "   - ✅ Wrote MariaDB collation defaults to $conf_file"
    return 0
}

# Restart MariaDB through whichever service manager owns it.
restart_mariadb_service() {
    if [ "$OS" = "macos" ]; then
        start_macos_mariadb
    else
        $SUDO_CMD systemctl restart "$(get_mariadb_service_name)"
    fi
}

is_caddy_running() {
    (echo > /dev/tcp/127.0.0.1/2019) &>/dev/null
}

# Cheap MariaDB liveness probe. Never shell out to `brew services list` for
# this: that launches a full Homebrew Ruby interpreter (~1-2s idle, minutes
# under load), and with the menu bar app polling `cove status` every few
# seconds the invocations stacked up and drove the machine into a load
# spiral. mysqladmin ping is a single client handshake, answers even when
# auth is denied, and covers socket-only setups.
is_mariadb_running() {
    if command -v mysqladmin &>/dev/null; then
        mysqladmin ping --silent &>/dev/null
    else
        pgrep -x mariadbd &>/dev/null
    fi
}

# Write a standalone watchdog script to $COVE_DIR so launchd (macOS) and
# systemd (Linux) can invoke it without depending on the cove binary's
# location. This matters because on dev installs cove.sh may live under
# ~/Documents, which macOS TCC blocks launchd from executing.
#
# The watchdog detects a "zombie" FrankenPHP — process alive but HTTPS
# requests hang — and SIGKILLs it so the service manager respawns a fresh
# instance. FrankenPHP occasionally panics with
#   "fatal error: non-Go code set up signal handler without SA_ONSTACK flag"
# (a Go/cgo-into-PHP signal-handling bug). Most panics exit cleanly and
# KeepAlive/Restart=on-failure bring it back, but the "panic during panic"
# path pegs the process at 100% CPU dumping goroutine stacks for hours
# while the kernel keeps accepting TCP connects on the listener fd — so a
# plain /dev/tcp probe still returns healthy. We need an HTTP-level probe
# that times out, otherwise the only recovery is `cove enable`.
#
# CRITICAL: the watchdog must NOT kill a server that is still starting up.
# With 200+ sites, FrankenPHP spends ~45s provisioning internal-CA certs and
# wiring auto-HTTPS for every site block before it binds the HTTPS listener.
# The old version killed on the first failed probe every 5s, so at scale it
# SIGKILLed FrankenPHP mid-startup forever and 443 never came up. The rules
# below make the kill conditional on the server having been healthy at least
# once (i.e. it finished startup and *then* wedged), plus a sustained run of
# consecutive failures so a single blip under load can't trigger a kill.
write_watchdog_script() {
    local script_path="$COVE_DIR/watchdog.sh"
    mkdir -p "$COVE_DIR"
    cat > "$script_path" << EOM
#!/bin/bash
# Auto-generated by cove_enable. See write_watchdog_script() in main.
pidfile="$COVE_DIR/caddy.pid"
https_port="$HTTPS_PORT"
log_file="$LOGS_DIR/watchdog.log"
# State: "<pid> <mode> <count>".
#   mode=starting : pid has not yet answered a probe. count is consecutive
#                   not-healthy ticks. Never killed until count crosses
#                   never_healthy_ticks (~10min) — a stuck-startup safety net.
#                   This is what makes a slow 200-site startup (~45s to bind
#                   443) safe: a still-starting server is never SIGKILLed.
#   mode=up       : pid answered a probe at least once. count is consecutive
#                   probe failures; SIGKILL once it reaches fail_threshold —
#                   the "healthy then wedged" (panic-during-panic) case.
# Elapsed time is tracked as ticks in this file rather than via \`ps\`, since
# ps' elapsed-seconds column (etimes) is not portable across macOS/Linux.
state_file="$COVE_DIR/.watchdog.state"
process_log="$LOGS_DIR/caddy-process.log"
fail_threshold=3          # ~15s of sustained failure (3 x 5s) before a kill
never_healthy_ticks=120   # ~10min (120 x 5s) stuck in startup -> retry once
log_cap_bytes=52428800    # 50MB — a restart storm must not fill the disk

[ -f "\$pidfile" ] || exit 0
pid=\$(cat "\$pidfile" 2>/dev/null)
[ -n "\$pid" ] || exit 0
# If the pid already exited the service manager will respawn it — nothing to do.
kill -0 "\$pid" 2>/dev/null || exit 0

mkdir -p "$LOGS_DIR"

# Cap the FrankenPHP process log. It grows unbounded (info-level auto-HTTPS
# lines on every startup) and a restart storm can push it into the GBs, which
# is itself a drag on the box. Keep the most recent 5MB.
if [ -f "\$process_log" ]; then
    lsize=\$(stat -f%z "\$process_log" 2>/dev/null || stat -c%s "\$process_log" 2>/dev/null || echo 0)
    if [ "\$lsize" -gt "\$log_cap_bytes" ]; then
        tail -c 5242880 "\$process_log" > "\$process_log.tmp" 2>/dev/null \\
            && mv "\$process_log.tmp" "\$process_log" 2>/dev/null
    fi
fi

# Load prior state.
s_pid=""; s_mode="starting"; s_count=0
if [ -f "\$state_file" ]; then
    read -r s_pid s_mode s_count < "\$state_file" 2>/dev/null
fi
[ -n "\$s_count" ] || s_count=0
[ -n "\$s_mode" ] || s_mode="starting"

# HTTP-level probe: in the panic-during-panic case the kernel still accepts
# TCP connects on the listener fd while the Go runtime is dead, so a plain
# /dev/tcp probe returns "healthy" forever. curl with --max-time catches both
# the no-listener case (connect refused) and the wedged case (request hangs).
# --resolve pins to loopback so the probe doesn't depend on /etc/hosts, and
# uses the dashboard hostname so it matches a real Caddyfile site block.
# 10s timeout tolerates a busy-but-alive server under load.
if curl -sk --max-time 10 -o /dev/null \\
    --resolve "cove.localhost:\$https_port:127.0.0.1" \\
    "https://cove.localhost:\$https_port/" 2>/dev/null; then
    # Healthy: mark this pid up, clear the failure streak.
    echo "\$pid up 0" > "\$state_file"

    # --- Nightly hygiene restart -----------------------------------------
    # Under ZTS every recompile of a changed file wastes its old OPcache
    # slot, and waste is only reclaimed by a shared-memory *restart* — the
    # one event that corrupts SHM when it races concurrent compiles (the
    # zend_mm_heap-corrupted / SA_ONSTACK abort class; see the OPcache
    # comment in regenerate_caddyfile). On a busy dev box the arena refills
    # in about a day, so rather than letting OPcache restart itself at a
    # random busy moment, restart the whole process on schedule while the
    # box is idle: a full process restart has no SHM race at all, and the
    # service manager respawns it in seconds. Window-gated (04:30-05:59
    # local), at most once per day, only from a healthy probe, never during
    # an active reload. A box asleep through the window just skips the day
    # — sleep also pauses the churn that fills the arena.
    hygiene_stamp="$COVE_DIR/.watchdog.hygiene"
    now_hhmm=\$((10#\$(date +%H%M)))
    today=\$(date +%Y-%m-%d)
    if [ "\$now_hhmm" -ge 430 ] && [ "\$now_hhmm" -lt 600 ] \\
        && [ "\$(cat "\$hygiene_stamp" 2>/dev/null)" != "\$today" ]; then
        hyg_lock="$COVE_DIR/.reload.lock"
        hyg_lock_fresh=0
        if [ -f "\$hyg_lock" ]; then
            hyg_mtime=\$(stat -f%m "\$hyg_lock" 2>/dev/null || stat -c%Y "\$hyg_lock" 2>/dev/null || echo 0)
            hyg_age=\$(( \$(date +%s) - hyg_mtime ))
            [ "\$hyg_age" -ge 0 ] && [ "\$hyg_age" -lt 300 ] && hyg_lock_fresh=1
        fi
        if [ "\$hyg_lock_fresh" -eq 0 ]; then
            echo "\$today" > "\$hygiene_stamp"
            ts=\$(date '+%Y-%m-%dT%H:%M:%S%z')
            echo "[\$ts] watchdog: pid=\$pid scheduled nightly restart (OPcache hygiene); SIGKILL for respawn" \\
                >> "\$log_file"
            kill -KILL "\$pid" 2>/dev/null || true
            : > "\$state_file"
        fi
    fi
    exit 0
fi

ts=\$(date '+%Y-%m-%dT%H:%M:%S%z')

# A cove reload is applying a new Caddyfile. With hundreds of sites the
# config swap holds HTTPS requests longer than fail_threshold ticks, and
# killing mid-swap trades a ~45s pause for a multi-minute cold start (TLS
# re-provisioning for every site). Hold fire while the reload lock is
# fresh — age-capped so a stale lock can't blind the watchdog forever.
# State is left untouched: a server still wedged after the reload ends
# must accumulate a full fresh streak before a kill.
reload_lock="$COVE_DIR/.reload.lock"
if [ -f "\$reload_lock" ]; then
    lock_mtime=\$(stat -f%m "\$reload_lock" 2>/dev/null || stat -c%Y "\$reload_lock" 2>/dev/null || echo 0)
    lock_age=\$(( \$(date +%s) - lock_mtime ))
    if [ "\$lock_age" -ge 0 ] && [ "\$lock_age" -lt 300 ]; then
        echo "[\$ts] watchdog: pid=\$pid probe failed during active reload (lock \${lock_age}s old); holding fire" >> "\$log_file"
        exit 0
    fi
fi

# Probe failed. A new pid, or one that has never been healthy, is still
# starting up (or its config is broken) — do NOT kill it, or we just restart
# the slow startup forever. Only intervene if it stays stuck far past any
# plausible startup window.
if [ "\$s_pid" != "\$pid" ] || [ "\$s_mode" = "starting" ]; then
    if [ "\$s_pid" = "\$pid" ] && [ "\$s_mode" = "starting" ]; then
        s_count=\$((s_count + 1))
    else
        s_count=1
    fi
    echo "\$pid starting \$s_count" > "\$state_file"
    if [ "\$s_count" -ge "\$never_healthy_ticks" ]; then
        echo "[\$ts] watchdog: pid=\$pid never became healthy after \$s_count ticks; SIGKILL for a fresh start" \\
            >> "\$log_file"
        kill -KILL "\$pid" 2>/dev/null || true
        : > "\$state_file"
    fi
    exit 0
fi

# s_pid == pid and mode=up: it was healthy and is now failing — the wedge case.
# Require a sustained streak before killing so a single transient timeout under
# load can't trigger a respawn.
s_count=\$((s_count + 1))
echo "\$pid up \$s_count" > "\$state_file"
if [ "\$s_count" -lt "\$fail_threshold" ]; then
    echo "[\$ts] watchdog: pid=\$pid probe failed (\$s_count/\$fail_threshold)" >> "\$log_file"
    exit 0
fi

echo "[\$ts] watchdog: pid=\$pid was healthy but failed \$s_count consecutive HTTPS probes; SIGKILL for respawn" \\
    >> "\$log_file"
kill -KILL "\$pid" 2>/dev/null || true
: > "\$state_file"
EOM
    chmod +x "$script_path"
    echo "$script_path"
}

# Register the watchdog with the OS service manager (launchd on macOS, a
# systemd timer on Linux) so it ticks every 5s. Extracted from cove_enable so
# cove_upgrade can install it too: pre-1.11 upgraders would otherwise get the
# new cove.sh but never the watchdog, leaving them exposed to the exact zombie
# FrankenPHP lockup the watchdog exists to auto-recover from. Idempotent —
# safe to re-run. Writes write_watchdog_script's output first.
install_watchdog_service() {
    local watchdog_bin
    watchdog_bin=$(write_watchdog_script)

    # Reset the watchdog's saved state on every (re)install. After a
    # disable/enable cycle a stale "<pid> up <n>" line could match a freshly
    # spawned FrankenPHP that the OS assigned the same pid — defeating the
    # never-kill-while-starting guard and letting the watchdog SIGKILL a server
    # that's merely still provisioning certs. A clean slate re-evaluates health
    # from scratch.
    rm -f "$COVE_DIR/.watchdog.state"

    if [ "$OS" == "macos" ]; then
        local watchdog_plist_path="$COVE_DIR/com.cove.watchdog.plist"

        launchctl unload "$watchdog_plist_path" &>/dev/null

        echo "   - Generating Cove watchdog service file..."
        cat > "$watchdog_plist_path" << EOM
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>Label</key>
        <string>com.cove.watchdog</string>
        <key>ProgramArguments</key>
        <array>
                <string>/bin/bash</string>
                <string>$watchdog_bin</string>
        </array>
        <key>StartInterval</key>
        <integer>5</integer>
        <key>RunAtLoad</key>
        <true/>
        <key>StandardErrorPath</key>
        <string>$LOGS_DIR/watchdog.log</string>
</dict>
</plist>
EOM
        launchctl load "$watchdog_plist_path"
    fi

    if [ "$OS" == "linux" ]; then
        local current_user
        current_user=$(whoami)
        local watchdog_service_path="/etc/systemd/system/cove-watchdog.service"
        local watchdog_timer_path="/etc/systemd/system/cove-watchdog.timer"

        echo "   - Generating Cove watchdog service + timer..."
        # Same sudo-tee pattern as the mailpit/cove units above; see note
        # on mailpit.service for why mktemp + sudo mv doesn't survive SELinux.
        $SUDO_CMD tee "$watchdog_service_path" >/dev/null << EOM
[Unit]
Description=Cove FrankenPHP watchdog (detects zombie process, forces respawn)
After=cove.service

[Service]
Type=oneshot
ExecStart=/bin/bash $watchdog_bin
User=$current_user
Environment=HOME=/home/$current_user
EOM
        $SUDO_CMD chmod 644 "$watchdog_service_path"

        $SUDO_CMD tee "$watchdog_timer_path" >/dev/null << EOM
[Unit]
Description=Run Cove watchdog every 5 seconds
Requires=cove-watchdog.service

[Timer]
OnBootSec=30s
OnUnitActiveSec=5s
AccuracySec=1s
Unit=cove-watchdog.service

[Install]
WantedBy=timers.target
EOM
        $SUDO_CMD chmod 644 "$watchdog_timer_path"

        $SUDO_CMD systemctl daemon-reload
        $SUDO_CMD systemctl enable cove-watchdog.timer &>/dev/null
        $SUDO_CMD systemctl restart cove-watchdog.timer
    fi
}

# Write a standalone mailpit runner to $COVE_DIR so launchd/systemd can invoke
# it without depending on the cove binary. The wrapper's job is to *own* the
# SMTP/HTTP ports cleanly: kill any orphaned mailpit that would make us fail
# to bind, cap the log so a past thrash doesn't fill the disk, then exec.
#
# Failure mode this prevents: an orphaned mailpit (manual start, brew services
# leftover, or a previous job that outlived unload) holds :1025/:8025; the
# service-managed instance fails with "address already in use" and exits;
# KeepAlive/Restart=always respawns forever (observed: 51k restarts over ~10
# days and a 28MB log of nothing but bind errors).
write_mailpit_run_script() {
    local script_path="$COVE_DIR/mailpit-run.sh"
    local mailpit_bin
    mailpit_bin=$(command -v mailpit)
    mkdir -p "$COVE_DIR" "$LOGS_DIR"
    cat > "$script_path" << EOM
#!/bin/bash
# Auto-generated by install_mailpit_service. See write_mailpit_run_script() in main.
mailpit_bin="$mailpit_bin"
db_path="$COVE_DIR/mailpit.db"
log_file="$LOGS_DIR/mailpit.log"
log_cap_bytes=52428800    # 50MB — a restart storm must not fill the disk

mkdir -p "$LOGS_DIR"

# Cap the log. A bind-failure restart storm used to push this into the tens of
# MBs with nothing useful but "address already in use" lines. Keep the most
# recent 1MB so a real error still has context.
if [ -f "\$log_file" ]; then
    lsize=\$(stat -f%z "\$log_file" 2>/dev/null || stat -c%s "\$log_file" 2>/dev/null || echo 0)
    if [ "\$lsize" -gt "\$log_cap_bytes" ]; then
        tail -c 1048576 "\$log_file" > "\$log_file.tmp" 2>/dev/null \\
            && mv "\$log_file.tmp" "\$log_file" 2>/dev/null
    fi
fi

# Clear the path. We're about to exec mailpit as the sole owner of :1025/:8025;
# any leftover is fair game. pgrep -x matches the basename only (never this
# bash wrapper), so we won't kill ourselves.
if command -v pgrep >/dev/null 2>&1; then
    orphans=\$(pgrep -x mailpit 2>/dev/null || true)
    if [ -n "\$orphans" ]; then
        # Intentional word-split: one signal for the whole set.
        # shellcheck disable=SC2086
        kill \$orphans 2>/dev/null || true
        sleep 0.4
        # shellcheck disable=SC2086
        kill -KILL \$orphans 2>/dev/null || true
        # Brief settle so the kernel releases the sockets before we bind.
        sleep 0.2
    fi
fi

if [ ! -x "\$mailpit_bin" ]; then
    echo "mailpit-run: binary not found or not executable: \$mailpit_bin" >&2
    exit 127
fi

exec "\$mailpit_bin" --database "\$db_path"
EOM
    chmod +x "$script_path"
    echo "$script_path"
}

# (Re)install the Mailpit service unit + runner. Shared by cove_enable and
# post-upgrade so upgraders pick up the orphan-clearing wrapper without a
# manual re-enable. Idempotent.
install_mailpit_service() {
    if ! command -v mailpit &>/dev/null; then
        echo "   ⚠️  mailpit not installed; skipping mailpit service." >&2
        return 0
    fi

    local run_script
    run_script=$(write_mailpit_run_script)
    mkdir -p "$LOGS_DIR"

    if [ "$OS" == "macos" ]; then
        local plist_path="$COVE_DIR/com.cove.mailpit.plist"

        # Stop any brew/nanobrew mailpit and unload our prior job so we own
        # the ports. The runner also kills orphans at start; this is the
        # enable-time pass so load doesn't race a leftover.
        launchctl unload "$plist_path" &>/dev/null || true
        pkg_service stop mailpit &>/dev/null || true
        if command -v pgrep >/dev/null 2>&1; then
            local orphans
            orphans=$(pgrep -x mailpit 2>/dev/null || true)
            if [ -n "$orphans" ]; then
                # shellcheck disable=SC2086
                kill $orphans 2>/dev/null || true
                sleep 0.3
                # shellcheck disable=SC2086
                kill -KILL $orphans 2>/dev/null || true
            fi
        fi

        echo "   - Generating Mailpit service file..."
        cat > "$plist_path" << EOM
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>KeepAlive</key>
        <true/>
        <!-- Default throttle is 10s; stretch it so a real port conflict
             (something non-mailpit on :1025) can't spam-restart forever.
             The runner clears mailpit orphans, so normal restarts are fast. -->
        <key>ThrottleInterval</key>
        <integer>30</integer>
        <key>Label</key>
        <string>com.cove.mailpit</string>
        <key>ProgramArguments</key>
        <array>
                <string>/bin/bash</string>
                <string>$run_script</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>StandardErrorPath</key>
        <string>$LOGS_DIR/mailpit.log</string>
        <key>StandardOutPath</key>
        <string>$LOGS_DIR/mailpit.log</string>
</dict>
</plist>
EOM
        launchctl load "$plist_path"
        launchctl start com.cove.mailpit
    fi

    if [ "$OS" == "linux" ]; then
        local service_path="/etc/systemd/system/mailpit.service"
        local current_user
        current_user=$(whoami)

        echo "   - Generating Mailpit service file..."
        # Write the unit file directly via sudo tee (SELinux-safe; see the
        # note in cove_enable's original mailpit unit for why mktemp+mv fails).
        $SUDO_CMD tee "$service_path" >/dev/null << EOM
[Unit]
Description=Mailpit Service for Cove
After=network.target

[Service]
# Wrapper clears orphaned mailpit processes before bind (see
# write_mailpit_run_script) so a leftover can't thrash Restart=.
ExecStart=/bin/bash $run_script
# on-failure (not always): a clean stop stays down. RestartSec backs off
# enough that a real port conflict doesn't spin the journal.
Restart=on-failure
RestartSec=5s
User=$current_user

[Install]
WantedBy=multi-user.target
EOM
        $SUDO_CMD chmod 644 "$service_path"
        $SUDO_CMD systemctl daemon-reload
        $SUDO_CMD systemctl enable mailpit &>/dev/null
        $SUDO_CMD systemctl restart mailpit
    fi
}

# --- Per-site PHP: native php-fpm services ---
# Sites pinned to an older PHP (a `php_version` file in the site dir) are
# served by Homebrew's php@<ver> php-fpm behind FrankenPHP. Cove owns the
# whole FPM lifecycle (config + launchd unit) rather than `brew services`:
# Homebrew's stock pool listens on 127.0.0.1:9000 for EVERY version (instant
# collision with two pinned versions) and carries none of Cove's ini
# semantics (mailpit sendmail, Whoops prepend, shared error log).

# Write the generated php-fpm config for a version. Homebrew's own php.ini +
# conf.d still load first (that's what enables the opcache extension); the
# pool then overrides everything Cove cares about via php_admin_value — the
# FPM analog of the frankenphp{} php_ini block in regenerate_caddyfile.
write_php_fpm_config() {
    local ver="$1"
    local conf_dir="$PHP_FPM_DIR/$ver"
    local mailpit_path
    mailpit_path=$(command -v mailpit)
    mkdir -p "$conf_dir" "$RUN_DIR" "$LOGS_DIR" "$COVE_DIR/cache/sessions"
    cat > "$conf_dir/php-fpm.conf" << EOM
[global]
; Auto-generated by Cove (write_php_fpm_config in main). Do not edit —
; regenerated on every pin, reload, and post-upgrade.
error_log = $LOGS_DIR/php-fpm-$ver.log
daemonize = no

[cove]
listen = $RUN_DIR/php-$ver.sock
listen.mode = 0600
; ondemand: workers spawn per request and idle out — right for a dev box
; where a pinned site may go untouched for days.
pm = ondemand
pm.max_children = 10
pm.process_idle_timeout = 60s
pm.max_requests = 500
catch_workers_output = yes
; Mirror of the frankenphp{} php_ini block. The ZTS OPcache sizing there is
; deliberately NOT replicated: this is NTS php-fpm with a per-pool cache, so
; PHP's stock OPcache defaults are correct here.
php_admin_value[sendmail_path] = $mailpit_path sendmail -t
php_admin_flag[log_errors] = on
php_admin_flag[display_errors] = off
php_admin_value[error_log] = $LOGS_DIR/errors.log
php_admin_value[auto_prepend_file] = $APP_DIR/whoops_bootstrap.php
php_admin_value[memory_limit] = $(cove_ini_get memory_limit 1G)
php_admin_value[upload_max_filesize] = $(cove_ini_get upload_max_filesize 1G)
php_admin_value[post_max_size] = $(cove_ini_get post_max_size 1G)
php_admin_value[session.save_path] = $COVE_DIR/cache/sessions
EOM
    echo "$conf_dir/php-fpm.conf"
}

# (Re)install the php-fpm unit for one version. Idempotent AND restart-shy:
# when the config is unchanged and the master process is already up, this is
# a no-op — regenerate_caddyfile calls the reconciler on every reload, and a
# `cove add` must not bounce every pinned site's FPM as a side effect.
install_php_fpm_service() {
    local ver="$1"
    local prefix
    prefix=$(php_fpm_prefix_for "$ver")
    if [ -z "$prefix" ]; then
        echo "   ⚠️  php@$ver (php-fpm) not found; sites pinned to $ver fall back to FrankenPHP." >&2
        return 1
    fi

    local conf_path="$PHP_FPM_DIR/$ver/php-fpm.conf"
    local old_conf=""
    [ -f "$conf_path" ] && old_conf=$(cat "$conf_path")
    write_php_fpm_config "$ver" >/dev/null
    local new_conf
    new_conf=$(cat "$conf_path")

    local label="com.cove.php-fpm-$ver"
    local plist_path="$COVE_DIR/$label.plist"
    if [ "$old_conf" == "$new_conf" ] && [ -f "$plist_path" ] \
        && pgrep -f "php-fpm/$ver/php-fpm.conf" &>/dev/null; then
        return 0
    fi

    launchctl unload "$plist_path" &>/dev/null || true
    cat > "$plist_path" << EOM
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>KeepAlive</key>
        <true/>
        <key>ThrottleInterval</key>
        <integer>10</integer>
        <key>Label</key>
        <string>$label</string>
        <key>ProgramArguments</key>
        <array>
                <string>$prefix/sbin/php-fpm</string>
                <string>--nodaemonize</string>
                <string>--fpm-config</string>
                <string>$conf_path</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>StandardErrorPath</key>
        <string>$LOGS_DIR/php-fpm-$ver.log</string>
        <key>StandardOutPath</key>
        <string>$LOGS_DIR/php-fpm-$ver.log</string>
</dict>
</plist>
EOM
    launchctl load "$plist_path"
    launchctl start "$label"
}

# Stop + remove the unit for a version nothing pins anymore. The generated
# config dir under $PHP_FPM_DIR is kept on purpose — it's tiny and makes a
# re-pin instant.
remove_php_fpm_service() {
    local ver="$1"
    local plist_path="$COVE_DIR/com.cove.php-fpm-$ver.plist"
    launchctl unload "$plist_path" &>/dev/null || true
    rm -f "$plist_path" "$RUN_DIR/php-$ver.sock"
}

# Reconcile running php-fpm units against what sites actually pin. Called
# from regenerate_caddyfile, so pin, unpin, delete, clone, and plain `cove
# reload` all converge service state for free — no eager teardown wiring
# anywhere else.
sync_php_fpm_services() {
    local needed=" "
    local site_path ver
    if [ -d "$SITES_DIR" ]; then
        for site_path in "$SITES_DIR"/*; do
            [ -d "$site_path" ] || continue
            ver=$(site_php_version "$site_path")
            [ -n "$ver" ] || continue
            if [ "$OS" != "macos" ] || [ "$MAC_BREW" != "brew" ]; then
                echo "   ⚠️  $(basename "$site_path") pins PHP $ver, but per-site PHP requires Homebrew on macOS; serving with FrankenPHP." >&2
                continue
            fi
            case "$needed" in
                *" $ver "*) ;;
                *) needed+="$ver " ;;
            esac
        done
    fi

    if [ "$OS" != "macos" ] || [ "$MAC_BREW" != "brew" ]; then
        return 0
    fi

    for ver in $needed; do
        install_php_fpm_service "$ver" || true
    done

    local plist
    for plist in "$COVE_DIR"/com.cove.php-fpm-*.plist; do
        [ -f "$plist" ] || continue
        ver=$(basename "$plist" .plist)
        ver="${ver#com.cove.php-fpm-}"
        case "$needed" in
            *" $ver "*) ;;
            *) remove_php_fpm_service "$ver" ;;
        esac
    done
}

# Validate a Cove site name: lowercase letters, digits, and hyphens only, no
# leading/trailing hyphen. Mirrors the rules cove_add enforces (add:14-23) and
# the dashboard's add_site regex, so every command that turns a name into a
# filesystem path or database name rejects `../` traversal and shell/SQL
# metacharacters uniformly. Returns non-zero on rejection; caller decides how
# to report. Keep in sync with add's inline checks.
validate_site_name() {
    local name="$1"
    [ -n "$name" ] || return 1
    [[ "$name" =~ [^a-z0-9-] ]] && return 1
    [[ "$name" == -* || "$name" == *- ]] && return 1
    return 0
}

# Validate a hostname/domain label before it is written into the Caddyfile and
# /etc/hosts (site mappings, proxy domains, the Tailscale hostname). Accepts a
# bare hostname or IP — underscores included (dev hostnames, _domainkey-style
# labels) and an optional leading "*." wildcard label (valid as a Caddy site
# address) — but no whitespace, no Caddy metacharacters ({ } newlines), no
# slashes. Without this the value could inject a Caddy server block, or (once
# read back into update_etc_hosts) a second root-written /etc/hosts line.
validate_hostname() {
    local host="$1"
    [ -n "$host" ] || return 1
    [ "${#host}" -le 253 ] || return 1
    host="${host#\*.}"
    [[ "$host" =~ ^[A-Za-z0-9_]([A-Za-z0-9._-]*[A-Za-z0-9_])?$ ]] || return 1
    return 0
}

# Validate a reverse-proxy target (host or host:port). Same safe charset the
# Tailscale proxy path already enforces on its target — letters, numbers, dots,
# hyphens, underscores, and the port colon — which forbids the whitespace and
# braces needed to break out of the `reverse_proxy <target>` line.
validate_proxy_target() {
    local target="$1"
    [ -n "$target" ] || return 1
    [[ "$target" =~ ^[A-Za-z0-9._:-]+$ ]] || return 1
    return 0
}

# Write the Cove-themed Adminer entry point (index.php with the head() hook
# that injects the theme toggle, plus autologin) and refresh the theme
# assets (adminer.css, adminer.js) from GitHub. Shared by cove_install
# (initial deploy) and cove_upgrade (so upgraders pick up theme changes
# without a reinstall). Idempotent — overwrites existing files.
deploy_adminer_theme() {
    local adminer_dir="${1:-$ADMINER_DIR}"
    mkdir -p "$adminer_dir"

    echo "⚙️ Writing Adminer entry point..."
    cat > "$adminer_dir/index.php" << 'ADMINER_INDEX_EOF'
<?php
// This is the custom entry point for Adminer with autologin.
function adminer_object() {
    // Adminer 5.x uses the Adminer namespace
    class AdminerCoveLogin extends Adminer\Adminer {
        function name() { return 'Cove DB Manager'; }
        function permanentLogin($i = false) { return "cove-local-development-key"; }
        function credentials() {
            $configFile = getenv('HOME') . '/Cove/config';
            if (file_exists($configFile)) {
                $config = parse_ini_file($configFile);
                $db_user = $config['DB_USER'] ?? null;
                $db_pass = $config['DB_PASSWORD'] ?? null;
                return ['localhost', $db_user, $db_pass];
            }
            return ['localhost', null, null];
        }
        function login($login, $password) { return true; }
        function head($title = null) {
            // Inject the Cove theme toggle. Inline init runs before adminer.css
            // applies so the saved choice (or system preference) is honored
            // without a theme flash on load.
            $nonce = \Adminer\nonce();
            $init = "(function(){try{var s=localStorage.getItem('cove-adminer-theme');var t=(s==='dark'||s==='light')?s:(window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');document.documentElement.setAttribute('data-theme',t);}catch(e){}})();";
            echo "<script{$nonce}>{$init}</script>\n";
            $v = @filemtime(__DIR__ . '/adminer.js') ?: 1;
            echo "<script src='adminer.js?v={$v}'{$nonce}></script>\n";
            return true;
        }
    }
    return new AdminerCoveLogin();
}
// Include the original Adminer core file to run the application.
include "./adminer-core.php";
ADMINER_INDEX_EOF

    echo "🎨 Downloading Cove Adminer theme..."
    curl -sL "https://raw.githubusercontent.com/anchorhost/cove/main/adminer-theme/adminer.css" -o "$adminer_dir/adminer.css"
    curl -sL "https://raw.githubusercontent.com/anchorhost/cove/main/adminer-theme/adminer.js"  -o "$adminer_dir/adminer.js"
}

# Repair ownership of ~/Cove state that a pre-1.10 root-run FrankenPHP may
# have left owned by root. The most user-visible symptom is the size cache
# (~/Cove/cache/site-sizes.json) becoming unwritable — refresh_sizes computes
# correctly, @file_put_contents silently fails, and list_sites returns stale
# nulls. Safe to call repeatedly; only runs chown when the ownership is
# actually wrong. macOS never needs this because launchd runs as the user.
heal_cove_state_ownership() {
    [ "$OS" = "linux" ] || return 0
    local uid; uid=$(id -u)
    local gid; gid=$(id -g)
    local target
    for target in "$COVE_DIR/cache" "$COVE_DIR/.reload.lock" "$COVE_DIR/.reload.lock.d" "$COVE_DIR/.reload.pending" "$COVE_DIR/caddy.pid" "$COVE_DIR/.watchdog.state"; do
        [ -e "$target" ] || continue
        # Cheap short-circuit: only invoke sudo if the top-level is wrong.
        [ "$(stat -c %u "$target" 2>/dev/null)" = "$uid" ] && continue
        $SUDO_CMD -n chown -R "$uid:$gid" "$target" 2>/dev/null || true
    done
}

# (Re)start the Caddy/FrankenPHP service. Safe to call when already running —
# both platforms stop any existing instance first. Called from `cove enable`
# and from regenerate_caddyfile when Caddy isn't up yet.
start_caddy_service() {
    echo "   - Starting Caddy/FrankenPHP..."
    mkdir -p "$LOGS_DIR"

    if [ "$OS" == "macos" ]; then
        local caddy_plist_path="$COVE_DIR/com.cove.caddy.plist"
        local frankenphp_bin
        frankenphp_bin=$(command -v "$CADDY_CMD")

        launchctl unload "$caddy_plist_path" &>/dev/null
        "$CADDY_CMD" stop --config "$CADDYFILE_PATH" &>/dev/null 2>&1

        cat > "$caddy_plist_path" << EOM
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>EnvironmentVariables</key>
        <dict>
                <!-- ImageMagick installs process-wide SIGSEGV/SIGABRT handlers
                     without SA_ONSTACK. In FrankenPHP's threaded (ZTS) server a
                     fault on a Go worker thread then trips the Go runtime's
                     "non-Go code set up signal handler without SA_ONSTACK flag"
                     fatal — and the "panic during panic" path wedges a core at
                     100% for minutes. Disabling IM's handlers lets a fault
                     surface as a clean crash the service manager restarts fast. -->
                <key>MAGICK_SIGNAL_HANDLERS</key>
                <string>0</string>
        </dict>
        <!-- launchd's default soft file-descriptor limit is 256. FrankenPHP
             holds ~1 FD per site (listener/cert) plus one per in-flight
             request, so a Cove install with a couple hundred sites idles near
             the ceiling and hits EMFILE ("too many open files") under any
             concurrency — which wedges the Go runtime (connections accept at
             the kernel but request handlers stall). Raise the soft limit well
             clear of that; the hard limit is already unlimited on macOS. -->
        <key>SoftResourceLimits</key>
        <dict>
                <key>NumberOfFiles</key>
                <integer>65536</integer>
        </dict>
        <key>HardResourceLimits</key>
        <dict>
                <key>NumberOfFiles</key>
                <integer>65536</integer>
        </dict>
        <key>KeepAlive</key>
        <true/>
        <key>Label</key>
        <string>com.cove.caddy</string>
        <key>ProgramArguments</key>
        <array>
                <string>$frankenphp_bin</string>
                <string>run</string>
                <string>--config</string>
                <string>$CADDYFILE_PATH</string>
                <string>--pidfile</string>
                <string>$COVE_DIR/caddy.pid</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>StandardErrorPath</key>
        <string>$LOGS_DIR/caddy-process.log</string>
        <key>StandardOutPath</key>
        <string>$LOGS_DIR/caddy-process.log</string>
</dict>
</plist>
EOM
        launchctl load "$caddy_plist_path"
        launchctl start com.cove.caddy
    fi

    if [ "$OS" == "linux" ]; then
        # v1.10+: Caddy runs as cove.service under systemd (installed by
        # cove_enable), so it survives reboots. Prefer systemctl when the
        # unit is present; fall back to an ad-hoc foreground start only if
        # someone invoked this before cove_enable wrote the unit.
        if systemctl list-unit-files cove.service &>/dev/null 2>&1 \
            && systemctl cat cove.service &>/dev/null 2>&1; then
            $SUDO_CMD systemctl restart cove.service
        else
            # A pre-1.10 root-owned pidfile would block a user-run start.
            if [ -e "$COVE_DIR/caddy.pid" ] && [ ! -w "$COVE_DIR/caddy.pid" ]; then
                $SUDO_CMD -n rm -f "$COVE_DIR/caddy.pid" 2>/dev/null || true
            fi
            "$CADDY_CMD" stop --config "$CADDYFILE_PATH" &>/dev/null \
                || $SUDO_CMD -n "$CADDY_CMD" stop --config "$CADDYFILE_PATH" &>/dev/null \
                || true
            # MAGICK_SIGNAL_HANDLERS=0: see the macOS plist above — keeps an
            # ImageMagick fault from tripping the Go runtime's SA_ONSTACK fatal.
            MAGICK_SIGNAL_HANDLERS=0 "$CADDY_CMD" start --config "$CADDYFILE_PATH" --pidfile "$COVE_DIR/caddy.pid" >> "$LOGS_DIR/caddy-process.log" 2>&1
        fi
    fi
}

# Function to regenerate the Caddyfile
# Remove leftover skeletons of deleted sites. A Caddy reload that races a
# `cove delete` re-applies a config snapshot that still names the deleted
# site, and Caddy's log directive re-creates <site>/logs/ at apply time.
# cove_delete leaves a tombstone naming each deleted site so the next reload
# can prune that skeleton. A dir that regained a public/ tree was re-created
# by the user — leave it alone and just drop the tombstone.
prune_delete_tombstones() {
    local tombstone_dir="$COVE_DIR/cache/delete-tombstones"
    [ -d "$tombstone_dir" ] || return 0
    local ts ts_site
    for ts in "$tombstone_dir"/*; do
        [ -e "$ts" ] || continue
        ts_site="$SITES_DIR/$(basename "$ts")"
        if [ -d "$ts_site" ] && [ ! -d "$ts_site/public" ]; then
            rm -rf "$ts_site"
        fi
        rm -f "$ts"
    done
}

# Emit the PHP handler line for a site's server block: php_fastcgi to the
# pinned native php-fpm when the site has a php_version AND the binary
# resolves, php_server (FrankenPHP) otherwise. The fallback means a
# half-installed pin degrades to "wrong PHP version" rather than a hard 502.
# php_fastcgi ships the same try_files/index semantics as php_server, and its
# default directive order already precedes file_server, so the plain-site
# file_server conditional below needs no change.
emit_site_php_handler() {
    local site_path="$1"
    local ver
    ver=$(site_php_version "$site_path")
    if [ -n "$ver" ] && [ -n "$(php_fpm_prefix_for "$ver")" ]; then
        # php_server is shorthand for php_fastcgi + file_server. When swapping
        # in a pinned socket, file_server must come along explicitly or every
        # static asset (JS/CSS/images) falls through to no handler and Caddy
        # answers with an empty 200 — which presents as a broken wp-admin.
        echo "    php_fastcgi unix/$(php_fpm_sock_for "$ver")" >> "$CADDYFILE_PATH"
        echo "    file_server" >> "$CADDYFILE_PATH"
    else
        echo "    php_server" >> "$CADDYFILE_PATH"
    fi
}

# Read a site's multisite marker: "subdirectory", "subdomain", or "" when the
# site is not a network. Written by `cove add --multisite`.
site_multisite_mode() {
    local site_path="$1"
    [ -f "$site_path/multisite" ] && cat "$site_path/multisite"
}

# WordPress subdirectory-multisite rewrites, the Caddy translation of the
# canonical nginx rules. A subsite request like /store/wp-admin/... or
# /store/wp-login.php has no matching file on disk — the real files live at
# the root — so rewrite the subsite prefix away. The `not file` guard is
# load-bearing: it scopes the rewrite to paths that DON'T exist, so real
# root files (/wp-admin/index.php itself) are never mangled. Caddy runs
# redir/rewrite before php_server AND php_fastcgi in its standard directive
# order, so this works for FrankenPHP and pinned-FPM sites alike.
emit_multisite_subdir_rewrites() {
    cat >> "$CADDYFILE_PATH" <<'EOM'
    @cove_ms_admin path_regexp ^(/[_0-9a-zA-Z-]+)?/wp-admin$
    redir @cove_ms_admin {path}/ permanent
    @cove_ms_rewrite {
        not file
        path_regexp cove_ms ^/[_0-9a-zA-Z-]+(/wp-.*|/.*\.php)$
    }
    rewrite @cove_ms_rewrite {re.cove_ms.1}
EOM
}

regenerate_caddyfile() {
    echo "🔄 Regenerating Caddyfile..."
    if ! command -v mailpit &> /dev/null; then
        gum style --foreground red "❌ Mailpit is not installed. Please run 'cove install' successfully first."
        return 1
    fi
    # Ensure the user-owned PHP session dir referenced by the Caddyfile's
    # `php_ini session.save_path` exists before FrankenPHP tries to use it.
    mkdir -p "$COVE_DIR/cache/sessions" "$RUN_DIR" 2>/dev/null
    # Converge native php-fpm services with the sites' php_version pins BEFORE
    # writing the config that points at their sockets.
    sync_php_fpm_services
    local mailpit_path
    mailpit_path=$(command -v mailpit)

    # Build optional http_port / https_port directives when non-default.
    local port_directives=""
    if [ "$HTTP_PORT" != "80" ]; then
        port_directives+="    http_port $HTTP_PORT"$'\n'
    fi
    if [ "$HTTPS_PORT" != "443" ]; then
        port_directives+="    https_port $HTTPS_PORT"$'\n'
    fi

    # Disable opcache_reset in the web SAPI. Plugins (Site Kit, Redirection)
    # call it from upgrader_process_complete; under ZTS that restart races
    # other threads and aborts the process. cove health still needs
    # opcache_get_status, so we disable only the reset. Merge with any
    # disable_functions the user already set in php.ini.
    local disabled_fns
    disabled_fns=$(cove_ini_get disable_functions "")
    case ",$disabled_fns," in
        *,opcache_reset,*) ;;
        *) disabled_fns="${disabled_fns:+$disabled_fns,}opcache_reset" ;;
    esac

    # Write the static header of the Caddyfile
    cat > "$CADDYFILE_PATH" <<- EOM
{
${port_directives}    frankenphp {
        # Worker threads: see cove_num_threads(). Long-running requests
        # (SSE long-polls, slow loopbacks) each pin a thread for their whole
        # lifetime; the stock 2x-cores pool starves under a handful of them.
        # Sized at 4x cores (floor 16), then capped at 1 thread per GB of
        # RAM so a 16 GB box does not get 32 ZTS workers compiling into
        # one OPcache arena.
        num_threads $(cove_ini_get num_threads "$(cove_num_threads)")
        php_ini sendmail_path "$mailpit_path sendmail -t"
        php_ini log_errors On
        php_ini display_errors Off
        php_ini error_log "$LOGS_DIR/errors.log"
        php_ini auto_prepend_file "$APP_DIR/whoops_bootstrap.php"
        php_ini memory_limit $(cove_ini_get memory_limit 1G)
        php_ini upload_max_filesize $(cove_ini_get upload_max_filesize 1G)
        php_ini post_max_size $(cove_ini_get post_max_size 1G)
        # OPcache sizing. FrankenPHP embeds a THREAD-SAFE (ZTS) PHP, so every
        # site on the box shares ONE OPcache arena across all worker threads.
        # PHP's stock limits (128M / 8M interned / 10000 files) are sized for a
        # single small FPM pool and are wildly undersized here: one Cove box
        # routinely holds 100+ WordPress sites (hundreds of thousands of PHP
        # files, tens of thousands in a single large site). When the arena or
        # the interned-strings buffer fills, OPcache does a blocking SHM
        # *restart* — and under ZTS a restart racing concurrent compiles
        # corrupts shared memory, segfaulting PHP inside cache_script_in_
        # shared_memory (lex/persist/optimize). FrankenPHP's Go runtime then
        # turns that SIGSEGV into a whole-process abort (the "non-Go code set
        # up signal handler without SA_ONSTACK" fatal), which reads as random
        # server crashes while editing a heavy plugin. Right-size the arena so
        # a restart is rare, and disable the optimizer: with validate_timestamps
        # on (dev), files recompile constantly so the optimizer buys almost
        # nothing, and its SSA/DFA/call-graph passes were a recurring crash site.
        php_ini opcache.memory_consumption $(cove_ini_get opcache.memory_consumption 512)
        php_ini opcache.interned_strings_buffer $(cove_ini_get opcache.interned_strings_buffer 64)
        php_ini opcache.max_accelerated_files $(cove_ini_get opcache.max_accelerated_files 100000)
        php_ini opcache.optimization_level $(cove_ini_get opcache.optimization_level 0)
        # See the disabled_fns note above: opcache_reset under ZTS aborts
        # the process. disable_functions leaves opcache_get_status intact
        # so the health command can still read the arena.
        php_ini disable_functions $disabled_fns
        # User-owned session dir. Linux apt's php.ini points sessions at
        # /var/lib/php-zts/session (owned by the frankenphp user); since
        # Cove runs FrankenPHP as the invoking user, that path is
        # unwritable and Adminer spams session_start warnings every
        # request.
        php_ini session.save_path "$COVE_DIR/cache/sessions"
    }
    order php_server before file_server
    servers {
        # HTTP/1.1 and HTTP/2. The h1-only pin this replaces dated from
        # FrankenPHP 1.11/1.12.2, where Chrome intermittently failed local
        # requests with ERR_INCOMPLETE_CHUNKED_ENCODING over h2. Cove ships
        # 1.12.4 now, which fixed those worker-mode races. h1 alone caps a
        # browser at six connections per site, which serializes any app that
        # opens with a fan-out of REST calls. h3 stays off: QUIC is UDP and
        # brings its own local-certificate variables for no dev-time gain.
        protocols h1 h2
    }
}

# --- Global Services ---

mail.cove.localhost {
    reverse_proxy 127.0.0.1:8025
    tls internal
}

db.cove.localhost {
    root * "$ADMINER_DIR"
    php_server
    tls internal
}

cove.localhost {
    root * "$GUI_DIR"
    php_server
    tls internal
}

# --- Cove Managed Sites ---
EOM

    # Check if Tailscale is enabled
    local tailscale_hostname=""
    local tailscale_config="$APP_DIR/tailscale"
    if [ -f "$tailscale_config" ]; then
        tailscale_hostname=$(cat "$tailscale_config")
    fi

    # Append blocks for each site dynamically
    if [ -d "$SITES_DIR" ]; then
        for site_path in "$SITES_DIR"/*; do
            if [ -d "$site_path" ]; then
                local site_name
                site_name=$(basename "$site_path")

                # Skip dirs that aren't servable sites: no public/ docroot and
                # no custom directive. Notably the logs/-only skeleton Caddy
                # re-creates when a reload races a delete — emitting a block
                # for it would resurrect the deleted site on every reload.
                if [ ! -d "$site_path/public" ] && [ ! -f "$CUSTOM_CADDY_DIR/$site_name" ]; then
                    continue
                fi

                # Build the list of domains
                local site_domains="$site_name"

                # Subdomain multisite: serve every subsite through a wildcard
                # alias. Caddy's internal CA issues the *.name.localhost cert
                # and *.localhost resolves to loopback natively, so subsites
                # created in wp-admin work with no further configuration.
                local ms_mode
                ms_mode=$(site_multisite_mode "$site_path")
                if [ "$ms_mode" == "subdomain" ]; then
                    site_domains="$site_domains, *.$site_name"
                fi

                if [ -f "$site_path/mappings" ]; then
                    while IFS= read -r mapping || [ -n "$mapping" ]; do
                         if [ -n "$mapping" ]; then
                            site_domains="$site_domains, $mapping"
                         fi
                    done < "$site_path/mappings"
                fi

                echo "$site_domains {" >> "$CADDYFILE_PATH"
                
                echo "    root * \"$site_path/public\"" >> "$CADDYFILE_PATH"
                echo "    tls internal" >> "$CADDYFILE_PATH"
                
                echo "    log {" >> "$CADDYFILE_PATH"
                echo "        output file \"$site_path/logs/caddy.log\"" >> "$CADDYFILE_PATH"
                echo "    }" >> "$CADDYFILE_PATH"
                
                local custom_conf_file="$CUSTOM_CADDY_DIR/$site_name"
                if [ -f "$custom_conf_file" ]; then
                    echo "" >> "$CADDYFILE_PATH"
                    sed 's/^/    /' "$custom_conf_file" >> "$CADDYFILE_PATH"
                    echo "" >> "$CADDYFILE_PATH"
                fi

                if [ "$ms_mode" == "subdirectory" ]; then
                    emit_multisite_subdir_rewrites
                fi

                emit_site_php_handler "$site_path"

                if [ ! -f "$site_path/public/wp-config.php" ]; then
                    echo "    file_server" >> "$CADDYFILE_PATH"
                fi

                echo "}" >> "$CADDYFILE_PATH"
                echo "" >> "$CADDYFILE_PATH"

                # Check if LAN access is enabled for this site
                local lan_config="$site_path/lan_config"
                if [ -f "$lan_config" ]; then
                    local lan_port
                    lan_port=$(grep "^port=" "$lan_config" | cut -d'=' -f2)

                    if [ -n "$lan_port" ]; then
                        local lan_ip
                        lan_ip=$(get_lan_ip)
                        echo "# LAN access for $site_name on port $lan_port" >> "$CADDYFILE_PATH"
                        echo "https://${lan_ip}:${lan_port} {" >> "$CADDYFILE_PATH"
                        echo "    bind 0.0.0.0" >> "$CADDYFILE_PATH"
                        echo "    root * \"$site_path/public\"" >> "$CADDYFILE_PATH"
                        echo "    tls internal" >> "$CADDYFILE_PATH"
                        
                        echo "    log {" >> "$CADDYFILE_PATH"
                        echo "        output file \"$site_path/logs/caddy-lan.log\"" >> "$CADDYFILE_PATH"
                        echo "    }" >> "$CADDYFILE_PATH"
                        
                        if [ -f "$custom_conf_file" ]; then
                            echo "" >> "$CADDYFILE_PATH"
                            sed 's/^/    /' "$custom_conf_file" >> "$CADDYFILE_PATH"
                            echo "" >> "$CADDYFILE_PATH"
                        fi

                        # Subdirectory subsites work over the LAN IP too;
                        # subdomain subsites can't (an IP has no subdomains),
                        # so only the network's main site is reachable there.
                        if [ "$ms_mode" == "subdirectory" ]; then
                            emit_multisite_subdir_rewrites
                        fi

                        emit_site_php_handler "$site_path"

                        if [ ! -f "$site_path/public/wp-config.php" ]; then
                            echo "    file_server" >> "$CADDYFILE_PATH"
                        fi

                        echo "}" >> "$CADDYFILE_PATH"
                        echo "" >> "$CADDYFILE_PATH"
                    fi
                fi
            fi
        done
    fi

    # Append custom proxy entries
    local proxy_dir="$APP_DIR/proxies"
    if [ -d "$proxy_dir" ] && [ -n "$(ls -A "$proxy_dir" 2>/dev/null)" ]; then
        echo "# --- Custom Reverse Proxies ---" >> "$CADDYFILE_PATH"
        echo "" >> "$CADDYFILE_PATH"
        
        for proxy_file in "$proxy_dir"/*; do
            if [ -f "$proxy_file" ]; then
                local proxy_name
                proxy_name=$(basename "$proxy_file")
                
                local proxy_domain=""
                local proxy_target=""
                local proxy_tls="internal"

                # Read the config file
                while IFS='=' read -r key value; do
                    case "$key" in
                        domain) proxy_domain="$value" ;;
                        target) proxy_target="$value" ;;
                        tls) proxy_tls="$value" ;;
                    esac
                done < "$proxy_file"

                if [ -n "$proxy_domain" ] && [ -n "$proxy_target" ]; then
                    echo "# Proxy: $proxy_name" >> "$CADDYFILE_PATH"
                    echo "$proxy_domain {" >> "$CADDYFILE_PATH"
                    echo "    reverse_proxy $proxy_target" >> "$CADDYFILE_PATH"
                    if [ "$proxy_tls" = "internal" ]; then
                        echo "    tls internal" >> "$CADDYFILE_PATH"
                    fi
                    echo "}" >> "$CADDYFILE_PATH"
                    echo "" >> "$CADDYFILE_PATH"
                fi
            fi
        done
    fi

    # Add Tailscale port-based routing if enabled
    if [ -n "$tailscale_hostname" ]; then
        echo "# --- Tailscale Port-Based Access ---" >> "$CADDYFILE_PATH"
        echo "" >> "$CADDYFILE_PATH"
        
        local ts_port=9001
        
        # Add a server block for each site on a unique port
        if [ -d "$SITES_DIR" ]; then
            for site_path in "$SITES_DIR"/*; do
                if [ -d "$site_path" ]; then
                    local site_name
                    site_name=$(basename "$site_path")
                    local site_base_name
                    site_base_name=$(echo "$site_name" | sed 's/\.localhost$//')

                    # Same skip as the main site loop: not a servable site.
                    if [ ! -d "$site_path/public" ] && [ ! -f "$CUSTOM_CADDY_DIR/$site_name" ]; then
                        continue
                    fi

                    # Check if this site has a simple reverse_proxy directive
                    local directive_file="$CUSTOM_CADDY_DIR/$site_name"
                    local direct_proxy_target=""
                    if [ -f "$directive_file" ]; then
                        # Extract target if directive is just "reverse_proxy <target>"
                        direct_proxy_target=$(grep -E '^reverse_proxy [0-9a-zA-Z._:-]+$' "$directive_file" 2>/dev/null | awk '{print $2}')
                    fi
                    
                    echo "# Tailscale: ${site_base_name} -> port ${ts_port}" >> "$CADDYFILE_PATH"
                    echo "https://${tailscale_hostname}:${ts_port} {" >> "$CADDYFILE_PATH"
                    echo "    tls internal" >> "$CADDYFILE_PATH"
                    
                    if [ -n "$direct_proxy_target" ]; then
                        # Proxy directly to the backend target
                        echo "    reverse_proxy ${direct_proxy_target}" >> "$CADDYFILE_PATH"
                    else
                        # Serve site directly (not via proxy) for better compatibility
                        echo "    root * \"$site_path/public\"" >> "$CADDYFILE_PATH"

                        echo "    log {" >> "$CADDYFILE_PATH"
                        echo "        output file \"$site_path/logs/caddy-tailscale.log\"" >> "$CADDYFILE_PATH"
                        echo "    }" >> "$CADDYFILE_PATH"
                        
                        # Include custom directives if present
                        if [ -f "$directive_file" ]; then
                            echo "" >> "$CADDYFILE_PATH"
                            sed 's/^/    /' "$directive_file" >> "$CADDYFILE_PATH"
                            echo "" >> "$CADDYFILE_PATH"
                        fi
                        
                        emit_site_php_handler "$site_path"

                        if [ ! -f "$site_path/public/wp-config.php" ]; then
                            echo "    file_server" >> "$CADDYFILE_PATH"
                        fi
                    fi
                    echo "}" >> "$CADDYFILE_PATH"
                    echo "" >> "$CADDYFILE_PATH"
                    
                    # Store port mapping for this site
                    echo "${ts_port}" > "$site_path/tailscale_port"
                    
                    ((ts_port++))
                fi
            done
        fi
        
        # Global services on fixed ports
        # Mail on port 9901
        echo "# Tailscale: mail -> port 9901" >> "$CADDYFILE_PATH"
        echo "https://${tailscale_hostname}:9901 {" >> "$CADDYFILE_PATH"
        echo "    tls internal" >> "$CADDYFILE_PATH"
        echo "    reverse_proxy 127.0.0.1:8025" >> "$CADDYFILE_PATH"
        echo "}" >> "$CADDYFILE_PATH"
        echo "" >> "$CADDYFILE_PATH"
        
        # DB on port 9902 - serve directly
        echo "# Tailscale: db -> port 9902" >> "$CADDYFILE_PATH"
        echo "https://${tailscale_hostname}:9902 {" >> "$CADDYFILE_PATH"
        echo "    tls internal" >> "$CADDYFILE_PATH"
        echo "    root * \"$ADMINER_DIR\"" >> "$CADDYFILE_PATH"
        echo "    php_server" >> "$CADDYFILE_PATH"
        echo "}" >> "$CADDYFILE_PATH"
        echo "" >> "$CADDYFILE_PATH"
        
        # Dashboard on port 9900 - serve directly
        echo "# Tailscale: cove dashboard -> port 9900" >> "$CADDYFILE_PATH"
        echo "https://${tailscale_hostname}:9900 {" >> "$CADDYFILE_PATH"
        echo "    tls internal" >> "$CADDYFILE_PATH"
        echo "    root * \"$GUI_DIR\"" >> "$CADDYFILE_PATH"
        echo "    php_server" >> "$CADDYFILE_PATH"
        echo "}" >> "$CADDYFILE_PATH"
        echo "" >> "$CADDYFILE_PATH"
    fi

    # If Caddy is already running, reload against the new config. If it isn't,
    # start it — the start command reads $CADDYFILE_PATH itself, so no reload
    # is needed. Without this probe, `cove add` on a stopped stack would
    # silently "succeed" while the site was actually unreachable.
    #
    # The reload runs synchronously so callers only see success after the new
    # config is actually live. The previous implementation backgrounded it to
    # avoid a self-deadlock when the dashboard (running inside FrankenPHP)
    # triggered a reload; that deadlock is now handled at the PHP layer, which
    # already backgrounds `cove reload` via shell_exec '…&' (see create_gui_file).
    # With hundreds of sites the Caddyfile adapt takes a few seconds — racing
    # the exit against a subsequent curl produced TLS internal errors.
    if is_caddy_running; then
        # Reload talks to the admin API on localhost:2019 and doesn't need
        # root. Dropping sudo here keeps the caller (incl. the dashboard's
        # shell_exec) running as the invoking user.
        if "$CADDY_CMD" reload --config "$CADDYFILE_PATH" --address localhost:2019 &> "$LOGS_DIR/caddy-reload.log"; then
            echo "✅ Caddy configuration reloaded."
        else
            # A `caddy reload` adapts the Caddyfile with the *on-disk* binary
            # and POSTs that JSON at the *running* process. After
            # `cove upgrade` swaps FrankenPHP, those are different versions:
            # 1.12.7's php_server adapter emits `route_group`, which 1.12.4's
            # handler rejects as an unknown field. Same class of failure as
            # any other binary/config skew. Fall through to a full restart
            # so the new binary both adapts and serves.
            echo "⚠️  Caddy reload rejected by the running process — restarting with the on-disk binary..."
            echo "   (see $LOGS_DIR/caddy-reload.log)"
            start_caddy_service
            if ! is_caddy_running; then
                gum style --foreground red "❌ Caddy failed to restart. See $LOGS_DIR/caddy-process.log for details."
                return 1
            fi
            echo "✅ Caddy restarted."
        fi
    else
        echo "ℹ️  Caddy is not running — starting it now."
        start_caddy_service
    fi
}

# --- GUI Generation ---
create_gui_file() {
    echo "🎨 Creating Cove dashboard files..."
    mkdir -p "$GUI_DIR"
    
    # Create the API file that handles the logic
    cat > "$GUI_DIR/api.php.tmp" << 'EOM'
<?php
header('Content-Type: application/json');
$sitedir = 'SITES_DIR_PLACEHOLDER';
$cove_path = 'COVE_EXECUTABLE_PATH_PLACEHOLDER';
$user_home = 'USER_HOME_PLACEHOLDER';

// Read the configured HTTPS port so site links include ":8453" when non-default.
$__cove_https_port = 443;
$__cove_cfg_path = $user_home . '/Cove/config';
if (file_exists($__cove_cfg_path)) {
    $__cove_cfg = parse_ini_file($__cove_cfg_path);
    if (!empty($__cove_cfg['HTTPS_PORT'])) {
        $__cove_https_port = (int) $__cove_cfg['HTTPS_PORT'];
    }
}
$__cove_port_suffix = ($__cove_https_port === 443) ? '' : ':' . $__cove_https_port;

// Per-site disk sizes are cached so list_sites stays fast even on hosts with
// ~100 sites. The cache is refreshed on demand by the dashboard's 'refresh_sizes'
// action; stale entries are tolerable because list_sites filters by what's on
// disk and the UI falls back to '—' when an entry is missing.
$__cove_sizes_cache = $user_home . '/Cove/cache/site-sizes.json';

// The add-site form offers real WordPress versions rather than a free-text box,
// so a typo can't turn into a failed install two minutes later. wp.org's
// stable-check endpoint is the only source that lists every shipped version, so
// it's fetched once and cached for a day — the dashboard must stay usable
// offline, so every failure path here falls back to "latest" and never blocks.
$__cove_wpver_cache = $user_home . '/Cove/cache/wp-versions.json';

function cove_wp_versions($cache_path, $ttl = 86400) {
    if (is_file($cache_path) && (time() - filemtime($cache_path)) < $ttl) {
        $cached = @json_decode(@file_get_contents($cache_path), true);
        if (is_array($cached) && !empty($cached)) return $cached;
    }

    // Short timeouts: this runs inline on a dashboard request, and a slow or
    // unreachable wp.org must degrade to a plain "latest" rather than hang.
    $raw = @file_get_contents('https://api.wordpress.org/core/stable-check/1.0/', false, stream_context_create([
        'http' => ['timeout' => 4, 'user_agent' => 'Cove'],
        'ssl'  => ['verify_peer' => true, 'verify_peer_name' => true],
    ]));
    $all = $raw ? @json_decode($raw, true) : null;
    if (!is_array($all) || empty($all)) {
        // Serve a stale cache in preference to nothing at all.
        $stale = is_file($cache_path) ? @json_decode(@file_get_contents($cache_path), true) : null;
        return is_array($stale) ? $stale : [];
    }

    // stable-check maps every version -> 'latest' | 'outdated' | 'insecure'.
    // Sort newest-first and keep a usable slice: the whole list is ~700 entries
    // going back to 0.71, which is noise in a dropdown.
    $versions = array_keys($all);
    usort($versions, static fn($a, $b) => version_compare($b, $a));
    $versions = array_slice($versions, 0, 40);

    $out = [];
    foreach ($versions as $v) {
        $out[] = ['version' => $v, 'status' => $all[$v]];
    }

    @mkdir(dirname($cache_path), 0755, true);
    @file_put_contents($cache_path, json_encode($out));
    return $out;
}

function cove_read_size_cache($path) {
    if (!file_exists($path)) return [];
    $data = @json_decode(@file_get_contents($path), true);
    return (is_array($data) && isset($data['sites']) && is_array($data['sites'])) ? $data['sites'] : [];
}

function cove_write_size_cache($path, array $sizes) {
    @mkdir(dirname($path), 0755, true);
    @file_put_contents($path, json_encode([
        'sites' => $sizes,
        'updated_at' => time(),
    ], JSON_UNESCAPED_SLASHES));
}

// Handle GET requests for listing sites
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $action = $_GET['action'] ?? '';
    if ($action === 'list_sites') {
        $sites_info = [];
        $size_cache = cove_read_size_cache($__cove_sizes_cache);

        // Read whatever stable-check data is already cached. Deliberately does
        // not fetch: list_sites is on the critical path for the dashboard's
        // first paint, and version status is a nicety. The add-site form's
        // wp_versions call is what populates this.
        $__cove_wpver_status = [];
        if (is_file($__cove_wpver_cache)) {
            $__cove_wpver_cached = @json_decode(@file_get_contents($__cove_wpver_cache), true);
            if (is_array($__cove_wpver_cached)) {
                foreach ($__cove_wpver_cached as $__e) {
                    if (isset($__e['version'], $__e['status'])) {
                        $__cove_wpver_status[$__e['version']] = $__e['status'];
                    }
                }
            }
        }
        if (file_exists($sitedir) && is_dir($sitedir)) {
            $items = scandir($sitedir);
            foreach ($items as $item) {
                if ($item === '.' || $item === '..') continue;
                $site_path = $sitedir . '/' . $item;
                if (is_dir($site_path)) {
                    // Prefer the public/ dir's mtime since it gets touched whenever
                    // files are added/removed at the doc root — closer to "when did I
                    // last work on this site" than the site dir itself.
                    $mtime = @filemtime($site_path . '/public');
                    if (!$mtime) $mtime = @filemtime($site_path);

                    // Parsed from version.php rather than booting WordPress —
                    // 250 sites of `wp core version` would take a minute, and
                    // this still reports on a site too broken to serve.
                    $wp_version = null;
                    $vfile = $site_path . '/public/wp-includes/version.php';
                    if (is_file($vfile)) {
                        $head = @file_get_contents($vfile, false, null, 0, 4096);
                        if ($head !== false && preg_match('/\$wp_version\s*=\s*\'([^\']+)\'/', $head, $m)) {
                            $wp_version = $m[1];
                        }
                    }

                    $sites_info[] = [
                        'name' => str_replace('.localhost', '', $item),
                        'domain' => 'https://' . $item . $__cove_port_suffix,
                        'type' => file_exists($site_path . "/public/wp-config.php") ? 'WordPress' : 'Plain',
                        'wp_version' => $wp_version,
                        // latest | outdated | insecure | null when wp.org's
                        // stable-check data has not been fetched yet.
                        'wp_status' => $wp_version !== null ? ($__cove_wpver_status[$wp_version] ?? null) : null,
                        'display_path' => '~/Cove/Sites/' . $item,
                        'full_path' => $site_path,
                        'size_bytes' => isset($size_cache[$item]) ? (int) $size_cache[$item] : null,
                        'modified_at' => $mtime ?: null,
                        // Mirrors cove_add's `echo "cove_$name" | tr -c '[:alnum:]_' '_'`,
                        // so the UI can deep-link Adminer straight at this site's schema.
                        'db_name' => preg_replace('/[^a-zA-Z0-9_]/', '_', 'cove_' . str_replace('.localhost', '', $item)),
                        // Per-site PHP pin (`cove php`); null = Cove's default PHP.
                        'php_version' => is_file($site_path . '/php_version') ? trim((string) @file_get_contents($site_path . '/php_version')) : null,
                    ];
                }
            }
            if (!empty($sites_info)) {
                array_multisort(
                    array_column($sites_info, "type"), SORT_ASC,
                    array_column($sites_info, "name"), SORT_ASC,
                    $sites_info
                );
            }
        }
        echo json_encode($sites_info);
        exit;
    }
    if ($action === 'wp_versions') {
        echo json_encode(cove_wp_versions($__cove_wpver_cache));
        exit;
    }
    if ($action === 'php_info') {
        // Which PHP versions the dashboard can offer for per-site pins. The
        // dashboard itself runs under FrankenPHP, so PHP_VERSION here IS
        // Cove's default PHP — only OLDER versions run on native php-fpm.
        // Installed = the Homebrew formula's php-fpm binary exists, mirroring
        // php_fpm_prefix_for in the CLI.
        $default_mm = preg_replace('/^(\d+\.\d+).*$/', '$1', PHP_VERSION);
        $brew_opt = is_dir('/opt/homebrew/opt') ? '/opt/homebrew/opt' : (is_dir('/usr/local/opt') ? '/usr/local/opt' : null);
        $supported = (PHP_OS_FAMILY === 'Darwin') && $brew_opt !== null;
        $versions = [];
        foreach (['8.4', '8.3', '8.2', '8.1', '8.0', '7.4'] as $v) {
            if (version_compare($v, $default_mm, '>=')) continue;
            $installed = $supported && is_executable($brew_opt . '/php@' . $v . '/sbin/php-fpm');
            // 8.0 and 7.4 left Homebrew core, so they can't be offered as
            // one-click installs — but when a tap already provides them
            // (shivammathur/php), pinning works, so show what's there.
            if (!$installed && version_compare($v, '8.1', '<')) continue;
            $versions[] = ['version' => $v, 'installed' => $installed];
        }
        echo json_encode(['supported' => $supported, 'default' => $default_mm, 'versions' => $versions]);
        exit;
    }
}

// Handle POST requests for adding/deleting/reloading
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF / cross-origin guard. Every POST action here mutates state (add /
    // delete sites, reload), and the body is read via php://input regardless
    // of Content-Type — so a cross-site page could drive it with a CORS
    // "simple" text/plain POST that skips preflight. Browsers still stamp such
    // a request with an Origin (and always a Referer on same-origin), so
    // require one of them to match this host before doing anything. Compare
    // host only; HTTP_HOST may carry a :port that the Origin/Referer host omits.
    $__cove_host_only = preg_replace('/:\d+$/', '', $_SERVER['HTTP_HOST'] ?? '');
    $__cove_src = $_SERVER['HTTP_ORIGIN'] ?? ($_SERVER['HTTP_REFERER'] ?? '');
    $__cove_src_host = $__cove_src !== '' ? parse_url($__cove_src, PHP_URL_HOST) : '';
    if (empty($__cove_src_host) || empty($__cove_host_only) || strcasecmp($__cove_src_host, $__cove_host_only) !== 0) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Cross-origin request blocked.']);
        exit;
    }

    $input = json_decode(file_get_contents('php://input'), true);
    $action = $input['action'] ?? '';
    $response = ['success' => false, 'message' => 'Invalid request.'];
    $command = '';
    $site_name = $input['site_name'] ?? '';

    switch ($action) {
        case 'add_site':
            if (!empty($site_name) && preg_match('/^[a-zA-Z0-9-]+$/', $site_name)) {
                // One positional "flavor" slot, mirroring the CLI: 'plain', a
                // WordPress version, 'nightly', or nothing at all for latest.
                // Validated here as well as in cove_add — escapeshellarg stops
                // shell injection, but there's no reason to hand the CLI a
                // value the UI already knows is malformed.
                $flavor = '';
                if ($input['is_plain'] ?? false) {
                    $flavor = 'plain';
                } elseif (!empty($input['wp_version']) && $input['wp_version'] !== 'latest') {
                    $v = $input['wp_version'];
                    if ($v === 'nightly' || preg_match('/^\d+(\.\d+){1,2}(-[A-Za-z0-9.]+)?$/', $v)) {
                        $flavor = $v;
                    }
                }
                $command = sprintf('HOME=%s %s add %s %s --no-reload 2>&1', escapeshellarg($user_home), escapeshellarg($cove_path), escapeshellarg($site_name), $flavor !== '' ? escapeshellarg($flavor) : '');
                // Remember we're adding so the post-exec block below can
                // measure the new site's size and fold it into the cache.
                $add_site_target = $site_name;
            } else { $response['message'] = 'Invalid site name provided.'; }
            break;
        case 'delete_site':
            // Same charset gate as add_site: escapeshellarg blocks shell
            // injection, but the name is still passed positionally to
            // `cove delete`, which builds a path from it — so reject `../`
            // traversal here too rather than relying on the CLI alone.
            if (!empty($site_name) && preg_match('/^[a-zA-Z0-9-]+$/', $site_name)) {
                // --no-reload: cove_delete otherwise auto-reloads Caddy after
                // each delete to prevent zombie log-dir skeletons from being
                // recreated. The dashboard batches one reload after the whole
                // delete queue drains, so skip per-item reloads here.
                $command = sprintf('HOME=%s %s delete %s --force --no-reload 2>&1', escapeshellarg($user_home), escapeshellarg($cove_path), escapeshellarg($site_name));
                $delete_site_target = $site_name;
            } else { $response['message'] = 'Invalid site name provided for deletion.'; }
            break;
        case 'rename_site':
            // Same charset gate as add/delete on BOTH names: escapeshellarg stops
            // shell injection, but cove_rename builds filesystem paths and a
            // database name from these, so `../` must never get that far.
            $new_name = $input['new_name'] ?? '';
            if (empty($site_name) || !preg_match('/^[a-zA-Z0-9-]+$/', $site_name)) {
                $response['message'] = 'Invalid site name provided.';
                break;
            }
            if (empty($new_name) || !preg_match('/^[a-zA-Z0-9-]+$/', $new_name)) {
                $response['message'] = 'Invalid new name. Use letters, numbers and hyphens only.';
                break;
            }
            if ($new_name === $site_name) {
                $response['message'] = 'That is already the site name.';
                break;
            }
            // Idempotent retry. Renaming regenerates the Caddyfile and reloads
            // the very Caddy serving this dashboard, so the response can be
            // dropped mid-reload and the UI retries. By then the rename has
            // already happened, and a naive retry fails with "site not found" —
            // reporting an error for work that actually succeeded. Source gone
            // plus destination present is exactly that case.
            $src_exists = is_dir($sitedir . '/' . $site_name . '.localhost');
            $dst_exists = is_dir($sitedir . '/' . $new_name . '.localhost');
            if (!$src_exists && $dst_exists) {
                echo json_encode(['success' => true, 'message' => 'Renamed to ' . $new_name . '.localhost.', 'new_name' => $new_name]);
                exit;
            }
            if ($dst_exists) {
                $response['message'] = 'A site named ' . $new_name . ' already exists.';
                break;
            }
            $command = sprintf('HOME=%s %s rename %s %s 2>&1', escapeshellarg($user_home), escapeshellarg($cove_path), escapeshellarg($site_name), escapeshellarg($new_name));
            $rename_site_target = $new_name;
            break;
        case 'reveal_site':
            // Opens the site directory in the desktop file manager. Only ever
            // hands the resolved path to the opener, never the raw name.
            if (empty($site_name) || !preg_match('/^[a-zA-Z0-9-]+$/', $site_name)) {
                $response['message'] = 'Invalid site name provided.';
                break;
            }
            $reveal_path = $sitedir . '/' . $site_name . '.localhost';
            if (!is_dir($reveal_path)) {
                $response['message'] = 'Site directory not found.';
                break;
            }
            $opener = (PHP_OS_FAMILY === 'Darwin') ? 'open' : 'xdg-open';
            // Detached: a file manager that stays in the foreground would hold
            // the request open until the user closed it.
            exec(sprintf('%s %s > /dev/null 2>&1 &', $opener, escapeshellarg($reveal_path)));
            echo json_encode(['success' => true, 'message' => 'Opened ' . $site_name . '.localhost in the file manager.']);
            exit;
        case 'site_log':
            // Read-only tail of the site's own Caddy log. Never shells out —
            // there is no reason to involve a shell to read a known file.
            if (empty($site_name) || !preg_match('/^[a-zA-Z0-9-]+$/', $site_name)) {
                $response['message'] = 'Invalid site name provided.';
                break;
            }
            $log_dir = $sitedir . '/' . $site_name . '.localhost/logs';
            $log_file = $log_dir . '/caddy.log';
            if (!is_file($log_file)) {
                echo json_encode(['success' => true, 'log' => '', 'message' => 'No log yet for this site.']);
                exit;
            }
            // Tail the last 64KB rather than reading the whole file: these grow
            // without bound and the UI only ever shows the recent end.
            $max = 64 * 1024;
            $size = filesize($log_file);
            $fh = fopen($log_file, 'r');
            if ($size > $max) { fseek($fh, $size - $max); fgets($fh); }
            $log = stream_get_contents($fh);
            fclose($fh);
            echo json_encode(['success' => true, 'log' => $log, 'truncated' => $size > $max]);
            exit;
        case 'get_login_link':
            $response = ['success' => false, 'message' => 'An unknown error occurred.'];
            if (!empty($site_name)) {
                // Delegate to the 'cove login' command which has the self-healing logic.
                $command = sprintf(
                    'HOME=%s %s login %s 2>&1',
                    escapeshellarg($user_home),
                    escapeshellarg($cove_path),
                    escapeshellarg($site_name)
                );

                exec($command, $output_lines, $return_code);
                $full_output = implode("\n", $output_lines);
                $login_url = '';

                // Parse the command's output to find the URL.
                foreach ($output_lines as $line) {
                    if (strpos($line, 'https://') !== false && strpos($line, '/wp-login.php') !== false) {
                        // Clean the line from any "gum" box characters.
                        $login_url = trim(preg_replace('/[│└┌]/u', '', $line));
                        break;
                    }
                }

                if (!empty($login_url)) {
                    $response = ['success' => true, 'url' => $login_url];
                } else {
                    $response = ['success' => false, 'message' => 'Failed to generate login link.', 'output' => $full_output];
                }

            } else {
                $response['message'] = 'Site name not provided for login link.';
            }
            echo json_encode($response);
            exit; // Exit immediately
        case 'set_php':
            // Pin a site to an older PHP (native php-fpm) or back to the
            // default. Charset gates mirror add/delete; the version must be a
            // major.minor or the literal 'default'.
            $php_version = $input['php_version'] ?? '';
            if (empty($site_name) || !preg_match('/^[a-zA-Z0-9-]+$/', $site_name)) {
                $response['message'] = 'Invalid site name provided.';
                break;
            }
            if (!preg_match('/^(default|\d+\.\d+)$/', $php_version)) {
                $response['message'] = 'Invalid PHP version.';
                break;
            }
            $pin_file = $sitedir . '/' . $site_name . '.localhost/php_version';
            $current_pin = is_file($pin_file) ? trim((string) @file_get_contents($pin_file)) : null;
            // Idempotent retry, same reasoning as rename: pinning reloads the
            // Caddy serving this dashboard, so a dropped response gets retried
            // by the UI after the work already happened.
            if (($php_version === 'default' && $current_pin === null) || $php_version === $current_pin) {
                echo json_encode(['success' => true, 'message' => 'Already set.']);
                exit;
            }
            $brew_opt = is_dir('/opt/homebrew/opt') ? '/opt/homebrew/opt' : '/usr/local/opt';
            $needs_install = $php_version !== 'default' && !is_executable($brew_opt . '/php@' . $php_version . '/sbin/php-fpm');
            // Always applied in the background — even an installed-version pin
            // regenerates the Caddyfile and reloads the Caddy serving this
            // dashboard, so a synchronous exec just hangs the response until
            // the client gives up. Return immediately; the UI polls list_sites
            // for the pin state. cove php auto-confirms brew installs when it
            // has no TTY, so the missing-formula case rides the same path.
            $apply_log = $user_home . '/Cove/cache/php-apply-' . $site_name . '.log';
            shell_exec(sprintf('HOME=%s %s php %s %s > %s 2>&1 &',
                escapeshellarg($user_home), escapeshellarg($cove_path),
                escapeshellarg($site_name), escapeshellarg($php_version), escapeshellarg($apply_log)));
            echo json_encode(['success' => true, 'applying' => true, 'installing' => $needs_install]);
            exit;
        case 'reload_server':
            // This command is run in the background to prevent deadlocking the server.
            // Output is redirected to /dev/null and the '&' backgrounds the process.
            $reload_command = sprintf('HOME=%s %s reload > /dev/null 2>&1 &', escapeshellarg($user_home), escapeshellarg($cove_path));
            shell_exec($reload_command);
            $response = ['success' => true, 'message' => 'Server reload initiated.'];
            echo json_encode($response);
            exit; // Exit immediately
        case 'refresh_sizes':
            // Walk every site directory with `du -sk` (portable on macOS + Linux — -k
            // forces 1024-byte blocks) and cache the result as bytes. Runs sequentially
            // so 80+ sites take a few seconds; acceptable because this is user-triggered.
            $sizes = [];
            if (file_exists($sitedir) && is_dir($sitedir)) {
                foreach (scandir($sitedir) as $item) {
                    if ($item === '.' || $item === '..') continue;
                    $p = $sitedir . '/' . $item;
                    if (!is_dir($p)) continue;
                    $out = []; $rc = 0;
                    exec('du -sk ' . escapeshellarg($p) . ' 2>/dev/null', $out, $rc);
                    if ($rc === 0 && !empty($out[0])) {
                        $parts = preg_split('/\s+/', trim($out[0]));
                        if (ctype_digit($parts[0] ?? '')) {
                            $sizes[$item] = ((int) $parts[0]) * 1024;
                        }
                    }
                }
            }
            cove_write_size_cache($__cove_sizes_cache, $sizes);
            echo json_encode(['success' => true, 'sites' => $sizes, 'updated_at' => time()]);
            exit;
    }

    if (!empty($command)) {
        exec($command, $output, $return_code);
        if ($return_code === 0) {
            $response = ['success' => true, 'message' => 'Operation completed successfully.'];
            if (isset($rename_site_target)) {
                $response['message'] = 'Renamed to ' . $rename_site_target . '.localhost.';
                $response['new_name'] = $rename_site_target;
            }
            // For add_site: measure the new site's footprint inline and fold
            // it into the size cache so the UI shows "4.0 KB" (or whatever)
            // immediately instead of "—" until the next refresh_sizes pass.
            if (isset($add_site_target)) {
                $new_path = $sitedir . '/' . $add_site_target . '.localhost';
                if (is_dir($new_path)) {
                    $size_out = []; $size_rc = 0;
                    exec('du -sk ' . escapeshellarg($new_path) . ' 2>/dev/null', $size_out, $size_rc);
                    if ($size_rc === 0 && !empty($size_out[0])) {
                        $parts = preg_split('/\s+/', trim($size_out[0]));
                        if (ctype_digit($parts[0] ?? '')) {
                            $bytes = ((int) $parts[0]) * 1024;
                            $response['size_bytes'] = $bytes;
                            $cache = cove_read_size_cache($__cove_sizes_cache);
                            $cache[$add_site_target . '.localhost'] = $bytes;
                            cove_write_size_cache($__cove_sizes_cache, $cache);
                        }
                    }
                }
            }
        } else {
            // Translate known failure signatures into user-friendly messages.
            // Generic "An error occurred" isn't actionable, but "Site name is
            // taken" tells the user exactly what to do next.
            $err_text = implode("\n", $output);
            $msg = 'An error occurred.';
            if (isset($delete_site_target) && stripos($err_text, 'not found') !== false) {
                // Idempotent delete: the UI retries deletes whose response was
                // dropped mid-reload — a retry that finds the site already
                // gone is a success, not an error.
                echo json_encode(['success' => true, 'message' => 'Site already deleted.']);
                exit;
            }
            if (isset($rename_site_target)) {
                $msg = 'Could not rename site.';
                if (stripos($err_text, 'already exists') !== false) {
                    $msg = 'That name is already taken.';
                } elseif (stripos($err_text, 'reserved name') !== false) {
                    $msg = 'That name is reserved. Pick another.';
                }
            }
            if (isset($add_site_target)) {
                $msg = 'Could not create site.';
                if (stripos($err_text, 'already exists') !== false) {
                    $msg = 'Site name is taken.';
                } elseif (stripos($err_text, 'reserved name') !== false) {
                    $msg = 'That name is reserved. Pick another.';
                } elseif (stripos($err_text, 'invalid site name') !== false) {
                    $msg = 'Invalid site name.';
                } elseif (stripos($err_text, 'WordPress installation failed') !== false) {
                    $msg = 'WordPress installation failed — check the logs.';
                }
            }
            $response = ['success' => false, 'message' => $msg, 'output' => $err_text];
        }
    }
    echo json_encode($response);
    exit;
}

http_response_code(405);
echo json_encode(['success' => false, 'message' => 'Method Not Allowed']);
EOM

    # Create the main dashboard file (the UI)
    cat > "$GUI_DIR/index.php.tmp" << 'EOM'
<?php
$config_file = getenv('HOME') . '/Cove/config';
$config_data = file_exists($config_file) ? parse_ini_file($config_file) : [];
$__cove_https_port = isset($config_data['HTTPS_PORT']) ? (int) $config_data['HTTPS_PORT'] : 443;
$__cove_port_suffix = ($__cove_https_port === 443) ? '' : ':' . $__cove_https_port;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="color-scheme" content="dark light">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cove — sites</title>
    <script>
        // Set data-theme synchronously before any CSS paints, so the correct
        // theme's background is used from the very first frame (no FOUC).
        // The dashboard script re-reads the same localStorage key in init()
        // — values stay in sync with no extra flip.
        (function () {
            try {
                var s = localStorage.getItem('theme');
                var t = (s === 'dark' || s === 'light')
                    ? s
                    : (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
                document.documentElement.setAttribute('data-theme', t);
            } catch (e) {}
        })();
    </script>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64' stroke-linecap='round' stroke-linejoin='round'><defs><clipPath id='c'><circle cx='32' cy='32' r='28'/></clipPath></defs><g clip-path='url(%23c)'><rect width='64' height='64' fill='%23f6f1e8'/><rect y='32' width='64' height='32' fill='%233a97a9'/><path d='M 4 32 C 4 22, 12 12, 22 12 C 30 12, 34 18, 42 16 C 50 14, 58 18, 60 24 L 60 32 Z' fill='%2358b293'/><line x1='2' y1='32' x2='62' y2='32' stroke='%231c4c58' stroke-width='2.5' fill='none'/><g stroke='%231c4c58' stroke-width='2.6' fill='none'><path d='M 10 42 Q 18 38, 26 42 T 42 42 T 56 42'/><path d='M 14 50 Q 22 46, 30 50 T 46 50 T 56 50'/></g></g><circle cx='32' cy='32' r='28' stroke='%231c4c58' stroke-width='3' fill='none'/></svg>">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fraunces:ital,opsz,wght@0,9..144,400..600;1,9..144,400..600&family=Geist:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after { box-sizing: border-box; }
        html, body { margin: 0; padding: 0; }
        html { background: #0f1210; }
        html[data-theme="light"] { background: #fbfaf7; }

        :root {
            --font-sans: 'Geist', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            --font-serif: 'Fraunces', Georgia, serif;
            --font-mono: 'JetBrains Mono', ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
            /* sRGB fallback first; browsers without oklch() support silently
               drop the override on the next line and keep the hex value.
               Without the fallback, the whole declaration would be invalid on
               Firefox <113 / Chrome <111 / Safari <16.4 and --accent would be
               unset — which reads as "transparent" for backgrounds and
               "black" for SVG fills (hence the invisible add button and the
               solid-black logo disc on older browsers). */
            --accent: #3a97a9;
            --accent: oklch(62% 0.11 190);
            --accent-fg: #0a1a1c;
            --radius-lg: 20px;
            --radius-md: 10px;
            --radius-pill: 999px;
        }

        html[data-theme="dark"], html:not([data-theme]) {
            --bg: #0f1210;
            --bg-sunk: #0b0e0c;
            --panel: #181c19;
            --panel-hover: #1e2320;
            --panel-border: #252925;
            --text: #edeee9;
            --text-dim: #8a8e85;
            --text-faint: #5d615a;
            /* Dark-mode teal is brighter so it reads cleanly against the
               warmer panel — matches the landing page palette. */
            --accent: #4db0c2;
            --accent: oklch(72% 0.12 190);
            --pill-bg: #1e2320;
            --pill-wp-bg: rgba(77, 176, 194, 0.18);
            --pill-wp-bg: color-mix(in oklch, var(--accent) 18%, transparent);
            --pill-wp-fg: #71c0ce;
            --pill-wp-fg: color-mix(in oklch, var(--accent) 80%, white);
            --pill-static-bg: #1e2320;
            --pill-static-fg: #9a9d94;
            --input-bg: #0b0e0c;
            --danger: #d66a6a;
            --shadow-lg: 0 28px 60px -24px rgba(0,0,0,0.7), 0 6px 16px -6px rgba(0,0,0,0.4);
            color-scheme: dark;
        }

        html[data-theme="light"] {
            --bg: #fbfaf7;
            --bg-sunk: #f4f2ec;
            --panel: #ffffff;
            --panel-hover: #f6f4ee;
            --panel-border: #e8e4da;
            --text: #1a1c1b;
            --text-dim: #6b6f6a;
            --text-faint: #9a9d97;
            /* White on teal reads stronger than the dark accent-fg does on
               the lighter background — override just for light mode. */
            --accent-fg: #ffffff;
            --pill-bg: #f1ede5;
            --pill-wp-bg: rgba(58, 151, 169, 0.14);
            --pill-wp-bg: color-mix(in oklch, var(--accent) 14%, transparent);
            --pill-wp-fg: #20535d;
            --pill-wp-fg: color-mix(in oklch, var(--accent) 55%, black);
            --pill-static-bg: #f1ede5;
            --pill-static-fg: #8a8781;
            --input-bg: #fbfaf7;
            --danger: #b44848;
            --shadow-lg: 0 24px 50px -24px rgba(20,28,30,0.18), 0 6px 16px -6px rgba(20,28,30,0.06);
            color-scheme: light;
        }

        body {
            background: var(--bg);
            color: var(--text);
            font-family: var(--font-sans);
            font-size: 15px;
            line-height: 1.5;
            min-height: 100vh;
            padding: 2.5rem 1.25rem 4rem;
            -webkit-font-smoothing: antialiased;
            font-feature-settings: "ss01", "cv11";
        }

        .wrap { max-width: 820px; margin: 0 auto; }

        /* Top nav */
        .nav { display: flex; align-items: center; justify-content: space-between; margin-bottom: 2rem; }
        .logo { display: inline-flex; align-items: center; gap: 12px; color: var(--text); text-decoration: none; font-weight: 600; font-size: 1.05rem; letter-spacing: -0.01em; }
        /* Brand mark: cove/bay silhouette in a circle. Classes are scoped to
           .logo-mark so they don't collide with unrelated elements. Colors
           are driven by CSS variables with sensible defaults, so each theme
           can override individual layers without touching the inline SVG. */
        /* Each layer gets a pair of declarations — the sRGB hex applies
           everywhere, then the oklch override kicks in on browsers that
           understand it. Without the fallback, unsupported oklch() in a
           var() default makes the whole `fill`/`stroke` declaration invalid
           and SVG falls back to fill:black (which is what produces the
           solid-black disc + missing layers on Firefox <113). */
        .logo-mark { width: 34px; height: 34px; display: block; flex-shrink: 0; }
        .logo-mark .disc    { fill: var(--mark-disc, #f6f1e8); fill: var(--mark-disc, oklch(96% 0.015 85)); }
        .logo-mark .water   { fill: var(--mark-water, #3a97a9); fill: var(--mark-water, oklch(62% 0.11 190)); }
        .logo-mark .land    { fill: var(--mark-land, #58b293); fill: var(--mark-land, oklch(70% 0.10 168)); }
        .logo-mark .horizon { stroke: var(--mark-horizon, #1c4c58); stroke: var(--mark-horizon, oklch(35% 0.08 190)); fill: none; }
        .logo-mark .wave    { stroke: var(--mark-wave, #1c4c58); stroke: var(--mark-wave, oklch(35% 0.08 190)); fill: none; }
        .logo-mark .ring    { stroke: var(--mark-ring, #1c4c58); stroke: var(--mark-ring, oklch(35% 0.08 190)); fill: none; stroke-width: 3; }
        html[data-theme="dark"] .logo-mark {
            --mark-disc:    #2b2925;
            --mark-disc:    oklch(22% 0.01 85);
            --mark-land:    #6a9d70;
            --mark-land:    oklch(64% 0.09 168);
            --mark-ring:    rgba(237, 238, 233, 0.72);
            --mark-ring:    color-mix(in oklab, var(--text) 72%, transparent);
            --mark-horizon: rgba(237, 238, 233, 0.72);
            --mark-horizon: color-mix(in oklab, var(--text) 72%, transparent);
            --mark-wave:    rgba(237, 238, 233, 0.65);
            --mark-wave:    color-mix(in oklab, var(--text) 65%, transparent);
        }
        /* Square icon button that cross-fades a moon (light mode) with a sun
           (dark mode). Both SVGs are stacked absolutely so the button size
           stays constant during the transition. */
        .theme-btn { display: inline-flex; align-items: center; justify-content: center; width: 32px; height: 32px; border-radius: 7px; border: 1px solid var(--panel-border); color: var(--text-dim); background: var(--panel); cursor: pointer; padding: 0; position: relative; flex: none; transition: border-color 120ms, background 120ms, color 120ms; }
        .theme-btn:hover { color: var(--text); background: var(--bg-sunk); }
        .theme-btn svg { width: 15px; height: 15px; position: absolute; transition: opacity 200ms ease, transform 300ms ease; }
        .theme-btn .icon-sun  { opacity: 0; transform: rotate(-40deg) scale(0.7); }
        .theme-btn .icon-moon { opacity: 1; transform: rotate(0) scale(1); }
        html[data-theme="dark"] .theme-btn .icon-sun  { opacity: 1; transform: rotate(0) scale(1); }
        html[data-theme="dark"] .theme-btn .icon-moon { opacity: 0; transform: rotate(40deg) scale(0.7); }

        /* Card */
        .card { background: var(--panel); border: 1px solid var(--panel-border); border-radius: var(--radius-lg); overflow: hidden; box-shadow: var(--shadow-lg); }
        .card-head { display: flex; align-items: center; justify-content: space-between; padding: 1.1rem 1.5rem; border-bottom: 1px solid var(--panel-border); gap: 1rem; }
        .card-title { font-family: var(--font-serif); font-style: italic; font-weight: 500; font-size: 1.45rem; margin: 0; letter-spacing: -0.01em; }
        .card-actions { display: flex; align-items: center; gap: 0.45rem; }

        /* Pills */
        .pill { display: inline-flex; align-items: center; gap: 0.4em; padding: 0.38rem 0.8rem; border-radius: var(--radius-pill); font-family: var(--font-mono); font-size: 0.8rem; font-weight: 400; border: 1px solid var(--panel-border); background: transparent; color: var(--text-dim); text-decoration: none; cursor: pointer; transition: color 120ms, border-color 120ms, background 120ms; white-space: nowrap; }
        .pill:hover { color: var(--text); border-color: var(--text-faint); }
        .pill.primary { background: var(--accent); border-color: var(--accent); color: var(--accent-fg); font-weight: 500; }
        .pill.primary:hover { filter: brightness(1.08); color: var(--accent-fg); border-color: var(--accent); }
        .pill:disabled { opacity: 0.5; cursor: not-allowed; }
        .pill-icon { width: 13px; height: 13px; flex: none; opacity: 0.85; }
        .pill:hover .pill-icon { opacity: 1; }

        /* Filter row */
        .filter-row { display: flex; align-items: center; gap: 0.5rem; padding: 0.6rem 1.5rem; border-bottom: 1px solid var(--panel-border); }
        .filter-input { flex: 1; min-width: 0; background: transparent; border: 0; color: var(--text); font-family: var(--font-mono); font-size: 0.88rem; padding: 0.15rem 0; outline: 0; }
        .filter-input::placeholder { color: var(--text-faint); }
        .filter-kbd { font-family: var(--font-mono); font-size: 0.68rem; color: var(--text-faint); border: 1px solid var(--panel-border); border-radius: 4px; padding: 0.1rem 0.35rem; }
        .filter-clear { background: transparent; border: 0; color: var(--text-dim); cursor: pointer; font-size: 1.05rem; line-height: 1; padding: 0 0.35rem; border-radius: 5px; }
        .filter-clear:hover { color: var(--text); background: var(--panel-hover); }
        /* Chip showing an active type-only filter (set by clicking a row pill).
           Separate state from the free-text filter so users can't hand-edit the
           "type:xxx" tokens and get into a weird parse state. */
        .filter-chip { display: inline-flex; align-items: center; gap: 0.1rem; padding: 0.18rem 0.22rem 0.18rem 0.65rem; background: var(--pill-wp-bg); color: var(--pill-wp-fg); border-radius: var(--radius-pill); font-family: var(--font-mono); font-size: 0.76rem; font-weight: 500; letter-spacing: 0.02em; white-space: nowrap; }
        .filter-chip-x { display: inline-flex; align-items: center; justify-content: center; width: 18px; height: 18px; background: transparent; border: 0; color: inherit; cursor: pointer; border-radius: 50%; font-size: 0.95rem; line-height: 1; padding: 0; }
        .filter-chip-x:hover { background: rgba(58, 151, 169, 0.28); background: color-mix(in oklch, var(--accent) 28%, transparent); }

        /* Add row */
        /* New-site alert: appears after creating a WP site so the one-time
           login is one click away, without hunting for the new row. */
        .new-site-alert { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem 1.25rem; border-bottom: 1px solid var(--panel-border); background: var(--bg-sunk); background: color-mix(in oklab, var(--accent) 12%, var(--panel)); color: var(--text); font-size: 0.92rem; }
        .new-site-alert-icon { display: inline-grid; place-items: center; width: 22px; height: 22px; border-radius: 50%; background: var(--accent); color: var(--accent-fg); flex: none; }
        .new-site-alert-text { flex: 1; min-width: 0; }
        .new-site-alert-text strong { font-family: var(--font-mono); font-weight: 500; }
        .new-site-alert-close { background: transparent; border: 0; color: var(--text-dim); cursor: pointer; font-size: 1.15rem; line-height: 1; padding: 0.25rem 0.55rem; border-radius: 5px; flex: none; }
        .new-site-alert-close:hover { color: var(--text); background: var(--panel-hover); }

        .add-row { position: relative; padding: 0.9rem 1.5rem; border-bottom: 1px solid var(--panel-border); background: var(--bg-sunk); }
        .add-row.is-creating { overflow: hidden; }
        /* Indeterminate progress stripe across the top while cove add is
           running — site creation takes 5-10s so we need a clear "working"
           cue beyond just the button text swap. Solid accent block slides
           across; a gradient-fade version blended with the row background
           and looked the wrong green. */
        .add-row.is-creating::before {
            content: '';
            position: absolute; top: 0; height: 3px; width: 30%;
            /* A thin 2px stripe of var(--accent) perceptually muted to olive
               against the cream bg-sunk; a brighter, more saturated teal at
               3px reads unambiguously as teal (same hue as the brand, just
               higher chroma so it survives the narrow band). */
            background: #3fb6cf;
            background: oklch(72% 0.15 190);
            animation: add-row-slide 1.3s linear infinite;
        }
        @keyframes add-row-slide {
            from { left: -30%; }
            to   { left: 100%; }
        }
        /* Inline spinner for the create button (reuses the .site-action-btn
           .btn-spinner pattern but scoped so pill button layout isn't altered). */
        .pill .btn-spinner { display: inline-block; width: 11px; height: 11px; border: 1.5px solid currentColor; border-top-color: transparent; border-radius: 50%; animation: spin 0.6s linear infinite; flex: none; }
        .add-row form { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
        .add-row input[type="text"] { background: var(--input-bg); border: 1px solid var(--panel-border); color: var(--text); font-family: var(--font-mono); font-size: 0.9rem; padding: 0.5rem 0.8rem; border-radius: var(--radius-md); min-width: 200px; flex: 1; }
        .add-row input[type="text"]:focus { outline: 0; border-color: var(--accent); }
        .add-row .plain-toggle { display: inline-flex; align-items: center; gap: 0.4rem; color: var(--text-dim); font-size: 0.85rem; cursor: pointer; }
        .add-row .plain-toggle input { accent-color: var(--accent); }
        .add-row select.wp-version { background: var(--input-bg); border: 1px solid var(--panel-border); color: var(--text); font-family: var(--font-mono); font-size: 0.85rem; padding: 0.5rem 0.7rem; border-radius: var(--radius-md); flex: none; cursor: pointer; }
        .add-row select.wp-version:focus { outline: 0; border-color: var(--accent); }

        /* Site list — one grid on the <ul>, rows inherit its columns via
           subgrid so type/modified/size/actions align vertically across rows
           instead of each row sizing independently. */
        .site-list { list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: 1fr auto auto auto auto; column-gap: 0.9rem; }
        .site-row { display: grid; grid-column: 1 / -1; grid-template-columns: subgrid; align-items: center; padding: 0.8rem 1.5rem; border-bottom: 1px solid var(--panel-border); transition: background 100ms; cursor: pointer; }
        .site-row:last-child { border-bottom: 0; }
        .site-row:hover { background: var(--panel-hover); }
        .site-domain-cell { display: inline-flex; align-items: center; gap: 0.35rem; min-width: 0; }
        .site-domain { font-family: var(--font-mono); font-size: 0.88rem; color: var(--text-dim); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .site-domain .host-accent { color: var(--accent); }
        /* The one spot on a row that opens the site — everywhere else on the
           row opens the context menu. Always visible (not hover-gated) so a
           site stays one tap away on touch. */
        .site-open-link { display: inline-flex; align-items: center; justify-content: center; width: 22px; height: 22px; border-radius: 6px; color: var(--text-faint); flex: none; }
        .site-open-link:hover { color: var(--accent); background: var(--panel-border); }
        .site-open-link svg { width: 13px; height: 13px; }
        .site-domain mark { background: rgba(58, 151, 169, 0.28); background: color-mix(in oklch, var(--accent) 28%, transparent); color: inherit; padding: 0 1px; border-radius: 3px; }
        .site-type { display: inline-flex; justify-content: center; min-width: 64px; padding: 0.2rem 0.55rem; border-radius: var(--radius-pill); font-family: var(--font-mono); font-size: 0.68rem; font-weight: 500; letter-spacing: 0.08em; text-transform: uppercase; cursor: pointer; user-select: none; transition: filter 120ms; }
        .site-type:hover { filter: brightness(1.15); }
        /* One grid child holding the pill plus its version, so adding the
           version does not shift the row's subgrid columns. */
        .site-type-cell { display: inline-flex; align-items: baseline; gap: 0.45rem; min-width: 0; }
        .site-wp-version { font-family: var(--font-mono); font-size: 0.7rem; color: var(--text-faint); white-space: nowrap; }
        /* Local sites aren't exposed, so an insecure release is a nudge to
           update rather than a warning — hence the dot, not a red badge. */
        .site-wp-version.insecure { color: var(--text-dim); }
        .site-wp-version.insecure::after { content: "●"; margin-left: 0.25rem; color: var(--pill-warn-fg, #d08c30); font-size: 0.6em; vertical-align: middle; }
        .site-type.wp { background: var(--pill-wp-bg); color: var(--pill-wp-fg); }
        .site-type.static { background: var(--pill-static-bg); color: var(--pill-static-fg); }
        /* Pinned-PHP chip: only rendered when a site is pinned off the default,
           so the common case stays visually quiet. While a version change is
           applying (or installing), the chip pulses with the target version. */
        .site-php-version { font-family: var(--font-mono); font-size: 0.66rem; color: var(--text-faint); white-space: nowrap; border: 1px solid var(--panel-border); border-radius: var(--radius-pill); padding: 0.05rem 0.45rem; }
        .site-php-version.applying { border-color: var(--accent); color: var(--text-dim); animation: php-pulse 1.2s ease-in-out infinite; }
        @keyframes php-pulse { 50% { opacity: 0.45; } }
        .site-modified { font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-faint); min-width: 44px; text-align: right; }
        .site-size { font-family: var(--font-mono); font-size: 0.82rem; color: var(--text-dim); min-width: 64px; text-align: right; }
        .site-actions { display: flex; gap: 0.15rem; opacity: 0; transition: opacity 100ms; }
        .site-row:hover .site-actions, .site-row:focus-within .site-actions { opacity: 1; }
        /* Fixed button size + both children stacked in one grid cell. Since
           grid-area "stack" collocates them at the same position and size is
           locked by width/height, toggling opacity on .loading can't shift
           any neighbour. */
        .site-action-btn { display: inline-grid; grid-template-areas: "stack"; place-items: center; box-sizing: border-box; width: 3.5em; height: 1.75em; padding: 0; background: transparent; border: 0; color: var(--text-dim); cursor: pointer; border-radius: 7px; font-family: var(--font-mono); font-size: 0.78rem; line-height: 1; }
        .site-action-btn > * { grid-area: stack; }
        .site-action-btn:hover { background: var(--panel-border); color: var(--text); }
        .site-action-btn.danger:hover { color: var(--danger); }
        .site-action-btn:disabled { cursor: wait; }
        .site-action-btn .btn-spinner { width: 10px; height: 10px; border: 1.5px solid currentColor; border-top-color: transparent; border-radius: 50%; animation: spin 0.6s linear infinite; opacity: 0; pointer-events: none; }
        .site-action-btn.loading .btn-label { opacity: 0; }
        .site-action-btn.loading .btn-spinner { opacity: 1; }

        /* Empty + loading states — scoped to direct children of .site-list so
           the global .loading class doesn't leak into unrelated elements
           (notably .site-action-btn.loading, which uses its own state class). */
        .site-list > .empty, .site-list > .loading { grid-column: 1 / -1; padding: 3rem 1.5rem; text-align: center; color: var(--text-dim); }
        .empty-hint { margin-top: 0.35rem; font-family: var(--font-mono); font-size: 0.82rem; color: var(--text-faint); }
        .empty-hint code { background: var(--panel-hover); padding: 0.1rem 0.4rem; border-radius: 5px; }
        .empty-art { display: block; width: 104px; height: 68px; margin: 0 auto 1rem; }
        .empty-art .art-line { stroke: var(--text-dim); stroke-width: 2; fill: none; }
        .empty-art .art-fill { fill: var(--accent); opacity: 0.14; stroke: none; }
        .empty-art .art-wave { stroke: var(--accent); stroke-width: 2; fill: none; opacity: 0.55; }

        /* Column headers — subgrid row mirroring .site-row's columns. */
        .site-head { display: grid; grid-column: 1 / -1; grid-template-columns: subgrid; align-items: center; padding: 0.5rem 1.5rem; border-bottom: 1px solid var(--panel-border); }
        .site-head-btn, .site-head-label { background: transparent; border: 0; padding: 0; font-family: var(--font-mono); font-size: 0.66rem; font-weight: 500; letter-spacing: 0.08em; text-transform: uppercase; color: var(--text-faint); text-align: left; }
        .site-head-btn { cursor: pointer; border-radius: 4px; }
        .site-head-btn:hover { color: var(--text); }
        .site-head-btn.active { color: var(--text-dim); }
        .site-head-label { justify-self: center; }
        .site-head-right { justify-self: end; text-align: right; }
        .sort-arrow { display: inline-block; min-width: 1em; text-align: right; }

        /* Bulk delete — appears in the filter row when a filter narrows the list. */
        .bulk-delete-btn { background: transparent; border: 1px solid var(--panel-border); color: var(--text-dim); cursor: pointer; font-family: var(--font-mono); font-size: 0.76rem; padding: 0.18rem 0.65rem; border-radius: var(--radius-pill); white-space: nowrap; transition: color 120ms, border-color 120ms, background 120ms; }
        .bulk-delete-btn:hover { color: var(--danger); border-color: var(--danger); }
        .bulk-delete-btn.armed { color: white; background: var(--danger); border-color: var(--danger); }

        /* Service dots in the top bar. They used to live only in the footer,
           which on an install with hundreds of sites sits ~14,000px down the
           page — the most glanceable status was the least reachable thing. */
        .nav-services { display: flex; align-items: center; gap: 0.85rem; margin-left: auto; margin-right: 0.85rem; font-family: var(--font-mono); font-size: 0.74rem; }

        /* Keyboard selection. Distinct from :hover so the two can coexist. */
        .site-row.is-selected { background: var(--panel-hover); box-shadow: inset 2px 0 0 var(--accent); }
        .site-row.is-selected .site-actions { opacity: 1; }
        /* Transient: only while this row's context menu is open. Deliberately
           separate from .is-selected — a mouse action shouldn't leave keyboard
           selection behind, which read as a highlight stuck on the last row. */
        .site-row.has-menu { background: var(--panel-hover); }
        .site-row.has-menu .site-actions { opacity: 1; }

        /* Pinned sites float to the top of the list. */
        .site-row.is-pinned .site-domain::before { content: '●'; color: var(--accent); font-size: 0.62rem; margin-right: 0.4rem; vertical-align: middle; opacity: 0.9; }

        /* Context menu — opened by clicking a row (right- or left-click). */
        .ctx-menu { position: fixed; z-index: 300; min-width: 190px; padding: 0.3rem; background: var(--panel); border: 1px solid var(--panel-border); border-radius: 10px; box-shadow: 0 12px 34px rgba(0,0,0,0.28); font-size: 0.85rem; }
        .ctx-title { padding: 0.35rem 0.6rem 0.45rem; font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-faint); border-bottom: 1px solid var(--panel-border); margin-bottom: 0.25rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .ctx-item { display: flex; align-items: center; justify-content: space-between; gap: 1rem; width: 100%; background: transparent; border: 0; text-align: left; padding: 0.42rem 0.6rem; border-radius: 6px; color: var(--text); cursor: pointer; font: inherit; }
        .ctx-item:hover { background: var(--panel-hover); }
        .ctx-item.danger { color: var(--danger); }
        .ctx-item .ctx-key { font-family: var(--font-mono); font-size: 0.7rem; color: var(--text-faint); }
        .ctx-sep { height: 1px; background: var(--panel-border); margin: 0.25rem 0; }

        /* Command palette. With 274 sites the list is not navigable by
           scrolling, so search is the real navigation and deserves to be one
           keystroke away. */
        .palette-backdrop { position: fixed; inset: 0; z-index: 400; background: rgba(0,0,0,0.45); display: flex; align-items: flex-start; justify-content: center; padding: 12vh 1rem 1rem; }
        .palette { width: 100%; max-width: 560px; background: var(--panel); border: 1px solid var(--panel-border); border-radius: 14px; box-shadow: 0 24px 60px rgba(0,0,0,0.4); overflow: hidden; display: flex; flex-direction: column; max-height: 70vh; }
        .palette-input { width: 100%; background: transparent; border: 0; border-bottom: 1px solid var(--panel-border); padding: 0.95rem 1.1rem; color: var(--text); font-family: var(--font-mono); font-size: 0.95rem; outline: none; }
        .palette-input::placeholder { color: var(--text-faint); }
        .palette-list { list-style: none; margin: 0; padding: 0.35rem; overflow-y: auto; flex: 1; }
        .palette-item { display: flex; align-items: center; gap: 0.7rem; padding: 0.5rem 0.75rem; border-radius: 8px; cursor: pointer; }
        .palette-item.active { background: var(--panel-hover); }
        .palette-item .pi-name { flex: 1; font-family: var(--font-mono); font-size: 0.85rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .palette-item .pi-meta { font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-faint); }
        .palette-item .pi-kind { font-family: var(--font-mono); font-size: 0.62rem; letter-spacing: 0.06em; text-transform: uppercase; color: var(--text-faint); border: 1px solid var(--panel-border); border-radius: var(--radius-pill); padding: 0.05rem 0.4rem; }
        .palette-empty { padding: 1.4rem; text-align: center; color: var(--text-dim); font-size: 0.87rem; }
        .palette-hint { display: flex; gap: 1rem; flex-wrap: wrap; padding: 0.5rem 0.9rem; border-top: 1px solid var(--panel-border); font-family: var(--font-mono); font-size: 0.7rem; color: var(--text-faint); }

        /* Footer */
        .card-foot { display: flex; align-items: center; justify-content: space-between; padding: 0.75rem 1.5rem; border-top: 1px solid var(--panel-border); color: var(--text-dim); font-family: var(--font-mono); font-size: 0.78rem; gap: 1rem; flex-wrap: wrap; }
        .services { display: flex; gap: 1.1rem; flex-wrap: wrap; }
        .dot { display: inline-flex; align-items: center; gap: 0.45rem; color: var(--text-dim); text-decoration: none; background: transparent; border: 0; padding: 0; font-family: inherit; font-size: inherit; cursor: default; }
        .dot.link, .dot[role="button"] { cursor: pointer; }
        .dot.link:hover, .dot[role="button"]:hover { color: var(--text); }
        .dot::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: var(--accent); box-shadow: 0 0 6px rgba(58, 151, 169, 0.6); box-shadow: 0 0 6px color-mix(in oklch, var(--accent) 60%, transparent); }
        .totals { display: inline-flex; align-items: center; gap: 0.5rem; }
        .refresh-btn { background: transparent; border: 0; color: var(--text-dim); cursor: pointer; padding: 0.15rem 0.35rem; font-size: 0.95rem; border-radius: 5px; }
        .refresh-btn:hover { color: var(--text); background: var(--panel-hover); }
        .refresh-btn.spinning { animation: spin 1s linear infinite; pointer-events: none; }
        @keyframes spin { to { transform: rotate(360deg); } }

        /* Pop-in fade for banners, menus, modals, palette and snackbar.
           Toggling display:none → visible replays the animation, so showing
           an element is all it takes to get the fade. */
        @keyframes cove-fade { from { opacity: 0; } }
        .new-site-alert, .filter-chip, .add-row, .modal-backdrop, .ctx-menu, .palette-backdrop, .snackbar { animation: cove-fade 140ms ease; }

        /* Modal */
        .modal-backdrop { position: fixed; inset: 0; background: rgba(0,0,0,0.55); display: grid; place-items: center; z-index: 80; padding: 1rem; }
        html[data-theme="light"] .modal-backdrop { background: rgba(20,20,18,0.35); }
        .modal { background: var(--panel); border: 1px solid var(--panel-border); border-radius: var(--radius-lg); padding: 1.5rem; min-width: min(420px, 90vw); max-width: 540px; }
        .modal h3 { font-family: var(--font-serif); font-style: italic; font-weight: 500; font-size: 1.25rem; margin: 0 0 0.3rem; }
        .modal .modal-sub { color: var(--text-dim); font-size: 0.85rem; margin: 0 0 1rem; }
        .modal pre { background: var(--input-bg); border: 1px solid var(--panel-border); border-radius: var(--radius-md); padding: 0.85rem 1rem; margin: 0; font-family: var(--font-mono); font-size: 0.82rem; color: var(--text); overflow-x: auto; }
        .db-creds { background: var(--input-bg); border: 1px solid var(--panel-border); border-radius: var(--radius-md); padding: 0.9rem 1rem; display: flex; flex-direction: column; gap: 0.7rem; }
        .db-cred-row { display: grid; grid-template-columns: 85px 1fr; align-items: baseline; gap: 0.75rem; font-family: var(--font-mono); font-size: 0.82rem; }
        .db-cred-label { color: var(--text-dim); font-weight: 500; }
        .db-cred-value { color: var(--text); word-break: break-all; background: transparent; padding: 0; }
        .modal .modal-foot { margin-top: 1rem; display: flex; justify-content: space-between; align-items: center; color: var(--text-faint); font-family: var(--font-mono); font-size: 0.75rem; }

        /* PHP version picker rows. Installed versions are one click; missing
           ones are greyed but still actionable — clicking installs the brew
           formula first, then pins. */
        .php-options { display: flex; flex-direction: column; gap: 0.35rem; }
        .php-option { display: flex; align-items: center; justify-content: space-between; gap: 1rem; width: 100%; background: var(--input-bg); border: 1px solid var(--panel-border); border-radius: var(--radius-md); padding: 0.55rem 0.9rem; color: var(--text); cursor: pointer; font-family: var(--font-mono); font-size: 0.85rem; text-align: left; transition: border-color 120ms, background 120ms; }
        .php-option:hover { border-color: var(--accent); }
        .php-option.current { border-color: var(--accent); background: var(--pill-wp-bg); cursor: default; }
        .php-option.uninstalled .php-option-name { color: var(--text-faint); }
        .php-option .php-option-meta { font-size: 0.72rem; color: var(--text-faint); }
        .php-option:disabled { opacity: 0.65; cursor: default; }

        /* Wider variant for log output, which is unreadable at 540px. */
        .modal-wide { max-width: min(900px, 92vw); width: 900px; }
        .modal-title-dim { font-family: var(--font-mono); font-style: normal; font-size: 0.9rem; color: var(--text-faint); }
        .modal-input { width: 100%; background: var(--input-bg); border: 1px solid var(--panel-border); border-radius: var(--radius-md); padding: 0.6rem 0.8rem; color: var(--text); font-family: var(--font-mono); font-size: 0.9rem; outline: none; }
        .modal-input:focus { border-color: var(--accent); }
        .modal-input:disabled { opacity: 0.6; }
        .modal-hint { margin-top: 0.4rem; min-height: 1.1em; font-family: var(--font-mono); font-size: 0.76rem; color: var(--text-faint); }
        .modal-actions { margin-top: 1.1rem; display: flex; justify-content: flex-end; gap: 0.6rem; }
        .log-pane { max-height: 55vh; overflow: auto; white-space: pre-wrap; word-break: break-word; font-size: 0.76rem !important; line-height: 1.5; }

        /* Snackbar */
        /* Centered via auto margins + fit-content width — no transform needed,
           so the fade animation can't interfere with positioning. */
        .snackbar { position: fixed; bottom: 1.5rem; left: 0; right: 0; margin-inline: auto; width: max-content; max-width: 90vw; display: flex; align-items: center; gap: 0.9rem; background: var(--text); color: var(--bg); padding: 0.7rem 1.15rem; border-radius: 10px; font-size: 0.88rem; z-index: 200; box-shadow: 0 10px 30px rgba(0,0,0,0.25); }
        .snackbar.error { background: var(--danger); color: white; }
        .snackbar-action { background: transparent; border: 0; padding: 0; color: inherit; font: inherit; font-weight: 600; text-decoration: underline; text-underline-offset: 2px; cursor: pointer; }
        .snackbar-action:hover { opacity: 0.8; }

        /* Responsive */
        @media (max-width: 620px) {
            body { padding: 1.25rem 0.75rem 3rem; }
            .card-head { padding: 0.9rem 1rem; flex-wrap: wrap; }
            .card-actions { width: 100%; justify-content: flex-end; }
            .site-list { grid-template-columns: 1fr auto auto; column-gap: 0.6rem; }
            .site-row { padding: 0.7rem 1rem; }
            .site-size, .site-modified, .head-size, .head-modified { display: none; }
            .site-actions { opacity: 1; }
            .add-row { padding: 0.8rem 1rem; }
            .card-foot { padding: 0.75rem 1rem; }
        }
    </style>
</head>
<body>
    <div class="wrap">
        <nav class="nav">
            <a class="logo" href="/">
                <svg class="logo-mark" viewBox="0 0 64 64" aria-hidden="true" focusable="false" stroke-linecap="round" stroke-linejoin="round">
                    <defs>
                        <clipPath id="cove-clip"><circle cx="32" cy="32" r="28"/></clipPath>
                    </defs>
                    <g clip-path="url(#cove-clip)">
                        <rect x="0" y="0" width="64" height="64" class="disc"/>
                        <rect x="0" y="32" width="64" height="32" class="water"/>
                        <path class="land" d="M 4 32 C 4 22, 12 12, 22 12 C 30 12, 34 18, 42 16 C 50 14, 58 18, 60 24 L 60 32 Z"/>
                        <line class="horizon" x1="2" y1="32" x2="62" y2="32" stroke-width="2.5"/>
                        <g class="wave" stroke-width="2.6">
                            <path d="M 10 42 Q 18 38, 26 42 T 42 42 T 56 42"/>
                            <path d="M 14 50 Q 22 46, 30 50 T 46 50 T 56 50"/>
                        </g>
                    </g>
                    <circle cx="32" cy="32" r="28" class="ring"/>
                </svg>
                <span>Cove</span>
            </a>
            <div class="nav-services services">
                <span class="dot" title="Caddy is serving this page — it's running">caddy</span>
                <button type="button" id="btnDbDot" class="dot link" title="Database credentials">mariadb</button>
                <a class="dot link" href="https://mail.cove.localhost<?= $__cove_port_suffix ?>" target="_blank" rel="noopener" title="Open Mailpit">mailpit</a>
            </div>
            <button class="theme-btn" id="btnTheme" title="Toggle theme" aria-label="Toggle theme">
                <svg class="icon-moon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M13.5 9.2A5.5 5.5 0 0 1 6.8 2.5a5.75 5.75 0 1 0 6.7 6.7Z"/></svg>
                <svg class="icon-sun" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="8" cy="8" r="3"/><path d="M8 1.5v1.8M8 12.7v1.8M2.6 2.6l1.3 1.3M12.1 12.1l1.3 1.3M1.5 8h1.8M12.7 8h1.8M2.6 13.4l1.3-1.3M12.1 3.9l1.3-1.3"/></svg>
            </button>
        </nav>

        <section class="card">
            <header class="card-head">
                <h1 class="card-title">Sites</h1>
                <div class="card-actions">
                    <a class="pill" href="https://db.cove.localhost<?= $__cove_port_suffix ?>" target="_blank" rel="noopener" title="Open Adminer">
                        <svg class="pill-icon" width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><ellipse cx="8" cy="3.5" rx="5" ry="1.5"/><path d="M3 3.5v9c0 .83 2.24 1.5 5 1.5s5-.67 5-1.5v-9"/><path d="M3 8c0 .83 2.24 1.5 5 1.5s5-.67 5-1.5"/></svg>
                        db
                    </a>
                    <a class="pill" href="https://mail.cove.localhost<?= $__cove_port_suffix ?>" target="_blank" rel="noopener" title="Open Mailpit">
                        <svg class="pill-icon" width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="4" width="12" height="9" rx="1.5"/><path d="M2.5 5 8 9l5.5-4"/></svg>
                        mail
                    </a>
                    <button class="pill primary" id="btnToggleAdd">+ add site</button>
                </div>
            </header>

            <div id="alerts"></div>
            <template id="tpl-alert">
                <div class="new-site-alert">
                    <span class="new-site-alert-icon" aria-hidden="true">
                        <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8.2l3 3 7-7"/></svg>
                    </span>
                    <div class="new-site-alert-text">
                        <strong></strong> is ready.
                    </div>
                    <button class="pill primary alert-login">log in to admin</button>
                    <a class="pill primary alert-open" target="_blank" rel="noopener">open site</a>
                    <button class="new-site-alert-close" aria-label="Dismiss" title="Dismiss">×</button>
                </div>
            </template>

            <div class="filter-row">
                <span class="filter-chip" id="typeChip" aria-label="Active type filter" style="display: none;">
                    <span id="typeChipLabel"></span>
                    <button type="button" class="filter-chip-x" id="typeChipClear" aria-label="Remove type filter" title="Remove">×</button>
                </span>
                <input
                    class="filter-input"
                    id="filterInput"
                    type="text"
                    placeholder="filter sites by name or type…"
                    spellcheck="false"
                    autocomplete="off"
                    autocapitalize="off"
                    autocorrect="off"
                    aria-label="Filter sites"
                    autofocus
                >
                <button
                    type="button"
                    class="bulk-delete-btn"
                    id="btnBulkDelete"
                    title="Delete every site matching the current filter"
                    style="display: none;"></button>
                <span class="filter-kbd" id="filterKbd" aria-hidden="true">/</span>
                <button class="filter-clear" id="btnFilterClear" aria-label="Clear filter" title="Clear all (Esc)" style="display: none;">×</button>
            </div>

            <div class="add-row" id="addRow" style="display: none;">
                <form id="addForm">
                    <input type="text" id="newSiteName" placeholder="site-name" required>
                    <label class="plain-toggle">
                        <input type="checkbox" id="newSitePlain">
                        plain (no WordPress)
                    </label>
                    <select class="wp-version" id="wpVersionSelect" title="WordPress version to install" aria-label="WordPress version">
                        <option value="latest">latest</option>
                        <option value="nightly">nightly</option>
                    </select>
                    <button class="pill primary" type="submit" id="btnCreate" disabled>
                        <span class="btn-spinner" id="createSpinner" aria-hidden="true" style="display: none;"></span>
                        <span id="createLabel">create</span>
                    </button>
                </form>
            </div>

            <ul class="site-list" id="siteList">
                <li class="site-head" id="siteHead" style="display: none;">
                    <button type="button" class="site-head-btn" data-sort="name" title="Sort by name">name<span class="sort-arrow"></span></button>
                    <button type="button" class="site-head-btn" data-sort="type" title="Sort by type">type<span class="sort-arrow"></span></button>
                    <button type="button" class="site-head-btn site-head-right head-modified" data-sort="modified" title="Sort by last modified">modified<span class="sort-arrow"></span></button>
                    <button type="button" class="site-head-btn site-head-right head-size" data-sort="size" title="Sort by disk size">size<span class="sort-arrow"></span></button>
                    <span aria-hidden="true"></span>
                </li>
                <template id="tpl-site-row">
                    <li class="site-row">
                        <span class="site-domain-cell">
                            <span class="site-domain"></span>
                            <a class="site-open-link" target="_blank" rel="noopener">
                                <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6.5 4.5h5v5"/><path d="M11.5 4.5 4.5 11.5"/></svg>
                            </a>
                        </span>
                        <span class="site-type-cell">
                            <span class="site-type"></span>
                            <span class="site-wp-version"></span>
                            <span class="site-php-version"></span>
                        </span>
                        <span class="site-modified"></span>
                        <span class="site-size"></span>
                        <div class="site-actions">
                            <button class="site-action-btn site-login-btn">
                                <span class="btn-label">login</span>
                                <span class="btn-spinner" aria-hidden="true"></span>
                            </button>
                        </div>
                    </li>
                </template>
                <li class="loading" id="siteLoading">Loading sites…</li>
                <li class="empty" id="emptyNone" style="display: none;">
                        <svg class="empty-art" viewBox="0 0 104 68" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                            <path class="art-fill" d="M52 12 L68 38 H52 Z"/>
                            <path class="art-line" d="M52 10 v30"/>
                            <path class="art-line" d="M52 14 L67 37 H52 Z"/>
                            <path class="art-line" d="M49 20 L39 37 H49 Z"/>
                            <path class="art-line" d="M36 42 h32 l-6 9 H42 Z"/>
                            <path class="art-wave" d="M8 56 Q 15 52, 22 56 T 36 56 T 50 56 T 64 56 T 78 56 T 92 56"/>
                            <path class="art-wave" d="M20 62 Q 27 58, 34 62 T 48 62 T 62 62 T 76 62" opacity="0.35"/>
                        </svg>
                    <div>No sites in the cove yet.</div>
                    <div class="empty-hint">Click <em>+ add site</em>, or run <code>cove add myblog</code>.</div>
                </li>
                <li class="empty" id="emptyFilter" style="display: none;">
                        <svg class="empty-art" viewBox="0 0 104 68" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                            <path class="art-line" d="M52 44 v-14 q0 -6 6 -6 h4"/>
                            <path class="art-line" d="M62 18 h8 q3 0 3 3 v3 h-11 q-3 0 -3 -3 v-3 Z"/>
                            <path class="art-line" d="M73 21 l7 -4 v11 l-7 -4"/>
                            <path class="art-fill" d="M46 44 h12 v8 H46 Z"/>
                            <path class="art-line" d="M46 52 v-8 h12 v8"/>
                            <path class="art-wave" d="M8 56 Q 15 52, 22 56 T 36 56 T 50 56 T 64 56 T 78 56 T 92 56"/>
                            <path class="art-wave" d="M20 62 Q 27 58, 34 62 T 48 62 T 62 62 T 76 62" opacity="0.35"/>
                        </svg>
                    <div>Nothing surfaced for <code id="emptyFilterQuery"></code>.</div>
                    <div class="empty-hint">Press Esc to clear.</div>
                </li>
            </ul>

            <footer class="card-foot">
                <div class="totals">
                    <span id="siteCount"></span>
                    <span id="totalSize" style="display: none;"></span>
                    <button type="button" class="refresh-btn" id="btnRefreshSizes" title="Refresh disk sizes">↻</button>
                </div>
            </footer>
        </section>
    </div>

    <div class="modal-backdrop" id="dbModal" style="display: none;">
        <div class="modal">
            <h3>Database credentials</h3>
            <p class="modal-sub">Cove uses these to create new WordPress databases.</p>
            <div class="db-creds">
                <div class="db-cred-row">
                    <span class="db-cred-label">user</span>
                    <code class="db-cred-value"><?= htmlspecialchars($config_data['DB_USER'] ?? '—') ?></code>
                </div>
                <div class="db-cred-row">
                    <span class="db-cred-label">password</span>
                    <code class="db-cred-value"><?= htmlspecialchars($config_data['DB_PASSWORD'] ?? '—') ?></code>
                </div>
            </div>
            <div class="modal-foot">
                <span>stored in <?= htmlspecialchars(str_replace(getenv('HOME'), '~', $config_file)) ?></span>
                <button class="pill" id="btnDbClose">close</button>
            </div>
        </div>
    </div>

    <!-- Rename -->
    <div class="modal-backdrop" id="renameModal" style="display: none;">
        <div class="modal">
            <h3>Rename site</h3>
            <p class="modal-sub">Renames the directory, the database, and the local URL. Any bookmark to the old address stops working.</p>
            <form id="renameForm">
                <input class="modal-input" type="text" id="renameInput" spellcheck="false" autocomplete="off" placeholder="new-name">
                <div class="modal-hint"><span id="renameHint">&nbsp;</span></div>
                <div class="modal-actions">
                    <button type="button" class="pill" id="btnRenameCancel">cancel</button>
                    <button type="submit" class="pill primary" id="btnRenameSubmit">rename</button>
                </div>
            </form>
        </div>
    </div>

    <!-- PHP version picker -->
    <div class="modal-backdrop" id="phpModal" style="display: none;">
        <div class="modal">
            <h3>PHP version <span class="modal-title-dim" id="phpModalSite"></span></h3>
            <p class="modal-sub">Pinned sites run on a native Homebrew php-fpm behind FrankenPHP — TLS, logs and the URL stay the same.</p>
            <div class="php-options" id="phpOptions"></div>
            <template id="tpl-php-option">
                <button type="button" class="php-option">
                    <span class="php-option-name"></span>
                    <span class="php-option-meta"></span>
                </button>
            </template>
            <div class="modal-foot">
                <span id="phpModalHint"></span>
                <button class="pill" id="btnPhpClose">close</button>
            </div>
        </div>
    </div>

    <!-- Site log -->
    <div class="modal-backdrop" id="logModal" style="display: none;">
        <div class="modal modal-wide">
            <h3>Log <span class="modal-title-dim" id="logTitle"></span></h3>
            <p class="modal-sub" id="logTruncated" style="display: none;">Showing the most recent 64KB.</p>
            <pre class="log-pane" id="logPane"></pre>
            <div class="modal-actions">
                <button type="button" class="pill" id="btnLogRaw">raw</button>
                <button type="button" class="pill" id="btnLogRefresh">refresh</button>
                <button type="button" class="pill primary" id="btnLogClose">close</button>
            </div>
        </div>
    </div>

    <!-- Context menu: one component driven by right- OR left-click anywhere on
         a row, so the two affordances can never drift apart. Opening the site
         itself lives on the row's ↗ icon. -->
    <div class="ctx-menu" id="ctxMenu" style="display: none;">
        <div>
            <div class="ctx-title" id="ctxTitle"></div>
            <button class="ctx-item" id="ctxOpen"><span>Open site</span><span class="ctx-key">↵</span></button>
            <button class="ctx-item" id="ctxLogin"><span>Log in to admin</span><span class="ctx-key">⌘↵</span></button>
            <div class="ctx-sep"></div>
            <button class="ctx-item" id="ctxRename"><span>Rename…</span></button>
            <button class="ctx-item" id="ctxReveal"><span>Open folder</span></button>
            <button class="ctx-item" id="ctxDb"><span>Open database</span></button>
            <button class="ctx-item" id="ctxPhp"><span>PHP version…</span><span class="ctx-key" id="ctxPhpMeta"></span></button>
            <button class="ctx-item" id="ctxLog"><span>View log</span></button>
            <div class="ctx-sep"></div>
            <button class="ctx-item" id="ctxCopy"><span>Copy path</span></button>
            <button class="ctx-item" id="ctxPin"><span>Pin to top</span></button>
            <div class="ctx-sep"></div>
            <button class="ctx-item danger" id="ctxDelete"><span>Delete site</span><span class="ctx-key">⌘⌫</span></button>
        </div>
    </div>

    <!-- Command palette. Primary navigation once the list is longer than a
         screen, which on a real install it always is. -->
    <div class="palette-backdrop" id="paletteBackdrop" style="display: none;">
        <div class="palette">
            <input class="palette-input" id="paletteInput" type="text"
                placeholder="Search sites, or type a command…" spellcheck="false" autocomplete="off"
                aria-label="Command palette">
            <ul class="palette-list" id="paletteList"></ul>
            <template id="tpl-palette-item">
                <li class="palette-item">
                    <span class="pi-kind"></span>
                    <span class="pi-name"></span>
                    <span class="pi-meta"></span>
                </li>
            </template>
            <div class="palette-hint">
                <span>↑↓ navigate</span><span>↵ open</span><span>⌘↵ log in</span><span>esc close</span>
            </div>
        </div>
    </div>

    <div class="snackbar" id="snackbar" style="display: none;">
        <span id="snackMsg"></span>
        <button type="button" class="snackbar-action" id="snackAction" style="display: none;"></button>
    </div>

    <script>
        const PORT_SUFFIX = '<?= $__cove_port_suffix ?>';
        const SITES_DIR = 'SITES_DIR_PLACEHOLDER';
        // Adminer needs the username to deep-link straight into a site's schema.
        const DB_USER = '<?= htmlspecialchars($config_data['DB_USER'] ?? '', ENT_QUOTES) ?>';

        // No framework: state lives on `app`, and every method that mutates
        // state ends by calling render(). Renderers are idempotent and only
        // write DOM they own — crucially they never write input values, so
        // typing never fights the renderer; inputs push into state via their
        // own listeners and open()-style methods set values explicitly.
        const $id = (id) => document.getElementById(id);
        const show = (el, on) => { if (el) el.style.display = on ? '' : 'none'; };

        const app = {
            // Respect the OS theme preference on first visit, dark otherwise.
            theme: localStorage.getItem('theme') || (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'),
            sites: [],
            isLoading: true,
            adding: false,
            showDbModal: false,
            isRefreshingSizes: false,
            filter: '',
            typeFilter: null, // null | 'WordPress' | 'Plain' — set via the row type pills, cleared via the chip × or overall filter clear
            // Default to most-recently-modified rather than alphabetical: on an
            // install with hundreds of sites, "what was I just working on" is a
            // far better landing state than "what starts with A".
            sort: ['name', 'type', 'size', 'modified'].includes(localStorage.getItem('sort')) ? localStorage.getItem('sort') : 'modified',
            sortDir: ['asc', 'desc'].includes(localStorage.getItem('sortDir')) ? localStorage.getItem('sortDir') : 'desc',
            pinned: (() => { try { return JSON.parse(localStorage.getItem('pinned')) || []; } catch (e) { return []; } })(),
            selectedName: null,
            ctxMenu: { open: false, site: null, x: 0, y: 0, openedAt: 0 },
            palette: { open: false, query: '', index: 0 },
            rename: { open: false, site: null, value: '', busy: false },
            logView: { open: false, site: '', text: '', truncated: false, busy: false, raw: false },
            phpModal: { open: false, site: null },
            // { supported, default, versions: [{version, installed}] } — fetched
            // lazily; null until loaded, refreshed after any pin change.
            phpInfo: null,
            phpInstallPoll: null,
            // name → target version while a change is in flight. Kept separate
            // from the site objects because getSites() rebuilds those from the
            // server and would drop a flag stored on them mid-install.
            phpApplying: {},
            newSite: { name: '', isPlain: false, wpVersion: 'latest', isLoading: false },
            // Populated lazily the first time the add row opens — no reason
            // to hit wp.org on a page load that never creates a site. Stays
            // empty when offline, leaving 'latest' and 'nightly' available.
            wpVersions: [],
            wpVersionsLoaded: false,
            snackbar: { visible: false, message: '', isError: false, timer: null, action: null, actionLabel: '' },
            // Deletes are staged for a short undo window before anything is
            // sent to the backend. One batch at a time; staging more sites
            // merges into it and restarts the window.
            pendingDelete: null, // { sites: [...], timer }
            bulkArmed: false,
            bulkArmTimer: null,
            // Persistent dismissible banners for newly-created sites — the
            // snackbar only lives ~3.5s, not long enough to reach for the
            // admin login after spinning up a fresh install.
            alerts: [],
            deleteQueue: [],
            isProcessingQueue: false,
            _paletteItems: [],

            get adminerUrl() { return 'https://db.cove.localhost' + PORT_SUFFIX; },
            get mailpitUrl() { return 'https://mail.cove.localhost' + PORT_SUFFIX; },
            get totalBytes() { return this.sites.reduce((t, s) => t + (s.size_bytes || 0), 0); },
            get filteredSites() {
                // Two independent filters ANDed together: typeFilter (chip,
                // exact match on site.type) and filter (free text, substring
                // match on name OR type). Keeping them separate means the
                // user can type anything in the input without worrying about
                // stepping on the type constraint.
                let base = [...this.sites];
                if (this.typeFilter) {
                    base = base.filter(s => s.type === this.typeFilter);
                }
                const q = this.filter.trim().toLowerCase();
                if (q) {
                    base = base.filter(s =>
                        s.name.toLowerCase().includes(q) ||
                        (s.type || '').toLowerCase().includes(q));
                }
                const dir = this.sortDir === 'asc' ? 1 : -1;
                if (this.sort === 'size') {
                    base.sort((a, b) => dir * ((a.size_bytes || 0) - (b.size_bytes || 0)));
                } else if (this.sort === 'modified') {
                    base.sort((a, b) => dir * ((a.modified_at || 0) - (b.modified_at || 0)));
                } else if (this.sort === 'type') {
                    // Version segments compare numerically so 6.10 outranks 6.9.
                    // Plain sites have no wp_version and stay grouped together.
                    const vcmp = (a, b) => {
                        const pa = (a.wp_version || '').split('.'), pb = (b.wp_version || '').split('.');
                        for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
                            const d = (parseInt(pa[i], 10) || 0) - (parseInt(pb[i], 10) || 0);
                            if (d) return d;
                        }
                        return 0;
                    };
                    base.sort((a, b) => dir * (a.type.localeCompare(b.type) || vcmp(a, b)) || a.name.localeCompare(b.name));
                } else {
                    base.sort((a, b) => dir * a.name.localeCompare(b.name));
                }
                // Pinned sites float above the chosen sort rather than replacing
                // it: out of hundreds of sites only a handful are ever active.
                if (this.pinned.length) {
                    base.sort((a, b) => (this.pinned.includes(b.name) ? 1 : 0) - (this.pinned.includes(a.name) ? 1 : 0));
                }
                return base;
            },

            get typeFilterLabel() {
                return this.typeFilter === 'WordPress' ? 'type: wp' : 'type: static';
            },

            setTypeFilter(v) {
                this.typeFilter = v;
                // An armed bulk-delete is scoped to the current result set —
                // disarm when the filter changes underneath it.
                this.bulkArmed = false;
                this.render();
            },

            clearAllFilters() {
                this.filter = '';
                $id('filterInput').value = '';
                this.typeFilter = null;
                this.bulkArmed = false;
                this.render();
            },

            get siteCountLabel() {
                const total = this.sites.length;
                const visible = this.filteredSites.length;
                const suffix = ' site' + (total === 1 ? '' : 's');
                return visible === total ? total + suffix : visible + ' of ' + total + suffix;
            },

            init() {
                this.applyTheme();
                this.bindStaticEvents();
                this.render();

                // If the tab closes during an undo window, flush the staged
                // deletes with keepalive requests so they aren't lost. No
                // reload_server here: the next reload from any source
                // regenerates from disk and prunes via tombstones.
                window.addEventListener('pagehide', () => {
                    if (!this.pendingDelete) return;
                    for (const s of this.pendingDelete.sites) {
                        fetch('api.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action: 'delete_site', site_name: s.name }),
                            keepalive: true
                        }).catch(() => {});
                    }
                    this.pendingDelete = null;
                });

                // `/` focuses the filter (GitHub-style). Ignored when typing
                // in a form field or holding a modifier key.
                window.addEventListener('keydown', (e) => {
                    const el = document.activeElement;
                    const tag = el && el.tagName;
                    const typing = tag === 'INPUT' || tag === 'TEXTAREA' || (el && el.isContentEditable);

                    // Cmd/Ctrl+K opens the palette from anywhere, including
                    // from inside the filter box — it's the one shortcut that
                    // should never be swallowed by a focused field.
                    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
                        e.preventDefault();
                        this.palette.open ? this.closePalette() : this.openPalette();
                        return;
                    }
                    if (this.palette.open) {
                        // Palette owns its own keys via its input's listeners;
                        // catch Esc here too in case the input lost focus.
                        if (e.key === 'Escape') this.closePalette();
                        return;
                    }

                    // Arrows work while filtering (type to narrow, arrow to pick).
                    // j/k only outside a text field, or they'd eat typed letters.
                    const isDown = e.key === 'ArrowDown' || (!typing && e.key === 'j');
                    const isUp   = e.key === 'ArrowUp'   || (!typing && e.key === 'k');
                    if ((isDown || isUp) && !e.metaKey && !e.ctrlKey && !e.altKey) {
                        e.preventDefault();
                        this.moveSelection(isDown ? 1 : -1);
                        return;
                    }

                    if (e.key === 'Enter' && this.selectedName && !this.adding) {
                        const site = this.selectedSite();
                        if (!site) return;
                        e.preventDefault();
                        if ((e.metaKey || e.ctrlKey) && site.type === 'WordPress') {
                            this.getLoginLink(site.name);
                        } else {
                            this.openSite(site);
                        }
                        return;
                    }

                    if ((e.metaKey || e.ctrlKey) && (e.key === 'Backspace' || e.key === 'Delete') && this.selectedName) {
                        e.preventDefault();
                        this.deleteSite(this.selectedName);
                        return;
                    }

                    if (e.key === 'Escape') {
                        if (this.ctxMenu.open) { this.closeRowMenu(); return; }
                        if (this.phpModal.open) { this.closePhpModal(); return; }
                        if (this.rename.open) { this.closeRename(); return; }
                        if (this.logView.open) { this.closeLog(); return; }
                        if (this.showDbModal) { this.setDbModal(false); return; }
                        if (this.selectedName && !typing) { this.selectedName = null; this.render(); return; }
                    }

                    if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey) {
                        if (typing) return;
                        e.preventDefault();
                        $id('filterInput').focus();
                    }
                });

                // A scroll or resize would leave the menu floating away from
                // the row it belongs to, so dismiss rather than reposition.
                window.addEventListener('scroll', () => { if (this.ctxMenu.open) this.closeRowMenu(); }, { passive: true });
                window.addEventListener('resize', () => { if (this.ctxMenu.open) this.closeRowMenu(); });

                // Click anywhere outside the context menu dismisses it. The
                // click that opened the menu also bubbles here, so skip it.
                document.addEventListener('click', (e) => {
                    if (!this.ctxMenu.open || e.timeStamp === this.ctxMenu.openedAt) return;
                    if (!$id('ctxMenu').contains(e.target)) this.closeRowMenu();
                });

                // Non-blocking: the context menu's "php X.Y" meta and the
                // platform-support check want this early, but nothing waits on it.
                this.loadPhpInfo();

                this.getSites().then(() => {
                    // If the size cache is empty (fresh install or just deleted),
                    // kick off a background refresh so sizes populate without
                    // making the user hunt for the ↻ button.
                    if (this.sites.length > 0 && this.sites.every(s => s.size_bytes === null)) {
                        this.refreshSizes();
                    }
                });
            },

            // One-time listeners on elements that are never re-created. Row,
            // alert, palette and menu clicks are delegated from their fixed
            // containers, so rebuilding children never orphans a handler.
            bindStaticEvents() {
                $id('btnTheme').addEventListener('click', () => this.toggleTheme());
                $id('btnDbDot').addEventListener('click', () => this.setDbModal(true));
                $id('btnToggleAdd').addEventListener('click', () => this.toggleAdd());
                $id('btnRefreshSizes').addEventListener('click', () => this.refreshSizes());
                $id('btnDbClose').addEventListener('click', () => this.setDbModal(false));
                $id('dbModal').addEventListener('click', (e) => { if (e.target === $id('dbModal')) this.setDbModal(false); });

                // Filter row
                const filterInput = $id('filterInput');
                filterInput.addEventListener('input', () => {
                    this.filter = filterInput.value;
                    this.bulkArmed = false;
                    this.render();
                });
                filterInput.addEventListener('keydown', (e) => {
                    if (e.key === 'Escape') {
                        e.preventDefault();
                        e.stopPropagation();
                        this.filter = '';
                        filterInput.value = '';
                        this.bulkArmed = false;
                        filterInput.blur();
                        this.render();
                    }
                });
                $id('typeChipClear').addEventListener('click', () => { this.setTypeFilter(null); filterInput.focus(); });
                $id('btnFilterClear').addEventListener('click', () => { this.clearAllFilters(); filterInput.focus(); });
                $id('btnBulkDelete').addEventListener('click', () => this.bulkDelete());

                // Add-site form
                const nameInput = $id('newSiteName');
                nameInput.addEventListener('input', () => {
                    const clean = nameInput.value.toLowerCase().replace(/[^a-z0-9-]/g, '');
                    if (clean !== nameInput.value) nameInput.value = clean;
                    this.newSite.name = clean;
                    this.render();
                });
                $id('newSitePlain').addEventListener('change', (e) => {
                    this.newSite.isPlain = e.target.checked;
                    this.render();
                });
                $id('wpVersionSelect').addEventListener('change', (e) => { this.newSite.wpVersion = e.target.value; });
                $id('addForm').addEventListener('submit', (e) => { e.preventDefault(); this.addSite(); });

                // Sort headers
                document.querySelectorAll('.site-head-btn[data-sort]').forEach(btn => {
                    btn.addEventListener('click', () => this.setSort(btn.dataset.sort));
                });

                // Site rows: one delegated listener instead of per-row handlers.
                // The ↗ icon is the only thing that opens the site; the type
                // pill filters and the login button logs in; a click anywhere
                // else on the row opens the context menu.
                const list = $id('siteList');
                list.addEventListener('click', (e) => {
                    const row = e.target.closest('.site-row');
                    if (!row) return;
                    const site = this.sites.find(s => s.name === row.dataset.name);
                    if (!site) return;
                    if (e.target.closest('.site-open-link')) return; // plain link — let it navigate
                    if (e.target.closest('.site-type')) { this.setTypeFilter(site.type); return; }
                    if (e.target.closest('.site-login-btn')) { this.getLoginLink(site.name); return; }
                    // Don't pop the menu when the click ends a drag-to-select —
                    // users still grab the domain/size text to copy it.
                    if (window.getSelection && window.getSelection().toString()) return;
                    this.openRowMenu(site, e);
                });
                list.addEventListener('contextmenu', (e) => {
                    const row = e.target.closest('.site-row');
                    if (!row) return;
                    const site = this.sites.find(s => s.name === row.dataset.name);
                    if (!site) return;
                    e.preventDefault();
                    this.openRowMenu(site, e);
                });

                // New-site alerts (delegated)
                $id('alerts').addEventListener('click', (e) => {
                    const box = e.target.closest('.new-site-alert');
                    if (!box) return;
                    const alert = this.alerts.find(a => String(a.id) === box.dataset.id);
                    if (!alert) return;
                    if (e.target.closest('.alert-login')) { this.loginToNewSite(alert); return; }
                    if (e.target.closest('.alert-open')) { this.dismissAlert(alert.id); return; } // link navigates itself
                    if (e.target.closest('.new-site-alert-close')) this.dismissAlert(alert.id);
                });

                // Context menu items act on whichever site the menu was opened for.
                const withCtxSite = (fn) => () => {
                    const site = this.ctxMenu.site;
                    this.closeRowMenu();
                    if (site) fn(site);
                };
                $id('ctxOpen').addEventListener('click', withCtxSite(s => this.openSite(s)));
                $id('ctxLogin').addEventListener('click', withCtxSite(s => this.getLoginLink(s.name)));
                $id('ctxRename').addEventListener('click', withCtxSite(s => this.promptRename(s)));
                $id('ctxReveal').addEventListener('click', withCtxSite(s => this.revealSite(s.name)));
                $id('ctxDb').addEventListener('click', withCtxSite(s => this.openSiteDb(s)));
                $id('ctxPhp').addEventListener('click', withCtxSite(s => this.openPhpModal(s)));
                $id('ctxLog').addEventListener('click', withCtxSite(s => this.viewLog(s)));

                // PHP version picker
                $id('btnPhpClose').addEventListener('click', () => this.closePhpModal());
                $id('phpModal').addEventListener('click', (e) => { if (e.target === $id('phpModal')) this.closePhpModal(); });
                $id('phpOptions').addEventListener('click', (e) => {
                    const btn = e.target.closest('.php-option');
                    if (btn && !btn.disabled) this.choosePhp(btn.dataset.version);
                });
                $id('ctxCopy').addEventListener('click', withCtxSite(s => this.copyPath(s.full_path)));
                $id('ctxPin').addEventListener('click', withCtxSite(s => this.togglePin(s.name)));
                $id('ctxDelete').addEventListener('click', withCtxSite(s => this.deleteSite(s.name)));

                // Command palette
                const paletteInput = $id('paletteInput');
                paletteInput.addEventListener('input', () => {
                    this.palette.query = paletteInput.value;
                    this.palette.index = 0;
                    this.renderPalette();
                });
                paletteInput.addEventListener('keydown', (e) => {
                    if (e.key === 'ArrowDown') { e.preventDefault(); this.paletteMove(1); }
                    else if (e.key === 'ArrowUp') { e.preventDefault(); this.paletteMove(-1); }
                    else if (e.key === 'Enter') { e.preventDefault(); this.paletteRun(e); }
                    else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); this.closePalette(); }
                });
                $id('paletteBackdrop').addEventListener('click', (e) => { if (e.target === $id('paletteBackdrop')) this.closePalette(); });
                const paletteList = $id('paletteList');
                paletteList.addEventListener('click', (e) => {
                    const li = e.target.closest('.palette-item');
                    if (li) this.paletteRunItem(this._paletteItems[Number(li.dataset.index)]);
                });
                paletteList.addEventListener('mouseover', (e) => {
                    const li = e.target.closest('.palette-item');
                    if (!li || Number(li.dataset.index) === this.palette.index) return;
                    this.palette.index = Number(li.dataset.index);
                    // Just move the highlight — a full re-render mid-hover would
                    // reset scroll position in the list.
                    paletteList.querySelectorAll('.palette-item').forEach(n =>
                        n.classList.toggle('active', Number(n.dataset.index) === this.palette.index));
                });

                // Rename modal
                const renameInput = $id('renameInput');
                renameInput.addEventListener('input', () => {
                    this.rename.value = renameInput.value;
                    this.renderRename();
                });
                renameInput.addEventListener('keydown', (e) => {
                    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); this.closeRename(); }
                });
                $id('renameForm').addEventListener('submit', (e) => { e.preventDefault(); this.submitRename(); });
                $id('btnRenameCancel').addEventListener('click', () => this.closeRename());
                $id('renameModal').addEventListener('click', (e) => { if (e.target === $id('renameModal')) this.closeRename(); });

                // Log modal
                $id('btnLogRaw').addEventListener('click', () => { this.logView.raw = !this.logView.raw; this.renderLog(); });
                $id('btnLogRefresh').addEventListener('click', () => this.viewLog({ name: this.logView.site }, true));
                $id('btnLogClose').addEventListener('click', () => this.closeLog());
                $id('logModal').addEventListener('click', (e) => { if (e.target === $id('logModal')) this.closeLog(); });

                // Snackbar action (undo etc.)
                $id('snackAction').addEventListener('click', () => { if (this.snackbar.action) this.snackbar.action(); });
            },

            // --- Rendering -------------------------------------------------
            // Everything below reads state and writes DOM. Cheap enough to run
            // wholesale after any state change: a few hundred rows rebuild in
            // low single-digit milliseconds.
            render() {
                this.renderChrome();
                this.renderAlerts();
                this.renderList();
                this.renderFooter();
                this.renderCtxMenu();
                this.renderModals();
                if (this.palette.open) this.renderPalette();
            },

            renderChrome() {
                $id('btnToggleAdd').textContent = this.adding ? 'cancel' : '+ add site';

                // Filter row
                const chip = $id('typeChip');
                show(chip, !!this.typeFilter);
                if (this.typeFilter) $id('typeChipLabel').textContent = this.typeFilterLabel;
                const bulk = $id('btnBulkDelete');
                const visible = this.filteredSites.length;
                show(bulk, (this.filter || this.typeFilter) && visible > 0 && visible < this.sites.length);
                bulk.classList.toggle('armed', this.bulkArmed);
                bulk.textContent = this.bulkArmed ? ('sure? delete ' + visible) : ('delete ' + visible + ' shown');
                show($id('filterKbd'), !this.filter && !this.typeFilter);
                show($id('btnFilterClear'), this.filter || this.typeFilter);

                // Add row
                const addRow = $id('addRow');
                show(addRow, this.adding);
                addRow.classList.toggle('is-creating', this.newSite.isLoading);
                $id('newSiteName').disabled = this.newSite.isLoading;
                $id('newSitePlain').disabled = this.newSite.isLoading;
                const sel = $id('wpVersionSelect');
                show(sel, !this.newSite.isPlain);
                sel.disabled = this.newSite.isLoading || this.newSite.isPlain;
                $id('btnCreate').disabled = !this.newSite.name || this.newSite.isLoading;
                show($id('createSpinner'), this.newSite.isLoading);
                $id('createLabel').textContent = this.newSite.isLoading ? 'creating…' : 'create';

                // Theme button tooltip tracks the mode it would switch to.
                $id('btnTheme').title = this.theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode';
            },

            renderAlerts() {
                const wrap = $id('alerts');
                wrap.querySelectorAll('.new-site-alert').forEach(n => n.remove());
                const tpl = $id('tpl-alert');
                for (const alert of this.alerts) {
                    const node = tpl.content.firstElementChild.cloneNode(true);
                    node.dataset.id = String(alert.id);
                    node.querySelector('strong').textContent = alert.name + '.localhost';
                    const login = node.querySelector('.alert-login');
                    const open = node.querySelector('.alert-open');
                    if (alert.isPlain) {
                        login.remove();
                        open.href = 'https://' + alert.name + '.localhost' + PORT_SUFFIX;
                    } else {
                        open.remove();
                        login.disabled = alert.isLoggingIn;
                        login.textContent = alert.isLoggingIn ? 'opening…' : 'log in to admin';
                    }
                    wrap.appendChild(node);
                }
            },

            renderList() {
                const list = $id('siteList');
                const rows = this.filteredSites;
                list.querySelectorAll('.site-row').forEach(n => n.remove());

                show($id('siteHead'), !this.isLoading && rows.length > 0);
                document.querySelectorAll('.site-head-btn[data-sort]').forEach(btn => {
                    btn.classList.toggle('active', this.sort === btn.dataset.sort);
                    btn.querySelector('.sort-arrow').textContent =
                        this.sort === btn.dataset.sort ? (this.sortDir === 'asc' ? '↑' : '↓') : '';
                });

                show($id('siteLoading'), this.isLoading);
                show($id('emptyNone'), !this.isLoading && this.sites.length === 0);
                const emptyFilter = !this.isLoading && this.sites.length > 0 && rows.length === 0;
                show($id('emptyFilter'), emptyFilter);
                if (emptyFilter) $id('emptyFilterQuery').textContent = this.filter || this.typeFilterLabel;

                const tpl = $id('tpl-site-row');
                const anchor = $id('siteLoading'); // rows insert before the loading li to keep list order
                for (const site of rows) {
                    const row = tpl.content.firstElementChild.cloneNode(true);
                    row.dataset.name = site.name;
                    row.classList.toggle('is-selected', this.selectedName === site.name);
                    row.classList.toggle('has-menu', this.ctxMenu.open && this.ctxMenu.site && this.ctxMenu.site.name === site.name);
                    row.classList.toggle('is-pinned', this.isPinned(site.name));

                    row.querySelector('.site-domain').innerHTML = this.highlightedDomain(site.domain, this.filter);
                    const openLink = row.querySelector('.site-open-link');
                    openLink.href = site.domain;
                    openLink.title = 'Open ' + site.domain.replace('https://', '');

                    const isWp = site.type === 'WordPress';
                    const type = row.querySelector('.site-type');
                    type.classList.add(isWp ? 'wp' : 'static');
                    type.textContent = isWp ? 'WP' : 'STATIC';
                    type.title = 'Filter to ' + (isWp ? 'WordPress' : 'static') + ' sites';

                    const ver = row.querySelector('.site-wp-version');
                    if (site.wp_version) {
                        ver.textContent = site.wp_version;
                        if (site.wp_status) ver.classList.add(site.wp_status);
                        ver.title = site.wp_status === 'insecure'
                            ? 'WordPress ' + site.wp_version + ' — wp.org marks this release insecure. Update with: cove core update ' + site.name
                            : 'WordPress ' + site.wp_version;
                    } else {
                        ver.remove();
                    }

                    const php = row.querySelector('.site-php-version');
                    const applying = this.phpApplying[site.name];
                    if (applying) {
                        php.classList.add('applying');
                        php.textContent = applying === 'default' ? 'php default…' : 'php ' + applying + '…';
                        php.title = 'Switching PHP version…';
                    } else if (site.php_version) {
                        php.textContent = 'php ' + site.php_version;
                        php.title = 'Pinned to PHP ' + site.php_version + ' (native php-fpm). Change via the row menu.';
                    } else {
                        php.remove();
                    }

                    const mod = row.querySelector('.site-modified');
                    mod.textContent = this.formatRelative(site.modified_at);
                    mod.title = site.modified_at ? new Date(site.modified_at * 1000).toLocaleString() : '';
                    row.querySelector('.site-size').textContent = this.formatSize(site.size_bytes);

                    const login = row.querySelector('.site-login-btn');
                    if (isWp) {
                        login.classList.toggle('loading', !!site.isLoggingIn);
                        login.disabled = !!site.isLoggingIn;
                        login.title = 'One-time admin login for ' + site.name;
                    } else {
                        login.remove();
                    }
                    list.insertBefore(row, anchor);
                }
            },

            renderFooter() {
                $id('siteCount').textContent = this.siteCountLabel;
                const totalEl = $id('totalSize');
                show(totalEl, this.totalBytes > 0);
                totalEl.textContent = '· ' + this.formatSize(this.totalBytes);
                $id('btnRefreshSizes').classList.toggle('spinning', this.isRefreshingSizes);
                $id('btnRefreshSizes').disabled = this.isRefreshingSizes;
                $id('btnRefreshSizes').title = this.isRefreshingSizes ? 'Refreshing…' : 'Refresh disk sizes';
            },

            renderCtxMenu() {
                const menu = $id('ctxMenu');
                show(menu, this.ctxMenu.open);
                const site = this.ctxMenu.site;
                if (!this.ctxMenu.open || !site) return;
                menu.style.left = this.ctxMenu.x + 'px';
                menu.style.top = this.ctxMenu.y + 'px';
                $id('ctxTitle').textContent = site.domain.replace('https://', '');
                const isWp = site.type === 'WordPress';
                show($id('ctxLogin'), isWp);
                show($id('ctxDb'), isWp);
                $id('ctxReveal').querySelector('span').textContent = this.revealLabel;
                $id('ctxPin').querySelector('span').textContent = this.isPinned(site.name) ? 'Unpin from top' : 'Pin to top';
                // Effective PHP as the item's meta; hide the item entirely on
                // platforms where per-site pins aren't supported.
                show($id('ctxPhp'), !this.phpInfo || this.phpInfo.supported !== false);
                const effPhp = site.php_version || (this.phpInfo && this.phpInfo.default) || '';
                $id('ctxPhpMeta').textContent = effPhp ? 'php ' + effPhp : '';
            },

            renderPhpModal() {
                show($id('phpModal'), this.phpModal.open);
                if (!this.phpModal.open) return;
                const site = this.phpModal.site;
                $id('phpModalSite').textContent = site.name + '.localhost';
                const wrap = $id('phpOptions');
                wrap.textContent = '';
                const info = this.phpInfo;
                if (!info) {
                    const loading = document.createElement('div');
                    loading.className = 'modal-hint';
                    loading.textContent = 'Loading…';
                    wrap.appendChild(loading);
                    return;
                }
                // The pin may have changed since the menu opened — read the
                // live site entry rather than the captured one.
                const live = this.sites.find(s => s.name === site.name) || site;
                const pin = live.php_version || null;
                const tpl = $id('tpl-php-option');
                const options = [{
                    version: 'default',
                    label: 'default — PHP ' + info.default,
                    meta: pin ? 'FrankenPHP' : 'current · FrankenPHP',
                    installed: true,
                    current: !pin,
                }];
                for (const v of info.versions) {
                    options.push({
                        version: v.version,
                        label: 'PHP ' + v.version,
                        meta: pin === v.version ? 'current · php-fpm'
                            : (v.installed ? 'installed' : 'not installed — click to install'),
                        installed: v.installed,
                        current: pin === v.version,
                    });
                }
                const applying = this.phpApplying[site.name];
                for (const o of options) {
                    const btn = tpl.content.firstElementChild.cloneNode(true);
                    btn.dataset.version = o.version;
                    btn.classList.toggle('current', o.current);
                    btn.classList.toggle('uninstalled', !o.installed);
                    btn.disabled = !!applying || o.current;
                    btn.querySelector('.php-option-name').textContent = o.label;
                    btn.querySelector('.php-option-meta').textContent = o.meta;
                    wrap.appendChild(btn);
                }
                // Only populated when the modal is reopened while a change is
                // still in flight — the normal path closes the modal instantly
                // and shows progress on the row chip instead.
                $id('phpModalHint').textContent = applying
                    ? 'Switching to ' + (applying === 'default' ? 'the default PHP' : 'PHP ' + applying) + '…'
                    : '';
            },

            renderModals() {
                show($id('dbModal'), this.showDbModal);
                show($id('renameModal'), this.rename.open);
                this.renderRename();
                show($id('logModal'), this.logView.open);
                this.renderLog();
                this.renderPhpModal();
            },

            renderRename() {
                if (!this.rename.open) return;
                $id('renameInput').disabled = this.rename.busy;
                $id('renameHint').textContent = this.rename.value ? this.rename.value + '.localhost' : ' ';
                $id('btnRenameCancel').disabled = this.rename.busy;
                const submit = $id('btnRenameSubmit');
                submit.disabled = this.rename.busy || !this.rename.value;
                submit.textContent = this.rename.busy ? 'renaming…' : 'rename';
            },

            renderLog() {
                if (!this.logView.open) return;
                $id('logTitle').textContent = this.logView.site;
                show($id('logTruncated'), this.logView.truncated);
                $id('logPane').textContent = this.logDisplay;
                $id('btnLogRaw').textContent = this.logView.raw ? 'formatted' : 'raw';
                $id('btnLogRefresh').disabled = this.logView.busy;
            },

            renderPalette() {
                const backdrop = $id('paletteBackdrop');
                show(backdrop, this.palette.open);
                if (!this.palette.open) return;
                const items = this.paletteResults;
                this._paletteItems = items;
                const list = $id('paletteList');
                list.innerHTML = '';
                const tpl = $id('tpl-palette-item');
                items.forEach((item, i) => {
                    const li = tpl.content.firstElementChild.cloneNode(true);
                    li.dataset.index = String(i);
                    li.classList.toggle('active', i === this.palette.index);
                    li.querySelector('.pi-kind').textContent = item.kind;
                    li.querySelector('.pi-name').textContent = item.label;
                    li.querySelector('.pi-meta').textContent = item.meta;
                    list.appendChild(li);
                });
                if (!items.length) {
                    const empty = document.createElement('li');
                    empty.className = 'palette-empty';
                    empty.textContent = 'No matches.';
                    list.appendChild(empty);
                }
            },

            renderSnackbar() {
                const bar = $id('snackbar');
                show(bar, this.snackbar.visible);
                bar.classList.toggle('error', this.snackbar.isError);
                $id('snackMsg').textContent = this.snackbar.message;
                const action = $id('snackAction');
                show(action, !!this.snackbar.action);
                action.textContent = this.snackbar.actionLabel;
            },

            // --- Behavior --------------------------------------------------
            applyTheme() {
                document.documentElement.dataset.theme = this.theme;
            },

            toggleTheme() {
                this.theme = this.theme === 'light' ? 'dark' : 'light';
                this.applyTheme();
                localStorage.setItem('theme', this.theme);
                this.renderChrome();
            },

            toggleAdd() {
                this.adding = !this.adding;
                this.render();
                if (this.adding) {
                    this.loadWpVersions();
                    $id('newSiteName').focus();
                }
            },

            // Fetched once per page load, and cached server-side for a day.
            // Deliberately silent on failure: an offline machine should
            // still be able to create a site, it just won't be offered a
            // pinned version alongside 'latest' and 'nightly'.
            async loadWpVersions() {
                if (this.wpVersionsLoaded) return;
                this.wpVersionsLoaded = true;
                try {
                    const res = await fetch('api.php?action=wp_versions');
                    const data = await res.json();
                    if (Array.isArray(data)) {
                        this.wpVersions = data;
                        // 'latest' and 'nightly' are hard-coded first options;
                        // real versions append after them.
                        const sel = $id('wpVersionSelect');
                        for (const v of data) {
                            const opt = document.createElement('option');
                            opt.value = v.version;
                            opt.textContent = v.version + (v.status === 'insecure' ? ' — insecure' : '');
                            sel.appendChild(opt);
                        }
                    }
                } catch (e) { /* offline — 'latest' still works */ }
            },

            formatSize(bytes) {
                if (bytes === null || bytes === undefined) return '—';
                if (bytes === 0) return '0 B';
                const units = ['B', 'KB', 'MB', 'GB', 'TB'];
                const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
                const v = bytes / Math.pow(1024, i);
                return (v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)) + ' ' + units[i];
            },

            formatRelative(ts) {
                if (!ts) return '—';
                const s = Math.max(0, Date.now() / 1000 - ts);
                if (s < 60) return 'now';
                if (s < 3600) return Math.floor(s / 60) + 'm';
                if (s < 86400) return Math.floor(s / 3600) + 'h';
                if (s < 86400 * 30) return Math.floor(s / 86400) + 'd';
                if (s < 86400 * 365) return Math.floor(s / 86400 / 30) + 'mo';
                return Math.floor(s / 86400 / 365) + 'y';
            },

            escapeHtml(s) {
                return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
            },

            // Wrap every case-insensitive occurrence of `query` in <mark> while
            // escaping every other substring. Safe for innerHTML use because the
            // inner text comes from the trusted domain, not from query (query
            // only controls WHERE to split).
            highlightMatch(text, query) {
                const q = (query || '').trim();
                if (!q) return this.escapeHtml(text);
                const lower = text.toLowerCase();
                const lowerQ = q.toLowerCase();
                let out = '';
                let i = 0;
                while (i < text.length) {
                    const idx = lower.indexOf(lowerQ, i);
                    if (idx === -1) { out += this.escapeHtml(text.slice(i)); break; }
                    out += this.escapeHtml(text.slice(i, idx));
                    out += '<mark>' + this.escapeHtml(text.slice(idx, idx + q.length)) + '</mark>';
                    i = idx + q.length;
                }
                return out;
            },

            // Wrap the site name in <span class="host-accent"> so it reads
            // teal while the .localhost suffix stays dim — matches the
            // landing-page dashboard mock. Split at the first dot; if
            // there's none, the whole string is treated as the name.
            highlightedDomain(domain, query) {
                const stripped = String(domain).replace(/^https?:\/\//, '');
                const dotIdx = stripped.indexOf('.');
                if (dotIdx === -1) return '<span class="host-accent">' + this.highlightMatch(stripped, query) + '</span>';
                const name = stripped.slice(0, dotIdx);
                const suffix = stripped.slice(dotIdx);
                return '<span class="host-accent">' + this.highlightMatch(name, query) + '</span>' + this.highlightMatch(suffix, query);
            },

            // --- Command palette -------------------------------------------
            // Results mix matching sites with global commands. Sites are ranked
            // by match position so a prefix hit beats a mid-string one.
            get paletteResults() {
                const q = this.palette.query.trim().toLowerCase();
                const out = [];
                const commands = [
                    { key: 'cmd:add',     kind: 'cmd', label: 'Add site',            meta: '',  run: () => { this.closePalette(); this.toggleAdd(); } },
                    { key: 'cmd:reload',  kind: 'cmd', label: 'Reload server',       meta: '',  run: () => { this.closePalette(); this.reloadServer(); } },
                    { key: 'cmd:sizes',   kind: 'cmd', label: 'Refresh disk sizes',  meta: '',  run: () => { this.closePalette(); this.refreshSizes(); } },
                    { key: 'cmd:db',      kind: 'cmd', label: 'Open database',       meta: '',  run: () => { this.closePalette(); window.open('https://db.cove.localhost' + PORT_SUFFIX, '_blank', 'noopener'); } },
                    { key: 'cmd:mail',    kind: 'cmd', label: 'Open Mailpit',        meta: '',  run: () => { this.closePalette(); window.open(this.mailpitUrl, '_blank', 'noopener'); } },
                    { key: 'cmd:creds',   kind: 'cmd', label: 'Database credentials',meta: '',  run: () => { this.closePalette(); this.setDbModal(true); } },
                    { key: 'cmd:theme',   kind: 'cmd', label: 'Toggle theme',        meta: '',  run: () => { this.closePalette(); this.toggleTheme(); } },
                ];
                let sites = this.sites;
                if (q) {
                    sites = sites
                        .map(s => ({ s, i: s.name.toLowerCase().indexOf(q) }))
                        .filter(x => x.i !== -1)
                        .sort((a, b) => a.i - b.i || a.s.name.localeCompare(b.s.name))
                        .map(x => x.s);
                } else {
                    // No query: show pinned first, then whatever the list is
                    // sorted by, capped so the palette stays a menu not a dump.
                    sites = this.filteredSites;
                }
                for (const site of sites.slice(0, 40)) {
                    out.push({
                        key: 'site:' + site.name,
                        kind: site.type === 'WordPress' ? 'wp' : 'static',
                        label: site.name + '.localhost',
                        meta: this.formatSize(site.size_bytes),
                        site,
                        run: () => { this.closePalette(); this.openSite(site); }
                    });
                }
                for (const c of commands) {
                    if (!q || c.label.toLowerCase().includes(q)) out.push(c);
                }
                return out;
            },

            async reloadServer() {
                this.showSnack('Reloading server…');
                const res = await this.apiPostRetry('reload_server', {}, 3, 10000);
                if (res.success) this.showSnack('Server reloaded.');
            },

            // --- Row actions -----------------------------------------------
            // macOS says "Finder"; everywhere else the file manager has no
            // one name, so stay generic rather than lie about it.
            get revealLabel() {
                return navigator.platform && navigator.platform.startsWith('Mac')
                    ? 'Reveal in Finder' : 'Open folder';
            },

            setDbModal(on) {
                this.showDbModal = on;
                show($id('dbModal'), on);
            },

            promptRename(site) {
                this.rename = { open: true, site, value: site.name, busy: false };
                show($id('renameModal'), true);
                this.renderRename();
                const el = $id('renameInput');
                el.value = site.name;
                el.focus();
                el.select();
            },

            closeRename() {
                this.rename.open = false;
                show($id('renameModal'), false);
            },

            async submitRename() {
                const site = this.rename.site;
                const next = (this.rename.value || '').trim();
                if (!site || !next || next === site.name) { this.closeRename(); return; }
                if (!/^[a-zA-Z0-9-]+$/.test(next)) {
                    this.showSnack('Use letters, numbers and hyphens only.', true);
                    return;
                }
                this.rename.busy = true;
                this.renderRename();
                // Renaming rewrites the Caddyfile, so the response can land
                // mid-reload exactly like a delete does — same retry policy.
                const res = await this.apiPostRetry('rename_site', { site_name: site.name, new_name: next });
                this.rename.busy = false;
                this.renderRename();
                if (!res.success) return;   // apiPost surfaced the reason
                this.closeRename();
                // Carry over UI state that is keyed by name, or a pinned site
                // would silently unpin itself on rename.
                if (this.isPinned(site.name)) {
                    this.pinned = this.pinned.map(n => (n === site.name ? next : n));
                    localStorage.setItem('pinned', JSON.stringify(this.pinned));
                }
                if (this.selectedName === site.name) this.selectedName = next;
                this.showSnack(res.message || 'Renamed.');
                await this.getSites();
            },

            async revealSite(name) {
                const res = await this.apiPost('reveal_site', { site_name: name });
                if (res.success) this.showSnack(res.message || 'Opened in the file manager.');
            },

            openSiteDb(site) {
                // Adminer takes the schema in the query string, so this lands
                // on the site's own tables instead of the server root.
                const url = this.adminerUrl + '/?username=' + encodeURIComponent(DB_USER) +
                            '&db=' + encodeURIComponent(site.db_name || ('cove_' + site.name).replace(/[^a-zA-Z0-9_]/g, '_'));
                window.open(url, '_blank', 'noopener');
            },

            // --- Per-site PHP version ---------------------------------------
            loadPhpInfo(force = false) {
                if (this.phpInfo && !force) return Promise.resolve(this.phpInfo);
                return fetch('api.php?action=php_info')
                    .then(r => r.json())
                    .then(d => { this.phpInfo = d; return d; })
                    .catch(() => null); // offline/mid-reload — the modal shows Loading… until retried
            },

            openPhpModal(site) {
                this.phpModal = { open: true, site };
                this.renderPhpModal();
                // Refresh every open: an install may have finished since the
                // last fetch, flipping a greyed row to clickable.
                this.loadPhpInfo(true).then(() => this.renderPhpModal());
            },

            closePhpModal() {
                this.phpModal.open = false;
                show($id('phpModal'), false);
            },

            async choosePhp(version) {
                const site = this.phpModal.site;
                if (!site || !version || this.phpApplying[site.name]) return;
                // Close immediately and show progress on the row itself — the
                // pulsing chip is the status, not a modal spinner.
                this.closePhpModal();
                this.phpApplying[site.name] = version;
                this.renderList();
                // The server backgrounds the whole change (it reloads the very
                // Caddy serving this dashboard), so this returns immediately
                // and the poll below watches for the pin state to flip.
                const res = await this.apiPostRetry('set_php', { site_name: site.name, php_version: version });
                if (!res.success) {
                    delete this.phpApplying[site.name];
                    this.renderList();
                    return; // apiPost surfaced the reason
                }
                if (!res.applying) {
                    // Idempotent no-op: the site was already on the requested
                    // version (e.g. a retried request that had already landed).
                    delete this.phpApplying[site.name];
                    this.renderList();
                    return;
                }
                if (res.installing) {
                    this.showSnack('Installing PHP ' + version + ' via Homebrew — this can take a few minutes…', false, { duration: 300000 });
                }
                this.startPhpPoll(site.name, version, res.installing ? 15 * 60 * 1000 : 90 * 1000);
            },

            startPhpPoll(name, version, timeoutMs) {
                // The change runs detached server-side; the pin state flipping
                // in list_sites is the completion signal. Polled with a raw
                // fetch, not getSites(), so the visible list does not flash
                // "Loading…" every few seconds — and a fetch that dies against
                // the mid-reload server just polls again.
                if (this.phpInstallPoll) clearInterval(this.phpInstallPoll);
                const started = Date.now();
                const wantPin = version === 'default' ? null : version;
                this.phpInstallPoll = setInterval(async () => {
                    try {
                        const r = await fetch('api.php?action=list_sites');
                        const data = await r.json();
                        const site = data.find(s => s.name === name);
                        if (site && (site.php_version || null) === wantPin) {
                            clearInterval(this.phpInstallPoll);
                            this.phpInstallPoll = null;
                            delete this.phpApplying[name];
                            this.loadPhpInfo(true);
                            await this.getSites();
                            this.showSnack(wantPin
                                ? name + '.localhost is now running PHP ' + version + '.'
                                : name + '.localhost is back on Cove\'s default PHP.');
                        } else if (Date.now() - started > timeoutMs) {
                            clearInterval(this.phpInstallPoll);
                            this.phpInstallPoll = null;
                            delete this.phpApplying[name];
                            this.renderList();
                            this.showSnack('PHP change hasn\'t finished — check ~/Cove/cache/php-apply-' + name + '.log.', true, { duration: 8000 });
                        }
                    } catch (e) { /* mid-reload — keep polling */ }
                }, 3000);
            },

            // Caddy writes one JSON object per line, which is unreadable as a
            // wall of text. Fold each request down to the fields you'd
            // actually scan for — time, status, method, path, duration —
            // and leave anything that isn't a request line untouched.
            get logDisplay() {
                if (this.logView.busy) return 'Loading…';
                const raw = this.logView.text || '';
                if (!raw) return 'No log entries yet.';
                if (this.logView.raw) return raw;
                const out = [];
                for (const line of raw.split('\n')) {
                    const t = line.trim();
                    if (!t) continue;
                    if (t[0] !== '{') { out.push(t); continue; }
                    let o;
                    try { o = JSON.parse(t); } catch (e) { out.push(t); continue; }
                    const req = o.request || {};
                    if (!req.method) { out.push(o.msg ? (o.level || '') + ' ' + o.msg : t); continue; }
                    const time = o.ts ? new Date(o.ts * 1000).toLocaleTimeString() : '';
                    const status = o.status !== undefined ? String(o.status) : '';
                    const dur = typeof o.duration === 'number' ? (o.duration * 1000).toFixed(0) + 'ms' : '';
                    out.push([
                        time,
                        status.padEnd(3),
                        (req.method || '').padEnd(6),
                        req.uri || '',
                        dur
                    ].filter(Boolean).join('  '));
                }
                return out.join('\n') || 'No log entries yet.';
            },

            async viewLog(site, refresh = false) {
                this.logView = { open: true, site: site.name, text: refresh ? this.logView.text : '', truncated: false, busy: true, raw: this.logView.raw };
                show($id('logModal'), true);
                this.renderLog();
                const res = await this.apiPost('site_log', { site_name: site.name });
                this.logView.busy = false;
                if (!res.success) { this.closeLog(); return; }
                this.logView.text = res.log || '';
                this.logView.truncated = !!res.truncated;
                this.renderLog();
                // Logs are read tail-first; jump to the newest lines.
                const el = $id('logPane');
                el.scrollTop = el.scrollHeight;
            },

            closeLog() {
                this.logView.open = false;
                show($id('logModal'), false);
            },

            openPalette() {
                this.palette.open = true;
                this.palette.query = '';
                this.palette.index = 0;
                this.closeRowMenu();
                $id('paletteInput').value = '';
                this.renderPalette();
                $id('paletteInput').focus();
            },

            closePalette() {
                this.palette.open = false;
                show($id('paletteBackdrop'), false);
            },

            paletteMove(delta) {
                const n = this._paletteItems.length;
                if (!n) return;
                this.palette.index = (this.palette.index + delta + n) % n;
                const list = $id('paletteList');
                list.querySelectorAll('.palette-item').forEach(el =>
                    el.classList.toggle('active', Number(el.dataset.index) === this.palette.index));
                const el = list.children[this.palette.index];
                if (el && el.scrollIntoView) el.scrollIntoView({ block: 'nearest' });
            },

            paletteRun(event) {
                const item = this._paletteItems[this.palette.index];
                if (!item) return;
                // Cmd/Ctrl+Enter logs into a WordPress site instead of opening it.
                if (event && (event.metaKey || event.ctrlKey) && item.site && item.site.type === 'WordPress') {
                    this.closePalette();
                    this.getLoginLink(item.site.name);
                    return;
                }
                item.run();
            },

            paletteRunItem(item) { if (item) item.run(); },

            // --- Row context menu ------------------------------------------
            openRowMenu(site, event) {
                // Show first, then clamp using the menu's real size — the item
                // set varies by site type, so a guessed height either wastes
                // margin or lets the bottom items land off-screen.
                this.ctxMenu = { open: true, site, x: event.clientX, y: event.clientY, openedAt: event.timeStamp };
                this.renderCtxMenu();
                const rect = $id('ctxMenu').getBoundingClientRect();
                this.ctxMenu.x = Math.max(8, Math.min(event.clientX, window.innerWidth - rect.width - 8));
                this.ctxMenu.y = Math.max(8, Math.min(event.clientY, window.innerHeight - rect.height - 8));
                this.renderCtxMenu();
                this.renderList(); // row highlight
            },

            closeRowMenu() {
                if (!this.ctxMenu.open) return;
                this.ctxMenu.open = false;
                show($id('ctxMenu'), false);
                this.renderList();
            },

            // --- Pinning ---------------------------------------------------
            isPinned(name) { return this.pinned.includes(name); },

            togglePin(name) {
                if (this.isPinned(name)) {
                    this.pinned = this.pinned.filter(n => n !== name);
                } else {
                    this.pinned = [...this.pinned, name];
                }
                localStorage.setItem('pinned', JSON.stringify(this.pinned));
                this.render();
            },

            // --- Keyboard list navigation ----------------------------------
            moveSelection(delta) {
                const list = this.filteredSites;
                if (!list.length) return;
                const cur = list.findIndex(s => s.name === this.selectedName);
                let next = cur === -1 ? (delta > 0 ? 0 : list.length - 1) : cur + delta;
                next = Math.max(0, Math.min(list.length - 1, next));
                this.selectedName = list[next].name;
                this.renderList();
                const el = document.querySelectorAll('.site-row')[next];
                if (el && el.scrollIntoView) el.scrollIntoView({ block: 'nearest' });
            },

            selectedSite() {
                return this.filteredSites.find(s => s.name === this.selectedName) || null;
            },

            setSort(key) {
                // Click the active header to flip direction; a new key
                // starts at its natural default (a→z for name, biggest /
                // most recent first for size and modified).
                if (this.sort === key) {
                    this.sortDir = this.sortDir === 'asc' ? 'desc' : 'asc';
                } else {
                    this.sort = key;
                    this.sortDir = key === 'name' ? 'asc' : 'desc';
                }
                localStorage.setItem('sort', this.sort);
                localStorage.setItem('sortDir', this.sortDir);
                this.render();
            },

            openSite(site) {
                // Don't navigate when the click was part of a drag-to-select,
                // so users can still grab the domain/size text to copy.
                if (window.getSelection && window.getSelection().toString()) return;
                window.open(site.domain, '_blank', 'noopener');
            },

            showSnack(msg, isError = false, opts = {}) {
                if (this.snackbar.timer) clearTimeout(this.snackbar.timer);
                this.snackbar = {
                    visible: true, message: msg, isError, timer: null,
                    action: opts.action || null,
                    actionLabel: opts.actionLabel || ''
                };
                this.snackbar.timer = setTimeout(() => { this.snackbar.visible = false; this.renderSnackbar(); }, opts.duration || 3500);
                this.renderSnackbar();
            },

            async apiPost(action, payload = {}, opts = {}) {
                const { timeoutMs = 0, quiet = false } = opts;
                const ctrl = timeoutMs ? new AbortController() : null;
                const timer = ctrl ? setTimeout(() => ctrl.abort(), timeoutMs) : null;
                try {
                    const res = await fetch('api.php', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ action, ...payload }),
                        ...(ctrl ? { signal: ctrl.signal } : {})
                    }).then(r => r.json());
                    if (!res.success && !quiet) this.showSnack(res.message || 'An error occurred.', true);
                    return res;
                } catch (e) {
                    // transport marks network-level failures (connection
                    // dropped, timeout) as distinct from server-reported
                    // errors — only these are worth retrying.
                    if (!quiet) this.showSnack('Network error.', true);
                    return { success: false, transport: true };
                } finally {
                    if (timer) clearTimeout(timer);
                }
            },

            async apiPostRetry(action, payload = {}, attempts = 3, timeoutMs = 30000) {
                // The Caddy/FrankenPHP reload the dashboard triggers after
                // add/delete can momentarily drop or hang requests to the
                // dashboard itself. Retry transport failures a few times so
                // an action that lands mid-reload isn't silently lost.
                let res;
                for (let i = 1; i <= attempts; i++) {
                    res = await this.apiPost(action, payload, { timeoutMs, quiet: i < attempts });
                    if (res.success || !res.transport) return res;
                    if (i < attempts) await new Promise(r => setTimeout(r, 3000));
                }
                return res;
            },

            async getSites() {
                this.isLoading = true;
                this.render();
                try {
                    const r = await fetch('api.php?action=list_sites');
                    const data = await r.json();
                    // Sites staged for deletion are still on disk (nothing
                    // is sent to the backend until the undo window closes),
                    // so a refresh landing mid-window would re-add the rows
                    // the user just deleted — and undo would then push a
                    // second copy of the same row.
                    const staged = new Set(this.pendingDelete ? this.pendingDelete.sites.map(s => s.name) : []);
                    this.sites = data
                        .map(s => ({ ...s, isLoggingIn: false }))
                        .filter(s => !staged.has(s.name));
                } catch (e) {
                    this.showSnack('Could not fetch sites.', true);
                } finally {
                    this.isLoading = false;
                    this.render();
                }
            },

            async addSite() {
                if (!this.newSite.name) return;
                this.newSite.isLoading = true;
                this.render();
                const name = this.newSite.name;
                const isPlain = this.newSite.isPlain;
                // 'latest' is the server's default, so it's sent as nothing
                // at all — keeps the generated command identical to what a
                // plain `cove add <name>` produces.
                const wpVersion = isPlain ? '' : this.newSite.wpVersion;

                const add = await this.apiPost('add_site', { site_name: name, is_plain: isPlain, wp_version: (wpVersion && wpVersion !== 'latest') ? wpVersion : undefined });
                if (add.success) {
                    // Optimistic insert: we already know every field the row
                    // template uses. No auto-refresh — the Caddy reload that
                    // follows can take tens of seconds on fleets with lots of
                    // sites and would either hang the fetch or drop the UI
                    // into an ERR_CONNECTION_REFUSED during the config swap.
                    this.sites.push({
                        name,
                        domain: 'https://' + name + '.localhost' + PORT_SUFFIX,
                        type: isPlain ? 'Plain' : 'WordPress',
                        display_path: '~/Cove/Sites/' + name + '.localhost',
                        full_path: SITES_DIR + '/' + name + '.localhost',
                        // Server calculates size in add_site and returns it
                        // alongside success. Fall back to null so the row
                        // shows "—" until the next refresh if anything failed.
                        size_bytes: (typeof add.size_bytes === 'number') ? add.size_bytes : null,
                        modified_at: Math.floor(Date.now() / 1000),
                        isLoggingIn: false,
                    });
                    this.showSnack('Site created.');
                    this.newSite.name = '';
                    $id('newSiteName').value = '';
                    this.newSite.wpVersion = 'latest';
                    $id('wpVersionSelect').value = 'latest';
                    this.adding = false;
                    this.apiPost('reload_server'); // fire and forget — Caddy reloads in the background

                    // Surface a persistent alert so the user can jump
                    // straight into the new site without hunting for the
                    // row. WP sites get a one-time admin login; plain
                    // sites get a simple "open site" link.
                    this.alerts.push({
                        id: Date.now() + Math.random(),
                        name,
                        isPlain,
                        isLoggingIn: false,
                    });
                }
                this.newSite.isLoading = false;
                this.render();
            },

            async loginToNewSite(alert) {
                alert.isLoggingIn = true;
                this.renderAlerts();
                const res = await this.apiPost('get_login_link', { site_name: alert.name });
                if (res.success && res.url) {
                    window.open(res.url, '_blank');
                    // Acted on — banner's job is done. The new tab has the
                    // one-time URL; dashboard can drop the prompt.
                    this.dismissAlert(alert.id);
                }
                alert.isLoggingIn = false;
                this.renderAlerts();
            },

            dismissAlert(id) {
                this.alerts = this.alerts.filter(a => a.id !== id);
                this.renderAlerts();
            },

            deleteSite(name) {
                const site = this.sites.find(s => s.name === name);
                if (!site) return;
                this.stageDeletes([site]);
            },

            bulkDelete() {
                // Two-step inline confirm: first click arms the button for a
                // few seconds, second click stages every filtered site. The
                // undo snackbar is the safety net after that.
                if (!this.bulkArmed) {
                    this.bulkArmed = true;
                    this.bulkArmTimer = setTimeout(() => { this.bulkArmed = false; this.renderChrome(); }, 3500);
                    this.renderChrome();
                    return;
                }
                clearTimeout(this.bulkArmTimer);
                this.bulkArmed = false;
                this.stageDeletes([...this.filteredSites]);
            },

            stageDeletes(sitesToDelete) {
                // Pull the rows from the list immediately (the UI feels
                // instant) but hold the backend work for an undo window.
                // Nothing is deleted server-side until the window passes.
                if (this.pendingDelete) clearTimeout(this.pendingDelete.timer);
                const staged = this.pendingDelete ? this.pendingDelete.sites : [];
                for (const site of sitesToDelete) {
                    const idx = this.sites.findIndex(s => s.name === site.name);
                    if (idx !== -1) { this.sites.splice(idx, 1); staged.push(site); }
                }
                if (!staged.length) { this.pendingDelete = null; this.render(); return; }
                this.pendingDelete = {
                    sites: staged,
                    timer: setTimeout(() => this.commitPendingDeletes(), 5000)
                };
                this.render();
                const label = staged.length === 1
                    ? 'Deleted ' + staged[0].name + '.'
                    : 'Deleted ' + staged.length + ' sites.';
                this.showSnack(label, false, {
                    actionLabel: 'undo',
                    action: () => this.undoPendingDeletes(),
                    duration: 5000
                });
            },

            commitPendingDeletes() {
                if (!this.pendingDelete) return;
                const names = this.pendingDelete.sites.map(s => s.name);
                this.pendingDelete = null;
                // processDeleteQueue drains the queue single-file so
                // concurrent deletes don't race on shared state (Caddyfile
                // regeneration, /etc/hosts edits).
                this.deleteQueue.push(...names);
                this.processDeleteQueue();
            },

            undoPendingDeletes() {
                if (!this.pendingDelete) return;
                clearTimeout(this.pendingDelete.timer);
                // renderList re-sorts, so push order is fine.
                this.sites.push(...this.pendingDelete.sites);
                this.pendingDelete = null;
                if (this.snackbar.timer) clearTimeout(this.snackbar.timer);
                this.snackbar.visible = false;
                this.render();
                this.renderSnackbar();
            },

            async processDeleteQueue() {
                // Single-flight runner: whichever call picks up the lock drains the
                // full queue. Concurrent deleteSite() calls just enqueue and return.
                if (this.isProcessingQueue) return;
                this.isProcessingQueue = true;

                let anyFailed = false;
                try {
                    // Outer loop catches deletes queued while we were awaiting the
                    // reload below — otherwise they'd sit forever because the next
                    // deleteSite() call short-circuits on isProcessingQueue.
                    while (this.deleteQueue.length > 0) {
                        while (this.deleteQueue.length > 0) {
                            const target = this.deleteQueue.shift();
                            const del = await this.apiPostRetry('delete_site', { site_name: target });
                            if (del.success) {
                                // Don't stomp a newer batch's undo snackbar
                                // with a routine confirmation.
                                if (!this.pendingDelete) this.showSnack('Site deleted.');
                            } else {
                                anyFailed = true; // apiPost already surfaced the error
                            }
                        }
                        // Kick a reload at the end of the batch. Race-safety
                        // lives server-side: cove_reload() uses a mkdir lock
                        // with a pending marker to coalesce concurrent calls,
                        // since reload_server itself backgrounds the shell
                        // command (shell_exec '...&') and returns instantly.
                        // Two unsynchronized frankenphp reload calls otherwise
                        // deadlock Caddy's admin server (10s shutdown timeout).
                        await this.apiPostRetry('reload_server', {}, 3, 10000);
                    }
                } finally {
                    this.isProcessingQueue = false;
                }

                // If anything failed mid-queue the optimistic UI is now out of sync
                // with the backend (e.g. a survivor is missing from our list).
                // Cheapest correct fix: re-fetch the authoritative list.
                if (anyFailed) await this.getSites();
            },

            async getLoginLink(name) {
                const site = this.sites.find(s => s.name === name);
                if (!site) return;
                site.isLoggingIn = true;
                this.renderList();
                const res = await this.apiPost('get_login_link', { site_name: name });
                if (res.success && res.url) {
                    window.open(res.url, '_blank');
                    this.showSnack('Login link opened in a new tab.');
                }
                site.isLoggingIn = false;
                this.renderList();
            },

            async copyPath(path) {
                try {
                    await navigator.clipboard.writeText(path);
                    this.showSnack('Path copied to clipboard.');
                } catch (e) {
                    this.showSnack('Could not copy path.', true);
                }
            },

            async refreshSizes() {
                this.isRefreshingSizes = true;
                this.renderFooter();
                const res = await this.apiPost('refresh_sizes');
                if (res.success) {
                    await this.getSites();
                    this.showSnack('Disk sizes updated.');
                }
                this.isRefreshingSizes = false;
                this.renderFooter();
            }
        };

        // The script sits at the end of <body>, so the DOM is already parsed.
        app.init();
    </script>
</body>
</html>
EOM

    # Find the absolute path to this script to pass to the GUI
    local script_dir
    script_dir=$(cd "$(dirname "$0")" && pwd)
    local absolute_script_path="$script_dir/$(basename "$0")"
    
    # Escape the paths for use in `sed`
    local escaped_path
    escaped_path=$(printf '%s\n' "$absolute_script_path" | sed -e 's/[\/&]/\\&/g')
    local escaped_sites_dir
    escaped_sites_dir=$(printf '%s\n' "$SITES_DIR" | sed -e 's/[\/&]/\\&/g')
    local escaped_home
    escaped_home=$(printf '%s\n' "$HOME" | sed -e 's/[\/&]/\\&/g')
    
    # Substitute placeholders in both api.php and index.php
    sed -e "s/COVE_EXECUTABLE_PATH_PLACEHOLDER/${escaped_path}/g" \
        -e "s/SITES_DIR_PLACEHOLDER/${escaped_sites_dir}/g" \
        -e "s/USER_HOME_PLACEHOLDER/${escaped_home}/g" \
        "$GUI_DIR/api.php.tmp" > "$GUI_DIR/api.php"

    sed -e "s/SITES_DIR_PLACEHOLDER/${escaped_sites_dir}/g" \
        "$GUI_DIR/index.php.tmp" > "$GUI_DIR/index.php"
        
    # Clean up temp files
    rm "$GUI_DIR/api.php.tmp" "$GUI_DIR/index.php.tmp"
}

# --- Help Functions ---
show_general_help() {
    echo "Cove - A tool for managing local development sites."
    echo ""
    echo "Usage: cove <command> [options]"
    echo ""
    echo "For help with a specific command, run: cove <command> --help"
    echo ""
    echo "Available Commands:"
    echo "  install          Installs and configures Homebrew dependencies."
    echo "  enable           Starts the Caddy, MariaDB, and Mailpit background services."
    echo "  disable          Stops all background services managed by Cove."
    echo "  status           Check the status of all background services."
    echo "  health           Diagnose crashes, OPcache pressure, and on-disk hygiene."
    echo "  transfer         Inspect the backup/restore engine used by pull and push."
    echo "  trust            Install Cove's local CA into browser + system trust stores."
    echo "  list             Lists all sites currently managed by Cove."
    echo "  add              Creates a new WordPress or plain static site."
    echo "  clone            Copies an existing site, database and all, under a new name."
    echo "  core             Report or update the WordPress version of your sites."
    echo "  delete           Deletes a site's directory and associated database."
    echo "  login            Generates a one-time login link for a WordPress site."
    echo "  rename           Renames a site, its directory, and database."
    echo "  path             Outputs the full path to a site's directory."
    echo "  pull             Pulls a remote WordPress site into Cove via SSH."
    echo "  push             Pushes a local Cove site to a remote WordPress site via SSH."
    echo "  directive        Add or remove custom Caddyfile rules for a site."
    echo "  proxy            Manage standalone reverse proxy entries."
    echo "  tailscale        Expose all sites to your Tailscale network."
    if [ "$OS" == "macos" ]; then
        echo "  menubar          Manage the macOS menu bar companion app."
    fi
    echo "  db               Manage databases (e.g., 'cove db backup')."
    echo "  lan              Enable LAN access to sites for mobile app sync."
    echo "  ports            Reconfigure HTTP/HTTPS ports + update site URLs."
    echo "  memory           Show or raise PHP memory_limit across Cove + Homebrew PHPs."
    echo "  php              Pin a site to an older PHP (native php-fpm behind FrankenPHP)."
    echo "  log              View logs for a site or the global error log."
    echo "  share            Create a temporary public tunnel to share a site."
    if [ "$IS_WSL" = true ]; then
        echo "  wsl-hosts        Show Windows hosts file update commands."
    fi
    echo "  reload           Regenerates the Caddyfile and reloads the Caddy server."
    echo "  url              Prints the HTTPS URL for a given site."
    echo "  upgrade          Upgrades Cove to the latest available version."
    echo "  version          Displays the current version of Cove."
}

display_command_help() {
    local cmd="$1"
    case "$cmd" in
        install)
            echo "Usage: cove install [--yes] [--http PORT] [--https PORT]"
            echo "                    [--db-root-user USER] [--db-root-pass PASS]"
            echo ""
            echo "Installs and configures Homebrew dependencies like Caddy, MariaDB, and Mailpit."
            echo "It also sets up the required directory structure inside '~/Cove'."
            echo ""
            echo "Options:"
            echo "  --yes, -y, --force   Skip confirmation prompts for scripted installs."
            echo "                       Auto-enabled when stdin is not a TTY."
            echo "  --http PORT          Set the HTTP port outright, skipping the port menus."
            echo "  --https PORT         Set the HTTPS port outright, skipping the port menus."
            echo "                       Without these, a scripted install keeps the configured"
            echo "                       ports and reports (rather than prompts on) a conflict."
            echo "  --db-root-user USER  MariaDB root user, used only if automatic database setup"
            echo "  --db-root-pass PASS  fails. Without them that fallback needs a terminal."
            ;;
        enable)
            echo "Usage: cove enable"
            echo ""
            echo "Starts the Caddy, MariaDB, and Mailpit background services."
            ;;
        disable)
            echo "Usage: cove disable"
            echo ""
            echo "Stops all background services managed by Cove."
            ;;
        status)
            echo "Usage: cove status [--porcelain]"
            echo ""
            echo "Checks the status of all background services."
            echo ""
            echo "Options:"
            echo "  --porcelain    Stable machine-readable output (key=value per line),"
            echo "                 as consumed by the menu bar app."
            ;;
        health)
            echo "Usage: cove health"
            echo ""
            echo "Read-only diagnostic. Reports service liveness, the FrankenPHP"
            echo "process state and last exit code, recent hard segfaults"
            echo "(classified as OPcache vs Imagick vs other), live OPcache"
            echo "pressure, and on-disk hygiene (zombie site dirs, oversized"
            echo "logs). Recommends fixes but changes nothing."
            ;;
        transfer)
            echo "Usage: cove transfer probe [site]"
            echo ""
            echo "Reports which tools the backup/restore engine behind 'cove pull' and"
            echo "'cove push' will use here. Cove implements backup and restore itself"
            echo "rather than fetching an external script, and degrades gracefully:"
            echo "archiving prefers zip, then tar, then PHP; the database is dumped and"
            echo "imported with mysqldump/mysql when present and through WordPress's own"
            echo "\$wpdb when not. Since the target is always a WordPress install, PHP is"
            echo "guaranteed — so a host with none of zip, unzip, tar, or a MySQL client"
            echo "still transfers, just more slowly. Missing tools are installed when the"
            echo "host allows it, and a remote with no WP-CLI gets wp-cli.phar sideloaded"
            echo "over SSH."
            ;;
        trust)
            echo "Usage: cove trust"
            echo ""
            echo "Installs Cove's local root certificate into the system trust store"
            echo "and browser NSS databases (Firefox, Chromium — including snap)."
            echo "Run once after install; re-run anytime to refresh."
            ;;
        list)
            echo "Usage: cove list [--totals]"
            echo ""
            echo "Lists all sites currently managed by Cove, showing their domain and type (WordPress/Plain)."
            echo ""
            echo "Flags:"
            echo "  --totals       Calculates and displays the size of each site's public directory."
            ;;
        add)
            echo "Usage: cove add <name> [flavor]"
            echo ""
            echo "Creates a new local site accessible at 'https://<name>.localhost'."
            echo ""
            echo "Arguments:"
            echo "  <name>         The name for the new site. Becomes the subdomain."
            echo "  [flavor]       What goes inside the site. Defaults to the latest WordPress."
            echo "                   <version>  A WordPress version: 6.4, 6.4.3, or 6.9-RC1."
            echo "                   nightly    WordPress trunk, rebuilt daily."
            echo "                   latest     The newest WordPress release (the default)."
            echo "                   plain      A static HTML site with no database."
            echo ""
            echo "Flags:"
            echo "  --plain        Alias for the 'plain' flavor."
            echo "  --php=<ver>    Pin the site to an older PHP (see 'cove php')."
            echo "  --multisite    Install a WordPress multisite network (subdirectory"
            echo "                 mode: <name>.localhost/store/). Use --multisite=subdomain"
            echo "                 for subdomain mode (store.<name>.localhost) — subsites"
            echo "                 resolve and get HTTPS automatically, no extra setup."
            echo ""
            echo "Examples:"
            echo "  cove add mysite                        Latest WordPress."
            echo "  cove add mysite 6.4.3                  WordPress pinned to 6.4.3."
            echo "  cove add mysite nightly                WordPress trunk."
            echo "  cove add mysite plain                  Static site, no database."
            echo "  cove add mysite --multisite            Subdirectory multisite network."
            echo "  cove add mysite --multisite=subdomain  Subdomain multisite network."
            ;;
        clone)
            echo "Usage: cove clone <source> <new-name>"
            echo ""
            echo "Copies an existing site to a new one — files, database, and custom"
            echo "Caddy directives — rewriting the site URL to the new hostname."
            echo ""
            echo "Seed a site once (WooCommerce, users, sample content) and stamp copies"
            echo "of it instead of building the same fixture over and over."
            echo ""
            echo "Arguments:"
            echo "  <source>       The existing site to copy."
            echo "  <new-name>     Name for the copy. Becomes the subdomain."
            echo ""
            echo "Notes:"
            echo "  Admin credentials are inherited from the source site."
            echo "  On APFS and btrfs the file copy is copy-on-write, so it is fast and"
            echo "  the two copies share disk until one is written to."
            echo ""
            echo "Example:"
            echo "  cove clone woo-template poc-acme"
            ;;
        core)
            echo "Usage: cove core <check|update> [options]"
            echo ""
            echo "Reports and updates the WordPress version installed on your sites."
            echo "Distinct from 'cove upgrade', which upgrades Cove itself."
            echo ""
            echo "Subcommands:"
            echo "  check                        Show every site's WordPress version, flagging"
            echo "                               releases wp.org marks outdated or insecure."
            echo "  update <site> [version]      Update one site to the latest release, or to a"
            echo "                               specific version (which may be a downgrade)."
            echo "  update --all                 Update every site that is behind."
            echo ""
            echo "Flags:"
            echo "  --all          Apply to every WordPress site."
            echo "  --dry-run      List what would change without touching anything."
            echo "  --yes, -y      Skip the confirmation prompt."
            echo ""
            echo "Examples:"
            echo "  cove core check"
            echo "  cove core update mysite"
            echo "  cove core update mysite 6.4.3"
            echo "  cove core update --all --dry-run"
            ;;
        delete)
            echo "Usage: cove delete <name> [--force]"
            echo ""
            echo "Deletes a site's directory and associated WordPress database."
            echo ""
            echo "Arguments:"
            echo "  <name>         The name of the site to delete."
            echo ""
            echo "Flags:"
            echo "  --force        Deletes a site without the interactive confirmation prompt."
            ;;
        rename)
            echo "Usage: cove rename <old-name> <new-name>"
            echo ""
            echo "Renames an existing local site."
            echo "This command will rename the site's directory, update its database name and"
            echo "contents for WordPress sites, and regenerate the server configuration."
            echo ""
            echo "Arguments:"
            echo "  <old-name>     The current name of the site to rename."
            echo "  <new-name>     The new name for the site."
            ;;
        directive)
            echo "Usage: cove directive <subcommand>"
            echo ""
            echo "Add or remove custom Caddyfile rules for a site."
            echo "Opens an editor to add/edit rules which are then included in the main Caddyfile."
            echo
            echo "Subcommands:"
            echo "  add                 Adds a rule to the Caddyfile for the specified site."
            echo "  update              Updates a rule in the Caddyfile for the specified site."
            echo "  delete <name>       Deletes custom rules from the Caddyfile for the specified site."
            echo "  list                Lists all custom directives for all managed sites."
            echo ""
            echo "Flags:"
            echo "  --rules \"...\"       Directives as a string, instead of opening the editor."
            echo "  --file <path>       Read directives from a file instead of the editor."
            echo "  --force             Skip confirmation prompt (delete only)."
            echo ""
            echo "Without --rules/--file, add/update opens an editor on a TTY and otherwise"
            echo "reads from stdin, so this also works:"
            echo "  cat rules.conf | cove directive add mysite"
            ;;
        proxy)
            echo "Usage: cove proxy <subcommand>"
            echo ""
            echo "Manage standalone reverse proxy entries in the Caddyfile."
            echo "These are top-level server blocks, useful for exposing local services"
            echo "via Tailscale or other external domains."
            echo ""
            echo "Subcommands:"
            echo "  add <name> <domain> <target>   Add a new reverse proxy entry"
            echo "  list                           List all proxy entries"
            echo "  delete <name>                  Delete a proxy entry"
            echo ""
            echo "Options:"
            echo "  --no-tls     Disable TLS for this proxy (default uses internal TLS)"
            echo "  --force      Skip confirmation prompts (add overwrite, delete)"
            echo ""
            echo "Examples:"
            echo "  cove proxy add opencode myhost.tailnet.ts.net 127.0.0.1:4096"
            echo "  cove proxy add api api.example.com localhost:3000 --force"
            echo "  cove proxy list"
            echo "  cove proxy delete opencode --force"
            ;;
        tailscale)
            echo "Usage: cove tailscale <subcommand>"
            echo ""
            echo "Expose all Cove sites to your Tailscale network."
            echo "This allows devices on your Tailnet (like your iPhone) to access"
            echo "your local development sites via their Tailscale hostname."
            echo ""
            echo "Subcommands:"
            echo "  enable [hostname]    Enable Tailscale access (auto-detects if omitted)"
            echo "  disable              Disable Tailscale access"
            echo "  status               Show current Tailscale configuration"
            echo ""
            echo "After enabling, your sites will be accessible at:"
            echo "  https://<site>.<your-tailscale-hostname>"
            echo ""
            echo "Examples:"
            echo "  cove tailscale enable"
            echo "  cove tailscale enable mycomputer.tail1234.ts.net"
            echo "  cove tailscale status"
            ;;
        menubar)
            echo "Usage: cove menubar <subcommand>"
            echo ""
            echo "Manage the native macOS menu bar companion app."
            echo "The menu bar icon shows Cove's status at a glance and can start/stop"
            echo "services and open the Dashboard, Adminer, Mailpit, and logs."
            echo ""
            echo "Subcommands:"
            echo "  enable     Build, install, and launch the menu bar app (also updates it)"
            echo "  disable    Quit and remove the menu bar app"
            echo ""
            echo "The app is built locally (requires Apple Command Line Tools) and is"
            echo "strictly opt-in — once enabled, 'cove upgrade' keeps it up to date."
            echo ""
            echo "Examples:"
            echo "  cove menubar enable"
            echo "  cove menubar disable"
            ;;
        db)
            echo "Usage: cove db <subcommand>"
            echo ""
            echo "Manage databases."
            echo ""
            echo "Subcommands:"
            echo "  backup             Creates a .sql dump for each WP site."
            echo "  list               Lists database connection details for each WP site."
            echo "  fix-collation      Converts tables stamped with MariaDB 11.5+'s uca1400"
            echo "                     collations back to utf8mb4_unicode_ci so dumps import"
            echo "                     on older MariaDB / MySQL hosts."
            echo ""
            echo "Usage: cove db fix-collation <site> | --all [--dry-run]"
            ;;
        login)
            echo "Usage: cove login <site> [<user>]"
            echo ""
            echo "Generates a one-time login link for a WordPress site."
            echo "If no user is specified, it defaults to the first available administrator."
            echo ""
            echo "Arguments:"
            echo "  <site>         The name of the WordPress site."
            echo "  <user>         (Optional) The user ID, email, or login of the admin to use."
            ;;
        mappings)
            echo "Usage: cove mappings <site> [add|remove] [domain]"
            echo ""
            echo "Manage additional domain mappings for a site."
            echo "Mappings allow a single site to be served from multiple domains."
            ;;
        lan)
            echo "Usage: cove lan <subcommand>"
            echo ""
            echo "Enable LAN access to Cove sites for mobile app sync."
            echo "This allows devices on your local network to connect to your sites."
            echo ""
            echo "Subcommands:"
            echo "  enable <site>    Enable LAN access for a site (assigns a port, starts Bonjour)"
            echo "  disable <site>   Disable LAN access for a site"
            echo "  status           Show which sites have LAN access enabled"
            echo "  trust            Instructions for trusting Caddy's CA on mobile devices"
            ;;
        ports)
            echo "Usage: cove ports [options]"
            echo ""
            echo "Reconfigure the HTTP/HTTPS ports Cove listens on."
            echo ""
            echo "By default, asks once to migrate every WordPress site's stored URLs"
            echo "(siteurl, home, and serialized content) via 'wp search-replace' so"
            echo "existing sites keep working on the new port. Handles custom mappings"
            echo "and skips non-WordPress sites automatically."
            echo ""
            echo "Run with no arguments for an interactive menu, or pass --http / --https"
            echo "for scripted use."
            echo ""
            echo "Options:"
            echo "  --http PORT     Non-interactive: set HTTP port"
            echo "  --https PORT    Non-interactive: set HTTPS port"
            echo "  --skip-urls     Change ports without touching WordPress databases"
            echo "  --dry-run       Preview changes (including replacement counts)"
            echo "                  without committing anything"
            echo ""
            echo "Examples:"
            echo "  cove ports                          Interactive menu"
            echo "  cove ports --http 8090 --https 8453 Set ports non-interactively"
            echo "  cove ports --dry-run                Preview the effect of a port change"
            echo ""
            echo "Tip: run 'cove db backup' first if you want a safety net before the DB update."
            ;;
        memory)
            echo "Usage: cove memory [set <value>] [--yes]"
            echo ""
            echo "Show or raise PHP memory_limit across every ini that affects Cove and"
            echo "the wp-cli on your PATH. With no arguments, prints a report covering:"
            echo ""
            echo "  • Cove's own CLI ini (~/Cove/php.ini), read by FrankenPHP"
            echo "  • The memory_limit baked into the Caddyfile's frankenphp block"
            echo "  • Every 'php' binary on PATH (version + loaded php.ini + memory_limit)"
            echo "  • wp-cli's effective PHP binary and its memory_limit"
            echo ""
            echo "With 'set <value>', writes memory_limit / upload_max_filesize /"
            echo "post_max_size into ~/Cove/php.ini, regenerates the Caddyfile so the"
            echo "FrankenPHP web server picks up the new values, and offers to update"
            echo "each external php.ini it finds on PATH (per-file confirmation)."
            echo ""
            echo "Values accept standard PHP shorthand: 512M, 2G, -1 for unlimited."
            echo ""
            echo "Flags:"
            echo "  --yes, -y    Update every writable ini without per-file confirmation."
            echo ""
            echo "Examples:"
            echo "  cove memory              Audit current limits"
            echo "  cove memory set 2G       Bump Cove + offer to bump Homebrew PHPs"
            echo "  cove memory set 2G --yes Bump Cove + every writable ini (non-interactive)"
            echo "  cove memory set -1       Unlimited (use sparingly)"
            ;;
        php)
            echo "Usage: cove php [<site>] [<version>|default]"
            echo ""
            echo "Per-site PHP version switching. FrankenPHP (bundling the latest PHP)"
            echo "serves every site by default; pinning a site routes its PHP through a"
            echo "native Homebrew php-fpm (php@<version>) behind Caddy via php_fastcgi."
            echo "TLS, logs, mappings, and custom directives are unaffected."
            echo ""
            echo "Commands:"
            echo "  cove php                 Overview: every site's effective PHP + services."
            echo "  cove php <site>          Show the site's effective PHP version."
            echo "  cove php <site> 8.2      Pin the site to PHP 8.2 (installs php@8.2 if needed)."
            echo "  cove php <site> default  Unpin — back to FrankenPHP's bundled PHP."
            echo ""
            echo "The pin is stored in the site's 'php_version' file and travels with the"
            echo "site through clone and rename. wp-cli commands for a pinned site run"
            echo "under the same native PHP. Requires Homebrew on macOS."
            ;;
        log)
            echo "Usage: cove log [site] [--follow]"
            echo ""
            echo "View logs for a site or the global error log."
            echo ""
            echo "Arguments:"
            echo "  [site]           The site name (optional). If omitted, shows global error log."
            echo ""
            echo "Options:"
            echo "  -f, --follow     Continuously follow log output (like tail -f)"
            echo ""
            echo "Examples:"
            echo "  cove log              Show last 50 lines of global error log"
            echo "  cove log beckon       Show last 50 lines of beckon site logs"
            echo "  cove log beckon -f    Follow beckon site logs in real-time"
            ;;
        share)
            echo "Usage: cove share [site] [--yes]"
            echo ""
            echo "Creates a temporary public tunnel to share a local site with anyone on the internet."
            echo "Powered by Cloudflare Quick Tunnels (cloudflared installed on-demand)."
            echo ""
            echo "Arguments:"
            echo "  [site]    The site name (optional). If omitted, prompts for selection."
            echo ""
            echo "Flags:"
            echo "  --yes, -y Install cloudflared without asking, if it's missing."
            echo "            Assumed when stdin is not a TTY."
            echo ""
            echo "Examples:"
            echo "  cove share           Interactive site selection"
            echo "  cove share mysite    Share mysite.localhost publicly"
            echo ""
            echo "You'll receive a random URL like https://random-words.trycloudflare.com"
            echo "The URL is temporary and stops working when you press Ctrl+C."
            ;;
        wsl-hosts)
            echo "Usage: cove wsl-hosts"
            echo ""
            echo "Display instructions for updating the Windows hosts file from WSL."
            echo ""
            echo "This command shows your current WSL IP address and provides PowerShell"
            echo "commands to update the Windows hosts file so you can access Cove sites"
            echo "from your Windows browser."
            echo ""
            echo "Note: Only available when running in WSL."
            ;;
        path)
            echo "Usage: cove path <name>"
            echo ""
            echo "Outputs the full path to the specified site's directory."
            echo ""
            echo "Arguments:"
            echo "  <name>         The name of the site."
            ;;
        pull)
            echo "Usage: cove pull [--ssh \"user@host -p 22\"] [--path public/] [--site <name>]"
            echo "                 [--proxy-uploads] [--yes]"
            echo ""
            echo "Pulls a remote WordPress site into Cove. Creates a backup on the remote,"
            echo "pulls it down, and configures it to run locally."
            echo ""
            echo "Prompts for anything you don't pass as a flag. Pass all of them and it"
            echo "runs unattended — no TTY required."
            echo ""
            echo "Flags:"
            echo "  --ssh <conn>     Remote SSH connection, e.g. \"user@host.com -p 2222\"."
            echo "  --path <path>    Remote WordPress root. Defaults to 'public/'."
            echo "  --site <name>    Destination site. An existing site is OVERWRITTEN;"
            echo "                   an unused name is created."
            echo "  --yes, -y        Skip the overwrite confirmation. Required (instead of the"
            echo "                   prompt) when overwriting an existing site headlessly."
            echo "  --proxy-uploads  Excludes the 'wp-content/uploads' directory from the backup and"
            echo "                   configures the local site to proxy media requests to the live URL."
            echo "                   This saves significant time and disk space for large sites."
            echo ""
            echo "Example:"
            echo "  cove pull --ssh \"dev@example.com -p 22\" --site myblog --yes"
            ;;
        push)
            echo "Usage: cove push [--site <name>] [--ssh \"user@host -p 22\"] [--path public/] [--yes]"
            echo ""
            echo "Pushes a local Cove site to a remote server. Creates a local backup, uploads"
            echo "it, and runs a migration on the remote to OVERWRITE its files and database."
            echo ""
            echo "Prompts for anything you don't pass as a flag. Pass all of them and it"
            echo "runs unattended — no TTY required."
            echo ""
            echo "Flags:"
            echo "  --site <name>    Local WordPress site to push."
            echo "  --ssh <conn>     Remote SSH connection, e.g. \"user@host.com -p 2222\"."
            echo "  --path <path>    Remote WordPress root. Defaults to 'public/'."
            echo "  --yes, -y        Confirm the overwrite. Unlike other commands this is never"
            echo "                   assumed when headless — push destroys a live remote site,"
            echo "                   so it must always be stated explicitly."
            echo ""
            echo "Example:"
            echo "  cove push --site myblog --ssh \"dev@example.com -p 22\" --yes"
            ;;
        reload)
            echo "Usage: cove reload"
            echo ""
            echo "Regenerates the Caddyfile and reloads the Caddy server gracefully."
            ;;
        url)
            echo "Usage: cove url <site>"
            echo ""
            echo "Prints the HTTPS URL for the given site."
            ;;
        upgrade)
            echo "Usage: cove upgrade [--yes]"
            echo ""
            echo "Checks for the latest version of Cove on GitHub and replaces the current executable if a newer version is available."
            echo "Also checks FrankenPHP and Adminer and upgrades them if newer versions are published."
            echo ""
            echo "Flags:"
            echo "  --yes, -y    Skip the prompt shown when the local Adminer version can't be parsed."
            ;;
        version)
            echo "Usage: cove version"
            echo ""
            echo "Displays the current version of Cove."
            ;;
        *)
            echo "Error: Unknown command '$cmd'"
            echo ""
            show_general_help
            exit 1
            ;;
    esac
}

# --- Main Command Router ---
main() {

    # Determine the path to the cove command
    local COVE_CMD
    if command -v cove &> /dev/null; then
        COVE_CMD="cove"
    else
        COVE_CMD="$0"
    fi

    # Check for a help flag anywhere in the arguments.
    for arg in "$@"; do
        if [[ "$arg" == "--help" || "$arg" == "-h" ]]; then
            local command_for_help="$1"
            # If the command is empty or a help flag, show general help.
            if [[ -z "$command_for_help" || "$command_for_help" == "--help" || "$command_for_help" == "-h" ]]; then
                show_general_help
                exit 0
            else
                # Otherwise, show help for the specific command.
                display_command_help "$command_for_help"
                exit 0
            fi
        fi
    done

    local command="$1"
    if [ -z "$command" ]; then
        show_general_help
        exit 0
    fi

    shift # Remove command from argument list

    case "$command" in
        add)
            check_dependencies
            cove_add "$@"
            ;;
        clone)
            check_dependencies
            cove_clone "$@"
            ;;
        core)
            check_dependencies
            cove_core "$@"
            ;;
        delete)
            check_dependencies
            cove_delete "$@"
            ;;
        rename)
            check_dependencies
            cove_rename "$@"
            ;;
        list)
            check_dependencies
            cove_list "$@"
            ;;
        path)
            check_dependencies
            cove_path "$@"
            ;;
        pull)
            check_dependencies
            cove_pull "$@"
            ;;
        push)
            check_dependencies
            cove_push "$@"
            ;;
        install)
            cove_install "$@"
            ;;
        login)
            check_dependencies
            cove_login "$@"
            ;;
        enable)
            check_dependencies
            cove_enable
            ;;
        disable)
            check_dependencies
            cove_disable
            ;;
        reload)
            check_dependencies
            cove_reload
            ;;
        post-upgrade)
            # Internal: cove_upgrade calls this through the freshly-installed
            # on-disk binary so these component refreshes run with the NEW code.
            # The upgrade process is still executing the pre-upgrade script in
            # memory, which may not define (or defines an older version of) these
            # functions — so anything that must ship the latest bits has to be
            # invoked via the on-disk binary here. Not part of the public CLI.
            deploy_whoops
            create_whoops_bootstrap
            refresh_all_mu_plugins
            install_watchdog_service
            # Pin portable collation defaults (MariaDB 11.5+ uca1400 trap).
            # Only restarts MariaDB the first time the drop-in lands.
            if write_mariadb_config; then
                echo "   - Restarting MariaDB to apply collation defaults..."
                restart_mariadb_service &>/dev/null || true
            fi
            # Orphan-clearing mailpit runner + throttled KeepAlive. Safe to
            # re-run: rewrites the unit and restarts mailpit once.
            install_mailpit_service
            # Regenerate per-version php-fpm configs/units so pinned sites pick
            # up pool-template changes. Restart-shy: unchanged configs with a
            # live master are left alone.
            sync_php_fpm_services
            # Rebuild the macOS menu bar app ONLY if the user opted in by
            # enabling it, and only when MENUBAR_VERSION changed. No-op on
            # Linux and for users without the app installed.
            menubar_refresh_if_enabled
            ;;
        status)
            check_dependencies
            cove_status "$@"
            ;;
        health)
            check_dependencies
            cove_health
            ;;
        transfer)
            check_dependencies
            cove_transfer "$@"
            ;;
        trust)
            check_dependencies
            cove_trust
            ;;
        db)
            check_dependencies
            local action="$1"
            shift # Remove subcommand from argument list to pass the rest to the function
            case "$action" in
                backup)
      
                    cove_db_backup "$@"
                    ;;
                list)
                    cove_db_list "$@"
                    ;;
                fix-collation)
                    cove_db_fix_collation "$@"
                    ;;
                *)
                    display_command_help "db"
                    exit 0
                    ;;
            esac
            ;;
        directive)
            check_dependencies
            local action="$1"
            shift # Remove subcommand from argument list
            case "$action" in
                add|update)
                    cove_directive_add_or_update "$@" # New function name
                    ;;
                delete)
                    cove_directive_delete "$@" # New function name
                    ;;
                list)
                    cove_directive_list "$@"
                    ;;
                *)
                    display_command_help "directive"
                    exit 0
                    ;;
            esac
            ;;
        proxy)
            check_dependencies
            cove_proxy "$@"
            ;;
        tailscale)
            check_dependencies
            cove_tailscale "$@"
            ;;
        menubar)
            check_dependencies
            cove_menubar "$@"
            ;;
        mappings)
            check_dependencies
            cove_mappings "$@"
            ;;
        lan)
            check_dependencies
            cove_lan "$@"
            ;;
        ports)
            check_dependencies
            cove_ports "$@"
            ;;
        memory)
            check_dependencies
            cove_memory "$@"
            ;;
        php)
            check_dependencies
            cove_php "$@"
            ;;
        log)
            cove_log "$@"
            ;;
        share)
            check_dependencies
            cove_share "$@"
            ;;
        wsl-hosts)
            cove_wsl_hosts
            ;;
        url)
            cove_url "$@"
            ;;
        upgrade)
            cove_upgrade "$@"
            ;;
        version)
            cove_version
            ;;
        *)
            echo "Error: Unknown command '$command'"
            echo ""
            show_general_help
            exit 1
            ;;
    esac
}

# --- Sourced Command Functions ---
# The following functions are sourced from the 'commands/' directory.

cove_add() {
    cd ~/
    local site_name="$1"
    local site_type="wordpress"
    local no_reload_flag=false
    local wp_version=""

    if [ -z "$site_name" ]; then
        gum style --foreground red "❌ Error: A site name is required."
        echo "Usage: cove add <name> [flavor] [--plain] [--php=8.2] [--multisite[=subdomain]]"
        exit 1
    fi

    # Check for invalid characters.
    if [[ "$site_name" =~ [^a-z0-9-] ]]; then
        gum style --foreground red "❌ Error: Invalid site name '$site_name'." "Site names can only contain lowercase letters, numbers, and hyphens."
        exit 1
    fi

    # Check if the name starts or ends with a hyphen.
    if [[ "$site_name" == -* || "$site_name" == *- ]]; then
        gum style --foreground red "❌ Error: Invalid site name '$site_name'." "Site names cannot begin or end with a hyphen."
        exit 1
    fi

    # Everything after the site name is parsed here. Cove's grammar is that
    # flags modify *behaviour* (--force, --totals, --no-reload) while positional
    # arguments name *things* — so what goes inside the site is a positional
    # "flavor" rather than a flag: `cove add mysite 6.4.3`, `cove add mysite
    # plain`, `cove add mysite nightly`. One slot answers "what do you want in
    # it?", which keeps the version and the plain/WordPress choice from being
    # two unrelated-looking knobs. --plain and --wp-version= stay accepted
    # forever so existing scripts and the dashboard never break.
    local flavor=""
    local plain_flag=false
    local php_pin=""
    local multisite_mode=""
    shift
    for arg in "$@"; do
        case "$arg" in
            --plain)        plain_flag=true ;;
            --no-reload)    no_reload_flag=true ;;
            --wp-version=*) flavor="${arg#*=}" ;;
            --php=*)        php_pin="${arg#*=}" ;;
            --multisite)    multisite_mode="subdirectory" ;;
            --multisite=*)  multisite_mode="${arg#*=}" ;;
            --multisite-subdomain) multisite_mode="subdomain" ;;
            -*)             ;;  # unknown flags ignored, as before
            *)              [ -z "$flavor" ] && flavor="$arg" ;;
        esac
    done

    # --multisite installs a network instead of a single site. Subdirectory
    # (mysite.localhost/store/) is the default; subdomain mode
    # (store.mysite.localhost) works because *.localhost resolves to loopback
    # natively on macOS and Linux and Caddy's local CA issues the wildcard
    # certificate — no per-subsite configuration ever.
    if [ -n "$multisite_mode" ]; then
        case "$multisite_mode" in
            subdirectory|subdirectories|subdir|subfolder) multisite_mode="subdirectory" ;;
            subdomain|subdomains) multisite_mode="subdomain" ;;
            *)
                gum style --foreground red "❌ Error: Unknown multisite mode '$multisite_mode'." "Use --multisite (subdirectory) or --multisite=subdomain."
                exit 1 ;;
        esac
    fi

    # --php pins the site to an older PHP served by native php-fpm (see
    # `cove php`). A flag rather than a second positional: the flavor slot
    # names what goes IN the site; the PHP version modifies how it runs.
    if [ -n "$php_pin" ]; then
        local php_pin_norm
        php_pin_norm=$(normalize_php_version "$php_pin")
        if [ -z "$php_pin_norm" ]; then
            gum style --foreground red "❌ Error: Invalid PHP version '$php_pin'." "Use a version like 8.2 or php@8.3."
            exit 1
        fi
        php_pin="$php_pin_norm"
        # Pinning to FrankenPHP's own version is a no-op, matching `cove php`.
        if [ "$php_pin" == "$(normalize_php_version "$(frankenphp_php_version)")" ]; then
            php_pin=""
        fi
    fi

    # Resolve the flavor into a site type + an optional pinned version.
    case "$flavor" in
        ""|latest)
            ;;                                  # newest WordPress — the default
        plain)
            site_type="plain" ;;
        nightly|trunk)
            wp_version="nightly" ;;
        [0-9]*)
            # Handed to wp-cli verbatim, so accept everything wp.org actually
            # ships: 6.4, 6.4.3, and prerelease builds like 6.9-RC1 or
            # 6.8-beta2. Pinning a prerelease is a large part of why you'd want
            # a throwaway local site in the first place.
            if ! [[ "$flavor" =~ ^[0-9]+(\.[0-9]+){1,2}(-[A-Za-z0-9.]+)?$ ]]; then
                gum style --foreground red "❌ Error: Invalid WordPress version '$flavor'." "Use a version like 6.4, 6.4.3, or 6.9-RC1."
                exit 1
            fi
            wp_version="$flavor" ;;
        *)
            gum style --foreground red "❌ Error: Unknown option '$flavor'." "Expected a WordPress version (6.4.3), 'nightly', 'latest', or 'plain'."
            exit 1 ;;
    esac

    if [ "$plain_flag" = true ]; then
        # --plain alongside a version is a contradiction rather than a harmless
        # combination: there is no WordPress in a plain site to pin.
        if [ -n "$wp_version" ]; then
            gum style --foreground red "❌ Error: Cannot combine a WordPress version with a plain site." "A plain site has no WordPress to version."
            exit 1
        fi
        site_type="plain"
    fi

    if [ -n "$multisite_mode" ] && [ "$site_type" == "plain" ]; then
        gum style --foreground red "❌ Error: Cannot combine --multisite with a plain site." "A plain site has no WordPress to network."
        exit 1
    fi

    for protected_name in $PROTECTED_NAMES; do
        if [ "$site_name" == "$protected_name" ]; then
            gum style --foreground red "❌ Error: '$site_name' is a reserved name. Choose another."
            exit 1
        fi
    done

    local site_dir="$SITES_DIR/$site_name.localhost"
    local full_hostname
    full_hostname=$(basename "$site_dir")

    if [ -d "$site_dir" ]; then
        echo "⚠️ Site '$full_hostname' already exists."
        exit 1
    fi

    # Resolve the PHP pin before creating anything so a failed brew install
    # leaves no half-made site behind.
    if [ -n "$php_pin" ] && ! ensure_php_formula "$php_pin"; then
        exit 1
    fi

    echo "➕ Creating $site_type site: $full_hostname"
    mkdir -p "$site_dir/public" "$site_dir/logs"
    if [ -n "$php_pin" ]; then
        # Written before the WordPress install so get_wp_cmd runs wp-cli under
        # the pinned PHP from the very first `core download`.
        echo "$php_pin" > "$site_dir/php_version"
    fi

    if [ "$site_type" == "plain" ]; then
        write_plain_site_landing "$site_dir/public"
    fi

    local admin_user="admin"
    local admin_pass
    local one_time_login_url=""

    if [ "$site_type" == "wordpress" ]; then
        source_config
        local db_name
        db_name=$(echo "cove_$site_name" | tr -c '[:alnum:]_' '_')

        if [ -n "$wp_version" ]; then
            # Show the pairing rather than just the pinned version. Cove runs a
            # current PHP, and an older WordPress predates it — deprecation
            # notices in the site's debug.log are expected rather than a fault,
            # and seeing both numbers together makes that obvious up front.
            local php_ver
            if [ -n "$php_pin" ]; then
                php_ver="$php_pin"
            else
                php_ver=$(frankenphp_php_version)
            fi
            if [ -n "$php_ver" ]; then
                echo "📌 Installing WordPress $wp_version on PHP $php_ver"
            else
                echo "📌 Installing WordPress $wp_version"
            fi
        fi
        echo "🗄️ Creating database: $db_name"
        mysql -u "$DB_USER" -p"$DB_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS \`$db_name\`;"
        echo "Installing WordPress..."
        admin_pass=$(cove_random_password 12)
        
        # get_wp_cmd routes wp-cli through `frankenphp php-cli` and PHPRC
        # (exported in main) sets display_errors=0 + error_reporting=6143.
        # That handles parse-time and pre-bootstrap warnings, but wp-cli's
        # own bootstrap calls `ini_set('display_errors', 'stderr')` to keep
        # its status messages on stdout, which re-routes PHP deprecation
        # warnings to stderr from wp-cli's bundled vendor code (Colors.php
        # on PHP 8.5+). The stderr filter on the subshell strips those
        # leaked Deprecated lines while still passing through real wp-cli
        # error output (which doesn't carry the "Deprecated:" prefix).
        local wp_cmd
        wp_cmd=$(get_wp_cmd "$site_dir")

        (
            cd "$site_dir/public" || exit 1

            # 1. Download WordPress with a higher memory limit. ${x:+...}
            # expands to nothing at all when no version is pinned, so the
            # default path is byte-identical to the unpinned command.
            if ! $wp_cmd core download --quiet ${wp_version:+--version="$wp_version"}; then
                echo "❌ Error: Failed to download WordPress core. This might be a network issue, a permissions problem, or a WordPress version that does not exist."
                exit 1 # Exit the subshell with an error
            fi
            # A zero exit is not proof the files exist: a `wp` that php-cli
            # can't run prints itself and exits 0 (#8). Only a WordPress tree
            # on disk counts as a download, so the rest of this block can
            # never report an install over an empty directory.
            if [ ! -f "wp-includes/version.php" ]; then
                echo "❌ Error: 'wp core download' reported success, but wp-includes/version.php is missing."
                echo "   The 'wp' on your PATH ($(command -v wp)) may be a shell wrapper rather than wp-cli itself."
                echo "   Point 'wp' at the wp-cli phar (a symlink works) and re-run. See https://github.com/anchorhost/cove/issues/8"
                exit 1
            fi

            # 2. Create the config file
            $wp_cmd config create --dbname="$db_name" --dbuser="$DB_USER" --dbpass="$DB_PASSWORD" --extra-php <<PHP
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
define( 'WP_DEBUG_DISPLAY', false );
PHP

            # 3. Install WordPress — a network when --multisite was given.
            # multisite-install also writes the MULTISITE / SUBDOMAIN_INSTALL /
            # DOMAIN_CURRENT_SITE constants into wp-config.php itself.
            if [ -n "$multisite_mode" ]; then
                local subdomains_flag=""
                [ "$multisite_mode" == "subdomain" ] && subdomains_flag="--subdomains"
                if ! $wp_cmd core multisite-install --url="$(url_for "$full_hostname")" $subdomains_flag --title="Welcome to $site_name" --admin_user="$admin_user" --admin_password="$admin_pass" --admin_email="admin@$full_hostname" --skip-email; then
                    echo "❌ Error: WordPress multisite install failed."
                    exit 1
                fi
            elif ! $wp_cmd core install --url="$(url_for "$full_hostname")" --title="Welcome to $site_name" --admin_user="$admin_user" --admin_password="$admin_pass" --admin_email="admin@$full_hostname" --skip-email; then
                echo "❌ Error: WordPress core install failed."
                exit 1
            fi

            # 4. Delete default plugins. Cosmetic cleanup — never let it decide
            # the subshell's exit status (it was the last command, so a benign
            # "already deleted" non-zero used to trigger the rollback below and
            # destroy a fully-installed site). Tolerate failure.
            echo "   - Deleting default plugins (Hello Dolly, Akismet)..."
            $wp_cmd plugin delete hello akismet --quiet || true
        ) 2> >(grep -v -E '^(PHP )?Deprecated:' >&2)

        # Check the exit code of the subshell. If it's not 0, something failed.
        if [ $? -ne 0 ]; then
            gum style --foreground red "❌ WordPress installation failed. Please review the errors above."
            # Clean up the failed site directory and database
            echo "   - Cleaning up failed installation..."
            mysql -u "$DB_USER" -p"$DB_PASSWORD" -e "DROP DATABASE IF EXISTS \`$db_name\`;"
            rm -rf "$site_dir"
            exit 1
        fi
        
        # Generate must-use plugin
        inject_mu_plugin "$site_dir/public"

        # The multisite marker drives Caddyfile generation (wildcard alias for
        # subdomain networks, subdirectory rewrites otherwise), so it must be
        # on disk before the regenerate below.
        if [ -n "$multisite_mode" ]; then
            echo "$multisite_mode" > "$site_dir/multisite"
        fi

        one_time_login_url=$($wp_cmd user login "$admin_user" --path="$site_dir/public/")
    fi

    # Only run the reload if the --no-reload flag was NOT passed.
    if [ "$no_reload_flag" = false ]; then
        regenerate_caddyfile

        # Caddy's reload admin API returns as soon as the new config is live,
        # but its internal CA issues the TLS cert for the new hostname
        # asynchronously after that. Racing a request in that window surfaces
        # as "tlsv1 alert internal error". Poll HTTPS briefly so we only return
        # once Caddy can actually complete a handshake for the new domain.
        local warm_url
        warm_url=$(url_for "$full_hostname")
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            if curl -ks --max-time 1 -o /dev/null "$warm_url/" 2>/dev/null; then
                break
            fi
            sleep 0.2
        done
    fi

    echo "✅ Site '$full_hostname' created successfully!"
    
    if [ "$site_type" == "wordpress" ]; then
        if [ -n "$multisite_mode" ]; then
            local subsite_example="$(url_for "$full_hostname")/store/"
            [ "$multisite_mode" == "subdomain" ] && subsite_example="$(url_for "store.$full_hostname")/"
            gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "✅ WordPress Multisite Installed ($multisite_mode)" "Network admin: $(url_for "$full_hostname")/wp-admin/network/" "User: $admin_user" "Pass: $admin_pass" "New subsites (e.g. $subsite_example) work with no extra setup." "One-time login URL: $one_time_login_url"
        else
            gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "✅ WordPress Installed" "URL: $(url_for "$full_hostname")/wp-admin" "User: $admin_user" "Pass: $admin_pass" "One-time login URL: $one_time_login_url"
        fi
    fi
}
# Copy a directory tree, preferring a copy-on-write clone where the filesystem
# supports one. On APFS this is roughly 3x faster than a byte copy and the two
# copies share blocks until one of them is written to, which matters when the
# whole point is stamping throwaway copies of a seeded site.
cove_copy_tree() {
    local src="$1"
    local dst="$2"

    # macOS / APFS.
    if cp -c -R "$src" "$dst" 2>/dev/null; then
        return 0
    fi
    rm -rf "$dst"

    # Linux with btrfs/xfs reflink support.
    if cp -R --reflink=auto "$src" "$dst" 2>/dev/null; then
        return 0
    fi
    rm -rf "$dst"

    # Plain byte copy — always correct, just slower.
    cp -R "$src" "$dst"
}

cove_clone() {
    cd ~/
    local source_name="$1"
    local new_name="$2"
    local no_reload_flag=false

    for arg in "$@"; do
        [ "$arg" == "--no-reload" ] && no_reload_flag=true
    done

    # --- Validation ---
    if [ -z "$source_name" ] || [ -z "$new_name" ]; then
        gum style --foreground red "❌ Error: Both a source site and a new name are required."
        echo "Usage: cove clone <source> <new-name>"
        exit 1
    fi

    if [ "$source_name" == "$new_name" ]; then
        gum style --foreground red "❌ Error: The new name must be different from the source."
        exit 1
    fi

    local source_dir="$SITES_DIR/$source_name.localhost"
    if [ ! -d "$source_dir" ]; then
        gum style --foreground red "❌ Error: Site '$source_name.localhost' not found."
        exit 1
    fi

    # Same name rules as cove_add — a clone must produce a site add could have.
    if [[ "$new_name" =~ [^a-z0-9-] ]]; then
        gum style --foreground red "❌ Error: Invalid site name '$new_name'." "Site names can only contain lowercase letters, numbers, and hyphens."
        exit 1
    fi
    if [[ "$new_name" == -* || "$new_name" == *- ]]; then
        gum style --foreground red "❌ Error: Invalid site name '$new_name'." "Site names cannot begin or end with a hyphen."
        exit 1
    fi
    for protected_name in $PROTECTED_NAMES; do
        if [ "$new_name" == "$protected_name" ]; then
            gum style --foreground red "❌ Error: '$new_name' is a reserved name. Choose another."
            exit 1
        fi
    done

    local new_dir="$SITES_DIR/$new_name.localhost"
    if [ -d "$new_dir" ]; then
        gum style --foreground red "❌ Error: A site named '$new_name.localhost' already exists."
        exit 1
    fi

    local is_wordpress=false
    [ -f "$source_dir/public/wp-config.php" ] && is_wordpress=true

    echo "🧬 Cloning $source_name.localhost → $new_name.localhost"

    # --- Files ---
    # Only public/ is cloned. logs/ is the source's own request history and
    # would be actively misleading under a new hostname, so the clone starts
    # with an empty one.
    mkdir -p "$new_dir"
    echo "   - Copying files..."
    if ! cove_copy_tree "$source_dir/public" "$new_dir/public"; then
        gum style --foreground red "❌ Error: Failed to copy site files."
        rm -rf "$new_dir"
        exit 1
    fi
    mkdir -p "$new_dir/logs"

    # Carry the PHP pin over before any wp-cli runs, so the clone's database
    # work happens under the same PHP as its source (and the clone serves
    # like its source after the reload below).
    if [ -f "$source_dir/php_version" ]; then
        cp "$source_dir/php_version" "$new_dir/php_version"
    fi

    # Carry the multisite marker so the clone's Caddy block keeps its wildcard
    # alias / subdirectory rewrites. Must exist before the regenerate below.
    local ms_mode=""
    if [ -f "$source_dir/multisite" ]; then
        ms_mode=$(cat "$source_dir/multisite")
        cp "$source_dir/multisite" "$new_dir/multisite"
    fi

    # --- Database ---
    if [ "$is_wordpress" = true ]; then
        source_config
        local wp_cmd
        wp_cmd=$(get_wp_cmd "$new_dir")

        local source_db new_db
        source_db=$(echo "cove_$source_name" | tr -c '[:alnum:]_' '_')
        new_db=$(echo "cove_$new_name" | tr -c '[:alnum:]_' '_')

        local temp_sql
        temp_sql=$(mktemp) || {
            gum style --foreground red "❌ Error: Could not create a temporary file for the database dump."
            rm -rf "$new_dir"
            exit 1
        }
        # Cleans up on every exit path below, including the error returns.
        trap 'rm -f "$temp_sql"' EXIT

        echo "   - Dumping database '$source_db'..."
        if ! mysqldump -u "$DB_USER" -p"$DB_PASSWORD" "$source_db" > "$temp_sql" 2>/dev/null; then
            gum style --foreground red "❌ Error: Failed to dump the source database '$source_db'."
            rm -rf "$new_dir"
            exit 1
        fi

        echo "   - Creating database '$new_db'..."
        mysql -u "$DB_USER" -p"$DB_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS \`$new_db\`;"
        if ! mysql -u "$DB_USER" -p"$DB_PASSWORD" "$new_db" < "$temp_sql" 2>/dev/null; then
            gum style --foreground red "❌ Error: Failed to import into '$new_db'."
            mysql -u "$DB_USER" -p"$DB_PASSWORD" -e "DROP DATABASE IF EXISTS \`$new_db\`;"
            rm -rf "$new_dir"
            exit 1
        fi

        echo "   - Pointing wp-config.php at '$new_db'..."
        if ! (cd "$new_dir/public" && $wp_cmd config set DB_NAME "$new_db" --quiet </dev/null); then
            gum style --foreground red "❌ Error: Failed to update wp-config.php."
            mysql -u "$DB_USER" -p"$DB_PASSWORD" -e "DROP DATABASE IF EXISTS \`$new_db\`;"
            rm -rf "$new_dir"
            exit 1
        fi

        echo "   - Rewriting site URLs..."
        # Non-fatal, matching cove_rename: the clone already exists and points at
        # its own database, so a search-replace hiccup is a thing to warn about
        # rather than a reason to destroy the copy.
        if ! (cd "$new_dir/public" && $wp_cmd search-replace "$(url_for "$source_name.localhost")" "$(url_for "$new_name.localhost")" --all-tables --skip-plugins --skip-themes --quiet </dev/null); then
            gum style --foreground yellow "⚠️  search-replace did not complete cleanly; verify the cloned site's URLs."
        fi

        if [ -n "$ms_mode" ]; then
            # Multisite stores BARE hostnames (no scheme) in wp_blogs.domain
            # and wp_site.domain — for subdomain networks that includes every
            # subsite (store.old.localhost). A bare-hostname pass rewrites
            # them all in one sweep; the scheme'd pass above already handled
            # option/content URLs.
            if ! (cd "$new_dir/public" && $wp_cmd search-replace "$source_name.localhost" "$new_name.localhost" --all-tables --skip-plugins --skip-themes --quiet </dev/null); then
                gum style --foreground yellow "⚠️  network domain search-replace did not complete cleanly; verify subsite domains."
            fi
            # DOMAIN_CURRENT_SITE is a wp-config constant, invisible to
            # search-replace; stale, it points the whole network at the source.
            (cd "$new_dir/public" && $wp_cmd config set DOMAIN_CURRENT_SITE "$new_name.localhost" --type=constant --quiet </dev/null) || \
                gum style --foreground yellow "⚠️  Could not update DOMAIN_CURRENT_SITE in wp-config.php."
        fi

        inject_mu_plugin "$new_dir/public"
    fi

    # --- Custom Caddy directives ---
    # Carried over so the clone behaves like its source. Directives can hardcode
    # the old hostname, so say so rather than letting it fail mysteriously.
    local source_conf="$CUSTOM_CADDY_DIR/$source_name.localhost"
    if [ -f "$source_conf" ]; then
        cp "$source_conf" "$CUSTOM_CADDY_DIR/$new_name.localhost"
        echo "   - Copied custom Caddy directives (check them for hardcoded hostnames)."
    fi

    if [ "$no_reload_flag" = false ]; then
        regenerate_caddyfile
        local warm_url
        warm_url=$(url_for "$new_name.localhost")
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            if curl -ks --max-time 1 -o /dev/null "$warm_url/" 2>/dev/null; then
                break
            fi
            sleep 0.2
        done
    fi

    if [ "$is_wordpress" = true ]; then
        local wp_cmd_final admin_login one_time_login_url
        wp_cmd_final=$(get_wp_cmd "$new_dir")
        # Unlike a fresh install there is no known admin username here, so pick
        # the first administrator out of the cloned database.
        admin_login=$($wp_cmd_final user list --role=administrator --field=user_login --number=1 --path="$new_dir/public/" 2>/dev/null </dev/null | head -1)
        # Credentials come from the source site, so they are deliberately not
        # printed here — a one-time link is the useful thing to hand back.
        if [ -n "$admin_login" ]; then
            one_time_login_url=$($wp_cmd_final user login "$admin_login" --path="$new_dir/public/" 2>/dev/null </dev/null | head -1)
        fi
        [ -n "$one_time_login_url" ] || one_time_login_url="(no administrator found — log in as you would on '$source_name')"
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 \
            "✅ Cloned '$source_name' → '$new_name'" \
            "URL: $(url_for "$new_name.localhost")" \
            "Logins are the same as '$source_name'." \
            "One-time login URL: $one_time_login_url"
    else
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 \
            "✅ Cloned '$source_name' → '$new_name'" \
            "URL: $(url_for "$new_name.localhost")"
    fi
}

# Refresh the wp.org stable-check cache the dashboard also reads. Best-effort:
# every failure leaves whatever cache already exists and returns non-zero, so
# callers degrade to "no status information" rather than aborting.
cove_wpver_refresh() {
    local max_age="${1:-86400}"

    if [ -f "$COVE_WPVER_CACHE" ]; then
        local age
        age=$(( $(date +%s) - $(cove_file_mtime "$COVE_WPVER_CACHE") ))
        [ "$age" -lt "$max_age" ] && return 0
    fi

    local tmp
    tmp=$(mktemp "${TMPDIR:-/tmp}/cove-wpver-XXXXXX") || return 1
    if ! curl -fsSL --max-time 8 "https://api.wordpress.org/core/stable-check/1.0/" -o "$tmp" 2>/dev/null; then
        rm -f "$tmp"
        return 1
    fi

    mkdir -p "$(dirname "$COVE_WPVER_CACHE")"
    # Normalised to the same {version,status} shape the dashboard writes, so one
    # cache file serves both and either side can refresh it.
    if ! SRC="$tmp" DEST="$COVE_WPVER_CACHE" frankenphp php-cli -r '
        $all = json_decode(@file_get_contents(getenv("SRC")), true);
        if (!is_array($all) || empty($all)) { exit(1); }
        $versions = array_keys($all);
        usort($versions, fn($a, $b) => version_compare($b, $a));
        $out = [];
        foreach (array_slice($versions, 0, 40) as $v) {
            $out[] = ["version" => $v, "status" => $all[$v]];
        }
        file_put_contents(getenv("DEST"), json_encode($out));
    ' 2>/dev/null; then
        rm -f "$tmp"
        return 1
    fi
    rm -f "$tmp"
    return 0
}

# Portable stat -- BSD and GNU disagree on the flag for mtime.
cove_file_mtime() {
    stat -f %m "$1" 2>/dev/null || stat -c %Y "$1" 2>/dev/null || echo 0
}

# Emit "name<TAB>version<TAB>status" for every WordPress site, in one PHP
# process. Doing this per-site from bash would mean 250+ interpreter starts.
cove_core_scan() {
    SITES_DIR="$SITES_DIR" WPVER_CACHE="$COVE_WPVER_CACHE" frankenphp php-cli -r '
        $sites_dir = getenv("SITES_DIR");
        if (!is_dir($sites_dir)) exit;

        $status_map = [];
        $cache = getenv("WPVER_CACHE");
        if ($cache && is_file($cache)) {
            $cached = @json_decode(@file_get_contents($cache), true);
            if (is_array($cached)) {
                foreach ($cached as $e) {
                    if (isset($e["version"], $e["status"])) $status_map[$e["version"]] = $e["status"];
                }
            }
        }

        $q = chr(39);
        $pattern = "/\\\$wp_version\\s*=\\s*" . $q . "([^" . $q . "]+)" . $q . "/";

        foreach (scandir($sites_dir) as $item) {
            if ($item === "." || $item === "..") continue;
            $public = $sites_dir . "/" . $item . "/public";
            if (!is_file($public . "/wp-config.php")) continue;
            $file = $public . "/wp-includes/version.php";
            if (!is_file($file)) continue;
            $head = @file_get_contents($file, false, null, 0, 4096);
            if ($head === false || !preg_match($pattern, $head, $m)) continue;
            $v = $m[1];
            echo str_replace(".localhost", "", $item) . "\t" . $v . "\t" . ($status_map[$v] ?? "unknown") . "\n";
        }
    ' 2>/dev/null
}

# Update a single site in place. Echoes a one-line result; never exits, so a
# fleet run keeps going past a broken site.
cove_core_update_one() {
    local name="$1"
    local target="$2"
    local public_dir="$SITES_DIR/$name.localhost/public"
    local wp_cmd
    wp_cmd=$(get_wp_cmd "$SITES_DIR/$name.localhost")

    local before
    before=$(cove_wp_version "$public_dir" 2>/dev/null || echo "unknown")

    # --force lets an explicit target move in either direction; reinstalling the
    # same version to repair core files is a legitimate reason to run this too.
    local args="core update"
    [ -n "$target" ] && args="core update --version=$target --force"

    # Capture the status of wp-cli itself, not of the filter. Piping straight
    # into grep would report a silent success as a failure, because grep exits
    # non-zero when it filters every line away.
    # stdin is closed for both wp-cli calls. The fleet loop feeds candidates in
    # on stdin via a here-string, and any child that reads stdin would swallow
    # the remaining lines -- silently updating one site and reporting success
    # for the whole run.
    local output status
    output=$( (cd "$public_dir" && $wp_cmd $args --quiet) 2>&1 </dev/null )
    status=$?
    output=$(printf '%s\n' "$output" | grep -v -E '^(PHP )?Deprecated:' || true)
    if [ "$status" -ne 0 ]; then
        local reason
        reason=$(printf '%s\n' "$output" | grep -v '^$' | tail -1)
        echo "   ❌ $name — ${reason:-wp core update failed}"
        return 1
    fi

    # Schema migrations are a separate step in WP-CLI, and skipping it leaves
    # the site showing the database-update screen on first admin load.
    (cd "$public_dir" && $wp_cmd core update-db --quiet) >/dev/null 2>&1 </dev/null || true

    local after
    after=$(cove_wp_version "$public_dir" 2>/dev/null || echo "unknown")
    if [ "$before" == "$after" ]; then
        echo "   • $name — already on $after"
    else
        echo "   ✅ $name — $before → $after"
    fi
    return 0
}

cove_core() {
    local sub="${1:-}"
    shift 2>/dev/null || true

    case "$sub" in
        check)
            cove_wpver_refresh || true
            local scan
            scan=$(cove_core_scan)
            if [ -z "$scan" ]; then
                gum style --padding "1 2" "No WordPress sites found."
                return 0
            fi
            local latest
            latest=$(echo "$scan" | awk -F'\t' '$3=="latest"{print $2; exit}')
            local total insecure outdated
            total=$(echo "$scan" | wc -l | tr -d ' ')
            insecure=$(echo "$scan" | awk -F'\t' '$3=="insecure"' | wc -l | tr -d ' ')
            outdated=$(echo "$scan" | awk -F'\t' '$3=="outdated"' | wc -l | tr -d ' ')

            echo ""
            echo "🔎 WordPress core across $total site(s)"
            [ -n "$latest" ] && echo "   latest release: $latest"
            echo ""
            echo "$scan" | awk -F'\t' '$3!="latest"' | sort -t'	' -k3,3 -k1,1 | while IFS=$'\t' read -r n v s; do
                case "$s" in
                    insecure) echo "   ❗ $n — $v (insecure)" ;;
                    outdated) echo "   ⚠️  $n — $v (outdated)" ;;
                    *)        echo "   ?  $n — $v" ;;
                esac
            done
            echo ""
            echo "   $insecure insecure, $outdated outdated, $((total - insecure - outdated)) current"
            [ $((insecure + outdated)) -gt 0 ] && echo "   Update them all with: cove core update --all"
            echo ""
            ;;
        update)
            local all=false dry_run=false assume_yes=false site="" target=""
            for arg in "$@"; do
                case "$arg" in
                    --all)              all=true ;;
                    --dry-run)          dry_run=true ;;
                    --yes|-y|--force)   assume_yes=true ;;
                    -*)                 ;;
                    *)
                        # Same grammar as `cove add`: a bare token that starts
                        # with a digit is a version, anything else is a site.
                        if [[ "$arg" == [0-9]* ]]; then target="$arg"; else site="$arg"; fi ;;
                esac
            done

            if [ -n "$target" ] && ! [[ "$target" =~ ^[0-9]+(\.[0-9]+){1,2}(-[A-Za-z0-9.]+)?$ ]]; then
                gum style --foreground red "❌ Error: Invalid WordPress version '$target'." "Use a version like 6.4, 6.4.3, or 6.9-RC1."
                exit 1
            fi

            if [ "$all" = false ] && [ -z "$site" ]; then
                gum style --foreground red "❌ Error: Name a site or pass --all."
                echo "Usage: cove core update <site> [version]"
                echo "       cove core update --all [--dry-run] [--yes]"
                exit 1
            fi

            # --- Single site ---
            if [ "$all" = false ]; then
                local public_dir="$SITES_DIR/$site.localhost/public"
                if [ ! -d "$SITES_DIR/$site.localhost" ]; then
                    gum style --foreground red "❌ Error: Site '$site.localhost' not found."
                    exit 1
                fi
                if [ ! -f "$public_dir/wp-config.php" ]; then
                    gum style --foreground red "❌ Error: '$site.localhost' is not a WordPress site."
                    exit 1
                fi
                source_config
                echo "🔄 Updating WordPress core on $site.localhost..."
                cove_core_update_one "$site" "$target"
                return $?
            fi

            # --- Fleet ---
            cove_wpver_refresh || true
            local scan
            scan=$(cove_core_scan)
            if [ -z "$scan" ]; then
                gum style --padding "1 2" "No WordPress sites found."
                return 0
            fi

            # With an explicit target every site is a candidate; otherwise only
            # the ones wp.org says are behind.
            local candidates
            if [ -n "$target" ]; then
                candidates=$(echo "$scan" | awk -F'\t' -v t="$target" '$2!=t{print $1"\t"$2"\t"$3}')
            else
                candidates=$(echo "$scan" | awk -F'\t' '$3!="latest"')
            fi

            if [ -z "$candidates" ]; then
                gum style --padding "1 2" "✅ Every WordPress site is already up to date."
                return 0
            fi

            local count
            count=$(echo "$candidates" | wc -l | tr -d ' ')

            echo ""
            echo "$candidates" | while IFS=$'\t' read -r n v s; do
                echo "   $n — $v${target:+ → $target}${s:+ ($s)}"
            done
            echo ""

            if [ "$dry_run" = true ]; then
                echo "🔎 Dry run — $count site(s) would be updated. Nothing changed."
                return 0
            fi

            if [ "$assume_yes" = false ]; then
                if ! gum confirm "Update $count site(s)?"; then
                    echo "Aborted."
                    return 1
                fi
            fi

            source_config
            local ok=0 failed=0
            # Sequential on purpose: parallel wp-cli runs would contend on the
            # same MariaDB and make a failure impossible to attribute.
            while IFS=$'\t' read -r n v s; do
                [ -z "$n" ] && continue
                if cove_core_update_one "$n" "$target" </dev/null; then
                    ok=$((ok + 1))
                else
                    failed=$((failed + 1))
                fi
            done <<< "$candidates"

            echo ""
            if [ "$failed" -gt 0 ]; then
                gum style --foreground yellow "⚠️  $ok updated, $failed failed."
            else
                gum style --foreground green "✅ $ok site(s) updated."
            fi
            ;;
        *)
            echo "Usage: cove core <check|update>"
            echo ""
            echo "  cove core check                    Report the WordPress version of every site."
            echo "  cove core update <site> [version]  Update one site to the latest, or to a version."
            echo "  cove core update --all             Update every site that is behind."
            echo ""
            echo "Flags:"
            echo "  --all          Apply to every WordPress site."
            echo "  --dry-run      List what would change without touching anything."
            echo "  --yes, -y      Skip the confirmation prompt."
            ;;
    esac
}

cove_db_backup() {
    echo "🚀 Starting database backup for all WordPress sites..."

    if [ ! -d "$SITES_DIR" ] || [ -z "$(ls -A "$SITES_DIR")" ]; then
        gum style --foreground yellow "ℹ️ No sites found to back up."
        exit 0
    fi

    local dump_command
    if command -v mariadb-dump &> /dev/null; then
        dump_command="mariadb-dump"
    elif command -v mysqldump &> /dev/null; then
        dump_command="mysqldump"
    else
        gum style --foreground red "❌ Error: Neither mariadb-dump nor mysqldump could be found. Please install MariaDB or MySQL."
        return 1
    fi
    echo "ℹ️ Using '$dump_command' for backups."

    local overall_success=true
    for site_path in "$SITES_DIR"/*; do
        if [ -d "$site_path" ] && [ -f "$site_path/public/wp-config.php" ]; then
            local site_name
            site_name=$(basename "$site_path")
            echo "-----------------------------------------------------"
            echo "➡️ Backing up site: $site_name"

            local public_dir="$site_path/public"
            local private_dir="$site_path/private"
            mkdir -p "$private_dir"

            # Use a subshell to avoid manual cd back and forth
            (
                cd "$public_dir" || return 1
                
                # Get WP-CLI command (adds --allow-root if running as root;
                # uses the site's pinned PHP when one is set)
                local wp_cmd
                wp_cmd=$(get_wp_cmd "$site_path")
                
                # Check if wp-cli can connect
                if ! $wp_cmd core is-installed --skip-plugins --skip-themes &> /dev/null; then
                    echo "   ❌ Error: wp-cli cannot connect to the database for this site. Skipping."
                    return 1 # This exits the subshell, not the main script
                fi

                local db_name db_user db_pass
                db_name=$($wp_cmd config get DB_NAME --skip-plugins --skip-themes)
                db_user=$($wp_cmd config get DB_USER --skip-plugins --skip-themes)
                db_pass=$($wp_cmd config get DB_PASSWORD --skip-plugins --skip-themes)

                if [ -z "$db_name" ] || [ -z "$db_user" ]; then
                    echo "   ❌ Error: Could not retrieve database credentials from wp-config.php. Skipping."
                    return 1
                fi
                
                local backup_timestamp
                backup_timestamp=$(date +%Y%m%d-%H%M%S)
                local backup_file="../private/database-backup-${backup_timestamp}.sql"
                echo "   Saving backup to: $(basename "$site_path")/private/$(basename "$backup_file")"

                # Execute the dump command
                if ! "${dump_command}" -u"${db_user}" -p"${db_pass}" --max_allowed_packet=512M --default-character-set=utf8mb4 --add-drop-table --single-transaction --quick --lock-tables=false "${db_name}" > "${backup_file}"; then
                    echo "   ❌ Error: Database dump failed for '${db_name}'."
                    rm -f "${backup_file}" # Clean up failed backup file
                    return 1
                fi
                
                chmod 600 "$backup_file"
                echo "   ✅ Backup successful."
            )
            
            # Check the exit code of the subshell
            if [ $? -ne 0 ]; then
                overall_success=false
            fi
        fi
    done
    
    echo "-----------------------------------------------------"
    if $overall_success; then
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "🎉 All WordPress database backups completed successfully!"
    else
        gum style --foreground red "⚠️ Some database backups failed. Please review the output above."
    fi
}
cove_db_list() {
    source_config # To get DB_USER and DB_PASSWORD for mysql command

    echo "🔎 Gathering database information for all WordPress sites..."

    if ! command -v wp &> /dev/null; then
        gum style --foreground red "❌ wp-cli is not installed or not in your PATH. Please run 'cove install'."
        exit 1
    fi

    if [ ! -d "$SITES_DIR" ] || [ -z "$(ls -A "$SITES_DIR" 2>/dev/null)" ]; then
        gum style --padding "1 2" "ℹ️ No sites found."
        exit 0
    fi

    # This heredoc contains a PHP script to find, connect, and format the database list.
    # We invoke it via `frankenphp php-cli -r` so we don't depend on a standalone php binary.
    #
    # Driver note: this MUST use mysqli, not PDO. The Linux apt build of
    # FrankenPHP (dunglas' frankenphp_*+php85 deb, php-zts) ships mysqli and
    # mysqlnd but no PDO at all — `class_exists("PDO")` is false there, while
    # the macOS build of the same version has it. Using PDO made this command
    # fatal on every Linux install, and because the fatal went to stderr the
    # empty stdout looked exactly like "no sites" (see the $php_status guard
    # below). mysqli is also the driver WordPress itself connects with, so a
    # site that loads is a site this command can read.
    # get_wp_cmd carries --allow-root when needed and sees through a shell
    # wrapper around wp (#8); hand-rolling `frankenphp php-cli $(command -v wp)`
    # here reintroduced both problems.
    local wp_invoker
    wp_invoker=$(get_wp_cmd)
    local php_output php_err php_status
    php_err=$(mktemp)
    php_output=$(DB_USER="$DB_USER" DB_PASSWORD="$DB_PASSWORD" SITES_DIR="$SITES_DIR" WP_INVOKER="$wp_invoker" frankenphp php-cli -r '
        function formatSize(int $bytes): string {
            if ($bytes === 0) return "0 B";
            $units = ["B", "KB", "MB", "GB", "TB"];
            $i = floor(log($bytes, 1024));
            return round($bytes / (1024 ** $i), 2) . " " . $units[$i];
        }

        $sites_dir = getenv("SITES_DIR");
        $db_user = getenv("DB_USER");
        $db_pass = getenv("DB_PASSWORD");
        $wp_invoker = getenv("WP_INVOKER");

        if (!is_dir($sites_dir)) { exit; }

        mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
        try {
            $mysqli = mysqli_init();
            $mysqli->options(MYSQLI_OPT_CONNECT_TIMEOUT, 2);
            $mysqli->real_connect("localhost", $db_user, $db_pass);
        } catch (Throwable $e) {
            fwrite(STDERR, "Could not connect to the database server: " . $e->getMessage() . "\n");
            exit(1);
        }

        $sites_info = [];
        foreach (scandir($sites_dir) as $item) {
            $public_dir = $sites_dir . "/" . $item . "/public";
            if (is_file($public_dir . "/wp-config.php")) {
                $site_name = str_replace(".localhost", "", $item);
                $public_dir_esc = escapeshellarg($public_dir);
                $cmd_suffix = " --skip-plugins --skip-themes --quiet 2>/dev/null";
                
                $name_raw = shell_exec("cd " . $public_dir_esc . " && " . $wp_invoker . " config get DB_NAME" . $cmd_suffix);
                if (is_null($name_raw)) { continue; }
                $site_db_name = trim($name_raw);
                if (empty($site_db_name)) { continue; }

                $site_db_user = "N/A";
                $site_db_pass = "N/A";
                $size_str = "N/A";

                if (!str_contains(strtolower($site_db_name), "sqlite")) {
                    $user_raw = shell_exec("cd " . $public_dir_esc . " && " . $wp_invoker . " config get DB_USER" . $cmd_suffix);
                    if (!is_null($user_raw)) { $site_db_user = trim($user_raw); }

                    $pass_raw = shell_exec("cd " . $public_dir_esc . " && " . $wp_invoker . " config get DB_PASSWORD" . $cmd_suffix);
                    if (!is_null($pass_raw)) { $site_db_pass = trim($pass_raw); }
                    
                    $stmt = $mysqli->prepare("SELECT SUM(data_length + index_length) as size FROM information_schema.TABLES WHERE table_schema = ?");
                    $stmt->bind_param("s", $site_db_name);
                    $stmt->execute();
                    $size_bytes = $stmt->get_result()->fetch_assoc()["size"] ?? 0;
                    $stmt->close();
                    $size_str = formatSize((int)$size_bytes);
                }

                $sites_info[] = [
                    "name" => $site_name,
                    "db_name" => $site_db_name,
                    "db_user" => $site_db_user,
                    "db_pass" => $site_db_pass,
                    "size" => $size_str,
                ];
            }
        }

        if (empty($sites_info)) { exit; }

        array_multisort(array_column($sites_info, "name"), SORT_ASC, $sites_info);
        
        $output = [];
        $w = ["name" => 20, "db_name" => 25, "db_user" => 20, "db_pass" => 25, "size" => 15];
        $header = str_pad("Name", $w["name"]) . " " . str_pad("DB Name", $w["db_name"]) . " " . str_pad("DB User", $w["db_user"]) . " " . str_pad("DB Pass", $w["db_pass"]) . " " . str_pad("Size", $w["size"]);
        $separator = str_repeat("-", $w["name"]) . " " . str_repeat("-", $w["db_name"]) . " " . str_repeat("-", $w["db_user"]) . " " . str_repeat("-", $w["db_pass"]) . " " . str_repeat("-", $w["size"]);
        $output[] = $header;
        $output[] = $separator;

        foreach ($sites_info as $site) {
            $row = str_pad($site["name"], $w["name"]) . " " . str_pad($site["db_name"], $w["db_name"]) . " " . str_pad($site["db_user"], $w["db_user"]) . " " . str_pad($site["db_pass"], $w["db_pass"]) . " " . str_pad($site["size"], $w["size"]);
            $output[] = $row;
        }
        echo implode("\n", $output);
    ' 2>"$php_err")
    php_status=$?

    # A crashing PHP block writes nothing to stdout, which is byte-identical to
    # "there are genuinely no sites". Not separating the two is why the
    # missing-PDO fatal above sat unnoticed for so long — so surface the real
    # error instead of reporting a comforting empty list.
    if [ "$php_status" -ne 0 ]; then
        gum style --foreground red "❌ Could not read database information."
        [ -s "$php_err" ] && sed 's/^/   /' "$php_err" >&2
        rm -f "$php_err"
        exit 1
    fi
    rm -f "$php_err"

    if [ -z "$php_output" ]; then
        gum style --padding "1 2" "ℹ️ No WordPress sites with readable database configurations found."
    else
        echo "$php_output" | gum style --border normal --margin "1" --padding "1 2" --border-foreground 212
    fi
}
# Convert tables that MariaDB 11.5+ stamped with its uca1400 default
# collations back to the classic *_unicode_ci ones. The drop-in written by
# write_mariadb_config stops NEW tables from getting uca1400, but tables
# imported or created before it landed keep the collation they were born
# with — and every dump of them fails to import on MariaDB 10.x / MySQL
# ("Unknown collation: 'utf8mb4_uca1400_ai_ci'"). Usage:
#   cove db fix-collation <site> [--dry-run]
#   cove db fix-collation --all  [--dry-run]
cove_db_fix_collation() {
    local site_name="" all=false dry_run=false
    local arg
    for arg in "$@"; do
        case "$arg" in
            --all)     all=true ;;
            --dry-run) dry_run=true ;;
            -*)
                gum style --foreground red "❌ Unknown option: $arg"
                echo "Usage: cove db fix-collation <site> | --all [--dry-run]"
                exit 1
                ;;
            *)         site_name="$arg" ;;
        esac
    done

    if ! $all && [ -z "$site_name" ]; then
        gum style --foreground red "❌ Error: A site name (or --all) is required."
        echo "Usage: cove db fix-collation <site> | --all [--dry-run]"
        exit 1
    fi
    if [ -n "$site_name" ] && ! validate_site_name "$site_name"; then
        gum style --foreground red "❌ Error: Invalid site name '$site_name'."
        exit 1
    fi

    local -a site_dirs=()
    if $all; then
        local d
        for d in "$SITES_DIR"/*; do
            [ -f "$d/public/wp-config.php" ] && site_dirs+=("$d")
        done
        if [ ${#site_dirs[@]} -eq 0 ]; then
            gum style --foreground yellow "ℹ️ No WordPress sites found."
            exit 0
        fi
    else
        local site_dir="$SITES_DIR/$site_name.localhost"
        if [ ! -f "$site_dir/public/wp-config.php" ]; then
            gum style --foreground red "❌ Error: WordPress site '$site_name.localhost' not found."
            exit 1
        fi
        site_dirs=("$site_dir")
    fi

    local overall_success=true converted_total=0
    local site_path
    for site_path in "${site_dirs[@]}"; do
        local name public_dir wp_cmd db_name db_user db_pass
        name=$(basename "$site_path")
        public_dir="$site_path/public"
        wp_cmd=$(get_wp_cmd "$site_path")
        echo "➡️ $name"

        db_name=$(cd "$public_dir" && $wp_cmd config get DB_NAME --skip-plugins --skip-themes 2>/dev/null)
        db_user=$(cd "$public_dir" && $wp_cmd config get DB_USER --skip-plugins --skip-themes 2>/dev/null)
        db_pass=$(cd "$public_dir" && $wp_cmd config get DB_PASSWORD --skip-plugins --skip-themes 2>/dev/null)
        if [ -z "$db_name" ] || [ -z "$db_user" ]; then
            echo "   ❌ Could not read database credentials from wp-config.php. Skipping."
            overall_success=false
            continue
        fi
        if printf '%s' "$db_name" | grep -qi sqlite; then
            echo "   ℹ️ SQLite site — nothing to do."
            continue
        fi

        # Tables whose default collation is uca1400. Emit "table<TAB>charset"
        # so the ALTER keeps the charset and only swaps the collation. The
        # charset is taken from the collation name's prefix on purpose:
        # MariaDB 10.10+ lists uca1400 collations in
        # collation_character_set_applicability under a charset-free name,
        # so a join on collation_name finds nothing.
        local rows
        rows=$(mysql -u"$db_user" -p"$db_pass" -N -B -e "
            SELECT table_name, SUBSTRING_INDEX(table_collation, '_', 1)
              FROM information_schema.tables
             WHERE table_schema = '${db_name//\'/\'\'}'
               AND table_collation LIKE '%uca1400%'
             ORDER BY table_name" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "   ❌ Could not query information_schema for '$db_name'. Skipping."
            overall_success=false
            continue
        fi
        if [ -z "$rows" ]; then
            echo "   ✅ No uca1400 tables found."
            continue
        fi

        local count
        count=$(printf '%s\n' "$rows" | wc -l | tr -d ' ')
        local sql="" table charset target
        while IFS=$'\t' read -r table charset; do
            [ -z "$table" ] && continue
            case "$charset" in
                utf8mb3|utf8) target="utf8mb3_unicode_ci"; charset="utf8mb3" ;;
                utf8mb4)      target="utf8mb4_unicode_ci" ;;
                *)            echo "   ⚠️ Skipping \`$table\` (unhandled charset '$charset')."; continue ;;
            esac
            if $dry_run; then
                echo "   would convert \`$table\` → $charset / $target"
            fi
            sql+="ALTER TABLE \`${table//\`/\`\`}\` CONVERT TO CHARACTER SET $charset COLLATE $target;"$'\n'
        done <<< "$rows"

        if $dry_run; then
            echo "   ℹ️ Dry run: $count table(s) would be converted."
            continue
        fi

        echo "   Converting $count table(s) to *_unicode_ci..."
        if ! printf '%s' "$sql" | mysql -u"$db_user" -p"$db_pass" "$db_name"; then
            echo "   ❌ One or more ALTER TABLE statements failed for '$db_name'."
            overall_success=false
            continue
        fi

        # CONVERT TO rewrites every string column, so what remains would be an
        # explicitly-collated column in a table whose default was already
        # something else. Rare, but worth pointing at rather than hiding.
        local leftovers
        leftovers=$(mysql -u"$db_user" -p"$db_pass" -N -B -e "
            SELECT CONCAT(table_name, '.', column_name, ' (', collation_name, ')')
              FROM information_schema.columns
             WHERE table_schema = '${db_name//\'/\'\'}'
               AND collation_name LIKE '%uca1400%'" 2>/dev/null)
        if [ -n "$leftovers" ]; then
            echo "   ⚠️ Columns still on a uca1400 collation (convert these by hand):"
            printf '%s\n' "$leftovers" | sed 's/^/      /'
        fi
        converted_total=$((converted_total + count))
        echo "   ✅ Converted $count table(s)."
    done

    echo "-----------------------------------------------------"
    if $overall_success; then
        if $dry_run; then
            gum style --foreground 212 "Dry run complete. Re-run without --dry-run to convert."
        else
            gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "🎉 Collation fix complete: $converted_total table(s) converted."
        fi
    else
        gum style --foreground red "⚠️ Some sites could not be processed. Please review the output above."
        exit 1
    fi
}

cove_delete() {
    source_config
    local site_name="$1"
    # Reject traversal / metacharacters before the name reaches rm -rf and
    # DROP DATABASE below — cove delete never validated it, so `../x` escaped
    # the Sites tree (and the sudo -n rm fallback made that worse).
    if ! validate_site_name "$site_name"; then
        gum style --foreground red "❌ Error: Invalid site name '$site_name'."
        exit 1
    fi
    for protected_name in $PROTECTED_NAMES; do
        if [ "$site_name" == "$protected_name" ]; then
            gum style --foreground red "❌ Error: '$site_name' is a reserved name and cannot be deleted."
            exit 1
        fi
    done

    local force_delete=false
    local no_reload=false
    for arg in "$@"; do
        case "$arg" in
            --force|--yes|-y) force_delete=true ;;
            --no-reload) no_reload=true ;;
        esac
    done
    # Non-interactive callers (dashboard shell_exec, scripted cleanup) have no
    # TTY; gum confirm aborts there. Auto-promote so the delete doesn't hang.
    [ -t 0 ] || force_delete=true

    local site_dir="$SITES_DIR/$site_name.localhost"
    if [ ! -d "$site_dir" ]; then
        echo "⚠️ Site '$site_name.localhost' not found."
        exit 1
    fi

    if ! $force_delete; then
        if ! gum confirm "🚨 Are you sure you want to delete '$site_name.localhost'? This will remove its files and potentially its database."; then
            echo "🚫 Deletion cancelled."
            exit 0
        fi
    fi

    # Collect hostnames to strip from /etc/hosts BEFORE we rm -rf the site dir
    local hosts_to_remove=("$site_name.localhost")
    if [ -f "$site_dir/mappings" ]; then
        while IFS= read -r mapping || [ -n "$mapping" ]; do
            if [ -n "$mapping" ]; then
                hosts_to_remove+=("$mapping")
            fi
        done < "$site_dir/mappings"
    fi

    echo "🔥 Deleting site: $site_name.localhost"
    if [ -f "$site_dir/public/wp-config.php" ]; then
        local db_name wp_cmd
        wp_cmd=$(get_wp_cmd "$site_dir")
        # Prefer the DB actually named in wp-config.php. Deriving cove_<name>
        # blindly (as before) would orphan the real database for any site whose
        # DB_NAME was changed — and could drop an unrelated database that
        # happened to match the derived name. Fall back to the derived name only
        # if wp-config can't be read.
        db_name=$( (cd "$site_dir/public" && $wp_cmd config get DB_NAME --skip-plugins --skip-themes 2>/dev/null) )
        if [ -z "$db_name" ]; then
            db_name=$(echo "cove_$site_name" | tr -c '[:alnum:]_' '_')
        fi
        echo "🗄️ Deleting database: $db_name"
        mysql -u "$DB_USER" -p"$DB_PASSWORD" -e "DROP DATABASE IF EXISTS \`$db_name\`;"
    fi

    # Don't trust the bare rm — a pre-1.10 dashboard-created site would be
    # root-owned (sudo-started FrankenPHP), and a silent rm failure would
    # previously still report "removed" while leaving the dir on disk. Try
    # sudo -n as a fallback, then surface the failure to the caller.
    if ! rm -rf "$site_dir" 2>/dev/null; then
        if ! $SUDO_CMD -n rm -rf "$site_dir" 2>/dev/null; then
            gum style --foreground red "❌ Failed to delete '$site_dir' — permission denied."
            gum style --foreground yellow "   Run: sudo rm -rf '$site_dir'"
            exit 1
        fi
    fi
    echo "✅ Directory deleted."

    # A reload already in flight snapshotted the Sites listing while this
    # site still existed. When that stale Caddyfile applies, Caddy re-creates
    # the site's logs/ skeleton — which resurrects the site in the dashboard.
    # Leave a tombstone so cove_reload prunes the skeleton, and flag the
    # in-flight holder to re-run against the post-delete Sites listing.
    mkdir -p "$COVE_DIR/cache/delete-tombstones"
    touch "$COVE_DIR/cache/delete-tombstones/$site_name.localhost"
    local reload_holder
    reload_holder=$(cat "$COVE_DIR/.reload.lock" 2>/dev/null)
    if [ -n "$reload_holder" ] && kill -0 "$reload_holder" 2>/dev/null; then
        touch "$COVE_DIR/.reload.pending" 2>/dev/null || true
    fi

    # --- Delete Custom Caddy Directives ---
    local custom_conf_file="$CUSTOM_CADDY_DIR/$site_name.localhost"
    if [ -f "$custom_conf_file" ]; then
        rm "$custom_conf_file"
        echo "⚙️ Custom directives deleted."
    fi

    # --- Clean /etc/hosts entries ---
    local entries_exist=false
    local host
    for host in "${hosts_to_remove[@]}"; do
        if grep -qE "^127\.0\.0\.1[[:space:]]+${host//./\\.}[[:space:]]*$" /etc/hosts 2>/dev/null; then
            entries_exist=true
            break
        fi
    done

    if $entries_exist; then
        echo "🧹 Removing /etc/hosts entries (requires sudo)..."
        local sed_args=()
        for host in "${hosts_to_remove[@]}"; do
            sed_args+=(-e "/^127\.0\.0\.1[[:space:]]+${host//./\\.}[[:space:]]*$/d")
        done
        # Use non-interactive sudo when we don't have a TTY (e.g., the dashboard's
        # PHP shell_exec). In that context an interactive sudo prompt can hang
        # the caller waiting for a password that will never arrive. From a real
        # terminal the flag is empty, so sudo prompts as normal.
        local sudo_flag=""
        [ -t 0 ] || sudo_flag="-n"
        if sudo $sudo_flag sed -i.bak -E "${sed_args[@]}" /etc/hosts 2>/dev/null; then
            sudo $sudo_flag rm -f /etc/hosts.bak 2>/dev/null
            echo "   - ✅ /etc/hosts cleaned."
        else
            gum style --foreground yellow "   - ⚠️ Skipped /etc/hosts cleanup (sudo unavailable from this context). Run 'cove reload' from a terminal to sync."
        fi
    fi

    # Regenerate the Caddyfile so Caddy stops holding log file handles for
    # this site. Without this, a later Caddy restart would re-create the
    # deleted directory skeleton from the stale Caddyfile entry. The
    # dashboard passes --no-reload because it batches one reload per
    # delete queue drain.
    if [ "$no_reload" = false ]; then
        regenerate_caddyfile &>/dev/null
    fi

    echo "✅ Site '$site_name.localhost' has been removed."
}
cove_directive_add_or_update() {
    local site_name=""
    local arg_rules=""
    local arg_file=""
    local have_rules=false
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --rules) arg_rules="$2"; have_rules=true; shift 2 ;;
            --rules=*) arg_rules="${1#*=}"; have_rules=true; shift ;;
            --file) arg_file="$2"; shift 2 ;;
            --file=*) arg_file="${1#*=}"; shift ;;
            -h|--help) display_command_help directive; exit 0 ;;
            -*)
                gum style --foreground red "❌ Unknown option: $1"
                echo "Usage: cove directive <add|update> <name> [--rules \"...\" | --file <path>]"
                exit 1
                ;;
            *) [ -z "$site_name" ] && site_name="$1"; shift ;;
        esac
    done

    if [ -z "$site_name" ]; then
        gum style --foreground red "❌ Error: Please provide a site name."
        echo "Usage: cove directive <add|update> <name> [--rules \"...\" | --file <path>]"
        exit 1
    fi

    if [ -n "$arg_file" ]; then
        if [ ! -f "$arg_file" ]; then
            gum style --foreground red "❌ Error: File not found: $arg_file"
            exit 1
        fi
        arg_rules=$(cat "$arg_file")
        have_rules=true
    fi
    
    local site_hostname="${site_name}.localhost"
    local site_dir="$SITES_DIR/$site_hostname"
    local custom_conf_file="$CUSTOM_CADDY_DIR/$site_hostname"

    if [ ! -d "$site_dir" ]; then
        gum style --foreground red "❌ Error: Site '$site_hostname' not found."
        exit 1
    fi

    local existing_rules=""
    if [ -f "$custom_conf_file" ]; then
        existing_rules=$(cat "$custom_conf_file")
    fi
    
    local custom_rules
    # --rules/--file win outright; otherwise a TTY gets the editor and a pipe
    # gets read from stdin (the path `cove pull --proxy-uploads` uses).
    if $have_rules; then
        custom_rules="$arg_rules"
    elif [ -t 0 ]; then
        if [ -f "$custom_conf_file" ]; then
            echo "📝 Editing custom Caddy directives for $site_hostname..."
        else
            echo "📝 Adding new custom Caddy directives for $site_hostname..."
        fi
        echo "   Press Ctrl+D to save and exit, Ctrl+C to cancel."
        custom_rules=$(gum write --value "$existing_rules" --placeholder "Enter custom Caddy directives here...")
    else
        echo "📝 Reading custom directives from stdin for $site_hostname..."
        custom_rules=$(cat) # Read from standard input
    fi

    if [ -n "$custom_rules" ]; then
        mkdir -p "$CUSTOM_CADDY_DIR"
        echo "$custom_rules" > "$custom_conf_file"
        echo "✅ Custom directives saved for $site_hostname."
        regenerate_caddyfile
    else
        echo "🚫 No input provided. Action cancelled."
    fi
}

# This new function handles deleting directives
cove_directive_delete() {
    local site_name=""
    local force_delete=false
    for arg in "$@"; do
        case "$arg" in
            --force|--yes|-y) force_delete=true ;;
            -*)
                gum style --foreground red "❌ Unknown option: $arg"
                echo "Usage: cove directive delete <name> [--force]"
                exit 1
                ;;
            *) [ -z "$site_name" ] && site_name="$arg" ;;
        esac
    done

    if [ -z "$site_name" ]; then
        gum style --foreground red "❌ Error: Please provide a site name."
        echo "Usage: cove directive delete <name> [--force]"
        exit 1
    fi

    local site_hostname="${site_name}.localhost"
    local custom_conf_file="$CUSTOM_CADDY_DIR/$site_hostname"

    # Non-interactive callers (dashboard shell_exec, CI) have no TTY — gum
    # confirm aborts there. Auto-promote to --force so scripted deletes work.
    [ -t 0 ] || force_delete=true

    if [ -f "$custom_conf_file" ]; then
        if ! $force_delete; then
            if ! gum confirm "🚨 Are you sure you want to delete the custom directives for '$site_hostname'?"; then
                echo "🚫 Deletion cancelled."
                return 0
            fi
        fi
        rm "$custom_conf_file"
        echo "✅ Custom directives deleted for $site_hostname."
        regenerate_caddyfile
    else
        echo "ℹ️ No custom directives found for $site_hostname."
    fi
}

cove_directive_list() {
    echo "🔎 Listing all custom Caddy directives..."
    
    if [ ! -d "$CUSTOM_CADDY_DIR" ] || [ -z "$(ls -A "$CUSTOM_CADDY_DIR" 2>/dev/null)" ]; then
        echo ""
        gum style --foreground "yellow" "ℹ️ No custom directives found for any sites."
        exit 0
    fi

    local found_one=false
    for conf_file in $(find "$CUSTOM_CADDY_DIR" -type f | sort); do
        found_one=true
        local site_name
        site_name=$(basename "$conf_file")
        
        local content
        content=$(cat "$conf_file")

        gum style --border normal --margin "1 0" --padding "1 2" --border-foreground 212 "📄 $site_name" "" "$content"
    done

    if ! $found_one; then
        echo ""
        gum style --foreground "yellow" "ℹ️ No custom directives found for any sites."
    fi
}
cove_disable() {
    echo "🛑 Disabling Cove services..."

    echo "   - Stopping Caddy/FrankenPHP..."

    # Stop services on MacOS
    if [ "$OS" == "macos" ]; then
        # Unload the watchdog first so it doesn't SIGKILL Caddy mid-shutdown.
        launchctl unload "$COVE_DIR/com.cove.watchdog.plist" &>/dev/null
        launchctl unload "$COVE_DIR/com.cove.caddy.plist" &>/dev/null
        "$CADDY_CMD" stop --config "$CADDYFILE_PATH" &>/dev/null 2>&1
        echo "   - Stopping MariaDB..."
        pkg_service stop mariadb &>/dev/null
        echo "   - Stopping Mailpit..."
        launchctl unload "$COVE_DIR/com.cove.mailpit.plist" &>/dev/null
        # Reap any leftover mailpit so it can't hold :1025/:8025 after unload
        # and thrash KeepAlive on the next enable (see install_mailpit_service).
        # -x matches basename only — never a random path containing "mailpit".
        pkill -x mailpit &>/dev/null || true
        # Per-site php-fpm units. Unload only — the plists stay on disk so the
        # next enable's sync_php_fpm_services restores them from the sites'
        # php_version files. The -f pattern matches the master's process title
        # ("php-fpm: master process (~/Cove/php-fpm/<ver>/php-fpm.conf)"),
        # which takes its workers down with it.
        local fpm_plist
        for fpm_plist in "$COVE_DIR"/com.cove.php-fpm-*.plist; do
            [ -f "$fpm_plist" ] || continue
            echo "   - Stopping PHP-FPM ($(basename "$fpm_plist" .plist | sed 's/com\.cove\.php-fpm-//'))..."
            launchctl unload "$fpm_plist" &>/dev/null
        done
        pkill -f "Cove/php-fpm/.*/php-fpm\.conf" &>/dev/null || true
    fi

    # Stop services on Linux
    if [ "$OS" == "linux" ]; then
        # Stop the watchdog first so it doesn't SIGKILL cove.service as we
        # bring it down.
        $SUDO_CMD systemctl stop cove-watchdog.timer &>/dev/null || true
        # v1.10+: FrankenPHP runs as cove.service under systemd. Try that
        # first; fall back to `frankenphp stop` in case a user skipped
        # cove_enable since the upgrade and still has an ad-hoc instance.
        $SUDO_CMD systemctl stop cove.service &>/dev/null \
            || "$CADDY_CMD" stop --config "$CADDYFILE_PATH" &>/dev/null \
            || $SUDO_CMD -n "$CADDY_CMD" stop --config "$CADDYFILE_PATH" &>/dev/null \
            || true

        # Also disable the Cove-owned units so they stay down across a reboot —
        # cove_enable runs `systemctl enable` on these, so stop-only left them
        # to re-grab ports 80/443 (the reason to disable in the first place) on
        # the next boot. MariaDB is intentionally left enabled: it's shared
        # infrastructure that doesn't conflict with another web server, so we
        # don't surprise users who rely on it outside Cove.
        $SUDO_CMD systemctl disable cove-watchdog.timer &>/dev/null || true
        $SUDO_CMD systemctl disable cove.service &>/dev/null || true

        # Get the correct MariaDB service name
        local mariadb_service
        mariadb_service=$(get_mariadb_service_name)

        echo "   - Stopping MariaDB ($mariadb_service)..."
        $SUDO_CMD systemctl stop "$mariadb_service" &>/dev/null
        echo "   - Stopping Mailpit..."
        $SUDO_CMD systemctl stop mailpit &>/dev/null
        # Same orphan reap as macOS: a manual or leftover mailpit would hold
        # the ports and fight the next enable's Restart=on-failure loop.
        pkill -x mailpit &>/dev/null || true
    fi
    
    echo "✅ Services stopped."
}
cove_enable() {
    echo "🚀 Enabling Cove services..."

    # Ensure log directory exists
    mkdir -p "$LOGS_DIR"

    if [ "$OS" == "macos" ]; then
        echo "   - Starting MariaDB..."
        start_macos_mariadb

        # Mailpit: runner + launchd unit (clears orphaned mailpit that would
        # otherwise thrash KeepAlive on a bind failure). Shared helper so
        # post-upgrade can refresh it without a full re-enable.
        install_mailpit_service

        # Native php-fpm units for any sites pinned to an older PHP.
        sync_php_fpm_services
    fi
    
    if [ "$OS" == "linux" ]; then
        # Get the correct MariaDB service name for this distro
        local mariadb_service
        mariadb_service=$(get_mariadb_service_name)
        
        echo "   - Starting MariaDB ($mariadb_service)..."
        $SUDO_CMD systemctl enable "$mariadb_service" &>/dev/null
        $SUDO_CMD systemctl restart "$mariadb_service"

        # Mailpit unit + orphan-clearing runner (see install_mailpit_service).
        install_mailpit_service

        local current_user
        current_user=$(whoami)

        # --- FrankenPHP / Cove systemd unit ---
        # Mirrors the mailpit pattern so the stack survives a reboot. The
        # apt frankenphp.service was masked during `cove install` so there
        # is no name conflict; we use `cove.service` to keep the scope
        # clear ("this is Cove's managed FrankenPHP").
        local cove_service_path="/etc/systemd/system/cove.service"
        local frankenphp_bin
        frankenphp_bin=$(command -v "$CADDY_CMD")

        echo "   - Generating Cove FrankenPHP service file..."
        # Same sudo-tee pattern as the mailpit unit (in install_mailpit_service);
        # see the note there for why mktemp + sudo mv doesn't survive SELinux.
        $SUDO_CMD tee "$cove_service_path" >/dev/null << EOM
[Unit]
Description=FrankenPHP for Cove
After=network.target mariadb.service
Wants=mariadb.service

[Service]
Type=simple
ExecStart=$frankenphp_bin run --config $CADDYFILE_PATH --pidfile $COVE_DIR/caddy.pid
ExecReload=$frankenphp_bin reload --config $CADDYFILE_PATH --address localhost:2019
Restart=on-failure
RestartSec=2s
# FrankenPHP holds ~1 FD per site (listener/cert) plus one per in-flight
# request. A Cove install with a couple hundred sites idles near the default
# soft limit and hits EMFILE ("too many open files") under concurrency, which
# wedges the Go runtime. Give it generous headroom (matches the macOS plist).
LimitNOFILE=65536
User=$current_user
Environment=HOME=/home/$current_user
Environment=PHPRC=$PHP_INI_FILE
# ImageMagick installs process-wide signal handlers without SA_ONSTACK; in
# FrankenPHP's threaded (ZTS) server that trips the Go runtime's "non-Go code
# set up signal handler without SA_ONSTACK flag" fatal (and the "panic during
# panic" 100%-CPU wedge). Disabling them lets a fault crash cleanly + restart.
Environment=MAGICK_SIGNAL_HANDLERS=0

[Install]
WantedBy=multi-user.target
EOM
        $SUDO_CMD chmod 644 "$cove_service_path"

        # Reload systemd, then enable and start the Cove FrankenPHP unit.
        # Mailpit was already enabled/restarted by install_mailpit_service.
        $SUDO_CMD systemctl daemon-reload
        $SUDO_CMD systemctl enable cove.service &>/dev/null
        # Stop any ad-hoc frankenphp started by a pre-1.10 cove_enable so
        # systemctl can take ownership of the listening sockets cleanly.
        "$CADDY_CMD" stop --config "$CADDYFILE_PATH" &>/dev/null \
            || $SUDO_CMD -n "$CADDY_CMD" stop --config "$CADDYFILE_PATH" &>/dev/null \
            || true
        $SUDO_CMD systemctl restart cove.service
    fi

    # Skip the ad-hoc Caddy start on Linux — systemd handles it now.
    if [ "$OS" != "linux" ]; then
        start_caddy_service
    fi

    # --- Watchdog ---
    # Installed last so the target service is already up when the first tick
    # fires. See cove_watchdog_tick() for why this exists.
    install_watchdog_service

    # Base the "Services are running" banner on Caddy actually answering, not
    # on the watchdog install's exit code (which is almost always 0 even when a
    # bad Caddyfile kept FrankenPHP from starting). Poll briefly — the admin
    # endpoint binds early but not instantly, especially on large installs.
    local caddy_up=false
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if is_caddy_running; then caddy_up=true; break; fi
        sleep 0.3
    done

    if [ "$caddy_up" = true ]; then
        echo ""
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 \
            "✅ Services are running" \
            "Dashboard: $(url_for cove.localhost)" \
            "Adminer:   $(url_for db.cove.localhost)" \
            "Mailpit:   $(url_for mail.cove.localhost)"
        
        # Show WSL-specific info
        if [ "$IS_WSL" = true ]; then
            local wsl_ip
            wsl_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
            echo ""
            gum style --foreground yellow "WSL Note: To access sites from Windows browser, update Windows hosts file."
            echo ""
            echo "  Run this in PowerShell (as Administrator):"
            echo ""
            echo "  Add-Content -Path C:\\Windows\\System32\\drivers\\etc\\hosts -Value \"\`n$wsl_ip cove.localhost db.cove.localhost mail.cove.localhost\""
            echo ""
            echo "  Or manually add this line to C:\\Windows\\System32\\drivers\\etc\\hosts:"
            echo "  $wsl_ip cove.localhost db.cove.localhost mail.cove.localhost"
            echo ""
            echo "  Note: WSL IP may change on restart. Run 'cove wsl-hosts' to get updated commands."
        fi
    else
        gum style --foreground red "❌ Caddy server failed to start. Check $LOGS_DIR/caddy-process.log for errors."
    fi
}
cove_health() {
    # Read-only diagnostic. Aggregates the signals you'd otherwise gather by
    # hand after a crash: service liveness, FrankenPHP process health + last
    # exit code, recent hard segfaults (classified), live OPcache pressure, and
    # on-disk hygiene. Never mutates anything — it only recommends fixes.
    local warn=0 crit=0
    echo ""
    gum style --bold "🩺 Cove health check"
    echo ""

    # --- Services -----------------------------------------------------------
    local caddy_up=false
    is_caddy_running && caddy_up=true
    echo "Services"
    if $caddy_up; then echo "  ✅ Caddy (FrankenPHP) running"; else echo "  ❌ Caddy not responding on :2019"; crit=$((crit+1)); fi
    if [ "$OS" = "macos" ]; then
        if is_mariadb_running; then echo "  ✅ MariaDB running"; else echo "  ❌ MariaDB stopped"; crit=$((crit+1)); fi
        if pgrep -x mailpit &>/dev/null; then echo "  ✅ Mailpit running"; else echo "  ⚠️  Mailpit stopped"; warn=$((warn+1)); fi
        # launchd's restart counter is the thrash tell: a healthy long-lived
        # mailpit sits at runs≈1–a few; an orphan-port fight climbs into the
        # tens of thousands (observed 51k). Surface it before the log fills.
        local mp_runs
        mp_runs=$(launchctl print "gui/$(id -u)/com.cove.mailpit" 2>/dev/null | awk '/^[[:space:]]*runs =/{print $3; exit}')
        if [ -n "$mp_runs" ] && [ "$mp_runs" -gt 20 ] 2>/dev/null; then
            echo "  ⚠️  Mailpit launchd has restarted $mp_runs times (orphan holding :1025/:8025?)"
            echo "     Fix: cove enable   (reinstalls the orphan-clearing mailpit runner)"
            warn=$((warn+1))
        fi
    else
        local mdb; mdb=$(get_mariadb_service_name)
        if systemctl is-active --quiet "$mdb" 2>/dev/null; then echo "  ✅ MariaDB running"; else echo "  ❌ MariaDB stopped"; crit=$((crit+1)); fi
        if systemctl is-active --quiet mailpit 2>/dev/null; then echo "  ✅ Mailpit running"; else echo "  ⚠️  Mailpit stopped"; warn=$((warn+1)); fi
    fi

    # --- FrankenPHP process + last exit code --------------------------------
    echo ""
    echo "FrankenPHP process"
    local fpid=""
    [ -f "$COVE_DIR/caddy.pid" ] && fpid=$(cat "$COVE_DIR/caddy.pid" 2>/dev/null)
    if [ -n "$fpid" ] && kill -0 "$fpid" 2>/dev/null; then
        # Uptime via ps etime (portable enough for display).
        local up; up=$(ps -o etime= -p "$fpid" 2>/dev/null | tr -d ' ')
        echo "  ✅ pid $fpid up ${up:-?}"
    else
        echo "  ⚠️  no live FrankenPHP pid on file"; warn=$((warn+1))
    fi
    # launchd's last-exit status is the crash tell: a negative value is the
    # signal that killed the previous instance (-11 = SIGSEGV). macOS only.
    if [ "$OS" = "macos" ]; then
        local last_exit
        last_exit=$(launchctl list 2>/dev/null | awk '$3=="com.cove.caddy"{print $2}')
        # Informational only (no warn++): launchd keeps showing the last
        # non-zero exit until the next clean restart, so this lingers long
        # after recovery. The crash section above owns severity (with recency).
        if [ -n "$last_exit" ] && [ "$last_exit" != "0" ]; then
            if [ "$last_exit" = "-11" ]; then
                echo "  ℹ️  last exit -11 (SIGSEGV) — a prior instance segfaulted (persists until next clean restart)"
            elif [ "$last_exit" = "-6" ]; then
                echo "  ℹ️  last exit -6 (SIGABRT) — a prior instance hit a Go fatal (PHP segfault turned abort)"
            elif [ "$last_exit" = "-9" ]; then
                # SIGKILL is what Cove's own watchdog sends, so this is usually
                # a deliberate restart of a wedged server — not a crash. Say so
                # rather than implying something went wrong unexplained.
                echo "  ℹ️  last exit -9 (SIGKILL) — a prior instance was killed, typically the watchdog restarting a wedged server"
            else
                echo "  ℹ️  last exit $last_exit — a prior instance died abnormally"
            fi
        fi
    fi

    # --- Recent hard crashes (macOS DiagnosticReports) ----------------------
    # Each .ips is one hard segfault. Classify by the culprit frames: the
    # OPcache-SHM path (this box's common cause) vs Imagick's signal-handler
    # bug vs anything else. grep the raw report — no JSON parser dependency.
    if [ "$OS" = "macos" ]; then
        echo ""
        echo "Hard crashes (last 24h)"
        local dr="$HOME/Library/Logs/DiagnosticReports"
        local oc_n=0 im_n=0 other_n=0 total=0 newest=""
        if [ -d "$dr" ]; then
            # -mtime -1 = within 24h. Null-safe loop.
            while IFS= read -r rpt; do
                [ -n "$rpt" ] || continue
                total=$((total+1))
                # Classify by culprit frames. OPcache SHM family is broad: the
                # crash can land in compile, persist, optimize, interned-string,
                # or shared-alloc frames — all the same root (arena corruption).
                # "other" is usually the same instability caught on a bystander
                # thread (e.g. a long-poll parked in sleep), not a compile frame.
                if grep -qE "cache_script_in_shared_memory|zend_persist|zend_accel|zend_optimize_script|zend_analyze_call|zend_shared_alloc|interned_string|lex_scan|zend_hash_func" "$rpt" 2>/dev/null; then
                    oc_n=$((oc_n+1))
                elif grep -qiE "MagickWand|Imagick|Magick" "$rpt" 2>/dev/null; then
                    im_n=$((im_n+1))
                else
                    other_n=$((other_n+1))
                fi
                # Track the true newest (find is unordered). Filename is
                # frankenphp-YYYY-MM-DD-HHMMSS.ips → strip prefix, drop dashes.
                local key; key=$(basename "$rpt" .ips | sed -E 's/^frankenphp-//; s/-//g')
                [ "$key" \> "$newest" ] && newest="$key"
            done < <(find "$dr" -name 'frankenphp-*.ips' -mtime -1 2>/dev/null)
        fi
        if [ "$total" -eq 0 ]; then
            echo "  ✅ none"
        else
            # Severity by recency. A real crash loop produces a crash every few
            # minutes, so a report in the last 5 min = actively looping
            # (critical). Older reports are history to note (warning) — notably
            # the single birth-crash that spawned a now-healthy process ages out
            # of the window within minutes. (A fixed window beats -newer on the
            # pidfile: macOS finalizes the crash report a second or two after the
            # crash, so the birth-crash report often lands just after the
            # respawned pidfile and would false-positive as "active".)
            local active5; active5=$(find "$dr" -name 'frankenphp-*.ips' -mmin -5 2>/dev/null | grep -c .)
            local nice_ts; nice_ts=$(echo "$newest" | sed -E 's/^[0-9]{8}([0-9]{2})([0-9]{2})([0-9]{2})$/\1:\2:\3/')
            if [ "$active5" -gt 0 ]; then
                echo "  ❌ $total in 24h ($active5 in last 5 min — ACTIVELY CRASHING); most recent $nice_ts"
                crit=$((crit+1))
            else
                echo "  ⚠️  $total in 24h; most recent $nice_ts (none in last 5 min — appears resolved)"
                warn=$((warn+1))
            fi
            [ "$oc_n"    -gt 0 ] && echo "     • $oc_n OPcache shared-memory (see OPcache section below)"
            [ "$im_n"    -gt 0 ] && echo "     • $im_n Imagick signal-handler (GD-editor MU-plugin should prevent — verify it's active)"
            [ "$other_n" -gt 0 ] && echo "     • $other_n other (bystander thread; usually the same OPcache instability)"
        fi
    fi

    # --- Live OPcache pressure ----------------------------------------------
    # The SHM is per-process, so we must ask the RUNNING server, not a fresh
    # php-cli (which would report an empty cache). Drop a probe into the
    # dashboard's own docroot ($GUI_DIR, served at cove.localhost), curl it,
    # remove it. Contained to Cove's dir — never touches a user's site.
    echo ""
    echo "OPcache pressure"
    if ! $caddy_up; then
        echo "  ⏭️  skipped (Caddy not running)"
    else
        local probe="_cove_health_oc_$$.php"
        cat > "$GUI_DIR/$probe" 2>/dev/null <<'PHP'
<?php
header('Content-Type: text/plain');
if (!function_exists('opcache_get_status')) { echo "noopcache\n"; exit; }
$s = @opcache_get_status(false); $c = @opcache_get_configuration();
if (!$s || !$c) { echo "disabled\n"; exit; }
$st = $s['opcache_statistics']; $is = $s['interned_strings_usage'];
$int_total = $is['used_memory'] + $is['free_memory'];
printf("hit_rate=%.1f\n", $st['opcache_hit_rate']);
printf("cached=%d\n", $st['num_cached_scripts']);
printf("maxfiles=%d\n", $c['directives']['opcache.max_accelerated_files']);
printf("interned_used_pct=%.0f\n", $int_total ? 100*$is['used_memory']/$int_total : 0);
printf("interned_mb=%.0f\n", $int_total/1048576);
printf("oom_restarts=%d\n", $st['oom_restarts']);
printf("hash_restarts=%d\n", $st['hash_restarts']);
printf("optimizer=%d\n", $c['directives']['opcache.optimization_level']);
PHP
        # Retry: a probe landing during a config reload hangs (the swap pauses
        # serving on a large box), which would otherwise look like a failure.
        local out="" attempt
        for attempt in 1 2 3; do
            out=$(curl -sk --max-time 12 "https://cove.localhost:${HTTPS_PORT}/$probe" 2>/dev/null)
            [ -n "$out" ] && break
            sleep 2
        done
        rm -f "$GUI_DIR/$probe" 2>/dev/null
        if [ -z "$out" ] || echo "$out" | grep -q "noopcache\|disabled"; then
            echo "  ⚠️  could not read OPcache status (${out:-no response; server may be mid-reload})"; warn=$((warn+1))
        else
            local hit cached maxf ipct imb oom hashr opt
            hit=$(echo "$out"   | sed -n 's/^hit_rate=//p')
            cached=$(echo "$out"| sed -n 's/^cached=//p')
            maxf=$(echo "$out"  | sed -n 's/^maxfiles=//p')
            ipct=$(echo "$out"  | sed -n 's/^interned_used_pct=//p')
            imb=$(echo "$out"   | sed -n 's/^interned_mb=//p')
            oom=$(echo "$out"   | sed -n 's/^oom_restarts=//p')
            hashr=$(echo "$out" | sed -n 's/^hash_restarts=//p')
            opt=$(echo "$out"   | sed -n 's/^optimizer=//p')
            echo "  interned buffer ${ipct}% full (${imb} MB) · cached ${cached}/${maxf} · hit ${hit}%"
            echo "  restarts: ${oom} OOM, ${hashr} max-files"
            local pressure=false
            [ "${ipct:-0}" -ge 85 ] 2>/dev/null && pressure=true
            [ "${oom:-0}" -gt 0 ] 2>/dev/null && pressure=true
            [ "${hashr:-0}" -gt 0 ] 2>/dev/null && pressure=true
            # cached within 10% of the cap = about to hash_restart
            if [ -n "$cached" ] && [ -n "$maxf" ] && [ "$maxf" -gt 0 ] 2>/dev/null; then
                [ $((cached*100/maxf)) -ge 90 ] 2>/dev/null && pressure=true
            fi
            if $pressure; then
                echo "  ⚠️  OPcache under pressure — SHM restarts under ZTS can segfault FrankenPHP."
                echo "     Raise limits in $PHP_INI_FILE, then fully restart FrankenPHP:"
                echo "       opcache.memory_consumption = 768"
                echo "       opcache.interned_strings_buffer = 128"
                echo "       opcache.max_accelerated_files = 200000"
                if [ "$OS" = "macos" ]; then
                    echo "     Restart: launchctl kickstart -k gui/\$(id -u)/com.cove.caddy"
                else
                    echo "     Restart: cove disable && cove enable"
                fi
                warn=$((warn+1))
            else
                echo "  ✅ within healthy limits"
            fi
            [ "${opt:-1}" != "0" ] && echo "  ℹ️  optimizer on (0x$(printf '%X' "${opt:-0}")); level 0 is recommended for dev (validate_timestamps recompiles constantly)"
        fi
    fi

    # --- On-disk hygiene ----------------------------------------------------
    echo ""
    echo "Hygiene"
    # Zombie skeletons: a Sites/ dir with no public/ and no custom directive —
    # the leftover a reload-racing-delete used to create (see delete/reload fix).
    local zombies=0 zlist=""
    if [ -d "$SITES_DIR" ]; then
        local sp bn
        for sp in "$SITES_DIR"/*; do
            [ -d "$sp" ] || continue
            bn=$(basename "$sp")
            if [ ! -d "$sp/public" ] && [ ! -f "$CUSTOM_CADDY_DIR/$bn" ]; then
                zombies=$((zombies+1)); zlist="$zlist $bn"
            fi
        done
    fi
    if [ "$zombies" -gt 0 ]; then
        echo "  ⚠️  $zombies zombie site dir(s):$zlist"
        echo "     Clear with: cove reload   (prunes public/-less skeletons)"
        warn=$((warn+1))
    else
        echo "  ✅ no zombie site directories"
    fi
    # Oversized logs (the process log grows on every restart; mailpit.log
    # balloons under a bind-failure KeepAlive thrash).
    local biglog=0 lf sz
    for lf in "$LOGS_DIR/caddy-process.log" "$LOGS_DIR/errors.log" "$LOGS_DIR/mailpit.log"; do
        [ -f "$lf" ] || continue
        sz=$(stat -f%z "$lf" 2>/dev/null || stat -c%s "$lf" 2>/dev/null || echo 0)
        if [ "$sz" -gt 52428800 ]; then
            echo "  ⚠️  $(basename "$lf") is $((sz/1048576)) MB"
            if [ "$(basename "$lf")" = "mailpit.log" ]; then
                echo "     (bind-failure thrash? reinstall with: cove enable)"
            fi
            biglog=$((biglog+1))
        fi
    done
    [ "$biglog" -eq 0 ] && echo "  ✅ logs within size limits"

    # --- Verdict ------------------------------------------------------------
    echo ""
    if [ "$crit" -gt 0 ]; then
        gum style --foreground red "❌ $crit critical, $warn warning(s) — see above."
    elif [ "$warn" -gt 0 ]; then
        gum style --foreground yellow "⚠️  $warn warning(s) — see above."
    else
        gum style --foreground green "✅ All healthy."
    fi
    echo ""
}

# A robust function to check, validate, and install a given dependency.
install_dependency() {
    local cmd_name="$1"      # The command to check for (e.g., "gum")
    local brew_pkg="$2"      # The package name for Homebrew (e.g., "gum")
    local apt_pkg="$3"       # The package name for apt (Debian/Ubuntu)
    local dnf_pkg="$4"       # The package name for dnf (Fedora/RHEL) - can differ from apt
    local binary_url="$5"    # Optional URL to a binary/tarball for fallback

    # If dnf_pkg not specified, default to apt_pkg
    if [ -z "$dnf_pkg" ]; then
        dnf_pkg="$apt_pkg"
    fi

    # 1. Validate the command. If it runs, we're done.
    if command -v "$cmd_name" &>/dev/null; then
        # Special cases: mariadb doesn't support --version, and wp's shebang
        # uses /usr/bin/env php which won't resolve since Cove no longer
        # installs a standalone php (wp-cli is invoked through frankenphp
        # php-cli at runtime — see get_wp_cmd in main).
        if [[ "$cmd_name" == "mariadb" || "$cmd_name" == "wp" ]] || "$cmd_name" --version &>/dev/null 2>&1; then
            echo "✅ $cmd_name is already installed and valid."
            return 0
        fi
    fi

    # If gum isn't installed yet, we can't use it for styling this first message.
    if ! command -v gum &>/dev/null; then
        echo "--- Installing Dependency: $cmd_name ---"
    else
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "Installing Dependency: $cmd_name"
    fi

    local installed_successfully=false
    local pkg_name=""

    # 2. Attempt installation with the native package manager.
    if [ "$OS" == "macos" ]; then
        if "$MAC_BREW" install "$brew_pkg"; then
            installed_successfully=true
        fi
    else # For Linux (apt/dnf)
        # Determine the correct package name for this distro
        if [ "$PKG_MANAGER" == "apt" ]; then
            pkg_name="$apt_pkg"
        else
            pkg_name="$dnf_pkg"
        fi
        
        # Only try native package manager if a name is provided
        if [ -n "$pkg_name" ]; then
            echo "   - Updating package cache..."
            if [ "$PKG_MANAGER" == "apt" ]; then
                $SUDO_CMD apt-get update -qq >/dev/null 2>&1
            else
                $SUDO_CMD dnf makecache -q >/dev/null 2>&1 || true
            fi
            
            echo "   - Installing $pkg_name via $PKG_MANAGER..."
            if [ "$PKG_MANAGER" == "apt" ]; then
                if $SUDO_CMD apt-get install -y "$pkg_name" >/dev/null 2>&1; then
                    installed_successfully=true
                fi
            else
                if $SUDO_CMD dnf install -y "$pkg_name" >/dev/null 2>&1; then
                    installed_successfully=true
                fi
            fi
        fi
        
        # 3. If native package fails or isn't specified, and a binary URL is provided, try that.
        if [ "$installed_successfully" = false ] && [ -n "$binary_url" ]; then
            if ! command -v gum &>/dev/null; then
                 echo "   - Native package not available. Falling back to binary download."
            else
                gum style --foreground "yellow" "   - Native package not available. Falling back to binary download."
            fi
            
            local temp_dir
            temp_dir=$(mktemp -d)
            
            # Check if URL is a tarball or direct binary
            if [[ "$binary_url" == *.tar.gz ]] || [[ "$binary_url" == *.tgz ]]; then
                # Minimal RHEL-family images (containers, cloud) ship without tar,
                # which makes the extraction below fail with no useful error.
                if ! command -v tar &>/dev/null; then
                    echo "   - Installing tar (required to extract)..."
                    if [ "$PKG_MANAGER" == "apt" ]; then
                        $SUDO_CMD apt-get install -y tar >/dev/null 2>&1
                    else
                        $SUDO_CMD dnf install -y tar >/dev/null 2>&1
                    fi
                fi
                echo "   - Downloading and extracting tarball..."
                if curl -sL "$binary_url" | tar -xz -C "$temp_dir"; then
                    # Find the binary in extracted contents
                    local binary_file
                    binary_file=$(find "$temp_dir" -name "$cmd_name" -type f -executable 2>/dev/null | head -1)
                    if [ -z "$binary_file" ]; then
                        # Try without executable flag (might need chmod)
                        binary_file=$(find "$temp_dir" -name "$cmd_name" -type f 2>/dev/null | head -1)
                    fi
                    if [ -n "$binary_file" ]; then
                        chmod +x "$binary_file"
                        if $SUDO_CMD mv "$binary_file" "$BIN_DIR/$cmd_name"; then
                            installed_successfully=true
                        fi
                    fi
                fi
            else
                # Direct binary download
                echo "   - Downloading binary..."
                if curl -sL "$binary_url" -o "$temp_dir/$cmd_name"; then
                    chmod +x "$temp_dir/$cmd_name"
                    if $SUDO_CMD mv "$temp_dir/$cmd_name" "$BIN_DIR/$cmd_name"; then
                        installed_successfully=true
                    fi
                fi
            fi
            rm -rf "$temp_dir"
        fi
    fi

    # 4. Final verification and cache clearing.
    if [ "$installed_successfully" = true ]; then
        hash -r # Clear the shell's command cache for this script session.
        if command -v "$cmd_name" &>/dev/null; then
            echo "✅ $cmd_name installed successfully."
            return 0
        else
            echo "⚠️  $cmd_name installed but not found in PATH. You may need to restart your shell."
            return 0
        fi
    else
        if command -v gum &>/dev/null; then
            gum style --foreground red "❌ Failed to install $cmd_name."
        else
            echo "❌ Failed to install $cmd_name."
        fi
        exit 1
    fi
}

cove_install() {
    local auto_yes=false
    local explicit_http=""
    local explicit_https=""
    local db_root_user=""
    local db_root_pass=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --yes|-y|--force)
                auto_yes=true
                shift
                ;;
            --http) explicit_http="$2"; shift 2 ;;
            --http=*) explicit_http="${1#*=}"; shift ;;
            --https) explicit_https="$2"; shift 2 ;;
            --https=*) explicit_https="${1#*=}"; shift ;;
            --db-root-user) db_root_user="$2"; shift 2 ;;
            --db-root-user=*) db_root_user="${1#*=}"; shift ;;
            --db-root-pass) db_root_pass="$2"; shift 2 ;;
            --db-root-pass=*) db_root_pass="${1#*=}"; shift ;;
            -h|--help)
                display_command_help install
                exit 0
                ;;
            *)
                echo "❌ Unknown argument: $1" >&2
                echo "Usage: cove install [--yes] [--http PORT] [--https PORT] [--db-root-user USER] [--db-root-pass PASS]" >&2
                exit 1
                ;;
        esac
    done

    # Explicit ports bypass both interactive port menus below entirely.
    if [ -n "$explicit_http" ] || [ -n "$explicit_https" ]; then
        local want_http="${explicit_http:-$HTTP_PORT}"
        local want_https="${explicit_https:-$HTTPS_PORT}"
        if [[ ! "$want_http" =~ ^[0-9]+$ ]] || [ "$want_http" -lt 1 ] || [ "$want_http" -gt 65535 ]; then
            echo "❌ Invalid HTTP port: $want_http" >&2; exit 1
        fi
        if [[ ! "$want_https" =~ ^[0-9]+$ ]] || [ "$want_https" -lt 1 ] || [ "$want_https" -gt 65535 ]; then
            echo "❌ Invalid HTTPS port: $want_https" >&2; exit 1
        fi
        if [ "$want_http" = "$want_https" ]; then
            echo "❌ HTTP and HTTPS ports must differ." >&2; exit 1
        fi
        HTTP_PORT="$want_http"
        HTTPS_PORT="$want_https"
    fi

    # Non-interactive callers (CI, installer piping, dashboards) have no TTY;
    # gum confirm / gum choose abort there. Auto-promote so the install doesn't
    # hang.
    [ -t 0 ] || auto_yes=true

    echo "🚀 Starting Cove installation..."

    # --- WSL/Systemd Check ---
    if [ "$OS" == "linux" ]; then
        if [ "$IS_WSL" = true ]; then
            echo "🐧 WSL environment detected."
            # Check if systemd is running
            if ! pidof systemd >/dev/null 2>&1; then
                echo ""
                echo "⚠️  WARNING: systemd is not running in WSL."
                echo "   Cove requires systemd for service management."
                echo ""
                echo "   To enable systemd in WSL2, add to /etc/wsl.conf:"
                echo "   [boot]"
                echo "   systemd=true"
                echo ""
                echo "   Then restart WSL with: wsl --shutdown"
                echo ""
                if $auto_yes; then
                    echo "   (--yes set — continuing anyway.)"
                else
                    read -p "Do you want to continue anyway? (y/N) " -n 1 -r
                    echo
                    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                        echo "🚫 Installation cancelled."
                        exit 0
                    fi
                fi
            fi
        fi
    fi

    # --- Gum (required for the port-selection UI that follows) ---
    # Note: gum releases use format: gum_VERSION_Linux_x86_64.tar.gz
    local gum_arch="x86_64"
    if [ "$(uname -m)" == "aarch64" ] || [ "$(uname -m)" == "arm64" ]; then
        gum_arch="arm64"
    fi
    local gum_url="https://github.com/charmbracelet/gum/releases/download/v0.14.1/gum_0.14.1_Linux_${gum_arch}.tar.gz"
    install_dependency "gum" "gum" "gum" "gum" "$gum_url"

    # --- Port Selection ---
    # Two paths can run here:
    #   1. Reconfigure path — saved config already has non-default ports; the
    #      user gets a menu to keep, switch to defaults, or pick new values.
    #   2. Conflict path — the target ports (post-reconfigure) are occupied
    #      by a non-Cove process; the user gets the conflict menu.
    # On a fresh install with free 80/443, both paths are skipped silently.
    # If the chosen ports differ from the starting values, a DB URL update
    # step runs after install services come up (same code path as `cove ports`).
    local original_http="$HTTP_PORT"
    local original_https="$HTTPS_PORT"
    local port_choice_made=false

    # Both menus below are gum choose, which aborts without a TTY. --yes (set
    # automatically when headless) and explicit --http/--https both mean "don't
    # ask" — keep whatever ports are configured and move on.
    local ports_decided=false
    if $auto_yes || [ -n "$explicit_http" ] || [ -n "$explicit_https" ]; then
        ports_decided=true
    fi

    # --- Reconfigure path ---
    if ! $ports_decided && { [ "$HTTP_PORT" != "80" ] || [ "$HTTPS_PORT" != "443" ]; }; then
        echo ""
        gum style --foreground "212" \
            "Cove is currently configured for custom ports: ${HTTP_PORT} / ${HTTPS_PORT}"
        echo ""

        local default_label="Switch to default ports (80 / 443)"
        if port_has_conflict 80 || port_has_conflict 443; then
            default_label="Switch to default ports (80 / 443) — currently in use"
        fi

        local choice
        choice=$(gum choose \
            "Keep current ports (${HTTP_PORT} / ${HTTPS_PORT})" \
            "$default_label" \
            "Pick different custom ports")

        case "$choice" in
            "Keep current"*)
                : # no change
                ;;
            "Switch to default"*)
                HTTP_PORT=80
                HTTPS_PORT=443
                ;;
            "Pick different"*)
                prompt_custom_ports 8090 8453
                ;;
        esac
        port_choice_made=true
    fi

    # --- Conflict path (for target ports post-reconfigure) ---
    local http_busy=false
    local https_busy=false
    port_has_conflict "$HTTP_PORT"  && http_busy=true
    port_has_conflict "$HTTPS_PORT" && https_busy=true

    if $http_busy || $https_busy; then
        echo ""
        echo "⚠️  Port Conflict Detected"
        echo ""
        if $http_busy; then
            local app
            app=$(port_listening_app "$HTTP_PORT")
            echo "   Port ${HTTP_PORT} is in use by: ${app:-another process}"
        fi
        if $https_busy; then
            local app
            app=$(port_listening_app "$HTTPS_PORT")
            echo "   Port ${HTTPS_PORT} is in use by: ${app:-another process}"
        fi
        echo ""

        # Headless (or --yes / explicit ports): report the conflict and carry
        # on with the requested ports rather than stalling on a menu. The
        # caller picked these deliberately, and re-running with
        # --http/--https is the way to change them.
        if $ports_decided; then
            echo "   Proceeding with ${HTTP_PORT}/${HTTPS_PORT} anyway."
            echo "   Re-run with --http PORT --https PORT to choose different ports."
            echo ""
        else

        echo "Cove needs an HTTP and HTTPS port. How would you like to proceed?"
        echo ""

        local choice
        choice=$(gum choose \
            "Use alternative ports (8090 / 8453) — run alongside other tools" \
            "Pick custom ports" \
            "Proceed with ${HTTP_PORT}/${HTTPS_PORT} anyway" \
            "Cancel installation")

        case "$choice" in
            "Use alternative ports"*)
                HTTP_PORT=8090
                HTTPS_PORT=8453
                if ! port_is_free "$HTTP_PORT" || ! port_is_free "$HTTPS_PORT"; then
                    gum style --foreground yellow \
                        "⚠️  8090 or 8453 is also in use — please pick custom ports."
                    prompt_custom_ports 8090 8453
                fi
                ;;
            "Pick custom ports")
                prompt_custom_ports 8090 8453
                ;;
            "Proceed with"*)
                gum style --foreground yellow \
                    "⚠️  Services may fail to bind on ${HTTP_PORT}/${HTTPS_PORT}."
                ;;
            "Cancel installation")
                echo "🚫 Installation cancelled."
                exit 1
                ;;
        esac
        fi
        port_choice_made=true
    fi

    if $port_choice_made; then
        gum style --foreground green \
            "✅ Using ports ${HTTP_PORT} (HTTP) / ${HTTPS_PORT} (HTTPS)"
    fi

    # Persist the final choice — regenerate_caddyfile and get_wp_cmd both
    # pick up the globals directly.
    config_set HTTP_PORT "$HTTP_PORT"
    config_set HTTPS_PORT "$HTTPS_PORT"

    # --- Pre-install Checks ---
    # $COVE_DIR alone isn't a reliable "previous install" marker — config_set
    # above creates it just to persist HTTP_PORT/HTTPS_PORT. Check for a
    # directory that only a completed install writes (Adminer), so the prompt
    # only fires when it's actually meaningful.
    if [ -d "$ADMINER_DIR" ]; then
        if ! $auto_yes && ! gum confirm "⚠️ Cove already appears to be installed at ~/Cove. Proceeding may overwrite some configurations. Continue?"; then
            echo "🚫 Installation cancelled."
            exit 0
        fi
    fi
    
    # FrankenPHP uses its own universal installer.
    # The upstream installer tries to write to /usr/local/bin and silently
    # falls back to CWD when that fails — which happens on a fresh Apple
    # Silicon Mac (Homebrew lives at /opt/homebrew/bin). To handle both,
    # we run the installer from a tempdir and, if the binary ends up there
    # instead of on PATH, move it into $BIN_DIR ourselves.
    if ! command -v frankenphp &> /dev/null; then
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "Installing Dependency: frankenphp"
        echo "   - Using the official FrankenPHP installer..."
        local fp_tmpdir
        fp_tmpdir=$(mktemp -d)
        if (cd "$fp_tmpdir" && curl -sL https://frankenphp.dev/install.sh | $SUDO_CMD bash); then
            hash -r
            if ! command -v frankenphp &> /dev/null && [ -x "$fp_tmpdir/frankenphp" ]; then
                $SUDO_CMD mv "$fp_tmpdir/frankenphp" "$BIN_DIR/frankenphp"
                $SUDO_CMD chmod +x "$BIN_DIR/frankenphp"
                hash -r
            fi
            rm -rf "$fp_tmpdir"
            if command -v frankenphp &> /dev/null; then
                echo "✅ FrankenPHP installed successfully."
            else
                gum style --foreground red "❌ FrankenPHP installer ran but the binary is not on PATH."
                exit 1
            fi
        else
            rm -rf "$fp_tmpdir"
            gum style --foreground red "❌ The FrankenPHP download script failed."
            exit 1
        fi
    else
        echo "✅ FrankenPHP is already installed."
    fi
    
    # On Linux with apt/dnf, FrankenPHP needs additional PHP extensions installed
    # The DEB/RPM packages don't include all extensions by default
    if [ "$OS" = "linux" ]; then
        echo "📦 Installing FrankenPHP PHP extensions for WordPress..."
        if [ "$PKG_MANAGER" = "apt" ]; then
            # Install required PHP extensions for WordPress via apt
            $SUDO_CMD apt install -y php-zts-mysqli php-zts-curl php-zts-gd php-zts-xml php-zts-mbstring php-zts-zip php-zts-intl php-zts-bcmath 2>/dev/null || true
            echo "✅ FrankenPHP PHP extensions installed."
        elif [ "$PKG_MANAGER" = "dnf" ]; then
            # Install required PHP extensions for WordPress via dnf
            $SUDO_CMD dnf install -y php-zts-mysqli php-zts-curl php-zts-gd php-zts-xml php-zts-mbstring php-zts-zip php-zts-intl php-zts-bcmath 2>/dev/null || true
            echo "✅ FrankenPHP PHP extensions installed."
        fi
        
        # Verify mysqli is available
        if ! frankenphp php-cli -r "echo implode(',', get_loaded_extensions());" 2>/dev/null | grep -qi mysqli; then
            gum style --foreground yellow "⚠️ Warning: mysqli extension not found in FrankenPHP."
            gum style --foreground yellow "   WordPress may not work correctly."
            gum style --foreground yellow "   Try: sudo apt install php-zts-mysqli (for apt)"
            gum style --foreground yellow "   Or:  sudo dnf install php-zts-mysqli (for dnf)"
        fi

        # Let FrankenPHP bind ports 80/443 as the user. Without this cap,
        # Cove would need to sudo-start the server, which makes every
        # dashboard-triggered file (sites, lock dirs, pidfile) root-owned.
        if command -v setcap &>/dev/null; then
            local fp_bin
            fp_bin=$(command -v frankenphp)
            if [ -n "$fp_bin" ]; then
                echo "🔐 Granting FrankenPHP cap_net_bind_service..."
                $SUDO_CMD setcap 'cap_net_bind_service=+ep' "$fp_bin" 2>/dev/null || \
                    gum style --foreground yellow "⚠️ setcap failed — Cove may fall back to needing sudo."
            fi
        fi

        # The apt `frankenphp` package ships a systemd unit that runs as
        # user `frankenphp` reading /etc/frankenphp/Caddyfile. That contends
        # with Cove for ports 80/443. Mask it so it stays out of our way.
        if systemctl list-unit-files frankenphp.service &>/dev/null \
            && systemctl cat frankenphp.service 2>/dev/null | grep -q '^\[Unit\]'; then
            echo "🚫 Masking conflicting apt frankenphp.service..."
            $SUDO_CMD systemctl stop frankenphp.service &>/dev/null || true
            $SUDO_CMD systemctl disable frankenphp.service &>/dev/null || true
            $SUDO_CMD systemctl mask frankenphp.service &>/dev/null || true
        fi
    fi

    # MariaDB - Database server
    install_dependency "mariadb" "mariadb" "mariadb-server" "mariadb-server" ""
    # Pin portable collation defaults before the first start (see
    # write_mariadb_config in main for the MariaDB 11.5+ uca1400 trap).
    write_mariadb_config || true

    # No standalone PHP install — wp-cli is invoked through `frankenphp php-cli`
    # (see get_wp_cmd in main), so FrankenPHP's bundled PHP is the single PHP
    # runtime for both web and CLI. On Linux the php-zts-* extensions installed
    # above provide WordPress's required extensions to FrankenPHP.

    # Mailpit - Email testing tool.
    # On macOS we use the Homebrew formula. On Linux we use the upstream
    # installer because mailpit isn't packaged in apt/dnf.
    # Why: the upstream installer hardcodes /usr/local/bin, which doesn't
    # exist on a fresh Apple Silicon Mac (Homebrew lives at /opt/homebrew).
    if [ "$OS" == "macos" ]; then
        install_dependency "mailpit" "mailpit" "" "" ""
    elif ! command -v mailpit &> /dev/null; then
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "Installing Dependency: mailpit"
        echo "   - Using the official Mailpit installer..."
        if curl -sL https://raw.githubusercontent.com/axllent/mailpit/develop/install.sh | $SUDO_CMD bash; then
            echo "✅ Mailpit installed successfully."
        else
            gum style --foreground red "❌ The Mailpit download script failed."
            exit 1
        fi
    else
        echo "✅ Mailpit is already installed."
    fi

    # WP-CLI - WordPress command line tool
    # Not in default Linux repos, so we use the phar download as fallback
    install_dependency "wp" "wp-cli" "" "" "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar"

    # --- Directory and Service Setup (Copied from original file) ---
    echo "📁 Creating Cove directory structure..."
    mkdir -p "$SITES_DIR" "$LOGS_DIR" "$GUI_DIR" "$ADMINER_DIR" "$CUSTOM_CADDY_DIR"

    # Write the PHP ini that wp-cli (via `frankenphp php-cli`) will load.
    # See the comment on $PHPRC export in main for the rationale.
    # error_reporting=6143 is E_ALL minus E_DEPRECATED/E_USER_DEPRECATED/E_STRICT
    # so wp-cli's bundled vendor code (react/promise, php-cli-tools/Colors.php)
    # doesn't flood every command on PHP 8.5+.
    echo "⚙️ Writing Cove PHP ini..."
    cat > "$PHP_INI_FILE" <<'INI'
memory_limit = 1G
display_errors = 0
error_reporting = 6143
INI
    echo "🗃️ Downloading Adminer 6.0.0..."
    curl -sL "https://github.com/vrana/adminer/releases/download/v6.0.0/adminer-6.0.0.php" -o "$ADMINER_DIR/adminer-core.php"
    # Entry point + theme assets. Keep in sync with cove_upgrade so upgraders
    # pick up index.php/head() and CSS/JS changes without a full reinstall.
    deploy_adminer_theme

    deploy_whoops

    # --- Fedora/RHEL SELinux labeling ---
    # The upstream FrankenPHP installer tags /usr/bin/frankenphp with the
    # httpd_exec_t file context. On Fedora/RHEL that triggers an exec-time
    # domain transition into httpd_t — a confined web-server domain that:
    #   - can't read files labeled user_home_t (fails to open ~/Cove/Caddyfile
    #     and ~/.local/share/caddy/pki/.../root.crt with "permission denied")
    #   - silently RSTs TLS connections under some configs (TCP accepts but
    #     the TLS ClientHello gets no response)
    # Neither failure logs an AVC — both are dontaudit'd. Retagging the binary
    # as bin_t keeps systemd running it in unconfined_service_t, which can
    # read user files normally. On non-SELinux distros (Debian/Ubuntu)
    # `semanage` isn't in $PATH and this block is a no-op.
    if [ "$OS" = "linux" ] && command -v semanage &>/dev/null; then
        local fp_bin
        fp_bin=$(command -v "$CADDY_CMD")
        if [ -n "$fp_bin" ]; then
            echo "🔐 Relabeling FrankenPHP for SELinux..."
            $SUDO_CMD semanage fcontext -a -t bin_t "$fp_bin" &>/dev/null \
                || $SUDO_CMD semanage fcontext -m -t bin_t "$fp_bin" &>/dev/null \
                || true
            $SUDO_CMD restorecon "$fp_bin" &>/dev/null || true
        fi
    fi

    echo "⚙️ Starting services..."
    if [ "$OS" == "macos" ]; then
        if ! start_macos_mariadb; then
            gum style --foreground red "❌ Failed to start MariaDB via ${MAC_BREW}."
            exit 1
        fi
    else # Linux
        if ! $SUDO_CMD systemctl restart mariadb; then
            gum style --foreground red "❌ Failed to start MariaDB via systemctl."
            exit 1
        fi
    fi

    # --- Database Configuration ---
    # Reuse saved DB creds if present. $CONFIG_FILE always exists at this
    # point (config_set above wrote HTTP_PORT/HTTPS_PORT), so probe for the
    # DB keys specifically rather than just the file.
    local has_db_config=false
    if [ -f "$CONFIG_FILE" ] && grep -q '^DB_USER=' "$CONFIG_FILE" 2>/dev/null; then
        has_db_config=true
    fi
    if $has_db_config && { $auto_yes || gum confirm "Existing Cove database config found. Use it and skip database setup?"; }; then
        echo "✅ Using existing database configuration."
    else
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "Configuring MariaDB"
        echo "   - Waiting for MariaDB service..."
        i=0
        while ! mysqladmin ping --silent; do
            sleep 1;
            i=$((i+1))
            if [ $i -ge 20 ]; then
                gum style --foreground red "❌ MariaDB did not become available in time."
                exit 1
            fi
        done
        echo "   - ✅ MariaDB is ready."
        local db_user="cove_user"
        local db_pass
        db_pass=$(cove_random_password 16)
        local sql_command="DROP USER IF EXISTS '$db_user'@'localhost'; CREATE USER '$db_user'@'localhost' IDENTIFIED BY '$db_pass'; GRANT ALL PRIVILEGES ON *.* TO '$db_user'@'localhost' WITH GRANT OPTION; FLUSH PRIVILEGES;"
        local user_created_successfully=false

        echo "   - Attempting automatic setup..."
        if echo "$sql_command" | $SUDO_CMD mysql &> /dev/null; then
            echo "   - ✅ Automatic database user creation successful."
            user_created_successfully=true
        else
            echo "   - ⚠️ Automatic setup failed. Falling back to manual credential entry..."
            local root_user="$db_root_user"
            local root_pass="$db_root_pass"
            if [ -z "$root_user" ]; then
                require_interactive "MariaDB root credentials (automatic setup failed)" "--db-root-user USER --db-root-pass PASS"
                root_user=$(gum input --value "root" --prompt "MariaDB Root Username: ")
                root_pass=$(gum input --password --placeholder "Password for '$root_user'")
            fi

            if echo "$sql_command" | mysql -u "$root_user" -p"$root_pass"; then
                echo "   - ✅ Manual database user creation successful."
                user_created_successfully=true
            fi
        fi

        if $user_created_successfully; then
            echo "   - 📝 Saving new configuration..."
            config_set DB_USER "$db_user"
            config_set DB_PASSWORD "$db_pass"
        else
            gum style --foreground red "❌ Database user creation failed. Please check credentials and MariaDB logs."
            exit 1
        fi
    fi
    
    # --- Finalize ---
    create_whoops_bootstrap
    create_gui_file
    regenerate_caddyfile

    echo "✅ Initial configuration complete. Starting services..."
    cove_enable

    # Install the local CA into the system trust store and any browser NSS
    # databases we can find. Needs Caddy up (for the admin API trust call)
    # and the root cert to exist (Caddy generated it during the initial
    # cove_enable above). Idempotent — users can re-run via `cove trust`.
    echo ""
    cove_trust

    # If the user changed HTTPS ports during install AND there are pre-existing
    # WordPress sites in $SITES_DIR, migrate their stored URLs to the new port.
    # On a fresh install with no sites, this is a silent no-op.
    if [ "$original_https" != "$HTTPS_PORT" ]; then
        if [ -d "$SITES_DIR" ] && [ -n "$(find "$SITES_DIR" -maxdepth 2 -name wp-config.php -print -quit 2>/dev/null)" ]; then
            echo ""
            echo "🔄 Updating WordPress site URLs to new HTTPS port..."
            update_wp_site_urls_for_port_change "$original_https" "$HTTPS_PORT"
        fi
    fi

    # Show post-install guidance
    echo ""
    if [ "$HTTPS_PORT" != "443" ]; then
        gum style --border normal --margin "1" --padding "1 2" --border-foreground "yellow" \
            "📋 First-Time Setup Notes" \
            "Cove is running on custom ports: HTTP ${HTTP_PORT} / HTTPS ${HTTPS_PORT}" \
            "Access the dashboard at: $(url_for cove.localhost)"
    else
        gum style --border normal --margin "1" --padding "1 2" --border-foreground "yellow" \
            "📋 First-Time Setup Notes"
    fi
    echo ""
    echo "  Your browser will show a certificate warning when accessing Cove sites."
    echo "  This is normal for local development with self-signed certificates."
    echo ""
    echo "  Options to resolve:"
    echo "    1. Click 'Advanced' and 'Proceed' to accept the certificate"
    echo "    2. Or trust Caddy's root CA certificate system-wide (recommended)"
    echo ""
    if [ "$OS" == "macos" ]; then
        echo "  On macOS, Caddy typically auto-trusts its CA. If not, the CA cert is at:"
        echo "    ~/Library/Application Support/Caddy/pki/authorities/local/root.crt"
    else
        echo "  On Linux, the CA certificate is located at:"
        echo "    ~/.local/share/caddy/pki/authorities/local/root.crt"
        echo ""
        echo "  To trust it system-wide (Ubuntu/Debian):"
        echo "    sudo cp ~/.local/share/caddy/pki/authorities/local/root.crt /usr/local/share/ca-certificates/caddy.crt"
        echo "    sudo update-ca-certificates"
        echo ""
        echo "  For browser-only trust, import the certificate in your browser settings."
    fi
    
    if [ "$IS_WSL" = true ]; then
        echo ""
        gum style --foreground yellow "  WSL: Run 'cove wsl-hosts' for Windows hosts file setup instructions."
    fi
}
# --- LAN Access Commands ---
# Enables local network access to Cove sites for mobile app sync

LAN_PORTS_FILE="$COVE_DIR/lan_ports"
LAN_START_PORT=8443

# Get the next available LAN port
get_next_lan_port() {
    local port=$LAN_START_PORT
    if [ -f "$LAN_PORTS_FILE" ]; then
        # Find the highest port in use and add 1
        local max_port
        max_port=$(cut -d'=' -f2 "$LAN_PORTS_FILE" | sort -n | tail -1)
        if [ -n "$max_port" ]; then
            port=$((max_port + 1))
        fi
    fi
    echo "$port"
}

# Get the assigned port for a site
get_site_lan_port() {
    local site_name="$1"
    if [ -f "$LAN_PORTS_FILE" ]; then
        grep "^${site_name}=" "$LAN_PORTS_FILE" | cut -d'=' -f2
    fi
}

# Get local network IP address
get_lan_ip() {
    if [ "$OS" == "macos" ]; then
        ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "unknown"
    else
        hostname -I 2>/dev/null | awk '{print $1}' || echo "unknown"
    fi
}

# Create Bonjour advertisement LaunchAgent
create_bonjour_service() {
    local site_name="$1"
    local port="$2"
    local service_name="com.cove.${site_name}.lan"
    local plist_path="$HOME/Library/LaunchAgents/${service_name}.plist"
    
    # Only supported on macOS
    if [ "$OS" != "macos" ]; then
        echo "   - Bonjour advertisement not supported on Linux (skipping)"
        return 0
    fi
    
    echo "   - Creating Bonjour advertisement for ${site_name}..."
    
    mkdir -p "$HOME/Library/LaunchAgents"
    
    cat > "$plist_path" << EOM
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${service_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/dns-sd</string>
        <string>-R</string>
        <string>${site_name}</string>
        <string>_beckon._tcp</string>
        <string>local</string>
        <string>${port}</string>
        <string>path=/</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOM
    
    # Load and start the service
    launchctl unload "$plist_path" &>/dev/null
    launchctl load "$plist_path"
    launchctl start "$service_name"
    
    echo "   - Bonjour service started: _beckon._tcp (${site_name})"
}

# Remove Bonjour advertisement LaunchAgent
remove_bonjour_service() {
    local site_name="$1"
    local service_name="com.cove.${site_name}.lan"
    local plist_path="$HOME/Library/LaunchAgents/${service_name}.plist"
    
    if [ "$OS" != "macos" ]; then
        return 0
    fi
    
    if [ -f "$plist_path" ]; then
        echo "   - Stopping Bonjour advertisement..."
        launchctl unload "$plist_path" &>/dev/null
        rm -f "$plist_path"
    fi
}

cove_lan_enable() {
    local site_name="$1"
    
    if [ -z "$site_name" ]; then
        gum style --foreground red "Error: Site name is required."
        echo "Usage: cove lan enable <site>"
        exit 1
    fi
    
    # Normalize site name (remove .localhost suffix if present)
    site_name="${site_name%.localhost}"
    
    local site_dir="$SITES_DIR/${site_name}.localhost"
    
    if [ ! -d "$site_dir" ]; then
        gum style --foreground red "Error: Site '${site_name}' not found."
        exit 1
    fi
    
    local lan_config="$site_dir/lan_config"
    
    if [ -f "$lan_config" ]; then
        local existing_port
        existing_port=$(grep "^port=" "$lan_config" | cut -d'=' -f2)
        gum style --foreground yellow "Site '${site_name}' already has LAN access enabled on port ${existing_port}."
        exit 0
    fi
    
    echo "Enabling LAN access for ${site_name}..."
    
    # Assign a port
    local port
    port=$(get_next_lan_port)
    
    # Save to lan_ports file
    echo "${site_name}=${port}" >> "$LAN_PORTS_FILE"
    
    # Create lan_config file in site directory
    echo "port=${port}" > "$lan_config"
    echo "enabled_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> "$lan_config"
    
    # Create Bonjour advertisement
    create_bonjour_service "$site_name" "$port"
    
    # Regenerate Caddyfile to include LAN binding
    regenerate_caddyfile
    
    local lan_ip
    lan_ip=$(get_lan_ip)
    
    echo ""
    gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 \
        "LAN Access Enabled for ${site_name}" \
        "" \
        "Port: ${port}" \
        "Local URL: $(url_for "${site_name}.localhost")" \
        "LAN URL: https://${lan_ip}:${port}" \
        "" \
        "Bonjour: _beckon._tcp (discoverable by iOS apps)" \
        "" \
        "Note: Mobile devices need to trust Caddy's CA certificate." \
        "Run 'cove lan trust' for instructions."
}

cove_lan_disable() {
    local site_name="$1"
    
    if [ -z "$site_name" ]; then
        gum style --foreground red "Error: Site name is required."
        echo "Usage: cove lan disable <site>"
        exit 1
    fi
    
    # Normalize site name
    site_name="${site_name%.localhost}"
    
    local site_dir="$SITES_DIR/${site_name}.localhost"
    local lan_config="$site_dir/lan_config"
    
    if [ ! -f "$lan_config" ]; then
        gum style --foreground yellow "Site '${site_name}' does not have LAN access enabled."
        exit 0
    fi
    
    echo "Disabling LAN access for ${site_name}..."
    
    # Remove Bonjour service
    remove_bonjour_service "$site_name"
    
    # Remove from lan_ports file
    if [ -f "$LAN_PORTS_FILE" ]; then
        grep -v "^${site_name}=" "$LAN_PORTS_FILE" > "${LAN_PORTS_FILE}.tmp"
        mv "${LAN_PORTS_FILE}.tmp" "$LAN_PORTS_FILE"
    fi
    
    # Remove lan_config file
    rm -f "$lan_config"
    
    # Regenerate Caddyfile
    regenerate_caddyfile
    
    gum style --foreground green "LAN access disabled for ${site_name}."
}

cove_lan_status() {
    echo "LAN Access Status"
    echo "================="
    echo ""
    
    local lan_ip
    lan_ip=$(get_lan_ip)
    echo "Your LAN IP: ${lan_ip}"
    echo ""
    
    local found_any=false
    
    if [ -d "$SITES_DIR" ]; then
        for site_path in "$SITES_DIR"/*; do
            if [ -d "$site_path" ]; then
                local site_name
                site_name=$(basename "$site_path")
                site_name="${site_name%.localhost}"
                
                local lan_config="$site_path/lan_config"
                if [ -f "$lan_config" ]; then
                    found_any=true
                    local port
                    port=$(grep "^port=" "$lan_config" | cut -d'=' -f2)
                    echo "  ${site_name}"
                    echo "    Port: ${port}"
                    echo "    LAN URL: https://${lan_ip}:${port}"
                    echo "    Bonjour: _beckon._tcp (${site_name})"
                    echo ""
                fi
            fi
        done
    fi
    
    if [ "$found_any" = false ]; then
        echo "  No sites have LAN access enabled."
        echo ""
        echo "  Enable LAN access for a site with:"
        echo "    cove lan enable <site>"
    fi
}

cove_lan_trust() {
    echo "Trusting Caddy's CA Certificate on Mobile Devices"
    echo "================================================="
    echo ""
    
    local ca_cert=""
    
    # Find Caddy's root CA certificate
    if [ "$OS" == "macos" ]; then
        ca_cert="$HOME/Library/Application Support/Caddy/pki/authorities/local/root.crt"
    else
        ca_cert="$HOME/.local/share/caddy/pki/authorities/local/root.crt"
    fi
    
    if [ ! -f "$ca_cert" ]; then
        gum style --foreground red "Error: Caddy's root CA certificate not found."
        echo "Expected location: $ca_cert"
        echo ""
        echo "Make sure Caddy has been started at least once with 'cove enable'."
        exit 1
    fi
    
    echo "Caddy's root CA certificate is located at:"
    echo "  $ca_cert"
    echo ""
    
    if [ "$OS" == "macos" ]; then
        echo "To trust this certificate on your iPhone/iPad:"
        echo ""
        echo "  1. AirDrop the certificate to your device:"
        gum style --foreground cyan "     Opening certificate location in Finder..."
        open -R "$ca_cert"
        echo ""
        echo "  2. On your iOS device, go to:"
        echo "     Settings > General > VPN & Device Management"
        echo "     Tap the certificate profile and install it."
        echo ""
        echo "  3. Then go to:"
        echo "     Settings > General > About > Certificate Trust Settings"
        echo "     Enable full trust for the Caddy root certificate."
        echo ""
    else
        echo "To trust this certificate on your mobile device:"
        echo ""
        echo "  1. Copy the certificate to your device (email, file transfer, etc.)"
        echo "  2. Install and trust the certificate in your device's settings"
        echo ""
    fi
    
    echo "Alternative: The Beckon iOS app can be configured to accept"
    echo "the self-signed certificate without system-wide trust."
}

cove_lan() {
    local action="$1"
    shift
    
    case "$action" in
        enable)
            cove_lan_enable "$@"
            ;;
        disable)
            cove_lan_disable "$@"
            ;;
        status)
            cove_lan_status "$@"
            ;;
        trust)
            cove_lan_trust "$@"
            ;;
        *)
            echo "Usage: cove lan <subcommand>"
            echo ""
            echo "Manage LAN access to Cove sites for mobile app sync."
            echo ""
            echo "Subcommands:"
            echo "  enable <site>    Enable LAN access for a site"
            echo "  disable <site>   Disable LAN access for a site"
            echo "  status           Show which sites have LAN access enabled"
            echo "  trust            Instructions for trusting Caddy's CA on mobile"
            exit 0
            ;;
    esac
}

cove_list() {
    local show_totals=false
    if [[ "$1" == "--totals" ]]; then
        show_totals=true
    fi

    # PHP script to find, sort, and format the site list with box-drawing characters
    local php_output
    php_output=$(SITES_DIR="$SITES_DIR" SHOW_TOTALS="$show_totals" HTTPS_PORT_SUFFIX="$(https_port_suffix)" WPVER_CACHE="$COVE_WPVER_CACHE" frankenphp php-cli -r '
        function getDirectorySize(string $path): int {
            if (!is_dir($path)) return 0;
            $total_size = 0;
            $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS));
            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $total_size += $file->getSize();
                }
            }
            return $total_size;
        }

        function formatSize(int $bytes): string {
            if ($bytes === 0) return "0 B";
            $units = ["B", "KB", "MB", "GB", "TB"];
            $i = floor(log($bytes, 1024));
            return round($bytes / (1024 ** $i), 2) . " " . $units[$i];
        }

        // Parsed rather than bootstrapped — see cove_wp_version in main for why.
        function wpVersion(string $public_path): ?string {
            $file = $public_path . "/wp-includes/version.php";
            if (!is_file($file)) return null;
            // The constant sits in the first few hundred bytes; no reason to
            // read the whole file 250 times.
            $head = @file_get_contents($file, false, null, 0, 4096);
            if ($head === false) return null;
            // This whole block is inside a single-quoted shell string, so the
            // apostrophe wrapping the version literal has to be built rather
            // than typed.
            $q = chr(39);
            $pattern = "/\\\$wp_version\\s*=\\s*" . $q . "([^" . $q . "]+)" . $q . "/";
            return preg_match($pattern, $head, $m) ? $m[1] : null;
        }

        $sites_dir = getenv("SITES_DIR");
        $show_totals = getenv("SHOW_TOTALS") === "true";
        $port_suffix = getenv("HTTPS_PORT_SUFFIX") ?: "";

        // wp.org marks every release latest / outdated / insecure. The dashboard
        // caches that map; reuse it when present so the list can flag a site
        // worth updating, and silently skip flagging when it is not.
        $status_map = [];
        $wpver_cache = getenv("WPVER_CACHE");
        if ($wpver_cache && is_file($wpver_cache)) {
            $cached = @json_decode(@file_get_contents($wpver_cache), true);
            if (is_array($cached)) {
                foreach ($cached as $entry) {
                    if (isset($entry["version"], $entry["status"])) {
                        $status_map[$entry["version"]] = $entry["status"];
                    }
                }
            }
        }

        if (!is_dir($sites_dir)) {
            exit;
        }

        $sites = [];
        $items = scandir($sites_dir);

        foreach ($items as $item) {
            if ($item === "." || $item === "..") continue;
            $site_path = $sites_dir . "/" . $item;
            if (is_dir($site_path)) {
                $public_path = $site_path . "/public";
                $size = $show_totals && is_dir($public_path) ? formatSize(getDirectorySize($public_path)) : null;
                $version = wpVersion($public_path);
                $status = $version !== null ? ($status_map[$version] ?? null) : null;
                $sites[] = [
                    "name" => str_replace(".localhost", "", $item),
                    "domain" => "https://" . $item . $port_suffix,
                    "type" => file_exists($site_path . "/multisite") ? "Multisite" : (file_exists($site_path . "/public/wp-config.php") ? "WordPress" : "Plain"),
                    "size" => $size,
                    // "!" marks a release wp.org considers insecure. Local sites
                    // are not exposed, so this is a nudge rather than an alarm.
                    // ASCII only: str_pad counts bytes, so a multibyte dash here
                    // would under-pad the column and skew the box border.
                    "wp" => $version === null ? "-" : $version . ($status === "insecure" ? " !" : ""),
                    // Per-site PHP pin (`cove php`); "-" = Cove default PHP.
                    "php" => is_file($site_path . "/php_version") ? trim((string) @file_get_contents($site_path . "/php_version")) : "-",
                ];
            }
        }

        if (empty($sites)) {
             exit;
        }

        // Sort the array: first by type, then by name
        array_multisort(
            array_column($sites, "type"), SORT_ASC,
            array_column($sites, "name"), SORT_ASC,
            $sites
        );

        // Column padding/gap
        $gap = 3;
        
        // Calculate column widths
        $name_width = max(array_map(fn($s) => strlen($s["name"]), $sites));
        $name_width = max($name_width, 4) + $gap;
        
        $domain_width = max(array_map(fn($s) => strlen($s["domain"]), $sites));
        $domain_width = max($domain_width, 6) + $gap;
        
        $type_width = 9 + $gap; // "WordPress" + gap

        // Sized from the content: versions run from "6.4" to "7.0-RC4 !".
        $wp_width = max(array_map(fn($s) => strlen($s["wp"]), $sites));
        $wp_width = max($wp_width, 2) + $gap;

        $php_width = max(array_map(fn($s) => strlen($s["php"]), $sites));
        $php_width = max($php_width, 3) + $gap;

        $size_width = $show_totals ? 11 : 0;

        // ANSI colors
        $pink = "\033[38;5;212m";
        $dim = "\033[2m";
        $reset = "\033[0m";

        // Box drawing characters
        $tl = "╭"; $tr = "╮"; $bl = "╰"; $br = "╯";
        $h = "─"; $v = "│";

        // Calculate total width
        $inner_width = $name_width + $domain_width + $type_width + $wp_width + $php_width;
        if ($show_totals) {
            $inner_width += $size_width;
        }

        // Build horizontal lines
        $top_line = $pink . $tl . str_repeat($h, $inner_width) . $tr . $reset;
        $mid_line = $pink . $v . $reset . $dim . " " . str_repeat("-", $inner_width - 2) . " " . $reset . $pink . $v . $reset;
        $bot_line = $pink . $bl . str_repeat($h, $inner_width) . $br . $reset;

        // Header row (white text)
        $header = $pink . $v . $reset . " " . str_pad("Name", $name_width - 1) . str_pad("Domain", $domain_width) . str_pad("Type", $type_width) . str_pad("WP", $wp_width) . str_pad("PHP", $php_width);
        if ($show_totals) {
            $header .= str_pad("Size", $size_width);
        }
        $header .= $pink . $v . $reset;

        // Output
        echo $top_line . "\n";
        echo $header . "\n";
        echo $mid_line . "\n";

        foreach ($sites as $site) {
            $row = $pink . $v . $reset . " " . str_pad($site["name"], $name_width - 1);
            $row .= str_pad($site["domain"], $domain_width);
            $row .= str_pad($site["type"], $type_width);
            $row .= str_pad($site["wp"], $wp_width);
            $row .= str_pad($site["php"], $php_width);
            if ($show_totals) {
                $row .= str_pad($site["size"] ?? "N/A", $size_width);
            }
            $row .= $pink . $v . $reset;
            echo $row . "\n";
        }

        echo $bot_line . "\n";
    ')

    if [ -z "$php_output" ]; then
        gum style --padding "1 2" "No sites found. Add one with 'cove add <name>'."
    else
        echo ""
        gum style --faint "Sites are located in ~/Cove/Sites/"
        echo ""
        echo "$php_output"
    fi
}
cove_log() {
    local site_name=""
    local follow_flag=""

    # Parse arguments
    for arg in "$@"; do
        case "$arg" in
            -f|--follow)
                follow_flag="-f"
                ;;
            *)
                if [[ -z "$site_name" ]]; then
                    site_name="$arg"
                fi
                ;;
        esac
    done

    # If no site specified, show the global error log
    if [[ -z "$site_name" ]]; then
        local log_file="$LOGS_DIR/errors.log"
        if [[ ! -f "$log_file" ]]; then
            echo "No global error log found at $log_file"
            exit 1
        fi

        if [[ -n "$follow_flag" ]]; then
            echo "Following global error log (Ctrl+C to stop)..."
            tail -f "$log_file"
        else
            echo "Global error log (last 50 lines):"
            echo ""
            tail -50 "$log_file"
        fi
        exit 0
    fi

    # Normalize site name
    local site_dir
    if [[ "$site_name" == *.localhost ]]; then
        site_dir="$SITES_DIR/$site_name"
    else
        site_dir="$SITES_DIR/${site_name}.localhost"
        site_name="${site_name}.localhost"
    fi

    if [[ ! -d "$site_dir" ]]; then
        echo "Site '$site_name' not found."
        exit 1
    fi

    local logs_dir="$site_dir/logs"
    if [[ ! -d "$logs_dir" ]]; then
        echo "No logs directory found for '$site_name'."
        exit 1
    fi

    # Find available log files
    local caddy_log="$logs_dir/caddy.log"
    local caddy_lan_log="$logs_dir/caddy-lan.log"

    # Determine which logs exist
    local available_logs=()
    [[ -f "$caddy_log" ]] && available_logs+=("$caddy_log")
    [[ -f "$caddy_lan_log" ]] && available_logs+=("$caddy_lan_log")

    if [[ ${#available_logs[@]} -eq 0 ]]; then
        echo "No log files found for '$site_name'."
        exit 1
    fi

    if [[ -n "$follow_flag" ]]; then
        echo "Following logs for $site_name (Ctrl+C to stop)..."
        tail -f "${available_logs[@]}"
    else
        echo "Logs for $site_name (last 50 lines each):"
        for log in "${available_logs[@]}"; do
            echo ""
            echo "--- $(basename "$log") ---"
            tail -50 "$log"
        done
    fi
}

cove_login() {
    local site_name="$1"
    local user_identifier="$2" # Optional second argument for the user

    # 1. Validate that a site name was provided.
    if [ -z "$site_name" ]; then
        gum style --foreground red "❌ Error: A site name is required."
        echo "Usage: cove login <site> [<user>]"
        exit 1
    fi

    # Reject traversal / metacharacters before the name builds a path we cd into
    # and run wp-cli against — otherwise `cove login ../x` targets a WordPress
    # install outside the Sites tree.
    if ! validate_site_name "$site_name"; then
        gum style --foreground red "❌ Error: Invalid site name '$site_name'."
        exit 1
    fi

    local site_dir="$SITES_DIR/$site_name.localhost"
    local public_dir="$site_dir/public"
    
    # Get WP-CLI command (adds --allow-root if running as root; uses the
    # site's pinned PHP when one is set)
    local wp_cmd
    wp_cmd=$(get_wp_cmd "$site_dir")

    # 2. Check if the site exists and is a WordPress installation.
    if [ ! -d "$site_dir" ] || [ ! -f "$public_dir/wp-config.php" ]; then
        gum style --foreground red "❌ Error: WordPress site '$site_name.localhost' not found."
        exit 1
    fi

    local admin_to_login
    if [ -n "$user_identifier" ]; then
        echo "🔎 Verifying user '$user_identifier' for '$site_name.localhost'..."
        local user_roles
        user_roles=$( (cd "$public_dir" && $wp_cmd user get "$user_identifier" --field=roles --format=json --skip-plugins --skip-themes 2>/dev/null) )

        if [ -z "$user_roles" ]; then
            gum style --foreground red "❌ Error: User '$user_identifier' not found on this site."
            exit 1
        fi

        if ! echo "$user_roles" | grep -q "administrator"; then
            gum style --foreground red "❌ Error: User '$user_identifier' is not an administrator."
            exit 1
        fi
        
        admin_to_login="$user_identifier"
        echo "✅ User '$admin_to_login' verified."
    else
        echo "🔎 Finding an administrator for '$site_name.localhost'..."
        admin_to_login=$( (cd "$public_dir" && $wp_cmd user list --role=administrator --field=user_login --format=csv --skip-plugins --skip-themes | head -n 1) )

        if [ -z "$admin_to_login" ]; then
            gum style --foreground red "❌ Error: Could not find any administrator users for this site."
            exit 1
        fi
        echo "✅ Found admin: '$admin_to_login'."
    fi

    # 3. Refresh the MU-plugin before generating the URL. Always overwrite
    # the file so sites created with older Cove versions pick up changes to
    # the plugin (token format, query-arg name, etc.) without needing a
    # re-add. The file is small and idempotent to regenerate.
    inject_mu_plugin "$public_dir"

    # 4. Generate the login URL.
    echo "   Generating login link..."
    local login_url
    login_url=$( (cd "$public_dir" && $wp_cmd user login "$admin_to_login" --skip-plugins --skip-themes) )

    # 5. Display the final URL or an error message.
    if [ -n "$login_url" ]; then
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "🔗 One-Time Login URL for '$admin_to_login'" "$login_url"
    else
        gum style --foreground red "❌ Error: Failed to generate the login link after all checks."
        exit 1
    fi
}
cove_mappings() {
    local site_name="$1"
    local action="$2"
    local domain="$3"

    # --- 1. Validation ---
    if [ -z "$site_name" ]; then
        gum style --foreground red "❌ Error: A site name is required."
        echo "Usage: cove mappings <site> [add|remove] [domain]"
        exit 1
    fi

    local site_dir="$SITES_DIR/$site_name.localhost"
    local mappings_file="$site_dir/mappings"

    if [ ! -d "$site_dir" ]; then
        gum style --foreground red "❌ Error: Site '$site_name.localhost' not found."
        exit 1
    fi

    # --- 2. List Mappings (Default Action) ---
    if [ -z "$action" ] || [ "$action" == "list" ]; then
        echo "🔎 Checking domain mappings for $site_name..."
        
        if [ ! -f "$mappings_file" ] || [ ! -s "$mappings_file" ]; then
             gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "ℹ️  No additional mappings found." "Main domain: $site_name.localhost"
        else
            local content
            content=$(cat "$mappings_file")
            gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "📂 Domain Mappings ($site_name)" "" "$content"
        fi
        return 0
    fi

    # --- 3. Add Mapping ---
    if [ "$action" == "add" ]; then
        if [ -z "$domain" ]; then
            gum style --foreground red "❌ Error: Please specify a domain to add."
            exit 1
        fi

        # Reject anything that isn't a bare hostname before it reaches the
        # Caddyfile and /etc/hosts (both generated from this file).
        if ! validate_hostname "$domain"; then
            gum style --foreground red "❌ Error: Invalid domain '$domain'." "Domains may contain only letters, numbers, dots, hyphens, and underscores (plus an optional leading '*.' wildcard)."
            exit 1
        fi

        # Simple validation: prevent duplicates
        if [ -f "$mappings_file" ] && grep -Fxq "$domain" "$mappings_file"; then
            gum style --foreground yellow "⚠️  Domain '$domain' is already mapped to this site."
            exit 0
        fi

        # Create file if not exists and append
        echo "$domain" >> "$mappings_file"
        echo "✅ Added mapping: $domain"
        
        regenerate_caddyfile
        update_etc_hosts
        return 0
    fi

    # --- 4. Remove Mapping ---
    if [ "$action" == "remove" ]; then
        if [ -z "$domain" ]; then
            gum style --foreground red "❌ Error: Please specify a domain to remove."
            exit 1
        fi

        if [ -f "$mappings_file" ]; then
            # Use grep to filter out the domain and write to a temp file
            if grep -Fxq "$domain" "$mappings_file"; then
                grep -Fxv "$domain" "$mappings_file" > "${mappings_file}.tmp"
                mv "${mappings_file}.tmp" "$mappings_file"
                echo "✅ Removed mapping: $domain"
                
                regenerate_caddyfile
                update_etc_hosts
            else
                gum style --foreground red "❌ Error: Mapping '$domain' not found."
            fi
        else
             gum style --foreground red "❌ Error: No mappings exist for this site."
        fi
        return 0
    fi

    # --- 5. Unknown Action ---
    gum style --foreground red "❌ Error: Unknown action '$action'."
    echo "Usage: cove mappings <site> [add|remove] [domain]"
    exit 1
}
cove_memory() {
    # -----------------------------------------------------------------
    #  cove memory [set <value>]
    #  Show or tweak PHP memory_limit across every ini Cove or the
    #  user's Homebrew PHPs load. Cove's own ini lives at
    #  ~/Cove/php.ini and is read by FrankenPHP (both CLI via PHPRC and
    #  the web server via the php_ini directive in the Caddyfile, which
    #  reads its values from the same file through cove_ini_get).
    # -----------------------------------------------------------------

    local action="show"
    local new_value=""
    local auto_yes=false

    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)
                display_command_help memory
                exit 0
                ;;
            set)
                action="set"
                new_value="$2"
                shift 2 || { gum style --foreground red "❌ 'set' requires a value (e.g. 2G)"; exit 1; }
                ;;
            --yes|-y|--force|--all)
                auto_yes=true
                shift
                ;;
            *)
                gum style --foreground red "❌ Unknown argument: $1"
                echo "Usage: cove memory [set <value>] [--yes]"
                exit 1
                ;;
        esac
    done

    if [ "$action" = "set" ]; then
        cove_memory_set "$new_value" "$auto_yes"
    else
        cove_memory_show
    fi
}

# Resolves the canonical path of a binary. Falls back to the original path
# if neither GNU readlink nor BSD-era greadlink is available.
cove_memory_realpath() {
    local p="$1"
    if readlink -f "$p" >/dev/null 2>&1; then
        readlink -f "$p"
    elif command -v greadlink >/dev/null 2>&1; then
        greadlink -f "$p"
    else
        echo "$p"
    fi
}

# Prints the php.ini path a given php binary loads, with surrounding
# whitespace and quotes trimmed (php --ini quotes the path when it
# contains special chars). PHPRC is unset so we see the ini each binary
# loads by default — without Cove's CLI override leaking in.
cove_memory_ini_for() {
    local php="$1"
    env -u PHPRC "$php" --ini 2>/dev/null \
        | awk -F': ' '/^Loaded Configuration File:/ {sub(/^[[:space:]]+/,"",$2); print $2}' \
        | sed -E 's/^"(.*)"$/\1/'
}

# Runs an inline PHP snippet against $1 without Cove's PHPRC, so the
# returned ini values reflect what the binary sees when the user invokes
# it from their own shell.
cove_memory_php_probe() {
    env -u PHPRC "$1" -r "$2" 2>/dev/null
}

cove_memory_show() {
    gum style --foreground "212" --bold "PHP memory_limit audit"
    echo ""

    # 1) Cove CLI ini
    local cove_mem
    cove_mem=$(cove_ini_get memory_limit "")
    echo "📁 Cove CLI  ($PHP_INI_FILE)"
    if [ -f "$PHP_INI_FILE" ]; then
        echo "   memory_limit         = ${cove_mem:-(unset — FrankenPHP default applies)}"
        echo "   upload_max_filesize  = $(cove_ini_get upload_max_filesize '(unset)')"
        echo "   post_max_size        = $(cove_ini_get post_max_size '(unset)')"
    else
        echo "   (file missing — run 'cove install')"
    fi

    # 2) Cove web server (Caddyfile frankenphp block)
    echo ""
    echo "🌐 Cove web ($CADDYFILE_PATH, frankenphp block)"
    if [ -f "$CADDYFILE_PATH" ]; then
        local caddy_mem
        caddy_mem=$(awk '/^[[:space:]]*php_ini[[:space:]]+memory_limit[[:space:]]+/ {print $3; exit}' "$CADDYFILE_PATH")
        if [ -n "$caddy_mem" ]; then
            echo "   memory_limit = $caddy_mem"
        else
            echo "   (no explicit memory_limit — inherits from ~/Cove/php.ini)"
        fi
    else
        echo "   (Caddyfile missing)"
    fi

    # 3) PHPs on PATH (dedup by canonical binary path)
    echo ""
    echo "🔍 PHP binaries on PATH"
    local seen_paths=""
    local php_path found=false
    while IFS= read -r php_path; do
        [ -z "$php_path" ] && continue
        local real_path
        real_path=$(cove_memory_realpath "$php_path")
        case ",$seen_paths," in *",$real_path,"*) continue ;; esac
        seen_paths="$seen_paths,$real_path"

        local php_ver php_ini php_mem
        php_ver=$(cove_memory_php_probe "$php_path" 'echo PHP_VERSION;')
        php_ini=$(cove_memory_ini_for "$php_path")
        php_mem=$(cove_memory_php_probe "$php_path" 'echo ini_get("memory_limit");')

        echo "   • $php_path"
        echo "       version       = ${php_ver:-unknown}"
        echo "       php.ini       = ${php_ini:-<none>}"
        echo "       memory_limit  = ${php_mem:-unknown}"
        found=true
    done < <(which -a php 2>/dev/null)
    if ! $found; then
        echo "   (no 'php' binary on PATH)"
    fi

    # 4) wp-cli's effective memory_limit (uses whichever php its shebang resolves)
    echo ""
    echo "🧰 wp-cli"
    local wp_bin
    wp_bin=$(command -v wp 2>/dev/null)
    if [ -n "$wp_bin" ]; then
        local wp_info wp_php wp_ver wp_mem
        wp_info=$(env -u PHPRC "$wp_bin" cli info 2>/dev/null)
        wp_php=$(echo "$wp_info" | awk -F':\t' '/^PHP binary:/ {sub(/^[[:space:]]+/,"",$2); print $2; exit}')
        wp_ver=$(echo "$wp_info" | awk -F':\t' '/^PHP version:/ {sub(/^[[:space:]]+/,"",$2); print $2; exit}')
        if [ -n "$wp_php" ] && [ -x "$wp_php" ]; then
            wp_mem=$(cove_memory_php_probe "$wp_php" 'echo ini_get("memory_limit");')
        fi
        echo "   wp             = $wp_bin"
        echo "   php binary     = ${wp_php:-unknown}"
        echo "   php version    = ${wp_ver:-unknown}"
        echo "   memory_limit   = ${wp_mem:-unknown}"
    else
        echo "   (wp-cli not found on PATH)"
    fi

    echo ""
    gum style --faint "To raise the limit everywhere: cove memory set 2G"
}

cove_memory_set() {
    local value="$1"
    local auto_yes="${2:-false}"

    if [ -z "$value" ]; then
        gum style --foreground red "❌ Missing value. Usage: cove memory set <value> (e.g. 2G)"
        exit 1
    fi

    # Non-interactive callers have no TTY; gum confirm aborts there. Auto-yes
    # so scripted fleet updates can bump every writable ini without hanging.
    [ -t 0 ] || auto_yes=true
    if [ "$value" != "-1" ] && [[ ! "$value" =~ ^[0-9]+[KMG]?$ ]]; then
        gum style --foreground red "❌ Invalid value '$value'. Use e.g. 512M, 2G, or -1 for unlimited."
        exit 1
    fi

    echo ""
    gum style --foreground "212" --bold "Setting memory_limit = $value"
    echo ""

    # 1) Cove CLI ini — source of truth for Cove
    mkdir -p "$(dirname "$PHP_INI_FILE")"
    touch "$PHP_INI_FILE"
    echo "📁 Updating $PHP_INI_FILE"
    local k
    for k in memory_limit upload_max_filesize post_max_size; do
        if grep -qE "^[[:space:]]*${k}[[:space:]]*=" "$PHP_INI_FILE"; then
            sed -i.bak -E "s|^[[:space:]]*${k}[[:space:]]*=.*|${k} = ${value}|" "$PHP_INI_FILE"
        else
            echo "${k} = ${value}" >> "$PHP_INI_FILE"
        fi
        echo "   ✓ ${k} = ${value}"
    done
    rm -f "${PHP_INI_FILE}.bak"

    # 2) Regenerate Caddyfile so FrankenPHP web server picks up the new values
    echo ""
    regenerate_caddyfile

    # 3) External PHP inis (Homebrew, distro-packaged) — opt-in per file.
    # Reads 'which -a php' on fd 3 so gum confirm inside the loop body can
    # read from the real stdin without swallowing the remaining PHP paths.
    echo ""
    echo "🔍 Scanning Homebrew / system PHP inis on PATH…"
    local seen_paths="" seen_inis=""
    local php_path
    while IFS= read -r php_path <&3; do
        [ -z "$php_path" ] && continue
        local real_path
        real_path=$(cove_memory_realpath "$php_path")
        case ",$seen_paths," in *",$real_path,"*) continue ;; esac
        seen_paths="$seen_paths,$real_path"

        local ini
        ini=$(cove_memory_ini_for "$php_path")
        [ -z "$ini" ] && continue
        # Skip Cove's ini (already handled) and duplicates
        [ "$(cove_memory_realpath "$ini")" = "$(cove_memory_realpath "$PHP_INI_FILE")" ] && continue
        case ",$seen_inis," in *",$ini,"*) continue ;; esac
        seen_inis="$seen_inis,$ini"

        local current
        current=$(grep -E "^[[:space:]]*memory_limit[[:space:]]*=" "$ini" 2>/dev/null \
            | tail -1 \
            | sed -E 's|^[[:space:]]*memory_limit[[:space:]]*=[[:space:]]*||' \
            | tr -d ' "')
        echo ""
        echo "   • $ini (current: ${current:-unset})"

        if ! [ -w "$ini" ]; then
            gum style --faint "     (not writable by this user — skipping. Run: sudo sed -i.bak -E 's|^[[:space:]]*memory_limit[[:space:]]*=.*|memory_limit = ${value}|' \"$ini\")"
            continue
        fi

        local do_update=false
        if [ "$auto_yes" = true ]; then
            do_update=true
        elif gum confirm "     Update this ini's memory_limit to ${value}?"; then
            do_update=true
        fi

        if $do_update; then
            if grep -qE "^[[:space:]]*memory_limit[[:space:]]*=" "$ini"; then
                sed -i.bak -E "s|^[[:space:]]*memory_limit[[:space:]]*=.*|memory_limit = ${value}|" "$ini"
            else
                echo "memory_limit = ${value}" >> "$ini"
            fi
            rm -f "${ini}.bak"
            gum style --foreground green "     ✓ Updated"
        else
            gum style --faint "     (skipped)"
        fi
    done 3< <(which -a php 2>/dev/null)

    echo ""
    gum style --foreground green "✅ Done. Run 'cove memory' to verify."
}

# --- macOS Menu Bar App ---
# Native menu bar companion (menubar/ in the repo), embedded into cove.sh at
# compile time and built locally with clang. Originally by Robby McCullough
# (github.com/RobbyMcCullough/cove-menubar, MIT), folded in with his blessing.
MENUBAR_APP_PATH="$HOME/Applications/Cove Menu Bar.app"

# Prints the CFBundleShortVersionString of the installed app, or nothing if the
# app is missing or the plist is unreadable (e.g. a pre-official install).
menubar_installed_version() {
    /usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" \
        "$MENUBAR_APP_PATH/Contents/Info.plist" 2>/dev/null
}

cove_menubar_enable() {
    local quiet="$1"

    if [ "$OS" != "macos" ]; then
        gum style --foreground red "❌ The menu bar app is only available on macOS."
        exit 1
    fi

    # clang ships with the Command Line Tools, which Homebrew already requires.
    if ! command -v clang &>/dev/null || ! xcode-select -p &>/dev/null; then
        gum style --foreground red "❌ Apple Command Line Tools are required to build the menu bar app."
        echo "   Install them with: xcode-select --install"
        exit 1
    fi

    local build_dir
    build_dir=$(mktemp -d)

    echo "🛠️  Building Cove Menu Bar v${MENUBAR_VERSION}..."

    # Write out the embedded sources. The Info.plist carries a version
    # placeholder so the installed bundle reports MENUBAR_VERSION — that is
    # what post-upgrade compares against to decide whether a rebuild is due.
    emit_menubar_main_m > "$build_dir/main.m"
    emit_menubar_info_plist | sed "s/__MENUBAR_VERSION__/${MENUBAR_VERSION}/g" > "$build_dir/Info.plist"
    emit_menubar_icon_svg > "$build_dir/cove-logo.svg"

    if ! clang \
        -fobjc-arc \
        -O2 \
        -Wall \
        -Wextra \
        -mmacosx-version-min=13.0 \
        -framework Cocoa \
        -framework CoreImage \
        -framework ServiceManagement \
        -framework UserNotifications \
        "$build_dir/main.m" \
        -o "$build_dir/CoveMenuBar"; then
        rm -rf "$build_dir"
        gum style --foreground red "❌ Failed to compile the menu bar app."
        exit 1
    fi

    # Generate the .icns from the bundled vector logo — every slot renders
    # crisp from the SVG, including the 1024px one. sips decoding SVG is
    # undocumented Apple behavior (CoreSVG, observed working since macOS 11),
    # so probe one conversion first and fail loudly rather than assemble a
    # bundle around a corrupt icon.
    local iconset_dir="$build_dir/CoveMenuBar.iconset"
    mkdir -p "$iconset_dir"
    if ! sips -s format png -z 16 16 "$build_dir/cove-logo.svg" \
            --out "$build_dir/icon-probe.png" >/dev/null 2>&1 \
        || ! sips -g pixelWidth "$build_dir/icon-probe.png" >/dev/null 2>&1; then
        rm -rf "$build_dir"
        gum style --foreground red "❌ This macOS could not rasterize the menu bar icon (SVG via sips)."
        exit 1
    fi
    local spec size name
    for spec in \
        "16 icon_16x16.png" \
        "32 icon_16x16@2x.png" \
        "32 icon_32x32.png" \
        "64 icon_32x32@2x.png" \
        "128 icon_128x128.png" \
        "256 icon_128x128@2x.png" \
        "256 icon_256x256.png" \
        "512 icon_256x256@2x.png" \
        "512 icon_512x512.png" \
        "1024 icon_512x512@2x.png"; do
        size="${spec%% *}"
        name="${spec#* }"
        sips -s format png -z "$size" "$size" "$build_dir/cove-logo.svg" \
            --out "$iconset_dir/$name" >/dev/null
    done
    iconutil -c icns "$iconset_dir" -o "$build_dir/CoveMenuBar.icns"

    # Replace any existing install — including a pre-official one from the
    # original standalone repo, which used the same bundle path.
    pkill -x CoveMenuBar 2>/dev/null || true
    rm -rf "$MENUBAR_APP_PATH"
    mkdir -p "$MENUBAR_APP_PATH/Contents/MacOS" "$MENUBAR_APP_PATH/Contents/Resources/Assets"
    cp "$build_dir/CoveMenuBar" "$MENUBAR_APP_PATH/Contents/MacOS/CoveMenuBar"
    cp "$build_dir/CoveMenuBar.icns" "$MENUBAR_APP_PATH/Contents/Resources/CoveMenuBar.icns"
    cp "$build_dir/cove-logo.svg" "$MENUBAR_APP_PATH/Contents/Resources/Assets/"
    cp "$build_dir/Info.plist" "$MENUBAR_APP_PATH/Contents/Info.plist"
    rm -rf "$build_dir"

    # Ad-hoc signing keeps Gatekeeper happy without notarization — the binary
    # was built on this machine, so there is no quarantine to clear.
    codesign --force --deep --sign - "$MENUBAR_APP_PATH" 2>/dev/null

    open "$MENUBAR_APP_PATH"

    if [ "$quiet" == "quiet" ]; then
        echo "   - Cove Menu Bar updated to v${MENUBAR_VERSION}."
        return 0
    fi

    echo ""
    gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 \
        "✅ Cove Menu Bar is enabled" \
        "Look for the Cove icon in your menu bar." \
        "It will stay up to date automatically via 'cove upgrade'." \
        "Remove it anytime with: cove menubar disable"
}

cove_menubar_disable() {
    if [ "$OS" != "macos" ]; then
        gum style --foreground red "❌ The menu bar app is only available on macOS."
        exit 1
    fi

    if [ ! -d "$MENUBAR_APP_PATH" ]; then
        echo "The menu bar app is not enabled."
        exit 0
    fi

    pkill -x CoveMenuBar 2>/dev/null || true
    # SMAppService login items can only be unregistered from inside the app
    # they belong to — run the binary's unregister mode before deleting the
    # bundle, or a stale entry lingers in System Settings → Login Items.
    "$MENUBAR_APP_PATH/Contents/MacOS/CoveMenuBar" unregister 2>/dev/null || true
    rm -rf "$MENUBAR_APP_PATH"
    echo "✅ Cove Menu Bar disabled and removed."
}

# Called from post-upgrade. Strictly opt-in: does nothing unless the app is
# already installed. Rebuilds only when the installed bundle's version differs
# from MENUBAR_VERSION (a missing/unreadable version — e.g. the original
# standalone install — counts as out of date and gets adopted).
menubar_refresh_if_enabled() {
    if [ "$OS" != "macos" ] || [ ! -d "$MENUBAR_APP_PATH" ]; then
        return 0
    fi

    local installed
    installed=$(menubar_installed_version)
    if [ "$installed" != "$MENUBAR_VERSION" ]; then
        echo "   - Menu bar app is v${installed:-unknown}; rebuilding as v${MENUBAR_VERSION}..."
        cove_menubar_enable quiet
    fi
}

cove_menubar() {
    local action="$1"
    shift 2>/dev/null || true

    case "$action" in
        enable)
            cove_menubar_enable
            ;;
        disable)
            cove_menubar_disable
            ;;
        *)
            echo "Usage: cove menubar <subcommand>"
            echo ""
            echo "Manage the native macOS menu bar companion app."
            echo "Shows service status at a glance and can start/stop Cove,"
            echo "open the Dashboard, Adminer, Mailpit, and logs."
            echo ""
            echo "Subcommands:"
            echo "  enable     Build, install, and launch the menu bar app (also updates it)"
            echo "  disable    Quit and remove the menu bar app"
            echo ""
            if [ "$OS" == "macos" ]; then
                local installed
                installed=$(menubar_installed_version)
                if [ -d "$MENUBAR_APP_PATH" ]; then
                    echo "Currently: enabled (v${installed:-unknown})"
                else
                    echo "Currently: disabled"
                fi
                echo ""
            fi
            echo "Once enabled, 'cove upgrade' keeps the app up to date automatically."
            exit 0
            ;;
    esac
}

cove_path() {
    local site_name="$1"

    if [ -z "$site_name" ]; then
        gum style --foreground red "❌ Error: A site name is required."
        echo "Usage: cove path <name>"
        exit 1
    fi

    local site_dir="$SITES_DIR/$site_name.localhost/public"

    if [ ! -d "$site_dir" ]; then
        gum style --foreground red "❌ Error: Site '$site_name.localhost' not found."
        exit 1
    fi

    echo "$site_dir"
}

# cove php — per-site PHP version switching.
#
# FrankenPHP (bundling the latest PHP) stays the front door for every site.
# Pinning a site to an older version swaps its Caddyfile handler from
# php_server to php_fastcgi against a Cove-managed Homebrew php-fpm on a unix
# socket. Service lifecycle + pool config live in main (write_php_fpm_config,
# sync_php_fpm_services, emit_site_php_handler); this file is the CLI.

# Make sure php@<ver>'s php-fpm is available, offering a brew install when
# the formula exists but isn't installed. Auto-confirms without a TTY so the
# dashboard and scripts can pin non-interactively. Returns non-zero when the
# binary still can't be resolved — callers must not write a php_version file
# in that case.
ensure_php_formula() {
    local ver="$1"
    if [ -n "$(php_fpm_prefix_for "$ver")" ]; then
        return 0
    fi
    if [ "$OS" != "macos" ] || [ "$MAC_BREW" != "brew" ]; then
        gum style --foreground red "❌ Per-site PHP versions currently require Homebrew on macOS." \
            "Cove serves everything with FrankenPHP's bundled PHP on this platform."
        return 1
    fi
    if ! brew info "php@$ver" &>/dev/null; then
        gum style --foreground red "❌ Error: Homebrew has no formula 'php@$ver'."
        return 1
    fi
    echo "📦 PHP $ver is not installed."
    if [ -t 0 ]; then
        if ! gum confirm "Install php@$ver via Homebrew now?"; then
            echo "Aborted."
            return 1
        fi
    else
        echo "   Installing php@$ver via Homebrew..."
    fi
    if ! brew install "php@$ver"; then
        gum style --foreground red "❌ Error: 'brew install php@$ver' failed."
        return 1
    fi
    if [ -z "$(php_fpm_prefix_for "$ver")" ]; then
        gum style --foreground red "❌ Error: php-fpm for PHP $ver still not found after install."
        return 1
    fi
    return 0
}

# The no-argument overview: every site's effective PHP, plus the state of the
# native php-fpm services backing the pins.
cove_php_overview() {
    local default_ver
    default_ver=$(frankenphp_php_version)
    echo "🐘 PHP versions (Cove default: ${default_ver:-unknown} via FrankenPHP)"
    echo ""
    if [ -d "$SITES_DIR" ]; then
        local site_path site_name ver
        for site_path in "$SITES_DIR"/*; do
            [ -d "$site_path/public" ] || continue
            site_name=$(basename "$site_path")
            ver=$(site_php_version "$site_path")
            if [ -n "$ver" ]; then
                printf "  %-42s %s\n" "$site_name" "$ver (php-fpm)"
            else
                printf "  %-42s %s\n" "$site_name" "default"
            fi
        done
    fi
    if [ "$OS" == "macos" ] && [ "$MAC_BREW" == "brew" ]; then
        echo ""
        local plist ver state found=false
        for plist in "$COVE_DIR"/com.cove.php-fpm-*.plist; do
            [ -f "$plist" ] || continue
            ver=$(basename "$plist" .plist)
            ver="${ver#com.cove.php-fpm-}"
            state="stopped"
            pgrep -f "php-fpm/$ver/php-fpm.conf" &>/dev/null && state="running"
            echo "  php-fpm $ver: $state ($RUN_DIR/php-$ver.sock)"
            found=true
        done
        if [ "$found" = false ]; then
            echo "  No native php-fpm services active. Pin one with: cove php <site> 8.2"
        fi
    fi
}

cove_php() {
    local site_name="$1"
    local requested="$2"

    if [ -z "$site_name" ]; then
        cove_php_overview
        return 0
    fi

    site_name="${site_name%.localhost}"
    local site_dir="$SITES_DIR/$site_name.localhost"
    if [ ! -d "$site_dir" ]; then
        gum style --foreground red "❌ Error: Site '$site_name.localhost' not found."
        exit 1
    fi

    # Show mode: no version argument.
    if [ -z "$requested" ]; then
        local pinned
        pinned=$(site_php_version "$site_dir")
        if [ -n "$pinned" ]; then
            echo "$site_name.localhost is pinned to PHP $pinned (native php-fpm)."
        else
            echo "$site_name.localhost uses Cove's default PHP $(frankenphp_php_version) (FrankenPHP)."
        fi
        return 0
    fi

    # Unpin: back to FrankenPHP.
    if [ "$requested" == "default" ]; then
        if [ ! -f "$site_dir/php_version" ]; then
            echo "ℹ️  $site_name.localhost already uses Cove's default PHP."
            return 0
        fi
        rm -f "$site_dir/php_version"
        regenerate_caddyfile
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 \
            "✅ $site_name.localhost back on Cove's default PHP $(frankenphp_php_version)" \
            "URL: $(url_for "$site_name.localhost")"
        return 0
    fi

    local ver
    ver=$(normalize_php_version "$requested")
    if [ -z "$ver" ]; then
        gum style --foreground red "❌ Error: Invalid PHP version '$requested'." \
            "Use a version like 8.2, php@8.3, or 'default'."
        exit 1
    fi

    # Pinning to FrankenPHP's own version means no pin at all — only OLDER
    # versions run on native FPM, per the feature's design.
    local default_mm
    default_mm=$(normalize_php_version "$(frankenphp_php_version)")
    if [ -n "$default_mm" ] && [ "$ver" == "$default_mm" ]; then
        echo "ℹ️  PHP $ver is Cove's default (FrankenPHP); nothing to pin."
        if [ -f "$site_dir/php_version" ]; then
            rm -f "$site_dir/php_version"
            regenerate_caddyfile
            echo "   Removed the existing pin."
        fi
        return 0
    fi

    if ! ensure_php_formula "$ver"; then
        exit 1
    fi

    echo "📌 Pinning $site_name.localhost to PHP $ver (native php-fpm behind FrankenPHP)..."
    echo "$ver" > "$site_dir/php_version"
    regenerate_caddyfile

    # Same warm-poll as cove add: the reload is synchronous, but give the new
    # fastcgi upstream a beat to accept its first connection.
    local warm_url
    warm_url=$(url_for "$site_name.localhost")
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if curl -ks --max-time 1 -o /dev/null "$warm_url/" 2>/dev/null; then
            break
        fi
        sleep 0.2
    done

    gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 \
        "✅ $site_name.localhost is now running PHP $ver" \
        "URL: $warm_url"
}

cove_ports() {
    # -----------------------------------------------------------------
    #  cove ports
    #  Reconfigure the HTTP / HTTPS ports Cove listens on and (by
    #  default) migrate every WordPress site's stored URLs via
    #  `wp search-replace` so they match the new port.
    #
    #  Flags:
    #    --http PORT     Non-interactive: set HTTP port
    #    --https PORT    Non-interactive: set HTTPS port
    #    --skip-urls     Change ports without touching WordPress databases
    #    --dry-run       Preview changes (including search-replace counts)
    #                    without committing anything
    # -----------------------------------------------------------------

    local explicit_http=""
    local explicit_https=""
    local skip_urls=false
    local dry_run=false
    local auto_yes=false

    while [ $# -gt 0 ]; do
        case "$1" in
            --http)
                explicit_http="$2"
                shift 2
                ;;
            --https)
                explicit_https="$2"
                shift 2
                ;;
            --skip-urls)
                skip_urls=true
                shift
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            --yes|-y|--force)
                auto_yes=true
                shift
                ;;
            -h|--help)
                display_command_help ports
                exit 0
                ;;
            *)
                gum style --foreground red "❌ Unknown option: $1"
                echo "Usage: cove ports [--http PORT] [--https PORT] [--skip-urls] [--dry-run] [--yes]"
                exit 1
                ;;
        esac
    done

    # Non-interactive shells (PHP shell_exec, ssh piped stdin, systemd) have
    # no TTY; gum confirm aborts there with "could not open a new TTY". Auto-
    # promote to --yes so the caller's flags are respected.
    if [ ! -t 0 ]; then
        auto_yes=true
    fi

    local original_http="$HTTP_PORT"
    local original_https="$HTTPS_PORT"

    # --- Determine target ports ---
    if [ -n "$explicit_http" ] || [ -n "$explicit_https" ]; then
        # Non-interactive path — validate and apply.
        local target_http="${explicit_http:-$HTTP_PORT}"
        local target_https="${explicit_https:-$HTTPS_PORT}"

        if [[ ! "$target_http" =~ ^[0-9]+$ ]] || [ "$target_http" -lt 1 ] || [ "$target_http" -gt 65535 ]; then
            gum style --foreground red "❌ Invalid HTTP port: $target_http"
            exit 1
        fi
        if [[ ! "$target_https" =~ ^[0-9]+$ ]] || [ "$target_https" -lt 1 ] || [ "$target_https" -gt 65535 ]; then
            gum style --foreground red "❌ Invalid HTTPS port: $target_https"
            exit 1
        fi
        if [ "$target_http" = "$target_https" ]; then
            gum style --foreground red "❌ HTTP and HTTPS ports must differ."
            exit 1
        fi

        HTTP_PORT="$target_http"
        HTTPS_PORT="$target_https"
    else
        # Interactive menu
        echo ""
        gum style --foreground "212" \
            "Cove is currently on ports: HTTP ${HTTP_PORT} / HTTPS ${HTTPS_PORT}"
        echo ""

        local default_label="Switch to default ports (80 / 443)"
        if [ "$HTTP_PORT" != "80" ] || [ "$HTTPS_PORT" != "443" ]; then
            if port_has_conflict 80 || port_has_conflict 443; then
                default_label="Switch to default ports (80 / 443) — currently in use"
            fi
        fi

        local alt_label="Use alternative ports (8090 / 8453)"
        if [ "$HTTP_PORT" = "8090" ] && [ "$HTTPS_PORT" = "8453" ]; then
            alt_label=""
        elif port_has_conflict 8090 || port_has_conflict 8453; then
            alt_label="Use alternative ports (8090 / 8453) — currently in use"
        fi

        local -a menu_opts
        menu_opts=("Keep current ports (${HTTP_PORT} / ${HTTPS_PORT})")
        if [ "$HTTP_PORT" != "80" ] || [ "$HTTPS_PORT" != "443" ]; then
            menu_opts+=("$default_label")
        fi
        if [ -n "$alt_label" ]; then
            menu_opts+=("$alt_label")
        fi
        menu_opts+=("Pick custom ports" "Cancel")

        local choice
        choice=$(gum choose "${menu_opts[@]}")

        case "$choice" in
            "Keep current"*)
                echo "ℹ️  No changes."
                exit 0
                ;;
            "Switch to default"*)
                HTTP_PORT=80
                HTTPS_PORT=443
                ;;
            "Use alternative"*)
                HTTP_PORT=8090
                HTTPS_PORT=8453
                ;;
            "Pick custom ports")
                prompt_custom_ports 8090 8453
                ;;
            "Cancel"|*)
                echo "🚫 Cancelled."
                exit 0
                ;;
        esac
    fi

    # --- Check if anything actually changed ---
    if [ "$original_http" = "$HTTP_PORT" ] && [ "$original_https" = "$HTTPS_PORT" ]; then
        echo "ℹ️  Ports unchanged."
        exit 0
    fi

    # --- Preview ---
    echo ""
    gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 \
        "Port change:" \
        "  HTTP:  ${original_http} → ${HTTP_PORT}" \
        "  HTTPS: ${original_https} → ${HTTPS_PORT}"

    if ! $skip_urls && [ "$original_https" != "$HTTPS_PORT" ]; then
        echo ""
        local any_wp=false
        if [ -d "$SITES_DIR" ]; then
            local site_path site_name
            for site_path in "$SITES_DIR"/*; do
                [ -d "$site_path" ] || continue
                [ -f "$site_path/public/wp-config.php" ] || continue
                if ! $any_wp; then
                    echo "The following WordPress sites will have stored URLs updated:"
                    any_wp=true
                fi
                site_name=$(basename "$site_path")
                echo "   • ${site_name}: $(port_url_for "$site_name" "$original_https") → $(port_url_for "$site_name" "$HTTPS_PORT")"
            done
        fi
        if ! $any_wp; then
            echo "(No WordPress sites to update.)"
        fi
    elif $skip_urls; then
        echo ""
        gum style --faint "(--skip-urls: WordPress databases will NOT be updated)"
    fi

    # --- Dry run exits here ---
    if $dry_run; then
        echo ""
        echo "🔍 Dry run: running wp search-replace --dry-run..."
        echo ""
        if ! $skip_urls; then
            update_wp_site_urls_for_port_change "$original_https" "$HTTPS_PORT" --dry-run
        fi
        # Revert globals so nothing leaks to the caller
        HTTP_PORT="$original_http"
        HTTPS_PORT="$original_https"
        echo ""
        gum style --faint "Dry run complete. No changes committed."
        exit 0
    fi

    # --- Confirm ---
    echo ""
    if [ "$auto_yes" = false ]; then
        if ! gum confirm "Proceed with the port change?"; then
            # Revert globals so nothing leaks to the caller
            HTTP_PORT="$original_http"
            HTTPS_PORT="$original_https"
            echo "🚫 Cancelled."
            exit 0
        fi
    fi

    # --- Commit ---
    echo ""
    echo "💾 Saving port configuration..."
    config_set HTTP_PORT "$HTTP_PORT"
    config_set HTTPS_PORT "$HTTPS_PORT"

    if ! $skip_urls && [ "$original_https" != "$HTTPS_PORT" ]; then
        echo ""
        echo "🔄 Updating WordPress site URLs..."
        update_wp_site_urls_for_port_change "$original_https" "$HTTPS_PORT"
    fi

    echo ""
    regenerate_caddyfile

    echo ""
    cove_enable

    echo ""
    gum style --foreground green "✅ Cove is now on ports ${HTTP_PORT} / ${HTTPS_PORT}"
    if [ "$HTTPS_PORT" != "443" ]; then
        gum style --faint "   Dashboard: $(url_for cove.localhost)"
    fi
}

# --- Proxy Storage Directory ---
PROXY_DIR="$APP_DIR/proxies"

# --- Helper to get LAN IP (may already exist in main, but define here for safety) ---
get_lan_ip() {
    if [ "$OS" == "macos" ]; then
        ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "127.0.0.1"
    else
        hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1"
    fi
}

cove_proxy_add() {
    local name=""
    local domain=""
    local target=""
    local tls_mode="internal"
    local force=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --no-tls)
                tls_mode="none"
                shift
                ;;
            --force|--yes|-y)
                force=true
                shift
                ;;
            *)
                if [ -z "$name" ]; then
                    name="$1"
                elif [ -z "$domain" ]; then
                    domain="$1"
                elif [ -z "$target" ]; then
                    target="$1"
                fi
                shift
                ;;
        esac
    done

    # Without a TTY, gum confirm can't prompt — treat as --force so scripted
    # callers (dashboard, CI) can overwrite safely.
    [ -t 0 ] || force=true

    # Interactive mode if arguments not provided. All three values are
    # positional, so a headless caller supplies them on the command line
    # rather than hitting a prompt it can't answer.
    if [ -z "$name" ]; then
        require_interactive "The proxy name" "it positionally: cove proxy add <name> <domain> <target>"
        echo "📝 Adding a new reverse proxy entry..."
        name=$(gum input --width 0 --placeholder "Proxy name (e.g., opencode)")
    fi

    if [ -z "$name" ]; then
        gum style --foreground red "❌ Error: Proxy name is required."
        exit 1
    fi

    # Validate name (alphanumeric and hyphens only)
    if ! [[ "$name" =~ ^[a-zA-Z0-9-]+$ ]]; then
        gum style --foreground red "❌ Error: Proxy name must contain only letters, numbers, and hyphens."
        exit 1
    fi

    local proxy_file="$PROXY_DIR/$name"

    # Check if proxy already exists
    if [ -f "$proxy_file" ] && ! $force; then
        if ! gum confirm "⚠️ Proxy '$name' already exists. Overwrite?"; then
            echo "🚫 Cancelled."
            exit 0
        fi
    fi

    if [ -z "$domain" ]; then
        require_interactive "The proxy domain" "it positionally: cove proxy add <name> <domain> <target>"
        domain=$(gum input --width 0 --placeholder "Domain to listen on (e.g., myhost.tailnet.ts.net)")
    fi

    if [ -z "$domain" ]; then
        gum style --foreground red "❌ Error: Domain is required."
        exit 1
    fi

    # Reject anything but a bare hostname before it becomes a Caddyfile domain
    # label — otherwise the value can inject an arbitrary server block.
    if ! validate_hostname "$domain"; then
        gum style --foreground red "❌ Error: Invalid domain '$domain'." "Domains may contain only letters, numbers, dots, hyphens, and underscores (plus an optional leading '*.' wildcard)."
        exit 1
    fi

    if [ -z "$target" ]; then
        require_interactive "The proxy target" "it positionally: cove proxy add <name> <domain> <target>"
        target=$(gum input --width 0 --placeholder "Target to proxy to (e.g., 127.0.0.1:4096)")
    fi

    if [ -z "$target" ]; then
        gum style --foreground red "❌ Error: Target is required."
        exit 1
    fi

    # Constrain to host[:port] so it can't break out of the reverse_proxy line.
    if ! validate_proxy_target "$target"; then
        gum style --foreground red "❌ Error: Invalid proxy target '$target'." "Targets may contain only letters, numbers, dots, hyphens, underscores, and a port colon (e.g. 127.0.0.1:4096)."
        exit 1
    fi

    # Create proxy directory if it doesn't exist
    mkdir -p "$PROXY_DIR"

    # Save the proxy configuration
    cat > "$proxy_file" << EOF
domain=$domain
target=$target
tls=$tls_mode
EOF

    echo "✅ Proxy '$name' created:"
    echo "   Domain: $domain"
    echo "   Target: $target"
    echo "   TLS: $tls_mode"

    regenerate_caddyfile
}

cove_proxy_list() {
    echo "🔎 Listing all reverse proxy entries..."
    echo ""

    if [ ! -d "$PROXY_DIR" ] || [ -z "$(ls -A "$PROXY_DIR" 2>/dev/null)" ]; then
        gum style --foreground "yellow" "ℹ️ No proxy entries found."
        echo ""
        echo "Add one with: cove proxy add <name> <domain> <target>"
        exit 0
    fi

    # Print header
    printf "%-15s %-40s %-25s %-10s\n" "NAME" "DOMAIN" "TARGET" "TLS"
    printf "%-15s %-40s %-25s %-10s\n" "----" "------" "------" "---"

    for proxy_file in "$PROXY_DIR"/*; do
        if [ -f "$proxy_file" ]; then
            local name
            name=$(basename "$proxy_file")
            
            local domain=""
            local target=""
            local tls="internal"

            # Read the config file
            while IFS='=' read -r key value; do
                case "$key" in
                    domain) domain="$value" ;;
                    target) target="$value" ;;
                    tls) tls="$value" ;;
                esac
            done < "$proxy_file"

            printf "%-15s %-40s %-25s %-10s\n" "$name" "$domain" "$target" "$tls"
        fi
    done
}

cove_proxy_delete() {
    local name=""
    local force=false
    for arg in "$@"; do
        case "$arg" in
            --force|--yes|-y) force=true ;;
            -*)
                gum style --foreground red "❌ Unknown option: $arg"
                echo "Usage: cove proxy delete <name> [--force]"
                exit 1
                ;;
            *) [ -z "$name" ] && name="$arg" ;;
        esac
    done

    if [ -z "$name" ]; then
        # Interactive mode - let user select from existing proxies
        if [ ! -d "$PROXY_DIR" ] || [ -z "$(ls -A "$PROXY_DIR" 2>/dev/null)" ]; then
            gum style --foreground "yellow" "ℹ️ No proxy entries to delete."
            exit 0
        fi

        require_interactive "Choosing a proxy to delete" "the proxy name as an argument: cove proxy delete <name>"
        echo "🗑️ Select a proxy to delete:"
        name=$(ls "$PROXY_DIR" | gum choose)

        if [ -z "$name" ]; then
            echo "🚫 Cancelled."
            exit 0
        fi
    fi

    local proxy_file="$PROXY_DIR/$name"

    if [ ! -f "$proxy_file" ]; then
        gum style --foreground red "❌ Error: Proxy '$name' not found."
        exit 1
    fi

    # Show what will be deleted
    echo "Proxy '$name' configuration:"
    cat "$proxy_file"
    echo ""

    # Non-interactive callers have no TTY; auto-force so scripted deletes work.
    [ -t 0 ] || force=true

    if ! $force; then
        if ! gum confirm "🚨 Are you sure you want to delete proxy '$name'?"; then
            echo "🚫 Deletion cancelled."
            return 0
        fi
    fi
    rm "$proxy_file"
    echo "✅ Proxy '$name' deleted."
    regenerate_caddyfile
}

cove_proxy() {
    local action="$1"
    shift 2>/dev/null || true

    case "$action" in
        add)
            cove_proxy_add "$@"
            ;;
        list|ls)
            cove_proxy_list
            ;;
        delete|rm)
            cove_proxy_delete "$@"
            ;;
        *)
            echo "Usage: cove proxy <subcommand>"
            echo ""
            echo "Manage standalone reverse proxy entries in the Caddyfile."
            echo "These are top-level server blocks, useful for exposing local services"
            echo "via Tailscale or other external domains."
            echo ""
            echo "Subcommands:"
            echo "  add <name> <domain> <target>   Add a new reverse proxy entry"
            echo "  list                           List all proxy entries"
            echo "  delete <name>                  Delete a proxy entry"
            echo ""
            echo "Flags:"
            echo "  --no-tls   Disable TLS for this proxy (add only)"
            echo "  --force    Skip confirmation prompts (add overwrite, delete)"
            echo ""
            echo "Examples:"
            echo "  cove proxy add opencode myhost.tailnet.ts.net 127.0.0.1:4096"
            echo "  cove proxy add api api.example.com localhost:3000 --no-tls"
            echo "  cove proxy add api api.example.com localhost:3000 --force"
            echo "  cove proxy list"
            echo "  cove proxy delete opencode --force"
            exit 0
            ;;
    esac
}

cove_pull() {
    # Sourced up front, not just before the post-migration step. Anything below
    # that touches DB_USER / DB_PASSWORD needs it, and an unset DB_USER turns
    # `mysql -u "$DB_USER" -p"$DB_PASSWORD"` into a bare `-p` that stops and
    # prompts "Enter password:" — which hangs a headless pull outright.
    source_config

    # --- UI/Logging Functions ---
    log_step() { 
        echo ""
        gum style --bold --foreground "yellow" "➡️  $1"
    }
    log_success() { 
        gum style --foreground "green" "✅ $1" 
    }
    log_error() {
        gum style --foreground "red" "❌ ERROR: $1" >&2
        exit 1
    }

    # --- Argument Parsing ---
    # Every prompt below has a flag equivalent so the whole pull can run
    # headless (CI, scripts, an AI agent). Omit a flag and you get the prompt
    # for it — but only when there's a TTY to prompt on.
    local proxy_uploads=false
    local arg_ssh=""
    local arg_path=""
    local arg_site=""
    local force=false
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --proxy-uploads) proxy_uploads=true; shift ;;
            --force|--yes|-y) force=true; shift ;;
            --ssh)  arg_ssh="$2";  shift 2 ;;
            --ssh=*)  arg_ssh="${1#*=}";  shift ;;
            --path) arg_path="$2"; shift 2 ;;
            --path=*) arg_path="${1#*=}"; shift ;;
            --site) arg_site="$2"; shift 2 ;;
            --site=*) arg_site="${1#*=}"; shift ;;
            -h|--help) display_command_help pull; exit 0 ;;
            *)
                gum style --foreground red "❌ Unknown option: $1" >&2
                echo "Usage: cove pull [--ssh \"user@host -p 22\"] [--path public/] [--site <name>] [--proxy-uploads] [--yes]" >&2
                exit 1
                ;;
        esac
    done

    # Headless, the destination can't be prompted for later — so catch a
    # missing --site now rather than after a full SSH round-trip to the
    # remote. (Interactively the picker runs after validation on purpose: it
    # proposes a site name derived from the remote URL.)
    if is_noninteractive && [ -z "$arg_site" ]; then
        require_interactive "Choosing a destination site" "--site <name> (an existing site is overwritten, a new name is created)"
    fi

    # Define quiet SSH options to prevent host key warnings. ControlMaster
    # shares a single authenticated connection across every ssh call below
    # so the user enters their password (or unlocks their key) once — the
    # validate, backup, and cleanup steps all piggyback on the first
    # connection instead of re-prompting. The socket lives in a per-run
    # path so parallel `cove pull` invocations don't collide.
    local ssh_ctl
    ssh_ctl=$(mktemp -u "${TMPDIR:-/tmp}/cove-ssh-XXXXXXXX")
    local ssh_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ControlMaster=auto -o ControlPath=$ssh_ctl -o ControlPersist=5m"
    # Remove the socket on any exit path (success, failure, Ctrl-C). Any
    # orphaned master process times out on its own via ControlPersist.
    # shellcheck disable=SC2064 # we want $ssh_ctl expanded at trap-set time
    trap "rm -f '$ssh_ctl'" EXIT

    # Bulk archive transfers deliberately bypass the multiplexed socket above.
    # Sharing one channel with the control commands throttled a 30MB upload to
    # ~16KB/s against a real gateway and then stalled outright, while the same
    # file moved in 15s on its own connection. Key auth makes the extra
    # connection free; with a password you are asked once more.
    local ssh_bulk_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ServerAliveInterval=15 -o ServerAliveCountMax=8"

    gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "This tool will guide you through pulling a remote WordPress site into Cove."
    # --- 1. Gather Remote Info ---
    local remote_ssh="$arg_ssh"
    if [ -z "$remote_ssh" ]; then
        require_interactive "The SSH connection" "--ssh \"user@host -p 2222\""
        log_step "Enter remote server details"
        remote_ssh=$(gum input --width 0 --placeholder "user@host.com -p 2222" --prompt "SSH Connection: ")
    fi
    if [ -z "$remote_ssh" ]; then log_error "SSH connection cannot be empty."; fi

    # Trim the "ssh " prefix if the user includes it.
    remote_ssh="${remote_ssh##ssh }"

    # The remote root defaults to public/ — the same value the prompt
    # pre-fills — so --path is only needed for non-standard layouts.
    local remote_path="$arg_path"
    if [ -z "$remote_path" ]; then
        if is_noninteractive; then
            remote_path="public/"
        else
            remote_path=$(gum input --width 0 --value "public/" --prompt "Path to WordPress Root: ")
        fi
    fi
    if [ -z "$remote_path" ]; then log_error "Remote path cannot be empty."; fi
    local remote_path_q
    remote_path_q=$(shell_quote "$remote_path")

    # --- 2. Validate Remote Site ---
    # One probe round-trip answers both questions at once: is there a usable
    # WordPress here, and which tools does this host actually have? The answer
    # decides whether we need to sideload WP-CLI before doing any real work.
    log_step "Validating remote WordPress site..."
    local wp_cli_flag=""
    wp_cli_flag=$(transfer_ensure_remote_wp_cli "$ssh_opts" "$remote_ssh" "$remote_path")
    local remote_probe
    remote_probe=$(transfer_remote "$ssh_opts" "$remote_ssh" probe "$remote_path" $wp_cli_flag 2>/dev/null)
    local remote_url
    remote_url=$(echo "$remote_probe" | sed -n 's/^home=//p')
    domain=$(echo "$remote_url" | sed -E 's/https?:\/\/(www\.)?//; s/\/.*//')

    if [ -z "$remote_url" ] || [[ ! "$remote_url" == http* ]]; then
        if echo "$remote_probe" | grep -q '^wp_cli=missing'; then
            log_error "No WP-CLI on the remote and the sideload failed. Install WP-CLI there, or check that PHP is available."
        fi
        log_error "Could not find a valid WordPress site at the specified path. Check your connection details and path."
    fi
    log_success "Found WordPress site: $remote_url"
    # Worth surfacing: a host on the PHP tier works, just more slowly.
    local remote_arch remote_db
    remote_arch=$(echo "$remote_probe" | sed -n 's/^archiver=//p')
    remote_db=$(echo "$remote_probe" | sed -n 's/^db_dump=//p')
    if [ "$remote_arch" = "php" ] || [ "$remote_arch" = "phar" ] || [ "$remote_db" = "php" ]; then
        log_success "Remote lacks some CLI tools; using the PHP fallback (archiver=$remote_arch, db=$remote_db)."
    fi

    # --- 3. Choose Destination ---
    local site_name
    local dest_path
    local local_url
    local is_new_site=false

    if [ -n "$arg_site" ]; then
        # --site covers both destinations: an existing site is overwritten,
        # an unused name is created. Which one it is follows from whether the
        # directory exists, so the caller doesn't need a second flag.
        site_name="${arg_site%.localhost}"
        if ! validate_site_name "$site_name"; then
            log_error "Invalid site name '$site_name'."
        fi
        [ -d "$SITES_DIR/$site_name.localhost" ] || is_new_site=true
    else
        require_interactive "Choosing a destination site" "--site <name> (an existing site is overwritten, a new name is created)"
        log_step "Choose a destination for the pulled site"

        local wp_sites=()
        for site_dir in "$SITES_DIR"/*.localhost; do
            if [ -f "$site_dir/public/wp-config.php" ]; then
                wp_sites+=("$(basename "$site_dir" .localhost)")
            fi
        done

        local destination_choice
        destination_choice=$(gum choose "New Site" "${wp_sites[@]}")
        if [ -z "$destination_choice" ]; then log_error "No destination selected."; fi

        if [ "$destination_choice" == "New Site" ]; then
            is_new_site=true
            local proposed_name
            proposed_name=$(echo "$remote_url" | sed -E 's/https?:\/\/(www\.)?//; s/\/.*//; s/\./-/g')
            site_name=$(gum input --width 0 --value "$proposed_name" --prompt "Enter a name for the new local site: ")
            if [ -z "$site_name" ]; then log_error "Site name cannot be empty."; fi
        else
            site_name="$destination_choice"
        fi
    fi

    if $is_new_site; then
        log_step "Creating new placeholder site: ${site_name}.localhost"
        if ! "$COVE_CMD" add "$site_name"; then
            log_error "Failed to create placeholder site. Does it already exist?"
        fi
    else
        # Overwriting destroys the local site's files and database, so it needs
        # an explicit yes: the confirm interactively, --yes when headless.
        if ! $force; then
            require_interactive "Overwriting the existing site '${site_name}'" "--yes to confirm the overwrite"
            if ! gum confirm "Are you sure you want to overwrite '${site_name}'? All its files and database content will be replaced."; then
                echo "🚫 Pull cancelled."
                exit 0
            fi
        fi

        log_step "Preparing to overwrite existing site: ${site_name}.localhost"
        # The database is reset by `do migrate` itself (wp db reset + import),
        # so nothing destructive happens here — the local site stays intact and
        # servable right up until the restore actually succeeds.
    fi

    dest_path="$SITES_DIR/$site_name.localhost/public"
    local_url="$(url_for "$site_name.localhost")"

    # --- 4. Perform Migration ---
    # Backup on the remote, stream it down over the SSH connection we already
    # hold, restore locally. Nothing is fetched over HTTP at any point, which is
    # what makes this work against hosts whose WordPress URL isn't publicly
    # reachable (staging behind auth, private networks, a sandbox whose `home`
    # still points at a provisioning template).
    log_step "Generating backup for ${remote_url}..."
    local -a backup_args=()
    if [ "$proxy_uploads" = true ]; then
        log_success "Uploads will be excluded from the backup and proxied instead."
        backup_args+=(--exclude=wp-content/uploads)
    fi

    local remote_archive
    remote_archive=$(transfer_remote "$ssh_opts" "$remote_ssh" backup "$remote_path" \
        ${backup_args[@]+"${backup_args[@]}"} $wp_cli_flag)
    if [ -z "$remote_archive" ]; then
        log_error "Failed to generate a backup on the remote."
    fi
    log_success "Backup created: ${remote_archive}"

    # The remote archive is removed on every exit path below, so a failed pull
    # never leaves a full database dump sitting on the remote filesystem.
    local remote_archive_q
    remote_archive_q=$(shell_quote "$remote_archive")

    log_step "Downloading backup over SSH..."
    # Keep the remote's own filename: the extension is what tells the restore
    # whether it is unpacking a zip or a tar.gz, and the remote may well have
    # picked a different archiver than this machine would have.
    local dl_dir
    dl_dir=$(mktemp -d "${TMPDIR:-/tmp}/cove-pull-XXXXXX") || log_error "mktemp failed."
    local local_archive="$dl_dir/$(basename "$remote_archive")"
    if ! ssh $ssh_bulk_opts $remote_ssh "cat $remote_archive_q" > "$local_archive"; then
        rm -rf "$dl_dir"
        ssh $ssh_opts $remote_ssh "rm -f $remote_archive_q" 2>/dev/null
        log_error "Failed to download the backup over SSH."
    fi
    log_success "Downloaded ($(du -h "$local_archive" 2>/dev/null | cut -f1 | tr -d ' '))."

    # NOTE: there is deliberately no DROP DATABASE here. The restore resets the
    # database itself, immediately before importing. Wiping it up front instead
    # BROKE the overwrite path: the destination has to still be a working
    # WordPress for the restore to read its current URL and rewrite links.
    log_step "Restoring backup to ${site_name}.localhost..."
    if ! transfer_local restore "$dest_path" "$local_archive" --url-to="$local_url"; then
        rm -rf "$dl_dir"
        ssh $ssh_opts $remote_ssh "rm -f $remote_archive_q" 2>/dev/null
        log_error "The restore failed."
    fi
    rm -rf "$dl_dir"
    log_success "Restore complete."

    # --- 5. Post-Migration Configuration ---
    log_step "Configuring local site..."
    source_config
    inject_mu_plugin "$dest_path"

    # --- 6. Add Proxy Directive if Flag is Set ---
    if [ "$proxy_uploads" = true ]; then
        log_step "Adding upload proxy directive..."
        local new_directive
        # Use a heredoc to create the multi-line directive string
        read -r -d '' new_directive << EOM
@local_upload {
    path /wp-content/uploads/*
    file {path}
}
handle @local_upload {
    # If the file exists, serve it and stop processing.
    file_server
}

handle /wp-content/uploads/* {
    # Proxy the request to the live site.
    reverse_proxy ${remote_url} {
        header_up Host ${domain}
        flush_interval -1
    }
}
EOM
        # Pipe the new directive into the add command
        echo "$new_directive" | "$COVE_CMD" directive add "$site_name"
        log_success "Upload proxy directive added."
    fi

    # --- 7. Cleanup ---
    log_step "Cleaning up remote backup file..."
    ssh $ssh_opts $remote_ssh "rm -f $remote_archive_q" 2>/dev/null
    log_success "Cleanup complete."
 
    # --- 8. Finalize ---
    regenerate_caddyfile
    
    gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "✨ All done! Your site is ready." "URL: ${local_url}"
}
cove_push() {
    # --- UI/Logging Functions ---
    log_step() { 
        echo ""
        gum style --bold --foreground "yellow" "➡️  $1"
    }
    log_success() { 
        gum style --foreground "green" "✅ $1" 
    }
    log_error() {
        gum style --foreground "red" "❌ ERROR: $1" >&2
        exit 1
    }

    # --- Argument Parsing ---
    # Flag equivalents for every prompt below, so a push can run headless
    # (CI, scripts, an AI agent). Omit a flag and you get its prompt — but
    # only when there's a TTY to prompt on.
    local arg_site=""
    local arg_ssh=""
    local arg_path=""
    local force=false
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --force|--yes|-y) force=true; shift ;;
            --site) arg_site="$2"; shift 2 ;;
            --site=*) arg_site="${1#*=}"; shift ;;
            --ssh)  arg_ssh="$2";  shift 2 ;;
            --ssh=*)  arg_ssh="${1#*=}";  shift ;;
            --path) arg_path="$2"; shift 2 ;;
            --path=*) arg_path="${1#*=}"; shift ;;
            -h|--help) display_command_help push; exit 0 ;;
            *)
                gum style --foreground red "❌ Unknown option: $1" >&2
                echo "Usage: cove push [--site <name>] [--ssh \"user@host -p 22\"] [--path public/] [--yes]" >&2
                exit 1
                ;;
        esac
    done

    # Define quiet SSH options to prevent host key warnings. ControlMaster
    # shares a single authenticated connection across every ssh call below
    # (validate, upload backup, restore, cleanup) so the user enters their
    # password or unlocks their key once instead of four times.
    local ssh_ctl
    ssh_ctl=$(mktemp -u "${TMPDIR:-/tmp}/cove-ssh-XXXXXXXX")
    local ssh_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ControlMaster=auto -o ControlPath=$ssh_ctl -o ControlPersist=5m"
    # shellcheck disable=SC2064 # we want $ssh_ctl expanded at trap-set time
    trap "rm -f '$ssh_ctl'" EXIT

    # Bulk archive transfers deliberately bypass the multiplexed socket above.
    # Sharing one channel with the control commands throttled a 30MB upload to
    # ~16KB/s against a real gateway and then stalled outright, while the same
    # file moved in 15s on its own connection. Key auth makes the extra
    # connection free; with a password you are asked once more.
    local ssh_bulk_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ServerAliveInterval=15 -o ServerAliveCountMax=8"

    gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "This tool will guide you through pushing a local Cove site to a remote server."

    # --- 1. Choose Local Site ---
    local site_name="${arg_site%.localhost}"
    if [ -z "$site_name" ]; then
        require_interactive "Choosing a local site to push" "--site <name>"
        log_step "Choose a local site to push"
        local wp_sites=()
        for site_dir in "$SITES_DIR"/*.localhost; do
            if [ -f "$site_dir/public/wp-config.php" ]; then
                wp_sites+=("$(basename "$site_dir" .localhost)")
            fi
        done

        if [ ${#wp_sites[@]} -eq 0 ]; then
            log_error "No local WordPress sites found to push."
        fi

        site_name=$(gum choose "${wp_sites[@]}")
        if [ -z "$site_name" ]; then log_error "No site selected."; fi
    else
        # A name supplied by flag skipped the picker, which only ever listed
        # real WordPress sites — so validate what the picker would have guaranteed.
        if ! validate_site_name "$site_name"; then
            log_error "Invalid site name '$site_name'."
        fi
        if [ ! -f "$SITES_DIR/$site_name.localhost/public/wp-config.php" ]; then
            log_error "No local WordPress site named '$site_name' (looked for $SITES_DIR/$site_name.localhost/public/wp-config.php)."
        fi
    fi

    local local_path="$SITES_DIR/$site_name.localhost/public"

    # --- 2. Gather Remote Info ---
    local remote_ssh="$arg_ssh"
    if [ -z "$remote_ssh" ]; then
        require_interactive "The SSH connection" "--ssh \"user@host -p 2222\""
        log_step "Enter remote server details"
        remote_ssh=$(gum input --width 0 --placeholder "user@host.com -p 2222" --prompt "SSH Connection: ")
    fi
    if [ -z "$remote_ssh" ]; then log_error "SSH connection cannot be empty."; fi

    # Trim the "ssh " prefix if the user includes it.
    remote_ssh="${remote_ssh##ssh }"

    # Defaults to public/ — the same value the prompt pre-fills.
    local remote_path="$arg_path"
    if [ -z "$remote_path" ]; then
        if is_noninteractive; then
            remote_path="public/"
        else
            remote_path=$(gum input --width 0 --value "public/" --prompt "Path to Remote WordPress Root: ")
        fi
    fi
    if [ -z "$remote_path" ]; then log_error "Remote path cannot be empty."; fi
    local remote_path_q
    remote_path_q=$(shell_quote "$remote_path")

    # --- 3. Validate Remote Site ---
    # A single probe confirms there's a usable WordPress there and reports the
    # host's tooling, so a remote without WP-CLI gets the phar sideloaded before
    # we spend time building a backup that couldn't be restored anyway.
    log_step "Validating remote WordPress site..."
    local wp_cli_flag=""
    wp_cli_flag=$(transfer_ensure_remote_wp_cli "$ssh_opts" "$remote_ssh" "$remote_path")
    local remote_probe
    remote_probe=$(transfer_remote "$ssh_opts" "$remote_ssh" probe "$remote_path" $wp_cli_flag 2>/dev/null)
    local remote_url
    remote_url=$(echo "$remote_probe" | sed -n 's/^home=//p')

    if [ -z "$remote_url" ] || [[ ! "$remote_url" == http* ]]; then
        if echo "$remote_probe" | grep -q '^wp_cli=missing'; then
            log_error "No WP-CLI on the remote and the sideload failed. Install WP-CLI there, or check that PHP is available."
        fi
        log_error "Could not find a valid WordPress site at the specified path. Check your connection details and path."
    fi
    log_success "Found remote site to overwrite: $remote_url"
    local remote_ext remote_db
    remote_ext=$(echo "$remote_probe" | sed -n 's/^extractor=//p')
    remote_db=$(echo "$remote_probe" | sed -n 's/^db_load=//p')
    if [ "$remote_ext" = "php" ] || [ "$remote_ext" = "phar" ] || [ "$remote_db" = "php" ]; then
        log_success "Remote lacks some CLI tools; using the PHP fallback (extractor=$remote_ext, db=$remote_db)."
    fi

    # --- 4. Confirmation ---
    # Deliberately NOT auto-promoted on a missing TTY the way `cove delete` is.
    # Delete is driven by the dashboard and only destroys a local throwaway;
    # push overwrites a live remote site's files AND database. A headless
    # caller has to say --yes out loud.
    if ! $force; then
        require_interactive "Overwriting the remote site at '${remote_url}'" "--yes to confirm the push"
        if ! gum confirm "🚨 Are you sure you want to push '${site_name}' to '${remote_url}'? This will completely overwrite the remote site's files and database."; then
            echo "🚫 Push cancelled."
            exit 0
        fi
    fi

    # --- 5. Perform Local Backup ---
    log_step "Generating local backup for ${site_name}..."
    local backup_path
    backup_path=$(transfer_local backup "$local_path")
    if [ -z "$backup_path" ] || [ ! -f "$backup_path" ]; then
        log_error "Failed to generate the local backup."
    fi
    local size
    size=$(du -h "$backup_path" 2>/dev/null | cut -f1 | tr -d ' ')
    log_success "Local backup created: $(basename "$backup_path") ($size)"

    # Upload to a temp path outside the web root. The old flow dropped the
    # archive into the remote's WordPress directory, where a full database dump
    # plus wp-config sat publicly downloadable until cleanup ran — and stayed
    # there for good if the restore died in between.
    local remote_tmp="/tmp/cove-push-$$-$(basename "$backup_path")"
    local remote_tmp_q
    remote_tmp_q=$(shell_quote "$remote_tmp")

    # --- 6. Upload Backup ---
    log_step "Uploading backup to remote server..."
    if ! ssh $ssh_bulk_opts $remote_ssh "cat > $remote_tmp_q" < "$backup_path"; then
        rm -f "$backup_path"
        ssh $ssh_opts $remote_ssh "rm -f $remote_tmp_q" 2>/dev/null
        log_error "Failed to upload backup."
    fi
    log_success "Upload complete."

    # --- 7. Remote Restore ---
    log_step "Restoring backup on remote server..."
    if ! transfer_remote "$ssh_opts" "$remote_ssh" restore "$remote_path" "$remote_tmp" \
            --url-to="$remote_url" $wp_cli_flag; then
        rm -f "$backup_path"
        ssh $ssh_opts $remote_ssh "rm -f $remote_tmp_q" 2>/dev/null
        log_error "The remote restore failed."
    fi
    log_success "Remote restore complete."

    # --- 8. Cleanup ---
    log_step "Cleaning up backup files..."
    rm -f "$backup_path"
    ssh $ssh_opts $remote_ssh "rm -f $remote_tmp_q" 2>/dev/null
    log_success "Cleanup complete."

    # --- 9. Finalize ---
    gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "✨ All done! Your site has been pushed successfully." "Remote URL: ${remote_url}"
}
cove_reload() {
    # Auto-heal any root-owned state left over from a pre-1.10 install.
    heal_cove_state_ownership
    # Serialize reloads to keep Caddy's admin server healthy. The dashboard
    # fires reload in the background after every site add/delete, so rapid
    # actions can spawn many concurrent cove-reload processes; two concurrent
    # `frankenphp reload` calls reliably deadlock Caddy's admin endpoint with
    # a 10s shutdown timeout.
    #
    # Strategy: first caller holds the lock and does the work. Subsequent
    # callers touch a "pending" marker and exit immediately. When the holder
    # finishes it re-runs once if the marker is set, so the final state
    # converges on the latest on-disk Sites listing.
    #
    # Implementation note: we use a single lock *file* (not a dir) opened with
    # set -C (noclobber) so the pid is written atomically with the lock's
    # creation. Earlier `mkdir + echo > pid` left a TOCTOU window where a
    # competing reload could read an empty pid, decide the holder was dead,
    # and stomp the lock — letting 3+ reloads run and race create_gui_file's
    # .tmp files.
    local lock_file="$COVE_DIR/.reload.lock"
    local pending="$COVE_DIR/.reload.pending"

    acquire_reload_lock() {
        (set -C; echo "$$" > "$lock_file") 2>/dev/null
    }

    if ! acquire_reload_lock; then
        local holder_pid
        holder_pid=$(cat "$lock_file" 2>/dev/null)
        if [ -n "$holder_pid" ] && kill -0 "$holder_pid" 2>/dev/null; then
            # A real holder is running — leave a breadcrumb and bail.
            touch "$pending" 2>/dev/null || true
            return 0
        fi
        # Stale (holder died, or was a pre-1.10 root-owned file). Reclaim,
        # falling back to sudo in case ownership blocks us.
        rm -f "$lock_file" 2>/dev/null || $SUDO_CMD -n rm -f "$lock_file" 2>/dev/null || true
        if ! acquire_reload_lock; then
            # Lost the race to another reclaimer — they've got it.
            touch "$pending" 2>/dev/null || true
            return 0
        fi
    fi

    # Trap for abnormal exits (Ctrl-C, signals). The happy-path cleanup
    # happens at the function end since the trap was observed not firing
    # reliably when cove_reload is invoked via shell_exec(…&) from PHP.
    trap 'rm -f "$lock_file" 2>/dev/null; trap - EXIT INT TERM' EXIT INT TERM

    # Track the last regenerate's result so a failed Caddy reload (bad
    # directive, port conflict) surfaces to the caller instead of being
    # swallowed — cove_reload used to always return 0, so upgrade/CLI callers
    # couldn't tell the new config never went live.
    local reload_rc=0
    while :; do
        rm -f "$pending"
        prune_delete_tombstones
        create_gui_file
        regenerate_caddyfile; reload_rc=$?
        update_etc_hosts
        [ -f "$pending" ] || break
    done

    # Explicit unlock — belt-and-suspenders with the trap.
    rm -f "$lock_file" 2>/dev/null
    trap - EXIT INT TERM

    if [ "$reload_rc" -ne 0 ]; then
        gum style --foreground red "❌ Caddy reload failed — check $LOGS_DIR/caddy-reload.log for the adapt/reload error." >&2
    fi
    return "$reload_rc"
}

cove_rename() {
    local old_name="$1"
    local new_name="$2"

    # --- Validation ---
    if [ -z "$old_name" ] || [ -z "$new_name" ]; then
        gum style --foreground red "❌ Error: Both old and new site names are required."
        echo "Usage: cove rename <old-name> <new-name>"
        exit 1
    fi

    if [ "$old_name" == "$new_name" ]; then
         gum style --foreground red "❌ Error: The new name must be different from the old name."
         exit 1
    fi

    local old_site_dir="$SITES_DIR/$old_name.localhost"
    if [ ! -d "$old_site_dir" ]; then
        gum style --foreground red "❌ Error: Site '$old_name.localhost' not found."
        exit 1
    fi

    # Validate the new_name using the same rules as the 'add' command
    if [[ "$new_name" =~ [^a-z0-9-] ]]; then
        gum style --foreground red "❌ Error: Invalid new site name '$new_name'." "Site names can only contain lowercase letters, numbers, and hyphens."
        exit 1
    fi
    if [[ "$new_name" == -* || "$new_name" == *- ]]; then
        gum style --foreground red "❌ Error: Invalid new site name '$new_name'." "Site names cannot begin or end with a hyphen."
        exit 1
    fi
    for protected_name in $PROTECTED_NAMES; do
        if [ "$new_name" == "$protected_name" ]; then
            gum style --foreground red "❌ Error: '$new_name' is a reserved name. Choose another."
            exit 1
        fi
    done

    local new_site_dir="$SITES_DIR/$new_name.localhost"
    if [ -d "$new_site_dir" ]; then
        gum style --foreground red "❌ Error: A site named '$new_name.localhost' already exists."
        exit 1
    fi

    echo "🔄 Renaming '$old_name.localhost' to '$new_name.localhost'..."

    # --- Rename Directory ---
    mv "$old_site_dir" "$new_site_dir"
    echo "   - Directory renamed."

    # --- Handle WordPress Specifics ---
    if [ -f "$new_site_dir/public/wp-config.php" ]; then
        source_config
        
        # Get WP-CLI command (adds --allow-root if running as root; uses the
        # site's pinned PHP when one is set)
        local wp_cmd
        wp_cmd=$(get_wp_cmd "$new_site_dir")
        
        local old_db_name
        old_db_name=$(echo "cove_$old_name" | tr -c '[:alnum:]_' '_')
        local new_db_name
        new_db_name=$(echo "cove_$new_name" | tr -c '[:alnum:]_' '_')
        local temp_sql_dump
        temp_sql_dump=$(mktemp) || {
            gum style --foreground red "❌ Error: Could not create a temporary file for the database dump."
            mv "$new_site_dir" "$old_site_dir"
            exit 1
        }
        trap 'rm -f "$temp_sql_dump"' EXIT

        echo "   - Backing up old database '$old_db_name'..."
        if ! mysqldump -u "$DB_USER" -p"$DB_PASSWORD" "$old_db_name" > "$temp_sql_dump"; then
            gum style --foreground red "❌ Error: Failed to dump the old database. Aborting."
            mv "$new_site_dir" "$old_site_dir" # Revert directory rename
            exit 1
        fi

        echo "   - Creating and importing to new database '$new_db_name'..."
        mysql -u "$DB_USER" -p"$DB_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS \`$new_db_name\`;"
        # Gate the destructive DROP below on a verified import + config update.
        # Previously the import was unchecked, so a failed import (disk full,
        # packet size) still fell through to dropping the old database — losing
        # the site's only good copy. On failure here, abort with the old
        # database and wp-config left intact.
        if ! mysql -u "$DB_USER" -p"$DB_PASSWORD" "$new_db_name" < "$temp_sql_dump"; then
            gum style --foreground red "❌ Error: Failed to import into '$new_db_name'. Aborting; old database left intact."
            mv "$new_site_dir" "$old_site_dir" # Revert directory rename
            exit 1
        fi

        echo "   - Updating wp-config.php..."
        if ! (cd "$new_site_dir/public" && $wp_cmd config set DB_NAME "$new_db_name" --quiet); then
            gum style --foreground red "❌ Error: Failed to update wp-config.php. Aborting; old database left intact."
            mv "$new_site_dir" "$old_site_dir" # Revert directory rename
            exit 1
        fi

        echo "   - Running search-replace for site URL..."
        # Non-fatal: the data already lives in the new DB and wp-config points
        # at it, so a search-replace hiccup shouldn't block the rename or strand
        # the old database — just warn.
        if ! (cd "$new_site_dir/public" && $wp_cmd search-replace "$(url_for "$old_name.localhost")" "$(url_for "$new_name.localhost")" --all-tables --skip-plugins --skip-themes --quiet); then
            gum style --foreground yellow "⚠️  search-replace did not complete cleanly; verify the site URL under the new name."
        fi

        # Multisite (the marker moved with the site dir): wp_blogs/wp_site
        # store bare hostnames the scheme'd pass above can't reach, and
        # DOMAIN_CURRENT_SITE is a wp-config constant. Same handling as clone.
        if [ -f "$new_site_dir/multisite" ]; then
            if ! (cd "$new_site_dir/public" && $wp_cmd search-replace "$old_name.localhost" "$new_name.localhost" --all-tables --skip-plugins --skip-themes --quiet); then
                gum style --foreground yellow "⚠️  network domain search-replace did not complete cleanly; verify subsite domains."
            fi
            (cd "$new_site_dir/public" && $wp_cmd config set DOMAIN_CURRENT_SITE "$new_name.localhost" --type=constant --quiet) || \
                gum style --foreground yellow "⚠️  Could not update DOMAIN_CURRENT_SITE in wp-config.php."
        fi

        echo "   - Dropping old database '$old_db_name'..."
        mysql -u "$DB_USER" -p"$DB_PASSWORD" -e "DROP DATABASE IF EXISTS \`$old_db_name\`;"
    fi

    # --- Rename Custom Caddy Directives File ---
    local old_custom_conf_file="$CUSTOM_CADDY_DIR/$old_name.localhost"
    local new_custom_conf_file="$CUSTOM_CADDY_DIR/$new_name.localhost"
    if [ -f "$old_custom_conf_file" ]; then
        mv "$old_custom_conf_file" "$new_custom_conf_file"
        echo "   - Custom Caddy directive file renamed."
    fi

    # --- Reload Server Configuration ---
    regenerate_caddyfile

    gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "✅ Site renamed successfully!" "New URL: $(url_for "$new_name.localhost")"
}
# --- Share Command ---
# Creates a temporary public tunnel to share a local site via Cloudflare Quick Tunnels
# Requires cloudflared (installed on-demand if missing)

SHARE_PROXY_PORT=19876

cove_share() {
    local site_name=""
    local auto_yes=false
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --yes|-y|--force) auto_yes=true; shift ;;
            -h|--help) display_command_help share; exit 0 ;;
            -*)
                gum style --foreground red "Error: Unknown option: $1" >&2
                echo "Usage: cove share [<name>] [--yes]" >&2
                exit 1
                ;;
            *) [ -z "$site_name" ] && site_name="$1"; shift ;;
        esac
    done

    # --- 1. Validate Site ---
    if [ -z "$site_name" ]; then
        require_interactive "Choosing a site to share" "the site name as an argument: cove share <name>"
        # Interactive mode: let user select a site
        local all_sites=()
        for site_dir in "$SITES_DIR"/*.localhost; do
            if [ -d "$site_dir" ]; then
                all_sites+=("$(basename "$site_dir" .localhost)")
            fi
        done
        
        if [ ${#all_sites[@]} -eq 0 ]; then
            gum style --foreground red "Error: No sites found. Create one with 'cove add <name>'."
            exit 1
        fi
        
        echo "Select a site to share:"
        site_name=$(gum choose "${all_sites[@]}")
        
        if [ -z "$site_name" ]; then
            echo "Cancelled."
            exit 0
        fi
    fi
    
    # Normalize site name (remove .localhost suffix if present)
    site_name="${site_name%.localhost}"
    
    local site_dir="$SITES_DIR/${site_name}.localhost"
    
    if [ ! -d "$site_dir" ]; then
        gum style --foreground red "Error: Site '${site_name}.localhost' not found."
        exit 1
    fi
    
    local local_hostname="${site_name}.localhost"
    
    # --- 2. Check for cloudflared (install on-demand if missing) ---
    if ! command -v cloudflared &> /dev/null; then
        echo "cloudflared is required for cove share but is not installed."
        echo ""
        
        local install_cmd=""
        local install_name=""
        
        if [ "$OS" == "macos" ] && command -v "$MAC_BREW" &> /dev/null; then
            install_cmd="$MAC_BREW install cloudflared"
            install_name=$([ "$MAC_BREW" = "nb" ] && echo "nanobrew" || echo "Homebrew")
        elif command -v brew &> /dev/null; then
            install_cmd="brew install cloudflared"
            install_name="Homebrew"
        elif command -v apt-get &> /dev/null; then
            # Debian/Ubuntu - need to add Cloudflare's repo first
            install_cmd="curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null && echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' | sudo tee /etc/apt/sources.list.d/cloudflared.list && sudo apt-get update && sudo apt-get install -y cloudflared"
            install_name="apt"
        elif command -v dnf &> /dev/null; then
            # Fedora/RHEL
            install_cmd="curl -fsSL https://pkg.cloudflare.com/cloudflared-ascii.repo | sudo tee /etc/yum.repos.d/cloudflared.repo && sudo dnf install -y cloudflared"
            install_name="dnf"
        fi
        
        if [ -n "$install_cmd" ]; then
            # --yes (or no TTY to ask on) installs without prompting; the
            # alternative is aborting a share for want of a keystroke.
            if $auto_yes || ! [ -t 0 ]; then
                echo "Installing cloudflared via ${install_name}..."
                eval "$install_cmd"
                if ! command -v cloudflared &> /dev/null; then
                    gum style --foreground red "Error: Failed to install cloudflared."
                    exit 1
                fi
                echo "cloudflared installed successfully."
                echo ""
            elif gum confirm "Install cloudflared via ${install_name}?"; then
                echo "Installing cloudflared..."
                eval "$install_cmd"
                if ! command -v cloudflared &> /dev/null; then
                    gum style --foreground red "Error: Failed to install cloudflared."
                    exit 1
                fi
                echo "cloudflared installed successfully."
                echo ""
            else
                gum style --foreground red "Error: cloudflared is required."
                exit 1
            fi
        else
            gum style --foreground red "Error: cloudflared not found."
            echo "Install it from: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
            exit 1
        fi
    fi
    
    # --- 3. Check for Python (needed for the HTTP proxy) ---
    local python_cmd=""
    if command -v python3 &> /dev/null; then
        python_cmd="python3"
    elif command -v python &> /dev/null; then
        python_cmd="python"
    else
        gum style --foreground red "Error: Python is required for cove share."
        exit 1
    fi
    
    # --- 4. Create temp files ---
    local tunnel_output
    tunnel_output=$(mktemp)
    
    # --- 5. Cleanup function ---
    local cleanup_triggered=""
    cleanup() {
        cleanup_triggered=1
        echo ""
        echo "Stopping tunnel..."
        # Kill processes and suppress job termination messages
        if [ -n "$proxy_pid" ]; then
            kill $proxy_pid 2>/dev/null
            wait $proxy_pid 2>/dev/null
        fi
        if [ -n "$tunnel_pid" ]; then
            kill $tunnel_pid 2>/dev/null
            wait $tunnel_pid 2>/dev/null
        fi
        rm -f "$tunnel_output"
        echo "Done."
    }
    trap cleanup EXIT
    
    # --- 6. Display initial message ---
    echo ""
    gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 \
        "Starting public tunnel for ${site_name}" \
        "" \
        "Local: $(url_for "${local_hostname}")" \
        "" \
        "Press Ctrl+C to stop sharing."
    echo ""
    
    echo "Starting Cloudflare tunnel..."
    
    # --- 7. Start cloudflared to get the public URL first ---
    # Use --protocol http2 for better compatibility (QUIC can be blocked by firewalls)
    cloudflared tunnel --url http://localhost:${SHARE_PROXY_PORT} \
        --protocol http2 --no-autoupdate > "$tunnel_output" 2>&1 &
    tunnel_pid=$!
    
    # Wait for the URL to appear in the output
    local public_url=""
    local attempts=0
    local max_attempts=30
    
    while [ -z "$public_url" ] && [ $attempts -lt $max_attempts ]; do
        sleep 1
        ((attempts++))
        
        if ! kill -0 $tunnel_pid 2>/dev/null; then
            gum style --foreground red "Error: Cloudflare tunnel failed to start."
            cat "$tunnel_output"
            exit 1
        fi
        
        public_url=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$tunnel_output" 2>/dev/null | head -1)
    done
    
    if [ -z "$public_url" ]; then
        gum style --foreground red "Error: Could not get public URL from Cloudflare"
        cat "$tunnel_output"
        exit 1
    fi
    
    # Extract just the hostname from the URL
    local public_host="${public_url#https://}"
    
    gum style --foreground 212 --bold "Public URL: $public_url"
    echo ""
    echo "Share this URL with anyone to give them access to your site."
    echo ""
    
    # --- 8. Start Python HTTP proxy that rewrites URLs ---
    echo "Starting local proxy with URL rewriting..."
    
    $python_cmd - "$local_hostname" "$SHARE_PROXY_PORT" "$public_host" "$HTTPS_PORT" << 'PYTHON_PROXY' &
import sys
import ssl
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen

TARGET_HOST = sys.argv[1]  # e.g., anchordev.localhost
LISTEN_PORT = int(sys.argv[2])
PUBLIC_HOST = sys.argv[3]  # e.g., random-words.trycloudflare.com
HTTPS_PORT = int(sys.argv[4]) if len(sys.argv) > 4 else 443
TARGET_AUTHORITY = TARGET_HOST if HTTPS_PORT == 443 else f"{TARGET_HOST}:{HTTPS_PORT}"

# Create SSL context that doesn't verify certificates (for self-signed)
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# Content types that should have URL rewriting
REWRITABLE_TYPES = ('text/html', 'text/css', 'application/javascript', 'application/json', 'text/javascript')

class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    
    def log_message(self, format, *args):
        # Log requests in a nice format
        import datetime
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        # Get client IP from CF-Connecting-IP (Cloudflare) or X-Forwarded-For
        client_ip = self.headers.get('CF-Connecting-IP',
                    self.headers.get('X-Forwarded-For', self.client_address[0]))
        # If multiple IPs in X-Forwarded-For, take the first (original client)
        if ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()
        # args[0] is typically "METHOD /path HTTP/1.1", args[1] is status code
        if len(args) >= 2:
            request_line = args[0]
            status_code = args[1]
            # Parse method and path from request line
            parts = request_line.split(' ')
            if len(parts) >= 2:
                method = parts[0]
                path = parts[1]
                # Color code status
                if str(status_code).startswith('2'):
                    status_color = '\033[32m'  # Green
                elif str(status_code).startswith('3'):
                    status_color = '\033[33m'  # Yellow
                elif str(status_code).startswith('4'):
                    status_color = '\033[31m'  # Red
                elif str(status_code).startswith('5'):
                    status_color = '\033[35m'  # Magenta
                else:
                    status_color = '\033[0m'
                reset = '\033[0m'
                dim = '\033[2m'
                print(f"{dim}{timestamp}{reset} {status_color}{status_code}{reset} {client_ip} {method} {path}", flush=True)
                return
        # Fallback for other log messages
        print(format % args, flush=True)
    
    def do_request(self):
        target_url = f"https://{TARGET_AUTHORITY}{self.path}"

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        req = Request(target_url, data=body, method=self.command)

        for key, value in self.headers.items():
            if key.lower() not in ('host', 'connection', 'accept-encoding'):
                req.add_header(key, value)
        req.add_header('Host', TARGET_AUTHORITY)

        try:
            with urlopen(req, context=ssl_ctx, timeout=60) as response:
                response_body = response.read()
                content_type = response.headers.get('Content-Type', '')

                # Rewrite URLs in text responses
                if any(ct in content_type for ct in REWRITABLE_TYPES):
                    try:
                        text = response_body.decode('utf-8')
                        # Replace https://site.localhost[:port] with https://public-url
                        text = text.replace(f'https://{TARGET_AUTHORITY}', f'https://{PUBLIC_HOST}')
                        text = text.replace(f'http://{TARGET_AUTHORITY}', f'https://{PUBLIC_HOST}')
                        # Escaped versions (for JSON)
                        text = text.replace(f'https:\\/\\/{TARGET_AUTHORITY}', f'https:\\/\\/{PUBLIC_HOST}')
                        response_body = text.encode('utf-8')
                    except:
                        pass  # If decode fails, send original
                
                self.send_response(response.status)
                for key, value in response.headers.items():
                    if key.lower() not in ('transfer-encoding', 'connection', 'content-length', 'content-encoding'):
                        self.send_header(key, value)
                self.send_header('Content-Length', len(response_body))
                self.end_headers()
                self.wfile.write(response_body)
        except Exception as e:
            error_msg = f"Proxy Error: {e}".encode()
            self.send_response(502)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', len(error_msg))
            self.end_headers()
            self.wfile.write(error_msg)
    
    def do_GET(self): self.do_request()
    def do_POST(self): self.do_request()
    def do_PUT(self): self.do_request()
    def do_DELETE(self): self.do_request()
    def do_HEAD(self): self.do_request()
    def do_OPTIONS(self): self.do_request()
    def do_PATCH(self): self.do_request()

class QuietHTTPServer(HTTPServer):
    """HTTPServer that silently ignores connection reset errors."""
    def handle_error(self, request, client_address):
        # Silently ignore connection reset errors (browser closed connection)
        import sys
        exc_type = sys.exc_info()[0]
        if exc_type in (ConnectionResetError, BrokenPipeError):
            return
        # For other errors, use default handling
        super().handle_error(request, client_address)

server = QuietHTTPServer(('127.0.0.1', LISTEN_PORT), ProxyHandler)
server.serve_forever()
PYTHON_PROXY
    proxy_pid=$!
    
    sleep 1
    
    if ! kill -0 $proxy_pid 2>/dev/null; then
        gum style --foreground red "Error: Failed to start local proxy."
        exit 1
    fi
    
    echo "Tunnel is active. Press Ctrl+C to stop."
    echo ""
    
    # Monitor tunnel connection - check every 5 seconds
    while kill -0 $tunnel_pid 2>/dev/null; do
        sleep 5
    done
    
    # Tunnel process ended - check if it was unexpected
    if [ -z "$cleanup_triggered" ]; then
        echo ""
        gum style --foreground yellow "Cloudflare tunnel disconnected."
    fi
}

cove_status() {
    # --porcelain: stable machine-readable output (one key=value per line,
    # lowercase). This is a CONTRACT consumed by the macOS menu bar app —
    # reword the human output freely, but never change these keys/values
    # without updating menubar/Sources/main.m alongside.
    local porcelain=false
    if [ "$1" == "--porcelain" ]; then
        porcelain=true
    fi

    if [ "$porcelain" == false ]; then
        echo "🔎 Checking Cove service status..."
    fi

    local caddy_status="❌ Stopped"
    local mariadb_status="❌ Stopped"
    local mailpit_status="❌ Stopped"

    # Probe Caddy's admin endpoint. The prior pidfile check fell over on
    # Linux where `sudo frankenphp start` left the pidfile root-owned (0600),
    # so the user reading it as austin got "" and the status falsely showed
    # Stopped. The TCP probe is readable by any local user.
    if is_caddy_running; then
        caddy_status="✅ Running"
    fi

    # Check MariaDB and Mailpit status on MacOS
    if [ "$OS" == "macos" ]; then
        if is_mariadb_running; then
            mariadb_status="✅ Running"
        fi
        # Probe the process, not the launchd label: `launchctl list` shows the
        # job as long as it's loaded even while it's crash-looping/throttled, so
        # it reported "Running" for a dead Mailpit. pgrep reflects real liveness.
        if pgrep -x mailpit &>/dev/null; then
            mailpit_status="✅ Running"
        fi
    fi
    
    # Check MariaDB and Mailpit status on Linux
    if [ "$OS" == "linux" ]; then
        # Check all possible MariaDB service names
        local mariadb_service
        mariadb_service=$(get_mariadb_service_name)
        if systemctl is-active --quiet "$mariadb_service" 2>/dev/null; then 
            mariadb_status="✅ Running"
        fi
        if systemctl is-active --quiet mailpit 2>/dev/null; then 
            mailpit_status="✅ Running"
        fi
    fi
    
    # Native php-fpm units for sites pinned to an older PHP (`cove php`).
    # One row per version with an installed unit; nothing pinned = no rows.
    local fpm_lines=""
    local fpm_porcelain=""
    if [ "$OS" == "macos" ]; then
        local fpm_plist fpm_ver fpm_state
        for fpm_plist in "$COVE_DIR"/com.cove.php-fpm-*.plist; do
            [ -f "$fpm_plist" ] || continue
            fpm_ver=$(basename "$fpm_plist" .plist)
            fpm_ver="${fpm_ver#com.cove.php-fpm-}"
            fpm_state="❌ Stopped"
            # Same reasoning as the mailpit pgrep above: probe the process,
            # not the launchd label. The master's title carries the config
            # path, which pins the match to this exact version.
            if pgrep -f "php-fpm/$fpm_ver/php-fpm.conf" &>/dev/null; then
                fpm_state="✅ Running"
            fi
            fpm_lines+="  PHP-FPM $fpm_ver:  $fpm_state"$'\n'
            if [[ "$fpm_state" == *Running* ]]; then
                fpm_porcelain+="php-fpm-$fpm_ver=running"$'\n'
            else
                fpm_porcelain+="php-fpm-$fpm_ver=stopped"$'\n'
            fi
        done
    fi

    if [ "$porcelain" == true ]; then
        echo "version=$COVE_VERSION"
        [[ "$caddy_status" == *Running* ]] && echo "caddy=running" || echo "caddy=stopped"
        [[ "$mariadb_status" == *Running* ]] && echo "mariadb=running" || echo "mariadb=stopped"
        [[ "$mailpit_status" == *Running* ]] && echo "mailpit=running" || echo "mailpit=stopped"
        [ -n "$fpm_porcelain" ] && printf '%s' "$fpm_porcelain"
        return 0
    fi

    echo ""
    echo "  Caddy Server: $caddy_status"
    echo "  MariaDB:      $mariadb_status"
    echo "  Mailpit:      $mailpit_status"
    [ -n "$fpm_lines" ] && printf '%s' "$fpm_lines"
    echo ""

    if [[ "$caddy_status" == "✅ Running" && "$mariadb_status" == "✅ Running" && "$mailpit_status" == "✅ Running" ]]; then
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 \
            "✅ All services are running" \
            "Dashboard: $(url_for cove.localhost)" \
            "Adminer:   $(url_for db.cove.localhost)" \
            "Mailpit:   $(url_for mail.cove.localhost)"
        
        # Show WSL-specific info
        if [ "$IS_WSL" = true ]; then
            local wsl_ip
            wsl_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
            echo ""
            echo "  WSL IP: $wsl_ip"
        fi
    else
        gum style --border normal --margin "1" --padding "1 2" --border-foreground "yellow" \
            "⚠️  Some services are stopped." \
            "Run 'cove enable' to start them."
    fi
}
# --- Tailscale Configuration ---
TAILSCALE_CONFIG="$APP_DIR/tailscale"

cove_tailscale_enable() {
    local hostname="$1"

    # Try to auto-detect hostname if not provided
    if [ -z "$hostname" ]; then
        if command -v tailscale &> /dev/null; then
            echo "🔎 Detecting Tailscale hostname..."
            # Extract DNSName from Self section (handles both "key": "value" and "key":"value" formats)
            hostname=$(tailscale status --json 2>/dev/null | grep -m1 '"DNSName"' | sed 's/.*"DNSName"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' | sed 's/\.$//')
        fi
    fi

    # Interactive mode if still no hostname
    if [ -z "$hostname" ]; then
        echo "📝 Enter your Tailscale machine hostname"
        echo "   (e.g., mycomputer.tail1234.ts.net)"
        hostname=$(gum input --width 0 --placeholder "your-machine.tailnet.ts.net")
    fi

    if [ -z "$hostname" ]; then
        gum style --foreground red "❌ Error: Tailscale hostname is required."
        exit 1
    fi

    # Remove any trailing dot
    hostname="${hostname%.}"

    # Validate it looks like a hostname. validate_hostname matters here beyond
    # UX: this value is interpolated raw into Caddyfile server-block labels by
    # regenerate_caddyfile, so a stray space/brace would take every site down
    # at the next reload.
    if [[ ! "$hostname" =~ \. ]] || ! validate_hostname "$hostname"; then
        gum style --foreground red "❌ Error: Invalid hostname. Expected format: machine.tailnet.ts.net"
        exit 1
    fi

    # Save the configuration
    mkdir -p "$APP_DIR"
    echo "$hostname" > "$TAILSCALE_CONFIG"

    echo "✅ Tailscale access enabled!"
    echo "   Hostname: $hostname"
    echo ""
    echo "   Regenerating Caddyfile with port-based routing..."
    echo ""
    regenerate_caddyfile
    
    echo ""
    echo "   Run 'cove tailscale status' to see all URLs."
}

cove_tailscale_disable() {
    if [ -f "$TAILSCALE_CONFIG" ]; then
        rm "$TAILSCALE_CONFIG"
        
        # Clean up port files
        if [ -d "$SITES_DIR" ]; then
            for site_path in "$SITES_DIR"/*; do
                if [ -f "$site_path/tailscale_port" ]; then
                    rm "$site_path/tailscale_port"
                fi
            done
        fi
        
        echo "✅ Tailscale access disabled."
        regenerate_caddyfile
    else
        echo "ℹ️ Tailscale access is not currently enabled."
    fi
}

cove_tailscale_status() {
    echo "🔎 Tailscale Access Status"
    echo ""
    
    if [ -f "$TAILSCALE_CONFIG" ]; then
        local hostname
        hostname=$(cat "$TAILSCALE_CONFIG")
        gum style --foreground green "✅ Enabled"
        echo "   Hostname: $hostname"
        echo ""
        echo "   Your sites are accessible at:"
        
        if [ -d "$SITES_DIR" ]; then
            for site_path in "$SITES_DIR"/*; do
                if [ -d "$site_path" ]; then
                    local site_name
                    site_name=$(basename "$site_path" | sed 's/\.localhost$//')
                    local port=""
                    if [ -f "$site_path/tailscale_port" ]; then
                        port=$(cat "$site_path/tailscale_port")
                    fi
                    if [ -n "$port" ]; then
                        echo "   - https://${hostname}:${port}  (${site_name})"
                    fi
                fi
            done
        fi
        
        echo ""
        echo "   Global services:"
        echo "   - https://${hostname}:9900  (Dashboard)"
        echo "   - https://${hostname}:9901  (Mailpit)"
        echo "   - https://${hostname}:9902  (Adminer)"
    else
        gum style --foreground yellow "❌ Disabled"
        echo ""
        echo "   Enable with: cove tailscale enable [hostname]"
    fi
}

cove_tailscale() {
    local action="$1"
    shift 2>/dev/null || true

    case "$action" in
        enable)
            cove_tailscale_enable "$@"
            ;;
        disable)
            cove_tailscale_disable
            ;;
        status)
            cove_tailscale_status
            ;;
        *)
            echo "Usage: cove tailscale <subcommand>"
            echo ""
            echo "Expose all Cove sites to your Tailscale network via port-based routing."
            echo "This allows devices on your Tailnet (like your iPhone) to access"
            echo "your local development sites."
            echo ""
            echo "Your Tailscale hostname is automatically detected when you run 'enable'."
            echo "Each site gets a unique port (starting at 9001), so you can access them at:"
            echo "  https://<your-tailscale-hostname>:<port>"
            echo ""
            echo "Subcommands:"
            echo "  enable     Enable Tailscale access (auto-detects hostname)"
            echo "  disable    Disable Tailscale access"
            echo "  status     Show current Tailscale configuration and URLs"
            echo ""
            echo "Examples:"
            echo "  cove tailscale enable"
            echo "  cove tailscale status"
            echo "  cove tailscale disable"
            exit 0
            ;;
    esac
}

# --- Site Transfer (backup / restore) ---
#
# Cove's own implementation of the two operations `cove pull` and `cove push`
# need. It replaces piping https://captaincore.io/do into bash on both the
# local machine and the user's remote server: that fetched 7300+ lines to use
# roughly 490 of them, tied Cove's behaviour to a script released separately
# (a mismatch there once made `cove pull` wipe a database it then refused to
# restore into), and required the remote to be online to captaincore.io.
#
# The helper below is emitted as one self-contained script and run identically
# on both ends — locally with bash, remotely by piping it into `bash -s --`
# over the SSH connection pull/push already hold open. Same code both sides
# means one archive contract rather than two implementations agreeing by luck.
#
# Everything moves over SSH, so no HTTP download happens at any point. That is
# what retires the old failure mode where the backup URL was built from the
# remote's own `home` option and therefore only resolved when the remote's
# WordPress URL was publicly reachable.

COVE_WP_CLI_PHAR_URL="https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar"

# Emit the transfer helper. Quoted heredoc: this text is shipped verbatim and
# must not expand anything on Cove's side.
transfer_helper_source() {
cat << 'COVE_TRANSFER_HELPER'
#!/bin/bash
# cove-transfer — self-contained WordPress backup/restore.
# Generated by Cove. Runs on the local machine and on remote hosts alike.
#
# Subcommands:
#   probe   <site_dir>                     report tool capabilities as key=value
#   backup  <site_dir> [--exclude=GLOB]... create an archive, print its path
#   restore <site_dir> <archive> [--url-to=URL]
#
# Design note: every capability degrades rather than failing. Archiving prefers
# zip, falls back to tar, and finally to PHP itself; the database is dumped and
# imported through the native client when present and through WordPress's own
# $wpdb when it isn't. Because the target is always a WordPress install, PHP is
# guaranteed to exist — which makes the PHP tier a true universal fallback and
# means a bare host needs no package installs at all.

set -uo pipefail

WP=""            # resolved WP-CLI invocation (may include php + phar + --allow-root)
ARCHIVER=""      # zip | tar | php
EXTRACTOR=""     # unzip | tar | php
DB_DUMP=""       # native | php
DB_LOAD=""       # native | php
WP_CLI_PHAR=""   # optional sideloaded phar path (--wp-cli=)

log()  { [ "${QUIET:-false}" = true ] || echo "$@" >&2; }
die()  { echo "cove-transfer: $*" >&2; exit 1; }

# --- package install (tier 3) -------------------------------------------------
# Only attempted when we're already root or hold passwordless sudo; a tool that
# stops to ask for a password would hang the non-interactive SSH session that
# invoked us. Failure here is never fatal — the PHP tier still covers us.
pkg_install() {
    local pkg="$1" sudo_cmd=""
    if [ "$(id -u)" != "0" ]; then
        if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            sudo_cmd="sudo -n"
        else
            return 1
        fi
    fi
    if   command -v apt-get >/dev/null 2>&1; then $sudo_cmd apt-get install -y -qq "$pkg" >/dev/null 2>&1
    elif command -v dnf     >/dev/null 2>&1; then $sudo_cmd dnf install -y -q "$pkg"      >/dev/null 2>&1
    elif command -v yum     >/dev/null 2>&1; then $sudo_cmd yum install -y -q "$pkg"      >/dev/null 2>&1
    elif command -v apk     >/dev/null 2>&1; then $sudo_cmd apk add --no-cache "$pkg"     >/dev/null 2>&1
    elif command -v zypper  >/dev/null 2>&1; then $sudo_cmd zypper -q install -y "$pkg"   >/dev/null 2>&1
    elif command -v brew    >/dev/null 2>&1; then brew install "$pkg"                     >/dev/null 2>&1
    else return 1
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# --- WP-CLI -------------------------------------------------------------------
# Order: an explicitly sideloaded phar, then wp/wp-cli on PATH, then a phar
# already sitting in the usual spots. --allow-root is appended when running as
# root, which is the norm inside containers and trips WP-CLI by default.
resolve_wp() {
    local root_flag=""
    [ "$(id -u)" = "0" ] && root_flag=" --allow-root"

    if [ -n "$WP_CLI_PHAR" ] && [ -f "$WP_CLI_PHAR" ]; then
        have php || die "PHP not found; cannot run the sideloaded WP-CLI."
        WP="php $WP_CLI_PHAR$root_flag"; return 0
    fi
    local c
    for c in wp wp-cli; do
        if have "$c"; then WP="$c$root_flag"; return 0; fi
    done
    for c in "$HOME/wp-cli.phar" /usr/local/bin/wp-cli.phar ./wp-cli.phar; do
        if [ -f "$c" ] && have php; then WP="php $c$root_flag"; return 0; fi
    done
    return 1
}

# $table_prefix straight out of a wp-config.php, without booting PHP — the
# source's config may name a database that does not exist on this machine.
read_table_prefix() {
    [ -f "$1" ] || return 0
    grep -m1 -E '^[[:space:]]*\$table_prefix[[:space:]]*=' "$1" 2>/dev/null \
        | sed -nE "s/.*=[[:space:]]*['\"]([A-Za-z0-9_]+)['\"].*/\1/p"
}

# Fallback when the archive carries no readable config: the prefix is whatever
# precedes `options` in the dump's CREATE TABLE for the options table.
infer_table_prefix_from_dump() {
    grep -m1 -oE 'CREATE TABLE `?[A-Za-z0-9_]*options`?' "$1" 2>/dev/null \
        | sed -E 's/CREATE TABLE `?([A-Za-z0-9_]*)options`?/\1/'
}

# --- capability detection -----------------------------------------------------
# php_has <extension|class> — asks PHP directly rather than guessing from the
# distro, since ZipArchive in particular is a separate package on many hosts.
php_has_zip()  { have php && php -r 'exit(class_exists("ZipArchive")?0:1);' 2>/dev/null; }
php_has_phar() { have php && php -r 'exit(class_exists("PharData")?0:1);' 2>/dev/null; }

resolve_archiver() {
    if have zip; then ARCHIVER=zip; return 0; fi
    if have tar; then ARCHIVER=tar; return 0; fi
    pkg_install zip && have zip && { ARCHIVER=zip; return 0; }
    if php_has_zip;  then ARCHIVER=php;  return 0; fi
    if php_has_phar; then ARCHIVER=phar; return 0; fi
    return 1
}

resolve_extractor() {
    local archive="${1:-}"
    case "$archive" in
        *.tar.gz|*.tgz)
            have tar && { EXTRACTOR=tar; return 0; }
            pkg_install tar && have tar && { EXTRACTOR=tar; return 0; }
            php_has_phar && { EXTRACTOR=phar; return 0; }
            return 1 ;;
    esac
    if have unzip; then EXTRACTOR=unzip; return 0; fi
    pkg_install unzip && have unzip && { EXTRACTOR=unzip; return 0; }
    if php_has_zip; then EXTRACTOR=php; return 0; fi
    return 1
}

# The native path goes through WP-CLI, which shells out to mysqldump/mysql (or
# the mariadb-named equivalents). When those are absent we drive $wpdb instead,
# which always works because WordPress itself has a live database connection.
resolve_db() {
    if have mysqldump || have mariadb-dump; then DB_DUMP=native; else DB_DUMP=php; fi
    if have mysql     || have mariadb;      then DB_LOAD=native; else DB_LOAD=php; fi
    if [ "$DB_DUMP" = php ] || [ "$DB_LOAD" = php ]; then
        # One cheap attempt to get the real client; harmless if it fails.
        for p in default-mysql-client mariadb-client mysql-client; do
            pkg_install "$p" && break
        done
        have mysqldump || have mariadb-dump && DB_DUMP=native
        have mysql     || have mariadb      && DB_LOAD=native
    fi
}

# --- PHP helpers --------------------------------------------------------------
# Written to temp files rather than piped: stdin is already carrying this very
# script when we run over SSH, so it isn't available to hand to `wp eval-file -`.
php_dump_script() {
cat << 'PHPDUMP'
<?php
// Dump every table to $args[0] as portable SQL. Used when no mysqldump exists.
global $wpdb;
$out = $args[0];
$fh  = fopen( $out, 'w' );
if ( ! $fh ) { WP_CLI::error( 'Cannot write ' . $out ); }
fwrite( $fh, "SET NAMES utf8mb4;\nSET FOREIGN_KEY_CHECKS=0;\n" );
$tables = $wpdb->get_col( 'SHOW TABLES' );
foreach ( $tables as $table ) {
    $create = $wpdb->get_row( "SHOW CREATE TABLE `$table`", ARRAY_N );
    fwrite( $fh, "\nDROP TABLE IF EXISTS `$table`;\n" . $create[1] . ";\n" );
    $offset = 0;
    $limit  = 500;
    while ( true ) {
        $rows = $wpdb->get_results( "SELECT * FROM `$table` LIMIT $limit OFFSET $offset", ARRAY_A );
        if ( empty( $rows ) ) { break; }
        foreach ( $rows as $row ) {
            $vals = array();
            foreach ( $row as $v ) {
                if ( is_null( $v ) ) {
                    $vals[] = 'NULL';
                } elseif ( ! mb_check_encoding( $v, 'UTF-8' ) ) {
                    // Binary column: hex literals survive a round trip that
                    // quoting would corrupt.
                    $vals[] = '0x' . bin2hex( $v );
                } else {
                    $vals[] = "'" . esc_sql( $v ) . "'";
                }
            }
            // One statement per line so the importer can split on newlines.
            fwrite( $fh, "INSERT INTO `$table` VALUES (" . implode( ',', $vals ) . ");\n" );
        }
        $offset += $limit;
    }
}
fwrite( $fh, "SET FOREIGN_KEY_CHECKS=1;\n" );
fclose( $fh );
WP_CLI::success( 'Database exported.' );
PHPDUMP
}

php_load_script() {
cat << 'PHPLOAD'
<?php
// Import SQL from $args[0] using $wpdb. Used when no mysql client exists.
// Splits on statement boundaries with a small state machine rather than a
// naive explode(';'): post content very often contains ";\n" inside a string
// literal, and splitting there would corrupt the import.
global $wpdb;
$file = $args[0];
$fh   = fopen( $file, 'r' );
if ( ! $fh ) { WP_CLI::error( 'Cannot read ' . $file ); }

$wpdb->query( 'SET FOREIGN_KEY_CHECKS=0' );
$buffer = '';
$in_str = false;
$quote  = '';
$esc    = false;
$count  = 0;

$run = function ( $sql ) use ( $wpdb, &$count ) {
    $sql = trim( $sql );
    if ( $sql === '' ) { return; }
    $wpdb->query( $sql );
    $count++;
};

while ( ( $chunk = fgets( $fh ) ) !== false ) {
    $len = strlen( $chunk );
    for ( $i = 0; $i < $len; $i++ ) {
        $ch      = $chunk[ $i ];
        $buffer .= $ch;
        if ( $esc ) { $esc = false; continue; }
        if ( $ch === '\\' ) { $esc = true; continue; }
        if ( $in_str ) {
            if ( $ch === $quote ) { $in_str = false; }
            continue;
        }
        if ( $ch === "'" || $ch === '"' ) { $in_str = true; $quote = $ch; continue; }
        if ( $ch === ';' ) {
            $run( substr( $buffer, 0, -1 ) );
            $buffer = '';
        }
    }
}
$run( $buffer );
fclose( $fh );
$wpdb->query( 'SET FOREIGN_KEY_CHECKS=1' );
WP_CLI::success( "Imported {$count} statements." );
PHPLOAD
}

php_archive_script() {
cat << 'PHPZIP'
<?php
// $args: 0=mode(create|extract) 1=archive 2=dir 3..=excludes (create only)
$mode    = $args[0];
$archive = $args[1];
$dir     = rtrim( $args[2], '/' );

if ( 'extract' === $mode ) {
    $zip = new ZipArchive();
    if ( true !== $zip->open( $archive ) ) { WP_CLI::error( 'Cannot open archive.' ); }
    $zip->extractTo( $dir );
    $zip->close();
    WP_CLI::success( 'Extracted.' );
    return;
}

$excludes = array_slice( $args, 3 );
$zip      = new ZipArchive();
if ( true !== $zip->open( $archive, ZipArchive::CREATE | ZipArchive::OVERWRITE ) ) {
    WP_CLI::error( 'Cannot create archive.' );
}
$base = basename( $dir );
$it   = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
    RecursiveIteratorIterator::SELF_FIRST
);
foreach ( $it as $path ) {
    $real = $path->getPathname();
    $rel  = $base . '/' . ltrim( substr( $real, strlen( $dir ) ), '/' );
    foreach ( $excludes as $pattern ) {
        if ( fnmatch( $base . '/' . $pattern, $rel ) || fnmatch( $pattern, $rel ) ) { continue 2; }
    }
    if ( $path->isDir() ) { $zip->addEmptyDir( $rel ); } else { $zip->addFile( $real, $rel ); }
}
$zip->close();
WP_CLI::success( 'Archived.' );
PHPZIP
}

# Run a PHP snippet through WP-CLI against $1 (site dir); remaining args are
# passed to the script as $args.
wp_eval() {
    local site_dir="$1" script="$2"; shift 2
    local tmp_php
    tmp_php=$(mktemp "${TMPDIR:-/tmp}/cove-php-XXXXXX.php") || die "mktemp failed"
    "$script" > "$tmp_php"
    local rc=0
    $WP eval-file "$tmp_php" "$@" --path="$site_dir" --skip-plugins --skip-themes >&2 || rc=$?
    rm -f "$tmp_php"
    return $rc
}

# --- subcommands --------------------------------------------------------------
cmd_probe() {
    local site_dir="$1"
    resolve_wp || { echo "wp_cli=missing"; exit 0; }
    resolve_archiver || true
    resolve_extractor "" || true
    resolve_db
    echo "wp_cli=${WP}"
    echo "archiver=${ARCHIVER:-none}"
    echo "extractor=${EXTRACTOR:-none}"
    echo "db_dump=${DB_DUMP}"
    echo "db_load=${DB_LOAD}"
    echo "zip=$(have zip && echo y || echo n)"
    echo "unzip=$(have unzip && echo y || echo n)"
    echo "tar=$(have tar && echo y || echo n)"
    echo "mysqldump=$( { have mysqldump || have mariadb-dump; } && echo y || echo n)"
    echo "mysql=$( { have mysql || have mariadb; } && echo y || echo n)"
    echo "php=$(have php && echo y || echo n)"
    if [ -n "$site_dir" ] && [ -d "$site_dir" ]; then
        echo "home=$($WP option get home --path="$site_dir" --skip-plugins --skip-themes 2>/dev/null)"
    fi
}

cmd_backup() {
    local site_dir="$1"; shift
    local -a excludes=()
    local a
    for a in "$@"; do
        case "$a" in --exclude=*) excludes+=("${a#--exclude=}") ;; esac
    done

    [ -d "$site_dir" ] || die "Site directory not found: $site_dir"
    resolve_wp       || die "WP-CLI not found and no PHP to run a phar with."
    resolve_archiver || die "No way to create an archive (need zip, tar, or PHP zip/phar support)."
    resolve_db

    site_dir=$(cd "$site_dir" && pwd -P)
    local parent base
    parent=$(dirname "$site_dir")
    base=$(basename "$site_dir")

    # Named like the old _do output so operators recognise the artefact.
    local stamp rand ext archive
    stamp=$(date +%Y-%m-%d)
    rand=$( (head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n') 2>/dev/null || echo "$$$(date +%s)" )
    rand=$(echo "$rand" | cut -c1-7)
    case "$ARCHIVER" in tar) ext="tar.gz" ;; *) ext="zip" ;; esac
    archive="$parent/${stamp}_${rand}.${ext}"

    # The dump lands inside the site dir so it travels in the archive, exactly
    # where restore expects to find it.
    log "Exporting database..."
    local dump="$site_dir/db_export.sql"
    if [ "$DB_DUMP" = native ]; then
        $WP db export "$dump" --path="$site_dir" --add-drop-table \
            --default-character-set=utf8mb4 --skip-plugins --skip-themes >&2 \
            || die "Database export failed."
    else
        log "  (no mysqldump — exporting through WordPress)"
        wp_eval "$site_dir" php_dump_script "$dump" || die "Database export failed."
    fi

    log "Creating archive (${ARCHIVER})..."
    ( cd "$parent" || exit 1
      case "$ARCHIVER" in
        zip)
            local -a zargs=(-rq "$archive" "$base")
            for a in ${excludes[@]+"${excludes[@]}"}; do zargs+=(-x "$base/$a" "$base/$a/*"); done
            zip "${zargs[@]}" ;;
        tar)
            local -a targs=()
            for a in ${excludes[@]+"${excludes[@]}"}; do targs+=(--exclude="$base/$a"); done
            tar -czf "$archive" ${targs[@]+"${targs[@]}"} "$base" ;;
        php|phar)
            local -a pargs=(create "$archive" "$site_dir")
            for a in ${excludes[@]+"${excludes[@]}"}; do pargs+=("$a"); done
            wp_eval "$site_dir" php_archive_script "${pargs[@]}" ;;
      esac ) || { rm -f "$dump"; die "Archive creation failed."; }

    rm -f "$dump"
    [ -f "$archive" ] || die "Archive was not created."
    echo "$archive"
}

cmd_restore() {
    local site_dir="$1" archive="$2"; shift 2
    local url_to=""
    local a
    for a in "$@"; do
        case "$a" in --url-to=*) url_to="${a#--url-to=}" ;; esac
    done

    [ -d "$site_dir" ] || die "Site directory not found: $site_dir"
    [ -f "$archive" ]  || die "Archive not found: $archive"
    resolve_wp || die "WP-CLI not found and no PHP to run a phar with."
    resolve_extractor "$archive" || die "No way to extract the archive (need unzip, tar, or PHP zip support)."
    resolve_db

    site_dir=$(cd "$site_dir" && pwd -P)
    archive=$(cd "$(dirname "$archive")" && pwd -P)/$(basename "$archive")

    # Defence in depth around the one destructive step in this engine (the
    # rm -rf below). `cove pull` always targets a Cove-managed site directory,
    # and `cove push` probes the remote first and refuses anything that isn't a
    # live WordPress install — so a stray --path cannot reach the wipe today.
    # But this helper is a standalone script piped over SSH, so any future
    # caller that skips that probe would otherwise hand rm -rf whatever it was
    # given. Refuse the obviously catastrophic targets outright, and require
    # the destination to actually look like WordPress.
    case "$site_dir" in
        /|/usr|/etc|/var|/var/www|/home|/root|/Users|/opt|/srv|/tmp|"$HOME")
            die "Refusing to restore over $site_dir." ;;
    esac
    if [ ! -f "$site_dir/wp-config.php" ] && [ ! -f "$site_dir/wp-load.php" ] && [ ! -d "$site_dir/wp-includes" ]; then
        die "Refusing to restore over $site_dir: it does not look like a WordPress install."
    fi

    local work
    work=$(mktemp -d "${TMPDIR:-/tmp}/cove-restore-XXXXXX") || die "mktemp failed"
    # shellcheck disable=SC2064
    trap "rm -rf '$work'" EXIT

    log "Extracting archive (${EXTRACTOR})..."
    case "$EXTRACTOR" in
        unzip) unzip -qo "$archive" -d "$work" ;;
        tar)   tar -xzf "$archive" -C "$work" ;;
        php|phar) wp_eval "$site_dir" php_archive_script extract "$archive" "$work" ;;
    esac || die "Extraction failed."

    # Archives carry a single top-level directory (the site folder). Descend
    # into it when present so both shapes restore identically.
    local src="$work"
    local entries
    entries=$(find "$work" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')
    if [ "$entries" = "1" ]; then
        local only
        only=$(find "$work" -mindepth 1 -maxdepth 1)
        [ -d "$only" ] && src="$only"
    fi

    local sql
    sql=$(find "$src" -maxdepth 1 -name '*.sql' | head -1)
    [ -n "$sql" ] || die "No .sql file found in the archive."

    # Preserve the destination's own wp-config.php: its credentials are the
    # ones that work here. Shipping the source's would point the restored site
    # at a database that does not exist on this machine.
    local keep_config=""
    if [ -f "$site_dir/wp-config.php" ]; then
        keep_config="$work/wp-config.php.keep"
        cp "$site_dir/wp-config.php" "$keep_config"
    fi

    log "Replacing files..."
    # Clear the destination except wp-config.php, then move the new tree in.
    find "$site_dir" -mindepth 1 -maxdepth 1 ! -name 'wp-config.php' -exec rm -rf {} + 2>/dev/null
    ( cd "$src" && find . -mindepth 1 -maxdepth 1 ! -name 'wp-config.php' \
        -exec cp -R {} "$site_dir/" \; ) || die "Copying files failed."
    if [ -n "$keep_config" ]; then
        cp "$keep_config" "$site_dir/wp-config.php"

        # Keeping the config also keeps its $table_prefix — almost always `wp_`
        # from `cove add` — while the dump carries the source's tables under
        # whatever prefix the source used. Left alone, WordPress looks for
        # wp_options in a database full of xyz_options, and the URL rewrite
        # below silently no-ops too, since it can't read `home` either (#7).
        # The source's own config travelled in the archive even though it is
        # never copied into place, so sync the prefix from it — or, failing
        # that, from the dump's table names.
        local src_prefix dest_prefix
        src_prefix=$(read_table_prefix "$src/wp-config.php")
        [ -n "$src_prefix" ] || src_prefix=$(infer_table_prefix_from_dump "$sql")
        dest_prefix=$(read_table_prefix "$site_dir/wp-config.php")
        if [ -n "$src_prefix" ] && [ "$src_prefix" != "$dest_prefix" ]; then
            log "Setting \$table_prefix to '$src_prefix' to match the imported tables (was '${dest_prefix:-unset}')..."
            $WP config set table_prefix "$src_prefix" --type=variable --path="$site_dir" \
                --skip-plugins --skip-themes >&2 \
                || die "Could not update \$table_prefix in wp-config.php."
        fi
    fi
    rm -f "$site_dir"/*.sql

    log "Importing database..."
    if [ "$DB_LOAD" = native ]; then
        $WP db reset --yes --path="$site_dir" --skip-plugins --skip-themes >&2 \
            || die "Database reset failed."
        $WP db import "$sql" --path="$site_dir" --skip-plugins --skip-themes >&2 \
            || die "Database import failed."
    else
        log "  (no mysql client — importing through WordPress)"
        # The dump's DROP TABLE statements make a separate reset unnecessary,
        # which matters here because `wp db reset` also needs the native client.
        wp_eval "$site_dir" php_load_script "$sql" || die "Database import failed."
    fi

    if [ -n "$url_to" ]; then
        local url_from
        url_from=$($WP option get home --path="$site_dir" --skip-plugins --skip-themes 2>/dev/null)
        if [ -n "$url_from" ] && [ "$url_from" != "$url_to" ]; then
            log "Rewriting URLs: $url_from -> $url_to"
            $WP search-replace "$url_from" "$url_to" --all-tables --skip-columns=guid \
                --path="$site_dir" --skip-plugins --skip-themes --quiet >&2 \
                || log "  (URL rewrite reported errors)"
            # search-replace covers serialized data but not a home/siteurl that
            # differed in scheme only; set them outright to be certain.
            $WP option update home "$url_to" --path="$site_dir" --skip-plugins --skip-themes >&2 2>/dev/null
            $WP option update siteurl "$url_to" --path="$site_dir" --skip-plugins --skip-themes >&2 2>/dev/null
        fi
    fi

    $WP cache flush --path="$site_dir" --skip-plugins --skip-themes >&2 2>/dev/null
    log "Restore complete."
}

# --- entry --------------------------------------------------------------------
QUIET=false
SUB="${1:-}"; shift 2>/dev/null || true
ARGS=()
for a in "$@"; do
    case "$a" in
        --quiet)    QUIET=true ;;
        --wp-cli=*) WP_CLI_PHAR="${a#--wp-cli=}" ;;
        *)          ARGS+=("$a") ;;
    esac
done
set -- ${ARGS+"${ARGS[@]}"}

case "$SUB" in
    probe)   cmd_probe   "${1:-}" ;;
    backup)  [ $# -ge 1 ] || die "usage: backup <site_dir> [--exclude=GLOB]..."; cmd_backup  "$@" ;;
    restore) [ $# -ge 2 ] || die "usage: restore <site_dir> <archive> [--url-to=URL]"; cmd_restore "$@" ;;
    *)       die "unknown subcommand: ${SUB:-<none>}" ;;
esac
COVE_TRANSFER_HELPER
}

# --- Cove-side plumbing -------------------------------------------------------

# Run the helper on this machine.
transfer_local() {
    transfer_helper_source | bash -s -- "$@"
}

# Run the helper on the remote, piping it in over the SSH connection pull/push
# already hold open. Nothing is written to the remote filesystem, so there is
# no installer to clean up and no trace left if the run dies partway.
# $1 = ssh option string (unquoted on purpose), $2 = connection, rest = args.
transfer_remote() {
    local opts="$1" conn="$2"; shift 2
    # shellcheck disable=SC2086
    transfer_helper_source | ssh $opts $conn "bash -s -- $(transfer_quote_args "$@")"
}

# Quote helper arguments for the single remote shell string.
transfer_quote_args() {
    local out="" a
    for a in "$@"; do
        out="$out $(shell_quote "$a")"
    done
    echo "$out"
}

# Cache wp-cli.phar locally so it can be sideloaded to a remote that has no
# WP-CLI at all (tier 4). The phar is architecture-independent, which is why
# it is the one binary worth pushing rather than trying to package-install.
transfer_wp_cli_phar() {
    local cache_dir="$COVE_DIR/cache"
    local phar="$cache_dir/wp-cli.phar"
    mkdir -p "$cache_dir"
    if [ ! -s "$phar" ]; then
        curl -sL "$COVE_WP_CLI_PHAR_URL" -o "$phar" || return 1
        [ -s "$phar" ] || { rm -f "$phar"; return 1; }
    fi
    echo "$phar"
}

# Ensure the remote can run WP-CLI, sideloading the phar when it can't.
# Echoes a "--wp-cli=<path>" flag to append (empty when the remote is fine).
# $1 = ssh opts, $2 = connection, $3 = remote site dir.
transfer_ensure_remote_wp_cli() {
    local opts="$1" conn="$2" site_dir="$3"
    local probe
    probe=$(transfer_remote "$opts" "$conn" probe "$site_dir" 2>/dev/null)
    if ! echo "$probe" | grep -q '^wp_cli=missing'; then
        echo ""
        return 0
    fi
    echo "   - Remote has no WP-CLI; sideloading wp-cli.phar over SSH..." >&2
    local phar
    phar=$(transfer_wp_cli_phar) || { echo "" ; return 0; }
    local remote_phar="/tmp/cove-wp-cli.phar"
    # shellcheck disable=SC2086
    if ! ssh $opts $conn "cat > $remote_phar" < "$phar"; then
        echo ""
        return 0
    fi
    echo "--wp-cli=$remote_phar"
}

# `cove transfer probe [site]` — surface the capability ladder for debugging a
# host that pull/push struggles with.
cove_transfer() {
    local sub="${1:-}"; shift 2>/dev/null || true
    case "$sub" in
        probe)
            local target="${1:-}"
            if [ -n "$target" ] && [[ "$target" != /* ]]; then
                target="$SITES_DIR/${target%.localhost}.localhost/public"
            fi
            echo "🔎 Transfer capabilities (local)"
            transfer_local probe "$target"
            ;;
        *)
            echo "Usage: cove transfer probe [site]"
            echo ""
            echo "Reports which tools the backup/restore engine will use here."
            ;;
    esac
}

cove_trust() {
    echo "🔐 Installing Cove's local root certificate..."

    # FrankenPHP's `trust` subcommand writes the Caddy local root into the
    # system store and any NSS DBs it discovers at the standard paths. On
    # macOS that's the login keychain; on Linux it's /usr/local/share/ca-
    # certificates + ~/.pki/nssdb + ~/.mozilla/firefox/*.
    #
    # Safe to re-run — all writes are idempotent.

    if [ "$OS" = "linux" ]; then
        # certutil (libnss3-tools / nss-tools) is needed to touch NSS DBs.
        # Without it Firefox and Chromium keep showing the "Not Secure"
        # warning even though curl and Chrome-with-system-roots are fine.
        if ! command -v certutil &>/dev/null; then
            echo "   - Installing NSS tools for browser trust..."
            if [ "$PKG_MANAGER" = "apt" ]; then
                $SUDO_CMD apt install -y libnss3-tools &>/dev/null || true
            elif [ "$PKG_MANAGER" = "dnf" ]; then
                $SUDO_CMD dnf install -y nss-tools &>/dev/null || true
            fi
        fi
    fi

    # Run the built-in trust installer. Needs sudo on Linux to write to
    # /usr/local/share/ca-certificates and re-run update-ca-certificates.
    # `frankenphp trust` talks to the Caddy admin API on :2019 to fetch the
    # current root — so if Caddy isn't up (common right after `cove install`
    # fails to start the service) the call errors with "connection refused"
    # and the remainder of the trust work is a no-op. Capture the exit code
    # so the final success banner only fires when something was actually
    # installed.
    echo "   - Running frankenphp trust..."
    local trust_output trust_rc=0
    if [ "$OS" = "linux" ]; then
        trust_output=$($SUDO_CMD "$CADDY_CMD" trust 2>&1)
        trust_rc=$?
    else
        trust_output=$("$CADDY_CMD" trust 2>&1)
        trust_rc=$?
    fi
    echo "$trust_output" | grep -vE '^\{|^$' || true

    # Linux-only: Firefox and Chromium ship as snaps on Ubuntu 22+ and
    # store their NSS DBs under ~/snap/... — a path that neither Caddy nor
    # mkcert scans. Inject the root explicitly for each profile we find.
    if [ "$OS" = "linux" ] && command -v certutil &>/dev/null; then
        local root_cert
        root_cert=$(find "$HOME/.local/share/caddy/pki/authorities/local" \
            -maxdepth 1 -name 'root.crt' 2>/dev/null | head -1)
        # Fallback: the system-trust copy Caddy drops on first auto-install.
        if [ -z "$root_cert" ]; then
            root_cert=$(find /usr/local/share/ca-certificates \
                -maxdepth 1 -name 'Caddy_Local_Authority*.crt' 2>/dev/null | head -1)
        fi

        if [ -n "$root_cert" ] && [ -r "$root_cert" ]; then
            # Snap Firefox, snap Chromium, plus any other NSS DB under ~/snap.
            # The `sql:` prefix tells certutil the DB is the modern cert9 format.
            local db
            while IFS= read -r db; do
                [ -z "$db" ] && continue
                local profile_dir
                profile_dir=$(dirname "$db")
                echo "   - Trusting in $(echo "$profile_dir" | sed "s|$HOME|~|")"
                # Remove any prior entry under our nickname so re-runs don't
                # layer stale copies, then add the current root.
                certutil -D -d sql:"$profile_dir" -n "Cove Local Authority" 2>/dev/null || true
                certutil -A -d sql:"$profile_dir" -n "Cove Local Authority" -t "C,," -i "$root_cert" 2>/dev/null || true
            done < <(find "$HOME/snap" "$HOME/.mozilla/firefox" \
                -name 'cert9.db' 2>/dev/null)
        else
            gum style --foreground yellow "⚠️ Could not locate Caddy root.crt — snap Firefox/Chromium trust skipped."
        fi
    fi

    echo ""
    if [ "$trust_rc" -eq 0 ]; then
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 \
            "✅ Local SSL trust installed" \
            "If a browser was open during this run, restart it to pick up the new CA."
    else
        # Tailor the hint based on what frankenphp actually said — "connection
        # refused" almost always means Caddy's admin API isn't up yet.
        if echo "$trust_output" | grep -q "connection refused"; then
            gum style --border normal --margin "1" --padding "1 2" --border-foreground yellow \
                "⚠️ Trust install skipped — Cove server isn't running yet" \
                "Run 'cove enable' then 'cove trust' to finish installing the local root."
        else
            gum style --border normal --margin "1" --padding "1 2" --border-foreground yellow \
                "⚠️ Trust install did not complete" \
                "Re-run 'cove trust' once Cove is running to try again."
        fi
    fi
}

upgrade_frankenphp() {
    local frankenphp_path
    frankenphp_path=$(command -v frankenphp)
    
    # Check if installed via package manager (typically at /usr/bin/frankenphp)
    if [ "$frankenphp_path" = "/usr/bin/frankenphp" ]; then
        # Package manager installation - use apt/dnf to upgrade
        if [ "$PKG_MANAGER" = "apt" ]; then
            echo "   - FrankenPHP installed via apt. Upgrading with apt..."
            if $SUDO_CMD apt update && $SUDO_CMD apt install --only-upgrade -y frankenphp; then
                echo "   - ✅ FrankenPHP upgraded successfully via apt."
            else
                gum style --foreground red "❌ Failed to upgrade FrankenPHP via apt."
                return 1
            fi
        elif [ "$PKG_MANAGER" = "dnf" ]; then
            echo "   - FrankenPHP installed via dnf. Upgrading with dnf..."
            if $SUDO_CMD dnf upgrade -y frankenphp; then
                echo "   - ✅ FrankenPHP upgraded successfully via dnf."
            else
                gum style --foreground red "❌ Failed to upgrade FrankenPHP via dnf."
                return 1
            fi
        else
            echo "   - ⚠️ Unknown package manager for FrankenPHP at /usr/bin. Skipping upgrade."
            return 1
        fi
    else
        # Static binary installation - download directly
        local target_bin_dir
        if [ -n "$frankenphp_path" ]; then
            target_bin_dir=$(dirname "$frankenphp_path")
            echo "   - Detected static FrankenPHP binary in '$target_bin_dir'."
        else
            target_bin_dir="$BIN_DIR"
            echo "   - FrankenPHP not found. Using default: $target_bin_dir"
        fi
        
        echo "   - Downloading latest FrankenPHP static binary..."
        
        # Determine the correct binary for this platform
        local arch=$(uname -m)
        local os=$(uname -s)
        local binary_name=""
        
        if [ "$os" = "Linux" ]; then
            case $arch in
                x86_64) binary_name="frankenphp-linux-x86_64" ;;
                aarch64) binary_name="frankenphp-linux-aarch64" ;;
            esac
            # Check for glibc
            if getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
                binary_name="${binary_name}-gnu"
            fi
        elif [ "$os" = "Darwin" ]; then
            case $arch in
                arm64) binary_name="frankenphp-mac-arm64" ;;
                x86_64) binary_name="frankenphp-mac-x86_64" ;;
            esac
        fi
        
        if [ -z "$binary_name" ]; then
            gum style --foreground red "❌ No precompiled FrankenPHP binary available for $os/$arch"
            return 1
        fi
        
        local temp_binary="/tmp/frankenphp_new"
        if curl -L --progress-bar "https://github.com/php/frankenphp/releases/latest/download/${binary_name}" -o "$temp_binary"; then
            chmod +x "$temp_binary"
            if sudo mv "$temp_binary" "$target_bin_dir/frankenphp"; then
                # Set capability to bind to low ports without root
                if command -v setcap &>/dev/null; then
                    $SUDO_CMD setcap 'cap_net_bind_service=+ep' "$target_bin_dir/frankenphp" 2>/dev/null || true
                fi
                echo "   - ✅ FrankenPHP upgraded successfully."
            else
                gum style --foreground red "❌ Failed to move FrankenPHP to $target_bin_dir"
                rm -f "$temp_binary"
                return 1
            fi
        else
            gum style --foreground red "❌ Failed to download FrankenPHP binary."
            return 1
        fi
    fi
    
    # Verify mysqli is available after upgrade
    echo "   - Verifying PHP mysqli extension..."
    if ! frankenphp php-cli -r "echo implode(',', get_loaded_extensions());" 2>/dev/null | grep -qi mysqli; then
        gum style --foreground yellow "⚠️ Warning: mysqli extension not found in FrankenPHP."
        gum style --foreground yellow "   WordPress sites may not work correctly."
        return 1
    fi
    echo "   - ✅ mysqli extension verified."
    
    return 0
}

cove_upgrade() {
    local auto_yes=false
    for arg in "$@"; do
        case "$arg" in
            --yes|-y|--force) auto_yes=true ;;
        esac
    done
    # Non-interactive callers have no TTY — auto-yes so the Adminer prompt
    # (only shown when the local version can't be parsed) doesn't hang.
    [ -t 0 ] || auto_yes=true

    echo "🔎 Checking for the latest version of Cove..."

    local download_url="https://github.com/anchorhost/cove/releases/latest/download/cove.sh"
    local temp_script="/tmp/cove.sh.latest"
    local install_path

    # Find the real path of the currently running script. $0 is authoritative:
    # when cove runs via a shell alias or absolute path, `command -v cove`
    # finds whatever happens to sit in PATH — possibly a different, older
    # copy. (A stale v1.8 in /opt/homebrew/bin once answered a v1.11
    # upgrade's post-upgrade/reload calls: "Unknown command 'post-upgrade'",
    # plus a reload through three-versions-old generators.) PATH lookup is
    # only the fallback when $0 is unusable.
    install_path="$(cd "$(dirname "$0")" 2>/dev/null && pwd -P)/$(basename "$0")"
    if [ ! -f "$install_path" ]; then
        install_path=$(command -v cove)
    fi
    if [ -z "$install_path" ]; then
        install_path="/usr/local/bin/cove" # Fallback to default
    fi

    # 1. Download the latest script
    echo "   - Downloading latest Cove script from GitHub..."
    if ! curl -L --fail --progress-bar "$download_url" -o "$temp_script"; then
        echo "❌ Error: Failed to download the latest version. Please check your connection."
        rm -f "$temp_script" 2>/dev/null
        return 1
    fi

    # 2. Make it executable
    chmod +x "$temp_script"

    # 3. Get the new version from the downloaded script
    local new_version
    new_version=$("$temp_script" version | awk '{print $3}')

    if [ -z "$new_version" ]; then
        echo "❌ Error: Could not determine the version from the downloaded script."
        rm -f "$temp_script" 2>/dev/null
        return 1
    fi

    # 4. Get the current version from the running script
    local current_version="$COVE_VERSION"
    echo "   - Current Cove version:         $current_version"
    echo "   - Latest available Cove version: $new_version"

    # 5. Compare versions
    local latest
    latest=$(printf '%s\n' "$current_version" "$new_version" | sort -V | tail -n1)

    if [[ "$latest" == "$current_version" ]] && [[ "$new_version" != "$current_version" ]]; then
         echo "✅ Your current Cove version ($current_version) is newer than the latest release ($new_version). No action taken."
         rm -f "$temp_script" 2>/dev/null
    elif [[ "$latest" == "$current_version" ]]; then
        echo "✅ You are already using the latest version of Cove."
        rm -f "$temp_script" 2>/dev/null
    else
        # 6. Perform the Cove upgrade
        echo "🚀 Upgrading Cove to version $new_version..."

        if [ ! -w "$(dirname "$install_path")" ]; then
            echo "❌ Error: No write permissions for '$(dirname "$install_path")'."
            echo "   Please try running with sudo: 'sudo cove upgrade'"
            rm -f "$temp_script" 2>/dev/null
            return 1
        fi

        if ! mv "$temp_script" "$install_path"; then
            echo "❌ Error: Failed to replace the old script at '$install_path'."
            rm -f "$temp_script" 2>/dev/null
        else
            echo "✅ Cove has been successfully upgraded to version $new_version!"
            echo "   Run 'cove version' to see the new version."
        fi
    fi

    # --- New Section: FrankenPHP Upgrade Check ---
    echo ""
    echo "🔎 Checking for FrankenPHP updates..."

    if ! command -v frankenphp &> /dev/null; then
        echo "   - ⚠️ FrankenPHP not found. Skipping update check."
        return 0
    fi

    # Get local version (strip 'v' prefix if present)
    local local_frankenphp_version
    local_frankenphp_version=$(frankenphp version | awk '{print $2}' | sed 's/^v//')
    if [ -z "$local_frankenphp_version" ]; then
        echo "   - ❌ Could not determine local FrankenPHP version. Skipping update check."
        return 1
    fi

    # Get latest version from GitHub redirect (strip 'v' prefix)
    local latest_frankenphp_version
    latest_frankenphp_version=$(curl -sL -o /dev/null -w '%{url_effective}' https://github.com/php/frankenphp/releases/latest | sed 's/.*\/v//')

    if [ -z "$latest_frankenphp_version" ]; then
        echo "   - ❌ Could not determine the latest FrankenPHP version from GitHub. Skipping update check."
        return 1
    fi

    echo "   - Current FrankenPHP version:  $local_frankenphp_version"
    echo "   - Latest available version:    $latest_frankenphp_version"

    # Compare versions using sort -V (works without PHP)
    local needs_upgrade="false"
    if [ "$local_frankenphp_version" != "$latest_frankenphp_version" ]; then
        local older_version
        older_version=$(printf '%s\n' "$local_frankenphp_version" "$latest_frankenphp_version" | sort -V | head -n1)
        if [ "$older_version" = "$local_frankenphp_version" ]; then
            needs_upgrade="true"
        fi
    fi

    if [ "$needs_upgrade" == "true" ]; then
        echo "🚀 Upgrading FrankenPHP to version $latest_frankenphp_version..."
        if upgrade_frankenphp; then
            # The on-disk binary is new, but the running process is still the
            # old one. `caddy reload` adapts with the NEW binary (which may
            # emit JSON fields the old handler rejects — 1.12.7's php_server
            # adapter adds `route_group`) and POSTs that at the old process.
            # Stop it now so the later `cove reload` starts the new binary
            # (launchd KeepAlive / systemd Restart=on-failure will also
            # respawn it from the new file).
            echo "   - Stopping the old FrankenPHP process so the next reload starts $latest_frankenphp_version..."
            "$CADDY_CMD" stop --config "$CADDYFILE_PATH" &>/dev/null || true
        fi
    else
        echo "✅ FrankenPHP is already up to date."
    fi
    
    # --- Adminer Upgrade Check ---
    echo ""
    echo "🔎 Checking for Adminer updates..."
    
    local adminer_file="$ADMINER_DIR/adminer-core.php"
    if [ ! -f "$adminer_file" ]; then
        echo "   - ⚠️ Adminer not found. Skipping update check."
        return 0
    fi
    
    # Get current Adminer version from the file (portable — BSD grep has no -P/\K)
    local current_adminer_version
    current_adminer_version=$(LC_ALL=C sed -nE 's/.*VERSION="([0-9]+\.[0-9]+\.[0-9]+)".*/\1/p' "$adminer_file" 2>/dev/null | head -1)
    if [ -z "$current_adminer_version" ]; then
        current_adminer_version=$(LC_ALL=C sed -nE 's/.*@version[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' "$adminer_file" 2>/dev/null | head -1)
    fi
    
    if [ -z "$current_adminer_version" ]; then
        echo "   - ⚠️ Could not determine current Adminer version."
        current_adminer_version="unknown"
    fi
    
    # Get latest version from GitHub
    local latest_adminer_version
    latest_adminer_version=$(curl -sL -o /dev/null -w '%{url_effective}' https://github.com/vrana/adminer/releases/latest | sed 's/.*\/v//')
    
    if [ -z "$latest_adminer_version" ]; then
        echo "   - ❌ Could not determine the latest Adminer version from GitHub."
        return 0
    fi
    
    echo "   - Current Adminer version:  $current_adminer_version"
    echo "   - Latest available version: $latest_adminer_version"
    
    # Compare versions (skip if current is unknown)
    if [ "$current_adminer_version" != "unknown" ]; then
        local adminer_needs_upgrade
        adminer_needs_upgrade=$(LOCAL_V="$current_adminer_version" REMOTE_V="$latest_adminer_version" frankenphp php-cli -r '
            if (version_compare(getenv("LOCAL_V"), getenv("REMOTE_V"), "<")) {
                echo "true";
            } else {
                echo "false";
            }
        ')
        
        if [ "$adminer_needs_upgrade" == "true" ]; then
            echo "🚀 Upgrading Adminer to version $latest_adminer_version..."
            if curl -sL "https://github.com/vrana/adminer/releases/download/v${latest_adminer_version}/adminer-${latest_adminer_version}.php" -o "$adminer_file"; then
                echo "✅ Adminer upgraded successfully."
            else
                echo "❌ Failed to download Adminer $latest_adminer_version."
            fi
        else
            echo "✅ Adminer is already up to date."
        fi
    else
        # If version unknown, offer to upgrade anyway
        local do_download=false
        if [ "$auto_yes" = true ]; then
            do_download=true
        elif gum confirm "Current version unknown. Would you like to download the latest Adminer ($latest_adminer_version)?"; then
            do_download=true
        fi
        if $do_download; then
            echo "🚀 Downloading Adminer $latest_adminer_version..."
            if curl -sL "https://github.com/vrana/adminer/releases/download/v${latest_adminer_version}/adminer-${latest_adminer_version}.php" -o "$adminer_file"; then
                echo "✅ Adminer downloaded successfully."
            else
                echo "❌ Failed to download Adminer $latest_adminer_version."
            fi
        fi
    fi

    # Always refresh the Cove Adminer theme + entry point. Pre-1.10 installs
    # shipped the Catppuccin CSS and a bare index.php without the head()
    # hook — without this step upgraders would keep the old UI even after
    # adminer-core.php gets the latest version.
    echo ""
    echo "🎨 Refreshing Cove Adminer theme..."
    deploy_adminer_theme


    # --- Floor Cove's PHP ini at the current installer default ---
    # Pre-1.10 installers wrote memory_limit=512M (also upload/post=unset).
    # Raise to the 1G floor the fresh installer uses today, but leave any
    # value already >= 1G alone so a user who bumped to 2G stays at 2G.
    local install_default_memory="1G"
    local floor_bytes=$(( 1024 * 1024 * 1024 ))

    mem_to_bytes() {
        local s="${1:-0}" n suffix
        n="${s%[KMGkmg]}"; suffix="${s#$n}"
        case "$suffix" in
            K|k) echo $((n * 1024)) ;;
            M|m) echo $((n * 1024 * 1024)) ;;
            G|g) echo $((n * 1024 * 1024 * 1024)) ;;
            *)   echo "${n:-0}" ;;
        esac
    }

    echo ""
    echo "🧠 Checking PHP memory floor…"
    local bumped_any=false
    local k
    for k in memory_limit upload_max_filesize post_max_size; do
        local current
        current=$(cove_ini_get "$k" "")
        local current_bytes
        current_bytes=$(mem_to_bytes "$current")
        # -1 means unlimited (valid for memory_limit) — it's above any floor,
        # not below it. mem_to_bytes("-1") returns -1, which would otherwise
        # test as < 1G and silently cap a user's unlimited limit at 1G.
        if [ "$current" = "-1" ]; then
            echo "   ✓ ${k}: -1 (unlimited)"
        elif [ -z "$current" ] || [ "$current_bytes" -lt "$floor_bytes" ]; then
            mkdir -p "$(dirname "$PHP_INI_FILE")"
            touch "$PHP_INI_FILE"
            if grep -qE "^[[:space:]]*${k}[[:space:]]*=" "$PHP_INI_FILE"; then
                sed -i.bak -E "s|^[[:space:]]*${k}[[:space:]]*=.*|${k} = ${install_default_memory}|" "$PHP_INI_FILE"
            else
                echo "${k} = ${install_default_memory}" >> "$PHP_INI_FILE"
            fi
            rm -f "${PHP_INI_FILE}.bak"
            echo "   ↑ ${k}: ${current:-unset} → ${install_default_memory}"
            bumped_any=true
        else
            echo "   ✓ ${k}: ${current} (already ≥ ${install_default_memory})"
        fi
    done
    if [ "$bumped_any" = true ]; then
        echo "   (cove reload below regenerates the Caddyfile so the web server picks up the new limits.)"
    fi

    # --- Refresh managed components with the new code ---
    # Whoops (PHP 8.5 compat), its resilient bootstrap, the one-time-login
    # MU-plugin across all sites, and the watchdog service. These are invoked
    # through the freshly-installed on-disk binary because the still-running
    # upgrade process holds the pre-upgrade script — which may not define these
    # functions (or defines older versions), so a direct call would deploy stale
    # bits or fail outright. See the 'post-upgrade' case in main.
    echo ""
    echo "🧩 Refreshing managed components (Whoops, MU-plugin, watchdog)..."
    "$install_path" post-upgrade

    # --- Reload to pull in any UI updates ---
    # Invoke the on-disk binary so a freshly-upgraded script's new functions are used
    # (the currently-running process still holds the pre-upgrade functions in memory).
    echo ""
    echo "🔄 Reloading Cove to apply UI updates..."
    "$install_path" reload
}
cove_url() {
    # -----------------------------------------------------------------
    #  cove url <site>
    #  Prints the HTTPS URL for a given site (e.g. https://foo.localhost)
    # -----------------------------------------------------------------
    local site_name="$1"

    # -------------------------------------------------------------
    #  Basic validation – the command requires exactly one argument.
    # -------------------------------------------------------------
    if [ -z "$site_name" ]; then
        gum style --foreground red "❌ Error: A site name is required."
        echo "Usage: cove url <site>"
        exit 1
    fi

    # -------------------------------------------------------------
    #  Build the expected directory name and verify that it exists.
    # -------------------------------------------------------------
    local site_dir="${SITES_DIR}/${site_name}.localhost"
    if [ ! -d "$site_dir" ]; then
        gum style --foreground red "❌ Error: Site '${site_name}.localhost' not found."
        exit 1
    fi

    # -------------------------------------------------------------
    #  Print the URL – we keep the output plain so it can be piped.
    # -------------------------------------------------------------
    url_for "${site_name}.localhost"
}
cove_version() {
    echo "Cove version $COVE_VERSION"
}
cove_wsl_hosts() {
    if [ "$IS_WSL" != true ]; then
        echo "This command is only available in WSL environments."
        exit 1
    fi
    
    local wsl_ip
    wsl_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    
    if [ -z "$wsl_ip" ]; then
        gum style --foreground red "❌ Could not determine WSL IP address."
        exit 1
    fi
    
    # Build list of all hostnames
    local hostnames="cove.localhost db.cove.localhost mail.cove.localhost"
    
    # Add all site hostnames
    if [ -d "$SITES_DIR" ]; then
        for site_path in "$SITES_DIR"/*; do
            if [ -d "$site_path" ]; then
                local site_hostname
                site_hostname=$(basename "$site_path")
                hostnames="$hostnames $site_hostname"
                
                # Also add any custom mappings
                if [ -f "$site_path/mappings" ]; then
                    while IFS= read -r mapping || [ -n "$mapping" ]; do
                        if [ -n "$mapping" ]; then
                            hostnames="$hostnames $mapping"
                        fi
                    done < "$site_path/mappings"
                fi
            fi
        done
    fi
    
    # Find Caddy's CA certificate path
    local ca_cert="$HOME/.local/share/caddy/pki/authorities/local/root.crt"
    local windows_cert_path=""
    
    # Convert WSL path to Windows path for the certificate
    if [ -f "$ca_cert" ]; then
        windows_cert_path=$(wslpath -w "$ca_cert" 2>/dev/null || echo "")
    fi
    
    echo ""
    gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 \
        "WSL Setup Helper" \
        "" \
        "WSL IP Address: $wsl_ip"
    
    # --- STEP 1: Hosts File ---
    echo ""
    gum style --foreground 212 "━━━ Step 1: Update Windows Hosts File ━━━"
    echo ""
    echo "Run this command in PowerShell (as Administrator):"
    echo ""
    gum style --foreground cyan "Add-Content -Path C:\\Windows\\System32\\drivers\\etc\\hosts -Value \"\`n$wsl_ip $hostnames\""
    echo ""
    echo "Or manually add this line to C:\\Windows\\System32\\drivers\\etc\\hosts:"
    echo ""
    gum style --foreground cyan "$wsl_ip $hostnames"
    
    # --- STEP 2: Certificate Trust ---
    echo ""
    gum style --foreground 212 "━━━ Step 2: Trust Caddy's CA Certificate ━━━"
    echo ""
    echo "To remove browser certificate warnings, install Caddy's root CA in Windows."
    echo ""
    
    if [ -n "$windows_cert_path" ]; then
        echo "The certificate is located at:"
        gum style --foreground cyan "$windows_cert_path"
        echo ""
        echo "Option A: Double-click the certificate in Windows Explorer and install it:"
        echo "  1. Open the path above in Windows Explorer"
        echo "  2. Double-click root.crt"
        echo "  3. Click 'Install Certificate...'"
        echo "  4. Select 'Local Machine' and click Next"
        echo "  5. Select 'Place all certificates in the following store'"
        echo "  6. Click Browse and select 'Trusted Root Certification Authorities'"
        echo "  7. Click Next, then Finish"
        echo ""
        echo "Option B: Run this in PowerShell (as Administrator):"
        echo ""
        gum style --foreground cyan "Import-Certificate -FilePath \"$windows_cert_path\" -CertStoreLocation Cert:\\LocalMachine\\Root"
    else
        echo "Certificate not found at: $ca_cert"
        echo "Make sure Caddy has been started at least once with 'cove enable'."
    fi
    
    echo ""
    gum style --foreground yellow "Note: WSL IP may change on restart. Run 'cove wsl-hosts' again to get updated info."
    echo ""
}

# --- Embedded macOS Menu Bar App (generated from menubar/ by compile.sh) ---

emit_menubar_main_m() {
cat <<'COVE_MENUBAR_MAIN_M_EOF'
// Cove Menu Bar — macOS menu bar companion for Cove.
//
// Originally created by Robby McCullough (github.com/RobbyMcCullough/cove-menubar,
// MIT) and folded into the official Cove project with his blessing.
// Copyright (c) 2026 Robby McCullough. MIT License.
//
// This source is embedded into cove.sh at compile time (see compile.sh) and
// built on the user's machine by `cove menubar enable` — dependency-free,
// clang + system frameworks only. Keep it that way.
//
// Status is read via `cove status --porcelain` (key=value per line) — a
// stable contract defined in commands/status. The human-readable status
// output can change freely; the porcelain keys cannot.
//
// Menu architecture: the menu skeleton is built ONCE, with the three core
// service rows pre-seeded, and every refresh mutates item titles/images in
// place. Rebuilding items on refresh caused two visible glitches: the first
// render had no service rows (so no icon column — text flush left), and the
// first poll's rebuild re-layouted the open menu, making everything jump.

#import <Cocoa/Cocoa.h>
#import <CoreImage/CoreImage.h>
#import <ServiceManagement/ServiceManagement.h>
#import <UserNotifications/UserNotifications.h>

typedef void (^CoveCommandCompletion)(int status, NSString *output, NSError *error);

// Index of the first service row: summary + separator come before it.
static const NSInteger kServiceRowStartIndex = 2;

@interface AppDelegate : NSObject <NSApplicationDelegate, NSMenuDelegate>
@property(nonatomic, strong) NSStatusItem *statusItem;
@property(nonatomic, strong) NSMenu *menu;
@property(nonatomic, strong) NSTimer *refreshTimer;
@property(nonatomic, strong) NSTimer *updateCheckTimer;
// Ordered porcelain keys (caddy, mariadb, mailpit, php-fpm-<ver>...) and
// their running state from the most recent successful poll. serviceStates is
// tri-state via absence: no entry for a key yet = unknown ("…" row).
@property(nonatomic, strong) NSArray<NSString *> *serviceKeys;
@property(nonatomic, strong) NSDictionary<NSString *, NSNumber *> *serviceStates;
@property(nonatomic, assign) BOOL statesKnown;
@property(nonatomic, assign) BOOL busy;
// What the summary row says while busy ("Starting Cove…", "Creating x…").
@property(nonatomic, copy) NSString *busyText;
// Pulses the menu bar icon while a long action runs, so multi-second work
// (site creation, enable) reads as "working" instead of "locked up".
@property(nonatomic, strong) NSTimer *busyPulseTimer;
@property(nonatomic, assign) BOOL pulsePhase;
@property(nonatomic, copy) NSString *lastError;
// A failed user action (create/start/stop/login). Unlike lastError, this is
// NOT cleared by the next successful status poll — only by the next action —
// so the evidence doesn't vanish seconds after the failure.
@property(nonatomic, copy) NSString *lastActionError;
@property(nonatomic, copy) NSString *coveVersion;
@property(nonatomic, copy) NSString *latestVersion;
@property(nonatomic, assign) CFAbsoluteTime lastUserActionTime;
// Services seen newly stopped on the last poll, awaiting a second consecutive
// stopped poll before the "stopped unexpectedly" notification fires. Absorbs
// transient restarts (a terminal-run `cove enable`, service churn during
// `cove upgrade`) that a single-poll snapshot would misread as a crash.
@property(nonatomic, strong) NSMutableSet<NSString *> *pendingStopKeys;
@property(nonatomic, assign) BOOL notificationsAllowed;
@property(nonatomic, strong) NSImage *runningImage;
@property(nonatomic, strong) NSImage *partialImage;
@property(nonatomic, strong) NSImage *stoppedImage;
// Stable menu items, created once and mutated in place.
@property(nonatomic, strong) NSMenuItem *summaryItem;
@property(nonatomic, strong) NSMutableArray<NSMenuItem *> *serviceItems;
@property(nonatomic, strong) NSArray<NSString *> *serviceItemKeys;
@property(nonatomic, strong) NSMenuItem *errorItem;
@property(nonatomic, strong) NSMenuItem *actionItem;
@property(nonatomic, strong) NSMenuItem *refreshItem;
@property(nonatomic, strong) NSMenuItem *reloadItem;
@property(nonatomic, strong) NSMenuItem *sitesItem;
@property(nonatomic, strong) NSMenuItem *dashboardItem;
@property(nonatomic, strong) NSMenuItem *adminerItem;
@property(nonatomic, strong) NSMenuItem *mailpitItem;
@property(nonatomic, strong) NSMenuItem *launchItem;
@property(nonatomic, strong) NSMenuItem *versionItem;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
    // NSStatusItem persists its visible flag in this app's defaults domain
    // (run.cove.menubar). A stale 0 there — e.g. left behind by the original
    // standalone build — would make every launch silently invisible, and
    // `cove menubar enable` replaces the bundle without touching preferences.
    // The item is never removal-allowed, so a hidden state can only be stale;
    // force it visible.
    self.statusItem.visible = YES;
    [self loadStatusImages];

    // Seed the core trio before the first poll so the very first render
    // already has the service rows (and their icon column). PHP-FPM rows for
    // pinned sites are appended when the first poll reports them.
    self.serviceKeys = @[ @"caddy", @"mariadb", @"mailpit" ];
    self.serviceStates = @{};
    self.serviceItems = [NSMutableArray array];
    self.serviceItemKeys = @[];

    [self buildMenuSkeleton];
    [self updateMenu];

    __weak typeof(self) weakSelf = self;
    [[UNUserNotificationCenter currentNotificationCenter]
        requestAuthorizationWithOptions:UNAuthorizationOptionAlert
                      completionHandler:^(BOOL granted, NSError *error) {
                          (void)error;
                          dispatch_async(dispatch_get_main_queue(), ^{
                              weakSelf.notificationsAllowed = granted;
                          });
                      }];

    [[[NSWorkspace sharedWorkspace] notificationCenter]
        addObserver:self
        selector:@selector(refreshStatus)
        name:NSWorkspaceDidWakeNotification
        object:nil];

    [self refreshStatus];

    // The menu refreshes on open (menuWillOpen:), so the timer only keeps the
    // *icon* honest. A generous interval + tolerance lets macOS coalesce the
    // wakeups instead of spinning up a bash pipeline every few seconds.
    self.refreshTimer = [NSTimer scheduledTimerWithTimeInterval:20.0
                                                        target:self
                                                      selector:@selector(refreshStatus)
                                                      userInfo:nil
                                                       repeats:YES];
    self.refreshTimer.tolerance = 5.0;

    [self checkForUpdates];
    self.updateCheckTimer = [NSTimer scheduledTimerWithTimeInterval:86400.0
                                                             target:self
                                                           selector:@selector(checkForUpdates)
                                                           userInfo:nil
                                                            repeats:YES];
    self.updateCheckTimer.tolerance = 3600.0;
}

- (void)menuWillOpen:(NSMenu *)menu {
    // Rebuild the Sites submenu before display (it isn't visible yet, so
    // this can't cause an on-screen re-layout), then poll for fresh state —
    // whose completion only mutates titles/images in place.
    [self rebuildSitesSubmenu];
    [self refreshStatus];
}

#pragma mark - Status polling

- (void)refreshStatus {
    if (self.busy) {
        return;
    }

    __weak typeof(self) weakSelf = self;
    [self runCoveWithArguments:@[@"status", @"--porcelain"]
                       timeout:20.0
                    completion:^(int status, NSString *output, NSError *error) {
        AppDelegate *strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        if (status == 0) {
            // Clear the prior error FIRST — applyPorcelainOutput may set a new
            // one (unparseable output), and it must survive this call.
            strongSelf.lastError = nil;
            [strongSelf applyPorcelainOutput:output];
        } else {
            strongSelf.lastError = error.localizedDescription ?: @"Unable to read Cove status.";
        }

        [strongSelf updateMenu];
    }];
}

- (void)applyPorcelainOutput:(NSString *)output {
    NSMutableArray<NSString *> *keys = [NSMutableArray array];
    NSMutableDictionary<NSString *, NSNumber *> *states = [NSMutableDictionary dictionary];

    for (NSString *rawLine in [output componentsSeparatedByCharactersInSet:
                               [NSCharacterSet newlineCharacterSet]]) {
        NSString *line = [rawLine stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceCharacterSet]];
        NSRange eq = [line rangeOfString:@"="];
        if (eq.location == NSNotFound || eq.location == 0) {
            continue;
        }
        NSString *key = [line substringToIndex:eq.location];
        NSString *value = [line substringFromIndex:eq.location + 1];

        if ([key isEqualToString:@"version"]) {
            self.coveVersion = value;
            continue;
        }
        if ([value isEqualToString:@"running"] || [value isEqualToString:@"stopped"]) {
            [keys addObject:key];
            states[key] = @([value isEqualToString:@"running"]);
        }
    }

    if (keys.count == 0) {
        // Porcelain output we can't read — treat as an error, not "all down".
        self.lastError = @"Unexpected status output from Cove.";
        return;
    }

    [self notifyUnexpectedStopsFrom:self.serviceStates to:states];

    self.serviceKeys = keys;
    self.serviceStates = states;
    self.statesKnown = YES;
}

// Post a notification for a service that died out from under a running stack.
// Suppressed when: states aren't established yet, the user just acted through
// the menu (start/stop churn), or EVERYTHING went down at once — that shape is
// almost always a deliberate `cove disable` from a terminal, not a crash.
// A stop must also survive TWO consecutive polls before it notifies: a service
// mid-restart (terminal-run `cove enable`, the multi-minute service churn of
// `cove upgrade`) is back up by the next poll and never alarms.
- (void)notifyUnexpectedStopsFrom:(NSDictionary<NSString *, NSNumber *> *)oldStates
                               to:(NSDictionary<NSString *, NSNumber *> *)newStates {
    if (!self.pendingStopKeys) {
        self.pendingStopKeys = [NSMutableSet set];
    }
    if (!self.statesKnown || !self.notificationsAllowed) {
        [self.pendingStopKeys removeAllObjects];
        return;
    }
    if (CFAbsoluteTimeGetCurrent() - self.lastUserActionTime < 20.0) {
        [self.pendingStopKeys removeAllObjects];
        return;
    }

    BOOL anyStillRunning = NO;
    for (NSNumber *running in newStates.allValues) {
        if (running.boolValue) {
            anyStillRunning = YES;
            break;
        }
    }
    if (!anyStillRunning) {
        [self.pendingStopKeys removeAllObjects];
        return;
    }

    NSMutableSet<NSString *> *stillPending = [NSMutableSet set];
    for (NSString *key in newStates) {
        if (newStates[key].boolValue) {
            continue;   // running — any pending suspicion is dropped
        }
        if (oldStates[key].boolValue) {
            // Newly stopped: hold for confirmation on the next poll.
            [stillPending addObject:key];
        } else if ([self.pendingStopKeys containsObject:key]) {
            // Stopped on the previous poll too — confirmed dead.
            [self postNotificationWithBody:
                [NSString stringWithFormat:@"%@ stopped unexpectedly.",
                 [self displayNameForServiceKey:key]]];
        }
    }
    self.pendingStopKeys = stillPending;
}

- (void)postNotificationWithBody:(NSString *)body {
    if (!self.notificationsAllowed) {
        return;
    }
    UNMutableNotificationContent *content = [[UNMutableNotificationContent alloc] init];
    content.title = @"Cove";
    content.body = body;
    UNNotificationRequest *request =
        [UNNotificationRequest requestWithIdentifier:[NSUUID UUID].UUIDString
                                             content:content
                                             trigger:nil];
    [[UNUserNotificationCenter currentNotificationCenter]
        addNotificationRequest:request withCompletionHandler:nil];
}

// Async action failures avoid NSAlert on purpose: a modal from an accessory
// app can land behind a full-screen window where it silently blocks the main
// thread. Instead: notification + persistent menu error row + a durable log
// of the full command output at ~/Cove/Logs/menubar.log.
- (void)reportActionFailure:(NSString *)title detail:(NSString *)detail {
    NSString *firstLine = [[detail componentsSeparatedByCharactersInSet:
                            [NSCharacterSet newlineCharacterSet]] firstObject] ?: @"";
    self.lastActionError = title;
    [self postNotificationWithBody:[NSString stringWithFormat:@"%@ — %@", title, firstLine]];
    [self appendToLog:[NSString stringWithFormat:@"%@\n%@\n", title, detail]];
    [self updateMenu];
}

- (void)appendToLog:(NSString *)text {
    NSString *logsDir = [NSHomeDirectory() stringByAppendingPathComponent:@"Cove/Logs"];
    NSString *path = [logsDir stringByAppendingPathComponent:@"menubar.log"];
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss";
    NSString *stamped = [NSString stringWithFormat:@"[%@] %@\n",
                         [formatter stringFromDate:[NSDate date]], text];

    NSFileManager *fileManager = [NSFileManager defaultManager];
    [fileManager createDirectoryAtPath:logsDir withIntermediateDirectories:YES
                            attributes:nil error:nil];
    if (![fileManager fileExistsAtPath:path]) {
        [fileManager createFileAtPath:path contents:nil attributes:nil];
    }
    NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:path];
    [handle seekToEndOfFile];
    [handle writeData:[stamped dataUsingEncoding:NSUTF8StringEncoding]];
    [handle closeFile];
}

- (NSString *)displayNameForServiceKey:(NSString *)key {
    if ([key isEqualToString:@"caddy"])   { return @"Caddy"; }
    if ([key isEqualToString:@"mariadb"]) { return @"MariaDB"; }
    if ([key isEqualToString:@"mailpit"]) { return @"Mailpit"; }
    if ([key hasPrefix:@"php-fpm-"]) {
        return [NSString stringWithFormat:@"PHP-FPM %@",
                [key substringFromIndex:[@"php-fpm-" length]]];
    }
    return key;
}

- (BOOL)serviceRunning:(NSString *)key {
    return self.serviceStates[key].boolValue;
}

- (NSInteger)runningServiceCount {
    NSInteger count = 0;
    for (NSNumber *running in self.serviceStates.allValues) {
        if (running.boolValue) {
            count++;
        }
    }
    return count;
}

- (BOOL)allServicesRunning {
    if (!self.statesKnown || self.serviceKeys.count == 0) {
        return NO;
    }
    for (NSString *key in self.serviceKeys) {
        if (!self.serviceStates[key].boolValue) {
            return NO;
        }
    }
    return YES;
}

#pragma mark - Actions

- (void)startCove {
    [self runActionWithArguments:@[@"enable"] actionName:@"start" busyText:@"Starting Cove…"];
}

- (void)stopCove {
    [self runActionWithArguments:@[@"disable"] actionName:@"stop" busyText:@"Stopping Cove…"];
}

// Regenerates the Caddyfile and reloads Caddy — the thing you want after
// hand-editing a directive. (Its /etc/hosts sudo step fails silently in a
// non-interactive shell; that's expected and harmless.)
- (void)reloadCaddy {
    [self runActionWithArguments:@[@"reload"] actionName:@"reload" busyText:@"Reloading Caddy…"];
}

- (void)runActionWithArguments:(NSArray<NSString *> *)arguments
                    actionName:(NSString *)actionName
                      busyText:(NSString *)busyText {
    if (self.busy) {
        return;
    }

    self.busy = YES;
    self.busyText = busyText;
    self.lastError = nil;
    self.lastActionError = nil;
    self.lastUserActionTime = CFAbsoluteTimeGetCurrent();
    [self updateMenu];

    // enable/disable/reload can legitimately take a while on a big install
    // (cert issuance, service restarts), so give them generous headroom.
    __weak typeof(self) weakSelf = self;
    [self runCoveWithArguments:arguments
                       timeout:120.0
                    completion:^(int status, NSString *output, NSError *error) {
        (void)output;
        AppDelegate *strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        strongSelf.busy = NO;
        strongSelf.busyText = nil;
        strongSelf.lastUserActionTime = CFAbsoluteTimeGetCurrent();
        if (status != 0) {
            NSString *detail = error.localizedDescription ?: @"The Cove command failed.";
            [strongSelf reportActionFailure:[NSString stringWithFormat:@"Could not %@ Cove", actionName]
                                     detail:detail];
            return;
        }

        [strongSelf refreshStatus];
    }];
}

- (void)runCoveWithArguments:(NSArray<NSString *> *)arguments
                     timeout:(NSTimeInterval)timeout
                  completion:(CoveCommandCompletion)completion {
    // Fire the completion at most once, on the main queue. The reader thread
    // and the watchdog both call this; whichever wins, the loser is a no-op.
    // This is what guarantees the app recovers: even if the blocking read
    // below never returns (a subprocess inherited the pipe and outlived cove),
    // the watchdog still fires completion and clears `busy`.
    NSLock *lock = [[NSLock alloc] init];
    __block BOOL finished = NO;
    CoveCommandCompletion finishOnce = ^(int status, NSString *output, NSError *error) {
        [lock lock];
        if (finished) { [lock unlock]; return; }
        finished = YES;
        [lock unlock];
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(status, output, error);
        });
    };

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *executable = [self coveExecutablePath];
        NSArray<NSString *> *actualArguments = arguments;
        if ([executable isEqualToString:@"/usr/bin/env"]) {
            actualArguments = [@[@"cove"] arrayByAddingObjectsFromArray:arguments];
        }

        NSTask *task = [[NSTask alloc] init];
        NSPipe *outputPipe = [NSPipe pipe];
        task.executableURL = [NSURL fileURLWithPath:executable];
        task.arguments = actualArguments;
        task.standardOutput = outputPipe;
        task.standardError = outputPipe;

        NSMutableDictionary<NSString *, NSString *> *environment =
            [[[NSProcessInfo processInfo] environment] mutableCopy];
        environment[@"PATH"] =
            @"/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";
        task.environment = environment;

        NSError *launchError = nil;
        BOOL launched = [task launchAndReturnError:&launchError];
        if (!launched) {
            finishOnce(-1, @"", launchError);
            return;
        }

        // Watchdog: a command that outlives its timeout is wedged. Terminate it
        // (which lets the read below unblock in the common case) and report a
        // timeout now regardless — so a stuck subprocess can't leave the app
        // disabled forever. In the worst case one reader thread lingers on the
        // dead pipe; the app itself stays responsive.
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC)),
                       dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            if (task.isRunning) {
                [task terminate];
            }
            NSError *timeoutError =
                [NSError errorWithDomain:@"CoveMenuBar"
                                    code:-2
                                userInfo:@{NSLocalizedDescriptionKey:
                                    [NSString stringWithFormat:@"Timed out after %.0f seconds.", timeout]}];
            finishOnce(-2, @"", timeoutError);
        });

        NSData *data = [[outputPipe fileHandleForReading] readDataToEndOfFile];
        [task waitUntilExit];
        NSString *output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
        int terminationStatus = task.terminationStatus;
        NSError *commandError = nil;

        if (terminationStatus != 0) {
            NSString *message = [output stringByTrimmingCharactersInSet:
                [NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (message.length == 0) {
                message = @"The Cove command exited with an error.";
            }
            commandError = [NSError errorWithDomain:@"CoveMenuBar"
                                                code:terminationStatus
                                            userInfo:@{NSLocalizedDescriptionKey: message}];
        }

        finishOnce(terminationStatus, output, commandError);
    });
}

- (NSString *)coveExecutablePath {
    NSFileManager *fileManager = [NSFileManager defaultManager];
    for (NSString *path in @[@"/opt/homebrew/bin/cove", @"/usr/local/bin/cove"]) {
        if ([fileManager isExecutableFileAtPath:path]) {
            return path;
        }
    }
    return @"/usr/bin/env";
}

#pragma mark - Menu skeleton (built once)

- (void)buildMenuSkeleton {
    self.menu = [[NSMenu alloc] init];
    self.menu.autoenablesItems = NO;
    self.menu.delegate = self;

    self.summaryItem = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
    self.summaryItem.enabled = NO;
    [self.menu addItem:self.summaryItem];
    [self.menu addItem:[NSMenuItem separatorItem]];

    // Service rows are inserted at kServiceRowStartIndex by syncServiceRows.

    self.errorItem = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
    self.errorItem.enabled = NO;
    self.errorItem.hidden = YES;
    [self.menu addItem:self.errorItem];

    [self.menu addItem:[NSMenuItem separatorItem]];

    self.actionItem = [[NSMenuItem alloc] initWithTitle:@"Start Cove"
                                                 action:@selector(startCove)
                                          keyEquivalent:@""];
    self.actionItem.target = self;
    [self.menu addItem:self.actionItem];

    self.refreshItem = [[NSMenuItem alloc] initWithTitle:@"Refresh Status"
                                                  action:@selector(refreshStatus)
                                           keyEquivalent:@"r"];
    self.refreshItem.target = self;
    [self.menu addItem:self.refreshItem];

    self.reloadItem = [[NSMenuItem alloc] initWithTitle:@"Reload Caddy"
                                                 action:@selector(reloadCaddy)
                                          keyEquivalent:@""];
    self.reloadItem.target = self;
    [self.menu addItem:self.reloadItem];

    [self.menu addItem:[NSMenuItem separatorItem]];

    self.sitesItem = [[NSMenuItem alloc] initWithTitle:@"Sites" action:nil keyEquivalent:@""];
    self.sitesItem.submenu = [[NSMenu alloc] init];
    self.sitesItem.submenu.autoenablesItems = NO;
    [self.menu addItem:self.sitesItem];
    [self rebuildSitesSubmenu];

    [self.menu addItem:[NSMenuItem separatorItem]];

    self.dashboardItem = [self linkItemWithTitle:@"Open Cove Dashboard"
                                          action:@selector(openDashboard)];
    [self.menu addItem:self.dashboardItem];
    self.adminerItem = [self linkItemWithTitle:@"Open Adminer"
                                        action:@selector(openAdminer)];
    [self.menu addItem:self.adminerItem];
    self.mailpitItem = [self linkItemWithTitle:@"Open Mailpit"
                                        action:@selector(openMailpit)];
    [self.menu addItem:self.mailpitItem];
    [self.menu addItem:[self linkItemWithTitle:@"Open Cove Logs"
                                        action:@selector(openLogs)]];
    [self.menu addItem:[self linkItemWithTitle:@"Open Sites Folder"
                                        action:@selector(openSitesFolder)]];

    [self.menu addItem:[NSMenuItem separatorItem]];

    self.launchItem = [[NSMenuItem alloc] initWithTitle:@"Launch at Login"
                                                 action:@selector(toggleLaunchAtLogin)
                                          keyEquivalent:@""];
    self.launchItem.target = self;
    [self.menu addItem:self.launchItem];

    self.versionItem = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
    self.versionItem.target = self;
    self.versionItem.enabled = NO;
    self.versionItem.hidden = YES;
    [self.menu addItem:self.versionItem];

    NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:@"Quit Cove Menu Bar"
                                                     action:@selector(quitApp)
                                              keyEquivalent:@"q"];
    quitItem.target = self;
    [self.menu addItem:quitItem];

    self.statusItem.menu = self.menu;
}

#pragma mark - Menu updates (in place)

- (void)updateMenu {
    [self syncBusyPulse];
    [self updateStatusButton];
    [self syncServiceRows];

    self.summaryItem.title = [self summaryText];

    // Action failures outlast status errors: a failed create/start/stop stays
    // visible until the next action, instead of being wiped by the next
    // successful 20s status poll.
    NSString *errorText = self.lastActionError.length > 0 ? self.lastActionError : self.lastError;
    if (errorText.length > 0) {
        NSString *firstLine = [[errorText componentsSeparatedByCharactersInSet:
                                [NSCharacterSet newlineCharacterSet]] firstObject];
        self.errorItem.title = [NSString stringWithFormat:@"Error: %@", firstLine];
        self.errorItem.hidden = NO;
    } else {
        self.errorItem.hidden = YES;
    }

    BOOL allRunning = [self allServicesRunning];
    self.actionItem.title = allRunning ? @"Stop Cove" : @"Start Cove";
    self.actionItem.action = allRunning ? @selector(stopCove) : @selector(startCove);
    self.actionItem.enabled = !self.busy;
    self.refreshItem.enabled = !self.busy;
    self.reloadItem.enabled = !self.busy && [self serviceRunning:@"caddy"];

    self.dashboardItem.enabled = [self serviceRunning:@"caddy"];
    self.adminerItem.enabled = [self serviceRunning:@"caddy"];
    self.mailpitItem.enabled = [self serviceRunning:@"mailpit"];

    self.launchItem.state = SMAppService.mainAppService.status == SMAppServiceStatusEnabled
        ? NSControlStateValueOn
        : NSControlStateValueOff;

    if ([self updateAvailable]) {
        self.versionItem.title = [NSString stringWithFormat:@"Update Cove to v%@…", self.latestVersion];
        self.versionItem.action = @selector(runUpgradeInTerminal);
        self.versionItem.enabled = YES;
        self.versionItem.hidden = NO;
    } else if (self.coveVersion.length > 0) {
        self.versionItem.title = [NSString stringWithFormat:@"Cove v%@", self.coveVersion];
        self.versionItem.action = nil;
        self.versionItem.enabled = NO;
        self.versionItem.hidden = NO;
    } else {
        self.versionItem.hidden = YES;
    }
}

// Keep one menu item per service key, inserting/removing rows only when the
// key set actually changes (e.g. a PHP-FPM pool appears after the first poll
// or a `cove php` pin). Everything else is a title/image mutation, so an open
// menu never re-layouts.
- (void)syncServiceRows {
    if (![self.serviceItemKeys isEqualToArray:self.serviceKeys]) {
        for (NSMenuItem *item in self.serviceItems) {
            [self.menu removeItem:item];
        }
        [self.serviceItems removeAllObjects];

        NSInteger index = kServiceRowStartIndex;
        for (NSString *key in self.serviceKeys) {
            (void)key;
            NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
            item.enabled = NO;
            [self.menu insertItem:item atIndex:index++];
            [self.serviceItems addObject:item];
        }
        self.serviceItemKeys = [self.serviceKeys copy];
    }

    [self.serviceKeys enumerateObjectsUsingBlock:^(NSString *key, NSUInteger idx, BOOL *stop) {
        (void)stop;
        NSMenuItem *item = self.serviceItems[idx];
        NSNumber *state = self.serviceStates[key];
        NSString *stateText = state ? (state.boolValue ? @"Running" : @"Stopped") : @"…";
        NSString *symbol = state
            ? (state.boolValue ? @"checkmark.circle.fill" : @"circle")
            : @"circle.dotted";
        item.title = [NSString stringWithFormat:@"%@: %@",
                      [self displayNameForServiceKey:key], stateText];
        item.image = [NSImage imageWithSystemSymbolName:symbol accessibilityDescription:nil];
    }];
}

#pragma mark - Sites submenu

- (NSString *)sitesDirectory {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Cove/Sites"];
}

// Cove's convention: every site is a directory named <name>.localhost inside
// ~/Cove/Sites. The directory also collects loose files (logs, scripts), so
// filter strictly. A cheap readdir on the main thread — sites lists are small.
// Called from menuWillOpen, before the menu is on screen.
//
// Long lists get a "Recent" section: top 5 by the same signal the dashboard's
// modified column uses — mtime of <site>/public, falling back to the site dir.
- (void)rebuildSitesSubmenu {
    NSMenu *submenu = self.sitesItem.submenu;
    [submenu removeAllItems];

    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSString *sitesDir = [self sitesDirectory];
    NSArray<NSString *> *entries =
        [[fileManager contentsOfDirectoryAtPath:sitesDir error:nil]
            sortedArrayUsingSelector:@selector(localizedCaseInsensitiveCompare:)];

    NSMutableArray<NSDictionary *> *sites = [NSMutableArray array];
    for (NSString *entry in entries) {
        if (![entry hasSuffix:@".localhost"]) {
            continue;
        }
        BOOL isDirectory = NO;
        NSString *sitePath = [sitesDir stringByAppendingPathComponent:entry];
        if (![fileManager fileExistsAtPath:sitePath isDirectory:&isDirectory] || !isDirectory) {
            continue;
        }

        NSString *publicPath = [sitePath stringByAppendingPathComponent:@"public"];
        NSDate *modified = [fileManager attributesOfItemAtPath:publicPath error:nil].fileModificationDate
            ?: [fileManager attributesOfItemAtPath:sitePath error:nil].fileModificationDate
            ?: [NSDate distantPast];
        BOOL isWordPress = [fileManager fileExistsAtPath:
                            [publicPath stringByAppendingPathComponent:@"wp-config.php"]];
        [sites addObject:@{ @"name": entry, @"modified": modified, @"wp": @(isWordPress) }];
    }

    if (sites.count >= 8) {
        NSArray<NSDictionary *> *recent =
            [[sites sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
                return [b[@"modified"] compare:a[@"modified"]];
            }] subarrayWithRange:NSMakeRange(0, 5)];

        NSMenuItem *recentHeader = [[NSMenuItem alloc] initWithTitle:@"Recent"
                                                              action:nil
                                                       keyEquivalent:@""];
        recentHeader.enabled = NO;
        [submenu addItem:recentHeader];
        for (NSDictionary *site in recent) {
            [self addItemsForSite:site[@"name"] isWordPress:[site[@"wp"] boolValue] toMenu:submenu];
        }
        [submenu addItem:[NSMenuItem separatorItem]];
    }

    for (NSDictionary *site in sites) {
        [self addItemsForSite:site[@"name"] isWordPress:[site[@"wp"] boolValue] toMenu:submenu];
    }

    if (sites.count > 0) {
        [submenu addItem:[NSMenuItem separatorItem]];
        self.sitesItem.title = [NSString stringWithFormat:@"Sites (%lu)", (unsigned long)sites.count];
    } else {
        self.sitesItem.title = @"Sites";
    }

    NSMenuItem *newSiteItem = [[NSMenuItem alloc] initWithTitle:@"New Site…"
                                                         action:@selector(promptForNewSite)
                                                  keyEquivalent:@""];
    newSiteItem.target = self;
    newSiteItem.enabled = !self.busy;
    [submenu addItem:newSiteItem];
}

- (void)addItemsForSite:(NSString *)entry isWordPress:(BOOL)isWordPress toMenu:(NSMenu *)submenu {
    NSMenuItem *siteItem = [[NSMenuItem alloc] initWithTitle:entry
                                                      action:@selector(openSite:)
                                               keyEquivalent:@""];
    siteItem.target = self;
    siteItem.representedObject = entry;
    [submenu addItem:siteItem];

    // WordPress sites get an option-key alternate that generates a
    // one-time admin login via `cove login`.
    if (isWordPress) {
        NSMenuItem *loginItem =
            [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"Log in to %@", entry]
                                      action:@selector(loginToSite:)
                               keyEquivalent:@""];
        loginItem.target = self;
        loginItem.representedObject = entry;
        loginItem.keyEquivalentModifierMask = NSEventModifierFlagOption;
        loginItem.alternate = YES;
        [submenu addItem:loginItem];
    }
}

#pragma mark - New site

- (void)promptForNewSite {
    [NSApp activateIgnoringOtherApps:YES];
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = @"New Cove Site";
    alert.informativeText = @"Creates a WordPress site at <name>.localhost.\n"
                             "Lowercase letters, numbers, and hyphens only.";
    [alert addButtonWithTitle:@"Create"];
    [alert addButtonWithTitle:@"Cancel"];

    NSTextField *field = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 230, 24)];
    field.placeholderString = @"my-new-site";
    alert.accessoryView = field;
    alert.window.initialFirstResponder = field;

    if ([alert runModal] != NSAlertFirstButtonReturn) {
        return;
    }

    NSString *name = [[field.stringValue lowercaseString] stringByTrimmingCharactersInSet:
                      [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (name.length == 0) {
        return;
    }

    // Mirror cove add's own validation so obvious typos fail fast with a
    // clear message instead of a shell error.
    NSRegularExpression *valid =
        [NSRegularExpression regularExpressionWithPattern:@"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"
                                                  options:0
                                                    error:nil];
    if (![valid firstMatchInString:name options:0 range:NSMakeRange(0, name.length)]) {
        [self showErrorWithTitle:@"Invalid site name"
                         message:@"Site names can only contain lowercase letters, numbers, and "
                                  "hyphens, and cannot begin or end with a hyphen."];
        return;
    }

    if (self.busy) {
        return;
    }
    self.busy = YES;
    self.busyText = [NSString stringWithFormat:@"Creating %@.localhost… (takes about a minute)", name];
    self.lastActionError = nil;
    self.lastUserActionTime = CFAbsoluteTimeGetCurrent();
    [self updateMenu];

    // A full WordPress install (core download + DB + install + reload) runs a
    // minute or more; allow four before treating it as wedged.
    __weak typeof(self) weakSelf = self;
    [self runCoveWithArguments:@[@"add", name]
                       timeout:240.0
                    completion:^(int status, NSString *output, NSError *error) {
        AppDelegate *strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        strongSelf.busy = NO;
        strongSelf.busyText = nil;
        strongSelf.lastUserActionTime = CFAbsoluteTimeGetCurrent();
        if (status != 0) {
            [strongSelf reportActionFailure:[NSString stringWithFormat:@"Could not create %@.localhost", name]
                                     detail:(error.localizedDescription.length > 0
                                             ? error.localizedDescription
                                             : (output.length > 0 ? output : @"cove add exited with an error."))];
            return;
        }

        [strongSelf postNotificationWithBody:
            [NSString stringWithFormat:@"%@.localhost is ready — opening it now.", name]];
        [strongSelf refreshStatus];
        [strongSelf openCoveHost:[name stringByAppendingString:@".localhost"]];
    }];
}

- (void)openSite:(NSMenuItem *)sender {
    NSString *host = sender.representedObject;
    if (host.length > 0) {
        [self openCoveHost:host];
    }
}

- (void)loginToSite:(NSMenuItem *)sender {
    NSString *host = sender.representedObject;
    if (host.length == 0) {
        return;
    }
    // Guard against a second click while wp-cli is still minting the URL:
    // each `cove login` run regenerates the one-time token, so a parallel run
    // would invalidate the first URL right before its tab opens.
    if (self.busy) {
        return;
    }
    self.busy = YES;
    self.busyText = [NSString stringWithFormat:@"Logging in to %@…", host];
    self.lastActionError = nil;
    self.lastUserActionTime = CFAbsoluteTimeGetCurrent();
    [self updateMenu];

    // `cove login` takes the site name without the .localhost suffix and
    // prints a one-time login URL inside a decorative gum box.
    NSString *siteName = [host stringByReplacingOccurrencesOfString:@".localhost"
                                                         withString:@""
                                                            options:NSAnchoredSearch | NSBackwardsSearch
                                                              range:NSMakeRange(0, host.length)];

    __weak typeof(self) weakSelf = self;
    [self runCoveWithArguments:@[@"login", siteName]
                       timeout:45.0
                    completion:^(int status, NSString *output, NSError *error) {
        AppDelegate *strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        strongSelf.busy = NO;
        strongSelf.busyText = nil;
        strongSelf.lastUserActionTime = CFAbsoluteTimeGetCurrent();

        NSString *loginURL = nil;
        if (status == 0) {
            // stdout and stderr are merged, so wp-cli/PHP notices (which often
            // print their own https:// URLs) can appear before the real login
            // line. Don't take the first URL — take the one that actually
            // points at THIS site's login endpoint. Charset widened so a token
            // containing ~ # + ! @ isn't truncated mid-URL.
            NSRegularExpression *regex =
                [NSRegularExpression regularExpressionWithPattern:@"https://[A-Za-z0-9.:/_?=&%~#+!@-]+"
                                                          options:0
                                                            error:nil];
            for (NSTextCheckingResult *match in
                 [regex matchesInString:output options:0 range:NSMakeRange(0, output.length)]) {
                NSString *candidate = [output substringWithRange:match.range];
                if ([candidate containsString:host] && [candidate containsString:@"wp-login"]) {
                    loginURL = candidate;   // keep scanning; last match wins
                }
            }
        }

        if (loginURL) {
            [strongSelf updateMenu];
            [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:loginURL]];
        } else {
            [strongSelf reportActionFailure:[NSString stringWithFormat:@"Could not log in to %@", host]
                                     detail:error.localizedDescription
                                            ?: @"cove login did not return a login URL."];
        }
    }];
}

- (void)openSitesFolder {
    NSURL *sitesURL = [NSURL fileURLWithPath:[self sitesDirectory] isDirectory:YES];
    [[NSWorkspace sharedWorkspace] openURL:sitesURL];
}

#pragma mark - Update check

// Resolve the latest released version by following the GitHub redirect for
// releases/latest → .../releases/tag/v<version>. No API token, no rate-limit
// concerns at once a day, and no JSON parsing needed.
- (void)checkForUpdates {
    NSURL *url = [NSURL URLWithString:@"https://github.com/anchorhost/cove/releases/latest"];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"HEAD";
    request.timeoutInterval = 15.0;

    __weak typeof(self) weakSelf = self;
    NSURLSessionDataTask *task = [[NSURLSession sharedSession]
        dataTaskWithRequest:request
          completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
              (void)data;
              if (error || !response.URL) {
                  return;
              }
              NSString *tag = response.URL.lastPathComponent;
              if (![tag hasPrefix:@"v"] || tag.length < 2) {
                  return;
              }
              NSString *version = [tag substringFromIndex:1];
              dispatch_async(dispatch_get_main_queue(), ^{
                  AppDelegate *strongSelf = weakSelf;
                  if (!strongSelf) {
                      return;
                  }
                  strongSelf.latestVersion = version;
                  [strongSelf updateMenu];
              });
          }];
    [task resume];
}

- (BOOL)updateAvailable {
    if (self.coveVersion.length == 0 || self.latestVersion.length == 0) {
        return NO;
    }
    return [self compareVersion:self.latestVersion to:self.coveVersion] == NSOrderedDescending;
}

// Numeric segment-by-segment comparison, so 1.10 > 1.9.
- (NSComparisonResult)compareVersion:(NSString *)a to:(NSString *)b {
    NSArray<NSString *> *aParts = [a componentsSeparatedByString:@"."];
    NSArray<NSString *> *bParts = [b componentsSeparatedByString:@"."];
    NSUInteger count = MAX(aParts.count, bParts.count);
    for (NSUInteger i = 0; i < count; i++) {
        NSInteger aValue = i < aParts.count ? aParts[i].integerValue : 0;
        NSInteger bValue = i < bParts.count ? bParts[i].integerValue : 0;
        if (aValue != bValue) {
            return aValue > bValue ? NSOrderedDescending : NSOrderedAscending;
        }
    }
    return NSOrderedSame;
}

// `cove upgrade` can install Homebrew packages and ask questions — that
// belongs in a real terminal, not a headless NSTask. A .command file opens in
// Terminal via Launch Services with no automation (TCC) prompt.
- (void)runUpgradeInTerminal {
    // The upgrade restarts services from the Terminal window over the next
    // couple of minutes; mark it as user-initiated so the poll landing in the
    // middle of it doesn't read the churn as a crash.
    self.lastUserActionTime = CFAbsoluteTimeGetCurrent();
    NSString *script = @"#!/bin/zsh\n"
                        "export PATH=\"/opt/homebrew/bin:/usr/local/bin:$PATH\"\n"
                        "cove upgrade\n";
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"cove-upgrade.command"];
    NSError *error = nil;
    if (![script writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&error]) {
        [self showErrorWithTitle:@"Update Cove" message:error.localizedDescription];
        return;
    }
    [[NSFileManager defaultManager] setAttributes:@{NSFilePosixPermissions: @0755}
                                     ofItemAtPath:path
                                            error:nil];
    [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:path]];
}

#pragma mark - Status button

- (void)syncBusyPulse {
    if (self.busy && !self.busyPulseTimer) {
        self.busyPulseTimer = [NSTimer scheduledTimerWithTimeInterval:0.6
                                                              target:self
                                                            selector:@selector(pulseTick)
                                                            userInfo:nil
                                                             repeats:YES];
    } else if (!self.busy && self.busyPulseTimer) {
        [self.busyPulseTimer invalidate];
        self.busyPulseTimer = nil;
        self.pulsePhase = NO;
    }
}

- (void)pulseTick {
    self.pulsePhase = !self.pulsePhase;
    [self updateStatusButton];
}

- (void)updateStatusButton {
    NSStatusBarButton *button = self.statusItem.button;
    if (!button) {
        return;
    }

    NSImage *image;
    if (self.busy) {
        // Alternate full-color / grayscale while an action runs — a visible
        // heartbeat that distinguishes "working" from "hung".
        image = self.pulsePhase ? self.partialImage : self.runningImage;
    } else if ([self allServicesRunning] && self.lastError.length == 0) {
        image = self.runningImage;
    } else if ([self runningServiceCount] > 0) {
        image = self.partialImage;
    } else {
        image = self.stoppedImage;
    }

    if (image) {
        button.title = @"";
        button.image = image;
        button.imagePosition = NSImageOnly;
    } else {
        // Icon decode failed (loadStatusImages guards against a macOS whose
        // ImageIO can't rasterize the SVG) — fall back to a text item rather
        // than an invisible one.
        button.title = @"Cove";
        button.image = nil;
        button.imagePosition = NSNoImage;
    }
    button.toolTip = [self summaryText];
    button.accessibilityLabel = [self summaryText];
}

- (void)loadStatusImages {
    // The vector logo — the same mark the dashboard renders. NSImage decoding
    // SVG is undocumented Apple behavior (CoreSVG, observed working since
    // macOS 11); if it ever fails, the images stay nil and updateStatusButton
    // falls back to a "Cove" text item instead of an invisible one.
    NSURL *assetURL = [[NSBundle mainBundle] URLForResource:@"cove-logo"
                                             withExtension:@"svg"
                                              subdirectory:@"Assets"];
    NSImage *source = assetURL ? [[NSImage alloc] initWithContentsOfURL:assetURL] : nil;
    if (!source || ![self imageDrawsVisibly:source]) {
        return;
    }

    source.size = NSMakeSize(18, 18);
    self.runningImage = source;
    self.partialImage = [self imageByDesaturating:source brightness:0.02 contrast:1.05];
    self.stoppedImage = [self imageByDesaturating:source brightness:-0.12 contrast:1.20];
}

// CoreSVG can "succeed" on an SVG yet hand back a non-nil image with no
// usable content (observed with viewBox-only SVGs on some macOS builds) —
// which would put an invisible status item in the menu bar. Rasterize a
// probe and require at least one visible pixel before trusting the icon.
- (BOOL)imageDrawsVisibly:(NSImage *)image {
    const NSInteger side = 18;
    NSBitmapImageRep *rep = [[NSBitmapImageRep alloc]
        initWithBitmapDataPlanes:NULL
                      pixelsWide:side
                      pixelsHigh:side
                   bitsPerSample:8
                 samplesPerPixel:4
                        hasAlpha:YES
                        isPlanar:NO
                  colorSpaceName:NSCalibratedRGBColorSpace
                     bytesPerRow:0
                    bitsPerPixel:0];
    if (!rep || !rep.bitmapData) {
        return NO;
    }
    memset(rep.bitmapData, 0, (size_t)(rep.bytesPerRow * side));

    NSGraphicsContext *context =
        [NSGraphicsContext graphicsContextWithBitmapImageRep:rep];
    if (!context) {
        return NO;
    }
    [NSGraphicsContext saveGraphicsState];
    [NSGraphicsContext setCurrentContext:context];
    [image drawInRect:NSMakeRect(0, 0, side, side)
             fromRect:NSZeroRect
            operation:NSCompositingOperationSourceOver
             fraction:1.0];
    [NSGraphicsContext restoreGraphicsState];

    const unsigned char *data = rep.bitmapData;
    NSInteger byteCount = rep.bytesPerRow * side;
    for (NSInteger i = 0; i < byteCount; i++) {
        if (data[i] != 0) {
            return YES;
        }
    }
    return NO;
}

- (NSImage *)imageByDesaturating:(NSImage *)source
                      brightness:(CGFloat)brightness
                        contrast:(CGFloat)contrast {
    NSData *sourceData = [source TIFFRepresentation];
    CIImage *inputImage = sourceData ? [CIImage imageWithData:sourceData] : nil;
    if (!inputImage) {
        return source;
    }

    CIFilter *filter = [CIFilter filterWithName:@"CIColorControls"];
    [filter setValue:inputImage forKey:kCIInputImageKey];
    [filter setValue:@0.0 forKey:kCIInputSaturationKey];
    [filter setValue:@(brightness) forKey:kCIInputBrightnessKey];
    [filter setValue:@(contrast) forKey:kCIInputContrastKey];

    CIImage *outputImage = filter.outputImage;
    if (!outputImage) {
        return source;
    }

    CIContext *context = [CIContext contextWithOptions:nil];
    CGImageRef cgImage = [context createCGImage:outputImage fromRect:outputImage.extent];
    if (!cgImage) {
        return source;
    }

    NSImage *result = [[NSImage alloc] initWithCGImage:cgImage size:NSMakeSize(18, 18)];
    CGImageRelease(cgImage);
    return result;
}

- (NSString *)summaryText {
    if (self.busy) {
        return self.busyText.length > 0 ? self.busyText : @"Cove is updating…";
    }
    if (self.lastError.length > 0) {
        return @"Cove status unavailable";
    }
    if (!self.statesKnown) {
        return @"Checking Cove status...";
    }
    if ([self allServicesRunning]) {
        return @"Cove is running";
    }
    if ([self runningServiceCount] > 0) {
        return @"Cove is partially running";
    }
    return @"Cove is stopped";
}

- (NSMenuItem *)linkItemWithTitle:(NSString *)title action:(SEL)action {
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title action:action keyEquivalent:@""];
    item.target = self;
    return item;
}

#pragma mark - Quick links

- (void)openDashboard {
    [self openCoveHost:@"cove.localhost"];
}

- (void)openAdminer {
    [self openCoveHost:@"db.cove.localhost"];
}

- (void)openMailpit {
    [self openCoveHost:@"mail.cove.localhost"];
}

- (void)openCoveHost:(NSString *)host {
    NSString *urlString = [NSString stringWithFormat:@"https://%@%@", host, [self httpsPortSuffix]];
    NSURL *url = [NSURL URLWithString:urlString];
    if (url) {
        [[NSWorkspace sharedWorkspace] openURL:url];
    }
}

- (NSString *)httpsPortSuffix {
    NSString *configPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Cove/config"];
    NSString *config = [NSString stringWithContentsOfFile:configPath
                                                  encoding:NSUTF8StringEncoding
                                                     error:nil];
    if (!config) {
        return @"";
    }

    NSString *port = nil;
    for (NSString *line in [config componentsSeparatedByCharactersInSet:
                            [NSCharacterSet newlineCharacterSet]]) {
        if ([line hasPrefix:@"HTTPS_PORT="]) {
            port = [[line substringFromIndex:[@"HTTPS_PORT=" length]]
                stringByTrimmingCharactersInSet:
                    [NSCharacterSet characterSetWithCharactersInString:@"'\" "]];
        }
    }

    if (port.length == 0 || [port isEqualToString:@"443"]) {
        return @"";
    }
    return [@":" stringByAppendingString:port];
}

- (void)openLogs {
    NSURL *logsURL = [NSURL fileURLWithPath:
        [NSHomeDirectory() stringByAppendingPathComponent:@"Cove/Logs"]
                               isDirectory:YES];
    [[NSWorkspace sharedWorkspace] openURL:logsURL];
}

#pragma mark - Housekeeping

- (void)toggleLaunchAtLogin {
    SMAppService *service = SMAppService.mainAppService;
    NSError *error = nil;
    BOOL succeeded;
    if (service.status == SMAppServiceStatusEnabled) {
        succeeded = [service unregisterAndReturnError:&error];
    } else {
        succeeded = [service registerAndReturnError:&error];
    }

    if (!succeeded) {
        [self showErrorWithTitle:@"Launch at Login"
                         message:error.localizedDescription ?: @"Unable to change the login item."];
    }
    [self updateMenu];
}

- (void)showErrorWithTitle:(NSString *)title message:(NSString *)message {
    NSAlert *alert = [[NSAlert alloc] init];
    alert.alertStyle = NSAlertStyleWarning;
    alert.messageText = title;
    alert.informativeText = message;
    // Accessory apps have no key window; without activation the alert can
    // appear behind whatever the user is working in.
    [NSApp activateIgnoringOtherApps:YES];
    [alert runModal];
}

- (void)quitApp {
    [NSApp terminate:nil];
}

@end

int main(int argc, const char *argv[]) {
    // `CoveMenuBar unregister` — invoked by `cove menubar disable` before the
    // bundle is deleted, because SMAppService login items can only be
    // unregistered from inside the app they belong to. Without this, disable
    // would leave a stale entry in System Settings → Login Items.
    if (argc > 1 && strcmp(argv[1], "unregister") == 0) {
        @autoreleasepool {
            [SMAppService.mainAppService unregisterAndReturnError:nil];
        }
        return 0;
    }

    @autoreleasepool {
        NSApplication *application = [NSApplication sharedApplication];
        // NSApplication does not retain its delegate, and ARC may release a
        // local as soon as its last use passes — before the run loop delivers
        // applicationDidFinishLaunching:. A static keeps the delegate alive
        // for the life of the process; without it the app can launch as a
        // healthy event loop that never creates its status item.
        static AppDelegate *delegate;
        delegate = [[AppDelegate alloc] init];
        application.delegate = delegate;
        [application run];
    }
    return 0;
}
COVE_MENUBAR_MAIN_M_EOF
}

emit_menubar_info_plist() {
cat <<'COVE_MENUBAR_PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleDisplayName</key>
    <string>Cove Menu Bar</string>
    <key>CFBundleExecutable</key>
    <string>CoveMenuBar</string>
    <key>CFBundleIdentifier</key>
    <string>run.cove.menubar</string>
    <key>CFBundleIconFile</key>
    <string>CoveMenuBar.icns</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Cove Menu Bar</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>__MENUBAR_VERSION__</string>
    <key>CFBundleVersion</key>
    <string>__MENUBAR_VERSION__</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright 2026 Robby McCullough &amp; Anchor Hosting</string>
</dict>
</plist>
COVE_MENUBAR_PLIST_EOF
}

emit_menubar_icon_svg() {
cat <<'COVE_MENUBAR_ICON_EOF'
<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64" stroke-linecap="round" stroke-linejoin="round">
    <defs>
        <clipPath id="cove-clip"><circle cx="32" cy="32" r="28"/></clipPath>
    </defs>
    <g clip-path="url(#cove-clip)">
        <rect x="0" y="0" width="64" height="64" fill="#f6f1e8"/>
        <rect x="0" y="32" width="64" height="32" fill="#3a97a9"/>
        <path fill="#58b293" d="M 4 32 C 4 22, 12 12, 22 12 C 30 12, 34 18, 42 16 C 50 14, 58 18, 60 24 L 60 32 Z"/>
        <line x1="2" y1="32" x2="62" y2="32" stroke="#1c4c58" fill="none" stroke-width="2.5"/>
        <g stroke="#1c4c58" fill="none" stroke-width="2.6">
            <path d="M 10 42 Q 18 38, 26 42 T 42 42 T 56 42"/>
            <path d="M 14 50 Q 22 46, 30 50 T 46 50 T 56 50"/>
        </g>
    </g>
    <circle cx="32" cy="32" r="28" stroke="#1c4c58" fill="none" stroke-width="3"/>
</svg>
COVE_MENUBAR_ICON_EOF
}

#  Pass all script arguments to the main function.
main "$@"
