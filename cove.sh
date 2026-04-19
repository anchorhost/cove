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
for _cove_bin in /opt/homebrew/bin /usr/local/bin /usr/local/sbin "$HOME/.local/bin"; do
    if [ -d "$_cove_bin" ] && [[ ":$PATH:" != *":$_cove_bin:"* ]]; then
        PATH="$_cove_bin:$PATH"
    fi
done
unset _cove_bin
export PATH

# --- OS & Package Manager Detection ---
OS=""
PKG_MANAGER=""
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

PROTECTED_NAMES="cove"
COVE_VERSION="1.9"
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
    wp_cmd=$(get_wp_cmd)

    local total_sites=0 updated_sites=0 failed_hosts=0
    local site_path site_name hostname mapping old_url new_url
    local -a hostnames

    for site_path in "$SITES_DIR"/*; do
        [ -d "$site_path" ] || continue
        [ -f "$site_path/public/wp-config.php" ] || continue
        total_sites=$((total_sites + 1))
        site_name=$(basename "$site_path")

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

$whoops = new \Whoops\Run;

// We want to see all errors *except* for the noisy Deprecated and Notice warnings,
// which are common with older plugins on modern PHP.
// E_USER_NOTICE is used by WordPress's _doing_it_wrong() function.
$whoops->silenceErrorsInPaths(
    '/.*/', // A regex that matches all file paths
    E_DEPRECATED | E_USER_DEPRECATED | E_NOTICE | E_USER_NOTICE
);

// The PrettyPageHandler will now only be triggered for fatal errors.
$whoops->pushHandler(new \Whoops\Handler\PrettyPageHandler);
$whoops->register();
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
 * Version: 0.3.0
 * Author: CaptainCore
 * Author URI: https://captaincore.io
 * Text Domain: captaincore-helper
 */

/**
 * Registers AJAX callback for quick logins
 */
function captaincore_quick_login_action_callback() {

	$post = json_decode( file_get_contents( 'php://input' ) );
	// Error if token not valid
	if ( ! isset( $post->token ) || $post->token != md5( AUTH_KEY ) ) {
		return new WP_Error( 'token_invalid', 'Invalid Token', [ 'status' => 404 ] );
		wp_die();
	}

	$post->user_login = str_replace( "%20", " ", $post->user_login );
	$user     = get_user_by( 'login', $post->user_login );
	$password = wp_generate_password();
	$token    = sha1( $password );

	update_user_meta( $user->ID, 'captaincore_login_token', $token );
	$query_args = [
			'user_id'                 => $user->ID,
			'captaincore_login_token' => $token,
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
	if ( 'wp-login.php' !== $pagenow || empty( $_GET['user_id'] ) || empty( $_GET['captaincore_login_token'] ) ) {
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

	$token    = get_user_meta( $user->ID, 'captaincore_login_token', true );
	$is_valid = false;
		if ( hash_equals( $token, $_GET['captaincore_login_token'] ) ) {
			$is_valid = true;
		}

	if ( ! $is_valid ) {
		wp_die( $error );
	}

	delete_user_meta( $user->ID, 'captaincore_login_token' );
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

        // Generate tokens
        $password = wp_generate_password();
        $token    = sha1($password);

        // Update user meta with the new token
        update_user_meta( $user->ID, 'captaincore_login_token', $token );
        // Construct the one-time login URL
        $query_args = [
            'user_id'                 => $user->ID,
            'captaincore_login_token' => $token,
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
heredoc

    local mu_plugins_dir="$public_dir/wp-content/mu-plugins"
    mkdir -p "$mu_plugins_dir"
    echo "$build_mu_plugin" > "$mu_plugins_dir/captaincore-helper.php"
    echo "   - ✅ Injected one-time login MU-plugin."
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
get_wp_cmd() {
    local wp_path
    wp_path=$(command -v wp)
    local frank
    frank=$(command -v frankenphp)
    if [ "$(id -u)" -eq 0 ]; then
        echo "$frank php-cli $wp_path --allow-root"
    else
        echo "$frank php-cli $wp_path"
    fi
}

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
                required_hosts+=("$(basename "$site_path")")

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
        local entries_to_add=""
        for host in "${missing_hosts[@]}"; do
            entries_to_add+="127.0.0.1 $host\n"
        done

        # Use sudo tee to append all missing entries at once
        echo -e "$entries_to_add" | sudo tee -a /etc/hosts > /dev/null
        echo "   - ✅ Done."
    else
        echo "   - ✅ All entries are present."
    fi
}

# Probe Caddy's admin API to see if the server is running.
# Uses bash's built-in /dev/tcp so we don't depend on nc/curl being installed.
is_caddy_running() {
    (echo > /dev/tcp/127.0.0.1/2019) &>/dev/null
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
        $SUDO_CMD "$CADDY_CMD" stop --config "$CADDYFILE_PATH" &> /dev/null
        $SUDO_CMD "$CADDY_CMD" start --config "$CADDYFILE_PATH" --pidfile "$COVE_DIR/caddy.pid" >> "$LOGS_DIR/caddy-process.log" 2>&1
    fi
}

# Function to regenerate the Caddyfile
regenerate_caddyfile() {
    echo "🔄 Regenerating Caddyfile..."
    if ! command -v mailpit &> /dev/null; then
        gum style --foreground red "❌ Mailpit is not installed. Please run 'cove install' successfully first."
        return 1
    fi
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

    # Write the static header of the Caddyfile
    cat > "$CADDYFILE_PATH" <<- EOM
{
${port_directives}    frankenphp {
        php_ini sendmail_path "$mailpit_path sendmail -t"
        php_ini log_errors On
        php_ini display_errors Off
        php_ini error_log "$LOGS_DIR/errors.log"
        php_ini auto_prepend_file "$APP_DIR/whoops_bootstrap.php"
        php_ini memory_limit 512M
        php_ini upload_max_filesize 512M
        php_ini post_max_size 512M
    }
    order php_server before file_server
    servers {
        protocols h1
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
                
                # Build the list of domains
                local site_domains="$site_name"
                
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

                echo "    php_server" >> "$CADDYFILE_PATH"

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

                        echo "    php_server" >> "$CADDYFILE_PATH"

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
                    
                    # Check if this site has a simple reverse_proxy directive
                    local directive_file="$CUSTOM_CADDY_DIR/$site_name"
                    local direct_proxy_target=""
                    if [ -f "$directive_file" ]; then
                        # Extract target if directive is just "reverse_proxy <target>"
                        direct_proxy_target=$(grep -E '^reverse_proxy [0-9a-zA-Z.:]+$' "$directive_file" 2>/dev/null | awk '{print $2}')
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
                        
                        echo "    php_server" >> "$CADDYFILE_PATH"
                        
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
        if $SUDO_CMD "$CADDY_CMD" reload --config "$CADDYFILE_PATH" --address localhost:2019 &> "$LOGS_DIR/caddy-reload.log"; then
            echo "✅ Caddy configuration reloaded."
        else
            gum style --foreground red "❌ Caddy reload failed. See $LOGS_DIR/caddy-reload.log for details."
            return 1
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

                    $sites_info[] = [
                        'name' => str_replace('.localhost', '', $item),
                        'domain' => 'https://' . $item . $__cove_port_suffix,
                        'type' => file_exists($site_path . "/public/wp-config.php") ? 'WordPress' : 'Plain',
                        'display_path' => '~/Cove/Sites/' . $item,
                        'full_path' => $site_path,
                        'size_bytes' => isset($size_cache[$item]) ? (int) $size_cache[$item] : null,
                        'modified_at' => $mtime ?: null,
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
}

// Handle POST requests for adding/deleting/reloading
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $action = $input['action'] ?? '';
    $response = ['success' => false, 'message' => 'Invalid request.'];
    $command = '';
    $site_name = $input['site_name'] ?? '';

    switch ($action) {
        case 'add_site':
            if (!empty($site_name) && preg_match('/^[a-zA-Z0-9-]+$/', $site_name)) {
                $type_flag = ($input['is_plain'] ?? false) ? '--plain' : '';
                $command = sprintf('HOME=%s %s add %s %s --no-reload 2>&1', escapeshellarg($user_home), escapeshellarg($cove_path), escapeshellarg($site_name), $type_flag);
            } else { $response['message'] = 'Invalid site name provided.'; }
            break;
        case 'delete_site':
            if (!empty($site_name)) {
                $command = sprintf('HOME=%s %s delete %s --force 2>&1', escapeshellarg($user_home), escapeshellarg($cove_path), escapeshellarg($site_name));
            } else { $response['message'] = 'Site name not provided for deletion.'; }
            break;
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
        } else {
            $response = ['success' => false, 'message' => 'An error occurred.', 'output' => implode("\n", $output)];
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cove — sites</title>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64' stroke-linecap='round' stroke-linejoin='round'><defs><clipPath id='c'><circle cx='32' cy='32' r='28'/></clipPath></defs><g clip-path='url(%23c)'><rect width='64' height='64' fill='%23f6f1e8'/><rect y='32' width='64' height='32' fill='%233a97a9'/><path d='M 4 32 C 4 22, 12 12, 22 12 C 30 12, 34 18, 42 16 C 50 14, 58 18, 60 24 L 60 32 Z' fill='%238bb382'/><line x1='2' y1='32' x2='62' y2='32' stroke='%231c4c58' stroke-width='2.5' fill='none'/><g stroke='%231c4c58' stroke-width='2.6' fill='none'><path d='M 10 42 Q 18 38, 26 42 T 42 42 T 56 42'/><path d='M 14 50 Q 22 46, 30 50 T 46 50 T 56 50'/></g></g><circle cx='32' cy='32' r='28' stroke='%231c4c58' stroke-width='3' fill='none'/></svg>">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fraunces:ital,opsz,wght@0,9..144,400..600;1,9..144,400..600&family=Geist:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <script src="//unpkg.com/alpinejs" defer></script>
    <style>
        *, *::before, *::after { box-sizing: border-box; }
        html, body { margin: 0; padding: 0; }
        html { background: #0f1210; }
        html[data-theme="light"] { background: #fbfaf7; }

        :root {
            --font-sans: 'Geist', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            --font-serif: 'Fraunces', Georgia, serif;
            --font-mono: 'JetBrains Mono', ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
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
            --accent: oklch(72% 0.12 190);
            --pill-bg: #1e2320;
            --pill-wp-bg: color-mix(in oklch, var(--accent) 18%, transparent);
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
            --pill-wp-bg: color-mix(in oklch, var(--accent) 14%, transparent);
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
        .logo-mark { width: 34px; height: 34px; display: block; flex-shrink: 0; }
        .logo-mark .disc    { fill: var(--mark-disc, oklch(96% 0.015 85)); }
        .logo-mark .water   { fill: var(--mark-water, oklch(62% 0.11 190)); }
        .logo-mark .land    { fill: var(--mark-land, oklch(72% 0.10 150)); }
        .logo-mark .horizon { stroke: var(--mark-horizon, oklch(35% 0.08 190)); fill: none; }
        .logo-mark .wave    { stroke: var(--mark-wave, oklch(35% 0.08 190)); fill: none; }
        .logo-mark .ring    { stroke: var(--mark-ring, oklch(35% 0.08 190)); fill: none; stroke-width: 3; }
        html[data-theme="dark"] .logo-mark {
            --mark-disc:    oklch(22% 0.01 85);
            --mark-land:    oklch(64% 0.09 150);
            --mark-ring:    color-mix(in oklab, var(--text) 72%, transparent);
            --mark-horizon: color-mix(in oklab, var(--text) 72%, transparent);
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
        .filter-chip-x:hover { background: color-mix(in oklch, var(--accent) 28%, transparent); }

        /* Add row */
        .add-row { padding: 0.9rem 1.5rem; border-bottom: 1px solid var(--panel-border); background: var(--bg-sunk); }
        .add-row form { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
        .add-row input[type="text"] { background: var(--input-bg); border: 1px solid var(--panel-border); color: var(--text); font-family: var(--font-mono); font-size: 0.9rem; padding: 0.5rem 0.8rem; border-radius: var(--radius-md); min-width: 200px; flex: 1; }
        .add-row input[type="text"]:focus { outline: 0; border-color: var(--accent); }
        .add-row .plain-toggle { display: inline-flex; align-items: center; gap: 0.4rem; color: var(--text-dim); font-size: 0.85rem; cursor: pointer; }
        .add-row .plain-toggle input { accent-color: var(--accent); }

        /* Site list — one grid on the <ul>, rows inherit its columns via
           subgrid so type/modified/size/actions align vertically across rows
           instead of each row sizing independently. */
        .site-list { list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: 1fr auto auto auto auto; column-gap: 0.9rem; }
        .site-row { display: grid; grid-column: 1 / -1; grid-template-columns: subgrid; align-items: center; padding: 0.8rem 1.5rem; border-bottom: 1px solid var(--panel-border); transition: background 100ms; cursor: pointer; }
        .site-row:last-child { border-bottom: 0; }
        .site-row:hover { background: var(--panel-hover); }
        .site-domain { font-family: var(--font-mono); font-size: 0.88rem; color: var(--text-dim); text-decoration: none; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .site-domain .host-accent { color: var(--accent); }
        .site-domain:hover { color: var(--accent); }
        .site-domain mark { background: color-mix(in oklch, var(--accent) 28%, transparent); color: inherit; padding: 0 1px; border-radius: 3px; }
        .site-type { display: inline-flex; justify-content: center; min-width: 64px; padding: 0.2rem 0.55rem; border-radius: var(--radius-pill); font-family: var(--font-mono); font-size: 0.68rem; font-weight: 500; letter-spacing: 0.08em; text-transform: uppercase; cursor: pointer; user-select: none; transition: filter 120ms; }
        .site-type:hover { filter: brightness(1.15); }
        .site-type.wp { background: var(--pill-wp-bg); color: var(--pill-wp-fg); }
        .site-type.static { background: var(--pill-static-bg); color: var(--pill-static-fg); }
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

        /* Footer */
        .card-foot { display: flex; align-items: center; justify-content: space-between; padding: 0.75rem 1.5rem; border-top: 1px solid var(--panel-border); color: var(--text-dim); font-family: var(--font-mono); font-size: 0.78rem; gap: 1rem; flex-wrap: wrap; }
        .services { display: flex; gap: 1.1rem; flex-wrap: wrap; }
        .dot { display: inline-flex; align-items: center; gap: 0.45rem; color: var(--text-dim); text-decoration: none; background: transparent; border: 0; padding: 0; font-family: inherit; font-size: inherit; cursor: default; }
        .dot.link, .dot[role="button"] { cursor: pointer; }
        .dot.link:hover, .dot[role="button"]:hover { color: var(--text); }
        .dot::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: var(--accent); box-shadow: 0 0 6px color-mix(in oklch, var(--accent) 60%, transparent); }
        .totals { display: inline-flex; align-items: center; gap: 0.5rem; }
        .refresh-btn { background: transparent; border: 0; color: var(--text-dim); cursor: pointer; padding: 0.15rem 0.35rem; font-size: 0.95rem; border-radius: 5px; }
        .refresh-btn:hover { color: var(--text); background: var(--panel-hover); }
        .refresh-btn.spinning { animation: spin 1s linear infinite; pointer-events: none; }
        @keyframes spin { to { transform: rotate(360deg); } }

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

        /* Snackbar */
        /* Centered via auto margins + fit-content width, NOT transform — Alpine
           writes transform inline during x-transition, which would wipe out a
           translateX(-50%) centering and slide the snackbar in from the edge. */
        .snackbar { position: fixed; bottom: 1.5rem; left: 0; right: 0; margin-inline: auto; width: max-content; max-width: 90vw; background: var(--text); color: var(--bg); padding: 0.7rem 1.15rem; border-radius: 10px; font-size: 0.88rem; z-index: 200; box-shadow: 0 10px 30px rgba(0,0,0,0.25); }
        .snackbar.error { background: var(--danger); color: white; }

        /* Responsive */
        @media (max-width: 620px) {
            body { padding: 1.25rem 0.75rem 3rem; }
            .card-head { padding: 0.9rem 1rem; flex-wrap: wrap; }
            .card-actions { width: 100%; justify-content: flex-end; }
            .site-list { grid-template-columns: 1fr auto auto; column-gap: 0.6rem; }
            .site-row { padding: 0.7rem 1rem; }
            .site-size, .site-modified { display: none; }
            .site-actions { opacity: 1; }
            .add-row { padding: 0.8rem 1rem; }
            .card-foot { padding: 0.75rem 1rem; }
        }
    </style>
</head>
<body x-data="dashboard" x-init="init()">
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
            <button class="theme-btn" @click="toggleTheme()" :title="theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'" aria-label="Toggle theme">
                <svg class="icon-moon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M13.5 9.2A5.5 5.5 0 0 1 6.8 2.5a5.75 5.75 0 1 0 6.7 6.7Z"/></svg>
                <svg class="icon-sun" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="8" cy="8" r="3"/><path d="M8 1.5v1.8M8 12.7v1.8M2.6 2.6l1.3 1.3M12.1 12.1l1.3 1.3M1.5 8h1.8M12.7 8h1.8M2.6 13.4l1.3-1.3M12.1 3.9l1.3-1.3"/></svg>
            </button>
        </nav>

        <section class="card">
            <header class="card-head">
                <h1 class="card-title">Sites</h1>
                <div class="card-actions">
                    <button class="pill" @click="cycleSort()" :title="'Sort by — click to cycle'" x-text="'sort: ' + sort"></button>
                    <a class="pill" :href="adminerUrl" target="_blank" rel="noopener" title="Open Adminer">db</a>
                    <a class="pill" :href="mailpitUrl" target="_blank" rel="noopener" title="Open Mailpit">mail</a>
                    <button class="pill primary" @click="toggleAdd()" x-text="adding ? 'cancel' : '+ add site'"></button>
                </div>
            </header>

            <div class="filter-row">
                <span class="filter-chip" x-show="typeFilter" x-transition.opacity aria-label="Active type filter" style="display: none;">
                    <span x-text="typeFilterLabel"></span>
                    <button type="button" class="filter-chip-x" @click="typeFilter = null; $refs.filterInput.focus()" aria-label="Remove type filter" title="Remove">×</button>
                </span>
                <input
                    class="filter-input"
                    type="text"
                    x-model="filter"
                    x-ref="filterInput"
                    placeholder="filter sites by name or type…"
                    spellcheck="false"
                    autocomplete="off"
                    autocapitalize="off"
                    autocorrect="off"
                    @keydown.escape.prevent="filter = ''; $event.target.blur()"
                    aria-label="Filter sites"
                >
                <span class="filter-kbd" x-show="!filter && !typeFilter" aria-hidden="true">/</span>
                <button class="filter-clear" x-show="filter || typeFilter" @click="clearAllFilters(); $refs.filterInput.focus()" aria-label="Clear filter" title="Clear all (Esc)">×</button>
            </div>

            <div x-show="adding" x-transition.opacity class="add-row" style="display: none;">
                <form @submit.prevent="addSite()">
                    <input type="text" x-model="newSite.name" @input="newSite.name = newSite.name.toLowerCase().replace(/[^a-z0-9-]/g, '')" placeholder="site-name" required :disabled="newSite.isLoading" x-ref="newSiteInput">
                    <label class="plain-toggle">
                        <input type="checkbox" x-model="newSite.isPlain" :disabled="newSite.isLoading">
                        plain (no WordPress)
                    </label>
                    <button class="pill primary" type="submit" :disabled="!newSite.name || newSite.isLoading" x-text="newSite.isLoading ? 'creating…' : 'create'"></button>
                </form>
            </div>

            <ul class="site-list">
                <template x-for="site in filteredSites" :key="site.name">
                    <li class="site-row" @click="openSite(site)">
                        <a class="site-domain" :href="site.domain" target="_blank" rel="noopener" @click.stop x-html="highlightedDomain(site.domain, filter)"></a>
                        <span class="site-type" :class="site.type === 'WordPress' ? 'wp' : 'static'" @click.stop="typeFilter = site.type" :title="'Filter to ' + (site.type === 'WordPress' ? 'WordPress' : 'static') + ' sites'" x-text="site.type === 'WordPress' ? 'WP' : 'STATIC'"></span>
                        <span class="site-modified" x-text="formatRelative(site.modified_at)" :title="site.modified_at ? new Date(site.modified_at * 1000).toLocaleString() : ''"></span>
                        <span class="site-size" x-text="formatSize(site.size_bytes)"></span>
                        <div class="site-actions">
                            <template x-if="site.type === 'WordPress'">
                                <button class="site-action-btn" :class="{ loading: site.isLoggingIn }" @click.stop="getLoginLink(site.name)" :disabled="site.isLoggingIn" :title="'One-time admin login for ' + site.name">
                                    <span class="btn-label">login</span>
                                    <span class="btn-spinner" aria-hidden="true"></span>
                                </button>
                            </template>
                            <button class="site-action-btn" @click.stop="copyPath(site.full_path)" title="Copy site path to clipboard">path</button>
                            <button class="site-action-btn danger" @click.stop="deleteSite(site.name)" :title="'Delete ' + site.name">delete</button>
                        </div>
                    </li>
                </template>
                <template x-if="isLoading">
                    <li class="loading">Loading sites…</li>
                </template>
                <template x-if="!isLoading && sites.length === 0">
                    <li class="empty">
                        <div>No sites yet.</div>
                        <div class="empty-hint">Click <em>+ add site</em>, or run <code>cove add myblog</code>.</div>
                    </li>
                </template>
                <template x-if="!isLoading && sites.length > 0 && filteredSites.length === 0">
                    <li class="empty">
                        <div>No matches for <code x-text="filter"></code>.</div>
                        <div class="empty-hint">Press Esc to clear.</div>
                    </li>
                </template>
            </ul>

            <footer class="card-foot">
                <div class="services">
                    <span class="dot" title="Caddy is serving this page — it's running">caddy</span>
                    <button type="button" class="dot link" @click="showDbModal = true" title="Database credentials">mariadb</button>
                    <a class="dot link" :href="mailpitUrl" target="_blank" rel="noopener" title="Open Mailpit">mailpit</a>
                </div>
                <div class="totals">
                    <span x-text="siteCountLabel"></span>
                    <span x-show="totalBytes > 0" x-text="'· ' + formatSize(totalBytes)"></span>
                    <button type="button" class="refresh-btn" :class="{ spinning: isRefreshingSizes }" @click="refreshSizes()" :disabled="isRefreshingSizes" :title="isRefreshingSizes ? 'Refreshing…' : 'Refresh disk sizes'">↻</button>
                </div>
            </footer>
        </section>
    </div>

    <div x-show="showDbModal" x-transition.opacity class="modal-backdrop" @click.self="showDbModal = false" @keydown.escape.window="showDbModal = false" style="display: none;">
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
                <button class="pill" @click="showDbModal = false">close</button>
            </div>
        </div>
    </div>

    <div x-show="snackbar.visible" x-transition.opacity.duration.200ms class="snackbar" :class="{ error: snackbar.isError }" x-text="snackbar.message" style="display: none;"></div>

    <script>
        const PORT_SUFFIX = '<?= $__cove_port_suffix ?>';
        const SITES_DIR = 'SITES_DIR_PLACEHOLDER';

        document.addEventListener('alpine:init', () => {
            Alpine.data('dashboard', () => ({
                // Respect the OS theme preference on first visit, dark otherwise.
                theme: localStorage.getItem('theme') || (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'),
                sites: [],
                isLoading: true,
                adding: false,
                showDbModal: false,
                isRefreshingSizes: false,
                filter: '',
                typeFilter: null, // null | 'WordPress' | 'Plain' — set via the row type pills, cleared via the chip × or overall filter clear
                sort: 'name',
                sortModes: ['name', 'size', 'modified'],
                newSite: { name: '', isPlain: false, isLoading: false },
                snackbar: { visible: false, message: '', isError: false, timer: null },
                deleteQueue: [],
                isProcessingQueue: false,

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
                    if (this.sort === 'size') {
                        base.sort((a, b) => (b.size_bytes || 0) - (a.size_bytes || 0));
                    } else if (this.sort === 'modified') {
                        base.sort((a, b) => (b.modified_at || 0) - (a.modified_at || 0));
                    } else {
                        base.sort((a, b) => a.name.localeCompare(b.name));
                    }
                    return base;
                },

                get typeFilterLabel() {
                    return this.typeFilter === 'WordPress' ? 'type: wp' : 'type: static';
                },

                clearAllFilters() {
                    this.filter = '';
                    this.typeFilter = null;
                },
                get siteCountLabel() {
                    const total = this.sites.length;
                    const visible = this.filteredSites.length;
                    const suffix = ' site' + (total === 1 ? '' : 's');
                    return visible === total ? total + suffix : visible + ' of ' + total + suffix;
                },

                init() {
                    this.applyTheme();
                    this.$watch('theme', () => { this.applyTheme(); localStorage.setItem('theme', this.theme); });

                    // `/` focuses the filter (GitHub-style). Ignored when typing
                    // in a form field or holding a modifier key.
                    window.addEventListener('keydown', (e) => {
                        if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
                        const el = document.activeElement;
                        const tag = el && el.tagName;
                        if (tag === 'INPUT' || tag === 'TEXTAREA' || (el && el.isContentEditable)) return;
                        e.preventDefault();
                        this.$refs.filterInput && this.$refs.filterInput.focus();
                    });

                    this.getSites().then(() => {
                        // If the size cache is empty (fresh install or just deleted),
                        // kick off a background refresh so sizes populate without
                        // making the user hunt for the ↻ button.
                        if (this.sites.length > 0 && this.sites.every(s => s.size_bytes === null)) {
                            this.refreshSizes();
                        }
                    });
                },

                applyTheme() {
                    document.documentElement.dataset.theme = this.theme;
                },

                toggleTheme() {
                    this.theme = this.theme === 'light' ? 'dark' : 'light';
                },

                toggleAdd() {
                    this.adding = !this.adding;
                    if (this.adding) {
                        this.$nextTick(() => { if (this.$refs.newSiteInput) this.$refs.newSiteInput.focus(); });
                    }
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
                // escaping every other substring. Safe for x-html use because the
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

                cycleSort() {
                    const i = this.sortModes.indexOf(this.sort);
                    this.sort = this.sortModes[(i + 1) % this.sortModes.length];
                },

                openSite(site) {
                    // Don't navigate when the click was part of a drag-to-select,
                    // so users can still grab the domain/size text to copy.
                    if (window.getSelection && window.getSelection().toString()) return;
                    window.open(site.domain, '_blank', 'noopener');
                },

                showSnack(msg, isError = false) {
                    if (this.snackbar.timer) clearTimeout(this.snackbar.timer);
                    this.snackbar = { visible: true, message: msg, isError, timer: null };
                    this.snackbar.timer = setTimeout(() => { this.snackbar.visible = false; }, 3500);
                },

                async apiPost(action, payload = {}) {
                    try {
                        const res = await fetch('api.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action, ...payload })
                        }).then(r => r.json());
                        if (!res.success) this.showSnack(res.message || 'An error occurred.', true);
                        return res;
                    } catch (e) {
                        this.showSnack('Network error.', true);
                        return { success: false };
                    }
                },

                async getSites() {
                    this.isLoading = true;
                    try {
                        const r = await fetch('api.php?action=list_sites');
                        const data = await r.json();
                        this.sites = data.map(s => ({ ...s, isLoggingIn: false }));
                    } catch (e) {
                        this.showSnack('Could not fetch sites.', true);
                    } finally {
                        this.isLoading = false;
                    }
                },

                async addSite() {
                    if (!this.newSite.name) return;
                    this.newSite.isLoading = true;
                    const name = this.newSite.name;
                    const isPlain = this.newSite.isPlain;

                    const add = await this.apiPost('add_site', { site_name: name, is_plain: isPlain });
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
                            size_bytes: null,
                            modified_at: Math.floor(Date.now() / 1000),
                            isLoggingIn: false,
                        });
                        this.showSnack('Site created.');
                        this.newSite.name = '';
                        this.adding = false;
                        this.apiPost('reload_server'); // fire and forget — Caddy reloads in the background
                    }
                    this.newSite.isLoading = false;
                },

                async deleteSite(name) {
                    if (!confirm(`Delete ${name}? This removes its files and database.`)) return;

                    // Optimistic: pull from the local list immediately so the UI feels
                    // instant, and enqueue the backend work. processDeleteQueue below
                    // drains the queue single-file so concurrent deletes don't race on
                    // shared state (Caddyfile regeneration, /etc/hosts edits).
                    const idx = this.sites.findIndex(s => s.name === name);
                    if (idx === -1) return;
                    this.sites.splice(idx, 1);
                    this.deleteQueue.push(name);
                    this.processDeleteQueue();
                },

                async processDeleteQueue() {
                    // Single-flight runner: whichever call picks up the lock drains the
                    // full queue. Concurrent deleteSite() calls just enqueue and return.
                    if (this.isProcessingQueue) return;
                    this.isProcessingQueue = true;

                    let anyFailed = false;
                    try {
                        while (this.deleteQueue.length > 0) {
                            const target = this.deleteQueue.shift();
                            const del = await this.apiPost('delete_site', { site_name: target });
                            if (del.success) {
                                this.showSnack('Site deleted.');
                            } else {
                                anyFailed = true; // apiPost already surfaced the error
                            }
                        }
                    } finally {
                        this.isProcessingQueue = false;
                    }

                    // One reload for the whole batch — avoids N overlapping Caddyfile
                    // regenerations when the user bulk-deletes several sites quickly.
                    this.apiPost('reload_server');

                    // If anything failed mid-queue the optimistic UI is now out of sync
                    // with the backend (e.g. a survivor is missing from our list).
                    // Cheapest correct fix: re-fetch the authoritative list.
                    if (anyFailed) await this.getSites();
                },

                async getLoginLink(name) {
                    const site = this.sites.find(s => s.name === name);
                    if (!site) return;
                    site.isLoggingIn = true;
                    const res = await this.apiPost('get_login_link', { site_name: name });
                    if (res.success && res.url) {
                        window.open(res.url, '_blank');
                        this.showSnack('Login link opened in a new tab.');
                    }
                    site.isLoggingIn = false;
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
                    const res = await this.apiPost('refresh_sizes');
                    if (res.success) {
                        await this.getSites();
                        this.showSnack('Disk sizes updated.');
                    }
                    this.isRefreshingSizes = false;
                }
            }));
        });
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
    echo "  list             Lists all sites currently managed by Cove."
    echo "  add              Creates a new WordPress or plain static site."
    echo "  delete           Deletes a site's directory and associated database."
    echo "  login            Generates a one-time login link for a WordPress site."
    echo "  rename           Renames a site, its directory, and database."
    echo "  path             Outputs the full path to a site's directory."
    echo "  pull             Pulls a remote WordPress site into Cove via SSH."
    echo "  push             Pushes a local Cove site to a remote WordPress site via SSH."
    echo "  directive        Add or remove custom Caddyfile rules for a site."
    echo "  proxy            Manage standalone reverse proxy entries."
    echo "  tailscale        Expose all sites to your Tailscale network."
    echo "  db               Manage databases (e.g., 'cove db backup')."
    echo "  lan              Enable LAN access to sites for mobile app sync."
    echo "  ports            Reconfigure HTTP/HTTPS ports + update site URLs."
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
            echo "Usage: cove install"
            echo ""
            echo "Installs and configures Homebrew dependencies like Caddy, MariaDB, and Mailpit."
            echo "It also sets up the required directory structure inside '~/Cove'."
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
            echo "Usage: cove status"
            echo ""
            echo "Checks the status of all background services."
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
            echo "Usage: cove add <name> [--plain]"
            echo ""
            echo "Creates a new local site accessible at 'https://<name>.localhost'."
            echo ""
            echo "Arguments:"
            echo "  <name>         The name for the new site. Becomes the subdomain."
            echo ""
            echo "Flags:"
            echo "  --plain        Creates a new static HTML site without a database."
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
            echo "  add         Adds a rule to the Caddyfile for the specified site."
            echo "  update      Updates a rule in the Caddyfile for the specified site."
            echo "  delete      Deletes custom rules from the Caddyfile for the specified site."
            echo "  list        Lists all custom directives for all managed sites."
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
            echo ""
            echo "Examples:"
            echo "  cove proxy add opencode myhost.tailnet.ts.net 127.0.0.1:4096"
            echo "  cove proxy list"
            echo "  cove proxy delete opencode"
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
        db)
            echo "Usage: cove db <subcommand>"
            echo ""
            echo "Manage databases."
            echo ""
            echo "Subcommands:"
            echo "  backup      Creates a .sql dump for each WP site."
            echo "  list        Lists database connection details for each WP site."
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
            echo "Usage: cove share [site]"
            echo ""
            echo "Creates a temporary public tunnel to share a local site with anyone on the internet."
            echo "Powered by Cloudflare Quick Tunnels (cloudflared installed on-demand)."
            echo ""
            echo "Arguments:"
            echo "  [site]    The site name (optional). If omitted, prompts for selection."
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
            echo "Usage: cove pull [--proxy-uploads]"
            echo ""
            echo "Pulls a remote WordPress site into Cove via an interactive TUI."
            echo "This command will guide you through providing SSH and path details for the remote site,"
            echo "then it will create a backup, pull it down, and configure it to run locally."
            echo "You can choose to create a new site or overwrite an existing one."
            echo ""
            echo "Flags:"
            echo "  --proxy-uploads  Excludes the 'wp-content/uploads' directory from the backup and"
            echo "                   configures the local site to proxy media requests to the live URL."
            echo "                   This saves significant time and disk space for large sites."
            ;;
        push)
            echo "Usage: cove push"
            echo ""
            echo "Pushes a local Cove site to a remote server via an interactive TUI."
            echo "This command will guide you through selecting a local site, providing SSH and path"
            echo "details for the remote site, then it will create a local backup, upload it, and"
            echo "run a migration script on the remote server to overwrite its contents."
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
            echo "Usage: cove upgrade"
            echo ""
            echo "Checks for the latest version of Cove on GitHub and replaces the current executable if a newer version is available."
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
            cove_install
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
        status)
            check_dependencies
            cove_status
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
            cove_upgrade
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

    if [ -z "$site_name" ]; then
        gum style --foreground red "❌ Error: A site name is required."
        echo "Usage: cove add <name> [--plain]"
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

    # Check all arguments passed to the function for our flags
    for arg in "$@"; do
        if [ "$arg" == "--plain" ]; then
            site_type="plain"
        fi
        if [ "$arg" == "--no-reload" ]; then
            no_reload_flag=true
        fi
    done

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

    echo "➕ Creating $site_type site: $full_hostname"
    mkdir -p "$site_dir/public" "$site_dir/logs"

    local admin_user="admin"
    local admin_pass
    local one_time_login_url=""

    if [ "$site_type" == "wordpress" ]; then
        source_config
        local db_name
        db_name=$(echo "cove_$site_name" | tr -c '[:alnum:]_' '_')
        
        echo "🗄️ Creating database: $db_name"
        mysql -u "$DB_USER" -p"$DB_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS \`$db_name\`;"
        echo "Installing WordPress..."
        admin_pass=$(openssl rand -base64 12)
        
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
        wp_cmd=$(get_wp_cmd)

        (
            cd "$site_dir/public" || exit 1

            # 1. Download WordPress with a higher memory limit
            if ! $wp_cmd core download --quiet; then
                echo "❌ Error: Failed to download WordPress core. This might be a network issue or a permissions problem."
                exit 1 # Exit the subshell with an error
            fi

            # 2. Create the config file
            $wp_cmd config create --dbname="$db_name" --dbuser="$DB_USER" --dbpass="$DB_PASSWORD" --extra-php <<PHP
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
define( 'WP_DEBUG_DISPLAY', false );
PHP

            # 3. Install WordPress
            $wp_cmd core install --url="$(url_for "$full_hostname")" --title="Welcome to $site_name" --admin_user="$admin_user" --admin_password="$admin_pass" --admin_email="admin@$full_hostname" --skip-email

            # 4. Delete default plugins
            echo "   - Deleting default plugins (Hello Dolly, Akismet)..."
            $wp_cmd plugin delete hello akismet --quiet
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
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "✅ WordPress Installed" "URL: $(url_for "$full_hostname")/wp-admin" "User: $admin_user" "Pass: $admin_pass" "One-time login URL: $one_time_login_url"
    fi
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
                
                # Get WP-CLI command (adds --allow-root if running as root)
                local wp_cmd
                wp_cmd=$(get_wp_cmd)
                
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

    # Determine if we need --allow-root for wp-cli (running as root in WSL/Docker)
    local wp_root_flag=""
    if [ "$(id -u)" -eq 0 ]; then
        wp_root_flag="--allow-root"
    fi

    # This heredoc contains a PHP script to find, connect, and format the database list.
    # We invoke it via `frankenphp php-cli -r` so we don't depend on a standalone php binary.
    local wp_path
    wp_path=$(command -v wp)
    local frank
    frank=$(command -v frankenphp)
    local php_output
    php_output=$(DB_USER="$DB_USER" DB_PASSWORD="$DB_PASSWORD" SITES_DIR="$SITES_DIR" WP_ROOT_FLAG="$wp_root_flag" WP_PATH="$wp_path" FRANK_BIN="$frank" frankenphp php-cli -r '
        function formatSize(int $bytes): string {
            if ($bytes === 0) return "0 B";
            $units = ["B", "KB", "MB", "GB", "TB"];
            $i = floor(log($bytes, 1024));
            return round($bytes / (1024 ** $i), 2) . " " . $units[$i];
        }

        $sites_dir = getenv("SITES_DIR");
        $db_user = getenv("DB_USER");
        $db_pass = getenv("DB_PASSWORD");
        $wp_root_flag = getenv("WP_ROOT_FLAG");
        $wp_path = getenv("WP_PATH");
        $frank_bin = getenv("FRANK_BIN");
        $wp_invoker = escapeshellarg($frank_bin) . " php-cli " . escapeshellarg($wp_path);

        if (!is_dir($sites_dir)) { exit; }

        try {
            $pdo = new PDO("mysql:host=localhost", $db_user, $db_pass, [PDO::ATTR_TIMEOUT => 2]);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) { exit; }

        $sites_info = [];
        foreach (scandir($sites_dir) as $item) {
            $public_dir = $sites_dir . "/" . $item . "/public";
            if (is_file($public_dir . "/wp-config.php")) {
                $site_name = str_replace(".localhost", "", $item);
                $public_dir_esc = escapeshellarg($public_dir);
                $cmd_suffix = " " . $wp_root_flag . " --skip-plugins --skip-themes --quiet 2>/dev/null";
                
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
                    
                    $stmt = $pdo->prepare("SELECT SUM(data_length + index_length) as size FROM information_schema.TABLES WHERE table_schema = ?");
                    $stmt->execute([$site_db_name]);
                    $size_bytes = $stmt->fetch(PDO::FETCH_ASSOC)["size"] ?? 0;
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
    ')

    if [ -z "$php_output" ]; then
        gum style --padding "1 2" "ℹ️ No WordPress sites with readable database configurations found."
    else
        echo "$php_output" | gum style --border normal --margin "1" --padding "1 2" --border-foreground 212
    fi
}
cove_delete() {
    source_config
    local site_name="$1"
    for protected_name in $PROTECTED_NAMES; do
        if [ "$site_name" == "$protected_name" ]; then
            gum style --foreground red "❌ Error: '$site_name' is a reserved name and cannot be deleted."
            exit 1
        fi
    done

    local force_delete=false
    if [ "$2" == "--force" ]; then
        force_delete=true
    fi

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
        local db_name
        db_name=$(echo "cove_$site_name" | tr -c '[:alnum:]_' '_')
        echo "🗄️ Deleting database: $db_name"
        mysql -u "$DB_USER" -p"$DB_PASSWORD" -e "DROP DATABASE IF EXISTS \`$db_name\`;"
    fi

    rm -rf "$site_dir"
    echo "✅ Directory deleted."

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

    echo "✅ Site '$site_name.localhost' has been removed."
}
cove_directive_add_or_update() {
    local site_name="$1"
    if [ -z "$site_name" ]; then
        gum style --foreground red "❌ Error: Please provide a site name."
        echo "Usage: cove directive <add|update> <name>"
        exit 1
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
    # If stdin is a terminal (interactive), use gum. Otherwise, read from pipe.
    if [ -t 0 ]; then
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
    local site_name="$1"
    if [ -z "$site_name" ]; then
        gum style --foreground red "❌ Error: Please provide a site name."
        echo "Usage: cove directive delete <name>"
        exit 1
    fi

    local site_hostname="${site_name}.localhost"
    local custom_conf_file="$CUSTOM_CADDY_DIR/$site_hostname"

    if [ -f "$custom_conf_file" ]; then
        if gum confirm "🚨 Are you sure you want to delete the custom directives for '$site_hostname'?"; then
            rm "$custom_conf_file"
            echo "✅ Custom directives deleted for $site_hostname."
            regenerate_caddyfile
        else
            echo "🚫 Deletion cancelled."
        fi
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
        launchctl unload "$COVE_DIR/com.cove.caddy.plist" &>/dev/null
        "$CADDY_CMD" stop --config "$CADDYFILE_PATH" &>/dev/null 2>&1
        echo "   - Stopping MariaDB..."
        brew services stop mariadb &>/dev/null
        echo "   - Stopping Mailpit..."
        launchctl unload "$COVE_DIR/com.cove.mailpit.plist" &>/dev/null
    fi

    # Stop services on Linux
    if [ "$OS" == "linux" ]; then
        # Get the correct MariaDB service name
        local mariadb_service
        mariadb_service=$(get_mariadb_service_name)
        
        echo "   - Stopping MariaDB ($mariadb_service)..."
        $SUDO_CMD systemctl stop "$mariadb_service" &>/dev/null
        echo "   - Stopping Mailpit..."
        $SUDO_CMD systemctl stop mailpit &>/dev/null
    fi
    
    echo "✅ Services stopped."
}
cove_enable() {
    echo "🚀 Enabling Cove services..."
    
    # Ensure log directory exists
    mkdir -p "$LOGS_DIR"

    if [ "$OS" == "macos" ]; then
        echo "   - Starting MariaDB..."
        brew services start mariadb

        local plist_path="$COVE_DIR/com.cove.mailpit.plist"
        local mailpit_bin
        mailpit_bin=$(command -v mailpit)

        # Stop and unload any existing service to ensure our custom one is used.
        launchctl unload "$plist_path" &>/dev/null
        brew services stop mailpit &>/dev/null

        echo "   - Generating custom Mailpit service file..."
        cat > "$plist_path" << EOM
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>KeepAlive</key>
        <true/>
        <key>Label</key>
        <string>com.cove.mailpit</string>
        <key>ProgramArguments</key>
        <array>
                <string>$mailpit_bin</string>
                <string>--database</string>
                <string>$COVE_DIR/mailpit.db</string>
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
        # Load and start the new service.
        launchctl load "$plist_path"
        launchctl start com.cove.mailpit
    fi
    
    if [ "$OS" == "linux" ]; then
        # Get the correct MariaDB service name for this distro
        local mariadb_service
        mariadb_service=$(get_mariadb_service_name)
        
        echo "   - Starting MariaDB ($mariadb_service)..."
        $SUDO_CMD systemctl enable "$mariadb_service" &>/dev/null
        $SUDO_CMD systemctl restart "$mariadb_service"
        
        local service_path="/etc/systemd/system/mailpit.service"
        local mailpit_bin
        mailpit_bin=$(command -v mailpit)
        local current_user
        current_user=$(whoami)

        echo "   - Generating custom Mailpit service file..."
        # Note: Using a temp file approach to avoid issues with heredoc and sudo
        local temp_service
        temp_service=$(mktemp)
        cat > "$temp_service" << EOM
[Unit]
Description=Mailpit Service for Cove
After=network.target

[Service]
ExecStart=$mailpit_bin --database $COVE_DIR/mailpit.db
Restart=always
User=$current_user

[Install]
WantedBy=multi-user.target
EOM
        
        $SUDO_CMD mv "$temp_service" "$service_path"
        $SUDO_CMD chmod 644 "$service_path"
        
        # Reload systemd, then enable and start the service
        $SUDO_CMD systemctl daemon-reload
        $SUDO_CMD systemctl enable mailpit &>/dev/null
        $SUDO_CMD systemctl restart mailpit
    fi
    
    start_caddy_service

    if [ $? -eq 0 ]; then
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
        if brew install "$brew_pkg"; then
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
                echo "   - Downloading and extracting tarball..."
                if curl -sL "$binary_url" | tar -xz -C "$temp_dir" 2>/dev/null; then
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
                read -p "Do you want to continue anyway? (y/N) " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    echo "🚫 Installation cancelled."
                    exit 0
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

    # --- Reconfigure path ---
    if [ "$HTTP_PORT" != "80" ] || [ "$HTTPS_PORT" != "443" ]; then
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
    if [ -d "$COVE_DIR" ]; then
        if ! gum confirm "⚠️ The Cove directory (~/Cove) already exists. Proceeding may overwrite some configurations. Continue?"; then
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
    fi

    # MariaDB - Database server
    install_dependency "mariadb" "mariadb" "mariadb-server" "mariadb-server" ""

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
memory_limit = 512M
display_errors = 0
error_reporting = 6143
INI
    echo "🗃️ Downloading Adminer 5.4.1..."
    curl -sL "https://github.com/vrana/adminer/releases/download/v5.4.1/adminer-5.4.1.php" -o "$ADMINER_DIR/adminer-core.php"
    echo "⚙️ Creating Adminer autologin..."
    # Create a custom index.php to handle autologin
    # Note: Adminer 5.x uses the Adminer\Adminer namespace
    cat > "$ADMINER_DIR/index.php" << 'EOM'
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
    }
    return new AdminerCoveLogin();
}
// Include the original Adminer core file to run the application.
include "./adminer-core.php";
EOM

    echo "🎨 Downloading Adminer Catppuccin theme..."
    curl -sL "https://raw.githubusercontent.com/anchorhost/cove/main/adminer-theme/adminer.css" -o "$ADMINER_DIR/adminer.css"

    echo "✨ Downloading Whoops error handler..."
    rm -rf "$APP_DIR/whoops" # Remove any old versions first
    mkdir -p "$APP_DIR/whoops"
    curl -sL "https://github.com/filp/whoops/archive/refs/tags/2.15.3.tar.gz" | tar -xz -C "$APP_DIR/whoops" --strip-components=1

    echo "⚙️ Starting services..."
    if [ "$OS" == "macos" ]; then
        if ! brew services restart mariadb; then
            gum style --foreground red "❌ Failed to start MariaDB via Homebrew."
            exit 1
        fi
    else # Linux
        if ! $SUDO_CMD systemctl restart mariadb; then
            gum style --foreground red "❌ Failed to start MariaDB via systemctl."
            exit 1
        fi
    fi

    # --- Database Configuration ---
    if [ -f "$CONFIG_FILE" ] && gum confirm "Existing Cove database config found. Use it and skip database setup?"; then
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
        db_pass=$(openssl rand -base64 16)
        local sql_command="DROP USER IF EXISTS '$db_user'@'localhost'; CREATE USER '$db_user'@'localhost' IDENTIFIED BY '$db_pass'; GRANT ALL PRIVILEGES ON *.* TO '$db_user'@'localhost' WITH GRANT OPTION; FLUSH PRIVILEGES;"
        local user_created_successfully=false

        echo "   - Attempting automatic setup..."
        if echo "$sql_command" | $SUDO_CMD mysql &> /dev/null; then
            echo "   - ✅ Automatic database user creation successful."
            user_created_successfully=true
        else
            echo "   - ⚠️ Automatic setup failed. Falling back to manual credential entry..."
            local root_user
            root_user=$(gum input --value "root" --prompt "MariaDB Root Username: ")
            local root_pass
            root_pass=$(gum input --password --placeholder "Password for '$root_user'")

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
    php_output=$(SITES_DIR="$SITES_DIR" SHOW_TOTALS="$show_totals" HTTPS_PORT_SUFFIX="$(https_port_suffix)" frankenphp php-cli -r '
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

        $sites_dir = getenv("SITES_DIR");
        $show_totals = getenv("SHOW_TOTALS") === "true";
        $port_suffix = getenv("HTTPS_PORT_SUFFIX") ?: "";

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
                $sites[] = [
                    "name" => str_replace(".localhost", "", $item),
                    "domain" => "https://" . $item . $port_suffix,
                    "type" => file_exists($site_path . "/public/wp-config.php") ? "WordPress" : "Plain",
                    "size" => $size,
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
        
        $type_width = $show_totals ? 9 + $gap : 10; // "WordPress" + gap or padding
        
        $size_width = $show_totals ? 11 : 0;

        // ANSI colors
        $pink = "\033[38;5;212m";
        $dim = "\033[2m";
        $reset = "\033[0m";

        // Box drawing characters
        $tl = "╭"; $tr = "╮"; $bl = "╰"; $br = "╯";
        $h = "─"; $v = "│";

        // Calculate total width
        $inner_width = $name_width + $domain_width + $type_width;
        if ($show_totals) {
            $inner_width += $size_width;
        }

        // Build horizontal lines
        $top_line = $pink . $tl . str_repeat($h, $inner_width) . $tr . $reset;
        $mid_line = $pink . $v . $reset . $dim . " " . str_repeat("-", $inner_width - 2) . " " . $reset . $pink . $v . $reset;
        $bot_line = $pink . $bl . str_repeat($h, $inner_width) . $br . $reset;

        // Header row (white text)
        $header = $pink . $v . $reset . " " . str_pad("Name", $name_width - 1) . str_pad("Domain", $domain_width) . str_pad("Type", $type_width);
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

    local site_dir="$SITES_DIR/$site_name.localhost"
    local public_dir="$site_dir/public"
    
    # Get WP-CLI command (adds --allow-root if running as root)
    local wp_cmd
    wp_cmd=$(get_wp_cmd)

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

    # 3. Attempt to generate the login URL.
    echo "   Generating login link..."
    local login_url
    # Suppress stderr on the first try so we can handle the error gracefully.
    login_url=$( (cd "$public_dir" && $wp_cmd user login "$admin_to_login" ) 2>/dev/null )
    local exit_code=$?

    # 4. If the command failed, check for the mu-plugin and retry.
    if [ $exit_code -ne 0 ]; then
        echo "   ⚠️ Login command failed. Checking for missing MU-plugin..."
        local mu_plugin_path="$public_dir/wp-content/mu-plugins/captaincore-helper.php"
        
        if [ ! -f "$mu_plugin_path" ]; then
            # The plugin is missing, so inject it.
            inject_mu_plugin "$public_dir"
            
            echo "   - Retrying login link generation..."
            # Run the command again, but this time, show errors if it fails.
            login_url=$( (cd "$public_dir" && $wp_cmd user login "$admin_to_login" --skip-plugins --skip-themes) )
        else
            # The plugin exists, so the failure is for another reason.
            echo "   - MU-plugin is already present. The issue may be with WP-CLI or the site's database."
        fi
    fi

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
            -h|--help)
                display_command_help ports
                exit 0
                ;;
            *)
                gum style --foreground red "❌ Unknown option: $1"
                echo "Usage: cove ports [--http PORT] [--https PORT] [--skip-urls] [--dry-run]"
                exit 1
                ;;
        esac
    done

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
    if ! gum confirm "Proceed with the port change?"; then
        # Revert globals so nothing leaks to the caller
        HTTP_PORT="$original_http"
        HTTPS_PORT="$original_https"
        echo "🚫 Cancelled."
        exit 0
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

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --no-tls)
                tls_mode="none"
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

    # Interactive mode if arguments not provided
    if [ -z "$name" ]; then
        echo "📝 Adding a new reverse proxy entry..."
        name=$(gum input --placeholder "Proxy name (e.g., opencode)")
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
    if [ -f "$proxy_file" ]; then
        if ! gum confirm "⚠️ Proxy '$name' already exists. Overwrite?"; then
            echo "🚫 Cancelled."
            exit 0
        fi
    fi

    if [ -z "$domain" ]; then
        domain=$(gum input --placeholder "Domain to listen on (e.g., myhost.tailnet.ts.net)")
    fi

    if [ -z "$domain" ]; then
        gum style --foreground red "❌ Error: Domain is required."
        exit 1
    fi

    if [ -z "$target" ]; then
        target=$(gum input --placeholder "Target to proxy to (e.g., 127.0.0.1:4096)")
    fi

    if [ -z "$target" ]; then
        gum style --foreground red "❌ Error: Target is required."
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
    local name="$1"

    if [ -z "$name" ]; then
        # Interactive mode - let user select from existing proxies
        if [ ! -d "$PROXY_DIR" ] || [ -z "$(ls -A "$PROXY_DIR" 2>/dev/null)" ]; then
            gum style --foreground "yellow" "ℹ️ No proxy entries to delete."
            exit 0
        fi

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

    if gum confirm "🚨 Are you sure you want to delete proxy '$name'?"; then
        rm "$proxy_file"
        echo "✅ Proxy '$name' deleted."
        regenerate_caddyfile
    else
        echo "🚫 Deletion cancelled."
    fi
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
            echo "Examples:"
            echo "  cove proxy add opencode myhost.tailnet.ts.net 127.0.0.1:4096"
            echo "  cove proxy add api api.example.com localhost:3000 --no-tls"
            echo "  cove proxy list"
            echo "  cove proxy delete opencode"
            exit 0
            ;;
    esac
}

cove_pull() {
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
    local proxy_uploads=false
    for arg in "$@"; do
        if [ "$arg" == "--proxy-uploads" ]; then
            proxy_uploads=true
            break
        fi
    done

    # Define quiet SSH options to prevent host key warnings
    local ssh_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

    gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "This tool will guide you through pulling a remote WordPress site into Cove."
    # --- 1. Gather Remote Info ---
    log_step "Enter remote server details"
    local remote_ssh
    remote_ssh=$(gum input --placeholder "user@host.com -p 2222" --prompt "SSH Connection: ")
    if [ -z "$remote_ssh" ]; then log_error "SSH connection cannot be empty."; fi

    # Trim the "ssh " prefix if the user includes it.
    remote_ssh="${remote_ssh##ssh }"

    local remote_path
    remote_path=$(gum input --value "public/" --prompt "Path to WordPress Root: ")
    if [ -z "$remote_path" ]; then log_error "Remote path cannot be empty."; fi
    local remote_path_q
    remote_path_q=$(shell_quote "$remote_path")

    # --- 2. Validate Remote Site ---
    log_step "Validating remote WordPress site..."
    local remote_url
    remote_url=$(ssh $ssh_opts $remote_ssh "cd $remote_path_q && wp option get home 2>/dev/null")
    domain=$(echo "$remote_url" | sed -E 's/https?:\/\/(www\.)?//; s/\/.*//')
    
    if [ -z "$remote_url" ] || [[ ! "$remote_url" == http* ]]; then
        log_error "Could not find a valid WordPress site at the specified path. Check your connection details and path."
    fi
    log_success "Found WordPress site: $remote_url"

    # --- 3. Choose Destination ---
    log_step "Choose a destination for the pulled site"
    
    local wp_sites=()
    for site_dir in "$SITES_DIR"/*.localhost; do
        if [ -f "$site_dir/public/wp-config.php" ]; then
            wp_sites+=("$(basename "$site_dir" .localhost)")
        fi
    done
    
    local destination_choice
    destination_choice=$(gum choose "New Site" "${wp_sites[@]}")

    local site_name
    local dest_path
    local local_url
    local db_name

    if [ "$destination_choice" == "New Site" ]; then
        local proposed_name
        proposed_name=$(echo "$remote_url" | sed -E 's/https?:\/\/(www\.)?//; s/\/.*//; s/\./-/g')
        site_name=$(gum input --value "$proposed_name" --prompt "Enter a name for the new local site: ")
        if [ -z "$site_name" ]; then log_error "Site name cannot be empty."; fi

        log_step "Creating new placeholder site: ${site_name}.localhost"
        "$COVE_CMD" add "$site_name"
        if [ $? -ne 0 ]; then log_error "Failed to create placeholder site. Does it already exist?"; fi
        
    else
        site_name="$destination_choice"
        if ! gum confirm "Are you sure you want to overwrite '${site_name}'? All its files and database content will be replaced."; then
            echo "🚫 Pull cancelled."
            exit 0
        fi
        
        log_step "Preparing to overwrite existing site: ${site_name}.localhost"
        db_name=$(echo "cove_$site_name" | tr -c '[:alnum:]_' '_')
        mysql -u "$DB_USER" -p"$DB_PASSWORD" -e "DROP DATABASE IF EXISTS \`$db_name\`; CREATE DATABASE \`$db_name\`;"
    fi

    dest_path="$SITES_DIR/$site_name.localhost/public"
    local_url="$(url_for "$site_name.localhost")"

    # --- 4. Perform Migration ---
    log_step "Generating backup for ${remote_url}..."
    local backup_extra_args=""
    if [ "$proxy_uploads" = true ]; then
        log_success "Uploads will be excluded from the backup and proxied instead."
        backup_extra_args="--exclude=\"wp-content/uploads\""
    fi

    local backup_url
    backup_url=$(ssh $ssh_opts $remote_ssh "curl -sL https://captaincore.io/do | bash -s -- backup $remote_path_q --quiet $backup_extra_args")

    if [[ -z "$backup_url" || ! "$backup_url" == *.zip ]]; then
        log_error "Failed to generate backup or received an invalid backup URL."
    fi
    log_success "Backup created: ${backup_url}"

    log_step "Restoring backup to ${site_name}.localhost..."
    # Execute the migration script directly instead of using a variable with a pipe
    if ! (cd "$dest_path" && curl -sL https://captaincore.io/do | bash -s -- migrate --url="$backup_url" --update-urls); then
        log_error "The migration script failed to execute correctly."
    fi
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
    local filename="${backup_url##*/}"
    local remote_backup_q
    remote_backup_q=$(shell_quote "$remote_path/$filename")
    ssh $ssh_opts $remote_ssh "rm -f $remote_backup_q" 2>/dev/null
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
        gum style --foreground "red" "❌ ERROR: $1" 
        >&2
        exit 1
    }

    # Define quiet SSH options to prevent host key warnings
    local ssh_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

    gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "This tool will guide you through pushing a local Cove site to a remote server."

    # --- 1. Choose Local Site ---
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

    local site_name
    site_name=$(gum choose "${wp_sites[@]}")
    if [ -z "$site_name" ]; then log_error "No site selected."; fi

    local local_path="$SITES_DIR/$site_name.localhost/public"
    
    # --- 2. Gather Remote Info ---
    log_step "Enter remote server details"
    local remote_ssh
    remote_ssh=$(gum input --placeholder "user@host.com -p 2222" --prompt "SSH Connection: ")
    if [ -z "$remote_ssh" ]; then log_error "SSH connection cannot be empty."; fi

    # Trim the "ssh " prefix if the user includes it.
    remote_ssh="${remote_ssh##ssh }"

    local remote_path
    remote_path=$(gum input --value "public/" --prompt "Path to Remote WordPress Root: ")
    if [ -z "$remote_path" ]; then log_error "Remote path cannot be empty."; fi
    local remote_path_q
    remote_path_q=$(shell_quote "$remote_path")

    # --- 3. Validate Remote Site ---
    log_step "Validating remote WordPress site..."
    local remote_url
    remote_url=$(ssh $ssh_opts $remote_ssh "cd $remote_path_q && wp option get home 2>/dev/null")
    
    if [ -z "$remote_url" ] || [[ ! "$remote_url" == http* ]]; then
        log_error "Could not find a valid WordPress site at the specified path. Check your connection details and path."
    fi
    log_success "Found remote site to overwrite: $remote_url"

    # --- 4. Confirmation ---
    if ! gum confirm "🚨 Are you sure you want to push '${site_name}' to '${remote_url}'? This will completely overwrite the remote site's files and database."; then
        echo "🚫 Push cancelled."
        exit 0
    fi

    # --- 5. Perform Local Backup ---
    log_step "Generating local backup for ${site_name}..."
    local backup_filename
    backup_filename=$( (cd "$local_path" && curl -sL https://captaincore.io/do | bash -s -- backup . --quiet --format=filename) )
    
    if [[ ! -f "$backup_filename" || ! "$backup_filename" == *".zip" ]]; then
        log_error "Failed to generate local backup. The captaincore script might have failed."
    fi
    
    size=$(ls -lh "$backup_filename" | awk '{print $5}')
    log_success "Local backup created: ${backup_filename} ($size)"

    local backup_filename_q
    backup_filename_q=$(shell_quote "$backup_filename")
    local remote_backup_q
    remote_backup_q=$(shell_quote "$remote_path/$backup_filename")

    # --- 6. Upload Backup ---
    log_step "Uploading backup to remote server..."
    if ! cat "$backup_filename" | ssh $ssh_opts $remote_ssh "cat > $remote_backup_q"; then
        # Clean up local backup on failure
        rm -f "$backup_filename"
        log_error "Failed to upload backup."
    fi
    log_success "Upload complete."

    # --- 7. Remote Restore ---
    log_step "Restoring backup on remote server..."
    if ! ssh $ssh_opts $remote_ssh "cd $remote_path_q && curl -sL https://captaincore.io/do | bash -s -- migrate --url=$backup_filename_q --update-urls"; then
        log_error "The remote migration script failed to execute correctly."
    fi
    log_success "Remote restore complete."

    # --- 8. Cleanup ---
    log_step "Cleaning up backup files..."
    rm -f "$backup_filename"
    ssh $ssh_opts $remote_ssh "rm -f $remote_backup_q"
    log_success "Cleanup complete."

    # --- 9. Finalize ---
    gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "✨ All done! Your site has been pushed successfully." "Remote URL: ${remote_url}"
}
cove_reload() {
    create_gui_file
    regenerate_caddyfile
    update_etc_hosts
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
        
        # Get WP-CLI command (adds --allow-root if running as root)
        local wp_cmd
        wp_cmd=$(get_wp_cmd)
        
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
        mysql -u "$DB_USER" -p"$DB_PASSWORD" "$new_db_name" < "$temp_sql_dump"

        echo "   - Updating wp-config.php..."
        (cd "$new_site_dir/public" && $wp_cmd config set DB_NAME "$new_db_name" --quiet)

        echo "   - Running search-replace for site URL..."
        (cd "$new_site_dir/public" && $wp_cmd search-replace "$(url_for "$old_name.localhost")" "$(url_for "$new_name.localhost")" --all-tables --skip-plugins --skip-themes --quiet)

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
    local site_name="$1"
    
    # --- 1. Validate Site ---
    if [ -z "$site_name" ]; then
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
        
        if command -v brew &> /dev/null; then
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
            if gum confirm "Install cloudflared via ${install_name}?"; then
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
    echo "🔎 Checking Cove service status..."

    local caddy_status="❌ Stopped"
    local mariadb_status="❌ Stopped"
    local mailpit_status="❌ Stopped"

    # Check Caddy status by PID file
    if [ -f "$COVE_DIR/caddy.pid" ]; then
        local caddy_pid
        caddy_pid=$(cat "$COVE_DIR/caddy.pid" 2>/dev/null)
        if [ -n "$caddy_pid" ] && ps -p "$caddy_pid" > /dev/null 2>&1; then
            caddy_status="✅ Running"
        fi
    fi

    # Check MariaDB and Mailpit status on MacOS
    if [ "$OS" == "macos" ]; then
        if brew services list 2>/dev/null | grep -q "mariadb.*started"; then 
            mariadb_status="✅ Running"
        fi
        if launchctl list 2>/dev/null | grep -q "com.cove.mailpit"; then 
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
    
    echo ""
    echo "  Caddy Server: $caddy_status"
    echo "  MariaDB:      $mariadb_status"
    echo "  Mailpit:      $mailpit_status"
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
        hostname=$(gum input --placeholder "your-machine.tailnet.ts.net")
    fi

    if [ -z "$hostname" ]; then
        gum style --foreground red "❌ Error: Tailscale hostname is required."
        exit 1
    fi

    # Remove any trailing dot
    hostname="${hostname%.}"

    # Validate it looks like a hostname
    if [[ ! "$hostname" =~ \. ]]; then
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
    echo "🔎 Checking for the latest version of Cove..."

    local download_url="https://github.com/anchorhost/cove/releases/latest/download/cove.sh"
    local temp_script="/tmp/cove.sh.latest"
    local install_path

    # Find the real path of the currently running script
    install_path=$(command -v cove)
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
        upgrade_frankenphp
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
        if gum confirm "Current version unknown. Would you like to download the latest Adminer ($latest_adminer_version)?"; then
            echo "🚀 Downloading Adminer $latest_adminer_version..."
            if curl -sL "https://github.com/vrana/adminer/releases/download/v${latest_adminer_version}/adminer-${latest_adminer_version}.php" -o "$adminer_file"; then
                echo "✅ Adminer downloaded successfully."
            else
                echo "❌ Failed to download Adminer $latest_adminer_version."
            fi
        fi
    fi
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

#  Pass all script arguments to the main function.
main "$@"
