#!/bin/bash

# ====================================================
#  Cove - Main Script
#  Contains global configurations, helper functions,
#  and the main command routing logic.
# ====================================================

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

APP_DIR="$COVE_DIR/App"
SITES_DIR="$COVE_DIR/Sites"
LOGS_DIR="$COVE_DIR/Logs"

# App Sub-directories
GUI_DIR="$APP_DIR/gui"
ADMINER_DIR="$APP_DIR/adminer"
CUSTOM_CADDY_DIR="$APP_DIR/directives"

PROTECTED_NAMES="cove"
COVE_VERSION="1.7"
CADDY_CMD="frankenphp"

# Note: BIN_DIR is set in setup_environment() based on OS and architecture

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
 * Version: 0.2.8
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

# Helper function to get WP-CLI command with --allow-root if running as root
# This is needed for WSL/Docker environments where root is common
get_wp_cmd() {
    local wp_path
    wp_path=$(command -v wp)
    if [ "$(id -u)" -eq 0 ]; then
        echo "$wp_path --allow-root"
    else
        echo "$wp_path"
    fi
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

# Function to regenerate the Caddyfile
regenerate_caddyfile() {
    echo "🔄 Regenerating Caddyfile..."
    if ! command -v mailpit &> /dev/null; then
        gum style --foreground red "❌ Mailpit is not installed. Please run 'cove install' successfully first."
        return 1
    fi
    local mailpit_path
    mailpit_path=$(command -v mailpit)

    # Write the static header of the Caddyfile
    cat > "$CADDYFILE_PATH" <<- EOM
{
    frankenphp {
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
                echo "    encode gzip" >> "$CADDYFILE_PATH"
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
                        echo "    encode gzip" >> "$CADDYFILE_PATH"
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
                        # Proxy through the local site
                        echo "    reverse_proxy https://${site_name} {" >> "$CADDYFILE_PATH"
                        echo "        header_up Host ${site_name}" >> "$CADDYFILE_PATH"
                        echo "        transport http {" >> "$CADDYFILE_PATH"
                        echo "            tls_insecure_skip_verify" >> "$CADDYFILE_PATH"
                        echo "        }" >> "$CADDYFILE_PATH"
                        echo "    }" >> "$CADDYFILE_PATH"
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
        
        # DB on port 9902
        echo "# Tailscale: db -> port 9902" >> "$CADDYFILE_PATH"
        echo "https://${tailscale_hostname}:9902 {" >> "$CADDYFILE_PATH"
        echo "    tls internal" >> "$CADDYFILE_PATH"
        echo "    reverse_proxy https://db.cove.localhost {" >> "$CADDYFILE_PATH"
        echo "        header_up Host db.cove.localhost" >> "$CADDYFILE_PATH"
        echo "        transport http {" >> "$CADDYFILE_PATH"
        echo "            tls_insecure_skip_verify" >> "$CADDYFILE_PATH"
        echo "        }" >> "$CADDYFILE_PATH"
        echo "    }" >> "$CADDYFILE_PATH"
        echo "}" >> "$CADDYFILE_PATH"
        echo "" >> "$CADDYFILE_PATH"
        
        # Dashboard on port 9900
        echo "# Tailscale: cove dashboard -> port 9900" >> "$CADDYFILE_PATH"
        echo "https://${tailscale_hostname}:9900 {" >> "$CADDYFILE_PATH"
        echo "    tls internal" >> "$CADDYFILE_PATH"
        echo "    reverse_proxy https://cove.localhost {" >> "$CADDYFILE_PATH"
        echo "        header_up Host cove.localhost" >> "$CADDYFILE_PATH"
        echo "        transport http {" >> "$CADDYFILE_PATH"
        echo "            tls_insecure_skip_verify" >> "$CADDYFILE_PATH"
        echo "        }" >> "$CADDYFILE_PATH"
        echo "    }" >> "$CADDYFILE_PATH"
        echo "}" >> "$CADDYFILE_PATH"
        echo "" >> "$CADDYFILE_PATH"
    fi

    # Reload Caddy with the new configuration.
    # We run this in the background (&) to prevent a deadlock when the GUI,
    # which is run by Caddy/FrankenPHP, executes a command that tries to reload the server.
    # The server can't wait for a command that it needs to process itself.
    $SUDO_CMD "$CADDY_CMD" reload --config "$CADDYFILE_PATH" --address localhost:2019 &> "$LOGS_DIR/caddy-reload.log" &
    
    # Because the command is backgrounded, we can't check its exit code directly.
    # We'll assume success and let the user check 'cove status' or logs if needed.
    echo "✅ Caddy configuration reload initiated."
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

// Handle GET requests for listing sites
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $action = $_GET['action'] ?? '';
    if ($action === 'list_sites') {
        $sites_info = [];
        if (file_exists($sitedir) && is_dir($sitedir)) {
            $items = scandir($sitedir);
            foreach ($items as $item) {
                if ($item === '.' || $item === '..') continue;
                $site_path = $sitedir . '/' . $item;
                if (is_dir($site_path)) {
                    $sites_info[] = [
                        'name' => str_replace('.localhost', '', $item),
                        'domain' => 'https://' . $item,
                        'type' => file_exists($site_path . "/public/wp-config.php") ? 'WordPress' : 'Plain',
                        'display_path' => '~/Cove/Sites/' . $item,
                        'full_path' => $site_path
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
?>
<!DOCTYPE html>
<html lang="en" x-data="{ theme: localStorage.getItem('theme') || 'dark' }" x-init="$watch('theme', val => localStorage.setItem('theme', val))" :data-theme="theme">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cove Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code&family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css"/>
    <script src="//unpkg.com/alpinejs" defer></script>
    <style>
        :root { --pico-font-family: 'Inter', sans-serif; --pico-font-size: 95%; --pico-spacing: 0.75rem; --pico-card-padding: 1.25rem; --pico-form-element-spacing-vertical: 0.75rem; --pico-form-element-spacing-horizontal: 1rem; --pico-form-element-spacing-vertical: 0.5rem; --pico-form-element-spacing-horizontal: 0.75rem;}
        code, pre, kbd { font-family: 'Fira Code', monospace; }
        [data-theme="light"], :root:not([data-theme="dark"]) { --pico-primary: #163c52; --pico-primary-hover: #1f5472; --pico-primary-focus: rgba(22, 60, 82, 0.25); --pico-card-background-color: #fdf4e9; --pico-card-border-color: #e9e2d9; --pico-code-background-color: #e9e2d9; }
        [data-theme="dark"] { --pico-primary: #00a9ff; --pico-primary-hover: #33bbff; --pico-primary-focus: rgba(0, 169, 255, 0.25); --pico-background-color: #1a1b26; --pico-card-background-color: #24283b; --pico-card-border-color: #414868; --pico-code-color: #ff9e64; --pico-code-background-color: #2e3247; }
        body { padding: 1rem; background-color: var(--pico-background-color); max-width: 1000px; margin: auto; }
        header { text-align: center; margin: 2rem 0; }
        section { margin-bottom: 36px; }
        .theme-toggle { position: absolute; top: 1rem; right: 1rem; background: transparent; border: none; padding: 0.5rem; cursor: pointer; font-size: 1.25rem; line-height: 1; width: auto; height: auto; }
        table { --pico-table-border-color: var(--pico-card-border-color); }
        article, figure { border-color: var(--pico-card-border-color); }
        .clickable-code { cursor: pointer; text-decoration: underline; text-decoration-style: dotted; }
        .clickable-code:hover { color: var(--pico-primary); }
        .snackbar { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); padding: 0.75rem 1.25rem; border-radius: var(--pico-border-radius); background-color: var(--pico-primary); color: var(--pico-primary-inverse); box-shadow: var(--pico-box-shadow); z-index: 1000; font-size: 0.9em; }
        .snackbar.error { background-color: #d32f2f; color: white; }
        button[aria-busy='true'] { pointer-events: none; }
    </style>
</head>
<body>
    <main class="container" x-data="sitesManager" x-init="getSites">
        <button class="theme-toggle" @click="theme = (theme === 'light' ? 'dark' : 'light')" x-text="theme === 'light' ? '🌙' : '☀️'"></button>
        <header><h1><img src="https://cove.run/content/15/uploads/2025/07/cropped-cove-1-192x192.webp" style="width: 38px;"> Cove</h1>
        <p>Local Development Powered by Caddy</p></header>
        
        <section>
            <h2>🚀 Quick Links</h2>
            <div class="grid">
                <a href="https://db.cove.localhost" target="_blank" rel="noopener noreferrer" role="button" class="secondary outline">🗃️ Manage Databases (Adminer)</a>
                <a href="https://mail.cove.localhost" target="_blank" rel="noopener noreferrer" role="button" class="secondary outline">✉️ Inspect Emails (Mailpit)</a>
            </div>
        </section>

        <section>
            <h2>✨ Add New Site</h2>
            <article>
                <form @submit.prevent="addSite">
                    <div class="grid">
                        <label>Site Name
                            <input type="text" name="site_name" required x-model="newSite.name" @input="newSite.name = newSite.name.toLowerCase().replace(/[^a-z0-9-]/g, '')" :disabled="newSite.isLoading">
                            <small>This will create <code x-text="newSite.name ? newSite.name + '.localhost' : '.localhost'"></code></small>
                        </label>
                        <label><input type="checkbox" name="is_plain" x-model="newSite.isPlain" :disabled="newSite.isLoading">Plain Site</label>
                    </div>
                    <button type="submit" :aria-busy="newSite.isLoading" x-text="newSite.isLoading ? 'Creating...' : 'Create Site'"></button>
                </form>
            </article>
        </section>

        <section>
            <h2>🗂️ Managed Sites</h2>
            <figure>
                <table role="grid">
                    <thead><tr><th scope="col">Site Domain</th><th scope="col">Type</th><th scope="col">Path</th><th scope="col"></th></tr></thead>
                    <tbody>
                        <template x-for="site in sites" :key="site.name">
                            <tr>
                                <td><a :href="site.domain" target="_blank" rel="noopener noreferrer" x-text="'🔗 ' + site.domain.replace('https://', '')"></a></td>
                                <td x-text="site.type"></td>
                                <td>
                                    <div @click="$store.snackbar.show('✅ Path copied!'); navigator.clipboard.writeText(site.full_path)" style="cursor: pointer;display:inline-flex;" title="Click to copy path">
                                        <small><code class="clickable-code" x-text="site.display_path"></code></small>
                                    </div>
                                </td>
                                <td style="width: 140px;">
                                    <div style="display: flex; justify-content: flex-end; gap: 0.5rem; align-items: center;">
                                        <template x-if="site.type === 'WordPress'">
                                            <button @click="getLoginLink(site.name)" :aria-busy="site.isLoggingIn" style="min-width: 85px; margin: 0;">Login</button>
                                        </template>
                                        <form @submit.prevent="deleteSite(site.name)" style="margin: 0;">
                                            <button type="submit" class="secondary outline" style="margin: 0;">🗑️</button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                        </template>
                        <tr x-show="sites.length === 0 && !isLoading">
                            <td colspan="4"><article>No sites found. Add one above!</article></td>
                        </tr>
                        <tr x-show="isLoading">
                            <td colspan="4"><progress></progress></td>
                        </tr>
                    </tbody>
                </table>
            </figure>
        </section>

        <section>
            <h2>⚙️ Cove Configuration</h2>
            <article>
                <p>These are the credentials Cove uses to create new WordPress databases.</p>
                <pre><code><strong>Database User:</strong> <?= htmlspecialchars($config_data['DB_USER'] ?? 'Not set') ?>&#x000A;<strong>Database Password:</strong> <?= htmlspecialchars($config_data['DB_PASSWORD'] ?? 'Not set') ?></code></pre>
                <p><small>Configuration stored in <code><?= htmlspecialchars($config_file) ?></code>.</small></p>
            </article>
        </section>
    </main>

    <div x-show="$store.snackbar.visible" x-transition class="snackbar" :class="{ 'error': $store.snackbar.isError }" style="display: none;">
        <span x-text="$store.snackbar.message"></span>
    </div>

    <script>
        document.addEventListener('alpine:init', () => {
            Alpine.data('sitesManager', () => ({
                sites: [],
                isLoading: true,
                newSite: { name: '', isPlain: false, isLoading: false },

                async apiCall(action, payload = {}) {
                    try {
                        const response = await fetch('api.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action, ...payload })
                        }).then(res => res.json());
                        if (!response.success) {
                            Alpine.store('snackbar').show(`❌ Error: ${response.message || 'Unknown error'}`, true);
                        }
                        return response;
                    } catch (e) {
                        Alpine.store('snackbar').show('❌ A network error occurred.', true);
                        return { success: false };
                    }
                },
                
                async getSites() {
                    this.isLoading = true;
                    try {
                        const r = await fetch('api.php?action=list_sites');
                        const siteData = await r.json();
                        this.sites = siteData.map(site => ({ ...site, isLoggingIn: false }));
                    } catch (e) {
                        Alpine.store('snackbar').show('❌ Could not fetch site list.', true);
                    } finally {
                        this.isLoading = false;
                    }
                },
                
                async addSite() {
                    this.newSite.isLoading = true;
                    const addResponse = await this.apiCall('add_site', { site_name: this.newSite.name, is_plain: this.newSite.isPlain });
                    if (addResponse.success) {
                        this.newSite.name = '';
                        Alpine.store('snackbar').show("✅ Site created. Initiating server reload...");
                        const reloadResponse = await this.apiCall('reload_server');
                        if (reloadResponse.success) {
                            Alpine.store('snackbar').show("✅ Reload initiated. List will refresh shortly.");
                            setTimeout(() => this.getSites(), 2000); // Refresh list after a delay
                        }
                    }
                    this.newSite.isLoading = false;
                },

                async deleteSite(siteName) {
                    if (!confirm(`Are you sure you want to permanently delete ${siteName}? This cannot be undone.`)) return;
                    const deleteResponse = await this.apiCall('delete_site', { site_name: siteName });
                    if (deleteResponse.success) {
                        Alpine.store('snackbar').show("✅ Site deleted. Initiating server reload...");
                        const reloadResponse = await this.apiCall('reload_server');
                        if (reloadResponse.success) {
                            Alpine.store('snackbar').show("✅ Reload initiated. List will refresh shortly.");
                            setTimeout(() => this.getSites(), 2000); // Refresh list after a delay
                        }
                    }
                },

                async getLoginLink(siteName) {
                    const site = this.sites.find(s => s.name === siteName);
                    if (!site) return;
                    site.isLoggingIn = true;
                    const response = await this.apiCall('get_login_link', { site_name: siteName });
                    if (response.success && response.url) {
                        window.open(response.url, '_blank');
                        Alpine.store('snackbar').show('✅ Login link opened in a new tab.');
                    }
                    // apiCall already shows an error snackbar on failure
                    site.isLoggingIn = false;
                }
            }));
            Alpine.store('snackbar', {
                visible: false, message: '', isError: false,
                show(message, isError = false) { this.message = message; this.isError = isError; this.visible = true; setTimeout(() => this.visible = false, 4000); }
            });
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
            echo "Powered by localhost.run - no downloads or signups required, just SSH."
            echo ""
            echo "Arguments:"
            echo "  [site]    The site name (optional). If omitted, prompts for selection."
            echo ""
            echo "Examples:"
            echo "  cove share           Interactive site selection"
            echo "  cove share mysite    Share mysite.localhost publicly"
            echo ""
            echo "You'll receive a random URL like https://abc123.localhost.run"
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
        
        # Use a variable for the WP-CLI command with increased memory limit
        # get_wp_cmd adds --allow-root if running as root (common in WSL/Docker)
        local wp_cmd="php -d memory_limit=512M $(get_wp_cmd)"

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
PHP
            
            # 3. Install WordPress
            $wp_cmd core install --url="https://$full_hostname" --title="Welcome to $site_name" --admin_user="$admin_user" --admin_password="$admin_pass" --admin_email="admin@$full_hostname" --skip-email

            # 4. Delete default plugins
            echo "   - Deleting default plugins (Hello Dolly, Akismet)..."
            $wp_cmd plugin delete hello akismet --quiet
        )

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
    fi

    sleep 0.25
    echo "✅ Site '$full_hostname' created successfully!"
    
    if [ "$site_type" == "wordpress" ]; then
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "✅ WordPress Installed" "URL: https://$full_hostname/wp-admin" "User: $admin_user" "Pass: $admin_pass" "One-time login URL: $one_time_login_url"
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
                
                local backup_file="../private/database-backup.sql"
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
    local php_output
    php_output=$(DB_USER="$DB_USER" DB_PASSWORD="$DB_PASSWORD" SITES_DIR="$SITES_DIR" WP_ROOT_FLAG="$wp_root_flag" php -r '
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
                
                $name_raw = shell_exec("cd " . $public_dir_esc . " && wp config get DB_NAME" . $cmd_suffix);
                if (is_null($name_raw)) { continue; }
                $site_db_name = trim($name_raw);
                if (empty($site_db_name)) { continue; }

                $site_db_user = "N/A";
                $site_db_pass = "N/A";
                $size_str = "N/A";

                if (!str_contains(strtolower($site_db_name), "sqlite")) {
                    $user_raw = shell_exec("cd " . $public_dir_esc . " && wp config get DB_USER" . $cmd_suffix);
                    if (!is_null($user_raw)) { $site_db_user = trim($user_raw); }

                    $pass_raw = shell_exec("cd " . $public_dir_esc . " && wp config get DB_PASSWORD" . $cmd_suffix);
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
    $SUDO_CMD "$CADDY_CMD" stop --config "$CADDYFILE_PATH" &>/dev/null
    
    # Stop services on MacOS
    if [ "$OS" == "macos" ]; then
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
    
    echo "   - Starting Caddy/FrankenPHP..."
    $SUDO_CMD "$CADDY_CMD" stop --config "$CADDYFILE_PATH" &> /dev/null
    $SUDO_CMD "$CADDY_CMD" start --config "$CADDYFILE_PATH" --pidfile "$COVE_DIR/caddy.pid" >> "$LOGS_DIR/caddy-process.log" 2>&1

    if [ $? -eq 0 ]; then
        echo ""
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 \
            "✅ Services are running" \
            "Dashboard: https://cove.localhost" \
            "Adminer:   https://db.cove.localhost" \
            "Mailpit:   https://mail.cove.localhost"
        
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
        # Special case: some commands don't support --version
        if [[ "$cmd_name" == "mariadb" ]] || "$cmd_name" --version &>/dev/null 2>&1; then
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

# Install PHP with required extensions for WordPress development
install_php_with_extensions() {
    echo "📦 Installing PHP with required extensions..."
    
    if [ "$OS" == "macos" ]; then
        # macOS: PHP from Homebrew includes most extensions
        if ! command -v php &>/dev/null; then
            brew install php
        fi
        echo "✅ PHP installed via Homebrew."
        return 0
    fi
    
    # Linux: Need to install PHP and extensions separately
    local php_packages=""
    
    if [ "$PKG_MANAGER" == "apt" ]; then
        # Note: php-mysql is a metapackage, php-mysqli is the actual extension
        php_packages="php php-cli php-fpm php-mysql php-mysqli php-xml php-mbstring php-curl php-gd php-zip php-intl php-bcmath php-soap"
        echo "   - Updating package cache..."
        $SUDO_CMD apt-get update -qq
        echo "   - Installing PHP and extensions..."
        # Show output so we can see what's happening
        if $SUDO_CMD apt-get install -y $php_packages; then
            echo "✅ PHP and extensions installed successfully."
        else
            echo "⚠️  Some PHP packages may have failed. Trying individual packages..."
            # Try installing core packages individually
            for pkg in php php-cli php-mysql php-mysqli php-xml php-mbstring php-curl; do
                $SUDO_CMD apt-get install -y "$pkg" 2>/dev/null || true
            done
        fi
    else
        # Fedora/RHEL - package names differ slightly
        php_packages="php php-cli php-fpm php-mysqlnd php-xml php-mbstring php-curl php-gd php-zip php-intl php-bcmath php-soap"
        echo "   - Installing PHP and extensions..."
        if $SUDO_CMD dnf install -y $php_packages; then
            echo "✅ PHP and extensions installed successfully."
        else
            echo "⚠️  Some PHP packages may have failed. Trying individual packages..."
            for pkg in php php-cli php-mysqlnd php-xml php-mbstring php-curl; do
                $SUDO_CMD dnf install -y "$pkg" 2>/dev/null || true
            done
        fi
    fi
    
    # Verify mysqli extension is available
    echo "   - Verifying PHP mysqli extension..."
    if php -m 2>/dev/null | grep -qi mysqli; then
        echo "✅ PHP mysqli extension is available."
    else
        echo ""
        gum style --foreground red "⚠️  WARNING: PHP mysqli extension not found!"
        echo "   WordPress and Adminer require mysqli to connect to MySQL/MariaDB."
        echo ""
        echo "   Try installing it manually:"
        if [ "$PKG_MANAGER" == "apt" ]; then
            echo "     sudo apt-get install php-mysqli"
        else
            echo "     sudo dnf install php-mysqlnd"
        fi
        echo ""
    fi
    
    return 0
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

    # Check for services using standard web ports
    # Use ss as fallback if lsof is not available (common on minimal Linux installs)
    local port_check_cmd=""
    if command -v lsof &>/dev/null; then
        port_check_cmd="lsof"
    elif command -v ss &>/dev/null; then
        port_check_cmd="ss"
    fi
    
    if [ -n "$port_check_cmd" ]; then
        local ports_in_use=false
        local listening_app=""
        
        if [ "$port_check_cmd" == "lsof" ]; then
            if lsof -i :80 -i :443 2>/dev/null | grep -q 'LISTEN'; then
                ports_in_use=true
                listening_app=$(lsof -i :80 -i :443 2>/dev/null | grep 'LISTEN' | awk '{print $1}' | sort -u | tr '\n' ' ' | sed 's/ $//')
            fi
        else
            # Use ss for port checking
            if ss -tlnp 2>/dev/null | grep -qE ':80\s|:443\s'; then
                ports_in_use=true
                listening_app=$(ss -tlnp 2>/dev/null | grep -E ':80\s|:443\s' | sed 's/.*users:(("\([^"]*\)".*/\1/' | sort -u | tr '\n' ' ')
            fi
        fi
        
        if [ "$ports_in_use" = true ]; then
            if [[ "$listening_app" != *"$CADDY_CMD"* && "$listening_app" != *"frankenph"* ]]; then
                echo "⚠️  Warning: A conflicting web server ('${listening_app}') may be running!"
                echo "Cove needs ports 80/443 to function."
                read -p "Do you want to proceed with the installation anyway? (y/N) " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    echo "🚫 Installation cancelled."
                    exit 0
                fi
            fi
        fi
    fi
    
    # --- Dependency Installation ---
    # Gum - Terminal UI library (needed first for nice prompts)
    # Note: gum releases use format: gum_VERSION_Linux_x86_64.tar.gz
    local gum_arch="x86_64"
    if [ "$(uname -m)" == "aarch64" ] || [ "$(uname -m)" == "arm64" ]; then
        gum_arch="arm64"
    fi
    local gum_url="https://github.com/charmbracelet/gum/releases/download/v0.14.1/gum_0.14.1_Linux_${gum_arch}.tar.gz"
    install_dependency "gum" "gum" "gum" "gum" "$gum_url"

    # --- Pre-install Checks ---
    if [ -d "$COVE_DIR" ]; then
        if ! gum confirm "⚠️ The Cove directory (~/Cove) already exists. Proceeding may overwrite some configurations. Continue?"; then
            echo "🚫 Installation cancelled."
            exit 0
        fi
    fi
    
    # FrankenPHP uses its own universal installer
    if ! command -v frankenphp &> /dev/null; then
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "Installing Dependency: frankenphp"
        echo "   - Using the official FrankenPHP installer..."
        if curl -sL https://frankenphp.dev/install.sh | $SUDO_CMD bash; then
             echo "✅ FrankenPHP installed successfully."
        else
            gum style --foreground red "❌ The FrankenPHP download script failed."
            exit 1
        fi
    else
        echo "✅ FrankenPHP is already installed."
    fi

    # MariaDB - Database server
    install_dependency "mariadb" "mariadb" "mariadb-server" "mariadb-server" ""
    
    # PHP with extensions (uses dedicated function for Linux)
    if [ "$OS" == "macos" ]; then
        install_dependency "php" "php" "" "" ""
    else
        install_php_with_extensions
    fi

    # Mailpit - Email testing tool (uses its own universal installer)
    if ! command -v mailpit &> /dev/null; then
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
            echo "DB_USER='$db_user'" > "$CONFIG_FILE"
            echo "DB_PASSWORD='$db_pass'" >> "$CONFIG_FILE"
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
    
    # Show post-install guidance
    echo ""
    gum style --border normal --margin "1" --padding "1 2" --border-foreground "yellow" \
        "📋 First-Time Setup Notes"
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
        "Local URL: https://${site_name}.localhost" \
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
    php_output=$(SITES_DIR="$SITES_DIR" SHOW_TOTALS="$show_totals" php -r '
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
                    "domain" => "https://" . $item,
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
    
    # --- 2. Validate Remote Site ---
    log_step "Validating remote WordPress site..."
    local remote_url
    remote_url=$(ssh $ssh_opts $remote_ssh "cd $remote_path && wp option get home 2>/dev/null")
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
    local_url="https://$site_name.localhost"

    # --- 4. Perform Migration ---
    log_step "Generating backup for ${remote_url}..."
    local backup_extra_args=""
    if [ "$proxy_uploads" = true ]; then
        log_success "Uploads will be excluded from the backup and proxied instead."
        backup_extra_args="--exclude=\"wp-content/uploads\""
    fi

    local backup_url
    backup_url=$(ssh $ssh_opts $remote_ssh "curl -sL https://captaincore.io/do | bash -s -- backup $remote_path --quiet $backup_extra_args")

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
    ssh $ssh_opts $remote_ssh "rm -f $remote_path/${filename}" 2>/dev/null
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
    
    # --- 3. Validate Remote Site ---
    log_step "Validating remote WordPress site..."
    local remote_url
    remote_url=$(ssh $ssh_opts $remote_ssh "cd $remote_path && wp option get home 2>/dev/null")
    
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

    # --- 6. Upload Backup ---
    log_step "Uploading backup to remote server..."
    if ! cat "$backup_filename" | ssh $ssh_opts $remote_ssh "cat > '$remote_path/$backup_filename'"; then
        # Clean up local backup on failure
        rm -f "$backup_filename"
        log_error "Failed to upload backup."
    fi
    log_success "Upload complete."

    # --- 7. Remote Restore ---
    log_step "Restoring backup on remote server..."
    if ! ssh $ssh_opts $remote_ssh "cd '$remote_path' && curl -sL https://captaincore.io/do | bash -s -- migrate --url='$backup_filename' --update-urls"; then
        log_error "The remote migration script failed to execute correctly."
    fi
    log_success "Remote restore complete."

    # --- 8. Cleanup ---
    log_step "Cleaning up backup files..."
    rm -f "$backup_filename"
    ssh $ssh_opts $remote_ssh "rm -f '$remote_path/$backup_filename'"
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
        local temp_sql_dump="/tmp/${old_db_name}.sql"

        echo "   - Backing up old database '$old_db_name'..."
        if ! mysqldump -u "$DB_USER" -p"$DB_PASSWORD" "$old_db_name" > "$temp_sql_dump"; then
            gum style --foreground red "❌ Error: Failed to dump the old database. Aborting."
            mv "$new_site_dir" "$old_site_dir" # Revert directory rename
            exit 1
        fi

        echo "   - Creating and importing to new database '$new_db_name'..."
        mysql -u "$DB_USER" -p"$DB_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS \`$new_db_name\`;"
        mysql -u "$DB_USER" -p"$DB_PASSWORD" "$new_db_name" < "$temp_sql_dump"
        rm "$temp_sql_dump"

        echo "   - Updating wp-config.php..."
        (cd "$new_site_dir/public" && $wp_cmd config set DB_NAME "$new_db_name" --quiet)

        echo "   - Running search-replace for site URL..."
        (cd "$new_site_dir/public" && $wp_cmd search-replace "https://$old_name.localhost" "https://$new_name.localhost" --all-tables --skip-plugins --skip-themes --quiet)

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

    gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "✅ Site renamed successfully!" "New URL: https://$new_name.localhost"
}
# --- Share Command ---
# Creates a temporary public tunnel to share a local site via localhost.run
# No downloads, no signups - just SSH

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
    
    # --- 2. Check for SSH ---
    if ! command -v ssh &> /dev/null; then
        gum style --foreground red "Error: SSH client not found. Please install OpenSSH."
        exit 1
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
    local ssh_output
    ssh_output=$(mktemp)
    local public_url_file
    public_url_file=$(mktemp)
    
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
        if [ -n "$ssh_pid" ]; then
            kill $ssh_pid 2>/dev/null
            wait $ssh_pid 2>/dev/null
        fi
        rm -f "$ssh_output" "$public_url_file"
        echo "Done."
    }
    trap cleanup EXIT
    
    # --- 6. Display initial message ---
    echo ""
    gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 \
        "Starting public tunnel for ${site_name}" \
        "" \
        "Local: https://${local_hostname}" \
        "" \
        "Press Ctrl+C to stop sharing."
    echo ""
    
    echo "Connecting to localhost.run..."
    
    # --- 7. Start SSH to get the public URL first ---
    ssh -o StrictHostKeyChecking=accept-new \
        -o ServerAliveInterval=30 \
        -o ServerAliveCountMax=3 \
        -R 80:localhost:${SHARE_PROXY_PORT} \
        nokey@localhost.run > "$ssh_output" 2>&1 &
    ssh_pid=$!
    
    # Wait for the URL to appear in the output
    local public_url=""
    local attempts=0
    local max_attempts=30
    
    while [ -z "$public_url" ] && [ $attempts -lt $max_attempts ]; do
        sleep 1
        ((attempts++))
        
        if ! kill -0 $ssh_pid 2>/dev/null; then
            gum style --foreground red "Error: SSH connection failed."
            cat "$ssh_output"
            exit 1
        fi
        
        public_url=$(grep -oE 'https://[a-z0-9]+\.lhr\.life' "$ssh_output" 2>/dev/null | head -1)
    done
    
    if [ -z "$public_url" ]; then
        gum style --foreground red "Error: Could not get public URL from localhost.run"
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
    
    $python_cmd - "$local_hostname" "$SHARE_PROXY_PORT" "$public_host" << 'PYTHON_PROXY' &
import sys
import ssl
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen

TARGET_HOST = sys.argv[1]  # e.g., anchordev.localhost
LISTEN_PORT = int(sys.argv[2])
PUBLIC_HOST = sys.argv[3]  # e.g., abc123.lhr.life

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
        # Get client IP from X-Forwarded-For header (set by localhost.run)
        client_ip = self.headers.get('X-Forwarded-For', self.client_address[0])
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
        target_url = f"https://{TARGET_HOST}{self.path}"
        
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else None
        
        req = Request(target_url, data=body, method=self.command)
        
        for key, value in self.headers.items():
            if key.lower() not in ('host', 'connection', 'accept-encoding'):
                req.add_header(key, value)
        req.add_header('Host', TARGET_HOST)
        
        try:
            with urlopen(req, context=ssl_ctx, timeout=60) as response:
                response_body = response.read()
                content_type = response.headers.get('Content-Type', '')
                
                # Rewrite URLs in text responses
                if any(ct in content_type for ct in REWRITABLE_TYPES):
                    try:
                        text = response_body.decode('utf-8')
                        # Replace https://site.localhost with https://public-url
                        text = text.replace(f'https://{TARGET_HOST}', f'https://{PUBLIC_HOST}')
                        # Also replace http:// version just in case
                        text = text.replace(f'http://{TARGET_HOST}', f'https://{PUBLIC_HOST}')
                        # Replace escaped versions (for JSON)
                        text = text.replace(f'https:\\/\\/{TARGET_HOST}', f'https:\\/\\/{PUBLIC_HOST}')
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

server = HTTPServer(('127.0.0.1', LISTEN_PORT), ProxyHandler)
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
    
    # Monitor SSH connection - check every 5 seconds
    while kill -0 $ssh_pid 2>/dev/null; do
        sleep 5
    done
    
    # SSH process ended - check if it was unexpected
    if [ -z "$cleanup_triggered" ]; then
        echo ""
        gum style --foreground yellow "Connection to localhost.run lost. Reconnecting..."
        # Could add reconnection logic here in the future
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
            "Dashboard: https://cove.localhost" \
            "Adminer:   https://db.cove.localhost" \
            "Mailpit:   https://mail.cove.localhost"
        
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

upgrade_frankenphp_binary() {
    local target_bin_dir
    local frankenphp_path

    # First, try to find the path of the existing frankenphp command.
    frankenphp_path=$(command -v frankenphp)

    if [ -n "$frankenphp_path" ]; then
        # If found, use its directory as the installation target.
        target_bin_dir=$(dirname "$frankenphp_path")
        echo "   - Detected existing FrankenPHP in '$target_bin_dir'. Using this as the installation target."
    else
        # If not found, use the global BIN_DIR (set in setup_environment)
        echo "   - FrankenPHP not found in PATH. Using default bin directory: $BIN_DIR"
        target_bin_dir="$BIN_DIR"
    fi

    echo "   - Downloading the latest FrankenPHP binary..."
    if curl -sL https://frankenphp.dev/install.sh | $SUDO_CMD bash; then
        if [ -f "./frankenphp" ]; then
            echo "   - Moving 'frankenphp' to $target_bin_dir/..."
            if $SUDO_CMD mv ./frankenphp "$target_bin_dir/frankenphp"; then
                echo "   - ✅ FrankenPHP reinstalled successfully."
            else
                gum style --foreground red "❌ Failed to move frankenphp." \
                    "Please run this command manually from the directory you ran the installer:" \
                    "sudo mv ./frankenphp \"$target_bin_dir/frankenphp\""
                return 1
            fi
        else
            gum style --foreground red "❌ FrankenPHP download script failed to create the 'frankenphp' file."
            return 1
        fi
    else
        gum style --foreground red "❌ The FrankenPHP download script failed."
        return 1
    fi
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

    # Get local version
    local local_frankenphp_version
    local_frankenphp_version=$(frankenphp version | awk '{print $2}')
    if [ -z "$local_frankenphp_version" ]; then
        echo "   - ❌ Could not determine local FrankenPHP version. Skipping update check."
        return 1
    fi

    # Get latest version from GitHub redirect
    local latest_frankenphp_version
    latest_frankenphp_version=$(curl -sL -o /dev/null -w '%{url_effective}' https://github.com/php/frankenphp/releases/latest | sed 's/.*\/v//')

    if [ -z "$latest_frankenphp_version" ]; then
        echo "   - ❌ Could not determine the latest FrankenPHP version from GitHub. Skipping update check."
        return 1
    fi

    echo "   - Current FrankenPHP version:  $local_frankenphp_version"
    echo "   - Latest available version:    $latest_frankenphp_version"

    # Use PHP for robust version comparison
    local needs_upgrade
    needs_upgrade=$(LOCAL_V="$local_frankenphp_version" REMOTE_V="$latest_frankenphp_version" php -r '
        if (version_compare(getenv("LOCAL_V"), getenv("REMOTE_V"), "<")) {
            echo "true";
        } else {
            echo "false";
        }
    ')

    if [ "$needs_upgrade" == "true" ]; then
        echo "🚀 Upgrading FrankenPHP to version $latest_frankenphp_version..."
        upgrade_frankenphp_binary
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
    
    # Get current Adminer version from the file
    local current_adminer_version
    current_adminer_version=$(grep -oP "version\s*=\s*['\"]?\K[0-9]+\.[0-9]+\.[0-9]+" "$adminer_file" 2>/dev/null | head -1)
    if [ -z "$current_adminer_version" ]; then
        # Try alternative pattern
        current_adminer_version=$(grep -oP "Adminer\s+\K[0-9]+\.[0-9]+\.[0-9]+" "$adminer_file" 2>/dev/null | head -1)
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
        adminer_needs_upgrade=$(LOCAL_V="$current_adminer_version" REMOTE_V="$latest_adminer_version" php -r '
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
    echo "https://${site_name}.localhost"
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
