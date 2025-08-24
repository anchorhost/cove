#!/bin/bash

# ====================================================
#  Cove - Main Script
#  Contains global configurations, helper functions,
#  and the main command routing logic.
# ====================================================

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
COVE_VERSION="1.3"
CADDY_CMD="frankenphp"

# Set the correct binary installation directory based on architecture
BIN_DIR="/usr/local/bin" # Default for Intel
if [ "$(uname -m)" = "arm64" ]; then
    BIN_DIR="/opt/homebrew/bin" # Override for Apple Silicon
fi

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

// Using the built-in method from the API docs to silence non-fatal errors.
// We are silencing every level except for fatal errors across all files.
$whoops->silenceErrorsInPaths(
    '/.*/', // A regex that matches all file paths
    E_ALL & ~E_ERROR & ~E_PARSE & ~E_CORE_ERROR & ~E_COMPILE_ERROR & ~E_USER_ERROR
);

// The PrettyPageHandler will now only be triggered for fatal errors.
$whoops->pushHandler(new \Whoops\Handler\PrettyPageHandler);
$whoops->register();
EOM
}

# --- Helper Functions ---

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
    mailpit_path="$(brew --prefix mailpit)/bin/mailpit"

    # Write the static header of the Caddyfile
    cat > "$CADDYFILE_PATH" <<- EOM
{
    frankenphp {
        php_ini sendmail_path "$mailpit_path sendmail -t"
        php_ini log_errors On
        php_ini error_log "$LOGS_DIR/errors.log"
        php_ini auto_prepend_file "$APP_DIR/whoops_bootstrap.php"
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

    # Append blocks for each site dynamically
    if [ -d "$SITES_DIR" ]; then
        for site_path in "$SITES_DIR"/*; do
            if [ -d "$site_path" ]; then
                local site_name
                site_name=$(basename "$site_path")
                
                echo "$site_name {" >> "$CADDYFILE_PATH"
                
                echo "    root * \"$site_path/public\"" >> "$CADDYFILE_PATH"
                echo "    encode gzip" >> "$CADDYFILE_PATH"
                echo "    tls internal" >> "$CADDYFILE_PATH"
                
                echo "    log {" >> "$CADDYFILE_PATH"
                echo "        output file \"$site_path/logs/caddy.log\"" >> "$CADDYFILE_PATH"
                echo "    }" >> "$CADDYFILE_PATH"
                
                echo "    php_server" >> "$CADDYFILE_PATH"

                if [ ! -f "$site_path/public/wp-config.php" ]; then
                    echo "    file_server" >> "$CADDYFILE_PATH"
                fi
                
                local custom_conf_file="$CUSTOM_CADDY_DIR/$site_name"
                if [ -f "$custom_conf_file" ]; then
                    echo "" >> "$CADDYFILE_PATH"
                    sed 's/^/    /' "$custom_conf_file" >> "$CADDYFILE_PATH"
                    echo "" >> "$CADDYFILE_PATH"
                fi

                echo "}" >> "$CADDYFILE_PATH"
                echo "" >> "$CADDYFILE_PATH"
            fi
        done
    fi

    # Reload Caddy with the new configuration
    if "$CADDY_CMD" reload --config "$CADDYFILE_PATH" --address localhost:2019; then
        echo "✅ Caddy configuration reloaded."
    else
        gum style --foreground red "❌ Caddy configuration failed to reload. See error above."
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
                $public_path = $sitedir . '/' . $site_name . '.localhost/public';
                if (is_dir($public_path) && is_file($public_path . '/wp-config.php')) {
                    $get_admin_cmd = sprintf(
                        'cd %s && wp user list --role=administrator --field=user_login --format=json --skip-plugins --skip-themes 2>&1',
                        escapeshellarg($public_path)
                    );
                    $admin_output_raw = shell_exec($get_admin_cmd);
                    $admin_users = json_decode($admin_output_raw, true);

                    if (json_last_error() === JSON_ERROR_NONE && !empty($admin_users[0])) {
                        $admin_login = $admin_users[0]; // Corrected line
                        $login_link_cmd = sprintf(
                            'cd %s && wp user login %s --skip-plugins --skip-themes 2>&1',
                            escapeshellarg($public_path),
                            escapeshellarg($admin_login)
                        );
                        exec($login_link_cmd, $output, $return_code);
                        if ($return_code === 0) {
                            $response = ['success' => true, 'url' => trim(implode("\n", $output))];
                        } else {
                            $response = ['success' => false, 'message' => 'Failed to generate login link.', 'output' => implode("\n", $output)];
                        }
                    } else {
                        $response['message'] = 'Could not find an administrator user for this site.';
                    }
                } else {
                    $response['message'] = 'This is not a valid WordPress site.';
                }
            } else {
                $response['message'] = 'Site name not provided for login link.';
            }
            echo json_encode($response);
            exit; // Exit immediately after handling
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
                                <td style="text-align: right; width: 132px;">
                                    <div style="margin-bottom: 0; display: inline-block;">
                                        <template x-if="site.type === 'WordPress'">
                                            <button @click="getLoginLink(site.name)" :aria-busy="site.isLoggingIn" class="primary">Login</button>
                                        </template>
                                        <form @submit.prevent="deleteSite(site.name)" style="margin-bottom: 0; display: inline-block;">
                                            <button type="submit" class="secondary outline" style="margin-bottom: 0;">🗑️</button>
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
    echo "  directive        Add or remove custom Caddyfile rules for a site."
    echo "  db               Manage databases (e.g., 'cove db backup')."
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
        path)
            echo "Usage: cove path <name>"
            echo ""
            echo "Outputs the full path to the specified site's directory."
            echo ""
            echo "Arguments:"
            echo "  <name>         The name of the site."
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
        
        # Use a variable for the WP-CLI command to increase memory limit
        local wp_cmd="php -d memory_limit=512M $(command -v wp)"

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
        wp_content="$site_dir/public/wp-content"
        echo "Generating '$wp_content/mu-plugins/captaincore-helper.php'"
        mkdir -p "$wp_content/mu-plugins/"
        echo "$build_mu_plugin" > "$wp_content/mu-plugins/captaincore-helper.php"
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
                
                # Check if wp-cli can connect
                if ! wp core is-installed --skip-plugins --skip-themes &> /dev/null; then
                    echo "   ❌ Error: wp-cli cannot connect to the database for this site. Skipping."
                    return 1 # This exits the subshell, not the main script
                fi

                local db_name db_user db_pass
                db_name=$(wp config get DB_NAME --skip-plugins --skip-themes)
                db_user=$(wp config get DB_USER --skip-plugins --skip-themes)
                db_pass=$(wp config get DB_PASSWORD --skip-plugins --skip-themes)

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

    # This heredoc contains a PHP script to find, connect, and format the database list.
    local php_output
    php_output=$(DB_USER="$DB_USER" DB_PASSWORD="$DB_PASSWORD" SITES_DIR="$SITES_DIR" php -r '
        function formatSize(int $bytes): string {
            if ($bytes === 0) return "0 B";
            $units = ["B", "KB", "MB", "GB", "TB"];
            $i = floor(log($bytes, 1024));
            return round($bytes / (1024 ** $i), 2) . " " . $units[$i];
        }

        $sites_dir = getenv("SITES_DIR");
        $db_user = getenv("DB_USER");
        $db_pass = getenv("DB_PASSWORD");

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
                $cmd_suffix = " --skip-plugins --skip-themes --quiet 2>/dev/null";
                
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
        local db_name; db_name=$(echo "cove_$site_name" | tr -c '[:alnum:]_' '_')
        echo "🗄️ Deleting database: $db_name"
        mysql -u "$DB_USER" -p"$DB_PASSWORD" -e "DROP DATABASE IF EXISTS \`$db_name\`;"
    fi

    rm -rf "$site_dir"
    echo "✅ Directory deleted."
    echo "✅ Site '$site_name.localhost' has been removed."
}
cove_directive_add_or_update() {
    local site_name="$1"
    if [ -z "$site_name" ];
 then
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

    if [ -f "$custom_conf_file" ];
 then
        echo "📝 Editing custom Caddy directives for $site_hostname..."
    else
        echo "📝 Adding new custom Caddy directives for $site_hostname..."
    fi
    echo "   Press Ctrl+D to save and exit, Ctrl+C to cancel."
 local existing_rules=""
    if [ -f "$custom_conf_file" ];
 then
        existing_rules=$(cat "$custom_conf_file")
    fi
    
    local custom_rules
    custom_rules=$(gum write --value "$existing_rules" --placeholder "Enter custom Caddy directives here...")

    if [ -n "$custom_rules" ];
 then
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
    if [ -z "$site_name" ];
 then
        gum style --foreground red "❌ Error: Please provide a site name."
 echo "Usage: cove directive delete <name>"
        exit 1
    fi

    local site_hostname="${site_name}.localhost"
    local custom_conf_file="$CUSTOM_CADDY_DIR/$site_hostname"

    if [ -f "$custom_conf_file" ];
 then
        if gum confirm "🚨 Are you sure you want to delete the custom directives for '$site_hostname'?";
 then
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
    "$CADDY_CMD" stop --config "$CADDYFILE_PATH"
    brew services stop mariadb
    pkill -f mailpit &> /dev/null
    echo "✅ Services stopped."
}
cove_enable() {
    echo "🚀 Enabling Cove services..."
    brew services restart mariadb &> /dev/null

    # Stop any running Mailpit instance (from brew or manual) before starting our own.
    pkill -f mailpit &> /dev/null
    brew services stop mailpit &> /dev/null

    # Start Mailpit directly with a persistent database file.
    local mailpit_path
    mailpit_path="$(brew --prefix mailpit)/bin/mailpit"
    if [ -x "$mailpit_path" ]; then
        echo "   - Starting Mailpit with persistent storage..."
        # --- CORRECTED FLAG ---
        nohup "$mailpit_path" --database "$COVE_DIR/mailpit.db" > "$LOGS_DIR/mailpit.log" 2>&1 &

        # --- Verify Mailpit has started ---
        echo "   - Waiting for Mailpit to initialize..."
        local i=0
        while ! lsof -i :8025 -sTCP:LISTEN -t >/dev/null; do
            sleep 1
            i=$((i+1))
            if [ $i -ge 10 ]; then
                gum style --foreground red "❌ Mailpit failed to start within 10 seconds." \
                          "Check the log for errors: ~/Cove/Logs/mailpit.log"
                exit 1
            fi
        done
        echo "   - Mailpit started successfully."
    fi
    
    "$CADDY_CMD" stop --config "$CADDYFILE_PATH" &> /dev/null
    
    "$CADDY_CMD" start --config "$CADDYFILE_PATH" --pidfile "$COVE_DIR/caddy.pid"

    if [ $? -eq 0 ]; then
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "✅ Services are running" "Dashboard: https://cove.localhost" "Adminer:   https://db.cove.localhost" "Mailpit:   https://mail.cove.localhost"
    else
        gum style --foreground red "❌ Caddy server failed to start. Check for errors above, or try running 'cove reload'."
    fi
}
cove_install() {
    echo "🚀 Starting Cove installation..."

    # Check for services using standard web ports
    if lsof -i :80 -i :443 | grep -q 'LISTEN'; then
        local listening_app
        listening_app=$(lsof -i :80 -i :443 | grep 'LISTEN' | awk '{print $1}' | sort -u | tr '\n' ' ' | sed 's/ $//')

        # If the listening app is the one Cove uses, don't show a warning.
        if [[ "$listening_app" == "$CADDY_CMD" || "$listening_app" == "frankenph" ]]; then
            echo "✅ Detected that FrankenPHP is already running."
        else
            # Otherwise, show the original warning for other apps like Nginx.
            gum style --border normal --margin "1" --padding "1 2" --border-foreground "yellow" \
                "⚠️  Warning: A conflicting web server may be running!" \
                "" \
                "Cove has detected that another program ('${listening_app}') is already using" \
                "the standard web ports (80/443). Cove needs these ports to function." \
                "" \
                "To resolve this, you must stop the conflicting service before using Cove." \
                "For NGINX, you can often use 'sudo brew services stop nginx' or 'sudo nginx -s stop'."
            if ! gum confirm "Do you want to proceed with the installation anyway?"; then
                echo "🚫 Installation cancelled."
                exit 0
            fi
       fi
    fi

    if ! command -v gum &> /dev/null; then brew install gum; fi

    # --- Pre-install Checks ---
    if [ -d "$COVE_DIR" ]; then
        if ! gum confirm "⚠️ The Cove directory (~/Cove) already exists. Proceeding may overwrite some configurations. Continue?"; then
            echo "🚫 Installation cancelled."
            exit 0
        fi
    fi

    # --- Dependency Installation ---
    # Handle FrankenPHP separately as it's not in Homebrew core.
    if ! command -v frankenphp &> /dev/null; then
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "Installing Missing Dependency: frankenphp"
        echo "   Using the official installer (this may take a moment)..."
        
        if curl -sL https://frankenphp.dev/install.sh | sh; then
            if [ -f "./frankenphp" ]; then
                echo "   Moving 'frankenphp' to $BIN_DIR/..."
                if mv ./frankenphp "$BIN_DIR/frankenphp"; then
                    echo "✅ FrankenPHP installed successfully."
                else
                    gum style --foreground red "❌ Failed to move frankenphp." \
                        "Please run this command manually from the directory you ran the installer:" \
                        "mv ./frankenphp \"$BIN_DIR/frankenphp\""
                    exit 1
                fi
            else
                gum style --foreground red "❌ FrankenPHP download script failed to create the 'frankenphp' file."
                exit 1
            fi
        else
            gum style --foreground red "❌ The FrankenPHP download script failed."
            exit 1
        fi
    else
        echo "✅ FrankenPHP is already installed."
    fi

    local packages_to_install=()

    for pkg_cmd in mariadb mailpit "wp:wp-cli" gum; do
        local pkg=${pkg_cmd##*:}
        local cmd=${pkg_cmd%%:*}
        if ! brew list "$pkg" &> /dev/null; then
            packages_to_install+=("$pkg")
        fi
    done

    if [ ${#packages_to_install[@]} -gt 0 ]; then
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "Installing Missing Dependencies: ${packages_to_install[*]}"
        brew install "${packages_to_install[@]}"
        if [ $? -ne 0 ]; then
            gum style --foreground red "❌ Dependency installation failed. Please check Homebrew errors."
            exit 1
        fi
    else
        echo "✅ All dependencies are already installed."
    fi

    # --- Directory and Service Setup ---
    echo "📁 Creating Cove directory structure..."
    mkdir -p "$SITES_DIR" "$LOGS_DIR" "$GUI_DIR" "$ADMINER_DIR" "$CUSTOM_CADDY_DIR"
    echo "🗃️ Downloading Adminer 5.3.0..."
    curl -sL "https://github.com/vrana/adminer/releases/download/v5.3.0/adminer-5.3.0.php" -o "$ADMINER_DIR/adminer-core.php"
    echo "⚙️ Creating Adminer autologin..."
    # Create a custom index.php to handle autologin
    cat > "$ADMINER_DIR/index.php" << 'EOM'
<?php
// This is the custom entry point for Adminer with autologin.

function adminer_object() {
    // This class extends the namespaced Adminer class.
    class AdminerCoveLogin extends Adminer\Adminer {
        /**
         * Returns the friendly name of the server.
         * @return string
         */
        function name() {
            return 'Cove DB Manager';
        }

        /**
         * Returns a fixed key to enable the permanent login feature.
         * This signature must match the parent class exactly.
         * @return string
         */
        function permanentLogin($i = false) {
            return "cove-local-development-key";
        }

        /**
         * Reads credentials from the Cove config file.
         * @return array
         */
        function credentials() {
            $configFile = getenv('HOME') . '/Cove/config';
            if (file_exists($configFile)) {
                $config = parse_ini_file($configFile);
                $db_user = $config['DB_USER'] ?? null;
                $db_pass = $config['DB_PASSWORD'] ?? null;
                // Return server, username, and password
                return ['localhost', $db_user, $db_pass];
            }
            // Fallback if config is missing
            return ['localhost', null, null];
        }

        function loginForm() {
            $html = <<<HTML
        <table class="layout" style="display:none;">
        <tbody><tr><th>System</th><td><select name="auth[driver]"><option value="server" selected="">MySQL / MariaDB</option><option value="sqlite">SQLite</option><option value="pgsql">PostgreSQL</option><option value="oracle">Oracle (beta)</option><option value="mssql">MS SQL</option></select><script nonce="">qsl('select').onchange = function () { loginDriver(this); };</script>
        </td></tr><tr><th>Server</th><td><input name="auth[server]" value="" title="hostname[:port]" placeholder="localhost" autocapitalize="off">
        </td></tr><tr><th>Username</th><td><input name="auth[username]" id="username" autofocus="" value="" autocomplete="username" autocapitalize="off"><script nonce="">const authDriver = qs('#username').form['auth[driver]']; authDriver && authDriver.onchange();</script>

        </td></tr><tr><th>Password</th><td><input type="password" name="auth[password]" autocomplete="current-password">
        </td></tr><tr><th>Database</th><td><input name="auth[db]" value="" autocapitalize="off">
        </td></tr></tbody></table>
        <p><input type="submit" value="Login" class="">
        <label><input type="checkbox" name="auth[permanent]" value="1">Permanent login</label>
        </p>
        HTML;
            echo $html;
            return false;
        }

        /**
         * Bypasses the login form by always returning true.
         * @return bool
         */
        function login($login, $password) {
            return true;
        }

        /**
         * Optionally specifies a default database to connect to.
         * @return string
         */
        function database() {
            return '';
        }
    }

    return new AdminerCoveLogin();
}

// Include the original Adminer core file to run the application.
include "./adminer-core.php";
EOM

    echo "🎨 Injecting custom Adminer theme..."
    cat > "$ADMINER_DIR/adminer.css" << 'EOM'
/*!
 * Material Design for Adminer, version 1.1.4
 * https://github.com/arcs-/Adminer-Material-Theme
 */@import url(https://fonts.googleapis.com/css?family=Noto+Sans:400,700);body{display:flex;height:100vh;background:#FAFAFA;font-family:"Noto Sans",sans-serif;text-rendering:optimizeLegibility !important}*{outline-color:#1E88E5}::selection{background:#4ca0ea;color:#fff}::-moz-selection{background:#4ca0ea;color:#fff}::-webkit-scrollbar{width:9px;height:12px;background-color:#CCC}::-webkit-scrollbar-corner{background-color:#CCC}::-webkit-scrollbar-thumb{background-color:#263238}::-webkit-scrollbar-corner{background-color:#263238;width:8px;height:8px}.scrollable{overflow-x:visible}#lang{position:fixed;top:auto;bottom:0;z-index:3;padding:.8em 1em;width:245px;border-top:1px solid #ccc;background:#fff}#lang select{width:66%}#menu{position:fixed;top:0;z-index:2;display:flex;margin:0;padding:0;height:100%;background:#fff;box-shadow:0 85px 5px 0 rgba(0,0,0,0.14),0 85px 10px 0 rgba(0,0,0,0.12),0 85px 4px -1px rgba(0,0,0,0.2);flex-flow:column}#menu h1{position:fixed;right:54px;border-bottom:none;font-size:12px;background:transparent;padding:4px 0}#menu select{width:86%}#menu #logins{padding:10px 14px 0;height:100%}#menu #logins:before{content:'Saved Logins';display:block;font-size:1.2em;margin:40px 0 10px}#menu #logins a{display:inline-block;margin:4px 0;padding:6px 12px;height:36px;width:86%;border-radius:2px;color:#fff;background:#1E88E5;box-shadow:0 2px 2px 0 rgba(0,0,0,0.14),0 3px 1px -2px rgba(0,0,0,0.2),0 1px 5px 0 rgba(0,0,0,0.12);text-decoration:none;transition:all .2s;border-radius:2px;text-align:center;font-weight:bold;font-size:13px;line-height:30px}#menu #logins a:hover{background:#10538d}#menu.active{background:#1E88E5 !important;color:#fff !important;font-weight:auto}#menu .links a{display:inline-block;margin:4px 2px;padding:5px;width:42%;border-radius:2px;background:#fff;color:#1E88E5;text-align:center;text-transform:uppercase;font-weight:bold;font-size:13px;line-height:24px;transition:all .2s}#menu .links a:hover{background:#1E88E5;color:#fff;text-decoration:none;font-weight:auto}a #h1{color:#AFB3B5}.version{color:#AFB3B5}#tables{overflow-x:hidden !important;margin-bottom:47px;padding:9px 12px 0 6px;flex:1}#tables .select:hover{background:#1E88E5;color:#fff;text-decoration:none;font-weight:auto}#tables a{display:inline-block;overflow:hidden;padding:6px 0 6px 8px;width:175px;border-radius:2px;text-overflow:ellipsis;transition:all .2s;color:#000}#tables a:hover{background:#e4e5e6;color:#000;text-decoration:none}#tables a.select{position:relative;float:right;padding:5px;width:auto;border-radius:2px;background:#fff;color:#1E88E5;text-align:center;text-transform:uppercase;font-weight:bold;font-size:13px;line-height:18px}#content{display:flex;flex-direction:column;overflow-x:auto;margin:83px 0 0 19em;padding:17px 27px 100px;min-width:600px;width:100%}#content h2{position:fixed;top:0;z-index:1;margin-left:-28px;padding-top:0;padding-left:30px;width:100%;height:65px;background:#263238;color:#AFB3B5;line-height:104px}#breadcrumb{position:fixed;z-index:2;padding-top:10px;padding-left:20px;background:#263238;color:#263238}#breadcrumb a{color:#1E88E5;font-size:13px;line-height:18px;transition:all .2s}#breadcrumb a:hover{color:#10538d;text-decoration:none}#logout{position:fixed;top:21px;right:50px;z-index:2;margin:4px 2px;padding:5px;min-width:88px;outline:none;border:none;border-radius:2px;background:#1E88E5;box-shadow:0 1px 4px rgba(48,48,48,0.41),0 2px 3px rgba(0,0,0,0.26);color:#fff;text-align:center;text-transform:uppercase;font-weight:bold;font-size:13px;line-height:24px;transition:all .2s}#logout:hover{background:#10538d}select{margin:0;padding:3px;border:none;border:1px solid rgba(0,0,0,0.12);border-radius:2px;color:#666;background:#fff;cursor:pointer}a,a:link{color:#1E88E5;transition:all .2s}a:hover,a:link:hover{color:#10538d;text-decoration:none}input:not([type]),input[type=number],input[type=password],input[type=search],input[type=text]{padding:8px;border:1px solid rgba(0,0,0,0.12);border-radius:2px;font-size:15px}input[type=search]:first-child{box-shadow:0 2px 2px 0 rgba(0,0,0,0.14),0 3px 1px -2px rgba(0,0,0,0.2),0 1px 5px 0 rgba(0,0,0,0.12)}input[type=submit]{padding:0 16px;min-width:64px;height:36px;border:none;border-radius:2px;background:#1E88E5;box-shadow:0 2px 2px 0 rgba(0,0,0,0.14),0 3px 1px -2px rgba(0,0,0,0.2),0 1px 5px 0 rgba(0,0,0,0.12);color:#fff;text-transform:uppercase;font-size:14px;cursor:pointer;transition:all .2s}input[type=submit]:hover{background:#10538d}input[type=button][disabled],input[type=submit][disabled]{background:#AFB3B5 !important;color:#504c4a;cursor:no-drop}div input[name=delete],div input[name=drop],div input[name=truncate],input[value=Kill]{background:repeating-linear-gradient(-55deg, #1E88E5, #1E88E5 5px, #4ca0ea 5px, #4ca0ea 10px);transition:all .2s}div input[name=delete]:hover,div input[name=drop]:hover,div input[name=truncate]:hover,input[value=Kill]:hover{background:repeating-linear-gradient(-55deg, #10538d, #10538d 5px, #1E88E5 5px, #1E88E5 10px)}input[type=checkbox]{display:inline-block;padding-left:25px;height:20px;outline:0;background-image:url("data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+CjxzdmcKICAgeG1sbnM6ZGM9Imh0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvIgogICB4bWxuczpjYz0iaHR0cDovL2NyZWF0aXZlY29tbW9ucy5vcmcvbnMjIgogICB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiCiAgIHhtbG5zOnN2Zz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciCiAgIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIKICAgeG1sbnM6c29kaXBvZGk9Imh0dHA6Ly9zb2RpcG9kaS5zb3VyY2Vmb3JnZS5uZXQvRFREL3NvZGlwb2RpLTAuZHRkIgogICB4bWxuczppbmtzY2FwZT0iaHR0cDovL3d3dy5pbmtzY2FwZS5vcmcvbmFtZXNwYWNlcy9pbmtzY2FwZSIKICAgd2lkdGg9IjIwcHQiCiAgIGhlaWdodD0iNDBwdCIKICAgdmlld0JveD0iMCAwIDIwIDQwIgogICB2ZXJzaW9uPSIxLjEiCiAgIGlkPSJzdmcyIgogICBpbmtzY2FwZTp2ZXJzaW9uPSIwLjQ4LjUgcjEwMDQwIgogICBzb2RpcG9kaTpkb2NuYW1lPSJjaGVjay5zdmciPgogIDxtZXRhZGF0YQogICAgIGlkPSJtZXRhZGF0YTE5Ij4KICAgIDxyZGY6UkRGPgogICAgICA8Y2M6V29yawogICAgICAgICByZGY6YWJvdXQ9IiI+CiAgICAgICAgPGRjOmZvcm1hdD5pbWFnZS9zdmcreG1sPC9kYzpmb3JtYXQ+CiAgICAgICAgPGRjOnR5cGUKICAgICAgICAgICByZGY6cmVzb3VyY2U9Imh0dHA6Ly9wdXJsLm9yZy9kYy9kY21pdHlwZS9TdGlsbEltYWdlIiAvPgogICAgICA8L2NjOldvcms+CiAgICA8L3JkZjpSREY+CiAgPC9tZXRhZGF0YT4KICA8ZGVmcwogICAgIGlkPSJkZWZzMTciIC8+CiAgPHNvZGlwb2RpOm5hbWVkdmlldwogICAgIHBhZ2Vjb2xvcj0iI2ZmZmZmZiIKICAgICBib3JkZXJjb2xvcj0iIzY2NjY2NiIKICAgICBib3JkZXJvcGFjaXR5PSIxIgogICAgIG9iamVjdHRvbGVyYW5jZT0iMTAiCiAgICAgZ3JpZHRvbGVyYW5jZT0iMTAiCiAgICAgZ3VpZGV0b2xlcmFuY2U9IjEwIgogICAgIGlua3NjYXBlOnBhZ2VvcGFjaXR5PSIwIgogICAgIGlua3NjYXBlOnBhZ2VzaGFkb3c9IjIiCiAgICAgaW5rc2NhcGU6d2luZG93LXdpZHRoPSIxOTIwIgogICAgIGlua3NjYXBlOndpbmRvdy1oZWlnaHQ9IjEwMTciCiAgICAgaWQ9Im5hbWVkdmlldzE1IgogICAgIHNob3dncmlkPSJmYWxzZSIKICAgICBpbmtzY2FwZTp6b29tPSIxNiIKICAgICBpbmtzY2FwZTpjeD0iNDMuNzAyNjQ2IgogICAgIGlua3NjYXBlOmN5PSIzMS45NTE3ODMiCiAgICAgaW5rc2NhcGU6d2luZG93LXg9IjE5MTIiCiAgICAgaW5rc2NhcGU6d2luZG93LXk9Ii04IgogICAgIGlua3NjYXBlOndpbmRvdy1tYXhpbWl6ZWQ9IjEiCiAgICAgaW5rc2NhcGU6Y3VycmVudC1sYXllcj0ic3ZnMiIgLz4KICA8ZwogICAgIHN0eWxlPSJmaWxsOiMwMDAwMDAiCiAgICAgaWQ9ImczMDY4IgogICAgIHRyYW5zZm9ybT0ic2NhbGUoMC44LDAuOCkiPgogICAgPHBhdGgKICAgICAgIGlkPSJwYXRoMzA1OCIKICAgICAgIGQ9Ik0gMTksNSBWIDE5IEggNSBWIDUgSCAxOSBNIDE5LDMgSCA1IEMgMy45LDMgMywzLjkgMyw1IHYgMTQgYyAwLDEuMSAwLjksMiAyLDIgaCAxNCBjIDEuMSwwIDIsLTAuOSAyLC0yIFYgNSBDIDIxLDMuOSAyMC4xLDMgMTksMyB6IgogICAgICAgaW5rc2NhcGU6Y29ubmVjdG9yLWN1cnZhdHVyZT0iMCIgLz4KICAgIDxwYXRoCiAgICAgICBpZD0icGF0aDMwNjAiCiAgICAgICBkPSJNIDAsMCBIIDI0IFYgMjQgSCAwIHoiCiAgICAgICBpbmtzY2FwZTpjb25uZWN0b3ItY3VydmF0dXJlPSIwIgogICAgICAgc3R5bGU9ImZpbGw6bm9uZSIgLz4KICA8L2c+CiAgPGcKICAgICBzdHlsZT0iZmlsbDojMDAwMDAwIgogICAgIGlkPSJnMzA4NCIKICAgICB0cmFuc2Zvcm09Im1hdHJpeCgwLjgsMCwwLDAuOCwwLDIwKSI+CiAgICA8cGF0aAogICAgICAgaWQ9InBhdGgzMDc0IgogICAgICAgZD0iTSAwLDAgSCAyNCBWIDI0IEggMCB6IgogICAgICAgaW5rc2NhcGU6Y29ubmVjdG9yLWN1cnZhdHVyZT0iMCIKICAgICAgIHN0eWxlPSJmaWxsOm5vbmUiIC8+CiAgICA8cGF0aAogICAgICAgaWQ9InBhdGgzMDc2IgogICAgICAgZD0iTSAxOSwzIEggNSBDIDMuODksMyAzLDMuOSAzLDUgdiAxNCBjIDAsMS4xIDAuODksMiAyLDIgaCAxNCBjIDEuMTEsMCAyLC0wLjkgMiwtMiBWIDUgQyAyMSwzLjkgMjAuMTEsMyAxOSwzIHogTSAxMCwxNyA1LDEyIDYuNDEsMTAuNTkgMTAsMTQuMTcgMTcuNTksNi41OCAxOSw4IDEwLDE3IHoiCiAgICAgICBpbmtzY2FwZTpjb25uZWN0b3ItY3VydmF0dXJlPSIwIiAvPgogIDwvZz4KPC9zdmc+Cg==");background-position:0 0;background-size:20px;background-repeat:no-repeat;vertical-align:middle;font-size:20px;line-height:20px;cursor:pointer;-webkit-appearance:none;-webkit-user-select:none;user-select:none}input[type=checkbox]:checked{background-position:0 -20px}input[type=radio]{display:inline-block;padding-left:25px;height:20px;outline:0;background-image:url("data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+CjxzdmcKICAgeG1sbnM6ZGM9Imh0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvIgogICB4bWxuczpjYz0iaHR0cDovL2NyZWF0aXZlY29tbW9ucy5vcmcvbnMjIgogICB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiCiAgIHhtbG5zOnN2Zz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciCiAgIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIKICAgeG1sbnM6c29kaXBvZGk9Imh0dHA6Ly9zb2RpcG9kaS5zb3VyY2Vmb3JnZS5uZXQvRFREL3NvZGlwb2RpLTAuZHRkIgogICB4bWxuczppbmtzY2FwZT0iaHR0cDovL3d3dy5pbmtzY2FwZS5vcmcvbmFtZXNwYWNlcy9pbmtzY2FwZSIKICAgd2lkdGg9IjIwcHQiCiAgIGhlaWdodD0iNDBwdCIKICAgdmlld0JveD0iMCAwIDIwIDQwIgogICB2ZXJzaW9uPSIxLjEiCiAgIGlkPSJzdmcyIgogICBpbmtzY2FwZTp2ZXJzaW9uPSIwLjQ4LjUgcjEwMDQwIgogICBzb2RpcG9kaTpkb2NuYW1lPSJjaGVjay5zdmciPgogIDxtZXRhZGF0YQogICAgIGlkPSJtZXRhZGF0YTE5Ij4KICAgIDxyZGY6UkRGPgogICAgICA8Y2M6V29yawogICAgICAgICByZGY6YWJvdXQ9IiI+CiAgICAgICAgPGRjOmZvcm1hdD5pbWFnZS9zdmcreG1sPC9kYzpmb3JtYXQ+CiAgICAgICAgPGRjOnR5cGUKICAgICAgICAgICByZGY6cmVzb3VyY2U9Imh0dHA6Ly9wdXJsLm9yZy9kYy9kY21pdHlwZS9TdGlsbEltYWdlIiAvPgogICAgICAgIDxkYzp0aXRsZT48L2RjOnRpdGxlPgogICAgICA8L2NjOldvcms+CiAgICA8L3JkZjpSREY+CiAgPC9tZXRhZGF0YT4KICA8ZGVmcwogICAgIGlkPSJkZWZzMTciIC8+CiAgPHNvZGlwb2RpOm5hbWVkdmlldwogICAgIHBhZ2Vjb2xvcj0iI2ZmZmZmZiIKICAgICBib3JkZXJjb2xvcj0iIzY2NjY2NiIKICAgICBib3JkZXJvcGFjaXR5PSIxIgogICAgIG9iamVjdHRvbGVyYW5jZT0iMTAiCiAgICAgZ3JpZHRvbGVyYW5jZT0iMTAiCiAgICAgZ3VpZGV0b2xlcmFuY2U9IjEwIgogICAgIGlua3NjYXBlOnBhZ2VvcGFjaXR5PSIwIgogICAgIGlua3NjYXBlOnBhZ2VzaGFkb3c9IjIiCiAgICAgaW5rc2NhcGU6d2luZG93LXdpZHRoPSIxOTIwIgogICAgIGlua3NjYXBlOndpbmRvdy1oZWlnaHQ9IjEwMTciCiAgICAgaWQ9Im5hbWVkdmlldzE1IgogICAgIHNob3dncmlkPSJmYWxzZSIKICAgICBpbmtzY2FwZTp6b29tPSIyMi42Mjc0MTciCiAgICAgaW5rc2NhcGU6Y3g9IjguNzkxODMzNyIKICAgICBpbmtzY2FwZTpjeT0iMTEuODUxMjkzIgogICAgIGlua3NjYXBlOndpbmRvdy14PSItOCIKICAgICBpbmtzY2FwZTp3aW5kb3cteT0iLTgiCiAgICAgaW5rc2NhcGU6d2luZG93LW1heGltaXplZD0iMSIKICAgICBpbmtzY2FwZTpjdXJyZW50LWxheWVyPSJzdmcyIiAvPgogIDxnCiAgICAgaWQ9ImczMDE1IgogICAgIHRyYW5zZm9ybT0ic2NhbGUoMC44LDAuOCkiPgogICAgPHBhdGgKICAgICAgIGlkPSJwYXRoMzAwNSIKICAgICAgIGQ9Ik0gMTIsMiBDIDYuNDgsMiAyLDYuNDggMiwxMiAyLDE3LjUyIDYuNDgsMjIgMTIsMjIgMTcuNTIsMjIgMjIsMTcuNTIgMjIsMTIgMjIsNi40OCAxNy41MiwyIDEyLDIgeiBtIDAsMTggQyA3LjU4LDIwIDQsMTYuNDIgNCwxMiA0LDcuNTggNy41OCw0IDEyLDQgYyA0LjQyLDAgOCwzLjU4IDgsOCAwLDQuNDIgLTMuNTgsOCAtOCw4IHoiCiAgICAgICBpbmtzY2FwZTpjb25uZWN0b3ItY3VydmF0dXJlPSIwIiAvPgogICAgPHBhdGgKICAgICAgIGlkPSJwYXRoMzAwNyIKICAgICAgIGQ9Ik0gMCwwIEggMjQgViAyNCBIIDAgeiIKICAgICAgIGlua3NjYXBlOmNvbm5lY3Rvci1jdXJ2YXR1cmU9IjAiCiAgICAgICBzdHlsZT0iZmlsbDpub25lIiAvPgogIDwvZz4KICA8ZwogICAgIGlkPSJnMzA0MiIKICAgICB0cmFuc2Zvcm09Im1hdHJpeCgwLjgsMCwwLDAuOCwwLDIwLjgpIj4KICAgIDxwYXRoCiAgICAgICBpZD0icGF0aDMwMzIiCiAgICAgICBkPSJtIDEyLDcgYyAtMi43NiwwIC01LDIuMjQgLTUsNSAwLDIuNzYgMi4yNCw1IDUsNSAyLjc2LDAgNSwtMi4yNCA1LC01IEMgMTcsOS4yNCAxNC43Niw3IDEyLDcgeiBNIDEyLDIgQyA2LjQ4LDIgMiw2LjQ4IDIsMTIgMiwxNy41MiA2LjQ4LDIyIDEyLDIyIDE3LjUyLDIyIDIyLDE3LjUyIDIyLDEyIDIyLDYuNDggMTcuNTIsMiAxMiwyIHogbSAwLDE4IEMgNy41OCwyMCA0LDE2LjQyIDQsMTIgNCw3LjU4IDcuNTgsNCAxMiw0IGMgNC40MiwwIDgsMy41OCA4LDggMCw0LjQyIC0zLjU4LDggLTgsOCB6IgogICAgICAgaW5rc2NhcGU6Y29ubmVjdG9yLWN1ydmF0dXJlPSIwIiAvPgogICAgPHBhdGgKICAgICAgIGlkPSJwYXRoMzAzNCIKICAgICAgIGQ9Ik0gMCwwIEggMjQgViAyNCBIIDAgeiIKICAgICAgIGlua3NjYXBlOmNvbm5lY3Rvci1jdXJ2YXR1cmU9IjAiCiAgICAgICBzdHlsZT0iZmlsbDpub25lIiAvPgogIDwvZz4KPC9zdmc+");background-position:0 0;background-size:20px;background-repeat:no-repeat;vertical-align:middle;font-size:20px;line-height:20px;cursor:pointer;-webkit-appearance:none;-webkit-user-select:none;user-select:none}input[type=radio]:checked{background-position:0 -21px}input[type=number]{padding:8px}#help{display:none}.sqlarea.jush-sql.jush{border:1px solid rgba(0,0,0,0.12) !important;background:#fff;box-shadow:0 2px 2px 0 rgba(0,0,0,0.14),0 3px 1px -2px rgba(0,0,0,0.2),0 1px 5px 0 rgba(0,0,0,0.12)}.js .column{left:-50px;margin:-6px 0 0;padding:5px 0 7px 3px;border:1px solid rgba(0,0,0,0.12);border-radius:3px;background:#fff;box-shadow:0 2px 2px 0 rgba(0,0,0,0.14),0 3px 1px -2px rgba(0,0,0,0.2),0 1px 5px 0 rgba(0,0,0,0.12)}.js .column a{padding:1px 8px 3px 5px;margin-right:3px;border-radius:2px;color:#1E88E5;transition:all .2s}.js .column a:hover{color:#fff;background:#1E88E5}table{margin-top:20px;min-width:800px;border-collapse:collapse;box-shadow:0 1px 4px rgba(88,88,88,0.01),0 2px 3px rgba(88,88,88,0.26);white-space:nowrap;font-size:13px;order:4}form table{width:100%}thead td,thead th{background:#ececec;position:sticky;top:0;z-index:2}thead td:before,thead th:before{content:'';position:absolute;background:#fafafa;top:-20px;left:-10px;width:120%;height:20px}thead td:after,thead th:after{content:'';position:absolute;left:0;bottom:0;width:100%;border-bottom:1px solid #cecece}thead th{padding:0 18px;text-align:left}th{box-sizing:border-box;padding:5px 18px !important;width:20%;border:1px solid #ececec;background:#fff;font-weight:normal;font-size:14px}td{box-sizing:border-box;padding:2px 10px 0;height:45px;border:1px solid #ececec;background:#fff;color:#000}.odd td,.odd th{background:#fafafa}td a,td a:visited,th a,th a:visited{color:#1E88E5;font-weight:700}.js .checkable .checked td,.js .checkable .checked th{background:#e0e0e0}#noindex,sup{display:none}.pages{position:absolute;padding:10px 20px 0;height:35px;border:1px solid rgba(0,0,0,0.12);background-color:#fff;box-shadow:0 2px 2px 0 rgba(0,0,0,0.14),0 3px 1px -2px rgba(0,0,0,0.2),0 1px 5px 0 rgba(0,0,0,0.12);font-size:15px}.pages a:not(:first-child){margin-top:5px;padding:5px;border:1px solid #1E88E5;border-radius:2px;color:#263238;text-align:center}.pages a:not(:first-child):hover{background:#1E88E5;color:#fff;text-decoration:none}.icon{width:24px;height:24px;border-radius:2px;background:#000;opacity:.8;-webkit-filter:contrast(125%) invert(1);filter:contrast(125%) invert(1);transition:all .2s}.icon:hover{background:#e1771a}.footer{background:none;border:none;border-color:transparent;position:relative}.footer>div{background:transparent}#content form{display:table;order:1}#content table:nth-of-type(1){order:1;margin:38px 0}#content .links,#content h3,#content h3+.error{margin:15px 0 0;order:4}#content .links:nth-of-type(2){margin-top:30px;order:1}#content .links a{display:inline-block;margin:4px;padding:6px 12px;min-width:88px;border-radius:2px;background:#fff;box-shadow:0 1px 4px rgba(88,88,88,0.41),0 2px 3px rgba(88,88,88,0.26);color:#1E88E5;text-align:center;text-transform:uppercase;font-weight:bold;font-size:13px;line-height:24px;transition:all .2s}#content .links a:hover{background:#1E88E5;color:#fff;text-decoration:none}#content .links .active{background:#1E88E5;color:#fff;cursor:default}#content form>fieldset:first-child{background-color:transparent;border:none;box-shadow:none;float:right;margin:0;padding:0;margin-bottom:4px;margin-top:-40px}#content form>fieldset:first-child legend{display:none}#content #form fieldset:nth-of-type(1){margin-bottom:10px;margin-top:0;padding-bottom:11px;min-height:57px;border:1px solid rgba(0,0,0,0.12);background-color:#fff;box-shadow:0 2px 2px 0 rgba(0,0,0,0.14),0 3px 1px -2px rgba(0,0,0,0.2),0 1px 5px 0 rgba(0,0,0,0.12);padding:.5em .8em;margin:.8em .5em 0 0;float:initial}#content #form fieldset:nth-of-type(1) legend{display:block}#content fieldset:nth-of-type(2).jsonly{float:right;margin-top:-30px;margin-right:8px;border:none}#content fieldset:nth-of-type(2).jsonly legend{display:none}#content fieldset:first-child #fieldset-import,#content fieldset:nth-of-type(1),#content fieldset:nth-of-type(2):not(.jsonly),#content fieldset:nth-of-type(3),#content fieldset:nth-of-type(4),#content fieldset:nth-of-type(5){margin-bottom:10px;padding-bottom:11px;min-height:57px;border:1px solid rgba(0,0,0,0.12);background-color:#fff;box-shadow:0 2px 2px 0 rgba(0,0,0,0.14),0 3px 1px -2px rgba(0,0,0,0.2),0 1px 5px 0 rgba(0,0,0,0.12)}#content fieldset:nth-of-type(6){border:none}#content fieldset:nth-of-type(6) legend{visibility:hidden}#content legend a{padding:5px;color:#1E88E5;font-weight:bold;font-size:13px;line-height:18px;transition:all .2s}#content legend a:hover{color:#10538d;text-decoration:none}#content fieldset:first-child #fieldset-import{margin-top:36px;padding:13px 10px 0 9px;margin-left:-12px}#content fieldset:first-child #fieldset-import:before{content:'Import';position:absolute;top:8px;left:20px;background:#fff;padding:0 7px}#content input[name=copy],#content input[name=move]{float:right;margin-right:-20px;margin-left:25px}#content input[name=copy],#content input[name=move]{float:right;margin-right:-20px;margin-left:25px}#content select{margin-bottom:2px;padding:8px}
EOM

    # Download and install Whoops into a clean directory
    echo "✨ Downloading Whoops error handler..."
    rm -rf "$APP_DIR/whoops" # Remove any old versions first
    mkdir -p "$APP_DIR/whoops"
    curl -sL "https://github.com/filp/whoops/archive/refs/tags/2.18.3.tar.gz" | tar -xz -C "$APP_DIR/whoops" --strip-components=1

    echo "⚙️ Starting services..."
    # Ensure the MariaDB service can be started before proceeding.
    if ! brew services restart mariadb; then
        gum style --foreground red "❌ Failed to start MariaDB via Homebrew." \
                  "Please run 'brew services start mariadb' manually and check for errors." \
                  "If the issue persists, try 'brew reinstall mariadb'."
        exit 1
    fi
    brew services restart mailpit

    # --- Database Configuration ---
    if [ -f "$CONFIG_FILE" ] && gum confirm "Existing Cove database config found. Use it and skip database setup?"; then
        echo "✅ Using existing database configuration."
    else
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "Configuring MariaDB"

        # Wait for MariaDB to be ready
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

        # First, attempt the automated, non-interactive setup
        echo "   - Attempting automatic setup..."
        if echo "$sql_command" | sudo mysql &> /dev/null; then
            echo "   - ✅ Automatic database user creation successful."
            user_created_successfully=true
        else
            # If the automated method fails, fall back to the interactive prompt
            echo "   - ⚠️ Automatic setup failed. This can happen on custom MariaDB installs."
            echo "   - Falling back to manual credential entry..."
            
            local root_user
            root_user=$(gum input --value "root" --prompt "MariaDB Root Username: ")
            local root_pass
            root_pass=$(gum input --password --placeholder "Password for '$root_user'")

            if echo "$sql_command" | mysql -u "$root_user" -p"$root_pass"; then
                echo "   - ✅ Manual database user creation successful."
                user_created_successfully=true
            fi
        fi

        # Final check: only proceed if one of the methods worked
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
}
cove_list() {
    local show_totals=false
    if [[ "$1" == "--totals" ]]; then
        show_totals=true
    fi

    # This heredoc contains a PHP script to find, sort, and format the site list.
    # The output is a single, pre-formatted text block.
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
                    "path" => "~/Cove/Sites/" . $item . "/public",
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

        $output = [];
        // Define column widths
        $name_width = 22;
        $domain_width = 40;
        $type_width = 11;
        $path_width = 52;
        $size_width = 15;

        // Manually build and pad the header
        $header = str_pad("Name", $name_width) . " " . str_pad("Domain", $domain_width) . " " . str_pad("Type", $type_width) . " " . str_pad("Path", $path_width);
        
        // Manually build the separator line
        $separator = str_repeat("-", $name_width) . " " . str_repeat("-", $domain_width) . " " . str_repeat("-", $type_width) . " " . str_repeat("-", $path_width);
        
        if ($show_totals) {
            $header    .= " " . str_pad("Size", $size_width);
            $separator .= " " . str_repeat("-", $size_width);
        }
        
        $output[] = $header;
        $output[] = $separator;

        // Build each data row with manual padding
        foreach ($sites as $site) {
            $name_col = str_pad($site["name"], $name_width);
            // Pad the URL first, then prepend the emoji to preserve alignment
            $domain_col = "🌐 " . str_pad($site["domain"], $domain_width - 3); // Subtract 3 for "🌐 "
            $type_col = str_pad($site["type"], $type_width);
            $path_col = str_pad($site["path"], $path_width - 3);
            $row = $name_col . " " . $domain_col . " " . $type_col . " " . $path_col;
            
            if ($show_totals) {
                $row .= " " . str_pad($site["size"] ?? "N/A", $size_width);
            }
            $output[] = $row;
        }

        // Print the entire formatted block
        echo implode("\n", $output);
    ')

    if [ -z "$php_output" ]; then
        # Display a message if no sites are found.
        gum style --padding "1 2" "ℹ️ No sites found. Add one with 'cove add <name>'."
    else
        # Pipe the pre-formatted text block into gum style to wrap it in a nice box.
        echo "$php_output" | gum style --border normal --margin "1" --padding "1 2" --border-foreground 212
    fi
}
#!/bin/bash

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

    # 2. Check if the site exists and is a WordPress installation.
    if [ ! -d "$site_dir" ] || [ ! -f "$public_dir/wp-config.php" ]; then
        gum style --foreground red "❌ Error: WordPress site '$site_name.localhost' not found."
        exit 1
    fi

    local admin_to_login

    if [ -n "$user_identifier" ]; then
        # A specific user was provided.
        echo "🔎 Verifying user '$user_identifier' for '$site_name.localhost'..."
        
        # Check if the specified user exists and has the 'administrator' role.
        local user_roles
        user_roles=$( (cd "$public_dir" && wp user get "$user_identifier" --field=roles --format=json --skip-plugins --skip-themes 2>/dev/null) )

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
        # No user was specified; fall back to finding the first admin.
        echo "🔎 Finding an administrator for '$site_name.localhost'..."
        admin_to_login=$( (cd "$public_dir" && wp user list --role=administrator --field=user_login --format=csv --skip-plugins --skip-themes | head -n 1) )

        if [ -z "$admin_to_login" ]; then
            gum style --foreground red "❌ Error: Could not find any administrator users for this site."
            exit 1
        fi
        echo "✅ Found admin: '$admin_to_login'."
    fi

    # 4. Generate the one-time login URL.
    echo "   Generating login link..."
    local login_url
    login_url=$( (cd "$public_dir" && wp user login "$admin_to_login" --skip-plugins --skip-themes) )

    # 5. Display the final URL in a styled box.
    if [ -n "$login_url" ]; then
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "🔗 One-Time Login URL for '$admin_to_login'" "$login_url"
    else
        gum style --foreground red "❌ Error: Failed to generate the login link."
        exit 1
    fi
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
        (cd "$new_site_dir/public" && wp config set DB_NAME "$new_db_name" --quiet)

        echo "   - Running search-replace for site URL..."
        (cd "$new_site_dir/public" && wp search-replace "https://$old_name.localhost" "https://$new_name.localhost" --all-tables --skip-plugins --skip-themes --quiet)

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
cove_status() {
    echo "🔎 Checking Cove service status..."

    local caddy_status="❌ Stopped"
    local mariadb_status="❌ Stopped"
    local mailpit_status="❌ Stopped"
    local all_running=false

    # Check Caddy status by looking for the PID file and checking if the process is running.
    if [ -f "$COVE_DIR/caddy.pid" ] && ps -p "$(cat "$COVE_DIR/caddy.pid")" > /dev/null; then
        caddy_status="✅ Running"
    fi

    # Check the status of Homebrew services.
    if brew services list | grep -q "mariadb.*started"; then
        mariadb_status="✅ Running"
    fi

    # Check for a running mailpit process directly.
    if pgrep -f mailpit > /dev/null; then
        mailpit_status="✅ Running"
    fi

    # Print the status of each individual service.
    echo "  - Caddy Server: $caddy_status"
    echo "  - MariaDB:      $mariadb_status"
    echo "  - Mailpit:      $mailpit_status"

    if [[ "$caddy_status" == "✅ Running" && "$mariadb_status" == "✅ Running" && "$mailpit_status" == "✅ Running" ]]; then
        all_running=true
    fi

    echo "" # Add a blank line for spacing.
    # Display the final summary message using gum.
    if $all_running; then
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "✅ Services are running" "Dashboard: https://cove.localhost" "Adminer:   https://db.cove.localhost" "Mailpit:   https://mail.cove.localhost"
    else
        gum style --border normal --margin "1" --padding "1 2" --border-foreground "yellow" "ℹ️ Some services are stopped." "Run 'cove enable' to start them."
    fi
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
    echo "   - Downloading latest version from GitHub..."
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
    echo "   - Current version:          $current_version"
    echo "   - Latest available version: $new_version"

    # 5. Compare versions
    local latest
    latest=$(printf '%s\n' "$current_version" "$new_version" | sort -V | tail -n1)

    if [[ "$latest" == "$current_version" ]] && [[ "$new_version" != "$current_version" ]]; then
         echo "✅ Your current version ($current_version) is newer than the latest release ($new_version). No action taken."
         rm -f "$temp_script" 2>/dev/null
         return 0
    elif [[ "$latest" == "$current_version" ]]; then
        echo "✅ You are already using the latest version of Cove."
        rm -f "$temp_script" 2>/dev/null
        return 0
    fi

    # 6. Perform the upgrade
    echo "🚀 Upgrading to version $new_version..."

    if [ ! -w "$(dirname "$install_path")" ]; then
        echo "❌ Error: No write permissions for '$(dirname "$install_path")'."
        echo "   Please try running with sudo: 'sudo cove upgrade'"
        rm -f "$temp_script" 2>/dev/null
        return 1
    fi

    if ! mv "$temp_script" "$install_path"; then
        echo "❌ Error: Failed to replace the old script at '$install_path'."
        rm -f "$temp_script" 2>/dev/null
        return 1
    else
        echo "✅ Cove has been successfully upgraded to version $new_version!"
        echo "   Run 'cove version' to see the new version."
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
#  Pass all script arguments to the main function.
main "$@"
