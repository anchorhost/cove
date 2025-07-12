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

PROTECTED_NAMES="cove mailpit adminer"
COVE_VERSION="1.0"

# --- Dynamic Command Configuration ---
# Detect if a manual frankenphp installation exists and prioritize it.
if [ -x "/usr/local/bin/frankenphp" ]; then
    CADDY_CMD="/usr/local/bin/frankenphp"
else
    CADDY_CMD="caddy"
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
    }
    order php_server before file_server
}

# --- Global Services ---

mailpit.localhost {
    reverse_proxy 127.0.0.1:8025
    tls internal
}

adminer.localhost {
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
    echo "🎨 Creating Cove dashboard file..."
    mkdir -p "$GUI_DIR"
    
    cat > "$GUI_DIR/index.php.tmp" << 'EOM'
<?php
$sitedir = 'SITES_DIR_PLACEHOLDER';
$config_file = getenv('HOME') . '/Cove/config';
$message = '';
$refresh_script = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $cove_path = 'COVE_EXECUTABLE_PATH';
    if (isset($_POST['add_site'])) {
        $site_name = trim($_POST['site_name']);
        $type_flag = isset($_POST['is_plain']) ? '--plain' : '';
        if (!empty($site_name) && preg_match('/^[a-zA-Z0-9-]+$/', $site_name)) {
            $command = sprintf('%s add %s %s > /dev/null 2>&1 &', escapeshellarg($cove_path), escapeshellarg($site_name), $type_flag);
            shell_exec($command);
            $message = "<p>✅ Site creation for '<strong>" . htmlspecialchars($site_name) . ".localhost</strong>' has been initiated.</p>";
            $refresh_script = '<script>setTimeout(() => window.location.reload(), 5000);</script>';
        } else {
            $message = "<p class='error'>Invalid site name. Use letters, numbers, and hyphens only.</p>";
        }
    } elseif (isset($_POST['delete_site'])) {
        $site_name = $_POST['site_name'];
        if (!empty($site_name)) {
            $command = sprintf('%s delete %s --force > /dev/null 2>&1 &', escapeshellarg($cove_path), escapeshellarg($site_name));
            shell_exec($command);
            $message = "<p>✅ Deletion for '<strong>" . htmlspecialchars($site_name) . ".localhost</strong>' has been initiated.</p>";
            $refresh_script = '<script>setTimeout(() => window.location.reload(), 2000);</script>';
        }
    }
}
$config_data = file_exists($config_file) ? parse_ini_file($config_file) : [];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cove Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css"/>
    <style>
        body { padding-bottom: 5rem; }
        .error { color: var(--pico-del-color); }
        pre { background-color: var(--pico-secondary-background); padding: 1em; border-radius: var(--pico-border-radius); white-space: pre-wrap; }
        .grid > article { margin-bottom: 0; }
        .delete-form { margin-bottom: 0; }
    </style>
</head>
<body>
    <main class="container">
        <header><h1>Cove Dashboard</h1><p>Manage your local development environment.</p></header>
        <?php if ($message): ?><article><footer><?= $message ?></footer></article><?php endif; ?>
        <section>
            <h2>Quick Links</h2>
            <div class="grid">
                <a href="http://adminer.localhost" role="button" class="outline">🗃️ Manage Databases (Adminer)</a>
                <a href="http://mailpit.localhost" role="button" class="outline">✉️ Inspect Emails (Mailpit)</a>
            </div>
        </section>
  
       <section>
            <h2>Add New Site</h2>
            <article><form method="POST"><div class="grid"><label for="site_name">Site Name<input type="text" id="site_name" name="site_name" placeholder="my-awesome-project" required><small>This will create <code>my-awesome-project.localhost</code></small></label><label for="is_plain"><input type="checkbox" id="is_plain" name="is_plain">Plain Site<small>Creates a static site without WordPress or a database.</small></label></div><button type="submit" name="add_site">Add Site</button></form></article>
        </section>
        <section>
            <h2>Managed Sites</h2>
           
             <?php $sites = file_exists($sitedir) ? scandir($sitedir) : []; if (count($sites) > 2): ?>
            <table><thead><tr><th>Site Domain</th><th>Type</th><th>Actions</th></tr></thead>
                <tbody>
                <?php foreach ($sites as $site): if ($site === '.' || $site === '..' || !is_dir($sitedir . '/' . $site)) continue; ?>
                    <tr>
                        <td><a href="https://<?= htmlspecialchars($site) ?>" target="_blank"><?= htmlspecialchars($site) ?></a></td>
                        <td><?= file_exists("$sitedir/$site/public/wp-config.php") ? 'WordPress' : 'Plain' ?></td>
                        <td><form method="POST" class="delete-form" onsubmit="return confirm('Are you sure you want to permanently delete <?= htmlspecialchars($site) ?>? This cannot be undone.');"><input type="hidden" name="site_name" value="<?= htmlspecialchars(str_replace('.localhost', '', $site)) ?>"><button type="submit" name="delete_site" class="secondary outline">Delete</button></form></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php 
            $site_directories = array_filter($sites, function($site) use ($sitedir) {
                return !in_array($site, ['.', '..']) && is_dir($sitedir . '/' . $site);
            });
            if (empty($site_directories)): ?>
            <p>No sites found. Add one above!</p>
            <?php endif; ?>
            <?php else: ?><p>No sites found. Add one above!</p><?php endif; ?>
        </section>
        <section>
            <h2>Cove Configuration</h2>
            <article>
                <p>These are the credentials Cove uses to create new WordPress databases.</p>
                <pre><strong>Database User:</strong> <?= htmlspecialchars($config_data['DB_USER'] ?? 'Not set') ?>&#x000A;<strong>Database Password:</strong> <?= htmlspecialchars($config_data['DB_PASSWORD'] ?? 'Not set') ?></pre>
                <small>Configuration stored in <code><?= htmlspecialchars($config_file) ?></code>.</small>
            </article>
        </section>
    </main>
    <?php if (!empty($refresh_script)) echo $refresh_script; ?>
</body>
</html>
EOM

    local script_dir
    script_dir=$(cd "$(dirname "$0")" && pwd)
    local absolute_script_path="$script_dir/$(basename "$0")"
    
    local escaped_path
    escaped_path=$(printf '%s\n' "$absolute_script_path" | sed -e 's/[\/&]/\\&/g')
    local escaped_sites_dir
    escaped_sites_dir=$(printf '%s\n' "$SITES_DIR" | sed -e 's/[\/&]/\\&/g')

    sed -e "s/COVE_EXECUTABLE_PATH/${escaped_path}/g" \
        -e "s/SITES_DIR_PLACEHOLDER/${escaped_sites_dir}/g" \
        "$GUI_DIR/index.php.tmp" > "$GUI_DIR/index.php"
    rm "$GUI_DIR/index.php.tmp"
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
    echo "  directive        Add or remove custom Caddyfile rules for a site."
    echo "  db               Manage databases (e.g., 'cove db backup')."
    echo "  reload           Regenerates the Caddyfile and reloads the Caddy server."
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
            echo "Usage: cove list"
            echo ""
            echo "Lists all sites currently managed by Cove, showing their domain and type (WordPress/Plain)."
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
        directive)
            echo "Usage: cove directive <command> <name>"
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
            echo "Usage: cove db backup"
            echo ""
            echo "Manage databases. 'backup' creates a .sql dump for each WP site."
            ;;
        reload)
            echo "Usage: cove reload"
            echo ""
            echo "Regenerates the Caddyfile and reloads the Caddy server gracefully."
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
        list)
            check_dependencies
            cove_list
            ;;
        install)
            cove_install
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

        # --- Refactored Commands with Sub-routing ---

        db)
            check_dependencies
            local action="$1"
            shift # Remove subcommand from argument list to pass the rest to the function
            case "$action" in
                backup)
                    cove_db_backup "$@"
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
    local site_name="$1"
    for protected_name in $PROTECTED_NAMES; do
        if [ "$site_name" == "$protected_name" ]; then
            gum style --foreground red "❌ Error: '$site_name' is a reserved name. Choose another."
            exit 1
        fi
    done

    local site_type="wordpress"
    if [ "$2" == "--plain" ]; then
        site_type="plain"
    fi

    local site_dir="$SITES_DIR/$site_name.localhost"
    # NEW: Define the full hostname from the site directory for consistency.
    local full_hostname
    full_hostname=$(basename "$site_dir")

    if [ -d "$site_dir" ]; then
        echo "⚠️ Site '$full_hostname' already exists."
        exit 1
    fi

    echo "➕ Creating $site_type site: $full_hostname"
    mkdir -p "$site_dir/public" "$site_dir/logs"

    # Define credential variables outside the if-statement to widen their scope
    local admin_user="admin"
    local admin_pass

    if [ "$site_type" == "wordpress" ]; then
        source_config
        local db_name
        db_name=$(echo "cove_$site_name" | tr -c '[:alnum:]_' '_')
        
        echo "🗄️ Creating database: $db_name"
        mysql -u "$DB_USER" -p"$DB_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS \`$db_name\`;"
        
        echo "Installing WordPress..."
        # Generate the random password and store it
        admin_pass=$(openssl rand -base64 12)
        
        ( cd "$site_dir/public" || exit
            wp core download --quiet
            wp config create --dbname="$db_name" --dbuser="$DB_USER" --dbpass="$DB_PASSWORD" --extra-php <<PHP
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
PHP
            # CORRECTED: Use the consistent hostname variable for the URL.
            wp core install --url="https://$full_hostname" --title="Welcome to $site_name" --admin_user="$admin_user" --admin_password="$admin_pass" --admin_email="admin@$full_hostname" --skip-email
        )
    fi

    regenerate_caddyfile
    echo "✅ Site '$full_hostname' created successfully!"

    # Display WordPress credentials only after everything else is done.
    if [ "$site_type" == "wordpress" ]; then
        # CORRECTED: Use the consistent hostname variable for the URL.
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "✅ WordPress Installed" "URL: https://$full_hostname/wp-admin" "User: $admin_user" "Pass: $admin_pass"
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
    regenerate_caddyfile
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
    brew services stop mailpit
    echo "✅ Services stopped."
}
cove_enable() {
    echo "🚀 Enabling Cove services..."
    brew services restart mariadb &> /dev/null
    brew services restart mailpit &> /dev/null
    
    "$CADDY_CMD" stop --config "$CADDYFILE_PATH" &> /dev/null
    
    "$CADDY_CMD" start --config "$CADDYFILE_PATH" --pidfile "$COVE_DIR/caddy.pid"

    if [ $? -eq 0 ]; then
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "✅ Services are running" "Dashboard: http://cove.localhost" "Mailpit:   http://mailpit.localhost" "Adminer:   http://adminer.localhost"
    else
        gum style --foreground red "❌ Caddy server failed to start. Check for errors above, or try running 'cove reload'."
    fi
}
cove_install() {
    echo "🚀 Starting Cove installation..."
    if ! command -v gum &> /dev/null; then brew install gum; fi

    # --- Pre-install Checks ---
    if [ -d "$COVE_DIR" ]; then
        if ! gum confirm "⚠️ The Cove directory (~/Cove) already exists. Proceeding may overwrite some configurations. Continue?"; then
            echo "🚫 Installation cancelled."
            exit 0
        fi
    fi

    # --- Dependency Installation ---
    local packages_to_install=()
    if [ "$CADDY_CMD" == "caddy" ] && ! command -v caddy &> /dev/null; then
        packages_to_install+=("caddy")
    else
        echo "ℹ️ Using existing Caddy/FrankenPHP installation."
    fi

    for pkg_cmd in mariadb mailpit "wp:wp-cli" gum; do
        local pkg=${pkg_cmd##*:}
        local cmd=${pkg_cmd%%:*}
        if ! command -v $cmd &> /dev/null; then
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
    curl -sL "https://github.com/vrana/adminer/releases/download/v5.3.0/adminer-5.3.0.php" -o "$COVE_DIR/adminer/index.php"
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
    brew services restart mariadb # Use restart to be safe
    brew services restart mailpit # Use restart to be safe

    # --- Database Configuration ---
    local skip_db_setup=false
    if [ -f "$CONFIG_FILE" ]; then
        if gum confirm "Existing Cove database config found. Use it and skip database setup?"; then
            skip_db_setup=true
            echo "✅ Using existing database configuration."
        else
            echo "🔥 Proceeding with database reconfiguration..."
        fi
    fi

    if ! $skip_db_setup; then
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "Configuring MariaDB"

        # Wait for MariaDB to be ready
        echo "Waiting for MariaDB..."
        i=0
        while ! mysqladmin pink --silent; do
            sleep 1; i=$((i+1))
            if [ $i -ge 20 ]; then
                gum style --foreground red "❌ MariaDB did not become available in time."
                exit 1
            fi
        done
        echo "✅ MariaDB is ready."

        echo "Please provide your MariaDB root credentials to create a 'cove' user."
        local root_user; root_user=$(gum input --value "root" --prompt "Root username: ")
        local root_pass; root_pass=$(gum input --password --placeholder "Password for '$root_user'")
        local db_user="cove_user"
        local db_pass; db_pass=$(openssl rand -base64 16)

        local sql_command="DROP USER IF EXISTS '$db_user'@'localhost'; CREATE USER '$db_user'@'localhost' IDENTIFIED BY '$db_pass'; GRANT ALL PRIVILEGES ON *.* TO '$db_user'@'localhost' WITH GRANT OPTION; FLUSH PRIVILEGES;"
        echo "$sql_command" | mysql -u "$root_user" -p"$root_pass"
        
        if [ $? -ne 0 ]; then
            gum style --foreground red "❌ Database user creation failed. Check credentials and try again."
            exit 1
        fi
        echo "✅ Database user '$db_user' created."

        echo "📝 Saving new configuration..."
        echo "DB_USER='$db_user'" > "$CONFIG_FILE"
        echo "DB_PASSWORD='$db_pass'" >> "$CONFIG_FILE"
    fi
    
    # --- Finalize ---
    create_whoops_bootstrap
    create_gui_file
    regenerate_caddyfile

    gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "🎉 Cove installation complete!" "Run 'cove enable' to start the server." "Your Cove Dashboard is at https://cove.localhost"
}
cove_list() {
    echo "Sites managed by Cove:"
    echo "-----------------------"
    if [ -d "$SITES_DIR" ] && [ "$(ls -A "$SITES_DIR")" ]; then
        for d in "$SITES_DIR"/*; do
            if [ -d "$d" ]; then
                site_name=$(basename "$d")
                type=$(if [ -f "$d/public/wp-config.php" ]; then echo "WordPress"; else echo "Plain"; fi)
                printf "🌐 https://%-30s (%s)\n" "$site_name" "$type"
            fi
        done
    else
        echo "No sites found. Add one with 'cove add <name>'."
    fi
    echo "-----------------------"
}
cove_reload() {
    create_gui_file
    regenerate_caddyfile
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

    if brew services list | grep -q "mailpit.*started"; then
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
        gum style --border normal --margin "1" --padding "1 2" --border-foreground 212 "✅ Services are running" "Dashboard: https://cove.localhost" "Mailpit:   https://mailpit.localhost" "Adminer:   https://adminer.localhost"
    else
        gum style --border normal --margin "1" --padding "1 2" --border-foreground "yellow" "ℹ️ Some services are stopped." "Run 'cove enable' to start them."
    fi
}
cove_version() {
    echo "Cove version $COVE_VERSION"
}
#  Pass all script arguments to the main function.
main "$@"
