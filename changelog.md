# Changelog

## [1.6] - 2025-09-18

### ✨ New Features

* **Remote Site Pushing:** A new `cove push` command has been introduced to migrate a local Cove site to a remote server via SSH.
    * It features an interactive TUI to guide you through selecting a local site and providing remote credentials.
    * The command creates a local backup, securely uploads it, and then executes a migration script on the remote server to overwrite the destination site's content.

## [1.5] - 2025-09-14

### ✨ New Features

* **Remote Site Pulling:** A new `cove pull` command has been introduced to migrate a remote WordPress site into Cove via SSH.
    * It features an interactive TUI to guide you through providing remote credentials.
    * It can create a new local site or overwrite an existing one.
    * Includes a powerful `--proxy-uploads` flag that skips downloading the `wp-content/uploads` directory and instead configures Caddy to `reverse_proxy` media requests to the live site, saving significant time and disk space.
* **Piped Directives:** The `cove directive add <site>` command now accepts input from `stdin`, allowing you to pipe complex, multi-line Caddy rules directly into a site's configuration. This is ideal for scripting and is used by the new `pull` command to set up the upload proxy.

### 🛠️ Improvements & Changes

* **FrankenPHP Auto-Upgrade:** The `cove upgrade` command is now more powerful. In addition to upgrading the Cove script itself, it now also checks for the latest version of the FrankenPHP binary on GitHub and will automatically download and install it if a newer version is available.
* **Correct Directive Order:** The Caddyfile generation logic has been updated to place custom directives *before* the `php_server` directive. This ensures that custom rules like `reverse_proxy` are evaluated first, which is critical for the new upload proxy feature to function correctly.
* **Automatic Directive Cleanup:** When a site is deleted using `cove delete`, any associated custom Caddy directive file is now also automatically removed, ensuring no orphaned configuration files are left behind.

## [1.4] - 2025-09-11

### ✨ New Features

* **Self-Healing Login Command:** The `cove login` command is now "self-healing." If the command fails, it will automatically check for and inject a required Must-Use (MU) plugin into the WordPress site, then retry the login process. This ensures the command works reliably even on sites created with older versions of Cove or if the plugin was manually deleted.
* **Integrated MU-Plugin:** Cove now uses a dedicated MU-plugin (`captaincore-helper.php`) which is automatically added to new WordPress sites. This plugin provides the core functionality for one-time logins via a custom WP-CLI command (`wp user login <user>`) and also disables WordPress's plugin and theme auto-update email notifications for a cleaner local experience.

### 🛠️ Improvements & Changes

* **Global PHP Memory Limit:** The global PHP `memory_limit` has been increased to **512M** in the main Caddyfile configuration. This helps prevent errors when working with memory-intensive plugins or operations across all sites.
* **Refactored Plugin Injection:** The logic for creating the MU-plugin has been moved into its own dedicated function (`inject_mu_plugin`), cleaning up the `cove add` command and allowing the new self-healing `cove login` command to utilize it.
* **More Robust Dashboard Logins:** The web dashboard's "Login" button is now significantly more reliable. It delegates directly to the `cove login` command, inheriting its new self-healing capabilities and simplifying the dashboard's backend logic.
* **Non-Blocking Server Reloads:** Server reloads triggered from the web UI (or the `cove reload` command) now run as a background process. This fixes a potential deadlock issue, preventing the dashboard from freezing and providing a much smoother user experience when adding, deleting, or modifying sites.

## [1.3] - 2025-08-24

### ✨ New Features

* **Admin Login Command:** A new `cove login <site> [<user>]` command has been added to generate a one-time login link for a WordPress site. This works by finding the first available administrator or by specifying a user ID, email, or login.
* **Dashboard Login Button:** The web dashboard now includes a "Login" button for WordPress sites, allowing for one-click access to the admin area. This is powered by a new `get_login_link` API endpoint.

### 🛠️ Improvements & Changes

* **Automatic `/etc/hosts` Management:** The `reload` command now automatically checks for and adds required entries for all Cove sites to the `/etc/hosts` file, ensuring local domains resolve without manual setup. This requires sudo privileges upon first run.
* **Smarter Installation Script:** The main installer (`install-cove.sh`) is now architecture-aware, correctly using `/opt/homebrew/bin` on Apple Silicon and `/usr/local/bin` on Intel Macs. It will also offer to install Homebrew if it's not detected and attempt to create the installation directory if it doesn't exist.
* **Robust MariaDB Setup:** The `cove install` command now first attempts an automatic, non-interactive `sudo mysql` command to create the database user. If this fails, it falls back to the interactive prompt for root credentials, improving the initial setup experience.
* **Resilient Site Creation:** The `cove add` command for WordPress sites is now more robust. It will automatically clean up the site directory and database if the installation process fails, preventing partial sites. It also now deletes the default "Hello Dolly" and "Akismet" plugins for a cleaner start.

## [1.2] - 2025-08-22

### **New Features**

* **Site Renaming:** A new `cove rename <old-name> <new-name>` command has been added to fully rename a site. This includes updating the directory name, database name, and running a search-and-replace on the site's URL within the database.
* **Path & URL Commands:**
    * Added `cove path <name>` to quickly get the full system path to a site's public directory.
    * Added `cove url <name>` to print the full `https://<name>.localhost` URL for a site.

### **Improvements & Changes**

* **Increased Upload Limits:** The default PHP `upload_max_filesize` and `post_max_size` have been increased to 512M to allow for larger file and database imports.
* **Enhanced `list` Command:** The `cove list` command now includes a "Path" column, displaying the path to each site's public directory.

## [1.1] - 2025-08-02

### **New Features**

* **Interactive Web UI:** A new web-based dashboard has been introduced at `cove.localhost` for managing sites. This interface allows users to:
    * Add and delete sites directly from the browser.
    * View a list of all managed sites with links to each.
    * See the current database user and password configuration.
    * Toggle between light and dark themes.

* **FrankenPHP Support:** The script now detects and prefers a `frankenphp` installation, falling back to `caddy` if it's not found. This allows Cove to leverage the performance benefits of FrankenPHP.

* **One-Time Login URLs:** When creating a new WordPress site, a one-time login URL is now generated and displayed, allowing for quick and easy access to the new site's admin area without needing to manually enter the generated password.

* **Database Listing:** A new command, `cove db list`, has been added. It provides a formatted table of all WordPress sites and their associated database credentials and size.

* **Sizing Information in Site List:** The `cove list` command now includes a `--totals` flag to display the disk usage of each site's `public` directory.

* **Upgrade Command:** A new `cove upgrade` command allows users to automatically fetch and install the latest version of Cove from GitHub.

### **Improvements & Changes**

* **Enhanced `list` Command:** The `cove list` command now outputs a neatly formatted and styled table for better readability, replacing the previous plain text list.

* **Persistent Mailpit Storage:** Mailpit is now launched with a persistent database file (`mailpit.db`), ensuring that emails are not lost when the service is restarted.

* **Adminer Auto-Login:** The Adminer setup now includes an auto-login feature, pre-filling the database credentials from the Cove configuration file for a more seamless experience. A custom theme has also been applied.

* **Improved Output and Styling:** The use of `gum` has been expanded across various commands to provide more consistent and visually appealing feedback, including styled tables, prompts, and messages.

* **Refined Site Creation and Deletion:**
    * The site creation process now validates against a list of protected names (`cove`, `mailpit`, `adminer`).
    * Site names are now restricted to lowercase letters, numbers, and hyphens.
    * The `cove add` command now accepts a `--no-reload` flag to prevent the server from reloading, which is used by the new web UI to manage the process.

* **Better Service Management:**
    * The `cove enable` command now ensures that any running instances of Mailpit are stopped before starting a new one to prevent conflicts.
    * The `cove status` command now provides more readable, color-coded output.

* **Robust Dependency Checks:** The installation script now checks for conflicting services running on ports 80 and 443 and warns the user.

* **Help Command Enhancements:** The help text for all commands has been updated to be more descriptive and now includes subcommand details for `db` and `directive`.

### **Bug Fixes**

* **MariaDB Connection Wait:** The installation script now correctly waits for the MariaDB service to be fully available before attempting to create the database user, preventing a common installation failure.

## [1.0] - 2025-07-12

### Added

* **Initial Release** of Cove, a command-line tool for local development.
* **Core Service Management**: Commands to `enable`, `disable`, and check the `status` of background services (Caddy, MariaDB, Mailpit).
* **Site Management**:
    * `cove add <name>`: Create new WordPress sites.
    * `cove add <name> --plain`: Create new plain/static HTML sites.
    * `cove delete <name>`: Delete sites and their associated databases.
    * `cove list`: List all currently managed local sites.
* **Web Dashboard**: A GUI at `https://cove.localhost` to view, add, and delete sites. It also provides quick links to Adminer and Mailpit.
* **Database Features**:
    * `cove db backup`: Command to create a `.sql` backup for every WordPress site.
    * Integrated Adminer for web-based database management.
* **Caddy Integration**:
    * `cove reload`: Regenerates the master Caddyfile and gracefully reloads the Caddy server.
    * `cove directive`: Sub-commands (`add`, `update`, `delete`, `list`) to manage site-specific Caddyfile rules.
    * Automatic HTTPS for all local sites using internal certificates.
* **Development Environment**:
    * `cove install`: Installs and configures all required dependencies like Caddy, MariaDB, and Mailpit using Homebrew.
    * Built-in Mailpit service to catch all outgoing application emails.
    * Integrated Whoops for informative PHP error pages.
* **Build System**:
    * `compile.sh`: Script to combine all source files into a single, distributable shell script.
    * `watch.sh`: A helper script using `fswatch` to automatically re-compile the project on file changes.
* **Versioning**:
    * `cove version` command to display the current version of the tool.
* **License**: The project is licensed under the MIT License.