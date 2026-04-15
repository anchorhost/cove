# Changelog

## [1.8] - 2026-04-15

### ✨ New Features

* **Alternative HTTP/HTTPS Ports:** Cove can now run alongside other local WordPress tools (Local, WordPress Studio, DevKinsta, MAMP) that already bind 80/443. The installer detects conflicts and offers a menu of alternatives.
    * IPv4 **and** IPv6 port probing via bash `/dev/tcp`, so the check works even against root-owned listeners (which `lsof` can't see from a regular user on macOS).
    * Recommended fallback ports `8090`/`8453` — picked specifically to avoid the well-trodden 8080/8443/8888/8881 range used by Docker, Lando, wp-env, MAMP, and WordPress Studio.
    * Chosen ports persist to `~/Cove/config` and are emitted into the Caddy global block as `http_port`/`https_port`. Site blocks continue to use their plain `site.localhost {}` form — Caddy handles the rewrite automatically.
    * Re-running `cove install` on a machine with non-default ports saved presents a "Keep current / Switch to default / Pick custom" menu so you can migrate in either direction.
* **`cove ports` Command:** A new top-level command to reconfigure ports at any time, not just during install.
    * Interactive menu by default; accepts `--http PORT --https PORT` for scripted use.
    * After a port change, walks every WordPress site under `~/Cove/Sites/` and runs `wp search-replace --all-tables --skip-plugins --skip-themes` to rewrite stored URLs (siteurl, home, serialized content, custom mappings) so existing sites keep working on the new port.
    * Iterates each hostname a site answers on — base domain *plus* any entries in `site/mappings` — so extra domains don't get left stale.
    * `--dry-run` previews the port change and per-site replacement counts without committing anything.
    * `--skip-urls` changes ports without touching databases, for power users who want to migrate manually.
    * Shows a confirmation list before running (ask-once, not per-site).
    * `cove install` now also runs this DB migration step when a re-install changes ports with pre-existing WordPress sites on disk.
* **FrankenPHP-Backed `wp-cli`:** Cove now uses FrankenPHP's bundled PHP for *both* the web server and `wp-cli` invocations, removing the standalone `brew install php` dependency entirely.
    * `get_wp_cmd` routes all wp-cli calls through `frankenphp php-cli` — one PHP runtime for everything Cove touches.
    * A dedicated `~/Cove/php.ini` is written at install time and exported via `PHPRC`, giving Cove full control of `memory_limit`, `display_errors`, and `error_reporting` without fighting any system-wide `/opt/homebrew/etc/php/*/php.ini`.
    * `cove list`, `cove db`, and `cove upgrade` also use `frankenphp php-cli -r` for their inline PHP helpers, so Cove works on a fresh Apple Silicon Mac with zero standalone PHP installed.

### 🛠️ Improvements & Changes

* **Tailscale Access Serves Sites Directly:** `cove tailscale enable` now serves site files directly from the Tailscale-scoped server block instead of reverse-proxying through the local `site.localhost` block. This fixes CSS/JS/image loading when a site is accessed from a remote device.
* **Dynamic siteurl/home Override:** The bundled `captaincore-helper.php` MU-plugin now filters `option_home` and `option_siteurl` at request time when a site is accessed via a non-`.localhost` host (Tailscale, LAN, or `cove share`). Assets resolve against the *current* host so the page renders correctly, and `wp-cli` is unaffected.
* **Smarter FrankenPHP Upgrade:** `cove upgrade` now detects how FrankenPHP was installed and uses the right upgrade path — `apt` or `dnf` for distro-packaged installs, direct download for static binaries.
* **macOS Services via `launchd`:** Caddy, Mailpit, and the Cove-managed services now run via custom `launchd` plists on macOS instead of `brew services`, giving Cove precise control over process arguments and log routing, plus proper auto-restart on crashes.
* **Shared Port Helpers:** `port_is_free`, `port_is_own`, `port_has_conflict`, `prompt_custom_ports`, `port_url_for`, and `update_wp_site_urls_for_port_change` are now top-level helpers in `main`, shared between `cove install` and `cove ports`.
* **Cleaner `cove add` Output:** `cove add` now writes `WP_DEBUG_DISPLAY = false` into `wp-config.php` so WordPress doesn't force `display_errors` back on mid-install, keeping the command output clean. An additional stderr filter strips any remaining `Deprecated:` lines that leak out of wp-cli's colorizer on PHP 8.5.
* **Readme Overhaul:** Major readme refresh, including a new Quick Start section, a "Running Alongside Local, Studio, or DevKinsta" walkthrough, a Troubleshooting section (cert warnings, WSL systemd, port conflicts, DB recovery), and a rewritten Features list that now covers LAN/mobile, Tailscale, Cloudflare share, WordPress migration, and `/etc/hosts` automation.

### 🐛 Bug Fixes

* **"Installation Cancelled" No Longer Reads as "Successful":** The outer `install-cove.sh` installer used to print `SUCCESS: Cove has been installed successfully!` even when the user explicitly cancelled from Cove's interactive prompts. The installer now lets `set -e` handle the non-zero exit from `cove install` cleanly, so a real cancel no longer ends with a contradictory success message.
* **Mailpit Install on Fresh Apple Silicon Macs:** The upstream Mailpit installer hardcodes `/usr/local/bin` as its install directory, which doesn't exist on a fresh Apple Silicon Mac (Homebrew lives at `/opt/homebrew`). Cove now uses `brew install mailpit` on macOS instead, sidestepping the issue entirely. The upstream installer is still used on Linux, where `/usr/local/bin` is always present.
* **FrankenPHP Install on Fresh Apple Silicon Macs:** The official FrankenPHP installer had the same `/usr/local/bin` problem — it would silently drop the binary in the *current working directory* instead of on `PATH`. Cove now runs the installer from a tempdir and, if the binary ends up there, moves it into `$BIN_DIR` (e.g., `/opt/homebrew/bin`) before continuing.
* **PHP 8.5 Deprecation Noise:** wp-cli 2.12.0's bundled vendor code (`react/promise`, `php-cli-tools/Colors.php`) emits `Deprecated:` warnings on PHP 8.5 that previously flooded every `cove add` run — ~50 lines per install, polluting captured output like the one-time login URL. A combination of PHPRC `display_errors=0`, `WP_DEBUG_DISPLAY=false`, and a precision stderr filter on the install subshell now keeps output clean while preserving real errors.
* **IPv6-Only Port Listeners Not Detected:** The initial version of `port_is_free` only probed `127.0.0.1`, which missed IPv6-only listeners like Python's `http.server` (which binds `::` by default). The helper now probes both IPv4 and IPv6 loopback so a service on either stack is seen.
* **`wp --version` Validation Loop:** `install_dependency` used to run `wp --version` as a sanity check after install, which failed when no standalone `php` was on PATH (wp's shebang is `#!/usr/bin/env php`). The check now skips that validation step for `wp`, matching the existing special case for `mariadb`.
* **Adminer Version Detection on macOS:** `cove upgrade` used Perl-regex `grep -oP ... \K` to read the installed Adminer version, which only works on GNU grep. macOS ships BSD grep, so detection silently fell back to "unknown" and the upgrade prompt always asked to re-download even when the current version was up to date. Switched to a portable `LC_ALL=C sed -nE` extraction that pulls the version cleanly from both `VERSION="x.y.z"` and the `@version` docblock.

## [1.7] - 2026-01-31

### ✨ New Features

* **Linux & WSL Support:** Cove now runs natively on Linux distributions including Ubuntu, Debian, Fedora, CentOS, and RHEL. It also includes full support for Windows Subsystem for Linux (WSL).
    * Automatic OS and package manager detection (`apt`/`dnf`/`brew`).
    * Smart MariaDB service name detection across different distros.
    * WP-CLI `--allow-root` support for Docker and WSL environments where running as root is common.
* **LAN Access for Mobile Sync:** A new `cove lan` command enables LAN access to your sites for mobile app testing and sync.
    * Assigns a unique port and broadcasts via Bonjour/mDNS for easy device discovery.
    * Includes `cove lan trust` instructions for installing Caddy's CA certificate on mobile devices.
* **Log Viewer:** A new `cove log` command provides quick access to site logs or the global error log.
    * Supports `--follow` (`-f`) flag for real-time log tailing.
* **Public Site Sharing:** A new `cove share` command creates temporary public tunnels using Cloudflare Quick Tunnels.
    * Uses `cloudflared` (installed on-demand via Homebrew if missing).
    * Generates a random public URL that works until you press Ctrl+C.
* **Tailscale Integration:** A new `cove tailscale` command exposes all Cove sites to your Tailscale network.
    * Auto-detects your Tailscale hostname or accepts a manual override.
    * Assigns unique ports to each site, plus fixed ports for Mailpit (9901), Adminer (9902), and the dashboard (9900).
* **Reverse Proxy Management:** A new `cove proxy` command manages standalone reverse proxy entries.
    * Useful for exposing local services (like AI coding tools) via Tailscale or custom domains.
* **Domain Mappings:** A new `cove mappings` command allows a single site to be served from multiple domains.
    * Mappings are automatically added to `/etc/hosts` and the Caddyfile on reload.
* **WSL Hosts Helper:** A new `cove wsl-hosts` command (WSL only) displays PowerShell commands for updating the Windows hosts file so you can access Cove sites from your Windows browser.

### 🛠️ Improvements & Changes

* **Catppuccin Adminer Theme:** A new custom Adminer theme has been bundled with Cove, featuring the beautiful Catppuccin color palette.
    * Automatic light/dark mode switching based on system preferences (Latte for light, Mocha for dark).
    * Full SQL syntax highlighting with Catppuccin colors.
    * Modern UI with improved typography, spacing, and styled action buttons.
* **Adminer Auto-Upgrade:** The `cove upgrade` command now also checks for and installs the latest version of Adminer.
* **Improved Site Listing:** The `cove list` command output has been refined for better readability.
* **Smarter Tailscale Detection:** Tailscale hostname auto-detection has been improved for more reliable setup.
* **Cleaner Error Display:** PHP's `display_errors` is now disabled by default. The Whoops error handler has been refined to silence noisy `E_DEPRECATED` and `E_NOTICE` warnings (common in older plugins) while still displaying fatal errors with full stack traces.
* **Enhanced Share Command:** The `cove share` command now displays a real-time access log showing timestamp, HTTP status (color-coded), client IP address, method, and path for each request. Connection loss is now detected and reported, and shutdown no longer displays terminal noise.

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