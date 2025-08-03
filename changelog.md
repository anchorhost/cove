# Changelog

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

- **Initial Release** of Cove, a command-line tool for local development.
- **Core Service Management**: Commands to `enable`, `disable`, and check the `status` of background services (Caddy, MariaDB, Mailpit).
- **Site Management**:
    - `cove add <name>`: Create new WordPress sites.
    - `cove add <name> --plain`: Create new plain/static HTML sites.
    - `cove delete <name>`: Delete sites and their associated databases.
    - `cove list`: List all currently managed local sites.
- **Web Dashboard**: A GUI at `https://cove.localhost` to view, add, and delete sites. It also provides quick links to Adminer and Mailpit.
- **Database Features**:
    - `cove db backup`: Command to create a `.sql` backup for every WordPress site.
    - Integrated Adminer for web-based database management.
- **Caddy Integration**:
    - `cove reload`: Regenerates the master Caddyfile and gracefully reloads the Caddy server.
    - `cove directive`: Sub-commands (`add`, `update`, `delete`, `list`) to manage site-specific Caddyfile rules.
    - Automatic HTTPS for all local sites using internal certificates.
- **Development Environment**:
    - `cove install`: Installs and configures all required dependencies like Caddy, MariaDB, and Mailpit using Homebrew.
    - Built-in Mailpit service to catch all outgoing application emails.
    - Integrated Whoops for informative PHP error pages.
- **Build System**:
    - `compile.sh`: Script to combine all source files into a single, distributable shell script.
    - `watch.sh`: A helper script using `fswatch` to automatically re-compile the project on file changes.
- **Versioning**:
    - `cove version` command to display the current version of the tool.
- **License**: The project is licensed under the MIT License.