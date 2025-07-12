# Changelog

## [1.0.0] - 2025-07-12

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