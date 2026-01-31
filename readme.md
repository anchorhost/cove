# Cove 🏝️

**Local Development Powered by Caddy**

Cove is a command-line tool that simplifies the creation and management of local development websites. It leverages Caddy, MariaDB, and Mailpit to provide a robust environment for both WordPress and plain static sites.

## ✨ Features

  * **Simple CLI**: Manage everything from your terminal with simple commands.
  * **Web Dashboard**: A handy web interface to view and manage your sites.
  * **Automatic HTTPS**: All sites are automatically served over HTTPS locally using internal certificates.
  * **WordPress & Static Sites**: Quickly create a new WordPress installation or a plain static site.
  * **Database Management**: Includes Adminer for database management and a command for easy backups.
  * **Email Catching**: Built-in Mailpit service catches all outgoing emails for easy inspection.
  * **Pretty Errors**: Uses Whoops for beautiful and informative PHP error pages.
  * **Custom Rules**: Easily add site-specific Caddy directives.

## Core Technologies

  * **Web Server**: [Caddy](https://caddyserver.com/) / [FrankenPHP](https://frankenphp.dev/)
  * **Database**: [MariaDB](https://mariadb.org/)
  * **Email Catching**: [Mailpit](https://mailpit.axllent.org/)
  * **Error Handling**: [whoops](https://filp.github.io/whoops/)
  * **CLI Beautification**: [`gum`](https://github.com/charmbracelet/gum)
  * **Made for**: [WordPress](https://wordpress.org) and [`WP-CLI`](https://wp-cli.org/)

## Installation

Run the following in your terminal to install `cove`.

```bash
bash <(curl -sL https://cove.run/cove-install.sh)
```

## 💻 Usage

Cove provides a simple set of commands to manage your local environment.

### Site Management

| Command | Description |
| --- | --- |
| `cove add <name> [--plain]` | Creates a new WordPress site (`<name>.localhost`). Use `--plain` for a static site. |
| `cove delete <name> [--force]` | Deletes a site's directory and its associated database. |
| `cove rename <old-name> <new-name>` | Renames a site, its directory, database, and updates its URL in the database. |
| `cove list [--totals]` | Lists all sites managed by Cove. Use `--totals` to show disk usage. |
| `cove login <site> [<user>]` | Generates a one-time login link for a WordPress site. |
| `cove path <name>` | Outputs the full system path to a site's public directory. |
| `cove url <name>` | Prints the full `https://<name>.localhost` URL for a site. |
| `cove log [<site>] [-f]` | Shows error logs. Use `-f` to follow logs in real-time. |

### Migration

| Command | Description |
| --- | --- |
| `cove pull [--proxy-uploads]` | Pulls a remote WordPress site into Cove via SSH. Use `--proxy-uploads` to proxy media instead of downloading. |
| `cove push` | Pushes a local Cove site to a remote WordPress site via SSH. |

### Services

| Command | Description |
| --- | --- |
| `cove enable` | Starts the Caddy, MariaDB, and Mailpit background services. |
| `cove disable` | Stops all Cove background services. |
| `cove status` | Checks the status of all background services. |
| `cove reload` | Regenerates the Caddyfile and reloads the Caddy server. |

### Database

| Command | Description |
| --- | --- |
| `cove db backup` | Creates a `.sql` backup for every WordPress site. |
| `cove db list` | Shows database credentials for all WordPress sites. |

### Advanced Configuration

| Command | Description |
| --- | --- |
| `cove directive <add\|update\|delete\|list> [site]` | Manages custom Caddyfile rules for a specific site. |
| `cove mappings <site> [add\|remove] [domain]` | Manages additional domain mappings for a site. |
| `cove proxy <add\|list\|delete>` | Manages standalone reverse proxy entries in the Caddyfile. |

### Network Access

| Command | Description |
| --- | --- |
| `cove share [site]` | Creates a temporary public tunnel via localhost.run (no signup required). |
| `cove lan <enable\|disable\|status\|trust> [site]` | Manages LAN access to sites for mobile app sync (Bonjour/mDNS). |
| `cove tailscale <enable\|disable\|status>` | Exposes sites to your Tailscale network via port-based routing. |
| `cove wsl-hosts` | (WSL only) Shows Windows hosts file setup instructions. |

### System

| Command | Description |
| --- | --- |
| `cove install` | Installs and configures all required dependencies. |
| `cove upgrade` | Upgrades Cove, FrankenPHP, and Adminer to the latest versions. |
| `cove version` | Displays the current version of Cove. |

*You can get help for any command by running `cove <command> --help`.*

## Proxying Local Services

Cove can proxy requests to any local service running on a port. This is useful for tools like [OpenCode](https://opencode.ai) that provide a web interface.

For example, if you run `opencode web` which starts a server on port 4096, you can access it through Cove at `https://opencode.localhost`:

```bash
# Create the site (if it doesn't exist)
cove add opencode --plain

# Add a reverse proxy directive
cove directive add opencode.localhost "reverse_proxy 127.0.0.1:4096"
```

Now `https://opencode.localhost` will proxy all requests to `127.0.0.1:4096`, giving you HTTPS access to the local service.

To remove the proxy later:

```bash
cove directive delete opencode.localhost
```

## Accessing Sites via Tailscale

[Tailscale](https://tailscale.com) allows you to securely access your computer from any other device on your private network. If you have Tailscale installed on both your laptop and your phone, you can access your Cove sites from your phone.

```bash
# Enable Tailscale integration (auto-detects your hostname)
cove tailscale enable

# View the generated URLs for each site
cove tailscale status
```

Cove automatically detects your Tailscale hostname. Each site gets a unique port (e.g., `https://your-laptop.tail1234.ts.net:9001`). Open these URLs on any device connected to your Tailscale network.

To disable:

```bash
cove tailscale disable
```

## 🖥️ The Dashboard

The web dashboard, available at `https://cove.localhost`, provides a quick and easy way to:

  * View all your managed sites.
  * Add new WordPress or Plain sites via a simple form.
  * Delete existing sites with a click.
  * Access quick links to Adminer and Mailpit.
  * See your database connection credentials.

## 🛠️ Development

Cove is built from modular source files that are compiled into a single distributable script.

### Project Structure

```
cove/
├── main                 # Core script with globals, helpers, and command routing
├── commands/            # Individual command files (one per command)
├── compile.sh           # Combines main + commands into cove.sh
├── cove.sh              # Compiled output (auto-generated, do not edit directly)
└── install-cove.sh      # Standalone installer script
```

### Building

After making changes to `main` or any file in `commands/`, compile the distributable script:

```bash
./compile.sh
```

### Auto-Compile on Save

The `watch.sh` script uses `fswatch` to monitor file changes and automatically runs `compile.sh`:

```bash
./watch.sh
```

### Testing on Linux/WSL

To test your local development version on Linux or WSL without publishing to GitHub:

1. **Copy the project folder** to your Linux machine or WSL environment

2. **Compile the script** (if not already done):
   ```bash
   ./compile.sh
   ```

3. **Install using dev mode**:
   ```bash
   ./install-cove.sh --dev
   ```

The `--dev` flag tells the installer to use the local `cove.sh` from the same directory instead of downloading from GitHub. This allows you to test your changes before publishing a release.

### Supported Platforms

- **macOS**: Intel and Apple Silicon (via Homebrew)
- **Linux**: Ubuntu/Debian (apt) and Fedora/RHEL/CentOS (dnf)
- **WSL2**: Windows Subsystem for Linux (requires systemd enabled)

## 📜 License

Cove is open-source software licensed under the MIT License.
Copyright (c) 2025-present, Austin Ginder.