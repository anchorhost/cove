# Cove 🏝️

**Local Development Powered by Caddy**

Cove is a command-line tool that simplifies the creation and management of local development websites. It leverages Caddy, MariaDB, and Mailpit to provide a robust environment for both WordPress and plain static sites.

## ✨ Features

  * **Simple CLI**: Manage everything from your terminal with a handful of short commands.
  * **Web Dashboard**: A PicoCSS-styled GUI at `https://cove.localhost` to view, add, and delete sites, plus one-click admin logins.
  * **Automatic HTTPS**: Every site is served over HTTPS using Caddy's internal CA — no cert wrangling.
  * **WordPress & Static Sites**: Spin up a fresh WordPress install or a plain static site with one command.
  * **WordPress Migration**: Pull a remote site down via SSH (`cove pull`) or push a local site up (`cove push`).
  * **Database Management**: Adminer with passwordless auto-login, `cove db backup` for every site, and `cove db list` to inspect credentials.
  * **Email Catching**: Built-in Mailpit catches every outgoing email so you never risk sending a test to a real inbox.
  * **Custom Ports**: Run Cove alongside Local, Studio, DevKinsta, or MAMP — pick alternative HTTP/HTTPS ports and Cove migrates stored WordPress URLs automatically.
  * **LAN & Mobile Testing**: `cove lan` exposes sites to your phone via Bonjour/mDNS for iOS app sync.
  * **Tailscale Integration**: `cove tailscale enable` makes every site reachable from any device on your tailnet.
  * **Instant Public Sharing**: `cove share` spins up a Cloudflare Tunnel so you can share a WIP site with a client in seconds.
  * **Hosts File Automation**: Cove manages `/etc/hosts` entries for you — no manual editing.
  * **Pretty Errors**: Whoops renders beautiful PHP error pages with stack traces and editor integration.
  * **Custom Caddy Rules**: Per-site directives for reverse proxies, auth, headers, or anything else Caddy supports.

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
bash <(curl -sL https://cove.run/install-cove.sh)
```

On macOS, the installer will offer to install Homebrew first if it's not already present. On Linux, make sure `curl` is installed before running it.

## 🚀 Quick Start

Once installed, this is the shortest path from zero to a working WordPress site:

```bash
cove add myblog                # fresh WP install at https://myblog.localhost
cove login myblog              # generates a one-time admin login URL
cove list                      # shows every site Cove manages
cove db backup                 # snapshots every site's database to .sql
```

Open `https://cove.localhost` in your browser to see the dashboard. Your browser may show a certificate warning on first visit — click through, or trust Caddy's root CA once (see [Troubleshooting](#-troubleshooting)).

## 💻 Usage

Cove provides a simple set of commands to manage your local environment.

### Site Management

| Command | Description |
| --- | --- |
| `cove add <name> [--plain]` | Creates a new WordPress site (`<name>.localhost`). Use `--plain` for a static site. |
| `cove delete <name> [--force]` | Deletes a site's directory and its associated database. |
| `cove rename <old-name> <new-name>` | Renames a site, its directory, database, and runs `wp search-replace` so stored URLs (siteurl, home, serialized content) all update to the new domain. |
| `cove list [--totals]` | Lists all sites managed by Cove. Use `--totals` to show disk usage. |
| `cove login <site> [<user>]` | Generates a one-time login link for a WordPress site. |
| `cove path <name>` | Outputs the full system path to a site's public directory. |
| `cove url <name>` | Prints the full HTTPS URL for a site (including the port suffix when on alternative ports). |
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
| `cove ports [--http N --https N]` | Interactively reconfigure HTTP/HTTPS ports. Migrates every WordPress site's stored URLs via `wp search-replace` so existing sites keep working. Supports `--dry-run` and `--skip-urls`. |
| `cove directive <add\|update\|delete\|list> [site]` | Manages custom Caddyfile rules for a specific site. |
| `cove mappings <site> [add\|remove] [domain]` | Manages additional domain mappings for a site. |
| `cove proxy <add\|list\|delete>` | Manages standalone reverse proxy entries in the Caddyfile. |

### Network Access

| Command | Description |
| --- | --- |
| `cove share [site]` | Creates a temporary public tunnel via Cloudflare (installs cloudflared on-demand). |
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

## Running Alongside Local, Studio, or DevKinsta

Cove can coexist with other local WordPress tools that already bind ports 80 and 443. When you run `cove install` and something else is listening on the default ports, Cove detects the conflict and offers a menu:

```
⚠️  Port Conflict Detected
   Port 80 is in use by: Local
   Port 443 is in use by: Local

❯ Use alternative ports (8090 / 8453) — run alongside other tools
  Pick custom ports
  Proceed with 80/443 anyway
  Cancel installation
```

Pick *Use alternative ports* and Cove will install on `8090` / `8453`. Visit `https://myblog.localhost:8453` — Caddy's auto-HTTPS handles the non-default port transparently.

You can switch back and forth at any time without losing work:

```bash
cove ports                              # interactive menu (Keep / Default / Custom)
cove ports --http 80 --https 443        # switch back to defaults
cove ports --http 8090 --https 8453     # switch to alternatives
cove ports --dry-run                    # preview the effect of a port change
```

When the HTTPS port changes, Cove walks every WordPress site under `~/Cove/Sites/` and runs `wp search-replace` to rewrite stored URLs (siteurl, home, serialized content, custom mappings) so existing sites keep working on the new port. Non-WordPress sites are skipped automatically.

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

The web dashboard, available at `https://cove.localhost` (or `https://cove.localhost:8453` when you're on alternative ports), provides a quick and easy way to:

  * View all your managed sites, with clickable domains that open each site in a new tab.
  * Add new WordPress or plain sites via a simple form.
  * Delete existing sites with one click (with a confirmation prompt).
  * Generate a one-time admin login URL for any WordPress site — no password needed.
  * Access quick links to Adminer and Mailpit.
  * See your shared MariaDB connection credentials at a glance.
  * Toggle between light and dark themes (your choice is remembered).

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

## 🩺 Troubleshooting

### "Your connection is not private" certificate warning

Cove issues its own local certificates via Caddy's internal CA. Browsers don't trust it by default, so you'll see a warning on your first visit to any site. You have two options:

1. **Click through once per site** — click *Advanced* → *Proceed to …* and the browser will cache the decision.
2. **Trust Caddy's root CA system-wide** (recommended). The CA cert lives at:
   - **macOS**: `~/Library/Application Support/Caddy/pki/authorities/local/root.crt` — usually auto-trusted by Caddy on install.
   - **Linux (Ubuntu/Debian)**:
     ```bash
     sudo cp ~/.local/share/caddy/pki/authorities/local/root.crt /usr/local/share/ca-certificates/caddy.crt
     sudo update-ca-certificates
     ```

### Ports 80 or 443 are already in use

Cove's installer detects this and offers the reconfiguration menu described in [Running Alongside Local, Studio, or DevKinsta](#running-alongside-local-studio-or-devkinsta). If you skipped the prompt or want to change ports later, run `cove ports`.

### WSL2: "systemd is not running"

Cove needs systemd for service management (Caddy, MariaDB, Mailpit). Enable it by adding to `/etc/wsl.conf` inside your WSL distro:

```ini
[boot]
systemd=true
```

Then from a Windows PowerShell: `wsl --shutdown`, and restart your WSL session.

### WSL2: sites unreachable from Windows browser

WSL2 has its own virtual network, so `myblog.localhost` doesn't resolve from Windows by default. Run `cove wsl-hosts` inside WSL and follow the PowerShell snippet it prints to update Windows' hosts file.

### `cove add` fails with a database error

Make sure MariaDB is running (`cove status`) and that `~/Cove/config` contains a valid `DB_USER` and `DB_PASSWORD`. If MariaDB won't start on macOS, try `brew services restart mariadb` and then re-run `cove enable`.

### I changed ports but existing WordPress sites are broken

If you used `--skip-urls` during `cove ports`, the WordPress `siteurl` / `home` options still point at the old port. Re-run `cove ports` without `--skip-urls` (even changing back and forth works) and Cove will run `wp search-replace` to realign everything. For one-off fixes, you can also run `wp option update siteurl https://yoursite.localhost:8453` from inside the site's `public/` directory.

## 📜 License

Cove is open-source software licensed under the MIT License.
Copyright (c) 2025-present, Austin Ginder.