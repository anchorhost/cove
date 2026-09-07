# Cove 🏝️

**The calm way to run local WordPress.**

Cove is a tiny CLI that spins up local sites in seconds — automatic HTTPS, one-click admin login, zero Docker. It bundles Caddy, FrankenPHP, MariaDB, and Mailpit into one self-contained toolchain for WordPress and plain static sites, with a dashboard at `https://cove.localhost` for your sites, their mail, their databases, and their logs.

## ✨ Features

  * **Simple CLI**: Manage everything from your terminal with a handful of short commands.
  * **Web Dashboard**: A built-in GUI at `https://cove.localhost` with four views. **Sites** to view, filter, sort, add, and delete sites with one-click admin logins; **Mail**, an inbox of everything your sites send, scoped per site; **Databases**, a browser with in-place editing and a SQL console; and **Logs**, PHP errors per site, `debug.log`, and access logs, live. Every view has a real URL.
  * **Automatic HTTPS**: Every site is served over HTTPS using Caddy's internal CA — no cert wrangling.
  * **WordPress & Static Sites**: Spin up a fresh WordPress install — any version, nightly, or a multisite network — or a plain static site with one command.
  * **Per-site PHP**: Pin any site to an older PHP (`cove php mysite 8.2`); it runs on a native php-fpm behind the same Caddy, with TLS, logs, and URLs unchanged.
  * **WordPress Migration**: Pull a remote site down via SSH (`cove pull`) or push a local site up (`cove push`).
  * **Database Management**: Browse and edit any table from the dashboard, run SQL with `⌘↵`, plus Adminer with passwordless auto-login for exports and schema work. `cove db backup` snapshots every site; `cove db list` shows credentials.
  * **Email Catching**: Built-in Mailpit catches every outgoing email so you never risk sending a test to a real inbox. Read it in the dashboard, filtered by site, with reset and login links lifted out of each message — and nothing is ever pruned.
  * **Logs, Parsed**: The shared PHP error log, each site's `debug.log`, Caddy access logs, and the service logs, read backwards in chunks so size never matters, with repeats folded and stack traces a click away.
  * **Custom Ports**: Run Cove alongside Local, Studio, DevKinsta, or MAMP — pick alternative HTTP/HTTPS ports and Cove migrates stored WordPress URLs automatically.
  * **LAN & Mobile Testing**: `cove lan` exposes sites to your phone via Bonjour/mDNS for iOS app sync.
  * **Tailscale Integration**: `cove tailscale enable` makes every site reachable from any device on your tailnet.
  * **Instant Public Sharing**: `cove share` spins up a Cloudflare Tunnel so you can share a WIP site with a client in seconds.
  * **Hosts File Automation**: Cove manages `/etc/hosts` entries for you — no manual editing.
  * **Pretty Errors**: Whoops renders beautiful PHP error pages with stack traces and editor integration.
  * **Health Check**: `cove health` diagnoses crashes, OPcache pressure, and on-disk hygiene, and recommends fixes without changing anything.
  * **Menu Bar App**: On macOS, `cove menubar enable` builds a tiny native companion showing service status at a glance.
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

To preview an unreleased build from the `main` branch — useful for verifying a fix before it's tagged — pass `--main`:

```bash
bash <(curl -sL https://cove.run/install-cove.sh) --main
```

## 🚀 Quick Start

Once installed, this is the shortest path from zero to a working WordPress site:

```bash
cove add myblog                # fresh WP install at https://myblog.localhost
cove login myblog              # generates a one-time admin login URL
cove list                      # shows every site Cove manages
cove db backup                 # snapshots every site's database to .sql
```

Open `https://cove.localhost` in your browser to see the dashboard. Fresh installs trust Cove's local certificate authority automatically; if a browser still warns you, run `cove trust` once (see [Troubleshooting](#-troubleshooting)).

## 💻 Usage

Cove provides a simple set of commands to manage your local environment.

### Site Management

| Command | Description |
| --- | --- |
| `cove add <name> [flavor]` | Creates a new WordPress site (`<name>.localhost`). The optional flavor says what goes inside it: a version (`6.4.3`, `6.9-RC1`), `nightly`, `latest` (the default), or `plain` for a static site with no database. `--multisite` builds a subdirectory network, `--multisite=subdomain` a subdomain one (subsites get HTTPS automatically); `--php=<ver>` pins the PHP version. |
| `cove clone <source> <new-name>` | Copies a site — files, database, and custom Caddy rules — under a new name, rewriting stored URLs to the new domain. Uses a copy-on-write clone on APFS and btrfs, so it's fast and the two copies share disk until one is written to. |
| `cove delete <name> [--force]` | Deletes a site's directory and its associated database. |
| `cove rename <old-name> <new-name>` | Renames a site, its directory, database, and runs `wp search-replace` so stored URLs (siteurl, home, serialized content) all update to the new domain. |
| `cove list [--totals]` | Lists all sites managed by Cove, including each one's WordPress version. Use `--totals` to show disk usage. |
| `cove core check` | Reports the WordPress version of every site, flagging releases wp.org marks outdated or insecure. |
| `cove core update <site> [version]` | Updates a site's WordPress core to the latest release, or to a specific version (which may be a downgrade). Use `--all` to update every site that's behind. |
| `cove login <site> [<user>]` | Generates a one-time login link for a WordPress site. |
| `cove path <name>` | Outputs the full system path to a site's public directory. |
| `cove url <name>` | Prints the full HTTPS URL for a site (including the port suffix when on alternative ports). |
| `cove php [<site>] [<version>\|default]` | Per-site PHP version switching. Pinning routes a site through a native Homebrew `php@<version>` php-fpm behind Caddy; `default` returns it to FrankenPHP's bundled PHP. The pin travels with the site through clone and rename. |
| `cove log [<site>] [-f]` | Shows error logs. Use `-f` to follow logs in real-time. The dashboard's **logs** view shows the same files parsed, filtered by level, and scoped per site. |

### Migration

| Command | Description |
| --- | --- |
| `cove pull [--proxy-uploads]` | Pulls a remote WordPress site into Cove via SSH. Use `--proxy-uploads` to proxy media instead of downloading. |
| `cove push` | Pushes a local Cove site to a remote WordPress site via SSH. |
| `cove transfer probe [site]` | Reports which tools the backup/restore engine behind `pull` and `push` will use on a host. The engine degrades gracefully — zip, then tar, then PHP; mysqldump, or WordPress's own `$wpdb` when there is no MySQL client. |

### Services

| Command | Description |
| --- | --- |
| `cove enable` | Starts the Caddy, MariaDB, and Mailpit background services. |
| `cove disable` | Stops all Cove background services. |
| `cove status` | Checks the status of all background services. |
| `cove reload` | Regenerates the Caddyfile and reloads the Caddy server. |
| `cove health` | Read-only diagnostic: service liveness, FrankenPHP process state and last exit, recent segfaults classified by cause, live OPcache pressure, and on-disk hygiene. Recommends fixes, changes nothing. |
| `cove menubar <enable\|disable>` | (macOS only) Native menu bar app showing service status at a glance, with start/stop controls and quick links to the Dashboard, Adminer, and Mailpit. Opt-in; built locally, no extra download. Originally by [Robby McCullough](https://github.com/RobbyMcCullough/cove-menubar). |

### Database

| Command | Description |
| --- | --- |
| `cove db backup` | Creates a `.sql` backup for every WordPress site. |
| `cove db list` | Shows database credentials for all WordPress sites. |

For browsing and editing, the dashboard's **databases** view lists every database with the site that owns it, opens WordPress databases on an overview (site URL, prefix, autoloaded option weight), and lets you page through any table, double-click a cell to edit it, and run SQL. Adminer at `https://db.cove.localhost` signs you in automatically for exports, imports, and schema changes.

### Advanced Configuration

| Command | Description |
| --- | --- |
| `cove ports [--http N --https N]` | Interactively reconfigure HTTP/HTTPS ports. Migrates every WordPress site's stored URLs via `wp search-replace` so existing sites keep working. Supports `--dry-run` and `--skip-urls`. |
| `cove memory [set <value>]` | Audits `memory_limit` across Cove's ini, the FrankenPHP web server, and every `php` on your PATH. `set 2G` bumps Cove's ini and offers to update each Homebrew/system ini. |
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
| `cove trust` | Installs Cove's local root certificate into the system trust store and every Firefox/Chromium profile it can find (snap browsers included). Fresh installs run it automatically; re-run any time the root rotates. |
| `cove upgrade` | Upgrades Cove, FrankenPHP, and Adminer to the latest versions, and refreshes the managed bits (Whoops, the login helper, the watchdog) across every site. |
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

The web dashboard lives at `https://cove.localhost` (or `https://cove.localhost:8453` on alternative ports). It has four views, one keystroke apart, and every one has a real URL you can bookmark or paste.

### Sites — `/`

  * Every site Cove manages, with its WordPress version (flagged when wp.org marks it insecure), PHP pin, disk usage, and last-modified time.
  * Filter by name (press `/` from anywhere) or by type (click a `WP` / `STATIC` pill); sort by name, type, size, or last modified; pin the sites you are working on to the top.
  * `⌘K` opens a command palette that searches sites and commands from anywhere.
  * Add WordPress or plain sites from a form that offers real WordPress versions; delete with an undo window, or bulk-delete everything a filter matches.
  * Right-click any row for the menu: open, one-time admin login, rename, reveal in Finder, database, PHP version, logs, mail, copy path, pin, delete.
  * The `caddy`, `mariadb`, and `mailpit` dots in the top bar open a panel with each service's status, version, ports, and credentials.

### Mail — `/mail`, `/mail/<site>`

  * An inbox of every message your sites send, over Mailpit's API. Each message carries a site chip; one click narrows the inbox to that site, and a site's row menu lands there directly.
  * The message opens beside the list with `html`, `text`, and `headers` a click apart. HTML renders in a sandboxed frame that runs no scripts and loads nothing remote; inline images come through, remote ones are counted and blocked.
  * Every link in a message is lifted into a row of chips with a **copy** button — most local mail exists to carry a password reset or login link.
  * Mark unread, delete, mark all read, delete everything matching. New mail arrives live. Nothing is ever pruned: Cove launches Mailpit with no message cap.

### Databases — `/db`, `/db/<database>/<table>`

  * Every database with the site that owns it, table counts, and sizes. A WordPress database opens on an overview: site URL, home, prefix, theme, post and user counts, and the largest autoloaded options.
  * Any table as a grid: column types in the header, click to sort, a search box for one column or all, paging. Tables with a primary key are editable in place — double-click a cell, `↵` saves, `Esc` cancels, `⌘⌫` writes `NULL` — and rows can be deleted.
  * A **structure** tab with columns, indexes, and the `CREATE TABLE`; a **sql** console that runs several statements at a time with `⌘↵`, shows results as grids or affected-row counts with timings, and keeps a history.
  * Adminer stays one click away, deep-linked to the open table, for exports, imports, schema changes, and users.

### Logs — `/logs`, `/logs/<site>/<tab>`

  * The system logs on the left — the shared PHP error log, Caddy's process and reload logs, the watchdog, Mailpit, php-fpm — and below them every site, most recently active first.
  * Pick a site for three tabs: **php errors** from the shared log scoped to that site, its own **debug.log**, and its Caddy **access** log. "View log" in a site's row menu opens whichever one the site actually writes to.
  * Entries are parsed into a level chip, the message, and `file:line`; consecutive repeats fold into one row with a count, and a click opens the stack trace. Filter by level, search, page back through **older**, or leave **live** on and watch the file grow.
  * Files are read backwards in chunks, so a 100 MB error log answers as fast as a small one.

### Everywhere

  * System, light, or dark theme — right-click the toggle to pick, and the choice is remembered.
  * Views crossfade into each other, the wordmark returns you to sites without a reload, and Back and Forward walk through what you opened.

## 🛠️ Development

Cove is built from modular source files that are compiled into a single distributable script.

### Project Structure

```
cove/
├── main                 # Core script: globals, helpers, the dashboard, and command routing
├── commands/            # Individual command files (one per command)
├── menubar/             # Source for the macOS menu bar app, embedded into cove.sh at compile time
├── adminer-theme/       # The Cove theme for Adminer (fetched at install/upgrade)
├── compile.sh           # Combines main + commands + menubar into cove.sh
├── cove.sh              # Compiled output (auto-generated, do not edit directly)
├── test-matrix.sh       # Cross-distro release checks (needs a private test box)
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

Cove issues its own local certificates via Caddy's internal CA. Fresh installs trust it automatically; if a browser still warns you, run `cove trust` — it drops the root into the system store and every Firefox/Chromium profile it can find. Failing that, you have two options:

1. **Click through once per site** — click *Advanced* → *Proceed to …* and the browser will cache the decision.
2. **Trust Caddy's root CA system-wide by hand**. The CA cert lives at:
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