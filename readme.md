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

| Command | Description |
| --- | --- |
| `cove add <name> [--plain]` | ➕ Creates a new WordPress site (`<name>.localhost`). Use `--plain` for a static site. |
| `cove delete <name> [--force]` | 🗑️ Deletes a site's directory and its associated database. |
| `cove rename <old-name> <new-name>` | 🔄 Renames a site, its directory, database, and updates its URL in the database. |
| `cove list [--totals]` | 📝 Lists all sites managed by Cove. Use `--totals` to show disk usage. |
| `cove login <site> [<user>]` | 🔑 Generates a one-time login link for a WordPress site. |
| `cove path <name>` | 📁 Outputs the full system path to a site's public directory. |
| `cove url <name>` | 🌐 Prints the full `https://<name>.localhost` URL for a site. |
| `cove pull [--proxy-uploads]` | 🔽 Pulls a remote WordPress site into Cove via SSH. Use `--proxy-uploads` to proxy media instead of downloading. |
| `cove push` | 🔼 Pushes a local Cove site to a remote WordPress site via SSH. |
| `cove enable` | ✅ Starts the Caddy, MariaDB, and Mailpit background services. |
| `cove disable` | 🛑 Stops all Cove background services. |
| `cove status` | 🔎 Checks the status of all background services. |
| `cove reload` | 🔄 Regenerates the Caddyfile and reloads the Caddy server gracefully. |
| `cove db <backup\|list>` | 💾 `backup` creates a `.sql` backup for every WordPress site. `list` shows database credentials. |
| `cove directive <add\|update\|delete\|list>` | ⚙️ Manages custom Caddyfile rules for a specific site. |
| `cove install` | 🛠️ Installs and configures all required dependencies. |
| `cove upgrade` | ⬆️ Upgrades the Cove script and the FrankenPHP binary to the latest versions. |
| `cove version` | ℹ️ Displays the current version of Cove. |

*You can get help for any command by running `cove <command> --help`.*

## 🖥️ The Dashboard

The web dashboard, available at `https://cove.localhost`, provides a quick and easy way to:

  * View all your managed sites.
  * Add new WordPress or Plain sites via a simple form.
  * Delete existing sites with a click.
  * Access quick links to Adminer and Mailpit.
  * See your database connection credentials.

## 🛠️ Development

If you're contributing to Cove, the `watch.sh` script is helpful. It uses `fswatch` to monitor file changes and automatically runs the `compile.sh` script for you.

```bash
./watch.sh
```

## 📜 License

Cove is open-source software licensed under the MIT License.
Copyright (c) 2025-present, Austin Ginder.