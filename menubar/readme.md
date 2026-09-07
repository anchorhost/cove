# Cove Menu Bar

A menu bar companion for Cove: a native, dependency-free macOS menu bar app
(`Sources/main.m`) and a Linux system tray app (`Linux/cove-tray.py`) that
share one menu, one icon, and one status contract. Originally created by
[Robby McCullough](https://github.com/RobbyMcCullough/cove-menubar) (MIT) and
folded into the official Cove project with his blessing.

The menu bar icon shows Cove at a glance:

- **Full color** — Caddy, MariaDB, and Mailpit are all running
- **Light grayscale** — some services are running
- **Dark grayscale** — all services are stopped

PHP-FPM pools for version-pinned sites (`cove php`) are monitored alongside the
three core services.

The menu can start/stop Cove, refresh status, reload Caddy, open the
Dashboard / Adminer / Mailpit, open the logs and Sites folders, and register
itself to launch at login. A Sites submenu lists every site for one-click
open — hold Option on a WordPress site to generate a one-time admin login via
`cove login` instead. Long lists get a "Recent" section (top 5 by the same
modified signal the dashboard sorts on), and "New Site…" prompts for a name
and runs `cove add`, opening the site when it lands.
The app posts a macOS notification when a service dies while the rest of the
stack is still running (it stays quiet when everything stops at once — that's
usually a deliberate `cove disable`), and checks GitHub daily for new Cove
releases, offering an "Update Cove" item that runs `cove upgrade` in Terminal.

Status is read via `cove status --porcelain` — a stable machine-readable
contract defined in `commands/status`. Reword the human status output freely;
never change the porcelain keys without updating `Sources/main.m` alongside.

## Linux

`Linux/cove-tray.py` is the same app as a StatusNotifierItem, published through
AyatanaAppIndicator3 so it appears on any desktop that hosts a tray: COSMIC,
KDE, XFCE, MATE, Cinnamon, and GNOME with an AppIndicator extension (Ubuntu
enables one by default; vanilla GNOME and Debian do not, and `cove menubar
enable` says so). It needs python3 with the GTK 3 and AyatanaAppIndicator3
introspection data — on Debian/Ubuntu `python3-gi gir1.2-gtk-3.0
gir1.2-ayatanaappindicator3-0.1`, which enable offers to install with apt —
plus optional `gir1.2-notify-0.7` for desktop notifications.

The menu is rendered by the desktop's panel over DBus, which never reports
which modifier keys were held. The macOS Option-key alternate therefore
becomes a small submenu per WordPress site: **Open** or **Log in**. Everything
else matches: the three icon states (derived from the one SVG at startup),
service rows including PHP-FPM pools, start/stop/reload, the Recent section,
"New Site…", the daily update check (opening `cove upgrade` in the desktop's
terminal), and unexpected-stop notifications. "Launch at Login" is an XDG
autostart entry at `~/.config/autostart/cove-menubar.desktop`, written on
enable and owned by the tray's toggle afterwards.

Install location is `~/.local/share/cove-menubar/` (`cove-tray.py`,
`cove-logo.svg`, `VERSION`, generated `icons/`). No build step: enable writes
the files, the autostart entry, and starts the tray in the current session.
Logs go to `~/Cove/Logs/menubar.log` (and `menubar-stderr.log` for Python
tracebacks).

## How it ships

There is no separate download. `compile.sh` embeds these sources into `cove.sh`
(`Sources/main.m`, `Resources/Info.plist`, the SVG icon, and `Linux/cove-tray.py`
as quoted heredocs). On macOS, `cove menubar enable` compiles the app locally
with `clang`, assembles `~/Applications/Cove Menu Bar.app`, ad-hoc signs it, and
launches it — building on the user's machine avoids notarization entirely, and
anyone with Homebrew already has the Command Line Tools this needs. On Linux it
writes the Python source out and runs it.

- `cove menubar enable` — install (or update/overwrite) and launch the app
- `cove menubar disable` — quit and remove the app
- `cove upgrade` — refreshes the app only if it is already installed and
  `MENUBAR_VERSION` (in `main`) changed. Strictly opt-in: upgrading Cove never
  installs the menu bar on its own.

When changing anything under `menubar/` (either platform), bump
`MENUBAR_VERSION` in `main` at release time so enabled installs pick up the
change on their next `cove upgrade`.
