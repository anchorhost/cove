#!/usr/bin/env python3
# Cove Menu Bar for Linux — a system tray companion for Cove.
#
# The Linux sibling of Sources/main.m. Same contract, same menu: status is
# read via `cove status --porcelain` (key=value per line, defined in
# commands/status — never change those keys without updating both apps),
# actions shell out to `cove`, and the icon tells the story at a glance:
# full colour when Caddy, MariaDB and Mailpit are all up, light grey when
# some are, dark grey when everything is stopped.
#
# It is a StatusNotifierItem (the freedesktop tray protocol) published through
# AyatanaAppIndicator3, so it shows up on any desktop that hosts a tray:
# COSMIC, KDE, XFCE, MATE, Cinnamon, and GNOME with the AppIndicator extension
# (Ubuntu ships it enabled; vanilla GNOME and Debian do not). The menu itself
# is rendered by the desktop's panel over DBus, which is why there is no
# Option-key trick here: the panel never tells us which modifiers were held.
# WordPress sites therefore get a small submenu — Open, or Log in — instead.
#
# Written out and launched by `cove menubar enable`; there is no build step.
# Runtime needs: python3, GTK 3 and AyatanaAppIndicator3 introspection data
# (Debian/Ubuntu: python3-gi gir1.2-gtk-3.0 gir1.2-ayatanaappindicator3-0.1).
# gir1.2-notify-0.7 is optional and only used for desktop notifications.

import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("AyatanaAppIndicator3", "0.1")
from gi.repository import Gtk, GLib, AyatanaAppIndicator3 as AppIndicator  # noqa: E402

try:
    gi.require_version("Notify", "0.7")
    from gi.repository import Notify  # noqa: E402
    Notify.init("Cove")
    HAVE_NOTIFY = True
except (ValueError, ImportError):
    HAVE_NOTIFY = False

HOME = os.path.expanduser("~")
COVE_DIR = os.path.join(HOME, "Cove")
SITES_DIR = os.path.join(COVE_DIR, "Sites")
LOGS_DIR = os.path.join(COVE_DIR, "Logs")
INSTALL_DIR = os.path.dirname(os.path.abspath(__file__))
ICON_DIR = os.path.join(INSTALL_DIR, "icons")
AUTOSTART_FILE = os.path.join(HOME, ".config", "autostart", "cove-menubar.desktop")
LOG_FILE = os.path.join(LOGS_DIR, "menubar.log")
REFRESH_SECONDS = 20
UPDATE_CHECK_SECONDS = 86400
CORE_SERVICES = ("caddy", "mariadb", "mailpit")
SERVICE_NAMES = {"caddy": "Caddy", "mariadb": "MariaDB", "mailpit": "Mailpit"}
URL_PATTERN = re.compile(r"https://[A-Za-z0-9.:/_?=&%~#+!@-]+")
SITE_NAME_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

# Icon colours: the brand disc, then the two greys the macOS app uses for
# "some services" and "everything stopped".
ICON_VARIANTS = {
    "cove-logo": "#009b95",
    "cove-logo-partial": "#9a9a9a",
    "cove-logo-stopped": "#4a4a4a",
}


def log(text):
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {text}\n")
    except OSError:
        pass


def cove_path():
    for candidate in ("/usr/local/bin/cove", "/usr/bin/cove", os.path.join(HOME, ".local", "bin", "cove")):
        if os.access(candidate, os.X_OK):
            return candidate
    return shutil.which("cove") or "cove"


def cove_env():
    env = dict(os.environ)
    env["PATH"] = "/usr/local/bin:/usr/bin:/bin:" + env.get("PATH", "")
    return env


def run_cove(args, timeout):
    """Run a cove subcommand headlessly. Returns (status, merged output, error text)."""
    try:
        result = subprocess.run(
            [cove_path(), *args], capture_output=True, text=True, timeout=timeout,
            env=cove_env(), stdin=subprocess.DEVNULL,
        )
        return result.returncode, (result.stdout or "") + (result.stderr or ""), None
    except subprocess.TimeoutExpired:
        return 1, "", f"cove {' '.join(args)} timed out after {int(timeout)}s."
    except OSError as error:
        return 1, "", str(error)


def strip_ansi(text):
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)


def first_line(text):
    """First meaningful line of command output, with gum's box borders stripped."""
    for line in strip_ansi(text or "").splitlines():
        line = line.strip().strip("│").strip()
        if line and not set(line) <= set("─┌┐└┘╭╮╰╯ "):
            return line
    return ""


def https_port():
    try:
        with open(os.path.join(COVE_DIR, "config"), encoding="utf-8") as handle:
            match = re.search(r"^HTTPS_PORT='?(\d+)'?", handle.read(), re.M)
            return match.group(1) if match else "443"
    except OSError:
        return "443"


def cove_url(host):
    port = https_port()
    return f"https://{host}" if port == "443" else f"https://{host}:{port}"


def open_uri(uri):
    log(f"open {uri}")
    subprocess.Popen(["xdg-open", uri], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def display_name(key):
    if key in SERVICE_NAMES:
        return SERVICE_NAMES[key]
    if key.startswith("php-fpm-"):
        return "PHP-FPM " + key[len("php-fpm-"):]
    return key


def version_tuple(text):
    return tuple(int(part) if part.isdigit() else 0 for part in text.split("."))


def write_icon_variants():
    """Derive the grey icon states from the shipped SVG so all three stay one drawing."""
    source = os.path.join(INSTALL_DIR, "cove-logo.svg")
    try:
        with open(source, encoding="utf-8") as handle:
            svg = handle.read()
    except OSError:
        return
    os.makedirs(ICON_DIR, exist_ok=True)
    for name, colour in ICON_VARIANTS.items():
        try:
            with open(os.path.join(ICON_DIR, f"{name}.svg"), "w", encoding="utf-8") as handle:
                handle.write(svg.replace("#009b95", colour))
        except OSError:
            pass


class CoveTray:
    def __init__(self):
        self.states = {}
        self.service_keys = list(CORE_SERVICES)
        self.states_known = False
        self.busy = None
        self.last_error = None
        self.last_action_error = None
        self.last_user_action = 0.0
        self.pending_stops = set()
        self.cove_version = ""
        self.latest_version = ""
        self.sites_dir_mtime = None

        write_icon_variants()
        self.indicator = AppIndicator.Indicator.new(
            "cove", "cove-logo-partial", AppIndicator.IndicatorCategory.APPLICATION_STATUS)
        self.indicator.set_icon_theme_path(ICON_DIR)
        self.indicator.set_title("Cove")
        self.indicator.set_status(AppIndicator.IndicatorStatus.ACTIVE)

        self.menu = Gtk.Menu()
        self.build_menu()
        self.indicator.set_menu(self.menu)
        self.render()

        self.refresh_status()
        self.check_for_updates()
        GLib.timeout_add_seconds(REFRESH_SECONDS, self.on_refresh_tick)
        GLib.timeout_add_seconds(UPDATE_CHECK_SECONDS, self.on_update_tick)

    # --- Menu skeleton -------------------------------------------------

    def add_item(self, label, callback=None, sensitive=True, menu=None):
        item = Gtk.MenuItem(label=label)
        item.set_sensitive(sensitive)
        if callback is not None:
            item.connect("activate", lambda *_: callback())
        (menu or self.menu).append(item)
        return item

    def add_separator(self, menu=None):
        (menu or self.menu).append(Gtk.SeparatorMenuItem())

    def build_menu(self):
        self.summary_item = self.add_item("Checking Cove…", sensitive=False)
        self.add_separator()
        self.service_items = {}
        self.service_anchor = Gtk.SeparatorMenuItem()
        for key in self.service_keys:
            self.service_items[key] = self.add_item(display_name(key) + ": …", sensitive=False)
        self.error_item = self.add_item("", sensitive=False)
        self.error_item.set_no_show_all(True)
        self.menu.append(self.service_anchor)

        self.action_item = self.add_item("Start Cove", self.toggle_cove)
        self.refresh_item = self.add_item("Refresh Status", self.refresh_status)
        self.reload_item = self.add_item("Reload Caddy", self.reload_caddy)
        self.add_separator()

        self.sites_item = Gtk.MenuItem(label="Sites")
        self.sites_menu = Gtk.Menu()
        self.sites_item.set_submenu(self.sites_menu)
        self.menu.append(self.sites_item)
        self.add_separator()

        self.dashboard_item = self.add_item("Open Dashboard", lambda: open_uri(cove_url("cove.localhost")))
        self.adminer_item = self.add_item("Open Adminer", lambda: open_uri(cove_url("db.cove.localhost")))
        self.mailpit_item = self.add_item("Open Mailpit", lambda: open_uri(cove_url("mail.cove.localhost")))
        self.add_item("Open Cove Logs", lambda: open_uri("file://" + LOGS_DIR))
        self.add_item("Open Sites Folder", lambda: open_uri("file://" + SITES_DIR))
        self.add_separator()

        self.launch_item = Gtk.CheckMenuItem(label="Launch at Login")
        self.launch_item.set_active(os.path.exists(AUTOSTART_FILE))
        self.launch_item.connect("toggled", self.on_launch_toggled)
        self.menu.append(self.launch_item)

        self.version_item = self.add_item("", sensitive=False)
        self.version_item.set_no_show_all(True)
        self.add_item("Quit Cove Menu Bar", Gtk.main_quit)
        self.menu.show_all()
        self.rebuild_sites_menu()

    # --- Rendering (in place, never rebuilds the open menu) --------------

    def all_running(self):
        return self.states_known and all(self.states.get(key) for key in CORE_SERVICES)

    def running(self, key):
        return bool(self.states.get(key))

    def summary_text(self):
        if self.busy:
            return self.busy
        if not self.states_known:
            return "Cove status unavailable" if self.last_error else "Checking Cove…"
        count = sum(1 for value in self.states.values() if value)
        if self.all_running():
            return "Cove is running"
        if count == 0:
            return "Cove is stopped"
        return f"Cove: {count} of {len(self.states)} services running"

    def render(self):
        self.summary_item.set_label(self.summary_text())

        error = self.last_action_error or self.last_error
        if error:
            self.error_item.set_label("Error: " + first_line(error))
            self.error_item.show()
        else:
            self.error_item.hide()

        for key in self.service_keys:
            item = self.service_items.get(key)
            if item is None:
                continue
            state = self.states.get(key)
            text = "…" if state is None else ("Running" if state else "Stopped")
            mark = "○" if state is None else ("●" if state else "○")
            item.set_label(f"{mark}  {display_name(key)}: {text}")

        all_up = self.all_running()
        self.action_item.set_label("Stop Cove" if all_up else "Start Cove")
        self.action_item.set_sensitive(self.busy is None)
        self.refresh_item.set_sensitive(self.busy is None)
        self.reload_item.set_sensitive(self.busy is None and self.running("caddy"))
        self.dashboard_item.set_sensitive(self.running("caddy"))
        self.adminer_item.set_sensitive(self.running("caddy"))
        self.mailpit_item.set_sensitive(self.running("mailpit"))

        if self.latest_version and self.cove_version and \
                version_tuple(self.latest_version) > version_tuple(self.cove_version):
            self.version_item.set_label(f"Update Cove to v{self.latest_version}…")
            self.version_item.set_sensitive(True)
            if not getattr(self, "_upgrade_wired", False):
                self.version_item.connect("activate", lambda *_: self.run_upgrade_in_terminal())
                self._upgrade_wired = True
            self.version_item.show()
        elif self.cove_version:
            self.version_item.set_label(f"Cove v{self.cove_version}")
            self.version_item.set_sensitive(False)
            self.version_item.show()
        else:
            self.version_item.hide()

        if not self.states_known:
            icon = "cove-logo-partial"
        elif all_up:
            icon = "cove-logo"
        elif any(self.states.values()):
            icon = "cove-logo-partial"
        else:
            icon = "cove-logo-stopped"
        self.indicator.set_icon_full(icon, self.summary_text())

    def sync_service_rows(self, keys):
        """Add rows for services that appear after the first poll (php-fpm pools)."""
        if keys == self.service_keys:
            return
        for key in list(self.service_items):
            if key not in keys:
                self.menu.remove(self.service_items.pop(key))
        # New rows go above the error row, so the service block stays together.
        position = self.menu.get_children().index(self.error_item)
        for key in keys:
            if key in self.service_items:
                continue
            item = Gtk.MenuItem(label=display_name(key) + ": …")
            item.set_sensitive(False)
            item.show()
            self.menu.insert(item, position)
            self.service_items[key] = item
            position += 1
        self.service_keys = list(keys)

    # --- Status polling -------------------------------------------------

    def on_refresh_tick(self):
        self.refresh_status()
        return True

    def refresh_status(self):
        if self.busy:
            return
        threading.Thread(target=self._poll_status, daemon=True).start()

    def _poll_status(self):
        status, output, error = run_cove(["status", "--porcelain"], timeout=30)
        GLib.idle_add(self._apply_status, status, output, error)

    def _apply_status(self, status, output, error):
        if status != 0:
            self.last_error = error or first_line(output) or "Unable to read Cove status."
            self.render()
            return False
        states = {}
        version = self.cove_version
        for line in output.splitlines():
            if "=" not in line:
                continue
            key, value = line.strip().split("=", 1)
            if key == "version":
                version = value
            elif value in ("running", "stopped"):
                states[key] = value == "running"
        if not states:
            self.last_error = "Unexpected status output from Cove."
            self.render()
            return False

        keys = [key for key in CORE_SERVICES if key in states] + \
               sorted(key for key in states if key not in CORE_SERVICES)
        old_states = dict(self.states)
        self.states = states
        self.cove_version = version
        self.last_error = None
        self.sync_service_rows(keys)
        self.notify_unexpected_stops(old_states, states)
        self.states_known = True
        self.render()
        self.rebuild_sites_menu()
        return False

    # Mirrors the macOS app: a service that is newly stopped is held for one
    # more poll before it alarms, everything-stopped-at-once is treated as a
    # deliberate `cove disable`, and nothing fires within 20s of our own action.
    def notify_unexpected_stops(self, old_states, new_states):
        if not self.states_known or time.monotonic() - self.last_user_action < 20.0 \
                or not any(new_states.values()):
            self.pending_stops.clear()
            return
        still_pending = set()
        for key, running in new_states.items():
            if running:
                continue
            if old_states.get(key):
                still_pending.add(key)
            elif key in self.pending_stops:
                self.notify(f"{display_name(key)} stopped unexpectedly.")
        self.pending_stops = still_pending

    # --- Actions ---------------------------------------------------------

    def toggle_cove(self):
        if self.all_running():
            self.run_action(["disable"], "stop", "Stopping Cove…")
        else:
            self.run_action(["enable"], "start", "Starting Cove…")

    def reload_caddy(self):
        self.run_action(["reload"], "reload", "Reloading Caddy…")

    def run_action(self, args, name, busy_text, timeout=300, on_success=None):
        if self.busy:
            return
        self.busy = busy_text
        self.last_action_error = None
        self.last_user_action = time.monotonic()
        self.render()

        def work():
            status, output, error = run_cove(args, timeout)
            GLib.idle_add(self._finish_action, name, status, output, error, on_success)

        threading.Thread(target=work, daemon=True).start()

    def _finish_action(self, name, status, output, error, on_success):
        self.busy = None
        self.last_user_action = time.monotonic()
        log(f"cove {name}: exit {status}")
        if status != 0:
            self.report_failure(f"Could not {name} Cove" if name in ("start", "stop", "reload") else name,
                                error or output or f"cove {name} exited with an error.")
        elif on_success is not None:
            on_success(output)
        self.refresh_status()
        self.render()
        return False

    def report_failure(self, title, detail):
        self.last_action_error = title
        self.notify(f"{title} — {first_line(detail)}")
        log(f"{title}\n{strip_ansi(detail)}")
        self.render()

    def notify(self, body):
        log(f"notify: {body}")
        if HAVE_NOTIFY:
            try:
                Notify.Notification.new("Cove", body, os.path.join(ICON_DIR, "cove-logo.svg")).show()
                return
            except GLib.Error:
                pass
        if shutil.which("notify-send"):
            subprocess.Popen(["notify-send", "-a", "Cove", "Cove", body])

    # --- Sites submenu ----------------------------------------------------

    def list_sites(self):
        sites = []
        try:
            entries = sorted(os.listdir(SITES_DIR), key=str.lower)
        except OSError:
            return sites
        for entry in entries:
            path = os.path.join(SITES_DIR, entry)
            if not entry.endswith(".localhost") or not os.path.isdir(path):
                continue
            public = os.path.join(path, "public")
            try:
                modified = os.stat(public).st_mtime
            except OSError:
                try:
                    modified = os.stat(path).st_mtime
                except OSError:
                    modified = 0
            sites.append({
                "name": entry,
                "modified": modified,
                "wp": os.path.exists(os.path.join(public, "wp-config.php")),
            })
        return sites

    def rebuild_sites_menu(self):
        sites = self.list_sites()
        signature = [(site["name"], site["wp"], site["modified"]) for site in sites]
        if signature == self.sites_dir_mtime and self.sites_menu.get_children():
            return
        self.sites_dir_mtime = signature

        for child in self.sites_menu.get_children():
            self.sites_menu.remove(child)

        if len(sites) >= 8:
            self.add_item("Recent", sensitive=False, menu=self.sites_menu)
            for site in sorted(sites, key=lambda site: site["modified"], reverse=True)[:5]:
                self.add_site_entry(site)
            self.add_separator(self.sites_menu)

        for site in sites:
            self.add_site_entry(site)

        if sites:
            self.add_separator(self.sites_menu)
            self.sites_item.set_label(f"Sites ({len(sites)})")
        else:
            self.sites_item.set_label("Sites")

        self.add_item("New Site…", self.prompt_for_new_site, menu=self.sites_menu)
        self.sites_menu.show_all()

    def add_site_entry(self, site):
        host = site["name"]
        if not site["wp"]:
            self.add_item(host, lambda h=host: open_uri(cove_url(h)), menu=self.sites_menu)
            return
        # The panel renders this menu and never reports modifier keys, so the
        # macOS Option-key alternate becomes a two-item submenu per site.
        item = Gtk.MenuItem(label=host)
        submenu = Gtk.Menu()
        self.add_item(f"Open {host}", lambda h=host: open_uri(cove_url(h)), menu=submenu)
        self.add_item(f"Log in to {host}", lambda h=host: self.login_to_site(h), menu=submenu)
        item.set_submenu(submenu)
        self.sites_menu.append(item)

    def login_to_site(self, host):
        site_name = host[:-len(".localhost")] if host.endswith(".localhost") else host

        def opened(output):
            login_url = None
            for candidate in URL_PATTERN.findall(strip_ansi(output)):
                if host in candidate and "wp-login" in candidate:
                    login_url = candidate
            if login_url:
                open_uri(login_url)
            else:
                self.report_failure(f"Could not log in to {host}", "cove login did not return a login URL.")

        self.run_action(["login", site_name], f"log in to {host}", f"Logging in to {host}…",
                        timeout=45, on_success=opened)

    def prompt_for_new_site(self):
        dialog = Gtk.Dialog(title="New Cove Site")
        dialog.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Create", Gtk.ResponseType.OK)
        dialog.set_default_response(Gtk.ResponseType.OK)
        box = dialog.get_content_area()
        box.set_spacing(8)
        box.set_border_width(12)
        box.add(Gtk.Label(label="Creates a WordPress site at <name>.localhost.\n"
                                "Lowercase letters, numbers, and hyphens only.", xalign=0))
        entry = Gtk.Entry(placeholder_text="my-new-site", activates_default=True)
        box.add(entry)
        dialog.show_all()
        response = dialog.run()
        name = entry.get_text().strip().lower()
        dialog.destroy()
        if response != Gtk.ResponseType.OK or not name:
            return
        if not SITE_NAME_PATTERN.match(name):
            self.report_failure("Invalid site name",
                                "Site names can only contain lowercase letters, numbers, and hyphens, "
                                "and cannot begin or end with a hyphen.")
            return

        def created(_output):
            self.notify(f"{name}.localhost is ready — opening it now.")
            self.sites_dir_mtime = None
            open_uri(cove_url(f"{name}.localhost"))

        self.run_action(["add", name], f"create {name}.localhost",
                        f"Creating {name}.localhost… (takes about a minute)", timeout=240, on_success=created)

    # --- Launch at login ----------------------------------------------------

    def on_launch_toggled(self, item):
        if item.get_active():
            try:
                os.makedirs(os.path.dirname(AUTOSTART_FILE), exist_ok=True)
                with open(AUTOSTART_FILE, "w", encoding="utf-8") as handle:
                    handle.write(autostart_entry())
            except OSError as error:
                self.report_failure("Launch at Login", str(error))
        else:
            try:
                os.remove(AUTOSTART_FILE)
            except FileNotFoundError:
                pass
            except OSError as error:
                self.report_failure("Launch at Login", str(error))

    # --- Update check -------------------------------------------------------

    def on_update_tick(self):
        self.check_for_updates()
        return True

    def check_for_updates(self):
        def work():
            try:
                request = urllib.request.Request(
                    "https://github.com/anchorhost/cove/releases/latest", method="HEAD")
                with urllib.request.urlopen(request, timeout=15) as response:
                    tag = response.geturl().rstrip("/").rsplit("/", 1)[-1]
            except Exception:  # noqa: BLE001 — offline is not an error worth surfacing
                return
            if tag.startswith("v") and len(tag) > 1:
                GLib.idle_add(self._set_latest, tag[1:])

        threading.Thread(target=work, daemon=True).start()

    def _set_latest(self, version):
        self.latest_version = version
        self.render()
        return False

    # `cove upgrade` may install packages and ask questions, so it belongs in
    # a real terminal. Try the desktop's own terminal first, then common ones.
    def run_upgrade_in_terminal(self):
        self.last_user_action = time.monotonic()
        script = "cove upgrade; echo; read -r -p 'Press Enter to close.' _"
        candidates = [
            ("cosmic-term", ["--", "bash", "-lc", script]),
            ("x-terminal-emulator", ["-e", "bash", "-lc", script]),
            ("gnome-terminal", ["--", "bash", "-lc", script]),
            ("konsole", ["-e", "bash", "-lc", script]),
            ("xfce4-terminal", ["-e", f"bash -lc \"{script}\""]),
            ("alacritty", ["-e", "bash", "-lc", script]),
            ("kitty", ["bash", "-lc", script]),
            ("xterm", ["-e", "bash", "-lc", script]),
        ]
        for binary, args in candidates:
            if shutil.which(binary):
                subprocess.Popen([binary, *args], env=cove_env())
                return
        self.report_failure("Update Cove", "No terminal found. Run `cove upgrade` in a terminal.")


def autostart_entry():
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Cove Menu Bar\n"
        "Comment=Cove service status in the system tray\n"
        f"Exec={sys.executable} {os.path.join(INSTALL_DIR, 'cove-tray.py')}\n"
        f"Icon={os.path.join(INSTALL_DIR, 'cove-logo.svg')}\n"
        "Terminal=false\n"
        "X-GNOME-Autostart-enabled=true\n"
        "NoDisplay=true\n"
    )


def main():
    if "--autostart-entry" in sys.argv:
        sys.stdout.write(autostart_entry())
        return
    log("Cove Menu Bar started")
    CoveTray()
    Gtk.main()
    log("Cove Menu Bar quit")


if __name__ == "__main__":
    main()
