#!/usr/bin/env python3
"""
Wazuh Browser History Monitor
Author  : Ram Kumar G (IT Fortress)
Version : 2.4 (macOS Fix)
Platform: Windows | Linux | macOS
Browsers: Chrome, Edge, Brave, Firefox, Opera, OperaGX, Vivaldi,
          Waterfox, Tor, Chromium, Safari (macOS)
          All install types: standard, snap, flatpak

Reads browser SQLite history databases every 60 seconds.
Writes syslog-format lines to browser_history.log.
Wazuh agent picks up the log via <localfile> in ossec.conf.

No internet connections made. No external dependencies.
VT-clean: no Invoke-WebRequest, no exe patterns, no url fetch.

macOS Fixes in v2.4:
  1. _get_install_dir() now uses ~/.browser-monitor on Darwin instead
     of /root/.browser-monitor — macOS Wazuh agent runs as the
     logged-in user, not root, so /root/ is inaccessible.
  2. _get_browser_roots() on Darwin now resolves all real user home
     dirs via dscl so that Safari/Chrome paths are discovered even
     when the script is invoked from a system context.
  3. Safari shutil.copy2() wrapped with a clear PermissionError
     message guiding the user to grant Full Disk Access in
     System Settings → Privacy & Security → Full Disk Access.
  4. Safari threshold fix: raw Core Data timestamp is stored and
     compared directly — no MAC_EPOCH_DIFF subtraction on read-back.
  5. run() no_browser_profiles_found warning extended to macOS.
"""

import os
import time
import sqlite3
import shutil
import platform
import json
import logging
import socket
import tempfile
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# --- CONFIGURATION ------------------------------------------------------------
SCAN_INTERVAL = 60
LOG_FILE_NAME = "browser_history.log"

# --- CONSTANTS ----------------------------------------------------------------
CHROME_EPOCH_DIFF = 11644473600
MAC_EPOCH_DIFF    = 978307200

# --- HELPERS ------------------------------------------------------------------
def chrome_time(ts):
    """Convert Chrome/Chromium microsecond timestamp to readable string."""
    if not ts:
        return "N/A"
    try:
        dt = datetime.fromtimestamp((ts / 1_000_000) - CHROME_EPOCH_DIFF, timezone.utc).astimezone()
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts)

def firefox_time(ts):
    """Convert Firefox microsecond timestamp to readable string."""
    if not ts:
        return "N/A"
    try:
        dt = datetime.fromtimestamp(ts / 1_000_000, timezone.utc).astimezone()
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts)

def safari_time(ts):
    """Convert Safari Core Data timestamp to readable string."""
    if not ts:
        return "N/A"
    try:
        dt = datetime.fromtimestamp(ts + MAC_EPOCH_DIFF, timezone.utc).astimezone()
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts)


# --- MAIN CLASS ---------------------------------------------------------------
class BrowserMonitor:
    def __init__(self):
        self.os_type     = platform.system()
        self.hostname    = socket.gethostname()
        self.user_home   = Path.home()
        self.install_dir = self._get_install_dir()
        self.log_path    = self.install_dir / LOG_FILE_NAME
        self.state_path  = self.install_dir / ".browser_monitor_state.json"
        self.state       = self._load_state()
        self._setup_logging()

    # -- paths -----------------------------------------------------------------
    def _get_install_dir(self):
        """
        Windows -> C:\\BrowserMonitor
        Linux   -> /root/.browser-monitor  (agent runs as root)
        macOS   -> ~/.browser-monitor      (agent runs as logged-in user)

        FIX v2.4: macOS was incorrectly using /root/.browser-monitor.
        macOS Wazuh agent runs as the local user, not root. Using
        Path.home() ensures the log and state files are written to the
        correct user-owned directory that Wazuh can watch via ossec.conf.
        """
        if self.os_type == "Windows":
            path = Path("C:/BrowserMonitor")
        elif self.os_type == "Darwin":
            path = Path.home() / ".browser-monitor"
        else:
            path = Path("/root/.browser-monitor")
        path.mkdir(parents=True, exist_ok=True)
        return path

    # -- state -----------------------------------------------------------------
    def _load_state(self):
        if self.state_path.exists():
            try:
                with open(self.state_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_state(self):
        try:
            with open(self.state_path, 'w', encoding='utf-8') as f:
                json.dump(self.state, f)
        except Exception as e:
            if hasattr(self, 'logger'):
                self.logger.error("State save error: %s", e)

    # -- logging ---------------------------------------------------------------
    def _setup_logging(self):
        self.logger = logging.getLogger("BrowserMonitor")
        self.logger.setLevel(logging.INFO)
        if self.logger.handlers:
            return
        fmt = logging.Formatter(
            fmt='%(asctime)s ' + self.hostname + ' browser-monitor: %(message)s',
            datefmt='%b %d %H:%M:%S'
        )
        fh = logging.FileHandler(str(self.log_path), encoding='utf-8')
        fh.setFormatter(fmt)
        self.logger.addHandler(fh)
        self.logger.info("service_started")

    # -- all user home dirs (Linux) --------------------------------------------
    def _get_all_home_dirs(self):
        homes = set()
        homes.add(Path("/root"))
        try:
            with open("/etc/passwd", "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 6:
                        home = Path(parts[5])
                        if home.exists() and str(home).startswith("/home"):
                            homes.add(home)
        except Exception:
            pass
        return list(homes)

    # -- all user home dirs (macOS) --------------------------------------------
    def _get_all_mac_home_dirs(self):
        """
        FIX v2.4: Enumerate all real macOS user home dirs via dscl so
        Safari/browser paths are resolved correctly even when the script
        runs from a system/daemon context where Path.home() may return
        /var/root instead of the actual user's home directory.
        Falls back to Path.home() if dscl is unavailable.
        """
        homes = set()
        homes.add(Path.home())
        try:
            result = subprocess.run(
                ["dscl", ".", "-list", "/Users", "NFSHomeDirectory"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) == 2:
                    home = Path(parts[1])
                    # Skip system accounts (home dirs not under /Users)
                    if home.exists() and str(home).startswith("/Users"):
                        homes.add(home)
        except Exception:
            pass
        return list(homes)

    # -- browser root paths ----------------------------------------------------
    def _get_browser_roots(self):
        """Return list of (browser_name, username, root_path) tuples."""
        roots = []

        if self.os_type == "Windows":
            lad = os.environ.get('LOCALAPPDATA', '')
            apd = os.environ.get('APPDATA', '')
            usr = os.environ.get('USERNAME', 'Default')
            if lad:
                roots += [
                    ("Chrome",   usr, Path(lad) / "Google" / "Chrome" / "User Data"),
                    ("Edge",     usr, Path(lad) / "Microsoft" / "Edge" / "User Data"),
                    ("Brave",    usr, Path(lad) / "BraveSoftware" / "Brave-Browser" / "User Data"),
                    ("Vivaldi",  usr, Path(lad) / "Vivaldi" / "User Data"),
                    ("Chromium", usr, Path(lad) / "Chromium" / "User Data"),
                ]
            if apd:
                roots += [
                    ("Opera",    usr, Path(apd) / "Opera Software" / "Opera Stable"),
                    ("OperaGX",  usr, Path(apd) / "Opera Software" / "Opera GX Stable"),
                    ("Firefox",  usr, Path(apd) / "Mozilla" / "Firefox" / "Profiles"),
                    ("Waterfox", usr, Path(apd) / "Waterfox" / "Profiles"),
                    ("Tor",      usr, Path(apd) / "tor project" / "Tor Browser" / "Browser" / "TorBrowser" / "Data" / "Browser" / "profile.default"),
                ]

        elif self.os_type == "Darwin":
            # FIX v2.4: Iterate all real user home dirs instead of only
            # Path.home(). This handles daemon/root execution contexts and
            # multi-user Macs correctly.
            for user_home in self._get_all_mac_home_dirs():
                lib = user_home / "Library" / "Application Support"
                usr = user_home.name
                roots += [
                    ("Chrome",   usr, lib / "Google" / "Chrome"),
                    ("Edge",     usr, lib / "Microsoft Edge"),
                    ("Brave",    usr, lib / "BraveSoftware" / "Brave-Browser"),
                    ("Vivaldi",  usr, lib / "Vivaldi"),
                    ("Opera",    usr, lib / "com.operasoftware.Opera"),
                    ("OperaGX",  usr, lib / "com.operasoftware.OperaGX"),
                    ("Firefox",  usr, lib / "Firefox" / "Profiles"),
                    ("Waterfox", usr, lib / "Waterfox" / "Profiles"),
                    ("Chromium", usr, lib / "Chromium"),
                    # Safari path: ~/Library/Safari (requires Full Disk Access)
                    ("Safari",   usr, user_home / "Library" / "Safari"),
                ]

        elif self.os_type == "Linux":
            for home in self._get_all_home_dirs():
                u   = home.name
                cfg = home / ".config"
                moz = home / ".mozilla"
                snap = home / "snap"
                flat = home / ".var" / "app"

                roots += [
                    # ── Standard installs ──────────────────────────────────
                    ("Chrome",   u, cfg / "google-chrome"),
                    ("Chrome",   u, cfg / "google-chrome-beta"),
                    ("Chrome",   u, cfg / "google-chrome-unstable"),
                    ("Chromium", u, cfg / "chromium"),
                    ("Edge",     u, cfg / "microsoft-edge"),
                    ("Edge",     u, cfg / "microsoft-edge-beta"),
                    ("Edge",     u, cfg / "microsoft-edge-dev"),
                    ("Brave",    u, cfg / "BraveSoftware" / "Brave-Browser"),
                    ("Brave",    u, cfg / "BraveSoftware" / "Brave-Browser-Beta"),
                    ("Brave",    u, cfg / "BraveSoftware" / "Brave-Browser-Nightly"),
                    ("Vivaldi",  u, cfg / "vivaldi"),
                    ("Opera",    u, cfg / "opera"),
                    ("OperaGX",  u, cfg / "opera-gx-stable"),
                    ("Firefox",  u, moz / "firefox"),
                    ("Waterfox", u, home / ".waterfox"),
                    ("Tor",      u, home / ".tor-browser" / "app" / "Browser" / "TorBrowser" / "Data" / "Browser" / "profile.default"),

                    # ── Snap installs ──────────────────────────────────────
                    ("Firefox",  u, snap / "firefox" / "common" / ".mozilla" / "firefox"),
                    ("Chromium", u, snap / "chromium" / "current" / ".config" / "chromium"),
                    ("Chrome",   u, snap / "google-chrome" / "current" / ".config" / "google-chrome"),
                    ("Edge",     u, snap / "microsoft-edge" / "current" / ".config" / "microsoft-edge"),
                    ("Brave",    u, snap / "brave" / "current" / ".config" / "BraveSoftware" / "Brave-Browser"),
                    ("Opera",    u, snap / "opera" / "current" / ".config" / "opera"),
                    ("Vivaldi",  u, snap / "vivaldi" / "current" / ".config" / "vivaldi"),

                    # ── Flatpak installs ───────────────────────────────────
                    ("Firefox",  u, flat / "org.mozilla.firefox" / ".mozilla" / "firefox"),
                    ("Waterfox", u, flat / "net.waterfox.waterfox" / ".waterfox"),
                    ("Chrome",   u, flat / "com.google.Chrome" / ".config" / "google-chrome"),
                    ("Chromium", u, flat / "org.chromium.Chromium" / ".config" / "chromium"),
                    ("Edge",     u, flat / "com.microsoft.Edge" / ".config" / "microsoft-edge"),
                    ("Brave",    u, flat / "com.brave.Browser" / ".config" / "BraveSoftware" / "Brave-Browser"),
                    ("Opera",    u, flat / "com.opera.Opera" / ".config" / "opera"),
                    ("Vivaldi",  u, flat / "com.vivaldi.Vivaldi" / ".config" / "vivaldi"),
                    ("Tor",      u, flat / "com.github.micahflee.torbrowser-launcher" / ".tor-browser" / "app" / "Browser" / "TorBrowser" / "Data" / "Browser" / "profile.default"),
                ]
        return roots

    # -- profile enumeration ---------------------------------------------------
    def _find_profiles(self):
        profiles = []
        seen_dbs = set()

        for name, username, root in self._get_browser_roots():
            if not root.exists():
                continue

            if name == "Safari":
                db = root / "History.db"
                if db.exists() and str(db) not in seen_dbs:
                    seen_dbs.add(str(db))
                    profiles.append({"browser": "Safari", "profile": "Default",
                                     "username": username, "db": db, "kind": "safari"})
                continue

            # Firefox-family (places.sqlite)
            if name in ("Firefox", "Waterfox", "Tor"):
                if name == "Tor" and (root / "places.sqlite").exists():
                    db = root / "places.sqlite"
                    if str(db) not in seen_dbs:
                        seen_dbs.add(str(db))
                        profiles.append({"browser": name, "profile": "default",
                                         "username": username, "db": db, "kind": "firefox"})
                    continue
                try:
                    for d in root.iterdir():
                        if d.is_dir() and (d / "places.sqlite").exists():
                            db = d / "places.sqlite"
                            if str(db) not in seen_dbs:
                                seen_dbs.add(str(db))
                                profiles.append({"browser": name, "profile": d.name,
                                                 "username": username, "db": db, "kind": "firefox"})
                except PermissionError:
                    pass
                continue

            # Chromium-family (History)
            candidates = [("Default", root / "Default")] + \
                         [(d.name, d) for d in root.glob("Profile *") if d.is_dir()]
            for subdir_name, subdir_path in candidates:
                db = subdir_path / "History"
                if db.exists() and str(db) not in seen_dbs:
                    seen_dbs.add(str(db))
                    profiles.append({"browser": name, "profile": subdir_name,
                                     "username": username, "db": db, "kind": "chrome"})
        return profiles

    # -- extension monitoring --------------------------------------------------
    def _scan_extensions(self, profile):
        exts = {}
        if profile["kind"] == "chrome":
            ext_dir = profile["db"].parent / "Extensions"
            if ext_dir.exists():
                for eid in ext_dir.iterdir():
                    if not eid.is_dir():
                        continue
                    versions = sorted([v for v in eid.iterdir() if v.is_dir()],
                                      key=lambda x: x.name, reverse=True)
                    if not versions:
                        continue
                    manifest = versions[0] / "manifest.json"
                    if manifest.exists():
                        try:
                            with open(manifest, 'r', encoding='utf-8', errors='ignore') as f:
                                d = json.load(f)
                                n = d.get('name', 'Unknown')
                                if n.startswith("__MSG_"):
                                    n = f"{n} (Localized)"
                                exts[eid.name] = {"name": n, "version": d.get('version', '0')}
                        except Exception:
                            pass
        elif profile["kind"] == "firefox":
            ejson = profile["db"].parent / "extensions.json"
            if ejson.exists():
                try:
                    with open(ejson, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        for addon in data.get('addons', []):
                            if addon.get('active', False):
                                n = addon.get('defaultLocale', {}).get('name') or addon.get('name', 'Unknown')
                                exts[addon.get('id', '?')] = {"name": n, "version": addon.get('version', '0')}
                except Exception:
                    pass
        return exts

    def _process_extensions(self, profile):
        current = self._scan_extensions(profile)
        if not current:
            return
        key   = f"ext_{profile['username']}_{profile['browser']}_{profile['profile']}"
        known = self.state.get(key, {})
        for eid, info in current.items():
            if eid not in known or known[eid]["version"] != info["version"]:
                self.logger.info(
                    "[Extension] %s %s %s \"%s\" (%s) v%s",
                    profile['username'], profile['browser'], profile['profile'],
                    info['name'], eid, info['version']
                )
        self.state[key] = current

    # -- history processing ----------------------------------------------------
    def _process_history(self, profile):
        state_key      = f"hist_{profile['username']}_{profile['browser']}_{profile['profile']}"
        last_scan_time = self.state.get(state_key, 0)

        safe_key = state_key.replace('/', '_').replace(' ', '_')
        tmp = Path(tempfile.gettempdir()) / f"bhm_{safe_key}.sqlite"

        # FIX v2.4: Catch PermissionError on Safari copy and emit a
        # clear actionable log message instead of silently returning.
        # Safari's History.db is TCC-protected on macOS Sonoma+.
        # Resolution: System Settings → Privacy & Security →
        # Full Disk Access → add Terminal (or Python binary).
        try:
            shutil.copy2(profile["db"], tmp)
        except PermissionError:
            if profile["browser"] == "Safari":
                self.logger.error(
                    "Safari history access denied for user '%s'. "
                    "Grant Full Disk Access to Terminal/Python in: "
                    "System Settings > Privacy & Security > Full Disk Access",
                    profile["username"]
                )
            else:
                self.logger.error(
                    "Permission denied reading %s history for user '%s': %s",
                    profile["browser"], profile["username"], profile["db"]
                )
            return
        except Exception as e:
            self.logger.error(
                "Cannot copy %s DB for user '%s': %s",
                profile["browser"], profile["username"], e
            )
            return

        conn    = None
        new_max = last_scan_time
        try:
            conn = sqlite3.connect(str(tmp))
            cur  = conn.cursor()

            if profile["kind"] == "chrome":
                cur.execute(
                    "SELECT last_visit_time, url, title FROM urls "
                    "WHERE last_visit_time > ? ORDER BY last_visit_time ASC",
                    (last_scan_time,)
                )
            elif profile["kind"] == "firefox":
                cur.execute(
                    "SELECT h.visit_date, p.url, p.title "
                    "FROM moz_historyvisits h "
                    "JOIN moz_places p ON h.place_id = p.id "
                    "WHERE h.visit_date > ? ORDER BY h.visit_date ASC",
                    (last_scan_time,)
                )
            elif profile["kind"] == "safari":
                # FIX v2.4: Store and compare raw Safari Core Data timestamps
                # directly. Previous code subtracted MAC_EPOCH_DIFF before
                # storing, causing the threshold to be a Unix timestamp while
                # the DB column holds a Core Data timestamp — mismatch skipped
                # all rows after the first scan.
                threshold = last_scan_time if last_scan_time > 0 else 0
                cur.execute(
                    "SELECT v.visit_time, i.url, v.title "
                    "FROM history_visits v "
                    "JOIN history_items i ON v.history_item = i.id "
                    "WHERE v.visit_time > ? ORDER BY v.visit_time ASC",
                    (threshold,)
                )

            for (raw_time, url, title) in cur.fetchall():
                if raw_time > new_max:
                    new_max = raw_time
                if profile["kind"] == "chrome":
                    readable = chrome_time(raw_time)
                elif profile["kind"] == "firefox":
                    readable = firefox_time(raw_time)
                else:
                    readable = safari_time(raw_time)
                clean_title = (title or "No Title").replace('\n', ' ').replace('\r', '')
                self.logger.info(
                    "%s %s %s %s %s %s",
                    readable, profile['browser'], profile['username'],
                    profile['profile'], url, clean_title
                )

        except Exception as e:
            self.logger.error("DB query error [%s %s %s]: %s",
                              profile['username'], profile['browser'], profile['profile'], e)
        finally:
            if conn:
                conn.close()
            try:
                tmp.unlink()
            except Exception:
                pass

        self.state[state_key] = new_max

    # -- main loop -------------------------------------------------------------
    def run(self):
        try:
            while True:
                profiles = self._find_profiles()
                # FIX v2.4: Extended no_browser_profiles_found warning to macOS
                if not profiles and self.os_type in ("Linux", "Darwin"):
                    self.logger.warning("no_browser_profiles_found")
                for profile in profiles:
                    self._process_extensions(profile)
                    self._process_history(profile)
                self._save_state()
                time.sleep(SCAN_INTERVAL)
        except KeyboardInterrupt:
            self.logger.info("service_stopped")


if __name__ == "__main__":
    BrowserMonitor().run()
