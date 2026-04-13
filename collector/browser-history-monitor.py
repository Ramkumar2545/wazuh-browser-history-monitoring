#!/usr/bin/env python3
"""
Wazuh Browser History Monitor
Author  : Ram Kumar G (IT Fortress)
Version : 2.0
Platform: Windows | Linux | macOS
Browsers: Chrome, Edge, Brave, Firefox, Opera, Opera GX, Safari (macOS)

Reads browser SQLite history databases every 60 seconds.
Writes syslog-format lines to browser_history.log.
Wazuh agent picks up the log via <localfile> in ossec.conf.

No internet connections made. No external dependencies.
VT-clean: no Invoke-WebRequest, no exe patterns, no url fetch.
"""

import os
import sys
import time
import sqlite3
import shutil
import platform
import json
import logging
import socket
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# ─── CONFIGURATION ────────────────────────────────────────────────────────────
SCAN_INTERVAL = 60          # seconds between scans
LOG_FILE_NAME = "browser_history.log"

# ─── CONSTANTS ────────────────────────────────────────────────────────────────
CHROME_EPOCH_DIFF = 11644473600   # Chrome timestamps are microseconds since 1601-01-01
MAC_EPOCH_DIFF    = 978307200     # Safari timestamps are seconds since 2001-01-01

# ─── HELPERS ──────────────────────────────────────────────────────────────────
def chrome_time(ts):
    """Convert Chrome/Chromium microsecond timestamp to readable string."""
    if not ts: return "N/A"
    try:
        dt = datetime.fromtimestamp((ts / 1_000_000) - CHROME_EPOCH_DIFF, timezone.utc).astimezone()
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return str(ts)

def firefox_time(ts):
    """Convert Firefox microsecond timestamp to readable string."""
    if not ts: return "N/A"
    try:
        dt = datetime.fromtimestamp(ts / 1_000_000, timezone.utc).astimezone()
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return str(ts)

def safari_time(ts):
    """Convert Safari Core Data timestamp to readable string."""
    if not ts: return "N/A"
    try:
        dt = datetime.fromtimestamp(ts + MAC_EPOCH_DIFF, timezone.utc).astimezone()
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return str(ts)


# ─── MAIN CLASS ───────────────────────────────────────────────────────────────
class BrowserMonitor:
    def __init__(self):
        self.os_type   = platform.system()   # 'Windows', 'Linux', 'Darwin'
        self.hostname  = socket.gethostname()
        self.user_home = Path.home()
        self.install_dir = self._get_install_dir()
        self.log_path    = self.install_dir / LOG_FILE_NAME
        self.state_path  = self.user_home / ".browser_monitor_state.json"
        self.state       = self._load_state()
        self._setup_logging()

    # ── paths ──────────────────────────────────────────────────────────────────
    def _get_install_dir(self):
        """
        Determine where to write the log file.
        Windows  → C:\BrowserMonitor  (shared, Wazuh agent watches it)
        Linux    → ~/.browser-monitor
        macOS    → ~/.browser-monitor
        """
        if self.os_type == "Windows":
            path = Path("C:/BrowserMonitor")
        else:
            path = Path.home() / ".browser-monitor"
        path.mkdir(parents=True, exist_ok=True)
        return path

    # ── state persistence ──────────────────────────────────────────────────────
    def _load_state(self):
        if self.state_path.exists():
            try:
                with open(self.state_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_state(self):
        try:
            with open(self.state_path, 'w', encoding='utf-8') as f:
                json.dump(self.state, f)
        except Exception as e:
            if hasattr(self, 'logger'):
                self.logger.error(f"State save error: {e}")

    # ── logging ────────────────────────────────────────────────────────────────
    def _setup_logging(self):
        """
        Syslog-style format: 'MMM DD HH:MM:SS hostname browser-monitor: message'
        This is what the Wazuh decoder expects.
        """
        self.logger = logging.getLogger("BrowserMonitor")
        self.logger.setLevel(logging.INFO)
        # Avoid duplicate handlers on re-init
        if self.logger.handlers:
            return
        fmt  = logging.Formatter(
            fmt='%(asctime)s ' + self.hostname + ' browser-monitor: %(message)s',
            datefmt='%b %d %H:%M:%S'
        )
        fh = logging.FileHandler(str(self.log_path), encoding='utf-8')
        fh.setFormatter(fmt)
        self.logger.addHandler(fh)
        self.logger.info("service_started")

    # ── browser profile discovery ──────────────────────────────────────────────
    def _get_browser_roots(self):
        """
        Returns list of (browser_name, root_path) tuples for all supported browsers
        on the current OS.
        """
        roots = []
        if self.os_type == "Windows":
            lad = os.environ.get('LOCALAPPDATA', '')
            apd = os.environ.get('APPDATA', '')
            if lad:
                roots += [
                    ("Chrome",   Path(lad) / r"Google\Chrome\User Data"),
                    ("Edge",     Path(lad) / r"Microsoft\Edge\User Data"),
                    ("Brave",    Path(lad) / r"BraveSoftware\Brave-Browser\User Data"),
                ]
            if apd:
                roots += [
                    ("Opera",    Path(apd) / r"Opera Software\Opera Stable"),
                    ("OperaGX",  Path(apd) / r"Opera Software\Opera GX Stable"),
                    ("Firefox",  Path(apd) / r"Mozilla\Firefox\Profiles"),
                ]

        elif self.os_type == "Darwin":
            lib = self.user_home / "Library/Application Support"
            roots += [
                ("Chrome",   lib / "Google/Chrome"),
                ("Edge",     lib / "Microsoft Edge"),
                ("Brave",    lib / "BraveSoftware/Brave-Browser"),
                ("Firefox",  lib / "Firefox/Profiles"),
                ("Opera",    lib / "com.operasoftware.Opera"),
                ("Safari",   self.user_home / "Library/Safari"),
            ]

        elif self.os_type == "Linux":
            cfg = self.user_home / ".config"
            moz = self.user_home / ".mozilla"
            roots += [
                ("Chrome",    cfg / "google-chrome"),
                ("Edge",      cfg / "microsoft-edge"),
                ("Brave",     cfg / "BraveSoftware/Brave-Browser"),
                ("Chromium",  cfg / "chromium"),
                ("Opera",     cfg / "opera"),
                ("Firefox",   moz / "firefox"),
            ]
        return roots

    def _find_profiles(self):
        """
        Walk each browser root and enumerate all profiles.
        Returns list of profile dicts.
        """
        profiles = []
        for name, root in self._get_browser_roots():
            if not root.exists():
                continue

            if name == "Safari":
                db = root / "History.db"
                if db.exists():
                    profiles.append({"browser": "Safari", "profile": "Default",
                                     "db": db, "kind": "safari"})
                continue

            if name == "Firefox":
                for d in root.iterdir():
                    if d.is_dir() and (d / "places.sqlite").exists():
                        profiles.append({"browser": "Firefox", "profile": d.name,
                                         "db": d / "places.sqlite", "kind": "firefox"})
                continue

            # Chromium-family
            for subdir_name, subdir_path in [("Default", root / "Default")] + \
                                             [(d.name, d) for d in root.glob("Profile *") if d.is_dir()]:
                db = subdir_path / "History"
                if db.exists():
                    profiles.append({"browser": name, "profile": subdir_name,
                                     "db": db, "kind": "chrome"})

        return profiles

    # ── extension monitoring ───────────────────────────────────────────────────
    def _scan_extensions(self, profile):
        exts = {}
        if profile["kind"] == "chrome":
            ext_dir = profile["db"].parent / "Extensions"
            if ext_dir.exists():
                for eid in ext_dir.iterdir():
                    if not eid.is_dir(): continue
                    versions = sorted([v for v in eid.iterdir() if v.is_dir()],
                                      key=lambda x: x.name, reverse=True)
                    if not versions: continue
                    manifest = versions[0] / "manifest.json"
                    if manifest.exists():
                        try:
                            with open(manifest, 'r', encoding='utf-8', errors='ignore') as f:
                                d = json.load(f)
                                n = d.get('name', 'Unknown')
                                if n.startswith("__MSG_"): n = f"{n} (Localized)"
                                exts[eid.name] = {"name": n, "version": d.get('version', '0')}
                        except:
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
                except:
                    pass
        return exts

    def _process_extensions(self, profile):
        current = self._scan_extensions(profile)
        if not current: return
        key = f"ext_{profile['browser']}_{profile['profile']}"
        known  = self.state.get(key, {})
        for eid, info in current.items():
            if eid not in known or known[eid]["version"] != info["version"]:
                self.logger.info(
                    f"[Extension] {profile['browser']} "
                    f"{profile['profile']} \"{info['name']}\" "
                    f"({eid}) v{info['version']}"
                )
        self.state[key] = current

    # ── history processing ─────────────────────────────────────────────────────
    def _process_history(self, profile):
        state_key      = f"hist_{profile['browser']}_{profile['profile']}"
        last_scan_time = self.state.get(state_key, 0)

        # Copy DB to temp to avoid locked-file issues (browser may be open)
        tmp = Path(tempfile.gettempdir()) / f"bhm_{state_key.replace('/', '_')}.sqlite"
        try:
            shutil.copy2(profile["db"], tmp)
        except Exception:
            return

        conn = None
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
                threshold = (last_scan_time - MAC_EPOCH_DIFF) if last_scan_time > 0 else 0
                cur.execute(
                    "SELECT v.visit_time, i.url, v.title "
                    "FROM history_visits v "
                    "JOIN history_items i ON v.history_item = i.id "
                    "WHERE v.visit_time > ? ORDER BY v.visit_time ASC",
                    (threshold,)
                )

            rows = cur.fetchall()
            for (raw_time, url, title) in rows:
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
                    f"{readable} {profile['browser']} "
                    f"{profile['profile']} {url} {clean_title}"
                )

        except Exception as e:
            self.logger.error(f"DB query error [{profile['browser']} {profile['profile']}]: {e}")
        finally:
            if conn: conn.close()
            try: tmp.unlink()
            except: pass

        self.state[state_key] = new_max

    # ── main loop ──────────────────────────────────────────────────────────────
    def run(self):
        try:
            while True:
                for profile in self._find_profiles():
                    self._process_extensions(profile)
                    self._process_history(profile)
                self._save_state()
                time.sleep(SCAN_INTERVAL)
        except KeyboardInterrupt:
            self.logger.info("service_stopped")


if __name__ == "__main__":
    BrowserMonitor().run()
