from __future__ import annotations
import os
import platform
import re
import socket
import sqlite3
import subprocess
import threading
import time
import csv
import logging
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from functools import wraps
from io import StringIO
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, session, send_from_directory, url_for
from werkzeug.security import check_password_hash, generate_password_hash

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import ARP, Ether, conf, srp, sniff, get_if_list, get_if_addr

    conf.verb = 0
    SCAPY_AVAILABLE = True
    SCAPY_ERROR = ""
except Exception as scapy_import_error:
    ARP = Ether = srp = get_if_list = get_if_addr = None
    SCAPY_AVAILABLE = False
    SCAPY_ERROR = str(scapy_import_error)


BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "netpulse.db"
IS_WINDOWS = platform.system() == "Windows"
MAX_SCAN_ADDRESSES = int(os.environ.get("NETPULSE_MAX_SCAN_ADDRESSES", "4096"))
PING_WORKERS = int(os.environ.get("NETPULSE_PING_WORKERS", "128"))
ARP_SCAN_TIMEOUT = float(os.environ.get("NETPULSE_ARP_SCAN_TIMEOUT", "2"))
SQLITE_TIMEOUT_SECONDS = int(os.environ.get("NETPULSE_SQLITE_TIMEOUT_SECONDS", "30"))
SCAN_LOCK = threading.Lock()
# Traffic monitoring globals
TRAFFIC_COUNTERS: dict[str, int] = {}
TRAFFIC_LOCK = threading.Lock()
TRAFFIC_FLUSH_INTERVAL = int(os.environ.get("NETPULSE_TRAFFIC_FLUSH_SECONDS", "30"))
TRAFFIC_MONITOR_ENABLED = os.environ.get("NETPULSE_ENABLE_TRAFFIC_MONITOR", "1") == "1" and SCAPY_AVAILABLE


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key")

    ensure_project_layout()
    init_db()
    # Start background traffic monitoring if available
    try:
        start_traffic_monitoring()
    except Exception:
        logging.exception("Failed to start traffic monitoring thread")

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.get("/<path:filename>")
    def root_asset(filename: str):
        if filename != "SNMS.png":
            return jsonify({"ok": False, "message": "Not found."}), 404
        return send_from_directory(BASE_DIR, filename)

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html", user=session.get("user_email"))

    @app.post("/api/login")
    def login():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip().lower()
        password = payload.get("password") or ""

        if not email or not password:
            return jsonify({"ok": False, "message": "Email and password are required."}), 400

        user = query_one("SELECT id, email, password_hash FROM users WHERE email = ?", (email,))
        if user is None or not check_password_hash(user["password_hash"], password):
            return jsonify({"ok": False, "message": "Invalid email or password."}), 401

        session["user_id"] = user["id"]
        session["user_email"] = user["email"]
        return jsonify({"ok": True, "redirect": url_for("dashboard")})

    @app.post("/api/logout")
    def logout():
        session.clear()
        return jsonify({"ok": True, "redirect": url_for("index")})

    @app.get("/api/summary")
    @login_required
    def summary():
        remove_scan_devices_not_on_current_network()
        network_info = get_current_network_info()
        if not network_info:
            return jsonify(
                {
                    "totalDevices": 0,
                    "activeDevices": 0,
                    "offlineDevices": 0,
                    "networkHealth": "0%",
                    "latency": "0ms",
                    "traffic": "0GB",
                    "alert": build_alert(0, 0, 0),
                    "updatedAt": utc_now(),
                }
            )

        network_id = network_info["network_id"]
        devices = query_all(
            "SELECT status, latency_ms, traffic_gb FROM devices WHERE network_id = ?",
            (network_id,),
        )
        online = sum(1 for device in devices if device["status"] == "Online")
        offline = sum(1 for device in devices if device["status"] == "Offline")
        total = online + offline
        online_devices = [device for device in devices if device["status"] == "Online"]
        avg_latency = round(sum(device["latency_ms"] for device in online_devices) / online) if online else 0
        total_traffic = round(sum(device["traffic_gb"] for device in devices), 2)
        health = round((online / total) * 100) if total else 0

        return jsonify(
            {
                "totalDevices": total,
                "activeDevices": online,
                "offlineDevices": offline,
                "networkHealth": f"{health}%",
                "latency": f"{avg_latency}ms",
                "traffic": format_traffic(total_traffic),
                "alert": build_alert(avg_latency, offline, total),
                "updatedAt": utc_now(),
            }
        )

    @app.get("/api/devices")
    @login_required
    def devices():
        remove_scan_devices_not_on_current_network()
        network_info = get_current_network_info()
        if not network_info:
            return jsonify({"devices": []})

        rows = query_all(
            """
            SELECT id, name, status, ip_address, mac_address, device_type, location, latency_ms, traffic_gb, first_seen, last_seen
            FROM devices
            WHERE network_id = ?
            ORDER BY id
            """,
            (network_info["network_id"],),
        )
        return jsonify({"devices": [dict(row) for row in rows]})

    @app.post("/api/scan")
    @login_required
    def api_scan():
        return jsonify(scan_local_network())

    # FIX 5: Added login_required to protect internal network data
    @app.get("/scan")
    @login_required
    def simple_scan():
        return jsonify([{"ip": ip, "mac": mac} for ip, mac in read_arp_table().items()])

    return app


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "message": "Login required."}), 401
            return redirect(url_for("index"))
        return view(*args, **kwargs)

    return wrapped_view


def get_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE, timeout=SQLITE_TIMEOUT_SECONDS)
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {SQLITE_TIMEOUT_SECONDS * 1000}")
    return connection


def query_one(sql: str, params: tuple = ()):
    with closing(get_db()) as db:
        return db.execute(sql, params).fetchone()


def query_all(sql: str, params: tuple = ()):
    with closing(get_db()) as db:
        return db.execute(sql, params).fetchall()


def init_db() -> None:
    with closing(get_db()) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        ensure_device_table(db)

        user_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count == 0:
            db.execute(
                "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                ("admin@netpulse.local", generate_password_hash("admin123"), utc_now()),
            )

        device_count = db.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        if device_count == 0:
            seed_devices(db)

        db.commit()


def ensure_device_table(db: sqlite3.Connection) -> None:
    table_exists = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='devices'"
    ).fetchone()

    if not table_exists:
        create_devices_table(db)
        return

    columns = {row[1] for row in db.execute("PRAGMA table_info(devices)").fetchall()}
    required_columns = {"mac_address", "source", "status", "first_seen", "last_seen", "network_id"}
    if not required_columns.issubset(columns) or not has_unique_mac_network_index(db):
        migrate_device_table(db)
    else:
        create_unique_mac_network_index(db)


def create_devices_table(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        CREATE TABLE devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('Online', 'Offline')),
            ip_address TEXT NOT NULL,
            mac_address TEXT NOT NULL,
            device_type TEXT NOT NULL,
            location TEXT NOT NULL,
            latency_ms INTEGER NOT NULL DEFAULT 0,
            traffic_gb REAL NOT NULL DEFAULT 0,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            network_id TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'demo'
        );
        """
    )
    create_unique_mac_network_index(db)


def has_unique_mac_network_index(db: sqlite3.Connection) -> bool:
    for row in db.execute("PRAGMA index_list('devices')").fetchall():
        index_name = row[1]
        if row[2] != 1:
            continue
        index_columns = [column[2] for column in db.execute(f"PRAGMA index_info('{index_name}')").fetchall()]
        if set(index_columns) == {"mac_address", "network_id"}:
            return True
    return False


def create_unique_mac_network_index(db: sqlite3.Connection) -> None:
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_mac_network ON devices (mac_address, network_id)")


def migrate_device_table(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS devices_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('Online', 'Offline')),
            ip_address TEXT NOT NULL,
            mac_address TEXT NOT NULL,
            device_type TEXT NOT NULL,
            location TEXT NOT NULL,
            latency_ms INTEGER NOT NULL DEFAULT 0,
            traffic_gb REAL NOT NULL DEFAULT 0,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            network_id TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'demo'
        );
        """
    )

    old_columns = [row[1] for row in db.execute("PRAGMA table_info(devices)").fetchall()]
    if old_columns:
        rows = db.execute("SELECT * FROM devices").fetchall()
        for row in rows:
            def row_value(key, default=None):
                return row[key] if key in row.keys() and row[key] is not None else default

            ip_address = row_value("ip_address", "")
            raw_mac = row_value("mac_address", "")
            mac_address = raw_mac.lower().replace(":", "-") if raw_mac else f"unknown-{ip_address}"
            if not mac_address:
                mac_address = f"unknown-{ip_address}"

            first_seen = row_value("first_seen") or row_value("last_seen") or utc_now()
            last_seen = row_value("last_seen") or utc_now()
            network_id = row_value("network_id", "demo")
            source = row_value("source", "demo")
            status = row_value("status", "Offline")
            name = row_value("name", f"Device {ip_address}")
            device_type = row_value("device_type", "Host")
            location = row_value("location", "Local network")
            latency_ms = row_value("latency_ms", 0)
            traffic_gb = row_value("traffic_gb", 0.0)

            db.execute(
                """
                INSERT OR IGNORE INTO devices_new
                (name, status, ip_address, mac_address, device_type, location, latency_ms, traffic_gb, first_seen, last_seen, network_id, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    status,
                    ip_address,
                    mac_address,
                    device_type,
                    location,
                    latency_ms,
                    traffic_gb,
                    first_seen,
                    last_seen,
                    network_id,
                    source,
                ),
            )

    db.execute("DROP TABLE devices")
    db.execute("ALTER TABLE devices_new RENAME TO devices")
    create_unique_mac_network_index(db)


def seed_devices(db: sqlite3.Connection) -> None:
    devices = [
        ("Core Router", "Online", "192.168.1.1", None, "Router", "Main Rack", 8, 280.4),
        ("Web Server", "Online", "192.168.1.5", None, "Server", "Data Center", 12, 512.9),
        ("Edge Firewall", "Online", "192.168.1.10", None, "Firewall", "Gateway", 6, 134.2),
        ("Access Switch", "Offline", "192.168.1.20", None, "Switch", "Floor 1", 0, 75.0),
    ]
    db.executemany(
        """
        INSERT INTO devices
        (name, status, ip_address, mac_address, device_type, location, latency_ms, traffic_gb, first_seen, last_seen, network_id, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                name,
                status,
                ip,
                mac or f"demo-{ip}",
                kind,
                location,
                latency,
                traffic,
                utc_now(),
                utc_now(),
                "demo",
                "demo",
            )
            for name, status, ip, mac, kind, location, latency, traffic in devices
        ],
    )


def get_default_gateway_ip() -> str | None:
    if IS_WINDOWS:
        output = run_command(["ipconfig"])
        match = re.search(r"Default Gateway[^\r\n:]*:\s*([\d.]+)", output)
        if match:
            return match.group(1).strip()
        output = run_command(["route", "PRINT", "0.0.0.0"])
        match = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)", output)
        if match:
            return match.group(1).strip()
    else:
        output = run_command(["ip", "route"])
        match = re.search(r"default via ([\d.]+)", output)
        if match:
            return match.group(1).strip()
        output = run_command(["netstat", "-rn"])
        match = re.search(r"default\s+([\d.]+)", output)
        if match:
            return match.group(1).strip()
    return None


def get_gateway_mac(gateway_ip: str) -> str | None:
    arp_entries = read_arp_table()
    if gateway_ip in arp_entries:
        return arp_entries[gateway_ip]

    if not SCAPY_AVAILABLE:
        return None

    interfaces = get_local_interfaces()
    if not interfaces:
        return None

    iface = get_scapy_interface(interfaces[0]["scan_network"])
    if not iface:
        return None

    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway_ip)
        answered, _ = srp(packet, timeout=ARP_SCAN_TIMEOUT, retry=1, iface=iface, verbose=False)
        for _, received in answered:
            mac_address = getattr(received, "hwsrc", "").lower().replace(":", "-")
            if mac_address:
                return mac_address
    except Exception:
        pass

    return None


def get_current_network_info() -> dict[str, str] | None:
    gateway_ip = get_default_gateway_ip()
    if not gateway_ip:
        return None

    gateway_mac = get_gateway_mac(gateway_ip)
    network_id = f"{gateway_ip}|{gateway_mac}" if gateway_mac else gateway_ip
    return {
        "gateway_ip": gateway_ip,
        "gateway_mac": gateway_mac or "",
        "network_id": network_id,
    }


def scan_local_network() -> dict:
    if not SCAN_LOCK.acquire(blocking=False):
        network_info = get_current_network_info()
        network_id = network_info["network_id"] if network_info else None
        return {
            "ok": False,
            "message": "A network scan is already running. Please wait for it to finish.",
            "devicesFound": count_online_devices(network_id),
            "offlineDevices": count_offline_devices(network_id),
            "scannedAt": utc_now(),
        }

    try:
        return run_network_scan()
    finally:
        SCAN_LOCK.release()


def run_network_scan() -> dict:
    interfaces = get_local_interfaces()
    network_info = get_current_network_info()
    if not interfaces or not network_info:
        clear_scan_devices()
        return {"ok": False, "message": "No active IPv4 network found.", "devicesFound": 0}

    current_network_id = network_info["network_id"]
    ping_results: dict[str, int] = {}
    arp_scan_entries: dict[str, str] = {}
    full_networks: list[IPv4Network] = []
    scan_networks: list[IPv4Network] = []
    local_ips: set[str] = set()

    for interface in interfaces:
        full_networks.append(interface["full_network"])
        scan_networks.append(interface["scan_network"])
        local_ips.add(interface["ip_address"])
        arp_scan_entries.update(arp_scan_network(interface["scan_network"]))
        ping_results.update(ping_network(interface["scan_network"]))

    arp_entries = read_arp_table()
    discovered_ips = sorted(
        {
            ip_address
            for ip_address in set(arp_scan_entries) | set(ping_results) | set(arp_entries) | local_ips
            if is_allowed_discovered_ip(ip_address, full_networks, scan_networks)
        },
        key=ip_sort_key,
    )

    with closing(get_db()) as db:
        db.execute(
            "UPDATE devices SET status = 'Offline', latency_ms = 0 WHERE network_id = ?",
            (current_network_id,),
        )

        for ip_address in discovered_ips:
            raw_mac = arp_scan_entries.get(ip_address) or arp_entries.get(ip_address) or ""
            mac_address = raw_mac.lower().replace(":", "-") if raw_mac else f"unknown-{ip_address}"
            latency = ping_results.get(ip_address, 0)
            name = resolve_hostname(ip_address)
            device_type = guess_device_type(ip_address, raw_mac)
            location = f"Router {network_info['gateway_ip']}"
            now = utc_now()

            existing = db.execute(
                "SELECT id, traffic_gb FROM devices WHERE network_id = ? AND (mac_address = ? OR ip_address = ?)",
                (current_network_id, mac_address, ip_address),
            ).fetchone()

            if existing:
                # Preserve existing traffic_gb value when updating (we don't actively measure usage here)
                existing_traffic = existing["traffic_gb"] if existing["traffic_gb"] is not None else 0
                db.execute(
                    """
                    UPDATE devices
                    SET name = ?, status = 'Online', ip_address = ?, mac_address = ?, device_type = ?, location = ?, latency_ms = ?, traffic_gb = ?, last_seen = ?, source = 'scan'
                    WHERE id = ?
                    """,
                    (
                        name,
                        ip_address,
                        mac_address,
                        device_type,
                        location,
                        latency,
                        existing_traffic,
                        now,
                        existing["id"],
                    ),
                )
            else:
                # New device: initialize traffic to 0 (GB)
                db.execute(
                    """
                    INSERT INTO devices
                    (name, status, ip_address, mac_address, device_type, location, latency_ms, traffic_gb, first_seen, last_seen, network_id, source)
                    VALUES (?, 'Online', ?, ?, ?, ?, ?, 0, ?, ?, ?, 'scan')
                    """,
                    (
                        name,
                        ip_address,
                        mac_address,
                        device_type,
                        location,
                        latency,
                        now,
                        now,
                        current_network_id,
                    ),
                )

        db.commit()

    return {
        "ok": True,
        "network": network_info["gateway_ip"],
        "networkId": current_network_id,
        "gatewayIp": network_info["gateway_ip"],
        "gatewayMac": network_info["gateway_mac"],
        "devicesFound": len(discovered_ips),
        "arpDevicesFound": len(arp_scan_entries),
        "scapyEnabled": SCAPY_AVAILABLE,
        "scapyError": SCAPY_ERROR,
        "offlineDevices": count_offline_devices(current_network_id),
        "scannedAt": utc_now(),
    }


def count_offline_devices(network_id: str | None) -> int:
    if not network_id:
        return 0
    row = query_one(
        "SELECT COUNT(*) AS count FROM devices WHERE network_id = ? AND status = 'Offline'",
        (network_id,),
    )
    return row["count"] if row else 0


def count_online_devices(network_id: str | None) -> int:
    if not network_id:
        return 0
    row = query_one(
        "SELECT COUNT(*) AS count FROM devices WHERE network_id = ? AND status = 'Online'",
        (network_id,),
    )
    return row["count"] if row else 0


def clear_scan_devices() -> None:
    current_network_id = get_current_network_info()
    if not current_network_id:
        return
    with closing(get_db()) as db:
        db.execute(
            "UPDATE devices SET status = 'Offline', latency_ms = 0 WHERE network_id = ?",
            (current_network_id["network_id"],),
        )
        db.commit()


def remove_scan_devices_not_on_current_network() -> None:
    # Devices are stored permanently and filtered by current network.
    # The dashboard and API endpoints only return records for the current network_id.
    return


def get_local_interfaces() -> list[dict]:
    # FIX 2: Cross-platform interface detection
    if IS_WINDOWS:
        output = run_command(["ipconfig"])
        matches = re.findall(
            r"IPv4 Address[^\r\n:]*:\s*([\d.]+).*?Subnet Mask[^\r\n:]*:\s*([\d.]+)",
            output,
            flags=re.S,
        )
    else:
        # Linux/macOS: use `ip addr` and derive subnet mask from prefix length
        output = run_command(["ip", "addr"])
        raw_matches = re.findall(r"inet\s+([\d.]+)/(\d+)", output)
        matches = []
        for ip_address, prefix in raw_matches:
            # Convert prefix length (e.g. "24") to dotted subnet mask (e.g. "255.255.255.0")
            bits = int(prefix)
            mask_int = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
            subnet_mask = ".".join(str((mask_int >> shift) & 0xFF) for shift in (24, 16, 8, 0))
            matches.append((ip_address, subnet_mask))

    interfaces: list[dict] = []
    seen_scan_networks: set[str] = set()

    for ip_address, subnet_mask in matches:
        if ip_address.startswith(("127.", "169.254.")):
            continue

        try:
            full_network = IPv4Network(f"{ip_address}/{subnet_mask}", strict=False)
            scan_network = choose_scan_network(ip_address, full_network)
        except ValueError:
            continue

        key = f"{ip_address}-{scan_network}"
        if key in seen_scan_networks:
            continue

        seen_scan_networks.add(key)
        interfaces.append(
            {
                "ip_address": ip_address,
                "full_network": full_network,
                "scan_network": scan_network,
            }
        )

    return interfaces


def choose_scan_network(ip_address: str, full_network: IPv4Network) -> IPv4Network:
    if full_network.num_addresses <= MAX_SCAN_ADDRESSES:
        return full_network

    return IPv4Network(f"{ip_address}/255.255.255.0", strict=False)


def normalize_mac(mac: str) -> str:
    if not mac:
        return ""
    return mac.lower().replace(":", "-")


def traffic_packet_handler(pkt) -> None:
    try:
        ether = pkt.getlayer(Ether)
        if not ether:
            return
        src = normalize_mac(getattr(ether, "src", "") or getattr(ether, "src", ""))
        dst = normalize_mac(getattr(ether, "dst", "") or getattr(ether, "dst", ""))
        size = len(bytes(pkt))

        with TRAFFIC_LOCK:
            if src and re.fullmatch(r"[0-9a-f]{2}(?:-[0-9a-f]{2}){5}", src):
                TRAFFIC_COUNTERS[src] = TRAFFIC_COUNTERS.get(src, 0) + size
            if dst and re.fullmatch(r"[0-9a-f]{2}(?:-[0-9a-f]{2}){5}", dst):
                TRAFFIC_COUNTERS[dst] = TRAFFIC_COUNTERS.get(dst, 0) + size
    except Exception:
        return


def traffic_flush_loop() -> None:
    while True:
        time_to_sleep = TRAFFIC_FLUSH_INTERVAL
        try:
            time.sleep(time_to_sleep)
            with TRAFFIC_LOCK:
                snapshot = TRAFFIC_COUNTERS.copy()
                TRAFFIC_COUNTERS.clear()

            if not snapshot:
                continue

            network_info = get_current_network_info()
            if not network_info:
                continue
            network_id = network_info["network_id"]

            with closing(get_db()) as db:
                for mac, bytes_count in snapshot.items():
                    gb = bytes_count / (1024 ** 3)
                    # Update matching device for current network
                    db.execute(
                        "UPDATE devices SET traffic_gb = COALESCE(traffic_gb, 0) + ?, last_seen = ? WHERE mac_address = ? AND network_id = ?",
                        (gb, utc_now(), mac, network_id),
                    )
                db.commit()
        except Exception:
            logging.exception("Error while flushing traffic counters")


def start_traffic_monitoring() -> None:
    if not TRAFFIC_MONITOR_ENABLED:
        logging.info("Traffic monitoring disabled or Scapy not available")
        return

    interfaces = get_local_interfaces()
    if not interfaces:
        logging.info("No interfaces found for traffic monitoring")
        return

    iface = get_scapy_interface(interfaces[0]["scan_network"]) or get_if_list()[0]

    # Start sniffer thread
    def _sniff_loop():
        try:
            sniff(iface=iface, prn=traffic_packet_handler, store=False)
        except Exception:
            logging.exception("Traffic sniffer stopped")

    t_sniff = threading.Thread(target=_sniff_loop, daemon=True, name="traffic-sniffer")
    t_sniff.start()

    # Start flush thread
    t_flush = threading.Thread(target=traffic_flush_loop, daemon=True, name="traffic-flush")
    t_flush.start()


def get_scapy_interface(network: IPv4Network) -> str | None:
    """Get the Scapy network interface name that matches the given network."""
    if not SCAPY_AVAILABLE or not get_if_list:
        return None
    
    try:
        ifaces = get_if_list()
        if not ifaces:
            logging.warning("No Scapy interfaces available")
            return None
        
        # On Windows, just use the first non-loopback interface
        # Scapy will auto-detect the right one for the network
        for iface in ifaces:
            if "loopback" not in iface.lower():
                logging.info(f"Selected Scapy interface: {iface}")
                return iface
        
        # Fallback to first interface if no non-loopback found
        logging.info(f"Using first available Scapy interface (fallback): {ifaces[0]}")
        return ifaces[0]
    except Exception as e:
        logging.warning(f"Error getting Scapy interface: {e}")
        return None


def arp_scan_network(network: IPv4Network) -> dict[str, str]:
    if not SCAPY_AVAILABLE:
        return {}

    entries: dict[str, str] = {}

    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        
        # FIX 4: Get the appropriate network interface for this network
        iface = get_scapy_interface(network)
        if not iface:
            logging.warning(f"No suitable Scapy interface found for network {network}")
            return entries
        
        logging.info(f"ARP scanning network {network} on interface {iface}")
        answered, _ = srp(packet, timeout=ARP_SCAN_TIMEOUT, retry=1, iface=iface, verbose=False)
    except Exception as e:
        logging.warning(f"Scapy ARP scan error for network {network}: {e}")
        return entries

    for _, received in answered:
        ip_address = getattr(received, "psrc", "")
        mac_address = getattr(received, "hwsrc", "").lower().replace(":", "-")
        if is_real_arp_entry(ip_address, mac_address):
            entries[ip_address] = mac_address

    return entries


def ping_network(network: IPv4Network) -> dict[str, int]:
    results: dict[str, int] = {}
    hosts = [str(host) for host in network.hosts()]

    with ThreadPoolExecutor(max_workers=PING_WORKERS) as executor:
        future_map = {executor.submit(ping_host, host): host for host in hosts}
        for future in as_completed(future_map):
            ip_address = future_map[future]
            latency = future.result()
            if latency is not None:
                results[ip_address] = latency

    return results


def ping_host(ip_address: str) -> int | None:
    # FIX 3: Cross-platform ping flags
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", "600", ip_address]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip_address]

    output = run_command(cmd)
    if "TTL=" not in output.upper():
        return None

    match = re.search(r"time[=<]\s*([\d.]+)\s*ms", output, flags=re.I)
    if match:
        return max(1, round(float(match.group(1))))
    return 1


def read_arp_table() -> dict[str, str]:
    output = run_command(["arp", "-a"])
    entries: dict[str, str] = {}

    # Windows:  192.168.1.1   aa-bb-cc-dd-ee-ff  dynamic
    # Linux:    192.168.1.1   aa:bb:cc:dd:ee:ff  ether
    for ip_address, mac_address in re.findall(
        r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F][0-9a-fA-F:\-]{14,16}[0-9a-fA-F])\s+\w+",
        output,
    ):
        # Normalise separators to dashes for consistency
        mac_address = mac_address.lower().replace(":", "-")
        if is_real_arp_entry(ip_address, mac_address):
            entries[ip_address] = mac_address

    if IS_WINDOWS:
        entries.update(read_windows_neighbor_table())

    return entries


def read_windows_neighbor_table() -> dict[str, str]:
    output = run_command(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-NetNeighbor -AddressFamily IPv4 | "
            "Where-Object { $_.LinkLayerAddress -and $_.State -ne 'Unreachable' } | "
            "Select-Object IPAddress,LinkLayerAddress | ConvertTo-Csv -NoTypeInformation",
        ]
    )
    entries: dict[str, str] = {}

    try:
        rows = csv.DictReader(StringIO(output))
        for row in rows:
            ip_address = (row.get("IPAddress") or "").strip()
            mac_address = (row.get("LinkLayerAddress") or "").strip().lower().replace(":", "-")
            if is_real_arp_entry(ip_address, mac_address):
                entries[ip_address] = mac_address
    except csv.Error:
        pass

    entries.update(read_windows_netsh_neighbors())

    return entries


def read_windows_netsh_neighbors() -> dict[str, str]:
    output = run_command(["netsh", "interface", "ipv4", "show", "neighbors"])
    entries: dict[str, str] = {}

    for ip_address, mac_address in re.findall(
        r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+\w+",
        output,
    ):
        mac_address = mac_address.lower()
        if is_real_arp_entry(ip_address, mac_address):
            entries[ip_address] = mac_address

    return entries


def is_real_arp_entry(ip_address: str, mac_address: str) -> bool:
    if not re.fullmatch(r"[0-9a-f]{2}(?:-[0-9a-f]{2}){5}", mac_address):
        return False
    if mac_address in {"00-00-00-00-00-00", "ff-ff-ff-ff-ff-ff"}:
        return False
    if ip_address.startswith(("224.", "239.", "255.")):
        return False
    try:
        address = IPv4Address(ip_address)
    except ValueError:
        return False
    return not (address.is_multicast or address.is_unspecified or address.is_loopback)


def is_allowed_discovered_ip(ip_address: str, full_networks: list[IPv4Network], scan_networks: list[IPv4Network]) -> bool:
    try:
        address = IPv4Address(ip_address)
    except ValueError:
        return False

    for network in scan_networks:
        if address in network and address not in (network.network_address, network.broadcast_address):
            return True

    for network in full_networks:
        if address in network and address not in (network.network_address, network.broadcast_address):
            return True

    return False


def run_command(command: list[str]) -> str:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return f"{completed.stdout}\n{completed.stderr}"


def resolve_hostname(ip_address: str) -> str:
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except OSError:
        return f"Device {ip_address}"


def guess_device_type(ip_address: str, mac_address: str | None) -> str:
    if ip_address.endswith(".1"):
        return "Router/Gateway"
    if mac_address:
        return "Network Device"
    return "Host"


def ip_sort_key(ip_address: str) -> tuple:
    # FIX 4: Corrected return type — tuple() from a generator is plain tuple, not tuple[int,int,int,int]
    return tuple(int(part) for part in ip_address.split("."))


def ensure_project_layout() -> None:
    (BASE_DIR / "templates").mkdir(exist_ok=True)
    (BASE_DIR / "static").mkdir(exist_ok=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def format_traffic(total_gb: float) -> str:
    if total_gb >= 1024:
        return f"{round(total_gb / 1024, 2)}TB"
    return f"{round(total_gb, 2)}GB"


def build_alert(avg_latency: int, offline: int, total: int) -> dict:
    if avg_latency > 25:
        return {"level": "critical", "message": "High Network Latency Detected"}
    if total and offline / total >= 0.35:
        return {"level": "warning", "message": "Multiple Devices Offline"}
    return {"level": "normal", "message": "Network Status Normal"}


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
