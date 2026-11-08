#!/usr/bin/env python3
"""Local-only PVE NIC traffic monitor and tc rate limiter."""
import hmac
import re
import shutil
import sqlite3
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

APP_DIR = Path("/opt/pve-nic-shaper")
DB_PATH = APP_DIR / "rules.db"
FRONTEND_DIR = APP_DIR / "frontend"
TOKEN_FILE = Path("/etc/pve-nic-shaper/token")
HOST = "127.0.0.1"
PORT = 8765
MAX_RATE_MBPS = 100_000
POLL_SECONDS = 2

app = Flask(__name__)
lock = threading.RLock()
previous_stats = {}
last_applied = {}
initial_reconcile = True

def db_connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    APP_DIR.mkdir(parents=True, exist_ok=True)
    with db_connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            iface TEXT NOT NULL,
            direction TEXT NOT NULL CHECK(direction IN ('tx','rx')),
            rate_mbps INTEGER NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            days TEXT NOT NULL,
            start_hhmm TEXT NOT NULL,
            end_hhmm TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
        db.commit()

def query_rules():
    with db_connect() as db:
        return [dict(row) for row in db.execute("SELECT * FROM rules ORDER BY id DESC")]

def get_token():
    try:
        return TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return ""

@app.before_request
def authorize():
    # Keep the agent local-only. Remote browser access should use an SSH tunnel.
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify(error="服务只允许本机访问；请通过 SSH 隧道连接"), 403
    if request.path == "/health":
        return None
    token = get_token()
    supplied = request.headers.get("Authorization", "")
    if supplied.startswith("Bearer "):
        supplied = supplied[7:].strip()
    if not token or not hmac.compare_digest(token, supplied):
        return jsonify(error="访问令牌无效"), 401
    return None

def interfaces():
    try:
        return sorted(p.name for p in Path("/sys/class/net").iterdir()
                      if re.fullmatch(r"[A-Za-z0-9_.:@-]{1,15}", p.name))
    except OSError:
        return []

def read_counters():
    result = {}
    try:
        lines = Path("/proc/net/dev").read_text(encoding="utf-8").splitlines()[2:]
    except OSError:
        return result
    for line in lines:
        if ":" not in line:
            continue
        iface, values = line.split(":", 1)
        nums = values.split()
        if len(nums) >= 9:
            result[iface.strip()] = (int(nums[0]), int(nums[8]), time.monotonic())
    return result

def traffic_rates():
    global previous_stats
    current = read_counters()
    result = {}
    for iface, (rx, tx, now) in current.items():
        old = previous_stats.get(iface)
        if old:
            dt = max(now - old[2], 0.001)
            rx_rate = max(rx - old[0], 0) * 8 / dt / 1_000_000
            tx_rate = max(tx - old[1], 0) * 8 / dt / 1_000_000
        else:
            rx_rate = tx_rate = 0.0
        result[iface] = {"rx_mbps": round(rx_rate, 3), "tx_mbps": round(tx_rate, 3)}
    previous_stats = current
    return result

def parse_time(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{2}:\d{2}", value):
        raise ValueError("时间必须采用 HH:MM 格式")
    hour, minute = map(int, value.split(":"))
    if hour > 23 or minute > 59:
        raise ValueError("时间无效")
    return hour * 60 + minute

def is_active(rule, now):
    if not rule["enabled"]:
        return False
    try:
        days = {int(x) for x in rule["days"].split(",")}
        start, end = parse_time(rule["start_hhmm"]), parse_time(rule["end_hhmm"])
    except (ValueError, AttributeError):
        return False
    if not days or not days <= set(range(7)):
        return False
    minute, weekday = now.hour * 60 + now.minute, now.weekday()  # Monday=0
    if start <= end:
        return weekday in days and start <= minute <= end
    # For overnight ranges, the after-midnight portion belongs to the prior day.
    return ((weekday in days and minute >= start) or
            ((weekday - 1) % 7 in days and minute <= end))

def desired_limits():
    valid = set(interfaces())
    result = {}
    now = datetime.now()
    for rule in query_rules():
        if rule["iface"] not in valid or not is_active(rule, now):
            continue
        key = (rule["iface"], rule["direction"])
        result[key] = min(result.get(key, rule["rate_mbps"]), rule["rate_mbps"])
    return result

def tc(args, check=True):
    binary = shutil.which("tc") or "/sbin/tc"
    try:
        result = subprocess.run([binary, *args], capture_output=True, text=True,
                                timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    message = (result.stderr or result.stdout).strip()
    return (result.returncode == 0 or not check), message

def qdisc_show(iface):
    ok, output = tc(["qdisc", "show", "dev", iface])
    if not ok:
        raise RuntimeError(output or "无法读取网卡队列")
    return output

def own_root(output):
    return any(re.search(r"^qdisc\s+\S+\s+7:\s+root(?:\s|$)", line)
               for line in output.splitlines())

def has_root(output):
    return any(re.search(r"\broot\b", line) for line in output.splitlines())

def apply_tx(iface, rate):
    output = qdisc_show(iface)
    if not own_root(output):
        if has_root(output):
            return False, f"{iface} 已有根 qdisc，为避免覆盖现有 QoS，拒绝操作"
        ok, err = tc(["qdisc", "add", "dev", iface, "root", "handle", "7:",
                      "htb", "default", "10"])
        if not ok:
            return False, f"创建上传队列失败：{err}"
    kbit = int(rate * 1000)
    ok, err = tc(["class", "replace", "dev", iface, "parent", "7:",
                  "classid", "7:10", "htb", "rate", f"{kbit}kbit",
                  "ceil", f"{kbit}kbit"])
    if not ok:
        return False, f"设置上传速率失败：{err}"
    ok, err = tc(["filter", "replace", "dev", iface, "parent", "7:",
                  "protocol", "all", "pref", "10", "matchall", "flowid", "7:10"])
    return (True, "") if ok else (False, f"设置上传过滤器失败：{err}")

def remove_tx(iface):
    if own_root(qdisc_show(iface)):
        ok, err = tc(["qdisc", "del", "dev", iface, "root"])
        return ok, err
    return True, ""

def apply_rx(iface, rate):
    output = qdisc_show(iface)
    if not re.search(r"^qdisc\s+ingress\s+ffff:", output, re.MULTILINE):
        # Do not replace clsact/other qdiscs; only add our ingress qdisc if absent.
        ok, err = tc(["qdisc", "add", "dev", iface, "handle", "ffff:", "ingress"])
        if not ok:
            return False, f"创建 ingress 队列失败（可能已有流控规则）：{err}"
    kbit = int(rate * 1000)
    ok, err = tc(["filter", "replace", "dev", iface, "parent", "ffff:",
                  "protocol", "all", "pref", "49152", "handle", "9000",
                  "matchall", "action", "police", "rate", f"{kbit}kbit",
                  "burst", "100k", "mtu", "65535", "conform-exceed", "drop"])
    return (True, "") if ok else (False, f"设置下载 policing 失败：{err}")

def remove_rx(iface):
    # Remove only this app's uniquely identified filter; leave ingress qdisc intact.
    ok, err = tc(["filter", "del", "dev", iface, "parent", "ffff:",
                  "protocol", "all", "pref", "49152", "handle", "9000", "matchall"])
    return (True, "") if ok else (False, err)

def apply_limits(force=False):
    global last_applied, initial_reconcile
    desired = desired_limits()
    keys = set(last_applied) | set(desired)
    if force or initial_reconcile:
        # Reconcile configured interfaces on service start, including expired schedules.
        for rule in query_rules():
            keys.add((rule["iface"], rule["direction"]))
    errors = []
    for iface, direction in sorted(keys):
        if iface not in interfaces():
            continue
        new = desired.get((iface, direction))
        old = last_applied.get((iface, direction), object())
        if old == new:
            continue
        try:
            if direction == "tx":
                ok, error = apply_tx(iface, new) if new is not None else remove_tx(iface)
            else:
                ok, error = apply_rx(iface, new) if new is not None else remove_rx(iface)
            if ok:
                if new is None:
                    last_applied.pop((iface, direction), None)
                else:
                    last_applied[(iface, direction)] = new
            else:
                errors.append(f"{iface}/{direction}: {error}")
        except Exception as exc:
            errors.append(f"{iface}/{direction}: {exc}")
    initial_reconcile = False
    app.config["last_errors"] = errors
    return desired, errors

def scheduler():
    while True:
        try:
            with lock:
                apply_limits()
        except Exception:
            app.logger.exception("限速调度失败")
        time.sleep(POLL_SECONDS)

@app.get("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.get("/health")
def health():
    return jsonify(status="ok")

@app.get("/api/status")
def status():
    with lock:
        rates, limits = traffic_rates(), desired_limits()
    rows = []
    for iface in interfaces():
        rows.append({"iface": iface, **rates.get(iface, {"rx_mbps": 0, "tx_mbps": 0}),
                     "rx_limit_mbps": limits.get((iface, "rx")),
                     "tx_limit_mbps": limits.get((iface, "tx"))})
    return jsonify(node=__import__("os").uname().nodename, interfaces=rows,
                   errors=app.config.get("last_errors", []))

@app.get("/api/rules")
def rules():
    return jsonify(query_rules())

@app.post("/api/rules")
def add_rule():
    payload = request.get_json(silent=True) or {}
    iface, direction = str(payload.get("iface", "")).strip(), payload.get("direction")
    days, start, end = payload.get("days"), payload.get("start_hhmm"), payload.get("end_hhmm")
    if iface not in interfaces():
        return jsonify(error="网卡不存在"), 400
    if direction not in ("tx", "rx"):
        return jsonify(error="方向必须为 tx 或 rx"), 400
    if (not isinstance(days, list) or not days or
        any(type(day) is not int or day not in range(7) for day in days)):
        return jsonify(error="星期必须为周一到周日（0 到 6）"), 400
    try:
        rate = int(payload.get("rate_mbps"))
        parse_time(start)
        parse_time(end)
    except (TypeError, ValueError) as exc:
        return jsonify(error=str(exc)), 400
    if not 1 <= rate <= MAX_RATE_MBPS:
        return jsonify(error=f"速率必须在 1 到 {MAX_RATE_MBPS} Mbps 之间"), 400
    enabled = 1 if payload.get("enabled", True) else 0
    with db_connect() as db:
        cur = db.execute("""INSERT INTO rules
            (iface,direction,rate_mbps,enabled,days,start_hhmm,end_hhmm)
            VALUES (?,?,?,?,?,?,?)""",
            (iface, direction, rate, enabled, ",".join(map(str, sorted(set(days))),), start, end))
        rule_id = cur.lastrowid
        db.commit()
    with lock:
        _, errors = apply_limits()
    return jsonify(id=rule_id, errors=errors), 201

@app.delete("/api/rules/<int:rule_id>")
def delete_rule(rule_id):
    with db_connect() as db:
        db.execute("DELETE FROM rules WHERE id=?", (rule_id,))
        db.commit()
    with lock:
        _, errors = apply_limits()
    return jsonify(status="deleted", errors=errors)

@app.post("/api/reload")
def reload_rules():
    with lock:
        _, errors = apply_limits(force=True)
    return jsonify(status="ok", errors=errors)

if __name__ == "__main__":
    init_db()
    threading.Thread(target=scheduler, daemon=True).start()
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
