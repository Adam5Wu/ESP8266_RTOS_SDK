#!/usr/bin/env python3
# Copyright 2026 Adam5Wu (ESP8266_RTOS_SDK OSS contributors)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
ESP8266 Wi-Fi Stack Performance Benchmark Suite.

Runs a reproducible end-to-end Wi-Fi benchmark against a running ESP8266 device
flashed with the ESPZWApplianceT2 base firmware (WebDAV enabled on /system),
taking only the device IP address. Produces trimmed mean +/- stdev metrics
matching components/esp8266/WIFI_DESIGN.md.

Zero third-party dependencies (Python 3.9+ stdlib only). On Windows, ICMP probes
use native iphlpapi.dll (IcmpSendEcho, sub-ms accuracy, no administrator rights).
On Linux/macOS, ICMP probes fall back to the system `ping` utility.
"""

import argparse
import concurrent.futures
import ctypes
import hashlib
import http.client
import json
import os
import platform
import random
import re
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Cross-platform ICMP Echo helper
# ---------------------------------------------------------------------------
_IS_WIN = platform.system() == "Windows"
if _IS_WIN:
    from ctypes import wintypes

    _iphlp = ctypes.windll.iphlpapi
    _iphlp.IcmpCreateFile.restype = wintypes.HANDLE
    _iphlp.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
    _iphlp.IcmpCloseHandle.restype = wintypes.BOOL
    _iphlp.IcmpSendEcho.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.WORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    _iphlp.IcmpSendEcho.restype = wintypes.DWORD


class IcmpPinger:
    """Thread-local ICMP echo sender (native Win32 IcmpSendEcho or POSIX ping)."""

    def __init__(self, ip: str, payload_size: int, timeout_ms: int = 1000) -> None:
        self.ip = ip
        self.payload_size = payload_size
        self.timeout_ms = timeout_ms
        self._handle = None
        if _IS_WIN:
            self._handle = _iphlp.IcmpCreateFile()
            self._addr_dw = struct.unpack("<I", socket.inet_aton(ip))[0]
            self._payload = b"E" * payload_size
            self._reply_sz = max(256, payload_size + 128)
            self._reply_buf = ctypes.create_string_buffer(self._reply_sz)

    def __enter__(self) -> "IcmpPinger":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def close(self) -> None:
        if _IS_WIN and self._handle is not None:
            _iphlp.IcmpCloseHandle(self._handle)
            self._handle = None

    def ping_once(self) -> Optional[float]:
        """Send one ICMP echo request and return RTT in ms, or None on timeout."""
        if _IS_WIN:
            t0 = time.perf_counter()
            n = _iphlp.IcmpSendEcho(
                self._handle,
                self._addr_dw,
                self._payload,
                len(self._payload),
                None,
                self._reply_buf,
                self._reply_sz,
                self.timeout_ms,
            )
            dt_ms = (time.perf_counter() - t0) * 1000.0
            if n > 0:
                status = struct.unpack_from("<I", self._reply_buf.raw, 4)[0]
                if status == 0:
                    return dt_ms
            return None

        # POSIX fallback (Linux / macOS)
        timeout_s = max(1, int((self.timeout_ms + 999) // 1000))
        if platform.system() == "Darwin":
            cmd = ["ping", "-c", "1", "-s", str(self.payload_size), "-W", str(self.timeout_ms), self.ip]
        else:
            cmd = ["ping", "-c", "1", "-s", str(self.payload_size), "-W", str(timeout_s), self.ip]
        t0 = time.perf_counter()
        proc = subprocess.run(cmd, capture_output=True, text=True)
        dt_ms = (time.perf_counter() - t0) * 1000.0
        if proc.returncode != 0:
            return None
        m = re.search(r"time[=<]\s*([0-9.]+)\s*ms", proc.stdout)
        return float(m.group(1)) if m else dt_ms


def warmup_radio(ip: str, count: int = 8) -> None:
    with IcmpPinger(ip, 32, 1000) as p:
        for _ in range(count):
            p.ping_once()


# ---------------------------------------------------------------------------
# Statistics helpers
# ---------------------------------------------------------------------------
def pct(vals: List[float], p: float) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    k = (len(s) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def trimmed_stats(vals: List[float]) -> Dict[str, Any]:
    """Compute trimmed mean & stdev (drops single min & max when len >= 4)."""
    clean = [float(v) for v in vals]
    s = sorted(clean)
    trimmed = s[1:-1] if len(s) >= 4 else s
    mean = statistics.mean(trimmed) if trimmed else 0.0
    stdev = statistics.stdev(trimmed) if len(trimmed) >= 2 else 0.0
    return {
        "n_raw": len(clean),
        "n_trimmed": len(trimmed),
        "mean": round(mean, 3),
        "stdev": round(stdev, 3),
        "raw_min": round(min(clean), 3) if clean else 0.0,
        "raw_max": round(max(clean), 3) if clean else 0.0,
        "raw": [round(v, 3) for v in clean],
    }


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
def http_req(
    ip: str,
    port: int,
    method: str,
    path: str,
    data: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 30.0,
) -> Tuple[int, bytes, float]:
    url = f"http://{ip}:{port}{path}"
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return resp.status, body, time.perf_counter() - t0
    except urllib.error.HTTPError as e:
        return e.code, e.read(), time.perf_counter() - t0


def get_boot_serial(ip: str, port: int, timeout: float = 5.0) -> str:
    st, body, _ = http_req(ip, port, "GET", "/!sys/boot_serial", timeout=timeout)
    if st != 200:
        raise RuntimeError(f"GET /!sys/boot_serial failed: HTTP {st}")
    return body.decode("ascii", errors="replace").strip()


# ---------------------------------------------------------------------------
# Benchmark workloads
# ---------------------------------------------------------------------------
def bench_warm_reboot(ip: str, port: int, runs: int) -> List[float]:
    vals: List[float] = []
    for _ in range(runs):
        bs_prev = get_boot_serial(ip, port)
        st, _, _ = http_req(ip, port, "GET", f"/!sys/reboot?bs={bs_prev}", timeout=10.0)
        if st not in (200, 204):
            raise RuntimeError(f"GET /!sys/reboot failed: HTTP {st}")
        t0 = time.perf_counter()
        time.sleep(0.5)
        deadline = t0 + 30.0
        while time.perf_counter() < deadline:
            try:
                bs_now = get_boot_serial(ip, port, timeout=1.5)
                if bs_now and bs_now != bs_prev:
                    vals.append((time.perf_counter() - t0) * 1000.0)
                    break
            except Exception:
                time.sleep(0.05)
        else:
            raise TimeoutError("Device did not come back online after /!sys/reboot")
        time.sleep(1.0)
    return vals


def bench_ps_wake(ip: str, port: int, runs: int, idle_s: float = 5.0) -> List[float]:
    vals: List[float] = []
    for _ in range(runs):
        time.sleep(idle_s)
        st, _, dt = http_req(ip, port, "GET", "/!sys/discover", timeout=10.0)
        if st != 200:
            raise RuntimeError(f"PS wake GET /!sys/discover failed: HTTP {st}")
        vals.append(dt * 1000.0)
    return vals


def bench_wifi_scan(ip: str, port: int, runs: int) -> List[float]:
    vals: List[float] = []
    for _ in range(runs):
        warmup_radio(ip, 4)
        st, _, dt = http_req(ip, port, "GET", "/!sys/prov/sta.aplist", timeout=30.0)
        if st != 200:
            raise RuntimeError(f"GET /!sys/prov/sta.aplist failed: HTTP {st}")
        vals.append(dt * 1000.0)
        time.sleep(0.3)
    return vals


def bench_seq_icmp(ip: str, payload_size: int, runs: int, count: int = 100) -> Tuple[List[float], List[float]]:
    p50_runs: List[float] = []
    pps_runs: List[float] = []
    for _ in range(runs):
        warmup_radio(ip, 5)
        rtts: List[float] = []
        t0 = time.perf_counter()
        with IcmpPinger(ip, payload_size, 1000) as p:
            for _ in range(count):
                dt = p.ping_once()
                if dt is not None:
                    rtts.append(dt)
        elapsed = time.perf_counter() - t0
        p50_runs.append(pct(rtts, 50))
        pps_runs.append(len(rtts) / elapsed if elapsed > 0 else 0.0)
        time.sleep(0.2)
    return p50_runs, pps_runs


def bench_icmp_flood(
    ip: str, payload_size: int, workers: int, per_worker: int, runs: int
) -> Tuple[List[float], List[float]]:
    pps_runs: List[float] = []
    p99_runs: List[float] = []

    def worker_fn() -> List[float]:
        out: List[float] = []
        with IcmpPinger(ip, payload_size, 1000) as p:
            for _ in range(per_worker):
                dt = p.ping_once()
                if dt is not None:
                    out.append(dt)
        return out

    for _ in range(runs):
        warmup_radio(ip, 5)
        t0 = time.perf_counter()
        all_rtts: List[float] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(worker_fn) for _ in range(workers)]
            for f in futs:
                all_rtts.extend(f.result())
        elapsed = time.perf_counter() - t0
        pps_runs.append(len(all_rtts) / elapsed if elapsed > 0 else 0.0)
        p99_runs.append(pct(all_rtts, 99))
        time.sleep(0.25)
    return pps_runs, p99_runs


def _probe_stream_thread(
    ip: str, payload_size: int, interval_s: float, stop_evt: threading.Event, out: Dict[str, Any]
) -> None:
    rtts: List[float] = []
    sent = 0
    next_t = time.perf_counter()
    with IcmpPinger(ip, payload_size, 1000) as p:
        while not stop_evt.is_set():
            sent += 1
            dt = p.ping_once()
            if dt is not None:
                rtts.append(dt)
            next_t += interval_s
            now = time.perf_counter()
            if next_t > now:
                stop_evt.wait(next_t - now)
            else:
                next_t = now
    out["sent"] = sent
    out["rtts"] = rtts


def bench_downlink_1mb(ip: str, port: int, runs: int, contended: bool = False) -> List[float]:
    bs = get_boot_serial(ip, port)
    path = f"/!sys/storage?bs={bs}&type=user"
    vals: List[float] = []
    for _ in range(runs):
        warmup_radio(ip, 5)
        stop_evt = threading.Event()
        probe_res: Dict[str, Any] = {}
        th = None
        if contended:
            th = threading.Thread(
                target=_probe_stream_thread, args=(ip, 1400, 0.020, stop_evt, probe_res), daemon=True
            )
            th.start()
            time.sleep(0.05)
        try:
            st, body, dt = http_req(ip, port, "GET", path, timeout=120.0)
        finally:
            if th is not None:
                stop_evt.set()
                th.join(timeout=5.0)
        if st != 200 or len(body) < 1024:
            raise RuntimeError(f"GET {path} failed: HTTP {st} ({len(body)} B)")
        vals.append((len(body) / 1024.0) / dt)
        time.sleep(0.25)
    return vals


def bench_webdav_128k(ip: str, port: int, runs: int) -> Tuple[List[float], List[float]]:
    rng = random.Random(42)
    payload = rng.randbytes(131072)
    expected_sha = hashlib.sha256(payload).hexdigest()
    path = "/.fs/system/_wifi_bench_128k.bin"
    put_vals: List[float] = []
    get_vals: List[float] = []

    try:
        for _ in range(runs):
            warmup_radio(ip, 4)
            st_p, _, dt_p = http_req(
                ip, port, "PUT", path, data=payload,
                headers={"Content-Type": "application/octet-stream"}, timeout=90.0,
            )
            if st_p not in (200, 201, 204):
                raise RuntimeError(f"WebDAV PUT failed: HTTP {st_p} (ensure WebDAV is enabled on /system)")
            st_g, body_g, dt_g = http_req(ip, port, "GET", path, timeout=60.0)
            if st_g != 200 or hashlib.sha256(body_g).hexdigest() != expected_sha:
                raise RuntimeError(f"WebDAV GET verification failed: HTTP {st_g} ({len(body_g)} B)")
            st_d, _, _ = http_req(ip, port, "DELETE", path, timeout=30.0)
            if st_d not in (200, 204):
                raise RuntimeError(f"WebDAV DELETE failed: HTTP {st_d}")
            put_vals.append((len(payload) / 1024.0) / dt_p)
            get_vals.append((len(body_g) / 1024.0) / dt_g)
            time.sleep(0.25)
    finally:
        try:
            http_req(ip, port, "DELETE", path, timeout=10.0)
        except Exception:
            pass
    return put_vals, get_vals


def bench_flash_erase_contention(
    ip: str, port: int, probe_size: int, interval_s: float, runs: int
) -> Tuple[List[float], List[float], List[float]]:
    rng = random.Random(42)
    payload = rng.randbytes(131072)
    expected_sha = hashlib.sha256(payload).hexdigest()
    path = "/.fs/system/_wifi_bench_p3_128k.bin"
    put_vals: List[float] = []
    p95_vals: List[float] = []
    gt40_vals: List[float] = []

    try:
        for r in range(runs):
            warmup_radio(ip, 5)
            stop_evt = threading.Event()
            probe_res: Dict[str, Any] = {}
            th = threading.Thread(
                target=_probe_stream_thread,
                args=(ip, probe_size, interval_s, stop_evt, probe_res),
                daemon=True,
            )
            th.start()
            time.sleep(0.05)
            try:
                st_p, _, dt_p = http_req(
                    ip, port, "PUT", path, data=payload,
                    headers={"Content-Type": "application/octet-stream"}, timeout=90.0,
                )
            finally:
                stop_evt.set()
                th.join(timeout=5.0)
            if st_p not in (200, 201, 204):
                raise RuntimeError(f"Contended WebDAV PUT failed: HTTP {st_p}")
            if r == 0:
                st_g, body_g, _ = http_req(ip, port, "GET", path, timeout=60.0)
                if st_g != 200 or hashlib.sha256(body_g).hexdigest() != expected_sha:
                    raise RuntimeError("Contended WebDAV PUT SHA-256 verification failed")
            st_d, _, _ = http_req(ip, port, "DELETE", path, timeout=30.0)
            if st_d not in (200, 204):
                raise RuntimeError(f"Contended WebDAV DELETE failed: HTTP {st_d}")

            rtts = probe_res.get("rtts", [])
            put_vals.append((len(payload) / 1024.0) / dt_p)
            p95_vals.append(pct(rtts, 95))
            gt40_vals.append((100.0 * sum(1 for x in rtts if x > 40.0) / len(rtts)) if rtts else 0.0)
            time.sleep(0.25)
    finally:
        try:
            http_req(ip, port, "DELETE", path, timeout=10.0)
        except Exception:
            pass
    return put_vals, p95_vals, gt40_vals


def bench_concurrent_http(
    ip: str, port: int, path: str, workers: int, per_worker: int, keepalive: bool, runs: int
) -> List[float]:
    rps_vals: List[float] = []

    def worker_fn() -> int:
        ok = 0
        if keepalive:
            conn = http.client.HTTPConnection(ip, port, timeout=15.0)
            try:
                for _ in range(per_worker):
                    try:
                        conn.request("GET", path, headers={"Connection": "keep-alive"})
                        resp = conn.getresponse()
                        resp.read()
                        if resp.status == 200:
                            ok += 1
                    except Exception:
                        conn.close()
                        conn = http.client.HTTPConnection(ip, port, timeout=15.0)
            finally:
                conn.close()
        else:
            for _ in range(per_worker):
                try:
                    st, _, _ = http_req(ip, port, "GET", path, timeout=15.0)
                    if st == 200:
                        ok += 1
                except Exception:
                    pass
        return ok

    for _ in range(runs):
        warmup_radio(ip, 4)
        t0 = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            total_ok = sum(f.result() for f in [ex.submit(worker_fn) for _ in range(workers)])
        elapsed = time.perf_counter() - t0
        expected = workers * per_worker
        if total_ok < expected:
            print(f"  [warn] {path}: {expected - total_ok}/{expected} requests failed", file=sys.stderr)
        rps_vals.append(total_ok / elapsed if elapsed > 0 else 0.0)
        time.sleep(0.25)
    return rps_vals


# ---------------------------------------------------------------------------
# Metric Registry & Output Formatting (Matches WIFI_DESIGN.md 1-to-1)
# ---------------------------------------------------------------------------
METRIC_SPECS: List[Tuple[str, str, str, str]] = [
    # (key, display_name, unit, direction)
    ("warm_reboot_ms",       "Warm Reboot -> HTTP Ready",                        "ms",    "lower"),
    ("ps_wake_ms",           "Modem-Sleep Wake Latency (5 s idle)",              "ms",    "lower"),
    ("wifi_scan_ms",         "Active Wi-Fi Scan (APSTA)",                        "ms",    "lower"),
    ("icmp_32b_p50_ms",      "Idle ICMP RTT (32 B, p50)",                        "ms",    "lower"),
    ("icmp_5800b_pps",       "Fragmented ICMP Burst (5800 B, 4-frag)",           "pps",   "higher"),
    ("flood_1400b_pps",      "Heavy-MTU Saturation (4w x 100 @ 1400 B)",         "pps",   "higher"),
    ("flood_1400b_p99_ms",   "Heavy-MTU Saturation Tail p99 (4w @ 1400 B)",      "ms",    "lower"),
    ("dl_1mb_kbs",           "Uncontested Downlink (1 MB flash read)",           "KB/s",  "higher"),
    ("dl_1mb_contended_kbs", "Flash-Read Contended Downlink (1 MB + 1400 B)",    "KB/s",  "higher"),
    ("webdav_put_128k_kbs",  "WebDAV Storage Write (128 KB PUT)",                "KB/s",  "higher"),
    ("webdav_get_128k_kbs",  "WebDAV Storage Read (128 KB GET)",                 "KB/s",  "higher"),
    ("erase_32b_p95_ms",     "Flash-Erase Contention Probe p95 (PUT + 32 B)",    "ms",    "lower"),
    ("erase_32b_gt40_pct",   "Flash-Erase Contention Stalls >40 ms (PUT + 32 B)","%",     "lower"),
    ("erase_4200b_put_kbs",  "Flash-Erase Burst Contention PUT (PUT + 4200 B)",  "KB/s",  "higher"),
    ("erase_4200b_p95_ms",   "Flash-Erase Burst Contention Probe p95 (+4200 B)", "ms",    "lower"),
    ("http_conc_disc_rps",   "Concurrent HTTP Close (6w x 25 /!sys/discover)",   "req/s", "higher"),
    ("http_conc_ka_rps",     "Concurrent HTTP Keep-Alive (4w x 40 boot_serial)", "req/s", "higher"),
]


def format_cell(
    stat: Dict[str, Any],
    base_stat: Optional[Dict[str, Any]],
    direction: str,
    markdown_color: bool = False,
) -> str:
    val = stat["mean"]
    sd = stat["stdev"]
    core = f"{val:.2f} ± {sd:.2f}"
    if base_stat is None or base_stat.get("mean", 0.0) == 0.0:
        return core
    bval = base_stat["mean"]
    bsd = base_stat.get("stdev", 0.0)
    if abs(val - bval) <= max(sd, bsd):
        return f"{core}<br>(on par)" if markdown_color else f"{core} (on par)"
    pct_diff = ((val - bval) / bval) * 100.0
    is_better = (pct_diff > 0.0) if direction == "higher" else (pct_diff < 0.0)
    sign_str = f"{pct_diff:+.1f}%"
    if markdown_color:
        color = "green" if is_better else "red"
        tex_str = sign_str.replace("%", r"\%")
        return f"{core}<br>($`\\color{{{color}}}{{{tex_str}}}`$)"
    return f"{core} ({sign_str})"


def print_table(
    metrics: Dict[str, Dict[str, Any]],
    baseline: Optional[Dict[str, Dict[str, Any]]] = None,
    markdown_color: bool = False,
) -> None:
    col_header = "Measured (mean ± stdev)" if baseline is None else "Measured vs. Baseline"
    print(f"\n| Metric<br>(unit, lower/higher is better) | {col_header} |")
    print("| :--- | ---: |")
    for key, label, unit, direction in METRIC_SPECS:
        if key not in metrics:
            continue
        dir_txt = "higher is better" if direction == "higher" else "lower is better"
        base_stat = baseline.get(key) if baseline else None
        cell = format_cell(metrics[key], base_stat, direction, markdown_color=markdown_color)
        print(f"| {label}<br>({unit}, {dir_txt}) | {cell} |")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run the ESP8266 OSS Wi-Fi benchmark suite against a flashed device IP."
    )
    ap.add_argument("ip", help="IPv4 address of the target ESP8266 device web interface")
    ap.add_argument("--port", type=int, default=80, help="HTTP port (default: 80)")
    ap.add_argument(
        "--runs", type=int, default=7,
        help="Iterations per test (default: 7; drops single min & max when >= 4)",
    )
    ap.add_argument("--skip-reboot", action="store_true", help="Skip the warm-reboot reconnect test")
    ap.add_argument("--json", dest="json_out", help="Optional path to save raw JSON results")
    ap.add_argument("--baseline", help="Optional baseline JSON from a previous run for delta percentages")
    ap.add_argument(
        "--markdown-color", action="store_true",
        help="Format delta percentages on a new line (<br>) with KaTeX/GitHub green/red color markup",
    )
    args = ap.parse_args()

    # Probe device availability
    st, disc_raw, _ = http_req(args.ip, args.port, "GET", "/!sys/discover", timeout=10.0)
    if st != 200:
        print(f"ERROR: Could not reach http://{args.ip}:{args.port}/!sys/discover (HTTP {st})", file=sys.stderr)
        return 1
    discover = json.loads(disc_raw.decode("utf-8", errors="replace"))
    fw = discover.get("firmware") or {}
    fw_label = f"{fw.get('name', 'ESP8266')} {fw.get('version', '')} (idf {fw.get('idf_ver', '?')})".strip()
    print(f"Target: http://{args.ip}:{args.port} ({fw_label}, runs={args.runs})", flush=True)

    metrics: Dict[str, Dict[str, Any]] = {}

    if not args.skip_reboot:
        print("[1/11] Warm Reboot -> HTTP Ready...", flush=True)
        metrics["warm_reboot_ms"] = trimmed_stats(bench_warm_reboot(args.ip, args.port, args.runs))

    print("[2/11] Modem-Sleep Wake Latency (5 s idle)...", flush=True)
    metrics["ps_wake_ms"] = trimmed_stats(bench_ps_wake(args.ip, args.port, args.runs, idle_s=5.0))

    print("[3/11] Active Wi-Fi Scan (APSTA)...", flush=True)
    metrics["wifi_scan_ms"] = trimmed_stats(bench_wifi_scan(args.ip, args.port, args.runs))

    print("[4/11] Idle ICMP RTT (32 B, 100x)...", flush=True)
    p50_32, _ = bench_seq_icmp(args.ip, 32, args.runs, count=100)
    metrics["icmp_32b_p50_ms"] = trimmed_stats(p50_32)

    print("[5/11] Fragmented ICMP Burst (5800 B, 4-frag, 100x)...", flush=True)
    _, pps_5800 = bench_seq_icmp(args.ip, 5800, args.runs, count=100)
    metrics["icmp_5800b_pps"] = trimmed_stats(pps_5800)

    print("[6/11] Heavy-MTU Saturation (4w x 100 @ 1400 B)...", flush=True)
    fl_pps, fl_p99 = bench_icmp_flood(args.ip, 1400, 4, 100, args.runs)
    metrics["flood_1400b_pps"] = trimmed_stats(fl_pps)
    metrics["flood_1400b_p99_ms"] = trimmed_stats(fl_p99)

    print("[7/11] Uncontested Downlink (1 MB /!sys/storage)...", flush=True)
    metrics["dl_1mb_kbs"] = trimmed_stats(bench_downlink_1mb(args.ip, args.port, args.runs, contended=False))

    print("[8/11] Flash-Read Contended Downlink (1 MB + 20 ms 1400 B ICMP)...", flush=True)
    metrics["dl_1mb_contended_kbs"] = trimmed_stats(bench_downlink_1mb(args.ip, args.port, args.runs, contended=True))

    print("[9/11] WebDAV Storage Write / Read (128 KB PUT / GET, SHA-256)...", flush=True)
    wd_put, wd_get = bench_webdav_128k(args.ip, args.port, args.runs)
    metrics["webdav_put_128k_kbs"] = trimmed_stats(wd_put)
    metrics["webdav_get_128k_kbs"] = trimmed_stats(wd_get)

    print("[10/11] Flash-Erase Contention (128 KB PUT + 32 B & 4200 B ICMP)...", flush=True)
    _, e32_p95, e32_gt40 = bench_flash_erase_contention(args.ip, args.port, 32, 0.020, args.runs)
    metrics["erase_32b_p95_ms"] = trimmed_stats(e32_p95)
    metrics["erase_32b_gt40_pct"] = trimmed_stats(e32_gt40)

    e4200_put, e4200_p95, _ = bench_flash_erase_contention(args.ip, args.port, 4200, 0.030, args.runs)
    metrics["erase_4200b_put_kbs"] = trimmed_stats(e4200_put)
    metrics["erase_4200b_p95_ms"] = trimmed_stats(e4200_p95)

    print("[11/11] Concurrent HTTP (6w x 25 discover close & 4w x 40 boot_serial KA)...", flush=True)
    metrics["http_conc_disc_rps"] = trimmed_stats(
        bench_concurrent_http(args.ip, args.port, "/!sys/discover", 6, 25, False, args.runs)
    )
    metrics["http_conc_ka_rps"] = trimmed_stats(
        bench_concurrent_http(args.ip, args.port, "/!sys/boot_serial", 4, 40, True, args.runs)
    )

    baseline_metrics = None
    if args.baseline:
        base_doc = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        baseline_metrics = base_doc.get("metrics", base_doc)

    print_table(metrics, baseline=baseline_metrics, markdown_color=args.markdown_color)

    if args.json_out:
        out_doc = {
            "meta": {
                "runs": args.runs,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "platform": platform.system(),
            },
            "metrics": metrics,
        }
        Path(args.json_out).write_text(json.dumps(out_doc, indent=2), encoding="utf-8")
        print(f"\nSaved JSON -> {args.json_out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
