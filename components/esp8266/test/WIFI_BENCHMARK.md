# ESP8266 Wi-Fi Stack Benchmark Guide (`WIFI_BENCHMARK.md`)

Reproducible instructions for benchmarking the ESP8266 Wi-Fi stack (`Vendor Blobs` vs. `OSS Baseline` vs. `OSS + IRAM Fast TX`) using [`wifi_benchmark.py`](wifi_benchmark.py). The script drives a running device solely over its HTTP/ICMP network interface—no serial console, JTAG probe, or automated flashing harness is required.

---

## 1. Prerequisites

- **Host Machine**: Python **3.9+** (standard library only; zero `pip` packages required).
  - **Windows**: Uses native `iphlpapi.dll` (`IcmpSendEcho`) for sub-millisecond ICMP timing with **no Administrator privileges** required.
  - **Linux / macOS**: Automatically falls back to the system `ping` utility.
- **Network**: Host and ESP8266 on the same 2.4 GHz WLAN / LAN segment. For repeatable A/B comparisons, run each firmware variant back-to-back in the same physical position and quiet RF window.
- **Target Firmware**: An ESP8266 (4 MB flash, 160 MHz CPU) running the **`ESPZWApplianceT2`** base firmware with:
  - Station (`STA`) connected to your Wi-Fi AP and reachable at `<device-ip>`.
  - **WebDAV enabled** on the `/system` LittleFS partition (used for 128 KB storage throughput and `spi_flash_erase_sector` contention tests; the script cleans up its temporary `_wifi_bench_*.bin` files automatically).
  - Standard system REST endpoints active: `/!sys/discover`, `/!sys/boot_serial`, `/!sys/reboot`, `/!sys/storage`, `/!sys/prov/sta.aplist`.

---

## 2. Building the Three Firmware Variants

Build and flash whichever firmware configuration you want to measure (via serial or the device Web OTA UI):

| Variant | SDK Branch / Environment | Key Kconfig Setting (`sdkconfig`) |
| :--- | :--- | :--- |
| **Vendor Blobs** | `deploy/live-gcc16-oss` (or `deploy/live-gcc16`) | `CONFIG_ESP8266_VENDOR_BLOBS=y`, `CONFIG_ESP8266_VENDOR_HAL=y`, `CONFIG_ESP8266_VENDOR_CORE=y`, `CONFIG_ESP8266_VENDOR_PHY_WIFI=y` |
| **OSS Minimal NMI** | `deploy/live-gcc16-oss` (e.g., `esp01_4m`) | Default OSS (`# CONFIG_ESP8266_VENDOR_BLOBS is not set`) + **`CONFIG_ESP8266_OSS_WIFI_MIN_NMI=y`** |
| **OSS Default (Fast TX)** | `deploy/live-gcc16-oss` (e.g., `esp01_4m`) | Out-of-the-box defaults (`CONFIG_ESP8266_OSS_PHY_WIFI=y`, `# CONFIG_ESP8266_OSS_WIFI_MIN_NMI is not set`) |

> **Tip**: Keep all non-Wi-Fi settings identical across variants (`CONFIG_ESP8266_DEFAULT_CPU_FREQ_160=y`, `CONFIG_ESP8266_WIFI_RX_BUFFER_NUM=16`, `CONFIG_ESP8266_WIFI_TX_PKT_NUM=6`, `CONFIG_COMPILER_OPTIMIZATION_LEVEL_RELEASE=y`, `WIFI_PS_MIN_MODEM`).

---

## 3. Running the Benchmark

### Single Firmware Run

```bash
python components/esp8266/test/wifi_benchmark.py 192.0.2.10
```

Replace `192.0.2.10` with your device's IPv4 address. By default, each test executes **`7` iterations** and computes a **trimmed mean ± stdev** (dropping the single best and single worst sample, yielding 5-of-7 statistics). A full 7-run pass takes ~4 minutes.

### Full A/B Comparison (Vendor vs. OSS Baseline vs. OSS + IRAM Fast TX)

1. Flash the **Vendor Blobs** firmware, wait for it to join Wi-Fi, and capture the baseline JSON:
   ```bash
   python components/esp8266/test/wifi_benchmark.py 192.0.2.10 --runs 7 --json vendor.json
   ```
2. Flash the **OSS Minimal NMI (`CONFIG_ESP8266_OSS_WIFI_MIN_NMI=y`)** firmware and compare against `vendor.json`:
   ```bash
   python components/esp8266/test/wifi_benchmark.py 192.0.2.10 --runs 7 --json oss_base.json --baseline vendor.json
   ```
3. Flash the **OSS Default (`CONFIG_ESP8266_OSS_WIFI_MIN_NMI=n`, fast TX enabled)** firmware and compare against `vendor.json`:
   ```bash
   python components/esp8266/test/wifi_benchmark.py 192.0.2.10 --runs 7 --json oss_fast.json --baseline vendor.json
   ```

### Useful CLI Options

| Flag | Default | Purpose |
| :--- | :--- | :--- |
| `--port <N>` | `80` | Target HTTP port if not standard port 80. |
| `--runs <N>` | `7` | Number of iterations per workload (`>= 4` enables min/max trimming). |
| `--skip-reboot` | off | Skip the `/!sys/reboot` reconnect latency test. |
| `--json <path>` | none | Save raw per-run samples and trimmed statistics to a JSON file. |
| `--baseline <path>` | none | Compare against a previously saved JSON and print percentage deltas (or `on par` when either mean is within the other's `±1σ` stdev range). |
| `--markdown-color` | off | Format delta percentages with KaTeX/GitHub green/red color markup matching [`../WIFI_DESIGN.md`](../WIFI_DESIGN.md). |

---

## 4. What the Suite Measures

| Category | Metrics | Architectural Path Stressed |
| :--- | :--- | :--- |
| **Lifecycle & Control** | Warm Reboot → HTTP Ready, Modem-Sleep Wake (5 s idle), Active Wi-Fi Scan | `RTC_SYS` PMK/channel fast-connect, `WIFI_PS_MIN_MODEM` RF wake, `ETSTimer` associated scan + home-channel visits |
| **ICMP Latency & Saturation** | Idle RTT (`32 B`), Fragmented Burst (`5800 B`, 4-frag), Heavy-MTU Flood (`4w × 100 @ 1400 B` PPS & `p99`) | RX/TX turnaround, back-to-back TXQ0 launch, 802.11 ACK-retry backoff & TRC stability |
| **Bulk Throughput** | Uncontested `1 MB` Downlink, WebDAV `128 KB PUT / GET` (SHA-256 verified) | Scatter-gather TX, worker coalescing/backpressure, LittleFS + lwIP pipelining |
| **Flash-Cache Contention** | `1 MB` Downlink + `20 ms 1400 B` ICMP; `128 KB PUT` + `20 ms 32 B` / `30 ms 4200 B` ICMP | `Cache_Read_Disable_2` (`spi_flash_read` / `spi_flash_erase_sector`) overlap with Level-3 NMI fast TX retry & next-slot launch |
| **Concurrency** | `6w × 25` `/!sys/discover` (close), `4w × 40` `/!sys/boot_serial` (Keep-Alive) | Event-ring batching, TCP connection churn, zero `vTaskSuspendAll()` scheduler stalls |
