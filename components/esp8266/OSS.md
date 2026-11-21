# Open-Source Binary Replacement & Provenance Log (`OSS.md`)

Public change log and license-compliance record for the open-source replacement of prebuilt binary static libraries in `ESP8266_RTOS_SDK` (`deploy/live-gcc16-oss`, compiled with `xtensa-esp-elf` GCC 16.2).

For the architecture of the replacement Wi-Fi stack and A/B performance results, see [WIFI_DESIGN.md](WIFI_DESIGN.md). For reproducible device benchmarking instructions, see [test/WIFI_BENCHMARK.md](test/WIFI_BENCHMARK.md).

---

## 1. Overview & Replacement Progress

Most upper-layer subsystems in `ESP8266_RTOS_SDK`—including FreeRTOS, lwIP, `tcpip_adapter`, `wpa_supplicant` (WPA2-PSK, WPA3-SAE, HostAP, WPS), `mbedtls`, `nvs_flash`, `spi_flash`, `vfs`, `newlib`, `bootloader`, `bootloader_support`, and peripheral drivers—are already open source, while `components/esp8266/lib/` historically shipped 11 prebuilt static archives (plus optional `components/esp-wolfssl/wolfssl/lib/libwolfssl*.a`).

### Current Milestone Summary
- **2nd-Stage Bootloader (`bootloader.bin`)**: **100% free of prebuilt vendor blobs** (`0` binary archives from `components/esp8266/lib/` linked; built entirely from open-source SDK C/ASM sources, toolchain `libgcc`, and ESP8266 Mask ROM symbols).
- **Default Application Build (`CONFIG_ESP8266_VENDOR_BLOBS=n`, Full Wi-Fi STA + SoftAP + APSTA + WPA2/WPA3-SAE + Modem Sleep)**: **100% free of prebuilt vendor blobs** (`0` binary archives linked; `components/esp8266/lib/` is excluded from the link; `libgcc.a`, `libssc.a`, and obsolete 2018 `components/esp-wolfssl/wolfssl/lib/libwolfssl*.a` removed from the repository; open-source `OSS_HAL`, `OSS_CORE`, and `OSS_WIFI` enabled by default with IRAM NMI fast TX active).
- **Opt-In Legacy Vendor Compatibility (`CONFIG_ESP8266_VENDOR_BLOBS=y`)**: Unlocks mutually exclusive vendor fallback selections (`CONFIG_ESP8266_VENDOR_HAL`, `CONFIG_ESP8266_VENDOR_WIFI`, `CONFIG_ESP8266_VENDOR_CORE`) plus optional `CONFIG_ESP8266_VENDOR_ESPNOW` and `CONFIG_ESP8266_VENDOR_SMARTCONFIG` (gated on `CONFIG_ESP8266_VENDOR_WIFI`).

### Master Archive Status Table

| Archive | Original Size (`.o` Count) | Current Status | Kconfig Option (Default) | Open-Source Replacement Path | Replacement License |
| :--- | ---: | :--- | :--- | :--- | :--- |
| `libgcc.a` | `600,904 B` (`86`) | **Replaced & Removed** | Always active | `tools/cmake/romstrip.cmake` + `tools/cmake/scripts/strip_rom_libgcc.py` (`libgcc_romstrip.a`) | `GPL-3.0-with-GCC-Runtime-Library-Exception` (build scripts: `Apache-2.0`) |
| `libssc.a` | `11,996 B` (`2`) | **Removed** | Unreferenced | Unused legacy serial test console (`include/esp_ssc.h`) | N/A |
| `libwolfssl.a` (`_debug`) | `1,843,000 B` / `2,127,680 B` | **Removed** | `CONFIG_ESP_TLS_USING_MBEDTLS` (`y`) | Replaced by built-in open-source `components/mbedtls/` (obsolete 2018 wolfSSL 3.15.7 blobs removed) | `Apache-2.0` (`mbedtls`) |
| `libhal.a` | `162,888 B` (`126`) | **Replaced (Opt-In Fallback)** | `CONFIG_ESP8266_OSS_HAL` (`y`) / `VENDOR_HAL` (`n`) | `components/esp8266/source/xtensa_hal.S` | `MIT` |
| `libclk.a` / `librtc.a` | `4,976 B` / `5,048 B` (`2`) | **Replaced (Opt-In Fallback)** | `CONFIG_ESP8266_OSS_CORE` (`y`) / `VENDOR_CORE` (`n`) | `components/esp8266/source/esp_clk_rtc.c` | `Apache-2.0` + `MIT` |
| `libcore.a` (`_dbg`) | `39,742 B` / `40,650 B` (`9`) | **Replaced (Opt-In Fallback)** | Bootloader: always OSS; App: `CONFIG_ESP8266_OSS_CORE` (`y`) / `VENDOR_CORE` (`n`) | `components/esp8266/source/{esp_ets_timer.c, esp_misc.c, esp_misc_nvs.c, esp_sys_ctrl.c}` | `Apache-2.0` |
| `libphy.a` | `265,988 B` (`11`) | **Replaced (Opt-In Fallback)** | `CONFIG_ESP8266_OSS_WIFI` (`y`) / `VENDOR_WIFI` (`n`) | `components/esp8266/phy/` (`8` `.c` + `2` `.h`) | `Apache-2.0` + `MIT` |
| `libpp.a` (`_dbg`) | `248,934 B` / `268,090 B` (`9`) | **Replaced (Opt-In Fallback)** | `CONFIG_ESP8266_OSS_WIFI` (`y`) / `VENDOR_WIFI` (`n`) | `components/esp8266/lmac/` (`6` `.c` + `3` `.h`) | `Apache-2.0` + `MIT` |
| `libnet80211.a` (`_dbg`) | `485,352 B` / `544,252 B` (`30`) | **Replaced (Opt-In Fallback)** | `CONFIG_ESP8266_OSS_WIFI` (`y`) / `VENDOR_WIFI` (`n`) | `components/esp8266/net80211/` (`9` `.c` + `1` `.h`) | `Apache-2.0` + `MIT` |
| `libsmartconfig.a` | `156,402 B` (`8`) | **Optional Vendor Blob (Off)** | `CONFIG_ESP8266_VENDOR_SMARTCONFIG` (`n`, requires `VENDOR_WIFI`) | Gates `libsmartconfig.a`, `source/smartconfig.c`, and `source/smartconfig_ack.c` | `Apache-2.0` (wrappers) |
| `libespnow.a` (`_dbg`) | `38,660 B` (`2`) | **Optional Vendor Blob (Off)** | `CONFIG_ESP8266_VENDOR_ESPNOW` (`n`, requires `VENDOR_WIFI`) | `esp_now_deinit()` stub in `components/esp8266/source/esp_wifi.c` when disabled | `Apache-2.0` |

---

## 2. Per-Module Change Log

### 2.1 Compiler Runtime (`libgcc.a` -> Toolchain `libgcc_romstrip.a`)

#### What Was Removed / Replaced
- Removed the prebuilt GCC 4.8.2 archive `components/esp8266/lib/libgcc.a` (`600,904 B`, `86` object members), eliminating legacy DWARF unwind (`unwind-dw2.o`, `unwind-dw2-fde.o`) and `emutls.o` objects that conflicted with modern GCC 16.2 `libstdc++.a` and duplicated ESP8266 Mask ROM routines.

#### Replacement Implementation
- `tools/cmake/romstrip.cmake` and `tools/cmake/scripts/strip_rom_libgcc.py` query the active compiler's `esp8266` Call0 multilib (`-mdynconfig=xtensa_esp8266.so`, honoring `-fno-rtti`) via `-print-file-name=libgcc.a` and strip only those archive members whose defined global symbols are already provided by the ESP8266 Mask ROM linker script (`components/esp8266/ld/esp8266.rom.ld`).
- Both `components/esp8266/CMakeLists.txt` (bootloader and application builds) and `components/newlib/CMakeLists.txt` link the generated `libgcc_romstrip.a`, while `components/esp8266/linker.lf` (`[mapping:gcc]`) maps cold unwind and non-ROM soft-float helpers to flash (`.flash.text`) so scarce 32 KB IRAM is preserved.

#### Origin & License Compliance
- **Runtime Archive (`libgcc_romstrip.a`)**: Derived directly at build configuration time from GNU `libgcc.a` in the active `xtensa-esp-elf` GCC 16.2 toolchain under **`GPL-3.0-with-GCC-Runtime-Library-Exception`**.
- **Build & Linker Integration (`romstrip.cmake`, `strip_rom_libgcc.py`, `linker.lf`, `cxx_abi.cpp`)**: Authored for `ESP8266_RTOS_SDK` under **`Apache-2.0`**, referencing `components/esp8266/ld/esp8266.rom.ld`.

#### Test Strength & Robustness
- Compiled cleanly with `0` compiler warnings across bootloader and C/C++20/C++17 application targets.
- Linker map and symbol verification confirmed all Mask ROM math and memory intrinsics (`memcpy`, `memset`, `memmove`, `memcmp`, `bzero`, `__divsi3`, `__udivsi3`, `__adddf3`) resolve to Mask ROM (`0x4000xxxx`), `.init_array` global constructors execute properly, and unused C++ exception personality/demangler objects (`eh_personality.o`) are absent when exceptions are disabled.
- Validated on physical ESP8266 hardware across C++ global constructor and `std::shared_ptr` checks, 64-bit integer/floating-point paths, WPA3-SAE ECC handshakes, VFS/LittleFS file operations, and concurrent HTTP workloads.

---

### 2.2 Xtensa LX106 Core HAL (`libhal.a` -> `components/esp8266/source/xtensa_hal.S`)

#### What Was Removed / Replaced
- Removed the prebuilt GCC 4.8.2 archive `components/esp8266/lib/libhal.a` (`162,888 B`, `126` object members) and replaced its Xtensa LX106 Call0 Core HAL routines with **25 exported global symbols** (**19 assembly functions + 6 symbol aliases**):
  - **Cycle counter & timers**: `xthal_get_ccount`, `xthal_get_ccompare`, `xthal_set_ccompare`.
  - **Interrupt special registers**: `xthal_set_intset`, `xthal_set_intclear`, `xthal_get_intenable`, `xthal_set_intenable`, `xthal_get_interrupt` (alias `xthal_get_intread`).
  - **Processor ID**: `xthal_get_prid`.
  - **Call0 window/coprocessor state no-ops**: `xthal_window_spill`, `xthal_window_spill_nw` (alias `xthal_spill_registers_into_stack_nw`), `xthal_save_extra`, `xthal_save_extra_nw`, `xthal_restore_extra`, `xthal_restore_extra_nw`.
  - **Cache/pipeline synchronization helpers**: `xthal_icache_sync` (`_nw`), `xthal_dcache_sync` (`_nw`), `xthal_icache_all_invalidate` (`_nw`), `xthal_dcache_all_invalidate` (`_nw`).

#### Replacement Implementation
- Implemented in `components/esp8266/source/xtensa_hal.S`, enabled by `CONFIG_ESP8266_OSS_HAL` (default `y`).
- Each routine is emitted into its own `.iram1.text.<name>` section via the `XTHAL_FUNC` macro (`components/esp8266/ld/esp8266_fragments.lf` maps `.iram1+` to `iram0_text`). Callers executing in ISRs or while SPI flash cache is disabled (such as FreeRTOS `PendSV` calling `xthal_set_intset` and microsecond delay loops calling `xthal_get_ccount`) remain safely in IRAM, while `-Wl,--gc-sections` discards unreferenced helpers, reducing static IRAM usage by `24 B` (`+24 B` free IRAM heap) relative to `libhal.a`.

#### Origin & License Compliance
- Authored under the **`MIT`** license (`components/esp8266/source/xtensa_hal.S`), referencing the MIT-licensed Tensilica / Cadence Xtensa HAL interface and LX106 core configuration headers already distributed in `components/esp8266/include/xtensa/` (`hal.h`, `coreasm.h`, `specreg.h`, `config/core-isa.h`).

#### Test Strength & Robustness
- Built with `0` compiler/assembler warnings; linker map inspection confirmed `0` references to `libhal.a`, IRAM placement for active `xthal_get_ccount` and `xthal_set_intset` routines, and `--gc-sections` elimination of unreferenced HAL symbols.
- Validated on physical ESP8266 hardware under FreeRTOS `PendSV` software-interrupt context switching (`ETS_SOFT_INUM`), microsecond hardware delays during SPI flash erase/write cycles, Wi-Fi STA + SoftAP operation, and concurrent HTTP load with `-24 B` static IRAM and `+24 B` runtime IRAM heap headroom.

---

### 2.3 2nd-Stage Bootloader SoC Core (Bootloader `libcore.a` -> `components/esp8266/source/esp_misc.c`)

#### What Was Removed / Replaced
- Removed `-lcore` (`libcore.a`) and `-L ${CMAKE_CURRENT_SOURCE_DIR}/lib` from `ESP8266_BOOTLOADER_LIBS` in `components/esp8266/CMakeLists.txt` (and `components/bootloader/subproject/main/component.mk`), replacing all **4 SoC hardware primitives (5 exported global symbols)** needed by the 2nd-stage bootloader:
  - `void phy_reg_default(void)` — initializes default RF/PHY register `0x60009D74` based on eFuse package/type bits in `EFUSE_DATA2_REG` (`0x3FF00058`).
  - `RESET_REASON rtc_get_reset_reason(int cpu_no)` — decodes hardware reset cause from `RTC_STATE1` (`0x60000714`) and wakeup cause from `RTC_STATE2` (`0x60000718`), clearing `BIT(21)` in `REG_RTC_BASE + 0x08` (`0x60000708`).
  - `void uart_div_modify(uint32_t uart_no, uint32_t baud_div)` — updates `UART_CLKDIV(port)` and pulses `UART_TXFIFO_RST | UART_RXFIFO_RST` in `UART_CONF0(port)`.
  - `void os_delay_us(uint16_t us)` and `void ets_delay_us(uint32_t us)` — cycle-accurate spin-wait using Mask ROM `xthal_get_ccount()` (`0x4000dd38` in `esp8266.bootloader.rom.ld`) scaled by the pre-BBPLL crystal clock (`CONFIG_ESP8266_XTAL_FREQ * 2`, or `* 4` when `DPORT_CTL_DOUBLE_CLK` is set).

#### Replacement Implementation
- Initially staged in `bootloader_core.c` and now unified directly into `components/esp8266/source/esp_misc.c` (compiled cleanly in both `BOOTLOADER_BUILD` and application builds via `#ifdef BOOTLOADER_BUILD` guards).

#### Origin & License Compliance
- Authored as clean-room C under **`Apache-2.0`**, using existing SDK register and ROM headers (`esp8266/eagle_soc.h`, `esp8266/efuse_register.h`, `esp8266/rom_functions.h`, `esp8266/rtc_register.h`, `esp8266/uart_register.h`, `rom/ets_sys.h`, `<xtensa/hal.h>`, `components/bootloader_support/src/bootloader_init.c`, and `components/bootloader/subproject/main/esp8266.bootloader.rom.ld`).

#### Test Strength & Robustness
- Built with `0` compiler warnings; bootloader linker map and ELF symbol audits confirmed **0 proprietary archives linked** into `bootloader.elf`, with `bootloader.bin` shrinking by `16 B` (`9,872 B`, well below the `32,768 B` partition table boundary at `0x8000`).
- Serial-flashed to offset `0x0000` on physical ESP8266 hardware and verified across cold/RTS/software resets, 74880-baud boot logging, SPI flash QIO/DIO initialization, and dual-slot OTA partition switching (`ota_0` <-> `ota_1`).

---

### 2.4 Optional & Unused Binary Archives (`libssc.a`, `libsmartconfig.a`, `libespnow.a`, `libwolfssl*.a`)

#### What Was Removed / Replaced
- **`libssc.a` (`11,996 B`)**: Unreferenced legacy serial AT/test console archive removed from `components/esp8266/lib/`, `CMakeLists.txt`, and `component.mk`.
- **`libsmartconfig.a` (`156,402 B`)**: Optional sniffer-based Wi-Fi provisioning archive (and wrapper sources `source/smartconfig.c`, `source/smartconfig_ack.c`) gated behind `CONFIG_ESP8266_VENDOR_SMARTCONFIG` (default `n`; requires `CONFIG_ESP8266_VENDOR_BLOBS && CONFIG_ESP8266_VENDOR_WIFI`).
- **`libespnow.a` / `libespnow_dbg.a` (`38,660 B`)**: Optional vendor Action-frame protocol archive gated behind `CONFIG_ESP8266_VENDOR_ESPNOW` (default `n`; requires `CONFIG_ESP8266_VENDOR_BLOBS && CONFIG_ESP8266_VENDOR_WIFI`).
- **`libwolfssl.a` / `libwolfssl_debug.a` (`1,843,000 B` / `2,127,680 B`)**: Removed obsolete 2018 wolfSSL 3.15.7 component (`components/esp-wolfssl/`) and wolfSSL glue from `components/esp-tls/`, standardizing on the built-in open-source `mbedTLS` backend (`CONFIG_ESP_TLS_USING_MBEDTLS`).

#### Replacement Implementation
- Because `libnet80211.a(ieee80211_api.o)` unconditionally calls `esp_now_deinit()` inside `esp_wifi_stop()`, `components/esp8266/source/esp_wifi.c` provides a clean-room `#ifndef CONFIG_ESP8266_VENDOR_ESPNOW` stub (`esp_err_t esp_now_deinit(void) { return ESP_OK; }`), allowing Wi-Fi stop/restart and mode transitions to link and execute cleanly without `libespnow.a`.

#### Origin & License Compliance
- Build-system gates (`CMakeLists.txt`, `component.mk`, `Kconfig`) and the `esp_now_deinit()` stub in `components/esp8266/source/esp_wifi.c` are authored under **`Apache-2.0`** against public API declarations in `components/esp8266/include/esp_now.h` and `esp_smartconfig.h`.

#### Test Strength & Robustness
- Linker map verification confirmed `0` bytes and `0` symbols from `libssc.a`, `libsmartconfig.a`, `libespnow*.a`, and `libwolfssl*.a` in default builds, saving `56 B` of static DRAM, `424 B` of `.flash.rodata`, and `448 B` of flash image size (`+32 B` to `+48 B` additional 8-bit free/min-free heap at runtime).
- Verified on physical ESP8266 hardware across full STA association, `esp_wifi_stop()` teardown, `WIFI_MODE_APSTA` SoftAP provisioning transitions, and OTA reboots.

---

### 2.5 RTC & Clock Driver (`libclk.a` & `librtc.a` -> `components/esp8266/source/esp_clk_rtc.c`)

#### What Was Removed / Replaced
- Replaced the prebuilt archives `components/esp8266/lib/libclk.a` (`4,976 B`, `1` object member) and `components/esp8266/lib/librtc.a` (`5,048 B`, `1` object member) (retained only as opt-in fallback under `CONFIG_ESP8266_VENDOR_CORE`), covering all **6 exported RTC/light-sleep clock primitives**:
  - `rtc_init_clk`, `phy_open_rf`, `rtc_wakeup_init`, `rtc_lightsleep_init`, `rtc_set_sleep_time`, `rtc_light_sleep_start`.
- Also provides `sleep_reset_analog_rtcreg_8266()` under `CONFIG_ESP8266_NO_WIFI` for standalone RTC analog reset without Wi-Fi/PHY.

#### Replacement Implementation
- Implemented in `components/esp8266/source/esp_clk_rtc.c` (`0 B` IRAM; all functions in `.flash.text`), enabled by default via `CONFIG_ESP8266_OSS_CORE`.
- Preserves the `librtc.a` `chip6_phy_init_ctrl[0]` / `[76]` BBPLL trigger and `g_phyFuns` (`offset 0x98`) RF I2C dispatch (`(0x62, 1, 3, 1)`), together with `libclk.a`'s defensive bitfield masks (`wakeup_opt & 0x3FU`, `reject_opt & 0x01U`) in `rtc_light_sleep_start()`, plus clean-room MMIO/ROM-I2C RTC analog reset and 26 MHz BBPLL init fallback paths when `CONFIG_ESP8266_NO_WIFI=y`.

#### Origin & License Compliance
- Authored as clean-room C under **`Apache-2.0`** using public SDK headers (`esp8266/eagle_soc.h`, `esp8266/rtc_register.h`, `esp8266/rom_functions.h`, `driver/rtc.h`, `rom/ets_sys.h`), with the standalone `CONFIG_ESP8266_NO_WIFI` RTC analog reset and BBPLL initialization sequences adapted from `teatime-os` under its preserved **`MIT`** license notice.

#### Test Strength & Robustness
- Compiled cleanly with `0` compiler warnings under GCC 16.2 (`-fno-common`) in both default Wi-Fi (`CONFIG_ESP8266_OSS_WIFI=y`) and non-Wi-Fi (`CONFIG_ESP8266_NO_WIFI=y`) configurations, with `0` references to `libclk.a` or `librtc.a` in linker maps.
- Validated on physical ESP8266 hardware across cold/software resets, 80 MHz / 160 MHz CPU clock transitions, RF/Wi-Fi STA + SoftAP operation, and standalone zero-blob boot/restart cycles.

---

### 2.6 SoC Core & Zero-Blob Support (`libcore.a` / `libcore_dbg.a` -> `esp_ets_timer.c`, `esp_misc.c`, `esp_misc_nvs.c`, `esp_sys_ctrl.c`, `esp_no_blobs_stubs.c`)

#### What Was Removed / Replaced
- Replaced the prebuilt archives `components/esp8266/lib/libcore.a` (`39,742 B`, `9` object members) and `components/esp8266/lib/libcore_dbg.a` (`40,650 B`, `9` object members) (retained only as opt-in fallback under `CONFIG_ESP8266_VENDOR_CORE`), covering all application SoC core routines across four modular files:
  - **`components/esp8266/source/esp_ets_timer.c`**: `FRC2`-backed software timer subsystem (`ets_timer_setfn`/`os_timer_setfn`, `ets_timer_disarm`/`os_timer_disarm`, `ets_timer_arm`/`os_timer_arm`, `ets_timer_arm_us`/`os_timer_arm_us`, `ets_timer_arm_ms_us`, `ets_timer_done`, `ets_timer_proc`, `ets_timer_init`) with `28 B` `ETSTimer` ABI parity and `0 B` IRAM.
  - **`components/esp8266/source/esp_misc.c`**: Unified bootloader + app primitives (`phy_reg_default`, `rtc_get_reset_reason`, `uart_div_modify`, `os_delay_us`, `ets_delay_us`) plus app-only helpers (`esp_get_cpu_frequency`, `_putc1`, `os_install_putc1`, `os_putc`, `gpio_output_set`, `bit_popcount`, `uart_buff_switch`, `Uart_Init`), retiring `bootloader_core.c`.
  - **`components/esp8266/source/esp_misc_nvs.c`**: `misc` NVS namespace manager (`misc_nvs_load`, `misc_nvs_deinit`, `misc_nvs_init`, `misc_nvs_restore`), `36 B` `misc_nvs_t` ABI, Wi-Fi debug log globals (`g_log_level`, `g_log_mod`, `g_log_print`), `1,224 B` 8-byte aligned `g_cnxMgr` storage (for mixed `OSS_CORE` + `VENDOR_WIFI` compatibility), and full `CONFIG_ESP8266_WIFI_DEBUG_LOG_ENABLE` verbose/warn logging parity.
  - **`components/esp8266/source/esp_sys_ctrl.c`**: ADC/VDD33 scaling (`system_adc_read`, `system_adc_read_fast`, `system_get_vdd33`), flash size map (`system_get_flash_size_map`), CPU frequency scaling (`esp_set_cpu_freq`), microsecond clock (`esp_get_time`), UART TX flush (`user_uart_wait_tx_fifo_empty`), eFuse/RF calibration checksum (`flash_data_check`), hardware init helpers (`rtc_init`, `mac_init`, `base_gpio_init`, `wifi_timer_init`), software restart (`esp_restart` + IRAM `__esp_soc_restart`), and deep sleep (`system_deep_sleep_instant`, `esp_deep_sleep` + IRAM `__esp_soc_deep_sleep`).
  - **`components/esp8266/source/esp_no_blobs_stubs.c`**: Minimal non-Wi-Fi symbols (`CONFIG_ESP8266_NO_WIFI=y` only) so non-Wi-Fi firmware links with zero vendor `.a` archives.

#### Replacement Implementation & Robustness Fixes
- Enabled by default via `CONFIG_ESP8266_OSS_CORE`, with `components/esp8266/linker.lf` (`[mapping:esp8266]`) honoring `CONFIG_ESP8266_CORE_GLOBAL_DATA_LINK_IRAM` to keep core `.bss` in `.iram0.bss` with zero IRAM or DRAM regression (`+0 B` IRAM, `+0 B` DRAM, `-16 B` flash binary size).
- Only `__esp_soc_restart` (`124 B`) and `__esp_soc_deep_sleep` (`65 B`, GC'd when unused) reside in IRAM; all other routines remain in `.flash.text`.
- Resolves four latent vendor defects identified during clean-room implementation and hardware validation:
  1. **`misc_nvs_deinit()` NULL-dereference guard**: checks `g_misc_nvs != NULL` before reading `nvs_handle` or freeing.
  2. **`esp_restart()` `g_wifi_nvs` NULL guard**: guards dereferencing `g_wifi_nvs` when restarting before Wi-Fi initialization.
  3. **`esp_deep_sleep()` 64-bit cycle overflow check**: uses full 64-bit return from `pm_get_sleep_cycles_64()` with `> 0xFFFFFFFFULL` overflow rejection and 1-tick minimum clamp.
  4. **`__esp_soc_restart()` Mask ROM jump hygiene**: clears `INTENABLE` and Xtensa hardware watchpoint `DBREAKC0` and resets `a1` to top-of-DRAM (`0x3fffffb0`) before jumping to Mask ROM (`0x40000080`), preventing spurious UART interrupts and FreeRTOS end-of-stack watchpoint traps during 2nd-stage bootloader loading on low-DRAM (`CONFIG_ESP8266_NO_WIFI=y`) images.

#### Origin & License Compliance
- Authored as clean-room C under **`Apache-2.0`**, referencing public SDK headers (`rom/ets_sys.h`, `esp_system.h`, `esp_private/esp_system_internal.h`, `esp8266/*_register.h`, `nvs.h`, `esp_heap_caps.h`, `esp_log.h`, `driver/soc.h`).

#### Test Strength & Robustness
- Compiled with `0` compiler warnings under GCC 16.2 (`-fno-common`) across default Wi-Fi builds, `CONFIG_ESP8266_WIFI_DEBUG_LOG_ENABLE=y` builds (all 4 debug log sites verified), 2nd-stage bootloader builds, mixed `OSS_CORE` + `VENDOR_WIFI` builds, and `CONFIG_ESP8266_NO_WIFI=y` builds, with `0` references to `libcore.a` or `libcore_dbg.a`.
- Validated on physical ESP8266 hardware across both full Wi-Fi/HTTP/WebDAV/dual-slot OTA workloads (`+0 B` static IRAM, `+0 B` static DRAM, `-16 B` flash) and a standalone zero-blob (`CONFIG_ESP8266_NO_WIFI=y`) validation image exercising 160 MHz CPU scaling, FreeRTOS `vTaskDelay` (`200 ms`) vs. `esp_timer_get_time()` timing, NVS read/write, LittleFS mount/read, GPIO output, and live `esp_restart()` software reboot (`EXT -> SW`).

---

### 2.7 RF / Baseband / PHY Driver (`libphy.a` -> `components/esp8266/phy/`)

#### What Was Removed / Replaced
- Removed the prebuilt GCC 5.2.0 archive `components/esp8266/lib/libphy.a` (`265,988 B`, `11` object members) and replaced its entire RF, PLL, PBUS, SAR ADC, modem-sleep, TX power/calibration, and RX gain driver with **48 exported cross-boundary symbols** across eight modular C sources and two internal headers in `components/esp8266/phy/`:
  - `phy_regs.h` & `phy_internal.h` — hardware register banks (`APB`, `DPORT`, `SAR`, `I2C`, `WDEV`, `NRX`/`FE`, `RTC`), ABI `_Static_assert` guards for `phy_sleep_params_t` (`96 B`) and `esp_phy_funs_t` (`280 B`), explicit data initialization (zero `SHN_COMMON` globals), and internal prototypes.
  - `phy_i2c_pbus.c` — Mask ROM I2C bus arbitration (`rom_i2c_readReg`, `rom_i2c_readReg_Mask`, `rom_i2c_writeReg`, `rom_i2c_writeReg_Mask`), PBUS register access, SAR ADC bias control, and `phy_get_mactime()`.
  - `phy_clock.c` — Crystal frequency configuration, `bbpll_cal()`, `change_bbpll160()`, `change_bbpll160_sleep()`, and peripheral clock gating.
  - `phy_rf_chan.c` — RF power-on/close (`phy_close_rf()`), pure-integer RFPLL fractional-N sigma-delta tuning and digital spur cancellation (`phy_change_channel()`), and baseband RX path setup (`phy_set_rx11b_reg()`).
  - `phy_rxgain.c` — Dual-window baseband RX gain RAM table construction (`phy_rx_gain_dc_table`), `chip_v6_rxmax_ext()`, `phy_enable_agc()` / `phy_disable_agc()`, and hardware noise-floor measurement (`read_hw_noisefloor()`, `noise_check_loop()`).
  - `phy_cal_tx.c` — Full/partial I/Q, TX DC, RC filter, and loopback RX I/Q calibration, baseband EVM (`phy_get_bb_evm()`), frequency-offset readout (`phy_get_bb_freqoffset()`, preserving the signed `int16_t` return ABI in `a2` for `wDev_ProcessFiq`), SPI flash cache erratum helper (`phy_fix_cache_bug()`), VDD33 PA power ceiling (`phy_set_most_tpw()`, `phy_get_most_tpw()`, `phy_vdd33_set_tpw()`), and background TX power control (`tx_pwctrl_background()`).
  - `phy_sleep.c` — Modem/light/deep-sleep state transitions (`pm_set_sleep_mode()`, `pm_set_sleep_cycles()`, `pm_goto_sleep()`, `pm_wakeup_init()`, `pm_set_wakeup_mac()`, `pm_set_wakeup_btco()`), two-step RTC clock calibration (`pm_rtc_clock_cali()`), 64-bit microsecond-to-RTC tick conversion (`pm_usec2rtc()`, `pm_usec2rtc_64()`), `deep_sleep_set_option()`, `clockgate_watchdog()`, and `sleep_reset_analog_rtcreg_8266()`.
  - `phy_adc.c` — SAR ADC sampling (`test_tout()`, `phy_adc_read_fast()`, `phy_get_vdd33()`) and `adc_rand_noise` entropy collection.
  - `phy_core.c` — `esp_phy_init_data_t` (`128 B`) validation and application (`phy_check_data_table()`, `register_chipv6_phy_init_param()`), `g_phyFuns` dispatch table export (`phy_get_romfunc_addr()`), NVS calibration state load/save, and top-level PHY initialization (`register_chipv6_phy()`).

#### Replacement Implementation
- Compiled cleanly with GCC 16.2 (`-fno-common`), enabled by default via `CONFIG_ESP8266_OSS_WIFI`, with shared coexistence guards in `components/esp8266/source/esp_clk_rtc.c`, `esp_sys_ctrl.c`, and `esp_no_blobs_stubs.c` for both Wi-Fi and standalone `CONFIG_ESP8266_NO_WIFI=y` configurations.
- Replaces `libphy.a`'s blanket `* (noflash_text)` IRAM mapping (`linker.lf`, now gated under `CONFIG_ESP8266_VENDOR_WIFI`) with targeted `IRAM_ATTR` placement strictly on the **10 IRAM-safe hot-path and flash-disabled functions** (`rom_i2c_readReg`, `rom_i2c_readReg_Mask`, `rom_i2c_writeReg`, `rom_i2c_writeReg_Mask`, `phy_get_mactime`, `clockgate_watchdog`, `pm_goto_sleep`, `phy_get_bb_evm`, `phy_fix_cache_bug`, `phy_get_bb_freqoffset`), keeping calibration, channel tuning, and gain tables in flash.
- Uses 100% pure-integer 64-bit arithmetic for RFPLL sigma-delta synthesis, spur cancellation, and RTC clock scaling with **0 soft-float helper imports**.

#### Origin & License Compliance
- Authored as clean-room C under **`Apache-2.0`** (`phy_internal.h`, `phy_adc.c`, `phy_core.c`, and shared SDK/build integration) against public SDK headers (`esp_phy_init.h`, `driver/rtc.h`, `esp8266/eagle_soc.h`, `esp8266/rom_functions.h`, `esp8266/rtc_register.h`, `phy_init_data.h`).
- Preserves upstream **`MIT`** license notices (`Copyright (c) 2025-2026 Jonathan Waters`, `teatime-os`) alongside **`Apache-2.0`** on modules containing adapted RF/PBUS/PLL/calibration/gain/sleep hardware sequences and register definitions (`phy_regs.h`, `phy_i2c_pbus.c`, `phy_clock.c`, `phy_rf_chan.c`, `phy_rxgain.c`, `phy_cal_tx.c`, `phy_sleep.c`).

#### Test Strength & Robustness
- Compiled with `0` compiler warnings under GCC 16.2 (`-Wall -Wextra -Werror -fno-common`) in both default Wi-Fi (`CONFIG_ESP8266_OSS_WIFI=y`) and `CONFIG_ESP8266_NO_WIFI=y` configurations, with `48/48` expected cross-boundary exports linked cleanly, `0` `libphy.a` references, `0` `SHN_COMMON` globals, and `0` soft-float helpers; reduced static IRAM by `1,216 B` (`+1,220 B` runtime IRAM heap headroom), static DRAM by `56 B`, and application binary size by `2,944 B`.
- Validated on physical ESP8266 hardware across erased-NVS cold-boot full RF calibration (`phy ver: 1167_0`) with NVS persistence, warm-reboot partial calibration reload (`checksum PASS`), multi-channel AP scanning, `WIFI_PS_MIN_MODEM` modem sleep/wake cycles, simultaneous STA + SoftAP operation, HTTP/WebDAV workloads, and dual-slot OTA upgrades.

---

### 2.8 Lower MAC / WDEV Driver (`libpp.a` / `libpp_dbg.a` -> `components/esp8266/lmac/`)

#### What Was Removed / Replaced
- Replaced the prebuilt archives `components/esp8266/lib/libpp.a` (`248,934 B`, `9` object members) and `components/esp8266/lib/libpp_dbg.a` (`268,090 B`, `9` object members) (retained only as opt-in fallback under `CONFIG_ESP8266_VENDOR_WIFI`, with `[mapping:pp]` and `[mapping:pp_dbg]` gated accordingly in `components/esp8266/linker.lf`), replacing the entire WDEV lower-MAC hardware driver with six modular C sources and three headers in `components/esp8266/lmac/`:
  - `esp_lmac.h`, `lmac_regs.h`, `lmac_internal.h` — clean public LMAC interface, `0x3FF20000` WDEV MMIO register definitions, and internal descriptor/state structures.
  - `lmac_nmi.c` — strict IRAM-only Level-3 NMI handler (`wDev_ProcessFiq`, compiled with `-fno-jump-tables` and `0 B` `.rodata`) and Level-1 SoftISR bridge (`MacIsrSigPostDefHdl`), respecting `xtensa_vectors.S` / `port.c` `NMIIrqIsOn` invariants. By default (`CONFIG_ESP8266_OSS_WIFI_MIN_NMI=n`), handles division-free TX re-arming, ACK/CTS retries, and queued next-slot launch directly inside `wDev_ProcessFiq` across SPI flash cache-disable windows (`2,762 B` IRAM, still recovering `~10.3 KB` of IRAM vs. `libpp.a`'s blanket `noflash_text` placement); setting `CONFIG_ESP8266_OSS_WIFI_MIN_NMI=y` trims this to `2,054 B` (`-708 B` IRAM).
  - `lmac_dma.c` — contiguous DMA-capable RX buffer ring (`CONFIG_ESP8266_WIFI_RX_BUFFER_NUM`), hardware wrap-around linearization, 4-byte FCS stripping, and calibrated RSSI readout.
  - `lmac_tx.c` — serialized hardware `TXQ0` engine with FIFO-preserving software priority (`VO/MGMT/BCN` ahead of `VI/BE/BK`), 12-byte scatter-gather DMA descriptor chains supporting arbitrary unaligned DRAM payload segments (`esp_lmac_tx_submit`), retry/timeout/hang recovery, and completion callbacks.
  - `lmac_trc.c` — windowed AARF 11b/11g/HT20 MCS transmit rate control (TRC) with mode-scoped peer tables (`STA` single peer + dynamically allocated SoftAP peer pool).
  - `lmac_crypto_vif.c` — hardware WEP/TKIP/CCMP key-table programming (including STA/SoftAP PTK/GTK and software CCMP/BIP fallback paths), dual-VIF MAC/BSSID filters, scan wildcard matching, SoftAP TBTT beacon timer/template engine, promiscuous sniffer hook, and 5-bank hardware MAC reset.
  - `lmac_pm_compat.c` — modem-sleep hooks (`pm_rtc_clock_cali_proc`, `wdev_get_tsf_time`, `wDev_MacTimSetFunc`, `reset_noise_timer`) and FreeRTOS/SDK runtime glue (`esp_wifi_post_timer_from_isr` with bounded `ets_timer_proc_one()`).

#### Replacement Implementation
- Enabled by default via `CONFIG_ESP8266_OSS_WIFI`, compiled with GCC 16.2 (`-fno-common`, `0` `SHN_COMMON` globals).
- Only the Level-3 NMI path and SoftISR trampoline in `lmac_nmi.c` (`2,762 B` default / `2,054 B` with `CONFIG_ESP8266_OSS_WIFI_MIN_NMI=y`) reside in IRAM; all DMA ring management, TX submission, rate control, crypto key programming, and beacon management execute from `.flash.text`.

#### Origin & License Compliance
- Authored as clean-room C under **`Apache-2.0`** (`esp_lmac.h`, `lmac_internal.h`, `lmac_trc.c`, `lmac_pm_compat.c`, and SDK/build integration).
- Preserves upstream **`MIT`** license notices (`Copyright (c) 2025-2026 Jonathan Waters`, `teatime-os`) alongside **`Apache-2.0`** on modules incorporating adapted ESP8266 WDEV register definitions and DMA/FIQ/CCMP hardware programming sequences (`lmac_regs.h`, `lmac_nmi.c`, `lmac_dma.c`, `lmac_tx.c`, `lmac_crypto_vif.c`).

#### Test Strength & Robustness
- Compiled with `0` warnings under GCC 16.2 (`-fno-common`), `0` `SHN_COMMON` symbols, `0 B` `.rodata` in `lmac_nmi.o`, and `2,762 B` default (`2,054 B` minimal) LMAC IRAM.
- Verified on physical ESP8266 hardware via a standalone zero-blob LMAC hardware test harness (NMI/WDT stability, promiscuous sniffer RX, 1-descriptor broadcast and 3-descriptor unaligned scatter-gather unicast Probe Requests with ACK RSSI, hardware CCMP key readback and encrypted TX, SoftAP TBTT beacon ticks, and RF close/open + 5-bank MAC reset recovery) and full production Wi-Fi workloads.

---

### 2.9 IEEE 802.11 MAC Stack (`libnet80211.a` / `libnet80211_dbg.a` -> `components/esp8266/net80211/`)

#### What Was Removed / Replaced
- Replaced the prebuilt archives `components/esp8266/lib/libnet80211.a` (`485,352 B`, `30` object members) and `components/esp8266/lib/libnet80211_dbg.a` (`544,252 B`, `30` object members) (retained only as opt-in fallback under `CONFIG_ESP8266_VENDOR_WIFI`), replacing the entire 802.11 management/data stack and `esp_wifi_*` public API with nine modular C sources and one internal header in `components/esp8266/net80211/`:
  - `net80211_internal.h` — internal 802.11 state, frame constants, and subsystem interfaces (`0` `SHN_COMMON` globals, retiring `g_cnxMgr`).
  - `net80211_worker.c` — single serialized FreeRTOS Wi-Fi worker task, bounded `ets_timer` drain, 100 ms housekeeping ticker, and minimal `128 B` IRAM ISR wakeup bridge.
  - `net80211_nvs_rtc.c` — Kconfig-gated `nvs.net80211` persistence, `64 B` `RTC_SYS` warm-reboot fast-connect PMK + channel cache (`esp_wifi_rtc_cache_t` in `rtc_sys_info`), and eager caller-task PBKDF2-SHA1 derivation so the Wi-Fi worker task never stalls during key derivation.
  - `net80211_supp_glue.c` — full `wpa_supplicant` / `hostapd` integration (`esp_wifi_register_wpa_cb_internal`, live RSN/WPA IE attachment, WPA2-PSK CCMP/TKIP + WPA3-SAE + PMF/BIP key installation, and `defs.h` cipher bit-index mapping).
  - `net80211_scan.c` — active/passive multi-channel scanning, hidden-SSID directed Probe Requests, Beacon/Probe Response IE parsing (SSID, rates, DS channel, RSN/WPA, HT20), and transient RSSI-sorted scan result list.
  - `net80211_sta.c` — STA state machine (fast-connect channel hint with full-sweep fallback, Open/SAE Auth, Assoc/Reassoc, WPA2/WPA3 4-way handshake orchestration, beacon timeout watchdog, deauth/disassoc handling, and `SYSTEM_EVENT_STA_*` dispatch).
  - `net80211_ap.c` — SoftAP and concurrent `WIFI_MODE_APSTA` engine (mode-scoped peer slab allocated on AP start and completely freed on AP stop, Probe Response / Auth / Assoc handling, hostapd authenticator bridge, PS station buffering with TIM bitmap, and STA inactivity aging).
  - `net80211_data.c` — zero-copy `pbuf` <-> 802.11 LLC/SNAP data plane (`esp_wifi_internal_tx`, QoS/HT20 headers, RX 802.11 -> Ethernet decapsulation, EAPOL dispatch, and SoftAP intra-BSS forwarding).
  - `net80211_pm.c` — `WIFI_PS_NONE` / `WIFI_PS_MIN_MODEM` / `WIFI_PS_MAX_MODEM` power-save coordination (Null-Data PM signaling, DTIM/beacon wake scheduling, and activity timers).
  - `net80211_api.c` — complete public `esp_wifi_*` and `esp_wifi_internal_*` API surface (mode/config/scan/connect/disconnect/AP STA list/country/protocol/bandwidth/TX power/promiscuous/PS/internal netif hooks).

#### Replacement Implementation
- Enabled by default via `CONFIG_ESP8266_OSS_WIFI`, compiled with GCC 16.2 (`-fno-common`, `0` `SHN_COMMON` globals).
- Combined with `esp8266_lmac` and `esp8266_phy`, eliminates all proprietary Wi-Fi/MAC blobs from default builds (`CONFIG_ESP8266_VENDOR_BLOBS=n`), reducing application IRAM by `~13.1 KB` (`-50.2%`, or `~13.8 KB` with `CONFIG_ESP8266_OSS_WIFI_MIN_NMI=y`), static DRAM by `~3.06 KB` (`-25.8%`), and firmware binary size by `~86.0 KB` (`-14.8%`), while increasing runtime free heap by `~19.9 KB` (`+34.7%`).

#### Origin & License Compliance
- Authored as clean-room C under **`Apache-2.0`** against public SDK headers (`esp_wifi.h`, `esp_wifi_types.h`, `esp_private/wifi.h`, `esp_wifi_internal.h`, `esp_event_legacy.h`, `components/wpa_supplicant/src/esp_supplicant/`).
- Preserves upstream **`MIT`** license notices (`Copyright (c) 2025-2026 Jonathan Waters`, `teatime-os`) where 802.11 frame layout helpers were cross-referenced.

#### Test Strength & Robustness
- Compiled with `0` compiler warnings under GCC 16.2 (`-fno-common`) across default OSS (`CONFIG_ESP8266_VENDOR_BLOBS=n`), `CONFIG_ESP8266_OSS_WIFI_MIN_NMI=y`, full vendor (`CONFIG_ESP8266_VENDOR_BLOBS=y`), and mixed-component builds, with `0` vendor `.a` archive references in default linker maps and `0` `SHN_COMMON` symbols.
- Validated end-to-end on physical ESP8266 hardware across hidden-SSID WPA2-PSK CCMP STA association, DHCP + SNTP time sync, warm-reboot `RTC_SYS` fast-connect, active multi-channel Wi-Fi scanning while associated, SoftAP provisioning + `WIFI_MODE_APSTA` concurrent operation, `WIFI_PS_MIN_MODEM` idle sleep/wake soak, concurrent HTTP load, full WebDAV CRUD/COPY/MOVE verification, and dual-slot HTTP OTA firmware updates.

---

## 3. Consumer Kconfig Reference

All open-source and opt-in vendor blob toggles live in `components/esp8266/Kconfig` under the menu hierarchy below (`(*)` = default choice, `[ ]` = default `n`):

```text
Component config
└── ESP8266-specific
    └── Open-Source / Vendor Blob Selection
        ├── [ ] CONFIG_ESP8266_VENDOR_BLOBS                             (default: n)
        │       Master gate unlocking prebuilt archives in components/esp8266/lib/.
        │       When disabled (default), 0 vendor blobs are linked.
        │
        ├── (choice) HAL implementation
        │   ├── (*) CONFIG_ESP8266_OSS_HAL                              (default)
        │   │       Clean-room xtensa_hal.S (mixable with OSS or Vendor Core/Wi-Fi).
        │   └── ( ) CONFIG_ESP8266_VENDOR_HAL                           [depends on: VENDOR_BLOBS]
        │           Prebuilt libhal.a.
        │
        ├── (choice) Wi-Fi implementation
        │   ├── (*) CONFIG_ESP8266_OSS_WIFI                             (default)
        │   │       Open-source phy/ + lmac/ + net80211/ stack.
        │   │   └── [ ] CONFIG_ESP8266_OSS_WIFI_MIN_NMI                 (default: n) [depends on: OSS_WIFI]
        │   │           Minimal IRAM NMI handler; defers TX retries/launch to worker (-708 B IRAM).
        │   ├── ( ) CONFIG_ESP8266_VENDOR_WIFI                          [depends on: VENDOR_BLOBS]
        │   │       Prebuilt libphy.a + libpp.a + libnet80211.a.
        │   └── ( ) CONFIG_ESP8266_NO_WIFI
        │           Minimal non-Wi-Fi zero-blob build (esp_no_blobs_stubs.c).
        │
        ├── (choice) Core & RTC implementation
        │   ├── (*) CONFIG_ESP8266_OSS_CORE                             (default)
        │   │       Open-source source/esp_*.c (works with OSS_WIFI, VENDOR_WIFI, or NO_WIFI).
        │   └── ( ) CONFIG_ESP8266_VENDOR_CORE                          [depends on: VENDOR_BLOBS && VENDOR_WIFI]
        │           Prebuilt libcore.a + libclk.a + librtc.a.
        │
        ├── [ ] CONFIG_ESP8266_VENDOR_ESPNOW                            (default: n) [depends on: VENDOR_BLOBS && VENDOR_WIFI]
        │       Link prebuilt libespnow.a (_dbg). When off, links OSS esp_now_deinit() stub.
        │
        └── [ ] CONFIG_ESP8266_VENDOR_SMARTCONFIG                       (default: n) [depends on: VENDOR_BLOBS && VENDOR_WIFI]
                Compile smartconfig*.c and link prebuilt libsmartconfig.a.
```

---

## 4. License & Clean-Room Attribution Summary

| Component / Path | License | Upstream / Clean-Room Provenance |
| :--- | :--- | :--- |
| `components/esp8266/net80211/*.{c,h}` | `Apache-2.0` | Clean-room `ESP8266_RTOS_SDK` IEEE 802.11 STA/SoftAP/APSTA/PS/scan/data stack and `wpa_supplicant` / `esp_wifi_*` API layer authored against public SDK headers. |
| `components/esp8266/lmac/{lmac_regs.h, lmac_nmi.c, lmac_dma.c, lmac_tx.c, lmac_crypto_vif.c}` | `Apache-2.0` + `MIT` | Clean-room `ESP8266_RTOS_SDK` Lower MAC subsystem (`Apache-2.0`) incorporating WDEV register definitions and DMA/FIQ/CCMP hardware programming sequences adapted from `teatime-os` (`MIT`, Copyright (c) 2025-2026 Jonathan Waters). |
| `components/esp8266/lmac/{esp_lmac.h, lmac_internal.h, lmac_trc.c, lmac_pm_compat.c}` | `Apache-2.0` | Clean-room `ESP8266_RTOS_SDK` LMAC public API, rate control (TRC), and sleep/runtime compatibility layer. |
| `components/esp8266/phy/{phy_regs.h, phy_i2c_pbus.c, phy_clock.c, phy_rf_chan.c, phy_rxgain.c, phy_cal_tx.c, phy_sleep.c}` | `Apache-2.0` + `MIT` | Clean-room `ESP8266_RTOS_SDK` RF/PHY subsystem (`Apache-2.0`) incorporating hardware register definitions and RF/PBUS/PLL/calibration/gain/sleep sequences adapted from `teatime-os` (`MIT`, Copyright (c) 2025-2026 Jonathan Waters). |
| `components/esp8266/phy/{phy_internal.h, phy_adc.c, phy_core.c}` | `Apache-2.0` | Clean-room `ESP8266_RTOS_SDK` PHY ABI/header, SAR ADC, and NVS/init-parameter orchestration authored against public SDK headers and `g_phyFuns` / `phy_init_data.h` interfaces. |
| `components/esp8266/source/esp_clk_rtc.c` | `Apache-2.0` + `MIT` | Clean-room `ESP8266_RTOS_SDK` RTC/clock driver (`Apache-2.0`) with standalone `CONFIG_ESP8266_NO_WIFI` RTC analog reset and BBPLL init sequences adapted from `teatime-os` (`MIT`, Copyright (c) 2025-2026 Jonathan Waters). |
| `components/esp8266/source/{esp_ets_timer.c, esp_misc.c, esp_misc_nvs.c, esp_sys_ctrl.c, esp_no_blobs_stubs.c, esp_wifi.c}`, `tools/cmake/romstrip.cmake`, `tools/cmake/scripts/strip_rom_libgcc.py` | `Apache-2.0` | Clean-room `ESP8266_RTOS_SDK` implementations authored against public SDK register headers and Mask ROM symbol definitions (`esp8266.rom.ld`, `esp8266.bootloader.rom.ld`). |
| `components/esp8266/source/xtensa_hal.S` | `MIT` | Clean-room Call0 Xtensa LX106 HAL authored against MIT-licensed Tensilica / Cadence headers in `components/esp8266/include/xtensa/`. |
| `${CMAKE_BINARY_DIR}/rom_stripped_lib/libgcc_romstrip.a` | `GPL-3.0-with-GCC-Runtime-Library-Exception` | Active `xtensa-esp-elf` GCC 16.2 compiler runtime (`libgcc.a`) with Mask ROM duplicate `.o` members stripped at configure time. |
