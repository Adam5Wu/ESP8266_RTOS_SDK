// Copyright 2026 Adam5Wu (ESP8266_RTOS_SDK OSS contributors)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Kconfig-gated Wi-Fi NVS persistence, 64-byte RTC_SYS fast-connect PMK +
// channel cache across warm resets/OTA, and eager caller-task PBKDF2-SHA1.

#include <stdio.h>
#include <string.h>

#include "esp_crc.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_private/esp_system_internal.h"
#ifdef CONFIG_ESP8266_WIFI_NVS_ENABLED
#include "nvs.h"
#endif
#include "net80211_internal.h"

#define TAG "wifi_store"

/*
 * 64-byte (16 x uint32_t) RTC_SYS fast-connect cache layout:
 *   word  0      : Magic ('WFC1' = 0x57464331U)
 *   words 1..4   : Truncated SHA-256(ssid || 0x00 || password) (16 bytes)
 *   words 5..12  : Derived WPA/WPA2 PMK (32 bytes)
 *   word  13     : BSSID bytes [0..3] (little-endian)
 *   word  14     : BSSID[4..5] in bits [15:0], channel in [23:16], authmode in [31:24]
 *   word  15     : CRC32-LE over words 0..14 (60 bytes)
 */
#define N8_RTC_MAGIC                    0x57464331U /* 'WFC1' */
#define N8_RTC_CACHE_WORDS              16U         /* Total 32-bit words (64 bytes) */
#define N8_RTC_CRC_WORDS                15U         /* Words covered by trailing CRC32 */
#define N8_RTC_WORD_MAGIC               0U
#define N8_RTC_WORD_HASH                1U
#define N8_RTC_HASH_WORDS               4U
#define N8_RTC_HASH_LEN                 16U         /* 4 x uint32_t truncated SHA-256 */
#define N8_RTC_WORD_PMK                 5U
#define N8_RTC_WORD_BSSID_LO            13U
#define N8_RTC_WORD_BSSID_HI_META       14U
#define N8_RTC_WORD_CRC                 15U

/* WPA/WPA2 passphrase & PBKDF2-SHA1 constants (IEEE 802.11-2016 §J.4) */
#define N8_SHA256_DIGEST_LEN            32U
#define N8_PSK_HEX_LEN                  (N8_PMK_LEN * 2U) /* 64 ASCII hex chars = raw 32B PMK */
#define N8_WPA_PASS_MIN_LEN             8U
#define N8_WPA_PASS_MAX_LEN             63U
#define N8_PBKDF2_ITERATIONS            4096

/* Default Wi-Fi runtime & NVS fallback parameters */
#define N8_DEFAULT_COUNTRY_NCHAN        13U         /* Default CN regulatory channel count (1..13) */
#define N8_DEFAULT_COUNTRY_MAX_DBM      20          /* Default country max TX power (dBm) */
#define N8_CHANNEL_UPPER_BOUND          (N8_CHANNEL_MAX + 1U) /* Exclusive upper channel (15) */
#define N8_TX_POWER_QDBM_PER_DBM        4           /* Quarter-dBm units per 1 dBm */
#define N8_DEFAULT_STA_INACTIVE_SEC     6U          /* STA beacon-loss inactivity timeout (s) */
#define N8_DEFAULT_AP_INACTIVE_SEC      300U        /* SoftAP client inactivity timeout (s) */
#define N8_DEFAULT_RSSI_THRESHOLD       (-127)      /* Disabled RSSI warning threshold (dBm) */
#define N8_DEFAULT_AP_MAX_CONN          4U          /* Default SoftAP max associated stations */
#define N8_DEFAULT_AP_BCN_INT_TU        100U        /* Default & minimum SoftAP beacon interval (TU) */

/* NVS namespace and key names (ESP8266_RTOS_SDK compatible) */
#define N8_NVS_NAMESPACE                "nvs.net80211"
#define N8_NVS_KEY_OPMODE               "opmode"
#define N8_NVS_KEY_STA_CFG              "sta.cfg"
#define N8_NVS_KEY_AP_CFG               "ap.cfg"
#define N8_NVS_KEY_STA_PMK              "sta.pmk"
#define N8_NVS_KEY_COUNTRY              "country"

/* Crypto primitives from wpa_supplicant */
extern int pbkdf2_sha1(const char *passphrase, const char *ssid, size_t ssid_len,
                       int iterations, u8 *buf, size_t buflen);
extern int sha256_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac);

/**
 * @brief Convert a single ASCII hexadecimal character to its 4-bit value.
 *
 * @param c ASCII character to decode.
 * @return Value in [0, 15] on success, or -1 if @p c is not a valid hex digit.
 */
static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/**
 * @brief Parse a 64-character hex-encoded raw PMK string into 32 binary bytes.
 *
 * @param pass    NUL-terminated password string from Wi-Fi config.
 * @param out_pmk Output buffer receiving the 32-byte decoded PMK on success.
 * @return True if @p pass is exactly 64 valid hex characters, false otherwise.
 */
static bool parse_hex_pmk(const uint8_t *pass, uint8_t out_pmk[N8_PMK_LEN])
{
    if (strlen((const char *)pass) != N8_PSK_HEX_LEN) {
        return false;
    }
    for (size_t i = 0U; i < N8_PMK_LEN; i++) {
        int hi = hex_nibble((char)pass[i * 2U]);
        int lo = hex_nibble((char)pass[i * 2U + 1U]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out_pmk[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/* --------------------------------------------------------------------------
 * 64-Byte RTC_SYS Fast-Connect Cache (32-Bit Aligned Word Accesses Only)
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_ESP8266_OSS_WIFI_RTC_FAST_CONNECT

/**
 * @brief Compute the 128-bit credential fingerprint for RTC fast-connect lookup.
 *
 * Hashes @c ssid || 0x00 || pass with SHA-256 and truncates the digest to
 * 16 bytes (4 x uint32_t) so the NUL separator prevents ambiguity between
 * adjacent SSID/password splits.
 *
 * @param ssid     Network SSID bytes.
 * @param ssid_len Length of @p ssid in bytes.
 * @param pass     NUL-terminated passphrase string.
 * @param out_hash Output array receiving the 4-word truncated SHA-256 digest.
 */
static void compute_cred_hash(const uint8_t *ssid, size_t ssid_len,
                              const uint8_t *pass, uint32_t out_hash[N8_RTC_HASH_WORDS])
{
    uint8_t sep = 0x00U;
    size_t pass_len = strlen((const char *)pass);
    const u8 *vecs[3] = { ssid, &sep, pass };
    size_t lens[3] = { ssid_len, 1U, pass_len };
    uint8_t digest[N8_SHA256_DIGEST_LEN];

    memset(digest, 0, sizeof(digest));
    (void)sha256_vector(3U, vecs, lens, digest);
    memcpy(out_hash, digest, N8_RTC_HASH_LEN);
}

/**
 * @brief Read and validate the 64-byte fast-connect cache from RTC_SYS memory.
 *
 * Performs strictly 32-bit aligned word reads (required by the ESP8266 RTC
 * memory bus), then verifies the N8_RTC_MAGIC header and trailing CRC32-LE.
 *
 * @param words Output buffer receiving all 16 raw RTC cache words.
 * @return True if magic and CRC32 match, false if empty or corrupt.
 */
static bool rtc_cache_read_raw(uint32_t words[N8_RTC_CACHE_WORDS])
{
    volatile const uint32_t *src = (volatile const uint32_t *)&rtc_sys_info.wifi_fast_connect;
    for (size_t i = 0U; i < N8_RTC_CACHE_WORDS; i++) {
        words[i] = src[i];
    }
    if (words[N8_RTC_WORD_MAGIC] != N8_RTC_MAGIC) {
        return false;
    }
    uint32_t calc = crc32_le(0U, (const uint8_t *)words, N8_RTC_CRC_WORDS * sizeof(uint32_t));
    return (calc == words[N8_RTC_WORD_CRC]);
}

/**
 * @brief Write all 16 words of the fast-connect cache into RTC_SYS memory.
 *
 * Uses strictly 32-bit aligned volatile stores for ESP8266 RTC bus safety.
 *
 * @param words Input array of 16 words formatted per the WFC1 RTC cache layout.
 */
static void rtc_cache_write_raw(const uint32_t words[N8_RTC_CACHE_WORDS])
{
    volatile uint32_t *dst = (volatile uint32_t *)&rtc_sys_info.wifi_fast_connect;
    for (size_t i = 0U; i < N8_RTC_CACHE_WORDS; i++) {
        dst[i] = words[i];
    }
}

/**
 * @brief Zero the RTC_SYS fast-connect cache and clear in-RAM cached hint state.
 *
 * Called on cold boot, factory restore, or credential invalidation.
 */
void n8_rtc_cache_clear(void)
{
    uint32_t zeros[N8_RTC_CACHE_WORDS];
    memset(zeros, 0, sizeof(zeros));
    rtc_cache_write_raw(zeros);
    g_n8.rtc_cache_valid = 0U;
    g_n8.rtc_cached_ch = 0U;
    memset(g_n8.rtc_cached_bssid, 0, IEEE80211_ADDR_LEN);
}

/**
 * @brief Load cached AP BSSID and channel hint from RTC_SYS on warm reboot.
 *
 * Called during Wi-Fi init. On cold resets (ESP_RST_POWERON or ESP_RST_EXT),
 * RTC SRAM contents are undefined so the cache is scrubbed immediately.
 */
void n8_rtc_cache_load(void)
{
    esp_reset_reason_t reason = esp_reset_reason();
    if (reason == ESP_RST_POWERON || reason == ESP_RST_EXT) {
        n8_rtc_cache_clear();
        return;
    }

    uint32_t words[N8_RTC_CACHE_WORDS];
    if (!rtc_cache_read_raw(words)) {
        g_n8.rtc_cache_valid = 0U;
        return;
    }

    g_n8.rtc_cached_bssid[0] = (uint8_t)(words[N8_RTC_WORD_BSSID_LO] & 0xFFU);
    g_n8.rtc_cached_bssid[1] = (uint8_t)((words[N8_RTC_WORD_BSSID_LO] >> 8) & 0xFFU);
    g_n8.rtc_cached_bssid[2] = (uint8_t)((words[N8_RTC_WORD_BSSID_LO] >> 16) & 0xFFU);
    g_n8.rtc_cached_bssid[3] = (uint8_t)((words[N8_RTC_WORD_BSSID_LO] >> 24) & 0xFFU);
    g_n8.rtc_cached_bssid[4] = (uint8_t)(words[N8_RTC_WORD_BSSID_HI_META] & 0xFFU);
    g_n8.rtc_cached_bssid[5] = (uint8_t)((words[N8_RTC_WORD_BSSID_HI_META] >> 8) & 0xFFU);
    g_n8.rtc_cached_ch = (uint8_t)((words[N8_RTC_WORD_BSSID_HI_META] >> 16) & 0xFFU);
    if (g_n8.rtc_cached_ch > N8_CHANNEL_MAX) {
        g_n8.rtc_cached_ch = 0U;
    }
    g_n8.rtc_cache_valid = 1U;
}

/**
 * @brief Persist the connected AP's channel, BSSID, authmode, and PMK to RTC_SYS.
 *
 * Called from the Wi-Fi worker task once STA reaches N8_STA_RUN so subsequent
 * warm resets/OTA reboots can skip PBKDF2-SHA1 and probe the cached channel first.
 *
 * @param channel  Associated 2.4 GHz primary channel (1..14).
 * @param bssid    6-byte MAC address of the associated AP.
 * @param authmode Negotiated authentication mode (wifi_auth_mode_t).
 */
void n8_rtc_cache_save(uint8_t channel, const uint8_t bssid[IEEE80211_ADDR_LEN], uint8_t authmode)
{
    size_t ssid_len = strnlen((const char *)g_n8.sta_cfg.sta.ssid, N8_MAX_SSID_LEN);
    if (ssid_len == 0U || channel == 0U || channel > N8_CHANNEL_MAX || bssid == NULL) {
        return;
    }

    uint32_t words[N8_RTC_CACHE_WORDS];
    memset(words, 0, sizeof(words));
    words[N8_RTC_WORD_MAGIC] = N8_RTC_MAGIC;
    compute_cred_hash(g_n8.sta_cfg.sta.ssid, ssid_len, g_n8.sta_cfg.sta.password, &words[N8_RTC_WORD_HASH]);
    memcpy(&words[N8_RTC_WORD_PMK], g_n8.sta_pmk, N8_PMK_LEN);
    words[N8_RTC_WORD_BSSID_LO] = (uint32_t)bssid[0] | ((uint32_t)bssid[1] << 8) |
                                  ((uint32_t)bssid[2] << 16) | ((uint32_t)bssid[3] << 24);
    words[N8_RTC_WORD_BSSID_HI_META] = (uint32_t)bssid[4] | ((uint32_t)bssid[5] << 8) |
                                       ((uint32_t)channel << 16) | ((uint32_t)authmode << 24);
    words[N8_RTC_WORD_CRC] = crc32_le(0U, (const uint8_t *)words, N8_RTC_CRC_WORDS * sizeof(uint32_t));

    rtc_cache_write_raw(words);
    memcpy(g_n8.rtc_cached_bssid, bssid, IEEE80211_ADDR_LEN);
    g_n8.rtc_cached_ch = channel;
    g_n8.rtc_cache_valid = 1U;
}

#else /* !CONFIG_ESP8266_OSS_WIFI_RTC_FAST_CONNECT */

/**
 * @brief Clear in-RAM RTC cache hint fields when RTC fast-connect is disabled.
 */
void n8_rtc_cache_clear(void)
{
    g_n8.rtc_cache_valid = 0U;
    g_n8.rtc_cached_ch = 0U;
}

/**
 * @brief Reset in-RAM RTC cache hint fields when RTC fast-connect is disabled.
 */
void n8_rtc_cache_load(void)
{
    g_n8.rtc_cache_valid = 0U;
    g_n8.rtc_cached_ch = 0U;
}

/**
 * @brief No-op stub when RTC fast-connect is disabled at build time.
 *
 * @param channel  Unused AP channel.
 * @param bssid    Unused AP BSSID.
 * @param authmode Unused authentication mode.
 */
void n8_rtc_cache_save(uint8_t channel, const uint8_t bssid[IEEE80211_ADDR_LEN], uint8_t authmode)
{
    (void)channel;
    (void)bssid;
    (void)authmode;
}

#endif /* CONFIG_ESP8266_OSS_WIFI_RTC_FAST_CONNECT */

/* --------------------------------------------------------------------------
 * Eager Caller-Task PMK Derivation (Never Blocks Wi-Fi Worker Task)
 * -------------------------------------------------------------------------- */

/**
 * @brief Derive or retrieve the 32-byte WPA/WPA2 PMK in caller-task context.
 *
 * Invoked from the caller task (e.g. esp_wifi_set_config()) *before* posting an
 * RPC to the Wi-Fi worker task so the CPU-heavy 4096-iteration PBKDF2-SHA1
 * computation never stalls LMAC RX/TX or beacon processing. Resolution order:
 *   1. Raw 64-hex-char PMK decoded directly.
 *   2. Valid RTC_SYS fast-connect entry matching SHA-256(ssid || 0x00 || pass)
 *      (when `CONFIG_ESP8266_OSS_WIFI_RTC_FAST_CONNECT` is enabled), which also
 *      refreshes @c g_n8.rtc_cached_bssid and @c g_n8.rtc_cached_ch.
 *   3. Standard PBKDF2-SHA1(pass, ssid, 4096) for 8..63-byte ASCII passphrases.
 *
 * @param ssid          Network SSID bytes.
 * @param ssid_len      Length of @p ssid in bytes.
 * @param pass          NUL-terminated passphrase or 64-char hex PMK string.
 * @param out_pmk       Output buffer receiving the 32-byte PMK (zeroed on empty/open).
 * @param hit_rtc_cache Optional output flag set true on an RTC cache hit, false otherwise.
 */
void n8_derive_pmk_eager(const uint8_t *ssid, size_t ssid_len, const uint8_t *pass,
                         uint8_t out_pmk[N8_PMK_LEN], bool *hit_rtc_cache)
{
    if (hit_rtc_cache != NULL) {
        *hit_rtc_cache = false;
    }
    memset(out_pmk, 0, N8_PMK_LEN);

    size_t pass_len = strnlen((const char *)pass, N8_PSK_HEX_LEN);
    if (ssid_len == 0U || pass_len == 0U) {
        return;
    }

    if (parse_hex_pmk(pass, out_pmk)) {
        return;
    }

#ifdef CONFIG_ESP8266_OSS_WIFI_RTC_FAST_CONNECT
    uint32_t words[N8_RTC_CACHE_WORDS];
    if (rtc_cache_read_raw(words)) {
        uint32_t hash[N8_RTC_HASH_WORDS];
        compute_cred_hash(ssid, ssid_len, pass, hash);
        if (memcmp(hash, &words[N8_RTC_WORD_HASH], N8_RTC_HASH_LEN) == 0) {
            memcpy(out_pmk, &words[N8_RTC_WORD_PMK], N8_PMK_LEN);
            g_n8.rtc_cached_bssid[0] = (uint8_t)(words[N8_RTC_WORD_BSSID_LO] & 0xFFU);
            g_n8.rtc_cached_bssid[1] = (uint8_t)((words[N8_RTC_WORD_BSSID_LO] >> 8) & 0xFFU);
            g_n8.rtc_cached_bssid[2] = (uint8_t)((words[N8_RTC_WORD_BSSID_LO] >> 16) & 0xFFU);
            g_n8.rtc_cached_bssid[3] = (uint8_t)((words[N8_RTC_WORD_BSSID_LO] >> 24) & 0xFFU);
            g_n8.rtc_cached_bssid[4] = (uint8_t)(words[N8_RTC_WORD_BSSID_HI_META] & 0xFFU);
            g_n8.rtc_cached_bssid[5] = (uint8_t)((words[N8_RTC_WORD_BSSID_HI_META] >> 8) & 0xFFU);
            g_n8.rtc_cached_ch = (uint8_t)((words[N8_RTC_WORD_BSSID_HI_META] >> 16) & 0xFFU);
            g_n8.rtc_cache_valid = 1U;
            if (hit_rtc_cache != NULL) {
                *hit_rtc_cache = true;
            }
            ESP_LOGD(TAG, "RTC fast-connect PMK cache hit (ch=%u)", (unsigned)g_n8.rtc_cached_ch);
            return;
        }
    }
#endif /* CONFIG_ESP8266_OSS_WIFI_RTC_FAST_CONNECT */

    if (pass_len >= N8_WPA_PASS_MIN_LEN && pass_len <= N8_WPA_PASS_MAX_LEN) {
        (void)pbkdf2_sha1((const char *)pass, (const char *)ssid, ssid_len,
                          N8_PBKDF2_ITERATIONS, out_pmk, N8_PMK_LEN);
    }
}

/* --------------------------------------------------------------------------
 * Defaults & Kconfig-Gated NVS Persistence (nvs.net80211)
 * -------------------------------------------------------------------------- */

/**
 * @brief Populate @c g_n8 with factory-default Wi-Fi mode, country, STA, and SoftAP settings.
 *
 * Called during esp_wifi_init() (before optional NVS load) and esp_wifi_restore().
 */
void n8_nvs_init_defaults(void)
{
    g_n8.mode = WIFI_MODE_STA;
#ifdef CONFIG_ESP8266_WIFI_NVS_ENABLED
    g_n8.storage = WIFI_STORAGE_FLASH;
#else
    g_n8.storage = WIFI_STORAGE_RAM;
#endif
    g_n8.ps_type = WIFI_PS_NONE;
    memcpy(g_n8.country.cc, "CN\0", 3U);
    g_n8.country.schan = N8_CHANNEL_MIN;
    g_n8.country.nchan = N8_DEFAULT_COUNTRY_NCHAN;
    g_n8.country.max_tx_power = N8_DEFAULT_COUNTRY_MAX_DBM;
    g_n8.country.policy = WIFI_COUNTRY_POLICY_AUTO;

    /* Index 0 = STA interface, index 1 = SoftAP interface */
    g_n8.proto[0] = WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N;
    g_n8.proto[1] = WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N;
    g_n8.bandwidth[0] = WIFI_BW_HT20;
    g_n8.bandwidth[1] = WIFI_BW_HT20;
    g_n8.cur_channel = N8_CHANNEL_MIN;
    g_n8.auto_connect = 1U;
    g_n8.max_tx_power = (int8_t)(CONFIG_ESP8266_PHY_MAX_WIFI_TX_POWER * N8_TX_POWER_QDBM_PER_DBM);
    g_n8.inactive_sec[0] = N8_DEFAULT_STA_INACTIVE_SEC;
    g_n8.inactive_sec[1] = N8_DEFAULT_AP_INACTIVE_SEC;
    g_n8.rssi_threshold = N8_DEFAULT_RSSI_THRESHOLD;

    memset(&g_n8.sta_cfg, 0, sizeof(g_n8.sta_cfg));
    g_n8.sta_cfg.sta.pmf_cfg.capable = true;
    g_n8.sta_cfg.sta.pmf_cfg.required = false;

    memset(&g_n8.ap_cfg, 0, sizeof(g_n8.ap_cfg));
    snprintf((char *)g_n8.ap_cfg.ap.ssid, sizeof(g_n8.ap_cfg.ap.ssid),
             "ESP_%02X%02X%02X", g_n8.ap_mac[3], g_n8.ap_mac[4], g_n8.ap_mac[5]);
    g_n8.ap_cfg.ap.ssid_len = (uint8_t)strlen((const char *)g_n8.ap_cfg.ap.ssid);
    g_n8.ap_cfg.ap.channel = N8_CHANNEL_MIN;
    g_n8.ap_cfg.ap.authmode = WIFI_AUTH_OPEN;
    g_n8.ap_cfg.ap.max_connection = N8_DEFAULT_AP_MAX_CONN;
    g_n8.ap_cfg.ap.beacon_interval = N8_DEFAULT_AP_BCN_INT_TU;
}

#ifdef CONFIG_ESP8266_WIFI_NVS_ENABLED

/**
 * @brief Check whether NVS flash persistence is enabled in both init config and storage mode.
 *
 * @return True if flash-backed NVS reads/writes should proceed, false otherwise.
 */
static bool nvs_use_flash(void)
{
    return (g_n8.init_cfg.nvs_enable != 0) && (g_n8.storage == WIFI_STORAGE_FLASH);
}

/**
 * @brief Load persisted Wi-Fi configuration blobs from the @c nvs.net80211 namespace.
 *
 * Called during esp_wifi_init() after n8_nvs_init_defaults(). Sanitizes loaded
 * SoftAP max_connection, beacon_interval, and regulatory country channel bounds
 * against out-of-range flash data.
 */
void n8_nvs_load(void)
{
    if (!nvs_use_flash()) {
        return;
    }

    nvs_handle_t h;
    if (nvs_open(N8_NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
        return;
    }

    uint8_t u8v = 0U;
    if (nvs_get_u8(h, N8_NVS_KEY_OPMODE, &u8v) == ESP_OK && u8v < WIFI_MODE_MAX) {
        g_n8.mode = (wifi_mode_t)u8v;
    }

    size_t sz = sizeof(g_n8.sta_cfg.sta);
    (void)nvs_get_blob(h, N8_NVS_KEY_STA_CFG, &g_n8.sta_cfg.sta, &sz);

    sz = sizeof(g_n8.ap_cfg.ap);
    (void)nvs_get_blob(h, N8_NVS_KEY_AP_CFG, &g_n8.ap_cfg.ap, &sz);
    if (g_n8.ap_cfg.ap.max_connection == 0U || g_n8.ap_cfg.ap.max_connection > ESP_WIFI_MAX_CONN_NUM) {
        g_n8.ap_cfg.ap.max_connection = N8_DEFAULT_AP_MAX_CONN;
    }
    if (g_n8.ap_cfg.ap.beacon_interval < N8_DEFAULT_AP_BCN_INT_TU) {
        g_n8.ap_cfg.ap.beacon_interval = N8_DEFAULT_AP_BCN_INT_TU;
    }

    sz = sizeof(g_n8.sta_pmk);
    if (nvs_get_blob(h, N8_NVS_KEY_STA_PMK, g_n8.sta_pmk, &sz) == ESP_OK && sz == N8_PMK_LEN) {
        g_n8.sta_reset_param = 0U;
    } else {
        g_n8.sta_reset_param = 1U;
    }

    sz = sizeof(g_n8.country);
    (void)nvs_get_blob(h, N8_NVS_KEY_COUNTRY, &g_n8.country, &sz);
    if (g_n8.country.schan == 0U || g_n8.country.nchan == 0U ||
        g_n8.country.schan + g_n8.country.nchan > N8_CHANNEL_UPPER_BOUND) {
        g_n8.country.schan = N8_CHANNEL_MIN;
        g_n8.country.nchan = N8_DEFAULT_COUNTRY_NCHAN;
    }

    nvs_close(h);
}

/**
 * @brief Persist the current Wi-Fi operating mode (@c g_n8.mode) to NVS flash.
 */
void n8_nvs_save_mode(void)
{
    if (!nvs_use_flash()) {
        return;
    }
    nvs_handle_t h;
    if (nvs_open(N8_NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        (void)nvs_set_u8(h, N8_NVS_KEY_OPMODE, (uint8_t)g_n8.mode);
        (void)nvs_commit(h);
        nvs_close(h);
    }
}

/**
 * @brief Persist the current STA configuration and derived PMK to NVS flash.
 */
void n8_nvs_save_sta_cfg(void)
{
    if (!nvs_use_flash()) {
        return;
    }
    nvs_handle_t h;
    if (nvs_open(N8_NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        (void)nvs_set_blob(h, N8_NVS_KEY_STA_CFG, &g_n8.sta_cfg.sta, sizeof(g_n8.sta_cfg.sta));
        (void)nvs_set_blob(h, N8_NVS_KEY_STA_PMK, g_n8.sta_pmk, sizeof(g_n8.sta_pmk));
        (void)nvs_commit(h);
        nvs_close(h);
    }
}

/**
 * @brief Persist the current SoftAP configuration to NVS flash.
 */
void n8_nvs_save_ap_cfg(void)
{
    if (!nvs_use_flash()) {
        return;
    }
    nvs_handle_t h;
    if (nvs_open(N8_NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        (void)nvs_set_blob(h, N8_NVS_KEY_AP_CFG, &g_n8.ap_cfg.ap, sizeof(g_n8.ap_cfg.ap));
        (void)nvs_commit(h);
        nvs_close(h);
    }
}

/**
 * @brief Persist the active regulatory country configuration to NVS flash.
 */
void n8_nvs_save_country(void)
{
    if (!nvs_use_flash()) {
        return;
    }
    nvs_handle_t h;
    if (nvs_open(N8_NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        (void)nvs_set_blob(h, N8_NVS_KEY_COUNTRY, &g_n8.country, sizeof(g_n8.country));
        (void)nvs_commit(h);
        nvs_close(h);
    }
}

/**
 * @brief Erase all persisted Wi-Fi NVS entries, clear RTC cache, and restore defaults.
 *
 * Called from esp_wifi_restore() (worker-task / API RPC context).
 */
void n8_nvs_restore(void)
{
    n8_rtc_cache_clear();
    if (g_n8.init_cfg.nvs_enable != 0) {
        nvs_handle_t h;
        if (nvs_open(N8_NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
            (void)nvs_erase_all(h);
            (void)nvs_commit(h);
            nvs_close(h);
        }
    }
    n8_nvs_init_defaults();
}

#else /* !CONFIG_ESP8266_WIFI_NVS_ENABLED */

/** @brief No-op NVS load stub when CONFIG_ESP8266_WIFI_NVS_ENABLED is disabled. */
void n8_nvs_load(void)         {}
/** @brief No-op NVS mode-save stub when CONFIG_ESP8266_WIFI_NVS_ENABLED is disabled. */
void n8_nvs_save_mode(void)    {}
/** @brief No-op NVS STA-config save stub when CONFIG_ESP8266_WIFI_NVS_ENABLED is disabled. */
void n8_nvs_save_sta_cfg(void) {}
/** @brief No-op NVS AP-config save stub when CONFIG_ESP8266_WIFI_NVS_ENABLED is disabled. */
void n8_nvs_save_ap_cfg(void)  {}
/** @brief No-op NVS country-save stub when CONFIG_ESP8266_WIFI_NVS_ENABLED is disabled. */
void n8_nvs_save_country(void) {}

/**
 * @brief Clear RTC cache and reset Wi-Fi configuration to factory defaults (NVS disabled).
 */
void n8_nvs_restore(void)
{
    n8_rtc_cache_clear();
    n8_nvs_init_defaults();
}

#endif /* CONFIG_ESP8266_WIFI_NVS_ENABLED */
