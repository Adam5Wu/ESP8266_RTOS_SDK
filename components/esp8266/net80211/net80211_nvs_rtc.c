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

#define N8_RTC_MAGIC    0x57464331U /* 'WFC1' */

/* Crypto primitives from wpa_supplicant */
extern int pbkdf2_sha1(const char *passphrase, const char *ssid, size_t ssid_len,
                       int iterations, u8 *buf, size_t buflen);
extern int sha256_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac);

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool parse_hex_pmk(const uint8_t *pass, uint8_t out_pmk[32])
{
    if (strlen((const char *)pass) != 64U) {
        return false;
    }
    for (size_t i = 0U; i < 32U; i++) {
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

static void compute_cred_hash(const uint8_t *ssid, size_t ssid_len,
                              const uint8_t *pass, uint32_t out_hash[4])
{
    uint8_t sep = 0x00U;
    size_t pass_len = strlen((const char *)pass);
    const u8 *vecs[3] = { ssid, &sep, pass };
    size_t lens[3] = { ssid_len, 1U, pass_len };
    uint8_t digest[32];

    memset(digest, 0, sizeof(digest));
    (void)sha256_vector(3U, vecs, lens, digest);
    memcpy(out_hash, digest, 16U);
}

#ifdef CONFIG_ESP8266_WIFI_RTC_FAST_CONNECT

static bool rtc_cache_read_raw(uint32_t words[16])
{
    volatile const uint32_t *src = (volatile const uint32_t *)&rtc_sys_info.wifi_fast_connect;
    for (size_t i = 0U; i < 16U; i++) {
        words[i] = src[i];
    }
    if (words[0] != N8_RTC_MAGIC) {
        return false;
    }
    uint32_t calc = crc32_le(0U, (const uint8_t *)words, 15U * sizeof(uint32_t));
    return (calc == words[15]);
}

static void rtc_cache_write_raw(const uint32_t words[16])
{
    volatile uint32_t *dst = (volatile uint32_t *)&rtc_sys_info.wifi_fast_connect;
    for (size_t i = 0U; i < 16U; i++) {
        dst[i] = words[i];
    }
}

void n8_rtc_cache_clear(void)
{
    uint32_t zeros[16];
    memset(zeros, 0, sizeof(zeros));
    rtc_cache_write_raw(zeros);
    g_n8.rtc_cache_valid = 0U;
    g_n8.rtc_cached_ch = 0U;
    memset(g_n8.rtc_cached_bssid, 0, 6U);
}

void n8_rtc_cache_load(void)
{
    esp_reset_reason_t reason = esp_reset_reason();
    if (reason == ESP_RST_POWERON || reason == ESP_RST_EXT) {
        n8_rtc_cache_clear();
        return;
    }

    uint32_t words[16];
    if (!rtc_cache_read_raw(words)) {
        g_n8.rtc_cache_valid = 0U;
        return;
    }

    g_n8.rtc_cached_bssid[0] = (uint8_t)(words[13] & 0xFFU);
    g_n8.rtc_cached_bssid[1] = (uint8_t)((words[13] >> 8) & 0xFFU);
    g_n8.rtc_cached_bssid[2] = (uint8_t)((words[13] >> 16) & 0xFFU);
    g_n8.rtc_cached_bssid[3] = (uint8_t)((words[13] >> 24) & 0xFFU);
    g_n8.rtc_cached_bssid[4] = (uint8_t)(words[14] & 0xFFU);
    g_n8.rtc_cached_bssid[5] = (uint8_t)((words[14] >> 8) & 0xFFU);
    g_n8.rtc_cached_ch = (uint8_t)((words[14] >> 16) & 0xFFU);
    if (g_n8.rtc_cached_ch > 14U) {
        g_n8.rtc_cached_ch = 0U;
    }
    g_n8.rtc_cache_valid = 1U;
}

void n8_rtc_cache_save(uint8_t channel, const uint8_t bssid[6], uint8_t authmode)
{
    size_t ssid_len = strnlen((const char *)g_n8.sta_cfg.sta.ssid, 32U);
    if (ssid_len == 0U || channel == 0U || channel > 14U || bssid == NULL) {
        return;
    }

    uint32_t words[16];
    memset(words, 0, sizeof(words));
    words[0] = N8_RTC_MAGIC;
    compute_cred_hash(g_n8.sta_cfg.sta.ssid, ssid_len, g_n8.sta_cfg.sta.password, &words[1]);
    memcpy(&words[5], g_n8.sta_pmk, 32U);
    words[13] = (uint32_t)bssid[0] | ((uint32_t)bssid[1] << 8) |
                ((uint32_t)bssid[2] << 16) | ((uint32_t)bssid[3] << 24);
    words[14] = (uint32_t)bssid[4] | ((uint32_t)bssid[5] << 8) |
                ((uint32_t)channel << 16) | ((uint32_t)authmode << 24);
    words[15] = crc32_le(0U, (const uint8_t *)words, 15U * sizeof(uint32_t));

    rtc_cache_write_raw(words);
    memcpy(g_n8.rtc_cached_bssid, bssid, 6U);
    g_n8.rtc_cached_ch = channel;
    g_n8.rtc_cache_valid = 1U;
}

#else /* !CONFIG_ESP8266_WIFI_RTC_FAST_CONNECT */

void n8_rtc_cache_clear(void)
{
    g_n8.rtc_cache_valid = 0U;
    g_n8.rtc_cached_ch = 0U;
}

void n8_rtc_cache_load(void)
{
    g_n8.rtc_cache_valid = 0U;
    g_n8.rtc_cached_ch = 0U;
}

void n8_rtc_cache_save(uint8_t channel, const uint8_t bssid[6], uint8_t authmode)
{
    (void)channel;
    (void)bssid;
    (void)authmode;
}

#endif /* CONFIG_ESP8266_WIFI_RTC_FAST_CONNECT */

/* --------------------------------------------------------------------------
 * Eager Caller-Task PMK Derivation (Never Blocks Wi-Fi Worker Task)
 * -------------------------------------------------------------------------- */

void n8_derive_pmk_eager(const uint8_t *ssid, size_t ssid_len, const uint8_t *pass,
                         uint8_t out_pmk[32], bool *hit_rtc_cache)
{
    if (hit_rtc_cache != NULL) {
        *hit_rtc_cache = false;
    }
    memset(out_pmk, 0, 32U);

    size_t pass_len = strnlen((const char *)pass, 64U);
    if (ssid_len == 0U || pass_len == 0U) {
        return;
    }

    if (parse_hex_pmk(pass, out_pmk)) {
        return;
    }

#ifdef CONFIG_ESP8266_WIFI_RTC_FAST_CONNECT
    uint32_t words[16];
    if (rtc_cache_read_raw(words)) {
        uint32_t hash[4];
        compute_cred_hash(ssid, ssid_len, pass, hash);
        if (memcmp(hash, &words[1], 16U) == 0) {
            memcpy(out_pmk, &words[5], 32U);
            g_n8.rtc_cached_bssid[0] = (uint8_t)(words[13] & 0xFFU);
            g_n8.rtc_cached_bssid[1] = (uint8_t)((words[13] >> 8) & 0xFFU);
            g_n8.rtc_cached_bssid[2] = (uint8_t)((words[13] >> 16) & 0xFFU);
            g_n8.rtc_cached_bssid[3] = (uint8_t)((words[13] >> 24) & 0xFFU);
            g_n8.rtc_cached_bssid[4] = (uint8_t)(words[14] & 0xFFU);
            g_n8.rtc_cached_bssid[5] = (uint8_t)((words[14] >> 8) & 0xFFU);
            g_n8.rtc_cached_ch = (uint8_t)((words[14] >> 16) & 0xFFU);
            g_n8.rtc_cache_valid = 1U;
            if (hit_rtc_cache != NULL) {
                *hit_rtc_cache = true;
            }
            ESP_LOGD(TAG, "RTC fast-connect PMK cache hit (ch=%u)", (unsigned)g_n8.rtc_cached_ch);
            return;
        }
    }
#endif

    if (pass_len >= 8U && pass_len <= 63U) {
        (void)pbkdf2_sha1((const char *)pass, (const char *)ssid, ssid_len, 4096, out_pmk, 32U);
    }
}

/* --------------------------------------------------------------------------
 * Defaults & Kconfig-Gated NVS Persistence (nvs.net80211)
 * -------------------------------------------------------------------------- */

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
    g_n8.country.schan = 1U;
    g_n8.country.nchan = 13U;
    g_n8.country.max_tx_power = 20;
    g_n8.country.policy = WIFI_COUNTRY_POLICY_AUTO;

    g_n8.proto[0] = WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N;
    g_n8.proto[1] = WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N;
    g_n8.bandwidth[0] = WIFI_BW_HT20;
    g_n8.bandwidth[1] = WIFI_BW_HT20;
    g_n8.cur_channel = 1U;
    g_n8.auto_connect = 1U;
    g_n8.max_tx_power = (int8_t)(CONFIG_ESP8266_PHY_MAX_WIFI_TX_POWER * 4);
    g_n8.inactive_sec[0] = 6U;
    g_n8.inactive_sec[1] = 300U;
    g_n8.rssi_threshold = -127;

    memset(&g_n8.sta_cfg, 0, sizeof(g_n8.sta_cfg));
    g_n8.sta_cfg.sta.pmf_cfg.capable = true;
    g_n8.sta_cfg.sta.pmf_cfg.required = false;

    memset(&g_n8.ap_cfg, 0, sizeof(g_n8.ap_cfg));
    snprintf((char *)g_n8.ap_cfg.ap.ssid, sizeof(g_n8.ap_cfg.ap.ssid),
             "ESP_%02X%02X%02X", g_n8.ap_mac[3], g_n8.ap_mac[4], g_n8.ap_mac[5]);
    g_n8.ap_cfg.ap.ssid_len = (uint8_t)strlen((const char *)g_n8.ap_cfg.ap.ssid);
    g_n8.ap_cfg.ap.channel = 1U;
    g_n8.ap_cfg.ap.authmode = WIFI_AUTH_OPEN;
    g_n8.ap_cfg.ap.max_connection = 4U;
    g_n8.ap_cfg.ap.beacon_interval = 100U;
}

#ifdef CONFIG_ESP8266_WIFI_NVS_ENABLED

static bool nvs_use_flash(void)
{
    return (g_n8.init_cfg.nvs_enable != 0) && (g_n8.storage == WIFI_STORAGE_FLASH);
}

void n8_nvs_load(void)
{
    if (!nvs_use_flash()) {
        return;
    }

    nvs_handle_t h;
    if (nvs_open("nvs.net80211", NVS_READONLY, &h) != ESP_OK) {
        return;
    }

    uint8_t u8v = 0U;
    if (nvs_get_u8(h, "opmode", &u8v) == ESP_OK && u8v < WIFI_MODE_MAX) {
        g_n8.mode = (wifi_mode_t)u8v;
    }

    size_t sz = sizeof(g_n8.sta_cfg.sta);
    (void)nvs_get_blob(h, "sta.cfg", &g_n8.sta_cfg.sta, &sz);

    sz = sizeof(g_n8.ap_cfg.ap);
    (void)nvs_get_blob(h, "ap.cfg", &g_n8.ap_cfg.ap, &sz);
    if (g_n8.ap_cfg.ap.max_connection == 0U || g_n8.ap_cfg.ap.max_connection > ESP_WIFI_MAX_CONN_NUM) {
        g_n8.ap_cfg.ap.max_connection = 4U;
    }
    if (g_n8.ap_cfg.ap.beacon_interval < 100U) {
        g_n8.ap_cfg.ap.beacon_interval = 100U;
    }

    sz = sizeof(g_n8.sta_pmk);
    if (nvs_get_blob(h, "sta.pmk", g_n8.sta_pmk, &sz) == ESP_OK && sz == 32U) {
        g_n8.sta_reset_param = 0U;
    } else {
        g_n8.sta_reset_param = 1U;
    }

    sz = sizeof(g_n8.country);
    (void)nvs_get_blob(h, "country", &g_n8.country, &sz);
    if (g_n8.country.schan == 0U || g_n8.country.nchan == 0U || g_n8.country.schan + g_n8.country.nchan > 15U) {
        g_n8.country.schan = 1U;
        g_n8.country.nchan = 13U;
    }

    nvs_close(h);
}

void n8_nvs_save_mode(void)
{
    if (!nvs_use_flash()) {
        return;
    }
    nvs_handle_t h;
    if (nvs_open("nvs.net80211", NVS_READWRITE, &h) == ESP_OK) {
        (void)nvs_set_u8(h, "opmode", (uint8_t)g_n8.mode);
        (void)nvs_commit(h);
        nvs_close(h);
    }
}

void n8_nvs_save_sta_cfg(void)
{
    if (!nvs_use_flash()) {
        return;
    }
    nvs_handle_t h;
    if (nvs_open("nvs.net80211", NVS_READWRITE, &h) == ESP_OK) {
        (void)nvs_set_blob(h, "sta.cfg", &g_n8.sta_cfg.sta, sizeof(g_n8.sta_cfg.sta));
        (void)nvs_set_blob(h, "sta.pmk", g_n8.sta_pmk, sizeof(g_n8.sta_pmk));
        (void)nvs_commit(h);
        nvs_close(h);
    }
}

void n8_nvs_save_ap_cfg(void)
{
    if (!nvs_use_flash()) {
        return;
    }
    nvs_handle_t h;
    if (nvs_open("nvs.net80211", NVS_READWRITE, &h) == ESP_OK) {
        (void)nvs_set_blob(h, "ap.cfg", &g_n8.ap_cfg.ap, sizeof(g_n8.ap_cfg.ap));
        (void)nvs_commit(h);
        nvs_close(h);
    }
}

void n8_nvs_save_country(void)
{
    if (!nvs_use_flash()) {
        return;
    }
    nvs_handle_t h;
    if (nvs_open("nvs.net80211", NVS_READWRITE, &h) == ESP_OK) {
        (void)nvs_set_blob(h, "country", &g_n8.country, sizeof(g_n8.country));
        (void)nvs_commit(h);
        nvs_close(h);
    }
}

void n8_nvs_restore(void)
{
    n8_rtc_cache_clear();
    if (g_n8.init_cfg.nvs_enable != 0) {
        nvs_handle_t h;
        if (nvs_open("nvs.net80211", NVS_READWRITE, &h) == ESP_OK) {
            (void)nvs_erase_all(h);
            (void)nvs_commit(h);
            nvs_close(h);
        }
    }
    n8_nvs_init_defaults();
}

#else /* !CONFIG_ESP8266_WIFI_NVS_ENABLED */

void n8_nvs_load(void)         {}
void n8_nvs_save_mode(void)    {}
void n8_nvs_save_sta_cfg(void) {}
void n8_nvs_save_ap_cfg(void)  {}
void n8_nvs_save_country(void) {}

void n8_nvs_restore(void)
{
    n8_rtc_cache_clear();
    n8_nvs_init_defaults();
}

#endif /* CONFIG_ESP8266_WIFI_NVS_ENABLED */
