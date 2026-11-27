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
// Active/passive channel scanning, Probe Request TX (with WPS/vendor IEs),
// Beacon/Probe Response IE parsing (SSID, rates, DS channel, Country, HT20/
// SGI20, RSN/WPA, WMM, WPS, freq_offset), callback-driven internal scans,
// authmode classification, and transient scan list & AP selection.

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "net80211_internal.h"

#define TAG "wifi_scan"

extern size_t esp_wifi_scan_get_ap_num_max(void);
extern const bool _g_esp_wifi_connect_open_router_when_pwd_is_set;
extern void n8_mgmt_free_tx_cb(void *ctx, const esp_lmac_tx_status_t *st);

/* Key management & capability masks from wpa_supplicant/src/common/defs.h */
#define SUPP_KEY_MGMT_IEEE8021X         (1 << 0)
#define SUPP_KEY_MGMT_PSK               (1 << 1)
#define SUPP_KEY_MGMT_IEEE8021X_SHA256  (1 << 7)
#define SUPP_KEY_MGMT_PSK_SHA256        (1 << 8)
#define SUPP_KEY_MGMT_SAE               (1 << 10)
#define SUPP_CAP_MFPR                   (1 << 6)
#define SUPP_CAP_MFPC                   (1 << 7)

/* Scan dwell timings (ms), channel policy, and result table bounds */
#define N8_SCAN_DEFAULT_ACTIVE_MS    120U
#define N8_SCAN_DEFAULT_PASSIVE_MS   360U
#define N8_SCAN_HOME_VISIT_MS        20U
#define N8_SCAN_PM_WAIT_MS           20U
#define N8_SCAN_DUAL_PROBE_MIN_MS    80U   /* Split active dwell into two probes when >= 80 ms */
#define N8_SCAN_DWELL_MIN_MS         30U
#define N8_SCAN_DWELL_MAX_MS         1500U
#define N8_SCAN_PASSIVE_CH_START     12U   /* Channels 12..14 passive for general scans */
#define N8_SCAN_DEFAULT_NCHAN        13U   /* Fallback channel count when country nchan is invalid */
#define N8_SCAN_AP_CAP_DEFAULT       16U
#define N8_SCAN_AP_CAP_MAX           64U
#define N8_SCAN_EVT_NUM_MAX          255U
#define N8_SCAN_PROBE_BODY_MAX       384U  /* Stack staging cap for ProbeReq body (with WPS/vendor IEs) */
#define N8_SCAN_PROBE_INLINE_MAX     92U   /* Single-descriptor LMAC scratch limit (hdr + body) */

/* Scan channel state-machine phases */
#define N8_SCAN_PHASE_PROBE1         0U    /* Mid-dwell checkpoint to emit 2nd active ProbeReq */
#define N8_SCAN_PHASE_DWELL_END      1U    /* End of current channel dwell */
#define N8_SCAN_PHASE_HOME_VISIT     2U    /* Brief return to home channel while associated */
#define N8_SCAN_PHASE_PM_WAIT        3U    /* Waiting for PM=1 NullFunc TX before off-ch hop */

/* Beacon/ProbeResp IE layout, OUI selectors, and rate masks */
#define N8_BCN_HDR_TOTAL_LEN         (IEEE80211_HDR_LEN + IEEE80211_BCN_FIXED_LEN)
#define IEEE80211_RATE_VAL_MASK      0x7FU /* Strips 0x80 basic-rate flag bit */
#define N8_RATE_MASK_11B             0x000FU /* Bits 0..3: 1, 2, 5.5, 11 Mbps */
#define N8_RATE_MASK_11G             0x0FF0U /* Bits 4..11: 6..54 Mbps */
#define IEEE80211_COUNTRY_IE_MIN_LEN 6U
#define IEEE80211_COUNTRY_CC_LEN     3U
#define IEEE80211_COUNTRY_SCHAN_OFF  3U
#define IEEE80211_COUNTRY_NCHAN_OFF  4U
#define IEEE80211_COUNTRY_MAXPWR_OFF 5U
#define IEEE80211_HT_CAP_IE_LEN      26U
#define IEEE80211_HT_CAP_MCS0_OFF    3U    /* Supported MCS Set byte 0 = MCS0..7 */
#define IEEE80211_VENDOR_OUI_TYPE_LEN 4U
#define N8_BCN_INT_MIN_TU            10U
#define N8_BCN_INT_MAX_TU            255U
#define N8_BCN_INT_DEFAULT_TU        100U

static const uint8_t s_bcast[IEEE80211_ADDR_LEN] = { 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU };

/* Pre-encoded Supported Rates (1,2,5.5,11 basic + 6,9,12,18) & Extended Rates (24,36,48,54 Mbps) */
static const uint8_t s_supp_rates_11bg[] = {
    IEEE80211_IE_SUPP_RATES, 0x08U, 0x82U, 0x84U, 0x8BU, 0x96U, 0x0CU, 0x12U, 0x18U, 0x24U,
    IEEE80211_IE_EXT_RATES,  0x04U, 0x30U, 0x48U, 0x60U, 0x6CU
};

static void scan_timer_cb(void *arg);

/**
 * @brief Check whether a 6-byte MAC address is all zeros.
 *
 * @param mac 6-byte MAC address.
 * @return true if every byte is 0x00.
 */
static bool is_zero_mac(const uint8_t mac[6])
{
    return (mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]) == 0U;
}

/**
 * @brief Check whether a 6-byte MAC address is the all-ones broadcast address.
 *
 * @param mac 6-byte MAC address.
 * @return true if every byte is 0xFF.
 */
static bool is_bcast_mac(const uint8_t mac[6])
{
    return (mac[0] & mac[1] & mac[2] & mac[3] & mac[4] & mac[5]) == 0xFFU;
}

/**
 * @brief Free the transient scan result table and reset entry counts.
 */
void n8_scan_free_results(void)
{
    if (g_n8.scan_results != NULL) {
        heap_caps_free(g_n8.scan_results);
        g_n8.scan_results = NULL;
    }
    g_n8.scan_result_cnt = 0U;
    g_n8.scan_result_cap = 0U;
}

/**
 * @brief Build and transmit an active 802.11 Probe Request frame on the current channel.
 *
 * Encodes either a directed SSID IE (when `ssid` and `ssid_len` are valid) or a
 * wildcard (length-0) SSID IE, followed by 11b/g Supported/Extended Rates, the
 * current channel DS Parameter Set IE, optional WPS Probe Request App-IE
 * (`WIFI_APPIE_WPS_PR`), and optional user Probe Request vendor IEs. Uses a
 * stack-allocated single-descriptor frame when total length fits within LMAC
 * scratch limits, falling back to a scatter-gather heap payload otherwise.
 *
 * @param ssid     Optional target SSID bytes (NULL for wildcard probe).
 * @param ssid_len Length of `ssid` in bytes (0..N8_MAX_SSID_LEN).
 */
static void scan_send_probe_req(const uint8_t *ssid, uint8_t ssid_len)
{
    uint8_t hdr[IEEE80211_HDR_LEN];
    uint8_t body[N8_SCAN_PROBE_BODY_MAX];
    memset(hdr, 0, sizeof(hdr));

    hdr[0] = IEEE80211_FC_TYPE_MGMT | IEEE80211_SUBTYPE_PROBE_REQ;
    memcpy(hdr + IEEE80211_HDR_ADDR1_OFF, s_bcast, IEEE80211_ADDR_LEN);
    memcpy(hdr + IEEE80211_HDR_ADDR2_OFF, g_n8.sta_mac, IEEE80211_ADDR_LEN);
    memcpy(hdr + IEEE80211_HDR_ADDR3_OFF, s_bcast, IEEE80211_ADDR_LEN);
    uint16_t seq = n8_sta_next_seq();
    hdr[IEEE80211_HDR_SEQ_OFF] = (uint8_t)(seq & 0xFFU);
    hdr[IEEE80211_HDR_SEQ_OFF + 1U] = (uint8_t)(seq >> 8);

    uint16_t off = 0U;
    if (ssid != NULL && ssid_len > 0U && ssid_len <= N8_MAX_SSID_LEN) {
        body[off++] = IEEE80211_IE_SSID;
        body[off++] = ssid_len;
        memcpy(body + off, ssid, ssid_len);
        off = (uint16_t)(off + ssid_len);
    } else {
        body[off++] = IEEE80211_IE_SSID;
        body[off++] = 0U;
    }

    memcpy(body + off, s_supp_rates_11bg, sizeof(s_supp_rates_11bg));
    off = (uint16_t)(off + sizeof(s_supp_rates_11bg));

    /* DS Parameter Set (current channel) */
    body[off++] = IEEE80211_IE_DS_PARAM;
    body[off++] = 1U;
    body[off++] = esp_lmac_get_channel();

    /* Append WPS Probe Request App-IE when installed by esp_wps */
    uint16_t wps_len = 0U;
    const uint8_t *wps_ie = n8_supp_get_ie_bytes(WIFI_APPIE_WPS_PR, &wps_len);
    if (wps_ie != NULL && wps_len > 0U && (uint16_t)(off + wps_len) <= sizeof(body)) {
        memcpy(body + off, wps_ie, wps_len);
        off = (uint16_t)(off + wps_len);
    }

    /* Append user Probe Request vendor IEs if configured */
    off = n8_append_vendor_ies(WIFI_VND_IE_TYPE_PROBE_REQ, body, off, sizeof(body));

    esp_lmac_tx_req_t tx = {0};
    tx.vif = ESP_LMAC_VIF_STA;
    tx.peer_id = ESP_LMAC_PEER_INVALID;
    tx.ac = ESP_LMAC_AC_MGMT;
    tx.flags = ESP_LMAC_TX_FLAG_NO_ACK | ESP_LMAC_TX_FLAG_FORCE_LOWEST_RATE;

    /* Fast path: small frames fit directly into LMAC TX header scratch (0 heap allocs) */
    if ((uint16_t)(IEEE80211_HDR_LEN + off) <= N8_SCAN_PROBE_INLINE_MAX) {
        uint8_t pkt[N8_SCAN_PROBE_INLINE_MAX];
        memcpy(pkt, hdr, IEEE80211_HDR_LEN);
        memcpy(pkt + IEEE80211_HDR_LEN, body, off);
        tx.hdr = pkt;
        tx.hdr_len = (uint16_t)(IEEE80211_HDR_LEN + off);
        (void)esp_lmac_tx_submit(&tx);
        return;
    }

    /* Oversized frames (e.g. with WPS/vendor IEs) split body into async-freed SG segment */
    uint8_t *copy = (uint8_t *)heap_caps_malloc(off, MALLOC_CAP_8BIT);
    if (copy == NULL) {
        return;
    }
    memcpy(copy, body, off);
    esp_lmac_sg_seg_t seg = { .ptr = copy, .len = off };
    tx.hdr = hdr;
    tx.hdr_len = IEEE80211_HDR_LEN;
    tx.segs = &seg;
    tx.seg_cnt = 1U;
    tx.done_cb = n8_mgmt_free_tx_cb;
    tx.done_ctx = copy;
    if (esp_lmac_tx_submit(&tx) != ESP_OK) {
        heap_caps_free(copy);
    }
}

/**
 * @brief Return the effective regulatory country configuration.
 *
 * Under `WIFI_COUNTRY_POLICY_AUTO`, returns the connected AP's advertised country
 * IE when STA is in `N8_STA_RUN`; otherwise returns the static country config.
 *
 * @return Pointer to active `wifi_country_t`.
 */
const wifi_country_t *n8_get_active_country(void)
{
    if (g_n8.country.policy == WIFI_COUNTRY_POLICY_AUTO &&
        g_n8.sta_state == N8_STA_RUN && g_n8.sta_ap_country_valid) {
        return &g_n8.sta_ap_country;
    }
    return &g_n8.country;
}

/**
 * @brief Determine whether a channel must be scanned passively.
 *
 * @param ch 2.4 GHz channel number (1..14).
 * @return true if passive scanning is required for `ch`, false for active probing.
 */
static bool scan_ch_is_passive(uint8_t ch)
{
    if (g_n8.scan_passive) {
        return true;
    }
    /* Channels 12..14 use passive scanning during non-connect scans */
    if (!g_n8.scan_for_connect && ch >= N8_SCAN_PASSIVE_CH_START) {
        return true;
    }
    return false;
}

/**
 * @brief Emit either a directed or wildcard Probe Request for the active scan.
 */
static void scan_send_active_probe(void)
{
    if (g_n8.scan_target_ssid_len > 0U) {
        scan_send_probe_req(g_n8.scan_target_ssid, g_n8.scan_target_ssid_len);
    } else {
        scan_send_probe_req(NULL, 0U);
    }
}

/**
 * @brief Arm the one-shot scan state-machine timer for the specified delay.
 *
 * @param ms Delay in milliseconds (clamped to at least 1 ms).
 */
static void scan_arm_timer(uint32_t ms)
{
    if (!g_n8.scan_timer_inited) {
        ets_timer_setfn(&g_n8.scan_timer, scan_timer_cb, NULL);
        g_n8.scan_timer_inited = 1U;
    }
    ets_timer_disarm(&g_n8.scan_timer);
    ets_timer_arm(&g_n8.scan_timer, (ms > 0U) ? ms : 1U, false);
}

/*
 * Multi-phase scan state machine (per channel in `scan_ch_list[]`):
 *   1. Associated off-channel entry (`scan_assoc_mode && ch != sta_channel`):
 *      Stay on `sta_channel`, transmit PM=1 NullFunc (`N8_SCAN_PHASE_PM_WAIT`,
 *      bounded by `N8_SCAN_PM_WAIT_MS`) so the AP buffers downlink traffic.
 *      When TX finishes (or times out), hop off-channel via `scan_enter_current_channel()`.
 *   2. Channel dwell (`scan_enter_current_channel()`):
 *      Enable LMAC scan RX mode and tune to `ch`.
 *      - Passive channel: dwell `scan_passive_ms` (`N8_SCAN_PHASE_DWELL_END`).
 *      - Active channel: emit ProbeReq #1. If `scan_active_ms >= 80 ms`, arm
 *        half-dwell (`N8_SCAN_PHASE_PROBE1`) to emit ProbeReq #2 halfway through,
 *        then wait the remaining half (`N8_SCAN_PHASE_DWELL_END`).
 *   3. Post-dwell transition (`scan_timer_cb()`):
 *      Advance `scan_ch_idx`. If associated and just finished an off-channel dwell,
 *      return to `sta_channel` with PM=0 NullFunc, drain parked TX, and dwell
 *      `N8_SCAN_HOME_VISIT_MS` (`N8_SCAN_PHASE_HOME_VISIT`) before the next hop.
 */

/**
 * @brief Tune the radio to `scan_ch_list[scan_ch_idx]` and begin its active or passive dwell.
 */
static void scan_enter_current_channel(void)
{
    if (!g_n8.scan_active || g_n8.scan_ch_idx >= g_n8.scan_ch_cnt) {
        return;
    }

    uint8_t ch = g_n8.scan_ch_list[g_n8.scan_ch_idx];
    esp_lmac_set_scan_rx_mode(true);
    (void)esp_lmac_set_channel(ch);
    g_n8.cur_channel = ch;

    if (scan_ch_is_passive(ch)) {
        g_n8.scan_phase = N8_SCAN_PHASE_DWELL_END;
        scan_arm_timer(g_n8.scan_passive_ms);
    } else {
        scan_send_active_probe();
        if (g_n8.scan_active_ms >= N8_SCAN_DUAL_PROBE_MIN_MS) {
            g_n8.scan_phase = N8_SCAN_PHASE_PROBE1;
            scan_arm_timer(g_n8.scan_active_ms / 2U);
        } else {
            g_n8.scan_phase = N8_SCAN_PHASE_DWELL_END;
            scan_arm_timer(g_n8.scan_active_ms);
        }
    }
}

/**
 * @brief LMAC TX completion callback for the PM=1 NullFunc sent before an off-channel hop.
 *
 * @param ctx Unused callback context.
 * @param st  LMAC TX completion status (unused; hop proceeds even on ACK timeout).
 */
static void scan_pm1_done_cb(void *ctx, const esp_lmac_tx_status_t *st)
{
    (void)ctx;
    (void)st;
    if (g_n8.scan_active && g_n8.scan_phase == N8_SCAN_PHASE_PM_WAIT) {
        if (g_n8.scan_timer_inited) {
            ets_timer_disarm(&g_n8.scan_timer);
        }
        scan_enter_current_channel();
    }
}

/**
 * @brief Start scanning `scan_ch_list[scan_ch_idx]`, announcing PM=1 first if leaving home channel.
 */
static void scan_begin_next_channel(void)
{
    if (!g_n8.scan_active || g_n8.scan_ch_idx >= g_n8.scan_ch_cnt) {
        return;
    }

    uint8_t ch = g_n8.scan_ch_list[g_n8.scan_ch_idx];
    if (g_n8.scan_assoc_mode && g_n8.sta_state == N8_STA_RUN && ch != g_n8.sta_channel) {
        /* Notify AP PM=1 on home channel and hop as soon as TX completes (with safety timeout) */
        if (g_n8.cur_channel != g_n8.sta_channel) {
            esp_lmac_set_scan_rx_mode(false);
            (void)esp_lmac_set_channel(g_n8.sta_channel);
            g_n8.cur_channel = g_n8.sta_channel;
        }
        g_n8.scan_phase = N8_SCAN_PHASE_PM_WAIT;
        scan_arm_timer(N8_SCAN_PM_WAIT_MS);
        n8_pm_send_nullfunc_cb(true, scan_pm1_done_cb, NULL);
        return;
    }

    scan_enter_current_channel();
}

/**
 * @brief Start an active or passive Wi-Fi scan on the worker task.
 *
 * Allocates the transient `scan_results` buffer, applies filter/dwell parameters
 * from `cfg` (or from `g_n8.sta_cfg` when `for_connect` is true), orders channels
 * prioritizing home channel (when associated) and channels 1/6/11, and kicks off
 * the first channel dwell.
 *
 * @param cfg         Optional user scan configuration (NULL uses defaults / STA profile).
 * @param for_connect true when invoked internally to locate an AP for STA association.
 * @param single_ch   Optional single channel hint (1..14) when `cfg` does not set one.
 * @return ESP_OK on start, ESP_ERR_WIFI_NOT_STARTED, ESP_ERR_WIFI_MODE, or ESP_ERR_NO_MEM.
 */
esp_err_t n8_scan_start_internal(const wifi_scan_config_t *cfg, bool for_connect,
                                 uint8_t single_ch)
{
    if (!g_n8.started) {
        return ESP_ERR_WIFI_NOT_STARTED;
    }
    if (g_n8.mode != WIFI_MODE_STA && g_n8.mode != WIFI_MODE_APSTA) {
        return ESP_ERR_WIFI_MODE;
    }

    /* Ensure RF is open before scanning */
    n8_pm_wake_for_tx();

    if (g_n8.scan_active) {
        n8_scan_stop_internal(false);
    }

    n8_scan_free_results();

    size_t max_ap = esp_wifi_scan_get_ap_num_max();
    if (max_ap == 0U) {
        max_ap = N8_SCAN_AP_CAP_DEFAULT;
    } else if (max_ap > N8_SCAN_AP_CAP_MAX) {
        max_ap = N8_SCAN_AP_CAP_MAX;
    }
    g_n8.scan_results = (n8_scan_entry_t *)heap_caps_zalloc(max_ap * sizeof(n8_scan_entry_t),
                                                            MALLOC_CAP_8BIT);
    if (g_n8.scan_results == NULL) {
        return ESP_ERR_NO_MEM;
    }
    g_n8.scan_result_cap = (uint16_t)max_ap;
    g_n8.scan_result_cnt = 0U;
    g_n8.scan_done_cb = NULL;

    g_n8.scan_for_connect = for_connect ? 1U : 0U;
    g_n8.scan_assoc_mode = (!for_connect && g_n8.sta_state == N8_STA_RUN) ? 1U : 0U;
    g_n8.scan_passive = 0U;
    g_n8.scan_target_ssid_len = 0U;
    g_n8.scan_use_bssid = 0U;
    g_n8.scan_show_hidden = for_connect ? 1U : 0U;
    g_n8.scan_active_ms = N8_SCAN_DEFAULT_ACTIVE_MS;
    g_n8.scan_passive_ms = N8_SCAN_DEFAULT_PASSIVE_MS;

    uint8_t req_ch = single_ch;
    if (cfg != NULL) {
        if (cfg->ssid != NULL && cfg->ssid[0] != 0U) {
            size_t n = strnlen((const char *)cfg->ssid, N8_MAX_SSID_LEN);
            memcpy(g_n8.scan_target_ssid, cfg->ssid, n);
            g_n8.scan_target_ssid[n] = '\0';
            g_n8.scan_target_ssid_len = (uint8_t)n;
        }
        if (cfg->bssid != NULL && !is_zero_mac(cfg->bssid) && !is_bcast_mac(cfg->bssid)) {
            memcpy(g_n8.scan_target_bssid, cfg->bssid, IEEE80211_ADDR_LEN);
            g_n8.scan_use_bssid = 1U;
        }
        if (cfg->channel >= N8_CHANNEL_MIN && cfg->channel <= N8_CHANNEL_MAX) {
            req_ch = cfg->channel;
        }
        g_n8.scan_show_hidden = cfg->show_hidden ? 1U : 0U;
        if (cfg->scan_type == WIFI_SCAN_TYPE_PASSIVE) {
            g_n8.scan_passive = 1U;
            if (cfg->scan_time.passive > 0U) {
                uint32_t ms = cfg->scan_time.passive;
                if (ms < N8_SCAN_DWELL_MIN_MS) ms = N8_SCAN_DWELL_MIN_MS;
                if (ms > N8_SCAN_DWELL_MAX_MS) ms = N8_SCAN_DWELL_MAX_MS;
                g_n8.scan_passive_ms = (uint16_t)ms;
            }
        } else if (cfg->scan_time.active.max > 0U) {
            uint32_t ms = cfg->scan_time.active.max;
            if (ms < N8_SCAN_DWELL_MIN_MS) ms = N8_SCAN_DWELL_MIN_MS;
            if (ms > N8_SCAN_DWELL_MAX_MS) ms = N8_SCAN_DWELL_MAX_MS;
            g_n8.scan_active_ms = (uint16_t)ms;
        }
    } else if (for_connect) {
        size_t n = strnlen((const char *)g_n8.sta_cfg.sta.ssid, N8_MAX_SSID_LEN);
        memcpy(g_n8.scan_target_ssid, g_n8.sta_cfg.sta.ssid, n);
        g_n8.scan_target_ssid[n] = '\0';
        g_n8.scan_target_ssid_len = (uint8_t)n;
        if (g_n8.sta_cfg.sta.bssid_set) {
            memcpy(g_n8.scan_target_bssid, g_n8.sta_cfg.sta.bssid, IEEE80211_ADDR_LEN);
            g_n8.scan_use_bssid = 1U;
        }
    }

    g_n8.scan_ch_cnt = 0U;
    if (req_ch >= N8_CHANNEL_MIN && req_ch <= N8_CHANNEL_MAX) {
        g_n8.scan_ch_list[g_n8.scan_ch_cnt++] = req_ch;
    } else {
        const wifi_country_t *cc = n8_get_active_country();
        uint8_t schan = (cc->schan >= N8_CHANNEL_MIN) ? cc->schan : N8_CHANNEL_MIN;
        uint8_t nchan = (cc->nchan >= N8_CHANNEL_MIN && cc->nchan <= N8_CHANNEL_MAX) ? cc->nchan : N8_SCAN_DEFAULT_NCHAN;
        /* Scan home channel first (if associated) and common non-overlapping 1/6/11 channels */
        uint8_t first_ch = (g_n8.scan_assoc_mode && g_n8.sta_channel >= schan &&
                            g_n8.sta_channel < (uint8_t)(schan + nchan))
                           ? g_n8.sta_channel : 0U;
        if (first_ch != 0U) {
            g_n8.scan_ch_list[g_n8.scan_ch_cnt++] = first_ch;
        }
        static const uint8_t pref[] = { 1U, 6U, 11U };
        for (size_t i = 0U; i < sizeof(pref); i++) {
            if (pref[i] != first_ch && pref[i] >= schan && pref[i] < (uint8_t)(schan + nchan)) {
                g_n8.scan_ch_list[g_n8.scan_ch_cnt++] = pref[i];
            }
        }
        for (uint8_t c = schan; c < (uint8_t)(schan + nchan) && c <= N8_CHANNEL_MAX; c++) {
            if (c != first_ch && c != 1U && c != 6U && c != 11U) {
                g_n8.scan_ch_list[g_n8.scan_ch_cnt++] = c;
            }
        }
    }

    g_n8.scan_ch_idx = 0U;
    g_n8.scan_active = 1U;
    scan_begin_next_channel();
    return ESP_OK;
}

/**
 * @brief Sort collected scan results in-place by descending RSSI (strongest first).
 */
static void scan_sort_results(void)
{
    /* Insertion sort by descending RSSI */
    for (uint16_t i = 1U; i < g_n8.scan_result_cnt; i++) {
        n8_scan_entry_t tmp = g_n8.scan_results[i];
        int32_t j = (int32_t)i - 1;
        while (j >= 0 && g_n8.scan_results[j].rec.rssi < tmp.rec.rssi) {
            g_n8.scan_results[j + 1] = g_n8.scan_results[j];
            j--;
        }
        g_n8.scan_results[j + 1] = tmp;
    }
}

/**
 * @brief Stop an active scan, restore the operating channel, and deliver completion notifications.
 *
 * Restores STA or SoftAP home channel, resumes awake PM state and drains any
 * parked TX frames if scanning while associated, sorts results by RSSI, and
 * delivers completion: invokes `n8_sta_on_scan_done()` for connect scans, or
 * signals `scan_done_sem` and either calls `scan_done_cb(NULL, OK)` (when
 * started via `esp_wifi_promiscuous_scan_start()`) or posts
 * `SYSTEM_EVENT_SCAN_DONE`.
 *
 * @param post_event true to notify completion (`scan_done_cb` or `SYSTEM_EVENT_SCAN_DONE`)
 *                   for non-connect scans; false when aborting/restarting silently.
 */
void n8_scan_stop_internal(bool post_event)
{
    if (!g_n8.scan_active) {
        return;
    }

    if (g_n8.scan_timer_inited) {
        ets_timer_disarm(&g_n8.scan_timer);
    }

    bool was_for_connect = (g_n8.scan_for_connect != 0U);
    bool was_assoc = (g_n8.scan_assoc_mode != 0U);
    n8_scan_done_cb_t done_cb = g_n8.scan_done_cb;
    g_n8.scan_active = 0U;
    g_n8.scan_for_connect = 0U;
    g_n8.scan_assoc_mode = 0U;
    g_n8.scan_done_cb = NULL;
    esp_lmac_set_scan_rx_mode(false);

    /* Restore operating channel (STA if connected, else SoftAP if running) */
    if (g_n8.sta_state >= N8_STA_AUTH && g_n8.sta_channel >= N8_CHANNEL_MIN) {
        (void)esp_lmac_set_channel(g_n8.sta_channel);
        g_n8.cur_channel = g_n8.sta_channel;
    } else if (g_n8.ap_running && g_n8.ap_cfg.ap.channel >= N8_CHANNEL_MIN) {
        (void)esp_lmac_set_channel(g_n8.ap_cfg.ap.channel);
        g_n8.cur_channel = g_n8.ap_cfg.ap.channel;
    }

    /* Resume STA normal awake/PM state and flush any TX jobs parked while off-channel */
    if (was_assoc && g_n8.sta_state == N8_STA_RUN) {
        n8_pm_send_nullfunc_now(false);
        n8_pm_on_activity();
        n8_data_process_tx_queue();
    }

    scan_sort_results();

    ESP_LOGD(TAG, "scan done: found=%u ch_cnt=%u cur_ch=%u assoc=%u",
             (unsigned)g_n8.scan_result_cnt, (unsigned)g_n8.scan_ch_cnt,
             (unsigned)g_n8.cur_channel, (unsigned)was_assoc);

    if (was_for_connect) {
        n8_sta_on_scan_done();
        return;
    }

    if (g_n8.scan_done_sem != NULL) {
        xSemaphoreGive(g_n8.scan_done_sem);
    }

    if (post_event && done_cb != NULL) {
        done_cb(NULL, OK);
        return;
    }

    if (post_event) {
        system_event_t evt;
        memset(&evt, 0, sizeof(evt));
        evt.event_id = SYSTEM_EVENT_SCAN_DONE;
        evt.event_info.scan_done.status = 0U;
        evt.event_info.scan_done.number = (uint8_t)(g_n8.scan_result_cnt > N8_SCAN_EVT_NUM_MAX ? N8_SCAN_EVT_NUM_MAX : g_n8.scan_result_cnt);
        evt.event_info.scan_done.scan_id = 0U;
        n8_send_system_event(&evt);
    }
}

typedef struct {
    const wifi_scan_config_t *cfg;
    n8_scan_done_cb_t         cb;
} n8_promisc_scan_arg_t;

/**
 * @brief Worker-task RPC handler for `esp_wifi_promiscuous_scan_start()`.
 *
 * Starts a non-connect scan via `n8_scan_start_internal()` and installs the
 * caller's completion callback into `g_n8.scan_done_cb` on success.
 *
 * @param arg Pointer to `n8_promisc_scan_arg_t` containing scan config and callback.
 * @return Result of `n8_scan_start_internal()`.
 */
static esp_err_t api_promiscuous_scan_start(void *arg)
{
    const n8_promisc_scan_arg_t *a = (const n8_promisc_scan_arg_t *)arg;
    esp_err_t err = n8_scan_start_internal(a->cfg, false, 0U);
    if (err == ESP_OK) {
        g_n8.scan_done_cb = a->cb;
    }
    return err;
}

/**
 * @brief Start a callback-driven active/passive scan for internal supplicant consumers (WPS).
 *
 * Marshals scan startup onto the net80211 worker task and invokes @p cb on normal
 * completion instead of emitting SYSTEM_EVENT_SCAN_DONE.
 *
 * @param config Scan parameters (channel, active/passive mode, dwell times).
 * @param cb     Optional completion callback invoked on worker context.
 * @return ESP_OK on success, or an ESP_ERR_* code on failure.
 */
int esp_wifi_promiscuous_scan_start(wifi_scan_config_t *config, n8_scan_done_cb_t cb)
{
    if (!g_n8.initialized) {
        return ESP_ERR_WIFI_NOT_INIT;
    }
    n8_promisc_scan_arg_t req = { .cfg = config, .cb = cb };
    return (int)n8_api_call(api_promiscuous_scan_start, &req);
}

/**
 * @brief ETS timer callback advancing the multi-phase channel scan state machine.
 *
 * Handles PM-wait fallback timeout, home-visit completion, mid-dwell second
 * Probe Request transmission, fast-scan early exit, and channel-to-channel hops
 * (with home-channel service windows when associated).
 *
 * @param arg Unused timer argument.
 */
static void scan_timer_cb(void *arg)
{
    (void)arg;
    if (!g_n8.scan_active) {
        return;
    }

    if (g_n8.scan_phase == N8_SCAN_PHASE_PM_WAIT) {
        scan_enter_current_channel();
        return;
    }

    if (g_n8.scan_phase == N8_SCAN_PHASE_HOME_VISIT) {
        scan_begin_next_channel();
        return;
    }

    /* In connect scan, early-exit as soon as we hear the exact target AP */
    if (g_n8.scan_for_connect && g_n8.scan_result_cnt > 0U &&
        g_n8.sta_cfg.sta.scan_method == WIFI_FAST_SCAN) {
        if (n8_scan_pick_best_ap() != NULL) {
            n8_scan_stop_internal(false);
            return;
        }
    }

    if (g_n8.scan_phase == N8_SCAN_PHASE_PROBE1) {
        /* Second active probe halfway through the active channel dwell */
        scan_send_active_probe();
        g_n8.scan_phase = N8_SCAN_PHASE_DWELL_END;
        uint32_t rem = g_n8.scan_active_ms - (g_n8.scan_active_ms / 2U);
        scan_arm_timer(rem);
        return;
    }

    /* Current channel dwell completed */
    uint8_t finished_ch = g_n8.scan_ch_list[g_n8.scan_ch_idx];
    g_n8.scan_ch_idx++;
    if (g_n8.scan_ch_idx >= g_n8.scan_ch_cnt) {
        n8_scan_stop_internal(true);
        return;
    }

    /* When associated, visit home channel for N8_SCAN_HOME_VISIT_MS between off-channel hops to service data */
    if (g_n8.scan_assoc_mode && g_n8.sta_state == N8_STA_RUN && finished_ch != g_n8.sta_channel) {
        esp_lmac_set_scan_rx_mode(false);
        (void)esp_lmac_set_channel(g_n8.sta_channel);
        g_n8.cur_channel = g_n8.sta_channel;
        n8_pm_send_nullfunc_now(false);
        n8_pm_on_activity();
        n8_data_process_tx_queue();
        g_n8.scan_phase = N8_SCAN_PHASE_HOME_VISIT;
        scan_arm_timer(N8_SCAN_HOME_VISIT_MS);
        return;
    }

    scan_begin_next_channel();
}

/* --------------------------------------------------------------------------
 * Beacon & Probe Response IE Parsing
 * -------------------------------------------------------------------------- */

/**
 * @brief Convert an IEEE 802.11 Supported/Extended Rate byte (500 kbps units) to a bitmask bit.
 *
 * @param r Raw rate octet (bit 7 basic-rate flag is masked off).
 * @return Single-bit mask (bits 0..3 for 11b, bits 4..11 for 11g), or 0 if unrecognized.
 */
static uint16_t rate_byte_to_bit(uint8_t r)
{
    switch (r & IEEE80211_RATE_VAL_MASK) {
    case 2:   return (1U << 0);  /* 1M */
    case 4:   return (1U << 1);  /* 2M */
    case 11:  return (1U << 2);  /* 5.5M */
    case 22:  return (1U << 3);  /* 11M */
    case 12:  return (1U << 4);  /* 6M */
    case 18:  return (1U << 5);  /* 9M */
    case 24:  return (1U << 6);  /* 12M */
    case 36:  return (1U << 7);  /* 18M */
    case 48:  return (1U << 8);  /* 24M */
    case 72:  return (1U << 9);  /* 36M */
    case 96:  return (1U << 10); /* 48M */
    case 108: return (1U << 11); /* 54M */
    default:  return 0U;
    }
}

/**
 * @brief Check whether an SSID Information Element value represents a hidden (all-zero) SSID.
 *
 * @param val Pointer to SSID IE payload bytes.
 * @param len Length of `val` in bytes.
 * @return true if `len == 0` or every byte is 0x00.
 */
static bool ssid_is_hidden(const uint8_t *val, uint8_t len)
{
    for (uint8_t i = 0U; i < len; i++) {
        if (val[i] != 0U) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Classify AP authentication mode from Beacon/ProbeResp capinfo and RSN/WPA IEs.
 *
 * Precedence: RSN (`WPA2_WPA3_PSK` > `WPA3_PSK` > `WPA2_ENTERPRISE` >
 * `WPA_WPA2_PSK` > `WPA2_PSK`) > WPA1 Vendor IE (`WPA_PSK`) > CapInfo Privacy
 * bit (`WEP`) > `OPEN`.
 *
 * @param capinfo     802.11 capability info field.
 * @param rsn_ie      Pointer to RSN IE (or NULL).
 * @param rsn_len     Length of @p rsn_ie including 2-byte IE header.
 * @param wpa_ie      Pointer to WPA1 vendor IE (or NULL).
 * @param wpa_len     Length of @p wpa_ie including 2-byte IE header.
 * @param rsn_out     Optional output parsed RSN IE data.
 * @param wpa_out     Optional output parsed WPA IE data.
 * @param rsn_ok_out  Optional output true if @p rsn_ie parsed cleanly.
 * @param wpa_ok_out  Optional output true if @p wpa_ie parsed cleanly.
 * @return Classified `wifi_auth_mode_t`.
 */
wifi_auth_mode_t n8_parse_ap_authmode(uint16_t capinfo, const uint8_t *rsn_ie, uint16_t rsn_len,
                                      const uint8_t *wpa_ie, uint16_t wpa_len,
                                      wifi_wpa_ie_t *rsn_out, wifi_wpa_ie_t *wpa_out,
                                      bool *rsn_ok_out, bool *wpa_ok_out)
{
    wifi_wpa_ie_t rsn_data;
    wifi_wpa_ie_t wpa_data;
    bool rsn_ok = false;
    bool wpa_ok = false;
    memset(&rsn_data, 0, sizeof(rsn_data));
    memset(&wpa_data, 0, sizeof(wpa_data));

    if (g_n8.wpa_cb != NULL && g_n8.wpa_cb->wpa_parse_wpa_ie != NULL) {
        if (rsn_ie != NULL) {
            rsn_ok = (g_n8.wpa_cb->wpa_parse_wpa_ie(rsn_ie, rsn_len, &rsn_data) == 0);
        }
        if (wpa_ie != NULL) {
            wpa_ok = (g_n8.wpa_cb->wpa_parse_wpa_ie(wpa_ie, wpa_len, &wpa_data) == 0);
        }
    }

    if (rsn_out != NULL)    *rsn_out = rsn_data;
    if (wpa_out != NULL)    *wpa_out = wpa_data;
    if (rsn_ok_out != NULL) *rsn_ok_out = rsn_ok;
    if (wpa_ok_out != NULL) *wpa_ok_out = wpa_ok;

    if (rsn_ok) {
        if ((rsn_data.key_mgmt & SUPP_KEY_MGMT_SAE) && (rsn_data.key_mgmt & SUPP_KEY_MGMT_PSK)) {
            return WIFI_AUTH_WPA2_WPA3_PSK;
        }
        if (rsn_data.key_mgmt & SUPP_KEY_MGMT_SAE) {
            return WIFI_AUTH_WPA3_PSK;
        }
        if (rsn_data.key_mgmt & (SUPP_KEY_MGMT_IEEE8021X | SUPP_KEY_MGMT_IEEE8021X_SHA256)) {
            return WIFI_AUTH_WPA2_ENTERPRISE;
        }
        if (wpa_ok) {
            return WIFI_AUTH_WPA_WPA2_PSK;
        }
        return WIFI_AUTH_WPA2_PSK;
    }
    if (wpa_ok) {
        return WIFI_AUTH_WPA_PSK;
    }
    if ((capinfo & IEEE80211_CAPINFO_PRIVACY) != 0U) {
        return WIFI_AUTH_WEP;
    }
    return WIFI_AUTH_OPEN;
}

/**
 * @brief Parse a received Beacon or Probe Response frame and record/update its scan entry.
 *
 * Walks all TLV Information Elements to extract SSID, 11b/g rates, DS channel,
 * Country IE, HT Capabilities (SGI20 and MCS0..7), RSN IE (ID 48), and
 * Microsoft-OUI Vendor IEs (WPA1 type 0x01, WMM type 0x02, and WPS type 0x04).
 * Forwards parsed IE pointers to the WPS enrollee scanner when active,
 * deduplicates entries by BSSID (evicting the weakest RSSI entry when full),
 * records baseband `freq_offset` when valid, classifies authmode/ciphers/PMF
 * via `n8_parse_ap_authmode()`, and triggers immediate fast-scan exit on
 * connect scans.
 *
 * @param ctrl        LMAC RX control metadata (RSSI, RX channel).
 * @param freq_offset Baseband frequency offset (or `N8_FREQ_OFFSET_INVALID`).
 * @param frame       Pointer to received 802.11 management frame.
 * @param len         Frame length in bytes (excluding FCS).
 */
void n8_scan_rx_beacon_or_probe(const wifi_pkt_rx_ctrl_t *ctrl, int16_t freq_offset,
                                const uint8_t *frame, uint16_t len)
{
    if (!g_n8.scan_active || g_n8.scan_results == NULL || len < N8_BCN_HDR_TOTAL_LEN) {
        return;
    }

    const uint8_t *bssid = frame + IEEE80211_HDR_ADDR3_OFF;
    if (g_n8.scan_use_bssid && memcmp(bssid, g_n8.scan_target_bssid, IEEE80211_ADDR_LEN) != 0) {
        return;
    }

    uint16_t bcn_int = (uint16_t)((uint16_t)frame[IEEE80211_HDR_LEN + IEEE80211_BCN_INT_OFF] |
                                  ((uint16_t)frame[IEEE80211_HDR_LEN + IEEE80211_BCN_INT_OFF + 1U] << 8));
    uint16_t capinfo = (uint16_t)((uint16_t)frame[IEEE80211_HDR_LEN + IEEE80211_BCN_CAPINFO_OFF] |
                                  ((uint16_t)frame[IEEE80211_HDR_LEN + IEEE80211_BCN_CAPINFO_OFF + 1U] << 8));

    /* Parse Information Elements */
    const uint8_t *ies = frame + N8_BCN_HDR_TOTAL_LEN;
    uint16_t ie_len = (uint16_t)(len - N8_BCN_HDR_TOTAL_LEN);
    uint16_t pos = 0U;

    uint8_t ssid[N8_MAX_SSID_LEN + 1U];
    uint8_t ssid_len = 0U;
    bool got_ssid = false;
    uint8_t ds_ch = (uint8_t)ctrl->channel;
    uint16_t rate_mask = 0U;
    uint8_t ht_mcs = 0U;
    uint8_t ht_present = 0U;
    uint8_t ht_sgi20 = 0U;
    uint8_t wmm_present = 0U;
    uint8_t wps_present = 0U;
    const uint8_t *ssid_ie = NULL;
    const uint8_t *rsn_ie = NULL;
    uint16_t rsn_len = 0U;
    const uint8_t *wpa_ie = NULL;
    uint16_t wpa_len = 0U;
    const uint8_t *wps_ie = NULL;
    wifi_country_t bcn_country;
    bool has_country = false;

    memset(ssid, 0, sizeof(ssid));
    memset(&bcn_country, 0, sizeof(bcn_country));

    while (pos + IEEE80211_IE_HDR_LEN <= ie_len) {
        uint8_t id = ies[pos];
        uint8_t elen = ies[pos + 1U];
        if (pos + IEEE80211_IE_HDR_LEN + elen > ie_len) {
            break;
        }
        const uint8_t *val = &ies[pos + IEEE80211_IE_HDR_LEN];

        switch (id) {
        case IEEE80211_IE_SSID:
            if (!got_ssid) {
                got_ssid = true;
                ssid_ie = &ies[pos];
                uint8_t raw_len = (elen > N8_MAX_SSID_LEN) ? N8_MAX_SSID_LEN : elen;
                if (ssid_is_hidden(val, raw_len)) {
                    ssid_len = 0U;
                    ssid[0] = '\0';
                } else {
                    ssid_len = raw_len;
                    memcpy(ssid, val, ssid_len);
                    ssid[ssid_len] = '\0';
                }
            }
            break;

        case IEEE80211_IE_SUPP_RATES:
        case IEEE80211_IE_EXT_RATES:
            for (uint8_t i = 0U; i < elen; i++) {
                rate_mask |= rate_byte_to_bit(val[i]);
            }
            break;

        case IEEE80211_IE_DS_PARAM:
            if (elen >= 1U && val[0] >= N8_CHANNEL_MIN && val[0] <= N8_CHANNEL_MAX) {
                ds_ch = val[0];
            }
            break;

        case IEEE80211_IE_COUNTRY:
            if (elen >= IEEE80211_COUNTRY_IE_MIN_LEN) {
                memcpy(bcn_country.cc, val, IEEE80211_COUNTRY_CC_LEN);
                bcn_country.schan = val[IEEE80211_COUNTRY_SCHAN_OFF];
                bcn_country.nchan = val[IEEE80211_COUNTRY_NCHAN_OFF];
                bcn_country.max_tx_power = (int8_t)val[IEEE80211_COUNTRY_MAXPWR_OFF];
                has_country = true;
            }
            break;

        case IEEE80211_IE_HT_CAP:
            if (elen >= IEEE80211_HT_CAP_IE_LEN) {
                ht_present = 1U;
                ht_sgi20 = ((val[0] & IEEE80211_HT_CAP_INFO_SGI20) != 0U) ? 1U : 0U;
                ht_mcs = val[IEEE80211_HT_CAP_MCS0_OFF]; /* Supported MCS Set byte 0 = MCS0..7 */
            }
            break;

        case IEEE80211_IE_RSN:
            rsn_ie = &ies[pos];
            rsn_len = (uint16_t)(elen + IEEE80211_IE_HDR_LEN);
            break;

        case IEEE80211_IE_VENDOR:
            if (elen >= IEEE80211_VENDOR_OUI_TYPE_LEN &&
                val[0] == IEEE80211_OUI_MS_0 &&
                val[1] == IEEE80211_OUI_MS_1 &&
                val[2] == IEEE80211_OUI_MS_2) {
                if (val[3] == IEEE80211_OUI_TYPE_WPA) {
                    wpa_ie = &ies[pos];
                    wpa_len = (uint16_t)(elen + IEEE80211_IE_HDR_LEN);
                } else if (val[3] == IEEE80211_OUI_TYPE_WMM &&
                           elen >= IEEE80211_WMM_IE_MIN_BODY_LEN &&
                           (val[4] == IEEE80211_WMM_SUBTYPE_INFO ||
                            val[4] == IEEE80211_WMM_SUBTYPE_PARAM) &&
                           val[5] == IEEE80211_WMM_VERSION) {
                    wmm_present = 1U;
                } else if (val[3] == IEEE80211_OUI_TYPE_WPS) {
                    wps_present = 1U;
                    if (elen > IEEE80211_WPS_OUI_HDR_LEN) {
                        wps_ie = &ies[pos];
                    }
                }
            }
            break;

        default:
            break;
        }
        pos = (uint16_t)(pos + IEEE80211_IE_HDR_LEN + elen);
    }

    if (ssid_len == 0U && !g_n8.scan_show_hidden) {
        return;
    }

    /* Forward IE pointers to WPS enrollee scanner before SSID filtering while WPS discovery runs */
    if (g_n8.wps_cb != NULL && g_n8.wps_cb->wps_parse_scan_result != NULL &&
        g_n8.wps_type != WPS_TYPE_DISABLE &&
        (g_n8.wps_status == WPS_STATUS_DISABLE || g_n8.wps_status == WPS_STATUS_SCANNING) &&
        ssid_ie != NULL && ssid_len > 0U && ssid_ie[1] <= N8_MAX_SSID_LEN) {
        struct wps_scan_ie scan_ie;
        scan_ie.bssid = (uint8_t *)(uintptr_t)bssid;
        scan_ie.chan = ds_ch;
        scan_ie.capinfo = capinfo;
        scan_ie.ssid = (uint8_t *)(uintptr_t)ssid_ie;
        scan_ie.wpa = (uint8_t *)(uintptr_t)wpa_ie;
        scan_ie.rsn = (uint8_t *)(uintptr_t)rsn_ie;
        scan_ie.wps = (uint8_t *)(uintptr_t)wps_ie;
        (void)g_n8.wps_cb->wps_parse_scan_result(&scan_ie);
    }
    if (g_n8.scan_target_ssid_len > 0U) {
        if (ssid_len != g_n8.scan_target_ssid_len ||
            memcmp(ssid, g_n8.scan_target_ssid, ssid_len) != 0) {
            return;
        }
    }

    /* Deduplicate by BSSID */
    n8_scan_entry_t *ent = NULL;
    for (uint16_t i = 0U; i < g_n8.scan_result_cnt; i++) {
        if (memcmp(g_n8.scan_results[i].rec.bssid, bssid, IEEE80211_ADDR_LEN) == 0) {
            ent = &g_n8.scan_results[i];
            break;
        }
    }
    if (ent == NULL) {
        if (g_n8.scan_result_cnt < g_n8.scan_result_cap) {
            ent = &g_n8.scan_results[g_n8.scan_result_cnt++];
            memset(ent, 0, sizeof(*ent));
        } else {
            /* Replace weakest entry if new AP is stronger */
            uint16_t weak = 0U;
            for (uint16_t i = 1U; i < g_n8.scan_result_cnt; i++) {
                if (g_n8.scan_results[i].rec.rssi < g_n8.scan_results[weak].rec.rssi) {
                    weak = i;
                }
            }
            if ((int8_t)ctrl->rssi <= g_n8.scan_results[weak].rec.rssi) {
                return;
            }
            ent = &g_n8.scan_results[weak];
            memset(ent, 0, sizeof(*ent));
        }
    }

    memcpy(ent->rec.bssid, bssid, IEEE80211_ADDR_LEN);
    if (ssid_len > 0U) {
        memcpy(ent->rec.ssid, ssid, ssid_len);
        ent->rec.ssid[ssid_len] = '\0';
    }
    ent->rec.primary = ds_ch;
    ent->rec.second = WIFI_SECOND_CHAN_NONE;
    ent->rec.rssi = (int8_t)ctrl->rssi;
    if (freq_offset != N8_FREQ_OFFSET_INVALID) {
        ent->rec.freq_offset = freq_offset;
    }
    ent->rec.phy_11b = (rate_mask & N8_RATE_MASK_11B) ? 1U : 0U;
    ent->rec.phy_11g = (rate_mask & N8_RATE_MASK_11G) ? 1U : 0U;
    ent->rec.phy_11n = ht_present;
    ent->rec.wps = wps_present;
    if (has_country) {
        ent->rec.country = bcn_country;
    }

    ent->capinfo = capinfo;
    ent->rate_mask_11bg = rate_mask;
    ent->ht_mcs_mask = ht_mcs;
    ent->ht_cap = ht_present;
    ent->ht_sgi20 = ht_sgi20;
    ent->wmm_cap = wmm_present;
    ent->beacon_int = (bcn_int >= N8_BCN_INT_MIN_TU && bcn_int <= N8_BCN_INT_MAX_TU)
                      ? (uint8_t)bcn_int : N8_BCN_INT_DEFAULT_TU;

    /*
     * RSN / WPA IE suite classification:
     * Delegate cipher/AKM/PMF suite parsing to wpa_supplicant's `wpa_parse_wpa_ie()`.
     * Precedence: RSN (WPA3-SAE / WPA2-WPA3 transition / WPA2-Enterprise / WPA-WPA2 /
     * WPA2-PSK) > WPA1 Vendor IE > CapInfo Privacy bit (WEP) > Open.
     */
    wifi_wpa_ie_t rsn_data;
    wifi_wpa_ie_t wpa_data;
    bool rsn_ok = false;
    bool wpa_ok = false;
    ent->rec.authmode = n8_parse_ap_authmode(capinfo, rsn_ie, rsn_len, wpa_ie, wpa_len,
                                             &rsn_data, &wpa_data, &rsn_ok, &wpa_ok);

    ent->wpa_proto = (uint8_t)((wpa_ok ? N8_WPA_PROTO_WPA : 0U) | (rsn_ok ? N8_WPA_PROTO_RSN : 0U));
    ent->akm_sae = 0U;
    ent->akm_psk_sha256 = 0U;
    ent->akm_psk = 0U;
    ent->pmf_capable = 0U;
    ent->pmf_required = 0U;
    ent->mgmt_cipher = WIFI_CIPHER_TYPE_NONE;

    if (rsn_ok) {
        ent->rec.pairwise_cipher = (wifi_cipher_type_t)rsn_data.pairwise_cipher;
        ent->rec.group_cipher = (wifi_cipher_type_t)rsn_data.group_cipher;
        ent->mgmt_cipher = (uint8_t)rsn_data.mgmt_group_cipher;
        ent->pmf_capable = (rsn_data.capabilities & SUPP_CAP_MFPC) ? 1U : 0U;
        ent->pmf_required = (rsn_data.capabilities & SUPP_CAP_MFPR) ? 1U : 0U;
        if (rsn_data.key_mgmt & SUPP_KEY_MGMT_SAE)        ent->akm_sae = 1U;
        if (rsn_data.key_mgmt & SUPP_KEY_MGMT_PSK_SHA256) ent->akm_psk_sha256 = 1U;
        if (rsn_data.key_mgmt & SUPP_KEY_MGMT_PSK)        ent->akm_psk = 1U;
    } else if (wpa_ok) {
        ent->rec.pairwise_cipher = (wifi_cipher_type_t)wpa_data.pairwise_cipher;
        ent->rec.group_cipher = (wifi_cipher_type_t)wpa_data.group_cipher;
        ent->akm_psk = 1U;
    } else if (ent->rec.authmode == WIFI_AUTH_WEP) {
        ent->rec.pairwise_cipher = WIFI_CIPHER_TYPE_WEP40;
        ent->rec.group_cipher = WIFI_CIPHER_TYPE_WEP40;
    } else {
        ent->rec.pairwise_cipher = WIFI_CIPHER_TYPE_NONE;
        ent->rec.group_cipher = WIFI_CIPHER_TYPE_NONE;
    }

    /* Immediate early-exit on connect fast-scan as soon as matching target AP responds */
    if (g_n8.scan_for_connect && g_n8.sta_cfg.sta.scan_method == WIFI_FAST_SCAN &&
        n8_scan_pick_best_ap() != NULL) {
        n8_scan_stop_internal(false);
    }
}

/**
 * @brief Select the best matching AP from `g_n8.scan_results` for STA connection.
 *
 * Filters candidates against exact SSID, optional pinned BSSID, and minimum
 * RSSI threshold. Unless a WPS enrollee exchange is pending (which associates
 * without pre-provisioned credentials), also enforces minimum authmode
 * threshold, password/open-router matching (allowing empty password for Open
 * and enabled WPA2-Enterprise networks), required PMF capability, and WPA3-SAE
 * support. Ranks eligible APs by `sort_method` (`WIFI_CONNECT_AP_BY_SECURITY`
 * prioritizes higher authmode with RSSI tie-breaker; default prioritizes higher
 * RSSI with authmode tie-breaker).
 *
 * @return Pointer to the winning `n8_scan_entry_t`, or NULL if no candidate matches.
 */
n8_scan_entry_t *n8_scan_pick_best_ap(void)
{
    size_t target_len = strnlen((const char *)g_n8.sta_cfg.sta.ssid, N8_MAX_SSID_LEN);
    if (target_len == 0U || g_n8.scan_results == NULL) {
        return NULL;
    }

    bool has_pwd = (g_n8.sta_cfg.sta.password[0] != 0U);
    bool wps_pending = n8_wps_is_pending();
    bool wpa2_ent_en = (g_n8.wpa2_cb != NULL);
    bool sae_allowed = false;
#ifdef CONFIG_ESP8266_WIFI_ENABLE_WPA3_SAE
    sae_allowed = (g_n8.init_cfg.wpa3_sae_enable != 0U);
#endif
    n8_scan_entry_t *best = NULL;

    for (uint16_t i = 0U; i < g_n8.scan_result_cnt; i++) {
        n8_scan_entry_t *e = &g_n8.scan_results[i];
        size_t elen = strnlen((const char *)e->rec.ssid, N8_MAX_SSID_LEN);
        if (elen != target_len || memcmp(e->rec.ssid, g_n8.sta_cfg.sta.ssid, target_len) != 0) {
            continue;
        }
        if (g_n8.sta_cfg.sta.bssid_set &&
            memcmp(e->rec.bssid, g_n8.sta_cfg.sta.bssid, IEEE80211_ADDR_LEN) != 0) {
            continue;
        }
        if (g_n8.sta_cfg.sta.threshold.rssi != 0 &&
            e->rec.rssi < g_n8.sta_cfg.sta.threshold.rssi) {
            continue;
        }
        /* Bypass security/credential filters during WPS enrollment (credentials arrive via EAP-WSC) */
        if (!wps_pending) {
            if (e->rec.authmode < g_n8.sta_cfg.sta.threshold.authmode) {
                continue;
            }
            bool allow_no_pwd = (e->rec.authmode == WIFI_AUTH_OPEN) ||
                                (wpa2_ent_en && e->rec.authmode == WIFI_AUTH_WPA2_ENTERPRISE);
            if (!has_pwd && !allow_no_pwd) {
                continue;
            }
            if (has_pwd && e->rec.authmode == WIFI_AUTH_OPEN &&
                !_g_esp_wifi_connect_open_router_when_pwd_is_set) {
                continue;
            }
            if (g_n8.sta_cfg.sta.pmf_cfg.required && !e->pmf_capable) {
                continue;
            }
            if (!sae_allowed && e->rec.authmode == WIFI_AUTH_WPA3_PSK) {
                continue;
            }
        }
        if (best == NULL) {
            best = e;
        } else if (g_n8.sta_cfg.sta.sort_method == WIFI_CONNECT_AP_BY_SECURITY) {
            if (e->rec.authmode > best->rec.authmode ||
                (e->rec.authmode == best->rec.authmode && e->rec.rssi > best->rec.rssi)) {
                best = e;
            }
        } else {
            if (e->rec.rssi > best->rec.rssi ||
                (e->rec.rssi == best->rec.rssi && e->rec.authmode > best->rec.authmode)) {
                best = e;
            }
        }
    }

    return best;
}
