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
// Active/passive channel scanning, Probe Request TX, Beacon/Probe Response IE
// parsing (SSID, rates, DS channel, RSN/WPA, HT20), and transient scan list.

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "net80211_internal.h"

#define TAG "wifi_scan"

extern size_t esp_wifi_scan_get_ap_num_max(void);
extern const bool _g_esp_wifi_connect_open_router_when_pwd_is_set;

/* Key management masks from wpa_supplicant/src/common/defs.h */
#define SUPP_KEY_MGMT_IEEE8021X      (1 << 0)
#define SUPP_KEY_MGMT_PSK            (1 << 1)
#define SUPP_KEY_MGMT_PSK_SHA256     (1 << 8)
#define SUPP_KEY_MGMT_SAE            (1 << 10)
#define SUPP_CAP_MFPR                (1 << 6)
#define SUPP_CAP_MFPC                (1 << 7)

static const uint8_t s_bcast[6] = { 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU };
static const uint8_t s_supp_rates_11bg[] = {
    0x01U, 0x08U, 0x82U, 0x84U, 0x8BU, 0x96U, 0x0CU, 0x12U, 0x18U, 0x24U,
    0x32U, 0x04U, 0x30U, 0x48U, 0x60U, 0x6CU
};

static bool is_zero_mac(const uint8_t mac[6])
{
    return (mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]) == 0U;
}

static bool is_bcast_mac(const uint8_t mac[6])
{
    return (mac[0] & mac[1] & mac[2] & mac[3] & mac[4] & mac[5]) == 0xFFU;
}

void n8_scan_free_results(void)
{
    if (g_n8.scan_results != NULL) {
        heap_caps_free(g_n8.scan_results);
        g_n8.scan_results = NULL;
    }
    g_n8.scan_result_cnt = 0U;
    g_n8.scan_result_cap = 0U;
}

static void scan_send_probe_req(const uint8_t *ssid, uint8_t ssid_len)
{
    uint8_t buf[96];
    memset(buf, 0, sizeof(buf));

    buf[0] = IEEE80211_FC_TYPE_MGMT | IEEE80211_SUBTYPE_PROBE_REQ;
    memcpy(buf + 4U, s_bcast, 6U);
    memcpy(buf + 10U, g_n8.sta_mac, 6U);
    memcpy(buf + 16U, s_bcast, 6U);
    uint16_t seq = n8_sta_next_seq();
    buf[22] = (uint8_t)(seq & 0xFFU);
    buf[23] = (uint8_t)(seq >> 8);

    uint16_t off = 24U;
    if (ssid != NULL && ssid_len > 0U && ssid_len <= 32U) {
        buf[off++] = IEEE80211_IE_SSID;
        buf[off++] = ssid_len;
        memcpy(buf + off, ssid, ssid_len);
        off = (uint16_t)(off + ssid_len);
    } else {
        buf[off++] = IEEE80211_IE_SSID;
        buf[off++] = 0U;
    }

    memcpy(buf + off, s_supp_rates_11bg, sizeof(s_supp_rates_11bg));
    off = (uint16_t)(off + sizeof(s_supp_rates_11bg));

    /* DS Parameter Set (current channel) */
    buf[off++] = IEEE80211_IE_DS_PARAM;
    buf[off++] = 1U;
    buf[off++] = esp_lmac_get_channel();

    esp_lmac_tx_req_t tx = {0};
    tx.vif = ESP_LMAC_VIF_STA;
    tx.peer_id = ESP_LMAC_PEER_INVALID;
    tx.ac = ESP_LMAC_AC_MGMT;
    tx.flags = ESP_LMAC_TX_FLAG_NO_ACK | ESP_LMAC_TX_FLAG_FORCE_LOWEST_RATE;
    tx.hdr = buf;
    tx.hdr_len = off;
    (void)esp_lmac_tx_submit(&tx);
}

#define N8_SCAN_DEFAULT_ACTIVE_MS   120U
#define N8_SCAN_DEFAULT_PASSIVE_MS  360U
#define N8_SCAN_HOME_VISIT_MS       20U
#define N8_SCAN_PM_WAIT_MS          20U

#define N8_SCAN_PHASE_PROBE1        0U
#define N8_SCAN_PHASE_DWELL_END     1U
#define N8_SCAN_PHASE_HOME_VISIT    2U
#define N8_SCAN_PHASE_PM_WAIT       3U

static void scan_timer_cb(void *arg);

const wifi_country_t *n8_get_active_country(void)
{
    if (g_n8.country.policy == WIFI_COUNTRY_POLICY_AUTO &&
        g_n8.sta_state == N8_STA_RUN && g_n8.sta_ap_country_valid) {
        return &g_n8.sta_ap_country;
    }
    return &g_n8.country;
}

static bool scan_ch_is_passive(uint8_t ch)
{
    if (g_n8.scan_passive) {
        return true;
    }
    /* Channels 12..14 use passive scanning during non-connect scans */
    if (!g_n8.scan_for_connect && ch >= 12U) {
        return true;
    }
    return false;
}

static void scan_send_active_probe(void)
{
    if (g_n8.scan_target_ssid_len > 0U) {
        scan_send_probe_req(g_n8.scan_target_ssid, g_n8.scan_target_ssid_len);
    } else {
        scan_send_probe_req(NULL, 0U);
    }
}

static void scan_arm_timer(uint32_t ms)
{
    if (!g_n8.scan_timer_inited) {
        ets_timer_setfn(&g_n8.scan_timer, scan_timer_cb, NULL);
        g_n8.scan_timer_inited = 1U;
    }
    ets_timer_disarm(&g_n8.scan_timer);
    ets_timer_arm(&g_n8.scan_timer, (ms > 0U) ? ms : 1U, false);
}

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
        if (g_n8.scan_active_ms >= 80U) {
            g_n8.scan_phase = N8_SCAN_PHASE_PROBE1;
            scan_arm_timer(g_n8.scan_active_ms / 2U);
        } else {
            g_n8.scan_phase = N8_SCAN_PHASE_DWELL_END;
            scan_arm_timer(g_n8.scan_active_ms);
        }
    }
}

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
        max_ap = 16U;
    } else if (max_ap > 64U) {
        max_ap = 64U;
    }
    g_n8.scan_results = (n8_scan_entry_t *)heap_caps_zalloc(max_ap * sizeof(n8_scan_entry_t),
                                                            MALLOC_CAP_8BIT);
    if (g_n8.scan_results == NULL) {
        return ESP_ERR_NO_MEM;
    }
    g_n8.scan_result_cap = (uint16_t)max_ap;
    g_n8.scan_result_cnt = 0U;

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
            size_t n = strnlen((const char *)cfg->ssid, 32U);
            memcpy(g_n8.scan_target_ssid, cfg->ssid, n);
            g_n8.scan_target_ssid[n] = '\0';
            g_n8.scan_target_ssid_len = (uint8_t)n;
        }
        if (cfg->bssid != NULL && !is_zero_mac(cfg->bssid) && !is_bcast_mac(cfg->bssid)) {
            memcpy(g_n8.scan_target_bssid, cfg->bssid, 6U);
            g_n8.scan_use_bssid = 1U;
        }
        if (cfg->channel >= 1U && cfg->channel <= 14U) {
            req_ch = cfg->channel;
        }
        g_n8.scan_show_hidden = cfg->show_hidden ? 1U : 0U;
        if (cfg->scan_type == WIFI_SCAN_TYPE_PASSIVE) {
            g_n8.scan_passive = 1U;
            if (cfg->scan_time.passive > 0U) {
                uint32_t ms = cfg->scan_time.passive;
                if (ms < 30U) ms = 30U;
                if (ms > 1500U) ms = 1500U;
                g_n8.scan_passive_ms = (uint16_t)ms;
            }
        } else if (cfg->scan_time.active.max > 0U) {
            uint32_t ms = cfg->scan_time.active.max;
            if (ms < 30U) ms = 30U;
            if (ms > 1500U) ms = 1500U;
            g_n8.scan_active_ms = (uint16_t)ms;
        }
    } else if (for_connect) {
        size_t n = strnlen((const char *)g_n8.sta_cfg.sta.ssid, 32U);
        memcpy(g_n8.scan_target_ssid, g_n8.sta_cfg.sta.ssid, n);
        g_n8.scan_target_ssid[n] = '\0';
        g_n8.scan_target_ssid_len = (uint8_t)n;
        if (g_n8.sta_cfg.sta.bssid_set) {
            memcpy(g_n8.scan_target_bssid, g_n8.sta_cfg.sta.bssid, 6U);
            g_n8.scan_use_bssid = 1U;
        }
    }

    g_n8.scan_ch_cnt = 0U;
    if (req_ch >= 1U && req_ch <= 14U) {
        g_n8.scan_ch_list[g_n8.scan_ch_cnt++] = req_ch;
    } else {
        const wifi_country_t *cc = n8_get_active_country();
        uint8_t schan = (cc->schan >= 1U) ? cc->schan : 1U;
        uint8_t nchan = (cc->nchan >= 1U && cc->nchan <= 14U) ? cc->nchan : 13U;
        /* Scan home channel first (if associated) and common 1/6/11 channels */
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
        for (uint8_t c = schan; c < (uint8_t)(schan + nchan) && c <= 14U; c++) {
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
    g_n8.scan_active = 0U;
    g_n8.scan_for_connect = 0U;
    g_n8.scan_assoc_mode = 0U;
    esp_lmac_set_scan_rx_mode(false);

    /* Restore operating channel (STA if connected, else SoftAP if running) */
    if (g_n8.sta_state >= N8_STA_AUTH && g_n8.sta_channel >= 1U) {
        (void)esp_lmac_set_channel(g_n8.sta_channel);
        g_n8.cur_channel = g_n8.sta_channel;
    } else if (g_n8.ap_running && g_n8.ap_cfg.ap.channel >= 1U) {
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

    if (post_event) {
        system_event_t evt;
        memset(&evt, 0, sizeof(evt));
        evt.event_id = SYSTEM_EVENT_SCAN_DONE;
        evt.event_info.scan_done.status = 0U;
        evt.event_info.scan_done.number = (uint8_t)(g_n8.scan_result_cnt > 255U ? 255U : g_n8.scan_result_cnt);
        evt.event_info.scan_done.scan_id = 0U;
        n8_send_system_event(&evt);
    }
}

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
        /* Second active probe halfway through the 120 ms channel dwell */
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

    /* When associated, visit home channel for 30 ms between off-channel hops to service data */
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

static uint16_t rate_byte_to_bit(uint8_t r)
{
    switch (r & 0x7FU) {
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

static bool ssid_is_hidden(const uint8_t *val, uint8_t len)
{
    for (uint8_t i = 0U; i < len; i++) {
        if (val[i] != 0U) {
            return false;
        }
    }
    return true;
}

void n8_scan_rx_beacon_or_probe(const wifi_pkt_rx_ctrl_t *ctrl,
                                const uint8_t *frame, uint16_t len)
{
    if (!g_n8.scan_active || g_n8.scan_results == NULL || len < 36U) {
        return;
    }

    const uint8_t *bssid = frame + 16U;
    if (g_n8.scan_use_bssid && memcmp(bssid, g_n8.scan_target_bssid, 6U) != 0) {
        return;
    }

    uint16_t bcn_int = (uint16_t)((uint16_t)frame[32] | ((uint16_t)frame[33] << 8));
    uint16_t capinfo = (uint16_t)((uint16_t)frame[34] | ((uint16_t)frame[35] << 8));

    /* Parse Information Elements */
    const uint8_t *ies = frame + 36U;
    uint16_t ie_len = (uint16_t)(len - 36U);
    uint16_t pos = 0U;

    uint8_t ssid[33];
    uint8_t ssid_len = 0U;
    bool got_ssid = false;
    uint8_t ds_ch = (uint8_t)ctrl->channel;
    uint16_t rate_mask = 0U;
    uint8_t ht_mcs = 0U;
    uint8_t ht_present = 0U;
    uint8_t wps_present = 0U;
    const uint8_t *rsn_ie = NULL;
    uint8_t rsn_len = 0U;
    const uint8_t *wpa_ie = NULL;
    uint8_t wpa_len = 0U;
    wifi_country_t bcn_country;
    bool has_country = false;

    memset(ssid, 0, sizeof(ssid));
    memset(&bcn_country, 0, sizeof(bcn_country));

    while (pos + 2U <= ie_len) {
        uint8_t id = ies[pos];
        uint8_t elen = ies[pos + 1U];
        if (pos + 2U + elen > ie_len) {
            break;
        }
        const uint8_t *val = &ies[pos + 2U];

        switch (id) {
        case IEEE80211_IE_SSID:
            if (!got_ssid) {
                got_ssid = true;
                uint8_t raw_len = (elen > 32U) ? 32U : elen;
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
            if (elen >= 1U && val[0] >= 1U && val[0] <= 14U) {
                ds_ch = val[0];
            }
            break;

        case IEEE80211_IE_COUNTRY:
            if (elen >= 6U) {
                memcpy(bcn_country.cc, val, 3U);
                bcn_country.schan = val[3];
                bcn_country.nchan = val[4];
                bcn_country.max_tx_power = (int8_t)val[5];
                has_country = true;
            }
            break;

        case IEEE80211_IE_HT_CAP:
            if (elen >= 26U) {
                ht_present = 1U;
                ht_mcs = val[3]; /* Supported MCS Set byte 0 = MCS0..7 */
            }
            break;

        case IEEE80211_IE_RSN:
            rsn_ie = &ies[pos];
            rsn_len = (uint8_t)(elen + 2U);
            break;

        case IEEE80211_IE_VENDOR:
            if (elen >= 4U && val[0] == 0x00U && val[1] == 0x50U && val[2] == 0xF2U) {
                if (val[3] == 0x01U) {
                    wpa_ie = &ies[pos];
                    wpa_len = (uint8_t)(elen + 2U);
                } else if (val[3] == 0x04U) {
                    wps_present = 1U;
                }
            }
            break;

        default:
            break;
        }
        pos = (uint16_t)(pos + 2U + elen);
    }

    if (ssid_len == 0U && !g_n8.scan_show_hidden) {
        return;
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
        if (memcmp(g_n8.scan_results[i].rec.bssid, bssid, 6U) == 0) {
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

    memcpy(ent->rec.bssid, bssid, 6U);
    if (ssid_len > 0U) {
        memcpy(ent->rec.ssid, ssid, ssid_len);
        ent->rec.ssid[ssid_len] = '\0';
    }
    ent->rec.primary = ds_ch;
    ent->rec.second = WIFI_SECOND_CHAN_NONE;
    ent->rec.rssi = (int8_t)ctrl->rssi;
    ent->rec.phy_11b = (rate_mask & 0x000FU) ? 1U : 0U;
    ent->rec.phy_11g = (rate_mask & 0x0FF0U) ? 1U : 0U;
    ent->rec.phy_11n = ht_present;
    ent->rec.wps = wps_present;
    if (has_country) {
        ent->rec.country = bcn_country;
    }

    ent->capinfo = capinfo;
    ent->rate_mask_11bg = rate_mask;
    ent->ht_mcs_mask = ht_mcs;
    ent->ht_cap = ht_present;
    ent->beacon_int = (bcn_int >= 10U && bcn_int <= 255U) ? (uint8_t)bcn_int : 100U;

    /* Classify security authmode & ciphers using wpa_supplicant's IE parser */
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

    ent->wpa_proto = (uint8_t)((wpa_ok ? 1U : 0U) | (rsn_ok ? 2U : 0U));
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

        if ((rsn_data.key_mgmt & SUPP_KEY_MGMT_SAE) && (rsn_data.key_mgmt & SUPP_KEY_MGMT_PSK)) {
            ent->rec.authmode = WIFI_AUTH_WPA2_WPA3_PSK;
        } else if (rsn_data.key_mgmt & SUPP_KEY_MGMT_SAE) {
            ent->rec.authmode = WIFI_AUTH_WPA3_PSK;
        } else if (rsn_data.key_mgmt & SUPP_KEY_MGMT_IEEE8021X) {
            ent->rec.authmode = WIFI_AUTH_WPA2_ENTERPRISE;
        } else if (wpa_ok) {
            ent->rec.authmode = WIFI_AUTH_WPA_WPA2_PSK;
        } else {
            ent->rec.authmode = WIFI_AUTH_WPA2_PSK;
        }
    } else if (wpa_ok) {
        ent->rec.pairwise_cipher = (wifi_cipher_type_t)wpa_data.pairwise_cipher;
        ent->rec.group_cipher = (wifi_cipher_type_t)wpa_data.group_cipher;
        ent->akm_psk = 1U;
        ent->rec.authmode = WIFI_AUTH_WPA_PSK;
    } else if ((capinfo & 0x0010U) != 0U) {
        ent->rec.authmode = WIFI_AUTH_WEP;
        ent->rec.pairwise_cipher = WIFI_CIPHER_TYPE_WEP40;
        ent->rec.group_cipher = WIFI_CIPHER_TYPE_WEP40;
    } else {
        ent->rec.authmode = WIFI_AUTH_OPEN;
        ent->rec.pairwise_cipher = WIFI_CIPHER_TYPE_NONE;
        ent->rec.group_cipher = WIFI_CIPHER_TYPE_NONE;
    }

    /* Immediate early-exit on connect fast-scan as soon as matching target AP responds */
    if (g_n8.scan_for_connect && g_n8.sta_cfg.sta.scan_method == WIFI_FAST_SCAN &&
        n8_scan_pick_best_ap() != NULL) {
        n8_scan_stop_internal(false);
    }
}

n8_scan_entry_t *n8_scan_pick_best_ap(void)
{
    size_t target_len = strnlen((const char *)g_n8.sta_cfg.sta.ssid, 32U);
    if (target_len == 0U || g_n8.scan_results == NULL) {
        return NULL;
    }

    bool has_pwd = (g_n8.sta_cfg.sta.password[0] != 0U);
    bool sae_allowed = false;
#ifdef CONFIG_ESP8266_WIFI_ENABLE_WPA3_SAE
    sae_allowed = (g_n8.init_cfg.wpa3_sae_enable != 0U);
#endif
    n8_scan_entry_t *best = NULL;

    for (uint16_t i = 0U; i < g_n8.scan_result_cnt; i++) {
        n8_scan_entry_t *e = &g_n8.scan_results[i];
        size_t elen = strnlen((const char *)e->rec.ssid, 32U);
        if (elen != target_len || memcmp(e->rec.ssid, g_n8.sta_cfg.sta.ssid, target_len) != 0) {
            continue;
        }
        if (g_n8.sta_cfg.sta.bssid_set &&
            memcmp(e->rec.bssid, g_n8.sta_cfg.sta.bssid, 6U) != 0) {
            continue;
        }
        if (g_n8.sta_cfg.sta.threshold.rssi != 0 &&
            e->rec.rssi < g_n8.sta_cfg.sta.threshold.rssi) {
            continue;
        }
        if (e->rec.authmode < g_n8.sta_cfg.sta.threshold.authmode) {
            continue;
        }
        if (!has_pwd && e->rec.authmode != WIFI_AUTH_OPEN) {
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
        if (best == NULL || e->rec.rssi > best->rec.rssi) {
            best = e;
        }
    }

    return best;
}
