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
// Complete public esp_wifi_* API implementation backed by esp8266_lmac and
// the unified open-source net80211 worker.

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_phy_init.h"
#include "esp_system.h"
#include "net80211_internal.h"

#define TAG "wifi"

extern esp_err_t esp_now_deinit(void);
extern int wifi_timer_init(void);
extern int misc_nvs_init(void);
extern void misc_nvs_deinit(void);
extern void phy_set_most_tpw(uint8_t max_tpw_qdb);
extern uint8_t phy_get_most_tpw(void);
extern uint32_t g_log_level;
extern uint32_t g_log_mod;
extern void n8_mgmt_free_tx_cb(void *ctx, const esp_lmac_tx_status_t *st);

#define N8_TX_POWER_QDB_MIN           8
#define N8_TX_POWER_QDB_MAX           84
#define N8_MAX_SINGLE_PKT_NO_AMPDU    (1600U - 524U) /* 1076 B extradata clamp when A-MPDU off */
#define N8_MAX_SINGLE_PKT_AMPDU       1600U

/**
 * @brief Apply the effective TX power ceiling across Kconfig, regulatory country, and user cap.
 */
void n8_apply_tx_power_limit(void)
{
    int32_t limit_qdb = (int32_t)CONFIG_ESP8266_PHY_MAX_WIFI_TX_POWER * 4;
    if ((int32_t)g_n8.max_tx_power < limit_qdb) {
        limit_qdb = (int32_t)g_n8.max_tx_power;
    }
    const wifi_country_t *cc = n8_get_active_country();
    if (cc != NULL && cc->max_tx_power > 0) {
        int32_t cc_qdb = (int32_t)cc->max_tx_power * 4;
        if (cc_qdb < limit_qdb) {
            limit_qdb = cc_qdb;
        }
    }
    if (limit_qdb < N8_TX_POWER_QDB_MIN) {
        limit_qdb = N8_TX_POWER_QDB_MIN;
    } else if (limit_qdb > N8_TX_POWER_QDB_MAX) {
        limit_qdb = N8_TX_POWER_QDB_MAX;
    }
    phy_set_most_tpw((uint8_t)limit_qdb);
}

/**
 * @brief Re-apply regulatory TX power limit and refresh SoftAP beacon Country IE if active.
 */
void n8_sync_country_power(void)
{
    n8_apply_tx_power_limit();
    if (g_n8.ap_running) {
        (void)n8_ap_update_beacon();
    }
}

/* --------------------------------------------------------------------------
 * LMAC Callback Bridge (Runs on Unified Wi-Fi Worker)
 * -------------------------------------------------------------------------- */

static void n8_lmac_on_rx(void *ctx, esp_lmac_rx_buf_t *rx_buf)
{
    (void)ctx;
    n8_data_rx_frame(rx_buf);
}

static void n8_lmac_on_sniffer(void *ctx, const wifi_pkt_rx_ctrl_t *ctrl,
                               const uint8_t *frame, uint16_t len)
{
    (void)ctx;
    n8_data_sniffer_rx(ctrl, frame, len);
}

static void n8_lmac_on_tbtt(void *ctx, esp_lmac_vif_t vif)
{
    (void)ctx;
    if (vif == ESP_LMAC_VIF_AP) {
        n8_ap_on_tbtt();
    }
}

/* --------------------------------------------------------------------------
 * Lifecycle: esp_wifi_init_internal / esp_wifi_deinit_internal / start / stop
 * -------------------------------------------------------------------------- */

esp_err_t esp_wifi_init_internal(const wifi_init_config_t *config)
{
    if (config == NULL || config->magic != WIFI_INIT_CONFIG_MAGIC) {
        return ESP_ERR_INVALID_ARG;
    }
    if (g_n8.initialized) {
        return ESP_OK;
    }

    memset(&g_n8, 0, sizeof(g_n8));
    g_n8.init_cfg = *config;
    g_n8.sta_peer_id = ESP_LMAC_PEER_INVALID;

    (void)esp_read_mac(g_n8.sta_mac, ESP_MAC_WIFI_STA);
    (void)esp_read_mac(g_n8.ap_mac, ESP_MAC_WIFI_SOFTAP);

    n8_nvs_init_defaults();
    n8_rtc_cache_load();
    (void)misc_nvs_init();
    n8_nvs_load();
    n8_pm_init();

    (void)wifi_timer_init();
    esp_phy_load_cal_and_init(PHY_WIFI_MODULE);
    n8_apply_tx_power_limit();

    esp_err_t err = n8_worker_start();
    if (err != ESP_OK) {
        return err;
    }

#ifdef CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
    uint8_t ampdu_en = (config->ampdu_rx_enable != 0U) ? 1U : 0U;
    uint8_t ba_win = ampdu_en ? (uint8_t)((config->rx_ba_win > 16U) ? 16U : config->rx_ba_win) : 0U;
    uint8_t abuf_num = ampdu_en
                       ? (uint8_t)(config->rx_ampdu_buf_num ? config->rx_ampdu_buf_num : WIFI_AMPDU_RX_AMPDU_BUF_NUM)
                       : 0U;
    uint16_t abuf_len = ampdu_en
                        ? (uint16_t)((config->rx_ampdu_buf_len >= 64U) ? config->rx_ampdu_buf_len : WIFI_AMPDU_RX_AMPDU_BUF_LEN)
                        : 0U;
#else
    uint8_t ampdu_en = 0U;
    uint8_t ba_win = 0U;
    uint8_t abuf_num = 0U;
    uint16_t abuf_len = 0U;
#endif
    uint16_t max_single = (config->rx_max_single_pkt_len >= 256U)
                          ? (uint16_t)config->rx_max_single_pkt_len
                          : N8_MAX_SINGLE_PKT_AMPDU;
    if (ampdu_en == 0U && max_single > N8_MAX_SINGLE_PKT_NO_AMPDU) {
        max_single = N8_MAX_SINGLE_PKT_NO_AMPDU;
    }

    g_n8.init_cfg.ampdu_rx_enable = ampdu_en;
    g_n8.init_cfg.rx_ba_win = ba_win;
    g_n8.init_cfg.rx_ampdu_buf_num = abuf_num;
    g_n8.init_cfg.rx_ampdu_buf_len = abuf_len;
    g_n8.init_cfg.rx_max_single_pkt_len = max_single;

    esp_lmac_config_t lcfg = {
        .rx_buf_num = (config->rx_buf_num >= 4) ? (uint8_t)config->rx_buf_num : 16U,
        .left_continuous_rx_buf_num = (uint8_t)config->left_continuous_rx_buf_num,
        .tx_slot_num = (config->tx_buf_num >= 2) ? (uint8_t)config->tx_buf_num : 6U,
        .ampdu_rx_enable = ampdu_en,
        .rx_ba_win = ba_win,
        .rx_ampdu_buf_num = abuf_num,
        .rx_ampdu_buf_len = abuf_len,
        .rx_buf_len = (config->rx_buf_len >= 64) ? (uint16_t)config->rx_buf_len : 524U,
        .rx_max_single_pkt_len = max_single,
    };
    esp_lmac_callbacks_t lcbs = {
        .notify_from_isr = n8_lmac_notify_from_isr,
        .on_rx_frame = n8_lmac_on_rx,
        .on_sniffer_frame = n8_lmac_on_sniffer,
        .on_tbtt = n8_lmac_on_tbtt,
        .on_beacon_miss = NULL,
        .ctx = NULL,
    };

    err = esp_lmac_init(&lcfg, &lcbs);
    if (err != ESP_OK) {
        n8_worker_stop();
        return err;
    }

    g_n8.initialized = true;
    g_n8.user_init_flag = 1U;
    return ESP_OK;
}

esp_err_t esp_wifi_deinit_internal(void)
{
    if (!g_n8.initialized) {
        return ESP_OK;
    }
    if (g_n8.started) {
        (void)esp_wifi_stop();
    }

    n8_pm_deinit();
    n8_scan_free_results();
    n8_supp_clear_appies();
    n8_vendor_ie_free_all();
    if (g_n8.scan_done_sem != NULL) {
        vSemaphoreDelete(g_n8.scan_done_sem);
        g_n8.scan_done_sem = NULL;
    }

    (void)esp_lmac_deinit();
    n8_worker_stop();
    misc_nvs_deinit();

    if (g_n8.wpa2_cb != NULL) {
        heap_caps_free(g_n8.wpa2_cb);
        g_n8.wpa2_cb = NULL;
    }
    if (g_n8.wps_cb != NULL) {
        heap_caps_free(g_n8.wps_cb);
        g_n8.wps_cb = NULL;
    }
    g_n8.wps_type = WPS_TYPE_DISABLE;
    g_n8.wps_status = WPS_STATUS_DISABLE;
    g_n8.wps_start_flag = 0U;
    g_n8.sta_conn_timer_disarmed = 0U;
    g_n8.wpa2_ent_state = WPA2_ENT_EAP_STATE_NOT_START;

    g_n8.initialized = false;
    g_n8.user_init_flag = 0U;
    return ESP_OK;
}

static esp_err_t api_start(void *arg)
{
    (void)arg;
    if (g_n8.started) {
        return ESP_OK;
    }

    esp_lmac_rf_open();

    g_n8.started = true;
    if (g_n8.mode == WIFI_MODE_STA || g_n8.mode == WIFI_MODE_APSTA) {
        esp_err_t err = n8_sta_start();
        if (err != ESP_OK) {
            g_n8.started = false;
            return err;
        }
    }
    if (g_n8.mode == WIFI_MODE_AP || g_n8.mode == WIFI_MODE_APSTA) {
        esp_err_t err = n8_ap_start();
        if (err != ESP_OK) {
            if (g_n8.mode == WIFI_MODE_APSTA) {
                n8_sta_stop();
            }
            g_n8.started = false;
            return err;
        }
    }
    return ESP_OK;
}

esp_err_t esp_wifi_start(void)
{
    if (!g_n8.initialized) {
        return ESP_ERR_WIFI_NOT_INIT;
    }
    return n8_api_call(api_start, NULL);
}

static esp_err_t api_stop(void *arg)
{
    (void)arg;
    if (!g_n8.started) {
        return ESP_OK;
    }

    (void)esp_now_deinit();
    if (g_n8.ap_running) {
        n8_ap_stop();
    }
    if (g_n8.mode == WIFI_MODE_STA || g_n8.mode == WIFI_MODE_APSTA) {
        n8_sta_stop();
    }
    esp_lmac_sniffer_disable();
    g_n8.promis_enabled = 0U;
    n8_scan_free_results();
    esp_lmac_rf_close();

    g_n8.started = false;
    return ESP_OK;
}

esp_err_t esp_wifi_stop(void)
{
    if (!g_n8.initialized) {
        return ESP_ERR_WIFI_NOT_INIT;
    }
    return n8_api_call(api_stop, NULL);
}

/* --------------------------------------------------------------------------
 * Mode & Configuration (Eager Caller-Task PBKDF2-SHA1 + RTC_SYS PMK Cache)
 * -------------------------------------------------------------------------- */

static esp_err_t api_set_mode(void *arg)
{
    wifi_mode_t new_mode = *(wifi_mode_t *)arg;
    wifi_mode_t old_mode = g_n8.mode;

    if (new_mode == old_mode) {
        return ESP_OK;
    }

    if (g_n8.started) {
        bool had_sta = (old_mode == WIFI_MODE_STA || old_mode == WIFI_MODE_APSTA);
        bool had_ap  = (old_mode == WIFI_MODE_AP  || old_mode == WIFI_MODE_APSTA);
        bool want_sta = (new_mode == WIFI_MODE_STA || new_mode == WIFI_MODE_APSTA);
        bool want_ap  = (new_mode == WIFI_MODE_AP  || new_mode == WIFI_MODE_APSTA);

        if (had_ap && !want_ap) {
            n8_ap_stop();
        }
        if (had_sta && !want_sta) {
            n8_sta_stop();
        }
        g_n8.mode = new_mode;
        if (!had_sta && want_sta) {
            esp_err_t err = n8_sta_start();
            if (err != ESP_OK) return err;
        }
        if (!had_ap && want_ap) {
            esp_err_t err = n8_ap_start();
            if (err != ESP_OK) return err;
        }
    } else {
        g_n8.mode = new_mode;
    }

    n8_nvs_save_mode();
    return ESP_OK;
}

esp_err_t esp_wifi_set_mode(wifi_mode_t mode)
{
    if (!g_n8.initialized) {
        return ESP_ERR_WIFI_NOT_INIT;
    }
    if (mode >= WIFI_MODE_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    return n8_api_call(api_set_mode, &mode);
}

esp_err_t esp_wifi_get_mode(wifi_mode_t *mode)
{
    if (!g_n8.initialized) {
        return ESP_ERR_WIFI_NOT_INIT;
    }
    if (mode == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    *mode = g_n8.mode;
    return ESP_OK;
}

typedef struct {
    wifi_interface_t ifx;
    const wifi_config_t *conf;
    uint8_t pmk[32];
    bool pmk_computed;
} api_set_cfg_arg_t;

static esp_err_t api_set_config(void *arg)
{
    api_set_cfg_arg_t *a = (api_set_cfg_arg_t *)arg;
    if (a->ifx == WIFI_IF_STA) {
        g_n8.sta_cfg.sta = a->conf->sta;
        if (a->pmk_computed) {
            memcpy(g_n8.sta_pmk, a->pmk, 32U);
            g_n8.sta_reset_param = 0U;
        } else {
            memset(g_n8.sta_pmk, 0, 32U);
            g_n8.sta_reset_param = 1U;
        }
        n8_nvs_save_sta_cfg();
    } else {
        g_n8.ap_cfg.ap = a->conf->ap;
        if (g_n8.ap_cfg.ap.max_connection == 0U || g_n8.ap_cfg.ap.max_connection > ESP_WIFI_MAX_CONN_NUM) {
            g_n8.ap_cfg.ap.max_connection = 4U;
        }
        if (g_n8.ap_cfg.ap.beacon_interval < 100U) {
            g_n8.ap_cfg.ap.beacon_interval = 100U;
        }
        if (g_n8.ap_cfg.ap.channel == 0U || g_n8.ap_cfg.ap.channel > 14U) {
            g_n8.ap_cfg.ap.channel = 1U;
        }
        if (a->pmk_computed) {
            memcpy(g_n8.ap_pmk, a->pmk, 32U);
        }
        n8_nvs_save_ap_cfg();

        if (g_n8.ap_running) {
            /* Re-apply SoftAP config cleanly */
            n8_ap_stop();
            return n8_ap_start();
        }
    }
    return ESP_OK;
}

esp_err_t esp_wifi_set_config(wifi_interface_t interface, wifi_config_t *conf)
{
    if (!g_n8.initialized) {
        return ESP_ERR_WIFI_NOT_INIT;
    }
    if (conf == NULL || (interface != WIFI_IF_STA && interface != WIFI_IF_AP)) {
        return ESP_ERR_INVALID_ARG;
    }

    api_set_cfg_arg_t req;
    memset(&req, 0, sizeof(req));
    req.ifx = interface;
    req.conf = conf;

    /*
     * Compute PBKDF2-SHA1 (or hit RTC_SYS fast-connect PMK cache) EAGERLY on the
     * caller's task context so the high-priority Wi-Fi worker never stalls 400 ms!
     */
    if (interface == WIFI_IF_STA && conf->sta.password[0] != 0U) {
        size_t slen = strnlen((const char *)conf->sta.ssid, 32U);
        bool rtc_hit = false;
        n8_derive_pmk_eager(conf->sta.ssid, slen, conf->sta.password, req.pmk, &rtc_hit);
        req.pmk_computed = true;
    } else if (interface == WIFI_IF_AP && conf->ap.authmode != WIFI_AUTH_OPEN &&
               conf->ap.password[0] != 0U) {
        size_t slen = conf->ap.ssid_len ? conf->ap.ssid_len : strnlen((const char *)conf->ap.ssid, 32U);
        if (slen > 32U) slen = 32U;
        n8_derive_pmk_eager(conf->ap.ssid, slen, conf->ap.password, req.pmk, NULL);
        req.pmk_computed = true;
    }

    return n8_api_call(api_set_config, &req);
}

esp_err_t esp_wifi_get_config(wifi_interface_t interface, wifi_config_t *conf)
{
    if (!g_n8.initialized) {
        return ESP_ERR_WIFI_NOT_INIT;
    }
    if (conf == NULL || (interface != WIFI_IF_STA && interface != WIFI_IF_AP)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (interface == WIFI_IF_STA) {
        conf->sta = g_n8.sta_cfg.sta;
    } else {
        conf->ap = g_n8.ap_cfg.ap;
    }
    return ESP_OK;
}

static esp_err_t api_restore(void *arg)
{
    (void)arg;
    n8_nvs_restore();
    return ESP_OK;
}

esp_err_t esp_wifi_restore(void)
{
    if (!g_n8.initialized) {
        return ESP_ERR_WIFI_NOT_INIT;
    }
    return n8_api_call(api_restore, NULL);
}

/* --------------------------------------------------------------------------
 * STA Connect / Disconnect / Info & SoftAP Deauth / List
 * -------------------------------------------------------------------------- */

static esp_err_t api_connect(void *arg)    { (void)arg; return n8_sta_connect(); }
static esp_err_t api_disconnect(void *arg) { (void)arg; n8_sta_disconnect(WIFI_REASON_ASSOC_LEAVE, true, true); return ESP_OK; }

esp_err_t esp_wifi_connect(void)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    return n8_api_call(api_connect, NULL);
}

esp_err_t esp_wifi_disconnect(void)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    return n8_api_call(api_disconnect, NULL);
}

esp_err_t esp_wifi_clear_fast_connect(void)
{
    n8_rtc_cache_clear();
    return ESP_OK;
}

static esp_err_t api_deauth_sta(void *arg)
{
    uint16_t aid = *(uint16_t *)arg;
    if (!g_n8.ap_running) {
        return ESP_ERR_WIFI_MODE;
    }
    if (aid == 0U) {
        for (uint8_t i = 0U; i < g_n8.ap_sta_cap; i++) {
            if (g_n8.ap_stas != NULL && g_n8.ap_stas[i].in_use) {
                n8_ap_remove_sta(&g_n8.ap_stas[i], WIFI_REASON_ASSOC_LEAVE, true);
            }
        }
    } else {
        n8_ap_sta_t *sta = n8_ap_find_sta_by_aid(aid);
        if (sta == NULL) {
            return ESP_ERR_INVALID_ARG;
        }
        n8_ap_remove_sta(sta, WIFI_REASON_ASSOC_LEAVE, true);
    }
    return ESP_OK;
}

esp_err_t esp_wifi_deauth_sta(uint16_t aid)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    return n8_api_call(api_deauth_sta, &aid);
}

esp_err_t esp_wifi_ap_get_sta_list(wifi_sta_list_t *sta)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (sta == NULL) return ESP_ERR_INVALID_ARG;
    if (g_n8.mode != WIFI_MODE_AP && g_n8.mode != WIFI_MODE_APSTA) return ESP_ERR_WIFI_MODE;

    memset(sta, 0, sizeof(*sta));
    if (g_n8.ap_running && g_n8.ap_stas != NULL) {
        for (uint8_t i = 0U; i < g_n8.ap_sta_cap && sta->num < ESP_WIFI_MAX_CONN_NUM; i++) {
            if (g_n8.ap_stas[i].in_use && g_n8.ap_stas[i].assoced) {
                wifi_sta_info_t *dst = &sta->sta[sta->num++];
                memcpy(dst->mac, g_n8.ap_stas[i].mac, 6U);
                dst->phy_11b = g_n8.ap_stas[i].phy_11b;
                dst->phy_11g = g_n8.ap_stas[i].phy_11g;
                dst->phy_11n = g_n8.ap_stas[i].phy_11n;
            }
        }
    }
    return ESP_OK;
}

esp_err_t esp_wifi_sta_get_ap_info(wifi_ap_record_t *ap_info)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (ap_info == NULL) return ESP_ERR_INVALID_ARG;
    if (g_n8.sta_state != N8_STA_RUN) return ESP_ERR_WIFI_NOT_CONNECT;

    memset(ap_info, 0, sizeof(*ap_info));
    memcpy(ap_info->bssid, g_n8.sta_bssid, 6U);
    memcpy(ap_info->ssid, g_n8.sta_ssid, g_n8.sta_ssid_len);
    ap_info->primary = g_n8.sta_channel;
    ap_info->second = WIFI_SECOND_CHAN_NONE;
    ap_info->rssi = esp_lmac_peer_get_rssi(g_n8.sta_peer_id);
    ap_info->freq_offset = g_n8.sta_last_freq_offset;
    ap_info->authmode = (wifi_auth_mode_t)g_n8.sta_authmode;
    ap_info->pairwise_cipher = (wifi_cipher_type_t)g_n8.sta_pairwise_cipher;
    ap_info->group_cipher = (wifi_cipher_type_t)g_n8.sta_group_cipher;
    ap_info->phy_11b = g_n8.sta_ap_phy_11b ? 1U : 0U;
    ap_info->phy_11g = g_n8.sta_ap_phy_11g ? 1U : 0U;
    ap_info->phy_11n = g_n8.sta_ht_active ? 1U : 0U;
    ap_info->wps = g_n8.sta_ap_wps ? 1U : 0U;
    ap_info->country = *n8_get_active_country();
    return ESP_OK;
}

int8_t esp_wifi_get_ap_rssi(void)
{
    if (!g_n8.initialized || g_n8.sta_state != N8_STA_RUN) {
        return -127;
    }
    return esp_lmac_peer_get_rssi(g_n8.sta_peer_id);
}

/* --------------------------------------------------------------------------
 * Scan APIs
 * -------------------------------------------------------------------------- */

static esp_err_t api_scan_start(void *arg)
{
    const wifi_scan_config_t *cfg = (const wifi_scan_config_t *)arg;
    return n8_scan_start_internal(cfg, false, 0U);
}

esp_err_t esp_wifi_scan_start(const wifi_scan_config_t *config, bool block)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (!g_n8.started) return ESP_ERR_WIFI_NOT_STARTED;

    if (block && !n8_on_worker_task()) {
        if (g_n8.scan_done_sem == NULL) {
            g_n8.scan_done_sem = xSemaphoreCreateBinary();
            if (g_n8.scan_done_sem == NULL) {
                return ESP_ERR_NO_MEM;
            }
        }
        (void)xSemaphoreTake(g_n8.scan_done_sem, 0);
    }

    esp_err_t err = n8_api_call(api_scan_start, (void *)(uintptr_t)config);
    if (err != ESP_OK) {
        return err;
    }

    if (block && !n8_on_worker_task() && g_n8.scan_done_sem != NULL) {
        (void)xSemaphoreTake(g_n8.scan_done_sem, pdMS_TO_TICKS(15000U));
    }
    return ESP_OK;
}

static esp_err_t api_scan_stop(void *arg)
{
    (void)arg;
    n8_scan_stop_internal(false);
    return ESP_OK;
}

esp_err_t esp_wifi_scan_stop(void)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    return n8_api_call(api_scan_stop, NULL);
}

esp_err_t esp_wifi_scan_get_ap_num(uint16_t *number)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (number == NULL) return ESP_ERR_INVALID_ARG;
    *number = g_n8.scan_result_cnt;
    return ESP_OK;
}

typedef struct {
    uint16_t *number;
    wifi_ap_record_t *recs;
} api_scan_recs_t;

static esp_err_t api_scan_get_records(void *arg)
{
    api_scan_recs_t *a = (api_scan_recs_t *)arg;
    uint16_t n = (*a->number < g_n8.scan_result_cnt) ? *a->number : g_n8.scan_result_cnt;
    for (uint16_t i = 0U; i < n; i++) {
        a->recs[i] = g_n8.scan_results[i].rec;
    }
    *a->number = n;
    n8_scan_free_results();
    return ESP_OK;
}

esp_err_t esp_wifi_scan_get_ap_records(uint16_t *number, wifi_ap_record_t *ap_records)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (number == NULL || (*number > 0U && ap_records == NULL)) return ESP_ERR_INVALID_ARG;
    api_scan_recs_t req = { .number = number, .recs = ap_records };
    return n8_api_call(api_scan_get_records, &req);
}

/* --------------------------------------------------------------------------
 * PS, Protocol, Bandwidth, Channel, Country, MAC & Storage
 * -------------------------------------------------------------------------- */

static esp_err_t api_set_ps(void *arg)
{
    n8_pm_set_ps(*(wifi_ps_type_t *)arg);
    return ESP_OK;
}

esp_err_t esp_wifi_set_ps(wifi_ps_type_t type)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (type > WIFI_PS_MAX_MODEM) return ESP_ERR_INVALID_ARG;
    return n8_api_call(api_set_ps, &type);
}

esp_err_t esp_wifi_get_ps(wifi_ps_type_t *type)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (type == NULL) return ESP_ERR_INVALID_ARG;
    *type = g_n8.ps_type;
    return ESP_OK;
}

typedef struct {
    wifi_interface_t ifx;
    uint8_t          proto;
} api_set_proto_t;

static esp_err_t api_set_protocol(void *arg)
{
    const api_set_proto_t *a = (const api_set_proto_t *)arg;
    g_n8.proto[a->ifx] = a->proto;
    esp_lmac_set_protocol_mask((a->ifx == WIFI_IF_AP) ? ESP_LMAC_VIF_AP : ESP_LMAC_VIF_STA,
                               a->proto);
    return ESP_OK;
}

esp_err_t esp_wifi_set_protocol(wifi_interface_t ifx, uint8_t protocol_bitmap)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (ifx != WIFI_IF_STA && ifx != WIFI_IF_AP) return ESP_ERR_WIFI_IF;
    if (protocol_bitmap == 0U) return ESP_ERR_INVALID_ARG;
    api_set_proto_t req = { .ifx = ifx, .proto = protocol_bitmap };
    return n8_api_call(api_set_protocol, &req);
}

esp_err_t esp_wifi_get_protocol(wifi_interface_t ifx, uint8_t *protocol_bitmap)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if ((ifx != WIFI_IF_STA && ifx != WIFI_IF_AP) || protocol_bitmap == NULL) return ESP_ERR_INVALID_ARG;
    *protocol_bitmap = g_n8.proto[ifx];
    return ESP_OK;
}

esp_err_t esp_wifi_set_bandwidth(wifi_interface_t ifx, wifi_bandwidth_t bw)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (ifx != WIFI_IF_STA && ifx != WIFI_IF_AP) return ESP_ERR_INVALID_ARG;
    /* ESP8266 silicon supports HT20 only */
    g_n8.bandwidth[ifx] = (bw == WIFI_BW_HT40) ? WIFI_BW_HT20 : (uint8_t)bw;
    return ESP_OK;
}

esp_err_t esp_wifi_get_bandwidth(wifi_interface_t ifx, wifi_bandwidth_t *bw)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if ((ifx != WIFI_IF_STA && ifx != WIFI_IF_AP) || bw == NULL) return ESP_ERR_INVALID_ARG;
    *bw = (wifi_bandwidth_t)g_n8.bandwidth[ifx];
    return ESP_OK;
}

static esp_err_t api_set_channel(void *arg)
{
    uint8_t ch = *(uint8_t *)arg;
    esp_err_t err = esp_lmac_set_channel(ch);
    if (err == ESP_OK) {
        g_n8.cur_channel = ch;
    }
    return err;
}

esp_err_t esp_wifi_set_channel(uint8_t primary, wifi_second_chan_t second)
{
    (void)second;
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (primary < 1U || primary > 14U) return ESP_ERR_INVALID_ARG;
    return n8_api_call(api_set_channel, &primary);
}

esp_err_t esp_wifi_get_channel(uint8_t *primary, wifi_second_chan_t *second)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (primary != NULL) *primary = esp_lmac_get_channel();
    if (second != NULL) *second = WIFI_SECOND_CHAN_NONE;
    return ESP_OK;
}

static esp_err_t api_set_country(void *arg)
{
    const wifi_country_t *country = (const wifi_country_t *)arg;
    g_n8.country = *country;
    n8_nvs_save_country();
    n8_sync_country_power();
    return ESP_OK;
}

esp_err_t esp_wifi_set_country(const wifi_country_t *country)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (country == NULL || country->schan < 1U || country->nchan == 0U ||
        (country->schan + country->nchan) > 15U) {
        return ESP_ERR_INVALID_ARG;
    }
    return n8_api_call(api_set_country, (void *)(uintptr_t)country);
}

esp_err_t esp_wifi_get_country(wifi_country_t *country)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (country == NULL) return ESP_ERR_INVALID_ARG;
    *country = *n8_get_active_country();
    return ESP_OK;
}

typedef struct {
    wifi_interface_t ifx;
    const uint8_t   *mac;
} api_set_mac_t;

static esp_err_t api_set_mac(void *arg)
{
    const api_set_mac_t *a = (const api_set_mac_t *)arg;
    if (g_n8.started) {
        return ESP_ERR_WIFI_STATE;
    }
    memcpy((a->ifx == WIFI_IF_STA) ? g_n8.sta_mac : g_n8.ap_mac, a->mac, IEEE80211_ADDR_LEN);
    return ESP_OK;
}

esp_err_t esp_wifi_set_mac(wifi_interface_t ifx, const uint8_t mac[6])
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (ifx != WIFI_IF_STA && ifx != WIFI_IF_AP) return ESP_ERR_WIFI_IF;
    if (mac == NULL) return ESP_ERR_INVALID_ARG;
    if ((mac[0] & N8_MAC_MCAST_BIT) != 0U ||
        (mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]) == 0U) {
        return ESP_ERR_WIFI_MAC;
    }
    api_set_mac_t req = { .ifx = ifx, .mac = mac };
    return n8_api_call(api_set_mac, &req);
}

esp_err_t esp_wifi_get_mac(wifi_interface_t ifx, uint8_t mac[6])
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if ((ifx != WIFI_IF_STA && ifx != WIFI_IF_AP) || mac == NULL) return ESP_ERR_INVALID_ARG;
    memcpy(mac, (ifx == WIFI_IF_AP) ? g_n8.ap_mac : g_n8.sta_mac, 6U);
    return ESP_OK;
}

esp_err_t esp_wifi_set_storage(wifi_storage_t storage)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (storage != WIFI_STORAGE_FLASH && storage != WIFI_STORAGE_RAM) return ESP_ERR_INVALID_ARG;
    g_n8.storage = storage;
    return ESP_OK;
}

esp_err_t esp_wifi_set_auto_connect(bool en)
{
    g_n8.auto_connect = en ? 1U : 0U;
    return ESP_OK;
}

esp_err_t esp_wifi_get_auto_connect(bool *en)
{
    if (en == NULL) return ESP_ERR_INVALID_ARG;
    *en = (g_n8.auto_connect != 0U);
    return ESP_OK;
}

/* --------------------------------------------------------------------------
 * Promiscuous / Sniffer, Raw TX, Power, Logging & Diagnostics
 * -------------------------------------------------------------------------- */

esp_err_t esp_wifi_set_promiscuous_rx_cb(wifi_promiscuous_cb_t cb)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    g_n8.promis_cb = cb;
    return ESP_OK;
}

static esp_err_t api_set_promis(void *arg)
{
    bool en = *(bool *)arg;
    if (en) {
        uint32_t f = 0U, cf = 0U;
        esp_lmac_sniffer_get_filter(&f, &cf);
        esp_err_t err = esp_lmac_sniffer_enable(f, cf);
        if (err == ESP_OK) {
            g_n8.promis_enabled = 1U;
        }
        return err;
    }
    esp_lmac_sniffer_disable();
    g_n8.promis_enabled = 0U;
    return ESP_OK;
}

esp_err_t esp_wifi_set_promiscuous(bool en)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    return n8_api_call(api_set_promis, &en);
}

esp_err_t esp_wifi_get_promiscuous(bool *en)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (en == NULL) return ESP_ERR_INVALID_ARG;
    *en = (g_n8.promis_enabled != 0U);
    return ESP_OK;
}

esp_err_t esp_wifi_set_promiscuous_filter(const wifi_promiscuous_filter_t *filter)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (filter == NULL) return ESP_ERR_INVALID_ARG;
    uint32_t cf = 0U;
    esp_lmac_sniffer_get_filter(NULL, &cf);
    esp_lmac_sniffer_set_filter(filter->filter_mask, cf);
    return ESP_OK;
}

esp_err_t esp_wifi_get_promiscuous_filter(wifi_promiscuous_filter_t *filter)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (filter == NULL) return ESP_ERR_INVALID_ARG;
    esp_lmac_sniffer_get_filter(&filter->filter_mask, NULL);
    return ESP_OK;
}

esp_err_t esp_wifi_set_promiscuous_ctrl_filter(const wifi_promiscuous_filter_t *filter)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (filter == NULL) return ESP_ERR_INVALID_ARG;
    uint32_t f = 0U;
    esp_lmac_sniffer_get_filter(&f, NULL);
    esp_lmac_sniffer_set_filter(f, filter->filter_mask);
    return ESP_OK;
}

esp_err_t esp_wifi_get_promiscuous_ctrl_filter(wifi_promiscuous_filter_t *filter)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (filter == NULL) return ESP_ERR_INVALID_ARG;
    esp_lmac_sniffer_get_filter(NULL, &filter->filter_mask);
    return ESP_OK;
}

static esp_err_t api_set_max_tx_power(void *arg)
{
    int8_t power = *(int8_t *)arg;
    if (power < N8_TX_POWER_QDB_MIN) power = N8_TX_POWER_QDB_MIN;
    if (power > N8_TX_POWER_QDB_MAX) power = N8_TX_POWER_QDB_MAX;
    g_n8.max_tx_power = power;
    n8_apply_tx_power_limit();
    return ESP_OK;
}

esp_err_t esp_wifi_set_max_tx_power(int8_t power)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    return n8_api_call(api_set_max_tx_power, &power);
}

esp_err_t esp_wifi_get_max_tx_power(int8_t *power)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (power == NULL) return ESP_ERR_INVALID_ARG;
    *power = (int8_t)phy_get_most_tpw();
    return ESP_OK;
}

esp_err_t esp_wifi_set_event_mask(uint32_t mask)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    g_n8.event_mask = mask;
    return ESP_OK;
}

esp_err_t esp_wifi_get_event_mask(uint32_t *mask)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (mask == NULL) return ESP_ERR_INVALID_ARG;
    *mask = g_n8.event_mask;
    return ESP_OK;
}

typedef struct {
    wifi_interface_t ifx;
    const uint8_t *buf;
    int len;
    bool en_sys_seq;
} api_80211_tx_t;

static esp_err_t api_80211_tx(void *arg)
{
    api_80211_tx_t *a = (api_80211_tx_t *)arg;
    uint8_t hdr[24];
    memcpy(hdr, a->buf, 24U);
    if (a->en_sys_seq) {
        uint16_t seq = (a->ifx == WIFI_IF_AP) ? n8_ap_next_seq() : n8_sta_next_seq();
        hdr[22] = (uint8_t)(seq & 0xFFU);
        hdr[23] = (uint8_t)(seq >> 8);
    }

    uint16_t body_len = (uint16_t)(a->len - 24);
    uint8_t *body = NULL;
    esp_lmac_sg_seg_t seg = {0};
    if (body_len > 0U) {
        body = (uint8_t *)heap_caps_malloc(body_len, MALLOC_CAP_8BIT);
        if (body == NULL) return ESP_ERR_NO_MEM;
        memcpy(body, a->buf + 24, body_len);
        seg.ptr = body;
        seg.len = body_len;
    }

    esp_lmac_tx_req_t tx = {0};
    tx.vif = (a->ifx == WIFI_IF_AP) ? ESP_LMAC_VIF_AP : ESP_LMAC_VIF_STA;
    tx.peer_id = ESP_LMAC_PEER_INVALID;
    tx.ac = ESP_LMAC_AC_MGMT;
    tx.flags = ESP_LMAC_TX_FLAG_FORCE_LOWEST_RATE | ((hdr[4] & 1U) ? ESP_LMAC_TX_FLAG_NO_ACK : 0U);
    tx.hdr = hdr;
    tx.hdr_len = 24U;
    tx.segs = (body != NULL) ? &seg : NULL;
    tx.seg_cnt = (body != NULL) ? 1U : 0U;
    tx.done_cb = (body != NULL) ? n8_mgmt_free_tx_cb : NULL;
    tx.done_ctx = body;

    esp_err_t err = esp_lmac_tx_submit(&tx);
    if (err != ESP_OK && body != NULL) {
        heap_caps_free(body);
    }
    return err;
}

esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (!g_n8.started) return ESP_ERR_WIFI_NOT_STARTED;
    if (buffer == NULL || len < 24 || len > 1500) return ESP_ERR_INVALID_ARG;
    api_80211_tx_t req = { .ifx = ifx, .buf = (const uint8_t *)buffer, .len = len, .en_sys_seq = en_sys_seq };
    return n8_api_call(api_80211_tx, &req);
}

typedef struct {
    bool                   enable;
    wifi_vendor_ie_type_t  type;
    wifi_vendor_ie_id_t    idx;
    const void            *vnd_ie;
} api_set_vnd_ie_t;

static void vendor_ie_prune_empty_table(void)
{
    if (g_n8.vendor_ies == NULL) {
        return;
    }
    for (uint8_t t = 0U; t < N8_VND_IE_TYPE_COUNT; t++) {
        for (uint8_t id = 0U; id < N8_VND_IE_ID_COUNT; id++) {
            if (g_n8.vendor_ies->slots[t][id] != NULL) {
                return;
            }
        }
    }
    heap_caps_free(g_n8.vendor_ies);
    g_n8.vendor_ies = NULL;
}

static esp_err_t api_set_vendor_ie(void *arg)
{
    const api_set_vnd_ie_t *a = (const api_set_vnd_ie_t *)arg;
    if (a->enable) {
        const vendor_ie_data_t *hdr = (const vendor_ie_data_t *)a->vnd_ie;
        uint16_t full_len = (uint16_t)hdr->length + IEEE80211_IE_HDR_LEN;
        if (g_n8.vendor_ies == NULL) {
            g_n8.vendor_ies = (n8_vendor_ie_table_t *)heap_caps_zalloc(
                sizeof(n8_vendor_ie_table_t), MALLOC_CAP_8BIT);
            if (g_n8.vendor_ies == NULL) {
                return ESP_ERR_NO_MEM;
            }
        }
        uint8_t *copy = (uint8_t *)heap_caps_malloc(full_len, MALLOC_CAP_8BIT);
        if (copy == NULL) {
            vendor_ie_prune_empty_table();
            return ESP_ERR_NO_MEM;
        }
        memcpy(copy, a->vnd_ie, full_len);
        if (g_n8.vendor_ies->slots[a->type][a->idx] != NULL) {
            heap_caps_free(g_n8.vendor_ies->slots[a->type][a->idx]);
        }
        g_n8.vendor_ies->slots[a->type][a->idx] = copy;
    } else if (g_n8.vendor_ies != NULL) {
        if (g_n8.vendor_ies->slots[a->type][a->idx] != NULL) {
            heap_caps_free(g_n8.vendor_ies->slots[a->type][a->idx]);
            g_n8.vendor_ies->slots[a->type][a->idx] = NULL;
        }
        vendor_ie_prune_empty_table();
    }

    if (a->type == WIFI_VND_IE_TYPE_BEACON && g_n8.ap_running) {
        (void)n8_ap_update_beacon();
    }
    return ESP_OK;
}

esp_err_t esp_wifi_set_vendor_ie(bool enable, wifi_vendor_ie_type_t type,
                                 wifi_vendor_ie_id_t idx, const void *vnd_ie)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if ((uint32_t)type >= N8_VND_IE_TYPE_COUNT || (uint32_t)idx >= N8_VND_IE_ID_COUNT) {
        return ESP_ERR_INVALID_ARG;
    }
    if (enable) {
        if (vnd_ie == NULL) {
            return ESP_ERR_INVALID_ARG;
        }
        const vendor_ie_data_t *hdr = (const vendor_ie_data_t *)vnd_ie;
        if (hdr->element_id != WIFI_VENDOR_IE_ELEMENT_ID || hdr->length < N8_VND_IE_MIN_LEN) {
            return ESP_ERR_INVALID_ARG;
        }
    }
    api_set_vnd_ie_t req = { .enable = enable, .type = type, .idx = idx, .vnd_ie = vnd_ie };
    return n8_api_call(api_set_vendor_ie, &req);
}

typedef struct {
    esp_vendor_ie_cb_t cb;
    void              *ctx;
} api_set_vnd_cb_t;

static esp_err_t api_set_vendor_ie_cb(void *arg)
{
    const api_set_vnd_cb_t *a = (const api_set_vnd_cb_t *)arg;
    g_n8.vendor_ie_cb = a->cb;
    g_n8.vendor_ie_ctx = a->ctx;
    return ESP_OK;
}

esp_err_t esp_wifi_set_vendor_ie_cb(esp_vendor_ie_cb_t cb, void *ctx)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    api_set_vnd_cb_t req = { .cb = cb, .ctx = ctx };
    return n8_api_call(api_set_vendor_ie_cb, &req);
}

static esp_err_t api_set_rssi_thresh(void *arg)
{
    g_n8.rssi_threshold = *(int32_t *)arg;
    g_n8.rssi_thresh_armed = 1U;
    return ESP_OK;
}

esp_err_t esp_wifi_set_rssi_threshold(int32_t rssi)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (rssi < N8_RSSI_THRESHOLD_MIN || rssi > N8_RSSI_THRESHOLD_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    return n8_api_call(api_set_rssi_thresh, &rssi);
}

typedef struct {
    wifi_interface_t ifx;
    uint16_t         sec;
} api_set_inactive_t;

static esp_err_t api_set_inactive_time(void *arg)
{
    const api_set_inactive_t *a = (const api_set_inactive_t *)arg;
    if (!g_n8.started) {
        return ESP_ERR_WIFI_NOT_STARTED;
    }
    g_n8.inactive_sec[a->ifx] = a->sec;
    return ESP_OK;
}

esp_err_t esp_wifi_set_inactive_time(wifi_interface_t ifx, uint16_t sec)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (ifx != WIFI_IF_STA && ifx != WIFI_IF_AP) return ESP_ERR_INVALID_ARG;
    if ((ifx == WIFI_IF_STA && sec < N8_STA_MIN_INACTIVE_SEC) ||
        (ifx == WIFI_IF_AP && sec < N8_AP_MIN_INACTIVE_SEC)) {
        return ESP_ERR_INVALID_ARG;
    }
    api_set_inactive_t req = { .ifx = ifx, .sec = sec };
    return n8_api_call(api_set_inactive_time, &req);
}

esp_err_t esp_wifi_get_inactive_time(wifi_interface_t ifx, uint16_t *sec)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if ((ifx != WIFI_IF_STA && ifx != WIFI_IF_AP) || sec == NULL) return ESP_ERR_INVALID_ARG;
    *sec = g_n8.inactive_sec[ifx];
    return ESP_OK;
}

esp_err_t esp_wifi_set_sta_rx_probe_req(wifi_sta_rx_probe_req_t cb)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    g_n8.probe_req_cb = cb;
    return ESP_OK;
}

esp_err_t esp_wifi_internal_set_log_level(wifi_log_level_t level)
{
    g_log_level = (uint32_t)level;
    return ESP_OK;
}

esp_err_t esp_wifi_internal_set_log_mod(uint32_t submodule)
{
    g_log_mod = submodule;
    return ESP_OK;
}

esp_err_t esp_wifi_internal_get_log(wifi_log_level_t *log_level, uint32_t *log_mod)
{
    if (log_level != NULL) *log_level = (wifi_log_level_t)g_log_level;
    if (log_mod != NULL) *log_mod = g_log_mod;
    return ESP_OK;
}

wifi_state_t esp_wifi_get_state(void)
{
    if (g_n8.started) {
        return WIFI_STATE_START;
    }
    return g_n8.initialized ? WIFI_STATE_INIT : WIFI_STATE_DEINIT;
}

int64_t esp_wifi_get_tsf_time(wifi_interface_t interface)
{
    if (!g_n8.initialized) {
        return 0;
    }
    if (interface == WIFI_IF_STA) {
        if (g_n8.sta_state != N8_STA_RUN || g_n8.sta_tsf_valid == 0U) {
            return 0;
        }
        return (int64_t)(esp_lmac_get_tsf_us(ESP_LMAC_VIF_STA) + (uint64_t)g_n8.sta_tsf_diff_us);
    }
    if (interface == WIFI_IF_AP) {
        return g_n8.ap_running ? (int64_t)esp_lmac_get_tsf_us(ESP_LMAC_VIF_AP) : 0;
    }
    return 0;
}

static esp_err_t api_set_pm_config(void *arg)
{
    g_n8.pm_cfg = *(const esp_pm_config_t *)arg;
#ifdef CONFIG_PM_ENABLE
    /* Hook point when CONFIG_PM_ENABLE dynamic PM integration is active */
#endif
    return ESP_OK;
}

void esp_wifi_set_pm_config(esp_pm_config_t *pm_config)
{
    if (pm_config == NULL || !g_n8.initialized) {
        return;
    }
    (void)n8_api_call(api_set_pm_config, pm_config);
}

void esp_wifi_get_pm_config(esp_pm_config_t *pm_config)
{
    if (pm_config == NULL) {
        return;
    }
    if (!g_n8.initialized) {
        memset(pm_config, 0, sizeof(*pm_config));
        return;
    }
    *pm_config = g_n8.pm_cfg;
}
