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
//
// Concurrency model:
//   All state-mutating MLME / LMAC operations marshal synchronously onto the
//   single net80211 worker task via n8_api_call(), which serializes API calls
//   against LMAC RX/TX completions and 100 ms timers without holding coarse
//   mutexes across the MLME (and executes inline if invoked from the worker
//   task itself). Simple getters and atomic flag setters operate directly.

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_phy_init.h"
#include "esp_system.h"
#include "net80211_internal.h"

#define TAG "wifi"

/* --------------------------------------------------------------------------
 * API Validation Bounds, Defaults & Hardware Constants
 * -------------------------------------------------------------------------- */

/** LMAC buffer pool validation minima, A-MPDU bounds, and fallback defaults. */
#define N8_LMAC_MIN_RX_BUFS             4
#define N8_LMAC_DEFAULT_RX_BUFS         16U
#define N8_LMAC_MIN_TX_SLOTS            2
#define N8_LMAC_DEFAULT_TX_SLOTS        6U
#define N8_LMAC_MIN_RX_BUF_LEN          64
#define N8_LMAC_DEFAULT_RX_BUF_LEN      524U
#define N8_LMAC_MAX_RX_BA_WIN           16U
#define N8_LMAC_MIN_AMPDU_BUF_LEN       64U
#define N8_LMAC_MIN_RX_SINGLE_PKT_LEN   256U
#define N8_MAX_SINGLE_PKT_AMPDU         1600U
#define N8_MAX_SINGLE_PKT_NO_AMPDU      (N8_MAX_SINGLE_PKT_AMPDU - N8_LMAC_DEFAULT_RX_BUF_LEN) /* 1076 B extradata clamp when A-MPDU off */

/** SoftAP configuration clamp defaults. */
#define N8_AP_DEFAULT_MAX_CONN          4U
#define N8_AP_MIN_BEACON_INT_TU         100U

/** Miscellaneous API limits, sentinel values & TX power conversion constants. */
#define N8_RSSI_DISCONNECTED            (-127)
#define N8_SCAN_BLOCK_TIMEOUT_MS        15000U
#define N8_RAW_TX_MAX_LEN               1500
#define N8_TX_POWER_QDB_PER_DBM         4

extern esp_err_t esp_now_deinit(void);
extern int wifi_timer_init(void);
extern int misc_nvs_init(void);
extern void misc_nvs_deinit(void);
extern void phy_set_most_tpw(uint8_t max_tpw_qdb);
extern uint8_t phy_get_most_tpw(void);
extern uint32_t g_log_level;
extern uint32_t g_log_mod;
extern void n8_mgmt_free_tx_cb(void *ctx, const esp_lmac_tx_status_t *st);

/**
 * @brief Apply the effective TX power ceiling across Kconfig, regulatory country, and user cap.
 *
 * Computes the minimum of `CONFIG_ESP8266_PHY_MAX_WIFI_TX_POWER` (converted to
 * quarter-dBm), user `g_n8.max_tx_power`, and active regulatory country
 * `max_tx_power` (when positive), clamps the result to
 * `[N8_TX_POWER_MIN_QDBM, N8_TX_POWER_MAX_QDBM]` (2..21 dBm), and programs the
 * PHY ceiling via `phy_set_most_tpw()`.
 */
void n8_apply_tx_power_limit(void)
{
    int32_t limit_qdb = (int32_t)CONFIG_ESP8266_PHY_MAX_WIFI_TX_POWER * N8_TX_POWER_QDB_PER_DBM;
    if ((int32_t)g_n8.max_tx_power < limit_qdb) {
        limit_qdb = (int32_t)g_n8.max_tx_power;
    }
    const wifi_country_t *cc = n8_get_active_country();
    if (cc != NULL && cc->max_tx_power > 0) {
        int32_t cc_qdb = (int32_t)cc->max_tx_power * N8_TX_POWER_QDB_PER_DBM;
        if (cc_qdb < limit_qdb) {
            limit_qdb = cc_qdb;
        }
    }
    if (limit_qdb < N8_TX_POWER_MIN_QDBM) {
        limit_qdb = N8_TX_POWER_MIN_QDBM;
    } else if (limit_qdb > N8_TX_POWER_MAX_QDBM) {
        limit_qdb = N8_TX_POWER_MAX_QDBM;
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

/**
 * @brief LMAC RX callback forwarding received 802.11 frames to the net80211 data/MLME router.
 *
 * @param ctx    Opaque LMAC callback context (unused).
 * @param rx_buf Received frame descriptor owned by LMAC until released by net80211.
 */
static void n8_lmac_on_rx(void *ctx, esp_lmac_rx_buf_t *rx_buf)
{
    (void)ctx;
    n8_data_rx_frame(rx_buf);
}

/**
 * @brief LMAC promiscuous/sniffer callback forwarding captured frames to the sniffer dispatcher.
 *
 * @param ctx   Opaque LMAC callback context (unused).
 * @param ctrl  Hardware RX metadata (RSSI, rate, channel, length).
 * @param frame Raw 802.11 frame bytes.
 * @param len   Frame length in bytes.
 */
static void n8_lmac_on_sniffer(void *ctx, const wifi_pkt_rx_ctrl_t *ctrl,
                               const uint8_t *frame, uint16_t len)
{
    (void)ctx;
    n8_data_sniffer_rx(ctrl, frame, len);
}

/**
 * @brief LMAC TBTT callback forwarding SoftAP beacon-interval ticks to SoftAP TIM maintenance.
 *
 * @param ctx Opaque LMAC callback context (unused).
 * @param vif Virtual interface whose TBTT fired.
 */
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

/**
 * @brief Initialize the Wi-Fi driver, NVS/RTC config, PHY, worker task, and LMAC engine.
 *
 * Loads NVS/RTC defaults, initializes PHY calibration and applies the effective
 * TX power ceiling, validates and clamps A-MPDU RX (`rx_ba_win`,
 * `rx_ampdu_buf_num`, `rx_ampdu_buf_len`) and single-packet RX buffer bounds,
 * starts the net80211 worker task, and initializes `esp_lmac`.
 *
 * @param config Pointer to validated `wifi_init_config_t` (must carry `WIFI_INIT_CONFIG_MAGIC`).
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG on bad config/magic, or worker/LMAC init error.
 */
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
    uint8_t ba_win = ampdu_en ? (uint8_t)((config->rx_ba_win > N8_LMAC_MAX_RX_BA_WIN)
                                          ? N8_LMAC_MAX_RX_BA_WIN : config->rx_ba_win) : 0U;
    uint8_t abuf_num = ampdu_en
                       ? (uint8_t)(config->rx_ampdu_buf_num ? config->rx_ampdu_buf_num : WIFI_AMPDU_RX_AMPDU_BUF_NUM)
                       : 0U;
    uint16_t abuf_len = ampdu_en
                        ? (uint16_t)((config->rx_ampdu_buf_len >= N8_LMAC_MIN_AMPDU_BUF_LEN)
                                     ? config->rx_ampdu_buf_len : WIFI_AMPDU_RX_AMPDU_BUF_LEN)
                        : 0U;
#else
    uint8_t ampdu_en = 0U;
    uint8_t ba_win = 0U;
    uint8_t abuf_num = 0U;
    uint16_t abuf_len = 0U;
#endif
    uint16_t max_single = (config->rx_max_single_pkt_len >= N8_LMAC_MIN_RX_SINGLE_PKT_LEN)
                          ? (uint16_t)config->rx_max_single_pkt_len
                          : N8_MAX_SINGLE_PKT_AMPDU;
    /* Without A-MPDU RX buffers, cap single-packet wrap scratch to the 1076 B extradata headroom */
    if (ampdu_en == 0U && max_single > N8_MAX_SINGLE_PKT_NO_AMPDU) {
        max_single = N8_MAX_SINGLE_PKT_NO_AMPDU;
    }

    g_n8.init_cfg.ampdu_rx_enable = ampdu_en;
    g_n8.init_cfg.rx_ba_win = ba_win;
    g_n8.init_cfg.rx_ampdu_buf_num = abuf_num;
    g_n8.init_cfg.rx_ampdu_buf_len = abuf_len;
    g_n8.init_cfg.rx_max_single_pkt_len = max_single;

    esp_lmac_config_t lcfg = {
        .rx_buf_num = (config->rx_buf_num >= N8_LMAC_MIN_RX_BUFS)
                      ? (uint8_t)config->rx_buf_num : N8_LMAC_DEFAULT_RX_BUFS,
        .left_continuous_rx_buf_num = (uint8_t)config->left_continuous_rx_buf_num,
        .tx_slot_num = (config->tx_buf_num >= N8_LMAC_MIN_TX_SLOTS)
                       ? (uint8_t)config->tx_buf_num : N8_LMAC_DEFAULT_TX_SLOTS,
        .ampdu_rx_enable = ampdu_en,
        .rx_ba_win = ba_win,
        .rx_ampdu_buf_num = abuf_num,
        .rx_ampdu_buf_len = abuf_len,
        .rx_buf_len = (config->rx_buf_len >= N8_LMAC_MIN_RX_BUF_LEN)
                      ? (uint16_t)config->rx_buf_len : N8_LMAC_DEFAULT_RX_BUF_LEN,
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

/**
 * @brief Stop Wi-Fi if running and release all PM, scan, IE, supplicant, LMAC, worker, and NVS state.
 *
 * Disarms and destroys the modem-sleep wake timer (`n8_pm_deinit()`), frees
 * scan results, supplicant App IEs, user vendor IE slots, `scan_done_sem`, and
 * registered WPA2-Enterprise/WPS callback tables, then deinitializes LMAC, the
 * worker task, and misc NVS.
 *
 * @return ESP_OK always.
 */
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

/**
 * @brief Worker-task RPC handler for `esp_wifi_start()`.
 *
 * Opens RF via `esp_lmac_rf_open()` and starts STA and/or SoftAP VIFs according
 * to `g_n8.mode`, rolling back STA if SoftAP startup fails during `WIFI_MODE_APSTA`.
 *
 * @param arg Unused RPC argument.
 * @return ESP_OK on success, or the VIF startup error code.
 */
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

/**
 * @brief Start the Wi-Fi subsystem according to the currently configured operating mode.
 *
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT if uninitialized, or startup error.
 */
esp_err_t esp_wifi_start(void)
{
    if (!g_n8.initialized) {
        return ESP_ERR_WIFI_NOT_INIT;
    }
    return n8_api_call(api_start, NULL);
}

/**
 * @brief Worker-task RPC handler for `esp_wifi_stop()`.
 *
 * Tears down ESP-NOW, active AP/STA VIFs, promiscuous sniffer mode, and scan
 * results, then closes RF via `esp_lmac_rf_close()`.
 *
 * @param arg Unused RPC argument.
 * @return ESP_OK always.
 */
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

/**
 * @brief Stop all active Wi-Fi interfaces and free transient runtime resources.
 *
 * @return ESP_OK on success, or ESP_ERR_WIFI_NOT_INIT if uninitialized.
 */
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

/**
 * @brief Worker-task RPC handler for `esp_wifi_set_mode()`.
 *
 * When Wi-Fi is already started, applies incremental STA/AP/APSTA transitions:
 * tears down outgoing VIFs first (freeing AP slab RAM before any bringup),
 * updates `g_n8.mode`, and starts only newly requested VIFs so the surviving
 * interface in STA<->APSTA or AP<->APSTA transitions remains undisturbed.
 *
 * @param arg Pointer to the requested `wifi_mode_t`.
 * @return ESP_OK on success, or an error code from newly started VIF bringup.
 */
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

        /* Tear down outgoing VIFs before bringing up incoming VIFs */
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

/**
 * @brief Set the Wi-Fi operating mode (NULL, STA, AP, or APSTA).
 *
 * @param mode Desired operating mode.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, ESP_ERR_INVALID_ARG, or VIF error.
 */
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

/**
 * @brief Query the currently configured Wi-Fi operating mode.
 *
 * @param mode Output pointer receiving the active `wifi_mode_t`.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
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
    uint8_t pmk[N8_PMK_LEN];
    bool pmk_computed;
} api_set_cfg_arg_t;

/**
 * @brief Worker-task RPC handler for `esp_wifi_set_config()`.
 *
 * Commits STA or SoftAP configuration (clamping SoftAP max connections, beacon
 * interval, and channel), installs the eagerly derived PMK, persists to NVS,
 * and restarts SoftAP cleanly if it is already running.
 *
 * @param arg Pointer to `api_set_cfg_arg_t` containing the interface, config, and PMK.
 * @return ESP_OK on success, or SoftAP restart error code.
 */
static esp_err_t api_set_config(void *arg)
{
    api_set_cfg_arg_t *a = (api_set_cfg_arg_t *)arg;
    if (a->ifx == WIFI_IF_STA) {
        g_n8.sta_cfg.sta = a->conf->sta;
        if (a->pmk_computed) {
            memcpy(g_n8.sta_pmk, a->pmk, N8_PMK_LEN);
            g_n8.sta_reset_param = 0U;
        } else {
            memset(g_n8.sta_pmk, 0, N8_PMK_LEN);
            g_n8.sta_reset_param = 1U;
        }
        n8_nvs_save_sta_cfg();
    } else {
        g_n8.ap_cfg.ap = a->conf->ap;
        if (g_n8.ap_cfg.ap.max_connection == 0U || g_n8.ap_cfg.ap.max_connection > ESP_WIFI_MAX_CONN_NUM) {
            g_n8.ap_cfg.ap.max_connection = N8_AP_DEFAULT_MAX_CONN;
        }
        if (g_n8.ap_cfg.ap.beacon_interval < N8_AP_MIN_BEACON_INT_TU) {
            g_n8.ap_cfg.ap.beacon_interval = N8_AP_MIN_BEACON_INT_TU;
        }
        if (g_n8.ap_cfg.ap.channel == 0U || g_n8.ap_cfg.ap.channel > N8_CHANNEL_MAX) {
            g_n8.ap_cfg.ap.channel = N8_CHANNEL_MIN;
        }
        if (a->pmk_computed) {
            memcpy(g_n8.ap_pmk, a->pmk, N8_PMK_LEN);
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

/**
 * @brief Configure STA or SoftAP credentials and operational parameters.
 *
 * Performs PBKDF2-SHA1 (or RTC_SYS PMK cache lookup) eagerly in the caller's
 * task context before marshaling the config commit onto the Wi-Fi worker task.
 *
 * @param interface Target interface (`WIFI_IF_STA` or `WIFI_IF_AP`).
 * @param conf      Pointer to STA or SoftAP configuration structure.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, ESP_ERR_INVALID_ARG, or AP restart error.
 */
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
        size_t slen = strnlen((const char *)conf->sta.ssid, N8_MAX_SSID_LEN);
        bool rtc_hit = false;
        n8_derive_pmk_eager(conf->sta.ssid, slen, conf->sta.password, req.pmk, &rtc_hit);
        req.pmk_computed = true;
    } else if (interface == WIFI_IF_AP && conf->ap.authmode != WIFI_AUTH_OPEN &&
               conf->ap.password[0] != 0U) {
        size_t slen = conf->ap.ssid_len
                      ? conf->ap.ssid_len : strnlen((const char *)conf->ap.ssid, N8_MAX_SSID_LEN);
        if (slen > N8_MAX_SSID_LEN) slen = N8_MAX_SSID_LEN;
        n8_derive_pmk_eager(conf->ap.ssid, slen, conf->ap.password, req.pmk, NULL);
        req.pmk_computed = true;
    }

    return n8_api_call(api_set_config, &req);
}

/**
 * @brief Retrieve the current STA or SoftAP configuration.
 *
 * @param interface Target interface (`WIFI_IF_STA` or `WIFI_IF_AP`).
 * @param conf      Output buffer receiving the active configuration.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
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

/**
 * @brief Worker-task RPC handler for `esp_wifi_restore()`.
 *
 * @param arg Unused RPC argument.
 * @return ESP_OK always.
 */
static esp_err_t api_restore(void *arg)
{
    (void)arg;
    n8_nvs_restore();
    return ESP_OK;
}

/**
 * @brief Reset all persistent Wi-Fi settings in NVS and RAM back to factory defaults.
 *
 * @return ESP_OK on success, or ESP_ERR_WIFI_NOT_INIT if uninitialized.
 */
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

/**
 * @brief Worker-task RPC handler for `esp_wifi_connect()`.
 *
 * @param arg Unused RPC argument.
 * @return Result of `n8_sta_connect()`.
 */
static esp_err_t api_connect(void *arg)    { (void)arg; return n8_sta_connect(); }

/**
 * @brief Worker-task RPC handler for `esp_wifi_disconnect()`.
 *
 * @param arg Unused RPC argument.
 * @return ESP_OK always.
 */
static esp_err_t api_disconnect(void *arg) { (void)arg; n8_sta_disconnect(WIFI_REASON_ASSOC_LEAVE, true, true); return ESP_OK; }

/**
 * @brief Connect the STA interface to the configured AP.
 *
 * @return ESP_OK on scan/connect start, ESP_ERR_WIFI_NOT_INIT, or STA connect error.
 */
esp_err_t esp_wifi_connect(void)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    return n8_api_call(api_connect, NULL);
}

/**
 * @brief Disconnect the STA interface from the currently associated AP.
 *
 * @return ESP_OK on success, or ESP_ERR_WIFI_NOT_INIT if uninitialized.
 */
esp_err_t esp_wifi_disconnect(void)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    return n8_api_call(api_disconnect, NULL);
}

/**
 * @brief Clear the RTC_SYS fast-connect cache (cached channel, BSSID, and PMK).
 *
 * @return ESP_OK always.
 */
esp_err_t esp_wifi_clear_fast_connect(void)
{
    n8_rtc_cache_clear();
    return ESP_OK;
}

/**
 * @brief Worker-task RPC handler for `esp_wifi_deauth_sta()`.
 *
 * @param arg Pointer to the target `uint16_t` AID (0 deauthenticates all connected STAs).
 * @return ESP_OK on success, ESP_ERR_WIFI_MODE if AP is stopped, or ESP_ERR_INVALID_ARG.
 */
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

/**
 * @brief Deauthenticate one or all clients connected to the SoftAP.
 *
 * @param aid Client Association ID to kick, or 0 to deauthenticate all clients.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, ESP_ERR_WIFI_MODE, or ESP_ERR_INVALID_ARG.
 */
esp_err_t esp_wifi_deauth_sta(uint16_t aid)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    return n8_api_call(api_deauth_sta, &aid);
}

/**
 * @brief Snapshot the list of currently associated SoftAP clients.
 *
 * @param sta Output structure populated with client MACs and 11b/g/n capability flags.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, ESP_ERR_INVALID_ARG, or ESP_ERR_WIFI_MODE.
 */
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
                memcpy(dst->mac, g_n8.ap_stas[i].mac, IEEE80211_ADDR_LEN);
                dst->phy_11b = g_n8.ap_stas[i].phy_11b;
                dst->phy_11g = g_n8.ap_stas[i].phy_11g;
                dst->phy_11n = g_n8.ap_stas[i].phy_11n;
            }
        }
    }
    return ESP_OK;
}

/**
 * @brief Retrieve information about the AP to which the STA is currently connected.
 *
 * @param ap_info Output record populated with BSSID, SSID, channel, RSSI,
 *                baseband `freq_offset`, security/ciphers, AP-advertised 11b/g/n
 *                and WPS flags, and active regulatory `country`.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, ESP_ERR_INVALID_ARG, or ESP_ERR_WIFI_NOT_CONNECT.
 */
esp_err_t esp_wifi_sta_get_ap_info(wifi_ap_record_t *ap_info)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (ap_info == NULL) return ESP_ERR_INVALID_ARG;
    if (g_n8.sta_state != N8_STA_RUN) return ESP_ERR_WIFI_NOT_CONNECT;

    memset(ap_info, 0, sizeof(*ap_info));
    memcpy(ap_info->bssid, g_n8.sta_bssid, IEEE80211_ADDR_LEN);
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

/**
 * @brief Return the smoothed RSSI (dBm) of the currently associated AP.
 *
 * @return AP RSSI in dBm, or `N8_RSSI_DISCONNECTED` (-127) if uninitialized or disconnected.
 */
int8_t esp_wifi_get_ap_rssi(void)
{
    if (!g_n8.initialized || g_n8.sta_state != N8_STA_RUN) {
        return N8_RSSI_DISCONNECTED;
    }
    return esp_lmac_peer_get_rssi(g_n8.sta_peer_id);
}

/* --------------------------------------------------------------------------
 * Scan APIs
 * -------------------------------------------------------------------------- */

/**
 * @brief Worker-task RPC handler for `esp_wifi_scan_start()`.
 *
 * @param arg Optional pointer to `const wifi_scan_config_t` (may be NULL for defaults).
 * @return Result of `n8_scan_start_internal()`.
 */
static esp_err_t api_scan_start(void *arg)
{
    const wifi_scan_config_t *cfg = (const wifi_scan_config_t *)arg;
    return n8_scan_start_internal(cfg, false, 0U);
}

/**
 * @brief Start a Wi-Fi channel scan, optionally blocking the caller until completion.
 *
 * Guards against self-deadlock by skipping the `scan_done_sem` wait if called
 * from the net80211 worker task itself.
 *
 * @param config Optional scan filter/timing configuration (NULL uses defaults).
 * @param block  If true, wait up to `N8_SCAN_BLOCK_TIMEOUT_MS` for scan completion.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, ESP_ERR_WIFI_NOT_STARTED, or scan error.
 */
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
        (void)xSemaphoreTake(g_n8.scan_done_sem, pdMS_TO_TICKS(N8_SCAN_BLOCK_TIMEOUT_MS));
    }
    return ESP_OK;
}

/**
 * @brief Worker-task RPC handler for `esp_wifi_scan_stop()`.
 *
 * @param arg Unused RPC argument.
 * @return ESP_OK always.
 */
static esp_err_t api_scan_stop(void *arg)
{
    (void)arg;
    n8_scan_stop_internal(false);
    return ESP_OK;
}

/**
 * @brief Abort any currently running Wi-Fi scan.
 *
 * @return ESP_OK on success, or ESP_ERR_WIFI_NOT_INIT if uninitialized.
 */
esp_err_t esp_wifi_scan_stop(void)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    return n8_api_call(api_scan_stop, NULL);
}

/**
 * @brief Return the number of AP records discovered in the most recent scan.
 *
 * @param number Output pointer receiving the cached scan record count.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
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

/**
 * @brief Worker-task RPC handler for `esp_wifi_scan_get_ap_records()`.
 *
 * Copies up to `*a->number` scan entries into the caller's array and frees the
 * internal transient scan result buffer.
 *
 * @param arg Pointer to `api_scan_recs_t`.
 * @return ESP_OK always.
 */
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

/**
 * @brief Copy AP records from the last completed scan and free the driver's scan cache.
 *
 * @param number     In/out pointer: maximum records to copy on entry, actual count on return.
 * @param ap_records Caller-allocated array receiving up to `*number` AP records.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
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

/**
 * @brief Worker-task RPC handler for `esp_wifi_set_ps()`.
 *
 * @param arg Pointer to the requested `wifi_ps_type_t`.
 * @return ESP_OK always.
 */
static esp_err_t api_set_ps(void *arg)
{
    n8_pm_set_ps(*(wifi_ps_type_t *)arg);
    return ESP_OK;
}

/**
 * @brief Configure station modem power-save mode (`NONE`, `MIN_MODEM`, or `MAX_MODEM`).
 *
 * @param type Desired power-save policy.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
esp_err_t esp_wifi_set_ps(wifi_ps_type_t type)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (type > WIFI_PS_MAX_MODEM) return ESP_ERR_INVALID_ARG;
    return n8_api_call(api_set_ps, &type);
}

/**
 * @brief Query the current station power-save mode.
 *
 * @param type Output pointer receiving the active `wifi_ps_type_t`.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
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

/**
 * @brief Worker-task RPC handler for `esp_wifi_set_protocol()`.
 *
 * @param arg Pointer to `api_set_proto_t`.
 * @return ESP_OK always.
 */
static esp_err_t api_set_protocol(void *arg)
{
    const api_set_proto_t *a = (const api_set_proto_t *)arg;
    g_n8.proto[a->ifx] = a->proto;
    esp_lmac_set_protocol_mask((a->ifx == WIFI_IF_AP) ? ESP_LMAC_VIF_AP : ESP_LMAC_VIF_STA,
                               a->proto);
    return ESP_OK;
}

/**
 * @brief Set the enabled 802.11 protocol bitmap (`11B | 11G | 11N`) for an interface.
 *
 * @param ifx             Target interface (`WIFI_IF_STA` or `WIFI_IF_AP`).
 * @param protocol_bitmap Non-zero bitmask of `WIFI_PROTOCOL_*` flags.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, ESP_ERR_WIFI_IF, or ESP_ERR_INVALID_ARG.
 */
esp_err_t esp_wifi_set_protocol(wifi_interface_t ifx, uint8_t protocol_bitmap)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (ifx != WIFI_IF_STA && ifx != WIFI_IF_AP) return ESP_ERR_WIFI_IF;
    if (protocol_bitmap == 0U) return ESP_ERR_INVALID_ARG;
    api_set_proto_t req = { .ifx = ifx, .proto = protocol_bitmap };
    return n8_api_call(api_set_protocol, &req);
}

/**
 * @brief Query the enabled 802.11 protocol bitmap for an interface.
 *
 * @param ifx             Target interface (`WIFI_IF_STA` or `WIFI_IF_AP`).
 * @param protocol_bitmap Output pointer receiving the `WIFI_PROTOCOL_*` bitmask.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
esp_err_t esp_wifi_get_protocol(wifi_interface_t ifx, uint8_t *protocol_bitmap)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if ((ifx != WIFI_IF_STA && ifx != WIFI_IF_AP) || protocol_bitmap == NULL) return ESP_ERR_INVALID_ARG;
    *protocol_bitmap = g_n8.proto[ifx];
    return ESP_OK;
}

/**
 * @brief Set the channel bandwidth for an interface (clamped to HT20 on ESP8266 silicon).
 *
 * @param ifx Target interface (`WIFI_IF_STA` or `WIFI_IF_AP`).
 * @param bw  Requested channel bandwidth (`WIFI_BW_HT40` is downgraded to `WIFI_BW_HT20`).
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
esp_err_t esp_wifi_set_bandwidth(wifi_interface_t ifx, wifi_bandwidth_t bw)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (ifx != WIFI_IF_STA && ifx != WIFI_IF_AP) return ESP_ERR_INVALID_ARG;
    /* ESP8266 silicon supports HT20 only */
    g_n8.bandwidth[ifx] = (bw == WIFI_BW_HT40) ? WIFI_BW_HT20 : (uint8_t)bw;
    return ESP_OK;
}

/**
 * @brief Query the configured channel bandwidth for an interface.
 *
 * @param ifx Target interface (`WIFI_IF_STA` or `WIFI_IF_AP`).
 * @param bw  Output pointer receiving the active `wifi_bandwidth_t`.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
esp_err_t esp_wifi_get_bandwidth(wifi_interface_t ifx, wifi_bandwidth_t *bw)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if ((ifx != WIFI_IF_STA && ifx != WIFI_IF_AP) || bw == NULL) return ESP_ERR_INVALID_ARG;
    *bw = (wifi_bandwidth_t)g_n8.bandwidth[ifx];
    return ESP_OK;
}

/**
 * @brief Worker-task RPC handler for `esp_wifi_set_channel()`.
 *
 * @param arg Pointer to the target primary channel (`uint8_t`, 1..14).
 * @return ESP_OK on success, or LMAC channel-tuning error.
 */
static esp_err_t api_set_channel(void *arg)
{
    uint8_t ch = *(uint8_t *)arg;
    esp_err_t err = esp_lmac_set_channel(ch);
    if (err == ESP_OK) {
        g_n8.cur_channel = ch;
    }
    return err;
}

/**
 * @brief Tune the radio directly to a primary 2.4 GHz channel.
 *
 * @param primary Primary channel number (1..14).
 * @param second  Secondary channel offset (ignored; ESP8266 is HT20-only).
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, ESP_ERR_INVALID_ARG, or LMAC error.
 */
esp_err_t esp_wifi_set_channel(uint8_t primary, wifi_second_chan_t second)
{
    (void)second;
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (primary < N8_CHANNEL_MIN || primary > N8_CHANNEL_MAX) return ESP_ERR_INVALID_ARG;
    return n8_api_call(api_set_channel, &primary);
}

/**
 * @brief Query the current primary radio channel and secondary channel offset.
 *
 * @param primary Optional output pointer receiving the current primary channel.
 * @param second  Optional output pointer (always set to `WIFI_SECOND_CHAN_NONE`).
 * @return ESP_OK on success, or ESP_ERR_WIFI_NOT_INIT if uninitialized.
 */
esp_err_t esp_wifi_get_channel(uint8_t *primary, wifi_second_chan_t *second)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (primary != NULL) *primary = esp_lmac_get_channel();
    if (second != NULL) *second = WIFI_SECOND_CHAN_NONE;
    return ESP_OK;
}

/**
 * @brief Worker-task RPC handler for `esp_wifi_set_country()`.
 *
 * Saves the new country configuration to NVS, re-applies the effective PHY TX
 * power ceiling, and refreshes the SoftAP beacon Country IE if active.
 *
 * @param arg Pointer to validated `wifi_country_t`.
 * @return ESP_OK always.
 */
static esp_err_t api_set_country(void *arg)
{
    const wifi_country_t *country = (const wifi_country_t *)arg;
    g_n8.country = *country;
    n8_nvs_save_country();
    n8_sync_country_power();
    return ESP_OK;
}

/**
 * @brief Configure regulatory country code, channel range, and policy, syncing TX power and NVS.
 *
 * @param country Pointer to validated `wifi_country_t` covering channels within 1..14.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
esp_err_t esp_wifi_set_country(const wifi_country_t *country)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (country == NULL || country->schan < N8_CHANNEL_MIN || country->nchan == 0U ||
        (country->schan + country->nchan) > (N8_CHANNEL_MAX + 1U)) {
        return ESP_ERR_INVALID_ARG;
    }
    return n8_api_call(api_set_country, (void *)(uintptr_t)country);
}

/**
 * @brief Query the currently effective regulatory country parameters.
 *
 * @param country Output structure receiving the active country configuration (manual or AP-adopted).
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
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

/**
 * @brief Worker-task RPC handler for `esp_wifi_set_mac()`.
 *
 * @param arg Pointer to `api_set_mac_t`.
 * @return ESP_OK on success, or ESP_ERR_WIFI_STATE if Wi-Fi is already started.
 */
static esp_err_t api_set_mac(void *arg)
{
    const api_set_mac_t *a = (const api_set_mac_t *)arg;
    if (g_n8.started) {
        return ESP_ERR_WIFI_STATE;
    }
    memcpy((a->ifx == WIFI_IF_STA) ? g_n8.sta_mac : g_n8.ap_mac, a->mac, IEEE80211_ADDR_LEN);
    return ESP_OK;
}

/**
 * @brief Override the unicast MAC address for the STA or SoftAP interface before start.
 *
 * Rejects multicast or all-zero MAC addresses (`ESP_ERR_WIFI_MAC`) and rejects
 * modification while Wi-Fi is started (`ESP_ERR_WIFI_STATE`).
 *
 * @param ifx Target interface (`WIFI_IF_STA` or `WIFI_IF_AP`).
 * @param mac 6-byte unicast MAC address.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, ESP_ERR_WIFI_IF, ESP_ERR_INVALID_ARG,
 *         ESP_ERR_WIFI_MAC, or ESP_ERR_WIFI_STATE.
 */
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

/**
 * @brief Retrieve the MAC address of the STA or SoftAP interface.
 *
 * @param ifx Target interface (`WIFI_IF_STA` or `WIFI_IF_AP`).
 * @param mac 6-byte output buffer receiving the MAC address.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
esp_err_t esp_wifi_get_mac(wifi_interface_t ifx, uint8_t mac[6])
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if ((ifx != WIFI_IF_STA && ifx != WIFI_IF_AP) || mac == NULL) return ESP_ERR_INVALID_ARG;
    memcpy(mac, (ifx == WIFI_IF_AP) ? g_n8.ap_mac : g_n8.sta_mac, IEEE80211_ADDR_LEN);
    return ESP_OK;
}

/**
 * @brief Select whether Wi-Fi configuration updates persist to NVS flash or stay in RAM only.
 *
 * @param storage Storage target (`WIFI_STORAGE_FLASH` or `WIFI_STORAGE_RAM`).
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
esp_err_t esp_wifi_set_storage(wifi_storage_t storage)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (storage != WIFI_STORAGE_FLASH && storage != WIFI_STORAGE_RAM) return ESP_ERR_INVALID_ARG;
    g_n8.storage = storage;
    return ESP_OK;
}

/**
 * @brief Legacy compatibility setter for the STA auto-connect flag.
 *
 * @param en true to enable auto-connect flag, false to disable.
 * @return ESP_OK always.
 */
esp_err_t esp_wifi_set_auto_connect(bool en)
{
    g_n8.auto_connect = en ? 1U : 0U;
    return ESP_OK;
}

/**
 * @brief Legacy compatibility getter for the STA auto-connect flag.
 *
 * @param en Output pointer receiving the auto-connect flag state.
 * @return ESP_OK on success, or ESP_ERR_INVALID_ARG if @p en is NULL.
 */
esp_err_t esp_wifi_get_auto_connect(bool *en)
{
    if (en == NULL) return ESP_ERR_INVALID_ARG;
    *en = (g_n8.auto_connect != 0U);
    return ESP_OK;
}

/* --------------------------------------------------------------------------
 * Promiscuous / Sniffer, Raw TX, Power, Logging & Diagnostics
 * -------------------------------------------------------------------------- */

/**
 * @brief Register the application callback invoked for received promiscuous frames.
 *
 * @param cb Callback function pointer (or NULL to unregister).
 * @return ESP_OK on success, or ESP_ERR_WIFI_NOT_INIT if uninitialized.
 */
esp_err_t esp_wifi_set_promiscuous_rx_cb(wifi_promiscuous_cb_t cb)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    g_n8.promis_cb = cb;
    return ESP_OK;
}

/**
 * @brief Worker-task RPC handler for `esp_wifi_set_promiscuous()`.
 *
 * @param arg Pointer to `bool` enabling or disabling LMAC sniffer capture.
 * @return ESP_OK on success, or LMAC sniffer enable error.
 */
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

/**
 * @brief Enable or disable promiscuous (sniffer) packet capture.
 *
 * @param en true to enable promiscuous mode, false to disable.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or LMAC error.
 */
esp_err_t esp_wifi_set_promiscuous(bool en)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    return n8_api_call(api_set_promis, &en);
}

/**
 * @brief Query whether promiscuous (sniffer) mode is currently enabled.
 *
 * @param en Output pointer receiving the promiscuous state.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
esp_err_t esp_wifi_get_promiscuous(bool *en)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (en == NULL) return ESP_ERR_INVALID_ARG;
    *en = (g_n8.promis_enabled != 0U);
    return ESP_OK;
}

/**
 * @brief Configure the main packet-type filter mask for promiscuous capture.
 *
 * @param filter Pointer to `wifi_promiscuous_filter_t` containing the main filter bitmask.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
esp_err_t esp_wifi_set_promiscuous_filter(const wifi_promiscuous_filter_t *filter)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (filter == NULL) return ESP_ERR_INVALID_ARG;
    uint32_t cf = 0U;
    esp_lmac_sniffer_get_filter(NULL, &cf);
    esp_lmac_sniffer_set_filter(filter->filter_mask, cf);
    return ESP_OK;
}

/**
 * @brief Retrieve the main packet-type filter mask for promiscuous capture.
 *
 * @param filter Output structure receiving the active main filter bitmask.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
esp_err_t esp_wifi_get_promiscuous_filter(wifi_promiscuous_filter_t *filter)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (filter == NULL) return ESP_ERR_INVALID_ARG;
    esp_lmac_sniffer_get_filter(&filter->filter_mask, NULL);
    return ESP_OK;
}

/**
 * @brief Configure the control-frame subtype filter mask for promiscuous capture.
 *
 * @param filter Pointer to `wifi_promiscuous_filter_t` containing the control subtype bitmask.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
esp_err_t esp_wifi_set_promiscuous_ctrl_filter(const wifi_promiscuous_filter_t *filter)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (filter == NULL) return ESP_ERR_INVALID_ARG;
    uint32_t f = 0U;
    esp_lmac_sniffer_get_filter(&f, NULL);
    esp_lmac_sniffer_set_filter(f, filter->filter_mask);
    return ESP_OK;
}

/**
 * @brief Retrieve the control-frame subtype filter mask for promiscuous capture.
 *
 * @param filter Output structure receiving the active control subtype bitmask.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
esp_err_t esp_wifi_get_promiscuous_ctrl_filter(wifi_promiscuous_filter_t *filter)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (filter == NULL) return ESP_ERR_INVALID_ARG;
    esp_lmac_sniffer_get_filter(NULL, &filter->filter_mask);
    return ESP_OK;
}

/**
 * @brief Worker-task RPC handler for `esp_wifi_set_max_tx_power()`.
 *
 * Clamps the requested user power cap to `[N8_TX_POWER_MIN_QDBM, N8_TX_POWER_MAX_QDBM]`
 * and re-applies the combined Kconfig/country/user ceiling via `n8_apply_tx_power_limit()`.
 *
 * @param arg Pointer to requested quarter-dBm `int8_t` power limit.
 * @return ESP_OK always.
 */
static esp_err_t api_set_max_tx_power(void *arg)
{
    int8_t power = *(int8_t *)arg;
    if (power < N8_TX_POWER_MIN_QDBM) power = N8_TX_POWER_MIN_QDBM;
    if (power > N8_TX_POWER_MAX_QDBM) power = N8_TX_POWER_MAX_QDBM;
    g_n8.max_tx_power = power;
    n8_apply_tx_power_limit();
    return ESP_OK;
}

/**
 * @brief Set the maximum Wi-Fi TX power cap in quarter-dBm units (clamped to 8..84, i.e. 2..21 dBm).
 *
 * @param power Requested maximum TX power in 0.25 dBm steps.
 * @return ESP_OK on success, or ESP_ERR_WIFI_NOT_INIT if uninitialized.
 */
esp_err_t esp_wifi_set_max_tx_power(int8_t power)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    return n8_api_call(api_set_max_tx_power, &power);
}

/**
 * @brief Query the current PHY maximum TX power limit in quarter-dBm units.
 *
 * @param power Output pointer receiving the TX power cap in 0.25 dBm steps.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
esp_err_t esp_wifi_get_max_tx_power(int8_t *power)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (power == NULL) return ESP_ERR_INVALID_ARG;
    *power = (int8_t)phy_get_most_tpw();
    return ESP_OK;
}

/**
 * @brief Set the bitmask of Wi-Fi system events to suppress.
 *
 * @param mask Bitmask of `WIFI_EVENT_MASK_*` flags.
 * @return ESP_OK on success, or ESP_ERR_WIFI_NOT_INIT if uninitialized.
 */
esp_err_t esp_wifi_set_event_mask(uint32_t mask)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    g_n8.event_mask = mask;
    return ESP_OK;
}

/**
 * @brief Query the current suppressed Wi-Fi event bitmask.
 *
 * @param mask Output pointer receiving the `WIFI_EVENT_MASK_*` bitmask.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
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

/**
 * @brief Worker-task RPC handler for `esp_wifi_80211_tx()`.
 *
 * Splits the caller's raw 802.11 buffer into its 24-byte MAC header (optionally
 * stamping the VIF's next sequence number) and a heap-copied body freed on LMAC
 * TX completion, then submits on the MGMT queue at the lowest basic rate.
 *
 * @param arg Pointer to `api_80211_tx_t`.
 * @return ESP_OK on LMAC submission, ESP_ERR_NO_MEM on body copy failure, or LMAC error.
 */
static esp_err_t api_80211_tx(void *arg)
{
    api_80211_tx_t *a = (api_80211_tx_t *)arg;
    uint8_t hdr[IEEE80211_HDR_LEN];
    memcpy(hdr, a->buf, IEEE80211_HDR_LEN);
    if (a->en_sys_seq) {
        uint16_t seq = (a->ifx == WIFI_IF_AP) ? n8_ap_next_seq() : n8_sta_next_seq();
        hdr[IEEE80211_HDR_SEQ_OFF] = (uint8_t)(seq & 0xFFU);
        hdr[IEEE80211_HDR_SEQ_OFF + 1U] = (uint8_t)(seq >> 8);
    }

    uint16_t body_len = (uint16_t)(a->len - (int)IEEE80211_HDR_LEN);
    uint8_t *body = NULL;
    esp_lmac_sg_seg_t seg = {0};
    if (body_len > 0U) {
        body = (uint8_t *)heap_caps_malloc(body_len, MALLOC_CAP_8BIT);
        if (body == NULL) return ESP_ERR_NO_MEM;
        memcpy(body, a->buf + IEEE80211_HDR_LEN, body_len);
        seg.ptr = body;
        seg.len = body_len;
    }

    esp_lmac_tx_req_t tx = {0};
    tx.vif = (a->ifx == WIFI_IF_AP) ? ESP_LMAC_VIF_AP : ESP_LMAC_VIF_STA;
    tx.peer_id = ESP_LMAC_PEER_INVALID;
    tx.ac = ESP_LMAC_AC_MGMT;
    tx.flags = ESP_LMAC_TX_FLAG_FORCE_LOWEST_RATE |
               ((hdr[IEEE80211_HDR_ADDR1_OFF] & N8_MAC_MCAST_BIT) ? ESP_LMAC_TX_FLAG_NO_ACK : 0U);
    tx.hdr = hdr;
    tx.hdr_len = IEEE80211_HDR_LEN;
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

/**
 * @brief Inject a raw IEEE 802.11 frame over the specified Wi-Fi interface.
 *
 * @param ifx        Target interface (`WIFI_IF_STA` or `WIFI_IF_AP`).
 * @param buffer     Pointer to raw 802.11 frame bytes (excluding FCS).
 * @param len        Frame length in bytes (`IEEE80211_HDR_LEN`..`N8_RAW_TX_MAX_LEN`).
 * @param en_sys_seq If true, overwrite Sequence Control with the interface's next sequence number.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, ESP_ERR_WIFI_NOT_STARTED, ESP_ERR_INVALID_ARG, or TX error.
 */
esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if (!g_n8.started) return ESP_ERR_WIFI_NOT_STARTED;
    if (buffer == NULL || len < (int)IEEE80211_HDR_LEN || len > N8_RAW_TX_MAX_LEN) return ESP_ERR_INVALID_ARG;
    api_80211_tx_t req = { .ifx = ifx, .buf = (const uint8_t *)buffer, .len = len, .en_sys_seq = en_sys_seq };
    return n8_api_call(api_80211_tx, &req);
}

typedef struct {
    bool                   enable;
    wifi_vendor_ie_type_t  type;
    wifi_vendor_ie_id_t    idx;
    const void            *vnd_ie;
} api_set_vnd_ie_t;

/**
 * @brief Free the lazy `g_n8.vendor_ies` slot table once every slot is empty.
 *
 * Restores zero heap overhead when all user-configured vendor IEs have been
 * removed or if an initial payload allocation failed.
 */
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

/**
 * @brief Worker-task RPC handler for `esp_wifi_set_vendor_ie()`.
 *
 * Lazily allocates `g_n8.vendor_ies` on first insertion, installs/replaces or
 * removes the requested `[type][idx]` vendor IE copy, prunes the table if empty,
 * and rebuilds the live SoftAP beacon template when `WIFI_VND_IE_TYPE_BEACON`
 * changes while SoftAP is running.
 *
 * @param arg Pointer to validated `api_set_vnd_ie_t`.
 * @return ESP_OK on success, or ESP_ERR_NO_MEM on heap exhaustion.
 */
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
            /* Release table if it was just lazily allocated and remains empty */
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

/**
 * @brief Attach or remove a vendor-specific IE on transmitted management frames.
 *
 * Lazily allocates the per-type vendor IE table on first insertion and frees it
 * automatically once all slots are disabled (0 B heap overhead when unused).
 *
 * @param enable True to install/replace the IE, false to remove it.
 * @param type   Management frame type selector.
 * @param idx    Vendor IE slot index.
 * @param vnd_ie Pointer to vendor IE payload (`vendor_ie_data_t`) when enabling.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, ESP_ERR_INVALID_ARG, or ESP_ERR_NO_MEM.
 */
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

/**
 * @brief Worker-task RPC handler for `esp_wifi_set_vendor_ie_cb()`.
 *
 * @param arg Pointer to `api_set_vnd_cb_t` containing the callback and user context.
 * @return ESP_OK always.
 */
static esp_err_t api_set_vendor_ie_cb(void *arg)
{
    const api_set_vnd_cb_t *a = (const api_set_vnd_cb_t *)arg;
    g_n8.vendor_ie_cb = a->cb;
    g_n8.vendor_ie_ctx = a->ctx;
    return ESP_OK;
}

/**
 * @brief Register a callback invoked when vendor-specific IEs are observed in management frames.
 *
 * @param cb  Callback function pointer (or NULL to clear).
 * @param ctx Opaque user context pointer passed to @p cb.
 * @return ESP_OK on success, or ESP_ERR_WIFI_NOT_INIT if uninitialized.
 */
esp_err_t esp_wifi_set_vendor_ie_cb(esp_vendor_ie_cb_t cb, void *ctx)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    api_set_vnd_cb_t req = { .cb = cb, .ctx = ctx };
    return n8_api_call(api_set_vendor_ie_cb, &req);
}

/**
 * @brief Worker-task RPC handler for `esp_wifi_set_rssi_threshold()`.
 *
 * Updates `g_n8.rssi_threshold` and re-arms one-shot `SYSTEM_EVENT_STA_BSS_RSSI_LOW`
 * delivery on subsequent AP beacons below the threshold.
 *
 * @param arg Pointer to validated `int32_t` RSSI threshold in dBm.
 * @return ESP_OK always.
 */
static esp_err_t api_set_rssi_thresh(void *arg)
{
    g_n8.rssi_threshold = *(int32_t *)arg;
    g_n8.rssi_thresh_armed = 1U;
    return ESP_OK;
}

/**
 * @brief Set and arm the one-shot low-RSSI threshold (dBm) for `SYSTEM_EVENT_STA_BSS_RSSI_LOW`.
 *
 * @param rssi RSSI threshold in dBm (`N8_RSSI_THRESHOLD_MIN`..`N8_RSSI_THRESHOLD_MAX`, i.e. -100..0).
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG if out of range.
 */
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

/**
 * @brief Worker-task RPC handler for `esp_wifi_set_inactive_time()`.
 *
 * @param arg Pointer to `api_set_inactive_t` containing interface and validated timeout.
 * @return ESP_OK on success, or ESP_ERR_WIFI_NOT_STARTED if Wi-Fi is stopped.
 */
static esp_err_t api_set_inactive_time(void *arg)
{
    const api_set_inactive_t *a = (const api_set_inactive_t *)arg;
    if (!g_n8.started) {
        return ESP_ERR_WIFI_NOT_STARTED;
    }
    g_n8.inactive_sec[a->ifx] = a->sec;
    return ESP_OK;
}

/**
 * @brief Set the inactivity timeout (seconds) for STA beacon loss or SoftAP client aging.
 *
 * Enforces minimum thresholds of `N8_STA_MIN_INACTIVE_SEC` (3 s) for STA and
 * `N8_AP_MIN_INACTIVE_SEC` (10 s) for SoftAP, and requires Wi-Fi to be started.
 *
 * @param ifx Target interface (`WIFI_IF_STA` or `WIFI_IF_AP`).
 * @param sec Timeout duration in seconds.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, ESP_ERR_WIFI_NOT_STARTED, or ESP_ERR_INVALID_ARG.
 */
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

/**
 * @brief Query the inactivity timeout (seconds) for STA or SoftAP.
 *
 * @param ifx Target interface (`WIFI_IF_STA` or `WIFI_IF_AP`).
 * @param sec Output pointer receiving the timeout duration in seconds.
 * @return ESP_OK on success, ESP_ERR_WIFI_NOT_INIT, or ESP_ERR_INVALID_ARG.
 */
esp_err_t esp_wifi_get_inactive_time(wifi_interface_t ifx, uint16_t *sec)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    if ((ifx != WIFI_IF_STA && ifx != WIFI_IF_AP) || sec == NULL) return ESP_ERR_INVALID_ARG;
    *sec = g_n8.inactive_sec[ifx];
    return ESP_OK;
}

/**
 * @brief Register a callback for Probe Request frames received in STA mode.
 *
 * @param cb Callback function pointer (or NULL to clear).
 * @return ESP_OK on success, or ESP_ERR_WIFI_NOT_INIT if uninitialized.
 */
esp_err_t esp_wifi_set_sta_rx_probe_req(wifi_sta_rx_probe_req_t cb)
{
    if (!g_n8.initialized) return ESP_ERR_WIFI_NOT_INIT;
    g_n8.probe_req_cb = cb;
    return ESP_OK;
}

/**
 * @brief Legacy internal API setting the Wi-Fi driver log verbosity level.
 *
 * @param level Desired `wifi_log_level_t` value stored into `g_log_level`.
 * @return ESP_OK always.
 */
esp_err_t esp_wifi_internal_set_log_level(wifi_log_level_t level)
{
    g_log_level = (uint32_t)level;
    return ESP_OK;
}

/**
 * @brief Legacy internal API setting the Wi-Fi driver log submodule bitmask.
 *
 * @param submodule Submodule filter mask stored into `g_log_mod`.
 * @return ESP_OK always.
 */
esp_err_t esp_wifi_internal_set_log_mod(uint32_t submodule)
{
    g_log_mod = submodule;
    return ESP_OK;
}

/**
 * @brief Legacy internal API querying the current Wi-Fi log level and submodule mask.
 *
 * @param log_level Optional output pointer receiving `g_log_level`.
 * @param log_mod   Optional output pointer receiving `g_log_mod`.
 * @return ESP_OK always.
 */
esp_err_t esp_wifi_internal_get_log(wifi_log_level_t *log_level, uint32_t *log_mod)
{
    if (log_level != NULL) *log_level = (wifi_log_level_t)g_log_level;
    if (log_mod != NULL) *log_mod = g_log_mod;
    return ESP_OK;
}

/**
 * @brief Return the coarse Wi-Fi driver lifecycle state (`DEINIT`, `INIT`, or `START`).
 *
 * @return Current `wifi_state_t`.
 */
wifi_state_t esp_wifi_get_state(void)
{
    if (g_n8.started) {
        return WIFI_STATE_START;
    }
    return g_n8.initialized ? WIFI_STATE_INIT : WIFI_STATE_DEINIT;
}

/**
 * @brief Read the synchronized 64-bit TSF microsecond timer for the requested Wi-Fi interface.
 *
 * For `WIFI_IF_STA`, returns the local LMAC TSF adjusted by the beacon-synced
 * offset (`sta_tsf_diff_us`) once associated in `N8_STA_RUN` with a valid TSF
 * sample. For `WIFI_IF_AP`, returns the SoftAP LMAC TSF while SoftAP is running.
 *
 * @param interface Target interface (`WIFI_IF_STA` or `WIFI_IF_AP`).
 * @return TSF timestamp in microseconds, or 0 if uninitialized, disconnected/stopped, or invalid.
 */
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

/**
 * @brief Worker-task RPC handler for `esp_wifi_set_pm_config()`.
 *
 * Stores the caller's `esp_pm_config_t` into `g_n8.pm_cfg` for modem-sleep
 * wake timing parameters (such as `max_bcn_early_ms`).
 *
 * @param arg Pointer to `const esp_pm_config_t`.
 * @return ESP_OK always.
 */
static esp_err_t api_set_pm_config(void *arg)
{
    g_n8.pm_cfg = *(const esp_pm_config_t *)arg;
#ifdef CONFIG_PM_ENABLE
    /* Hook point when CONFIG_PM_ENABLE dynamic PM integration is active */
#endif
    return ESP_OK;
}

/**
 * @brief Apply Wi-Fi modem-sleep power management tuning parameters.
 *
 * Marshals @p pm_config onto the net80211 worker task and stores it in
 * `g_n8.pm_cfg`. No-op if @p pm_config is NULL or Wi-Fi is uninitialized.
 *
 * @param pm_config Pointer to `esp_pm_config_t` containing PM timing parameters.
 */
void esp_wifi_set_pm_config(esp_pm_config_t *pm_config)
{
    if (pm_config == NULL || !g_n8.initialized) {
        return;
    }
    (void)n8_api_call(api_set_pm_config, pm_config);
}

/**
 * @brief Retrieve the active Wi-Fi modem-sleep power management configuration.
 *
 * Copies `g_n8.pm_cfg` into @p pm_config when initialized, or zeroes the struct
 * if Wi-Fi is not yet initialized. No-op when @p pm_config is NULL.
 *
 * @param pm_config Output pointer receiving the current `esp_pm_config_t`.
 */
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
