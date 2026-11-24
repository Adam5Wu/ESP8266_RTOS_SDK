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
// Station Modem Sleep (WIFI_PS_MIN_MODEM / WIFI_PS_MAX_MODEM): Null-Data
// PM=1/PM=0 handshaking, RF power gating via esp_lmac_rf_close/open, and
// TIM IE checking on AP beacons. Pure-STA only; AP/APSTA keeps RF open.

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "net80211_internal.h"

#define TAG "wifi_pm"

extern void ets_timer_arm_us(ETSTimer *ptimer, uint32_t u_seconds, bool repeat_flag);

#define N8_PM_IDLE_ENTER_TICKS  3U          /* 300 ms idle before entering modem sleep */
#define N8_PM_EARLY_WAKE_US     3000U       /* Default 3 ms early wake before expected TBTT */
#define N8_PM_DEFAULT_BCN_INT_TU 100U
#define N8_PM_TU_TO_US          1024U
#define N8_PM_MAX_SLEEP_MULT    10U
#define N8_PM_MIN_SLEEP_US      1000U
#define N8_PM_MAX_SLEEP_US      0x198A5759U /* Hard ets_timer_arm_us ceiling */

/**
 * @brief One-shot worker timer callback waking RF prior to the target AP TBTT.
 *
 * @param arg Unused callback context.
 */
static void pm_wake_timer_cb(void *arg)
{
    (void)arg;
    if (g_n8.pm_state == N8_PM_SLEEPING && g_n8.sta_state == N8_STA_RUN &&
        g_n8.mode == WIFI_MODE_STA && !g_n8.scan_active &&
        g_n8.ps_type != WIFI_PS_NONE && !esp_lmac_ps_is_locked()) {
        esp_lmac_rf_open();
        g_n8.pm_state = N8_PM_WAKING;
        g_n8.pm_idle_ticks = 0U;
    }
}

/**
 * @brief Compute the next TSF-aligned modem-sleep duration in microseconds.
 *
 * Honors WIFI_PS_MAX_MODEM listen_interval or WIFI_PS_MIN_MODEM DTIM period,
 * aligns to synced AP TSF modulo (mult * beacon_interval_us), subtracts the
 * early-wake margin, and clamps within ets_timer_arm_us() bounds.
 *
 * @return Sleep duration in microseconds.
 */
static uint32_t pm_calc_sleep_interval_us(void)
{
    uint32_t bi_us = (uint32_t)(g_n8.sta_beacon_int ? g_n8.sta_beacon_int : N8_PM_DEFAULT_BCN_INT_TU) *
                     N8_PM_TU_TO_US;
    uint32_t mult = (g_n8.ps_type == WIFI_PS_MAX_MODEM && g_n8.sta_cfg.sta.listen_interval > 1U)
                    ? g_n8.sta_cfg.sta.listen_interval
                    : (g_n8.sta_dtim_period ? g_n8.sta_dtim_period : 1U);
    if (mult > N8_PM_MAX_SLEEP_MULT) {
        mult = N8_PM_MAX_SLEEP_MULT;
    }

    uint64_t period_us = (uint64_t)bi_us * (uint64_t)mult;
    uint32_t early_us = (g_n8.pm_cfg.max_bcn_early_ms >= 2U && g_n8.pm_cfg.max_bcn_early_ms <= 15U)
                        ? ((uint32_t)g_n8.pm_cfg.max_bcn_early_ms * 1000U)
                        : N8_PM_EARLY_WAKE_US;

    uint64_t sleep_u64 = period_us;
    if (g_n8.sta_tsf_valid != 0U && period_us > 0ULL) {
        uint64_t synced_tsf = esp_lmac_get_tsf_us(ESP_LMAC_VIF_STA) + (uint64_t)g_n8.sta_tsf_diff_us;
        sleep_u64 = period_us - (synced_tsf % period_us);
        if (sleep_u64 <= (uint64_t)early_us + N8_PM_MIN_SLEEP_US) {
            sleep_u64 += (uint64_t)bi_us;
        }
    }

    if (sleep_u64 > (uint64_t)early_us + N8_PM_MIN_SLEEP_US) {
        sleep_u64 -= early_us;
    } else {
        sleep_u64 = N8_PM_MIN_SLEEP_US;
    }
    if (sleep_u64 > N8_PM_MAX_SLEEP_US) {
        sleep_u64 = N8_PM_MAX_SLEEP_US;
    }
    return (uint32_t)sleep_u64;
}

/**
 * @brief Arm the one-shot microsecond wake timer and power-gate RF for modem sleep.
 */
static void pm_enter_sleep(void)
{
    uint32_t sleep_us = pm_calc_sleep_interval_us();
    g_n8.pm_wake_time_us = (uint32_t)esp_timer_get_time() + sleep_us;
    g_n8.pm_state = N8_PM_SLEEPING;

    if (!g_n8.pm_timer_inited) {
        ets_timer_setfn(&g_n8.pm_wake_timer, pm_wake_timer_cb, NULL);
        g_n8.pm_timer_inited = 1U;
    }
    ets_timer_disarm(&g_n8.pm_wake_timer);
    ets_timer_arm_us(&g_n8.pm_wake_timer, sleep_us, false);
    esp_lmac_rf_close();
}

static void pm_null_done_cb(void *ctx, const esp_lmac_tx_status_t *st)
{
    bool entering = (ctx != NULL);
    if (!entering) {
        return;
    }
    if (g_n8.pm_state != N8_PM_ENTERING_SLEEP) {
        return;
    }
    if (st->ok && g_n8.sta_state == N8_STA_RUN && g_n8.mode == WIFI_MODE_STA &&
        g_n8.ps_type != WIFI_PS_NONE && !esp_lmac_ps_is_locked() && esp_lmac_tx_is_idle()) {
        pm_enter_sleep();
    } else {
        g_n8.pm_state = N8_PM_AWAKE;
    }
}

static void pm_send_nullfunc_ex(bool pm_bit, esp_lmac_tx_done_cb_t cb, void *ctx)
{
    if (g_n8.sta_state != N8_STA_RUN) {
        return;
    }

    uint8_t hdr[24];
    memset(hdr, 0, sizeof(hdr));
    hdr[0] = IEEE80211_FC_TYPE_DATA | IEEE80211_SUBTYPE_NULLFUNC;
    hdr[1] = IEEE80211_FC1_TODS | (pm_bit ? IEEE80211_FC1_PM : 0U);
    memcpy(hdr + 4U, g_n8.sta_bssid, 6U);
    memcpy(hdr + 10U, g_n8.sta_mac, 6U);
    memcpy(hdr + 16U, g_n8.sta_bssid, 6U);
    uint16_t seq = n8_sta_next_seq();
    hdr[22] = (uint8_t)(seq & 0xFFU);
    hdr[23] = (uint8_t)(seq >> 8);

    esp_lmac_tx_req_t req = {0};
    req.vif = ESP_LMAC_VIF_STA;
    req.peer_id = g_n8.sta_peer_id;
    req.ac = ESP_LMAC_AC_VO;
    req.flags = ESP_LMAC_TX_FLAG_FORCE_LOWEST_RATE;
    req.hdr = hdr;
    req.hdr_len = sizeof(hdr);
    req.done_cb = cb;
    req.done_ctx = ctx;
    (void)esp_lmac_tx_submit(&req);
}

static void pm_send_nullfunc(bool pm_bit)
{
    pm_send_nullfunc_ex(pm_bit, pm_null_done_cb, pm_bit ? (void *)1 : NULL);
}

void n8_pm_send_nullfunc_now(bool pm_bit)
{
    pm_send_nullfunc_ex(pm_bit, NULL, NULL);
}

void n8_pm_send_nullfunc_cb(bool pm_bit, esp_lmac_tx_done_cb_t cb, void *ctx)
{
    pm_send_nullfunc_ex(pm_bit, cb, ctx);
}

void n8_pm_init(void)
{
    g_n8.pm_state = N8_PM_AWAKE;
    g_n8.pm_idle_ticks = 0U;
    g_n8.pm_wake_time_us = 0U;
    g_n8.pm_last_bcn_us = 0U;
    g_n8.pm_timer_inited = 0U;
    g_n8.pm_cfg.max_bcn_early_ms = 4U;
    g_n8.pm_cfg.max_bcn_timeout_ms = 24U;
    g_n8.pm_cfg.wait_time = 20U;
    g_n8.pm_cfg.wait_tx_cnt = 2U;
    g_n8.pm_cfg.wait_rx_bdata_cnt = 2U;
    g_n8.pm_cfg.wait_rx_udata_cnt = 4U;
    g_n8.pm_cfg.recv_bdata = true;
}

/**
 * @brief Disarm and release the modem-sleep wake timer during Wi-Fi deinit.
 */
void n8_pm_deinit(void)
{
    if (g_n8.pm_timer_inited != 0U) {
        ets_timer_disarm(&g_n8.pm_wake_timer);
        ets_timer_done(&g_n8.pm_wake_timer);
        g_n8.pm_timer_inited = 0U;
    }
}

void n8_pm_on_connect(void)
{
    g_n8.pm_state = N8_PM_AWAKE;
    g_n8.pm_idle_ticks = 0U;
    g_n8.pm_last_bcn_us = (uint32_t)esp_timer_get_time();
}

void n8_pm_on_disconnect(void)
{
    if (g_n8.pm_timer_inited != 0U) {
        ets_timer_disarm(&g_n8.pm_wake_timer);
    }
    if (esp_lmac_rf_is_closed()) {
        esp_lmac_rf_open();
    }
    g_n8.pm_state = N8_PM_AWAKE;
    g_n8.pm_idle_ticks = 0U;
}

void n8_pm_on_activity(void)
{
    g_n8.pm_idle_ticks = 0U;
}

void n8_pm_wake_for_tx(void)
{
    g_n8.pm_idle_ticks = 0U;
    if (g_n8.pm_state == N8_PM_AWAKE && !esp_lmac_rf_is_closed()) {
        return;
    }
    if (g_n8.pm_timer_inited != 0U) {
        ets_timer_disarm(&g_n8.pm_wake_timer);
    }

    if (esp_lmac_rf_is_closed()) {
        esp_lmac_rf_open();
    }
    bool was_sleeping = (g_n8.pm_state == N8_PM_SLEEPING || g_n8.pm_state == N8_PM_WAKING);
    g_n8.pm_state = N8_PM_AWAKE;
    if (was_sleeping && g_n8.sta_state == N8_STA_RUN) {
        pm_send_nullfunc(false);
    }
}

void n8_pm_set_ps(wifi_ps_type_t type)
{
    g_n8.ps_type = type;
    if (type == WIFI_PS_NONE) {
        n8_pm_wake_for_tx();
    }
}

void n8_pm_on_beacon_rx(const uint8_t *frame, uint16_t len)
{
    g_n8.pm_last_bcn_us = (uint32_t)esp_timer_get_time();

    if (len < 36U) {
        return;
    }

    /* Scan IEs for TIM (ID=5) to track DTIM period and check buffered AID bit */
    const uint8_t *ies = frame + 36U;
    uint16_t ie_len = (uint16_t)(len - 36U);
    uint16_t pos = 0U;
    bool tim_for_us = false;

    while (pos + 2U <= ie_len) {
        uint8_t id = ies[pos];
        uint8_t elen = ies[pos + 1U];
        if (pos + 2U + elen > ie_len) {
            break;
        }
        if (id == IEEE80211_IE_TIM && elen >= 4U) {
            uint8_t dtim_cnt = ies[pos + 2U];
            uint8_t dtim_per = ies[pos + 3U];
            uint8_t bmc = ies[pos + 4U];
            if (dtim_per >= 1U) {
                g_n8.sta_dtim_period = dtim_per;
            }
            if (dtim_cnt == 0U && (bmc & 0x01U) != 0U) {
                tim_for_us = true;
            }
            uint16_t n1 = (uint16_t)(bmc & 0xFEU);
            uint16_t byte_idx = g_n8.sta_aid >> 3;
            uint8_t bit_mask = (uint8_t)(1U << (g_n8.sta_aid & 7U));
            if (g_n8.sta_aid > 0U && byte_idx >= n1 && (uint16_t)(byte_idx - n1) < (uint16_t)(elen - 3U)) {
                if ((ies[pos + 5U + (byte_idx - n1)] & bit_mask) != 0U) {
                    tim_for_us = true;
                }
            }
            break;
        }
        pos = (uint16_t)(pos + 2U + elen);
    }

    if (g_n8.pm_state == N8_PM_WAKING) {
        if (tim_for_us) {
            /* AP has buffered frames for us -> stay awake and notify PM=0 */
            g_n8.pm_state = N8_PM_AWAKE;
            g_n8.pm_idle_ticks = 0U;
            pm_send_nullfunc(false);
        } else if (g_n8.ps_type != WIFI_PS_NONE && g_n8.mode == WIFI_MODE_STA &&
                   !esp_lmac_ps_is_locked() && esp_lmac_tx_is_idle()) {
            /* Nothing buffered -> return to TSF-aligned RF sleep immediately */
            pm_enter_sleep();
        } else {
            g_n8.pm_state = N8_PM_AWAKE;
        }
    }
}

void n8_pm_on_tick_100ms(void)
{
    if (g_n8.sta_state != N8_STA_RUN || g_n8.mode != WIFI_MODE_STA || g_n8.scan_active) {
        if (g_n8.pm_state != N8_PM_AWAKE) {
            n8_pm_wake_for_tx();
        }
        return;
    }

    if (g_n8.ps_type == WIFI_PS_NONE || esp_lmac_ps_is_locked()) {
        if (g_n8.pm_state != N8_PM_AWAKE) {
            n8_pm_wake_for_tx();
        }
        return;
    }

    if (g_n8.pm_state == N8_PM_SLEEPING) {
        int32_t rem = (int32_t)(g_n8.pm_wake_time_us - (uint32_t)esp_timer_get_time());
        if (rem <= 0) {
            if (g_n8.pm_timer_inited != 0U) {
                ets_timer_disarm(&g_n8.pm_wake_timer);
            }
            esp_lmac_rf_open();
            g_n8.pm_state = N8_PM_WAKING;
            g_n8.pm_idle_ticks = 0U;
        }
        return;
    }

    if (g_n8.pm_state == N8_PM_WAKING) {
        g_n8.pm_idle_ticks++;
        if (g_n8.pm_idle_ticks >= 2U) {
            /* Missed beacon while waking -> resume normal awake state */
            g_n8.pm_state = N8_PM_AWAKE;
            g_n8.pm_idle_ticks = 0U;
            pm_send_nullfunc(false);
        }
        return;
    }

    if (g_n8.pm_state == N8_PM_AWAKE && esp_lmac_tx_is_idle()) {
        g_n8.pm_idle_ticks++;
        if (g_n8.pm_idle_ticks >= N8_PM_IDLE_ENTER_TICKS) {
            g_n8.pm_state = N8_PM_ENTERING_SLEEP;
            pm_send_nullfunc(true);
        }
    }
}
