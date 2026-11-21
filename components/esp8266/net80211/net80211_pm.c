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

#define N8_PM_IDLE_ENTER_TICKS  3U    /* 300 ms idle before entering modem sleep */
#define N8_PM_EARLY_WAKE_US     6000U /* Wake RF 6 ms before expected TBTT */

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
        uint32_t bi_us = (uint32_t)(g_n8.sta_beacon_int ? g_n8.sta_beacon_int : 100U) * 1024U;
        uint32_t mult = (g_n8.ps_type == WIFI_PS_MAX_MODEM && g_n8.sta_cfg.sta.listen_interval > 1U)
                        ? g_n8.sta_cfg.sta.listen_interval
                        : (g_n8.sta_dtim_period ? g_n8.sta_dtim_period : 1U);
        if (mult > 10U) {
            mult = 10U;
        }
        uint32_t sleep_us = bi_us * mult;
        if (sleep_us > N8_PM_EARLY_WAKE_US) {
            sleep_us -= N8_PM_EARLY_WAKE_US;
        }
        g_n8.pm_wake_time_us = (uint32_t)esp_timer_get_time() + sleep_us;
        g_n8.pm_state = N8_PM_SLEEPING;
        esp_lmac_rf_close();
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
}

void n8_pm_on_connect(void)
{
    g_n8.pm_state = N8_PM_AWAKE;
    g_n8.pm_idle_ticks = 0U;
    g_n8.pm_last_bcn_us = (uint32_t)esp_timer_get_time();
}

void n8_pm_on_disconnect(void)
{
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
            /* Nothing buffered -> return to RF sleep immediately */
            uint32_t bi_us = (uint32_t)(g_n8.sta_beacon_int ? g_n8.sta_beacon_int : 100U) * 1024U;
            uint32_t sleep_us = (bi_us > N8_PM_EARLY_WAKE_US) ? (bi_us - N8_PM_EARLY_WAKE_US) : bi_us;
            g_n8.pm_wake_time_us = (uint32_t)esp_timer_get_time() + sleep_us;
            g_n8.pm_state = N8_PM_SLEEPING;
            esp_lmac_rf_close();
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
