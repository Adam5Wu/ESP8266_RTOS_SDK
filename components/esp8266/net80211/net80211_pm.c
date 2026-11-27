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
// PM=1/PM=0 handshaking, TSF-synced microsecond RF wake scheduling, RF power
// gating via esp_lmac_rf_close/open, and TIM IE checking on AP beacons.
// Pure-STA only; AP/APSTA keeps RF open.

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "net80211_internal.h"

#define TAG "wifi_pm"

extern void ets_timer_arm_us(ETSTimer *ptimer, uint32_t u_seconds, bool repeat_flag);

/* Modem-sleep timing thresholds and beacon-interval scaling */
#define N8_PM_IDLE_ENTER_TICKS      3U          /* 300 ms idle (3 x 100 ms) before entering sleep */
#define N8_PM_WAKE_TIMEOUT_TICKS    2U          /* 200 ms beacon wait in WAKING before falling back */
#define N8_PM_EARLY_WAKE_US         3000U       /* Default 3 ms early wake before expected TBTT */
#define N8_PM_EARLY_MIN_MS          2U          /* Minimum accepted pm_cfg.max_bcn_early_ms */
#define N8_PM_EARLY_MAX_MS          15U         /* Maximum accepted pm_cfg.max_bcn_early_ms */
#define N8_PM_MS_TO_US              1000U       /* Microseconds per millisecond */
#define N8_PM_DEFAULT_BCN_INT_TU    100U        /* Fallback beacon interval (TU) when AP value is 0 */
#define N8_PM_TU_TO_US              1024U       /* IEEE 802.11 Time Unit (TU) duration in microseconds */
#define N8_PM_MAX_SLEEP_MULT        10U         /* Cap sleep span to 10 beacon intervals */
#define N8_PM_MIN_SLEEP_US          1000U       /* Minimum microsecond wake timer floor */
#define N8_PM_MAX_SLEEP_US          0x198A5759U /* Hard ets_timer_arm_us ceiling */
#define N8_PM_CTX_ENTERING_SLEEP    ((void *)1) /* Non-NULL TX-done ctx sentinel for PM=1 sleep */

/* Default esp_pm_config_t parameters (matching ESP8266_RTOS_SDK defaults) */
#define N8_PM_CFG_DEF_BCN_EARLY_MS  4U
#define N8_PM_CFG_DEF_BCN_TMO_MS    24U
#define N8_PM_CFG_DEF_WAIT_TIME_MS  20U
#define N8_PM_CFG_DEF_WAIT_TX_CNT   2U
#define N8_PM_CFG_DEF_WAIT_RX_BCNT  2U
#define N8_PM_CFG_DEF_WAIT_RX_UCNT  4U

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
    /*
     * WIFI_PS_MAX_MODEM sleeps for the configured listen_interval (when > 1);
     * WIFI_PS_MIN_MODEM wakes every DTIM period so group traffic is not missed.
     */
    uint32_t mult = (g_n8.ps_type == WIFI_PS_MAX_MODEM && g_n8.sta_cfg.sta.listen_interval > 1U)
                    ? g_n8.sta_cfg.sta.listen_interval
                    : (g_n8.sta_dtim_period ? g_n8.sta_dtim_period : 1U);
    if (mult > N8_PM_MAX_SLEEP_MULT) {
        mult = N8_PM_MAX_SLEEP_MULT;
    }

    uint64_t period_us = (uint64_t)bi_us * (uint64_t)mult;
    uint32_t early_us = (g_n8.pm_cfg.max_bcn_early_ms >= N8_PM_EARLY_MIN_MS &&
                         g_n8.pm_cfg.max_bcn_early_ms <= N8_PM_EARLY_MAX_MS)
                        ? ((uint32_t)g_n8.pm_cfg.max_bcn_early_ms * N8_PM_MS_TO_US)
                        : N8_PM_EARLY_WAKE_US;

    /*
     * Align wake to the AP's synced TSF modulo period_us so RF opens right before
     * the target TBTT. If the upcoming TBTT is already within the early-wake +
     * minimum-sleep margin, step ahead by one beacon interval to avoid waking late.
     */
    uint64_t sleep_u64 = period_us;
    if (g_n8.sta_tsf_valid != 0U && period_us > 0ULL) {
        uint64_t synced_tsf = esp_lmac_get_tsf_us(ESP_LMAC_VIF_STA) + (uint64_t)g_n8.sta_tsf_diff_us;
        sleep_u64 = period_us - (synced_tsf % period_us);
        if (sleep_u64 <= (uint64_t)early_us + N8_PM_MIN_SLEEP_US) {
            sleep_u64 += (uint64_t)bi_us;
        }
    }

    /* Subtract early-wake lead time and clamp to ets_timer_arm_us() bounds. */
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
 *
 * Computes the TSF-aligned sleep duration via `pm_calc_sleep_interval_us()`,
 * records `g_n8.pm_wake_time_us` as the 100 ms tick fallback deadline, lazily
 * binds `pm_wake_timer_cb`, arms `g_n8.pm_wake_timer`, and closes RF.
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

/* Beacon IE / TIM element layout (IEEE 802.11-2016 §9.4.2.6) */
#define N8_PM_BCN_IE_OFF            (IEEE80211_HDR_LEN + IEEE80211_BCN_FIXED_LEN)
#define N8_PM_TIM_MIN_LEN           4U      /* DTIM Count + Period + Bitmap Ctrl + >=1B PVB */
#define N8_PM_TIM_FIXED_LEN         3U      /* Fixed TIM header bytes preceding PVB */
#define N8_PM_TIM_DTIM_CNT_OFF      2U      /* Offset of DTIM Count from IE start */
#define N8_PM_TIM_DTIM_PER_OFF      3U      /* Offset of DTIM Period from IE start */
#define N8_PM_TIM_BMC_OFF           4U      /* Offset of Bitmap Control from IE start */
#define N8_PM_TIM_PVB_OFF           5U      /* Offset of Partial Virtual Bitmap from IE start */
#define N8_PM_TIM_BMC_MCAST_BIT     0x01U   /* Bitmap Control bit 0: buffered group traffic */
#define N8_PM_TIM_BMC_OFFSET_MASK   0xFEU   /* Bitmap Control bits [7:1]: N1 byte offset (even) */

/*
 * STA Modem Sleep State Machine (pure WIFI_MODE_STA, worker-task serialized):
 *
 *   N8_PM_AWAKE --(idle >= 300 ms, TX idle)--> send Null-Data(PM=1) --> N8_PM_ENTERING_SLEEP
 *   N8_PM_ENTERING_SLEEP --(ACK ok & still idle)--> close RF ---------> N8_PM_SLEEPING
 *   N8_PM_ENTERING_SLEEP --(ACK fail / busy)--------------------------> N8_PM_AWAKE
 *   N8_PM_SLEEPING --(wake timer expired)-----> open RF --------------> N8_PM_WAKING
 *   N8_PM_WAKING --(beacon TIM clear)---------> close RF -------------> N8_PM_SLEEPING
 *   N8_PM_WAKING --(TIM set or 200 ms miss)---> send Null-Data(PM=0) -> N8_PM_AWAKE
 *
 * Any outbound TX, scan, PS disable, or disconnect calls n8_pm_wake_for_tx() /
 * n8_pm_on_disconnect() to open RF immediately and return to N8_PM_AWAKE.
 */

/**
 * @brief LMAC TX-completion callback for modem-sleep Null-Data frames.
 *
 * Executed in the Wi-Fi worker task via LMAC event processing. Only handles
 * PM=1 sleep-entry frames (identified by non-NULL @p ctx); on ACK and if the
 * STA is still eligible for modem sleep, delegates to `pm_enter_sleep()` to
 * arm the TSF-aligned wake timer and power down the RF front-end.
 *
 * @param ctx Non-NULL (N8_PM_CTX_ENTERING_SLEEP) for PM=1 sleep entry, NULL for PM=0 wake.
 * @param st  LMAC transmission completion status.
 */
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

/**
 * @brief Build and submit a STA-to-AP 802.11 Null-Data frame carrying the PM bit.
 *
 * Must be called from the Wi-Fi worker task. Transmits on AC_VO at the lowest
 * basic rate for reliable AP acknowledgement during power-state transitions.
 *
 * @param pm_bit True to set Frame Control PM=1 (sleep), false for PM=0 (awake).
 * @param cb     Optional LMAC TX-done callback, or NULL.
 * @param ctx    Opaque context pointer passed to @p cb.
 */
static void pm_send_nullfunc_ex(bool pm_bit, esp_lmac_tx_done_cb_t cb, void *ctx)
{
    if (g_n8.sta_state != N8_STA_RUN) {
        return;
    }

    uint8_t hdr[IEEE80211_HDR_LEN];
    memset(hdr, 0, sizeof(hdr));
    hdr[0] = IEEE80211_FC_TYPE_DATA | IEEE80211_SUBTYPE_NULLFUNC;
    hdr[1] = IEEE80211_FC1_TODS | (pm_bit ? IEEE80211_FC1_PM : 0U);
    memcpy(hdr + IEEE80211_HDR_ADDR1_OFF, g_n8.sta_bssid, IEEE80211_ADDR_LEN);
    memcpy(hdr + IEEE80211_HDR_ADDR2_OFF, g_n8.sta_mac, IEEE80211_ADDR_LEN);
    memcpy(hdr + IEEE80211_HDR_ADDR3_OFF, g_n8.sta_bssid, IEEE80211_ADDR_LEN);
    uint16_t seq = n8_sta_next_seq();
    hdr[IEEE80211_HDR_SEQ_OFF] = (uint8_t)(seq & 0xFFU);
    hdr[IEEE80211_HDR_SEQ_OFF + 1U] = (uint8_t)(seq >> 8);

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

/**
 * @brief Send a Null-Data frame wired to the internal modem-sleep TX-done callback.
 *
 * Called from the Wi-Fi worker task.
 *
 * @param pm_bit True to announce sleep entry (PM=1), false to announce wake (PM=0).
 */
static void pm_send_nullfunc(bool pm_bit)
{
    pm_send_nullfunc_ex(pm_bit, pm_null_done_cb, pm_bit ? N8_PM_CTX_ENTERING_SLEEP : NULL);
}

/**
 * @brief Send a fire-and-forget Null-Data frame with the requested PM bit.
 *
 * Called from the Wi-Fi worker task (e.g. off-channel scan transitions).
 *
 * @param pm_bit True to set PM=1, false to set PM=0.
 */
void n8_pm_send_nullfunc_now(bool pm_bit)
{
    pm_send_nullfunc_ex(pm_bit, NULL, NULL);
}

/**
 * @brief Send a Null-Data frame with a caller-supplied TX-completion callback.
 *
 * Called from the Wi-Fi worker task (e.g. associated-scan PM=1 handshake).
 *
 * @param pm_bit True to set PM=1, false to set PM=0.
 * @param cb     LMAC TX-done callback invoked in worker-task context.
 * @param ctx    Opaque context pointer forwarded to @p cb.
 */
void n8_pm_send_nullfunc_cb(bool pm_bit, esp_lmac_tx_done_cb_t cb, void *ctx)
{
    pm_send_nullfunc_ex(pm_bit, cb, ctx);
}

/**
 * @brief Reset STA modem-sleep state, wake timer flag, and default `pm_cfg` during Wi-Fi init.
 *
 * Called from initialization / worker-task context. Populates `g_n8.pm_cfg`
 * (`esp_pm_config_t`) with SDK-compatible defaults before any user override.
 */
void n8_pm_init(void)
{
    g_n8.pm_state = N8_PM_AWAKE;
    g_n8.pm_idle_ticks = 0U;
    g_n8.pm_wake_time_us = 0U;
    g_n8.pm_last_bcn_us = 0U;
    g_n8.pm_timer_inited = 0U;
    g_n8.pm_cfg.max_bcn_early_ms = N8_PM_CFG_DEF_BCN_EARLY_MS;
    g_n8.pm_cfg.max_bcn_timeout_ms = N8_PM_CFG_DEF_BCN_TMO_MS;
    g_n8.pm_cfg.wait_time = N8_PM_CFG_DEF_WAIT_TIME_MS;
    g_n8.pm_cfg.wait_tx_cnt = N8_PM_CFG_DEF_WAIT_TX_CNT;
    g_n8.pm_cfg.wait_rx_bdata_cnt = N8_PM_CFG_DEF_WAIT_RX_BCNT;
    g_n8.pm_cfg.wait_rx_udata_cnt = N8_PM_CFG_DEF_WAIT_RX_UCNT;
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

/**
 * @brief Reset modem-sleep state upon STA association/4-way completion.
 *
 * Called from the Wi-Fi worker task when STA enters N8_STA_RUN.
 */
void n8_pm_on_connect(void)
{
    g_n8.pm_state = N8_PM_AWAKE;
    g_n8.pm_idle_ticks = 0U;
    g_n8.pm_last_bcn_us = (uint32_t)esp_timer_get_time();
}

/**
 * @brief Disarm the wake timer, ensure RF is open, and reset modem-sleep state on disconnect.
 *
 * Called from the Wi-Fi worker task.
 */
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

/**
 * @brief Reset the modem-sleep inactivity counter on STA TX/RX traffic.
 *
 * Called from the Wi-Fi worker task.
 */
void n8_pm_on_activity(void)
{
    g_n8.pm_idle_ticks = 0U;
}

/**
 * @brief Disarm the wake timer, wake RF, and exit modem sleep before transmitting or scanning.
 *
 * Called from the Wi-Fi worker task. If the STA was in N8_PM_SLEEPING or
 * N8_PM_WAKING while connected, disarms `g_n8.pm_wake_timer`, opens RF, and
 * sends a Null-Data(PM=0) frame so the AP flushes buffered frames and resumes
 * immediate delivery.
 */
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

/**
 * @brief Update the active Wi-Fi power-save policy.
 *
 * Called from the Wi-Fi worker task via synchronous API RPC. Immediately wakes
 * the STA when switching to WIFI_PS_NONE.
 *
 * @param type Desired power-save mode (WIFI_PS_NONE, WIFI_PS_MIN_MODEM, or WIFI_PS_MAX_MODEM).
 */
void n8_pm_set_ps(wifi_ps_type_t type)
{
    g_n8.ps_type = type;
    if (type == WIFI_PS_NONE) {
        n8_pm_wake_for_tx();
    }
}

/**
 * @brief Process a received beacon from the associated AP for TIM traffic indication.
 *
 * Called from the Wi-Fi worker task. Parses the TIM Information Element (ID 5)
 * to track the AP's DTIM period and determine whether group-addressed (DTIM=0,
 * Bitmap Control bit 0) or unicast (STA AID bit in the Partial Virtual Bitmap)
 * frames are buffered. While in N8_PM_WAKING, either stays awake with PM=0 or
 * immediately returns to TSF-aligned RF sleep via `pm_enter_sleep()`.
 *
 * @param frame Raw 802.11 beacon frame starting at the MAC header.
 * @param len   Total length of @p frame in bytes.
 */
void n8_pm_on_beacon_rx(const uint8_t *frame, uint16_t len)
{
    g_n8.pm_last_bcn_us = (uint32_t)esp_timer_get_time();

    if (len < N8_PM_BCN_IE_OFF) {
        return;
    }

    /* Scan IEs for TIM (ID=5) to track DTIM period and check buffered AID bit */
    const uint8_t *ies = frame + N8_PM_BCN_IE_OFF;
    uint16_t ie_len = (uint16_t)(len - N8_PM_BCN_IE_OFF);
    uint16_t pos = 0U;
    bool tim_for_us = false;

    while (pos + IEEE80211_IE_HDR_LEN <= ie_len) {
        uint8_t id = ies[pos];
        uint8_t elen = ies[pos + 1U];
        if (pos + IEEE80211_IE_HDR_LEN + elen > ie_len) {
            break;
        }
        if (id == IEEE80211_IE_TIM && elen >= N8_PM_TIM_MIN_LEN) {
            uint8_t dtim_cnt = ies[pos + N8_PM_TIM_DTIM_CNT_OFF];
            uint8_t dtim_per = ies[pos + N8_PM_TIM_DTIM_PER_OFF];
            uint8_t bmc = ies[pos + N8_PM_TIM_BMC_OFF];
            if (dtim_per >= 1U) {
                g_n8.sta_dtim_period = dtim_per;
            }
            if (dtim_cnt == 0U && (bmc & N8_PM_TIM_BMC_MCAST_BIT) != 0U) {
                tim_for_us = true;
            }
            /*
             * IEEE 802.11-2016 §9.4.2.6 TIM Partial Virtual Bitmap decoding:
             * Bitmap Control bits [7:1] encode Bitmap Offset, whose byte index
             * into the full Traffic Indication Virtual Bitmap is N1 = 2 * Offset
             * (i.e. bmc & 0xFEU). The PVB covers bytes [N1, N1 + (elen - 3) - 1],
             * where STA AID maps to byte (AID >> 3) and bit (1 << (AID & 7)).
             */
            uint16_t n1 = (uint16_t)(bmc & N8_PM_TIM_BMC_OFFSET_MASK);
            uint16_t byte_idx = g_n8.sta_aid >> 3;
            uint8_t bit_mask = (uint8_t)(1U << (g_n8.sta_aid & 7U));
            if (g_n8.sta_aid > 0U && byte_idx >= n1 &&
                (uint16_t)(byte_idx - n1) < (uint16_t)(elen - N8_PM_TIM_FIXED_LEN)) {
                if ((ies[pos + N8_PM_TIM_PVB_OFF + (byte_idx - n1)] & bit_mask) != 0U) {
                    tim_for_us = true;
                }
            }
            break;
        }
        pos = (uint16_t)(pos + IEEE80211_IE_HDR_LEN + elen);
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

/**
 * @brief Advance the STA modem-sleep state machine on the 100 ms worker tick.
 *
 * Called from the Wi-Fi worker task. Enforces pure-STA / non-scanning / unlocked
 * eligibility, provides a wrap-safe 32-bit fallback wake check if `pm_wake_timer`
 * has not yet fired after `pm_wake_time_us` (disarming the timer and opening RF),
 * times out missed beacons while waking, and initiates Null-Data(PM=1) sleep
 * entry after N8_PM_IDLE_ENTER_TICKS idle ticks.
 */
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
        /* Signed subtraction handles 32-bit microsecond timer wraparound safely. */
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
        if (g_n8.pm_idle_ticks >= N8_PM_WAKE_TIMEOUT_TICKS) {
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
