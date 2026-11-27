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
// LMAC lifecycle, bounded cooperative event pump, channel/PHY interface,
// RF open/close sleep gating, housekeeping, and external SDK compatibility
// exports (.flash.text).

#include <string.h>

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_private/wifi.h"
#include "lmac_internal.h"

#define TAG "lmac"

/* Default and minimum LMAC ring/pool configuration bounds */
#define LMAC_CFG_MIN_RX_BUF_NUM          4U    /* Minimum circular RX descriptors */
#define LMAC_CFG_DEFAULT_RX_BUF_NUM      16U   /* Default circular RX descriptors */
#define LMAC_CFG_DEFAULT_RX_BUF_LEN      524U  /* Default bytes per RX descriptor slot */
#define LMAC_CFG_DEFAULT_RX_MAX_PKT_LEN  1600U /* Default extradata wrap-around scratch bytes (AMPDU_RX=y) */
#define LMAC_CFG_NO_AMPDU_RX_MAX_PKT_LEN 1076U /* Clamped extradata scratch bytes when AMPDU_RX=n */
#define LMAC_CFG_MIN_TX_SLOT_NUM         2U    /* Minimum TX slot pool depth */
#define LMAC_CFG_DEFAULT_TX_SLOT_NUM     6U    /* Default TX slot pool depth */
#if CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
#define LMAC_CFG_MAX_RX_BA_WIN           16U   /* Maximum hardware RX BA reorder window */
#define LMAC_CFG_DEFAULT_AMPDU_BUF_NUM   5U    /* Default A-MPDU subframe info ring depth */
#define LMAC_CFG_MIN_AMPDU_BUF_LEN       64U   /* Minimum bytes per A-MPDU info buffer */
#define LMAC_CFG_DEFAULT_AMPDU_BUF_LEN   256U  /* Default bytes per A-MPDU info buffer */
#endif

/* Cooperative event pump extra step budget for control events (TBTT / TX timeout) */
#define LMAC_EVENT_PUMP_CTRL_BUDGET     4U

/* Periodic 100 ms housekeeping intervals */
#define LMAC_HK_TICKS_PER_SEC           10U   /* 10 * 100 ms = 1 second */
#define LMAC_HK_NOISE_CHECK_TICKS       30U   /* 30 * 100 ms = 3 seconds */
#define LMAC_HK_RX_HANG_THRESHOLD_SEC   5U    /* Stalled RX watchdog reset threshold (s) */

/* 2.4 GHz ISM band channel numbering & center-frequency conversion */
#define LMAC_CHAN_MIN                   1U
#define LMAC_CHAN_MAX_2G_STD            13U
#define LMAC_CHAN_JAPAN_14              14U
#define LMAC_CHAN_2G_BASE_MHZ           2407U /* f(ch) = 2407 + 5 * ch MHz for ch 1..13 */
#define LMAC_CHAN_2G_STEP_MHZ           5U
#define LMAC_CHAN_14_FREQ_MHZ           2484U /* Japan-only CCK channel 14 center freq */

/* 64-bit TSF upper-word shift and Wi-Fi power-save lock bit */
#define LMAC_TSF_HI_SHIFT               32U
#define LMAC_PS_LOCK_WIFI_BIT           1U

/* Single zero-initialized global LMAC context (explicitly initialized — 0 SHN_COMMON) */
lmac_ctx_t g_lmac = {0};

/* --------------------------------------------------------------------------
 * Lifecycle: esp_lmac_init / esp_lmac_deinit
 * -------------------------------------------------------------------------- */

/**
 * @brief Initialize the LMAC driver, DMA rings, TX pool, TRC state, and WDEV hardware.
 *
 * Preserves boot-time power-save lock flags and RX pbuf memory type across
 * re-initialization. Clamps or defaults unspecified ring sizes and A-MPDU RX settings
 * (`rx_ba_win` <= 16, `rx_ampdu_buf_num` default 5, `rx_ampdu_buf_len` >= 64 / default
 * 256, zeroed when A-MPDU RX is disabled; `rx_max_single_pkt_len` defaults to 1600 B
 * with A-MPDU RX enabled or clamps to 1076 B when disabled), enables AGC, and tunes to
 * channel 1. Calling when already initialized is a safe no-op returning ESP_OK.
 *
 * @param cfg  Non-NULL LMAC buffer/slot configuration (copied into internal state).
 * @param cbs  Non-NULL upper-layer callback table (copied into internal state).
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG if @p cfg or @p cbs is NULL, or the
 *         underlying error code if DMA or TX initialization fails.
 */
esp_err_t esp_lmac_init(const esp_lmac_config_t *cfg, const esp_lmac_callbacks_t *cbs)
{
    if (cfg == NULL || cbs == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (g_lmac.initialized) {
        return ESP_OK;
    }

    /* Preserve ps_lock_flags and rx_pbuf_mem_type across re-init */
    uint32_t saved_ps_lock = g_lmac.ps_lock_flags;
    uint8_t saved_pbuf_type = g_lmac.rx_pbuf_mem_type;

    memset(&g_lmac, 0, sizeof(g_lmac));
    g_lmac.ps_lock_flags = saved_ps_lock;
    g_lmac.rx_pbuf_mem_type = saved_pbuf_type;

    g_lmac.cfg = *cfg;
    if (g_lmac.cfg.rx_buf_num < LMAC_CFG_MIN_RX_BUF_NUM) {
        g_lmac.cfg.rx_buf_num = LMAC_CFG_DEFAULT_RX_BUF_NUM;
    } else if (g_lmac.cfg.rx_buf_num > LMAC_MAX_RX_BUFS) {
        g_lmac.cfg.rx_buf_num = LMAC_MAX_RX_BUFS;
    }
    if (g_lmac.cfg.rx_buf_len == 0U) {
        g_lmac.cfg.rx_buf_len = LMAC_CFG_DEFAULT_RX_BUF_LEN;
    }
#if !CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
    g_lmac.cfg.ampdu_rx_enable = 0U;
    g_lmac.cfg.rx_ba_win = 0U;
    g_lmac.cfg.rx_ampdu_buf_num = 0U;
    g_lmac.cfg.rx_ampdu_buf_len = 0U;
#else
    if (g_lmac.cfg.ampdu_rx_enable != 0U) {
        if (g_lmac.cfg.rx_ba_win > LMAC_CFG_MAX_RX_BA_WIN) {
            g_lmac.cfg.rx_ba_win = LMAC_CFG_MAX_RX_BA_WIN;
        }
        if (g_lmac.cfg.rx_ampdu_buf_num == 0U) {
            g_lmac.cfg.rx_ampdu_buf_num = LMAC_CFG_DEFAULT_AMPDU_BUF_NUM;
        }
        if (g_lmac.cfg.rx_ampdu_buf_len < LMAC_CFG_MIN_AMPDU_BUF_LEN) {
            g_lmac.cfg.rx_ampdu_buf_len = LMAC_CFG_DEFAULT_AMPDU_BUF_LEN;
        }
    } else {
        g_lmac.cfg.rx_ba_win = 0U;
        g_lmac.cfg.rx_ampdu_buf_num = 0U;
        g_lmac.cfg.rx_ampdu_buf_len = 0U;
    }
#endif
    if (g_lmac.cfg.rx_max_single_pkt_len == 0U) {
        g_lmac.cfg.rx_max_single_pkt_len = g_lmac.cfg.ampdu_rx_enable
                                           ? LMAC_CFG_DEFAULT_RX_MAX_PKT_LEN
                                           : LMAC_CFG_NO_AMPDU_RX_MAX_PKT_LEN;
    } else if (g_lmac.cfg.ampdu_rx_enable == 0U &&
               g_lmac.cfg.rx_max_single_pkt_len > LMAC_CFG_NO_AMPDU_RX_MAX_PKT_LEN) {
        g_lmac.cfg.rx_max_single_pkt_len = LMAC_CFG_NO_AMPDU_RX_MAX_PKT_LEN;
    }
    if (g_lmac.cfg.tx_slot_num < LMAC_CFG_MIN_TX_SLOT_NUM) {
        g_lmac.cfg.tx_slot_num = LMAC_CFG_DEFAULT_TX_SLOT_NUM;
    }

    g_lmac.cbs = *cbs;
    g_lmac.cur_channel = LMAC_CHAN_MIN;
    g_lmac.sniffer_filter = WIFI_PROMIS_FILTER_MASK_ALL;

    esp_err_t err = lmac_dma_init();
    if (err != ESP_OK) {
        return err;
    }

    err = lmac_tx_init();
    if (err != ESP_OK) {
        lmac_dma_deinit();
        return err;
    }

    lmac_trc_init();

    /* Ensure RF & PHY are active before touching WDEV hardware registers */
    g_lmac.rf_closed = 0U;
    lmac_wdev_hw_init();
    phy_enable_agc();
    esp_lmac_set_channel(LMAC_CHAN_MIN);

    g_lmac.initialized = true;
    return ESP_OK;
}

/**
 * @brief Tear down the LMAC driver, wake RF, disable WDEV MAC/interrupts, and free dynamic pools.
 *
 * Disables sniffer mode, calls esp_lmac_rf_open() so RF/PHY clocks are active before
 * touching WDEV hardware registers, disables both VIFs, masks all WDEV interrupts except
 * `LMAC_INT_MACTIM0` (retained for system task_wdt), and releases the SoftAP peer pool,
 * TX slot pool, and RX DMA arena (including `snf_ring`). Safe to call when already deinitialized.
 *
 * @return ESP_OK always.
 */
esp_err_t esp_lmac_deinit(void)
{
    if (!g_lmac.initialized) {
        return ESP_OK;
    }

    if (g_lmac.sniffer_mode != 0U) {
        esp_lmac_sniffer_disable();
    }

    esp_lmac_rf_open();
    esp_lmac_vif_disable(ESP_LMAC_VIF_STA);
    esp_lmac_vif_disable(ESP_LMAC_VIF_AP);

    vPortETSIntrLock();
    lmac_reg_clr(LMAC_WDEV_MAC_ENABLE, LMAC_WDEV_MAC_ENABLE_BIT);
    lmac_reg_write(LMAC_WDEV_INT_ENA, LMAC_INT_MACTIM0);
    vPortETSIntrUnlock();

    esp_lmac_peer_free_ap_pool();
    lmac_tx_deinit();
    lmac_dma_deinit();

    g_lmac.initialized = false;
    return ESP_OK;
}

/* --------------------------------------------------------------------------
 * Bounded Cooperative Event Pump (Drains NMI Ring on Wi-Fi Worker)
 * -------------------------------------------------------------------------- */

/**
 * @brief Drain pending NMI-produced RX, sniffer, TX-completion, timeout, and TBTT events cooperatively.
 *
 * Executes on the Wi-Fi worker task, bounding work per invocation so higher-level timers
 * and management commands are not starved during traffic bursts. Dispatches both single-MPDU
 * (`LMAC_NMI_EVT_RX_DESC`) and A-MPDU subframe (`LMAC_NMI_EVT_RX_AMPDU`) RX events from
 * `nmi_ring`, as well as NMI-captured `LMAC_INT_SNIFFER_END` packets from `snf_ring` (each
 * ring bounded by @p max_rx_batch).
 *
 * @param max_rx_batch  Maximum RX events to dispatch per ring in this call (`0` = unbounded
 *                      within `max_total` for `nmi_ring`, unbounded for `snf_ring`).
 * @param max_tx_batch  Maximum TX completion events to drain in this call (`0` = unbounded).
 * @return `true` if additional NMI events (`nmi_rd != nmi_wr`), sniffer packets
 *         (`snf_rd != snf_wr`), or completed TX slots (`tx_done_head != NULL`) remain
 *         pending and the caller should re-schedule another pump pass; `false` if all
 *         queues are drained (or LMAC is not initialized).
 */
bool esp_lmac_process_events(uint8_t max_rx_batch, uint8_t max_tx_batch)
{
    if (!g_lmac.initialized) {
        return false;
    }

    uint8_t rx_done = 0U;
    uint8_t tx_done = 0U;
    uint8_t total_steps = 0U;
    const uint8_t max_total = (uint8_t)(max_rx_batch + max_tx_batch + LMAC_EVENT_PUMP_CTRL_BUDGET);

#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
    tx_done = lmac_tx_drain_done(max_tx_batch);
#endif

    while (g_lmac.nmi_rd != g_lmac.nmi_wr) {
        uint8_t rd = g_lmac.nmi_rd;
        lmac_nmi_evt_t ev = g_lmac.nmi_ring[rd];

        if ((ev.type == LMAC_NMI_EVT_RX_DESC
#if CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
             || ev.type == LMAC_NMI_EVT_RX_AMPDU
#endif
             ) && max_rx_batch > 0U && rx_done >= max_rx_batch) {
            return true;
        }
#ifdef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
        if (ev.type == LMAC_NMI_EVT_TX_DONE && max_tx_batch > 0U && tx_done >= max_tx_batch) {
            return true;
        }
#endif

        /* Ensure event struct copy completes before releasing ring slot to NMI producer */
        __asm__ volatile("" ::: "memory");
        g_lmac.nmi_rd = (uint8_t)((rd + 1U) & LMAC_NMI_RING_MASK);

        switch (ev.type) {
        case LMAC_NMI_EVT_RX_DESC:
#if CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
        case LMAC_NMI_EVT_RX_AMPDU:
#endif
            lmac_dma_dispatch_rx_evt(&ev);
            rx_done++;
            break;

#ifdef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
        case LMAC_NMI_EVT_TX_DONE:
            lmac_tx_on_done_evt(&ev);
            tx_done++;
            break;
#endif

        case LMAC_NMI_EVT_TX_TIMEOUT:
            lmac_tx_on_timeout_evt();
            break;

        case LMAC_NMI_EVT_TBTT:
            lmac_beacon_on_tbtt_evt();
            break;

        default:
            break;
        }

        total_steps++;
        if (total_steps >= max_total) {
            break;
        }
    }

    /* Drain NMI-captured LMAC_INT_SNIFFER_END frames from the separate snf_ring */
    uint8_t snf_done = 0U;
    while (g_lmac.snf_rd != g_lmac.snf_wr) {
        if (g_lmac.snf_ring == NULL) {
            g_lmac.snf_rd = g_lmac.snf_wr;
            break;
        }
        uint8_t rd = g_lmac.snf_rd;
        lmac_snf_pkt_t pkt = g_lmac.snf_ring[rd];
        /* Ensure 128-B local copy completes before releasing ring slot back to NMI producer */
        __asm__ volatile("memw" ::: "memory");
        g_lmac.snf_rd = (uint8_t)((rd + 1U) & LMAC_SNF_RING_MASK);

        lmac_dma_dispatch_sniffer_pkt(&pkt);
        snf_done++;
        if (max_rx_batch > 0U && snf_done >= max_rx_batch) {
            break;
        }
    }

#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
    if (max_tx_batch == 0U || tx_done < max_tx_batch) {
        uint8_t rem = (max_tx_batch > 0U) ? (uint8_t)(max_tx_batch - tx_done) : 0U;
        tx_done = (uint8_t)(tx_done + lmac_tx_drain_done(rem));
    }
    return (g_lmac.nmi_rd != g_lmac.nmi_wr) ||
           (g_lmac.snf_rd != g_lmac.snf_wr) ||
           (g_lmac.tx_done_head != NULL);
#else
    return (g_lmac.nmi_rd != g_lmac.nmi_wr) || (g_lmac.snf_rd != g_lmac.snf_wr);
#endif
}

/* --------------------------------------------------------------------------
 * 100 ms Periodic Housekeeping (Noise Floor, TX Power Tracking, Hang Watchdog)
 * -------------------------------------------------------------------------- */

/**
 * @brief Run periodic 100 ms LMAC maintenance on the Wi-Fi worker task.
 *
 * Performs:
 *   - Every 100 ms: drains any pending NMI-completed TX slots (fast-NMI mode) and runs
 *     lmac_tx_check_hang() to detect stalled TX queues.
 *   - Every 1 s (while RF is open): runs background TX power control, triggers PHY
 *     noise-floor tracking every 3 s (or immediately when `pend_noise_check` is set),
 *     and monitors `LMAC_WDEV_RX_END_CNT` alongside `rx_avail_mask` to reset the MAC if
 *     RX DMA remains exhausted and wedged for 5 consecutive seconds.
 */
void esp_lmac_housekeeping_100ms(void)
{
    if (!g_lmac.initialized) {
        return;
    }

    g_lmac.hk_tick_cnt++;

#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
    /* Safety net: drain any NMI-completed TX slots before hang checks */
    (void)lmac_tx_drain_done(0U);
#endif

    /* Check for stalled TX queues every 100 ms */
    lmac_tx_check_hang();

    /* Every 1 second: PHY noise-floor & background TX power tracking when RF is open */
    if ((g_lmac.hk_tick_cnt % LMAC_HK_TICKS_PER_SEC) == 0U && !g_lmac.rf_closed) {
        if (g_lmac.pend_noise_check != 0U || (g_lmac.hk_tick_cnt % LMAC_HK_NOISE_CHECK_TICKS) == 0U) {
            g_lmac.pend_noise_check = 0U;
            uint8_t ch_idx = (g_lmac.cur_channel >= LMAC_CHAN_MIN)
                             ? (uint8_t)(g_lmac.cur_channel - LMAC_CHAN_MIN)
                             : 0U;
            noise_check_loop(ch_idx, 1U);
        }
        tx_pwctrl_background(1U, 0U);
    }

    /* RX hang watchdog every 1 second when MAC is active and RF is awake */
    if ((g_lmac.hk_tick_cnt % LMAC_HK_TICKS_PER_SEC) == 0U && !g_lmac.rf_closed &&
        (g_lmac.vif[ESP_LMAC_VIF_STA].enabled || g_lmac.vif[ESP_LMAC_VIF_AP].enabled)) {
        uint32_t rx_end = lmac_reg_read(LMAC_WDEV_RX_END_CNT);
        if (rx_end == g_lmac.last_rx_end_cnt && g_lmac.rx_avail_mask == 0U) {
            g_lmac.rx_hang_ticks++;
            if (g_lmac.rx_hang_ticks >= LMAC_HK_RX_HANG_THRESHOLD_SEC) {
                g_lmac.rx_hang_ticks = 0U;
                esp_lmac_hw_mac_reset();
            }
        } else {
            g_lmac.last_rx_end_cnt = rx_end;
            g_lmac.rx_hang_ticks = 0U;
        }
    }
}

/* --------------------------------------------------------------------------
 * Channel Tuning, RF Power Gating & Timers
 * -------------------------------------------------------------------------- */

/**
 * @brief Convert an IEEE 802.11 2.4 GHz channel number to its center frequency in MHz.
 *
 * @param ch  2.4 GHz channel number (`1..14`).
 * @return Center frequency in MHz (`2412..2472` for ch `1..13`, `2484` for ch `14`),
 *         or `0` if @p ch is out of range.
 */
static uint16_t channel_to_freq_mhz(uint8_t ch)
{
    if (ch >= LMAC_CHAN_MIN && ch <= LMAC_CHAN_MAX_2G_STD) {
        return (uint16_t)(LMAC_CHAN_2G_BASE_MHZ + (uint16_t)ch * LMAC_CHAN_2G_STEP_MHZ);
    }
    if (ch == LMAC_CHAN_JAPAN_14) {
        return LMAC_CHAN_14_FREQ_MHZ;
    }
    return 0U;
}

/**
 * @brief Tune the PHY and WDEV auto-ACK rate LUT to a 2.4 GHz primary channel.
 *
 * If RF is currently closed, records @p primary_chan so esp_lmac_rf_open() applies it on
 * wake. When RF is open, tunes the radio, resets close-range LNA attenuation
 * (`chip_v6_rxmax_ext(0)` and `g_lmac.rxmax_ext = 0`), and switches
 * `LMAC_WDEV_ACK_RATE_TAB0` plus the 11b RX PHY register for CCK-only channel 14 (Japan).
 *
 * @param primary_chan  2.4 GHz channel number (`1..14`).
 * @return ESP_OK on success, or ESP_ERR_INVALID_ARG if @p primary_chan is out of range.
 */
esp_err_t esp_lmac_set_channel(uint8_t primary_chan)
{
    uint16_t mhz = channel_to_freq_mhz(primary_chan);
    if (mhz == 0U) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lmac.rf_closed) {
        g_lmac.cur_channel = primary_chan;
        return ESP_OK;
    }

    phy_change_channel(mhz);
    chip_v6_rxmax_ext(0U);
    g_lmac.rxmax_ext = 0U;

    /* Channel 14 (Japan) is CCK-only: remap ACK rate table to 11b rates */
    if (primary_chan == LMAC_CHAN_JAPAN_14) {
        lmac_reg_write(LMAC_WDEV_ACK_RATE_TAB0, LMAC_WDEV_ACK_RATE_CH14);
        phy_set_rx11b_reg(1U);
    } else {
        lmac_reg_write(LMAC_WDEV_ACK_RATE_TAB0, LMAC_WDEV_ACK_RATE_NORMAL);
        phy_set_rx11b_reg(0U);
    }

    g_lmac.cur_channel = primary_chan;
    return ESP_OK;
}

/**
 * @brief Wake the RF front end, restore the active channel, and re-enable WDEV MAC RX/TX.
 *
 * When exiting LMAC modem sleep (`g_lmac.rf_closed != 0`), acquires the sleep lock,
 * ungates the baseband clock watchdog, opens RF, reapplies the saved channel and MAC
 * enable state, and runs any deferred noise-floor measurement. If `g_lmac.rf_closed == 0`
 * but `esp_light_sleep_start()` independently powered down PHY (`g_phy_sleep_mode_flag != 0`),
 * wakes PHY and restores channel/MAC without double-incrementing the sleep lock count;
 * otherwise acts as a no-op.
 */
void esp_lmac_rf_open(void)
{
    extern uint8_t g_phy_sleep_mode_flag;

    if (!g_lmac.rf_closed) {
        if (g_phy_sleep_mode_flag != 0U) {
            /* Light sleep (esp_light_sleep_start) closed PHY/RF without
             * toggling g_lmac.rf_closed or s_lock_cnt; wake PHY without
             * double-incrementing s_lock_cnt. */
            clockgate_watchdog(0U);
            phy_open_rf();
            if (g_lmac.cur_channel >= LMAC_CHAN_MIN && g_lmac.cur_channel <= LMAC_CHAN_JAPAN_14) {
                esp_lmac_set_channel(g_lmac.cur_channel);
            }
            lmac_wdev_update_mac_enable();
        }
        return;
    }

    esp_sleep_lock();
    clockgate_watchdog(0U);
    phy_open_rf();
    g_lmac.rf_closed = 0U;

    /* Re-apply channel & re-enable MAC RX/TX */
    if (g_lmac.cur_channel >= LMAC_CHAN_MIN && g_lmac.cur_channel <= LMAC_CHAN_JAPAN_14) {
        esp_lmac_set_channel(g_lmac.cur_channel);
    }
    lmac_wdev_update_mac_enable();

    if (g_lmac.pend_noise_check != 0U) {
        g_lmac.pend_noise_check = 0U;
        uint8_t ch_idx = (g_lmac.cur_channel >= LMAC_CHAN_MIN)
                         ? (uint8_t)(g_lmac.cur_channel - LMAC_CHAN_MIN)
                         : 0U;
        noise_check_loop(ch_idx, 1U);
    }
}

/**
 * @brief Power down the RF front end and release the sleep lock when permitted.
 *
 * Disables WDEV MAC RX/TX, closes RF, enables clock-gating watchdog, and unlocks light
 * sleep. No-op if RF is already closed or a power-save lock (`ps_lock_flags != 0`) is held.
 */
void esp_lmac_rf_close(void)
{
    if (g_lmac.rf_closed || g_lmac.ps_lock_flags != 0U) {
        return;
    }

    lmac_reg_clr(LMAC_WDEV_MAC_ENABLE, LMAC_WDEV_MAC_ENABLE_BIT);
    phy_close_rf();
    clockgate_watchdog(1U);
    g_lmac.rf_closed = 1U;
    esp_sleep_unlock();
}

/**
 * @brief Query whether the RF front end is currently powered down.
 *
 * @return `true` if RF is closed (sleep-gated), `false` if RF is active.
 */
bool esp_lmac_rf_is_closed(void)
{
    return (g_lmac.rf_closed != 0U);
}

/**
 * @brief Apply PHY close-range LNA attenuation level when changed since last channel tune.
 *
 * Caches the programmed level in `g_lmac.rxmax_ext` (reset to 0 by esp_lmac_set_channel())
 * to avoid redundant `chip_v6_rxmax_ext()` register writes.
 *
 * @param level  Target `rxmax_ext` level (0 = normal sensitivity, 3 = strong close-range attenuation).
 */
void esp_lmac_set_rxmax_ext(uint8_t level)
{
    if (g_lmac.rxmax_ext != level) {
        chip_v6_rxmax_ext(level);
        g_lmac.rxmax_ext = level;
    }
}

/**
 * @brief Read the 64-bit hardware TSF counter for a VIF in microseconds.
 *
 * @param vif  Virtual interface (`ESP_LMAC_VIF_AP` selects TSF1; all others select TSF0).
 * @return Current 64-bit TSF timestamp in microseconds.
 */
uint64_t esp_lmac_get_tsf_us(esp_lmac_vif_t vif)
{
    uint32_t lo_reg = (vif == ESP_LMAC_VIF_AP) ? LMAC_WDEV_TSF1_LO : LMAC_WDEV_TSF0_LO;
    uint32_t hi_reg = (vif == ESP_LMAC_VIF_AP) ? LMAC_WDEV_TSF1_HI : LMAC_WDEV_TSF0_HI;

    /*
     * Wrap-safe 64-bit TSF snapshot (hi/lo/hi loop):
     * TSF_LO and TSF_HI are separate 32-bit MMIO registers incremented asynchronously by
     * the 1 MHz MAC clock. Reading HI, then LO, then HI again and retrying whenever the
     * two HI samples differ prevents returning a torn value across a 32-bit LO rollover.
     */
    uint32_t hi1;
    uint32_t lo;
    uint32_t hi2;
    do {
        hi1 = lmac_reg_read(hi_reg);
        lo = lmac_reg_read(lo_reg);
        hi2 = lmac_reg_read(hi_reg);
    } while (hi1 != hi2);

    return ((uint64_t)hi1 << LMAC_TSF_HI_SHIFT) | (uint64_t)lo;
}

/**
 * @brief Read the 32-bit free-running WDEV MAC microsecond clock (`LMAC_WDEV_TIME`).
 *
 * @return Current 1 MHz MAC hardware timestamp in microseconds (wraps every ~71.6 min).
 */
uint32_t esp_lmac_get_mac_time_us(void)
{
    return lmac_reg_read(LMAC_WDEV_TIME);
}

/**
 * @brief Read a 32-bit random word from the WDEV hardware RNG (`LMAC_WDEV_HW_SEQ_RND`).
 *
 * @return 32-bit hardware-generated pseudorandom / entropy value.
 */
uint32_t esp_lmac_get_hw_rand(void)
{
    return lmac_reg_read(LMAC_WDEV_HW_SEQ_RND);
}

/**
 * @brief Copy the cumulative LMAC telemetry counters into a caller-provided struct.
 *
 * @param out  Destination struct pointer; safely ignored if NULL.
 */
void esp_lmac_get_stats(esp_lmac_stats_t *out)
{
    if (out != NULL) {
        *out = g_lmac.stats;
    }
}

/**
 * @brief Check whether Wi-Fi power-save RF sleep is currently inhibited by a lock.
 *
 * @return `true` if one or more power-save lock flags are set, `false` otherwise.
 */
bool esp_lmac_ps_is_locked(void)
{
    return (g_lmac.ps_lock_flags != 0U);
}

/* --------------------------------------------------------------------------
 * External SDK Compatibility Exports (Consumed by esp_sleep, esp_wifi,
 * tcpip_adapter, phy)
 * -------------------------------------------------------------------------- */

/**
 * @brief Legacy PM hook to power on the RF front end upon sleep wakeup.
 */
void pm_goto_rf_on(void)
{
    esp_lmac_rf_open();
}

/**
 * @brief Acquire the Wi-Fi power-save lock to prevent esp_lmac_rf_close() from sleeping RF.
 */
void esp_wifi_ps_lock(void)
{
    g_lmac.ps_lock_flags |= LMAC_PS_LOCK_WIFI_BIT;
}

/**
 * @brief Release the Wi-Fi power-save lock so RF may enter sleep when idle.
 */
void esp_wifi_ps_unlock(void)
{
    g_lmac.ps_lock_flags &= ~LMAC_PS_LOCK_WIFI_BIT;
}

/**
 * @brief Record the configured memory allocation type for incoming Wi-Fi RX pbufs.
 *
 * @param type  Preferred RX pbuf memory type (`wifi_rx_pbuf_mem_type_t`).
 */
void esp_wifi_set_rx_pbuf_mem_type(wifi_rx_pbuf_mem_type_t type)
{
    g_lmac.rx_pbuf_mem_type = (uint8_t)type;
}

/**
 * @brief Retrieve the configured memory allocation type for incoming Wi-Fi RX pbufs.
 *
 * @return Currently configured `wifi_rx_pbuf_mem_type_t`.
 */
wifi_rx_pbuf_mem_type_t esp_wifi_get_rx_pbuf_mem_type(void)
{
    return (wifi_rx_pbuf_mem_type_t)g_lmac.rx_pbuf_mem_type;
}

/**
 * @brief Request a deferred PHY noise-floor measurement on the next housekeeping/RF-open opportunity.
 *
 * @param interval  Legacy SDK timer interval parameter (unused; measurement is serviced by
 *                  esp_lmac_housekeeping_100ms() or esp_lmac_rf_open()).
 */
void reset_noise_timer(uint16_t interval)
{
    (void)interval;
    g_lmac.pend_noise_check = 1U;
}
