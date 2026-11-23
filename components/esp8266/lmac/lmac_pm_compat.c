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

/* Single zero-initialized global LMAC context (explicitly initialized — 0 SHN_COMMON) */
lmac_ctx_t g_lmac = {0};

/* --------------------------------------------------------------------------
 * Lifecycle: esp_lmac_init / esp_lmac_deinit
 * -------------------------------------------------------------------------- */

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
    if (g_lmac.cfg.rx_buf_num < 4U) {
        g_lmac.cfg.rx_buf_num = 16U;
    } else if (g_lmac.cfg.rx_buf_num > LMAC_MAX_RX_BUFS) {
        g_lmac.cfg.rx_buf_num = LMAC_MAX_RX_BUFS;
    }
    if (g_lmac.cfg.rx_buf_len == 0U) {
        g_lmac.cfg.rx_buf_len = 524U;
    }
    if (g_lmac.cfg.rx_max_single_pkt_len == 0U) {
        g_lmac.cfg.rx_max_single_pkt_len = 1600U;
    }
    if (g_lmac.cfg.tx_slot_num < 2U) {
        g_lmac.cfg.tx_slot_num = 6U;
    }

    g_lmac.cbs = *cbs;
    g_lmac.cur_channel = 1U;
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
    esp_lmac_set_channel(1U);

    g_lmac.initialized = true;
    return ESP_OK;
}

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

bool esp_lmac_process_events(uint8_t max_rx_batch, uint8_t max_tx_batch)
{
    if (!g_lmac.initialized) {
        return false;
    }

    uint8_t rx_done = 0U;
    uint8_t tx_done = 0U;
    uint8_t total_steps = 0U;
    const uint8_t max_total = (uint8_t)(max_rx_batch + max_tx_batch + 4U);

#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
    tx_done = lmac_tx_drain_done(max_tx_batch);
#endif

    while (g_lmac.nmi_rd != g_lmac.nmi_wr) {
        uint8_t rd = g_lmac.nmi_rd;
        lmac_nmi_evt_t ev = g_lmac.nmi_ring[rd];

        if (ev.type == LMAC_NMI_EVT_RX_DESC && max_rx_batch > 0U && rx_done >= max_rx_batch) {
            return true;
        }
#ifdef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
        if (ev.type == LMAC_NMI_EVT_TX_DONE && max_tx_batch > 0U && tx_done >= max_tx_batch) {
            return true;
        }
#endif

        __asm__ volatile("" ::: "memory");
        g_lmac.nmi_rd = (uint8_t)((rd + 1U) & LMAC_NMI_RING_MASK);

        switch (ev.type) {
        case LMAC_NMI_EVT_RX_DESC:
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

#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
    if (max_tx_batch == 0U || tx_done < max_tx_batch) {
        uint8_t rem = (max_tx_batch > 0U) ? (uint8_t)(max_tx_batch - tx_done) : 0U;
        tx_done = (uint8_t)(tx_done + lmac_tx_drain_done(rem));
    }
    return (g_lmac.nmi_rd != g_lmac.nmi_wr) || (g_lmac.tx_done_head != NULL);
#else
    return (g_lmac.nmi_rd != g_lmac.nmi_wr);
#endif
}

/* --------------------------------------------------------------------------
 * 100 ms Periodic Housekeeping (Noise Floor, TX Power Tracking, Hang Watchdog)
 * -------------------------------------------------------------------------- */

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
    if ((g_lmac.hk_tick_cnt % 10U) == 0U && !g_lmac.rf_closed) {
        if (g_lmac.pend_noise_check != 0U || (g_lmac.hk_tick_cnt % 30U) == 0U) {
            g_lmac.pend_noise_check = 0U;
            uint8_t ch_idx = (g_lmac.cur_channel >= 1U) ? (uint8_t)(g_lmac.cur_channel - 1U) : 0U;
            noise_check_loop(ch_idx, 1U);
        }
        tx_pwctrl_background(1U, 0U);
    }

    /* RX hang check every 1 second when MAC is active and not in sleep */
    if ((g_lmac.hk_tick_cnt % 10U) == 0U && !g_lmac.rf_closed &&
        (g_lmac.vif[ESP_LMAC_VIF_STA].enabled || g_lmac.vif[ESP_LMAC_VIF_AP].enabled)) {
        uint32_t rx_end = lmac_reg_read(LMAC_WDEV_RX_END_CNT);
        if (rx_end == g_lmac.last_rx_end_cnt && g_lmac.rx_avail_mask == 0U) {
            g_lmac.rx_hang_ticks++;
            if (g_lmac.rx_hang_ticks >= 5U) {
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

static uint16_t channel_to_freq_mhz(uint8_t ch)
{
    if (ch >= 1U && ch <= 13U) {
        return (uint16_t)(2407U + (uint16_t)ch * 5U);
    }
    if (ch == 14U) {
        return 2484U;
    }
    return 0U;
}

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

    /* Channel 14 (Japan) is CCK-only: remap ACK rate table to 11b rates */
    if (primary_chan == 14U) {
        lmac_reg_write(LMAC_WDEV_ACK_RATE_TAB0, 0x32103210U);
        phy_set_rx11b_reg(1U);
    } else {
        lmac_reg_write(LMAC_WDEV_ACK_RATE_TAB0, 0x76503210U);
        phy_set_rx11b_reg(0U);
    }

    g_lmac.cur_channel = primary_chan;
    return ESP_OK;
}

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
            if (g_lmac.cur_channel >= 1U && g_lmac.cur_channel <= 14U) {
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
    if (g_lmac.cur_channel >= 1U && g_lmac.cur_channel <= 14U) {
        esp_lmac_set_channel(g_lmac.cur_channel);
    }
    lmac_wdev_update_mac_enable();

    if (g_lmac.pend_noise_check != 0U) {
        g_lmac.pend_noise_check = 0U;
        uint8_t ch_idx = (g_lmac.cur_channel >= 1U) ? (uint8_t)(g_lmac.cur_channel - 1U) : 0U;
        noise_check_loop(ch_idx, 1U);
    }
}

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

bool esp_lmac_rf_is_closed(void)
{
    return (g_lmac.rf_closed != 0U);
}

uint64_t esp_lmac_get_tsf_us(esp_lmac_vif_t vif)
{
    uint32_t lo_reg = (vif == ESP_LMAC_VIF_AP) ? LMAC_WDEV_TSF1_LO : LMAC_WDEV_TSF0_LO;
    uint32_t hi_reg = (vif == ESP_LMAC_VIF_AP) ? LMAC_WDEV_TSF1_HI : LMAC_WDEV_TSF0_HI;

    uint32_t hi1;
    uint32_t lo;
    uint32_t hi2;
    do {
        hi1 = lmac_reg_read(hi_reg);
        lo = lmac_reg_read(lo_reg);
        hi2 = lmac_reg_read(hi_reg);
    } while (hi1 != hi2);

    return ((uint64_t)hi1 << 32) | (uint64_t)lo;
}

uint32_t esp_lmac_get_mac_time_us(void)
{
    return lmac_reg_read(LMAC_WDEV_TIME);
}

uint32_t esp_lmac_get_hw_rand(void)
{
    return lmac_reg_read(LMAC_WDEV_HW_SEQ_RND);
}

void esp_lmac_get_stats(esp_lmac_stats_t *out)
{
    if (out != NULL) {
        *out = g_lmac.stats;
    }
}

bool esp_lmac_ps_is_locked(void)
{
    return (g_lmac.ps_lock_flags != 0U);
}

/* --------------------------------------------------------------------------
 * External SDK Compatibility Exports (Consumed by esp_clk_rtc, esp_sleep,
 * esp_wifi, tcpip_adapter, phy)
 * -------------------------------------------------------------------------- */

void pm_goto_rf_on(void)
{
    esp_lmac_rf_open();
}

void esp_wifi_ps_lock(void)
{
    g_lmac.ps_lock_flags |= 1U;
}

void esp_wifi_ps_unlock(void)
{
    g_lmac.ps_lock_flags &= ~1U;
}

void esp_wifi_set_rx_pbuf_mem_type(wifi_rx_pbuf_mem_type_t type)
{
    g_lmac.rx_pbuf_mem_type = (uint8_t)type;
}

wifi_rx_pbuf_mem_type_t esp_wifi_get_rx_pbuf_mem_type(void)
{
    return (wifi_rx_pbuf_mem_type_t)g_lmac.rx_pbuf_mem_type;
}

void reset_noise_timer(uint16_t interval)
{
    (void)interval;
    g_lmac.pend_noise_check = 1U;
}
