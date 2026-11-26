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
// Level-3 NMI handler (wDev_ProcessFiq), Level-1 SoftISR handoff
// (MacIsrSigPostDefHdl), and IRAM-resident hardware MAC timer / RX descriptor
// primitives. Compiled with -fno-jump-tables to guarantee zero flash .rodata
// dereferences while SPI flash cache is disabled.
//
// Portions of the WDEV NMI RX-drain and RX-head hardware sequences are adapted
// in part from teatime-os:
//   MIT License
//   Copyright (c) 2025-2026 Jonathan Waters
//   Permission is hereby granted, free of charge, to any person obtaining a
//   copy of this software and associated documentation files (the "Software"),
//   to deal in the Software without restriction, including without limitation
//   the rights to use, copy, modify, merge, publish, distribute, sublicense,
//   and/or sell copies of the Software, and to permit persons to whom the
//   Software is furnished to do so, subject to the following conditions:
//   The above copyright notice and this permission notice shall be included in
//   all copies or substantial portions of the Software.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "lmac_internal.h"

/* --------------------------------------------------------------------------
 * External SDK / FreeRTOS ABI Globals (port.c, esp_sleep.c, esp_sys_ctrl.c)
 * -------------------------------------------------------------------------- */

volatile uint8_t  NMIIrqIsOn = 0U;
volatile uint32_t WDEV_INTEREST_EVENT = LMAC_WDEV_INTEREST_DEFAULT;
volatile uint64_t WdevTimOffSet = 0ULL;

/* Hardware MAC timer callbacks (MAC Timer 0 = task_wdt NMI WDT, Timer 1 = TBTT) */
static void (*s_mac_tim0_cb)(void) = NULL;
static void (*s_mac_tim1_cb)(void) = NULL;

/* --------------------------------------------------------------------------
 * IRAM RX Circular Descriptor Bitmask Helpers (Division-Free)
 * -------------------------------------------------------------------------- */

void IRAM_ATTR lmac_rx_set_desc_bit_locked(uint8_t idx)
{
    uint8_t n = g_lmac.cfg.rx_buf_num;
    uint8_t prev = (idx == 0U) ? (uint8_t)(n - 1U) : (uint8_t)(idx - 1U);

    g_lmac.rx_descs[prev].next = &g_lmac.rx_descs[idx];
    g_lmac.rx_avail_mask |= (1U << idx);
}

static inline __attribute__((always_inline)) void IRAM_ATTR lmac_rx_clear_desc_bit_locked(uint8_t idx)
{
    uint8_t n = g_lmac.cfg.rx_buf_num;
    uint8_t prev = (idx == 0U) ? (uint8_t)(n - 1U) : (uint8_t)(idx - 1U);

    g_lmac.rx_descs[prev].next = NULL;
    g_lmac.rx_avail_mask &= ~(1U << idx);
}

void IRAM_ATTR lmac_check_and_move_hwbuf_locked(void)
{
    uint8_t n = g_lmac.cfg.rx_buf_num;
    lmac_lldesc_t *descs = g_lmac.rx_descs;

    if (descs == NULL || n == 0U) {
        return;
    }

    lmac_lldesc_t *head = &descs[g_lmac.rx_head_idx];
    lmac_lldesc_t *d1 = head->next;
    lmac_lldesc_t *d2 = (d1 != NULL) ? d1->next : NULL;

    /* If head and its next 2 descriptors are all DMA-owned and linked, keep current head */
    if ((head->ctrl & LLDESC_OWNER) != 0U &&
        d1 != NULL && (d1->ctrl & LLDESC_OWNER) != 0U &&
        d2 != NULL && (d2->ctrl & LLDESC_OWNER) != 0U) {
        return;
    }

    /* Find start index of the longest contiguous run of available (1) bits in circular rx_avail_mask */
    uint32_t avail = g_lmac.rx_avail_mask;
    uint32_t doubled = (avail << n) | avail;
    uint32_t runs = doubled;

    for (;;) {
        uint32_t next_runs = (runs >> 1) & runs;
        if (next_runs == 0U) {
            break;
        }
        runs = next_runs;
    }

    uint32_t valid_mask = (n >= 32U) ? 0xFFFFFFFFU : ((1U << n) - 1U);
    runs &= valid_mask;
    if (runs == 0U) {
        return;
    }

    /* Find highest set bit index (matches vendor wDev_Check_And_Move_hwbuf) */
    uint8_t best_idx = 0U;
    uint32_t tmp = runs;
    while (tmp > 1U) {
        tmp >>= 1;
        best_idx++;
    }

    /* Never move WDEV_RX_LINK_HEAD while DMA is actively writing to our current head */
    if (lmac_reg_read(LMAC_WDEV_RX_CUR_DESC) != (uint32_t)(uintptr_t)head) {
        g_lmac.rx_head_idx = best_idx;
        lmac_reg_write(LMAC_WDEV_RX_LINK_HEAD, (uint32_t)(uintptr_t)&descs[best_idx]);
    }
}

/* --------------------------------------------------------------------------
 * Lock-Free NMI -> Worker Ring Push (IRAM, Single-Producer NMI Only)
 * -------------------------------------------------------------------------- */

static bool IRAM_ATTR nmi_ring_push(const lmac_nmi_evt_t *ev)
{
    uint8_t wr = g_lmac.nmi_wr;
    uint8_t next = (uint8_t)((wr + 1U) & LMAC_NMI_RING_MASK);

    if (next == g_lmac.nmi_rd) {
        return false;
    }

    g_lmac.nmi_ring[wr] = *ev;
    __asm__ volatile("memw" ::: "memory");
    g_lmac.nmi_wr = next;
    return true;
}

static void __attribute__((noinline)) IRAM_ATTR nmi_recycle_desc_range(uint8_t start_idx, uint8_t cnt)
{
    uint8_t n = g_lmac.cfg.rx_buf_num;
    uint8_t idx = start_idx;

    for (uint8_t i = 0U; i < cnt; i++) {
        lmac_lldesc_t *d = &g_lmac.rx_descs[idx];
        uint32_t sz = d->ctrl & LLDESC_SIZE_MASK;
        d->ctrl = LLDESC_OWNER | (sz << LLDESC_LEN_SHIFT) | sz;
        lmac_rx_set_desc_bit_locked(idx);
        idx++;
        if (idx >= n) {
            idx = 0U;
        }
    }
}

#if CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
/**
 * @brief Demux an A-MPDU RX chain in IRAM NMI using WDEV's subframe-info descriptor.
 *
 * Walks rx_ampdu_descs[rx_ampdu_head_idx], enforces CVE-2020-26146 fragment
 * drops, allocates handles from the 32-entry static rx_subframes pool, tracks
 * 5-bit LLDESC_OFF_MASK refcounts on shared rx_descs, immediately restores
 * LLDESC_OWNER on rx_ampdu_descs, and recycles any unreferenced rx_descs.
 *
 * @return true if at least one subframe event was pushed to nmi_ring.
 */
static bool __attribute__((noinline)) IRAM_ATTR nmi_drain_ampdu(
    uint8_t start_idx, uint8_t cnt, uint32_t w0, uint32_t w1, uint32_t w2, uint8_t ch)
{
    lmac_lldesc_t *descs = g_lmac.rx_descs;
    uint8_t n = g_lmac.cfg.rx_buf_num;

    if (g_lmac.cfg.ampdu_rx_enable == 0U || g_lmac.rx_ampdu_descs == NULL ||
        g_lmac.rx_subframes == NULL || cnt == 0U) {
        nmi_recycle_desc_range(start_idx, cnt);
        return false;
    }

    uint8_t ahead = g_lmac.rx_ampdu_head_idx;
    uint8_t anum = g_lmac.cfg.rx_ampdu_buf_num;
    uint16_t abuf_len = g_lmac.cfg.rx_ampdu_buf_len;
    lmac_lldesc_t *adesc = &g_lmac.rx_ampdu_descs[ahead];
    uint32_t actrl = adesc->ctrl;
    uint16_t sub_cnt = ((actrl & LLDESC_EOF) != 0U) ? (uint16_t)((actrl >> 14) & 0x3FFU) : 0U;
    uint16_t max_entries = (uint16_t)(abuf_len >> 2);
    if (sub_cnt > max_entries) {
        sub_cnt = max_entries;
    }

    uint16_t buf_len = g_lmac.cfg.rx_buf_len;
    uint8_t sf_desc_idx = start_idx;
    uint16_t sf_off = sizeof(wifi_pkt_rx_ctrl_t);
    uint16_t rem_in_desc = (uint16_t)(buf_len - sf_off);
    uint8_t consumed_descs = 1U;
    uint8_t first_fc1 = descs[start_idx].buf[13];
    uint16_t strip = (!g_lmac.sniffer_mode && ((first_fc1 & 0x40U) != 0U))
                     ? LMAC_AMPDU_STRIP_CRYPTO
                     : LMAC_AMPDU_STRIP_PLAIN;
    int16_t freq_off = (!g_lmac.sniffer_mode) ? phy_get_bb_freqoffset() : 0;
    const uint32_t *entries = (const uint32_t *)(const void *)adesc->buf;
    bool pushed_any = false;

    for (uint16_t si = 0U; si < sub_cnt; si++) {
        uint32_t entry = entries[si];
        uint8_t sub_state = (uint8_t)(entry & 0xFFU);
        uint16_t sub_len = (uint16_t)((entry >> 8) & 0xFFFU);

        /* WDEV silicon only DMAs subframes with sub_state == 0 into rx_frontdata */
        if (sub_state != LMAC_RXSTATE_OK) {
            continue;
        }
        if (sub_len < LMAC_AMPDU_MIN_SUBFRAME_LEN) {
            break;
        }
        if (sub_len <= strip) {
            break;
        }

        uint16_t dma_bytes = (uint16_t)(((sub_len - strip) + 3U) & ~3U);
        if (rem_in_desc == 0U) {
            if (consumed_descs >= cnt) {
                break;
            }
            sf_desc_idx++;
            if (sf_desc_idx >= n) {
                sf_desc_idx = 0U;
            }
            consumed_descs++;
            rem_in_desc = buf_len;
            sf_off = 0U;
        }

        uint32_t avail_bytes = (uint32_t)rem_in_desc +
                               (uint32_t)(cnt - consumed_descs) * (uint32_t)buf_len;
        if ((uint32_t)dma_bytes > avail_bytes) {
            break;
        }

        uint8_t cur_start_desc = sf_desc_idx;
        uint16_t cur_start_off = sf_off;
        uint8_t cur_desc_cnt = 1U;

        uint16_t rem = dma_bytes;
        while (rem > rem_in_desc) {
            rem = (uint16_t)(rem - rem_in_desc);
            sf_desc_idx++;
            if (sf_desc_idx >= n) {
                sf_desc_idx = 0U;
            }
            consumed_descs++;
            cur_desc_cnt++;
            rem_in_desc = buf_len;
            sf_off = 0U;
        }
        rem_in_desc = (uint16_t)(rem_in_desc - rem);
        sf_off = (uint16_t)(buf_len - rem_in_desc);

        if (sub_len > LMAC_AMPDU_MAX_SUBFRAME_LEN) {
            continue;
        }

        /* Read 802.11 FC1 and Sequence Control LSB safely across descriptor wrap */
        uint8_t sf_fc1 = descs[cur_start_desc].buf[cur_start_off + 1U];
        uint8_t sf_seq_lo;
        if ((uint16_t)(cur_start_off + 22U) < buf_len) {
            sf_seq_lo = descs[cur_start_desc].buf[cur_start_off + 22U];
        } else {
            uint8_t next_d = (uint8_t)(cur_start_desc + 1U);
            if (next_d >= n) {
                next_d = 0U;
            }
            sf_seq_lo = descs[next_d].buf[cur_start_off + 22U - buf_len];
        }

        /* CVE-2020-26146: drop fragmented A-MPDU subframes (MoreFrag != 0 || FragNum != 0) */
        if (!g_lmac.sniffer_mode && ((sf_fc1 & 0x04U) != 0U || (sf_seq_lo & 0x0FU) != 0U)) {
            g_lmac.stats.rx_nmi_drops++;
            continue;
        }

        /* Branchless 5-step LSB lookup in the 32-entry static subframe pool */
        uint32_t free_mask = ~g_lmac.rx_subframe_used_mask;
        if (free_mask == 0U) {
            g_lmac.stats.rx_nmi_drops++;
            continue;
        }
        uint32_t lsb = free_mask & (uint32_t)(-(int32_t)free_mask);
        uint8_t sidx = 0U;
        if ((lsb & 0xFFFF0000U) != 0U) { sidx += 16U; }
        if ((lsb & 0xFF00FF00U) != 0U) { sidx += 8U; }
        if ((lsb & 0xF0F0F0F0U) != 0U) { sidx += 4U; }
        if ((lsb & 0xCCCCCCCCU) != 0U) { sidx += 2U; }
        if ((lsb & 0xAAAAAAAAU) != 0U) { sidx += 1U; }

        /* Guard 5-bit descriptor refcount against saturation (< 31) */
        bool ref_ok = true;
        uint8_t ridx = cur_start_desc;
        for (uint8_t k = 0U; k < cur_desc_cnt; k++) {
            uint32_t rc = (descs[ridx].ctrl & LLDESC_OFF_MASK) >> LLDESC_OFF_SHIFT;
            if (rc >= LMAC_LLDESC_REFCNT_MAX) {
                ref_ok = false;
                break;
            }
            ridx++;
            if (ridx >= n) {
                ridx = 0U;
            }
        }
        if (!ref_ok) {
            g_lmac.stats.rx_nmi_drops++;
            continue;
        }

        lmac_rx_subframe_t *sf = &g_lmac.rx_subframes[sidx];
        sf->rx_ctrl_w[0] = ((w0 & 0xC000U) == 0U)
                           ? ((w0 & 0xF000FFFFU) | ((uint32_t)sub_len << 16))
                           : w0;
        sf->rx_ctrl_w[1] = ((w0 & 0xC000U) != 0U)
                           ? ((w1 & 0xFF0000FFU) | ((uint32_t)sub_len << 8))
                           : w1;
        sf->rx_ctrl_w[2] = (w2 & 0xFFF0FF00U) | (((uint32_t)ch & 0x0FU) << 16) | (uint32_t)sub_state;
        sf->start_off = cur_start_off;
        sf->handle.rx_ctrl = NULL;
        sf->handle.frame = NULL;
        sf->handle.len = (!g_lmac.sniffer_mode && sub_len >= 4U) ? (uint16_t)(sub_len - 4U) : sub_len;
        sf->handle.freq_offset = freq_off;
        sf->handle.vif_match = (uint8_t)((w0 >> 28) & 0x0FU);
        sf->handle.desc_start = cur_start_desc;
        sf->handle.desc_cnt = cur_desc_cnt;
        sf->handle.in_use = 1U;

        lmac_nmi_evt_t ev;
        ev.type = LMAC_NMI_EVT_RX_AMPDU;
        ev.a = sidx;
        ev.b = 0U;
        ev.c = sub_state;
        ev.d = freq_off;
        ev.len = sub_len;

        if (nmi_ring_push(&ev)) {
            g_lmac.rx_subframe_used_mask |= (1U << sidx);
            ridx = cur_start_desc;
            for (uint8_t k = 0U; k < cur_desc_cnt; k++) {
                uint32_t rc = (descs[ridx].ctrl & LLDESC_OFF_MASK) >> LLDESC_OFF_SHIFT;
                descs[ridx].ctrl = (descs[ridx].ctrl & ~LLDESC_OFF_MASK) |
                                   ((rc + 1U) << LLDESC_OFF_SHIFT);
                ridx++;
                if (ridx >= n) {
                    ridx = 0U;
                }
            }
            g_lmac.stats.rx_nmi_frames++;
            pushed_any = true;
        } else {
            sf->handle.in_use = 0U;
            g_lmac.stats.rx_nmi_drops++;
        }
    }

    /* Immediately restore rx_ampdu_descs owner and advance head index */
    adesc->ctrl = LLDESC_OWNER | ((uint32_t)abuf_len << LLDESC_LEN_SHIFT) | (uint32_t)abuf_len;
    ahead++;
    if (ahead >= anum) {
        ahead = 0U;
    }
    g_lmac.rx_ampdu_head_idx = ahead;

    /* Immediately recycle any rx_descs not pinned by an accepted subframe */
    uint8_t idx = start_idx;
    for (uint8_t i = 0U; i < cnt; i++) {
        lmac_lldesc_t *d = &descs[idx];
        if ((d->ctrl & LLDESC_OFF_MASK) == 0U) {
            uint32_t sz = d->ctrl & LLDESC_SIZE_MASK;
            d->ctrl = LLDESC_OWNER | (sz << LLDESC_LEN_SHIFT) | sz;
            lmac_rx_set_desc_bit_locked(idx);
        }
        idx++;
        if (idx >= n) {
            idx = 0U;
        }
    }

    return pushed_any;
}
#endif

/* --------------------------------------------------------------------------
 * Thin RX Descriptor Drain in NMI (<10 us, zero malloc/memcpy)
 * -------------------------------------------------------------------------- */

static bool IRAM_ATTR nmi_drain_rx(void)
{
    lmac_lldesc_t *descs = g_lmac.rx_descs;
    uint8_t n = g_lmac.cfg.rx_buf_num;

    if (descs == NULL || n == 0U) {
        return false;
    }

    uint32_t last_addr = lmac_reg_read(LMAC_WDEV_RX_LAST_DESC);
    uintptr_t base_addr = (uintptr_t)descs;
    uintptr_t end_addr = (uintptr_t)(descs + n);

    if (last_addr < base_addr || last_addr >= end_addr) {
        return false;
    }

    lmac_lldesc_t *last_desc = (lmac_lldesc_t *)(uintptr_t)last_addr;
    uint8_t cur_idx = g_lmac.rx_head_idx;
    uint8_t ch = g_lmac.cur_channel;
    bool pushed_any = false;
    uint8_t budget = n;

    while (budget > 0U) {
        /* Guard against spurious bit 8 when descriptor was already popped */
        if ((g_lmac.rx_avail_mask & (1U << cur_idx)) == 0U) {
            break;
        }

        lmac_lldesc_t *first = &descs[cur_idx];
        uint8_t start_idx = cur_idx;
        uint8_t cnt = 0U;
        bool reached_eof = false;
        bool reached_last = false;

        /* Walk descriptors belonging to this MPDU */
        while (budget > 0U) {
            lmac_lldesc_t *d = &descs[cur_idx];
            uint32_t ctrl = d->ctrl;

            /* Claim descriptor from hardware DMA */
            d->ctrl = ctrl & ~(LLDESC_OWNER | LLDESC_OFF_MASK);
            lmac_rx_clear_desc_bit_locked(cur_idx);
            cnt++;
            budget--;

            if (d == last_desc) {
                reached_last = true;
            }
            if ((ctrl & LLDESC_EOF) != 0U) {
                reached_eof = true;
            }

            cur_idx++;
            if (cur_idx >= n) {
                cur_idx = 0U;
            }

            if (reached_eof || reached_last) {
                break;
            }
        }

        /* Inspect 12-byte hardware rx_ctrl header in DRAM */
        uint32_t *rxw = (uint32_t *)(void *)first->buf;
        uint32_t w0 = rxw[0];
        uint32_t w1 = rxw[1];
        uint32_t w2 = rxw[2];

        /* Stamp current primary channel into rx_ctrl->channel (bits [19:16] of word 2) */
        rxw[2] = (w2 & 0xFFF0FFFFU) | (((uint32_t)ch & 0x0FU) << 16);

        uint16_t flen = ((w0 & 0xC000U) != 0U)
                        ? (uint16_t)((w1 >> 8) & 0xFFFFU)
                        : (uint16_t)((w0 >> 16) & 0x0FFFU);
        uint8_t rx_state = (uint8_t)(w2 & 0xFFU);
        bool is_ampdu = ((w1 & 0x08000000U) != 0U);
#if CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
        if (reached_eof && is_ampdu) {
            if (nmi_drain_ampdu(start_idx, cnt, w0, w1, w2, ch)) {
                pushed_any = true;
            }
            if (reached_last) {
                break;
            }
            continue;
        }
#endif
        int16_t freq_off = 0;

        bool accept = reached_eof && (flen >= 10U) && (flen <= 2346U) && (!is_ampdu);
        if (accept && !g_lmac.sniffer_mode) {
            /* Match vendor wDev_ProcessFiq valid rxend_state check: 0, 0x32 ('2'), 0xF5 (-11) */
            if (rx_state != LMAC_RXSTATE_OK && rx_state != LMAC_RXSTATE_ALT1 &&
                rx_state != LMAC_RXSTATE_ALT2) {
                accept = false;
            } else {
                freq_off = phy_get_bb_freqoffset();
            }
        }

        g_lmac.stats.rx_nmi_frames++;

        bool recycle = true;
        if (accept) {
            lmac_nmi_evt_t ev;
            ev.type = LMAC_NMI_EVT_RX_DESC;
            ev.a = start_idx;
            ev.b = cnt;
            ev.c = rx_state;
            ev.d = freq_off;
            ev.len = flen;

            if (nmi_ring_push(&ev)) {
#if CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
                uint8_t ridx = start_idx;
                for (uint8_t k = 0U; k < cnt; k++) {
                    descs[ridx].ctrl = (descs[ridx].ctrl & ~LLDESC_OFF_MASK) |
                                       (1U << LLDESC_OFF_SHIFT);
                    ridx++;
                    if (ridx >= n) {
                        ridx = 0U;
                    }
                }
#endif
                pushed_any = true;
                recycle = false;
            } else {
                g_lmac.stats.rx_nmi_drops++;
            }
        }
        if (recycle) {
            /* Drop invalid/truncated/unsupported frame or full ring and recycle descriptors */
            nmi_recycle_desc_range(start_idx, cnt);
        }

        if (reached_last) {
            break;
        }
    }

    g_lmac.rx_head_idx = cur_idx;
    lmac_check_and_move_hwbuf_locked();
    return pushed_any;
}

/**
 * @brief Capture a sniffer-mode non-RX_DONE frame on LMAC_INT_SNIFFER_END (BIT(2)).
 *
 * WDEV delivers control frames and filtered MPDUs into rx_head->buf without
 * advancing LMAC_WDEV_RX_LAST_DESC or clearing LLDESC_OWNER. Because subsequent
 * over-the-air arrivals overwrite rx_head->buf within SIFS, NMI validates
 * LMAC_WDEV_RX_STAT_INFO (0x00 or 0x41, rejecting 0x42..0x7F error states),
 * pre-filters against sniffer_filter / sniffer_ctrl_filter, copies
 * 12 + min(flen, 112) bytes into snf_ring, and guards against torn DMA
 * overwrites via LMAC_WDEV_RX_TSF_LO, INT_RAW, and post-copy header checks.
 *
 * @return true if a packet was committed to snf_ring and the worker should be notified.
 */
static bool __attribute__((noinline)) IRAM_ATTR nmi_drain_sniffer_end(void)
{
    uint32_t sinfo = lmac_reg_read(LMAC_WDEV_RX_STAT_INFO) & 0xFFU;
    if (sinfo != LMAC_RX_STAT_OK && sinfo != LMAC_RX_STAT_SNIFFER_OK) {
        return false;
    }
    if (g_lmac.snf_ring == NULL || g_lmac.rx_descs == NULL) {
        return false;
    }

    uint8_t head_idx = g_lmac.rx_head_idx;
    if ((g_lmac.rx_avail_mask & (1U << head_idx)) == 0U) {
        return false;
    }

    uint32_t tsf_before = lmac_reg_read(LMAC_WDEV_RX_TSF_LO);
    const uint8_t *raw = g_lmac.rx_descs[head_idx].buf;

    uint32_t w0 = ((const uint32_t *)(const void *)raw)[0];
    uint32_t w1 = ((const uint32_t *)(const void *)raw)[1];
    if ((w1 & 0x08000000U) != 0U) {
        return false;
    }

    uint16_t flen;
    if ((w0 & 0xC000U) != 0U) {
        if ((w1 & 0x40000080U) != 0U || (w1 & 0x7FU) >= 8U) {
            return false;
        }
        flen = (uint16_t)((w1 >> 8) & 0xFFFFU);
    } else {
        flen = (uint16_t)((w0 >> 16) & 0x0FFFU);
    }
    if (flen < 10U || flen > 2346U) {
        return false;
    }

    uint8_t fc0 = raw[12];
    uint8_t ftype = (uint8_t)(fc0 & 0x0FU);
    uint32_t fmask;
    if (ftype == 0x00U) {
        fmask = WIFI_PROMIS_FILTER_MASK_MGMT;
    } else if (ftype == 0x04U) {
        uint8_t sub = (uint8_t)(fc0 >> 4);
        if (sub < 7U || (g_lmac.sniffer_ctrl_filter & (1U << (16U + sub))) == 0U) {
            return false;
        }
        fmask = WIFI_PROMIS_FILTER_MASK_CTRL;
    } else if (ftype == 0x08U) {
        fmask = WIFI_PROMIS_FILTER_MASK_DATA;
    } else {
        return false;
    }
    if ((g_lmac.sniffer_filter & fmask) == 0U) {
        return false;
    }

    uint8_t wr = g_lmac.snf_wr;
    uint8_t next = (uint8_t)((wr + 1U) & LMAC_SNF_RING_MASK);
    if (next == g_lmac.snf_rd) {
        g_lmac.stats.rx_nmi_drops++;
        return false;
    }

    uint16_t copy_len = (flen > LMAC_SNF_MAX_PAYLOAD) ? LMAC_SNF_MAX_PAYLOAD : flen;
    lmac_snf_pkt_t *dst = &g_lmac.snf_ring[wr];
    size_t rem = 12U + (size_t)copy_len;
    size_t avail = (size_t)((uintptr_t)g_lmac.rx_extradata - (uintptr_t)raw);
    const uint8_t *src = raw;
    uint8_t *out = dst->raw;

    while (rem > 0U) {
        size_t chunk = (rem > avail) ? avail : rem;
        memcpy(out, src, chunk);
        out += chunk;
        rem -= chunk;
        src = g_lmac.rx_frontdata;
        avail = rem;
    }
    dst->flen = flen;
    dst->copy_len = copy_len;

    __asm__ volatile("memw" ::: "memory");
    if (lmac_reg_read(LMAC_WDEV_RX_TSF_LO) != tsf_before ||
        (lmac_reg_read(LMAC_WDEV_INT_RAW) & LMAC_INT_RX_DONE) != 0U ||
        ((const uint32_t *)(const void *)dst->raw)[0] != w0 ||
        dst->raw[12] != fc0) {
        return false;
    }

    dst->raw[10] = (uint8_t)((dst->raw[10] & 0xF0U) | (g_lmac.cur_channel & 0x0FU));
    g_lmac.stats.rx_nmi_frames++;
    __asm__ volatile("memw" ::: "memory");
    g_lmac.snf_wr = next;
    return true;
}

#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
/* --------------------------------------------------------------------------
 * IRAM / NMI Fast TX Arming, Retry & Next-Slot Launch (Zero Flash Access)
 * -------------------------------------------------------------------------- */

void IRAM_ATTR lmac_tx_arm_hw_slot_fast(uint8_t q, lmac_tx_slot_t *slot)
{
    lmac_hw_txq_t *txq = &g_lmac.hw_txq[q];
    uint8_t ridx = slot->retries;
    if (ridx > LMAC_TX_DEFAULT_MAX_RETRIES) {
        ridx = LMAC_TX_DEFAULT_MAX_RETRIES;
    }

    uint8_t hw_rate = slot->retry_rate[ridx];
    uint16_t dur_us = slot->retry_dur[ridx];
    slot->hw_rate = hw_rate;

    /* Set 802.11 FC Retry bit (byte 1, bit 3) on retransmissions */
    if (ridx > 0U) {
        slot->hdr_buf[1] |= 0x08U;
    }

    /* Reset owner bit on all descriptors in the scatter-gather chain */
    for (lmac_lldesc_t *d = &slot->descs[0]; d != NULL; d = d->next) {
        d->ctrl |= LLDESC_OWNER;
    }

    /* Compute remaining MSDU lifetime in TU (1024 us), division-free */
    uint32_t now_us = lmac_reg_read(LMAC_WDEV_TIME);
    uint32_t elapsed_us = now_us - slot->enqueue_us;
    uint32_t rem_tu = (elapsed_us < LMAC_TX_LIFETIME_US)
                      ? ((LMAC_TX_LIFETIME_US - elapsed_us) >> 10)
                      : 10U;
    if (rem_tu < 10U) {
        rem_tu = 10U;
    }

    uint32_t desc_addr = (uint32_t)(uintptr_t)&slot->descs[0] & 0x3FFFFU;
    uint32_t link_word = desc_addr | LMAC_TXQ_LINK_VALID;

    if (hw_rate < 16U) {
        link_word |= LMAC_TXQ_LINK_LEGACY;
    }
    if ((slot->flags & ESP_LMAC_TX_FLAG_NO_ACK) == 0U) {
        link_word |= LMAC_TXQ_LINK_ACK_NORMAL;
    }
    if ((slot->flags & ESP_LMAC_TX_FLAG_USE_RTS) != 0U) {
        link_word |= LMAC_TXQ_LINK_USE_RTS;
    } else if ((slot->flags & ESP_LMAC_TX_FLAG_USE_CTS) != 0U) {
        link_word |= LMAC_TXQ_LINK_USE_CTS;
    }

    /* Write duration into 802.11 MAC header [2..3] */
    slot->hdr_buf[2] = (uint8_t)(dur_us & 0xFFU);
    slot->hdr_buf[3] = (uint8_t)(dur_us >> 8);

    uint32_t rate_word = ((uint32_t)slot->air_len & 0x0FFFU)
                         | (((uint32_t)hw_rate & 0x0FU) << 12)
                         | (((uint32_t)slot->hw_key_slot & 0xFFU) << 16)
                         | ((hw_rate >= 16U) ? BIT(24) : 0U);

    /* Division-free EDCA backoff: (rand & ((1<<cw)-1)) * 991/256 (~3.871); beacons use 0x7D / 100 TU */
    uint32_t backoff;
    if ((slot->flags & ESP_LMAC_TX_FLAG_BEACON) != 0U) {
        backoff = 0x7DU;
        rem_tu = 100U;
    } else {
        uint32_t cw_mask = (1U << (txq->cw & 0x0FU)) - 1U;
        uint32_t rnd = lmac_reg_read(LMAC_WDEV_HW_SEQ_RND) & cw_mask;
        backoff = (rnd * 991U) >> 8;
    }

    /* Arm TXQ registers in verified sequence before setting GO bits [31:30] */
    lmac_reg_write(LMAC_TXQ_LIFETIME(q), (rem_tu & 0xFFFU) << 12);
    lmac_reg_write(LMAC_TXQ_LINK(q), link_word);
    lmac_reg_write(LMAC_TXQ_DURATION(q), (uint32_t)dur_us << 16);
    lmac_reg_write(LMAC_TXQ_RATE(q), rate_word);
    if (hw_rate >= 16U) {
        uint32_t ht_gi = (hw_rate >= 24U) ? 0x87000000U : 0x07000000U;
        lmac_reg_write(LMAC_TXQ_HT_PLCP(q),
                       ((uint32_t)hw_rate & 7U) | (((uint32_t)slot->air_len & 0xFFFFU) << 8) | ht_gi);
    }
    lmac_reg_write(LMAC_TXQ_CONF(q), (backoff & 0x3FFU) << 12);

    txq->launch_us = now_us;
    if ((slot->hdr_buf[1] & LMAC_FC1_PROTECTED) != 0U &&
        (slot->hw_key_slot & LMAC_KEY_SLOT_MASK) == 0U) {
        uint8_t vif_idx = (slot->hw_key_slot >> 7) & 1U;
        uint32_t creg = LMAC_WDEV_CRYPTO_CONF0 + ((uint32_t)vif_idx << 2);
        uint32_t cval = lmac_reg_read(creg);
        if ((cval & LMAC_CRYPTO_TX_ENC) == 0U) {
            lmac_reg_write(creg, cval | LMAC_CRYPTO_TX_ENC);
            g_lmac.sw_prot_bypass_vif = (uint8_t)(vif_idx + 1U);
        }
    }
    lmac_reg_write(LMAC_TXQ_LINK(q), link_word | LMAC_TXQ_LINK_GO);
}

static bool IRAM_ATTR nmi_handle_tx_done(uint32_t tx_status)
{
    uint8_t q = (uint8_t)((tx_status >> 8) & 0x0FU);
    uint8_t cause = (uint8_t)(tx_status >> 28);
    uint8_t sub = (uint8_t)((tx_status >> 16) & 0xFFU);

    if (q >= LMAC_HW_TXQ_COUNT) {
        return false;
    }

    lmac_hw_txq_t *txq = &g_lmac.hw_txq[q];
    lmac_tx_slot_t *slot = txq->active;
    if (slot == NULL) {
        return false;
    }

    uint8_t ok = 0U;
    int8_t ack_rssi = (int8_t)0x7F;

    if (cause == 0U) {
        uint32_t rssi_reg = lmac_reg_read(LMAC_WDEV_TX_ACK_RSSI);
        if ((rssi_reg & 0x01000000U) != 0U) {
            ack_rssi = (int8_t)((int32_t)((rssi_reg >> 16) & 0xFFU) - 96);
        }
        ok = 1U;
    } else {
        /* Retryable timeout/error: cause 2 (CTS timeout), 5 (ACK timeout), or sub 1/3 on 1/4 */
        bool retryable = (cause == 2U || cause == 5U ||
                          ((cause == 1U || cause == 4U) && (sub == 1U || sub == 3U)));
        uint32_t elapsed = lmac_reg_read(LMAC_WDEV_TIME) - slot->enqueue_us;

        if (retryable && slot->retries < slot->max_retries && elapsed < LMAC_TX_LIFETIME_US) {
            slot->retries++;
            g_lmac.stats.tx_retries++;
            if (txq->cw < txq->cw_max) {
                txq->cw++;
            }
            lmac_tx_arm_hw_slot_fast(q, slot);
            return false;
        }
    }

    /* Slot completed: reset CW, immediately launch next queued slot in NMI */
    txq->cw = txq->cw_min;
    slot->done_ok = ok;
    slot->done_ack_rssi = ack_rssi;
    slot->next = NULL;

    /* If SW-protected TX bypassed HW crypto on the opposite active VIF, restore it on completion */
    if (g_lmac.sw_prot_bypass_vif != 0U) {
        lmac_reg_clr(LMAC_WDEV_CRYPTO_CONF0 + (((uint32_t)g_lmac.sw_prot_bypass_vif - 1U) << 2),
                     LMAC_CRYPTO_TX_ENC);
        g_lmac.sw_prot_bypass_vif = 0U;
    }

    lmac_tx_slot_t *next_slot = txq->q_head;
    if (next_slot != NULL && !g_lmac.rf_closed) {
        txq->q_head = next_slot->next;
        if (txq->q_head == NULL) {
            txq->q_tail = NULL;
        }
        next_slot->next = NULL;
        txq->active = next_slot;
        lmac_tx_arm_hw_slot_fast(q, next_slot);
    } else {
        txq->active = NULL;
    }

    /* Append finished slot to FIFO done list for worker TRC + release + done_cb */
    if (g_lmac.tx_done_tail != NULL) {
        g_lmac.tx_done_tail->next = slot;
        g_lmac.tx_done_tail = slot;
    } else {
        g_lmac.tx_done_head = slot;
        g_lmac.tx_done_tail = slot;
    }

    return true;
}
#endif

/* --------------------------------------------------------------------------
 * Level-3 NMI Entry Point (Called by _xt_nmi in xtensa_vectors.S)
 * -------------------------------------------------------------------------- */

void IRAM_ATTR wDev_ProcessFiq(void)
{
    uint32_t status = lmac_reg_read(LMAC_WDEV_INT_STATUS);
    uint32_t saved_ena = lmac_reg_read(LMAC_WDEV_INT_ENA);

    NMIIrqIsOn++;
    lmac_reg_write(LMAC_WDEV_INT_ENA, 0U);

    uint32_t tx_status = lmac_reg_read(LMAC_WDEV_TX_STATUS);
    g_lmac.stats.nmi_count++;

    /*
     * Priority 1: WDEV_TSF0_REACH_INT (BIT 27) — MAC Timer 0 (task_wdt NMI WDT).
     * port.c leaves BIT(27) unmasked even inside vPortETSIntrLock(), so this may
     * preempt a lower-level NMI or run with NMIIrqIsOn > 1.
     */
    if ((status & LMAC_INT_MACTIM0) != 0U) {
        if (s_mac_tim0_cb != NULL) {
            s_mac_tim0_cb();
        }
        if (NMIIrqIsOn > 1U) {
            lmac_reg_write(LMAC_DPORT_NMI_INT_ENA, 0U);
            NMIIrqIsOn--;
            lmac_reg_write(LMAC_WDEV_INT_ENA, LMAC_INT_MACTIM0);
            lmac_reg_write(LMAC_WDEV_INT_CLR, LMAC_INT_MACTIM0);
            return;
        }
        lmac_reg_write(LMAC_WDEV_INT_CLR, LMAC_INT_MACTIM0);
        status &= ~LMAC_INT_MACTIM0;
    }

    /* Keep MAC Timer 0 armed while processing remaining NMI events */
    if (NMIIrqIsOn == 1U) {
        lmac_reg_write(LMAC_WDEV_INT_ENA, LMAC_INT_MACTIM0);
    }

    bool need_notify = false;

    if (status != 0U) {
        /* Priority 2: MAC Timer 1 (BIT 26) — SoftAP TBTT or registered callback */
        if ((status & LMAC_INT_MACTIM1) != 0U) {
            if (s_mac_tim1_cb != NULL) {
                s_mac_tim1_cb();
            }
            if (g_lmac.beacon.active) {
                lmac_nmi_evt_t ev;
                ev.type = LMAC_NMI_EVT_TBTT;
                ev.a = ESP_LMAC_VIF_AP;
                ev.b = 0U;
                ev.c = 0U;
                ev.d = 0;
                ev.len = 0U;
                if (nmi_ring_push(&ev)) {
                    need_notify = true;
                }
            }
        }

        /* Normal mode: acknowledge latched status before draining so new arrivals re-pend */
        if (!g_lmac.sniffer_mode) {
            lmac_reg_write(LMAC_WDEV_INT_CLR, status);
        }

        /* Priority 3: TX Complete / ACK Timeout / CTS Timeout / Error (BIT 19) */
        if ((status & LMAC_INT_TX_DONE) != 0U) {
#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
            if (nmi_handle_tx_done(tx_status)) {
                need_notify = true;
            }
#else
            uint8_t slot = (uint8_t)((tx_status >> 8) & 0x0FU);
            uint8_t cause = (uint8_t)(tx_status >> 28);
            uint8_t sub = (uint8_t)((tx_status >> 16) & 0xFFU);
            uint32_t rssi_reg = lmac_reg_read(LMAC_WDEV_TX_ACK_RSSI);
            int8_t ack_rssi = ((rssi_reg & 0x01000000U) != 0U)
                              ? (int8_t)((int32_t)((rssi_reg >> 16) & 0xFFU) - 96)
                              : (int8_t)0x7F;

            lmac_nmi_evt_t ev;
            ev.type = LMAC_NMI_EVT_TX_DONE;
            ev.a = slot;
            ev.b = cause;
            ev.c = sub;
            ev.d = (int16_t)ack_rssi;
            ev.len = 0U;
            if (nmi_ring_push(&ev)) {
                need_notify = true;
            }
#endif
        }

        /* Priority 4: Main RX Frame Complete (BIT 8) or Sniffer-End Capture (BIT 2 without BIT 8) */
        if ((status & LMAC_INT_RX_DONE) != 0U) {
            if (nmi_drain_rx()) {
                need_notify = true;
            }
        } else if ((status & LMAC_INT_SNIFFER_END) != 0U && g_lmac.sniffer_mode != 0U) {
            if (nmi_drain_sniffer_end()) {
                need_notify = true;
            }
        }

        /* Priority 5: Hardware TX Queue Timeout (BIT 29) */
        if ((status & LMAC_INT_TX_TIMEOUT) != 0U) {
            lmac_nmi_evt_t ev;
            ev.type = LMAC_NMI_EVT_TX_TIMEOUT;
            ev.a = 0U;
            ev.b = 0U;
            ev.c = 0U;
            ev.d = 0;
            ev.len = 0U;
            if (nmi_ring_push(&ev)) {
                need_notify = true;
            }
        }

        if (need_notify) {
            g_lmac.nmi_notify_pending = 1U;
            PendSV(2);
        }
    }

    /* Sniffer mode: acknowledge status after drain */
    if (g_lmac.sniffer_mode) {
        lmac_reg_write(LMAC_WDEV_INT_CLR, status);
    }

    /*
     * Mandatory _xt_nmi epilogue invariant:
     * Restore WDEV_INT_ENA, then write 0 to DPORT NMI enable (0x3FF00000) so no
     * back-to-back NMI can fire while _xt_nmi pops HESF_AR; _xt_nmi writes 1
     * back to 0x3FF00000 immediately before rfi 3.
     */
    lmac_reg_write(LMAC_WDEV_INT_ENA, saved_ena);
    lmac_reg_write(LMAC_DPORT_NMI_INT_ENA, 0U);
    NMIIrqIsOn--;
}

/* --------------------------------------------------------------------------
 * Level-1 SoftISR Handoff (Called by SoftIsrHdl in port.c on ETS_SOFT_INUM)
 * -------------------------------------------------------------------------- */

int IRAM_ATTR MacIsrSigPostDefHdl(void)
{
    if (g_lmac.nmi_notify_pending == 0U) {
        return 0;
    }

    g_lmac.nmi_notify_pending = 0U;
    __asm__ volatile("memw" ::: "memory");

    if (g_lmac.cbs.notify_from_isr != NULL) {
        return g_lmac.cbs.notify_from_isr(g_lmac.cbs.ctx);
    }
    return 0;
}

/* --------------------------------------------------------------------------
 * Hardware MAC Timers (TSF0 = task_wdt NMI WDT, TSF1 = SoftAP TBTT) & TSF
 * -------------------------------------------------------------------------- */

void IRAM_ATTR wDev_MacTimSetFunc(void *cb)
{
    lmac_reg_set(LMAC_WDEV_MACTIM0_CONF, BIT(31));
    s_mac_tim0_cb = (void (*)(void))cb;
}

void IRAM_ATTR wDev_MacTimArm(uint32_t delta_us)
{
    vPortETSIntrLock();
    uint32_t lo = lmac_reg_read(LMAC_WDEV_TSF0_LO);
    uint32_t hi = lmac_reg_read(LMAC_WDEV_TSF0_HI);
    uint32_t target_lo = lo + delta_us;
    uint32_t target_hi = (target_lo <= lo) ? (hi + 1U) : hi;

    lmac_reg_write(LMAC_WDEV_MACTIM0_TARGET_LO, target_lo);
    lmac_reg_write(LMAC_WDEV_MACTIM0_TARGET_HI, target_hi);
    lmac_reg_set(LMAC_WDEV_MACTIM0_ARM, BIT(31));
    vPortETSIntrUnlock();
}

void lmac_mactim1_set_func(void (*cb)(void))
{
    lmac_reg_set(LMAC_WDEV_TSF1_CONF, BIT(31));
    s_mac_tim1_cb = cb;
}

void lmac_mactim1_arm(uint32_t delta_us)
{
    vPortETSIntrLock();
    uint32_t lo = lmac_reg_read(LMAC_WDEV_TSF1_LO);
    uint32_t hi = lmac_reg_read(LMAC_WDEV_TSF1_HI);
    uint32_t target_lo = lo + delta_us;
    uint32_t target_hi = (target_lo <= lo) ? (hi + 1U) : hi;

    lmac_reg_write(LMAC_WDEV_MACTIM1_TARGET_LO, target_lo);
    lmac_reg_write(LMAC_WDEV_MACTIM1_TARGET_HI, target_hi);
    lmac_reg_set(LMAC_WDEV_MACTIM1_ARM, BIT(31));
    vPortETSIntrUnlock();
}

void lmac_mactim1_disarm(void)
{
    vPortETSIntrLock();
    lmac_reg_clr(LMAC_WDEV_MACTIM1_ARM, BIT(31));
    vPortETSIntrUnlock();
}

uint8_t esp_lmac_get_channel(void)
{
    return g_lmac.cur_channel;
}
