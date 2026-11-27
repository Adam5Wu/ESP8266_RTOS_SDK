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
 * File-Local IRAM / NMI Hardware & Protocol Constants
 * -------------------------------------------------------------------------- */

#define LMAC_PENDSV_REQ_WIFI_SOFTISR     2           /* PendSV request ID for Level-1 Wi-Fi SoftISR */
#define LMAC_RX_DESC_MAX_BITS            32U         /* Bit width of uint32_t rx_avail_mask */
#define LMAC_RX_DESC_ALL_MASK            0xFFFFFFFFU /* Full-width mask when rx_buf_num >= 32 */
#define LMAC_RX_STAT_INFO_MASK           0xFFU       /* Low status byte of LMAC_WDEV_RX_STAT_INFO */
#define LMAC_RXCTRL_W0_LEG_LEN_CLEAR     0xF000FFFFU /* Clears rx_ctrl w0[27:16] legacy_length */
#define LMAC_RXCTRL_W0_VIF_MASK          0x0FU       /* 4-bit hardware VIF/BSSID match mask in w0[31:28] */
#define LMAC_RXCTRL_W1_MCS_MASK          0x7FU       /* 7-bit 802.11n MCS index in rx_ctrl w1[6:0] */
#define LMAC_RXCTRL_W1_HT20_1SS_MCS_MAX  8U          /* ESP8266 1x1 PHY supports MCS 0..7 only */
#define LMAC_RXCTRL_W1_UNSUP_HT_MASK     0x40000080U /* w1[30]=LDPC fec_coding | w1[7]=HT40 cwb */
#define LMAC_RXCTRL_W1_HT_LEN_MASK       0xFFFFU     /* 16-bit HT_length mask in rx_ctrl word 1 [23:8] */
#define LMAC_RXCTRL_W1_HT_LEN_CLEAR      0xFF0000FFU /* Clears rx_ctrl w1[23:8] HT_length */
#define LMAC_RXCTRL_W2_CH_MASK           0x0FU       /* 4-bit primary channel mask in rx_ctrl word 2 [19:16] */
#define LMAC_RXCTRL_W2_CH_STATE_CLEAR    0xFFF0FF00U /* Clears w2[19:16] channel & w2[7:0] rxend_state */
#define LMAC_RXCTRL_CH_BYTE_OFF          10U         /* Byte offset of channel nibble inside 12-B rx_ctrl */
#define LMAC_RXCTRL_CH_BYTE_KEEP         0xF0U       /* Preserves upper nibble of rx_ctrl byte 10 */
#define LMAC_DMA_WORD_ALIGN_MASK         3U          /* 4-byte DMA padding between A-MPDU subframes */
#define LMAC_AMPDU_INFO_CNT_SHIFT        14U         /* LLDESC_LEN_SHIFT (12) + 2: 4-B subframe entry count */
#define LMAC_AMPDU_INFO_CNT_MASK         0x3FFU      /* 10-bit max subframe info entry count */
#define LMAC_AMPDU_INFO_WORD_SHIFT       2U          /* Shift dividing info buffer bytes by 4 B/entry */
#define LMAC_AMPDU_ENTRY_STATE_MASK      0xFFU       /* Subframe info dword [7:0]: rxend_state */
#define LMAC_AMPDU_ENTRY_LEN_SHIFT       8U          /* Subframe info dword [19:8]: subframe PSDU len */
#define LMAC_AMPDU_ENTRY_LEN_MASK        0xFFFU      /* 12-bit subframe PSDU length mask */
#define LMAC_TXQ_CW_SHIFT_MASK           0x0FU       /* Bounds CW exponent to 0..15 before (1U << cw) */
#define LMAC_TXQ_RATE_KEY_MASK           0xFFU       /* 8-bit key slot mask in TXQ_RATE [23:16] */
#define LMAC_KEY_SLOT_AP_SHIFT           7U          /* Bit position of LMAC_KEY_SLOT_AP_BIT (0x80) */
#define LMAC_TXQ_HT_PLCP_LEN_MASK        0xFFFFU     /* 16-bit air_len mask in TXQ_HT_PLCP [23:8] */
#define LMAC_TX_ACK_RSSI_BYTE_MASK       0xFFU       /* 8-bit raw ACK RSSI byte in WDEV_TX_ACK_RSSI [23:16] */
#define LMAC_NMI_BACKOFF_SCALE_NUM       991U        /* Division-free EDCA backoff multiplier (~3.871 = 991/256) */
#define LMAC_NMI_BACKOFF_SCALE_SHIFT     8U          /* Right-shift divisor (256) for IRAM NMI backoff */
#define LMAC_IEEE80211_FC0_VER_TYPE_MASK 0x0FU       /* FC0 Protocol Version [1:0] | Frame Type [3:2] */
#define LMAC_IEEE80211_FC0_TYPE_MGMT     0x00U       /* FC0 Ver=0, Type=0 (Management) */
#define LMAC_IEEE80211_FC0_TYPE_CTRL     0x04U       /* FC0 Ver=0, Type=1 (Control) */
#define LMAC_IEEE80211_FC0_TYPE_DATA     0x08U       /* FC0 Ver=0, Type=2 (Data) */
#define LMAC_IEEE80211_FC0_SUBTYPE_SHIFT 4U          /* FC0 [7:4] Frame Subtype shift */
#define LMAC_IEEE80211_CTRL_SUBTYPE_MIN  7U          /* Control subtypes 0..6 are reserved in 802.11 */
#define LMAC_SNF_CTRL_FILTER_BIT_BASE    16U         /* WIFI_PROMIS_CTRL_FILTER_MASK bit = 16 + subtype */
#define LMAC_IEEE80211_HDR_FC1_OFF       1U          /* 802.11 Frame Control byte 1 offset (Retry/MoreFrag/Prot) */
#define LMAC_IEEE80211_FC1_MORE_FRAG     0x04U       /* FC1 bit 2: More Fragments flag */
#define LMAC_IEEE80211_HDR_DUR_LO_OFF    2U          /* 802.11 Duration/ID low byte offset */
#define LMAC_IEEE80211_HDR_DUR_HI_OFF    3U          /* 802.11 Duration/ID high byte offset */
#define LMAC_IEEE80211_HDR_SEQ_LO_OFF    22U         /* 802.11 Sequence Control byte 0 (FragNum[3:0]) */
#define LMAC_IEEE80211_SEQ_FRAG_MASK     0x0FU       /* Sequence Control [3:0] Fragment Number mask */

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

/**
 * @brief Link RX descriptor @p idx back into the circular DMA ring and mark it available.
 *
 * IRAM-resident with zero flash access (compiled with -fno-jump-tables).
 * Precondition: caller must run in Level-3 NMI context or hold vPortETSIntrLock().
 *
 * @param idx  Descriptor index in g_lmac.rx_descs[] (0 .. rx_buf_num - 1).
 */
void IRAM_ATTR lmac_rx_set_desc_bit_locked(uint8_t idx)
{
    uint8_t n = g_lmac.cfg.rx_buf_num;
    uint8_t prev = (idx == 0U) ? (uint8_t)(n - 1U) : (uint8_t)(idx - 1U);

    g_lmac.rx_descs[prev].next = &g_lmac.rx_descs[idx];
    g_lmac.rx_avail_mask |= (1U << idx);
}

/**
 * @brief Unlink the predecessor of RX descriptor @p idx and mark it unavailable to DMA.
 *
 * Breaking the predecessor's next pointer prevents WDEV DMA from advancing into a
 * descriptor currently pinned by the CPU. Marked always_inline + IRAM_ATTR so -Og/-O0
 * builds never emit an out-of-line flash call from Level-3 NMI.
 * Precondition: caller must run in Level-3 NMI context or hold vPortETSIntrLock().
 *
 * @param idx  Descriptor index in g_lmac.rx_descs[] (0 .. rx_buf_num - 1).
 */
static inline __attribute__((always_inline)) void IRAM_ATTR lmac_rx_clear_desc_bit_locked(uint8_t idx)
{
    uint8_t n = g_lmac.cfg.rx_buf_num;
    uint8_t prev = (idx == 0U) ? (uint8_t)(n - 1U) : (uint8_t)(idx - 1U);

    g_lmac.rx_descs[prev].next = NULL;
    g_lmac.rx_avail_mask &= ~(1U << idx);
}

/**
 * @brief Reposition WDEV_RX_LINK_HEAD to the longest contiguous free RX descriptor run.
 *
 * Keeps the existing RX head untouched while it and its next two successors are all
 * linked and DMA-owned (enough room for a maximum-size 802.11 MPDU). Otherwise scans
 * the circular rx_avail_mask without division to find the longest contiguous free run
 * and updates LMAC_WDEV_RX_LINK_HEAD if DMA is not actively writing to the current head.
 *
 * IRAM-resident, division-free, zero flash access (-fno-jump-tables).
 * Precondition: caller must run in Level-3 NMI context or hold vPortETSIntrLock().
 */
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

    /*
     * Circular longest-run bitmask scan (division-free, O(longest_run) shifts):
     *   1. Duplicate the n-bit rx_avail_mask into bits [2n-1:n] so any contiguous run
     *      wrapping from index (n - 1) to 0 becomes a linear run in `doubled`.
     *   2. Repeatedly intersect `runs` with `(runs >> 1)`. Each iteration shrinks every
     *      run of 1-bits by 1 while keeping its surviving bit anchored at the run's
     *      starting index. The loop stops on the last non-zero mask, whose set bits
     *      mark the start indices of all maximal-length runs.
     *   3. Mask to the canonical ring indices [n-1:0] and select the highest set bit,
     *      matching vendor wDev_Check_And_Move_hwbuf().
     */
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

    uint32_t valid_mask = (n >= LMAC_RX_DESC_MAX_BITS) ? LMAC_RX_DESC_ALL_MASK : ((1U << n) - 1U);
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

/**
 * @brief Enqueue an event into the lock-free SPSC Level-3 NMI -> worker ring buffer.
 *
 * IRAM-resident with zero flash access. Must only be called from the single producer
 * (Level-3 NMI inside wDev_ProcessFiq) while the Wi-Fi worker task is the sole consumer
 * advancing g_lmac.nmi_rd.
 *
 * @param ev  Pointer to the 8-byte event record to copy into the ring.
 * @return    true if enqueued; false if the ring is full (1 slot kept open to distinguish full/empty).
 */
static bool IRAM_ATTR nmi_ring_push(const lmac_nmi_evt_t *ev)
{
    uint8_t wr = g_lmac.nmi_wr;
    uint8_t next = (uint8_t)((wr + 1U) & LMAC_NMI_RING_MASK);

    if (next == g_lmac.nmi_rd) {
        return false;
    }

    /*
     * Lock-free SPSC release ordering: write the 8-byte event payload first, then issue
     * an Xtensa `memw` barrier so the DRAM stores complete before publishing `nmi_wr`.
     * The worker consumer reads `nmi_wr` before loading `nmi_ring[rd]`.
     */
    g_lmac.nmi_ring[wr] = *ev;
    __asm__ volatile("memw" ::: "memory");
    g_lmac.nmi_wr = next;
    return true;
}

/**
 * @brief Immediately return a circular range of RX descriptors to hardware DMA ownership.
 *
 * Used in Level-3 NMI to recycle descriptors belonging to dropped, malformed, or
 * ring-overflow frames without waiting for the worker task. IRAM-resident, zero flash
 * access. Precondition: called from Level-3 NMI context.
 *
 * @param start_idx  First descriptor index in g_lmac.rx_descs[].
 * @param cnt        Number of consecutive circular descriptors to recycle.
 */
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
 * Walks `rx_ampdu_descs[rx_ampdu_head_idx]`, tracks the packed 4-byte-aligned DMA
 * offset of each valid subframe inside `rx_frontdata`, enforces CVE-2020-26146
 * fragment drops, allocates handles via a branchless 5-step CTZ lookup in the
 * 32-entry `rx_subframes` pool, tracks 5-bit `LLDESC_OFF_MASK` refcounts on shared
 * `rx_descs`, immediately restores `LLDESC_OWNER` on `rx_ampdu_descs`, and recycles
 * any unreferenced `rx_descs`.
 *
 * IRAM-resident (`__attribute__((noinline)) IRAM_ATTR`), zero flash access
 * (`-fno-jump-tables`), called from Level-3 NMI context.
 *
 * @param start_idx  First circular RX descriptor index claimed for this A-MPDU chain.
 * @param cnt        Number of consecutive circular RX descriptors claimed.
 * @param w0         Word 0 of the 12-byte aggregate `wifi_pkt_rx_ctrl_t` header.
 * @param w1         Word 1 of the 12-byte aggregate `wifi_pkt_rx_ctrl_t` header.
 * @param w2         Word 2 of the 12-byte aggregate `wifi_pkt_rx_ctrl_t` header.
 * @param ch         Active primary 2.4 GHz channel stamped into each subframe header.
 * @return           true if at least one `LMAC_NMI_EVT_RX_AMPDU` event was pushed.
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
    /* Each subframe info entry is 4 bytes, so dword count = byte_len[23:12] / 4 = ctrl[23:14] */
    uint16_t sub_cnt = ((actrl & LLDESC_EOF) != 0U)
                       ? (uint16_t)((actrl >> LMAC_AMPDU_INFO_CNT_SHIFT) & LMAC_AMPDU_INFO_CNT_MASK)
                       : 0U;
    uint16_t max_entries = (uint16_t)(abuf_len >> LMAC_AMPDU_INFO_WORD_SHIFT);
    if (sub_cnt > max_entries) {
        sub_cnt = max_entries;
    }

    uint16_t buf_len = g_lmac.cfg.rx_buf_len;
    uint8_t sf_desc_idx = start_idx;
    uint16_t sf_off = sizeof(wifi_pkt_rx_ctrl_t);
    uint16_t rem_in_desc = (uint16_t)(buf_len - sf_off);
    uint8_t consumed_descs = 1U;
    /*
     * WDEV hardware strips trailing crypto MIC/ICV + FCS (12 B for protected frames,
     * 4 B FCS only for plaintext) before DMAing each valid subframe padded to a 4-byte
     * boundary into rx_frontdata; inspect the first subframe's FC1 Protected bit to
     * compute the exact per-subframe DMA stride.
     */
    uint8_t first_fc1 = descs[start_idx].buf[sizeof(wifi_pkt_rx_ctrl_t) + LMAC_IEEE80211_HDR_FC1_OFF];
    uint16_t strip = (!g_lmac.sniffer_mode && ((first_fc1 & LMAC_FC1_PROTECTED) != 0U))
                     ? LMAC_AMPDU_STRIP_CRYPTO
                     : LMAC_AMPDU_STRIP_PLAIN;
    int16_t freq_off = (!g_lmac.sniffer_mode) ? phy_get_bb_freqoffset() : 0;
    const uint32_t *entries = (const uint32_t *)(const void *)adesc->buf;
    bool pushed_any = false;

    for (uint16_t si = 0U; si < sub_cnt; si++) {
        uint32_t entry = entries[si];
        uint8_t sub_state = (uint8_t)(entry & LMAC_AMPDU_ENTRY_STATE_MASK);
        uint16_t sub_len = (uint16_t)((entry >> LMAC_AMPDU_ENTRY_LEN_SHIFT) & LMAC_AMPDU_ENTRY_LEN_MASK);

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

        uint16_t dma_bytes = (uint16_t)(((sub_len - strip) + LMAC_DMA_WORD_ALIGN_MASK) & ~LMAC_DMA_WORD_ALIGN_MASK);
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

        /* Advance DMA cursor across descriptor boundaries to record this subframe's span */
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

        /*
         * Read 802.11 FC1 (+1) and Sequence Control LSB (+22) safely across descriptor wrap:
         * cur_start_off and buf_len are both 4-byte aligned so +1 always stays in cur_start_desc,
         * while +22 may wrap into the next circular descriptor.
         */
        uint8_t sf_fc1 = descs[cur_start_desc].buf[cur_start_off + LMAC_IEEE80211_HDR_FC1_OFF];
        uint8_t sf_seq_lo;
        if ((uint16_t)(cur_start_off + LMAC_IEEE80211_HDR_SEQ_LO_OFF) < buf_len) {
            sf_seq_lo = descs[cur_start_desc].buf[cur_start_off + LMAC_IEEE80211_HDR_SEQ_LO_OFF];
        } else {
            uint8_t next_d = (uint8_t)(cur_start_desc + 1U);
            if (next_d >= n) {
                next_d = 0U;
            }
            sf_seq_lo = descs[next_d].buf[cur_start_off + LMAC_IEEE80211_HDR_SEQ_LO_OFF - buf_len];
        }

        /* CVE-2020-26146: drop fragmented A-MPDU subframes (MoreFrag != 0 || FragNum != 0) */
        if (!g_lmac.sniffer_mode &&
            ((sf_fc1 & LMAC_IEEE80211_FC1_MORE_FRAG) != 0U ||
             (sf_seq_lo & LMAC_IEEE80211_SEQ_FRAG_MASK) != 0U)) {
            g_lmac.stats.rx_nmi_drops++;
            continue;
        }

        /* Branchless 5-step binary-search CTZ lookup for lowest free bit in 32-entry pool */
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

        /* Guard 5-bit LLDESC_OFF_MASK descriptor refcounts against saturation (< 31) */
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

        /* Synthesize per-subframe 12-B rx_ctrl header with subframe length, channel, and state */
        lmac_rx_subframe_t *sf = &g_lmac.rx_subframes[sidx];
        sf->rx_ctrl_w[0] = ((w0 & LMAC_RXCTRL_W0_HT_MASK) == 0U)
                           ? ((w0 & LMAC_RXCTRL_W0_LEG_LEN_CLEAR) | ((uint32_t)sub_len << LMAC_RXCTRL_W0_LEG_LEN_SH))
                           : w0;
        sf->rx_ctrl_w[1] = ((w0 & LMAC_RXCTRL_W0_HT_MASK) != 0U)
                           ? ((w1 & LMAC_RXCTRL_W1_HT_LEN_CLEAR) | ((uint32_t)sub_len << LMAC_RXCTRL_W1_HT_LEN_SH))
                           : w1;
        sf->rx_ctrl_w[2] = (w2 & LMAC_RXCTRL_W2_CH_STATE_CLEAR) |
                           (((uint32_t)ch & LMAC_RXCTRL_W2_CH_MASK) << LMAC_RXCTRL_W2_CH_SHIFT) |
                           (uint32_t)sub_state;
        sf->start_off = cur_start_off;
        sf->handle.rx_ctrl = NULL;
        sf->handle.frame = NULL;
        sf->handle.len = (!g_lmac.sniffer_mode && sub_len >= LMAC_IEEE80211_FCS_LEN)
                         ? (uint16_t)(sub_len - LMAC_IEEE80211_FCS_LEN)
                         : sub_len;
        sf->handle.freq_offset = freq_off;
        sf->handle.vif_match = (uint8_t)((w0 >> LMAC_RXCTRL_W0_VIF_SHIFT) & LMAC_RXCTRL_W0_VIF_MASK);
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
            /* Commit pool slot and increment 5-bit refcount on every descriptor spanned by subframe */
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

    /* Immediately recycle any rx_descs whose refcount remained 0 (dropped/unaccepted subframes) */
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

/**
 * @brief Drain hardware-completed RX MPDUs in Level-3 NMI and post descriptor events.
 *
 * Walks circular descriptors from `g_lmac.rx_head_idx` up to `LMAC_WDEV_RX_LAST_DESC`,
 * claims each descriptor away from WDEV DMA, stamps `g_lmac.cur_channel` into the 12-byte
 * hardware `rx_ctrl` header, dispatches aggregated frames to `nmi_drain_ampdu()` when
 * `CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED` is enabled (otherwise drops A-MPDUs), filters
 * invalid/truncated frames (`LMAC_RXSTATE_OK`, `LMAC_RXSTATE_ALT1`, `LMAC_RXSTATE_ALT2`),
 * and pushes accepted descriptor ranges into the lock-free NMI ring (initializing 5-bit
 * `LLDESC_OFF_MASK` refcount = 1 under `AMPDU_RX` so `esp_lmac_rx_free()` handles single
 * and shared descriptors uniformly; recycling rejected/overflow ranges immediately).
 * Runs in <10 us with zero heap allocation, zero frame copies, and zero flash access
 * (IRAM-resident, `-fno-jump-tables`, Level-3 NMI context).
 *
 * @return  true if at least one RX event was pushed and the worker needs notification.
 */
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

        /*
         * Claim all descriptors belonging to this MPDU atomically in NMI:
         * clearing LLDESC_OWNER|LLDESC_OFF_MASK and unlinking via rx_avail_mask
         * pins the backing DRAM slice until the worker calls esp_lmac_rx_free()
         * (or nmi_recycle_desc_range() reclaims it below on drop).
         */
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

        /*
         * Inspect the 12-byte hardware rx_ctrl header in DRAM and stamp the active
         * primary channel into word 2 bits [19:16] right here in NMI: WDEV hardware
         * does not populate rx_ctrl->channel, and stamping at RX completion ensures
         * scan frames retain their reception channel even if the worker hops channels
         * before draining the event ring.
         */
        uint32_t *rxw = (uint32_t *)(void *)first->buf;
        uint32_t w0 = rxw[0];
        uint32_t w1 = rxw[1];
        uint32_t w2 = rxw[2];

        rxw[2] = (w2 & LMAC_RXCTRL_W2_CH_CLEAR)
                 | (((uint32_t)ch & LMAC_RXCTRL_W2_CH_MASK) << LMAC_RXCTRL_W2_CH_SHIFT);

        uint16_t flen = ((w0 & LMAC_RXCTRL_W0_HT_MASK) != 0U)
                        ? (uint16_t)((w1 >> LMAC_RXCTRL_W1_HT_LEN_SH) & LMAC_RXCTRL_W1_HT_LEN_MASK)
                        : (uint16_t)((w0 >> LMAC_RXCTRL_W0_LEG_LEN_SH) & LMAC_RXCTRL_W0_LEG_LEN_MASK);
        uint8_t rx_state = (uint8_t)(w2 & LMAC_RXCTRL_W2_STATE_MASK);
        bool is_ampdu = ((w1 & LMAC_RXCTRL_W1_AMPDU_BIT) != 0U);
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

        bool accept = reached_eof
                      && (flen >= LMAC_IEEE80211_MIN_MPDU_LEN)
                      && (flen <= LMAC_IEEE80211_MAX_MPDU_LEN)
                      && (!is_ampdu);
        if (accept && !g_lmac.sniffer_mode) {
            /* Match vendor wDev_ProcessFiq valid rxend_state check: 0, 0x32 ('2'), 0xF5 (-11) */
            if (rx_state != LMAC_RXSTATE_OK && rx_state != LMAC_RXSTATE_ALT1 && rx_state != LMAC_RXSTATE_ALT2) {
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
                /* Initialize 5-bit LLDESC_OFF_MASK refcount = 1 for uniform esp_lmac_rx_free() handling */
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
 * @brief Capture a sniffer-mode non-RX_DONE frame on `LMAC_INT_SNIFFER_END` (BIT(2)).
 *
 * WDEV delivers control frames and filtered MPDUs into `rx_head->buf` without
 * advancing `LMAC_WDEV_RX_LAST_DESC` or clearing `LLDESC_OWNER`. Because subsequent
 * over-the-air arrivals overwrite `rx_head->buf` within SIFS, NMI validates
 * `LMAC_WDEV_RX_STAT_INFO` (`LMAC_RX_STAT_OK` or `LMAC_RX_STAT_SNIFFER_OK`, rejecting
 * error states), filters unsupported HT40/LDPC/multi-stream-MIMO frames, pre-filters
 * against `sniffer_filter` / `sniffer_ctrl_filter`, copies `12 + min(flen, 112)` bytes
 * (handling circular wrap across `rx_extradata`) into `snf_ring`, and guards against
 * torn DMA overwrites via `LMAC_WDEV_RX_TSF_LO`, `INT_RAW`, and post-copy header checks.
 *
 * IRAM-resident (`__attribute__((noinline)) IRAM_ATTR`), zero flash access
 * (`-fno-jump-tables`), called from Level-3 NMI context.
 *
 * @return  true if a packet was committed to `snf_ring` and the worker should be notified.
 */
static bool __attribute__((noinline)) IRAM_ATTR nmi_drain_sniffer_end(void)
{
    uint32_t sinfo = lmac_reg_read(LMAC_WDEV_RX_STAT_INFO) & LMAC_RX_STAT_INFO_MASK;
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
    if ((w1 & LMAC_RXCTRL_W1_AMPDU_BIT) != 0U) {
        return false;
    }

    uint16_t flen;
    if ((w0 & LMAC_RXCTRL_W0_HT_MASK) != 0U) {
        /* Reject HT40 (cwb), LDPC (fec_coding), and multi-stream MIMO (MCS >= 8) unsupported by 1x1 PHY */
        if ((w1 & LMAC_RXCTRL_W1_UNSUP_HT_MASK) != 0U ||
            (w1 & LMAC_RXCTRL_W1_MCS_MASK) >= LMAC_RXCTRL_W1_HT20_1SS_MCS_MAX) {
            return false;
        }
        flen = (uint16_t)((w1 >> LMAC_RXCTRL_W1_HT_LEN_SH) & LMAC_RXCTRL_W1_HT_LEN_MASK);
    } else {
        flen = (uint16_t)((w0 >> LMAC_RXCTRL_W0_LEG_LEN_SH) & LMAC_RXCTRL_W0_LEG_LEN_MASK);
    }
    if (flen < LMAC_IEEE80211_MIN_MPDU_LEN || flen > LMAC_IEEE80211_MAX_MPDU_LEN) {
        return false;
    }

    /* Pre-filter by 802.11 Protocol Version (must be 0), Frame Type, and Control Subtype */
    uint8_t fc0 = raw[sizeof(wifi_pkt_rx_ctrl_t)];
    uint8_t ftype = (uint8_t)(fc0 & LMAC_IEEE80211_FC0_VER_TYPE_MASK);
    uint32_t fmask;
    if (ftype == LMAC_IEEE80211_FC0_TYPE_MGMT) {
        fmask = WIFI_PROMIS_FILTER_MASK_MGMT;
    } else if (ftype == LMAC_IEEE80211_FC0_TYPE_CTRL) {
        uint8_t sub = (uint8_t)(fc0 >> LMAC_IEEE80211_FC0_SUBTYPE_SHIFT);
        if (sub < LMAC_IEEE80211_CTRL_SUBTYPE_MIN ||
            (g_lmac.sniffer_ctrl_filter & (1U << (LMAC_SNF_CTRL_FILTER_BIT_BASE + sub))) == 0U) {
            return false;
        }
        fmask = WIFI_PROMIS_FILTER_MASK_CTRL;
    } else if (ftype == LMAC_IEEE80211_FC0_TYPE_DATA) {
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

    /* Copy 12-B rx_ctrl + up to 112-B payload into snf_ring, wrapping at rx_extradata -> rx_frontdata */
    uint16_t copy_len = (flen > LMAC_SNF_MAX_PAYLOAD) ? LMAC_SNF_MAX_PAYLOAD : flen;
    lmac_snf_pkt_t *dst = &g_lmac.snf_ring[wr];
    size_t rem = sizeof(wifi_pkt_rx_ctrl_t) + (size_t)copy_len;
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

    /*
     * Torn-DMA verification:
     * Because rx_head->buf remains DMA-owned during SNIFFER_END, a back-to-back arrival
     * may overwrite the buffer mid-copy. Drop the copy if RX_TSF_LO advanced, RX_DONE
     * latched concurrently, or the copied header words diverged from our pre-copy snapshot.
     */
    __asm__ volatile("memw" ::: "memory");
    if (lmac_reg_read(LMAC_WDEV_RX_TSF_LO) != tsf_before ||
        (lmac_reg_read(LMAC_WDEV_INT_RAW) & LMAC_INT_RX_DONE) != 0U ||
        ((const uint32_t *)(const void *)dst->raw)[0] != w0 ||
        dst->raw[sizeof(wifi_pkt_rx_ctrl_t)] != fc0) {
        return false;
    }

    dst->raw[LMAC_RXCTRL_CH_BYTE_OFF] =
        (uint8_t)((dst->raw[LMAC_RXCTRL_CH_BYTE_OFF] & LMAC_RXCTRL_CH_BYTE_KEEP) |
                  (g_lmac.cur_channel & LMAC_RXCTRL_W2_CH_MASK));
    g_lmac.stats.rx_nmi_frames++;
    __asm__ volatile("memw" ::: "memory");
    g_lmac.snf_wr = next;
    return true;
}

#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
/* --------------------------------------------------------------------------
 * IRAM / NMI Fast TX Arming, Retry & Next-Slot Launch (Zero Flash Access)
 * -------------------------------------------------------------------------- */

/**
 * @brief Program WDEV TXQ hardware registers and assert GO bits for @p slot from IRAM.
 *
 * Uses the precomputed per-retry rate and duration tables populated in DRAM during
 * esp_lmac_tx_submit() so retries and back-to-back launches execute entirely in IRAM
 * with zero flash access (even while SPI flash cache is disabled for erase/write).
 * Uses division-free arithmetic (shift by 10 for TU lifetime, multiply by 991 >> 8
 * for ~3.871x EDCA backoff). For software-encrypted frames (`Protected=1`, key slot 0),
 * temporarily asserts `LMAC_CRYPTO_TX_ENC` on the steered opposite VIF's `CRYPTO_CONF`
 * register (recording `g_lmac.sw_prot_bypass_vif`) so WDEV transmits the frame verbatim.
 *
 * IRAM-resident, zero flash access (-fno-jump-tables).
 * Precondition: called from Level-3 NMI or from the Wi-Fi worker holding vPortETSIntrLock().
 *
 * @param q     Hardware TX queue index (0 .. LMAC_HW_TXQ_COUNT - 1).
 * @param slot  Pre-populated TX slot in DRAM to arm and launch on queue @p q.
 */
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
        slot->hdr_buf[LMAC_IEEE80211_HDR_FC1_OFF] |= LMAC_IEEE80211_FC1_RETRY;
    }

    /* Reset owner bit on all descriptors in the scatter-gather chain */
    for (lmac_lldesc_t *d = &slot->descs[0]; d != NULL; d = d->next) {
        d->ctrl |= LLDESC_OWNER;
    }

    /* Compute remaining MSDU lifetime in TU (1024 us), division-free */
    uint32_t now_us = lmac_reg_read(LMAC_WDEV_TIME);
    uint32_t elapsed_us = now_us - slot->enqueue_us;
    uint32_t rem_tu = (elapsed_us < LMAC_TX_LIFETIME_US)
                      ? ((LMAC_TX_LIFETIME_US - elapsed_us) >> LMAC_TU_SHIFT)
                      : LMAC_TX_MIN_LIFETIME_TU;
    if (rem_tu < LMAC_TX_MIN_LIFETIME_TU) {
        rem_tu = LMAC_TX_MIN_LIFETIME_TU;
    } else if (rem_tu > LMAC_TX_MAX_LIFETIME_TU) {
        rem_tu = LMAC_TX_MAX_LIFETIME_TU;
    }

    uint32_t desc_addr = (uint32_t)(uintptr_t)&slot->descs[0] & LMAC_TXQ_DESC_ADDR_MASK;
    uint32_t link_word = desc_addr | LMAC_TXQ_LINK_VALID;

    if (hw_rate < LMAC_RATE_11N_MCS0) {
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
    slot->hdr_buf[LMAC_IEEE80211_HDR_DUR_LO_OFF] = (uint8_t)(dur_us & 0xFFU);
    slot->hdr_buf[LMAC_IEEE80211_HDR_DUR_HI_OFF] = (uint8_t)(dur_us >> 8);

    uint32_t rate_word = ((uint32_t)slot->air_len & LMAC_TXQ_RATE_LEN_MASK)
                         | (((uint32_t)hw_rate & LMAC_TXQ_RATE_CODE_MASK) << LMAC_TXQ_RATE_CODE_SHIFT)
                         | (((uint32_t)slot->hw_key_slot & LMAC_TXQ_RATE_KEY_MASK) << LMAC_TXQ_RATE_KEY_SHIFT)
                         | ((hw_rate >= LMAC_RATE_11N_MCS0) ? LMAC_TXQ_RATE_11N_BIT : 0U);

    /* Division-free EDCA backoff: (rand & ((1<<cw)-1)) * 991/256 (~3.871); beacons use fixed backoff/lifetime */
    uint32_t backoff;
    if ((slot->flags & ESP_LMAC_TX_FLAG_BEACON) != 0U) {
        backoff = LMAC_TX_BEACON_BACKOFF;
        rem_tu = LMAC_TX_BEACON_LIFETIME_TU;
    } else {
        uint32_t cw_mask = (1U << (txq->cw & LMAC_TXQ_CW_SHIFT_MASK)) - 1U;
        uint32_t rnd = lmac_reg_read(LMAC_WDEV_HW_SEQ_RND) & cw_mask;
        backoff = (rnd * LMAC_NMI_BACKOFF_SCALE_NUM) >> LMAC_NMI_BACKOFF_SCALE_SHIFT;
        if (backoff > LMAC_TXQ_CONF_BACKOFF_MASK) {
            backoff = LMAC_TXQ_CONF_BACKOFF_MASK;
        }
    }

    /* Arm TXQ registers in verified sequence before setting GO bits [31:30] */
    lmac_reg_write(LMAC_TXQ_LIFETIME(q), (rem_tu & LMAC_TXQ_LIFETIME_MASK) << LMAC_TXQ_LIFETIME_SHIFT);
    lmac_reg_write(LMAC_TXQ_LINK(q), link_word);
    lmac_reg_write(LMAC_TXQ_DURATION(q), (uint32_t)dur_us << LMAC_TXQ_DURATION_SHIFT);
    lmac_reg_write(LMAC_TXQ_RATE(q), rate_word);
    if (hw_rate >= LMAC_RATE_11N_MCS0) {
        uint32_t ht_gi = (hw_rate >= LMAC_RATE_11N_SGI_BASE)
                         ? LMAC_TXQ_HT_PLCP_SGI_FLAGS
                         : LMAC_TXQ_HT_PLCP_LGI_FLAGS;
        lmac_reg_write(LMAC_TXQ_HT_PLCP(q),
                       ((uint32_t)hw_rate & LMAC_TXQ_HT_PLCP_MCS_MASK)
                       | (((uint32_t)slot->air_len & LMAC_TXQ_HT_PLCP_LEN_MASK) << LMAC_TXQ_HT_PLCP_LEN_SHIFT)
                       | ht_gi);
    }
    lmac_reg_write(LMAC_TXQ_CONF(q), (backoff & LMAC_TXQ_CONF_BACKOFF_MASK) << LMAC_TXQ_CONF_BACKOFF_SHIFT);

    txq->launch_us = now_us;
    /*
     * Opposite-VIF SW-protected TX bypass:
     * Software-encrypted frames carry Protected=1 with hardware key slot 0 (bit 7 steered to
     * the opposite VIF). Temporarily set LMAC_CRYPTO_TX_ENC on that VIF's CRYPTO_CONF so WDEV
     * skips hardware encryption until nmi_handle_tx_done() or tx_abort_hw_queue() restores it.
     */
    if ((slot->hdr_buf[LMAC_IEEE80211_HDR_FC1_OFF] & LMAC_FC1_PROTECTED) != 0U &&
        (slot->hw_key_slot & LMAC_KEY_SLOT_MASK) == 0U) {
        uint8_t vif_idx = (slot->hw_key_slot >> LMAC_KEY_SLOT_AP_SHIFT) & 1U;
        uint32_t creg = LMAC_WDEV_CRYPTO_CONF0 + ((uint32_t)vif_idx << 2);
        uint32_t cval = lmac_reg_read(creg);
        if ((cval & LMAC_CRYPTO_TX_ENC) == 0U) {
            lmac_reg_write(creg, cval | LMAC_CRYPTO_TX_ENC);
            g_lmac.sw_prot_bypass_vif = (uint8_t)(vif_idx + 1U);
        }
    }
    lmac_reg_write(LMAC_TXQ_LINK(q), link_word | LMAC_TXQ_LINK_GO);
}

/**
 * @brief Process a WDEV TX completion interrupt directly in Level-3 NMI.
 *
 * Keeps the radio pipeline saturated across SPI flash cache-off windows:
 *   - On retryable error within retry/lifetime budgets, bumps CW and re-arms the same
 *     slot immediately in IRAM without waking the worker task.
 *   - On final completion (success or exhausted failure), resets CW, clears any temporary
 *     opposite-VIF `LMAC_CRYPTO_TX_ENC` bypass (`g_lmac.sw_prot_bypass_vif`), immediately
 *     launches the next queued DRAM slot (if RF is open), and appends the finished slot to
 *     the `tx_done_head`/`tx_done_tail` FIFO for deferred worker TRC update, slot release,
 *     and `done_cb` invocation in `.flash.text`.
 *
 * IRAM-resident, zero flash access (-fno-jump-tables).
 * Precondition: called from Level-3 NMI context (wDev_ProcessFiq).
 *
 * @param tx_status  Snapshot of LMAC_WDEV_TX_STATUS captured at NMI entry.
 * @return           true if a slot completed and was appended to the done FIFO; false otherwise.
 */
static bool IRAM_ATTR nmi_handle_tx_done(uint32_t tx_status)
{
    uint8_t q = (uint8_t)((tx_status >> LMAC_TX_STATUS_SLOT_SHIFT) & LMAC_TX_STATUS_SLOT_MASK);
    uint8_t cause = (uint8_t)(tx_status >> LMAC_TX_STATUS_CAUSE_SHIFT);
    uint8_t sub = (uint8_t)((tx_status >> LMAC_TX_STATUS_SUB_SHIFT) & LMAC_TX_STATUS_SUB_MASK);

    if (q >= LMAC_HW_TXQ_COUNT) {
        return false;
    }

    lmac_hw_txq_t *txq = &g_lmac.hw_txq[q];
    lmac_tx_slot_t *slot = txq->active;
    if (slot == NULL) {
        return false;
    }

    uint8_t ok = 0U;
    int8_t ack_rssi = (int8_t)LMAC_RSSI_UNAVAILABLE;

    if (cause == LMAC_TX_CAUSE_OK) {
        uint32_t rssi_reg = lmac_reg_read(LMAC_WDEV_TX_ACK_RSSI);
        if ((rssi_reg & LMAC_TX_ACK_RSSI_VALID_BIT) != 0U) {
            ack_rssi = (int8_t)((int32_t)((rssi_reg >> LMAC_TX_ACK_RSSI_SHIFT) & LMAC_TX_ACK_RSSI_BYTE_MASK)
                                - LMAC_RSSI_HW_OFFSET_DBM);
        }
        ok = 1U;
    } else {
        /* Retryable timeout/error: CTS timeout, ACK timeout, or sub 1/3 on cause 1/4 */
        bool retryable = (cause == LMAC_TX_CAUSE_CTS_TIMEOUT || cause == LMAC_TX_CAUSE_ACK_TIMEOUT ||
                          ((cause == LMAC_TX_CAUSE_ERR1 || cause == LMAC_TX_CAUSE_ERR4) &&
                           (sub == LMAC_TX_SUB_RETRY1 || sub == LMAC_TX_SUB_RETRY3)));
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

    /*
     * Slot completed: reset CW and launch the next queued DRAM slot right here in NMI
     * so TX throughput survives SPI flash erase/write cache-off stalls. The finished slot
     * is handed off via the singly-linked tx_done_head/tx_done_tail FIFO (protected on
     * the worker side by vPortETSIntrLock()) for TRC accounting, release, and done_cb.
     */
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

/**
 * @brief Top-level WDEV Level-3 NMI handler invoked by _xt_nmi in xtensa_vectors.S.
 *
 * Services WDEV interrupt sources in strict priority order:
 *   1. LMAC_INT_MACTIM0 (BIT 27): MAC Timer 0 / task_wdt NMI watchdog (may nest when
 *      NMIIrqIsOn > 1 because vPortETSIntrLock leaves BIT 27 unmasked).
 *   2. LMAC_INT_MACTIM1 (BIT 26): MAC Timer 1 / SoftAP TBTT callback and worker event.
 *   3. LMAC_INT_TX_DONE (BIT 19): Fast IRAM TX retry/launch (or MIN_NMI event push).
 *   4. LMAC_INT_RX_DONE (BIT 8) or LMAC_INT_SNIFFER_END (BIT 2): Thin zero-copy RX
 *      descriptor drain (with A-MPDU subframe demux when enabled), or sniffer-mode
 *      `SNIFFER_END` capture into `snf_ring` when `BIT 8` is not set.
 *   5. LMAC_INT_TX_TIMEOUT (BIT 29): Hardware TX queue timeout worker event.
 *
 * IRAM-resident, compiled with -fno-jump-tables, strictly zero .flash.text calls and
 * zero .flash.rodata dereferences so it can preempt SPI flash cache-off operations.
 * Maintains the _xt_nmi epilogue invariant (clears LMAC_DPORT_NMI_INT_ENA before return).
 */
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
     * preempt an outer NMI invocation (NMIIrqIsOn > 1). On nested entry, ack BIT 27
     * and return immediately while honoring the _xt_nmi DPORT clear invariant.
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
            uint8_t slot = (uint8_t)((tx_status >> LMAC_TX_STATUS_SLOT_SHIFT) & LMAC_TX_STATUS_SLOT_MASK);
            uint8_t cause = (uint8_t)(tx_status >> LMAC_TX_STATUS_CAUSE_SHIFT);
            uint8_t sub = (uint8_t)((tx_status >> LMAC_TX_STATUS_SUB_SHIFT) & LMAC_TX_STATUS_SUB_MASK);
            uint32_t rssi_reg = lmac_reg_read(LMAC_WDEV_TX_ACK_RSSI);
            int8_t ack_rssi = ((rssi_reg & LMAC_TX_ACK_RSSI_VALID_BIT) != 0U)
                              ? (int8_t)((int32_t)((rssi_reg >> LMAC_TX_ACK_RSSI_SHIFT) & LMAC_TX_ACK_RSSI_BYTE_MASK)
                                         - LMAC_RSSI_HW_OFFSET_DBM)
                              : (int8_t)LMAC_RSSI_UNAVAILABLE;

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
            PendSV(LMAC_PENDSV_REQ_WIFI_SOFTISR);
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

/**
 * @brief Level-1 SoftISR trampoline that notifies the Wi-Fi worker task from FreeRTOS context.
 *
 * Level-3 NMI cannot invoke FreeRTOS APIs directly (it can preempt critical sections and
 * SPI flash cache-off windows). Instead, wDev_ProcessFiq sets nmi_notify_pending and
 * triggers PendSV(LMAC_PENDSV_REQ_WIFI_SOFTISR); SoftIsrHdl in port.c then invokes this
 * IRAM handler at Level-1 interrupt priority once FreeRTOS critical sections exit.
 *
 * @return  Non-zero if g_lmac.cbs.notify_from_isr woke a higher-priority task; 0 otherwise.
 */
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

/**
 * @brief Enable hardware MAC Timer 0 (TSF0) and register its Level-3 NMI callback.
 *
 * Used by task_wdt for the NMI watchdog. IRAM-resident with zero flash access.
 * The registered callback executes inside Level-3 NMI and must itself be IRAM-safe.
 *
 * @param cb  Function pointer (cast to void *) to invoke on LMAC_INT_MACTIM0, or NULL.
 */
void IRAM_ATTR wDev_MacTimSetFunc(void *cb)
{
    lmac_reg_set(LMAC_WDEV_MACTIM0_CONF, LMAC_MACTIM_EN_BIT);
    s_mac_tim0_cb = (void (*)(void))cb;
}

/**
 * @brief Arm hardware MAC Timer 0 comparator to fire @p delta_us microseconds from now.
 *
 * IRAM-resident with zero flash access. Acquires vPortETSIntrLock() while reading the
 * 64-bit TSF0 counter and programming the 64-bit comparator target registers.
 *
 * @param delta_us  Relative delay in microseconds from current TSF0 time.
 */
void IRAM_ATTR wDev_MacTimArm(uint32_t delta_us)
{
    vPortETSIntrLock();
    uint32_t lo = lmac_reg_read(LMAC_WDEV_TSF0_LO);
    uint32_t hi = lmac_reg_read(LMAC_WDEV_TSF0_HI);
    uint32_t target_lo = lo + delta_us;
    uint32_t target_hi = (target_lo <= lo) ? (hi + 1U) : hi;

    lmac_reg_write(LMAC_WDEV_MACTIM0_TARGET_LO, target_lo);
    lmac_reg_write(LMAC_WDEV_MACTIM0_TARGET_HI, target_hi);
    lmac_reg_set(LMAC_WDEV_MACTIM0_ARM, LMAC_MACTIM_EN_BIT);
    vPortETSIntrUnlock();
}

/**
 * @brief Enable hardware MAC Timer 1 (TSF1) and register its Level-3 NMI callback.
 *
 * Called from task context (.flash.text) during SoftAP/TBTT setup. If non-NULL, @p cb
 * executes inside Level-3 NMI and must be IRAM-safe.
 *
 * @param cb  Callback to invoke on LMAC_INT_MACTIM1, or NULL to clear.
 */
void lmac_mactim1_set_func(void (*cb)(void))
{
    lmac_reg_set(LMAC_WDEV_TSF1_CONF, LMAC_MACTIM_EN_BIT);
    s_mac_tim1_cb = cb;
}

/**
 * @brief Arm hardware MAC Timer 1 comparator to fire @p delta_us microseconds from now.
 *
 * Called from task context (.flash.text). Acquires vPortETSIntrLock() while reading the
 * 64-bit TSF1 counter and programming the 64-bit comparator target registers.
 *
 * @param delta_us  Relative delay in microseconds from current TSF1 time.
 */
void lmac_mactim1_arm(uint32_t delta_us)
{
    vPortETSIntrLock();
    uint32_t lo = lmac_reg_read(LMAC_WDEV_TSF1_LO);
    uint32_t hi = lmac_reg_read(LMAC_WDEV_TSF1_HI);
    uint32_t target_lo = lo + delta_us;
    uint32_t target_hi = (target_lo <= lo) ? (hi + 1U) : hi;

    lmac_reg_write(LMAC_WDEV_MACTIM1_TARGET_LO, target_lo);
    lmac_reg_write(LMAC_WDEV_MACTIM1_TARGET_HI, target_hi);
    lmac_reg_set(LMAC_WDEV_MACTIM1_ARM, LMAC_MACTIM_EN_BIT);
    vPortETSIntrUnlock();
}

/**
 * @brief Disarm hardware MAC Timer 1 comparator.
 *
 * Called from task context (.flash.text). Acquires vPortETSIntrLock() while clearing
 * the comparator arm bit.
 */
void lmac_mactim1_disarm(void)
{
    vPortETSIntrLock();
    lmac_reg_clr(LMAC_WDEV_MACTIM1_ARM, LMAC_MACTIM_EN_BIT);
    vPortETSIntrUnlock();
}

/**
 * @brief Read the currently active primary 2.4 GHz Wi-Fi channel number.
 *
 * Lock-free volatile read residing in `.flash.text` (task context only; IRAM/NMI code
 * reads `g_lmac.cur_channel` directly).
 *
 * @return  Current primary channel (1..14), or 0 if not yet configured.
 */
uint8_t esp_lmac_get_channel(void)
{
    return g_lmac.cur_channel;
}
