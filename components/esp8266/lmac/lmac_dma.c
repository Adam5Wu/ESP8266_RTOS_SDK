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
// Circular RX DMA arena, wrap-around linearization into extradata, and
// zero-copy/hybrid descriptor recycling (executes in .flash.text).
//
// Portions of the WDEV RX DMA window bounds and dummy control-descriptor
// hardware sequences are adapted in part from teatime-os:
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

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "lmac_internal.h"

#define TAG "lmac_dma"

/* File-local RX DMA geometry and bitfield constants */
#define LMAC_DMA_MIN_RX_BUF_LEN   64U         /* Minimum bytes per circular RX or A-MPDU info slot (4-B aligned) */
#define LMAC_DMA_ALIGN_MASK       3U          /* 4-byte DMA alignment mask */
#define LMAC_DMA_AMPDU_DESC_CNT   5U          /* Default hardware A-MPDU subframe info ring depth */
#define LMAC_DMA_AMPDU_BUF_LEN    256U        /* Default bytes per A-MPDU subframe info buffer */
#define LMAC_DMA_EMPTY_AMPDU_LEN  4U          /* Dummy 4-byte A-MPDU descriptor length */
#define LMAC_DMA_AVAIL_MASK_BITS  32U         /* Bit width of rx_avail_mask */
#define LMAC_DMA_AVAIL_MASK_ALL   0xFFFFFFFFU /* Full 32-bit availability mask */
#define LMAC_DMA_VIF_MATCH_MASK   0x0FU       /* 4-bit hardware VIF/BSSID match mask */

/**
 * @brief Allocate and initialize the contiguous circular RX DMA arena and WDEV ring.
 *
 * Lays out a single 4-byte-aligned DRAM arena with the following contiguous sections:
 *   1. `rx_descs`     : `n * sizeof(lmac_lldesc_t)` circular RX descriptor array.
 *   2. `rx_frontdata` : `n * rx_buf_len` bytes backing the circular ring descriptors.
 *   3. `rx_extradata` : `align4(rx_max_single_pkt_len)` linearization scratch immediately
 *                       adjacent to the end of `rx_frontdata`, allowing frames that wrap
 *                       across the end of the ring to be made contiguous in-place.
 *   4. `rx_handles`   : `n * sizeof(esp_lmac_rx_buf_t)` arena-backed per-descriptor RX
 *                       handles (0 B static BSS).
 *   5. `rx_ampdu_*`   : optional configurable `rx_ampdu_buf_num x rx_ampdu_buf_len`
 *                       (default 5 x 256 B) A-MPDU subframe info ring when compiled and
 *                       enabled; otherwise a 4-byte dummy descriptor keeps WDEV unblocked.
 *   6. `rx_subframes` : optional `LMAC_AMPDU_SUBFRAME_POOL_SIZE` (32) x 32 B static
 *                       A-MPDU subframe descriptor pool allocated in NMI without malloc.
 *
 * Reuses `g_lmac.hw_arena` if already allocated (zeroing it) and programs WDEV RX DMA
 * registers via lmac_dma_reprogram_regs().
 *
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG if ring size or buffer length is invalid,
 *         or ESP_ERR_NO_MEM if DRAM allocation fails.
 */
esp_err_t lmac_dma_init(void)
{
    uint8_t n = g_lmac.cfg.rx_buf_num;
    uint16_t buf_len = g_lmac.cfg.rx_buf_len;
    uint16_t extra_len = g_lmac.cfg.rx_max_single_pkt_len;

    if (n == 0U || n > LMAC_MAX_RX_BUFS) {
        return ESP_ERR_INVALID_ARG;
    }
    if (buf_len < LMAC_DMA_MIN_RX_BUF_LEN || (buf_len & LMAC_DMA_ALIGN_MASK) != 0U) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t desc_bytes = (size_t)n * sizeof(lmac_lldesc_t);
    size_t front_bytes = (size_t)n * (size_t)buf_len;
    size_t extra_bytes = ((size_t)extra_len + LMAC_DMA_ALIGN_MASK) & ~LMAC_DMA_ALIGN_MASK;
    size_t handle_bytes = (size_t)n * sizeof(esp_lmac_rx_buf_t);
    size_t ampdu_desc_bytes = 0U;
    size_t ampdu_buf_bytes = 0U;
    size_t subframe_bytes = 0U;

#if CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
    uint8_t abuf_num = g_lmac.cfg.rx_ampdu_buf_num;
    uint16_t abuf_len = g_lmac.cfg.rx_ampdu_buf_len;
    if (g_lmac.cfg.ampdu_rx_enable != 0U) {
        if (abuf_num == 0U) {
            abuf_num = LMAC_DMA_AMPDU_DESC_CNT;
            g_lmac.cfg.rx_ampdu_buf_num = abuf_num;
        }
        if (abuf_len < LMAC_DMA_MIN_RX_BUF_LEN) {
            abuf_len = LMAC_DMA_AMPDU_BUF_LEN;
            g_lmac.cfg.rx_ampdu_buf_len = abuf_len;
        }
        ampdu_desc_bytes = (size_t)abuf_num * sizeof(lmac_lldesc_t);
        ampdu_buf_bytes = (size_t)abuf_num * (size_t)abuf_len;
        subframe_bytes = LMAC_AMPDU_SUBFRAME_POOL_SIZE * sizeof(lmac_rx_subframe_t);
    }
#endif

    size_t total = desc_bytes + front_bytes + extra_bytes + handle_bytes +
                   ampdu_desc_bytes + ampdu_buf_bytes + subframe_bytes;

    if (g_lmac.hw_arena == NULL) {
        g_lmac.hw_arena = (uint8_t *)heap_caps_zalloc(total, MALLOC_CAP_8BIT);
        if (g_lmac.hw_arena == NULL) {
            ESP_LOGE(TAG, "RX DMA arena alloc failed (%u B)", (unsigned)total);
            return ESP_ERR_NO_MEM;
        }
    } else {
        memset(g_lmac.hw_arena, 0, total);
    }

    /* Partition arena: [rx_descs][rx_frontdata][rx_extradata][rx_handles][optional rx_ampdu_* + rx_subframes] */
    g_lmac.rx_descs = (lmac_lldesc_t *)(void *)g_lmac.hw_arena;
    g_lmac.rx_frontdata = g_lmac.hw_arena + desc_bytes;
    g_lmac.rx_extradata = g_lmac.rx_frontdata + front_bytes;
    g_lmac.rx_handles = (esp_lmac_rx_buf_t *)(void *)(g_lmac.rx_extradata + extra_bytes);

    for (uint8_t i = 0U; i < n; i++) {
        lmac_lldesc_t *d = &g_lmac.rx_descs[i];
        d->ctrl = LLDESC_OWNER | ((uint32_t)buf_len << LLDESC_LEN_SHIFT) | (uint32_t)buf_len;
        d->buf = g_lmac.rx_frontdata + (size_t)i * (size_t)buf_len;
        d->next = &g_lmac.rx_descs[(i + 1U) % n];
    }

    /* Dummy 4-byte A-MPDU descriptor prevents WDEV RX DMA from wedging when A-MPDU is off */
    g_lmac.empty_ampdu_word = 0U;
    g_lmac.empty_ampdu_desc.ctrl = LLDESC_OWNER | LMAC_DMA_EMPTY_AMPDU_LEN;
    g_lmac.empty_ampdu_desc.buf = (uint8_t *)(void *)&g_lmac.empty_ampdu_word;
    g_lmac.empty_ampdu_desc.next = NULL;

#if CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
    if (g_lmac.cfg.ampdu_rx_enable != 0U) {
        g_lmac.rx_ampdu_descs = (lmac_lldesc_t *)(void *)((uint8_t *)g_lmac.rx_handles + handle_bytes);
        g_lmac.rx_ampdu_bufs = (uint8_t *)g_lmac.rx_ampdu_descs + ampdu_desc_bytes;
        g_lmac.rx_subframes = (lmac_rx_subframe_t *)(void *)(g_lmac.rx_ampdu_bufs + ampdu_buf_bytes);
        g_lmac.rx_subframe_used_mask = 0U;
        g_lmac.rx_ampdu_head_idx = 0U;
        for (uint8_t i = 0U; i < abuf_num; i++) {
            lmac_lldesc_t *d = &g_lmac.rx_ampdu_descs[i];
            d->ctrl = LLDESC_OWNER | ((uint32_t)abuf_len << LLDESC_LEN_SHIFT) | (uint32_t)abuf_len;
            d->buf = g_lmac.rx_ampdu_bufs + (size_t)i * (size_t)abuf_len;
            d->next = &g_lmac.rx_ampdu_descs[(i + 1U) % abuf_num];
        }
    } else {
        g_lmac.rx_ampdu_descs = NULL;
        g_lmac.rx_ampdu_bufs = NULL;
        g_lmac.rx_subframes = NULL;
        g_lmac.rx_subframe_used_mask = 0U;
        g_lmac.rx_ampdu_head_idx = 0U;
    }
#else
    g_lmac.rx_ampdu_descs = NULL;
    g_lmac.rx_ampdu_bufs = NULL;
#endif

    g_lmac.rx_avail_mask = (n >= LMAC_DMA_AVAIL_MASK_BITS) ? LMAC_DMA_AVAIL_MASK_ALL : ((1U << n) - 1U);
    g_lmac.rx_head_idx = 0U;

    lmac_dma_reprogram_regs();
    return ESP_OK;
}

/**
 * @brief Program WDEV RX DMA descriptor heads, memory bounds, and RX config register.
 *
 * Configures both the A-MPDU subframe info ring (pointing `LMAC_WDEV_RX_AMPDU_LINK` at
 * `rx_ampdu_descs[rx_ampdu_head_idx]` with bounds covering `rx_ampdu_buf_num * rx_ampdu_buf_len`,
 * or falling back to the 4-byte dummy descriptor when A-MPDU RX is disabled) and the main
 * circular RX ring bounds (`rx_descs`..`rx_extradata`), points the hardware link head at
 * `rx_descs[rx_head_idx]`, and clears initial RX configuration flags. Called during
 * lmac_dma_init() and after hardware MAC resets.
 */
void lmac_dma_reprogram_regs(void)
{
    uint32_t ampdu_start;
    uint32_t ampdu_end;
    uint32_t ampdu_link;

    if (g_lmac.rx_ampdu_descs != NULL) {
#if CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
        uint8_t head = g_lmac.rx_ampdu_head_idx;
        size_t abuf_total = (size_t)g_lmac.cfg.rx_ampdu_buf_num * (size_t)g_lmac.cfg.rx_ampdu_buf_len;
        ampdu_start = (uint32_t)(uintptr_t)g_lmac.rx_ampdu_descs;
        ampdu_end = (uint32_t)(uintptr_t)(g_lmac.rx_ampdu_bufs + abuf_total);
        ampdu_link = (uint32_t)(uintptr_t)&g_lmac.rx_ampdu_descs[head];
#else
        ampdu_start = (uint32_t)(uintptr_t)&g_lmac.empty_ampdu_desc;
        ampdu_end = (uint32_t)(uintptr_t)(&g_lmac.empty_ampdu_word + 1U);
        ampdu_link = ampdu_start;
#endif
    } else {
        ampdu_start = (uint32_t)(uintptr_t)&g_lmac.empty_ampdu_desc;
        ampdu_end = (uint32_t)(uintptr_t)(&g_lmac.empty_ampdu_word + 1U);
        ampdu_link = ampdu_start;
    }

    lmac_reg_write(LMAC_WDEV_RX_AMPDU_LINK, ampdu_link);
    lmac_reg_write(LMAC_WDEV_RX_AMPDU_START, ampdu_start);
    lmac_reg_write(LMAC_WDEV_RX_AMPDU_END, ampdu_end);
    lmac_reg_write(LMAC_WDEV_RX_DESC_START, (uint32_t)(uintptr_t)g_lmac.rx_descs);
    lmac_reg_write(LMAC_WDEV_RX_BUF_END, (uint32_t)(uintptr_t)g_lmac.rx_extradata);
    lmac_reg_write(LMAC_WDEV_RX_LINK_CLR, 0U);
    lmac_reg_write(LMAC_WDEV_RX_LINK_HEAD, (uint32_t)(uintptr_t)&g_lmac.rx_descs[g_lmac.rx_head_idx]);
    lmac_reg_rmw(LMAC_WDEV_RX_CONF, LMAC_WDEV_RX_CONF_INIT_CLR, 0U);
}

/**
 * @brief Free the sniffer capture ring and RX DMA arena, resetting all ring and pool state.
 *
 * Releases `g_lmac.snf_ring` (resetting `snf_wr`/`snf_rd`) and `g_lmac.hw_arena`, and
 * clears all arena-backed pointers (`rx_descs`, `rx_frontdata`, `rx_extradata`,
 * `rx_handles`, `rx_ampdu_*`, and when enabled `rx_subframes` / `rx_subframe_used_mask`
 * / `rx_ampdu_head_idx`) plus descriptor availability state.
 */
void lmac_dma_deinit(void)
{
    if (g_lmac.snf_ring != NULL) {
        heap_caps_free(g_lmac.snf_ring);
        g_lmac.snf_ring = NULL;
    }
    g_lmac.snf_wr = 0U;
    g_lmac.snf_rd = 0U;
    if (g_lmac.hw_arena != NULL) {
        heap_caps_free(g_lmac.hw_arena);
        g_lmac.hw_arena = NULL;
    }
    g_lmac.rx_descs = NULL;
    g_lmac.rx_frontdata = NULL;
    g_lmac.rx_extradata = NULL;
    g_lmac.rx_handles = NULL;
    g_lmac.rx_ampdu_descs = NULL;
    g_lmac.rx_ampdu_bufs = NULL;
#if CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
    g_lmac.rx_subframes = NULL;
    g_lmac.rx_subframe_used_mask = 0U;
    g_lmac.rx_ampdu_head_idx = 0U;
#endif
    g_lmac.rx_avail_mask = 0U;
    g_lmac.rx_head_idx = 0U;
}

/**
 * @brief Return true when the linearized frame extends into the shared rx_extradata scratch buffer.
 *
 * Returns false if @p rx_buf, `rx_buf->frame`, or `g_lmac.rx_extradata` is NULL.
 *
 * @param rx_buf  RX buffer handle delivered to the upper layer.
 * @return        true if the frame crosses `rx_extradata` and must be heap-copied instead
 *                of pinned zero-copy (the shared scratch is overwritten by later wrapped frames).
 */
bool esp_lmac_rx_buf_is_wrapped(const esp_lmac_rx_buf_t *rx_buf)
{
    if (rx_buf == NULL || rx_buf->frame == NULL || g_lmac.rx_extradata == NULL) {
        return false;
    }
    return (rx_buf->frame + rx_buf->len) > g_lmac.rx_extradata;
}

/**
 * @brief Compute the longest contiguous run of free descriptors in the circular RX ring.
 *
 * Used by upper layers to decide whether zero-copy RX buffer pinning has sufficient ring
 * headroom or should fall back to copying into heap pbufs.
 *
 * @return Length of the longest contiguous run of available RX descriptors (`0..rx_buf_num`).
 */
uint8_t esp_lmac_rx_free_contiguous(void)
{
    uint8_t n = g_lmac.cfg.rx_buf_num;
    if (n == 0U) {
        return 0U;
    }

    vPortETSIntrLock();
    uint32_t avail = g_lmac.rx_avail_mask;
    vPortETSIntrUnlock();

    /*
     * Bit-doubling longest-contiguous-run algorithm:
     * Concatenate the n-bit circular bitmap with itself (`(avail << n) | avail`) so any
     * run of 1-bits wrapping across descriptor (n-1) -> 0 becomes a linear run. Each
     * `doubled &= (doubled >> 1)` step trims every run of k ones down to k-1 ones; the
     * iteration count until zero is therefore the maximum run length (capped at n).
     */
    uint32_t doubled = (avail << n) | avail;
    uint8_t max_run = 0U;
    while (doubled != 0U) {
        doubled &= (doubled >> 1);
        max_run++;
        if (max_run >= n) {
            return n;
        }
    }
    return max_run;
}

/**
 * @brief Return a pinned circular RX buffer handle and its descriptors back to WDEV DMA.
 *
 * Under `CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED`, returns A-MPDU subframe handles back to
 * `rx_subframe_used_mask` (using pointer-range lookup into `rx_subframes[]`) and decrements
 * each spanned descriptor's 5-bit `LLDESC_OFF_MASK` reference count so descriptors shared
 * across multiple A-MPDU subframes stay pinned until the final subframe is freed. Once a
 * descriptor's refcount reaches zero (or unconditionally when A-MPDU RX is compiled out),
 * restores `LLDESC_OWNER`, sets its bit in `rx_avail_mask`, and advances the hardware RX
 * link pointer under ETS interrupt lock so WDEV can reuse the recycled slots immediately.
 *
 * @param rx_buf  RX handle previously passed to `on_rx_frame`; ownership transfers back
 *                to LMAC. Passing NULL or an already-freed handle is a safe no-op.
 */
void esp_lmac_rx_free(esp_lmac_rx_buf_t *rx_buf)
{
    if (rx_buf == NULL || !rx_buf->in_use) {
        return;
    }

    uint8_t n = g_lmac.cfg.rx_buf_num;
    uint8_t idx = rx_buf->desc_start;
    uint8_t cnt = rx_buf->desc_cnt;
    rx_buf->in_use = 0U;

    vPortETSIntrLock();
#if CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
    /* Release pool bit when rx_buf is embedded at offset 0 of an rx_subframes[] entry */
    if (g_lmac.rx_subframes != NULL &&
        (uintptr_t)rx_buf >= (uintptr_t)g_lmac.rx_subframes &&
        (uintptr_t)rx_buf < (uintptr_t)(g_lmac.rx_subframes + LMAC_AMPDU_SUBFRAME_POOL_SIZE)) {
        size_t sidx = (size_t)((const lmac_rx_subframe_t *)(const void *)rx_buf - g_lmac.rx_subframes);
        g_lmac.rx_subframe_used_mask &= ~(1U << sidx);
    }
#endif
    for (uint8_t i = 0U; i < cnt; i++) {
        lmac_lldesc_t *d = &g_lmac.rx_descs[idx];
#if CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
        /* Shared A-MPDU descriptors hold a 5-bit refcount in LLDESC_OFF_MASK; recycle only on last ref */
        uint32_t rc = (d->ctrl & LLDESC_OFF_MASK) >> LLDESC_OFF_SHIFT;
        if (rc > 1U) {
            d->ctrl = (d->ctrl & ~LLDESC_OFF_MASK) | ((rc - 1U) << LLDESC_OFF_SHIFT);
        } else {
            uint32_t sz = d->ctrl & LLDESC_SIZE_MASK;
            d->ctrl = LLDESC_OWNER | (sz << LLDESC_LEN_SHIFT) | sz;
            lmac_rx_set_desc_bit_locked(idx);
        }
#else
        uint32_t sz = d->ctrl & LLDESC_SIZE_MASK;
        d->ctrl = LLDESC_OWNER | (sz << LLDESC_LEN_SHIFT) | sz;
        lmac_rx_set_desc_bit_locked(idx);
#endif
        idx++;
        if (idx >= n) {
            idx = 0U;
        }
    }
    lmac_check_and_move_hwbuf_locked();
    vPortETSIntrUnlock();
}

/**
 * @brief Finalize a received MPDU or A-MPDU subframe from an NMI RX event and dispatch it.
 *
 * Handles both `LMAC_NMI_EVT_RX_DESC` (single MPDU using `rx_handles[ev->a]` and in-place
 * `rx_ctrl`) and, when `CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED` is enabled,
 * `LMAC_NMI_EVT_RX_AMPDU` (demuxed subframe using `rx_subframes[ev->a]`, its NMI-patched
 * `rx_ctrl_w`, and byte offset `sf->start_off`). Calibrates raw RSSI to dBm, linearizes
 * circular wrap-around into `rx_extradata` over `span_len` (`flen` in sniffer mode,
 * FCS-stripped `rb->len` in normal mode), and invokes either `on_sniffer_frame` (freeing
 * the handle immediately) or `on_rx_frame` (transferring ownership until esp_lmac_rx_free()).
 *
 * @param ev  Pointer to an `LMAC_NMI_EVT_RX_DESC` (`a` = `desc_start`, `b` = `desc_cnt`)
 *            or `LMAC_NMI_EVT_RX_AMPDU` (`a` = `rx_subframes[]` index) event popped from
 *            the NMI event ring (`d` = BB frequency offset, `len` = PSDU length incl. FCS).
 */
void lmac_dma_dispatch_rx_evt(const lmac_nmi_evt_t *ev)
{
    esp_lmac_rx_buf_t *rb = NULL;
    const wifi_pkt_rx_ctrl_t *ctrl = NULL;
    uint8_t *frame = NULL;
    uint16_t flen = ev->len;

#if CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
    if (ev->type == LMAC_NMI_EVT_RX_AMPDU) {
        uint8_t sidx = ev->a;
        if (g_lmac.rx_subframes == NULL || sidx >= LMAC_AMPDU_SUBFRAME_POOL_SIZE) {
            return;
        }
        lmac_rx_subframe_t *sf = &g_lmac.rx_subframes[sidx];
        rb = &sf->handle;
        if (!rb->in_use || rb->desc_start >= g_lmac.cfg.rx_buf_num || rb->desc_cnt == 0U) {
            return;
        }
        /* Calibrate raw RSSI byte in the NMI-synthesized per-subframe rx_ctrl copy */
        uint8_t *ctrl_raw = (uint8_t *)(void *)sf->rx_ctrl_w;
        ctrl_raw[0] = (uint8_t)((int8_t)ctrl_raw[0] - LMAC_RSSI_HW_OFFSET_DBM);
        ctrl = (const wifi_pkt_rx_ctrl_t *)(const void *)ctrl_raw;
        frame = g_lmac.rx_descs[rb->desc_start].buf + sf->start_off;
    } else
#endif
    {
        uint8_t start_idx = ev->a;
        uint8_t desc_cnt = ev->b;

        if (g_lmac.rx_handles == NULL || start_idx >= g_lmac.cfg.rx_buf_num || desc_cnt == 0U) {
            return;
        }

        rb = &g_lmac.rx_handles[start_idx];
        uint8_t *raw = g_lmac.rx_descs[start_idx].buf;
        /* Convert hardware raw RSSI (byte 0) to calibrated dBm (raw - 96, matching ppProcessRxPktHdr) */
        raw[0] = (uint8_t)((int8_t)raw[0] - LMAC_RSSI_HW_OFFSET_DBM);
        ctrl = (const wifi_pkt_rx_ctrl_t *)(const void *)raw;
        frame = raw + sizeof(wifi_pkt_rx_ctrl_t);

        uint32_t w0 = ((const uint32_t *)(const void *)ctrl)[0];
        uint8_t vif_match = (uint8_t)((w0 >> LMAC_RXCTRL_W0_VIF_SHIFT) & LMAC_DMA_VIF_MATCH_MASK);

        rb->rx_ctrl = ctrl;
        rb->frame = frame;
        /* PLCP PSDU length includes the 4-byte hardware FCS; strip FCS for normal 802.11 consumers */
        rb->len = (!g_lmac.sniffer_mode && flen >= LMAC_IEEE80211_FCS_LEN)
                  ? (uint16_t)(flen - LMAC_IEEE80211_FCS_LEN)
                  : flen;
        rb->freq_offset = ev->d;
        rb->vif_match = vif_match;
        rb->desc_start = start_idx;
        rb->desc_cnt = desc_cnt;
        rb->in_use = 1U;
    }

    /*
     * Wrap-around linearization into extradata:
     * WDEV writes [rx_ctrl][frame] into the circular rx_frontdata arena, wrapping from
     * the end of rx_frontdata back to rx_frontdata[0]. Because rx_extradata sits
     * immediately after rx_frontdata in memory, copying the wrapped tail bytes from
     * rx_frontdata[0] into rx_extradata yields a contiguous [frame, frame + span_len) view
     * in-place (preserving FCS in sniffer mode, or using stripped rb->len in normal mode).
     * The wrapped descriptors are pinned (cleared in rx_avail_mask) until
     * esp_lmac_rx_free(), so DMA cannot overwrite rx_frontdata[0..tail_bytes) beforehand.
     */
    uint16_t span_len = g_lmac.sniffer_mode ? flen : rb->len;
    uint8_t *frame_end = frame + span_len;
    if (frame_end > g_lmac.rx_extradata) {
        size_t tail_bytes = (size_t)(frame_end - g_lmac.rx_extradata);
        if (tail_bytes <= g_lmac.cfg.rx_max_single_pkt_len) {
            memcpy(g_lmac.rx_extradata, g_lmac.rx_frontdata, tail_bytes);
        } else {
            /* Frame exceeds extradata scratch: drop and recycle */
            esp_lmac_rx_free(rb);
            return;
        }
    }

    rb->rx_ctrl = ctrl;
    rb->frame = frame;
    g_lmac.stats.rx_delivered++;

    if (g_lmac.sniffer_mode) {
        if (g_lmac.cbs.on_sniffer_frame != NULL) {
            g_lmac.cbs.on_sniffer_frame(g_lmac.cbs.ctx, ctrl, frame, flen);
        }
        esp_lmac_rx_free(rb);
        return;
    }

    if (g_lmac.cbs.on_rx_frame != NULL) {
        /* Upper layer takes ownership and MUST call esp_lmac_rx_free(rb) (immediately or via pbuf free) */
        g_lmac.cbs.on_rx_frame(g_lmac.cbs.ctx, rb);
    } else {
        esp_lmac_rx_free(rb);
    }
}

/**
 * @brief Calibrate RSSI and deliver an NMI-captured `LMAC_INT_SNIFFER_END` packet.
 *
 * Drops NULL entries or frames shorter than `LMAC_IEEE80211_MIN_MPDU_LEN` (10 B),
 * calibrates raw RSSI to dBm, increments `rx_delivered`, and invokes `on_sniffer_frame`
 * if sniffer mode is still active.
 *
 * @param pkt  Local stack copy of the 128-byte `snf_ring` entry (12-B `rx_ctrl` + up to 112-B frame).
 */
void lmac_dma_dispatch_sniffer_pkt(lmac_snf_pkt_t *pkt)
{
    if (pkt == NULL || pkt->flen < LMAC_IEEE80211_MIN_MPDU_LEN) {
        return;
    }

    /* Convert hardware raw RSSI (byte 0) to calibrated dBm (raw - 96, matching ppProcessRxPktHdr) */
    pkt->raw[0] = (uint8_t)((int8_t)pkt->raw[0] - LMAC_RSSI_HW_OFFSET_DBM);
    g_lmac.stats.rx_delivered++;

    if (g_lmac.sniffer_mode != 0U && g_lmac.cbs.on_sniffer_frame != NULL) {
        const wifi_pkt_rx_ctrl_t *ctrl = (const wifi_pkt_rx_ctrl_t *)(const void *)pkt->raw;
        const uint8_t *frame = pkt->raw + sizeof(wifi_pkt_rx_ctrl_t);
        g_lmac.cbs.on_sniffer_frame(g_lmac.cbs.ctx, ctrl, frame, pkt->flen);
    }
}
