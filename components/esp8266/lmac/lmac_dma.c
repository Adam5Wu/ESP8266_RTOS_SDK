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

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "lmac_internal.h"

#define TAG "lmac_dma"

esp_err_t lmac_dma_init(void)
{
    uint8_t n = g_lmac.cfg.rx_buf_num;
    uint16_t buf_len = g_lmac.cfg.rx_buf_len;
    uint16_t extra_len = g_lmac.cfg.rx_max_single_pkt_len;

    if (n == 0U || n > LMAC_MAX_RX_BUFS) {
        return ESP_ERR_INVALID_ARG;
    }
    if (buf_len < 64U || (buf_len & 3U) != 0U) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t desc_bytes = (size_t)n * sizeof(lmac_lldesc_t);
    size_t front_bytes = (size_t)n * (size_t)buf_len;
    size_t extra_bytes = ((size_t)extra_len + 3U) & ~3U;
    size_t handle_bytes = (size_t)n * sizeof(esp_lmac_rx_buf_t);
    size_t ampdu_desc_bytes = 0U;
    size_t ampdu_buf_bytes = 0U;
    size_t subframe_bytes = 0U;

#if CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
    uint8_t abuf_num = g_lmac.cfg.rx_ampdu_buf_num;
    uint16_t abuf_len = g_lmac.cfg.rx_ampdu_buf_len;
    if (g_lmac.cfg.ampdu_rx_enable != 0U) {
        if (abuf_num == 0U) {
            abuf_num = 5U;
            g_lmac.cfg.rx_ampdu_buf_num = abuf_num;
        }
        if (abuf_len < 64U) {
            abuf_len = 256U;
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
    g_lmac.empty_ampdu_desc.ctrl = LLDESC_OWNER | 4U;
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

    g_lmac.rx_avail_mask = (n >= 32U) ? 0xFFFFFFFFU : ((1U << n) - 1U);
    g_lmac.rx_head_idx = 0U;

    lmac_dma_reprogram_regs();
    return ESP_OK;
}

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
    lmac_reg_rmw(LMAC_WDEV_RX_CONF, 0x200000FFU, 0U);
}

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
 * @param rx_buf RX buffer handle delivered to the upper layer.
 * @return true if the frame crosses rx_extradata and must be heap-copied instead of zero-copied.
 */
bool esp_lmac_rx_buf_is_wrapped(const esp_lmac_rx_buf_t *rx_buf)
{
    if (rx_buf == NULL || rx_buf->frame == NULL || g_lmac.rx_extradata == NULL) {
        return false;
    }
    return (rx_buf->frame + rx_buf->len) > g_lmac.rx_extradata;
}

uint8_t esp_lmac_rx_free_contiguous(void)
{
    uint8_t n = g_lmac.cfg.rx_buf_num;
    if (n == 0U) {
        return 0U;
    }

    vPortETSIntrLock();
    uint32_t avail = g_lmac.rx_avail_mask;
    vPortETSIntrUnlock();

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
        uint8_t *ctrl_raw = (uint8_t *)(void *)sf->rx_ctrl_w;
        ctrl_raw[0] = (uint8_t)((int8_t)ctrl_raw[0] - 96);
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
        raw[0] = (uint8_t)((int8_t)raw[0] - 96);
        ctrl = (const wifi_pkt_rx_ctrl_t *)(const void *)raw;
        frame = raw + sizeof(wifi_pkt_rx_ctrl_t);

        uint32_t w0 = ((const uint32_t *)(const void *)ctrl)[0];
        uint8_t vif_match = (uint8_t)((w0 >> 28) & 0x0FU);

        rb->rx_ctrl = ctrl;
        rb->frame = frame;
        /* PLCP PSDU length includes the 4-byte hardware FCS; strip FCS for normal 802.11 consumers */
        rb->len = (!g_lmac.sniffer_mode && flen >= 4U) ? (uint16_t)(flen - 4U) : flen;
        rb->freq_offset = ev->d;
        rb->vif_match = vif_match;
        rb->desc_start = start_idx;
        rb->desc_cnt = desc_cnt;
        rb->in_use = 1U;
    }

    /* Linearize circular wrap-around into extradata (safe because wrapped descriptors are pinned) */
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
 * @brief Calibrate RSSI and deliver an NMI-captured LMAC_INT_SNIFFER_END packet.
 *
 * @param pkt Local copy of the 128-byte sniffer ring entry (header + up to 112-B frame).
 */
void lmac_dma_dispatch_sniffer_pkt(lmac_snf_pkt_t *pkt)
{
    if (pkt == NULL || pkt->flen < 10U) {
        return;
    }

    /* Convert hardware raw RSSI (byte 0) to calibrated dBm (raw - 96, matching ppProcessRxPktHdr) */
    pkt->raw[0] = (uint8_t)((int8_t)pkt->raw[0] - 96);
    g_lmac.stats.rx_delivered++;

    if (g_lmac.sniffer_mode != 0U && g_lmac.cbs.on_sniffer_frame != NULL) {
        const wifi_pkt_rx_ctrl_t *ctrl = (const wifi_pkt_rx_ctrl_t *)(const void *)pkt->raw;
        const uint8_t *frame = pkt->raw + sizeof(wifi_pkt_rx_ctrl_t);
        g_lmac.cbs.on_sniffer_frame(g_lmac.cbs.ctx, ctrl, frame, pkt->flen);
    }
}
