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
// Scatter-gather TX descriptor builder, per-AC software queues, 8 hardware TX
// queue slots, retry/backoff FSM, and TX timeout/hang recovery (.flash.text).

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "lmac_internal.h"

#define TAG "lmac_tx"

#define LMAC_TX_HANG_TIMEOUT_US         400000U

static uint8_t ac_to_hwq(esp_lmac_ac_t ac, uint8_t flags)
{
    (void)ac;
    (void)flags;
    /* Serialize through HW TXQ0 to avoid multi-queue WDEV backoff lockup; prioritize VO/MGMT/BCN in SW */
    return LMAC_HW_Q_VO;
}

static lmac_tx_slot_t *tx_slot_alloc(void)
{
    for (uint8_t i = 0U; i < g_lmac.tx_pool_cnt; i++) {
        if (!g_lmac.tx_pool[i].in_use) {
            g_lmac.tx_pool[i].in_use = 1U;
            g_lmac.tx_pool[i].next = NULL;
            return &g_lmac.tx_pool[i];
        }
    }
    return NULL;
}

bool esp_lmac_tx_has_free_slot(void)
{
    if (g_lmac.tx_pool == NULL) {
        return false;
    }
    for (uint8_t i = 0U; i < g_lmac.tx_pool_cnt; i++) {
        if (!g_lmac.tx_pool[i].in_use) {
            return true;
        }
    }
    return false;
}

static void tx_slot_release(lmac_tx_slot_t *slot)
{
    if (slot != NULL) {
        slot->in_use = 0U;
        slot->next = NULL;
        slot->done_cb = NULL;
        slot->done_ctx = NULL;
    }
}

static void tx_finish_slot(lmac_tx_slot_t *slot, uint8_t ok, int8_t ack_rssi)
{
    esp_lmac_tx_done_cb_t cb = slot->done_cb;
    void *ctx = slot->done_ctx;
    esp_lmac_tx_status_t st;

    st.ok = ok;
    st.retries = slot->retries;
    st.hw_rate = slot->hw_rate;
    st.ack_rssi = ack_rssi;

    if (ok) {
        g_lmac.stats.tx_ok++;
    } else {
        g_lmac.stats.tx_fail++;
    }

    if ((slot->flags & ESP_LMAC_TX_FLAG_NO_ACK) == 0U && slot->peer_id != ESP_LMAC_PEER_INVALID) {
        lmac_trc_on_tx_result(slot->peer_id, ok, slot->retries, ack_rssi);
    }

    tx_slot_release(slot);

    if (cb != NULL) {
        cb(ctx, &st);
    }
}

#ifdef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
static void tx_arm_hw_slot(uint8_t q, lmac_tx_slot_t *slot)
{
    lmac_hw_txq_t *txq = &g_lmac.hw_txq[q];
    uint8_t hw_rate = lmac_trc_select_rate(slot->peer_id, slot->vif, slot->flags, slot->retries);
    slot->hw_rate = hw_rate;

    /* Set 802.11 FC Retry bit (byte 1, bit 3) on retransmissions */
    if (slot->retries > 0U) {
        slot->hdr_buf[1] |= 0x08U;
    }

    /* Reset owner bit on all descriptors in the scatter-gather chain */
    for (lmac_lldesc_t *d = &slot->descs[0]; d != NULL; d = d->next) {
        d->ctrl |= LLDESC_OWNER;
    }

    /* Compute remaining MSDU lifetime in TU (1024 us) */
    uint32_t elapsed_us = lmac_reg_read(LMAC_WDEV_TIME) - slot->enqueue_us;
    uint32_t rem_tu = (elapsed_us < LMAC_TX_LIFETIME_US)
                      ? ((LMAC_TX_LIFETIME_US - elapsed_us) >> 10)
                      : 10U;
    if (rem_tu < 10U) {
        rem_tu = 10U;
    } else if (rem_tu > 0x3FFU) {
        rem_tu = 0x3FFU;
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

    uint16_t dur_us = ((slot->flags & ESP_LMAC_TX_FLAG_NO_ACK) != 0U)
                      ? 0U
                      : lmac_trc_ack_duration_us(hw_rate);

    /* Write duration into 802.11 MAC header [2..3] when hardware expects ACK */
    slot->hdr_buf[2] = (uint8_t)(dur_us & 0xFFU);
    slot->hdr_buf[3] = (uint8_t)(dur_us >> 8);

    uint32_t rate_word = ((uint32_t)slot->air_len & 0x0FFFU)
                         | (((uint32_t)hw_rate & 0x0FU) << 12)
                         | (((uint32_t)slot->hw_key_slot & 0xFFU) << 16)
                         | ((hw_rate >= 16U) ? BIT(24) : 0U);

    /* Compute EDCA random backoff (matches lmacTxFrame: rand & ((1<<cw)-1) * 3.87; beacons use 0x7d) */
    uint32_t backoff;
    if ((slot->flags & ESP_LMAC_TX_FLAG_BEACON) != 0U) {
        backoff = 0x7DU;
        rem_tu = 100U;
    } else {
        uint32_t cw_mask = (1U << (txq->cw & 0x0FU)) - 1U;
        backoff = ((lmac_reg_read(LMAC_WDEV_HW_SEQ_RND) & cw_mask) * 387U) / 100U;
        if (backoff > 0x3FFU) {
            backoff = 0x3FFU;
        }
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

    txq->launch_us = lmac_reg_read(LMAC_WDEV_TIME);
    lmac_reg_set(LMAC_TXQ_LINK(q), LMAC_TXQ_LINK_GO);
}
#endif

static void tx_kick_queue(uint8_t q)
{
    lmac_hw_txq_t *txq = &g_lmac.hw_txq[q];

#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
    if (txq->q_head == NULL) {
        return;
    }

    if (g_lmac.rf_closed) {
        esp_lmac_rf_open();
    }

    vPortETSIntrLock();
    if (txq->active == NULL && txq->q_head != NULL) {
        lmac_tx_slot_t *slot = txq->q_head;
        txq->q_head = slot->next;
        if (txq->q_head == NULL) {
            txq->q_tail = NULL;
        }
        slot->next = NULL;
        txq->active = slot;
        lmac_tx_arm_hw_slot_fast(q, slot);
    }
    vPortETSIntrUnlock();
#else
    if (txq->active != NULL || txq->q_head == NULL) {
        return;
    }

    if (g_lmac.rf_closed) {
        esp_lmac_rf_open();
    }

    lmac_tx_slot_t *slot = txq->q_head;
    txq->q_head = slot->next;
    if (txq->q_head == NULL) {
        txq->q_tail = NULL;
    }
    slot->next = NULL;
    txq->active = slot;

    tx_arm_hw_slot(q, slot);
#endif
}

esp_err_t lmac_tx_init(void)
{
    uint8_t cnt = g_lmac.cfg.tx_slot_num;
    if (cnt == 0U) {
        cnt = 6U;
    }
#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
    /* Keep enough pre-built slots in DRAM to ride across SPI flash erase/read cache-off windows */
    if (cnt < 10U) {
        cnt = 10U;
    }
#endif

    if (g_lmac.tx_pool == NULL) {
        g_lmac.tx_pool = (lmac_tx_slot_t *)heap_caps_zalloc((size_t)cnt * sizeof(lmac_tx_slot_t), MALLOC_CAP_8BIT);
        if (g_lmac.tx_pool == NULL) {
            ESP_LOGE(TAG, "TX slot pool alloc failed");
            return ESP_ERR_NO_MEM;
        }
        /* Hardware TXQ_LINK uses 18-bit DRAM offset (& 0x3FFFF) in 0x3FFC0000..0x3FFFFFFF */
        uintptr_t pool_end = (uintptr_t)(g_lmac.tx_pool + cnt);
        if ((uintptr_t)g_lmac.tx_pool < 0x3FFE8000U || pool_end > 0x40000000U) {
            ESP_LOGE(TAG, "TX pool out of DRAM range: %p", (void *)g_lmac.tx_pool);
            heap_caps_free(g_lmac.tx_pool);
            g_lmac.tx_pool = NULL;
            return ESP_ERR_NO_MEM;
        }
    } else {
        memset(g_lmac.tx_pool, 0, (size_t)cnt * sizeof(lmac_tx_slot_t));
    }

    g_lmac.tx_pool_cnt = cnt;
    memset(g_lmac.hw_txq, 0, sizeof(g_lmac.hw_txq));
#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
    g_lmac.tx_done_head = NULL;
    g_lmac.tx_done_tail = NULL;
#endif

    /* EDCA backoff bounds for serialized HW TXQ0 (snappy cw_min=2, exponential backoff up to cw_max=7) */
    static const uint8_t s_aifsn[LMAC_HW_TXQ_COUNT] = { 2 };
    static const uint8_t s_cwmin[LMAC_HW_TXQ_COUNT] = { 2 };
    static const uint8_t s_cwmax[LMAC_HW_TXQ_COUNT] = { 7 };

    for (uint8_t q = 0U; q < LMAC_HW_TXQ_COUNT; q++) {
        g_lmac.hw_txq[q].aifsn = s_aifsn[q];
        g_lmac.hw_txq[q].cw_min = s_cwmin[q];
        g_lmac.hw_txq[q].cw_max = s_cwmax[q];
        g_lmac.hw_txq[q].cw = s_cwmin[q];
    }

    return ESP_OK;
}

void lmac_tx_deinit(void)
{
    for (uint8_t v = 0U; v < ESP_LMAC_VIF_MAX; v++) {
        esp_lmac_tx_flush_vif(v);
    }
    if (g_lmac.tx_pool != NULL) {
        heap_caps_free(g_lmac.tx_pool);
        g_lmac.tx_pool = NULL;
    }
    g_lmac.tx_pool_cnt = 0U;
}

esp_err_t esp_lmac_tx_submit(const esp_lmac_tx_req_t *req)
{
    if (!g_lmac.initialized || req == NULL || req->hdr == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (req->hdr_len == 0U || req->hdr_len > LMAC_TX_HDR_SCRATCH_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (req->seg_cnt > LMAC_TX_MAX_SG_SEGS || req->trailer_len > (LMAC_TX_TRAILER_SCRATCH_MAX - 4U)) {
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t mpdu_len = req->hdr_len;
    for (uint8_t i = 0U; i < req->seg_cnt; i++) {
        if (req->segs == NULL || req->segs[i].ptr == NULL || req->segs[i].len == 0U) {
            return ESP_ERR_INVALID_ARG;
        }
        uintptr_t p = (uintptr_t)req->segs[i].ptr;
        if (p < DRAM_BASE || (p + req->segs[i].len) > (DRAM_BASE + DRAM_SIZE)) {
            return ESP_ERR_INVALID_ARG;
        }
        mpdu_len += req->segs[i].len;
    }
    mpdu_len += req->trailer_len;
    if (mpdu_len + 4U > 2346U) {
        return ESP_ERR_INVALID_SIZE;
    }

    lmac_tx_slot_t *slot = tx_slot_alloc();
    if (slot == NULL) {
        return ESP_ERR_NO_MEM;
    }

    memcpy(slot->hdr_buf, req->hdr, req->hdr_len);

    /* Trailer scratch holds optional crypto MIC/ICV + 4-byte FCS padding */
    uint8_t trail_total = (uint8_t)(req->trailer_len + 4U);
    if (req->trailer != NULL && req->trailer_len > 0U) {
        memcpy(slot->trailer_buf, req->trailer, req->trailer_len);
        memset(slot->trailer_buf + req->trailer_len, 0, 4U);
    } else {
        memset(slot->trailer_buf, 0, trail_total);
    }

    /*
     * Build 2- or 3-descriptor scatter-gather DMA chain without mutating caller payload bytes:
     *   desc[0]: hdr_buf (copied header + optional inline trailer/FCS if seg_cnt == 0)
     *   desc[1..k]: read-only payload segments in DRAM
     *   desc[last]: trailer_buf (trailer_len + 4 B FCS pad)
     */
    uint8_t dcnt = 0U;
    if (req->seg_cnt == 0U && (req->hdr_len + trail_total) <= LMAC_TX_HDR_SCRATCH_MAX) {
        /* Fast single-descriptor path for short management/control frames */
        memcpy(slot->hdr_buf + req->hdr_len, slot->trailer_buf, trail_total);
        uint16_t tot = (uint16_t)(req->hdr_len + trail_total);
        slot->descs[0].ctrl = LLDESC_OWNER | LLDESC_EOF | ((uint32_t)tot << LLDESC_LEN_SHIFT) | tot;
        slot->descs[0].buf = slot->hdr_buf;
        slot->descs[0].next = NULL;
        dcnt = 1U;
    } else {
        slot->descs[dcnt].ctrl = LLDESC_OWNER | ((uint32_t)req->hdr_len << LLDESC_LEN_SHIFT) | req->hdr_len;
        slot->descs[dcnt].buf = slot->hdr_buf;
        dcnt++;

        for (uint8_t i = 0U; i < req->seg_cnt; i++) {
            uint16_t slen = req->segs[i].len;
            slot->descs[dcnt].ctrl = LLDESC_OWNER | ((uint32_t)slen << LLDESC_LEN_SHIFT) | slen;
            slot->descs[dcnt].buf = (uint8_t *)(uintptr_t)req->segs[i].ptr;
            dcnt++;
        }

        slot->descs[dcnt].ctrl = LLDESC_OWNER | LLDESC_EOF
                                 | ((uint32_t)trail_total << LLDESC_LEN_SHIFT) | trail_total;
        slot->descs[dcnt].buf = slot->trailer_buf;
        slot->descs[dcnt].next = NULL;
        dcnt++;

        for (uint8_t i = 0U; i + 1U < dcnt; i++) {
            slot->descs[i].next = &slot->descs[i + 1U];
        }
    }

    uint8_t q = ac_to_hwq(req->ac, req->flags);
    slot->done_cb = req->done_cb;
    slot->done_ctx = req->done_ctx;
    slot->enqueue_us = lmac_reg_read(LMAC_WDEV_TIME);
    slot->air_len = (uint16_t)(mpdu_len + 4U);
    slot->vif = req->vif;
    slot->peer_id = req->peer_id;
    slot->hw_q = q;
    slot->flags = req->flags;
    slot->retries = 0U;
    slot->max_retries = ((req->flags & ESP_LMAC_TX_FLAG_NO_ACK) != 0U)
                        ? 0U
                        : LMAC_TX_DEFAULT_MAX_RETRIES;
    slot->hw_key_slot = (req->cipher == ESP_LMAC_CIPHER_NONE)
                        ? 0U
                        : lmac_crypto_lookup_tx_slot(req->vif, req->peer_id, req->cipher, req->key_idx);

    g_lmac.stats.tx_submitted++;

    lmac_hw_txq_t *txq = &g_lmac.hw_txq[q];
    bool high_prio = (req->ac == ESP_LMAC_AC_VO || req->ac == ESP_LMAC_AC_MGMT ||
                      (req->flags & ESP_LMAC_TX_FLAG_BEACON) != 0U);
    slot->high_prio = high_prio ? 1U : 0U;

#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
    /* Precompute per-retry hardware rate & ACK duration in .flash.text so NMI never touches flash */
    for (uint8_t r = 0U; r <= slot->max_retries; r++) {
        uint8_t r_rate = lmac_trc_select_rate(slot->peer_id, slot->vif, slot->flags, r);
        slot->retry_rate[r] = r_rate;
        slot->retry_dur[r] = ((slot->flags & ESP_LMAC_TX_FLAG_NO_ACK) != 0U)
                             ? 0U
                             : lmac_trc_ack_duration_us(r_rate);
    }

    if (g_lmac.rf_closed) {
        esp_lmac_rf_open();
    }

    vPortETSIntrLock();
    if (txq->active == NULL && txq->q_head == NULL) {
        slot->next = NULL;
        txq->active = slot;
        lmac_tx_arm_hw_slot_fast(q, slot);
    } else {
        if (high_prio && txq->q_head != NULL && !txq->q_head->high_prio) {
            slot->next = txq->q_head;
            txq->q_head = slot;
        } else if (high_prio && txq->q_head != NULL) {
            /* Insert after last high-priority frame to preserve FIFO within VO/MGMT/BCN */
            lmac_tx_slot_t *cur = txq->q_head;
            while (cur->next != NULL && cur->next->high_prio) {
                cur = cur->next;
            }
            slot->next = cur->next;
            cur->next = slot;
            if (slot->next == NULL) {
                txq->q_tail = slot;
            }
        } else if (txq->q_tail != NULL) {
            txq->q_tail->next = slot;
            txq->q_tail = slot;
        } else {
            txq->q_head = slot;
            txq->q_tail = slot;
        }

        if (txq->active == NULL && txq->q_head != NULL) {
            lmac_tx_slot_t *head = txq->q_head;
            txq->q_head = head->next;
            if (txq->q_head == NULL) {
                txq->q_tail = NULL;
            }
            head->next = NULL;
            txq->active = head;
            lmac_tx_arm_hw_slot_fast(q, head);
        }
    }
    vPortETSIntrUnlock();
    return ESP_OK;
#else
    if (high_prio && txq->q_head != NULL && !txq->q_head->high_prio) {
        slot->next = txq->q_head;
        txq->q_head = slot;
    } else if (high_prio && txq->q_head != NULL) {
        /* Insert after last high-priority frame to preserve FIFO within VO/MGMT/BCN */
        lmac_tx_slot_t *cur = txq->q_head;
        while (cur->next != NULL && cur->next->high_prio) {
            cur = cur->next;
        }
        slot->next = cur->next;
        cur->next = slot;
        if (slot->next == NULL) {
            txq->q_tail = slot;
        }
    } else if (txq->q_tail != NULL) {
        txq->q_tail->next = slot;
        txq->q_tail = slot;
    } else {
        txq->q_head = slot;
        txq->q_tail = slot;
    }

    tx_kick_queue(q);
    return ESP_OK;
#endif
}

#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
uint8_t lmac_tx_drain_done(uint8_t max_batch)
{
    uint8_t drained = 0U;

    for (;;) {
        if (max_batch > 0U && drained >= max_batch) {
            break;
        }

        vPortETSIntrLock();
        lmac_tx_slot_t *slot = g_lmac.tx_done_head;
        if (slot != NULL) {
            g_lmac.tx_done_head = slot->next;
            if (g_lmac.tx_done_head == NULL) {
                g_lmac.tx_done_tail = NULL;
            }
            slot->next = NULL;
        }
        vPortETSIntrUnlock();

        if (slot == NULL) {
            break;
        }

        if (!slot->done_ok) {
            ESP_LOGD(TAG, "tx fail q=%u retries=%u rate=0x%02x",
                     (unsigned)slot->hw_q, (unsigned)slot->retries, (unsigned)slot->hw_rate);
        }
        tx_finish_slot(slot, slot->done_ok, slot->done_ack_rssi);
        drained++;
    }

    return drained;
}
#else
void lmac_tx_on_done_evt(const lmac_nmi_evt_t *ev)
{
    uint8_t q = ev->a;
    uint8_t cause = ev->b;
    int8_t ack_rssi = (int8_t)ev->d;

    if (q >= LMAC_HW_TXQ_COUNT) {
        return;
    }

    lmac_hw_txq_t *txq = &g_lmac.hw_txq[q];
    lmac_tx_slot_t *slot = txq->active;
    if (slot == NULL) {
        return;
    }

    if (cause == 0U) {
        /* TX success (ACK received or NO_ACK sent) */
        txq->cw = txq->cw_min;
        txq->active = NULL;
        tx_finish_slot(slot, 1U, ack_rssi);
        tx_kick_queue(q);
        return;
    }

    /* Retryable timeout/error: cause 2 (CTS timeout), 5 (ACK timeout), or sub 1/3 on 1/4 */
    bool retryable = (cause == 2U || cause == 5U ||
                      ((cause == 1U || cause == 4U) && (ev->c == 1U || ev->c == 3U)));
    uint32_t elapsed = lmac_reg_read(LMAC_WDEV_TIME) - slot->enqueue_us;

    if (retryable && slot->retries < slot->max_retries && elapsed < LMAC_TX_LIFETIME_US) {
        slot->retries++;
        g_lmac.stats.tx_retries++;
        if (txq->cw < txq->cw_max) {
            txq->cw++;
        }
        tx_arm_hw_slot(q, slot);
        return;
    }

    /* Retries exhausted or non-retryable TX error */
    ESP_LOGD(TAG, "tx fail q=%u cause=%u sub=%u retries=%u rate=0x%02x",
             (unsigned)q, (unsigned)cause, (unsigned)ev->c,
             (unsigned)slot->retries, (unsigned)slot->hw_rate);
    txq->cw = txq->cw_min;
    txq->active = NULL;
    tx_finish_slot(slot, 0U, (int8_t)0x7F);
    tx_kick_queue(q);
}
#endif

static void tx_abort_hw_queue(uint8_t q)
{
    vPortETSIntrLock();
    lmac_reg_set(LMAC_WDEV_TX_ABORT, 0xC0000000U);
    vPortETSIntrUnlock();

    ets_delay_us(34U);

    vPortETSIntrLock();
    lmac_reg_clr(LMAC_TXQ_LINK(q), BIT(30));
    lmac_reg_clr(LMAC_WDEV_TX_ABORT, 0xC0000000U);
    lmac_reg_clr(LMAC_TXQ_LINK(q), BIT(31));
    vPortETSIntrUnlock();
}

void lmac_tx_on_timeout_evt(void)
{
    uint32_t reg = lmac_reg_read(LMAC_WDEV_TXQ_TIMEOUT_MASK);
    uint32_t mask = (reg >> 16) & 0x0FFFU;
    lmac_reg_write(LMAC_WDEV_TXQ_TIMEOUT_MASK, reg & 0xF000FFFFU);

    g_lmac.stats.tx_timeouts++;
    ESP_LOGD(TAG, "hw tx timeout mask=0x%03x", (unsigned)mask);

    for (uint8_t q = 0U; q < LMAC_HW_TXQ_COUNT; q++) {
        if ((mask & (1U << q)) == 0U) {
            continue;
        }
        lmac_hw_txq_t *txq = &g_lmac.hw_txq[q];
#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
        /* Claim active slot atomically before HW abort so NMI cannot launch a new slot mid-abort */
        vPortETSIntrLock();
        lmac_tx_slot_t *slot = txq->active;
        txq->active = NULL;
        txq->cw = txq->cw_min;
        vPortETSIntrUnlock();
        tx_abort_hw_queue(q);
        (void)lmac_tx_drain_done(0U);
        if (slot != NULL) {
            tx_finish_slot(slot, 0U, (int8_t)0x7F);
        }
        tx_kick_queue(q);
#else
        tx_abort_hw_queue(q);
        if (txq->active != NULL) {
            lmac_tx_slot_t *slot = txq->active;
            txq->active = NULL;
            txq->cw = txq->cw_min;
            tx_finish_slot(slot, 0U, (int8_t)0x7F);
            tx_kick_queue(q);
        }
#endif
    }
}

void lmac_tx_check_hang(void)
{
    for (uint8_t q = 0U; q < LMAC_HW_TXQ_COUNT; q++) {
        lmac_hw_txq_t *txq = &g_lmac.hw_txq[q];
#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
        /* Read WDEV_TIME inside the NMI lock so NMI cannot advance launch_us past 'now' */
        vPortETSIntrLock();
        uint32_t now = lmac_reg_read(LMAC_WDEV_TIME);
        lmac_tx_slot_t *cur = txq->active;
        bool hung = (cur != NULL && (int32_t)(now - txq->launch_us) > (int32_t)LMAC_TX_HANG_TIMEOUT_US);
        uint8_t retries = 0U;
        uint8_t hw_rate = 0U;
        lmac_tx_slot_t *slot = NULL;
        if (hung) {
            retries = cur->retries;
            hw_rate = cur->hw_rate;
            slot = cur;
            txq->active = NULL;
            txq->cw = txq->cw_min;
        }
        vPortETSIntrUnlock();

        if (hung) {
            ESP_LOGW(TAG, "tx hang q=%u ret=%u rate=0x%02x",
                     (unsigned)q, (unsigned)retries, (unsigned)hw_rate);
            g_lmac.stats.tx_timeouts++;
            lmac_reg_set(LMAC_WDEV_PHY_CTRL, 0x00000002U);
            tx_abort_hw_queue(q);
            (void)lmac_tx_drain_done(0U);
            if (slot != NULL) {
                tx_finish_slot(slot, 0U, (int8_t)0x7F);
            }
            tx_kick_queue(q);
        }
#else
        uint32_t now = lmac_reg_read(LMAC_WDEV_TIME);
        if (txq->active != NULL && (int32_t)(now - txq->launch_us) > (int32_t)LMAC_TX_HANG_TIMEOUT_US) {
            ESP_LOGW(TAG, "tx hang q=%u ret=%u rate=0x%02x",
                     (unsigned)q, (unsigned)txq->active->retries, (unsigned)txq->active->hw_rate);
            g_lmac.stats.tx_timeouts++;
            lmac_reg_set(LMAC_WDEV_PHY_CTRL, 0x00000002U);
            tx_abort_hw_queue(q);
            lmac_tx_slot_t *slot = txq->active;
            txq->active = NULL;
            txq->cw = txq->cw_min;
            tx_finish_slot(slot, 0U, (int8_t)0x7F);
            tx_kick_queue(q);
        }
#endif
    }
}

void esp_lmac_tx_flush_vif(esp_lmac_vif_t vif)
{
#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
    (void)lmac_tx_drain_done(0U);

    for (uint8_t q = 0U; q < LMAC_HW_TXQ_COUNT; q++) {
        lmac_hw_txq_t *txq = &g_lmac.hw_txq[q];
        lmac_tx_slot_t *flush_head = NULL;
        lmac_tx_slot_t *flush_tail = NULL;

        /* Atomically unlink queued frames for this VIF and inspect active slot */
        vPortETSIntrLock();
        lmac_tx_slot_t *prev = NULL;
        lmac_tx_slot_t *cur = txq->q_head;
        while (cur != NULL) {
            lmac_tx_slot_t *next = cur->next;
            if (cur->vif == vif) {
                if (prev != NULL) {
                    prev->next = next;
                } else {
                    txq->q_head = next;
                }
                if (txq->q_tail == cur) {
                    txq->q_tail = prev;
                }
                cur->next = NULL;
                if (flush_tail != NULL) {
                    flush_tail->next = cur;
                    flush_tail = cur;
                } else {
                    flush_head = cur;
                    flush_tail = cur;
                }
            } else {
                prev = cur;
            }
            cur = next;
        }
        bool abort_active = (txq->active != NULL && txq->active->vif == vif);
        vPortETSIntrUnlock();

        if (abort_active) {
            tx_abort_hw_queue(q);
            vPortETSIntrLock();
            if (txq->active != NULL) {
                if (txq->active->vif == vif) {
                    lmac_tx_slot_t *slot = txq->active;
                    txq->active = NULL;
                    txq->cw = txq->cw_min;
                    slot->next = flush_head;
                    flush_head = slot;
                } else if (!g_lmac.rf_closed) {
                    /* NMI transitioned to another VIF's slot before abort: re-arm it */
                    lmac_tx_arm_hw_slot_fast(q, txq->active);
                }
            }
            vPortETSIntrUnlock();
        }

        (void)lmac_tx_drain_done(0U);

        while (flush_head != NULL) {
            lmac_tx_slot_t *next = flush_head->next;
            flush_head->next = NULL;
            tx_finish_slot(flush_head, 0U, (int8_t)0x7F);
            flush_head = next;
        }

        tx_kick_queue(q);
    }
#else
    for (uint8_t q = 0U; q < LMAC_HW_TXQ_COUNT; q++) {
        lmac_hw_txq_t *txq = &g_lmac.hw_txq[q];

        /* Abort active frame if it belongs to this VIF */
        if (txq->active != NULL && txq->active->vif == vif) {
            tx_abort_hw_queue(q);
            lmac_tx_slot_t *slot = txq->active;
            txq->active = NULL;
            txq->cw = txq->cw_min;
            tx_finish_slot(slot, 0U, (int8_t)0x7F);
        }

        /* Drain queued frames belonging to this VIF */
        lmac_tx_slot_t *prev = NULL;
        lmac_tx_slot_t *cur = txq->q_head;
        while (cur != NULL) {
            lmac_tx_slot_t *next = cur->next;
            if (cur->vif == vif) {
                if (prev != NULL) {
                    prev->next = next;
                } else {
                    txq->q_head = next;
                }
                if (txq->q_tail == cur) {
                    txq->q_tail = prev;
                }
                tx_finish_slot(cur, 0U, (int8_t)0x7F);
            } else {
                prev = cur;
            }
            cur = next;
        }

        tx_kick_queue(q);
    }
#endif
}

bool esp_lmac_tx_is_idle(void)
{
    if (g_lmac.beacon.tx_pending) {
        return false;
    }
#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
    bool idle = true;
    vPortETSIntrLock();
    if (g_lmac.tx_done_head != NULL) {
        idle = false;
    } else {
        for (uint8_t q = 0U; q < LMAC_HW_TXQ_COUNT; q++) {
            if (g_lmac.hw_txq[q].active != NULL || g_lmac.hw_txq[q].q_head != NULL) {
                idle = false;
                break;
            }
        }
    }
    vPortETSIntrUnlock();
    return idle;
#else
    for (uint8_t q = 0U; q < LMAC_HW_TXQ_COUNT; q++) {
        if (g_lmac.hw_txq[q].active != NULL || g_lmac.hw_txq[q].q_head != NULL) {
            return false;
        }
    }
    return true;
#endif
}

static void beacon_tx_done_cb(void *ctx, const esp_lmac_tx_status_t *st)
{
    (void)ctx;
    (void)st;
    g_lmac.beacon.tx_pending = 0U;
}

void lmac_tx_launch_beacon_now(void)
{
    lmac_beacon_t *b = &g_lmac.beacon;
    if (!b->active || b->buf == NULL || b->len < 36U || b->tx_pending || g_lmac.rf_closed) {
        return;
    }

    /* Stamp live 64-bit TSF1 into 802.11 Beacon fixed Timestamp field (offset 24..31) */
    uint64_t tsf = wdev_get_tsf_time(ESP_LMAC_VIF_AP);
    for (uint8_t i = 0U; i < 8U; i++) {
        b->buf[24U + i] = (uint8_t)((tsf >> (i * 8U)) & 0xFFU);
    }

    esp_lmac_sg_seg_t seg = { .ptr = b->buf + 24U, .len = (uint16_t)(b->len - 24U) };
    esp_lmac_tx_req_t req = {0};
    req.vif = ESP_LMAC_VIF_AP;
    req.peer_id = ESP_LMAC_PEER_INVALID;
    req.ac = ESP_LMAC_AC_VO;
    req.flags = ESP_LMAC_TX_FLAG_BEACON | ESP_LMAC_TX_FLAG_NO_ACK | ESP_LMAC_TX_FLAG_FORCE_LOWEST_RATE;
    req.hdr = b->buf;
    req.hdr_len = 24U;
    req.segs = &seg;
    req.seg_cnt = 1U;
    req.done_cb = beacon_tx_done_cb;
    req.done_ctx = NULL;

    b->tx_pending = 1U;
    if (esp_lmac_tx_submit(&req) != ESP_OK) {
        b->tx_pending = 0U;
    }
}
