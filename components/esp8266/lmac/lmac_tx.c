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
// Scatter-gather TX descriptor builder, serialized HW TXQ0 software priority
// queue, retry/backoff FSM, and TX timeout/hang recovery (.flash.text).
//
// Portions of the WDEV TXQ MMIO arming hardware sequences are adapted in part
// from teatime-os:
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

#define TAG "lmac_tx"

/* --------------------------------------------------------------------------
 * File-Local TX Pool, DMA, Backoff, Abort & Beacon Constants
 * -------------------------------------------------------------------------- */

#define LMAC_TX_HANG_TIMEOUT_US         400000U     /* Software hang watchdog threshold (400 ms) */
#define LMAC_TX_DEFAULT_POOL_SLOTS      6U          /* Fallback TX slot count when cfg.tx_slot_num == 0 */
#define LMAC_TX_FAST_NMI_MIN_SLOTS      10U         /* Minimum DRAM slots to survive flash cache-off windows */
#define LMAC_TX_DRAM_DMA_MIN_ADDR       0x3FFE8000U /* Lower DRAM bound addressable by WDEV TXQ_LINK */
#define LMAC_TX_DRAM_DMA_END_ADDR       0x40000000U /* Exclusive upper DRAM bound for WDEV TX DMA */
#define LMAC_TX_ABORT_SETTLE_US         34U         /* Hardware settle delay while TX abort strobe drains */
#define LMAC_TX_BACKOFF_SCALE_NUM       387U        /* EDCA backoff rational multiplier numerator (3.87x) */
#define LMAC_TX_BACKOFF_SCALE_DEN       100U        /* EDCA backoff rational multiplier denominator */
#define LMAC_TXQ_CW_SHIFT_MASK          0x0FU       /* Bounds CW exponent to 0..15 before (1U << cw) */
#define LMAC_TXQ_RATE_KEY_MASK          0xFFU       /* 8-bit key slot mask in TXQ_RATE [23:16] */
#define LMAC_TXQ_HT_PLCP_LEN_MASK       0xFFFFU     /* 16-bit air_len mask in TXQ_HT_PLCP [23:8] */
#define LMAC_TXQ0_DEFAULT_AIFSN         2U          /* Serialized HW TXQ0 default AIFSN */
#define LMAC_TXQ0_DEFAULT_CW_MIN        2U          /* Serialized HW TXQ0 default CW_min exponent */
#define LMAC_TXQ0_DEFAULT_CW_MAX        7U          /* Serialized HW TXQ0 default CW_max exponent */
#define LMAC_KEY_SLOT_BYPASS            0U          /* TXQ_RATE key slot 0 = hardware crypto bypass */
#define LMAC_SW_PROT_BYPASS_NONE        0U          /* No opposite-VIF CRYPTO_CONF TX_ENC bypass active */
#define LMAC_SW_PROT_BYPASS_CONF0       1U          /* Temporarily bypassed LMAC_WDEV_CRYPTO_CONF0 (STA) */
#define LMAC_SW_PROT_BYPASS_CONF1       2U          /* Temporarily bypassed LMAC_WDEV_CRYPTO_CONF1 (SoftAP) */
#define LMAC_IEEE80211_FC_LEN           2U          /* 2-byte 802.11 Frame Control field */
#define LMAC_IEEE80211_HDR_FC1_OFF      1U          /* 802.11 Frame Control byte 1 offset (Retry/Protected) */
#define LMAC_IEEE80211_HDR_DUR_LO_OFF   2U          /* 802.11 Duration/ID low byte offset */
#define LMAC_IEEE80211_HDR_DUR_HI_OFF   3U          /* 802.11 Duration/ID high byte offset */
#define LMAC_BEACON_MIN_LEN             36U         /* 24-B mgmt header + 12-B fixed fields */
#define LMAC_BEACON_TIMESTAMP_OFF       LMAC_IEEE80211_MGMT_HDR_LEN /* 24U: 8-byte TSF1 timestamp offset */
#define LMAC_BEACON_TIMESTAMP_LEN       8U          /* 64-bit IEEE 802.11 Beacon Timestamp field size */

/**
 * @brief Map an upper-layer access category and TX flags to a hardware TX queue index.
 *
 * All traffic is serialized through hardware TXQ0 (LMAC_HW_Q_VO) to avoid multi-queue
 * WDEV backoff lockup; VO, management, and beacon frames are prioritized ahead of BE/BK
 * in the software queue of TXQ0.
 *
 * @param ac     802.11 access category (BE, BK, VI, VO, or MGMT).
 * @param flags  ESP_LMAC_TX_FLAG_* bitmask.
 * @return       Hardware TX queue index (always LMAC_HW_Q_VO = 0).
 */
static uint8_t ac_to_hwq(esp_lmac_ac_t ac, uint8_t flags)
{
    (void)ac;
    (void)flags;
    /* Serialize through HW TXQ0 to avoid multi-queue WDEV backoff lockup; prioritize VO/MGMT/BCN in SW */
    return LMAC_HW_Q_VO;
}

/**
 * @brief Allocate an unused TX slot from the static DRAM pool.
 *
 * Called serialized on the Wi-Fi worker task. Slots are only released back to the pool
 * on the Wi-Fi worker task via tx_slot_release(), so no NMI lock is required here.
 *
 * @return  Pointer to an allocated lmac_tx_slot_t, or NULL if all slots are in use.
 */
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

/**
 * @brief Check whether at least one DRAM TX slot is currently free for submission.
 *
 * Called on the Wi-Fi worker task for backpressure before assembling a TX request.
 *
 * @return  true if at least one TX slot is free; false if the pool is uninitialized or full.
 */
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

/**
 * @brief Return a completed or cancelled TX slot to the DRAM pool.
 *
 * Called only on the Wi-Fi worker task after hardware DMA and NMI no longer reference @p slot.
 *
 * @param slot  Slot pointer to mark free (NULL is safely ignored).
 */
static void tx_slot_release(lmac_tx_slot_t *slot)
{
    if (slot != NULL) {
        slot->in_use = 0U;
        slot->next = NULL;
        slot->done_cb = NULL;
        slot->done_ctx = NULL;
    }
}

/**
 * @brief Finalize a TX slot on the Wi-Fi worker task: update stats/TRC, release slot, and invoke callback.
 *
 * Releases @p slot before invoking @c done_cb so the callback may safely submit a follow-up
 * frame even when the pool was previously full. Always runs on the Wi-Fi worker task
 * outside any NMI lock.
 *
 * @param slot      Completed or aborted TX slot.
 * @param ok        1 if ACKed or NO_ACK transmission succeeded; 0 on failure/abort/timeout.
 * @param ack_rssi  Calibrated ACK RSSI in dBm, or LMAC_RSSI_UNAVAILABLE (0x7F).
 */
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
/**
 * @brief Program WDEV TXQ registers and assert GO bits from the Wi-Fi worker task (MIN_NMI mode).
 *
 * Compiled only when CONFIG_ESP8266_OSS_WIFI_MIN_NMI is enabled, where TX retries and
 * queue launches are handled entirely on the worker task in .flash.text instead of in
 * Level-3 NMI (lmac_tx_arm_hw_slot_fast). For software-encrypted frames (`Protected=1`
 * with hardware key slot 0), temporarily asserts `LMAC_CRYPTO_TX_ENC` on the opposite
 * VIF's `CRYPTO_CONF` register (recording `g_lmac.sw_prot_bypass_vif`) so WDEV transmits
 * the pre-encrypted payload verbatim until completion or abort restores it.
 *
 * @param q     Hardware TX queue index (0 .. LMAC_HW_TXQ_COUNT - 1).
 * @param slot  TX slot to arm and launch on queue @p q.
 */
static void tx_arm_hw_slot(uint8_t q, lmac_tx_slot_t *slot)
{
    lmac_hw_txq_t *txq = &g_lmac.hw_txq[q];
    uint8_t hw_rate = lmac_trc_select_rate(slot->peer_id, slot->vif, slot->flags, slot->retries);
    slot->hw_rate = hw_rate;

    /* Set 802.11 FC Retry bit (byte 1, bit 3) on retransmissions */
    if (slot->retries > 0U) {
        slot->hdr_buf[LMAC_IEEE80211_HDR_FC1_OFF] |= LMAC_IEEE80211_FC1_RETRY;
    }

    /* Reset owner bit on all descriptors in the scatter-gather chain */
    for (lmac_lldesc_t *d = &slot->descs[0]; d != NULL; d = d->next) {
        d->ctrl |= LLDESC_OWNER;
    }

    /* Compute remaining MSDU lifetime in TU (1024 us) */
    uint32_t elapsed_us = lmac_reg_read(LMAC_WDEV_TIME) - slot->enqueue_us;
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

    uint16_t dur_us = ((slot->flags & ESP_LMAC_TX_FLAG_NO_ACK) != 0U)
                      ? 0U
                      : lmac_trc_ack_duration_us(hw_rate);

    /* Write duration into 802.11 MAC header [2..3] when hardware expects ACK */
    slot->hdr_buf[LMAC_IEEE80211_HDR_DUR_LO_OFF] = (uint8_t)(dur_us & 0xFFU);
    slot->hdr_buf[LMAC_IEEE80211_HDR_DUR_HI_OFF] = (uint8_t)(dur_us >> 8);

    uint32_t rate_word = ((uint32_t)slot->air_len & LMAC_TXQ_RATE_LEN_MASK)
                         | (((uint32_t)hw_rate & LMAC_TXQ_RATE_CODE_MASK) << LMAC_TXQ_RATE_CODE_SHIFT)
                         | (((uint32_t)slot->hw_key_slot & LMAC_TXQ_RATE_KEY_MASK) << LMAC_TXQ_RATE_KEY_SHIFT)
                         | ((hw_rate >= LMAC_RATE_11N_MCS0) ? LMAC_TXQ_RATE_11N_BIT : 0U);

    /* Compute EDCA random backoff (matches lmacTxFrame: rand & ((1<<cw)-1) * 3.87; beacons use fixed backoff) */
    uint32_t backoff;
    if ((slot->flags & ESP_LMAC_TX_FLAG_BEACON) != 0U) {
        backoff = LMAC_TX_BEACON_BACKOFF;
        rem_tu = LMAC_TX_BEACON_LIFETIME_TU;
    } else {
        uint32_t cw_mask = (1U << (txq->cw & LMAC_TXQ_CW_SHIFT_MASK)) - 1U;
        backoff = ((lmac_reg_read(LMAC_WDEV_HW_SEQ_RND) & cw_mask) * LMAC_TX_BACKOFF_SCALE_NUM)
                  / LMAC_TX_BACKOFF_SCALE_DEN;
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

    txq->launch_us = lmac_reg_read(LMAC_WDEV_TIME);
    /*
     * Opposite-VIF SW-protected TX bypass:
     * When a frame is already software-encrypted (FC Protected=1, HW key slot 0), WDEV
     * still invokes HW encryption unless the selected VIF's CRYPTO_CONF has TX_ENC=1.
     * Temporarily assert TX_ENC on the steered opposite VIF register until TX finishes.
     */
    if ((slot->hdr_buf[LMAC_IEEE80211_HDR_FC1_OFF] & LMAC_FC1_PROTECTED) != 0U &&
        (slot->hw_key_slot & LMAC_KEY_SLOT_MASK) == LMAC_KEY_SLOT_BYPASS) {
        uint32_t creg = ((slot->hw_key_slot & LMAC_KEY_SLOT_AP_BIT) != 0U)
                        ? LMAC_WDEV_CRYPTO_CONF1
                        : LMAC_WDEV_CRYPTO_CONF0;
        if ((lmac_reg_read(creg) & LMAC_CRYPTO_TX_ENC) == 0U) {
            lmac_reg_set(creg, LMAC_CRYPTO_TX_ENC);
            g_lmac.sw_prot_bypass_vif = ((slot->hw_key_slot & LMAC_KEY_SLOT_AP_BIT) != 0U)
                                        ? LMAC_SW_PROT_BYPASS_CONF1
                                        : LMAC_SW_PROT_BYPASS_CONF0;
        }
    }
    lmac_reg_set(LMAC_TXQ_LINK(q), LMAC_TXQ_LINK_GO);
}
#endif

/**
 * @brief Start transmission of the head slot on queue @p q if the queue is currently idle.
 *
 * Wakes RF if currently power-gated. Under #ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI,
 * checks txq->active/q_head and calls lmac_tx_arm_hw_slot_fast() inside vPortETSIntrLock()
 * so Level-3 NMI cannot race a concurrent queue transition; under MIN_NMI, runs directly
 * on the serialized Wi-Fi worker task.
 *
 * @param q  Hardware TX queue index (0 .. LMAC_HW_TXQ_COUNT - 1).
 */
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

/**
 * @brief Allocate and initialize the DRAM TX slot pool and hardware queue EDCA state.
 *
 * Verifies the allocated pool lies within the 18-bit DRAM DMA window
 * [LMAC_TX_DRAM_DMA_MIN_ADDR, LMAC_TX_DRAM_DMA_END_ADDR) required by LMAC_TXQ_LINK.
 * Under #ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI, enforces at least LMAC_TX_FAST_NMI_MIN_SLOTS
 * (10) DRAM slots so NMI can keep transmitting across SPI flash erase/write cache-off stalls.
 *
 * @return  ESP_OK on success, or ESP_ERR_NO_MEM if DRAM allocation or DMA range check fails.
 */
esp_err_t lmac_tx_init(void)
{
    uint8_t cnt = g_lmac.cfg.tx_slot_num;
    if (cnt == 0U) {
        cnt = LMAC_TX_DEFAULT_POOL_SLOTS;
    }
#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
    /* Keep enough pre-built slots in DRAM to ride across SPI flash erase/read cache-off windows */
    if (cnt < LMAC_TX_FAST_NMI_MIN_SLOTS) {
        cnt = LMAC_TX_FAST_NMI_MIN_SLOTS;
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
        if ((uintptr_t)g_lmac.tx_pool < LMAC_TX_DRAM_DMA_MIN_ADDR || pool_end > LMAC_TX_DRAM_DMA_END_ADDR) {
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
    static const uint8_t s_aifsn[LMAC_HW_TXQ_COUNT] = { LMAC_TXQ0_DEFAULT_AIFSN };
    static const uint8_t s_cwmin[LMAC_HW_TXQ_COUNT] = { LMAC_TXQ0_DEFAULT_CW_MIN };
    static const uint8_t s_cwmax[LMAC_HW_TXQ_COUNT] = { LMAC_TXQ0_DEFAULT_CW_MAX };

    for (uint8_t q = 0U; q < LMAC_HW_TXQ_COUNT; q++) {
        g_lmac.hw_txq[q].aifsn = s_aifsn[q];
        g_lmac.hw_txq[q].cw_min = s_cwmin[q];
        g_lmac.hw_txq[q].cw_max = s_cwmax[q];
        g_lmac.hw_txq[q].cw = s_cwmin[q];
    }

    return ESP_OK;
}

/**
 * @brief Flush all active and queued TX frames across all VIFs and free the TX slot pool.
 *
 * Called during esp_lmac_deinit() on the Wi-Fi worker task.
 */
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

/**
 * @brief Validate, assemble, and enqueue an 802.11 MPDU for hardware DMA transmission.
 *
 * Resolves the hardware key slot before allocating a TX slot (failing with
 * `ESP_ERR_NOT_FOUND` when hardware encryption is requested without a matching installed
 * key, or steering software-encrypted frames with `Protected=1` and `cipher == NONE` to
 * slot 0 on the opposite VIF so WDEV bypasses hardware encryption). Copies the caller's
 * 802.11 header and optional crypto trailer into per-slot DRAM scratch buffers, chains
 * read-only DRAM payload segments without mutating caller memory, and inserts into
 * serialized HW TXQ0 with FIFO-within-priority ordering (VO/MGMT/Beacon ahead of BE/BK).
 *
 * Under #ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI, precomputes the full per-retry rate and
 * ACK duration tables in .flash.text before acquiring vPortETSIntrLock() to insert/launch
 * atomically with Level-3 NMI.
 *
 * @param req  TX submission descriptor (header, optional 0..2 DRAM segments, optional trailer, callback).
 * @return     ESP_OK if queued/launched; ESP_ERR_INVALID_ARG on bad parameters or non-DRAM segment;
 *             ESP_ERR_INVALID_SIZE if MPDU + FCS exceeds 2346 B; ESP_ERR_NOT_FOUND if hardware
 *             encryption was requested without a valid installed key slot; ESP_ERR_NO_MEM if TX
 *             slot pool is full.
 */
esp_err_t esp_lmac_tx_submit(const esp_lmac_tx_req_t *req)
{
    if (!g_lmac.initialized || req == NULL || req->hdr == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (req->hdr_len == 0U || req->hdr_len > LMAC_TX_HDR_SCRATCH_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (req->seg_cnt > LMAC_TX_MAX_SG_SEGS
        || req->trailer_len > (LMAC_TX_TRAILER_SCRATCH_MAX - LMAC_IEEE80211_FCS_LEN)) {
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
    if (mpdu_len + LMAC_IEEE80211_FCS_LEN > LMAC_IEEE80211_MAX_MPDU_LEN) {
        return ESP_ERR_INVALID_SIZE;
    }

    /*
     * Resolve HW crypto key slot before allocating a TX slot so a missing key
     * returns ESP_ERR_NOT_FOUND cleanly instead of leaking plaintext with Protected=1.
     * When SW crypto already set FC Protected=1 (cipher == NONE), steer hw_key_slot
     * to the opposite VIF's CONF register so WDEV TX bypasses HW encryption.
     */
    uint8_t hw_key_slot;
    if (req->cipher == ESP_LMAC_CIPHER_NONE && req->hdr_len >= LMAC_IEEE80211_FC_LEN &&
        (req->hdr[LMAC_IEEE80211_HDR_FC1_OFF] & LMAC_FC1_PROTECTED) != 0U) {
        hw_key_slot = (req->vif == ESP_LMAC_VIF_AP) ? LMAC_KEY_SLOT_BYPASS : LMAC_KEY_SLOT_AP_BIT;
    } else if (req->cipher == ESP_LMAC_CIPHER_NONE) {
        hw_key_slot = LMAC_KEY_SLOT_BYPASS;
    } else {
        hw_key_slot = lmac_crypto_lookup_tx_slot(req->vif, req->peer_id, req->cipher, req->key_idx);
        if (hw_key_slot == LMAC_KEY_SLOT_BYPASS) {
            return ESP_ERR_NOT_FOUND;
        }
    }

    lmac_tx_slot_t *slot = tx_slot_alloc();
    if (slot == NULL) {
        return ESP_ERR_NO_MEM;
    }

    memcpy(slot->hdr_buf, req->hdr, req->hdr_len);
    if (req->hdr_len < LMAC_IEEE80211_FC_LEN) {
        /* Clear stale FC1 byte from prior slot reuse so SW-protected detection never false-triggers */
        slot->hdr_buf[LMAC_IEEE80211_HDR_FC1_OFF] = 0U;
    }

    /* Trailer scratch holds optional crypto MIC/ICV + 4-byte FCS padding */
    uint8_t trail_total = (uint8_t)(req->trailer_len + LMAC_IEEE80211_FCS_LEN);
    if (req->trailer != NULL && req->trailer_len > 0U) {
        memcpy(slot->trailer_buf, req->trailer, req->trailer_len);
        memset(slot->trailer_buf + req->trailer_len, 0, LMAC_IEEE80211_FCS_LEN);
    } else {
        memset(slot->trailer_buf, 0, trail_total);
    }

    /*
     * Scatter-gather DMA descriptor chain construction (zero mutation of caller payload):
     *   - Fast 1-descriptor path: when there are no external payload segments and
     *     (hdr_len + trailer_len + 4-B FCS) fits inside hdr_buf (96 B), coalesce header,
     *     trailer, and FCS pad into desc[0] with LLDESC_EOF set.
     *   - Multi-descriptor path (2..4 descriptors):
     *       desc[0]      -> slot->hdr_buf (802.11 + QoS + IV + LLC/SNAP)
     *       desc[1..k]   -> read-only caller DRAM payload segments (e.g. lwIP pbufs)
     *       desc[last]   -> slot->trailer_buf (MIC/ICV + 4-B zeroed FCS pad, LLDESC_EOF)
     *     Descriptors are linked linearly with next pointers; hardware appends real FCS
     *     over the trailing 4-byte pad.
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
    slot->air_len = (uint16_t)(mpdu_len + LMAC_IEEE80211_FCS_LEN);
    slot->vif = req->vif;
    slot->peer_id = req->peer_id;
    slot->hw_q = q;
    slot->flags = req->flags;
    slot->retries = 0U;
    slot->max_retries = ((req->flags & ESP_LMAC_TX_FLAG_NO_ACK) != 0U)
                        ? 0U
                        : LMAC_TX_DEFAULT_MAX_RETRIES;
    slot->hw_key_slot = hw_key_slot;

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

    /*
     * Serialized TXQ0 FIFO-within-priority insertion under vPortETSIntrLock():
     *   - Fast path: if both active and q_head are empty, arm HW immediately.
     *   - High-priority (VO/MGMT/Beacon): preempt ahead of normal frames at q_head,
     *     or walk past existing high_prio entries so VO/MGMT/Beacon stay strictly FIFO
     *     relative to each other while jumping ahead of queued BE/BK data.
     *   - Normal priority (BE/BK/VI): append at q_tail.
     *   - Finally, if txq->active became idle before the lock, pop and arm q_head.
     */
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
    /* Serialized TXQ0 FIFO-within-priority insertion: high_prio ahead of BE/BK, FIFO within each class */
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
/**
 * @brief Drain completed TX slots handed off by Level-3 NMI on the tx_done FIFO.
 *
 * Pops each slot from g_lmac.tx_done_head under vPortETSIntrLock() (synchronized with
 * nmi_handle_tx_done() in lmac_nmi.c), then runs TRC accounting, slot release, and
 * done_cb invocation outside the lock on the Wi-Fi worker task.
 *
 * @param max_batch  Maximum number of completed slots to drain (0 = drain until empty).
 * @return           Number of completed TX slots drained and finalized.
 */
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
/**
 * @brief Handle a deferred LMAC_NMI_EVT_TX_DONE event on the Wi-Fi worker task (MIN_NMI mode).
 *
 * Compiled only when CONFIG_ESP8266_OSS_WIFI_MIN_NMI is enabled. Evaluates hardware TX
 * completion status, performs retry + CW backoff when retryable and within lifetime/retry
 * budgets, or restores any temporary opposite-VIF `LMAC_CRYPTO_TX_ENC` bypass
 * (`g_lmac.sw_prot_bypass_vif`), finalizes the active slot, and kicks the next queued slot.
 *
 * @param ev  Decoded TX-done event popped from g_lmac.nmi_ring[].
 */
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

    if (cause == LMAC_TX_CAUSE_OK) {
        /* TX success (ACK received or NO_ACK sent) */
        txq->cw = txq->cw_min;
        txq->active = NULL;
        /* Restore opposite-VIF CRYPTO_CONF TX_ENC bit if bypassed for SW-protected TX */
        if (g_lmac.sw_prot_bypass_vif != LMAC_SW_PROT_BYPASS_NONE) {
            lmac_reg_clr(LMAC_WDEV_CRYPTO_CONF0 + (((uint32_t)g_lmac.sw_prot_bypass_vif - 1U) << 2),
                         LMAC_CRYPTO_TX_ENC);
            g_lmac.sw_prot_bypass_vif = LMAC_SW_PROT_BYPASS_NONE;
        }
        tx_finish_slot(slot, 1U, ack_rssi);
        tx_kick_queue(q);
        return;
    }

    /* Retryable timeout/error: CTS timeout, ACK timeout, or sub 1/3 on cause 1/4 */
    bool retryable = (cause == LMAC_TX_CAUSE_CTS_TIMEOUT || cause == LMAC_TX_CAUSE_ACK_TIMEOUT ||
                      ((cause == LMAC_TX_CAUSE_ERR1 || cause == LMAC_TX_CAUSE_ERR4) &&
                       (ev->c == LMAC_TX_SUB_RETRY1 || ev->c == LMAC_TX_SUB_RETRY3)));
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
    /* Restore opposite-VIF CRYPTO_CONF TX_ENC bit if bypassed for SW-protected TX */
    if (g_lmac.sw_prot_bypass_vif != LMAC_SW_PROT_BYPASS_NONE) {
        lmac_reg_clr(LMAC_WDEV_CRYPTO_CONF0 + (((uint32_t)g_lmac.sw_prot_bypass_vif - 1U) << 2),
                     LMAC_CRYPTO_TX_ENC);
        g_lmac.sw_prot_bypass_vif = LMAC_SW_PROT_BYPASS_NONE;
    }
    tx_finish_slot(slot, 0U, (int8_t)LMAC_RSSI_UNAVAILABLE);
    tx_kick_queue(q);
}
#endif

/**
 * @brief Pulse the WDEV hardware TX abort strobe and disarm GO bits on queue @p q.
 *
 * Sets LMAC_WDEV_TX_ABORT_STROBE under vPortETSIntrLock(), waits LMAC_TX_ABORT_SETTLE_US
 * (34 us) with interrupts unlocked for hardware DMA/PHY to drain, then clears GO bit 0,
 * releases the abort strobe, clears GO bit 1, and restores any temporary opposite-VIF
 * `LMAC_CRYPTO_TX_ENC` bypass (`g_lmac.sw_prot_bypass_vif`) atomically under vPortETSIntrLock().
 *
 * @param q  Hardware TX queue index (0 .. LMAC_HW_TXQ_COUNT - 1).
 */
static void tx_abort_hw_queue(uint8_t q)
{
    vPortETSIntrLock();
    lmac_reg_set(LMAC_WDEV_TX_ABORT, LMAC_WDEV_TX_ABORT_STROBE);
    vPortETSIntrUnlock();

    ets_delay_us(LMAC_TX_ABORT_SETTLE_US);

    vPortETSIntrLock();
    lmac_reg_clr(LMAC_TXQ_LINK(q), LMAC_TXQ_LINK_GO_BIT0);
    lmac_reg_clr(LMAC_WDEV_TX_ABORT, LMAC_WDEV_TX_ABORT_STROBE);
    lmac_reg_clr(LMAC_TXQ_LINK(q), LMAC_TXQ_LINK_GO_BIT1);
    /* Restore opposite-VIF CRYPTO_CONF TX_ENC bit if an aborted slot held a SW-protected bypass */
    if (g_lmac.sw_prot_bypass_vif != LMAC_SW_PROT_BYPASS_NONE) {
        uint32_t creg = (g_lmac.sw_prot_bypass_vif == LMAC_SW_PROT_BYPASS_CONF0)
                        ? LMAC_WDEV_CRYPTO_CONF0
                        : LMAC_WDEV_CRYPTO_CONF1;
        lmac_reg_clr(creg, LMAC_CRYPTO_TX_ENC);
        g_lmac.sw_prot_bypass_vif = LMAC_SW_PROT_BYPASS_NONE;
    }
    vPortETSIntrUnlock();
}

/**
 * @brief Handle a hardware TX queue lifetime timeout interrupt (LMAC_NMI_EVT_TX_TIMEOUT).
 *
 * Reads and clears the latched timeout bitmask in LMAC_WDEV_TXQ_TIMEOUT_MASK, aborts each
 * timed-out hardware queue, fails its active slot, and kicks any remaining queued frames.
 * Under #ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI, atomically detaches txq->active under
 * vPortETSIntrLock() before calling tx_abort_hw_queue() so Level-3 NMI cannot launch a
 * replacement slot during the 34 us abort window.
 */
void lmac_tx_on_timeout_evt(void)
{
    uint32_t reg = lmac_reg_read(LMAC_WDEV_TXQ_TIMEOUT_MASK);
    uint32_t mask = (reg >> LMAC_TXQ_TIMEOUT_SHIFT) & LMAC_TXQ_TIMEOUT_MASK;
    lmac_reg_write(LMAC_WDEV_TXQ_TIMEOUT_MASK, reg & LMAC_TXQ_TIMEOUT_CLR_KEEP);

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
            tx_finish_slot(slot, 0U, (int8_t)LMAC_RSSI_UNAVAILABLE);
        }
        tx_kick_queue(q);
#else
        tx_abort_hw_queue(q);
        if (txq->active != NULL) {
            lmac_tx_slot_t *slot = txq->active;
            txq->active = NULL;
            txq->cw = txq->cw_min;
            tx_finish_slot(slot, 0U, (int8_t)LMAC_RSSI_UNAVAILABLE);
            tx_kick_queue(q);
        }
#endif
    }
}

/**
 * @brief Detect and recover from a stalled hardware TX queue during 100 ms housekeeping.
 *
 * Compares LMAC_WDEV_TIME against txq->launch_us; if an active frame has exceeded
 * LMAC_TX_HANG_TIMEOUT_US (400 ms), re-enables LMAC_WDEV_PHY_CTRL_RF_UP, aborts the
 * stalled queue, fails the stuck slot, and kicks the next queued frame.
 *
 * Under #ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI, reads LMAC_WDEV_TIME and inspects/claims
 * txq->active inside vPortETSIntrLock() so NMI cannot update launch_us past `now` or
 * rotate txq->active between inspection and abort.
 */
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
            lmac_reg_set(LMAC_WDEV_PHY_CTRL, LMAC_WDEV_PHY_CTRL_RF_UP);
            tx_abort_hw_queue(q);
            (void)lmac_tx_drain_done(0U);
            if (slot != NULL) {
                tx_finish_slot(slot, 0U, (int8_t)LMAC_RSSI_UNAVAILABLE);
            }
            tx_kick_queue(q);
        }
#else
        uint32_t now = lmac_reg_read(LMAC_WDEV_TIME);
        if (txq->active != NULL && (int32_t)(now - txq->launch_us) > (int32_t)LMAC_TX_HANG_TIMEOUT_US) {
            ESP_LOGW(TAG, "tx hang q=%u ret=%u rate=0x%02x",
                     (unsigned)q, (unsigned)txq->active->retries, (unsigned)txq->active->hw_rate);
            g_lmac.stats.tx_timeouts++;
            lmac_reg_set(LMAC_WDEV_PHY_CTRL, LMAC_WDEV_PHY_CTRL_RF_UP);
            tx_abort_hw_queue(q);
            lmac_tx_slot_t *slot = txq->active;
            txq->active = NULL;
            txq->cw = txq->cw_min;
            tx_finish_slot(slot, 0U, (int8_t)LMAC_RSSI_UNAVAILABLE);
            tx_kick_queue(q);
        }
#endif
    }
}

/**
 * @brief Cancel and fail all queued and in-flight TX frames belonging to @p vif.
 *
 * Preserves queued and active frames belonging to the other VIF (e.g. SoftAP traffic when
 * flushing STA on disconnect). Under #ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI, synchronizes
 * queue unlinking and active-slot abort with Level-3 NMI using vPortETSIntrLock() and
 * handles the race where NMI finishes @p vif's frame and launches the other VIF's frame
 * before tx_abort_hw_queue() completes.
 *
 * @param vif  Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP) to flush.
 */
void esp_lmac_tx_flush_vif(esp_lmac_vif_t vif)
{
#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
    (void)lmac_tx_drain_done(0U);

    for (uint8_t q = 0U; q < LMAC_HW_TXQ_COUNT; q++) {
        lmac_hw_txq_t *txq = &g_lmac.hw_txq[q];
        lmac_tx_slot_t *flush_head = NULL;
        lmac_tx_slot_t *flush_tail = NULL;

        /*
         * Step 1: Under vPortETSIntrLock(), unlink all queued slots for `vif` onto a local
         * flush list (so NMI cannot launch another frame for `vif`) and check whether the
         * currently active hardware slot belongs to `vif`.
         */
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

        /*
         * Step 2: If `vif` owned the active slot, pulse the 34 us HW TX abort outside the
         * NMI lock, then re-lock and re-inspect txq->active to resolve any NMI race:
         *   - If txq->active still belongs to `vif`, detach it onto flush_head and reset CW.
         *   - If NMI completed `vif`'s frame during the unlocked window and immediately
         *     launched a frame belonging to the *other* VIF just before tx_abort_hw_queue()
         *     cleared GO, re-arm that other VIF's slot so it is not left stranded.
         */
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

        /* Step 3: Drain any slot NMI completed mid-race, fail flushed slots, then resume other VIF */
        (void)lmac_tx_drain_done(0U);

        while (flush_head != NULL) {
            lmac_tx_slot_t *next = flush_head->next;
            flush_head->next = NULL;
            tx_finish_slot(flush_head, 0U, (int8_t)LMAC_RSSI_UNAVAILABLE);
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
            tx_finish_slot(slot, 0U, (int8_t)LMAC_RSSI_UNAVAILABLE);
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
                tx_finish_slot(cur, 0U, (int8_t)LMAC_RSSI_UNAVAILABLE);
            } else {
                prev = cur;
            }
            cur = next;
        }

        tx_kick_queue(q);
    }
#endif
}

/**
 * @brief Query whether all TX queues, pending done callbacks, and SoftAP beacon TX are idle.
 *
 * Used before channel switches, RF sleep gating, and MAC resets. Under
 * #ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI, snapshots tx_done_head, hw_txq[].active, and
 * hw_txq[].q_head atomically under vPortETSIntrLock() to avoid races with Level-3 NMI.
 *
 * @return  true if no TX frames or beacon transmissions are in flight or pending; false otherwise.
 */
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

/**
 * @brief TX completion callback for SoftAP beacon frames; clears the single-in-flight guard.
 *
 * Invoked on the Wi-Fi worker task via tx_finish_slot().
 *
 * @param ctx  Unused callback context (NULL).
 * @param st   Unused TX completion status.
 */
static void beacon_tx_done_cb(void *ctx, const esp_lmac_tx_status_t *st)
{
    (void)ctx;
    (void)st;
    g_lmac.beacon.tx_pending = 0U;
}

/**
 * @brief Stamp live TSF1 into the SoftAP beacon template and submit it for immediate TX.
 *
 * Invoked on the Wi-Fi worker task upon TBTT (LMAC_NMI_EVT_TBTT). Enforces a single
 * beacon in flight via g_lmac.beacon.tx_pending, snapshots live 64-bit TSF1 via
 * esp_lmac_get_tsf_us(ESP_LMAC_VIF_AP) into bytes [24..31] of the DRAM beacon template,
 * and submits the 24-byte 802.11 management header plus remaining body as a single
 * scatter-gather segment.
 */
void lmac_tx_launch_beacon_now(void)
{
    lmac_beacon_t *b = &g_lmac.beacon;
    if (!b->active || b->buf == NULL || b->len < LMAC_BEACON_MIN_LEN || b->tx_pending || g_lmac.rf_closed) {
        return;
    }

    /* Stamp live 64-bit TSF1 into 802.11 Beacon fixed Timestamp field (offset 24..31) */
    uint64_t tsf = esp_lmac_get_tsf_us(ESP_LMAC_VIF_AP);
    for (uint8_t i = 0U; i < LMAC_BEACON_TIMESTAMP_LEN; i++) {
        b->buf[LMAC_BEACON_TIMESTAMP_OFF + i] = (uint8_t)((tsf >> (i * 8U)) & 0xFFU);
    }

    esp_lmac_sg_seg_t seg = {
        .ptr = b->buf + LMAC_IEEE80211_MGMT_HDR_LEN,
        .len = (uint16_t)(b->len - LMAC_IEEE80211_MGMT_HDR_LEN),
    };
    esp_lmac_tx_req_t req = {0};
    req.vif = ESP_LMAC_VIF_AP;
    req.peer_id = ESP_LMAC_PEER_INVALID;
    req.ac = ESP_LMAC_AC_VO;
    req.flags = ESP_LMAC_TX_FLAG_BEACON | ESP_LMAC_TX_FLAG_NO_ACK | ESP_LMAC_TX_FLAG_FORCE_LOWEST_RATE;
    req.hdr = b->buf;
    req.hdr_len = LMAC_IEEE80211_MGMT_HDR_LEN;
    req.segs = &seg;
    req.seg_cnt = 1U;
    req.done_cb = beacon_tx_done_cb;
    req.done_ctx = NULL;

    b->tx_pending = 1U;
    if (esp_lmac_tx_submit(&req) != ESP_OK) {
        b->tx_pending = 0U;
    }
}
