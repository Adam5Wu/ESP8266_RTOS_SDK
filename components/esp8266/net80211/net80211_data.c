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
// 802.3 <-> 802.11 data plane: scatter-gather TX without mutating lwIP pbufs,
// hardware CCMP / SoftAP TKIP Michael MIC framing, in-place RX decapsulation,
// hybrid zero-copy vs copy RX handoff, EAPOL dispatch, and SoftAP hairpinning.

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "net80211_internal.h"

#define TAG "wifi_data"

#define N8_RX_COPY_HEAP_FLOOR   0x1800U /* 6 KB minimum DRAM floor for zero-copy */

static const uint8_t s_rfc1042_hdr[6] = { 0xAAU, 0xAAU, 0x03U, 0x00U, 0x00U, 0x00U };

static void write_ccmp_hdr(uint8_t out[8], uint64_t pn, uint8_t key_idx)
{
    out[0] = (uint8_t)(pn & 0xFFU);
    out[1] = (uint8_t)((pn >> 8) & 0xFFU);
    out[2] = 0U;
    out[3] = (uint8_t)(0x20U | ((key_idx & 3U) << 6));
    out[4] = (uint8_t)((pn >> 16) & 0xFFU);
    out[5] = (uint8_t)((pn >> 24) & 0xFFU);
    out[6] = (uint8_t)((pn >> 32) & 0xFFU);
    out[7] = (uint8_t)((pn >> 40) & 0xFFU);
}

static void write_tkip_hdr(uint8_t out[8], uint64_t tsc, uint8_t key_idx)
{
    uint8_t tsc1 = (uint8_t)((tsc >> 8) & 0xFFU);
    out[0] = tsc1;
    out[1] = (uint8_t)((tsc1 | 0x20U) & 0x7FU);
    out[2] = (uint8_t)(tsc & 0xFFU);
    out[3] = (uint8_t)(0x20U | ((key_idx & 3U) << 6));
    out[4] = (uint8_t)((tsc >> 16) & 0xFFU);
    out[5] = (uint8_t)((tsc >> 24) & 0xFFU);
    out[6] = (uint8_t)((tsc >> 32) & 0xFFU);
    out[7] = (uint8_t)((tsc >> 40) & 0xFFU);
}

/**
 * @brief Extract a 48-bit CCMP Packet Number (PN) from an 8-byte CCMP header.
 *
 * @param iv Pointer to the 8-byte CCMP IV immediately following the MAC header.
 * @return 48-bit little-endian CCMP packet number.
 */
uint64_t n8_ccmp_iv_to_pn(const uint8_t *iv)
{
    return (uint64_t)iv[0] |
           ((uint64_t)iv[1] << 8) |
           ((uint64_t)iv[4] << 16) |
           ((uint64_t)iv[5] << 24) |
           ((uint64_t)iv[6] << 32) |
           ((uint64_t)iv[7] << 40);
}

/**
 * @brief Extract a 48-bit TKIP Sequence Counter (TSC) from an 8-byte TKIP IV/EIV.
 *
 * @param iv Pointer to the 8-byte TKIP IV/EIV (iv[2]=TSC0, iv[0]=TSC1, iv[4..7]=TSC2..5).
 * @return 48-bit TKIP sequence counter.
 */
static uint64_t n8_tkip_iv_to_tsc(const uint8_t *iv)
{
    return (uint64_t)iv[2] |
           ((uint64_t)iv[0] << 8) |
           ((uint64_t)iv[4] << 16) |
           ((uint64_t)iv[5] << 24) |
           ((uint64_t)iv[6] << 32) |
           ((uint64_t)iv[7] << 40);
}

/**
 * @brief Check and update a 64-packet sliding-window RX replay tracker.
 *
 * @param win Replay window state (bitmap == 0ULL indicates uninitialized).
 * @param pn  48-bit PN/TSC extracted from the incoming frame.
 * @return true if the frame is fresh (non-replay) and accepted; false if replayed/stale.
 */
bool n8_replay_win_accept(n8_replay_win_t *win, uint64_t pn)
{
    if (win->bitmap == 0ULL) {
        win->max_pn = pn;
        win->bitmap = 1ULL;
        return true;
    }
    if (pn > win->max_pn) {
        uint64_t delta = pn - win->max_pn;
        win->bitmap = (delta >= N8_REPLAY_WIN_BITS) ? 1ULL : ((win->bitmap << delta) | 1ULL);
        win->max_pn = pn;
        return true;
    }
    uint64_t diff = win->max_pn - pn;
    if (diff >= N8_REPLAY_WIN_BITS || ((win->bitmap >> diff) & 1ULL) != 0ULL) {
        return false;
    }
    win->bitmap |= (1ULL << diff);
    return true;
}

/**
 * @brief Deduplicate retransmitted open-link data frames per TID.
 *
 * @param last_seq   Per-TID array of last accepted Sequence Control values.
 * @param valid_mask Bitmask of TIDs with an initialized entry in last_seq.
 * @param tid        Frame TID (0..7, or N8_NON_QOS_TID=8 for non-QoS).
 * @param fc1        Second byte of 802.11 Frame Control (contains Retry bit).
 * @param seq_ctrl   16-bit 802.11 Sequence Control field.
 * @return true if frame should be accepted; false if it is a duplicate retry.
 */
static bool n8_open_seq_dedup(uint16_t last_seq[N8_REPLAY_TID_SLOTS], uint16_t *valid_mask,
                              uint8_t tid, uint8_t fc1, uint16_t seq_ctrl)
{
    uint16_t bit = (uint16_t)(1U << tid);
    if ((fc1 & IEEE80211_FC1_RETRY) != 0U && (*valid_mask & bit) != 0U &&
        last_seq[tid] == seq_ctrl) {
        return false;
    }
    last_seq[tid] = seq_ctrl;
    *valid_mask |= bit;
    return true;
}

/* --------------------------------------------------------------------------
 * TX Completion Callback (Packs wifi_tx_status_t for lwIP wlanif.c & EAPOL)
 * -------------------------------------------------------------------------- */

static void data_tx_done_cb(void *user_ctx, const esp_lmac_tx_status_t *st)
{
    n8_tx_job_t *job = (n8_tx_job_t *)user_ctx;
    if (job == NULL || !job->in_use) {
        return;
    }

    esp_aio_t aio = job->aio;
    uint8_t is_eapol = job->is_eapol;
    job->in_use = 0U;

    wifi_tx_status_t tx_st;
    memset(&tx_st, 0, sizeof(tx_st));
    tx_st.wifi_tx_result = st->ok ? TX_STATUS_SUCCESS : TX_STATUS_LRC_EXCEED;
    tx_st.wifi_tx_lrc = (st->retries > 63U) ? 63U : st->retries;
    tx_st.wifi_tx_rate = st->hw_rate;
    memcpy(&aio.ret, &tx_st, sizeof(aio.ret));

    if (aio.cb != NULL) {
        (void)aio.cb(&aio);
    }

    if (is_eapol && g_n8.tx_cbs[WIFI_TXCB_EAPOL_ID] != NULL) {
        g_n8.tx_cbs[WIFI_TXCB_EAPOL_ID](NULL);
    }

    /* Re-kick backpressured TX queue now that an LMAC TX slot has freed */
    if (g_n8.tx_q_head != g_n8.tx_q_tail) {
        n8_post_evt(N8_EVT_TX, NULL);
    }
}

/* --------------------------------------------------------------------------
 * Internal TX Builder: 802.3 Ethernet Frame -> Scatter-Gather 802.11 LMAC TX
 * -------------------------------------------------------------------------- */

#define N8_ETH_TYPE_IPV4_H              0x08U
#define N8_ETH_TYPE_IPV4_L              0x00U
#define N8_IPV4_MIN_HDR_LEN             20U
#define N8_CTRL_SUBTYPE_WRAPPER_MIN     7U
#define N8_CTRL_FILTER_SHIFT            16U

/**
 * @brief Map an IPv4 DSCP field to 802.11 UP/TID (0..7) and LMAC Access Category.
 *
 * @param eth         Pointer to 802.3 Ethernet frame header.
 * @param payload_len Payload length following the 14-byte Ethernet header.
 * @param ac_out      Output LMAC Access Category.
 * @return 802.11 QoS TID / User Priority (0..7).
 */
static uint8_t n8_dscp_to_tid_ac(const uint8_t *eth, uint16_t payload_len, esp_lmac_ac_t *ac_out)
{
    uint8_t up = 0U;
    if (eth[12] == N8_ETH_TYPE_IPV4_H && eth[13] == N8_ETH_TYPE_IPV4_L &&
        payload_len >= N8_IPV4_MIN_HDR_LEN) {
        uint8_t dscp = (uint8_t)(eth[15] >> 2); /* IPv4 TOS/DSCP byte is payload[1] == eth[15] */
        up = (uint8_t)((dscp >> 3) & IEEE80211_QOS_TID_MASK);
    }
    switch (up) {
    case 6U:
    case 7U:
        *ac_out = ESP_LMAC_AC_VO;
        break;
    case 4U:
    case 5U:
        *ac_out = ESP_LMAC_AC_VI;
        break;
    case 1U:
    case 2U:
        *ac_out = ESP_LMAC_AC_BK;
        break;
    default: /* 0, 3 */
        *ac_out = ESP_LMAC_AC_BE;
        break;
    }
    return up;
}

static esp_err_t tx_eth_frame_on_worker(uint8_t vif, const uint8_t *eth, uint16_t eth_len,
                                        bool is_eapol, bool bypass_ap_ps,
                                        esp_lmac_tx_done_cb_t done_cb, void *done_ctx)
{
    if (eth == NULL || eth_len < 14U || eth_len > 1536U) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Fast-fail before advancing seq/PN or allocating TKIP MIC scratch when LMAC TX pool is full */
    if (!esp_lmac_tx_has_free_slot()) {
        return ESP_ERR_NO_MEM;
    }

    const uint8_t *da = eth;
    const uint8_t *sa = eth + 6U;
    const uint8_t *payload = eth + 14U;
    uint16_t payload_len = (uint16_t)(eth_len - 14U);
    bool is_mcast = (da[0] & 1U) != 0U;

    uint8_t hdr[52];
    uint16_t hdr_len = 24U;
    uint8_t trailer_len = 0U;

    esp_lmac_cipher_t cipher = ESP_LMAC_CIPHER_NONE;
    uint8_t key_idx = 0U;
    esp_lmac_peer_id_t peer_id = ESP_LMAC_PEER_INVALID;
    /*
     * Only SoftAP (FromDS=1) multicast frames have a multicast RA (Address 1)
     * and therefore use NO_ACK. On STA TX (ToDS=1), Address 1 is always the
     * unicast AP BSSID (even for Ethernet broadcast like DHCP/ARP) and MUST
     * request 802.11 ACK + hardware retries.
     */
    uint8_t flags = (vif == ESP_LMAC_VIF_AP && is_mcast)
                    ? (ESP_LMAC_TX_FLAG_NO_ACK | ESP_LMAC_TX_FLAG_FORCE_LOWEST_RATE)
                    : 0U;
    bool qos = false;
    esp_lmac_ac_t ac = is_eapol ? ESP_LMAC_AC_VO : ESP_LMAC_AC_BE;
    uint64_t pn = 0ULL;

    memset(hdr, 0, sizeof(hdr));

    if (vif == ESP_LMAC_VIF_STA) {
        if (g_n8.sta_state < N8_STA_ASSOC) {
            return ESP_ERR_WIFI_NOT_CONNECT;
        }
        if (g_n8.sta_state != N8_STA_RUN && !is_eapol) {
            return ESP_ERR_WIFI_NOT_CONNECT;
        }

        n8_pm_wake_for_tx();
        n8_pm_on_activity();

        qos = (g_n8.sta_qos_active != 0U) && !is_eapol;
        hdr[0] = IEEE80211_FC_TYPE_DATA | (qos ? IEEE80211_SUBTYPE_QOS_DATA : IEEE80211_SUBTYPE_DATA);
        hdr[1] = IEEE80211_FC1_TODS;
        memcpy(hdr + 4U, g_n8.sta_bssid, 6U);
        memcpy(hdr + 10U, g_n8.sta_mac, 6U);
        memcpy(hdr + 16U, da, 6U);
        uint16_t seq = n8_sta_next_seq();
        hdr[22] = (uint8_t)(seq & 0xFFU);
        hdr[23] = (uint8_t)(seq >> 8);
        peer_id = g_n8.sta_peer_id;
        if (is_eapol) {
            flags |= ESP_LMAC_TX_FLAG_FORCE_LOWEST_RATE;
        }

        /* Encrypt data frames once PTK is installed (never encrypt 4-way EAPOL before RUN) */
        if (g_n8.sta_ptk_cipher != ESP_LMAC_CIPHER_NONE && (!is_eapol || g_n8.sta_state == N8_STA_RUN)) {
            cipher = (esp_lmac_cipher_t)g_n8.sta_ptk_cipher;
            pn = g_n8.sta_tx_pn++;
        }
    } else {
        /* SoftAP TX */
        if (!g_n8.ap_running) {
            return ESP_ERR_WIFI_NOT_STARTED;
        }
        n8_ap_sta_t *sta = NULL;
        if (is_mcast) {
            /* Buffer multicast if any STA is sleeping (unless flushing on DTIM) */
            if (!bypass_ap_ps && g_n8.ap_stas != NULL) {
                for (uint8_t i = 0U; i < g_n8.ap_sta_cap; i++) {
                    if (g_n8.ap_stas[i].in_use && g_n8.ap_stas[i].ps_sleeping) {
                        if (n8_ap_ps_enqueue(0U, eth, eth_len)) {
                            if (done_cb != NULL) {
                                esp_lmac_tx_status_t ok_st = { .ok = 1U, .retries = 0U, .hw_rate = 0U, .ack_rssi = 0x7F };
                                done_cb(done_ctx, &ok_st);
                            }
                            return ESP_OK;
                        }
                        break;
                    }
                }
            }
            if (g_n8.ap_gtk_cipher != ESP_LMAC_CIPHER_NONE) {
                cipher = (esp_lmac_cipher_t)g_n8.ap_gtk_cipher;
                key_idx = g_n8.ap_gtk_key_idx;
                pn = g_n8.ap_gtk_pn++;
            }
        } else {
            sta = n8_ap_find_sta(da);
            if (sta == NULL || !sta->assoced) {
                return ESP_ERR_NOT_FOUND;
            }
            if (!sta->authorized && !is_eapol) {
                return ESP_ERR_WIFI_NOT_CONNECT;
            }
            if (!bypass_ap_ps && sta->ps_sleeping && !is_eapol) {
                if (n8_ap_ps_enqueue(sta->aid, eth, eth_len)) {
                    if (done_cb != NULL) {
                        esp_lmac_tx_status_t ok_st = { .ok = 1U, .retries = 0U, .hw_rate = 0U, .ack_rssi = 0x7F };
                        done_cb(done_ctx, &ok_st);
                    }
                    return ESP_OK;
                }
                return ESP_ERR_NO_MEM;
            }
            peer_id = sta->peer_id;
            qos = (sta->qos_enabled != 0U) && !is_eapol;
            if (sta->ptk_cipher != ESP_LMAC_CIPHER_NONE && (!is_eapol || sta->authorized)) {
                cipher = (esp_lmac_cipher_t)sta->ptk_cipher;
                key_idx = sta->ptk_key_idx;
                pn = sta->tx_pn++;
            }
        }

        hdr[0] = IEEE80211_FC_TYPE_DATA | (qos ? IEEE80211_SUBTYPE_QOS_DATA : IEEE80211_SUBTYPE_DATA);
        hdr[1] = IEEE80211_FC1_FROMDS;
        memcpy(hdr + 4U, da, 6U);
        memcpy(hdr + 10U, g_n8.ap_mac, 6U);
        memcpy(hdr + 16U, sa, 6U);
        uint16_t seq = n8_ap_next_seq();
        hdr[22] = (uint8_t)(seq & 0xFFU);
        hdr[23] = (uint8_t)(seq >> 8);
        if (is_eapol) {
            flags |= ESP_LMAC_TX_FLAG_FORCE_LOWEST_RATE;
        }
    }

    if (qos) {
        uint8_t up = n8_dscp_to_tid_ac(eth, payload_len, &ac);
        hdr[hdr_len++] = up;
        hdr[hdr_len++] = 0U;
    }

    /* Crypto IV/EIV header */
    if (cipher == ESP_LMAC_CIPHER_CCMP) {
        hdr[1] |= IEEE80211_FC1_PROTECTED;
        write_ccmp_hdr(hdr + hdr_len, pn, key_idx);
        hdr_len = (uint16_t)(hdr_len + 8U);
        trailer_len = 8U; /* Hardware fills 8-byte CCMP MIC */
    } else if (cipher == ESP_LMAC_CIPHER_TKIP) {
        hdr[1] |= IEEE80211_FC1_PROTECTED;
        write_tkip_hdr(hdr + hdr_len, pn, key_idx);
        hdr_len = (uint16_t)(hdr_len + IEEE80211_TKIP_HDR_LEN);
        /* Hardware computes 8-byte TKIP Michael MIC + 4-byte ICV (verified on live silicon) */
        trailer_len = IEEE80211_TKIP_TRAILER_LEN;
    }

    /* Append 8-byte LLC/SNAP header (RFC1042 + original EtherType) into LMAC scratch */
    memcpy(hdr + hdr_len, s_rfc1042_hdr, 6U);
    hdr[hdr_len + 6U] = eth[12];
    hdr[hdr_len + 7U] = eth[13];
    hdr_len = (uint16_t)(hdr_len + 8U);

    /* Scatter-gather payload directly from read-only lwIP pbuf (zero payload copy/mutation!) */
    esp_lmac_sg_seg_t seg = { .ptr = payload, .len = payload_len };
    esp_lmac_tx_req_t req = {0};
    req.vif = vif;
    req.peer_id = peer_id;
    req.ac = ac;
    req.cipher = cipher;
    req.key_idx = key_idx;
    req.flags = flags;
    req.hdr = hdr;
    req.hdr_len = hdr_len;
    req.segs = (payload_len > 0U) ? &seg : NULL;
    req.seg_cnt = (payload_len > 0U) ? 1U : 0U;
    req.trailer = NULL;
    req.trailer_len = trailer_len;
    req.done_cb = done_cb;
    req.done_ctx = done_ctx;

    return esp_lmac_tx_submit(&req);
}

static void ap_internal_free_cb(void *ctx, const esp_lmac_tx_status_t *st)
{
    (void)st;
    if (ctx != NULL) {
        heap_caps_free(ctx);
    }
}

esp_err_t n8_data_tx_eth_ap_internal(const uint8_t *eth_frame, uint16_t len, bool bypass_ps)
{
    uint8_t *copy = (uint8_t *)heap_caps_malloc(len, MALLOC_CAP_8BIT);
    if (copy == NULL) {
        return ESP_ERR_NO_MEM;
    }
    memcpy(copy, eth_frame, len);
    esp_err_t err = tx_eth_frame_on_worker(ESP_LMAC_VIF_AP, copy, len, false, bypass_ps,
                                           ap_internal_free_cb, copy);
    if (err != ESP_OK) {
        heap_caps_free(copy);
    }
    return err;
}

/* --------------------------------------------------------------------------
 * Public lwIP / Supplicant TX Entry Point: ieee80211_output_pbuf()
 * -------------------------------------------------------------------------- */

int ieee80211_output_pbuf(esp_aio_t *aio)
{
    if (!g_n8.started || aio == NULL || aio->pbuf == NULL || aio->len < 14U) {
        return -1;
    }

    uint8_t vif = (aio->fd == WIFI_IF_AP) ? ESP_LMAC_VIF_AP : ESP_LMAC_VIF_STA;
    const uint8_t *eth = (const uint8_t *)aio->pbuf;
    bool is_eapol = (eth[12] == ETH_P_EAPOL_H && eth[13] == ETH_P_EAPOL_L);

    if (vif == ESP_LMAC_VIF_STA && g_n8.sta_state < N8_STA_ASSOC) {
        return -1;
    }
    if (vif == ESP_LMAC_VIF_AP && !g_n8.ap_running) {
        return -1;
    }

    /* Allocate a TX job slot and push index to pending ring (thread-safe for tcpip_thread) */
    int slot_idx = -1;
    taskENTER_CRITICAL();
    uint8_t next_tail = (uint8_t)((g_n8.tx_q_tail + 1U) & N8_TX_RING_MASK);
    if (next_tail != g_n8.tx_q_head) {
        for (uint8_t i = 0U; i < N8_TX_RING_SIZE; i++) {
            if (!g_n8.tx_jobs[i].in_use) {
                g_n8.tx_jobs[i].in_use = 1U;
                g_n8.tx_jobs[i].aio = *aio;
                g_n8.tx_jobs[i].is_eapol = is_eapol ? 1U : 0U;
                g_n8.tx_jobs[i].vif = vif;
                g_n8.tx_pending_idx[g_n8.tx_q_tail] = i;
                g_n8.tx_q_tail = next_tail;
                slot_idx = (int)i;
                break;
            }
        }
    }
    taskEXIT_CRITICAL();

    if (slot_idx < 0) {
        if (!n8_on_worker_task() && g_n8.tx_q_head != g_n8.tx_q_tail) {
            n8_post_evt(N8_EVT_TX, NULL);
        }
        return -1; /* Queue full -> caller frees/retries pbuf */
    }

    if (n8_on_worker_task()) {
        n8_data_process_tx_queue();
    } else {
        n8_post_evt(N8_EVT_TX, NULL);
    }
    return 0;
}

void n8_data_process_tx_queue(void)
{
    for (;;) {
        int idx = -1;
        taskENTER_CRITICAL();
        if (g_n8.tx_q_head != g_n8.tx_q_tail) {
            /* Peek without advancing head until LMAC accepts or frame fails permanently */
            idx = (int)g_n8.tx_pending_idx[g_n8.tx_q_head];
        }
        taskEXIT_CRITICAL();

        if (idx < 0) {
            break;
        }

        n8_tx_job_t *job = &g_n8.tx_jobs[idx];
        if (!job->in_use) {
            taskENTER_CRITICAL();
            if (g_n8.tx_q_head != g_n8.tx_q_tail && g_n8.tx_pending_idx[g_n8.tx_q_head] == (uint8_t)idx) {
                g_n8.tx_q_head = (uint8_t)((g_n8.tx_q_head + 1U) & N8_TX_RING_MASK);
            }
            taskEXIT_CRITICAL();
            continue;
        }

        /* Pause data TX while scanning off-channel so frames never collide with off-ch ProbeResp */
        if (g_n8.scan_active) {
            if (job->vif == ESP_LMAC_VIF_STA && g_n8.sta_state == N8_STA_RUN &&
                g_n8.cur_channel != g_n8.sta_channel) {
                break;
            }
            if (job->vif == ESP_LMAC_VIF_AP && g_n8.ap_running &&
                g_n8.cur_channel != g_n8.ap_cfg.ap.channel) {
                break;
            }
        }

        esp_err_t err = tx_eth_frame_on_worker(job->vif, (const uint8_t *)job->aio.pbuf,
                                               (uint16_t)job->aio.len,
                                               (job->is_eapol != 0U), false,
                                               data_tx_done_cb, job);
        if (err == ESP_ERR_NO_MEM) {
            /* LMAC TX pool full: keep job intact at tx_q_head until data_tx_done_cb re-kicks */
            break;
        }

        taskENTER_CRITICAL();
        if (g_n8.tx_q_head != g_n8.tx_q_tail && g_n8.tx_pending_idx[g_n8.tx_q_head] == (uint8_t)idx) {
            g_n8.tx_q_head = (uint8_t)((g_n8.tx_q_head + 1U) & N8_TX_RING_MASK);
        }
        taskEXIT_CRITICAL();

        if (err != ESP_OK) {
            esp_lmac_tx_status_t fail_st = { .ok = 0U, .retries = 0U, .hw_rate = 0U, .ack_rssi = 0x7F };
            data_tx_done_cb(job, &fail_st);
        }
    }
}

/* --------------------------------------------------------------------------
 * RX Path: 802.11 -> 802.3 Decap, EAPOL Dispatch & Hybrid Zero-Copy Handoff
 * -------------------------------------------------------------------------- */

static void deliver_eth_to_netif(uint8_t vif, uint8_t *eth_ptr, uint16_t eth_len,
                                 esp_lmac_rx_buf_t *rx_buf)
{
    wifi_rxcb_t cb = (vif < 2U) ? g_n8.rxcb[vif] : NULL;
    if (cb == NULL) {
        if (rx_buf != NULL) {
            esp_lmac_rx_free(rx_buf);
        } else {
            heap_caps_free(eth_ptr);
        }
        return;
    }

    /* Heap-reassembled defragmented Ethernet buffers are already owned by caller */
    if (rx_buf == NULL) {
        if (cb(eth_ptr, eth_len, NULL) != ESP_OK) {
            heap_caps_free(eth_ptr);
        }
        return;
    }

    /*
     * Hybrid RX ownership policy:
     * Use zero-copy (eb = rx_buf) only when the frame did not wrap through the
     * shared rx_extradata scratch, contiguous DMA ring headroom exceeds
     * left_continuous_rx_buf_num, AND free DRAM > 6 KB; otherwise copy to heap,
     * recycle DMA immediately, and pass eb = NULL (tcpip_adapter frees via os_free).
     */
    bool allow_zero_copy = !esp_lmac_rx_buf_is_wrapped(rx_buf) &&
                           (esp_lmac_rx_free_contiguous() > g_n8.init_cfg.left_continuous_rx_buf_num) &&
                           (esp_get_free_heap_size() > N8_RX_COPY_HEAP_FLOOR);

    if (allow_zero_copy) {
        if (cb(eth_ptr, eth_len, rx_buf) != ESP_OK) {
            esp_lmac_rx_free(rx_buf);
        }
        return;
    }

    uint8_t *copy = (uint8_t *)heap_caps_malloc(eth_len, MALLOC_CAP_8BIT);
    if (copy == NULL) {
        esp_lmac_rx_free(rx_buf);
        return;
    }
    memcpy(copy, eth_ptr, eth_len);
    esp_lmac_rx_free(rx_buf);

    if (cb(copy, eth_len, NULL) != ESP_OK) {
        heap_caps_free(copy);
    }
}

static void handle_rx_data(esp_lmac_rx_buf_t *rx_buf)
{
    uint8_t *frame = rx_buf->frame;
    uint16_t flen = rx_buf->len;

    if (flen < 24U) {
        esp_lmac_rx_free(rx_buf);
        return;
    }

    uint8_t fc0 = frame[0];
    uint8_t fc1 = frame[1];
    uint8_t subtype = (uint8_t)(fc0 & IEEE80211_FC_SUBTYPE_MASK);
    bool to_ds = (fc1 & IEEE80211_FC1_TODS) != 0U;
    bool from_ds = (fc1 & IEEE80211_FC1_FROMDS) != 0U;
    bool is_prot = (fc1 & IEEE80211_FC1_PROTECTED) != 0U;
    bool is_qos = (subtype & 0x80U) != 0U;

    /* Determine target VIF (FromDS = STA RX, ToDS = SoftAP RX) */
    uint8_t vif;
    uint8_t da[6];
    uint8_t sa[6];
    n8_ap_sta_t *ap_sta = NULL;

    if (from_ds && !to_ds) {
        if (g_n8.sta_state < N8_STA_ASSOC || memcmp(frame + 10U, g_n8.sta_bssid, 6U) != 0) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        vif = ESP_LMAC_VIF_STA;
        memcpy(da, frame + 4U, 6U);
        memcpy(sa, frame + 16U, 6U);
        /* Drop reflected multicast frames originating from our own STA MAC */
        if (memcmp(sa, g_n8.sta_mac, 6U) == 0) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        n8_pm_on_activity();
    } else if (to_ds && !from_ds) {
        if (!g_n8.ap_running || memcmp(frame + 4U, g_n8.ap_mac, 6U) != 0) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        vif = ESP_LMAC_VIF_AP;
        memcpy(sa, frame + 10U, 6U);
        memcpy(da, frame + 16U, 6U);
        ap_sta = n8_ap_find_sta(sa);
        if (ap_sta == NULL || !ap_sta->assoced) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        ap_sta->last_rx_sec = g_n8.ap_uptime_sec;

        /* Track STA Power Management transitions (PM=1 sleeping -> PM=0 awake) */
        bool pm_now = (fc1 & IEEE80211_FC1_PM) != 0U;
        if (ap_sta->ps_sleeping && !pm_now) {
            ap_sta->ps_sleeping = 0U;
            n8_ap_ps_flush_sta(ap_sta, false);
        } else {
            ap_sta->ps_sleeping = pm_now ? 1U : 0U;
        }
    } else {
        esp_lmac_rx_free(rx_buf);
        return;
    }

    /* Drop frames flagged by WDEV hardware with TKIP Michael MIC failure (0xF5U) */
    if (rx_buf->rx_ctrl != NULL &&
        rx_buf->rx_ctrl->rxend_state == ESP_LMAC_RXSTATE_TKIP_MIC_FAIL) {
        bool is_unicast = ((da[0] & N8_MAC_MCAST_BIT) == 0U);
        esp_lmac_rx_free(rx_buf);
        if (vif == ESP_LMAC_VIF_STA && g_n8.sta_state == N8_STA_RUN && is_prot) {
            esp_lmac_cipher_t exp_c = is_unicast
                                      ? (esp_lmac_cipher_t)g_n8.sta_ptk_cipher
                                      : (esp_lmac_cipher_t)g_n8.sta_gtk_cipher;
            if (exp_c == ESP_LMAC_CIPHER_TKIP &&
                g_n8.wpa_cb != NULL && g_n8.wpa_cb->wpa_michael_mic_failure != NULL) {
                (void)g_n8.wpa_cb->wpa_michael_mic_failure(is_unicast ? 1U : 0U);
            }
        } else if (vif == ESP_LMAC_VIF_AP) {
            ESP_LOGW(TAG, "SoftAP TKIP MIC failure from %02x:%02x:%02x:%02x:%02x:%02x",
                     sa[0], sa[1], sa[2], sa[3], sa[4], sa[5]);
        }
        return;
    }

    /* Null-data / QoS-Null frames carry PM state only, no payload */
    if (subtype == IEEE80211_SUBTYPE_NULLFUNC || subtype == IEEE80211_SUBTYPE_QOS_NULL) {
        esp_lmac_rx_free(rx_buf);
        return;
    }

    /* Defensive A-MSDU drop guard (OSS does not support A-MSDU RX) */
    if (is_qos && (flen < IEEE80211_QOS_HDR_LEN ||
                   (frame[IEEE80211_HDR_LEN] & IEEE80211_QOS_AMSDU_BIT) != 0U)) {
        esp_lmac_rx_free(rx_buf);
        return;
    }

    uint16_t seq_ctrl = (uint16_t)((uint16_t)frame[IEEE80211_HDR_SEQ_OFF] |
                                   ((uint16_t)frame[IEEE80211_HDR_SEQ_OFF + 1U] << 8));
#ifndef CONFIG_ESP8266_OSS_WIFI_RX_DEFRAG_ENABLED
    /* Drop fragmented MPDUs by default when RX defragmentation is disabled */
    if ((fc1 & IEEE80211_FC1_MOREFRAG) != 0U || (seq_ctrl & IEEE80211_FRAG_NUM_MASK) != 0U) {
        esp_lmac_rx_free(rx_buf);
        return;
    }
#endif

    /* Enforce Protected bit against expected link cipher (CVE-2020-26140) */
    esp_lmac_cipher_t exp_cipher = ESP_LMAC_CIPHER_NONE;
    if (vif == ESP_LMAC_VIF_STA) {
        exp_cipher = ((da[0] & N8_MAC_MCAST_BIT) != 0U)
                     ? (esp_lmac_cipher_t)g_n8.sta_gtk_cipher
                     : (esp_lmac_cipher_t)g_n8.sta_ptk_cipher;
    } else if (ap_sta != NULL) {
        exp_cipher = (esp_lmac_cipher_t)ap_sta->ptk_cipher;
    }

    uint16_t hdr_len = IEEE80211_HDR_LEN + (is_qos ? IEEE80211_QOS_CTRL_LEN : 0U);
    uint8_t tid = is_qos ? (uint8_t)(frame[IEEE80211_HDR_LEN] & IEEE80211_QOS_TID_MASK) : N8_NON_QOS_TID;
    uint16_t tail_strip = 0U;
    uint8_t key_idx = 0U;
    uint64_t frag_pn = 0ULL;
    if (is_prot) {
        if (exp_cipher == ESP_LMAC_CIPHER_NONE) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        if (rx_buf->rx_ctrl != NULL && rx_buf->rx_ctrl->rxend_state != ESP_LMAC_RXSTATE_OK) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        if (flen < (uint16_t)(hdr_len + 8U)) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        const uint8_t *iv = frame + hdr_len;
        uint8_t ext_iv = iv[3] & 0x20U;
        key_idx = (uint8_t)((iv[3] >> 6) & 3U);
        if (exp_cipher == ESP_LMAC_CIPHER_CCMP || exp_cipher == ESP_LMAC_CIPHER_TKIP) {
            if (ext_iv == 0U) {
                esp_lmac_rx_free(rx_buf);
                return;
            }
            uint64_t pn = (exp_cipher == ESP_LMAC_CIPHER_TKIP)
                          ? n8_tkip_iv_to_tsc(iv)
                          : n8_ccmp_iv_to_pn(iv);
            n8_replay_win_t *rwin = NULL;
            if (vif == ESP_LMAC_VIF_STA) {
                if ((da[0] & N8_MAC_MCAST_BIT) != 0U) {
                    uint8_t kidx = (uint8_t)(key_idx & 1U);
                    rwin = &g_n8.sta_rx_gtk_pn[kidx];
                } else {
                    rwin = &g_n8.sta_rx_ptk_pn[tid];
                }
            } else {
                rwin = &ap_sta->ptk_pn[tid];
            }
            if (!n8_replay_win_accept(rwin, pn)) {
                esp_lmac_rx_free(rx_buf);
                return;
            }
            frag_pn = pn;
            hdr_len = (uint16_t)(hdr_len + 8U);
            tail_strip = (exp_cipher == ESP_LMAC_CIPHER_TKIP)
                         ? IEEE80211_TKIP_TRAILER_LEN
                         : IEEE80211_CCMP_MIC_LEN;
        } else {
            /* WEP (4-B IV + 4-B ICV) */
            if (ext_iv != 0U) {
                esp_lmac_rx_free(rx_buf);
                return;
            }
            hdr_len = (uint16_t)(hdr_len + 4U);
            tail_strip = 4U;
        }
    } else {
        if (vif == ESP_LMAC_VIF_STA) {
            if ((g_n8.sta_state == N8_STA_RUN && exp_cipher != ESP_LMAC_CIPHER_NONE) ||
                (g_n8.sta_ptk_cipher != (uint8_t)ESP_LMAC_CIPHER_NONE)) {
                esp_lmac_rx_free(rx_buf);
                return;
            }
            if (!n8_open_seq_dedup(g_n8.sta_last_rx_seq, &g_n8.sta_last_rx_seq_valid,
                                   tid, fc1, seq_ctrl)) {
                esp_lmac_rx_free(rx_buf);
                return;
            }
        } else {
            if (ap_sta->ptk_cipher != (uint8_t)ESP_LMAC_CIPHER_NONE) {
                esp_lmac_rx_free(rx_buf);
                return;
            }
            if (!n8_open_seq_dedup(ap_sta->last_rx_seq, &ap_sta->last_rx_seq_valid,
                                   tid, fc1, seq_ctrl)) {
                esp_lmac_rx_free(rx_buf);
                return;
            }
        }
    }

    uint8_t *llc = NULL;
    uint16_t msdu_len = 0U;
    uint8_t *reasm = NULL;

#ifdef CONFIG_ESP8266_OSS_WIFI_RX_DEFRAG_ENABLED
    bool more_frag = (fc1 & IEEE80211_FC1_MOREFRAG) != 0U;
    uint8_t frag_num = (uint8_t)(seq_ctrl & IEEE80211_FRAG_NUM_MASK);
    if (more_frag || frag_num != 0U) {
        if ((da[0] & N8_MAC_MCAST_BIT) != 0U || flen < (uint16_t)(hdr_len + tail_strip + 1U)) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        uint16_t frag_payload_len = (uint16_t)(flen - hdr_len - tail_strip);
        reasm = n8_defrag_rx_frag(vif, frame + IEEE80211_HDR_ADDR2_OFF, tid, seq_ctrl,
                                  more_frag, is_prot, exp_cipher, key_idx, frag_pn,
                                  frame + hdr_len, frag_payload_len, &msdu_len);
        esp_lmac_rx_free(rx_buf);
        rx_buf = NULL;
        if (reasm == NULL) {
            return;
        }
        if (msdu_len < 8U || memcmp(reasm, s_rfc1042_hdr, 6U) != 0) {
            heap_caps_free(reasm);
            return;
        }
        llc = reasm;
    } else
#else
    (void)key_idx;
    (void)frag_pn;
#endif
    {
        /* Need at least 8-byte RFC1042 LLC/SNAP header + trailer */
        if (flen < (uint16_t)(hdr_len + 8U + tail_strip)) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        llc = frame + hdr_len;
        if (memcmp(llc, s_rfc1042_hdr, 6U) != 0) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        msdu_len = (uint16_t)(flen - hdr_len - tail_strip);
    }

    uint8_t etype_h = llc[6];
    uint8_t etype_l = llc[7];
    uint8_t *payload = llc + 8U;
    uint16_t payload_len = (uint16_t)(msdu_len - 8U);

    /* Route EAPOL (0x888E) to wpa_supplicant */
    if (etype_h == ETH_P_EAPOL_H && etype_l == ETH_P_EAPOL_L) {
        uint8_t *eapol = payload;
        if (rx_buf != NULL) {
            /* Copy EAPOL to heap & free DMA descriptor BEFORE calling supplicant (which may TX!) */
            eapol = (uint8_t *)heap_caps_malloc(payload_len, MALLOC_CAP_8BIT);
            if (eapol == NULL) {
                esp_lmac_rx_free(rx_buf);
                return;
            }
            memcpy(eapol, payload, payload_len);
            esp_lmac_rx_free(rx_buf);
        }

        if (g_n8.wpa_cb != NULL) {
            if (vif == ESP_LMAC_VIF_STA && g_n8.wpa_cb->wpa_sta_rx_eapol != NULL) {
                (void)g_n8.wpa_cb->wpa_sta_rx_eapol(sa, eapol, payload_len);
            } else if (vif == ESP_LMAC_VIF_AP && ap_sta != NULL &&
                       g_n8.wpa_cb->wpa_ap_rx_eapol != NULL) {
                (void)g_n8.wpa_cb->wpa_ap_rx_eapol(g_n8.ap_hapd, ap_sta->wpa_sm, eapol, payload_len);
            }
        }
        if (reasm != NULL) {
            heap_caps_free(reasm);
        } else {
            heap_caps_free(eapol);
        }
        return;
    }

    /* Drop non-EAPOL data while port is unauthorized */
    if (vif == ESP_LMAC_VIF_STA && g_n8.sta_state != N8_STA_RUN) {
        if (reasm != NULL) {
            heap_caps_free(reasm);
        } else {
            esp_lmac_rx_free(rx_buf);
        }
        return;
    }
    if (vif == ESP_LMAC_VIF_AP && (ap_sta == NULL || !ap_sta->authorized)) {
        if (reasm != NULL) {
            heap_caps_free(reasm);
        } else {
            esp_lmac_rx_free(rx_buf);
        }
        return;
    }

    uint8_t *eth_ptr = NULL;
    uint16_t eth_len = (uint16_t)(14U + payload_len);
    if (reasm != NULL) {
        eth_ptr = (uint8_t *)heap_caps_malloc(eth_len, MALLOC_CAP_8BIT);
        if (eth_ptr == NULL) {
            heap_caps_free(reasm);
            return;
        }
        memcpy(eth_ptr, da, 6U);
        memcpy(eth_ptr + 6U, sa, 6U);
        eth_ptr[12] = etype_h;
        eth_ptr[13] = etype_l;
        memcpy(eth_ptr + 14U, payload, payload_len);
        heap_caps_free(reasm);
        reasm = NULL;
    } else {
        /* In-place 802.3 Ethernet header rewrite immediately preceding payload (safe: hdr_len+8 >= 32 >= 14) */
        eth_ptr = payload - 14U;
        memcpy(eth_ptr, da, 6U);
        memcpy(eth_ptr + 6U, sa, 6U);
        eth_ptr[12] = etype_h;
        eth_ptr[13] = etype_l;
    }

    /* SoftAP STA-to-STA hairpinning */
    if (vif == ESP_LMAC_VIF_AP) {
        if ((da[0] & 1U) != 0U) {
            /* Broadcast/multicast: forward to other associated STAs AND deliver to lwIP */
            (void)n8_data_tx_eth_ap_internal(eth_ptr, eth_len, false);
        } else if (memcmp(da, g_n8.ap_mac, 6U) != 0) {
            n8_ap_sta_t *dst_sta = n8_ap_find_sta(da);
            if (dst_sta != NULL && dst_sta->authorized) {
                (void)n8_data_tx_eth_ap_internal(eth_ptr, eth_len, false);
                if (rx_buf != NULL) {
                    esp_lmac_rx_free(rx_buf);
                } else {
                    heap_caps_free(eth_ptr);
                }
                return;
            }
        }
    }

    deliver_eth_to_netif(vif, eth_ptr, eth_len, rx_buf);
}

/**
 * @brief Dispatch received 802.11 vendor IEs once per management frame to vendor_ie_cb.
 *
 * @param ctrl  Hardware RX control header.
 * @param frame Raw 802.11 management frame.
 * @param len   Total MPDU length in bytes.
 */
static void n8_dispatch_vendor_ie_rx(const wifi_pkt_rx_ctrl_t *ctrl,
                                     const uint8_t *frame, uint16_t len)
{
    if (g_n8.vendor_ie_cb == NULL || frame == NULL || len < IEEE80211_HDR_LEN) {
        return;
    }

    uint8_t subtype = (uint8_t)(frame[0] & IEEE80211_FC_SUBTYPE_MASK);
    wifi_vendor_ie_type_t type;
    uint16_t ie_off;
    switch (subtype) {
    case IEEE80211_SUBTYPE_BEACON:
        type = WIFI_VND_IE_TYPE_BEACON;
        ie_off = 36U;
        break;
    case IEEE80211_SUBTYPE_PROBE_REQ:
        type = WIFI_VND_IE_TYPE_PROBE_REQ;
        ie_off = 24U;
        break;
    case IEEE80211_SUBTYPE_PROBE_RESP:
        type = WIFI_VND_IE_TYPE_PROBE_RESP;
        ie_off = 36U;
        break;
    case IEEE80211_SUBTYPE_ASSOC_REQ:
        type = WIFI_VND_IE_TYPE_ASSOC_REQ;
        ie_off = 28U;
        break;
    case IEEE80211_SUBTYPE_REASSOC_REQ:
        type = WIFI_VND_IE_TYPE_ASSOC_REQ;
        ie_off = 34U;
        break;
    case IEEE80211_SUBTYPE_ASSOC_RESP:
    case IEEE80211_SUBTYPE_REASSOC_RESP:
        type = WIFI_VND_IE_TYPE_ASSOC_RESP;
        ie_off = 30U;
        break;
    default:
        return;
    }

    if (len <= ie_off) {
        return;
    }

    const uint8_t *ies = frame + ie_off;
    uint16_t ie_len = (uint16_t)(len - ie_off);
    uint16_t pos = 0U;
    int rssi = (ctrl != NULL) ? (int)(int8_t)ctrl->rssi : -127;
    const uint8_t *sa = frame + IEEE80211_HDR_ADDR2_OFF;

    while (pos + 2U <= ie_len) {
        uint8_t id = ies[pos];
        uint8_t elen = ies[pos + 1U];
        if (pos + 2U + elen > ie_len) {
            break;
        }
        if (id == WIFI_VENDOR_IE_ELEMENT_ID && elen >= N8_VND_IE_MIN_LEN) {
            esp_vendor_ie_cb_t cb = g_n8.vendor_ie_cb;
            if (cb == NULL) {
                break;
            }
            cb(g_n8.vendor_ie_ctx, type, sa,
               (const vendor_ie_data_t *)(const void *)&ies[pos], rssi);
        }
        pos = (uint16_t)(pos + 2U + elen);
    }
}

void n8_data_rx_frame(esp_lmac_rx_buf_t *rx_buf)
{
    if (rx_buf == NULL || rx_buf->frame == NULL || rx_buf->len < 10U) {
        esp_lmac_rx_free(rx_buf);
        return;
    }

    uint8_t ftype = (uint8_t)(rx_buf->frame[0] & IEEE80211_FC_TYPE_MASK);

    if (ftype == IEEE80211_FC_TYPE_DATA) {
        handle_rx_data(rx_buf);
        return;
    }

    if (rx_buf->rx_ctrl != NULL &&
        rx_buf->rx_ctrl->rxend_state == ESP_LMAC_RXSTATE_TKIP_MIC_FAIL) {
        esp_lmac_rx_free(rx_buf);
        return;
    }

    if (ftype == IEEE80211_FC_TYPE_MGMT) {
        if (g_n8.vendor_ie_cb != NULL) {
            n8_dispatch_vendor_ie_rx(rx_buf->rx_ctrl, rx_buf->frame, rx_buf->len);
        }
        if (g_n8.mode == WIFI_MODE_STA || g_n8.mode == WIFI_MODE_APSTA) {
            n8_sta_rx_mgmt(rx_buf->rx_ctrl, rx_buf->freq_offset, rx_buf->frame, rx_buf->len);
        }
        if (g_n8.ap_running) {
            n8_ap_rx_mgmt(rx_buf->rx_ctrl, rx_buf->frame, rx_buf->len);
        }
    } else if (ftype == IEEE80211_FC_TYPE_CTRL) {
        if (g_n8.ap_running) {
            n8_ap_rx_ctrl(rx_buf->frame, rx_buf->len);
        }
    }

    esp_lmac_rx_free(rx_buf);
}

void n8_data_sniffer_rx(const wifi_pkt_rx_ctrl_t *ctrl, const uint8_t *frame, uint16_t len)
{
    if (g_n8.promis_cb == NULL || ctrl == NULL || frame == NULL || len < 4U) {
        return;
    }

    uint8_t ftype = (uint8_t)(frame[0] & IEEE80211_FC_TYPE_MASK);
    wifi_promiscuous_pkt_type_t ptype = WIFI_PKT_MISC;
    uint32_t fmask = WIFI_PROMIS_FILTER_MASK_MISC;

    if (ftype == IEEE80211_FC_TYPE_MGMT) {
        ptype = WIFI_PKT_MGMT;
        fmask = WIFI_PROMIS_FILTER_MASK_MGMT;
    } else if (ftype == IEEE80211_FC_TYPE_CTRL) {
        ptype = WIFI_PKT_CTRL;
        fmask = WIFI_PROMIS_FILTER_MASK_CTRL;
    } else if (ftype == IEEE80211_FC_TYPE_DATA) {
        ptype = WIFI_PKT_DATA;
        fmask = WIFI_PROMIS_FILTER_MASK_DATA;
    }

    uint32_t cur_filt = 0U;
    uint32_t cur_ctrl_filt = 0U;
    esp_lmac_sniffer_get_filter(&cur_filt, &cur_ctrl_filt);
    if ((cur_filt & fmask) == 0U) {
        return;
    }
    if (ptype == WIFI_PKT_CTRL) {
        uint8_t sub = (uint8_t)(frame[0] >> 4);
        uint32_t cbit = (sub >= N8_CTRL_SUBTYPE_WRAPPER_MIN)
                        ? (1U << (N8_CTRL_FILTER_SHIFT + sub))
                        : 0U;
        if ((cur_ctrl_filt & cbit) == 0U) {
            return;
        }
    }

    uint16_t copy_len = (len > 112U) ? 112U : len;
    uint8_t pkt_buf[sizeof(wifi_pkt_rx_ctrl_t) + 112U];
    memcpy(pkt_buf, ctrl, sizeof(wifi_pkt_rx_ctrl_t));
    memcpy(pkt_buf + sizeof(wifi_pkt_rx_ctrl_t), frame, copy_len);
    g_n8.promis_cb(pkt_buf, ptype);
}

/* --------------------------------------------------------------------------
 * tcpip_adapter RX Callback Registration & Buffer Free
 * -------------------------------------------------------------------------- */

esp_err_t esp_wifi_internal_reg_rxcb(wifi_interface_t ifx, wifi_rxcb_t fn)
{
    if (ifx != WIFI_IF_STA && ifx != WIFI_IF_AP) {
        return ESP_ERR_INVALID_ARG;
    }
    g_n8.rxcb[ifx] = fn;
    return ESP_OK;
}

void esp_wifi_internal_free_rx_buffer(void *buffer)
{
    if (buffer != NULL) {
        esp_lmac_rx_free((esp_lmac_rx_buf_t *)buffer);
    }
}
