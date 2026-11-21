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

/* --------------------------------------------------------------------------
 * Compact IEEE 802.11i Michael MIC (for SoftAP TKIP GTK & Optional Legacy TKIP)
 * -------------------------------------------------------------------------- */

static inline uint32_t rotl32(uint32_t v, uint8_t n) { return (v << n) | (v >> (32U - n)); }
static inline uint32_t rotr32(uint32_t v, uint8_t n) { return (v >> n) | (v << (32U - n)); }
static inline uint32_t xswap32(uint32_t v)           { return ((v & 0x00FF00FFU) << 8) | ((v & 0xFF00FF00U) >> 8); }

static inline uint32_t get_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
    p[2] = (uint8_t)((v >> 16) & 0xFFU);
    p[3] = (uint8_t)((v >> 24) & 0xFFU);
}

static void michael_block(uint32_t *l, uint32_t *r)
{
    *r ^= rotl32(*l, 17U); *l += *r;
    *r ^= xswap32(*l);     *l += *r;
    *r ^= rotl32(*l, 3U);  *l += *r;
    *r ^= rotr32(*l, 2U);  *l += *r;
}

void n8_michael_mic(const uint8_t key[8], const uint8_t da[6], const uint8_t sa[6],
                    uint8_t prio, const uint8_t *data, size_t len, uint8_t out_mic[8])
{
    uint32_t l = get_le32(key);
    uint32_t r = get_le32(key + 4U);

    /* Pseudo-header: DA(6) | SA(6) | prio(1) | 0,0,0(3) = 4 words */
    uint8_t phdr[16];
    memcpy(phdr, da, 6U);
    memcpy(phdr + 6U, sa, 6U);
    phdr[12] = prio;
    phdr[13] = 0U;
    phdr[14] = 0U;
    phdr[15] = 0U;
    for (uint8_t i = 0U; i < 16U; i += 4U) {
        l ^= get_le32(&phdr[i]);
        michael_block(&l, &r);
    }

    size_t pos = 0U;
    while (pos + 4U <= len) {
        l ^= get_le32(&data[pos]);
        michael_block(&l, &r);
        pos += 4U;
    }

    uint8_t tail[4] = { 0x5AU, 0U, 0U, 0U };
    size_t rem = len - pos;
    for (size_t i = 0U; i < rem; i++) {
        tail[i] = data[pos + i];
    }
    tail[rem] = 0x5AU;
    l ^= get_le32(tail);
    michael_block(&l, &r);

    /* Final zero padding word */
    michael_block(&l, &r);

    put_le32(out_mic, l);
    put_le32(out_mic + 4U, r);
}

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
    uint8_t trailer[12];
    uint8_t trailer_len = 0U;
    const uint8_t *trailer_ptr = NULL;

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
    uint64_t pn = 0ULL;
    const uint8_t *tkip_mic_key = NULL;

    memset(hdr, 0, sizeof(hdr));
    memset(trailer, 0, sizeof(trailer));

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
            tkip_mic_key = g_n8.sta_tkip_tx_mic;
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
                tkip_mic_key = g_n8.ap_gtk_tkip_mic;
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
                tkip_mic_key = sta->tkip_tx_mic;
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
        hdr[hdr_len++] = 0U; /* TID 0 (BE) */
        hdr[hdr_len++] = 0U;
    }

    /* Crypto IV/EIV header */
    if (cipher == ESP_LMAC_CIPHER_CCMP) {
        hdr[1] |= IEEE80211_FC1_PROTECTED;
        write_ccmp_hdr(hdr + hdr_len, pn, key_idx);
        hdr_len = (uint16_t)(hdr_len + 8U);
        trailer_len = 8U; /* Hardware fills 8-byte CCMP MIC */
        trailer_ptr = NULL;
    } else if (cipher == ESP_LMAC_CIPHER_TKIP) {
        hdr[1] |= IEEE80211_FC1_PROTECTED;
        write_tkip_hdr(hdr + hdr_len, pn, key_idx);
        hdr_len = (uint16_t)(hdr_len + 8U);
        if (tkip_mic_key != NULL) {
            /* Compute Michael MIC over [RFC1042(6) + EtherType(2) + payload] */
            uint8_t *mic_in = (uint8_t *)heap_caps_malloc(8U + payload_len, MALLOC_CAP_8BIT);
            if (mic_in != NULL) {
                memcpy(mic_in, s_rfc1042_hdr, 6U);
                mic_in[6] = eth[12];
                mic_in[7] = eth[13];
                memcpy(mic_in + 8U, payload, payload_len);
                n8_michael_mic(tkip_mic_key, da, sa, 0U, mic_in, (size_t)(8U + payload_len), trailer);
                heap_caps_free(mic_in);
            }
        }
        /* 8-byte Michael MIC + 4-byte hardware-filled TKIP ICV */
        trailer_len = 12U;
        trailer_ptr = trailer;
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
    req.ac = is_eapol ? ESP_LMAC_AC_VO : ESP_LMAC_AC_BE;
    req.cipher = cipher;
    req.key_idx = key_idx;
    req.flags = flags;
    req.hdr = hdr;
    req.hdr_len = hdr_len;
    req.segs = (payload_len > 0U) ? &seg : NULL;
    req.seg_cnt = (payload_len > 0U) ? 1U : 0U;
    req.trailer = trailer_ptr;
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
        esp_lmac_rx_free(rx_buf);
        return;
    }

    /*
     * Hybrid RX ownership policy:
     * Use zero-copy (eb = rx_buf) only when contiguous DMA ring headroom exceeds
     * left_continuous_rx_buf_num AND free DRAM > 6 KB; otherwise copy to heap,
     * recycle DMA immediately, and pass eb = NULL (tcpip_adapter frees via os_free).
     */
    bool allow_zero_copy = (esp_lmac_rx_free_contiguous() > g_n8.init_cfg.left_continuous_rx_buf_num) &&
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

    /* Null-data / QoS-Null frames carry PM state only, no payload */
    if (subtype == IEEE80211_SUBTYPE_NULLFUNC || subtype == IEEE80211_SUBTYPE_QOS_NULL) {
        esp_lmac_rx_free(rx_buf);
        return;
    }

    uint16_t hdr_len = 24U + (is_qos ? 2U : 0U);
    uint16_t tail_strip = 0U;
    if (is_prot) {
        if (flen < hdr_len + 8U) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        uint8_t ext_iv = frame[hdr_len + 3U] & 0x20U;
        if (ext_iv) {
            /* CCMP (8-B IV + 8-B MIC) or TKIP (8-B IV + 8-B MIC + 4-B ICV) */
            esp_lmac_cipher_t rx_c = ESP_LMAC_CIPHER_CCMP;
            if (vif == ESP_LMAC_VIF_STA) {
                rx_c = ((da[0] & 1U) != 0U) ? (esp_lmac_cipher_t)g_n8.sta_gtk_cipher
                                            : (esp_lmac_cipher_t)g_n8.sta_ptk_cipher;
            } else if (ap_sta != NULL) {
                rx_c = (esp_lmac_cipher_t)ap_sta->ptk_cipher;
            }
            hdr_len = (uint16_t)(hdr_len + 8U);
            tail_strip = (rx_c == ESP_LMAC_CIPHER_TKIP) ? 12U : 8U;
        } else {
            /* WEP (4-B IV + 4-B ICV) */
            hdr_len = (uint16_t)(hdr_len + 4U);
            tail_strip = 4U;
        }
    }

    /* Need at least 8-byte RFC1042 LLC/SNAP header + trailer */
    if (flen < (uint16_t)(hdr_len + 8U + tail_strip)) {
        esp_lmac_rx_free(rx_buf);
        return;
    }

    uint8_t *llc = frame + hdr_len;
    if (memcmp(llc, s_rfc1042_hdr, 6U) != 0) {
        esp_lmac_rx_free(rx_buf);
        return;
    }

    uint8_t etype_h = llc[6];
    uint8_t etype_l = llc[7];
    uint8_t *payload = llc + 8U;
    uint16_t payload_len = (uint16_t)(flen - hdr_len - 8U - tail_strip);

    /* Route EAPOL (0x888E) to wpa_supplicant */
    if (etype_h == ETH_P_EAPOL_H && etype_l == ETH_P_EAPOL_L) {
        /* Copy EAPOL to heap & free DMA descriptor BEFORE calling supplicant (which may TX!) */
        uint8_t *eapol = (uint8_t *)heap_caps_malloc(payload_len, MALLOC_CAP_8BIT);
        if (eapol == NULL) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        memcpy(eapol, payload, payload_len);
        esp_lmac_rx_free(rx_buf);

        if (g_n8.wpa_cb != NULL) {
            if (vif == ESP_LMAC_VIF_STA && g_n8.wpa_cb->wpa_sta_rx_eapol != NULL) {
                (void)g_n8.wpa_cb->wpa_sta_rx_eapol(sa, eapol, payload_len);
            } else if (vif == ESP_LMAC_VIF_AP && ap_sta != NULL &&
                       g_n8.wpa_cb->wpa_ap_rx_eapol != NULL) {
                (void)g_n8.wpa_cb->wpa_ap_rx_eapol(g_n8.ap_hapd, ap_sta->wpa_sm, eapol, payload_len);
            }
        }
        heap_caps_free(eapol);
        return;
    }

    /* Drop non-EAPOL data while port is unauthorized */
    if (vif == ESP_LMAC_VIF_STA && g_n8.sta_state != N8_STA_RUN) {
        esp_lmac_rx_free(rx_buf);
        return;
    }
    if (vif == ESP_LMAC_VIF_AP && (ap_sta == NULL || !ap_sta->authorized)) {
        esp_lmac_rx_free(rx_buf);
        return;
    }

    /* In-place 802.3 Ethernet header rewrite immediately preceding payload (safe: hdr_len+8 >= 32 >= 14) */
    uint8_t *eth_ptr = payload - 14U;
    uint16_t eth_len = (uint16_t)(14U + payload_len);
    memcpy(eth_ptr, da, 6U);
    memcpy(eth_ptr + 6U, sa, 6U);
    eth_ptr[12] = etype_h;
    eth_ptr[13] = etype_l;

    /* SoftAP STA-to-STA hairpinning */
    if (vif == ESP_LMAC_VIF_AP) {
        if ((da[0] & 1U) != 0U) {
            /* Broadcast/multicast: forward to other associated STAs AND deliver to lwIP */
            (void)n8_data_tx_eth_ap_internal(eth_ptr, eth_len, false);
        } else if (memcmp(da, g_n8.ap_mac, 6U) != 0) {
            n8_ap_sta_t *dst_sta = n8_ap_find_sta(da);
            if (dst_sta != NULL && dst_sta->authorized) {
                (void)n8_data_tx_eth_ap_internal(eth_ptr, eth_len, false);
                esp_lmac_rx_free(rx_buf);
                return;
            }
        }
    }

    deliver_eth_to_netif(vif, eth_ptr, eth_len, rx_buf);
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

    if (ftype == IEEE80211_FC_TYPE_MGMT) {
        if (g_n8.mode == WIFI_MODE_STA || g_n8.mode == WIFI_MODE_APSTA) {
            n8_sta_rx_mgmt(rx_buf->rx_ctrl, rx_buf->frame, rx_buf->len);
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
    esp_lmac_sniffer_get_filter(&cur_filt, NULL);
    if ((cur_filt & fmask) == 0U) {
        return;
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
