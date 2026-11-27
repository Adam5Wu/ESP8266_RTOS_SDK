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
// 802.3 <-> 802.11 data plane: scatter-gather QoS/WMM TX without mutating lwIP
// pbufs, hardware CCMP/TKIP framing, 64-bit PN/TSC replay & FragAttacks RX
// hardening, opt-in defragmentation, hybrid zero-copy vs copy RX handoff,
// EAPOL dispatch, SoftAP hairpinning, vendor-IE RX dispatch, and sniffer RX.

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "net80211_internal.h"

#define TAG "wifi_data"

#define N8_RX_COPY_HEAP_FLOOR       0x1800U /* 6 KB minimum DRAM floor for zero-copy */

/* Ethernet II, IPv4/DSCP, EAPOL & RFC 1042 LLC/SNAP framing constants */
#define N8_RFC1042_PREFIX_LEN       6U      /* DSAP(1) + SSAP(1) + CTRL(1) + OUI 00:00:00(3) */
#define N8_ETH_SA_OFF               6U
#define N8_ETH_TYPE_OFF             12U
#define N8_ETH_TYPE_IPV4_H          0x08U
#define N8_ETH_TYPE_IPV4_L          0x00U
#define N8_ETH_IPV4_TOS_OFF         (IEEE80211_ETH_HDR_LEN + 1U) /* IPv4 TOS/DSCP byte = payload[1] */
#define N8_IPV4_MIN_HDR_LEN         20U
#define N8_IPV4_DSCP_SHIFT          2       /* Bits [7:2] of IPv4 TOS byte hold 6-bit DSCP */
#define N8_IPV4_DSCP_UP_SHIFT       3       /* Upper 3 bits of DSCP (IP Precedence) -> 802.11 UP */
#define N8_ETH_FRAME_MAX_LEN        1536U
#define N8_EAPOL_TYPE_OFF           1U      /* Packet Type byte inside 4-byte 802.1X EAPOL header */

/* 802.11 MAC/QoS/crypto header, trailer, and control-frame sizing */
#define IEEE80211_WEP_ICV_LEN       4U
#define IEEE80211_CTRL_MIN_LEN      10U     /* Shortest valid 802.11 frame (10B ACK/CTS) */
#define N8_TX_HDR_BUF_LEN           52U     /* Scratch space: MAC(24)+QoS(2)+IV(8)+SNAP(8)=42B */
#define N8_CRYPTO_EXT_IV_OFF        3U      /* Byte 3 of 8-byte CCMP/TKIP header: ExtIV + KeyID */
#define N8_CRYPTO_KEY_IDX_MASK      3U
#define N8_CRYPTO_KEY_IDX_SHIFT     6
#define N8_GTK_REPLAY_SLOT_MASK     (N8_GTK_REPLAY_SLOTS - 1U) /* Maps GTK key IDs 1/2 -> slots 1/0 */
#define N8_TKIP_WEP_SEED_OR_MASK    0x20U   /* WEPSeed = (TSC1 | 0x20) & 0x7F (avoids weak RC4 keys) */
#define N8_TKIP_WEP_SEED_AND_MASK   0x7FU

/* Management frame fixed-body IE offsets for vendor-IE RX scanning */
#define N8_MGMT_BCN_IE_OFF          (IEEE80211_HDR_LEN + IEEE80211_BCN_FIXED_LEN) /* 36B: MAC+TSF/Int/Cap */
#define N8_MGMT_PROBE_REQ_IE_OFF    IEEE80211_HDR_LEN                              /* 24B: MAC hdr only */
#define N8_MGMT_ASSOC_REQ_IE_OFF    (IEEE80211_HDR_LEN + 4U)                       /* 28B: +Cap(2)+Listen(2) */
#define N8_MGMT_REASSOC_REQ_IE_OFF  (IEEE80211_HDR_LEN + 10U)                      /* 34B: +CurrentAP(6) */
#define N8_MGMT_ASSOC_RESP_IE_OFF   (IEEE80211_HDR_LEN + 6U)                       /* 30B: +Cap(2)+St(2)+AID(2) */

/* ERP/HT & adaptive STA RTS/CTS retry-burst thresholds */
#define N8_ERP_RTS_THRESHOLD_BYTES  256U    /* Min Ethernet frame size eligible for RTS/CTS */
#define N8_RTS_HEAVY_RETRIES        4U      /* Retries considered a contention/hidden-node burst */
#define N8_RTS_CLEAN_RETRIES        1U      /* Retries at/below which burst hysteresis decays */
#define N8_RTS_BURST_THRESH         3U      /* Burst count threshold to assert TX RTS/CTS */
#define N8_RTS_BURST_CAP            6U      /* Saturating cap on STA retry-burst counter */

/* TX status, VIF bounds, RSSI fallback, and promiscuous sniffer filtering */
#define N8_TX_STATUS_LRC_MAX        63U     /* 6-bit wifi_tx_lrc retry counter cap */
#define N8_ACK_RSSI_INVALID         0x7F
#define N8_RSSI_UNKNOWN             (-127)
#define N8_VIF_MAX                  2U
#define N8_FC_SUBTYPE_SHIFT         4
#define N8_CTRL_SUBTYPE_WRAPPER_MIN 7U      /* Lowest control subtype mapped in ctrl_filter_mask */
#define N8_CTRL_FILTER_SHIFT        16U     /* Bit shift matching WIFI_PROMIS_CTRL_FILTER_MASK_* */
#define N8_SNIFFER_MIN_LEN          4U      /* FC(2) + Duration(2) */
#define N8_SNIFFER_MAX_COPY_LEN     112U    /* ESP8266 promiscuous payload copy cap */

static const uint8_t s_rfc1042_hdr[N8_RFC1042_PREFIX_LEN] = {
    IEEE80211_LLC_DSAP_SNAP, IEEE80211_LLC_SSAP_SNAP, IEEE80211_LLC_CTRL_UI, 0x00U, 0x00U, 0x00U
};

/**
 * @brief Encode an 8-byte IEEE 802.11 CCMP (AES-CCM / RFC 3610) header.
 *
 * Wire layout: `[PN0 | PN1 | 0x00 | ExtIV(0x20) | (KeyID<<6) | PN2 | PN3 | PN4 | PN5]`.
 *
 * @param out     Output 8-byte CCMP header buffer.
 * @param pn      48-bit monotonically increasing Packet Number.
 * @param key_idx 2-bit 802.11 key index (0..3).
 */
static void write_ccmp_hdr(uint8_t out[IEEE80211_CCMP_HDR_LEN], uint64_t pn, uint8_t key_idx)
{
    out[0] = (uint8_t)(pn & 0xFFU);
    out[1] = (uint8_t)((pn >> 8) & 0xFFU);
    out[2] = 0U;
    out[3] = (uint8_t)(IEEE80211_CCMP_EXT_IV_BIT | ((key_idx & N8_CRYPTO_KEY_IDX_MASK) << N8_CRYPTO_KEY_IDX_SHIFT));
    out[4] = (uint8_t)((pn >> 16) & 0xFFU);
    out[5] = (uint8_t)((pn >> 24) & 0xFFU);
    out[6] = (uint8_t)((pn >> 32) & 0xFFU);
    out[7] = (uint8_t)((pn >> 40) & 0xFFU);
}

/**
 * @brief Encode an 8-byte IEEE 802.11 TKIP IV/Extended-IV header.
 *
 * Wire layout: `[TSC1 | WEPSeed | TSC0 | ExtIV(0x20) | (KeyID<<6) | TSC2 | TSC3 | TSC4 | TSC5]`,
 * where `WEPSeed = (TSC1 | 0x20) & 0x7F` avoids known weak RC4 IVs.
 *
 * @param out     Output 8-byte TKIP header buffer.
 * @param tsc     48-bit TKIP Sequence Counter.
 * @param key_idx 2-bit 802.11 key index (0..3).
 */
static void write_tkip_hdr(uint8_t out[IEEE80211_TKIP_HDR_LEN], uint64_t tsc, uint8_t key_idx)
{
    uint8_t tsc1 = (uint8_t)((tsc >> 8) & 0xFFU);
    out[0] = tsc1;
    out[1] = (uint8_t)((tsc1 | N8_TKIP_WEP_SEED_OR_MASK) & N8_TKIP_WEP_SEED_AND_MASK);
    out[2] = (uint8_t)(tsc & 0xFFU);
    out[3] = (uint8_t)(IEEE80211_TKIP_EXT_IV_BIT | ((key_idx & N8_CRYPTO_KEY_IDX_MASK) << N8_CRYPTO_KEY_IDX_SHIFT));
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
 * Tracks the highest accepted PN/TSC in `win->max_pn` and a 64-bit reception
 * mask in `win->bitmap` where bit `k` corresponds to `max_pn - k` (bit 0 =
 * `max_pn`). Tolerates out-of-order delivery up to 63 packets behind `max_pn`
 * while rejecting duplicates and stale packets outside the window.
 *
 * @param win Replay window state (bitmap == 0ULL indicates uninitialized).
 * @param pn  48-bit PN/TSC extracted from the incoming frame.
 * @return true if the frame is fresh (non-replay) and accepted; false if replayed/stale.
 */
bool n8_replay_win_accept(n8_replay_win_t *win, uint64_t pn)
{
    /* First packet on a fresh/rekeyed window initializes the anchor at bit 0. */
    if (win->bitmap == 0ULL) {
        win->max_pn = pn;
        win->bitmap = 1ULL;
        return true;
    }
    /* Newer than high-water mark: slide window forward (reset if jump >= 64 avoids shift UB). */
    if (pn > win->max_pn) {
        uint64_t delta = pn - win->max_pn;
        win->bitmap = (delta >= N8_REPLAY_WIN_BITS) ? 1ULL : ((win->bitmap << delta) | 1ULL);
        win->max_pn = pn;
        return true;
    }
    /* At or behind high-water mark: drop if older than 64-packet window or already seen. */
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

/**
 * @brief LMAC TX completion callback for queued data/EAPOL jobs.
 *
 * Releases the `n8_tx_job_t` slot, updates the STA retry-burst hysteresis
 * counter (`g_n8.sta_tx_retry_burst`) driving adaptive RTS/CTS protection,
 * packs `wifi_tx_status_t` into `aio.ret`, invokes the lwIP/supplicant
 * `aio.cb` (and EAPOL TX callback if applicable), and re-kicks the TX worker
 * queue if backpressured jobs remain pending.
 *
 * @param user_ctx Pointer to the completed `n8_tx_job_t`.
 * @param st       LMAC TX status (success flag, retry count, HW rate).
 */
static void data_tx_done_cb(void *user_ctx, const esp_lmac_tx_status_t *st)
{
    n8_tx_job_t *job = (n8_tx_job_t *)user_ctx;
    if (job == NULL || !job->in_use) {
        return;
    }

    esp_aio_t aio = job->aio;
    uint8_t is_eapol = job->is_eapol;
    uint8_t vif = job->vif;
    job->in_use = 0U;

    /* Track consecutive heavy-retry/failed STA data frames for adaptive RTS/CTS hysteresis */
    if (vif == ESP_LMAC_VIF_STA && is_eapol == 0U && st != NULL) {
        if (st->ok == 0U || st->retries >= N8_RTS_HEAVY_RETRIES) {
            if (g_n8.sta_tx_retry_burst < N8_RTS_BURST_CAP) {
                g_n8.sta_tx_retry_burst++;
            }
        } else if (st->retries <= N8_RTS_CLEAN_RETRIES && g_n8.sta_tx_retry_burst > 0U) {
            g_n8.sta_tx_retry_burst--;
        }
    }

    wifi_tx_status_t tx_st;
    memset(&tx_st, 0, sizeof(tx_st));
    tx_st.wifi_tx_result = st->ok ? TX_STATUS_SUCCESS : TX_STATUS_LRC_EXCEED;
    tx_st.wifi_tx_lrc = (st->retries > N8_TX_STATUS_LRC_MAX) ? N8_TX_STATUS_LRC_MAX : st->retries;
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

/**
 * @brief Map an IPv4 DSCP field to 802.11 UP/TID (0..7) and LMAC Access Category.
 *
 * Extracts the upper 3 bits (IP Precedence) of the 6-bit IPv4 DSCP field per
 * RFC 8325 / WMM default mapping (UP 6..7 -> AC_VO, 4..5 -> AC_VI, 1..2 ->
 * AC_BK, 0/3 -> AC_BE). Non-IPv4 or truncated payloads default to UP 0 (AC_BE).
 *
 * @param eth         Pointer to 802.3 Ethernet frame header.
 * @param payload_len Payload length following the 14-byte Ethernet header.
 * @param ac_out      Output LMAC Access Category.
 * @return 802.11 QoS TID / User Priority (0..7).
 */
static uint8_t n8_dscp_to_tid_ac(const uint8_t *eth, uint16_t payload_len, esp_lmac_ac_t *ac_out)
{
    uint8_t up = 0U;
    if (eth[N8_ETH_TYPE_OFF] == N8_ETH_TYPE_IPV4_H &&
        eth[N8_ETH_TYPE_OFF + 1U] == N8_ETH_TYPE_IPV4_L &&
        payload_len >= N8_IPV4_MIN_HDR_LEN) {
        uint8_t dscp = (uint8_t)(eth[N8_ETH_IPV4_TOS_OFF] >> N8_IPV4_DSCP_SHIFT);
        up = (uint8_t)((dscp >> N8_IPV4_DSCP_UP_SHIFT) & IEEE80211_QOS_TID_MASK);
    }
    switch (up) {
    case 6U: /* UP 6..7: Voice */
    case 7U:
        *ac_out = ESP_LMAC_AC_VO;
        break;
    case 4U: /* UP 4..5: Video */
    case 5U:
        *ac_out = ESP_LMAC_AC_VI;
        break;
    case 1U: /* UP 1..2: Background */
    case 2U:
        *ac_out = ESP_LMAC_AC_BK;
        break;
    default: /* UP 0, 3: Best Effort */
        *ac_out = ESP_LMAC_AC_BE;
        break;
    }
    return up;
}

/**
 * @brief Encapsulate an 802.3 Ethernet II frame into 802.11 + LLC/SNAP and submit to LMAC.
 *
 * Converts `[DA(6) | SA(6) | EtherType(2) | payload]` into a scatter-gather
 * 802.11 Data/QoS-Data frame without mutating the caller's payload buffer:
 *   - Builds `[MAC hdr (24B) | optional QoS (2B) | optional CCMP/TKIP IV (8B) | RFC1042 LLC/SNAP (8B)]`
 *     in stack scratch `hdr[]`. When QoS/WMM is active (non-EAPOL), maps IPv4 DSCP
 *     to QoS Control TID and LMAC Access Category via `n8_dscp_to_tid_ac()`.
 *   - For STA (ToDS=1): `A1=BSSID, A2=STA_MAC, A3=DA`; wakes modem sleep; requests
 *     RTS/CTS (`ESP_LMAC_TX_FLAG_USE_RTS`) for frames >= `N8_ERP_RTS_THRESHOLD_BYTES`
 *     when AP ERP/HT protection is active or STA retry-burst hysteresis trips;
 *     encrypts with PTK once installed (leaving 4-way handshake EAPOL unencrypted before RUN).
 *   - For SoftAP (FromDS=1): `A1=DA, A2=AP_MAC, A3=SA`; buffers frames for sleeping
 *     stations (or multicast when any station sleeps) unless `bypass_ap_ps` is set;
 *     uses GTK for multicast and per-STA PTK for unicast.
 *   - For CCMP/TKIP, reserves the hardware trailer slot (8B CCMP MIC, or 12B TKIP
 *     8B Michael MIC + 4B ICV, computed by WDEV hardware).
 *
 * @param vif          LMAC VIF index (`ESP_LMAC_VIF_STA` or `ESP_LMAC_VIF_AP`).
 * @param eth          Pointer to complete 802.3 Ethernet II frame.
 * @param eth_len      Frame length in bytes (14..1536).
 * @param is_eapol     true if EtherType is 0x888E (sent AC_VO, lowest rate, non-QoS).
 * @param bypass_ap_ps true when flushing SoftAP PS-buffered frames (skip re-buffering).
 * @param done_cb      LMAC TX completion callback.
 * @param done_ctx     Opaque context passed to `done_cb`.
 * @return ESP_OK on submission or PS enqueue, or an ESP_ERR_* failure code.
 */
static esp_err_t tx_eth_frame_on_worker(uint8_t vif, const uint8_t *eth, uint16_t eth_len,
                                        bool is_eapol, bool bypass_ap_ps,
                                        esp_lmac_tx_done_cb_t done_cb, void *done_ctx)
{
    if (eth == NULL || eth_len < IEEE80211_ETH_HDR_LEN || eth_len > N8_ETH_FRAME_MAX_LEN) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Fast-fail before advancing seq/PN when the LMAC TX pool is full */
    if (!esp_lmac_tx_has_free_slot()) {
        return ESP_ERR_NO_MEM;
    }

    const uint8_t *da = eth;
    const uint8_t *sa = eth + N8_ETH_SA_OFF;
    const uint8_t *payload = eth + IEEE80211_ETH_HDR_LEN;
    uint16_t payload_len = (uint16_t)(eth_len - IEEE80211_ETH_HDR_LEN);
    bool is_mcast = (da[0] & N8_MAC_MCAST_BIT) != 0U;

    uint8_t hdr[N8_TX_HDR_BUF_LEN];
    uint16_t hdr_len = IEEE80211_HDR_LEN;
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
        memcpy(hdr + IEEE80211_HDR_ADDR1_OFF, g_n8.sta_bssid, IEEE80211_ADDR_LEN);
        memcpy(hdr + IEEE80211_HDR_ADDR2_OFF, g_n8.sta_mac, IEEE80211_ADDR_LEN);
        memcpy(hdr + IEEE80211_HDR_ADDR3_OFF, da, IEEE80211_ADDR_LEN);
        uint16_t seq = n8_sta_next_seq();
        hdr[IEEE80211_HDR_SEQ_OFF] = (uint8_t)(seq & 0xFFU);
        hdr[IEEE80211_HDR_SEQ_OFF + 1U] = (uint8_t)(seq >> 8);
        peer_id = g_n8.sta_peer_id;
        if (is_eapol) {
            flags |= ESP_LMAC_TX_FLAG_FORCE_LOWEST_RATE;
        } else if (eth_len >= N8_ERP_RTS_THRESHOLD_BYTES &&
                   (g_n8.sta_erp_prot != 0U || g_n8.sta_tx_retry_burst >= N8_RTS_BURST_THRESH)) {
            flags |= ESP_LMAC_TX_FLAG_USE_RTS;
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
                                esp_lmac_tx_status_t ok_st = { .ok = 1U, .retries = 0U, .hw_rate = 0U, .ack_rssi = N8_ACK_RSSI_INVALID };
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
                        esp_lmac_tx_status_t ok_st = { .ok = 1U, .retries = 0U, .hw_rate = 0U, .ack_rssi = N8_ACK_RSSI_INVALID };
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
        memcpy(hdr + IEEE80211_HDR_ADDR1_OFF, da, IEEE80211_ADDR_LEN);
        memcpy(hdr + IEEE80211_HDR_ADDR2_OFF, g_n8.ap_mac, IEEE80211_ADDR_LEN);
        memcpy(hdr + IEEE80211_HDR_ADDR3_OFF, sa, IEEE80211_ADDR_LEN);
        uint16_t seq = n8_ap_next_seq();
        hdr[IEEE80211_HDR_SEQ_OFF] = (uint8_t)(seq & 0xFFU);
        hdr[IEEE80211_HDR_SEQ_OFF + 1U] = (uint8_t)(seq >> 8);
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
        hdr_len = (uint16_t)(hdr_len + IEEE80211_CCMP_HDR_LEN);
        trailer_len = IEEE80211_CCMP_MIC_LEN; /* Hardware fills 8-byte CCMP MIC */
    } else if (cipher == ESP_LMAC_CIPHER_TKIP) {
        hdr[1] |= IEEE80211_FC1_PROTECTED;
        write_tkip_hdr(hdr + hdr_len, pn, key_idx);
        hdr_len = (uint16_t)(hdr_len + IEEE80211_TKIP_HDR_LEN);
        /* Hardware computes 8-byte TKIP Michael MIC + 4-byte ICV (verified on live silicon) */
        trailer_len = IEEE80211_TKIP_TRAILER_LEN;
    }

    /* Append 8-byte LLC/SNAP header (RFC1042 + original EtherType) into LMAC scratch */
    memcpy(hdr + hdr_len, s_rfc1042_hdr, N8_RFC1042_PREFIX_LEN);
    hdr[hdr_len + N8_RFC1042_PREFIX_LEN] = eth[N8_ETH_TYPE_OFF];
    hdr[hdr_len + N8_RFC1042_PREFIX_LEN + 1U] = eth[N8_ETH_TYPE_OFF + 1U];
    hdr_len = (uint16_t)(hdr_len + IEEE80211_LLC_SNAP_LEN);

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

/**
 * @brief LMAC TX completion callback that frees an internal heap-copied AP Ethernet frame.
 *
 * @param ctx Heap buffer allocated by `n8_data_tx_eth_ap_internal()`.
 * @param st  LMAC TX status (unused).
 */
static void ap_internal_free_cb(void *ctx, const esp_lmac_tx_status_t *st)
{
    (void)st;
    if (ctx != NULL) {
        heap_caps_free(ctx);
    }
}

/**
 * @brief Transmit an internal SoftAP Ethernet frame (PS flush or STA-to-STA hairpin).
 *
 * Copies `eth_frame` to the heap so the caller's RX or PS buffer can be recycled
 * immediately, then submits asynchronously on `ESP_LMAC_VIF_AP`.
 *
 * @param eth_frame Pointer to 802.3 Ethernet II frame bytes.
 * @param len       Frame length in bytes.
 * @param bypass_ps true to transmit directly without re-entering the AP PS queue.
 * @return ESP_OK on submission, ESP_ERR_NO_MEM, or LMAC/AP TX error.
 */
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

/**
 * @brief Enqueue an Ethernet II pbuf from lwIP or wpa_supplicant onto the async TX job ring.
 *
 * Copies the `esp_aio_t` descriptor by value into a free slot of `g_n8.tx_jobs[]`
 * and appends its slot index to the lock-protected circular index ring
 * (`tx_pending_idx[]` / `tx_q_head` / `tx_q_tail`), making it safe to call from
 * `tcpip_thread` or any external task. Executes inline when already on the worker
 * task; otherwise posts `N8_EVT_TX`.
 *
 * @param aio Asynchronous I/O descriptor referencing the Ethernet frame and completion callback.
 * @return 0 if accepted into the TX ring, or -1 if interface is down or ring is full.
 */
int ieee80211_output_pbuf(esp_aio_t *aio)
{
    if (!g_n8.started || aio == NULL || aio->pbuf == NULL || aio->len < IEEE80211_ETH_HDR_LEN) {
        return -1;
    }

    uint8_t vif = (aio->fd == WIFI_IF_AP) ? ESP_LMAC_VIF_AP : ESP_LMAC_VIF_STA;
    const uint8_t *eth = (const uint8_t *)aio->pbuf;
    bool is_eapol = (eth[N8_ETH_TYPE_OFF] == ETH_P_EAPOL_H && eth[N8_ETH_TYPE_OFF + 1U] == ETH_P_EAPOL_L);

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

/**
 * @brief Drain pending async TX jobs on the worker task and submit them to LMAC.
 *
 * Uses peek-then-advance semantics on `tx_q_head`: if STA CSA quiet mode is
 * active (`g_n8.sta_csa_tx_paused`), an off-channel scan is away from the job's
 * operating channel, or LMAC returns `ESP_ERR_NO_MEM` (hardware TX pool full),
 * the job remains at `tx_q_head` until CSA completes, the radio returns to home
 * channel, or `data_tx_done_cb()` re-kicks `N8_EVT_TX`. Permanent submission
 * errors immediately synthesize a failed TX completion callback.
 */
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

        /* Pause STA data TX while CSA quiet mode (mode == 1) is active */
        if (job->vif == ESP_LMAC_VIF_STA && g_n8.sta_csa_tx_paused != 0U) {
            break;
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
            esp_lmac_tx_status_t fail_st = { .ok = 0U, .retries = 0U, .hw_rate = 0U, .ack_rssi = N8_ACK_RSSI_INVALID };
            data_tx_done_cb(job, &fail_st);
        }
    }
}

/* --------------------------------------------------------------------------
 * RX Path: 802.11 -> 802.3 Decap, EAPOL Dispatch & Hybrid Zero-Copy Handoff
 * -------------------------------------------------------------------------- */

/**
 * @brief Deliver a decapsulated 802.3 Ethernet frame to the registered netif RX callback.
 *
 * Ownership policy:
 *   - Heap-reassembled defragmented frames (`rx_buf == NULL`) are passed directly
 *     with `eb = NULL` so `tcpip_adapter` frees `eth_ptr` (freed here on error).
 *   - LMAC DMA frames (`rx_buf != NULL`) use zero-copy (`eb = rx_buf`) only when
 *     the frame did not wrap through `rx_extradata` (`!esp_lmac_rx_buf_is_wrapped`),
 *     contiguous DMA ring headroom exceeds `left_continuous_rx_buf_num`, and free
 *     DRAM exceeds `N8_RX_COPY_HEAP_FLOOR`; otherwise copied to heap so the DMA
 *     descriptor is recycled immediately.
 *
 * @param vif     Target VIF index (`ESP_LMAC_VIF_STA` or `ESP_LMAC_VIF_AP`).
 * @param eth_ptr Pointer to 802.3 Ethernet frame (inside `rx_buf->frame` or heap-allocated).
 * @param eth_len Ethernet frame length in bytes.
 * @param rx_buf  LMAC RX DMA buffer owning `eth_ptr`, or NULL for a heap-owned defrag buffer.
 */
static void deliver_eth_to_netif(uint8_t vif, uint8_t *eth_ptr, uint16_t eth_len,
                                 esp_lmac_rx_buf_t *rx_buf)
{
    wifi_rxcb_t cb = (vif < N8_VIF_MAX) ? g_n8.rxcb[vif] : NULL;
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

/**
 * @brief Process a received 802.11 Data frame: validate VIF, enforce security, decap, and dispatch.
 *
 * Pipeline stages:
 *   1. DS direction & VIF validation: FromDS=1 routes to STA (dropping reflected
 *      own-SA multicast); ToDS=1 routes to SoftAP (updating peer activity & PM sleep
 *      state, flushing PS queue on PM 1->0 transitions).
 *   2. Hardware TKIP Michael MIC failure (`ESP_LMAC_RXSTATE_TKIP_MIC_FAIL`, 0xF5)
 *      handling (drops frame, triggers `wpa_michael_mic_failure` on STA, logs on AP)
 *      and Null/QoS-Null early exit.
 *   3. FragAttacks & replay hardening: drops A-MSDU frames (CVE-2020-26145 /
 *      EAPOL-in-A-MSDU), drops fragments unless `CONFIG_ESP8266_OSS_WIFI_RX_DEFRAG_ENABLED`,
 *      enforces `Protected` bit & `rxend_state == OK` against the expected link
 *      cipher (CVE-2020-26140), runs 64-bit sliding-window PN/TSC replay checks
 *      (`n8_replay_win_accept`) for CCMP/TKIP or per-TID retry dedup (`n8_open_seq_dedup`)
 *      for open links, and strips IV/MIC/ICV framing.
 *   4. Opt-in unicast RX defragmentation (`n8_defrag_rx_frag`, CVE-2020-26142..26146)
 *      and RFC 1042 LLC/SNAP verification.
 *   5. EAPOL (0x888E) dispatch: copies DMA-backed EAPOL to heap and frees `rx_buf`
 *      before invoking WPS, WPA2-Enterprise (non-Key EAP), or WPA/RSN callbacks.
 *   6. Port authorization gate, 802.3 Ethernet II construction (heap copy for
 *      reassembled MSDUs or in-place header rewrite in `rx_buf->frame`), optional
 *      SoftAP STA-to-STA hairpinning, and netif handoff.
 *
 * @param rx_buf LMAC RX buffer (always freed or transferred to netif before return).
 */
static void handle_rx_data(esp_lmac_rx_buf_t *rx_buf)
{
    uint8_t *frame = rx_buf->frame;
    uint16_t flen = rx_buf->len;

    if (flen < IEEE80211_HDR_LEN) {
        esp_lmac_rx_free(rx_buf);
        return;
    }

    uint8_t fc0 = frame[0];
    uint8_t fc1 = frame[1];
    uint8_t subtype = (uint8_t)(fc0 & IEEE80211_FC_SUBTYPE_MASK);
    bool to_ds = (fc1 & IEEE80211_FC1_TODS) != 0U;
    bool from_ds = (fc1 & IEEE80211_FC1_FROMDS) != 0U;
    bool is_prot = (fc1 & IEEE80211_FC1_PROTECTED) != 0U;
    bool is_qos = (subtype & IEEE80211_SUBTYPE_QOS_DATA) != 0U;

    /* Determine target VIF (FromDS = STA RX, ToDS = SoftAP RX) */
    uint8_t vif;
    uint8_t da[IEEE80211_ADDR_LEN];
    uint8_t sa[IEEE80211_ADDR_LEN];
    n8_ap_sta_t *ap_sta = NULL;

    if (from_ds && !to_ds) {
        if (g_n8.sta_state < N8_STA_ASSOC ||
            memcmp(frame + IEEE80211_HDR_ADDR2_OFF, g_n8.sta_bssid, IEEE80211_ADDR_LEN) != 0) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        vif = ESP_LMAC_VIF_STA;
        memcpy(da, frame + IEEE80211_HDR_ADDR1_OFF, IEEE80211_ADDR_LEN);
        memcpy(sa, frame + IEEE80211_HDR_ADDR3_OFF, IEEE80211_ADDR_LEN);
        /* Drop reflected multicast frames originating from our own STA MAC */
        if (memcmp(sa, g_n8.sta_mac, IEEE80211_ADDR_LEN) == 0) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        n8_pm_on_activity();
    } else if (to_ds && !from_ds) {
        if (!g_n8.ap_running ||
            memcmp(frame + IEEE80211_HDR_ADDR1_OFF, g_n8.ap_mac, IEEE80211_ADDR_LEN) != 0) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        vif = ESP_LMAC_VIF_AP;
        memcpy(sa, frame + IEEE80211_HDR_ADDR2_OFF, IEEE80211_ADDR_LEN);
        memcpy(da, frame + IEEE80211_HDR_ADDR3_OFF, IEEE80211_ADDR_LEN);
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
        /* Protected=1 requires an installed link cipher and clean HW decrypt status */
        if (exp_cipher == ESP_LMAC_CIPHER_NONE) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        if (rx_buf->rx_ctrl != NULL && rx_buf->rx_ctrl->rxend_state != ESP_LMAC_RXSTATE_OK) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        if (flen < (uint16_t)(hdr_len + IEEE80211_CCMP_HDR_LEN)) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        const uint8_t *iv = frame + hdr_len;
        uint8_t ext_iv = iv[N8_CRYPTO_EXT_IV_OFF] & IEEE80211_CCMP_EXT_IV_BIT;
        key_idx = (uint8_t)((iv[N8_CRYPTO_EXT_IV_OFF] >> N8_CRYPTO_KEY_IDX_SHIFT) & N8_CRYPTO_KEY_IDX_MASK);
        if (exp_cipher == ESP_LMAC_CIPHER_CCMP || exp_cipher == ESP_LMAC_CIPHER_TKIP) {
            if (ext_iv == 0U) {
                esp_lmac_rx_free(rx_buf);
                return;
            }
            uint64_t pn = (exp_cipher == ESP_LMAC_CIPHER_TKIP)
                          ? n8_tkip_iv_to_tsc(iv)
                          : n8_ccmp_iv_to_pn(iv);
            /* Select per-GTK-slot (multicast) or per-TID PTK (unicast) replay window */
            n8_replay_win_t *rwin = NULL;
            if (vif == ESP_LMAC_VIF_STA) {
                if ((da[0] & N8_MAC_MCAST_BIT) != 0U) {
                    uint8_t kidx = (uint8_t)(key_idx & N8_GTK_REPLAY_SLOT_MASK);
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
            /* CCMP and TKIP share an 8-byte IV/ExtIV header; trailers are 8B vs 12B */
            hdr_len = (uint16_t)(hdr_len + IEEE80211_CCMP_HDR_LEN);
            tail_strip = (exp_cipher == ESP_LMAC_CIPHER_TKIP)
                         ? IEEE80211_TKIP_TRAILER_LEN
                         : IEEE80211_CCMP_MIC_LEN;
        } else {
            /* WEP (4-B IV + 4-B ICV) */
            if (ext_iv != 0U) {
                esp_lmac_rx_free(rx_buf);
                return;
            }
            hdr_len = (uint16_t)(hdr_len + IEEE80211_WEP_IV_LEN);
            tail_strip = IEEE80211_WEP_ICV_LEN;
        }
    } else {
        /* Reject plaintext data once keys are installed (CVE-2020-26140); dedup open retries */
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
    /*
     * Opt-in unicast MSDU defragmentation (CVE-2020-26142..26146): multicast
     * fragments are forbidden by 802.11; n8_defrag_rx_frag() enforces matching
     * cipher/key_idx and strictly consecutive fragment numbers + PN/TSC values.
     */
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
        if (msdu_len < IEEE80211_LLC_SNAP_LEN || memcmp(reasm, s_rfc1042_hdr, N8_RFC1042_PREFIX_LEN) != 0) {
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
        if (flen < (uint16_t)(hdr_len + IEEE80211_LLC_SNAP_LEN + tail_strip)) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        llc = frame + hdr_len;
        if (memcmp(llc, s_rfc1042_hdr, N8_RFC1042_PREFIX_LEN) != 0) {
            esp_lmac_rx_free(rx_buf);
            return;
        }
        msdu_len = (uint16_t)(flen - hdr_len - tail_strip);
    }

    uint8_t etype_h = llc[N8_RFC1042_PREFIX_LEN];
    uint8_t etype_l = llc[N8_RFC1042_PREFIX_LEN + 1U];
    uint8_t *payload = llc + IEEE80211_LLC_SNAP_LEN;
    uint16_t payload_len = (uint16_t)(msdu_len - IEEE80211_LLC_SNAP_LEN);

    /* Route EAPOL (0x888E) to wpa_supplicant */
    if (etype_h == ETH_P_EAPOL_H && etype_l == ETH_P_EAPOL_L) {
        if (payload_len < N8_EAPOL_HDR_LEN) {
            if (reasm != NULL) {
                heap_caps_free(reasm);
            } else {
                esp_lmac_rx_free(rx_buf);
            }
            return;
        }
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

        /* STA EAPOL routing priority: WPS enrollee > WPA2-Enterprise EAP > WPA/RSN 4-way */
        if (vif == ESP_LMAC_VIF_STA) {
            if (n8_wps_is_pending() && g_n8.wps_cb->wps_sm_rx_eapol != NULL) {
                (void)g_n8.wps_cb->wps_sm_rx_eapol(sa, eapol, payload_len);
            } else if (g_n8.wpa2_cb != NULL && g_n8.sta_supp_authmode == WPA2_AUTH_ENT &&
                       eapol[N8_EAPOL_TYPE_OFF] != N8_EAPOL_TYPE_KEY &&
                       g_n8.wpa2_cb->wpa2_sm_rx_eapol != NULL) {
                (void)g_n8.wpa2_cb->wpa2_sm_rx_eapol(sa, eapol, payload_len, g_n8.sta_bssid);
            } else if (g_n8.wpa_cb != NULL && g_n8.wpa_cb->wpa_sta_rx_eapol != NULL) {
                (void)g_n8.wpa_cb->wpa_sta_rx_eapol(sa, eapol, payload_len);
            }
        } else if (vif == ESP_LMAC_VIF_AP && ap_sta != NULL &&
                   g_n8.wpa_cb != NULL && g_n8.wpa_cb->wpa_ap_rx_eapol != NULL) {
            (void)g_n8.wpa_cb->wpa_ap_rx_eapol(g_n8.ap_hapd, ap_sta->wpa_sm, eapol, payload_len);
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
    uint16_t eth_len = (uint16_t)(IEEE80211_ETH_HDR_LEN + payload_len);
    if (reasm != NULL) {
        eth_ptr = (uint8_t *)heap_caps_malloc(eth_len, MALLOC_CAP_8BIT);
        if (eth_ptr == NULL) {
            heap_caps_free(reasm);
            return;
        }
        memcpy(eth_ptr, da, IEEE80211_ADDR_LEN);
        memcpy(eth_ptr + N8_ETH_SA_OFF, sa, IEEE80211_ADDR_LEN);
        eth_ptr[N8_ETH_TYPE_OFF] = etype_h;
        eth_ptr[N8_ETH_TYPE_OFF + 1U] = etype_l;
        memcpy(eth_ptr + IEEE80211_ETH_HDR_LEN, payload, payload_len);
        heap_caps_free(reasm);
        reasm = NULL;
    } else {
        /* In-place 802.3 Ethernet header rewrite immediately preceding payload (safe: hdr_len+8 >= 32 >= 14) */
        eth_ptr = payload - IEEE80211_ETH_HDR_LEN;
        memcpy(eth_ptr, da, IEEE80211_ADDR_LEN);
        memcpy(eth_ptr + N8_ETH_SA_OFF, sa, IEEE80211_ADDR_LEN);
        eth_ptr[N8_ETH_TYPE_OFF] = etype_h;
        eth_ptr[N8_ETH_TYPE_OFF + 1U] = etype_l;
    }

    /* SoftAP STA-to-STA hairpinning */
    if (vif == ESP_LMAC_VIF_AP) {
        if ((da[0] & N8_MAC_MCAST_BIT) != 0U) {
            /* Broadcast/multicast: forward to other associated STAs AND deliver to lwIP */
            (void)n8_data_tx_eth_ap_internal(eth_ptr, eth_len, false);
        } else if (memcmp(da, g_n8.ap_mac, IEEE80211_ADDR_LEN) != 0) {
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
 * @brief Scan a received management frame for vendor-specific IEs (ID 221) and notify `vendor_ie_cb`.
 *
 * Called once per received management frame from `n8_data_rx_frame()` before
 * STA/AP MLME routing so APSTA mode never delivers duplicate callbacks.
 *
 * @param ctrl  Hardware RX control header (may be NULL).
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
        ie_off = N8_MGMT_BCN_IE_OFF;
        break;
    case IEEE80211_SUBTYPE_PROBE_REQ:
        type = WIFI_VND_IE_TYPE_PROBE_REQ;
        ie_off = N8_MGMT_PROBE_REQ_IE_OFF;
        break;
    case IEEE80211_SUBTYPE_PROBE_RESP:
        type = WIFI_VND_IE_TYPE_PROBE_RESP;
        ie_off = N8_MGMT_BCN_IE_OFF;
        break;
    case IEEE80211_SUBTYPE_ASSOC_REQ:
        type = WIFI_VND_IE_TYPE_ASSOC_REQ;
        ie_off = N8_MGMT_ASSOC_REQ_IE_OFF;
        break;
    case IEEE80211_SUBTYPE_REASSOC_REQ:
        type = WIFI_VND_IE_TYPE_ASSOC_REQ;
        ie_off = N8_MGMT_REASSOC_REQ_IE_OFF;
        break;
    case IEEE80211_SUBTYPE_ASSOC_RESP:
    case IEEE80211_SUBTYPE_REASSOC_RESP:
        type = WIFI_VND_IE_TYPE_ASSOC_RESP;
        ie_off = N8_MGMT_ASSOC_RESP_IE_OFF;
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
    int rssi = (ctrl != NULL) ? (int)(int8_t)ctrl->rssi : N8_RSSI_UNKNOWN;
    const uint8_t *sa = frame + IEEE80211_HDR_ADDR2_OFF;

    while (pos + IEEE80211_IE_HDR_LEN <= ie_len) {
        uint8_t id = ies[pos];
        uint8_t elen = ies[pos + 1U];
        if (pos + IEEE80211_IE_HDR_LEN + elen > ie_len) {
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
        pos = (uint16_t)(pos + IEEE80211_IE_HDR_LEN + elen);
    }
}

/**
 * @brief Top-level LMAC RX frame dispatcher routing Data, Management, and Control frames.
 *
 * Transfers ownership of `rx_buf` to `handle_rx_data()` for Data frames. For
 * non-Data frames, drops any frame flagged with `ESP_LMAC_RXSTATE_TKIP_MIC_FAIL`,
 * dispatches vendor IEs once via `n8_dispatch_vendor_ie_rx()`, routes Management
 * frames to STA (forwarding `rx_buf->freq_offset`) and/or SoftAP MLME, and
 * routes Control frames (e.g. PS-Poll) to SoftAP before freeing `rx_buf`.
 *
 * @param rx_buf Received LMAC RX buffer descriptor.
 */
void n8_data_rx_frame(esp_lmac_rx_buf_t *rx_buf)
{
    if (rx_buf == NULL || rx_buf->frame == NULL || rx_buf->len < IEEE80211_CTRL_MIN_LEN) {
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

/**
 * @brief Filter and forward a raw received 802.11 frame to the promiscuous sniffer callback.
 *
 * Maps Frame Control type to `wifi_promiscuous_pkt_type_t`, checks the active LMAC
 * promiscuous filter mask (and secondary `cur_ctrl_filt` subtype mask for Control
 * frames), packs `wifi_pkt_rx_ctrl_t` followed by up to `N8_SNIFFER_MAX_COPY_LEN`
 * (112) payload bytes onto the stack, and invokes `g_n8.promis_cb`.
 *
 * @param ctrl  LMAC RX metadata header.
 * @param frame Pointer to raw 802.11 frame bytes.
 * @param len   Frame length in bytes.
 */
void n8_data_sniffer_rx(const wifi_pkt_rx_ctrl_t *ctrl, const uint8_t *frame, uint16_t len)
{
    if (g_n8.promis_cb == NULL || ctrl == NULL || frame == NULL || len < N8_SNIFFER_MIN_LEN) {
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
        /* WIFI_PROMIS_CTRL_FILTER_MASK_* maps control subtypes 7..15 to BIT(16 + sub) */
        uint8_t sub = (uint8_t)(frame[0] >> N8_FC_SUBTYPE_SHIFT);
        uint32_t cbit = (sub >= N8_CTRL_SUBTYPE_WRAPPER_MIN)
                        ? (1U << (N8_CTRL_FILTER_SHIFT + sub))
                        : 0U;
        if ((cur_ctrl_filt & cbit) == 0U) {
            return;
        }
    }

    uint16_t copy_len = (len > N8_SNIFFER_MAX_COPY_LEN) ? N8_SNIFFER_MAX_COPY_LEN : len;
    uint8_t pkt_buf[sizeof(wifi_pkt_rx_ctrl_t) + N8_SNIFFER_MAX_COPY_LEN];
    memcpy(pkt_buf, ctrl, sizeof(wifi_pkt_rx_ctrl_t));
    memcpy(pkt_buf + sizeof(wifi_pkt_rx_ctrl_t), frame, copy_len);
    g_n8.promis_cb(pkt_buf, ptype);
}

/* --------------------------------------------------------------------------
 * tcpip_adapter RX Callback Registration & Buffer Free
 * -------------------------------------------------------------------------- */

/**
 * @brief Register the upper-layer (tcpip_adapter / lwIP) RX callback for a Wi-Fi interface.
 *
 * @param ifx Wi-Fi interface (`WIFI_IF_STA` or `WIFI_IF_AP`).
 * @param fn  RX callback function, or NULL to unregister.
 * @return ESP_OK on success, or ESP_ERR_INVALID_ARG if `ifx` is invalid.
 */
esp_err_t esp_wifi_internal_reg_rxcb(wifi_interface_t ifx, wifi_rxcb_t fn)
{
    if (ifx != WIFI_IF_STA && ifx != WIFI_IF_AP) {
        return ESP_ERR_INVALID_ARG;
    }
    g_n8.rxcb[ifx] = fn;
    return ESP_OK;
}

/**
 * @brief Recycle a zero-copy LMAC RX buffer previously handed to `tcpip_adapter`.
 *
 * @param buffer Opaque `esp_lmac_rx_buf_t *` pointer (ignored if NULL).
 */
void esp_wifi_internal_free_rx_buffer(void *buffer)
{
    if (buffer != NULL) {
        esp_lmac_rx_free((esp_lmac_rx_buf_t *)buffer);
    }
}
