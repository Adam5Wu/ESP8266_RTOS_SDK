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
// SoftAP MLME & APSTA coexistence: mode-scoped peer slab, Beacon synthesis +
// TBTT TIM updates (Country, HT20, WMM/QoS, vendor IEs), Probe/Auth/Assoc
// responders, hostapd WPA2/WPA glue, A-MPDU RX Block-Ack (ADDBA/DELBA)
// negotiation, PS buffering (global 4-packet tail-drop cap + PS-Poll/DTIM
// flush), and client inactivity aging.

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "net80211_internal.h"

#define TAG "wifi_ap"

/* --------------------------------------------------------------------------
 * SoftAP Protocol, Frame Layout & Timing Constants
 * -------------------------------------------------------------------------- */

/** SoftAP default configuration and inactivity aging parameters. */
#define N8_AP_DEFAULT_BEACON_INT_TU     100U
#define N8_AP_DEFAULT_DTIM_PERIOD       2U
#define N8_AP_DEFAULT_MAX_CONN          4U
#define N8_AP_DEFAULT_INACTIVE_SEC      300U
#define N8_AP_TICKS_PER_SEC             10U   /* 100 ms worker ticks per second */

/** SoftAP Power-Save buffering and TIM IE layout constants. */
#define N8_AP_PS_AID_BCAST              0U    /* AID 0 denotes buffered broadcast/multicast traffic */
#define N8_AP_TIM_IE_BODY_LEN           5U    /* DTIM cnt(1) + DTIM per(1) + BitmapCtrl(1) + PVB(2) */
#define N8_AP_TIM_MAX_AID_BITS          16U   /* 2-byte Partial Virtual Bitmap covers AIDs 1..15 */

/** Stack buffer sizes for synthesized management frames (bytes). */
#define N8_AP_BEACON_BUF_LEN            400U
#define N8_AP_PROBE_RESP_BUF_LEN        384U
#define N8_AP_ASSOC_RESP_BUF_LEN        256U

/** Information Element lengths and HT Capability / Operation offsets (bytes). */
#define N8_AP_COUNTRY_BODY_LEN          6U    /* 3B country string + 3B subband triplet */
#define N8_AP_COUNTRY_IE_LEN            (IEEE80211_IE_HDR_LEN + N8_AP_COUNTRY_BODY_LEN)
#define N8_AP_HT_CAP_IE_LEN             28U   /* 2B IE header + 26B HT Capabilities body */
#define N8_AP_HT_CAP_BODY_LEN           26U
#define N8_AP_HT_CAP_MCS0_OFF           3U    /* Offset of RX MCS bitmask byte 0 in HT Cap body */
#define N8_AP_HT_OP_IE_LEN              24U   /* 2B IE header + 22B HT Operation body */
#define N8_AP_HT_OP_BODY_LEN            22U
#define N8_AP_WMM_PARAM_BODY_LEN        (IEEE80211_WMM_PARAM_IE_LEN - IEEE80211_IE_HDR_LEN)
#define N8_AP_MAX_SEC_IE_LEN            255U  /* Max uint8_t IE length accepted by wpa_ap_join() */

/** Authentication / Association / Deauth / PS-Poll fixed field offsets & status codes. */
#define N8_AP_AUTH_FIXED_LEN            6U    /* Algorithm(2) + Sequence(2) + Status(2) */
#define N8_AP_AUTH_MIN_FRAME_LEN        (IEEE80211_HDR_LEN + N8_AP_AUTH_FIXED_LEN)
#define N8_AP_AUTH_ALG_OFF              (IEEE80211_HDR_LEN)
#define N8_AP_AUTH_SEQ_OFF              (IEEE80211_HDR_LEN + 2U)
#define N8_AP_AUTH_SEQ_REQ              1U
#define N8_AP_AUTH_SEQ_RESP             2U
#define N8_AP_STATUS_SUCCESS            0U
#define N8_AP_STATUS_UNSUPP_AUTH_ALG    13U   /* IEEE 802.11 §9.4.1.9: Auth algorithm unsupported */
#define N8_AP_STATUS_AP_UNABLE_STA      17U   /* IEEE 802.11 §9.4.1.9: AP unable to handle more STAs */
#define N8_AP_STATUS_DECLINED           37U   /* IEEE 802.11 §9.4.1.9: Request declined (e.g. ADDBA) */
#define N8_AP_ASSOC_REQ_FIXED_LEN       4U    /* CapInfo(2) + ListenInterval(2) */
#define N8_AP_REASSOC_REQ_FIXED_LEN     10U   /* CapInfo(2) + ListenInterval(2) + CurrentAP(6) */
#define N8_AP_ASSOC_REQ_IE_OFF          (IEEE80211_HDR_LEN + N8_AP_ASSOC_REQ_FIXED_LEN)
#define N8_AP_REASSOC_REQ_IE_OFF        (IEEE80211_HDR_LEN + N8_AP_REASSOC_REQ_FIXED_LEN)
#define N8_AP_DEAUTH_BODY_LEN           2U    /* Reason Code (2 bytes, little-endian) */
#define N8_AP_AID_TOP_BITS              0xC000U /* IEEE 802.11 §9.4.1.8: MSBs 15:14 set to 1 */
#define N8_AP_AID_MASK                  0x3FFFU
#define N8_AP_PS_POLL_MIN_LEN           16U   /* FC(2) + AID(2) + BSSID(6) + TA(6) */
#define N8_AP_PS_POLL_AID_OFF           2U

/** Action / Block Ack (ADDBA/DELBA) frame layout and bitfield shifts. */
#define N8_AP_ACTION_HDR_LEN            2U    /* Category(1) + Action(1) */
#define N8_AP_ADDBA_REQ_BODY_LEN        9U    /* Cat(1)+Act(1)+Dlg(1)+Param(2)+Tmo(2)+SSN(2) */
#define N8_AP_ADDBA_RESP_BODY_LEN       9U    /* Cat(1)+Act(1)+Dlg(1)+Stat(2)+Param(2)+Tmo(2) */
#define N8_AP_DELBA_BODY_LEN            6U    /* Cat(1)+Act(1)+Param(2)+Reason(2) */
#define N8_AP_ADDBA_POLICY_SHIFT        1U
#define N8_AP_ADDBA_POLICY_MASK         1U
#define N8_AP_ADDBA_POLICY_IMMED_VAL    1U    /* Immediate Block Ack policy field value */
#define N8_AP_ADDBA_POLICY_IMMED_BIT    0x02U /* Immediate Block Ack bit in BA Parameter Set */
#define N8_AP_ADDBA_TID_SHIFT           2U
#define N8_AP_ADDBA_TID_MASK            0x0FU
#define N8_AP_ADDBA_WIN_SHIFT           6U
#define N8_AP_ADDBA_WIN_MASK            0x3FFU
#define N8_AP_DELBA_TID_SHIFT           12U

/** Default LMAC peer rate/MCS masks and vendor OUI+Type header length. */
#define N8_AP_RATE_MASK_11BG_ALL        0x0FFFU
#define N8_AP_HT20_MCS0_7_MASK          0xFFU
#define N8_AP_VENDOR_OUI_TYPE_LEN       4U    /* 3-byte OUI + 1-byte OUI Type */

extern void n8_mgmt_free_tx_cb(void *ctx, const esp_lmac_tx_status_t *st);

static const uint8_t s_ap_bcast[IEEE80211_ADDR_LEN] = { 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU };

/*
 * Supported Rates (1, 2, 5.5, 11 Mbps basic; 6, 9, 12, 18 Mbps) and
 * Extended Supported Rates (24, 36, 48, 54 Mbps), in 500 kbps units.
 */
static const uint8_t s_ap_rates_ie[] = {
    IEEE80211_IE_SUPP_RATES, 0x08U, 0x82U, 0x84U, 0x8BU, 0x96U, 0x0CU, 0x12U, 0x18U, 0x24U,
    IEEE80211_IE_EXT_RATES,  0x04U, 0x30U, 0x48U, 0x60U, 0x6CU
};

/*
 * 802.11n HT20 Capabilities IE (26-byte body):
 *   HT Cap Info = 0x012C (SM PS disabled, Short GI 20 MHz, RX STBC 1-stream)
 *   A-MPDU Params = 0x1A (max RX A-MPDU 16 KB, min MPDU spacing 8 us)
 *   Supported MCS Set = 0xFF (MCS 0..7 single spatial stream)
 */
static const uint8_t s_ap_ht20_cap_ie[N8_AP_HT_CAP_IE_LEN] = {
    IEEE80211_IE_HT_CAP, N8_AP_HT_CAP_BODY_LEN,
    0x2CU, 0x01U, 0x1AU,
    0xFFU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
};

/* WFA WMM v1.1 Parameter Element (26 bytes: EDCA defaults for AC_BE, AC_BK, AC_VI, AC_VO) */
static const uint8_t s_ap_wmm_param_ie[IEEE80211_WMM_PARAM_IE_LEN] = {
    IEEE80211_IE_VENDOR, N8_AP_WMM_PARAM_BODY_LEN,
    IEEE80211_OUI_MS_0, IEEE80211_OUI_MS_1, IEEE80211_OUI_MS_2,
    IEEE80211_OUI_TYPE_WMM, IEEE80211_WMM_SUBTYPE_PARAM, IEEE80211_WMM_VERSION,
    0x00U, 0x00U,               /* QoS Info (param set cnt 0), Reserved */
    0x03U, 0xA4U, 0x00U, 0x00U, /* AC_BE: ACI=0, AIFSN=3, ECWmin=4, ECWmax=10, TXOP=0 */
    0x27U, 0xA4U, 0x00U, 0x00U, /* AC_BK: ACI=1, AIFSN=7, ECWmin=4, ECWmax=10, TXOP=0 */
    0x42U, 0x43U, 0x5EU, 0x00U, /* AC_VI: ACI=2, AIFSN=2, ECWmin=3, ECWmax=4,  TXOP=94 (3008 us) */
    0x62U, 0x32U, 0x2FU, 0x00U  /* AC_VO: ACI=3, AIFSN=2, ECWmin=2, ECWmax=3,  TXOP=47 (1504 us) */
};

/**
 * @brief Allocate the next 802.11 Sequence Control value for the SoftAP VIF.
 *
 * @return Sequence Control field value (12-bit sequence number shifted left by 4, fragment 0).
 */
uint16_t n8_ap_next_seq(void)
{
    return (uint16_t)((g_n8.ap_tx_seq++ & IEEE80211_SEQ_MASK) << IEEE80211_SEQ_SHIFT);
}

/**
 * @brief Look up an active SoftAP client entry by MAC address.
 *
 * @param mac 6-byte client MAC address to match.
 * @return Pointer to the matching peer slot, or NULL if not found or SoftAP is stopped.
 */
n8_ap_sta_t *n8_ap_find_sta(const uint8_t mac[6])
{
    if (!g_n8.ap_running || g_n8.ap_stas == NULL || mac == NULL) {
        return NULL;
    }
    for (uint8_t i = 0U; i < g_n8.ap_sta_cap; i++) {
        if (g_n8.ap_stas[i].in_use && memcmp(g_n8.ap_stas[i].mac, mac, IEEE80211_ADDR_LEN) == 0) {
            return &g_n8.ap_stas[i];
        }
    }
    return NULL;
}

/**
 * @brief Look up an active SoftAP client entry by its 1-based Association ID (AID).
 *
 * @param aid Client Association ID (1..ap_sta_cap).
 * @return Pointer to the peer slot if occupied, or NULL if out of range or unused.
 */
n8_ap_sta_t *n8_ap_find_sta_by_aid(uint16_t aid)
{
    if (!g_n8.ap_running || g_n8.ap_stas == NULL || aid == 0U || aid > g_n8.ap_sta_cap) {
        return NULL;
    }
    n8_ap_sta_t *sta = &g_n8.ap_stas[aid - 1U];
    return sta->in_use ? sta : NULL;
}

/**
 * @brief Find an existing peer slot for @p mac or allocate a free slot from the SoftAP slab.
 *
 * Each slab index `i` maps directly to a fixed 1-based AID (`i + 1`) so TIM PVB
 * indexing and PS-Poll AID lookup operate in O(1) time without a separate map.
 *
 * @param mac 6-byte MAC address of the authenticating client.
 * @return Pointer to the existing or newly initialized peer slot, or NULL if the slab is full.
 */
static n8_ap_sta_t *ap_alloc_sta(const uint8_t mac[6])
{
    n8_ap_sta_t *existing = n8_ap_find_sta(mac);
    if (existing != NULL) {
        return existing;
    }
    for (uint8_t i = 0U; i < g_n8.ap_sta_cap; i++) {
        if (!g_n8.ap_stas[i].in_use) {
            n8_ap_sta_t *s = &g_n8.ap_stas[i];
            memset(s, 0, sizeof(*s));
            s->in_use = 1U;
            s->aid = (uint8_t)(i + 1U);
            memcpy(s->mac, mac, IEEE80211_ADDR_LEN);
            s->peer_id = ESP_LMAC_PEER_INVALID;
            s->last_rx_sec = g_n8.ap_uptime_sec;
            return s;
        }
    }
    return NULL;
}

/** Transient wrapper pairing a heap-copied MGMT body with a caller TX-done callback. */
typedef struct {
    void                 *buf;
    esp_lmac_tx_done_cb_t cb;
    void                 *ctx;
} n8_ap_mgmt_wrap_t;

/**
 * @brief LMAC TX completion trampoline freeing a SoftAP MGMT body copy before invoking caller callback.
 *
 * Releases the heap-copied management body, forwards the LMAC TX status to the
 * wrapped callback (when non-NULL), and frees the transient `n8_ap_mgmt_wrap_t`.
 *
 * @param ctx Heap-allocated `n8_ap_mgmt_wrap_t` wrapper context.
 * @param st  LMAC transmission completion status forwarded to the wrapped callback.
 */
static void ap_mgmt_wrap_tx_cb(void *ctx, const esp_lmac_tx_status_t *st)
{
    n8_ap_mgmt_wrap_t *w = (n8_ap_mgmt_wrap_t *)ctx;
    if (w == NULL) {
        return;
    }
    if (w->buf != NULL) {
        heap_caps_free(w->buf);
    }
    if (w->cb != NULL) {
        w->cb(w->ctx, st);
    }
    heap_caps_free(w);
}

/**
 * @brief Transmit a SoftAP 802.11 management frame through the LMAC MGMT queue with optional TX-done callback.
 *
 * Copies @p body into a transient heap buffer freed asynchronously on TX
 * completion. When both @p done_cb and a non-empty @p body are supplied, a
 * heap-allocated `n8_ap_mgmt_wrap_t` chains freeing the copy with invoking
 * @p done_cb. Forces the lowest basic rate and sets NO_ACK for
 * multicast/broadcast destinations.
 *
 * @param subtype  Management frame subtype (pre-shifted into FC0 bits [7:4]).
 * @param da       6-byte destination MAC address (Addr1).
 * @param body     Optional management frame body bytes (may be NULL if @p body_len == 0).
 * @param body_len Length of @p body in bytes.
 * @param done_cb  Optional completion callback fired after LMAC TX finishes.
 * @param done_ctx Caller context passed to @p done_cb.
 * @return ESP_OK on LMAC submission, ESP_ERR_NO_MEM on copy/wrapper failure, or LMAC error code.
 */
static esp_err_t ap_tx_mgmt_cb(uint8_t subtype, const uint8_t da[6],
                               const uint8_t *body, uint16_t body_len,
                               esp_lmac_tx_done_cb_t done_cb, void *done_ctx)
{
    uint8_t hdr[IEEE80211_HDR_LEN];
    memset(hdr, 0, sizeof(hdr));
    hdr[0] = (uint8_t)(IEEE80211_FC_TYPE_MGMT | subtype);
    memcpy(hdr + IEEE80211_HDR_ADDR1_OFF, da, IEEE80211_ADDR_LEN);
    memcpy(hdr + IEEE80211_HDR_ADDR2_OFF, g_n8.ap_mac, IEEE80211_ADDR_LEN);
    memcpy(hdr + IEEE80211_HDR_ADDR3_OFF, g_n8.ap_mac, IEEE80211_ADDR_LEN);
    uint16_t seq = n8_ap_next_seq();
    hdr[IEEE80211_HDR_SEQ_OFF] = (uint8_t)(seq & 0xFFU);
    hdr[IEEE80211_HDR_SEQ_OFF + 1U] = (uint8_t)(seq >> 8);

    uint8_t *copy = NULL;
    esp_lmac_sg_seg_t seg = {0};
    if (body != NULL && body_len > 0U) {
        copy = (uint8_t *)heap_caps_malloc(body_len, MALLOC_CAP_8BIT);
        if (copy == NULL) {
            return ESP_ERR_NO_MEM;
        }
        memcpy(copy, body, body_len);
        seg.ptr = copy;
        seg.len = body_len;
    }

    esp_lmac_tx_req_t tx = {0};
    tx.vif = ESP_LMAC_VIF_AP;
    tx.peer_id = ESP_LMAC_PEER_INVALID;
    tx.ac = ESP_LMAC_AC_MGMT;
    tx.flags = ESP_LMAC_TX_FLAG_FORCE_LOWEST_RATE |
               ((da[0] & N8_MAC_MCAST_BIT) ? ESP_LMAC_TX_FLAG_NO_ACK : 0U);
    tx.hdr = hdr;
    tx.hdr_len = sizeof(hdr);
    tx.segs = (copy != NULL) ? &seg : NULL;
    tx.seg_cnt = (copy != NULL) ? 1U : 0U;

    /* Chain buffer free + caller callback via wrapper when both are present */
    n8_ap_mgmt_wrap_t *wrap = NULL;
    if (done_cb != NULL && copy != NULL) {
        wrap = (n8_ap_mgmt_wrap_t *)heap_caps_malloc(sizeof(*wrap), MALLOC_CAP_8BIT);
        if (wrap == NULL) {
            heap_caps_free(copy);
            return ESP_ERR_NO_MEM;
        }
        wrap->buf = copy;
        wrap->cb = done_cb;
        wrap->ctx = done_ctx;
        tx.done_cb = ap_mgmt_wrap_tx_cb;
        tx.done_ctx = wrap;
    } else if (done_cb != NULL) {
        tx.done_cb = done_cb;
        tx.done_ctx = done_ctx;
    } else {
        tx.done_cb = (copy != NULL) ? n8_mgmt_free_tx_cb : NULL;
        tx.done_ctx = copy;
    }

    esp_err_t err = esp_lmac_tx_submit(&tx);
    if (err != ESP_OK) {
        if (copy != NULL) {
            heap_caps_free(copy);
        }
        if (wrap != NULL) {
            heap_caps_free(wrap);
        }
    }
    return err;
}

/**
 * @brief Transmit a SoftAP 802.11 management frame without a caller TX-done callback.
 *
 * @param subtype  Management frame subtype (pre-shifted into FC0 bits [7:4]).
 * @param da       6-byte destination MAC address (Addr1).
 * @param body     Optional management frame body bytes (may be NULL if @p body_len == 0).
 * @param body_len Length of @p body in bytes.
 * @return ESP_OK on LMAC submission, ESP_ERR_NO_MEM on copy failure, or LMAC error code.
 */
static esp_err_t ap_tx_mgmt(uint8_t subtype, const uint8_t da[6],
                            const uint8_t *body, uint16_t body_len)
{
    return ap_tx_mgmt_cb(subtype, da, body, body_len, NULL, NULL);
}

/* --------------------------------------------------------------------------
 * SoftAP PS Buffering (Global 4-Packet Tail-Drop Cap + TIM Bitmap)
 *
 * Sleeping STAs (PM=1) and broadcast/multicast frames (when any STA sleeps)
 * share a single FIFO queue capped at N8_AP_PS_MAX_PKTS to bound heap usage.
 * Each queued node is tagged with AID 0 (broadcast/multicast, flushed on DTIM)
 * or AID 1..max_connection (unicast, delivered one frame per PS-Poll or
 * drained completely when the STA transitions back to PM=0).
 * -------------------------------------------------------------------------- */

/**
 * @brief Free all frames currently held in the SoftAP power-save buffer queue.
 */
void n8_ap_ps_free_all(void)
{
    n8_ps_pkt_t *cur = g_n8.ap_ps_head;
    while (cur != NULL) {
        n8_ps_pkt_t *next = cur->next;
        heap_caps_free(cur);
        cur = next;
    }
    g_n8.ap_ps_head = NULL;
    g_n8.ap_ps_tail = NULL;
    g_n8.ap_ps_count = 0U;
}

/**
 * @brief Unlink and discard all buffered PS packets belonging to a specific AID.
 *
 * @param aid Association ID whose queued packets should be purged (0 for broadcast).
 */
static void ap_ps_purge_aid(uint8_t aid)
{
    n8_ps_pkt_t **pp = &g_n8.ap_ps_head;
    n8_ps_pkt_t *prev = NULL;
    while (*pp != NULL) {
        n8_ps_pkt_t *cur = *pp;
        if (cur->aid == aid) {
            *pp = cur->next;
            if (g_n8.ap_ps_tail == cur) {
                g_n8.ap_ps_tail = prev;
            }
            heap_caps_free(cur);
            if (g_n8.ap_ps_count > 0U) {
                g_n8.ap_ps_count--;
            }
        } else {
            prev = cur;
            pp = &cur->next;
        }
    }
}

/**
 * @brief Buffer an outgoing Ethernet frame for a sleeping SoftAP client or DTIM broadcast.
 *
 * Drops the frame at the tail when the global `N8_AP_PS_MAX_PKTS` cap is reached.
 *
 * @param aid       Target client AID (1..max_connection), or 0 for broadcast/multicast.
 * @param eth_frame Pointer to the raw Ethernet II frame to copy.
 * @param len       Length of @p eth_frame in bytes.
 * @return true if enqueued, false if dropped due to queue cap or heap exhaustion.
 */
bool n8_ap_ps_enqueue(uint8_t aid, const uint8_t *eth_frame, uint16_t len)
{
    if (g_n8.ap_ps_count >= N8_AP_PS_MAX_PKTS) {
        return false; /* Tail-drop when global 4-packet cap reached */
    }
    n8_ps_pkt_t *node = (n8_ps_pkt_t *)heap_caps_malloc(sizeof(n8_ps_pkt_t) + len, MALLOC_CAP_8BIT);
    if (node == NULL) {
        return false;
    }
    node->next = NULL;
    node->aid = aid;
    node->len = len;
    memcpy(node->data, eth_frame, len);

    if (g_n8.ap_ps_tail == NULL) {
        g_n8.ap_ps_head = node;
        g_n8.ap_ps_tail = node;
    } else {
        g_n8.ap_ps_tail->next = node;
        g_n8.ap_ps_tail = node;
    }
    g_n8.ap_ps_count++;
    return true;
}

/**
 * @brief Transmit buffered unicast PS frames for a specific SoftAP client.
 *
 * Called with @p single_frame = true on PS-Poll reception (delivering exactly
 * one buffered MPDU) and @p single_frame = false when the STA wakes (PM 1->0)
 * to drain all queued frames in FIFO order bypassing PS re-buffering.
 *
 * @param sta          Target client peer slot.
 * @param single_frame If true, transmit only the oldest buffered frame; if false, drain all.
 */
void n8_ap_ps_flush_sta(n8_ap_sta_t *sta, bool single_frame)
{
    if (sta == NULL || g_n8.ap_ps_count == 0U) {
        return;
    }

    n8_ps_pkt_t **pp = &g_n8.ap_ps_head;
    n8_ps_pkt_t *prev = NULL;
    while (*pp != NULL) {
        n8_ps_pkt_t *cur = *pp;
        if (cur->aid == sta->aid) {
            *pp = cur->next;
            if (g_n8.ap_ps_tail == cur) {
                g_n8.ap_ps_tail = prev;
            }
            if (g_n8.ap_ps_count > 0U) {
                g_n8.ap_ps_count--;
            }
            (void)n8_data_tx_eth_ap_internal(cur->data, cur->len, true);
            heap_caps_free(cur);
            if (single_frame) {
                return;
            }
        } else {
            prev = cur;
            pp = &cur->next;
        }
    }
}

/**
 * @brief Transmit all buffered broadcast/multicast PS frames (AID 0) after a DTIM beacon.
 */
void n8_ap_ps_flush_bcast(void)
{
    if (g_n8.ap_ps_count == 0U) {
        return;
    }
    n8_ps_pkt_t **pp = &g_n8.ap_ps_head;
    n8_ps_pkt_t *prev = NULL;
    while (*pp != NULL) {
        n8_ps_pkt_t *cur = *pp;
        if (cur->aid == N8_AP_PS_AID_BCAST) {
            *pp = cur->next;
            if (g_n8.ap_ps_tail == cur) {
                g_n8.ap_ps_tail = prev;
            }
            if (g_n8.ap_ps_count > 0U) {
                g_n8.ap_ps_count--;
            }
            (void)n8_data_tx_eth_ap_internal(cur->data, cur->len, true);
            heap_caps_free(cur);
        } else {
            prev = cur;
            pp = &cur->next;
        }
    }
}

/* --------------------------------------------------------------------------
 * Beacon & Probe Response Synthesis (TIM, Country, HT20, WPA/RSN, WMM & Vendor IEs)
 * -------------------------------------------------------------------------- */

/**
 * @brief Build the management body of a SoftAP Beacon or Probe Response frame.
 *
 * Emits the 12-byte fixed header (TSF placeholder overwritten by hardware,
 * Beacon Interval, Capability Info) followed by SSID (zero-length in beacons
 * when `ssid_hidden` is set), Supported/Extended Rates, DS Parameter Set,
 * optional TIM IE (beacons only, with live DTIM count, BMC bit, and 16-bit
 * Partial Virtual Bitmap built from the PS queue), Country IE (from active
 * regulatory config), optional HT20 Capabilities and HT Operation IEs,
 * hostapd-generated WPA/RSN IE, optional WMM Parameter IE (when QoS/WMM is
 * enabled), and any user-configured Beacon/ProbeResp vendor IEs.
 *
 * @param out            Destination buffer for the management frame body (after the 24B MAC hdr).
 * @param max_len        Capacity of @p out in bytes.
 * @param is_beacon      true to synthesize a Beacon (honors hidden SSID and includes TIM IE);
 *                       false for a Probe Response.
 * @param tim_offset_out Optional output receiving the TIM IE byte offset from the start of the
 *                       802.11 MAC header (used by LMAC to locate the TIM during TBTT updates).
 * @return Number of body bytes written into @p out.
 */
static uint16_t ap_build_beacon_or_probe_body(uint8_t *out, uint16_t max_len,
                                              bool is_beacon, uint16_t *tim_offset_out)
{
    uint16_t off = 0U;
    uint16_t bi = g_n8.ap_cfg.ap.beacon_interval
                  ? g_n8.ap_cfg.ap.beacon_interval : N8_AP_DEFAULT_BEACON_INT_TU;
    uint16_t cap = (uint16_t)(IEEE80211_CAPINFO_ESS | IEEE80211_CAPINFO_SHORT_SLOT);
    if (g_n8.ap_cfg.ap.authmode != WIFI_AUTH_OPEN) {
        cap |= IEEE80211_CAPINFO_PRIVACY;
    }

    /* Fixed 12-byte body: Timestamp (8, stamped by MAC HW) + Beacon Interval (2) + Capability (2) */
    memset(out, 0, IEEE80211_BCN_INT_OFF);
    off = IEEE80211_BCN_INT_OFF;
    out[off++] = (uint8_t)(bi & 0xFFU);
    out[off++] = (uint8_t)(bi >> 8);
    out[off++] = (uint8_t)(cap & 0xFFU);
    out[off++] = (uint8_t)(cap >> 8);

    /* SSID IE (hidden in beacons if ssid_hidden != 0) */
    uint8_t slen = g_n8.ap_cfg.ap.ssid_len;
    if (slen == 0U) {
        slen = (uint8_t)strnlen((const char *)g_n8.ap_cfg.ap.ssid, N8_MAX_SSID_LEN);
    }
    if (slen > N8_MAX_SSID_LEN) {
        slen = N8_MAX_SSID_LEN;
    }
    out[off++] = IEEE80211_IE_SSID;
    if (is_beacon && g_n8.ap_cfg.ap.ssid_hidden != 0U) {
        out[off++] = 0U;
    } else {
        out[off++] = slen;
        memcpy(out + off, g_n8.ap_cfg.ap.ssid, slen);
        off = (uint16_t)(off + slen);
    }

    /* Supported & Extended Rates */
    memcpy(out + off, s_ap_rates_ie, sizeof(s_ap_rates_ie));
    off = (uint16_t)(off + sizeof(s_ap_rates_ie));

    /* DS Parameter Set (Channel) */
    uint8_t ch = (g_n8.ap_cfg.ap.channel >= N8_CHANNEL_MIN && g_n8.ap_cfg.ap.channel <= N8_CHANNEL_MAX)
                 ? g_n8.ap_cfg.ap.channel : N8_CHANNEL_MIN;
    out[off++] = IEEE80211_IE_DS_PARAM;
    out[off++] = 1U;
    out[off++] = ch;

    /*
     * TIM IE (Beacons only): [ID=5, Len=5, DTIM_cnt, DTIM_per, BitmapCtrl, PVB[0], PVB[1]].
     * Walk the PS buffer queue to compute the 2-byte Partial Virtual Bitmap (bit N = AID N)
     * and set BitmapCtrl bit 0 (multicast/broadcast pending) only on DTIM beacons (DTIM_cnt == 0).
     */
    if (is_beacon) {
        if (tim_offset_out != NULL) {
            *tim_offset_out = (uint16_t)(IEEE80211_HDR_LEN + off);
        }
        uint16_t pvb = 0U;
        uint8_t bmc = 0U;
        for (n8_ps_pkt_t *p = g_n8.ap_ps_head; p != NULL; p = p->next) {
            if (p->aid == N8_AP_PS_AID_BCAST) {
                bmc = 1U;
            } else if (p->aid < N8_AP_TIM_MAX_AID_BITS) {
                pvb |= (uint16_t)(1U << p->aid);
            }
        }
        out[off++] = IEEE80211_IE_TIM;
        out[off++] = N8_AP_TIM_IE_BODY_LEN;
        out[off++] = g_n8.ap_dtim_count;
        out[off++] = g_n8.ap_dtim_period ? g_n8.ap_dtim_period : 1U;
        out[off++] = (g_n8.ap_dtim_count == 0U) ? bmc : 0U;
        out[off++] = (uint8_t)(pvb & 0xFFU);
        out[off++] = (uint8_t)((pvb >> 8) & 0xFFU);
    }

    /* Country IE (ID 7, IEEE 802.11 9.4.2.9: 3B country string + 3B subband triplet) */
    const wifi_country_t *cc = n8_get_active_country();
    if (cc != NULL && (uint16_t)(off + N8_AP_COUNTRY_IE_LEN) <= max_len) {
        out[off++] = IEEE80211_IE_COUNTRY;
        out[off++] = N8_AP_COUNTRY_BODY_LEN;
        out[off++] = (uint8_t)cc->cc[0];
        out[off++] = (uint8_t)cc->cc[1];
        out[off++] = (cc->cc[2] != '\0') ? (uint8_t)cc->cc[2] : (uint8_t)' ';
        out[off++] = cc->schan;
        out[off++] = cc->nchan;
        out[off++] = (uint8_t)cc->max_tx_power;
    }

    /* HT20 Capabilities + HT Operation IEs when 11n enabled */
    if ((g_n8.proto[WIFI_IF_AP] & WIFI_PROTOCOL_11N) != 0U &&
        (uint16_t)(off + N8_AP_HT_CAP_IE_LEN + N8_AP_HT_OP_IE_LEN) <= max_len) {
        memcpy(out + off, s_ap_ht20_cap_ie, sizeof(s_ap_ht20_cap_ie));
        off = (uint16_t)(off + sizeof(s_ap_ht20_cap_ie));

        out[off++] = IEEE80211_IE_HT_OP;
        out[off++] = N8_AP_HT_OP_BODY_LEN;
        memset(out + off, 0, N8_AP_HT_OP_BODY_LEN);
        out[off] = ch; /* Primary channel */
        off = (uint16_t)(off + N8_AP_HT_OP_BODY_LEN);
    }

    /* WPA / RSN IE from hostapd */
    if (g_n8.ap_cfg.ap.authmode != WIFI_AUTH_OPEN &&
        g_n8.wpa_cb != NULL && g_n8.wpa_cb->wpa_ap_get_wpa_ie != NULL) {
        uint8_t wpa_len = 0U;
        uint8_t *wpa_ie = g_n8.wpa_cb->wpa_ap_get_wpa_ie(&wpa_len);
        if (wpa_ie != NULL && wpa_len > 0U && (uint16_t)(off + wpa_len) <= max_len) {
            memcpy(out + off, wpa_ie, wpa_len);
            off = (uint16_t)(off + wpa_len);
        }
    }

    /* WMM Parameter IE when QoS/WMM is enabled */
    if (n8_qos_cfg_enabled() && (uint16_t)(off + sizeof(s_ap_wmm_param_ie)) <= max_len) {
        memcpy(out + off, s_ap_wmm_param_ie, sizeof(s_ap_wmm_param_ie));
        off = (uint16_t)(off + sizeof(s_ap_wmm_param_ie));
    }

    /* User-configured Beacon or Probe Response vendor IEs */
    off = n8_append_vendor_ies(is_beacon ? WIFI_VND_IE_TYPE_BEACON : WIFI_VND_IE_TYPE_PROBE_RESP,
                               out, off, max_len);

    return off;
}

/**
 * @brief Rebuild the SoftAP beacon template and push it to the LMAC beacon engine.
 *
 * @return ESP_OK on success (or if SoftAP is not running), or an LMAC error code.
 */
esp_err_t n8_ap_update_beacon(void)
{
    if (!g_n8.ap_running) {
        return ESP_OK;
    }

    uint8_t frame[N8_AP_BEACON_BUF_LEN];
    memset(frame, 0, IEEE80211_HDR_LEN);
    frame[0] = IEEE80211_FC_TYPE_MGMT | IEEE80211_SUBTYPE_BEACON;
    memcpy(frame + IEEE80211_HDR_ADDR1_OFF, s_ap_bcast, IEEE80211_ADDR_LEN);
    memcpy(frame + IEEE80211_HDR_ADDR2_OFF, g_n8.ap_mac, IEEE80211_ADDR_LEN);
    memcpy(frame + IEEE80211_HDR_ADDR3_OFF, g_n8.ap_mac, IEEE80211_ADDR_LEN);

    uint16_t tim_off = 0U;
    uint16_t blen = ap_build_beacon_or_probe_body(frame + IEEE80211_HDR_LEN,
                                                  (uint16_t)(sizeof(frame) - IEEE80211_HDR_LEN),
                                                  true, &tim_off);
    g_n8.ap_tim_offset = tim_off;

    uint16_t bi = g_n8.ap_cfg.ap.beacon_interval
                  ? g_n8.ap_cfg.ap.beacon_interval : N8_AP_DEFAULT_BEACON_INT_TU;
    return esp_lmac_set_beacon(ESP_LMAC_VIF_AP, frame, (uint16_t)(IEEE80211_HDR_LEN + blen),
                               tim_off, bi);
}

/**
 * @brief Handle SoftAP Target Beacon Transmission Time (TBTT) notification from LMAC.
 *
 * Advances the modulo-`ap_dtim_period` DTIM countdown; whenever PS-buffered
 * packets are pending, refreshes the LMAC beacon template with an updated TIM
 * PVB/DTIM count and drains buffered broadcast/multicast packets on DTIM == 0.
 */
void n8_ap_on_tbtt(void)
{
    if (!g_n8.ap_running) {
        return;
    }

    uint8_t per = g_n8.ap_dtim_period ? g_n8.ap_dtim_period : 1U;
    if (g_n8.ap_dtim_count == 0U) {
        g_n8.ap_dtim_count = (uint8_t)(per - 1U);
    } else {
        g_n8.ap_dtim_count--;
    }

    /* Re-synthesize TIM PVB/BMC into beacon template only while PS traffic is buffered */
    if (g_n8.ap_ps_count > 0U) {
        (void)n8_ap_update_beacon();
        if (g_n8.ap_dtim_count == 0U) {
            n8_ap_ps_flush_bcast();
        }
    }
}

/**
 * @brief Synchronize the SoftAP operating channel and beacon DS/HT-Op IEs in APSTA mode.
 *
 * @param new_channel Target 2.4 GHz primary channel (1..14) adopted from the STA link.
 */
void n8_ap_sync_channel(uint8_t new_channel)
{
    if (!g_n8.ap_running || new_channel < N8_CHANNEL_MIN || new_channel > N8_CHANNEL_MAX) {
        return;
    }
    g_n8.ap_cfg.ap.channel = new_channel;
    (void)n8_ap_update_beacon();
}

/* --------------------------------------------------------------------------
 * SoftAP Lifecycle (Mode-Scoped Peer Slab Allocation & Cleanup)
 * -------------------------------------------------------------------------- */

/**
 * @brief Start the SoftAP VIF, allocate mode-scoped peer state, and begin beaconing.
 *
 * Allocates the contiguous `ap_stas` peer slab and matching LMAC AP peer pool
 * only while AP/APSTA mode is active (0 bytes consumed in pure-STA mode),
 * forces RF awake, initializes hostapd when security is enabled, uploads the
 * initial beacon template, and posts `SYSTEM_EVENT_AP_START`.
 *
 * @return ESP_OK on success, ESP_ERR_NO_MEM on slab exhaustion, or LMAC error code.
 */
esp_err_t n8_ap_start(void)
{
    if (g_n8.ap_running) {
        return ESP_OK;
    }

    uint8_t max_conn = g_n8.ap_cfg.ap.max_connection;
    if (max_conn == 0U) {
        max_conn = N8_AP_DEFAULT_MAX_CONN;
    } else if (max_conn > ESP_WIFI_MAX_CONN_NUM) {
        max_conn = ESP_WIFI_MAX_CONN_NUM;
    }

    /* Mode-scoped contiguous SoftAP peer slab + matching LMAC AP peer pool */
    g_n8.ap_stas = (n8_ap_sta_t *)heap_caps_zalloc((size_t)max_conn * sizeof(n8_ap_sta_t),
                                                   MALLOC_CAP_8BIT);
    if (g_n8.ap_stas == NULL) {
        return ESP_ERR_NO_MEM;
    }
    g_n8.ap_sta_cap = max_conn;

    esp_err_t err = esp_lmac_peer_alloc_ap_pool(max_conn);
    if (err != ESP_OK) {
        heap_caps_free(g_n8.ap_stas);
        g_n8.ap_stas = NULL;
        g_n8.ap_sta_cap = 0U;
        return err;
    }

    /* SoftAP requires RF always open */
    n8_pm_wake_for_tx();

    err = esp_lmac_vif_enable(ESP_LMAC_VIF_AP, g_n8.ap_mac);
    if (err != ESP_OK) {
        esp_lmac_peer_free_ap_pool();
        heap_caps_free(g_n8.ap_stas);
        g_n8.ap_stas = NULL;
        g_n8.ap_sta_cap = 0U;
        return err;
    }
    esp_lmac_set_bssid_filter(ESP_LMAC_VIF_AP, g_n8.ap_mac, true);
    esp_lmac_set_protocol_mask(ESP_LMAC_VIF_AP, g_n8.proto[WIFI_IF_AP]);

    /* In APSTA mode, follow an already-active STA channel to maintain single-radio sync */
    uint8_t ch = (g_n8.sta_state >= N8_STA_AUTH && g_n8.sta_channel >= N8_CHANNEL_MIN)
                 ? g_n8.sta_channel
                 : ((g_n8.ap_cfg.ap.channel >= N8_CHANNEL_MIN && g_n8.ap_cfg.ap.channel <= N8_CHANNEL_MAX)
                    ? g_n8.ap_cfg.ap.channel : N8_CHANNEL_MIN);
    g_n8.ap_cfg.ap.channel = ch;
    (void)esp_lmac_set_channel(ch);
    g_n8.cur_channel = ch;

    g_n8.ap_dtim_period = N8_AP_DEFAULT_DTIM_PERIOD;
    g_n8.ap_dtim_count = 0U;
    g_n8.ap_gtk_cipher = (uint8_t)ESP_LMAC_CIPHER_NONE;
    g_n8.ap_uptime_sec = 0U;
    g_n8.ap_sec_subtick = 0U;
    g_n8.ap_running = 1U;

    /* Initialize hostapd authenticator if AP security != OPEN */
    if (g_n8.ap_cfg.ap.authmode != WIFI_AUTH_OPEN &&
        g_n8.wpa_cb != NULL && g_n8.wpa_cb->wpa_ap_init != NULL) {
        g_n8.ap_hapd = g_n8.wpa_cb->wpa_ap_init();
        if (g_n8.ap_hapd == NULL) {
            ESP_LOGE(TAG, "wpa_ap_init failed");
        }
    }

    (void)n8_ap_update_beacon();

    ESP_LOGD(TAG, "SoftAP started: ssid='%.*s' ch=%u auth=%u max_conn=%u",
             (int)(g_n8.ap_cfg.ap.ssid_len ? g_n8.ap_cfg.ap.ssid_len : strnlen((const char *)g_n8.ap_cfg.ap.ssid, N8_MAX_SSID_LEN)),
             (const char *)g_n8.ap_cfg.ap.ssid, (unsigned)ch,
             (unsigned)g_n8.ap_cfg.ap.authmode, (unsigned)max_conn);

    system_event_t evt;
    memset(&evt, 0, sizeof(evt));
    evt.event_id = SYSTEM_EVENT_AP_START;
    n8_send_system_event(&evt);
    return ESP_OK;
}

/**
 * @brief Disconnect and tear down a single SoftAP client slot.
 *
 * Optionally transmits an 802.11 Deauthentication frame, purges queued PS
 * packets for the client's AID and any pending RX defragmentation fragments,
 * releases its hostapd state machine and LMAC peer entry, zeroes the slab slot,
 * and posts `SYSTEM_EVENT_AP_STADISCONNECTED` if the client had completed
 * association.
 *
 * @param sta         Peer slot to remove (no-op if NULL or unused).
 * @param reason      802.11 reason code included in the Deauth frame when @p send_deauth is true.
 * @param send_deauth If true, transmit a Deauthentication frame to the client before cleanup.
 */
void n8_ap_remove_sta(n8_ap_sta_t *sta, uint8_t reason, bool send_deauth)
{
    if (sta == NULL || !sta->in_use) {
        return;
    }

    if (send_deauth) {
        uint8_t body[N8_AP_DEAUTH_BODY_LEN] = { reason, 0U };
        (void)ap_tx_mgmt(IEEE80211_SUBTYPE_DEAUTH, sta->mac, body, sizeof(body));
    }

    ap_ps_purge_aid(sta->aid);
    n8_defrag_purge_peer(ESP_LMAC_VIF_AP, sta->mac);

    if (sta->wpa_sm != NULL && g_n8.wpa_cb != NULL && g_n8.wpa_cb->wpa_ap_remove != NULL) {
        (void)g_n8.wpa_cb->wpa_ap_remove(sta->wpa_sm);
        sta->wpa_sm = NULL;
    }
    if (sta->peer_id != ESP_LMAC_PEER_INVALID) {
        esp_lmac_peer_remove(sta->peer_id);
        sta->peer_id = ESP_LMAC_PEER_INVALID;
    }

    bool notify = (sta->assoced != 0U);
    uint8_t mac[IEEE80211_ADDR_LEN];
    uint8_t aid = sta->aid;
    memcpy(mac, sta->mac, IEEE80211_ADDR_LEN);
    memset(sta, 0, sizeof(*sta));

    if (notify) {
        system_event_t evt;
        memset(&evt, 0, sizeof(evt));
        evt.event_id = SYSTEM_EVENT_AP_STADISCONNECTED;
        memcpy(evt.event_info.sta_disconnected.mac, mac, IEEE80211_ADDR_LEN);
        evt.event_info.sta_disconnected.aid = aid;
        n8_send_system_event(&evt);
    }
}

/**
 * @brief Stop the SoftAP VIF, deauthenticate all clients, and free all mode-scoped RAM.
 */
void n8_ap_stop(void)
{
    if (!g_n8.ap_running) {
        return;
    }

    if (g_n8.ap_stas != NULL) {
        for (uint8_t i = 0U; i < g_n8.ap_sta_cap; i++) {
            if (g_n8.ap_stas[i].in_use) {
                n8_ap_remove_sta(&g_n8.ap_stas[i], WIFI_REASON_ASSOC_LEAVE, true);
            }
        }
    }

    n8_ap_ps_free_all();
    esp_lmac_stop_beacon(ESP_LMAC_VIF_AP);
    esp_lmac_vif_disable(ESP_LMAC_VIF_AP);

    if (g_n8.ap_hapd != NULL && g_n8.wpa_cb != NULL && g_n8.wpa_cb->wpa_ap_deinit != NULL) {
        (void)g_n8.wpa_cb->wpa_ap_deinit(g_n8.ap_hapd);
        g_n8.ap_hapd = NULL;
    }

    /* Release mode-scoped peer slab completely (0 B SoftAP RAM in STA-only mode) */
    esp_lmac_peer_free_ap_pool();
    if (g_n8.ap_stas != NULL) {
        heap_caps_free(g_n8.ap_stas);
        g_n8.ap_stas = NULL;
    }
    g_n8.ap_sta_cap = 0U;
    g_n8.ap_running = 0U;

    system_event_t evt;
    memset(&evt, 0, sizeof(evt));
    evt.event_id = SYSTEM_EVENT_AP_STOP;
    n8_send_system_event(&evt);
}

/**
 * @brief Mark a SoftAP client as data-plane authorized after hostapd completes PTK installation.
 *
 * @param mac 6-byte MAC address of the client whose 4-Way Handshake succeeded.
 */
void n8_ap_on_ptk_done(const uint8_t mac[6])
{
    n8_ap_sta_t *sta = n8_ap_find_sta(mac);
    if (sta == NULL) {
        return;
    }
    sta->authorized = 1U;
    ESP_LOGD(TAG, "SoftAP STA authorized: aid=%u %02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned)sta->aid, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* --------------------------------------------------------------------------
 * SoftAP Management & Control Frame Handlers
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
typedef struct {
    esp_lmac_peer_id_t peer_id;
    uint8_t            tid;
    uint8_t            win;
    uint16_t           ssn;
} n8_ap_addba_ctx_t;

/**
 * @brief Arm SoftAP hardware RX Block Ack only after ADDBA Response is ACKed over air.
 *
 * Re-validates that SoftAP is still running and that the target peer slot
 * remains active, associated, and authorized before opening the hardware RX BA
 * window, avoiding races if the client disconnected while the frame was in flight.
 *
 * @param ctx Heap-allocated `n8_ap_addba_ctx_t` pending session state.
 * @param st  LMAC TX status for the transmitted ADDBA Response.
 */
static void ap_addba_tx_done_cb(void *ctx, const esp_lmac_tx_status_t *st)
{
    n8_ap_addba_ctx_t *pending = (n8_ap_addba_ctx_t *)ctx;
    if (pending == NULL) {
        return;
    }
    if (st != NULL && st->ok != 0U && g_n8.ap_running != 0U && g_n8.ap_stas != NULL) {
        for (uint8_t i = 0U; i < g_n8.ap_sta_cap; i++) {
            n8_ap_sta_t *sta = &g_n8.ap_stas[i];
            if (sta->in_use != 0U && sta->assoced != 0U && sta->authorized != 0U &&
                sta->peer_id == pending->peer_id) {
                (void)esp_lmac_add_rx_ba(pending->peer_id, pending->tid,
                                         pending->ssn, pending->win);
                break;
            }
        }
    }
    heap_caps_free(pending);
}
#endif

/**
 * @brief Process received 802.11 management frames addressed to the SoftAP VIF.
 *
 * Handles Probe Requests (wildcard or matching SSID), Open-System Authentication
 * Requests, Association/Reassociation Requests (parsing HT Caps/SGI20, RSN/WPA,
 * and WMM IEs, purging stale security/LMAC/replay/defrag state on in-place
 * re-association, registering the LMAC peer, replying with AssocResp including
 * HT/WMM/vendor IEs before starting hostapd's 4-Way Handshake so the client
 * transitions to Associated before EAPOL M1), Category 3 Block Ack (ADDBA/DELBA)
 * negotiation with ACK-gated RX BA activation, and client-initiated Deauth/Disassoc.
 *
 * @param ctrl  RX metadata (used for Probe Request RSSI reporting).
 * @param frame Raw 802.11 management frame starting at Frame Control.
 * @param len   Total frame length in bytes (excluding FCS).
 */
void n8_ap_rx_mgmt(const wifi_pkt_rx_ctrl_t *ctrl, const uint8_t *frame, uint16_t len)
{
    if (!g_n8.ap_running || len < IEEE80211_HDR_LEN) {
        return;
    }

    uint8_t subtype = (uint8_t)(frame[0] & IEEE80211_FC_SUBTYPE_MASK);
    const uint8_t *da = frame + IEEE80211_HDR_ADDR1_OFF;
    const uint8_t *sa = frame + IEEE80211_HDR_ADDR2_OFF;

    /* Probe Request (may be broadcast or addressed to AP MAC) */
    if (subtype == IEEE80211_SUBTYPE_PROBE_REQ) {
        if ((da[0] & N8_MAC_MCAST_BIT) == 0U &&
            memcmp(da, g_n8.ap_mac, IEEE80211_ADDR_LEN) != 0) {
            return;
        }
        /* Check SSID IE matches wildcard or our AP SSID */
        const uint8_t *ies = frame + IEEE80211_HDR_LEN;
        uint16_t ie_len = (uint16_t)(len - IEEE80211_HDR_LEN);
        bool ssid_match = true;
        if (ie_len >= IEEE80211_IE_HDR_LEN && ies[0] == IEEE80211_IE_SSID && ies[1] > 0U) {
            uint8_t ap_slen = g_n8.ap_cfg.ap.ssid_len;
            if (ap_slen == 0U) {
                ap_slen = (uint8_t)strnlen((const char *)g_n8.ap_cfg.ap.ssid, N8_MAX_SSID_LEN);
            }
            if (ies[1] != ap_slen || (uint16_t)(IEEE80211_IE_HDR_LEN + ies[1]) > ie_len ||
                memcmp(ies + IEEE80211_IE_HDR_LEN, g_n8.ap_cfg.ap.ssid, ap_slen) != 0) {
                ssid_match = false;
            }
        }
        if (ssid_match) {
            uint8_t resp[N8_AP_PROBE_RESP_BUF_LEN];
            uint16_t blen = ap_build_beacon_or_probe_body(resp, sizeof(resp), false, NULL);
            (void)ap_tx_mgmt(IEEE80211_SUBTYPE_PROBE_RESP, sa, resp, blen);

            if ((g_n8.event_mask & WIFI_EVENT_MASK_AP_PROBEREQRECVED) == 0U) {
                system_event_t evt;
                memset(&evt, 0, sizeof(evt));
                evt.event_id = SYSTEM_EVENT_AP_PROBEREQRECVED;
                evt.event_info.ap_probereqrecved.rssi = (int8_t)ctrl->rssi;
                memcpy(evt.event_info.ap_probereqrecved.mac, sa, IEEE80211_ADDR_LEN);
                n8_send_system_event(&evt);
            }
        }
        return;
    }

    /* Remaining mgmt frames must be addressed to our AP MAC */
    if (memcmp(da, g_n8.ap_mac, IEEE80211_ADDR_LEN) != 0) {
        return;
    }

    if (subtype == IEEE80211_SUBTYPE_AUTH && len >= N8_AP_AUTH_MIN_FRAME_LEN) {
        uint16_t alg = (uint16_t)((uint16_t)frame[N8_AP_AUTH_ALG_OFF] |
                                  ((uint16_t)frame[N8_AP_AUTH_ALG_OFF + 1U] << 8));
        uint16_t seq = (uint16_t)((uint16_t)frame[N8_AP_AUTH_SEQ_OFF] |
                                  ((uint16_t)frame[N8_AP_AUTH_SEQ_OFF + 1U] << 8));
        uint16_t status = N8_AP_STATUS_SUCCESS;

        if (alg != IEEE80211_AUTH_ALG_OPEN || seq != N8_AP_AUTH_SEQ_REQ) {
            status = N8_AP_STATUS_UNSUPP_AUTH_ALG;
        } else {
            n8_ap_sta_t *sta = ap_alloc_sta(sa);
            if (sta == NULL) {
                status = N8_AP_STATUS_AP_UNABLE_STA;
            } else {
                sta->authed = 1U;
                sta->last_rx_sec = g_n8.ap_uptime_sec;
            }
        }

        uint8_t resp[N8_AP_AUTH_FIXED_LEN] = {
            (uint8_t)(alg & 0xFFU), (uint8_t)(alg >> 8),
            N8_AP_AUTH_SEQ_RESP, 0U,
            (uint8_t)(status & 0xFFU), (uint8_t)(status >> 8)
        };
        (void)ap_tx_mgmt(IEEE80211_SUBTYPE_AUTH, sa, resp, sizeof(resp));
        return;
    }

    if ((subtype == IEEE80211_SUBTYPE_ASSOC_REQ || subtype == IEEE80211_SUBTYPE_REASSOC_REQ) &&
        len >= N8_AP_ASSOC_REQ_IE_OFF) {
        uint16_t ie_off = (subtype == IEEE80211_SUBTYPE_REASSOC_REQ)
                          ? N8_AP_REASSOC_REQ_IE_OFF : N8_AP_ASSOC_REQ_IE_OFF;
        if (len < ie_off) {
            return;
        }

        n8_ap_sta_t *sta = n8_ap_find_sta(sa);
        uint16_t status = N8_AP_STATUS_SUCCESS;
        if (sta == NULL || !sta->authed) {
            uint8_t deauth[N8_AP_DEAUTH_BODY_LEN] = { WIFI_REASON_NOT_AUTHED, 0U };
            (void)ap_tx_mgmt(IEEE80211_SUBTYPE_DEAUTH, sa, deauth, sizeof(deauth));
            return;
        }

        /* Parse client IEs (HT Caps + RSN/WPA IE + WMM IE) */
        const uint8_t *ies = frame + ie_off;
        uint16_t ie_len = (uint16_t)(len - ie_off);
        uint16_t pos = 0U;
        const uint8_t *sec_ie = NULL;
        uint16_t sec_ie_len = 0U;
        uint8_t ht_cap = 0U;
        uint8_t ht_mcs = 0U;
        uint8_t ht_sgi20 = 0U;
        uint8_t wmm_cap = 0U;

        while (pos + IEEE80211_IE_HDR_LEN <= ie_len) {
            uint8_t id = ies[pos];
            uint8_t elen = ies[pos + 1U];
            if (pos + IEEE80211_IE_HDR_LEN + elen > ie_len) {
                break;
            }
            if (id == IEEE80211_IE_HT_CAP && elen >= N8_AP_HT_CAP_BODY_LEN) {
                ht_cap = 1U;
                ht_sgi20 = ((ies[pos + IEEE80211_IE_HDR_LEN] & IEEE80211_HT_CAP_INFO_SGI20) != 0U) ? 1U : 0U;
                ht_mcs = ies[pos + IEEE80211_IE_HDR_LEN + N8_AP_HT_CAP_MCS0_OFF];
            } else if (id == IEEE80211_IE_RSN) {
                sec_ie = &ies[pos];
                sec_ie_len = (uint16_t)(elen + IEEE80211_IE_HDR_LEN);
            } else if (id == IEEE80211_IE_VENDOR && elen >= N8_AP_VENDOR_OUI_TYPE_LEN &&
                       ies[pos + IEEE80211_IE_HDR_LEN] == IEEE80211_OUI_MS_0 &&
                       ies[pos + IEEE80211_IE_HDR_LEN + 1U] == IEEE80211_OUI_MS_1 &&
                       ies[pos + IEEE80211_IE_HDR_LEN + 2U] == IEEE80211_OUI_MS_2) {
                if (ies[pos + IEEE80211_IE_HDR_LEN + 3U] == IEEE80211_OUI_TYPE_WPA && sec_ie == NULL) {
                    sec_ie = &ies[pos];
                    sec_ie_len = (uint16_t)(elen + IEEE80211_IE_HDR_LEN);
                } else if (ies[pos + IEEE80211_IE_HDR_LEN + 3U] == IEEE80211_OUI_TYPE_WMM &&
                           elen >= IEEE80211_WMM_IE_MIN_BODY_LEN &&
                           (ies[pos + IEEE80211_IE_HDR_LEN + 4U] == IEEE80211_WMM_SUBTYPE_INFO ||
                            ies[pos + IEEE80211_IE_HDR_LEN + 4U] == IEEE80211_WMM_SUBTYPE_PARAM) &&
                           ies[pos + IEEE80211_IE_HDR_LEN + 5U] == IEEE80211_WMM_VERSION) {
                    wmm_cap = 1U;
                }
            }
            pos = (uint16_t)(pos + IEEE80211_IE_HDR_LEN + elen);
        }

        /* Clear stale security/LMAC/replay state when a STA re-associates in-place */
        if (sta->wpa_sm != NULL && g_n8.wpa_cb != NULL && g_n8.wpa_cb->wpa_ap_remove != NULL) {
            (void)g_n8.wpa_cb->wpa_ap_remove(sta->wpa_sm);
            sta->wpa_sm = NULL;
        }
        if (sta->peer_id != ESP_LMAC_PEER_INVALID) {
            esp_lmac_peer_remove(sta->peer_id);
            sta->peer_id = ESP_LMAC_PEER_INVALID;
        }
        sta->ptk_cipher = (uint8_t)ESP_LMAC_CIPHER_NONE;
        sta->authorized = 0U;
        sta->last_rx_seq_valid = 0U;
        memset(sta->ptk_pn, 0, sizeof(sta->ptk_pn));
        n8_defrag_purge_peer(ESP_LMAC_VIF_AP, sta->mac);

        /* Register peer in LMAC TRC */
        esp_lmac_peer_caps_t pcaps = {0};
        memcpy(pcaps.mac, sta->mac, IEEE80211_ADDR_LEN);
        pcaps.rate_mask_11bg = N8_AP_RATE_MASK_11BG_ALL;
        pcaps.ht20_mcs_mask = (ht_cap && (g_n8.proto[WIFI_IF_AP] & WIFI_PROTOCOL_11N))
                              ? (ht_mcs ? ht_mcs : N8_AP_HT20_MCS0_7_MASK) : 0U;
        pcaps.ht_enabled = (pcaps.ht20_mcs_mask != 0U) ? 1U : 0U;
        pcaps.short_gi_20 = (pcaps.ht_enabled && ht_sgi20 != 0U) ? 1U : 0U;
        pcaps.qos_enabled = (n8_qos_cfg_enabled() && (wmm_cap || pcaps.ht_enabled)) ? 1U : 0U;
        sta->peer_id = esp_lmac_peer_add(ESP_LMAC_VIF_AP, &pcaps);
        sta->ht_enabled = pcaps.ht_enabled;
        sta->qos_enabled = pcaps.qos_enabled;
        sta->phy_11b = 1U;
        sta->phy_11g = 1U;
        sta->phy_11n = pcaps.ht_enabled;
        sta->assoced = 1U;
        sta->last_rx_sec = g_n8.ap_uptime_sec;

        /* Build and send AssocResp BEFORE launching hostapd 4-way handshake */
        uint8_t resp[N8_AP_ASSOC_RESP_BUF_LEN];
        uint16_t roff = 0U;
        uint16_t cap = (uint16_t)(IEEE80211_CAPINFO_ESS | IEEE80211_CAPINFO_SHORT_SLOT) |
                       ((g_n8.ap_cfg.ap.authmode != WIFI_AUTH_OPEN) ? IEEE80211_CAPINFO_PRIVACY : 0U);
        resp[roff++] = (uint8_t)(cap & 0xFFU);
        resp[roff++] = (uint8_t)(cap >> 8);
        resp[roff++] = (uint8_t)(status & 0xFFU);
        resp[roff++] = (uint8_t)(status >> 8);
        uint16_t aid_field = (uint16_t)(N8_AP_AID_TOP_BITS | sta->aid);
        resp[roff++] = (uint8_t)(aid_field & 0xFFU);
        resp[roff++] = (uint8_t)(aid_field >> 8);
        memcpy(resp + roff, s_ap_rates_ie, sizeof(s_ap_rates_ie));
        roff = (uint16_t)(roff + sizeof(s_ap_rates_ie));
        if (sta->ht_enabled) {
            memcpy(resp + roff, s_ap_ht20_cap_ie, sizeof(s_ap_ht20_cap_ie));
            roff = (uint16_t)(roff + sizeof(s_ap_ht20_cap_ie));
        }
        if (sta->qos_enabled != 0U &&
            (uint16_t)(roff + sizeof(s_ap_wmm_param_ie)) <= sizeof(resp)) {
            memcpy(resp + roff, s_ap_wmm_param_ie, sizeof(s_ap_wmm_param_ie));
            roff = (uint16_t)(roff + sizeof(s_ap_wmm_param_ie));
        }
        roff = n8_append_vendor_ies(WIFI_VND_IE_TYPE_ASSOC_RESP, resp, roff, sizeof(resp));

        uint8_t resp_sub = (subtype == IEEE80211_SUBTYPE_REASSOC_REQ)
                           ? IEEE80211_SUBTYPE_REASSOC_RESP : IEEE80211_SUBTYPE_ASSOC_RESP;
        (void)ap_tx_mgmt(resp_sub, sa, resp, roff);

        if (g_n8.ap_cfg.ap.authmode == WIFI_AUTH_OPEN) {
            sta->authorized = 1U;
        } else {
            sta->authorized = 0U;
            if (g_n8.wpa_cb != NULL && g_n8.wpa_cb->wpa_ap_join != NULL) {
                if (sec_ie_len > N8_AP_MAX_SEC_IE_LEN ||
                    !g_n8.wpa_cb->wpa_ap_join(&sta->wpa_sm, sta->mac,
                                              (uint8_t *)(uintptr_t)sec_ie,
                                              (uint8_t)sec_ie_len)) {
                    n8_ap_remove_sta(sta, WIFI_REASON_INVALID_RSN_IE_CAP, true);
                    return;
                }
            }
        }

        system_event_t evt;
        memset(&evt, 0, sizeof(evt));
        evt.event_id = SYSTEM_EVENT_AP_STACONNECTED;
        memcpy(evt.event_info.sta_connected.mac, sta->mac, IEEE80211_ADDR_LEN);
        evt.event_info.sta_connected.aid = sta->aid;
        n8_send_system_event(&evt);
        return;
    }

    if (subtype == IEEE80211_SUBTYPE_ACTION && len >= (IEEE80211_HDR_LEN + N8_AP_ACTION_HDR_LEN)) {
        n8_ap_sta_t *sta = n8_ap_find_sta(sa);
        if (sta == NULL || sta->assoced == 0U || sta->authorized == 0U) {
            return;
        }
        const uint8_t *body = frame + IEEE80211_HDR_LEN;
        uint16_t blen = (uint16_t)(len - IEEE80211_HDR_LEN);
        if (body[0] == IEEE80211_CAT_BA) {
            if (body[1] == IEEE80211_BA_ACTION_ADDBA_REQ && blen >= N8_AP_ADDBA_REQ_BODY_LEN) {
                uint8_t dialog = body[2];
                uint16_t ba_param = (uint16_t)((uint16_t)body[3] | ((uint16_t)body[4] << 8));
                uint8_t policy = (uint8_t)((ba_param >> N8_AP_ADDBA_POLICY_SHIFT) & N8_AP_ADDBA_POLICY_MASK);
                uint8_t tid = (uint8_t)((ba_param >> N8_AP_ADDBA_TID_SHIFT) & N8_AP_ADDBA_TID_MASK);
                uint16_t req_win = (uint16_t)((ba_param >> N8_AP_ADDBA_WIN_SHIFT) & N8_AP_ADDBA_WIN_MASK);
                uint16_t timeout = (uint16_t)((uint16_t)body[5] | ((uint16_t)body[6] << 8));
                uint16_t ssn = (uint16_t)((((uint16_t)body[7] | ((uint16_t)body[8] << 8)) >> IEEE80211_SEQ_SHIFT) & IEEE80211_SEQ_MASK);
                uint16_t status = N8_AP_STATUS_DECLINED;
                uint16_t resp_win = req_win;
                esp_lmac_tx_done_cb_t tx_cb = NULL;
                void *tx_ctx = NULL;

#ifdef CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
                /* Accept Immediate BA on HT clients only; defer HW RX BA arm until ADDBA Resp ACK */
                if (g_n8.init_cfg.ampdu_rx_enable != 0U &&
                    sta->ht_enabled != 0U &&
                    policy == N8_AP_ADDBA_POLICY_IMMED_VAL && tid < N8_MAX_TID &&
                    g_n8.init_cfg.rx_ba_win > 0U &&
                    esp_lmac_can_add_rx_ba(sta->peer_id, tid)) {
                    uint16_t max_win = g_n8.init_cfg.rx_ba_win;
                    resp_win = (req_win == 0U || req_win > max_win) ? max_win : req_win;
                    n8_ap_addba_ctx_t *pending = (n8_ap_addba_ctx_t *)heap_caps_malloc(
                        sizeof(*pending), MALLOC_CAP_8BIT);
                    if (pending != NULL) {
                        pending->peer_id = sta->peer_id;
                        pending->tid = tid;
                        pending->win = (uint8_t)resp_win;
                        pending->ssn = ssn;
                        status = N8_AP_STATUS_SUCCESS;
                        tx_cb = ap_addba_tx_done_cb;
                        tx_ctx = pending;
                    }
                }
#else
                (void)policy;
                (void)ssn;
#endif

                uint16_t resp_param = (uint16_t)(((resp_win & N8_AP_ADDBA_WIN_MASK) << N8_AP_ADDBA_WIN_SHIFT) |
                                                 ((uint16_t)tid << N8_AP_ADDBA_TID_SHIFT) |
                                                 N8_AP_ADDBA_POLICY_IMMED_BIT);
                uint8_t resp[N8_AP_ADDBA_RESP_BODY_LEN] = {
                    IEEE80211_CAT_BA, IEEE80211_BA_ACTION_ADDBA_RESP,
                    dialog,
                    (uint8_t)(status & 0xFFU), (uint8_t)(status >> 8),
                    (uint8_t)(resp_param & 0xFFU), (uint8_t)(resp_param >> 8),
                    (uint8_t)(timeout & 0xFFU), (uint8_t)(timeout >> 8)
                };
                esp_err_t tx_err = ap_tx_mgmt_cb(IEEE80211_SUBTYPE_ACTION, sa,
                                                 resp, sizeof(resp), tx_cb, tx_ctx);
                if (tx_err != ESP_OK && tx_ctx != NULL) {
                    heap_caps_free(tx_ctx);
                }
            } else if (body[1] == IEEE80211_BA_ACTION_DELBA && blen >= N8_AP_DELBA_BODY_LEN) {
                uint16_t del_param = (uint16_t)((uint16_t)body[2] | ((uint16_t)body[3] << 8));
                uint8_t tid = (uint8_t)((del_param >> N8_AP_DELBA_TID_SHIFT) & N8_AP_ADDBA_TID_MASK);
                if (tid < N8_MAX_TID) {
                    esp_lmac_del_rx_ba(sta->peer_id, tid);
                }
            }
        }
        return;
    }

    if (subtype == IEEE80211_SUBTYPE_DEAUTH || subtype == IEEE80211_SUBTYPE_DISASSOC) {
        n8_ap_sta_t *sta = n8_ap_find_sta(sa);
        if (sta != NULL) {
            n8_ap_remove_sta(sta, WIFI_REASON_ASSOC_LEAVE, false);
        }
    }
}

/**
 * @brief Process received 802.11 control frames for the SoftAP VIF (PS-Poll delivery).
 *
 * Extracts the 14-bit AID from the PS-Poll Duration/ID field, refreshes the
 * client's activity timestamp, and releases one buffered unicast frame.
 *
 * @param frame Raw 802.11 control frame starting at Frame Control.
 * @param len   Total frame length in bytes (excluding FCS).
 */
void n8_ap_rx_ctrl(const uint8_t *frame, uint16_t len)
{
    if (!g_n8.ap_running || len < N8_AP_PS_POLL_MIN_LEN) {
        return;
    }
    if ((frame[0] & IEEE80211_FC_SUBTYPE_MASK) == IEEE80211_SUBTYPE_PS_POLL) {
        uint16_t aid = (uint16_t)(((uint16_t)frame[N8_AP_PS_POLL_AID_OFF] |
                                   ((uint16_t)frame[N8_AP_PS_POLL_AID_OFF + 1U] << 8)) &
                                  N8_AP_AID_MASK);
        n8_ap_sta_t *sta = n8_ap_find_sta_by_aid(aid);
        if (sta != NULL) {
            sta->last_rx_sec = g_n8.ap_uptime_sec;
            n8_ap_ps_flush_sta(sta, true);
        }
    }
}

/**
 * @brief Periodic 100 ms SoftAP maintenance tick for client inactivity aging.
 *
 * Divides the 100 ms worker tick down to 1 Hz (`ap_uptime_sec`) and
 * deauthenticates any client whose `last_rx_sec` has exceeded `inactive_sec[AP]`
 * (default 300 s).
 */
void n8_ap_on_tick_100ms(void)
{
    if (!g_n8.ap_running || g_n8.ap_stas == NULL) {
        return;
    }

    g_n8.ap_sec_subtick++;
    if (g_n8.ap_sec_subtick < N8_AP_TICKS_PER_SEC) {
        return;
    }
    g_n8.ap_sec_subtick = 0U;
    g_n8.ap_uptime_sec++;

    uint32_t max_idle = g_n8.inactive_sec[WIFI_IF_AP]
                        ? g_n8.inactive_sec[WIFI_IF_AP] : N8_AP_DEFAULT_INACTIVE_SEC;
    for (uint8_t i = 0U; i < g_n8.ap_sta_cap; i++) {
        n8_ap_sta_t *sta = &g_n8.ap_stas[i];
        if (sta->in_use && (g_n8.ap_uptime_sec - sta->last_rx_sec) >= max_idle) {
            ESP_LOGD(TAG, "SoftAP aging out inactive STA aid=%u", (unsigned)sta->aid);
            n8_ap_remove_sta(sta, WIFI_REASON_ASSOC_EXPIRE, true);
        }
    }
}
