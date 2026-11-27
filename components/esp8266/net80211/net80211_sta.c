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
// Station MLME state machine: fast-connect scan, Open & WPA3-SAE authentication,
// 802.11n HT20/SGI20 & WMM/QoS association, WPS enrollee & WPA2-Enterprise EAP
// integration, 4-Way Handshake coordination, 802.11w PMF (SW CCMP mgmt TX/RX,
// BIP MMIE, SA-Query initiator/watchdog), CSA IE 37 channel switching, ERP/HT
// protection & close-range rxmax_ext hysteresis, 802.11k/11v RRM/Action hooks,
// ADDBA/DELBA RX Block-Ack negotiation, and beacon-loss watchdog.
//
// STA MLME state progression:
//   N8_STA_IDLE -> N8_STA_SCANNING (cached-channel probe, then full sweep)
//               -> N8_STA_AUTH     (Open Auth or WPA3-SAE Commit + Confirm)
//               -> N8_STA_ASSOC    (AssocReq / AssocResp)
//               -> N8_STA_4WAY     (EAPOL 4-Way / WPS / WPA2-Ent; skipped for Open)
//               -> N8_STA_RUN      (Authorized data plane + PM + CSA + watchdogs)

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "os.h"
#include "net80211_internal.h"

#define TAG "wifi_sta"

/* From wpa_supplicant/src/crypto/ccmp.c (compiled with -DCONFIG_IEEE80211W) */
extern u8 *ccmp_decrypt(const u8 *tk, const u8 *hdr, const u8 *data,
                        size_t data_len, size_t *decrypted_len, bool espnow_pkt);
extern u8 *ccmp_encrypt(const u8 *tk, u8 *frame, size_t len, size_t hdrlen,
                        u8 *pn, int keyid, size_t *encrypted_len);

/* --------------------------------------------------------------------------
 * STA Protocol, Frame Layout & Watchdog Timing Constants
 * -------------------------------------------------------------------------- */

/** WPA3-SAE sequence numbers and IEEE 802.11 §9.4.1.9 status codes. */
#define SAE_MSG_COMMIT_TYPE                 1U
#define SAE_MSG_CONFIRM_TYPE                2U
#define WLAN_STATUS_SUCCESS_CODE            0U
#define WLAN_STATUS_REQUEST_DECLINED        37U  /* ADDBA declined when AMPDU RX disabled */
#define WLAN_STATUS_ANTI_CLOGGING_CODE      76U  /* SAE anti-clogging token required */

/** STA MLME retry/timeout thresholds (100 ms worker ticks) and RF hysteresis bounds. */
#define N8_STA_AUTH_TIMEOUT_TICKS           2U   /* 200 ms per Auth retry */
#define N8_STA_SAE_AUTH_TIMEOUT_TICKS       10U  /* 1000 ms per SAE Commit/Confirm step */
#define N8_STA_ASSOC_TIMEOUT_TICKS          2U   /* 200 ms per Assoc retry */
#define N8_STA_4WAY_TIMEOUT_TICKS           50U  /* 5.0 s 4-Way Handshake timeout */
#define N8_STA_WPA2_ENT_TIMEOUT_TICKS       300U /* 30.0 s (TLS/RADIUS EAP) */
#define N8_STA_MAX_AUTH_RETRIES             6U
#define N8_STA_SA_QUERY_RETRY_TICKS         2U   /* 200 ms SA-Query retry */
#define N8_STA_SA_QUERY_TIMEOUT_TICKS       10U  /* 1000 ms SA-Query total timeout */
#define N8_STA_TICKS_PER_SEC                10U  /* 100 ms ticks per second */
#define N8_STA_TICK_MS                      100U
#define N8_STA_MIN_BCN_MISS_TICKS           30U  /* 3.0 s minimum beacon-loss watchdog */
#define N8_STA_CSA_MISS_FALLBACK_TICKS      2U   /* 200 ms missed-beacon CSA decrement threshold */
#define N8_STA_LMAC_SCRATCH_MAX             96U
#define N8_STA_LMAC_FCS_LEN                 4U   /* Trailing 802.11 FCS headroom in LMAC scratch */
#define N8_STA_RXMAX_HI_RSSI                (-25) /* dBm threshold to engage close-range attenuation */
#define N8_STA_RXMAX_LO_RSSI                (-30) /* dBm hysteresis threshold to clear attenuation */
#define N8_STA_RXMAX_EXT_LVL                3U
#define N8_STA_RSSI_UNKNOWN                 (-127)
#define N8_STA_DEFAULT_NCHAN                13U  /* Fallback regulatory channel count for CSA validation */

/** Fast-connect scan pass identifiers (`sta_scan_connect_pass`). */
#define N8_STA_SCAN_PASS_CACHED             0U   /* Single-channel probe on configured/RTC hint */
#define N8_STA_SCAN_PASS_FULL               1U   /* Full regulatory channel sweep fallback */

/** 802.11 MAC/CCMP header, management body sizes & fixed field offsets (bytes). */
#define N8_STA_PROT_HDR_LEN                 (IEEE80211_HDR_LEN + IEEE80211_CCMP_HDR_LEN)
#define N8_STA_DEAUTH_BODY_LEN              2U
#define N8_STA_AUTH_FIXED_LEN               6U   /* Algorithm(2) + Sequence(2) + Status(2) */
#define N8_STA_AUTH_MIN_FRAME_LEN           (IEEE80211_HDR_LEN + N8_STA_AUTH_FIXED_LEN)
#define N8_STA_AUTH_ALG_OFF                 (IEEE80211_HDR_LEN)
#define N8_STA_AUTH_SEQ_OFF                 (IEEE80211_HDR_LEN + 2U)
#define N8_STA_AUTH_STATUS_OFF              (IEEE80211_HDR_LEN + 4U)
#define N8_STA_AUTH_SEQ_REQ                 1U
#define N8_STA_AUTH_SEQ_RESP                2U
#define N8_STA_SAE_MAX_MSG_LEN              384U
#define N8_STA_ASSOC_REQ_BUF_LEN            384U
#define N8_STA_ASSOC_RESP_MIN_LEN           30U  /* 24B hdr + Cap(2) + Status(2) + AID(2) */
#define N8_STA_ASSOC_RESP_STATUS_OFF        (IEEE80211_HDR_LEN + 2U)
#define N8_STA_ASSOC_RESP_AID_OFF           (IEEE80211_HDR_LEN + 4U)
#define N8_STA_AID_MASK                     0x3FFFU
#define N8_STA_DEFAULT_LISTEN_INT           3U
#define N8_STA_MIN_BEACON_INT_TU            10U
#define N8_STA_DEFAULT_BEACON_INT_TU        100U
#define N8_STA_DEFAULT_DTIM_PERIOD          1U
#define N8_STA_BCN_CAPINFO_OFF              (IEEE80211_HDR_LEN + IEEE80211_BCN_CAPINFO_OFF)
#define N8_STA_BCN_IE_OFF                   (IEEE80211_HDR_LEN + IEEE80211_BCN_FIXED_LEN)
#define N8_STA_FC_SUBTYPE_SHIFT             4U

/** Information Element sizes, Country IE offsets, and default peer rate masks. */
#define N8_STA_HT_CAP_IE_LEN                28U  /* 2B IE header + 26B HT Capabilities body */
#define N8_STA_HT_CAP_BODY_LEN              26U
#define N8_STA_RATE_MASK_11BG_ALL           0x0FFFU
#define N8_STA_HT20_MCS0_7_MASK             0xFFU
#define N8_STA_COUNTRY_IE_MIN_LEN           6U   /* CC(3) + StartChan(1) + NumChan(1) + MaxPwr(1) */
#define N8_STA_COUNTRY_CC_LEN               3U
#define N8_STA_COUNTRY_SCHAN_OFF            5U   /* Offset from IE start: hdr(2) + CC(3) */
#define N8_STA_COUNTRY_NCHAN_OFF            6U
#define N8_STA_COUNTRY_PWR_OFF              7U
#define N8_STA_VENDOR_OUI_TYPE_LEN          4U   /* 3-byte OUI + 1-byte OUI Type */

/** Action frame (SA Query, Block Ack ADDBA/DELBA & 11k/11v) layout and bitfield shifts. */
#define N8_STA_ACTION_HDR_LEN               2U   /* Category(1) + Action(1) */
#define N8_STA_ACTION_TX_MAX_LEN            512U /* Max Action body accepted by n8_sta_tx_action() */
#define N8_STA_REG_SUBTYPE_MAX              32U  /* Bit width of frame_reg_subtype category mask */
#define N8_STA_SA_QUERY_BODY_LEN            4U   /* Category(1) + Action(1) + TransID(2) */
#define N8_STA_ADDBA_REQ_BODY_LEN           9U
#define N8_STA_ADDBA_RESP_BODY_LEN          9U
#define N8_STA_DELBA_BODY_LEN               6U
#define N8_STA_ADDBA_POLICY_SHIFT           1U
#define N8_STA_ADDBA_POLICY_MASK            1U
#define N8_STA_ADDBA_POLICY_IMMED_VAL       1U   /* Immediate Block Ack policy field value */
#define N8_STA_ADDBA_TID_SHIFT              2U
#define N8_STA_ADDBA_TID_MASK               0x0FU
#define N8_STA_ADDBA_WIN_SHIFT              6U
#define N8_STA_ADDBA_WIN_MASK               0x3FFU
#define N8_STA_ADDBA_POLICY_IMMED           0x02U /* Immediate Block Ack policy bit */
#define N8_STA_DELBA_TID_SHIFT              12U

/*
 * Supported Rates (1, 2, 5.5, 11 Mbps basic; 6, 9, 12, 18 Mbps) and
 * Extended Supported Rates (24, 36, 48, 54 Mbps), in 500 kbps units.
 */
static const uint8_t s_sta_rates_ie[] = {
    IEEE80211_IE_SUPP_RATES, 0x08U, 0x82U, 0x84U, 0x8BU, 0x96U, 0x0CU, 0x12U, 0x18U, 0x24U,
    IEEE80211_IE_EXT_RATES,  0x04U, 0x30U, 0x48U, 0x60U, 0x6CU
};

/* WFA WMM Information Element (9 bytes: OUI 00:50:F2, Type 2, Subtype 0, Ver 1, QoS Info 0) */
static const uint8_t s_sta_wmm_info_ie[IEEE80211_WMM_INFO_IE_LEN] = {
    IEEE80211_IE_VENDOR, IEEE80211_WMM_IE_MIN_BODY_LEN,
    IEEE80211_OUI_MS_0, IEEE80211_OUI_MS_1, IEEE80211_OUI_MS_2,
    IEEE80211_OUI_TYPE_WMM, IEEE80211_WMM_SUBTYPE_INFO, IEEE80211_WMM_VERSION, 0x00U
};

/* 802.11n HT20 Capabilities IE (26-byte body: SGI20, MCS0..7, max A-MPDU 16KB) */
static const uint8_t s_ht20_cap_ie[N8_STA_HT_CAP_IE_LEN] = {
    IEEE80211_IE_HT_CAP, N8_STA_HT_CAP_BODY_LEN,
    0x2CU, 0x01U, /* HT Cap Info: SM PS disabled, Short GI 20MHz, Rx STBC 1-stream */
    0x1AU,        /* A-MPDU params: max 16KB (2), min spacing 8us */
    0xFFU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, /* MCS0..7 */
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, /* Extended HT Caps */
    0x00U, 0x00U, 0x00U, 0x00U, /* TxBF */
    0x00U         /* ASEL */
};

/**
 * @brief Allocate the next 802.11 Sequence Control value for the STA VIF.
 *
 * @return Sequence Control field value (12-bit sequence number shifted left by 4, fragment 0).
 */
uint16_t n8_sta_next_seq(void)
{
    uint16_t s = (uint16_t)((g_n8.sta_tx_seq++ & IEEE80211_SEQ_MASK) << IEEE80211_SEQ_SHIFT);
    return s;
}

/**
 * @brief LMAC TX completion callback that releases a heap-copied management frame body.
 *
 * Shared by STA, SoftAP, and raw 802.11 TX paths for asynchronous management frame copies.
 *
 * @param ctx Heap pointer allocated for the management frame body (may be NULL).
 * @param st  LMAC transmission completion status (unused).
 */
void n8_mgmt_free_tx_cb(void *ctx, const esp_lmac_tx_status_t *st)
{
    (void)st;
    if (ctx != NULL) {
        heap_caps_free(ctx);
    }
}

/**
 * @brief Free an os_malloc'd management frame buffer upon LMAC TX completion.
 *
 * @param ctx Pointer to the buffer allocated by ccmp_encrypt().
 * @param st  LMAC TX status (unused).
 */
static void sta_os_free_tx_cb(void *ctx, const esp_lmac_tx_status_t *st)
{
    (void)st;
    if (ctx != NULL) {
        os_free(ctx);
    }
}

/**
 * @brief Classify an 802.11 Action category as Robust per IEEE 802.11 Table 9-51.
 *
 * @param cat Action category octet.
 * @return true if the category is a Robust Management Action frame; false otherwise.
 */
static bool sta_is_robust_action(uint8_t cat)
{
    if (cat == IEEE80211_CAT_PUBLIC || cat == IEEE80211_CAT_HT ||
        cat == IEEE80211_CAT_UNPROT_WNM || cat == IEEE80211_CAT_SELF_PROT ||
        cat == IEEE80211_CAT_WMM || cat == IEEE80211_CAT_UNPROT_DMG ||
        cat == IEEE80211_CAT_VHT || cat == IEEE80211_CAT_VENDOR ||
        (cat & IEEE80211_CAT_ERR_BIT) != 0U) {
        return false;
    }
    return true;
}

/**
 * @brief Software-decrypt and replay-check a PMF CCMP-protected unicast management frame.
 *
 * Extracts the 48-bit CCMP PN, rejects replays against `sta_rx_mgmt_pn`,
 * invokes `ccmp_decrypt()` (which builds the IEEE 802.11w management-frame
 * AAD/nonce and validates the 8-byte CCMP MIC in software), and advances
 * `sta_rx_mgmt_pn` only after cryptographic verification succeeds so forged
 * high-PN frames cannot DoS legitimate management traffic.
 *
 * @param frame   Full 802.11 management frame starting at Frame Control.
 * @param len     Total MPDU length in bytes.
 * @param out_len Output decrypted body length in bytes.
 * @return Heap buffer from `os_malloc()` on success (caller must `os_free()`), or NULL on failure.
 */
static uint8_t *sta_decrypt_pmf_mgmt(const uint8_t *frame, uint16_t len, size_t *out_len)
{
    if (g_n8.sta_ptk_key_valid == 0U ||
        g_n8.sta_ptk_cipher != (uint8_t)ESP_LMAC_CIPHER_CCMP ||
        len < (IEEE80211_HDR_LEN + IEEE80211_CCMP_HDR_LEN + IEEE80211_CCMP_MIC_LEN)) {
        return NULL;
    }

    /* Fast-reject stale/replayed PNs before spending CPU on AES-CCMP decryption */
    uint64_t pn = n8_ccmp_iv_to_pn(frame + IEEE80211_HDR_LEN);
    if (g_n8.sta_rx_mgmt_pn_valid != 0U && pn <= g_n8.sta_rx_mgmt_pn) {
        return NULL;
    }

    /* SW CCMP builds IEEE 802.11w mgmt AAD + nonce (priority byte = 0x10) and checks MIC */
    u8 *plain = ccmp_decrypt(g_n8.sta_ptk_key, frame, frame + IEEE80211_HDR_LEN,
                             (size_t)(len - IEEE80211_HDR_LEN), out_len, false);
    if (plain == NULL) {
        return NULL;
    }

    /* Commit RX management PN watermark only after MIC authentication succeeds */
    g_n8.sta_rx_mgmt_pn = pn;
    g_n8.sta_rx_mgmt_pn_valid = 1U;
    return (uint8_t *)plain;
}

/** Transient wrapper pairing an async MGMT payload buffer with a caller TX-done callback. */
typedef struct {
    void                 *buf;
    bool                  use_os_free;
    esp_lmac_tx_done_cb_t cb;
    void                 *ctx;
} n8_sta_mgmt_wrap_t;

/**
 * @brief LMAC TX completion trampoline freeing a STA MGMT buffer before invoking caller callback.
 *
 * Releases `w->buf` via `os_free()` (for `ccmp_encrypt()` buffers) or
 * `heap_caps_free()` (for plain body copies), forwards the LMAC TX status to
 * `w->cb` when non-NULL, and frees the `n8_sta_mgmt_wrap_t` wrapper.
 *
 * @param ctx Heap-allocated `n8_sta_mgmt_wrap_t` wrapper context.
 * @param st  LMAC transmission completion status forwarded to the wrapped callback.
 */
static void sta_mgmt_wrap_tx_cb(void *ctx, const esp_lmac_tx_status_t *st)
{
    n8_sta_mgmt_wrap_t *w = (n8_sta_mgmt_wrap_t *)ctx;
    if (w == NULL) {
        return;
    }
    if (w->buf != NULL) {
        if (w->use_os_free) {
            os_free(w->buf);
        } else {
            heap_caps_free(w->buf);
        }
    }
    if (w->cb != NULL) {
        w->cb(w->ctx, st);
    }
    heap_caps_free(w);
}

/**
 * @brief Transmit a STA 802.11 management frame to the current AP BSSID with optional TX-done callback.
 *
 * When @p protected_mgmt is true and CCMP PTK is active (802.11w PMF),
 * software-encrypts the frame with `ccmp_encrypt()` using an incrementing
 * 48-bit management PN (`sta_tx_mgmt_pn`) and submits to LMAC with
 * `ESP_LMAC_CIPHER_NONE` (inline when `enc_len + FCS <= N8_STA_LMAC_SCRATCH_MAX`,
 * or via a scatter-gather segment freed asynchronously otherwise).
 *
 * @param subtype        Management frame subtype (pre-shifted into FC0 bits [7:4]).
 * @param body           Optional management frame body bytes (may be NULL if @p body_len == 0).
 * @param body_len       Length of @p body in bytes.
 * @param force_lowest   If true, force transmission at the lowest basic rate.
 * @param protected_mgmt If true, set the Protected Frame bit and apply SW CCMP encryption.
 * @param done_cb        Optional completion callback fired after LMAC TX finishes.
 * @param done_ctx       Caller context passed to @p done_cb.
 * @return ESP_OK on LMAC submission, ESP_ERR_INVALID_STATE if PMF PTK is unavailable,
 *         ESP_ERR_NO_MEM on copy/encrypt/wrapper failure, or LMAC error code.
 */
static esp_err_t sta_tx_mgmt_cb(uint8_t subtype, const uint8_t *body, uint16_t body_len,
                                bool force_lowest, bool protected_mgmt,
                                esp_lmac_tx_done_cb_t done_cb, void *done_ctx)
{
    if (protected_mgmt) {
        if (g_n8.sta_pmf_active == 0U || g_n8.sta_ptk_key_valid == 0U ||
            g_n8.sta_ptk_cipher != (uint8_t)ESP_LMAC_CIPHER_CCMP) {
            return ESP_ERR_INVALID_STATE;
        }

        size_t plain_len = (size_t)IEEE80211_HDR_LEN + (size_t)body_len;
        uint8_t *plain = (uint8_t *)os_malloc(plain_len);
        if (plain == NULL) {
            return ESP_ERR_NO_MEM;
        }
        memset(plain, 0, IEEE80211_HDR_LEN);
        plain[0] = (uint8_t)(IEEE80211_FC_TYPE_MGMT | subtype);
        plain[1] = IEEE80211_FC1_PROTECTED;
        memcpy(plain + IEEE80211_HDR_ADDR1_OFF, g_n8.sta_bssid, IEEE80211_ADDR_LEN);
        memcpy(plain + IEEE80211_HDR_ADDR2_OFF, g_n8.sta_mac, IEEE80211_ADDR_LEN);
        memcpy(plain + IEEE80211_HDR_ADDR3_OFF, g_n8.sta_bssid, IEEE80211_ADDR_LEN);
        uint16_t seq = n8_sta_next_seq();
        plain[IEEE80211_HDR_SEQ_OFF] = (uint8_t)(seq & 0xFFU);
        plain[IEEE80211_HDR_SEQ_OFF + 1U] = (uint8_t)(seq >> 8);
        if (body != NULL && body_len > 0U) {
            memcpy(plain + IEEE80211_HDR_LEN, body, body_len);
        }

        /*
         * WDEV hardware CCMP cannot form IEEE 802.11w management AAD/nonce
         * (nonce priority = 0x10); encrypt in software with big-endian 6B PN
         * from the dedicated management PN space and pass raw ciphertext to LMAC.
         */
        uint64_t pn_val = g_n8.sta_tx_mgmt_pn++;
        uint8_t pn_be[IEEE80211_PN_BYTES] = {
            (uint8_t)((pn_val >> 40) & 0xFFU),
            (uint8_t)((pn_val >> 32) & 0xFFU),
            (uint8_t)((pn_val >> 24) & 0xFFU),
            (uint8_t)((pn_val >> 16) & 0xFFU),
            (uint8_t)((pn_val >> 8) & 0xFFU),
            (uint8_t)(pn_val & 0xFFU),
        };
        size_t enc_len = 0U;
        u8 *crypt = ccmp_encrypt(g_n8.sta_ptk_key, plain, plain_len,
                                 IEEE80211_HDR_LEN, pn_be, 0, &enc_len);
        os_free(plain);
        if (crypt == NULL || enc_len <= N8_STA_PROT_HDR_LEN) {
            if (crypt != NULL) {
                os_free(crypt);
            }
            return ESP_ERR_NO_MEM;
        }

        esp_lmac_sg_seg_t seg = {0};
        esp_lmac_tx_req_t tx = {0};
        tx.vif = ESP_LMAC_VIF_STA;
        tx.peer_id = g_n8.sta_peer_id;
        tx.ac = ESP_LMAC_AC_MGMT;
        tx.cipher = ESP_LMAC_CIPHER_NONE; /* SW CCMP already applied */
        tx.flags = force_lowest ? ESP_LMAC_TX_FLAG_FORCE_LOWEST_RATE : 0U;
        tx.hdr = crypt;
        tx.trailer_len = 0U;

        /* Small encrypted frames (e.g. Deauth/SA-Query/ADDBA) copy inline into LMAC scratch */
        if (enc_len + N8_STA_LMAC_FCS_LEN <= N8_STA_LMAC_SCRATCH_MAX) {
            tx.hdr_len = (uint16_t)enc_len;
            tx.done_cb = done_cb;
            tx.done_ctx = done_ctx;
            esp_err_t err = esp_lmac_tx_submit(&tx);
            os_free(crypt);
            return err;
        }

        /* Larger encrypted frames split at 32B (MAC+CCMP hdr) and free crypt on TX done */
        tx.hdr_len = N8_STA_PROT_HDR_LEN;
        seg.ptr = crypt + N8_STA_PROT_HDR_LEN;
        seg.len = (uint16_t)(enc_len - N8_STA_PROT_HDR_LEN);
        tx.segs = &seg;
        tx.seg_cnt = 1U;

        n8_sta_mgmt_wrap_t *wrap = NULL;
        if (done_cb != NULL) {
            wrap = (n8_sta_mgmt_wrap_t *)heap_caps_malloc(sizeof(*wrap), MALLOC_CAP_8BIT);
            if (wrap == NULL) {
                os_free(crypt);
                return ESP_ERR_NO_MEM;
            }
            wrap->buf = crypt;
            wrap->use_os_free = true;
            wrap->cb = done_cb;
            wrap->ctx = done_ctx;
            tx.done_cb = sta_mgmt_wrap_tx_cb;
            tx.done_ctx = wrap;
        } else {
            tx.done_cb = sta_os_free_tx_cb;
            tx.done_ctx = crypt;
        }

        esp_err_t err = esp_lmac_tx_submit(&tx);
        if (err != ESP_OK) {
            os_free(crypt);
            if (wrap != NULL) {
                heap_caps_free(wrap);
            }
        }
        return err;
    }

    uint8_t hdr[IEEE80211_HDR_LEN];
    memset(hdr, 0, sizeof(hdr));
    hdr[0] = (uint8_t)(IEEE80211_FC_TYPE_MGMT | subtype);
    hdr[1] = 0U;
    memcpy(hdr + IEEE80211_HDR_ADDR1_OFF, g_n8.sta_bssid, IEEE80211_ADDR_LEN);
    memcpy(hdr + IEEE80211_HDR_ADDR2_OFF, g_n8.sta_mac, IEEE80211_ADDR_LEN);
    memcpy(hdr + IEEE80211_HDR_ADDR3_OFF, g_n8.sta_bssid, IEEE80211_ADDR_LEN);
    uint16_t seq = n8_sta_next_seq();
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
    tx.vif = ESP_LMAC_VIF_STA;
    tx.peer_id = ESP_LMAC_PEER_INVALID;
    tx.ac = ESP_LMAC_AC_MGMT;
    tx.cipher = ESP_LMAC_CIPHER_NONE;
    tx.flags = force_lowest ? ESP_LMAC_TX_FLAG_FORCE_LOWEST_RATE : 0U;
    tx.hdr = hdr;
    tx.hdr_len = sizeof(hdr);
    tx.segs = (copy != NULL) ? &seg : NULL;
    tx.seg_cnt = (copy != NULL) ? 1U : 0U;
    tx.trailer_len = 0U;

    /* Chain buffer free + caller callback via wrapper when both are present */
    n8_sta_mgmt_wrap_t *wrap = NULL;
    if (done_cb != NULL && copy != NULL) {
        wrap = (n8_sta_mgmt_wrap_t *)heap_caps_malloc(sizeof(*wrap), MALLOC_CAP_8BIT);
        if (wrap == NULL) {
            heap_caps_free(copy);
            return ESP_ERR_NO_MEM;
        }
        wrap->buf = copy;
        wrap->use_os_free = false;
        wrap->cb = done_cb;
        wrap->ctx = done_ctx;
        tx.done_cb = sta_mgmt_wrap_tx_cb;
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
 * @brief Transmit a STA 802.11 management frame without a caller TX-done callback.
 *
 * @param subtype        Management frame subtype (pre-shifted into FC0 bits [7:4]).
 * @param body           Optional management frame body bytes (may be NULL if @p body_len == 0).
 * @param body_len       Length of @p body in bytes.
 * @param force_lowest   If true, force transmission at the lowest basic rate.
 * @param protected_mgmt If true, set the Protected Frame bit and apply SW CCMP encryption.
 * @return ESP_OK on LMAC submission, ESP_ERR_INVALID_STATE, ESP_ERR_NO_MEM, or LMAC error code.
 */
static esp_err_t sta_tx_mgmt(uint8_t subtype, const uint8_t *body, uint16_t body_len,
                             bool force_lowest, bool protected_mgmt)
{
    return sta_tx_mgmt_cb(subtype, body, body_len, force_lowest, protected_mgmt, NULL, NULL);
}

#ifdef CONFIG_WPA_11KV_SUPPORT
/**
 * @brief Transmit an 802.11 Action frame from the STA interface with PMF protection when active.
 *
 * Automatically enables software CCMP encryption when `sta_pmf_active` is set
 * and the Action category octet classifies as Robust per IEEE 802.11 Table 9-51.
 *
 * @param body     Action frame payload starting at Category octet.
 * @param body_len Payload length in bytes (1..`N8_STA_ACTION_TX_MAX_LEN`).
 * @return ESP_OK on submission, ESP_ERR_INVALID_ARG, ESP_ERR_WIFI_NOT_CONNECT, or TX error code.
 */
esp_err_t n8_sta_tx_action(const uint8_t *body, uint16_t body_len)
{
    if (body == NULL || body_len == 0U || body_len > N8_STA_ACTION_TX_MAX_LEN) {
        return ESP_ERR_INVALID_ARG;
    }
    if (g_n8.sta_state < N8_STA_ASSOC) {
        return ESP_ERR_WIFI_NOT_CONNECT;
    }
    bool prot = (g_n8.sta_pmf_active != 0U) && sta_is_robust_action(body[0]);
    return sta_tx_mgmt(IEEE80211_SUBTYPE_ACTION, body, body_len, true, prot);
}
#endif

/**
 * @brief Clear active STA Channel Switch Announcement (CSA) state and resume STA TX.
 */
static void sta_csa_reset(void)
{
    g_n8.sta_csa_active = 0U;
    g_n8.sta_csa_mode = 0U;
    g_n8.sta_csa_new_ch = 0U;
    g_n8.sta_csa_count = 0U;
    g_n8.sta_csa_tx_paused = 0U;
}

/**
 * @brief Validate a CSA target channel against 1..14 and active country regulatory bounds.
 *
 * @param ch Candidate channel number.
 * @return true if channel is valid and permitted; false otherwise.
 */
static bool sta_csa_is_valid_channel(uint8_t ch)
{
    if (ch < N8_CHANNEL_MIN || ch > N8_CHANNEL_MAX) {
        return false;
    }
    const wifi_country_t *cc = n8_get_active_country();
    uint8_t schan = (cc->schan >= N8_CHANNEL_MIN && cc->schan <= N8_CHANNEL_MAX)
                    ? cc->schan : N8_CHANNEL_MIN;
    uint8_t nchan = (cc->nchan >= N8_CHANNEL_MIN && cc->nchan <= N8_CHANNEL_MAX)
                    ? cc->nchan : N8_STA_DEFAULT_NCHAN;
    uint16_t end_ch = (uint16_t)schan + (uint16_t)nchan;
    if (end_ch > (N8_CHANNEL_MAX + 1U)) {
        end_ch = (N8_CHANNEL_MAX + 1U);
    }
    return (ch >= schan) && ((uint16_t)ch < end_ch);
}

/**
 * @brief Execute a validated STA channel switch without dropping association.
 *
 * Updates `sta_channel`/`cur_channel`, persists the RTC fast-connect cache when
 * in `N8_STA_RUN`, tunes PHY when not scanning, restores close-range `rxmax_ext`,
 * resynchronizes SoftAP in APSTA mode, clears CSA quiet pause, and drains the TX queue.
 *
 * @param new_ch Target channel number (1..14).
 */
static void sta_csa_apply_switch(uint8_t new_ch)
{
    sta_csa_reset();
    g_n8.sta_channel = new_ch;
    g_n8.sta_bcn_miss_ticks = 0U;

    if (g_n8.sta_state == N8_STA_RUN) {
        n8_rtc_cache_save(g_n8.sta_channel, g_n8.sta_bssid, g_n8.sta_authmode);
    }

    if (!g_n8.scan_active) {
        (void)esp_lmac_set_channel(new_ch);
        g_n8.cur_channel = new_ch;
        if (g_n8.sta_rxmax_ext_state != 0U) {
            esp_lmac_set_rxmax_ext(g_n8.sta_rxmax_ext_state);
        }
    }

    if (g_n8.ap_running && g_n8.ap_cfg.ap.channel != new_ch) {
        n8_ap_sync_channel(new_ch);
    }

    n8_data_process_tx_queue();
}

/**
 * @brief Transmit a PMF-protected 802.11w SA-Query Request or Response frame.
 *
 * @param action IEEE80211_SA_QUERY_REQ or IEEE80211_SA_QUERY_RESP.
 * @param tid    2-byte Transaction Identifier.
 */
static void sta_send_sa_query(uint8_t action, const uint8_t tid[2])
{
    uint8_t body[N8_STA_SA_QUERY_BODY_LEN] = { IEEE80211_CAT_SA_QUERY, action, tid[0], tid[1] };
    (void)sta_tx_mgmt(IEEE80211_SUBTYPE_ACTION, body, sizeof(body), false,
                      (g_n8.sta_pmf_active != 0U));
}

/**
 * @brief Initiate STA-side 802.11w SA-Query procedure upon unprotected Deauth/Disassoc.
 *
 * Generates a fresh 16-bit random Transaction Identifier, arms the SA-Query
 * watchdog in `n8_sta_on_tick_100ms()`, and transmits the initial protected
 * SA-Query Request. No-op if an SA-Query is already in progress.
 */
static void sta_start_sa_query(void)
{
    if (g_n8.sa_query_active != 0U) {
        return;
    }
    uint32_t rnd = esp_random();
    g_n8.sa_query_tid[0] = (uint8_t)(rnd & 0xFFU);
    g_n8.sa_query_tid[1] = (uint8_t)((rnd >> 8) & 0xFFU);
    g_n8.sa_query_active = 1U;
    g_n8.sa_query_ticks = 0U;
    sta_send_sa_query(IEEE80211_SA_QUERY_REQ, g_n8.sa_query_tid);
}

/**
 * @brief Send an 802.11 Deauthentication frame to the associated AP.
 *
 * Encrypts the frame via software CCMP when the STA is in `N8_STA_RUN` with PMF active.
 *
 * @param reason 802.11 reason code written into the 2-byte deauth body.
 */
static void sta_send_deauth(uint8_t reason)
{
    uint8_t body[N8_STA_DEAUTH_BODY_LEN] = { reason, 0U };
    bool prot = (g_n8.sta_state == N8_STA_RUN) && (g_n8.sta_pmf_active != 0U) &&
                (g_n8.sta_ptk_key_valid != 0U) &&
                (g_n8.sta_ptk_cipher == (uint8_t)ESP_LMAC_CIPHER_CCMP);
    (void)sta_tx_mgmt(IEEE80211_SUBTYPE_DEAUTH, body, sizeof(body), true, prot);
}

/**
 * @brief Transmit an Open-System Authentication Request (sequence 1) to the target AP.
 */
static void sta_send_auth_open(void)
{
    uint8_t body[N8_STA_AUTH_FIXED_LEN] = {
        IEEE80211_AUTH_ALG_OPEN, 0U,
        N8_STA_AUTH_SEQ_REQ, 0U,     /* seq 1 */
        WLAN_STATUS_SUCCESS_CODE, 0U /* status 0 */
    };
    (void)sta_tx_mgmt(IEEE80211_SUBTYPE_AUTH, body, sizeof(body), true, false);
}

/**
 * @brief Build and transmit a WPA3-SAE Authentication frame (Commit or Confirm).
 *
 * Queries `wpa_supplicant` via `wpa3_build_sae_msg` to generate the finite-field
 * SAE element payload and wraps it in an 802.11 Auth body with algorithm SAE (3).
 *
 * @param sae_type `SAE_MSG_COMMIT_TYPE` (1) or `SAE_MSG_CONFIRM_TYPE` (2).
 * @return true if the SAE frame was built and submitted to LMAC, false otherwise.
 */
static bool sta_send_auth_sae(uint8_t sae_type)
{
#ifdef CONFIG_ESP8266_WIFI_ENABLE_WPA3_SAE
    if (g_n8.wpa_cb == NULL || g_n8.wpa_cb->wpa3_build_sae_msg == NULL) {
        return false;
    }
    size_t sae_len = 0U;
    uint8_t *sae_msg = g_n8.wpa_cb->wpa3_build_sae_msg(g_n8.sta_bssid, sae_type, &sae_len);
    if (sae_msg == NULL || sae_len == 0U || sae_len > N8_STA_SAE_MAX_MSG_LEN) {
        return false;
    }

    uint16_t body_len = (uint16_t)(N8_STA_AUTH_FIXED_LEN + sae_len);
    uint8_t *body = (uint8_t *)heap_caps_malloc(body_len, MALLOC_CAP_8BIT);
    if (body == NULL) {
        return false;
    }
    body[0] = IEEE80211_AUTH_ALG_SAE;
    body[1] = 0U;
    body[2] = sae_type; /* 1=Commit, 2=Confirm */
    body[3] = 0U;
    body[4] = 0U;
    body[5] = 0U;
    memcpy(body + N8_STA_AUTH_FIXED_LEN, sae_msg, sae_len);

    esp_err_t err = sta_tx_mgmt(IEEE80211_SUBTYPE_AUTH, body, body_len, true, false);
    heap_caps_free(body);
    return (err == ESP_OK);
#else
    (void)sae_type;
    return false;
#endif
}

/**
 * @brief Build and transmit an 802.11 Association Request to the target AP.
 *
 * Includes Capability Info (with optional Radio Measurement bit when 802.11k RM
 * is enabled), Listen Interval, SSID, Supported/Extended Rates, HT20
 * Capabilities (when both STA and AP support 802.11n), either the WPS AssocReq
 * IE (suppressing RSN/WPA during WPS enrollment) or the supplicant's RSN/WPA
 * IE, optional WMM Information IE, optional 802.11k RRM Enabled Capabilities
 * IE (`CONFIG_WPA_11KV_SUPPORT`), and any user-configured AssocReq vendor IEs.
 */
static void sta_send_assoc_req(void)
{
    uint8_t body[N8_STA_ASSOC_REQ_BUF_LEN];
    uint16_t off = 0U;

    uint16_t cap = (uint16_t)(IEEE80211_CAPINFO_ESS | IEEE80211_CAPINFO_SHORT_SLOT);
    if (g_n8.sta_authmode != WIFI_AUTH_OPEN) {
        cap |= IEEE80211_CAPINFO_PRIVACY;
    }
    if ((g_n8.sta_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE) != 0U) {
        cap |= IEEE80211_CAPINFO_SHORT_PREAMBLE;
    }
#ifdef CONFIG_WPA_11KV_SUPPORT
    uint16_t rm_len = 0U;
    const uint8_t *rm_ie = NULL;
    if (esp_wifi_is_rm_enabled_internal(WIFI_IF_STA)) {
        rm_ie = n8_supp_get_ie_bytes(WIFI_APPIE_RM_ENABLED_CAPS, &rm_len);
        if (rm_ie != NULL && rm_len == IEEE80211_RM_CAPS_LEN) {
            cap |= IEEE80211_CAP_RADIO_MEASUREMENT;
        }
    }
#endif

    body[off++] = (uint8_t)(cap & 0xFFU);
    body[off++] = (uint8_t)(cap >> 8);
    uint16_t listen_int = g_n8.sta_cfg.sta.listen_interval
                          ? g_n8.sta_cfg.sta.listen_interval : N8_STA_DEFAULT_LISTEN_INT;
    body[off++] = (uint8_t)(listen_int & 0xFFU);
    body[off++] = (uint8_t)(listen_int >> 8);

    /* SSID IE */
    body[off++] = IEEE80211_IE_SSID;
    body[off++] = g_n8.sta_ssid_len;
    memcpy(body + off, g_n8.sta_ssid, g_n8.sta_ssid_len);
    off = (uint16_t)(off + g_n8.sta_ssid_len);

    /* Supported & Extended Rates */
    memcpy(body + off, s_sta_rates_ie, sizeof(s_sta_rates_ie));
    off = (uint16_t)(off + sizeof(s_sta_rates_ie));

    /* HT20 Capabilities IE when 11n is enabled on STA and AP supports HT */
    if (g_n8.sta_ht_active && (g_n8.proto[WIFI_IF_STA] & WIFI_PROTOCOL_11N) != 0U) {
        memcpy(body + off, s_ht20_cap_ie, sizeof(s_ht20_cap_ie));
        off = (uint16_t)(off + sizeof(s_ht20_cap_ie));
    }

    /* WPS AssocReq IE (suppresses RSN/WPA IE during WPS enrollment) or RSN/WPA IE */
    if (n8_wps_is_pending()) {
        uint16_t wps_len = 0U;
        const uint8_t *wps_ie = n8_supp_get_ie_bytes(WIFI_APPIE_WPS_AR, &wps_len);
        if (wps_ie != NULL && wps_len > 0U && (uint16_t)(off + wps_len) <= sizeof(body)) {
            memcpy(body + off, wps_ie, wps_len);
            off = (uint16_t)(off + wps_len);
        }
    } else if (g_n8.sta_authmode != WIFI_AUTH_OPEN && g_n8.sta_authmode != WIFI_AUTH_WEP) {
        uint8_t ie_type = (g_n8.sta_wpa_proto == N8_WPA_PROTO_WPA)
                          ? WIFI_APPIE_WPA : WIFI_APPIE_RSN;
        uint16_t sec_len = 0U;
        const uint8_t *sec_ie = n8_supp_get_ie_bytes(ie_type, &sec_len);
        if (sec_ie != NULL && sec_len > 0U && (uint16_t)(off + sec_len) <= sizeof(body)) {
            memcpy(body + off, sec_ie, sec_len);
            off = (uint16_t)(off + sec_len);
        }
    }

    /* WMM Information IE when QoS/WMM is active on this association */
    if (g_n8.sta_qos_active != 0U &&
        (uint16_t)(off + sizeof(s_sta_wmm_info_ie)) <= sizeof(body)) {
        memcpy(body + off, s_sta_wmm_info_ie, sizeof(s_sta_wmm_info_ie));
        off = (uint16_t)(off + sizeof(s_sta_wmm_info_ie));
    }

#ifdef CONFIG_WPA_11KV_SUPPORT
    /* 802.11k RRM Enabled Capabilities IE (WIFI_APPIE_RM_ENABLED_CAPS holds 5-byte body) */
    if (rm_ie != NULL && rm_len == IEEE80211_RM_CAPS_LEN &&
        (uint16_t)(off + IEEE80211_IE_HDR_LEN + rm_len) <= sizeof(body)) {
        body[off++] = IEEE80211_IE_RM_ENABLED_CAP;
        body[off++] = (uint8_t)rm_len;
        memcpy(body + off, rm_ie, rm_len);
        off = (uint16_t)(off + rm_len);
    }
#endif

    /* User-configured AssocReq vendor IEs */
    off = n8_append_vendor_ies(WIFI_VND_IE_TYPE_ASSOC_REQ, body, off, sizeof(body));

    (void)sta_tx_mgmt(IEEE80211_SUBTYPE_ASSOC_REQ, body, off, true, false);
}

/* --------------------------------------------------------------------------
 * STA Lifecycle & Connect / Disconnect
 * -------------------------------------------------------------------------- */

/**
 * @brief Enable the STA VIF, initialize wpa_supplicant STA state, and post `STA_START`.
 *
 * @return ESP_OK on success, or an LMAC error code if VIF activation fails.
 */
esp_err_t n8_sta_start(void)
{
    esp_err_t err = esp_lmac_vif_enable(ESP_LMAC_VIF_STA, g_n8.sta_mac);
    if (err != ESP_OK) {
        return err;
    }
    esp_lmac_set_protocol_mask(ESP_LMAC_VIF_STA, g_n8.proto[WIFI_IF_STA]);

    if (g_n8.wpa_cb != NULL && g_n8.wpa_cb->wpa_sta_init != NULL) {
        (void)g_n8.wpa_cb->wpa_sta_init();
    }

    g_n8.sta_state = N8_STA_IDLE;
    g_n8.sta_peer_id = ESP_LMAC_PEER_INVALID;

    system_event_t evt;
    memset(&evt, 0, sizeof(evt));
    evt.event_id = SYSTEM_EVENT_STA_START;
    n8_send_system_event(&evt);

    return ESP_OK;
}

/**
 * @brief Stop any active scan/connection, deinitialize WPA/WPA2-Enterprise STA state, and disable STA VIF.
 *
 * Also clears 802.11k/11v management frame registration masks when
 * `CONFIG_WPA_11KV_SUPPORT` is enabled and posts `SYSTEM_EVENT_STA_STOP`.
 */
void n8_sta_stop(void)
{
    if (g_n8.scan_active) {
        n8_scan_stop_internal(false);
    }
    if (g_n8.sta_state != N8_STA_IDLE) {
        n8_sta_disconnect(WIFI_REASON_ASSOC_LEAVE, (g_n8.sta_state >= N8_STA_ASSOC), true);
    }
    if (g_n8.wpa2_cb != NULL && g_n8.wpa2_cb->wpa2_deinit != NULL) {
        g_n8.wpa2_cb->wpa2_deinit();
    }
    if (g_n8.wpa_cb != NULL && g_n8.wpa_cb->wpa_sta_deinit != NULL) {
        (void)g_n8.wpa_cb->wpa_sta_deinit();
    }
#ifdef CONFIG_WPA_11KV_SUPPORT
    g_n8.frame_reg_type = 0U;
    g_n8.frame_reg_subtype = 0U;
#endif
    esp_lmac_vif_disable(ESP_LMAC_VIF_STA);

    system_event_t evt;
    memset(&evt, 0, sizeof(evt));
    evt.event_id = SYSTEM_EVENT_STA_STOP;
    n8_send_system_event(&evt);
}

/**
 * @brief Initiate a STA connection using a two-pass fast-connect scan strategy.
 *
 * Pass 0 (`N8_STA_SCAN_PASS_CACHED`) probes only the user-configured channel or
 * the RTC-cached last-known AP channel to shave >1 s off reconnect latency. If
 * no hint channel exists (or pass 0 misses in `n8_sta_on_scan_done`), pass 1
 * (`N8_STA_SCAN_PASS_FULL`) performs a full regulatory channel sweep.
 *
 * @return ESP_OK when the connect scan starts, or an ESP_ERR_WIFI_* error code.
 */
esp_err_t n8_sta_connect(void)
{
    if (!g_n8.started) {
        return ESP_ERR_WIFI_NOT_STARTED;
    }
    if (g_n8.mode != WIFI_MODE_STA && g_n8.mode != WIFI_MODE_APSTA) {
        return ESP_ERR_WIFI_MODE;
    }
    if (g_n8.sta_cfg.sta.ssid[0] == '\0') {
        return ESP_ERR_WIFI_SSID;
    }

    if (g_n8.sta_state != N8_STA_IDLE) {
        n8_sta_disconnect(WIFI_REASON_ASSOC_LEAVE, (g_n8.sta_state >= N8_STA_ASSOC), false);
    }

    g_n8.sta_connect_req = 1U;
    g_n8.sta_state = N8_STA_SCANNING;

    /* Fast-connect optimization: probe configured channel or RTC_SYS cached channel first! */
    uint8_t hint_ch = g_n8.sta_cfg.sta.channel;
    if (hint_ch == 0U && g_n8.rtc_cache_valid &&
        g_n8.rtc_cached_ch >= N8_CHANNEL_MIN && g_n8.rtc_cached_ch <= N8_CHANNEL_MAX) {
        hint_ch = g_n8.rtc_cached_ch;
    }

    if (hint_ch >= N8_CHANNEL_MIN && hint_ch <= N8_CHANNEL_MAX) {
        g_n8.sta_scan_connect_pass = N8_STA_SCAN_PASS_CACHED;
        return n8_scan_start_internal(NULL, true, hint_ch);
    }

    g_n8.sta_scan_connect_pass = N8_STA_SCAN_PASS_FULL;
    return n8_scan_start_internal(NULL, true, 0U);
}

/**
 * @brief Tear down the current STA session, flush LMAC state, and reset MLME to `N8_STA_IDLE`.
 *
 * Wakes modem sleep, aborts any connect scan, optionally transmits a Deauth
 * frame (PMF-encrypted when in `N8_STA_RUN` with CCMP PTK), flushes pending
 * STA TX buffers, clears keys, BSSID filtering, and RX defragmentation buffers,
 * tears down all RX Block-Ack sessions and the LMAC peer slot, notifies
 * `wpa_supplicant` (and deinitializes WPA2-Enterprise if active), zeroes PMF
 * keys/PNs/replay windows, SA-Query, CSA, ERP protection, TSF offset, and
 * close-range `rxmax_ext`, re-applies regulatory TX power limits, and posts
 * `SYSTEM_EVENT_STA_DISCONNECTED`.
 *
 * @param reason       802.11 or `wifi_err_reason_t` disconnect reason code.
 * @param send_deauth  If true and STA has reached at least `N8_STA_AUTH`, send a Deauth frame.
 * @param notify_event If true and STA was not already `N8_STA_IDLE`, post `STA_DISCONNECTED`.
 */
void n8_sta_disconnect(uint8_t reason, bool send_deauth, bool notify_event)
{
    n8_pm_on_disconnect();

    if (g_n8.scan_active && g_n8.scan_for_connect) {
        g_n8.scan_for_connect = 0U;
        n8_scan_stop_internal(false);
    }

    bool was_active = (g_n8.sta_state != N8_STA_IDLE);
    if (send_deauth && g_n8.sta_state >= N8_STA_AUTH) {
        sta_send_deauth(reason);
    }

    esp_lmac_tx_flush_vif(ESP_LMAC_VIF_STA);
    esp_lmac_key_clear_vif(ESP_LMAC_VIF_STA);
    esp_lmac_set_bssid_filter(ESP_LMAC_VIF_STA, NULL, false);
    n8_defrag_purge_vif(ESP_LMAC_VIF_STA);

    if (g_n8.sta_peer_id != ESP_LMAC_PEER_INVALID) {
        for (uint8_t tid = 0U; tid < N8_MAX_TID; tid++) {
            esp_lmac_del_rx_ba(g_n8.sta_peer_id, tid);
        }
        esp_lmac_peer_remove(g_n8.sta_peer_id);
        g_n8.sta_peer_id = ESP_LMAC_PEER_INVALID;
    }

    if (g_n8.sta_supp_authmode == WPA2_AUTH_ENT &&
        g_n8.wpa2_cb != NULL && g_n8.wpa2_cb->wpa2_deinit != NULL) {
        g_n8.wpa2_cb->wpa2_deinit();
    }
    if (g_n8.wpa_cb != NULL && g_n8.wpa_cb->wpa_sta_disconnected_cb != NULL) {
        g_n8.wpa_cb->wpa_sta_disconnected_cb(reason);
    }

    uint8_t old_ssid[N8_MAX_SSID_LEN];
    uint8_t old_ssid_len = g_n8.sta_ssid_len;
    uint8_t old_bssid[IEEE80211_ADDR_LEN];
    memcpy(old_ssid, g_n8.sta_ssid, N8_MAX_SSID_LEN);
    memcpy(old_bssid, g_n8.sta_bssid, IEEE80211_ADDR_LEN);

    g_n8.sta_state = N8_STA_IDLE;
    g_n8.sta_connect_req = 0U;
    g_n8.sta_conn_timer_disarmed = 0U;
    g_n8.sta_supp_authmode = NONE_AUTH;
    g_n8.sta_wpa_proto = 0U;
    g_n8.sta_ptk_cipher = (uint8_t)ESP_LMAC_CIPHER_NONE;
    g_n8.sta_gtk_cipher = (uint8_t)ESP_LMAC_CIPHER_NONE;
    memset(g_n8.sta_ptk_key, 0, sizeof(g_n8.sta_ptk_key));
    g_n8.sta_ptk_key_valid = 0U;
    g_n8.sta_tx_mgmt_pn = 0ULL;
    g_n8.sta_rx_mgmt_pn = 0ULL;
    g_n8.sta_rx_mgmt_pn_valid = 0U;
    g_n8.sta_rx_bip_ipn = 0ULL;
    g_n8.sta_rx_bip_ipn_valid = 0U;
    g_n8.sta_last_rx_seq_valid = 0U;
    memset(g_n8.sta_rx_ptk_pn, 0, sizeof(g_n8.sta_rx_ptk_pn));
    memset(g_n8.sta_rx_gtk_pn, 0, sizeof(g_n8.sta_rx_gtk_pn));
    g_n8.sa_query_active = 0U;
    g_n8.sa_query_ticks = 0U;
    memset(g_n8.sa_query_tid, 0, sizeof(g_n8.sa_query_tid));
    g_n8.sta_igtk_valid = 0U;
    g_n8.sta_pmf_active = 0U;
    g_n8.sta_ht_active = 0U;
    g_n8.sta_qos_active = 0U;
    g_n8.sta_beacon_authmode = 0U;
    g_n8.sta_ap_wps = 0U;
    g_n8.sta_ap_phy_11b = 0U;
    g_n8.sta_ap_phy_11g = 0U;
    g_n8.sta_last_freq_offset = 0;
    g_n8.sta_tsf_diff_us = 0;
    g_n8.sta_tsf_valid = 0U;
    g_n8.sta_rxmax_ext_state = 0U;
    esp_lmac_set_rxmax_ext(0U);
    g_n8.sta_aid = 0U;
    g_n8.sta_state_ticks = 0U;
    g_n8.sta_bcn_miss_ticks = 0U;
    sta_csa_reset();
    g_n8.sta_erp_prot = 0U;
    g_n8.sta_tx_retry_burst = 0U;
    bool had_ap_country = (g_n8.sta_ap_country_valid != 0U);
    g_n8.sta_ap_country_valid = 0U;
    memset(&g_n8.sta_ap_country, 0, sizeof(g_n8.sta_ap_country));
    if (was_active) {
        if (had_ap_country && g_n8.country.policy == WIFI_COUNTRY_POLICY_AUTO) {
            n8_sync_country_power();
        } else {
            n8_apply_tx_power_limit();
        }
    }

    if (notify_event && was_active) {
        ESP_LOGD(TAG, "STA disconnected: reason=%u", (unsigned)reason);
        system_event_t evt;
        memset(&evt, 0, sizeof(evt));
        evt.event_id = SYSTEM_EVENT_STA_DISCONNECTED;
        memcpy(evt.event_info.disconnected.ssid, old_ssid, old_ssid_len);
        evt.event_info.disconnected.ssid_len = old_ssid_len;
        memcpy(evt.event_info.disconnected.bssid, old_bssid, IEEE80211_ADDR_LEN);
        evt.event_info.disconnected.reason = reason;
        n8_send_system_event(&evt);
    }
}

/* --------------------------------------------------------------------------
 * Post-Scan Candidate Selection & Auth/Assoc Launch
 * -------------------------------------------------------------------------- */

/**
 * @brief Configure negotiated link parameters for a chosen AP and transmit the initial Auth frame.
 *
 * Captures AP PHY/WMM/SGI20/WPS/Country/frequency-offset metadata, selects
 * cipher suite, AKM (Open, WPS-pending, WPA2-Enterprise, WPA3-SAE gated by
 * `wpa3_sae_enable`, RSN/WPA2-PSK, or WPA1-PSK), and PMF activation from the
 * scan entry; tunes the radio (and synchronizes SoftAP in APSTA mode);
 * registers the AP peer in LMAC TRC and seeds close-range `rxmax_ext`; primes
 * `wpa_supplicant` (and `wpa2_init()` for WPA2-Enterprise) before AssocReq;
 * and transmits either WPA3-SAE Commit or Open-System Auth (seq 1).
 *
 * @param ap Selected scan result entry describing the target AP.
 */
static void sta_begin_auth(const n8_scan_entry_t *ap)
{
    memcpy(g_n8.sta_bssid, ap->rec.bssid, IEEE80211_ADDR_LEN);
    size_t slen = strnlen((const char *)ap->rec.ssid, N8_MAX_SSID_LEN);
    memcpy(g_n8.sta_ssid, ap->rec.ssid, slen);
    g_n8.sta_ssid[slen] = '\0';
    g_n8.sta_ssid_len = (uint8_t)slen;
    g_n8.sta_channel = ap->rec.primary;
    g_n8.sta_capinfo = ap->capinfo;
    g_n8.sta_beacon_int = (ap->beacon_int >= N8_STA_MIN_BEACON_INT_TU)
                          ? ap->beacon_int : N8_STA_DEFAULT_BEACON_INT_TU;
    g_n8.sta_dtim_period = N8_STA_DEFAULT_DTIM_PERIOD;
    g_n8.sta_authmode = (uint8_t)ap->rec.authmode;
    g_n8.sta_beacon_authmode = (uint8_t)ap->rec.authmode;
    g_n8.sta_ap_wps = ap->rec.wps;
    g_n8.sta_ap_phy_11b = ap->rec.phy_11b;
    g_n8.sta_ap_phy_11g = ap->rec.phy_11g;
    g_n8.sta_last_freq_offset = ap->rec.freq_offset;
    g_n8.sta_tsf_diff_us = 0;
    g_n8.sta_tsf_valid = 0U;
    sta_csa_reset();
    g_n8.sta_erp_prot = 0U;
    g_n8.sta_tx_retry_burst = 0U;
    g_n8.sta_ht_active = ap->ht_cap && ((g_n8.proto[WIFI_IF_STA] & WIFI_PROTOCOL_11N) != 0U);
    g_n8.sta_qos_active = (n8_qos_cfg_enabled() && (ap->wmm_cap || g_n8.sta_ht_active)) ? 1U : 0U;

    /* Adopt AP Country IE if present in scan entry (for WIFI_COUNTRY_POLICY_AUTO) */
    g_n8.sta_ap_country_valid = 0U;
    memset(&g_n8.sta_ap_country, 0, sizeof(g_n8.sta_ap_country));
    if (ap->rec.country.schan >= N8_CHANNEL_MIN && ap->rec.country.nchan >= 1U &&
        (uint16_t)ap->rec.country.schan + (uint16_t)ap->rec.country.nchan <= (N8_CHANNEL_MAX + 1U)) {
        g_n8.sta_ap_country = ap->rec.country;
        g_n8.sta_ap_country.policy = WIFI_COUNTRY_POLICY_AUTO;
        g_n8.sta_ap_country_valid = 1U;
    }

    /* Select negotiated WPA/WPA2/WPA3 parameters & PMF */
    g_n8.sta_pairwise_cipher = (uint8_t)ap->rec.pairwise_cipher;
    if (g_n8.sta_pairwise_cipher == WIFI_CIPHER_TYPE_TKIP_CCMP) {
        g_n8.sta_pairwise_cipher = WIFI_CIPHER_TYPE_CCMP;
    }
    g_n8.sta_group_cipher = (uint8_t)ap->rec.group_cipher;
    g_n8.sta_mgmt_cipher = ap->mgmt_cipher ? ap->mgmt_cipher : (uint8_t)WIFI_CIPHER_TYPE_AES_CMAC128;

    bool sae_allowed = false;
#ifdef CONFIG_ESP8266_WIFI_ENABLE_WPA3_SAE
    sae_allowed = (g_n8.init_cfg.wpa3_sae_enable != 0U);
#endif
    bool use_sae = false;
    if (sae_allowed && ap->akm_sae &&
        (g_n8.sta_cfg.sta.pmf_cfg.capable || g_n8.sta_cfg.sta.pmf_cfg.required ||
         ap->rec.authmode == WIFI_AUTH_WPA3_PSK)) {
        use_sae = true;
    }

    bool wps_pending = n8_wps_is_pending();
    g_n8.sta_conn_timer_disarmed = 0U;

    if (wps_pending || ap->rec.authmode == WIFI_AUTH_OPEN) {
        g_n8.sta_wpa_proto = 0U;
        g_n8.sta_supp_authmode = NONE_AUTH;
        g_n8.sta_pmf_active = 0U;
    } else if (ap->rec.authmode == WIFI_AUTH_WPA2_ENTERPRISE && g_n8.wpa2_cb != NULL) {
        g_n8.sta_wpa_proto = N8_WPA_PROTO_RSN;
        bool pmf_on = (ap->pmf_capable != 0U &&
                       (g_n8.sta_cfg.sta.pmf_cfg.capable || g_n8.sta_cfg.sta.pmf_cfg.required)) ||
                      (ap->pmf_required != 0U);
        g_n8.sta_pmf_active = pmf_on ? 1U : 0U;
        g_n8.sta_supp_authmode = WPA2_AUTH_ENT;
        /* Skip redundant 400 ms empty-password pbkdf2_sha1() in wpa_set_passphrase() */
        g_n8.sta_reset_param = 0U;
    } else if (use_sae) {
        g_n8.sta_wpa_proto = N8_WPA_PROTO_RSN;
        g_n8.sta_supp_authmode = WPA3_AUTH_PSK;
        g_n8.sta_pmf_active = 1U;
        g_n8.sta_authmode = WIFI_AUTH_WPA3_PSK;
    } else if ((ap->wpa_proto & N8_WPA_PROTO_RSN) != 0U) {
        g_n8.sta_wpa_proto = N8_WPA_PROTO_RSN;
        bool pmf_on = (ap->pmf_capable != 0U &&
                       (g_n8.sta_cfg.sta.pmf_cfg.capable || g_n8.sta_cfg.sta.pmf_cfg.required)) ||
                      (ap->pmf_required != 0U) ||
                      (ap->rec.authmode == WIFI_AUTH_WPA3_PSK);
        g_n8.sta_pmf_active = pmf_on ? 1U : 0U;
        g_n8.sta_supp_authmode = (pmf_on && ap->akm_psk_sha256) ? WPA2_AUTH_PSK_SHA256 : WPA2_AUTH_PSK;
    } else if ((ap->wpa_proto & N8_WPA_PROTO_WPA) != 0U) {
        g_n8.sta_wpa_proto = N8_WPA_PROTO_WPA;
        g_n8.sta_supp_authmode = WPA_AUTH_PSK;
        g_n8.sta_pmf_active = 0U;
    } else {
        g_n8.sta_wpa_proto = 0U;
        g_n8.sta_supp_authmode = NONE_AUTH;
        g_n8.sta_pmf_active = 0U;
    }

    /* Tune to AP channel & sync SoftAP channel in APSTA mode */
    (void)esp_lmac_set_channel(g_n8.sta_channel);
    g_n8.cur_channel = g_n8.sta_channel;
    if (g_n8.ap_running && g_n8.ap_cfg.ap.channel != g_n8.sta_channel) {
        n8_ap_sync_channel(g_n8.sta_channel);
    }

    esp_lmac_set_bssid_filter(ESP_LMAC_VIF_STA, g_n8.sta_bssid, true);

    /* Register AP peer in LMAC TRC */
    esp_lmac_peer_caps_t pcaps = {0};
    memcpy(pcaps.mac, g_n8.sta_bssid, IEEE80211_ADDR_LEN);
    pcaps.rate_mask_11bg = ap->rate_mask_11bg ? ap->rate_mask_11bg : N8_STA_RATE_MASK_11BG_ALL;
    pcaps.ht20_mcs_mask = g_n8.sta_ht_active ? (ap->ht_mcs_mask ? ap->ht_mcs_mask : N8_STA_HT20_MCS0_7_MASK) : 0U;
    pcaps.short_preamble = (ap->capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE) ? 1U : 0U;
    pcaps.short_gi_20 = (g_n8.sta_ht_active && ap->ht_sgi20 != 0U) ? 1U : 0U;
    pcaps.qos_enabled = g_n8.sta_qos_active ? 1U : 0U;
    pcaps.ht_enabled = g_n8.sta_ht_active ? 1U : 0U;
    g_n8.sta_peer_id = esp_lmac_peer_add(ESP_LMAC_VIF_STA, &pcaps);
    esp_lmac_peer_update_rssi(g_n8.sta_peer_id, ap->rec.rssi);
    g_n8.sta_rxmax_ext_state = (ap->rec.rssi > N8_STA_RXMAX_HI_RSSI) ? N8_STA_RXMAX_EXT_LVL : 0U;
    esp_lmac_set_rxmax_ext(g_n8.sta_rxmax_ext_state);

    /* Configure wpa_supplicant BEFORE AssocReq so RSN/WPA IE is generated */
    if (g_n8.sta_wpa_proto != 0U && g_n8.wpa_cb != NULL && g_n8.wpa_cb->wpa_sta_connect != NULL) {
        g_n8.wpa_cb->wpa_sta_connect(g_n8.sta_bssid);
    }

    /* Initialize WPA2-Enterprise EAP peer SM before associating */
    if (g_n8.sta_supp_authmode == WPA2_AUTH_ENT &&
        g_n8.wpa2_cb != NULL && g_n8.wpa2_cb->wpa2_init != NULL) {
        if (g_n8.wpa2_cb->wpa2_init() != ESP_OK) {
            ESP_LOGW(TAG, "WPA2-Enterprise EAP SM init failed");
            n8_sta_disconnect(WIFI_REASON_UNSPECIFIED, false, true);
            return;
        }
    }

    g_n8.sta_state = N8_STA_AUTH;
    g_n8.sta_state_ticks = 0U;
    g_n8.sta_auth_retries = 0U;
    g_n8.sta_sae_seq = SAE_MSG_COMMIT_TYPE;

    ESP_LOGD(TAG, "Joining '%s' ch=%u rssi=%d auth=%u pmf=%u ht=%u",
             (const char *)g_n8.sta_ssid, (unsigned)g_n8.sta_channel, (int)ap->rec.rssi,
             (unsigned)g_n8.sta_authmode, (unsigned)g_n8.sta_pmf_active, (unsigned)g_n8.sta_ht_active);

    if (g_n8.sta_supp_authmode == WPA3_AUTH_PSK) {
        if (!sta_send_auth_sae(SAE_MSG_COMMIT_TYPE)) {
            /* Cached PMKSA skip or SAE error -> fall back to Open Auth */
            sta_send_auth_open();
        }
    } else {
        sta_send_auth_open();
    }
}

/**
 * @brief Handle completion of a STA connect scan and launch authentication or fallback sweep.
 *
 * If the fast cached-channel probe (`N8_STA_SCAN_PASS_CACHED`) finds no matching
 * AP, falls back to a full channel sweep (`N8_STA_SCAN_PASS_FULL`). If still not
 * found, disconnects with `WIFI_REASON_NO_AP_FOUND`.
 */
void n8_sta_on_scan_done(void)
{
    if (g_n8.sta_state != N8_STA_SCANNING) {
        return;
    }

    n8_scan_entry_t *best = n8_scan_pick_best_ap();
    if (best == NULL) {
        if (g_n8.sta_scan_connect_pass == N8_STA_SCAN_PASS_CACHED) {
            /* Cached/hint channel missed -> fall back to full channel sweep */
            g_n8.sta_scan_connect_pass = N8_STA_SCAN_PASS_FULL;
            if (n8_scan_start_internal(NULL, true, 0U) == ESP_OK) {
                return;
            }
        }
        /* Report NO_AP_FOUND */
        size_t slen = strnlen((const char *)g_n8.sta_cfg.sta.ssid, N8_MAX_SSID_LEN);
        memcpy(g_n8.sta_ssid, g_n8.sta_cfg.sta.ssid, slen);
        g_n8.sta_ssid_len = (uint8_t)slen;
        memset(g_n8.sta_bssid, 0, IEEE80211_ADDR_LEN);
        n8_sta_disconnect(WIFI_REASON_NO_AP_FOUND, false, true);
        return;
    }

    n8_scan_entry_t chosen = *best;
    n8_scan_free_results();
    sta_begin_auth(&chosen);
}

/**
 * @brief Transition STA to `N8_STA_RUN` after Open Assoc or 4-Way Handshake completion.
 *
 * Persists the channel/BSSID/PMK fast-connect cache in RTC_SYS memory, applies
 * regulatory TX power limits (syncing SoftAP beacon Country IE if AP country
 * was adopted under `WIFI_COUNTRY_POLICY_AUTO`), enables station power
 * management, and posts `SYSTEM_EVENT_STA_CONNECTED`.
 */
void n8_sta_on_auth_done(void)
{
    if (g_n8.sta_state != N8_STA_4WAY && g_n8.sta_state != N8_STA_ASSOC) {
        return;
    }

    g_n8.sta_state = N8_STA_RUN;
    g_n8.sta_state_ticks = 0U;
    g_n8.sta_bcn_miss_ticks = 0U;

    /* Persist fast-connect PMK + channel + BSSID in RTC_SYS for warm resets */
    n8_rtc_cache_save(g_n8.sta_channel, g_n8.sta_bssid, g_n8.sta_authmode);
    if (g_n8.sta_ap_country_valid != 0U && g_n8.country.policy == WIFI_COUNTRY_POLICY_AUTO) {
        n8_sync_country_power();
    } else {
        n8_apply_tx_power_limit();
    }
    n8_pm_on_connect();

    ESP_LOGD(TAG, "STA connected: '%s' ch=%u aid=%u",
             (const char *)g_n8.sta_ssid, (unsigned)g_n8.sta_channel, (unsigned)g_n8.sta_aid);

    system_event_t evt;
    memset(&evt, 0, sizeof(evt));
    evt.event_id = SYSTEM_EVENT_STA_CONNECTED;
    memcpy(evt.event_info.connected.ssid, g_n8.sta_ssid, g_n8.sta_ssid_len);
    evt.event_info.connected.ssid_len = g_n8.sta_ssid_len;
    memcpy(evt.event_info.connected.bssid, g_n8.sta_bssid, IEEE80211_ADDR_LEN);
    evt.event_info.connected.channel = g_n8.sta_channel;
    evt.event_info.connected.authmode = (wifi_auth_mode_t)g_n8.sta_authmode;
    n8_send_system_event(&evt);
}

/* --------------------------------------------------------------------------
 * STA Management Frame RX (Beacon, Auth/SAE, AssocResp, Deauth, Action/BA)
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
typedef struct {
    esp_lmac_peer_id_t peer_id;
    uint8_t            tid;
    uint8_t            win;
    uint16_t           ssn;
} n8_sta_addba_ctx_t;

/**
 * @brief Arm STA hardware RX Block Ack only after ADDBA Response is ACKed over air.
 *
 * Re-validates that the STA is still in `N8_STA_RUN` with the same `sta_peer_id`
 * before calling `esp_lmac_add_rx_ba()`, preventing stale BA activation if the
 * STA disconnected while the ADDBA Response was in flight.
 *
 * @param ctx Heap-allocated `n8_sta_addba_ctx_t` pending session state.
 * @param st  LMAC TX status for the transmitted ADDBA Response.
 */
static void sta_addba_tx_done_cb(void *ctx, const esp_lmac_tx_status_t *st)
{
    n8_sta_addba_ctx_t *pending = (n8_sta_addba_ctx_t *)ctx;
    if (pending == NULL) {
        return;
    }
    if (st != NULL && st->ok != 0U &&
        g_n8.sta_state == N8_STA_RUN &&
        g_n8.sta_peer_id == pending->peer_id) {
        (void)esp_lmac_add_rx_ba(pending->peer_id, pending->tid,
                                 pending->ssn, pending->win);
    }
    heap_caps_free(pending);
}
#endif

/**
 * @brief Dispatch received 802.11 Action frames (SA Query, Block Ack, and 11k/11v).
 *
 * Enforces 802.11w PMF (software CCMP decryption for unicast protected frames,
 * BIP MMIE verification for broadcast Robust Action frames, and dropping
 * unprotected Robust Action frames once PMF is negotiated), handles SA-Query
 * Requests/Responses, negotiates STA RX Block Ack (including WPA3/PMF links)
 * when `CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED` is enabled, and forwards registered
 * Action categories (e.g., 802.11k RRM / 802.11v BTM) to `wpa_supplicant`.
 *
 * @param ctrl  RX radio metadata header (RSSI/channel), may be NULL in unit tests.
 * @param frame Raw 802.11 Action frame starting at Frame Control.
 * @param len   Total frame length in bytes (excluding FCS).
 */
static void sta_handle_action(const wifi_pkt_rx_ctrl_t *ctrl, const uint8_t *frame, uint16_t len)
{
    bool is_bcast = (frame[IEEE80211_HDR_ADDR1_OFF] & N8_MAC_MCAST_BIT) != 0U;
    bool is_prot = (frame[1] & IEEE80211_FC1_PROTECTED) != 0U;
    uint8_t *plain = NULL;
    const uint8_t *body = NULL;
    uint16_t blen = 0U;

    /*
     * 802.11w PMF RX validation:
     *  - Broadcast robust Action: must be unencrypted + pass BIP MMIE (strip 18B MMIE).
     *  - Unicast Protected=1: software-decrypt + PN replay check via sta_decrypt_pmf_mgmt().
     *  - Unicast Protected=0: reject Robust categories once PMF is negotiated.
     */
    if (is_bcast) {
        if (is_prot || len < (IEEE80211_HDR_LEN + N8_STA_ACTION_HDR_LEN)) {
            return;
        }
        uint8_t cat = frame[IEEE80211_HDR_LEN];
        if (g_n8.sta_state == N8_STA_RUN && g_n8.sta_pmf_active != 0U &&
            sta_is_robust_action(cat)) {
            if (!n8_verify_bip_mmie(frame, len)) {
                return;
            }
            if (len < (IEEE80211_HDR_LEN + N8_STA_ACTION_HDR_LEN + IEEE80211_MMIE_LEN)) {
                return;
            }
            blen = (uint16_t)(len - IEEE80211_HDR_LEN - IEEE80211_MMIE_LEN);
        } else {
            blen = (uint16_t)(len - IEEE80211_HDR_LEN);
        }
        body = frame + IEEE80211_HDR_LEN;
    } else if (is_prot) {
        size_t dlen = 0U;
        plain = sta_decrypt_pmf_mgmt(frame, len, &dlen);
        if (plain == NULL || dlen < N8_STA_ACTION_HDR_LEN) {
            if (plain != NULL) {
                os_free(plain);
            }
            return;
        }
        body = plain;
        blen = (uint16_t)dlen;
    } else {
        if (len < (IEEE80211_HDR_LEN + N8_STA_ACTION_HDR_LEN)) {
            return;
        }
        uint8_t cat = frame[IEEE80211_HDR_LEN];
        if (g_n8.sta_pmf_active != 0U && g_n8.sta_state >= N8_STA_ASSOC &&
            sta_is_robust_action(cat)) {
            return;
        }
        body = frame + IEEE80211_HDR_LEN;
        blen = (uint16_t)(len - IEEE80211_HDR_LEN);
    }

    uint8_t cat = body[0];
    uint8_t act = body[1];

    /* 802.11w SA-Query Request/Response */
    if (cat == IEEE80211_CAT_SA_QUERY && blen >= N8_STA_SA_QUERY_BODY_LEN) {
        if (g_n8.sta_state == N8_STA_RUN &&
            (g_n8.sta_pmf_active == 0U || g_n8.sta_ptk_key_valid != 0U)) {
            if (act == IEEE80211_SA_QUERY_REQ) {
                sta_send_sa_query(IEEE80211_SA_QUERY_RESP, &body[2]);
            } else if (act == IEEE80211_SA_QUERY_RESP && g_n8.sa_query_active != 0U &&
                       body[2] == g_n8.sa_query_tid[0] && body[3] == g_n8.sa_query_tid[1]) {
                g_n8.sa_query_active = 0U;
                g_n8.sa_query_ticks = 0U;
                memset(g_n8.sa_query_tid, 0, sizeof(g_n8.sa_query_tid));
            }
        }
        if (plain != NULL) {
            os_free(plain);
        }
        return;
    }

    /* 802.11n Block Ack (STA RX A-MPDU, including WPA3/PMF links) */
    if (cat == IEEE80211_CAT_BA && g_n8.sta_state == N8_STA_RUN &&
        (g_n8.sta_pmf_active == 0U || g_n8.sta_ptk_key_valid != 0U)) {
        if (act == IEEE80211_BA_ACTION_ADDBA_REQ && blen >= N8_STA_ADDBA_REQ_BODY_LEN) {
            uint8_t dialog = body[2];
            uint16_t ba_param = (uint16_t)((uint16_t)body[3] | ((uint16_t)body[4] << 8));
            uint8_t policy = (uint8_t)((ba_param >> N8_STA_ADDBA_POLICY_SHIFT) & N8_STA_ADDBA_POLICY_MASK);
            uint8_t tid = (uint8_t)((ba_param >> N8_STA_ADDBA_TID_SHIFT) & N8_STA_ADDBA_TID_MASK);
            uint16_t req_win = (uint16_t)((ba_param >> N8_STA_ADDBA_WIN_SHIFT) & N8_STA_ADDBA_WIN_MASK);
            uint16_t timeout = (uint16_t)((uint16_t)body[5] | ((uint16_t)body[6] << 8));
            uint16_t ssn = (uint16_t)((((uint16_t)body[7] | ((uint16_t)body[8] << 8)) >> IEEE80211_SEQ_SHIFT) & IEEE80211_SEQ_MASK);
            uint16_t status = WLAN_STATUS_REQUEST_DECLINED;
            uint16_t resp_win = req_win;
            esp_lmac_tx_done_cb_t tx_cb = NULL;
            void *tx_ctx = NULL;

#ifdef CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
            /* Accept Immediate BA on HT links only; arm HW RX BA only after ADDBA Resp ACK */
            if (g_n8.init_cfg.ampdu_rx_enable != 0U &&
                g_n8.sta_ht_active != 0U &&
                policy == N8_STA_ADDBA_POLICY_IMMED_VAL && tid < N8_MAX_TID &&
                g_n8.init_cfg.rx_ba_win > 0U &&
                esp_lmac_can_add_rx_ba(g_n8.sta_peer_id, tid)) {
                uint16_t max_win = g_n8.init_cfg.rx_ba_win;
                resp_win = (req_win == 0U || req_win > max_win) ? max_win : req_win;
                n8_sta_addba_ctx_t *pending = (n8_sta_addba_ctx_t *)heap_caps_malloc(
                    sizeof(*pending), MALLOC_CAP_8BIT);
                if (pending != NULL) {
                    pending->peer_id = g_n8.sta_peer_id;
                    pending->tid = tid;
                    pending->win = (uint8_t)resp_win;
                    pending->ssn = ssn;
                    status = WLAN_STATUS_SUCCESS_CODE;
                    tx_cb = sta_addba_tx_done_cb;
                    tx_ctx = pending;
                }
            }
#else
            (void)policy;
            (void)ssn;
#endif

            uint16_t resp_param = (uint16_t)(((resp_win & N8_STA_ADDBA_WIN_MASK) << N8_STA_ADDBA_WIN_SHIFT) |
                                             ((uint16_t)tid << N8_STA_ADDBA_TID_SHIFT) |
                                             N8_STA_ADDBA_POLICY_IMMED);
            uint8_t resp[N8_STA_ADDBA_RESP_BODY_LEN] = {
                IEEE80211_CAT_BA, IEEE80211_BA_ACTION_ADDBA_RESP,
                dialog,
                (uint8_t)(status & 0xFFU), (uint8_t)(status >> 8),
                (uint8_t)(resp_param & 0xFFU), (uint8_t)(resp_param >> 8),
                (uint8_t)(timeout & 0xFFU), (uint8_t)(timeout >> 8)
            };
            esp_err_t tx_err = sta_tx_mgmt_cb(IEEE80211_SUBTYPE_ACTION, resp, sizeof(resp),
                                              false, (g_n8.sta_pmf_active != 0U), tx_cb, tx_ctx);
            if (tx_err != ESP_OK && tx_ctx != NULL) {
                heap_caps_free(tx_ctx);
            }
        } else if (act == IEEE80211_BA_ACTION_DELBA && blen >= N8_STA_DELBA_BODY_LEN) {
            uint16_t del_param = (uint16_t)((uint16_t)body[2] | ((uint16_t)body[3] << 8));
            uint8_t tid = (uint8_t)((del_param >> N8_STA_DELBA_TID_SHIFT) & N8_STA_ADDBA_TID_MASK);
            if (tid < N8_MAX_TID) {
                esp_lmac_del_rx_ba(g_n8.sta_peer_id, tid);
            }
        }
    }
#ifdef CONFIG_WPA_11KV_SUPPORT
    else if (g_n8.sta_state == N8_STA_RUN && g_n8.wpa_cb != NULL &&
             g_n8.wpa_cb->esp_sta_rx_mgmt != NULL &&
             (g_n8.frame_reg_type & (1UL << IEEE80211_STYPE_IDX_ACTION)) != 0U &&
             cat < N8_STA_REG_SUBTYPE_MAX && (g_n8.frame_reg_subtype & (1UL << cat)) != 0U) {
        int32_t rssi_val = (ctrl != NULL) ? (int32_t)(int8_t)ctrl->rssi : N8_STA_RSSI_UNKNOWN;
        (void)g_n8.wpa_cb->esp_sta_rx_mgmt(
            IEEE80211_STYPE_IDX_ACTION,
            (u8 *)(uintptr_t)body,
            (size_t)blen,
            (u8 *)(uintptr_t)(frame + IEEE80211_HDR_ADDR2_OFF),
            (u32)rssi_val,
            g_n8.cur_channel,
            esp_lmac_get_tsf_us(ESP_LMAC_VIF_STA));
    }
#else
    (void)ctrl;
#endif

    if (plain != NULL) {
        os_free(plain);
    }
}

/**
 * @brief Process received 802.11 management frames for the STA VIF.
 *
 * Forwards Probe Requests to `probe_req_cb` in STA-only mode, feeds registered
 * Beacons/Probe Responses to 802.11k/11v (`CONFIG_WPA_11KV_SUPPORT`) and the
 * active scanner, and for associated AP beacons resets the beacon-loss
 * watchdog, updates TSF offset, frequency offset, smoothed RSSI, close-range
 * `rxmax_ext` hysteresis, one-shot low-RSSI threshold, Country/WPS/ERP/HT
 * protection/CSA IE 37 state, AP authmode-change events, and modem-sleep TIM
 * parsing. Drives MLME transitions for Open Auth, WPA3-SAE Commit/Confirm
 * (including anti-clogging token retry), AssocResp (including WPS pending and
 * WPA2-Enterprise EAP startup), PMF-enforced Deauth/Disassoc (with SA-Query
 * verification), and Action frames.
 *
 * @param ctrl        RX metadata (RSSI, rate, channel).
 * @param freq_offset Baseband frequency offset (or `N8_FREQ_OFFSET_INVALID`).
 * @param frame       Raw 802.11 management frame starting at Frame Control.
 * @param len         Total frame length in bytes (excluding FCS).
 */
void n8_sta_rx_mgmt(const wifi_pkt_rx_ctrl_t *ctrl, int16_t freq_offset,
                    const uint8_t *frame, uint16_t len)
{
    if (len < IEEE80211_HDR_LEN) {
        return;
    }

    uint8_t subtype = (uint8_t)(frame[0] & IEEE80211_FC_SUBTYPE_MASK);

    if (subtype == IEEE80211_SUBTYPE_PROBE_REQ) {
        if (g_n8.mode == WIFI_MODE_STA && g_n8.probe_req_cb != NULL) {
            int rssi = (ctrl != NULL) ? (int)(int8_t)ctrl->rssi : N8_STA_RSSI_UNKNOWN;
            g_n8.probe_req_cb(frame, (int)len, rssi);
        }
        return;
    }

    if (subtype == IEEE80211_SUBTYPE_BEACON || subtype == IEEE80211_SUBTYPE_PROBE_RESP) {
#ifdef CONFIG_WPA_11KV_SUPPORT
        /* Forward before n8_scan_rx_beacon_or_probe(), which stops fast connect scan inline */
        if (len > IEEE80211_HDR_LEN && g_n8.wpa_cb != NULL && g_n8.wpa_cb->esp_sta_rx_mgmt != NULL) {
            uint8_t stype_idx = (uint8_t)(subtype >> N8_STA_FC_SUBTYPE_SHIFT);
            bool reg_match = (g_n8.frame_reg_type & (1UL << stype_idx)) != 0U;
            bool conn_scan_11kv = (g_n8.scan_active != 0U && g_n8.scan_for_connect != 0U &&
                                   (esp_wifi_is_rm_enabled_internal(WIFI_IF_STA) ||
                                    esp_wifi_is_btm_enabled_internal(WIFI_IF_STA)));
            if (reg_match || conn_scan_11kv) {
                int32_t rssi_val = (ctrl != NULL) ? (int32_t)(int8_t)ctrl->rssi : N8_STA_RSSI_UNKNOWN;
                (void)g_n8.wpa_cb->esp_sta_rx_mgmt(
                    stype_idx,
                    (u8 *)(uintptr_t)(frame + IEEE80211_HDR_LEN),
                    (size_t)(len - IEEE80211_HDR_LEN),
                    (u8 *)(uintptr_t)(frame + IEEE80211_HDR_ADDR2_OFF),
                    (u32)rssi_val,
                    g_n8.cur_channel,
                    esp_lmac_get_tsf_us(ESP_LMAC_VIF_STA));
            }
        }
#endif
        if (g_n8.scan_active) {
            n8_scan_rx_beacon_or_probe(ctrl, freq_offset, frame, len);
        }
        if (subtype == IEEE80211_SUBTYPE_BEACON && g_n8.sta_state >= N8_STA_ASSOC &&
            memcmp(frame + IEEE80211_HDR_ADDR3_OFF, g_n8.sta_bssid, IEEE80211_ADDR_LEN) == 0) {
            g_n8.sta_bcn_miss_ticks = 0U;
            if (len >= N8_STA_BCN_IE_OFF) {
                uint64_t bcn_tsf;
                memcpy(&bcn_tsf, frame + IEEE80211_HDR_LEN, sizeof(bcn_tsf));
                g_n8.sta_tsf_diff_us = (int64_t)(bcn_tsf - esp_lmac_get_tsf_us(ESP_LMAC_VIF_STA));
                g_n8.sta_tsf_valid = 1U;
            }
            if (freq_offset != N8_FREQ_OFFSET_INVALID) {
                g_n8.sta_last_freq_offset = freq_offset;
            }
            esp_lmac_peer_update_rssi(g_n8.sta_peer_id, (int8_t)ctrl->rssi);
            /*
             * Close-range RX front-end attenuation hysteresis (5 dB band):
             * engage rxmax_ext=3 above -25 dBm to avoid LNA saturation, and
             * restore rxmax_ext=0 only below -30 dBm to prevent rapid toggling.
             */
            int8_t rssi_now = esp_lmac_peer_get_rssi(g_n8.sta_peer_id);
            if (rssi_now > N8_STA_RXMAX_HI_RSSI) {
                g_n8.sta_rxmax_ext_state = N8_STA_RXMAX_EXT_LVL;
            } else if (rssi_now < N8_STA_RXMAX_LO_RSSI) {
                g_n8.sta_rxmax_ext_state = 0U;
            }
            esp_lmac_set_rxmax_ext(g_n8.sta_rxmax_ext_state);

            if (g_n8.sta_state == N8_STA_RUN && g_n8.rssi_thresh_armed != 0U &&
                (int32_t)rssi_now < g_n8.rssi_threshold) {
                g_n8.rssi_thresh_armed = 0U;
                system_event_t evt;
                memset(&evt, 0, sizeof(evt));
                evt.event_id = SYSTEM_EVENT_STA_BSS_RSSI_LOW;
                evt.event_info.bss_rssi_low.rssi = (int32_t)rssi_now;
                n8_send_system_event(&evt);
            }

            if (len > N8_STA_BCN_IE_OFF) {
                uint16_t capinfo = (uint16_t)((uint16_t)frame[N8_STA_BCN_CAPINFO_OFF] |
                                              ((uint16_t)frame[N8_STA_BCN_CAPINFO_OFF + 1U] << 8));
                const uint8_t *ies = frame + N8_STA_BCN_IE_OFF;
                uint16_t ie_len = (uint16_t)(len - N8_STA_BCN_IE_OFF);
                uint16_t pos = 0U;
                const uint8_t *rsn_ie = NULL;
                uint16_t rsn_len = 0U;
                const uint8_t *wpa_ie = NULL;
                uint16_t wpa_len = 0U;
                bool wps_seen = false;
                bool country_adopted = false;
                bool erp_prot = false;
                bool csa_seen = false;
                uint8_t csa_mode = 0U;
                uint8_t csa_new_ch = 0U;
                uint8_t csa_count = 0U;

                while (pos + IEEE80211_IE_HDR_LEN <= ie_len) {
                    uint8_t id = ies[pos];
                    uint8_t elen = ies[pos + 1U];
                    if (pos + IEEE80211_IE_HDR_LEN + elen > ie_len) {
                        break;
                    }
                    if (id == IEEE80211_IE_COUNTRY && !g_n8.sta_ap_country_valid &&
                        elen >= N8_STA_COUNTRY_IE_MIN_LEN) {
                        uint8_t sc = ies[pos + N8_STA_COUNTRY_SCHAN_OFF];
                        uint8_t nc = ies[pos + N8_STA_COUNTRY_NCHAN_OFF];
                        if (sc >= N8_CHANNEL_MIN && nc >= 1U &&
                            (uint16_t)sc + (uint16_t)nc <= (N8_CHANNEL_MAX + 1U)) {
                            memcpy(g_n8.sta_ap_country.cc, &ies[pos + IEEE80211_IE_HDR_LEN],
                                   N8_STA_COUNTRY_CC_LEN);
                            g_n8.sta_ap_country.schan = sc;
                            g_n8.sta_ap_country.nchan = nc;
                            g_n8.sta_ap_country.max_tx_power = (int8_t)ies[pos + N8_STA_COUNTRY_PWR_OFF];
                            g_n8.sta_ap_country.policy = WIFI_COUNTRY_POLICY_AUTO;
                            g_n8.sta_ap_country_valid = 1U;
                            country_adopted = true;
                        }
                    } else if (id == IEEE80211_IE_CSA && elen >= IEEE80211_CSA_IE_LEN) {
                        csa_seen = true;
                        csa_mode = ies[pos + IEEE80211_IE_HDR_LEN];
                        csa_new_ch = ies[pos + IEEE80211_IE_HDR_LEN + 1U];
                        csa_count = ies[pos + IEEE80211_IE_HDR_LEN + 2U];
                    } else if (id == IEEE80211_IE_ERP_INFO && elen >= 1U) {
                        /* Legacy 802.11g ERP Use_Protection bit (drives data-path RTS/CTS) */
                        if ((ies[pos + IEEE80211_IE_HDR_LEN] & IEEE80211_ERP_USE_PROTECTION) != 0U) {
                            erp_prot = true;
                        }
                    } else if (id == IEEE80211_IE_HT_OP && elen >= IEEE80211_HT_OP_MIN_LEN) {
                        /* Non-zero 802.11n HT Operation protection mode (non-HT/mixed BSS) */
                        if ((ies[pos + IEEE80211_IE_HDR_LEN + IEEE80211_HT_OP_PROT_OFF] & IEEE80211_HT_OP_PROT_MASK) != 0U) {
                            erp_prot = true;
                        }
                    } else if (id == IEEE80211_IE_RSN) {
                        rsn_ie = &ies[pos];
                        rsn_len = (uint16_t)(elen + IEEE80211_IE_HDR_LEN);
                    } else if (id == IEEE80211_IE_VENDOR && elen >= N8_STA_VENDOR_OUI_TYPE_LEN &&
                               ies[pos + IEEE80211_IE_HDR_LEN] == IEEE80211_OUI_MS_0 &&
                               ies[pos + IEEE80211_IE_HDR_LEN + 1U] == IEEE80211_OUI_MS_1 &&
                               ies[pos + IEEE80211_IE_HDR_LEN + 2U] == IEEE80211_OUI_MS_2) {
                        if (ies[pos + IEEE80211_IE_HDR_LEN + 3U] == IEEE80211_OUI_TYPE_WPA) {
                            wpa_ie = &ies[pos];
                            wpa_len = (uint16_t)(elen + IEEE80211_IE_HDR_LEN);
                        } else if (ies[pos + IEEE80211_IE_HDR_LEN + 3U] == IEEE80211_OUI_TYPE_WPS) {
                            wps_seen = true;
                        }
                    }
                    pos = (uint16_t)(pos + IEEE80211_IE_HDR_LEN + elen);
                }

                if (country_adopted && g_n8.sta_state == N8_STA_RUN &&
                    g_n8.country.policy == WIFI_COUNTRY_POLICY_AUTO) {
                    n8_sync_country_power();
                }

                /* Apply beacon-wide flags only when TLV walk reached exact end (ignores truncated frames) */
                if (pos == ie_len) {
                    g_n8.sta_ap_wps = wps_seen ? 1U : 0U;
                    g_n8.sta_erp_prot = erp_prot ? 1U : 0U;

                    /*
                     * CSA IE 37 countdown & quiet-mode state machine:
                     *  - Target == current channel or CSA IE vanished: cancel countdown and resume TX.
                     *  - mode == 1 (quiet): pause STA data TX until switch completes.
                     *  - count <= 1: execute switch immediately; count > 1: track TBTT countdown.
                     */
                    if (csa_seen) {
                        if (csa_new_ch == g_n8.sta_channel) {
                            if (g_n8.sta_csa_active != 0U || g_n8.sta_csa_tx_paused != 0U) {
                                sta_csa_reset();
                                n8_data_process_tx_queue();
                            }
                        } else if (sta_csa_is_valid_channel(csa_new_ch)) {
                            g_n8.sta_csa_tx_paused = (csa_mode == IEEE80211_CSA_MODE_QUIET) ? 1U : 0U;
                            if (csa_count <= 1U) {
                                sta_csa_apply_switch(csa_new_ch);
                            } else {
                                g_n8.sta_csa_active = 1U;
                                g_n8.sta_csa_mode = csa_mode;
                                g_n8.sta_csa_new_ch = csa_new_ch;
                                g_n8.sta_csa_count = csa_count;
                                if (g_n8.sta_csa_tx_paused == 0U && g_n8.tx_q_head != g_n8.tx_q_tail) {
                                    n8_data_process_tx_queue();
                                }
                            }
                        }
                    } else if (g_n8.sta_csa_active != 0U) {
                        sta_csa_reset();
                        n8_data_process_tx_queue();
                    }

                    if (g_n8.sta_state == N8_STA_RUN && g_n8.wpa_cb != NULL &&
                        g_n8.wpa_cb->wpa_parse_wpa_ie != NULL) {
                        bool rsn_ok = false;
                        bool wpa_ok = false;
                        wifi_auth_mode_t bcn_mode = n8_parse_ap_authmode(capinfo, rsn_ie, rsn_len,
                                                                         wpa_ie, wpa_len,
                                                                         NULL, NULL, &rsn_ok, &wpa_ok);
                        if ((rsn_ie == NULL || rsn_ok) && (wpa_ie == NULL || wpa_ok) &&
                            (uint8_t)bcn_mode != g_n8.sta_beacon_authmode) {
                            system_event_t evt;
                            memset(&evt, 0, sizeof(evt));
                            evt.event_id = SYSTEM_EVENT_STA_AUTHMODE_CHANGE;
                            evt.event_info.auth_change.old_mode = (wifi_auth_mode_t)g_n8.sta_authmode;
                            evt.event_info.auth_change.new_mode = bcn_mode;
                            g_n8.sta_beacon_authmode = (uint8_t)bcn_mode;
                            g_n8.sta_authmode = (uint8_t)bcn_mode;
                            n8_send_system_event(&evt);
                        }
                    }
                }
            }
            n8_pm_on_beacon_rx(frame, len);
        }
        return;
    }

    if (g_n8.sta_state < N8_STA_AUTH) {
        return;
    }

    /* Filter to our associated AP's BSSID */
    if (memcmp(frame + IEEE80211_HDR_ADDR3_OFF, g_n8.sta_bssid, IEEE80211_ADDR_LEN) != 0) {
        return;
    }

    if (subtype == IEEE80211_SUBTYPE_AUTH && g_n8.sta_state == N8_STA_AUTH &&
        len >= N8_STA_AUTH_MIN_FRAME_LEN) {
        uint16_t alg = (uint16_t)((uint16_t)frame[N8_STA_AUTH_ALG_OFF] |
                                  ((uint16_t)frame[N8_STA_AUTH_ALG_OFF + 1U] << 8));
        uint16_t seq = (uint16_t)((uint16_t)frame[N8_STA_AUTH_SEQ_OFF] |
                                  ((uint16_t)frame[N8_STA_AUTH_SEQ_OFF + 1U] << 8));
        uint16_t status = (uint16_t)((uint16_t)frame[N8_STA_AUTH_STATUS_OFF] |
                                     ((uint16_t)frame[N8_STA_AUTH_STATUS_OFF + 1U] << 8));

        if (alg == IEEE80211_AUTH_ALG_OPEN && seq == N8_STA_AUTH_SEQ_RESP) {
            if (status != WLAN_STATUS_SUCCESS_CODE) {
                ESP_LOGW(TAG, "Auth rejected status=%u", (unsigned)status);
                n8_sta_disconnect(WIFI_REASON_AUTH_FAIL, false, true);
                return;
            }
            g_n8.sta_state = N8_STA_ASSOC;
            g_n8.sta_state_ticks = 0U;
            sta_send_assoc_req();
            return;
        }

#ifdef CONFIG_ESP8266_WIFI_ENABLE_WPA3_SAE
        /*
         * WPA3-SAE two-round handshake:
         *   Seq 1 (Commit): parse AP commit (or resend with anti-clogging token on status 76),
         *                   then advance to Seq 2 (Confirm).
         *   Seq 2 (Confirm): verify AP confirm tag, then transition to N8_STA_ASSOC.
         */
        if (alg == IEEE80211_AUTH_ALG_SAE && g_n8.wpa_cb != NULL &&
            g_n8.wpa_cb->wpa3_parse_sae_msg != NULL) {
            uint8_t *sae_body = (uint8_t *)(uintptr_t)(frame + N8_STA_AUTH_MIN_FRAME_LEN);
            size_t sae_len = (size_t)(len - N8_STA_AUTH_MIN_FRAME_LEN);

            if (seq == SAE_MSG_COMMIT_TYPE && g_n8.sta_sae_seq == SAE_MSG_COMMIT_TYPE) {
                if (status == WLAN_STATUS_ANTI_CLOGGING_CODE) {
                    if (g_n8.wpa_cb->wpa3_parse_sae_msg(sae_body, sae_len, SAE_MSG_COMMIT_TYPE, status) == 0) {
                        (void)sta_send_auth_sae(SAE_MSG_COMMIT_TYPE);
                    }
                    return;
                }
                if (status != WLAN_STATUS_SUCCESS_CODE ||
                    g_n8.wpa_cb->wpa3_parse_sae_msg(sae_body, sae_len, SAE_MSG_COMMIT_TYPE, status) != 0) {
                    n8_sta_disconnect(WIFI_REASON_AUTH_FAIL, false, true);
                    return;
                }
                g_n8.sta_sae_seq = SAE_MSG_CONFIRM_TYPE;
                g_n8.sta_state_ticks = 0U;
                if (!sta_send_auth_sae(SAE_MSG_CONFIRM_TYPE)) {
                    n8_sta_disconnect(WIFI_REASON_AUTH_FAIL, false, true);
                }
            } else if (seq == SAE_MSG_CONFIRM_TYPE && g_n8.sta_sae_seq == SAE_MSG_CONFIRM_TYPE) {
                if (status != WLAN_STATUS_SUCCESS_CODE ||
                    g_n8.wpa_cb->wpa3_parse_sae_msg(sae_body, sae_len, SAE_MSG_CONFIRM_TYPE, status) != 0) {
                    n8_sta_disconnect(WIFI_REASON_AUTH_FAIL, false, true);
                    return;
                }
                g_n8.sta_state = N8_STA_ASSOC;
                g_n8.sta_state_ticks = 0U;
                sta_send_assoc_req();
            }
        }
#endif
        return;
    }

    if ((subtype == IEEE80211_SUBTYPE_ASSOC_RESP || subtype == IEEE80211_SUBTYPE_REASSOC_RESP) &&
        g_n8.sta_state == N8_STA_ASSOC && len >= N8_STA_ASSOC_RESP_MIN_LEN) {
        uint16_t status = (uint16_t)((uint16_t)frame[N8_STA_ASSOC_RESP_STATUS_OFF] |
                                     ((uint16_t)frame[N8_STA_ASSOC_RESP_STATUS_OFF + 1U] << 8));
        uint16_t aid = (uint16_t)(((uint16_t)frame[N8_STA_ASSOC_RESP_AID_OFF] |
                                   ((uint16_t)frame[N8_STA_ASSOC_RESP_AID_OFF + 1U] << 8)) &
                                  N8_STA_AID_MASK);
        if (status != WLAN_STATUS_SUCCESS_CODE) {
            ESP_LOGW(TAG, "Assoc rejected status=%u", (unsigned)status);
            n8_sta_disconnect(WIFI_REASON_ASSOC_FAIL, false, true);
            return;
        }
        g_n8.sta_aid = aid;
        g_n8.sta_state_ticks = 0U;
        g_n8.sta_bcn_miss_ticks = 0U;

        if (n8_wps_is_pending()) {
            g_n8.sta_state = N8_STA_4WAY;
            g_n8.sta_conn_timer_disarmed = 1U;
            if (g_n8.wps_cb->wps_start_pending != NULL) {
                (void)g_n8.wps_cb->wps_start_pending();
            }
        } else if (g_n8.sta_authmode == WIFI_AUTH_OPEN) {
            n8_sta_on_auth_done();
        } else {
            g_n8.sta_state = N8_STA_4WAY;
            if (g_n8.sta_supp_authmode == WPA2_AUTH_ENT &&
                g_n8.wpa2_cb != NULL && g_n8.wpa2_cb->wpa2_start != NULL) {
                (void)g_n8.wpa2_cb->wpa2_start();
            }
        }
        return;
    }

    if (subtype == IEEE80211_SUBTYPE_DEAUTH || subtype == IEEE80211_SUBTYPE_DISASSOC) {
        if (subtype == IEEE80211_SUBTYPE_DISASSOC && g_n8.sta_state < N8_STA_4WAY) {
            /*
             * Not yet associated; AP evicted a stale pre-reboot session in
             * response to our fresh Auth/Assoc Req. Re-send immediately instead
             * of waiting for the retry timer.
             */
            if (g_n8.sta_state == N8_STA_AUTH && g_n8.sta_auth_retries < N8_STA_MAX_AUTH_RETRIES) {
                g_n8.sta_state_ticks = 0U;
                g_n8.sta_auth_retries++;
                if (g_n8.sta_supp_authmode == WPA3_AUTH_PSK) {
                    (void)sta_send_auth_sae(g_n8.sta_sae_seq);
                } else {
                    sta_send_auth_open();
                }
            }
            return;
        }
        bool is_bcast = (frame[IEEE80211_HDR_ADDR1_OFF] & N8_MAC_MCAST_BIT) != 0U;
        bool is_prot = (frame[1] & IEEE80211_FC1_PROTECTED) != 0U;
        uint8_t reason = WIFI_REASON_UNSPECIFIED;

        /* 802.11w Protected Management Frame enforcement when PMF is active */
        if (g_n8.sta_state == N8_STA_RUN && g_n8.sta_pmf_active != 0U) {
            if (is_bcast) {
                if (is_prot || !n8_verify_bip_mmie(frame, len)) {
                    return; /* Drop spoofed broadcast deauth/disassoc */
                }
                reason = (len >= IEEE80211_HDR_LEN + N8_STA_DEAUTH_BODY_LEN)
                         ? frame[IEEE80211_HDR_LEN] : WIFI_REASON_UNSPECIFIED;
            } else if (!is_prot) {
                /* Unprotected unicast deauth/disassoc under PMF: verify AP liveness via SA-Query */
                sta_start_sa_query();
                return;
            } else {
                size_t dlen = 0U;
                uint8_t *plain = sta_decrypt_pmf_mgmt(frame, len, &dlen);
                if (plain == NULL) {
                    return; /* Drop forged Protected=1 frame on CCMP MIC/replay failure */
                }
                reason = (dlen >= N8_STA_DEAUTH_BODY_LEN) ? plain[0] : WIFI_REASON_UNSPECIFIED;
                os_free(plain);
            }
        } else if (is_prot) {
            size_t dlen = 0U;
            uint8_t *plain = sta_decrypt_pmf_mgmt(frame, len, &dlen);
            if (plain == NULL) {
                return;
            }
            reason = (dlen >= N8_STA_DEAUTH_BODY_LEN) ? plain[0] : WIFI_REASON_UNSPECIFIED;
            os_free(plain);
        } else {
            reason = (len >= IEEE80211_HDR_LEN + N8_STA_DEAUTH_BODY_LEN)
                     ? frame[IEEE80211_HDR_LEN] : WIFI_REASON_UNSPECIFIED;
        }

        ESP_LOGW(TAG, "RX %s from AP (reason=%u)",
                 (subtype == IEEE80211_SUBTYPE_DEAUTH) ? "deauth" : "disassoc", (unsigned)reason);
        n8_sta_disconnect(reason, false, true);
        return;
    }

    if (subtype == IEEE80211_SUBTYPE_ACTION && g_n8.sta_state >= N8_STA_ASSOC) {
        sta_handle_action(ctrl, frame, len);
    }
}

/* --------------------------------------------------------------------------
 * 100 ms STA Watchdog (Auth/Assoc/4-Way, SA-Query, CSA Fallback & Beacon Loss)
 * -------------------------------------------------------------------------- */

/**
 * @brief Periodic 100 ms STA MLME watchdog for Auth/Assoc retries, handshakes, SA-Query, CSA, and beacon loss.
 *
 * Retransmits Open/SAE Auth (200 ms / 1.0 s step timeout) and Assoc frames up
 * to `N8_STA_MAX_AUTH_RETRIES`, enforces the 4-Way (5 s) or WPA2-Enterprise
 * (30 s) handshake deadline unless disarmed for WPS enrollment, drives 802.11w
 * SA-Query retries (every 200 ms, disconnecting after 1.0 s timeout), provides
 * a missed-beacon CSA countdown fallback, and while in `N8_STA_RUN` (and not
 * scanning off-channel) disconnects with `WIFI_REASON_BEACON_TIMEOUT` if no AP
 * beacon arrives within `max(inactive_sec[STA], 3 s)`.
 */
void n8_sta_on_tick_100ms(void)
{
    if (g_n8.sta_state == N8_STA_IDLE || g_n8.sta_state == N8_STA_SCANNING) {
        return;
    }

    g_n8.sta_state_ticks++;

    uint16_t auth_tmo = (g_n8.sta_supp_authmode == WPA3_AUTH_PSK)
                        ? N8_STA_SAE_AUTH_TIMEOUT_TICKS
                        : N8_STA_AUTH_TIMEOUT_TICKS;
    if (g_n8.sta_state == N8_STA_AUTH && g_n8.sta_state_ticks >= auth_tmo) {
        g_n8.sta_state_ticks = 0U;
        g_n8.sta_auth_retries++;
        if (g_n8.sta_auth_retries >= N8_STA_MAX_AUTH_RETRIES) {
            n8_sta_disconnect(WIFI_REASON_AUTH_EXPIRE, false, true);
            return;
        }
        if (g_n8.sta_supp_authmode == WPA3_AUTH_PSK) {
            (void)sta_send_auth_sae(g_n8.sta_sae_seq);
        } else {
            sta_send_auth_open();
        }
    } else if (g_n8.sta_state == N8_STA_ASSOC && g_n8.sta_state_ticks >= N8_STA_ASSOC_TIMEOUT_TICKS) {
        g_n8.sta_state_ticks = 0U;
        g_n8.sta_auth_retries++;
        if (g_n8.sta_auth_retries >= N8_STA_MAX_AUTH_RETRIES) {
            n8_sta_disconnect(WIFI_REASON_ASSOC_EXPIRE, false, true);
            return;
        }
        sta_send_assoc_req();
    } else if (g_n8.sta_state == N8_STA_4WAY) {
        if (g_n8.sta_conn_timer_disarmed == 0U) {
            uint16_t hs_tmo = (g_n8.sta_supp_authmode == WPA2_AUTH_ENT)
                              ? N8_STA_WPA2_ENT_TIMEOUT_TICKS
                              : N8_STA_4WAY_TIMEOUT_TICKS;
            if (g_n8.sta_state_ticks >= hs_tmo) {
                n8_sta_disconnect(WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT, true, true);
            }
        }
    } else if (g_n8.sta_state == N8_STA_RUN) {
        if (g_n8.sa_query_active != 0U) {
            g_n8.sa_query_ticks++;
            if (g_n8.sa_query_ticks >= N8_STA_SA_QUERY_TIMEOUT_TICKS) {
                g_n8.sa_query_active = 0U;
                g_n8.sa_query_ticks = 0U;
                memset(g_n8.sa_query_tid, 0, sizeof(g_n8.sa_query_tid));
                n8_sta_disconnect(WIFI_REASON_UNSPECIFIED, false, true);
                return;
            }
            if ((g_n8.sa_query_ticks % N8_STA_SA_QUERY_RETRY_TICKS) == 0U) {
                sta_send_sa_query(IEEE80211_SA_QUERY_REQ, g_n8.sa_query_tid);
            }
        }
        if (!g_n8.scan_active) {
            g_n8.sta_bcn_miss_ticks++;
            if (g_n8.sta_csa_active != 0U && g_n8.sta_bcn_miss_ticks >= N8_STA_CSA_MISS_FALLBACK_TICKS) {
                /* Missed-beacon CSA countdown fallback when AP hops before count=1 beacon */
                if (g_n8.sta_csa_count > 1U) {
                    g_n8.sta_csa_count--;
                }
                if (g_n8.sta_csa_count <= 1U) {
                    sta_csa_apply_switch(g_n8.sta_csa_new_ch);
                }
            }
            uint16_t max_miss = (uint16_t)(g_n8.inactive_sec[WIFI_IF_STA] * N8_STA_TICKS_PER_SEC);
            if (max_miss < N8_STA_MIN_BCN_MISS_TICKS) {
                max_miss = N8_STA_MIN_BCN_MISS_TICKS;
            }
            if (g_n8.sta_bcn_miss_ticks >= max_miss) {
                ESP_LOGW(TAG, "Beacon timeout (%u ms)",
                         (unsigned)g_n8.sta_bcn_miss_ticks * N8_STA_TICK_MS);
                n8_sta_disconnect(WIFI_REASON_BEACON_TIMEOUT, false, true);
            }
        }
    }
}
