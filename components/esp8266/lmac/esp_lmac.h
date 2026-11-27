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

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_wifi_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ESP_LMAC_VIF_STA        0U
#define ESP_LMAC_VIF_AP         1U
#define ESP_LMAC_VIF_MAX        2U
#define ESP_LMAC_PEER_INVALID   0xFFU

/* TX request flags */
#define ESP_LMAC_TX_FLAG_NO_ACK            (1U << 0)
#define ESP_LMAC_TX_FLAG_FORCE_LOWEST_RATE (1U << 1)
#define ESP_LMAC_TX_FLAG_SHORT_PREAMBLE    (1U << 2)
#define ESP_LMAC_TX_FLAG_USE_CTS           (1U << 3)
#define ESP_LMAC_TX_FLAG_USE_RTS           (1U << 4)
#define ESP_LMAC_TX_FLAG_BEACON            (1U << 5)

/* RX VIF match bitmask */
#define ESP_LMAC_RX_MATCH_STA_DA           (1U << 0)
#define ESP_LMAC_RX_MATCH_AP_DA            (1U << 1)
#define ESP_LMAC_RX_MATCH_STA_BSSID        (1U << 2)
#define ESP_LMAC_RX_MATCH_AP_BSSID         (1U << 3)

/** Hardware rxend_state status codes (wifi_pkt_rx_ctrl_t.rxend_state). */
#define ESP_LMAC_RXSTATE_OK                0x00U /**< Normal valid MPDU */
#define ESP_LMAC_RXSTATE_ALT1              0x32U /**< Vendor-accepted state '2' (pre-11w PMF mgmt) */
#define ESP_LMAC_RXSTATE_TKIP_MIC_FAIL     0xF5U /**< Hardware TKIP Michael MIC failure (-11) */

typedef uint8_t esp_lmac_vif_t;
typedef uint8_t esp_lmac_peer_id_t;

typedef enum {
    ESP_LMAC_CIPHER_NONE = 0,
    ESP_LMAC_CIPHER_WEP40,
    ESP_LMAC_CIPHER_WEP104,
    ESP_LMAC_CIPHER_TKIP,
    ESP_LMAC_CIPHER_CCMP,
} esp_lmac_cipher_t;

typedef enum {
    ESP_LMAC_KEY_TYPE_GTK = 0,
    ESP_LMAC_KEY_TYPE_PTK = 1,
} esp_lmac_key_type_t;

typedef enum {
    ESP_LMAC_AC_BE = 0,
    ESP_LMAC_AC_BK = 1,
    ESP_LMAC_AC_VI = 2,
    ESP_LMAC_AC_VO = 3,
    ESP_LMAC_AC_MGMT = 4,
} esp_lmac_ac_t;

/* Opaque handle representing a pinned slice of the circular RX DMA ring */
typedef struct esp_lmac_rx_buf {
    const wifi_pkt_rx_ctrl_t *rx_ctrl;     /* 12-B hardware RX header */
    uint8_t                  *frame;       /* Pointer to 802.11 MAC header (linearized across wrap) */
    uint16_t                  len;         /* Exact MPDU length from rx_ctrl */
    int16_t                   freq_offset; /* Baseband frequency offset snapshot */
    uint8_t                   vif_match;   /* Bitmask of matched VIFs (ESP_LMAC_RX_MATCH_*) */
    uint8_t                   desc_start;  /* First circular RX descriptor index */
    uint8_t                   desc_cnt;    /* Number of pinned circular RX descriptors */
    uint8_t                   in_use;      /* Non-zero while owned by upper layer */
} esp_lmac_rx_buf_t;

/* Scatter-gather payload segment (points read-only into lwIP pbuf or mgmt body) */
typedef struct esp_lmac_sg_seg {
    const uint8_t *ptr;  /* Must reside in DRAM (0x3ffe8000..0x3fffffff) */
    uint16_t       len;
} esp_lmac_sg_seg_t;

typedef struct esp_lmac_tx_status {
    uint8_t  ok;         /* 1 = ACKed / multicast sent, 0 = failed/aged-out */
    uint8_t  retries;    /* Total retry attempts executed */
    uint8_t  hw_rate;    /* Final hardware rate code used */
    int8_t   ack_rssi;   /* ACK RSSI (0x7f if unavailable) */
} esp_lmac_tx_status_t;

typedef void (*esp_lmac_tx_done_cb_t)(void *user_ctx, const esp_lmac_tx_status_t *st);

/* TX submission request: LMAC copies hdr into per-slot scratch and chains payload segs read-only */
typedef struct esp_lmac_tx_req {
    esp_lmac_vif_t           vif;
    esp_lmac_peer_id_t       peer_id;      /* ESP_LMAC_PEER_INVALID for mgmt/bcast/forced rate */
    esp_lmac_ac_t            ac;
    esp_lmac_cipher_t        cipher;       /* Drives HW key-slot selection + MIC/ICV trailer */
    uint8_t                  key_idx;      /* 0..3 for GTK / WEP */
    uint8_t                  flags;        /* ESP_LMAC_TX_FLAG_* */
    const uint8_t           *hdr;          /* 802.11 + QoS + IV + LLC/SNAP header (<= 96 B) */
    uint16_t                 hdr_len;
    const esp_lmac_sg_seg_t *segs;         /* Read-only payload segments (0..2) */
    uint8_t                  seg_cnt;
    const uint8_t           *trailer;      /* Optional SW trailer (e.g. 8-B TKIP MIC); NULL for HW CCMP */
    uint8_t                  trailer_len;  /* 8 for HW CCMP (zero-filled), 12 for TKIP, 4 for WEP, 0 plain */
    esp_lmac_tx_done_cb_t    done_cb;      /* Invoked on Wi-Fi worker inside esp_lmac_process_events() */
    void                    *done_ctx;
} esp_lmac_tx_req_t;

typedef struct esp_lmac_peer_caps {
    uint8_t  mac[6];
    uint16_t rate_mask_11bg; /* Basic + supported 11b/11g rate bitmap */
    uint8_t  ht20_mcs_mask;  /* MCS0..7 bitmask (0 for 11b/g) */
    uint8_t  short_preamble : 1;
    uint8_t  short_gi_20    : 1;
    uint8_t  qos_enabled    : 1;
    uint8_t  ht_enabled     : 1;
} esp_lmac_peer_caps_t;

/* Upper-layer callbacks registered by net80211 (or Phase 5 standalone test runner) */
typedef struct esp_lmac_callbacks {
    /* Called from Level-1 SoftISR (MacIsrSigPostDefHdl); returns non-zero if higher-prio task woken */
    int  (*notify_from_isr)(void *ctx);
    /* Called on Wi-Fi worker inside esp_lmac_process_events() */
    void (*on_rx_frame)(void *ctx, esp_lmac_rx_buf_t *rx_buf);
    void (*on_sniffer_frame)(void *ctx, const wifi_pkt_rx_ctrl_t *ctrl, const uint8_t *frame, uint16_t len);
    void (*on_tbtt)(void *ctx, esp_lmac_vif_t vif);
    void (*on_beacon_miss)(void *ctx);
    void *ctx;
} esp_lmac_callbacks_t;

typedef struct esp_lmac_config {
    uint8_t  rx_buf_num;                  /* e.g. CONFIG_ESP8266_WIFI_RX_BUFFER_NUM (16) */
    uint8_t  left_continuous_rx_buf_num;  /* Copy fallback threshold (16 in ESPZWApplianceT2) */
    uint8_t  tx_slot_num;                 /* e.g. CONFIG_ESP8266_WIFI_TX_PKT_NUM (6) */
    uint8_t  ampdu_rx_enable;             /* Compiled out when CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED=n */
    uint8_t  rx_ba_win;                   /* Max RX BA window (default 6, max 16) */
    uint8_t  rx_ampdu_buf_num;            /* A-MPDU subframe info descriptor count (5) */
    uint16_t rx_ampdu_buf_len;            /* A-MPDU subframe info buffer size (256) */
    uint16_t rx_buf_len;                  /* Default WIFI_HW_RX_BUFFER_LEN (524) */
    uint16_t rx_max_single_pkt_len;       /* Default WIFI_RX_MAX_SINGLE_PKT_LEN (1076 or 1600) */
} esp_lmac_config_t;

/* --------------------------------------------------------------------------
 * Lifecycle & Event Pump
 * All non-ISR API calls run serialized on the Wi-Fi worker task unless noted.
 * -------------------------------------------------------------------------- */

/**
 * @brief Initialize the LMAC driver, DMA arenas, TX slot pool, TRC, and WDEV hardware.
 *
 * Must be called from the Wi-Fi worker task. Idempotent if already initialized;
 * preserves power-save lock flags and RX pbuf memory type across re-initialization.
 *
 * @param cfg  Driver buffer and pool sizing configuration (non-NULL).
 * @param cbs  Upper-layer event callbacks and opaque user context (non-NULL).
 * @return     ESP_OK on success, ESP_ERR_INVALID_ARG on NULL/invalid parameters,
 *             or ESP_ERR_NO_MEM if DMA/TX DRAM allocation fails.
 */
esp_err_t esp_lmac_init(const esp_lmac_config_t *cfg, const esp_lmac_callbacks_t *cbs);

/**
 * @brief Shut down the LMAC driver, wake RF, disable VIFs/sniffer/MAC IRQs, and free pools.
 *
 * Must be called from the Wi-Fi worker task. Safe to call when not initialized.
 *
 * @return ESP_OK on completion.
 */
esp_err_t esp_lmac_deinit(void);

/**
 * @brief Drain pending NMI ring, sniffer ring, and TX-completion events on the Wi-Fi worker task.
 *
 * Dispatches received frames (including A-MPDU subframes and SNIFFER_END captures),
 * TX completions/timeouts, and SoftAP TBTT events up to the caller-specified per-call
 * batch budgets so the worker yields cooperatively under heavy traffic.
 *
 * @param max_rx_batch  Maximum RX/sniffer events to dispatch per ring (0 = unbounded).
 * @param max_tx_batch  Maximum TX completion events to drain (0 = unbounded).
 * @return              true if additional events remain queued; false if idle.
 */
bool      esp_lmac_process_events(uint8_t max_rx_batch, uint8_t max_tx_batch);

/**
 * @brief Run periodic 100 ms LMAC maintenance on the Wi-Fi worker task.
 *
 * Checks TX queues for stalled frames every 100 ms, triggers PHY noise-floor
 * calibration and background TX power tracking every 1 s when RF is open, and
 * invokes esp_lmac_hw_mac_reset() if the RX engine wedges for 5 consecutive seconds.
 */
void      esp_lmac_housekeeping_100ms(void);

/* --------------------------------------------------------------------------
 * RX Buffer Ownership & Ring Headroom
 * -------------------------------------------------------------------------- */

/**
 * @brief Return the longest contiguous run of free RX DMA descriptors.
 *
 * Thread-safe via brief interrupt lock around the circular availability bitmap.
 * Used by upper layers to decide between zero-copy pbuf pinning and copy fallback.
 *
 * @return Maximum number of contiguous free RX descriptors (0..rx_buf_num).
 */
uint8_t   esp_lmac_rx_free_contiguous(void);
/**
 * @brief Return true when the linearized frame extends into the shared rx_extradata scratch buffer.
 *
 * @param rx_buf  RX buffer handle delivered via on_rx_frame().
 * @return        true if the frame crosses rx_extradata and must be heap-copied instead of zero-copied.
 */
bool      esp_lmac_rx_buf_is_wrapped(const esp_lmac_rx_buf_t *rx_buf);

/**
 * @brief Release a pinned RX buffer slice back to the hardware RX DMA ring.
 *
 * Decrements per-descriptor refcounts when A-MPDU RX is enabled (returning
 * subframe handles to the static subframe pool), re-arms hardware ownership
 * once a descriptor's refcount reaches zero, and advances the hardware RX ring
 * watermark if freed buffers are contiguous. Safe to call with NULL or an
 * already-freed handle.
 *
 * @param rx_buf  RX buffer handle previously delivered via on_rx_frame().
 */
void      esp_lmac_rx_free(esp_lmac_rx_buf_t *rx_buf);

/* --------------------------------------------------------------------------
 * TX Submission & Queue Control
 * -------------------------------------------------------------------------- */

/**
 * @brief Submit an 802.11 frame for scatter-gather DMA transmission.
 *
 * Resolves the hardware key slot up front (failing with ESP_ERR_NOT_FOUND if a
 * requested hardware key is absent, or routing software-encrypted frames with
 * Protected=1 to the opposite VIF's crypto bypass register), copies the MAC
 * header into per-slot DRAM scratch, chains up to two read-only DRAM payload
 * segments plus crypto/FCS trailer, selects the rate schedule, and arms or
 * enqueues the frame on the serialized HW TXQ. Runs serialized on the Wi-Fi worker.
 *
 * @param req  Transmit request descriptor (header, segments, cipher, callback).
 * @return     ESP_OK if queued/armed, ESP_ERR_INVALID_ARG on invalid pointers/bounds,
 *             ESP_ERR_INVALID_SIZE if MPDU + FCS exceeds 2346 B, ESP_ERR_NOT_FOUND
 *             if hardware encryption was requested without a valid key slot, or
 *             ESP_ERR_NO_MEM if no TX slot is free.
 */
esp_err_t esp_lmac_tx_submit(const esp_lmac_tx_req_t *req);

/**
 * @brief Abort and flush all active and queued TX frames belonging to a VIF.
 *
 * Invokes each flushed frame's completion callback with ok=0 on the Wi-Fi worker.
 *
 * @param vif  Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 */
void      esp_lmac_tx_flush_vif(esp_lmac_vif_t vif);

/**
 * @brief Check whether all hardware and software TX queues are empty.
 *
 * Runs serialized on the Wi-Fi worker task.
 *
 * @return true if no TX frame is active or queued; false otherwise.
 */
bool      esp_lmac_tx_is_idle(void);

/**
 * @brief Check whether at least one TX slot is currently available in the pool.
 *
 * Runs serialized on the Wi-Fi worker task.
 *
 * @return true if a subsequent esp_lmac_tx_submit() can allocate a slot.
 */
bool      esp_lmac_tx_has_free_slot(void);

/* --------------------------------------------------------------------------
 * Virtual Interface, Filter, Channel & RF Power Gating
 * -------------------------------------------------------------------------- */

/**
 * @brief Enable a virtual interface and program its unicast hardware MAC filter.
 *
 * Defaults the VIF protocol mask to 11b/11g/11n if unset and enables the master
 * WDEV MAC engine when RF is open. Runs serialized on the Wi-Fi worker task.
 *
 * @param vif  Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 * @param mac  6-byte local MAC address to match in hardware (non-NULL).
 * @return     ESP_OK on success, or ESP_ERR_INVALID_ARG if @p vif or @p mac is invalid.
 */
esp_err_t esp_lmac_vif_enable(esp_lmac_vif_t vif, const uint8_t mac[6]);

/**
 * @brief Disable a virtual interface, flushing its TX queue, RX BA sessions, keys, and beacon.
 *
 * Clears the hardware unicast MAC and BSSID filters (unless in sniffer mode)
 * and disables the master WDEV MAC engine if no other VIF/sniffer is active.
 * Runs serialized on the Wi-Fi worker task.
 *
 * @param vif  Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 */
void      esp_lmac_vif_disable(esp_lmac_vif_t vif);

/**
 * @brief Configure or disable the hardware BSSID match filter for a VIF.
 *
 * Ignored at the hardware level while promiscuous/sniffer mode or STA scan
 * wildcard mode is active (the software shadow state is still updated and
 * restored upon exit). Runs serialized on the Wi-Fi worker task.
 *
 * @param vif     Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 * @param bssid   6-byte BSSID to match when @p enable is true (may be NULL if false).
 * @param enable  true to enable exact BSSID matching; false to disable it.
 */
void      esp_lmac_set_bssid_filter(esp_lmac_vif_t vif, const uint8_t bssid[6], bool enable);

/**
 * @brief Toggle STA scan RX wildcard mode for beacon and probe-response capture.
 *
 * When @p scanning is true, disables the VIF0 BSSID filter and sets the hardware
 * scan-filter bit so beacons/probe-responses from all APs are received without
 * flooding RX DMA with neighbor data traffic. Runs serialized on the Wi-Fi worker.
 *
 * @param scanning  true when entering active/passive scan; false to restore BSSID filter.
 */
void      esp_lmac_set_scan_rx_mode(bool scanning);

/**
 * @brief Tune the radio and hardware auto-ACK LUT to a 2.4 GHz primary channel.
 *
 * If RF is currently closed, records the channel to be applied on the next
 * esp_lmac_rf_open(). Applies Japan CCK-only auto-ACK remapping on channel 14.
 * Runs serialized on the Wi-Fi worker task.
 *
 * @param primary_chan  IEEE 802.11 2.4 GHz channel number (1..14).
 * @return              ESP_OK on success, or ESP_ERR_INVALID_ARG if out of range.
 */
esp_err_t esp_lmac_set_channel(uint8_t primary_chan);

/**
 * @brief Return the currently configured 2.4 GHz primary channel number.
 *
 * @return Primary channel number (1..14).
 */
uint8_t   esp_lmac_get_channel(void);

/**
 * @brief Wake the RF/PHY subsystem, re-apply channel, and re-enable WDEV MAC.
 *
 * Acquires the system sleep lock and runs any deferred noise-floor check when
 * transitioning from LMAC modem sleep (`rf_closed != 0`). If `rf_closed == 0`
 * but PHY was independently put to sleep by `esp_light_sleep_start()`
 * (`g_phy_sleep_mode_flag != 0`), wakes PHY and restores channel/MAC without
 * double-incrementing the sleep lock count. Runs serialized on the Wi-Fi worker.
 */
void      esp_lmac_rf_open(void);

/**
 * @brief Gate off WDEV MAC and RF/PHY for modem sleep unless PS-locked.
 *
 * No-op if RF is already closed or esp_lmac_ps_is_locked() is true. Releases
 * the system sleep lock after powering down RF. Runs serialized on the Wi-Fi worker.
 */
void      esp_lmac_rf_close(void);

/**
 * @brief Query whether the RF/PHY subsystem is currently power-gated off.
 *
 * @return true if RF is closed (modem sleep); false if RF is awake.
 */
bool      esp_lmac_rf_is_closed(void);

/**
 * @brief Apply PHY close-range LNA attenuation level when changed since last channel tune.
 *
 * Caches the active level in `g_lmac.rxmax_ext` (reset to 0 on channel change)
 * to avoid redundant `chip_v6_rxmax_ext()` writes. Runs serialized on the Wi-Fi worker.
 *
 * @param level  Target `rxmax_ext` level (0 = normal sensitivity, 3 = strong close-range attenuation).
 */
void      esp_lmac_set_rxmax_ext(uint8_t level);

/* --------------------------------------------------------------------------
 * Peer / Rate Control (TRC) & Hardware Crypto Key Slots (LMAC-managed 0..24)
 * -------------------------------------------------------------------------- */

/**
 * @brief Allocate the dynamic SoftAP peer table slab (peer IDs 1..max_ap_peers).
 *
 * Frees any previously allocated SoftAP peer pool first. Clamps @p max_ap_peers
 * to 10; passing 0 frees the pool and returns ESP_OK. Runs on the Wi-Fi worker.
 *
 * @param max_ap_peers  Maximum concurrent SoftAP clients to support (0..10).
 * @return              ESP_OK on success, or ESP_ERR_NO_MEM if allocation fails.
 */
esp_err_t esp_lmac_peer_alloc_ap_pool(uint8_t max_ap_peers);

/**
 * @brief Free the dynamic SoftAP peer table slab if allocated.
 *
 * Runs serialized on the Wi-Fi worker task.
 */
void      esp_lmac_peer_free_ap_pool(void);

/**
 * @brief Add or update a peer entry and initialize its TRC rate schedule.
 *
 * STA VIF always maps to static peer ID 0; SoftAP VIF reuses an existing slot
 * matching caps->mac or allocates a free slot from the SoftAP pool (IDs 1..N).
 * Preserves any previously installed PTK slot when updating an existing peer.
 * Runs serialized on the Wi-Fi worker task.
 *
 * @param vif   Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 * @param caps  Peer MAC address and negotiated 11b/11g/11n capabilities (non-NULL).
 * @return      Assigned peer ID, or ESP_LMAC_PEER_INVALID on error or full pool.
 */
esp_lmac_peer_id_t esp_lmac_peer_add(esp_lmac_vif_t vif, const esp_lmac_peer_caps_t *caps);

/**
 * @brief Remove a peer entry and clear any associated hardware RX BA sessions and PTK slot.
 *
 * Runs serialized on the Wi-Fi worker task.
 *
 * @param peer_id  Peer ID previously returned by esp_lmac_peer_add().
 */
void      esp_lmac_peer_remove(esp_lmac_peer_id_t peer_id);

/**
 * @brief Get the smoothed RSSI estimate (dBm) for a peer.
 *
 * @param peer_id  Peer ID previously returned by esp_lmac_peer_add().
 * @return         Smoothed RSSI in dBm, or -127 if @p peer_id is invalid.
 */
int8_t    esp_lmac_peer_get_rssi(esp_lmac_peer_id_t peer_id);

/**
 * @brief Feed an instantaneous RX/ACK RSSI sample into a peer's 7/8-1/8 EMA.
 *
 * Ignores out-of-range samples (> 0 or < -120 dBm) and applies a one-time
 * weak-link initial rate clamp on join when the first sample is below -80 dBm.
 * Runs serialized on the Wi-Fi worker task.
 *
 * @param peer_id  Peer ID to update.
 * @param rssi     Calibrated RSSI sample in dBm (valid range: -120..0).
 */
void      esp_lmac_peer_update_rssi(esp_lmac_peer_id_t peer_id, int8_t rssi);

/**
 * @brief Set the allowed 802.11 protocol bitmap for a VIF and rebuild TRC schedules.
 *
 * Runs serialized on the Wi-Fi worker task.
 *
 * @param vif           Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 * @param proto_bitmap  Bitmask of WIFI_PROTOCOL_11B / WIFI_PROTOCOL_11G / WIFI_PROTOCOL_11N.
 */
void      esp_lmac_set_protocol_mask(esp_lmac_vif_t vif, uint8_t proto_bitmap);

/**
 * @brief Install a hardware crypto key into the 25-slot WDEV key table.
 *
 * Allocates the appropriate hardware slot (2..5 WEP, 2..3 STA GTK, 4..5 AP GTK,
 * 6..24 PTK), writes the 40-byte hardware entry, updates metadata, and enables
 * the VIF crypto engine register. Runs serialized on the Wi-Fi worker task.
 *
 * @param vif      Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 * @param peer_id  Peer ID for PTK installation (ignored for GTK/WEP).
 * @param type     Key type (ESP_LMAC_KEY_TYPE_GTK or ESP_LMAC_KEY_TYPE_PTK).
 * @param key_idx  802.11 key ID (0..3).
 * @param cipher   Cipher suite (must not be ESP_LMAC_CIPHER_NONE).
 * @param key      Raw key bytes (up to 32 bytes; zero-padded in hardware).
 * @param key_len  Length of @p key in bytes (must be > 0).
 * @return         ESP_OK on success, ESP_ERR_INVALID_ARG on invalid parameters,
 *                 ESP_ERR_NOT_FOUND if PTK @p peer_id does not exist, or
 *                 ESP_ERR_NO_MEM if all 19 PTK hardware slots are occupied.
 */
esp_err_t esp_lmac_key_set(esp_lmac_vif_t vif, esp_lmac_peer_id_t peer_id,
                           esp_lmac_key_type_t type, uint8_t key_idx,
                           esp_lmac_cipher_t cipher, const uint8_t *key, uint8_t key_len);

/**
 * @brief Clear a specific PTK or GTK entry for a VIF and refresh its crypto mode.
 *
 * Runs serialized on the Wi-Fi worker task.
 *
 * @param vif      Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 * @param peer_id  Peer ID to match when @p type is ESP_LMAC_KEY_TYPE_PTK.
 * @param type     Key type to clear (PTK or GTK).
 * @param key_idx  802.11 key ID (0..3) to match when @p type is ESP_LMAC_KEY_TYPE_GTK.
 */
void      esp_lmac_key_clear(esp_lmac_vif_t vif, esp_lmac_peer_id_t peer_id,
                             esp_lmac_key_type_t type, uint8_t key_idx);

/**
 * @brief Clear all hardware key slots owned by a VIF and return its crypto engine to bypass.
 *
 * Preserves hardware broadcast placeholder slots 0 and 1. Runs serialized on
 * the Wi-Fi worker task.
 *
 * @param vif  Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 */
void      esp_lmac_key_clear_vif(esp_lmac_vif_t vif);

/**
 * @brief Read back the decoded hardware configuration and key bytes of a key slot.
 *
 * Diagnostic/inspection helper; any output pointer may be NULL to skip reading
 * that field. Runs serialized on the Wi-Fi worker task.
 *
 * @param slot         Hardware key slot index (0..24).
 * @param vif_out      Optional output for slot VIF index (0 or 1).
 * @param cipher_out   Optional output for decoded esp_lmac_cipher_t.
 * @param key_idx_out  Optional output for 802.11 key ID (0..3).
 * @param addr_out     Optional 6-byte output buffer for the slot MAC/BSSID address.
 * @param key_out      Optional output buffer for raw key material (up to 32 bytes).
 * @param key_len      Number of key bytes to copy into @p key_out.
 * @return             ESP_OK on success, or ESP_ERR_INVALID_ARG if @p slot >= 25.
 */
esp_err_t esp_lmac_key_read_slot(uint8_t slot, uint8_t *vif_out, esp_lmac_cipher_t *cipher_out,
                                 uint8_t *key_idx_out, uint8_t addr_out[6],
                                 uint8_t *key_out, uint8_t key_len);

/* --------------------------------------------------------------------------
 * SoftAP Beacon Template & TSF / TBTT
 * -------------------------------------------------------------------------- */

/**
 * @brief Install or update the SoftAP beacon template and start TSF1/TBTT timing.
 *
 * Allocates a DRAM copy of @p frame with 4-byte FCS padding. Intervals below
 * 10 TU default to 100 TU. On first activation, resets TSF1 and arms MAC Timer 1
 * for periodic TBTT interrupts. Runs serialized on the Wi-Fi worker task.
 *
 * @param vif                 Must be ESP_LMAC_VIF_AP.
 * @param frame               Beacon frame bytes excluding FCS (36..512 bytes).
 * @param len                 Length of @p frame in bytes.
 * @param tim_ie_offset       Byte offset of the TIM information element in @p frame.
 * @param beacon_interval_tu  Beacon interval in 802.11 Time Units (1 TU = 1024 us).
 * @return                    ESP_OK on success, ESP_ERR_INVALID_ARG on invalid args,
 *                            or ESP_ERR_NO_MEM if DRAM template allocation fails.
 */
esp_err_t esp_lmac_set_beacon(esp_lmac_vif_t vif, const uint8_t *frame, uint16_t len,
                              uint16_t tim_ie_offset, uint16_t beacon_interval_tu);

/**
 * @brief Stop SoftAP beaconing, disarm MAC Timer 1, flush pending beacon TX, and free template.
 *
 * Runs serialized on the Wi-Fi worker task. No-op for non-AP VIFs.
 *
 * @param vif  Virtual interface index (must be ESP_LMAC_VIF_AP).
 */
void      esp_lmac_stop_beacon(esp_lmac_vif_t vif);

/**
 * @brief Read the 64-bit hardware TSF timestamp (microseconds) for a VIF.
 *
 * Uses a hi-lo-hi read loop to guarantee a tear-free 64-bit snapshot from
 * TSF0 (STA) or TSF1 (SoftAP).
 *
 * @param vif  Virtual interface index (ESP_LMAC_VIF_AP selects TSF1; else TSF0).
 * @return     64-bit TSF counter value in microseconds.
 */
uint64_t  esp_lmac_get_tsf_us(esp_lmac_vif_t vif);

/**
 * @brief Read the 32-bit free-running 1 MHz (1 us) WDEV MAC hardware clock.
 *
 * @return Current WDEV MAC time counter in microseconds.
 */
uint32_t  esp_lmac_get_mac_time_us(void);

/**
 * @brief Read a 32-bit pseudo-random word from the WDEV hardware RNG/backoff register.
 *
 * @return 32-bit hardware random value.
 */
uint32_t  esp_lmac_get_hw_rand(void);

/* --------------------------------------------------------------------------
 * Promiscuous / Sniffer Mode
 * -------------------------------------------------------------------------- */

/**
 * @brief Enter promiscuous/sniffer mode and route raw over-the-air frames to on_sniffer_frame().
 *
 * Lazily allocates the 16-entry `snf_ring` for NMI `SNIFFER_END` captures, opens
 * MAC/BSSID filters, switches hardware crypto to raw bypass while keeping
 * RX_OPTION bit 18 enabled, clears baseband sniffer filter bits, waits 15 ms
 * for baseband settle, and disables hardware auto-ACK. Runs on the Wi-Fi worker.
 *
 * @param filter_mask       Packet type filter bitmask (0 defaults to WIFI_PROMIS_FILTER_MASK_ALL).
 * @param ctrl_filter_mask  Control-frame subtype filter bitmask.
 * @return                  ESP_OK on completion, or ESP_ERR_NO_MEM if `snf_ring` allocation fails.
 */
esp_err_t esp_lmac_sniffer_enable(uint32_t filter_mask, uint32_t ctrl_filter_mask);

/**
 * @brief Exit promiscuous/sniffer mode and cleanly restore normal MAC/crypto filters.
 *
 * Disables sniffer NMI interrupts, waits for any in-flight NMI (`NMIIrqIsOn == 0`)
 * before freeing `snf_ring`, re-enables auto-ACK and baseband filtering, restores
 * VIF0 MAC/BSSID filters and per-VIF crypto registers, and preserves RX_OPTION
 * bit 18 so subsequent encrypted frames continue decrypting. Runs on the Wi-Fi worker.
 */
void      esp_lmac_sniffer_disable(void);

/**
 * @brief Update the software promiscuous packet and control-frame filter masks.
 *
 * Runs serialized on the Wi-Fi worker task.
 *
 * @param filter_mask       Packet type filter bitmask.
 * @param ctrl_filter_mask  Control-frame subtype filter bitmask.
 */
void      esp_lmac_sniffer_set_filter(uint32_t filter_mask, uint32_t ctrl_filter_mask);

/**
 * @brief Read the active software promiscuous packet and control-frame filter masks.
 *
 * Runs serialized on the Wi-Fi worker task. Either pointer may be NULL.
 *
 * @param filter_mask       Optional output for packet type filter bitmask.
 * @param ctrl_filter_mask  Optional output for control-frame subtype filter bitmask.
 */
void      esp_lmac_sniffer_get_filter(uint32_t *filter_mask, uint32_t *ctrl_filter_mask);

/* --------------------------------------------------------------------------
 * Hardware RX Block-Ack Scoreboards (0..3, max 4 sessions)
 * -------------------------------------------------------------------------- */

/**
 * @brief Return true if a hardware RX BA scoreboard slot is available or already assigned to (peer_id, tid).
 *
 * Runs serialized on the Wi-Fi worker task. Returns false when
 * CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED is disabled or ampdu_rx_enable is 0.
 *
 * @param peer_id  Valid peer ID whose MAC address owns the BA session.
 * @param tid      802.11 QoS Traffic Identifier (0..7).
 * @return         true when esp_lmac_add_rx_ba() can accept the session.
 */
bool      esp_lmac_can_add_rx_ba(esp_lmac_peer_id_t peer_id, uint8_t tid);

/**
 * @brief Program or update one of the 4 active hardware RX Block-Ack scoreboards for a peer/TID.
 *
 * Reuses an existing scoreboard slot if `(peer_id, tid)` is already active.
 * Runs serialized on the Wi-Fi worker task. Returns ESP_ERR_NOT_SUPPORTED when
 * CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED is disabled or `cfg.ampdu_rx_enable == 0`.
 *
 * @param peer_id   Valid peer ID whose MAC address owns the BA session.
 * @param tid       802.11 QoS Traffic Identifier (0..7).
 * @param ssn       12-bit Starting Sequence Number (0..4095).
 * @param win_size  Block-Ack reorder window size (1..64).
 * @return          ESP_OK on success, ESP_ERR_INVALID_ARG on invalid peer/tid/win_size,
 *                  ESP_ERR_NO_MEM if all 4 active hardware scoreboards are occupied, or
 *                  ESP_ERR_NOT_SUPPORTED if A-MPDU RX is disabled.
 */
esp_err_t esp_lmac_add_rx_ba(esp_lmac_peer_id_t peer_id, uint8_t tid, uint16_t ssn, uint8_t win_size);

/**
 * @brief Remove and clear the hardware RX Block-Ack scoreboard for a peer/TID.
 *
 * Runs serialized on the Wi-Fi worker task. No-op when A-MPDU RX is disabled
 * or if no matching scoreboard entry is active.
 *
 * @param peer_id  Valid peer ID whose BA session is being torn down.
 * @param tid      802.11 QoS Traffic Identifier (0..7).
 */
void      esp_lmac_del_rx_ba(esp_lmac_peer_id_t peer_id, uint8_t tid);

/* --------------------------------------------------------------------------
 * Power-Save Lock Status & Hardware MAC Soft Reset / Diagnostics
 * -------------------------------------------------------------------------- */

/**
 * @brief Query whether Wi-Fi modem-sleep power-saving is currently locked out.
 *
 * @return true if one or more esp_wifi_ps_lock() holds are active; false otherwise.
 */
bool      esp_lmac_ps_is_locked(void);

/**
 * @brief Perform a 5-bank hardware WDEV MAC soft reset while preserving state.
 *
 * Saves all 5 WDEV register banks plus live RX BA scoreboard SSNs into a
 * temporary heap buffer under an interrupt lock, pulses the RTC/PHY MAC reset
 * bits, restores all registers and live SSNs, reprograms RX DMA bounds, and
 * re-enables the MAC engine. Runs serialized on the Wi-Fi worker task.
 */
void      esp_lmac_hw_mac_reset(void);

typedef struct esp_lmac_stats {
    uint32_t nmi_count;
    uint32_t rx_nmi_frames;
    uint32_t rx_nmi_drops;
    uint32_t rx_delivered;
    uint32_t tx_submitted;
    uint32_t tx_ok;
    uint32_t tx_fail;
    uint32_t tx_retries;
    uint32_t tx_timeouts;
    uint32_t tbtt_count;
    uint32_t mac_resets;
} esp_lmac_stats_t;

/**
 * @brief Copy a snapshot of cumulative LMAC diagnostic counters.
 *
 * No-op if @p out is NULL.
 *
 * @param out  Destination structure to receive the telemetry snapshot.
 */
void      esp_lmac_get_stats(esp_lmac_stats_t *out);

#ifdef __cplusplus
}
#endif
