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
    uint8_t  ht20_mcs_mask;  /* MCS0..7 bitmask (Milestone 6C; 0 for 11b/g) */
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
    uint16_t rx_buf_len;                  /* Default WIFI_HW_RX_BUFFER_LEN (524) */
    uint16_t rx_max_single_pkt_len;       /* Default WIFI_RX_MAX_SINGLE_PKT_LEN (1076 or 1600) */
} esp_lmac_config_t;

/* Lifecycle & Event Pump (all non-ISR calls run serialized on the Wi-Fi worker task) */
esp_err_t esp_lmac_init(const esp_lmac_config_t *cfg, const esp_lmac_callbacks_t *cbs);
esp_err_t esp_lmac_deinit(void);
bool      esp_lmac_process_events(uint8_t max_rx_batch, uint8_t max_tx_batch);
void      esp_lmac_housekeeping_100ms(void);

/* RX Buffer Ownership & Ring Headroom */
uint8_t   esp_lmac_rx_free_contiguous(void);
void      esp_lmac_rx_free(esp_lmac_rx_buf_t *rx_buf);

/* TX Submission & Queue Control */
esp_err_t esp_lmac_tx_submit(const esp_lmac_tx_req_t *req);
void      esp_lmac_tx_flush_vif(esp_lmac_vif_t vif);
bool      esp_lmac_tx_is_idle(void);
bool      esp_lmac_tx_has_free_slot(void);

/* Virtual Interface, Filter, Channel & RF Power Gating */
esp_err_t esp_lmac_vif_enable(esp_lmac_vif_t vif, const uint8_t mac[6]);
void      esp_lmac_vif_disable(esp_lmac_vif_t vif);
void      esp_lmac_set_bssid_filter(esp_lmac_vif_t vif, const uint8_t bssid[6], bool enable);
void      esp_lmac_set_scan_rx_mode(bool scanning);
esp_err_t esp_lmac_set_channel(uint8_t primary_chan);
uint8_t   esp_lmac_get_channel(void);
void      esp_lmac_rf_open(void);
void      esp_lmac_rf_close(void);
bool      esp_lmac_rf_is_closed(void);

/* Peer / Rate Control (TRC) & Hardware Crypto Key Slots (LMAC-managed 0..24) */
esp_err_t esp_lmac_peer_alloc_ap_pool(uint8_t max_ap_peers);
void      esp_lmac_peer_free_ap_pool(void);
esp_lmac_peer_id_t esp_lmac_peer_add(esp_lmac_vif_t vif, const esp_lmac_peer_caps_t *caps);
void      esp_lmac_peer_remove(esp_lmac_peer_id_t peer_id);
int8_t    esp_lmac_peer_get_rssi(esp_lmac_peer_id_t peer_id);
void      esp_lmac_peer_update_rssi(esp_lmac_peer_id_t peer_id, int8_t rssi);
void      esp_lmac_set_protocol_mask(esp_lmac_vif_t vif, uint8_t proto_bitmap);

esp_err_t esp_lmac_key_set(esp_lmac_vif_t vif, esp_lmac_peer_id_t peer_id,
                           esp_lmac_key_type_t type, uint8_t key_idx,
                           esp_lmac_cipher_t cipher, const uint8_t *key, uint8_t key_len);
void      esp_lmac_key_clear(esp_lmac_vif_t vif, esp_lmac_peer_id_t peer_id,
                             esp_lmac_key_type_t type, uint8_t key_idx);
void      esp_lmac_key_clear_vif(esp_lmac_vif_t vif);
esp_err_t esp_lmac_key_read_slot(uint8_t slot, uint8_t *vif_out, esp_lmac_cipher_t *cipher_out,
                                 uint8_t *key_idx_out, uint8_t addr_out[6],
                                 uint8_t *key_out, uint8_t key_len);

/* SoftAP Beacon Template & TSF / TBTT */
esp_err_t esp_lmac_set_beacon(esp_lmac_vif_t vif, const uint8_t *frame, uint16_t len,
                              uint16_t tim_ie_offset, uint16_t beacon_interval_tu);
void      esp_lmac_stop_beacon(esp_lmac_vif_t vif);
uint64_t  esp_lmac_get_tsf_us(esp_lmac_vif_t vif);
uint32_t  esp_lmac_get_mac_time_us(void);
uint32_t  esp_lmac_get_hw_rand(void);

/* Promiscuous / Sniffer Mode */
esp_err_t esp_lmac_sniffer_enable(uint32_t filter_mask, uint32_t ctrl_filter_mask);
void      esp_lmac_sniffer_disable(void);
void      esp_lmac_sniffer_set_filter(uint32_t filter_mask, uint32_t ctrl_filter_mask);
void      esp_lmac_sniffer_get_filter(uint32_t *filter_mask, uint32_t *ctrl_filter_mask);

/* Milestone 6C: Hardware RX Block-Ack Scoreboards (0..7); ESP_ERR_NOT_SUPPORTED when AMPDU_RX=n */
esp_err_t esp_lmac_add_rx_ba(esp_lmac_peer_id_t peer_id, uint8_t tid, uint16_t ssn, uint8_t win_size);
void      esp_lmac_del_rx_ba(esp_lmac_peer_id_t peer_id, uint8_t tid);

/* Power-save lock status helper for net80211 PM */
bool      esp_lmac_ps_is_locked(void);

/* Hardware MAC soft reset & diagnostics */
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

void      esp_lmac_get_stats(esp_lmac_stats_t *out);

#ifdef __cplusplus
}
#endif
