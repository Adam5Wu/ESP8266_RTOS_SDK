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

#include "sdkconfig.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"

#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_private/wifi.h"
#include "esp_event_legacy.h"
#include "esp_aio.h"
#include "esp_lmac.h"
#include "rom/ets_sys.h"

/* wpa_supplicant driver glue types (components/wpa_supplicant/src/esp_supplicant/) */
#ifndef u8
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#endif
#include "esp_wps.h"
#include "esp_wifi_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * 802.11 Frame Control, Subtypes, Header Layout & Information Elements
 * -------------------------------------------------------------------------- */

/** Frame Control byte 0 masks and frame type values (IEEE 802.11-2016 §9.2.4.1). */
#define IEEE80211_FC_TYPE_MASK          0x0CU
#define IEEE80211_FC_TYPE_MGMT          0x00U
#define IEEE80211_FC_TYPE_CTRL          0x04U
#define IEEE80211_FC_TYPE_DATA          0x08U
#define IEEE80211_FC_SUBTYPE_MASK       0xF0U

/** Management frame subtypes (shifted into Frame Control byte 0 bits [7:4]). */
#define IEEE80211_SUBTYPE_ASSOC_REQ     0x00U
#define IEEE80211_SUBTYPE_ASSOC_RESP    0x10U
#define IEEE80211_SUBTYPE_REASSOC_REQ   0x20U
#define IEEE80211_SUBTYPE_REASSOC_RESP  0x30U
#define IEEE80211_SUBTYPE_PROBE_REQ     0x40U
#define IEEE80211_SUBTYPE_PROBE_RESP    0x50U
#define IEEE80211_SUBTYPE_BEACON        0x80U
#define IEEE80211_SUBTYPE_DISASSOC      0xA0U
#define IEEE80211_SUBTYPE_AUTH          0xB0U
#define IEEE80211_SUBTYPE_DEAUTH        0xC0U
#define IEEE80211_SUBTYPE_ACTION        0xD0U

/** Control frame subtypes. */
#define IEEE80211_SUBTYPE_PS_POLL       0xA0U /* CTRL */

/** Data frame subtypes. */
#define IEEE80211_SUBTYPE_DATA          0x00U
#define IEEE80211_SUBTYPE_NULLFUNC      0x40U
#define IEEE80211_SUBTYPE_QOS_DATA      0x80U
#define IEEE80211_SUBTYPE_QOS_NULL      0xC0U

/** Frame Control byte 1 flag bits. */
#define IEEE80211_FC1_TODS              0x01U
#define IEEE80211_FC1_FROMDS            0x02U
#define IEEE80211_FC1_MOREFRAG          0x04U
#define IEEE80211_FC1_RETRY             0x08U
#define IEEE80211_FC1_PM                0x10U
#define IEEE80211_FC1_MOREDATA          0x20U
#define IEEE80211_FC1_PROTECTED         0x40U

/** Standard 3-address 802.11 MAC header field offsets and lengths (bytes). */
#define IEEE80211_HDR_LEN               24U
#define IEEE80211_QOS_HDR_LEN           26U
#define IEEE80211_HDR_ADDR1_OFF         4U
#define IEEE80211_HDR_ADDR2_OFF         10U
#define IEEE80211_HDR_ADDR3_OFF         16U
#define IEEE80211_HDR_SEQ_OFF           22U
#define IEEE80211_ADDR_LEN              6U
#define IEEE80211_SEQ_SHIFT             4U
#define IEEE80211_SEQ_MASK              0x0FFFU

/** Beacon / Probe Response fixed-parameter length (8B TSF + 2B interval + 2B capinfo). */
#define IEEE80211_BCN_FIXED_LEN         12U
#define IEEE80211_BCN_INT_OFF           8U
#define IEEE80211_BCN_CAPINFO_OFF       10U

/** Capability Information field bits (IEEE 802.11-2016 §9.4.1.4). */
#define IEEE80211_CAPINFO_ESS           0x0001U
#define IEEE80211_CAPINFO_PRIVACY       0x0010U
#define IEEE80211_CAPINFO_SHORT_PREAMBLE 0x0020U
#define IEEE80211_CAPINFO_SHORT_SLOT    0x0400U

/** Ethernet II & LLC/SNAP framing constants (bytes). */
#define IEEE80211_ETH_HDR_LEN           14U
#define IEEE80211_LLC_SNAP_LEN          8U
#define IEEE80211_LLC_DSAP_SNAP         0xAAU
#define IEEE80211_LLC_SSAP_SNAP         0xAAU
#define IEEE80211_LLC_CTRL_UI           0x03U

/** Security header / trailer lengths (bytes). */
#define IEEE80211_WEP_IV_LEN            4U
#define IEEE80211_CCMP_HDR_LEN          8U
#define IEEE80211_CCMP_MIC_LEN          8U
#define IEEE80211_TKIP_HDR_LEN          8U
#define IEEE80211_TKIP_MIC_LEN          8U
#define IEEE80211_TKIP_EXT_IV_BIT       0x20U
#define IEEE80211_CCMP_EXT_IV_BIT       0x20U

/** Information Element IDs (IEEE 802.11-2016 §9.4.2.1). */
#define IEEE80211_IE_SSID               0U
#define IEEE80211_IE_SUPP_RATES         1U
#define IEEE80211_IE_DS_PARAM           3U
#define IEEE80211_IE_TIM                5U
#define IEEE80211_IE_COUNTRY            7U
#define IEEE80211_IE_CSA                37U
#define IEEE80211_IE_ERP_INFO           42U
#define IEEE80211_IE_HT_CAP             45U
#define IEEE80211_IE_RSN                48U
#define IEEE80211_IE_EXT_RATES          50U
#define IEEE80211_IE_HT_OP              61U
#define IEEE80211_IE_RM_ENABLED_CAP     70U
#define IEEE80211_IE_MMIE               76U
#define IEEE80211_IE_VENDOR             221U
#define IEEE80211_IE_HDR_LEN            2U
#define IEEE80211_CSA_IE_LEN            3U
#define IEEE80211_CSA_MODE_QUIET        1U
#define IEEE80211_ERP_USE_PROTECTION    0x02U
#define IEEE80211_HT_CAP_INFO_SGI20     0x20U
#define IEEE80211_HT_OP_MIN_LEN         4U
#define IEEE80211_HT_OP_PROT_OFF        2U
#define IEEE80211_HT_OP_PROT_MASK       0x03U
#define IEEE80211_RM_CAPS_LEN           5U
#define IEEE80211_CAP_RADIO_MEASUREMENT 0x1000U
#define IEEE80211_STYPE_IDX_PROBE_RESP  5U
#define IEEE80211_STYPE_IDX_BEACON      8U
#define IEEE80211_STYPE_IDX_ACTION      13U
#define IEEE80211_OUI_MS_0              0x00U
#define IEEE80211_OUI_MS_1              0x50U
#define IEEE80211_OUI_MS_2              0xF2U
#define IEEE80211_OUI_TYPE_WPA          0x01U
#define IEEE80211_OUI_TYPE_WMM          0x02U
#define IEEE80211_OUI_TYPE_WPS          0x04U
#define IEEE80211_WPS_OUI_HDR_LEN       4U
#define N8_EAPOL_HDR_LEN                4U
#define N8_EAPOL_TYPE_KEY               3U
#define IEEE80211_WMM_SUBTYPE_INFO      0x00U
#define IEEE80211_WMM_SUBTYPE_PARAM     0x01U
#define IEEE80211_WMM_VERSION           0x01U
#define IEEE80211_WMM_IE_MIN_BODY_LEN   7U
#define IEEE80211_WMM_INFO_IE_LEN       9U
#define IEEE80211_WMM_PARAM_IE_LEN      26U

/** Authentication algorithm numbers (IEEE 802.11-2016 §9.4.1.1). */
#define IEEE80211_AUTH_ALG_OPEN         0U
#define IEEE80211_AUTH_ALG_SHARED       1U
#define IEEE80211_AUTH_ALG_SAE          3U

/** Action frame categories and action codes (Block Ack & SA Query). */
#define IEEE80211_CAT_SPECTRUM_MGMT     0U
#define IEEE80211_CAT_QOS               1U
#define IEEE80211_CAT_DLS               2U
#define IEEE80211_CAT_BA                3U
#define IEEE80211_CAT_PUBLIC            4U
#define IEEE80211_CAT_RRM               5U
#define IEEE80211_CAT_FT                6U
#define IEEE80211_CAT_HT                7U
#define IEEE80211_CAT_SA_QUERY          8U
#define IEEE80211_CAT_PROT_DUAL_PUB     9U
#define IEEE80211_CAT_WNM               10U
#define IEEE80211_CAT_UNPROT_WNM        11U
#define IEEE80211_CAT_SELF_PROT         15U
#define IEEE80211_CAT_WMM               17U
#define IEEE80211_CAT_UNPROT_DMG        20U
#define IEEE80211_CAT_VHT               21U
#define IEEE80211_CAT_VENDOR_PROT       126U
#define IEEE80211_CAT_VENDOR            127U
#define IEEE80211_CAT_ERR_BIT           0x80U

#define IEEE80211_BA_ACTION_ADDBA_REQ   0U
#define IEEE80211_BA_ACTION_ADDBA_RESP  1U
#define IEEE80211_BA_ACTION_DELBA       2U
#define IEEE80211_SA_QUERY_REQ          0U
#define IEEE80211_SA_QUERY_RESP         1U

/** Additional 802.11 QoS, crypto, MMIE, and replay-window constants. */
#define IEEE80211_QOS_CTRL_LEN          2U
#define IEEE80211_QOS_TID_MASK          0x07U
#define IEEE80211_QOS_AMSDU_BIT         0x80U
#define IEEE80211_FRAG_NUM_MASK         0x000FU
#define IEEE80211_CCMP_KEY_LEN          16U
#define IEEE80211_TKIP_ICV_LEN          4U
#define IEEE80211_TKIP_TRAILER_LEN      (IEEE80211_TKIP_MIC_LEN + IEEE80211_TKIP_ICV_LEN)
#define IEEE80211_PN_BYTES              6U
#define IEEE80211_MMIE_LEN              18U
#define IEEE80211_MMIE_IPN_OFF          4U
#define IEEE80211_MMIE_MIC_OFF          10U

#define N8_MAC_MCAST_BIT                0x01U
#define N8_MAX_TID                      8U
#define N8_NON_QOS_TID                  8U
#define N8_REPLAY_TID_SLOTS             9U
#define N8_GTK_REPLAY_SLOTS             2U
#define N8_REPLAY_WIN_BITS              64U
#define N8_FREQ_OFFSET_INVALID          ((int16_t)0x7FFF)
#define N8_RSSI_THRESHOLD_MIN           (-100)
#define N8_RSSI_THRESHOLD_MAX           0
#define N8_STA_MIN_INACTIVE_SEC         3U
#define N8_AP_MIN_INACTIVE_SEC          10U
#define N8_VND_IE_TYPE_COUNT            5U
#define N8_VND_IE_ID_COUNT              2U
#define N8_VND_IE_MIN_LEN               4U

typedef struct {
    uint8_t *slots[N8_VND_IE_TYPE_COUNT][N8_VND_IE_ID_COUNT];
} n8_vendor_ie_table_t;

/** EAPOL EtherType (0x888E) high/low bytes. */
#define ETH_P_EAPOL_H                   0x88U
#define ETH_P_EAPOL_L                   0x8EU

/** Data-plane async TX job ring capacity (power of 2) and SoftAP PS buffer cap. */
#define N8_TX_RING_SIZE                 16U
#define N8_TX_RING_MASK                 (N8_TX_RING_SIZE - 1U)
_Static_assert((N8_TX_RING_SIZE & N8_TX_RING_MASK) == 0U, "N8_TX_RING_SIZE must be power of 2");
#define N8_AP_PS_MAX_PKTS               4U

/** 2.4 GHz channel range and default TX power limit (quarter-dBm: 78 = 19.5 dBm). */
#define N8_CHANNEL_MIN                  1U
#define N8_CHANNEL_MAX                  14U
#define N8_MAX_SSID_LEN                 32U
#define N8_PMK_LEN                      32U
#define N8_TKIP_MIC_KEY_LEN             8U
#define N8_TX_POWER_MIN_QDBM            8
#define N8_TX_POWER_MAX_QDBM            84
#define N8_WPA_PROTO_WPA                1U
#define N8_WPA_PROTO_RSN                2U

/* --------------------------------------------------------------------------
 * Supplicant App IE Slot (supports both copied IEs and live assoc_ie_buf+2)
 * -------------------------------------------------------------------------- */

struct wifi_appie {
    uint16_t ie_len;
    uint8_t  ie_data[1];
};

typedef struct {
    uint8_t *buf;        /* Heap copy (flag=0) or live pointer to assoc_ie_buf (flag=1) */
    uint16_t len;
    uint8_t  live_ptr;   /* Non-zero when buf points to wpa_supplicant's assoc_ie_buf (+2 offset) */
    uint8_t  in_use;
} n8_appie_slot_t;

/* --------------------------------------------------------------------------
 * Worker Event Queue & Synchronous RPC
 * -------------------------------------------------------------------------- */

typedef enum {
    N8_EVT_NONE = 0,
    N8_EVT_LMAC,
    N8_EVT_ETS_TIMER,
    N8_EVT_TX,
    N8_EVT_API,
    N8_EVT_TICK_100MS,
    N8_EVT_STOP_WORKER,
} n8_evt_type_t;

typedef esp_err_t (*n8_api_fn_t)(void *arg);

typedef struct {
    n8_api_fn_t       fn;
    void             *arg;
    esp_err_t         ret;
    SemaphoreHandle_t done_sem;
} n8_api_req_t;

typedef struct {
    uint8_t  type;
    void    *ptr;
} n8_evt_t;

/* --------------------------------------------------------------------------
 * TX Queue Job (Copies esp_aio_t by Value for Async LMAC Completion)
 * -------------------------------------------------------------------------- */

typedef struct {
    esp_aio_t aio;
    uint8_t   in_use;
    uint8_t   is_eapol;
    uint8_t   vif;
} n8_tx_job_t;

/* --------------------------------------------------------------------------
 * STA MLME State Machine
 * -------------------------------------------------------------------------- */

typedef enum {
    N8_STA_IDLE = 0,
    N8_STA_SCANNING,
    N8_STA_AUTH,
    N8_STA_ASSOC,
    N8_STA_4WAY,
    N8_STA_RUN,
} n8_sta_state_t;

typedef enum {
    N8_PM_AWAKE = 0,
    N8_PM_ENTERING_SLEEP,
    N8_PM_SLEEPING,
    N8_PM_WAKING,
} n8_pm_state_t;

typedef void (*n8_scan_done_cb_t)(void *arg, STATUS status);

/** Compact 64-packet sliding-window RX PN/TSC replay state (0ULL bitmap == uninitialized). */
typedef struct {
    uint64_t max_pn;
    uint64_t bitmap;
} n8_replay_win_t;

_Static_assert(sizeof(n8_replay_win_t) == 16U, "n8_replay_win_t must be 16 bytes");

/* --------------------------------------------------------------------------
 * Mode-Scoped SoftAP Peer Slab & PS Buffer Node (Heap-Allocated on AP Start)
 * -------------------------------------------------------------------------- */

typedef struct {
    uint8_t            in_use;
    uint8_t            aid;           /* 1..max_connection */
    uint8_t            mac[6];
    uint8_t            authed;
    uint8_t            assoced;
    uint8_t            authorized;    /* True when open or 4-way PTK done */
    uint8_t            ps_sleeping;   /* STA PM=1 */
    uint8_t            qos_enabled;
    uint8_t            ht_enabled;
    uint8_t            phy_11b;
    uint8_t            phy_11g;
    uint8_t            phy_11n;
    uint8_t            ptk_cipher;    /* esp_lmac_cipher_t */
    uint8_t            ptk_key_idx;
    esp_lmac_peer_id_t peer_id;
    uint16_t           last_rx_seq_valid;
    uint16_t           last_rx_seq[N8_REPLAY_TID_SLOTS];
    uint32_t           last_rx_sec;
    uint64_t           tx_pn;
    n8_replay_win_t    ptk_pn[N8_REPLAY_TID_SLOTS];
    void              *wpa_sm;        /* Supplicant per-STA SM from wpa_ap_join */
} n8_ap_sta_t;

typedef struct n8_ps_pkt {
    struct n8_ps_pkt *next;
    uint8_t           aid;            /* 0 = broadcast/multicast, 1..max = unicast STA */
    uint16_t          len;            /* Full Ethernet frame length */
    uint8_t           data[0];
} n8_ps_pkt_t;

/* --------------------------------------------------------------------------
 * Transient Scan State (List Heap-Allocated During Scan, Freed on Clear/Stop)
 * -------------------------------------------------------------------------- */

typedef struct {
    wifi_ap_record_t  rec;
    uint16_t          capinfo;
    uint16_t          rate_mask_11bg;
    uint8_t           ht_mcs_mask;
    uint8_t           ht_cap;
    uint8_t           ht_sgi20;
    uint8_t           wmm_cap;
    uint8_t           pmf_capable;
    uint8_t           pmf_required;
    uint8_t           akm_sae;
    uint8_t           akm_psk_sha256;
    uint8_t           akm_psk;
    uint8_t           wpa_proto;     /* 1=WPA, 2=RSN, 3=both */
    uint8_t           mgmt_cipher;   /* wifi_cipher_type_t */
    uint8_t           beacon_int;
} n8_scan_entry_t;

/* --------------------------------------------------------------------------
 * Unified Net80211 Context (Compact Static DRAM, Zero SHN_COMMON)
 * -------------------------------------------------------------------------- */

typedef struct {
    /* Lifecycle & worker */
    bool              initialized;
    bool              started;
    bool              worker_running;
    volatile uint8_t  lmac_evt_queued;
    volatile uint8_t  tx_evt_queued;
    volatile uint8_t  timer_evt_queued;
    TaskHandle_t      worker_task;
    QueueHandle_t     evt_queue;
    SemaphoreHandle_t api_mutex;
    wifi_init_config_t init_cfg;

    /* Configuration & mode */
    wifi_mode_t       mode;
    wifi_storage_t    storage;
    wifi_ps_type_t    ps_type;
    wifi_country_t    country;
    wifi_country_t    sta_ap_country;
    uint8_t           sta_ap_country_valid;
    wifi_config_t     sta_cfg;
    wifi_config_t     ap_cfg;
    uint8_t           sta_mac[6];
    uint8_t           ap_mac[6];
    uint8_t           proto[2];        /* WIFI_PROTOCOL_11B|11G|11N */
    uint8_t           bandwidth[2];    /* WIFI_BW_HT20 */
    uint8_t           cur_channel;
    uint8_t           auto_connect;
    int8_t            max_tx_power;    /* quarter-dBm (8..84) */
    uint32_t          event_mask;
    uint16_t          inactive_sec[2];
    int32_t           rssi_threshold;
    uint8_t           rssi_thresh_armed;
    uint8_t           user_init_flag;

    /* Derived STA PMK & SSID helper (for wpa_supplicant glue) */
    struct wifi_ssid  sta_ssid_box;
    struct wifi_ssid  ap_ssid_box;
    uint8_t           sta_pmk[32];
    uint8_t           ap_pmk[32];
    uint8_t           sta_reset_param;
    uint8_t           rtc_cached_ch;
    uint8_t           rtc_cached_bssid[6];
    uint8_t           rtc_cache_valid;

    /* STA connection state */
    n8_sta_state_t    sta_state;
    uint8_t           sta_connect_req;
    uint8_t           sta_bssid[6];
    uint8_t           sta_ssid[33];
    uint8_t           sta_ssid_len;
    uint8_t           sta_channel;
    uint16_t          sta_aid;
    uint16_t          sta_capinfo;
    uint16_t          sta_beacon_int;
    uint8_t           sta_dtim_period;
    uint8_t           sta_authmode;       /* wifi_auth_mode_t */
    uint8_t           sta_beacon_authmode;/* Advertised AP authmode from beacon/probe */
    uint8_t           sta_supp_authmode;  /* WPA2_AUTH_PSK / WPA3_AUTH_PSK / etc. */
    uint8_t           sta_wpa_proto;      /* 1=WPA, 2=RSN */
    uint8_t           sta_pairwise_cipher;/* wifi_cipher_type_t */
    uint8_t           sta_group_cipher;   /* wifi_cipher_type_t */
    uint8_t           sta_mgmt_cipher;    /* wifi_cipher_type_t */
    uint8_t           sta_pmf_active;
    uint8_t           sta_ht_active;
    uint8_t           sta_qos_active;
    uint8_t           sta_ap_wps;
    uint8_t           sta_ap_phy_11b;
    uint8_t           sta_ap_phy_11g;
    uint8_t           sta_tsf_valid;
    uint8_t           sta_rxmax_ext_state;
    int16_t           sta_last_freq_offset;
    uint8_t           sta_sae_seq;        /* 1=Commit, 2=Confirm */
    uint8_t           sta_auth_retries;
    uint8_t           sta_ptk_cipher;     /* esp_lmac_cipher_t */
    uint8_t           sta_gtk_cipher;     /* esp_lmac_cipher_t */
    uint8_t           sta_gtk_key_idx;
    esp_lmac_peer_id_t sta_peer_id;
    uint8_t           sta_ptk_key[IEEE80211_CCMP_KEY_LEN];
    uint8_t           sta_ptk_key_valid;
    uint8_t           sta_rx_mgmt_pn_valid;
    uint8_t           sta_rx_bip_ipn_valid;
    uint8_t           sa_query_active;
    uint8_t           sa_query_ticks;
    uint8_t           sa_query_tid[2];
    uint16_t          sta_tx_seq;
    uint16_t          sta_last_rx_seq_valid;
    uint16_t          sta_last_rx_seq[N8_REPLAY_TID_SLOTS];
    uint64_t          sta_tx_pn;
    uint64_t          sta_tx_mgmt_pn;
    uint64_t          sta_rx_mgmt_pn;
    uint64_t          sta_rx_bip_ipn;
    int64_t           sta_tsf_diff_us;
    n8_replay_win_t   sta_rx_ptk_pn[N8_REPLAY_TID_SLOTS];
    n8_replay_win_t   sta_rx_gtk_pn[N8_GTK_REPLAY_SLOTS];
    uint8_t           sta_igtk_valid;
    uint8_t           sta_scan_connect_pass; /* 0 = cached/hint chan probe, 1 = full sweep */
    wifi_wpa_igtk_t   sta_igtk;
    uint16_t          sta_state_ticks;    /* 100 ms ticks in current auth/assoc/4way state */
    uint32_t          sta_bcn_miss_ticks; /* 100 ms ticks since last AP beacon */
    uint8_t           sta_csa_active;     /* CSA IE 37 countdown active */
    uint8_t           sta_csa_mode;       /* CSA mode (1 = quiet / pause STA TX) */
    uint8_t           sta_csa_new_ch;     /* CSA target channel (1..14) */
    uint8_t           sta_csa_count;      /* Remaining TBTTs until channel switch */
    uint8_t           sta_csa_tx_paused;  /* Non-zero while STA data TX paused for CSA */
    uint8_t           sta_erp_prot;       /* ERP/HT protection active on connected AP */
    uint8_t           sta_tx_retry_burst; /* Consecutive STA heavy-retry/fail burst count */

    /* STA Modem Sleep (TSF-synced us wake timer + pm_config) */
    n8_pm_state_t     pm_state;
    uint16_t          pm_idle_ticks;      /* 100 ms idle ticks */
    uint32_t          pm_wake_time_us;
    uint32_t          pm_last_bcn_us;
    ETSTimer          pm_wake_timer;
    esp_pm_config_t   pm_cfg;
    uint8_t           pm_timer_inited;

    /* SoftAP state (peer slab heap-allocated only while AP/APSTA active) */
    uint8_t           ap_running;
    void             *ap_hapd;            /* hostapd_data from wpa_ap_init() */
    n8_ap_sta_t      *ap_stas;            /* Contiguous slab of ap_sta_cap entries */
    uint8_t           ap_sta_cap;
    uint8_t           ap_gtk_cipher;      /* esp_lmac_cipher_t */
    uint8_t           ap_gtk_key_idx;
    uint64_t          ap_gtk_pn;
    uint16_t          ap_tx_seq;
    uint8_t           ap_dtim_count;
    uint8_t           ap_dtim_period;
    uint16_t          ap_tim_offset;
    uint32_t          ap_uptime_sec;
    uint8_t           ap_sec_subtick;
    n8_ps_pkt_t      *ap_ps_head;
    n8_ps_pkt_t      *ap_ps_tail;
    uint8_t           ap_ps_count;

    /* Scan state */
    ETSTimer          scan_timer;
    uint8_t           scan_timer_inited;
    uint8_t           scan_active;
    uint8_t           scan_for_connect;
    uint8_t           scan_passive;
    uint8_t           scan_assoc_mode;  /* 1 if scan started while STA is RUN */
    uint8_t           scan_phase;       /* 0=probe1, 1=probe2/dwell, 2=home_visit, 3=pm_wait */
    uint8_t           scan_ch_idx;
    uint8_t           scan_ch_cnt;
    uint8_t           scan_ch_list[14];
    uint16_t          scan_active_ms;
    uint16_t          scan_passive_ms;
    uint8_t           scan_target_ssid[33];
    uint8_t           scan_target_ssid_len;
    uint8_t           scan_target_bssid[6];
    uint8_t           scan_use_bssid;
    uint8_t           scan_show_hidden;
    n8_scan_entry_t  *scan_results;
    uint16_t          scan_result_cnt;
    uint16_t          scan_result_cap;
    SemaphoreHandle_t scan_done_sem;
    n8_scan_done_cb_t scan_done_cb;

    /* Supplicant callbacks & App IEs */
    struct wpa_funcs  *wpa_cb;
    struct wpa2_funcs *wpa2_cb;
    struct wps_funcs  *wps_cb;
    wifi_tx_cb_t       tx_cbs[8];
    n8_appie_slot_t    appies[WIFI_APPIE_MAX];
    int                wps_type;
    int                wps_status;
    uint8_t            wps_start_flag;
    uint8_t            sta_conn_timer_disarmed;
    wpa2_ent_eap_state_t wpa2_ent_state;
#ifdef CONFIG_WPA_11KV_SUPPORT
    uint32_t           frame_reg_type;
    uint32_t           frame_reg_subtype;
#endif

    /* Promiscuous & Data Plane hooks */
    uint8_t                 promis_enabled;
    wifi_promiscuous_cb_t   promis_cb;
    wifi_sta_rx_probe_req_t probe_req_cb;
    esp_vendor_ie_cb_t      vendor_ie_cb;
    void                   *vendor_ie_ctx;
    n8_vendor_ie_table_t   *vendor_ies;
    wifi_rxcb_t             rxcb[2];
    n8_tx_job_t             tx_jobs[N8_TX_RING_SIZE];
    uint8_t                 tx_q_head;
    uint8_t                 tx_q_tail;
    uint8_t                 tx_pending_idx[N8_TX_RING_SIZE];
} net80211_ctx_t;

extern net80211_ctx_t g_n8;

/** @brief Return true when QoS/WMM is enabled via init_cfg.qos_enable or ampdu_rx_enable. */
static inline bool n8_qos_cfg_enabled(void)
{
    return (g_n8.init_cfg.qos_enable != 0U) || (g_n8.init_cfg.ampdu_rx_enable != 0U);
}

/** @brief Return true when a WPS enrollee exchange is pending STA association/EAPOL. */
static inline bool n8_wps_is_pending(void)
{
    return (g_n8.wps_cb != NULL) &&
           (g_n8.wps_type != WPS_TYPE_DISABLE) &&
           (g_n8.wps_status == WPS_STATUS_PENDING);
}

/* --------------------------------------------------------------------------
 * Internal Module Prototypes
 * -------------------------------------------------------------------------- */

/* net80211_worker.c */
esp_err_t n8_worker_start(void);
void      n8_worker_stop(void);
bool      n8_on_worker_task(void);
esp_err_t n8_api_call(n8_api_fn_t fn, void *arg);
void      n8_post_evt(n8_evt_type_t type, void *ptr);
void      n8_send_system_event(system_event_t *evt);
int       n8_lmac_notify_from_isr(void *ctx);

/* net80211_nvs_rtc.c */
void      n8_nvs_init_defaults(void);
void      n8_nvs_load(void);
void      n8_nvs_save_mode(void);
void      n8_nvs_save_sta_cfg(void);
void      n8_nvs_save_ap_cfg(void);
void      n8_nvs_save_country(void);
void      n8_nvs_restore(void);
void      n8_rtc_cache_load(void);
void      n8_rtc_cache_save(uint8_t channel, const uint8_t bssid[6], uint8_t authmode);
void      n8_rtc_cache_clear(void);
void      n8_derive_pmk_eager(const uint8_t *ssid, size_t ssid_len, const uint8_t *pass,
                              uint8_t out_pmk[32], bool *hit_rtc_cache);

/* net80211_supp_glue.c */
void      n8_supp_clear_appies(void);
void      n8_vendor_ie_free_all(void);
uint16_t  n8_append_vendor_ies(wifi_vendor_ie_type_t type, uint8_t *out, uint16_t off,
                               uint16_t max_len);
const uint8_t *n8_supp_get_ie_bytes(uint8_t type, uint16_t *out_len);
bool      n8_verify_bip_mmie(const uint8_t *frame, uint16_t len);
esp_lmac_cipher_t n8_wifi_cipher_to_lmac(wifi_cipher_type_t c);

/* net80211_scan.c */
const wifi_country_t *n8_get_active_country(void);
esp_err_t n8_scan_start_internal(const wifi_scan_config_t *cfg, bool for_connect,
                                 uint8_t single_ch);
void      n8_scan_stop_internal(bool post_event);
void      n8_scan_free_results(void);
wifi_auth_mode_t n8_parse_ap_authmode(uint16_t capinfo, const uint8_t *rsn_ie, uint16_t rsn_len,
                                      const uint8_t *wpa_ie, uint16_t wpa_len,
                                      wifi_wpa_ie_t *rsn_out, wifi_wpa_ie_t *wpa_out,
                                      bool *rsn_ok_out, bool *wpa_ok_out);
void      n8_scan_rx_beacon_or_probe(const wifi_pkt_rx_ctrl_t *ctrl, int16_t freq_offset,
                                     const uint8_t *frame, uint16_t len);
n8_scan_entry_t *n8_scan_pick_best_ap(void);
int       esp_wifi_promiscuous_scan_start(wifi_scan_config_t *config, n8_scan_done_cb_t cb);

/* net80211_sta.c */
esp_err_t n8_sta_start(void);
void      n8_sta_stop(void);
esp_err_t n8_sta_connect(void);
void      n8_sta_disconnect(uint8_t reason, bool send_deauth, bool notify_event);
void      n8_sta_on_scan_done(void);
void      n8_sta_on_auth_done(void);
void      n8_sta_on_tick_100ms(void);
void      n8_sta_rx_mgmt(const wifi_pkt_rx_ctrl_t *ctrl, int16_t freq_offset,
                         const uint8_t *frame, uint16_t len);
uint16_t  n8_sta_next_seq(void);
#ifdef CONFIG_WPA_11KV_SUPPORT
esp_err_t n8_sta_tx_action(const uint8_t *body, uint16_t body_len);
#endif

/* net80211_ap.c */
esp_err_t n8_ap_start(void);
void      n8_ap_stop(void);
esp_err_t n8_ap_update_beacon(void);
void      n8_ap_on_tbtt(void);
void      n8_ap_on_tick_100ms(void);
void      n8_ap_rx_mgmt(const wifi_pkt_rx_ctrl_t *ctrl, const uint8_t *frame, uint16_t len);
void      n8_ap_rx_ctrl(const uint8_t *frame, uint16_t len);
n8_ap_sta_t *n8_ap_find_sta(const uint8_t mac[6]);
n8_ap_sta_t *n8_ap_find_sta_by_aid(uint16_t aid);
void      n8_ap_remove_sta(n8_ap_sta_t *sta, uint8_t reason, bool send_deauth);
bool      n8_ap_ps_enqueue(uint8_t aid, const uint8_t *eth_frame, uint16_t len);
void      n8_ap_ps_flush_sta(n8_ap_sta_t *sta, bool single_frame);
void      n8_ap_ps_flush_bcast(void);
void      n8_ap_ps_free_all(void);
void      n8_ap_sync_channel(uint8_t new_channel);
void      n8_ap_on_ptk_done(const uint8_t mac[6]);
uint16_t  n8_ap_next_seq(void);

/* net80211_data.c */
void      n8_data_process_tx_queue(void);
void      n8_data_rx_frame(esp_lmac_rx_buf_t *rx_buf);
void      n8_data_sniffer_rx(const wifi_pkt_rx_ctrl_t *ctrl, const uint8_t *frame, uint16_t len);
esp_err_t n8_data_tx_eth_ap_internal(const uint8_t *eth_frame, uint16_t len, bool bypass_ps);
bool      n8_replay_win_accept(n8_replay_win_t *win, uint64_t pn);
uint64_t  n8_ccmp_iv_to_pn(const uint8_t *iv);

/* net80211_defrag.c (opt-in via CONFIG_ESP8266_OSS_WIFI_RX_DEFRAG_ENABLED) */
#ifdef CONFIG_ESP8266_OSS_WIFI_RX_DEFRAG_ENABLED
uint8_t  *n8_defrag_rx_frag(uint8_t vif, const uint8_t ta[IEEE80211_ADDR_LEN],
                             uint8_t tid, uint16_t seq_ctrl, bool more_frag,
                             bool is_prot, esp_lmac_cipher_t cipher, uint8_t key_idx,
                             uint64_t pn, const uint8_t *frag_data, uint16_t frag_len,
                             uint16_t *out_len);
void      n8_defrag_purge_vif(uint8_t vif);
void      n8_defrag_purge_peer(uint8_t vif, const uint8_t ta[IEEE80211_ADDR_LEN]);
void      n8_defrag_on_tick_100ms(void);
#else
static inline void n8_defrag_purge_vif(uint8_t vif) { (void)vif; }
static inline void n8_defrag_purge_peer(uint8_t vif, const uint8_t ta[IEEE80211_ADDR_LEN])
{
    (void)vif;
    (void)ta;
}
static inline void n8_defrag_on_tick_100ms(void) {}
#endif

/* net80211_pm.c */
void      n8_pm_init(void);
void      n8_pm_deinit(void);
void      n8_pm_on_connect(void);
void      n8_pm_on_disconnect(void);
void      n8_pm_on_activity(void);
void      n8_pm_on_beacon_rx(const uint8_t *frame, uint16_t len);
void      n8_pm_on_tick_100ms(void);
void      n8_pm_wake_for_tx(void);
void      n8_pm_set_ps(wifi_ps_type_t type);
void      n8_pm_send_nullfunc_now(bool pm_bit);
void      n8_pm_send_nullfunc_cb(bool pm_bit, esp_lmac_tx_done_cb_t cb, void *ctx);

/* net80211_api.c */
void      n8_apply_tx_power_limit(void);
void      n8_sync_country_power(void);

#ifdef __cplusplus
}
#endif
