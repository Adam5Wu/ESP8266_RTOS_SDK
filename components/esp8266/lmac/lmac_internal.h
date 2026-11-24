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
#include "esp_attr.h"
#include "rom/ets_sys.h"
#include "esp_lmac.h"
#include "lmac_regs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* External RTOS / PHY / SDK hooks */
extern void PendSV(int req);
extern void vPortETSIntrLock(void);
extern void vPortETSIntrUnlock(void);
extern void vPortEnterCritical(void);
extern void vPortExitCritical(void);
extern void esp_sleep_lock(void);
extern void esp_sleep_unlock(void);
extern int64_t esp_timer_get_time(void);

/* OSS PHY hooks (components/esp8266/phy/) */
extern void phy_open_rf(void);
extern void phy_close_rf(void);
extern void phy_enable_agc(void);
extern void phy_disable_agc(void);
extern void clockgate_watchdog(uint8_t disable);
extern int phy_change_channel(uint16_t freq_mhz);
extern void chip_v6_rxmax_ext(uint8_t level);
extern void phy_set_rx11b_reg(uint8_t enable);
extern void noise_check_loop(uint8_t chan_idx, uint8_t apply_now);
extern void tx_pwctrl_background(uint8_t apply_enable, uint8_t debug_print);
extern int16_t phy_get_bb_freqoffset(void);
extern void pm_wakeup_init(uint32_t mode, uint32_t skip_bbpll);

/* --------------------------------------------------------------------------
 * Standard 12-Byte ESP8266 SLC/WDEV DMA Descriptor
 * -------------------------------------------------------------------------- */

typedef struct lmac_lldesc {
    uint32_t           ctrl; /* [11:0] size, [23:12] len, [28:24] off, [29] sosf, [30] eof, [31] owner */
    uint8_t           *buf;
    struct lmac_lldesc *next;
} lmac_lldesc_t;

_Static_assert(sizeof(lmac_lldesc_t) == 12U, "lmac_lldesc_t must be 12 bytes");

#define LLDESC_SIZE_MASK     0x00000FFFU
#define LLDESC_LEN_SHIFT     12U
#define LLDESC_LEN_MASK      0x00FFF000U
#define LLDESC_OFF_SHIFT     24U
#define LLDESC_OFF_MASK      0x1F000000U
#define LLDESC_SOSF          0x20000000U
#define LLDESC_EOF           0x40000000U
#define LLDESC_OWNER         0x80000000U

/* --------------------------------------------------------------------------
 * Lock-Free Level-3 NMI -> Wi-Fi Worker Event Ring (Power-of-2, DRAM)
 * -------------------------------------------------------------------------- */

#define LMAC_NMI_RING_SIZE   32U
#define LMAC_NMI_RING_MASK   (LMAC_NMI_RING_SIZE - 1U)

#define LMAC_RXSTATE_OK      ESP_LMAC_RXSTATE_OK
#define LMAC_RXSTATE_ALT1    ESP_LMAC_RXSTATE_ALT1
#define LMAC_RXSTATE_ALT2    ESP_LMAC_RXSTATE_TKIP_MIC_FAIL

typedef enum {
    LMAC_NMI_EVT_NONE = 0,
    LMAC_NMI_EVT_RX_DESC,
    LMAC_NMI_EVT_TX_DONE,
    LMAC_NMI_EVT_TX_TIMEOUT,
    LMAC_NMI_EVT_TBTT,
} lmac_nmi_evt_type_t;

typedef struct {
    uint8_t  type;
    uint8_t  a;      /* RX: desc_start; TX: hw_queue; TBTT: vif */
    uint8_t  b;      /* RX: desc_cnt;   TX: cause (0/1/2/4/5) */
    uint8_t  c;      /* RX: rx_state;   TX: sub_code / ack_rssi */
    int16_t  d;      /* RX: freq_offset; TX: ack_rssi */
    uint16_t len;    /* RX: mpdu len from rx_ctrl */
} lmac_nmi_evt_t;

_Static_assert(sizeof(lmac_nmi_evt_t) == 8U, "lmac_nmi_evt_t must be 8 bytes");

/* --------------------------------------------------------------------------
 * TX Slot & Hardware Queue Structures (DRAM for DMA)
 * -------------------------------------------------------------------------- */

#define LMAC_TX_HDR_SCRATCH_MAX     96U
#define LMAC_TX_TRAILER_SCRATCH_MAX 16U /* Up to 12-B TKIP MIC/ICV + 4-B FCS pad */
#define LMAC_TX_MAX_SG_SEGS         2U
#define LMAC_TX_MAX_DESCS           (1U + LMAC_TX_MAX_SG_SEGS + 1U) /* hdr + 2 segs + trailer/FCS */
#define LMAC_TX_DEFAULT_MAX_RETRIES 7U
#define LMAC_TX_LIFETIME_US         500000U

#define LMAC_FC1_PROTECTED          0x40U
#define LMAC_KEY_SLOT_AP_BIT        0x80U
#define LMAC_KEY_SLOT_MASK          0x7FU

#define LMAC_HW_Q_BE                2U
#define LMAC_HW_Q_BK                3U
#define LMAC_HW_Q_VI                1U
#define LMAC_HW_Q_VO                0U
#define LMAC_HW_Q_MGMT              0U
#define LMAC_HW_Q_BEACON            0U

typedef struct lmac_tx_slot {
    /* DMA descriptors and scratch buffers first (4-byte aligned in DRAM 0x3ffc0000..0x3fffffff) */
    lmac_lldesc_t          descs[LMAC_TX_MAX_DESCS];
    uint8_t                hdr_buf[LMAC_TX_HDR_SCRATCH_MAX];
    uint8_t                trailer_buf[LMAC_TX_TRAILER_SCRATCH_MAX];

    struct lmac_tx_slot   *next;
    esp_lmac_tx_done_cb_t  done_cb;
    void                  *done_ctx;
    uint32_t               enqueue_us;
    uint16_t               air_len;      /* mpdu_len + 4 (FCS) */
    uint8_t                vif;
    uint8_t                peer_id;
    uint8_t                hw_q;
    uint8_t                hw_key_slot;
    uint8_t                flags;
    uint8_t                hw_rate;
    uint8_t                retries;
    uint8_t                max_retries;
    uint8_t                high_prio;
    uint8_t                in_use;
#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
    /* Precomputed retry schedule (populated in .flash.text on submit, read in IRAM NMI) */
    uint8_t                retry_rate[LMAC_TX_DEFAULT_MAX_RETRIES + 1U];
    uint16_t               retry_dur[LMAC_TX_DEFAULT_MAX_RETRIES + 1U];
    uint8_t                done_ok;
    int8_t                 done_ack_rssi;
#endif
} lmac_tx_slot_t;

typedef struct {
    lmac_tx_slot_t *active;
    lmac_tx_slot_t *q_head;
    lmac_tx_slot_t *q_tail;
    uint32_t        launch_us;
    uint8_t         cw;
    uint8_t         cw_min;
    uint8_t         cw_max;
    uint8_t         aifsn;
} lmac_hw_txq_t;

/* --------------------------------------------------------------------------
 * Per-Peer Rate Control (TRC) State
 * -------------------------------------------------------------------------- */

typedef struct {
    uint8_t  valid;
    uint8_t  vif;
    uint8_t  mac[6];
    uint16_t rate_mask_11bg;
    uint8_t  ht20_mcs_mask;
    uint8_t  flags;          /* bit0=short_pre, bit1=sgi, bit2=qos, bit3=ht */
    uint8_t  sched_mode;     /* 0=11b, 1=11g, 2=11n */
    uint8_t  cur_idx;
    uint8_t  max_idx;
    uint8_t  min_idx;
    uint8_t  rssi_inited;
    uint8_t  win_frames;
    uint8_t  win_retries;
    uint8_t  win_fails;
    uint8_t  clean_windows;
    uint8_t  up_hold;        /* AARF exponential probe backoff: 1, 2, 4, 8 */
    uint8_t  probing;        /* 1 while evaluating a step-up probe window */
    uint8_t  consec_heavy;   /* Consecutive frames requiring >= 4 retries */
    uint8_t  consec_fail;    /* Consecutive TX failures (!ok) */
    int8_t   rssi_avg;
    uint8_t  ptk_hw_slot;    /* 0xFF if none, else 6..24 */
    uint8_t  ptk_cipher;
    uint32_t win_start_us;
} lmac_peer_t;

/* --------------------------------------------------------------------------
 * Hardware Key Slot Tracking (25 Slots)
 * -------------------------------------------------------------------------- */

typedef struct {
    uint8_t  in_use;
    uint8_t  vif;
    uint8_t  peer_id;
    uint8_t  key_type;       /* ESP_LMAC_KEY_TYPE_* */
    uint8_t  key_idx;
    uint8_t  cipher;         /* ESP_LMAC_CIPHER_* */
} lmac_key_meta_t;

/* --------------------------------------------------------------------------
 * SoftAP Beacon Template State
 * -------------------------------------------------------------------------- */

typedef struct {
    uint8_t  *buf;           /* Heap buffer in DRAM */
    uint16_t  len;
    uint16_t  tim_ie_offset;
    uint32_t  interval_us;
    uint32_t  next_tbtt_lo;
    uint8_t   active;
    uint8_t   tx_pending;
} lmac_beacon_t;

/* --------------------------------------------------------------------------
 * Virtual Interface State (STA=0, SoftAP=1)
 * -------------------------------------------------------------------------- */

typedef struct {
    uint8_t enabled;
    uint8_t bssid_enabled;
    uint8_t proto_mask;      /* WIFI_PROTOCOL_11B/11G/11N */
    uint8_t ptk_cipher;
    uint8_t gtk_cipher;
    uint8_t gtk_active_slot; /* Currently installed GTK slot for TX */
    uint8_t gtk_toggle;      /* Ping-pong 0/1 for STA GTK slots 2..3 */
    uint8_t mac[6];
    uint8_t bssid[6];
} lmac_vif_state_t;

/* --------------------------------------------------------------------------
 * Global LMAC Driver Context (Static DRAM)
 * -------------------------------------------------------------------------- */

#define LMAC_MAX_RX_BUFS     24U

typedef struct {
    bool                 initialized;
    esp_lmac_config_t    cfg;
    esp_lmac_callbacks_t cbs;

    /* RX DMA arena */
    uint8_t             *hw_arena;
    lmac_lldesc_t       *rx_descs;
    uint8_t             *rx_frontdata;
    uint8_t             *rx_extradata;
    lmac_lldesc_t        empty_ampdu_desc;
    uint32_t             empty_ampdu_word;
    lmac_lldesc_t       *rx_ampdu_descs;
    uint8_t             *rx_ampdu_bufs;
    volatile uint32_t    rx_avail_mask;     /* Circular availability bitmap (rxbufbit) */
    volatile uint8_t     rx_head_idx;       /* Current CPU read index into rx_descs[] */
    esp_lmac_rx_buf_t    rx_handles[LMAC_MAX_RX_BUFS];

    /* Lock-free NMI -> worker event ring */
    lmac_nmi_evt_t       nmi_ring[LMAC_NMI_RING_SIZE];
    volatile uint8_t     nmi_wr;
    volatile uint8_t     nmi_rd;
    volatile uint8_t     nmi_notify_pending;

    /* TX slot pool & serialized hardware queue */
    lmac_tx_slot_t      *tx_pool;
    uint8_t              tx_pool_cnt;
    lmac_hw_txq_t        hw_txq[LMAC_HW_TXQ_COUNT];
#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
    lmac_tx_slot_t *volatile tx_done_head;
    lmac_tx_slot_t      *tx_done_tail;
#endif

    /* VIFs, peers (1 static STA + mode-scoped SoftAP slab), keys, beacon */
    lmac_vif_state_t     vif[ESP_LMAC_VIF_MAX];
    lmac_peer_t          sta_peer;          /* peer_id = 0 */
    lmac_peer_t         *ap_peers;          /* peer_id = 1..ap_peer_cap */
    uint8_t              ap_peer_cap;
    lmac_key_meta_t      keys[LMAC_HW_KEY_SLOTS];
    lmac_beacon_t        beacon;

    /* Channel, RF sleep, sniffer, housekeeping state */
    volatile uint8_t     cur_channel;
    volatile uint8_t     sniffer_mode;
    uint8_t              scan_mode;
    uint8_t              rf_closed;
    uint8_t              pend_noise_check;
    uint32_t             sniffer_filter;
    uint32_t             sniffer_ctrl_filter;
    uint32_t             ps_lock_flags;
    uint8_t              rx_pbuf_mem_type;
    uint8_t              hk_tick_cnt;
    uint32_t             last_rx_end_cnt;
    uint8_t              rx_hang_ticks;
    uint8_t              rx_ba_used_mask;
    uint8_t              sw_prot_bypass_vif; /* 0=none, 1=CONF0, 2=CONF1 temporarily bypassed */

    /* Telemetry */
    esp_lmac_stats_t     stats;
} lmac_ctx_t;

extern lmac_ctx_t g_lmac;

/* NMI / IRAM helpers (lmac_nmi.c) — IRAM_ATTR applied on definitions only */
void lmac_rx_set_desc_bit_locked(uint8_t idx);
void lmac_rx_clear_desc_bit_locked(uint8_t idx);
void lmac_check_and_move_hwbuf_locked(void);
void lmac_mactim1_set_func(void (*cb)(void));
void lmac_mactim1_arm(uint32_t delta_us);
void lmac_mactim1_disarm(void);
uint64_t wdev_get_tsf_time(int vif_idx);
#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
void lmac_tx_arm_hw_slot_fast(uint8_t q, lmac_tx_slot_t *slot);
#endif

/* DMA helpers (lmac_dma.c) */
esp_err_t lmac_dma_init(void);
void lmac_dma_reprogram_regs(void);
void lmac_dma_deinit(void);
void lmac_dma_dispatch_rx_evt(const lmac_nmi_evt_t *ev);

/* TX helpers (lmac_tx.c) */
esp_err_t lmac_tx_init(void);
void lmac_tx_deinit(void);
#ifndef CONFIG_ESP8266_OSS_WIFI_MIN_NMI
uint8_t lmac_tx_drain_done(uint8_t max_batch);
#else
void lmac_tx_on_done_evt(const lmac_nmi_evt_t *ev);
#endif
void lmac_tx_on_timeout_evt(void);
void lmac_tx_check_hang(void);
void lmac_tx_launch_beacon_now(void);

/* TRC helpers (lmac_trc.c) */
void lmac_trc_init(void);
lmac_peer_t *lmac_trc_get_peer(esp_lmac_peer_id_t peer_id);
uint8_t lmac_trc_select_rate(esp_lmac_peer_id_t peer_id, esp_lmac_vif_t vif, uint8_t flags, uint8_t retry_idx);
uint16_t lmac_trc_ack_duration_us(uint8_t hw_rate);
void lmac_trc_on_tx_result(esp_lmac_peer_id_t peer_id, uint8_t ok, uint8_t retries, int8_t ack_rssi);

/* Hardware MAC / Crypto / VIF / Beacon helpers (lmac_crypto_vif.c) */
void lmac_wdev_hw_init(void);
void lmac_wdev_update_mac_enable(void);
uint8_t lmac_crypto_lookup_tx_slot(esp_lmac_vif_t vif, esp_lmac_peer_id_t peer_id,
                                   esp_lmac_cipher_t cipher, uint8_t key_idx);
void lmac_beacon_on_tbtt_evt(void);

#ifdef __cplusplus
}
#endif
