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
// Transmit Rate Control (TRC), peer table (static STA peer + mode-scoped SoftAP
// peer pool), and compact flash-resident 11b/11g/11n rate schedules (.flash.text).

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "lmac_internal.h"

/* --------------------------------------------------------------------------
 * TRC Peer Pool, Schedule Index, RSSI, and AARF Window Constants
 * -------------------------------------------------------------------------- */

#define LMAC_TRC_STA_PEER_ID            0U      /* Reserved peer_id for STA VIF */
#define LMAC_TRC_MAX_AP_PEERS           10U     /* Hard cap on SoftAP peer pool slots */
#define LMAC_TRC_MAC_ADDR_LEN           6U      /* IEEE 802.11 MAC address length (bytes) */

/* Rate schedule indices and capability masks */
#define LMAC_TRC_HT_MCS_COUNT           8U      /* HT20 MCS0..MCS7 */
#define LMAC_TRC_11N_MCS0_IDX           4U      /* Index of MCS0 in s_sched_11n[] */
#define LMAC_TRC_11N_MCS7_SGI_IDX       12U     /* Index of MCS7 SGI20 in s_sched_11n[] */
#define LMAC_TRC_OFDM_MIN_IDX           3U      /* Index of 6 Mbps OFDM in 11g/11n schedules */
#define LMAC_TRC_11G_RATE_MASK          0x0FF0U /* OFDM rate bits in rate_mask_11bg */
#define LMAC_TRC_11N_INIT_IDX           8U      /* Default 11n start index: MCS4 */
#define LMAC_TRC_11G_INIT_IDX           7U      /* Default 11g start index: 24 Mbps */
#define LMAC_TRC_SGI_MAX_RETRY_IDX      1U      /* Promote MCS5/6 to SGI20 only on attempts 0..1 */
#define LMAC_RATE_HT_SGI_BIT            0x08U   /* Short GI 20 MHz rate code bit on MCS0..7 */
#define LMAC_RATE_HT_MCS7_SGI           0x1FU   /* 11n HT20 MCS7 Short GI (72.2 Mbps) */

/* RSSI validation bounds, defaults, weak-link clamp, and EMA weights */
#define LMAC_TRC_RSSI_INVALID_DBM       (-127)  /* Returned when peer_id is invalid */
#define LMAC_TRC_RSSI_MIN_VALID_DBM     (-120)  /* Lower bound for valid RSSI samples (dBm) */
#define LMAC_TRC_RSSI_MAX_VALID_DBM     0       /* Upper bound for valid RSSI samples (dBm) */
#define LMAC_TRC_RSSI_DEFAULT_DBM       (-65)   /* Initial placeholder RSSI on peer add */
#define LMAC_TRC_RSSI_WEAK_LINK_DBM     (-80)   /* Initial weak-link clamp threshold (dBm) */
#define LMAC_TRC_WEAK_CLAMP_11N_IDX     6U      /* Weak-link cap in s_sched_11n[]: MCS2 */
#define LMAC_TRC_WEAK_CLAMP_11G_IDX     5U      /* Weak-link cap in s_sched_11g[]: 12 Mbps */
#define LMAC_TRC_WEAK_CLAMP_11B_IDX     2U      /* Weak-link cap in s_sched_11b[]: 5.5 Mbps */
#define LMAC_TRC_RSSI_EMA_OLD_WEIGHT    7       /* 7/8 old + 1/8 new RSSI EMA weight */
#define LMAC_TRC_RSSI_EMA_DENOM         8       /* EMA denominator */

/* Non-linear per-packet retry fallback table dimensions */
#define LMAC_TRC_RETRY_DROP_LEN         7U
#define LMAC_TRC_RETRY_DROP_MAX         8U

/* SIFS + ACK air-time durations (us) for IEEE 802.11 NAV Duration field */
#define LMAC_TRC_ACK_DUR_HT_OFDM_HI_US  44U     /* 16 us SIFS + 28 us 24M/6M OFDM ACK */
#define LMAC_TRC_ACK_DUR_11B_1M_US      314U    /* 1 Mbps CCK long preamble */
#define LMAC_TRC_ACK_DUR_11B_2M_US      258U    /* 2 Mbps CCK long preamble */
#define LMAC_TRC_ACK_DUR_11B_2M_SP_US   162U    /* 2 Mbps CCK short preamble */
#define LMAC_TRC_ACK_DUR_11B_5_5M_US    222U    /* 5.5 Mbps CCK long preamble */
#define LMAC_TRC_ACK_DUR_11B_5_5M_SP_US 126U    /* 5.5 Mbps CCK short preamble */
#define LMAC_TRC_ACK_DUR_11B_11M_US     212U    /* 11 Mbps CCK long preamble */
#define LMAC_TRC_ACK_DUR_11B_11M_SP_US  116U    /* 11 Mbps CCK short preamble */
#define LMAC_TRC_ACK_DUR_OFDM_6_9M_US   60U     /* 6 / 9 Mbps OFDM */
#define LMAC_TRC_ACK_DUR_OFDM_12_18M_US 48U     /* 12 / 18 Mbps OFDM */

/* AARF probe backoff & pure-integer windowed adaptation thresholds */
#define LMAC_TRC_HEAVY_RETRIES_MIN      4U      /* Retries >= 4 counts as a heavy-retry frame */
#define LMAC_TRC_CONSEC_FAIL_DROP       2U      /* Consecutive TX failures triggering fast drop */
#define LMAC_TRC_CONSEC_HEAVY_DROP      3U      /* Consecutive heavy frames triggering fast drop */
#define LMAC_TRC_AARF_HOLD_INIT         1U      /* Initial clean-window hold count before probe */
#define LMAC_TRC_AARF_HOLD_MAX          8U      /* Max exponential AARF probe hold (1,2,4,8) */
#define LMAC_TRC_WIN_STAT_SAT_MAX       255U    /* Saturation ceiling for uint8 window counters */
#define LMAC_TRC_WIN_MAX_FRAMES         16U     /* Frame count that closes an evaluation window */
#define LMAC_TRC_WIN_MIN_TIME_FRAMES    4U      /* Minimum frames to close window on timeout */
#define LMAC_TRC_WIN_MAX_US             100000U /* 100 ms max evaluation window duration */
#define LMAC_TRC_FAIL_RETRY_WEIGHT      4U      /* Retry-equivalent penalty per failed frame */
#define LMAC_TRC_STEP_DOWN_NUM          5U      /* Step-down ratio numerator (5/4 = 1.25) */
#define LMAC_TRC_STEP_DOWN_DEN          4U      /* Step-down ratio denominator */
#define LMAC_TRC_STEP_UP_RETRY_INV      8U      /* Step-up max retry ratio = 1/8 (12.5%) */

/* --------------------------------------------------------------------------
 * Hardware Rate Schedules in Flash (.rodata, Zero DRAM)
 *
 * ESP8266 WDEV hardware rate encodings:
 *   11b long preamble        : 0x00=1M, 0x01=2M, 0x02=5.5M, 0x03=11M
 *   11b short preamble       : 0x05=2M, 0x06=5.5M, 0x07=11M
 *   11g OFDM                 : 0x0B=6M, 0x0F=9M, 0x0A=12M, 0x0E=18M,
 *                              0x09=24M, 0x0D=36M, 0x08=48M, 0x0C=54M
 *   11n HT20 LGI (bit4=1)    : 0x10..0x17 = MCS0..MCS7
 *   11n HT20 SGI (bit4,3=1)  : 0x18..0x1F = MCS0..MCS7 Short GI 20 MHz
 * -------------------------------------------------------------------------- */

static const uint8_t s_sched_11b[] = {
    LMAC_RATE_11B_1M,
    LMAC_RATE_11B_2M,
    LMAC_RATE_11B_5_5M,
    LMAC_RATE_11B_11M,
};

static const uint8_t s_sched_11g[] = {
    LMAC_RATE_11B_1M,
    LMAC_RATE_11B_2M,
    LMAC_RATE_11B_5_5M,
    LMAC_RATE_11G_6M,
    LMAC_RATE_11B_11M,
    LMAC_RATE_11G_12M,
    LMAC_RATE_11G_18M,
    LMAC_RATE_11G_24M,
    LMAC_RATE_11G_36M,
    LMAC_RATE_11G_48M,
    LMAC_RATE_11G_54M,
};

static const uint8_t s_sched_11n[] = {
    LMAC_RATE_11B_1M,
    LMAC_RATE_11B_2M,
    LMAC_RATE_11B_5_5M,
    LMAC_RATE_11G_6M,
    LMAC_RATE_11N_MCS0,
    LMAC_RATE_11N_MCS1,
    LMAC_RATE_11N_MCS2,
    LMAC_RATE_11N_MCS3,
    LMAC_RATE_11N_MCS4,
    LMAC_RATE_11N_MCS5,
    LMAC_RATE_11N_MCS6,
    LMAC_RATE_11N_MCS7,
    LMAC_RATE_HT_MCS7_SGI,
};

/**
 * @brief Return the number of entries in the flash rate schedule for a schedule mode.
 *
 * @param mode  TRC schedule mode (`LMAC_SCHED_11B`, `LMAC_SCHED_11G`, or `LMAC_SCHED_11N`).
 * @return Number of rate entries in the corresponding schedule table.
 */
static uint8_t sched_len(uint8_t mode)
{
    if (mode == LMAC_SCHED_11N) {
        return (uint8_t)sizeof(s_sched_11n);
    }
    if (mode == LMAC_SCHED_11G) {
        return (uint8_t)sizeof(s_sched_11g);
    }
    return (uint8_t)sizeof(s_sched_11b);
}

/**
 * @brief Look up the WDEV hardware rate code at a clamped index in a rate schedule.
 *
 * @param mode  TRC schedule mode (`LMAC_SCHED_11B`, `LMAC_SCHED_11G`, or `LMAC_SCHED_11N`).
 * @param idx   Zero-based index into the schedule; clamped to `sched_len(mode) - 1`.
 * @return WDEV hardware rate code (`LMAC_RATE_*`).
 */
static uint8_t sched_rate_at(uint8_t mode, uint8_t idx)
{
    uint8_t len = sched_len(mode);
    if (idx >= len) {
        idx = (uint8_t)(len - 1U);
    }
    if (mode == LMAC_SCHED_11N) {
        return s_sched_11n[idx];
    }
    if (mode == LMAC_SCHED_11G) {
        return s_sched_11g[idx];
    }
    return s_sched_11b[idx];
}

/**
 * @brief Return the lowest mandatory base rate permitted by a VIF's protocol bitmap.
 *
 * @param vif  Virtual interface (`ESP_LMAC_VIF_STA` or `ESP_LMAC_VIF_AP`).
 * @return `LMAC_RATE_11G_6M` when 11b is explicitly excluded from the VIF's protocol mask,
 *         otherwise `LMAC_RATE_11B_1M`.
 */
static uint8_t lowest_rate_for_vif(esp_lmac_vif_t vif)
{
    uint8_t proto = (vif < ESP_LMAC_VIF_MAX) ? g_lmac.vif[vif].proto_mask : 0U;
    if (proto != 0U && (proto & WIFI_PROTOCOL_11B) == 0U) {
        return LMAC_RATE_11G_6M; /* 6 Mbps OFDM when 11b is explicitly disabled */
    }
    return LMAC_RATE_11B_1M; /* 1 Mbps CCK */
}

/**
 * @brief Reset the static STA peer slot and SoftAP peer pool pointers during LMAC init.
 */
void lmac_trc_init(void)
{
    memset(&g_lmac.sta_peer, 0, sizeof(g_lmac.sta_peer));
    g_lmac.sta_peer.ptk_hw_slot = LMAC_KEY_SLOT_INVALID;
    g_lmac.ap_peers = NULL;
    g_lmac.ap_peer_cap = 0U;
}

/**
 * @brief Allocate (or reallocate) the mode-scoped DRAM pool for SoftAP station peers.
 *
 * Frees any previously allocated SoftAP peer pool first. Passing `0` leaves the pool
 * unallocated and returns ESP_OK; counts above `LMAC_TRC_MAX_AP_PEERS` (10) are clamped.
 *
 * @param max_ap_peers  Maximum simultaneous SoftAP clients (`0..10`; clamped above 10).
 * @return ESP_OK on success, or ESP_ERR_NO_MEM if heap allocation fails.
 */
esp_err_t esp_lmac_peer_alloc_ap_pool(uint8_t max_ap_peers)
{
    esp_lmac_peer_free_ap_pool();
    if (max_ap_peers == 0U) {
        return ESP_OK;
    }
    if (max_ap_peers > LMAC_TRC_MAX_AP_PEERS) {
        max_ap_peers = LMAC_TRC_MAX_AP_PEERS;
    }

    lmac_peer_t *pool = (lmac_peer_t *)heap_caps_calloc(max_ap_peers, sizeof(lmac_peer_t), MALLOC_CAP_8BIT);
    if (pool == NULL) {
        return ESP_ERR_NO_MEM;
    }
    for (uint8_t i = 0U; i < max_ap_peers; i++) {
        pool[i].ptk_hw_slot = LMAC_KEY_SLOT_INVALID;
    }
    g_lmac.ap_peers = pool;
    g_lmac.ap_peer_cap = max_ap_peers;
    return ESP_OK;
}

/**
 * @brief Free the dynamically allocated SoftAP peer pool and clear its capacity.
 */
void esp_lmac_peer_free_ap_pool(void)
{
    if (g_lmac.ap_peers != NULL) {
        heap_caps_free(g_lmac.ap_peers);
        g_lmac.ap_peers = NULL;
    }
    g_lmac.ap_peer_cap = 0U;
}

/**
 * @brief Resolve an LMAC peer identifier to its active `lmac_peer_t` state record.
 *
 * @param peer_id  Peer ID (`0` for the STA peer, `1..ap_peer_cap` for SoftAP clients, or
 *                 `ESP_LMAC_PEER_INVALID`).
 * @return Pointer to the valid `lmac_peer_t` entry, or NULL if invalid or inactive.
 */
lmac_peer_t *lmac_trc_get_peer(esp_lmac_peer_id_t peer_id)
{
    if (peer_id == LMAC_TRC_STA_PEER_ID) {
        return g_lmac.sta_peer.valid ? &g_lmac.sta_peer : NULL;
    }
    if (peer_id == ESP_LMAC_PEER_INVALID || g_lmac.ap_peers == NULL) {
        return NULL;
    }
    uint8_t idx = (uint8_t)(peer_id - 1U);
    if (idx >= g_lmac.ap_peer_cap || !g_lmac.ap_peers[idx].valid) {
        return NULL;
    }
    return &g_lmac.ap_peers[idx];
}

/**
 * @brief Clear per-window TX frame/retry/failure accumulators and restart the window timer.
 *
 * @param p       Non-NULL peer state record whose evaluation window is reset.
 * @param now_us  Current monotonic timestamp in microseconds (truncated 32-bit `esp_timer`).
 */
static void trc_reset_window(lmac_peer_t *p, uint32_t now_us)
{
    p->win_frames = 0U;
    p->win_retries = 0U;
    p->win_fails = 0U;
    p->win_start_us = now_us;
}

/**
 * @brief Select a peer's 11b/11g/11n rate schedule, index bounds, and starting rate.
 *
 * Intersects the peer's advertised capabilities with its VIF's active `proto_mask`,
 * computes `[min_idx, max_idx]` (extending `max_idx` to `LMAC_TRC_11N_MCS7_SGI_IDX`
 * when SGI20 and MCS7 are both supported) and initial `cur_idx` (under
 * `CONFIG_WIFI_TX_RATE_SEQUENCE_FROM_HIGH`, 11n starts at the highest LGI MCS rather
 * than `MCS7_SGI` and steps up to SGI20 only after a clean evaluation window), and
 * resets all AARF probe and evaluation-window counters.
 *
 * @param p  Non-NULL active peer state record to configure.
 */
static void configure_peer_schedule(lmac_peer_t *p)
{
    uint8_t proto = (p->vif < ESP_LMAC_VIF_MAX) ? g_lmac.vif[p->vif].proto_mask : 0U;
    if (proto == 0U) {
        proto = WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N;
    }

    if ((p->flags & LMAC_PEER_FLAG_HT) != 0U && (proto & WIFI_PROTOCOL_11N) != 0U && p->ht20_mcs_mask != 0U) {
        p->sched_mode = LMAC_SCHED_11N;
        uint8_t top_mcs = 0U;
        for (uint8_t m = 0U; m < LMAC_TRC_HT_MCS_COUNT; m++) {
            if ((p->ht20_mcs_mask & (1U << m)) != 0U) {
                top_mcs = m;
            }
        }
        uint8_t base_max = (uint8_t)(LMAC_TRC_11N_MCS0_IDX + top_mcs);
        p->max_idx = (top_mcs == (LMAC_TRC_HT_MCS_COUNT - 1U) && (p->flags & LMAC_PEER_FLAG_SGI20) != 0U)
                     ? LMAC_TRC_11N_MCS7_SGI_IDX : base_max;
        p->min_idx = ((proto & WIFI_PROTOCOL_11B) != 0U) ? 0U : LMAC_TRC_OFDM_MIN_IDX;
#ifdef CONFIG_WIFI_TX_RATE_SEQUENCE_FROM_HIGH
        p->cur_idx = base_max; /* Start at highest LGI MCS (MCS7) and step to SGI after clean window */
#else
        p->cur_idx = (base_max >= LMAC_TRC_11N_INIT_IDX) ? LMAC_TRC_11N_INIT_IDX : base_max; /* Start at MCS4 */
#endif
    } else if ((proto & WIFI_PROTOCOL_11G) != 0U &&
               (p->rate_mask_11bg == 0U || (p->rate_mask_11bg & LMAC_TRC_11G_RATE_MASK) != 0U)) {
        p->sched_mode = LMAC_SCHED_11G;
        p->max_idx = (uint8_t)(sizeof(s_sched_11g) - 1U);
        p->min_idx = ((proto & WIFI_PROTOCOL_11B) != 0U) ? 0U : LMAC_TRC_OFDM_MIN_IDX;
#ifdef CONFIG_WIFI_TX_RATE_SEQUENCE_FROM_HIGH
        p->cur_idx = p->max_idx; /* Start at 54 Mbps */
#else
        p->cur_idx = LMAC_TRC_11G_INIT_IDX; /* Start at 24 Mbps */
#endif
    } else {
        p->sched_mode = LMAC_SCHED_11B;
        p->max_idx = (uint8_t)(sizeof(s_sched_11b) - 1U);
        p->min_idx = 0U;
        p->cur_idx = p->max_idx; /* Start at 11 Mbps */
    }

    if (p->cur_idx < p->min_idx) {
        p->cur_idx = p->min_idx;
    }
    if (p->cur_idx > p->max_idx) {
        p->cur_idx = p->max_idx;
    }

    p->clean_windows = 0U;
    p->up_hold = LMAC_TRC_AARF_HOLD_INIT;
    p->probing = 0U;
    p->consec_heavy = 0U;
    p->consec_fail = 0U;
    trc_reset_window(p, (uint32_t)esp_timer_get_time());
}

/**
 * @brief Register or update a peer on a VIF and initialize its TRC schedule.
 *
 * For `ESP_LMAC_VIF_STA`, uses static peer ID `0`. For `ESP_LMAC_VIF_AP`, reuses an
 * existing slot with the same MAC address if present or allocates a free slot from
 * `g_lmac.ap_peers`. Preserves any installed PTK hardware key slot across re-addition.
 *
 * @param vif   Virtual interface (`ESP_LMAC_VIF_STA` or `ESP_LMAC_VIF_AP`).
 * @param caps  Non-NULL negotiated peer MAC address and rate/HT/QoS capabilities.
 * @return Assigned `esp_lmac_peer_id_t` (`0` for STA, `1..ap_peer_cap` for AP), or
 *         `ESP_LMAC_PEER_INVALID` on invalid arguments or full/unallocated AP pool.
 */
esp_lmac_peer_id_t esp_lmac_peer_add(esp_lmac_vif_t vif, const esp_lmac_peer_caps_t *caps)
{
    if (vif >= ESP_LMAC_VIF_MAX || caps == NULL) {
        return ESP_LMAC_PEER_INVALID;
    }

    lmac_peer_t *p = NULL;
    esp_lmac_peer_id_t id = ESP_LMAC_PEER_INVALID;

    if (vif == ESP_LMAC_VIF_STA) {
        p = &g_lmac.sta_peer;
        id = LMAC_TRC_STA_PEER_ID;
    } else {
        if (g_lmac.ap_peers == NULL) {
            return ESP_LMAC_PEER_INVALID;
        }
        /* Reuse existing entry for the same MAC if present */
        for (uint8_t i = 0U; i < g_lmac.ap_peer_cap; i++) {
            if (g_lmac.ap_peers[i].valid && memcmp(g_lmac.ap_peers[i].mac, caps->mac, LMAC_TRC_MAC_ADDR_LEN) == 0) {
                p = &g_lmac.ap_peers[i];
                id = (esp_lmac_peer_id_t)(i + 1U);
                break;
            }
        }
        if (p == NULL) {
            for (uint8_t i = 0U; i < g_lmac.ap_peer_cap; i++) {
                if (!g_lmac.ap_peers[i].valid) {
                    p = &g_lmac.ap_peers[i];
                    id = (esp_lmac_peer_id_t)(i + 1U);
                    break;
                }
            }
        }
        if (p == NULL) {
            return ESP_LMAC_PEER_INVALID;
        }
    }

    uint8_t saved_slot = p->valid ? p->ptk_hw_slot : LMAC_KEY_SLOT_INVALID;
    uint8_t saved_cipher = p->valid ? p->ptk_cipher : (uint8_t)ESP_LMAC_CIPHER_NONE;

    memset(p, 0, sizeof(*p));
    p->valid = 1U;
    p->vif = vif;
    memcpy(p->mac, caps->mac, LMAC_TRC_MAC_ADDR_LEN);
    p->rate_mask_11bg = caps->rate_mask_11bg;
    p->ht20_mcs_mask = caps->ht20_mcs_mask;
    p->flags = (uint8_t)((caps->short_preamble ? LMAC_PEER_FLAG_SHORT_PRE : 0U) |
                         (caps->short_gi_20    ? LMAC_PEER_FLAG_SGI20     : 0U) |
                         (caps->qos_enabled    ? LMAC_PEER_FLAG_QOS       : 0U) |
                         (caps->ht_enabled     ? LMAC_PEER_FLAG_HT        : 0U));
    p->rssi_avg = LMAC_TRC_RSSI_DEFAULT_DBM;
    p->ptk_hw_slot = saved_slot;
    p->ptk_cipher = saved_cipher;

    configure_peer_schedule(p);
    return id;
}

/**
 * @brief Remove an active peer, clearing its hardware RX BA scoreboards and bound PTK key slot.
 *
 * Clears all hardware RX Block-Ack scoreboard entries matching the peer's MAC address
 * via lmac_rx_ba_clear_peer(), clears any installed PTK key slot, and resets the peer slot.
 *
 * @param peer_id  Peer ID to remove; safely ignored if invalid or already inactive.
 */
void esp_lmac_peer_remove(esp_lmac_peer_id_t peer_id)
{
    lmac_peer_t *p = lmac_trc_get_peer(peer_id);
    if (p == NULL) {
        return;
    }
    lmac_rx_ba_clear_peer(p->mac);
    if (p->ptk_hw_slot < LMAC_HW_KEY_SLOTS) {
        esp_lmac_key_clear(p->vif, peer_id, ESP_LMAC_KEY_TYPE_PTK, 0U);
    }
    memset(p, 0, sizeof(*p));
    p->ptk_hw_slot = LMAC_KEY_SLOT_INVALID;
}

/**
 * @brief Query the smoothed RSSI estimate for a peer in dBm.
 *
 * @param peer_id  Peer ID to query.
 * @return Smoothed RSSI in dBm, or `LMAC_TRC_RSSI_INVALID_DBM` (`-127`) if peer is invalid.
 */
int8_t esp_lmac_peer_get_rssi(esp_lmac_peer_id_t peer_id)
{
    lmac_peer_t *p = lmac_trc_get_peer(peer_id);
    return (p != NULL) ? p->rssi_avg : LMAC_TRC_RSSI_INVALID_DBM;
}

/**
 * @brief Feed a calibrated RSSI observation into a peer's exponential moving average.
 *
 * Rejects out-of-range samples (`rssi > 0` or `rssi < -120` dBm). On the very first valid
 * sample after association, seeds `rssi_avg` directly and applies a one-time weak-link
 * initial rate clamp if `rssi < -80` dBm before any TX feedback has arrived. Subsequent
 * samples update `rssi_avg` using a `7/8` old + `1/8` new integer EMA with directional
 * rounding toward @p rssi so C integer truncation toward zero does not stall downward moves
 * on negative dBm values.
 *
 * @param peer_id  Active peer ID.
 * @param rssi     Calibrated received signal strength in dBm (valid range `[-120, 0]`).
 */
void esp_lmac_peer_update_rssi(esp_lmac_peer_id_t peer_id, int8_t rssi)
{
    lmac_peer_t *p = lmac_trc_get_peer(peer_id);
    if (p == NULL || rssi > LMAC_TRC_RSSI_MAX_VALID_DBM || rssi < LMAC_TRC_RSSI_MIN_VALID_DBM) {
        return;
    }
    if (!p->rssi_inited) {
        p->rssi_avg = rssi;
        p->rssi_inited = 1U;
        /*
         * One-time initial weak-link RSSI clamp:
         * On join (before any TX window feedback has been collected), starting at MCS4/MCS7
         * or 24/54 Mbps on a fringe link (< -80 dBm) causes an initial burst of retries.
         * Cap cur_idx once to a conservative mid-low rate (MCS2 / 12 Mbps / 5.5 Mbps),
         * respecting min_idx; AARF can still probe upward if the link proves clean.
         */
        if (p->win_frames == 0U && rssi < LMAC_TRC_RSSI_WEAK_LINK_DBM) {
            uint8_t clamp = (p->sched_mode == LMAC_SCHED_11N)
                            ? LMAC_TRC_WEAK_CLAMP_11N_IDX
                            : ((p->sched_mode == LMAC_SCHED_11G)
                               ? LMAC_TRC_WEAK_CLAMP_11G_IDX
                               : LMAC_TRC_WEAK_CLAMP_11B_IDX);
            if (clamp < p->min_idx) {
                clamp = p->min_idx;
            }
            if (p->cur_idx > clamp) {
                p->cur_idx = clamp;
            }
        }
        return;
    }
    /*
     * 7/8 old + 1/8 new EMA with directional rounding:
     * Because RSSI values are negative, C division truncates toward 0 (upward), which
     * would stall downward steps whenever |rssi - rssi_avg| < 8 (e.g. (-60*7 + -61)/8 = -60).
     * Subtracting 7 when rssi < rssi_avg rounds away from zero so the EMA converges in
     * both directions without floating point.
     */
    int32_t sum = (int32_t)p->rssi_avg * LMAC_TRC_RSSI_EMA_OLD_WEIGHT + (int32_t)rssi;
    int32_t avg = (rssi < p->rssi_avg)
                  ? ((sum - LMAC_TRC_RSSI_EMA_OLD_WEIGHT) / LMAC_TRC_RSSI_EMA_DENOM)
                  : (sum / LMAC_TRC_RSSI_EMA_DENOM);
    p->rssi_avg = (int8_t)avg;
}

/**
 * @brief Update the allowed 802.11 protocol bitmap for a VIF and rebuild active peer schedules.
 *
 * @param vif           Virtual interface (`ESP_LMAC_VIF_STA` or `ESP_LMAC_VIF_AP`).
 * @param proto_bitmap  Bitmask of `WIFI_PROTOCOL_11B`, `WIFI_PROTOCOL_11G`, `WIFI_PROTOCOL_11N`.
 */
void esp_lmac_set_protocol_mask(esp_lmac_vif_t vif, uint8_t proto_bitmap)
{
    if (vif >= ESP_LMAC_VIF_MAX) {
        return;
    }
    g_lmac.vif[vif].proto_mask = proto_bitmap;

    if (vif == ESP_LMAC_VIF_STA && g_lmac.sta_peer.valid) {
        configure_peer_schedule(&g_lmac.sta_peer);
    } else if (vif == ESP_LMAC_VIF_AP && g_lmac.ap_peers != NULL) {
        for (uint8_t i = 0U; i < g_lmac.ap_peer_cap; i++) {
            if (g_lmac.ap_peers[i].valid) {
                configure_peer_schedule(&g_lmac.ap_peers[i]);
            }
        }
    }
}

/**
 * @brief Select the WDEV hardware TX rate code for a given frame and retry attempt.
 *
 * Returns the VIF's lowest mandatory base rate for beacons, forced-lowest-rate frames,
 * or invalid/broadcast peer IDs. For unicast peer transmissions, applies a non-linear
 * per-packet retry fallback relative to `p->cur_idx`, enables 11b short preamble on
 * 2/5.5/11 Mbps when requested or supported by the peer, and dynamically promotes
 * MCS5/MCS6 to Short GI 20 MHz on attempts `0..1` when `LMAC_PEER_FLAG_SGI20` is
 * negotiated and link PER is low (MCS7 SGI20 is an explicit top index in `s_sched_11n[]`).
 *
 * @param peer_id    Target peer ID (`ESP_LMAC_PEER_INVALID` for broadcast/mgmt frames).
 * @param vif        Source virtual interface (`ESP_LMAC_VIF_STA` or `ESP_LMAC_VIF_AP`).
 * @param flags      `ESP_LMAC_TX_FLAG_*` bitmask for this transmission.
 * @param retry_idx  Zero-based attempt index (`0` = initial attempt, `1..7` = retries).
 * @return WDEV hardware rate code (`LMAC_RATE_*`).
 */
uint8_t lmac_trc_select_rate(esp_lmac_peer_id_t peer_id, esp_lmac_vif_t vif,
                             uint8_t flags, uint8_t retry_idx)
{
    uint8_t base = lowest_rate_for_vif(vif);

    if ((flags & (ESP_LMAC_TX_FLAG_FORCE_LOWEST_RATE | ESP_LMAC_TX_FLAG_BEACON)) != 0U ||
        peer_id == ESP_LMAC_PEER_INVALID) {
        return base;
    }

    lmac_peer_t *p = lmac_trc_get_peer(peer_id);
    if (p == NULL) {
        return base;
    }

    /*
     * Non-linear per-packet retry fallback table:
     *   attempt 0 (initial) & attempt 1 (1st retry): drop 0 steps (tolerate a single collision)
     *   attempts 2..6: drop 1, 2, 4, 6, 8 schedule indices (attempt >= 7: drop 8)
     * Dropping progressively faster ensures weak or suddenly faded links reach robust base
     * rates well before exhausting the 7-retry limit.
     */
    static const uint8_t s_retry_drop[LMAC_TRC_RETRY_DROP_LEN] = { 0U, 0U, 1U, 2U, 4U, 6U, 8U };
    uint8_t step = (retry_idx < LMAC_TRC_RETRY_DROP_LEN) ? s_retry_drop[retry_idx] : LMAC_TRC_RETRY_DROP_MAX;
    uint8_t idx = (p->cur_idx > (uint8_t)(p->min_idx + step))
                  ? (uint8_t)(p->cur_idx - step)
                  : p->min_idx;
    uint8_t hw_rate = sched_rate_at(p->sched_mode, idx);

    /* Apply 11b short preamble for 2M/5.5M/11M when peer supports it */
    if (hw_rate >= LMAC_RATE_11B_2M && hw_rate <= LMAC_RATE_11B_11M &&
        ((flags & ESP_LMAC_TX_FLAG_SHORT_PREAMBLE) != 0U || (p->flags & LMAC_PEER_FLAG_SHORT_PRE) != 0U)) {
        hw_rate |= LMAC_RATE_11B_SHORT_PRE_BIT;
    } else if ((hw_rate == LMAC_RATE_11N_MCS5 || hw_rate == LMAC_RATE_11N_MCS6) &&
               (p->flags & LMAC_PEER_FLAG_SGI20) != 0U &&
               retry_idx <= LMAC_TRC_SGI_MAX_RETRY_IDX && p->win_fails == 0U && p->consec_heavy == 0U &&
               ((uint16_t)p->win_retries * LMAC_TRC_STEP_UP_RETRY_INV) <= (uint16_t)p->win_frames &&
               (p->clean_windows > 0U || p->cur_idx == p->max_idx)) {
        /*
         * Dynamic SGI20 promotion on MCS5/MCS6:
         * Unlike MCS7 SGI20 (dedicated top step in s_sched_11n[]), MCS5/MCS6 SGI20 is
         * promoted opportunistically on attempts 0..1 when the link is clean (0 fails,
         * 0 consecutive heavy retries, retry ratio <= 1/8, and a clean window or at max_idx);
         * deeper retries automatically revert to Long GI for multipath robustness.
         */
        hw_rate |= LMAC_RATE_HT_SGI_BIT;
    }

    return hw_rate;
}

/**
 * @brief Compute the SIFS + ACK air-time in microseconds for the 802.11 Duration/NAV field.
 *
 * @param hw_rate  WDEV hardware rate code (`LMAC_RATE_*`) of the transmitted data/mgmt frame.
 * @return Duration in microseconds covering one SIFS plus the corresponding ACK frame.
 */
uint16_t lmac_trc_ack_duration_us(uint8_t hw_rate)
{
    /* SIFS + ACK air-time (us) for NAV Duration field */
    if (hw_rate >= LMAC_RATE_11N_MCS0) {
        return LMAC_TRC_ACK_DUR_HT_OFDM_HI_US; /* 16 us SIFS + 28 us 24M/6M OFDM ACK */
    }
    switch (hw_rate & LMAC_TXQ_RATE_CODE_MASK) {
    case LMAC_RATE_11B_1M:     return LMAC_TRC_ACK_DUR_11B_1M_US;
    case LMAC_RATE_11B_2M:     return LMAC_TRC_ACK_DUR_11B_2M_US;
    case LMAC_RATE_11B_2M_SP:  return LMAC_TRC_ACK_DUR_11B_2M_SP_US;
    case LMAC_RATE_11B_5_5M:   return LMAC_TRC_ACK_DUR_11B_5_5M_US;
    case LMAC_RATE_11B_5_5M_SP: return LMAC_TRC_ACK_DUR_11B_5_5M_SP_US;
    case LMAC_RATE_11B_11M:    return LMAC_TRC_ACK_DUR_11B_11M_US;
    case LMAC_RATE_11B_11M_SP: return LMAC_TRC_ACK_DUR_11B_11M_SP_US;
    case LMAC_RATE_11G_6M:
    case LMAC_RATE_11G_9M:     return LMAC_TRC_ACK_DUR_OFDM_6_9M_US;
    case LMAC_RATE_11G_12M:
    case LMAC_RATE_11G_18M:    return LMAC_TRC_ACK_DUR_OFDM_12_18M_US;
    default:                   return LMAC_TRC_ACK_DUR_HT_OFDM_HI_US; /* 24M..54M OFDM */
    }
}

/**
 * @brief Update a peer's AARF transmit rate state and ACK RSSI after a completed TX frame.
 *
 * Incorporates valid ACK RSSI into the peer's EMA, reacts immediately to consecutive
 * failures or heavy-retry bursts, and otherwise evaluates closed windows (16 frames or
 * >= 4 frames over 100 ms) using pure-integer retry-equivalent thresholds with AARF
 * exponential probe backoff (`up_hold` in `{1, 2, 4, 8}`).
 *
 * @param peer_id   Target peer ID (no-op if invalid/inactive).
 * @param ok        Non-zero if the frame was ACKed, `0` if TX failed/timed out.
 * @param retries   Number of hardware retry attempts executed before completion.
 * @param ack_rssi  Calibrated ACK RSSI in dBm, or `LMAC_RSSI_UNAVAILABLE` (`0x7F`).
 */
void lmac_trc_on_tx_result(esp_lmac_peer_id_t peer_id, uint8_t ok, uint8_t retries, int8_t ack_rssi)
{
    lmac_peer_t *p = lmac_trc_get_peer(peer_id);
    if (p == NULL) {
        return;
    }

    if (ok && ack_rssi != LMAC_RSSI_UNAVAILABLE &&
        ack_rssi <= LMAC_TRC_RSSI_MAX_VALID_DBM && ack_rssi >= LMAC_TRC_RSSI_MIN_VALID_DBM) {
        esp_lmac_peer_update_rssi(peer_id, ack_rssi);
    }

    uint32_t now_us = (uint32_t)esp_timer_get_time();

    /* Emergency fast drop on severe consecutive retries (>= 4) or consecutive TX failures */
    if (!ok) {
        p->consec_fail++;
        p->consec_heavy++;
    } else if (retries >= LMAC_TRC_HEAVY_RETRIES_MIN) {
        p->consec_fail = 0U;
        p->consec_heavy++;
    } else {
        p->consec_fail = 0U;
        p->consec_heavy = 0U;
    }

    if (p->consec_fail >= LMAC_TRC_CONSEC_FAIL_DROP || p->consec_heavy >= LMAC_TRC_CONSEC_HEAVY_DROP) {
        if (p->cur_idx > p->min_idx) {
            p->cur_idx--;
        }
        p->clean_windows = 0U;
        if (p->probing) {
            /* Failed during a step-up probe: double AARF hold count up to 8 */
            p->probing = 0U;
            if (p->up_hold < LMAC_TRC_AARF_HOLD_MAX) {
                p->up_hold = (uint8_t)(p->up_hold << 1);
            }
        }
        p->consec_fail = 0U;
        p->consec_heavy = 0U;
        trc_reset_window(p, now_us);
        return;
    }

    /* Accumulate window stats (pure integer, zero division, saturating uint8 counters) */
    p->win_frames++;
    if ((uint16_t)p->win_retries + retries > LMAC_TRC_WIN_STAT_SAT_MAX) {
        p->win_retries = LMAC_TRC_WIN_STAT_SAT_MAX;
    } else {
        p->win_retries = (uint8_t)(p->win_retries + retries);
    }
    if (!ok && p->win_fails < LMAC_TRC_WIN_STAT_SAT_MAX) {
        p->win_fails++;
    }

    bool win_due = (p->win_frames >= LMAC_TRC_WIN_MAX_FRAMES) ||
                   (p->win_frames >= LMAC_TRC_WIN_MIN_TIME_FRAMES &&
                    (uint32_t)(now_us - p->win_start_us) >= LMAC_TRC_WIN_MAX_US);
    if (!win_due) {
        return;
    }

    /*
     * Windowed integer retry-equivalent step-down test (zero division):
     * Each failed frame adds 4 retry-equivalents. Step down when:
     *   retry_eq / win_frames >= 5 / 4  (1.25 retry-equivalents per frame)
     * expressed in exact integer arithmetic as:
     *   retry_eq * 4 >= win_frames * 5
     */
    uint16_t retry_eq = (uint16_t)p->win_retries + (uint16_t)p->win_fails * LMAC_TRC_FAIL_RETRY_WEIGHT;
    bool step_down = ((uint32_t)retry_eq * LMAC_TRC_STEP_DOWN_DEN) >=
                     ((uint32_t)p->win_frames * LMAC_TRC_STEP_DOWN_NUM);

    if (step_down) {
        if (p->cur_idx > p->min_idx) {
            p->cur_idx--;
        }
        p->clean_windows = 0U;
        if (p->probing) {
            /* AARF exponential probe hold: double wait (1 -> 2 -> 4 -> 8) on failed probe */
            p->probing = 0U;
            if (p->up_hold < LMAC_TRC_AARF_HOLD_MAX) {
                p->up_hold = (uint8_t)(p->up_hold << 1);
            }
        }
    } else {
        if (p->probing) {
            /* Probe window survived without step-down: lock in new rate and reset AARF hold */
            p->probing = 0U;
            p->up_hold = LMAC_TRC_AARF_HOLD_INIT;
        }
        /*
         * Step-up cleanliness test (zero division):
         * Require 0 failures and retry ratio <= 1/8 (12.5%), expressed as:
         *   win_retries * 8 <= win_frames
         * (tolerates up to 2 single-retry collisions in a 16-frame window).
         * After `up_hold` consecutive clean windows, advance cur_idx by 1 and enter
         * probing mode so a bad probe backs off exponentially on the next window.
         */
        if (p->win_fails == 0U &&
            ((uint16_t)p->win_retries * LMAC_TRC_STEP_UP_RETRY_INV) <= (uint16_t)p->win_frames) {
            p->clean_windows++;
            if (p->clean_windows >= p->up_hold) {
                p->clean_windows = 0U;
                if (p->cur_idx < p->max_idx) {
                    p->cur_idx++;
                    p->probing = 1U;
                }
            }
        } else {
            p->clean_windows = 0U;
        }
    }

    trc_reset_window(p, now_us);
}
