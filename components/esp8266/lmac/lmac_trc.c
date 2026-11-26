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
 * Hardware Rate Schedules in Flash (.rodata, Zero DRAM)
 *
 * ESP8266 WDEV hardware rate encodings:
 *   11b long preamble : 0x00=1M, 0x01=2M, 0x02=5.5M, 0x03=11M
 *   11b short preamble: 0x05=2M, 0x06=5.5M, 0x07=11M
 *   11g OFDM          : 0x0B=6M, 0x0F=9M, 0x0A=12M, 0x0E=18M,
 *                       0x09=24M, 0x0D=36M, 0x08=48M, 0x0C=54M
 *   11n HT20 (bit4=1) : 0x10..0x17 = MCS0..MCS7
 * -------------------------------------------------------------------------- */

static const uint8_t s_sched_11b[] = {
    0x00U, 0x01U, 0x02U, 0x03U,
};

static const uint8_t s_sched_11g[] = {
    0x00U, 0x01U, 0x02U, 0x0BU, 0x03U, 0x0AU, 0x0EU, 0x09U, 0x0DU, 0x08U, 0x0CU,
};

static const uint8_t s_sched_11n[] = {
    0x00U, 0x01U, 0x02U, 0x0BU, 0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
};

static uint8_t sched_len(uint8_t mode)
{
    if (mode == 2U) {
        return (uint8_t)sizeof(s_sched_11n);
    }
    if (mode == 1U) {
        return (uint8_t)sizeof(s_sched_11g);
    }
    return (uint8_t)sizeof(s_sched_11b);
}

static uint8_t sched_rate_at(uint8_t mode, uint8_t idx)
{
    uint8_t len = sched_len(mode);
    if (idx >= len) {
        idx = (uint8_t)(len - 1U);
    }
    if (mode == 2U) {
        return s_sched_11n[idx];
    }
    if (mode == 1U) {
        return s_sched_11g[idx];
    }
    return s_sched_11b[idx];
}

static uint8_t lowest_rate_for_vif(esp_lmac_vif_t vif)
{
    uint8_t proto = (vif < ESP_LMAC_VIF_MAX) ? g_lmac.vif[vif].proto_mask : 0U;
    if (proto != 0U && (proto & WIFI_PROTOCOL_11B) == 0U) {
        return 0x0BU; /* 6 Mbps OFDM when 11b is explicitly disabled */
    }
    return 0x00U; /* 1 Mbps CCK */
}

void lmac_trc_init(void)
{
    memset(&g_lmac.sta_peer, 0, sizeof(g_lmac.sta_peer));
    g_lmac.sta_peer.ptk_hw_slot = 0xFFU;
    g_lmac.ap_peers = NULL;
    g_lmac.ap_peer_cap = 0U;
}

esp_err_t esp_lmac_peer_alloc_ap_pool(uint8_t max_ap_peers)
{
    esp_lmac_peer_free_ap_pool();
    if (max_ap_peers == 0U) {
        return ESP_OK;
    }
    if (max_ap_peers > 10U) {
        max_ap_peers = 10U;
    }

    lmac_peer_t *pool = (lmac_peer_t *)heap_caps_calloc(max_ap_peers, sizeof(lmac_peer_t), MALLOC_CAP_8BIT);
    if (pool == NULL) {
        return ESP_ERR_NO_MEM;
    }
    for (uint8_t i = 0U; i < max_ap_peers; i++) {
        pool[i].ptk_hw_slot = 0xFFU;
    }
    g_lmac.ap_peers = pool;
    g_lmac.ap_peer_cap = max_ap_peers;
    return ESP_OK;
}

void esp_lmac_peer_free_ap_pool(void)
{
    if (g_lmac.ap_peers != NULL) {
        heap_caps_free(g_lmac.ap_peers);
        g_lmac.ap_peers = NULL;
    }
    g_lmac.ap_peer_cap = 0U;
}

lmac_peer_t *lmac_trc_get_peer(esp_lmac_peer_id_t peer_id)
{
    if (peer_id == 0U) {
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

static void trc_reset_window(lmac_peer_t *p, uint32_t now_us)
{
    p->win_frames = 0U;
    p->win_retries = 0U;
    p->win_fails = 0U;
    p->win_start_us = now_us;
}

static void configure_peer_schedule(lmac_peer_t *p)
{
    uint8_t proto = (p->vif < ESP_LMAC_VIF_MAX) ? g_lmac.vif[p->vif].proto_mask : 0U;
    if (proto == 0U) {
        proto = WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N;
    }

    if ((p->flags & 0x08U) != 0U && (proto & WIFI_PROTOCOL_11N) != 0U && p->ht20_mcs_mask != 0U) {
        p->sched_mode = 2U;
        uint8_t top_mcs = 0U;
        for (uint8_t m = 0U; m < 8U; m++) {
            if ((p->ht20_mcs_mask & (1U << m)) != 0U) {
                top_mcs = m;
            }
        }
        p->max_idx = (uint8_t)(4U + top_mcs);
        p->min_idx = ((proto & WIFI_PROTOCOL_11B) != 0U) ? 0U : 3U;
#ifdef CONFIG_WIFI_TX_RATE_SEQUENCE_FROM_HIGH
        p->cur_idx = p->max_idx; /* Start at highest supported MCS (MCS7) */
#else
        p->cur_idx = (p->max_idx >= 8U) ? 8U : p->max_idx; /* Start at MCS4 */
#endif
    } else if ((proto & WIFI_PROTOCOL_11G) != 0U && (p->rate_mask_11bg == 0U || (p->rate_mask_11bg & 0x0FF0U) != 0U)) {
        p->sched_mode = 1U;
        p->max_idx = (uint8_t)(sizeof(s_sched_11g) - 1U);
        p->min_idx = ((proto & WIFI_PROTOCOL_11B) != 0U) ? 0U : 3U;
#ifdef CONFIG_WIFI_TX_RATE_SEQUENCE_FROM_HIGH
        p->cur_idx = p->max_idx; /* Start at 54 Mbps */
#else
        p->cur_idx = 7U; /* Start at 24 Mbps */
#endif
    } else {
        p->sched_mode = 0U;
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
    p->up_hold = 1U;
    p->probing = 0U;
    p->consec_heavy = 0U;
    p->consec_fail = 0U;
    trc_reset_window(p, (uint32_t)esp_timer_get_time());
}

esp_lmac_peer_id_t esp_lmac_peer_add(esp_lmac_vif_t vif, const esp_lmac_peer_caps_t *caps)
{
    if (vif >= ESP_LMAC_VIF_MAX || caps == NULL) {
        return ESP_LMAC_PEER_INVALID;
    }

    lmac_peer_t *p = NULL;
    esp_lmac_peer_id_t id = ESP_LMAC_PEER_INVALID;

    if (vif == ESP_LMAC_VIF_STA) {
        p = &g_lmac.sta_peer;
        id = 0U;
    } else {
        if (g_lmac.ap_peers == NULL) {
            return ESP_LMAC_PEER_INVALID;
        }
        /* Reuse existing entry for the same MAC if present */
        for (uint8_t i = 0U; i < g_lmac.ap_peer_cap; i++) {
            if (g_lmac.ap_peers[i].valid && memcmp(g_lmac.ap_peers[i].mac, caps->mac, 6U) == 0) {
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

    uint8_t saved_slot = p->valid ? p->ptk_hw_slot : 0xFFU;
    uint8_t saved_cipher = p->valid ? p->ptk_cipher : (uint8_t)ESP_LMAC_CIPHER_NONE;

    memset(p, 0, sizeof(*p));
    p->valid = 1U;
    p->vif = vif;
    memcpy(p->mac, caps->mac, 6U);
    p->rate_mask_11bg = caps->rate_mask_11bg;
    p->ht20_mcs_mask = caps->ht20_mcs_mask;
    p->flags = (uint8_t)((caps->short_preamble ? 0x01U : 0U) |
                         (caps->short_gi_20    ? 0x02U : 0U) |
                         (caps->qos_enabled    ? 0x04U : 0U) |
                         (caps->ht_enabled     ? 0x08U : 0U));
    p->rssi_avg = -65;
    p->ptk_hw_slot = saved_slot;
    p->ptk_cipher = saved_cipher;

    configure_peer_schedule(p);
    return id;
}

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
    p->ptk_hw_slot = 0xFFU;
}

int8_t esp_lmac_peer_get_rssi(esp_lmac_peer_id_t peer_id)
{
    lmac_peer_t *p = lmac_trc_get_peer(peer_id);
    return (p != NULL) ? p->rssi_avg : -127;
}

void esp_lmac_peer_update_rssi(esp_lmac_peer_id_t peer_id, int8_t rssi)
{
    lmac_peer_t *p = lmac_trc_get_peer(peer_id);
    if (p == NULL || rssi > 0 || rssi < -120) {
        return;
    }
    if (!p->rssi_inited) {
        p->rssi_avg = rssi;
        p->rssi_inited = 1U;
        /* One-time weak-link initial clamp on join before runtime TX feedback */
        if (p->win_frames == 0U && rssi < -80) {
            uint8_t clamp = (p->sched_mode == 2U) ? 6U : ((p->sched_mode == 1U) ? 5U : 2U); /* MCS2 / 12M / 5.5M */
            if (clamp < p->min_idx) {
                clamp = p->min_idx;
            }
            if (p->cur_idx > clamp) {
                p->cur_idx = clamp;
            }
        }
        return;
    }
    /* Exponential moving average: 7/8 old + 1/8 new with directional rounding to avoid stalls */
    int32_t sum = (int32_t)p->rssi_avg * 7 + (int32_t)rssi;
    int32_t avg = (rssi < p->rssi_avg) ? ((sum - 7) / 8) : (sum / 8);
    p->rssi_avg = (int8_t)avg;
}

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

    /* Non-linear per-packet retry fallback so weak links drop rapidly before exhausting 7 retries */
    static const uint8_t s_retry_drop[7] = { 0U, 0U, 1U, 2U, 4U, 6U, 8U };
    uint8_t step = (retry_idx < 7U) ? s_retry_drop[retry_idx] : 8U;
    uint8_t idx = (p->cur_idx > (uint8_t)(p->min_idx + step))
                  ? (uint8_t)(p->cur_idx - step)
                  : p->min_idx;
    uint8_t hw_rate = sched_rate_at(p->sched_mode, idx);

    /* Apply 11b short preamble for 2M/5.5M/11M when peer supports it */
    if (hw_rate >= 1U && hw_rate <= 3U && ((flags & ESP_LMAC_TX_FLAG_SHORT_PREAMBLE) != 0U ||
                                           (p->flags & 0x01U) != 0U)) {
        hw_rate |= 0x04U;
    }

    return hw_rate;
}

uint16_t lmac_trc_ack_duration_us(uint8_t hw_rate)
{
    /* SIFS + ACK air-time (us) for NAV Duration field */
    if (hw_rate >= 0x10U) {
        return 44U; /* 16 us SIFS + 28 us 24M/6M OFDM ACK */
    }
    switch (hw_rate & 0x0FU) {
    case 0x00U: return 314U; /* 1M CCK long preamble */
    case 0x01U: return 258U; /* 2M CCK long */
    case 0x05U: return 162U; /* 2M CCK short */
    case 0x02U: return 222U; /* 5.5M CCK long */
    case 0x06U: return 126U; /* 5.5M CCK short */
    case 0x03U: return 212U; /* 11M CCK long */
    case 0x07U: return 116U; /* 11M CCK short */
    case 0x0BU:
    case 0x0FU: return 60U;  /* 6M/9M OFDM */
    case 0x0AU:
    case 0x0EU: return 48U;  /* 12M/18M OFDM */
    default:    return 44U;  /* 24M..54M OFDM */
    }
}

void lmac_trc_on_tx_result(esp_lmac_peer_id_t peer_id, uint8_t ok, uint8_t retries, int8_t ack_rssi)
{
    lmac_peer_t *p = lmac_trc_get_peer(peer_id);
    if (p == NULL) {
        return;
    }

    if (ok && ack_rssi != 0x7F && ack_rssi <= 0 && ack_rssi >= -120) {
        esp_lmac_peer_update_rssi(peer_id, ack_rssi);
    }

    uint32_t now_us = (uint32_t)esp_timer_get_time();

    /* Emergency fast drop on severe consecutive retries or consecutive TX failures */
    if (!ok) {
        p->consec_fail++;
        p->consec_heavy++;
    } else if (retries >= 4U) {
        p->consec_fail = 0U;
        p->consec_heavy++;
    } else {
        p->consec_fail = 0U;
        p->consec_heavy = 0U;
    }

    if (p->consec_fail >= 2U || p->consec_heavy >= 3U) {
        if (p->cur_idx > p->min_idx) {
            p->cur_idx--;
        }
        p->clean_windows = 0U;
        if (p->probing) {
            p->probing = 0U;
            if (p->up_hold < 8U) {
                p->up_hold = (uint8_t)(p->up_hold << 1);
            }
        }
        p->consec_fail = 0U;
        p->consec_heavy = 0U;
        trc_reset_window(p, now_us);
        return;
    }

    /* Accumulate window stats (pure integer, zero division) */
    p->win_frames++;
    if ((uint16_t)p->win_retries + retries > 255U) {
        p->win_retries = 255U;
    } else {
        p->win_retries = (uint8_t)(p->win_retries + retries);
    }
    if (!ok && p->win_fails < 255U) {
        p->win_fails++;
    }

    bool win_due = (p->win_frames >= 16U) ||
                   (p->win_frames >= 4U && (uint32_t)(now_us - p->win_start_us) >= 100000U);
    if (!win_due) {
        return;
    }

    uint16_t retry_eq = (uint16_t)p->win_retries + (uint16_t)p->win_fails * 4U;
    bool step_down = ((uint32_t)retry_eq * 4U) >= ((uint32_t)p->win_frames * 5U); /* >= 1.25 retry-eq/frame */

    if (step_down) {
        if (p->cur_idx > p->min_idx) {
            p->cur_idx--;
        }
        p->clean_windows = 0U;
        if (p->probing) {
            /* AARF exponential probe backoff on failed step-up probe */
            p->probing = 0U;
            if (p->up_hold < 8U) {
                p->up_hold = (uint8_t)(p->up_hold << 1);
            }
        }
    } else {
        if (p->probing) {
            /* Probe window survived without step-down: lock in and reset backoff */
            p->probing = 0U;
            p->up_hold = 1U;
        }
        /* Step UP when 0 failures and <= 12.5% retry ratio (tolerates 2 single-retry collisions / 16 frames) */
        if (p->win_fails == 0U && ((uint16_t)p->win_retries * 8U) <= (uint16_t)p->win_frames) {
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
