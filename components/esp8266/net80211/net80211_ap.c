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
// TBTT TIM updates, Probe/Auth/Assoc responders, hostapd WPA2/WPA glue,
// PS buffering (global 4-packet tail-drop cap + PS-Poll/DTIM flush), and
// client inactivity aging.

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "net80211_internal.h"

#define TAG "wifi_ap"

extern void n8_mgmt_free_tx_cb(void *ctx, const esp_lmac_tx_status_t *st);

static const uint8_t s_ap_bcast[6] = { 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU };
static const uint8_t s_ap_rates_ie[] = {
    0x01U, 0x08U, 0x82U, 0x84U, 0x8BU, 0x96U, 0x0CU, 0x12U, 0x18U, 0x24U,
    0x32U, 0x04U, 0x30U, 0x48U, 0x60U, 0x6CU
};

static const uint8_t s_ap_ht20_cap_ie[28] = {
    IEEE80211_IE_HT_CAP, 26U,
    0x2CU, 0x01U, 0x1AU,
    0xFFU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
};

uint16_t n8_ap_next_seq(void)
{
    return (uint16_t)((g_n8.ap_tx_seq++ & 0x0FFFU) << 4);
}

n8_ap_sta_t *n8_ap_find_sta(const uint8_t mac[6])
{
    if (!g_n8.ap_running || g_n8.ap_stas == NULL || mac == NULL) {
        return NULL;
    }
    for (uint8_t i = 0U; i < g_n8.ap_sta_cap; i++) {
        if (g_n8.ap_stas[i].in_use && memcmp(g_n8.ap_stas[i].mac, mac, 6U) == 0) {
            return &g_n8.ap_stas[i];
        }
    }
    return NULL;
}

n8_ap_sta_t *n8_ap_find_sta_by_aid(uint16_t aid)
{
    if (!g_n8.ap_running || g_n8.ap_stas == NULL || aid == 0U || aid > g_n8.ap_sta_cap) {
        return NULL;
    }
    n8_ap_sta_t *sta = &g_n8.ap_stas[aid - 1U];
    return sta->in_use ? sta : NULL;
}

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
            memcpy(s->mac, mac, 6U);
            s->peer_id = ESP_LMAC_PEER_INVALID;
            s->last_rx_sec = g_n8.ap_uptime_sec;
            return s;
        }
    }
    return NULL;
}

static esp_err_t ap_tx_mgmt(uint8_t subtype, const uint8_t da[6],
                            const uint8_t *body, uint16_t body_len)
{
    uint8_t hdr[24];
    memset(hdr, 0, sizeof(hdr));
    hdr[0] = (uint8_t)(IEEE80211_FC_TYPE_MGMT | subtype);
    memcpy(hdr + 4U, da, 6U);
    memcpy(hdr + 10U, g_n8.ap_mac, 6U);
    memcpy(hdr + 16U, g_n8.ap_mac, 6U);
    uint16_t seq = n8_ap_next_seq();
    hdr[22] = (uint8_t)(seq & 0xFFU);
    hdr[23] = (uint8_t)(seq >> 8);

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
               ((da[0] & 1U) ? ESP_LMAC_TX_FLAG_NO_ACK : 0U);
    tx.hdr = hdr;
    tx.hdr_len = sizeof(hdr);
    tx.segs = (copy != NULL) ? &seg : NULL;
    tx.seg_cnt = (copy != NULL) ? 1U : 0U;
    tx.done_cb = (copy != NULL) ? n8_mgmt_free_tx_cb : NULL;
    tx.done_ctx = copy;

    esp_err_t err = esp_lmac_tx_submit(&tx);
    if (err != ESP_OK && copy != NULL) {
        heap_caps_free(copy);
    }
    return err;
}

/* --------------------------------------------------------------------------
 * SoftAP PS Buffering (Global 4-Packet Tail-Drop Cap + TIM Bitmap)
 * -------------------------------------------------------------------------- */

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

void n8_ap_ps_flush_bcast(void)
{
    if (g_n8.ap_ps_count == 0U) {
        return;
    }
    n8_ps_pkt_t **pp = &g_n8.ap_ps_head;
    n8_ps_pkt_t *prev = NULL;
    while (*pp != NULL) {
        n8_ps_pkt_t *cur = *pp;
        if (cur->aid == 0U) {
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
 * Beacon & Probe Response Synthesis (with TIM, HT20 & HostAP WPA/RSN IE)
 * -------------------------------------------------------------------------- */

static uint16_t ap_build_beacon_or_probe_body(uint8_t *out, uint16_t max_len,
                                              bool is_beacon, uint16_t *tim_offset_out)
{
    uint16_t off = 0U;
    uint16_t bi = g_n8.ap_cfg.ap.beacon_interval ? g_n8.ap_cfg.ap.beacon_interval : 100U;
    uint16_t cap = 0x0401U; /* ESS | Short Slot */
    if (g_n8.ap_cfg.ap.authmode != WIFI_AUTH_OPEN) {
        cap |= 0x0010U; /* Privacy */
    }

    /* Fixed 12-byte body: Timestamp (8) + Beacon Interval (2) + Capability (2) */
    memset(out, 0, 8U);
    off = 8U;
    out[off++] = (uint8_t)(bi & 0xFFU);
    out[off++] = (uint8_t)(bi >> 8);
    out[off++] = (uint8_t)(cap & 0xFFU);
    out[off++] = (uint8_t)(cap >> 8);

    /* SSID IE (hidden in beacons if ssid_hidden != 0) */
    uint8_t slen = g_n8.ap_cfg.ap.ssid_len;
    if (slen == 0U) {
        slen = (uint8_t)strnlen((const char *)g_n8.ap_cfg.ap.ssid, 32U);
    }
    if (slen > 32U) {
        slen = 32U;
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
    uint8_t ch = (g_n8.ap_cfg.ap.channel >= 1U && g_n8.ap_cfg.ap.channel <= 14U)
                 ? g_n8.ap_cfg.ap.channel : 1U;
    out[off++] = IEEE80211_IE_DS_PARAM;
    out[off++] = 1U;
    out[off++] = ch;

    /* TIM IE (in Beacons only): [ID=5, Len=5, DTIM_cnt, DTIM_per, BitmapCtrl, PVB[0], PVB[1]] */
    if (is_beacon) {
        if (tim_offset_out != NULL) {
            *tim_offset_out = (uint16_t)(24U + off);
        }
        uint16_t pvb = 0U;
        uint8_t bmc = 0U;
        for (n8_ps_pkt_t *p = g_n8.ap_ps_head; p != NULL; p = p->next) {
            if (p->aid == 0U) {
                bmc = 1U;
            } else if (p->aid < 16U) {
                pvb |= (uint16_t)(1U << p->aid);
            }
        }
        out[off++] = IEEE80211_IE_TIM;
        out[off++] = 5U;
        out[off++] = g_n8.ap_dtim_count;
        out[off++] = g_n8.ap_dtim_period ? g_n8.ap_dtim_period : 1U;
        out[off++] = (g_n8.ap_dtim_count == 0U) ? bmc : 0U;
        out[off++] = (uint8_t)(pvb & 0xFFU);
        out[off++] = (uint8_t)((pvb >> 8) & 0xFFU);
    }

    /* HT20 Capabilities + HT Operation IEs when 11n enabled */
    if ((g_n8.proto[1] & WIFI_PROTOCOL_11N) != 0U && (uint16_t)(off + 28U + 24U) <= max_len) {
        memcpy(out + off, s_ap_ht20_cap_ie, sizeof(s_ap_ht20_cap_ie));
        off = (uint16_t)(off + sizeof(s_ap_ht20_cap_ie));

        out[off++] = IEEE80211_IE_HT_OP;
        out[off++] = 22U;
        memset(out + off, 0, 22U);
        out[off] = ch; /* Primary channel */
        off = (uint16_t)(off + 22U);
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

    return off;
}

esp_err_t n8_ap_update_beacon(void)
{
    if (!g_n8.ap_running) {
        return ESP_OK;
    }

    uint8_t frame[320];
    memset(frame, 0, 24U);
    frame[0] = IEEE80211_FC_TYPE_MGMT | IEEE80211_SUBTYPE_BEACON;
    memcpy(frame + 4U, s_ap_bcast, 6U);
    memcpy(frame + 10U, g_n8.ap_mac, 6U);
    memcpy(frame + 16U, g_n8.ap_mac, 6U);

    uint16_t tim_off = 0U;
    uint16_t blen = ap_build_beacon_or_probe_body(frame + 24U, (uint16_t)(sizeof(frame) - 24U),
                                                  true, &tim_off);
    g_n8.ap_tim_offset = tim_off;

    uint16_t bi = g_n8.ap_cfg.ap.beacon_interval ? g_n8.ap_cfg.ap.beacon_interval : 100U;
    return esp_lmac_set_beacon(ESP_LMAC_VIF_AP, frame, (uint16_t)(24U + blen), tim_off, bi);
}

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

    /* Update TIM IE when PS-buffered packets exist */
    if (g_n8.ap_ps_count > 0U) {
        (void)n8_ap_update_beacon();
        if (g_n8.ap_dtim_count == 0U) {
            n8_ap_ps_flush_bcast();
        }
    }
}

void n8_ap_sync_channel(uint8_t new_channel)
{
    if (!g_n8.ap_running || new_channel < 1U || new_channel > 14U) {
        return;
    }
    g_n8.ap_cfg.ap.channel = new_channel;
    (void)n8_ap_update_beacon();
}

/* --------------------------------------------------------------------------
 * SoftAP Lifecycle (Mode-Scoped Peer Slab Allocation & Cleanup)
 * -------------------------------------------------------------------------- */

esp_err_t n8_ap_start(void)
{
    if (g_n8.ap_running) {
        return ESP_OK;
    }

    uint8_t max_conn = g_n8.ap_cfg.ap.max_connection;
    if (max_conn == 0U) {
        max_conn = 4U;
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
    esp_lmac_set_protocol_mask(ESP_LMAC_VIF_AP, g_n8.proto[1]);

    uint8_t ch = (g_n8.sta_state >= N8_STA_AUTH && g_n8.sta_channel >= 1U)
                 ? g_n8.sta_channel
                 : ((g_n8.ap_cfg.ap.channel >= 1U && g_n8.ap_cfg.ap.channel <= 14U)
                    ? g_n8.ap_cfg.ap.channel : 1U);
    g_n8.ap_cfg.ap.channel = ch;
    (void)esp_lmac_set_channel(ch);
    g_n8.cur_channel = ch;

    g_n8.ap_dtim_period = 2U;
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
             (int)(g_n8.ap_cfg.ap.ssid_len ? g_n8.ap_cfg.ap.ssid_len : strnlen((const char *)g_n8.ap_cfg.ap.ssid, 32U)),
             (const char *)g_n8.ap_cfg.ap.ssid, (unsigned)ch,
             (unsigned)g_n8.ap_cfg.ap.authmode, (unsigned)max_conn);

    system_event_t evt;
    memset(&evt, 0, sizeof(evt));
    evt.event_id = SYSTEM_EVENT_AP_START;
    n8_send_system_event(&evt);
    return ESP_OK;
}

void n8_ap_remove_sta(n8_ap_sta_t *sta, uint8_t reason, bool send_deauth)
{
    if (sta == NULL || !sta->in_use) {
        return;
    }

    if (send_deauth) {
        uint8_t body[2] = { reason, 0U };
        (void)ap_tx_mgmt(IEEE80211_SUBTYPE_DEAUTH, sta->mac, body, sizeof(body));
    }

    ap_ps_purge_aid(sta->aid);

    if (sta->wpa_sm != NULL && g_n8.wpa_cb != NULL && g_n8.wpa_cb->wpa_ap_remove != NULL) {
        (void)g_n8.wpa_cb->wpa_ap_remove(sta->wpa_sm);
        sta->wpa_sm = NULL;
    }
    if (sta->peer_id != ESP_LMAC_PEER_INVALID) {
        esp_lmac_peer_remove(sta->peer_id);
        sta->peer_id = ESP_LMAC_PEER_INVALID;
    }

    bool notify = (sta->assoced != 0U);
    uint8_t mac[6];
    uint8_t aid = sta->aid;
    memcpy(mac, sta->mac, 6U);
    memset(sta, 0, sizeof(*sta));

    if (notify) {
        system_event_t evt;
        memset(&evt, 0, sizeof(evt));
        evt.event_id = SYSTEM_EVENT_AP_STADISCONNECTED;
        memcpy(evt.event_info.sta_disconnected.mac, mac, 6U);
        evt.event_info.sta_disconnected.aid = aid;
        n8_send_system_event(&evt);
    }
}

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

void n8_ap_rx_mgmt(const wifi_pkt_rx_ctrl_t *ctrl, const uint8_t *frame, uint16_t len)
{
    if (!g_n8.ap_running || len < 24U) {
        return;
    }

    uint8_t subtype = (uint8_t)(frame[0] & IEEE80211_FC_SUBTYPE_MASK);
    const uint8_t *da = frame + 4U;
    const uint8_t *sa = frame + 10U;

    /* Probe Request (may be broadcast or addressed to AP MAC) */
    if (subtype == IEEE80211_SUBTYPE_PROBE_REQ) {
        if ((da[0] & 1U) == 0U && memcmp(da, g_n8.ap_mac, 6U) != 0) {
            return;
        }
        /* Check SSID IE matches wildcard or our AP SSID */
        const uint8_t *ies = frame + 24U;
        uint16_t ie_len = (uint16_t)(len - 24U);
        bool ssid_match = true;
        if (ie_len >= 2U && ies[0] == IEEE80211_IE_SSID && ies[1] > 0U) {
            uint8_t ap_slen = g_n8.ap_cfg.ap.ssid_len;
            if (ap_slen == 0U) {
                ap_slen = (uint8_t)strnlen((const char *)g_n8.ap_cfg.ap.ssid, 32U);
            }
            if (ies[1] != ap_slen || (uint16_t)(2U + ies[1]) > ie_len ||
                memcmp(ies + 2U, g_n8.ap_cfg.ap.ssid, ap_slen) != 0) {
                ssid_match = false;
            }
        }
        if (ssid_match) {
            uint8_t resp[288];
            uint16_t blen = ap_build_beacon_or_probe_body(resp, sizeof(resp), false, NULL);
            (void)ap_tx_mgmt(IEEE80211_SUBTYPE_PROBE_RESP, sa, resp, blen);

            if ((g_n8.event_mask & WIFI_EVENT_MASK_AP_PROBEREQRECVED) == 0U) {
                system_event_t evt;
                memset(&evt, 0, sizeof(evt));
                evt.event_id = SYSTEM_EVENT_AP_PROBEREQRECVED;
                evt.event_info.ap_probereqrecved.rssi = (int8_t)ctrl->rssi;
                memcpy(evt.event_info.ap_probereqrecved.mac, sa, 6U);
                n8_send_system_event(&evt);
            }
        }
        return;
    }

    /* Remaining mgmt frames must be addressed to our AP MAC */
    if (memcmp(da, g_n8.ap_mac, 6U) != 0) {
        return;
    }

    if (subtype == IEEE80211_SUBTYPE_AUTH && len >= 30U) {
        uint16_t alg = (uint16_t)((uint16_t)frame[24] | ((uint16_t)frame[25] << 8));
        uint16_t seq = (uint16_t)((uint16_t)frame[26] | ((uint16_t)frame[27] << 8));
        uint16_t status = 0U;

        if (alg != IEEE80211_AUTH_ALG_OPEN || seq != 1U) {
            status = 13U; /* Unsupported auth algorithm */
        } else {
            n8_ap_sta_t *sta = ap_alloc_sta(sa);
            if (sta == NULL) {
                status = 17U; /* AP unable to handle additional STAs */
            } else {
                sta->authed = 1U;
                sta->last_rx_sec = g_n8.ap_uptime_sec;
            }
        }

        uint8_t resp[6] = {
            (uint8_t)(alg & 0xFFU), (uint8_t)(alg >> 8),
            2U, 0U,
            (uint8_t)(status & 0xFFU), (uint8_t)(status >> 8)
        };
        (void)ap_tx_mgmt(IEEE80211_SUBTYPE_AUTH, sa, resp, sizeof(resp));
        return;
    }

    if ((subtype == IEEE80211_SUBTYPE_ASSOC_REQ || subtype == IEEE80211_SUBTYPE_REASSOC_REQ) &&
        len >= 28U) {
        uint16_t ie_off = (subtype == IEEE80211_SUBTYPE_REASSOC_REQ) ? 34U : 28U;
        if (len < ie_off) {
            return;
        }

        n8_ap_sta_t *sta = n8_ap_find_sta(sa);
        uint16_t status = 0U;
        if (sta == NULL || !sta->authed) {
            uint8_t deauth[2] = { WIFI_REASON_NOT_AUTHED, 0U };
            (void)ap_tx_mgmt(IEEE80211_SUBTYPE_DEAUTH, sa, deauth, sizeof(deauth));
            return;
        }

        /* Parse client IEs (HT Caps + RSN/WPA IE) */
        const uint8_t *ies = frame + ie_off;
        uint16_t ie_len = (uint16_t)(len - ie_off);
        uint16_t pos = 0U;
        const uint8_t *sec_ie = NULL;
        uint8_t sec_ie_len = 0U;
        uint8_t ht_cap = 0U;
        uint8_t ht_mcs = 0U;

        while (pos + 2U <= ie_len) {
            uint8_t id = ies[pos];
            uint8_t elen = ies[pos + 1U];
            if (pos + 2U + elen > ie_len) {
                break;
            }
            if (id == IEEE80211_IE_HT_CAP && elen >= 26U) {
                ht_cap = 1U;
                ht_mcs = ies[pos + 2U + 3U];
            } else if (id == IEEE80211_IE_RSN) {
                sec_ie = &ies[pos];
                sec_ie_len = (uint8_t)(elen + 2U);
            } else if (id == IEEE80211_IE_VENDOR && elen >= 4U &&
                       ies[pos + 2U] == 0x00U && ies[pos + 3U] == 0x50U &&
                       ies[pos + 4U] == 0xF2U && ies[pos + 5U] == 0x01U && sec_ie == NULL) {
                sec_ie = &ies[pos];
                sec_ie_len = (uint8_t)(elen + 2U);
            }
            pos = (uint16_t)(pos + 2U + elen);
        }

        /* Register peer in LMAC TRC */
        esp_lmac_peer_caps_t pcaps = {0};
        memcpy(pcaps.mac, sta->mac, 6U);
        pcaps.rate_mask_11bg = 0x0FFFU;
        pcaps.ht20_mcs_mask = (ht_cap && (g_n8.proto[1] & WIFI_PROTOCOL_11N)) ? (ht_mcs ? ht_mcs : 0xFFU) : 0U;
        pcaps.ht_enabled = (pcaps.ht20_mcs_mask != 0U) ? 1U : 0U;
        pcaps.qos_enabled = pcaps.ht_enabled;
        sta->peer_id = esp_lmac_peer_add(ESP_LMAC_VIF_AP, &pcaps);
        sta->ht_enabled = pcaps.ht_enabled;
        sta->qos_enabled = pcaps.qos_enabled;
        sta->phy_11b = 1U;
        sta->phy_11g = 1U;
        sta->phy_11n = pcaps.ht_enabled;
        sta->assoced = 1U;
        sta->last_rx_sec = g_n8.ap_uptime_sec;

        /* Build and send AssocResp BEFORE launching hostapd 4-way handshake */
        uint8_t resp[96];
        uint16_t roff = 0U;
        uint16_t cap = 0x0401U | ((g_n8.ap_cfg.ap.authmode != WIFI_AUTH_OPEN) ? 0x0010U : 0U);
        resp[roff++] = (uint8_t)(cap & 0xFFU);
        resp[roff++] = (uint8_t)(cap >> 8);
        resp[roff++] = (uint8_t)(status & 0xFFU);
        resp[roff++] = (uint8_t)(status >> 8);
        uint16_t aid_field = (uint16_t)(0xC000U | sta->aid);
        resp[roff++] = (uint8_t)(aid_field & 0xFFU);
        resp[roff++] = (uint8_t)(aid_field >> 8);
        memcpy(resp + roff, s_ap_rates_ie, sizeof(s_ap_rates_ie));
        roff = (uint16_t)(roff + sizeof(s_ap_rates_ie));
        if (sta->ht_enabled) {
            memcpy(resp + roff, s_ap_ht20_cap_ie, sizeof(s_ap_ht20_cap_ie));
            roff = (uint16_t)(roff + sizeof(s_ap_ht20_cap_ie));
        }

        uint8_t resp_sub = (subtype == IEEE80211_SUBTYPE_REASSOC_REQ)
                           ? IEEE80211_SUBTYPE_REASSOC_RESP : IEEE80211_SUBTYPE_ASSOC_RESP;
        (void)ap_tx_mgmt(resp_sub, sa, resp, roff);

        if (g_n8.ap_cfg.ap.authmode == WIFI_AUTH_OPEN) {
            sta->authorized = 1U;
        } else {
            sta->authorized = 0U;
            if (g_n8.wpa_cb != NULL && g_n8.wpa_cb->wpa_ap_join != NULL) {
                if (!g_n8.wpa_cb->wpa_ap_join(&sta->wpa_sm, sta->mac,
                                              (uint8_t *)(uintptr_t)sec_ie, sec_ie_len)) {
                    n8_ap_remove_sta(sta, WIFI_REASON_INVALID_RSN_IE_CAP, true);
                    return;
                }
            }
        }

        system_event_t evt;
        memset(&evt, 0, sizeof(evt));
        evt.event_id = SYSTEM_EVENT_AP_STACONNECTED;
        memcpy(evt.event_info.sta_connected.mac, sta->mac, 6U);
        evt.event_info.sta_connected.aid = sta->aid;
        n8_send_system_event(&evt);
        return;
    }

    if (subtype == IEEE80211_SUBTYPE_DEAUTH || subtype == IEEE80211_SUBTYPE_DISASSOC) {
        n8_ap_sta_t *sta = n8_ap_find_sta(sa);
        if (sta != NULL) {
            n8_ap_remove_sta(sta, WIFI_REASON_ASSOC_LEAVE, false);
        }
    }
}

void n8_ap_rx_ctrl(const uint8_t *frame, uint16_t len)
{
    if (!g_n8.ap_running || len < 16U) {
        return;
    }
    if ((frame[0] & IEEE80211_FC_SUBTYPE_MASK) == IEEE80211_SUBTYPE_PS_POLL) {
        uint16_t aid = (uint16_t)(((uint16_t)frame[2] | ((uint16_t)frame[3] << 8)) & 0x3FFFU);
        n8_ap_sta_t *sta = n8_ap_find_sta_by_aid(aid);
        if (sta != NULL) {
            sta->last_rx_sec = g_n8.ap_uptime_sec;
            n8_ap_ps_flush_sta(sta, true);
        }
    }
}

void n8_ap_on_tick_100ms(void)
{
    if (!g_n8.ap_running || g_n8.ap_stas == NULL) {
        return;
    }

    g_n8.ap_sec_subtick++;
    if (g_n8.ap_sec_subtick < 10U) {
        return;
    }
    g_n8.ap_sec_subtick = 0U;
    g_n8.ap_uptime_sec++;

    uint32_t max_idle = g_n8.inactive_sec[1] ? g_n8.inactive_sec[1] : 300U;
    for (uint8_t i = 0U; i < g_n8.ap_sta_cap; i++) {
        n8_ap_sta_t *sta = &g_n8.ap_stas[i];
        if (sta->in_use && (g_n8.ap_uptime_sec - sta->last_rx_sec) >= max_idle) {
            ESP_LOGD(TAG, "SoftAP aging out inactive STA aid=%u", (unsigned)sta->aid);
            n8_ap_remove_sta(sta, WIFI_REASON_ASSOC_EXPIRE, true);
        }
    }
}
