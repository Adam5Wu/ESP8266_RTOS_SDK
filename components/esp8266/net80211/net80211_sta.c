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
// 802.11n HT20 association, 4-Way Handshake coordination, 802.11w PMF/SA-Query,
// ADDBA/DELBA RX Block-Ack negotiation, and beacon-loss watchdog.

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "net80211_internal.h"

#define TAG "wifi_sta"

#define SAE_MSG_COMMIT_TYPE                 1U
#define SAE_MSG_CONFIRM_TYPE                2U
#define WLAN_STATUS_SUCCESS_CODE            0U
#define WLAN_STATUS_ANTI_CLOGGING_CODE      76U

#define N8_STA_AUTH_TIMEOUT_TICKS           2U   /* 200 ms */
#define N8_STA_ASSOC_TIMEOUT_TICKS          2U   /* 200 ms */
#define N8_STA_4WAY_TIMEOUT_TICKS           50U  /* 5.0 s */
#define N8_STA_MAX_AUTH_RETRIES             6U

static const uint8_t s_sta_rates_ie[] = {
    0x01U, 0x08U, 0x82U, 0x84U, 0x8BU, 0x96U, 0x0CU, 0x12U, 0x18U, 0x24U,
    0x32U, 0x04U, 0x30U, 0x48U, 0x60U, 0x6CU
};

/* 802.11n HT20 Capabilities IE (26-byte body: SGI20, MCS0..7, max A-MPDU 16KB) */
static const uint8_t s_ht20_cap_ie[28] = {
    IEEE80211_IE_HT_CAP, 26U,
    0x2CU, 0x01U, /* HT Cap Info: SM PS disabled, Short GI 20MHz, Rx STBC 1-stream */
    0x1AU,        /* A-MPDU params: max 16KB (2), min spacing 8us */
    0xFFU, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, /* MCS0..7 */
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, /* Extended HT Caps */
    0x00U, 0x00U, 0x00U, 0x00U, /* TxBF */
    0x00U         /* ASEL */
};

uint16_t n8_sta_next_seq(void)
{
    uint16_t s = (uint16_t)((g_n8.sta_tx_seq++ & 0x0FFFU) << 4);
    return s;
}

void n8_mgmt_free_tx_cb(void *ctx, const esp_lmac_tx_status_t *st)
{
    (void)st;
    if (ctx != NULL) {
        heap_caps_free(ctx);
    }
}

static esp_err_t sta_tx_mgmt(uint8_t subtype, const uint8_t *body, uint16_t body_len,
                             bool force_lowest, bool protected_mgmt)
{
    uint8_t hdr[32];
    uint16_t hdr_len = 24U;
    memset(hdr, 0, sizeof(hdr));

    hdr[0] = (uint8_t)(IEEE80211_FC_TYPE_MGMT | subtype);
    hdr[1] = protected_mgmt ? IEEE80211_FC1_PROTECTED : 0U;
    memcpy(hdr + 4U, g_n8.sta_bssid, 6U);
    memcpy(hdr + 10U, g_n8.sta_mac, 6U);
    memcpy(hdr + 16U, g_n8.sta_bssid, 6U);
    uint16_t seq = n8_sta_next_seq();
    hdr[22] = (uint8_t)(seq & 0xFFU);
    hdr[23] = (uint8_t)(seq >> 8);

    esp_lmac_cipher_t cipher = ESP_LMAC_CIPHER_NONE;
    uint8_t trailer_len = 0U;
    if (protected_mgmt && g_n8.sta_ptk_cipher == ESP_LMAC_CIPHER_CCMP) {
        uint64_t pn = g_n8.sta_tx_pn++;
        hdr[24] = (uint8_t)(pn & 0xFFU);
        hdr[25] = (uint8_t)((pn >> 8) & 0xFFU);
        hdr[26] = 0U;
        hdr[27] = 0x20U; /* ExtIV=1, KeyID=0 */
        hdr[28] = (uint8_t)((pn >> 16) & 0xFFU);
        hdr[29] = (uint8_t)((pn >> 24) & 0xFFU);
        hdr[30] = (uint8_t)((pn >> 32) & 0xFFU);
        hdr[31] = (uint8_t)((pn >> 40) & 0xFFU);
        hdr_len = 32U;
        cipher = ESP_LMAC_CIPHER_CCMP;
        trailer_len = 8U;
    }

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
    tx.peer_id = protected_mgmt ? g_n8.sta_peer_id : ESP_LMAC_PEER_INVALID;
    tx.ac = ESP_LMAC_AC_MGMT;
    tx.cipher = cipher;
    tx.flags = force_lowest ? ESP_LMAC_TX_FLAG_FORCE_LOWEST_RATE : 0U;
    tx.hdr = hdr;
    tx.hdr_len = hdr_len;
    tx.segs = (copy != NULL) ? &seg : NULL;
    tx.seg_cnt = (copy != NULL) ? 1U : 0U;
    tx.trailer_len = trailer_len;
    tx.done_cb = (copy != NULL) ? n8_mgmt_free_tx_cb : NULL;
    tx.done_ctx = copy;

    esp_err_t err = esp_lmac_tx_submit(&tx);
    if (err != ESP_OK && copy != NULL) {
        heap_caps_free(copy);
    }
    return err;
}

static void sta_send_deauth(uint8_t reason)
{
    uint8_t body[2] = { reason, 0U };
    bool prot = (g_n8.sta_state == N8_STA_RUN) && (g_n8.sta_pmf_active != 0U) &&
                (g_n8.sta_ptk_cipher == ESP_LMAC_CIPHER_CCMP);
    (void)sta_tx_mgmt(IEEE80211_SUBTYPE_DEAUTH, body, sizeof(body), true, prot);
}

static void sta_send_auth_open(void)
{
    uint8_t body[6] = {
        IEEE80211_AUTH_ALG_OPEN, 0U,
        1U, 0U, /* seq 1 */
        0U, 0U  /* status 0 */
    };
    (void)sta_tx_mgmt(IEEE80211_SUBTYPE_AUTH, body, sizeof(body), true, false);
}

static bool sta_send_auth_sae(uint8_t sae_type)
{
#ifdef CONFIG_ESP8266_WIFI_ENABLE_WPA3_SAE
    if (g_n8.wpa_cb == NULL || g_n8.wpa_cb->wpa3_build_sae_msg == NULL) {
        return false;
    }
    size_t sae_len = 0U;
    uint8_t *sae_msg = g_n8.wpa_cb->wpa3_build_sae_msg(g_n8.sta_bssid, sae_type, &sae_len);
    if (sae_msg == NULL || sae_len == 0U || sae_len > 384U) {
        return false;
    }

    uint16_t body_len = (uint16_t)(6U + sae_len);
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
    memcpy(body + 6U, sae_msg, sae_len);

    esp_err_t err = sta_tx_mgmt(IEEE80211_SUBTYPE_AUTH, body, body_len, true, false);
    heap_caps_free(body);
    return (err == ESP_OK);
#else
    (void)sae_type;
    return false;
#endif
}

static void sta_send_assoc_req(void)
{
    uint8_t body[256];
    uint16_t off = 0U;

    uint16_t cap = 0x0401U; /* ESS | Short Slot */
    if (g_n8.sta_authmode != WIFI_AUTH_OPEN) {
        cap |= 0x0010U; /* Privacy */
    }
    if ((g_n8.sta_capinfo & 0x0020U) != 0U) {
        cap |= 0x0020U; /* Short Preamble */
    }

    body[off++] = (uint8_t)(cap & 0xFFU);
    body[off++] = (uint8_t)(cap >> 8);
    uint16_t listen_int = g_n8.sta_cfg.sta.listen_interval ? g_n8.sta_cfg.sta.listen_interval : 3U;
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
    if (g_n8.sta_ht_active && (g_n8.proto[0] & WIFI_PROTOCOL_11N) != 0U) {
        memcpy(body + off, s_ht20_cap_ie, sizeof(s_ht20_cap_ie));
        off = (uint16_t)(off + sizeof(s_ht20_cap_ie));
    }

    /* RSN or WPA IE generated by wpa_supplicant */
    if (g_n8.sta_authmode != WIFI_AUTH_OPEN && g_n8.sta_authmode != WIFI_AUTH_WEP) {
        uint8_t ie_type = (g_n8.sta_wpa_proto == 1U) ? WIFI_APPIE_WPA : WIFI_APPIE_RSN;
        uint16_t sec_len = 0U;
        const uint8_t *sec_ie = n8_supp_get_ie_bytes(ie_type, &sec_len);
        if (sec_ie != NULL && sec_len > 0U && (uint16_t)(off + sec_len) <= sizeof(body)) {
            memcpy(body + off, sec_ie, sec_len);
            off = (uint16_t)(off + sec_len);
        }
    }

    (void)sta_tx_mgmt(IEEE80211_SUBTYPE_ASSOC_REQ, body, off, true, false);
}

/* --------------------------------------------------------------------------
 * STA Lifecycle & Connect / Disconnect
 * -------------------------------------------------------------------------- */

esp_err_t n8_sta_start(void)
{
    esp_err_t err = esp_lmac_vif_enable(ESP_LMAC_VIF_STA, g_n8.sta_mac);
    if (err != ESP_OK) {
        return err;
    }
    esp_lmac_set_protocol_mask(ESP_LMAC_VIF_STA, g_n8.proto[0]);

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

void n8_sta_stop(void)
{
    if (g_n8.scan_active) {
        n8_scan_stop_internal(false);
    }
    if (g_n8.sta_state != N8_STA_IDLE) {
        n8_sta_disconnect(WIFI_REASON_ASSOC_LEAVE, (g_n8.sta_state >= N8_STA_ASSOC), true);
    }
    if (g_n8.wpa_cb != NULL && g_n8.wpa_cb->wpa_sta_deinit != NULL) {
        (void)g_n8.wpa_cb->wpa_sta_deinit();
    }
    esp_lmac_vif_disable(ESP_LMAC_VIF_STA);

    system_event_t evt;
    memset(&evt, 0, sizeof(evt));
    evt.event_id = SYSTEM_EVENT_STA_STOP;
    n8_send_system_event(&evt);
}

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
    if (hint_ch == 0U && g_n8.rtc_cache_valid && g_n8.rtc_cached_ch >= 1U && g_n8.rtc_cached_ch <= 14U) {
        hint_ch = g_n8.rtc_cached_ch;
    }

    if (hint_ch >= 1U && hint_ch <= 14U) {
        g_n8.sta_scan_connect_pass = 0U;
        return n8_scan_start_internal(NULL, true, hint_ch);
    }

    g_n8.sta_scan_connect_pass = 1U;
    return n8_scan_start_internal(NULL, true, 0U);
}

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

    if (g_n8.sta_peer_id != ESP_LMAC_PEER_INVALID) {
        for (uint8_t tid = 0U; tid < 8U; tid++) {
            esp_lmac_del_rx_ba(g_n8.sta_peer_id, tid);
        }
        esp_lmac_peer_remove(g_n8.sta_peer_id);
        g_n8.sta_peer_id = ESP_LMAC_PEER_INVALID;
    }

    if (g_n8.wpa_cb != NULL && g_n8.wpa_cb->wpa_sta_disconnected_cb != NULL) {
        g_n8.wpa_cb->wpa_sta_disconnected_cb(reason);
    }

    uint8_t old_ssid[32];
    uint8_t old_ssid_len = g_n8.sta_ssid_len;
    uint8_t old_bssid[6];
    memcpy(old_ssid, g_n8.sta_ssid, 32U);
    memcpy(old_bssid, g_n8.sta_bssid, 6U);

    g_n8.sta_state = N8_STA_IDLE;
    g_n8.sta_connect_req = 0U;
    g_n8.sta_ptk_cipher = (uint8_t)ESP_LMAC_CIPHER_NONE;
    g_n8.sta_gtk_cipher = (uint8_t)ESP_LMAC_CIPHER_NONE;
    g_n8.sta_igtk_valid = 0U;
    g_n8.sta_pmf_active = 0U;
    g_n8.sta_aid = 0U;
    g_n8.sta_state_ticks = 0U;
    g_n8.sta_bcn_miss_ticks = 0U;
    g_n8.sta_ap_country_valid = 0U;
    memset(&g_n8.sta_ap_country, 0, sizeof(g_n8.sta_ap_country));

    if (notify_event && was_active) {
        ESP_LOGD(TAG, "STA disconnected: reason=%u", (unsigned)reason);
        system_event_t evt;
        memset(&evt, 0, sizeof(evt));
        evt.event_id = SYSTEM_EVENT_STA_DISCONNECTED;
        memcpy(evt.event_info.disconnected.ssid, old_ssid, old_ssid_len);
        evt.event_info.disconnected.ssid_len = old_ssid_len;
        memcpy(evt.event_info.disconnected.bssid, old_bssid, 6U);
        evt.event_info.disconnected.reason = reason;
        n8_send_system_event(&evt);
    }
}

/* --------------------------------------------------------------------------
 * Post-Scan Candidate Selection & Auth/Assoc Launch
 * -------------------------------------------------------------------------- */

static void sta_begin_auth(const n8_scan_entry_t *ap)
{
    memcpy(g_n8.sta_bssid, ap->rec.bssid, 6U);
    size_t slen = strnlen((const char *)ap->rec.ssid, 32U);
    memcpy(g_n8.sta_ssid, ap->rec.ssid, slen);
    g_n8.sta_ssid[slen] = '\0';
    g_n8.sta_ssid_len = (uint8_t)slen;
    g_n8.sta_channel = ap->rec.primary;
    g_n8.sta_capinfo = ap->capinfo;
    g_n8.sta_beacon_int = (ap->beacon_int >= 10U) ? ap->beacon_int : 100U;
    g_n8.sta_dtim_period = 1U;
    g_n8.sta_authmode = (uint8_t)ap->rec.authmode;
    g_n8.sta_ht_active = ap->ht_cap && ((g_n8.proto[0] & WIFI_PROTOCOL_11N) != 0U);
    g_n8.sta_qos_active = g_n8.sta_ht_active;

    /* Adopt AP Country IE if present in scan entry (for WIFI_COUNTRY_POLICY_AUTO) */
    g_n8.sta_ap_country_valid = 0U;
    memset(&g_n8.sta_ap_country, 0, sizeof(g_n8.sta_ap_country));
    if (ap->rec.country.schan >= 1U && ap->rec.country.nchan >= 1U &&
        (uint16_t)ap->rec.country.schan + (uint16_t)ap->rec.country.nchan <= 15U) {
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

    bool use_sae = false;
#ifdef CONFIG_ESP8266_WIFI_ENABLE_WPA3_SAE
    if (ap->akm_sae && (g_n8.sta_cfg.sta.pmf_cfg.capable || g_n8.sta_cfg.sta.pmf_cfg.required ||
                        ap->rec.authmode == WIFI_AUTH_WPA3_PSK)) {
        use_sae = true;
    }
#endif

    if (ap->rec.authmode == WIFI_AUTH_OPEN) {
        g_n8.sta_wpa_proto = 0U;
        g_n8.sta_supp_authmode = NONE_AUTH;
        g_n8.sta_pmf_active = 0U;
    } else if (use_sae) {
        g_n8.sta_wpa_proto = 2U;
        g_n8.sta_supp_authmode = WPA3_AUTH_PSK;
        g_n8.sta_pmf_active = 1U;
        g_n8.sta_authmode = WIFI_AUTH_WPA3_PSK;
    } else if ((ap->wpa_proto & 2U) != 0U) {
        g_n8.sta_wpa_proto = 2U;
        bool pmf_on = (ap->pmf_required != 0U) ||
                      (ap->pmf_capable != 0U && g_n8.sta_cfg.sta.pmf_cfg.capable);
        g_n8.sta_pmf_active = pmf_on ? 1U : 0U;
        g_n8.sta_supp_authmode = (pmf_on && ap->akm_psk_sha256) ? WPA2_AUTH_PSK_SHA256 : WPA2_AUTH_PSK;
    } else if ((ap->wpa_proto & 1U) != 0U) {
        g_n8.sta_wpa_proto = 1U;
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
    memcpy(pcaps.mac, g_n8.sta_bssid, 6U);
    pcaps.rate_mask_11bg = ap->rate_mask_11bg ? ap->rate_mask_11bg : 0x0FFFU;
    pcaps.ht20_mcs_mask = g_n8.sta_ht_active ? (ap->ht_mcs_mask ? ap->ht_mcs_mask : 0xFFU) : 0U;
    pcaps.short_preamble = (ap->capinfo & 0x0020U) ? 1U : 0U;
    pcaps.qos_enabled = g_n8.sta_qos_active ? 1U : 0U;
    pcaps.ht_enabled = g_n8.sta_ht_active ? 1U : 0U;
    g_n8.sta_peer_id = esp_lmac_peer_add(ESP_LMAC_VIF_STA, &pcaps);
    esp_lmac_peer_update_rssi(g_n8.sta_peer_id, ap->rec.rssi);

    /* Configure wpa_supplicant BEFORE AssocReq so RSN/WPA IE is generated */
    if (g_n8.sta_wpa_proto != 0U && g_n8.wpa_cb != NULL && g_n8.wpa_cb->wpa_sta_connect != NULL) {
        g_n8.wpa_cb->wpa_sta_connect(g_n8.sta_bssid);
    }

    g_n8.sta_state = N8_STA_AUTH;
    g_n8.sta_state_ticks = 0U;
    g_n8.sta_auth_retries = 0U;
    g_n8.sta_sae_seq = 1U;

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

void n8_sta_on_scan_done(void)
{
    if (g_n8.sta_state != N8_STA_SCANNING) {
        return;
    }

    n8_scan_entry_t *best = n8_scan_pick_best_ap();
    if (best == NULL) {
        if (g_n8.sta_scan_connect_pass == 0U) {
            /* Cached/hint channel missed -> fall back to full channel sweep */
            g_n8.sta_scan_connect_pass = 1U;
            if (n8_scan_start_internal(NULL, true, 0U) == ESP_OK) {
                return;
            }
        }
        /* Report NO_AP_FOUND */
        size_t slen = strnlen((const char *)g_n8.sta_cfg.sta.ssid, 32U);
        memcpy(g_n8.sta_ssid, g_n8.sta_cfg.sta.ssid, slen);
        g_n8.sta_ssid_len = (uint8_t)slen;
        memset(g_n8.sta_bssid, 0, 6U);
        n8_sta_disconnect(WIFI_REASON_NO_AP_FOUND, false, true);
        return;
    }

    n8_scan_entry_t chosen = *best;
    n8_scan_free_results();
    sta_begin_auth(&chosen);
}

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
    n8_pm_on_connect();

    ESP_LOGD(TAG, "STA connected: '%s' ch=%u aid=%u",
             (const char *)g_n8.sta_ssid, (unsigned)g_n8.sta_channel, (unsigned)g_n8.sta_aid);

    system_event_t evt;
    memset(&evt, 0, sizeof(evt));
    evt.event_id = SYSTEM_EVENT_STA_CONNECTED;
    memcpy(evt.event_info.connected.ssid, g_n8.sta_ssid, g_n8.sta_ssid_len);
    evt.event_info.connected.ssid_len = g_n8.sta_ssid_len;
    memcpy(evt.event_info.connected.bssid, g_n8.sta_bssid, 6U);
    evt.event_info.connected.channel = g_n8.sta_channel;
    evt.event_info.connected.authmode = (wifi_auth_mode_t)g_n8.sta_authmode;
    n8_send_system_event(&evt);
}

/* --------------------------------------------------------------------------
 * STA Management Frame RX (Beacon, Auth/SAE, AssocResp, Deauth, Action/BA)
 * -------------------------------------------------------------------------- */

static void sta_handle_action(const uint8_t *frame, uint16_t len)
{
    if (len < 26U) {
        return;
    }
    uint16_t body_off = 24U;
    bool is_prot = (frame[1] & IEEE80211_FC1_PROTECTED) != 0U;
    if (is_prot) {
        if (len < 24U + 8U + 2U + 8U) {
            return;
        }
        body_off = 32U;
        len = (uint16_t)(len - 8U);
    }

    const uint8_t *body = frame + body_off;
    uint16_t blen = (uint16_t)(len - body_off);
    uint8_t cat = body[0];
    uint8_t act = body[1];

    /* 802.11w SA-Query Request -> reply with SA-Query Response */
    if (cat == IEEE80211_CAT_SA_QUERY && act == IEEE80211_SA_QUERY_REQ && blen >= 4U) {
        uint8_t resp[4] = { IEEE80211_CAT_SA_QUERY, IEEE80211_SA_QUERY_RESP, body[2], body[3] };
        (void)sta_tx_mgmt(IEEE80211_SUBTYPE_ACTION, resp, sizeof(resp), false,
                          (g_n8.sta_pmf_active != 0U));
        return;
    }

    /* 802.11n Block Ack (Milestone 6C) */
    if (cat == IEEE80211_CAT_BA) {
        if (act == IEEE80211_BA_ACTION_ADDBA_REQ && blen >= 9U) {
            uint8_t dialog = body[2];
            uint16_t ba_param = (uint16_t)((uint16_t)body[3] | ((uint16_t)body[4] << 8));
            uint8_t tid = (uint8_t)((ba_param >> 2) & 0x0FU);
            uint8_t win = (uint8_t)((ba_param >> 6) & 0x3FU);
            uint16_t timeout = (uint16_t)((uint16_t)body[5] | ((uint16_t)body[6] << 8));
            uint16_t ssn = (uint16_t)(((uint16_t)body[7] | ((uint16_t)body[8] << 8)) >> 4);

            uint16_t status = 37U; /* Declined by default when AMPDU RX disabled */
#ifdef CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
            uint8_t max_win = (uint8_t)CONFIG_ESP8266_WIFI_RX_BA_WIN_SIZE;
            if (max_win == 0U) {
                max_win = 6U;
            }
            if (win == 0U || win > max_win) {
                win = max_win;
            }
            if (esp_lmac_add_rx_ba(g_n8.sta_peer_id, tid, ssn, win) == ESP_OK) {
                status = 0U; /* Success */
            }
#else
            (void)ssn;
            (void)win;
#endif
            uint16_t resp_param = (uint16_t)(((uint16_t)win << 6) | ((uint16_t)tid << 2) | 0x02U);
            uint8_t resp[9] = {
                IEEE80211_CAT_BA, IEEE80211_BA_ACTION_ADDBA_RESP,
                dialog,
                (uint8_t)(status & 0xFFU), (uint8_t)(status >> 8),
                (uint8_t)(resp_param & 0xFFU), (uint8_t)(resp_param >> 8),
                (uint8_t)(timeout & 0xFFU), (uint8_t)(timeout >> 8)
            };
            (void)sta_tx_mgmt(IEEE80211_SUBTYPE_ACTION, resp, sizeof(resp), false, false);
        } else if (act == IEEE80211_BA_ACTION_DELBA && blen >= 6U) {
            uint16_t del_param = (uint16_t)((uint16_t)body[2] | ((uint16_t)body[3] << 8));
            uint8_t tid = (uint8_t)((del_param >> 12) & 0x0FU);
            esp_lmac_del_rx_ba(g_n8.sta_peer_id, tid);
        }
    }
}

void n8_sta_rx_mgmt(const wifi_pkt_rx_ctrl_t *ctrl, const uint8_t *frame, uint16_t len)
{
    if (len < 24U) {
        return;
    }

    uint8_t subtype = (uint8_t)(frame[0] & IEEE80211_FC_SUBTYPE_MASK);

    if (subtype == IEEE80211_SUBTYPE_BEACON || subtype == IEEE80211_SUBTYPE_PROBE_RESP) {
        if (g_n8.scan_active) {
            n8_scan_rx_beacon_or_probe(ctrl, frame, len);
        }
        if (subtype == IEEE80211_SUBTYPE_BEACON && g_n8.sta_state >= N8_STA_ASSOC &&
            memcmp(frame + 16U, g_n8.sta_bssid, 6U) == 0) {
            g_n8.sta_bcn_miss_ticks = 0U;
            esp_lmac_peer_update_rssi(g_n8.sta_peer_id, (int8_t)ctrl->rssi);
            /* Adopt Country IE from connected AP beacon if not yet captured */
            if (!g_n8.sta_ap_country_valid && len > 36U) {
                const uint8_t *ies = frame + 36U;
                uint16_t ie_len = (uint16_t)(len - 36U);
                uint16_t pos = 0U;
                while (pos + 2U <= ie_len) {
                    uint8_t id = ies[pos];
                    uint8_t elen = ies[pos + 1U];
                    if (pos + 2U + elen > ie_len) {
                        break;
                    }
                    if (id == IEEE80211_IE_COUNTRY && elen >= 6U) {
                        uint8_t sc = ies[pos + 5U];
                        uint8_t nc = ies[pos + 6U];
                        if (sc >= 1U && nc >= 1U && (uint16_t)sc + (uint16_t)nc <= 15U) {
                            memcpy(g_n8.sta_ap_country.cc, &ies[pos + 2U], 3U);
                            g_n8.sta_ap_country.schan = sc;
                            g_n8.sta_ap_country.nchan = nc;
                            g_n8.sta_ap_country.max_tx_power = (int8_t)ies[pos + 7U];
                            g_n8.sta_ap_country.policy = WIFI_COUNTRY_POLICY_AUTO;
                            g_n8.sta_ap_country_valid = 1U;
                        }
                        break;
                    }
                    pos = (uint16_t)(pos + 2U + elen);
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
    if (memcmp(frame + 16U, g_n8.sta_bssid, 6U) != 0) {
        return;
    }

    if (subtype == IEEE80211_SUBTYPE_AUTH && g_n8.sta_state == N8_STA_AUTH && len >= 30U) {
        uint16_t alg = (uint16_t)((uint16_t)frame[24] | ((uint16_t)frame[25] << 8));
        uint16_t seq = (uint16_t)((uint16_t)frame[26] | ((uint16_t)frame[27] << 8));
        uint16_t status = (uint16_t)((uint16_t)frame[28] | ((uint16_t)frame[29] << 8));

        if (alg == IEEE80211_AUTH_ALG_OPEN && seq == 2U) {
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
        if (alg == IEEE80211_AUTH_ALG_SAE && g_n8.wpa_cb != NULL &&
            g_n8.wpa_cb->wpa3_parse_sae_msg != NULL) {
            uint8_t *sae_body = (uint8_t *)(uintptr_t)(frame + 30U);
            size_t sae_len = (size_t)(len - 30U);

            if (seq == SAE_MSG_COMMIT_TYPE && g_n8.sta_sae_seq == 1U) {
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
                g_n8.sta_sae_seq = 2U;
                g_n8.sta_state_ticks = 0U;
                if (!sta_send_auth_sae(SAE_MSG_CONFIRM_TYPE)) {
                    n8_sta_disconnect(WIFI_REASON_AUTH_FAIL, false, true);
                }
            } else if (seq == SAE_MSG_CONFIRM_TYPE && g_n8.sta_sae_seq == 2U) {
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
        g_n8.sta_state == N8_STA_ASSOC && len >= 30U) {
        uint16_t status = (uint16_t)((uint16_t)frame[26] | ((uint16_t)frame[27] << 8));
        uint16_t aid = (uint16_t)(((uint16_t)frame[28] | ((uint16_t)frame[29] << 8)) & 0x3FFFU);
        if (status != WLAN_STATUS_SUCCESS_CODE) {
            ESP_LOGW(TAG, "Assoc rejected status=%u", (unsigned)status);
            n8_sta_disconnect(WIFI_REASON_ASSOC_FAIL, false, true);
            return;
        }
        g_n8.sta_aid = aid;
        g_n8.sta_state_ticks = 0U;
        g_n8.sta_bcn_miss_ticks = 0U;

        if (g_n8.sta_authmode == WIFI_AUTH_OPEN) {
            n8_sta_on_auth_done();
        } else {
            g_n8.sta_state = N8_STA_4WAY;
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
        bool is_bcast = (frame[4] & 1U) != 0U;
        bool is_prot = (frame[1] & IEEE80211_FC1_PROTECTED) != 0U;

        /* 802.11w Protected Management Frame enforcement when PMF is active */
        if (g_n8.sta_state == N8_STA_RUN && g_n8.sta_pmf_active) {
            if (is_bcast) {
                if (!n8_verify_bip_mmie(frame, len)) {
                    return; /* Drop spoofed broadcast deauth/disassoc */
                }
            } else if (!is_prot) {
                /* Unprotected unicast deauth while PMF active: ignore (per 802.11w) */
                return;
            }
        }

        uint16_t body_off = is_prot ? 32U : 24U;
        uint8_t reason = (len >= body_off + 2U) ? frame[body_off] : WIFI_REASON_UNSPECIFIED;
        ESP_LOGW(TAG, "RX %s from AP (reason=%u)",
                 (subtype == IEEE80211_SUBTYPE_DEAUTH) ? "deauth" : "disassoc", (unsigned)reason);
        n8_sta_disconnect(reason, false, true);
        return;
    }

    if (subtype == IEEE80211_SUBTYPE_ACTION && g_n8.sta_state >= N8_STA_ASSOC) {
        sta_handle_action(frame, len);
    }
}

/* --------------------------------------------------------------------------
 * 100 ms STA Watchdog (Auth/Assoc/4-Way Timeouts + Beacon Loss)
 * -------------------------------------------------------------------------- */

void n8_sta_on_tick_100ms(void)
{
    if (g_n8.sta_state == N8_STA_IDLE || g_n8.sta_state == N8_STA_SCANNING) {
        return;
    }

    g_n8.sta_state_ticks++;

    if (g_n8.sta_state == N8_STA_AUTH && g_n8.sta_state_ticks >= N8_STA_AUTH_TIMEOUT_TICKS) {
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
    } else if (g_n8.sta_state == N8_STA_4WAY && g_n8.sta_state_ticks >= N8_STA_4WAY_TIMEOUT_TICKS) {
        n8_sta_disconnect(WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT, true, true);
    } else if (g_n8.sta_state == N8_STA_RUN) {
        if (!g_n8.scan_active) {
            g_n8.sta_bcn_miss_ticks++;
            uint16_t max_miss = (uint16_t)(g_n8.inactive_sec[0] * 10U);
            if (max_miss < 30U) {
                max_miss = 30U;
            }
            if (g_n8.sta_bcn_miss_ticks >= max_miss) {
                ESP_LOGW(TAG, "Beacon timeout (%u ms)", (unsigned)g_n8.sta_bcn_miss_ticks * 100U);
                n8_sta_disconnect(WIFI_REASON_BEACON_TIMEOUT, false, true);
            }
        }
    }
}
