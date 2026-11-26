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
// Complete wpa_supplicant driver glue implementing every function in
// components/wpa_supplicant/src/esp_supplicant/esp_wifi_driver.h, including
// STA/AP key installation, SoftAP TKIP MIC key handling, 802.11w BIP
// AES-128-CMAC verification, and App-IE management.

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "net80211_internal.h"

#define TAG "wifi_supp"

/* From wpa_supplicant/src/crypto/aes-omac1.c */
extern int omac1_aes_128(const u8 *key, const u8 *data, size_t data_len, u8 *mac);

/* Matching enum wpa_alg from wpa_supplicant/src/common/defs.h */
#define SUPP_WPA_ALG_NONE   0
#define SUPP_WPA_ALG_WEP    1
#define SUPP_WPA_ALG_TKIP   2
#define SUPP_WPA_ALG_CCMP   3
#define SUPP_WPA_ALG_IGTK   4

static esp_lmac_cipher_t supp_alg_to_lmac(int alg, size_t key_len)
{
    switch (alg) {
    case SUPP_WPA_ALG_CCMP: return ESP_LMAC_CIPHER_CCMP;
    case SUPP_WPA_ALG_TKIP: return ESP_LMAC_CIPHER_TKIP;
    case SUPP_WPA_ALG_WEP:  return (key_len <= 5U) ? ESP_LMAC_CIPHER_WEP40 : ESP_LMAC_CIPHER_WEP104;
    default:                return ESP_LMAC_CIPHER_NONE;
    }
}

static int lmac_to_supp_alg(esp_lmac_cipher_t c)
{
    switch (c) {
    case ESP_LMAC_CIPHER_CCMP:   return SUPP_WPA_ALG_CCMP;
    case ESP_LMAC_CIPHER_TKIP:   return SUPP_WPA_ALG_TKIP;
    case ESP_LMAC_CIPHER_WEP40:
    case ESP_LMAC_CIPHER_WEP104: return SUPP_WPA_ALG_WEP;
    default:                     return SUPP_WPA_ALG_NONE;
    }
}

esp_lmac_cipher_t n8_wifi_cipher_to_lmac(wifi_cipher_type_t c)
{
    switch (c) {
    case WIFI_CIPHER_TYPE_WEP40:  return ESP_LMAC_CIPHER_WEP40;
    case WIFI_CIPHER_TYPE_WEP104: return ESP_LMAC_CIPHER_WEP104;
    case WIFI_CIPHER_TYPE_TKIP:   return ESP_LMAC_CIPHER_TKIP;
    case WIFI_CIPHER_TYPE_CCMP:
    case WIFI_CIPHER_TYPE_TKIP_CCMP: return ESP_LMAC_CIPHER_CCMP;
    default:                      return ESP_LMAC_CIPHER_NONE;
    }
}

/* --------------------------------------------------------------------------
 * Supplicant Callback Registration
 * -------------------------------------------------------------------------- */

int esp_wifi_register_wpa_cb_internal(struct wpa_funcs *cb)
{
    g_n8.wpa_cb = cb;
    return ESP_OK;
}

int esp_wifi_unregister_wpa_cb_internal(void)
{
    if (g_n8.wpa_cb != NULL) {
        heap_caps_free(g_n8.wpa_cb);
        g_n8.wpa_cb = NULL;
    }
    return ESP_OK;
}

static esp_err_t api_register_wpa2_cb(void *arg)
{
    struct wpa2_funcs *cb = (struct wpa2_funcs *)arg;
    if (g_n8.wpa2_cb != NULL && g_n8.wpa2_cb != cb) {
        heap_caps_free(g_n8.wpa2_cb);
    }
    g_n8.wpa2_cb = cb;
    return ESP_OK;
}

/**
 * @brief Register the WPA2-Enterprise supplicant callback table on the worker task.
 *
 * @param cb Heap-allocated wpa2_funcs callback table (ownership transferred).
 * @return ESP_OK on success.
 */
int esp_wifi_register_wpa2_cb_internal(struct wpa2_funcs *cb)
{
    return (int)n8_api_call(api_register_wpa2_cb, cb);
}

static esp_err_t api_unregister_wpa2_cb(void *arg)
{
    (void)arg;
    if (g_n8.wpa2_cb != NULL) {
        heap_caps_free(g_n8.wpa2_cb);
        g_n8.wpa2_cb = NULL;
    }
    return ESP_OK;
}

/**
 * @brief Unregister and free the WPA2-Enterprise supplicant callback table on the worker task.
 *
 * @return ESP_OK on success.
 */
int esp_wifi_unregister_wpa2_cb_internal(void)
{
    return (int)n8_api_call(api_unregister_wpa2_cb, NULL);
}

static esp_err_t api_set_wps_cb(void *arg)
{
    struct wps_funcs *wps_cb = (struct wps_funcs *)arg;
    if (g_n8.wps_cb != NULL && g_n8.wps_cb != wps_cb) {
        heap_caps_free(g_n8.wps_cb);
    }
    g_n8.wps_cb = wps_cb;
    return ESP_OK;
}

/**
 * @brief Register or clear the WPS supplicant callback table on the worker task.
 *
 * @param wps_cb Heap-allocated wps_funcs callback table (or NULL to clear).
 * @return ESP_OK on success.
 */
int esp_wifi_set_wps_cb_internal(struct wps_funcs *wps_cb)
{
    return (int)n8_api_call(api_set_wps_cb, wps_cb);
}

int esp_wifi_register_tx_cb_internal(wifi_tx_cb_t fn, u8 id)
{
    if (id >= 8U) {
        return ESP_ERR_INVALID_ARG;
    }
    g_n8.tx_cbs[id] = fn;
    return ESP_OK;
}

/* --------------------------------------------------------------------------
 * App-IE Management (Handles Both Copied IEs [flag=0] & Live assoc_ie_buf [flag=1])
 * -------------------------------------------------------------------------- */

void n8_supp_clear_appies(void)
{
    for (uint8_t i = 0U; i < WIFI_APPIE_MAX; i++) {
        if (g_n8.appies[i].in_use && !g_n8.appies[i].live_ptr && g_n8.appies[i].buf != NULL) {
            heap_caps_free(g_n8.appies[i].buf);
        }
        memset(&g_n8.appies[i], 0, sizeof(g_n8.appies[i]));
    }
}

/**
 * @brief Free all dynamically allocated vendor IE slots and the lazy table.
 */
void n8_vendor_ie_free_all(void)
{
    if (g_n8.vendor_ies == NULL) {
        return;
    }
    for (uint8_t t = 0U; t < N8_VND_IE_TYPE_COUNT; t++) {
        for (uint8_t idx = 0U; idx < N8_VND_IE_ID_COUNT; idx++) {
            if (g_n8.vendor_ies->slots[t][idx] != NULL) {
                heap_caps_free(g_n8.vendor_ies->slots[t][idx]);
                g_n8.vendor_ies->slots[t][idx] = NULL;
            }
        }
    }
    heap_caps_free(g_n8.vendor_ies);
    g_n8.vendor_ies = NULL;
}

/**
 * @brief Append any enabled user vendor IEs for @p type to a management frame buffer.
 *
 * @param type    Vendor IE frame slot type (Beacon, ProbeReq, ProbeResp, AssocReq, AssocResp).
 * @param out     Destination frame buffer.
 * @param off     Current write offset inside @p out.
 * @param max_len Total capacity of @p out in bytes.
 * @return Updated write offset after appending enabled vendor IEs.
 */
uint16_t n8_append_vendor_ies(wifi_vendor_ie_type_t type, uint8_t *out, uint16_t off, uint16_t max_len)
{
    if (g_n8.vendor_ies == NULL || out == NULL || (uint32_t)type >= N8_VND_IE_TYPE_COUNT) {
        return off;
    }
    for (uint8_t idx = 0U; idx < N8_VND_IE_ID_COUNT; idx++) {
        const uint8_t *ie = g_n8.vendor_ies->slots[type][idx];
        if (ie != NULL) {
            uint16_t full_len = (uint16_t)ie[1] + IEEE80211_IE_HDR_LEN;
            if ((uint32_t)off + full_len <= max_len) {
                memcpy(out + off, ie, full_len);
                off = (uint16_t)(off + full_len);
            }
        }
    }
    return off;
}

int esp_wifi_set_appie_internal(uint8_t type, uint8_t *ie, uint16_t len, uint8_t flag)
{
    if (type >= WIFI_APPIE_MAX || ie == NULL || len == 0U) {
        return ESP_ERR_INVALID_ARG;
    }

    n8_appie_slot_t *s = &g_n8.appies[type];
    if (s->in_use && !s->live_ptr && s->buf != NULL) {
        heap_caps_free(s->buf);
    }
    memset(s, 0, sizeof(*s));

    if (flag != 0U) {
        /*
         * wpa_supplicant set_assoc_ie() passes assoc_ie_buf BEFORE wpa_gen_wpa_ie()
         * populates assoc_ie_buf + 2. Keep the live pointer and read exact IE length
         * dynamically when building AssocReq.
         */
        s->buf = ie;
        s->len = len;
        s->live_ptr = 1U;
        s->in_use = 1U;
    } else {
        uint8_t *copy = (uint8_t *)heap_caps_malloc(len + sizeof(uint16_t), MALLOC_CAP_8BIT);
        if (copy == NULL) {
            return ESP_ERR_NO_MEM;
        }
        struct wifi_appie *hdr = (struct wifi_appie *)(void *)copy;
        hdr->ie_len = len;
        memcpy(hdr->ie_data, ie, len);
        s->buf = copy;
        s->len = len;
        s->live_ptr = 0U;
        s->in_use = 1U;
    }

    return ESP_OK;
}

int esp_wifi_unset_appie_internal(uint8_t type)
{
    if (type >= WIFI_APPIE_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    n8_appie_slot_t *s = &g_n8.appies[type];
    if (s->in_use && !s->live_ptr && s->buf != NULL) {
        heap_caps_free(s->buf);
    }
    memset(s, 0, sizeof(*s));
    return ESP_OK;
}

struct wifi_appie *esp_wifi_get_appie_internal(uint8_t type)
{
    if (type >= WIFI_APPIE_MAX || !g_n8.appies[type].in_use) {
        return NULL;
    }
    return (struct wifi_appie *)(void *)g_n8.appies[type].buf;
}

const uint8_t *n8_supp_get_ie_bytes(uint8_t type, uint16_t *out_len)
{
    if (out_len != NULL) {
        *out_len = 0U;
    }
    if (type >= WIFI_APPIE_MAX || !g_n8.appies[type].in_use || g_n8.appies[type].buf == NULL) {
        return NULL;
    }

    n8_appie_slot_t *s = &g_n8.appies[type];
    if (s->live_ptr) {
        /* assoc_ie_buf + 2 holds [elem_id, elem_len, body...] */
        const uint8_t *ie = s->buf + 2U;
        uint16_t full_len = (uint16_t)(ie[1] + 2U);
        if (full_len < 2U || full_len > 257U) {
            return NULL;
        }
        if (out_len != NULL) {
            *out_len = full_len;
        }
        return ie;
    } else {
        const struct wifi_appie *hdr = (const struct wifi_appie *)(const void *)s->buf;
        if (out_len != NULL) {
            *out_len = hdr->ie_len;
        }
        return hdr->ie_data;
    }
}

/* --------------------------------------------------------------------------
 * STA & SoftAP Profile Getters Consumed by wpa_supplicant
 * -------------------------------------------------------------------------- */

struct wifi_ssid *esp_wifi_sta_get_prof_ssid_internal(void)
{
    size_t n = strnlen((const char *)g_n8.sta_cfg.sta.ssid, 32U);
    g_n8.sta_ssid_box.len = (int)n;
    memcpy(g_n8.sta_ssid_box.ssid, g_n8.sta_cfg.sta.ssid, n);
    return &g_n8.sta_ssid_box;
}

uint8_t *esp_wifi_sta_get_prof_password_internal(void)
{
    return g_n8.sta_cfg.sta.password;
}

uint8_t *esp_wifi_sta_get_prof_pmk_internal(void)
{
    return g_n8.sta_pmk;
}

uint8_t *esp_wifi_sta_get_ap_info_prof_pmk_internal(void)
{
    return g_n8.sta_pmk;
}

uint8_t esp_wifi_sta_get_reset_param_internal(void)
{
    return g_n8.sta_reset_param;
}

uint8_t esp_wifi_sta_set_reset_param_internal(uint8_t reset_flag)
{
    g_n8.sta_reset_param = reset_flag;
    return 0U;
}

int esp_wifi_sta_update_ap_info_internal(void)
{
    return ESP_OK;
}

bool esp_wifi_sta_is_running_internal(void)
{
    return g_n8.started && (g_n8.sta_state >= N8_STA_AUTH);
}

bool esp_wifi_sta_is_ap_notify_completed_rsne_internal(void)
{
    return true;
}

int esp_wifi_get_macaddr_internal(uint8_t if_index, uint8_t *macaddr)
{
    if (macaddr == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (if_index == WIFI_IF_AP) {
        memcpy(macaddr, g_n8.ap_mac, 6U);
    } else {
        memcpy(macaddr, g_n8.sta_mac, 6U);
    }
    return ESP_OK;
}

uint8_t esp_wifi_sta_get_prof_authmode_internal(void)
{
    return g_n8.sta_supp_authmode;
}

bool esp_wifi_sta_prof_is_wpa_internal(void)
{
    return (g_n8.sta_wpa_proto == 1U);
}

bool esp_wifi_sta_prof_is_wpa2_internal(void)
{
    return (g_n8.sta_wpa_proto == 2U) && (g_n8.sta_supp_authmode != WPA3_AUTH_PSK);
}

bool esp_wifi_sta_prof_is_wpa3_internal(void)
{
    return (g_n8.sta_supp_authmode == WPA3_AUTH_PSK);
}

static uint8_t wifi_cipher_to_supp_bit(uint8_t wifi_cipher)
{
    /* Maps wifi_cipher_type_t to bit index expected by wpa_set_bss: BIT(ret) == WPA_CIPHER_* */
    switch ((wifi_cipher_type_t)wifi_cipher) {
    case WIFI_CIPHER_TYPE_TKIP:       return 1U; /* WPA_CIPHER_TKIP = BIT(1) */
    case WIFI_CIPHER_TYPE_CCMP:
    case WIFI_CIPHER_TYPE_TKIP_CCMP:  return 3U; /* WPA_CIPHER_CCMP = BIT(3) */
    case WIFI_CIPHER_TYPE_AES_CMAC128:return 5U; /* WPA_CIPHER_AES_128_CMAC = BIT(5) */
    case WIFI_CIPHER_TYPE_WEP40:      return 7U; /* WPA_CIPHER_WEP40 = BIT(7) */
    case WIFI_CIPHER_TYPE_WEP104:     return 8U; /* WPA_CIPHER_WEP104 = BIT(8) */
    default:                          return 0U; /* WPA_CIPHER_NONE = BIT(0) */
    }
}

uint8_t esp_wifi_sta_get_pairwise_cipher_internal(void)
{
    return wifi_cipher_to_supp_bit(g_n8.sta_pairwise_cipher);
}

uint8_t esp_wifi_sta_get_group_cipher_internal(void)
{
    return wifi_cipher_to_supp_bit(g_n8.sta_group_cipher);
}

uint16_t esp_wifi_sta_pmf_enabled(void)
{
    return g_n8.sta_pmf_active ? 1U : 0U;
}

wifi_cipher_type_t esp_wifi_sta_get_mgmt_group_cipher(void)
{
    return (wifi_cipher_type_t)g_n8.sta_mgmt_cipher;
}

int esp_wifi_get_assoc_bssid_internal(uint8_t *bssid)
{
    if (bssid == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (g_n8.sta_state < N8_STA_AUTH) {
        return ESP_FAIL;
    }
    memcpy(bssid, g_n8.sta_bssid, 6U);
    return ESP_OK;
}

/* SoftAP getters */
struct wifi_ssid *esp_wifi_ap_get_prof_ap_ssid_internal(void)
{
    size_t n = g_n8.ap_cfg.ap.ssid_len;
    if (n == 0U) {
        n = strnlen((const char *)g_n8.ap_cfg.ap.ssid, 32U);
    }
    if (n > 32U) {
        n = 32U;
    }
    g_n8.ap_ssid_box.len = (int)n;
    memcpy(g_n8.ap_ssid_box.ssid, g_n8.ap_cfg.ap.ssid, n);
    return &g_n8.ap_ssid_box;
}

uint8_t esp_wifi_ap_get_prof_authmode_internal(void)
{
    return (uint8_t)g_n8.ap_cfg.ap.authmode;
}

uint8_t *esp_wifi_ap_get_prof_password_internal(void)
{
    return g_n8.ap_cfg.ap.password;
}

uint8_t *esp_wifi_ap_get_prof_pmk_internal(void)
{
    return g_n8.ap_pmk;
}

void *esp_wifi_get_hostap_private_internal(void)
{
    return g_n8.ap_hapd;
}

/* --------------------------------------------------------------------------
 * STA & SoftAP Hardware Key Installation + 802.11w BIP IGTK
 * -------------------------------------------------------------------------- */

int esp_wifi_set_sta_key_internal(int alg, u8 *addr, int key_idx, int set_tx,
                                  u8 *seq, size_t seq_len, u8 *key, size_t key_len,
                                  int key_entry_valid)
{
    (void)seq;
    (void)seq_len;
    (void)key_entry_valid;

    bool is_ptk = (set_tx != 0) && (addr != NULL) && ((addr[0] & N8_MAC_MCAST_BIT) == 0U);
    uint8_t kidx = (uint8_t)(key_idx & 3);
    if (alg == SUPP_WPA_ALG_NONE || key == NULL || key_len == 0U) {
        esp_lmac_key_clear(ESP_LMAC_VIF_STA,
                           is_ptk ? g_n8.sta_peer_id : ESP_LMAC_PEER_INVALID,
                           is_ptk ? ESP_LMAC_KEY_TYPE_PTK : ESP_LMAC_KEY_TYPE_GTK,
                           kidx);
        n8_defrag_purge_vif(ESP_LMAC_VIF_STA);
        if (is_ptk) {
            g_n8.sta_ptk_cipher = (uint8_t)ESP_LMAC_CIPHER_NONE;
            memset(g_n8.sta_ptk_key, 0, sizeof(g_n8.sta_ptk_key));
            g_n8.sta_ptk_key_valid = 0U;
            g_n8.sta_tx_mgmt_pn = 0ULL;
            g_n8.sta_rx_mgmt_pn = 0ULL;
            g_n8.sta_rx_mgmt_pn_valid = 0U;
            memset(g_n8.sta_rx_ptk_pn, 0, sizeof(g_n8.sta_rx_ptk_pn));
        } else {
            g_n8.sta_gtk_cipher = (uint8_t)ESP_LMAC_CIPHER_NONE;
            memset(&g_n8.sta_rx_gtk_pn[kidx & 1U], 0, sizeof(g_n8.sta_rx_gtk_pn[0]));
        }
        return 0;
    }

    esp_lmac_cipher_t cipher = supp_alg_to_lmac(alg, key_len);
    if (cipher == ESP_LMAC_CIPHER_NONE) {
        return -1;
    }

    esp_lmac_key_type_t ktype = is_ptk ? ESP_LMAC_KEY_TYPE_PTK : ESP_LMAC_KEY_TYPE_GTK;
    esp_lmac_peer_id_t pid = is_ptk ? g_n8.sta_peer_id : ESP_LMAC_PEER_INVALID;

    esp_err_t err = esp_lmac_key_set(ESP_LMAC_VIF_STA, pid, ktype,
                                     kidx, cipher, key, (uint8_t)key_len);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "STA key_set failed: err=0x%x alg=%d idx=%d", (unsigned)err, alg, key_idx);
        return -1;
    }

    if (is_ptk) {
        g_n8.sta_ptk_cipher = (uint8_t)cipher;
        g_n8.sta_tx_pn = 1ULL;
        if (cipher == ESP_LMAC_CIPHER_CCMP && key_len >= IEEE80211_CCMP_KEY_LEN) {
            memcpy(g_n8.sta_ptk_key, key, IEEE80211_CCMP_KEY_LEN);
            g_n8.sta_ptk_key_valid = 1U;
        } else {
            memset(g_n8.sta_ptk_key, 0, sizeof(g_n8.sta_ptk_key));
            g_n8.sta_ptk_key_valid = 0U;
        }
        g_n8.sta_tx_mgmt_pn = 1ULL;
        g_n8.sta_rx_mgmt_pn = 0ULL;
        g_n8.sta_rx_mgmt_pn_valid = 0U;
        memset(g_n8.sta_rx_ptk_pn, 0, sizeof(g_n8.sta_rx_ptk_pn));
    } else {
        g_n8.sta_gtk_cipher = (uint8_t)cipher;
        g_n8.sta_gtk_key_idx = kidx;
        memset(&g_n8.sta_rx_gtk_pn[kidx & 1U], 0, sizeof(g_n8.sta_rx_gtk_pn[0]));
    }
    n8_defrag_purge_vif(ESP_LMAC_VIF_STA);
    return 0;
}

int esp_wifi_get_sta_key_internal(uint8_t *ifx, int *alg, u8 *addr, int *key_idx,
                                  u8 *key, size_t key_len, int key_entry_valid)
{
    uint8_t slot = (uint8_t)key_entry_valid;
    if (slot >= 25U) {
        return -1;
    }
    uint8_t rd_vif = 0U;
    uint8_t rd_idx = 0U;
    esp_lmac_cipher_t rd_c = ESP_LMAC_CIPHER_NONE;

    if (esp_lmac_key_read_slot(slot, &rd_vif, &rd_c, &rd_idx, addr, key, (uint8_t)key_len) != ESP_OK) {
        return -1;
    }
    if (ifx != NULL) {
        *ifx = rd_vif;
    }
    if (alg != NULL) {
        *alg = lmac_to_supp_alg(rd_c);
    }
    if (key_idx != NULL) {
        *key_idx = (int)rd_idx;
    }
    return 0;
}

int esp_wifi_set_ap_key_internal(int alg, const u8 *addr, int idx, u8 *key, size_t key_len)
{
    bool is_bcast = (addr == NULL) || ((addr[0] & 1U) != 0U);

    if (alg == SUPP_WPA_ALG_NONE || key == NULL || key_len == 0U) {
        if (is_bcast) {
            esp_lmac_key_clear(ESP_LMAC_VIF_AP, ESP_LMAC_PEER_INVALID,
                               ESP_LMAC_KEY_TYPE_GTK, (uint8_t)(idx & 3));
            g_n8.ap_gtk_cipher = (uint8_t)ESP_LMAC_CIPHER_NONE;
            n8_defrag_purge_vif(ESP_LMAC_VIF_AP);
        } else {
            n8_ap_sta_t *sta = n8_ap_find_sta(addr);
            if (sta != NULL) {
                esp_lmac_key_clear(ESP_LMAC_VIF_AP, sta->peer_id, ESP_LMAC_KEY_TYPE_PTK, 0U);
                sta->ptk_cipher = (uint8_t)ESP_LMAC_CIPHER_NONE;
                if (g_n8.ap_cfg.ap.authmode != WIFI_AUTH_OPEN) {
                    sta->authorized = 0U;
                }
                memset(sta->ptk_pn, 0, sizeof(sta->ptk_pn));
                n8_defrag_purge_peer(ESP_LMAC_VIF_AP, sta->mac);
            }
        }
        return 0;
    }

    esp_lmac_cipher_t cipher = supp_alg_to_lmac(alg, key_len);
    if (cipher == ESP_LMAC_CIPHER_NONE) {
        return -1;
    }

    /*
     * AP TKIP key layout (IEEE 802.11 / hostapd):
     * wpa_supplicant passes [16B TK | 8B Authenticator->Supplicant TX MIC | 8B Supplicant->Authenticator RX MIC].
     * Hardware expects [16B TK | 8B RX MIC | 8B TX MIC] for AP role, so swap halves when passing to HW.
     */
    uint8_t hw_key[32];
    size_t copy_len = (key_len > sizeof(hw_key)) ? sizeof(hw_key) : key_len;
    memcpy(hw_key, key, copy_len);
    if (cipher == ESP_LMAC_CIPHER_TKIP && copy_len == 32U) {
        memcpy(hw_key + 16U, key + 24U, 8U);
        memcpy(hw_key + 24U, key + 16U, 8U);
    }

    if (is_bcast) {
        esp_err_t err = esp_lmac_key_set(ESP_LMAC_VIF_AP, ESP_LMAC_PEER_INVALID,
                                         ESP_LMAC_KEY_TYPE_GTK, (uint8_t)(idx & 3),
                                         cipher, hw_key, (uint8_t)copy_len);
        if (err != ESP_OK) {
            return -1;
        }
        g_n8.ap_gtk_cipher = (uint8_t)cipher;
        g_n8.ap_gtk_key_idx = (uint8_t)(idx & 3);
        g_n8.ap_gtk_pn = 1ULL;
        n8_defrag_purge_vif(ESP_LMAC_VIF_AP);
        return 0;
    }

    n8_ap_sta_t *sta = n8_ap_find_sta(addr);
    if (sta == NULL) {
        return -1;
    }
    esp_err_t err = esp_lmac_key_set(ESP_LMAC_VIF_AP, sta->peer_id,
                                     ESP_LMAC_KEY_TYPE_PTK, 0U,
                                     cipher, hw_key, (uint8_t)copy_len);
    if (err != ESP_OK) {
        return -1;
    }
    sta->ptk_cipher = (uint8_t)cipher;
    sta->ptk_key_idx = (uint8_t)(idx & 3);
    sta->tx_pn = 1ULL;
    memset(sta->ptk_pn, 0, sizeof(sta->ptk_pn));
    n8_defrag_purge_peer(ESP_LMAC_VIF_AP, sta->mac);
    return 0;
}

int esp_wifi_set_igtk_internal(uint8_t if_index, const wifi_wpa_igtk_t *igtk)
{
    if (if_index != WIFI_IF_STA || igtk == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    g_n8.sta_igtk = *igtk;
    g_n8.sta_igtk_valid = 1U;
    g_n8.sta_rx_bip_ipn = 0ULL;
    g_n8.sta_rx_bip_ipn_valid = 0U;
    return ESP_OK;
}

bool n8_verify_bip_mmie(const uint8_t *frame, uint16_t len)
{
    /* IEEE 802.11w BIP-CMAC-128 MMIE is 18 bytes at end of broadcast mgmt frame:
     * [ID=76 (1B) | Len=16 (1B) | KeyID (2B) | IPN (6B) | MIC (8B)] */
    if (!g_n8.sta_igtk_valid || len < IEEE80211_HDR_LEN + IEEE80211_MMIE_LEN) {
        return false;
    }

    const uint8_t *mmie = frame + len - IEEE80211_MMIE_LEN;
    if (mmie[0] != IEEE80211_IE_MMIE || mmie[1] != 16U) {
        return false;
    }
    if (mmie[2] != g_n8.sta_igtk.keyid[0] || mmie[3] != g_n8.sta_igtk.keyid[1]) {
        return false;
    }

    /* Extract LE48 IPN and enforce strict monotonicity against replay */
    const uint8_t *ipn_bytes = mmie + IEEE80211_MMIE_IPN_OFF;
    uint64_t ipn = (uint64_t)ipn_bytes[0] |
                   ((uint64_t)ipn_bytes[1] << 8) |
                   ((uint64_t)ipn_bytes[2] << 16) |
                   ((uint64_t)ipn_bytes[3] << 24) |
                   ((uint64_t)ipn_bytes[4] << 32) |
                   ((uint64_t)ipn_bytes[5] << 40);
    if (g_n8.sta_rx_bip_ipn_valid != 0U && ipn <= g_n8.sta_rx_bip_ipn) {
        return false;
    }

    /* AAD (20 bytes): masked FC (2B) + A1 (6B) + A2 (6B) + A3 (6B) */
    uint16_t body_len = (uint16_t)(len - IEEE80211_HDR_LEN);
    if (body_len > 256U) {
        return false;
    }

    uint8_t bip_buf[20U + 256U];
    bip_buf[0] = (uint8_t)(frame[0] & 0xFFU);
    bip_buf[1] = (uint8_t)(frame[1] & ~(IEEE80211_FC1_RETRY | IEEE80211_FC1_PM | IEEE80211_FC1_MOREDATA));
    memcpy(bip_buf + 2U, frame + IEEE80211_HDR_ADDR1_OFF, 18U);
    memcpy(bip_buf + 20U, frame + IEEE80211_HDR_LEN, body_len);
    /* Zero the 8-byte MIC field inside MMIE before computing AES-128-CMAC */
    memset(bip_buf + 20U + body_len - 8U, 0, 8U);

    uint8_t mac[16];
    if (omac1_aes_128(g_n8.sta_igtk.igtk, bip_buf, (size_t)(20U + body_len), mac) != 0) {
        return false;
    }

    if (memcmp(mac, mmie + IEEE80211_MMIE_MIC_OFF, 8U) != 0) {
        return false;
    }

    g_n8.sta_rx_bip_ipn = ipn;
    g_n8.sta_rx_bip_ipn_valid = 1U;
    return true;
}

/* --------------------------------------------------------------------------
 * Handshake Completion, Deauth, IPC & Management Frame Injection
 * -------------------------------------------------------------------------- */

bool esp_wifi_auth_done_internal(void)
{
    n8_sta_on_auth_done();
    return true;
}

void esp_wifi_deauthenticate_internal(u8 reason_code)
{
    n8_sta_disconnect(reason_code, true, true);
}

esp_err_t esp_wifi_internal_issue_disconnect(uint8_t reason_code)
{
    n8_sta_disconnect(reason_code, true, true);
    return ESP_OK;
}

bool esp_wifi_wpa_ptk_init_done_internal(uint8_t *mac)
{
    if (mac != NULL) {
        n8_ap_on_ptk_done(mac);
    }
    return true;
}

int esp_wifi_ap_deauth_internal(uint8_t *mac, uint32_t reason)
{
    if (mac == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    n8_ap_sta_t *sta = n8_ap_find_sta(mac);
    if (sta != NULL) {
        n8_ap_remove_sta(sta, (uint8_t)reason, true);
    }
    return ESP_OK;
}

static esp_err_t ipc_trampoline(void *arg)
{
    wifi_ipc_config_t *cfg = (wifi_ipc_config_t *)arg;
    return (esp_err_t)cfg->fn(cfg->arg);
}

int esp_wifi_ipc_internal(wifi_ipc_config_t *cfg, bool sync)
{
    if (cfg == NULL || cfg->fn == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    (void)sync;
    return (int)n8_api_call(ipc_trampoline, cfg);
}

/**
 * @brief Transmit a management frame on the net80211 worker task.
 *
 * Routes STA Action frames through n8_sta_tx_action() when CONFIG_WPA_11KV_SUPPORT
 * is enabled so 802.11w PMF CCMP encryption is applied when active.
 *
 * @param arg Pointer to const mgmt_frm_req_t.
 * @return ESP_OK on submission, or error code.
 */
static esp_err_t api_send_mgmt_frm(void *arg)
{
    const mgmt_frm_req_t *req = (const mgmt_frm_req_t *)arg;
#ifdef CONFIG_WPA_11KV_SUPPORT
    if (req->ifx == WIFI_IF_STA && req->subtype == IEEE80211_STYPE_IDX_ACTION) {
        return n8_sta_tx_action((const uint8_t *)req->data, (uint16_t)req->data_len);
    }
#endif

    uint8_t hdr[24];
    memset(hdr, 0, sizeof(hdr));
    hdr[0] = (uint8_t)(IEEE80211_FC_TYPE_MGMT | ((req->subtype & 0x0FU) << 4));
    if (req->ifx == WIFI_IF_STA) {
        memcpy(hdr + 4U, g_n8.sta_bssid, 6U);
        memcpy(hdr + 10U, g_n8.sta_mac, 6U);
        memcpy(hdr + 16U, g_n8.sta_bssid, 6U);
        uint16_t seq = n8_sta_next_seq();
        hdr[22] = (uint8_t)(seq & 0xFFU);
        hdr[23] = (uint8_t)(seq >> 8);
    } else {
        memset(hdr + 4U, 0xFF, 6U);
        memcpy(hdr + 10U, g_n8.ap_mac, 6U);
        memcpy(hdr + 16U, g_n8.ap_mac, 6U);
        uint16_t seq = n8_ap_next_seq();
        hdr[22] = (uint8_t)(seq & 0xFFU);
        hdr[23] = (uint8_t)(seq >> 8);
    }

    uint8_t *body = (uint8_t *)heap_caps_malloc(req->data_len, MALLOC_CAP_8BIT);
    if (body == NULL) {
        return ESP_ERR_NO_MEM;
    }
    memcpy(body, req->data, req->data_len);

    esp_lmac_sg_seg_t seg = { .ptr = body, .len = (uint16_t)req->data_len };
    esp_lmac_tx_req_t tx = {0};
    tx.vif = (req->ifx == WIFI_IF_AP) ? ESP_LMAC_VIF_AP : ESP_LMAC_VIF_STA;
    tx.peer_id = ESP_LMAC_PEER_INVALID;
    tx.ac = ESP_LMAC_AC_MGMT;
    tx.flags = ESP_LMAC_TX_FLAG_FORCE_LOWEST_RATE;
    tx.hdr = hdr;
    tx.hdr_len = sizeof(hdr);
    tx.segs = &seg;
    tx.seg_cnt = 1U;
    /* Note: synchronous-free helper via simple callback */
    extern void n8_mgmt_free_tx_cb(void *ctx, const esp_lmac_tx_status_t *st);
    tx.done_cb = n8_mgmt_free_tx_cb;
    tx.done_ctx = body;

    esp_err_t err = esp_lmac_tx_submit(&tx);
    if (err != ESP_OK) {
        heap_caps_free(body);
    }
    return err;
}

/**
 * @brief Send a management frame on behalf of wpa_supplicant (thread-safe).
 *
 * @param req Management frame request descriptor.
 * @return ESP_OK on success, or error code.
 */
esp_err_t esp_wifi_send_mgmt_frm_internal(const mgmt_frm_req_t *req)
{
    if (req == NULL || req->data_len == 0U || req->data_len > 512U) {
        return ESP_ERR_INVALID_ARG;
    }
    return n8_api_call(api_send_mgmt_frm, (void *)(uintptr_t)req);
}

/* --------------------------------------------------------------------------
 * WPS / WPA2-Enterprise / 11k/11v Hooks (Required by esp_wifi_driver.h)
 * -------------------------------------------------------------------------- */

static esp_err_t api_wpa2_ent_param(void *arg)
{
    wifi_wpa2_param_t *param = (wifi_wpa2_param_t *)arg;
    return param->fn(param->param);
}

/**
 * @brief Marshal WPA2-Enterprise enable callback onto the net80211 worker task.
 *
 * @param param Callback descriptor containing fn and opaque arg from esp_wpa2.c.
 * @return Return value of param->fn, or ESP_ERR_INVALID_ARG if NULL.
 */
esp_err_t esp_wifi_sta_wpa2_ent_enable_internal(wifi_wpa2_param_t *param)
{
    if (param == NULL || param->fn == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    return n8_api_call(api_wpa2_ent_param, param);
}

/**
 * @brief Marshal WPA2-Enterprise disable callback onto the net80211 worker task.
 *
 * @param param Callback descriptor containing fn and opaque arg from esp_wpa2.c.
 * @return Return value of param->fn, or ESP_ERR_INVALID_ARG if NULL.
 */
esp_err_t esp_wifi_sta_wpa2_ent_disable_internal(wifi_wpa2_param_t *param)
{
    if (param == NULL || param->fn == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    return n8_api_call(api_wpa2_ent_param, param);
}

esp_err_t esp_wifi_set_wpa2_ent_state_internal(wpa2_ent_eap_state_t state)
{
    g_n8.wpa2_ent_state = state;
    return ESP_OK;
}

int esp_wifi_get_wps_type_internal(void)           { return g_n8.wps_type; }
int esp_wifi_set_wps_type_internal(uint32_t type)  { g_n8.wps_type = (int)type; return ESP_OK; }
int esp_wifi_get_wps_status_internal(void)         { return g_n8.wps_status; }
int esp_wifi_set_wps_status_internal(uint32_t st)  { g_n8.wps_status = (int)st; return ESP_OK; }
bool esp_wifi_enable_sta_privacy_internal(void)    { return true; }
int esp_wifi_disarm_sta_connection_timer_internal(void) { g_n8.sta_conn_timer_disarmed = 1U; return ESP_OK; }
esp_err_t esp_wifi_set_wps_start_flag_internal(bool start) { g_n8.wps_start_flag = start ? 1U : 0U; return ESP_OK; }
uint8_t esp_wifi_get_user_init_flag_internal(void) { return g_n8.user_init_flag; }
/**
 * @brief Return whether 802.11k Radio Measurement is enabled on an interface.
 *
 * @param ifx Wi-Fi interface index (only WIFI_IF_STA is supported).
 * @return true when CONFIG_WPA_11KV_SUPPORT is enabled and sta.rm_enabled != 0.
 */
bool esp_wifi_is_rm_enabled_internal(uint8_t ifx)
{
#ifdef CONFIG_WPA_11KV_SUPPORT
    return (ifx == WIFI_IF_STA) && (g_n8.sta_cfg.sta.rm_enabled != 0U);
#else
    (void)ifx;
    return false;
#endif
}

/**
 * @brief Return whether 802.11v BSS Transition Management is enabled on an interface.
 *
 * @param ifx Wi-Fi interface index (only WIFI_IF_STA is supported).
 * @return true when CONFIG_WPA_11KV_SUPPORT is enabled and sta.btm_enabled != 0.
 */
bool esp_wifi_is_btm_enabled_internal(uint8_t ifx)
{
#ifdef CONFIG_WPA_11KV_SUPPORT
    return (ifx == WIFI_IF_STA) && (g_n8.sta_cfg.sta.btm_enabled != 0U);
#else
    (void)ifx;
    return false;
#endif
}

/**
 * @brief Register management frame subtype and Action category interest bitmasks.
 *
 * @param type    Bitmask of 802.11 management subtypes (1 << WLAN_FC_STYPE_*).
 * @param subtype Bitmask of 802.11 Action categories (1 << WLAN_ACTION_*).
 */
void esp_wifi_register_frame_internal(uint32_t type, uint32_t subtype)
{
#ifdef CONFIG_WPA_11KV_SUPPORT
    taskENTER_CRITICAL();
    g_n8.frame_reg_type = type;
    g_n8.frame_reg_subtype = subtype;
    taskEXIT_CRITICAL();
#else
    (void)type;
    (void)subtype;
#endif
}
