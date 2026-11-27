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
// STA/AP hardware key installation, 802.11w BIP AES-128-CMAC & IPN replay
// verification, App-IE & vendor-IE management, and WPS / WPA2-Enterprise /
// 802.11k/11v hooks.

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "net80211_internal.h"

#define TAG "wifi_supp"

/* From wpa_supplicant/src/crypto/aes-omac1.c */
extern int omac1_aes_128(const u8 *key, const u8 *data, size_t data_len, u8 *mac);

/* Matching enum wpa_alg from wpa_supplicant/src/common/defs.h */
#define SUPP_WPA_ALG_NONE           0
#define SUPP_WPA_ALG_WEP            1
#define SUPP_WPA_ALG_TKIP           2
#define SUPP_WPA_ALG_CCMP           3
#define SUPP_WPA_ALG_IGTK           4

/* Cipher bit indices expected by wpa_set_bss(): BIT(ret) == WPA_CIPHER_* */
#define SUPP_CIPHER_BIT_NONE         0U
#define SUPP_CIPHER_BIT_TKIP         1U
#define SUPP_CIPHER_BIT_CCMP         3U
#define SUPP_CIPHER_BIT_AES_128_CMAC 5U
#define SUPP_CIPHER_BIT_WEP40        7U
#define SUPP_CIPHER_BIT_WEP104       8U

/* Key material sizes, offsets, and hardware key table bounds */
#define SUPP_WEP40_KEY_LEN          5U
#define SUPP_TKIP_KEY_LEN           32U
#define SUPP_TKIP_TX_MIC_OFF        16U
#define SUPP_TKIP_RX_MIC_OFF        24U
#define SUPP_KEY_IDX_MASK           3
#define SUPP_GTK_REPLAY_SLOT_MASK   (N8_GTK_REPLAY_SLOTS - 1U) /* Maps GTK key IDs 1/2 -> slots 1/0 */
#define SUPP_LMAC_KEY_SLOT_MAX      25U

/* Supplicant TX callback table & App-IE / management frame limits */
#define SUPP_TX_CB_MAX              8U
#define SUPP_ASSOC_IE_PREFIX_LEN    2U
#define SUPP_IE_MAX_FULL_LEN        257U  /* 2B IE header + 255B max IE body */
#define SUPP_MGMT_FRM_MAX_LEN       512U
#define SUPP_MGMT_SUBTYPE_MASK      0x0FU
#define SUPP_MGMT_SUBTYPE_SHIFT     4

/* IEEE 802.11w BIP-CMAC-128 MMIE layout and AAD sizing (IEEE 802.11-2016 §12.5.4) */
#define BIP_MMIE_BODY_LEN           16U   /* MMIE IE length field value */
#define BIP_MMIE_KEYID_OFF          2U
#define BIP_MIC_LEN                 8U
#define BIP_AAD_FC_LEN              2U    /* Masked Frame Control field inside BIP AAD */
#define BIP_AAD_LEN                 20U   /* Masked FC(2) + A1(6) + A2(6) + A3(6) */
#define BIP_AAD_ADDRS_LEN           18U   /* A1 + A2 + A3 */
#define BIP_MAX_BODY_LEN            256U
#define BIP_CMAC_DIGEST_LEN         16U

/**
 * @brief Convert a wpa_supplicant cipher algorithm ID to an LMAC cipher enum.
 *
 * @param alg     Supplicant algorithm identifier (SUPP_WPA_ALG_*).
 * @param key_len Key length in bytes (used to distinguish WEP40 vs WEP104).
 * @return Corresponding LMAC cipher type, or ESP_LMAC_CIPHER_NONE if unsupported.
 */
static esp_lmac_cipher_t supp_alg_to_lmac(int alg, size_t key_len)
{
    switch (alg) {
    case SUPP_WPA_ALG_CCMP: return ESP_LMAC_CIPHER_CCMP;
    case SUPP_WPA_ALG_TKIP: return ESP_LMAC_CIPHER_TKIP;
    case SUPP_WPA_ALG_WEP:  return (key_len <= SUPP_WEP40_KEY_LEN) ? ESP_LMAC_CIPHER_WEP40 : ESP_LMAC_CIPHER_WEP104;
    default:                return ESP_LMAC_CIPHER_NONE;
    }
}

/**
 * @brief Convert an LMAC cipher enum back to a wpa_supplicant algorithm ID.
 *
 * @param c LMAC cipher type.
 * @return Corresponding SUPP_WPA_ALG_* constant.
 */
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

/**
 * @brief Convert a public ESP Wi-Fi cipher type to an LMAC cipher enum.
 *
 * @param c Public Wi-Fi cipher type (wifi_cipher_type_t).
 * @return Corresponding LMAC cipher type, or ESP_LMAC_CIPHER_NONE if none/unknown.
 */
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

/**
 * @brief Register the wpa_supplicant callback dispatch table.
 *
 * @param cb Pointer to heap-allocated wpa_funcs callback table owned by net80211.
 * @return ESP_OK always.
 */
int esp_wifi_register_wpa_cb_internal(struct wpa_funcs *cb)
{
    g_n8.wpa_cb = cb;
    return ESP_OK;
}

/**
 * @brief Unregister and free the wpa_supplicant callback dispatch table.
 *
 * @return ESP_OK always.
 */
int esp_wifi_unregister_wpa_cb_internal(void)
{
    if (g_n8.wpa_cb != NULL) {
        heap_caps_free(g_n8.wpa_cb);
        g_n8.wpa_cb = NULL;
    }
    return ESP_OK;
}

/**
 * @brief Worker-task RPC handler replacing `g_n8.wpa2_cb` and freeing any prior table.
 *
 * @param arg Pointer to heap-allocated `struct wpa2_funcs` (or NULL).
 * @return ESP_OK always.
 */
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

/**
 * @brief Worker-task RPC handler freeing and clearing `g_n8.wpa2_cb`.
 *
 * @param arg Unused RPC argument.
 * @return ESP_OK always.
 */
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

/**
 * @brief Worker-task RPC handler replacing `g_n8.wps_cb` and freeing any prior table.
 *
 * @param arg Pointer to heap-allocated `struct wps_funcs` (or NULL to clear).
 * @return ESP_OK always.
 */
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

/**
 * @brief Register a TX completion callback for a supplicant frame slot ID.
 *
 * @param fn Callback function invoked upon TX completion.
 * @param id Callback slot index (0 .. SUPP_TX_CB_MAX - 1).
 * @return ESP_OK on success, or ESP_ERR_INVALID_ARG if id is out of range.
 */
int esp_wifi_register_tx_cb_internal(wifi_tx_cb_t fn, u8 id)
{
    if (id >= SUPP_TX_CB_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    g_n8.tx_cbs[id] = fn;
    return ESP_OK;
}

/* --------------------------------------------------------------------------
 * App-IE Management (Handles Both Copied IEs [flag=0] & Live assoc_ie_buf [flag=1])
 * -------------------------------------------------------------------------- */

/**
 * @brief Release all registered App-IE slots, freeing heap-copied buffers only.
 */
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

/**
 * @brief Install an application/supplicant Information Element into an App-IE slot.
 *
 * Supports two ownership conventions used by wpa_supplicant:
 * - flag != 0: retains a live pointer directly to wpa_supplicant's `assoc_ie_buf`
 *   (whose first 2 bytes are a reserved length prefix and whose actual TLV IE
 *   bytes are populated later at `assoc_ie_buf + 2` by `wpa_gen_wpa_ie()`).
 * - flag == 0: allocates a `struct wifi_appie` buffer on the heap and copies `ie`.
 *
 * @param type App-IE slot type (0 .. WIFI_APPIE_MAX - 1).
 * @param ie   Pointer to IE bytes (or `assoc_ie_buf` base when flag != 0).
 * @param len  Length in bytes.
 * @param flag Non-zero to store as a live pointer; zero to deep-copy.
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG on bad parameters, or ESP_ERR_NO_MEM.
 */
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

/**
 * @brief Clear a single App-IE slot and free its buffer if heap-copied.
 *
 * @param type App-IE slot type (0 .. WIFI_APPIE_MAX - 1).
 * @return ESP_OK on success, or ESP_ERR_INVALID_ARG if type is out of range.
 */
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

/**
 * @brief Return the raw `struct wifi_appie` handle stored in an App-IE slot.
 *
 * @param type App-IE slot type (0 .. WIFI_APPIE_MAX - 1).
 * @return Pointer to stored buffer cast as `struct wifi_appie`, or NULL if unused.
 */
struct wifi_appie *esp_wifi_get_appie_internal(uint8_t type)
{
    if (type >= WIFI_APPIE_MAX || !g_n8.appies[type].in_use) {
        return NULL;
    }
    return (struct wifi_appie *)(void *)g_n8.appies[type].buf;
}

/**
 * @brief Resolve the wire-format TLV IE bytes and length for an App-IE slot.
 *
 * For live-pointer slots (`assoc_ie_buf`), skips the 2-byte prefix to reach the
 * `[elem_id, elem_len, body...]` TLV written by `wpa_gen_wpa_ie()` and derives
 * total length as `elem_len + 2`. For copied slots, returns `ie_data` and `ie_len`.
 *
 * @param type    App-IE slot type (0 .. WIFI_APPIE_MAX - 1).
 * @param out_len Optional output receiving the resolved IE byte length.
 * @return Pointer to wire-format IE bytes, or NULL if slot is empty/malformed.
 */
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
        const uint8_t *ie = s->buf + SUPP_ASSOC_IE_PREFIX_LEN;
        uint16_t full_len = (uint16_t)(ie[1] + IEEE80211_IE_HDR_LEN);
        if (full_len < IEEE80211_IE_HDR_LEN || full_len > SUPP_IE_MAX_FULL_LEN) {
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

/**
 * @brief Return the configured STA profile SSID boxed in `struct wifi_ssid`.
 *
 * @return Pointer to static STA SSID box inside `g_n8`.
 */
struct wifi_ssid *esp_wifi_sta_get_prof_ssid_internal(void)
{
    size_t n = strnlen((const char *)g_n8.sta_cfg.sta.ssid, N8_MAX_SSID_LEN);
    g_n8.sta_ssid_box.len = (int)n;
    memcpy(g_n8.sta_ssid_box.ssid, g_n8.sta_cfg.sta.ssid, n);
    return &g_n8.sta_ssid_box;
}

/**
 * @brief Return the configured STA passphrase buffer.
 *
 * @return Pointer to `g_n8.sta_cfg.sta.password`.
 */
uint8_t *esp_wifi_sta_get_prof_password_internal(void)
{
    return g_n8.sta_cfg.sta.password;
}

/**
 * @brief Return the eagerly derived 32-byte STA PMK buffer.
 *
 * @return Pointer to `g_n8.sta_pmk`.
 */
uint8_t *esp_wifi_sta_get_prof_pmk_internal(void)
{
    return g_n8.sta_pmk;
}

/**
 * @brief Return the AP-info cached STA PMK buffer (aliased to `g_n8.sta_pmk`).
 *
 * @return Pointer to `g_n8.sta_pmk`.
 */
uint8_t *esp_wifi_sta_get_ap_info_prof_pmk_internal(void)
{
    return g_n8.sta_pmk;
}

/**
 * @brief Query whether supplicant STA parameters require a reset.
 *
 * @return Current `g_n8.sta_reset_param` flag value.
 */
uint8_t esp_wifi_sta_get_reset_param_internal(void)
{
    return g_n8.sta_reset_param;
}

/**
 * @brief Update the supplicant STA parameter reset flag.
 *
 * @param reset_flag New flag value.
 * @return 0 always.
 */
uint8_t esp_wifi_sta_set_reset_param_internal(uint8_t reset_flag)
{
    g_n8.sta_reset_param = reset_flag;
    return 0U;
}

/**
 * @brief Notify net80211 that supplicant updated AP info (no-op stub).
 *
 * @return ESP_OK always.
 */
int esp_wifi_sta_update_ap_info_internal(void)
{
    return ESP_OK;
}

/**
 * @brief Check whether STA has started and entered at least authentication state.
 *
 * @return true if Wi-Fi is started and STA state >= N8_STA_AUTH.
 */
bool esp_wifi_sta_is_running_internal(void)
{
    return g_n8.started && (g_n8.sta_state >= N8_STA_AUTH);
}

/**
 * @brief Report whether the AP notification included a complete RSNE.
 *
 * @return true always.
 */
bool esp_wifi_sta_is_ap_notify_completed_rsne_internal(void)
{
    return true;
}

/**
 * @brief Copy the local MAC address of the requested Wi-Fi interface.
 *
 * @param if_index Interface index (WIFI_IF_AP or WIFI_IF_STA).
 * @param macaddr  Output 6-byte MAC address buffer.
 * @return ESP_OK on success, or ESP_ERR_INVALID_ARG if macaddr is NULL.
 */
int esp_wifi_get_macaddr_internal(uint8_t if_index, uint8_t *macaddr)
{
    if (macaddr == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (if_index == WIFI_IF_AP) {
        memcpy(macaddr, g_n8.ap_mac, IEEE80211_ADDR_LEN);
    } else {
        memcpy(macaddr, g_n8.sta_mac, IEEE80211_ADDR_LEN);
    }
    return ESP_OK;
}

/**
 * @brief Return the supplicant-format STA authentication mode for the active AP.
 *
 * @return Negotiated supplicant authmode (e.g. WPA2_AUTH_PSK, WPA3_AUTH_PSK).
 */
uint8_t esp_wifi_sta_get_prof_authmode_internal(void)
{
    return g_n8.sta_supp_authmode;
}

/**
 * @brief Check whether the active STA security protocol is legacy WPA (v1).
 *
 * @return true if WPA1 protocol is selected.
 */
bool esp_wifi_sta_prof_is_wpa_internal(void)
{
    return (g_n8.sta_wpa_proto == N8_WPA_PROTO_WPA);
}

/**
 * @brief Check whether the active STA security protocol is WPA2 (RSN, non-SAE).
 *
 * @return true if RSN protocol is selected and authmode is not WPA3 SAE.
 */
bool esp_wifi_sta_prof_is_wpa2_internal(void)
{
    return (g_n8.sta_wpa_proto == N8_WPA_PROTO_RSN) && (g_n8.sta_supp_authmode != WPA3_AUTH_PSK);
}

/**
 * @brief Check whether the active STA authentication mode is WPA3-Personal (SAE).
 *
 * @return true if STA authmode is WPA3_AUTH_PSK.
 */
bool esp_wifi_sta_prof_is_wpa3_internal(void)
{
    return (g_n8.sta_supp_authmode == WPA3_AUTH_PSK);
}

/**
 * @brief Map a `wifi_cipher_type_t` value to the bit position expected by `wpa_set_bss()`.
 *
 * @param wifi_cipher Cipher value (cast from `wifi_cipher_type_t`).
 * @return Bit index `n` such that `BIT(n)` matches supplicant's `WPA_CIPHER_*`.
 */
static uint8_t wifi_cipher_to_supp_bit(uint8_t wifi_cipher)
{
    /* Maps wifi_cipher_type_t to bit index expected by wpa_set_bss: BIT(ret) == WPA_CIPHER_* */
    switch ((wifi_cipher_type_t)wifi_cipher) {
    case WIFI_CIPHER_TYPE_TKIP:       return SUPP_CIPHER_BIT_TKIP;         /* WPA_CIPHER_TKIP = BIT(1) */
    case WIFI_CIPHER_TYPE_CCMP:
    case WIFI_CIPHER_TYPE_TKIP_CCMP:  return SUPP_CIPHER_BIT_CCMP;         /* WPA_CIPHER_CCMP = BIT(3) */
    case WIFI_CIPHER_TYPE_AES_CMAC128:return SUPP_CIPHER_BIT_AES_128_CMAC; /* WPA_CIPHER_AES_128_CMAC = BIT(5) */
    case WIFI_CIPHER_TYPE_WEP40:      return SUPP_CIPHER_BIT_WEP40;        /* WPA_CIPHER_WEP40 = BIT(7) */
    case WIFI_CIPHER_TYPE_WEP104:     return SUPP_CIPHER_BIT_WEP104;       /* WPA_CIPHER_WEP104 = BIT(8) */
    default:                          return SUPP_CIPHER_BIT_NONE;         /* WPA_CIPHER_NONE = BIT(0) */
    }
}

/**
 * @brief Return the STA pairwise cipher as a supplicant cipher bit index.
 *
 * @return Supplicant cipher bit index for `g_n8.sta_pairwise_cipher`.
 */
uint8_t esp_wifi_sta_get_pairwise_cipher_internal(void)
{
    return wifi_cipher_to_supp_bit(g_n8.sta_pairwise_cipher);
}

/**
 * @brief Return the STA group cipher as a supplicant cipher bit index.
 *
 * @return Supplicant cipher bit index for `g_n8.sta_group_cipher`.
 */
uint8_t esp_wifi_sta_get_group_cipher_internal(void)
{
    return wifi_cipher_to_supp_bit(g_n8.sta_group_cipher);
}

/**
 * @brief Query whether 802.11w Protected Management Frames (PMF) are active on STA.
 *
 * @return 1 if PMF is negotiated for the current association, 0 otherwise.
 */
uint16_t esp_wifi_sta_pmf_enabled(void)
{
    return g_n8.sta_pmf_active ? 1U : 0U;
}

/**
 * @brief Return the negotiated management group cipher (BIP) for STA PMF.
 *
 * @return Active management group cipher type.
 */
wifi_cipher_type_t esp_wifi_sta_get_mgmt_group_cipher(void)
{
    return (wifi_cipher_type_t)g_n8.sta_mgmt_cipher;
}

/**
 * @brief Copy the BSSID of the AP that STA is authenticating or associated with.
 *
 * @param bssid Output 6-byte BSSID buffer.
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG if NULL, or ESP_FAIL if not connecting/connected.
 */
int esp_wifi_get_assoc_bssid_internal(uint8_t *bssid)
{
    if (bssid == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (g_n8.sta_state < N8_STA_AUTH) {
        return ESP_FAIL;
    }
    memcpy(bssid, g_n8.sta_bssid, IEEE80211_ADDR_LEN);
    return ESP_OK;
}

/* SoftAP getters */

/**
 * @brief Return the configured SoftAP SSID boxed in `struct wifi_ssid`.
 *
 * @return Pointer to static AP SSID box inside `g_n8`.
 */
struct wifi_ssid *esp_wifi_ap_get_prof_ap_ssid_internal(void)
{
    size_t n = g_n8.ap_cfg.ap.ssid_len;
    if (n == 0U) {
        n = strnlen((const char *)g_n8.ap_cfg.ap.ssid, N8_MAX_SSID_LEN);
    }
    if (n > N8_MAX_SSID_LEN) {
        n = N8_MAX_SSID_LEN;
    }
    g_n8.ap_ssid_box.len = (int)n;
    memcpy(g_n8.ap_ssid_box.ssid, g_n8.ap_cfg.ap.ssid, n);
    return &g_n8.ap_ssid_box;
}

/**
 * @brief Return the configured SoftAP authentication mode.
 *
 * @return SoftAP `wifi_auth_mode_t` cast to uint8_t.
 */
uint8_t esp_wifi_ap_get_prof_authmode_internal(void)
{
    return (uint8_t)g_n8.ap_cfg.ap.authmode;
}

/**
 * @brief Return the configured SoftAP passphrase buffer.
 *
 * @return Pointer to `g_n8.ap_cfg.ap.password`.
 */
uint8_t *esp_wifi_ap_get_prof_password_internal(void)
{
    return g_n8.ap_cfg.ap.password;
}

/**
 * @brief Return the derived 32-byte SoftAP PMK buffer.
 *
 * @return Pointer to `g_n8.ap_pmk`.
 */
uint8_t *esp_wifi_ap_get_prof_pmk_internal(void)
{
    return g_n8.ap_pmk;
}

/**
 * @brief Return the opaque hostapd private handle for the running SoftAP.
 *
 * @return Pointer to `g_n8.ap_hapd`, or NULL if SoftAP hostapd is not active.
 */
void *esp_wifi_get_hostap_private_internal(void)
{
    return g_n8.ap_hapd;
}

/* --------------------------------------------------------------------------
 * STA & SoftAP Hardware Key Installation + 802.11w BIP IGTK
 * -------------------------------------------------------------------------- */

/**
 * @brief Install or clear a STA unicast PTK or multicast GTK in LMAC hardware.
 *
 * Key routing: a unicast peer address with `set_tx != 0` routes to the STA's
 * PTK slot (bound to `g_n8.sta_peer_id`) and resets STA TX/mgmt PNs and
 * per-TID RX replay windows; broadcast/NULL address or `set_tx == 0` routes to
 * the VIF GTK slot and resets that GTK replay slot.
 * For CCMP PTKs, caches the 16-byte key in `g_n8.sta_ptk_key` for 802.11w
 * software management frame encryption/decryption. Purges STA RX defragmentation
 * buffers on every key change to prevent mixed-key reassembly (CVE-2020-26146).
 *
 * @param alg             Supplicant cipher algorithm (SUPP_WPA_ALG_*).
 * @param addr            Peer MAC address (unicast for PTK, broadcast/NULL for GTK).
 * @param key_idx         802.11 key index (0..3).
 * @param set_tx          Non-zero when installing a TX-active key (PTK).
 * @param seq             Optional receive sequence counter (unused).
 * @param seq_len         Length of `seq` in bytes (unused).
 * @param key             Raw key bytes, or NULL when deleting a key.
 * @param key_len         Length of `key` in bytes.
 * @param key_entry_valid Key slot hint from supplicant (unused).
 * @return 0 on success, or -1 on unsupported cipher or hardware key error.
 */
int esp_wifi_set_sta_key_internal(int alg, u8 *addr, int key_idx, int set_tx,
                                  u8 *seq, size_t seq_len, u8 *key, size_t key_len,
                                  int key_entry_valid)
{
    (void)seq;
    (void)seq_len;
    (void)key_entry_valid;

    /* Route unicast TX keys to PTK (bound to AP peer_id); all others to VIF GTK */
    bool is_ptk = (set_tx != 0) && (addr != NULL) && ((addr[0] & N8_MAC_MCAST_BIT) == 0U);
    uint8_t kidx = (uint8_t)(key_idx & SUPP_KEY_IDX_MASK);
    if (alg == SUPP_WPA_ALG_NONE || key == NULL || key_len == 0U) {
        esp_lmac_key_clear(ESP_LMAC_VIF_STA,
                           is_ptk ? g_n8.sta_peer_id : ESP_LMAC_PEER_INVALID,
                           is_ptk ? ESP_LMAC_KEY_TYPE_PTK : ESP_LMAC_KEY_TYPE_GTK,
                           kidx);
        /* Purge in-flight STA fragments so stale cipher fragments cannot mix across keys */
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
            memset(&g_n8.sta_rx_gtk_pn[kidx & SUPP_GTK_REPLAY_SLOT_MASK], 0, sizeof(g_n8.sta_rx_gtk_pn[0]));
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
        /* Cache CCMP PTK for 802.11w SW protected management frame crypto */
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
        memset(&g_n8.sta_rx_gtk_pn[kidx & SUPP_GTK_REPLAY_SLOT_MASK], 0, sizeof(g_n8.sta_rx_gtk_pn[0]));
    }
    n8_defrag_purge_vif(ESP_LMAC_VIF_STA);
    return 0;
}

/**
 * @brief Read back a hardware key table slot for diagnostics or supplicant queries.
 *
 * @param ifx             Optional output receiving the slot's VIF index.
 * @param alg             Optional output receiving the supplicant algorithm ID.
 * @param addr            Output peer MAC buffer (6 bytes).
 * @param key_idx         Optional output receiving the 802.11 key index.
 * @param key             Output buffer for raw key bytes.
 * @param key_len         Maximum bytes to read into `key`.
 * @param key_entry_valid Hardware key slot index (0 .. SUPP_LMAC_KEY_SLOT_MAX - 1).
 * @return 0 on success, or -1 if the slot index is invalid or unreadable.
 */
int esp_wifi_get_sta_key_internal(uint8_t *ifx, int *alg, u8 *addr, int *key_idx,
                                  u8 *key, size_t key_len, int key_entry_valid)
{
    uint8_t slot = (uint8_t)key_entry_valid;
    if (slot >= SUPP_LMAC_KEY_SLOT_MAX) {
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

/**
 * @brief Install or clear a SoftAP GTK (broadcast) or per-STA PTK (unicast) in LMAC hardware.
 *
 * Key routing: broadcast/NULL `addr` installs or clears the SoftAP GTK and purges
 * AP defragmentation state; a unicast `addr` looks up the associated `n8_ap_sta_t`,
 * installs/clears its PTK, resets its per-TID RX replay windows (`ptk_pn`), purges
 * its defragmentation slots (CVE-2020-26146), and deauthorizes the station when
 * clearing a key on a secured AP.
 * For TKIP keys, swaps the Authenticator TX/RX MIC halves before programming
 * WDEV hardware (which computes TKIP Michael MIC in silicon).
 *
 * @param alg     Supplicant cipher algorithm (SUPP_WPA_ALG_*).
 * @param addr    Station MAC address (unicast for PTK, broadcast/NULL for GTK).
 * @param idx     802.11 key index (0..3).
 * @param key     Raw key bytes, or NULL when clearing a key.
 * @param key_len Length of `key` in bytes.
 * @return 0 on success, or -1 if cipher is invalid, station is unknown, or HW install fails.
 */
int esp_wifi_set_ap_key_internal(int alg, const u8 *addr, int idx, u8 *key, size_t key_len)
{
    bool is_bcast = (addr == NULL) || ((addr[0] & N8_MAC_MCAST_BIT) != 0U);

    if (alg == SUPP_WPA_ALG_NONE || key == NULL || key_len == 0U) {
        if (is_bcast) {
            esp_lmac_key_clear(ESP_LMAC_VIF_AP, ESP_LMAC_PEER_INVALID,
                               ESP_LMAC_KEY_TYPE_GTK, (uint8_t)(idx & SUPP_KEY_IDX_MASK));
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
    uint8_t hw_key[SUPP_TKIP_KEY_LEN];
    size_t copy_len = (key_len > sizeof(hw_key)) ? sizeof(hw_key) : key_len;
    memcpy(hw_key, key, copy_len);
    if (cipher == ESP_LMAC_CIPHER_TKIP && copy_len == SUPP_TKIP_KEY_LEN) {
        memcpy(hw_key + SUPP_TKIP_TX_MIC_OFF, key + SUPP_TKIP_RX_MIC_OFF, N8_TKIP_MIC_KEY_LEN);
        memcpy(hw_key + SUPP_TKIP_RX_MIC_OFF, key + SUPP_TKIP_TX_MIC_OFF, N8_TKIP_MIC_KEY_LEN);
    }

    if (is_bcast) {
        esp_err_t err = esp_lmac_key_set(ESP_LMAC_VIF_AP, ESP_LMAC_PEER_INVALID,
                                         ESP_LMAC_KEY_TYPE_GTK, (uint8_t)(idx & SUPP_KEY_IDX_MASK),
                                         cipher, hw_key, (uint8_t)copy_len);
        if (err != ESP_OK) {
            return -1;
        }
        g_n8.ap_gtk_cipher = (uint8_t)cipher;
        g_n8.ap_gtk_key_idx = (uint8_t)(idx & SUPP_KEY_IDX_MASK);
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
    sta->ptk_key_idx = (uint8_t)(idx & SUPP_KEY_IDX_MASK);
    sta->tx_pn = 1ULL;
    memset(sta->ptk_pn, 0, sizeof(sta->ptk_pn));
    n8_defrag_purge_peer(ESP_LMAC_VIF_AP, sta->mac);
    return 0;
}

/**
 * @brief Store the 802.11w Integrity Group Temporal Key (IGTK) for STA BIP verification.
 *
 * IGTK verification is performed in software via `n8_verify_bip_mmie()` rather than
 * in LMAC hardware, so this stores the key material directly in `g_n8.sta_igtk`
 * and resets the BIP IPN replay watermark (`sta_rx_bip_ipn` / `sta_rx_bip_ipn_valid`).
 *
 * @param if_index Interface index (must be WIFI_IF_STA).
 * @param igtk     Pointer to IGTK key structure provided by wpa_supplicant.
 * @return ESP_OK on success, or ESP_ERR_INVALID_ARG if interface or pointer is invalid.
 */
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

/**
 * @brief Verify an IEEE 802.11w BIP-CMAC-128 Management MIC IE (MMIE) on a received frame.
 *
 * Validates the MMIE header and KeyID, enforces strict LE48 IPN monotonicity
 * against `g_n8.sta_rx_bip_ipn` to block replayed broadcast management frames,
 * constructs the BIP-CMAC-128 input buffer per IEEE 802.11-2016 §12.5.4:
 *   `[AAD (20B) | Management Frame Body (with trailing 8-byte MMIE MIC zeroed)]`
 * where AAD = masked Frame Control (Retry/PM/MoreData cleared) + A1 + A2 + A3,
 * computes AES-128-CMAC (OMAC1) with `g_n8.sta_igtk.igtk`, and commits the new
 * IPN watermark only after the truncated 8-byte MIC matches.
 *
 * @param frame Pointer to complete received 802.11 management frame.
 * @param len   Total frame length in bytes (excluding FCS).
 * @return true if IGTK is valid, MMIE header/KeyID/IPN pass, and AES-CMAC MIC verifies.
 */
bool n8_verify_bip_mmie(const uint8_t *frame, uint16_t len)
{
    /* IEEE 802.11w BIP-CMAC-128 MMIE is 18 bytes at end of broadcast mgmt frame:
     * [ID=76 (1B) | Len=16 (1B) | KeyID (2B) | IPN (6B) | MIC (8B)] */
    if (!g_n8.sta_igtk_valid || len < IEEE80211_HDR_LEN + IEEE80211_MMIE_LEN) {
        return false;
    }

    const uint8_t *mmie = frame + len - IEEE80211_MMIE_LEN;
    if (mmie[0] != IEEE80211_IE_MMIE || mmie[1] != BIP_MMIE_BODY_LEN) {
        return false;
    }
    if (mmie[BIP_MMIE_KEYID_OFF] != g_n8.sta_igtk.keyid[0] ||
        mmie[BIP_MMIE_KEYID_OFF + 1U] != g_n8.sta_igtk.keyid[1]) {
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
    if (body_len > BIP_MAX_BODY_LEN) {
        return false;
    }

    uint8_t bip_buf[BIP_AAD_LEN + BIP_MAX_BODY_LEN];
    bip_buf[0] = (uint8_t)(frame[0] & 0xFFU);
    bip_buf[1] = (uint8_t)(frame[1] & ~(IEEE80211_FC1_RETRY | IEEE80211_FC1_PM | IEEE80211_FC1_MOREDATA));
    memcpy(bip_buf + BIP_AAD_FC_LEN, frame + IEEE80211_HDR_ADDR1_OFF, BIP_AAD_ADDRS_LEN);
    memcpy(bip_buf + BIP_AAD_LEN, frame + IEEE80211_HDR_LEN, body_len);
    /* Zero the 8-byte MIC field inside MMIE before computing AES-128-CMAC */
    memset(bip_buf + BIP_AAD_LEN + body_len - BIP_MIC_LEN, 0, BIP_MIC_LEN);

    uint8_t mac[BIP_CMAC_DIGEST_LEN];
    if (omac1_aes_128(g_n8.sta_igtk.igtk, bip_buf, (size_t)(BIP_AAD_LEN + body_len), mac) != 0) {
        return false;
    }

    if (memcmp(mac, mmie + IEEE80211_MMIE_MIC_OFF, BIP_MIC_LEN) != 0) {
        return false;
    }

    /* Advance IPN watermark only after CMAC succeeds so forged frames cannot DoS replay state */
    g_n8.sta_rx_bip_ipn = ipn;
    g_n8.sta_rx_bip_ipn_valid = 1U;
    return true;
}

/* --------------------------------------------------------------------------
 * Handshake Completion, Deauth, IPC & Management Frame Injection
 * -------------------------------------------------------------------------- */

/**
 * @brief Notify STA MLME that the 4-way handshake has completed.
 *
 * @return true always.
 */
bool esp_wifi_auth_done_internal(void)
{
    n8_sta_on_auth_done();
    return true;
}

/**
 * @brief Deauthenticate the STA from the current AP with the given reason code.
 *
 * @param reason_code IEEE 802.11 reason code sent in the Deauth frame and event.
 */
void esp_wifi_deauthenticate_internal(u8 reason_code)
{
    n8_sta_disconnect(reason_code, true, true);
}

/**
 * @brief Issue a STA disconnect with deauthentication and system event notification.
 *
 * @param reason_code IEEE 802.11 reason code.
 * @return ESP_OK always.
 */
esp_err_t esp_wifi_internal_issue_disconnect(uint8_t reason_code)
{
    n8_sta_disconnect(reason_code, true, true);
    return ESP_OK;
}

/**
 * @brief Notify SoftAP MLME that a station completed its 4-way PTK handshake.
 *
 * @param mac 6-byte MAC address of the newly authorized station.
 * @return true always.
 */
bool esp_wifi_wpa_ptk_init_done_internal(uint8_t *mac)
{
    if (mac != NULL) {
        n8_ap_on_ptk_done(mac);
    }
    return true;
}

/**
 * @brief Deauthenticate and remove an associated station from the SoftAP.
 *
 * @param mac    6-byte MAC address of the station to deauthenticate.
 * @param reason IEEE 802.11 reason code.
 * @return ESP_OK on success, or ESP_ERR_INVALID_ARG if `mac` is NULL.
 */
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

/**
 * @brief Worker-task trampoline adapting `wifi_ipc_config_t` to `n8_api_fn_t`.
 *
 * @param arg Pointer to `wifi_ipc_config_t`.
 * @return Return code from `cfg->fn(cfg->arg)` cast to `esp_err_t`.
 */
static esp_err_t ipc_trampoline(void *arg)
{
    wifi_ipc_config_t *cfg = (wifi_ipc_config_t *)arg;
    return (esp_err_t)cfg->fn(cfg->arg);
}

/**
 * @brief Execute a supplicant callback serialized on the net80211 worker task.
 *
 * @param cfg  IPC descriptor specifying target function and argument.
 * @param sync Synchronization hint (always executed synchronously via `n8_api_call`).
 * @return Return value of the invoked callback, or ESP_ERR_INVALID_ARG.
 */
int esp_wifi_ipc_internal(wifi_ipc_config_t *cfg, bool sync)
{
    if (cfg == NULL || cfg->fn == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    (void)sync;
    return (int)n8_api_call(ipc_trampoline, cfg);
}

/**
 * @brief Build an 802.11 management frame header and transmit a supplicant payload on the worker task.
 *
 * Routes STA Action frames through `n8_sta_tx_action()` when `CONFIG_WPA_11KV_SUPPORT`
 * is enabled so 802.11w PMF CCMP encryption is applied when active. Allocates a heap copy
 * of the body that is freed asynchronously by `n8_mgmt_free_tx_cb` upon LMAC TX completion.
 *
 * @param arg Pointer to `const mgmt_frm_req_t` specifying interface, subtype, and payload bytes.
 * @return ESP_OK on submission, ESP_ERR_NO_MEM, or LMAC TX error.
 */
static esp_err_t api_send_mgmt_frm(void *arg)
{
    const mgmt_frm_req_t *req = (const mgmt_frm_req_t *)arg;
#ifdef CONFIG_WPA_11KV_SUPPORT
    if (req->ifx == WIFI_IF_STA && req->subtype == IEEE80211_STYPE_IDX_ACTION) {
        return n8_sta_tx_action((const uint8_t *)req->data, (uint16_t)req->data_len);
    }
#endif

    uint8_t hdr[IEEE80211_HDR_LEN];
    memset(hdr, 0, sizeof(hdr));
    hdr[0] = (uint8_t)(IEEE80211_FC_TYPE_MGMT | ((req->subtype & SUPP_MGMT_SUBTYPE_MASK) << SUPP_MGMT_SUBTYPE_SHIFT));
    if (req->ifx == WIFI_IF_STA) {
        memcpy(hdr + IEEE80211_HDR_ADDR1_OFF, g_n8.sta_bssid, IEEE80211_ADDR_LEN);
        memcpy(hdr + IEEE80211_HDR_ADDR2_OFF, g_n8.sta_mac, IEEE80211_ADDR_LEN);
        memcpy(hdr + IEEE80211_HDR_ADDR3_OFF, g_n8.sta_bssid, IEEE80211_ADDR_LEN);
        uint16_t seq = n8_sta_next_seq();
        hdr[IEEE80211_HDR_SEQ_OFF] = (uint8_t)(seq & 0xFFU);
        hdr[IEEE80211_HDR_SEQ_OFF + 1U] = (uint8_t)(seq >> 8);
    } else {
        memset(hdr + IEEE80211_HDR_ADDR1_OFF, 0xFF, IEEE80211_ADDR_LEN);
        memcpy(hdr + IEEE80211_HDR_ADDR2_OFF, g_n8.ap_mac, IEEE80211_ADDR_LEN);
        memcpy(hdr + IEEE80211_HDR_ADDR3_OFF, g_n8.ap_mac, IEEE80211_ADDR_LEN);
        uint16_t seq = n8_ap_next_seq();
        hdr[IEEE80211_HDR_SEQ_OFF] = (uint8_t)(seq & 0xFFU);
        hdr[IEEE80211_HDR_SEQ_OFF + 1U] = (uint8_t)(seq >> 8);
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
    /* Free the heap-copied body asynchronously when LMAC completes TX */
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
 * Validates `req` length against `SUPP_MGMT_FRM_MAX_LEN` and marshals frame
 * construction/TX onto the net80211 worker task via `api_send_mgmt_frm()`.
 *
 * @param req Management frame request descriptor.
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG on bad parameters, or TX error code.
 */
esp_err_t esp_wifi_send_mgmt_frm_internal(const mgmt_frm_req_t *req)
{
    if (req == NULL || req->data_len == 0U || req->data_len > SUPP_MGMT_FRM_MAX_LEN) {
        return ESP_ERR_INVALID_ARG;
    }
    return n8_api_call(api_send_mgmt_frm, (void *)(uintptr_t)req);
}

/* --------------------------------------------------------------------------
 * WPS / WPA2-Enterprise / 11k/11v Hooks (Required by esp_wifi_driver.h)
 * -------------------------------------------------------------------------- */

/**
 * @brief Worker-task RPC trampoline invoking a WPA2-Enterprise enable/disable callback.
 *
 * @param arg Pointer to `wifi_wpa2_param_t` specifying target function and parameter.
 * @return Return value of `param->fn(param->param)`.
 */
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

/**
 * @brief Record the current WPA2-Enterprise EAP state.
 *
 * @param state New EAP state value.
 * @return ESP_OK always.
 */
esp_err_t esp_wifi_set_wpa2_ent_state_internal(wpa2_ent_eap_state_t state)
{
    g_n8.wpa2_ent_state = state;
    return ESP_OK;
}

/**
 * @brief Return the active WPS mode type.
 *
 * @return Stored `g_n8.wps_type`.
 */
int esp_wifi_get_wps_type_internal(void)           { return g_n8.wps_type; }

/**
 * @brief Set the active WPS mode type.
 *
 * @param type WPS type value.
 * @return ESP_OK always.
 */
int esp_wifi_set_wps_type_internal(uint32_t type)  { g_n8.wps_type = (int)type; return ESP_OK; }

/**
 * @brief Return the current WPS status code.
 *
 * @return Stored `g_n8.wps_status`.
 */
int esp_wifi_get_wps_status_internal(void)         { return g_n8.wps_status; }

/**
 * @brief Set the current WPS status code.
 *
 * @param st WPS status value.
 * @return ESP_OK always.
 */
int esp_wifi_set_wps_status_internal(uint32_t st)  { g_n8.wps_status = (int)st; return ESP_OK; }

/**
 * @brief Enable STA privacy bit for protected associations (always enabled on demand).
 *
 * @return true always.
 */
bool esp_wifi_enable_sta_privacy_internal(void)    { return true; }

/**
 * @brief Disarm the STA connection timeout timer during WPS/EAP handshakes.
 *
 * @return ESP_OK always.
 */
int esp_wifi_disarm_sta_connection_timer_internal(void) { g_n8.sta_conn_timer_disarmed = 1U; return ESP_OK; }

/**
 * @brief Set or clear the WPS start flag.
 *
 * @param start true when WPS is starting, false when stopped.
 * @return ESP_OK always.
 */
esp_err_t esp_wifi_set_wps_start_flag_internal(bool start) { g_n8.wps_start_flag = start ? 1U : 0U; return ESP_OK; }

/**
 * @brief Return the user Wi-Fi initialization flag.
 *
 * @return Stored `g_n8.user_init_flag`.
 */
uint8_t esp_wifi_get_user_init_flag_internal(void) { return g_n8.user_init_flag; }

/**
 * @brief Check whether 802.11k Radio Measurement (RM) is enabled on an interface.
 *
 * @param ifx Interface index (only `WIFI_IF_STA` is supported).
 * @return true if `CONFIG_WPA_11KV_SUPPORT` is enabled, `ifx == WIFI_IF_STA`, and `rm_enabled` is configured.
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
 * @brief Check whether 802.11v BSS Transition Management (BTM) is enabled on an interface.
 *
 * @param ifx Interface index (only `WIFI_IF_STA` is supported).
 * @return true if `CONFIG_WPA_11KV_SUPPORT` is enabled, `ifx == WIFI_IF_STA`, and `btm_enabled` is configured.
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
 * @param type    Bitmask of 802.11 management subtypes (`1 << WLAN_FC_STYPE_*`).
 * @param subtype Bitmask of 802.11 Action categories (`1 << WLAN_ACTION_*`).
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
