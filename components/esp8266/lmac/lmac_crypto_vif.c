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
// WDEV hardware initialization, dual-VIF MAC/BSSID filters, 25-slot hardware
// crypto engine, SoftAP beacon/TBTT engine, promiscuous/sniffer mode, RX BA
// scoreboards, and 5-bank hardware MAC reset (.flash.text).
//
// Portions of the WDEV hardware init, key-slot, and crypto-config sequences
// are adapted in part from teatime-os:
//   MIT License
//   Copyright (c) 2025-2026 Jonathan Waters
//   Permission is hereby granted, free of charge, to any person obtaining a
//   copy of this software and associated documentation files (the "Software"),
//   to deal in the Software without restriction, including without limitation
//   the rights to use, copy, modify, merge, publish, distribute, sublicense,
//   and/or sell copies of the Software, and to permit persons to whom the
//   Software is furnished to do so, subject to the following conditions:
//   The above copyright notice and this permission notice shall be included in
//   all copies or substantial portions of the Software.

#include <string.h>

#include "FreeRTOS.h"
#include "task.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "lmac_internal.h"

#define TAG "lmac_hw"

extern uint32_t WDEV_INTEREST_EVENT;
extern volatile uint8_t NMIIrqIsOn;

static const uint8_t s_bcast_mac[6] = { 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU };

static inline uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline uint16_t read_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* --------------------------------------------------------------------------
 * Hardware Key Table (25 Slots @ 0x3FF21400, 40 B Each)
 * -------------------------------------------------------------------------- */

static void hw_key_clear_slot(uint8_t slot)
{
    if (slot >= LMAC_HW_KEY_SLOTS) {
        return;
    }

    lmac_reg_clr(LMAC_WDEV_KEY_VALID_MASK, (1U << slot));
    for (uint32_t off = 0U; off < 0x28U; off += 4U) {
        lmac_reg_write(LMAC_KEY_SLOT_BASE(slot) + off, 0U);
    }

    memset(&g_lmac.keys[slot], 0, sizeof(g_lmac.keys[slot]));
    g_lmac.keys[slot].peer_id = ESP_LMAC_PEER_INVALID;
}

static void hw_key_write_slot(uint8_t slot, uint8_t vif, uint8_t hw_alg, uint8_t sub_alg,
                              uint8_t key_class, uint8_t key_idx, const uint8_t addr[6],
                              const uint8_t *key, uint8_t key_len)
{
    /* Match vendor wDev_Insert_KeyEntry eviction guard when writing STA GTK slot 2 */
    if (slot == 2U && ((lmac_reg_read(LMAC_KEY_SLOT_FLAGS(3U)) >> 30) & 3U) == (key_idx & 3U)) {
        hw_key_clear_slot(3U);
    }

    uint32_t addr_lo = read_le32(addr);
    uint32_t addr_hi = (uint32_t)read_le16(addr + 4);
    uint32_t flags = addr_hi |
                     (((uint32_t)sub_alg & 3U) << 16) |
                     (((uint32_t)hw_alg & 7U) << 18) |
                     (((uint32_t)key_class & 7U) << 21) |
                     (((uint32_t)vif & 1U) << 24) |
                     (((uint32_t)key_idx & 3U) << 30);

    uint8_t padded[32];
    memset(padded, 0, sizeof(padded));
    if (key != NULL && key_len > 0U) {
        uint8_t copy_len = (key_len > sizeof(padded)) ? (uint8_t)sizeof(padded) : key_len;
        memcpy(padded, key, copy_len);
    }

    lmac_reg_write(LMAC_KEY_SLOT_ADDR(slot), addr_lo);
    lmac_reg_write(LMAC_KEY_SLOT_FLAGS(slot), flags);
    for (uint8_t w = 0U; w < 8U; w++) {
        lmac_reg_write(LMAC_KEY_SLOT_DATA(slot, w), read_le32(&padded[w * 4U]));
    }
    lmac_reg_set(LMAC_WDEV_KEY_VALID_MASK, (1U << slot));
}

/**
 * @brief Update the per-VIF hardware crypto engine control register (CONF0/CONF1).
 *
 * Scans user key slots (2..24) for active keys belonging to @p vif and writes
 * either bypass mode or active STA/SoftAP crypto mode (plus the WEP flag when
 * any WEP key is installed). Preserves LMAC_CRYPTO_TX_ENC across key updates
 * whenever an opposite-VIF software-protected frame is active in hardware TX.
 *
 * @param vif  Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 */
static void hw_crypto_update_vif_reg(esp_lmac_vif_t vif)
{
    if (vif >= ESP_LMAC_VIF_MAX || g_lmac.sniffer_mode != 0U) {
        return;
    }

    uint32_t reg = (vif == ESP_LMAC_VIF_STA) ? LMAC_WDEV_CRYPTO_CONF0 : LMAC_WDEV_CRYPTO_CONF1;
    bool has_key = false;
    bool is_wep = false;

    for (uint8_t s = 2U; s < LMAC_HW_KEY_SLOTS; s++) {
        if (g_lmac.keys[s].in_use && g_lmac.keys[s].vif == vif) {
            has_key = true;
            if (g_lmac.keys[s].cipher == ESP_LMAC_CIPHER_WEP40 ||
                g_lmac.keys[s].cipher == ESP_LMAC_CIPHER_WEP104) {
                is_wep = true;
            }
        }
    }

    /* Cross-checked against wDev_Crypto_Conf (wdev.o.c) & teatime-os (wifi_ccmp.c) */
    uint32_t val;
    if (!has_key) {
        val = LMAC_CRYPTO_BYPASS;
    } else {
        val = (vif == ESP_LMAC_VIF_STA) ? LMAC_CRYPTO_ACTIVE_STA : LMAC_CRYPTO_ACTIVE_SPP;
        if (is_wep) {
            val |= LMAC_CRYPTO_WEP_BIT;
        }
    }

    vPortETSIntrLock();
    bool sw_bypass_active = (g_lmac.sw_prot_bypass_vif == (uint8_t)(vif + 1U));
    if (!sw_bypass_active) {
        for (uint8_t q = 0U; q < LMAC_HW_TXQ_COUNT; q++) {
            const lmac_tx_slot_t *act = g_lmac.hw_txq[q].active;
            if (act != NULL &&
                (act->hdr_buf[1] & LMAC_FC1_PROTECTED) != 0U &&
                (act->hw_key_slot & LMAC_KEY_SLOT_MASK) == 0U) {
                esp_lmac_vif_t target_vif = ((act->hw_key_slot & LMAC_KEY_SLOT_AP_BIT) != 0U)
                                            ? ESP_LMAC_VIF_AP
                                            : ESP_LMAC_VIF_STA;
                if (target_vif == vif) {
                    sw_bypass_active = true;
                    break;
                }
            }
        }
    }
    if (sw_bypass_active) {
        if (!has_key) {
            /* LMAC_CRYPTO_BYPASS already sets TX_ENC=1; prevent TX-done from clearing it */
            g_lmac.sw_prot_bypass_vif = 0U;
        } else {
            /* Keep TX_ENC=1 while an opposite-VIF SW-protected TX is in flight */
            val |= LMAC_CRYPTO_TX_ENC;
            g_lmac.sw_prot_bypass_vif = (uint8_t)(vif + 1U);
        }
    }
    lmac_reg_write(reg, val);
    vPortETSIntrUnlock();
}

static void cipher_to_hw_alg(esp_lmac_cipher_t cipher, uint8_t *hw_alg, uint8_t *sub_alg)
{
    *sub_alg = 0U;
    switch (cipher) {
    case ESP_LMAC_CIPHER_WEP40:
        *hw_alg = LMAC_HW_ALG_WEP;
        *sub_alg = 0U;
        break;
    case ESP_LMAC_CIPHER_WEP104:
        *hw_alg = LMAC_HW_ALG_WEP;
        *sub_alg = 1U;
        break;
    case ESP_LMAC_CIPHER_TKIP:
        *hw_alg = LMAC_HW_ALG_TKIP;
        break;
    case ESP_LMAC_CIPHER_CCMP:
        *hw_alg = LMAC_HW_ALG_CCMP;
        break;
    default:
        *hw_alg = LMAC_HW_ALG_NONE;
        break;
    }
}

esp_err_t esp_lmac_key_set(esp_lmac_vif_t vif, esp_lmac_peer_id_t peer_id,
                           esp_lmac_key_type_t type, uint8_t key_idx,
                           esp_lmac_cipher_t cipher, const uint8_t *key, uint8_t key_len)
{
    if (vif >= ESP_LMAC_VIF_MAX || key == NULL || key_len == 0U || key_idx > 3U) {
        return ESP_ERR_INVALID_ARG;
    }
    if (cipher == ESP_LMAC_CIPHER_NONE) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t hw_alg = 0U;
    uint8_t sub_alg = 0U;
    cipher_to_hw_alg(cipher, &hw_alg, &sub_alg);

    uint8_t slot = 0xFFU;
    uint8_t key_class = LMAC_HW_KEY_CLASS_GTK;
    const uint8_t *addr = s_bcast_mac;

    if (cipher == ESP_LMAC_CIPHER_WEP40 || cipher == ESP_LMAC_CIPHER_WEP104) {
        slot = (uint8_t)(2U + (key_idx & 3U));
        key_class = LMAC_HW_KEY_CLASS_WEP;
        addr = g_lmac.vif[vif].bssid_enabled ? g_lmac.vif[vif].bssid : s_bcast_mac;
    } else if (type == ESP_LMAC_KEY_TYPE_GTK) {
        key_class = LMAC_HW_KEY_CLASS_GTK;
        uint8_t base = (vif == ESP_LMAC_VIF_STA) ? 2U : 4U;

        /* Reuse slot if same key_idx is already installed on this VIF */
        if (g_lmac.keys[base].in_use && g_lmac.keys[base].vif == vif &&
            g_lmac.keys[base].key_idx == key_idx) {
            slot = base;
        } else if (g_lmac.keys[base + 1U].in_use && g_lmac.keys[base + 1U].vif == vif &&
                   g_lmac.keys[base + 1U].key_idx == key_idx) {
            slot = (uint8_t)(base + 1U);
        } else if (!g_lmac.keys[base].in_use) {
            slot = base;
        } else if (!g_lmac.keys[base + 1U].in_use) {
            slot = (uint8_t)(base + 1U);
        } else {
            slot = (uint8_t)(base + (g_lmac.vif[vif].gtk_toggle & 1U));
            g_lmac.vif[vif].gtk_toggle ^= 1U;
        }

        if (vif == ESP_LMAC_VIF_STA && g_lmac.vif[vif].bssid_enabled) {
            addr = g_lmac.vif[vif].bssid;
        } else {
            addr = s_bcast_mac;
        }
    } else {
        /* Pairwise key (PTK): slots 6..24 */
        lmac_peer_t *p = lmac_trc_get_peer(peer_id);
        if (p == NULL) {
            return ESP_ERR_NOT_FOUND;
        }
        key_class = LMAC_HW_KEY_CLASS_PTK;
        addr = p->mac;

        if (p->ptk_hw_slot >= 6U && p->ptk_hw_slot < LMAC_HW_KEY_SLOTS) {
            slot = p->ptk_hw_slot;
        } else {
            for (uint8_t s = 6U; s < LMAC_HW_KEY_SLOTS; s++) {
                if (!g_lmac.keys[s].in_use) {
                    slot = s;
                    break;
                }
            }
            if (slot == 0xFFU) {
                return ESP_ERR_NO_MEM;
            }
        }
        p->ptk_hw_slot = slot;
        p->ptk_cipher = (uint8_t)cipher;
    }

    hw_key_write_slot(slot, vif, hw_alg, sub_alg, key_class, key_idx, addr, key, key_len);

    g_lmac.keys[slot].in_use = 1U;
    g_lmac.keys[slot].vif = vif;
    g_lmac.keys[slot].peer_id = peer_id;
    g_lmac.keys[slot].key_type = (uint8_t)type;
    g_lmac.keys[slot].key_idx = key_idx;
    g_lmac.keys[slot].cipher = (uint8_t)cipher;

    if (type == ESP_LMAC_KEY_TYPE_GTK) {
        g_lmac.vif[vif].gtk_cipher = (uint8_t)cipher;
        g_lmac.vif[vif].gtk_active_slot = slot;
    } else {
        g_lmac.vif[vif].ptk_cipher = (uint8_t)cipher;
    }

    hw_crypto_update_vif_reg(vif);
    return ESP_OK;
}

void esp_lmac_key_clear(esp_lmac_vif_t vif, esp_lmac_peer_id_t peer_id,
                        esp_lmac_key_type_t type, uint8_t key_idx)
{
    if (vif >= ESP_LMAC_VIF_MAX) {
        return;
    }

    for (uint8_t s = 2U; s < LMAC_HW_KEY_SLOTS; s++) {
        if (!g_lmac.keys[s].in_use || g_lmac.keys[s].vif != vif) {
            continue;
        }
        bool match = false;
        if (type == ESP_LMAC_KEY_TYPE_PTK && g_lmac.keys[s].key_type == ESP_LMAC_KEY_TYPE_PTK) {
            match = (g_lmac.keys[s].peer_id == peer_id);
        } else if (type == ESP_LMAC_KEY_TYPE_GTK && g_lmac.keys[s].key_type == ESP_LMAC_KEY_TYPE_GTK) {
            match = (g_lmac.keys[s].key_idx == key_idx);
        }
        if (match) {
            if (type == ESP_LMAC_KEY_TYPE_PTK) {
                lmac_peer_t *p = lmac_trc_get_peer(peer_id);
                if (p != NULL && p->ptk_hw_slot == s) {
                    p->ptk_hw_slot = 0xFFU;
                    p->ptk_cipher = (uint8_t)ESP_LMAC_CIPHER_NONE;
                }
            }
            hw_key_clear_slot(s);
        }
    }

    hw_crypto_update_vif_reg(vif);
}

void esp_lmac_key_clear_vif(esp_lmac_vif_t vif)
{
    if (vif >= ESP_LMAC_VIF_MAX) {
        return;
    }

    for (uint8_t s = 2U; s < LMAC_HW_KEY_SLOTS; s++) {
        if (g_lmac.keys[s].in_use && g_lmac.keys[s].vif == vif) {
            if (g_lmac.keys[s].key_type == ESP_LMAC_KEY_TYPE_PTK) {
                lmac_peer_t *p = lmac_trc_get_peer(g_lmac.keys[s].peer_id);
                if (p != NULL && p->ptk_hw_slot == s) {
                    p->ptk_hw_slot = 0xFFU;
                    p->ptk_cipher = (uint8_t)ESP_LMAC_CIPHER_NONE;
                }
            }
            hw_key_clear_slot(s);
        }
    }

    g_lmac.vif[vif].ptk_cipher = (uint8_t)ESP_LMAC_CIPHER_NONE;
    g_lmac.vif[vif].gtk_cipher = (uint8_t)ESP_LMAC_CIPHER_NONE;
    g_lmac.vif[vif].gtk_active_slot = 0U;
    hw_crypto_update_vif_reg(vif);
}

esp_err_t esp_lmac_key_read_slot(uint8_t slot, uint8_t *vif_out, esp_lmac_cipher_t *cipher_out,
                                 uint8_t *key_idx_out, uint8_t addr_out[6],
                                 uint8_t *key_out, uint8_t key_len)
{
    if (slot >= LMAC_HW_KEY_SLOTS) {
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t addr_lo = lmac_reg_read(LMAC_KEY_SLOT_ADDR(slot));
    uint32_t flags = lmac_reg_read(LMAC_KEY_SLOT_FLAGS(slot));

    if (addr_out != NULL) {
        addr_out[0] = (uint8_t)(addr_lo & 0xFFU);
        addr_out[1] = (uint8_t)((addr_lo >> 8) & 0xFFU);
        addr_out[2] = (uint8_t)((addr_lo >> 16) & 0xFFU);
        addr_out[3] = (uint8_t)((addr_lo >> 24) & 0xFFU);
        addr_out[4] = (uint8_t)(flags & 0xFFU);
        addr_out[5] = (uint8_t)((flags >> 8) & 0xFFU);
    }
    if (vif_out != NULL) {
        *vif_out = (uint8_t)((flags >> 24) & 1U);
    }
    if (key_idx_out != NULL) {
        *key_idx_out = (uint8_t)((flags >> 30) & 3U);
    }
    if (cipher_out != NULL) {
        uint8_t alg = (uint8_t)((flags >> 18) & 7U);
        uint8_t sub = (uint8_t)((flags >> 16) & 3U);
        if (alg == LMAC_HW_ALG_CCMP) {
            *cipher_out = ESP_LMAC_CIPHER_CCMP;
        } else if (alg == LMAC_HW_ALG_TKIP) {
            *cipher_out = ESP_LMAC_CIPHER_TKIP;
        } else if (alg == LMAC_HW_ALG_WEP) {
            *cipher_out = (sub == 1U) ? ESP_LMAC_CIPHER_WEP104 : ESP_LMAC_CIPHER_WEP40;
        } else {
            *cipher_out = ESP_LMAC_CIPHER_NONE;
        }
    }
    if (key_out != NULL && key_len > 0U) {
        uint8_t raw[32];
        for (uint8_t w = 0U; w < 8U; w++) {
            uint32_t v = lmac_reg_read(LMAC_KEY_SLOT_DATA(slot, w));
            raw[w * 4U + 0U] = (uint8_t)(v & 0xFFU);
            raw[w * 4U + 1U] = (uint8_t)((v >> 8) & 0xFFU);
            raw[w * 4U + 2U] = (uint8_t)((v >> 16) & 0xFFU);
            raw[w * 4U + 3U] = (uint8_t)((v >> 24) & 0xFFU);
        }
        uint8_t copy_len = (key_len > sizeof(raw)) ? (uint8_t)sizeof(raw) : key_len;
        memcpy(key_out, raw, copy_len);
    }

    return ESP_OK;
}

uint8_t lmac_crypto_lookup_tx_slot(esp_lmac_vif_t vif, esp_lmac_peer_id_t peer_id,
                                   esp_lmac_cipher_t cipher, uint8_t key_idx)
{
    uint8_t slot = 0U;
    if (cipher == ESP_LMAC_CIPHER_NONE || vif >= ESP_LMAC_VIF_MAX) {
        return 0U; /* Bypass */
    }
    if (cipher == ESP_LMAC_CIPHER_WEP40 || cipher == ESP_LMAC_CIPHER_WEP104) {
        uint8_t wslot = (uint8_t)(2U + (key_idx & 3U));
        slot = g_lmac.keys[wslot].in_use ? wslot : 0U;
    } else if (peer_id != ESP_LMAC_PEER_INVALID) {
        lmac_peer_t *p = lmac_trc_get_peer(peer_id);
        if (p != NULL && p->ptk_hw_slot < LMAC_HW_KEY_SLOTS && g_lmac.keys[p->ptk_hw_slot].in_use) {
            slot = p->ptk_hw_slot;
        }
    } else {
        /* Multicast/broadcast GTK lookup */
        uint8_t base = (vif == ESP_LMAC_VIF_STA) ? 2U : 4U;
        for (uint8_t s = base; s < (uint8_t)(base + 2U); s++) {
            if (g_lmac.keys[s].in_use && g_lmac.keys[s].vif == vif && g_lmac.keys[s].key_idx == key_idx) {
                slot = s;
                break;
            }
        }
        if (slot == 0U && g_lmac.vif[vif].gtk_active_slot >= base &&
            g_lmac.vif[vif].gtk_active_slot < (uint8_t)(base + 2U) &&
            g_lmac.keys[g_lmac.vif[vif].gtk_active_slot].in_use) {
            slot = g_lmac.vif[vif].gtk_active_slot;
        }
    }
    /* Match vendor ieee80211_output.o: set bit 7 (0x80) on SoftAP encrypted TX slot */
    if (slot != 0U && vif == ESP_LMAC_VIF_AP) {
        slot |= LMAC_KEY_SLOT_AP_BIT;
    }
    return slot;
}

/* --------------------------------------------------------------------------
 * WDEV Hardware Initialization & Master Enable
 * -------------------------------------------------------------------------- */

void lmac_wdev_update_mac_enable(void)
{
    bool any_active = (g_lmac.vif[ESP_LMAC_VIF_STA].enabled != 0U) ||
                      (g_lmac.vif[ESP_LMAC_VIF_AP].enabled != 0U) ||
                      (g_lmac.sniffer_mode != 0U);
    if (any_active && !g_lmac.rf_closed) {
        lmac_reg_set(LMAC_WDEV_MAC_ENABLE, LMAC_WDEV_MAC_ENABLE_BIT);
    } else {
        lmac_reg_clr(LMAC_WDEV_MAC_ENABLE, LMAC_WDEV_MAC_ENABLE_BIT);
    }
}

void lmac_wdev_hw_init(void)
{
    /* Cross-checked against wDev_Initialize + wDev_Option_Init (wdev.o.c) */
    lmac_reg_write(LMAC_WDEV_INT_ENA, 0U);
    lmac_reg_write(LMAC_WDEV_INT_CLR, 0xFFFFFFFFU);

    /* wDev_Option_Init: bit 18 (0x40000) enables protected frame RX decryption */
    lmac_reg_write(LMAC_WDEV_RX_OPTION,
                   (lmac_reg_read(LMAC_WDEV_RX_OPTION) & 0xFFDFBFF7U) | 0x8084A000U);
    lmac_reg_set(LMAC_WDEV_RXTX_OPTION, 0x00000008U);
    lmac_reg_set(LMAC_WDEV_TX_OPTION, 0x00000003U);
    lmac_reg_clr(LMAC_WDEV_PHY_CONF, 0x000000F0U);

    uint32_t sc0 = lmac_reg_read(LMAC_WDEV_SLOT_CONF0);
    sc0 = ((((sc0 >> 16) + 0x12U) & 0xFFU) << 16) | (sc0 & 0xFF00FFFFU);
    lmac_reg_write(LMAC_WDEV_SLOT_CONF0, sc0);
    lmac_reg_write(LMAC_WDEV_SLOT_CONF1, (lmac_reg_read(LMAC_WDEV_SLOT_CONF1) & 0xFFFF0000U) | 0x1616U);
    lmac_reg_write(LMAC_WDEV_NAV_CONF, (lmac_reg_read(LMAC_WDEV_NAV_CONF) & 0xFFFFF000U) | 0xC00000F0U);

    /* Hardware crypto bypass & clean 25-slot key table */
    lmac_reg_write(LMAC_WDEV_CRYPTO_CONF0, LMAC_CRYPTO_BYPASS);
    lmac_reg_write(LMAC_WDEV_CRYPTO_CONF1, LMAC_CRYPTO_BYPASS);
    lmac_reg_write(LMAC_WDEV_KEY_VALID_MASK, 0U);
    for (uint8_t s = 0U; s < LMAC_HW_KEY_SLOTS; s++) {
        hw_key_clear_slot(s);
    }
    /* Vendor wDev_Initialize installs broadcast placeholder entries in slots 0 & 1 */
    hw_key_write_slot(0U, 0U, LMAC_HW_ALG_CCMP, 0U, LMAC_HW_KEY_CLASS_GTK, 0U, s_bcast_mac, s_bcast_mac, 6U);
    hw_key_write_slot(1U, 1U, LMAC_HW_ALG_CCMP, 0U, LMAC_HW_KEY_CLASS_GTK, 0U, s_bcast_mac, s_bcast_mac, 6U);
    lmac_reg_write(LMAC_WDEV_CRYPTO_WAPI, 0U);

    /* Program RX DMA ring & bounds */
    lmac_dma_reprogram_regs();

    /* Auto-ACK / CTS rate response LUTs */
    lmac_reg_write(LMAC_WDEV_ACK_RATE_TAB0, 0x76503210U);
    lmac_reg_write(LMAC_WDEV_ACK_RATE_TAB1, 0xBBBBBBBBU);
    lmac_reg_write(LMAC_WDEV_ACK_RATE_TAB2, 0xBBBBBBBBU);

    /* RX filter control & clear both BSSID filters */
    lmac_reg_write(LMAC_WDEV_RX_FILTER_CTRL,
                   (lmac_reg_read(LMAC_WDEV_RX_FILTER_CTRL) & 0xFFFFEFEFU) | 0x0707U);
    lmac_reg_clr(LMAC_WDEV_BSSID_MASK_HI(0U), LMAC_WDEV_MATCH_ENABLE);
    lmac_reg_clr(LMAC_WDEV_BSSID_MASK_HI(1U), LMAC_WDEV_MATCH_ENABLE);
    lmac_reg_clr(LMAC_WDEV_MAC_MASK_HI(0U), LMAC_WDEV_MATCH_ENABLE);
    lmac_reg_clr(LMAC_WDEV_MAC_MASK_HI(1U), LMAC_WDEV_MATCH_ENABLE);

    /* Enable WDEV NMI mask and Level-3 NMI bridge */
    vPortETSIntrLock();
    WDEV_INTEREST_EVENT = LMAC_WDEV_INTEREST_DEFAULT;
    lmac_reg_write(LMAC_WDEV_INT_ENA, WDEV_INTEREST_EVENT);
    vPortETSIntrUnlock();

    lmac_reg_set(LMAC_WDEV_RX_CTRL2, 0x00000002U);
    lmac_reg_clr(LMAC_WDEV_MAC_ENABLE, LMAC_WDEV_MAC_ENABLE_BIT);
    lmac_reg_write(LMAC_DPORT_NMI_INT_ENA, 1U);
}

/* --------------------------------------------------------------------------
 * Dual Virtual Interfaces (STA=0, SoftAP=1) & BSSID / Scan Filter
 * -------------------------------------------------------------------------- */

esp_err_t esp_lmac_vif_enable(esp_lmac_vif_t vif, const uint8_t mac[6])
{
    if (vif >= ESP_LMAC_VIF_MAX || mac == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memcpy(g_lmac.vif[vif].mac, mac, 6U);
    g_lmac.vif[vif].enabled = 1U;
    if (g_lmac.vif[vif].proto_mask == 0U) {
        g_lmac.vif[vif].proto_mask = WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N;
    }

    if (g_lmac.sniffer_mode == 0U) {
        lmac_reg_write(LMAC_WDEV_MAC_LO(vif), read_le32(mac));
        lmac_reg_write(LMAC_WDEV_MAC_HI(vif), (uint32_t)read_le16(mac + 4));
        lmac_reg_write(LMAC_WDEV_MAC_MASK_LO(vif), 0xFFFFFFFFU);
        lmac_reg_write(LMAC_WDEV_MAC_MASK_HI(vif), 0x0000FFFFU | LMAC_WDEV_MATCH_ENABLE);
    }

    lmac_wdev_update_mac_enable();
    return ESP_OK;
}

void esp_lmac_vif_disable(esp_lmac_vif_t vif)
{
    if (vif >= ESP_LMAC_VIF_MAX) {
        return;
    }

    esp_lmac_tx_flush_vif(vif);
    lmac_rx_ba_clear_vif(vif);
    esp_lmac_key_clear_vif(vif);
    if (vif == ESP_LMAC_VIF_AP) {
        esp_lmac_stop_beacon(vif);
    }

    g_lmac.vif[vif].enabled = 0U;
    g_lmac.vif[vif].bssid_enabled = 0U;

    if (g_lmac.sniffer_mode == 0U) {
        lmac_reg_clr(LMAC_WDEV_MAC_MASK_HI(vif), LMAC_WDEV_MATCH_ENABLE);
        lmac_reg_clr(LMAC_WDEV_BSSID_MASK_HI(vif), LMAC_WDEV_MATCH_ENABLE);
    }

    lmac_wdev_update_mac_enable();
}

static void hw_apply_bssid_filter(esp_lmac_vif_t vif)
{
    if (g_lmac.sniffer_mode != 0U) {
        return;
    }
    if (vif == ESP_LMAC_VIF_STA && g_lmac.scan_mode != 0U) {
        /*
         * Disable VIF0 BSSID filter and set RX_FILTER_CTRL bit 4 (0x10) so HW
         * admits beacons/probe-responses without flooding RX DMA with neighbor
         * AP data frames (matching vendor wDev_SetRxPolicy(0, 0, 0) + scan bit).
         */
        lmac_reg_clr(LMAC_WDEV_BSSID_MASK_HI(ESP_LMAC_VIF_STA), LMAC_WDEV_MATCH_ENABLE);
        lmac_reg_set(LMAC_WDEV_RX_FILTER_CTRL, 0x10U);
        return;
    }

    if (g_lmac.vif[vif].bssid_enabled) {
        const uint8_t *bssid = g_lmac.vif[vif].bssid;
        lmac_reg_clr(LMAC_WDEV_BSSID_MASK_HI(vif), LMAC_WDEV_MATCH_ENABLE);
        lmac_reg_write(LMAC_WDEV_BSSID_LO(vif), read_le32(bssid));
        lmac_reg_write(LMAC_WDEV_BSSID_HI(vif), (uint32_t)read_le16(bssid + 4));
        lmac_reg_write(LMAC_WDEV_BSSID_MASK_LO(vif), 0xFFFFFFFFU);
        lmac_reg_write(LMAC_WDEV_BSSID_MASK_HI(vif), 0x0000FFFFU | LMAC_WDEV_MATCH_ENABLE);
    } else {
        lmac_reg_clr(LMAC_WDEV_BSSID_MASK_HI(vif), LMAC_WDEV_MATCH_ENABLE);
    }
}

void esp_lmac_set_bssid_filter(esp_lmac_vif_t vif, const uint8_t bssid[6], bool enable)
{
    if (vif >= ESP_LMAC_VIF_MAX) {
        return;
    }

    if (enable && bssid != NULL) {
        memcpy(g_lmac.vif[vif].bssid, bssid, 6U);
        g_lmac.vif[vif].bssid_enabled = 1U;
    } else {
        g_lmac.vif[vif].bssid_enabled = 0U;
    }

    hw_apply_bssid_filter(vif);
}

void esp_lmac_set_scan_rx_mode(bool scanning)
{
    g_lmac.scan_mode = scanning ? 1U : 0U;
    if (!scanning && g_lmac.sniffer_mode == 0U) {
        lmac_reg_clr(LMAC_WDEV_RX_FILTER_CTRL, 0x10U);
    }
    hw_apply_bssid_filter(ESP_LMAC_VIF_STA);
}

/* --------------------------------------------------------------------------
 * SoftAP Beacon Template & TSF1 / TBTT Engine
 * -------------------------------------------------------------------------- */

esp_err_t esp_lmac_set_beacon(esp_lmac_vif_t vif, const uint8_t *frame, uint16_t len,
                              uint16_t tim_ie_offset, uint16_t beacon_interval_tu)
{
    if (vif != ESP_LMAC_VIF_AP || frame == NULL || len < 36U || len > 512U) {
        return ESP_ERR_INVALID_ARG;
    }
    if (beacon_interval_tu < 10U) {
        beacon_interval_tu = 100U;
    }

    uint16_t alloc_len = (uint16_t)(len + 4U); /* Include 4-B hardware FCS space */
    uint8_t *new_buf = (uint8_t *)heap_caps_malloc(alloc_len, MALLOC_CAP_8BIT);
    if (new_buf == NULL) {
        return ESP_ERR_NO_MEM;
    }
    memcpy(new_buf, frame, len);
    memset(new_buf + len, 0, 4U);

    bool was_active = (g_lmac.beacon.active != 0U);
    if (g_lmac.beacon.tx_pending) {
        esp_lmac_tx_flush_vif(ESP_LMAC_VIF_AP);
    }
    if (g_lmac.beacon.buf != NULL) {
        heap_caps_free(g_lmac.beacon.buf);
    }

    g_lmac.beacon.buf = new_buf;
    g_lmac.beacon.len = len;
    g_lmac.beacon.tim_ie_offset = tim_ie_offset;
    g_lmac.beacon.interval_us = (uint32_t)beacon_interval_tu * 1024U;
    g_lmac.beacon.active = 1U;
    g_lmac.beacon.tx_pending = 0U;

    if (!was_active) {
        /* Reset and enable TSF1 + MAC Timer 1 (cross-checked: wDev_Reset_TBTT) */
        lmac_reg_clr(LMAC_WDEV_TSF1_CONF, 0xC4000000U);
        lmac_reg_write(LMAC_WDEV_TBTT1_LO, 0U);
        lmac_reg_write(LMAC_WDEV_TBTT1_HI, 0U);
        lmac_reg_set(LMAC_WDEV_TSF1_CONF, 0xC4000000U);

        g_lmac.beacon.next_tbtt_lo = lmac_reg_read(LMAC_WDEV_TSF1_LO) + g_lmac.beacon.interval_us;
        lmac_mactim1_arm(g_lmac.beacon.interval_us);
    }

    return ESP_OK;
}

void esp_lmac_stop_beacon(esp_lmac_vif_t vif)
{
    if (vif != ESP_LMAC_VIF_AP) {
        return;
    }

    lmac_mactim1_disarm();
    lmac_reg_clr(LMAC_WDEV_TSF1_CONF, 0xC4000000U);

    if (g_lmac.beacon.tx_pending) {
        esp_lmac_tx_flush_vif(ESP_LMAC_VIF_AP);
    }
    g_lmac.beacon.active = 0U;
    g_lmac.beacon.tx_pending = 0U;
    g_lmac.beacon.len = 0U;
    if (g_lmac.beacon.buf != NULL) {
        heap_caps_free(g_lmac.beacon.buf);
        g_lmac.beacon.buf = NULL;
    }
}

void lmac_beacon_on_tbtt_evt(void)
{
    if (!g_lmac.beacon.active || g_lmac.beacon.buf == NULL) {
        return;
    }

    g_lmac.stats.tbtt_count++;

    /* Let net80211 update TIM IE or handle DTIM flush before HW launch */
    if (g_lmac.cbs.on_tbtt != NULL) {
        g_lmac.cbs.on_tbtt(g_lmac.cbs.ctx, ESP_LMAC_VIF_AP);
    }

    if (g_lmac.beacon.active && !g_lmac.rf_closed && g_lmac.sniffer_mode == 0U && g_lmac.scan_mode == 0U) {
        /* Stamp current 64-bit TSF1 timestamp into beacon body bytes [24..31] */
        uint64_t tsf = esp_lmac_get_tsf_us(ESP_LMAC_VIF_AP);
        memcpy(g_lmac.beacon.buf + 24U, &tsf, 8U);
        lmac_tx_launch_beacon_now();
    }

    /* Re-arm MAC Timer 1 for next TBTT with drift compensation */
    if (g_lmac.beacon.active) {
        uint32_t now_lo = lmac_reg_read(LMAC_WDEV_TSF1_LO);
        uint32_t delta = g_lmac.beacon.interval_us;
        g_lmac.beacon.next_tbtt_lo += g_lmac.beacon.interval_us;
        int32_t rem = (int32_t)(g_lmac.beacon.next_tbtt_lo - now_lo);
        if (rem > 2000 && (uint32_t)rem <= (g_lmac.beacon.interval_us * 2U)) {
            delta = (uint32_t)rem;
        } else {
            g_lmac.beacon.next_tbtt_lo = now_lo + g_lmac.beacon.interval_us;
        }
        lmac_mactim1_arm(delta);
    }
}

/* --------------------------------------------------------------------------
 * Promiscuous / Sniffer Mode (Fixes Vendor Bit-18 Exit Bug, Non-Blocking)
 * -------------------------------------------------------------------------- */

esp_err_t esp_lmac_sniffer_enable(uint32_t filter_mask, uint32_t ctrl_filter_mask)
{
    g_lmac.sniffer_filter = (filter_mask == 0U) ? WIFI_PROMIS_FILTER_MASK_ALL : filter_mask;
    g_lmac.sniffer_ctrl_filter = ctrl_filter_mask;

    if (g_lmac.sniffer_mode != 0U) {
        return ESP_OK;
    }

    if (g_lmac.snf_ring == NULL) {
        lmac_snf_pkt_t *ring = (lmac_snf_pkt_t *)heap_caps_zalloc(
            LMAC_SNF_RING_SIZE * sizeof(lmac_snf_pkt_t), MALLOC_CAP_8BIT);
        if (ring == NULL) {
            return ESP_ERR_NO_MEM;
        }
        g_lmac.snf_wr = 0U;
        g_lmac.snf_rd = 0U;
        __asm__ volatile("memw" ::: "memory");
        g_lmac.snf_ring = ring;
    }

    g_lmac.sniffer_mode = 1U;

    /* Ensure RX option bit 18 stays set and bypass hardware crypto into raw sniffer capture */
    lmac_reg_set(LMAC_WDEV_RX_OPTION, 0x00040000U);
    lmac_reg_write(LMAC_WDEV_CRYPTO_CONF0,
                   (lmac_reg_read(LMAC_WDEV_CRYPTO_CONF0) & ~LMAC_CRYPTO_ENG_EN) | LMAC_CRYPTO_SNIFFER_RAW);
    lmac_reg_write(LMAC_WDEV_CRYPTO_CONF1,
                   (lmac_reg_read(LMAC_WDEV_CRYPTO_CONF1) & ~LMAC_CRYPTO_ENG_EN) | LMAC_CRYPTO_SNIFFER_RAW);

    /* Open MAC & BSSID address masks and RX filter so all over-the-air frames enter RX DMA */
    lmac_reg_clr(LMAC_WDEV_RX_FILTER_CTRL, 0x00000007U);
    lmac_reg_write(LMAC_WDEV_MAC_MASK_LO(0U), 0U);
    lmac_reg_write(LMAC_WDEV_MAC_MASK_HI(0U), LMAC_WDEV_MATCH_ENABLE);
    lmac_reg_write(LMAC_WDEV_BSSID_MASK_LO(0U), 0U);
    lmac_reg_write(LMAC_WDEV_BSSID_MASK_HI(0U), LMAC_WDEV_MATCH_ENABLE);

    vPortETSIntrLock();
    WDEV_INTEREST_EVENT |= LMAC_WDEV_INTEREST_SNIFFER;
    lmac_reg_write(LMAC_WDEV_INT_ENA, WDEV_INTEREST_EVENT);
    vPortETSIntrUnlock();

    /* Clear baseband sniffer filter bits [29,26] and disable auto-ACK in sniffer */
    lmac_reg_clr(LMAC_BB_RX_SNIFFER_FILT, LMAC_BB_RX_SNIFFER_MASK);
    vTaskDelay(pdMS_TO_TICKS(15U));
    lmac_reg_clr(LMAC_WDEV_TX_OPTION, 0x00000001U);

    lmac_wdev_update_mac_enable();
    return ESP_OK;
}

void esp_lmac_sniffer_disable(void)
{
    if (g_lmac.sniffer_mode == 0U) {
        return;
    }

    lmac_reg_set(LMAC_WDEV_TX_OPTION, 0x00000001U);
    lmac_reg_set(LMAC_BB_RX_SNIFFER_FILT, LMAC_BB_RX_SNIFFER_MASK);

    vPortETSIntrLock();
    WDEV_INTEREST_EVENT &= ~LMAC_WDEV_INTEREST_SNIFFER;
    lmac_reg_write(LMAC_WDEV_INT_ENA, WDEV_INTEREST_EVENT);
    vPortETSIntrUnlock();

    g_lmac.sniffer_mode = 0U;
    __asm__ volatile("memw" ::: "memory");
    while (NMIIrqIsOn != 0U) {
    }
    lmac_snf_pkt_t *old_ring = g_lmac.snf_ring;
    g_lmac.snf_ring = NULL;
    g_lmac.snf_wr = 0U;
    g_lmac.snf_rd = 0U;
    __asm__ volatile("memw" ::: "memory");
    if (old_ring != NULL) {
        heap_caps_free(old_ring);
    }

    /* Restore MAC0/BSSID0 filters & normal RX filter control */
    lmac_reg_set(LMAC_WDEV_RX_FILTER_CTRL, 0x00000707U);
    if (g_lmac.vif[ESP_LMAC_VIF_STA].enabled) {
        const uint8_t *mac = g_lmac.vif[ESP_LMAC_VIF_STA].mac;
        lmac_reg_write(LMAC_WDEV_MAC_LO(0U), read_le32(mac));
        lmac_reg_write(LMAC_WDEV_MAC_HI(0U), (uint32_t)read_le16(mac + 4));
        lmac_reg_write(LMAC_WDEV_MAC_MASK_LO(0U), 0xFFFFFFFFU);
        lmac_reg_write(LMAC_WDEV_MAC_MASK_HI(0U), 0x0000FFFFU | LMAC_WDEV_MATCH_ENABLE);
    } else {
        lmac_reg_write(LMAC_WDEV_MAC_MASK_LO(0U), 0xFFFFFFFFU);
        lmac_reg_write(LMAC_WDEV_MAC_MASK_HI(0U), 0x0000FFFFU);
    }
    hw_apply_bssid_filter(ESP_LMAC_VIF_STA);

    /* Restore crypto engine registers cleanly while KEEPING RX_OPTION bit 18 ON */
    lmac_reg_write(LMAC_WDEV_CRYPTO_CONF0,
                   (lmac_reg_read(LMAC_WDEV_CRYPTO_CONF0) & ~LMAC_CRYPTO_SNIFFER_RAW) | LMAC_CRYPTO_ENG_EN);
    lmac_reg_write(LMAC_WDEV_CRYPTO_CONF1,
                   (lmac_reg_read(LMAC_WDEV_CRYPTO_CONF1) & ~LMAC_CRYPTO_SNIFFER_RAW) | LMAC_CRYPTO_ENG_EN);
    hw_crypto_update_vif_reg(ESP_LMAC_VIF_STA);
    hw_crypto_update_vif_reg(ESP_LMAC_VIF_AP);
    lmac_reg_set(LMAC_WDEV_RX_OPTION, 0x00040000U);

    lmac_wdev_update_mac_enable();
}

void esp_lmac_sniffer_set_filter(uint32_t filter_mask, uint32_t ctrl_filter_mask)
{
    g_lmac.sniffer_filter = filter_mask;
    g_lmac.sniffer_ctrl_filter = ctrl_filter_mask;
}

void esp_lmac_sniffer_get_filter(uint32_t *filter_mask, uint32_t *ctrl_filter_mask)
{
    if (filter_mask != NULL) {
        *filter_mask = g_lmac.sniffer_filter;
    }
    if (ctrl_filter_mask != NULL) {
        *ctrl_filter_mask = g_lmac.sniffer_ctrl_filter;
    }
}

/* --------------------------------------------------------------------------
 * Hardware RX Block-Ack Scoreboards (0..3, max 4 sessions, Gated by AMPDU_RX)
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
static void lmac_rx_ba_clear_slot(uint8_t slot)
{
    lmac_reg_write(LMAC_WDEV_RXBA_ADDR_LO(slot), 0U);
    lmac_reg_write(LMAC_WDEV_RXBA_ADDR_HI(slot), 0U);
    lmac_reg_write(LMAC_WDEV_RXBA_SSN_WIN(slot), 0U);
    lmac_reg_write(LMAC_WDEV_RXBA_CONF(slot), 0U);
    g_lmac.rx_ba_used_mask &= (uint8_t)~(1U << slot);
    g_lmac.rx_ba_vif_mask &= (uint8_t)~(1U << slot);
}
#endif

/**
 * @brief Return true if a hardware RX BA scoreboard slot is available or already assigned to (peer_id, tid).
 *
 * @param peer_id LMAC peer identifier.
 * @param tid     802.11 Traffic Identifier (0..7).
 * @return true when esp_lmac_add_rx_ba() can accept the session.
 */
bool esp_lmac_can_add_rx_ba(esp_lmac_peer_id_t peer_id, uint8_t tid)
{
#ifdef CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
    lmac_peer_t *p = lmac_trc_get_peer(peer_id);
    if (g_lmac.cfg.ampdu_rx_enable == 0U || p == NULL || tid >= 8U) {
        return false;
    }
    uint32_t addr_lo = read_le32(p->mac);
    uint32_t addr_hi = (uint32_t)read_le16(p->mac + 4);
    for (uint8_t i = 0U; i < LMAC_RXBA_MAX_SESSIONS; i++) {
        if ((g_lmac.rx_ba_used_mask & (1U << i)) == 0U) {
            return true;
        }
        uint32_t conf = lmac_reg_read(LMAC_WDEV_RXBA_CONF(i));
        if (((conf >> 12) & 0x0FU) == tid &&
            lmac_reg_read(LMAC_WDEV_RXBA_ADDR_LO(i)) == addr_lo &&
            (lmac_reg_read(LMAC_WDEV_RXBA_ADDR_HI(i)) & 0xFFFFU) == addr_hi) {
            return true;
        }
    }
    return false;
#else
    (void)peer_id;
    (void)tid;
    return false;
#endif
}

esp_err_t esp_lmac_add_rx_ba(esp_lmac_peer_id_t peer_id, uint8_t tid, uint16_t ssn, uint8_t win_size)
{
#ifdef CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
    lmac_peer_t *p = lmac_trc_get_peer(peer_id);
    if (g_lmac.cfg.ampdu_rx_enable == 0U) {
        return ESP_ERR_NOT_SUPPORTED;
    }
    if (p == NULL || tid >= 8U || win_size == 0U || win_size > 64U) {
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t addr_lo = read_le32(p->mac);
    uint32_t addr_hi = (uint32_t)read_le16(p->mac + 4);
    uint8_t slot = 0xFFU;

    /* Deduplicate existing (peer, tid) session before claiming a new scoreboard slot */
    for (uint8_t i = 0U; i < LMAC_RXBA_MAX_SESSIONS; i++) {
        if ((g_lmac.rx_ba_used_mask & (1U << i)) != 0U) {
            uint32_t conf = lmac_reg_read(LMAC_WDEV_RXBA_CONF(i));
            if (((conf >> 12) & 0x0FU) == tid &&
                lmac_reg_read(LMAC_WDEV_RXBA_ADDR_LO(i)) == addr_lo &&
                (lmac_reg_read(LMAC_WDEV_RXBA_ADDR_HI(i)) & 0xFFFFU) == addr_hi) {
                slot = i;
                break;
            }
        } else if (slot == 0xFFU) {
            slot = i;
        }
    }
    if (slot == 0xFFU) {
        return ESP_ERR_NO_MEM;
    }

    /* Exact wDev_AddRXBA register layout (wdev.o.c:2451-2466) */
    lmac_reg_write(LMAC_WDEV_RXBA_ADDR_LO(slot), addr_lo);
    lmac_reg_write(LMAC_WDEV_RXBA_ADDR_HI(slot), addr_hi);
    lmac_reg_write(LMAC_WDEV_RXBA_SSN_WIN(slot),
                   (((uint32_t)win_size & 0x7FU) << 13) | ((uint32_t)ssn & 0xFFFU));
    lmac_reg_write(LMAC_WDEV_RXBA_CONF(slot),
                   (((uint32_t)tid & 0x0FU) << 12) | 0xC0000005U);
    g_lmac.rx_ba_used_mask |= (uint8_t)(1U << slot);
    if (p->vif == ESP_LMAC_VIF_AP) {
        g_lmac.rx_ba_vif_mask |= (uint8_t)(1U << slot);
    } else {
        g_lmac.rx_ba_vif_mask &= (uint8_t)~(1U << slot);
    }
    return ESP_OK;
#else
    (void)peer_id;
    (void)tid;
    (void)ssn;
    (void)win_size;
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

void esp_lmac_del_rx_ba(esp_lmac_peer_id_t peer_id, uint8_t tid)
{
#ifdef CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
    lmac_peer_t *p = lmac_trc_get_peer(peer_id);
    if (p == NULL || tid >= 8U) {
        return;
    }

    uint32_t addr_lo = read_le32(p->mac);
    uint32_t addr_hi = (uint32_t)read_le16(p->mac + 4);

    for (uint8_t i = 0U; i < LMAC_RXBA_MAX_SESSIONS; i++) {
        if ((g_lmac.rx_ba_used_mask & (1U << i)) == 0U) {
            continue;
        }
        uint32_t conf = lmac_reg_read(LMAC_WDEV_RXBA_CONF(i));
        if (((conf >> 12) & 0x0FU) == tid &&
            lmac_reg_read(LMAC_WDEV_RXBA_ADDR_LO(i)) == addr_lo &&
            (lmac_reg_read(LMAC_WDEV_RXBA_ADDR_HI(i)) & 0xFFFFU) == addr_hi) {
            lmac_rx_ba_clear_slot(i);
            break;
        }
    }
#else
    (void)peer_id;
    (void)tid;
#endif
}

/**
 * @brief Clear all hardware RX BA scoreboard slots belonging to a peer MAC address.
 *
 * @param mac Peer 6-byte MAC address.
 */
void lmac_rx_ba_clear_peer(const uint8_t mac[6])
{
#ifdef CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
    if (mac == NULL) {
        return;
    }
    uint32_t addr_lo = read_le32(mac);
    uint32_t addr_hi = (uint32_t)read_le16(mac + 4);

    for (uint8_t i = 0U; i < LMAC_RXBA_MAX_SESSIONS; i++) {
        if ((g_lmac.rx_ba_used_mask & (1U << i)) != 0U &&
            lmac_reg_read(LMAC_WDEV_RXBA_ADDR_LO(i)) == addr_lo &&
            (lmac_reg_read(LMAC_WDEV_RXBA_ADDR_HI(i)) & 0xFFFFU) == addr_hi) {
            lmac_rx_ba_clear_slot(i);
        }
    }
#else
    (void)mac;
#endif
}

/**
 * @brief Clear all hardware RX BA scoreboard slots owned by a virtual interface.
 *
 * @param vif Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 */
void lmac_rx_ba_clear_vif(esp_lmac_vif_t vif)
{
#ifdef CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
    uint8_t want_ap = (vif == ESP_LMAC_VIF_AP) ? 1U : 0U;
    for (uint8_t i = 0U; i < LMAC_RXBA_MAX_SESSIONS; i++) {
        if ((g_lmac.rx_ba_used_mask & (1U << i)) != 0U &&
            (((g_lmac.rx_ba_vif_mask >> i) & 1U) == want_ap)) {
            lmac_rx_ba_clear_slot(i);
        }
    }
#else
    (void)vif;
#endif
}

/* --------------------------------------------------------------------------
 * 5-Bank Hardware MAC Soft Reset (Cross-Checked: wdev_hw_mac_reset)
 * -------------------------------------------------------------------------- */

static void reg_save_bank(uint32_t *dst, uint32_t base, uint32_t words)
{
    for (uint32_t i = 0U; i < words; i++) {
        dst[i] = lmac_reg_read(base + i * 4U);
    }
}

static void reg_restore_bank(uint32_t base, const uint32_t *src, uint32_t words)
{
    for (uint32_t i = 0U; i < words; i++) {
        lmac_reg_write(base + i * 4U, src[i]);
    }
}

void esp_lmac_hw_mac_reset(void)
{
    const uint32_t total_words = LMAC_WDEV_BANK0_WORDS + LMAC_WDEV_BANK1_WORDS +
                                 LMAC_WDEV_BANK2_WORDS + LMAC_WDEV_BANK3_WORDS +
                                 LMAC_WDEV_BANK4_WORDS;
    uint32_t *save = (uint32_t *)heap_caps_malloc(total_words * sizeof(uint32_t), MALLOC_CAP_8BIT);
    if (save == NULL) {
        ESP_LOGW(TAG, "hw_mac_reset: OOM");
        return;
    }

    uint32_t ba_ssn[8];
    uint32_t *b0 = save;
    uint32_t *b1 = b0 + LMAC_WDEV_BANK0_WORDS;
    uint32_t *b2 = b1 + LMAC_WDEV_BANK1_WORDS;
    uint32_t *b3 = b2 + LMAC_WDEV_BANK2_WORDS;
    uint32_t *b4 = b3 + LMAC_WDEV_BANK3_WORDS;

    vPortETSIntrLock();
    lmac_reg_clr(LMAC_WDEV_MAC_ENABLE, LMAC_WDEV_MAC_ENABLE_BIT);

    reg_save_bank(b0, LMAC_WDEV_BANK0_BASE, LMAC_WDEV_BANK0_WORDS);
    reg_save_bank(b1, LMAC_WDEV_BANK1_BASE, LMAC_WDEV_BANK1_WORDS);
    reg_save_bank(b2, LMAC_WDEV_BANK2_BASE, LMAC_WDEV_BANK2_WORDS);
    reg_save_bank(b3, LMAC_WDEV_BANK3_BASE, LMAC_WDEV_BANK3_WORDS);
    reg_save_bank(b4, LMAC_WDEV_BANK4_BASE, LMAC_WDEV_BANK4_WORDS);
    for (uint8_t i = 0U; i < 8U; i++) {
        ba_ssn[i] = lmac_reg_read(LMAC_WDEV_RXBA_SSN_WIN(i)) >> 20;
    }

    /* Pulse MAC hardware reset */
    lmac_reg_clr(LMAC_RTC_MAC_RESET_CTRL, 0x00000002U);
    lmac_reg_set(LMAC_WDEV_PHY_CTRL, 0x000000F0U);

    reg_restore_bank(LMAC_WDEV_BANK0_BASE, b0, LMAC_WDEV_BANK0_WORDS);
    reg_restore_bank(LMAC_WDEV_BANK1_BASE, b1, LMAC_WDEV_BANK1_WORDS);
    reg_restore_bank(LMAC_WDEV_BANK2_BASE, b2, LMAC_WDEV_BANK2_WORDS);
    reg_restore_bank(LMAC_WDEV_BANK3_BASE, b3, LMAC_WDEV_BANK3_WORDS);
    reg_restore_bank(LMAC_WDEV_BANK4_BASE, b4, LMAC_WDEV_BANK4_WORDS);
    for (uint8_t i = 0U; i < 8U; i++) {
        uint32_t cur = lmac_reg_read(LMAC_WDEV_RXBA_SSN_WIN(i));
        lmac_reg_write(LMAC_WDEV_RXBA_SSN_WIN(i), (cur & 0xFFFFF000U) | (ba_ssn[i] & 0xFFFU));
    }

    lmac_reg_write(LMAC_WDEV_TX_CLR, 0U);
    lmac_reg_write(LMAC_WDEV_RX_CTRL2, 0x00000002U);
    lmac_reg_clr(LMAC_WDEV_PHY_CTRL, 0x000000F0U);

    lmac_dma_reprogram_regs();
    lmac_wdev_update_mac_enable();
    g_lmac.stats.mac_resets++;

    vPortETSIntrUnlock();

    heap_caps_free(save);
}
