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

/* --------------------------------------------------------------------------
 * File-Local Hardware & Protocol Constants
 * -------------------------------------------------------------------------- */

#define LMAC_MAC_ADDR_LEN               6U
#define LMAC_IEEE80211_HDR_FC1_OFF      1U  /* 802.11 Frame Control byte 1 offset (Protected bit) */
#define LMAC_SW_PROT_BYPASS_NONE        0U  /* No opposite-VIF CRYPTO_CONF TX_ENC bypass active */

/* 25-slot hardware key table helpers & FLAGS bitfield masks */
#define LMAC_KEY_SLOT_BYPASS            0U  /* TXQ_RATE key slot 0 = hardware crypto bypass */
#define LMAC_KEY_SLOT_FIRST_USER        LMAC_KEY_SLOT_STA_GTK_BASE
#define LMAC_KEY_SLOT_STA_GTK_ALT       (LMAC_KEY_SLOT_STA_GTK_BASE + 1U)
#define LMAC_KEY_GTK_SLOTS_PER_VIF      2U
#define LMAC_KEY_SLOT_DATA_BYTES        (LMAC_KEY_SLOT_DATA_WORDS * 4U)
#define LMAC_KEY_IDX_MAX                3U
#define LMAC_KEY_IDX_MASK               3U
#define LMAC_KEY_FLAGS_SUBALG_MASK      3U
#define LMAC_KEY_FLAGS_ALG_MASK         7U
#define LMAC_KEY_FLAGS_CLASS_MASK       7U
#define LMAC_KEY_FLAGS_VIF_MASK         1U
#define LMAC_HW_SUBALG_WEP40            0U
#define LMAC_HW_SUBALG_WEP104           1U

/* WDEV initialization, interrupt clear, and 48-bit MAC/BSSID exact-match masks */
#define LMAC_WDEV_INT_CLR_ALL           0xFFFFFFFFU
#define LMAC_DPORT_NMI_ENABLE_BIT       1U
#define LMAC_ADDR_MASK_LO_EXACT         0xFFFFFFFFU
#define LMAC_ADDR_MASK_HI_EXACT         0x0000FFFFU

/*
 * Vendor wDev_Option_Init hardware slot/SIFS/NAV timing calibration constants.
 * Cross-checked against ESP8266 RTOS SDK wdev.o; exact silicon bitfield
 * sub-definitions inside SLOT_CONF0/SLOT_CONF1/NAV_CONF are undocumented
 * beyond preserving these verified masks and values.
 */
#define LMAC_SLOT_CONF0_FIELD_SHIFT     16U
#define LMAC_SLOT_CONF0_FIELD_MASK      0xFFU
#define LMAC_SLOT_CONF0_FIELD_CLEAR     0xFF00FFFFU
#define LMAC_SLOT_CONF0_DELTA           0x12U       /* +18 offset to SLOT_CONF0[23:16] */
#define LMAC_SLOT_CONF1_KEEP_MASK       0xFFFF0000U
#define LMAC_SLOT_CONF1_INIT_VAL        0x1616U     /* Slot/SIFS timing pair in [15:0] */
#define LMAC_NAV_CONF_KEEP_MASK         0xFFFFF000U
#define LMAC_NAV_CONF_INIT_VAL          0xC00000F0U /* NAV enable/limit bits */

/* SoftAP beacon template & TBTT scheduling limits */
#define LMAC_BEACON_MIN_LEN             36U         /* 24-B 802.11 mgmt hdr + 12-B fixed fields */
#define LMAC_BEACON_MAX_LEN             512U
#define LMAC_BEACON_MIN_INTERVAL_TU     10U
#define LMAC_BEACON_DEF_INTERVAL_TU     100U
#define LMAC_BEACON_TSF_OFFSET          LMAC_IEEE80211_MGMT_HDR_LEN /* TSF timestamp bytes [24..31] */
#define LMAC_BEACON_TSF_LEN             8U
#define LMAC_BEACON_TBTT_DRIFT_GUARD_US 2000        /* Signed min remaining delta (us) before snapping */

/* Promiscuous / sniffer settle delay */
#define LMAC_SNIFFER_SETTLE_MS          15U         /* Wait for baseband RX filter clear to settle */

/* Hardware RX Block-Ack scoreboard bounds */
#define LMAC_RXBA_MAX_TID               8U
#define LMAC_RXBA_MAX_WIN_SIZE          64U
#define LMAC_RXBA_SLOT_INVALID          0xFFU

extern uint32_t WDEV_INTEREST_EVENT;
extern volatile uint8_t NMIIrqIsOn;

static const uint8_t s_bcast_mac[LMAC_MAC_ADDR_LEN] = { 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU };

/**
 * @brief Read a 32-bit little-endian integer from an unaligned byte pointer.
 *
 * @param p  Pointer to at least 4 readable bytes.
 * @return   Decoded 32-bit unsigned integer.
 */
static inline uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/**
 * @brief Read a 16-bit little-endian integer from an unaligned byte pointer.
 *
 * @param p  Pointer to at least 2 readable bytes.
 * @return   Decoded 16-bit unsigned integer.
 */
static inline uint16_t read_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* --------------------------------------------------------------------------
 * Hardware Key Table (25 Slots @ 0x3FF21400, 40 B Each)
 *
 * WDEV hardware key table partitioning (25 slots total, 0..24):
 *   - Slots  0..1 : Broadcast CCMP placeholder entries installed during
 *                   lmac_wdev_hw_init() (slot 0 = STA VIF, slot 1 = AP VIF)
 *                   matching vendor wDev_Initialize; never allocated to user
 *                   keys, and TXQ_RATE key-slot index 0 selects crypto bypass.
 *   - Slots  2..3 : STA GTK ping-pong pair (rotated across GTK rekeys so the
 *                   previous key can remain valid briefly); also slots 2..5
 *                   hold 802.11 WEP key indices 0..3 when WEP is configured.
 *   - Slots  4..5 : SoftAP GTK ping-pong pair (for WPA/WPA2 group rekeys).
 *   - Slots  6..24: Pairwise PTK pool (19 slots, dynamically assigned per peer).
 * -------------------------------------------------------------------------- */

/**
 * @brief Disable and zero a single hardware crypto key slot and its SW metadata.
 *
 * Clears the slot's valid bit in LMAC_WDEV_KEY_VALID_MASK first so hardware
 * stops matching the entry before its 40-byte register block is wiped.
 *
 * @param slot  Hardware key slot index (0..24); out-of-range values are ignored.
 */
static void hw_key_clear_slot(uint8_t slot)
{
    if (slot >= LMAC_HW_KEY_SLOTS) {
        return;
    }

    lmac_reg_clr(LMAC_WDEV_KEY_VALID_MASK, (1U << slot));
    for (uint32_t off = 0U; off < LMAC_KEY_SLOT_STRIDE_BYTES; off += 4U) {
        lmac_reg_write(LMAC_KEY_SLOT_BASE(slot) + off, 0U);
    }

    memset(&g_lmac.keys[slot], 0, sizeof(g_lmac.keys[slot]));
    g_lmac.keys[slot].peer_id = ESP_LMAC_PEER_INVALID;
}

/**
 * @brief Program a 40-byte hardware crypto key slot and mark it valid.
 *
 * Packs the 48-bit MAC/BSSID address, sub-algorithm, cipher code, key class,
 * VIF bit, and 2-bit 802.11 key ID into ADDR + FLAGS, zero-pads the key bytes
 * to 32 bytes (8 dwords), writes DATA[0..7], and enables the slot valid bit.
 *
 * @param slot       Hardware key slot index (0..24).
 * @param vif        Virtual interface index (0 = STA, 1 = SoftAP).
 * @param hw_alg     Hardware cipher code (LMAC_HW_ALG_*).
 * @param sub_alg    Hardware sub-algorithm (LMAC_HW_SUBALG_WEP40 / WEP104).
 * @param key_class  Hardware key class (LMAC_HW_KEY_CLASS_*).
 * @param key_idx    802.11 key ID (0..3).
 * @param addr       6-byte peer MAC, BSSID, or broadcast address.
 * @param key        Pointer to raw key bytes (may be NULL if key_len == 0).
 * @param key_len    Length of @p key in bytes (clamped to 32 bytes).
 */
static void hw_key_write_slot(uint8_t slot, uint8_t vif, uint8_t hw_alg, uint8_t sub_alg,
                              uint8_t key_class, uint8_t key_idx, const uint8_t addr[6],
                              const uint8_t *key, uint8_t key_len)
{
    /*
     * STA GTK slot-2/3 eviction guard (matches vendor wDev_Insert_KeyEntry):
     * When installing a key into STA GTK slot 2, WDEV hardware scans slots in
     * ascending order and may still match a stale entry in slot 3 carrying the
     * same 2-bit key_idx (bits [31:30]). Evict slot 3 first to prevent duplicate
     * key_idx collisions after GTK rekeying or WEP/GTK transitions.
     */
    if (slot == LMAC_KEY_SLOT_STA_GTK_BASE &&
        ((lmac_reg_read(LMAC_KEY_SLOT_FLAGS(LMAC_KEY_SLOT_STA_GTK_ALT)) >> LMAC_KEY_FLAGS_KEYIDX_SHIFT) &
         LMAC_KEY_IDX_MASK) == (key_idx & LMAC_KEY_IDX_MASK)) {
        hw_key_clear_slot(LMAC_KEY_SLOT_STA_GTK_ALT);
    }

    uint32_t addr_lo = read_le32(addr);
    uint32_t addr_hi = (uint32_t)read_le16(addr + 4);
    uint32_t flags = addr_hi |
                     (((uint32_t)sub_alg & LMAC_KEY_FLAGS_SUBALG_MASK) << LMAC_KEY_FLAGS_SUBALG_SHIFT) |
                     (((uint32_t)hw_alg & LMAC_KEY_FLAGS_ALG_MASK) << LMAC_KEY_FLAGS_ALG_SHIFT) |
                     (((uint32_t)key_class & LMAC_KEY_FLAGS_CLASS_MASK) << LMAC_KEY_FLAGS_CLASS_SHIFT) |
                     (((uint32_t)vif & LMAC_KEY_FLAGS_VIF_MASK) << LMAC_KEY_FLAGS_VIF_SHIFT) |
                     (((uint32_t)key_idx & LMAC_KEY_IDX_MASK) << LMAC_KEY_FLAGS_KEYIDX_SHIFT);

    uint8_t padded[LMAC_KEY_SLOT_DATA_BYTES];
    memset(padded, 0, sizeof(padded));
    if (key != NULL && key_len > 0U) {
        uint8_t copy_len = (key_len > sizeof(padded)) ? (uint8_t)sizeof(padded) : key_len;
        memcpy(padded, key, copy_len);
    }

    lmac_reg_write(LMAC_KEY_SLOT_ADDR(slot), addr_lo);
    lmac_reg_write(LMAC_KEY_SLOT_FLAGS(slot), flags);
    for (uint8_t w = 0U; w < LMAC_KEY_SLOT_DATA_WORDS; w++) {
        lmac_reg_write(LMAC_KEY_SLOT_DATA(slot, w), read_le32(&padded[w * 4U]));
    }
    lmac_reg_set(LMAC_WDEV_KEY_VALID_MASK, (1U << slot));
}

/**
 * @brief Update the per-VIF hardware crypto engine control register (CONF0/CONF1).
 *
 * Scans user key slots (2..24) for active keys belonging to @p vif and writes
 * either bypass mode or active STA/SoftAP crypto mode (plus the WEP flag when
 * any WEP key is installed). Deferred while sniffer mode owns the crypto engine.
 * Preserves LMAC_CRYPTO_TX_ENC across key updates whenever an opposite-VIF
 * software-protected frame is active in hardware TX.
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

    for (uint8_t s = LMAC_KEY_SLOT_FIRST_USER; s < LMAC_HW_KEY_SLOTS; s++) {
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

    /*
     * Opposite-VIF SW-protected TX bypass invariant:
     * Software-encrypted frames (Protected=1, key slot 0) borrow the opposite VIF's
     * CRYPTO_CONF register with LMAC_CRYPTO_TX_ENC=1 while in flight so WDEV passes
     * the pre-encrypted payload verbatim (sw_prot_bypass_vif encodes vif + 1: 1=CONF0,
     * 2=CONF1, 0=none). Preserve TX_ENC across concurrent key updates until TX finishes,
     * or clear sw_prot_bypass_vif when transitioning to LMAC_CRYPTO_BYPASS (which keeps
     * TX_ENC=1 permanently) so TX-done does not clear BYPASS's TX_ENC bit.
     */
    vPortETSIntrLock();
    bool sw_bypass_active = (g_lmac.sw_prot_bypass_vif == (uint8_t)(vif + 1U));
    if (!sw_bypass_active) {
        for (uint8_t q = 0U; q < LMAC_HW_TXQ_COUNT; q++) {
            const lmac_tx_slot_t *act = g_lmac.hw_txq[q].active;
            if (act != NULL &&
                (act->hdr_buf[LMAC_IEEE80211_HDR_FC1_OFF] & LMAC_FC1_PROTECTED) != 0U &&
                (act->hw_key_slot & LMAC_KEY_SLOT_MASK) == LMAC_KEY_SLOT_BYPASS) {
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
            g_lmac.sw_prot_bypass_vif = LMAC_SW_PROT_BYPASS_NONE;
        } else {
            /* Keep TX_ENC=1 while an opposite-VIF SW-protected TX is in flight */
            val |= LMAC_CRYPTO_TX_ENC;
            g_lmac.sw_prot_bypass_vif = (uint8_t)(vif + 1U);
        }
    }
    lmac_reg_write(reg, val);
    vPortETSIntrUnlock();
}

/**
 * @brief Translate a public LMAC cipher enum into WDEV hardware alg/sub-alg codes.
 *
 * @param cipher   Public LMAC cipher identifier.
 * @param hw_alg   Output pointer for 3-bit hardware algorithm code (LMAC_HW_ALG_*).
 * @param sub_alg  Output pointer for 2-bit sub-algorithm code (WEP40=0, WEP104=1).
 */
static void cipher_to_hw_alg(esp_lmac_cipher_t cipher, uint8_t *hw_alg, uint8_t *sub_alg)
{
    *sub_alg = LMAC_HW_SUBALG_WEP40;
    switch (cipher) {
    case ESP_LMAC_CIPHER_WEP40:
        *hw_alg = LMAC_HW_ALG_WEP;
        *sub_alg = LMAC_HW_SUBALG_WEP40;
        break;
    case ESP_LMAC_CIPHER_WEP104:
        *hw_alg = LMAC_HW_ALG_WEP;
        *sub_alg = LMAC_HW_SUBALG_WEP104;
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

/**
 * @brief Install a WEP, GTK, or PTK key into the WDEV hardware key table.
 *
 * Selects a slot according to the 25-slot partition (WEP 2..5, STA GTK 2..3,
 * SoftAP GTK 4..5, PTK 6..24), programs hardware registers, records software
 * tracking metadata, and updates the VIF crypto engine control register.
 *
 * @param vif      Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 * @param peer_id  Peer ID for PTK keys (ignored for WEP/GTK).
 * @param type     Key type (ESP_LMAC_KEY_TYPE_GTK or ESP_LMAC_KEY_TYPE_PTK).
 * @param key_idx  802.11 key index (0..3).
 * @param cipher   Cipher suite (must not be ESP_LMAC_CIPHER_NONE).
 * @param key      Pointer to raw key bytes (non-NULL).
 * @param key_len  Key length in bytes (> 0).
 * @return         ESP_OK, ESP_ERR_INVALID_ARG, ESP_ERR_NOT_FOUND, or ESP_ERR_NO_MEM.
 */
esp_err_t esp_lmac_key_set(esp_lmac_vif_t vif, esp_lmac_peer_id_t peer_id,
                           esp_lmac_key_type_t type, uint8_t key_idx,
                           esp_lmac_cipher_t cipher, const uint8_t *key, uint8_t key_len)
{
    if (vif >= ESP_LMAC_VIF_MAX || key == NULL || key_len == 0U || key_idx > LMAC_KEY_IDX_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (cipher == ESP_LMAC_CIPHER_NONE) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t hw_alg = 0U;
    uint8_t sub_alg = 0U;
    cipher_to_hw_alg(cipher, &hw_alg, &sub_alg);

    uint8_t slot = LMAC_KEY_SLOT_INVALID;
    uint8_t key_class = LMAC_HW_KEY_CLASS_GTK;
    const uint8_t *addr = s_bcast_mac;

    if (cipher == ESP_LMAC_CIPHER_WEP40 || cipher == ESP_LMAC_CIPHER_WEP104) {
        /* WEP maps 802.11 key_idx 0..3 directly onto hardware slots 2..5 */
        slot = (uint8_t)(LMAC_KEY_SLOT_STA_GTK_BASE + (key_idx & LMAC_KEY_IDX_MASK));
        key_class = LMAC_HW_KEY_CLASS_WEP;
        addr = g_lmac.vif[vif].bssid_enabled ? g_lmac.vif[vif].bssid : s_bcast_mac;
    } else if (type == ESP_LMAC_KEY_TYPE_GTK) {
        /* GTK ping-pong pair: slots 2..3 for STA, slots 4..5 for SoftAP */
        key_class = LMAC_HW_KEY_CLASS_GTK;
        uint8_t base = (vif == ESP_LMAC_VIF_STA) ? LMAC_KEY_SLOT_STA_GTK_BASE : LMAC_KEY_SLOT_AP_GTK_BASE;

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
        /* Pairwise key (PTK): dynamically allocated from slots 6..24 */
        lmac_peer_t *p = lmac_trc_get_peer(peer_id);
        if (p == NULL) {
            return ESP_ERR_NOT_FOUND;
        }
        key_class = LMAC_HW_KEY_CLASS_PTK;
        addr = p->mac;

        if (p->ptk_hw_slot >= LMAC_KEY_SLOT_PTK_BASE && p->ptk_hw_slot < LMAC_HW_KEY_SLOTS) {
            slot = p->ptk_hw_slot;
        } else {
            for (uint8_t s = LMAC_KEY_SLOT_PTK_BASE; s < LMAC_HW_KEY_SLOTS; s++) {
                if (!g_lmac.keys[s].in_use) {
                    slot = s;
                    break;
                }
            }
            if (slot == LMAC_KEY_SLOT_INVALID) {
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

/**
 * @brief Clear matching PTK or GTK hardware key slot(s) for a VIF.
 *
 * Also detaches any cleared PTK slot from its peer record and refreshes the
 * VIF hardware crypto engine register.
 *
 * @param vif      Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 * @param peer_id  Peer ID to match when @p type is ESP_LMAC_KEY_TYPE_PTK.
 * @param type     Key type to remove (PTK or GTK).
 * @param key_idx  802.11 key ID (0..3) to match when @p type is ESP_LMAC_KEY_TYPE_GTK.
 */
void esp_lmac_key_clear(esp_lmac_vif_t vif, esp_lmac_peer_id_t peer_id,
                        esp_lmac_key_type_t type, uint8_t key_idx)
{
    if (vif >= ESP_LMAC_VIF_MAX) {
        return;
    }

    for (uint8_t s = LMAC_KEY_SLOT_FIRST_USER; s < LMAC_HW_KEY_SLOTS; s++) {
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
                    p->ptk_hw_slot = LMAC_KEY_SLOT_INVALID;
                    p->ptk_cipher = (uint8_t)ESP_LMAC_CIPHER_NONE;
                }
            }
            hw_key_clear_slot(s);
        }
    }

    hw_crypto_update_vif_reg(vif);
}

/**
 * @brief Clear all user-installed hardware key slots owned by a VIF.
 *
 * Leaves broadcast placeholder slots 0..1 intact, detaches cleared PTK slots
 * from peer entries, resets VIF cipher state, and returns crypto to bypass.
 *
 * @param vif  Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 */
void esp_lmac_key_clear_vif(esp_lmac_vif_t vif)
{
    if (vif >= ESP_LMAC_VIF_MAX) {
        return;
    }

    for (uint8_t s = LMAC_KEY_SLOT_FIRST_USER; s < LMAC_HW_KEY_SLOTS; s++) {
        if (g_lmac.keys[s].in_use && g_lmac.keys[s].vif == vif) {
            if (g_lmac.keys[s].key_type == ESP_LMAC_KEY_TYPE_PTK) {
                lmac_peer_t *p = lmac_trc_get_peer(g_lmac.keys[s].peer_id);
                if (p != NULL && p->ptk_hw_slot == s) {
                    p->ptk_hw_slot = LMAC_KEY_SLOT_INVALID;
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

/**
 * @brief Read and decode a hardware key slot directly from WDEV MMIO registers.
 *
 * Any output pointer may be NULL to omit reading that field.
 *
 * @param slot         Hardware key slot index (0..24).
 * @param vif_out      Optional output for slot VIF bit (0 or 1).
 * @param cipher_out   Optional output for decoded esp_lmac_cipher_t.
 * @param key_idx_out  Optional output for 2-bit 802.11 key index (0..3).
 * @param addr_out     Optional 6-byte output buffer for the slot MAC/BSSID.
 * @param key_out      Optional output buffer for raw key bytes (up to 32 B).
 * @param key_len      Number of key bytes requested in @p key_out.
 * @return             ESP_OK on success, or ESP_ERR_INVALID_ARG if @p slot >= 25.
 */
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
        *vif_out = (uint8_t)((flags >> LMAC_KEY_FLAGS_VIF_SHIFT) & LMAC_KEY_FLAGS_VIF_MASK);
    }
    if (key_idx_out != NULL) {
        *key_idx_out = (uint8_t)((flags >> LMAC_KEY_FLAGS_KEYIDX_SHIFT) & LMAC_KEY_IDX_MASK);
    }
    if (cipher_out != NULL) {
        uint8_t alg = (uint8_t)((flags >> LMAC_KEY_FLAGS_ALG_SHIFT) & LMAC_KEY_FLAGS_ALG_MASK);
        uint8_t sub = (uint8_t)((flags >> LMAC_KEY_FLAGS_SUBALG_SHIFT) & LMAC_KEY_FLAGS_SUBALG_MASK);
        if (alg == LMAC_HW_ALG_CCMP) {
            *cipher_out = ESP_LMAC_CIPHER_CCMP;
        } else if (alg == LMAC_HW_ALG_TKIP) {
            *cipher_out = ESP_LMAC_CIPHER_TKIP;
        } else if (alg == LMAC_HW_ALG_WEP) {
            *cipher_out = (sub == LMAC_HW_SUBALG_WEP104) ? ESP_LMAC_CIPHER_WEP104 : ESP_LMAC_CIPHER_WEP40;
        } else {
            *cipher_out = ESP_LMAC_CIPHER_NONE;
        }
    }
    if (key_out != NULL && key_len > 0U) {
        uint8_t raw[LMAC_KEY_SLOT_DATA_BYTES];
        for (uint8_t w = 0U; w < LMAC_KEY_SLOT_DATA_WORDS; w++) {
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

/**
 * @brief Resolve the hardware key slot index for an outgoing TX frame.
 *
 * Looks up WEP direct slots (2..5), pairwise peer PTK slot (6..24 when @p peer_id
 * is valid), or VIF GTK ping-pong slots (2..3 STA / 4..5 SoftAP, falling back to
 * the VIF's active GTK slot when @p peer_id is `ESP_LMAC_PEER_INVALID`). When an
 * active key slot is found for `ESP_LMAC_VIF_AP`, sets bit 7 (`LMAC_KEY_SLOT_AP_BIT`,
 * `0x80`) so WDEV selects `LMAC_WDEV_CRYPTO_CONF1` (matching vendor `ieee80211_output.o`).
 *
 * @param vif      Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 * @param peer_id  Destination peer ID (ESP_LMAC_PEER_INVALID for group-addressed TX).
 * @param cipher   Requested frame cipher suite.
 * @param key_idx  802.11 key ID (0..3) for WEP or GTK frames.
 * @return         Hardware key slot index (`2..24`, OR'd with `LMAC_KEY_SLOT_AP_BIT`
 *                 on SoftAP TX), or 0 (`LMAC_KEY_SLOT_BYPASS`) for plaintext or when
 *                 no matching key is installed.
 */
uint8_t lmac_crypto_lookup_tx_slot(esp_lmac_vif_t vif, esp_lmac_peer_id_t peer_id,
                                   esp_lmac_cipher_t cipher, uint8_t key_idx)
{
    uint8_t slot = LMAC_KEY_SLOT_BYPASS;
    if (cipher == ESP_LMAC_CIPHER_NONE || vif >= ESP_LMAC_VIF_MAX) {
        return LMAC_KEY_SLOT_BYPASS;
    }
    if (cipher == ESP_LMAC_CIPHER_WEP40 || cipher == ESP_LMAC_CIPHER_WEP104) {
        uint8_t wslot = (uint8_t)(LMAC_KEY_SLOT_STA_GTK_BASE + (key_idx & LMAC_KEY_IDX_MASK));
        slot = g_lmac.keys[wslot].in_use ? wslot : LMAC_KEY_SLOT_BYPASS;
    } else if (peer_id != ESP_LMAC_PEER_INVALID) {
        lmac_peer_t *p = lmac_trc_get_peer(peer_id);
        if (p != NULL && p->ptk_hw_slot < LMAC_HW_KEY_SLOTS && g_lmac.keys[p->ptk_hw_slot].in_use) {
            slot = p->ptk_hw_slot;
        }
    } else {
        /* Multicast/broadcast GTK lookup */
        uint8_t base = (vif == ESP_LMAC_VIF_STA) ? LMAC_KEY_SLOT_STA_GTK_BASE : LMAC_KEY_SLOT_AP_GTK_BASE;
        for (uint8_t s = base; s < (uint8_t)(base + LMAC_KEY_GTK_SLOTS_PER_VIF); s++) {
            if (g_lmac.keys[s].in_use && g_lmac.keys[s].vif == vif && g_lmac.keys[s].key_idx == key_idx) {
                slot = s;
                break;
            }
        }
        if (slot == LMAC_KEY_SLOT_BYPASS && g_lmac.vif[vif].gtk_active_slot >= base &&
            g_lmac.vif[vif].gtk_active_slot < (uint8_t)(base + LMAC_KEY_GTK_SLOTS_PER_VIF) &&
            g_lmac.keys[g_lmac.vif[vif].gtk_active_slot].in_use) {
            slot = g_lmac.vif[vif].gtk_active_slot;
        }
    }
    /* Match vendor ieee80211_output.o: set bit 7 (0x80) on SoftAP encrypted TX slot */
    if (slot != LMAC_KEY_SLOT_BYPASS && vif == ESP_LMAC_VIF_AP) {
        slot |= LMAC_KEY_SLOT_AP_BIT;
    }
    return slot;
}

/* --------------------------------------------------------------------------
 * WDEV Hardware Initialization & Master Enable
 * -------------------------------------------------------------------------- */

/**
 * @brief Synchronize the WDEV master MAC RX/TX enable bit with active LMAC state.
 *
 * Sets LMAC_WDEV_MAC_ENABLE_BIT if RF is open and at least one VIF (STA or AP)
 * or sniffer mode is active; clears it otherwise.
 */
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

/**
 * @brief Perform cold initialization of WDEV MAC options, crypto, DMA, and NMI routing.
 *
 * Configures RX/TX options (including protected-frame RX bit 18), vendor-verified
 * slot/NAV timing registers, clean 25-slot key table with slots 0..1 broadcast
 * placeholders, RX DMA bounds, auto-ACK rate LUTs, RX address filters, default
 * WDEV interrupt mask, and the DPORT Level-3 NMI bridge. Leaves the master MAC
 * enable bit cleared until a VIF or sniffer is enabled.
 */
void lmac_wdev_hw_init(void)
{
    /* Cross-checked against wDev_Initialize + wDev_Option_Init (wdev.o.c) */
    lmac_reg_write(LMAC_WDEV_INT_ENA, 0U);
    lmac_reg_write(LMAC_WDEV_INT_CLR, LMAC_WDEV_INT_CLR_ALL);

    /*
     * wDev_Option_Init: LMAC_WDEV_RX_OPTION_INIT includes bit 18
     * (LMAC_WDEV_RX_OPTION_PROT_EN), which must remain set for hardware
     * protected-frame RX decryption across normal and post-sniffer operation.
     */
    lmac_reg_write(LMAC_WDEV_RX_OPTION,
                   (lmac_reg_read(LMAC_WDEV_RX_OPTION) & LMAC_WDEV_RX_OPTION_KEEP) | LMAC_WDEV_RX_OPTION_INIT);
    lmac_reg_set(LMAC_WDEV_RXTX_OPTION, LMAC_WDEV_RXTX_OPTION_INIT);
    lmac_reg_set(LMAC_WDEV_TX_OPTION, LMAC_WDEV_TX_OPTION_INIT);
    lmac_reg_clr(LMAC_WDEV_PHY_CONF, LMAC_WDEV_PHY_CONF_INIT_CLR);

    /* Apply vendor-verified slot/SIFS/NAV timing calibration offsets */
    uint32_t sc0 = lmac_reg_read(LMAC_WDEV_SLOT_CONF0);
    sc0 = ((((sc0 >> LMAC_SLOT_CONF0_FIELD_SHIFT) + LMAC_SLOT_CONF0_DELTA) & LMAC_SLOT_CONF0_FIELD_MASK)
           << LMAC_SLOT_CONF0_FIELD_SHIFT) | (sc0 & LMAC_SLOT_CONF0_FIELD_CLEAR);
    lmac_reg_write(LMAC_WDEV_SLOT_CONF0, sc0);
    lmac_reg_write(LMAC_WDEV_SLOT_CONF1,
                   (lmac_reg_read(LMAC_WDEV_SLOT_CONF1) & LMAC_SLOT_CONF1_KEEP_MASK) | LMAC_SLOT_CONF1_INIT_VAL);
    lmac_reg_write(LMAC_WDEV_NAV_CONF,
                   (lmac_reg_read(LMAC_WDEV_NAV_CONF) & LMAC_NAV_CONF_KEEP_MASK) | LMAC_NAV_CONF_INIT_VAL);

    /* Hardware crypto bypass & clean 25-slot key table */
    lmac_reg_write(LMAC_WDEV_CRYPTO_CONF0, LMAC_CRYPTO_BYPASS);
    lmac_reg_write(LMAC_WDEV_CRYPTO_CONF1, LMAC_CRYPTO_BYPASS);
    lmac_reg_write(LMAC_WDEV_KEY_VALID_MASK, 0U);
    for (uint8_t s = 0U; s < LMAC_HW_KEY_SLOTS; s++) {
        hw_key_clear_slot(s);
    }
    /*
     * Vendor wDev_Initialize installs broadcast CCMP placeholder entries in
     * slots 0 (STA VIF) and 1 (SoftAP VIF); user keys start at slot 2.
     */
    hw_key_write_slot(0U, ESP_LMAC_VIF_STA, LMAC_HW_ALG_CCMP, 0U, LMAC_HW_KEY_CLASS_GTK, 0U,
                      s_bcast_mac, s_bcast_mac, LMAC_MAC_ADDR_LEN);
    hw_key_write_slot(1U, ESP_LMAC_VIF_AP, LMAC_HW_ALG_CCMP, 0U, LMAC_HW_KEY_CLASS_GTK, 0U,
                      s_bcast_mac, s_bcast_mac, LMAC_MAC_ADDR_LEN);
    lmac_reg_write(LMAC_WDEV_CRYPTO_WAPI, 0U);

    /* Program RX DMA ring & bounds */
    lmac_dma_reprogram_regs();

    /* Auto-ACK / CTS rate response LUTs */
    lmac_reg_write(LMAC_WDEV_ACK_RATE_TAB0, LMAC_WDEV_ACK_RATE_NORMAL);
    lmac_reg_write(LMAC_WDEV_ACK_RATE_TAB1, LMAC_WDEV_ACK_RATE_EXT_DEF);
    lmac_reg_write(LMAC_WDEV_ACK_RATE_TAB2, LMAC_WDEV_ACK_RATE_EXT_DEF);

    /* RX filter control & clear both BSSID/MAC match filters */
    lmac_reg_write(LMAC_WDEV_RX_FILTER_CTRL,
                   (lmac_reg_read(LMAC_WDEV_RX_FILTER_CTRL) & LMAC_WDEV_RX_FILTER_KEEP) | LMAC_WDEV_RX_FILTER_NORMAL);
    lmac_reg_clr(LMAC_WDEV_BSSID_MASK_HI(ESP_LMAC_VIF_STA), LMAC_WDEV_MATCH_ENABLE);
    lmac_reg_clr(LMAC_WDEV_BSSID_MASK_HI(ESP_LMAC_VIF_AP), LMAC_WDEV_MATCH_ENABLE);
    lmac_reg_clr(LMAC_WDEV_MAC_MASK_HI(ESP_LMAC_VIF_STA), LMAC_WDEV_MATCH_ENABLE);
    lmac_reg_clr(LMAC_WDEV_MAC_MASK_HI(ESP_LMAC_VIF_AP), LMAC_WDEV_MATCH_ENABLE);

    /* Enable WDEV NMI mask and Level-3 NMI bridge */
    vPortETSIntrLock();
    WDEV_INTEREST_EVENT = LMAC_WDEV_INTEREST_DEFAULT;
    lmac_reg_write(LMAC_WDEV_INT_ENA, WDEV_INTEREST_EVENT);
    vPortETSIntrUnlock();

    lmac_reg_set(LMAC_WDEV_RX_CTRL2, LMAC_WDEV_RX_CTRL2_INIT_BIT);
    lmac_reg_clr(LMAC_WDEV_MAC_ENABLE, LMAC_WDEV_MAC_ENABLE_BIT);
    lmac_reg_write(LMAC_DPORT_NMI_INT_ENA, LMAC_DPORT_NMI_ENABLE_BIT);
}

/* --------------------------------------------------------------------------
 * Dual Virtual Interfaces (STA=0, SoftAP=1) & BSSID / Scan Filter
 * -------------------------------------------------------------------------- */

/**
 * @brief Enable a VIF, program its 48-bit hardware MAC filter, and wake MAC RX/TX.
 *
 * Defaults the VIF protocol mask to 11b/11g/11n if not yet configured. Hardware
 * filter writes are deferred if promiscuous/sniffer mode is active (restored on
 * sniffer exit).
 *
 * @param vif  Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 * @param mac  6-byte local MAC address (non-NULL).
 * @return     ESP_OK on success, or ESP_ERR_INVALID_ARG if @p vif or @p mac is invalid.
 */
esp_err_t esp_lmac_vif_enable(esp_lmac_vif_t vif, const uint8_t mac[6])
{
    if (vif >= ESP_LMAC_VIF_MAX || mac == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memcpy(g_lmac.vif[vif].mac, mac, LMAC_MAC_ADDR_LEN);
    g_lmac.vif[vif].enabled = 1U;
    if (g_lmac.vif[vif].proto_mask == 0U) {
        g_lmac.vif[vif].proto_mask = WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N;
    }

    if (g_lmac.sniffer_mode == 0U) {
        lmac_reg_write(LMAC_WDEV_MAC_LO(vif), read_le32(mac));
        lmac_reg_write(LMAC_WDEV_MAC_HI(vif), (uint32_t)read_le16(mac + 4));
        lmac_reg_write(LMAC_WDEV_MAC_MASK_LO(vif), LMAC_ADDR_MASK_LO_EXACT);
        lmac_reg_write(LMAC_WDEV_MAC_MASK_HI(vif), LMAC_ADDR_MASK_HI_EXACT | LMAC_WDEV_MATCH_ENABLE);
    }

    lmac_wdev_update_mac_enable();
    return ESP_OK;
}

/**
 * @brief Disable a VIF, flushing its queued TX frames, RX BA sessions, keys, beacon, and HW filters.
 *
 * @param vif  Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 */
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

/**
 * @brief Reconcile hardware BSSID and scan-wildcard filter registers for a VIF.
 *
 * Skips hardware writes while sniffer mode owns the address masks. During STA
 * scan mode, engages scan wildcard reception (LMAC_WDEV_RX_FILTER_SCAN) instead
 * of a strict BSSID match; otherwise programs or clears the exact 48-bit BSSID
 * filter from software shadow state.
 *
 * @param vif  Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 */
static void hw_apply_bssid_filter(esp_lmac_vif_t vif)
{
    if (g_lmac.sniffer_mode != 0U) {
        return;
    }
    if (vif == ESP_LMAC_VIF_STA && g_lmac.scan_mode != 0U) {
        /*
         * Scan wildcard mode (matches vendor wDev_SetRxPolicy(0, 0, 0) + scan bit):
         * Clear VIF0 BSSID match-enable and set LMAC_WDEV_RX_FILTER_SCAN (bit 4)
         * so WDEV admits beacons and probe responses from any BSSID while still
         * dropping unrelated neighbor-AP data frames before they fill RX DMA.
         */
        lmac_reg_clr(LMAC_WDEV_BSSID_MASK_HI(ESP_LMAC_VIF_STA), LMAC_WDEV_MATCH_ENABLE);
        lmac_reg_set(LMAC_WDEV_RX_FILTER_CTRL, LMAC_WDEV_RX_FILTER_SCAN);
        return;
    }

    if (g_lmac.vif[vif].bssid_enabled) {
        const uint8_t *bssid = g_lmac.vif[vif].bssid;
        lmac_reg_clr(LMAC_WDEV_BSSID_MASK_HI(vif), LMAC_WDEV_MATCH_ENABLE);
        lmac_reg_write(LMAC_WDEV_BSSID_LO(vif), read_le32(bssid));
        lmac_reg_write(LMAC_WDEV_BSSID_HI(vif), (uint32_t)read_le16(bssid + 4));
        lmac_reg_write(LMAC_WDEV_BSSID_MASK_LO(vif), LMAC_ADDR_MASK_LO_EXACT);
        lmac_reg_write(LMAC_WDEV_BSSID_MASK_HI(vif), LMAC_ADDR_MASK_HI_EXACT | LMAC_WDEV_MATCH_ENABLE);
    } else {
        lmac_reg_clr(LMAC_WDEV_BSSID_MASK_HI(vif), LMAC_WDEV_MATCH_ENABLE);
    }
}

/**
 * @brief Update software BSSID filter state for a VIF and apply it to hardware.
 *
 * @param vif     Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 * @param bssid   6-byte BSSID to match when @p enable is true (may be NULL if false).
 * @param enable  true to enable exact BSSID filtering; false to disable it.
 */
void esp_lmac_set_bssid_filter(esp_lmac_vif_t vif, const uint8_t bssid[6], bool enable)
{
    if (vif >= ESP_LMAC_VIF_MAX) {
        return;
    }

    if (enable && bssid != NULL) {
        memcpy(g_lmac.vif[vif].bssid, bssid, LMAC_MAC_ADDR_LEN);
        g_lmac.vif[vif].bssid_enabled = 1U;
    } else {
        g_lmac.vif[vif].bssid_enabled = 0U;
    }

    hw_apply_bssid_filter(vif);
}

/**
 * @brief Enter or exit STA scan RX wildcard mode.
 *
 * On exit (when sniffer is inactive), clears LMAC_WDEV_RX_FILTER_SCAN and
 * restores the saved STA BSSID filter via hw_apply_bssid_filter().
 *
 * @param scanning  true to enable scan wildcard reception; false to restore normal filter.
 */
void esp_lmac_set_scan_rx_mode(bool scanning)
{
    g_lmac.scan_mode = scanning ? 1U : 0U;
    if (!scanning && g_lmac.sniffer_mode == 0U) {
        lmac_reg_clr(LMAC_WDEV_RX_FILTER_CTRL, LMAC_WDEV_RX_FILTER_SCAN);
    }
    hw_apply_bssid_filter(ESP_LMAC_VIF_STA);
}

/* --------------------------------------------------------------------------
 * SoftAP Beacon Template & TSF1 / TBTT Engine
 * -------------------------------------------------------------------------- */

/**
 * @brief Install or replace the SoftAP beacon frame template and arm TSF1/TBTT.
 *
 * Allocates a DRAM buffer holding @p frame plus 4 bytes of zeroed FCS space,
 * swaps out any prior template (flushing AP TX if a beacon was in flight),
 * and on initial activation resets TSF1/TBTT1 and arms MAC Timer 1.
 *
 * @param vif                 Must be ESP_LMAC_VIF_AP.
 * @param frame               Beacon frame bytes excluding FCS (36..512 bytes).
 * @param len                 Length of @p frame in bytes.
 * @param tim_ie_offset       Byte offset of the TIM IE inside @p frame.
 * @param beacon_interval_tu  Beacon interval in TU (< 10 defaults to 100 TU).
 * @return                    ESP_OK, ESP_ERR_INVALID_ARG, or ESP_ERR_NO_MEM.
 */
esp_err_t esp_lmac_set_beacon(esp_lmac_vif_t vif, const uint8_t *frame, uint16_t len,
                              uint16_t tim_ie_offset, uint16_t beacon_interval_tu)
{
    if (vif != ESP_LMAC_VIF_AP || frame == NULL || len < LMAC_BEACON_MIN_LEN || len > LMAC_BEACON_MAX_LEN) {
        return ESP_ERR_INVALID_ARG;
    }
    if (beacon_interval_tu < LMAC_BEACON_MIN_INTERVAL_TU) {
        beacon_interval_tu = LMAC_BEACON_DEF_INTERVAL_TU;
    }

    uint16_t alloc_len = (uint16_t)(len + LMAC_IEEE80211_FCS_LEN); /* Include 4-B hardware FCS space */
    uint8_t *new_buf = (uint8_t *)heap_caps_malloc(alloc_len, MALLOC_CAP_8BIT);
    if (new_buf == NULL) {
        return ESP_ERR_NO_MEM;
    }
    memcpy(new_buf, frame, len);
    memset(new_buf + len, 0, LMAC_IEEE80211_FCS_LEN);

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
    g_lmac.beacon.interval_us = (uint32_t)beacon_interval_tu * LMAC_TU_US;
    g_lmac.beacon.active = 1U;
    g_lmac.beacon.tx_pending = 0U;

    if (!was_active) {
        /* Reset and enable TSF1 + MAC Timer 1 (cross-checked: wDev_Reset_TBTT) */
        lmac_reg_clr(LMAC_WDEV_TSF1_CONF, LMAC_TSF1_CONF_TBTT_EN);
        lmac_reg_write(LMAC_WDEV_TBTT1_LO, 0U);
        lmac_reg_write(LMAC_WDEV_TBTT1_HI, 0U);
        lmac_reg_set(LMAC_WDEV_TSF1_CONF, LMAC_TSF1_CONF_TBTT_EN);

        g_lmac.beacon.next_tbtt_lo = lmac_reg_read(LMAC_WDEV_TSF1_LO) + g_lmac.beacon.interval_us;
        lmac_mactim1_arm(g_lmac.beacon.interval_us);
    }

    return ESP_OK;
}

/**
 * @brief Stop SoftAP beaconing, disarm TSF1/MAC Timer 1, and free the template buffer.
 *
 * @param vif  Virtual interface index (no-op unless ESP_LMAC_VIF_AP).
 */
void esp_lmac_stop_beacon(esp_lmac_vif_t vif)
{
    if (vif != ESP_LMAC_VIF_AP) {
        return;
    }

    lmac_mactim1_disarm();
    lmac_reg_clr(LMAC_WDEV_TSF1_CONF, LMAC_TSF1_CONF_TBTT_EN);

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

/**
 * @brief Handle a SoftAP TBTT event on the Wi-Fi worker task.
 *
 * Invokes the upper-layer on_tbtt() hook (TIM/DTIM updates), stamps the live
 * 64-bit TSF1 timestamp into the beacon body and launches TX (when RF is open
 * and neither sniffer nor scan is active), then re-arms MAC Timer 1 with
 * phase-locked drift compensation.
 */
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
        /* Stamp current 64-bit TSF1 timestamp into beacon fixed body bytes [24..31] */
        uint64_t tsf = esp_lmac_get_tsf_us(ESP_LMAC_VIF_AP);
        memcpy(g_lmac.beacon.buf + LMAC_BEACON_TSF_OFFSET, &tsf, LMAC_BEACON_TSF_LEN);
        lmac_tx_launch_beacon_now();
    }

    /*
     * Drift-compensated TBTT re-arming:
     * Advance the ideal target (next_tbtt_lo) by one beacon interval and compute
     * the signed remaining time relative to live TSF1_LO. If the worker was only
     * slightly delayed (remaining > 2000 us and <= 2 intervals), arm the exact
     * shortened remainder to keep long-term beacon cadence phase-locked to TSF1
     * without cumulative jitter drift. If the target fell behind or jumped (e.g.,
     * after a long flash stall or TSF discontinuity), snap next_tbtt_lo forward
     * to now_lo + interval_us to avoid arming an already-expired comparator.
     */
    if (g_lmac.beacon.active) {
        uint32_t now_lo = lmac_reg_read(LMAC_WDEV_TSF1_LO);
        uint32_t delta = g_lmac.beacon.interval_us;
        g_lmac.beacon.next_tbtt_lo += g_lmac.beacon.interval_us;
        int32_t rem = (int32_t)(g_lmac.beacon.next_tbtt_lo - now_lo);
        if (rem > LMAC_BEACON_TBTT_DRIFT_GUARD_US && (uint32_t)rem <= (g_lmac.beacon.interval_us * 2U)) {
            delta = (uint32_t)rem;
        } else {
            g_lmac.beacon.next_tbtt_lo = now_lo + g_lmac.beacon.interval_us;
        }
        lmac_mactim1_arm(delta);
    }
}

/* --------------------------------------------------------------------------
 * Promiscuous / Sniffer Mode (Fixes Vendor Bit-18 Exit Bug, Non-Blocking)
 *
 * RX_OPTION bit 18 (LMAC_WDEV_RX_OPTION_PROT_EN) invariant:
 *   Vendor ROM/libpp cleared RX_OPTION bit 18 when leaving promiscuous mode,
 *   which silently disabled hardware protected-frame decryption for subsequent
 *   STA/AP sessions until a full MAC reset. Both sniffer enter and exit here
 *   keep LMAC_WDEV_RX_OPTION_PROT_EN explicitly set and switch raw capture via
 *   CRYPTO_CONF0/CONF1 (LMAC_CRYPTO_SNIFFER_RAW vs LMAC_CRYPTO_ENG_EN) instead.
 * -------------------------------------------------------------------------- */

/**
 * @brief Enable promiscuous/sniffer capture mode and configure software filter masks.
 *
 * Lazily allocates the 16-entry `snf_ring` (`LMAC_SNF_RING_SIZE * sizeof(lmac_snf_pkt_t)`)
 * for NMI `LMAC_INT_SNIFFER_END` captures, places the hardware crypto engine into raw
 * sniffer bypass while preserving `LMAC_WDEV_RX_OPTION_PROT_EN` (bit 18), opens VIF0
 * MAC/BSSID address masks, enables sniffer NMI bits, clears baseband sniffer filter bits,
 * waits 15 ms for baseband settle, and disables hardware auto-ACK.
 *
 * @param filter_mask       Packet type filter bitmask (0 defaults to WIFI_PROMIS_FILTER_MASK_ALL).
 * @param ctrl_filter_mask  Control-frame subtype filter bitmask.
 * @return                  ESP_OK on success, or ESP_ERR_NO_MEM if `snf_ring` allocation fails.
 */
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
        /* Publish zeroed ring and indices before exposing snf_ring to Level-3 NMI */
        __asm__ volatile("memw" ::: "memory");
        g_lmac.snf_ring = ring;
    }

    g_lmac.sniffer_mode = 1U;

    /* Preserve RX_OPTION bit 18 invariant and switch hardware crypto into raw sniffer capture */
    lmac_reg_set(LMAC_WDEV_RX_OPTION, LMAC_WDEV_RX_OPTION_PROT_EN);
    lmac_reg_write(LMAC_WDEV_CRYPTO_CONF0,
                   (lmac_reg_read(LMAC_WDEV_CRYPTO_CONF0) & ~LMAC_CRYPTO_ENG_EN) | LMAC_CRYPTO_SNIFFER_RAW);
    lmac_reg_write(LMAC_WDEV_CRYPTO_CONF1,
                   (lmac_reg_read(LMAC_WDEV_CRYPTO_CONF1) & ~LMAC_CRYPTO_ENG_EN) | LMAC_CRYPTO_SNIFFER_RAW);

    /* Open MAC & BSSID address masks and RX filter so all over-the-air frames enter RX DMA */
    lmac_reg_clr(LMAC_WDEV_RX_FILTER_CTRL, LMAC_WDEV_RX_FILTER_ADDR);
    lmac_reg_write(LMAC_WDEV_MAC_MASK_LO(ESP_LMAC_VIF_STA), 0U);
    lmac_reg_write(LMAC_WDEV_MAC_MASK_HI(ESP_LMAC_VIF_STA), LMAC_WDEV_MATCH_ENABLE);
    lmac_reg_write(LMAC_WDEV_BSSID_MASK_LO(ESP_LMAC_VIF_STA), 0U);
    lmac_reg_write(LMAC_WDEV_BSSID_MASK_HI(ESP_LMAC_VIF_STA), LMAC_WDEV_MATCH_ENABLE);

    vPortETSIntrLock();
    WDEV_INTEREST_EVENT |= LMAC_WDEV_INTEREST_SNIFFER;
    lmac_reg_write(LMAC_WDEV_INT_ENA, WDEV_INTEREST_EVENT);
    vPortETSIntrUnlock();

    /* Clear baseband sniffer filter bits [29,26], let BB settle, and disable auto-ACK */
    lmac_reg_clr(LMAC_BB_RX_SNIFFER_FILT, LMAC_BB_RX_SNIFFER_MASK);
    vTaskDelay(pdMS_TO_TICKS(LMAC_SNIFFER_SETTLE_MS));
    lmac_reg_clr(LMAC_WDEV_TX_OPTION, LMAC_WDEV_TX_OPTION_AUTOACK);

    lmac_wdev_update_mac_enable();
    return ESP_OK;
}

/**
 * @brief Exit promiscuous/sniffer mode and restore normal MAC, filter, and crypto state.
 *
 * Re-enables hardware auto-ACK and baseband filtering, clears sniffer NMI bits,
 * clears `sniffer_mode` and spins until any in-flight Level-3 NMI completes
 * (`NMIIrqIsOn == 0`) before freeing `snf_ring`, restores VIF0 MAC and BSSID filters,
 * reloads per-VIF crypto control registers, and explicitly keeps
 * `LMAC_WDEV_RX_OPTION_PROT_EN` (bit 18) enabled.
 */
void esp_lmac_sniffer_disable(void)
{
    if (g_lmac.sniffer_mode == 0U) {
        return;
    }

    lmac_reg_set(LMAC_WDEV_TX_OPTION, LMAC_WDEV_TX_OPTION_AUTOACK);
    lmac_reg_set(LMAC_BB_RX_SNIFFER_FILT, LMAC_BB_RX_SNIFFER_MASK);

    vPortETSIntrLock();
    WDEV_INTEREST_EVENT &= ~LMAC_WDEV_INTEREST_SNIFFER;
    lmac_reg_write(LMAC_WDEV_INT_ENA, WDEV_INTEREST_EVENT);
    vPortETSIntrUnlock();

    /*
     * Safe snf_ring teardown barrier:
     * Clear sniffer_mode after masking LMAC_WDEV_INTEREST_SNIFFER and spin until
     * NMIIrqIsOn drops to 0 so no in-flight Level-3 NMI can still write into snf_ring
     * when it is freed to the heap.
     */
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
    lmac_reg_set(LMAC_WDEV_RX_FILTER_CTRL, LMAC_WDEV_RX_FILTER_NORMAL);
    if (g_lmac.vif[ESP_LMAC_VIF_STA].enabled) {
        const uint8_t *mac = g_lmac.vif[ESP_LMAC_VIF_STA].mac;
        lmac_reg_write(LMAC_WDEV_MAC_LO(ESP_LMAC_VIF_STA), read_le32(mac));
        lmac_reg_write(LMAC_WDEV_MAC_HI(ESP_LMAC_VIF_STA), (uint32_t)read_le16(mac + 4));
        lmac_reg_write(LMAC_WDEV_MAC_MASK_LO(ESP_LMAC_VIF_STA), LMAC_ADDR_MASK_LO_EXACT);
        lmac_reg_write(LMAC_WDEV_MAC_MASK_HI(ESP_LMAC_VIF_STA), LMAC_ADDR_MASK_HI_EXACT | LMAC_WDEV_MATCH_ENABLE);
    } else {
        lmac_reg_write(LMAC_WDEV_MAC_MASK_LO(ESP_LMAC_VIF_STA), LMAC_ADDR_MASK_LO_EXACT);
        lmac_reg_write(LMAC_WDEV_MAC_MASK_HI(ESP_LMAC_VIF_STA), LMAC_ADDR_MASK_HI_EXACT);
    }
    hw_apply_bssid_filter(ESP_LMAC_VIF_STA);

    /* Restore crypto engine registers cleanly while KEEPING RX_OPTION bit 18 ON */
    lmac_reg_write(LMAC_WDEV_CRYPTO_CONF0,
                   (lmac_reg_read(LMAC_WDEV_CRYPTO_CONF0) & ~LMAC_CRYPTO_SNIFFER_RAW) | LMAC_CRYPTO_ENG_EN);
    lmac_reg_write(LMAC_WDEV_CRYPTO_CONF1,
                   (lmac_reg_read(LMAC_WDEV_CRYPTO_CONF1) & ~LMAC_CRYPTO_SNIFFER_RAW) | LMAC_CRYPTO_ENG_EN);
    hw_crypto_update_vif_reg(ESP_LMAC_VIF_STA);
    hw_crypto_update_vif_reg(ESP_LMAC_VIF_AP);
    lmac_reg_set(LMAC_WDEV_RX_OPTION, LMAC_WDEV_RX_OPTION_PROT_EN);

    lmac_wdev_update_mac_enable();
}

/**
 * @brief Update the software sniffer packet-type and control-frame filter bitmasks.
 *
 * @param filter_mask       Packet type filter bitmask.
 * @param ctrl_filter_mask  Control-frame subtype filter bitmask.
 */
void esp_lmac_sniffer_set_filter(uint32_t filter_mask, uint32_t ctrl_filter_mask)
{
    g_lmac.sniffer_filter = filter_mask;
    g_lmac.sniffer_ctrl_filter = ctrl_filter_mask;
}

/**
 * @brief Retrieve the active software sniffer filter bitmasks.
 *
 * @param filter_mask       Optional output pointer for packet type filter mask.
 * @param ctrl_filter_mask  Optional output pointer for control-frame filter mask.
 */
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
 * Hardware RX Block-Ack Scoreboards (0..3, max 4 active sessions, Gated by AMPDU_RX)
 *
 * WDEV Bank 0 exposes hardware RX Block-Ack scoreboards with a reverse-stride
 * register layout (-0x18 bytes per slot i = 0..7; active cap LMAC_RXBA_MAX_SESSIONS = 4):
 *   - LMAC_WDEV_RXBA_CONF(i)    = 0x3FF2014C - 0x18 * i  ([15:12] TID, enable)
 *   - LMAC_WDEV_RXBA_ADDR_HI(i) = 0x3FF20150 - 0x18 * i  ([15:0]  TA[4..5])
 *   - LMAC_WDEV_RXBA_ADDR_LO(i) = 0x3FF20154 - 0x18 * i  ([31:0]  TA[0..3])
 *   - LMAC_WDEV_RXBA_SSN_WIN(i) = 0x3FF20158 - 0x18 * i  ([11:0]  init SSN,
 *                                                         [19:13] win_size,
 *                                                         [31:20] live HW SSN RO)
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
/**
 * @brief Zero a single hardware RX Block-Ack scoreboard slot and clear its SW bitmasks.
 *
 * Writes 0 to all four reverse-stride WDEV RX BA registers (`ADDR_LO`, `ADDR_HI`,
 * `SSN_WIN`, `CONF`) for @p slot and clears its bits in `rx_ba_used_mask` and
 * `rx_ba_vif_mask`.
 *
 * @param slot  Hardware RX BA scoreboard slot index (`0 .. LMAC_RXBA_MAX_SESSIONS - 1`).
 */
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
 * Returns `false` when `CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED` is disabled, runtime
 * `g_lmac.cfg.ampdu_rx_enable == 0`, @p peer_id is invalid, @p tid >= 8, or all
 * `LMAC_RXBA_MAX_SESSIONS` (4) active slots are held by other `(peer, tid)` sessions.
 *
 * @param peer_id  LMAC peer identifier.
 * @param tid      802.11 QoS Traffic Identifier (`0..7`).
 * @return         `true` when esp_lmac_add_rx_ba() can accept the session; `false` otherwise.
 */
bool esp_lmac_can_add_rx_ba(esp_lmac_peer_id_t peer_id, uint8_t tid)
{
#ifdef CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
    lmac_peer_t *p = lmac_trc_get_peer(peer_id);
    if (g_lmac.cfg.ampdu_rx_enable == 0U || p == NULL || tid >= LMAC_RXBA_MAX_TID) {
        return false;
    }
    uint32_t addr_lo = read_le32(p->mac);
    uint32_t addr_hi = (uint32_t)read_le16(p->mac + 4);
    for (uint8_t i = 0U; i < LMAC_RXBA_MAX_SESSIONS; i++) {
        if ((g_lmac.rx_ba_used_mask & (1U << i)) == 0U) {
            return true;
        }
        uint32_t conf = lmac_reg_read(LMAC_WDEV_RXBA_CONF(i));
        if (((conf >> LMAC_WDEV_RXBA_TID_SHIFT) & LMAC_WDEV_RXBA_TID_MASK) == tid &&
            lmac_reg_read(LMAC_WDEV_RXBA_ADDR_LO(i)) == addr_lo &&
            (lmac_reg_read(LMAC_WDEV_RXBA_ADDR_HI(i)) & LMAC_ADDR_MASK_HI_EXACT) == addr_hi) {
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

/**
 * @brief Allocate or update a hardware RX Block-Ack scoreboard for a peer/TID.
 *
 * Enforces the 4-session cap (`LMAC_RXBA_MAX_SESSIONS`), deduplicating any existing
 * active scoreboard matching `(peer_id, tid)` before claiming a free slot, and records
 * per-slot VIF ownership in `g_lmac.rx_ba_vif_mask` (`0` = STA, `1` = SoftAP). Returns
 * `ESP_ERR_NOT_SUPPORTED` when `CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED` is compiled out
 * or runtime `g_lmac.cfg.ampdu_rx_enable == 0`.
 *
 * @param peer_id   Valid peer ID whose MAC address originates the A-MPDU stream.
 * @param tid       802.11 QoS TID (`0..7`).
 * @param ssn       12-bit Starting Sequence Number (`0..4095`).
 * @param win_size  Block-Ack window size (`1..64`).
 * @return          ESP_OK on success, ESP_ERR_INVALID_ARG on invalid peer/tid/win_size,
 *                  ESP_ERR_NO_MEM if all 4 active scoreboard slots are occupied, or
 *                  ESP_ERR_NOT_SUPPORTED if A-MPDU RX is disabled.
 */
esp_err_t esp_lmac_add_rx_ba(esp_lmac_peer_id_t peer_id, uint8_t tid, uint16_t ssn, uint8_t win_size)
{
#ifdef CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
    lmac_peer_t *p = lmac_trc_get_peer(peer_id);
    if (g_lmac.cfg.ampdu_rx_enable == 0U) {
        return ESP_ERR_NOT_SUPPORTED;
    }
    if (p == NULL || tid >= LMAC_RXBA_MAX_TID || win_size == 0U || win_size > LMAC_RXBA_MAX_WIN_SIZE) {
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t addr_lo = read_le32(p->mac);
    uint32_t addr_hi = (uint32_t)read_le16(p->mac + 4);
    uint8_t slot = LMAC_RXBA_SLOT_INVALID;

    /* Deduplicate existing (peer, tid) session before claiming a new scoreboard slot */
    for (uint8_t i = 0U; i < LMAC_RXBA_MAX_SESSIONS; i++) {
        if ((g_lmac.rx_ba_used_mask & (1U << i)) != 0U) {
            uint32_t conf = lmac_reg_read(LMAC_WDEV_RXBA_CONF(i));
            if (((conf >> LMAC_WDEV_RXBA_TID_SHIFT) & LMAC_WDEV_RXBA_TID_MASK) == tid &&
                lmac_reg_read(LMAC_WDEV_RXBA_ADDR_LO(i)) == addr_lo &&
                (lmac_reg_read(LMAC_WDEV_RXBA_ADDR_HI(i)) & LMAC_ADDR_MASK_HI_EXACT) == addr_hi) {
                slot = i;
                break;
            }
        } else if (slot == LMAC_RXBA_SLOT_INVALID) {
            slot = i;
        }
    }
    if (slot == LMAC_RXBA_SLOT_INVALID) {
        return ESP_ERR_NO_MEM;
    }

    /* Exact wDev_AddRXBA reverse-stride register sequence (wdev.o.c:2451-2466) */
    lmac_reg_write(LMAC_WDEV_RXBA_ADDR_LO(slot), addr_lo);
    lmac_reg_write(LMAC_WDEV_RXBA_ADDR_HI(slot), addr_hi);
    lmac_reg_write(LMAC_WDEV_RXBA_SSN_WIN(slot),
                   (((uint32_t)win_size & LMAC_WDEV_RXBA_WIN_MASK) << LMAC_WDEV_RXBA_WIN_SHIFT) |
                   ((uint32_t)ssn & LMAC_WDEV_RXBA_SSN_MASK));
    lmac_reg_write(LMAC_WDEV_RXBA_CONF(slot),
                   (((uint32_t)tid & LMAC_WDEV_RXBA_TID_MASK) << LMAC_WDEV_RXBA_TID_SHIFT) |
                   LMAC_WDEV_RXBA_CONF_ENABLE);
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

/**
 * @brief Clear and free the hardware RX Block-Ack scoreboard matching a peer and TID.
 *
 * Scans the `LMAC_RXBA_MAX_SESSIONS` (4) active scoreboard slots for matching TID and
 * 48-bit peer MAC address and clears all four reverse-stride registers plus
 * `rx_ba_used_mask` / `rx_ba_vif_mask` via lmac_rx_ba_clear_slot(). Compiled to a no-op
 * when `CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED` is disabled.
 *
 * @param peer_id  Valid peer ID whose BA session is being removed.
 * @param tid      802.11 QoS TID (`0..7`).
 */
void esp_lmac_del_rx_ba(esp_lmac_peer_id_t peer_id, uint8_t tid)
{
#ifdef CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED
    lmac_peer_t *p = lmac_trc_get_peer(peer_id);
    if (p == NULL || tid >= LMAC_RXBA_MAX_TID) {
        return;
    }

    uint32_t addr_lo = read_le32(p->mac);
    uint32_t addr_hi = (uint32_t)read_le16(p->mac + 4);

    for (uint8_t i = 0U; i < LMAC_RXBA_MAX_SESSIONS; i++) {
        if ((g_lmac.rx_ba_used_mask & (1U << i)) == 0U) {
            continue;
        }
        uint32_t conf = lmac_reg_read(LMAC_WDEV_RXBA_CONF(i));
        if (((conf >> LMAC_WDEV_RXBA_TID_SHIFT) & LMAC_WDEV_RXBA_TID_MASK) == tid &&
            lmac_reg_read(LMAC_WDEV_RXBA_ADDR_LO(i)) == addr_lo &&
            (lmac_reg_read(LMAC_WDEV_RXBA_ADDR_HI(i)) & LMAC_ADDR_MASK_HI_EXACT) == addr_hi) {
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
 * Scans all `LMAC_RXBA_MAX_SESSIONS` (4) slots and clears every active entry whose
 * 48-bit transmitter address matches @p mac. No-op when `CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED`
 * is disabled or @p mac is NULL.
 *
 * @param mac  Peer 6-byte MAC address.
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
            (lmac_reg_read(LMAC_WDEV_RXBA_ADDR_HI(i)) & LMAC_ADDR_MASK_HI_EXACT) == addr_hi) {
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
 * Matches active slots in `LMAC_RXBA_MAX_SESSIONS` (0..3) against `g_lmac.rx_ba_vif_mask`
 * and clears every entry belonging to @p vif. No-op when `CONFIG_ESP8266_WIFI_AMPDU_RX_ENABLED`
 * is disabled.
 *
 * @param vif  Virtual interface index (`ESP_LMAC_VIF_STA` or `ESP_LMAC_VIF_AP`).
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
 *
 * Recovers a wedged WDEV MAC engine without dropping associations, keys, or
 * active Block-Ack sessions:
 *   1. Under an interrupt lock, halt MAC RX/TX and snapshot all 5 WDEV MMIO
 *      banks (Bank 0 RX/DMA/BA, Bank 1 ACK LUT, Bank 2 Crypto, Bank 3 Clock/
 *      Filters/TXQ, Bank 4 TSF/Timers) into a temporary DRAM buffer.
 *   2. Capture each RX BA scoreboard's live hardware-tracked SSN from RO bits
 *      [31:20] of LMAC_WDEV_RXBA_SSN_WIN(i), because a raw Bank 0 save/restore
 *      would otherwise replay the stale initial SSN stored in [11:0].
 *   3. Pulse LMAC_RTC_MAC_RESET_BIT + LMAC_WDEV_PHY_CTRL_RST_MASK, restore all
 *      5 banks, patch each live SSN back into [11:0], release PHY reset,
 *      reprogram RX DMA ring bounds, and re-enable the MAC engine.
 * -------------------------------------------------------------------------- */

/**
 * @brief Save a contiguous bank of 32-bit WDEV MMIO registers into DRAM.
 *
 * @param dst    Destination buffer with room for at least @p words dwords.
 * @param base   Base MMIO byte address of the WDEV register bank.
 * @param words  Number of 32-bit registers to read sequentially.
 */
static void reg_save_bank(uint32_t *dst, uint32_t base, uint32_t words)
{
    for (uint32_t i = 0U; i < words; i++) {
        dst[i] = lmac_reg_read(base + i * 4U);
    }
}

/**
 * @brief Restore a contiguous bank of 32-bit WDEV MMIO registers from DRAM.
 *
 * @param base   Base MMIO byte address of the WDEV register bank.
 * @param src    Source buffer containing @p words previously saved dwords.
 * @param words  Number of 32-bit registers to write sequentially.
 */
static void reg_restore_bank(uint32_t base, const uint32_t *src, uint32_t words)
{
    for (uint32_t i = 0U; i < words; i++) {
        lmac_reg_write(base + i * 4U, src[i]);
    }
}

/**
 * @brief Execute a 5-bank WDEV MAC soft reset while preserving live MAC and BA state.
 *
 * Allocates a transient heap buffer for the 5 register banks; logs a warning
 * and returns without resetting if allocation fails. Increments
 * g_lmac.stats.mac_resets on completion.
 */
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

    uint32_t ba_ssn[LMAC_WDEV_RXBA_SLOTS];
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
    /* Snapshot live hardware RX BA scoreboard SSNs from RO bits [31:20] */
    for (uint8_t i = 0U; i < LMAC_WDEV_RXBA_SLOTS; i++) {
        ba_ssn[i] = lmac_reg_read(LMAC_WDEV_RXBA_SSN_WIN(i)) >> LMAC_WDEV_RXBA_CUR_SSN_SH;
    }

    /* Pulse MAC hardware reset */
    lmac_reg_clr(LMAC_RTC_MAC_RESET_CTRL, LMAC_RTC_MAC_RESET_BIT);
    lmac_reg_set(LMAC_WDEV_PHY_CTRL, LMAC_WDEV_PHY_CTRL_RST_MASK);

    reg_restore_bank(LMAC_WDEV_BANK0_BASE, b0, LMAC_WDEV_BANK0_WORDS);
    reg_restore_bank(LMAC_WDEV_BANK1_BASE, b1, LMAC_WDEV_BANK1_WORDS);
    reg_restore_bank(LMAC_WDEV_BANK2_BASE, b2, LMAC_WDEV_BANK2_WORDS);
    reg_restore_bank(LMAC_WDEV_BANK3_BASE, b3, LMAC_WDEV_BANK3_WORDS);
    reg_restore_bank(LMAC_WDEV_BANK4_BASE, b4, LMAC_WDEV_BANK4_WORDS);
    /* Re-seed each RX BA scoreboard's initial SSN [11:0] with its pre-reset live SSN */
    for (uint8_t i = 0U; i < LMAC_WDEV_RXBA_SLOTS; i++) {
        uint32_t cur = lmac_reg_read(LMAC_WDEV_RXBA_SSN_WIN(i));
        lmac_reg_write(LMAC_WDEV_RXBA_SSN_WIN(i),
                       (cur & ~LMAC_WDEV_RXBA_SSN_MASK) | (ba_ssn[i] & LMAC_WDEV_RXBA_SSN_MASK));
    }

    lmac_reg_write(LMAC_WDEV_TX_CLR, 0U);
    lmac_reg_write(LMAC_WDEV_RX_CTRL2, LMAC_WDEV_RX_CTRL2_INIT_BIT);
    lmac_reg_clr(LMAC_WDEV_PHY_CTRL, LMAC_WDEV_PHY_CTRL_RST_MASK);

    lmac_dma_reprogram_regs();
    lmac_wdev_update_mac_enable();
    g_lmac.stats.mac_resets++;

    vPortETSIntrUnlock();

    heap_caps_free(save);
}
