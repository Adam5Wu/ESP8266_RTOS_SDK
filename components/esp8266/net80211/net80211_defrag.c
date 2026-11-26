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
// Opt-in IEEE 802.11 RX MSDU defragmentation with FragAttacks hardening
// (CVE-2020-26142..26146). Compiled only when
// CONFIG_ESP8266_OSS_WIFI_RX_DEFRAG_ENABLED=y (0 B overhead when disabled).

#include <string.h>

#include "esp_heap_caps.h"
#include "net80211_internal.h"

#define N8_DEFRAG_SLOTS         2U
#define N8_DEFRAG_MAX_MSDU_LEN  2304U
#define N8_DEFRAG_TIMEOUT_TICKS 20U /* 2.0 s at 100 ms worker ticks */

typedef struct {
    uint8_t  in_use;
    uint8_t  vif;
    uint8_t  ta[IEEE80211_ADDR_LEN];
    uint8_t  tid;
    uint8_t  next_frag;
    uint8_t  is_prot;
    uint8_t  cipher;
    uint8_t  key_idx;
    uint8_t  age_ticks;
    uint16_t seq_num;
    uint16_t len;
    uint64_t last_pn;
    uint8_t *buf;
} n8_defrag_slot_t;

static n8_defrag_slot_t *s_defrag_slots = NULL;

static void defrag_maybe_release_table(void)
{
    if (s_defrag_slots == NULL) {
        return;
    }
    for (uint8_t i = 0U; i < N8_DEFRAG_SLOTS; i++) {
        if (s_defrag_slots[i].in_use != 0U) {
            return;
        }
    }
    heap_caps_free(s_defrag_slots);
    s_defrag_slots = NULL;
}

static void defrag_reset_slot(n8_defrag_slot_t *slot)
{
    if (slot->buf != NULL) {
        heap_caps_free(slot->buf);
    }
    memset(slot, 0, sizeof(*slot));
}

/**
 * @brief Process one validated 802.11 data fragment into the bounded defragmentation cache.
 *
 * Enforces IEEE 802.11 + FragAttacks invariants: strictly contiguous fragment
 * numbers (0, 1, 2, ...), matching (vif, ta, tid, seq_num, is_prot, cipher,
 * 2-bit key_idx), and strictly consecutive PN/TSC (PN[i] == PN[i-1] + 1) for
 * CCMP and TKIP.
 *
 * @param vif       Interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 * @param ta        Transmitter MAC address (802.11 Address 2).
 * @param tid       Traffic Identifier (0..7 or N8_NON_QOS_TID).
 * @param seq_ctrl  16-bit 802.11 Sequence Control field.
 * @param more_frag Non-zero when IEEE80211_FC1_MOREFRAG is set.
 * @param is_prot   Non-zero when IEEE80211_FC1_PROTECTED is set.
 * @param cipher    Expected link cipher for this frame.
 * @param key_idx   2-bit key identifier ((iv[3] >> 6) & 3U when protected).
 * @param pn        48-bit CCMP PN or TKIP TSC (0 when WEP or open).
 * @param frag_data Pointer to the decrypted MPDU payload (LLC+data on frag 0).
 * @param frag_len  Payload byte length excluding MAC/IV headers and MIC/ICV trailer.
 * @param out_len   Output byte length of the reassembled MSDU when non-NULL returned.
 * @return Heap-allocated reassembled MSDU buffer (caller frees via heap_caps_free),
 *         or NULL if incomplete, rejected, or out of memory.
 */
uint8_t *n8_defrag_rx_frag(uint8_t vif, const uint8_t ta[IEEE80211_ADDR_LEN],
                           uint8_t tid, uint16_t seq_ctrl, bool more_frag,
                           bool is_prot, esp_lmac_cipher_t cipher, uint8_t key_idx,
                           uint64_t pn, const uint8_t *frag_data, uint16_t frag_len,
                           uint16_t *out_len)
{
    if (out_len != NULL) {
        *out_len = 0U;
    }
    if (ta == NULL || frag_data == NULL || frag_len == 0U || frag_len > N8_DEFRAG_MAX_MSDU_LEN) {
        return NULL;
    }

    uint16_t seq_num = (uint16_t)(seq_ctrl >> 4);
    uint8_t frag_num = (uint8_t)(seq_ctrl & IEEE80211_FRAG_NUM_MASK);

    if (s_defrag_slots == NULL) {
        if (frag_num != 0U || !more_frag) {
            return NULL;
        }
        s_defrag_slots = (n8_defrag_slot_t *)heap_caps_zalloc(
            N8_DEFRAG_SLOTS * sizeof(n8_defrag_slot_t), MALLOC_CAP_8BIT);
        if (s_defrag_slots == NULL) {
            return NULL;
        }
    }

    n8_defrag_slot_t *match = NULL;
    for (uint8_t i = 0U; i < N8_DEFRAG_SLOTS; i++) {
        n8_defrag_slot_t *s = &s_defrag_slots[i];
        if (s->in_use != 0U && s->vif == vif && s->tid == tid &&
            s->seq_num == seq_num && memcmp(s->ta, ta, IEEE80211_ADDR_LEN) == 0) {
            match = s;
            break;
        }
    }

    if (frag_num == 0U) {
        if (!more_frag) {
            defrag_maybe_release_table();
            return NULL;
        }
        if (match == NULL) {
            uint8_t pick = 0U;
            for (uint8_t i = 0U; i < N8_DEFRAG_SLOTS; i++) {
                if (s_defrag_slots[i].in_use == 0U) {
                    pick = i;
                    break;
                }
                if (s_defrag_slots[i].age_ticks > s_defrag_slots[pick].age_ticks) {
                    pick = i;
                }
            }
            match = &s_defrag_slots[pick];
        }
        defrag_reset_slot(match);

        uint8_t *buf = (uint8_t *)heap_caps_malloc(N8_DEFRAG_MAX_MSDU_LEN, MALLOC_CAP_8BIT);
        if (buf == NULL) {
            defrag_maybe_release_table();
            return NULL;
        }
        memcpy(buf, frag_data, frag_len);
        match->in_use = 1U;
        match->vif = vif;
        memcpy(match->ta, ta, IEEE80211_ADDR_LEN);
        match->tid = tid;
        match->next_frag = 1U;
        match->is_prot = is_prot ? 1U : 0U;
        match->cipher = (uint8_t)cipher;
        match->key_idx = (uint8_t)(key_idx & 3U);
        match->age_ticks = 0U;
        match->seq_num = seq_num;
        match->len = frag_len;
        match->last_pn = pn;
        match->buf = buf;
        return NULL;
    }

    /* Continuation fragment (frag_num > 0): enforce all FragAttacks consistency invariants */
    if (match == NULL || match->buf == NULL) {
        return NULL;
    }

    bool pn_required = is_prot &&
                       (cipher == ESP_LMAC_CIPHER_CCMP || cipher == ESP_LMAC_CIPHER_TKIP);
    if (frag_num != match->next_frag ||
        (is_prot ? 1U : 0U) != match->is_prot ||
        (uint8_t)cipher != match->cipher ||
        (uint8_t)(key_idx & 3U) != match->key_idx ||
        (pn_required && pn != (match->last_pn + 1ULL)) ||
        ((uint32_t)match->len + (uint32_t)frag_len > N8_DEFRAG_MAX_MSDU_LEN)) {
        defrag_reset_slot(match);
        defrag_maybe_release_table();
        return NULL;
    }

    memcpy(match->buf + match->len, frag_data, frag_len);
    match->len = (uint16_t)(match->len + frag_len);
    match->next_frag = (uint8_t)(match->next_frag + 1U);
    match->last_pn = pn;
    match->age_ticks = 0U;

    if (more_frag) {
        return NULL;
    }

    uint8_t *completed = match->buf;
    if (out_len != NULL) {
        *out_len = match->len;
    }
    match->buf = NULL;
    memset(match, 0, sizeof(*match));
    defrag_maybe_release_table();
    return completed;
}

/**
 * @brief Purge all active defragmentation entries belonging to a virtual interface.
 *
 * @param vif Virtual interface index (ESP_LMAC_VIF_STA or ESP_LMAC_VIF_AP).
 */
void n8_defrag_purge_vif(uint8_t vif)
{
    if (s_defrag_slots == NULL) {
        return;
    }
    for (uint8_t i = 0U; i < N8_DEFRAG_SLOTS; i++) {
        if (s_defrag_slots[i].in_use != 0U && s_defrag_slots[i].vif == vif) {
            defrag_reset_slot(&s_defrag_slots[i]);
        }
    }
    defrag_maybe_release_table();
}

/**
 * @brief Purge all active defragmentation entries for a specific peer transmitter address.
 *
 * @param vif Virtual interface index.
 * @param ta  6-byte transmitter MAC address.
 */
void n8_defrag_purge_peer(uint8_t vif, const uint8_t ta[IEEE80211_ADDR_LEN])
{
    if (ta == NULL || s_defrag_slots == NULL) {
        return;
    }
    for (uint8_t i = 0U; i < N8_DEFRAG_SLOTS; i++) {
        if (s_defrag_slots[i].in_use != 0U && s_defrag_slots[i].vif == vif &&
            memcmp(s_defrag_slots[i].ta, ta, IEEE80211_ADDR_LEN) == 0) {
            defrag_reset_slot(&s_defrag_slots[i]);
        }
    }
    defrag_maybe_release_table();
}

/**
 * @brief Age active defragmentation entries on each 100 ms worker tick and drop after 2 s.
 */
void n8_defrag_on_tick_100ms(void)
{
    if (s_defrag_slots == NULL) {
        return;
    }
    for (uint8_t i = 0U; i < N8_DEFRAG_SLOTS; i++) {
        if (s_defrag_slots[i].in_use != 0U) {
            s_defrag_slots[i].age_ticks++;
            if (s_defrag_slots[i].age_ticks >= N8_DEFRAG_TIMEOUT_TICKS) {
                defrag_reset_slot(&s_defrag_slots[i]);
            }
        }
    }
    defrag_maybe_release_table();
}
