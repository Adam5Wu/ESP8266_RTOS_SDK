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

#include "phy_internal.h"

/* --------------------------------------------------------------------------
 * Exported & Cross-TU SoC PHY Globals Owned by phy_soc.c (0 COMMON)
 * -------------------------------------------------------------------------- */

uint8_t chip6_phy_init_ctrl[80] = { 0 };

#ifdef CONFIG_ESP8266_OSS_PHY_ONLY
uint8_t g_phy_sleep_mode_flag = 1U;
#else
uint8_t g_phy_sleep_mode_flag = 0U;
#endif
uint8_t g_phy_wakeup_rf_flag = 0U;

/* --------------------------------------------------------------------------
 * 128-Byte esp_phy_init_data_t Parser
 * -------------------------------------------------------------------------- */

int register_chipv6_phy_init_param(const uint8_t *init_data)
{
#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
    g_phy_rx_gain_swp_step = init_data + 2;
#endif

    for (uint32_t i = 0U; i < 3U; i++) {
        uint8_t base_cmp = init_data[0x11U + i];
        uint8_t ext2_cmp = init_data[0x14U + i];
        chip6_phy_init_ctrl[1U + i] = base_cmp;
        chip6_phy_init_ctrl[4U + i] = (uint8_t)(base_cmp + ext2_cmp);
        chip6_phy_init_ctrl[7U + i] = 0xE2U;
    }

    chip6_phy_init_ctrl[0x0B] = init_data[0x1A];
    chip6_phy_init_ctrl[0x0C] = init_data[0x1B];

    uint16_t spur1_mask = (uint16_t)(((uint16_t)(init_data[0x1C] & 0x3FU) << 8) |
                                     (uint16_t)init_data[0x1D]);
    chip6_phy_init_ctrl[0x0E] = (uint8_t)(spur1_mask & 0xFFU);
    chip6_phy_init_ctrl[0x0F] = (uint8_t)(spur1_mask >> 8);

    for (uint32_t i = 0U; i < 4U; i++) {
        int8_t clamp_idx = (int8_t)init_data[0x1EU + i];
        chip6_phy_init_ctrl[0x10U + i] = (clamp_idx >= 0 && clamp_idx < 6)
                                             ? (uint8_t)clamp_idx
                                             : 0U;
    }

    for (uint32_t i = 0U; i < 6U; i++) {
        chip6_phy_init_ctrl[0x14U + i] = init_data[0x22U + i];
    }
    for (uint32_t i = 0U; i < 8U; i++) {
        chip6_phy_init_ctrl[0x1AU + i] = init_data[0x28U + i];
    }

    chip6_phy_init_ctrl[0x00] = init_data[0x30];
    chip6_phy_init_ctrl[0x22] = init_data[0x33];
    chip6_phy_init_ctrl[0x23] = init_data[0x34];
    chip6_phy_init_ctrl[0x24] = init_data[0x35];

    chip6_phy_init_ctrl[0x26] = init_data[0x40];
    chip6_phy_init_ctrl[0x27] = init_data[0x41];

    uint16_t spur2_mask = (uint16_t)(((uint16_t)(init_data[0x42] & 0x3FU) << 8) |
                                     (uint16_t)init_data[0x43]);
    chip6_phy_init_ctrl[0x28] = (uint8_t)(spur2_mask & 0xFFU);
    chip6_phy_init_ctrl[0x29] = (uint8_t)(spur2_mask >> 8);

    chip6_phy_init_ctrl[0x2A] = init_data[0x44];
    chip6_phy_init_ctrl[0x2B] = init_data[0x45];
    chip6_phy_init_ctrl[0x2C] = init_data[0x46];
    chip6_phy_init_ctrl[0x2D] = init_data[0x47];
    chip6_phy_init_ctrl[0x2E] = init_data[0x48];
    chip6_phy_init_ctrl[0x2F] = init_data[0x49];

    chip6_phy_init_ctrl[0x30] = init_data[0x4A];

    uint8_t fcc_lo = init_data[0x4B];
    uint8_t lo_idx = fcc_lo & 0x0FU;
    chip6_phy_init_ctrl[0x32] = (lo_idx > 5U) ? 5U : lo_idx;
    chip6_phy_init_ctrl[0x34] = (fcc_lo >> 4) & 0x07U;
    chip6_phy_init_ctrl[0x36] = (fcc_lo >> 7) & 0x01U;

    uint8_t fcc_hi = init_data[0x4C];
    uint8_t hi_idx = fcc_hi & 0x0FU;
    chip6_phy_init_ctrl[0x31] = (hi_idx > 5U) ? 5U : hi_idx;
    chip6_phy_init_ctrl[0x33] = (fcc_hi >> 4) & 0x07U;
    chip6_phy_init_ctrl[0x35] = (fcc_hi >> 7) & 0x01U;

    chip6_phy_init_ctrl[0x37] = (init_data[0x4D] >> 4) & 0x0FU;
    chip6_phy_init_ctrl[0x38] = init_data[0x4D] & 0x0FU;
    chip6_phy_init_ctrl[0x39] = init_data[0x4E];

    chip6_phy_init_ctrl[0x3A] = init_data[0x54];
    chip6_phy_init_ctrl[0x3B] = init_data[0x58];

    chip6_phy_init_ctrl[0x3D] = init_data[0x5D];
    chip6_phy_init_ctrl[0x3E] = init_data[0x5E];
    chip6_phy_init_ctrl[0x3F] = init_data[0x5F];
    chip6_phy_init_ctrl[0x40] = init_data[0x60];
    chip6_phy_init_ctrl[0x41] = init_data[0x61];
    chip6_phy_init_ctrl[0x42] = init_data[0x62];
    chip6_phy_init_ctrl[0x43] = init_data[0x63];
    chip6_phy_init_ctrl[0x44] = init_data[0x64];

    chip6_phy_init_ctrl[0x45] = init_data[0x69];
    chip6_phy_init_ctrl[0x46] = init_data[0x6A];
    chip6_phy_init_ctrl[0x47] = init_data[0x6B];
    chip6_phy_init_ctrl[0x48] = init_data[0x6C];
    chip6_phy_init_ctrl[0x49] = init_data[0x6D];
    chip6_phy_init_ctrl[0x4A] = init_data[0x6E];
    chip6_phy_init_ctrl[0x4B] = init_data[0x6F];

    uint8_t freq_en = init_data[0x70];
    int8_t freq_val = (int8_t)init_data[0x71];
    if ((freq_en < 5U) || (freq_val >= 0) || (((uint8_t)(freq_en - 7U) & 0xFDU) != 0U)) {
        chip6_phy_init_ctrl[0x4C] = 0U;
    } else {
        chip6_phy_init_ctrl[0x4C] = 7U;
    }
    if (freq_val < -10) {
        freq_val = -10;
    }
    chip6_phy_init_ctrl[0x4D] = (uint8_t)freq_val;
    chip6_phy_init_ctrl[0x4E] = init_data[0x72];

    return 0;
}
