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
 * File-Local Constants (Init Data Offsets & Parsing Bounds)
 * -------------------------------------------------------------------------- */

/* 128-byte esp_phy_init_data_t byte offsets (init_data[0..127]) */
#define PHY_INIT_OFF_RX_GAIN_SWP        2U    /* RX gain sweep step table start */
#define PHY_INIT_OFF_RX_CMP_BASE        0x11U /* 3 bytes: Ch 1/6/11 base RX comp */
#define PHY_INIT_OFF_RX_CMP_EXT2        0x14U /* 3 bytes: rxmax_ext level 2 delta */
#define PHY_INIT_OFF_SPUR1_NUM_LO       0x1AU
#define PHY_INIT_OFF_SPUR1_DEN          0x1BU
#define PHY_INIT_OFF_SPUR1_MASK_HI      0x1CU /* [5:0]: upper 6 bits of 14-ch mask */
#define PHY_INIT_OFF_SPUR1_MASK_LO      0x1DU
#define PHY_INIT_OFF_CH_CLAMP_BASE      0x1EU /* 4 bytes: Ch 1/11/13/14 power clamps */
#define PHY_INIT_OFF_TARGET_PWR_BASE    0x22U /* 6 bytes: target TX power (0.25 dBm) */
#define PHY_INIT_OFF_RATE_PWR_IDX_BASE  0x28U /* 8 bytes: per-rate power index */
#define PHY_INIT_OFF_XTAL_FREQ          0x30U
#define PHY_INIT_OFF_BTCO_MODE          0x33U
#define PHY_INIT_OFF_BTCO_SUBMODE       0x34U
#define PHY_INIT_OFF_ANT_SWITCH_MODE    0x35U
#define PHY_INIT_OFF_SPUR2_NUM_LO       0x40U
#define PHY_INIT_OFF_SPUR2_DEN          0x41U
#define PHY_INIT_OFF_SPUR2_MASK_HI      0x42U
#define PHY_INIT_OFF_SPUR2_MASK_LO      0x43U
#define PHY_INIT_OFF_SPUR1_NUM_HI       0x44U
#define PHY_INIT_OFF_SPUR2_NUM_HI       0x45U
#define PHY_INIT_OFF_SPUR3_FREQ_LO      0x46U
#define PHY_INIT_OFF_SPUR3_FREQ_HI      0x47U
#define PHY_INIT_OFF_SPUR4_FREQ_LO      0x48U
#define PHY_INIT_OFF_SPUR4_FREQ_HI      0x49U
#define PHY_INIT_OFF_FCC_BACKOFF_EN     0x4AU
#define PHY_INIT_OFF_FCC_LO_PACKED      0x4BU /* [3:0]=idx, [6:4]=cnt, [7]=flag */
#define PHY_INIT_OFF_FCC_HI_PACKED      0x4CU /* [3:0]=idx, [6:4]=cnt, [7]=interp */
#define PHY_INIT_OFF_FCC_11B_PACKED     0x4DU /* [7:4]=hi_off, [3:0]=lo_off */
#define PHY_INIT_OFF_FCC_TEST_MODE      0x4EU
#define PHY_INIT_OFF_CCA_THRESH         0x54U
#define PHY_INIT_OFF_CCA_MODE           0x58U
#define PHY_INIT_OFF_LOW_PWR_EN         0x5DU
#define PHY_INIT_OFF_LOW_PWR_STAGE10    0x5EU
#define PHY_INIT_OFF_LOW_PWR_BB_DELTA   0x5FU
#define PHY_INIT_OFF_11B_PWR_EN         0x60U
#define PHY_INIT_OFF_11B_1M2M_IDX       0x61U
#define PHY_INIT_OFF_11B_5M11M_IDX      0x62U
#define PHY_INIT_OFF_BG_PWCTRL_DIS      0x63U
#define PHY_INIT_OFF_BBPLL160_OPT       0x64U
#define PHY_INIT_OFF_RSVD_45            0x69U
#define PHY_INIT_OFF_RSVD_46            0x6AU
#define PHY_INIT_OFF_VDD33_CONST        0x6BU
#define PHY_INIT_OFF_DSLP_RECAL_INT     0x6CU
#define PHY_INIT_OFF_CH14_FREQ_EN       0x6DU
#define PHY_INIT_OFF_CH14_FREQ_LO       0x6EU
#define PHY_INIT_OFF_CH14_FREQ_HI       0x6FU
#define PHY_INIT_OFF_FREQ_OFF_EN        0x70U
#define PHY_INIT_OFF_FREQ_OFF_VAL       0x71U
#define PHY_INIT_OFF_POWERUP_CAL_MODE   0x72U

/* Complementary high-byte / reserved chip6_phy_init_ctrl[] indices */
#define PHY_CTRL_SPUR3_FREQ_HI          0x2DU
#define PHY_CTRL_SPUR4_FREQ_HI          0x2FU
#define PHY_CTRL_RSVD_45                0x45U
#define PHY_CTRL_RSVD_46                0x46U
#define PHY_CTRL_CH14_FREQ_HI           0x4BU

/* Init-parameter parsing bounds and defaults */
#define PHY_RX_CMP_EXT3_DEFAULT         0xE2U /* Signed -30 for rxmax_ext level 3 */
#define PHY_SPUR_MASK_HI_BITS           0x3FU /* Upper 6 bits of 14-channel bitmask */
#define PHY_CH_CLAMP_COUNT              4U
#define PHY_TARGET_PWR_COUNT            6U
#define PHY_TARGET_PWR_MAX_IDX          5U
#define PHY_RATE_PWR_COUNT              8U
#define PHY_FREQ_OFF_MIN_EN             5U    /* Minimum valid freq-off enable code */
#define PHY_FREQ_OFF_VALID_BASE         7U    /* Valid enable codes are 7 and 9 */
#define PHY_FREQ_OFF_VALID_MASK         0xFDU /* Clears bit 1 so 7 and 9 both test 0 */
#define PHY_FREQ_OFF_MODE_ACTIVE        7U
#define PHY_FREQ_OFF_MIN_STEP           (-10) /* Lower clamp: -10 * 8 kHz = -80 kHz */

/* --------------------------------------------------------------------------
 * Exported & Cross-TU SoC PHY Globals Owned by phy_soc.c (0 COMMON)
 * -------------------------------------------------------------------------- */

/** Parsed 80-byte SoC PHY control table unpacked from `esp_phy_init_data_t`. */
uint8_t chip6_phy_init_ctrl[80] = { 0 };

/**
 * RF sleep-state flag (`1U` initial value when `CONFIG_ESP8266_OSS_PHY_ONLY` is set
 * so SoC ADC/sleep paths keep RF gated; `0U` when `CONFIG_ESP8266_OSS_PHY_WIFI` is active).
 */
#ifdef CONFIG_ESP8266_OSS_PHY_ONLY
uint8_t g_phy_sleep_mode_flag = 1U;
#else
uint8_t g_phy_sleep_mode_flag = 0U;
#endif

/** Non-zero while executing inside an RF sleep-wakeup critical section (suppresses I2C relocking). */
uint8_t g_phy_wakeup_rf_flag = 0U;

/* --------------------------------------------------------------------------
 * 128-Byte esp_phy_init_data_t Parser
 * -------------------------------------------------------------------------- */

/**
 * @brief Unpack the 128-byte `esp_phy_init_data_t` blob into `chip6_phy_init_ctrl[80]`.
 *
 * Parses RX gain sweep pointer (when `CONFIG_ESP8266_OSS_PHY_WIFI` is enabled),
 * 3-band RX compensation tables, spur frequencies and 14-channel bitmasks, target
 * TX power & per-rate tables, crystal/BT-coex/antenna settings, packed FCC
 * edge-channel backoff fields, CCA/low-power options, VDD33 mode, Ch 14 frequency
 * override, and crystal frequency-offset compensation parameters.
 *
 * @param init_data Pointer to the 128-byte PHY initialization parameter block.
 * @return          Always `0`.
 */
int register_chipv6_phy_init_param(const uint8_t *init_data)
{
#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
    g_phy_rx_gain_swp_step = init_data + PHY_INIT_OFF_RX_GAIN_SWP;
#endif

    /* Per-band (Ch 1/6/11) RX compensation for normal, rxmax_ext lvl 2, and fixed lvl 3 (-30) */
    for (uint32_t i = 0U; i < 3U; i++) {
        uint8_t base_cmp = init_data[PHY_INIT_OFF_RX_CMP_BASE + i];
        uint8_t ext2_cmp = init_data[PHY_INIT_OFF_RX_CMP_EXT2 + i];
        chip6_phy_init_ctrl[PHY_CTRL_RX_CMP_BASE + i] = base_cmp;
        chip6_phy_init_ctrl[PHY_CTRL_RX_CMP_EXT2 + i] = (uint8_t)(base_cmp + ext2_cmp);
        chip6_phy_init_ctrl[PHY_CTRL_RX_CMP_EXT3 + i] = PHY_RX_CMP_EXT3_DEFAULT;
    }

    /* Spur #1 fractional numerator/denominator and 14-channel mask (stored LE) */
    chip6_phy_init_ctrl[PHY_CTRL_SPUR1_NUM_LO] = init_data[PHY_INIT_OFF_SPUR1_NUM_LO];
    chip6_phy_init_ctrl[PHY_CTRL_SPUR1_DEN] = init_data[PHY_INIT_OFF_SPUR1_DEN];

    uint16_t spur1_mask =
        (uint16_t)(((uint16_t)(init_data[PHY_INIT_OFF_SPUR1_MASK_HI] &
                               PHY_SPUR_MASK_HI_BITS) << 8) |
                   (uint16_t)init_data[PHY_INIT_OFF_SPUR1_MASK_LO]);
    chip6_phy_init_ctrl[PHY_CTRL_SPUR1_MASK_LO] = (uint8_t)(spur1_mask & 0xFFU);
    chip6_phy_init_ctrl[PHY_CTRL_SPUR1_MASK_HI] = (uint8_t)(spur1_mask >> 8);

    /* Validate Ch 1/11/13/14 power clamp indices into [0..5], defaulting invalid entries to 0 */
    for (uint32_t i = 0U; i < PHY_CH_CLAMP_COUNT; i++) {
        int8_t clamp_idx = (int8_t)init_data[PHY_INIT_OFF_CH_CLAMP_BASE + i];
        chip6_phy_init_ctrl[PHY_CTRL_CH_CLAMP_BASE + i] =
            (clamp_idx >= 0 && clamp_idx < (int)PHY_TARGET_PWR_COUNT)
                ? (uint8_t)clamp_idx
                : 0U;
    }

    /* Target TX power levels (6 x 0.25 dBm) and per-rate index mapping (8 rates) */
    for (uint32_t i = 0U; i < PHY_TARGET_PWR_COUNT; i++) {
        chip6_phy_init_ctrl[PHY_CTRL_TARGET_PWR_BASE + i] =
            init_data[PHY_INIT_OFF_TARGET_PWR_BASE + i];
    }
    for (uint32_t i = 0U; i < PHY_RATE_PWR_COUNT; i++) {
        chip6_phy_init_ctrl[PHY_CTRL_RATE_PWR_IDX_BASE + i] =
            init_data[PHY_INIT_OFF_RATE_PWR_IDX_BASE + i];
    }

    chip6_phy_init_ctrl[PHY_CTRL_XTAL_FREQ] = init_data[PHY_INIT_OFF_XTAL_FREQ];
    chip6_phy_init_ctrl[PHY_CTRL_BTCO_MODE] = init_data[PHY_INIT_OFF_BTCO_MODE];
    chip6_phy_init_ctrl[PHY_CTRL_BTCO_SUBMODE] = init_data[PHY_INIT_OFF_BTCO_SUBMODE];
    chip6_phy_init_ctrl[PHY_CTRL_ANT_SWITCH_MODE] = init_data[PHY_INIT_OFF_ANT_SWITCH_MODE];

    /* Spur #2 fractional config, upper numerator bytes, and fixed spurs #3/#4 */
    chip6_phy_init_ctrl[PHY_CTRL_SPUR2_NUM_LO] = init_data[PHY_INIT_OFF_SPUR2_NUM_LO];
    chip6_phy_init_ctrl[PHY_CTRL_SPUR2_DEN] = init_data[PHY_INIT_OFF_SPUR2_DEN];

    uint16_t spur2_mask =
        (uint16_t)(((uint16_t)(init_data[PHY_INIT_OFF_SPUR2_MASK_HI] &
                               PHY_SPUR_MASK_HI_BITS) << 8) |
                   (uint16_t)init_data[PHY_INIT_OFF_SPUR2_MASK_LO]);
    chip6_phy_init_ctrl[PHY_CTRL_SPUR2_MASK_LO] = (uint8_t)(spur2_mask & 0xFFU);
    chip6_phy_init_ctrl[PHY_CTRL_SPUR2_MASK_HI] = (uint8_t)(spur2_mask >> 8);

    chip6_phy_init_ctrl[PHY_CTRL_SPUR1_NUM_HI] = init_data[PHY_INIT_OFF_SPUR1_NUM_HI];
    chip6_phy_init_ctrl[PHY_CTRL_SPUR2_NUM_HI] = init_data[PHY_INIT_OFF_SPUR2_NUM_HI];
    chip6_phy_init_ctrl[PHY_CTRL_SPUR3_FREQ_LO] = init_data[PHY_INIT_OFF_SPUR3_FREQ_LO];
    chip6_phy_init_ctrl[PHY_CTRL_SPUR3_FREQ_HI] = init_data[PHY_INIT_OFF_SPUR3_FREQ_HI];
    chip6_phy_init_ctrl[PHY_CTRL_SPUR4_FREQ_LO] = init_data[PHY_INIT_OFF_SPUR4_FREQ_LO];
    chip6_phy_init_ctrl[PHY_CTRL_SPUR4_FREQ_HI] = init_data[PHY_INIT_OFF_SPUR4_FREQ_HI];

    /* Unpack FCC low-band and high-band edge-channel backoff parameters */
    chip6_phy_init_ctrl[PHY_CTRL_FCC_BACKOFF_EN] = init_data[PHY_INIT_OFF_FCC_BACKOFF_EN];

    uint8_t fcc_lo = init_data[PHY_INIT_OFF_FCC_LO_PACKED];
    uint8_t lo_idx = fcc_lo & 0x0FU;
    chip6_phy_init_ctrl[PHY_CTRL_FCC_LO_IDX] =
        (lo_idx > PHY_TARGET_PWR_MAX_IDX) ? PHY_TARGET_PWR_MAX_IDX : lo_idx;
    chip6_phy_init_ctrl[PHY_CTRL_FCC_LO_CNT] = (fcc_lo >> 4) & 0x07U;
    chip6_phy_init_ctrl[PHY_CTRL_FCC_LO_FLAG] = (fcc_lo >> 7) & 0x01U;

    uint8_t fcc_hi = init_data[PHY_INIT_OFF_FCC_HI_PACKED];
    uint8_t hi_idx = fcc_hi & 0x0FU;
    chip6_phy_init_ctrl[PHY_CTRL_FCC_HI_IDX] =
        (hi_idx > PHY_TARGET_PWR_MAX_IDX) ? PHY_TARGET_PWR_MAX_IDX : hi_idx;
    chip6_phy_init_ctrl[PHY_CTRL_FCC_HI_CNT] = (fcc_hi >> 4) & 0x07U;
    chip6_phy_init_ctrl[PHY_CTRL_FCC_INTERP_EN] = (fcc_hi >> 7) & 0x01U;

    chip6_phy_init_ctrl[PHY_CTRL_FCC_11B_HI_OFF] =
        (init_data[PHY_INIT_OFF_FCC_11B_PACKED] >> 4) & 0x0FU;
    chip6_phy_init_ctrl[PHY_CTRL_FCC_11B_LO_OFF] =
        init_data[PHY_INIT_OFF_FCC_11B_PACKED] & 0x0FU;
    chip6_phy_init_ctrl[PHY_CTRL_FCC_TEST_MODE] = init_data[PHY_INIT_OFF_FCC_TEST_MODE];

    /* CCA override, fixed low-power TX, 11b power indices, and BBPLL/VDD33/Ch14 options */
    chip6_phy_init_ctrl[PHY_CTRL_CCA_THRESH] = init_data[PHY_INIT_OFF_CCA_THRESH];
    chip6_phy_init_ctrl[PHY_CTRL_CCA_MODE] = init_data[PHY_INIT_OFF_CCA_MODE];

    chip6_phy_init_ctrl[PHY_CTRL_LOW_PWR_EN] = init_data[PHY_INIT_OFF_LOW_PWR_EN];
    chip6_phy_init_ctrl[PHY_CTRL_LOW_PWR_STAGE10] = init_data[PHY_INIT_OFF_LOW_PWR_STAGE10];
    chip6_phy_init_ctrl[PHY_CTRL_LOW_PWR_BB_DELTA] = init_data[PHY_INIT_OFF_LOW_PWR_BB_DELTA];
    chip6_phy_init_ctrl[PHY_CTRL_11B_PWR_EN] = init_data[PHY_INIT_OFF_11B_PWR_EN];
    chip6_phy_init_ctrl[PHY_CTRL_11B_1M2M_IDX] = init_data[PHY_INIT_OFF_11B_1M2M_IDX];
    chip6_phy_init_ctrl[PHY_CTRL_11B_5M11M_IDX] = init_data[PHY_INIT_OFF_11B_5M11M_IDX];
    chip6_phy_init_ctrl[PHY_CTRL_BG_PWCTRL_DIS] = init_data[PHY_INIT_OFF_BG_PWCTRL_DIS];
    chip6_phy_init_ctrl[PHY_CTRL_BBPLL160_OPT] = init_data[PHY_INIT_OFF_BBPLL160_OPT];

    chip6_phy_init_ctrl[PHY_CTRL_RSVD_45] = init_data[PHY_INIT_OFF_RSVD_45];
    chip6_phy_init_ctrl[PHY_CTRL_RSVD_46] = init_data[PHY_INIT_OFF_RSVD_46];
    chip6_phy_init_ctrl[PHY_CTRL_VDD33_CONST] = init_data[PHY_INIT_OFF_VDD33_CONST];
    chip6_phy_init_ctrl[PHY_CTRL_DSLP_RECAL_INT] = init_data[PHY_INIT_OFF_DSLP_RECAL_INT];
    chip6_phy_init_ctrl[PHY_CTRL_CH14_FREQ_EN] = init_data[PHY_INIT_OFF_CH14_FREQ_EN];
    chip6_phy_init_ctrl[PHY_CTRL_CH14_FREQ_LO] = init_data[PHY_INIT_OFF_CH14_FREQ_LO];
    chip6_phy_init_ctrl[PHY_CTRL_CH14_FREQ_HI] = init_data[PHY_INIT_OFF_CH14_FREQ_HI];

    /*
     * Crystal frequency-offset compensation is enabled only when freq_en is
     * 7 or 9 (tested via `(freq_en - 7) & ~2 == 0`) AND freq_val is strictly
     * negative; negative steps are clamped to >= -10 (-80 kHz).
     */
    uint8_t freq_en = init_data[PHY_INIT_OFF_FREQ_OFF_EN];
    int8_t freq_val = (int8_t)init_data[PHY_INIT_OFF_FREQ_OFF_VAL];
    if ((freq_en < PHY_FREQ_OFF_MIN_EN) || (freq_val >= 0) ||
        (((uint8_t)(freq_en - PHY_FREQ_OFF_VALID_BASE) & PHY_FREQ_OFF_VALID_MASK) != 0U)) {
        chip6_phy_init_ctrl[PHY_CTRL_FREQ_OFF_MODE] = 0U;
    } else {
        chip6_phy_init_ctrl[PHY_CTRL_FREQ_OFF_MODE] = PHY_FREQ_OFF_MODE_ACTIVE;
    }
    if (freq_val < PHY_FREQ_OFF_MIN_STEP) {
        freq_val = PHY_FREQ_OFF_MIN_STEP;
    }
    chip6_phy_init_ctrl[PHY_CTRL_FREQ_OFF_VAL] = (uint8_t)freq_val;
    chip6_phy_init_ctrl[PHY_CTRL_POWERUP_CAL_MODE] = init_data[PHY_INIT_OFF_POWERUP_CAL_MODE];

    return 0;
}
