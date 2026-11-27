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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "phy_internal.h"

/* --------------------------------------------------------------------------
 * File-Local Constants (Init Data Offsets, Control Modes & Bring-Up Defaults)
 * -------------------------------------------------------------------------- */

/* 128-byte esp_phy_init_data_t size and boot frequency-offset shift/mask */
#define PHY_INIT_DATA_SIZE              128U
#define PHY_FREQ_OFF_MODE_SHIFT_MASK    0x0CU /* Bits [3:2]: apply freq offset at boot */
#define PHY_FREQ_OFF_STEP_SHIFT         3     /* Convert 8 kHz steps to kHz */

/* Power-up calibration mode codes (PHY_RTC_SCRATCH3_REG / PHY_CTRL_POWERUP_CAL_MODE) */
#define PHY_POWERUP_CAL_DEFAULT         0U    /* Defer to init_data[0x72] */
#define PHY_POWERUP_CAL_PARTIAL         1U    /* Partial cal (keep noise floor valid) */
#define PHY_POWERUP_CAL_NO_CAL          2U    /* Skip RF cal when valid RTC cal exists */
#define PHY_POWERUP_CAL_FULL            3U    /* Force full RF calibration */

/* Deep-sleep wake RF option codes (PHY_RTC_RFOPTION_REG[23:16]) */
#define PHY_RFOPT_AUTO_INTERVAL         0U    /* Recalibrate every DSLP_RECAL_INT wakes */
#define PHY_RFOPT_NO_CAL                2U    /* Skip RF cal after deep-sleep wake */
#define PHY_RFOPT_RF_DISABLED           4U    /* Keep RF off after deep-sleep wake */

/* Baseband bring-up, checksum, and runtime override constants */
#define PHY_CH14_MIC_MAX_POWER_QDB      52U   /* Default Ch 14 MIC cap (13.0 dBm) */
#define PHY_RFCAL_BB_ATTEN_INIT_DEFAULT 0x3CU
#define PHY_I2C_RX_ANA_BB_INIT_REG      7U
#define PHY_I2C_RX_ANA_BB_INIT_VAL      0x51U
#define PHY_CAL_DEFAULT_CHAN            6U    /* Mid-band channel for RX table renew */
#define PHY_NOISE_INIT_TIMEOUT_US       0x7800U
#define PHY_FCC_TEST_CONT_TX            1U
#define PHY_PARAM_CAL_VALID_MASK        0x00FF0000U /* All 8 cal-valid bits [23:16] */
#define PHY_PARAM_RX_GAIN_VALID_SHIFT   16U
#define PHY_EFUSE_CHIP_ID_L_SHIFT       16U
#define PHY_RTC_PHY_VER_MASK            0xFFFF0000U
#define PHY_CCA_MODE_THRESH             3U
#define PHY_CCA_MODE_THRESH_COMP        4U
#define PHY_MAC_DEBUG_PATTERN_MODE      2U

/* --------------------------------------------------------------------------
 * Exported Globals Owned by phy_core.c (Explicitly Initialized, 0 COMMON)
 * -------------------------------------------------------------------------- */

uint32_t *phy_rx_gain_dc_table = NULL;

/* --------------------------------------------------------------------------
 * Internal Cross-TU Globals Owned by phy_core.c (Explicitly Initialized)
 * -------------------------------------------------------------------------- */

phy_sleep_params_t g_phy_sleep_params = {
    .rf_ana_gain = PHY_TX_RF_ANA_GAIN_DEFAULT,
};
uint8_t g_phy_rx_table_renew_en = 0U;
uint8_t g_phy_init_rf_no_cal = 0U;
int16_t g_phy_freq_offset = 0;
const uint8_t *g_phy_rx_gain_swp_step = NULL;
uint8_t g_phy_rxmax_ext_level = 0U;
uint8_t g_phy_rx_max_gain_val = PHY_BB_RX_MAX_GAIN_CAP;
uint8_t g_phy_chan14_mic_en = 0U;
uint8_t g_phy_chan14_mic_most_power = PHY_CH14_MIC_MAX_POWER_QDB;
uint8_t g_phy_rfcal_bb_atten_init = PHY_RFCAL_BB_ATTEN_INIT_DEFAULT;
uint32_t g_phy_check_result = 0U;

/* --------------------------------------------------------------------------
 * File-Local Static State
 * -------------------------------------------------------------------------- */

static uint8_t s_re_entry = 0U;
static uint32_t s_test_print_time = 0U;

/* --------------------------------------------------------------------------
 * RTC Calibration RAM Backup, Recovery & Checksum Helpers
 * -------------------------------------------------------------------------- */

/**
 * @brief Copy a word-aligned byte range from RAM into RTC PHY calibration memory.
 *
 * @param src      Source buffer in system RAM.
 * @param byte_len Number of bytes to copy (must be a multiple of 4).
 * @param rtc_off  Destination byte offset from `PHY_RTC_PHY_CAL_RAM_BASE` (multiple of 4).
 */
static void phy_rtc_mem_backup_range(const void *src, uint32_t byte_len, uint32_t rtc_off)
{
    const uint8_t *p = (const uint8_t *)src;
    uint32_t words = byte_len / 4U;
    uint32_t base_word = rtc_off / 4U;

    for (uint32_t i = 0U; i < words; i++) {
        uint32_t w;
        memcpy(&w, p + i * 4U, sizeof(w));
        PHY_REG_WRITE(PHY_RTC_PHY_CAL_RAM_REG(base_word + i), w);
    }
}

/**
 * @brief Copy a word-aligned byte range from RTC PHY calibration memory into RAM.
 *
 * @param[out] dst      Destination buffer in system RAM.
 * @param      byte_len Number of bytes to read (must be a multiple of 4).
 * @param      rtc_off  Source byte offset from `PHY_RTC_PHY_CAL_RAM_BASE` (multiple of 4).
 */
static void phy_rtc_mem_recovery_range(void *dst, uint32_t byte_len, uint32_t rtc_off)
{
    uint8_t *p = (uint8_t *)dst;
    uint32_t words = byte_len / 4U;
    uint32_t base_word = rtc_off / 4U;

    for (uint32_t i = 0U; i < words; i++) {
        uint32_t w = PHY_REG_READ(PHY_RTC_PHY_CAL_RAM_REG(base_word + i));
        memcpy(p + i * 4U, &w, sizeof(w));
    }
}

/**
 * @brief Persist Chunk 1 (bytes `0x00..0x53`, W0..W20) of `g_phy_sleep_params` to RTC RAM.
 */
void phy_rtc_mem_backup_chunk1(void)
{
    phy_rtc_mem_backup_range(&g_phy_sleep_params, PHY_RTC_CHUNK1_BYTES, 0U);
}

/**
 * @brief Persist Chunk 2 (bytes `0x54..0x5F`, W21..W23) of `g_phy_sleep_params` to RTC RAM.
 */
void phy_rtc_mem_backup_chunk2(void)
{
    const uint8_t *base = (const uint8_t *)&g_phy_sleep_params;
    phy_rtc_mem_backup_range(base + PHY_RTC_CHUNK2_OFFSET,
                             PHY_RTC_CHUNK2_BYTES, PHY_RTC_CHUNK2_OFFSET);
}

/**
 * @brief Restore Chunk 1 (bytes `0x00..0x53`, W0..W20) of `g_phy_sleep_params` from RTC RAM.
 */
void phy_rtc_mem_recovery_chunk1(void)
{
    phy_rtc_mem_recovery_range(&g_phy_sleep_params, PHY_RTC_CHUNK1_BYTES, 0U);
}

/**
 * @brief Restore Chunk 2 (bytes `0x54..0x5F`, W21..W23) of `g_phy_sleep_params` from RTC RAM.
 */
void phy_rtc_mem_recovery_chunk2(void)
{
    uint8_t *base = (uint8_t *)&g_phy_sleep_params;
    phy_rtc_mem_recovery_range(base + PHY_RTC_CHUNK2_OFFSET,
                               PHY_RTC_CHUNK2_BYTES, PHY_RTC_CHUNK2_OFFSET);
}

/**
 * @brief Compute or verify the ones'-complement checksum over RTC calibration words W0..W25.
 *
 * Covers `g_phy_sleep_params` (W0..W23) plus the stored eFuse chip ID (W24..W25),
 * storing or comparing against `PHY_RTC_CAL_CHKSUM_REG` (W26).
 *
 * @param verify_only Zero to write the computed checksum to W26; non-zero to verify W26.
 * @return            `false` when writing or when verification succeeds; `true` on checksum mismatch.
 */
bool phy_rtc_mem_check(uint8_t verify_only)
{
    uint32_t sum = 0U;

    for (uint32_t w = 0U; w < PHY_RTC_CAL_CHKSUM_WORDS; w++) {
        sum += PHY_REG_READ(PHY_RTC_PHY_CAL_RAM_REG(w));
    }

    uint32_t expected = ~sum;
    if (verify_only == 0U) {
        PHY_REG_WRITE(PHY_RTC_CAL_CHKSUM_REG, expected);
        return false;
    }

    return (PHY_REG_READ(PHY_RTC_CAL_CHKSUM_REG) != expected);
}

/* --------------------------------------------------------------------------
 * Exported RTC Storage, Checksum & Option APIs
 * -------------------------------------------------------------------------- */

/**
 * @brief Update or verify the trailing ones'-complement checksum word of a 32-bit table.
 *
 * Used primarily to protect the 125-word `phy_rx_gain_dc_table` (124 data words
 * followed by `table[124] = ~sum(table[0..123])`).
 *
 * @param[in,out] table Pointer to an array of `len` 32-bit words; last word holds checksum.
 * @param         len   Total number of 32-bit words including the trailing checksum word.
 * @param         mode  Zero to write the checksum into `table[len - 1]`; non-zero to verify.
 * @return              `0` on success (or write), `1` on invalid arguments or checksum mismatch.
 */
uint8_t phy_check_data_table(uint32_t *table, uint8_t len, uint8_t mode)
{
    if (table == NULL || len == 0U) {
        return 1U;
    }

    uint32_t sum = 0U;
    uint32_t count = (uint32_t)len - 1U;
    for (uint32_t i = 0U; i < count; i++) {
        sum += table[i];
    }

    uint32_t expected = ~sum;
    if (mode == 0U) {
        table[count] = expected;
        return 0U;
    }

    return (table[count] != expected) ? 1U : 0U;
}

/**
 * @brief Write a 128-byte little-endian PHY calibration blob into RTC RAM (W0..W31).
 *
 * @param cal_data_128 Pointer to 128 bytes of calibration data (alignment-safe byte reads).
 */
void write_data_to_rtc(uint8_t *cal_data_128)
{
    for (uint32_t w = 0U; w < PHY_RTC_CAL_DATA_WORDS; w++) {
        const uint8_t *p = cal_data_128 + w * 4U;
        uint32_t val = (uint32_t)p[0] |
                       ((uint32_t)p[1] << 8) |
                       ((uint32_t)p[2] << 16) |
                       ((uint32_t)p[3] << 24);
        PHY_REG_WRITE(PHY_RTC_PHY_CAL_RAM_REG(w), val);
    }
}

/**
 * @brief Read the 128-byte RTC PHY calibration block (W0..W31) into a byte buffer.
 *
 * @param[out] cal_data_128 Destination buffer of at least 128 bytes (little-endian).
 */
void get_data_from_rtc(uint8_t *cal_data_128)
{
    for (uint32_t w = 0U; w < PHY_RTC_CAL_DATA_WORDS; w++) {
        uint32_t val = PHY_REG_READ(PHY_RTC_PHY_CAL_RAM_REG(w));
        uint8_t *p = cal_data_128 + w * 4U;
        p[0] = (uint8_t)(val & 0xFFU);
        p[1] = (uint8_t)((val >> 8) & 0xFFU);
        p[2] = (uint8_t)((val >> 16) & 0xFFU);
        p[3] = (uint8_t)((val >> 24) & 0xFFU);
    }
}

/**
 * @brief Store the post-deep-sleep RF calibration option without updating the RTC checksum.
 *
 * Writes `option` into `PHY_RTC_RFOPTION_REG[31:16]` while preserving the
 * deep-sleep wakeup counter in bits `[15:0]`.
 *
 * @param option Deep-sleep RF option (`0`=interval auto, `1`=force cal, `2`=no cal, `4`=RF off).
 */
void phy_afterwake_set_rfoption(uint8_t option)
{
    PHY_REG_RMW(PHY_RTC_RFOPTION_REG, PHY_RTC_RFOPTION_MASK,
                (uint32_t)option << PHY_RTC_RFOPTION_SHIFT);
}

/**
 * @brief Store the deep-sleep RF calibration option and refresh the RTC calibration checksum.
 *
 * @param option Deep-sleep RF option (`0`=interval auto, `1`=force cal, `2`=no cal, `4`=RF off).
 */
void deep_sleep_set_option(uint8_t option)
{
    PHY_REG_RMW(PHY_RTC_RFOPTION_REG, PHY_RTC_RFOPTION_MASK,
                (uint32_t)option << PHY_RTC_RFOPTION_SHIFT);
    (void)phy_rtc_mem_check(0U);
}

/**
 * @brief Set the power-up RF calibration mode override in `PHY_RTC_SCRATCH3_REG`.
 *
 * @param option Calibration mode (`0`=use init_data, `1`=partial, `2`=no cal, `3`=full cal).
 */
void phy_set_powerup_option(uint8_t option)
{
    PHY_REG_WRITE(PHY_RTC_SCRATCH3_REG, (uint32_t)option);
}

/* --------------------------------------------------------------------------
 * Baseband Calibration Sequence & Top-Level PHY Bring-Up
 * -------------------------------------------------------------------------- */

/**
 * @brief Run the ordered baseband initialization and RF calibration pipeline.
 *
 * Bring-up order is dependency-driven:
 * 1. Analog RX front-end init, PBUS SoC timing config, and TXIQ sign enable.
 * 2. RC filter calibration (`phy_rc_cal`) and TX DC offset calibration.
 * 3. One-time VDD33 TX power offset compensation, TX PA capacitor calibration,
 *    and TX power-control LUT initialization (skipped when fixed low-power mode
 *    is enabled).
 * 4. TX IQ imbalance calibration using the calibrated high-band attenuation.
 * 5. Optional Ch 6 retune for RX gain/DC table renewal, baseband RX config, and
 *    asserting `PHY_MAC_PHY_RF_UP` to release the MAC-to-PHY handshake.
 * 6. Initial noise-floor measurement, background TX power-tracking arm, sleep
 *    wakeup-exit channel restore, DPD bypass, fixed low-power override, and
 *    FCC continuous-TX test-mode switch.
 *
 * @return Always `0`.
 */
int phy_initialize_bb(void)
{
    /* Stage 1: Base analog RX, PBUS timing, and TXIQ gain-sign interface setup */
    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_ANA, PHY_I2C_HOST_1,
                     PHY_I2C_RX_ANA_BB_INIT_REG, PHY_I2C_RX_ANA_BB_INIT_VAL);
    phy_pbus_soc_cfg();
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                          PHY_I2C_ANA_INF_TXIQ_G_REG, 0U, 0U, 1U);

    /* Stage 2: RC filter & TX DC offset calibration */
    phy_rc_cal();
    phy_init_cal_dcoffset(&g_phy_sleep_params.param_flag, g_phy_sleep_params.txdc);

    /* Stage 3: Apply VDD33 TX power offset once, then calibrate PA caps and TX power control */
    if ((g_phy_sleep_params.param_flag & PHY_PARAM_VDD33_APPLIED) == 0U) {
        phy_txpwr_offset(0);
        g_phy_sleep_params.param_flag |= PHY_PARAM_VDD33_APPLIED;
    }

    phy_tx_cap_init();
    phy_tx_pwctrl_init(chip6_phy_init_ctrl[PHY_CTRL_LOW_PWR_EN] == 0U ? 1U : 0U);

    /* Stage 4: Calibrate TX IQ imbalance using calibrated attenuation slot [3][3] + bias */
    int8_t txiq_atten =
        (int8_t)(g_phy_sleep_params.tx_pwctrl_atten[3][3] + (int32_t)PHY_CAL_BB_ATTEN_BIAS);
    if (txiq_atten < 0) {
        txiq_atten = 0;
    }
    phy_rfcal_txiq(&g_phy_sleep_params.param_flag, &g_phy_sleep_params.txiq,
                   g_phy_sleep_params.rf_ana_gain, PHY_TONE_FREQ_CAL_DEFAULT,
                   txiq_atten, 0U, 0U, 1U);

    /* Stage 5: Optional mid-band retune for RX gain table renewal, then enable BB RX & MAC */
    if (g_phy_rx_table_renew_en != 0U) {
        phy_set_chan(PHY_CAL_DEFAULT_CHAN);
    }

    phy_bb_rx_cfg();
    PHY_REG_SET(PHY_MAC_PHY_CTRL_REG, PHY_MAC_PHY_RF_UP);

    /* Stage 6: Noise floor, background TX tracking, wakeup channel restore, DPD & test modes */
    phy_noise_init(1U, 7U, 5U, PHY_NOISE_INIT_TIMEOUT_US, 1U, 0U,
                   &g_phy_sleep_params.param_flag);
    phy_tx_pwctrl_bg_init();

    if ((g_phy_sleep_params.param_flag & PHY_PARAM_WAKEUP_RF) != 0U) {
        phy_set_chan_wakeup_exit(g_phy_sleep_params.cur_chan);
    }

    phy_dpd_bypass();
    phy_low_power_set(chip6_phy_init_ctrl[PHY_CTRL_LOW_PWR_EN],
                      chip6_phy_init_ctrl[PHY_CTRL_LOW_PWR_STAGE10],
                      chip6_phy_init_ctrl[PHY_CTRL_LOW_PWR_BB_DELTA]);

    if (chip6_phy_init_ctrl[PHY_CTRL_FCC_TEST_MODE] == PHY_FCC_TEST_CONT_TX) {
        phy_tx_cont_en();
    } else {
        phy_tx_cont_dis();
    }

    return 0;
}

/**
 * @brief Top-level ESP8266 PHY registration, calibration recovery, and RF/baseband bring-up.
 *
 * Manages three distinct lifecycle paths via `s_re_entry`, RTC reset reason,
 * and `PHY_RTC_DEEPSLEEP_MAGIC_REG`:
 * - **Cold boot** (`s_re_entry == 0`, not deep sleep): parses `init_data_256[0..127]`,
 *   optionally seeds RTC cal RAM from `init_data_256[128..255]` (`opt < 3`),
 *   verifies the 64-bit eFuse chip ID and RTC checksum, runs partial/no-cal/full
 *   bring-up, persists updated calibration to RTC RAM, and exports fresh cal
 *   data back to `init_data_256[128..255]` when calibration ran from scratch.
 * - **Deep-sleep wake** (`s_re_entry == 0`, reset reason `2` & magic `5`): honors
 *   `PHY_RTC_RFOPTION_REG` (`2`=no cal, `4`=RF disabled, `0`=recalibrate every
 *   `PHY_CTRL_DSLP_RECAL_INT` wakes) and updates the wake counter in bits `[15:0]`.
 * - **Re-entry** (`s_re_entry == 1`): preserves `cur_chan`, recovers RTC cal if
 *   any calibration-valid bit `[23:16]` was cleared, brings up RF/BB, and
 *   retunes to the saved channel unless waking via `PHY_PARAM_WAKEUP_RF`.
 *
 * @param[in,out] init_data_256 256-byte buffer: `[0..127]` holds `esp_phy_init_data_t`;
 *                              `[128..255]` holds persistent RTC calibration data (read
 *                              on cold boot if `opt < 3`, updated when freshly calibrated).
 * @return                      `0` on success (propagated from `register_chipv6_phy_init_param`).
 */
int register_chipv6_phy(uint8_t *init_data_256)
{
    int ret = 0;
    uint8_t saved_chan = 1U;

    g_phy_sleep_mode_flag = 0U;
    phy_fix_cache_bug();

    if (s_re_entry == 0U) {
        ret = register_chipv6_phy_init_param(init_data_256);
        g_phy_in_most_power = chip6_phy_init_ctrl[PHY_CTRL_TARGET_PWR_BASE];
    } else {
        saved_chan = g_phy_sleep_params.cur_chan;
    }

    phy_set_crystal_uart();
    phy_ant_switch_init();
    if (s_re_entry == 0U) {
        phy_gpio_cfg();
    }
    phy_tx_cont_dis();

    uint8_t re_entry = s_re_entry;
    if (re_entry == 0U &&
        (chip6_phy_init_ctrl[PHY_CTRL_FREQ_OFF_MODE] & PHY_FREQ_OFF_MODE_SHIFT_MASK) != 0U) {
        g_phy_freq_offset =
            (int16_t)((int32_t)(int8_t)chip6_phy_init_ctrl[PHY_CTRL_FREQ_OFF_VAL] <<
                      PHY_FREQ_OFF_STEP_SHIFT);
    }

    /* Resolve effective power-up cal mode (SCRATCH3 override takes precedence over init_data) */
    uint8_t opt = (uint8_t)(PHY_REG_READ(PHY_RTC_SCRATCH3_REG) & 0xFFU);
    if (chip6_phy_init_ctrl[PHY_CTRL_POWERUP_CAL_MODE] == PHY_POWERUP_CAL_NO_CAL) {
        chip6_phy_init_ctrl[PHY_CTRL_POWERUP_CAL_MODE] = PHY_POWERUP_CAL_PARTIAL;
    }
    if (opt == PHY_POWERUP_CAL_DEFAULT) {
        opt = chip6_phy_init_ctrl[PHY_CTRL_POWERUP_CAL_MODE];
    }

    uint8_t is_partial = (opt < PHY_POWERUP_CAL_NO_CAL) ? 1U : 0U;
    uint8_t is_no_cal = (opt == PHY_POWERUP_CAL_NO_CAL) ? 1U : 0U;

    /* Detect confirmed deep-sleep wakeup via both RTC reset reason and magic marker */
    uint8_t is_deepsleep = 0U;
    if (re_entry == 0U &&
        (PHY_REG_READ(PHY_RTC_RESET_REASON_REG) & PHY_RTC_RESET_REASON_MASK) ==
            PHY_RTC_RESET_DEEPSLEEP) {
        if (PHY_REG_READ(PHY_RTC_DEEPSLEEP_MAGIC_REG) == PHY_RTC_DEEPSLEEP_MAGIC_VAL) {
            is_deepsleep = 1U;
        }
    }

    /* On cold boot (unless full cal requested), seed RTC cal RAM from init_data_256[128..255] */
    uint8_t is_cold_boot = (re_entry == 0U && is_deepsleep == 0U) ? 1U : 0U;
    if (is_cold_boot != 0U && opt < PHY_POWERUP_CAL_FULL) {
        write_data_to_rtc(init_data_256 + PHY_INIT_DATA_SIZE);
    }

    /*
     * Assemble the 64-bit eFuse chip ID across all four eFuse words to ensure
     * persisted RTC/flash calibration data matches this exact physical die:
     *   chip_id_l = DATA2[15:12] << 16 | DATA1[27:0]
     *   chip_id_h = DATA0[31:24]       | DATA3[23:0]
     */
    uint32_t chip_id_l = 0U;
    uint32_t chip_id_h = 0U;
    bool id_mismatch = false;

    if (re_entry == 0U) {
        chip_id_l = ((PHY_REG_READ(PHY_EFUSE_DATA2_REG) & PHY_EFUSE_CHIP_ID_L_EF2_MASK) <<
                     PHY_EFUSE_CHIP_ID_L_SHIFT) |
                    (PHY_REG_READ(PHY_EFUSE_DATA1_REG) & PHY_EFUSE_CHIP_ID_L_EF1_MASK);
        chip_id_h = (PHY_REG_READ(PHY_EFUSE_DATA0_REG) & PHY_EFUSE_CHIP_ID_H_EF0_MASK) |
                    (PHY_REG_READ(PHY_EFUSE_DATA3_REG) & PHY_EFUSE_CHIP_ID_H_EF3_MASK);

        id_mismatch = (chip_id_l != PHY_REG_READ(PHY_RTC_CHIP_ID_L_REG)) ||
                      (chip_id_h != PHY_REG_READ(PHY_RTC_CHIP_ID_H_REG));
    }

    /* Process deep-sleep RF option and periodic deep-sleep recalibration wake counter */
    bool rf_disabled = false;
    if (is_deepsleep == 0U) {
        if (re_entry == 0U) {
            PHY_REG_RMW(PHY_RTC_RFOPTION_REG, PHY_RTC_RFOPTION_CNT_MASK, 0U);
        }
    } else {
        uint32_t rfopt_reg = PHY_REG_READ(PHY_RTC_RFOPTION_REG);
        uint8_t rfopt = (uint8_t)((rfopt_reg >> PHY_RTC_RFOPTION_SHIFT) & 0xFFU);

        if (rfopt == PHY_RFOPT_NO_CAL) {
            is_no_cal = 1U;
        }
        rf_disabled = (rfopt == PHY_RFOPT_RF_DISABLED);

        if (re_entry == 0U) {
            uint32_t cnt = rfopt_reg & PHY_RTC_RFOPTION_CNT_MASK;
            uint32_t new_cnt = 0U;

            if (rfopt == PHY_RFOPT_AUTO_INTERVAL &&
                chip6_phy_init_ctrl[PHY_CTRL_DSLP_RECAL_INT] != 0U) {
                if (cnt < chip6_phy_init_ctrl[PHY_CTRL_DSLP_RECAL_INT]) {
                    is_no_cal = 1U;
                    new_cnt = (cnt + 1U) & PHY_RTC_RFOPTION_CNT_MASK;
                }
            } else {
                new_cnt = (cnt + 1U) & PHY_RTC_RFOPTION_CNT_MASK;
            }
            PHY_REG_RMW(PHY_RTC_RFOPTION_REG, PHY_RTC_RFOPTION_CNT_MASK, new_cnt);
        }
    }

    /* Recover cached calibration from RTC RAM if permitted and checksum + chip ID match */
    uint8_t cal_loaded = 0U;
    bool try_recover = false;
    if (!rf_disabled && re_entry == 0U && (is_no_cal != 0U || is_partial != 0U)) {
        try_recover = true;
    } else if (re_entry == 1U &&
               (g_phy_sleep_params.param_flag & PHY_PARAM_CAL_VALID_MASK) !=
                   PHY_PARAM_CAL_VALID_MASK) {
        try_recover = true;
    }

    if (try_recover) {
        bool chk_err = phy_rtc_mem_check(1U);
        if (!id_mismatch && !chk_err) {
            phy_rtc_mem_recovery_chunk1();
            phy_rtc_mem_recovery_chunk2();
            cal_loaded = 1U;

            if (re_entry == 0U) {
                if (is_no_cal == 0U) {
                    /* Partial cal: invalidate RF cal bits, keep noise flag with -96 dBm floor */
                    if (opt < PHY_POWERUP_CAL_NO_CAL) {
                        g_phy_sleep_params.param_flag = PHY_PARAM_NOISE_VALID;
                        g_phy_sleep_params.rx_noise = PHY_NOISE_FLOOR_PARTIAL_QDB;
                    }
                } else if (is_cold_boot != 0U) {
                    /* Cold-boot no-cal: force fresh VDD33 TX power offset application */
                    g_phy_sleep_params.param_flag &= ~PHY_PARAM_VDD33_APPLIED;
                }
            }
        }
    }

    g_phy_init_rf_no_cal = (uint8_t)(is_no_cal & cal_loaded);

    /* Renew RX gain/DC table unless an intact table exists and PHY_PARAM_RX_GAIN_VALID is set */
    g_phy_rx_table_renew_en = 1U;
    if (phy_rx_gain_dc_table != NULL &&
        phy_check_data_table(phy_rx_gain_dc_table, PHY_RX_GAIN_DC_TABLE_WORDS, 1U) == 0U) {
        g_phy_rx_table_renew_en =
            (uint8_t)(((g_phy_sleep_params.param_flag >> PHY_PARAM_RX_GAIN_VALID_SHIFT) ^ 1U) &
                      1U);
    }

    /* Bring up RF + baseband (or park RF in reduced-current state if rf_disabled) */
    uint32_t t0 = phy_get_mactime();
    if (rf_disabled) {
        phy_reduce_current_init();
    } else {
        (void)phy_rf_init();
        (void)phy_initialize_bb();
    }
    s_test_print_time = phy_get_mactime() - t0;

    if (g_phy_rx_table_renew_en != 0U && phy_rx_gain_dc_table != NULL) {
        (void)phy_check_data_table(phy_rx_gain_dc_table, PHY_RX_GAIN_DC_TABLE_WORDS, 0U);
    }

    /* Restore saved channel on re-entry, or snapshot fresh calibration + chip ID to RTC RAM */
    if (s_re_entry == 1U) {
        if ((g_phy_sleep_params.param_flag & PHY_PARAM_WAKEUP_RF) == 0U) {
            phy_set_chan(saved_chan);
        }
    } else if (!rf_disabled) {
        phy_rtc_mem_backup_chunk1();
        phy_rtc_mem_backup_chunk2();
        PHY_REG_WRITE(PHY_RTC_CHIP_ID_L_REG, chip_id_l);
        PHY_REG_WRITE(PHY_RTC_CHIP_ID_H_REG, chip_id_h);
        (void)phy_rtc_mem_check(0U);
        g_phy_sleep_params.param_flag |= PHY_PARAM_BOOT_DONE;
    }

    PHY_REG_RMW(PHY_RTC_PHY_VER_REG, PHY_RTC_PHY_VER_MASK, PHY_VER_1167_0_WORD);

    /* Export freshly generated cold-boot cal data back to caller's buffer (cal_loaded==0 && cold) */
    if (cal_loaded < is_cold_boot) {
        get_data_from_rtc(init_data_256 + PHY_INIT_DATA_SIZE);
    }

    /* Apply optional CCA threshold and MAC debug test-pattern overrides from init_data */
    if (chip6_phy_init_ctrl[PHY_CTRL_CCA_MODE] == PHY_CCA_MODE_THRESH) {
        PHY_REG_RMW(PHY_BB_NOISE_FLOOR_REG, PHY_BB_NOISE_FLOOR_CCA_MASK,
                    (uint32_t)chip6_phy_init_ctrl[PHY_CTRL_CCA_THRESH] <<
                        PHY_BB_NOISE_FLOOR_CCA_SHIFT);
    } else if (chip6_phy_init_ctrl[PHY_CTRL_CCA_MODE] == PHY_CCA_MODE_THRESH_COMP) {
        PHY_REG_RMW(PHY_BB_NOISE_FLOOR_REG, PHY_BB_NOISE_FLOOR_CCA_MASK,
                    (uint32_t)chip6_phy_init_ctrl[PHY_CTRL_CCA_THRESH] <<
                        PHY_BB_NOISE_FLOOR_CCA_SHIFT);
        PHY_REG_SET(PHY_BB_RX_CHAN_COMP_REG, PHY_BB_RX_CHAN_COMP_CCA_BIT);
    }

    if (chip6_phy_init_ctrl[PHY_CTRL_MAC_DEBUG_MODE] == PHY_MAC_DEBUG_PATTERN_MODE) {
        PHY_REG_WRITE(PHY_MAC_DEBUG_REG, PHY_MAC_DEBUG_TEST_PATTERN);
    }

    if ((g_phy_sleep_params.param_flag & PHY_PARAM_WAKEUP_RF) != 0U) {
        phy_sleep_set_rxpbus(1U);
    }

    s_re_entry = 1U;
    return ret;
}
