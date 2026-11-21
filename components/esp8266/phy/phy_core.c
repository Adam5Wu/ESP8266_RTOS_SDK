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
 * Exported Globals Owned by phy_core.c (Explicitly Initialized, 0 COMMON)
 * -------------------------------------------------------------------------- */

uint8_t chip6_phy_init_ctrl[80] = { 0 };
uint32_t *phy_rx_gain_dc_table = NULL;

/* --------------------------------------------------------------------------
 * Internal Cross-TU Globals Owned by phy_core.c (Explicitly Initialized)
 * -------------------------------------------------------------------------- */

phy_sleep_params_t g_phy_sleep_params = {
    .rf_ana_gain = 0x0BF0U,
};
uint8_t g_phy_sleep_mode_flag = 0U;
uint8_t g_phy_wakeup_rf_flag = 0U;
uint8_t g_phy_rx_table_renew_en = 0U;
uint8_t g_phy_init_rf_no_cal = 0U;
int16_t g_phy_freq_offset = 0;
const uint8_t *g_phy_rx_gain_swp_step = NULL;
uint8_t g_phy_rxmax_ext_level = 0U;
uint8_t g_phy_rx_max_gain_val = 0x55U;
uint8_t g_phy_chan14_mic_en = 0U;
uint8_t g_phy_chan14_mic_most_power = 52U;
uint8_t g_phy_rfcal_bb_atten_init = 0x3CU;
uint32_t g_phy_check_result = 0U;

/* --------------------------------------------------------------------------
 * File-Local Static State
 * -------------------------------------------------------------------------- */

static uint8_t s_re_entry = 0U;
static uint32_t s_test_print_time = 0U;

/* --------------------------------------------------------------------------
 * RTC Calibration RAM Backup, Recovery & Checksum Helpers
 * -------------------------------------------------------------------------- */

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

void phy_rtc_mem_backup_chunk1(void)
{
    phy_rtc_mem_backup_range(&g_phy_sleep_params, PHY_RTC_CHUNK1_BYTES, 0U);
}

void phy_rtc_mem_backup_chunk2(void)
{
    const uint8_t *base = (const uint8_t *)&g_phy_sleep_params;
    phy_rtc_mem_backup_range(base + PHY_RTC_CHUNK2_OFFSET,
                             PHY_RTC_CHUNK2_BYTES, PHY_RTC_CHUNK2_OFFSET);
}

void phy_rtc_mem_recovery_chunk1(void)
{
    phy_rtc_mem_recovery_range(&g_phy_sleep_params, PHY_RTC_CHUNK1_BYTES, 0U);
}

void phy_rtc_mem_recovery_chunk2(void)
{
    uint8_t *base = (uint8_t *)&g_phy_sleep_params;
    phy_rtc_mem_recovery_range(base + PHY_RTC_CHUNK2_OFFSET,
                               PHY_RTC_CHUNK2_BYTES, PHY_RTC_CHUNK2_OFFSET);
}

bool phy_rtc_mem_check(uint8_t verify_only)
{
    uint32_t sum = 0U;

    for (uint32_t w = 0U; w < 26U; w++) {
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

void write_data_to_rtc(uint8_t *cal_data_128)
{
    for (uint32_t w = 0U; w < 32U; w++) {
        const uint8_t *p = cal_data_128 + w * 4U;
        uint32_t val = (uint32_t)p[0] |
                       ((uint32_t)p[1] << 8) |
                       ((uint32_t)p[2] << 16) |
                       ((uint32_t)p[3] << 24);
        PHY_REG_WRITE(PHY_RTC_PHY_CAL_RAM_REG(w), val);
    }
}

void get_data_from_rtc(uint8_t *cal_data_128)
{
    for (uint32_t w = 0U; w < 32U; w++) {
        uint32_t val = PHY_REG_READ(PHY_RTC_PHY_CAL_RAM_REG(w));
        uint8_t *p = cal_data_128 + w * 4U;
        p[0] = (uint8_t)(val & 0xFFU);
        p[1] = (uint8_t)((val >> 8) & 0xFFU);
        p[2] = (uint8_t)((val >> 16) & 0xFFU);
        p[3] = (uint8_t)((val >> 24) & 0xFFU);
    }
}

void phy_afterwake_set_rfoption(uint8_t option)
{
    PHY_REG_RMW(PHY_RTC_RFOPTION_REG, 0xFFFF0000U, (uint32_t)option << 16);
}

void deep_sleep_set_option(uint8_t option)
{
    PHY_REG_RMW(PHY_RTC_RFOPTION_REG, 0xFFFF0000U, (uint32_t)option << 16);
    (void)phy_rtc_mem_check(0U);
}

void phy_set_powerup_option(uint8_t option)
{
    PHY_REG_WRITE(PHY_RTC_SCRATCH3_REG, (uint32_t)option);
}

/* --------------------------------------------------------------------------
 * 128-Byte esp_phy_init_data_t Parser
 * -------------------------------------------------------------------------- */

int register_chipv6_phy_init_param(const uint8_t *init_data)
{
    g_phy_rx_gain_swp_step = init_data + 2;

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

/* --------------------------------------------------------------------------
 * Baseband Calibration Sequence & Top-Level PHY Bring-Up
 * -------------------------------------------------------------------------- */

int phy_initialize_bb(void)
{
    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_ANA, PHY_I2C_HOST_1, 7U, 0x51U);
    phy_pbus_soc_cfg();
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x10U, 0U, 0U, 1U);

    phy_rc_cal();
    phy_init_cal_dcoffset(&g_phy_sleep_params.param_flag, g_phy_sleep_params.txdc);

    if ((g_phy_sleep_params.param_flag & PHY_PARAM_VDD33_APPLIED) == 0U) {
        phy_txpwr_offset(0);
        g_phy_sleep_params.param_flag |= PHY_PARAM_VDD33_APPLIED;
    }

    phy_tx_cap_init();
    phy_tx_pwctrl_init(chip6_phy_init_ctrl[0x3D] == 0U ? 1U : 0U);

    int8_t txiq_atten = (int8_t)(g_phy_sleep_params.tx_pwctrl_atten[3][3] + 31);
    if (txiq_atten < 0) {
        txiq_atten = 0;
    }
    phy_rfcal_txiq(&g_phy_sleep_params.param_flag, &g_phy_sleep_params.txiq,
                   g_phy_sleep_params.rf_ana_gain, 0x40U, txiq_atten, 0U, 0U, 1U);

    if (g_phy_rx_table_renew_en != 0U) {
        phy_set_chan(6U);
    }

    phy_bb_rx_cfg();
    PHY_REG_SET(PHY_MAC_PHY_CTRL_REG, PHY_MAC_PHY_RF_UP);

    phy_noise_init(1U, 7U, 5U, 0x7800U, 1U, 0U, &g_phy_sleep_params.param_flag);
    phy_tx_pwctrl_bg_init();

    if ((g_phy_sleep_params.param_flag & PHY_PARAM_WAKEUP_RF) != 0U) {
        phy_set_chan_wakeup_exit(g_phy_sleep_params.cur_chan);
    }

    phy_dpd_bypass();
    phy_low_power_set(chip6_phy_init_ctrl[0x3D], chip6_phy_init_ctrl[0x3E],
                      chip6_phy_init_ctrl[0x3F]);

    if (chip6_phy_init_ctrl[0x39] == 1U) {
        phy_tx_cont_en();
    } else {
        phy_tx_cont_dis();
    }

    return 0;
}

int register_chipv6_phy(uint8_t *init_data_256)
{
    int ret = 0;
    uint8_t saved_chan = 1U;

    g_phy_sleep_mode_flag = 0U;
    phy_fix_cache_bug();

    if (s_re_entry == 0U) {
        ret = register_chipv6_phy_init_param(init_data_256);
        g_phy_in_most_power = chip6_phy_init_ctrl[0x14];
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
    if (re_entry == 0U && (chip6_phy_init_ctrl[0x4C] & 0x0CU) != 0U) {
        g_phy_freq_offset = (int16_t)((int32_t)(int8_t)chip6_phy_init_ctrl[0x4D] << 3);
    }

    uint8_t opt = (uint8_t)(PHY_REG_READ(PHY_RTC_SCRATCH3_REG) & 0xFFU);
    if (chip6_phy_init_ctrl[0x4E] == 2U) {
        chip6_phy_init_ctrl[0x4E] = 1U;
    }
    if (opt == 0U) {
        opt = chip6_phy_init_ctrl[0x4E];
    }

    uint8_t is_partial = (opt < 2U) ? 1U : 0U;
    uint8_t is_no_cal = (opt == 2U) ? 1U : 0U;

    uint8_t is_deepsleep = 0U;
    if (re_entry == 0U && (PHY_REG_READ(PHY_RTC_RESET_REASON_REG) & 7U) == 2U) {
        if (PHY_REG_READ(PHY_RTC_DEEPSLEEP_MAGIC_REG) == 5U) {
            is_deepsleep = 1U;
        }
    }

    uint8_t is_cold_boot = (re_entry == 0U && is_deepsleep == 0U) ? 1U : 0U;
    if (is_cold_boot != 0U && opt < 3U) {
        write_data_to_rtc(init_data_256 + 128);
    }

    uint32_t chip_id_l = 0U;
    uint32_t chip_id_h = 0U;
    bool id_mismatch = false;

    if (re_entry == 0U) {
        chip_id_l = ((PHY_REG_READ(PHY_EFUSE_DATA2_REG) & 0xF000U) << 16) |
                    (PHY_REG_READ(PHY_EFUSE_DATA1_REG) & 0x0FFFFFFFU);
        chip_id_h = (PHY_REG_READ(PHY_EFUSE_DATA0_REG) & 0xFF000000U) |
                    (PHY_REG_READ(PHY_EFUSE_DATA3_REG) & 0x00FFFFFFU);

        id_mismatch = (chip_id_l != PHY_REG_READ(PHY_RTC_CHIP_ID_L_REG)) ||
                      (chip_id_h != PHY_REG_READ(PHY_RTC_CHIP_ID_H_REG));
    }

    bool rf_disabled = false;
    if (is_deepsleep == 0U) {
        if (re_entry == 0U) {
            PHY_REG_RMW(PHY_RTC_RFOPTION_REG, 0x0000FFFFU, 0U);
        }
    } else {
        uint32_t rfopt_reg = PHY_REG_READ(PHY_RTC_RFOPTION_REG);
        uint8_t rfopt = (uint8_t)((rfopt_reg >> 16) & 0xFFU);

        if (rfopt == 2U) {
            is_no_cal = 1U;
        }
        rf_disabled = (rfopt == 4U);

        if (re_entry == 0U) {
            uint32_t cnt = rfopt_reg & 0xFFFFU;
            uint32_t new_cnt = 0U;

            if (rfopt == 0U && chip6_phy_init_ctrl[0x48] != 0U) {
                if (cnt < chip6_phy_init_ctrl[0x48]) {
                    is_no_cal = 1U;
                    new_cnt = (cnt + 1U) & 0xFFFFU;
                }
            } else {
                new_cnt = (cnt + 1U) & 0xFFFFU;
            }
            PHY_REG_RMW(PHY_RTC_RFOPTION_REG, 0x0000FFFFU, new_cnt);
        }
    }

    uint8_t cal_loaded = 0U;
    bool try_recover = false;
    if (!rf_disabled && re_entry == 0U && (is_no_cal != 0U || is_partial != 0U)) {
        try_recover = true;
    } else if (re_entry == 1U &&
               (g_phy_sleep_params.param_flag & 0x00FF0000U) != 0x00FF0000U) {
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
                    if (opt < 2U) {
                        g_phy_sleep_params.param_flag = PHY_PARAM_NOISE_VALID;
                        g_phy_sleep_params.rx_noise = -384;
                    }
                } else if (is_cold_boot != 0U) {
                    g_phy_sleep_params.param_flag &= ~PHY_PARAM_VDD33_APPLIED;
                }
            }
        }
    }

    g_phy_init_rf_no_cal = (uint8_t)(is_no_cal & cal_loaded);

    g_phy_rx_table_renew_en = 1U;
    if (phy_rx_gain_dc_table != NULL &&
        phy_check_data_table(phy_rx_gain_dc_table, 125U, 1U) == 0U) {
        g_phy_rx_table_renew_en =
            (uint8_t)(((g_phy_sleep_params.param_flag >> 16) ^ 1U) & 1U);
    }

    uint32_t t0 = phy_get_mactime();
    if (rf_disabled) {
        phy_reduce_current_init();
    } else {
        (void)phy_rf_init();
        (void)phy_initialize_bb();
    }
    s_test_print_time = phy_get_mactime() - t0;

    if (g_phy_rx_table_renew_en != 0U && phy_rx_gain_dc_table != NULL) {
        (void)phy_check_data_table(phy_rx_gain_dc_table, 125U, 0U);
    }

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

    PHY_REG_RMW(PHY_RTC_PHY_VER_REG, 0xFFFF0000U, PHY_VER_1167_0_WORD);

    if (cal_loaded < is_cold_boot) {
        get_data_from_rtc(init_data_256 + 128);
    }

    if (chip6_phy_init_ctrl[0x3B] == 3U) {
        PHY_REG_RMW(PHY_BB_NOISE_FLOOR_REG, 0x000FF000U,
                    (uint32_t)chip6_phy_init_ctrl[0x3A] << 12);
    } else if (chip6_phy_init_ctrl[0x3B] == 4U) {
        PHY_REG_RMW(PHY_BB_NOISE_FLOOR_REG, 0x000FF000U,
                    (uint32_t)chip6_phy_init_ctrl[0x3A] << 12);
        PHY_REG_SET(PHY_BB_RX_CHAN_COMP_REG, 0x00040000U);
    }

    if (chip6_phy_init_ctrl[0x3C] == 2U) {
        PHY_REG_WRITE(PHY_MAC_DEBUG_REG, 0x55555555U);
    }

    if ((g_phy_sleep_params.param_flag & PHY_PARAM_WAKEUP_RF) != 0U) {
        phy_sleep_set_rxpbus(1U);
    }

    s_re_entry = 1U;
    return ret;
}
