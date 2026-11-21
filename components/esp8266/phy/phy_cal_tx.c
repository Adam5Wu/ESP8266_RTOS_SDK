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
// RC filter calibration, TX DC offset calibration, and baseband analog default
// erratum sequences adapted in part from teatime-os:
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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "phy_internal.h"

/* --------------------------------------------------------------------------
 * Cross-TU Globals Owned by phy_cal_tx.c (Explicitly Initialized, 0 COMMON)
 * -------------------------------------------------------------------------- */

uint8_t g_phy_in_most_power = 0x4EU;
int8_t g_phy_in_vdd33_offset = 0;
uint8_t g_phy_set_most_tpw_flag = 0U;
uint8_t g_phy_set_most_tpw_val = 0U;
uint8_t g_phy_set_most_tpw_index = 0U;
uint8_t g_phy_set_most_tpw_disbg = 0U;
uint8_t g_phy_periodic_cal_flag = 0U;
uint8_t g_phy_periodic_cal_sat = 0U;
uint8_t g_phy_bbpll_cal_flag = 0U;
uint8_t g_phy_tx_pwctrl_track_num = 0U;
int8_t g_phy_txpwr_diff_flash[2] = { 0, 0 };
uint8_t g_phy_dpd_bypass_original = 0U;
uint8_t g_phy_txbk_dpdby_flag = 0U;

/* --------------------------------------------------------------------------
 * File-Local Static State & Read-Only Lookup Tables (.flash.rodata)
 * -------------------------------------------------------------------------- */

static uint16_t s_tx_rf_ana_gain = 0x0BF0U;
static int16_t s_meas_freq_offset = 0;
static int16_t s_phy_tx_power_out = 0;
static int16_t s_phy_tx_pwr_error = 0;
static uint8_t s_do_pwctrl_flag = 0U;

static const uint8_t s_txbb_gain_tbl[4] = { 0x04U, 0x10U, 0x12U, 0x14U };
static const uint8_t s_rf_gain_qdb[6] = { 14U, 10U, 8U, 7U, 6U, 5U };
static const uint8_t s_txcap_chans[3] = { 1U, 6U, 11U };

#define PHY_TXDC_POLL_LIMIT     100000U

/* --------------------------------------------------------------------------
 * IRAM Errata, Baseband EVM & RX Frequency-Offset FIQ Readout
 * (ONLY these 3 functions in phy_cal_tx.c are placed in IRAM)
 * -------------------------------------------------------------------------- */

uint16_t IRAM_ATTR phy_get_bb_evm(void)
{
    PHY_REG_SET(PHY_ANALOG_RST_REG, BIT(0));
    PHY_REG_CLR(PHY_ANALOG_RST_REG, BIT(0));

    if (((PHY_REG_READ(PHY_EFUSE_DATA2_REG) >> 12) & 0xAU) == 0xAU) {
        PHY_REG_WRITE(PHY_BB_ANALOG_DEFAULT_REG, 0xE690A568U);
    } else {
        PHY_REG_WRITE(PHY_BB_ANALOG_DEFAULT_REG, 0xEAB4D027U);
    }

    return (uint16_t)((PHY_REG_READ(PHY_BB_RX_METRIC_REG) >> 16) & 0x1FFFU);
}

void IRAM_ATTR phy_fix_cache_bug(void)
{
    vPortEnterCritical();
    Cache_Read_Disable();
    (void)phy_get_bb_evm();
    Cache_Read_Enable_New();
    vPortExitCritical();
}

int16_t IRAM_ATTR phy_get_bb_freqoffset(void)
{
    int16_t off = 0x7FFF;

    if (((PHY_REG_READ(PHY_MAC_RX_RATE_INFO_REG) >> 16) & 0xFU) < 8U) {
        uint32_t metric = PHY_REG_READ(PHY_BB_RX_METRIC_REG);
        if ((metric & 1U) != 0U) {
            int8_t raw = (int8_t)((metric >> 8) & 0xFFU);
            off = (int16_t)(((int32_t)raw * 0x1AC00) >> 16);
        }
    }

    PHY_REG_SET(PHY_BB_FREQOFF_CLR_REG, 0xFU);
    s_meas_freq_offset = off;
    return off;
}

/* --------------------------------------------------------------------------
 * Internal Integer & Gain Mapping Helpers
 * -------------------------------------------------------------------------- */

static int32_t phy_abs_i32(int32_t v)
{
    return (v < 0) ? -v : v;
}

static uint8_t phy_txbbgain2dcoindex(uint8_t gain)
{
    switch (gain) {
    case 0x04U:
        return 0U;
    case 0x12U:
        return 2U;
    case 0x14U:
        return 3U;
    case 0x10U:
    default:
        return 1U;
    }
}

static uint8_t phy_get_rf_gain_qdb(uint8_t rf_gain)
{
    uint8_t idx = (uint8_t)(rf_gain - 1U);
    if (idx < 6U) {
        return s_rf_gain_qdb[idx];
    }
    return 5U;
}

static void phy_set_rf_gain_stage10(uint8_t stage10)
{
    uint32_t val = ((uint32_t)(stage10 & 0x0FU)) << 13;
    for (uint32_t i = 0U; i < PHY_RF_TXPWR_REGS; i++) {
        PHY_REG_RMW(PHY_RF_TXPWR_REG(i), 0x0001E000U, val);
    }
}

static void phy_target_power_add_backoff(int8_t out_pwr[6], const int8_t in_pwr[6],
                                         int16_t backoff)
{
    if (backoff > 24) {
        backoff = 24;
    }
    for (uint32_t i = 0U; i < 6U; i++) {
        out_pwr[i] = (int8_t)(in_pwr[i] - (int8_t)backoff);
    }
}

static int8_t phy_get_vdd33_offset(uint16_t vdd33)
{
    if ((uint16_t)(vdd33 - 1800U) > 1500U) {
        vdd33 = 3300U;
    }

    uint16_t cal_vdd33 = (uint16_t)(g_phy_sleep_params.vdd33_tsen_off >> 16);
    int32_t db_cur = phy_linear_to_db((int32_t)vdd33, 3U);
    int32_t db_cal = phy_linear_to_db((int32_t)cal_vdd33, 3U);
    int32_t diff = (((db_cur - db_cal) * 2) + 2) >> 2;

    if (diff < -127) {
        diff = -127;
    } else if (diff > 127) {
        diff = 127;
    }
    return (int8_t)diff;
}

static void phy_get_phy_target_power(int8_t out_pwr[6], int8_t vdd_off)
{
    uint8_t chan = g_phy_sleep_params.cur_chan;
    int32_t backoff;

    if (chan < 7U) {
        int32_t b0 = g_phy_sleep_params.tx_pwr_backoff[0];
        int32_t b1 = g_phy_sleep_params.tx_pwr_backoff[1];
        backoff = b0 + ((b1 - b0) * ((int32_t)chan - 1)) / 5;
    } else if (chan < 12U) {
        int32_t b1 = g_phy_sleep_params.tx_pwr_backoff[1];
        int32_t b2 = g_phy_sleep_params.tx_pwr_backoff[2];
        backoff = b1 + ((b2 - b1) * ((int32_t)chan - 6)) / 5;
    } else if (chan < 14U) {
        int32_t b2 = g_phy_sleep_params.tx_pwr_backoff[2];
        int32_t b3 = g_phy_sleep_params.tx_pwr_backoff[3];
        backoff = b2 + (((b3 - b2) * ((int32_t)chan - 11) * 5) / 22);
    } else {
        backoff = g_phy_sleep_params.tx_pwr_backoff[3];
    }

    phy_target_power_add_backoff(out_pwr, g_phy_sleep_params.target_power_vdd,
                                 (int16_t)backoff);
    for (uint32_t i = 0U; i < 6U; i++) {
        out_pwr[i] = (int8_t)(out_pwr[i] + vdd_off);
    }
}

/* --------------------------------------------------------------------------
 * RC Filter Calibration (40 MHz & 26/24 MHz XTAL)
 * -------------------------------------------------------------------------- */

void phy_rc_cal(void)
{
    if ((g_phy_sleep_params.param_flag & PHY_PARAM_RCCAL_VALID) == 0U) {
        uint8_t xtal_mode = (chip6_phy_init_ctrl[0] == 0U) ? 2U : 1U;

        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 0U, 5U, 4U, 0U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 4U, 7U, 4U, xtal_mode);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_RC_REF, PHY_I2C_HOST_3, 1U, 0U, 0U, 1U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 6U, 4U, 0U, 8U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 4U, 0U, 0U, 1U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 3U, 6U, 6U, 1U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 4U, 3U, 3U, 0U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 4U, 3U, 3U, 1U);

        ets_delay_us(100U);

        uint32_t v = rom_i2c_readReg_Mask(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 5U, 5U, 0U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_RC_REF, PHY_I2C_HOST_3, 1U, 0U, 0U, 0U);

        if ((uint8_t)(v - 3U) > 0x39U) {
            g_phy_check_result |= 0x01000000U;
        }

        int32_t rx_dcap;
        if (chip6_phy_init_ctrl[0] == 0U) {
            rx_dcap = ((int32_t)v * 11 - 14) / 20;
        } else {
            rx_dcap = ((int32_t)v * 16 - 39) / 30;
        }
        uint32_t tx_dcap = (((v * 28U) / 9U) + 2U) >> 2;

        g_phy_sleep_params.rx_filt_dcap = (uint8_t)rx_dcap;
        g_phy_sleep_params.tx_filt_dcap = (uint8_t)tx_dcap;
        g_phy_sleep_params.param_flag |= PHY_PARAM_RCCAL_VALID;
    }

    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_ANA, PHY_I2C_HOST_1, 2U,
                     (uint8_t)(g_phy_sleep_params.rx_filt_dcap | 0xA0U));
    rom_i2c_writeReg(PHY_I2C_BLOCK_TX_FILT, PHY_I2C_HOST_3, 1U,
                     (uint8_t)(g_phy_sleep_params.tx_filt_dcap | 0x40U));
}

/* --------------------------------------------------------------------------
 * TX DC Offset Calibration & RF Analog Gain Register Loading
 * -------------------------------------------------------------------------- */

void phy_set_rfanagain_dc_reg(uint16_t rf_ana_gain, const int8_t dc_iq[2])
{
    uint32_t gain_bits = ((uint32_t)(rf_ana_gain & 0x0FFFU)) << 8;
    uint32_t i_off = (uint32_t)(uint8_t)dc_iq[0] & 0x7FU;
    uint32_t q_off = (uint32_t)(uint8_t)dc_iq[1] & 0x7FU;

    for (uint32_t i = 0U; i < PHY_RF_TXPWR_REGS; i++) {
        PHY_REG_RMW(PHY_RF_TXPWR_REG(i), 0x000FFF00U, gain_bits);

        if ((i & 1U) == 0U) {
            PHY_REG_RMW(PHY_RF_TX_DC_REG(i), 0x00003FFFU, (q_off << 7) | i_off);
        } else {
            PHY_REG_RMW(PHY_RF_TX_DC_REG(i), 0x0FFFC000U, (q_off << 21) | (i_off << 14));
        }
    }
}

void phy_set_txdc_pbus(uint16_t gain, int8_t out_iq[2], uint8_t apply_pbus)
{
    uint8_t idx = phy_txbbgain2dcoindex((uint8_t)(gain & 0x1FU));
    uint16_t packed = g_phy_sleep_params.txdc[idx];

    out_iq[0] = (int8_t)(packed & 0xFFU);
    out_iq[1] = (int8_t)((packed >> 8) & 0xFFU);

    if (apply_pbus != 0U) {
        phy_pbus_force(0U, 2U, (uint16_t)(int16_t)out_iq[0]);
        phy_pbus_force(1U, 2U, (uint16_t)(int16_t)out_iq[1]);
    }
}

static void phy_cal_tos_v60(uint8_t write_bb, uint16_t tx_gain, uint8_t samples,
                            int8_t out_iq[2])
{
    int32_t code_i = 64;
    int32_t code_q = 64;
    int32_t acc_i = 0;
    int32_t acc_q = 0;
    int32_t step = 28;

    phy_pbus_force(0U, 1U, tx_gain);

    for (uint8_t n = 0U; n < samples; n++) {
        phy_pbus_force(1U, 2U, (uint16_t)code_q);
        phy_pbus_force(0U, 2U, (uint16_t)code_i);

        PHY_REG_WRITE(PHY_MCAL_TXDC_REG, PHY_MCAL_ARM);
        PHY_REG_WRITE(PHY_MCAL_TXDC_REG, PHY_MCAL_TRIGGER);
        ets_delay_us(2U);

        for (uint32_t t = 0U; t < PHY_TXDC_POLL_LIMIT; t++) {
            if ((PHY_REG_READ(PHY_MCAL_TXDC_REG) & PHY_MCAL_DONE) != 0U) {
                break;
            }
        }

        uint32_t sign_i = PHY_REG_READ(PHY_MCAL_TXDC_REG);
        uint32_t sign_q = PHY_REG_READ(PHY_MCAL_TXDC_REG);

        if ((int32_t)sign_i < 0) {
            code_i -= step;
            if (code_i < 0) {
                code_i = 0;
            }
        } else {
            code_i += step;
            if (code_i > 127) {
                code_i = 127;
            }
        }

        if ((sign_q & PHY_MCAL_QFLAG) != 0U) {
            code_q -= step;
            if (code_q < 0) {
                code_q = 0;
            }
        } else {
            code_q += step;
            if (code_q > 127) {
                code_q = 127;
            }
        }

        step = (step == 2) ? 1 : ((step >> 1) + 1);

        if ((int32_t)n >= (int32_t)samples - 4) {
            acc_i += code_i;
            acc_q += code_q;
        }
    }

    int32_t avg_q = (acc_q + 2) >> 2;
    int32_t avg_i = (acc_i + 2) >> 2;

    phy_pbus_force(1U, 2U, (uint16_t)avg_q);
    phy_pbus_force(0U, 2U, (uint16_t)avg_i);
    phy_pbus_force(1U, 1U, 0x7FU);
    PHY_REG_WRITE(PHY_MCAL_TXDC_REG, PHY_MCAL_STOP);

    out_iq[0] = (int8_t)avg_i;
    out_iq[1] = (int8_t)avg_q;

    if (write_bb != 0U) {
        PHY_REG_RMW(PHY_BB_TXDC_EN_REG, 0xFFFC0000U,
                    (((uint32_t)avg_q & 0x7FU) << 25) |
                    (((uint32_t)avg_i & 0x7FU) << 18));
    }
}

void phy_init_cal_dcoffset(uint32_t *param_flag, uint16_t txdc[4])
{
    if ((*param_flag & PHY_PARAM_TXDC_VALID) == 0U) {
        int8_t iq[2];

        phy_pbus_enter_debugmode((uint16_t)(s_tx_rf_ana_gain & 0x1FU));
        phy_pbus_force(1U, 1U, 0x1FU);

        for (uint32_t i = 0U; i < 4U; i++) {
            phy_cal_tos_v60(0U, s_txbb_gain_tbl[i], 12U, iq);
            txdc[i] = (uint16_t)((uint16_t)(uint8_t)iq[0] |
                                 ((uint16_t)(uint8_t)iq[1] << 8));
        }

        phy_set_txdc_pbus(s_tx_rf_ana_gain, iq, 1U);
        phy_set_rfanagain_dc_reg(s_tx_rf_ana_gain, iq);
        phy_pbus_exit_debugmode();
        *param_flag |= PHY_PARAM_TXDC_VALID;
    }
}

/* --------------------------------------------------------------------------
 * VDD33 TX Power Offset
 * -------------------------------------------------------------------------- */

void phy_txpwr_offset(int16_t extra_off)
{
    uint8_t vdd_cfg = chip6_phy_init_ctrl[0x47];
    uint32_t vdd_raw;
    int32_t vdd_off = 0;

    if (vdd_cfg == 0xFFU) {
        vdd_raw = phy_readvdd33(1U);
    } else if ((uint8_t)(vdd_cfg - 18U) <= 18U) {
        vdd_raw = (uint32_t)vdd_cfg * 102U;
    } else {
        vdd_raw = 0x0D33U;
    }

    if (vdd_raw < 0x0D33U) {
        int32_t db_cur = phy_linear_to_db((int32_t)vdd_raw, 3U);
        int32_t db_nom = phy_linear_to_db(0x0D33, 3U);
        vdd_off = (((db_cur - db_nom) * 2) + 2) >> 2;
    }

    int32_t tot_off = vdd_off + (int32_t)extra_off;
    for (uint32_t i = 0U; i < 6U; i++) {
        g_phy_sleep_params.target_power_vdd[i] =
            (int8_t)((int8_t)chip6_phy_init_ctrl[0x14U + i] + (int8_t)tot_off);
    }

    if (tot_off < -127) {
        tot_off = -127;
    }
    g_phy_sleep_params.vdd33_tsen_off = (vdd_raw << 16) | ((uint32_t)tot_off & 0xFFU);
}

/* --------------------------------------------------------------------------
 * TX Power Calibration Servo & TX Capacitor Bank Tuning
 * -------------------------------------------------------------------------- */

static void phy_rfcal_pwrctrl(uint8_t tone_freq, const int8_t *target_pwr,
                              uint8_t count, uint8_t atten_bias, int8_t init_atten,
                              int8_t *out_atten, uint16_t sar_ref)
{
    int32_t stop_idx = (chip6_phy_init_ctrl[0x3D] != 0U) ? ((int32_t)count - 1) : 0;
    int32_t servo_off = 0;

    for (int32_t idx = (int32_t)count - 1; idx >= stop_idx; idx--) {
        int32_t tgt = (int32_t)(uint8_t)target_pwr[idx];
        if (idx < (int32_t)count - 1) {
            servo_off = (int16_t)(servo_off +
                                  ((int32_t)(uint8_t)target_pwr[idx + 1] - tgt));
        }

        int32_t prev_err = 2;
        int32_t att = 0;

        for (int32_t iter = 0; iter < 10; iter++) {
            att = (int16_t)(servo_off + (int32_t)init_atten);
            if (att < 0) {
                att = 0;
            } else if (att > 100) {
                att = 100;
            }

            phy_start_tx_tone(1U, (int16_t)tone_freq, (uint8_t)att,
                              0U, 0, 0U, 0U, 0, 0U);
            ets_delay_us(2U);

            int32_t p1 = phy_get_power_db(sar_ref);
            int32_t p2 = phy_get_power_db(sar_ref);
            int32_t meas = ((int16_t)(p1 + p2) + 4) >> 3;
            if (meas < 0) {
                meas = 0;
            }

            int32_t err = meas - tgt;
            if (err > 24) {
                err = 24;
            } else if (err < -24) {
                err = -24;
            }

            if ((err == 0 && iter > 0) ||
                (err == -1 && prev_err >= 0 && prev_err < 2)) {
                break;
            }
            if (att == 0 && err < 0) {
                break;
            }
            if (att == 100 && err > 0) {
                break;
            }

            int32_t next_off = servo_off + err;
            if ((uint16_t)(err + 2) > 4U) {
                next_off -= (err >> 2);
            }
            servo_off = (int16_t)next_off;
            prev_err = err;
        }

        int32_t final_att = att - (int32_t)atten_bias;
        if (final_att < -24) {
            final_att = -24;
        }
        out_atten[idx] = (int8_t)final_att;
    }

    int32_t last = (int32_t)count - 1;
    if ((int32_t)out_atten[last] - (int32_t)out_atten[0] > 50) {
        out_atten[0] = (int8_t)(out_atten[last] - 50);
    }

    if (chip6_phy_init_ctrl[0x3D] != 0U) {
        for (int32_t i = 0; i < last; i++) {
            out_atten[i] = (int8_t)(out_atten[last] +
                                    g_phy_sleep_params.target_power_vdd[last] -
                                    g_phy_sleep_params.target_power_vdd[i]);
        }
    }

    phy_stop_tx_tone(1U);
}

static void phy_rfcal_txcap(uint8_t tone_freq, uint8_t atten, uint8_t avg_cnt,
                            uint8_t out_cap[3])
{
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 9U, 7U, 0U, 0U);
    phy_start_tx_tone(1U, (int16_t)tone_freq, atten, 0U, 0, 0U, 0U, 0, 0U);

    static const uint8_t s_reg_addr[3] = { 1U, 2U, 2U };
    static const uint8_t s_msb[3] = { 3U, 3U, 6U };
    static const uint8_t s_lsb[3] = { 0U, 0U, 4U };
    static const uint8_t s_max_k[3] = { 7U, 15U, 7U };

    for (uint8_t stage = 0U; stage < 3U; stage++) {
        uint8_t best_val = 0U;
        int32_t best_pwr = 0;

        for (uint8_t k = 0U; k <= s_max_k[stage]; k++) {
            uint8_t val = (stage == 0U) ? (uint8_t)(k * 2U + 1U) : k;
            rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2,
                                  s_reg_addr[stage], s_msb[stage], s_lsb[stage], val);

            int32_t pwr = phy_txtone_linear_pwr(avg_cnt, 10U);
            if (pwr > best_pwr) {
                best_pwr = pwr;
                best_val = val;
            }
        }

        out_cap[stage] = best_val;
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2,
                              s_reg_addr[stage], s_msb[stage], s_lsb[stage], best_val);
    }

    phy_stop_tx_tone(1U);
}

void phy_set_txcap_reg(const uint8_t txcap[4][3], uint8_t chan)
{
    uint8_t grp = (uint8_t)((chan >> 2) & 0x03U);
    uint8_t c0 = txcap[grp][0];
    uint8_t c1 = txcap[grp][1];
    uint8_t c2 = txcap[grp][2];

    rom_i2c_writeReg(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2, 1U, (uint8_t)(c0 | 0x40U));
    rom_i2c_writeReg(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2, 2U,
                     (uint8_t)(((c2 & 0x0FU) << 4) | c1));
}

void phy_tx_cap_init(void)
{
    if ((g_phy_sleep_params.param_flag & PHY_PARAM_TXCAP_VALID) == 0U) {
        int8_t dc_iq[2];

        phy_pbus_debugmode();
        phy_pbus_xpd_rx_off(1);
        phy_pbus_xpd_tx_on((uint16_t)(s_tx_rf_ana_gain & 0x0FFFU));
        phy_set_txdc_pbus(s_tx_rf_ana_gain, dc_iq, 1U);
        phy_en_pwdet(0U);

        for (uint8_t i = 0U; i < 3U; i++) {
            phy_set_chan_60(s_txcap_chans[i], chip6_phy_init_ctrl[0], 0U,
                            g_phy_freq_offset, &g_phy_sleep_params, 100U, 1U);
            if (i == 0U) {
                int8_t tgt = 0x30;
                int8_t att_out = 0;

                rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2, 1U, 3U, 0U, 0x0FU);
                rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2, 2U, 3U, 0U, 7U);
                rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2, 2U, 6U, 4U, 3U);

                g_phy_rfcal_bb_atten_init = 0x50U;
                phy_rfcal_pwrctrl(0x40U, &tgt, 1U, 0x1FU, 0x50, &att_out, 0x0138U);
                g_phy_rfcal_bb_atten_init = (uint8_t)(att_out + 0x1F);
            }

            uint8_t *cap = g_phy_sleep_params.txcap[i];
            phy_rfcal_txcap(0x40U, g_phy_rfcal_bb_atten_init, 2U, cap);
            if (cap[0] == 0U && cap[1] == 0U && cap[2] == 0U) {
                cap[0] = 0x0FU;
                cap[1] = 7U;
                cap[2] = 3U;
            }
        }

        g_phy_sleep_params.txcap[3][0] = g_phy_sleep_params.txcap[2][0];
        g_phy_sleep_params.txcap[3][1] = g_phy_sleep_params.txcap[2][1];
        g_phy_sleep_params.txcap[3][2] = g_phy_sleep_params.txcap[2][2];

        phy_pbus_xpd_tx_off();
        phy_pbus_xpd_rx_on();
        phy_pbus_workmode();
        g_phy_sleep_params.param_flag |= PHY_PARAM_TXCAP_VALID;
    }

    if ((g_phy_sleep_params.param_flag & PHY_PARAM_WAKEUP_RF) == 0U) {
        phy_set_txcap_reg(g_phy_sleep_params.txcap, g_phy_sleep_params.cur_chan);
    }
}

/* --------------------------------------------------------------------------
 * RF Analog Gain Calibration, PA Backoff & TX Power Control
 * -------------------------------------------------------------------------- */

static void phy_correct_rf_ana_gain(int8_t *delta_atten, uint16_t *rf_ana_gain)
{
    uint16_t cur = *rf_ana_gain;
    uint8_t bb_gain = (uint8_t)(((cur >> 4) & 1U) * 6U + (cur & 0x0FU));
    uint8_t rf_gain = (uint8_t)((cur >> 9) & 7U);

    if (*delta_atten <= 0) {
        if (*delta_atten != 0) {
            while (*delta_atten < 0 && bb_gain >= 7U) {
                *delta_atten = (int8_t)(*delta_atten + 8);
                bb_gain = (uint8_t)(bb_gain - 2U);
            }
            while (*delta_atten < 0 && rf_gain > 1U) {
                rf_gain = (uint8_t)(rf_gain - 1U);
                *delta_atten = (int8_t)(*delta_atten + (int8_t)phy_get_rf_gain_qdb(rf_gain));
            }
            if (*delta_atten < 0 && bb_gain == 6U) {
                *delta_atten = (int8_t)(*delta_atten + 8);
                bb_gain = 4U;
            }
        }
    } else {
        if (bb_gain == 4U) {
            *delta_atten = (int8_t)(*delta_atten - 8);
            bb_gain = 6U;
        }
        while (*delta_atten > 0 && rf_gain != 7U) {
            *delta_atten = (int8_t)(*delta_atten - (int8_t)phy_get_rf_gain_qdb(rf_gain));
            rf_gain = (uint8_t)(rf_gain + 1U);
        }
        while (*delta_atten > 0 && bb_gain < 10U) {
            *delta_atten = (int8_t)(*delta_atten - 8);
            bb_gain = (uint8_t)(bb_gain + 2U);
        }
    }

    if (bb_gain > 5U) {
        bb_gain = (uint8_t)(bb_gain + 10U);
    }
    *rf_ana_gain = (uint16_t)(((((uint16_t)rf_gain * 16U) + 15U) << 5) + bb_gain);
}

static void phy_cal_rf_ana_gain(void)
{
    int8_t dc_iq[2];
    int8_t tgt = g_phy_sleep_params.target_power_vdd[5];
    int8_t att_out = 0;

    s_tx_rf_ana_gain = 0x0BF0U;
    g_phy_rfcal_bb_atten_init = 0x3CU;

    for (uint8_t iter = 0U; iter < 2U; iter++) {
        phy_pbus_force(7U, 1U, (uint16_t)(s_tx_rf_ana_gain >> 5));
        phy_pbus_force(0U, 1U, (uint16_t)(s_tx_rf_ana_gain & 0x1FU));
        phy_set_txdc_pbus(s_tx_rf_ana_gain, dc_iq, 1U);

        phy_rfcal_pwrctrl(0x40U, &tgt, 1U, 0x1FU, (int8_t)g_phy_rfcal_bb_atten_init,
                          &att_out, 0x0138U);
        g_phy_rfcal_bb_atten_init = (uint8_t)(att_out + 0x1F);

        if (att_out >= 12 && att_out <= 36) {
            break;
        }

        att_out = (int8_t)(24 - att_out);
        phy_correct_rf_ana_gain(&att_out, &s_tx_rf_ana_gain);
        phy_pbus_force(7U, 1U, (uint16_t)(s_tx_rf_ana_gain >> 5));
        phy_pbus_force(0U, 1U, (uint16_t)(s_tx_rf_ana_gain & 0x1FU));
        g_phy_rfcal_bb_atten_init = (uint8_t)(55 - att_out);
    }

    phy_set_txdc_pbus(s_tx_rf_ana_gain, dc_iq, 1U);
    phy_set_rfanagain_dc_reg(s_tx_rf_ana_gain, dc_iq);
    g_phy_sleep_params.rf_ana_gain = s_tx_rf_ana_gain;
}

static int32_t phy_meas_tone_pwr_db(int8_t atten)
{
    phy_start_tx_tone(1U, 0x40, (uint8_t)atten, 0U, 0, 0U, 0U, 0, 0U);
    int32_t p1 = phy_get_power_db(0x0138U);
    int32_t p2 = phy_get_power_db(0x0138U);
    phy_stop_tx_tone(1U);

    int32_t sum = (int16_t)(p1 + p2);
    int32_t rounded = sum + 2;
    if (rounded < 0) {
        rounded = sum + 5;
    }
    return rounded >> 2;
}

static int16_t phy_tx_pwr_backoff(const int8_t *target_pwr, uint8_t *out_linear_ok)
{
    uint8_t tgt0 = (uint8_t)target_pwr[0];
    int32_t tgt2x = (int32_t)tgt0 * 2;
    int8_t cal_tgt = (tgt0 < 0x4DU) ? (int8_t)(tgt0 - 0x1AU) : 0x32;
    uint8_t search_up = (tgt0 >= 0x4DU) ? 1U : 0U;
    int8_t att_out = 0;

    phy_rfcal_pwrctrl(0x40U, &cal_tgt, 1U, 0x1FU, (int8_t)g_phy_rfcal_bb_atten_init,
                      &att_out, 0x0138U);
    g_phy_rfcal_bb_atten_init = (uint8_t)(att_out + 0x1F);

    int8_t att_lo = (int8_t)(att_out + 5);
    int8_t att_hi = (int8_t)g_phy_rfcal_bb_atten_init;
    int32_t pwr_hi = 0;
    int32_t diff = 0;
    int32_t prev_diff = 0;

    for (uint8_t iter = 0U; iter < 10U; iter++) {
        if (att_lo < 0) {
            att_lo = 0;
        }
        if (att_hi > 0x6F) {
            att_hi = 0x6F;
        }

        pwr_hi = phy_meas_tone_pwr_db(att_lo);
        int32_t pwr_lo = phy_meas_tone_pwr_db(att_hi);
        diff = (int16_t)(pwr_hi - pwr_lo);

        if (((pwr_hi < tgt2x) && (iter == 0U) && (diff > 44) && (search_up == 0U)) ||
            (search_up != 0U)) {
            search_up = 0U;
            if (diff > 43) {
                search_up = ((diff <= 44) && (pwr_hi >= tgt2x)) ? 0U : 1U;
            }
        }

        if ((diff > 44 && search_up == 0U) ||
            (search_up == 0U && diff <= prev_diff && diff > 43) ||
            (search_up != 0U && pwr_hi >= tgt2x) ||
            (pwr_lo <= 80) ||
            (att_hi == 0x6F) ||
            (att_lo == 0)) {
            break;
        }

        int8_t step = 2;
        if (search_up != 0U) {
            int32_t delta = pwr_hi - tgt2x;
            if (diff < 49 || iter != 0U) {
                step = -4;
            } else {
                step = (int8_t)((delta / 2) - 1);
            }
            if (((int32_t)step * 2) < delta) {
                step = (int8_t)((delta - 1) / 2);
            }
        }

        att_lo = (int8_t)(att_lo + step);
        att_hi = (int8_t)(att_lo + 26);
        prev_diff = (search_up == 0U) ? diff : 0;
    }

    *out_linear_ok = (diff > 48) ? 1U : 0U;
    if (pwr_hi < tgt2x) {
        return (int16_t)((tgt2x - pwr_hi + 1) >> 1);
    }
    return 0;
}

static uint8_t phy_chan_to_band(uint8_t chan)
{
    if (chan == 1U) {
        return 0U;
    }
    if (chan == 6U) {
        return 1U;
    }
    if (chan == 11U) {
        return 2U;
    }
    return 3U;
}

static void phy_tx_pwctrl_init_cal(uint8_t chan, uint8_t do_backoff)
{
    int8_t adj_pwr[6];
    int16_t backoff = 0;

    phy_set_chan_60(chan, chip6_phy_init_ctrl[0], 0U, g_phy_freq_offset,
                    &g_phy_sleep_params, 100U, 1U);
    phy_set_txcap_reg(g_phy_sleep_params.txcap, chan);

    if (chan == 6U && s_do_pwctrl_flag == 0U) {
        phy_cal_rf_ana_gain();
    }

    if (do_backoff == 1U) {
        uint8_t linear_ok = 0U;
        int16_t b1 = phy_tx_pwr_backoff(g_phy_sleep_params.target_power_vdd, &linear_ok);
        if (b1 != 0 || linear_ok == 0U) {
            int16_t b2 = phy_tx_pwr_backoff(g_phy_sleep_params.target_power_vdd, &linear_ok);
            if (b2 != 0 || linear_ok == 0U) {
                int32_t sum = (int32_t)b1 + (int32_t)b2 + 1;
                backoff = (int16_t)((sum - (sum >> 31)) >> 1);
            }
        }
    }

    phy_target_power_add_backoff(adj_pwr, g_phy_sleep_params.target_power_vdd, backoff);

    uint8_t band = phy_chan_to_band(chan);
    g_phy_sleep_params.tx_pwr_backoff[band] = backoff;

    if (do_backoff == 1U) {
        uint32_t shift = (uint32_t)band * 8U;
        PHY_REG_RMW(PHY_FE_TX_BACKOFF_LOG_REG, 0xFFU << shift,
                    ((uint32_t)(uint8_t)backoff) << shift);
    }

    g_phy_rfcal_bb_atten_init = (uint8_t)(g_phy_rfcal_bb_atten_init - 6U);
    phy_rfcal_pwrctrl(0x40U, adj_pwr, 6U, 0x1FU, (int8_t)g_phy_rfcal_bb_atten_init,
                      g_phy_sleep_params.tx_pwctrl_atten[band], 0x0138U);
    g_phy_rfcal_bb_atten_init = (uint8_t)(g_phy_sleep_params.tx_pwctrl_atten[band][5] + 37);

    int32_t tgt_diff = (int32_t)(uint8_t)g_phy_sleep_params.target_power_vdd[0] -
                       (int32_t)(uint8_t)g_phy_sleep_params.target_power_vdd[1] + 4;
    int32_t att_diff = (int32_t)g_phy_sleep_params.tx_pwctrl_atten[band][1] -
                       (int32_t)g_phy_sleep_params.tx_pwctrl_atten[band][0];
    if (att_diff > tgt_diff) {
        g_phy_sleep_params.param_flag |= PHY_PARAM_TX_SLOPE_WARN;
    }

    if (g_phy_sleep_params.tx_pwr_backoff[band] > 4) {
        g_phy_txbk_dpdby_flag = 1U;
    }
}

static void phy_check_tx_pwr_cal(uint16_t old_rf_ana_gain, const int8_t old_att5[4],
                                 const int16_t old_backoff[4])
{
    uint16_t cur = g_phy_sleep_params.rf_ana_gain;
    uint8_t rf_cur = (uint8_t)((cur >> 9) & 7U);
    uint8_t rf_old = (uint8_t)((old_rf_ana_gain >> 9) & 7U);

    int32_t bb_cur = (int32_t)(((cur >> 4) & 1U) * 6U + (cur & 0x0FU));
    int32_t bb_old = (int32_t)(((old_rf_ana_gain >> 4) & 1U) * 6U + (old_rf_ana_gain & 0x0FU));
    int8_t gain_diff = (int8_t)((bb_cur - bb_old) * 4);

    bool inc = (rf_old <= rf_cur);
    uint8_t lo = inc ? rf_old : rf_cur;
    uint8_t hi = inc ? rf_cur : rf_old;

    for (uint8_t r = lo; r < hi; r++) {
        int8_t step = (int8_t)phy_get_rf_gain_qdb(r);
        gain_diff = inc ? (int8_t)(gain_diff + step) : (int8_t)(gain_diff - step);
    }

    int8_t max_att_diff = 0;
    int32_t max_att_abs = 0;
    for (uint32_t i = 0U; i < 4U; i++) {
        int8_t d = (int8_t)(old_att5[i] - g_phy_sleep_params.tx_pwctrl_atten[i][5]);
        int32_t a = phy_abs_i32((int32_t)d);
        if (a > max_att_abs) {
            max_att_abs = a;
            max_att_diff = d;
        }
    }

    int8_t max_bk_diff = 0;
    int32_t max_bk_abs = 0;
    for (uint32_t i = 0U; i < 4U; i++) {
        int8_t d = (int8_t)((int8_t)old_backoff[i] - (int8_t)g_phy_sleep_params.tx_pwr_backoff[i]);
        int32_t a = phy_abs_i32((int32_t)d);
        if (a > max_bk_abs) {
            max_bk_abs = a;
            max_bk_diff = d;
        }
    }

    g_phy_txpwr_diff_flash[0] = (int8_t)(gain_diff + max_att_diff);
    g_phy_txpwr_diff_flash[1] = max_bk_diff;
}

void phy_tx_pwctrl_init(uint8_t calibrate_now)
{
    int8_t dc_iq[2];
    int8_t tmp_atten[6];
    uint16_t saved_gain = g_phy_sleep_params.rf_ana_gain;

    if ((g_phy_sleep_params.param_flag & PHY_PARAM_TX_PWCTRL_VALID) == 0U) {
        int16_t old_backoff[4];
        int8_t old_att5[4];

        for (uint32_t i = 0U; i < 4U; i++) {
            old_backoff[i] = g_phy_sleep_params.tx_pwr_backoff[i];
            old_att5[i] = g_phy_sleep_params.tx_pwctrl_atten[i][5];
        }

        phy_pbus_debugmode();
        phy_pbus_xpd_rx_off(1);
        phy_pbus_xpd_tx_on((uint16_t)(s_tx_rf_ana_gain & 0x0FFFU));
        phy_set_txdc_pbus(s_tx_rf_ana_gain, dc_iq, 1U);
        phy_en_pwdet(0U);

        phy_tx_pwctrl_init_cal(6U, calibrate_now);
        phy_tx_pwctrl_init_cal(1U, calibrate_now);
        phy_tx_pwctrl_init_cal(11U, calibrate_now);

        g_phy_sleep_params.tx_pwr_backoff[3] = g_phy_sleep_params.tx_pwr_backoff[2];
        for (uint32_t i = 0U; i < 6U; i++) {
            g_phy_sleep_params.tx_pwctrl_atten[3][i] = g_phy_sleep_params.tx_pwctrl_atten[2][i];
        }

        phy_pbus_xpd_tx_off();
        phy_pbus_xpd_rx_on();
        phy_pbus_workmode();

        g_phy_sleep_params.param_flag |= PHY_PARAM_TX_PWCTRL_VALID;
        g_phy_sleep_params.tot_p = 0;
        g_phy_sleep_params.coatt = 0;
        g_phy_sleep_params.pwctrl_err_accum = 0;
        g_phy_sleep_params.periodic_delta = 0;

        phy_check_tx_pwr_cal(saved_gain, old_att5, old_backoff);
    } else {
        s_tx_rf_ana_gain = saved_gain;
        phy_set_txdc_pbus(saved_gain, dc_iq, 0U);
        phy_set_rfanagain_dc_reg(s_tx_rf_ana_gain, dc_iq);
    }

    if ((g_phy_sleep_params.param_flag & PHY_PARAM_WAKEUP_RF) == 0U) {
        phy_tx_atten_set_interp(g_phy_sleep_params.cur_chan, tmp_atten);
    }
}

/* --------------------------------------------------------------------------
 * Per-Rate Attenuation Interpolation, FCC Band-Edge & Max TX Power Clamping
 * -------------------------------------------------------------------------- */

static uint8_t phy_get_fcc_1m2m_pwr_offset(uint8_t fcc_active, uint8_t rate_slot)
{
    if (fcc_active != 0U && (uint8_t)((rate_slot & 0xFBU) - 2U) < 2U) {
        if (g_phy_sleep_params.cur_chan > 6U) {
            return chip6_phy_init_ctrl[0x37];
        }
        return chip6_phy_init_ctrl[0x38];
    }
    return 0U;
}

static uint8_t phy_get_target_power_offset(uint8_t rate_slot, const uint8_t rate_idx_tab[8])
{
    uint8_t fcc_off = phy_get_fcc_1m2m_pwr_offset(g_phy_sleep_params.fcc_active != 0U ? 1U : 0U,
                                                  rate_slot);
    uint8_t idx;

    switch (rate_slot) {
    case 0U:
    case 1U:
    case 4U:
    case 5U:
        idx = (chip6_phy_init_ctrl[0x40] != 0U) ? chip6_phy_init_ctrl[0x42] : rate_idx_tab[0];
        idx = (uint8_t)(idx + fcc_off);
        break;
    case 2U:
    case 3U:
    case 6U:
    case 7U:
        idx = (chip6_phy_init_ctrl[0x40] != 0U) ? chip6_phy_init_ctrl[0x41] : rate_idx_tab[0];
        idx = (uint8_t)(idx + fcc_off);
        break;
    case 8U:
        idx = rate_idx_tab[5];
        break;
    case 9U:
        idx = rate_idx_tab[3];
        break;
    case 10U:
        idx = rate_idx_tab[1];
        break;
    case 11U:
    case 15U:
        idx = rate_idx_tab[0];
        break;
    case 12U:
        idx = rate_idx_tab[6];
        break;
    case 13U:
        idx = rate_idx_tab[4];
        break;
    case 14U:
        idx = rate_idx_tab[2];
        break;
    default:
        idx = rate_idx_tab[(uint8_t)(rate_slot - 16U) & 7U];
        break;
    }

    if (chip6_phy_init_ctrl[0x39] == 2U) {
        uint8_t ch = g_phy_sleep_params.cur_chan;
        uint8_t clamp_idx = 0U;
        bool has_clamp = false;

        if (ch == 1U) {
            clamp_idx = chip6_phy_init_ctrl[0x10];
            has_clamp = true;
        } else if (ch == 11U) {
            clamp_idx = chip6_phy_init_ctrl[0x11];
            has_clamp = true;
        } else if (ch == 13U) {
            clamp_idx = chip6_phy_init_ctrl[0x12];
            has_clamp = true;
        } else if (ch == 14U) {
            clamp_idx = chip6_phy_init_ctrl[0x13];
            has_clamp = true;
        }

        if (has_clamp && idx < clamp_idx) {
            idx = clamp_idx;
        }
    }

    if (idx < g_phy_set_most_tpw_index) {
        idx = g_phy_set_most_tpw_index;
    }
    if (idx > 5U) {
        idx = 5U;
    }
    return idx;
}

static void phy_set_txbb_atten(const uint8_t rate_idx_tab[8], uint8_t cck_delta,
                               const int8_t atten_tab[6], int8_t fcc_min_att)
{
    for (uint8_t i = 0U; i < PHY_RF_TXPWR_REGS; i++) {
        uint8_t pidx = phy_get_target_power_offset(i, rate_idx_tab);
        int8_t att = atten_tab[pidx];
        int8_t eff_att;

        if (i < 8U) {
            eff_att = (int8_t)(att + (int8_t)cck_delta);
        } else {
            eff_att = (att < fcc_min_att) ? fcc_min_att : att;
        }

        int8_t neg_att = (int8_t)(-eff_att);
        if (neg_att > 24) {
            neg_att = 24;
        }

        PHY_REG_RMW(PHY_RF_TXPWR_REG(i), 0x000000FFU, (uint32_t)(uint8_t)neg_att);
    }
}

void phy_set_most_pwr_reg(void)
{
    int8_t tgt_s8[6];
    uint8_t stage10 = 0x0FU;

    phy_get_phy_target_power(tgt_s8, g_phy_in_vdd33_offset);

    int32_t req = (int32_t)(int8_t)g_phy_in_most_power;
    uint8_t t5 = (uint8_t)tgt_s8[5];

    if (req < (int32_t)t5) {
        g_phy_set_most_tpw_disbg = 1U;
        g_phy_set_most_tpw_index = 5U;

        uint8_t diff = (uint8_t)(t5 - g_phy_in_most_power);
        if (diff < 9U) {
            g_phy_set_most_tpw_val = (uint8_t)(t5 - 8U);
            stage10 = 0x0EU;
        } else if (diff < 25U) {
            g_phy_set_most_tpw_val = (uint8_t)(t5 - 24U);
            stage10 = 0x0DU;
        } else if (diff < 33U) {
            g_phy_set_most_tpw_val = (uint8_t)(t5 - 32U);
            stage10 = 0x09U;
        } else if (diff < 45U) {
            g_phy_set_most_tpw_val = (uint8_t)(t5 - 44U);
            stage10 = 0x0CU;
        } else if (diff < 57U) {
            g_phy_set_most_tpw_val = (uint8_t)(t5 - 56U);
            stage10 = 0x08U;
        } else if (diff < 69U) {
            g_phy_set_most_tpw_val = (uint8_t)(t5 - 68U);
            stage10 = 0x04U;
        } else {
            g_phy_set_most_tpw_val = (uint8_t)(t5 - 92U);
            stage10 = 0x00U;
        }
    } else {
        g_phy_set_most_tpw_disbg = 0U;
        if (req < (int32_t)(uint8_t)tgt_s8[4]) {
            g_phy_set_most_tpw_index = 5U;
            g_phy_set_most_tpw_val = (uint8_t)tgt_s8[5];
        } else if (req < (int32_t)(uint8_t)tgt_s8[3]) {
            g_phy_set_most_tpw_index = 4U;
            g_phy_set_most_tpw_val = (uint8_t)tgt_s8[4];
        } else if (req < (int32_t)(uint8_t)tgt_s8[2]) {
            g_phy_set_most_tpw_index = 3U;
            g_phy_set_most_tpw_val = (uint8_t)tgt_s8[3];
        } else if (req < (int32_t)(uint8_t)tgt_s8[1]) {
            g_phy_set_most_tpw_index = 2U;
            g_phy_set_most_tpw_val = (uint8_t)tgt_s8[2];
        } else if (req < (int32_t)(uint8_t)tgt_s8[0]) {
            g_phy_set_most_tpw_index = 1U;
            g_phy_set_most_tpw_val = (uint8_t)tgt_s8[1];
        } else {
            g_phy_set_most_tpw_index = 0U;
            g_phy_set_most_tpw_val = (uint8_t)tgt_s8[0];
        }
    }

    if (g_phy_set_most_tpw_disbg == 0U) {
        stage10 = (chip6_phy_init_ctrl[0x3D] == 0U) ? 0x0FU : chip6_phy_init_ctrl[0x3E];
    }
    phy_set_rf_gain_stage10(stage10);
}

void phy_tx_atten_set_interp(uint8_t chan, int8_t out_atten[6])
{
    if (chip6_phy_init_ctrl[0x3D] == 0U) {
        phy_set_most_pwr_reg();
    }

    int8_t coatt = g_phy_sleep_params.coatt;
    for (uint32_t i = 0U; i < 6U; i++) {
        int32_t att;
        if (chan < 7U) {
            int32_t a0 = g_phy_sleep_params.tx_pwctrl_atten[0][i];
            int32_t a1 = g_phy_sleep_params.tx_pwctrl_atten[1][i];
            att = a0 + ((a1 - a0) * ((int32_t)chan - 1)) / 5;
        } else if (chan < 12U) {
            int32_t a1 = g_phy_sleep_params.tx_pwctrl_atten[1][i];
            int32_t a2 = g_phy_sleep_params.tx_pwctrl_atten[2][i];
            att = a1 + ((a2 - a1) * ((int32_t)chan - 6)) / 5;
        } else if (chan < 14U) {
            int32_t a2 = g_phy_sleep_params.tx_pwctrl_atten[2][i];
            int32_t a3 = g_phy_sleep_params.tx_pwctrl_atten[3][i];
            att = a2 + (((a3 - a2) * ((int32_t)chan - 11) * 5) / 22);
        } else {
            att = g_phy_sleep_params.tx_pwctrl_atten[3][i];
        }
        out_atten[i] = (int8_t)((int8_t)att + coatt);
    }

    int8_t fcc_edge = -128;
    uint8_t fcc_active = 0U;

    if (chip6_phy_init_ctrl[0x39] == 1U) {
        if (chip6_phy_init_ctrl[0x30] == 0U) {
            if (chan < 3U) {
                fcc_edge = g_phy_sleep_params.tx_pwctrl_atten[0][2];
                fcc_active = 1U;
            } else if (chan >= 10U) {
                fcc_edge = g_phy_sleep_params.tx_pwctrl_atten[2][2];
                fcc_active = 1U;
            }
        } else {
            uint8_t lo_cnt = chip6_phy_init_ctrl[0x34];
            if (chan <= lo_cnt && lo_cnt != 0U) {
                uint8_t lo_idx = chip6_phy_init_ctrl[0x32];
                fcc_edge = g_phy_sleep_params.tx_pwctrl_atten[0][lo_idx];
                fcc_active = 1U;
                if (chip6_phy_init_ctrl[0x35] == 1U) {
                    int32_t a0 = g_phy_sleep_params.tx_pwctrl_atten[0][0];
                    int32_t a1 = g_phy_sleep_params.tx_pwctrl_atten[1][0];
                    int8_t edge_end = (int8_t)(a0 + ((a1 - a0) * (int32_t)lo_cnt) / 5);
                    fcc_edge = (int8_t)(fcc_edge +
                                        (((int32_t)edge_end - (int32_t)fcc_edge) *
                                         ((int32_t)chan - 1)) / (int32_t)lo_cnt);
                }
            } else if ((int32_t)chan >= (15 - (int32_t)chip6_phy_init_ctrl[0x33])) {
                uint8_t hi_idx = chip6_phy_init_ctrl[0x31];
                fcc_edge = g_phy_sleep_params.tx_pwctrl_atten[3][hi_idx];
                fcc_active = 1U;
                if (chip6_phy_init_ctrl[0x35] == 1U && lo_cnt != 0U) {
                    int8_t edge_end;
                    if (chan < 12U) {
                        int32_t a1 = g_phy_sleep_params.tx_pwctrl_atten[1][0];
                        int32_t a2 = g_phy_sleep_params.tx_pwctrl_atten[2][0];
                        edge_end = (int8_t)(a1 + ((a2 - a1) * (8 - (int32_t)lo_cnt)) / 5);
                    } else {
                        int32_t a2 = g_phy_sleep_params.tx_pwctrl_atten[2][0];
                        int32_t a3 = g_phy_sleep_params.tx_pwctrl_atten[3][0];
                        edge_end = (int8_t)(a2 + (((a3 - a2) * (3 - (int32_t)lo_cnt) * 5) / 22));
                    }
                    fcc_edge = (int8_t)(fcc_edge +
                                        (((int32_t)edge_end - (int32_t)fcc_edge) *
                                         (14 - (int32_t)chan)) / (int32_t)lo_cnt);
                }
            }
        }
    }

    g_phy_sleep_params.fcc_edge_atten = fcc_edge;
    g_phy_sleep_params.fcc_active = fcc_active;
    phy_set_txbb_atten(&chip6_phy_init_ctrl[0x1A], 8U, out_atten, fcc_edge);
}

void phy_low_power_set(uint8_t en, uint8_t stage10, uint8_t bb_delta)
{
    if (en != 0U) {
        uint32_t stage_bits = ((uint32_t)(stage10 & 0x0FU)) << 13;
        uint32_t delta = (uint32_t)bb_delta - (uint32_t)(uint8_t)g_phy_sleep_params.coatt;

        for (uint32_t i = 0U; i < PHY_RF_TXPWR_REGS; i++) {
            uint32_t reg = PHY_RF_TXPWR_REG(i);
            uint32_t cur = PHY_REG_READ(reg);
            uint32_t new_att = (cur - delta) & 0xFFU;
            PHY_REG_WRITE(reg, (cur & 0xFFFE1F00U) | stage_bits | new_att);
        }
        g_phy_sleep_params.coatt = (int8_t)bb_delta;
    }
}

/* --------------------------------------------------------------------------
 * Exported TX Power Control APIs
 * -------------------------------------------------------------------------- */

void phy_set_most_tpw(uint8_t max_tpw_qdb)
{
    int8_t tmp_atten[6];

    g_phy_in_most_power = max_tpw_qdb;
    phy_tx_atten_set_interp(g_phy_sleep_params.cur_chan, tmp_atten);
    g_phy_set_most_tpw_flag = 1U;
}

uint8_t phy_get_most_tpw(void)
{
    if (g_phy_set_most_tpw_flag == 0U) {
        return chip6_phy_init_ctrl[0x14];
    }
    return g_phy_set_most_tpw_val;
}

void phy_vdd33_set_tpw(uint16_t vdd33)
{
    g_phy_in_vdd33_offset = phy_get_vdd33_offset(vdd33);
}

/* --------------------------------------------------------------------------
 * Background Closed-Loop TX Power Tracking & Periodic BBPLL Calibration
 * -------------------------------------------------------------------------- */

void phy_tx_pwctrl_bg_init(void)
{
    /* Match exact hardware pulse sequence in linked_disasm.txt */
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_TOUT_EN);
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_VDD33_EN);
    PHY_REG_CLR(PHY_SAR_CTRL_REG, BIT(0));
    PHY_REG_SET(PHY_SAR_PWDET_CTRL_REG, BIT(1));
    PHY_REG_CLR(PHY_SAR_PWDET_CTRL_REG, BIT(0));
    PHY_REG_SET(PHY_SAR_PWDET_CTRL_REG, BIT(0));
}

void phy_periodic_cal_top(void)
{
    pm_set_sleep_mode(4U);
    if (g_phy_bbpll_cal_flag == 0U) {
        bbpll_cal(0U);
    }
    g_phy_bbpll_cal_flag = 0U;
    pm_wakeup_init(4U, 0U);
}

static int8_t phy_get_pwctrl_correct(int16_t err, int16_t *err_accum,
                                     uint8_t shift, uint8_t step)
{
    int16_t acc = (int16_t)((*err_accum + err) - (int16_t)((int32_t)*err_accum >> shift));
    int32_t thresh = (int32_t)step << (shift + 2U);

    if (acc >= thresh) {
        *err_accum = (int16_t)(acc - (int16_t)thresh);
        return (int8_t)(-(int8_t)step);
    }
    if (acc <= -thresh) {
        *err_accum = (int16_t)(acc + (int16_t)thresh);
        return (int8_t)step;
    }

    *err_accum = acc;
    return 0;
}

static void phy_tx_pwctrl_cal(const int8_t target_pwr[6], const uint8_t rate_idx_tab[8],
                              int16_t *err_accum, uint8_t apply_enable)
{
    uint32_t pwdet = PHY_REG_READ(PHY_SAR_PWDET_CTRL_REG);
    int16_t p_out = phy_get_sar_dout(0x0138U);
    uint8_t txq_rate = (uint8_t)((pwdet >> 24) & 0x1FU);

    s_phy_tx_power_out = p_out;

    uint8_t rate_slot = (txq_rate < 8U) ? (uint8_t)((~txq_rate) & 7U) : txq_rate;
    uint8_t pidx = phy_get_target_power_offset(rate_slot, rate_idx_tab);

    int16_t err = (int16_t)(p_out - (int16_t)((uint8_t)target_pwr[pidx] * 4U));
    s_phy_tx_pwr_error = err;

    if (err < -32) {
        err = -32;
    } else if (err > 32) {
        err = 32;
    }

    int8_t correct_v = 0;
    if (g_phy_tx_pwctrl_track_num < 4U) {
        int32_t q = (int32_t)err >> 2;
        if (err > 0) {
            correct_v = (int8_t)(-((q + (int32_t)err) >> 2));
        } else if (err < -16) {
            correct_v = (int8_t)(-(((int32_t)err - q) >> 2));
            if (g_phy_sleep_params.tot_p > 19) {
                correct_v = 0;
            }
        }
    } else {
        correct_v = phy_get_pwctrl_correct(err, err_accum, 4U, 2U);
        if (correct_v > 0 && g_phy_sleep_params.tot_p > 19) {
            correct_v = 0;
        }
    }

    if (correct_v == 0 || apply_enable == 0U) {
        return;
    }

    int8_t min_att = g_phy_sleep_params.tx_pwctrl_atten[0][5];
    for (uint32_t b = 1U; b < 4U; b++) {
        if (g_phy_sleep_params.tx_pwctrl_atten[b][5] < min_att) {
            min_att = g_phy_sleep_params.tx_pwctrl_atten[b][5];
        }
    }

    int8_t base_att = (int8_t)(g_phy_sleep_params.coatt + min_att);
    int8_t next_att = (int8_t)(base_att - correct_v);

    bool need_rf_step = false;
    if (next_att >= 37) {
        need_rf_step = (s_tx_rf_ana_gain >= 0x03E5U);
    } else if (next_att <= 11) {
        need_rf_step = (s_tx_rf_ana_gain <= 0x0FF3U);
    }

    if (need_rf_step) {
        int8_t dc_iq[2];
        int8_t delta = (int8_t)(24 - next_att);
        int8_t orig_delta = delta;

        phy_correct_rf_ana_gain(&delta, &s_tx_rf_ana_gain);
        int8_t applied = (int8_t)(orig_delta - delta);

        g_phy_sleep_params.tot_p = (int8_t)(g_phy_sleep_params.tot_p + applied);
        g_phy_sleep_params.periodic_delta = (int8_t)(g_phy_sleep_params.periodic_delta + applied);
        correct_v = (int8_t)(correct_v + delta - orig_delta);

        phy_set_txdc_pbus(s_tx_rf_ana_gain, dc_iq, 0U);
        phy_set_rfanagain_dc_reg(s_tx_rf_ana_gain, dc_iq);
        g_phy_sleep_params.rf_ana_gain = s_tx_rf_ana_gain;
    }

    int8_t final_att = (int8_t)(base_att - correct_v);
    if ((correct_v < 0 && final_att < 71) || (correct_v > 0 && final_att > 11)) {
        int8_t tmp_atten[6];

        g_phy_sleep_params.coatt = (int8_t)(g_phy_sleep_params.coatt - correct_v);
        g_phy_sleep_params.tot_p = (int8_t)(g_phy_sleep_params.tot_p + correct_v);
        g_phy_sleep_params.periodic_delta = (int8_t)(g_phy_sleep_params.periodic_delta + correct_v);

        phy_tx_atten_set_interp(g_phy_sleep_params.cur_chan, tmp_atten);
        phy_rtc_mem_backup_chunk2();
    }
}

void tx_pwctrl_background(uint8_t apply_enable, uint8_t debug_print)
{
    (void)debug_print;

    if ((chip6_phy_init_ctrl[0x43] & 1U) != 0U ||
        chip6_phy_init_ctrl[0x3D] != 0U ||
        g_phy_set_most_tpw_disbg != 0U ||
        g_phy_tout_dis_txpwr_track != 0U) {
        return;
    }

    uint32_t sar_ctrl = PHY_REG_READ(PHY_SAR_CTRL_REG);
    if ((int32_t)sar_ctrl < 0 || ((sar_ctrl >> 24) & 7U) != 0U) {
        s_phy_tx_power_out = 0;
    } else {
        int8_t tgt_pwr[6];
        phy_get_phy_target_power(tgt_pwr, g_phy_in_vdd33_offset);
        phy_tx_pwctrl_cal(tgt_pwr, &chip6_phy_init_ctrl[0x1A],
                          &g_phy_sleep_params.pwctrl_err_accum, apply_enable);
        if (g_phy_tx_pwctrl_track_num < 20U) {
            g_phy_tx_pwctrl_track_num++;
        }
    }

    phy_tx_pwctrl_bg_init();

    if (phy_abs_i32((int32_t)g_phy_sleep_params.periodic_delta) > 7) {
        g_phy_sleep_params.periodic_delta = 0;
        phy_periodic_cal_top();
    }
}

/* --------------------------------------------------------------------------
 * TX I/Q Mismatch Calibration
 * -------------------------------------------------------------------------- */

static int8_t phy_rfcal_txiq_set_reg(int8_t val, uint8_t is_gain, uint8_t sign_flag)
{
    if (sign_flag == 0U) {
        int8_t limit = (is_gain != 0U) ? 15 : 31;
        if (val > limit) {
            val = limit;
        } else if (val < -limit) {
            val = (int8_t)(-limit);
        }

        if (is_gain != 0U) {
            rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                  0x10U, 7U, 3U, (uint8_t)val & 0x1FU);
        } else {
            rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                  0x11U, 5U, 0U, (uint8_t)val & 0x3FU);
        }
        return val;
    }

    uint8_t neg = (val < 0) ? 1U : 0U;
    int8_t mag = neg ? (int8_t)(-val) : val;

    if (is_gain != 0U) {
        if (mag > 15) {
            mag = 15;
        }
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x10U, 0U, 0U, neg);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              0x10U, 7U, 3U, (uint8_t)mag & 0x1FU);
    } else {
        if (mag > 31) {
            mag = 31;
        }
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x0FU, 6U, 6U, neg);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              0x11U, 5U, 0U, (uint8_t)mag & 0x3FU);
    }

    return neg ? (int8_t)(-mag) : mag;
}

static void phy_txiq_get_mis_pwr(uint8_t phase_sel, int8_t atten, int16_t freq,
                                 int16_t *p1, int16_t *p2)
{
    uint32_t neg_att = (uint32_t)(uint8_t)(-atten);
    uint32_t freq_bits = (uint32_t)(uint16_t)freq & 0x03FFU;
    uint32_t sel = phase_sel & 1U;

    PHY_REG_RMW(PHY_FE_TX_TONE_1_REG, 0x0FFFFFFFU,
                0x002C0000U | (sel << 26) | (neg_att << 10) | freq_bits);
    *p1 = (int16_t)phy_txtone_linear_pwr(4U, 10U);

    uint32_t swap_bits = ((sel << 3) | (sel ^ 1U)) << 24;
    PHY_REG_RMW(PHY_FE_TX_TONE_1_REG, 0x0F000000U, swap_bits);
    *p2 = (int16_t)phy_txtone_linear_pwr(4U, 10U);
}

static void phy_txiq_cover(int8_t bb_atten, int16_t tone_freq, int8_t out_gp[2],
                           uint8_t sign_flag)
{
    int8_t att_gain = (int8_t)(bb_atten - 12);
    int8_t cur_gain = 0;
    int8_t cur_phase = 0;
    int8_t sum_gain = 0;
    int8_t sum_phase = 0;

    for (uint8_t iter = 0U; iter < 7U; iter++) {
        if (iter < 4U) {
            int8_t quad = (int8_t)((((int32_t)cur_phase * (int32_t)cur_phase) + 128) >> 8);
            int8_t set_g = phy_rfcal_txiq_set_reg((int8_t)(cur_gain + quad), 1U, sign_flag);
            cur_gain = (int8_t)(set_g - quad);
            cur_phase = phy_rfcal_txiq_set_reg(cur_phase, 0U, sign_flag);
        }

        int16_t p1 = 0;
        int16_t p2 = 0;
        phy_txiq_get_mis_pwr(1U, att_gain, tone_freq, &p1, &p2);
        int32_t denom = (p1 < p2) ? (int32_t)p1 : (int32_t)p2;
        if (denom == 0) {
            denom = 1;
        }
        int8_t g_err = (int8_t)(((((int32_t)p2 - (int32_t)p1) * 2048) / denom + 16) >> 5);
        if (cur_gain < 0 && sign_flag != 0U) {
            g_err = (int8_t)(-g_err);
        }
        out_gp[0] = g_err;

        phy_txiq_get_mis_pwr(0U, bb_atten, tone_freq, &p1, &p2);
        denom = (int16_t)(p1 + p2);
        if (denom == 0) {
            denom = 1;
        }
        int8_t p_err = (int8_t)(((((int32_t)p1 - (int32_t)p2) * 4096) / denom + 16) >> 5);
        if (cur_phase < 0 && sign_flag != 0U) {
            p_err = (int8_t)(-p_err);
        }
        out_gp[1] = p_err;

        if (iter < 3U) {
            cur_gain = (int8_t)(cur_gain - g_err);
            cur_phase = (int8_t)(cur_phase - p_err);
        } else {
            sum_gain = (int8_t)(sum_gain + g_err);
            sum_phase = (int8_t)(sum_phase + p_err);

            if (phy_abs_i32((int32_t)g_err) < 2 && phy_abs_i32((int32_t)p_err) < 2) {
                break;
            }
            if (iter == 6U) {
                int8_t avg_g = (int8_t)((sum_gain + 2) >> 2);
                int8_t avg_p = (int8_t)((sum_phase + 2) >> 2);
                cur_gain = (int8_t)(cur_gain - avg_g);
                cur_phase = (int8_t)(cur_phase - avg_p);
                if (phy_abs_i32((int32_t)avg_g) > 4 || phy_abs_i32((int32_t)avg_p) > 4) {
                    g_phy_check_result |= 0x2000U;
                }
                break;
            }
        }
    }

    (void)phy_rfcal_txiq_set_reg(cur_gain, 1U, sign_flag);
    (void)phy_rfcal_txiq_set_reg(cur_phase, 0U, sign_flag);
    out_gp[0] = cur_gain;
    out_gp[1] = cur_phase;
}

void phy_rfcal_txiq(uint32_t *param_flag, uint16_t *txiq_out,
                    uint16_t rf_ana_gain, uint8_t amp, int8_t bb_atten,
                    uint8_t sign_flag, uint8_t mode_flag, uint8_t apply_bb)
{
    uint32_t gain_u;
    uint32_t phase_u;

    (void)mode_flag;
    (void)apply_bb;

    if ((*param_flag & PHY_PARAM_TXIQ_VALID) == 0U) {
        int8_t dc_iq[2];
        int8_t gp[2];

        uint8_t saved_r10_b0 = rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                                    0x10U, 0U, 0U);
        uint8_t saved_r0f_b6 = rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                                    0x0FU, 6U, 6U);
        uint8_t saved_r09 = rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                                 9U, 7U, 0U);

        phy_pbus_debugmode();
        phy_pbus_xpd_rx_off(1);
        phy_pbus_xpd_tx_on(rf_ana_gain);
        phy_set_txdc_pbus(rf_ana_gain, dc_iq, 1U);
        phy_en_pwdet(0U);
        phy_set_txclk_en(1U);

        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 9U, 7U, 0U, 0U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x10U, 2U, 2U, 1U);

        phy_txiq_cover(bb_atten, (int16_t)amp, gp, sign_flag);

        phy_stop_tx_tone(1U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x10U, 0U, 0U, saved_r10_b0);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x0FU, 6U, 6U, saved_r0f_b6);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 9U, 7U, 0U, saved_r09);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x10U, 2U, 2U, 0U);

        if (gp[0] > 15) {
            gp[0] = 15;
        } else if (gp[0] < -15) {
            gp[0] = -15;
        }
        if (gp[1] > 31) {
            gp[1] = 31;
        } else if (gp[1] < -31) {
            gp[1] = -31;
        }
        if (saved_r10_b0 != 0U && sign_flag != 0U) {
            gp[0] = (int8_t)(-gp[0]);
        }

        gain_u = (gp[0] < 0) ? (uint32_t)(gp[0] + 32) : (uint32_t)gp[0];
        phase_u = (gp[1] < 0) ? (uint32_t)(gp[1] + 64) : (uint32_t)gp[1];

        phy_pbus_exit_debugmode();

        *txiq_out = (uint16_t)((gain_u << 8) | (phase_u & 0xFFU));
        *param_flag |= PHY_PARAM_TXIQ_VALID;
    } else {
        gain_u = (*txiq_out >> 8) & 0xFFU;
        phase_u = *txiq_out & 0xFFU;
    }

    PHY_REG_RMW(PHY_BB_TXIQ_GAIN_COMMIT_REG, 0x1FFF0000U,
                0x00030000U | ((gain_u & 0x1FU) << 24) | ((phase_u & 0x3FU) << 18));
    PHY_REG_SET(PHY_BB_TX_CAL_REG, 0x20U);
    PHY_REG_RMW(PHY_BB_TXIQ_MODE_REG, 0x0000000FU, 2U);
    PHY_REG_RMW(PHY_BB_TXDC_EN_REG, 0x000001F1U, 1U);
}
