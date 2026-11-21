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
// Portions of the RX gain table builder, dual-window baseband gain RAM loader,
// and noise-floor hardware sequences are adapted from teatime-os:
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

#include "phy_internal.h"

/* --------------------------------------------------------------------------
 * Owned Cross-TU & File-Local State (Explicitly Initialized, 0 SHN_COMMON)
 * -------------------------------------------------------------------------- */

uint8_t g_phy_sw_scan_mode = 0U;

static int16_t s_noise_array[4] = { 0, 0, 0, 0 };
static uint16_t s_loop_time_limit = 0U;
static uint32_t s_rxiq_compute_num = 0U;
static uint8_t s_rxiq_cover_fail_num = 0U;

/* --------------------------------------------------------------------------
 * 4-Byte Aligned Flash Lookup Tables (.flash.rodata)
 * -------------------------------------------------------------------------- */

static const uint16_t s_bb_step_tab[5] __attribute__((aligned(4))) = {
    0x0000U, 0x0010U, 0x0014U, 0x0015U, 0x0017U
};

static const uint8_t s_gain_idx_tab[16] __attribute__((aligned(4))) = {
    0x00U, 0x04U, 0x20U, 0x24U, 0x28U, 0x2CU, 0x30U, 0x34U,
    0x40U, 0x60U, 0x64U, 0x68U, 0x70U, 0x74U, 0x78U, 0x7CU
};

static const uint8_t s_bb_idx_tab[15] __attribute__((aligned(4))) = {
    4U, 2U, 5U, 5U, 5U, 2U, 5U, 5U, 3U, 5U, 5U, 4U, 5U, 5U, 4U
};

static const uint8_t s_dco_gain_coarse[7] __attribute__((aligned(4))) = {
    105U, 86U, 80U, 72U, 64U, 55U, 50U
};

static const uint8_t s_rxiq_bbrx1[4] __attribute__((aligned(4))) = {
    0x04U, 0x14U, 0x54U, 0x74U
};

static const uint8_t s_rxiq_atten[4] __attribute__((aligned(4))) = {
    0U, 15U, 24U, 24U
};

/* --------------------------------------------------------------------------
 * Internal Utility Helpers
 * -------------------------------------------------------------------------- */

static inline int32_t s_abs32(int32_t v)
{
    return (v < 0) ? -v : v;
}

static inline int32_t s_clamp32(int32_t v, int32_t lo, int32_t hi)
{
    if (v < lo) {
        return lo;
    }
    if (v > hi) {
        return hi;
    }
    return v;
}

static uint32_t s_popcount7(uint32_t v)
{
    v &= 0x7FU;
    uint32_t n = 0U;
    while (v != 0U) {
        v &= (v - 1U);
        n++;
    }
    return n;
}

static uint16_t s_read_gain_entry(const uint32_t *gain_table, uint32_t n)
{
    uint32_t w = gain_table[n >> 1];
    return (uint16_t)(((n & 1U) != 0U) ? (w >> 16) : (w & 0xFFFFU));
}

/* --------------------------------------------------------------------------
 * Live PBUS RX DC Offset Calibration (rom_pbus_dco___SA2)
 * -------------------------------------------------------------------------- */

static void phy_pbus_dco_sa2(uint16_t samples, int16_t out_dac[4], uint16_t delay_us)
{
    uint32_t r31 = (uint32_t)phy_pbus_rd(3U, 1U) & 0xFFU;
    uint32_t cgain = s_popcount7(r31 & 0x7CU);
    uint32_t fgain = ((uint32_t)phy_pbus_rd(3U, 2U) >> 3) & 0xFFU;
    if (fgain > 6U) {
        fgain = 6U;
    }

    phy_pbus_force(4U, 2U, 0x100U);
    phy_pbus_force(5U, 2U, 0x100U);

    uint32_t shift1 = (cgain + 6U) & 0xFFU;
    int32_t tol = (cgain < 3U) ? 2 : (cgain == 3U) ? 5 : 10;
    int32_t tol2 = (cgain > 3U) ? 5 : 2;
    uint32_t shift = shift1;

    for (uint8_t stage = 1U; stage <= 2U; stage++) {
        int32_t dac_i = 0x200;
        int32_t dac_q = 0x200;
        int16_t *dst = &out_dac[(uint32_t)(stage - 1U) * 2U];

        for (uint32_t iter = 0U; iter < 12U; iter++) {
            dst[0] = (int16_t)((dac_i + 1) >> 1);
            phy_pbus_force(4U, stage, (uint16_t)dst[0]);
            dst[1] = (int16_t)((dac_q + 1) >> 1);
            phy_pbus_force(5U, stage, (uint16_t)dst[1]);

            ets_delay_us(delay_us);

            int32_t dc[2];
            phy_dc_iq_est(1U, samples, dc);

            if (s_abs32(dc[0]) <= tol && s_abs32(dc[1]) <= tol) {
                break;
            }

            int32_t step_i;
            int32_t step_q;
            if (stage == 1U) {
                step_i = ((int32_t)s_dco_gain_coarse[fgain] * dc[0]) >> (shift1 & 31U);
                step_q = ((int32_t)s_dco_gain_coarse[fgain] * dc[1]) >> (shift1 & 31U);
            } else {
                step_i = (dc[0] * 40) >> (shift & 31U);
                step_q = (dc[1] * 40) >> (shift & 31U);
            }

            dac_i = s_clamp32(dac_i - step_i, 0, 0x3FF);
            dac_q = s_clamp32(dac_q - step_q, 0, 0x3FF);
        }

        uint32_t s2_sel = ((r31 >> 2) & 3U) + ((r31 >> 4) & 1U);
        shift = (s2_sel == 0U) ? 4U : (s2_sel == 1U) ? 5U : 6U;
        tol = tol2;
    }
}

/* --------------------------------------------------------------------------
 * Live Loopback RXIQ Calibration
 * -------------------------------------------------------------------------- */

static void s_rxiq_cal_tos_v60(uint16_t gain, int8_t out_iq[2])
{
    phy_pbus_force(0U, 1U, gain);

    int32_t code_i = 64;
    int32_t code_q = 64;
    int32_t acc_i = 0;
    int32_t acc_q = 0;
    int32_t step = 28;

    for (uint32_t n = 0U; n < 12U; n++) {
        phy_pbus_force(1U, 2U, (uint16_t)code_q);
        phy_pbus_force(0U, 2U, (uint16_t)code_i);

        PHY_REG_WRITE(PHY_MCAL_TXDC_REG, PHY_MCAL_ARM);
        PHY_REG_WRITE(PHY_MCAL_TXDC_REG, PHY_MCAL_TRIGGER);
        ets_delay_us(2U);

        for (uint32_t t = 0U; t < 100000U; t++) {
            if ((PHY_REG_READ(PHY_MCAL_TXDC_REG) & PHY_MCAL_DONE) != 0U) {
                break;
            }
        }

        uint32_t status_i = PHY_REG_READ(PHY_MCAL_TXDC_REG);
        uint32_t status_q = PHY_REG_READ(PHY_MCAL_TXDC_REG);

        if ((int32_t)status_i < 0) {
            code_i = s_clamp32(code_i - step, 0, 127);
        } else {
            code_i = s_clamp32(code_i + step, 0, 127);
        }

        if ((status_q & PHY_MCAL_QFLAG) != 0U) {
            code_q = s_clamp32(code_q - step, 0, 127);
        } else {
            code_q = s_clamp32(code_q + step, 0, 127);
        }

        step = (step == 2) ? 1 : ((step >> 1) + 1);

        if (n >= 8U) {
            acc_i += code_i;
            acc_q += code_q;
        }
    }

    int32_t avg_q = (acc_q + 2) >> 2;
    int32_t avg_i = (acc_i + 2) >> 2;

    phy_pbus_force(1U, 2U, (uint16_t)avg_q);
    phy_pbus_force(0U, 2U, (uint16_t)avg_i);
    phy_pbus_force(1U, 1U, 127U);
    PHY_REG_WRITE(PHY_MCAL_TXDC_REG, PHY_MCAL_STOP);

    out_iq[0] = (int8_t)avg_i;
    out_iq[1] = (int8_t)avg_q;
}

static void s_set_cal_rxdc(uint16_t bbrx1, uint16_t bbrx2, const uint32_t *dc_table)
{
    uint32_t bits = s_popcount7(bbrx1);
    if (bits > 4U) {
        bits = 4U;
    }
    uint32_t idx = bits * 6U + (((uint32_t)bbrx2 >> 3) & 7U);
    if (idx > 29U) {
        idx = 29U;
    }

    uint32_t dc_i = dc_table[idx * 2U];
    uint32_t dc_q = dc_table[idx * 2U + 1U];

    phy_pbus_force(4U, 1U, (uint16_t)((dc_i >> 9) & 0x1FFU));
    phy_pbus_force(5U, 1U, (uint16_t)((dc_q >> 9) & 0x1FFU));
    phy_pbus_force(4U, 2U, (uint16_t)(dc_i & 0x1FFU));
    phy_pbus_force(5U, 2U, (uint16_t)(dc_q & 0x1FFU));
}

static int8_t phy_rfcal_rxiq_set_reg(int8_t val, uint8_t *sign_out,
                                     uint8_t is_gain, uint8_t sign_mag_mode)
{
    int32_t v = (int32_t)val;
    uint8_t neg = 0U;

    if (sign_mag_mode == 0U) {
        int32_t lim = (is_gain != 0U) ? 15 : 31;
        v = s_clamp32(v, -lim, lim);
        if (is_gain != 0U) {
            rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x19U, 4U, 0U,
                                  (uint8_t)((uint32_t)v & 0x1FU));
            return (int8_t)v;
        }
    } else {
        if (v < 0) {
            neg = 1U;
            v = -v;
        }
        *sign_out = neg;
        if (is_gain != 0U) {
            if (v > 15) {
                v = 15;
            }
            rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x18U, 5U, 5U, neg);
            rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x19U, 4U, 0U,
                                  (uint8_t)((uint32_t)v & 0x1FU));
            return (neg != 0U) ? (int8_t)(-v) : (int8_t)v;
        }
        if (v > 31) {
            v = 31;
        }
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x18U, 3U, 3U, neg);
    }

    uint32_t uv = (uint32_t)v & 0xFFU;
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x19U, 7U, 5U,
                          (uint8_t)((uv >> 3) & 7U));
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x1AU, 2U, 0U,
                          (uint8_t)(uv & 7U));

    if (sign_mag_mode != 0U && neg != 0U) {
        return (int8_t)(-v);
    }
    return (int8_t)v;
}

static void phy_rxiq_get_mis(uint8_t shift_bits, uint8_t tx_g_sign, uint8_t tx_p_sign,
                             uint8_t rx_p_sign, uint8_t rx_g_sign, int8_t out_mis[2])
{
    uint32_t sh = ((uint32_t)shift_bits - 2U) & 31U;
    int32_t ii = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_ACC_REG(0)) >> sh;
    int32_t iq = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_ACC_REG(1)) >> sh;
    int32_t qi = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_ACC_REG(2)) >> sh;
    int32_t qq = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_ACC_REG(3)) >> sh;

    int32_t p1 = ii + qq;
    int32_t p2 = ii - qq;
    int32_t q1 = iq - qi;
    int32_t q2 = qi + iq;

    if ((tx_p_sign ^ tx_g_sign) != (rx_p_sign ^ rx_g_sign)) {
        int32_t tmp = p1;
        p1 = p2;
        p2 = tmp;
        tmp = q1;
        q1 = q2;
        q2 = tmp;
    }

    int64_t denom = (int64_t)p1 * (int64_t)p1 + (int64_t)q1 * (int64_t)q1;
    int64_t num_g = (int64_t)p1 * (int64_t)p2 - (int64_t)q1 * (int64_t)q2;
    int64_t num_p = (int64_t)q1 * (int64_t)p2 + (int64_t)p1 * (int64_t)q2;

    if (denom == 0) {
        denom = 1;
    }

    int8_t raw_g = (int8_t)((num_g * 512) / denom);
    int8_t raw_p = (int8_t)((num_p * 512) / denom);
    int8_t g_mis = (int8_t)((raw_g + 1) >> 1);
    int8_t p_mis = (int8_t)((raw_p + 1) >> 1);

    if (rx_g_sign != 0U) {
        g_mis = (int8_t)(-g_mis);
    }
    if (rx_p_sign != 0U) {
        p_mis = (int8_t)(-p_mis);
    }
    out_mis[0] = g_mis;
    out_mis[1] = p_mis;
}

static void phy_rxiq_cover_mg_mp(uint8_t shift_bits, uint8_t tx_g_sign, uint8_t tx_p_sign,
                                 uint8_t orig_rx_g_sign, uint8_t orig_rx_p_sign,
                                 int8_t *out_gain, int8_t *out_phase,
                                 uint8_t sign_mag_mode)
{
    uint16_t samples = (uint16_t)(1U << (shift_bits & 31U));
    int8_t gain_est = 0;
    int8_t phase_est = 0;
    uint8_t cur_g_sign = orig_rx_g_sign;
    uint8_t cur_p_sign = orig_rx_p_sign;
    int8_t mis[2] = { 0, 0 };

    for (uint32_t iter = 0U; iter < 2U; iter++) {
        int32_t p_sq = ((int32_t)phase_est * (int32_t)phase_est + 128) >> 8;
        int8_t g_applied = phy_rfcal_rxiq_set_reg((int8_t)((int32_t)gain_est - p_sq),
                                                  &cur_g_sign, 1U, sign_mag_mode);
        int8_t p_applied = phy_rfcal_rxiq_set_reg(phase_est, &cur_p_sign, 0U, sign_mag_mode);

        phy_iq_est_enable(1U, samples);

        cur_g_sign = (uint8_t)(orig_rx_g_sign ^ cur_g_sign);
        cur_p_sign = (uint8_t)(orig_rx_p_sign ^ cur_p_sign);

        phy_rxiq_get_mis(shift_bits, tx_g_sign, tx_p_sign, cur_p_sign, cur_g_sign, mis);

        gain_est = (int8_t)(p_sq + (int32_t)mis[0] + (int32_t)g_applied);
        phase_est = (int8_t)((int32_t)p_applied - (int32_t)mis[1]);

        phy_iq_est_disable();
    }

    if (s_abs32((int32_t)mis[0]) > 4 || s_abs32((int32_t)mis[1]) > 4) {
        g_phy_check_result |= 0x4000U;
        s_rxiq_cover_fail_num++;
    }

    gain_est = (int8_t)s_clamp32((int32_t)gain_est, -15, 15);
    phase_est = (int8_t)s_clamp32((int32_t)phase_est, -31, 31);

    (void)phy_rfcal_rxiq_set_reg(gain_est, &cur_g_sign, 1U, sign_mag_mode);
    (void)phy_rfcal_rxiq_set_reg(phase_est, &cur_p_sign, 0U, sign_mag_mode);

    *out_gain = gain_est;
    *out_phase = phase_est;
}

static void s_set_txiq_cal(uint8_t *tx_g_sign, uint8_t *tx_p_sign)
{
    uint32_t reg = PHY_REG_READ(PHY_BB_TXIQ_GAIN_COMMIT_REG);
    uint32_t g = (reg >> 24) & 0x1FU;
    uint32_t p = (reg >> 18) & 0x3FU;

    uint32_t g_val = (g < 16U) ? g : ((g - 32U) & 0xFFU);
    uint32_t p_val = (p < 32U) ? 0U : ((p - 64U) & 0xFFU);

    *tx_g_sign = (uint8_t)(((-g_val) >> 7) & 1U);
    *tx_p_sign = (uint8_t)((p_val >> 7) & 1U);

    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x10U, 0U, 0U, *tx_g_sign);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x0FU, 6U, 6U, *tx_p_sign);
}

static void phy_rfcal_rxiq(uint8_t shift_bits, int16_t tone_freq, uint8_t atten,
                           int8_t out_iq[2], uint8_t sign_mag_mode)
{
    uint8_t orig_tx_g = (rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x10U, 0U, 0U) != 0U) ? 1U : 0U;
    uint8_t orig_tx_p = (rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x0FU, 6U, 6U) != 0U) ? 1U : 0U;
    uint8_t orig_rx_g = (rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x18U, 5U, 5U) != 0U) ? 1U : 0U;
    uint8_t orig_rx_p = (rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x18U, 3U, 3U) != 0U) ? 1U : 0U;
    uint8_t orig_scale = rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 9U, 7U, 0U);

    phy_set_rxclk_en(1U);

    uint8_t tx_g = orig_tx_g;
    uint8_t tx_p = orig_tx_p;
    if (sign_mag_mode != 0U) {
        s_set_txiq_cal(&tx_g, &tx_p);
    }

    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x10U, 2U, 2U, 1U);
    tx_g ^= orig_tx_g;
    tx_p ^= orig_tx_p;
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x18U, 7U, 7U, 1U);

    uint8_t tx_atten = phy_set_ana_inf_tx_scale(atten);
    phy_start_tx_tone(1U, tone_freq, tx_atten, 0U, 0, 0U, 0U, 0, 0U);

    int8_t g_out = 0;
    int8_t p_out = 0;
    phy_rxiq_cover_mg_mp(shift_bits, tx_g, tx_p, orig_rx_g, orig_rx_p,
                         &g_out, &p_out, sign_mag_mode);

    phy_stop_tx_tone(1U);

    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x10U, 0U, 0U, orig_tx_g);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x0FU, 6U, 6U, orig_tx_p);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x18U, 5U, 5U, orig_rx_g);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x18U, 3U, 3U, orig_rx_p);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 9U, 7U, 0U, orig_scale);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x18U, 7U, 7U, 0U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x10U, 2U, 2U, 0U);

    phy_set_rxclk_en(0U);

    out_iq[0] = g_out;
    out_iq[1] = p_out;
}

static void phy_set_rx_gain_cal_iq(uint8_t single_mode, int16_t tone_freq,
                                   uint16_t rxiq_out[5], const uint32_t *dc_table,
                                   uint8_t sign_mag_mode)
{
    PHY_REG_CLR(PHY_RF_RX_GAIN_EXT_REG, PHY_RF_RX_GAIN_EXT_DIG);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x12U, 7U, 0U, 0U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 9U, 7U, 0U, 0U);

    uint32_t num_levels = (single_mode != 0U) ? 1U : 5U;

    for (uint32_t lvl = 0U; lvl < num_levels; lvl++) {
        uint16_t txbb;
        uint16_t bbrx1;
        uint8_t atten;

        if (lvl >= 1U && lvl <= 4U) {
            txbb = 0U;
            bbrx1 = s_rxiq_bbrx1[lvl - 1U];
            atten = s_rxiq_atten[lvl - 1U];
        } else {
            txbb = (lvl == 0U) ? 8U : 0U;
            bbrx1 = 0U;
            atten = 0U;
        }

        phy_pbus_xpd_tx_on(txbb);
        if (lvl < 2U) {
            int8_t tdc[2];
            s_rxiq_cal_tos_v60(txbb, tdc);
        }

        phy_set_loopback_gain(1U, 0x104U, bbrx1, 0x16U);
        s_set_cal_rxdc(bbrx1, 0x16U, dc_table);
        phy_set_rxclk_en(1U);

        uint16_t pa_gain = 1U;
        for (uint32_t k = 0U; k < 2U; k++) {
            phy_start_tx_tone(1U, tone_freq, atten, 0U, 0, 0U, 0U, 0, 0U);
            phy_iq_est_enable(1U, 0x400U);
            uint32_t total_pwr = PHY_REG_READ(PHY_FE_IQ_EST_PWR_REG) >> 8;
            phy_iq_est_disable();
            phy_stop_tx_tone(1U);

            if (total_pwr >= 0x200U && total_pwr <= 0x7A00U) {
                break;
            }
            if ((int32_t)total_pwr <= 0x8000) {
                if (k == 0U) {
                    pa_gain = ((int32_t)total_pwr > 0x3FF) ? 3U : 7U;
                } else {
                    atten = 0U;
                }
            } else {
                if (k == 0U) {
                    pa_gain = 0U;
                } else {
                    atten = (uint8_t)(atten + 24U);
                }
            }

            phy_set_loopback_gain(pa_gain, 0x104U, bbrx1, 0x16U);
            s_set_cal_rxdc(bbrx1, 0x16U, dc_table);
        }

        int32_t sum_g = 0;
        int32_t sum_p = 0;
        int8_t prev_g = 0;
        int8_t prev_p = 0;
        int32_t final_g = 0;
        int32_t final_p = 0;
        uint32_t iters = 4U;

        for (uint32_t n = 0U; n < 4U; n++) {
            int8_t iq[2];
            phy_rfcal_rxiq(13U, tone_freq, atten, iq, sign_mag_mode);

            if (n != 0U &&
                s_abs32((int32_t)prev_g - (int32_t)iq[0]) < 2 &&
                s_abs32((int32_t)prev_p - (int32_t)iq[1]) < 2) {
                final_g = ((int32_t)iq[0] + (int32_t)prev_g + 1) >> 1;
                final_p = ((int32_t)iq[1] + (int32_t)prev_p + 1) >> 1;
                iters = n;
                break;
            }

            sum_g += (int32_t)iq[0];
            sum_p += (int32_t)iq[1];
            prev_g = iq[0];
            prev_p = iq[1];

            if (n == 3U) {
                final_g = (sum_g + 2) >> 2;
                final_p = (sum_p + 2) >> 2;
            }
        }

        final_g = s_clamp32(final_g, -15, 15);
        final_p = s_clamp32(final_p, -31, 31);

        if (single_mode == 0U) {
            rxiq_out[lvl] = (uint16_t)((((uint32_t)final_g & 0x1FU) << 6) |
                                       ((uint32_t)final_p & 0x3FU));
        }
        s_rxiq_compute_num = (s_rxiq_compute_num << 2) | (iters & 3U);
    }

    PHY_REG_SET(PHY_RF_RX_GAIN_EXT_REG, PHY_RF_RX_GAIN_EXT_DIG);
}

/* --------------------------------------------------------------------------
 * RX Gain Table Generation & Dual-Window Hardware RAM Load
 * -------------------------------------------------------------------------- */

static uint8_t phy_gen_rx_gain_table(uint32_t *table, uint8_t max_gain,
                                     const uint8_t *gain_idx,
                                     const uint8_t *bb_idx, uint8_t bb_len)
{
    uint32_t last = (uint32_t)bb_len - 1U;
    uint32_t seq = 0U;
    uint32_t gain = 0U;
    uint32_t pos = 0U;

    for (;;) {
        if (gain == (uint32_t)bb_idx[pos] && pos < last) {
            do {
                pos++;
                if (bb_idx[pos] != 0U) {
                    break;
                }
            } while (pos < last);
            gain = 0U;
        }

        uint32_t frac = gain % 6U;
        uint32_t step = gain / 6U;
        uint32_t bb = ((uint32_t)s_bb_step_tab[step] & 0x1FFFU) << 3;
        uint32_t val = (((uint32_t)gain_idx[pos] << 8) + bb + frac) & 0xFFFFU;

        if ((seq & 1U) == 0U) {
            table[seq >> 1] = val;
        } else {
            table[seq >> 1] |= val << 16;
        }

        if (gain > (uint32_t)max_gain) {
            return (uint8_t)seq;
        }

        seq++;
        gain++;
        if (seq == 0x7FU) {
            return 0x55U;
        }
    }
}

static void phy_set_rx_gain_testchip_50(uint8_t cal_iq_en, uint32_t *param_flag,
                                        uint32_t *dc_table, uint16_t rxiq_table[5],
                                        uint8_t count, const uint32_t *gain_table)
{
    if (g_phy_rx_table_renew_en != 0U || (*param_flag & PHY_PARAM_RX_GAIN_VALID) == 0U) {
        PHY_REG_SET(PHY_RFPLL_CTRL_REG, PHY_RFPLL_SLP_HOLD);
        PHY_REG_WRITE(PHY_BB_RX_GAIN_WINDOW_REG, 0x000001E0U);
        phy_pbus_debugmode();

        uint8_t saved_12 = rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x12U, 7U, 0U);
        uint8_t saved_18 = (rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x18U, 5U, 5U) != 0U) ? 1U : 0U;

        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x18U, 5U, 5U, 0U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x12U, 7U, 0U, 0U);

        uint32_t done_mask = 0U;
        for (uint32_t n = 0U; n < (uint32_t)count; n++) {
            uint16_t raw = s_read_gain_entry(gain_table, n);
            uint32_t bits = s_popcount7((uint32_t)(raw & 0x7FFFU) >> 3);
            if (bits > 4U) {
                bits = 4U;
            }
            uint32_t idx = bits * 6U + ((uint32_t)raw & 7U);
            if (idx > 29U) {
                idx = 29U;
            }

            if ((done_mask & (1U << idx)) == 0U) {
                if (idx < 24U && (idx & 1U) == 0U) {
                    int16_t dac[4];
                    phy_pbus_set_rxgain(raw & 0x0FFFU);
                    phy_pbus_dco_sa2(4000U, dac, 10U);
                    dc_table[idx * 2U] = (((uint32_t)dac[0] & 0x1FFU) << 9) |
                                         ((uint32_t)dac[2] & 0x1FFU);
                    dc_table[idx * 2U + 1U] = (((uint32_t)dac[1] & 0x1FFU) << 9) |
                                              ((uint32_t)dac[3] & 0x1FFU);
                } else {
                    uint32_t src = (idx < 24U) ? (idx - 1U) : (idx - 6U);
                    dc_table[idx * 2U] = dc_table[src * 2U];
                    dc_table[idx * 2U + 1U] = dc_table[src * 2U + 1U];
                }
                done_mask |= (1U << idx);
            }
        }

        if ((*param_flag & PHY_PARAM_RX_GAIN_VALID) == 0U && cal_iq_en != 0U) {
            phy_set_rx_gain_cal_iq(0U, 8, rxiq_table, dc_table, 0U);
        }

        PHY_REG_CLR(PHY_RFPLL_CTRL_REG, PHY_RFPLL_SLP_HOLD);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x18U, 5U, 5U, saved_18);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x12U, 7U, 0U, saved_12);
        phy_pbus_xpd_tx_off();
        phy_pbus_xpd_rx_on();
        phy_pbus_workmode();

        *param_flag |= PHY_PARAM_RX_GAIN_VALID;
    }

    for (uint32_t n = 0U; n < (uint32_t)count; n++) {
        uint32_t raw = (uint32_t)s_read_gain_entry(gain_table, n) & 0x7FFFU;
        uint32_t bits = s_popcount7(raw >> 3);
        if (bits > 4U) {
            bits = 4U;
        }
        uint32_t idx = bits * 6U + (raw & 7U);
        if (idx > 29U) {
            idx = 29U;
        }

        uint32_t dc_i = dc_table[idx * 2U];
        uint32_t dc_q = dc_table[idx * 2U + 1U];

        uint32_t lo_word = (raw << 17) |
                           (((dc_i >> 9) & 0x1FFU) << 8) |
                           ((dc_i & 0x1FFU) >> 1);
        uint32_t hi_word = ((dc_i & 1U) << 31) |
                           (((dc_q >> 9) & 0x1FFU) << 22) |
                           ((dc_q & 0x1FFU) << 13) |
                           (((uint32_t)rxiq_table[bits] & 0x7FFU) << 2);

        PHY_REG_WRITE(PHY_BB_RX_GAIN_WINDOW_REG, 0x0000001EU);
        PHY_REG_WRITE(PHY_BB_RX_GAIN_TABLE_REG(n), lo_word);
        PHY_REG_WRITE(PHY_BB_RX_GAIN_WINDOW_REG, 0x000001E0U);
        PHY_REG_WRITE(PHY_BB_RX_GAIN_TABLE_REG(n), hi_word);
    }
}

void phy_set_rx_gain_table(uint8_t rxmax)
{
    if (g_phy_rx_table_renew_en != 0U) {
        g_phy_rx_max_gain_val = phy_gen_rx_gain_table(phy_rx_gain_dc_table, 0x1CU,
                                                      s_gain_idx_tab, s_bb_idx_tab,
                                                      (uint8_t)(16U - rxmax));
    }

    phy_set_rx_gain_testchip_50(1U, &g_phy_sleep_params.param_flag,
                                &phy_rx_gain_dc_table[64], g_phy_sleep_params.rxiq,
                                (uint8_t)(g_phy_rx_max_gain_val + 1U),
                                phy_rx_gain_dc_table);

    if ((chip6_phy_init_ctrl[0x4C] & 1U) == 0U) {
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x12U, 0xE8U);
    } else {
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x12U, 0xD8U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x18U, 1U, 1U, 1U);
    }

    PHY_REG_SET(PHY_BB_TXIQ_GAIN_COMMIT_REG, 1U);

    if (g_phy_rx_max_gain_val > 0x55U) {
        g_phy_rx_max_gain_val = 0x55U;
    }
    if (rxmax == 0U) {
        g_phy_rx_max_gain_val = 0x46U;
    }

    PHY_REG_RMW(PHY_BB_RX_MAX_GAIN_REG, 0x0000007FU, g_phy_rx_max_gain_val);
}

/* --------------------------------------------------------------------------
 * Noise Floor Measurement, Initialization & Background Tracking
 * -------------------------------------------------------------------------- */

int16_t phy_get_noisefloor(void)
{
    uint32_t raw = (PHY_REG_READ(PHY_BB_NOISE_FLOOR_REG) >> 20) & 0xFFFU;
    return (int16_t)(((int32_t)((raw + 1U) >> 1)) - 0x800);
}

static int16_t s_get_noisefloor_sat(void)
{
    int32_t nf = (int32_t)phy_get_noisefloor();
    if (nf >= -340) {
        return -340;
    }
    if (nf < -392) {
        return -392;
    }
    return (int16_t)nf;
}

void phy_set_noise_floor(int16_t nf)
{
    PHY_REG_CLR(PHY_BB_RX_CTRL_REG, PHY_BB_NOISE_MEAS);
    int32_t half = ((int32_t)nf + 1) / 2;
    PHY_REG_RMW(PHY_BB_NOISE_FLOOR_REG, 0x000001FFU, (uint32_t)half & 0x1FFU);
    PHY_REG_RMW(PHY_BB_RX_CTRL_REG, 0x00028002U, PHY_BB_NOISE_MEAS);
}

void phy_start_noisefloor(uint8_t chan_idx)
{
    if ((PHY_REG_READ(PHY_BB_RX_CTRL_REG) & PHY_BB_NOISE_MEAS) == 0U) {
        PHY_REG_RMW(PHY_BB_NOISE_FLOOR_REG, 0x00000FFFU,
                    (((uint32_t)chan_idx & 7U) << 9) | 0x1A0U);
        PHY_REG_SET(PHY_BB_RX_CTRL_REG, 0x00028002U);
    }
}

static uint8_t s_do_noisefloor(uint8_t chan_idx, uint16_t delay_us,
                               uint32_t start_time, uint32_t timeout_us)
{
    while ((PHY_REG_READ(PHY_BB_RX_CTRL_REG) & PHY_BB_NOISE_MEAS) != 0U) {
        if ((phy_get_mactime() - start_time) > timeout_us) {
            return 1U;
        }
    }

    ets_delay_us(delay_us);
    phy_start_noisefloor(chan_idx);

    do {
        if ((PHY_REG_READ(PHY_BB_RX_CTRL_REG) & PHY_BB_NOISE_MEAS) == 0U) {
            return 0U;
        }
    } while ((phy_get_mactime() - start_time) <= timeout_us);

    return 1U;
}

int16_t read_hw_noisefloor(void)
{
    int32_t v = (int32_t)(PHY_REG_READ(PHY_BB_RX_RSSI_REG) & 0xFFFU) - 0xFFF;
    return (int16_t)(v >> 1);
}

void noise_check_loop(uint8_t chan_idx, uint8_t apply_now)
{
    PHY_REG_RMW(PHY_BB_NOISE_FLOOR_REG, 0x00000E00U, 0x00000200U);

    if (((PHY_REG_READ(PHY_BB_RX_CTRL_REG) >> 15) & 5U) != 5U) {
        phy_start_noisefloor(chan_idx);
        phy_rtc_mem_backup_chunk2();
        return;
    }

    if ((PHY_REG_READ(PHY_BB_RX_CTRL_REG) & PHY_BB_NOISE_MEAS) == 0U ||
        s_loop_time_limit > 9U) {
        int32_t nf = -336;
        if (s_loop_time_limit > 9U ||
            ((nf = (int32_t)phy_get_noisefloor()), nf > -404)) {
            if (s_loop_time_limit < 10U) {
                nf = s_clamp32(nf, -392, -340);
            }

            int32_t cur = (int32_t)g_phy_sleep_params.loop_noisefloor;
            if (cur < nf) {
                g_phy_sleep_params.loop_noisefloor = (int16_t)((nf + cur * 3 - 2) / 4);
            } else if (nf < cur) {
                if (cur - 16 <= nf) {
                    g_phy_sleep_params.loop_noisefloor = (int16_t)((nf * 3 + cur - 2) / 4);
                } else {
                    g_phy_sleep_params.loop_noisefloor = (int16_t)(cur - 12);
                }
            }

            int32_t updated = (int32_t)g_phy_sleep_params.loop_noisefloor;
            if (g_phy_sw_scan_mode == 0U) {
                if (updated > (int32_t)g_phy_sleep_params.rx_noise + 8 ||
                    updated < (int32_t)g_phy_sleep_params.rx_noise - 8) {
                    g_phy_sleep_params.rx_noise = (int16_t)updated;
                    if (apply_now != 0U) {
                        phy_set_noise_floor(g_phy_sleep_params.rx_noise);
                    }
                }
            } else {
                if (updated < -387) {
                    g_phy_sleep_params.rx_noise = (int16_t)updated;
                } else {
                    g_phy_sleep_params.rx_noise = (int16_t)((updated - 388) / 2);
                }
                if (apply_now != 0U) {
                    phy_set_noise_floor(g_phy_sleep_params.rx_noise);
                }
            }
        }

        phy_start_noisefloor(chan_idx);
        s_loop_time_limit = 0U;
    } else {
        s_loop_time_limit++;
    }

    phy_rtc_mem_backup_chunk2();
}

void phy_noise_init(uint8_t chan_start, uint8_t num_samples, uint8_t max_ch,
                    uint16_t timeout_us, uint8_t use_min, uint32_t unused,
                    uint32_t *param_flag)
{
    (void)unused;

    if ((*param_flag & PHY_PARAM_NOISE_VALID) != 0U) {
        phy_set_noise_floor(g_phy_sleep_params.rx_noise);
        PHY_REG_RMW(PHY_BB_RX_GAIN_FORCE_REG, 0x000003FFU, 201U);
        PHY_REG_CLR(PHY_BB_RX_GAIN_FORCE_REG, PHY_BB_RX_GAIN_LATCH);
        (void)PHY_REG_READ(PHY_BB_RX_CTRL_REG);
        return;
    }

    phy_set_noise_floor(-388);
    PHY_REG_RMW(PHY_BB_RX_GAIN_FORCE_REG, 0x000003FFU, 201U);
    PHY_REG_CLR(PHY_BB_RX_GAIN_FORCE_REG, PHY_BB_RX_GAIN_LATCH);
    (void)PHY_REG_READ(PHY_BB_RX_CTRL_REG);

    g_phy_sleep_params.rx_noise = -388;
    for (uint32_t i = 0U; i < 4U; i++) {
        s_noise_array[i] = -340;
    }

    uint32_t saved_dig_rx = PHY_REG_READ(PHY_BB_DIG_RX_REG);
    uint32_t saved_d20 = PHY_REG_READ(PHY_BB_AGC_THR_9D20_REG);
    uint32_t saved_d40 = PHY_REG_READ(PHY_BB_AGC_THR_9D40_REG);

    PHY_REG_CLR(PHY_BB_DIG_RX_REG, 1U);
    PHY_REG_CLR(PHY_BB_AGC_THR_9D20_REG, 0x40000000U);

    for (uint32_t g = 0U; g < 4U; g++) {
        uint32_t start_t = phy_get_mactime();
        uint8_t ch = (g == 3U) ? 14U : (uint8_t)(g * 5U + 1U);
        phy_set_chan(ch);
        (void)PHY_REG_READ(PHY_BB_RX_CTRL_REG);

        for (uint32_t s = 0U; s < (uint32_t)num_samples; s++) {
            if (s_do_noisefloor(chan_start, (uint16_t)max_ch, start_t, timeout_us) != 0U) {
                break;
            }
            int16_t val = s_get_noisefloor_sat();
            if (val < s_noise_array[g]) {
                s_noise_array[g] = val;
            }
        }

        PHY_REG_CLR(PHY_BB_RX_GAIN_FORCE_REG, PHY_BB_RX_GAIN_LATCH);
    }

    PHY_REG_WRITE(PHY_BB_DIG_RX_REG, saved_dig_rx);
    PHY_REG_WRITE(PHY_BB_AGC_THR_9D20_REG, saved_d20);
    PHY_REG_WRITE(PHY_BB_AGC_THR_9D40_REG, saved_d40);

    if (use_min == 0U) {
        g_phy_sleep_params.rx_noise = -388;
    } else {
        int16_t mn = s_noise_array[0];
        if (mn > -40) {
            mn = -40;
        }
        for (uint32_t i = 1U; i < 4U; i++) {
            if (s_noise_array[i] < mn) {
                mn = s_noise_array[i];
            }
        }
        g_phy_sleep_params.rx_noise = mn;
        phy_set_noise_floor(mn);
    }

    *param_flag |= PHY_PARAM_NOISE_VALID;
    g_phy_sleep_params.loop_noisefloor = g_phy_sleep_params.rx_noise;
}
