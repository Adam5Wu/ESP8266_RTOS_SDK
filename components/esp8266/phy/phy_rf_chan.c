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
// Portions of the RF power-on/wake/close, RFPLL tuning, channel compensation,
// and baseband RX configuration sequences are adapted from teatime-os:
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

uint8_t g_phy_vga_lna_dcap[2] = { 0U, 0U };
uint8_t g_phy_rfpll_sdm_reg[3] = { 0U, 0U, 0U };
uint8_t g_phy_or_pll_cap_last = 0U;
uint8_t g_phy_rfpll_unlock = 0U;
uint8_t g_phy_rx_gain_dc_flag = 0U;

static uint8_t s_pll_cap_m[2] = { 0U, 0U };
static uint8_t s_tx_cont_en_flag = 0U;
static uint32_t s_tx_data[4] = { 0U, 0U, 0U, 0U };

/* --------------------------------------------------------------------------
 * 4-Byte Aligned Flash Lookup Tables (.flash.rodata)
 * -------------------------------------------------------------------------- */

static const uint16_t s_chan_mhz[14] __attribute__((aligned(4))) = {
    2412U, 2417U, 2422U, 2427U, 2432U, 2437U, 2442U,
    2447U, 2452U, 2457U, 2462U, 2467U, 2472U, 2484U
};

static const uint16_t s_chan_rcp_off[14] __attribute__((aligned(4))) = {
    737U, 692U, 647U, 602U, 558U, 514U, 470U,
    426U, 382U, 339U, 295U, 252U, 209U, 106U
};

/* --------------------------------------------------------------------------
 * Internal Helpers
 * -------------------------------------------------------------------------- */

static inline int32_t s_abs32(int32_t v)
{
    return (v < 0) ? -v : v;
}

static uint16_t s_read_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static int32_t s_calc_frac_spur(uint16_t freq_mhz, uint32_t num, uint32_t denom)
{
    if (denom == 0U || num == 0U) {
        return 0;
    }

    int32_t p = (int32_t)(denom * (uint32_t)freq_mhz);
    int32_t q = p / (int32_t)num;
    int32_t r = p % (int32_t)num;
    int32_t thresh = (int32_t)(denom * 10U);

    if (r < thresh) {
        /* q is the closest harmonic below freq_mhz */
    } else if ((int32_t)num - r < thresh) {
        q += 1;
    } else {
        return 0;
    }

    /* floor((num / denom) * q * 10) - freq_mhz * 10 using pure 32-bit math */
    int32_t harm_0p1 = (int32_t)(((uint32_t)num * (uint32_t)q * 10U) / denom);
    return harm_0p1 - (int32_t)freq_mhz * 10;
}

static int32_t s_dig_spur_set(uint8_t chan, uint16_t freq_mhz)
{
    uint32_t xtal_mhz = (chip6_phy_init_ctrl[0] == 1U) ? 26U :
                        (chip6_phy_init_ctrl[0] == 2U) ? 24U : 40U;

    int32_t xtal_q = (int32_t)((uint32_t)freq_mhz / xtal_mhz);
    int32_t xtal_r = (int32_t)((uint32_t)freq_mhz % xtal_mhz);
    int32_t spur_xtal = 0;

    if (xtal_r < 10) {
        spur_xtal = (xtal_q * (int32_t)xtal_mhz - (int32_t)freq_mhz) * 10;
    } else if ((int32_t)xtal_mhz - xtal_r < 10) {
        spur_xtal = ((xtal_q + 1) * (int32_t)xtal_mhz - (int32_t)freq_mhz) * 10;
    }

    uint32_t s1_num = (uint32_t)chip6_phy_init_ctrl[0x0B] |
                      ((uint32_t)chip6_phy_init_ctrl[0x2A] << 8);
    uint32_t s1_den = (uint32_t)chip6_phy_init_ctrl[0x0C];
    int32_t spur1 = s_calc_frac_spur(freq_mhz, s1_num, s1_den);

    uint32_t s2_num = (uint32_t)chip6_phy_init_ctrl[0x26] |
                      ((uint32_t)chip6_phy_init_ctrl[0x2B] << 8);
    uint32_t s2_den = (uint32_t)chip6_phy_init_ctrl[0x27];
    int32_t spur2 = s_calc_frac_spur(freq_mhz, s2_num, s2_den);

    int32_t base_0p1 = 24000 - (int32_t)freq_mhz * 10;
    int32_t spur3 = (int32_t)s_read_le16(&chip6_phy_init_ctrl[0x2C]) + base_0p1;
    if (s_abs32(spur3) > 99) {
        spur3 = 0;
    }
    int32_t spur4 = (int32_t)s_read_le16(&chip6_phy_init_ctrl[0x2E]) + base_0p1;
    if (s_abs32(spur4) > 99) {
        spur4 = 0;
    }

    uint32_t ch_bit = (uint32_t)(chan - 1U) & 31U;
    uint16_t s1_mask = s_read_le16(&chip6_phy_init_ctrl[0x0E]);
    uint16_t s2_mask = s_read_le16(&chip6_phy_init_ctrl[0x28]);

    int32_t spur_0p1;
    if ((((uint32_t)s1_mask >> ch_bit) & 1U) != 0U && spur1 != 0) {
        spur_0p1 = spur1;
    } else if ((((uint32_t)s2_mask >> ch_bit) & 1U) != 0U && spur2 != 0) {
        spur_0p1 = spur2;
    } else if (spur3 != 0) {
        spur_0p1 = spur3;
    } else if (spur4 != 0) {
        spur_0p1 = spur4;
    } else {
        spur_0p1 = spur_xtal;
    }

    /* Pure-integer equivalent of (int32_t)(spur_0p1 * 52428.8 / 10.0) and
     * (int32_t)(spur_0p1 * 51.2 / 10.0), verified bit-exact over [-99, +99]. */
    uint32_t freq_lo = (uint32_t)((spur_0p1 * 131072) / 25) & 0xFFFFFU;
    uint32_t freq_hi = (uint32_t)((spur_0p1 * 128) / 25) & 0x3FFU;

    PHY_REG_RMW(PHY_BB_SPUR_FREQ_REG, 0x3FFFFFFFU, (freq_hi << 20) | freq_lo);
    return spur_0p1;
}

static void s_write_spur_mask_quad(uint32_t r_hi, uint32_t r_mid,
                                   uint32_t r_lo1, uint32_t r_lo2,
                                   int32_t s_idx, uint8_t u_idx, uint32_t pat)
{
    uint32_t v_hi = (s_idx > 15) ? (pat << (((uint32_t)s_idx << 1) & 31U)) : 0U;
    uint32_t v_mid;
    if ((uint8_t)(u_idx - 1U) < 15U) {
        v_mid = pat << ((uint32_t)(s_idx * 2 - 2) & 31U);
    } else {
        v_mid = (u_idx == 0U) ? (pat >> 2) : 0U;
    }
    uint32_t v_lo1 = ((uint8_t)(u_idx + 15U) < 15U)
                         ? (pat << ((uint32_t)(s_idx * 2 + 30) & 31U))
                         : 0U;
    uint32_t v_lo2 = ((uint8_t)(u_idx + 30U) < 15U)
                         ? (pat << ((uint32_t)(s_idx * 2 + 60) & 31U))
                         : 0U;

    PHY_REG_WRITE(r_hi, v_hi);
    PHY_REG_WRITE(r_mid, v_mid);
    PHY_REG_WRITE(r_lo1, v_lo1);
    PHY_REG_WRITE(r_lo2, v_lo2);
}

static void s_dig_spur_prot(int32_t spur_0p1)
{
    uint8_t u_idx = 0U;
    int32_t mask = 0;

    if (spur_0p1 != 0) {
        int32_t s32 = spur_0p1 << 5;
        int32_t q = s32 / 100;
        int32_t d = (s32 / 10) % 10;

        if (spur_0p1 <= 0) {
            u_idx = (uint8_t)(q - 1);
            if (d == -9) {
                mask = 1;
            } else if (d < -2) {
                mask = 3;
            } else {
                mask = 2;
            }
        } else {
            u_idx = (uint8_t)q;
            if (d < 2) {
                mask = 1;
            } else if (d < 8) {
                mask = 3;
            } else {
                mask = 2;
            }
        }
    }

    int32_t s_idx = (int32_t)(int8_t)u_idx;
    uint32_t pos_val = (s_idx > 0)
                           ? ((uint32_t)mask << ((uint32_t)(s_idx - 1) & 31U))
                           : (uint32_t)(mask >> 1);
    uint32_t neg_val = (s_idx < 0)
                           ? ((uint32_t)mask << ((uint32_t)(s_idx + 30) & 31U))
                           : 0U;

    PHY_REG_WRITE(PHY_BB_SPUR_MASK4_REG, pos_val);
    PHY_REG_WRITE(PHY_BB_SPUR_MASK3_REG, neg_val);
    PHY_REG_WRITE(PHY_BB_SPUR_MASK7_REG, pos_val);
    PHY_REG_WRITE(PHY_BB_SPUR_MASK0_REG, neg_val);

    uint32_t m2 = (mask == 1) ? 2U : (mask == 2) ? 8U : (mask == 3) ? 10U : 0U;
    s_write_spur_mask_quad(PHY_BB_SPUR_MASK2_REG, PHY_BB_SPUR_MASK1_REG,
                           PHY_BB_SPUR_MASK11_REG, PHY_BB_SPUR_MASK10_REG,
                           s_idx, u_idx, m2);

    uint32_t m1 = (mask == 1) ? 1U : (mask == 2) ? 4U : (mask == 3) ? 5U : 0U;
    s_write_spur_mask_quad(PHY_BB_SPUR_MASK9_REG, PHY_BB_SPUR_MASK8_REG,
                           PHY_BB_SPUR_MASK6_REG, PHY_BB_SPUR_MASK5_REG,
                           s_idx, u_idx, m1);
}

static void s_set_chan_rx_cmp(int8_t chan, uint8_t level)
{
    chip6_phy_init_ctrl[1] = (uint8_t)(int8_t)-7;
    chip6_phy_init_ctrl[2] = (uint8_t)(int8_t)-7;
    chip6_phy_init_ctrl[3] = (uint8_t)(int8_t)-6;

    int32_t ch = (int32_t)chan;
    int32_t base;
    if (ch < 7) {
        base = -7;
    } else if (ch < 14) {
        base = ((ch - 6) / 5) - 7;
    } else {
        base = ((ch - 2) / 5) - 7;
    }

    int8_t c0 = 0;
    int8_t c1 = 0;
    int8_t c2 = 0;
    if (level == 1U) {
        c0 = -6;
        c1 = -6;
        c2 = -6;
    } else if (level == 2U) {
        c0 = (int8_t)chip6_phy_init_ctrl[4];
        c1 = (int8_t)chip6_phy_init_ctrl[5];
        c2 = (int8_t)chip6_phy_init_ctrl[6];
    } else if (level == 3U) {
        c0 = (int8_t)chip6_phy_init_ctrl[7];
        c1 = (int8_t)chip6_phy_init_ctrl[8];
        c2 = (int8_t)chip6_phy_init_ctrl[9];
    }

    int32_t ext;
    if (ch < 7) {
        ext = (((int32_t)c1 - (int32_t)c0) * (ch - 1)) / 5 + (int32_t)c0;
    } else if (ch < 14) {
        ext = (((int32_t)c2 - (int32_t)c1) * (ch - 6)) / 5 + (int32_t)c1;
    } else {
        ext = (((int32_t)c2 - (int32_t)c1) * (ch - 2)) / 5 + (int32_t)c1;
    }

    uint32_t cmp = (uint32_t)((base + ext) & 0xFF);
    PHY_REG_RMW(PHY_BB_RX_CHAN_COMP_REG, 0x0003FC00U, cmp << 10);
    PHY_REG_SET(PHY_BB_RX_GAIN_FORCE_REG, PHY_BB_RX_GAIN_LATCH);
    PHY_REG_CLR(PHY_BB_RX_GAIN_FORCE_REG, PHY_BB_RX_GAIN_LATCH);
}

static uint16_t s_set_channel_freq_impl(uint8_t chan, uint8_t xtal_flag,
                                        int16_t freq_off, uint8_t wait_pll)
{
    PHY_REG_SET(PHY_RFPLL_CTRL_REG, PHY_RFPLL_LATCH);
    phy_rfpll_reset();

    uint8_t idx = (uint8_t)(chan - 1U);
    uint16_t freq_mhz = (idx < 13U) ? s_chan_mhz[idx] : s_chan_mhz[13];

    if ((chip6_phy_init_ctrl[0x49] & 1U) != 0U && chan == 14U) {
        freq_mhz = s_read_le16(&chip6_phy_init_ctrl[0x4A]);
    }

    uint8_t sdm[3];
    phy_rfpll_calc_sdm(freq_mhz, xtal_flag, freq_off, sdm);
    phy_write_rfpll_sdm(sdm);
    phy_rfpll_restart_cal();

    if (wait_pll != 0U) {
        phy_wait_rfpll_cal_end();
    }

    PHY_REG_CLR(PHY_RFPLL_CTRL_REG, PHY_RFPLL_LATCH);
    g_phy_rfpll_sdm_reg[0] = sdm[0];
    g_phy_rfpll_sdm_reg[1] = sdm[1];
    g_phy_rfpll_sdm_reg[2] = sdm[2];
    return freq_mhz;
}

/* --------------------------------------------------------------------------
 * Exported & Cross-TU Functions
 * -------------------------------------------------------------------------- */

void phy_rfpll_reset(void)
{
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 10U, 0xA6U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 10U, 0xA7U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 10U, 0xA5U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL_SDM, PHY_I2C_HOST_0, 1U, 0xF3U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 11U, 0xC0U);
}

void phy_write_rfpll_sdm(const uint8_t sdm[3])
{
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL_SDM, PHY_I2C_HOST_0, 0U, 0x07U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL_SDM, PHY_I2C_HOST_0, 3U, sdm[0]);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL_SDM, PHY_I2C_HOST_0, 4U, sdm[1]);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL_SDM, PHY_I2C_HOST_0, 5U, sdm[2]);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL_SDM, PHY_I2C_HOST_0, 0U, 0x17U);
}

void phy_rfpll_restart_cal(void)
{
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 0U, 6U, 6U, 1U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 0U, 5U, 5U, 0U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 0U, 5U, 5U, 1U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 0U, 6U, 6U, 0U);
}

void phy_wait_rfpll_cal_end(void)
{
    for (uint32_t i = 0U; i < 100U; i++) {
        ets_delay_us(20U);
        if (rom_i2c_readReg_Mask(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 7U, 7U, 7U) != 0U) {
            return;
        }
    }
}

void phy_rfpll_calc_sdm(uint16_t freq_mhz, uint8_t xtal_flag, int16_t freq_off,
                        uint8_t sdm[3])
{
    uint32_t xtal_mhz = (xtal_flag == 1U) ? 26U :
                        (xtal_flag == 2U) ? 24U : 40U;
    uint32_t num = (uint32_t)((int32_t)freq_mhz * 1024 + (int32_t)freq_off);
    uint32_t sdm24 = ((num << 8) / (3U * xtal_mhz)) - (32U << 16);

    sdm[0] = (uint8_t)(sdm24 >> 16);
    sdm[1] = (uint8_t)(sdm24 >> 8);
    sdm[2] = (uint8_t)(sdm24);
}

uint16_t phy_set_channel_freq(uint8_t chan, uint8_t xtal_flag, int16_t freq_off)
{
    return s_set_channel_freq_impl(chan, xtal_flag, freq_off, 1U);
}

void phy_set_chan_60(uint8_t chan, uint8_t xtal_flag, uint8_t unused,
                     int16_t freq_off, phy_sleep_params_t *slp,
                     uint16_t delay_us, uint8_t wait_pll)
{
    (void)unused;
    (void)slp;
    (void)delay_us;

    int16_t eff_off = 0;
    int16_t ana_off = 0;

    if ((chip6_phy_init_ctrl[0x4C] & 1U) != 0U) {
        int32_t fo = (int32_t)freq_off;
        if (fo < -300) {
            fo = -300;
        } else if (fo > 300) {
            fo = 300;
        }
        if ((chip6_phy_init_ctrl[0x4C] & 2U) != 0U && fo > 0) {
            fo = 0;
        }
        eff_off = (int16_t)fo;
        ana_off = (int16_t)(fo / 3);
    }

    g_phy_sleep_params.cur_chan = chan;

    if (g_phy_rfpll_unlock != 0U) {
        g_phy_or_pll_cap_last = 0x40U;
    }
    uint8_t cap_hint = (g_phy_or_pll_cap_last != 0U) ? g_phy_or_pll_cap_last : 0x60U;
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 1U, cap_hint);

    uint16_t freq_mhz = s_set_channel_freq_impl(chan, xtal_flag, eff_off, wait_pll);

    g_phy_or_pll_cap_last = rom_i2c_readReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 5U);
    int8_t s_chan = (int8_t)chan;
    if (s_chan < 3) {
        s_pll_cap_m[0] = g_phy_or_pll_cap_last;
    } else if (s_chan > 9) {
        s_pll_cap_m[1] = g_phy_or_pll_cap_last;
    }
    if (s_pll_cap_m[1] == s_pll_cap_m[0] && s_pll_cap_m[0] != 0U) {
        g_phy_rfpll_unlock = 1U;
    }

    /* eFuse RF silicon errata workaround */
    if (((PHY_REG_READ(PHY_EFUSE_DATA2_REG) >> 12) & 0xEU) == 0U &&
        (PHY_REG_READ(PHY_BB_ADC_RAND_REG) & 0x7U) == 0U) {
        PHY_REG_WRITE(PHY_RF_I2C_HOST_REG(0), 0x01041D77U);
    }

    uint8_t idx = (uint8_t)(chan - 1U);
    uint32_t rcp = 21000U + (uint32_t)((idx < 13U) ? s_chan_rcp_off[idx] : s_chan_rcp_off[13]);

    if ((chip6_phy_init_ctrl[0x4C] & 1U) != 0U) {
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 4U,
                         (uint8_t)((uint32_t)((int32_t)ana_off + 0x0C6186) & 0xFFU));
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x1CU, 6U, 6U, 1U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x1CU, 5U, 5U, 1U);
        ets_delay_us(5U);
    }

    PHY_REG_RMW(PHY_BB_CHAN_FREQ_REG, 0xFFFFE000U, 0x6000U | (rcp << 17));

    int32_t spur_0p1 = s_dig_spur_set(chan, freq_mhz);
    s_dig_spur_prot(spur_0p1);
}

void phy_set_chan_misc(uint8_t chan)
{
    int8_t tmp_atten[6];

    if ((g_phy_sleep_params.param_flag & PHY_PARAM_TXCAP_VALID) != 0U) {
        phy_set_txcap_reg(g_phy_sleep_params.txcap, chan);
    }
    if ((PHY_REG_READ(PHY_MAC_PHY_CTRL_REG) & PHY_MAC_PHY_RF_UP) != 0U) {
        phy_tx_atten_set_interp(chan, tmp_atten);
        chip_v6_rxmax_ext(g_phy_rxmax_ext_level);
        phy_set_noise_floor(g_phy_sleep_params.rx_noise);
        ets_delay_us(30U);
    }
}

void phy_set_chan(uint8_t chan)
{
    if (g_phy_sleep_mode_flag != 0U) {
        return;
    }

    uint32_t saved_dig_rx = 0U;
    if ((g_phy_sleep_params.param_flag & PHY_PARAM_BOOT_DONE) == 0U) {
        saved_dig_rx = phy_stop_dig_rx();
    } else {
        pm_set_sleep_mode(4U);
    }

    phy_set_chan_60(chan, chip6_phy_init_ctrl[0], 0U, g_phy_freq_offset,
                    &g_phy_sleep_params, 100U, 1U);
    phy_set_chan_misc(chan);
    bbpll_cal(0U);

    if ((g_phy_sleep_params.param_flag & PHY_PARAM_BOOT_DONE) == 0U) {
        phy_start_dig_rx(saved_dig_rx);
    } else {
        pm_wakeup_init(4U, 0U);
        phy_after_init_enrx();
    }

    PHY_REG_CLR(PHY_SAR_PWDET_CTRL_REG, 1U);
    PHY_REG_SET(PHY_SAR_PWDET_CTRL_REG, 1U);

    if (chip6_phy_init_ctrl[0x3C] == 2U) {
        PHY_REG_WRITE(PHY_MAC_DEBUG_REG, 0x55555555U);
    }

    if (g_phy_chan14_mic_en != 0U) {
        phy_chan14_mic_cfg((chan == 14U) ? 1U : 0U);
    }
}

void phy_set_chan_wakeup(uint8_t chan)
{
    PHY_REG_SET(PHY_RFPLL_CTRL_REG, PHY_RFPLL_LATCH);
    phy_set_chan_60(chan, chip6_phy_init_ctrl[0], 0U, g_phy_freq_offset,
                    &g_phy_sleep_params, 100U, 0U);
}

void phy_set_chan_wakeup_exit(uint8_t chan)
{
    int8_t tmp_atten[6];

    phy_set_txcap_reg(g_phy_sleep_params.txcap, chan);
    phy_tx_atten_set_interp(chan, tmp_atten);
    phy_wait_rfpll_cal_end();
    chip_v6_rxmax_ext(g_phy_rxmax_ext_level);
    phy_set_noise_floor(g_phy_sleep_params.rx_noise);
    PHY_REG_CLR(PHY_RFPLL_CTRL_REG, PHY_RFPLL_LATCH);
}

int phy_change_channel(uint16_t freq_mhz)
{
    uint8_t chan = phy_mhz2ieee(freq_mhz, 0x80U);
    phy_set_chan(chan);
    return 0;
}

void phy_enable_agc(void)
{
    phy_chip_v5_enable_cca();
}

void phy_disable_agc(void)
{
    phy_chip_v5_disable_cca();
}

void phy_rxmax_ext_ana(uint8_t level)
{
    uint32_t d = (uint32_t)rom_i2c_readReg_Mask(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 5U, 7U, 0U);

    int32_t g0 = ((int32_t)(d * 24U) - 340) / 227;
    if (g0 > 15) {
        g0 = 15;
    } else if (g0 == -1) {
        g0 = 0;
    }

    int32_t g1 = ((int32_t)(d * 23U) + 29) / 207;
    if (g1 > 15) {
        g1 = 15;
    }

    if (level >= 3U) {
        g0 += (g0 > 7) ? -8 : 8;
    }
    g_phy_vga_lna_dcap[0] = (uint8_t)(((uint32_t)g0 & 0x0FU) | 0x40U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_GAIN, PHY_I2C_HOST_0, 4U, g_phy_vga_lna_dcap[0]);

    if (level >= 2U) {
        g1 += (g1 > 7) ? -8 : 8;
    }
    g_phy_vga_lna_dcap[1] = (uint8_t)(((uint32_t)g1 & 0x0FU) | 0x40U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_GAIN, PHY_I2C_HOST_0, 7U, g_phy_vga_lna_dcap[1]);

    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_ANA, PHY_I2C_HOST_1, 5U,
                     (level == 0U) ? 0xE0U : 0xEFU);
}

void phy_rxmax_ext_dig(uint8_t level)
{
    if (level == 0U) {
        PHY_REG_SET(PHY_RF_RX_GAIN_EXT_REG, PHY_RF_RX_GAIN_EXT_DIG);
    } else {
        PHY_REG_CLR(PHY_RF_RX_GAIN_EXT_REG, PHY_RF_RX_GAIN_EXT_DIG);
    }
    s_set_chan_rx_cmp((int8_t)g_phy_sleep_params.cur_chan, level);
}

void chip_v6_rxmax_ext(uint8_t level)
{
    phy_rxmax_ext_ana(level);
    phy_rxmax_ext_dig(level);
}

void phy_set_rx11b_reg(uint8_t enable)
{
    if (enable == 0U) {
        PHY_REG_CLR(PHY_BB_RX11B_REG, 0x000000C0U);
    } else {
        PHY_REG_RMW(PHY_BB_RX11B_REG, 0x00000FCFU, 0x0000048AU);
    }
}

void phy_dig_11b_filt_sel(uint8_t sel)
{
    uint32_t val = 0U;
    if (sel == 1U) {
        val = 0x00000010U;
    } else if (sel == 2U) {
        val = 0x00001000U;
    } else if (sel == 3U) {
        val = 0x00002000U;
    }
    PHY_REG_RMW(PHY_BB_RX_FILTER_REG, 0x00003010U, val);
}

void phy_chan14_mic_cfg(uint8_t is_ch14)
{
    if (is_ch14 == 1U) {
        phy_dig_11b_filt_sel(1U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_FILT, PHY_I2C_HOST_3, 1U, 5U, 0U, 0x3CU);
        phy_set_most_tpw(g_phy_chan14_mic_most_power);
    } else {
        phy_dig_11b_filt_sel(3U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_FILT, PHY_I2C_HOST_3, 1U, 5U, 0U,
                              g_phy_sleep_params.tx_filt_dcap);
        phy_set_most_tpw(chip6_phy_init_ctrl[0x14]);
    }
}

void phy_rf_i2c_init(void)
{
    rom_i2c_writeReg(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 0U, 0x25U);
    phy_chip_v5_tx_init();
    rom_i2c_writeReg(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2, 1U, 0x48U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_RX_GAIN, PHY_I2C_HOST_0, 5U, 1U, 0U, 3U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_ANA, PHY_I2C_HOST_1, 8U, 0x11U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, 0U, 0x15U);
    phy_sar_init();
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BBPLL, PHY_I2C_HOST_4, 4U, 7U, 7U, 1U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 0U, 0x29U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 4U, 0xAFU);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 11U, 0x80U);
    PHY_REG_RMW(PHY_BBPLL_CTRL_REG, 0x00000600U, 0x00000400U);
}

int phy_rf_init(void)
{
    PHY_REG_SET(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_ALL);

    if ((g_phy_sleep_params.param_flag & PHY_PARAM_WAKEUP_RF) == 0U) {
        PHY_REG_WRITE(PHY_RTC_PLL_CTRL_REG, 0x0019C06AU);
        PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, 0xF0000000U);
        PHY_REG_CLR(PHY_RF_CAL_MODE_REG, 0x01800000U);
    }

    PHY_REG_CLR(PHY_RF_CAL_MODE_REG, 0x08000000U);
    PHY_REG_SET(PHY_RTC_RF_PWR_REG, PHY_RTC_RF_PWR_SAR_BIT);

    if (g_phy_init_rf_no_cal != 0U) {
        PHY_REG_RMW(PHY_RF_CAL_MODE_REG, 0x01800000U, 0x00800000U);
    }

    PHY_REG_SET(PHY_RTC_RF_PWR_REG, 0x30000000U);
    PHY_REG_RMW(PHY_PBUS_STATUS_REG, 0x1F000000U, 0x1C000000U);
    PHY_REG_RMW(PHY_PBUS_CFG_REG, 0x30000000U, 0x10000000U);
    PHY_REG_CLR(PHY_MAC_PHY_CTRL_REG, PHY_MAC_PHY_RF_UP);
    ets_delay_us(2U);
    PHY_REG_SET(PHY_RTC_RF_PWR_REG, 0x0C000000U);

    phy_pbus_debugmode();
    phy_pbus_force(2U, 1U, 0x81U);
    phy_pbus_xpd_tx_off();
    phy_pbus_workmode();

    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 0U, 0x28U);

    if ((g_phy_sleep_params.param_flag & PHY_PARAM_WAKEUP_RF) == 0U) {
        phy_set_chan(1U);
    } else {
        phy_set_chan_wakeup(g_phy_sleep_params.cur_chan);
    }

    /* RX analog defaults (ram_chip_v6_rx_init) */
    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_ANA, PHY_I2C_HOST_1, 8U, 0x11U);
    phy_rxmax_ext_ana(g_phy_rxmax_ext_level);

    phy_rf_i2c_init();
    rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x1AU, 0x08U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x1AU, 0x38U);
    return 0;
}

void phy_wakeup_rf(void)
{
    g_phy_wakeup_rf_flag = 1U;
    vPortETSIntrLock();

    PHY_REG_CLR(PHY_MAC_PHY_CTRL_REG, PHY_MAC_PHY_RF_UP);
    PHY_REG_SET(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_ALL);
    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, 0xFE000000U);

    phy_rf_i2c_init();
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 1U, g_phy_or_pll_cap_last);
    phy_rfpll_reset();
    phy_write_rfpll_sdm(g_phy_rfpll_sdm_reg);
    phy_rfpll_restart_cal();

    if (((PHY_REG_READ(PHY_EFUSE_DATA2_REG) >> 12) & 0xEU) == 0U &&
        (PHY_REG_READ(PHY_BB_ADC_RAND_REG) & 0x7U) == 0U) {
        PHY_REG_WRITE(PHY_RF_I2C_HOST_REG(0), 0x01041D77U);
    }

    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_ANA, PHY_I2C_HOST_1, 7U, 0x51U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_ANA, PHY_I2C_HOST_1, 2U,
                     (uint8_t)(g_phy_sleep_params.rx_filt_dcap | 0xA0U));
    rom_i2c_writeReg(PHY_I2C_BLOCK_TX_FILT, PHY_I2C_HOST_3, 1U,
                     (uint8_t)(g_phy_sleep_params.tx_filt_dcap | 0x40U));

    PHY_REG_SET(PHY_MAC_PHY_CTRL_REG, PHY_MAC_PHY_RF_UP);

    phy_set_txcap_reg(g_phy_sleep_params.txcap, g_phy_sleep_params.cur_chan);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_GAIN, PHY_I2C_HOST_0, 4U, g_phy_vga_lna_dcap[0]);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_GAIN, PHY_I2C_HOST_0, 7U, g_phy_vga_lna_dcap[1]);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_ANA, PHY_I2C_HOST_1, 5U,
                     (g_phy_rxmax_ext_level == 0U) ? 0xE0U : 0xEFU);

    if (chip6_phy_init_ctrl[0x39] == 1U) {
        phy_tx_cont_en();
    } else {
        phy_tx_cont_dis();
    }

    phy_sleep_set_rxpbus(1U);

    vPortETSIntrUnlock();
    g_phy_wakeup_rf_flag = 0U;
}

void phy_close_rf(void)
{
    pm_set_sleep_mode(4U);
    phy_sleep_set_rxpbus(0U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 3U, 0x01U);
    PHY_REG_CLR(PHY_MAC_PHY_CTRL_REG, PHY_MAC_PHY_RF_UP);
    PHY_REG_CLR(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_GATE_MASK);
    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, 0x50000000U);
    g_phy_sleep_mode_flag = 1U;
}

void phy_bb_rx_cfg(void)
{
    PHY_REG_SET(PHY_BB_RX_CTRL_REG, 0x00001400U);
    PHY_REG_SET(PHY_BB_AGC_THR_9B0C_REG, 0x10000000U);
    PHY_REG_RMW(PHY_BB_AGC_THR_9D40_REG, 0x7F800000U, 0x10000000U);

    PHY_REG_WRITE(PHY_BB_AGC_THR_9B6C_REG, 0x0914BC81U);
    PHY_REG_WRITE(PHY_BB_AGC_THR_9B68_REG, 0x5AC64198U);
    PHY_REG_CLR(PHY_BB_AGC_THR_9B50_REG, 0x80000000U);

    PHY_REG_WRITE(PHY_BB_AGC_THR_9D18_REG, 400U);
    PHY_REG_RMW(PHY_BB_AGC_THR_98EC_REG, 0x03FF0000U, 0x01900000U);
    PHY_REG_CLR(PHY_BB_AGC_THR_9988_REG, 0x04000000U);

    PHY_REG_RMW(PHY_BB_RX_MAX_GAIN_REG, 0x0000007FU,
                ((uint32_t)g_phy_rx_max_gain_val - 15U) & 0x7FU);
    PHY_REG_RMW(PHY_BB_AGC_THR_9B28_REG, 0xFF000000U, 0x18000000U);
    PHY_REG_CLR(PHY_BB_RX_GAIN_FORCE_REG, 0x7F000000U);
    PHY_REG_RMW(PHY_BB_AGC_THR_9B44_REG, 0x0000007FU,
                ((chip6_phy_init_ctrl[0x4C] & 1U) != 0U) ? 0x2EU : 0x26U);
    PHY_REG_RMW(PHY_BB_AGC_THR_9D70_REG, 0x0000003FU, 0x00000011U);

    PHY_REG_SET(PHY_BB_SPUR_FREQ_REG, 0xC0000000U);
    PHY_REG_RMW(PHY_BB_NOISE_FLOOR_REG, 0x000FF000U, 0x00022000U);
    PHY_REG_RMW(PHY_BB_NOISE_FLOOR_REG, 0x00000FFFU, 0x00000FA6U);

    PHY_REG_RMW(PHY_BB_AGC_THR_9B5C_REG, 0x003FFFFFU, 0x00385854U);
    PHY_REG_RMW(PHY_BB_AGC_THR_9B50_REG, 0x0FF000FFU, 0x0B2000E6U);
    PHY_REG_WRITE(PHY_BB_AGC_THR_9D18_REG, 0x00000080U);
    PHY_REG_SET(PHY_BB_AGC_THR_9D10_REG, 0x00000004U);
    PHY_REG_RMW(PHY_BB_AGC_THR_9D70_REG, 0x20000FC0U, 0x20000C40U);

    PHY_REG_RMW(PHY_BB_AGC_THR_9D24_REG, 0x007F0000U, 0x00130000U);
    PHY_REG_RMW(PHY_BB_AGC_THR_9B58_REG, 0x00000FC0U, 0x00000D80U);
    PHY_REG_RMW(PHY_BB_AGC_THR_9D4C_REG, 0x03FFFFFFU, 0x03FE0124U);
    PHY_REG_RMW(PHY_BB_AGC_THR_9D20_REG, 0xF0000000U, 0xB0000000U);
    PHY_REG_SET(PHY_BB_AGC_THR_9988_REG, 0x04000000U);

    PHY_REG_RMW(PHY_MAC_PHY_CTRL_REG, 0x00F40000U, 0x00240000U);
    PHY_REG_CLR(PHY_BB_AGC_THR_9D44_REG, 0x00400000U);

    phy_rxmax_ext_dig(g_phy_rxmax_ext_level);
    phy_chip_v5_sense_backoff(0U);

    PHY_REG_RMW(PHY_BB_11B_FE_REG, 0x00000030U, 0x00000020U);
    PHY_REG_WRITE(PHY_BB_AGC_THR_9C48_REG, 0x00800083U);
    PHY_REG_SET(PHY_BB_AGC_THR_9C4C_REG, 0x00000006U);
    PHY_REG_WRITE(PHY_BB_AGC_THR_9D1C_REG, 0x00000FFFU);
    PHY_REG_SET(PHY_BB_AGC_THR_9D1C_REG, 0x00000FFFU);
    PHY_REG_CLR(PHY_BB_TX_CAL_REG, 0x00000800U);

    PHY_REG_RMW(PHY_DPORT_PERI_CLK_REG, 0x00000006U, 0x00000002U);
    PHY_REG_CLR(PHY_FE_RX_CTRL_REG, 0x00000001U);

    phy_pbus_debugmode();
    phy_pbus_force(1U, 1U, 0x0CU);
    if (g_phy_rx_table_renew_en != 0U) {
        phy_pbus_force(2U, 1U, 0x184U);
        phy_pbus_force(3U, 2U, 0x06U);
    }
    phy_pbus_workmode();

    phy_set_rx_gain_table(3U);
    phy_dig_11b_filt_sel(3U);
}

void phy_ant_switch_init(void)
{
    uint8_t btco = chip6_phy_init_ctrl[0x22];
    uint8_t ant = chip6_phy_init_ctrl[0x24];

    if (btco == 1U || btco == 3U) {
        PHY_REG_WRITE(PHY_BB_ANT_SWITCH_LO_REG, 0x01010101U);
        PHY_REG_WRITE(PHY_BB_ANT_SWITCH_HI_REG, 0x04010101U);
    } else if (btco == 4U || btco == 5U) {
        PHY_REG_WRITE(PHY_BB_ANT_SWITCH_LO_REG, 0x04040404U);
        PHY_REG_WRITE(PHY_BB_ANT_SWITCH_HI_REG, 0x01040404U);
    } else if (ant == 2U) {
        PHY_REG_WRITE(PHY_BB_ANT_SWITCH_LO_REG, 0x04010104U);
        PHY_REG_WRITE(PHY_BB_ANT_SWITCH_HI_REG, 0x04040404U);
    } else if (ant == 3U) {
        PHY_REG_WRITE(PHY_BB_ANT_SWITCH_LO_REG, 0x01040401U);
        PHY_REG_WRITE(PHY_BB_ANT_SWITCH_HI_REG, 0x01010101U);
    }

    PHY_REG_SET(PHY_BB_AGC_CTRL_REG, 0x00800000U);
    PHY_REG_RMW(PHY_BB_SLEEP_REG, 0x00003C00U, 0x00000800U);
    PHY_REG_WRITE(PHY_BB_TX_CAL_REG, 2U);
}

void phy_gpio_cfg(void)
{
    if (chip6_phy_init_ctrl[0x25] == 2U) {
        PHY_REG_RMW(PHY_RTC_EXT_GPIO_REG, 0x0000006BU, 0x00000069U);
    }

    uint8_t btco = chip6_phy_init_ctrl[0x22];
    uint8_t btco_sub = chip6_phy_init_ctrl[0x23];
    uint8_t ant = chip6_phy_init_ctrl[0x24];

    if (btco != 1U && btco != 3U && btco != 4U && btco != 5U) {
        if (ant == 3U) {
            PHY_REG_RMW(PHY_IO_MUX_GPIO0_REG, 0x00000130U, 0x00000020U);
        } else if (ant == 2U) {
            PHY_REG_RMW(PHY_IO_MUX_MTDO_REG, 0x00000130U, 0x00000020U);
        }
        return;
    }

    if (btco == 1U || btco == 4U) {
        if (btco_sub == 3U || btco_sub == 5U) {
            PHY_REG_WRITE(PHY_GPIO_BTCO_CFG_REG, 0x03DE0000U);
        } else if (btco_sub < 2U) {
            PHY_REG_WRITE(PHY_GPIO_BTCO_CFG_REG, 0U);
        } else {
            PHY_REG_WRITE(PHY_GPIO_BTCO_CFG_REG, 0x010E0000U);
        }
    } else if (btco == 3U || btco == 5U) {
        if (btco_sub == 3U || btco_sub == 5U) {
            PHY_REG_WRITE(PHY_GPIO_BTCO_CFG_REG, 0x03ED0000U);
        } else if (btco_sub < 2U) {
            PHY_REG_WRITE(PHY_GPIO_BTCO_CFG_REG, 0U);
        } else {
            PHY_REG_WRITE(PHY_GPIO_BTCO_CFG_REG, 0x010D0000U);
        }
    }

    PHY_REG_RMW(PHY_IO_MUX_MTCK_REG, 0x000001F0U, 0x00000030U);
    PHY_REG_RMW(PHY_IO_MUX_MTMS_REG, 0x000001F0U, 0x00000030U);

    if (btco_sub < 2U) {
        PHY_REG_RMW(PHY_IO_MUX_MTDO_REG, 0x00000130U, 0x00000030U);
        PHY_REG_CLR(PHY_IO_MUX_GPIO0_REG, 0x00000130U);
    } else {
        PHY_REG_RMW(PHY_IO_MUX_MTDO_REG, 0x00000130U, 0x00000020U);
        PHY_REG_RMW(PHY_IO_MUX_GPIO0_REG, 0x00000130U, 0x00000020U);
    }

    if (btco == 1U || btco == 3U) {
        if (btco_sub == 1U) {
            gpio_output_set(1U, 0U, 1U, 0U);
            gpio_output_set(0U, 8U, 8U, 0U);
        } else if (btco_sub == 0U) {
            gpio_output_set(0U, 1U, 1U, 0U);
            gpio_output_set(8U, 0U, 8U, 0U);
        }
    } else if (btco == 4U || btco == 5U) {
        if (btco_sub == 0U) {
            gpio_output_set(1U, 0U, 1U, 0U);
            gpio_output_set(0U, 8U, 8U, 0U);
        } else if (btco_sub == 1U) {
            gpio_output_set(0U, 1U, 1U, 0U);
            gpio_output_set(8U, 0U, 8U, 0U);
        }
    }
}

void phy_reduce_current_init(void)
{
    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, 0xD6000000U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 3U, 7U, 4U, 0U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BIAS_PWR, PHY_I2C_HOST_4, 0U, 6U, 6U, 0U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BIAS_PWR, PHY_I2C_HOST_4, 0U, 7U, 7U, 0U);

    if (chip6_phy_init_ctrl[0x47] == 0xFFU) {
        PHY_REG_CLR(PHY_RF_CAL_MODE_REG, 0x08000000U);
        PHY_REG_SET(PHY_PBUS_CTRL_REG, PHY_PBUS_DEBUG_MODE);
        phy_pbus_force(6U, 1U, 2U);
        PHY_REG_CLR(PHY_PBUS_CTRL_REG, PHY_PBUS_DEBUG_MODE);
    }

    PHY_REG_CLR(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_GATE_MASK);
    rom_i2c_writeReg(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 0U, 0x25U);
    phy_sar_init();
}

void phy_tx_cont_en(void)
{
    if (s_tx_cont_en_flag == 0U) {
        s_tx_data[0] = (uint32_t)rom_i2c_readReg(PHY_I2C_BLOCK_TX_FILT, PHY_I2C_HOST_3, 1U);
        s_tx_data[1] = PHY_REG_READ(PHY_PBUS_CTRL_REG);
        s_tx_data[2] = PHY_REG_READ(PHY_PBUS_CFG_REG);
        s_tx_data[3] = PHY_REG_READ(PHY_PBUS_CFG_MIRROR_REG);

        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_FILT, PHY_I2C_HOST_3, 1U, 5U, 0U, 0x3CU);
        PHY_REG_SET(PHY_PBUS_CFG_MIRROR_REG, 0x0FE03F80U);
        PHY_REG_SET(PHY_PBUS_CFG_REG, 0x0FFFFFFFU);
        PHY_REG_CLR(PHY_PBUS_CTRL_REG, 0x00300000U);
    }
    s_tx_cont_en_flag = 1U;
}

void phy_tx_cont_dis(void)
{
    if (s_tx_cont_en_flag == 1U) {
        rom_i2c_writeReg(PHY_I2C_BLOCK_TX_FILT, PHY_I2C_HOST_3, 1U, (uint8_t)s_tx_data[0]);
        PHY_REG_WRITE(PHY_PBUS_CTRL_REG, s_tx_data[1]);
        PHY_REG_WRITE(PHY_PBUS_CFG_REG, s_tx_data[2]);
        PHY_REG_WRITE(PHY_PBUS_CFG_MIRROR_REG, s_tx_data[3]);
    }
    s_tx_cont_en_flag = 0U;
}

void phy_sleep_set_rxpbus(uint8_t en)
{
    if (en == 0U) {
        PHY_REG_CLR(PHY_PBUS_CTRL_REG, 0x00F00000U);
        PHY_REG_CLR(PHY_PBUS_CTRL_REG, 0xFC000000U);
    } else {
        PHY_REG_RMW(PHY_PBUS_CTRL_REG, 0x00F00000U, 0x00300000U);
        PHY_REG_RMW(PHY_PBUS_CTRL_REG, 0xFC000000U, 0xD8000000U);
    }

    PHY_REG_RMW(PHY_RF_CAL_MODE_REG, 0x01800000U, 0x00800000U);
    ets_delay_us(1U);
    PHY_REG_CLR(PHY_RF_CAL_MODE_REG, 0x01800000U);
}

uint32_t phy_stop_dig_rx(void)
{
    uint32_t saved = PHY_REG_READ(PHY_BB_DIG_RX_REG);
    PHY_REG_SET(PHY_BB_SLEEP_REG, PHY_BB_SLEEP_RX);
    PHY_REG_CLR(PHY_BB_DIG_RX_REG, PHY_BB_DIG_RX_EN);
    return saved;
}

void phy_start_dig_rx(uint32_t saved_dig_rx)
{
    PHY_REG_CLR(PHY_BB_SLEEP_REG, PHY_BB_SLEEP_RX);
    PHY_REG_SET(PHY_BB_RX_CTRL_REG, PHY_BB_RX_RESET);
    PHY_REG_CLR(PHY_BB_RX_CTRL_REG, PHY_BB_RX_RESET);
    PHY_REG_WRITE(PHY_BB_DIG_RX_REG, saved_dig_rx);
}

void phy_after_init_enrx(void)
{
    PHY_REG_CLR(PHY_RF_CAL_MODE_REG, 0x01800000U);
    ets_delay_us(5U);
    PHY_REG_RMW(PHY_BB_RX_GAIN_FORCE_REG, 0x000003FFU, 0x000000F1U);
    PHY_REG_RMW(PHY_BB_RX_GAIN_FORCE_REG, 0x000003FFU, 0x000000F0U);
    ets_delay_us(5U);
}
