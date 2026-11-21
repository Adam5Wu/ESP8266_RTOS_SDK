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
// Portions of the RF-I2C and PBUS hardware sequences are adapted from teatime-os:
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

#define PHY_I2C_POLL_MAX                100000U
#define PHY_PBUS_POLL_MAX               100000U
#define PHY_IQ_EST_POLL_MAX             1000000U

/* Re-entrancy guard for RF-I2C ETS interrupt locking (1 B DRAM, explicit init) */
static uint8_t s_phy_interrup_flag = 0U;

/* --------------------------------------------------------------------------
 * IRAM Primitives: ROM-I2C Bus & MAC Microsecond Timer
 * -------------------------------------------------------------------------- */

uint8_t IRAM_ATTR rom_i2c_readReg(uint8_t block, uint8_t host_id, uint8_t reg_add)
{
    bool locked = (g_phy_wakeup_rf_flag == 0U) && (s_phy_interrup_flag == 0U);
    if (locked) {
        vPortETSIntrLock();
        s_phy_interrup_flag = 1U;
    }

    uint32_t reg_addr = PHY_RF_I2C_HOST_REG((uint32_t)host_id & 0xFFU);
    PHY_REG_WRITE(reg_addr,
                  (((uint32_t)reg_add & 0xFFU) << 8) | ((uint32_t)block & 0xFFU));
    for (uint32_t t = 0U;
         (PHY_REG_READ(reg_addr) & PHY_RF_I2C_BUSY) != 0U && t < PHY_I2C_POLL_MAX;
         t++) {
    }
    uint32_t val = (PHY_REG_READ(reg_addr) >> 16) & 0xFFU;

    if (locked) {
        s_phy_interrup_flag = 0U;
        vPortETSIntrUnlock();
    }

    return (uint8_t)val;
}

uint8_t IRAM_ATTR rom_i2c_readReg_Mask(uint8_t block, uint8_t host_id, uint8_t reg_add,
                                       uint8_t msb, uint8_t lsb)
{
    uint32_t reg_val = rom_i2c_readReg(block, host_id, reg_add);
    uint32_t width = ((uint32_t)msb - (uint32_t)lsb + 1U) & 0x1FU;
    uint32_t mask = (1U << width) - 1U;
    return (uint8_t)((reg_val >> ((uint32_t)lsb & 0x1FU)) & mask);
}

void IRAM_ATTR rom_i2c_writeReg(uint8_t block, uint8_t host_id, uint8_t reg_add, uint8_t data)
{
    bool locked = (g_phy_wakeup_rf_flag == 0U) && (s_phy_interrup_flag == 0U);
    if (locked) {
        vPortETSIntrLock();
        s_phy_interrup_flag = 1U;
    }

    uint32_t reg_addr = PHY_RF_I2C_HOST_REG((uint32_t)host_id & 0xFFU);
    PHY_REG_WRITE(reg_addr,
                  PHY_RF_I2C_START |
                  (((uint32_t)data & 0xFFU) << 16) |
                  (((uint32_t)reg_add & 0xFFU) << 8) |
                  ((uint32_t)block & 0xFFU));
    for (uint32_t t = 0U;
         (PHY_REG_READ(reg_addr) & PHY_RF_I2C_BUSY) != 0U && t < PHY_I2C_POLL_MAX;
         t++) {
    }

    if (locked) {
        s_phy_interrup_flag = 0U;
        vPortETSIntrUnlock();
    }
}

void IRAM_ATTR rom_i2c_writeReg_Mask(uint8_t block, uint8_t host_id, uint8_t reg_add,
                                     uint8_t msb, uint8_t lsb, uint8_t data)
{
    uint32_t reg_val = rom_i2c_readReg(block, host_id, reg_add);
    uint32_t width = ((uint32_t)msb - (uint32_t)lsb + 1U) & 0x1FU;
    uint32_t shift = (uint32_t)lsb & 0x1FU;
    uint32_t mask = ((1U << width) - 1U) << shift;
    uint32_t next_val = ((reg_val & ~mask) | ((((uint32_t)data & 0xFFU) << shift) & mask)) & 0xFFU;
    rom_i2c_writeReg(block, host_id, reg_add, (uint8_t)next_val);
}

uint32_t IRAM_ATTR phy_get_mactime(void)
{
    return PHY_REG_READ(PHY_WDEV_MAC_TIME_REG);
}

/* --------------------------------------------------------------------------
 * ABI-Locked g_phyFuns Dispatch Table (Flash .rodata + 4 B .data ptr)
 * -------------------------------------------------------------------------- */

static const esp_phy_funs_t s_phy_funs_instance WORD_ALIGNED_ATTR = {
    .rom_i2c_readReg = rom_i2c_readReg,
    .rom_i2c_readReg_Mask = rom_i2c_readReg_Mask,
    .rom_i2c_writeReg = rom_i2c_writeReg,
    .rom_i2c_writeReg_Mask = rom_i2c_writeReg_Mask,
};

const esp_phy_funs_t *g_phyFuns = &s_phy_funs_instance;

void phy_get_romfunc_addr(void)
{
    /* g_phyFuns is statically bound to s_phy_funs_instance. */
}

/* --------------------------------------------------------------------------
 * PBUS Configuration, Readback, Force-Write & Debug/Work Modes
 * -------------------------------------------------------------------------- */

static const uint8_t s_pbus_rd_base[8] WORD_ALIGNED_ATTR = {
    0U, 2U, 4U, 5U, 7U, 9U, 11U, 12U
};

void phy_pbus_soc_cfg(void)
{
    PHY_REG_RMW(PHY_PBUS_CFG_REG,        0x0FE00000U, 0x01800000U);
    PHY_REG_RMW(PHY_PBUS_CFG_MIRROR_REG, 0x0FE00000U, 0x01800000U);
    PHY_REG_RMW(PHY_PBUS_CTRL_REG,       0xE0000000U, 0xC0000000U);
    PHY_REG_RMW(PHY_PBUS_CFG_REG,        0x001FC000U, 0x001F4000U);
    PHY_REG_RMW(PHY_PBUS_STATUS_REG,     0x00FF0000U, 0x00AB0000U);
    PHY_REG_RMW(PHY_RFPLL_CTRL_REG,      0x0000FF00U, 0x00000100U);
    PHY_REG_RMW(PHY_PBUS_CFG_REG,        0x0000007FU, 0x00000047U);
}

uint16_t phy_pbus_rd(uint8_t reg, uint8_t width)
{
    uint32_t w = (width == 4U) ? 2U : (uint32_t)((width - 1U) & 0xFFU);
    uint32_t slot = (w + (uint32_t)s_pbus_rd_base[reg & 7U]) & 0xFFU;
    uint32_t word = PHY_REG_READ(PHY_PBUS_READ_WINDOW_REG(slot / 3U));
    uint32_t shift = (slot == 12U) ? 0U : (18U - (slot % 3U) * 9U);
    return (uint16_t)((word >> shift) & 0x1FFU);
}

void phy_pbus_force(uint8_t reg, uint8_t width, uint16_t val)
{
    uint32_t v = (PHY_REG_READ(PHY_PBUS_CTRL_REG) & 0xFFFF0001U) |
                 PHY_PBUS_FORCE_STROBE |
                 ((uint32_t)reg << PHY_PBUS_FORCE_REG_SHIFT) |
                 ((uint32_t)val << PHY_PBUS_FORCE_VAL_SHIFT) |
                 ((uint32_t)width << PHY_PBUS_FORCE_WIDTH_SHIFT);
    PHY_REG_WRITE(PHY_PBUS_CTRL_REG, v);
    for (uint32_t t = 0U;
         (PHY_REG_READ(PHY_PBUS_STATUS_REG) & PHY_PBUS_BUSY) != 0U && t < PHY_PBUS_POLL_MAX;
         t++) {
    }
    PHY_REG_CLR(PHY_PBUS_CTRL_REG, PHY_PBUS_FORCE_STROBE);
}

void phy_pbus_debugmode(void)
{
    if ((PHY_REG_READ(PHY_PBUS_CTRL_REG) & PHY_PBUS_DEBUG_MODE) == 0U &&
        (PHY_REG_READ(PHY_MAC_PHY_CTRL_REG) & PHY_MAC_PHY_RF_UP) != 0U) {
        ets_delay_us(5U);
        for (uint32_t t = 0U; t < PHY_PBUS_POLL_MAX; t++) {
            if ((phy_pbus_rd(2U, 1U) & 0x184U) == 0x184U &&
                (phy_pbus_rd(3U, 2U) & 6U) == 6U) {
                break;
            }
        }
    }
    PHY_REG_SET(PHY_BB_SLEEP_REG, PHY_BB_SLEEP_RX);
    PHY_REG_SET(PHY_PBUS_CTRL_REG, PHY_PBUS_DEBUG_MODE);
    if ((PHY_REG_READ(PHY_MAC_PHY_CTRL_REG) & PHY_MAC_PHY_RF_UP) != 0U) {
        for (uint32_t t = 0U; t < PHY_PBUS_POLL_MAX; t++) {
            if ((PHY_REG_READ(PHY_PBUS_STATUS_REG) & PHY_PBUS_READY) != 0U) {
                break;
            }
        }
    }
}

void phy_pbus_enter_debugmode(uint16_t tx_rf_ana_gain)
{
    phy_pbus_debugmode();
    phy_pbus_xpd_rx_off(1);
    phy_pbus_xpd_tx_on((uint16_t)(tx_rf_ana_gain & 0x1FU));
}

void phy_pbus_exit_debugmode(void)
{
    phy_pbus_xpd_tx_off();
    phy_pbus_xpd_rx_on();
    phy_pbus_workmode();
}

void phy_pbus_workmode(void)
{
    PHY_REG_CLR(PHY_PBUS_CTRL_REG, PHY_PBUS_DEBUG_MODE);
    PHY_REG_CLR(PHY_BB_SLEEP_REG, PHY_BB_SLEEP_RX);
}

void phy_pbus_xpd_tx_off(void)
{
    phy_pbus_force(6U, 1U, 0U);
    phy_pbus_force(1U, 1U, 0x0CU);
    phy_pbus_force(2U, 1U, 0x80U);
}

void phy_pbus_xpd_tx_on(uint16_t rf_ana_gain)
{
    phy_pbus_force(2U, 1U, 0x81U);
    phy_pbus_force(7U, 1U, (uint16_t)(rf_ana_gain >> 5));
    phy_pbus_force(0U, 1U, (uint16_t)(rf_ana_gain & 0x1FU));
    phy_pbus_force(1U, 1U, 0x7FU);
    phy_pbus_force(6U, 1U, 0x7FU);
}

void phy_pbus_xpd_rx_on(void)
{
    phy_pbus_force(2U, 1U, 0x184U);
    phy_pbus_force(3U, 2U, 6U);
}

void phy_pbus_xpd_rx_off(int16_t reg2_val)
{
    phy_pbus_force(2U, 1U, (uint16_t)(reg2_val + 0x80));
    phy_pbus_force(3U, 1U, 0U);
    phy_pbus_force(3U, 2U, 0U);
}

void phy_pbus_set_txgain(uint16_t gain)
{
    uint16_t packed = (uint16_t)(((gain & 0x1FU) << 4) |
                                 (((gain >> 5) & 3U) << 2) |
                                 ((gain >> 7) & 3U));
    phy_pbus_force(4U, 1U, packed);
}

void phy_pbus_set_rxgain(uint16_t gain)
{
    uint32_t g = (uint32_t)gain;
    uint16_t r3_w1 = (uint16_t)((((g >> 3) & 1U) << 6) |
                                (((g >> 4) & 1U) << 5) |
                                (((g >> 5) & 1U) << 4) |
                                (((g >> 6) & 1U) << 3) |
                                (((g >> 7) & 1U) << 2) |
                                (((g >> 8) & 1U) << 1) |
                                ((g >> 9) & 1U));
    uint16_t r3_w2 = (uint16_t)((phy_pbus_rd(3U, 2U) & 0x1C7U) | ((g & 7U) << 3));
    uint16_t r2_w1 = (uint16_t)((phy_pbus_rd(2U, 1U) & 0x185U) |
                                (((g >> 11) & 0x0FU) << 3) |
                                (((g >> 10) & 1U) << 1));
    phy_pbus_force(3U, 1U, r3_w1);
    phy_pbus_force(3U, 2U, r3_w2);
    phy_pbus_force(2U, 1U, r2_w1);
}

void phy_pbus_set_rxbbgain(int16_t bbgain)
{
    uint16_t coarse;
    if (bbgain >= 24) {
        coarse = 0x78U;
    } else if (bbgain >= 18) {
        coarse = 0x70U;
    } else if (bbgain >= 12) {
        coarse = 0x60U;
    } else if (bbgain >= 6) {
        coarse = 0x40U;
    } else {
        coarse = 0x00U;
    }
    phy_pbus_force(3U, 1U, coarse);
    int32_t fine = (int32_t)bbgain % 6;
    phy_pbus_force(3U, 2U, (uint16_t)(((uint32_t)fine << 3) | 6U));
}

/* --------------------------------------------------------------------------
 * Analog Interface, Clocks, Loopback, DPD & SAR/Power-Detector Helpers
 * -------------------------------------------------------------------------- */

void phy_set_txclk_en(uint8_t en)
{
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x1CU, 6U, 6U, en);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_CLK, PHY_I2C_HOST_1, 0x15U, 0U, 0U, en);
}

void phy_set_rxclk_en(uint8_t en)
{
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x1CU, 5U, 5U, en);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_CLK, PHY_I2C_HOST_1, 0x15U, 1U, 1U, en);
}

uint8_t phy_set_ana_inf_tx_scale(uint8_t val)
{
    uint8_t scale = 0U;
    if (val > 0x3FU) {
        scale = (uint8_t)((0x3FU - (uint32_t)val) & 0xFFU);
        val = 0x3FU;
    }
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 9U, 7U, 0U, scale);
    return val;
}

void phy_ana_inf_gating_en(uint8_t en, uint32_t int_div, uint32_t frac_div)
{
    if (en != 0U) {
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x1CU, 0U, 0U, 0U);
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x1AU, 0x28U);
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x1AU, 0x38U);
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x1AU, 0x18U);
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x1AU, 0x38U);
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x00U,
                         (uint8_t)((int_div >> 12) & 0xFFU));
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x01U,
                         (uint8_t)((int_div >> 4) & 0xFFU));
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x04U,
                         (uint8_t)(frac_div & 0xFFU));
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x03U,
                         (uint8_t)((frac_div >> 8) & 0xFFU));
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x02U,
                         (uint8_t)((((frac_div >> 16) & 0x0FU) << 4) | (int_div & 0x0FU)));
    }
    uint8_t inv = (uint8_t)(en ^ 1U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x0FU, 3U, 3U, inv);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x18U, 0U, 0U, inv);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x1CU, 0U, 0U, en);
}

void phy_set_loopback_gain(uint16_t pa_gain, uint16_t pbus_r2,
                           uint16_t pbus_r3_1, uint16_t pbus_r3_2)
{
    phy_pbus_force(2U, 1U, 0x185U);
    phy_pbus_force(7U, 1U, pa_gain);
    phy_pbus_force(2U, 1U, pbus_r2);
    phy_pbus_force(3U, 1U, pbus_r3_1);
    phy_pbus_force(3U, 2U, pbus_r3_2);
}

void phy_dpd_bypass(void)
{
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x0FU, 1U, 1U, 1U);
}

void phy_dpd_scale_set(void)
{
    uint32_t txpwr23 = PHY_REG_READ(PHY_RF_TXPWR_REG(23U));
    uint32_t off = (uint32_t)(uint8_t)g_phy_sleep_params.dpd_atten_off;
    uint8_t scale = (uint8_t)((0U - 24U - (txpwr23 + off)) & 0xFFU);
    rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 8U, scale);
}

void phy_sar_init(void)
{
    PHY_REG_SET(PHY_RTC_RF_PWR_REG, PHY_RTC_RF_PWR_SAR_BIT);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, 0U, 4U, 4U, 1U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, 1U, 1U, 0U, 2U);
}

void phy_en_pwdet(uint8_t en)
{
    phy_sar_init();
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_TOUT_EN);
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_VDD33_EN);
    if (en != 0U) {
        PHY_REG_SET(PHY_SAR_CTRL_REG, BIT(0));
    } else {
        PHY_REG_CLR(PHY_SAR_CTRL_REG, BIT(0));
    }
}

/* --------------------------------------------------------------------------
 * IQ Estimator, TX Test Tones & Pure-Integer dB Conversion
 * -------------------------------------------------------------------------- */

void phy_iq_est_enable(uint8_t mode, uint16_t samples)
{
    PHY_REG_SET(PHY_FE_IQ_EST_CTRL_REG, BIT(0));
    PHY_REG_RMW(PHY_FE_IQ_EST_CTRL_REG, 0x0005FFFEU,
                BIT(1) | ((uint32_t)mode << 18) | (((uint32_t)samples & 0x7FFFU) << 2));
    for (uint32_t t = 0U;
         (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_CTRL_REG) >= 0 && t < PHY_IQ_EST_POLL_MAX;
         t++) {
    }
}

void phy_iq_est_disable(void)
{
    PHY_REG_RMW(PHY_FE_IQ_EST_CTRL_REG, 0x0005FFFEU, 0x00001000U);
    PHY_REG_CLR(PHY_FE_IQ_EST_CTRL_REG, BIT(0));
}

void phy_dc_iq_est(uint8_t mode, uint16_t samples, int32_t out_iq[2])
{
    phy_iq_est_enable(mode, samples);
    int32_t denom = (int32_t)samples + 1;
    out_iq[0] = ((int32_t)PHY_REG_READ(PHY_FE_IQ_EST_DC_I_REG) >> 6) / denom;
    out_iq[1] = ((int32_t)PHY_REG_READ(PHY_FE_IQ_EST_DC_Q_REG) >> 6) / denom;
    phy_iq_est_disable();
}

void phy_get_corr_power(int32_t out_pwr[3], uint8_t shift)
{
    int32_t acc0 = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_ACC_REG(0U)) >> 18;
    int32_t acc1 = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_ACC_REG(1U)) >> 18;
    int32_t acc2 = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_ACC_REG(2U)) >> 18;
    int32_t acc3 = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_ACC_REG(3U)) >> 18;

    uint32_t sh = ((uint32_t)shift - 2U) & 0x1FU;
    int32_t dc_i = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_DC_I_REG) >> sh;
    int32_t dc_q = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_DC_Q_REG) >> sh;
    int32_t tot_pwr = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_PWR_REG) >> sh;

    int32_t re = acc0 + acc3;
    int32_t im = acc1 - acc2;
    uint32_t corr_sh = (((uint32_t)shift - 11U) * 2U) & 0x1FU;

    out_pwr[0] = tot_pwr;
    out_pwr[1] = (re * re + im * im) >> corr_sh;
    out_pwr[2] = (dc_i * dc_i + dc_q * dc_q) >> 16;
}

void phy_start_tx_tone(uint8_t en1, int16_t freq1, uint8_t atten1,
                       uint8_t en2, int16_t freq2, uint8_t atten2,
                       uint8_t en3, int16_t freq3, uint8_t atten3)
{
    phy_set_txclk_en(1U);

    if (en1 != 0U) {
        uint32_t att = (0U - (uint32_t)atten1) & 0xFFU;
        PHY_REG_RMW(PHY_FE_TX_TONE_1_REG, 0x0FFFFFFFU,
                    BIT(18) | (att << 10) | ((uint32_t)(uint16_t)freq1 & 0x3FFU));
    }
    if (en2 != 0U) {
        uint32_t att = (0U - (uint32_t)atten2) & 0xFFU;
        PHY_REG_RMW(PHY_FE_TX_TONE_2_REG, 0x0FFFFFFFU,
                    BIT(18) | (att << 10) | ((uint32_t)(uint16_t)freq2 & 0x3FFU));
    }
    if (en3 != 0U) {
        uint32_t att = (0U - (uint32_t)atten3) & 0xFFU;
        PHY_REG_RMW(PHY_FE_TX_TONE_3_REG, 0x1FFFFFFFU,
                    0x10040000U | (att << 10) | ((uint32_t)(uint16_t)freq3 & 0x3FFU));
    }
}

void phy_stop_tx_tone(uint8_t tone_idx)
{
    if (tone_idx == 1U) {
        PHY_REG_CLR(PHY_FE_TX_TONE_1_REG, BIT(18));
    } else if (tone_idx == 2U) {
        PHY_REG_CLR(PHY_FE_TX_TONE_2_REG, BIT(18));
    } else if (tone_idx == 3U) {
        PHY_REG_CLR(PHY_FE_TX_TONE_3_REG, BIT(18));
    } else {
        PHY_REG_CLR(PHY_FE_TX_TONE_1_REG, BIT(18));
        PHY_REG_CLR(PHY_FE_TX_TONE_2_REG, BIT(18));
        PHY_REG_CLR(PHY_FE_TX_TONE_3_REG, BIT(18));
    }
    phy_set_txclk_en(0U);
}

int32_t phy_txtone_linear_pwr(uint8_t avg_cnt, uint8_t shift)
{
    int16_t acc = 0;
    uint32_t sh = (uint32_t)shift & 0x1FU;

    for (uint8_t i = 0U; i < avg_cnt; i++) {
        int16_t out1 = 0;
        int16_t out2 = 0;
        phy_get_fm_sar_dout(&out1, &out2);
        if (out2 == 0) {
            out2 = 1;
        }
        int32_t num = (int32_t)((uint32_t)(int32_t)out1 << sh);
        acc = (int16_t)(acc + (num / (int32_t)out2));
    }
    return (int32_t)acc;
}

static const uint8_t s_linear_to_db_lut[16] WORD_ALIGNED_ATTR = {
    0U, 4U, 8U, 12U, 16U, 19U, 22U, 25U,
    28U, 31U, 34U, 36U, 39U, 41U, 44U, 46U
};

int32_t phy_linear_to_db(int32_t val, uint8_t shift)
{
    int32_t scaled;
    if (shift < 3U) {
        scaled = (int32_t)((uint32_t)val << (3U - shift));
    } else {
        scaled = val >> (((uint32_t)shift - 3U) & 0x1FU);
    }

    uint32_t u = (uint32_t)scaled;
    uint32_t lz = (u == 0U) ? 32U : (uint32_t)__builtin_clz(u);
    int8_t exp = (int8_t)(28 - (int32_t)lz);
    uint32_t idx;

    if (exp < 1) {
        exp = 0;
        idx = u & 0x0FU;
    } else {
        idx = (uint32_t)(scaled >> (exp - 1)) & 0x0FU;
    }

    int16_t db = (int16_t)((int32_t)s_linear_to_db_lut[idx] + (int32_t)exp * 48);
    return (int32_t)db;
}

/* --------------------------------------------------------------------------
 * Channel Mapping, CCA & Chip-v5 TX Analog Defaults
 * -------------------------------------------------------------------------- */

uint8_t phy_mhz2ieee(uint16_t freq_mhz, uint8_t flags)
{
    if (freq_mhz == 2484U) {
        return 14U;
    }
    if (freq_mhz > 2483U) {
        if ((flags & 0x80U) == 0U) {
            return 0xFFU;
        }
        return (uint8_t)((((int32_t)freq_mhz - 2512) / 20) + 15);
    }
    return (uint8_t)(((int32_t)freq_mhz - 2407) / 5);
}

void phy_chip_v5_enable_cca(void)
{
    PHY_REG_CLR(PHY_BB_AGC_CTRL_REG, PHY_BB_AGC_OFF);
}

void phy_chip_v5_disable_cca(void)
{
    PHY_REG_SET(PHY_BB_AGC_CTRL_REG, PHY_BB_AGC_OFF);
}

void phy_chip_v5_sense_backoff(uint8_t backoff)
{
    int8_t s = (int8_t)backoff;
    uint32_t v1 = (s < 0) ? 0x0001FC00U : ((uint32_t)backoff << 10);
    PHY_REG_RMW(PHY_BB_SENSE_BACKOFF_REG, 0x0001FC00U, v1);

    uint32_t v2 = (s < 0) ? 0x000000FEU : ((uint32_t)backoff << 1);
    PHY_REG_RMW(PHY_BB_AGC_THR_9D24_REG, 0x000000FEU, v2);
}

static const uint8_t s_chip_v5_tx_init_vals[11] WORD_ALIGNED_ATTR = {
    0x68U, 0x0FU, 0xA8U, 0x06U, 0x08U, 0xB8U, 0x5BU, 0x04U, 0x00U, 0x74U, 0x07U
};

void phy_chip_v5_tx_init(void)
{
    for (uint8_t reg = 1U; reg <= 11U; reg++) {
        rom_i2c_writeReg(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2, reg,
                         s_chip_v5_tx_init_vals[reg - 1U]);
    }
}
