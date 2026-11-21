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
// Portions of the BBPLL calibration sequence are adapted from teatime-os:
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

/* Cached eFuse chip revision (4 B .data, explicit init) */
static uint32_t s_chip_version = 0xFFFFFFFFU;

uint32_t phy_get_chip_version(void)
{
    if (s_chip_version == 0xFFFFFFFFU) {
        uint32_t efuse_reg = ((PHY_REG_READ(PHY_EFUSE_DATA2_REG) & BIT(15)) != 0U)
                                 ? PHY_EFUSE_DATA1_REG
                                 : PHY_EFUSE_DATA3_REG;
        s_chip_version = (PHY_REG_READ(efuse_reg) >> 24) & 0x0FU;
    }
    return s_chip_version;
}

void change_bbpll160_sleep(void)
{
    PHY_REG_WRITE(PHY_RTC_INT_CLR_REG, 0xFFFFFFFFU);
    rom_i2c_writeReg(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 8U, 0U);
    PHY_REG_WRITE(PHY_RTC_PLL_XTAL_WAIT_REG, 0U);
    pm_set_sleep_cycles(3U);

    PHY_REG_WRITE(PHY_RTC_SLP_STATE0_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_SLP_STATE1_REG, 0U);
    PHY_REG_CLR(PHY_RTC_SLP_REJECT_CONF_REG, BIT(0));

    uint32_t saved_pll_ctrl = PHY_REG_READ(PHY_RTC_PLL_CTRL_REG);
    PHY_REG_WRITE(PHY_RTC_PLL_CTRL_REG, 0x00800070U);
    phy_pm_wakeup_opt(8U, 0U);

    uint32_t slp_start = PHY_REG_READ(PHY_RTC_STATE0_REG) | PHY_RTC_SLP_START_BIT;
    uint8_t ctrl4c = chip6_phy_init_ctrl[0x4CU];

    if ((ctrl4c & 1U) == 0U) {
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x0FU, 3U, 3U, 1U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x18U, 0U, 0U, 1U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x1CU, 0U, 0U, 0U);
    } else {
        uint32_t int_div = ((ctrl4c & 2U) != 0U) ? 0x000C6186U : 0x000D0000U;
        phy_ana_inf_gating_en(1U, int_div, 0x000C6186U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x1CU, 6U, 6U, 1U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x1CU, 5U, 5U, 1U);
        ets_delay_us(5U);
    }

    uint8_t bbpll_trim = ((chip6_phy_init_ctrl[0x4CU] & 3U) == 1U) ? 0x14U : 0x13U;
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BBPLL, PHY_I2C_HOST_4, 4U, 4U, 0U, bbpll_trim);

    uint8_t xtal = chip6_phy_init_ctrl[0];
    if (xtal == 1U) {
        rom_i2c_writeReg(PHY_I2C_BLOCK_BBPLL, PHY_I2C_HOST_4, 1U, 0x88U);
        rom_i2c_writeReg(PHY_I2C_BLOCK_BBPLL, PHY_I2C_HOST_4, 2U, 0x91U);
    } else if (xtal == 2U) {
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BBPLL, PHY_I2C_HOST_4, 2U, 7U, 5U, 2U);
    }

    PHY_REG_WRITE(PHY_RTC_STATE0_REG, slp_start);
    phy_pm_wait4wakeup(1U);
    PHY_REG_WRITE(PHY_RTC_PLL_CTRL_REG, saved_pll_ctrl);
    g_phy_sleep_params.param_flag |= PHY_PARAM_BBPLL160_DONE;
}

void change_bbpll160(void)
{
    uint32_t chip_ver = phy_get_chip_version();
    if (chip6_phy_init_ctrl[0] != 0U) {
        uint8_t opt = chip6_phy_init_ctrl[0x44U];
        if (opt == 1U || (chip_ver > 1U && opt == 0U)) {
            change_bbpll160_sleep();
        }
    }
}

void bbpll_cal(uint8_t slow)
{
    uint32_t saved_ctl = PHY_REG_READ(PHY_DPORT_CTL_REG);
    PHY_REG_CLR(PHY_DPORT_CTL_REG, PHY_DPORT_CTL_DOUBLE_CLK);
    ets_update_cpu_frequency(80U);
    ets_delay_us(1U);

    PHY_REG_RMW(PHY_BBPLL_CTRL_REG, 0x0000000CU, 0x00000008U);
    ets_delay_us((slow != 0U) ? 1000U : 100U);
    PHY_REG_RMW(PHY_BBPLL_CTRL_REG, 0x0000000CU, 0x00000004U);
    ets_delay_us(1U);

    PHY_REG_WRITE(PHY_DPORT_CTL_REG, saved_ctl);
    if ((saved_ctl & PHY_DPORT_CTL_DOUBLE_CLK) != 0U) {
        ets_update_cpu_frequency(160U);
    }
}

void phy_set_crystal_uart(void)
{
    if ((chip6_phy_init_ctrl[0] != 0U || (chip6_phy_init_ctrl[0x4CU] & 1U) != 0U) &&
        (g_phy_sleep_params.param_flag & PHY_PARAM_WAKEUP_RF) == 0U) {
        PHY_REG_RMW(PHY_BBPLL_CTRL_REG, 0x0000000CU, 0x00000008U);
        if ((g_phy_sleep_params.param_flag & PHY_PARAM_BBPLL160_DONE) == 0U) {
            change_bbpll160_sleep();
        }
        if ((PHY_REG_READ(PHY_GPIO_STRAP_REG) & BIT(18)) != 0U &&
            ((PHY_REG_READ(PHY_GPIO_STRAP_REG) >> 29) & 7U) == 2U &&
            (PHY_REG_READ(PHY_IO_MUX_U0TXD_REG) & BIT(8)) != 0U) {
            Uart_Init(1U);
            uart_buff_switch(1U);
        }
    }
}
