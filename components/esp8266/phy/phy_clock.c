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

/* --------------------------------------------------------------------------
 * File-Local Constants (Chip Revision, BBPLL 160 MHz & UART Strap)
 * -------------------------------------------------------------------------- */

#define PHY_CHIP_VERSION_UNINIT     0xFFFFFFFFU /* Sentinel before first eFuse read */

#define PHY_RTC_INT_CLR_ALL         0xFFFFFFFFU /* Clear all pending RTC interrupts */
#define PHY_RTC_SLP_REJECT_DIS_BIT  BIT(0)      /* Hardware sleep-reject disable bit */
#define PHY_BBPLL_SLEEP_CYCLES      3U          /* Minimal RTC cycles to pulse BBPLL lock */

#define PHY_BBPLL_OPT_AUTO          0U          /* Auto-enable 160 MHz BBPLL on rev > 1 */
#define PHY_BBPLL_OPT_FORCE_ON      1U          /* Always run 160 MHz BBPLL re-lock */

#define PHY_FREQ_OFF_MODE_EN_BIT    1U          /* Bit 0: analog clock gating / freq-off en */
#define PHY_FREQ_OFF_MODE_FRAC_BIT  2U          /* Bit 1: select fractional int divider */
#define PHY_FREQ_OFF_MODE_MASK      3U          /* Bits [1:0] controlling BBPLL trim code */

#define PHY_I2C_BIAS_RC_CAL_REG     8U          /* Bias/RC calibration control sub-reg */
#define PHY_I2C_BBPLL_DIV_REG       1U          /* BBPLL divider register */
#define PHY_I2C_BBPLL_CTRL_REG      2U          /* BBPLL loop/divider control register */
#define PHY_I2C_BBPLL_TRIM_REG      4U          /* BBPLL [4:0] VCO frequency trim register */

#define PHY_ANA_INF_DIV_26M_BASE    0x000D0000U /* Integer divider when frac bit is 0 */
#define PHY_ANA_INF_DIV_FRAC_COMP   0x000C6186U /* Fractional divider for crystal offset */
#define PHY_BBPLL_TRIM_DEFAULT      0x13U       /* Standard BBPLL trim code */
#define PHY_BBPLL_TRIM_COMP         0x14U       /* Compensated BBPLL trim (mode & 3 == 1) */
#define PHY_BBPLL_26M_DIV_VAL       0x88U       /* 26 MHz XTAL -> 160 MHz BBPLL div reg 1 */
#define PHY_BBPLL_26M_CTRL_VAL      0x91U       /* 26 MHz XTAL -> 160 MHz BBPLL ctrl reg 2 */
#define PHY_BBPLL_24M_CTRL_DIV      2U          /* 24 MHz XTAL -> BBPLL reg 2 [7:5] code */
#define PHY_BBPLL_GATING_DELAY_US   5U          /* Settle delay after enabling clk gating */

#define PHY_CPU_FREQ_80MHZ          80U         /* CPU ticks/us at 80 MHz */
#define PHY_CPU_FREQ_160MHZ         160U        /* CPU ticks/us at 160 MHz */
#define PHY_BBPLL_CAL_DELAY_FAST_US 100U        /* Fast BBPLL calibration settle time */
#define PHY_BBPLL_CAL_DELAY_SLOW_US 1000U       /* Full/slow BBPLL calibration settle time */

#define PHY_IO_MUX_U0TXD_ALT_BIT    BIT(8)      /* IO_MUX U0TXD alternate-function bit */
#define PHY_UART1_NUM               1U          /* Debug UART port switched under SDIO */

/* Cached eFuse chip revision (4 B .data, explicit init) */
static uint32_t s_chip_version = PHY_CHIP_VERSION_UNINIT;

/**
 * @brief Read and cache the 4-bit ESP8266 silicon chip revision from eFuse.
 *
 * Selects the eFuse word containing the chip version nibble using
 * `PHY_EFUSE_DATA2_REG[15]` (`PHY_EFUSE_DATA2_VER_SEL_BIT`), extracts
 * bits `[27:24]`, and caches the result in `s_chip_version`.
 *
 * @return 4-bit silicon revision code (`0..15`).
 */
uint32_t phy_get_chip_version(void)
{
    if (s_chip_version == PHY_CHIP_VERSION_UNINIT) {
        /*
         * Silicon eFuse layout: when DATA2[15] is set, the 4-bit chip
         * revision is stored in DATA1[27:24]; otherwise it resides in
         * DATA3[27:24].
         */
        uint32_t efuse_reg = ((PHY_REG_READ(PHY_EFUSE_DATA2_REG) &
                               PHY_EFUSE_DATA2_VER_SEL_BIT) != 0U)
                                 ? PHY_EFUSE_DATA1_REG
                                 : PHY_EFUSE_DATA3_REG;
        s_chip_version = (PHY_REG_READ(efuse_reg) >> PHY_EFUSE_CHIP_VER_SHIFT) &
                         PHY_EFUSE_CHIP_VER_MASK;
    }
    return s_chip_version;
}

/**
 * @brief Re-lock the 160 MHz BBPLL for non-40 MHz crystals via a brief RTC sleep pulse.
 *
 * Configures analog interface clock gating, BBPLL trim, and crystal-specific
 * BBPLL divider registers (`26 MHz` or `24 MHz`), then triggers a minimal
 * 3-cycle RTC timer sleep/wake cycle so the PMU hardware safely re-locks the
 * 160 MHz BBPLL without glitching the active CPU clock tree. Sets
 * `PHY_PARAM_BBPLL160_DONE` in `g_phy_sleep_params.param_flag` on completion.
 */
void change_bbpll160_sleep(void)
{
    /* Clear RTC interrupts and configure a 3-cycle timer wakeup with no XTAL wait */
    PHY_REG_WRITE(PHY_RTC_INT_CLR_REG, PHY_RTC_INT_CLR_ALL);
    rom_i2c_writeReg(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, PHY_I2C_BIAS_RC_CAL_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_PLL_XTAL_WAIT_REG, 0U);
    pm_set_sleep_cycles(PHY_BBPLL_SLEEP_CYCLES);

    PHY_REG_WRITE(PHY_RTC_SLP_STATE0_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_SLP_STATE1_REG, 0U);
    PHY_REG_CLR(PHY_RTC_SLP_REJECT_CONF_REG, PHY_RTC_SLP_REJECT_DIS_BIT);

    /* Program short BBPLL-re-lock RTC PLL control and select timer wakeup */
    uint32_t saved_pll_ctrl = PHY_REG_READ(PHY_RTC_PLL_CTRL_REG);
    PHY_REG_WRITE(PHY_RTC_PLL_CTRL_REG, PHY_RTC_PLL_CTRL_BBPLL160);
    phy_pm_wakeup_opt(PHY_RTC_WAKEUP_TIMER, 0U);

    uint32_t slp_start = PHY_REG_READ(PHY_RTC_STATE0_REG) | PHY_RTC_SLP_START_BIT;
    uint8_t ctrl4c = chip6_phy_init_ctrl[PHY_CTRL_FREQ_OFF_MODE];

    /* Configure analog-interface clock gating or fractional frequency-offset divider */
    if ((ctrl4c & PHY_FREQ_OFF_MODE_EN_BIT) == 0U) {
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_DPD_TXIQ_P_REG, 3U, 3U, 1U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_RXIQ_SIGN_REG, 0U, 0U, 1U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_CLK_GATE_REG, 0U, 0U, 0U);
    } else {
        uint32_t int_div = ((ctrl4c & PHY_FREQ_OFF_MODE_FRAC_BIT) != 0U)
                               ? PHY_ANA_INF_DIV_FRAC_COMP
                               : PHY_ANA_INF_DIV_26M_BASE;
        phy_ana_inf_gating_en(1U, int_div, PHY_ANA_INF_DIV_FRAC_COMP);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_CLK_GATE_REG, 6U, 6U, 1U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_CLK_GATE_REG, 5U, 5U, 1U);
        ets_delay_us(PHY_BBPLL_GATING_DELAY_US);
    }

    /* Apply BBPLL trim and crystal-specific feedback dividers for 26 MHz / 24 MHz */
    uint8_t bbpll_trim = ((chip6_phy_init_ctrl[PHY_CTRL_FREQ_OFF_MODE] &
                           PHY_FREQ_OFF_MODE_MASK) == PHY_FREQ_OFF_MODE_EN_BIT)
                             ? PHY_BBPLL_TRIM_COMP
                             : PHY_BBPLL_TRIM_DEFAULT;
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BBPLL, PHY_I2C_HOST_4,
                          PHY_I2C_BBPLL_TRIM_REG, 4U, 0U, bbpll_trim);

    uint8_t xtal = chip6_phy_init_ctrl[PHY_CTRL_XTAL_FREQ];
    if (xtal == PHY_XTAL_26MHZ) {
        rom_i2c_writeReg(PHY_I2C_BLOCK_BBPLL, PHY_I2C_HOST_4,
                         PHY_I2C_BBPLL_DIV_REG, PHY_BBPLL_26M_DIV_VAL);
        rom_i2c_writeReg(PHY_I2C_BLOCK_BBPLL, PHY_I2C_HOST_4,
                         PHY_I2C_BBPLL_CTRL_REG, PHY_BBPLL_26M_CTRL_VAL);
    } else if (xtal == PHY_XTAL_24MHZ) {
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BBPLL, PHY_I2C_HOST_4,
                              PHY_I2C_BBPLL_CTRL_REG, 7U, 5U, PHY_BBPLL_24M_CTRL_DIV);
    }

    /* Trigger the sleep pulse, wait for RTC wakeup, and restore PLL control */
    PHY_REG_WRITE(PHY_RTC_STATE0_REG, slp_start);
    phy_pm_wait4wakeup(PHY_PM_MODE_LIGHT_BB_OFF);
    PHY_REG_WRITE(PHY_RTC_PLL_CTRL_REG, saved_pll_ctrl);
#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
    g_phy_sleep_params.param_flag |= PHY_PARAM_BBPLL160_DONE;
#endif
}

/**
 * @brief Conditionally switch BBPLL to 160 MHz according to crystal, revision, and init option.
 *
 * Only runs for non-40 MHz crystals when `PHY_CTRL_BBPLL160_OPT` is forced on
 * (`1`), or when set to auto (`0`) on silicon revisions greater than `1`.
 */
void change_bbpll160(void)
{
    uint32_t chip_ver = phy_get_chip_version();
    if (chip6_phy_init_ctrl[PHY_CTRL_XTAL_FREQ] != PHY_XTAL_40MHZ) {
        uint8_t opt = chip6_phy_init_ctrl[PHY_CTRL_BBPLL160_OPT];
        if (opt == PHY_BBPLL_OPT_FORCE_ON || (chip_ver > 1U && opt == PHY_BBPLL_OPT_AUTO)) {
            change_bbpll160_sleep();
        }
    }
}

/**
 * @brief Recalibrate the 160 MHz BBPLL while temporarily stepping the CPU clock down to 80 MHz.
 *
 * Clears `PHY_DPORT_CTL_DOUBLE_CLK` before entering `PHY_BBPLL_MODE_CAL` so the
 * CPU remains within timing margins during PLL re-lock, then restores run mode
 * and the original CPU frequency.
 *
 * @param slow Non-zero for a full 1000 us calibration wait; zero for a fast 100 us wait.
 */
void bbpll_cal(uint8_t slow)
{
    uint32_t saved_ctl = PHY_REG_READ(PHY_DPORT_CTL_REG);
    PHY_REG_CLR(PHY_DPORT_CTL_REG, PHY_DPORT_CTL_DOUBLE_CLK);
    ets_update_cpu_frequency(PHY_CPU_FREQ_80MHZ);
    ets_delay_us(1U);

    PHY_REG_RMW(PHY_BBPLL_CTRL_REG, PHY_BBPLL_MODE_MASK, PHY_BBPLL_MODE_CAL);
    ets_delay_us((slow != 0U) ? PHY_BBPLL_CAL_DELAY_SLOW_US : PHY_BBPLL_CAL_DELAY_FAST_US);
    PHY_REG_RMW(PHY_BBPLL_CTRL_REG, PHY_BBPLL_MODE_MASK, PHY_BBPLL_MODE_RUN);
    ets_delay_us(1U);

    PHY_REG_WRITE(PHY_DPORT_CTL_REG, saved_ctl);
    if ((saved_ctl & PHY_DPORT_CTL_DOUBLE_CLK) != 0U) {
        ets_update_cpu_frequency(PHY_CPU_FREQ_160MHZ);
    }
}

#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
/**
 * @brief Synchronize BBPLL to the configured crystal frequency and re-init UART1 under SDIO boot.
 *
 * Skips execution during RF sleep wakeup (`PHY_PARAM_WAKEUP_RF`) or when using a
 * 40 MHz crystal without frequency-offset gating. Otherwise places BBPLL into
 * calibration mode, runs `change_bbpll160_sleep()` if not yet performed, and
 * re-initializes UART1 when the GPIO boot straps indicate SDIO boot with
 * alternate U0TXD pin muxing.
 */
void phy_set_crystal_uart(void)
{
    if ((chip6_phy_init_ctrl[PHY_CTRL_XTAL_FREQ] != PHY_XTAL_40MHZ ||
         (chip6_phy_init_ctrl[PHY_CTRL_FREQ_OFF_MODE] & PHY_FREQ_OFF_MODE_EN_BIT) != 0U) &&
        (g_phy_sleep_params.param_flag & PHY_PARAM_WAKEUP_RF) == 0U) {
        PHY_REG_RMW(PHY_BBPLL_CTRL_REG, PHY_BBPLL_MODE_MASK, PHY_BBPLL_MODE_CAL);
        if ((g_phy_sleep_params.param_flag & PHY_PARAM_BBPLL160_DONE) == 0U) {
            change_bbpll160_sleep();
        }
        /*
         * In SDIO host-boot mode with U0TXD mapped to its alternate function,
         * re-initialize UART1 so baud-rate dividers match the new PLL clock.
         */
        if ((PHY_REG_READ(PHY_GPIO_STRAP_REG) & PHY_GPIO_STRAP_SDIO_BIT) != 0U &&
            ((PHY_REG_READ(PHY_GPIO_STRAP_REG) >> PHY_GPIO_STRAP_BOOT_SHIFT) &
             PHY_GPIO_STRAP_BOOT_MASK) == PHY_GPIO_STRAP_BOOT_SDIO &&
            (PHY_REG_READ(PHY_IO_MUX_U0TXD_REG) & PHY_IO_MUX_U0TXD_ALT_BIT) != 0U) {
            Uart_Init(PHY_UART1_NUM);
            uart_buff_switch(PHY_UART1_NUM);
        }
    }
}
#endif
