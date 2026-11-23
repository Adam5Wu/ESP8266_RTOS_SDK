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
// Portions of the RTC analog reset sequence (sleep_reset_analog_rtcreg_8266)
// are adapted from teatime-os:
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
 * Exported & Cross-TU Globals (Explicitly Initialized — 0 SHN_COMMON)
 * -------------------------------------------------------------------------- */

uint8_t sleep_wake_bbpll = 0U;
uint8_t software_slp_reject = 0U;
uint8_t hardware_reject = 0U;

uint8_t g_phy_rtc_cali_trig_en = 0U;
uint16_t g_phy_lslp_mem_opt_8266 = 0U;

static uint8_t s_sdio_slp_reject = 0U;
static uint32_t s_rtc_cali_ctx[2] = { 0U, 0U };
static uint32_t s_rtc_cali_q12 = 0U;

/* --------------------------------------------------------------------------
 * IRAM Inline Helpers for Light-Sleep Entry / Exit
 * -------------------------------------------------------------------------- */

static inline uint8_t pm_sdio_nidle(void)
{
    uint32_t clk_en = PHY_REG_READ(PHY_DPORT_CLK_EN_REG);
    uint32_t strap = PHY_REG_READ(PHY_GPIO_STRAP_REG);

    if ((strap & BIT(18)) == 0U) {
        return 0U;
    }

    uint32_t status1 = PHY_REG_READ(PHY_SLC_SDIO_STATUS1_REG);
    if (status1 != 0x00002011U) {
        return 1U;
    }

    uint32_t status0 = PHY_REG_READ(PHY_SLC_SDIO_STATUS0_REG);
    if (((status0 >> 18) & 0x0FFFU) != 0x00BU) {
        return 1U;
    }

    status0 = PHY_REG_READ(PHY_SLC_SDIO_STATUS0_REG);
    if (((status0 >> 18) & 0x0FFFU) != 0x00BU) {
        return 1U;
    }

    if (PHY_REG_READ(PHY_SLC_SDIO_STATUS1_REG) != status1) {
        return 1U;
    }

    PHY_REG_WRITE(PHY_DPORT_CLK_EN_REG, clk_en & ~PHY_DPORT_CLK_WIFI_EN);
    return 0U;
}

static inline void pm_iram_delay_us(uint32_t us)
{
    uint32_t ticks_per_us =
        ((PHY_REG_READ(PHY_DPORT_CTL_REG) & PHY_DPORT_CTL_DOUBLE_CLK) != 0U) ? 160U : 80U;
    uint32_t wait_ticks = us * ticks_per_us;
    uint32_t start;
    uint32_t now;

    __asm__ __volatile__("rsr.ccount %0" : "=a"(start));
    do {
        __asm__ __volatile__("rsr.ccount %0" : "=a"(now));
    } while ((uint32_t)(now - start) < wait_ticks);
}

/* --------------------------------------------------------------------------
 * IRAM Functions (Strictly Limited to pm_goto_sleep & clockgate_watchdog)
 * -------------------------------------------------------------------------- */

void IRAM_ATTR clockgate_watchdog(uint8_t disable)
{
    if (disable == 0U) {
        PHY_REG_SET(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WDT_EN);
    } else {
        PHY_REG_CLR(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WDT_EN);
    }
}

uint32_t IRAM_ATTR pm_goto_sleep(uint32_t mode)
{
    uint32_t efuse2 = PHY_REG_READ(PHY_EFUSE_DATA2_REG);

    if ((mode != 1U) && (mode != 2U)) {
        return 1U;
    }

    uint16_t mem_opt = g_phy_lslp_mem_opt_8266;
    s_sdio_slp_reject = pm_sdio_nidle();
#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
    software_slp_reject =
        (uint8_t)(s_sdio_slp_reject | (g_phy_periodic_cal_flag & g_phy_periodic_cal_sat));
#else
    software_slp_reject = s_sdio_slp_reject;
#endif
    if (software_slp_reject != 0U) {
        return 1U;
    }

#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
    g_phy_bbpll_cal_flag = 1U;
#endif
    uint32_t lslp_en = (efuse2 >> 15) & 1U;

    PHY_REG_WRITE(PHY_RTC_INT_CLR_REG, 0xFFFFFFFFU);

    if (lslp_en == 1U) {
        PHY_REG_RMW(PHY_DPORT_LSLP_MEM0_REG, 0x000F0000U, ((uint32_t)(mem_opt & 0x0FU) << 16));
        PHY_REG_RMW(PHY_DPORT_LSLP_MEM0_REG, 0x00003000U,
                    ((uint32_t)((mem_opt >> 4) & 0x03U) << 12));
        PHY_REG_RMW(PHY_DPORT_LSLP_MEM1_REG, 0x0000003FU, ((uint32_t)((mem_opt >> 6) & 0x3FU)));
    }

    PHY_REG_RMW(PHY_BBPLL_CTRL_REG, 0x0000000CU, 0x00000008U);
    PHY_REG_SET(PHY_RTC_STATE0_REG, PHY_RTC_SLP_START_BIT);

    while ((PHY_REG_READ(PHY_RTC_INT_RAW_REG) & 0x3U) == 0U) {
    }

    pm_iram_delay_us(10U);

    if (lslp_en == 1U) {
        PHY_REG_CLR(PHY_DPORT_LSLP_MEM0_REG, 0x000F0000U);
        PHY_REG_CLR(PHY_DPORT_LSLP_MEM0_REG, 0x00003000U);
        PHY_REG_CLR(PHY_DPORT_LSLP_MEM1_REG, 0x0000003FU);
    }

    hardware_reject = (uint8_t)(PHY_REG_READ(PHY_RTC_INT_RAW_REG) & 0x2U);
    return 0U;
}

/* --------------------------------------------------------------------------
 * Internal MAC & BT Coexistence Sleep/Wake Helpers (Flash)
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
static void pm_sleep_set_mac(void)
{
    PHY_REG_WRITE(PHY_MAC_BTCO_MASK_REG, 0x00003333U);
    PHY_REG_RMW(PHY_MAC_SLEEP_CTRL_REG, 0x00C00000U, 0x00800000U);
    PHY_REG_RMW(PHY_MAC_SLEEP_CTRL_REG, 0x03000000U, 0x02000000U);
    PHY_REG_RMW(PHY_MAC_SLEEP_CTRL_REG, 0x30000000U, 0x20000000U);
    PHY_REG_RMW(PHY_MAC_SLEEP_CTRL_REG, 0xC0000000U, 0x80000000U);
    PHY_REG_CLR(PHY_MAC_TX_CTRL_REG, PHY_MAC_TX_ENABLE);
}

static void pm_check_mac_idle(void)
{
    uint16_t retry = 5001U;

    os_delay_us(20U);
    while (((PHY_REG_READ(PHY_MAC_RX_STATE_REG) & 0x0000000FU) != 0U) ||
           ((PHY_REG_READ(PHY_MAC_TX_STATE_REG) & 0x0000F000U) != 0U)) {
        retry--;
        os_delay_us(2U);
        if (retry == 0U) {
            return;
        }
    }
}

static void pm_set_sleep_btco(void)
{
    uint8_t btco_mode = chip6_phy_init_ctrl[0x22];

    if ((btco_mode != 1U) && ((uint8_t)(btco_mode - 3U) >= 3U)) {
        return;
    }

    PHY_REG_RMW(PHY_IO_MUX_MTDO_REG, 0x00000130U, 0x00000030U);
    PHY_REG_CLR(PHY_IO_MUX_GPIO0_REG, 0x00000130U);

    uint8_t btco_sub = chip6_phy_init_ctrl[0x23];
    if (btco_sub < 2U) {
        return;
    }

    if ((btco_mode == 1U) || (btco_mode == 3U)) {
        gpio_output_set(1U, 0U, 1U, 0U);
        gpio_output_set(0U, 8U, 8U, 0U);
    } else if ((btco_mode == 4U) || (btco_mode == 5U)) {
        gpio_output_set(0U, 1U, 1U, 0U);
        gpio_output_set(8U, 0U, 8U, 0U);
    }
}

static void pm_unmask_bt(uint8_t mode)
{
    static const uint32_t s_btco_masks[6] = {
        0x00000000U,
        0x00003333U,
        0x40001110U,
        0x40001550U,
        0x40003330U,
        0x40003660U,
    };

    if (mode < 6U) {
        PHY_REG_WRITE(PHY_MAC_BTCO_MASK_REG, s_btco_masks[mode]);
    }
}
#endif

static void sleep_opt_bb_on_8266(void)
{
    uint32_t chip_ver = phy_get_chip_version();

    PHY_REG_WRITE(PHY_RTC_SLP_STATE0_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_SLP_STATE1_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_PLL_CTRL_REG, (chip_ver == 2U) ? 0x00800000U : 0x00800050U);
    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, 0U);
}

/* --------------------------------------------------------------------------
 * Cross-TU PMU Sleep / Wake Primitives (Flash)
 * -------------------------------------------------------------------------- */

void phy_pm_wakeup_opt(uint32_t wakeup_opt, uint32_t wakeup_opt2)
{
    PHY_REG_RMW(PHY_RTC_WAKEUP_OPT_REG, 0x0000003FU, wakeup_opt);
    PHY_REG_RMW(PHY_RTC_SLP_REJECT_CONF_REG, 0x00000001U, wakeup_opt2);
}

void phy_pm_set_pll_xtal_wait_time(void)
{
    if (phy_get_chip_version() < 2U) {
        PHY_REG_WRITE(PHY_RTC_PLL_XTAL_WAIT_REG, 0x000C8064U);
    } else {
        PHY_REG_WRITE(PHY_RTC_PLL_XTAL_WAIT_REG, 0x00046046U);
    }
}

void phy_pm_wait4wakeup(uint32_t mode)
{
    if (((mode == 1U) || (mode == 2U)) && (software_slp_reject == 0U)) {
        for (uint32_t t = 0U;
             (PHY_REG_READ(PHY_RTC_INT_RAW_REG) & 0x3U) == 0U && t < 100000U;
             t++) {
        }
        hardware_reject = (uint8_t)(PHY_REG_READ(PHY_RTC_INT_RAW_REG) & 0x2U);
    }
}

#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
void phy_pm_open_rf(void)
{
    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, 0xFE000000U);
    PHY_REG_WRITE(PHY_RTC_SLP_STATE1_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_PLL_CTRL_REG, 0x01000000U);
    PHY_REG_CLR(PHY_RFPLL_CTRL_REG, PHY_RFPLL_SLP_HOLD);
}
#endif

void phy_pm_sleep_opt(uint32_t slp_state1, uint32_t unused,
                      uint32_t pll_ctrl, uint32_t mode)
{
    uint8_t ext_opt = chip6_phy_init_ctrl[0x25];
    uint8_t saved_ana_inf;

    (void)unused;

    if (ext_opt == 0U) {
        PHY_REG_CLR(PHY_RTC_EXT_SLEEP_OPT_REG, 0x00000003U);
    } else if (ext_opt == 1U) {
        pll_ctrl |= 0x00000020U;
    } else if (ext_opt == 2U) {
        PHY_REG_SET(PHY_RTC_EXT_SLEEP_OPT_REG, 0x00000003U);
    }

    PHY_REG_WRITE(PHY_RTC_SLP_STATE0_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_SLP_STATE1_REG, slp_state1);
    PHY_REG_WRITE(PHY_RTC_PLL_CTRL_REG, pll_ctrl);

    saved_ana_inf = rom_i2c_readReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x1CU);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x1CU, 5U, 5U, 1U);
    PHY_REG_RMW(PHY_RFPLL_CTRL_REG, PHY_RFPLL_SLP_HOLD, 0x00010000U);
    ets_delay_us(1U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, 0x1CU, saved_ana_inf);

    PHY_REG_RMW(PHY_RF_CAL_MODE_REG, 0x01800000U, 0x00800000U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 3U, 1U);

    if (mode == 8U) {
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, 0U, 0U, 0U, 0U);
        rom_i2c_writeReg(PHY_I2C_BLOCK_BIAS_PWR, PHY_I2C_HOST_4, 0U, 6U);
        PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, 0xD6000000U);
    } else {
        PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, 0x50000000U);
    }
}

void phy_pm_sleep_opt_bb_off(uint32_t mode)
{
    uint32_t pll_ctrl =
        ((phy_get_chip_version() == 2U) && (chip6_phy_init_ctrl[0x44] != 2U))
            ? 0x00800000U
            : 0x00800050U;

    phy_pm_sleep_opt(4U, 0U, pll_ctrl, mode);
}

void phy_pm_sleep_opt_bb_on(uint32_t mode)
{
    uint32_t pll_ctrl =
        ((phy_get_chip_version() == 2U) && (chip6_phy_init_ctrl[0x44] != 2U))
            ? 0x00800000U
            : 0x00800050U;

    phy_pm_sleep_opt(0U, 0U, pll_ctrl, mode);
}

/* --------------------------------------------------------------------------
 * Exported PMU Sleep, Wake, RTC Reset & Clock Calibration APIs (Flash)
 * -------------------------------------------------------------------------- */

void pm_set_sleep_cycles(uint32_t cycles)
{
    PHY_REG_WRITE(PHY_RTC_SLP_VAL_REG, PHY_REG_READ(PHY_RTC_SLP_CNT_VAL_REG) + cycles);
#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
    g_phy_periodic_cal_sat = (cycles > 5000U) ? 1U : 0U;
#endif
}

void pm_set_sleep_mode(uint32_t mode)
{
    sleep_wake_bbpll = 1U;
#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
    noise_check_loop(1U, 0U);
    PHY_REG_SET(PHY_BB_SLEEP_REG, PHY_BB_SLEEP_RX);
#endif
    phy_pm_set_pll_xtal_wait_time();

    if (mode != 4U) {
        g_phy_sleep_mode_flag = 1U;
        if (mode == 1U) {
            phy_pm_sleep_opt_bb_off(1U);
        } else if ((mode == 2U) || (mode == 8U)) {
            phy_pm_sleep_opt_bb_on(mode);
        }
    }

#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
    PHY_REG_RMW(PHY_MAC_CTRL_REG, 0x00000FFFU, 0x00000002U);
    PHY_REG_CLR(PHY_MAC_CTRL_REG, 0x40000000U);
    PHY_REG_SET(PHY_MAC_CTRL_REG, 0x80000000U);
    PHY_REG_RMW(PHY_MAC_SLEEP_CTRL_REG, 0x00C00000U, 0x00800000U);

    pm_set_sleep_btco();
    pm_sleep_set_mac();
    pm_check_mac_idle();

    if (mode == 8U) {
        if (chip6_phy_init_ctrl[0x47] == 0xFFU) {
            PHY_REG_SET(PHY_PBUS_CTRL_REG, PHY_PBUS_DEBUG_MODE);
            phy_pbus_force(6U, 1U, 2U);
            PHY_REG_CLR(PHY_PBUS_CTRL_REG, PHY_PBUS_DEBUG_MODE);
        }
    } else
#endif
    if ((mode != 1U) && (mode != 2U)) {
        return;
    }

    PHY_REG_CLR(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_GATE_MASK);
}

#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
void pm_set_wakeup_btco(void)
{
    uint8_t btco_mode = chip6_phy_init_ctrl[0x22];

    if ((btco_mode != 1U) && ((uint8_t)(btco_mode - 3U) >= 3U)) {
        return;
    }

    uint8_t btco_sub = chip6_phy_init_ctrl[0x23];
    if (btco_sub < 2U) {
        PHY_REG_RMW(PHY_IO_MUX_MTDO_REG, 0x00000130U, 0x00000030U);
        PHY_REG_CLR(PHY_IO_MUX_GPIO0_REG, 0x00000130U);
    } else {
        PHY_REG_RMW(PHY_IO_MUX_MTDO_REG, 0x00000130U, 0x00000020U);
        PHY_REG_RMW(PHY_IO_MUX_GPIO0_REG, 0x00000130U, 0x00000020U);
    }

    if ((btco_mode == 1U) || (btco_mode == 3U)) {
        if (btco_sub == 1U) {
            gpio_output_set(1U, 0U, 1U, 0U);
            gpio_output_set(0U, 8U, 8U, 0U);
        } else if (btco_sub == 0U) {
            gpio_output_set(0U, 1U, 1U, 0U);
            gpio_output_set(8U, 0U, 8U, 0U);
        }
    } else if ((btco_mode == 4U) || (btco_mode == 5U)) {
        if (btco_sub == 1U) {
            gpio_output_set(0U, 1U, 1U, 0U);
            gpio_output_set(8U, 0U, 8U, 0U);
        } else if (btco_sub == 0U) {
            gpio_output_set(1U, 0U, 1U, 0U);
            gpio_output_set(0U, 8U, 8U, 0U);
        }
    }
}

void pm_set_wakeup_mac(void)
{
    uint8_t btco_mode = chip6_phy_init_ctrl[0x22];

    if ((btco_mode == 1U) || ((uint8_t)(btco_mode - 3U) < 3U)) {
        pm_unmask_bt(chip6_phy_init_ctrl[0x23]);
    } else {
        PHY_REG_WRITE(PHY_MAC_BTCO_MASK_REG, 0U);
    }

    PHY_REG_CLR(PHY_MAC_SLEEP_CTRL_REG, 0xC0000000U);
    PHY_REG_CLR(PHY_MAC_SLEEP_CTRL_REG, 0x30000000U);
    PHY_REG_CLR(PHY_MAC_SLEEP_CTRL_REG, 0x03000000U);
    PHY_REG_CLR(PHY_MAC_SLEEP_CTRL_REG, 0x00C00000U);
    PHY_REG_SET(PHY_MAC_TX_CTRL_REG, PHY_MAC_TX_ENABLE);
}

void pm_wakeup_init(uint32_t mode, uint32_t skip_bbpll)
{
    uint8_t skip = (uint8_t)(skip_bbpll & 0xFFU);
    bool is_lslp = (mode == 1U) || (mode == 2U);
    bool is_rf_sleep = is_lslp || (mode == 8U);

    if ((skip == 0U) && is_lslp && (sleep_wake_bbpll != 0U) &&
        (software_slp_reject == 0U) && (hardware_reject == 0U)) {
        change_bbpll160();
        sleep_wake_bbpll = 0U;
    }

    PHY_REG_RMW(PHY_BBPLL_CTRL_REG, 0x0000000CU, 0x00000004U);
    PHY_REG_SET(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_EN);
    if (is_rf_sleep) {
        PHY_REG_SET(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_SUB);
    }

    PHY_REG_WRITE(PHY_MAC_CTRL_REG, 0x80000FFFU);
    PHY_REG_CLR(PHY_MAC_SLEEP_CTRL_REG, 0x00C00000U);

    if (is_rf_sleep) {
        phy_sleep_set_rxpbus(0U);
        rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 3U, 0xF1U);
        rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 11U, 0x80U);
        phy_pm_open_rf();
        rom_i2c_writeReg(PHY_I2C_BLOCK_BIAS_PWR, PHY_I2C_HOST_4, 0U, 0xC6U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, 0U, 0U, 0U, 1U);

        g_phy_sleep_params.param_flag |= PHY_PARAM_WAKEUP_RF;
        phy_wakeup_rf();
        g_phy_sleep_params.param_flag &= ~PHY_PARAM_WAKEUP_RF;
    }

    PHY_REG_CLR(PHY_BB_SLEEP_REG, PHY_BB_SLEEP_RX);
    PHY_REG_SET(PHY_BB_RX_CTRL_REG, PHY_BB_RX_RESET);
    PHY_REG_CLR(PHY_BB_RX_CTRL_REG, PHY_BB_RX_RESET);

    if ((PHY_REG_READ(PHY_MAC_PHY_CTRL_REG) & PHY_MAC_PHY_RF_UP) != 0U) {
        ets_delay_us(2U);
        PHY_REG_RMW(PHY_BB_RX_GAIN_FORCE_REG, 0x000003FFU, 0x000000F1U);
        PHY_REG_RMW(PHY_BB_RX_GAIN_FORCE_REG, 0x000003FFU, 0x000000F0U);
        ets_delay_us(2U);
    }

    adc_rand_noise = phy_get_adc_rand();
    pm_set_wakeup_btco();
    pm_set_wakeup_mac();

    if ((skip == 0U) && (s_sdio_slp_reject == 0U) && (g_phy_periodic_cal_flag == 1U) &&
        (g_phy_periodic_cal_sat == 1U) && is_lslp) {
        g_phy_periodic_cal_flag = 0U;
        g_phy_periodic_cal_sat = 0U;
    }

    g_phy_sleep_mode_flag = 0U;
}
#endif

void sleep_reset_analog_rtcreg_8266(void)
{
    PHY_REG_SET(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_EN);
    software_slp_reject = 0U;
    PHY_REG_WRITE(PHY_RTC_INT_CLR_REG, 0xFFFFFFFFU);
    sleep_opt_bb_on_8266();
    phy_pm_wakeup_opt(8U, 0U);
    phy_pm_set_pll_xtal_wait_time();
    pm_set_sleep_cycles(1000U);
    PHY_REG_SET(PHY_RTC_STATE0_REG, PHY_RTC_SLP_START_BIT);
    phy_pm_wait4wakeup(2U);

    PHY_REG_WRITE(PHY_RTC_PLL_CTRL_REG, 0x0019C06AU);
    PHY_REG_WRITE(PHY_RTC_SLP_VAL_REG, 0x00000FFFU);
    PHY_REG_WRITE(PHY_RTC_STATE0_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_PLL_XTAL_WAIT_REG, 0x000640C8U);
    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, 0xF0000000U);
    PHY_REG_WRITE(PHY_RTC_WAKEUP_OPT_REG, 0x00000004U);
    PHY_REG_WRITE(PHY_RTC_INT_ENA_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_SLP_STATE0_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_SLP_STATE1_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_TIMING0_REG, 0x20302020U);
    PHY_REG_WRITE(PHY_RTC_TIMING1_REG, 0x20500000U);
    PHY_REG_WRITE(PHY_RTC_ANALOG1_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_ANALOG2_REG, 7U);
    PHY_REG_WRITE(PHY_RTC_ANALOG3_REG, 7U);
    PHY_REG_WRITE(PHY_RTC_EXT_SLEEP_OPT_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_GPIO_OUT_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_GPIO_EN_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_ANALOG6_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_GPIO_CONF_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_CLK1_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_CLK2_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_CLK3_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_EXT_GPIO_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_SLP_REJECT_CONF_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_TRIM0_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_TRIM1_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_TRIM2_REG, 0U);
}

#ifdef CONFIG_ESP8266_OSS_PHY_ONLY
void phy_pm_rf_off_boot(void)
{
    g_phy_sleep_mode_flag = 1U;
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 3U, 0x01U);
    PHY_REG_CLR(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_GATE_MASK);
    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, 0x50000000U);
}
#endif

void pm_rtc_clock_cali(uint32_t *pm_ctx)
{
    if (g_phy_rtc_cali_trig_en == 0U) {
        PHY_REG_WRITE(PHY_RTC_CALI_CTRL_REG, 0x00000101U);
        PHY_REG_SET(PHY_RTC_CALI_CTRL_REG, PHY_RTC_CALI_START);
    }

    ets_delay_us(10U);
    while ((int32_t)PHY_REG_READ(PHY_RTC_CALI_DATA_REG) >= 0) {
    }

    uint32_t cnt = PHY_REG_READ(PHY_RTC_CALI_DATA_REG) & PHY_RTC_CALI_CNT_MASK;
    g_phy_rtc_cali_trig_en = 0U;

    uint32_t xtal_mhz = (chip6_phy_init_ctrl[0] == 1U)
                            ? 26U
                            : ((chip6_phy_init_ctrl[0] == 2U) ? 24U : 40U);
    uint32_t cali_q12 = (cnt << 4) / xtal_mhz;

    if (cali_q12 != 0U) {
        uint32_t prev = pm_ctx[1];
        if (prev != 0U) {
            uint32_t diff = (prev >= cali_q12) ? (prev - cali_q12) : (cali_q12 - prev);
            if (diff > 511U) {
                return;
            }
            cali_q12 = ((prev * 3U) + (cali_q12 * 5U)) >> 3;
        }
        pm_ctx[1] = cali_q12;
    }
}

uint32_t pm_rtc_clock_cali_proc(void)
{
    s_rtc_cali_ctx[1] = 0U;
    rom_i2c_writeReg(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 8U, 0U);
    pm_rtc_clock_cali(s_rtc_cali_ctx);
    s_rtc_cali_q12 = s_rtc_cali_ctx[1];
    return s_rtc_cali_q12;
}

uint32_t pm_usec2rtc(uint32_t usec, uint32_t cali_q12)
{
    if (cali_q12 == 0U) {
        return usec / 5U;
    }
    if (usec > 0x000FFFFFU) {
        return (usec / cali_q12) << 12;
    }
    return (usec << 12) / cali_q12;
}

uint64_t pm_usec2rtc_64(uint64_t usec, uint32_t cali_q12)
{
    if (cali_q12 == 0U) {
        return usec / 5ULL;
    }
    if ((uint32_t)(usec >> 32) > 0x000FFFFFU) {
        return (usec / (uint64_t)cali_q12) << 12;
    }
    return (usec << 12) / (uint64_t)cali_q12;
}

uint64_t pm_get_sleep_cycles_64(uint64_t usec)
{
    return pm_usec2rtc_64(usec, s_rtc_cali_q12);
}
