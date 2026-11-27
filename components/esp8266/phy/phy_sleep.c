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

/* IRAM CCOUNT busy-wait timing & post-wake settling */
#define PM_CPU_FREQ_80MHZ               80U
#define PM_CPU_FREQ_160MHZ              160U
#define PM_WAKE_SETTLE_US               10U

/* eFuse & DPORT light-sleep memory-retention option unpacking */
#define PM_EFUSE_LSLP_EN_SHIFT          15U
#define PM_LSLP_MEM0_LO_VAL_MASK        0x0FU
#define PM_LSLP_MEM0_MID_SHIFT_SRC      4U
#define PM_LSLP_MEM0_MID_VAL_MASK       0x03U
#define PM_LSLP_MEM1_HI_SHIFT_SRC       6U
#define PM_LSLP_MEM1_HI_VAL_MASK        0x3FU

/* RTC PMU interrupt, sleep-option, silicon-version & reset constants */
#define PM_RTC_INT_CLR_ALL              0xFFFFFFFFU
#define PM_RTC_SLP_REJECT_CONF_MASK     0x00000001U
#define PM_RTC_EXT_SLEEP_OPT_MASK       0x00000003U
#define PM_RTC_PLL_CTRL_EXT_OPT1_BIT    0x00000020U
#define PM_EXT_SLEEP_OPT_CLR            0U
#define PM_EXT_SLEEP_OPT_PLL_BIT        1U
#define PM_EXT_SLEEP_OPT_SET            2U
#define PM_CHIP_VER_REV2                2U
#define PM_BBPLL160_OPT_FORCE_OFF       2U
#define PM_RTC_ANALOG_RESET_CYCLES      1000U
#define PM_PERIODIC_CAL_MIN_CYCLES      5000U

/* MAC idle polling & Bluetooth coexistence pin / mode configuration */
#define PM_MAC_IDLE_INIT_DELAY_US       20U
#define PM_MAC_IDLE_POLL_DELAY_US       2U
#define PM_MAC_IDLE_RETRY_LIMIT         5001U
#define PM_MAC_BTCO_SLEEP_MASK          0x00003333U
#define PM_BTCO_MODE_1                  1U
#define PM_BTCO_MODE_3                  3U
#define PM_BTCO_MODE_4                  4U
#define PM_BTCO_MODE_5                  5U
#define PM_BTCO_SUBMODE_STATIC_MAX      2U
#define PM_BTCO_SUBMODE_COUNT           6U
#define PM_BTCO_GPIO0_BIT               1U     /* GPIO0 mask for gpio_output_set() */
#define PM_BTCO_GPIO3_BIT               8U     /* GPIO3 mask for gpio_output_set() */
#define PM_IO_MUX_FUNC_MTDO_GPIO        0x00000030U /* IO_MUX MTDO -> GPIO mode */
#define PM_IO_MUX_FUNC_BTCO_HW          0x00000020U /* IO_MUX -> HW BT coex mode */

/* RF-I2C / PBUS / BB sleep & wakeup payloads */
#define PM_I2C_ANA_INF_RXCLK_BIT        5U
#define PM_I2C_RFPLL_PWR_SLEEP          0x01U
#define PM_I2C_RFPLL_PWR_ACTIVE         0xF1U
#define PM_I2C_RFPLL_EN_RUN             0x80U
#define PM_I2C_BIAS_PWR_REG             0U
#define PM_I2C_BIAS_PWR_MODEM_SLP       0x06U
#define PM_I2C_BIAS_PWR_ACTIVE          0xC6U
#define PM_I2C_SAR_PWR_BIT              0U
#define PM_PBUS_PA_SAR_VDD33_BIAS       2U
#define PM_BB_RX_GAIN_FORCE_LATCH_HI    0x000000F1U
#define PM_BB_RX_GAIN_FORCE_LATCH_LO    0x000000F0U

/* RTC slow-clock calibration & microsecond-to-RTC-tick conversion (Q12 fixed-point) */
#define PM_RTC_CALI_SETTLE_US           10U
#define PM_XTAL_FREQ_40MHZ              40U
#define PM_XTAL_FREQ_26MHZ              26U
#define PM_XTAL_FREQ_24MHZ              24U
#define PM_RTC_CALI_Q12_CNT_SHIFT       4U     /* 2^12 / 256 = 2^4 (256-cycle cali -> Q12 us/tick) */
#define PM_RTC_CALI_OUTLIER_THRESH      511U   /* Reject jumps > 511 Q12 (~0.125 us/tick) */
#define PM_RTC_CALI_EMA_PREV_WT         3U     /* 3/8 weight on prior filtered period */
#define PM_RTC_CALI_EMA_CURR_WT         5U     /* 5/8 weight on new measured period */
#define PM_RTC_CALI_EMA_SHIFT           3U     /* Divide EMA sum by 8 */
#define PM_RTC_Q12_SHIFT                12U
#define PM_RTC_FALLBACK_US_PER_TICK     5U     /* Fallback ~200 kHz (5 us/tick) when uncalibrated */
#define PM_RTC_FALLBACK_US_PER_TICK_64  5ULL
#define PM_RTC_SHIFT_OVERFLOW_LIMIT     0x000FFFFFU /* Max value safe to left-shift by 12 */
#define PM_I2C_BIAS_RC_CAL_REG          8U          /* Bias/RC calibration control sub-reg */
#define PM_I2C_BIAS_RC_CALI_VAL         0U          /* Bias/RC cali trigger reset value */
#define PM_RTC_CALI_CTX_WORDS           2U          /* Caller PM context array length */
#define PM_RTC_CALI_RESULT_IDX          1U          /* Index holding filtered Q12 period */
#define PM_RTC_WAKE_POLL_LIMIT          100000U     /* Bounded RTC wake/reject poll limit */

/* --------------------------------------------------------------------------
 * Exported & Cross-TU Globals (Explicitly Initialized — 0 SHN_COMMON)
 * -------------------------------------------------------------------------- */

uint8_t sleep_wake_bbpll = 0U;
uint8_t software_slp_reject = 0U;
uint8_t hardware_reject = 0U;

uint8_t g_phy_rtc_cali_trig_en = 0U;
uint16_t g_phy_lslp_mem_opt_8266 = 0U;

static uint8_t s_sdio_slp_reject = 0U;
/* Scratch PM context passed to pm_rtc_clock_cali() and cached Q12 RTC period (us * 4096) */
static uint32_t s_rtc_cali_ctx[PM_RTC_CALI_CTX_WORDS] = { 0U, 0U };
static uint32_t s_rtc_cali_q12 = 0U;

/* --------------------------------------------------------------------------
 * IRAM Inline Helpers for Light-Sleep Entry / Exit
 * -------------------------------------------------------------------------- */

/**
 * @brief Check whether the SLC/SDIO host interface is busy and gate Wi-Fi clock if idle.
 *
 * Inline helper invoked solely from `IRAM_ATTR` pm_goto_sleep() while flash cache
 * may be suspended. When the SDIO strapping bit (`PHY_GPIO_STRAP_SDIO_BIT`) is set,
 * performs a double-read debounce of `PHY_SLC_SDIO_STATUS0_REG` and
 * `PHY_SLC_SDIO_STATUS1_REG` to confirm no SDIO transaction starts mid-check before
 * clearing `PHY_DPORT_CLK_WIFI_EN`.
 *
 * @return  `0` if SDIO is not strapped or confirmed idle (safe to sleep);
 *          `1` if an SDIO transaction is active (caller must reject sleep).
 */
static inline uint8_t pm_sdio_nidle(void)
{
    uint32_t clk_en = PHY_REG_READ(PHY_DPORT_CLK_EN_REG);
    uint32_t strap = PHY_REG_READ(PHY_GPIO_STRAP_REG);

    if ((strap & PHY_GPIO_STRAP_SDIO_BIT) == 0U) {
        return 0U;
    }

    /*
     * Double-read debounce: verify STATUS1 == IDLE, then read STATUS0[29:18] twice
     * and confirm STATUS1 has not changed in between, catching host-initiated SDIO
     * transfers racing against sleep entry.
     */
    uint32_t status1 = PHY_REG_READ(PHY_SLC_SDIO_STATUS1_REG);
    if (status1 != PHY_SLC_SDIO_IDLE_ST1) {
        return 1U;
    }

    uint32_t status0 = PHY_REG_READ(PHY_SLC_SDIO_STATUS0_REG);
    if (((status0 >> PHY_SLC_SDIO_IDLE_ST0_SHIFT) & PHY_SLC_SDIO_IDLE_ST0_MASK) !=
        PHY_SLC_SDIO_IDLE_ST0_VAL) {
        return 1U;
    }

    status0 = PHY_REG_READ(PHY_SLC_SDIO_STATUS0_REG);
    if (((status0 >> PHY_SLC_SDIO_IDLE_ST0_SHIFT) & PHY_SLC_SDIO_IDLE_ST0_MASK) !=
        PHY_SLC_SDIO_IDLE_ST0_VAL) {
        return 1U;
    }

    if (PHY_REG_READ(PHY_SLC_SDIO_STATUS1_REG) != status1) {
        return 1U;
    }

    PHY_REG_WRITE(PHY_DPORT_CLK_EN_REG, clk_en & ~PHY_DPORT_CLK_WIFI_EN);
    return 0U;
}

/**
 * @brief Busy-wait for @p us microseconds using the Xtensa `CCOUNT` cycle counter.
 *
 * Inline IRAM-safe delay used by pm_goto_sleep() immediately after light-sleep wakeup,
 * avoiding ROM/flash delay helpers while memory retention / clocks are still settling.
 * Scales `ticks_per_us` dynamically from `PHY_DPORT_CTL_DOUBLE_CLK` (160 MHz vs 80 MHz).
 *
 * @param us  Delay duration in microseconds.
 */
static inline void pm_iram_delay_us(uint32_t us)
{
    uint32_t ticks_per_us =
        ((PHY_REG_READ(PHY_DPORT_CTL_REG) & PHY_DPORT_CTL_DOUBLE_CLK) != 0U)
            ? PM_CPU_FREQ_160MHZ
            : PM_CPU_FREQ_80MHZ;
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

/**
 * @brief Gate or ungate the hardware watchdog peripheral clock in DPORT.
 *
 * Placed in `IRAM_ATTR` so sleep/wake critical sections can toggle the WDT clock
 * without touching SPI flash cache.
 *
 * @param disable  `0` to enable the WDT clock (`PHY_DPORT_CLK_WDT_EN`),
 *                 non-zero to gate it off.
 */
void IRAM_ATTR clockgate_watchdog(uint8_t disable)
{
    if (disable == 0U) {
        PHY_REG_SET(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WDT_EN);
    } else {
        PHY_REG_CLR(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WDT_EN);
    }
}

/**
 * @brief Execute hardware light-sleep entry and wait in IRAM until RTC wakeup or reject.
 *
 * Placed in `IRAM_ATTR` because the CPU and flash cache suspend during light sleep.
 * Rejects sleep in software if @p mode is not a light-sleep mode, if SDIO is busy,
 * or if periodic RF calibration is pending on a long sleep (`g_phy_periodic_cal_flag`
 * & `g_phy_periodic_cal_sat`). On rev-1+ silicon (`EFUSE_DATA2[15] == 1`), applies
 * DPORT light-sleep SRAM retention (`g_phy_lslp_mem_opt_8266`) across the sleep
 * window, waits 10 us via `CCOUNT` after wakeup, and clears the retention bits before
 * recording `hardware_reject`.
 *
 * @param mode  Requested PM sleep mode (`PHY_PM_MODE_LIGHT_BB_OFF` = 1 or
 *              `PHY_PM_MODE_LIGHT_BB_ON` = 2; all other modes return `1`).
 * @return      `0` if hardware sleep was triggered (check `hardware_reject` for HW
 *              rejection), or `1` if rejected in software before triggering RTC sleep.
 */
uint32_t IRAM_ATTR pm_goto_sleep(uint32_t mode)
{
    uint32_t efuse2 = PHY_REG_READ(PHY_EFUSE_DATA2_REG);

    if ((mode != PHY_PM_MODE_LIGHT_BB_OFF) && (mode != PHY_PM_MODE_LIGHT_BB_ON)) {
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
    uint32_t lslp_en = (efuse2 >> PM_EFUSE_LSLP_EN_SHIFT) & 1U;

    PHY_REG_WRITE(PHY_RTC_INT_CLR_REG, PM_RTC_INT_CLR_ALL);

    /*
     * Unpack 12-bit light-sleep memory-retention mask across DPORT LSLP_MEM0/MEM1
     * ([3:0] -> MEM0[19:16], [5:4] -> MEM0[13:12], [11:6] -> MEM1[5:0]) when eFuse
     * bit 15 indicates silicon supporting LSLP SRAM retention.
     */
    if (lslp_en == 1U) {
        PHY_REG_RMW(PHY_DPORT_LSLP_MEM0_REG, PHY_DPORT_LSLP_MEM0_LO_MASK,
                    ((uint32_t)(mem_opt & PM_LSLP_MEM0_LO_VAL_MASK)
                     << PHY_DPORT_LSLP_MEM0_LO_SHIFT));
        PHY_REG_RMW(PHY_DPORT_LSLP_MEM0_REG, PHY_DPORT_LSLP_MEM0_MID_MASK,
                    ((uint32_t)((mem_opt >> PM_LSLP_MEM0_MID_SHIFT_SRC) &
                                PM_LSLP_MEM0_MID_VAL_MASK)
                     << PHY_DPORT_LSLP_MEM0_MID_SHIFT));
        PHY_REG_RMW(PHY_DPORT_LSLP_MEM1_REG, PHY_DPORT_LSLP_MEM1_HI_MASK,
                    ((uint32_t)((mem_opt >> PM_LSLP_MEM1_HI_SHIFT_SRC) &
                                PM_LSLP_MEM1_HI_VAL_MASK)));
    }

    /* Switch BBPLL to sleep-entry mode, strobe RTC sleep start, and spin until wake/reject. */
    PHY_REG_RMW(PHY_BBPLL_CTRL_REG, PHY_BBPLL_MODE_MASK, PHY_BBPLL_MODE_CAL);
    PHY_REG_SET(PHY_RTC_STATE0_REG, PHY_RTC_SLP_START_BIT);

    while ((PHY_REG_READ(PHY_RTC_INT_RAW_REG) & PHY_RTC_INT_WAKE_OR_REJECT) == 0U) {
    }

    /* Allow SRAM rails and XTAL/PLL clocks to stabilize using an IRAM-only CCOUNT delay. */
    pm_iram_delay_us(PM_WAKE_SETTLE_US);

    if (lslp_en == 1U) {
        PHY_REG_CLR(PHY_DPORT_LSLP_MEM0_REG, PHY_DPORT_LSLP_MEM0_LO_MASK);
        PHY_REG_CLR(PHY_DPORT_LSLP_MEM0_REG, PHY_DPORT_LSLP_MEM0_MID_MASK);
        PHY_REG_CLR(PHY_DPORT_LSLP_MEM1_REG, PHY_DPORT_LSLP_MEM1_HI_MASK);
    }

    hardware_reject = (uint8_t)(PHY_REG_READ(PHY_RTC_INT_RAW_REG) & PHY_RTC_INT_REJECT_BIT);
    return 0U;
}

/* --------------------------------------------------------------------------
 * Internal MAC & BT Coexistence Sleep/Wake Helpers (Flash)
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
/**
 * @brief Park the lower-MAC sleep gates, mask BT coex, and disable MAC TX.
 */
static void pm_sleep_set_mac(void)
{
    PHY_REG_WRITE(PHY_MAC_BTCO_MASK_REG, PM_MAC_BTCO_SLEEP_MASK);
    PHY_REG_RMW(PHY_MAC_SLEEP_CTRL_REG, PHY_MAC_SLEEP_CTRL_F0_MASK, PHY_MAC_SLEEP_CTRL_F0_SLEEP);
    PHY_REG_RMW(PHY_MAC_SLEEP_CTRL_REG, PHY_MAC_SLEEP_CTRL_F1_MASK, PHY_MAC_SLEEP_CTRL_F1_SLEEP);
    PHY_REG_RMW(PHY_MAC_SLEEP_CTRL_REG, PHY_MAC_SLEEP_CTRL_F2_MASK, PHY_MAC_SLEEP_CTRL_F2_SLEEP);
    PHY_REG_RMW(PHY_MAC_SLEEP_CTRL_REG, PHY_MAC_SLEEP_CTRL_F3_MASK, PHY_MAC_SLEEP_CTRL_F3_SLEEP);
    PHY_REG_CLR(PHY_MAC_TX_CTRL_REG, PHY_MAC_TX_ENABLE);
}

/**
 * @brief Wait for the lower-MAC RX and TX finite state machines to go idle.
 *
 * Waits an initial 20 us, then polls `PHY_MAC_RX_STATE_REG` and `PHY_MAC_TX_STATE_REG`
 * every 2 us up to `PM_MAC_IDLE_RETRY_LIMIT` iterations (~10 ms max) before returning.
 */
static void pm_check_mac_idle(void)
{
    uint16_t retry = PM_MAC_IDLE_RETRY_LIMIT;

    os_delay_us(PM_MAC_IDLE_INIT_DELAY_US);
    while (((PHY_REG_READ(PHY_MAC_RX_STATE_REG) & PHY_MAC_RX_STATE_BUSY_MASK) != 0U) ||
           ((PHY_REG_READ(PHY_MAC_TX_STATE_REG) & PHY_MAC_TX_STATE_BUSY_MASK) != 0U)) {
        retry--;
        os_delay_us(PM_MAC_IDLE_POLL_DELAY_US);
        if (retry == 0U) {
            return;
        }
    }
}

/**
 * @brief Park Bluetooth coexistence GPIO pins for sleep when BT coex is enabled.
 *
 * Active only when `chip6_phy_init_ctrl[PHY_CTRL_BTCO_MODE]` is in `{1, 3, 4, 5}`.
 * Muxes MTDO and GPIO0 to GPIO mode and, when `PHY_CTRL_BTCO_SUBMODE >= 2`, drives
 * the coex signaling polarity on GPIO0/GPIO3 to grant the medium to BT during sleep.
 */
static void pm_set_sleep_btco(void)
{
    uint8_t btco_mode = chip6_phy_init_ctrl[PHY_CTRL_BTCO_MODE];

    /* Active BT coexistence modes are 1, 3, 4, and 5; all others leave pins untouched. */
    if ((btco_mode != PM_BTCO_MODE_1) && ((uint8_t)(btco_mode - PM_BTCO_MODE_3) >= 3U)) {
        return;
    }

    PHY_REG_RMW(PHY_IO_MUX_MTDO_REG, PHY_IO_MUX_FUNC_MASK, PM_IO_MUX_FUNC_MTDO_GPIO);
    PHY_REG_CLR(PHY_IO_MUX_GPIO0_REG, PHY_IO_MUX_FUNC_MASK);

    uint8_t btco_sub = chip6_phy_init_ctrl[PHY_CTRL_BTCO_SUBMODE];
    if (btco_sub < PM_BTCO_SUBMODE_STATIC_MAX) {
        return;
    }

    if ((btco_mode == PM_BTCO_MODE_1) || (btco_mode == PM_BTCO_MODE_3)) {
        gpio_output_set(PM_BTCO_GPIO0_BIT, 0U, PM_BTCO_GPIO0_BIT, 0U);
        gpio_output_set(0U, PM_BTCO_GPIO3_BIT, PM_BTCO_GPIO3_BIT, 0U);
    } else if ((btco_mode == PM_BTCO_MODE_4) || (btco_mode == PM_BTCO_MODE_5)) {
        gpio_output_set(0U, PM_BTCO_GPIO0_BIT, PM_BTCO_GPIO0_BIT, 0U);
        gpio_output_set(PM_BTCO_GPIO3_BIT, 0U, PM_BTCO_GPIO3_BIT, 0U);
    }
}

/**
 * @brief Restore the MAC Bluetooth coexistence arbitration mask for @p mode.
 *
 * @param mode  BT coexistence sub-mode index (`0..5`, from `PHY_CTRL_BTCO_SUBMODE`);
 *              values `>= 6` are ignored.
 */
static void pm_unmask_bt(uint8_t mode)
{
    /* Empirical MAC BT coexistence arbitration masks indexed by btco_sub (0..5). */
    static const uint32_t s_btco_masks[PM_BTCO_SUBMODE_COUNT] = {
        0x00000000U,
        0x00003333U,
        0x40001110U,
        0x40001550U,
        0x40003330U,
        0x40003660U,
    };

    if (mode < PM_BTCO_SUBMODE_COUNT) {
        PHY_REG_WRITE(PHY_MAC_BTCO_MASK_REG, s_btco_masks[mode]);
    }
}
#endif

/**
 * @brief Configure RTC sleep registers for a brief baseband-on analog-reset sleep pulse.
 *
 * Used exclusively by sleep_reset_analog_rtcreg_8266() to prepare a short RTC sleep
 * cycle that resets lingering analog RTC state from prior deep sleep or soft reset.
 */
static void sleep_opt_bb_on_8266(void)
{
    uint32_t chip_ver = phy_get_chip_version();

    PHY_REG_WRITE(PHY_RTC_SLP_STATE0_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_SLP_STATE1_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_PLL_CTRL_REG,
                  (chip_ver == PM_CHIP_VER_REV2)
                      ? PHY_RTC_PLL_CTRL_SLEEP_REV2
                      : PHY_RTC_PLL_CTRL_SLEEP_OLD);
    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, 0U);
}

/* --------------------------------------------------------------------------
 * Cross-TU PMU Sleep / Wake Primitives (Flash)
 * -------------------------------------------------------------------------- */

/**
 * @brief Program RTC wakeup source selection and sleep-rejection configuration.
 *
 * @param wakeup_opt   6-bit wakeup source bitmask written to `PHY_RTC_WAKEUP_OPT_REG[5:0]`
 *                     (e.g., `PHY_RTC_WAKEUP_TIMER` = 8 for RTC timer wakeup).
 * @param wakeup_opt2  1-bit sleep-reject control written to `PHY_RTC_SLP_REJECT_CONF_REG[0]`.
 */
void phy_pm_wakeup_opt(uint32_t wakeup_opt, uint32_t wakeup_opt2)
{
    PHY_REG_RMW(PHY_RTC_WAKEUP_OPT_REG, PHY_RTC_WAKEUP_OPT_MASK, wakeup_opt);
    PHY_REG_RMW(PHY_RTC_SLP_REJECT_CONF_REG, PM_RTC_SLP_REJECT_CONF_MASK, wakeup_opt2);
}

/**
 * @brief Program silicon-version-dependent RTC XTAL and PLL wakeup wait durations.
 */
void phy_pm_set_pll_xtal_wait_time(void)
{
    /* Empirical silicon XTAL/PLL wakeup settling counts (longer on pre-rev2 silicon). */
    if (phy_get_chip_version() < PM_CHIP_VER_REV2) {
        PHY_REG_WRITE(PHY_RTC_PLL_XTAL_WAIT_REG, 0x000C8064U);
    } else {
        PHY_REG_WRITE(PHY_RTC_PLL_XTAL_WAIT_REG, 0x00046046U);
    }
}

/**
 * @brief Spin until the RTC hardware asserts wakeup/sleep-reject status or the poll limit expires.
 *
 * Only waits when @p mode is a light-sleep mode and sleep was not rejected in software
 * (`software_slp_reject == 0`), bounding the spin to `PM_RTC_WAKE_POLL_LIMIT` (100,000)
 * iterations. Updates global `hardware_reject` from bit 1 of `PHY_RTC_INT_RAW_REG`.
 *
 * @param mode  Active PM sleep mode (`PHY_PM_MODE_LIGHT_BB_OFF` or `PHY_PM_MODE_LIGHT_BB_ON`).
 */
void phy_pm_wait4wakeup(uint32_t mode)
{
    if (((mode == PHY_PM_MODE_LIGHT_BB_OFF) || (mode == PHY_PM_MODE_LIGHT_BB_ON)) &&
        (software_slp_reject == 0U)) {
        for (uint32_t t = 0U;
             (PHY_REG_READ(PHY_RTC_INT_RAW_REG) & PHY_RTC_INT_WAKE_OR_REJECT) == 0U &&
             t < PM_RTC_WAKE_POLL_LIMIT;
             t++) {
        }
        hardware_reject = (uint8_t)(PHY_REG_READ(PHY_RTC_INT_RAW_REG) & PHY_RTC_INT_REJECT_BIT);
    }
}

#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
/**
 * @brief Power up all RTC RF/analog rails and release the RFPLL sleep-hold latch.
 */
void phy_pm_open_rf(void)
{
    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, PHY_RTC_RF_PWR_ALL_ON);
    PHY_REG_WRITE(PHY_RTC_SLP_STATE1_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_PLL_CTRL_REG, PHY_RTC_PLL_CTRL_OPEN_RF);
    PHY_REG_CLR(PHY_RFPLL_CTRL_REG, PHY_RFPLL_SLP_HOLD);
}
#endif

/**
 * @brief Apply RTC sleep state, RFPLL sleep-hold, and RF analog power-down registers.
 *
 * Applies `PHY_CTRL_EXT_SLEEP_OPT`, programs `PHY_RTC_SLP_STATE0/1` and
 * `PHY_RTC_PLL_CTRL_REG`, briefly enables the ANA_INF RX clock while asserting
 * `PHY_RFPLL_SLP_HOLD_LO` so the hold latches cleanly, powers down RFPLL via RF-I2C,
 * and cuts RTC RF power rails (retaining SAR-ready rail in modem sleep vs full RF off
 * in light sleep).
 *
 * @param slp_state1  Value for `PHY_RTC_SLP_STATE1_REG` (`0` = BB on,
 *                    `PHY_RTC_SLP_STATE1_BB_OFF` = 4 for BB off).
 * @param unused      Unused legacy ABI parameter (ignored).
 * @param pll_ctrl    Base value for `PHY_RTC_PLL_CTRL_REG` (`PHY_RTC_PLL_CTRL_SLEEP_*`).
 * @param mode        Target PM sleep mode (`PHY_PM_MODE_*`).
 */
void phy_pm_sleep_opt(uint32_t slp_state1, uint32_t unused,
                      uint32_t pll_ctrl, uint32_t mode)
{
    uint8_t ext_opt = chip6_phy_init_ctrl[PHY_CTRL_EXT_SLEEP_OPT];
    uint8_t saved_ana_inf;

    (void)unused;

    if (ext_opt == PM_EXT_SLEEP_OPT_CLR) {
        PHY_REG_CLR(PHY_RTC_EXT_SLEEP_OPT_REG, PM_RTC_EXT_SLEEP_OPT_MASK);
    } else if (ext_opt == PM_EXT_SLEEP_OPT_PLL_BIT) {
        pll_ctrl |= PM_RTC_PLL_CTRL_EXT_OPT1_BIT;
    } else if (ext_opt == PM_EXT_SLEEP_OPT_SET) {
        PHY_REG_SET(PHY_RTC_EXT_SLEEP_OPT_REG, PM_RTC_EXT_SLEEP_OPT_MASK);
    }

    PHY_REG_WRITE(PHY_RTC_SLP_STATE0_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_SLP_STATE1_REG, slp_state1);
    PHY_REG_WRITE(PHY_RTC_PLL_CTRL_REG, pll_ctrl);

    /* Temporarily ungate ANA_INF RX clock for 1 us so RFPLL_SLP_HOLD_LO latches reliably. */
    saved_ana_inf = rom_i2c_readReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                    PHY_I2C_ANA_INF_CLK_GATE_REG);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_CLK_GATE_REG,
                          PM_I2C_ANA_INF_RXCLK_BIT, PM_I2C_ANA_INF_RXCLK_BIT, 1U);
    PHY_REG_RMW(PHY_RFPLL_CTRL_REG, PHY_RFPLL_SLP_HOLD, PHY_RFPLL_SLP_HOLD_LO);
    ets_delay_us(1U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_CLK_GATE_REG,
                     saved_ana_inf);

    PHY_REG_RMW(PHY_RF_CAL_MODE_REG, PHY_RF_CAL_MODE_MASK, PHY_RF_CAL_MODE_ACTIVE);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, PHY_I2C_RFPLL_PWR_REG,
                     PM_I2C_RFPLL_PWR_SLEEP);

    if (mode == PHY_PM_MODE_MODEM_SLEEP) {
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, PHY_I2C_SAR_CTRL_REG,
                              PM_I2C_SAR_PWR_BIT, PM_I2C_SAR_PWR_BIT, 0U);
        rom_i2c_writeReg(PHY_I2C_BLOCK_BIAS_PWR, PHY_I2C_HOST_4, PM_I2C_BIAS_PWR_REG,
                         PM_I2C_BIAS_PWR_MODEM_SLP);
        PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, PHY_RTC_RF_PWR_DEEP_SAR);
    } else {
        PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, PHY_RTC_RF_PWR_RF_OFF);
    }
}

/**
 * @brief Configure RTC sleep options with baseband powered down (`SLP_STATE1 = 4`).
 *
 * Selects `PHY_RTC_PLL_CTRL_SLEEP_REV2` on rev-2 silicon unless 160 MHz BBPLL is
 * forced off (`PHY_CTRL_BBPLL160_OPT == 2`), otherwise `PHY_RTC_PLL_CTRL_SLEEP_OLD`.
 *
 * @param mode  Target PM sleep mode (`PHY_PM_MODE_*`).
 */
void phy_pm_sleep_opt_bb_off(uint32_t mode)
{
    uint32_t pll_ctrl =
        ((phy_get_chip_version() == PM_CHIP_VER_REV2) &&
         (chip6_phy_init_ctrl[PHY_CTRL_BBPLL160_OPT] != PM_BBPLL160_OPT_FORCE_OFF))
            ? PHY_RTC_PLL_CTRL_SLEEP_REV2
            : PHY_RTC_PLL_CTRL_SLEEP_OLD;

    phy_pm_sleep_opt(PHY_RTC_SLP_STATE1_BB_OFF, 0U, pll_ctrl, mode);
}

/**
 * @brief Configure RTC sleep options with baseband powered on (`SLP_STATE1 = 0`).
 *
 * Selects `PHY_RTC_PLL_CTRL_SLEEP_REV2` on rev-2 silicon unless 160 MHz BBPLL is
 * forced off (`PHY_CTRL_BBPLL160_OPT == 2`), otherwise `PHY_RTC_PLL_CTRL_SLEEP_OLD`.
 *
 * @param mode  Target PM sleep mode (`PHY_PM_MODE_*`).
 */
void phy_pm_sleep_opt_bb_on(uint32_t mode)
{
    uint32_t pll_ctrl =
        ((phy_get_chip_version() == PM_CHIP_VER_REV2) &&
         (chip6_phy_init_ctrl[PHY_CTRL_BBPLL160_OPT] != PM_BBPLL160_OPT_FORCE_OFF))
            ? PHY_RTC_PLL_CTRL_SLEEP_REV2
            : PHY_RTC_PLL_CTRL_SLEEP_OLD;

    phy_pm_sleep_opt(0U, 0U, pll_ctrl, mode);
}

/* --------------------------------------------------------------------------
 * Exported PMU Sleep, Wake, RTC Reset & Clock Calibration APIs (Flash)
 * -------------------------------------------------------------------------- */

/**
 * @brief Arm the RTC sleep wakeup comparator for @p cycles RTC slow-clock ticks ahead.
 *
 * Also sets `g_phy_periodic_cal_sat` when @p cycles exceeds `PM_PERIODIC_CAL_MIN_CYCLES`
 * (5000 ticks), allowing a pending periodic RF calibration to veto a long light sleep.
 *
 * @param cycles  Sleep duration in RTC slow-clock ticks added to `PHY_RTC_SLP_CNT_VAL_REG`.
 */
void pm_set_sleep_cycles(uint32_t cycles)
{
    PHY_REG_WRITE(PHY_RTC_SLP_VAL_REG, PHY_REG_READ(PHY_RTC_SLP_CNT_VAL_REG) + cycles);
#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
    g_phy_periodic_cal_sat = (cycles > PM_PERIODIC_CAL_MIN_CYCLES) ? 1U : 0U;
#endif
}

/**
 * @brief Prepare baseband, RF, MAC, BT coex, and DPORT clocks for sleep or RF pause.
 *
 * Updates noise floor tracking, gates baseband RX, applies RTC sleep options for
 * light/modem sleep modes (skipped for `PHY_PM_MODE_MODEM_PAUSE`), parks the MAC and
 * waits for TX/RX idle, biases PA PBUS ch 6 for ADC VDD33 measurement during modem
 * sleep when `PHY_CTRL_VDD33_CONST == 0xFF`, and gates Wi-Fi sub-block clocks.
 *
 * @param mode  Target PM mode:
 *              - `PHY_PM_MODE_LIGHT_BB_OFF` (1): light sleep, baseband off
 *              - `PHY_PM_MODE_LIGHT_BB_ON` (2): light sleep, baseband retained
 *              - `PHY_PM_MODE_MODEM_PAUSE` (4): transient RF/MAC pause (clocks stay on)
 *              - `PHY_PM_MODE_MODEM_SLEEP` (8): modem sleep (RF off, CPU active)
 */
void pm_set_sleep_mode(uint32_t mode)
{
    sleep_wake_bbpll = 1U;
#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
    noise_check_loop(1U, 0U);
    PHY_REG_SET(PHY_BB_SLEEP_REG, PHY_BB_SLEEP_RX);
#endif
    phy_pm_set_pll_xtal_wait_time();

    if (mode != PHY_PM_MODE_MODEM_PAUSE) {
        g_phy_sleep_mode_flag = 1U;
        if (mode == PHY_PM_MODE_LIGHT_BB_OFF) {
            phy_pm_sleep_opt_bb_off(PHY_PM_MODE_LIGHT_BB_OFF);
        } else if ((mode == PHY_PM_MODE_LIGHT_BB_ON) || (mode == PHY_PM_MODE_MODEM_SLEEP)) {
            phy_pm_sleep_opt_bb_on(mode);
        }
    }

#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
    PHY_REG_RMW(PHY_MAC_CTRL_REG, PHY_MAC_CTRL_SLEEP_CLR_MASK, PHY_MAC_CTRL_SLEEP_SET_VAL);
    PHY_REG_CLR(PHY_MAC_CTRL_REG, PHY_MAC_CTRL_WAKE_HOLD_BIT);
    PHY_REG_SET(PHY_MAC_CTRL_REG, PHY_MAC_CTRL_EN_BIT);
    PHY_REG_RMW(PHY_MAC_SLEEP_CTRL_REG, PHY_MAC_SLEEP_CTRL_F0_MASK, PHY_MAC_SLEEP_CTRL_F0_SLEEP);

    pm_set_sleep_btco();
    pm_sleep_set_mac();
    pm_check_mac_idle();

    if (mode == PHY_PM_MODE_MODEM_SLEEP) {
        if (chip6_phy_init_ctrl[PHY_CTRL_VDD33_CONST] == PHY_VDD33_MODE_MEASURE) {
            PHY_REG_SET(PHY_PBUS_CTRL_REG, PHY_PBUS_DEBUG_MODE);
            phy_pbus_force(PHY_PBUS_CH_PA_EN, PHY_PBUS_WIDTH_1, PM_PBUS_PA_SAR_VDD33_BIAS);
            PHY_REG_CLR(PHY_PBUS_CTRL_REG, PHY_PBUS_DEBUG_MODE);
        }
    } else
#endif
    if ((mode != PHY_PM_MODE_LIGHT_BB_OFF) && (mode != PHY_PM_MODE_LIGHT_BB_ON)) {
        return;
    }

    PHY_REG_CLR(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_GATE_MASK);
}

#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
/**
 * @brief Restore Bluetooth coexistence IO_MUX functions and GPIO levels on wakeup.
 *
 * Active only when `chip6_phy_init_ctrl[PHY_CTRL_BTCO_MODE]` is in `{1, 3, 4, 5}`.
 * Selects static GPIO muxing (`btco_sub < 2`) or hardware BT coex muxing (`btco_sub >= 2`)
 * and drives the configured active-mode polarity on GPIO0 and GPIO3 for static sub-modes.
 */
void pm_set_wakeup_btco(void)
{
    uint8_t btco_mode = chip6_phy_init_ctrl[PHY_CTRL_BTCO_MODE];

    if ((btco_mode != PM_BTCO_MODE_1) && ((uint8_t)(btco_mode - PM_BTCO_MODE_3) >= 3U)) {
        return;
    }

    uint8_t btco_sub = chip6_phy_init_ctrl[PHY_CTRL_BTCO_SUBMODE];
    if (btco_sub < PM_BTCO_SUBMODE_STATIC_MAX) {
        PHY_REG_RMW(PHY_IO_MUX_MTDO_REG, PHY_IO_MUX_FUNC_MASK, PM_IO_MUX_FUNC_MTDO_GPIO);
        PHY_REG_CLR(PHY_IO_MUX_GPIO0_REG, PHY_IO_MUX_FUNC_MASK);
    } else {
        PHY_REG_RMW(PHY_IO_MUX_MTDO_REG, PHY_IO_MUX_FUNC_MASK, PM_IO_MUX_FUNC_BTCO_HW);
        PHY_REG_RMW(PHY_IO_MUX_GPIO0_REG, PHY_IO_MUX_FUNC_MASK, PM_IO_MUX_FUNC_BTCO_HW);
    }

    if ((btco_mode == PM_BTCO_MODE_1) || (btco_mode == PM_BTCO_MODE_3)) {
        if (btco_sub == 1U) {
            gpio_output_set(PM_BTCO_GPIO0_BIT, 0U, PM_BTCO_GPIO0_BIT, 0U);
            gpio_output_set(0U, PM_BTCO_GPIO3_BIT, PM_BTCO_GPIO3_BIT, 0U);
        } else if (btco_sub == 0U) {
            gpio_output_set(0U, PM_BTCO_GPIO0_BIT, PM_BTCO_GPIO0_BIT, 0U);
            gpio_output_set(PM_BTCO_GPIO3_BIT, 0U, PM_BTCO_GPIO3_BIT, 0U);
        }
    } else if ((btco_mode == PM_BTCO_MODE_4) || (btco_mode == PM_BTCO_MODE_5)) {
        if (btco_sub == 1U) {
            gpio_output_set(0U, PM_BTCO_GPIO0_BIT, PM_BTCO_GPIO0_BIT, 0U);
            gpio_output_set(PM_BTCO_GPIO3_BIT, 0U, PM_BTCO_GPIO3_BIT, 0U);
        } else if (btco_sub == 0U) {
            gpio_output_set(PM_BTCO_GPIO0_BIT, 0U, PM_BTCO_GPIO0_BIT, 0U);
            gpio_output_set(0U, PM_BTCO_GPIO3_BIT, PM_BTCO_GPIO3_BIT, 0U);
        }
    }
}

/**
 * @brief Unmask BT coexistence, release lower-MAC sleep gates, and re-enable MAC TX.
 */
void pm_set_wakeup_mac(void)
{
    uint8_t btco_mode = chip6_phy_init_ctrl[PHY_CTRL_BTCO_MODE];

    if ((btco_mode == PM_BTCO_MODE_1) || ((uint8_t)(btco_mode - PM_BTCO_MODE_3) < 3U)) {
        pm_unmask_bt(chip6_phy_init_ctrl[PHY_CTRL_BTCO_SUBMODE]);
    } else {
        PHY_REG_WRITE(PHY_MAC_BTCO_MASK_REG, 0U);
    }

    PHY_REG_CLR(PHY_MAC_SLEEP_CTRL_REG, PHY_MAC_SLEEP_CTRL_F3_MASK);
    PHY_REG_CLR(PHY_MAC_SLEEP_CTRL_REG, PHY_MAC_SLEEP_CTRL_F2_MASK);
    PHY_REG_CLR(PHY_MAC_SLEEP_CTRL_REG, PHY_MAC_SLEEP_CTRL_F1_MASK);
    PHY_REG_CLR(PHY_MAC_SLEEP_CTRL_REG, PHY_MAC_SLEEP_CTRL_F0_MASK);
    PHY_REG_SET(PHY_MAC_TX_CTRL_REG, PHY_MAC_TX_ENABLE);
}

/**
 * @brief Restore BBPLL, clocks, RF front-end, baseband RX, BT coex, and MAC after sleep.
 *
 * Recalibrates 160 MHz BBPLL via change_bbpll160() after a real (non-rejected) light
 * sleep unless @p skip_bbpll is non-zero. Re-enables Wi-Fi clocks, powers up RFPLL,
 * analog bias, SAR, and RF calibration state (`phy_wakeup_rf()`) for light/modem sleep,
 * pulses baseband RX reset and RX gain force latch, refreshes `adc_rand_noise`, restores
 * BT coex and MAC, and clears `g_phy_sleep_mode_flag`.
 *
 * @param mode        PM sleep mode being exited (`PHY_PM_MODE_*`).
 * @param skip_bbpll  Non-zero (low byte) to skip change_bbpll160() and periodic-cal
 *                    flag clearing on wakeup.
 */
void pm_wakeup_init(uint32_t mode, uint32_t skip_bbpll)
{
    uint8_t skip = (uint8_t)(skip_bbpll & 0xFFU);
    bool is_lslp = (mode == PHY_PM_MODE_LIGHT_BB_OFF) || (mode == PHY_PM_MODE_LIGHT_BB_ON);
    bool is_rf_sleep = is_lslp || (mode == PHY_PM_MODE_MODEM_SLEEP);

    if ((skip == 0U) && is_lslp && (sleep_wake_bbpll != 0U) &&
        (software_slp_reject == 0U) && (hardware_reject == 0U)) {
        change_bbpll160();
        sleep_wake_bbpll = 0U;
    }

    PHY_REG_RMW(PHY_BBPLL_CTRL_REG, PHY_BBPLL_MODE_MASK, PHY_BBPLL_MODE_RUN);
    PHY_REG_SET(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_EN);
    if (is_rf_sleep) {
        PHY_REG_SET(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_SUB);
    }

    PHY_REG_WRITE(PHY_MAC_CTRL_REG, PHY_MAC_CTRL_ACTIVE_VAL);
    PHY_REG_CLR(PHY_MAC_SLEEP_CTRL_REG, PHY_MAC_SLEEP_CTRL_F0_MASK);

    if (is_rf_sleep) {
        phy_sleep_set_rxpbus(0U);
        rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, PHY_I2C_RFPLL_PWR_REG,
                         PM_I2C_RFPLL_PWR_ACTIVE);
        rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, PHY_I2C_RFPLL_EN_REG,
                         PM_I2C_RFPLL_EN_RUN);
        phy_pm_open_rf();
        rom_i2c_writeReg(PHY_I2C_BLOCK_BIAS_PWR, PHY_I2C_HOST_4, PM_I2C_BIAS_PWR_REG,
                         PM_I2C_BIAS_PWR_ACTIVE);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, PHY_I2C_SAR_CTRL_REG,
                              PM_I2C_SAR_PWR_BIT, PM_I2C_SAR_PWR_BIT, 1U);

        g_phy_sleep_params.param_flag |= PHY_PARAM_WAKEUP_RF;
        phy_wakeup_rf();
        g_phy_sleep_params.param_flag &= ~PHY_PARAM_WAKEUP_RF;
    }

    PHY_REG_CLR(PHY_BB_SLEEP_REG, PHY_BB_SLEEP_RX);
    PHY_REG_SET(PHY_BB_RX_CTRL_REG, PHY_BB_RX_RESET);
    PHY_REG_CLR(PHY_BB_RX_CTRL_REG, PHY_BB_RX_RESET);

    if ((PHY_REG_READ(PHY_MAC_PHY_CTRL_REG) & PHY_MAC_PHY_RF_UP) != 0U) {
        /* Pulse RX gain force latch (1 -> 0) so baseband reloads post-wake RX gain state. */
        ets_delay_us(2U);
        PHY_REG_RMW(PHY_BB_RX_GAIN_FORCE_REG, PHY_BB_RX_GAIN_FORCE_MASK,
                    PM_BB_RX_GAIN_FORCE_LATCH_HI);
        PHY_REG_RMW(PHY_BB_RX_GAIN_FORCE_REG, PHY_BB_RX_GAIN_FORCE_MASK,
                    PM_BB_RX_GAIN_FORCE_LATCH_LO);
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

/**
 * @brief Reset ESP8266 RTC analog and PMU registers via a short forced timer sleep cycle.
 *
 * Enables `PHY_DPORT_CLK_WIFI_EN` and clears `software_slp_reject`, executes a
 * 1000-tick RTC timer light-sleep pulse with baseband retained to clear latched
 * analog RTC domains, then writes silicon power-on reset defaults across
 * `0x60000700..0x600007B4`.
 */
void sleep_reset_analog_rtcreg_8266(void)
{
    PHY_REG_SET(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_EN);
    software_slp_reject = 0U;
    PHY_REG_WRITE(PHY_RTC_INT_CLR_REG, PM_RTC_INT_CLR_ALL);
    sleep_opt_bb_on_8266();
    phy_pm_wakeup_opt(PHY_RTC_WAKEUP_TIMER, 0U);
    phy_pm_set_pll_xtal_wait_time();
    pm_set_sleep_cycles(PM_RTC_ANALOG_RESET_CYCLES);
    PHY_REG_SET(PHY_RTC_STATE0_REG, PHY_RTC_SLP_START_BIT);
    phy_pm_wait4wakeup(PHY_PM_MODE_LIGHT_BB_ON);

    /* Restore empirical ESP8266 silicon power-on defaults for all RTC PMU/analog registers. */
    PHY_REG_WRITE(PHY_RTC_PLL_CTRL_REG, PHY_RTC_PLL_CTRL_BOOT);
    PHY_REG_WRITE(PHY_RTC_SLP_VAL_REG, 0x00000FFFU);
    PHY_REG_WRITE(PHY_RTC_STATE0_REG, 0U);
    PHY_REG_WRITE(PHY_RTC_PLL_XTAL_WAIT_REG, 0x000640C8U);
    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, PHY_RTC_RF_PWR_INIT_BASE);
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
/**
 * @brief Park RFPLL, gate Wi-Fi sub-block clocks, and power down RF rails for PHY-only mode.
 *
 * Called on boot and light-sleep wakeup when `CONFIG_ESP8266_OSS_PHY_ONLY` is enabled.
 * Keeps `PHY_DPORT_CLK_WIFI_EN` (`BIT(20)`) active for `WDEV_COUNT_REG` / `esp_get_time()`
 * while gating `PHY_DPORT_CLK_WIFI_GATE_MASK` (`0x038F0000`) and holding `g_phy_sleep_mode_flag`
 * at `1U`.
 */
void phy_pm_rf_off_boot(void)
{
    g_phy_sleep_mode_flag = 1U;
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, PHY_I2C_RFPLL_PWR_REG,
                     PM_I2C_RFPLL_PWR_SLEEP);
    PHY_REG_CLR(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_GATE_MASK);
    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, PHY_RTC_RF_PWR_RF_OFF);
}
#endif

/**
 * @brief Measure and EMA-filter the RTC slow-clock period in Q12 microseconds per tick.
 *
 * If not already pre-triggered (`g_phy_rtc_cali_trig_en == 0`), triggers a 256-cycle
 * hardware calibration measurement via a two-step rising edge on `PHY_RTC_CALI_START`.
 * Converts the measured XTAL cycle count into Q12 us/RTC-tick, rejects single-sample
 * outliers deviating by more than `PM_RTC_CALI_OUTLIER_THRESH` (511 Q12 units), and
 * blends valid readings into `pm_ctx[1]` using a 5/8-new + 3/8-previous EMA filter.
 *
 * @param pm_ctx  Pointer to the caller's PM context array; `pm_ctx[1]` holds the
 *                persistent Q12 RTC period estimate (updated in place when valid).
 */
void pm_rtc_clock_cali(uint32_t *pm_ctx)
{
    /*
     * Two-step rising-edge trigger: first arm the 256-RTC-cycle measurement window
     * with START=0, then assert BIT(31) (PHY_RTC_CALI_START) to begin counting.
     */
    if (g_phy_rtc_cali_trig_en == 0U) {
        PHY_REG_WRITE(PHY_RTC_CALI_CTRL_REG, PHY_RTC_CALI_CYCLES_256_EN);
        PHY_REG_SET(PHY_RTC_CALI_CTRL_REG, PHY_RTC_CALI_START);
    }

    /* Bit 31 (PHY_RTC_CALI_RDY) goes high (negative signed int32) when count is ready. */
    ets_delay_us(PM_RTC_CALI_SETTLE_US);
    while ((int32_t)PHY_REG_READ(PHY_RTC_CALI_DATA_REG) >= 0) {
    }

    uint32_t cnt = PHY_REG_READ(PHY_RTC_CALI_DATA_REG) & PHY_RTC_CALI_CNT_MASK;
    g_phy_rtc_cali_trig_en = 0U;

    /*
     * Convert XTAL cycles per 256 RTC ticks into Q12 microseconds per RTC tick:
     *   T_rtc_us * 2^12 = (cnt / 256 / xtal_mhz) * 2^12 = (cnt << 4) / xtal_mhz.
     */
    uint32_t xtal_mhz = (chip6_phy_init_ctrl[PHY_CTRL_XTAL_FREQ] == PHY_XTAL_26MHZ)
                            ? PM_XTAL_FREQ_26MHZ
                            : ((chip6_phy_init_ctrl[PHY_CTRL_XTAL_FREQ] == PHY_XTAL_24MHZ)
                                   ? PM_XTAL_FREQ_24MHZ
                                   : PM_XTAL_FREQ_40MHZ);
    uint32_t cali_q12 = (cnt << PM_RTC_CALI_Q12_CNT_SHIFT) / xtal_mhz;

    if (cali_q12 != 0U) {
        uint32_t prev = pm_ctx[1];
        if (prev != 0U) {
            /* Discard transient spikes (> 511 Q12 ≈ 0.125 us/tick); otherwise apply 5/8-3/8 EMA. */
            uint32_t diff = (prev >= cali_q12) ? (prev - cali_q12) : (cali_q12 - prev);
            if (diff > PM_RTC_CALI_OUTLIER_THRESH) {
                return;
            }
            cali_q12 = ((prev * PM_RTC_CALI_EMA_PREV_WT) +
                        (cali_q12 * PM_RTC_CALI_EMA_CURR_WT)) >> PM_RTC_CALI_EMA_SHIFT;
        }
        pm_ctx[1] = cali_q12;
    }
}

/**
 * @brief Run one hardware RTC slow-clock calibration cycle and cache the Q12 period.
 *
 * Resets the scratch calibration slot, triggers bias-RC measurement over ROM-I2C,
 * calls pm_rtc_clock_cali(), and caches the resulting Q12 microseconds/tick value in
 * `s_rtc_cali_q12`.
 *
 * @return  Calibrated RTC slow-clock period in Q12 microseconds per tick.
 */
uint32_t pm_rtc_clock_cali_proc(void)
{
    s_rtc_cali_ctx[PM_RTC_CALI_RESULT_IDX] = 0U;
    rom_i2c_writeReg(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2,
                     PM_I2C_BIAS_RC_CAL_REG, PM_I2C_BIAS_RC_CALI_VAL);
    pm_rtc_clock_cali(s_rtc_cali_ctx);
    s_rtc_cali_q12 = s_rtc_cali_ctx[PM_RTC_CALI_RESULT_IDX];
    return s_rtc_cali_q12;
}

/**
 * @brief Convert a 32-bit microsecond interval into RTC slow-clock ticks.
 *
 * @param usec      Duration in microseconds.
 * @param cali_q12  Calibrated RTC period in Q12 microseconds/tick (`T_rtc_us * 4096`),
 *                  or `0` to fall back to a nominal 5 us/tick (~200 kHz) divisor.
 * @return          Equivalent duration in 32-bit RTC slow-clock ticks.
 */
uint32_t pm_usec2rtc(uint32_t usec, uint32_t cali_q12)
{
    if (cali_q12 == 0U) {
        return usec / PM_RTC_FALLBACK_US_PER_TICK;
    }
    /*
     * Avoid 32-bit overflow in (usec << 12): when usec exceeds 20 bits (> 0xFFFFF),
     * divide first and shift left by 12; otherwise shift first for full precision.
     */
    if (usec > PM_RTC_SHIFT_OVERFLOW_LIMIT) {
        return (usec / cali_q12) << PM_RTC_Q12_SHIFT;
    }
    return (usec << PM_RTC_Q12_SHIFT) / cali_q12;
}

/**
 * @brief Convert a 64-bit microsecond interval into 64-bit RTC slow-clock ticks.
 *
 * @param usec      Duration in microseconds (64-bit).
 * @param cali_q12  Calibrated RTC period in Q12 microseconds/tick (`T_rtc_us * 4096`),
 *                  or `0` to fall back to a nominal 5 us/tick (~200 kHz) divisor.
 * @return          Equivalent duration in 64-bit RTC slow-clock ticks.
 */
uint64_t pm_usec2rtc_64(uint64_t usec, uint32_t cali_q12)
{
    if (cali_q12 == 0U) {
        return usec / PM_RTC_FALLBACK_US_PER_TICK_64;
    }
    /*
     * Avoid 64-bit overflow in (usec << 12): when the upper 32 bits exceed 20 bits
     * (i.e. usec >= 2^52), divide first and shift left by 12.
     */
    if ((uint32_t)(usec >> 32) > PM_RTC_SHIFT_OVERFLOW_LIMIT) {
        return (usec / (uint64_t)cali_q12) << PM_RTC_Q12_SHIFT;
    }
    return (usec << PM_RTC_Q12_SHIFT) / (uint64_t)cali_q12;
}

/**
 * @brief Convert a 64-bit microsecond duration into RTC slow-clock ticks using the cached Q12 period.
 *
 * @param usec  Sleep/timer duration in microseconds.
 * @return      Equivalent number of RTC slow-clock ticks based on `s_rtc_cali_q12`.
 */
uint64_t pm_get_sleep_cycles_64(uint64_t usec)
{
    return pm_usec2rtc_64(usec, s_rtc_cali_q12);
}
