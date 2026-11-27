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

#include <stddef.h>
#include <stdint.h>

#include "sdkconfig.h"
#include "driver/rtc.h"
#include "esp8266/eagle_soc.h"
#include "esp8266/rtc_register.h"
#include "esp8266/rom_functions.h"
#include "rom/ets_sys.h"

#define ESP8266_BBPLL_CTRL_REG          0x60000D40U
#define ESP8266_BBPLL_MODE_MASK         0x0CU       /* [3:2]: BBPLL operating mode */
#define ESP8266_BBPLL_MODE_CAL          0x08U       /* Calibration / sleep-entry mode */

#define ESP8266_WDEV_MAC_CTRL_REG       0x3FF20C14U
#define ESP8266_WDEV_MAC_CTRL_ACTIVE    0x80000FFFU /* Active MAC NAV/clock configuration */
#define ESP8266_WDEV_MAC_SLEEP_CTRL_REG 0x3FF20C74U
#define ESP8266_WDEV_MAC_SLEEP_GATE_F0  0x00C00000U /* MAC sleep sub-block gate cleared on wake */

#define ESP8266_RTC_SLP_REJECT_CONF_REG (REG_RTC_BASE + 0xA8U)

#define ESP8266_RTC_WAKEUP_OPT_MASK     0x3FU       /* RTC_STATE2[5:0]: wakeup source mask */
#define ESP8266_RTC_SLP_REJECT_EN_MASK  0x01U

#define ESP8266_I2C_RFPLL_BLOCK         0x62U
#define ESP8266_I2C_RFPLL_HOST          1U
#define ESP8266_I2C_RFPLL_PWR_REG       3U
#define ESP8266_I2C_RFPLL_PWR_SLEEP     1U

#define ESP8266_PHY_CTRL_XTAL_OFF       0U          /* chip6_phy_init_ctrl[0]: 0=40M, 1=26M, 2=24M */
#define ESP8266_PHY_CTRL_FREQOFF_OFF    76U         /* chip6_phy_init_ctrl[0x4C]: freq-offset mode */
#define ESP8266_PM_MODE_LIGHT_BB_ON     2U          /* Light sleep with baseband retained */
#define ESP8266_PM_MODE_MODEM_SLEEP     8U          /* Modem sleep / RF-off wake mode */

typedef struct {
    void *reserved[38];
    void (*rom_i2c_writeReg)(uint8_t block, uint8_t host_id, uint8_t reg_add, uint8_t data);
} esp_phy_funs_t;

_Static_assert(offsetof(esp_phy_funs_t, rom_i2c_writeReg) == 0x98U,
               "esp_phy_funs_t::rom_i2c_writeReg must be at offset 0x98");

extern void phy_get_romfunc_addr(void);
extern int register_chipv6_phy_init_param(const uint8_t *init_param);
extern uint8_t chip6_phy_init_ctrl[80];
extern void sleep_reset_analog_rtcreg_8266(void);
extern void change_bbpll160_sleep(void);
extern void change_bbpll160(void);
extern void pm_set_wakeup_btco(void);
extern void pm_set_wakeup_mac(void);
extern void pm_wakeup_init(uint32_t mode, uint32_t arg);
extern uint32_t pm_goto_sleep(uint32_t mode);
#ifdef CONFIG_ESP8266_OSS_PHY_ONLY
extern void phy_pm_rf_off_boot(void);
#endif

extern uint8_t sleep_wake_bbpll;
extern uint8_t software_slp_reject;
extern uint8_t hardware_reject;
extern const esp_phy_funs_t *g_phyFuns;

/* Prototype for symbol not declared in public driver/rtc.h */
void rtc_set_sleep_time(uint32_t sleep_cycles);

/**
 * @brief Initialize RTC analog registers and lock the 160 MHz BBPLL at early boot.
 *
 * Parses the 128-byte PHY initialization table, resets RTC analog state, switches
 * the BBPLL to 160 MHz (yielding an 80 MHz APB bus) whenever the board uses a non-40 MHz
 * crystal (typically 26 MHz) or frequency-offset compensation is enabled, and under
 * `CONFIG_ESP8266_OSS_PHY_ONLY` parks RF power/clocks via `phy_pm_rf_off_boot()`.
 *
 * @param init_param  Pointer to the 128-byte esp_phy_init_data_t configuration block.
 */
void rtc_init_clk(uint8_t *init_param)
{
    phy_get_romfunc_addr();
    (void)register_chipv6_phy_init_param(init_param);
    sleep_reset_analog_rtcreg_8266();

    if (chip6_phy_init_ctrl[ESP8266_PHY_CTRL_XTAL_OFF] != 0U ||
        (chip6_phy_init_ctrl[ESP8266_PHY_CTRL_FREQOFF_OFF] & 0x01U) != 0U) {
        REG_WRITE(ESP8266_BBPLL_CTRL_REG,
                  (REG_READ(ESP8266_BBPLL_CTRL_REG) & ~ESP8266_BBPLL_MODE_MASK) |
                  ESP8266_BBPLL_MODE_CAL);
        change_bbpll160_sleep();
    }
#ifdef CONFIG_ESP8266_OSS_PHY_ONLY
    phy_pm_rf_off_boot();
#endif
}

/**
 * @brief Prepare the PHY/MAC PMU for light sleep (baseband retained) and calibrate RTC clock.
 */
void rtc_lightsleep_init(void)
{
    pm_set_sleep_mode(ESP8266_PM_MODE_LIGHT_BB_ON);
    (void)pm_rtc_clock_cali_proc();
}

/**
 * @brief Program the RTC wakeup target in slow-clock cycles relative to the current counter.
 *
 * @param sleep_cycles  Number of RTC slow-clock ticks to sleep before wakeup.
 */
void rtc_set_sleep_time(uint32_t sleep_cycles)
{
    pm_set_sleep_cycles(sleep_cycles);
}

/**
 * @brief Restore BBPLL, MAC clock/sleep gates, and BT coexistence state after light-sleep wake.
 *
 * Re-locks 160 MHz BBPLL when needed, keeps the RFPLL parked in sleep power state
 * (`0x62:1:3 = 1`) until Wi-Fi explicitly opens RF, and under `CONFIG_ESP8266_OSS_PHY_ONLY`
 * delegates to `phy_pm_rf_off_boot()`.
 */
void rtc_wakeup_init(void)
{
    if (sleep_wake_bbpll != 0U && software_slp_reject == 0U && hardware_reject == 0U) {
        change_bbpll160();
        sleep_wake_bbpll = 0U;
    }

#ifndef CONFIG_ESP8266_OSS_PHY_ONLY
    REG_WRITE(ESP8266_WDEV_MAC_CTRL_REG, ESP8266_WDEV_MAC_CTRL_ACTIVE);
    CLEAR_PERI_REG_MASK(ESP8266_WDEV_MAC_SLEEP_CTRL_REG, ESP8266_WDEV_MAC_SLEEP_GATE_F0);
    pm_set_wakeup_btco();
    pm_set_wakeup_mac();
    g_phyFuns->rom_i2c_writeReg(ESP8266_I2C_RFPLL_BLOCK, ESP8266_I2C_RFPLL_HOST,
                                ESP8266_I2C_RFPLL_PWR_REG, ESP8266_I2C_RFPLL_PWR_SLEEP);
#else
    phy_pm_rf_off_boot();
#endif
}

/**
 * @brief Power up the 2.4 GHz RF front-end and restore RFPLL/PHY calibration after modem sleep.
 */
void phy_open_rf(void)
{
#ifndef CONFIG_ESP8266_OSS_PHY_ONLY
    pm_wakeup_init(ESP8266_PM_MODE_MODEM_SLEEP, 0U);
#endif
}

/**
 * @brief Configure RTC wakeup/reject sources and enter hardware light sleep (baseband retained).
 *
 * @param wakeup_opt  6-bit wakeup source bitmask written to RTC_STATE2[5:0].
 * @param reject_opt  Bit 0 enables hardware sleep rejection in RTC_SLP_REJECT_CONF_REG.
 * @return            0 if hardware sleep was entered, or 1 if rejected by software/SDIO/cal.
 */
uint32_t rtc_light_sleep_start(uint32_t wakeup_opt, uint32_t reject_opt)
{
    REG_WRITE(RTC_STATE2,
              (REG_READ(RTC_STATE2) & ~ESP8266_RTC_WAKEUP_OPT_MASK) |
              (wakeup_opt & ESP8266_RTC_WAKEUP_OPT_MASK));
    REG_WRITE(ESP8266_RTC_SLP_REJECT_CONF_REG,
              (REG_READ(ESP8266_RTC_SLP_REJECT_CONF_REG) & ~ESP8266_RTC_SLP_REJECT_EN_MASK) |
              (reject_opt & ESP8266_RTC_SLP_REJECT_EN_MASK));

    return pm_goto_sleep(ESP8266_PM_MODE_LIGHT_BB_ON);
}
