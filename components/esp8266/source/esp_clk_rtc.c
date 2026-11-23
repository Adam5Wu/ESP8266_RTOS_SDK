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
#define ESP8266_WDEV_MAC_CTRL_REG       0x3FF20C14U
#define ESP8266_WDEV_MAC_SLEEP_CTRL_REG 0x3FF20C74U

#define ESP8266_RTC_SLP_REJECT_CONF_REG (REG_RTC_BASE + 0xA8U)

#define ESP8266_I2C_RFPLL_BLOCK         0x62U

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

void rtc_init_clk(uint8_t *init_param)
{
    phy_get_romfunc_addr();
    (void)register_chipv6_phy_init_param(init_param);
    sleep_reset_analog_rtcreg_8266();

    if (chip6_phy_init_ctrl[0] != 0U || (chip6_phy_init_ctrl[76] & 0x01U) != 0U) {
        REG_WRITE(ESP8266_BBPLL_CTRL_REG,
                  (REG_READ(ESP8266_BBPLL_CTRL_REG) & ~0x0CU) | 0x08U);
        change_bbpll160_sleep();
    }
#ifdef CONFIG_ESP8266_OSS_PHY_ONLY
    phy_pm_rf_off_boot();
#endif
}

void rtc_lightsleep_init(void)
{
    pm_set_sleep_mode(2U);
    (void)pm_rtc_clock_cali_proc();
}

void rtc_set_sleep_time(uint32_t sleep_cycles)
{
    pm_set_sleep_cycles(sleep_cycles);
}

void rtc_wakeup_init(void)
{
    if (sleep_wake_bbpll != 0U && software_slp_reject == 0U && hardware_reject == 0U) {
        change_bbpll160();
        sleep_wake_bbpll = 0U;
    }

#ifndef CONFIG_ESP8266_OSS_PHY_ONLY
    REG_WRITE(ESP8266_WDEV_MAC_CTRL_REG, 0x80000FFFU);
    CLEAR_PERI_REG_MASK(ESP8266_WDEV_MAC_SLEEP_CTRL_REG, 0x00C00000U);
    pm_set_wakeup_btco();
    pm_set_wakeup_mac();
    g_phyFuns->rom_i2c_writeReg(ESP8266_I2C_RFPLL_BLOCK, 1U, 3U, 1U);
#else
    phy_pm_rf_off_boot();
#endif
}

void phy_open_rf(void)
{
#ifndef CONFIG_ESP8266_OSS_PHY_ONLY
    pm_wakeup_init(8U, 0U);
#endif
}

uint32_t rtc_light_sleep_start(uint32_t wakeup_opt, uint32_t reject_opt)
{
    REG_WRITE(RTC_STATE2, (REG_READ(RTC_STATE2) & ~0x3FU) | (wakeup_opt & 0x3FU));
    REG_WRITE(ESP8266_RTC_SLP_REJECT_CONF_REG,
              (REG_READ(ESP8266_RTC_SLP_REJECT_CONF_REG) & ~0x01U) | (reject_opt & 0x01U));

    return pm_goto_sleep(2U);
}
