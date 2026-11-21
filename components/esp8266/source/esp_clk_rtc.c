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
// Portions of the standalone non-Wi-Fi (CONFIG_ESP8266_NO_WIFI) RTC analog reset and BBPLL
// hardware initialization sequences are adapted from teatime-os:
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

#include <stddef.h>
#include <stdint.h>

#include "sdkconfig.h"
#include "driver/rtc.h"
#include "esp8266/eagle_soc.h"
#include "esp8266/rtc_register.h"
#include "esp8266/rom_functions.h"
#include "rom/ets_sys.h"

#define ESP8266_DPORT_CLK_EN_REG        (PERIPHS_DPORT_BASEADDR + 0x18U)
#define ESP8266_DPORT_WIFI_CLK_EN       BIT(20)

#define ESP8266_BBPLL_CTRL_REG          0x60000D40U
#define ESP8266_WDEV_MAC_CTRL_REG       0x3FF20C14U
#define ESP8266_WDEV_MAC_SLEEP_CTRL_REG 0x3FF20C74U

#define ESP8266_RTC_STATE0_REG          (REG_RTC_BASE + 0x08U)
#define ESP8266_RTC_PWR_REG             (REG_RTC_BASE + 0x0CU)
#define ESP8266_RTC_INT_ENA_REG         (REG_RTC_BASE + 0x20U)
#define ESP8266_RTC_INT_CLR_REG         (REG_RTC_BASE + 0x24U)
#define ESP8266_RTC_INT_RAW_REG         (REG_RTC_BASE + 0x28U)
#define ESP8266_RTC_TIMING0_REG         (REG_RTC_BASE + 0x48U)
#define ESP8266_RTC_TIMING1_REG         (REG_RTC_BASE + 0x4CU)
#define ESP8266_RTC_ANALOG1_REG         (REG_RTC_BASE + 0x58U)
#define ESP8266_RTC_ANALOG2_REG         (REG_RTC_BASE + 0x5CU)
#define ESP8266_RTC_ANALOG3_REG         (REG_RTC_BASE + 0x60U)
#define ESP8266_RTC_ANALOG6_REG         (REG_RTC_BASE + 0x80U)
#define ESP8266_RTC_CLK1_REG            (REG_RTC_BASE + 0x94U)
#define ESP8266_RTC_CLK2_REG            (REG_RTC_BASE + 0x98U)
#define ESP8266_RTC_CLK3_REG            (REG_RTC_BASE + 0x9CU)
#define ESP8266_RTC_SLP_REJECT_CONF_REG (REG_RTC_BASE + 0xA8U)
#define ESP8266_RTC_TRIM0_REG           (REG_RTC_BASE + 0xACU)
#define ESP8266_RTC_TRIM1_REG           (REG_RTC_BASE + 0xB0U)
#define ESP8266_RTC_TRIM2_REG           (REG_RTC_BASE + 0xB4U)

#define ESP8266_I2C_RFPLL_BLOCK         0x62U
#define ESP8266_I2C_BBPLL_BLOCK         0x67U

#ifndef CONFIG_ESP8266_NO_WIFI
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

extern uint8_t sleep_wake_bbpll;
extern uint8_t software_slp_reject;
extern uint8_t hardware_reject;
extern const esp_phy_funs_t *g_phyFuns;
#else
void sleep_reset_analog_rtcreg_8266(void);

void sleep_reset_analog_rtcreg_8266(void)
{
    /* Clean-room RTC analog reset sequence (leaves RTC user RAM 0x60001200+ intact) */
    SET_PERI_REG_MASK(ESP8266_DPORT_CLK_EN_REG, ESP8266_DPORT_WIFI_CLK_EN);

    REG_WRITE(ESP8266_RTC_INT_CLR_REG, 0xFFFFFFFFU);
    REG_WRITE(RTC_STATE2, (REG_READ(RTC_STATE2) & ~0x3FU) | 8U);
    CLEAR_PERI_REG_MASK(ESP8266_RTC_SLP_REJECT_CONF_REG, 0x01U);

    REG_WRITE(ESP8266_RTC_PWR_REG, 0x00046046U);
    REG_WRITE(RTC_SLP_VAL, REG_READ(RTC_SLP_CNT_VAL) + 1000U);

    SET_PERI_REG_MASK(ESP8266_RTC_STATE0_REG, BIT(20));
    for (uint32_t t = 0U; (REG_READ(ESP8266_RTC_INT_RAW_REG) & 0x03U) == 0U && t < 100000U; t++) {
    }

    REG_WRITE(ESP8266_RTC_TIMING0_REG, 0x20302020U);
    REG_WRITE(ESP8266_RTC_TIMING1_REG, 0x20500000U);

    REG_WRITE(ESP8266_RTC_ANALOG1_REG, 0U);
    REG_WRITE(ESP8266_RTC_ANALOG2_REG, 7U);
    REG_WRITE(ESP8266_RTC_ANALOG3_REG, 7U);

    REG_WRITE(RTC_GPIO_OUT, 0U);
    REG_WRITE(RTC_GPIO_ENABLE, 0U);
    REG_WRITE(ESP8266_RTC_ANALOG6_REG, 0U);
    REG_WRITE(RTC_GPIO_CONF, 0U);
    REG_WRITE(ESP8266_RTC_CLK1_REG, 0U);
    REG_WRITE(ESP8266_RTC_CLK2_REG, 0U);
    REG_WRITE(ESP8266_RTC_CLK3_REG, 0U);
    REG_WRITE(ESP8266_RTC_TRIM0_REG, 0U);
    REG_WRITE(ESP8266_RTC_TRIM1_REG, 0U);
    REG_WRITE(ESP8266_RTC_TRIM2_REG, 0U);

    REG_WRITE(ESP8266_RTC_STATE0_REG, 0U);
    REG_WRITE(ESP8266_RTC_INT_ENA_REG, 0U);
}
#endif /* !CONFIG_ESP8266_NO_WIFI */

/* Prototype for symbol not declared in public driver/rtc.h */
void rtc_set_sleep_time(uint32_t sleep_cycles);

void rtc_init_clk(uint8_t *init_param)
{
#ifndef CONFIG_ESP8266_NO_WIFI
    phy_get_romfunc_addr();
    (void)register_chipv6_phy_init_param(init_param);
    sleep_reset_analog_rtcreg_8266();

    if (chip6_phy_init_ctrl[0] != 0U || (chip6_phy_init_ctrl[76] & 0x01U) != 0U) {
        REG_WRITE(ESP8266_BBPLL_CTRL_REG,
                  (REG_READ(ESP8266_BBPLL_CTRL_REG) & ~0x0CU) | 0x08U);
        change_bbpll160_sleep();
    }
#else
    sleep_reset_analog_rtcreg_8266();

    /* Non-40 MHz XTAL (e.g. 26 MHz): lock 160 MHz BBPLL (80 MHz APB) */
    if (init_param != NULL && init_param[48] != 0U) {
        REG_WRITE(ESP8266_BBPLL_CTRL_REG,
                  (REG_READ(ESP8266_BBPLL_CTRL_REG) & ~0x0CU) | 0x08U);
        rom_i2c_writeReg(ESP8266_I2C_BBPLL_BLOCK, 4U, 1U, 0x88U);
        rom_i2c_writeReg(ESP8266_I2C_BBPLL_BLOCK, 4U, 2U, 0x91U);
        os_delay_us(100U);
        REG_WRITE(ESP8266_BBPLL_CTRL_REG,
                  (REG_READ(ESP8266_BBPLL_CTRL_REG) & ~0x0CU) | 0x04U);
    }
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
#ifndef CONFIG_ESP8266_NO_WIFI
    if (sleep_wake_bbpll != 0U && software_slp_reject == 0U && hardware_reject == 0U) {
        change_bbpll160();
        sleep_wake_bbpll = 0U;
    }

    REG_WRITE(ESP8266_WDEV_MAC_CTRL_REG, 0x80000FFFU);
    CLEAR_PERI_REG_MASK(ESP8266_WDEV_MAC_SLEEP_CTRL_REG, 0x00C00000U);
    pm_set_wakeup_btco();
    pm_set_wakeup_mac();
    g_phyFuns->rom_i2c_writeReg(ESP8266_I2C_RFPLL_BLOCK, 1U, 3U, 1U);
#else
    REG_WRITE(ESP8266_WDEV_MAC_CTRL_REG, 0x80000FFFU);
    CLEAR_PERI_REG_MASK(ESP8266_WDEV_MAC_SLEEP_CTRL_REG, 0x00C00000U);
    rom_i2c_writeReg(ESP8266_I2C_RFPLL_BLOCK, 1U, 3U, 1U);
#endif
}

void phy_open_rf(void)
{
#ifndef CONFIG_ESP8266_NO_WIFI
    pm_wakeup_init(8U, 0U);
#endif
}

uint32_t rtc_light_sleep_start(uint32_t wakeup_opt, uint32_t reject_opt)
{
    REG_WRITE(RTC_STATE2, (REG_READ(RTC_STATE2) & ~0x3FU) | (wakeup_opt & 0x3FU));
    REG_WRITE(ESP8266_RTC_SLP_REJECT_CONF_REG,
              (REG_READ(ESP8266_RTC_SLP_REJECT_CONF_REG) & ~0x01U) | (reject_opt & 0x01U));

#ifndef CONFIG_ESP8266_NO_WIFI
    return pm_goto_sleep(2U);
#else
    return 0U;
#endif
}
