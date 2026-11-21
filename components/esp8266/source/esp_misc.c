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
#include "esp8266/eagle_soc.h"
#include "esp8266/efuse_register.h"
#include "esp8266/gpio_register.h"
#include "esp8266/rom_functions.h"
#include "esp8266/rtc_register.h"
#include "esp8266/uart_register.h"
#include "rom/ets_sys.h"
#include "rom/gpio.h"
#include <xtensa/hal.h>

#undef ets_delay_us

#define ESP8266_PHY_DEFAULT_REG     0x60009D74U
#define ESP8266_PHY_DEFAULT_TYPE2   0xE690A568U
#define ESP8266_PHY_DEFAULT_TYPE1   0xEAB4D027U
#define ESP8266_RTC_CTL_REG         (REG_RTC_BASE + 0x08U)

void phy_reg_default(void);
RESET_REASON rtc_get_reset_reason(int cpu_no);

void phy_reg_default(void)
{
    uint32_t efuse2 = REG_READ(EFUSE_DATA2_REG);

    if (((efuse2 >> 12) & 0xAU) == 0xAU) {
        REG_WRITE(ESP8266_PHY_DEFAULT_REG, ESP8266_PHY_DEFAULT_TYPE2);
    } else {
        REG_WRITE(ESP8266_PHY_DEFAULT_REG, ESP8266_PHY_DEFAULT_TYPE1);
    }
}

RESET_REASON rtc_get_reset_reason(int cpu_no)
{
    (void)cpu_no;
    uint32_t reason = REG_READ(RTC_STATE1) & 0xFU;

    if (reason == DEEPSLEEP_RESET) {
        uint32_t wakeup = (REG_READ(RTC_STATE2) >> 8) & 0x3FU;
        if (wakeup == 1U) {
            reason = SDIO_RESET;
        } else {
            wakeup = (REG_READ(RTC_STATE2) >> 8) & 0x3FU;
            if (wakeup != 8U) {
                reason = NO_MEAN;
            }
        }
    }

    CLEAR_PERI_REG_MASK(ESP8266_RTC_CTL_REG, BIT(21));
    return (RESET_REASON)reason;
}

void uart_div_modify(uint32_t uart_no, uint32_t baud_div)
{
    uint8_t port = (uint8_t)uart_no;

    WRITE_PERI_REG(UART_CLKDIV(port), baud_div & 0xFFFFU);
    SET_PERI_REG_MASK(UART_CONF0(port), UART_TXFIFO_RST | UART_RXFIFO_RST);
    CLEAR_PERI_REG_MASK(UART_CONF0(port), UART_TXFIFO_RST | UART_RXFIFO_RST);
}

void os_delay_us(uint16_t us)
{
    uint32_t start = xthal_get_ccount();
#ifdef BOOTLOADER_BUILD
    uint32_t ticks_per_us = (REG_READ(DPORT_CTL_REG) & DPORT_CTL_DOUBLE_CLK)
                            ? ((uint32_t)CONFIG_ESP8266_XTAL_FREQ * 4U)
                            : ((uint32_t)CONFIG_ESP8266_XTAL_FREQ * 2U);
#else
    extern uint32_t g_esp_ticks_per_us;
    uint32_t ticks_per_us = g_esp_ticks_per_us;
#endif
    uint32_t ticks = (uint32_t)us * ticks_per_us;

    while ((uint32_t)(xthal_get_ccount() - start) < ticks) {
    }
}

void ets_delay_us(uint32_t us)
{
    os_delay_us((uint16_t)us);
}

#ifndef BOOTLOADER_BUILD

uint32_t esp_get_cpu_frequency(void);
uint32_t bit_popcount(uint32_t val);
void uart_buff_switch(uint8_t uart_no);
void Uart_Init(uint32_t uart_no);

void (*_putc1)(char c) = NULL;

uint32_t esp_get_cpu_frequency(void)
{
    extern uint32_t g_esp_ticks_per_us;
    return g_esp_ticks_per_us;
}

void os_install_putc1(void (*p)(char c))
{
    _putc1 = p;
}

void os_putc(char c)
{
    if (_putc1 != NULL) {
        _putc1(c);
    }
}

void gpio_output_set(uint32_t set_mask, uint32_t clear_mask,
                     uint32_t enable_mask, uint32_t disable_mask)
{
    REG_WRITE(PERIPHS_GPIO_BASEADDR + GPIO_OUT_W1TS_ADDRESS, set_mask);
    REG_WRITE(PERIPHS_GPIO_BASEADDR + GPIO_OUT_W1TC_ADDRESS, clear_mask);
    REG_WRITE(PERIPHS_GPIO_BASEADDR + GPIO_ENABLE_W1TS_ADDRESS, enable_mask);
    REG_WRITE(PERIPHS_GPIO_BASEADDR + GPIO_ENABLE_W1TC_ADDRESS, disable_mask);
}

uint32_t bit_popcount(uint32_t val)
{
    uint32_t count = 0U;

    while (val != 0U) {
        count += val & 1U;
        val >>= 1;
    }
    return count;
}

void uart_buff_switch(uint8_t uart_no)
{
    (void)uart_no;
}

void Uart_Init(uint32_t uart_no)
{
    (void)uart_no;
}

#endif /* !BOOTLOADER_BUILD */
