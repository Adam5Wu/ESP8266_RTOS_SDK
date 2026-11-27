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

#define ESP8266_PHY_DEFAULT_REG         0x60009D74U
#define ESP8266_PHY_DEFAULT_TYPE2       0xE690A568U /* Analog default for eFuse rev A */
#define ESP8266_PHY_DEFAULT_TYPE1       0xEAB4D027U /* Standard ESP8266 analog default */
#define ESP8266_EFUSE2_ANA_REV_SHIFT    12U
#define ESP8266_EFUSE2_ANA_REV_MASK     0x0AU
#define ESP8266_RTC_CTL_REG             (REG_RTC_BASE + 0x08U)
#define ESP8266_RTC_CTL_RST_LATCH_BIT   BIT(21)     /* Cleared after latching reset reason */
#define ESP8266_RTC_REASON_MASK         0x0FU
#define ESP8266_RTC_WAKEUP_CAUSE_SHIFT  8U
#define ESP8266_RTC_WAKEUP_CAUSE_MASK   0x3FU
#define ESP8266_RTC_WAKEUP_SDIO         1U
#define ESP8266_RTC_WAKEUP_TIMER        8U

void phy_reg_default(void);
RESET_REASON rtc_get_reset_reason(int cpu_no);

/**
 * @brief Write silicon-revision-specific analog defaults to baseband register 0x60009D74.
 *
 * Called early by the 2nd-stage bootloader before full PHY initialization.
 */
void phy_reg_default(void)
{
    uint32_t efuse2 = REG_READ(EFUSE_DATA2_REG);

    if (((efuse2 >> ESP8266_EFUSE2_ANA_REV_SHIFT) & ESP8266_EFUSE2_ANA_REV_MASK) ==
        ESP8266_EFUSE2_ANA_REV_MASK) {
        REG_WRITE(ESP8266_PHY_DEFAULT_REG, ESP8266_PHY_DEFAULT_TYPE2);
    } else {
        REG_WRITE(ESP8266_PHY_DEFAULT_REG, ESP8266_PHY_DEFAULT_TYPE1);
    }
}

/**
 * @brief Decode and acknowledge the hardware SoC reset reason from RTC state registers.
 *
 * For DEEPSLEEP_RESET, disambiguates SDIO wakeup (cause 1 -> SDIO_RESET) vs RTC timer
 * wakeup (cause 8 -> DEEPSLEEP_RESET) vs invalid/unrecognized causes (NO_MEAN), then
 * clears RTC_CTL bit 21.
 *
 * @param cpu_no  CPU core index (unused on single-core ESP8266).
 * @return        Decoded ROM RESET_REASON enum value.
 */
RESET_REASON rtc_get_reset_reason(int cpu_no)
{
    (void)cpu_no;
    uint32_t reason = REG_READ(RTC_STATE1) & ESP8266_RTC_REASON_MASK;

    if (reason == DEEPSLEEP_RESET) {
        uint32_t wakeup = (REG_READ(RTC_STATE2) >> ESP8266_RTC_WAKEUP_CAUSE_SHIFT) &
                          ESP8266_RTC_WAKEUP_CAUSE_MASK;
        if (wakeup == ESP8266_RTC_WAKEUP_SDIO) {
            reason = SDIO_RESET;
        } else {
            wakeup = (REG_READ(RTC_STATE2) >> ESP8266_RTC_WAKEUP_CAUSE_SHIFT) &
                     ESP8266_RTC_WAKEUP_CAUSE_MASK;
            if (wakeup != ESP8266_RTC_WAKEUP_TIMER) {
                reason = NO_MEAN;
            }
        }
    }

    CLEAR_PERI_REG_MASK(ESP8266_RTC_CTL_REG, ESP8266_RTC_CTL_RST_LATCH_BIT);
    return (RESET_REASON)reason;
}

/**
 * @brief Update a UART controller's baud-rate clock divider and flush its TX/RX FIFOs.
 *
 * @param uart_no   UART peripheral index (0 or 1).
 * @param baud_div  16-bit integer clock divider (`APB_CLK_FREQ / baud_rate`).
 */
void uart_div_modify(uint32_t uart_no, uint32_t baud_div)
{
    uint8_t port = (uint8_t)uart_no;

    WRITE_PERI_REG(UART_CLKDIV(port), baud_div & 0xFFFFU);
    SET_PERI_REG_MASK(UART_CONF0(port), UART_TXFIFO_RST | UART_RXFIFO_RST);
    CLEAR_PERI_REG_MASK(UART_CONF0(port), UART_TXFIFO_RST | UART_RXFIFO_RST);
}

/**
 * @brief Busy-wait for `us` microseconds using the Xtensa CCOUNT cycle counter.
 *
 * Safe to call in both bootloader (derives MHz from XTAL * 2 or * 4 via DPORT_CTL_DOUBLE_CLK)
 * and application runtime (uses `g_esp_ticks_per_us`, 80 or 160).
 *
 * @param us  Delay duration in microseconds (0..65535).
 */
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

/**
 * @brief ROM-compatible microsecond busy-wait wrapper forwarding to os_delay_us().
 *
 * @param us  Delay duration in microseconds (truncated to uint16_t for ABI parity).
 */
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

/**
 * @brief Return the current CPU frequency in MHz (ticks per microsecond, 80 or 160).
 *
 * @return Active CPU clock frequency in MHz.
 */
uint32_t esp_get_cpu_frequency(void)
{
    extern uint32_t g_esp_ticks_per_us;
    return g_esp_ticks_per_us;
}

/**
 * @brief Register the low-level character output sink invoked by os_putc() / ets_printf().
 *
 * @param p  Function pointer accepting one character, or NULL to disable output.
 */
void os_install_putc1(void (*p)(char c))
{
    _putc1 = p;
}

/**
 * @brief Emit one character through the installed `_putc1` callback if non-NULL.
 *
 * @param c  Character byte to output.
 */
void os_putc(char c)
{
    if (_putc1 != NULL) {
        _putc1(c);
    }
}

/**
 * @brief Atomically drive GPIO output levels and output-enable masks via W1TS/W1TC registers.
 *
 * @param set_mask      Bitmask of GPIO pins to drive high.
 * @param clear_mask    Bitmask of GPIO pins to drive low.
 * @param enable_mask   Bitmask of GPIO pins to configure as outputs.
 * @param disable_mask  Bitmask of GPIO pins to disable output drivers (tri-state/input).
 */
void gpio_output_set(uint32_t set_mask, uint32_t clear_mask,
                     uint32_t enable_mask, uint32_t disable_mask)
{
    REG_WRITE(PERIPHS_GPIO_BASEADDR + GPIO_OUT_W1TS_ADDRESS, set_mask);
    REG_WRITE(PERIPHS_GPIO_BASEADDR + GPIO_OUT_W1TC_ADDRESS, clear_mask);
    REG_WRITE(PERIPHS_GPIO_BASEADDR + GPIO_ENABLE_W1TS_ADDRESS, enable_mask);
    REG_WRITE(PERIPHS_GPIO_BASEADDR + GPIO_ENABLE_W1TC_ADDRESS, disable_mask);
}

/**
 * @brief Count the number of set (1) bits in a 32-bit unsigned integer.
 *
 * @param val  32-bit input value.
 * @return     Population count in [0..32].
 */
uint32_t bit_popcount(uint32_t val)
{
    uint32_t count = 0U;

    while (val != 0U) {
        count += val & 1U;
        val >>= 1;
    }
    return count;
}

/**
 * @brief Legacy ROM UART buffer switch stub (no-op in RTOS SDK).
 *
 * @param uart_no  UART peripheral index (ignored).
 */
void uart_buff_switch(uint8_t uart_no)
{
    (void)uart_no;
}

/**
 * @brief Legacy ROM UART init stub (no-op in RTOS SDK; UART is initialized by driver/uart.c).
 *
 * @param uart_no  UART peripheral index (ignored).
 */
void Uart_Init(uint32_t uart_no)
{
    (void)uart_no;
}

#endif /* !BOOTLOADER_BUILD */
