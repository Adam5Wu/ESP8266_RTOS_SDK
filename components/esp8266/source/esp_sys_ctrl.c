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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "sdkconfig.h"
#include "esp_attr.h"
#include "esp_err.h"
#include "esp_sleep.h"
#include "esp_spi_flash.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_private/esp_system_internal.h"
#include "driver/rtc.h"
#include "driver/soc.h"
#include "esp8266/eagle_soc.h"
#include "esp8266/efuse_register.h"
#include "esp8266/pin_mux_register.h"
#include "esp8266/rom_functions.h"
#include "esp8266/rtc_register.h"
#include "esp8266/spi_register.h"
#include "esp8266/uart_register.h"
#include "rom/ets_sys.h"
#include "FreeRTOS.h"
#include "task.h"

const char default_ssid[17] = "ESP_%02X%02X%02X";
uint8_t freq_trace_enable = 0U;
static uint16_t s_cpu_speed_up_nest = 0U;

extern void os_update_cpu_frequency(uint32_t ticks_per_us);

uint16_t system_adc_read(void);
void system_adc_read_fast(uint16_t *adc_addr, uint16_t adc_num, uint8_t adc_clk_div);
uint16_t system_get_vdd33(void);
void __attribute__((noreturn)) __esp_soc_restart(void (*reboot_fn)(void));
void __esp_soc_deep_sleep(void);
void system_deep_sleep_instant(uint32_t sleep_cycles);
uint32_t esp_get_time(void);
void user_uart_wait_tx_fifo_empty(uint32_t uart_no, uint32_t timeout_us);
int flash_data_check(const uint8_t *cal_data);
int rtc_init(void);
esp_err_t mac_init(void);
int base_gpio_init(void);
int wifi_timer_init(void);

uint16_t system_adc_read(void)
{
#ifndef CONFIG_ESP8266_NO_WIFI
    extern uint16_t test_tout(bool flag);
    uint16_t raw = test_tout(false);

    if (raw != 0xFFFFU) {
        uint16_t val = (uint16_t)(((int32_t)raw * 12) / 11);
        if (val > 1024U) {
            val = 1024U;
        }
        return val;
    }
#endif
    return 0xFFFFU;
}

void system_adc_read_fast(uint16_t *adc_addr, uint16_t adc_num, uint8_t adc_clk_div)
{
#ifndef CONFIG_ESP8266_NO_WIFI
    extern void phy_adc_read_fast(uint16_t *adc_addr, uint16_t adc_num, uint8_t adc_clk_div);
    uint16_t i;

    phy_adc_read_fast(adc_addr, adc_num, adc_clk_div);
    for (i = 0U; i < adc_num; i++) {
        uint16_t v = adc_addr[i];
        if (v != 0xFFFFU) {
            v = (uint16_t)(((int32_t)v * 12) / 11);
            if (v > 1024U) {
                v = 1024U;
            }
            adc_addr[i] = v;
        }
    }
#else
    (void)adc_addr;
    (void)adc_num;
    (void)adc_clk_div;
#endif
}

uint16_t system_get_vdd33(void)
{
#ifndef CONFIG_ESP8266_NO_WIFI
    extern uint16_t phy_get_vdd33(void);
    uint16_t raw = phy_get_vdd33();

    if (raw != 0xFFFFU) {
        return (uint16_t)(((int32_t)raw * 12) / 11);
    }
#endif
    return 0xFFFFU;
}

void IRAM_ATTR __attribute__((noreturn)) __esp_soc_restart(void (*reboot_fn)(void))
{
    volatile uint32_t *dport = (volatile uint32_t *)0x3FF00018U;
    volatile uint32_t *ana_rst = (volatile uint32_t *)0x60000D48U;
    uint32_t m = 0x00007700U;
    uint32_t s;

    __asm__("" : "+r"(dport), "+r"(m));
    s = dport[0] | m;
    dport[0] = s;
    __asm__("" : "+r"(s));
    dport[0] = s ^ m;

    s = *ana_rst | 0x02U;
    *ana_rst = s;
    *ana_rst = s ^ 0x02U;

    Cache_Read_Disable();

    dport[3] &= ~0x18U;
    __asm__ volatile (
        "movi a11, 0\n"
        "wsr.intenable a11\n"
        "wsr.dbreakc0 a11\n"
        "isync\n"
        "movi a1, 0x3fffffb0\n"
        "jx %0\n"
        :: "r"(reboot_fn) : "a11"
    );
    __builtin_unreachable();
}

void esp_restart(void)
{
    extern void sleep_reset_analog_rtcreg_8266(void);
#if defined(CONFIG_ESP8266_OSS_WIFI)
    extern void pm_goto_rf_on(void);
    (void)esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(70U));
#elif defined(CONFIG_ESP8266_VENDOR_WIFI)
    extern const uint8_t *g_wifi_nvs;
    extern bool wifi_station_stop(void);
    extern bool wifi_softap_stop(void);
    extern void __wifi_task_delay(uint32_t tick);
    extern uint32_t __wifi_task_ms_to_ticks(uint32_t ms);
    extern void pm_goto_rf_on(void);

    if (g_wifi_nvs != NULL) {
        uint8_t opmode = *g_wifi_nvs;
        if ((opmode & ~2U) == 1U) {
            (void)wifi_station_stop();
        }
        if ((uint8_t)(opmode - 2U) < 2U) {
            (void)wifi_softap_stop();
        }
    }
    __wifi_task_delay(__wifi_task_ms_to_ticks(70U));
#endif

    SET_PERI_REG_MASK(PERIPHS_IO_MUX_MTDI_U, PERIPHS_IO_MUX_PULLUP);

#ifndef CONFIG_ESP8266_NO_WIFI
    {
        extern void pm_goto_rf_on(void);
        pm_goto_rf_on();
    }
#endif
#ifndef CONFIG_ESP8266_NO_WIFI
    {
        extern void clockgate_watchdog(uint8_t en);
        clockgate_watchdog(0U);
    }
#endif

    REG_WRITE(PERIPHS_DPORT_BASEADDR + 0x18U, 0xFFFF00FFU);
    user_uart_wait_tx_fifo_empty(0U, 500000U);
    user_uart_wait_tx_fifo_empty(1U, 500000U);

    vPortETSIntrLock();
    CLEAR_PERI_REG_MASK(HOST_INF_SEL, PERI_IO_UART0_PIN_SWAP);
    esp_reset_reason_set_hint(ESP_RST_SW);

    REG_WRITE(PERIPHS_RTC_BASEADDR + 0x10U, 0xFE000000U);
    sleep_reset_analog_rtcreg_8266();
    rom_i2c_writeReg(0x67U, 4U, 1U, 0x08U);
    rom_i2c_writeReg(0x67U, 4U, 2U, 0x81U);
#ifndef CONFIG_ESP8266_NO_WIFI
    {
        extern void bbpll_cal(uint8_t mode);
        bbpll_cal(1U);
    }
#else
    CLEAR_PERI_REG_MASK(DPORT_CTL_REG, DPORT_CTL_DOUBLE_CLK);
    REG_WRITE(0x60000D40U, (REG_READ(0x60000D40U) & ~0x0CU) | 0x08U);
    os_delay_us(1000U);
    REG_WRITE(0x60000D40U, (REG_READ(0x60000D40U) & ~0x0CU) | 0x04U);
    os_delay_us(1U);
#endif
#ifdef CONFIG_ESP8266_NO_WIFI
    CLEAR_PERI_REG_MASK(EDGE_INT_ENABLE_REG, BIT(0));
    _xt_isr_mask(1U << ETS_WDT_INUM);
    CLEAR_WDT_REG_MASK(WDT_CTL_ADDRESS, WDT_CTL_EN_MASK);
#endif

    soc_set_ccount(0U);
    __esp_soc_restart((void (*)(void))0x40000080U);
    for (;;) {
    }
}

flash_size_map system_get_flash_size_map(void)
{
    uint32_t buf[2] = { 0U, 0U };

    if (spi_flash_read(0U, buf, sizeof(buf)) != ESP_OK) {
        return FLASH_SIZE_4M_MAP_256_256;
    }
    return (flash_size_map)((buf[0] >> 28) & 0x0FU);
}

void IRAM_ATTR __esp_soc_deep_sleep(void)
{
    Cache_Read_Disable();
    REG_WRITE(SPI_CMD(0), SPI_FLASH_DPD);
    while (REG_READ(SPI_CMD(0)) != 0U) {
    }
    REG_WRITE(PERIPHS_RTC_BASEADDR + 0x08U, BIT(20));
}

void system_deep_sleep_instant(uint32_t sleep_cycles)
{
#ifndef CONFIG_ESP8266_NO_WIFI
    extern void deep_sleep_set_option(uint8_t opt);
    deep_sleep_set_option(0U);
#endif

    REG_WRITE(0x3FF20DE0U, 0x00003333U);
    os_delay_us(20U);

    user_uart_wait_tx_fifo_empty(0U, 500000U);
    user_uart_wait_tx_fifo_empty(1U, 500000U);

    /* Stage A: 136-cycle transitional RTC pre-sleep pulse */
    REG_WRITE(PERIPHS_RTC_BASEADDR + 0x00U, 0U);
    CLEAR_PERI_REG_MASK(PERIPHS_RTC_BASEADDR + 0x00U, BIT(14));
    SET_PERI_REG_MASK(PERIPHS_RTC_BASEADDR + 0x00U, BIT(5) | BIT(4));
    REG_WRITE(PERIPHS_RTC_BASEADDR + 0x44U, 4U);
    REG_WRITE(PERIPHS_RTC_BASEADDR + 0x0CU, 0x00010010U);
    REG_WRITE(PERIPHS_RTC_BASEADDR + 0x48U,
              (REG_READ(PERIPHS_RTC_BASEADDR + 0x48U) & 0xFFFF01FFU) | 0x0000FC00U);
    REG_WRITE(PERIPHS_RTC_BASEADDR + 0x48U,
              (REG_READ(PERIPHS_RTC_BASEADDR + 0x48U) & 0xFFFFFE00U) | 0x00000080U);
    REG_WRITE(PERIPHS_RTC_BASEADDR + 0x10U, 0U);
    REG_WRITE(RTC_SLP_VAL, REG_READ(RTC_SLP_CNT_VAL) + 136U);
    REG_WRITE(RTC_STATE2, RTC_TIMER_TRIG_EN);
    REG_WRITE(PERIPHS_RTC_BASEADDR + 0x08U, BIT(20));
    os_delay_us(200U);

    /* Stage B: Configure XPD_DCDC (GPIO16 -> EXT_RSTB) and regulator latches */
    REG_WRITE(PERIPHS_RTC_BASEADDR + 0x9CU, 0x11U);
    REG_WRITE(PAD_XPD_DCDC_CONF, 0x03U);
    REG_WRITE(PERIPHS_RTC_BASEADDR + 0x0CU, 0x000640C8U);
    CLEAR_PERI_REG_MASK(PERIPHS_RTC_BASEADDR + 0x00U, BIT(5) | BIT(4));
    REG_WRITE(PERIPHS_RTC_BASEADDR + 0x9CU, 0x11U);
    REG_WRITE(PAD_XPD_DCDC_CONF, 0x03U);

    /* Stage C: Quiesce WDT and Wi-Fi NMI interrupts */
    CLEAR_PERI_REG_MASK(EDGE_INT_ENABLE_REG, BIT(0));
    _xt_isr_mask(1U << ETS_WDT_INUM);
    do {
        REG_WRITE(NMI_INT_ENABLE_REG, (REG_READ(NMI_INT_ENABLE_REG) & ~0x1FU) | 0x0EU);
    } while ((REG_READ(NMI_INT_ENABLE_REG) & 0x01U) != 0U);

    /* Stage D: Program final sleep duration and enter deep sleep */
    REG_WRITE(PERIPHS_RTC_BASEADDR + 0x40U, 0xFFFFFFFFU);
    REG_WRITE(PERIPHS_RTC_BASEADDR + 0x44U, 0x20U);
#ifndef CONFIG_ESP8266_NO_WIFI
    pm_set_sleep_cycles(sleep_cycles);
#else
    REG_WRITE(RTC_SLP_VAL, REG_READ(RTC_SLP_CNT_VAL) + sleep_cycles);
#endif
    if (sleep_cycles == 0U) {
        REG_WRITE(RTC_STATE2, 0U);
    } else {
        REG_WRITE(RTC_STATE2, RTC_TIMER_TRIG_EN);
    }
    vPortETSIntrLock();
    esp_reset_reason_set_hint(ESP_RST_DEEPSLEEP);
    __esp_soc_deep_sleep();
}

void esp_deep_sleep(uint64_t time_in_us)
{
#ifndef CONFIG_ESP8266_NO_WIFI
    extern uint64_t pm_get_sleep_cycles_64(uint64_t time_in_us);
    uint64_t cycles;

    (void)pm_rtc_clock_cali_proc();
    cycles = pm_get_sleep_cycles_64(time_in_us);
    if (cycles > 0xFFFFFFFFULL) {
        printf("deep sleep time too long\n");
        return;
    }
    if (time_in_us != 0ULL && cycles == 0ULL) {
        cycles = 1ULL;
    }
#ifndef CONFIG_ESP8266_NO_WIFI
    (void)esp_wifi_stop();
#endif
    vTaskDelay(pdMS_TO_TICKS(100U));
    system_deep_sleep_instant((uint32_t)cycles);
#else
    uint64_t cycles = (time_in_us * 15ULL) / 100ULL;

    if (cycles > 0xFFFFFFFFULL) {
        printf("deep sleep time too long\n");
        return;
    }
    if (time_in_us != 0ULL && cycles == 0ULL) {
        cycles = 1ULL;
    }
    vTaskDelay(pdMS_TO_TICKS(100U));
    system_deep_sleep_instant((uint32_t)cycles);
#endif
}

void esp_set_cpu_freq(esp_cpu_freq_t cpu_freq)
{
    unsigned ps = XTOS_SET_INTLEVEL(3);

    if (cpu_freq == ESP_CPU_FREQ_80M) {
        if (s_cpu_speed_up_nest == 0U) {
            ets_printf("CLK:switch SoC Frequency to 80MHz fail");
        } else {
            s_cpu_speed_up_nest--;
            if (s_cpu_speed_up_nest == 0U) {
                CLEAR_PERI_REG_MASK(DPORT_CTL_REG, DPORT_CTL_DOUBLE_CLK);
                os_update_cpu_frequency(80U);
            }
        }
    } else if (cpu_freq == ESP_CPU_FREQ_160M) {
        if (s_cpu_speed_up_nest == 0U) {
            SET_PERI_REG_MASK(DPORT_CTL_REG, DPORT_CTL_DOUBLE_CLK);
            os_update_cpu_frequency(160U);
        }
        s_cpu_speed_up_nest++;
    }

    XTOS_RESTORE_INTLEVEL(ps);
}

uint32_t esp_get_time(void)
{
    extern uint64_t WdevTimOffSet;
    return REG_READ(WDEV_COUNT_REG) + (uint32_t)WdevTimOffSet;
}

void user_uart_wait_tx_fifo_empty(uint32_t uart_no, uint32_t timeout_us)
{
    uint8_t port = (uint8_t)uart_no;
    uint32_t start_us = esp_get_time();
    uint32_t status_reg = UART_STATUS(port);

    while ((REG_READ(status_reg) & (UART_TXFIFO_CNT << UART_TXFIFO_CNT_S)) != 0U) {
        if ((uint32_t)(esp_get_time() - start_us) > timeout_us) {
            break;
        }
    }
}

int flash_data_check(const uint8_t *cal_data)
{
    uint32_t buf[32];
    uint32_t sum = 0U;
    uint32_t i;

    for (i = 0U; i < 32U; i++) {
        size_t off = (size_t)i * 4U;
        buf[i] = (uint32_t)cal_data[off]
               | ((uint32_t)cal_data[off + 1U] << 8)
               | ((uint32_t)cal_data[off + 2U] << 16)
               | ((uint32_t)cal_data[off + 3U] << 24);
    }

    buf[24] = ((REG_READ(EFUSE_DATA2_REG) & 0x0000F000U) << 16)
            | (REG_READ(EFUSE_DATA1_REG) & 0x0FFFFFFFU);
    buf[25] = (REG_READ(EFUSE_DATA0_REG) & 0xFF000000U)
            | (REG_READ(EFUSE_DATA3_REG) & 0x00FFFFFFU);

    for (i = 0U; i < 26U; i++) {
        sum += buf[i];
    }

    return (buf[26] == ~sum) ? 0 : 1;
}

int rtc_init(void)
{
    extern void sleep_reset_analog_rtcreg_8266(void);
    sleep_reset_analog_rtcreg_8266();
    return 0;
}

esp_err_t mac_init(void)
{
#ifdef CONFIG_ESP8266_VENDOR_WIFI
    extern uint8_t g_ic[];
    (void)esp_read_mac(&g_ic[0x199], ESP_MAC_WIFI_STA);
    (void)esp_read_mac(&g_ic[0x193], ESP_MAC_WIFI_SOFTAP);
#endif
    return ESP_OK;
}

int base_gpio_init(void)
{
    CLEAR_PERI_REG_MASK(PERIPHS_IO_MUX_GPIO0_U, 0x00000100U);
    CLEAR_PERI_REG_MASK(PERIPHS_IO_MUX_GPIO2_U, 0x00000100U);
    return 0;
}

int wifi_timer_init(void)
{
    extern void ets_timer_init(void);
    ets_timer_init();
#ifdef CONFIG_ESP8266_VENDOR_WIFI
    extern void pp_noise_test(void);
    pp_noise_test();
#endif
    return 0;
}
