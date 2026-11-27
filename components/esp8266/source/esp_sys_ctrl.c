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

/**
 * @file esp_sys_ctrl.c
 * @brief Open-source ESP8266 system control primitives: ADC/VDD33 scaling,
 *        software reboot, deep-sleep sequencing, CPU frequency scaling,
 *        hardware microsecond clock, UART flush, and RF-cal checksum validation.
 */

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

/* ---- ADC / VDD33 scaling constants ---- */
/** Sentinel returned by SAR ADC / VDD33 helpers when reading is unavailable. */
#define SYS_ADC_INVALID                 0xFFFFU
/** Empirical 12/11 gain correction applied to raw ESP8266 SAR ADC counts. */
#define SYS_ADC_SCALE_NUM               12
#define SYS_ADC_SCALE_DEN               11
/** Saturation ceiling for 10-bit TOUT ADC readings. */
#define SYS_ADC_MAX_VALUE               1024U

/* ---- SoC restart / ROM boot constants ---- */
/** DPORT peripheral soft-reset register (`dport[0]`); `dport[3]` is `0x3FF00024` (IRAM/cache map). */
#define SYS_DPORT_SOFT_RESET_REG        0x3FF00018U
/** DPORT peripheral soft-reset pulse mask toggled before jumping to ROM. */
#define SYS_DPORT_SW_RST_MASK           0x00007700U
/** Bits in DPORT `0x3FF00024` cleared after disabling flash cache so ROM starts cleanly. */
#define SYS_DPORT_CACHE_MAP_CLEAR_MASK  0x18U
/** Pre-restart DPORT `0x3FF00018` mask written before draining UART FIFOs. */
#define SYS_DPORT_PRE_RESTART_MASK      0xFFFF00FFU
/** RTC / analog subsystem soft-reset register and pulse bit. */
#define SYS_ANALOG_RST_REG              0x60000D48U
#define SYS_ANALOG_RST_BIT              0x02U
/** ESP8266 Mask ROM reset/boot entry point. */
#define SYS_ROM_RESET_ENTRY_ADDR        0x40000080U
/** Delay (ms) after stopping Wi-Fi in esp_restart() so RF/DMA quiesce cleanly. */
#define SYS_WIFI_STOP_SETTLE_MS         70U
/** Delay (ms) after stopping Wi-Fi in esp_deep_sleep() before cutting power domains. */
#define SYS_DEEP_SLEEP_SETTLE_MS        100U
/** Maximum time (us) to wait for each UART TX FIFO to drain before reset/sleep. */
#define SYS_UART_FLUSH_TIMEOUT_US       500000U
/** ROM-I2C BBPLL block address and host index used to restore default PLL taps before reboot. */
#define SYS_BBPLL_I2C_BLOCK             0x67U
#define SYS_BBPLL_I2C_HOST              4U
#define SYS_BBPLL_REG1_DEFAULT          0x08U
#define SYS_BBPLL_REG2_DEFAULT          0x81U

/* ---- SPI flash header constants ---- */
/** Bit shift and mask of the 4-bit `flash_size_map` nibble inside SPI flash word 0 (byte 3 high nibble). */
#define SYS_FLASH_HDR_SIZE_SHIFT        28U
#define SYS_FLASH_HDR_SIZE_MASK         0x0FU

/* ---- Deep-sleep RTC / WDEV register offsets & empirical sequencing values ---- */
/** WDEV register written before deep sleep to quiesce Wi-Fi RF/baseband front-end. */
#define SYS_WDEV_DEEP_SLEEP_QUIESCE_REG 0x3FF20DE0U
#define SYS_WDEV_DEEP_SLEEP_QUIESCE_VAL 0x00003333U
/** RTC register offsets relative to `PERIPHS_RTC_BASEADDR` (`0x60000700`). */
#define SYS_RTC_STATE0_OFF              0x00U
#define SYS_RTC_SLP_TRIG_OFF            0x08U
#define SYS_RTC_STATE1_OFF              0x0CU
#define SYS_RTC_MISC_OFF                0x10U
#define SYS_RTC_INT_CLR_OFF             0x40U
#define SYS_RTC_INT_ENA_OFF             0x44U
#define SYS_RTC_ANA_CONF_OFF            0x48U
#define SYS_RTC_GPIO_CFG_OFF            0x9CU
/** Trigger bit written to `RTC_SLP_TRIG` (`+0x08`) to initiate RTC sleep FSM. */
#define SYS_RTC_SLP_TRIG_BIT            BIT(20)
/** Stage A transitional pre-sleep duration in slow RTC clock cycles (~900 us at 150 kHz). */
#define SYS_RTC_PRE_SLEEP_CYCLES        136U
/** XPD_DCDC (GPIO16) RTC mux value routing wake pulse to `EXT_RSTB`. */
#define SYS_RTC_XPD_DCDC_WAKE_CFG       0x11U
#define SYS_PAD_XPD_DCDC_WAKE_CONF      0x03U
/** NMI interrupt enable register mask/value to disable Wi-Fi NMI before deep sleep. */
#define SYS_NMI_DISABLE_MASK            0x1FU
#define SYS_NMI_DISABLE_VAL             0x0EU
#define SYS_NMI_ACTIVE_BIT              0x01U

/* ---- CPU frequency scaling constants ---- */
#define SYS_CPU_FREQ_80M_MHZ            80U
#define SYS_CPU_FREQ_160M_MHZ           160U
#define SYS_CRIT_INTLEVEL               3

/* ---- Flash RF-cal checksum constants ---- */
/** Total 32-bit words parsed from the 128-byte RF calibration header. */
#define SYS_CAL_DATA_WORDS              32U
/** Number of 32-bit words summed (24 payload words + 2 chip-eFuse identity words). */
#define SYS_CAL_DATA_SUM_WORDS          26U
#define SYS_CAL_DATA_EFUSE_WORD0_IDX    24U
#define SYS_CAL_DATA_EFUSE_WORD1_IDX    25U
#define SYS_CAL_DATA_CHECKSUM_IDX       26U
/** eFuse field masks combined into words 24..25 to bind RF cal data to a specific chip. */
#define SYS_EFUSE_DATA2_ID_MASK         0x0000F000U
#define SYS_EFUSE_DATA1_ID_MASK         0x0FFFFFFFU
#define SYS_EFUSE_DATA0_MAC_MASK        0xFF000000U
#define SYS_EFUSE_DATA3_MAC_MASK        0x00FFFFFFU

/** IO_MUX bit 8 cleared on GPIO0 and GPIO2 during early `base_gpio_init()`. */
#define SYS_IO_MUX_GPIO_OE_BIT          0x00000100U

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

/**
 * @brief Read a single 10-bit calibrated sample from the external TOUT ADC pin.
 *
 * Calls the PHY SAR ADC sampler (`test_tout(0U)`), applies the 12/11 scale
 * factor, and clamps the result to `[0, 1024]`.
 *
 * @return Scaled ADC reading in `[0, 1024]`, or `SYS_ADC_INVALID` (`0xFFFF`)
 *         if ADC read failed or TOUT is configured for VDD33 sensing.
 */
uint16_t system_adc_read(void)
{
    extern uint16_t test_tout(uint8_t no_sleep_mode);
    uint16_t raw = test_tout(0U);

    if (raw != SYS_ADC_INVALID) {
        uint16_t val = (uint16_t)(((int32_t)raw * SYS_ADC_SCALE_NUM) / SYS_ADC_SCALE_DEN);
        if (val > SYS_ADC_MAX_VALUE) {
            val = SYS_ADC_MAX_VALUE;
        }
        return val;
    }
    return SYS_ADC_INVALID;
}

/**
 * @brief Capture a burst of SAR ADC samples from TOUT and scale them in place.
 *
 * Delegates raw acquisition to `phy_adc_read_fast()`, then applies the 12/11
 * scale factor and 1024 ceiling to every valid sample.
 *
 * @param[out] adc_addr    Destination buffer of at least @p adc_num entries.
 * @param[in]  adc_num     Number of samples to read.
 * @param[in]  adc_clk_div SAR ADC clock divider passed through to PHY.
 */
void system_adc_read_fast(uint16_t *adc_addr, uint16_t adc_num, uint8_t adc_clk_div)
{
    extern void phy_adc_read_fast(uint16_t *adc_addr, uint16_t adc_num, uint8_t adc_clk_div);
    uint16_t i;

    phy_adc_read_fast(adc_addr, adc_num, adc_clk_div);
    for (i = 0U; i < adc_num; i++) {
        uint16_t v = adc_addr[i];
        if (v != SYS_ADC_INVALID) {
            v = (uint16_t)(((int32_t)v * SYS_ADC_SCALE_NUM) / SYS_ADC_SCALE_DEN);
            if (v > SYS_ADC_MAX_VALUE) {
                v = SYS_ADC_MAX_VALUE;
            }
            adc_addr[i] = v;
        }
    }
}

/**
 * @brief Measure the chip's internal VDD33 supply voltage in units of 1/1024 V.
 *
 * Applies the 12/11 scaling correction to the raw PHY reading (without the
 * 1024 clamp used for TOUT).
 *
 * @return Scaled VDD33 value in 1/1024 V units, or `SYS_ADC_INVALID` (`0xFFFF`)
 *         if VDD33 sensing is disabled in PHY init data.
 */
uint16_t system_get_vdd33(void)
{
    extern uint16_t phy_get_vdd33(void);
    uint16_t raw = phy_get_vdd33();

    if (raw != SYS_ADC_INVALID) {
        return (uint16_t)(((int32_t)raw * SYS_ADC_SCALE_NUM) / SYS_ADC_SCALE_DEN);
    }
    return SYS_ADC_INVALID;
}

/**
 * @brief Low-level IRAM SoC reset trampoline that disables flash cache and jumps to ROM.
 *
 * Must execute strictly from IRAM because it disables the SPI flash instruction
 * cache (`Cache_Read_Disable()`). Toggles DPORT peripheral reset bits and the
 * analog reset pulse, clears the IRAM/cache remap bits in `0x3FF00024`, masks
 * all Xtensa interrupts and debug breakpoints, resets the stack pointer `a1` to
 * top of DRAM (`0x3FFFFFB0`), and jumps directly to @p reboot_fn (typically the
 * Mask ROM entry `0x40000080`).
 *
 * @param reboot_fn Target entry vector to jump to after resetting core state.
 */
void IRAM_ATTR __attribute__((noreturn)) __esp_soc_restart(void (*reboot_fn)(void))
{
    volatile uint32_t *dport = (volatile uint32_t *)SYS_DPORT_SOFT_RESET_REG;
    volatile uint32_t *ana_rst = (volatile uint32_t *)SYS_ANALOG_RST_REG;
    uint32_t m = SYS_DPORT_SW_RST_MASK;
    uint32_t s;

    /* Compiler barriers keep the pulse read-modify-write sequence intact in IRAM */
    __asm__("" : "+r"(dport), "+r"(m));
    s = dport[0] | m;
    dport[0] = s;
    __asm__("" : "+r"(s));
    dport[0] = s ^ m;

    s = *ana_rst | SYS_ANALOG_RST_BIT;
    *ana_rst = s;
    *ana_rst = s ^ SYS_ANALOG_RST_BIT;

    Cache_Read_Disable();

    dport[3] &= ~SYS_DPORT_CACHE_MAP_CLEAR_MASK;
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

/**
 * @brief Perform a clean software reboot of the ESP8266 SoC.
 *
 * Stops active Wi-Fi interfaces, brings RF out of sleep so clock/analog reset
 * succeeds, disables the clock-gate watchdog, drains UART0/UART1 TX FIFOs,
 * restores UART0 pin routing, records `ESP_RST_SW` in the RTC reset-reason
 * hint, restores default BBPLL I2C taps and 80 MHz CPU clock, zeroes `CCOUNT`,
 * and jumps to the Mask ROM boot vector via __esp_soc_restart(). Does not return.
 */
void esp_restart(void)
{
    extern void sleep_reset_analog_rtcreg_8266(void);
    extern void clockgate_watchdog(uint8_t en);
    extern void bbpll_cal(uint8_t mode);
#if defined(CONFIG_ESP8266_OSS_PHY_WIFI)
    (void)esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(SYS_WIFI_STOP_SETTLE_MS));
#elif defined(CONFIG_ESP8266_VENDOR_PHY_WIFI)
    extern const uint8_t *g_wifi_nvs;
    extern bool wifi_station_stop(void);
    extern bool wifi_softap_stop(void);
    extern void __wifi_task_delay(uint32_t tick);
    extern uint32_t __wifi_task_ms_to_ticks(uint32_t ms);

    if (g_wifi_nvs != NULL) {
        uint8_t opmode = *g_wifi_nvs;
        if ((opmode & ~2U) == 1U) {
            (void)wifi_station_stop();
        }
        if ((uint8_t)(opmode - 2U) < 2U) {
            (void)wifi_softap_stop();
        }
    }
    __wifi_task_delay(__wifi_task_ms_to_ticks(SYS_WIFI_STOP_SETTLE_MS));
#endif

    SET_PERI_REG_MASK(PERIPHS_IO_MUX_MTDI_U, PERIPHS_IO_MUX_PULLUP);

#ifndef CONFIG_ESP8266_OSS_PHY_ONLY
    {
        extern void pm_goto_rf_on(void);
        pm_goto_rf_on();
    }
#endif
    clockgate_watchdog(0U);

    REG_WRITE(PERIPHS_DPORT_BASEADDR + 0x18U, SYS_DPORT_PRE_RESTART_MASK);
    user_uart_wait_tx_fifo_empty(0U, SYS_UART_FLUSH_TIMEOUT_US);
    user_uart_wait_tx_fifo_empty(1U, SYS_UART_FLUSH_TIMEOUT_US);

    vPortETSIntrLock();
    CLEAR_PERI_REG_MASK(HOST_INF_SEL, PERI_IO_UART0_PIN_SWAP);
    esp_reset_reason_set_hint(ESP_RST_SW);

    /* Reset RTC analog state and restore BBPLL to boot-ROM defaults */
    REG_WRITE(PERIPHS_RTC_BASEADDR + SYS_RTC_MISC_OFF, 0xFE000000U);
    sleep_reset_analog_rtcreg_8266();
    rom_i2c_writeReg(SYS_BBPLL_I2C_BLOCK, SYS_BBPLL_I2C_HOST, 1U, SYS_BBPLL_REG1_DEFAULT);
    rom_i2c_writeReg(SYS_BBPLL_I2C_BLOCK, SYS_BBPLL_I2C_HOST, 2U, SYS_BBPLL_REG2_DEFAULT);
    bbpll_cal(1U);
#ifdef CONFIG_ESP8266_OSS_PHY_ONLY
    CLEAR_PERI_REG_MASK(EDGE_INT_ENABLE_REG, BIT(0));
    _xt_isr_mask(1U << ETS_WDT_INUM);
    CLEAR_WDT_REG_MASK(WDT_CTL_ADDRESS, WDT_CTL_EN_MASK);
#endif

    soc_set_ccount(0U);
    __esp_soc_restart((void (*)(void))SYS_ROM_RESET_ENTRY_ADDR);
    for (;;) {
    }
}

/**
 * @brief Read the SPI flash size/layout enum encoded in the flash image header.
 *
 * Reads the first 8 bytes at flash offset 0 and extracts the upper nibble of
 * byte 3 (`word0[31:28]`).
 *
 * @return Decoded `flash_size_map` enum, or `FLASH_SIZE_4M_MAP_256_256` if the
 *         SPI flash read fails.
 */
flash_size_map system_get_flash_size_map(void)
{
    uint32_t buf[2] = { 0U, 0U };

    if (spi_flash_read(0U, buf, sizeof(buf)) != ESP_OK) {
        return FLASH_SIZE_4M_MAP_256_256;
    }
    return (flash_size_map)((buf[0] >> SYS_FLASH_HDR_SIZE_SHIFT) & SYS_FLASH_HDR_SIZE_MASK);
}

/**
 * @brief Final IRAM deep-sleep entry: put SPI flash in deep power-down and trigger RTC sleep.
 *
 * Must run from IRAM because flash instruction cache is disabled before
 * issuing `SPI_FLASH_DPD` to SPI0. Once `RTC_SLP_TRIG` bit 20 is written, the
 * RTC state machine powers down the digital core.
 */
void IRAM_ATTR __esp_soc_deep_sleep(void)
{
    Cache_Read_Disable();
    REG_WRITE(SPI_CMD(0), SPI_FLASH_DPD);
    while (REG_READ(SPI_CMD(0)) != 0U) {
    }
    REG_WRITE(PERIPHS_RTC_BASEADDR + SYS_RTC_SLP_TRIG_OFF, SYS_RTC_SLP_TRIG_BIT);
}

/**
 * @brief Execute the 4-stage ESP8266 hardware deep-sleep sequence immediately.
 *
 * Stages:
 *  - Stage A: Trigger a short 136-cycle transitional RTC pre-sleep pulse so
 *    internal RTC voltage/clock domains settle into the low-power state.
 *  - Stage B: Configure `XPD_DCDC` (GPIO16) to drive `EXT_RSTB` on wake and
 *    latch the deep-sleep regulator timing register (`+0x0C`).
 *  - Stage C: Mask watchdog and Wi-Fi NMI interrupts so no pending edge can
 *    abort power-down.
 *  - Stage D: Program the final wake cycle count (0 = sleep indefinitely until
 *    external reset), record `ESP_RST_DEEPSLEEP`, and invoke __esp_soc_deep_sleep().
 *
 * @param sleep_cycles Wake timeout in slow RTC clock cycles (0 = indefinite deep sleep).
 */
void system_deep_sleep_instant(uint32_t sleep_cycles)
{
#ifndef CONFIG_ESP8266_OSS_PHY_ONLY
    extern void deep_sleep_set_option(uint8_t opt);
    deep_sleep_set_option(0U);
#endif

    REG_WRITE(SYS_WDEV_DEEP_SLEEP_QUIESCE_REG, SYS_WDEV_DEEP_SLEEP_QUIESCE_VAL);
    os_delay_us(20U);

    user_uart_wait_tx_fifo_empty(0U, SYS_UART_FLUSH_TIMEOUT_US);
    user_uart_wait_tx_fifo_empty(1U, SYS_UART_FLUSH_TIMEOUT_US);

    /* Stage A: 136-cycle transitional RTC pre-sleep pulse (empirical Espressif RTC sequence) */
    REG_WRITE(PERIPHS_RTC_BASEADDR + SYS_RTC_STATE0_OFF, 0U);
    CLEAR_PERI_REG_MASK(PERIPHS_RTC_BASEADDR + SYS_RTC_STATE0_OFF, BIT(14));
    SET_PERI_REG_MASK(PERIPHS_RTC_BASEADDR + SYS_RTC_STATE0_OFF, BIT(5) | BIT(4));
    REG_WRITE(PERIPHS_RTC_BASEADDR + SYS_RTC_INT_ENA_OFF, 4U);
    REG_WRITE(PERIPHS_RTC_BASEADDR + SYS_RTC_STATE1_OFF, 0x00010010U);
    REG_WRITE(PERIPHS_RTC_BASEADDR + SYS_RTC_ANA_CONF_OFF,
              (REG_READ(PERIPHS_RTC_BASEADDR + SYS_RTC_ANA_CONF_OFF) & 0xFFFF01FFU) | 0x0000FC00U);
    REG_WRITE(PERIPHS_RTC_BASEADDR + SYS_RTC_ANA_CONF_OFF,
              (REG_READ(PERIPHS_RTC_BASEADDR + SYS_RTC_ANA_CONF_OFF) & 0xFFFFFE00U) | 0x00000080U);
    REG_WRITE(PERIPHS_RTC_BASEADDR + SYS_RTC_MISC_OFF, 0U);
    REG_WRITE(RTC_SLP_VAL, REG_READ(RTC_SLP_CNT_VAL) + SYS_RTC_PRE_SLEEP_CYCLES);
    REG_WRITE(RTC_STATE2, RTC_TIMER_TRIG_EN);
    REG_WRITE(PERIPHS_RTC_BASEADDR + SYS_RTC_SLP_TRIG_OFF, SYS_RTC_SLP_TRIG_BIT);
    os_delay_us(200U);

    /* Stage B: Configure XPD_DCDC (GPIO16 -> EXT_RSTB) and regulator latches */
    REG_WRITE(PERIPHS_RTC_BASEADDR + SYS_RTC_GPIO_CFG_OFF, SYS_RTC_XPD_DCDC_WAKE_CFG);
    REG_WRITE(PAD_XPD_DCDC_CONF, SYS_PAD_XPD_DCDC_WAKE_CONF);
    REG_WRITE(PERIPHS_RTC_BASEADDR + SYS_RTC_STATE1_OFF, 0x000640C8U);
    CLEAR_PERI_REG_MASK(PERIPHS_RTC_BASEADDR + SYS_RTC_STATE0_OFF, BIT(5) | BIT(4));
    REG_WRITE(PERIPHS_RTC_BASEADDR + SYS_RTC_GPIO_CFG_OFF, SYS_RTC_XPD_DCDC_WAKE_CFG);
    REG_WRITE(PAD_XPD_DCDC_CONF, SYS_PAD_XPD_DCDC_WAKE_CONF);

    /* Stage C: Quiesce WDT and Wi-Fi NMI interrupts */
    CLEAR_PERI_REG_MASK(EDGE_INT_ENABLE_REG, BIT(0));
    _xt_isr_mask(1U << ETS_WDT_INUM);
    do {
        REG_WRITE(NMI_INT_ENABLE_REG,
                  (REG_READ(NMI_INT_ENABLE_REG) & ~SYS_NMI_DISABLE_MASK) | SYS_NMI_DISABLE_VAL);
    } while ((REG_READ(NMI_INT_ENABLE_REG) & SYS_NMI_ACTIVE_BIT) != 0U);

    /* Stage D: Program final sleep duration and enter deep sleep */
    REG_WRITE(PERIPHS_RTC_BASEADDR + SYS_RTC_INT_CLR_OFF, 0xFFFFFFFFU);
    REG_WRITE(PERIPHS_RTC_BASEADDR + SYS_RTC_INT_ENA_OFF, 0x20U);
    pm_set_sleep_cycles(sleep_cycles);
    if (sleep_cycles == 0U) {
        REG_WRITE(RTC_STATE2, 0U);
    } else {
        REG_WRITE(RTC_STATE2, RTC_TIMER_TRIG_EN);
    }
    vPortETSIntrLock();
    esp_reset_reason_set_hint(ESP_RST_DEEPSLEEP);
    __esp_soc_deep_sleep();
}

/**
 * @brief Enter deep sleep for the requested duration in microseconds.
 *
 * Calibrates the internal slow RTC oscillator, converts @p time_in_us into
 * 32-bit RTC cycles, stops Wi-Fi cleanly (when built with Wi-Fi), waits 100 ms,
 * and invokes system_deep_sleep_instant(). Returns early with a log message if
 * the converted cycle count overflows 32 bits.
 *
 * @param time_in_us Desired deep-sleep duration in microseconds (0 = indefinite sleep).
 */
void esp_deep_sleep(uint64_t time_in_us)
{
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
#ifndef CONFIG_ESP8266_OSS_PHY_ONLY
    (void)esp_wifi_stop();
#endif
    vTaskDelay(pdMS_TO_TICKS(SYS_DEEP_SLEEP_SETTLE_MS));
    system_deep_sleep_instant((uint32_t)cycles);
}

/**
 * @brief Switch CPU clock between 80 MHz and 160 MHz using a reference-counted boost lock.
 *
 * Maintains a nesting counter (`s_cpu_speed_up_nest`): switching to 160 MHz
 * increments the count and enables `DPORT_CTL_DOUBLE_CLK` on the 0 -> 1 edge;
 * switching back to 80 MHz decrements the count and restores 80 MHz only when
 * the count returns to 0.
 *
 * @param cpu_freq Target CPU frequency (`ESP_CPU_FREQ_80M` or `ESP_CPU_FREQ_160M`).
 */
void esp_set_cpu_freq(esp_cpu_freq_t cpu_freq)
{
    unsigned ps = XTOS_SET_INTLEVEL(SYS_CRIT_INTLEVEL);

    if (cpu_freq == ESP_CPU_FREQ_80M) {
        if (s_cpu_speed_up_nest == 0U) {
            ets_printf("CLK:switch SoC Frequency to 80MHz fail");
        } else {
            s_cpu_speed_up_nest--;
            if (s_cpu_speed_up_nest == 0U) {
                CLEAR_PERI_REG_MASK(DPORT_CTL_REG, DPORT_CTL_DOUBLE_CLK);
                os_update_cpu_frequency(SYS_CPU_FREQ_80M_MHZ);
            }
        }
    } else if (cpu_freq == ESP_CPU_FREQ_160M) {
        if (s_cpu_speed_up_nest == 0U) {
            SET_PERI_REG_MASK(DPORT_CTL_REG, DPORT_CTL_DOUBLE_CLK);
            os_update_cpu_frequency(SYS_CPU_FREQ_160M_MHZ);
        }
        s_cpu_speed_up_nest++;
    }

    XTOS_RESTORE_INTLEVEL(ps);
}

/**
 * @brief Return the low 32 bits of the monotonic 1 MHz WDEV hardware timestamp.
 *
 * Combines the live hardware counter (`WDEV_COUNT_REG`) with the sleep-offset
 * accumulator (`WdevTimOffSet`). Wraps every ~71.58 minutes.
 *
 * @return Current microsecond timestamp (mod 2^32).
 */
uint32_t esp_get_time(void)
{
    extern uint64_t WdevTimOffSet;
    return REG_READ(WDEV_COUNT_REG) + (uint32_t)WdevTimOffSet;
}

/**
 * @brief Busy-wait until a UART's hardware TX FIFO is completely empty or a timeout elapses.
 *
 * @param uart_no    UART peripheral index (0 or 1).
 * @param timeout_us Maximum wait time in microseconds.
 */
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

/**
 * @brief Verify the chip-bound inverted-sum integrity checksum of a 128-byte RF cal sector.
 *
 * Unpacks 32 little-endian 32-bit words from @p cal_data, replaces words 24
 * and 25 with the live chip-unique eFuse identity/MAC bits, sums words 0..25,
 * and checks whether word 26 equals the bitwise complement `~sum`. Binding the
 * checksum to eFuse prevents RF calibration data cloned from another chip from
 * being accepted blindly.
 *
 * @param cal_data Pointer to a 128-byte RF calibration data block read from flash.
 * @return 0 if the checksum is valid, 1 if invalid/mismatched.
 */
int flash_data_check(const uint8_t *cal_data)
{
    uint32_t buf[SYS_CAL_DATA_WORDS];
    uint32_t sum = 0U;
    uint32_t i;

    for (i = 0U; i < SYS_CAL_DATA_WORDS; i++) {
        size_t off = (size_t)i * 4U;
        buf[i] = (uint32_t)cal_data[off]
               | ((uint32_t)cal_data[off + 1U] << 8)
               | ((uint32_t)cal_data[off + 2U] << 16)
               | ((uint32_t)cal_data[off + 3U] << 24);
    }

    /* Fold live chip eFuse identity into words 24..25 before summing */
    buf[SYS_CAL_DATA_EFUSE_WORD0_IDX] = ((REG_READ(EFUSE_DATA2_REG) & SYS_EFUSE_DATA2_ID_MASK) << 16)
                                      | (REG_READ(EFUSE_DATA1_REG) & SYS_EFUSE_DATA1_ID_MASK);
    buf[SYS_CAL_DATA_EFUSE_WORD1_IDX] = (REG_READ(EFUSE_DATA0_REG) & SYS_EFUSE_DATA0_MAC_MASK)
                                      | (REG_READ(EFUSE_DATA3_REG) & SYS_EFUSE_DATA3_MAC_MASK);

    for (i = 0U; i < SYS_CAL_DATA_SUM_WORDS; i++) {
        sum += buf[i];
    }

    return (buf[SYS_CAL_DATA_CHECKSUM_IDX] == ~sum) ? 0 : 1;
}

/**
 * @brief Early startup hook that resets analog RTC registers to power-on defaults.
 *
 * @return Always 0.
 */
int rtc_init(void)
{
    extern void sleep_reset_analog_rtcreg_8266(void);
    sleep_reset_analog_rtcreg_8266();
    return 0;
}

/**
 * @brief Early startup hook that seeds vendor Wi-Fi `g_ic` STA/SoftAP MAC addresses.
 *
 * No-op in open-source Wi-Fi builds (where net80211 queries `esp_read_mac()`
 * directly during interface initialization).
 *
 * @return Always `ESP_OK`.
 */
esp_err_t mac_init(void)
{
#ifdef CONFIG_ESP8266_VENDOR_PHY_WIFI
    extern uint8_t g_ic[];
    (void)esp_read_mac(&g_ic[0x199], ESP_MAC_WIFI_STA);
    (void)esp_read_mac(&g_ic[0x193], ESP_MAC_WIFI_SOFTAP);
#endif
    return ESP_OK;
}

/**
 * @brief Clear residual boot-strap IO_MUX output-enable bits on GPIO0 and GPIO2.
 *
 * @return Always 0.
 */
int base_gpio_init(void)
{
    CLEAR_PERI_REG_MASK(PERIPHS_IO_MUX_GPIO0_U, SYS_IO_MUX_GPIO_OE_BIT);
    CLEAR_PERI_REG_MASK(PERIPHS_IO_MUX_GPIO2_U, SYS_IO_MUX_GPIO_OE_BIT);
    return 0;
}

/**
 * @brief Initialize the FRC2 software timer subsystem (and vendor noise test if enabled).
 *
 * @return Always 0.
 */
int wifi_timer_init(void)
{
    extern void ets_timer_init(void);
    ets_timer_init();
#ifdef CONFIG_ESP8266_VENDOR_PHY_WIFI
    extern void pp_noise_test(void);
    pp_noise_test();
#endif
    return 0;
}
