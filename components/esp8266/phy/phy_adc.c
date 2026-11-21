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

#include "phy_internal.h"

/* --------------------------------------------------------------------------
 * Exported & Cross-TU Globals (Explicitly Initialized — 0 SHN_COMMON)
 * -------------------------------------------------------------------------- */

unsigned int adc_rand_noise = 0U;
uint8_t g_phy_tout_dis_txpwr_track = 0U;

/* --------------------------------------------------------------------------
 * Internal SAR Helpers (Flash — 0 B IRAM)
 * -------------------------------------------------------------------------- */

static inline uint16_t sar_raw_correct(uint32_t reg_val)
{
    uint32_t raw = (~reg_val) & 0xFFFFU;
    int32_t lo = (int32_t)(raw & 0xFFU) - 21;

    if (lo < 0) {
        lo = 0;
    }
    return (uint16_t)((raw & 0x700U) + (uint32_t)((lo * 279) >> 8));
}

static inline void sar_wait_idle(void)
{
    while (((PHY_REG_READ(PHY_SAR_CTRL_REG) >> 24) & 0x7U) != 0U) {
    }
}

static inline void sar_trigger_pulse(void)
{
    PHY_REG_CLR(PHY_SAR_CTRL_REG, BIT(1));
    PHY_REG_SET(PHY_SAR_CTRL_REG, BIT(1));
}

static inline void sar_pwdet_rearm_pulse(void)
{
    PHY_REG_CLR(PHY_SAR_PWDET_CTRL_REG, BIT(0));
    PHY_REG_SET(PHY_SAR_PWDET_CTRL_REG, BIT(0));
}

/* --------------------------------------------------------------------------
 * Cross-TU SAR ADC, Power Detector, TSEN & Entropy Helpers (Flash)
 * -------------------------------------------------------------------------- */

void phy_read_sar_dout(int16_t out[8])
{
    for (uint32_t i = 0U; i < 8U; i++) {
        out[i] = (int16_t)sar_raw_correct(PHY_REG_READ(PHY_SAR_DOUT_REG(i)));
    }
}

uint16_t phy_readvdd33(uint8_t pbus_dbg)
{
    int16_t samples[8];

    if (pbus_dbg != 0U) {
        PHY_REG_SET(PHY_PBUS_CTRL_REG, PHY_PBUS_DEBUG_MODE);
    }

    uint16_t saved_pbus = phy_pbus_rd(6U, 1U);
    uint8_t saved_pa_9 = rom_i2c_readReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2, 9U, 2U, 0U);
    uint8_t saved_sar_0 = rom_i2c_readReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, 0U, 5U, 5U);

    phy_pbus_force(6U, 1U, (uint16_t)(saved_pbus | 2U));
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2, 9U, 7U, 7U, 1U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2, 9U, 2U, 0U, 0U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, 0U, 5U, 5U, 1U);

    PHY_REG_SET(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_VDD33_EN);
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_TOUT_EN);

    sar_wait_idle();
    sar_trigger_pulse();
    ets_delay_us(25U);

    phy_read_sar_dout(samples);

    uint16_t sum = 0U;
    for (uint32_t i = 0U; i < 8U; i++) {
        sum = (uint16_t)(sum + (uint16_t)samples[i]);
    }
    uint16_t result = (uint16_t)(((uint32_t)sum + 2U) >> 2);

    phy_pbus_force(6U, 1U, saved_pbus);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2, 9U, 7U, 7U, 0U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2, 9U, 2U, 0U, saved_pa_9);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, 0U, 5U, 5U, saved_sar_0);

    if (pbus_dbg != 0U) {
        PHY_REG_CLR(PHY_PBUS_CTRL_REG, PHY_PBUS_DEBUG_MODE);
    }

    return result;
}

uint8_t phy_tsen_meas(void)
{
    PHY_REG_CLR(PHY_SAR_CTRL_REG, BIT(5));
    PHY_REG_SET(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_TOUT_EN);
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_VDD33_EN);
    ets_delay_us(200U);

    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, 0U, 6U, 6U, 0U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, 0U, 6U, 6U, 1U);
    PHY_REG_SET(PHY_SAR_CTRL_REG, BIT(5));

    return rom_i2c_readReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, 2U, 7U, 0U);
}

void phy_get_fm_sar_dout(int16_t *out1, int16_t *out2)
{
    int16_t d[8];

    sar_trigger_pulse();
    ets_delay_us(25U);
    sar_wait_idle();
    phy_read_sar_dout(d);

    uint16_t ref3 = (uint16_t)(((uint16_t)d[6] + (uint16_t)d[7]) * 3U);
    uint16_t sig1 = (uint16_t)(((uint16_t)d[1] + (uint16_t)d[2] + (uint16_t)d[3]) * 2U);
    uint16_t sig2 = (uint16_t)(((uint16_t)d[4] + (uint16_t)d[5]) * 3U);

    *out1 = (sig1 < ref3) ? 0 : (int16_t)(sig1 - ref3);
    *out2 = (sig2 < ref3) ? 0 : (int16_t)(sig2 - ref3);
}

int16_t phy_get_sar_dout(uint16_t ref)
{
    int16_t d[8];

    phy_read_sar_dout(d);

    uint16_t ref3 = (uint16_t)(((uint16_t)d[6] + (uint16_t)d[7]) * 3U);
    int16_t diff1 =
        (int16_t)((uint16_t)(((uint16_t)d[1] + (uint16_t)d[2] + (uint16_t)d[3]) * 2U) - ref3);
    int16_t diff2 = (int16_t)((uint16_t)(((uint16_t)d[4] + (uint16_t)d[5]) * 3U) - ref3);

    if (diff1 < 0) {
        diff1 = 0;
    }
    int32_t db1 = phy_linear_to_db((int32_t)diff1, 3U);

    if (diff2 < 0) {
        diff2 = 0;
    }
    int32_t db2 = phy_linear_to_db((int32_t)diff2, 3U);

    return (int16_t)(((int32_t)ref + db1) - db2);
}

int16_t phy_get_power_db(uint16_t ref)
{
    int16_t out1 = 0;
    int16_t out2 = 0;

    phy_get_fm_sar_dout(&out1, &out2);
    int32_t db1 = phy_linear_to_db((int32_t)out1, 3U);
    int32_t db2 = phy_linear_to_db((int32_t)out2, 3U);
    return (int16_t)(((int32_t)ref + db1) - db2);
}

uint32_t phy_get_adc_rand(void)
{
    uint32_t rnd = 0U;

    for (uint32_t shift = 0U; shift < 32U; shift += 4U) {
        uint32_t val = PHY_REG_READ(PHY_BB_ADC_RAND_REG);
        uint32_t nibble = ((val >> 8) & 0x0CU) | (val & 0x03U);
        rnd |= (nibble << shift);
    }
    return rnd;
}

/* --------------------------------------------------------------------------
 * Exported ADC & VDD33 APIs (Flash)
 * -------------------------------------------------------------------------- */

uint16_t phy_get_vdd33(void)
{
    uint32_t saved_rf_pwr = PHY_REG_READ(PHY_RTC_RF_PWR_REG);
    uint16_t ret = 0xFFFFU;

    PHY_REG_SET(PHY_RTC_RF_PWR_REG, 0xD6000000U);

    if (g_phy_sleep_mode_flag == 0U) {
        pm_set_sleep_mode(4U);
    } else {
        phy_sar_init();
        PHY_REG_SET(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_SUB);
    }

    if (chip6_phy_init_ctrl[0x47] == 0xFFU) {
        ret = phy_readvdd33(1U);
    }

    sar_wait_idle();
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_TOUT_EN);
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_VDD33_EN);
    sar_pwdet_rearm_pulse();

    if (g_phy_sleep_mode_flag == 0U) {
        pm_wakeup_init(4U, 0U);
    } else {
        PHY_REG_CLR(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_GATE_MASK);
    }

    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, saved_rf_pwr);
    return ret;
}

uint16_t test_tout(uint8_t no_sleep_mode)
{
    int16_t samples[8];

    g_phy_tout_dis_txpwr_track = 1U;

    uint32_t saved_rf_pwr = PHY_REG_READ(PHY_RTC_RF_PWR_REG);
    PHY_REG_SET(PHY_RTC_RF_PWR_REG, 0xD6000000U);
    if ((saved_rf_pwr & PHY_RTC_RF_PWR_SAR_BIT) == 0U) {
        phy_sar_init();
    }

    if ((g_phy_sleep_mode_flag == 0U) && (no_sleep_mode == 0U)) {
        pm_set_sleep_mode(4U);
    }

    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, 0U, 5U, 5U, 1U);
    PHY_REG_SET(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_TOUT_EN);

    sar_wait_idle();
    sar_trigger_pulse();
    ets_delay_us(2U);
    sar_wait_idle();

    phy_read_sar_dout(samples);

    uint16_t sum = 0U;
    for (uint32_t i = 0U; i < 8U; i++) {
        sum = (uint16_t)(sum + (uint16_t)samples[i]);
    }

    uint16_t ret =
        (chip6_phy_init_ctrl[0x47] == 0xFFU) ? 0xFFFFU : (uint16_t)(((uint32_t)sum + 8U) >> 4);

    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, 0U, 5U, 5U, 0U);
    sar_wait_idle();
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_TOUT_EN);
    sar_pwdet_rearm_pulse();

    if ((g_phy_sleep_mode_flag == 0U) && (no_sleep_mode == 0U)) {
        pm_wakeup_init(4U, 0U);
    }

    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, saved_rf_pwr);
    g_phy_tout_dis_txpwr_track = 0U;
    return ret;
}

void phy_adc_read_fast(uint16_t *dst, uint16_t len, uint8_t clk_div)
{
    uint32_t saved_rf_pwr = PHY_REG_READ(PHY_RTC_RF_PWR_REG);
    PHY_REG_SET(PHY_RTC_RF_PWR_REG, 0xD6000000U);
    if ((saved_rf_pwr & PHY_RTC_RF_PWR_SAR_BIT) == 0U) {
        phy_sar_init();
    }

    g_phy_tout_dis_txpwr_track = 1U;
    if (clk_div < 2U) {
        clk_div = 2U;
    }

    uint32_t saved_ctrl = PHY_REG_READ(PHY_SAR_CTRL_REG);
    uint32_t saved_t0 = PHY_REG_READ(PHY_SAR_TIMING0_REG);
    uint32_t saved_t1 = PHY_REG_READ(PHY_SAR_TIMING1_REG);

    PHY_REG_RMW(PHY_SAR_CTRL_REG, 0x0000FF00U, ((uint32_t)clk_div << 8));
    PHY_REG_RMW(PHY_SAR_TIMING0_REG, 0x00FFFFFFU,
                ((uint32_t)clk_div * 0x010105U) - 0x010101U);
    PHY_REG_RMW(PHY_SAR_TIMING1_REG, 0x00FFFFFFU,
                ((uint32_t)clk_div * 0x0A030BU) - 0x010101U);
    PHY_REG_CLR(PHY_SAR_CTRL_REG, 0x0000001CU);

    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, 0U, 5U, 5U, 1U);
    PHY_REG_SET(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_TOUT_EN);
    sar_wait_idle();

    for (uint16_t i = 0U; i < len; i++) {
        sar_trigger_pulse();
        ets_delay_us(1U);
        sar_wait_idle();

        uint32_t raw = PHY_REG_READ(PHY_SAR_DOUT_REG(0U));
        if (chip6_phy_init_ctrl[0x47] == 0xFFU) {
            dst[i] = 0xFFFFU;
        } else {
            dst[i] = (uint16_t)(((uint32_t)sar_raw_correct(raw) + 1U) >> 1);
        }
    }

    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, 0U, 5U, 5U, 0U);
    PHY_REG_WRITE(PHY_SAR_CTRL_REG, saved_ctrl);
    PHY_REG_WRITE(PHY_SAR_TIMING0_REG, saved_t0);
    PHY_REG_WRITE(PHY_SAR_TIMING1_REG, saved_t1);

    sar_wait_idle();
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_TOUT_EN);
    sar_pwdet_rearm_pulse();

    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, saved_rf_pwr);
    g_phy_tout_dis_txpwr_track = 0U;
}
