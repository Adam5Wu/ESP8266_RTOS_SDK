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
// RC filter calibration, TX DC offset calibration, and baseband analog default
// erratum sequences adapted in part from teatime-os:
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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "phy_internal.h"

/* --------------------------------------------------------------------------
 * Module-Local Calibration & Scaling Constants
 * -------------------------------------------------------------------------- */

#define PHY_TXDC_POLL_LIMIT             100000U
#define PHY_TXDC_MIDSCALE               64      /* 7-bit TX DC DAC midscale (0..127) */
#define PHY_TXDC_MAX_CODE               127
#define PHY_TXDC_INIT_STEP              28      /* Initial binary-search step size */
#define PHY_TXDC_AVG_WINDOW             4       /* Average the final 4 binary-search steps */

#define PHY_FREQOFF_INVALID             0x7FFF  /* Sentinel when RX freq-offset is invalid */
#define PHY_FREQOFF_SCALE_Q16           0x1AC00 /* Q16 scale factor (~1.6719) -> Hz/unit */

#define PHY_TXPWR_LEVEL_COUNT           6U      /* 6 target power tiers in init_data */
#define PHY_TXPWR_BAND_COUNT            4U      /* 4 anchor bands: Ch 1, 6, 11, 14 */
#define PHY_TXPWR_MAX_BACKOFF_QDB       24      /* Maximum PA saturation backoff (6.0 dB) */
#define PHY_TXPWR_MAX_NEG_ATTEN_QDB     24      /* Upper clamp on signed -bb_atten register */
#define PHY_TXPWR_SERVO_MAX_ATTEN       100     /* Maximum digital TX tone attenuation */
#define PHY_TXPWR_SERVO_ERR_CLAMP       24      /* Per-iteration servo error clamp (0.25 dB) */
#define PHY_TXPWR_SERVO_MAX_DIFF        50      /* Max allowed span between tier 5 and tier 0 */

#define PHY_VDD33_MIN_MV                1800U   /* Valid VDD33 measurement floor (1.8 V) */
#define PHY_VDD33_SPAN_MV               1500U   /* Valid VDD33 span above floor (to 3.3 V) */
#define PHY_VDD33_DEFAULT_MV            3300U   /* Fallback nominal supply voltage (3.3 V) */
#define PHY_VDD33_CFG_MIN_DV            18U     /* Fixed vdd33_const minimum (1.8 V in 0.1 V) */
#define PHY_VDD33_CFG_SPAN_DV           18U     /* Fixed vdd33_const span (1.8..3.6 V) */
#define PHY_VDD33_DV_TO_RAW             102U    /* Scale 0.1 V config units to raw SAR counts */

#define PHY_TX_RF_GAIN_MIN_REG          0x03E5U /* Lower RF analog gain bound for bg step-down */
#define PHY_TX_RF_GAIN_MAX_REG          0x0FF3U /* Upper RF analog gain bound for bg step-up */
#define PHY_TX_STAGE10_DEFAULT          0x0FU   /* Full PA stage-10 gain code (4-bit) */
#define PHY_TX_FCC_NO_EDGE_CLAMP        (-128)  /* Sentinel: no FCC band-edge clamp active */

#define PHY_PWCTRL_BG_ERR_CLAMP         32      /* Background tracking error clamp */
#define PHY_PWCTRL_BG_MAX_DRIFT         19      /* Max cumulative positive TX power drift */
#define PHY_PWCTRL_BG_PERIODIC_THRESH   7       /* |periodic_delta| > 7 triggers BBPLL recal */

#define PHY_TXIQ_GAIN_LIMIT             15      /* 5-bit signed TXIQ gain range [-15..+15] */
#define PHY_TXIQ_PHASE_LIMIT            31      /* 6-bit signed TXIQ phase range [-31..+31] */
#define PHY_TXIQ_CONVERGE_ERR_MAX       4       /* Residual error threshold for check flag */
#define PHY_CHECK_RC_CAL_FAIL_BIT       0x01000000U
#define PHY_CHECK_TXIQ_FAIL_BIT         0x00002000U

#define PHY_TXBB_GAIN_CODE_0            0x04U
#define PHY_TXBB_GAIN_CODE_1            0x10U
#define PHY_TXBB_GAIN_CODE_2            0x12U
#define PHY_TXBB_GAIN_CODE_3            0x14U

/* --------------------------------------------------------------------------
 * Cross-TU Globals Owned by phy_cal_tx.c (Explicitly Initialized, 0 COMMON)
 * -------------------------------------------------------------------------- */

uint8_t g_phy_in_most_power = 0x4EU;            /* Requested max TX power (0.25 dBm; 19.5 dBm) */
int8_t g_phy_in_vdd33_offset = 0;               /* Dynamic VDD33 TX power offset (0.25 dB) */
uint8_t g_phy_set_most_tpw_flag = 0U;           /* Non-zero once phy_set_most_tpw() called */
uint8_t g_phy_set_most_tpw_val = 0U;            /* Quantized effective max TX power (0.25 dBm) */
uint8_t g_phy_set_most_tpw_index = 0U;          /* Minimum allowed target power tier (0..5) */
uint8_t g_phy_set_most_tpw_disbg = 0U;          /* 1 = disable bg tracking (below tier 5) */
uint8_t g_phy_periodic_cal_flag = 0U;           /* Periodic cal pending flag (sleep gate) */
uint8_t g_phy_periodic_cal_sat = 0U;            /* Long-sleep threshold flag from PM */
uint8_t g_phy_bbpll_cal_flag = 0U;              /* 1 = BBPLL already recalibrated on wake */
uint8_t g_phy_tx_pwctrl_track_num = 0U;         /* Background tracking iteration count (0..20) */
int8_t g_phy_txpwr_diff_flash[2] = { 0, 0 };    /* Delta vs cached cal [0]=gain+att, [1]=bkoff */
uint8_t g_phy_dpd_bypass_original = 0U;         /* Saved DPD bypass state */
uint8_t g_phy_txbk_dpdby_flag = 0U;             /* 1 = PA backoff > 1 dB (bypass DPD) */

/* --------------------------------------------------------------------------
 * File-Local Static State & Read-Only Lookup Tables (.flash.rodata)
 * -------------------------------------------------------------------------- */

static uint16_t s_tx_rf_ana_gain = PHY_TX_RF_ANA_GAIN_DEFAULT;
static int16_t s_meas_freq_offset = 0;
static int16_t s_phy_tx_power_out = 0;
static int16_t s_phy_tx_pwr_error = 0;
static uint8_t s_do_pwctrl_flag = 0U;

/* Four TX baseband analog gain codes swept during TX DC offset calibration */
static const uint8_t s_txbb_gain_tbl[4] = {
    PHY_TXBB_GAIN_CODE_0, PHY_TXBB_GAIN_CODE_1,
    PHY_TXBB_GAIN_CODE_2, PHY_TXBB_GAIN_CODE_3
};
/* RF gain step sizes in 0.25 dB units for RF gain index transitions 1->2 .. 6->7 */
static const uint8_t s_rf_gain_qdb[6] = { 14U, 10U, 8U, 7U, 6U, 5U };
/* Three anchor channels swept during TX capacitor bank calibration */
static const uint8_t s_txcap_chans[3] = { 1U, 6U, 11U };

/* --------------------------------------------------------------------------
 * IRAM Errata, Baseband EVM & RX Frequency-Offset FIQ Readout
 * (ONLY these 3 functions in phy_cal_tx.c are placed in IRAM)
 * -------------------------------------------------------------------------- */

/**
 * @brief Pulse analog reset, program silicon-rev baseband analog defaults, and read RX EVM.
 *
 * Resides in IRAM because phy_fix_cache_bug() invokes it with SPI flash XIP cache
 * disabled. Selects the empirically characterized analog default word based on
 * eFuse word 2 bits [15:12].
 *
 * @return 13-bit unsigned baseband EVM metric from PHY_BB_RX_METRIC_REG[28:16].
 */
uint16_t IRAM_ATTR phy_get_bb_evm(void)
{
    PHY_REG_SET(PHY_ANALOG_RST_REG, PHY_ANALOG_RST_BIT);
    PHY_REG_CLR(PHY_ANALOG_RST_REG, PHY_ANALOG_RST_BIT);

    if (((PHY_REG_READ(PHY_EFUSE_DATA2_REG) >> PHY_EFUSE_DATA2_ANA_REV_SHIFT) &
         PHY_EFUSE_DATA2_ANA_REV_MASK) == PHY_EFUSE_DATA2_ANA_REV_MASK) {
        PHY_REG_WRITE(PHY_BB_ANALOG_DEFAULT_REG, PHY_BB_ANALOG_DEFAULT_REV_A);
    } else {
        PHY_REG_WRITE(PHY_BB_ANALOG_DEFAULT_REG, PHY_BB_ANALOG_DEFAULT_STD);
    }

    return (uint16_t)((PHY_REG_READ(PHY_BB_RX_METRIC_REG) >> PHY_BB_RX_METRIC_EVM_SHIFT) &
                      PHY_BB_RX_METRIC_EVM_MASK);
}

/**
 * @brief Apply the ESP8266 flash-cache / baseband analog erratum workaround safely in IRAM.
 *
 * Enters a critical section, disables SPI flash XIP cache, executes phy_get_bb_evm()
 * to reset analog defaults, then re-enables flash cache before exiting the critical
 * section. Must live in IRAM so no flash instruction fetches occur while cache is off.
 */
void IRAM_ATTR phy_fix_cache_bug(void)
{
    vPortEnterCritical();
    Cache_Read_Disable();
    (void)phy_get_bb_evm();
    Cache_Read_Enable_New();
    vPortExitCritical();
}

/**
 * @brief Read and clear the baseband RX carrier frequency offset latch from Level-3 NMI.
 *
 * Called directly from wDev_ProcessFiq() in IRAM for each completed RX frame. Only
 * reads the signed 8-bit hardware frequency-offset metric when the received frame is
 * an 802.11b/CCK rate (rate code < 8) and the valid bit is set; otherwise returns
 * PHY_FREQOFF_INVALID (0x7FFF). Scales the raw byte by Q16 factor 0x1AC00 (~1.6719)
 * and clears the baseband frequency-offset latch before returning.
 *
 * @return Scaled signed carrier frequency offset, or PHY_FREQOFF_INVALID (0x7FFF) if unavailable.
 */
int16_t IRAM_ATTR phy_get_bb_freqoffset(void)
{
    int16_t off = PHY_FREQOFF_INVALID;

    if (((PHY_REG_READ(PHY_MAC_RX_RATE_INFO_REG) >> PHY_MAC_RX_RATE_INFO_SHIFT) &
         PHY_MAC_RX_RATE_INFO_MASK) < PHY_MAC_RX_RATE_OFDM_MIN) {
        uint32_t metric = PHY_REG_READ(PHY_BB_RX_METRIC_REG);
        if ((metric & PHY_BB_RX_METRIC_FO_VALID) != 0U) {
            int8_t raw = (int8_t)((metric >> PHY_BB_RX_METRIC_FO_SHIFT) & 0xFFU);
            off = (int16_t)(((int32_t)raw * PHY_FREQOFF_SCALE_Q16) >> 16);
        }
    }

    PHY_REG_SET(PHY_BB_FREQOFF_CLR_REG, PHY_BB_FREQOFF_CLR_MASK);
    s_meas_freq_offset = off;
    return off;
}

/* --------------------------------------------------------------------------
 * Internal Integer & Gain Mapping Helpers
 * -------------------------------------------------------------------------- */

/**
 * @brief Return the absolute value of a signed 32-bit integer.
 *
 * @param v  Signed 32-bit input value.
 * @return   Non-negative magnitude |v|.
 */
static int32_t phy_abs_i32(int32_t v)
{
    return (v < 0) ? -v : v;
}

/**
 * @brief Map a 5-bit TX baseband analog gain code to its TX DC offset table index (0..3).
 *
 * @param gain  5-bit TX baseband analog gain code (0x04, 0x10, 0x12, or 0x14).
 * @return      Index into g_phy_sleep_params.txdc[0..3] (defaults to 1 for 0x10/unknown).
 */
static uint8_t phy_txbbgain2dcoindex(uint8_t gain)
{
    switch (gain) {
    case PHY_TXBB_GAIN_CODE_0:
        return 0U;
    case PHY_TXBB_GAIN_CODE_2:
        return 2U;
    case PHY_TXBB_GAIN_CODE_3:
        return 3U;
    case PHY_TXBB_GAIN_CODE_1:
    default:
        return 1U;
    }
}

/**
 * @brief Return the incremental RF PA gain step size (in 0.25 dB) for a given RF gain index.
 *
 * @param rf_gain  RF gain index (1..6 mapped via s_rf_gain_qdb[]; out-of-range returns 5).
 * @return         Gain delta in 0.25 dB units between rf_gain and rf_gain + 1.
 */
static uint8_t phy_get_rf_gain_qdb(uint8_t rf_gain)
{
    uint8_t idx = (uint8_t)(rf_gain - 1U);
    if (idx < 6U) {
        return s_rf_gain_qdb[idx];
    }
    return 5U;
}

/**
 * @brief Program the 4-bit RF PA stage-10 gain field across all 24 per-rate TX power registers.
 *
 * @param stage10  4-bit PA stage-10 gain code (0x00 = minimum, 0x0F = full nominal gain).
 */
static void phy_set_rf_gain_stage10(uint8_t stage10)
{
    uint32_t val = ((uint32_t)(stage10 & 0x0FU)) << PHY_RF_TXPWR_STAGE10_SHIFT;
    for (uint32_t i = 0U; i < PHY_RF_TXPWR_REGS; i++) {
        PHY_REG_RMW(PHY_RF_TXPWR_REG(i), PHY_RF_TXPWR_STAGE10_MASK, val);
    }
}

/**
 * @brief Subtract a clamped PA saturation backoff from all 6 target TX power tiers.
 *
 * @param out_pwr  Output array of 6 adjusted target powers (0.25 dBm units).
 * @param in_pwr   Input array of 6 nominal VDD33-adjusted target powers (0.25 dBm units).
 * @param backoff  PA backoff to subtract (0.25 dB units; clamped to <= 24, i.e. 6.0 dB).
 */
static void phy_target_power_add_backoff(int8_t out_pwr[6], const int8_t in_pwr[6],
                                         int16_t backoff)
{
    if (backoff > PHY_TXPWR_MAX_BACKOFF_QDB) {
        backoff = PHY_TXPWR_MAX_BACKOFF_QDB;
    }
    for (uint32_t i = 0U; i < PHY_TXPWR_LEVEL_COUNT; i++) {
        out_pwr[i] = (int8_t)(in_pwr[i] - (int8_t)backoff);
    }
}

/**
 * @brief Compute the TX power offset (0.25 dB) caused by VDD33 drift since boot calibration.
 *
 * Converts both the supplied runtime VDD33 and the boot-time reference VDD33 stored in
 * g_phy_sleep_params.vdd33_tsen_off[31:16] to 0.125 dB units via phy_linear_to_db(),
 * then scales the voltage ratio (20*log10(V/V0) -> 0.25 dB steps via (diff*2 + 2) >> 2).
 *
 * @param vdd33  Current supply voltage in mV (values outside 1800..3300 mV fall back to 3300).
 * @return       Signed TX power compensation in 0.25 dB units, clamped to [-127, +127].
 */
static int8_t phy_get_vdd33_offset(uint16_t vdd33)
{
    if ((uint16_t)(vdd33 - PHY_VDD33_MIN_MV) > PHY_VDD33_SPAN_MV) {
        vdd33 = PHY_VDD33_DEFAULT_MV;
    }

    uint16_t cal_vdd33 = (uint16_t)(g_phy_sleep_params.vdd33_tsen_off >> 16);
    int32_t db_cur = phy_linear_to_db((int32_t)vdd33, 3U);
    int32_t db_cal = phy_linear_to_db((int32_t)cal_vdd33, 3U);
    int32_t diff = (((db_cur - db_cal) * 2) + 2) >> 2;

    if (diff < -127) {
        diff = -127;
    } else if (diff > 127) {
        diff = 127;
    }
    return (int8_t)diff;
}

/**
 * @brief Compute the effective 6-tier target TX powers for the active channel and VDD33 offset.
 *
 * Piecewise-linearly interpolates the 4 calibrated anchor-band PA backoffs (Ch 1, 6, 11, 14)
 * to g_phy_sleep_params.cur_chan (accounting for the wider 12 MHz gap between Ch 11 and
 * Ch 14 via the 5/22 slope factor), subtracts the backoff, and adds vdd_off.
 *
 * @param out_pwr  Output array receiving the 6 effective target TX powers (0.25 dBm).
 * @param vdd_off  Signed runtime VDD33 compensation offset (0.25 dB).
 */
static void phy_get_phy_target_power(int8_t out_pwr[6], int8_t vdd_off)
{
    uint8_t chan = g_phy_sleep_params.cur_chan;
    int32_t backoff;

    /* Piecewise-linear interpolation across anchor channels {1, 6, 11, 14}
     * (Ch 1..11 spacing is 5 MHz/ch; Ch 11->14 span is 22 MHz vs 5 MHz/ch for 12..13). */
    if (chan < 7U) {
        int32_t b0 = g_phy_sleep_params.tx_pwr_backoff[0];
        int32_t b1 = g_phy_sleep_params.tx_pwr_backoff[1];
        backoff = b0 + ((b1 - b0) * ((int32_t)chan - 1)) / 5;
    } else if (chan < 12U) {
        int32_t b1 = g_phy_sleep_params.tx_pwr_backoff[1];
        int32_t b2 = g_phy_sleep_params.tx_pwr_backoff[2];
        backoff = b1 + ((b2 - b1) * ((int32_t)chan - 6)) / 5;
    } else if (chan < 14U) {
        int32_t b2 = g_phy_sleep_params.tx_pwr_backoff[2];
        int32_t b3 = g_phy_sleep_params.tx_pwr_backoff[3];
        backoff = b2 + (((b3 - b2) * ((int32_t)chan - 11) * 5) / 22);
    } else {
        backoff = g_phy_sleep_params.tx_pwr_backoff[3];
    }

    phy_target_power_add_backoff(out_pwr, g_phy_sleep_params.target_power_vdd,
                                 (int16_t)backoff);
    for (uint32_t i = 0U; i < PHY_TXPWR_LEVEL_COUNT; i++) {
        out_pwr[i] = (int8_t)(out_pwr[i] + vdd_off);
    }
}

/* --------------------------------------------------------------------------
 * RC Filter Calibration (40 MHz & 26/24 MHz XTAL)
 * -------------------------------------------------------------------------- */

/**
 * @brief Calibrate and load the analog RX and TX baseband RC low-pass filter capacitor trims.
 *
 * When PHY_PARAM_RCCAL_VALID is not yet set, triggers the on-chip RC time-constant
 * measurement engine (I2C block BIAS_RC) using the appropriate crystal divider
 * (40 MHz vs 26/24 MHz), converts the 6-bit measurement into rx_filt_dcap and
 * tx_filt_dcap codes, and caches them in g_phy_sleep_params. Always writes the
 * resulting capacitor trims into RX_ANA reg 2 and TX_FILT reg 1.
 */
void phy_rc_cal(void)
{
    if ((g_phy_sleep_params.param_flag & PHY_PARAM_RCCAL_VALID) == 0U) {
        /* RC-cal reference divider: 2 for 40 MHz XTAL, 1 for 26/24 MHz XTAL */
        uint8_t xtal_mode = (chip6_phy_init_ctrl[PHY_CTRL_XTAL_FREQ] == PHY_XTAL_40MHZ) ? 2U : 1U;

        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 0U, 5U, 4U, 0U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 4U, 7U, 4U, xtal_mode);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_RC_REF, PHY_I2C_HOST_3, 1U, 0U, 0U, 1U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 6U, 4U, 0U, 8U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 4U, 0U, 0U, 1U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 3U, 6U, 6U, 1U);
        /* Rising edge on BIAS_RC reg 4[3] starts the RC oscillation count */
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 4U, 3U, 3U, 0U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 4U, 3U, 3U, 1U);

        ets_delay_us(100U);

        uint32_t v = rom_i2c_readReg_Mask(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 5U, 5U, 0U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_RC_REF, PHY_I2C_HOST_3, 1U, 0U, 0U, 0U);

        /* Flag out-of-range RC count (valid window: 3..60) */
        if ((uint8_t)(v - 3U) > 0x39U) {
            g_phy_check_result |= PHY_CHECK_RC_CAL_FAIL_BIT;
        }

        /* Map raw RC count to empirical RX/TX low-pass filter capacitor codes */
        int32_t rx_dcap;
        if (chip6_phy_init_ctrl[PHY_CTRL_XTAL_FREQ] == PHY_XTAL_40MHZ) {
            rx_dcap = ((int32_t)v * 11 - 14) / 20;
        } else {
            rx_dcap = ((int32_t)v * 16 - 39) / 30;
        }
        uint32_t tx_dcap = (((v * 28U) / 9U) + 2U) >> 2;

        g_phy_sleep_params.rx_filt_dcap = (uint8_t)rx_dcap;
        g_phy_sleep_params.tx_filt_dcap = (uint8_t)tx_dcap;
        g_phy_sleep_params.param_flag |= PHY_PARAM_RCCAL_VALID;
    }

    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_ANA, PHY_I2C_HOST_1, PHY_I2C_RX_ANA_FILT_REG,
                     (uint8_t)(g_phy_sleep_params.rx_filt_dcap | 0xA0U));
    rom_i2c_writeReg(PHY_I2C_BLOCK_TX_FILT, PHY_I2C_HOST_3, PHY_I2C_TX_FILT_DCAP_REG,
                     (uint8_t)(g_phy_sleep_params.tx_filt_dcap | 0x40U));
}

/* --------------------------------------------------------------------------
 * TX DC Offset Calibration & RF Analog Gain Register Loading
 * -------------------------------------------------------------------------- */

/**
 * @brief Program the RF analog gain and 7-bit TX DC I/Q offset into all 24 hardware TX slots.
 *
 * Updates PHY_RF_TXPWR_REG(0..23) bits [19:8] with rf_ana_gain, and packs the paired
 * 7-bit I/Q TX DC offsets into PHY_RF_TX_DC_REG(0..23) (two slots per 32-bit word:
 * even slots in [13:0], odd slots in [27:14]).
 *
 * @param rf_ana_gain  12-bit packed RF + TXBB analog gain word.
 * @param dc_iq        Two-element array: dc_iq[0] = 7-bit I offset, dc_iq[1] = 7-bit Q offset.
 */
void phy_set_rfanagain_dc_reg(uint16_t rf_ana_gain, const int8_t dc_iq[2])
{
    uint32_t gain_bits = ((uint32_t)(rf_ana_gain & 0x0FFFU)) << PHY_RF_TXPWR_ANA_GAIN_SHIFT;
    uint32_t i_off = (uint32_t)(uint8_t)dc_iq[0] & PHY_RF_TX_DC_7BIT_MASK;
    uint32_t q_off = (uint32_t)(uint8_t)dc_iq[1] & PHY_RF_TX_DC_7BIT_MASK;

    for (uint32_t i = 0U; i < PHY_RF_TXPWR_REGS; i++) {
        PHY_REG_RMW(PHY_RF_TXPWR_REG(i), PHY_RF_TXPWR_ANA_GAIN_MASK, gain_bits);

        if ((i & 1U) == 0U) {
            PHY_REG_RMW(PHY_RF_TX_DC_REG(i), PHY_RF_TX_DC_EVEN_MASK, (q_off << 7) | i_off);
        } else {
            PHY_REG_RMW(PHY_RF_TX_DC_REG(i), PHY_RF_TX_DC_ODD_MASK, (q_off << 21) | (i_off << 14));
        }
    }
}

/**
 * @brief Look up calibrated TX DC I/Q offsets for a TXBB analog gain and optionally write PBUS.
 *
 * @param gain        Packed RF/TXBB analog gain word (low 5 bits select the TXBB gain code).
 * @param out_iq      Output array: out_iq[0] = I DC code, out_iq[1] = Q DC code.
 * @param apply_pbus  Non-zero to immediately force the codes onto PBUS TXDC I/Q channels.
 */
void phy_set_txdc_pbus(uint16_t gain, int8_t out_iq[2], uint8_t apply_pbus)
{
    uint8_t idx = phy_txbbgain2dcoindex((uint8_t)(gain & 0x1FU));
    uint16_t packed = g_phy_sleep_params.txdc[idx];

    out_iq[0] = (int8_t)(packed & 0xFFU);
    out_iq[1] = (int8_t)((packed >> 8) & 0xFFU);

    if (apply_pbus != 0U) {
        phy_pbus_force(PHY_PBUS_CH_TXBB_DCO_I, PHY_PBUS_WIDTH_2, (uint16_t)(int16_t)out_iq[0]);
        phy_pbus_force(PHY_PBUS_CH_TXEN_DCO_Q, PHY_PBUS_WIDTH_2, (uint16_t)(int16_t)out_iq[1]);
    }
}

/**
 * @brief Measure TX carrier-leakage DC offset I/Q codes via damped binary search on MCAL_TXDC.
 *
 * Forces the requested TXBB gain on PBUS, then iterates the hardware TX DC sign
 * comparator (PHY_MCAL_TXDC_REG) for `samples` steps starting at midscale (64) with a
 * decaying step size (`28 -> 15 -> 8 -> 5 -> 3 -> 2 -> 1`). Averages the last 4 steps
 * to suppress comparator dither and applies the result to PBUS (and optionally BB_TXDC_EN).
 *
 * @param write_bb  Non-zero to also commit the averaged I/Q codes into PHY_BB_TXDC_EN_REG.
 * @param tx_gain   TXBB analog gain code forced on PBUS channel 0 width 1.
 * @param samples   Number of comparator iterations (typically 12; must be >= 4).
 * @param out_iq    Output array receiving calibrated 7-bit codes: out_iq[0]=I, out_iq[1]=Q.
 */
static void phy_cal_tos_v60(uint8_t write_bb, uint16_t tx_gain, uint8_t samples,
                            int8_t out_iq[2])
{
    int32_t code_i = PHY_TXDC_MIDSCALE;
    int32_t code_q = PHY_TXDC_MIDSCALE;
    int32_t acc_i = 0;
    int32_t acc_q = 0;
    int32_t step = PHY_TXDC_INIT_STEP;

    phy_pbus_force(PHY_PBUS_CH_TXBB_DCO_I, PHY_PBUS_WIDTH_1, tx_gain);

    for (uint8_t n = 0U; n < samples; n++) {
        phy_pbus_force(PHY_PBUS_CH_TXEN_DCO_Q, PHY_PBUS_WIDTH_2, (uint16_t)code_q);
        phy_pbus_force(PHY_PBUS_CH_TXBB_DCO_I, PHY_PBUS_WIDTH_2, (uint16_t)code_i);

        /* Arm and trigger hardware TXDC sign comparator, then poll DONE bit */
        PHY_REG_WRITE(PHY_MCAL_TXDC_REG, PHY_MCAL_ARM);
        PHY_REG_WRITE(PHY_MCAL_TXDC_REG, PHY_MCAL_TRIGGER);
        ets_delay_us(2U);

        for (uint32_t t = 0U; t < PHY_TXDC_POLL_LIMIT; t++) {
            if ((PHY_REG_READ(PHY_MCAL_TXDC_REG) & PHY_MCAL_DONE) != 0U) {
                break;
            }
        }

        /* Bit 31 (sign bit) = I comparator polarity; bit 30 (PHY_MCAL_QFLAG) = Q polarity */
        uint32_t sign_i = PHY_REG_READ(PHY_MCAL_TXDC_REG);
        uint32_t sign_q = PHY_REG_READ(PHY_MCAL_TXDC_REG);

        if ((int32_t)sign_i < 0) {
            code_i -= step;
            if (code_i < 0) {
                code_i = 0;
            }
        } else {
            code_i += step;
            if (code_i > PHY_TXDC_MAX_CODE) {
                code_i = PHY_TXDC_MAX_CODE;
            }
        }

        if ((sign_q & PHY_MCAL_QFLAG) != 0U) {
            code_q -= step;
            if (code_q < 0) {
                code_q = 0;
            }
        } else {
            code_q += step;
            if (code_q > PHY_TXDC_MAX_CODE) {
                code_q = PHY_TXDC_MAX_CODE;
            }
        }

        step = (step == 2) ? 1 : ((step >> 1) + 1);

        if ((int32_t)n >= (int32_t)samples - PHY_TXDC_AVG_WINDOW) {
            acc_i += code_i;
            acc_q += code_q;
        }
    }

    int32_t avg_q = (acc_q + 2) >> 2;
    int32_t avg_i = (acc_i + 2) >> 2;

    phy_pbus_force(PHY_PBUS_CH_TXEN_DCO_Q, PHY_PBUS_WIDTH_2, (uint16_t)avg_q);
    phy_pbus_force(PHY_PBUS_CH_TXBB_DCO_I, PHY_PBUS_WIDTH_2, (uint16_t)avg_i);
    phy_pbus_force(PHY_PBUS_CH_TXEN_DCO_Q, PHY_PBUS_WIDTH_1, 0x7FU);
    PHY_REG_WRITE(PHY_MCAL_TXDC_REG, PHY_MCAL_STOP);

    out_iq[0] = (int8_t)avg_i;
    out_iq[1] = (int8_t)avg_q;

    if (write_bb != 0U) {
        PHY_REG_RMW(PHY_BB_TXDC_EN_REG, 0xFFFC0000U,
                    (((uint32_t)avg_q & PHY_RF_TX_DC_7BIT_MASK) << 25) |
                    (((uint32_t)avg_i & PHY_RF_TX_DC_7BIT_MASK) << 18));
    }
}

/**
 * @brief Calibrate TX DC offsets across all 4 TXBB analog gain settings and populate hardware.
 *
 * Skips calibration if PHY_PARAM_TXDC_VALID is already set in *param_flag (e.g., recovered
 * from RTC/NVS calibration data). Otherwise enters PBUS debug mode, sweeps the 4 gain codes
 * in s_txbb_gain_tbl[], stores packed `(I | Q << 8)` entries into txdc[0..3], loads the
 * active RF analog gain & DC offset registers, and sets PHY_PARAM_TXDC_VALID.
 *
 * @param param_flag  In/out pointer to calibration validity bitmask (g_phy_sleep_params.param_flag).
 * @param txdc        Output array of 4 packed `(I | (Q << 8))` TX DC offset entries.
 */
void phy_init_cal_dcoffset(uint32_t *param_flag, uint16_t txdc[4])
{
    if ((*param_flag & PHY_PARAM_TXDC_VALID) == 0U) {
        int8_t iq[2];

        phy_pbus_enter_debugmode((uint16_t)(s_tx_rf_ana_gain & 0x1FU));
        phy_pbus_force(PHY_PBUS_CH_TXEN_DCO_Q, PHY_PBUS_WIDTH_1, 0x1FU);

        for (uint32_t i = 0U; i < 4U; i++) {
            phy_cal_tos_v60(0U, s_txbb_gain_tbl[i], 12U, iq);
            txdc[i] = (uint16_t)((uint16_t)(uint8_t)iq[0] |
                                 ((uint16_t)(uint8_t)iq[1] << 8));
        }

        phy_set_txdc_pbus(s_tx_rf_ana_gain, iq, 1U);
        phy_set_rfanagain_dc_reg(s_tx_rf_ana_gain, iq);
        phy_pbus_exit_debugmode();
        *param_flag |= PHY_PARAM_TXDC_VALID;
    }
}

/* --------------------------------------------------------------------------
 * VDD33 TX Power Offset
 * -------------------------------------------------------------------------- */

/**
 * @brief Measure or derive boot-time VDD33 and compute VDD33-adjusted target TX powers.
 *
 * Reads chip6_phy_init_ctrl[PHY_CTRL_VDD33_CONST]:
 * - 0xFF: measures VDD33 live via internal SAR ADC (`phy_readvdd33(1)`).
 * - 18..36: treats value as fixed supply voltage in 0.1 V steps (`* 102` raw units).
 * - Other: assumes nominal 3.3 V (`PHY_VDD33_NOMINAL_RAW = 0x0D33`).
 * When below nominal 3.3 V, reduces all 6 target power tiers proportionally in 0.25 dB
 * units and saves `(vdd_raw << 16) | (tot_off & 0xFF)` in g_phy_sleep_params.vdd33_tsen_off.
 *
 * @param extra_off  Additional signed offset in 0.25 dB units added to the VDD33 offset.
 */
void phy_txpwr_offset(int16_t extra_off)
{
    uint8_t vdd_cfg = chip6_phy_init_ctrl[PHY_CTRL_VDD33_CONST];
    uint32_t vdd_raw;
    int32_t vdd_off = 0;

    if (vdd_cfg == PHY_VDD33_MODE_MEASURE) {
        vdd_raw = phy_readvdd33(1U);
    } else if ((uint8_t)(vdd_cfg - PHY_VDD33_CFG_MIN_DV) <= PHY_VDD33_CFG_SPAN_DV) {
        vdd_raw = (uint32_t)vdd_cfg * PHY_VDD33_DV_TO_RAW;
    } else {
        vdd_raw = PHY_VDD33_NOMINAL_RAW;
    }

    if (vdd_raw < PHY_VDD33_NOMINAL_RAW) {
        int32_t db_cur = phy_linear_to_db((int32_t)vdd_raw, 3U);
        int32_t db_nom = phy_linear_to_db((int32_t)PHY_VDD33_NOMINAL_RAW, 3U);
        vdd_off = (((db_cur - db_nom) * 2) + 2) >> 2;
    }

    int32_t tot_off = vdd_off + (int32_t)extra_off;
    for (uint32_t i = 0U; i < PHY_TXPWR_LEVEL_COUNT; i++) {
        g_phy_sleep_params.target_power_vdd[i] =
            (int8_t)((int8_t)chip6_phy_init_ctrl[PHY_CTRL_TARGET_PWR_BASE + i] + (int8_t)tot_off);
    }

    if (tot_off < -127) {
        tot_off = -127;
    }
    g_phy_sleep_params.vdd33_tsen_off = (vdd_raw << 16) | ((uint32_t)tot_off & 0xFFU);
}

/* --------------------------------------------------------------------------
 * TX Power Calibration Servo & TX Capacitor Bank Tuning
 * -------------------------------------------------------------------------- */

/**
 * @brief Closed-loop TX tone attenuation servo targeting one or more TX power levels.
 *
 * Sweeps target_pwr[] from highest index (lowest power) down to lowest index (highest
 * power), emitting a CW calibration tone at `tone_freq` and reading the on-chip SAR power
 * detector twice per step. Converges each tier's baseband attenuation (0..100 in 0.25 dB)
 * using damped proportional feedback, subtracts `atten_bias`, and stores the signed
 * result in `out_atten[]`. When low-power fixed gain mode is enabled, calibrates only the
 * lowest power tier and derives the remaining tiers linearly from target_power_vdd[].
 *
 * @param tone_freq   DDS TX calibration tone frequency code (typically 0x40).
 * @param target_pwr  Array of `count` target TX powers (0.25 dBm units).
 * @param count       Number of power tiers to calibrate (1 or 6).
 * @param atten_bias  Baseband attenuation zero-reference bias subtracted from output (typically 0x1F).
 * @param init_atten  Starting baseband attenuation guess for the first (lowest-power) tier.
 * @param out_atten   Output array of `count` signed baseband attenuation values (0.25 dB).
 * @param sar_ref     Reference dB offset passed to phy_get_power_db() (typically 0x0138).
 */
static void phy_rfcal_pwrctrl(uint8_t tone_freq, const int8_t *target_pwr,
                              uint8_t count, uint8_t atten_bias, int8_t init_atten,
                              int8_t *out_atten, uint16_t sar_ref)
{
    int32_t stop_idx = (chip6_phy_init_ctrl[PHY_CTRL_LOW_PWR_EN] != 0U) ? ((int32_t)count - 1) : 0;
    int32_t servo_off = 0;

    for (int32_t idx = (int32_t)count - 1; idx >= stop_idx; idx--) {
        int32_t tgt = (int32_t)(uint8_t)target_pwr[idx];
        if (idx < (int32_t)count - 1) {
            /* Warm-start next tier by shifting servo_off by the nominal inter-tier dB delta */
            servo_off = (int16_t)(servo_off +
                                  ((int32_t)(uint8_t)target_pwr[idx + 1] - tgt));
        }

        int32_t prev_err = 2;
        int32_t att = 0;

        for (int32_t iter = 0; iter < 10; iter++) {
            att = (int16_t)(servo_off + (int32_t)init_atten);
            if (att < 0) {
                att = 0;
            } else if (att > PHY_TXPWR_SERVO_MAX_ATTEN) {
                att = PHY_TXPWR_SERVO_MAX_ATTEN;
            }

            phy_start_tx_tone(1U, (int16_t)tone_freq, (uint8_t)att,
                              0U, 0, 0U, 0U, 0, 0U);
            ets_delay_us(2U);

            /* Average two 0.125 dB SAR readings and convert to 0.25 dB: ((p1+p2) + 4) >> 3 */
            int32_t p1 = phy_get_power_db(sar_ref);
            int32_t p2 = phy_get_power_db(sar_ref);
            int32_t meas = ((int16_t)(p1 + p2) + 4) >> 3;
            if (meas < 0) {
                meas = 0;
            }

            int32_t err = meas - tgt;
            if (err > PHY_TXPWR_SERVO_ERR_CLAMP) {
                err = PHY_TXPWR_SERVO_ERR_CLAMP;
            } else if (err < -PHY_TXPWR_SERVO_ERR_CLAMP) {
                err = -PHY_TXPWR_SERVO_ERR_CLAMP;
            }

            /* Stop on exact convergence, +/-0.25 dB oscillation, or attenuation rail hit */
            if ((err == 0 && iter > 0) ||
                (err == -1 && prev_err >= 0 && prev_err < 2)) {
                break;
            }
            if (att == 0 && err < 0) {
                break;
            }
            if (att == PHY_TXPWR_SERVO_MAX_ATTEN && err > 0) {
                break;
            }

            /* Damped update: apply 0.75x gain when |err| > 2 to avoid PA-compression overshoot */
            int32_t next_off = servo_off + err;
            if ((uint16_t)(err + 2) > 4U) {
                next_off -= (err >> 2);
            }
            servo_off = (int16_t)next_off;
            prev_err = err;
        }

        int32_t final_att = att - (int32_t)atten_bias;
        if (final_att < -PHY_TXPWR_MAX_BACKOFF_QDB) {
            final_att = -PHY_TXPWR_MAX_BACKOFF_QDB;
        }
        out_atten[idx] = (int8_t)final_att;
    }

    int32_t last = (int32_t)count - 1;
    if ((int32_t)out_atten[last] - (int32_t)out_atten[0] > PHY_TXPWR_SERVO_MAX_DIFF) {
        out_atten[0] = (int8_t)(out_atten[last] - PHY_TXPWR_SERVO_MAX_DIFF);
    }

    if (chip6_phy_init_ctrl[PHY_CTRL_LOW_PWR_EN] != 0U) {
        for (int32_t i = 0; i < last; i++) {
            out_atten[i] = (int8_t)(out_atten[last] +
                                    g_phy_sleep_params.target_power_vdd[last] -
                                    g_phy_sleep_params.target_power_vdd[i]);
        }
    }

    phy_stop_tx_tone(1U);
}

/**
 * @brief Tune the 3-stage RF TX matching-network capacitor bank for peak linear output power.
 *
 * Emits a continuous calibration tone and sweeps each of the three capacitor fields in
 * I2C block PHY_I2C_BLOCK_TX_PA (reg 1[3:0] odd codes 1..15, reg 2[3:0] 0..15, reg 2[6:4] 0..7),
 * locking each stage to the code that maximizes phy_txtone_linear_pwr().
 *
 * @param tone_freq  DDS TX calibration tone frequency code.
 * @param atten      Baseband tone attenuation used during the sweep.
 * @param avg_cnt    Number of SAR readings averaged per candidate capacitor code.
 * @param out_cap    Output 3-byte array receiving optimal capacitor codes [stage0, stage1, stage2].
 */
static void phy_rfcal_txcap(uint8_t tone_freq, uint8_t atten, uint8_t avg_cnt,
                            uint8_t out_cap[3])
{
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                          PHY_I2C_ANA_INF_TX_SCALE_REG, 7U, 0U, 0U);
    phy_start_tx_tone(1U, (int16_t)tone_freq, atten, 0U, 0, 0U, 0U, 0, 0U);

    static const uint8_t s_reg_addr[3] = { 1U, 2U, 2U };
    static const uint8_t s_msb[3] = { 3U, 3U, 6U };
    static const uint8_t s_lsb[3] = { 0U, 0U, 4U };
    static const uint8_t s_max_k[3] = { 7U, 15U, 7U };

    for (uint8_t stage = 0U; stage < 3U; stage++) {
        uint8_t best_val = 0U;
        int32_t best_pwr = 0;

        for (uint8_t k = 0U; k <= s_max_k[stage]; k++) {
            uint8_t val = (stage == 0U) ? (uint8_t)(k * 2U + 1U) : k;
            rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2,
                                  s_reg_addr[stage], s_msb[stage], s_lsb[stage], val);

            int32_t pwr = phy_txtone_linear_pwr(avg_cnt, 10U);
            if (pwr > best_pwr) {
                best_pwr = pwr;
                best_val = val;
            }
        }

        out_cap[stage] = best_val;
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2,
                              s_reg_addr[stage], s_msb[stage], s_lsb[stage], best_val);
    }

    phy_stop_tx_tone(1U);
}

/**
 * @brief Load calibrated TX PA capacitor bank trims for a Wi-Fi channel into TX_PA I2C regs.
 *
 * Groups channels 1..14 into 4 bands via `chan >> 2` (0: Ch 1-3, 1: Ch 4-7, 2: Ch 8-11,
 * 3: Ch 12-14) and writes the corresponding 3-byte capacitor setting to TX_PA regs 1 and 2.
 *
 * @param txcap  4x3 array of calibrated capacitor codes (g_phy_sleep_params.txcap).
 * @param chan   Active IEEE 802.11 channel number (1..14).
 */
void phy_set_txcap_reg(const uint8_t txcap[4][3], uint8_t chan)
{
    uint8_t grp = (uint8_t)((chan >> 2) & 0x03U);
    uint8_t c0 = txcap[grp][0];
    uint8_t c1 = txcap[grp][1];
    uint8_t c2 = txcap[grp][2];

    rom_i2c_writeReg(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2, 1U, (uint8_t)(c0 | 0x40U));
    rom_i2c_writeReg(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2, 2U,
                     (uint8_t)(((c2 & 0x0FU) << 4) | c1));
}

/**
 * @brief Calibrate TX PA matching capacitors across Ch 1, 6, 11 (or reuse cached RTC values).
 *
 * When PHY_PARAM_TXCAP_VALID is clear, enters PBUS debug mode, runs a preliminary TX power
 * servo on Ch 1 (target 12 dBm / 0x30 qdBm) to pick a non-saturating tone attenuation, then
 * optimizes TX_PA capacitors on Ch 1, 6, and 11 (cloning band 2 to band 3 for Ch 12..14).
 * Applies the active channel's TXCAP registers unless called during fast RF wakeup.
 */
void phy_tx_cap_init(void)
{
    if ((g_phy_sleep_params.param_flag & PHY_PARAM_TXCAP_VALID) == 0U) {
        int8_t dc_iq[2];

        phy_pbus_debugmode();
        phy_pbus_xpd_rx_off(1);
        phy_pbus_xpd_tx_on((uint16_t)(s_tx_rf_ana_gain & 0x0FFFU));
        phy_set_txdc_pbus(s_tx_rf_ana_gain, dc_iq, 1U);
        phy_en_pwdet(0U);

        for (uint8_t i = 0U; i < 3U; i++) {
            phy_set_chan_60(s_txcap_chans[i], chip6_phy_init_ctrl[PHY_CTRL_XTAL_FREQ], 0U,
                            g_phy_freq_offset, &g_phy_sleep_params, 100U, 1U);
            if (i == 0U) {
                int8_t tgt = 0x30; /* 12.0 dBm safe linear measurement target */
                int8_t att_out = 0;

                /* Reset PA capacitor bank to mid-range defaults before finding baseline atten */
                rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2, 1U, 3U, 0U, 0x0FU);
                rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2, 2U, 3U, 0U, 7U);
                rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2, 2U, 6U, 4U, 3U);

                g_phy_rfcal_bb_atten_init = 0x50U;
                phy_rfcal_pwrctrl(PHY_TONE_FREQ_CAL_DEFAULT, &tgt, 1U,
                                  PHY_CAL_BB_ATTEN_BIAS, 0x50, &att_out,
                                  PHY_SAR_PWDET_REF_DEFAULT);
                g_phy_rfcal_bb_atten_init = (uint8_t)(att_out + (int8_t)PHY_CAL_BB_ATTEN_BIAS);
            }

            uint8_t *cap = g_phy_sleep_params.txcap[i];
            phy_rfcal_txcap(PHY_TONE_FREQ_CAL_DEFAULT, g_phy_rfcal_bb_atten_init, 2U, cap);
            if (cap[0] == 0U && cap[1] == 0U && cap[2] == 0U) {
                cap[0] = 0x0FU;
                cap[1] = 7U;
                cap[2] = 3U;
            }
        }

        /* Reuse Ch 11 capacitor tuning for Ch 12..14 band */
        g_phy_sleep_params.txcap[3][0] = g_phy_sleep_params.txcap[2][0];
        g_phy_sleep_params.txcap[3][1] = g_phy_sleep_params.txcap[2][1];
        g_phy_sleep_params.txcap[3][2] = g_phy_sleep_params.txcap[2][2];

        phy_pbus_xpd_tx_off();
        phy_pbus_xpd_rx_on();
        phy_pbus_workmode();
        g_phy_sleep_params.param_flag |= PHY_PARAM_TXCAP_VALID;
    }

    if ((g_phy_sleep_params.param_flag & PHY_PARAM_WAKEUP_RF) == 0U) {
        phy_set_txcap_reg(g_phy_sleep_params.txcap, g_phy_sleep_params.cur_chan);
    }
}

/* --------------------------------------------------------------------------
 * RF Analog Gain Calibration, PA Backoff & TX Power Control
 * -------------------------------------------------------------------------- */

/**
 * @brief Adjust packed RF + TXBB analog gain to absorb a requested attenuation delta (0.25 dB).
 *
 * Unpacks the 12-bit `rf_ana_gain` into its 3-bit RF gain index (`[11:9]`) and linearized
 * TXBB analog gain code (`bb_gain` in `{4, 6, 8, 10}`, where each 2-unit step equals
 * 2.0 dB = 8 qdB). Steps TXBB and RF analog stages in the direction of `*delta_atten`,
 * updating `*delta_atten` with any unabsorbed residual and repacking `*rf_ana_gain`.
 *
 * @param delta_atten  In/out signed attenuation adjustment needed (0.25 dB units); returns residual.
 * @param rf_ana_gain  In/out 12-bit packed `(((rf_gain * 16) + 15) << 5) | txbb_code`.
 */
static void phy_correct_rf_ana_gain(int8_t *delta_atten, uint16_t *rf_ana_gain)
{
    uint16_t cur = *rf_ana_gain;
    /* Decode non-linear TXBB encoding: 0x04 -> 4; 0x10..0x14 -> 6..10 */
    uint8_t bb_gain = (uint8_t)(((cur >> 4) & 1U) * 6U + (cur & 0x0FU));
    uint8_t rf_gain = (uint8_t)((cur >> 9) & 7U);

    if (*delta_atten <= 0) {
        if (*delta_atten != 0) {
            /* Need less analog gain: step down upper TXBB, then RF PA, then final TXBB 6->4 */
            while (*delta_atten < 0 && bb_gain >= 7U) {
                *delta_atten = (int8_t)(*delta_atten + 8);
                bb_gain = (uint8_t)(bb_gain - 2U);
            }
            while (*delta_atten < 0 && rf_gain > 1U) {
                rf_gain = (uint8_t)(rf_gain - 1U);
                *delta_atten = (int8_t)(*delta_atten + (int8_t)phy_get_rf_gain_qdb(rf_gain));
            }
            if (*delta_atten < 0 && bb_gain == 6U) {
                *delta_atten = (int8_t)(*delta_atten + 8);
                bb_gain = 4U;
            }
        }
    } else {
        /* Need more analog gain: step TXBB 4->6, then RF PA up to 7, then upper TXBB */
        if (bb_gain == 4U) {
            *delta_atten = (int8_t)(*delta_atten - 8);
            bb_gain = 6U;
        }
        while (*delta_atten > 0 && rf_gain != 7U) {
            *delta_atten = (int8_t)(*delta_atten - (int8_t)phy_get_rf_gain_qdb(rf_gain));
            rf_gain = (uint8_t)(rf_gain + 1U);
        }
        while (*delta_atten > 0 && bb_gain < 10U) {
            *delta_atten = (int8_t)(*delta_atten - 8);
            bb_gain = (uint8_t)(bb_gain + 2U);
        }
    }

    /* Re-encode linearized bb_gain back into hardware 5-bit TXBB code (6..10 -> 0x10..0x14) */
    if (bb_gain > 5U) {
        bb_gain = (uint8_t)(bb_gain + 10U);
    }
    *rf_ana_gain = (uint16_t)(((((uint16_t)rf_gain * 16U) + 15U) << 5) + bb_gain);
}

/**
 * @brief Center the RF/TXBB analog gain so digital TX attenuation sits in its sweet spot (12..36).
 *
 * Calibrates tier 5 (lowest nominal target TX power) on the active channel starting from
 * PHY_TX_RF_ANA_GAIN_DEFAULT (0x0BF0). If the resulting digital attenuation falls outside
 * [12, 36] (3..9 dB), shifts `s_tx_rf_ana_gain` toward center (24) via phy_correct_rf_ana_gain()
 * and re-verifies once, then commits the RF analog gain + matching TXDC to hardware registers
 * and g_phy_sleep_params.rf_ana_gain.
 */
static void phy_cal_rf_ana_gain(void)
{
    int8_t dc_iq[2];
    int8_t tgt = g_phy_sleep_params.target_power_vdd[5];
    int8_t att_out = 0;

    s_tx_rf_ana_gain = PHY_TX_RF_ANA_GAIN_DEFAULT;
    g_phy_rfcal_bb_atten_init = 0x3CU;

    for (uint8_t iter = 0U; iter < 2U; iter++) {
        phy_pbus_force(PHY_PBUS_CH_RF_GAIN, PHY_PBUS_WIDTH_1, (uint16_t)(s_tx_rf_ana_gain >> 5));
        phy_pbus_force(PHY_PBUS_CH_TXBB_DCO_I, PHY_PBUS_WIDTH_1, (uint16_t)(s_tx_rf_ana_gain & 0x1FU));
        phy_set_txdc_pbus(s_tx_rf_ana_gain, dc_iq, 1U);

        phy_rfcal_pwrctrl(PHY_TONE_FREQ_CAL_DEFAULT, &tgt, 1U, PHY_CAL_BB_ATTEN_BIAS,
                          (int8_t)g_phy_rfcal_bb_atten_init, &att_out, PHY_SAR_PWDET_REF_DEFAULT);
        g_phy_rfcal_bb_atten_init = (uint8_t)(att_out + (int8_t)PHY_CAL_BB_ATTEN_BIAS);

        if (att_out >= 12 && att_out <= 36) {
            break;
        }

        att_out = (int8_t)(24 - att_out);
        phy_correct_rf_ana_gain(&att_out, &s_tx_rf_ana_gain);
        phy_pbus_force(PHY_PBUS_CH_RF_GAIN, PHY_PBUS_WIDTH_1, (uint16_t)(s_tx_rf_ana_gain >> 5));
        phy_pbus_force(PHY_PBUS_CH_TXBB_DCO_I, PHY_PBUS_WIDTH_1, (uint16_t)(s_tx_rf_ana_gain & 0x1FU));
        g_phy_rfcal_bb_atten_init = (uint8_t)(55 - att_out);
    }

    phy_set_txdc_pbus(s_tx_rf_ana_gain, dc_iq, 1U);
    phy_set_rfanagain_dc_reg(s_tx_rf_ana_gain, dc_iq);
    g_phy_sleep_params.rf_ana_gain = s_tx_rf_ana_gain;
}

/**
 * @brief Measure TX calibration tone output power averaged over two SAR readings (0.125 dB).
 *
 * @param atten  Digital baseband tone attenuation code.
 * @return       Rounded average output power in 0.125 dB units (signed).
 */
static int32_t phy_meas_tone_pwr_db(int8_t atten)
{
    phy_start_tx_tone(1U, PHY_TONE_FREQ_CAL_DEFAULT, (uint8_t)atten, 0U, 0, 0U, 0U, 0, 0U);
    int32_t p1 = phy_get_power_db(PHY_SAR_PWDET_REF_DEFAULT);
    int32_t p2 = phy_get_power_db(PHY_SAR_PWDET_REF_DEFAULT);
    phy_stop_tx_tone(1U);

    /* Arithmetic round-to-nearest divide by 4 matching vendor libphy rounding */
    int32_t sum = (int16_t)(p1 + p2);
    int32_t rounded = sum + 2;
    if (rounded < 0) {
        rounded = sum + 5;
    }
    return rounded >> 2;
}

/**
 * @brief Detect PA 1 dB compression point via a 6.5 dB two-tone step test and compute backoff.
 *
 * Drives the PA at two baseband attenuations separated by 26 quarter-dB (6.5 dB = 52 in
 * 0.125 dB units). In the linear PA region `pwr_hi - pwr_lo` is ~52; once compression
 * drops the differential below ~44 (5.5 dB, i.e. >= 1 dB compression), walks attenuation
 * until linearity is restored and returns the backoff (in 0.25 dB) below target_pwr[0].
 *
 * @param target_pwr     Array whose element [0] is the highest target TX power (0.25 dBm).
 * @param out_linear_ok  Output flag set to 1 if measured step delta > 48 (> 6.0 dB, well linear).
 * @return               Required PA saturation backoff in 0.25 dB units (0 if linear at target).
 */
static int16_t phy_tx_pwr_backoff(const int8_t *target_pwr, uint8_t *out_linear_ok)
{
    uint8_t tgt0 = (uint8_t)target_pwr[0];
    int32_t tgt2x = (int32_t)tgt0 * 2; /* Convert 0.25 dBm target to 0.125 dBm */
    int8_t cal_tgt = (tgt0 < 0x4DU) ? (int8_t)(tgt0 - 0x1AU) : 0x32;
    uint8_t search_up = (tgt0 >= 0x4DU) ? 1U : 0U;
    int8_t att_out = 0;

    phy_rfcal_pwrctrl(PHY_TONE_FREQ_CAL_DEFAULT, &cal_tgt, 1U, PHY_CAL_BB_ATTEN_BIAS,
                      (int8_t)g_phy_rfcal_bb_atten_init, &att_out, PHY_SAR_PWDET_REF_DEFAULT);
    g_phy_rfcal_bb_atten_init = (uint8_t)(att_out + (int8_t)PHY_CAL_BB_ATTEN_BIAS);

    /* Two probe points separated by 26 qdB (6.5 dB nominal input step) */
    int8_t att_lo = (int8_t)(att_out + 5);
    int8_t att_hi = (int8_t)g_phy_rfcal_bb_atten_init;
    int32_t pwr_hi = 0;
    int32_t diff = 0;
    int32_t prev_diff = 0;

    for (uint8_t iter = 0U; iter < 10U; iter++) {
        if (att_lo < 0) {
            att_lo = 0;
        }
        if (att_hi > 0x6F) {
            att_hi = 0x6F;
        }

        pwr_hi = phy_meas_tone_pwr_db(att_lo);
        int32_t pwr_lo = phy_meas_tone_pwr_db(att_hi);
        diff = (int16_t)(pwr_hi - pwr_lo);

        if (((pwr_hi < tgt2x) && (iter == 0U) && (diff > 44) && (search_up == 0U)) ||
            (search_up != 0U)) {
            search_up = 0U;
            if (diff > 43) {
                search_up = ((diff <= 44) && (pwr_hi >= tgt2x)) ? 0U : 1U;
            }
        }

        if ((diff > 44 && search_up == 0U) ||
            (search_up == 0U && diff <= prev_diff && diff > 43) ||
            (search_up != 0U && pwr_hi >= tgt2x) ||
            (pwr_lo <= 80) ||
            (att_hi == 0x6F) ||
            (att_lo == 0)) {
            break;
        }

        int8_t step = 2;
        if (search_up != 0U) {
            int32_t delta = pwr_hi - tgt2x;
            if (diff < 49 || iter != 0U) {
                step = -4;
            } else {
                step = (int8_t)((delta / 2) - 1);
            }
            if (((int32_t)step * 2) < delta) {
                step = (int8_t)((delta - 1) / 2);
            }
        }

        att_lo = (int8_t)(att_lo + step);
        att_hi = (int8_t)(att_lo + 26);
        prev_diff = (search_up == 0U) ? diff : 0;
    }

    *out_linear_ok = (diff > 48) ? 1U : 0U;
    if (pwr_hi < tgt2x) {
        return (int16_t)((tgt2x - pwr_hi + 1) >> 1);
    }
    return 0;
}

/**
 * @brief Map one of the 4 calibration anchor channels (1, 6, 11, 14) to its band index (0..3).
 *
 * @param chan  Wi-Fi channel number (1, 6, 11, or 14).
 * @return      Band index: 0 (Ch 1), 1 (Ch 6), 2 (Ch 11), or 3 (Ch 14 / other).
 */
static uint8_t phy_chan_to_band(uint8_t chan)
{
    if (chan == 1U) {
        return 0U;
    }
    if (chan == 6U) {
        return 1U;
    }
    if (chan == 11U) {
        return 2U;
    }
    return 3U;
}

/**
 * @brief Calibrate PA saturation backoff and all 6 baseband TX attenuation tiers on one band.
 *
 * Tunes to `chan`, loads TXCAP, runs phy_cal_rf_ana_gain() on Ch 6, optionally measures PA
 * saturation backoff (re-measuring and averaging when non-zero or marginally linear), logs
 * the backoff byte into PHY_FE_TX_BACKOFF_LOG_REG, and runs phy_rfcal_pwrctrl() across all
 * 6 target power levels.
 *
 * @param chan        Anchor channel to calibrate (1, 6, or 11).
 * @param do_backoff  Non-zero (1) to run PA 1 dB compression backoff detection; 0 to skip.
 */
static void phy_tx_pwctrl_init_cal(uint8_t chan, uint8_t do_backoff)
{
    int8_t adj_pwr[6];
    int16_t backoff = 0;

    phy_set_chan_60(chan, chip6_phy_init_ctrl[PHY_CTRL_XTAL_FREQ], 0U, g_phy_freq_offset,
                    &g_phy_sleep_params, 100U, 1U);
    phy_set_txcap_reg(g_phy_sleep_params.txcap, chan);

    if (chan == 6U && s_do_pwctrl_flag == 0U) {
        phy_cal_rf_ana_gain();
    }

    if (do_backoff == 1U) {
        uint8_t linear_ok = 0U;
        int16_t b1 = phy_tx_pwr_backoff(g_phy_sleep_params.target_power_vdd, &linear_ok);
        if (b1 != 0 || linear_ok == 0U) {
            int16_t b2 = phy_tx_pwr_backoff(g_phy_sleep_params.target_power_vdd, &linear_ok);
            if (b2 != 0 || linear_ok == 0U) {
                int32_t sum = (int32_t)b1 + (int32_t)b2 + 1;
                backoff = (int16_t)((sum - (sum >> 31)) >> 1);
            }
        }
    }

    phy_target_power_add_backoff(adj_pwr, g_phy_sleep_params.target_power_vdd, backoff);

    uint8_t band = phy_chan_to_band(chan);
    g_phy_sleep_params.tx_pwr_backoff[band] = backoff;

    if (do_backoff == 1U) {
        uint32_t shift = (uint32_t)band * 8U;
        PHY_REG_RMW(PHY_FE_TX_BACKOFF_LOG_REG, 0xFFU << shift,
                    ((uint32_t)(uint8_t)backoff) << shift);
    }

    g_phy_rfcal_bb_atten_init = (uint8_t)(g_phy_rfcal_bb_atten_init - 6U);
    phy_rfcal_pwrctrl(PHY_TONE_FREQ_CAL_DEFAULT, adj_pwr, PHY_TXPWR_LEVEL_COUNT,
                      PHY_CAL_BB_ATTEN_BIAS, (int8_t)g_phy_rfcal_bb_atten_init,
                      g_phy_sleep_params.tx_pwctrl_atten[band], PHY_SAR_PWDET_REF_DEFAULT);
    g_phy_rfcal_bb_atten_init = (uint8_t)(g_phy_sleep_params.tx_pwctrl_atten[band][5] + 37);

    /* Flag TX slope warning if tier 0->1 attenuation delta exceeds target power delta by > 1 dB */
    int32_t tgt_diff = (int32_t)(uint8_t)g_phy_sleep_params.target_power_vdd[0] -
                       (int32_t)(uint8_t)g_phy_sleep_params.target_power_vdd[1] + 4;
    int32_t att_diff = (int32_t)g_phy_sleep_params.tx_pwctrl_atten[band][1] -
                       (int32_t)g_phy_sleep_params.tx_pwctrl_atten[band][0];
    if (att_diff > tgt_diff) {
        g_phy_sleep_params.param_flag |= PHY_PARAM_TX_SLOPE_WARN;
    }

    if (g_phy_sleep_params.tx_pwr_backoff[band] > 4) {
        g_phy_txbk_dpdby_flag = 1U;
    }
}

/**
 * @brief Record diagnostic TX power calibration drift against previous RTC/flash values.
 *
 * Compares the newly calibrated RF/TXBB analog gain, tier-5 baseband attenuation, and
 * PA backoff against the prior values saved before recalibration, storing the worst-case
 * deltas in g_phy_txpwr_diff_flash[0..1].
 *
 * @param old_rf_ana_gain  Previous 12-bit packed rf_ana_gain before recalibration.
 * @param old_att5         Previous tier-5 attenuation for each of the 4 anchor bands.
 * @param old_backoff      Previous PA backoff for each of the 4 anchor bands.
 */
static void phy_check_tx_pwr_cal(uint16_t old_rf_ana_gain, const int8_t old_att5[4],
                                 const int16_t old_backoff[4])
{
    uint16_t cur = g_phy_sleep_params.rf_ana_gain;
    uint8_t rf_cur = (uint8_t)((cur >> 9) & 7U);
    uint8_t rf_old = (uint8_t)((old_rf_ana_gain >> 9) & 7U);

    int32_t bb_cur = (int32_t)(((cur >> 4) & 1U) * 6U + (cur & 0x0FU));
    int32_t bb_old = (int32_t)(((old_rf_ana_gain >> 4) & 1U) * 6U + (old_rf_ana_gain & 0x0FU));
    int8_t gain_diff = (int8_t)((bb_cur - bb_old) * 4);

    bool inc = (rf_old <= rf_cur);
    uint8_t lo = inc ? rf_old : rf_cur;
    uint8_t hi = inc ? rf_cur : rf_old;

    for (uint8_t r = lo; r < hi; r++) {
        int8_t step = (int8_t)phy_get_rf_gain_qdb(r);
        gain_diff = inc ? (int8_t)(gain_diff + step) : (int8_t)(gain_diff - step);
    }

    int8_t max_att_diff = 0;
    int32_t max_att_abs = 0;
    for (uint32_t i = 0U; i < PHY_TXPWR_BAND_COUNT; i++) {
        int8_t d = (int8_t)(old_att5[i] - g_phy_sleep_params.tx_pwctrl_atten[i][5]);
        int32_t a = phy_abs_i32((int32_t)d);
        if (a > max_att_abs) {
            max_att_abs = a;
            max_att_diff = d;
        }
    }

    int8_t max_bk_diff = 0;
    int32_t max_bk_abs = 0;
    for (uint32_t i = 0U; i < PHY_TXPWR_BAND_COUNT; i++) {
        int8_t d = (int8_t)((int8_t)old_backoff[i] - (int8_t)g_phy_sleep_params.tx_pwr_backoff[i]);
        int32_t a = phy_abs_i32((int32_t)d);
        if (a > max_bk_abs) {
            max_bk_abs = a;
            max_bk_diff = d;
        }
    }

    g_phy_txpwr_diff_flash[0] = (int8_t)(gain_diff + max_att_diff);
    g_phy_txpwr_diff_flash[1] = max_bk_diff;
}

/**
 * @brief Initialize or calibrate the TX power control tables across bands 1, 6, 11, and 14.
 *
 * When PHY_PARAM_TX_PWCTRL_VALID is clear, enters PBUS debug mode and calibrates Ch 6
 * (including RF analog gain centering), Ch 1, and Ch 11, cloning band 2 to band 3 (Ch 14)
 * and resetting background tracking accumulators. Otherwise restores the cached RF analog
 * gain and matching TXDC directly to hardware. Finally interpolates and loads per-rate TX
 * attenuation for the current channel unless running inside fast RF wakeup.
 *
 * @param calibrate_now  1 to run PA saturation backoff checks during calibration; 0 to skip.
 */
void phy_tx_pwctrl_init(uint8_t calibrate_now)
{
    int8_t dc_iq[2];
    int8_t tmp_atten[6];
    uint16_t saved_gain = g_phy_sleep_params.rf_ana_gain;

    if ((g_phy_sleep_params.param_flag & PHY_PARAM_TX_PWCTRL_VALID) == 0U) {
        int16_t old_backoff[4];
        int8_t old_att5[4];

        for (uint32_t i = 0U; i < PHY_TXPWR_BAND_COUNT; i++) {
            old_backoff[i] = g_phy_sleep_params.tx_pwr_backoff[i];
            old_att5[i] = g_phy_sleep_params.tx_pwctrl_atten[i][5];
        }

        phy_pbus_debugmode();
        phy_pbus_xpd_rx_off(1);
        phy_pbus_xpd_tx_on((uint16_t)(s_tx_rf_ana_gain & 0x0FFFU));
        phy_set_txdc_pbus(s_tx_rf_ana_gain, dc_iq, 1U);
        phy_en_pwdet(0U);

        /* Calibrate Ch 6 first so phy_cal_rf_ana_gain() centers analog gain mid-band */
        phy_tx_pwctrl_init_cal(6U, calibrate_now);
        phy_tx_pwctrl_init_cal(1U, calibrate_now);
        phy_tx_pwctrl_init_cal(11U, calibrate_now);

        g_phy_sleep_params.tx_pwr_backoff[3] = g_phy_sleep_params.tx_pwr_backoff[2];
        for (uint32_t i = 0U; i < PHY_TXPWR_LEVEL_COUNT; i++) {
            g_phy_sleep_params.tx_pwctrl_atten[3][i] = g_phy_sleep_params.tx_pwctrl_atten[2][i];
        }

        phy_pbus_xpd_tx_off();
        phy_pbus_xpd_rx_on();
        phy_pbus_workmode();

        g_phy_sleep_params.param_flag |= PHY_PARAM_TX_PWCTRL_VALID;
        g_phy_sleep_params.tot_p = 0;
        g_phy_sleep_params.coatt = 0;
        g_phy_sleep_params.pwctrl_err_accum = 0;
        g_phy_sleep_params.periodic_delta = 0;

        phy_check_tx_pwr_cal(saved_gain, old_att5, old_backoff);
    } else {
        s_tx_rf_ana_gain = saved_gain;
        phy_set_txdc_pbus(saved_gain, dc_iq, 0U);
        phy_set_rfanagain_dc_reg(s_tx_rf_ana_gain, dc_iq);
    }

    if ((g_phy_sleep_params.param_flag & PHY_PARAM_WAKEUP_RF) == 0U) {
        phy_tx_atten_set_interp(g_phy_sleep_params.cur_chan, tmp_atten);
    }
}

/* --------------------------------------------------------------------------
 * Per-Rate Attenuation Interpolation, FCC Band-Edge & Max TX Power Clamping
 * -------------------------------------------------------------------------- */

/**
 * @brief Return optional FCC power-tier offset for 802.11b 1M/2M rate slots (2, 3, 6, 7).
 *
 * When FCC band-edge mode is active and `rate_slot` is one of the 1M/2M long/short
 * preamble slots (`(rate_slot & 0xFB) in {2, 3}`), returns the configured power-tier
 * offset for upper (ch > 6) or lower (ch <= 6) channels; otherwise returns 0.
 *
 * @param fcc_active  Non-zero if FCC band-edge backoff is active on the current channel.
 * @param rate_slot   Hardware TX power register slot index (0..23).
 * @return            Additional power tier index offset (0..15).
 */
static uint8_t phy_get_fcc_1m2m_pwr_offset(uint8_t fcc_active, uint8_t rate_slot)
{
    if (fcc_active != 0U && (uint8_t)((rate_slot & 0xFBU) - 2U) < 2U) {
        if (g_phy_sleep_params.cur_chan > 6U) {
            return chip6_phy_init_ctrl[PHY_CTRL_FCC_11B_HI_OFF];
        }
        return chip6_phy_init_ctrl[PHY_CTRL_FCC_11B_LO_OFF];
    }
    return 0U;
}

/**
 * @brief Map a hardware TX power register slot (0..23) to its target power tier index (0..5).
 *
 * Hardware TXPWR slot mapping:
 * - Slots 0, 1, 4, 5: 802.11b 5.5M/11M (long/short preamble)
 * - Slots 2, 3, 6, 7: 802.11b 1M/2M (long/short preamble)
 * - Slots 8..15:      802.11g OFDM rates (54M, 36M, 18M, 6M, 48M, 24M, 12M, 9M)
 * - Slots 16..23:     802.11n HT20 MCS0..MCS7
 * Applies optional per-channel FCC clamps (when FCC test mode == 2) and the global
 * `g_phy_set_most_tpw_index` floor before saturating to `[0..5]`.
 *
 * @param rate_slot     Hardware TX power register slot index (0..23).
 * @param rate_idx_tab  8-byte rate-to-power-tier mapping table (from init_data[40..47]).
 * @return              Target power tier index in [0..5] (0 = highest power, 5 = lowest).
 */
static uint8_t phy_get_target_power_offset(uint8_t rate_slot, const uint8_t rate_idx_tab[8])
{
    uint8_t fcc_off = phy_get_fcc_1m2m_pwr_offset(g_phy_sleep_params.fcc_active != 0U ? 1U : 0U,
                                                  rate_slot);
    uint8_t idx;

    switch (rate_slot) {
    case 0U:
    case 1U:
    case 4U:
    case 5U:
        idx = (chip6_phy_init_ctrl[PHY_CTRL_11B_PWR_EN] != 0U)
                  ? chip6_phy_init_ctrl[PHY_CTRL_11B_5M11M_IDX]
                  : rate_idx_tab[0];
        idx = (uint8_t)(idx + fcc_off);
        break;
    case 2U:
    case 3U:
    case 6U:
    case 7U:
        idx = (chip6_phy_init_ctrl[PHY_CTRL_11B_PWR_EN] != 0U)
                  ? chip6_phy_init_ctrl[PHY_CTRL_11B_1M2M_IDX]
                  : rate_idx_tab[0];
        idx = (uint8_t)(idx + fcc_off);
        break;
    case 8U:
        idx = rate_idx_tab[5];
        break;
    case 9U:
        idx = rate_idx_tab[3];
        break;
    case 10U:
        idx = rate_idx_tab[1];
        break;
    case 11U:
    case 15U:
        idx = rate_idx_tab[0];
        break;
    case 12U:
        idx = rate_idx_tab[6];
        break;
    case 13U:
        idx = rate_idx_tab[4];
        break;
    case 14U:
        idx = rate_idx_tab[2];
        break;
    default:
        idx = rate_idx_tab[(uint8_t)(rate_slot - 16U) & 7U];
        break;
    }

    if (chip6_phy_init_ctrl[PHY_CTRL_FCC_TEST_MODE] == 2U) {
        uint8_t ch = g_phy_sleep_params.cur_chan;
        uint8_t clamp_idx = 0U;
        bool has_clamp = false;

        if (ch == 1U) {
            clamp_idx = chip6_phy_init_ctrl[PHY_CTRL_CH_CLAMP_BASE + 0U];
            has_clamp = true;
        } else if (ch == 11U) {
            clamp_idx = chip6_phy_init_ctrl[PHY_CTRL_CH_CLAMP_BASE + 1U];
            has_clamp = true;
        } else if (ch == 13U) {
            clamp_idx = chip6_phy_init_ctrl[PHY_CTRL_CH_CLAMP_BASE + 2U];
            has_clamp = true;
        } else if (ch == 14U) {
            clamp_idx = chip6_phy_init_ctrl[PHY_CTRL_CH_CLAMP_BASE + 3U];
            has_clamp = true;
        }

        if (has_clamp && idx < clamp_idx) {
            idx = clamp_idx;
        }
    }

    if (idx < g_phy_set_most_tpw_index) {
        idx = g_phy_set_most_tpw_index;
    }
    if (idx > 5U) {
        idx = 5U;
    }
    return idx;
}

/**
 * @brief Write signed negated baseband TX attenuation codes into all 24 PHY_RF_TXPWR_REG slots.
 *
 * For 802.11b CCK slots (0..7), adds `cck_delta` (typically +8 = +2.0 dB backoff to match
 * CCK peak-to-average ratio). For OFDM/HT slots (8..23), enforces the FCC band-edge floor
 * `fcc_min_att`. Hardware expects signed `-eff_att` clamped to <= +24 (+6.0 dB digital gain).
 *
 * @param rate_idx_tab  8-byte rate-to-power-tier mapping table.
 * @param cck_delta     Extra attenuation (0.25 dB units) applied to 802.11b CCK slots 0..7.
 * @param atten_tab     6-element interpolated baseband attenuation table for the active channel.
 * @param fcc_min_att   Minimum attenuation floor enforced on OFDM/HT slots (-128 if none).
 */
static void phy_set_txbb_atten(const uint8_t rate_idx_tab[8], uint8_t cck_delta,
                               const int8_t atten_tab[6], int8_t fcc_min_att)
{
    for (uint8_t i = 0U; i < PHY_RF_TXPWR_REGS; i++) {
        uint8_t pidx = phy_get_target_power_offset(i, rate_idx_tab);
        int8_t att = atten_tab[pidx];
        int8_t eff_att;

        if (i < 8U) {
            eff_att = (int8_t)(att + (int8_t)cck_delta);
        } else {
            eff_att = (att < fcc_min_att) ? fcc_min_att : att;
        }

        int8_t neg_att = (int8_t)(-eff_att);
        if (neg_att > PHY_TXPWR_MAX_NEG_ATTEN_QDB) {
            neg_att = PHY_TXPWR_MAX_NEG_ATTEN_QDB;
        }

        PHY_REG_RMW(PHY_RF_TXPWR_REG(i), PHY_RF_TXPWR_ATTEN_MASK, (uint32_t)(uint8_t)neg_att);
    }
}

/**
 * @brief Quantize the requested max TX power (g_phy_in_most_power) into tier index + stage-10 gain.
 *
 * When g_phy_in_most_power falls at or above tier 5 (`tgt_s8[5]`), selects the highest
 * target tier <= requested power and keeps PA stage-10 at full gain (0x0F, or configured
 * low-power stage-10). When below tier 5, locks tier index to 5, disables background power
 * tracking (`g_phy_set_most_tpw_disbg = 1`), and steps down the 4-bit RF PA stage-10 gain
 * code (`0x0E -> 0x0D -> 0x09 -> 0x0C -> 0x08 -> 0x04 -> 0x00`) in calibrated dB steps.
 */
void phy_set_most_pwr_reg(void)
{
    int8_t tgt_s8[6];
    uint8_t stage10 = PHY_TX_STAGE10_DEFAULT;

    phy_get_phy_target_power(tgt_s8, g_phy_in_vdd33_offset);

    int32_t req = (int32_t)(int8_t)g_phy_in_most_power;
    uint8_t t5 = (uint8_t)tgt_s8[5];

    if (req < (int32_t)t5) {
        g_phy_set_most_tpw_disbg = 1U;
        g_phy_set_most_tpw_index = 5U;

        /* Step down PA stage-10 code in empirically characterized 2..23 dB increments */
        uint8_t diff = (uint8_t)(t5 - g_phy_in_most_power);
        if (diff < 9U) {
            g_phy_set_most_tpw_val = (uint8_t)(t5 - 8U);
            stage10 = 0x0EU;
        } else if (diff < 25U) {
            g_phy_set_most_tpw_val = (uint8_t)(t5 - 24U);
            stage10 = 0x0DU;
        } else if (diff < 33U) {
            g_phy_set_most_tpw_val = (uint8_t)(t5 - 32U);
            stage10 = 0x09U;
        } else if (diff < 45U) {
            g_phy_set_most_tpw_val = (uint8_t)(t5 - 44U);
            stage10 = 0x0CU;
        } else if (diff < 57U) {
            g_phy_set_most_tpw_val = (uint8_t)(t5 - 56U);
            stage10 = 0x08U;
        } else if (diff < 69U) {
            g_phy_set_most_tpw_val = (uint8_t)(t5 - 68U);
            stage10 = 0x04U;
        } else {
            g_phy_set_most_tpw_val = (uint8_t)(t5 - 92U);
            stage10 = 0x00U;
        }
    } else {
        g_phy_set_most_tpw_disbg = 0U;
        if (req < (int32_t)(uint8_t)tgt_s8[4]) {
            g_phy_set_most_tpw_index = 5U;
            g_phy_set_most_tpw_val = (uint8_t)tgt_s8[5];
        } else if (req < (int32_t)(uint8_t)tgt_s8[3]) {
            g_phy_set_most_tpw_index = 4U;
            g_phy_set_most_tpw_val = (uint8_t)tgt_s8[4];
        } else if (req < (int32_t)(uint8_t)tgt_s8[2]) {
            g_phy_set_most_tpw_index = 3U;
            g_phy_set_most_tpw_val = (uint8_t)tgt_s8[3];
        } else if (req < (int32_t)(uint8_t)tgt_s8[1]) {
            g_phy_set_most_tpw_index = 2U;
            g_phy_set_most_tpw_val = (uint8_t)tgt_s8[2];
        } else if (req < (int32_t)(uint8_t)tgt_s8[0]) {
            g_phy_set_most_tpw_index = 1U;
            g_phy_set_most_tpw_val = (uint8_t)tgt_s8[1];
        } else {
            g_phy_set_most_tpw_index = 0U;
            g_phy_set_most_tpw_val = (uint8_t)tgt_s8[0];
        }
    }

    if (g_phy_set_most_tpw_disbg == 0U) {
        stage10 = (chip6_phy_init_ctrl[PHY_CTRL_LOW_PWR_EN] == 0U)
                      ? PHY_TX_STAGE10_DEFAULT
                      : chip6_phy_init_ctrl[PHY_CTRL_LOW_PWR_STAGE10];
    }
    phy_set_rf_gain_stage10(stage10);
}

/**
 * @brief Interpolate calibrated TX attenuation across bands for `chan`, apply FCC rules, and load HW.
 *
 * Piecewise-linearly interpolates all 6 tiers of `g_phy_sleep_params.tx_pwctrl_atten[0..3]`
 * to `chan`, adds the background tracking offset `coatt`, computes any FCC band-edge
 * minimum attenuation floor (when FCC test mode == 1), and programs all 24 hardware
 * PHY_RF_TXPWR_REG slots via phy_set_txbb_atten().
 *
 * @param chan       Target Wi-Fi channel (1..14).
 * @param out_atten  Output array receiving the 6 interpolated baseband attenuations (0.25 dB).
 */
void phy_tx_atten_set_interp(uint8_t chan, int8_t out_atten[6])
{
    if (chip6_phy_init_ctrl[PHY_CTRL_LOW_PWR_EN] == 0U) {
        phy_set_most_pwr_reg();
    }

    int8_t coatt = g_phy_sleep_params.coatt;
    for (uint32_t i = 0U; i < PHY_TXPWR_LEVEL_COUNT; i++) {
        int32_t att;
        if (chan < 7U) {
            int32_t a0 = g_phy_sleep_params.tx_pwctrl_atten[0][i];
            int32_t a1 = g_phy_sleep_params.tx_pwctrl_atten[1][i];
            att = a0 + ((a1 - a0) * ((int32_t)chan - 1)) / 5;
        } else if (chan < 12U) {
            int32_t a1 = g_phy_sleep_params.tx_pwctrl_atten[1][i];
            int32_t a2 = g_phy_sleep_params.tx_pwctrl_atten[2][i];
            att = a1 + ((a2 - a1) * ((int32_t)chan - 6)) / 5;
        } else if (chan < 14U) {
            int32_t a2 = g_phy_sleep_params.tx_pwctrl_atten[2][i];
            int32_t a3 = g_phy_sleep_params.tx_pwctrl_atten[3][i];
            att = a2 + (((a3 - a2) * ((int32_t)chan - 11) * 5) / 22);
        } else {
            att = g_phy_sleep_params.tx_pwctrl_atten[3][i];
        }
        out_atten[i] = (int8_t)((int8_t)att + coatt);
    }

    int8_t fcc_edge = PHY_TX_FCC_NO_EDGE_CLAMP;
    uint8_t fcc_active = 0U;

    if (chip6_phy_init_ctrl[PHY_CTRL_FCC_TEST_MODE] == 1U) {
        if (chip6_phy_init_ctrl[PHY_CTRL_FCC_BACKOFF_EN] == 0U) {
            /* Legacy fixed FCC band-edge channels: Ch 1-2 (low) and Ch 10-14 (high) */
            if (chan < 3U) {
                fcc_edge = g_phy_sleep_params.tx_pwctrl_atten[0][2];
                fcc_active = 1U;
            } else if (chan >= 10U) {
                fcc_edge = g_phy_sleep_params.tx_pwctrl_atten[2][2];
                fcc_active = 1U;
            }
        } else {
            /* Configurable FCC band-edge channel counts + optional linear ramp across edge */
            uint8_t lo_cnt = chip6_phy_init_ctrl[PHY_CTRL_FCC_LO_CNT];
            if (chan <= lo_cnt && lo_cnt != 0U) {
                uint8_t lo_idx = chip6_phy_init_ctrl[PHY_CTRL_FCC_LO_IDX];
                fcc_edge = g_phy_sleep_params.tx_pwctrl_atten[0][lo_idx];
                fcc_active = 1U;
                if (chip6_phy_init_ctrl[PHY_CTRL_FCC_INTERP_EN] == 1U) {
                    int32_t a0 = g_phy_sleep_params.tx_pwctrl_atten[0][0];
                    int32_t a1 = g_phy_sleep_params.tx_pwctrl_atten[1][0];
                    int8_t edge_end = (int8_t)(a0 + ((a1 - a0) * (int32_t)lo_cnt) / 5);
                    fcc_edge = (int8_t)(fcc_edge +
                                        (((int32_t)edge_end - (int32_t)fcc_edge) *
                                         ((int32_t)chan - 1)) / (int32_t)lo_cnt);
                }
            } else if ((int32_t)chan >= (15 - (int32_t)chip6_phy_init_ctrl[PHY_CTRL_FCC_HI_CNT])) {
                uint8_t hi_idx = chip6_phy_init_ctrl[PHY_CTRL_FCC_HI_IDX];
                fcc_edge = g_phy_sleep_params.tx_pwctrl_atten[3][hi_idx];
                fcc_active = 1U;
                if (chip6_phy_init_ctrl[PHY_CTRL_FCC_INTERP_EN] == 1U && lo_cnt != 0U) {
                    int8_t edge_end;
                    if (chan < 12U) {
                        int32_t a1 = g_phy_sleep_params.tx_pwctrl_atten[1][0];
                        int32_t a2 = g_phy_sleep_params.tx_pwctrl_atten[2][0];
                        edge_end = (int8_t)(a1 + ((a2 - a1) * (8 - (int32_t)lo_cnt)) / 5);
                    } else {
                        int32_t a2 = g_phy_sleep_params.tx_pwctrl_atten[2][0];
                        int32_t a3 = g_phy_sleep_params.tx_pwctrl_atten[3][0];
                        edge_end = (int8_t)(a2 + (((a3 - a2) * (3 - (int32_t)lo_cnt) * 5) / 22));
                    }
                    fcc_edge = (int8_t)(fcc_edge +
                                        (((int32_t)edge_end - (int32_t)fcc_edge) *
                                         (14 - (int32_t)chan)) / (int32_t)lo_cnt);
                }
            }
        }
    }

    g_phy_sleep_params.fcc_edge_atten = fcc_edge;
    g_phy_sleep_params.fcc_active = fcc_active;
    phy_set_txbb_atten(&chip6_phy_init_ctrl[PHY_CTRL_RATE_PWR_IDX_BASE], 8U, out_atten, fcc_edge);
}

/**
 * @brief Apply fixed low-power RF stage-10 gain and baseband attenuation delta across all slots.
 *
 * @param en        Non-zero to activate low-power fixed gain mode; 0 is a no-op.
 * @param stage10   4-bit PA stage-10 gain code written into PHY_RF_TXPWR_REG[16:13].
 * @param bb_delta  New coarse baseband attenuation offset replacing g_phy_sleep_params.coatt.
 */
void phy_low_power_set(uint8_t en, uint8_t stage10, uint8_t bb_delta)
{
    if (en != 0U) {
        uint32_t stage_bits = ((uint32_t)(stage10 & 0x0FU)) << PHY_RF_TXPWR_STAGE10_SHIFT;
        uint32_t delta = (uint32_t)bb_delta - (uint32_t)(uint8_t)g_phy_sleep_params.coatt;

        for (uint32_t i = 0U; i < PHY_RF_TXPWR_REGS; i++) {
            uint32_t reg = PHY_RF_TXPWR_REG(i);
            uint32_t cur = PHY_REG_READ(reg);
            uint32_t new_att = (cur - delta) & PHY_RF_TXPWR_ATTEN_MASK;
            PHY_REG_WRITE(reg, (cur & ~(PHY_RF_TXPWR_STAGE10_MASK | PHY_RF_TXPWR_ATTEN_MASK)) |
                                   stage_bits | new_att);
        }
        g_phy_sleep_params.coatt = (int8_t)bb_delta;
    }
}

/* --------------------------------------------------------------------------
 * Exported TX Power Control APIs
 * -------------------------------------------------------------------------- */

/**
 * @brief Set the runtime maximum TX power cap and immediately reprogram hardware TX tables.
 *
 * @param max_tpw_qdb  Maximum TX power limit in 0.25 dBm units (e.g. 82 = 20.5 dBm).
 */
void phy_set_most_tpw(uint8_t max_tpw_qdb)
{
    int8_t tmp_atten[6];

    g_phy_in_most_power = max_tpw_qdb;
    phy_tx_atten_set_interp(g_phy_sleep_params.cur_chan, tmp_atten);
    g_phy_set_most_tpw_flag = 1U;
}

/**
 * @brief Return the effective quantized maximum TX power limit (in 0.25 dBm units).
 *
 * @return Effective max TX power in 0.25 dBm units (init_data tier 0 if unset).
 */
uint8_t phy_get_most_tpw(void)
{
    if (g_phy_set_most_tpw_flag == 0U) {
        return chip6_phy_init_ctrl[PHY_CTRL_TARGET_PWR_BASE];
    }
    return g_phy_set_most_tpw_val;
}

/**
 * @brief Update the dynamic VDD33 TX power compensation offset from a runtime VDD33 reading.
 *
 * @param vdd33  Measured supply voltage in mV (1800..3300 mV; out-of-range defaults to 3300).
 */
void phy_vdd33_set_tpw(uint16_t vdd33)
{
    g_phy_in_vdd33_offset = phy_get_vdd33_offset(vdd33);
}

/* --------------------------------------------------------------------------
 * Background Closed-Loop TX Power Tracking & Periodic BBPLL Calibration
 * -------------------------------------------------------------------------- */

/**
 * @brief Arm the hardware SAR power detector to capture the next transmitted Wi-Fi packet.
 *
 * Disconnects TOUT and VDD33 from the SAR analog mux, clears manual power-detector mode,
 * sets the background-arm bit, and pulses PHY_SAR_PWDET_EN_BIT low->high to latch on TX.
 */
void phy_tx_pwctrl_bg_init(void)
{
    /* Match exact hardware pulse sequence in linked_disasm.txt */
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_TOUT_EN);
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_VDD33_EN);
    PHY_REG_CLR(PHY_SAR_CTRL_REG, PHY_SAR_CTRL_PWDET_EN);
    PHY_REG_SET(PHY_SAR_PWDET_CTRL_REG, PHY_SAR_PWDET_BG_ARM_BIT);
    PHY_REG_CLR(PHY_SAR_PWDET_CTRL_REG, PHY_SAR_PWDET_EN_BIT);
    PHY_REG_SET(PHY_SAR_PWDET_CTRL_REG, PHY_SAR_PWDET_EN_BIT);
}

/**
 * @brief Perform periodic BBPLL recalibration safely while pausing MAC/RF via modem pause.
 *
 * Skips bbpll_cal(0) if g_phy_bbpll_cal_flag indicates light-sleep already recalibrated
 * the BBPLL since the last check.
 */
void phy_periodic_cal_top(void)
{
    pm_set_sleep_mode(PHY_PM_MODE_MODEM_PAUSE);
    if (g_phy_bbpll_cal_flag == 0U) {
        bbpll_cal(0U);
    }
    g_phy_bbpll_cal_flag = 0U;
    pm_wakeup_init(PHY_PM_MODE_MODEM_PAUSE, 0U);
}

/**
 * @brief Leaky-integrator hysteresis filter for background TX power tracking corrections.
 *
 * Updates the leaky error accumulator `acc = acc + err - (acc >> shift)`. When `|acc|`
 * crosses `step << (shift + 2)`, emits a discrete `+/-step` correction (inverted sign so
 * positive power error reduces gain) and subtracts the threshold from `*err_accum`.
 *
 * @param err        Clamped TX power error `(measured - target)` in 0.0625 dB units.
 * @param err_accum  In/out pointer to leaky IIR error accumulator (`pwctrl_err_accum`).
 * @param shift      Leaky decay shift (4 -> 15/16 retention per sample).
 * @param step       Discrete correction step size in 0.25 dB units (typically 2 = 0.5 dB).
 * @return           Signed attenuation correction (`-step`, `0`, or `+step`).
 */
static int8_t phy_get_pwctrl_correct(int16_t err, int16_t *err_accum,
                                     uint8_t shift, uint8_t step)
{
    int16_t acc = (int16_t)((*err_accum + err) - (int16_t)((int32_t)*err_accum >> shift));
    int32_t thresh = (int32_t)step << (shift + 2U);

    if (acc >= thresh) {
        *err_accum = (int16_t)(acc - (int16_t)thresh);
        return (int8_t)(-(int8_t)step);
    }
    if (acc <= -thresh) {
        *err_accum = (int16_t)(acc + (int16_t)thresh);
        return (int8_t)step;
    }

    *err_accum = acc;
    return 0;
}

/**
 * @brief Evaluate one captured TX packet power reading and adjust RF/BB gain for drift.
 *
 * Reads the hardware-latched packet rate from PHY_SAR_PWDET_CTRL_REG[28:24], looks up the
 * expected target power for that rate, compares against phy_get_sar_dout(0x0138), and
 * computes a correction (fast proportional for the first 4 packets, leaky IIR thereafter).
 * When digital baseband attenuation drifts outside [12..36], shifts analog RF/TXBB gain
 * via phy_correct_rf_ana_gain(), otherwise updates `coatt` and backs up RTC chunk 2.
 *
 * @param target_pwr    6-element effective target TX powers for the active channel (0.25 dBm).
 * @param rate_idx_tab  8-byte rate-to-power-tier mapping table.
 * @param err_accum     In/out pointer to leaky IIR error accumulator.
 * @param apply_enable  Non-zero to apply computed corrections to hardware; 0 for dry-run.
 */
static void phy_tx_pwctrl_cal(const int8_t target_pwr[6], const uint8_t rate_idx_tab[8],
                              int16_t *err_accum, uint8_t apply_enable)
{
    uint32_t pwdet = PHY_REG_READ(PHY_SAR_PWDET_CTRL_REG);
    int16_t p_out = phy_get_sar_dout(PHY_SAR_PWDET_REF_DEFAULT);
    uint8_t txq_rate = (uint8_t)((pwdet >> PHY_SAR_PWDET_TXRATE_SHIFT) & PHY_SAR_PWDET_TXRATE_MASK);

    s_phy_tx_power_out = p_out;

    /* 11b hardware rate codes 0..7 are bit-inverted relative to TXPWR register slot indices */
    uint8_t rate_slot = (txq_rate < 8U) ? (uint8_t)((~txq_rate) & 7U) : txq_rate;
    uint8_t pidx = phy_get_target_power_offset(rate_slot, rate_idx_tab);

    int16_t err = (int16_t)(p_out - (int16_t)((uint8_t)target_pwr[pidx] * 4U));
    s_phy_tx_pwr_error = err;

    if (err < -PHY_PWCTRL_BG_ERR_CLAMP) {
        err = -PHY_PWCTRL_BG_ERR_CLAMP;
    } else if (err > PHY_PWCTRL_BG_ERR_CLAMP) {
        err = PHY_PWCTRL_BG_ERR_CLAMP;
    }

    int8_t correct_v = 0;
    if (g_phy_tx_pwctrl_track_num < 4U) {
        /* Fast initial convergence during first 4 tracked packets */
        int32_t q = (int32_t)err >> 2;
        if (err > 0) {
            correct_v = (int8_t)(-((q + (int32_t)err) >> 2));
        } else if (err < -16) {
            correct_v = (int8_t)(-(((int32_t)err - q) >> 2));
            if (g_phy_sleep_params.tot_p > PHY_PWCTRL_BG_MAX_DRIFT) {
                correct_v = 0;
            }
        }
    } else {
        correct_v = phy_get_pwctrl_correct(err, err_accum, 4U, 2U);
        if (correct_v > 0 && g_phy_sleep_params.tot_p > PHY_PWCTRL_BG_MAX_DRIFT) {
            correct_v = 0;
        }
    }

    if (correct_v == 0 || apply_enable == 0U) {
        return;
    }

    int8_t min_att = g_phy_sleep_params.tx_pwctrl_atten[0][5];
    for (uint32_t b = 1U; b < PHY_TXPWR_BAND_COUNT; b++) {
        if (g_phy_sleep_params.tx_pwctrl_atten[b][5] < min_att) {
            min_att = g_phy_sleep_params.tx_pwctrl_atten[b][5];
        }
    }

    int8_t base_att = (int8_t)(g_phy_sleep_params.coatt + min_att);
    int8_t next_att = (int8_t)(base_att - correct_v);

    /* If digital attenuation would leave [12..36], absorb part of the shift in analog RF gain */
    bool need_rf_step = false;
    if (next_att >= 37) {
        need_rf_step = (s_tx_rf_ana_gain >= PHY_TX_RF_GAIN_MIN_REG);
    } else if (next_att <= 11) {
        need_rf_step = (s_tx_rf_ana_gain <= PHY_TX_RF_GAIN_MAX_REG);
    }

    if (need_rf_step) {
        int8_t dc_iq[2];
        int8_t delta = (int8_t)(24 - next_att);
        int8_t orig_delta = delta;

        phy_correct_rf_ana_gain(&delta, &s_tx_rf_ana_gain);
        int8_t applied = (int8_t)(orig_delta - delta);

        g_phy_sleep_params.tot_p = (int8_t)(g_phy_sleep_params.tot_p + applied);
        g_phy_sleep_params.periodic_delta = (int8_t)(g_phy_sleep_params.periodic_delta + applied);
        correct_v = (int8_t)(correct_v + delta - orig_delta);

        phy_set_txdc_pbus(s_tx_rf_ana_gain, dc_iq, 0U);
        phy_set_rfanagain_dc_reg(s_tx_rf_ana_gain, dc_iq);
        g_phy_sleep_params.rf_ana_gain = s_tx_rf_ana_gain;
    }

    int8_t final_att = (int8_t)(base_att - correct_v);
    if ((correct_v < 0 && final_att < 71) || (correct_v > 0 && final_att > 11)) {
        int8_t tmp_atten[6];

        g_phy_sleep_params.coatt = (int8_t)(g_phy_sleep_params.coatt - correct_v);
        g_phy_sleep_params.tot_p = (int8_t)(g_phy_sleep_params.tot_p + correct_v);
        g_phy_sleep_params.periodic_delta = (int8_t)(g_phy_sleep_params.periodic_delta + correct_v);

        phy_tx_atten_set_interp(g_phy_sleep_params.cur_chan, tmp_atten);
        phy_rtc_mem_backup_chunk2();
    }
}

/**
 * @brief Periodic background TX power tracking entry point called every ~1 s by LMAC housekeeping.
 *
 * Exits early when background tracking is disabled via init_data, low-power mode, sub-tier-5
 * power capping, or active TOUT ADC sampling. If the SAR power detector captured a TX packet
 * and is idle, runs phy_tx_pwctrl_cal(), rearms the power detector, and triggers
 * phy_periodic_cal_top() whenever cumulative temperature/voltage drift exceeds +/-7 qdB.
 *
 * @param apply_enable  Non-zero to apply gain adjustments; 0 to measure only.
 * @param debug_print   Unused legacy vendor debug flag (preserved for ABI compatibility).
 */
void tx_pwctrl_background(uint8_t apply_enable, uint8_t debug_print)
{
    (void)debug_print;

    if ((chip6_phy_init_ctrl[PHY_CTRL_BG_PWCTRL_DIS] & 1U) != 0U ||
        chip6_phy_init_ctrl[PHY_CTRL_LOW_PWR_EN] != 0U ||
        g_phy_set_most_tpw_disbg != 0U ||
        g_phy_tout_dis_txpwr_track != 0U) {
        return;
    }

    uint32_t sar_ctrl = PHY_REG_READ(PHY_SAR_CTRL_REG);
    if ((int32_t)sar_ctrl < 0 ||
        ((sar_ctrl >> PHY_SAR_CTRL_STATE_SHIFT) & PHY_SAR_CTRL_STATE_MASK) != 0U) {
        s_phy_tx_power_out = 0;
    } else {
        int8_t tgt_pwr[6];
        phy_get_phy_target_power(tgt_pwr, g_phy_in_vdd33_offset);
        phy_tx_pwctrl_cal(tgt_pwr, &chip6_phy_init_ctrl[PHY_CTRL_RATE_PWR_IDX_BASE],
                          &g_phy_sleep_params.pwctrl_err_accum, apply_enable);
        if (g_phy_tx_pwctrl_track_num < 20U) {
            g_phy_tx_pwctrl_track_num++;
        }
    }

    phy_tx_pwctrl_bg_init();

    if (phy_abs_i32((int32_t)g_phy_sleep_params.periodic_delta) > PHY_PWCTRL_BG_PERIODIC_THRESH) {
        g_phy_sleep_params.periodic_delta = 0;
        phy_periodic_cal_top();
    }
}

/* --------------------------------------------------------------------------
 * TX I/Q Mismatch Calibration
 * -------------------------------------------------------------------------- */

/**
 * @brief Clamp and write a TXIQ gain (5-bit) or phase (6-bit) correction to ANA_INF I2C regs.
 *
 * Supports both two's-complement (`sign_flag == 0`) and sign-magnitude (`sign_flag != 0`)
 * encodings across PHY_I2C_ANA_INF_TXIQ_G_REG / PHY_I2C_ANA_INF_TXIQ_P_REG.
 *
 * @param val        Signed correction value (clamped to [-15..+15] for gain, [-31..+31] for phase).
 * @param is_gain    Non-zero for TXIQ gain register; 0 for TXIQ phase register.
 * @param sign_flag  Non-zero to write sign bit separately (sign-magnitude mode); 0 for two's-comp.
 * @return           Clamped signed value actually written to hardware.
 */
static int8_t phy_rfcal_txiq_set_reg(int8_t val, uint8_t is_gain, uint8_t sign_flag)
{
    if (sign_flag == 0U) {
        int8_t limit = (is_gain != 0U) ? PHY_TXIQ_GAIN_LIMIT : PHY_TXIQ_PHASE_LIMIT;
        if (val > limit) {
            val = limit;
        } else if (val < -limit) {
            val = (int8_t)(-limit);
        }

        if (is_gain != 0U) {
            rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                  PHY_I2C_ANA_INF_TXIQ_G_REG, 7U, 3U, (uint8_t)val & 0x1FU);
        } else {
            rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                  PHY_I2C_ANA_INF_TXIQ_P_REG, 5U, 0U, (uint8_t)val & 0x3FU);
        }
        return val;
    }

    uint8_t neg = (val < 0) ? 1U : 0U;
    int8_t mag = neg ? (int8_t)(-val) : val;

    if (is_gain != 0U) {
        if (mag > PHY_TXIQ_GAIN_LIMIT) {
            mag = PHY_TXIQ_GAIN_LIMIT;
        }
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_TXIQ_G_REG, 0U, 0U, neg);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_TXIQ_G_REG, 7U, 3U, (uint8_t)mag & 0x1FU);
    } else {
        if (mag > PHY_TXIQ_PHASE_LIMIT) {
            mag = PHY_TXIQ_PHASE_LIMIT;
        }
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_DPD_TXIQ_P_REG, 6U, 6U, neg);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_TXIQ_P_REG, 5U, 0U, (uint8_t)mag & 0x3FU);
    }

    return neg ? (int8_t)(-mag) : mag;
}

/**
 * @brief Measure a complementary pair of TX tone powers to extract I/Q gain or phase imbalance.
 *
 * Drives PHY_FE_TX_TONE_1_REG with two orthogonal I/Q phase/polarity configurations
 * selected by `phase_sel` (`1` = I vs Q amplitude balance, `0` = +45/-45 deg phase balance)
 * and reads linear SAR envelope power for each state.
 *
 * @param phase_sel  1 to measure I/Q gain imbalance; 0 to measure I/Q phase imbalance.
 * @param atten      Baseband TX tone attenuation code.
 * @param freq       10-bit DDS calibration tone frequency code.
 * @param p1         Output pointer receiving linear power for the first polarity state.
 * @param p2         Output pointer receiving linear power for the swapped polarity state.
 */
static void phy_txiq_get_mis_pwr(uint8_t phase_sel, int8_t atten, int16_t freq,
                                 int16_t *p1, int16_t *p2)
{
    uint32_t neg_att = (uint32_t)(uint8_t)(-atten);
    uint32_t freq_bits = (uint32_t)(uint16_t)freq & PHY_FE_TX_TONE_FREQ_MASK;
    uint32_t sel = phase_sel & 1U;

    PHY_REG_RMW(PHY_FE_TX_TONE_1_REG, PHY_FE_TX_TONE_CFG_MASK,
                0x002C0000U | (sel << 26) | (neg_att << PHY_FE_TX_TONE_ATTEN_SHIFT) | freq_bits);
    *p1 = (int16_t)phy_txtone_linear_pwr(4U, 10U);

    /* Swap I/Q test polarity in bits [27:24] and re-measure */
    uint32_t swap_bits = ((sel << 3) | (sel ^ 1U)) << 24;
    PHY_REG_RMW(PHY_FE_TX_TONE_1_REG, 0x0F000000U, swap_bits);
    *p2 = (int16_t)phy_txtone_linear_pwr(4U, 10U);
}

/**
 * @brief Iteratively converge TX I/Q gain and phase mismatch compensation using SAR envelope power.
 *
 * Runs up to 7 iterations: the first 3 iterations apply direct closed-loop updates with
 * second-order phase-squared gain compensation (`quad = (phase^2 + 128) >> 8`), and
 * iterations 3..6 verify convergence (`|g_err| < 2 && |p_err| < 2`) or average the 4
 * residual measurements to make one final refinement step.
 *
 * @param bb_atten   Nominal baseband TX attenuation for phase imbalance measurements.
 * @param tone_freq  DDS calibration tone frequency code.
 * @param out_gp     Output 2-byte array receiving converged [0]=gain, [1]=phase codes.
 * @param sign_flag  Passed through to phy_rfcal_txiq_set_reg() (0 = two's-complement).
 */
static void phy_txiq_cover(int8_t bb_atten, int16_t tone_freq, int8_t out_gp[2],
                           uint8_t sign_flag)
{
    /* Gain imbalance measurement uses 3 dB (12 qdB) higher drive for better SNR */
    int8_t att_gain = (int8_t)(bb_atten - 12);
    int8_t cur_gain = 0;
    int8_t cur_phase = 0;
    int8_t sum_gain = 0;
    int8_t sum_phase = 0;

    for (uint8_t iter = 0U; iter < 7U; iter++) {
        if (iter < 4U) {
            /* Compensate cos(phi) ~ 1 - phi^2/2 amplitude droop induced by phase correction */
            int8_t quad = (int8_t)((((int32_t)cur_phase * (int32_t)cur_phase) + 128) >> 8);
            int8_t set_g = phy_rfcal_txiq_set_reg((int8_t)(cur_gain + quad), 1U, sign_flag);
            cur_gain = (int8_t)(set_g - quad);
            cur_phase = phy_rfcal_txiq_set_reg(cur_phase, 0U, sign_flag);
        }

        int16_t p1 = 0;
        int16_t p2 = 0;
        phy_txiq_get_mis_pwr(1U, att_gain, tone_freq, &p1, &p2);
        int32_t denom = (p1 < p2) ? (int32_t)p1 : (int32_t)p2;
        if (denom == 0) {
            denom = 1;
        }
        /* Normalized gain mismatch error scaled to hardware 5-bit gain units */
        int8_t g_err = (int8_t)(((((int32_t)p2 - (int32_t)p1) * 2048) / denom + 16) >> 5);
        if (cur_gain < 0 && sign_flag != 0U) {
            g_err = (int8_t)(-g_err);
        }
        out_gp[0] = g_err;

        phy_txiq_get_mis_pwr(0U, bb_atten, tone_freq, &p1, &p2);
        denom = (int16_t)(p1 + p2);
        if (denom == 0) {
            denom = 1;
        }
        /* Normalized phase mismatch error scaled to hardware 6-bit phase units */
        int8_t p_err = (int8_t)(((((int32_t)p1 - (int32_t)p2) * 4096) / denom + 16) >> 5);
        if (cur_phase < 0 && sign_flag != 0U) {
            p_err = (int8_t)(-p_err);
        }
        out_gp[1] = p_err;

        if (iter < 3U) {
            cur_gain = (int8_t)(cur_gain - g_err);
            cur_phase = (int8_t)(cur_phase - p_err);
        } else {
            sum_gain = (int8_t)(sum_gain + g_err);
            sum_phase = (int8_t)(sum_phase + p_err);

            if (phy_abs_i32((int32_t)g_err) < 2 && phy_abs_i32((int32_t)p_err) < 2) {
                break;
            }
            if (iter == 6U) {
                int8_t avg_g = (int8_t)((sum_gain + 2) >> 2);
                int8_t avg_p = (int8_t)((sum_phase + 2) >> 2);
                cur_gain = (int8_t)(cur_gain - avg_g);
                cur_phase = (int8_t)(cur_phase - avg_p);
                if (phy_abs_i32((int32_t)avg_g) > PHY_TXIQ_CONVERGE_ERR_MAX ||
                    phy_abs_i32((int32_t)avg_p) > PHY_TXIQ_CONVERGE_ERR_MAX) {
                    g_phy_check_result |= PHY_CHECK_TXIQ_FAIL_BIT;
                }
                break;
            }
        }
    }

    (void)phy_rfcal_txiq_set_reg(cur_gain, 1U, sign_flag);
    (void)phy_rfcal_txiq_set_reg(cur_phase, 0U, sign_flag);
    out_gp[0] = cur_gain;
    out_gp[1] = cur_phase;
}

/**
 * @brief Calibrate (or restore cached) TX I/Q imbalance and commit it to baseband hardware.
 *
 * When PHY_PARAM_TXIQ_VALID is clear, enters PBUS debug mode, enables the ANA_INF TXIQ
 * calibration mux, runs phy_txiq_cover(), restores ANA_INF state, packs the 5-bit gain
 * and 6-bit phase codes into `*txiq_out` (`(gain << 8) | phase`), and sets
 * PHY_PARAM_TXIQ_VALID. Always programs the digital TXIQ correction into
 * PHY_BB_TXIQ_GAIN_COMMIT_REG, PHY_BB_TX_CAL_REG, PHY_BB_TXIQ_MODE_REG, and PHY_BB_TXDC_EN_REG.
 *
 * @param param_flag   In/out calibration validity bitmask (`g_phy_sleep_params.param_flag`).
 * @param txiq_out     In/out packed TXIQ code `(gain_5b << 8) | phase_6b`.
 * @param rf_ana_gain  Active 12-bit RF/TXBB analog gain word used during calibration.
 * @param amp          DDS calibration tone frequency code (typically 0x40).
 * @param bb_atten     Baseband TX attenuation for calibration tone drive.
 * @param sign_flag    0 for two's-complement register encoding; non-zero for sign-magnitude.
 * @param mode_flag    Reserved legacy parameter (unused).
 * @param apply_bb     Reserved legacy parameter (baseband commit is always performed).
 */
void phy_rfcal_txiq(uint32_t *param_flag, uint16_t *txiq_out,
                    uint16_t rf_ana_gain, uint8_t amp, int8_t bb_atten,
                    uint8_t sign_flag, uint8_t mode_flag, uint8_t apply_bb)
{
    uint32_t gain_u;
    uint32_t phase_u;

    (void)mode_flag;
    (void)apply_bb;

    if ((*param_flag & PHY_PARAM_TXIQ_VALID) == 0U) {
        int8_t dc_iq[2];
        int8_t gp[2];

        uint8_t saved_r10_b0 = rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                                    PHY_I2C_ANA_INF_TXIQ_G_REG, 0U, 0U);
        uint8_t saved_r0f_b6 = rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                                    PHY_I2C_ANA_INF_DPD_TXIQ_P_REG, 6U, 6U);
        uint8_t saved_r09 = rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                                 PHY_I2C_ANA_INF_TX_SCALE_REG, 7U, 0U);

        phy_pbus_debugmode();
        phy_pbus_xpd_rx_off(1);
        phy_pbus_xpd_tx_on(rf_ana_gain);
        phy_set_txdc_pbus(rf_ana_gain, dc_iq, 1U);
        phy_en_pwdet(0U);
        phy_set_txclk_en(1U);

        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_TX_SCALE_REG, 7U, 0U, 0U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_TXIQ_G_REG, 2U, 2U, 1U);

        phy_txiq_cover(bb_atten, (int16_t)amp, gp, sign_flag);

        phy_stop_tx_tone(1U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_TXIQ_G_REG, 0U, 0U, saved_r10_b0);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_DPD_TXIQ_P_REG, 6U, 6U, saved_r0f_b6);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_TX_SCALE_REG, 7U, 0U, saved_r09);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_TXIQ_G_REG, 2U, 2U, 0U);

        if (gp[0] > PHY_TXIQ_GAIN_LIMIT) {
            gp[0] = PHY_TXIQ_GAIN_LIMIT;
        } else if (gp[0] < -PHY_TXIQ_GAIN_LIMIT) {
            gp[0] = -PHY_TXIQ_GAIN_LIMIT;
        }
        if (gp[1] > PHY_TXIQ_PHASE_LIMIT) {
            gp[1] = PHY_TXIQ_PHASE_LIMIT;
        } else if (gp[1] < -PHY_TXIQ_PHASE_LIMIT) {
            gp[1] = -PHY_TXIQ_PHASE_LIMIT;
        }
        if (saved_r10_b0 != 0U && sign_flag != 0U) {
            gp[0] = (int8_t)(-gp[0]);
        }

        /* Encode signed [-15..15] / [-31..31] into unsigned 5-bit / 6-bit two's complement */
        gain_u = (gp[0] < 0) ? (uint32_t)(gp[0] + 32) : (uint32_t)gp[0];
        phase_u = (gp[1] < 0) ? (uint32_t)(gp[1] + 64) : (uint32_t)gp[1];

        phy_pbus_exit_debugmode();

        *txiq_out = (uint16_t)((gain_u << 8) | (phase_u & 0xFFU));
        *param_flag |= PHY_PARAM_TXIQ_VALID;
    } else {
        gain_u = (*txiq_out >> 8) & 0xFFU;
        phase_u = *txiq_out & 0xFFU;
    }

    PHY_REG_RMW(PHY_BB_TXIQ_GAIN_COMMIT_REG, PHY_BB_TXIQ_FIELD_MASK,
                PHY_BB_TXIQ_EN_BITS |
                ((gain_u & 0x1FU) << PHY_BB_TXIQ_GAIN_SHIFT) |
                ((phase_u & 0x3FU) << PHY_BB_TXIQ_PHASE_SHIFT));
    PHY_REG_SET(PHY_BB_TX_CAL_REG, PHY_BB_TX_CAL_TXIQ_EN);
    PHY_REG_RMW(PHY_BB_TXIQ_MODE_REG, 0x0000000FU, 2U);
    PHY_REG_RMW(PHY_BB_TXDC_EN_REG, 0x000001F1U, 1U);
}
