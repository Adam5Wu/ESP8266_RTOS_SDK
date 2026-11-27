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
 * File-Local Constants (SAR ADC Correction, Mux/Timing & Entropy Harvest)
 * -------------------------------------------------------------------------- */

#define PHY_SAR_RAW_MASK            0xFFFFU    /* Active-low 16-bit SAR register mask */
#define PHY_SAR_COARSE_MASK         0x700U     /* Upper 3-bit coarse SAR code [10:8] */
#define PHY_SAR_FINE_MASK           0xFFU      /* Lower 8-bit fine SAR code [7:0] */
#define PHY_SAR_FINE_OFFSET         21         /* Fine-DAC zero-point deadband offset */
#define PHY_SAR_FINE_SCALE_NUM      279        /* Q8 stretch numerator (279/256 ~= 255/234) */
#define PHY_SAR_FINE_SCALE_SHIFT    8          /* Q8 divisor shift for fine-DAC stretch */

#define PHY_PBUS_PA_VDD33_BIAS_BIT  2U         /* PBUS ch 6 w=1 bit 1: VDD33 SAR rail bias */
#define PHY_I2C_TX_PA_VDD33_REG     9U         /* TX PA sub-reg 9: [7]=VDD33 tap, [2:0]=atten */
#define PHY_I2C_SAR_MUX_BIT         5U         /* SAR I2C reg 0 bit 5: analog mux enable */
#define PHY_I2C_SAR_TSEN_BIT        6U         /* SAR I2C reg 0 bit 6: TSEN trigger bit */

#define PHY_SAR_CONV_DELAY_US       25U        /* 8-sample SAR burst settle time (us) */
#define PHY_SAR_TOUT_DELAY_US       2U         /* Initial settle before polling TOUT burst */
#define PHY_SAR_FAST_DELAY_US       1U         /* Per-sample settle in fast single-shot mode */
#define PHY_SAR_TSEN_SETTLE_US      200U       /* Temperature sensor analog settle time (us) */

#define PHY_SAR_PWDET_DB_SHIFT      3U         /* Fixed-point shift passed to phy_linear_to_db */

#define PHY_SAR_FAST_MIN_CLKDIV     2U         /* Minimum safe SAR clock divider */
#define PHY_SAR_FAST_TIMING0_MUL    0x010105U  /* Packed phase-0 cycle multipliers [1, 1, 5] */
#define PHY_SAR_FAST_TIMING1_MUL    0x0A030BU  /* Packed phase-1 cycle multipliers [10, 3, 11] */
#define PHY_SAR_FAST_TIMING_BIAS    0x010101U  /* Packed -1/byte bias (HW expects cycles - 1) */

#define PHY_ADC_RAND_Q_SHIFT        8U         /* Aligns Q-ch LSBs [11:10] into nibble [3:2] */
#define PHY_ADC_RAND_Q_MASK         0x0CU      /* Shifted Q-channel 2-bit entropy mask */
#define PHY_ADC_RAND_I_MASK         0x03U      /* I-channel 2-bit entropy mask [1:0] */

/* --------------------------------------------------------------------------
 * Exported & Cross-TU Globals (Explicitly Initialized — 0 SHN_COMMON)
 * -------------------------------------------------------------------------- */

unsigned int adc_rand_noise = 0U;
uint8_t g_phy_tout_dis_txpwr_track = 0U;

/* --------------------------------------------------------------------------
 * Internal SAR Helpers (Flash — 0 B IRAM)
 * -------------------------------------------------------------------------- */

/**
 * @brief Invert and apply piecewise non-linearity correction to a raw SAR ADC register word.
 *
 * The ESP8266 SAR ADC outputs active-low 11-bit codes (`~reg_val`). Its lower
 * 8-bit fine capacitor bank has a ~21-LSB zero deadband (`0..20`), so the fine
 * code is shifted down by `PHY_SAR_FINE_OFFSET` (`21`), clamped at `0`, and
 * linearly stretched back across `[0..255]` by multiplying by `279/256` before
 * recombining with the 3-bit coarse upper field (`[10:8]`).
 *
 * @param reg_val Raw 32-bit value read from `PHY_SAR_DOUT_REG(n)`.
 * @return        Linearized 11-bit SAR sample in `[0..2047]`.
 */
static inline uint16_t sar_raw_correct(uint32_t reg_val)
{
    uint32_t raw = (~reg_val) & PHY_SAR_RAW_MASK;
    int32_t lo = (int32_t)(raw & PHY_SAR_FINE_MASK) - PHY_SAR_FINE_OFFSET;

    if (lo < 0) {
        lo = 0;
    }
    return (uint16_t)((raw & PHY_SAR_COARSE_MASK) +
                      (uint32_t)((lo * PHY_SAR_FINE_SCALE_NUM) >> PHY_SAR_FINE_SCALE_SHIFT));
}

/**
 * @brief Spin until the hardware SAR ADC state machine returns to idle (`state == 0`).
 */
static inline void sar_wait_idle(void)
{
    while (((PHY_REG_READ(PHY_SAR_CTRL_REG) >> PHY_SAR_CTRL_STATE_SHIFT) &
            PHY_SAR_CTRL_STATE_MASK) != 0U) {
    }
}

/**
 * @brief Generate a rising edge on `PHY_SAR_CTRL_START` to launch a SAR conversion burst.
 */
static inline void sar_trigger_pulse(void)
{
    PHY_REG_CLR(PHY_SAR_CTRL_REG, PHY_SAR_CTRL_START);
    PHY_REG_SET(PHY_SAR_CTRL_REG, PHY_SAR_CTRL_START);
}

/**
 * @brief Pulse `PHY_SAR_PWDET_EN_BIT` low-then-high to re-arm the TX power detector latch.
 */
static inline void sar_pwdet_rearm_pulse(void)
{
    PHY_REG_CLR(PHY_SAR_PWDET_CTRL_REG, PHY_SAR_PWDET_EN_BIT);
    PHY_REG_SET(PHY_SAR_PWDET_CTRL_REG, PHY_SAR_PWDET_EN_BIT);
}

/* --------------------------------------------------------------------------
 * Cross-TU SAR ADC, Power Detector, TSEN & Entropy Helpers (Flash)
 * -------------------------------------------------------------------------- */

/**
 * @brief Read and linearize all 8 hardware SAR ADC output registers.
 *
 * @param[out] out Array of 8 linearized SAR samples corresponding to `PHY_SAR_DOUT_REG(0..7)`.
 */
void phy_read_sar_dout(int16_t out[8])
{
    for (uint32_t i = 0U; i < PHY_SAR_SAMPLE_COUNT; i++) {
        out[i] = (int16_t)sar_raw_correct(PHY_REG_READ(PHY_SAR_DOUT_REG(i)));
    }
}

/**
 * @brief Measure the internal VDD33 supply rail using the SAR ADC.
 *
 * Temporarily biases the PA VDD33 sense tap via PBUS and ROM-I2C, switches the
 * SAR analog mux to `PHY_SAR_MUX_VDD33_EN`, triggers an 8-sample burst, and
 * averages the 8 samples scaled by `2x` (`(sum + 2) >> 2`, i.e., `mean * 2`).
 * Restores all modified PBUS and I2C registers before returning.
 *
 * @param pbus_dbg Non-zero to temporarily enable `PHY_PBUS_DEBUG_MODE` around the measurement;
 *                 zero if the caller has already entered PBUS debug mode.
 * @return         Raw VDD33 reading (nominal 3.3 V ~= `PHY_VDD33_NOMINAL_RAW` / `0x0D33`).
 */
uint16_t phy_readvdd33(uint8_t pbus_dbg)
{
    int16_t samples[PHY_SAR_SAMPLE_COUNT];

    if (pbus_dbg != 0U) {
        PHY_REG_SET(PHY_PBUS_CTRL_REG, PHY_PBUS_DEBUG_MODE);
    }

    uint16_t saved_pbus = phy_pbus_rd(PHY_PBUS_CH_PA_EN, PHY_PBUS_WIDTH_1);
    uint8_t saved_pa_9 = rom_i2c_readReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2,
                                              PHY_I2C_TX_PA_VDD33_REG, 2U, 0U);
    uint8_t saved_sar_0 = rom_i2c_readReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2,
                                               PHY_I2C_SAR_CTRL_REG,
                                               PHY_I2C_SAR_MUX_BIT, PHY_I2C_SAR_MUX_BIT);

    /* Route internal VDD33 divider through TX PA tap into the SAR ADC input */
    phy_pbus_force(PHY_PBUS_CH_PA_EN, PHY_PBUS_WIDTH_1,
                   (uint16_t)(saved_pbus | PHY_PBUS_PA_VDD33_BIAS_BIT));
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2,
                          PHY_I2C_TX_PA_VDD33_REG, 7U, 7U, 1U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2,
                          PHY_I2C_TX_PA_VDD33_REG, 2U, 0U, 0U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2,
                          PHY_I2C_SAR_CTRL_REG,
                          PHY_I2C_SAR_MUX_BIT, PHY_I2C_SAR_MUX_BIT, 1U);

    PHY_REG_SET(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_VDD33_EN);
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_TOUT_EN);

    sar_wait_idle();
    sar_trigger_pulse();
    ets_delay_us(PHY_SAR_CONV_DELAY_US);

    phy_read_sar_dout(samples);

    /* Sum 8 samples and divide by 4 with rounding -> 2x average matching SDK VDD33 scale */
    uint16_t sum = 0U;
    for (uint32_t i = 0U; i < PHY_SAR_SAMPLE_COUNT; i++) {
        sum = (uint16_t)(sum + (uint16_t)samples[i]);
    }
    uint16_t result = (uint16_t)(((uint32_t)sum + 2U) >> 2);

    /* Restore PA VDD33 tap, SAR mux, and optional PBUS debug mode */
    phy_pbus_force(PHY_PBUS_CH_PA_EN, PHY_PBUS_WIDTH_1, saved_pbus);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2,
                          PHY_I2C_TX_PA_VDD33_REG, 7U, 7U, 0U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2,
                          PHY_I2C_TX_PA_VDD33_REG, 2U, 0U, saved_pa_9);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2,
                          PHY_I2C_SAR_CTRL_REG,
                          PHY_I2C_SAR_MUX_BIT, PHY_I2C_SAR_MUX_BIT, saved_sar_0);

    if (pbus_dbg != 0U) {
        PHY_REG_CLR(PHY_PBUS_CTRL_REG, PHY_PBUS_DEBUG_MODE);
    }

    return result;
}

/**
 * @brief Trigger and read the on-die analog temperature sensor via the SAR I2C block.
 *
 * Routes the SAR mux to the TSEN/TOUT path, waits 200 us for analog settling,
 * strobes the SAR I2C temperature sensor bit, and reads the 8-bit sensor output.
 *
 * @return Raw 8-bit temperature sensor code (`0..255`).
 */
uint8_t phy_tsen_meas(void)
{
    PHY_REG_CLR(PHY_SAR_CTRL_REG, PHY_SAR_CTRL_TSEN_EN);
    PHY_REG_SET(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_TOUT_EN);
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_VDD33_EN);
    ets_delay_us(PHY_SAR_TSEN_SETTLE_US);

    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2,
                          PHY_I2C_SAR_CTRL_REG,
                          PHY_I2C_SAR_TSEN_BIT, PHY_I2C_SAR_TSEN_BIT, 0U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2,
                          PHY_I2C_SAR_CTRL_REG,
                          PHY_I2C_SAR_TSEN_BIT, PHY_I2C_SAR_TSEN_BIT, 1U);
    PHY_REG_SET(PHY_SAR_CTRL_REG, PHY_SAR_CTRL_TSEN_EN);

    return rom_i2c_readReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2,
                                PHY_I2C_SAR_TSEN_DOUT_REG, 7U, 0U);
}

/**
 * @brief Trigger a power-detector SAR burst and compute differential signal/reference levels.
 *
 * The hardware power-detector FSM populates 8 SAR slots across three phases:
 * - `d[0]`: discarded initial settling sample
 * - `d[1..3]`: 3 primary RF-signal detector samples
 * - `d[4..5]`: 2 secondary/calibration reference-tone samples
 * - `d[6..7]`: 2 zero-signal baseline offset samples
 *
 * Scaling `(d[1]+d[2]+d[3])*2`, `(d[4]+d[5])*3`, and `(d[6]+d[7])*3` puts all
 * three phase averages on an exact common `6 * mean` scale without integer
 * division, then subtracts the baseline (`ref3`) and clamps negative results to 0.
 *
 * @param[out] out1 Non-negative differential primary detector magnitude (`6 * (mean1 - base)`).
 * @param[out] out2 Non-negative differential reference detector magnitude (`6 * (mean2 - base)`).
 */
void phy_get_fm_sar_dout(int16_t *out1, int16_t *out2)
{
    int16_t d[PHY_SAR_SAMPLE_COUNT];

    sar_trigger_pulse();
    ets_delay_us(PHY_SAR_CONV_DELAY_US);
    sar_wait_idle();
    phy_read_sar_dout(d);

    /* Place 3-sample sig1, 2-sample sig2, and 2-sample baseline onto a common 6x mean scale */
    uint16_t ref3 = (uint16_t)(((uint16_t)d[6] + (uint16_t)d[7]) * 3U);
    uint16_t sig1 = (uint16_t)(((uint16_t)d[1] + (uint16_t)d[2] + (uint16_t)d[3]) * 2U);
    uint16_t sig2 = (uint16_t)(((uint16_t)d[4] + (uint16_t)d[5]) * 3U);

    *out1 = (sig1 < ref3) ? 0 : (int16_t)(sig1 - ref3);
    *out2 = (sig2 < ref3) ? 0 : (int16_t)(sig2 - ref3);
}

/**
 * @brief Convert an already-latched 8-sample power-detector SAR capture into relative dB power.
 *
 * Reads `PHY_SAR_DOUT_REG(0..7)` without triggering a new conversion (used for
 * background TX packet power captures), applies the same 6x-scaled differential
 * baseline subtraction as `phy_get_fm_sar_dout()`, converts both channels to
 * logarithmic dB via `phy_linear_to_db(..., 3)`, and computes `ref + db1 - db2`.
 *
 * @param ref Reference dB offset (typically `PHY_SAR_PWDET_REF_DEFAULT`).
 * @return    Measured relative TX power in fixed-point dB units.
 */
int16_t phy_get_sar_dout(uint16_t ref)
{
    int16_t d[PHY_SAR_SAMPLE_COUNT];

    phy_read_sar_dout(d);

    /* Common 6x-scaled differential average against baseline d[6..7] */
    uint16_t ref3 = (uint16_t)(((uint16_t)d[6] + (uint16_t)d[7]) * 3U);
    int16_t diff1 =
        (int16_t)((uint16_t)(((uint16_t)d[1] + (uint16_t)d[2] + (uint16_t)d[3]) * 2U) - ref3);
    int16_t diff2 = (int16_t)((uint16_t)(((uint16_t)d[4] + (uint16_t)d[5]) * 3U) - ref3);

    if (diff1 < 0) {
        diff1 = 0;
    }
    int32_t db1 = phy_linear_to_db((int32_t)diff1, PHY_SAR_PWDET_DB_SHIFT);

    if (diff2 < 0) {
        diff2 = 0;
    }
    int32_t db2 = phy_linear_to_db((int32_t)diff2, PHY_SAR_PWDET_DB_SHIFT);

    return (int16_t)(((int32_t)ref + db1) - db2);
}

/**
 * @brief Actively sample the TX power detector and return the measured power in dB.
 *
 * Triggers a fresh differential SAR burst via `phy_get_fm_sar_dout()` and
 * converts the primary-to-reference ratio into dB relative to `ref`.
 *
 * @param ref Reference dB offset (typically `PHY_SAR_PWDET_REF_DEFAULT`).
 * @return    Measured relative TX power in fixed-point dB units (`ref + db1 - db2`).
 */
int16_t phy_get_power_db(uint16_t ref)
{
    int16_t out1 = 0;
    int16_t out2 = 0;

    phy_get_fm_sar_dout(&out1, &out2);
    int32_t db1 = phy_linear_to_db((int32_t)out1, PHY_SAR_PWDET_DB_SHIFT);
    int32_t db2 = phy_linear_to_db((int32_t)out2, PHY_SAR_PWDET_DB_SHIFT);
    return (int16_t)(((int32_t)ref + db1) - db2);
}

/**
 * @brief Harvest 32 bits of hardware thermal-noise entropy from the baseband RX ADC LSBs.
 *
 * Reads `PHY_BB_ADC_RAND_REG` 8 times; each read extracts 2 I-channel LSBs
 * (`bits [1:0]`) and 2 Q-channel LSBs (`bits [11:10]`, shifted down by 8 into
 * `bits [3:2]`), assembling eight 4-bit nibbles from LSB to MSB.
 *
 * @return 32-bit random word assembled from ADC thermal noise.
 */
uint32_t phy_get_adc_rand(void)
{
    uint32_t rnd = 0U;

    for (uint32_t shift = 0U; shift < 32U; shift += 4U) {
        uint32_t val = PHY_REG_READ(PHY_BB_ADC_RAND_REG);
        /* Combine Q-channel LSBs [11:10] (shifted to [3:2]) with I-channel LSBs [1:0] */
        uint32_t nibble = ((val >> PHY_ADC_RAND_Q_SHIFT) & PHY_ADC_RAND_Q_MASK) |
                          (val & PHY_ADC_RAND_I_MASK);
        rnd |= (nibble << shift);
    }
    return rnd;
}

/* --------------------------------------------------------------------------
 * Exported ADC & VDD33 APIs (Flash)
 * -------------------------------------------------------------------------- */

/**
 * @brief Safely measure internal VDD33 voltage while coordinating with Wi-Fi RF sleep state.
 *
 * Powers the SAR analog rail, pauses active Wi-Fi RF via `PHY_PM_MODE_MODEM_PAUSE`
 * (or enables Wi-Fi sub-block clocks, initializes SAR, and clears
 * `PHY_RF_CAL_MODE_LOWPWR_BIT` if RF is already sleeping or built in `PHY_ONLY` mode),
 * measures VDD33 when `PHY_CTRL_VDD33_CONST == PHY_VDD33_MODE_MEASURE` (`0xFF`),
 * clears the SAR input muxes, re-arms the power detector, and restores prior
 * RF/clock/power state.
 *
 * @return Raw VDD33 reading when VDD33 ADC measurement is enabled in init data,
 *         or `PHY_ADC_INVALID` (`0xFFFF`) when init data configures TOUT mode instead.
 */
uint16_t phy_get_vdd33(void)
{
    uint32_t saved_rf_pwr = PHY_REG_READ(PHY_RTC_RF_PWR_REG);
    uint16_t ret = PHY_ADC_INVALID;

    PHY_REG_SET(PHY_RTC_RF_PWR_REG, PHY_RTC_RF_PWR_DEEP_SAR);

#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
    if (g_phy_sleep_mode_flag == 0U) {
        pm_set_sleep_mode(PHY_PM_MODE_MODEM_PAUSE);
    } else
#endif
    {
        phy_sar_init();
        PHY_REG_SET(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_SUB);
        PHY_REG_CLR(PHY_RF_CAL_MODE_REG, PHY_RF_CAL_MODE_LOWPWR_BIT);
    }

    /* VDD33 measurement is only active when init_data sets vdd33_const == 0xFF */
    if (chip6_phy_init_ctrl[PHY_CTRL_VDD33_CONST] == PHY_VDD33_MODE_MEASURE) {
        ret = phy_readvdd33(1U);
    }

    sar_wait_idle();
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_TOUT_EN);
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_VDD33_EN);
    sar_pwdet_rearm_pulse();

#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
    if (g_phy_sleep_mode_flag == 0U) {
        pm_wakeup_init(PHY_PM_MODE_MODEM_PAUSE, 0U);
    } else
#endif
    {
        PHY_REG_CLR(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_GATE_MASK);
    }

    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, saved_rf_pwr);
    return ret;
}

/**
 * @brief Read the external TOUT (A0) ADC pin by averaging an 8-sample SAR burst.
 *
 * Temporarily inhibits background TX power tracking (`g_phy_tout_dis_txpwr_track`),
 * powers and initializes the SAR rail if needed, optionally pauses active RF via
 * `PHY_PM_MODE_MODEM_PAUSE` (when built with Wi-Fi), temporarily ungates
 * `PHY_DPORT_CLK_WIFI_SUB` when `g_phy_sleep_mode_flag != 0` (modem sleep / `PHY_ONLY`),
 * captures 8 SAR samples, restores saved clocks/RF power, and returns the 10-bit
 * rounded average (`(sum + 8) >> 4`, mapping 11-bit SAR codes to `0..1024`).
 *
 * @param no_sleep_mode Zero to pause active RF (`PHY_PM_MODE_MODEM_PAUSE`) during
 *                      sampling; non-zero to skip the RF sleep/wake transition
 *                      (ignored in `CONFIG_ESP8266_OSS_PHY_ONLY` builds).
 * @return              10-bit TOUT ADC reading (`0..1024`), or `PHY_ADC_INVALID`
 *                      (`0xFFFF`) when init data reserves the ADC for VDD33 sensing.
 */
uint16_t test_tout(uint8_t no_sleep_mode)
{
    int16_t samples[PHY_SAR_SAMPLE_COUNT];

    g_phy_tout_dis_txpwr_track = 1U;

    uint32_t saved_rf_pwr = PHY_REG_READ(PHY_RTC_RF_PWR_REG);
    PHY_REG_SET(PHY_RTC_RF_PWR_REG, PHY_RTC_RF_PWR_DEEP_SAR);
    if ((saved_rf_pwr & PHY_RTC_RF_PWR_SAR_BIT) == 0U) {
        phy_sar_init();
    }

#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
    if ((g_phy_sleep_mode_flag == 0U) && (no_sleep_mode == 0U)) {
        pm_set_sleep_mode(PHY_PM_MODE_MODEM_PAUSE);
    }
#else
    (void)no_sleep_mode;
#endif

    uint32_t saved_clk = 0U;
    if (g_phy_sleep_mode_flag != 0U) {
        saved_clk = PHY_REG_READ(PHY_DPORT_CLK_EN_REG) & PHY_DPORT_CLK_WIFI_GATE_MASK;
        PHY_REG_SET(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_SUB);
    }

    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2,
                          PHY_I2C_SAR_CTRL_REG,
                          PHY_I2C_SAR_MUX_BIT, PHY_I2C_SAR_MUX_BIT, 1U);
    PHY_REG_SET(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_TOUT_EN);

    sar_wait_idle();
    sar_trigger_pulse();
    ets_delay_us(PHY_SAR_TOUT_DELAY_US);
    sar_wait_idle();

    phy_read_sar_dout(samples);

    uint16_t sum = 0U;
    for (uint32_t i = 0U; i < PHY_SAR_SAMPLE_COUNT; i++) {
        sum = (uint16_t)(sum + (uint16_t)samples[i]);
    }

    /* External TOUT is unavailable when the SAR pin is configured for VDD33 sensing */
    uint16_t ret = (chip6_phy_init_ctrl[PHY_CTRL_VDD33_CONST] == PHY_VDD33_MODE_MEASURE)
                       ? PHY_ADC_INVALID
                       : (uint16_t)(((uint32_t)sum + 8U) >> 4);

    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2,
                          PHY_I2C_SAR_CTRL_REG,
                          PHY_I2C_SAR_MUX_BIT, PHY_I2C_SAR_MUX_BIT, 0U);
    sar_wait_idle();
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_TOUT_EN);
    sar_pwdet_rearm_pulse();

    if (g_phy_sleep_mode_flag != 0U) {
        PHY_REG_RMW(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_GATE_MASK, saved_clk);
    }

#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
    if ((g_phy_sleep_mode_flag == 0U) && (no_sleep_mode == 0U)) {
        pm_wakeup_init(PHY_PM_MODE_MODEM_PAUSE, 0U);
    }
#endif

    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, saved_rf_pwr);
    g_phy_tout_dis_txpwr_track = 0U;
    return ret;
}

/**
 * @brief Capture a high-speed sequence of single-shot TOUT ADC samples at a custom clock divider.
 *
 * Caller is responsible for ensuring Wi-Fi RF is idle/paused. Saves and reconfigures
 * the SAR clock divider, packed 6-phase timing registers, and 1-sample burst length
 * (temporarily ungating `PHY_DPORT_CLK_WIFI_SUB` when `g_phy_sleep_mode_flag != 0`),
 * captures `len` samples into `dst`, and restores all SAR control, timing, mux,
 * clock-gate, power-detector, and RF power registers on exit.
 *
 * @param[out] dst     Destination buffer of at least `len` elements; each entry receives a
 *                     10-bit rounded sample (`(corrected + 1) >> 1`), or `PHY_ADC_INVALID`
 *                     (`0xFFFF`) when init data reserves the ADC for VDD33 sensing.
 * @param      len     Number of consecutive single-shot samples to capture.
 * @param      clk_div SAR clock divider (clamped to a minimum of `PHY_SAR_FAST_MIN_CLKDIV` = 2).
 */
void phy_adc_read_fast(uint16_t *dst, uint16_t len, uint8_t clk_div)
{
    uint32_t saved_rf_pwr = PHY_REG_READ(PHY_RTC_RF_PWR_REG);
    PHY_REG_SET(PHY_RTC_RF_PWR_REG, PHY_RTC_RF_PWR_DEEP_SAR);
    if ((saved_rf_pwr & PHY_RTC_RF_PWR_SAR_BIT) == 0U) {
        phy_sar_init();
    }

    g_phy_tout_dis_txpwr_track = 1U;
    if (clk_div < PHY_SAR_FAST_MIN_CLKDIV) {
        clk_div = PHY_SAR_FAST_MIN_CLKDIV;
    }

    uint32_t saved_clk = 0U;
    if (g_phy_sleep_mode_flag != 0U) {
        saved_clk = PHY_REG_READ(PHY_DPORT_CLK_EN_REG) & PHY_DPORT_CLK_WIFI_GATE_MASK;
        PHY_REG_SET(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_SUB);
    }

    uint32_t saved_ctrl = PHY_REG_READ(PHY_SAR_CTRL_REG);
    uint32_t saved_t0 = PHY_REG_READ(PHY_SAR_TIMING0_REG);
    uint32_t saved_t1 = PHY_REG_READ(PHY_SAR_TIMING1_REG);

    /*
     * Scale the six 8-bit SAR phase durations proportionally to clk_div.
     * Each byte in TIMING0/TIMING1 encodes (cycles - 1), so multiplying by
     * packed byte constants [1,1,5] / [10,3,11] and subtracting 0x010101
     * updates all three phases in each register simultaneously.
     */
    PHY_REG_RMW(PHY_SAR_CTRL_REG, PHY_SAR_CTRL_CLKDIV_MASK,
                ((uint32_t)clk_div << PHY_SAR_CTRL_CLKDIV_SHIFT));
    PHY_REG_RMW(PHY_SAR_TIMING0_REG, PHY_SAR_TIMING_MASK,
                ((uint32_t)clk_div * PHY_SAR_FAST_TIMING0_MUL) - PHY_SAR_FAST_TIMING_BIAS);
    PHY_REG_RMW(PHY_SAR_TIMING1_REG, PHY_SAR_TIMING_MASK,
                ((uint32_t)clk_div * PHY_SAR_FAST_TIMING1_MUL) - PHY_SAR_FAST_TIMING_BIAS);
    /* Clear burst sample count field to 0 (single-sample conversion mode) */
    PHY_REG_CLR(PHY_SAR_CTRL_REG, PHY_SAR_CTRL_SAMPLE_CNT_MASK);

    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2,
                          PHY_I2C_SAR_CTRL_REG,
                          PHY_I2C_SAR_MUX_BIT, PHY_I2C_SAR_MUX_BIT, 1U);
    PHY_REG_SET(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_TOUT_EN);
    sar_wait_idle();

    for (uint16_t i = 0U; i < len; i++) {
        sar_trigger_pulse();
        ets_delay_us(PHY_SAR_FAST_DELAY_US);
        sar_wait_idle();

        uint32_t raw = PHY_REG_READ(PHY_SAR_DOUT_REG(0U));
        if (chip6_phy_init_ctrl[PHY_CTRL_VDD33_CONST] == PHY_VDD33_MODE_MEASURE) {
            dst[i] = PHY_ADC_INVALID;
        } else {
            dst[i] = (uint16_t)(((uint32_t)sar_raw_correct(raw) + 1U) >> 1);
        }
    }

    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2,
                          PHY_I2C_SAR_CTRL_REG,
                          PHY_I2C_SAR_MUX_BIT, PHY_I2C_SAR_MUX_BIT, 0U);
    PHY_REG_WRITE(PHY_SAR_CTRL_REG, saved_ctrl);
    PHY_REG_WRITE(PHY_SAR_TIMING0_REG, saved_t0);
    PHY_REG_WRITE(PHY_SAR_TIMING1_REG, saved_t1);

    sar_wait_idle();
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_TOUT_EN);
    sar_pwdet_rearm_pulse();

    if (g_phy_sleep_mode_flag != 0U) {
        PHY_REG_RMW(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_GATE_MASK, saved_clk);
    }

    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, saved_rf_pwr);
    g_phy_tout_dis_txpwr_track = 0U;
}
