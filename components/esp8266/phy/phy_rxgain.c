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
// Portions of the RX gain table builder, dual-window baseband gain RAM loader,
// and noise-floor hardware sequences are adapted from teatime-os:
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

#include "phy_internal.h"

/* --------------------------------------------------------------------------
 * File-Local Calibration, Gain Table & Noise-Floor Constants
 * -------------------------------------------------------------------------- */

/* Two-stage PBUS RX DC offset servo (phy_pbus_dco_sa2) */
#define RXDCO_STAGE_COARSE              PHY_PBUS_WIDTH_1 /* Stage 1: coarse DCO DAC */
#define RXDCO_STAGE_FINE                PHY_PBUS_WIDTH_2 /* Stage 2: fine DCO DAC */
#define RXDCO_FINE_MIDSCALE_VAL         0x100U           /* Mid-scale 9-bit fine DAC preload */
#define RXDCO_DAC_INIT_Q1               0x200            /* Initial Q1 accumulator (DAC 256.0) */
#define RXDCO_DAC_MAX_Q1                0x3FF            /* Max Q1 accumulator (DAC 511.5) */
#define RXDCO_MAX_ITERS                 12U              /* Max servo iterations per stage */
#define RXDCO_CGAIN_BITS_MASK           0x7CU            /* 5 thermometer coarse-gain bits */
#define RXDCO_FGAIN_SHIFT               3U               /* Fine-gain shift in PBUS ch3 w2 */
#define RXDCO_FGAIN_MAX                 6U               /* Max index into s_dco_gain_coarse */
#define RXDCO_FINE_GAIN_SCALE           40               /* Stage-2 proportional gain factor */
#define RXDCO_TOL_LOW                   2                /* Convergence deadband (cgain < 3) */
#define RXDCO_TOL_MID                   5                /* Convergence deadband (cgain == 3) */
#define RXDCO_TOL_HIGH                  10               /* Convergence deadband (cgain > 3) */
#define RXDCO_CAL_SAMPLES               4000U            /* IQ-est samples per DCO servo step */
#define RXDCO_CAL_SETTLE_US             10U              /* Analog settle delay after PBUS write */

/* TX DC offset binary search for RXIQ loopback (s_rxiq_cal_tos_v60) */
#define RXIQ_TOS_INIT_CODE              64               /* Mid-range 7-bit TXDC code */
#define RXIQ_TOS_MAX_CODE               127              /* Max 7-bit TXDC code */
#define RXIQ_TOS_INIT_STEP              28               /* Initial binary search step */
#define RXIQ_TOS_ITERS                  12U              /* Total comparator iterations */
#define RXIQ_TOS_AVG_START              8U               /* First iter included in 4-pt average */
#define RXIQ_TOS_MCAL_TIMEOUT           100000U          /* Poll limit for PHY_MCAL_DONE */
#define RXIQ_TOS_MCAL_SETTLE_US         2U               /* Comparator settle delay (us) */
#define RXIQ_TOS_TXEN_BIAS              127U             /* PBUS ch1 w1 bias after TXDC search */

/* RXIQ mismatch estimation and register encoding */
#define RXIQ_GAIN_LIMIT                 15               /* Signed 5-bit RXIQ gain limit [-15, 15] */
#define RXIQ_PHASE_LIMIT                31               /* Signed 6-bit RXIQ phase limit [-31, 31] */
#define RXIQ_GAIN_FIELD_MASK            0x1FU            /* 5-bit gain register / packed mask */
#define RXIQ_PHASE_FIELD_MASK           0x3FU            /* 6-bit phase register / packed mask */
#define RXIQ_PACK_GAIN_SHIFT            6U               /* Gain bit offset in 11-bit rxiq[5] */
#define RXIQ_PACK_MASK                  0x7FFU           /* 11-bit packed (g[4:0]<<6 | p[5:0]) */
#define RXIQ_MIS_SCALE                  512              /* Q9 correlator scale before /2 round */
#define RXIQ_PHASE_SQ_ROUND             128              /* Half-LSB rounding for (p^2)/256 */
#define RXIQ_PHASE_SQ_SHIFT             8                /* Divide by 256 for p^2 gain comp */
#define RXIQ_COVER_ITERS                2U               /* Closed-loop refinement passes */
#define RXIQ_COVER_FAIL_THRESH          4                /* Residual threshold flagging cal warn */
#define PHY_CHECK_RXIQ_FAIL_BIT         0x4000U          /* g_phy_check_result RXIQ warn bit */
#define RXIQ_CAL_LEVELS                 5U               /* 5 coarse-gain RXIQ levels (0..4) */
#define RXIQ_CAL_SHIFT_BITS             13U              /* 2^13 = 8192 IQ-est samples */
#define RXIQ_CAL_TONE_FREQ              8                /* Loopback DDS tone frequency code */
#define RXIQ_CAL_AVG_ITERS              4U               /* Max RXIQ measurements averaged */
#define RXIQ_LOOPBACK_PBUS_R2           0x104U           /* Loopback PBUS ch2 RX ctrl word */
#define RXIQ_LOOPBACK_BBRX2             0x16U            /* Loopback PBUS ch3 w2 RXBB fine word */
#define RXIQ_PWR_PROBE_SAMPLES          0x400U           /* 1024 samples for loopback AGC probe */
#define RXIQ_PWR_MIN                    0x200U           /* Minimum target loopback power */
#define RXIQ_PWR_MAX                    0x7A00U          /* Maximum target loopback power */
#define RXIQ_PWR_HIGH_THRESH            0x8000           /* Clipping threshold (> reduces gain) */
#define RXIQ_PWR_LOW_THRESH             0x3FF            /* Very-low power threshold (PA gain 7) */
#define RXIQ_ATTEN_STEP_QDB             24U              /* Fallback DDS tone atten increase */
#define ANA_INF_RX_MODE_CAL             0U               /* ANA_INF reg 0x12 calibration mode */
#define ANA_INF_RX_MODE_NORMAL          0xE8U            /* ANA_INF reg 0x12 normal RX mode */
#define ANA_INF_RX_MODE_FREQOFF         0xD8U            /* ANA_INF reg 0x12 freq-offset mode */

/* RX gain table geometry and dual-window 64-bit baseband RAM packing */
#define RXGAIN_COARSE_LEVELS_MAX        4U               /* Max thermometer bit count (0..4) */
#define RXGAIN_FINE_STEPS_PER_COARSE    6U               /* 6 fine steps per coarse level */
#define RXGAIN_DC_SLOT_MAX              29U              /* Last of 30 (5x6) DC table slots */
#define RXGAIN_DC_DIRECT_LIMIT          24U              /* Slots 0..23 calibrated; 24..29 cloned */
#define RXGAIN_DC_TABLE_OFFSET          64U              /* Word offset of DC table in 125-w buf */
#define RXGAIN_ENTRY_MASK               0x7FFFU          /* 15-bit hardware RX gain code mask */
#define RXGAIN_PBUS_MASK                0x0FFFU          /* 12-bit RX gain code for PBUS force */
#define RXGAIN_BB_STEP_MASK             0x1FFFU          /* 13-bit baseband step field mask */
#define RXGAIN_BB_STEP_SHIFT            3U               /* Baseband step bit shift in gain word */
#define RXGAIN_MAX_SEQ                  0x7FU            /* Hard entry limit (127) in table gen */
#define RXGAIN_DEFAULT_MAX_BB           0x1CU            /* Max BB gain step (28) for table gen */
#define RXGAIN_TABLE_LEN_BASE           16U              /* Full length of s_gain_idx_tab */
#define RXGAIN_DC_COARSE_SHIFT          9U               /* Coarse 9-bit DAC offset in dc word */
#define RXGAIN_RAM_LO_GAIN_SHIFT        17U              /* Gain[14:0] -> lo_word[31:17] */
#define RXGAIN_RAM_LO_DCI_HI_SHIFT      8U               /* dc_i_coarse[8:0] -> lo_word[16:8] */
#define RXGAIN_RAM_HI_DCI_LSB_SHIFT     31U              /* dc_i_fine[0] -> hi_word[31] */
#define RXGAIN_RAM_HI_DCQ_HI_SHIFT      22U              /* dc_q_coarse[8:0] -> hi_word[30:22] */
#define RXGAIN_RAM_HI_DCQ_LO_SHIFT      13U              /* dc_q_fine[8:0] -> hi_word[21:13] */
#define RXGAIN_RAM_HI_RXIQ_SHIFT        2U               /* rxiq[10:0] -> hi_word[12:2] */

/* Noise-floor readout, IIR tracking and initialization constants */
#define NOISE_RAW_OFFSET                0x800            /* 12-bit readout signed bias (-2048) */
#define NOISE_HW_RSSI_MASK              0xFFFU           /* 12-bit raw RSSI noise mask */
#define NOISE_HW_RSSI_BIAS              0xFFF            /* Raw RSSI full-scale subtraction bias */
#define NOISE_START_INIT_VAL            0x1A0U           /* Initial NF register seed on start */
#define NOISE_FLOOR_CH_AND_SET_MASK     (PHY_BB_NOISE_FLOOR_CH_MASK | PHY_BB_NOISE_FLOOR_SET_MASK)
#define NOISE_LOOP_CH_DEFAULT           (1U << PHY_BB_NOISE_FLOOR_CH_SHIFT)
#define NOISE_LOOP_CTRL_READY_SHIFT     15U              /* Bits [17,15] in PHY_BB_RX_CTRL_REG */
#define NOISE_LOOP_CTRL_READY_MASK      5U               /* Both bits set => meas engine armed */
#define NOISE_LOOP_TIMEOUT_LIMIT        9U               /* Max busy polls before fallback NF */
#define NOISE_LOOP_TIMEOUT_FALLBACK_QDB (-336)           /* -84.0 dBm fallback on meas timeout */
#define NOISE_LOOP_VALID_MIN_QDB        (-404)           /* Reject readings <= -101.0 dBm */
#define NOISE_LOOP_DROP_FAST_THRESH     16               /* > 4 dB drop uses max-step clamp */
#define NOISE_LOOP_DROP_MAX_STEP        12               /* Max single-step drop (3.0 dB) */
#define NOISE_LOOP_HYSTERESIS_QDB       8                /* +/-2.0 dB update hysteresis */
#define NOISE_SCAN_BLEND_THRESH_QDB     (-387)           /* Scan-mode blend threshold (-96.75 dBm) */
#define NOISE_INIT_GROUPS               4U               /* 4 probe channels: Ch 1, 6, 11, 14 */
#define NOISE_INIT_GAIN_FORCE_VAL       201U             /* RX gain force code during NF init */
#define NOISE_INIT_CH0_CAP_QDB          (-40)            /* Upper cap (-10 dBm) on Ch 1 init NF */
#define NOISE_INIT_DIG_RX_BIT           1U               /* Bit cleared in PHY_BB_DIG_RX_REG */
#define NOISE_INIT_AGC_9D20_BIT         0x40000000U      /* Bit cleared in PHY_BB_AGC_THR_9D20 */

/* --------------------------------------------------------------------------
 * Owned Cross-TU & File-Local State (Explicitly Initialized, 0 SHN_COMMON)
 * -------------------------------------------------------------------------- */

uint8_t g_phy_sw_scan_mode = 0U;

static int16_t s_noise_array[NOISE_INIT_GROUPS] = { 0, 0, 0, 0 };
static uint16_t s_loop_time_limit = 0U;
static uint32_t s_rxiq_compute_num = 0U;
static uint8_t s_rxiq_cover_fail_num = 0U;

/* --------------------------------------------------------------------------
 * 4-Byte Aligned Flash Lookup Tables (.flash.rodata)
 * -------------------------------------------------------------------------- */

/* Thermometer-encoded RXBB coarse step codes for baseband gain groups 0..4 */
static const uint16_t s_bb_step_tab[5] __attribute__((aligned(4))) = {
    0x0000U, 0x0010U, 0x0014U, 0x0015U, 0x0017U
};

/* RF front-end (LNA/mixer) gain stage codes indexed by coarse gain tier 0..15 */
static const uint8_t s_gain_idx_tab[16] __attribute__((aligned(4))) = {
    0x00U, 0x04U, 0x20U, 0x24U, 0x28U, 0x2CU, 0x30U, 0x34U,
    0x40U, 0x60U, 0x64U, 0x68U, 0x70U, 0x74U, 0x78U, 0x7CU
};

/* Number of 1 dB baseband steps traversed within each RF gain tier 0..14 */
static const uint8_t s_bb_idx_tab[15] __attribute__((aligned(4))) = {
    4U, 2U, 5U, 5U, 5U, 2U, 5U, 5U, 3U, 5U, 5U, 4U, 5U, 5U, 4U
};

/* Coarse-stage DCO servo proportional gain per RXBB fine-gain index (0..6) */
static const uint8_t s_dco_gain_coarse[7] __attribute__((aligned(4))) = {
    105U, 86U, 80U, 72U, 64U, 55U, 50U
};

/* PBUS ch3 w1 RXBB coarse-gain codes for RXIQ loopback levels 1..4 */
static const uint8_t s_rxiq_bbrx1[4] __attribute__((aligned(4))) = {
    0x04U, 0x14U, 0x54U, 0x74U
};

/* Initial DDS tone attenuation (0.25 dB units) for RXIQ loopback levels 1..4 */
static const uint8_t s_rxiq_atten[4] __attribute__((aligned(4))) = {
    0U, 15U, 24U, 24U
};

/* --------------------------------------------------------------------------
 * Internal Utility Helpers
 * -------------------------------------------------------------------------- */

/**
 * @brief Return the absolute value of a signed 32-bit integer.
 *
 * @param v  Signed 32-bit input value.
 * @return   Non-negative magnitude of @p v.
 */
static inline int32_t s_abs32(int32_t v)
{
    return (v < 0) ? -v : v;
}

/**
 * @brief Clamp a signed 32-bit integer to the closed interval [@p lo, @p hi].
 *
 * @param v   Signed 32-bit value to clamp.
 * @param lo  Lower inclusive bound.
 * @param hi  Upper inclusive bound.
 * @return    @p lo if @p v < @p lo, @p hi if @p v > @p hi, otherwise @p v.
 */
static inline int32_t s_clamp32(int32_t v, int32_t lo, int32_t hi)
{
    if (v < lo) {
        return lo;
    }
    if (v > hi) {
        return hi;
    }
    return v;
}

/**
 * @brief Count the number of set bits in the lowest 7 bits of @p v.
 *
 * Used to decode thermometer-encoded RXBB coarse-gain bitfields (0..4 active stages).
 *
 * @param v  Input bitfield; only bits [6:0] are examined.
 * @return   Population count in the range 0..7.
 */
static uint32_t s_popcount7(uint32_t v)
{
    v &= 0x7FU;
    uint32_t n = 0U;
    while (v != 0U) {
        v &= (v - 1U);
        n++;
    }
    return n;
}

/**
 * @brief Read the 16-bit packed RX gain entry at index @p n from a 32-bit word table.
 *
 * Even indices occupy bits [15:0] and odd indices occupy bits [31:16] of word `n >> 1`.
 *
 * @param gain_table  Pointer to the packed RX gain table (`phy_rx_gain_dc_table[0..63]`).
 * @param n           Zero-based gain entry index (0..127).
 * @return            16-bit packed RX gain entry.
 */
static uint16_t s_read_gain_entry(const uint32_t *gain_table, uint32_t n)
{
    uint32_t w = gain_table[n >> 1];
    return (uint16_t)(((n & 1U) != 0U) ? (w >> 16) : (w & 0xFFFFU));
}

/* --------------------------------------------------------------------------
 * Live PBUS RX DC Offset Calibration (rom_pbus_dco___SA2)
 * -------------------------------------------------------------------------- */

/**
 * @brief Run the 2-stage coarse/fine PBUS RX DC-offset nulling servo.
 *
 * Reads the currently active RXBB coarse and fine gain settings from PBUS channel 3,
 * preloads the fine DCO DACs to midscale, and executes two successive proportional
 * feedback loops (stage 1 = coarse DAC, stage 2 = fine DAC) using the hardware IQ/DC
 * estimator to zero both I and Q baseband DC offsets.
 *
 * @param samples   Number of ADC samples accumulated per IQ-estimator measurement.
 * @param out_dac   Output array of 4 converged 9-bit DAC codes:
 *                  `[0]`=I coarse, `[1]`=Q coarse, `[2]`=I fine, `[3]`=Q fine.
 * @param delay_us  Analog settling delay in microseconds after each PBUS DAC update.
 */
static void phy_pbus_dco_sa2(uint16_t samples, int16_t out_dac[4], uint16_t delay_us)
{
    /* Decode active RXBB coarse gain (thermometer bit count in bits [6:2]) and
     * fine gain index (bits [10:3] of width 2, clamped to s_dco_gain_coarse[0..6]). */
    uint32_t r31 = (uint32_t)phy_pbus_rd(PHY_PBUS_CH_RXBB_GAIN, PHY_PBUS_WIDTH_1) & 0xFFU;
    uint32_t cgain = s_popcount7(r31 & RXDCO_CGAIN_BITS_MASK);
    uint32_t fgain = ((uint32_t)phy_pbus_rd(PHY_PBUS_CH_RXBB_GAIN, PHY_PBUS_WIDTH_2) >>
                      RXDCO_FGAIN_SHIFT) & 0xFFU;
    if (fgain > RXDCO_FGAIN_MAX) {
        fgain = RXDCO_FGAIN_MAX;
    }

    /* Center the fine-stage I/Q DCO DACs so stage 1 nulls around midscale. */
    phy_pbus_force(PHY_PBUS_CH_TXGAIN_RXDCO_I, RXDCO_STAGE_FINE, RXDCO_FINE_MIDSCALE_VAL);
    phy_pbus_force(PHY_PBUS_CH_RXDCO_Q, RXDCO_STAGE_FINE, RXDCO_FINE_MIDSCALE_VAL);

    /* Loop gain shift and convergence deadband scale with RXBB coarse gain to
     * keep the proportional servo critically damped across all gain tiers. */
    uint32_t shift1 = (cgain + 6U) & 0xFFU;
    int32_t tol = (cgain < 3U) ? RXDCO_TOL_LOW : (cgain == 3U) ? RXDCO_TOL_MID : RXDCO_TOL_HIGH;
    int32_t tol2 = (cgain > 3U) ? RXDCO_TOL_MID : RXDCO_TOL_LOW;
    uint32_t shift = shift1;

    /* Two-stage servo: stage 1 drives PBUS width 1 (coarse DCO), stage 2 drives
     * PBUS width 2 (fine DCO). Each stage tracks the DAC in Q1 fixed-point
     * [0x000..0x3FF] (rounded to 9-bit DAC code via (dac + 1) >> 1) for up to
     * 12 iterations until |DC_I| and |DC_Q| both fall within tolerance. */
    for (uint8_t stage = RXDCO_STAGE_COARSE; stage <= RXDCO_STAGE_FINE; stage++) {
        int32_t dac_i = RXDCO_DAC_INIT_Q1;
        int32_t dac_q = RXDCO_DAC_INIT_Q1;
        int16_t *dst = &out_dac[(uint32_t)(stage - 1U) * 2U];

        for (uint32_t iter = 0U; iter < RXDCO_MAX_ITERS; iter++) {
            dst[0] = (int16_t)((dac_i + 1) >> 1);
            phy_pbus_force(PHY_PBUS_CH_TXGAIN_RXDCO_I, stage, (uint16_t)dst[0]);
            dst[1] = (int16_t)((dac_q + 1) >> 1);
            phy_pbus_force(PHY_PBUS_CH_RXDCO_Q, stage, (uint16_t)dst[1]);

            ets_delay_us(delay_us);

            int32_t dc[2];
            phy_dc_iq_est(1U, samples, dc);

            if (s_abs32(dc[0]) <= tol && s_abs32(dc[1]) <= tol) {
                break;
            }

            int32_t step_i;
            int32_t step_q;
            if (stage == RXDCO_STAGE_COARSE) {
                /* Coarse step: inverse sensitivity from s_dco_gain_coarse[fgain] >> (cgain + 6) */
                step_i = ((int32_t)s_dco_gain_coarse[fgain] * dc[0]) >> (shift1 & 31U);
                step_q = ((int32_t)s_dco_gain_coarse[fgain] * dc[1]) >> (shift1 & 31U);
            } else {
                /* Fine step: constant sensitivity numerator 40 scaled by stage-2 shift */
                step_i = (dc[0] * RXDCO_FINE_GAIN_SCALE) >> (shift & 31U);
                step_q = (dc[1] * RXDCO_FINE_GAIN_SCALE) >> (shift & 31U);
            }

            dac_i = s_clamp32(dac_i - step_i, 0, RXDCO_DAC_MAX_Q1);
            dac_q = s_clamp32(dac_q - step_q, 0, RXDCO_DAC_MAX_Q1);
        }

        /* Select fine-stage gain shift (4, 5, or 6) from the lower coarse-gain bits
         * and tighten the deadband for stage 2. */
        uint32_t s2_sel = ((r31 >> 2) & 3U) + ((r31 >> 4) & 1U);
        shift = (s2_sel == 0U) ? 4U : (s2_sel == 1U) ? 5U : 6U;
        tol = tol2;
    }
}

/* --------------------------------------------------------------------------
 * Live Loopback RXIQ Calibration
 * -------------------------------------------------------------------------- */

/**
 * @brief Calibrate TX baseband DC offset via binary search on the MCAL_TXDC comparator.
 *
 * Used prior to internal TX->RX loopback RXIQ measurements so LO/DC leakage does not
 * corrupt the loopback tone correlator. Runs 12 comparator steps with decaying step size
 * and averages the final 4 iterations to suppress 1-LSB limit-cycle dither.
 *
 * @param gain    TXBB gain word written to PBUS channel 0 width 1.
 * @param out_iq  Output 2-element array receiving converged 7-bit TXDC codes:
 *                `[0]`=I code (0..127), `[1]`=Q code (0..127).
 */
static void s_rxiq_cal_tos_v60(uint16_t gain, int8_t out_iq[2])
{
    phy_pbus_force(PHY_PBUS_CH_TXBB_DCO_I, PHY_PBUS_WIDTH_1, gain);

    int32_t code_i = RXIQ_TOS_INIT_CODE;
    int32_t code_q = RXIQ_TOS_INIT_CODE;
    int32_t acc_i = 0;
    int32_t acc_q = 0;
    int32_t step = RXIQ_TOS_INIT_STEP;

    /* 12-iteration successive-approximation search on PHY_MCAL_TXDC_REG:
     * bit 31 (sign bit) indicates I comparator polarity, bit 30 (PHY_MCAL_QFLAG)
     * indicates Q comparator polarity. Step decays via (step >> 1) + 1 down to 1,
     * and iterations 8..11 are averaged to center out limit-cycle oscillation. */
    for (uint32_t n = 0U; n < RXIQ_TOS_ITERS; n++) {
        phy_pbus_force(PHY_PBUS_CH_TXEN_DCO_Q, PHY_PBUS_WIDTH_2, (uint16_t)code_q);
        phy_pbus_force(PHY_PBUS_CH_TXBB_DCO_I, PHY_PBUS_WIDTH_2, (uint16_t)code_i);

        PHY_REG_WRITE(PHY_MCAL_TXDC_REG, PHY_MCAL_ARM);
        PHY_REG_WRITE(PHY_MCAL_TXDC_REG, PHY_MCAL_TRIGGER);
        ets_delay_us(RXIQ_TOS_MCAL_SETTLE_US);

        for (uint32_t t = 0U; t < RXIQ_TOS_MCAL_TIMEOUT; t++) {
            if ((PHY_REG_READ(PHY_MCAL_TXDC_REG) & PHY_MCAL_DONE) != 0U) {
                break;
            }
        }

        uint32_t status_i = PHY_REG_READ(PHY_MCAL_TXDC_REG);
        uint32_t status_q = PHY_REG_READ(PHY_MCAL_TXDC_REG);

        if ((int32_t)status_i < 0) {
            code_i = s_clamp32(code_i - step, 0, RXIQ_TOS_MAX_CODE);
        } else {
            code_i = s_clamp32(code_i + step, 0, RXIQ_TOS_MAX_CODE);
        }

        if ((status_q & PHY_MCAL_QFLAG) != 0U) {
            code_q = s_clamp32(code_q - step, 0, RXIQ_TOS_MAX_CODE);
        } else {
            code_q = s_clamp32(code_q + step, 0, RXIQ_TOS_MAX_CODE);
        }

        step = (step == 2) ? 1 : ((step >> 1) + 1);

        if (n >= RXIQ_TOS_AVG_START) {
            acc_i += code_i;
            acc_q += code_q;
        }
    }

    int32_t avg_q = (acc_q + 2) >> 2;
    int32_t avg_i = (acc_i + 2) >> 2;

    phy_pbus_force(PHY_PBUS_CH_TXEN_DCO_Q, PHY_PBUS_WIDTH_2, (uint16_t)avg_q);
    phy_pbus_force(PHY_PBUS_CH_TXBB_DCO_I, PHY_PBUS_WIDTH_2, (uint16_t)avg_i);
    phy_pbus_force(PHY_PBUS_CH_TXEN_DCO_Q, PHY_PBUS_WIDTH_1, RXIQ_TOS_TXEN_BIAS);
    PHY_REG_WRITE(PHY_MCAL_TXDC_REG, PHY_MCAL_STOP);

    out_iq[0] = (int8_t)avg_i;
    out_iq[1] = (int8_t)avg_q;
}

/**
 * @brief Program PBUS RX DCO coarse/fine DACs from the pre-calibrated 30-slot DC table.
 *
 * Maps the active RXBB coarse (`bbrx1`) and fine (`bbrx2`) gain words to a slot index
 * `bits * 6 + fine_idx` in [0..29] and writes the unpacked 9-bit coarse/fine I and Q
 * codes to PBUS channels 4 and 5.
 *
 * @param bbrx1     PBUS channel 3 width 1 RXBB coarse-gain word.
 * @param bbrx2     PBUS channel 3 width 2 RXBB fine-gain word.
 * @param dc_table  Pointer to the 60-word calibrated RX DC table (30 pairs of {I, Q},
 *                  each word packing `(coarse << 9) | fine`).
 */
static void s_set_cal_rxdc(uint16_t bbrx1, uint16_t bbrx2, const uint32_t *dc_table)
{
    uint32_t bits = s_popcount7(bbrx1);
    if (bits > RXGAIN_COARSE_LEVELS_MAX) {
        bits = RXGAIN_COARSE_LEVELS_MAX;
    }
    uint32_t idx = bits * RXGAIN_FINE_STEPS_PER_COARSE +
                   (((uint32_t)bbrx2 >> RXDCO_FGAIN_SHIFT) & 7U);
    if (idx > RXGAIN_DC_SLOT_MAX) {
        idx = RXGAIN_DC_SLOT_MAX;
    }

    uint32_t dc_i = dc_table[idx * 2U];
    uint32_t dc_q = dc_table[idx * 2U + 1U];

    phy_pbus_force(PHY_PBUS_CH_TXGAIN_RXDCO_I, PHY_PBUS_WIDTH_1,
                   (uint16_t)((dc_i >> RXGAIN_DC_COARSE_SHIFT) & PHY_PBUS_VAL_MASK));
    phy_pbus_force(PHY_PBUS_CH_RXDCO_Q, PHY_PBUS_WIDTH_1,
                   (uint16_t)((dc_q >> RXGAIN_DC_COARSE_SHIFT) & PHY_PBUS_VAL_MASK));
    phy_pbus_force(PHY_PBUS_CH_TXGAIN_RXDCO_I, PHY_PBUS_WIDTH_2,
                   (uint16_t)(dc_i & PHY_PBUS_VAL_MASK));
    phy_pbus_force(PHY_PBUS_CH_RXDCO_Q, PHY_PBUS_WIDTH_2,
                   (uint16_t)(dc_q & PHY_PBUS_VAL_MASK));
}

/**
 * @brief Write an RXIQ gain or phase correction code into the ANA_INF I2C registers.
 *
 * Supports both two's-complement register encoding (`sign_mag_mode == 0`) and
 * sign-magnitude encoding (`sign_mag_mode != 0`, writing the sign bit into
 * `PHY_I2C_ANA_INF_RXIQ_SIGN_REG` and recording it in @p sign_out).
 *
 * @param val            Signed correction value (gain clamped to [-15, 15], phase to [-31, 31]).
 * @param sign_out       Output pointer receiving the sign bit (1 = negative) when
 *                       @p sign_mag_mode is non-zero; unmodified when @p sign_mag_mode == 0.
 * @param is_gain        Non-zero to program RXIQ gain (`reg 0x19[4:0]`); 0 to program
 *                       RXIQ phase (`reg 0x19[7:5]` and `reg 0x1A[2:0]`).
 * @param sign_mag_mode  0 for two's-complement encoding; non-zero for sign-magnitude encoding.
 * @return               Actual clamped signed value applied to hardware.
 */
static int8_t phy_rfcal_rxiq_set_reg(int8_t val, uint8_t *sign_out,
                                     uint8_t is_gain, uint8_t sign_mag_mode)
{
    int32_t v = (int32_t)val;
    uint8_t neg = 0U;

    if (sign_mag_mode == 0U) {
        int32_t lim = (is_gain != 0U) ? RXIQ_GAIN_LIMIT : RXIQ_PHASE_LIMIT;
        v = s_clamp32(v, -lim, lim);
        if (is_gain != 0U) {
            rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                  PHY_I2C_ANA_INF_RXIQ_G_REG, 4U, 0U,
                                  (uint8_t)((uint32_t)v & RXIQ_GAIN_FIELD_MASK));
            return (int8_t)v;
        }
    } else {
        if (v < 0) {
            neg = 1U;
            v = -v;
        }
        *sign_out = neg;
        if (is_gain != 0U) {
            if (v > RXIQ_GAIN_LIMIT) {
                v = RXIQ_GAIN_LIMIT;
            }
            rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                  PHY_I2C_ANA_INF_RXIQ_SIGN_REG, 5U, 5U, neg);
            rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                  PHY_I2C_ANA_INF_RXIQ_G_REG, 4U, 0U,
                                  (uint8_t)((uint32_t)v & RXIQ_GAIN_FIELD_MASK));
            return (neg != 0U) ? (int8_t)(-v) : (int8_t)v;
        }
        if (v > RXIQ_PHASE_LIMIT) {
            v = RXIQ_PHASE_LIMIT;
        }
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_RXIQ_SIGN_REG, 3U, 3U, neg);
    }

    uint32_t uv = (uint32_t)v & 0xFFU;
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                          PHY_I2C_ANA_INF_RXIQ_G_REG, 7U, 5U,
                          (uint8_t)((uv >> 3) & 7U));
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                          PHY_I2C_ANA_INF_RXIQ_P_REG, 2U, 0U,
                          (uint8_t)(uv & 7U));

    if (sign_mag_mode != 0U && neg != 0U) {
        return (int8_t)(-v);
    }
    return (int8_t)v;
}

/**
 * @brief Compute residual RX I/Q gain and phase mismatch from hardware correlator accumulators.
 *
 * Reads the 4 cross-correlation accumulators `{II, IQ, QI, QQ}` produced by the front-end
 * IQ estimator during a single-tone loopback run, forms the positive- and negative-frequency
 * complex tone components `(p1 + j*q1)` and `(p2 + j*q2)`, and computes the image-to-signal
 * ratio `(p2 + j*q2) / (p1 + j*q1)` scaled to Q8 hardware correction units.
 *
 * @param shift_bits  Log2 sample count used to program the IQ estimator (typically 13).
 * @param tx_g_sign   Effective TX I/Q gain sign parity (0 or 1).
 * @param tx_p_sign   Effective TX I/Q phase sign parity (0 or 1).
 * @param rx_p_sign   Effective RX I/Q phase sign parity (0 or 1).
 * @param rx_g_sign   Effective RX I/Q gain sign parity (0 or 1).
 * @param out_mis     Output 2-element array: `[0]`=gain mismatch, `[1]`=phase mismatch.
 */
static void phy_rxiq_get_mis(uint8_t shift_bits, uint8_t tx_g_sign, uint8_t tx_p_sign,
                             uint8_t rx_p_sign, uint8_t rx_g_sign, int8_t out_mis[2])
{
    /* Down-shift raw 32-bit correlator sums by (shift_bits - 2) to avoid 64-bit
     * overflow while retaining full precision in the complex ratio below. */
    uint32_t sh = ((uint32_t)shift_bits - 2U) & 31U;
    int32_t ii = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_ACC_REG(0)) >> sh;
    int32_t iq = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_ACC_REG(1)) >> sh;
    int32_t qi = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_ACC_REG(2)) >> sh;
    int32_t qq = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_ACC_REG(3)) >> sh;

    /* Complex envelope decomposition of the loopback tone:
     *   S_pos = (ii + qq) + j*(iq - qi) = p1 + j*q1  (desired tone)
     *   S_neg = (ii - qq) + j*(qi + iq) = p2 + j*q2  (mirror image from IQ mismatch)
     * If TX and RX I/Q swap parities differ, desired and image tones swap roles. */
    int32_t p1 = ii + qq;
    int32_t p2 = ii - qq;
    int32_t q1 = iq - qi;
    int32_t q2 = qi + iq;

    if ((tx_p_sign ^ tx_g_sign) != (rx_p_sign ^ rx_g_sign)) {
        int32_t tmp = p1;
        p1 = p2;
        p2 = tmp;
        tmp = q1;
        q1 = q2;
        q2 = tmp;
    }

    /* Complex ratio conj(S_pos) * S_neg / |S_pos|^2:
     *   Re = (p1*p2 - q1*q2) / (p1^2 + q1^2) -> gain mismatch
     *   Im = (q1*p2 + p1*q2) / (p1^2 + q1^2) -> phase mismatch
     * Scaled by 512 (Q9) and rounded right by 1 bit into Q8 hardware step units. */
    int64_t denom = (int64_t)p1 * (int64_t)p1 + (int64_t)q1 * (int64_t)q1;
    int64_t num_g = (int64_t)p1 * (int64_t)p2 - (int64_t)q1 * (int64_t)q2;
    int64_t num_p = (int64_t)q1 * (int64_t)p2 + (int64_t)p1 * (int64_t)q2;

    if (denom == 0) {
        denom = 1;
    }

    int8_t raw_g = (int8_t)((num_g * RXIQ_MIS_SCALE) / denom);
    int8_t raw_p = (int8_t)((num_p * RXIQ_MIS_SCALE) / denom);
    int8_t g_mis = (int8_t)((raw_g + 1) >> 1);
    int8_t p_mis = (int8_t)((raw_p + 1) >> 1);

    if (rx_g_sign != 0U) {
        g_mis = (int8_t)(-g_mis);
    }
    if (rx_p_sign != 0U) {
        p_mis = (int8_t)(-p_mis);
    }
    out_mis[0] = g_mis;
    out_mis[1] = p_mis;
}

/**
 * @brief Iteratively converge RXIQ gain and phase estimates with second-order phase compensation.
 *
 * Performs two closed-loop estimator passes while applying a second-order phase-squared
 * gain adjustment (`p^2 / 256`) to cancel the cosine attenuation (`cos(phi) ~= 1 - phi^2/2`)
 * introduced by the phase corrector. Flags `PHY_CHECK_RXIQ_FAIL_BIT` in `g_phy_check_result`
 * if residual mismatch exceeds +/-4 after convergence.
 *
 * @param shift_bits      Log2 sample count per IQ estimator run (samples = `1 << shift_bits`).
 * @param tx_g_sign       Effective TX gain sign parity.
 * @param tx_p_sign       Effective TX phase sign parity.
 * @param orig_rx_g_sign  Initial RX gain sign bit saved from `PHY_I2C_ANA_INF_RXIQ_SIGN_REG`.
 * @param orig_rx_p_sign  Initial RX phase sign bit saved from `PHY_I2C_ANA_INF_RXIQ_SIGN_REG`.
 * @param out_gain        Output pointer receiving final clamped RXIQ gain code [-15, 15].
 * @param out_phase       Output pointer receiving final clamped RXIQ phase code [-31, 31].
 * @param sign_mag_mode   0 for two's-complement register encoding; non-zero for sign-magnitude.
 */
static void phy_rxiq_cover_mg_mp(uint8_t shift_bits, uint8_t tx_g_sign, uint8_t tx_p_sign,
                                 uint8_t orig_rx_g_sign, uint8_t orig_rx_p_sign,
                                 int8_t *out_gain, int8_t *out_phase,
                                 uint8_t sign_mag_mode)
{
    uint16_t samples = (uint16_t)(1U << (shift_bits & 31U));
    int8_t gain_est = 0;
    int8_t phase_est = 0;
    uint8_t cur_g_sign = orig_rx_g_sign;
    uint8_t cur_p_sign = orig_rx_p_sign;
    int8_t mis[2] = { 0, 0 };

    /* Closed-loop 2-pass convergence: before measuring, subtract the second-order
     * phase-squared gain term p_sq = round(phase^2 / 256) from the programmed gain
     * so the phase corrector's amplitude cross-coupling does not bias gain_est,
     * then add p_sq back when accumulating the measured residual mismatch. */
    for (uint32_t iter = 0U; iter < RXIQ_COVER_ITERS; iter++) {
        int32_t p_sq = ((int32_t)phase_est * (int32_t)phase_est + RXIQ_PHASE_SQ_ROUND) >>
                       RXIQ_PHASE_SQ_SHIFT;
        int8_t g_applied = phy_rfcal_rxiq_set_reg((int8_t)((int32_t)gain_est - p_sq),
                                                  &cur_g_sign, 1U, sign_mag_mode);
        int8_t p_applied = phy_rfcal_rxiq_set_reg(phase_est, &cur_p_sign, 0U, sign_mag_mode);

        phy_iq_est_enable(1U, samples);

        cur_g_sign = (uint8_t)(orig_rx_g_sign ^ cur_g_sign);
        cur_p_sign = (uint8_t)(orig_rx_p_sign ^ cur_p_sign);

        phy_rxiq_get_mis(shift_bits, tx_g_sign, tx_p_sign, cur_p_sign, cur_g_sign, mis);

        gain_est = (int8_t)(p_sq + (int32_t)mis[0] + (int32_t)g_applied);
        phase_est = (int8_t)((int32_t)p_applied - (int32_t)mis[1]);

        phy_iq_est_disable();
    }

    if (s_abs32((int32_t)mis[0]) > RXIQ_COVER_FAIL_THRESH ||
        s_abs32((int32_t)mis[1]) > RXIQ_COVER_FAIL_THRESH) {
        g_phy_check_result |= PHY_CHECK_RXIQ_FAIL_BIT;
        s_rxiq_cover_fail_num++;
    }

    gain_est = (int8_t)s_clamp32((int32_t)gain_est, -RXIQ_GAIN_LIMIT, RXIQ_GAIN_LIMIT);
    phase_est = (int8_t)s_clamp32((int32_t)phase_est, -RXIQ_PHASE_LIMIT, RXIQ_PHASE_LIMIT);

    (void)phy_rfcal_rxiq_set_reg(gain_est, &cur_g_sign, 1U, sign_mag_mode);
    (void)phy_rfcal_rxiq_set_reg(phase_est, &cur_p_sign, 0U, sign_mag_mode);

    *out_gain = gain_est;
    *out_phase = phase_est;
}

/**
 * @brief Extract TXIQ sign bits from baseband register and mirror them to ANA_INF I2C.
 *
 * Used only when `sign_mag_mode != 0` so the analog loopback path matches the sign
 * polarity of the committed baseband TXIQ correction.
 *
 * @param tx_g_sign  Output pointer receiving the TXIQ gain sign bit (0 or 1).
 * @param tx_p_sign  Output pointer receiving the TXIQ phase sign bit (0 or 1).
 */
static void s_set_txiq_cal(uint8_t *tx_g_sign, uint8_t *tx_p_sign)
{
    uint32_t reg = PHY_REG_READ(PHY_BB_TXIQ_GAIN_COMMIT_REG);
    uint32_t g = (reg >> PHY_BB_TXIQ_GAIN_SHIFT) & RXIQ_GAIN_FIELD_MASK;
    uint32_t p = (reg >> PHY_BB_TXIQ_PHASE_SHIFT) & RXIQ_PHASE_FIELD_MASK;

    uint32_t g_val = (g < 16U) ? g : ((g - 32U) & 0xFFU);
    uint32_t p_val = (p < 32U) ? 0U : ((p - 64U) & 0xFFU);

    *tx_g_sign = (uint8_t)(((-g_val) >> 7) & 1U);
    *tx_p_sign = (uint8_t)((p_val >> 7) & 1U);

    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                          PHY_I2C_ANA_INF_TXIQ_G_REG, 0U, 0U, *tx_g_sign);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                          PHY_I2C_ANA_INF_DPD_TXIQ_P_REG, 6U, 6U, *tx_p_sign);
}

/**
 * @brief Run one complete single-tone loopback RXIQ calibration measurement.
 *
 * Saves ANA_INF sign/scale registers, enables the RX clock and calibration muxes,
 * injects a single DDS tone at @p tone_freq and @p atten, invokes `phy_rxiq_cover_mg_mp()`
 * to converge gain and phase codes, and restores all ANA_INF registers.
 *
 * @param shift_bits     Log2 IQ-estimator sample count (typically `RXIQ_CAL_SHIFT_BITS` = 13).
 * @param tone_freq      Signed 10-bit DDS tone frequency code.
 * @param atten          Desired tone attenuation (0.25 dB units) split across ANA_INF and DDS.
 * @param out_iq         Output 2-element array: `[0]`=gain [-15, 15], `[1]`=phase [-31, 31].
 * @param sign_mag_mode  0 for two's-complement register encoding; non-zero for sign-magnitude.
 */
static void phy_rfcal_rxiq(uint8_t shift_bits, int16_t tone_freq, uint8_t atten,
                           int8_t out_iq[2], uint8_t sign_mag_mode)
{
    uint8_t orig_tx_g = (rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                              PHY_I2C_ANA_INF_TXIQ_G_REG, 0U, 0U) != 0U) ? 1U : 0U;
    uint8_t orig_tx_p = (rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                              PHY_I2C_ANA_INF_DPD_TXIQ_P_REG, 6U, 6U) != 0U) ? 1U : 0U;
    uint8_t orig_rx_g = (rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                              PHY_I2C_ANA_INF_RXIQ_SIGN_REG, 5U, 5U) != 0U) ? 1U : 0U;
    uint8_t orig_rx_p = (rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                              PHY_I2C_ANA_INF_RXIQ_SIGN_REG, 3U, 3U) != 0U) ? 1U : 0U;
    uint8_t orig_scale = rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                              PHY_I2C_ANA_INF_TX_SCALE_REG, 7U, 0U);

    phy_set_rxclk_en(1U);

    uint8_t tx_g = orig_tx_g;
    uint8_t tx_p = orig_tx_p;
    if (sign_mag_mode != 0U) {
        s_set_txiq_cal(&tx_g, &tx_p);
    }

    /* Enable TXIQ cal mux (reg 0x10[2]) and RXIQ cal path (reg 0x18[7]). */
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                          PHY_I2C_ANA_INF_TXIQ_G_REG, 2U, 2U, 1U);
    tx_g ^= orig_tx_g;
    tx_p ^= orig_tx_p;
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                          PHY_I2C_ANA_INF_RXIQ_SIGN_REG, 7U, 7U, 1U);

    uint8_t tx_atten = phy_set_ana_inf_tx_scale(atten);
    phy_start_tx_tone(1U, tone_freq, tx_atten, 0U, 0, 0U, 0U, 0, 0U);

    int8_t g_out = 0;
    int8_t p_out = 0;
    phy_rxiq_cover_mg_mp(shift_bits, tx_g, tx_p, orig_rx_g, orig_rx_p,
                         &g_out, &p_out, sign_mag_mode);

    phy_stop_tx_tone(1U);

    /* Restore ANA_INF sign bits, TX scale, and disable calibration muxes. */
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                          PHY_I2C_ANA_INF_TXIQ_G_REG, 0U, 0U, orig_tx_g);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                          PHY_I2C_ANA_INF_DPD_TXIQ_P_REG, 6U, 6U, orig_tx_p);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                          PHY_I2C_ANA_INF_RXIQ_SIGN_REG, 5U, 5U, orig_rx_g);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                          PHY_I2C_ANA_INF_RXIQ_SIGN_REG, 3U, 3U, orig_rx_p);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                          PHY_I2C_ANA_INF_TX_SCALE_REG, 7U, 0U, orig_scale);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                          PHY_I2C_ANA_INF_RXIQ_SIGN_REG, 7U, 7U, 0U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                          PHY_I2C_ANA_INF_TXIQ_G_REG, 2U, 2U, 0U);

    phy_set_rxclk_en(0U);

    out_iq[0] = g_out;
    out_iq[1] = p_out;
}

/**
 * @brief Calibrate RXIQ correction values across all 5 coarse RXBB gain tiers.
 *
 * For each coarse gain level (0..4, or level 0 only when @p single_mode is non-zero):
 * configures internal TX->RX loopback, nulls TX DC on levels 0..1, auto-levels the
 * loopback tone amplitude into `[0x200..0x7A00]` via PA gain / tone attenuation, and
 * averages up to 4 `phy_rfcal_rxiq()` runs (stopping early when two consecutive runs
 * agree within 1 LSB). Packs each 11-bit `(gain[4:0] << 6) | phase[5:0]` into @p rxiq_out.
 *
 * @param single_mode    Non-zero to probe only gain level 0 without storing to @p rxiq_out;
 *                       0 to calibrate and store all 5 coarse gain levels.
 * @param tone_freq      Signed 10-bit loopback DDS tone frequency code.
 * @param rxiq_out       Output array of 5 packed 11-bit RXIQ entries (one per coarse tier).
 * @param dc_table       Pre-calibrated 60-word RX DC table applied for each loopback gain.
 * @param sign_mag_mode  0 for two's-complement register encoding; non-zero for sign-magnitude.
 */
static void phy_set_rx_gain_cal_iq(uint8_t single_mode, int16_t tone_freq,
                                   uint16_t rxiq_out[5], const uint32_t *dc_table,
                                   uint8_t sign_mag_mode)
{
    PHY_REG_CLR(PHY_RF_RX_GAIN_EXT_REG, PHY_RF_RX_GAIN_EXT_DIG);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                          PHY_I2C_ANA_INF_RX_MODE_REG, 7U, 0U, ANA_INF_RX_MODE_CAL);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                          PHY_I2C_ANA_INF_TX_SCALE_REG, 7U, 0U, 0U);

    uint32_t num_levels = (single_mode != 0U) ? 1U : RXIQ_CAL_LEVELS;

    for (uint32_t lvl = 0U; lvl < num_levels; lvl++) {
        uint16_t txbb;
        uint16_t bbrx1;
        uint8_t atten;

        if (lvl >= 1U && lvl <= 4U) {
            txbb = 0U;
            bbrx1 = s_rxiq_bbrx1[lvl - 1U];
            atten = s_rxiq_atten[lvl - 1U];
        } else {
            txbb = (lvl == 0U) ? 8U : 0U;
            bbrx1 = 0U;
            atten = 0U;
        }

        phy_pbus_xpd_tx_on(txbb);
        if (lvl < 2U) {
            int8_t tdc[2];
            s_rxiq_cal_tos_v60(txbb, tdc);
        }

        phy_set_loopback_gain(1U, RXIQ_LOOPBACK_PBUS_R2, bbrx1, RXIQ_LOOPBACK_BBRX2);
        s_set_cal_rxdc(bbrx1, RXIQ_LOOPBACK_BBRX2, dc_table);
        phy_set_rxclk_en(1U);

        /* Up to 2 automatic level-control probes keep loopback ADC power inside
         * the linear sweet spot [0x200..0x7A00] (no noise floor starvation or clipping). */
        uint16_t pa_gain = 1U;
        for (uint32_t k = 0U; k < 2U; k++) {
            phy_start_tx_tone(1U, tone_freq, atten, 0U, 0, 0U, 0U, 0, 0U);
            phy_iq_est_enable(1U, RXIQ_PWR_PROBE_SAMPLES);
            uint32_t total_pwr = PHY_REG_READ(PHY_FE_IQ_EST_PWR_REG) >> 8;
            phy_iq_est_disable();
            phy_stop_tx_tone(1U);

            if (total_pwr >= RXIQ_PWR_MIN && total_pwr <= RXIQ_PWR_MAX) {
                break;
            }
            if ((int32_t)total_pwr <= RXIQ_PWR_HIGH_THRESH) {
                if (k == 0U) {
                    pa_gain = ((int32_t)total_pwr > RXIQ_PWR_LOW_THRESH) ? 3U : 7U;
                } else {
                    atten = 0U;
                }
            } else {
                if (k == 0U) {
                    pa_gain = 0U;
                } else {
                    atten = (uint8_t)(atten + RXIQ_ATTEN_STEP_QDB);
                }
            }

            phy_set_loopback_gain(pa_gain, RXIQ_LOOPBACK_PBUS_R2, bbrx1, RXIQ_LOOPBACK_BBRX2);
            s_set_cal_rxdc(bbrx1, RXIQ_LOOPBACK_BBRX2, dc_table);
        }

        /* Repeat RXIQ measurement up to 4 times; exit early with a 2-point average
         * once consecutive gain & phase readings match within 1 LSB. */
        int32_t sum_g = 0;
        int32_t sum_p = 0;
        int8_t prev_g = 0;
        int8_t prev_p = 0;
        int32_t final_g = 0;
        int32_t final_p = 0;
        uint32_t iters = RXIQ_CAL_AVG_ITERS;

        for (uint32_t n = 0U; n < RXIQ_CAL_AVG_ITERS; n++) {
            int8_t iq[2];
            phy_rfcal_rxiq(RXIQ_CAL_SHIFT_BITS, tone_freq, atten, iq, sign_mag_mode);

            if (n != 0U &&
                s_abs32((int32_t)prev_g - (int32_t)iq[0]) < 2 &&
                s_abs32((int32_t)prev_p - (int32_t)iq[1]) < 2) {
                final_g = ((int32_t)iq[0] + (int32_t)prev_g + 1) >> 1;
                final_p = ((int32_t)iq[1] + (int32_t)prev_p + 1) >> 1;
                iters = n;
                break;
            }

            sum_g += (int32_t)iq[0];
            sum_p += (int32_t)iq[1];
            prev_g = iq[0];
            prev_p = iq[1];

            if (n == (RXIQ_CAL_AVG_ITERS - 1U)) {
                final_g = (sum_g + 2) >> 2;
                final_p = (sum_p + 2) >> 2;
            }
        }

        final_g = s_clamp32(final_g, -RXIQ_GAIN_LIMIT, RXIQ_GAIN_LIMIT);
        final_p = s_clamp32(final_p, -RXIQ_PHASE_LIMIT, RXIQ_PHASE_LIMIT);

        if (single_mode == 0U) {
            rxiq_out[lvl] = (uint16_t)((((uint32_t)final_g & RXIQ_GAIN_FIELD_MASK) <<
                                        RXIQ_PACK_GAIN_SHIFT) |
                                       ((uint32_t)final_p & RXIQ_PHASE_FIELD_MASK));
        }
        s_rxiq_compute_num = (s_rxiq_compute_num << 2) | (iters & 3U);
    }

    PHY_REG_SET(PHY_RF_RX_GAIN_EXT_REG, PHY_RF_RX_GAIN_EXT_DIG);
}

/* --------------------------------------------------------------------------
 * RX Gain Table Generation & Dual-Window Hardware RAM Load
 * -------------------------------------------------------------------------- */

/**
 * @brief Generate the monotonic 1 dB-per-entry RX gain code table in packed 16-bit entries.
 *
 * Walks through each RF front-end gain tier `gain_idx[pos]` while stepping baseband gain
 * from `0` up to `bb_idx[pos] - 1` (and on the final tier `last`, up to `max_gain + 1`).
 * Each baseband step is split into a coarse thermometer group (`step = gain / 6`, looked up
 * in `s_bb_step_tab`) and a 3-bit fine step (`frac = gain % 6`), then packed into a 16-bit
 * word `(gain_idx[pos] << 8) + (s_bb_step_tab[step] << 3) + frac`. Pairs of 16-bit entries
 * are stored little-endian in `table[seq >> 1]`.
 *
 * @param table     Destination 32-bit word buffer (at least 64 words for 128 entries).
 * @param max_gain  Maximum baseband gain step allowed on the final RF tier (typically `0x1C`).
 * @param gain_idx  Array of RF front-end gain codes (`s_gain_idx_tab`).
 * @param bb_idx    Array of per-tier baseband step counts (`s_bb_idx_tab`).
 * @param bb_len    Number of active RF gain tiers (`16 - rxmax`).
 * @return          Index of the highest generated gain entry (capped at `PHY_BB_RX_MAX_GAIN_CAP`
 *                  if `seq` reaches `RXGAIN_MAX_SEQ`).
 */
static uint8_t phy_gen_rx_gain_table(uint32_t *table, uint8_t max_gain,
                                     const uint8_t *gain_idx,
                                     const uint8_t *bb_idx, uint8_t bb_len)
{
    uint32_t last = (uint32_t)bb_len - 1U;
    uint32_t seq = 0U;
    uint32_t gain = 0U;
    uint32_t pos = 0U;

    for (;;) {
        /* Advance to the next non-zero RF tier once the current tier's baseband
         * steps are exhausted; on the final tier, continue ramping BB gain up to max_gain. */
        if (gain == (uint32_t)bb_idx[pos] && pos < last) {
            do {
                pos++;
                if (bb_idx[pos] != 0U) {
                    break;
                }
            } while (pos < last);
            gain = 0U;
        }

        /* Encode 15-bit hardware gain word:
         *   [14:8] = RF gain stage (gain_idx[pos])
         *   [7:3]  = RXBB coarse thermometer code (s_bb_step_tab[gain / 6])
         *   [2:0]  = RXBB fine 1 dB step (gain % 6) */
        uint32_t frac = gain % RXGAIN_FINE_STEPS_PER_COARSE;
        uint32_t step = gain / RXGAIN_FINE_STEPS_PER_COARSE;
        uint32_t bb = ((uint32_t)s_bb_step_tab[step] & RXGAIN_BB_STEP_MASK) << RXGAIN_BB_STEP_SHIFT;
        uint32_t val = (((uint32_t)gain_idx[pos] << 8) + bb + frac) & 0xFFFFU;

        if ((seq & 1U) == 0U) {
            table[seq >> 1] = val;
        } else {
            table[seq >> 1] |= val << 16;
        }

        if (gain > (uint32_t)max_gain) {
            return (uint8_t)seq;
        }

        seq++;
        gain++;
        if (seq == RXGAIN_MAX_SEQ) {
            return PHY_BB_RX_MAX_GAIN_CAP;
        }
    }
}

/**
 * @brief Calibrate RX DC offsets & RXIQ (if needed) and load the 64-bit baseband RX gain RAM.
 *
 * Phase 1 (skipped on warm wakeups when `PHY_PARAM_RX_GAIN_VALID` is already set and
 * `g_phy_rx_table_renew_en == 0`): places PBUS in debug mode, calibrates the 30 unique
 * `(coarse_tier, fine_step)` DC-offset slots (measuring even slots `0, 2, ..., 22` via
 * `phy_pbus_dco_sa2()`, copying odd slots from `idx - 1`, and cloning top tier slots
 * `24..29` from `idx - 6`), and optionally runs `phy_set_rx_gain_cal_iq()`.
 *
 * Phase 2 (always executed): packs each gain entry's 15-bit gain code, 18-bit I DC offset,
 * 18-bit Q DC offset, and 11-bit RXIQ word into a 64-bit baseband gain RAM entry and writes
 * it through the dual-window selector `PHY_BB_RX_GAIN_WINDOW_REG` (`LO` then `HI`).
 *
 * @param cal_iq_en   Non-zero to run RXIQ calibration when `PHY_PARAM_RX_GAIN_VALID` is clear.
 * @param param_flag  Pointer to `g_phy_sleep_params.param_flag`; sets `PHY_PARAM_RX_GAIN_VALID`.
 * @param dc_table    60-word buffer holding 30 calibrated `{dc_i, dc_q}` word pairs.
 * @param rxiq_table  5-entry array of packed 11-bit RXIQ values (indexed by coarse tier 0..4).
 * @param count       Number of RX gain entries to calibrate/load (`g_phy_rx_max_gain_val + 1`).
 * @param gain_table  Packed 16-bit RX gain code table produced by `phy_gen_rx_gain_table()`.
 */
static void phy_set_rx_gain_testchip_50(uint8_t cal_iq_en, uint32_t *param_flag,
                                        uint32_t *dc_table, uint16_t rxiq_table[5],
                                        uint8_t count, const uint32_t *gain_table)
{
    if (g_phy_rx_table_renew_en != 0U || (*param_flag & PHY_PARAM_RX_GAIN_VALID) == 0U) {
        PHY_REG_SET(PHY_RFPLL_CTRL_REG, PHY_RFPLL_SLP_HOLD);
        PHY_REG_WRITE(PHY_BB_RX_GAIN_WINDOW_REG, PHY_BB_RX_GAIN_WINDOW_HI);
        phy_pbus_debugmode();

        uint8_t saved_12 = rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                                PHY_I2C_ANA_INF_RX_MODE_REG, 7U, 0U);
        uint8_t saved_18 = (rom_i2c_readReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                                                 PHY_I2C_ANA_INF_RXIQ_SIGN_REG, 5U, 5U) != 0U)
                               ? 1U
                               : 0U;

        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_RXIQ_SIGN_REG, 5U, 5U, 0U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_RX_MODE_REG, 7U, 0U, ANA_INF_RX_MODE_CAL);

        /* Populate all referenced slots in the 30-slot (5 coarse x 6 fine) DC table.
         * Even slots below 24 are directly nulled via phy_pbus_dco_sa2(); odd slots
         * reuse their even neighbor (idx - 1) and slots 24..29 clone tier 3 (idx - 6). */
        uint32_t done_mask = 0U;
        for (uint32_t n = 0U; n < (uint32_t)count; n++) {
            uint16_t raw = s_read_gain_entry(gain_table, n);
            uint32_t bits = s_popcount7((uint32_t)(raw & RXGAIN_ENTRY_MASK) >> RXGAIN_BB_STEP_SHIFT);
            if (bits > RXGAIN_COARSE_LEVELS_MAX) {
                bits = RXGAIN_COARSE_LEVELS_MAX;
            }
            uint32_t idx = bits * RXGAIN_FINE_STEPS_PER_COARSE + ((uint32_t)raw & 7U);
            if (idx > RXGAIN_DC_SLOT_MAX) {
                idx = RXGAIN_DC_SLOT_MAX;
            }

            if ((done_mask & (1U << idx)) == 0U) {
                if (idx < RXGAIN_DC_DIRECT_LIMIT && (idx & 1U) == 0U) {
                    int16_t dac[4];
                    phy_pbus_set_rxgain(raw & RXGAIN_PBUS_MASK);
                    phy_pbus_dco_sa2(RXDCO_CAL_SAMPLES, dac, RXDCO_CAL_SETTLE_US);
                    dc_table[idx * 2U] =
                        (((uint32_t)dac[0] & PHY_PBUS_VAL_MASK) << RXGAIN_DC_COARSE_SHIFT) |
                        ((uint32_t)dac[2] & PHY_PBUS_VAL_MASK);
                    dc_table[idx * 2U + 1U] =
                        (((uint32_t)dac[1] & PHY_PBUS_VAL_MASK) << RXGAIN_DC_COARSE_SHIFT) |
                        ((uint32_t)dac[3] & PHY_PBUS_VAL_MASK);
                } else {
                    uint32_t src = (idx < RXGAIN_DC_DIRECT_LIMIT)
                                       ? (idx - 1U)
                                       : (idx - RXGAIN_FINE_STEPS_PER_COARSE);
                    dc_table[idx * 2U] = dc_table[src * 2U];
                    dc_table[idx * 2U + 1U] = dc_table[src * 2U + 1U];
                }
                done_mask |= (1U << idx);
            }
        }

        if ((*param_flag & PHY_PARAM_RX_GAIN_VALID) == 0U && cal_iq_en != 0U) {
            phy_set_rx_gain_cal_iq(0U, RXIQ_CAL_TONE_FREQ, rxiq_table, dc_table, 0U);
        }

        PHY_REG_CLR(PHY_RFPLL_CTRL_REG, PHY_RFPLL_SLP_HOLD);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_RXIQ_SIGN_REG, 5U, 5U, saved_18);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_RX_MODE_REG, 7U, 0U, saved_12);
        phy_pbus_xpd_tx_off();
        phy_pbus_xpd_rx_on();
        phy_pbus_workmode();

        *param_flag |= PHY_PARAM_RX_GAIN_VALID;
    }

    /* Program the 64-bit hardware RX gain RAM via its dual 32-bit window register:
     *   LO window (0x01E): [31:17]=gain[14:0], [16:8]=dc_i_coarse[8:0], [7:0]=dc_i_fine[8:1]
     *   HI window (0x1E0): [31]=dc_i_fine[0],  [30:22]=dc_q_coarse[8:0],
     *                      [21:13]=dc_q_fine[8:0], [12:2]=rxiq[10:0], [1:0]=0 */
    for (uint32_t n = 0U; n < (uint32_t)count; n++) {
        uint32_t raw = (uint32_t)s_read_gain_entry(gain_table, n) & RXGAIN_ENTRY_MASK;
        uint32_t bits = s_popcount7(raw >> RXGAIN_BB_STEP_SHIFT);
        if (bits > RXGAIN_COARSE_LEVELS_MAX) {
            bits = RXGAIN_COARSE_LEVELS_MAX;
        }
        uint32_t idx = bits * RXGAIN_FINE_STEPS_PER_COARSE + (raw & 7U);
        if (idx > RXGAIN_DC_SLOT_MAX) {
            idx = RXGAIN_DC_SLOT_MAX;
        }

        uint32_t dc_i = dc_table[idx * 2U];
        uint32_t dc_q = dc_table[idx * 2U + 1U];

        uint32_t lo_word = (raw << RXGAIN_RAM_LO_GAIN_SHIFT) |
                           (((dc_i >> RXGAIN_DC_COARSE_SHIFT) & PHY_PBUS_VAL_MASK) <<
                            RXGAIN_RAM_LO_DCI_HI_SHIFT) |
                           ((dc_i & PHY_PBUS_VAL_MASK) >> 1);
        uint32_t hi_word = ((dc_i & 1U) << RXGAIN_RAM_HI_DCI_LSB_SHIFT) |
                           (((dc_q >> RXGAIN_DC_COARSE_SHIFT) & PHY_PBUS_VAL_MASK) <<
                            RXGAIN_RAM_HI_DCQ_HI_SHIFT) |
                           ((dc_q & PHY_PBUS_VAL_MASK) << RXGAIN_RAM_HI_DCQ_LO_SHIFT) |
                           (((uint32_t)rxiq_table[bits] & RXIQ_PACK_MASK) <<
                            RXGAIN_RAM_HI_RXIQ_SHIFT);

        PHY_REG_WRITE(PHY_BB_RX_GAIN_WINDOW_REG, PHY_BB_RX_GAIN_WINDOW_LO);
        PHY_REG_WRITE(PHY_BB_RX_GAIN_TABLE_REG(n), lo_word);
        PHY_REG_WRITE(PHY_BB_RX_GAIN_WINDOW_REG, PHY_BB_RX_GAIN_WINDOW_HI);
        PHY_REG_WRITE(PHY_BB_RX_GAIN_TABLE_REG(n), hi_word);
    }
}

/**
 * @brief Build, calibrate, and commit the hardware AGC RX gain table.
 *
 * Regenerates the gain code sequence when `g_phy_rx_table_renew_en` is set, loads the
 * dual-window baseband gain RAM, configures `PHY_I2C_ANA_INF_RX_MODE_REG` for normal or
 * crystal frequency-offset tracking mode, pulses the baseband gain commit bit, and caps
 * `PHY_BB_RX_MAX_GAIN_REG`.
 *
 * @param rxmax  Number of top RF gain tiers withheld from `s_gain_idx_tab[16]` (0..15;
 *               3 during standard bring-up, 0 forces `PHY_BB_RX_MAX_GAIN_ZERO_CAP` = 70).
 */
void phy_set_rx_gain_table(uint8_t rxmax)
{
    if (g_phy_rx_table_renew_en != 0U) {
        g_phy_rx_max_gain_val = phy_gen_rx_gain_table(phy_rx_gain_dc_table, RXGAIN_DEFAULT_MAX_BB,
                                                      s_gain_idx_tab, s_bb_idx_tab,
                                                      (uint8_t)(RXGAIN_TABLE_LEN_BASE - rxmax));
    }

    phy_set_rx_gain_testchip_50(1U, &g_phy_sleep_params.param_flag,
                                &phy_rx_gain_dc_table[RXGAIN_DC_TABLE_OFFSET],
                                g_phy_sleep_params.rxiq,
                                (uint8_t)(g_phy_rx_max_gain_val + 1U),
                                phy_rx_gain_dc_table);

    if ((chip6_phy_init_ctrl[PHY_CTRL_FREQ_OFF_MODE] & 1U) == 0U) {
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                         PHY_I2C_ANA_INF_RX_MODE_REG, ANA_INF_RX_MODE_NORMAL);
    } else {
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                         PHY_I2C_ANA_INF_RX_MODE_REG, ANA_INF_RX_MODE_FREQOFF);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_RXIQ_SIGN_REG, 1U, 1U, 1U);
    }

    PHY_REG_SET(PHY_BB_TXIQ_GAIN_COMMIT_REG, PHY_BB_TXIQ_COMMIT_BIT);

    if (g_phy_rx_max_gain_val > PHY_BB_RX_MAX_GAIN_CAP) {
        g_phy_rx_max_gain_val = PHY_BB_RX_MAX_GAIN_CAP;
    }
    if (rxmax == 0U) {
        g_phy_rx_max_gain_val = PHY_BB_RX_MAX_GAIN_ZERO_CAP;
    }

    PHY_REG_RMW(PHY_BB_RX_MAX_GAIN_REG, PHY_BB_RX_MAX_GAIN_MASK, g_phy_rx_max_gain_val);
}

/* --------------------------------------------------------------------------
 * Noise Floor Measurement, Initialization & Background Tracking
 * -------------------------------------------------------------------------- */

/**
 * @brief Read the hardware-measured RX noise floor from `PHY_BB_NOISE_FLOOR_REG`.
 *
 * Unpacks the 12-bit unsigned accumulator in bits [31:20], rounds right by 1 bit, and
 * subtracts `0x800` to obtain signed quarter-dBm (0.25 dB) units.
 *
 * @return  Measured noise floor in 0.25 dBm units (typically around -388 for -97.0 dBm).
 */
int16_t phy_get_noisefloor(void)
{
    uint32_t raw = (PHY_REG_READ(PHY_BB_NOISE_FLOOR_REG) >> PHY_BB_NOISE_FLOOR_RD_SHIFT) &
                   PHY_BB_NOISE_FLOOR_RD_MASK;
    return (int16_t)(((int32_t)((raw + 1U) >> 1)) - NOISE_RAW_OFFSET);
}

/**
 * @brief Read the hardware RX noise floor and clamp it to valid operating bounds.
 *
 * @return  Measured noise floor clamped to `[PHY_NOISE_FLOOR_MIN_QDB, PHY_NOISE_FLOOR_MAX_QDB]`
 *          ([-392, -340], i.e. -98.0 dBm to -85.0 dBm in 0.25 dB units).
 */
static int16_t s_get_noisefloor_sat(void)
{
    int32_t nf = (int32_t)phy_get_noisefloor();
    if (nf >= PHY_NOISE_FLOOR_MAX_QDB) {
        return PHY_NOISE_FLOOR_MAX_QDB;
    }
    if (nf < PHY_NOISE_FLOOR_MIN_QDB) {
        return PHY_NOISE_FLOOR_MIN_QDB;
    }
    return (int16_t)nf;
}

/**
 * @brief Program the baseband AGC noise-floor reference register.
 *
 * Converts quarter-dBm input @p nf to signed 9-bit half-dBm units (`(nf + 1) / 2`), writes
 * bits [8:0] of `PHY_BB_NOISE_FLOOR_REG`, and re-arms `PHY_BB_NOISE_MEAS` to latch it.
 *
 * @param nf  Desired noise-floor reference in 0.25 dBm units (e.g. -388 = -97.0 dBm).
 */
void phy_set_noise_floor(int16_t nf)
{
    PHY_REG_CLR(PHY_BB_RX_CTRL_REG, PHY_BB_NOISE_MEAS);
    int32_t half = ((int32_t)nf + 1) / 2;
    PHY_REG_RMW(PHY_BB_NOISE_FLOOR_REG, PHY_BB_NOISE_FLOOR_SET_MASK,
                (uint32_t)half & PHY_BB_NOISE_FLOOR_SET_MASK);
    PHY_REG_RMW(PHY_BB_RX_CTRL_REG, PHY_BB_RX_CTRL_NOISE_START, PHY_BB_NOISE_MEAS);
}

/**
 * @brief Trigger a non-blocking hardware RX noise-floor measurement if idle.
 *
 * @param chan_idx  3-bit measurement channel selector written to `PHY_BB_NOISE_FLOOR_REG[11:9]`.
 */
void phy_start_noisefloor(uint8_t chan_idx)
{
    if ((PHY_REG_READ(PHY_BB_RX_CTRL_REG) & PHY_BB_NOISE_MEAS) == 0U) {
        PHY_REG_RMW(PHY_BB_NOISE_FLOOR_REG, NOISE_FLOOR_CH_AND_SET_MASK,
                    (((uint32_t)chan_idx & 7U) << PHY_BB_NOISE_FLOOR_CH_SHIFT) |
                    NOISE_START_INIT_VAL);
        PHY_REG_SET(PHY_BB_RX_CTRL_REG, PHY_BB_RX_CTRL_NOISE_START);
    }
}

/**
 * @brief Run one blocking hardware noise-floor measurement with MAC-time deadline check.
 *
 * Waits for any prior measurement to finish, delays @p delay_us for channel settling,
 * starts a new measurement on @p chan_idx, and polls until `PHY_BB_NOISE_MEAS` clears or
 * elapsed MAC time exceeds @p timeout_us.
 *
 * @param chan_idx    3-bit hardware noise measurement channel index.
 * @param delay_us    Pre-measurement settling delay in microseconds.
 * @param start_time  Reference 1 MHz MAC timestamp from `phy_get_mactime()`.
 * @param timeout_us  Maximum elapsed time in microseconds before aborting.
 * @return            0 on successful completion, 1 if @p timeout_us expired.
 */
static uint8_t s_do_noisefloor(uint8_t chan_idx, uint16_t delay_us,
                               uint32_t start_time, uint32_t timeout_us)
{
    while ((PHY_REG_READ(PHY_BB_RX_CTRL_REG) & PHY_BB_NOISE_MEAS) != 0U) {
        if ((phy_get_mactime() - start_time) > timeout_us) {
            return 1U;
        }
    }

    ets_delay_us(delay_us);
    phy_start_noisefloor(chan_idx);

    do {
        if ((PHY_REG_READ(PHY_BB_RX_CTRL_REG) & PHY_BB_NOISE_MEAS) == 0U) {
            return 0U;
        }
    } while ((phy_get_mactime() - start_time) <= timeout_us);

    return 1U;
}

/**
 * @brief Read the instantaneous raw hardware RSSI noise floor register.
 *
 * @return  Signed noise-floor reading in 0.5 dB steps derived from `PHY_BB_RX_RSSI_REG[11:0]`.
 */
int16_t read_hw_noisefloor(void)
{
    int32_t v = (int32_t)(PHY_REG_READ(PHY_BB_RX_RSSI_REG) & NOISE_HW_RSSI_MASK) -
                NOISE_HW_RSSI_BIAS;
    return (int16_t)(v >> 1);
}

/**
 * @brief Periodic background RX noise-floor tracker with asymmetric IIR and scan-mode adjustment.
 *
 * Polls the hardware noise-floor measurement engine; when a measurement completes (or
 * after 10 busy ticks, falling back to -84.0 dBm), updates `loop_noisefloor` through an
 * asymmetric first-order IIR filter:
 * - Rising noise (`cur < nf`): slow attack `(nf + 3*cur - 2) / 4` (25% weight) to resist
 *   transient interferers.
 * - Falling noise (`nf < cur`): fast decay `(3*nf + cur - 2) / 4` (75% weight) when within
 *   4 dB, or capped at a -3.0 dB step (`cur - 12`) for larger drops.
 *
 * Outside scan mode (`g_phy_sw_scan_mode == 0`), `rx_noise` is updated only when it
 * diverges by more than +/-2.0 dB (`NOISE_LOOP_HYSTERESIS_QDB`). During active Wi-Fi
 * scanning, readings above `-387` (-96.75 dBm) are blended halfway toward `-388` (-97.0 dBm)
 * to preserve probe-response sensitivity. Persists chunk 2 to RTC calibration RAM on exit.
 *
 * @param chan_idx   3-bit hardware noise-floor measurement channel index for the next cycle.
 * @param apply_now  Non-zero to immediately program `PHY_BB_NOISE_FLOOR_REG` when `rx_noise`
 *                   changes; 0 to update RAM/RTC state only.
 */
void noise_check_loop(uint8_t chan_idx, uint8_t apply_now)
{
    PHY_REG_RMW(PHY_BB_NOISE_FLOOR_REG, PHY_BB_NOISE_FLOOR_CH_MASK, NOISE_LOOP_CH_DEFAULT);

    /* If the measurement engine is not yet armed (bits [17,15] not both set),
     * kick off an initial measurement and defer filtering until the next tick. */
    if (((PHY_REG_READ(PHY_BB_RX_CTRL_REG) >> NOISE_LOOP_CTRL_READY_SHIFT) &
         NOISE_LOOP_CTRL_READY_MASK) != NOISE_LOOP_CTRL_READY_MASK) {
        phy_start_noisefloor(chan_idx);
        phy_rtc_mem_backup_chunk2();
        return;
    }

    if ((PHY_REG_READ(PHY_BB_RX_CTRL_REG) & PHY_BB_NOISE_MEAS) == 0U ||
        s_loop_time_limit > NOISE_LOOP_TIMEOUT_LIMIT) {
        /* On timeout (> 9 busy ticks), assume an elevated busy-channel floor (-84 dBm);
         * otherwise read hardware and discard implausibly low readings (<= -101 dBm). */
        int32_t nf = NOISE_LOOP_TIMEOUT_FALLBACK_QDB;
        if (s_loop_time_limit > NOISE_LOOP_TIMEOUT_LIMIT ||
            ((nf = (int32_t)phy_get_noisefloor()), nf > NOISE_LOOP_VALID_MIN_QDB)) {
            if (s_loop_time_limit < (NOISE_LOOP_TIMEOUT_LIMIT + 1U)) {
                nf = s_clamp32(nf, PHY_NOISE_FLOOR_MIN_QDB, PHY_NOISE_FLOOR_MAX_QDB);
            }

            /* Asymmetric IIR: slow rise (1/4 new), fast fall (3/4 new, max -3 dB step). */
            int32_t cur = (int32_t)g_phy_sleep_params.loop_noisefloor;
            if (cur < nf) {
                g_phy_sleep_params.loop_noisefloor = (int16_t)((nf + cur * 3 - 2) / 4);
            } else if (nf < cur) {
                if (cur - NOISE_LOOP_DROP_FAST_THRESH <= nf) {
                    g_phy_sleep_params.loop_noisefloor = (int16_t)((nf * 3 + cur - 2) / 4);
                } else {
                    g_phy_sleep_params.loop_noisefloor = (int16_t)(cur - NOISE_LOOP_DROP_MAX_STEP);
                }
            }

            int32_t updated = (int32_t)g_phy_sleep_params.loop_noisefloor;
            if (g_phy_sw_scan_mode == 0U) {
                /* Normal mode: +/-2 dB hysteresis prevents constant AGC threshold churn. */
                if (updated > (int32_t)g_phy_sleep_params.rx_noise + NOISE_LOOP_HYSTERESIS_QDB ||
                    updated < (int32_t)g_phy_sleep_params.rx_noise - NOISE_LOOP_HYSTERESIS_QDB) {
                    g_phy_sleep_params.rx_noise = (int16_t)updated;
                    if (apply_now != 0U) {
                        phy_set_noise_floor(g_phy_sleep_params.rx_noise);
                    }
                }
            } else {
                /* Scan mode: keep noise floor sensitive by averaging elevated floors with -97 dBm. */
                if (updated < NOISE_SCAN_BLEND_THRESH_QDB) {
                    g_phy_sleep_params.rx_noise = (int16_t)updated;
                } else {
                    g_phy_sleep_params.rx_noise =
                        (int16_t)((updated + PHY_NOISE_FLOOR_DEFAULT_QDB) / 2);
                }
                if (apply_now != 0U) {
                    phy_set_noise_floor(g_phy_sleep_params.rx_noise);
                }
            }
        }

        phy_start_noisefloor(chan_idx);
        s_loop_time_limit = 0U;
    } else {
        s_loop_time_limit++;
    }

    phy_rtc_mem_backup_chunk2();
}

/**
 * @brief Initialize the RX noise floor across 4 representative 2.4 GHz channels at boot.
 *
 * When `PHY_PARAM_NOISE_VALID` is already set in @p param_flag (warm RTC restore), simply
 * reprograms the saved `g_phy_sleep_params.rx_noise` and pulses RX gain force latch.
 * Otherwise, sweeps channels 1, 6, 11, and 14 taking @p num_samples noise-floor readings
 * per channel, records the minimum per channel in `s_noise_array[0..3]`, and selects either
 * the global minimum (`use_min != 0`) or the default `-97.0 dBm` (`PHY_NOISE_FLOOR_DEFAULT_QDB`).
 *
 * @param chan_start   Hardware noise-floor channel selector passed to `s_do_noisefloor()`.
 * @param num_samples  Number of measurements per channel group (Ch 1, 6, 11, 14).
 * @param max_ch       Per-sample pre-measurement settle delay in microseconds.
 * @param timeout_us   Per-channel total timeout budget in microseconds.
 * @param use_min      Non-zero to adopt the lowest measured noise floor across all 4 channels;
 *                     0 to keep `PHY_NOISE_FLOOR_DEFAULT_QDB` (-388).
 * @param unused       Unused legacy ABI parameter.
 * @param param_flag   Pointer to `g_phy_sleep_params.param_flag`; sets `PHY_PARAM_NOISE_VALID`.
 */
void phy_noise_init(uint8_t chan_start, uint8_t num_samples, uint8_t max_ch,
                    uint16_t timeout_us, uint8_t use_min, uint32_t unused,
                    uint32_t *param_flag)
{
    (void)unused;

    if ((*param_flag & PHY_PARAM_NOISE_VALID) != 0U) {
        phy_set_noise_floor(g_phy_sleep_params.rx_noise);
        PHY_REG_RMW(PHY_BB_RX_GAIN_FORCE_REG, PHY_BB_RX_GAIN_FORCE_MASK, NOISE_INIT_GAIN_FORCE_VAL);
        PHY_REG_CLR(PHY_BB_RX_GAIN_FORCE_REG, PHY_BB_RX_GAIN_LATCH);
        (void)PHY_REG_READ(PHY_BB_RX_CTRL_REG);
        return;
    }

    phy_set_noise_floor(PHY_NOISE_FLOOR_DEFAULT_QDB);
    PHY_REG_RMW(PHY_BB_RX_GAIN_FORCE_REG, PHY_BB_RX_GAIN_FORCE_MASK, NOISE_INIT_GAIN_FORCE_VAL);
    PHY_REG_CLR(PHY_BB_RX_GAIN_FORCE_REG, PHY_BB_RX_GAIN_LATCH);
    (void)PHY_REG_READ(PHY_BB_RX_CTRL_REG);

    g_phy_sleep_params.rx_noise = PHY_NOISE_FLOOR_DEFAULT_QDB;
    for (uint32_t i = 0U; i < NOISE_INIT_GROUPS; i++) {
        s_noise_array[i] = PHY_NOISE_FLOOR_MAX_QDB;
    }

    uint32_t saved_dig_rx = PHY_REG_READ(PHY_BB_DIG_RX_REG);
    uint32_t saved_d20 = PHY_REG_READ(PHY_BB_AGC_THR_9D20_REG);
    uint32_t saved_d40 = PHY_REG_READ(PHY_BB_AGC_THR_9D40_REG);

    PHY_REG_CLR(PHY_BB_DIG_RX_REG, NOISE_INIT_DIG_RX_BIT);
    PHY_REG_CLR(PHY_BB_AGC_THR_9D20_REG, NOISE_INIT_AGC_9D20_BIT);

    /* Probe 4 spaced channels (Ch 1, 6, 11, 14) to find an interferer-free thermal floor. */
    for (uint32_t g = 0U; g < NOISE_INIT_GROUPS; g++) {
        uint32_t start_t = phy_get_mactime();
        uint8_t ch = (g == 3U) ? 14U : (uint8_t)(g * 5U + 1U);
        phy_set_chan(ch);
        (void)PHY_REG_READ(PHY_BB_RX_CTRL_REG);

        for (uint32_t s = 0U; s < (uint32_t)num_samples; s++) {
            if (s_do_noisefloor(chan_start, (uint16_t)max_ch, start_t, timeout_us) != 0U) {
                break;
            }
            int16_t val = s_get_noisefloor_sat();
            if (val < s_noise_array[g]) {
                s_noise_array[g] = val;
            }
        }

        PHY_REG_CLR(PHY_BB_RX_GAIN_FORCE_REG, PHY_BB_RX_GAIN_LATCH);
    }

    PHY_REG_WRITE(PHY_BB_DIG_RX_REG, saved_dig_rx);
    PHY_REG_WRITE(PHY_BB_AGC_THR_9D20_REG, saved_d20);
    PHY_REG_WRITE(PHY_BB_AGC_THR_9D40_REG, saved_d40);

    if (use_min == 0U) {
        g_phy_sleep_params.rx_noise = PHY_NOISE_FLOOR_DEFAULT_QDB;
    } else {
        int16_t mn = s_noise_array[0];
        if (mn > NOISE_INIT_CH0_CAP_QDB) {
            mn = NOISE_INIT_CH0_CAP_QDB;
        }
        for (uint32_t i = 1U; i < NOISE_INIT_GROUPS; i++) {
            if (s_noise_array[i] < mn) {
                mn = s_noise_array[i];
            }
        }
        g_phy_sleep_params.rx_noise = mn;
        phy_set_noise_floor(mn);
    }

    *param_flag |= PHY_PARAM_NOISE_VALID;
    g_phy_sleep_params.loop_noisefloor = g_phy_sleep_params.rx_noise;
}
