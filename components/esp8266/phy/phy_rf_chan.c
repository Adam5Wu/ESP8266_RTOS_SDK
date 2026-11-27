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
// Portions of the RF power-on/wake/close, RFPLL tuning, channel compensation,
// and baseband RX configuration sequences are adapted from teatime-os:
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
 * File-Local Channel, RFPLL, Spur, RX-Cap & Coexistence Constants
 * -------------------------------------------------------------------------- */

/* 2.4 GHz channel table geometry and crystal reference frequencies */
#define PHY_CHAN_COUNT                  14U          /* 802.11b/g/n channels 1..14 */
#define PHY_CHAN_14                     14U          /* Japan Channel 14 (2484 MHz default) */
#define PHY_CHAN_LAST_13_IDX            13U          /* Zero-based index of Channel 14 */
#define PHY_CHAN_RCP_BASE               21000U       /* Base for BB reciprocal freq table */
#define PHY_BB_CHAN_FREQ_MASK           0xFFFFE000U  /* [31:13]: rcp[31:17] + enable[14:13] */
#define PHY_BB_CHAN_FREQ_EN             0x00006000U  /* Bits [14:13] = 3 enable reciprocal */
#define PHY_BB_CHAN_FREQ_RCP_SHIFT      17U          /* [31:17]: 15-bit reciprocal frequency */
#define PHY_XTAL_FREQ_40MHZ             40U          /* 40 MHz crystal frequency (MHz) */
#define PHY_XTAL_FREQ_26MHZ             26U          /* 26 MHz crystal frequency (MHz) */
#define PHY_XTAL_FREQ_24MHZ             24U          /* 24 MHz crystal frequency (MHz) */
#define PHY_IEEE_2GHZ_FLAG              0x80U        /* Band flag passed to phy_mhz2ieee() */

/* Harmonic spur calculation and OFDM subcarrier notch mask constants */
#define PHY_SPUR_HALF_BW_MHZ            10           /* +/-10 MHz capture half-bandwidth */
#define PHY_SPUR_TENTHS_PER_MHZ         10           /* 0.1 MHz fixed-point units per MHz */
#define PHY_SPUR_FIXED_BASE_0P1         24000        /* 2400.0 MHz reference in 0.1 MHz */
#define PHY_SPUR_MAX_OFF_0P1            99           /* +/-9.9 MHz in-band spur cutoff */
#define PHY_SPUR_SCALE_LO_NUM           131072       /* Exact numerator for 52428.8 / 10 */
#define PHY_SPUR_SCALE_HI_NUM           128          /* Exact numerator for 51.2 / 10 */
#define PHY_SPUR_SCALE_DEN              25           /* Exact common denominator */
#define PHY_SPUR_FREQ_LO_MASK           0xFFFFFU     /* [19:0]: 20-bit fine notch phase */
#define PHY_SPUR_FREQ_HI_MASK           0x3FFU       /* [29:20]: 10-bit coarse notch phase */
#define PHY_SPUR_FREQ_HI_SHIFT          20U          /* Coarse phase field bit shift */
#define PHY_SPUR_SUBCARRIER_SHIFT       5            /* *32 -> 3.2 subcarriers/MHz * 10 */
#define PHY_SPUR_SUBCARRIER_DIV         100          /* Converts spur_0p1*32 to bin index */
#define PHY_SPUR_MASK_QUAD_BAND         15U          /* 15 subcarriers per mask register */

/* Fractional-N RFPLL SDM calculation, reset, lock and errata constants */
#define PHY_RFPLL_SDM_FREQ_SCALE        1024         /* MHz -> 1/1024 MHz (~976.6 Hz) */
#define PHY_RFPLL_SDM_FRAC_SHIFT        8U           /* Shift before dividing by 3*xtal */
#define PHY_RFPLL_VCO_MULT              3U           /* VCO/LO multiplier factor */
#define PHY_RFPLL_SDM_OFFSET            (32U << 16)  /* Fixed integer-N hardware offset */
#define PHY_RFPLL_RST_SEQ0              0xA6U        /* RFPLL reset sequence byte 0 */
#define PHY_RFPLL_RST_SEQ1              0xA7U        /* RFPLL reset sequence byte 1 */
#define PHY_RFPLL_RST_SEQ2              0xA5U        /* RFPLL reset sequence byte 2 */
#define PHY_RFPLL_SDM_CFG_RST           0xF3U        /* SDM config byte during reset */
#define PHY_RFPLL_EN_RUN                0x80U        /* RFPLL normal run enable */
#define PHY_RFPLL_EN_RST                0xC0U        /* RFPLL reset assert value */
#define PHY_RFPLL_SDM_LOAD              0x07U        /* SDM byte-load mode */
#define PHY_RFPLL_SDM_LATCH             0x17U        /* SDM latch & activate */
#define PHY_RFPLL_PWR_OFF               0x01U        /* RFPLL sleep / power-down value */
#define PHY_RFPLL_LOCK_POLL_MAX         100U         /* Max lock poll iterations (2 ms) */
#define PHY_RFPLL_LOCK_POLL_US          20U          /* Delay per lock poll iteration (us) */
#define PHY_RFPLL_CAP_UNLOCK_HINT       0x40U        /* Recovery VCO cap hint after unlock */
#define PHY_RFPLL_CAP_DEFAULT_HINT      0x60U        /* Cold-boot VCO cap hint */
#define PHY_RFPLL_FREQ_OFF_LIMIT        300          /* +/-300 clamp on crystal freq offset */
#define PHY_RFPLL_ANA_INF_FO_REG        4U           /* ANA_INF frequency-offset trim reg */
#define PHY_RFPLL_ANA_INF_FO_BASE       0x0C6186     /* Base offset added to ana_off */
#define PHY_EFUSE_ERRATA_RAND_MASK      0x7U         /* ADC entropy gate for RF errata */

/* Per-channel RX compensation, LNA/VGA cap trims and 802.11b filter codes */
#define PHY_RX_CMP_BASE_LO              (-7)         /* Base RX comp for Ch 1..6 */
#define PHY_RX_CMP_BASE_HI              (-6)         /* Base RX comp anchor for Ch 11 */
#define PHY_RX_CMP_EXT1_VAL             (-6)         /* Flat RX comp for rxmax_ext level 1 */
#define PHY_RX_GAIN_CAP_EN_BIT          0x40U        /* LNA/VGA capacitor bank enable bit */
#define PHY_RX_GAIN_CAP_MASK            0x0FU        /* 4-bit LNA/VGA cap trim code mask */
#define PHY_RX_GAIN_CAP_MAX             15           /* Max 4-bit cap trim value */
#define PHY_RX_GAIN_CAP_HALF            8            /* Half-range wrap offset (+/-8) */
#define PHY_RX_ANA_EXT_GAIN_NORM        0xE0U        /* RX_ANA reg 5: normal RX gain */
#define PHY_RX_ANA_EXT_GAIN_EXT         0xEFU        /* RX_ANA reg 5: extended RX max gain */
#define PHY_RX_ANA_FILT_EN_BIT          0xA0U        /* RX_ANA reg 2 filter enable bits */
#define PHY_TX_FILT_DCAP_EN_BIT         0x40U        /* TX_FILT reg 1 dcap enable bit */
#define PHY_TX_FILT_CH14_DCAP           0x3CU        /* Narrow TX filter code (Ch 14 / cont) */
#define PHY_BB_RX11B_DIS_MASK           0x000000C0U  /* Bits cleared to disable 11b RX mod */
#define PHY_BB_RX11B_EN_MASK            0x00000FCFU  /* Bits updated to enable 11b RX mod */
#define PHY_BB_RX11B_EN_VAL             0x0000048AU  /* 802.11b RX tuning register value */
#define PHY_BB_RX_FILTER_MASK           0x00003010U  /* Digital 11b RX filter select mask */
#define PHY_BB_RX_FILTER_SEL1           0x00000010U  /* Narrow filter (Channel 14 MIC) */
#define PHY_BB_RX_FILTER_SEL2           0x00001000U  /* Medium filter */
#define PHY_BB_RX_FILTER_SEL3           0x00002000U  /* Wide/default filter (Channels 1..13) */

/* RF power-on stages, sleep PBUS patterns, continuous TX and modes */
#define PHY_RTC_RF_PWR_STAGE2_BITS      0x30000000U  /* RF power-up stage 2 bits */
#define PHY_RTC_RF_PWR_STAGE3_BITS      0x0C000000U  /* RF power-up stage 3 bits */
#define PHY_PBUS_RXPBUS_LO_EN           0x00300000U  /* Active RX PBUS low sleep-park field */
#define PHY_PBUS_RXPBUS_HI_EN           0xD8000000U  /* Active RX PBUS high sleep-park field */
#define PHY_BB_RX_GAIN_ENRX_LATCH       0x000000F1U  /* Post-wake RX gain force latch assert */
#define PHY_BB_RX_GAIN_ENRX_DONE        0x000000F0U  /* Post-wake RX gain force latch clear */
#define PHY_PBUS_PA_VDD33_BIAS          2U           /* PBUS ch6 w1 SAR VDD33 bias word */
#define PHY_MAC_DEBUG_ENABLE_MODE       2U           /* Init-ctrl value enabling MAC debug */
#define PHY_FCC_TEST_CONT_TX            1U           /* Init-ctrl continuous TX mode */
#define PHY_EXT_SLEEP_OPT_GPIO          2U           /* Init-ctrl external sleep GPIO opt */
#define PHY_RX_MAX_GAIN_INIT_STEP       15U          /* Initial AGC max-gain step offset */
#define PHY_RX_GAIN_TABLE_DEFAULT_RXMAX 3U           /* Standard rxmax argument at bring-up */

/* Bluetooth coexistence and external antenna-switch truth tables / IO_MUX codes */
#define PHY_ANT_SW_BTCO_13_LO           0x01010101U  /* BTCO mode 1/3 truth table low */
#define PHY_ANT_SW_BTCO_13_HI           0x04010101U  /* BTCO mode 1/3 truth table high */
#define PHY_ANT_SW_BTCO_45_LO           0x04040404U  /* BTCO mode 4/5 truth table low */
#define PHY_ANT_SW_BTCO_45_HI           0x01040404U  /* BTCO mode 4/5 truth table high */
#define PHY_ANT_SW_EXT_2_LO             0x04010104U  /* Standalone antenna mode 2 low */
#define PHY_ANT_SW_EXT_2_HI             0x04040404U  /* Standalone antenna mode 2 high */
#define PHY_ANT_SW_EXT_3_LO             0x01040401U  /* Standalone antenna mode 3 low */
#define PHY_ANT_SW_EXT_3_HI             0x01010101U  /* Standalone antenna mode 3 high */
#define PHY_BTCO_GPIO_CFG_14_HI         0x03DE0000U  /* BTCO 1/4 submode 3/5 GPIO matrix */
#define PHY_BTCO_GPIO_CFG_14_LO         0x010E0000U  /* BTCO 1/4 submode 2/4 GPIO matrix */
#define PHY_BTCO_GPIO_CFG_35_HI         0x03ED0000U  /* BTCO 3/5 submode 3/5 GPIO matrix */
#define PHY_BTCO_GPIO_CFG_35_LO         0x010D0000U  /* BTCO 3/5 submode 2/4 GPIO matrix */
#define PHY_IO_MUX_FUNC_BTCO_ANT        0x00000020U  /* IO_MUX function select: BTCO/ANT */
#define PHY_IO_MUX_FUNC_GPIO            0x00000030U  /* IO_MUX function select: GPIO */
#define PHY_BTCO_GPIO_PIN0_MASK         1U           /* GPIO0 bit mask for BTCO polarity */
#define PHY_BTCO_GPIO_PIN3_MASK         8U           /* GPIO3 bit mask for BTCO polarity */

/* --------------------------------------------------------------------------
 * Owned Cross-TU & File-Local State (Explicitly Initialized, 0 SHN_COMMON)
 * -------------------------------------------------------------------------- */

uint8_t g_phy_vga_lna_dcap[2] = { 0U, 0U };
uint8_t g_phy_rfpll_sdm_reg[3] = { 0U, 0U, 0U };
uint8_t g_phy_or_pll_cap_last = 0U;
uint8_t g_phy_rfpll_unlock = 0U;
uint8_t g_phy_rx_gain_dc_flag = 0U;

static uint8_t s_pll_cap_m[2] = { 0U, 0U };
static uint8_t s_tx_cont_en_flag = 0U;
static uint32_t s_tx_data[4] = { 0U, 0U, 0U, 0U };

/* --------------------------------------------------------------------------
 * 4-Byte Aligned Flash Lookup Tables (.flash.rodata)
 * -------------------------------------------------------------------------- */

/* Standard 802.11 2.4 GHz center frequencies (MHz) for Channels 1..14 */
static const uint16_t s_chan_mhz[PHY_CHAN_COUNT] __attribute__((aligned(4))) = {
    2412U, 2417U, 2422U, 2427U, 2432U, 2437U, 2442U,
    2447U, 2452U, 2457U, 2462U, 2467U, 2472U, 2484U
};

/* Baseband reciprocal channel-frequency offsets added to PHY_CHAN_RCP_BASE (21000) */
static const uint16_t s_chan_rcp_off[PHY_CHAN_COUNT] __attribute__((aligned(4))) = {
    737U, 692U, 647U, 602U, 558U, 514U, 470U,
    426U, 382U, 339U, 295U, 252U, 209U, 106U
};

/* --------------------------------------------------------------------------
 * Internal Helpers
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
 * @brief Read an unaligned little-endian 16-bit unsigned integer from a byte buffer.
 *
 * @param p  Pointer to at least 2 bytes in little-endian order.
 * @return   Decoded 16-bit unsigned value.
 */
static uint16_t s_read_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/**
 * @brief Compute the signed in-band offset of the nearest harmonic of `num / denom` MHz.
 *
 * Tests whether any integer harmonic `q * (num / denom)` MHz lies strictly within
 * +/-10 MHz (`PHY_SPUR_HALF_BW_MHZ`) of channel center @p freq_mhz. If so, returns the
 * signed offset `(harmonic - freq_mhz)` in 0.1 MHz units; otherwise returns 0.
 *
 * @param freq_mhz  Current Wi-Fi channel center frequency in MHz (e.g. 2412..2484).
 * @param num       Rational spur clock numerator (0 disables).
 * @param denom     Rational spur clock denominator (0 disables).
 * @return          Signed spur offset in 0.1 MHz units (range roughly [-99, +99]), or 0
 *                  if disabled or no harmonic falls within +/-10 MHz of @p freq_mhz.
 */
static int32_t s_calc_frac_spur(uint16_t freq_mhz, uint32_t num, uint32_t denom)
{
    if (denom == 0U || num == 0U) {
        return 0;
    }

    /* Find q = floor(freq_mhz / (num/denom)) = floor(denom * freq_mhz / num) and
     * remainder r = (denom * freq_mhz) mod num. A harmonic falls within +/-10 MHz iff
     * r < 10*denom (below freq_mhz) or (num - r) < 10*denom (above freq_mhz). */
    int32_t p = (int32_t)(denom * (uint32_t)freq_mhz);
    int32_t q = p / (int32_t)num;
    int32_t r = p % (int32_t)num;
    int32_t thresh = (int32_t)(denom * (uint32_t)PHY_SPUR_HALF_BW_MHZ);

    if (r < thresh) {
        /* q is the closest harmonic below freq_mhz */
    } else if ((int32_t)num - r < thresh) {
        q += 1;
    } else {
        return 0;
    }

    /* floor((num / denom) * q * 10) - freq_mhz * 10 using pure 32-bit math */
    int32_t harm_0p1 = (int32_t)(((uint32_t)num * (uint32_t)q * (uint32_t)PHY_SPUR_TENTHS_PER_MHZ) /
                                 denom);
    return harm_0p1 - (int32_t)freq_mhz * PHY_SPUR_TENTHS_PER_MHZ;
}

/**
 * @brief Select the highest-priority in-band spur for @p chan and program `PHY_BB_SPUR_FREQ_REG`.
 *
 * Evaluates five candidate spur sources in priority order:
 * 1. Configured fractional clock spur #1 (when enabled for @p chan in `SPUR1_MASK`).
 * 2. Configured fractional clock spur #2 (when enabled for @p chan in `SPUR2_MASK`).
 * 3. Fixed spur #3 (`2400.0 + SPUR3_FREQ * 0.1` MHz) if within +/-9.9 MHz.
 * 4. Fixed spur #4 (`2400.0 + SPUR4_FREQ * 0.1` MHz) if within +/-9.9 MHz.
 * 5. Nearest crystal clock harmonic (`24 / 26 / 40 MHz`) within +/-10 MHz.
 *
 * Converts the winning offset (in 0.1 MHz units) into the hardware 20-bit fine and 10-bit
 * coarse digital notch phase words using exact integer ratios `131072/25` (`52428.8/10`)
 * and `128/25` (`51.2/10`) and writes them into `PHY_BB_SPUR_FREQ_REG[29:0]`.
 *
 * @param chan      1-based IEEE 802.11 channel number (1..14).
 * @param freq_mhz  Active channel center frequency in MHz.
 * @return          Selected spur offset in 0.1 MHz units (0 if no in-band spur active).
 */
static int32_t s_dig_spur_set(uint8_t chan, uint16_t freq_mhz)
{
    uint32_t xtal_mhz = (chip6_phy_init_ctrl[PHY_CTRL_XTAL_FREQ] == PHY_XTAL_26MHZ)
                            ? PHY_XTAL_FREQ_26MHZ
                            : (chip6_phy_init_ctrl[PHY_CTRL_XTAL_FREQ] == PHY_XTAL_24MHZ)
                                  ? PHY_XTAL_FREQ_24MHZ
                                  : PHY_XTAL_FREQ_40MHZ;

    /* Compute nearest crystal harmonic within +/-10 MHz of freq_mhz. */
    int32_t xtal_q = (int32_t)((uint32_t)freq_mhz / xtal_mhz);
    int32_t xtal_r = (int32_t)((uint32_t)freq_mhz % xtal_mhz);
    int32_t spur_xtal = 0;

    if (xtal_r < PHY_SPUR_HALF_BW_MHZ) {
        spur_xtal = (xtal_q * (int32_t)xtal_mhz - (int32_t)freq_mhz) * PHY_SPUR_TENTHS_PER_MHZ;
    } else if ((int32_t)xtal_mhz - xtal_r < PHY_SPUR_HALF_BW_MHZ) {
        spur_xtal = ((xtal_q + 1) * (int32_t)xtal_mhz - (int32_t)freq_mhz) *
                    PHY_SPUR_TENTHS_PER_MHZ;
    }

    uint32_t s1_num = (uint32_t)chip6_phy_init_ctrl[PHY_CTRL_SPUR1_NUM_LO] |
                      ((uint32_t)chip6_phy_init_ctrl[PHY_CTRL_SPUR1_NUM_HI] << 8);
    uint32_t s1_den = (uint32_t)chip6_phy_init_ctrl[PHY_CTRL_SPUR1_DEN];
    int32_t spur1 = s_calc_frac_spur(freq_mhz, s1_num, s1_den);

    uint32_t s2_num = (uint32_t)chip6_phy_init_ctrl[PHY_CTRL_SPUR2_NUM_LO] |
                      ((uint32_t)chip6_phy_init_ctrl[PHY_CTRL_SPUR2_NUM_HI] << 8);
    uint32_t s2_den = (uint32_t)chip6_phy_init_ctrl[PHY_CTRL_SPUR2_DEN];
    int32_t spur2 = s_calc_frac_spur(freq_mhz, s2_num, s2_den);

    int32_t base_0p1 = PHY_SPUR_FIXED_BASE_0P1 - (int32_t)freq_mhz * PHY_SPUR_TENTHS_PER_MHZ;
    int32_t spur3 = (int32_t)s_read_le16(&chip6_phy_init_ctrl[PHY_CTRL_SPUR3_FREQ_LO]) + base_0p1;
    if (s_abs32(spur3) > PHY_SPUR_MAX_OFF_0P1) {
        spur3 = 0;
    }
    int32_t spur4 = (int32_t)s_read_le16(&chip6_phy_init_ctrl[PHY_CTRL_SPUR4_FREQ_LO]) + base_0p1;
    if (s_abs32(spur4) > PHY_SPUR_MAX_OFF_0P1) {
        spur4 = 0;
    }

    uint32_t ch_bit = (uint32_t)(chan - 1U) & 31U;
    uint16_t s1_mask = s_read_le16(&chip6_phy_init_ctrl[PHY_CTRL_SPUR1_MASK_LO]);
    uint16_t s2_mask = s_read_le16(&chip6_phy_init_ctrl[PHY_CTRL_SPUR2_MASK_LO]);

    int32_t spur_0p1;
    if ((((uint32_t)s1_mask >> ch_bit) & 1U) != 0U && spur1 != 0) {
        spur_0p1 = spur1;
    } else if ((((uint32_t)s2_mask >> ch_bit) & 1U) != 0U && spur2 != 0) {
        spur_0p1 = spur2;
    } else if (spur3 != 0) {
        spur_0p1 = spur3;
    } else if (spur4 != 0) {
        spur_0p1 = spur4;
    } else {
        spur_0p1 = spur_xtal;
    }

    /* Pure-integer equivalent of (int32_t)(spur_0p1 * 52428.8 / 10.0) and
     * (int32_t)(spur_0p1 * 51.2 / 10.0), verified bit-exact over [-99, +99]. */
    uint32_t freq_lo = (uint32_t)((spur_0p1 * PHY_SPUR_SCALE_LO_NUM) / PHY_SPUR_SCALE_DEN) &
                       PHY_SPUR_FREQ_LO_MASK;
    uint32_t freq_hi = (uint32_t)((spur_0p1 * PHY_SPUR_SCALE_HI_NUM) / PHY_SPUR_SCALE_DEN) &
                       PHY_SPUR_FREQ_HI_MASK;

    PHY_REG_RMW(PHY_BB_SPUR_FREQ_REG, PHY_BB_SPUR_FREQ_VAL_MASK,
                (freq_hi << PHY_SPUR_FREQ_HI_SHIFT) | freq_lo);
    return spur_0p1;
}

/**
 * @brief Write a 2-bit-per-subcarrier OFDM spur mask across a 4-register subcarrier bank.
 *
 * The 60 active 802.11g/n OFDM subcarriers (`[-30..-1, +1..+30]`) are partitioned into four
 * 15-subcarrier quadrants (30 bits each, 2 bits per subcarrier):
 * - @p r_hi : positive subcarriers `[+16..+30]`
 * - @p r_mid: positive subcarriers `[+1..+15]` (with DC straddle when `u_idx == 0`)
 * - @p r_lo1: negative subcarriers `[-15..-1]`
 * - @p r_lo2: negative subcarriers `[-30..-16]`
 *
 * @param r_hi   MMIO register address for subcarriers `[+16..+30]`.
 * @param r_mid  MMIO register address for subcarriers `[+1..+15]`.
 * @param r_lo1  MMIO register address for subcarriers `[-15..-1]`.
 * @param r_lo2  MMIO register address for subcarriers `[-30..-16]`.
 * @param s_idx  Sign-extended OFDM subcarrier index (`(int8_t)u_idx`).
 * @param u_idx  8-bit wrapped subcarrier index used for quadrant range tests.
 * @param pat    2-bit-per-subcarrier weight pattern (`m2` or `m1` from `s_dig_spur_prot()`).
 */
static void s_write_spur_mask_quad(uint32_t r_hi, uint32_t r_mid,
                                   uint32_t r_lo1, uint32_t r_lo2,
                                   int32_t s_idx, uint8_t u_idx, uint32_t pat)
{
    uint32_t v_hi = (s_idx > (int32_t)PHY_SPUR_MASK_QUAD_BAND)
                        ? (pat << (((uint32_t)s_idx << 1) & 31U))
                        : 0U;
    uint32_t v_mid;
    if ((uint8_t)(u_idx - 1U) < PHY_SPUR_MASK_QUAD_BAND) {
        v_mid = pat << ((uint32_t)(s_idx * 2 - 2) & 31U);
    } else {
        v_mid = (u_idx == 0U) ? (pat >> 2) : 0U;
    }
    uint32_t v_lo1 = ((uint8_t)(u_idx + PHY_SPUR_MASK_QUAD_BAND) < PHY_SPUR_MASK_QUAD_BAND)
                         ? (pat << ((uint32_t)(s_idx * 2 + 30) & 31U))
                         : 0U;
    uint32_t v_lo2 = ((uint8_t)(u_idx + (2U * PHY_SPUR_MASK_QUAD_BAND)) < PHY_SPUR_MASK_QUAD_BAND)
                         ? (pat << ((uint32_t)(s_idx * 2 + 60) & 31U))
                         : 0U;

    PHY_REG_WRITE(r_hi, v_hi);
    PHY_REG_WRITE(r_mid, v_mid);
    PHY_REG_WRITE(r_lo1, v_lo1);
    PHY_REG_WRITE(r_lo2, v_lo2);
}

/**
 * @brief Program the 12 baseband OFDM subcarrier spur-protection mask registers.
 *
 * Maps @p spur_0p1 (offset in 0.1 MHz units) to its nearest 802.11 OFDM subcarrier bin
 * (312.5 kHz spacing -> `spur_0p1 * 32 / 100 = spur_0p1 / 3.125`) and fractional bin
 * position `d` in tenths of a subcarrier:
 * - Near a single bin center (`d < 2` or `d >= 8`): notches 1 subcarrier (`mask = 1` or `2`).
 * - Between two adjacent bins (`2 <= d < 8`): notches both adjacent bins (`mask = 3`).
 *
 * Updates both the 1-bit-per-subcarrier masks (`MASK0/3/4/7`) and the two 2-bit-per-subcarrier
 * quad banks (`MASK1/2/10/11` with pattern `m2` and `MASK5/6/8/9` with pattern `m1`).
 *
 * @param spur_0p1  Signed active spur offset in 0.1 MHz units (0 clears all masks).
 */
static void s_dig_spur_prot(int32_t spur_0p1)
{
    uint8_t u_idx = 0U;
    int32_t mask = 0;

    /* Convert 0.1 MHz offset to OFDM subcarrier index (spacing = 20 MHz / 64 = 0.3125 MHz):
     *   bin = spur_0p1 / 3.125 = (spur_0p1 * 32) / 100
     *   d   = fractional tenths of a subcarrier bin, determining 1-bin vs 2-bin notch. */
    if (spur_0p1 != 0) {
        int32_t s32 = spur_0p1 << PHY_SPUR_SUBCARRIER_SHIFT;
        int32_t q = s32 / PHY_SPUR_SUBCARRIER_DIV;
        int32_t d = (s32 / PHY_SPUR_TENTHS_PER_MHZ) % PHY_SPUR_TENTHS_PER_MHZ;

        if (spur_0p1 <= 0) {
            u_idx = (uint8_t)(q - 1);
            if (d == -9) {
                mask = 1;
            } else if (d < -2) {
                mask = 3;
            } else {
                mask = 2;
            }
        } else {
            u_idx = (uint8_t)q;
            if (d < 2) {
                mask = 1;
            } else if (d < 8) {
                mask = 3;
            } else {
                mask = 2;
            }
        }
    }

    int32_t s_idx = (int32_t)(int8_t)u_idx;
    uint32_t pos_val = (s_idx > 0)
                           ? ((uint32_t)mask << ((uint32_t)(s_idx - 1) & 31U))
                           : (uint32_t)(mask >> 1);
    uint32_t neg_val = (s_idx < 0)
                           ? ((uint32_t)mask << ((uint32_t)(s_idx + 30) & 31U))
                           : 0U;

    PHY_REG_WRITE(PHY_BB_SPUR_MASK4_REG, pos_val);
    PHY_REG_WRITE(PHY_BB_SPUR_MASK3_REG, neg_val);
    PHY_REG_WRITE(PHY_BB_SPUR_MASK7_REG, pos_val);
    PHY_REG_WRITE(PHY_BB_SPUR_MASK0_REG, neg_val);

    /* Expand 2-bit bin mask (1, 2, 3) into paired 2-bit-per-bin weight patterns:
     *   m2 (high-weight bit): 1->0b0010 (2), 2->0b1000 (8), 3->0b1010 (10)
     *   m1 (low-weight bit):  1->0b0001 (1), 2->0b0100 (4), 3->0b0101 (5) */
    uint32_t m2 = (mask == 1) ? 2U : (mask == 2) ? 8U : (mask == 3) ? 10U : 0U;
    s_write_spur_mask_quad(PHY_BB_SPUR_MASK2_REG, PHY_BB_SPUR_MASK1_REG,
                           PHY_BB_SPUR_MASK11_REG, PHY_BB_SPUR_MASK10_REG,
                           s_idx, u_idx, m2);

    uint32_t m1 = (mask == 1) ? 1U : (mask == 2) ? 4U : (mask == 3) ? 5U : 0U;
    s_write_spur_mask_quad(PHY_BB_SPUR_MASK9_REG, PHY_BB_SPUR_MASK8_REG,
                           PHY_BB_SPUR_MASK6_REG, PHY_BB_SPUR_MASK5_REG,
                           s_idx, u_idx, m1);
}

/**
 * @brief Interpolate and latch per-channel baseband RX gain compensation.
 *
 * Combines the baseline channel slope (`-7` on Ch 1..6 ramping toward `-6` on Ch 11..14)
 * with the piecewise-linearly interpolated `rxmax_ext` compensation anchored at Channels
 * 1, 6, and 11 (Ch 14 extrapolates using `(ch - 2) / 5` for the 12 MHz gap). Writes the
 * signed 8-bit sum to `PHY_BB_RX_CHAN_COMP_REG[17:10]` and pulses `PHY_BB_RX_GAIN_LATCH`.
 *
 * @param chan   Signed 1-based channel number (1..14).
 * @param level  Extended RX max-gain level (0=normal, 1=flat -6, 2=EXT2 table, 3=EXT3 table).
 */
static void s_set_chan_rx_cmp(int8_t chan, uint8_t level)
{
    chip6_phy_init_ctrl[PHY_CTRL_RX_CMP_BASE + 0U] = (uint8_t)(int8_t)PHY_RX_CMP_BASE_LO;
    chip6_phy_init_ctrl[PHY_CTRL_RX_CMP_BASE + 1U] = (uint8_t)(int8_t)PHY_RX_CMP_BASE_LO;
    chip6_phy_init_ctrl[PHY_CTRL_RX_CMP_BASE + 2U] = (uint8_t)(int8_t)PHY_RX_CMP_BASE_HI;

    int32_t ch = (int32_t)chan;
    int32_t base;
    if (ch < 7) {
        base = PHY_RX_CMP_BASE_LO;
    } else if (ch < (int32_t)PHY_CHAN_14) {
        base = ((ch - 6) / 5) + PHY_RX_CMP_BASE_LO;
    } else {
        base = ((ch - 2) / 5) + PHY_RX_CMP_BASE_LO;
    }

    int8_t c0 = 0;
    int8_t c1 = 0;
    int8_t c2 = 0;
    if (level == 1U) {
        c0 = PHY_RX_CMP_EXT1_VAL;
        c1 = PHY_RX_CMP_EXT1_VAL;
        c2 = PHY_RX_CMP_EXT1_VAL;
    } else if (level == 2U) {
        c0 = (int8_t)chip6_phy_init_ctrl[PHY_CTRL_RX_CMP_EXT2 + 0U];
        c1 = (int8_t)chip6_phy_init_ctrl[PHY_CTRL_RX_CMP_EXT2 + 1U];
        c2 = (int8_t)chip6_phy_init_ctrl[PHY_CTRL_RX_CMP_EXT2 + 2U];
    } else if (level == 3U) {
        c0 = (int8_t)chip6_phy_init_ctrl[PHY_CTRL_RX_CMP_EXT3 + 0U];
        c1 = (int8_t)chip6_phy_init_ctrl[PHY_CTRL_RX_CMP_EXT3 + 1U];
        c2 = (int8_t)chip6_phy_init_ctrl[PHY_CTRL_RX_CMP_EXT3 + 2U];
    }

    int32_t ext;
    if (ch < 7) {
        ext = (((int32_t)c1 - (int32_t)c0) * (ch - 1)) / 5 + (int32_t)c0;
    } else if (ch < (int32_t)PHY_CHAN_14) {
        ext = (((int32_t)c2 - (int32_t)c1) * (ch - 6)) / 5 + (int32_t)c1;
    } else {
        ext = (((int32_t)c2 - (int32_t)c1) * (ch - 2)) / 5 + (int32_t)c1;
    }

    uint32_t cmp = (uint32_t)((base + ext) & 0xFF);
    PHY_REG_RMW(PHY_BB_RX_CHAN_COMP_REG, PHY_BB_RX_CHAN_COMP_MASK,
                cmp << PHY_BB_RX_CHAN_COMP_SHIFT);
    PHY_REG_SET(PHY_BB_RX_GAIN_FORCE_REG, PHY_BB_RX_GAIN_LATCH);
    PHY_REG_CLR(PHY_BB_RX_GAIN_FORCE_REG, PHY_BB_RX_GAIN_LATCH);
}

/**
 * @brief Program the 2.4 GHz RFPLL to @p chan and optionally wait for VCO calibration lock.
 *
 * Looks up the channel center frequency (honoring custom Channel 14 frequency override in
 * `chip6_phy_init_ctrl[PHY_CTRL_CH14_FREQ_EN..LO]`), resets the RFPLL, writes the 24-bit
 * fractional-N SDM registers, restarts VCO calibration, caches `g_phy_rfpll_sdm_reg[0..2]`,
 * and releases `PHY_RFPLL_LATCH`.
 *
 * @param chan       1-based IEEE 802.11 channel number (1..14).
 * @param xtal_flag  Crystal selector (`PHY_XTAL_40MHZ`, `PHY_XTAL_26MHZ`, `PHY_XTAL_24MHZ`).
 * @param freq_off   Signed crystal frequency offset in 1/1024 MHz (~976.6 Hz) units.
 * @param wait_pll   Non-zero to block on `phy_wait_rfpll_cal_end()`; 0 to return immediately
 *                   (used during asynchronous wakeup so TX cap / atten overlap PLL lock).
 * @return           Tuned channel center frequency in MHz.
 */
static uint16_t s_set_channel_freq_impl(uint8_t chan, uint8_t xtal_flag,
                                        int16_t freq_off, uint8_t wait_pll)
{
    PHY_REG_SET(PHY_RFPLL_CTRL_REG, PHY_RFPLL_LATCH);
    phy_rfpll_reset();

    uint8_t idx = (uint8_t)(chan - 1U);
    uint16_t freq_mhz = (idx < PHY_CHAN_LAST_13_IDX)
                            ? s_chan_mhz[idx]
                            : s_chan_mhz[PHY_CHAN_LAST_13_IDX];

    if ((chip6_phy_init_ctrl[PHY_CTRL_CH14_FREQ_EN] & 1U) != 0U && chan == PHY_CHAN_14) {
        freq_mhz = s_read_le16(&chip6_phy_init_ctrl[PHY_CTRL_CH14_FREQ_LO]);
    }

    uint8_t sdm[3];
    phy_rfpll_calc_sdm(freq_mhz, xtal_flag, freq_off, sdm);
    phy_write_rfpll_sdm(sdm);
    phy_rfpll_restart_cal();

    if (wait_pll != 0U) {
        phy_wait_rfpll_cal_end();
    }

    PHY_REG_CLR(PHY_RFPLL_CTRL_REG, PHY_RFPLL_LATCH);
    g_phy_rfpll_sdm_reg[0] = sdm[0];
    g_phy_rfpll_sdm_reg[1] = sdm[1];
    g_phy_rfpll_sdm_reg[2] = sdm[2];
    return freq_mhz;
}

/* --------------------------------------------------------------------------
 * Exported & Cross-TU Functions
 * -------------------------------------------------------------------------- */

/**
 * @brief Pulse the RFPLL analog reset sequence and initialize SDM control state.
 *
 * Drives the 3-step `0xA6 -> 0xA7 -> 0xA5` reset strobe on `PHY_I2C_RFPLL_RST_REG`,
 * writes the SDM reset configuration byte (`0xF3`), and sets `PHY_I2C_RFPLL_EN_REG` to `0xC0`.
 */
void phy_rfpll_reset(void)
{
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1,
                     PHY_I2C_RFPLL_RST_REG, PHY_RFPLL_RST_SEQ0);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1,
                     PHY_I2C_RFPLL_RST_REG, PHY_RFPLL_RST_SEQ1);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1,
                     PHY_I2C_RFPLL_RST_REG, PHY_RFPLL_RST_SEQ2);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL_SDM, PHY_I2C_HOST_0,
                     PHY_I2C_SDM_CFG_REG, PHY_RFPLL_SDM_CFG_RST);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1,
                     PHY_I2C_RFPLL_EN_REG, PHY_RFPLL_EN_RST);
}

/**
 * @brief Write and latch the 3-byte (24-bit) fractional-N RFPLL SDM divider word.
 *
 * @param sdm  3-byte big-endian SDM register word: `sdm[0]`=bits[23:16],
 *             `sdm[1]`=bits[15:8], `sdm[2]`=bits[7:0].
 */
void phy_write_rfpll_sdm(const uint8_t sdm[3])
{
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL_SDM, PHY_I2C_HOST_0,
                     PHY_I2C_SDM_CTRL_REG, PHY_RFPLL_SDM_LOAD);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL_SDM, PHY_I2C_HOST_0, PHY_I2C_SDM_BYTE0_REG, sdm[0]);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL_SDM, PHY_I2C_HOST_0, PHY_I2C_SDM_BYTE1_REG, sdm[1]);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL_SDM, PHY_I2C_HOST_0, PHY_I2C_SDM_BYTE2_REG, sdm[2]);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL_SDM, PHY_I2C_HOST_0,
                     PHY_I2C_SDM_CTRL_REG, PHY_RFPLL_SDM_LATCH);
}

/**
 * @brief Trigger a fresh RFPLL VCO capacitor-bank self-calibration cycle.
 *
 * Toggles bits 6 and 5 of `PHY_I2C_RFPLL_CAL_CTRL_REG` (`bit6=1, bit5=0 -> 1, bit6=0`).
 */
void phy_rfpll_restart_cal(void)
{
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1,
                          PHY_I2C_RFPLL_CAL_CTRL_REG, 6U, 6U, 1U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1,
                          PHY_I2C_RFPLL_CAL_CTRL_REG, 5U, 5U, 0U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1,
                          PHY_I2C_RFPLL_CAL_CTRL_REG, 5U, 5U, 1U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1,
                          PHY_I2C_RFPLL_CAL_CTRL_REG, 6U, 6U, 0U);
}

/**
 * @brief Poll `PHY_I2C_RFPLL_LOCK_STAT_REG[7]` until RFPLL VCO calibration completes.
 *
 * Polls up to 100 times with 20 us intervals (2 ms maximum wait).
 */
void phy_wait_rfpll_cal_end(void)
{
    for (uint32_t i = 0U; i < PHY_RFPLL_LOCK_POLL_MAX; i++) {
        ets_delay_us(PHY_RFPLL_LOCK_POLL_US);
        if (rom_i2c_readReg_Mask(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1,
                                 PHY_I2C_RFPLL_LOCK_STAT_REG, 7U, 7U) != 0U) {
            return;
        }
    }
}

/**
 * @brief Compute the 24-bit fractional-N RFPLL SDM register bytes using pure integer math.
 *
 * The hardware 2.4 GHz RFPLL synthesizes LO frequency `f_LO = (3/2) * f_xtal * (N + 32) / 2^16`
 * where the VCO runs at `4/3 * f_LO` (equivalently `SDM_total = (f_MHz * 2^18) / (3 * f_xtal)`).
 * Expressing the target frequency with crystal offset as `num = freq_mhz * 1024 + freq_off`
 * (in `1/1024` MHz units), shifting left 8 bits yields `num << 8 = freq * 2^18`, so:
 *   `sdm24 = ((num << 8) / (3 * xtal_mhz)) - (32 << 16)`
 * which fits cleanly in unsigned 32-bit arithmetic without overflow or floating point.
 *
 * @param freq_mhz   Target channel center frequency in MHz (2412..2484).
 * @param xtal_flag  Crystal selector (`PHY_XTAL_40MHZ`, `PHY_XTAL_26MHZ`, `PHY_XTAL_24MHZ`).
 * @param freq_off   Signed crystal frequency offset in 1/1024 MHz (~976.6 Hz) units.
 * @param sdm        Output 3-byte big-endian SDM word: `[0]`=[23:16], `[1]`=[15:8], `[2]`=[7:0].
 */
void phy_rfpll_calc_sdm(uint16_t freq_mhz, uint8_t xtal_flag, int16_t freq_off,
                        uint8_t sdm[3])
{
    uint32_t xtal_mhz = (xtal_flag == PHY_XTAL_26MHZ)
                            ? PHY_XTAL_FREQ_26MHZ
                            : (xtal_flag == PHY_XTAL_24MHZ)
                                  ? PHY_XTAL_FREQ_24MHZ
                                  : PHY_XTAL_FREQ_40MHZ;

    /* Pure-integer fractional-N divider:
     *   num   = freq_mhz * 2^10 + freq_off   (units of 2^-10 MHz)
     *   sdm24 = (num * 2^8) / (3 * xtal_mhz) - 32 * 2^16 */
    uint32_t num = (uint32_t)((int32_t)freq_mhz * PHY_RFPLL_SDM_FREQ_SCALE + (int32_t)freq_off);
    uint32_t sdm24 = ((num << PHY_RFPLL_SDM_FRAC_SHIFT) / (PHY_RFPLL_VCO_MULT * xtal_mhz)) -
                     PHY_RFPLL_SDM_OFFSET;

    sdm[0] = (uint8_t)(sdm24 >> 16);
    sdm[1] = (uint8_t)(sdm24 >> 8);
    sdm[2] = (uint8_t)(sdm24);
}

/**
 * @brief Tune the RFPLL to @p chan and block until VCO calibration locks.
 *
 * @param chan       1-based IEEE 802.11 channel number (1..14).
 * @param xtal_flag  Crystal selector (`PHY_XTAL_40MHZ`, `PHY_XTAL_26MHZ`, `PHY_XTAL_24MHZ`).
 * @param freq_off   Signed crystal frequency offset in 1/1024 MHz units.
 * @return           Tuned channel center frequency in MHz.
 */
uint16_t phy_set_channel_freq(uint8_t chan, uint8_t xtal_flag, int16_t freq_off)
{
    return s_set_channel_freq_impl(chan, xtal_flag, freq_off, 1U);
}

/**
 * @brief Core RF channel-tuning routine with VCO cap-unlock recovery, errata, and spur setup.
 *
 * Executes the complete per-channel RF & baseband tuning sequence:
 * 1. Applies optional crystal frequency-offset clamping (`[-300, +300]`, or `[-300, 0]`
 *    when `PHY_CTRL_FREQ_OFF_MODE` bit 1 is set) and derives the analog offset `fo / 3`.
 * 2. Seeds the RFPLL VCO capacitor bank hint from `g_phy_or_pll_cap_last` (falling back
 *    to `0x60` on cold boot or `0x40` after an unlock event), tunes the RFPLL, and tracks
 *    low-band (`chan < 3`) vs high-band (`chan > 9`) locked VCO cap values to detect a
 *    stuck/unlocked capacitor bank (`s_pll_cap_m[1] == s_pll_cap_m[0] != 0`).
 * 3. Applies the ESP8266 eFuse silicon RF-I2C errata write when `EFUSE_DATA2[15:13] == 0`
 *    and ADC thermal entropy bits `[2:0] == 0`.
 * 4. Programs the baseband reciprocal channel frequency (`PHY_BB_CHAN_FREQ_REG`),
 *    digital spur notch frequency (`s_dig_spur_set`), and OFDM subcarrier masks
 *    (`s_dig_spur_prot`).
 *
 * @param chan       1-based IEEE 802.11 channel number (1..14).
 * @param xtal_flag  Crystal selector (`PHY_XTAL_40MHZ`, `PHY_XTAL_26MHZ`, `PHY_XTAL_24MHZ`).
 * @param unused     Unused legacy ABI parameter.
 * @param freq_off   Signed crystal frequency offset in 1/1024 MHz units.
 * @param slp        Unused legacy ABI pointer (operates on `g_phy_sleep_params`).
 * @param delay_us   Unused legacy ABI delay parameter.
 * @param wait_pll   Non-zero to wait for RFPLL lock; 0 for deferred wakeup lock wait.
 */
void phy_set_chan_60(uint8_t chan, uint8_t xtal_flag, uint8_t unused,
                     int16_t freq_off, phy_sleep_params_t *slp,
                     uint16_t delay_us, uint8_t wait_pll)
{
    (void)unused;
    (void)slp;
    (void)delay_us;

    int16_t eff_off = 0;
    int16_t ana_off = 0;

    if ((chip6_phy_init_ctrl[PHY_CTRL_FREQ_OFF_MODE] & 1U) != 0U) {
        int32_t fo = (int32_t)freq_off;
        if (fo < -PHY_RFPLL_FREQ_OFF_LIMIT) {
            fo = -PHY_RFPLL_FREQ_OFF_LIMIT;
        } else if (fo > PHY_RFPLL_FREQ_OFF_LIMIT) {
            fo = PHY_RFPLL_FREQ_OFF_LIMIT;
        }
        if ((chip6_phy_init_ctrl[PHY_CTRL_FREQ_OFF_MODE] & 2U) != 0U && fo > 0) {
            fo = 0;
        }
        eff_off = (int16_t)fo;
        ana_off = (int16_t)(fo / 3);
    }

    g_phy_sleep_params.cur_chan = chan;

    /* VCO capacitor-bank unlock tracking:
     * Seed the PLL cap hint from the last locked cap (0x60 cold default; forced to 0x40
     * if a prior unlock was detected). After tuning, compare the locked cap observed on
     * low channels (Ch 1..2) against high channels (Ch 10..14): a working VCO must shift
     * its cap bank across the band, so identical non-zero values indicate a stuck/unlocked
     * bank and arm recovery on the next channel switch. */
    if (g_phy_rfpll_unlock != 0U) {
        g_phy_or_pll_cap_last = PHY_RFPLL_CAP_UNLOCK_HINT;
    }
    uint8_t cap_hint = (g_phy_or_pll_cap_last != 0U)
                           ? g_phy_or_pll_cap_last
                           : PHY_RFPLL_CAP_DEFAULT_HINT;
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1,
                     PHY_I2C_RFPLL_CAP_HINT_REG, cap_hint);

    uint16_t freq_mhz = s_set_channel_freq_impl(chan, xtal_flag, eff_off, wait_pll);

    g_phy_or_pll_cap_last = rom_i2c_readReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1,
                                            PHY_I2C_RFPLL_CAP_READ_REG);
    int8_t s_chan = (int8_t)chan;
    if (s_chan < 3) {
        s_pll_cap_m[0] = g_phy_or_pll_cap_last;
    } else if (s_chan > 9) {
        s_pll_cap_m[1] = g_phy_or_pll_cap_last;
    }
    if (s_pll_cap_m[1] == s_pll_cap_m[0] && s_pll_cap_m[0] != 0U) {
        g_phy_rfpll_unlock = 1U;
    }

    /* eFuse RF silicon errata workaround: on early silicon with EFUSE_DATA2[15:13] == 0,
     * probabilistically (1-in-8 via thermal ADC LSBs) issue the direct RF-I2C host-0 command
     * to prevent RFPLL/analog latchup across repeated channel switches. */
    if (((PHY_REG_READ(PHY_EFUSE_DATA2_REG) >> PHY_EFUSE_DATA2_ANA_REV_SHIFT) &
         PHY_EFUSE_DATA2_RF_ERRATA_MASK) == 0U &&
        (PHY_REG_READ(PHY_BB_ADC_RAND_REG) & PHY_EFUSE_ERRATA_RAND_MASK) == 0U) {
        PHY_REG_WRITE(PHY_RF_I2C_HOST_REG(0), PHY_RF_I2C_ERRATA_CMD);
    }

    uint8_t idx = (uint8_t)(chan - 1U);
    uint32_t rcp = PHY_CHAN_RCP_BASE +
                   (uint32_t)((idx < PHY_CHAN_LAST_13_IDX)
                                  ? s_chan_rcp_off[idx]
                                  : s_chan_rcp_off[PHY_CHAN_LAST_13_IDX]);

    if ((chip6_phy_init_ctrl[PHY_CTRL_FREQ_OFF_MODE] & 1U) != 0U) {
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_RFPLL_ANA_INF_FO_REG,
                         (uint8_t)((uint32_t)((int32_t)ana_off + PHY_RFPLL_ANA_INF_FO_BASE) &
                                   0xFFU));
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_CLK_GATE_REG, 6U, 6U, 1U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0,
                              PHY_I2C_ANA_INF_CLK_GATE_REG, 5U, 5U, 1U);
        ets_delay_us(5U);
    }

    PHY_REG_RMW(PHY_BB_CHAN_FREQ_REG, PHY_BB_CHAN_FREQ_MASK,
                PHY_BB_CHAN_FREQ_EN | (rcp << PHY_BB_CHAN_FREQ_RCP_SHIFT));

    int32_t spur_0p1 = s_dig_spur_set(chan, freq_mhz);
    s_dig_spur_prot(spur_0p1);
}

/**
 * @brief Apply channel-dependent TX capacitor, TX attenuation, RX max-gain, and noise floor.
 *
 * Updates the PA TX capacitor bank if `PHY_PARAM_TXCAP_VALID` is set; if the MAC-PHY RF
 * ready flag (`PHY_MAC_PHY_RF_UP`) is active, also updates interpolated per-channel TX
 * attenuation, `chip_v6_rxmax_ext()`, and the baseband noise floor, followed by a 30 us
 * settling delay.
 *
 * @param chan  1-based IEEE 802.11 channel number (1..14).
 */
void phy_set_chan_misc(uint8_t chan)
{
    int8_t tmp_atten[6];

    if ((g_phy_sleep_params.param_flag & PHY_PARAM_TXCAP_VALID) != 0U) {
        phy_set_txcap_reg(g_phy_sleep_params.txcap, chan);
    }
    if ((PHY_REG_READ(PHY_MAC_PHY_CTRL_REG) & PHY_MAC_PHY_RF_UP) != 0U) {
        phy_tx_atten_set_interp(chan, tmp_atten);
        chip_v6_rxmax_ext(g_phy_rxmax_ext_level);
        phy_set_noise_floor(g_phy_sleep_params.rx_noise);
        ets_delay_us(30U);
    }
}

/**
 * @brief Switch the active Wi-Fi radio channel with safe MAC/RX pausing and recalibration.
 *
 * No-ops while `g_phy_sleep_mode_flag` is set. During initial boot (before `PHY_PARAM_BOOT_DONE`),
 * pauses digital RX directly; during normal operation, enters transient modem pause
 * (`PHY_PM_MODE_MODEM_PAUSE`). Tunes the RFPLL, applies channel-dependent TX/RX settings,
 * runs fast BBPLL calibration, resumes RX, re-arms the SAR power detector, optionally writes
 * the MAC debug test pattern, and applies Japan Channel 14 MIC filter/power overrides.
 *
 * @param chan  1-based IEEE 802.11 channel number (1..14).
 */
void phy_set_chan(uint8_t chan)
{
    if (g_phy_sleep_mode_flag != 0U) {
        return;
    }

    uint32_t saved_dig_rx = 0U;
    if ((g_phy_sleep_params.param_flag & PHY_PARAM_BOOT_DONE) == 0U) {
        saved_dig_rx = phy_stop_dig_rx();
    } else {
        pm_set_sleep_mode(PHY_PM_MODE_MODEM_PAUSE);
    }

    phy_set_chan_60(chan, chip6_phy_init_ctrl[PHY_CTRL_XTAL_FREQ], 0U, g_phy_freq_offset,
                    &g_phy_sleep_params, 100U, 1U);
    phy_set_chan_misc(chan);
    bbpll_cal(0U);

    if ((g_phy_sleep_params.param_flag & PHY_PARAM_BOOT_DONE) == 0U) {
        phy_start_dig_rx(saved_dig_rx);
    } else {
        pm_wakeup_init(PHY_PM_MODE_MODEM_PAUSE, 0U);
        phy_after_init_enrx();
    }

    PHY_REG_CLR(PHY_SAR_PWDET_CTRL_REG, PHY_SAR_PWDET_EN_BIT);
    PHY_REG_SET(PHY_SAR_PWDET_CTRL_REG, PHY_SAR_PWDET_EN_BIT);

    if (chip6_phy_init_ctrl[PHY_CTRL_MAC_DEBUG_MODE] == PHY_MAC_DEBUG_ENABLE_MODE) {
        PHY_REG_WRITE(PHY_MAC_DEBUG_REG, PHY_MAC_DEBUG_TEST_PATTERN);
    }

    if (g_phy_chan14_mic_en != 0U) {
        phy_chan14_mic_cfg((chan == PHY_CHAN_14) ? 1U : 0U);
    }
}

/**
 * @brief Start non-blocking RFPLL channel tuning during light/deep-sleep RF wakeup.
 *
 * Holds `PHY_RFPLL_LATCH` and launches `phy_set_chan_60()` with `wait_pll = 0` so
 * subsequent baseband setup overlaps RFPLL VCO calibration; paired with
 * `phy_set_chan_wakeup_exit()`.
 *
 * @param chan  1-based IEEE 802.11 channel number to restore (1..14).
 */
void phy_set_chan_wakeup(uint8_t chan)
{
    PHY_REG_SET(PHY_RFPLL_CTRL_REG, PHY_RFPLL_LATCH);
    phy_set_chan_60(chan, chip6_phy_init_ctrl[PHY_CTRL_XTAL_FREQ], 0U, g_phy_freq_offset,
                    &g_phy_sleep_params, 100U, 0U);
}

/**
 * @brief Complete deferred RF wakeup channel restoration started by `phy_set_chan_wakeup()`.
 *
 * Restores TX capacitor and attenuation tables, waits for RFPLL calibration lock, updates
 * extended RX gain and noise floor, and clears `PHY_RFPLL_LATCH`.
 *
 * @param chan  1-based IEEE 802.11 channel number being restored (1..14).
 */
void phy_set_chan_wakeup_exit(uint8_t chan)
{
    int8_t tmp_atten[6];

    phy_set_txcap_reg(g_phy_sleep_params.txcap, chan);
    phy_tx_atten_set_interp(chan, tmp_atten);
    phy_wait_rfpll_cal_end();
    chip_v6_rxmax_ext(g_phy_rxmax_ext_level);
    phy_set_noise_floor(g_phy_sleep_params.rx_noise);
    PHY_REG_CLR(PHY_RFPLL_CTRL_REG, PHY_RFPLL_LATCH);
}

/**
 * @brief Public SDK entry point to switch the Wi-Fi operating channel by frequency in MHz.
 *
 * Converts @p freq_mhz to a 1-based IEEE channel number via `phy_mhz2ieee()` and calls
 * `phy_set_chan()`.
 *
 * @param freq_mhz  Target 2.4 GHz center frequency in MHz (e.g. 2412..2484).
 * @return          Always returns 0.
 */
int phy_change_channel(uint16_t freq_mhz)
{
    uint8_t chan = phy_mhz2ieee(freq_mhz, PHY_IEEE_2GHZ_FLAG);
    phy_set_chan(chan);
    return 0;
}

/**
 * @brief Enable hardware AGC and Clear Channel Assessment (CCA).
 */
void phy_enable_agc(void)
{
    phy_chip_v5_enable_cca();
}

/**
 * @brief Disable hardware AGC and Clear Channel Assessment (CCA).
 */
void phy_disable_agc(void)
{
    phy_chip_v5_disable_cca();
}

/**
 * @brief Tune analog RX LNA and VGA capacitor banks from the locked RFPLL VCO cap value.
 *
 * Because the RFPLL VCO capacitor code `d` (`PHY_I2C_RFPLL_CAP_READ_REG`) tracks both
 * operating frequency and silicon process corner, linear interpolation yields matched
 * resonant tank trims for the RX LNA (`g0`) and VGA (`g1`):
 * - `g0 = clamp((24 * d - 340) / 227, 0..15)` (with `-1` clamped to `0`)
 * - `g1 = clamp((23 * d + 29)  / 207, 0..15)`
 *
 * When extended max-gain mode requires deliberate front-end detuning (`level >= 3` for LNA,
 * `level >= 2` for VGA), wraps the 4-bit code by `+/-8` (half-scale phase flip). Sets bit 6
 * (`0x40`) to enable each trim bank, caches both bytes in `g_phy_vga_lna_dcap[0..1]`, and
 * toggles `PHY_I2C_RX_ANA_EXT_GAIN_REG` (`0xE0` normal vs `0xEF` extended).
 *
 * @param level  Extended RX max-gain level (0=normal, 1=RX_ANA ext, 2=+VGA wrap, 3=+LNA wrap).
 */
void phy_rxmax_ext_ana(uint8_t level)
{
    /* Read locked VCO capacitor bank code as a process-and-frequency tracker. */
    uint32_t d = (uint32_t)rom_i2c_readReg_Mask(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1,
                                                PHY_I2C_RFPLL_CAP_READ_REG, 7U, 0U);

    /* Linearly interpolate 4-bit LNA cap code g0 and VGA cap code g1 from VCO cap d. */
    int32_t g0 = ((int32_t)(d * 24U) - 340) / 227;
    if (g0 > PHY_RX_GAIN_CAP_MAX) {
        g0 = PHY_RX_GAIN_CAP_MAX;
    } else if (g0 == -1) {
        g0 = 0;
    }

    int32_t g1 = ((int32_t)(d * 23U) + 29) / 207;
    if (g1 > PHY_RX_GAIN_CAP_MAX) {
        g1 = PHY_RX_GAIN_CAP_MAX;
    }

    /* High ext levels flip the MSB (add/sub 8) to detune LNA (lvl >= 3) / VGA (lvl >= 2). */
    if (level >= 3U) {
        g0 += (g0 > 7) ? -PHY_RX_GAIN_CAP_HALF : PHY_RX_GAIN_CAP_HALF;
    }
    g_phy_vga_lna_dcap[0] = (uint8_t)(((uint32_t)g0 & PHY_RX_GAIN_CAP_MASK) |
                                      PHY_RX_GAIN_CAP_EN_BIT);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_GAIN, PHY_I2C_HOST_0,
                     PHY_I2C_RX_GAIN_LNA_CAP_REG, g_phy_vga_lna_dcap[0]);

    if (level >= 2U) {
        g1 += (g1 > 7) ? -PHY_RX_GAIN_CAP_HALF : PHY_RX_GAIN_CAP_HALF;
    }
    g_phy_vga_lna_dcap[1] = (uint8_t)(((uint32_t)g1 & PHY_RX_GAIN_CAP_MASK) |
                                      PHY_RX_GAIN_CAP_EN_BIT);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_GAIN, PHY_I2C_HOST_0,
                     PHY_I2C_RX_GAIN_VGA_CAP_REG, g_phy_vga_lna_dcap[1]);

    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_ANA, PHY_I2C_HOST_1, PHY_I2C_RX_ANA_EXT_GAIN_REG,
                     (level == 0U) ? PHY_RX_ANA_EXT_GAIN_NORM : PHY_RX_ANA_EXT_GAIN_EXT);
}

/**
 * @brief Configure digital extended RX max-gain bit and per-channel RX compensation.
 *
 * @param level  Extended RX max-gain level (0=normal gain, 1..3=extended gain tiers).
 */
void phy_rxmax_ext_dig(uint8_t level)
{
    if (level == 0U) {
        PHY_REG_SET(PHY_RF_RX_GAIN_EXT_REG, PHY_RF_RX_GAIN_EXT_DIG);
    } else {
        PHY_REG_CLR(PHY_RF_RX_GAIN_EXT_REG, PHY_RF_RX_GAIN_EXT_DIG);
    }
    s_set_chan_rx_cmp((int8_t)g_phy_sleep_params.cur_chan, level);
}

/**
 * @brief Apply both analog and digital extended RX max-gain settings for @p level.
 *
 * @param level  Extended RX max-gain level (0..3).
 */
void chip_v6_rxmax_ext(uint8_t level)
{
    phy_rxmax_ext_ana(level);
    phy_rxmax_ext_dig(level);
}

/**
 * @brief Enable or disable the 802.11b CCK RX tuning bits in `PHY_BB_RX11B_REG`.
 *
 * @param enable  0 to clear bits [7:6]; non-zero to write `0x48A` into bits [11:6,3:0].
 */
void phy_set_rx11b_reg(uint8_t enable)
{
    if (enable == 0U) {
        PHY_REG_CLR(PHY_BB_RX11B_REG, PHY_BB_RX11B_DIS_MASK);
    } else {
        PHY_REG_RMW(PHY_BB_RX11B_REG, PHY_BB_RX11B_EN_MASK, PHY_BB_RX11B_EN_VAL);
    }
}

/**
 * @brief Select the digital 802.11b RX baseband filter profile in `PHY_BB_RX_FILTER_REG`.
 *
 * @param sel  Filter selector: 0=bypass, 1=narrow (Ch 14 MIC), 2=medium, 3=wide (default).
 */
void phy_dig_11b_filt_sel(uint8_t sel)
{
    uint32_t val = 0U;
    if (sel == 1U) {
        val = PHY_BB_RX_FILTER_SEL1;
    } else if (sel == 2U) {
        val = PHY_BB_RX_FILTER_SEL2;
    } else if (sel == 3U) {
        val = PHY_BB_RX_FILTER_SEL3;
    }
    PHY_REG_RMW(PHY_BB_RX_FILTER_REG, PHY_BB_RX_FILTER_MASK, val);
}

/**
 * @brief Configure Japan Channel 14 MIC spectral-mask compliance filters and TX power cap.
 *
 * On Channel 14 (`is_ch14 == 1`), narrows both the 802.11b digital RX filter (`sel=1`) and
 * analog TX baseband filter (`0x3C`) and caps max TX power to `g_phy_chan14_mic_most_power`.
 * On Channels 1..13, restores default filter settings and nominal max TX power.
 *
 * @param is_ch14  1 when operating on Channel 14; 0 for all other channels.
 */
void phy_chan14_mic_cfg(uint8_t is_ch14)
{
    if (is_ch14 == 1U) {
        phy_dig_11b_filt_sel(1U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_FILT, PHY_I2C_HOST_3,
                              PHY_I2C_TX_FILT_DCAP_REG, 5U, 0U, PHY_TX_FILT_CH14_DCAP);
        phy_set_most_tpw(g_phy_chan14_mic_most_power);
    } else {
        phy_dig_11b_filt_sel(3U);
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_FILT, PHY_I2C_HOST_3,
                              PHY_I2C_TX_FILT_DCAP_REG, 5U, 0U, g_phy_sleep_params.tx_filt_dcap);
        phy_set_most_tpw(chip6_phy_init_ctrl[PHY_CTRL_TARGET_PWR_BASE]);
    }
}

/**
 * @brief Initialize RF analog I2C sub-blocks (bias, TX PA, RX analog, SAR, BBPLL, RFPLL).
 *
 * Programs verified analog bias/gain/PLL control defaults across the internal ROM-I2C
 * blocks during cold boot and RF wakeup.
 */
void phy_rf_i2c_init(void)
{
    rom_i2c_writeReg(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 0U, 0x25U);
    phy_chip_v5_tx_init();
    rom_i2c_writeReg(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2, 1U, 0x48U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_RX_GAIN, PHY_I2C_HOST_0, 5U, 1U, 0U, 3U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_ANA, PHY_I2C_HOST_1, 8U, 0x11U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, PHY_I2C_SAR_CTRL_REG, 0x15U);
    phy_sar_init();
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BBPLL, PHY_I2C_HOST_4, 4U, 7U, 7U, 1U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 0U, 0x29U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, 4U, 0xAFU);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, PHY_I2C_RFPLL_EN_REG, PHY_RFPLL_EN_RUN);
    PHY_REG_RMW(PHY_BBPLL_CTRL_REG, 0x00000600U, 0x00000400U);
}

/**
 * @brief Power up and initialize the RF front-end, PBUS defaults, RFPLL, and analog blocks.
 *
 * Enables Wi-Fi clocks, stages the RTC RF power rails, initializes PBUS RX/TX safe state,
 * tunes Channel 1 (cold boot) or starts deferred wakeup tuning on `cur_chan` (when
 * `PHY_PARAM_WAKEUP_RF` is set), configures RX analog trims and I2C blocks, and pulses the
 * ANA_INF gating reset (`reg 0x1A: 0x08 -> 0x38`).
 *
 * @return  Always returns 0.
 */
int phy_rf_init(void)
{
    PHY_REG_SET(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_ALL);

    if ((g_phy_sleep_params.param_flag & PHY_PARAM_WAKEUP_RF) == 0U) {
        PHY_REG_WRITE(PHY_RTC_PLL_CTRL_REG, PHY_RTC_PLL_CTRL_BOOT);
        PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, PHY_RTC_RF_PWR_INIT_BASE);
        PHY_REG_CLR(PHY_RF_CAL_MODE_REG, PHY_RF_CAL_MODE_MASK);
    }

    PHY_REG_CLR(PHY_RF_CAL_MODE_REG, PHY_RF_CAL_MODE_LOWPWR_BIT);
    PHY_REG_SET(PHY_RTC_RF_PWR_REG, PHY_RTC_RF_PWR_SAR_BIT);

    if (g_phy_init_rf_no_cal != 0U) {
        PHY_REG_RMW(PHY_RF_CAL_MODE_REG, PHY_RF_CAL_MODE_MASK, PHY_RF_CAL_MODE_ACTIVE);
    }

    PHY_REG_SET(PHY_RTC_RF_PWR_REG, PHY_RTC_RF_PWR_STAGE2_BITS);
    PHY_REG_RMW(PHY_PBUS_STATUS_REG, 0x1F000000U, 0x1C000000U);
    PHY_REG_RMW(PHY_PBUS_CFG_REG, 0x30000000U, 0x10000000U);
    PHY_REG_CLR(PHY_MAC_PHY_CTRL_REG, PHY_MAC_PHY_RF_UP);
    ets_delay_us(2U);
    PHY_REG_SET(PHY_RTC_RF_PWR_REG, PHY_RTC_RF_PWR_STAGE3_BITS);

    phy_pbus_debugmode();
    phy_pbus_force(PHY_PBUS_CH_RX_CTRL, PHY_PBUS_WIDTH_1, 0x81U);
    phy_pbus_xpd_tx_off();
    phy_pbus_workmode();

    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, PHY_I2C_RFPLL_CAL_CTRL_REG, 0x28U);

    if ((g_phy_sleep_params.param_flag & PHY_PARAM_WAKEUP_RF) == 0U) {
        phy_set_chan(1U);
    } else {
        phy_set_chan_wakeup(g_phy_sleep_params.cur_chan);
    }

    /* RX analog defaults (ram_chip_v6_rx_init) */
    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_ANA, PHY_I2C_HOST_1, 8U, 0x11U);
    phy_rxmax_ext_ana(g_phy_rxmax_ext_level);

    phy_rf_i2c_init();
    rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_RXIQ_P_REG, 0x08U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_RXIQ_P_REG, 0x38U);
    return 0;
}

/**
 * @brief Fast-restore RF analog rails, RFPLL, RC filter trims, and PBUS state on wakeup.
 *
 * Runs with ETS interrupts locked: powers up all RTC RF rails (`0xFE000000`), re-initializes
 * RF I2C blocks, reloads the cached RFPLL VCO cap hint and 3-byte SDM word, applies the eFuse
 * errata if needed, restores calibrated RX/TX RC filter dcaps, TX PA caps, and LNA/VGA cap
 * trims, toggles continuous TX mode if configured, and unparks the sleep RX PBUS fields.
 */
void phy_wakeup_rf(void)
{
    g_phy_wakeup_rf_flag = 1U;
    vPortETSIntrLock();

    PHY_REG_CLR(PHY_MAC_PHY_CTRL_REG, PHY_MAC_PHY_RF_UP);
    PHY_REG_SET(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_ALL);
    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, PHY_RTC_RF_PWR_ALL_ON);

    phy_rf_i2c_init();
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1,
                     PHY_I2C_RFPLL_CAP_HINT_REG, g_phy_or_pll_cap_last);
    phy_rfpll_reset();
    phy_write_rfpll_sdm(g_phy_rfpll_sdm_reg);
    phy_rfpll_restart_cal();

    if (((PHY_REG_READ(PHY_EFUSE_DATA2_REG) >> PHY_EFUSE_DATA2_ANA_REV_SHIFT) &
         PHY_EFUSE_DATA2_RF_ERRATA_MASK) == 0U &&
        (PHY_REG_READ(PHY_BB_ADC_RAND_REG) & PHY_EFUSE_ERRATA_RAND_MASK) == 0U) {
        PHY_REG_WRITE(PHY_RF_I2C_HOST_REG(0), PHY_RF_I2C_ERRATA_CMD);
    }

    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_ANA, PHY_I2C_HOST_1, 7U, 0x51U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_ANA, PHY_I2C_HOST_1, PHY_I2C_RX_ANA_FILT_REG,
                     (uint8_t)(g_phy_sleep_params.rx_filt_dcap | PHY_RX_ANA_FILT_EN_BIT));
    rom_i2c_writeReg(PHY_I2C_BLOCK_TX_FILT, PHY_I2C_HOST_3, PHY_I2C_TX_FILT_DCAP_REG,
                     (uint8_t)(g_phy_sleep_params.tx_filt_dcap | PHY_TX_FILT_DCAP_EN_BIT));

    PHY_REG_SET(PHY_MAC_PHY_CTRL_REG, PHY_MAC_PHY_RF_UP);

    phy_set_txcap_reg(g_phy_sleep_params.txcap, g_phy_sleep_params.cur_chan);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_GAIN, PHY_I2C_HOST_0,
                     PHY_I2C_RX_GAIN_LNA_CAP_REG, g_phy_vga_lna_dcap[0]);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_GAIN, PHY_I2C_HOST_0,
                     PHY_I2C_RX_GAIN_VGA_CAP_REG, g_phy_vga_lna_dcap[1]);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RX_ANA, PHY_I2C_HOST_1, PHY_I2C_RX_ANA_EXT_GAIN_REG,
                     (g_phy_rxmax_ext_level == 0U)
                         ? PHY_RX_ANA_EXT_GAIN_NORM
                         : PHY_RX_ANA_EXT_GAIN_EXT);

    if (chip6_phy_init_ctrl[PHY_CTRL_FCC_TEST_MODE] == PHY_FCC_TEST_CONT_TX) {
        phy_tx_cont_en();
    } else {
        phy_tx_cont_dis();
    }

    phy_sleep_set_rxpbus(1U);

    vPortETSIntrUnlock();
    g_phy_wakeup_rf_flag = 0U;
}

/**
 * @brief Power down the RF front-end and gate Wi-Fi sub-block clocks for RF-off/sleep state.
 *
 * Pauses the modem, parks sleep RX PBUS bits, disables the RFPLL, clears `PHY_MAC_PHY_RF_UP`,
 * gates Wi-Fi sub-block clocks, powers down RTC RF rails (`PHY_RTC_RF_PWR_RF_OFF`), and
 * marks `g_phy_sleep_mode_flag = 1`.
 */
void phy_close_rf(void)
{
    pm_set_sleep_mode(PHY_PM_MODE_MODEM_PAUSE);
    phy_sleep_set_rxpbus(0U);
    rom_i2c_writeReg(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1,
                     PHY_I2C_RFPLL_PWR_REG, PHY_RFPLL_PWR_OFF);
    PHY_REG_CLR(PHY_MAC_PHY_CTRL_REG, PHY_MAC_PHY_RF_UP);
    PHY_REG_CLR(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_GATE_MASK);
    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, PHY_RTC_RF_PWR_RF_OFF);
    g_phy_sleep_mode_flag = 1U;
}

/**
 * @brief Program baseband RX AGC thresholds, timing, framing, PBUS defaults, and gain table.
 *
 * Applies the empirically characterized ESP8266 baseband AGC threshold bank, enables digital
 * spur suppression and default CCA/noise-floor baselines, configures MAC-PHY RX framing and
 * peripheral BB clock, sets initial PBUS TX/RX bias words, loads the RX gain table
 * (`rxmax = 3`), and selects the default 802.11b digital filter (`sel = 3`).
 */
void phy_bb_rx_cfg(void)
{
    /* Baseband RX control enable and primary AGC target / saturation thresholds */
    PHY_REG_SET(PHY_BB_RX_CTRL_REG, 0x00001400U);
    PHY_REG_SET(PHY_BB_AGC_THR_9B0C_REG, 0x10000000U);
    PHY_REG_RMW(PHY_BB_AGC_THR_9D40_REG, 0x7F800000U, 0x10000000U);

    /* AGC coarse/fine step timing, energy-detection windows, and clip recovery */
    PHY_REG_WRITE(PHY_BB_AGC_THR_9B6C_REG, 0x0914BC81U);
    PHY_REG_WRITE(PHY_BB_AGC_THR_9B68_REG, 0x5AC64198U);
    PHY_REG_CLR(PHY_BB_AGC_THR_9B50_REG, 0x80000000U);

    /* OFDM / 11b packet-detect correlation timeout and preamble thresholds */
    PHY_REG_WRITE(PHY_BB_AGC_THR_9D18_REG, 400U);
    PHY_REG_RMW(PHY_BB_AGC_THR_98EC_REG, 0x03FF0000U, 0x01900000U);
    PHY_REG_CLR(PHY_BB_AGC_THR_9988_REG, 0x04000000U);

    /* Initial AGC max-gain index, gain-step limits, and frequency-offset AGC trim */
    PHY_REG_RMW(PHY_BB_RX_MAX_GAIN_REG, PHY_BB_RX_MAX_GAIN_MASK,
                ((uint32_t)g_phy_rx_max_gain_val - PHY_RX_MAX_GAIN_INIT_STEP) &
                PHY_BB_RX_MAX_GAIN_MASK);
    PHY_REG_RMW(PHY_BB_AGC_THR_9B28_REG, 0xFF000000U, 0x18000000U);
    PHY_REG_CLR(PHY_BB_RX_GAIN_FORCE_REG, 0x7F000000U);
    PHY_REG_RMW(PHY_BB_AGC_THR_9B44_REG, 0x0000007FU,
                ((chip6_phy_init_ctrl[PHY_CTRL_FREQ_OFF_MODE] & 1U) != 0U) ? 0x2EU : 0x26U);
    PHY_REG_RMW(PHY_BB_AGC_THR_9D70_REG, 0x0000003FU, 0x00000011U);

    /* Enable digital spur notch engine and seed CCA / noise-floor baseline */
    PHY_REG_SET(PHY_BB_SPUR_FREQ_REG, PHY_BB_SPUR_FREQ_EN_BITS);
    PHY_REG_RMW(PHY_BB_NOISE_FLOOR_REG, PHY_BB_NOISE_FLOOR_CCA_MASK, 0x00022000U);
    PHY_REG_RMW(PHY_BB_NOISE_FLOOR_REG, 0x00000FFFU, 0x00000FA6U);

    /* Secondary AGC lock-in, gain-drop hysteresis, and CCA sensitivity thresholds */
    PHY_REG_RMW(PHY_BB_AGC_THR_9B5C_REG, 0x003FFFFFU, 0x00385854U);
    PHY_REG_RMW(PHY_BB_AGC_THR_9B50_REG, 0x0FF000FFU, 0x0B2000E6U);
    PHY_REG_WRITE(PHY_BB_AGC_THR_9D18_REG, 0x00000080U);
    PHY_REG_SET(PHY_BB_AGC_THR_9D10_REG, 0x00000004U);
    PHY_REG_RMW(PHY_BB_AGC_THR_9D70_REG, 0x20000FC0U, 0x20000C40U);

    /* Strong-signal / adjacent-channel rejection and OFDM timing sync thresholds */
    PHY_REG_RMW(PHY_BB_AGC_THR_9D24_REG, 0x007F0000U, 0x00130000U);
    PHY_REG_RMW(PHY_BB_AGC_THR_9B58_REG, 0x00000FC0U, 0x00000D80U);
    PHY_REG_RMW(PHY_BB_AGC_THR_9D4C_REG, 0x03FFFFFFU, 0x03FE0124U);
    PHY_REG_RMW(PHY_BB_AGC_THR_9D20_REG, 0xF0000000U, 0xB0000000U);
    PHY_REG_SET(PHY_BB_AGC_THR_9988_REG, 0x04000000U);

    /* MAC-PHY RX framing handshake, extended RX gain, and sensitivity backoff */
    PHY_REG_RMW(PHY_MAC_PHY_CTRL_REG, PHY_MAC_PHY_RX_FRAME_MASK, PHY_MAC_PHY_RX_FRAME_VAL);
    PHY_REG_CLR(PHY_BB_AGC_THR_9D44_REG, 0x00400000U);

    phy_rxmax_ext_dig(g_phy_rxmax_ext_level);
    phy_chip_v5_sense_backoff(0U);

    /* 802.11b front-end demodulator, DC-tracker, and baseband clock configuration */
    PHY_REG_RMW(PHY_BB_11B_FE_REG, 0x00000030U, 0x00000020U);
    PHY_REG_WRITE(PHY_BB_AGC_THR_9C48_REG, 0x00800083U);
    PHY_REG_SET(PHY_BB_AGC_THR_9C4C_REG, 0x00000006U);
    PHY_REG_WRITE(PHY_BB_AGC_THR_9D1C_REG, 0x00000FFFU);
    PHY_REG_SET(PHY_BB_AGC_THR_9D1C_REG, 0x00000FFFU);
    PHY_REG_CLR(PHY_BB_TX_CAL_REG, 0x00000800U);

    PHY_REG_RMW(PHY_DPORT_PERI_CLK_REG, PHY_DPORT_PERI_CLK_BB_MASK, PHY_DPORT_PERI_CLK_BB_VAL);
    PHY_REG_CLR(PHY_FE_RX_CTRL_REG, 0x00000001U);

    /* Initial PBUS TX bias and RX front-end/BB defaults before loading the RX gain RAM */
    phy_pbus_debugmode();
    phy_pbus_force(PHY_PBUS_CH_TXEN_DCO_Q, PHY_PBUS_WIDTH_1, 0x0CU);
    if (g_phy_rx_table_renew_en != 0U) {
        phy_pbus_force(PHY_PBUS_CH_RX_CTRL, PHY_PBUS_WIDTH_1, 0x184U);
        phy_pbus_force(PHY_PBUS_CH_RXBB_GAIN, PHY_PBUS_WIDTH_2, 0x06U);
    }
    phy_pbus_workmode();

    phy_set_rx_gain_table(PHY_RX_GAIN_TABLE_DEFAULT_RXMAX);
    phy_dig_11b_filt_sel(3U);
}

/**
 * @brief Program baseband antenna-switch truth tables for BT coexistence or external switch.
 *
 * Selects the `PHY_BB_ANT_SWITCH_LO_REG` and `PHY_BB_ANT_SWITCH_HI_REG` lookup words based
 * on `PHY_CTRL_BTCO_MODE` (1/3 vs 4/5) or standalone `PHY_CTRL_ANT_SWITCH_MODE` (2 vs 3),
 * enables `PHY_BB_AGC_ANT_SW_EN`, and configures baseband sleep/TX-cal switch routing.
 */
void phy_ant_switch_init(void)
{
    uint8_t btco = chip6_phy_init_ctrl[PHY_CTRL_BTCO_MODE];
    uint8_t ant = chip6_phy_init_ctrl[PHY_CTRL_ANT_SWITCH_MODE];

    if (btco == 1U || btco == 3U) {
        PHY_REG_WRITE(PHY_BB_ANT_SWITCH_LO_REG, PHY_ANT_SW_BTCO_13_LO);
        PHY_REG_WRITE(PHY_BB_ANT_SWITCH_HI_REG, PHY_ANT_SW_BTCO_13_HI);
    } else if (btco == 4U || btco == 5U) {
        PHY_REG_WRITE(PHY_BB_ANT_SWITCH_LO_REG, PHY_ANT_SW_BTCO_45_LO);
        PHY_REG_WRITE(PHY_BB_ANT_SWITCH_HI_REG, PHY_ANT_SW_BTCO_45_HI);
    } else if (ant == 2U) {
        PHY_REG_WRITE(PHY_BB_ANT_SWITCH_LO_REG, PHY_ANT_SW_EXT_2_LO);
        PHY_REG_WRITE(PHY_BB_ANT_SWITCH_HI_REG, PHY_ANT_SW_EXT_2_HI);
    } else if (ant == 3U) {
        PHY_REG_WRITE(PHY_BB_ANT_SWITCH_LO_REG, PHY_ANT_SW_EXT_3_LO);
        PHY_REG_WRITE(PHY_BB_ANT_SWITCH_HI_REG, PHY_ANT_SW_EXT_3_HI);
    }

    PHY_REG_SET(PHY_BB_AGC_CTRL_REG, PHY_BB_AGC_ANT_SW_EN);
    PHY_REG_RMW(PHY_BB_SLEEP_REG, 0x00003C00U, 0x00000800U);
    PHY_REG_WRITE(PHY_BB_TX_CAL_REG, 2U);
}

/**
 * @brief Configure IO_MUX, RTC external-sleep GPIO, and Bluetooth coexistence GPIO routing.
 *
 * Handles external sleep option 2 (`PHY_RTC_EXT_GPIO_REG`), standalone antenna-switch pins
 * (`GPIO0` for mode 3, `MTDO` for mode 2), or full 2/3-wire BT coexistence matrix routing
 * (`PHY_GPIO_BTCO_CFG_REG`, `MTCK`/`MTMS`/`MTDO`/`GPIO0` muxes, and static GPIO0/GPIO3
 * polarity drives for `btco_sub < 2`).
 */
void phy_gpio_cfg(void)
{
    if (chip6_phy_init_ctrl[PHY_CTRL_EXT_SLEEP_OPT] == PHY_EXT_SLEEP_OPT_GPIO) {
        PHY_REG_RMW(PHY_RTC_EXT_GPIO_REG, 0x0000006BU, 0x00000069U);
    }

    uint8_t btco = chip6_phy_init_ctrl[PHY_CTRL_BTCO_MODE];
    uint8_t btco_sub = chip6_phy_init_ctrl[PHY_CTRL_BTCO_SUBMODE];
    uint8_t ant = chip6_phy_init_ctrl[PHY_CTRL_ANT_SWITCH_MODE];

    if (btco != 1U && btco != 3U && btco != 4U && btco != 5U) {
        if (ant == 3U) {
            PHY_REG_RMW(PHY_IO_MUX_GPIO0_REG, PHY_IO_MUX_FUNC_MASK, PHY_IO_MUX_FUNC_BTCO_ANT);
        } else if (ant == 2U) {
            PHY_REG_RMW(PHY_IO_MUX_MTDO_REG, PHY_IO_MUX_FUNC_MASK, PHY_IO_MUX_FUNC_BTCO_ANT);
        }
        return;
    }

    if (btco == 1U || btco == 4U) {
        if (btco_sub == 3U || btco_sub == 5U) {
            PHY_REG_WRITE(PHY_GPIO_BTCO_CFG_REG, PHY_BTCO_GPIO_CFG_14_HI);
        } else if (btco_sub < 2U) {
            PHY_REG_WRITE(PHY_GPIO_BTCO_CFG_REG, 0U);
        } else {
            PHY_REG_WRITE(PHY_GPIO_BTCO_CFG_REG, PHY_BTCO_GPIO_CFG_14_LO);
        }
    } else if (btco == 3U || btco == 5U) {
        if (btco_sub == 3U || btco_sub == 5U) {
            PHY_REG_WRITE(PHY_GPIO_BTCO_CFG_REG, PHY_BTCO_GPIO_CFG_35_HI);
        } else if (btco_sub < 2U) {
            PHY_REG_WRITE(PHY_GPIO_BTCO_CFG_REG, 0U);
        } else {
            PHY_REG_WRITE(PHY_GPIO_BTCO_CFG_REG, PHY_BTCO_GPIO_CFG_35_LO);
        }
    }

    PHY_REG_RMW(PHY_IO_MUX_MTCK_REG, PHY_IO_MUX_FUNC_PU_MASK, PHY_IO_MUX_FUNC_GPIO);
    PHY_REG_RMW(PHY_IO_MUX_MTMS_REG, PHY_IO_MUX_FUNC_PU_MASK, PHY_IO_MUX_FUNC_GPIO);

    if (btco_sub < 2U) {
        PHY_REG_RMW(PHY_IO_MUX_MTDO_REG, PHY_IO_MUX_FUNC_MASK, PHY_IO_MUX_FUNC_GPIO);
        PHY_REG_CLR(PHY_IO_MUX_GPIO0_REG, PHY_IO_MUX_FUNC_MASK);
    } else {
        PHY_REG_RMW(PHY_IO_MUX_MTDO_REG, PHY_IO_MUX_FUNC_MASK, PHY_IO_MUX_FUNC_BTCO_ANT);
        PHY_REG_RMW(PHY_IO_MUX_GPIO0_REG, PHY_IO_MUX_FUNC_MASK, PHY_IO_MUX_FUNC_BTCO_ANT);
    }

    if (btco == 1U || btco == 3U) {
        if (btco_sub == 1U) {
            gpio_output_set(PHY_BTCO_GPIO_PIN0_MASK, 0U, PHY_BTCO_GPIO_PIN0_MASK, 0U);
            gpio_output_set(0U, PHY_BTCO_GPIO_PIN3_MASK, PHY_BTCO_GPIO_PIN3_MASK, 0U);
        } else if (btco_sub == 0U) {
            gpio_output_set(0U, PHY_BTCO_GPIO_PIN0_MASK, PHY_BTCO_GPIO_PIN0_MASK, 0U);
            gpio_output_set(PHY_BTCO_GPIO_PIN3_MASK, 0U, PHY_BTCO_GPIO_PIN3_MASK, 0U);
        }
    } else if (btco == 4U || btco == 5U) {
        if (btco_sub == 0U) {
            gpio_output_set(PHY_BTCO_GPIO_PIN0_MASK, 0U, PHY_BTCO_GPIO_PIN0_MASK, 0U);
            gpio_output_set(0U, PHY_BTCO_GPIO_PIN3_MASK, PHY_BTCO_GPIO_PIN3_MASK, 0U);
        } else if (btco_sub == 1U) {
            gpio_output_set(0U, PHY_BTCO_GPIO_PIN0_MASK, PHY_BTCO_GPIO_PIN0_MASK, 0U);
            gpio_output_set(PHY_BTCO_GPIO_PIN3_MASK, 0U, PHY_BTCO_GPIO_PIN3_MASK, 0U);
        }
    }
}

/**
 * @brief Place RF analog rails in minimal-current standby while keeping SAR ADC usable.
 *
 * Used when booting with RF disabled (e.g. `powerup_cal_mode == 0` / deep-sleep no-RF wake):
 * drops `PHY_RTC_RF_PWR_REG` to `PHY_RTC_RF_PWR_DEEP_SAR`, disables RFPLL and analog bias
 * stages, optionally enables PBUS PA VDD33 SAR bias when `PHY_CTRL_VDD33_CONST == 0xFF`,
 * gates Wi-Fi sub-block clocks, and initializes the SAR ADC.
 */
void phy_reduce_current_init(void)
{
    PHY_REG_WRITE(PHY_RTC_RF_PWR_REG, PHY_RTC_RF_PWR_DEEP_SAR);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_RFPLL, PHY_I2C_HOST_1, PHY_I2C_RFPLL_PWR_REG, 7U, 4U, 0U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BIAS_PWR, PHY_I2C_HOST_4, 0U, 6U, 6U, 0U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_BIAS_PWR, PHY_I2C_HOST_4, 0U, 7U, 7U, 0U);

    if (chip6_phy_init_ctrl[PHY_CTRL_VDD33_CONST] == PHY_VDD33_MODE_MEASURE) {
        PHY_REG_CLR(PHY_RF_CAL_MODE_REG, PHY_RF_CAL_MODE_LOWPWR_BIT);
        PHY_REG_SET(PHY_PBUS_CTRL_REG, PHY_PBUS_DEBUG_MODE);
        phy_pbus_force(PHY_PBUS_CH_PA_EN, PHY_PBUS_WIDTH_1, PHY_PBUS_PA_VDD33_BIAS);
        PHY_REG_CLR(PHY_PBUS_CTRL_REG, PHY_PBUS_DEBUG_MODE);
    }

    PHY_REG_CLR(PHY_DPORT_CLK_EN_REG, PHY_DPORT_CLK_WIFI_GATE_MASK);
    rom_i2c_writeReg(PHY_I2C_BLOCK_BIAS_RC, PHY_I2C_HOST_2, 0U, 0x25U);
    phy_sar_init();
}

/**
 * @brief Enable FCC continuous-TX hardware override (saving original TX filter & PBUS regs).
 *
 * Idempotent: saves `TX_FILT_DCAP`, `PBUS_CTRL`, `PBUS_CFG`, and `PBUS_CFG_MIRROR` on first
 * entry and forces continuous-TX filter/PBUS timing overrides until `phy_tx_cont_dis()`.
 */
void phy_tx_cont_en(void)
{
    if (s_tx_cont_en_flag == 0U) {
        s_tx_data[0] = (uint32_t)rom_i2c_readReg(PHY_I2C_BLOCK_TX_FILT, PHY_I2C_HOST_3,
                                                 PHY_I2C_TX_FILT_DCAP_REG);
        s_tx_data[1] = PHY_REG_READ(PHY_PBUS_CTRL_REG);
        s_tx_data[2] = PHY_REG_READ(PHY_PBUS_CFG_REG);
        s_tx_data[3] = PHY_REG_READ(PHY_PBUS_CFG_MIRROR_REG);

        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_TX_FILT, PHY_I2C_HOST_3,
                              PHY_I2C_TX_FILT_DCAP_REG, 5U, 0U, PHY_TX_FILT_CH14_DCAP);
        PHY_REG_SET(PHY_PBUS_CFG_MIRROR_REG, 0x0FE03F80U);
        PHY_REG_SET(PHY_PBUS_CFG_REG, 0x0FFFFFFFU);
        PHY_REG_CLR(PHY_PBUS_CTRL_REG, PHY_PBUS_RXPBUS_LO_EN);
    }
    s_tx_cont_en_flag = 1U;
}

/**
 * @brief Disable FCC continuous-TX mode and restore registers saved by `phy_tx_cont_en()`.
 */
void phy_tx_cont_dis(void)
{
    if (s_tx_cont_en_flag == 1U) {
        rom_i2c_writeReg(PHY_I2C_BLOCK_TX_FILT, PHY_I2C_HOST_3,
                         PHY_I2C_TX_FILT_DCAP_REG, (uint8_t)s_tx_data[0]);
        PHY_REG_WRITE(PHY_PBUS_CTRL_REG, s_tx_data[1]);
        PHY_REG_WRITE(PHY_PBUS_CFG_REG, s_tx_data[2]);
        PHY_REG_WRITE(PHY_PBUS_CFG_MIRROR_REG, s_tx_data[3]);
    }
    s_tx_cont_en_flag = 0U;
}

/**
 * @brief Park or unpark the sleep RX PBUS control fields and strobe `PHY_RF_CAL_MODE_REG`.
 *
 * @param en  0 to zero the sleep RX PBUS fields (before RF sleep/close);
 *            non-zero to restore active RX PBUS fields (`0x00300000` / `0xD8000000`).
 */
void phy_sleep_set_rxpbus(uint8_t en)
{
    if (en == 0U) {
        PHY_REG_CLR(PHY_PBUS_CTRL_REG, PHY_PBUS_RXPBUS_LO_MASK);
        PHY_REG_CLR(PHY_PBUS_CTRL_REG, PHY_PBUS_RXPBUS_HI_MASK);
    } else {
        PHY_REG_RMW(PHY_PBUS_CTRL_REG, PHY_PBUS_RXPBUS_LO_MASK, PHY_PBUS_RXPBUS_LO_EN);
        PHY_REG_RMW(PHY_PBUS_CTRL_REG, PHY_PBUS_RXPBUS_HI_MASK, PHY_PBUS_RXPBUS_HI_EN);
    }

    PHY_REG_RMW(PHY_RF_CAL_MODE_REG, PHY_RF_CAL_MODE_MASK, PHY_RF_CAL_MODE_ACTIVE);
    ets_delay_us(1U);
    PHY_REG_CLR(PHY_RF_CAL_MODE_REG, PHY_RF_CAL_MODE_MASK);
}

/**
 * @brief Temporarily gate digital RX baseband and return the previous `PHY_BB_DIG_RX_REG`.
 *
 * Paired with `phy_start_dig_rx()` during boot-time channel switches and calibration.
 *
 * @return  Saved 32-bit value of `PHY_BB_DIG_RX_REG` prior to clearing `PHY_BB_DIG_RX_EN`.
 */
uint32_t phy_stop_dig_rx(void)
{
    uint32_t saved = PHY_REG_READ(PHY_BB_DIG_RX_REG);
    PHY_REG_SET(PHY_BB_SLEEP_REG, PHY_BB_SLEEP_RX);
    PHY_REG_CLR(PHY_BB_DIG_RX_REG, PHY_BB_DIG_RX_EN);
    return saved;
}

/**
 * @brief Ungate digital RX baseband, pulse `PHY_BB_RX_RESET`, and restore `PHY_BB_DIG_RX_REG`.
 *
 * @param saved_dig_rx  Register value previously returned by `phy_stop_dig_rx()`.
 */
void phy_start_dig_rx(uint32_t saved_dig_rx)
{
    PHY_REG_CLR(PHY_BB_SLEEP_REG, PHY_BB_SLEEP_RX);
    PHY_REG_SET(PHY_BB_RX_CTRL_REG, PHY_BB_RX_RESET);
    PHY_REG_CLR(PHY_BB_RX_CTRL_REG, PHY_BB_RX_RESET);
    PHY_REG_WRITE(PHY_BB_DIG_RX_REG, saved_dig_rx);
}

/**
 * @brief Re-enable live RX gain tracking after wakeup or channel-switch pause.
 *
 * Clears `PHY_RF_CAL_MODE_MASK`, waits 5 us, pulses `PHY_BB_RX_GAIN_FORCE_REG`
 * (`0xF1 -> 0xF0`), and waits 5 us for the RX front-end to settle.
 */
void phy_after_init_enrx(void)
{
    PHY_REG_CLR(PHY_RF_CAL_MODE_REG, PHY_RF_CAL_MODE_MASK);
    ets_delay_us(5U);
    PHY_REG_RMW(PHY_BB_RX_GAIN_FORCE_REG, PHY_BB_RX_GAIN_FORCE_MASK, PHY_BB_RX_GAIN_ENRX_LATCH);
    PHY_REG_RMW(PHY_BB_RX_GAIN_FORCE_REG, PHY_BB_RX_GAIN_FORCE_MASK, PHY_BB_RX_GAIN_ENRX_DONE);
    ets_delay_us(5U);
}
