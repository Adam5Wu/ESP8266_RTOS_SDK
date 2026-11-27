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
// Portions of the RF-I2C and PBUS hardware sequences are adapted from teatime-os:
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

/* Hardware polling limits (iteration counts) */
#define PHY_I2C_POLL_MAX                100000U
#define PHY_PBUS_POLL_MAX               100000U
#define PHY_IQ_EST_POLL_MAX             1000000U

/* RF-I2C MMIO command word bitfield packing */
#define PHY_I2C_REG_SHIFT               8U
#define PHY_I2C_DATA_SHIFT              16U
#define PHY_I2C_BYTE_MASK               0xFFU
#define PHY_I2C_BITPOS_MASK             0x1FU

/* PBUS read-window decoding (13 x 9-bit slots across 5 x 32-bit words) */
#define PHY_PBUS_WIDTH_4                4U
#define PHY_PBUS_CH_MASK                7U
#define PHY_PBUS_RD_SLOTS_PER_WORD      3U
#define PHY_PBUS_RD_SLOT_BITS           9U
#define PHY_PBUS_RD_TOP_SHIFT           18U
#define PHY_PBUS_RD_SLOT_SPECIAL        12U

/* PBUS TX/RX power-down (XPD) & loopback default 9-bit channel payloads */
#define PHY_PBUS_XPD_RX_ON_R2           0x184U /* Ch2 w1: RX path/LNA/VGA power on */
#define PHY_PBUS_XPD_RX_ON_R3_W2        6U     /* Ch3 w2: RXBB fine-stage enable bits */
#define PHY_PBUS_XPD_RX_OFF_BASE        0x80   /* Ch2 w1: base bias added to reg2_val */
#define PHY_PBUS_XPD_TX_OFF_R1          0x0CU  /* Ch1 w1: TX bias off / standby */
#define PHY_PBUS_XPD_TX_OFF_R2          0x80U  /* Ch2 w1: TX off, base bias retained */
#define PHY_PBUS_XPD_TX_ON_R2           0x81U  /* Ch2 w1: TX path enabled */
#define PHY_PBUS_XPD_TX_ON_R1           0x7FU  /* Ch1 w1: TX bias / enable all on */
#define PHY_PBUS_XPD_TX_ON_R6           0x7FU  /* Ch6 w1: PA power enable all on */
#define PHY_PBUS_LOOPBACK_R2_INIT       0x185U /* Ch2 w1: simultaneous TX+RX loopback */
#define PHY_PBUS_DEBUG_SETTLE_US        5U

/* PBUS gain packing masks & RXBB coarse-stage thermometer codes (6 dB/step) */
#define PHY_PBUS_TX_ANA_GAIN_MASK       0x1FU
#define PHY_PBUS_TX_RF_GAIN_SHIFT       5U
#define PHY_PBUS_RXGAIN_R3_W2_KEEP      0x1C7U
#define PHY_PBUS_RXGAIN_R2_W1_KEEP      0x185U
#define PHY_PBUS_RXBB_STEP_DB           6
#define PHY_PBUS_RXBB_COARSE_0DB        0x00U
#define PHY_PBUS_RXBB_COARSE_6DB        0x40U
#define PHY_PBUS_RXBB_COARSE_12DB       0x60U
#define PHY_PBUS_RXBB_COARSE_18DB       0x70U
#define PHY_PBUS_RXBB_COARSE_24DB       0x78U

/* Analog interface, clock-gating, DPD & SAR sub-register bit positions */
#define PHY_I2C_ANA_INF_TXCLK_BIT       6U
#define PHY_I2C_ANA_INF_RXCLK_BIT       5U
#define PHY_I2C_ANA_INF_GATING_BIT      0U
#define PHY_I2C_ANA_INF_DPD_BYP_BIT     1U
#define PHY_I2C_ANA_INF_DPD_GATE_BIT    3U
#define PHY_I2C_ANA_INF_RXIQ_GATE_BIT   0U
#define PHY_I2C_ANA_INF_DIV_REG0        0x00U
#define PHY_I2C_ANA_INF_DIV_REG1        0x01U
#define PHY_I2C_ANA_INF_DIV_REG2        0x02U
#define PHY_I2C_ANA_INF_DIV_REG3        0x03U
#define PHY_I2C_ANA_INF_DIV_REG4        0x04U
#define PHY_I2C_ANA_CLK_TX_BIT          0U
#define PHY_I2C_ANA_CLK_RX_BIT          1U
#define PHY_I2C_SAR_INIT_BIT            4U
#define PHY_I2C_SAR_CFG_DEFAULT         2U
#define PHY_ANA_INF_TX_SCALE_MAX        0x3FU
#define PHY_DPD_TXPWR_REF_SLOT          23U
#define PHY_DPD_SCALE_BIAS              24U

/* IQ/DC estimator & correlator scaling shifts */
#define PHY_IQ_DC_SHIFT                 6
#define PHY_CORR_ACC_SHIFT              18
#define PHY_CORR_DC_SHIFT_BIAS          2U
#define PHY_CORR_PWR_SHIFT_BIAS         11U
#define PHY_CORR_DC_SQ_SHIFT            16

/* Pure-integer amplitude-to-dB approximation (0.125 dB / LSB) */
#define PHY_DB_SCALE_REF_SHIFT          3U
#define PHY_DB_EXP_BIAS                 28
#define PHY_DB_OCTAVE_STEPS             48     /* 20*log10(2) / 0.125 ≈ 48 (6.0 dB/octave) */
#define PHY_DB_MANTISSA_MASK            0x0FU

/* IEEE 802.11 2.4 GHz / extended 2.5 GHz channel frequency mapping */
#define PHY_IEEE_CH14_FREQ_MHZ          2484U
#define PHY_IEEE_CH14_NUM               14U
#define PHY_IEEE_ISM_MAX_MHZ            2483U
#define PHY_IEEE_ISM_BASE_MHZ           2407
#define PHY_IEEE_ISM_STEP_MHZ           5
#define PHY_IEEE_EXT_BASE_MHZ           2512
#define PHY_IEEE_EXT_STEP_MHZ           20
#define PHY_IEEE_EXT_CHAN_BASE          15
#define PHY_IEEE_FLAG_EXT_2GHZ          0x80U
#define PHY_IEEE_CHAN_INVALID           0xFFU

/* Baseband sense backoff bitfields & chip-v5 TX PA init count */
#define PHY_BB_SENSE_BACKOFF_MASK       0x0001FC00U
#define PHY_BB_SENSE_BACKOFF_SHIFT      10U
#define PHY_BB_AGC_THR_9D24_MASK        0x000000FEU
#define PHY_BB_AGC_THR_9D24_SHIFT       1U
#define PHY_CHIP_V5_TX_INIT_REG_COUNT   11U

/* Re-entrancy guard for RF-I2C ETS interrupt locking (1 B DRAM, explicit init) */
static uint8_t s_phy_interrup_flag = 0U;

/* --------------------------------------------------------------------------
 * IRAM Primitives: ROM-I2C Bus & MAC Microsecond Timer
 * -------------------------------------------------------------------------- */

/**
 * @brief Read an 8-bit register from an internal analog block over the RF-I2C bus.
 *
 * Placed in `IRAM_ATTR` so it remains callable while SPI flash cache is disabled
 * (e.g., during wake/BBPLL transitions). Acquires `vPortETSIntrLock()` unless
 * already inside an RF wakeup critical section (`g_phy_wakeup_rf_flag != 0`) or
 * a nested RF-I2C call (`s_phy_interrup_flag != 0`).
 *
 * @param block    Internal analog block address (`PHY_I2C_BLOCK_*`, 8-bit).
 * @param host_id  RF-I2C controller host index (`PHY_I2C_HOST_0`..`PHY_I2C_HOST_4`).
 * @param reg_add  Target sub-register offset within @p block (8-bit).
 * @return         8-bit value read back from the analog sub-register.
 */
uint8_t IRAM_ATTR rom_i2c_readReg(uint8_t block, uint8_t host_id, uint8_t reg_add)
{
    /*
     * Guard against re-entrant ETS locking: callers inside RF wakeup already
     * hold interrupts masked, and nested calls are tracked via s_phy_interrup_flag.
     */
    bool locked = (g_phy_wakeup_rf_flag == 0U) && (s_phy_interrup_flag == 0U);
    if (locked) {
        vPortETSIntrLock();
        s_phy_interrup_flag = 1U;
    }

    /* Command word format for read: [15:8]=reg_add, [7:0]=block, BIT(24)=0 (read). */
    uint32_t reg_addr = PHY_RF_I2C_HOST_REG((uint32_t)host_id & PHY_I2C_BYTE_MASK);
    PHY_REG_WRITE(reg_addr,
                  (((uint32_t)reg_add & PHY_I2C_BYTE_MASK) << PHY_I2C_REG_SHIFT) |
                  ((uint32_t)block & PHY_I2C_BYTE_MASK));
    for (uint32_t t = 0U;
         (PHY_REG_READ(reg_addr) & PHY_RF_I2C_BUSY) != 0U && t < PHY_I2C_POLL_MAX;
         t++) {
    }
    uint32_t val = (PHY_REG_READ(reg_addr) >> PHY_I2C_DATA_SHIFT) & PHY_I2C_BYTE_MASK;

    if (locked) {
        s_phy_interrup_flag = 0U;
        vPortETSIntrUnlock();
    }

    return (uint8_t)val;
}

/**
 * @brief Read and extract an inclusive bitfield `[msb:lsb]` from an RF-I2C register.
 *
 * Placed in `IRAM_ATTR`; delegates bus locking and I/O to rom_i2c_readReg().
 *
 * @param block    Internal analog block address (`PHY_I2C_BLOCK_*`, 8-bit).
 * @param host_id  RF-I2C controller host index (`PHY_I2C_HOST_0`..`PHY_I2C_HOST_4`).
 * @param reg_add  Target sub-register offset within @p block (8-bit).
 * @param msb      Most-significant bit index of the field (0..7, inclusive).
 * @param lsb      Least-significant bit index of the field (0..msb, inclusive).
 * @return         Right-aligned bitfield value `(reg >> lsb) & ((1 << (msb - lsb + 1)) - 1)`.
 */
uint8_t IRAM_ATTR rom_i2c_readReg_Mask(uint8_t block, uint8_t host_id, uint8_t reg_add,
                                       uint8_t msb, uint8_t lsb)
{
    uint32_t reg_val = rom_i2c_readReg(block, host_id, reg_add);
    /* Build an unshifted bitmask of (msb - lsb + 1) ones; & 0x1F matches Xtensa shift semantics. */
    uint32_t width = ((uint32_t)msb - (uint32_t)lsb + 1U) & PHY_I2C_BITPOS_MASK;
    uint32_t mask = (1U << width) - 1U;
    return (uint8_t)((reg_val >> ((uint32_t)lsb & PHY_I2C_BITPOS_MASK)) & mask);
}

/**
 * @brief Write an 8-bit value to an internal analog block register over the RF-I2C bus.
 *
 * Placed in `IRAM_ATTR` for cache-disabled execution. Acquires `vPortETSIntrLock()`
 * using the same re-entrancy guard (`g_phy_wakeup_rf_flag` and `s_phy_interrup_flag`)
 * as rom_i2c_readReg().
 *
 * @param block    Internal analog block address (`PHY_I2C_BLOCK_*`, 8-bit).
 * @param host_id  RF-I2C controller host index (`PHY_I2C_HOST_0`..`PHY_I2C_HOST_4`).
 * @param reg_add  Target sub-register offset within @p block (8-bit).
 * @param data     8-bit payload to write.
 */
void IRAM_ATTR rom_i2c_writeReg(uint8_t block, uint8_t host_id, uint8_t reg_add, uint8_t data)
{
    bool locked = (g_phy_wakeup_rf_flag == 0U) && (s_phy_interrup_flag == 0U);
    if (locked) {
        vPortETSIntrLock();
        s_phy_interrup_flag = 1U;
    }

    /* Command word format for write: BIT(24)=1 (write), [23:16]=data, [15:8]=reg_add, [7:0]=block. */
    uint32_t reg_addr = PHY_RF_I2C_HOST_REG((uint32_t)host_id & PHY_I2C_BYTE_MASK);
    PHY_REG_WRITE(reg_addr,
                  PHY_RF_I2C_START |
                  (((uint32_t)data & PHY_I2C_BYTE_MASK) << PHY_I2C_DATA_SHIFT) |
                  (((uint32_t)reg_add & PHY_I2C_BYTE_MASK) << PHY_I2C_REG_SHIFT) |
                  ((uint32_t)block & PHY_I2C_BYTE_MASK));
    for (uint32_t t = 0U;
         (PHY_REG_READ(reg_addr) & PHY_RF_I2C_BUSY) != 0U && t < PHY_I2C_POLL_MAX;
         t++) {
    }

    if (locked) {
        s_phy_interrup_flag = 0U;
        vPortETSIntrUnlock();
    }
}

/**
 * @brief Read-modify-write an inclusive bitfield `[msb:lsb]` in an RF-I2C register.
 *
 * Placed in `IRAM_ATTR`. Performs a read via rom_i2c_readReg(), inserts the masked
 * @p data bits at @p lsb, and writes back via rom_i2c_writeReg().
 *
 * @param block    Internal analog block address (`PHY_I2C_BLOCK_*`, 8-bit).
 * @param host_id  RF-I2C controller host index (`PHY_I2C_HOST_0`..`PHY_I2C_HOST_4`).
 * @param reg_add  Target sub-register offset within @p block (8-bit).
 * @param msb      Most-significant bit index of the field (0..7, inclusive).
 * @param lsb      Least-significant bit index of the field (0..msb, inclusive).
 * @param data     Right-aligned field value to insert into `[msb:lsb]`.
 */
void IRAM_ATTR rom_i2c_writeReg_Mask(uint8_t block, uint8_t host_id, uint8_t reg_add,
                                     uint8_t msb, uint8_t lsb, uint8_t data)
{
    uint32_t reg_val = rom_i2c_readReg(block, host_id, reg_add);
    /* Shift field mask into [msb:lsb], clear target bits, and splice masked data in. */
    uint32_t width = ((uint32_t)msb - (uint32_t)lsb + 1U) & PHY_I2C_BITPOS_MASK;
    uint32_t shift = (uint32_t)lsb & PHY_I2C_BITPOS_MASK;
    uint32_t mask = ((1U << width) - 1U) << shift;
    uint32_t next_val = ((reg_val & ~mask) |
                         ((((uint32_t)data & PHY_I2C_BYTE_MASK) << shift) & mask)) &
                        PHY_I2C_BYTE_MASK;
    rom_i2c_writeReg(block, host_id, reg_add, (uint8_t)next_val);
}

/**
 * @brief Read the free-running 1 MHz (1 us resolution) WDEV MAC hardware timer.
 *
 * Placed in `IRAM_ATTR` for safe invocation from ISRs and cache-disabled paths.
 *
 * @return  Current 32-bit MAC microsecond counter value.
 */
uint32_t IRAM_ATTR phy_get_mactime(void)
{
    return PHY_REG_READ(PHY_WDEV_MAC_TIME_REG);
}

/* --------------------------------------------------------------------------
 * ABI-Locked g_phyFuns Dispatch Table (Flash .rodata + 4 B .data ptr)
 * -------------------------------------------------------------------------- */

static const esp_phy_funs_t s_phy_funs_instance WORD_ALIGNED_ATTR = {
    .rom_i2c_readReg = rom_i2c_readReg,
    .rom_i2c_readReg_Mask = rom_i2c_readReg_Mask,
    .rom_i2c_writeReg = rom_i2c_writeReg,
    .rom_i2c_writeReg_Mask = rom_i2c_writeReg_Mask,
};

const esp_phy_funs_t *g_phyFuns = &s_phy_funs_instance;

/**
 * @brief Compatibility no-op for legacy ROM function-table resolution.
 *
 * Retained for SDK ABI compatibility; `g_phyFuns` is statically initialized to
 * `s_phy_funs_instance` at link time.
 */
void phy_get_romfunc_addr(void)
{
    /* g_phyFuns is statically bound to s_phy_funs_instance. */
}

/* --------------------------------------------------------------------------
 * PBUS Configuration, Readback, Force-Write & Debug/Work Modes
 * -------------------------------------------------------------------------- */

/* Base read-window slot index for each logical PBUS channel 0..7 (13 slots total). */
static const uint8_t s_pbus_rd_base[8] WORD_ALIGNED_ATTR = {
    0U, 2U, 4U, 5U, 7U, 9U, 11U, 12U
};

/**
 * @brief Apply ESP8266 silicon default PBUS timing, bus control, and ADC clock settings.
 *
 * Writes empirical silicon-characterized fields across PBUS configuration, mirror,
 * control, status, and RFPLL control registers during PHY bring-up.
 */
void phy_pbus_soc_cfg(void)
{
    /* Empirical silicon defaults for PBUS timing, bus arbitration, and ADC clock divider. */
    PHY_REG_RMW(PHY_PBUS_CFG_REG,        0x0FE00000U, 0x01800000U);
    PHY_REG_RMW(PHY_PBUS_CFG_MIRROR_REG, 0x0FE00000U, 0x01800000U);
    PHY_REG_RMW(PHY_PBUS_CTRL_REG,       0xE0000000U, 0xC0000000U);
    PHY_REG_RMW(PHY_PBUS_CFG_REG,        0x001FC000U, 0x001F4000U);
    PHY_REG_RMW(PHY_PBUS_STATUS_REG,     0x00FF0000U, 0x00AB0000U);
    PHY_REG_RMW(PHY_RFPLL_CTRL_REG,      0x0000FF00U, 0x00000100U);
    PHY_REG_RMW(PHY_PBUS_CFG_REG,        0x0000007FU, 0x00000047U);
}

/**
 * @brief Read a 9-bit value from the PBUS hardware readback window.
 *
 * @param reg    Logical PBUS channel (`PHY_PBUS_CH_*`, 0..7; masked to 3 bits).
 * @param width  Sub-register selector (`PHY_PBUS_WIDTH_1` = 1, `PHY_PBUS_WIDTH_2` = 2,
 *               or `4` for the third sub-slot).
 * @return       9-bit PBUS register value (`0x000`..`0x1FF`).
 */
uint16_t phy_pbus_rd(uint8_t reg, uint8_t width)
{
    /*
     * Hardware packs 13 logical 9-bit PBUS slots into five 32-bit readback words
     * (3 slots/word, MSB-first: slot%3 == 0 -> [26:18], 1 -> [17:9], 2 -> [8:0]).
     * Channel starting slots come from s_pbus_rd_base[reg & 7]; width selector
     * {1, 2, 4} maps to sub-slot offset {0, 1, 2}. Slot 12 (ch 7, w 1) is the lone
     * entry in word 4 and sits at LSB [8:0] (shift 0) rather than [26:18].
     */
    uint32_t w = (width == PHY_PBUS_WIDTH_4) ? 2U : (uint32_t)((width - 1U) & PHY_I2C_BYTE_MASK);
    uint32_t slot = (w + (uint32_t)s_pbus_rd_base[reg & PHY_PBUS_CH_MASK]) & PHY_I2C_BYTE_MASK;
    uint32_t word = PHY_REG_READ(PHY_PBUS_READ_WINDOW_REG(slot / PHY_PBUS_RD_SLOTS_PER_WORD));
    uint32_t shift = (slot == PHY_PBUS_RD_SLOT_SPECIAL)
                         ? 0U
                         : (PHY_PBUS_RD_TOP_SHIFT -
                            (slot % PHY_PBUS_RD_SLOTS_PER_WORD) * PHY_PBUS_RD_SLOT_BITS);
    return (uint16_t)((word >> shift) & PHY_PBUS_VAL_MASK);
}

/**
 * @brief Force-write a 9-bit payload to a logical PBUS channel in debug/override mode.
 *
 * Strobes `PHY_PBUS_FORCE_STROBE`, polls `PHY_PBUS_BUSY` up to `PHY_PBUS_POLL_MAX`
 * iterations, and deasserts the strobe bit upon completion.
 *
 * @param reg    Logical PBUS channel (`PHY_PBUS_CH_*`, 0..7).
 * @param width  Sub-register selector (`PHY_PBUS_WIDTH_1` = 1 or `PHY_PBUS_WIDTH_2` = 2).
 * @param val    9-bit payload value to write (`0x000`..`0x1FF`).
 */
void phy_pbus_force(uint8_t reg, uint8_t width, uint16_t val)
{
    uint32_t v = (PHY_REG_READ(PHY_PBUS_CTRL_REG) & PHY_PBUS_FORCE_PRESERVE_MASK) |
                 PHY_PBUS_FORCE_STROBE |
                 ((uint32_t)reg << PHY_PBUS_FORCE_REG_SHIFT) |
                 ((uint32_t)val << PHY_PBUS_FORCE_VAL_SHIFT) |
                 ((uint32_t)width << PHY_PBUS_FORCE_WIDTH_SHIFT);
    PHY_REG_WRITE(PHY_PBUS_CTRL_REG, v);
    for (uint32_t t = 0U;
         (PHY_REG_READ(PHY_PBUS_STATUS_REG) & PHY_PBUS_BUSY) != 0U && t < PHY_PBUS_POLL_MAX;
         t++) {
    }
    PHY_REG_CLR(PHY_PBUS_CTRL_REG, PHY_PBUS_FORCE_STROBE);
}

/**
 * @brief Switch PBUS from hardware AGC control into software debug/force-write mode.
 *
 * When transitioning out of normal mode while RF is powered (`PHY_MAC_PHY_RF_UP`),
 * waits for the RX path to settle in idle-RX state before gating baseband RX,
 * asserting `PHY_PBUS_DEBUG_MODE`, and waiting for `PHY_PBUS_READY`.
 */
void phy_pbus_debugmode(void)
{
    if ((PHY_REG_READ(PHY_PBUS_CTRL_REG) & PHY_PBUS_DEBUG_MODE) == 0U &&
        (PHY_REG_READ(PHY_MAC_PHY_CTRL_REG) & PHY_MAC_PHY_RF_UP) != 0U) {
        ets_delay_us(PHY_PBUS_DEBUG_SETTLE_US);
        for (uint32_t t = 0U; t < PHY_PBUS_POLL_MAX; t++) {
            if ((phy_pbus_rd(PHY_PBUS_CH_RX_CTRL, PHY_PBUS_WIDTH_1) & PHY_PBUS_XPD_RX_ON_R2) ==
                    PHY_PBUS_XPD_RX_ON_R2 &&
                (phy_pbus_rd(PHY_PBUS_CH_RXBB_GAIN, PHY_PBUS_WIDTH_2) & PHY_PBUS_XPD_RX_ON_R3_W2) ==
                    PHY_PBUS_XPD_RX_ON_R3_W2) {
                break;
            }
        }
    }
    PHY_REG_SET(PHY_BB_SLEEP_REG, PHY_BB_SLEEP_RX);
    PHY_REG_SET(PHY_PBUS_CTRL_REG, PHY_PBUS_DEBUG_MODE);
    if ((PHY_REG_READ(PHY_MAC_PHY_CTRL_REG) & PHY_MAC_PHY_RF_UP) != 0U) {
        for (uint32_t t = 0U; t < PHY_PBUS_POLL_MAX; t++) {
            if ((PHY_REG_READ(PHY_PBUS_STATUS_REG) & PHY_PBUS_READY) != 0U) {
                break;
            }
        }
    }
}

/**
 * @brief Enter PBUS debug mode configured for TX calibration (RX off, TX on).
 *
 * @param tx_rf_ana_gain  Packed TX gain word; its low 5 bits (`[4:0]`) are applied
 *                        as the initial analog TX gain via phy_pbus_xpd_tx_on().
 */
void phy_pbus_enter_debugmode(uint16_t tx_rf_ana_gain)
{
    phy_pbus_debugmode();
    phy_pbus_xpd_rx_off(1);
    phy_pbus_xpd_tx_on((uint16_t)(tx_rf_ana_gain & PHY_PBUS_TX_ANA_GAIN_MASK));
}

/**
 * @brief Exit PBUS debug mode by powering down TX, restoring RX, and re-enabling AGC.
 */
void phy_pbus_exit_debugmode(void)
{
    phy_pbus_xpd_tx_off();
    phy_pbus_xpd_rx_on();
    phy_pbus_workmode();
}

/**
 * @brief Return PBUS to normal hardware AGC work mode and ungate RX baseband.
 */
void phy_pbus_workmode(void)
{
    PHY_REG_CLR(PHY_PBUS_CTRL_REG, PHY_PBUS_DEBUG_MODE);
    PHY_REG_CLR(PHY_BB_SLEEP_REG, PHY_BB_SLEEP_RX);
}

/**
 * @brief Power down the analog TX PA and TX bias stages over PBUS.
 */
void phy_pbus_xpd_tx_off(void)
{
    phy_pbus_force(PHY_PBUS_CH_PA_EN, PHY_PBUS_WIDTH_1, 0U);
    phy_pbus_force(PHY_PBUS_CH_TXEN_DCO_Q, PHY_PBUS_WIDTH_1, PHY_PBUS_XPD_TX_OFF_R1);
    phy_pbus_force(PHY_PBUS_CH_RX_CTRL, PHY_PBUS_WIDTH_1, PHY_PBUS_XPD_TX_OFF_R2);
}

/**
 * @brief Power up the analog TX chain over PBUS with the given RF and analog gain.
 *
 * @param rf_ana_gain  Packed TX gain: bits `[4:0]` = TXBB analog gain (ch 0),
 *                     bits `[15:5]` = RF PA gain stage (ch 7).
 */
void phy_pbus_xpd_tx_on(uint16_t rf_ana_gain)
{
    phy_pbus_force(PHY_PBUS_CH_RX_CTRL, PHY_PBUS_WIDTH_1, PHY_PBUS_XPD_TX_ON_R2);
    phy_pbus_force(PHY_PBUS_CH_RF_GAIN, PHY_PBUS_WIDTH_1,
                   (uint16_t)(rf_ana_gain >> PHY_PBUS_TX_RF_GAIN_SHIFT));
    phy_pbus_force(PHY_PBUS_CH_TXBB_DCO_I, PHY_PBUS_WIDTH_1,
                   (uint16_t)(rf_ana_gain & PHY_PBUS_TX_ANA_GAIN_MASK));
    phy_pbus_force(PHY_PBUS_CH_TXEN_DCO_Q, PHY_PBUS_WIDTH_1, PHY_PBUS_XPD_TX_ON_R1);
    phy_pbus_force(PHY_PBUS_CH_PA_EN, PHY_PBUS_WIDTH_1, PHY_PBUS_XPD_TX_ON_R6);
}

/**
 * @brief Power up the analog RX front-end and RXBB stages over PBUS.
 */
void phy_pbus_xpd_rx_on(void)
{
    phy_pbus_force(PHY_PBUS_CH_RX_CTRL, PHY_PBUS_WIDTH_1, PHY_PBUS_XPD_RX_ON_R2);
    phy_pbus_force(PHY_PBUS_CH_RXBB_GAIN, PHY_PBUS_WIDTH_2, PHY_PBUS_XPD_RX_ON_R3_W2);
}

/**
 * @brief Power down the analog RX front-end and zero RXBB gain stages over PBUS.
 *
 * @param reg2_val  Signed offset added to the base RX-off bias (`0x80`) written to
 *                  PBUS channel 2 (`PHY_PBUS_CH_RX_CTRL`, width 1); typically `0` or `1`.
 */
void phy_pbus_xpd_rx_off(int16_t reg2_val)
{
    phy_pbus_force(PHY_PBUS_CH_RX_CTRL, PHY_PBUS_WIDTH_1,
                   (uint16_t)(reg2_val + PHY_PBUS_XPD_RX_OFF_BASE));
    phy_pbus_force(PHY_PBUS_CH_RXBB_GAIN, PHY_PBUS_WIDTH_1, 0U);
    phy_pbus_force(PHY_PBUS_CH_RXBB_GAIN, PHY_PBUS_WIDTH_2, 0U);
}

/**
 * @brief Swizzle and write a 9-bit TX gain word to PBUS channel 4.
 *
 * @param gain  Logical 9-bit TX gain: `[4:0]` = fine/BB, `[6:5]` = mid, `[8:7]` = coarse.
 */
void phy_pbus_set_txgain(uint16_t gain)
{
    /* Hardware PBUS ch4 w1 bit order: [8:4]=gain[4:0], [3:2]=gain[6:5], [1:0]=gain[8:7]. */
    uint16_t packed = (uint16_t)(((gain & PHY_PBUS_TX_ANA_GAIN_MASK) << 4) |
                                 (((gain >> 5) & 3U) << 2) |
                                 ((gain >> 7) & 3U));
    phy_pbus_force(PHY_PBUS_CH_TXGAIN_RXDCO_I, PHY_PBUS_WIDTH_1, packed);
}

/**
 * @brief Swizzle and apply a 15-bit packed RX gain code across PBUS channels 2 and 3.
 *
 * @param gain  15-bit packed RX gain word:
 *              - `[2:0]`: RXBB fine gain (placed at ch3 w2 `[5:3]`)
 *              - `[9:3]`: 7-bit RXBB coarse code (bit-reversed into ch3 w1 `[0:6]`)
 *              - `[10]`: RX attenuator/stage bit (placed at ch2 w1 `[1]`)
 *              - `[14:11]`: 4-bit LNA/RF stage gain (placed at ch2 w1 `[6:3]`)
 */
void phy_pbus_set_rxgain(uint16_t gain)
{
    uint32_t g = (uint32_t)gain;
    /* Bit-reverse g[9:3] into ch3 w1 bits [0:6] to match the analog RXBB switch wiring. */
    uint16_t r3_w1 = (uint16_t)((((g >> 3) & 1U) << 6) |
                                (((g >> 4) & 1U) << 5) |
                                (((g >> 5) & 1U) << 4) |
                                (((g >> 6) & 1U) << 3) |
                                (((g >> 7) & 1U) << 2) |
                                (((g >> 8) & 1U) << 1) |
                                ((g >> 9) & 1U));
    /* Preserve non-gain control bits in ch3 w2 (0x1C7) and ch2 w1 (0x185) via readback. */
    uint16_t r3_w2 = (uint16_t)((phy_pbus_rd(PHY_PBUS_CH_RXBB_GAIN, PHY_PBUS_WIDTH_2) &
                                 PHY_PBUS_RXGAIN_R3_W2_KEEP) |
                                ((g & 7U) << 3));
    uint16_t r2_w1 = (uint16_t)((phy_pbus_rd(PHY_PBUS_CH_RX_CTRL, PHY_PBUS_WIDTH_1) &
                                 PHY_PBUS_RXGAIN_R2_W1_KEEP) |
                                (((g >> 11) & 0x0FU) << 3) |
                                (((g >> 10) & 1U) << 1));
    phy_pbus_force(PHY_PBUS_CH_RXBB_GAIN, PHY_PBUS_WIDTH_1, r3_w1);
    phy_pbus_force(PHY_PBUS_CH_RXBB_GAIN, PHY_PBUS_WIDTH_2, r3_w2);
    phy_pbus_force(PHY_PBUS_CH_RX_CTRL, PHY_PBUS_WIDTH_1, r2_w1);
}

/**
 * @brief Program RX baseband gain in dB onto PBUS channel 3 (coarse + fine stages).
 *
 * Splits @p bbgain into a 6 dB thermometer-coded coarse stage (`0, 6, 12, 18, >=24 dB`)
 * on ch3 w1 and a `0..5 dB` fine remainder (`bbgain % 6`) on ch3 w2 `[5:3]` with RXBB
 * enable bits (`0x06`) asserted.
 *
 * @param bbgain  Requested RX baseband gain in dB (typically `0..29`).
 */
void phy_pbus_set_rxbbgain(int16_t bbgain)
{
    /* 6 dB/step thermometer encoding for the 4 coarse RXBB gain switches in ch3 w1. */
    uint16_t coarse;
    if (bbgain >= (4 * PHY_PBUS_RXBB_STEP_DB)) {
        coarse = PHY_PBUS_RXBB_COARSE_24DB;
    } else if (bbgain >= (3 * PHY_PBUS_RXBB_STEP_DB)) {
        coarse = PHY_PBUS_RXBB_COARSE_18DB;
    } else if (bbgain >= (2 * PHY_PBUS_RXBB_STEP_DB)) {
        coarse = PHY_PBUS_RXBB_COARSE_12DB;
    } else if (bbgain >= PHY_PBUS_RXBB_STEP_DB) {
        coarse = PHY_PBUS_RXBB_COARSE_6DB;
    } else {
        coarse = PHY_PBUS_RXBB_COARSE_0DB;
    }
    phy_pbus_force(PHY_PBUS_CH_RXBB_GAIN, PHY_PBUS_WIDTH_1, coarse);
    int32_t fine = (int32_t)bbgain % PHY_PBUS_RXBB_STEP_DB;
    phy_pbus_force(PHY_PBUS_CH_RXBB_GAIN, PHY_PBUS_WIDTH_2,
                   (uint16_t)(((uint32_t)fine << 3) | PHY_PBUS_XPD_RX_ON_R3_W2));
}

/* --------------------------------------------------------------------------
 * Analog Interface, Clocks, Loopback, DPD & SAR/Power-Detector Helpers
 * -------------------------------------------------------------------------- */

/**
 * @brief Enable or disable the analog TX path clocks in ANA_INF and ANA_CLK.
 *
 * @param en  `1` to enable TX analog clocks, `0` to gate them off.
 */
void phy_set_txclk_en(uint8_t en)
{
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_CLK_GATE_REG,
                          PHY_I2C_ANA_INF_TXCLK_BIT, PHY_I2C_ANA_INF_TXCLK_BIT, en);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_CLK, PHY_I2C_HOST_1, PHY_I2C_ANA_CLK_PATH_REG,
                          PHY_I2C_ANA_CLK_TX_BIT, PHY_I2C_ANA_CLK_TX_BIT, en);
}

/**
 * @brief Enable or disable the analog RX path clocks in ANA_INF and ANA_CLK.
 *
 * @param en  `1` to enable RX analog clocks, `0` to gate them off.
 */
void phy_set_rxclk_en(uint8_t en)
{
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_CLK_GATE_REG,
                          PHY_I2C_ANA_INF_RXCLK_BIT, PHY_I2C_ANA_INF_RXCLK_BIT, en);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_CLK, PHY_I2C_HOST_1, PHY_I2C_ANA_CLK_PATH_REG,
                          PHY_I2C_ANA_CLK_RX_BIT, PHY_I2C_ANA_CLK_RX_BIT, en);
}

/**
 * @brief Clamp a TX baseband attenuation code to 6 bits and push overflow into ANA_INF TX scale.
 *
 * When @p val exceeds `0x3F`, writes the negative excess `(0x3F - val)` as an 8-bit
 * two's-complement trim to `PHY_I2C_ANA_INF_TX_SCALE_REG` and returns `0x3F`.
 * Otherwise resets the trim register to `0` and returns @p val unchanged.
 *
 * @param val  Requested TX baseband attenuation code (`0..255`).
 * @return     Clamped 6-bit attenuation value (`0..0x3F`).
 */
uint8_t phy_set_ana_inf_tx_scale(uint8_t val)
{
    uint8_t scale = 0U;
    if (val > PHY_ANA_INF_TX_SCALE_MAX) {
        scale = (uint8_t)((PHY_ANA_INF_TX_SCALE_MAX - (uint32_t)val) & PHY_I2C_BYTE_MASK);
        val = PHY_ANA_INF_TX_SCALE_MAX;
    }
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_TX_SCALE_REG,
                          7U, 0U, scale);
    return val;
}

/**
 * @brief Configure or disable analog-interface clock gating / fractional sample-rate divider.
 *
 * When enabling (`en != 0`), resets the gating logic via a 4-step empirical pulse
 * sequence on `PHY_I2C_ANA_INF_RXIQ_P_REG` and loads the 20-bit integer and 20-bit
 * fractional divider values across ANA_INF sub-registers `0x00..0x04`.
 *
 * @param en        `1` to enable gating/divider, `0` to bypass/disable.
 * @param int_div   20-bit integer divider value (used only when @p en != 0).
 * @param frac_div  20-bit fractional divider value (used only when @p en != 0).
 */
void phy_ana_inf_gating_en(uint8_t en, uint32_t int_div, uint32_t frac_div)
{
    if (en != 0U) {
        rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_CLK_GATE_REG,
                              PHY_I2C_ANA_INF_GATING_BIT, PHY_I2C_ANA_INF_GATING_BIT, 0U);
        /* Empirical silicon reset strobe sequence for ANA_INF gating state machine. */
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_RXIQ_P_REG, 0x28U);
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_RXIQ_P_REG, 0x38U);
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_RXIQ_P_REG, 0x18U);
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_RXIQ_P_REG, 0x38U);
        /* Pack 20-bit int_div and 20-bit frac_div into 5 contiguous bytes (reg 0x02 shares nibbles). */
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_DIV_REG0,
                         (uint8_t)((int_div >> 12) & PHY_I2C_BYTE_MASK));
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_DIV_REG1,
                         (uint8_t)((int_div >> 4) & PHY_I2C_BYTE_MASK));
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_DIV_REG4,
                         (uint8_t)(frac_div & PHY_I2C_BYTE_MASK));
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_DIV_REG3,
                         (uint8_t)((frac_div >> 8) & PHY_I2C_BYTE_MASK));
        rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_DIV_REG2,
                         (uint8_t)((((frac_div >> 16) & 0x0FU) << 4) | (int_div & 0x0FU)));
    }
    uint8_t inv = (uint8_t)(en ^ 1U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_DPD_TXIQ_P_REG,
                          PHY_I2C_ANA_INF_DPD_GATE_BIT, PHY_I2C_ANA_INF_DPD_GATE_BIT, inv);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_RXIQ_SIGN_REG,
                          PHY_I2C_ANA_INF_RXIQ_GATE_BIT, PHY_I2C_ANA_INF_RXIQ_GATE_BIT, inv);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_CLK_GATE_REG,
                          PHY_I2C_ANA_INF_GATING_BIT, PHY_I2C_ANA_INF_GATING_BIT, en);
}

/**
 * @brief Configure PBUS gains for internal RF TX-to-RX loopback calibration.
 *
 * @param pa_gain   9-bit PA gain written to PBUS ch 7 (`PHY_PBUS_CH_RF_GAIN`, w 1).
 * @param pbus_r2   9-bit RX control / LNA gain written to PBUS ch 2 (`PHY_PBUS_CH_RX_CTRL`, w 1).
 * @param pbus_r3_1 9-bit RXBB coarse gain written to PBUS ch 3 (`PHY_PBUS_CH_RXBB_GAIN`, w 1).
 * @param pbus_r3_2 9-bit RXBB fine gain + enable written to PBUS ch 3 (`PHY_PBUS_CH_RXBB_GAIN`, w 2).
 */
void phy_set_loopback_gain(uint16_t pa_gain, uint16_t pbus_r2,
                           uint16_t pbus_r3_1, uint16_t pbus_r3_2)
{
    phy_pbus_force(PHY_PBUS_CH_RX_CTRL, PHY_PBUS_WIDTH_1, PHY_PBUS_LOOPBACK_R2_INIT);
    phy_pbus_force(PHY_PBUS_CH_RF_GAIN, PHY_PBUS_WIDTH_1, pa_gain);
    phy_pbus_force(PHY_PBUS_CH_RX_CTRL, PHY_PBUS_WIDTH_1, pbus_r2);
    phy_pbus_force(PHY_PBUS_CH_RXBB_GAIN, PHY_PBUS_WIDTH_1, pbus_r3_1);
    phy_pbus_force(PHY_PBUS_CH_RXBB_GAIN, PHY_PBUS_WIDTH_2, pbus_r3_2);
}

/**
 * @brief Bypass the analog-interface digital pre-distortion (DPD) block.
 */
void phy_dpd_bypass(void)
{
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_DPD_TXIQ_P_REG,
                          PHY_I2C_ANA_INF_DPD_BYP_BIT, PHY_I2C_ANA_INF_DPD_BYP_BIT, 1U);
}

#ifdef CONFIG_ESP8266_OSS_PHY_WIFI
/**
 * @brief Program the ANA_INF DPD scale attenuation from TXPWR slot 23 and `dpd_atten_off`.
 */
void phy_dpd_scale_set(void)
{
    uint32_t txpwr23 = PHY_REG_READ(PHY_RF_TXPWR_REG(PHY_DPD_TXPWR_REF_SLOT));
    uint32_t off = (uint32_t)(uint8_t)g_phy_sleep_params.dpd_atten_off;
    uint8_t scale = (uint8_t)((0U - PHY_DPD_SCALE_BIAS - (txpwr23 + off)) & PHY_I2C_BYTE_MASK);
    rom_i2c_writeReg(PHY_I2C_BLOCK_ANA_INF, PHY_I2C_HOST_0, PHY_I2C_ANA_INF_DPD_SCALE_REG, scale);
}
#endif

/**
 * @brief Power up the SAR ADC analog rail and apply its RF-I2C initialization defaults.
 */
void phy_sar_init(void)
{
    PHY_REG_SET(PHY_RTC_RF_PWR_REG, PHY_RTC_RF_PWR_SAR_BIT);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, PHY_I2C_SAR_CTRL_REG,
                          PHY_I2C_SAR_INIT_BIT, PHY_I2C_SAR_INIT_BIT, 1U);
    rom_i2c_writeReg_Mask(PHY_I2C_BLOCK_SAR, PHY_I2C_HOST_2, PHY_I2C_SAR_CFG_REG,
                          1U, 0U, PHY_I2C_SAR_CFG_DEFAULT);
}

/**
 * @brief Enable or disable the SAR TX power-detector auto-trigger path.
 *
 * Ensures SAR is powered and disconnects external TOUT and VDD33 mux inputs so the
 * SAR samples the internal RF power detector.
 *
 * @param en  Non-zero to enable power-detector capture, `0` to disable.
 */
void phy_en_pwdet(uint8_t en)
{
    phy_sar_init();
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_TOUT_EN);
    PHY_REG_CLR(PHY_SAR_MUX_CTRL_REG, PHY_SAR_MUX_VDD33_EN);
    if (en != 0U) {
        PHY_REG_SET(PHY_SAR_CTRL_REG, PHY_SAR_CTRL_PWDET_EN);
    } else {
        PHY_REG_CLR(PHY_SAR_CTRL_REG, PHY_SAR_CTRL_PWDET_EN);
    }
}

/* --------------------------------------------------------------------------
 * IQ Estimator, TX Test Tones & Pure-Integer dB Conversion
 * -------------------------------------------------------------------------- */

/**
 * @brief Start the hardware IQ/DC estimator and block until sample accumulation finishes.
 *
 * @param mode     Estimator mode bit placed at `PHY_FE_IQ_EST_MODE_SHIFT` (`0` = TX/corr,
 *                 `1` = RX IQ/DC).
 * @param samples  15-bit hardware sample-count code (`samples + 1` samples accumulated).
 */
void phy_iq_est_enable(uint8_t mode, uint16_t samples)
{
    PHY_REG_SET(PHY_FE_IQ_EST_CTRL_REG, PHY_FE_IQ_EST_EN);
    PHY_REG_RMW(PHY_FE_IQ_EST_CTRL_REG, PHY_FE_IQ_EST_CFG_MASK,
                PHY_FE_IQ_EST_START |
                ((uint32_t)mode << PHY_FE_IQ_EST_MODE_SHIFT) |
                (((uint32_t)samples & PHY_FE_IQ_EST_SAMPLES_MASK) << PHY_FE_IQ_EST_SAMPLES_SHIFT));
    /* Bit 31 of PHY_FE_IQ_EST_CTRL_REG goes high (negative signed int32) when complete. */
    for (uint32_t t = 0U;
         (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_CTRL_REG) >= 0 && t < PHY_IQ_EST_POLL_MAX;
         t++) {
    }
}

/**
 * @brief Reset the hardware IQ/DC estimator configuration and power down the estimator block.
 */
void phy_iq_est_disable(void)
{
    PHY_REG_RMW(PHY_FE_IQ_EST_CTRL_REG, PHY_FE_IQ_EST_CFG_MASK, PHY_FE_IQ_EST_DISABLE_VAL);
    PHY_REG_CLR(PHY_FE_IQ_EST_CTRL_REG, PHY_FE_IQ_EST_EN);
}

/**
 * @brief Measure mean I and Q DC offsets using the hardware IQ estimator.
 *
 * @param mode     Estimator mode (`0` = TX/corr, `1` = RX IQ/DC).
 * @param samples  15-bit hardware sample-count code (`samples + 1` samples averaged).
 * @param out_iq   Output array receiving `[0]` = mean I DC offset, `[1]` = mean Q DC offset.
 */
void phy_dc_iq_est(uint8_t mode, uint16_t samples, int32_t out_iq[2])
{
    phy_iq_est_enable(mode, samples);
    int32_t denom = (int32_t)samples + 1;
    out_iq[0] = ((int32_t)PHY_REG_READ(PHY_FE_IQ_EST_DC_I_REG) >> PHY_IQ_DC_SHIFT) / denom;
    out_iq[1] = ((int32_t)PHY_REG_READ(PHY_FE_IQ_EST_DC_Q_REG) >> PHY_IQ_DC_SHIFT) / denom;
    phy_iq_est_disable();
}

/**
 * @brief Read and scale total, coherent-correlator, and DC powers from the IQ estimator.
 *
 * Expects phy_iq_est_enable() to have just completed a capture.
 *
 * @param out_pwr  Output array receiving:
 *                 - `out_pwr[0]`: scaled total signal power
 *                 - `out_pwr[1]`: squared complex correlation power `|re + j*im|^2`
 *                 - `out_pwr[2]`: squared DC power `(dc_i^2 + dc_q^2) >> 16`
 * @param shift    Log2 sample-length scaling parameter (typically `11..15`).
 */
void phy_get_corr_power(int32_t out_pwr[3], uint8_t shift)
{
    /*
     * Shift the 32-bit signed II/IQ/QI/QQ correlator accumulators down by 18 bits
     * before combining into complex correlation (re = II + QQ, im = IQ - QI) so
     * re^2 + im^2 fits in signed 32-bit arithmetic; scale DC/total power by (shift - 2)
     * and the squared correlation by 2 * (shift - 11).
     */
    int32_t acc0 = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_ACC_REG(0U)) >> PHY_CORR_ACC_SHIFT;
    int32_t acc1 = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_ACC_REG(1U)) >> PHY_CORR_ACC_SHIFT;
    int32_t acc2 = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_ACC_REG(2U)) >> PHY_CORR_ACC_SHIFT;
    int32_t acc3 = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_ACC_REG(3U)) >> PHY_CORR_ACC_SHIFT;

    uint32_t sh = ((uint32_t)shift - PHY_CORR_DC_SHIFT_BIAS) & PHY_I2C_BITPOS_MASK;
    int32_t dc_i = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_DC_I_REG) >> sh;
    int32_t dc_q = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_DC_Q_REG) >> sh;
    int32_t tot_pwr = (int32_t)PHY_REG_READ(PHY_FE_IQ_EST_PWR_REG) >> sh;

    int32_t re = acc0 + acc3;
    int32_t im = acc1 - acc2;
    uint32_t corr_sh = (((uint32_t)shift - PHY_CORR_PWR_SHIFT_BIAS) * 2U) & PHY_I2C_BITPOS_MASK;

    out_pwr[0] = tot_pwr;
    out_pwr[1] = (re * re + im * im) >> corr_sh;
    out_pwr[2] = (dc_i * dc_i + dc_q * dc_q) >> PHY_CORR_DC_SQ_SHIFT;
}

/**
 * @brief Enable up to three hardware DDS TX calibration test tones.
 *
 * Enables analog TX clocks via phy_set_txclk_en(1) and programs each requested DDS
 * tone register with its 10-bit signed frequency code and negated 8-bit attenuation.
 *
 * @param en1     Non-zero to enable tone generator 1.
 * @param freq1   Signed 10-bit DDS frequency code for tone 1.
 * @param atten1  Unsigned attenuation magnitude for tone 1 (negated in hardware).
 * @param en2     Non-zero to enable tone generator 2.
 * @param freq2   Signed 10-bit DDS frequency code for tone 2.
 * @param atten2  Unsigned attenuation magnitude for tone 2 (negated in hardware).
 * @param en3     Non-zero to enable tone generator 3 (also sets auxiliary enable bit 28).
 * @param freq3   Signed 10-bit DDS frequency code for tone 3.
 * @param atten3  Unsigned attenuation magnitude for tone 3 (negated in hardware).
 */
void phy_start_tx_tone(uint8_t en1, int16_t freq1, uint8_t atten1,
                       uint8_t en2, int16_t freq2, uint8_t atten2,
                       uint8_t en3, int16_t freq3, uint8_t atten3)
{
    phy_set_txclk_en(1U);

    if (en1 != 0U) {
        uint32_t att = (0U - (uint32_t)atten1) & PHY_I2C_BYTE_MASK;
        PHY_REG_RMW(PHY_FE_TX_TONE_1_REG, PHY_FE_TX_TONE_CFG_MASK,
                    PHY_FE_TX_TONE_EN | (att << PHY_FE_TX_TONE_ATTEN_SHIFT) |
                    ((uint32_t)(uint16_t)freq1 & PHY_FE_TX_TONE_FREQ_MASK));
    }
    if (en2 != 0U) {
        uint32_t att = (0U - (uint32_t)atten2) & PHY_I2C_BYTE_MASK;
        PHY_REG_RMW(PHY_FE_TX_TONE_2_REG, PHY_FE_TX_TONE_CFG_MASK,
                    PHY_FE_TX_TONE_EN | (att << PHY_FE_TX_TONE_ATTEN_SHIFT) |
                    ((uint32_t)(uint16_t)freq2 & PHY_FE_TX_TONE_FREQ_MASK));
    }
    if (en3 != 0U) {
        uint32_t att = (0U - (uint32_t)atten3) & PHY_I2C_BYTE_MASK;
        PHY_REG_RMW(PHY_FE_TX_TONE_3_REG, PHY_FE_TX_TONE3_CFG_MASK,
                    PHY_FE_TX_TONE3_EN_BITS | (att << PHY_FE_TX_TONE_ATTEN_SHIFT) |
                    ((uint32_t)(uint16_t)freq3 & PHY_FE_TX_TONE_FREQ_MASK));
    }
}

/**
 * @brief Stop one or all hardware DDS TX calibration test tones and gate off TX clocks.
 *
 * @param tone_idx  Tone generator index (`1`, `2`, `3`) to disable individually,
 *                  or any other value (e.g. `0`) to disable all three tones.
 */
void phy_stop_tx_tone(uint8_t tone_idx)
{
    if (tone_idx == 1U) {
        PHY_REG_CLR(PHY_FE_TX_TONE_1_REG, PHY_FE_TX_TONE_EN);
    } else if (tone_idx == 2U) {
        PHY_REG_CLR(PHY_FE_TX_TONE_2_REG, PHY_FE_TX_TONE_EN);
    } else if (tone_idx == 3U) {
        PHY_REG_CLR(PHY_FE_TX_TONE_3_REG, PHY_FE_TX_TONE_EN);
    } else {
        PHY_REG_CLR(PHY_FE_TX_TONE_1_REG, PHY_FE_TX_TONE_EN);
        PHY_REG_CLR(PHY_FE_TX_TONE_2_REG, PHY_FE_TX_TONE_EN);
        PHY_REG_CLR(PHY_FE_TX_TONE_3_REG, PHY_FE_TX_TONE_EN);
    }
    phy_set_txclk_en(0U);
}

/**
 * @brief Accumulate normalized linear TX-tone power ratios from the FM SAR detector.
 *
 * Repeatedly reads paired SAR detector outputs `(out1, out2)` via phy_get_fm_sar_dout(),
 * clamping a zero denominator to `1`, and sums `(out1 << shift) / out2` in a wrapping
 * 16-bit signed accumulator.
 *
 * @param avg_cnt  Number of SAR measurement pairs to accumulate.
 * @param shift    Left-shift scaling factor applied to numerator `out1` (0..31).
 * @return         Sign-extended 16-bit accumulated linear power ratio.
 */
int32_t phy_txtone_linear_pwr(uint8_t avg_cnt, uint8_t shift)
{
    int16_t acc = 0;
    uint32_t sh = (uint32_t)shift & PHY_I2C_BITPOS_MASK;

    for (uint8_t i = 0U; i < avg_cnt; i++) {
        int16_t out1 = 0;
        int16_t out2 = 0;
        phy_get_fm_sar_dout(&out1, &out2);
        if (out2 == 0) {
            out2 = 1;
        }
        int32_t num = (int32_t)((uint32_t)(int32_t)out1 << sh);
        acc = (int16_t)(acc + (num / (int32_t)out2));
    }
    return (int32_t)acc;
}

/* Fractional octave LUT: round(20 * log10(1 + idx / 16) / 0.125) in 0.125 dB units. */
static const uint8_t s_linear_to_db_lut[16] WORD_ALIGNED_ATTR = {
    0U, 4U, 8U, 12U, 16U, 19U, 22U, 25U,
    28U, 31U, 34U, 36U, 39U, 41U, 44U, 46U
};

/**
 * @brief Convert a scaled linear magnitude to dB (0.125 dB units) via CLZ log2 approximation.
 *
 * @param val    Input signed linear magnitude.
 * @param shift  Input right-shift exponent relative to the internal Q3 normalization
 *               (`shift < 3` shifts left by `3 - shift`; `shift >= 3` shifts right by `shift - 3`).
 * @return       Approximate `20 * log10(scaled)` in 0.125 dB units (signed 16-bit range).
 */
int32_t phy_linear_to_db(int32_t val, uint8_t shift)
{
    /* Normalize input to the reference Q3 scale before extracting log2(u). */
    int32_t scaled;
    if (shift < PHY_DB_SCALE_REF_SHIFT) {
        scaled = (int32_t)((uint32_t)val << (PHY_DB_SCALE_REF_SHIFT - shift));
    } else {
        scaled = val >> (((uint32_t)shift - PHY_DB_SCALE_REF_SHIFT) & PHY_I2C_BITPOS_MASK);
    }

    /*
     * Decompose scaled = 2^(exp + 3) * (1 + idx / 16) using count-leading-zeros:
     *   - exp = 28 - clz(u) counts octaves above the 4-bit base range [0..15]
     *   - idx = 4 fractional bits immediately below the MSB (or u[3:0] when u < 16)
     *   - dB (0.125 dB/LSB) = lut[idx] + exp * 48  (48 * 0.125 = 6.0 dB/octave)
     */
    uint32_t u = (uint32_t)scaled;
    uint32_t lz = (u == 0U) ? 32U : (uint32_t)__builtin_clz(u);
    int8_t exp = (int8_t)(PHY_DB_EXP_BIAS - (int32_t)lz);
    uint32_t idx;

    if (exp < 1) {
        exp = 0;
        idx = u & PHY_DB_MANTISSA_MASK;
    } else {
        idx = (uint32_t)(scaled >> (exp - 1)) & PHY_DB_MANTISSA_MASK;
    }

    int16_t db = (int16_t)((int32_t)s_linear_to_db_lut[idx] + (int32_t)exp * PHY_DB_OCTAVE_STEPS);
    return (int32_t)db;
}

/* --------------------------------------------------------------------------
 * Channel Mapping, CCA & Chip-v5 TX Analog Defaults
 * -------------------------------------------------------------------------- */

/**
 * @brief Convert a 2.4 GHz (or extended 2.5 GHz) center frequency in MHz to an IEEE channel number.
 *
 * @param freq_mhz  Channel center frequency in MHz (`2412..2472`, `2484`, or `>= 2512`).
 * @param flags     Band flag bitmask; bit 7 (`0x80`) permits extended 2.5 GHz channels (15+).
 * @return          IEEE channel number (`1..14`, `15+` with bit 7 set), or `0xFF` if invalid.
 */
uint8_t phy_mhz2ieee(uint16_t freq_mhz, uint8_t flags)
{
    if (freq_mhz == PHY_IEEE_CH14_FREQ_MHZ) {
        return PHY_IEEE_CH14_NUM;
    }
    if (freq_mhz > PHY_IEEE_ISM_MAX_MHZ) {
        if ((flags & PHY_IEEE_FLAG_EXT_2GHZ) == 0U) {
            return PHY_IEEE_CHAN_INVALID;
        }
        return (uint8_t)((((int32_t)freq_mhz - PHY_IEEE_EXT_BASE_MHZ) / PHY_IEEE_EXT_STEP_MHZ) +
                         PHY_IEEE_EXT_CHAN_BASE);
    }
    return (uint8_t)(((int32_t)freq_mhz - PHY_IEEE_ISM_BASE_MHZ) / PHY_IEEE_ISM_STEP_MHZ);
}

/**
 * @brief Enable hardware AGC and Clear Channel Assessment (CCA) in the baseband.
 */
void phy_chip_v5_enable_cca(void)
{
    PHY_REG_CLR(PHY_BB_AGC_CTRL_REG, PHY_BB_AGC_OFF);
}

/**
 * @brief Disable hardware AGC and Clear Channel Assessment (CCA) in the baseband.
 */
void phy_chip_v5_disable_cca(void)
{
    PHY_REG_SET(PHY_BB_AGC_CTRL_REG, PHY_BB_AGC_OFF);
}

/**
 * @brief Program RX sensitivity backoff into the baseband sense and AGC threshold registers.
 *
 * Treats @p backoff as a signed 7-bit magnitude: negative values (bit 7 set) saturate
 * both 7-bit hardware fields to `0x7F` (all-ones mask).
 *
 * @param backoff  Signed 8-bit sensitivity backoff (`0..127` written verbatim; `< 0` saturates).
 */
void phy_chip_v5_sense_backoff(uint8_t backoff)
{
    int8_t s = (int8_t)backoff;
    uint32_t v1 = (s < 0)
                      ? PHY_BB_SENSE_BACKOFF_MASK
                      : ((uint32_t)backoff << PHY_BB_SENSE_BACKOFF_SHIFT);
    PHY_REG_RMW(PHY_BB_SENSE_BACKOFF_REG, PHY_BB_SENSE_BACKOFF_MASK, v1);

    uint32_t v2 = (s < 0)
                      ? PHY_BB_AGC_THR_9D24_MASK
                      : ((uint32_t)backoff << PHY_BB_AGC_THR_9D24_SHIFT);
    PHY_REG_RMW(PHY_BB_AGC_THR_9D24_REG, PHY_BB_AGC_THR_9D24_MASK, v2);
}

/* Empirical ESP8266 silicon TX PA analog initialization defaults (TX_PA sub-regs 1..11). */
static const uint8_t s_chip_v5_tx_init_vals[PHY_CHIP_V5_TX_INIT_REG_COUNT] WORD_ALIGNED_ATTR = {
    0x68U, 0x0FU, 0xA8U, 0x06U, 0x08U, 0xB8U, 0x5BU, 0x04U, 0x00U, 0x74U, 0x07U
};

/**
 * @brief Load silicon-default TX PA bias and capacitor trim registers over RF-I2C.
 *
 * Writes `s_chip_v5_tx_init_vals[0..10]` sequentially to `PHY_I2C_BLOCK_TX_PA`
 * sub-registers `1..11` on `PHY_I2C_HOST_2`.
 */
void phy_chip_v5_tx_init(void)
{
    for (uint8_t reg = 1U; reg <= PHY_CHIP_V5_TX_INIT_REG_COUNT; reg++) {
        rom_i2c_writeReg(PHY_I2C_BLOCK_TX_PA, PHY_I2C_HOST_2, reg,
                         s_chip_v5_tx_init_vals[reg - 1U]);
    }
}
