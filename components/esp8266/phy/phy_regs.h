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
// Register addresses and bitfield constants adapted in part from teatime-os:
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

#pragma once

#include <stdint.h>
#include "esp8266/eagle_soc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Typed Volatile MMIO Helpers (Xtensa memw-ordered via REG_READ / REG_WRITE)
 * -------------------------------------------------------------------------- */

/**
 * @brief Read a 32-bit PHY/RF/RTC/DPORT MMIO register with Xtensa memw ordering.
 *
 * @param reg  Byte address of the 32-bit hardware register.
 * @return     Current 32-bit register value.
 */
static inline uint32_t PHY_REG_READ(uint32_t reg)
{
    return REG_READ(reg);
}

/**
 * @brief Write a 32-bit PHY/RF/RTC/DPORT MMIO register with Xtensa memw ordering.
 *
 * @param reg  Byte address of the 32-bit hardware register.
 * @param val  32-bit value to write.
 */
static inline void PHY_REG_WRITE(uint32_t reg, uint32_t val)
{
    REG_WRITE(reg, val);
}

/**
 * @brief Set one or more bits in a 32-bit MMIO register (read-modify-write OR).
 *
 * @param reg   Byte address of the 32-bit hardware register.
 * @param mask  Bitmask of bits to set to 1.
 */
static inline void PHY_REG_SET(uint32_t reg, uint32_t mask)
{
    REG_WRITE(reg, REG_READ(reg) | mask);
}

/**
 * @brief Clear one or more bits in a 32-bit MMIO register (read-modify-write AND-NOT).
 *
 * @param reg   Byte address of the 32-bit hardware register.
 * @param mask  Bitmask of bits to clear to 0.
 */
static inline void PHY_REG_CLR(uint32_t reg, uint32_t mask)
{
    REG_WRITE(reg, REG_READ(reg) & ~mask);
}

/**
 * @brief Update a bitfield in a 32-bit MMIO register by clearing clear_mask and ORing set_val.
 *
 * @param reg         Byte address of the 32-bit hardware register.
 * @param clear_mask  Bitmask of bits to clear before inserting set_val.
 * @param set_val     Pre-shifted bitfield value to OR into the cleared register.
 */
static inline void PHY_REG_RMW(uint32_t reg, uint32_t clear_mask, uint32_t set_val)
{
    REG_WRITE(reg, (REG_READ(reg) & ~clear_mask) | set_val);
}

/* --------------------------------------------------------------------------
 * 1. DPORT & eFuse (0x3FF00008 .. 0x3FF0005C)
 * -------------------------------------------------------------------------- */

#define PHY_DPORT_LSLP_MEM0_REG         0x3FF00008U /* Light-sleep memory retention bank 0 */
#define PHY_DPORT_LSLP_MEM0_LO_MASK     0x000F0000U /* [19:16]: mem_opt[3:0] */
#define PHY_DPORT_LSLP_MEM0_LO_SHIFT    16U
#define PHY_DPORT_LSLP_MEM0_MID_MASK    0x00003000U /* [13:12]: mem_opt[5:4] */
#define PHY_DPORT_LSLP_MEM0_MID_SHIFT   12U
#define PHY_DPORT_CTL_REG               0x3FF00014U /* CPU clock multiplier control */
#define PHY_DPORT_CTL_DOUBLE_CLK        BIT(0)      /* 1 = 160 MHz CPU, 0 = 80 MHz CPU */
#define PHY_DPORT_CLK_EN_REG            0x3FF00018U /* Peripheral / Wi-Fi / WDT clock gate */
#define PHY_DPORT_CLK_WDT_EN            BIT(3)      /* Hardware watchdog clock enable */
#define PHY_DPORT_CLK_WIFI_EN           BIT(20)     /* Wi-Fi master clock enable */
#define PHY_DPORT_CLK_WIFI_SUB          0x038F0000U /* Wi-Fi sub-block clocks (BB/MAC/RF) */
#define PHY_DPORT_CLK_WIFI_GATE_MASK    0x038F0000U /* Sub-block clocks gated during RF sleep */
#define PHY_DPORT_CLK_WIFI_ALL          0xFFFF0000U /* All upper Wi-Fi subsystem clocks */
#define PHY_DPORT_LSLP_MEM1_REG         0x3FF0001CU /* Light-sleep memory retention bank 1 */
#define PHY_DPORT_LSLP_MEM1_HI_MASK     0x0000003FU /* [5:0]: mem_opt[11:6] */
#define PHY_DPORT_PERI_CLK_REG          0x3FF00024U /* Peripheral clock divider control */
#define PHY_DPORT_PERI_CLK_BB_MASK      0x00000006U /* [2:1]: BB peripheral clock select */
#define PHY_DPORT_PERI_CLK_BB_VAL       0x00000002U
#define PHY_EFUSE_DATA0_REG             0x3FF00050U /* eFuse word 0 ([31:24] -> chip_id_h[31:24]) */
#define PHY_EFUSE_DATA1_REG             0x3FF00054U /* eFuse word 1 ([27:0] -> chip_id_l[27:0]) */
#define PHY_EFUSE_DATA2_REG             0x3FF00058U /* eFuse word 2 (rev select, analog errata) */
#define PHY_EFUSE_DATA3_REG             0x3FF0005CU /* eFuse word 3 ([23:0] -> chip_id_h[23:0]) */
#define PHY_EFUSE_DATA2_VER_SEL_BIT     BIT(15)     /* 1 = ver in DATA1 & LSLP mem retention on */
#define PHY_EFUSE_DATA2_ANA_REV_SHIFT   12U         /* [15:12]: silicon analog revision nibble */
#define PHY_EFUSE_DATA2_ANA_REV_MASK    0x0AU       /* Bits [3,1] set -> rev-A BB analog default */
#define PHY_EFUSE_DATA2_RF_ERRATA_MASK  0x0EU       /* [15:13] == 0 -> RF-I2C channel-tune errata */
#define PHY_EFUSE_CHIP_VER_SHIFT        24U
#define PHY_EFUSE_CHIP_VER_MASK         0x0FU
#define PHY_EFUSE_CHIP_ID_L_EF2_MASK    0x0000F000U
#define PHY_EFUSE_CHIP_ID_L_EF1_MASK    0x0FFFFFFFU
#define PHY_EFUSE_CHIP_ID_H_EF0_MASK    0xFF000000U
#define PHY_EFUSE_CHIP_ID_H_EF3_MASK    0x00FFFFFFU

/* --------------------------------------------------------------------------
 * 2. WDEV / Lower MAC Bridge (0x3FF20004 .. 0x3FF20E44)
 * -------------------------------------------------------------------------- */

#define PHY_MAC_TX_CTRL_REG             0x3FF20004U /* Master MAC TX/RX enable */
#define PHY_MAC_TX_ENABLE               BIT(31)
#define PHY_MAC_RX_RATE_INFO_REG        0x3FF2003CU /* [19:16]: last RX packet rate code */
#define PHY_MAC_RX_RATE_INFO_SHIFT      16U
#define PHY_MAC_RX_RATE_INFO_MASK       0x0FU
#define PHY_MAC_RX_RATE_OFDM_MIN        8U          /* Rates < 8 are 11b/CCK; freq-offset gated */
#define PHY_MAC_TX_STATE_REG            0x3FF201D0U /* [15:12]: TX FSM busy state (0 = idle) */
#define PHY_MAC_TX_STATE_BUSY_MASK      0x0000F000U
#define PHY_MAC_DEBUG_REG               0x3FF20400U /* MAC debug / ACK rate table 0 */
#define PHY_MAC_DEBUG_TEST_PATTERN      0x55555555U
#define PHY_MAC_RX_STATE_REG            0x3FF20410U /* [3:0]: RX FSM busy state (0 = idle) */
#define PHY_MAC_RX_STATE_BUSY_MASK      0x0000000FU
#define PHY_WDEV_MAC_TIME_REG           0x3FF20C00U /* Free-running 1 MHz (1 us) MAC clock */
#define PHY_MAC_CTRL_REG                0x3FF20C14U /* MAC NAV / clock / sleep park control */
#define PHY_MAC_CTRL_ACTIVE_VAL         0x80000FFFU
#define PHY_MAC_CTRL_SLEEP_CLR_MASK     0x00000FFFU
#define PHY_MAC_CTRL_SLEEP_SET_VAL      0x00000002U
#define PHY_MAC_CTRL_WAKE_HOLD_BIT      BIT(30)
#define PHY_MAC_CTRL_EN_BIT             BIT(31)
#define PHY_MAC_PHY_CTRL_REG            0x3FF20C70U /* MAC-to-PHY handshake & RX framing */
#define PHY_MAC_PHY_RF_UP               BIT(1)      /* 1 = RF/PHY powered and ready for MAC */
#define PHY_MAC_PHY_RX_FRAME_MASK       0x00F40000U
#define PHY_MAC_PHY_RX_FRAME_VAL        0x00240000U
#define PHY_MAC_SLEEP_CTRL_REG          0x3FF20C74U /* MAC sleep/TX-abort sub-block gates */
#define PHY_MAC_SLEEP_CTRL_F0_MASK      0x00C00000U
#define PHY_MAC_SLEEP_CTRL_F0_SLEEP     0x00800000U
#define PHY_MAC_SLEEP_CTRL_F1_MASK      0x03000000U
#define PHY_MAC_SLEEP_CTRL_F1_SLEEP     0x02000000U
#define PHY_MAC_SLEEP_CTRL_F2_MASK      0x30000000U
#define PHY_MAC_SLEEP_CTRL_F2_SLEEP     0x20000000U
#define PHY_MAC_SLEEP_CTRL_F3_MASK      0xC0000000U
#define PHY_MAC_SLEEP_CTRL_F3_SLEEP     0x80000000U
#define PHY_MAC_BTCO_MASK_REG           0x3FF20DE0U /* Bluetooth coexistence arbitration mask */
#define PHY_WDEV_HW_RNG_REG             0x3FF20E44U /* Hardware PRNG register */

/* --------------------------------------------------------------------------
 * 3. GPIO / Strap / RTC Clock Calibration (0x60000300 .. 0x60000370)
 * -------------------------------------------------------------------------- */

#define PHY_GPIO_BTCO_CFG_REG           0x60000300U /* BT coexistence GPIO matrix */
#define PHY_GPIO_STRAP_REG              0x60000318U /* Boot strapping pin latch */
#define PHY_GPIO_STRAP_SDIO_BIT         BIT(18)     /* SDIO host interface strap active */
#define PHY_GPIO_STRAP_BOOT_SHIFT       29U         /* [31:29]: boot mode strap */
#define PHY_GPIO_STRAP_BOOT_MASK        0x7U
#define PHY_GPIO_STRAP_BOOT_SDIO        2U          /* SDIO boot mode */
#define PHY_RTC_CALI_CTRL_REG           0x6000036CU /* RTC slow-clock calibration control */
#define PHY_RTC_CALI_CYCLES_256_EN      0x00000101U /* Enable cali over 256 RTC clock cycles */
#define PHY_RTC_CALI_START              BIT(31)     /* Rising-edge trigger to start measurement */
#define PHY_RTC_CALI_DATA_REG           0x60000370U /* RTC slow-clock calibration result */
#define PHY_RTC_CALI_RDY                BIT(31)     /* 1 = calibration count ready */
#define PHY_RTC_CALI_CNT_MASK           0x0FFFFFFFU /* [27:0]: XTAL cycles per 256 RTC cycles */

/* --------------------------------------------------------------------------
 * 4. RF Front-End, PBUS, IQ Estimator & TX Tone (0x60000404 .. 0x600005FC)
 * -------------------------------------------------------------------------- */

#define PHY_RF_TX_DC_REGS               24U
#define PHY_RF_TX_DC_REG(i)             (0x60000404U + 4U * ((uint32_t)(i) >> 1))
#define PHY_RF_TX_DC_7BIT_MASK          0x7FU       /* 7-bit signed I or Q TX DC offset code */
#define PHY_RF_TX_DC_EVEN_MASK          0x00003FFFU /* Even slot: [13:7]=Q, [6:0]=I */
#define PHY_RF_TX_DC_ODD_MASK           0x0FFFC000U /* Odd slot:  [27:21]=Q, [20:14]=I */
#define PHY_RF_TXPWR_REGS               24U         /* 24 per-rate TX power/gain LUT registers */
#define PHY_RF_TXPWR_REG(i)             (0x60000504U + 4U * (uint32_t)(i))
#define PHY_RF_TXPWR_ATTEN_MASK         0x000000FFU /* [7:0]: signed -bb_atten (0.25 dB steps) */
#define PHY_RF_TXPWR_ANA_GAIN_MASK      0x000FFF00U /* [19:8]: 12-bit tx_rf_ana_gain */
#define PHY_RF_TXPWR_ANA_GAIN_SHIFT     8U
#define PHY_RF_TXPWR_STAGE10_MASK       0x0001E000U /* [16:13]: 4-bit PA stage-10 gain code */
#define PHY_RF_TXPWR_STAGE10_SHIFT      13U

#define PHY_FE_IQ_EST_CTRL_REG          0x6000057CU /* Hardware IQ/DC estimator control */
#define PHY_FE_IQ_EST_EN                BIT(0)      /* Enable IQ estimator block */
#define PHY_FE_IQ_EST_START             BIT(1)      /* Start sample accumulation */
#define PHY_FE_IQ_EST_SAMPLES_SHIFT     2U          /* [16:2]: sample count (15-bit) */
#define PHY_FE_IQ_EST_SAMPLES_MASK      0x7FFFU
#define PHY_FE_IQ_EST_MODE_SHIFT        18U         /* [18]: 1 = RX IQ/DC mode */
#define PHY_FE_IQ_EST_CFG_MASK          0x0005FFFEU
#define PHY_FE_IQ_EST_DISABLE_VAL       0x00001000U /* Idle reset sample count on disable */
#define PHY_FE_IQ_EST_ACC_REG(n)        (0x60000580U + 4U * (uint32_t)(n)) /* [0..3]: II,IQ,QI,QQ */
#define PHY_RF_RX_GAIN_EXT_REG          0x60000590U /* Digital extended RX max-gain switch */
#define PHY_RF_RX_GAIN_EXT_DIG          BIT(4)      /* 1 = normal RX gain, 0 = extended */

/* PBUS (Baseband-to-RF Analog Serial Control Bus) registers and logical channels */
#define PHY_PBUS_CTRL_REG               0x60000594U
#define PHY_PBUS_DEBUG_MODE             BIT(0)      /* 1 = SW force-write mode, 0 = HW AGC mode */
#define PHY_PBUS_FORCE_STROBE           BIT(1)      /* Trigger single PBUS force transaction */
#define PHY_PBUS_FORCE_REG_SHIFT        2U          /* [4:2]: PBUS target channel (0..7) */
#define PHY_PBUS_FORCE_VAL_SHIFT        5U          /* [13:5]: 9-bit payload value */
#define PHY_PBUS_FORCE_WIDTH_SHIFT      14U         /* [15:14]: sub-register selector (1, 2, 4) */
#define PHY_PBUS_FORCE_PRESERVE_MASK    0xFFFF0001U /* Preserve upper bus cfg + debug mode bit */
#define PHY_PBUS_VAL_MASK               0x1FFU      /* 9-bit PBUS word mask */
#define PHY_PBUS_RXPBUS_LO_MASK         0x00F00000U /* [23:20]: sleep RX PBUS low field */
#define PHY_PBUS_RXPBUS_HI_MASK         0xFC000000U /* [31:26]: sleep RX PBUS high field */
#define PHY_PBUS_CFG_REG                0x60000598U /* PBUS timing + ADC clock divider [6:0] */
#define PHY_PBUS_CFG_MIRROR_REG         0x6000059CU /* Secondary chain PBUS timing mirror */
#define PHY_PBUS_STATUS_REG             0x600005A0U
#define PHY_PBUS_READY                  BIT(30)     /* 1 = PBUS debug bus ready */
#define PHY_PBUS_BUSY                   BIT(31)     /* 1 = force-write transaction in progress */
#define PHY_PBUS_READ_WINDOW_REG(n)     (0x600005A4U + 4U * (uint32_t)(n))

/* Logical PBUS channels (reg parameter to phy_pbus_rd / phy_pbus_force) */
#define PHY_PBUS_CH_TXBB_DCO_I          0U          /* w=1: TXBB gain; w=2: TX DC offset I */
#define PHY_PBUS_CH_TXEN_DCO_Q          1U          /* w=1: TX enable/bias; w=2: TX DC offset Q */
#define PHY_PBUS_CH_RX_CTRL             2U          /* w=1: RX power/LNA/VGA control */
#define PHY_PBUS_CH_RXBB_GAIN           3U          /* w=1: RXBB coarse gain; w=2: fine + en */
#define PHY_PBUS_CH_TXGAIN_RXDCO_I      4U          /* w=1: TX gain / RX DCO I coarse; w=2: fine */
#define PHY_PBUS_CH_RXDCO_Q             5U          /* w=1: RX DCO Q coarse; w=2: RX DCO Q fine */
#define PHY_PBUS_CH_PA_EN               6U          /* w=1: PA power enable / VDD33 SAR bias */
#define PHY_PBUS_CH_RF_GAIN             7U          /* w=1: RF front-end PA gain stage */
#define PHY_PBUS_WIDTH_1                1U
#define PHY_PBUS_WIDTH_2                2U

#define PHY_FE_TX_TONE_1_REG            0x600005B8U /* DDS TX test tone generator 1 */
#define PHY_FE_TX_TONE_2_REG            0x600005BCU /* DDS TX test tone generator 2 */
#define PHY_FE_RX_CTRL_REG              0x600005C0U /* Front-end RX path control */
#define PHY_FE_TX_TONE_3_REG            0x600005C4U /* DDS TX test tone generator 3 */
#define PHY_FE_TX_TONE_FREQ_MASK        0x03FFU     /* [9:0]: signed 10-bit DDS frequency */
#define PHY_FE_TX_TONE_ATTEN_SHIFT      10U         /* [17:10]: 8-bit two's-complement -atten */
#define PHY_FE_TX_TONE_EN               BIT(18)     /* [18]: tone generator output enable */
#define PHY_FE_TX_TONE_CFG_MASK         0x0FFFFFFFU
#define PHY_FE_TX_TONE3_CFG_MASK        0x1FFFFFFFU
#define PHY_FE_TX_TONE3_EN_BITS         0x10040000U /* Tone 3 enable + auxiliary enable BIT(28) */
#define PHY_RFPLL_CTRL_REG              0x600005C8U /* RFPLL latch & sleep-hold control */
#define PHY_RFPLL_SLP_HOLD              0x00030000U /* [17:16]: RFPLL sleep hold bits */
#define PHY_RFPLL_SLP_HOLD_LO           0x00010000U
#define PHY_RFPLL_LATCH                 0x00F00000U /* [23:20]: RFPLL register update latch */

#define PHY_FE_IQ_EST_DC_I_REG          0x600005DCU /* IQ estimator I-channel DC accumulator */
#define PHY_FE_IQ_EST_DC_Q_REG          0x600005E0U /* IQ estimator Q-channel DC accumulator */
#define PHY_FE_IQ_EST_PWR_REG           0x600005E4U /* IQ estimator total signal power acc */
#define PHY_RF_CAL_MODE_REG             0x600005E8U /* RF calibration / low-power mode bits */
#define PHY_RF_CAL_MODE_MASK            0x01800000U /* [24:23]: RF calibration mode field */
#define PHY_RF_CAL_MODE_ACTIVE          0x00800000U
#define PHY_RF_CAL_MODE_LOWPWR_BIT      BIT(27)
#define PHY_FE_TX_BACKOFF_LOG_REG       0x600005FCU /* 4 packed bytes: per-band PA backoff log */

/* --------------------------------------------------------------------------
 * 5. RTC PMU & Calibration RAM (0x60000700 .. 0x60001100)
 * -------------------------------------------------------------------------- */

#define PHY_RTC_PLL_CTRL_REG            0x60000700U
#define PHY_RTC_PLL_CTRL_BOOT           0x0019C06AU /* Boot / analog reset default */
#define PHY_RTC_PLL_CTRL_OPEN_RF        0x01000000U /* RF open / active run state */
#define PHY_RTC_PLL_CTRL_BBPLL160       0x00800070U /* Short sleep pulse for 160 MHz BBPLL */
#define PHY_RTC_PLL_CTRL_SLEEP_REV2     0x00800000U /* Sleep PLL config for chip_ver == 2 */
#define PHY_RTC_PLL_CTRL_SLEEP_OLD      0x00800050U /* Sleep PLL config for chip_ver != 2 */
#define PHY_RTC_SLP_VAL_REG             0x60000704U
#define PHY_RTC_STATE0_REG              0x60000708U
#define PHY_RTC_SLP_START_BIT           BIT(20)     /* Trigger RTC sleep state machine */
#define PHY_RTC_PLL_XTAL_WAIT_REG       0x6000070CU
#define PHY_RTC_RF_PWR_REG              0x60000710U
#define PHY_RTC_RF_PWR_SAR_BIT          BIT(25)     /* SAR ADC analog rail enable */
#define PHY_RTC_RF_PWR_ALL_ON           0xFE000000U /* Full RF/BB/SAR analog power up */
#define PHY_RTC_RF_PWR_INIT_BASE        0xF0000000U /* Initial RF power-up stage 1 */
#define PHY_RTC_RF_PWR_DEEP_SAR         0xD6000000U /* Low-power RF rail with SAR active */
#define PHY_RTC_RF_PWR_RF_OFF           0x50000000U /* RF front-end powered down */
#define PHY_RTC_RESET_REASON_REG        0x60000714U
#define PHY_RTC_RESET_REASON_MASK       0x00000007U
#define PHY_RTC_RESET_DEEPSLEEP         2U          /* Reset reason code for deep-sleep wake */
#define PHY_RTC_WAKEUP_OPT_REG          0x60000718U
#define PHY_RTC_WAKEUP_OPT_MASK         0x0000003FU
#define PHY_RTC_WAKEUP_TIMER            8U          /* Wakeup source: RTC sleep timer */
#define PHY_RTC_SLP_CNT_VAL_REG         0x6000071CU /* Current RTC slow-clock counter (RO) */
#define PHY_RTC_INT_ENA_REG             0x60000720U
#define PHY_RTC_INT_CLR_REG             0x60000724U
#define PHY_RTC_INT_RAW_REG             0x60000728U
#define PHY_RTC_INT_WAKE_BIT            BIT(0)      /* RTC wakeup completed */
#define PHY_RTC_INT_REJECT_BIT          BIT(1)      /* RTC sleep rejected by hardware */
#define PHY_RTC_INT_WAKE_OR_REJECT      (PHY_RTC_INT_WAKE_BIT | PHY_RTC_INT_REJECT_BIT)
#define PHY_RTC_SCRATCH0_REG            0x60000730U
#define PHY_RTC_SCRATCH1_REG            0x60000734U
#define PHY_RTC_SCRATCH2_REG            0x60000738U
#define PHY_RTC_SCRATCH3_REG            0x6000073CU /* [7:0]: power-up RF cal option */
#define PHY_RTC_SLP_STATE0_REG          0x60000740U
#define PHY_RTC_SLP_STATE1_REG          0x60000744U
#define PHY_RTC_SLP_STATE1_BB_OFF       4U          /* Power down baseband during light sleep */
#define PHY_RTC_TIMING0_REG             0x60000748U
#define PHY_RTC_TIMING1_REG             0x6000074CU
#define PHY_RTC_ANALOG1_REG             0x60000758U
#define PHY_RTC_ANALOG2_REG             0x6000075CU
#define PHY_RTC_ANALOG3_REG             0x60000760U
#define PHY_RTC_EXT_SLEEP_OPT_REG       0x60000764U
#define PHY_RTC_GPIO_OUT_REG            0x60000768U
#define PHY_RTC_GPIO_EN_REG             0x60000774U
#define PHY_RTC_ANALOG6_REG             0x60000780U
#define PHY_RTC_GPIO_CONF_REG           0x60000790U
#define PHY_RTC_CLK1_REG                0x60000794U
#define PHY_RTC_CLK2_REG                0x60000798U
#define PHY_RTC_CLK3_REG                0x6000079CU
#define PHY_RTC_EXT_GPIO_REG            0x600007A0U
#define PHY_RTC_SLP_REJECT_CONF_REG     0x600007A8U
#define PHY_RTC_TRIM0_REG               0x600007ACU
#define PHY_RTC_TRIM1_REG               0x600007B0U
#define PHY_RTC_TRIM2_REG               0x600007B4U

#define PHY_RTC_PHY_CAL_RAM_BASE        0x60001000U /* 128-byte RTC PHY cal storage (W0..W31) */
#define PHY_RTC_PHY_CAL_RAM_REG(w)      (0x60001000U + 4U * (uint32_t)(w))
#define PHY_RTC_CHIP_ID_L_REG           0x60001060U /* W24: eFuse chip ID low word */
#define PHY_RTC_CHIP_ID_H_REG           0x60001064U /* W25: eFuse chip ID high word */
#define PHY_RTC_CAL_CHKSUM_REG          0x60001068U /* W26: ~sum(W0..W25) */
#define PHY_RTC_RFOPTION_REG            0x6000106CU /* W27: [23:16]=rfoption, [15:0]=wake cnt */
#define PHY_RTC_RFOPTION_SHIFT          16U
#define PHY_RTC_RFOPTION_MASK           0xFFFF0000U
#define PHY_RTC_RFOPTION_CNT_MASK       0x0000FFFFU
#define PHY_RTC_PHY_VER_REG             0x6000107CU /* W31: [31:16] = PHY version word */
#define PHY_RTC_DEEPSLEEP_MAGIC_REG     0x60001100U
#define PHY_RTC_DEEPSLEEP_MAGIC_VAL     5U          /* Confirmed deep-sleep wakeup marker */

/* --------------------------------------------------------------------------
 * 6. IO_MUX, SLC/SDIO, RF-I2C, BBPLL, MCAL & SAR ADC (0x60000808 .. 0x60000D9C)
 * -------------------------------------------------------------------------- */

#define PHY_IO_MUX_MTCK_REG             0x60000808U
#define PHY_IO_MUX_MTMS_REG             0x6000080CU
#define PHY_IO_MUX_MTDO_REG             0x60000814U
#define PHY_IO_MUX_U0TXD_REG            0x60000820U
#define PHY_IO_MUX_GPIO0_REG            0x60000834U
#define PHY_IO_MUX_FUNC_MASK            0x00000130U /* IO_MUX function select bits [8,5:4] */
#define PHY_IO_MUX_FUNC_PU_MASK         0x000001F0U /* Function select + pull-up bits */

#define PHY_SLC_SDIO_STATUS0_REG        0x60000B3CU
#define PHY_SLC_SDIO_STATUS1_REG        0x60000B58U
#define PHY_SLC_SDIO_IDLE_ST1           0x00002011U
#define PHY_SLC_SDIO_IDLE_ST0_SHIFT     18U
#define PHY_SLC_SDIO_IDLE_ST0_MASK      0x0FFFU
#define PHY_SLC_SDIO_IDLE_ST0_VAL       0x000BU

#define PHY_RF_I2C_HOST_REG(h)          (0x60000D00U + 4U * (uint32_t)(h))
#define PHY_RF_I2C_START                BIT(24)     /* Write transaction trigger bit */
#define PHY_RF_I2C_BUSY                 BIT(25)     /* 1 = transaction in progress */
#define PHY_RF_I2C_ERRATA_CMD           0x01041D77U /* Silicon RF errata direct write on host 0 */
#define PHY_BBPLL_CTRL_REG              0x60000D40U
#define PHY_BBPLL_MODE_MASK             0x0000000CU /* [3:2]: BBPLL operating mode */
#define PHY_BBPLL_MODE_RUN              0x00000004U /* Normal locked run mode */
#define PHY_BBPLL_MODE_CAL              0x00000008U /* Calibration / sleep-entry mode */
#define PHY_ANALOG_RST_REG              0x60000D48U
#define PHY_ANALOG_RST_BIT              BIT(0)
#define PHY_MCAL_TXDC_REG               0x60000D4CU /* Hardware TX DC comparator engine */
#define PHY_MCAL_ARM                    0x01113CF1U
#define PHY_MCAL_TRIGGER                0x01113CF3U
#define PHY_MCAL_STOP                   0x01113CF0U
#define PHY_MCAL_DONE                   BIT(24)     /* 1 = comparator measurement complete */
#define PHY_MCAL_QFLAG                  BIT(30)     /* Q-branch comparator sign (bit 31 = I) */

#define PHY_SAR_CTRL_REG                0x60000D50U /* SAR ADC control & FSM status */
#define PHY_SAR_CTRL_PWDET_EN           BIT(0)      /* Power-detector auto-trigger enable */
#define PHY_SAR_CTRL_START              BIT(1)      /* Rising-edge single conversion trigger */
#define PHY_SAR_CTRL_TSEN_EN            BIT(5)      /* Temperature sensor enable */
#define PHY_SAR_CTRL_CLKDIV_MASK        0x0000FF00U /* [15:8]: SAR ADC clock divider */
#define PHY_SAR_CTRL_CLKDIV_SHIFT       8U
#define PHY_SAR_CTRL_SAMPLE_CNT_MASK    0x0000001CU /* [4:2]: burst sample count - 1 (0 = 1) */
#define PHY_SAR_CTRL_STATE_SHIFT        24U         /* [26:24]: SAR FSM state (0 = idle) */
#define PHY_SAR_CTRL_STATE_MASK         0x7U
#define PHY_SAR_TIMING0_REG             0x60000D54U /* SAR phase timing register 0 */
#define PHY_SAR_TIMING1_REG             0x60000D58U /* SAR phase timing register 1 */
#define PHY_SAR_TIMING_MASK             0x00FFFFFFU
#define PHY_SAR_MUX_CTRL_REG            0x60000D5CU /* SAR analog input mux */
#define PHY_SAR_MUX_TOUT_EN             BIT(21)     /* Select external TOUT / TSEN pin */
#define PHY_SAR_MUX_VDD33_EN            BIT(23)     /* Select internal VDD33 rail */
#define PHY_SAR_PWDET_CTRL_REG          0x60000D60U /* TX power-detector capture control */
#define PHY_SAR_PWDET_EN_BIT            BIT(0)      /* Power-detector latch enable */
#define PHY_SAR_PWDET_BG_ARM_BIT        BIT(1)      /* Arm background TX packet capture */
#define PHY_SAR_PWDET_TXRATE_SHIFT      24U         /* [28:24]: captured TX packet rate slot */
#define PHY_SAR_PWDET_TXRATE_MASK       0x1FU
#define PHY_SAR_SAMPLE_COUNT            8U          /* 8 hardware SAR output registers */
#define PHY_SAR_DOUT_REG(n)             (0x60000D80U + 4U * (uint32_t)(n))

/* --------------------------------------------------------------------------
 * 7. Baseband, AGC, Spur Suppression & RX Gain RAM (0x60009800 .. 0x60009F54)
 * -------------------------------------------------------------------------- */

#define PHY_BB_RX_METRIC_REG            0x60009800U /* [0]=fo valid, [15:8]=fo, [28:16]=EVM */
#define PHY_BB_RX_METRIC_FO_VALID       BIT(0)
#define PHY_BB_RX_METRIC_FO_SHIFT       8U
#define PHY_BB_RX_METRIC_EVM_SHIFT      16U
#define PHY_BB_RX_METRIC_EVM_MASK       0x1FFFU
#define PHY_BB_RX11B_REG                0x60009820U /* 802.11b CCK RX tuning (Ch 14) */
#define PHY_BB_RX_RSSI_REG              0x60009824U /* [11:0]: raw hardware noise floor */
#define PHY_BB_ADC_RAND_REG             0x60009830U /* Thermal ADC LSB noise entropy source */
#define PHY_BB_11B_FE_REG               0x60009838U
#define PHY_BB_TXIQ_MODE_REG            0x6000983CU
#define PHY_BB_TXIQ_GAIN_COMMIT_REG     0x60009860U /* [0]=RX gain commit; [28:18]=TXIQ */
#define PHY_BB_TXIQ_COMMIT_BIT          BIT(0)
#define PHY_BB_TXIQ_EN_BITS             0x00030000U
#define PHY_BB_TXIQ_FIELD_MASK          0x1FFF0000U
#define PHY_BB_TXIQ_PHASE_SHIFT         18U         /* [23:18]: 6-bit TXIQ phase */
#define PHY_BB_TXIQ_GAIN_SHIFT          24U         /* [28:24]: 5-bit TXIQ gain */
#define PHY_BB_TXDC_EN_REG              0x60009864U /* [0]=TXDC enable; [31:18]=optional I/Q */

#define PHY_BB_SPUR_MASK0_REG           0x60009884U
#define PHY_BB_SPUR_MASK1_REG           0x60009888U
#define PHY_BB_SPUR_MASK2_REG           0x6000988CU
#define PHY_BB_SPUR_MASK3_REG           0x6000989CU
#define PHY_BB_SPUR_FREQ_REG            0x600098A0U /* [31:30]=en; [29:20]=coarse; [19:0]=fine */
#define PHY_BB_SPUR_FREQ_EN_BITS        0xC0000000U
#define PHY_BB_SPUR_FREQ_VAL_MASK       0x3FFFFFFFU
#define PHY_BB_SPUR_MASK4_REG           0x600098D4U
#define PHY_BB_FREQOFF_CLR_REG          0x600098DCU /* |= 0xF latches/clears RX freq offset */
#define PHY_BB_FREQOFF_CLR_MASK         0x0000000FU
#define PHY_BB_AGC_THR_98EC_REG         0x600098ECU
#define PHY_BB_AGC_THR_9988_REG         0x60009988U
#define PHY_BB_SPUR_MASK5_REG           0x600099A8U
#define PHY_BB_SPUR_MASK6_REG           0x600099ACU
#define PHY_BB_SPUR_MASK7_REG           0x600099B0U
#define PHY_BB_SPUR_MASK8_REG           0x600099B8U
#define PHY_BB_SPUR_MASK9_REG           0x600099BCU

#define PHY_BB_TX_CAL_REG               0x60009A28U
#define PHY_BB_TX_CAL_TXIQ_EN           BIT(5)      /* 0x20: enable baseband TXIQ correction */
#define PHY_BB_DIG_RX_REG               0x60009A2CU
#define PHY_BB_DIG_RX_EN                BIT(19)     /* Digital RX baseband enable */
#define PHY_BB_RX_GAIN_FORCE_REG        0x60009A34U
#define PHY_BB_RX_GAIN_LATCH            BIT(0)      /* Pulse 1->0 to latch RX gain/comp */
#define PHY_BB_RX_GAIN_FORCE_MASK       0x000003FFU
#define PHY_BB_RX_GAIN_WINDOW_REG       0x60009A68U /* Dual-window selector for RX gain RAM */
#define PHY_BB_RX_GAIN_WINDOW_LO        0x0000001EU /* Low 32-bit word window (gain + DC_I) */
#define PHY_BB_RX_GAIN_WINDOW_HI        0x000001E0U /* High 32-bit word window (DC_Q + RXIQ) */

#define PHY_BB_AGC_CTRL_REG             0x60009B00U
#define PHY_BB_AGC_ANT_SW_EN            BIT(23)     /* Antenna switch control enable */
#define PHY_BB_AGC_OFF                  BIT(28)     /* 1 = AGC/CCA disabled, 0 = enabled */
#define PHY_BB_SLEEP_REG                0x60009B08U
#define PHY_BB_SLEEP_RX                 BIT(27)     /* Gate RX baseband during sleep/debug */
#define PHY_BB_AGC_THR_9B0C_REG         0x60009B0CU
#define PHY_BB_CHAN_FREQ_REG            0x60009B14U /* [31:17]=reciprocal freq; [14:13]=3 */
#define PHY_BB_AGC_THR_9B28_REG         0x60009B28U
#define PHY_BB_AGC_THR_9B44_REG         0x60009B44U
#define PHY_BB_RX_MAX_GAIN_REG          0x60009B48U /* [6:0]: max AGC gain table index */
#define PHY_BB_RX_MAX_GAIN_MASK         0x0000007FU
#define PHY_BB_RX_MAX_GAIN_CAP          0x55U       /* Hardware max AGC index (85) */
#define PHY_BB_RX_MAX_GAIN_ZERO_CAP     0x46U       /* Cap used when rxmax == 0 (70) */
#define PHY_BB_RX_DBG_REG               0x60009B4CU
#define PHY_BB_AGC_THR_9B50_REG         0x60009B50U
#define PHY_BB_AGC_THR_9B58_REG         0x60009B58U
#define PHY_BB_AGC_THR_9B5C_REG         0x60009B5CU
#define PHY_BB_RX_CTRL_REG              0x60009B60U
#define PHY_BB_RX_RESET                 BIT(0)      /* Pulse 1->0 to reset RX baseband */
#define PHY_BB_NOISE_MEAS               BIT(1)      /* 1 = hardware noise measurement active */
#define PHY_BB_RX_CTRL_NOISE_START      0x00028002U /* Bits [17,15,1]: start noise floor meas */
#define PHY_BB_NOISE_FLOOR_REG          0x60009B64U
#define PHY_BB_NOISE_FLOOR_SET_MASK     0x000001FFU /* [8:0]: programmed noise floor (0.5 dB) */
#define PHY_BB_NOISE_FLOOR_CH_SHIFT     9U          /* [11:9]: measurement channel index */
#define PHY_BB_NOISE_FLOOR_CH_MASK      0x00000E00U
#define PHY_BB_NOISE_FLOOR_CCA_SHIFT    12U         /* [19:12]: CCA threshold override */
#define PHY_BB_NOISE_FLOOR_CCA_MASK     0x000FF000U
#define PHY_BB_NOISE_FLOOR_RD_SHIFT     20U         /* [31:20]: measured noise floor readout */
#define PHY_BB_NOISE_FLOOR_RD_MASK      0x0FFFU
#define PHY_BB_AGC_THR_9B68_REG         0x60009B68U
#define PHY_BB_AGC_THR_9B6C_REG         0x60009B6CU
#define PHY_BB_RX_FILTER_REG            0x60009C04U /* 802.11b digital RX filter select */
#define PHY_BB_SENSE_BACKOFF_REG        0x60009C28U /* [16:10]: RX sensitivity backoff */
#define PHY_BB_AGC_THR_9C48_REG         0x60009C48U
#define PHY_BB_AGC_THR_9C4C_REG         0x60009C4CU
#define PHY_BB_SPUR_MASK10_REG          0x60009D08U
#define PHY_BB_SPUR_MASK11_REG          0x60009D0CU
#define PHY_BB_AGC_THR_9D10_REG         0x60009D10U
#define PHY_BB_AGC_THR_9D18_REG         0x60009D18U
#define PHY_BB_AGC_THR_9D1C_REG         0x60009D1CU
#define PHY_BB_AGC_THR_9D20_REG         0x60009D20U
#define PHY_BB_AGC_THR_9D24_REG         0x60009D24U
#define PHY_BB_AGC_THR_9D40_REG         0x60009D40U
#define PHY_BB_AGC_THR_9D44_REG         0x60009D44U
#define PHY_BB_AGC_THR_9D4C_REG         0x60009D4CU
#define PHY_BB_ANT_SWITCH_LO_REG        0x60009D60U /* Antenna switch truth table low */
#define PHY_BB_ANT_SWITCH_HI_REG        0x60009D64U /* Antenna switch truth table high */
#define PHY_BB_RX_CHAN_COMP_REG         0x60009D68U /* [17:10]: signed per-ch RX comp; [18]=CCA */
#define PHY_BB_RX_CHAN_COMP_SHIFT       10U
#define PHY_BB_RX_CHAN_COMP_MASK        0x0003FC00U
#define PHY_BB_RX_CHAN_COMP_CCA_BIT     BIT(18)
#define PHY_BB_AGC_THR_9D70_REG         0x60009D70U
#define PHY_BB_ANALOG_DEFAULT_REG       0x60009D74U /* Silicon-rev analog default erratum reg */
#define PHY_BB_ANALOG_DEFAULT_REV_A     0xE690A568U /* eFuse DATA2[15:12] & 0xA == 0xA */
#define PHY_BB_ANALOG_DEFAULT_STD       0xEAB4D027U /* Standard ESP8266 silicon default */
#define PHY_BB_RX_GAIN_TABLE_REG(n)     (0x60009E00U + 4U * (uint32_t)(n))

/* --------------------------------------------------------------------------
 * 8. ROM-I2C Analog Blocks (13 Blocks), Sub-Registers & Host IDs (0..4)
 * -------------------------------------------------------------------------- */

#define PHY_I2C_BLOCK_RX_ANA            0x61U /* Host 1: RX analog front-end & filter */
#define PHY_I2C_BLOCK_RFPLL             0x62U /* Host 1: 2.4 GHz RFPLL VCO / cap / lock */
#define PHY_I2C_BLOCK_RFPLL_SDM         0x63U /* Host 0: 24-bit fractional-N RFPLL SDM */
#define PHY_I2C_BLOCK_RX_GAIN           0x64U /* Host 0: RX LNA/VGA capacitor trims */
#define PHY_I2C_BLOCK_BIAS_PWR          0x65U /* Host 4: RF analog bias & power rail */
#define PHY_I2C_BLOCK_TX_FILT           0x66U /* Host 3: TX baseband low-pass filter */
#define PHY_I2C_BLOCK_BBPLL             0x67U /* Host 4: 160 MHz baseband/CPU PLL */
#define PHY_I2C_BLOCK_RC_REF            0x68U /* Host 3: RC filter calibration reference */
#define PHY_I2C_BLOCK_BIAS_RC           0x6AU /* Host 2: Bias & RC calibration engine */
#define PHY_I2C_BLOCK_TX_PA             0x6BU /* Host 2: RF TX PA & TXCAP capacitor bank */
#define PHY_I2C_BLOCK_SAR               0x6CU /* Host 2: SAR ADC & temperature sensor */
#define PHY_I2C_BLOCK_ANA_INF           0x77U /* Host 0: BB-analog interface, IQ & DPD */
#define PHY_I2C_BLOCK_ANA_CLK           0x7CU /* Host 1: TX/RX analog clock gating */

#define PHY_I2C_HOST_0                  0U
#define PHY_I2C_HOST_1                  1U
#define PHY_I2C_HOST_2                  2U
#define PHY_I2C_HOST_3                  3U
#define PHY_I2C_HOST_4                  4U

/* Frequently accessed ROM-I2C sub-register addresses */
#define PHY_I2C_RX_ANA_FILT_REG         2U    /* [5:0]=rx_filt_dcap, |0xA0 enable */
#define PHY_I2C_RX_ANA_EXT_GAIN_REG     5U    /* 0xE0 normal, 0xEF extended RX gain */
#define PHY_I2C_RFPLL_CAL_CTRL_REG      0U    /* [6:5] calibration restart pulse */
#define PHY_I2C_RFPLL_CAP_HINT_REG      1U    /* Initial VCO capacitor bank hint */
#define PHY_I2C_RFPLL_PWR_REG           3U    /* 0xF1 active, 0x01 sleep/off */
#define PHY_I2C_RFPLL_CAP_READ_REG      5U    /* Locked VCO capacitor bank readback */
#define PHY_I2C_RFPLL_LOCK_STAT_REG     7U    /* [7]: 1 when RFPLL calibration locked */
#define PHY_I2C_RFPLL_RST_REG           10U   /* 0xA6 -> 0xA7 -> 0xA5 reset sequence */
#define PHY_I2C_RFPLL_EN_REG            11U   /* 0x80 run, 0xC0 reset */
#define PHY_I2C_SDM_CTRL_REG            0U    /* 0x07 load, 0x17 latch/enable */
#define PHY_I2C_SDM_CFG_REG             1U    /* 0xF3 SDM reset configuration */
#define PHY_I2C_SDM_BYTE0_REG           3U    /* SDM[23:16] integer + top frac */
#define PHY_I2C_SDM_BYTE1_REG           4U    /* SDM[15:8] */
#define PHY_I2C_SDM_BYTE2_REG           5U    /* SDM[7:0] */
#define PHY_I2C_RX_GAIN_LNA_CAP_REG     4U    /* [3:0]=LNA cap trim, |0x40 enable */
#define PHY_I2C_RX_GAIN_VGA_CAP_REG     7U    /* [3:0]=VGA cap trim, |0x40 enable */
#define PHY_I2C_TX_FILT_DCAP_REG        1U    /* [5:0]=tx_filt_dcap, |0x40 enable */
#define PHY_I2C_SAR_CTRL_REG            0U    /* [0]=pwr, [4]=init, [5]=mux, [6]=tsen */
#define PHY_I2C_SAR_CFG_REG             1U
#define PHY_I2C_SAR_TSEN_DOUT_REG       2U    /* 8-bit temperature sensor readout */
#define PHY_I2C_ANA_INF_DPD_SCALE_REG   8U    /* DPD scale attenuation register */
#define PHY_I2C_ANA_INF_TX_SCALE_REG    9U    /* TX digital scale trim (0 = normal) */
#define PHY_I2C_ANA_INF_DPD_TXIQ_P_REG  0x0FU /* [1]=DPD bypass, [3]=gating, [6]=TXIQ p sign */
#define PHY_I2C_ANA_INF_TXIQ_G_REG      0x10U /* [0]=TXIQ g sign, [2]=cal mux, [7:3]=TXIQ g */
#define PHY_I2C_ANA_INF_TXIQ_P_REG      0x11U /* [5:0]=TXIQ phase */
#define PHY_I2C_ANA_INF_RX_MODE_REG     0x12U /* 0xE8 normal, 0xD8 freq-off, 0 cal */
#define PHY_I2C_ANA_INF_RXIQ_SIGN_REG   0x18U /* [0]=gate, [3]=p sign, [5]=g sign, [7]=cal */
#define PHY_I2C_ANA_INF_RXIQ_G_REG      0x19U /* [4:0]=RXIQ gain, [7:5]=RXIQ phase[5:3] */
#define PHY_I2C_ANA_INF_RXIQ_P_REG      0x1AU /* [2:0]=RXIQ phase[2:0] / gating reset */
#define PHY_I2C_ANA_INF_CLK_GATE_REG    0x1CU /* [0]=gating, [5]=RX clk, [6]=TX clk */
#define PHY_I2C_ANA_CLK_PATH_REG        0x15U /* [0]=TX path clk, [1]=RX path clk */

#ifdef __cplusplus
}
#endif
