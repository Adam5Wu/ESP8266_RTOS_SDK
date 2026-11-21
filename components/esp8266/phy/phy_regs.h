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

static inline uint32_t PHY_REG_READ(uint32_t reg)
{
    return REG_READ(reg);
}

static inline void PHY_REG_WRITE(uint32_t reg, uint32_t val)
{
    REG_WRITE(reg, val);
}

static inline void PHY_REG_SET(uint32_t reg, uint32_t mask)
{
    REG_WRITE(reg, REG_READ(reg) | mask);
}

static inline void PHY_REG_CLR(uint32_t reg, uint32_t mask)
{
    REG_WRITE(reg, REG_READ(reg) & ~mask);
}

/* Clear bits in clear_mask, then OR in set_val */
static inline void PHY_REG_RMW(uint32_t reg, uint32_t clear_mask, uint32_t set_val)
{
    REG_WRITE(reg, (REG_READ(reg) & ~clear_mask) | set_val);
}

/* --------------------------------------------------------------------------
 * 1. DPORT & eFuse (0x3FF00008 .. 0x3FF0005C)
 * -------------------------------------------------------------------------- */

#define PHY_DPORT_LSLP_MEM0_REG         0x3FF00008U
#define PHY_DPORT_CTL_REG               0x3FF00014U
#define PHY_DPORT_CTL_DOUBLE_CLK        BIT(0)
#define PHY_DPORT_CLK_EN_REG            0x3FF00018U
#define PHY_DPORT_CLK_WDT_EN            BIT(3)
#define PHY_DPORT_CLK_WIFI_EN           BIT(20)
#define PHY_DPORT_CLK_WIFI_SUB          0x038F0000U
#define PHY_DPORT_CLK_WIFI_GATE_MASK    0x038F0000U
#define PHY_DPORT_CLK_WIFI_ALL          0xFFFF0000U
#define PHY_DPORT_LSLP_MEM1_REG         0x3FF0001CU
#define PHY_DPORT_PERI_CLK_REG          0x3FF00024U
#define PHY_EFUSE_DATA0_REG             0x3FF00050U
#define PHY_EFUSE_DATA1_REG             0x3FF00054U
#define PHY_EFUSE_DATA2_REG             0x3FF00058U
#define PHY_EFUSE_DATA3_REG             0x3FF0005CU

/* --------------------------------------------------------------------------
 * 2. WDEV / Lower MAC Bridge (0x3FF20004 .. 0x3FF20E44)
 * -------------------------------------------------------------------------- */

#define PHY_MAC_TX_CTRL_REG             0x3FF20004U
#define PHY_MAC_TX_ENABLE               BIT(31)
#define PHY_MAC_RX_RATE_INFO_REG        0x3FF2003CU
#define PHY_MAC_TX_STATE_REG            0x3FF201D0U
#define PHY_MAC_DEBUG_REG               0x3FF20400U
#define PHY_MAC_RX_STATE_REG            0x3FF20410U
#define PHY_WDEV_MAC_TIME_REG           0x3FF20C00U
#define PHY_MAC_CTRL_REG                0x3FF20C14U
#define PHY_MAC_PHY_CTRL_REG            0x3FF20C70U
#define PHY_MAC_PHY_RF_UP               BIT(1)
#define PHY_MAC_SLEEP_CTRL_REG          0x3FF20C74U
#define PHY_MAC_BTCO_MASK_REG           0x3FF20DE0U
#define PHY_WDEV_HW_RNG_REG             0x3FF20E44U

/* --------------------------------------------------------------------------
 * 3. GPIO / Strap / RTC Clock Calibration (0x60000300 .. 0x60000370)
 * -------------------------------------------------------------------------- */

#define PHY_GPIO_BTCO_CFG_REG           0x60000300U
#define PHY_GPIO_STRAP_REG              0x60000318U
#define PHY_RTC_CALI_CTRL_REG           0x6000036CU
#define PHY_RTC_CALI_START              BIT(31)
#define PHY_RTC_CALI_DATA_REG           0x60000370U
#define PHY_RTC_CALI_RDY                BIT(31)
#define PHY_RTC_CALI_CNT_MASK           0x0FFFFFFFU

/* --------------------------------------------------------------------------
 * 4. RF Front-End, PBUS, IQ Estimator & TX Tone (0x60000404 .. 0x600005FC)
 * -------------------------------------------------------------------------- */

#define PHY_RF_TX_DC_REGS               24U
#define PHY_RF_TX_DC_REG(i)             (0x60000404U + 4U * ((uint32_t)(i) >> 1))
#define PHY_RF_TXPWR_REGS               24U
#define PHY_RF_TXPWR_REG(i)             (0x60000504U + 4U * (uint32_t)(i))

#define PHY_FE_IQ_EST_CTRL_REG          0x6000057CU
#define PHY_FE_IQ_EST_ACC_REG(n)        (0x60000580U + 4U * (uint32_t)(n))
#define PHY_RF_RX_GAIN_EXT_REG          0x60000590U
#define PHY_RF_RX_GAIN_EXT_DIG          BIT(4)

#define PHY_PBUS_CTRL_REG               0x60000594U
#define PHY_PBUS_DEBUG_MODE             BIT(0)
#define PHY_PBUS_FORCE_STROBE           BIT(1)
#define PHY_PBUS_FORCE_REG_SHIFT        2U
#define PHY_PBUS_FORCE_VAL_SHIFT        5U
#define PHY_PBUS_FORCE_WIDTH_SHIFT      14U
#define PHY_PBUS_CFG_REG                0x60000598U
#define PHY_PBUS_CFG_MIRROR_REG         0x6000059CU
#define PHY_PBUS_STATUS_REG             0x600005A0U
#define PHY_PBUS_READY                  BIT(30)
#define PHY_PBUS_BUSY                   BIT(31)
#define PHY_PBUS_READ_WINDOW_REG(n)     (0x600005A4U + 4U * (uint32_t)(n))

#define PHY_FE_TX_TONE_1_REG            0x600005B8U
#define PHY_FE_TX_TONE_2_REG            0x600005BCU
#define PHY_FE_RX_CTRL_REG              0x600005C0U
#define PHY_FE_TX_TONE_3_REG            0x600005C4U
#define PHY_RFPLL_CTRL_REG              0x600005C8U
#define PHY_RFPLL_SLP_HOLD              0x00030000U
#define PHY_RFPLL_LATCH                 0x00F00000U

#define PHY_FE_IQ_EST_DC_I_REG          0x600005DCU
#define PHY_FE_IQ_EST_DC_Q_REG          0x600005E0U
#define PHY_FE_IQ_EST_PWR_REG           0x600005E4U
#define PHY_RF_CAL_MODE_REG             0x600005E8U
#define PHY_FE_TX_BACKOFF_LOG_REG       0x600005FCU

/* --------------------------------------------------------------------------
 * 5. RTC PMU & Calibration RAM (0x60000700 .. 0x60001100)
 * -------------------------------------------------------------------------- */

#define PHY_RTC_PLL_CTRL_REG            0x60000700U
#define PHY_RTC_SLP_VAL_REG             0x60000704U
#define PHY_RTC_STATE0_REG              0x60000708U
#define PHY_RTC_SLP_START_BIT           BIT(20)
#define PHY_RTC_PLL_XTAL_WAIT_REG       0x6000070CU
#define PHY_RTC_RF_PWR_REG              0x60000710U
#define PHY_RTC_RF_PWR_SAR_BIT          BIT(25)
#define PHY_RTC_RESET_REASON_REG        0x60000714U
#define PHY_RTC_WAKEUP_OPT_REG          0x60000718U
#define PHY_RTC_SLP_CNT_VAL_REG         0x6000071CU
#define PHY_RTC_INT_ENA_REG             0x60000720U
#define PHY_RTC_INT_CLR_REG             0x60000724U
#define PHY_RTC_INT_RAW_REG             0x60000728U
#define PHY_RTC_SCRATCH0_REG            0x60000730U
#define PHY_RTC_SCRATCH1_REG            0x60000734U
#define PHY_RTC_SCRATCH2_REG            0x60000738U
#define PHY_RTC_SCRATCH3_REG            0x6000073CU
#define PHY_RTC_SLP_STATE0_REG          0x60000740U
#define PHY_RTC_SLP_STATE1_REG          0x60000744U
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

#define PHY_RTC_PHY_CAL_RAM_BASE        0x60001000U
#define PHY_RTC_PHY_CAL_RAM_REG(w)      (0x60001000U + 4U * (uint32_t)(w))
#define PHY_RTC_CHIP_ID_L_REG           0x60001060U
#define PHY_RTC_CHIP_ID_H_REG           0x60001064U
#define PHY_RTC_CAL_CHKSUM_REG          0x60001068U
#define PHY_RTC_RFOPTION_REG            0x6000106CU
#define PHY_RTC_PHY_VER_REG             0x6000107CU
#define PHY_RTC_DEEPSLEEP_MAGIC_REG     0x60001100U

/* --------------------------------------------------------------------------
 * 6. IO_MUX, SLC/SDIO, RF-I2C, BBPLL, MCAL & SAR ADC (0x60000808 .. 0x60000D9C)
 * -------------------------------------------------------------------------- */

#define PHY_IO_MUX_MTCK_REG             0x60000808U
#define PHY_IO_MUX_MTMS_REG             0x6000080CU
#define PHY_IO_MUX_MTDO_REG             0x60000814U
#define PHY_IO_MUX_U0TXD_REG            0x60000820U
#define PHY_IO_MUX_GPIO0_REG            0x60000834U

#define PHY_SLC_SDIO_STATUS0_REG        0x60000B3CU
#define PHY_SLC_SDIO_STATUS1_REG        0x60000B58U

#define PHY_RF_I2C_HOST_REG(h)          (0x60000D00U + 4U * (uint32_t)(h))
#define PHY_RF_I2C_START                BIT(24)
#define PHY_RF_I2C_BUSY                 BIT(25)
#define PHY_BBPLL_CTRL_REG              0x60000D40U
#define PHY_ANALOG_RST_REG              0x60000D48U
#define PHY_MCAL_TXDC_REG               0x60000D4CU
#define PHY_MCAL_ARM                    0x01113CF1U
#define PHY_MCAL_TRIGGER                0x01113CF3U
#define PHY_MCAL_STOP                   0x01113CF0U
#define PHY_MCAL_DONE                   BIT(24)
#define PHY_MCAL_QFLAG                  BIT(30)

#define PHY_SAR_CTRL_REG                0x60000D50U
#define PHY_SAR_TIMING0_REG             0x60000D54U
#define PHY_SAR_TIMING1_REG             0x60000D58U
#define PHY_SAR_MUX_CTRL_REG            0x60000D5CU
#define PHY_SAR_MUX_TOUT_EN             BIT(21)
#define PHY_SAR_MUX_VDD33_EN            BIT(23)
#define PHY_SAR_PWDET_CTRL_REG          0x60000D60U
#define PHY_SAR_DOUT_REG(n)             (0x60000D80U + 4U * (uint32_t)(n))

/* --------------------------------------------------------------------------
 * 7. Baseband, AGC, Spur Suppression & RX Gain RAM (0x60009800 .. 0x60009F54)
 * -------------------------------------------------------------------------- */

#define PHY_BB_RX_METRIC_REG            0x60009800U
#define PHY_BB_RX11B_REG                0x60009820U
#define PHY_BB_RX_RSSI_REG              0x60009824U
#define PHY_BB_ADC_RAND_REG             0x60009830U
#define PHY_BB_11B_FE_REG               0x60009838U
#define PHY_BB_TXIQ_MODE_REG            0x6000983CU
#define PHY_BB_TXIQ_GAIN_COMMIT_REG     0x60009860U
#define PHY_BB_TXDC_EN_REG              0x60009864U

#define PHY_BB_SPUR_MASK0_REG           0x60009884U
#define PHY_BB_SPUR_MASK1_REG           0x60009888U
#define PHY_BB_SPUR_MASK2_REG           0x6000988CU
#define PHY_BB_SPUR_MASK3_REG           0x6000989CU
#define PHY_BB_SPUR_FREQ_REG            0x600098A0U
#define PHY_BB_SPUR_MASK4_REG           0x600098D4U
#define PHY_BB_FREQOFF_CLR_REG          0x600098DCU
#define PHY_BB_AGC_THR_98EC_REG         0x600098ECU
#define PHY_BB_AGC_THR_9988_REG         0x60009988U
#define PHY_BB_SPUR_MASK5_REG           0x600099A8U
#define PHY_BB_SPUR_MASK6_REG           0x600099ACU
#define PHY_BB_SPUR_MASK7_REG           0x600099B0U
#define PHY_BB_SPUR_MASK8_REG           0x600099B8U
#define PHY_BB_SPUR_MASK9_REG           0x600099BCU

#define PHY_BB_TX_CAL_REG               0x60009A28U
#define PHY_BB_DIG_RX_REG               0x60009A2CU
#define PHY_BB_DIG_RX_EN                BIT(19)
#define PHY_BB_RX_GAIN_FORCE_REG        0x60009A34U
#define PHY_BB_RX_GAIN_LATCH            BIT(0)
#define PHY_BB_RX_GAIN_WINDOW_REG       0x60009A68U

#define PHY_BB_AGC_CTRL_REG             0x60009B00U
#define PHY_BB_AGC_OFF                  BIT(28)
#define PHY_BB_SLEEP_REG                0x60009B08U
#define PHY_BB_SLEEP_RX                 BIT(27)
#define PHY_BB_AGC_THR_9B0C_REG         0x60009B0CU
#define PHY_BB_CHAN_FREQ_REG            0x60009B14U
#define PHY_BB_AGC_THR_9B28_REG         0x60009B28U
#define PHY_BB_AGC_THR_9B44_REG         0x60009B44U
#define PHY_BB_RX_MAX_GAIN_REG          0x60009B48U
#define PHY_BB_RX_DBG_REG               0x60009B4CU
#define PHY_BB_AGC_THR_9B50_REG         0x60009B50U
#define PHY_BB_AGC_THR_9B58_REG         0x60009B58U
#define PHY_BB_AGC_THR_9B5C_REG         0x60009B5CU
#define PHY_BB_RX_CTRL_REG              0x60009B60U
#define PHY_BB_RX_RESET                 BIT(0)
#define PHY_BB_NOISE_MEAS               BIT(1)
#define PHY_BB_NOISE_FLOOR_REG          0x60009B64U
#define PHY_BB_AGC_THR_9B68_REG         0x60009B68U
#define PHY_BB_AGC_THR_9B6C_REG         0x60009B6CU
#define PHY_BB_RX_FILTER_REG            0x60009C04U
#define PHY_BB_SENSE_BACKOFF_REG        0x60009C28U
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
#define PHY_BB_ANT_SWITCH_LO_REG        0x60009D60U
#define PHY_BB_ANT_SWITCH_HI_REG        0x60009D64U
#define PHY_BB_RX_CHAN_COMP_REG         0x60009D68U
#define PHY_BB_AGC_THR_9D70_REG         0x60009D70U
#define PHY_BB_ANALOG_DEFAULT_REG       0x60009D74U
#define PHY_BB_RX_GAIN_TABLE_REG(n)     (0x60009E00U + 4U * (uint32_t)(n))

/* --------------------------------------------------------------------------
 * 8. ROM-I2C Analog Blocks (13 Blocks) & Host IDs (0..4)
 * -------------------------------------------------------------------------- */

#define PHY_I2C_BLOCK_RX_ANA            0x61U
#define PHY_I2C_BLOCK_RFPLL             0x62U
#define PHY_I2C_BLOCK_RFPLL_SDM         0x63U
#define PHY_I2C_BLOCK_RX_GAIN           0x64U
#define PHY_I2C_BLOCK_BIAS_PWR          0x65U
#define PHY_I2C_BLOCK_TX_FILT           0x66U
#define PHY_I2C_BLOCK_BBPLL             0x67U
#define PHY_I2C_BLOCK_RC_REF            0x68U
#define PHY_I2C_BLOCK_BIAS_RC           0x6AU
#define PHY_I2C_BLOCK_TX_PA             0x6BU
#define PHY_I2C_BLOCK_SAR               0x6CU
#define PHY_I2C_BLOCK_ANA_INF           0x77U
#define PHY_I2C_BLOCK_ANA_CLK           0x7CU

#define PHY_I2C_HOST_0                  0U
#define PHY_I2C_HOST_1                  1U
#define PHY_I2C_HOST_2                  2U
#define PHY_I2C_HOST_3                  3U
#define PHY_I2C_HOST_4                  4U

#ifdef __cplusplus
}
#endif
