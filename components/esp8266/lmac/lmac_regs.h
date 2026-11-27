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
// Hardware register map cross-checked against and adapted in part from teatime-os
// (ESP8266 RTOS SDK eagle_soc.h and WDEV silicon specifications also referenced):
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

/**
 * @brief Read a 32-bit WDEV/DPORT/BB MMIO register with Xtensa memw barrier.
 *
 * Marked always_inline so Level-3 NMI code in lmac_nmi.c never emits an out-of-line
 * call into .flash.text while SPI flash cache is disabled.
 *
 * @param addr  Byte address of the 32-bit hardware register.
 * @return      32-bit value read from hardware.
 */
static inline __attribute__((always_inline)) uint32_t lmac_reg_read(uint32_t addr)
{
    uint32_t v;
    __asm__ volatile("memw" ::: "memory");
    v = *(volatile uint32_t *)(uintptr_t)addr;
    return v;
}

/**
 * @brief Write a 32-bit WDEV/DPORT/BB MMIO register with Xtensa memw barrier.
 *
 * Marked always_inline for Level-3 NMI IRAM safety.
 *
 * @param addr  Byte address of the 32-bit hardware register.
 * @param val   32-bit value to write.
 */
static inline __attribute__((always_inline)) void lmac_reg_write(uint32_t addr, uint32_t val)
{
    __asm__ volatile("memw" ::: "memory");
    *(volatile uint32_t *)(uintptr_t)addr = val;
}

/**
 * @brief Set bits in a 32-bit MMIO register (read-modify-write OR).
 *
 * Marked always_inline for Level-3 NMI IRAM safety.
 *
 * @param addr  Byte address of the 32-bit hardware register.
 * @param mask  Bitmask of bits to set.
 */
static inline __attribute__((always_inline)) void lmac_reg_set(uint32_t addr, uint32_t mask)
{
    lmac_reg_write(addr, lmac_reg_read(addr) | mask);
}

/**
 * @brief Clear bits in a 32-bit MMIO register (read-modify-write AND-NOT).
 *
 * Marked always_inline for Level-3 NMI IRAM safety.
 *
 * @param addr  Byte address of the 32-bit hardware register.
 * @param mask  Bitmask of bits to clear.
 */
static inline __attribute__((always_inline)) void lmac_reg_clr(uint32_t addr, uint32_t mask)
{
    lmac_reg_write(addr, lmac_reg_read(addr) & ~mask);
}

/**
 * @brief Update a bitfield in a 32-bit MMIO register by clearing clr_mask and ORing set_mask.
 *
 * Marked always_inline for Level-3 NMI IRAM safety.
 *
 * @param addr      Byte address of the 32-bit hardware register.
 * @param clr_mask  Bitmask of bits to clear first.
 * @param set_mask  Pre-shifted bitfield value to OR into the register.
 */
static inline __attribute__((always_inline)) void lmac_reg_rmw(uint32_t addr, uint32_t clr_mask, uint32_t set_mask)
{
    lmac_reg_write(addr, (lmac_reg_read(addr) & ~clr_mask) | set_mask);
}

/* --------------------------------------------------------------------------
 * System / DPORT / Baseband Bridge Registers
 * -------------------------------------------------------------------------- */

#define LMAC_DPORT_NMI_INT_ENA      0x3FF00000U /* Bit 0 routes WDEV IRQ to Level-3 NMI */
#define LMAC_SYS_WDEV_CLK_STATUS    0x60000710U
#define LMAC_RTC_MAC_RESET_CTRL     0x60000D48U /* Bit 1 cleared to pulse MAC core reset */
#define LMAC_RTC_MAC_RESET_BIT      BIT(1)
#define LMAC_GPIO_BT_COEX_CFG       0x600011F8U
#define LMAC_BB_RX_SNIFFER_FILT     0x60009D44U /* Bits [29,26] = 0x24000000 cleared in sniffer */
#define LMAC_BB_RX_SNIFFER_MASK     0x24000000U

/* --------------------------------------------------------------------------
 * WDEV Bank 0 (0x3FF20000..0x3FF201DB): RX DMA Engine, Bounds & RX BA
 * -------------------------------------------------------------------------- */

#define LMAC_WDEV_BANK0_BASE        0x3FF20000U
#define LMAC_WDEV_BANK0_WORDS       0x77U       /* 119 dwords */

#define LMAC_WDEV_RX_CONF           0x3FF20000U /* &= ~0x200000FF on init */
#define LMAC_WDEV_RX_CONF_INIT_CLR  0x200000FFU
#define LMAC_WDEV_MAC_ENABLE        0x3FF20004U /* Bit 31: master MAC RX/TX enable */
#define LMAC_WDEV_MAC_ENABLE_BIT    0x80000000U
#define LMAC_WDEV_RX_LINK_HEAD      0x3FF20008U /* Circular RX lldesc head */
#define LMAC_WDEV_RX_AMPDU_LINK     0x3FF2000CU /* A-MPDU subframe info lldesc head */
#define LMAC_WDEV_RX_LINK_CLR       0x3FF20010U /* Written 0 on init */
#define LMAC_WDEV_RX_LAST_DESC      0x3FF20014U /* Last HW-completed RX lldesc */
#define LMAC_WDEV_RX_CUR_DESC       0x3FF2001CU /* Current DMA-active RX lldesc (RO) */
#define LMAC_WDEV_RX_STAT_INFO      0x3FF20038U /* Per-frame RX status byte */
#define LMAC_RX_STAT_OK             0x00U       /* Valid legacy/control RX status on SNIFFER_END */
#define LMAC_RX_STAT_SNIFFER_OK     0x41U       /* Valid non-AMPDU frame latched on SNIFFER_END */
#define LMAC_WDEV_RX_FILTER_CTRL    0x3FF2006CU /* Bits 0..2 addr match, bit 4 scan, bits 8..10 */
#define LMAC_WDEV_RX_FILTER_ADDR    0x00000007U /* VIF0 unicast/BSSID/mcast filter bits */
#define LMAC_WDEV_RX_FILTER_SCAN    BIT(4)      /* Admit beacons/probe-resps during scan */
#define LMAC_WDEV_RX_FILTER_KEEP    0xFFFFEFEFU /* Init mask clearing scan/wildcard bits */
#define LMAC_WDEV_RX_FILTER_NORMAL  0x00000707U /* Normal STA+AP hardware filter enable */
#define LMAC_WDEV_RX_BUF_END        0x3FF2007CU /* Main RX frontdata end bound */
#define LMAC_WDEV_RX_DESC_START     0x3FF20080U /* Main RX lldesc array start bound */
#define LMAC_WDEV_RX_AMPDU_END      0x3FF20084U /* A-MPDU RX buf end bound */
#define LMAC_WDEV_RX_AMPDU_START    0x3FF20088U /* A-MPDU RX lldesc start bound */

/* 8 Hardware RX Block-Ack Scoreboards (i = 0..7, reverse stride -0x18) */
#define LMAC_WDEV_RXBA_SLOTS        8U
#define LMAC_WDEV_RXBA_CONF(i)      (0x3FF2014CU - 0x18U * (uint32_t)(i))
#define LMAC_WDEV_RXBA_ADDR_HI(i)   (0x3FF20150U - 0x18U * (uint32_t)(i))
#define LMAC_WDEV_RXBA_ADDR_LO(i)   (0x3FF20154U - 0x18U * (uint32_t)(i))
#define LMAC_WDEV_RXBA_SSN_WIN(i)   (0x3FF20158U - 0x18U * (uint32_t)(i))
#define LMAC_WDEV_RXBA_WIN_SHIFT    13U         /* [19:13]: BA window size */
#define LMAC_WDEV_RXBA_WIN_MASK     0x7FU
#define LMAC_WDEV_RXBA_SSN_MASK     0x0FFFU     /* [11:0]: starting sequence number */
#define LMAC_WDEV_RXBA_CUR_SSN_SH   20U         /* [31:20]: live HW scoreboard SSN (RO) */
#define LMAC_WDEV_RXBA_TID_SHIFT    12U         /* [15:12]: 802.11 QoS TID */
#define LMAC_WDEV_RXBA_TID_MASK     0x0FU
#define LMAC_WDEV_RXBA_CONF_ENABLE  0xC0000005U /* Enable RX BA scoreboard entry */

#define LMAC_WDEV_RX_CTRL2          0x3FF20178U /* Bit 1 set on init/reset */
#define LMAC_WDEV_RX_CTRL2_INIT_BIT BIT(1)
#define LMAC_WDEV_RX_DATASUC_CNT    0x3FF201BCU
#define LMAC_WDEV_RX_END_CNT        0x3FF201C0U
#define LMAC_WDEV_DIAG6             0x3FF201D4U

/* --------------------------------------------------------------------------
 * WDEV Bank 1 (0x3FF20400..0x3FF20423): Auto-ACK/CTS Rate Response LUT
 * -------------------------------------------------------------------------- */

#define LMAC_WDEV_BANK1_BASE        0x3FF20400U
#define LMAC_WDEV_BANK1_WORDS       9U

#define LMAC_WDEV_ACK_RATE_TAB0     0x3FF20400U /* 0x76503210 normal; ch14 CCK remap */
#define LMAC_WDEV_ACK_RATE_TAB1     0x3FF20404U /* 0xBBBBBBBB */
#define LMAC_WDEV_ACK_RATE_TAB2     0x3FF20408U /* 0xBBBBBBBB */
#define LMAC_WDEV_ACK_RATE_NORMAL   0x76503210U /* Standard ch 1..13 CCK+OFDM ACK LUT */
#define LMAC_WDEV_ACK_RATE_CH14     0x32103210U /* Ch 14 (Japan) CCK-only ACK LUT */
#define LMAC_WDEV_ACK_RATE_EXT_DEF  0xBBBBBBBBU /* 6 Mbps OFDM ACK for HT/high rates */
#define LMAC_WDEV_FORCE_ACK_RATE    0x3FF2040CU /* 0x70C07 normal, 0x70B00 force 6M */

/* --------------------------------------------------------------------------
 * WDEV Bank 2 (0x3FF20800..0x3FF2082F): Hardware Crypto Engine
 * -------------------------------------------------------------------------- */

#define LMAC_WDEV_BANK2_BASE        0x3FF20800U
#define LMAC_WDEV_BANK2_WORDS       0x0CU

#define LMAC_WDEV_CRYPTO_CONF0      0x3FF20800U /* VIF 0 (STA) crypto engine control */
#define LMAC_WDEV_CRYPTO_CONF1      0x3FF20804U /* VIF 1 (SoftAP) crypto engine control */
#define LMAC_WDEV_CRYPTO_WAPI       0x3FF20808U /* Cleared to 0 on init */
#define LMAC_WDEV_KEY_VALID_MASK    0x3FF2080CU /* Bits [24:0] enable slots 0..24 */

#define LMAC_CRYPTO_BYPASS          0x00030000U
#define LMAC_CRYPTO_ACTIVE_STA      0x00010103U
#define LMAC_CRYPTO_ACTIVE_SPP      0x00010303U
#define LMAC_CRYPTO_TX_ENC          0x00020000U
#define LMAC_CRYPTO_WEP_BIT         0x10000000U
#define LMAC_CRYPTO_SNIFFER_RAW     0x03000000U
#define LMAC_CRYPTO_ENG_EN          0x00010000U

/* 25 Hardware Key Slots (s = 0..24, 40 B = 10 dwords each) */
#define LMAC_HW_KEY_SLOTS           25U
#define LMAC_KEY_SLOT_STRIDE_BYTES  0x28U       /* 40 B per hardware key slot */
#define LMAC_KEY_SLOT_DATA_WORDS    8U          /* 32 B key material (8 dwords) */
#define LMAC_KEY_SLOT_STA_GTK_BASE  2U          /* STA GTK ping-pong slots 2..3 (WEP 2..5) */
#define LMAC_KEY_SLOT_AP_GTK_BASE   4U          /* SoftAP GTK ping-pong slots 4..5 */
#define LMAC_KEY_SLOT_PTK_BASE      6U          /* Pairwise PTK slots 6..24 (19 slots) */
#define LMAC_KEY_SLOT_INVALID       0xFFU
#define LMAC_KEY_SLOT_BASE(s)       (0x3FF21400U + LMAC_KEY_SLOT_STRIDE_BYTES * (uint32_t)(s))
#define LMAC_KEY_SLOT_ADDR(s)       (LMAC_KEY_SLOT_BASE(s) + 0x00U)
#define LMAC_KEY_SLOT_FLAGS(s)      (LMAC_KEY_SLOT_BASE(s) + 0x04U)
#define LMAC_KEY_SLOT_DATA(s, w)    (LMAC_KEY_SLOT_BASE(s) + 0x08U + 4U * (uint32_t)(w))

/* Hardware key slot FLAGS word bit positions (LMAC_KEY_SLOT_FLAGS) */
#define LMAC_KEY_FLAGS_SUBALG_SHIFT 16U         /* [17:16]: sub-algorithm (WEP40=0, WEP104=1) */
#define LMAC_KEY_FLAGS_ALG_SHIFT    18U         /* [20:18]: cipher algorithm (LMAC_HW_ALG_*) */
#define LMAC_KEY_FLAGS_CLASS_SHIFT  21U         /* [23:21]: key class (PTK/GTK/WEP) */
#define LMAC_KEY_FLAGS_VIF_SHIFT    24U         /* [24]: VIF index (0=STA, 1=SoftAP) */
#define LMAC_KEY_FLAGS_KEYIDX_SHIFT 30U         /* [31:30]: 802.11 key ID (0..3) */

/* Hardware key slot cipher codes in bits [20:18] (sub_alg in [17:16]) */
#define LMAC_HW_ALG_NONE            0U
#define LMAC_HW_ALG_WEP             1U /* sub_alg=0 WEP40, sub_alg=1 WEP104 */
#define LMAC_HW_ALG_TKIP            2U
#define LMAC_HW_ALG_CCMP            3U

/* Hardware key class codes in bits [23:21] */
#define LMAC_HW_KEY_CLASS_PTK       2U
#define LMAC_HW_KEY_CLASS_GTK       6U
#define LMAC_HW_KEY_CLASS_WEP       7U

/* --------------------------------------------------------------------------
 * WDEV Bank 3 (0x3FF20C00..0x3FF20E57): Clock, NMI, Filters & TX Queue
 * -------------------------------------------------------------------------- */

#define LMAC_WDEV_BANK3_BASE        0x3FF20C00U
#define LMAC_WDEV_BANK3_WORDS       0x96U       /* 150 dwords */

#define LMAC_WDEV_TIME              0x3FF20C00U /* Free-running 1 MHz (1 us) MAC clock */
#define LMAC_WDEV_NAV_CONF          0x3FF20C14U /* & 0xFFFFF000 | 0xC00000F0 */
#define LMAC_WDEV_INT_ENA           0x3FF20C18U /* NMI enable mask (shadowed by WDEV_INTEREST_EVENT) */
#define LMAC_WDEV_INT_RAW           0x3FF20C1CU /* Raw unmasked interrupt status */
#define LMAC_WDEV_INT_STATUS        0x3FF20C20U /* Masked interrupt status */
#define LMAC_WDEV_INT_CLR           0x3FF20C24U /* Write-1-to-clear interrupt acknowledge */

/* Verified WDEV interrupt bits (cross-checked: wdev.o.c + eagle_soc.h + teatime-os) */
#define LMAC_INT_SNIFFER_END        BIT(2)      /* 0x00000004: Sniffer RX end / unsupported */
#define LMAC_INT_SNIFFER_START      BIT(3)      /* 0x00000008: Sniffer RX start / A-MPDU */
#define LMAC_INT_RX_DONE            BIT(8)      /* 0x00000100: Main RX frame complete */
#define LMAC_INT_RX_OVF             BIT(9)      /* 0x00000200: RX secondary / overflow */
#define LMAC_INT_TX_DONE            BIT(19)     /* 0x00080000: TX complete / ack/cts/err */
#define LMAC_INT_PANIC0             BIT(20)     /* 0x00100000: Hardware panic 0 */
#define LMAC_INT_RX_MISC            BIT(23)     /* 0x00800000: RX buffer event */
#define LMAC_INT_MACTIM1            BIT(26)     /* 0x04000000: TSF1 / MAC Timer 1 match */
#define LMAC_INT_MACTIM0            BIT(27)     /* 0x08000000: WDEV_TSF0_REACH_INT (task_wdt) */
#define LMAC_INT_PANIC1             BIT(28)     /* 0x10000000: Hardware panic 1 */
#define LMAC_INT_TX_TIMEOUT         BIT(29)     /* 0x20000000: Hardware TX queue timeout */

#define LMAC_WDEV_INTEREST_DEFAULT  0x2C880300U /* Bits 8, 9, 19, 23, 26, 27, 29 */
#define LMAC_WDEV_INTEREST_SNIFFER  (LMAC_INT_SNIFFER_END | LMAC_INT_SNIFFER_START)

/* Dual Hardware BSSID & Unicast MAC Address Filters (u = 0 STA, u = 1 SoftAP) */
#define LMAC_WDEV_BSSID_LO(u)       (0x3FF20C28U + 8U * (uint32_t)(u))
#define LMAC_WDEV_BSSID_HI(u)       (0x3FF20C2CU + 8U * (uint32_t)(u))
#define LMAC_WDEV_BSSID_MASK_LO(u)  (0x3FF20C38U + 8U * (uint32_t)(u))
#define LMAC_WDEV_BSSID_MASK_HI(u)  (0x3FF20C3CU + 8U * (uint32_t)(u))
#define LMAC_WDEV_MAC_LO(u)         (0x3FF20C48U + 8U * (uint32_t)(u))
#define LMAC_WDEV_MAC_HI(u)         (0x3FF20C4CU + 8U * (uint32_t)(u))
#define LMAC_WDEV_MAC_MASK_LO(u)    (0x3FF20C58U + 8U * (uint32_t)(u))
#define LMAC_WDEV_MAC_MASK_HI(u)    (0x3FF20C5CU + 8U * (uint32_t)(u))
#define LMAC_WDEV_MATCH_ENABLE      0x00010000U

#define LMAC_WDEV_SLOT_CONF0        0x3FF20C68U
#define LMAC_WDEV_SLOT_CONF1        0x3FF20C6CU
#define LMAC_WDEV_PHY_CTRL          0x3FF20C70U /* Bit 1: RF/RX path up; bits [7:4] reset */
#define LMAC_WDEV_PHY_CTRL_RF_UP    BIT(1)
#define LMAC_WDEV_PHY_CTRL_RST_MASK 0x000000F0U
#define LMAC_WDEV_TX_ABORT          0x3FF20C74U /* Bits [31:30] TX abort strobe */
#define LMAC_WDEV_TX_ABORT_STROBE   0xC0000000U
#define LMAC_WDEV_TX_CLR            0x3FF20C78U
#define LMAC_WDEV_TX_STATUS         0x3FF20C84U /* [31:28]=cause, [23:16]=sub, [11:8]=slot */
#define LMAC_TX_STATUS_SLOT_SHIFT   8U
#define LMAC_TX_STATUS_SLOT_MASK    0x0FU
#define LMAC_TX_STATUS_SUB_SHIFT    16U
#define LMAC_TX_STATUS_SUB_MASK     0xFFU
#define LMAC_TX_STATUS_CAUSE_SHIFT  28U
#define LMAC_TX_CAUSE_OK            0U          /* ACK received or NO_ACK frame sent */
#define LMAC_TX_CAUSE_ERR1          1U          /* Retryable when sub in {1, 3} */
#define LMAC_TX_CAUSE_CTS_TIMEOUT   2U          /* RTS sent, no CTS received */
#define LMAC_TX_CAUSE_ERR4          4U          /* Retryable when sub in {1, 3} */
#define LMAC_TX_CAUSE_ACK_TIMEOUT   5U          /* Data/mgmt sent, no ACK received */
#define LMAC_TX_SUB_RETRY1          1U
#define LMAC_TX_SUB_RETRY3          3U
#define LMAC_WDEV_RX_OPTION         0x3FF20C88U /* & 0xFFDFBFF7 | 0x8084A000 (bit 18 = protected RX!) */
#define LMAC_WDEV_RX_OPTION_KEEP    0xFFDFBFF7U
#define LMAC_WDEV_RX_OPTION_INIT    0x8084A000U
#define LMAC_WDEV_RX_OPTION_PROT_EN BIT(18)     /* Enables hardware protected-frame RX decryption */
#define LMAC_WDEV_RXTX_OPTION       0x3FF20C90U /* |= 0x8 */
#define LMAC_WDEV_RXTX_OPTION_INIT  BIT(3)
#define LMAC_WDEV_TX_OPTION         0x3FF20C94U /* |= 0x3 (bit 0 = TX/ACK enable; cleared in sniffer) */
#define LMAC_WDEV_TX_OPTION_AUTOACK BIT(0)
#define LMAC_WDEV_TX_OPTION_INIT    0x00000003U
#define LMAC_WDEV_TXQ_TIMEOUT_MASK  0x3FF20CC0U /* Bits [27:16] timed-out TX slots */
#define LMAC_TXQ_TIMEOUT_SHIFT      16U
#define LMAC_TXQ_TIMEOUT_MASK       0x0FFFU
#define LMAC_TXQ_TIMEOUT_CLR_KEEP   0xF000FFFFU

/* Serialized Hardware TX Queue (q = 0: 0x3FF20DC0..0x3FF20DD4; SW priority queues VO/MGMT/BCN ahead of BE/BK) */
#define LMAC_HW_TXQ_COUNT           1U
#define LMAC_HW_TXQ_BASE(q)         (0x3FF20DC0U - 0x18U * (uint32_t)(q))
#define LMAC_TXQ_CONF(q)            (LMAC_HW_TXQ_BASE(q) + 0x00U) /* [21:12] backoff slots */
#define LMAC_TXQ_LINK(q)            (LMAC_HW_TXQ_BASE(q) + 0x04U) /* [17:0] desc, [25:24] ack, [31:30] GO */
#define LMAC_TXQ_RATE(q)            (LMAC_HW_TXQ_BASE(q) + 0x08U) /* [11:0] air, [15:12] rate, [23:16] key, [24] 11n */
#define LMAC_TXQ_HT_PLCP(q)         (LMAC_HW_TXQ_BASE(q) + 0x0CU) /* HT20 MCS + len + GI */
#define LMAC_TXQ_DURATION(q)        (LMAC_HW_TXQ_BASE(q) + 0x10U) /* [31:16] duration_us */
#define LMAC_TXQ_LIFETIME(q)        (LMAC_HW_TXQ_BASE(q) + 0x14U) /* [23:12] lifetime_tu */

#define LMAC_TXQ_DESC_ADDR_MASK     0x0003FFFFU /* Low 18 bits of DRAM descriptor address */
#define LMAC_TXQ_LINK_VALID         0x00200000U
#define LMAC_TXQ_LINK_LEGACY        0x00400000U /* Set for 11b/11g rates (< 0x10) */
#define LMAC_TXQ_LINK_ACK_NORMAL    (1U << 24)
#define LMAC_TXQ_LINK_ACK_BA        (3U << 24)
#define LMAC_TXQ_LINK_USE_RTS       (1U << 27)
#define LMAC_TXQ_LINK_USE_CTS       (1U << 28)
#define LMAC_TXQ_LINK_GO_BIT0       BIT(30)
#define LMAC_TXQ_LINK_GO_BIT1       BIT(31)
#define LMAC_TXQ_LINK_GO            0xC0000000U

#define LMAC_TXQ_CONF_BACKOFF_SHIFT 12U
#define LMAC_TXQ_CONF_BACKOFF_MASK  0x03FFU
#define LMAC_TXQ_RATE_LEN_MASK      0x0FFFU
#define LMAC_TXQ_RATE_CODE_SHIFT    12U
#define LMAC_TXQ_RATE_CODE_MASK     0x0FU
#define LMAC_TXQ_RATE_KEY_SHIFT     16U
#define LMAC_TXQ_RATE_11N_BIT       BIT(24)
#define LMAC_TXQ_HT_PLCP_MCS_MASK   0x07U
#define LMAC_TXQ_HT_PLCP_LEN_SHIFT  8U
#define LMAC_TXQ_HT_PLCP_LGI_FLAGS  0x07000000U /* HT20 Long GI PLCP flags */
#define LMAC_TXQ_HT_PLCP_SGI_FLAGS  0x87000000U /* HT20 Short GI PLCP flags (bit 31) */
#define LMAC_TXQ_DURATION_SHIFT     16U
#define LMAC_TXQ_LIFETIME_SHIFT     12U
#define LMAC_TXQ_LIFETIME_MASK      0x0FFFU

#define LMAC_WDEV_TX_ACK_RSSI       0x3FF20E04U /* Bit 24 valid; [23:16] ACK RSSI */
#define LMAC_TX_ACK_RSSI_VALID_BIT  BIT(24)
#define LMAC_TX_ACK_RSSI_SHIFT      16U
#define LMAC_RSSI_HW_OFFSET_DBM     96          /* Calibrated dBm = raw_rssi - 96 */
#define LMAC_RSSI_UNAVAILABLE       0x7F        /* Sentinel when ACK RSSI is unavailable */
#define LMAC_WDEV_PHY_CONF          0x3FF20E08U /* &= 0xFFFFFF0F on init */
#define LMAC_WDEV_PHY_CONF_INIT_CLR 0x000000F0U
#define LMAC_WDEV_HW_SEQ_RND        0x3FF20E44U /* Hardware PRNG / backoff seed */

/* --------------------------------------------------------------------------
 * WDEV Bank 4 (0x3FF21000..0x3FF2111B): TSF0, TSF1 & Hardware MAC Timers
 * -------------------------------------------------------------------------- */

#define LMAC_WDEV_BANK4_BASE        0x3FF21000U
#define LMAC_WDEV_BANK4_WORDS       0x47U       /* 71 dwords */

#define LMAC_WDEV_TSF0_LO           0x3FF21004U
#define LMAC_WDEV_TSF0_HI           0x3FF21008U
#define LMAC_WDEV_MACTIM0_CONF      0x3FF21014U /* Bit 31 enables MAC Timer 0 */
#define LMAC_WDEV_TSF1_LO           0x3FF21048U
#define LMAC_WDEV_TSF1_HI           0x3FF2104CU
#define LMAC_WDEV_TSF1_CONF         0x3FF21058U /* 0xC4000000 enables TSF1 + TBTT; bit 31 = MacTim1 */
#define LMAC_TSF1_CONF_TBTT_EN      0xC4000000U
#define LMAC_WDEV_TBTT1_LO          0x3FF2105CU
#define LMAC_WDEV_TBTT1_HI          0x3FF21060U
#define LMAC_WDEV_MACTIM0_ARM       0x3FF21098U /* Bit 31 arms TSF0 comparator */
#define LMAC_WDEV_MACTIM0_TARGET_LO 0x3FF2109CU
#define LMAC_WDEV_MACTIM0_TARGET_HI 0x3FF210A0U
#define LMAC_WDEV_MACTIM1_ARM       0x3FF210C8U /* Bit 31 arms TSF1 comparator */
#define LMAC_WDEV_MACTIM1_TARGET_LO 0x3FF210CCU
#define LMAC_WDEV_MACTIM1_TARGET_HI 0x3FF210D0U
#define LMAC_WDEV_RX_TSF_LO         0x3FF210FCU
#define LMAC_WDEV_RX_TSF_HI         0x3FF21100U
#define LMAC_MACTIM_EN_BIT          BIT(31)     /* Enable/arm bit for MACTIM0/1 conf & arm regs */

#ifdef __cplusplus
}
#endif
