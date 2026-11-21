/*
 * Open-source Xtensa LX106 Core HAL for ESP8266 (Call0 ABI)
 *
 * MIT License
 *
 * Copyright (c) 2026 Adam5Wu (ESP8266_RTOS_SDK OSS contributors)
 * Based on Tensilica / Cadence Xtensa HAL interface definitions
 * (<xtensa/hal.h>, <xtensa/coreasm.h>, <xtensa/config/core-isa.h>).
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <xtensa/coreasm.h>
#include <xtensa/specreg.h>

/*
 * Place every HAL routine in its own .iram1.text.<name> section so that:
 *   1. All linked HAL routines reside in IRAM (safe to call from ISRs and
 *      flash-disabled contexts such as PendSV -> xthal_set_intset and
 *      ets_delay_us -> xthal_get_ccount).
 *   2. --gc-sections discards every unreferenced routine with zero IRAM cost.
 */
.macro XTHAL_FUNC name
    .section .iram1.text.\name,"ax",@progbits
    .align 4
    .global \name
    .type \name,@function
\name:
.endm

.macro XTHAL_ENDFUNC name
    .size \name, . - \name
.endm

/* --------------------------------------------------------------------------
 * Core Cycle Counter & Compare Timers
 * -------------------------------------------------------------------------- */

/* unsigned xthal_get_ccount(void) */
XTHAL_FUNC xthal_get_ccount
#if XCHAL_HAVE_CCOUNT
    rsr.ccount  a2
#else
    movi.n      a2, 0
#endif
    ret.n
XTHAL_ENDFUNC xthal_get_ccount

/* unsigned xthal_get_ccompare(int n) */
XTHAL_FUNC xthal_get_ccompare
#if XCHAL_NUM_TIMERS > 0
    bnez.n      a2, 1f
    rsr.ccompare0 a2
    ret.n
1:
#endif
    movi.n      a2, 0
    ret.n
XTHAL_ENDFUNC xthal_get_ccompare

/* void xthal_set_ccompare(int n, unsigned val) */
XTHAL_FUNC xthal_set_ccompare
#if XCHAL_NUM_TIMERS > 0
    bnez.n      a2, 1f
    wsr.ccompare0 a3
    isync
1:
#endif
    ret.n
XTHAL_ENDFUNC xthal_set_ccompare

/* --------------------------------------------------------------------------
 * Interrupt Control Special Registers
 * -------------------------------------------------------------------------- */

/* void xthal_set_intset(unsigned mask) */
XTHAL_FUNC xthal_set_intset
#if XCHAL_HAVE_INTERRUPTS
    wsr.intset  a2
#endif
    ret.n
XTHAL_ENDFUNC xthal_set_intset

/* void xthal_set_intclear(unsigned mask) */
XTHAL_FUNC xthal_set_intclear
#if XCHAL_HAVE_INTERRUPTS
    wsr.intclear a2
#endif
    ret.n
XTHAL_ENDFUNC xthal_set_intclear

/* unsigned xthal_get_intenable(void) */
XTHAL_FUNC xthal_get_intenable
#if XCHAL_HAVE_INTERRUPTS
    rsr.intenable a2
#else
    movi.n      a2, 0
#endif
    ret.n
XTHAL_ENDFUNC xthal_get_intenable

/* void xthal_set_intenable(unsigned mask) */
XTHAL_FUNC xthal_set_intenable
#if XCHAL_HAVE_INTERRUPTS
    wsr.intenable a2
#endif
    ret.n
XTHAL_ENDFUNC xthal_set_intenable

/* unsigned xthal_get_interrupt(void) / xthal_get_intread(void) */
XTHAL_FUNC xthal_get_interrupt
    .global xthal_get_intread
    .set xthal_get_intread, xthal_get_interrupt
#if XCHAL_HAVE_INTERRUPTS
    rsr.interrupt a2
#else
    movi.n      a2, 0
#endif
    ret.n
XTHAL_ENDFUNC xthal_get_interrupt

/* --------------------------------------------------------------------------
 * Processor ID
 * -------------------------------------------------------------------------- */

/* unsigned xthal_get_prid(void) */
XTHAL_FUNC xthal_get_prid
#if XCHAL_HAVE_PRID
    rsr.prid    a2
#else
    movi.n      a2, 0
#endif
    ret.n
XTHAL_ENDFUNC xthal_get_prid

/* --------------------------------------------------------------------------
 * Register Window Spill & Extra/Coprocessor State (No-ops on LX106 Call0)
 * -------------------------------------------------------------------------- */

/* void xthal_window_spill(void) */
XTHAL_FUNC xthal_window_spill
    ret.n
XTHAL_ENDFUNC xthal_window_spill

/* void xthal_window_spill_nw(void) / xthal_spill_registers_into_stack_nw */
XTHAL_FUNC xthal_window_spill_nw
    .global xthal_spill_registers_into_stack_nw
    .set xthal_spill_registers_into_stack_nw, xthal_window_spill_nw
    movi.n      a2, 0
    ret.n
XTHAL_ENDFUNC xthal_window_spill_nw

/* void xthal_save_extra(void *base) */
XTHAL_FUNC xthal_save_extra
    ret.n
XTHAL_ENDFUNC xthal_save_extra

/* void xthal_save_extra_nw(void *base) */
XTHAL_FUNC xthal_save_extra_nw
    ret.n
XTHAL_ENDFUNC xthal_save_extra_nw

/* void xthal_restore_extra(void *base) */
XTHAL_FUNC xthal_restore_extra
    ret.n
XTHAL_ENDFUNC xthal_restore_extra

/* void xthal_restore_extra_nw(void *base) */
XTHAL_FUNC xthal_restore_extra_nw
    ret.n
XTHAL_ENDFUNC xthal_restore_extra_nw

/* --------------------------------------------------------------------------
 * Cache / Pipeline Synchronization Helpers (LX106 has no Xtensa L1 cache)
 * -------------------------------------------------------------------------- */

/* void xthal_icache_sync(void) / xthal_icache_sync_nw(void) */
XTHAL_FUNC xthal_icache_sync
    .global xthal_icache_sync_nw
    .set xthal_icache_sync_nw, xthal_icache_sync
    isync
    ret.n
XTHAL_ENDFUNC xthal_icache_sync

/* void xthal_dcache_sync(void) / xthal_dcache_sync_nw(void) */
XTHAL_FUNC xthal_dcache_sync
    .global xthal_dcache_sync_nw
    .set xthal_dcache_sync_nw, xthal_dcache_sync
    ret.n
XTHAL_ENDFUNC xthal_dcache_sync

/* void xthal_icache_all_invalidate(void) / xthal_icache_all_invalidate_nw(void) */
XTHAL_FUNC xthal_icache_all_invalidate
    .global xthal_icache_all_invalidate_nw
    .set xthal_icache_all_invalidate_nw, xthal_icache_all_invalidate
    ret.n
XTHAL_ENDFUNC xthal_icache_all_invalidate

/* void xthal_dcache_all_invalidate(void) / xthal_dcache_all_invalidate_nw(void) */
XTHAL_FUNC xthal_dcache_all_invalidate
    .global xthal_dcache_all_invalidate_nw
    .set xthal_dcache_all_invalidate_nw, xthal_dcache_all_invalidate
    ret.n
XTHAL_ENDFUNC xthal_dcache_all_invalidate
