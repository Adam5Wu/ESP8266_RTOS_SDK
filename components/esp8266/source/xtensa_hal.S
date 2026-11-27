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

/*
 * Call0 ABI Register Convention (Xtensa LX106):
 *   a2..a7  : incoming arguments (a2 = arg0, a3 = arg1, ...)
 *   a2      : return value
 *   a0      : return address (preserved by leaf routines using ret.n)
 *   a1      : stack pointer
 *   a12..a15: callee-saved
 *
 * Architectural notes for ESP8266 LX106:
 *   - No windowed register option -> window spill routines are no-ops.
 *   - No floating-point / coprocessor / TIE extra state -> save/restore extra are no-ops.
 *   - No Xtensa internal L1 I-cache or D-cache (SPI flash cache is an external
 *     memory-mapped MMIO controller managed separately) -> cache ops are no-ops
 *     except xthal_icache_sync which emits an instruction-pipeline `isync`.
 *   - Exactly one timer comparator (CCOMPARE0, XCHAL_NUM_TIMERS == 1).
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

/*
 * unsigned xthal_get_ccount(void)
 * Read the 32-bit CPU cycle counter (CCOUNT special register).
 * Output: a2 = current cycle count (0 if XCHAL_HAVE_CCOUNT == 0).
 */
XTHAL_FUNC xthal_get_ccount
#if XCHAL_HAVE_CCOUNT
    rsr.ccount  a2
#else
    movi.n      a2, 0
#endif
    ret.n
XTHAL_ENDFUNC xthal_get_ccount

/*
 * unsigned xthal_get_ccompare(int n)
 * Read timer comparator `n`. LX106 only implements CCOMPARE0 (n == 0).
 * Input:  a2 = comparator index `n`.
 * Output: a2 = CCOMPARE0 value when n == 0, otherwise 0.
 */
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

/*
 * void xthal_set_ccompare(int n, unsigned val)
 * Write timer comparator `n` and synchronize the pipeline (`isync`).
 * Writing CCOMPARE0 also clears the pending timer0 interrupt bit.
 * Input:  a2 = comparator index `n` (only n == 0 is implemented on LX106),
 *         a3 = new comparator target `val`.
 */
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

/*
 * void xthal_set_intset(unsigned mask)
 * Assert software-triggerable interrupt bits specified in `mask` via INTSET.
 * Input:  a2 = bitmask of interrupts to set.
 */
XTHAL_FUNC xthal_set_intset
#if XCHAL_HAVE_INTERRUPTS
    wsr.intset  a2
#endif
    ret.n
XTHAL_ENDFUNC xthal_set_intset

/*
 * void xthal_set_intclear(unsigned mask)
 * Clear pending edge-triggered or software interrupt bits in `mask` via INTCLEAR.
 * Input:  a2 = bitmask of interrupts to clear.
 */
XTHAL_FUNC xthal_set_intclear
#if XCHAL_HAVE_INTERRUPTS
    wsr.intclear a2
#endif
    ret.n
XTHAL_ENDFUNC xthal_set_intclear

/*
 * unsigned xthal_get_intenable(void)
 * Read the current interrupt enable mask from INTENABLE.
 * Output: a2 = bitmask of currently enabled interrupts.
 */
XTHAL_FUNC xthal_get_intenable
#if XCHAL_HAVE_INTERRUPTS
    rsr.intenable a2
#else
    movi.n      a2, 0
#endif
    ret.n
XTHAL_ENDFUNC xthal_get_intenable

/*
 * void xthal_set_intenable(unsigned mask)
 * Replace the interrupt enable mask in INTENABLE.
 * Input:  a2 = new interrupt enable bitmask.
 */
XTHAL_FUNC xthal_set_intenable
#if XCHAL_HAVE_INTERRUPTS
    wsr.intenable a2
#endif
    ret.n
XTHAL_ENDFUNC xthal_set_intenable

/*
 * unsigned xthal_get_interrupt(void) / xthal_get_intread(void)
 * Read the raw pending interrupt status bitmask from INTERRUPT.
 * Output: a2 = bitmask of currently pending interrupts.
 */
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

/*
 * unsigned xthal_get_prid(void)
 * Read the core Processor ID register (always 0 on single-core LX106).
 * Output: a2 = PRID register value (0 if XCHAL_HAVE_PRID == 0).
 */
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

/*
 * void xthal_window_spill(void)
 * No-op on LX106 (Call0 ABI has no register windows to spill).
 */
XTHAL_FUNC xthal_window_spill
    ret.n
XTHAL_ENDFUNC xthal_window_spill

/*
 * void xthal_window_spill_nw(void) / xthal_spill_registers_into_stack_nw
 * Non-windowed entry alias for xthal_window_spill(); zeroes a2 per HAL ABI.
 * Output: a2 = 0.
 */
XTHAL_FUNC xthal_window_spill_nw
    .global xthal_spill_registers_into_stack_nw
    .set xthal_spill_registers_into_stack_nw, xthal_window_spill_nw
    movi.n      a2, 0
    ret.n
XTHAL_ENDFUNC xthal_window_spill_nw

/*
 * void xthal_save_extra(void *base)
 * No-op on LX106 (no extra/TIE architectural state outside general registers).
 * Input:  a2 = unused save-area pointer `base`.
 */
XTHAL_FUNC xthal_save_extra
    ret.n
XTHAL_ENDFUNC xthal_save_extra

/*
 * void xthal_save_extra_nw(void *base)
 * Non-windowed entry point for xthal_save_extra() (no-op on LX106).
 * Input:  a2 = unused save-area pointer `base`.
 */
XTHAL_FUNC xthal_save_extra_nw
    ret.n
XTHAL_ENDFUNC xthal_save_extra_nw

/*
 * void xthal_restore_extra(void *base)
 * No-op on LX106 (no extra/TIE architectural state outside general registers).
 * Input:  a2 = unused save-area pointer `base`.
 */
XTHAL_FUNC xthal_restore_extra
    ret.n
XTHAL_ENDFUNC xthal_restore_extra

/*
 * void xthal_restore_extra_nw(void *base)
 * Non-windowed entry point for xthal_restore_extra() (no-op on LX106).
 * Input:  a2 = unused save-area pointer `base`.
 */
XTHAL_FUNC xthal_restore_extra_nw
    ret.n
XTHAL_ENDFUNC xthal_restore_extra_nw

/* --------------------------------------------------------------------------
 * Cache / Pipeline Synchronization Helpers (LX106 has no Xtensa L1 cache)
 * -------------------------------------------------------------------------- */

/*
 * void xthal_icache_sync(void) / xthal_icache_sync_nw(void)
 * Flush the instruction fetch pipeline via `isync` so subsequent fetches see
 * prior instruction-memory or special-register updates.
 */
XTHAL_FUNC xthal_icache_sync
    .global xthal_icache_sync_nw
    .set xthal_icache_sync_nw, xthal_icache_sync
    isync
    ret.n
XTHAL_ENDFUNC xthal_icache_sync

/*
 * void xthal_dcache_sync(void) / xthal_dcache_sync_nw(void)
 * No-op on LX106 (no Xtensa L1 data cache).
 */
XTHAL_FUNC xthal_dcache_sync
    .global xthal_dcache_sync_nw
    .set xthal_dcache_sync_nw, xthal_dcache_sync
    ret.n
XTHAL_ENDFUNC xthal_dcache_sync

/*
 * void xthal_icache_all_invalidate(void) / xthal_icache_all_invalidate_nw(void)
 * No-op on LX106 (no Xtensa L1 instruction cache; SPI flash cache is external).
 */
XTHAL_FUNC xthal_icache_all_invalidate
    .global xthal_icache_all_invalidate_nw
    .set xthal_icache_all_invalidate_nw, xthal_icache_all_invalidate
    ret.n
XTHAL_ENDFUNC xthal_icache_all_invalidate

/*
 * void xthal_dcache_all_invalidate(void) / xthal_dcache_all_invalidate_nw(void)
 * No-op on LX106 (no Xtensa L1 data cache).
 */
XTHAL_FUNC xthal_dcache_all_invalidate
    .global xthal_dcache_all_invalidate_nw
    .set xthal_dcache_all_invalidate_nw, xthal_dcache_all_invalidate
    ret.n
XTHAL_ENDFUNC xthal_dcache_all_invalidate
