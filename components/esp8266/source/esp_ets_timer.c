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

/**
 * @file esp_ets_timer.c
 * @brief Open-source FRC2-backed ETS / OS software timer scheduler for ESP8266.
 *
 * Implements the linked-list software timer queue driven by hardware timer
 * FRC2 (80 MHz APB / 16 prescaler = 5 MHz tick rate, 32-bit up-counter with
 * match-alarm comparator on Xtensa IRQ 10).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sdkconfig.h"
#include "esp_log.h"
#include "esp8266/eagle_soc.h"
#include "esp8266/timer_register.h"
#include "rom/ets_sys.h"
#include "FreeRTOS.h"

#undef ets_timer_setfn
#undef ets_timer_disarm
#undef ets_timer_arm
#undef ets_timer_arm_us

_Static_assert(sizeof(ETSTimer) == 28, "ETSTimer ABI");

#if defined(CONFIG_ESP8266_OSS_PHY_WIFI)
extern int esp_wifi_post_timer_from_isr(void);
#elif defined(CONFIG_ESP8266_VENDOR_PHY_WIFI)
extern int pp_post_from_isr(uint32_t sig, uint32_t par);
#endif

void ets_timer_setfn(ETSTimer *ptimer, ETSTimerFunc *pfunction, void *parg);
void ets_timer_disarm(ETSTimer *ptimer);
void ets_timer_arm_ms_us(ETSTimer *ptimer, uint32_t time_val, bool repeat_flag, bool is_ms);
void ets_timer_arm_us(ETSTimer *ptimer, uint32_t u_seconds, bool repeat_flag);
void os_timer_arm_us(os_timer_t *ptimer, uint32_t u_seconds, bool repeat_flag);
void ets_timer_arm(ETSTimer *ptimer, uint32_t milliseconds, bool repeat_flag);
bool ets_timer_proc_one(void);
void ets_timer_proc(void);
void ets_timer_init(void);

/** Sentinel pointer written to @c timer_next when a timer is not queued. */
#define ETSTIMER_DISARMED               ((ETSTimer *)(uintptr_t)0xFFFFFFFFU)

/** Xtensa interrupt level used to protect timer-list mutations against FRC2 ISR. */
#define ETS_TIMER_CRIT_INTLEVEL         3

/** Hardware IRQ line for FRC2 match alarm (`ETS_FRC_TIMER2_INUM`). */
#define ETS_TIMER_FRC2_IRQ_NUM          10

/** `FRC2_CTRL` init value: enable timer (BIT7) + divide-by-16 prescaler (0x04) = 5 MHz. */
#define ETS_TIMER_FRC2_CTRL_5MHZ_EN     0x84U

/** `FRC2_CTRL` parked value: disable timer (BIT7=0) while retaining /16 prescaler (0x04). */
#define ETS_TIMER_FRC2_CTRL_5MHZ_DIS    0x04U

/** Park offset (~429 s at 5 MHz) keeping `FRC2_ALARM` safely ahead of `FRC2_COUNT` while idle. */
#define ETS_FRC2_PARK_OFFSET_TICKS      0x7FFFFFFFU

/** `EDGE_INT_ENABLE_REG` bit enabling edge-triggered interrupts from FRC2. */
#define ETS_TIMER_FRC2_EDGE_INT_BIT     BIT(2)

/** Fallback margin (100 ticks = 20 us at 5 MHz) if an alarm target is already in the past. */
#define ETS_FRC2_PAST_DUE_MARGIN_TICKS  100U

/** Guard window (0x500 = 1280 ticks = 256 us) below which an alarm is pushed out to avoid missing match. */
#define ETS_FRC2_INTR_GUARD_TICKS       0x500

/** Deferral offset (0x540 = 1344 ticks = 268.8 us) added to near-future deadlines inside the guard window. */
#define ETS_FRC2_INTR_DEFER_TICKS       0x540U

/** Maximum arm duration in milliseconds (~428.5 s; keeps 5 MHz ticks below INT32_MAX for signed wrap math). */
#define ETS_TIMER_MAX_MS                0x000689D0U

/** Maximum arm duration in microseconds (~428.5 s; 0x198A5759 * 5 < 2^31). */
#define ETS_TIMER_MAX_US                0x198A5759U

/** Legacy vendor Wi-Fi `pp` task signal ID posted by the FRC2 ISR. */
#define ETS_TIMER_VENDOR_PP_SIG         0x10U

/** SDK-compatible panic tag codes matching the original ROM/libmain assertions. */
#define ETS_TIMER_PANIC_NULL_PTR        162U
#define ETS_TIMER_PANIC_SELF_CYCLE      198U
#define ETS_TIMER_PANIC_DONE_ARMED      307U

/** Head of the singly-linked armed timer queue, sorted by ascending expiration tick. */
static ETSTimer *s_timer_list = NULL;

/**
 * @brief Program the FRC2 hardware alarm comparator and enable FRC2, clamping past-due targets.
 *
 * Because FRC2 is a free-running 32-bit up-counter that only fires on exact
 * equality (`FRC2_COUNT == FRC2_ALARM`), programming a target already at or
 * behind `now` would stall for a full 2^32-tick (~858 s) wrap. When
 * `(int32_t)(alarm_ticks - now) <= 0`, the alarm is pushed 100 ticks (20 us)
 * into the future so the interrupt fires promptly. Enables FRC2 at 5 MHz
 * (`ETS_TIMER_FRC2_CTRL_5MHZ_EN`) after latching `FRC2_ALARM`.
 *
 * @param alarm_ticks Desired 5 MHz FRC2 match value.
 */
static void ets_rtc_timer_arm(uint32_t alarm_ticks)
{
    uint32_t now = REG_READ(FRC2_COUNT_ADDRESS);
    uint32_t target = alarm_ticks;

    if ((int32_t)(alarm_ticks - now) <= 0) {
        target = REG_READ(FRC2_COUNT_ADDRESS) + ETS_FRC2_PAST_DUE_MARGIN_TICKS;
    }
    REG_WRITE(FRC2_ALARM_ADDRESS, target);
    REG_WRITE(FRC2_CTRL_ADDRESS, ETS_TIMER_FRC2_CTRL_5MHZ_EN);
}

/**
 * @brief Schedule the next FRC2 match interrupt for a software timer deadline.
 *
 * Applies a 256 us (`0x500` tick) guard band so that deadlines imminent during
 * critical-section exit cannot slip past the comparator before `FRC2_ALARM` is
 * latched.
 *
 * @param expire_ticks Absolute 5 MHz FRC2 tick count at which the head timer expires.
 */
static void ets_timer_intr_set(uint32_t expire_ticks)
{
    uint32_t now = REG_READ(FRC2_COUNT_ADDRESS);
    int32_t diff = (int32_t)(expire_ticks - now);
    uint32_t alarm;

    if (diff > ETS_FRC2_INTR_GUARD_TICKS) {
        alarm = expire_ticks;
    } else if (diff >= 1) {
        alarm = expire_ticks + ETS_FRC2_INTR_DEFER_TICKS;
    } else {
        alarm = now + (uint32_t)ETS_FRC2_INTR_GUARD_TICKS;
    }
    ets_rtc_timer_arm(alarm);
}

/**
 * @brief FRC2 hardware timer ISR (IRQ 10).
 *
 * Defers software timer callback execution out of interrupt context by posting
 * a timer-processing event to the Wi-Fi / system timer worker task.
 *
 * @param arg Unused ISR registration argument.
 */
static void ets_timer_handler_dsr(void *arg)
{
    (void)arg;
#if defined(CONFIG_ESP8266_OSS_PHY_WIFI)
    (void)esp_wifi_post_timer_from_isr();
#elif defined(CONFIG_ESP8266_VENDOR_PHY_WIFI)
    (void)pp_post_from_isr(ETS_TIMER_VENDOR_PP_SIG, 0U);
#endif
}

/**
 * @brief Insert a timer node into the sorted active queue and reprogram FRC2 if it becomes head.
 *
 * Must be called with interrupts masked at level >= @c ETS_TIMER_CRIT_INTLEVEL.
 * Ordering uses signed 32-bit modular difference `(int32_t)(a - b)` so 32-bit
 * counter wrap-around is handled seamlessly for all durations < 2^31 ticks.
 *
 * @param expire_ticks Absolute 5 MHz FRC2 expiration timestamp.
 * @param ptimer       Timer object to insert (must be non-NULL; halts on NULL or self-loop).
 */
static void timer_insert(uint32_t expire_ticks, ETSTimer *ptimer)
{
    ETSTimer *prev = NULL;
    ETSTimer *curr;

    if (ptimer == NULL) {
        ets_printf("%s %u\n", "tim", ETS_TIMER_PANIC_NULL_PTR);
        for (;;) {
        }
    }

    for (curr = s_timer_list; curr != NULL; prev = curr, curr = curr->timer_next) {
        if ((int32_t)(expire_ticks - curr->timer_expire) < 1) {
            break;
        }
    }

    /* Defensive handling if the same node is already present at the insertion slot */
    if (curr == ptimer) {
        curr->timer_expire = expire_ticks;
        ets_printf("T_R:%p\n", (void *)curr);
        if (curr == s_timer_list) {
            ets_timer_intr_set(expire_ticks);
        }
        return;
    }

    ptimer->timer_next = curr;
    ptimer->timer_expire = expire_ticks;
    if (prev != NULL) {
        prev->timer_next = ptimer;
    } else {
        s_timer_list = ptimer;
        ets_timer_intr_set(expire_ticks);
    }

    if (ptimer->timer_next == ptimer) {
        ets_printf("%s %u\n", "tim", ETS_TIMER_PANIC_SELF_CYCLE);
        for (;;) {
        }
    }
}

/**
 * @brief Initialize a timer handle with its callback function and user argument.
 *
 * Marks the timer as disarmed (`ETSTIMER_DISARMED`) and clears expiration and
 * repeat-period fields under a level-3 interrupt lock. Must be called before
 * arming the timer for the first time (and never while the timer is armed).
 *
 * @param ptimer    Pointer to the caller-allocated `ETSTimer` structure.
 * @param pfunction Callback invoked when the timer expires.
 * @param parg      Opaque argument passed to @p pfunction.
 */
void ets_timer_setfn(ETSTimer *ptimer, ETSTimerFunc *pfunction, void *parg)
{
    unsigned ps = XTOS_SET_INTLEVEL(ETS_TIMER_CRIT_INTLEVEL);

    ptimer->timer_next = ETSTIMER_DISARMED;
    ptimer->timer_expire = 0U;
    ptimer->timer_period = 0U;
    ptimer->timer_func = pfunction;
    ptimer->timer_arg = parg;

    XTOS_RESTORE_INTLEVEL(ps);
}

void os_timer_setfn(os_timer_t *ptimer, os_timer_func_t *pfunction, void *parg)
    __attribute__((alias("ets_timer_setfn")));

/**
 * @brief Disarm a timer, unlinking it from the active queue if currently armed.
 *
 * Safe to call on an already disarmed timer or from inside the timer's own
 * callback (clearing `timer_period` prevents periodic re-arming). If the
 * removed timer was at the head of the queue, FRC2 is reprogrammed for the new
 * head timer, or parked/disabled (`ETS_TIMER_FRC2_CTRL_5MHZ_DIS`) with its
 * alarm pushed `ETS_FRC2_PARK_OFFSET_TICKS` ahead and pending IRQ cleared when
 * the queue becomes empty.
 *
 * @param ptimer Pointer to the timer to disarm.
 */
void ets_timer_disarm(ETSTimer *ptimer)
{
    unsigned ps = XTOS_SET_INTLEVEL(ETS_TIMER_CRIT_INTLEVEL);
    ETSTimer *prev = NULL;
    ETSTimer *curr = s_timer_list;

    while (curr != NULL) {
        if (curr == ptimer) {
            if (prev != NULL) {
                prev->timer_next = ptimer->timer_next;
            } else {
                s_timer_list = ptimer->timer_next;
                if (s_timer_list != NULL) {
                    ets_timer_intr_set(s_timer_list->timer_expire);
                } else {
                    REG_WRITE(FRC2_CTRL_ADDRESS, ETS_TIMER_FRC2_CTRL_5MHZ_DIS);
                    REG_WRITE(FRC2_ALARM_ADDRESS,
                              REG_READ(FRC2_COUNT_ADDRESS) + ETS_FRC2_PARK_OFFSET_TICKS);
                    REG_WRITE(FRC2_INT_ADDRESS, TIMER_FRC2_INT_CLR_MASK);
                }
            }
            break;
        }
        prev = curr;
        curr = curr->timer_next;
    }

    ptimer->timer_next = ETSTIMER_DISARMED;
    ptimer->timer_period = 0U;

    XTOS_RESTORE_INTLEVEL(ps);
}

void os_timer_disarm(os_timer_t *ptimer)
    __attribute__((alias("ets_timer_disarm")));

/**
 * @brief Arm a software timer with either millisecond or microsecond granularity.
 *
 * If the timer is already armed, it is disarmed first. Validates the callback
 * pointer and caps the duration so that the converted 5 MHz tick count fits
 * strictly inside the signed 32-bit wrap-safe half-range (`< 2^31` ticks).
 *
 * @param ptimer      Timer previously initialized with ets_timer_setfn().
 * @param time_val    Delay duration in milliseconds (`is_ms == true`) or microseconds (`is_ms == false`).
 * @param repeat_flag If true, automatically re-arms with the same period after each expiry.
 * @param is_ms       True when @p time_val is in milliseconds; false for microseconds.
 */
void ets_timer_arm_ms_us(ETSTimer *ptimer, uint32_t time_val, bool repeat_flag, bool is_ms)
{
    uint32_t us;
    uint32_t ticks;
    unsigned ps;

    if (ptimer->timer_next != ETSTIMER_DISARMED) {
        ets_timer_disarm(ptimer);
    }

    if (ptimer->timer_func == NULL) {
        esp_log_write(ESP_LOG_ERROR, "wifi", "timer:%p cb is null", (void *)ptimer);
        return;
    }

    if (is_ms) {
        if (time_val > ETS_TIMER_MAX_MS) {
            esp_log_write(ESP_LOG_ERROR, "wifi",
                          "err1,exceed max time value,max val is %08X", ETS_TIMER_MAX_MS);
            return;
        }
        us = time_val * 1000U;
    } else {
        if (time_val > ETS_TIMER_MAX_US) {
            esp_log_write(ESP_LOG_ERROR, "wifi",
                          "err2,exceed max time value,max val is %08X", ETS_TIMER_MAX_US);
            return;
        }
        us = time_val;
    }

    /*
     * Exact 5 MHz FRC2 ticks = us * 5 without 32-bit intermediate overflow:
     * decompose us = 4*q + r, so 5*us = 20*q + 5*r.
     */
    ticks = (us >> 2) * 20U + (us & 3U) * 5U;

    if (repeat_flag) {
        ptimer->timer_period = ticks;
    }

    ps = XTOS_SET_INTLEVEL(ETS_TIMER_CRIT_INTLEVEL);
    if (ptimer->timer_next != ETSTIMER_DISARMED) {
        ets_timer_disarm(ptimer);
    }
    timer_insert(REG_READ(FRC2_COUNT_ADDRESS) + ticks, ptimer);
    XTOS_RESTORE_INTLEVEL(ps);
}

/**
 * @brief Arm a software timer with a microsecond timeout.
 *
 * @param ptimer      Timer previously initialized with ets_timer_setfn().
 * @param u_seconds   Timeout in microseconds (max @c ETS_TIMER_MAX_US).
 * @param repeat_flag True for periodic re-arming, false for one-shot.
 */
void ets_timer_arm_us(ETSTimer *ptimer, uint32_t u_seconds, bool repeat_flag)
{
    ets_timer_arm_ms_us(ptimer, u_seconds, repeat_flag, false);
}

void os_timer_arm_us(os_timer_t *ptimer, uint32_t u_seconds, bool repeat_flag)
    __attribute__((alias("ets_timer_arm_us")));

/**
 * @brief Arm a software timer with a millisecond timeout.
 *
 * @param ptimer       Timer previously initialized with ets_timer_setfn().
 * @param milliseconds Timeout in milliseconds (max @c ETS_TIMER_MAX_MS).
 * @param repeat_flag  True for periodic re-arming, false for one-shot.
 */
void ets_timer_arm(ETSTimer *ptimer, uint32_t milliseconds, bool repeat_flag)
{
    ets_timer_arm_ms_us(ptimer, milliseconds, repeat_flag, true);
}

void os_timer_arm(os_timer_t *ptimer, uint32_t milliseconds, bool repeat_flag)
    __attribute__((alias("ets_timer_arm")));

/**
 * @brief Tear down a disarmed timer and clear its callback registration.
 *
 * Halts with panic tag `"tim 307"` if called while the timer is still linked
 * in the active queue (caller must call ets_timer_disarm() first).
 *
 * @param ptimer Pointer to the disarmed timer to finalize.
 */
void ets_timer_done(ETSTimer *ptimer)
{
    if (ptimer->timer_next != ETSTIMER_DISARMED) {
        ets_printf("%s %u\n", "tim", ETS_TIMER_PANIC_DONE_ARMED);
        for (;;) {
        }
    }
    ets_timer_setfn(ptimer, NULL, NULL);
}

/**
 * @brief Pop and execute at most one expired timer from the head of the queue.
 *
 * Invokes the callback with interrupts unmasked so callbacks may freely arm or
 * disarm timers (including themselves). After the callback returns, periodic
 * timers that were neither disarmed nor re-armed by the callback are reinserted
 * at `old_expire + timer_period` to prevent cumulative phase drift. When the
 * queue drains empty, parks and disables FRC2 (`ETS_TIMER_FRC2_CTRL_5MHZ_DIS`)
 * to prevent spurious interrupts on 32-bit counter wrap.
 *
 * @return True if another timer at the head of the queue is already due;
 *         false when the queue is empty (FRC2 parked) or the next timer is
 *         still in the future (FRC2 armed for that next deadline).
 */
bool ets_timer_proc_one(void)
{
    unsigned ps = XTOS_SET_INTLEVEL(ETS_TIMER_CRIT_INTLEVEL);
    ETSTimer *head = s_timer_list;

    if (head == NULL) {
        XTOS_RESTORE_INTLEVEL(ps);
        return false;
    }

    uint32_t now = REG_READ(FRC2_COUNT_ADDRESS);
    if ((int32_t)(head->timer_expire - now) >= 1) {
        ets_timer_intr_set(head->timer_expire);
        XTOS_RESTORE_INTLEVEL(ps);
        return false;
    }

    s_timer_list = head->timer_next;
    head->timer_next = ETSTIMER_DISARMED;
    ETSTimerFunc *cb = head->timer_func;
    void *arg = head->timer_arg;
    XTOS_RESTORE_INTLEVEL(ps);

    cb(arg);

    ps = XTOS_SET_INTLEVEL(ETS_TIMER_CRIT_INTLEVEL);
    /* Re-arm periodic timer only if the callback did not disarm or manually re-arm it */
    if (head->timer_next == ETSTIMER_DISARMED && head->timer_period != 0U) {
        head->timer_expire += head->timer_period;
        timer_insert(head->timer_expire, head);
    }

    bool more = false;
    if (s_timer_list != NULL) {
        uint32_t now2 = REG_READ(FRC2_COUNT_ADDRESS);
        if ((int32_t)(s_timer_list->timer_expire - now2) < 1) {
            more = true;
        } else {
            ets_timer_intr_set(s_timer_list->timer_expire);
        }
    } else {
        REG_WRITE(FRC2_CTRL_ADDRESS, ETS_TIMER_FRC2_CTRL_5MHZ_DIS);
        REG_WRITE(FRC2_ALARM_ADDRESS,
                  REG_READ(FRC2_COUNT_ADDRESS) + ETS_FRC2_PARK_OFFSET_TICKS);
        REG_WRITE(FRC2_INT_ADDRESS, TIMER_FRC2_INT_CLR_MASK);
    }
    XTOS_RESTORE_INTLEVEL(ps);
    return more;
}

/**
 * @brief Drain and dispatch all currently expired software timers.
 */
void ets_timer_proc(void)
{
    while (ets_timer_proc_one()) {
    }
}

/**
 * @brief Configure hardware timer FRC2 at 5 MHz (parked until armed) and enable its Xtensa interrupt.
 *
 * Attaches ets_timer_handler_dsr() to IRQ 10, initializes FRC2 with a /16
 * prescaler (80 MHz / 16 = 5 MHz) parked with `FRC2_ALARM` at
 * `ETS_FRC2_PARK_OFFSET_TICKS` until `ets_rtc_timer_arm()` is called, clears
 * any pending FRC2 interrupt, enables edge-interrupt routing, and unmasks IRQ 10
 * in `INTENABLE`.
 */
void ets_timer_init(void)
{
    _xt_isr_attach(ETS_TIMER_FRC2_IRQ_NUM, ets_timer_handler_dsr, NULL);
    REG_WRITE(FRC2_CTRL_ADDRESS, ETS_TIMER_FRC2_CTRL_5MHZ_DIS);
    REG_WRITE(FRC2_LOAD_ADDRESS, 0U);
    REG_WRITE(FRC2_ALARM_ADDRESS, ETS_FRC2_PARK_OFFSET_TICKS);
    REG_WRITE(FRC2_INT_ADDRESS, TIMER_FRC2_INT_CLR_MASK);
    SET_PERI_REG_MASK(EDGE_INT_ENABLE_REG, ETS_TIMER_FRC2_EDGE_INT_BIT);
    _xt_isr_unmask(1U << ETS_TIMER_FRC2_IRQ_NUM);
}
