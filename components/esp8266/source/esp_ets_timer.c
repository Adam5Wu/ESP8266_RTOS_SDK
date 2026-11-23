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

#define ETSTIMER_DISARMED ((ETSTimer *)(uintptr_t)0xFFFFFFFFU)

static ETSTimer *s_timer_list = NULL;

static void ets_rtc_timer_arm(uint32_t alarm_ticks)
{
    uint32_t now = REG_READ(FRC2_COUNT_ADDRESS);
    uint32_t target = alarm_ticks;

    if ((int32_t)(alarm_ticks - now) <= 0) {
        target = REG_READ(FRC2_COUNT_ADDRESS) + 100U;
    }
    REG_WRITE(FRC2_ALARM_ADDRESS, target);
    REG_WRITE(FRC2_CTRL_ADDRESS, 0x84U);
}

static void ets_timer_intr_set(uint32_t expire_ticks)
{
    uint32_t now = REG_READ(FRC2_COUNT_ADDRESS);
    int32_t diff = (int32_t)(expire_ticks - now);
    uint32_t alarm;

    if (diff > 0x500) {
        alarm = expire_ticks;
    } else if (diff >= 1) {
        alarm = expire_ticks + 0x540U;
    } else {
        alarm = now + 0x500U;
    }
    ets_rtc_timer_arm(alarm);
}

static void ets_timer_handler_dsr(void *arg)
{
    (void)arg;
#if defined(CONFIG_ESP8266_OSS_PHY_WIFI)
    (void)esp_wifi_post_timer_from_isr();
#elif defined(CONFIG_ESP8266_VENDOR_PHY_WIFI)
    (void)pp_post_from_isr(0x10U, 0U);
#endif
}

static void timer_insert(uint32_t expire_ticks, ETSTimer *ptimer)
{
    ETSTimer *prev = NULL;
    ETSTimer *curr;

    if (ptimer == NULL) {
        ets_printf("%s %u\n", "tim", 162U);
        for (;;) {
        }
    }

    for (curr = s_timer_list; curr != NULL; prev = curr, curr = curr->timer_next) {
        if ((int32_t)(expire_ticks - curr->timer_expire) < 1) {
            break;
        }
    }

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
        ets_printf("%s %u\n", "tim", 198U);
        for (;;) {
        }
    }
}

void ets_timer_setfn(ETSTimer *ptimer, ETSTimerFunc *pfunction, void *parg)
{
    unsigned ps = XTOS_SET_INTLEVEL(3);

    ptimer->timer_next = ETSTIMER_DISARMED;
    ptimer->timer_expire = 0U;
    ptimer->timer_period = 0U;
    ptimer->timer_func = pfunction;
    ptimer->timer_arg = parg;

    XTOS_RESTORE_INTLEVEL(ps);
}

void os_timer_setfn(os_timer_t *ptimer, os_timer_func_t *pfunction, void *parg)
    __attribute__((alias("ets_timer_setfn")));

void ets_timer_disarm(ETSTimer *ptimer)
{
    unsigned ps = XTOS_SET_INTLEVEL(3);
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
                    REG_WRITE(FRC2_CTRL_ADDRESS, 0x04U);
                    REG_WRITE(FRC2_ALARM_ADDRESS, REG_READ(FRC2_COUNT_ADDRESS) + 0x7FFFFFFFU);
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
        if (time_val > 0x000689D0U) {
            esp_log_write(ESP_LOG_ERROR, "wifi",
                          "err1,exceed max time value,max val is %08X", 0x000689D0U);
            return;
        }
        us = time_val * 1000U;
    } else {
        if (time_val > 0x198A5759U) {
            esp_log_write(ESP_LOG_ERROR, "wifi",
                          "err2,exceed max time value,max val is %08X", 0x198A5759U);
            return;
        }
        us = time_val;
    }

    /* Exact 5 MHz FRC2 ticks = us * 5 without 32-bit intermediate overflow */
    ticks = (us >> 2) * 20U + (us & 3U) * 5U;

    if (repeat_flag) {
        ptimer->timer_period = ticks;
    }

    ps = XTOS_SET_INTLEVEL(3);
    if (ptimer->timer_next != ETSTIMER_DISARMED) {
        ets_timer_disarm(ptimer);
    }
    timer_insert(REG_READ(FRC2_COUNT_ADDRESS) + ticks, ptimer);
    XTOS_RESTORE_INTLEVEL(ps);
}

void ets_timer_arm_us(ETSTimer *ptimer, uint32_t u_seconds, bool repeat_flag)
{
    ets_timer_arm_ms_us(ptimer, u_seconds, repeat_flag, false);
}

void os_timer_arm_us(os_timer_t *ptimer, uint32_t u_seconds, bool repeat_flag)
    __attribute__((alias("ets_timer_arm_us")));

void ets_timer_arm(ETSTimer *ptimer, uint32_t milliseconds, bool repeat_flag)
{
    ets_timer_arm_ms_us(ptimer, milliseconds, repeat_flag, true);
}

void os_timer_arm(os_timer_t *ptimer, uint32_t milliseconds, bool repeat_flag)
    __attribute__((alias("ets_timer_arm")));

void ets_timer_done(ETSTimer *ptimer)
{
    if (ptimer->timer_next != ETSTIMER_DISARMED) {
        ets_printf("%s %u\n", "tim", 307U);
        for (;;) {
        }
    }
    ets_timer_setfn(ptimer, NULL, NULL);
}

bool ets_timer_proc_one(void)
{
    unsigned ps = XTOS_SET_INTLEVEL(3);
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

    ps = XTOS_SET_INTLEVEL(3);
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
        REG_WRITE(FRC2_CTRL_ADDRESS, 0x04U);
        REG_WRITE(FRC2_ALARM_ADDRESS, REG_READ(FRC2_COUNT_ADDRESS) + 0x7FFFFFFFU);
        REG_WRITE(FRC2_INT_ADDRESS, TIMER_FRC2_INT_CLR_MASK);
    }
    XTOS_RESTORE_INTLEVEL(ps);
    return more;
}

void ets_timer_proc(void)
{
    while (ets_timer_proc_one()) {
    }
}

void ets_timer_init(void)
{
    _xt_isr_attach(10, ets_timer_handler_dsr, NULL);
    REG_WRITE(FRC2_CTRL_ADDRESS, 0x04U);
    REG_WRITE(FRC2_LOAD_ADDRESS, 0U);
    REG_WRITE(FRC2_ALARM_ADDRESS, 0x7FFFFFFFU);
    REG_WRITE(FRC2_INT_ADDRESS, TIMER_FRC2_INT_CLR_MASK);
    SET_PERI_REG_MASK(EDGE_INT_ENABLE_REG, BIT(2));
    _xt_isr_unmask(1U << 10);
}
