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
// Unified cooperative Wi-Fi worker task: drains LMAC NMI events, bounded
// ets_timer callbacks, TX submissions, and synchronous esp_wifi_* RPCs without
// scheduler-wide freezes (zero vTaskSuspendAll).

#include <string.h>

#include "esp_attr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "net80211_internal.h"

#define TAG "net80211"

extern const size_t _g_esp_wifi_ppt_task_stk_size;
extern bool ets_timer_proc_one(void);

/* Single zero-initialized global net80211 context (0 SHN_COMMON) */
net80211_ctx_t g_n8 = {0};

#define N8_EVT_QUEUE_LEN        64U
#define N8_LMAC_RX_BATCH        16U
#define N8_LMAC_TX_BATCH        16U
#define N8_HK_PERIOD_US         100000LL

/* --------------------------------------------------------------------------
 * ISR Event Posting Hooks (LMAC SoftISR + esp_ets_timer FRC2 ISR)
 * -------------------------------------------------------------------------- */

int n8_lmac_notify_from_isr(void *ctx)
{
    (void)ctx;
    if (g_n8.evt_queue == NULL || g_n8.lmac_evt_queued) {
        return 0;
    }
    g_n8.lmac_evt_queued = 1U;
    n8_evt_t ev = { .type = N8_EVT_LMAC, .ptr = NULL };
    BaseType_t woken = pdFALSE;
    if (xQueueSendFromISR(g_n8.evt_queue, &ev, &woken) != pdTRUE) {
        g_n8.lmac_evt_queued = 0U;
    }
    return (int)woken;
}

int esp_wifi_post_timer_from_isr(void)
{
    if (g_n8.evt_queue == NULL || g_n8.timer_evt_queued) {
        return 0;
    }
    g_n8.timer_evt_queued = 1U;
    n8_evt_t ev = { .type = N8_EVT_ETS_TIMER, .ptr = NULL };
    BaseType_t woken = pdFALSE;
    if (xQueueSendFromISR(g_n8.evt_queue, &ev, &woken) != pdTRUE) {
        g_n8.timer_evt_queued = 0U;
    } else if (woken == pdTRUE) {
        portYIELD_FROM_ISR();
    }
    return (int)woken;
}

void n8_post_evt(n8_evt_type_t type, void *ptr)
{
    if (g_n8.evt_queue == NULL) {
        return;
    }

    volatile uint8_t *flag = NULL;
    if (type == N8_EVT_LMAC) {
        flag = &g_n8.lmac_evt_queued;
    } else if (type == N8_EVT_TX) {
        flag = &g_n8.tx_evt_queued;
    } else if (type == N8_EVT_ETS_TIMER) {
        flag = &g_n8.timer_evt_queued;
    }

    if (flag != NULL) {
        taskENTER_CRITICAL();
        if (*flag) {
            taskEXIT_CRITICAL();
            return;
        }
        *flag = 1U;
        taskEXIT_CRITICAL();
    }

    n8_evt_t ev = { .type = (uint8_t)type, .ptr = ptr };
    if (xQueueSend(g_n8.evt_queue, &ev, 0) != pdTRUE && flag != NULL) {
        taskENTER_CRITICAL();
        *flag = 0U;
        taskEXIT_CRITICAL();
    }
}

bool n8_on_worker_task(void)
{
    return (g_n8.worker_task != NULL) && (xTaskGetCurrentTaskHandle() == g_n8.worker_task);
}

esp_err_t n8_api_call(n8_api_fn_t fn, void *arg)
{
    if (fn == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!g_n8.worker_running || g_n8.evt_queue == NULL || n8_on_worker_task()) {
        return fn(arg);
    }

    if (g_n8.api_mutex != NULL) {
        xSemaphoreTake(g_n8.api_mutex, portMAX_DELAY);
    }

    n8_api_req_t req;
    req.fn = fn;
    req.arg = arg;
    req.ret = ESP_FAIL;
    req.done_sem = xSemaphoreCreateBinary();
    if (req.done_sem == NULL) {
        if (g_n8.api_mutex != NULL) {
            xSemaphoreGive(g_n8.api_mutex);
        }
        return ESP_ERR_NO_MEM;
    }

    n8_evt_t ev = { .type = N8_EVT_API, .ptr = &req };
    if (xQueueSend(g_n8.evt_queue, &ev, portMAX_DELAY) == pdTRUE) {
        xSemaphoreTake(req.done_sem, portMAX_DELAY);
    }

    vSemaphoreDelete(req.done_sem);
    if (g_n8.api_mutex != NULL) {
        xSemaphoreGive(g_n8.api_mutex);
    }
    return req.ret;
}

void n8_send_system_event(system_event_t *evt)
{
    if (evt == NULL) {
        return;
    }
    if (g_n8.init_cfg.event_handler != NULL) {
        (void)g_n8.init_cfg.event_handler(evt);
    } else {
        (void)esp_event_send(evt);
    }
}

/* --------------------------------------------------------------------------
 * Cooperative Single Wi-Fi Worker Task
 * -------------------------------------------------------------------------- */

static void n8_worker_task(void *arg)
{
    (void)arg;
    int64_t last_hk_us = esp_timer_get_time();

    while (g_n8.worker_running) {
        n8_evt_t ev;
        BaseType_t got = xQueueReceive(g_n8.evt_queue, &ev, pdMS_TO_TICKS(50U));

        if (got == pdTRUE) {
            switch (ev.type) {
            case N8_EVT_LMAC:
                taskENTER_CRITICAL();
                g_n8.lmac_evt_queued = 0U;
                taskEXIT_CRITICAL();
                if (esp_lmac_process_events(N8_LMAC_RX_BATCH, N8_LMAC_TX_BATCH)) {
                    n8_post_evt(N8_EVT_LMAC, NULL);
                }
                /* Drain any backpressured data TX as soon as ANY LMAC slot frees (data/mgmt/null/bcn) */
                if (g_n8.tx_q_head != g_n8.tx_q_tail && esp_lmac_tx_has_free_slot()) {
                    n8_data_process_tx_queue();
                }
                break;

            case N8_EVT_ETS_TIMER:
                taskENTER_CRITICAL();
                g_n8.timer_evt_queued = 0U;
                taskEXIT_CRITICAL();
                if (ets_timer_proc_one()) {
                    n8_post_evt(N8_EVT_ETS_TIMER, NULL);
                }
                break;

            case N8_EVT_TX:
                taskENTER_CRITICAL();
                g_n8.tx_evt_queued = 0U;
                taskEXIT_CRITICAL();
                n8_data_process_tx_queue();
                break;

            case N8_EVT_API: {
                n8_api_req_t *req = (n8_api_req_t *)ev.ptr;
                if (req != NULL) {
                    req->ret = req->fn(req->arg);
                    xSemaphoreGive(req->done_sem);
                }
                break;
            }

            case N8_EVT_STOP_WORKER:
                g_n8.worker_running = false;
                break;

            default:
                break;
            }
        }

        /* Run 100 ms periodic housekeeping without creating an extra timer task */
        int64_t now_us = esp_timer_get_time();
        if ((now_us - last_hk_us) >= N8_HK_PERIOD_US) {
            last_hk_us = now_us;
            esp_lmac_housekeeping_100ms();
            if (g_n8.started) {
                if (g_n8.tx_q_head != g_n8.tx_q_tail && !g_n8.scan_active && esp_lmac_tx_has_free_slot()) {
                    n8_data_process_tx_queue();
                }
                n8_sta_on_tick_100ms();
                n8_ap_on_tick_100ms();
                n8_pm_on_tick_100ms();
                n8_defrag_on_tick_100ms();
            }
        }
    }

    TaskHandle_t self = g_n8.worker_task;
    g_n8.worker_task = NULL;
    (void)self;
    vTaskDelete(NULL);
}

esp_err_t n8_worker_start(void)
{
    if (g_n8.worker_running) {
        return ESP_OK;
    }

    g_n8.evt_queue = xQueueCreate(N8_EVT_QUEUE_LEN, sizeof(n8_evt_t));
    if (g_n8.evt_queue == NULL) {
        return ESP_ERR_NO_MEM;
    }

    g_n8.api_mutex = xSemaphoreCreateMutex();
    if (g_n8.api_mutex == NULL) {
        vQueueDelete(g_n8.evt_queue);
        g_n8.evt_queue = NULL;
        return ESP_ERR_NO_MEM;
    }

    g_n8.lmac_evt_queued = 0U;
    g_n8.tx_evt_queued = 0U;
    g_n8.timer_evt_queued = 0U;
    g_n8.worker_running = true;

    uint32_t stk_bytes = (uint32_t)_g_esp_wifi_ppt_task_stk_size;
    if (stk_bytes < 3072U) {
        stk_bytes = 3072U;
    }
    UBaseType_t prio = (UBaseType_t)CONFIG_ESP8266_OSS_WIFI_TASK_PRIO;
    if (prio >= configMAX_PRIORITIES) {
        prio = configMAX_PRIORITIES - 1U;
    }

    BaseType_t ok = xTaskCreate(n8_worker_task, "wifi", (uint16_t)(stk_bytes / sizeof(StackType_t)),
                                NULL, prio, &g_n8.worker_task);
    if (ok != pdPASS) {
        g_n8.worker_running = false;
        vSemaphoreDelete(g_n8.api_mutex);
        vQueueDelete(g_n8.evt_queue);
        g_n8.api_mutex = NULL;
        g_n8.evt_queue = NULL;
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

void n8_worker_stop(void)
{
    if (!g_n8.worker_running && g_n8.worker_task == NULL) {
        return;
    }

    g_n8.worker_running = false;
    n8_post_evt(N8_EVT_STOP_WORKER, NULL);

    uint32_t wait_ms = 0U;
    while (g_n8.worker_task != NULL && wait_ms < 500U) {
        vTaskDelay(pdMS_TO_TICKS(10U));
        wait_ms += 10U;
    }

    if (g_n8.evt_queue != NULL) {
        vQueueDelete(g_n8.evt_queue);
        g_n8.evt_queue = NULL;
    }
    if (g_n8.api_mutex != NULL) {
        vSemaphoreDelete(g_n8.api_mutex);
        g_n8.api_mutex = NULL;
    }
}
