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

#include "sdkconfig.h"

#ifdef CONFIG_ESP8266_OSS_PHY_ONLY

#include <stdint.h>
#include "esp_attr.h"

/* Minimal non-Wi-Fi symbols satisfied when Wi-Fi is disabled (CONFIG_ESP8266_OSS_PHY_ONLY) */
uint8_t NMIIrqIsOn = 0;
uint32_t WDEV_INTEREST_EVENT = 0;
uint64_t WdevTimOffSet = 0;

int MacIsrSigPostDefHdl(void);
void wDev_ProcessFiq(void);
void wDev_MacTimSetFunc(void *func);
void reset_noise_timer(uint16_t interval);

/** @brief No-op SoftISR stub invoked by port.c when Wi-Fi is compiled out. @return 0. */
int IRAM_ATTR MacIsrSigPostDefHdl(void)
{
    return 0;
}

/** @brief No-op Level-3 NMI handler stub invoked by _xt_nmi when Wi-Fi is compiled out. */
void IRAM_ATTR wDev_ProcessFiq(void)
{
}

/**
 * @brief No-op MAC Timer 0 callback registration stub for non-Wi-Fi builds.
 * @param func  Ignored timer callback pointer.
 */
void wDev_MacTimSetFunc(void *func)
{
    (void)func;
}

/**
 * @brief No-op noise-floor timer reset stub for non-Wi-Fi builds.
 * @param interval  Ignored timer interval.
 */
void reset_noise_timer(uint16_t interval)
{
    (void)interval;
}

int esp_wifi_get_state(void);

/** @brief Report Wi-Fi state as idle/stopped in non-Wi-Fi builds. @return 0. */
int esp_wifi_get_state(void)
{
    return 0;
}

#endif /* CONFIG_ESP8266_OSS_PHY_ONLY */
