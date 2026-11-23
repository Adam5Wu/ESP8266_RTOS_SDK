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

int IRAM_ATTR MacIsrSigPostDefHdl(void)
{
    return 0;
}

void IRAM_ATTR wDev_ProcessFiq(void)
{
}

void wDev_MacTimSetFunc(void *func)
{
    (void)func;
}

void reset_noise_timer(uint16_t interval)
{
    (void)interval;
}

int esp_wifi_get_state(void);

int esp_wifi_get_state(void)
{
    return 0;
}

#endif /* CONFIG_ESP8266_OSS_PHY_ONLY */
