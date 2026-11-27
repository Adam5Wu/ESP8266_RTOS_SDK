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
#include <string.h>

#include "sdkconfig.h"
#include "esp_err.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "nvs.h"

typedef struct misc_nvs {
    uint32_t     reserved_0;
    uint32_t     wps_type;
    uint32_t     wps_status;
    uint8_t      reserved_0c[20];
    nvs_handle_t nvs_handle;
} misc_nvs_t;

_Static_assert(sizeof(misc_nvs_t) == 36, "misc_nvs_t ABI");
_Static_assert(offsetof(misc_nvs_t, wps_type) == 0x04U, "misc_nvs_t::wps_type offset");
_Static_assert(offsetof(misc_nvs_t, wps_status) == 0x08U, "misc_nvs_t::wps_status offset");
_Static_assert(offsetof(misc_nvs_t, nvs_handle) == 0x20U, "misc_nvs_t::nvs_handle offset");

static uint8_t g_misc_nvs_init = 0U;

misc_nvs_t *g_misc_nvs = NULL;
uint32_t g_log_level = 0U;
uint32_t g_log_mod = 0U;
uint32_t g_log_print = 0U;

#ifdef CONFIG_ESP8266_VENDOR_PHY_WIFI
__attribute__((aligned(8))) uint8_t g_cnxMgr[1224];
#endif

#define MISC_NVS_LOG_MOD_BIT        0x08U /* Wi-Fi log module bit for misc_nvs */
#define MISC_NVS_LOG_LVL_VERBOSE    4U
#define MISC_NVS_VENDOR_EN_OFFSET   20U   /* Byte offset of nvs_enable in g_wifi_menuconfig[] */

int misc_nvs_load(bool reset);
void misc_nvs_deinit(void);
int misc_nvs_init(void);
int misc_nvs_restore(void);

/**
 * @brief Query whether Wi-Fi NVS persistence is enabled in the active configuration.
 *
 * @return Non-zero (1) if NVS storage is enabled, 0 otherwise.
 */
static inline uint8_t misc_nvs_is_enabled(void)
{
#ifdef CONFIG_ESP8266_VENDOR_PHY_WIFI
    extern const uint8_t g_wifi_menuconfig[];
    return g_wifi_menuconfig[MISC_NVS_VENDOR_EN_OFFSET];
#else
#ifdef CONFIG_ESP8266_WIFI_NVS_ENABLED
    return 1U;
#else
    return 0U;
#endif
#endif
}

/**
 * @brief Allocate and open the `"misc"` NVS handle, or reset cached WPS status in place.
 *
 * @param reset  If true, only clears `g_misc_nvs->wps_status` without reallocating.
 * @return       ESP_OK on success, ESP_ERR_NO_MEM on allocation failure, or NVS error code.
 */
int misc_nvs_load(bool reset)
{
    if (reset) {
        if (g_misc_nvs != NULL) {
            g_misc_nvs->wps_status = 0U;
        }
        return ESP_OK;
    }

    g_misc_nvs = (misc_nvs_t *)_heap_caps_malloc(sizeof(misc_nvs_t), MALLOC_CAP_32BIT,
                                                 "misc_nvs.c", __LINE__);
#ifdef CONFIG_ESP8266_WIFI_DEBUG_LOG_ENABLE
    if (g_log_level >= MISC_NVS_LOG_LVL_VERBOSE && (g_log_mod & MISC_NVS_LOG_MOD_BIT) != 0U) {
        esp_log_write(ESP_LOG_VERBOSE, "wifi", "g_misc_nvs=%p", (void *)g_misc_nvs);
    }
#endif
    if (g_misc_nvs == NULL) {
#ifdef CONFIG_ESP8266_WIFI_DEBUG_LOG_ENABLE
        if (g_log_level != 0U && (g_log_mod & MISC_NVS_LOG_MOD_BIT) != 0U) {
            esp_log_write(ESP_LOG_WARN, "wifi", "misc nvs f");
        }
#endif
        return ESP_ERR_NO_MEM;
    }

    memset(g_misc_nvs, 0, sizeof(misc_nvs_t));

    if (misc_nvs_is_enabled() != 0U) {
        esp_err_t ret = nvs_open("misc", NVS_READWRITE, &g_misc_nvs->nvs_handle);
        if (ret != ESP_OK) {
#ifdef CONFIG_ESP8266_WIFI_DEBUG_LOG_ENABLE
            if (g_log_level != 0U && (g_log_mod & MISC_NVS_LOG_MOD_BIT) != 0U) {
                esp_log_write(ESP_LOG_WARN, "wifi", "wifi wifi_nvs_open fail ret=%d", (int)ret);
            }
#endif
            return ret;
        }
#ifdef CONFIG_ESP8266_WIFI_DEBUG_LOG_ENABLE
        if (g_log_level >= MISC_NVS_LOG_LVL_VERBOSE && (g_log_mod & MISC_NVS_LOG_MOD_BIT) != 0U) {
            esp_log_write(ESP_LOG_VERBOSE, "wifi", "open misc nvs name=%s ok, handle=%p",
                          "misc", (void *)(uintptr_t)g_misc_nvs->nvs_handle);
        }
#endif
    }

    g_misc_nvs->wps_status = 0U;
    return ESP_OK;
}

/**
 * @brief Close the `"misc"` NVS handle, free `g_misc_nvs`, and mark the module uninitialized.
 */
void misc_nvs_deinit(void)
{
    if (g_misc_nvs != NULL) {
        if (misc_nvs_is_enabled() != 0U && g_misc_nvs->nvs_handle != 0U) {
            nvs_close(g_misc_nvs->nvs_handle);
        }
        _heap_caps_free(g_misc_nvs, "misc_nvs.c", __LINE__);
        g_misc_nvs = NULL;
    }
    g_misc_nvs_init = 0U;
}

/**
 * @brief Idempotently initialize the `misc_nvs` context and open NVS storage if enabled.
 *
 * @return ESP_OK on success (or if already initialized), or an error code on failure.
 */
int misc_nvs_init(void)
{
    int ret;

    if (g_misc_nvs_init != 0U) {
        return ESP_OK;
    }

    g_misc_nvs_init = 1U;
    ret = misc_nvs_load(false);
    if (ret != ESP_OK) {
        misc_nvs_deinit();
        return ret;
    }

    return ESP_OK;
}

/**
 * @brief Reset cached `misc_nvs` runtime status fields to factory defaults.
 *
 * @return ESP_OK.
 */
int misc_nvs_restore(void)
{
    return misc_nvs_load(true);
}
