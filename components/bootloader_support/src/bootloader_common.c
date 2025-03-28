// Copyright 2018 Espressif Systems (Shanghai) PTE LTD
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
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "sdkconfig.h"

#include "esp_err.h"
#include "esp_log.h"
#include "esp_flash_data_types.h"
#include "esp_flash_partitions.h"
#include "rom/crc.h"
#include "rom/gpio.h"

#include "bootloader_config.h"
#include "bootloader_flash.h"
#include "bootloader_common.h"

static const char* TAG = "boot_comm";

#ifdef CONFIG_IDF_TARGET_ESP32

#include "rom/spi_flash.h"
#include "rom/ets_sys.h"

#include "esp_secure_boot.h"

#define _strnstr strstr
#define _strcspn strspn

#endif

#ifdef CONFIG_IDF_TARGET_ESP8266

#include <xtensa/hal.h>

static char *_strnstr(const char *haystack, const char *needle, size_t len) {
    size_t i;
    size_t j;

    if (needle[0] == '\0') return ((char *)haystack);
    j = 0;
    while (j < len && haystack[j]) {
        i = 0;
        while (j < len && needle[i] && haystack[j] && needle[i] == haystack[j]) {
            ++i;
            ++j;
        }
        if (needle[i] == '\0') return ((char *)&haystack[j - i]);
        j = j - i + 1;
    }
    return (0);
}

static size_t _strcspn(const char *str1, const char *str2) {
    size_t length = 0;
    while (str1[length] != '\0') {
        size_t i = 0;
        while (str2[i] != '\0') {
            if (str1[length] == str2[i]) {
                return length;
            }
            i++;
        }
        length++;
    }
    return length;
}

#endif

uint32_t bootloader_common_ota_select_crc(const esp_ota_select_entry_t *s)
{
    return crc32_le(UINT32_MAX, (uint8_t*)&s->ota_seq, 4);
}

bool bootloader_common_ota_select_valid(const esp_ota_select_entry_t *s)
{
    return s->ota_seq != UINT32_MAX && s->crc == bootloader_common_ota_select_crc(s);
}

esp_comm_gpio_hold_t bootloader_common_check_long_hold_gpio(uint32_t num_pin, uint32_t delay_sec)
{
    gpio_pad_select_gpio(num_pin);
    gpio_pad_pullup(num_pin);

    uint32_t tm_start = esp_log_early_timestamp();
    if (GPIO_INPUT_GET(num_pin) == 1) {
        ESP_LOGD(TAG, "gpio %d not held", num_pin);
        return GPIO_NOT_HOLD;
    }
    do {
        if (GPIO_INPUT_GET(num_pin) != 0) {
            ESP_LOGD(TAG, "gpio %d short hold", num_pin);
            return GPIO_SHORT_HOLD;
        }
    } while (delay_sec > ((esp_log_early_timestamp() - tm_start) / 1000L));
    ESP_LOGD(TAG, "gpio %d long hold", num_pin);
    return GPIO_LONG_HOLD;
}

// Search for a label in the list. list = "nvs1, nvs2, otadata, nvs"; label = "nvs".
bool bootloader_common_label_search(const char *list, char *label)
{
    if (list == NULL || label == NULL) {
        return false;
    }
    const char *sub_list_start_like_label =
        _strnstr(list, label, sizeof(((esp_partition_info_t *)0)->label));
    while (sub_list_start_like_label != NULL) {

        // ["," or " "] + label + ["," or " " or "\0"]
        // first character before the label found there must be a delimiter ["," or " "].
        int idx_first = sub_list_start_like_label - list;
        if (idx_first == 0 || (idx_first != 0 && (list[idx_first - 1] == ',' || list[idx_first - 1] == ' '))) {
            // next character after the label found there must be a delimiter ["," or " " or "\0"].
            int len_label = strlen(label);
            if (sub_list_start_like_label[len_label] == 0   ||
                sub_list_start_like_label[len_label] == ',' ||
                sub_list_start_like_label[len_label] == ' ') {
                return true;
            }
        }

        // [start_delim] + label + [end_delim] was not found.
        // Position is moving to next delimiter if it is not the end of list.
        int pos_delim = _strcspn(sub_list_start_like_label, ", ");
        if (pos_delim == strlen(sub_list_start_like_label)) {
            break;
        }
        sub_list_start_like_label = _strnstr(&sub_list_start_like_label[pos_delim], label,
                                             sizeof(((esp_partition_info_t *)0)->label));
    }
    return false;
}

bool bootloader_utility_load_partition_table_for(load_partition_callback cb, void *arg) {
    const esp_partition_info_t *partitions;
    esp_err_t err;
    int num_partitions;

#ifdef CONFIG_SECURE_BOOT_ENABLED
    if (esp_secure_boot_enabled()) {
        ESP_LOGI(TAG, "Verifying partition table signature...");
        err = esp_secure_boot_verify_signature(ESP_PARTITION_TABLE_ADDR, ESP_PARTITION_TABLE_MAX_LEN);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to verify partition table signature.");
            return false;
        }
        ESP_LOGD(TAG, "Partition table signature verified");
    }
#endif

    partitions = bootloader_mmap(ESP_PARTITION_TABLE_ADDR, ESP_PARTITION_TABLE_MAX_LEN);
    if (!partitions) {
            ESP_LOGE(TAG, "bootloader_mmap(0x%x, 0x%x) failed", ESP_PARTITION_TABLE_ADDR, ESP_PARTITION_TABLE_MAX_LEN);
            return false;
    }
    ESP_LOGD(TAG, "mapped partition table 0x%x at 0x%x", ESP_PARTITION_TABLE_ADDR, (intptr_t)partitions);

    err = esp_partition_table_basic_verify(partitions, true, &num_partitions);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to verify partition table");
        return false;
    }

    cb(partitions, num_partitions, arg);
    bootloader_munmap(partitions);

    return true;
}

struct PartitionEraseConfig {
    const char *list_erase;
    bool ota_data_erase;
    bool completed_without_error;
};

static void enumerate_partitions_for_erasure(const esp_partition_info_t *partitions,
                                             int num_partitions, void *arg) {
    struct PartitionEraseConfig *config = (struct PartitionEraseConfig *)arg;

    ESP_LOGI(TAG, "## Label            Offset   Length   Cleaned");
    for (int i = 0; i < num_partitions; i++) {
#ifdef CONFIG_IDF_TARGET_ESP32
        const esp_partition_info_t *partition = &partitions[i];
#else   // CONFIG_IDF_TARGET_ESP8266
        esp_partition_info_t partiton_local;
        esp_partition_info_t *partition = &partiton_local;
        memcpy(&partiton_local, (void *)((intptr_t)partitions + i * sizeof(esp_partition_info_t)),
               sizeof(esp_partition_info_t));
#endif  // CONFIG_IDF_TARGET_ESP32
        if (partition->magic == ESP_PARTITION_MAGIC_MD5) continue;

        const char *state = "n/a";
        if (partition->type == PART_TYPE_DATA) {
            bool fl_ota_data_erase = false;
            if (config->ota_data_erase == true && partition->subtype == PART_SUBTYPE_DATA_OTA) {
                fl_ota_data_erase = true;
            }

            if (fl_ota_data_erase == true ||
                (bootloader_common_label_search(config->list_erase, (char *)partition->label) == true)) {
#ifdef CONFIG_IDF_TARGET_ESP32
                esp_err_t err = esp_rom_spiflash_erase_area(partition->pos.offset, partition->pos.size);
#else   // CONFIG_IDF_TARGET_ESP8266
                // Maybe just erasing the first 10 sectors is enough?
                esp_err_t err = ESP_OK;
                for (int x = 0; x < 10 && x < (partition->pos.size / FLASH_SECTOR_SIZE); x++) {
                    err = spi_flash_erase_sector(partition->pos.offset / FLASH_SECTOR_SIZE + x);
                    if (err != ESP_OK) break;
                }
#endif  // CONFIG_IDF_TARGET_ESP32
                if (err != ESP_OK) {
                    config->completed_without_error = false;
                    state = "err";
                } else {
                    state = "yes";
                }
            } else {
                    state = "no";
            }
        }
        ESP_LOGI(TAG, "%2d %-16s %08x %08x [%s]", i, partition->label,
            partition->pos.offset, partition->pos.size, state);
    }
}

bool bootloader_common_erase_part_type_data(const char *list_erase, bool ota_data_erase) {
    struct PartitionEraseConfig config = {list_erase, ota_data_erase, true};
    if (!bootloader_utility_load_partition_table_for(enumerate_partitions_for_erasure, &config)) {
        return false;
    }
    return config.completed_without_error;
}
