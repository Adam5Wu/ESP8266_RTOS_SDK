// Copyright 2015-2016 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __ESP_LOG_INTERNAL_H__
#define __ESP_LOG_INTERNAL_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Logs a buffer of hexadecimal bytes at the specified log level.
 *
 * This function logs a buffer of hexadecimal bytes with 16 bytes per line. The
 * log level determines the severity of the log message.
 *
 * @note This function does not check the log level against the ESP_LOCAL_LEVEL.
 * The log level comparison should be done in esp_log.h.
 *
 * @param tag       Description tag to identify the log.
 * @param buffer    Pointer to the buffer array containing the data to be logged.
 * @param buff_len  Length of the buffer in bytes.
 * @param level     Log level indicating the severity of the log message.
 */
void esp_log_buffer_hex_internal(const char *tag, const void *buffer, uint16_t buff_len,
                                 esp_log_level_t level);

/**
 * @brief This function logs a buffer of characters with 16 characters per line.
 * The buffer should contain only printable characters. The log level determines
 * the severity of the log message.
 *
 * @note This function does not check the log level against the ESP_LOCAL_LEVEL.
 * The log level comparison should be done in esp_log.h.
 *
 * @param tag       Description tag to identify the log.
 * @param buffer    Pointer to the buffer array containing the data to be logged.
 * @param buff_len  Length of the buffer in bytes.
 * @param level     Log level indicating the severity of the log message.
 */
void esp_log_buffer_char_internal(const char *tag, const void *buffer, uint16_t buff_len,
                                  esp_log_level_t level);

/**
 * @brief This function dumps a buffer to the log in a formatted hex dump style,
 * displaying both the memory address and the corresponding hex and ASCII values
 * of the bytes. The log level determines the severity of the log message.
 *
 * @note This function does not check the log level against the ESP_LOCAL_LEVEL.
 * The log level comparison should be done in esp_log.h.
 * @note It is recommended to use terminals with a width of at least 102
 * characters to display the log dump properly.
 *
 * @param tag       Description tag to identify the log.
 * @param buffer    Pointer to the buffer array containing the data to be logged.
 * @param buff_len  Length of the buffer in bytes.
 * @param level     Log level indicating the severity of the log message.
 */
void esp_log_buffer_hexdump_internal(const char *tag, const void *buffer, uint16_t buff_len,
                                     esp_log_level_t level);

#ifdef __cplusplus
}
#endif

#endif
