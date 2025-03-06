// Copyright 2018-2025 Espressif Systems (Shanghai) PTE LTD
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

#pragma once

#include <stdint.h>
#include "esp8266/eagle_soc.h"

#ifdef __cplusplus
extern "C" {
#endif


/* ESP8266 FRC Register Definitions */

// FRC1 is a 23-bit countdown timer, triggers interrupt when reaches zero.
typedef struct {
    union {
        struct {
            uint32_t data:        23;  // bits 22-0  RW
            uint32_t reserved23:   9;
        };
        uint32_t val;  // default: 0
    } load;

    union {
        struct {
            uint32_t data:        23;  // bits 22-0  RO
            uint32_t reserved23:   9;
        };
        uint32_t val;  // default: 0x7FFFFF
    } count;

    union {
        struct {
            uint32_t intr_type:    1;  // bit 0       RW
            uint32_t reserved1:    1;  // bit 1
            uint32_t div:          2;  // bits 3-2    RW  0-divBy1, 1-divBy16, 2or3-divBy256
            uint32_t reserved4:    2;  // bits 5-4
            uint32_t reload:       1;  // bit 6       RW
            uint32_t en:           1;  // bit 7       RW
            uint32_t intr_status:  1;  // bit 8       RO
            uint32_t reserved9:   23;  // bits 31-9   RO
        };
        uint32_t val;  // default: 0
    } ctrl;

    union {
        struct {
            uint32_t clr:          1;  // bit 0     RW
            uint32_t reserved1:   31;  // bit 31-1  RO
        };
        uint32_t val;  // default: 0
    } intr;
} frc1_struct_t;

extern volatile frc1_struct_t frc1;

#ifdef __cplusplus
}
#endif  /* end of __cplusplus */

