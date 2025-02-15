// Copyright 2019-2020 Espressif Systems (Shanghai) PTE LTD
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

#include <stdint.h>
#include <stdbool.h>
#include "esp8266/eagle_soc.h"

static uint32_t prev_text_size(const uint32_t pc)
{
    uint32_t size;
    extern uint32_t _text_start, _text_end;

    if (pc > (uint32_t)&_text_start && pc < (uint32_t)&_text_end) {
        size = pc - (uint32_t )&_text_start;
    } else if (IS_IRAM(pc)) {
        size = pc - IRAM_BASE;
    } else if (IS_ROM(pc)) {
        size = pc - ROM_BASE;
    } else {
        size = 0;
    }

    return size;
}

int xt_pc_is_valid(const void *pc)
{
    return prev_text_size((uint32_t)pc) ? 1 : 0;
}

// Ported from https://github.com/mhightower83/BacktraceLog
// Commented / disabled code segments and debug prints are stripped off.
// Spelling errors are also fixed.

#define BACKTRACE_MAX_RETRY 3
#define BACKTRACE_MAX_LOOKBACK 1024

// Copied from mmu_iram.h - We have a special need to read IRAM code. In a debug
// build the original would have validated the address range. And, panic at the
// attempt to access the IRAM code area. Original comments stripped.
static inline __attribute__((always_inline))
uint8_t _get_uint8(const void *p8) {
  void *v32 = (void *)((uintptr_t)p8 & ~(uintptr_t)3u);
  uint32_t val;
  __builtin_memcpy(&val, v32, sizeof(uint32_t));
  asm volatile ("" :"+r"(val)); // inject 32-bit dependency
  uint32_t pos = ((uintptr_t)p8 & 3u) * 8u;
  val >>= pos;
  return (uint8_t)val;
}

static inline uint8_t _idx(void *a) __attribute__((always_inline));
static inline uint8_t _idx(void *a) { return _get_uint8(a); }

static inline int idx(void *a, uint32_t b) __attribute__((always_inline));
static inline int sidx(void *a, uint32_t b) __attribute__((always_inline));

static inline int idx(void *a, uint32_t b) { return _idx((void*)((uintptr_t)a + b)); }
static inline int sidx(void *a, uint32_t b) { return (int8_t)_idx((void*)((uintptr_t)a + b)); }

static int find_addim_ax_a1(uint32_t pc, uint32_t off, int ax) {
    // returns an additional adjustment, if any, to reach a0 stored value
    int a0_off = -1;  // Assume failed
    if (1 == ax) {
        // a1 needs no adjustment
        return 0;
    }
    for (uint8_t *p0 = (uint8_t *)(pc - off);
        (uintptr_t)p0 < pc;
        p0 = (idx(p0, 0) & 0x08) ? &p0[2] : &p0[3]) {
        //
        // y2 d1 xx  addmi   ay, a1, (xx * 4)
        //
        if (idx(p0, 0) == (0x02 | (ax << 4)) && idx(p0, 1) == 0xd1) {
            a0_off = sidx(p0, 2) * 256;
            // We don't expect negative values
            // let negative values implicitly fail
            break;
        }
    }
    return a0_off;
}

// For a definitive return value, we look for a0 save.
// The current GNU compiler appears to store at +12 for a size 16 stack;
// however, some other compiler or version will save at 0.
// (maybe it is xtensa?)
//
// If we truly found the stack add instruction, then we should be able to scan
// forward looking for a0 being saved and where.
//
// Except, if the function being evaluated never calls another function there is
// no need to save a0 on the stack. Thus, this case would fail. Hmm, however,
// when using profiler (-finstrument-functions) every function does call another
// function forcing a0 to always be saved.
//
static
int find_s32i_a0_a1(uint32_t pc, uint32_t off) {
    int a0_off = -1;  // Assume failed

    // For the xtensa instruction set, it looks like, bit 0x08 on the LSB is the
    // instruction size bit. set => two bytes / clear => 3 bytes
    //
    // Scan forward
    for (uint8_t *p0 = (uint8_t *)(pc - off);
        (uintptr_t)p0 < pc;
        p0 = (idx(p0, 0) & 0x08) ? &p0[2] : &p0[3]) {
        //
        // 02 6x zz s32i   a0, ax, n  (n = zz * 4)
        //
        if (idx(p0, 0) == 0x02 && (idx(p0, 1) & 0xF0) == 0x60) {
            int ax = idx(p0, 1) & 0x0F;
            // Check for addmi ax, a1, n
            a0_off = find_addim_ax_a1((uint32_t)p0, (uintptr_t)p0 - (pc - off), ax);
            if (a0_off >= 0) a0_off += 4 * idx(p0, 2);
            break;
        } else
        //
        // 09 zx    s32i.n a0, ax, n  (n = z * 4)
        //
        if (idx(p0, 0) == 0x09) {
            int ax = idx(p0, 1) & 0x0F;
            // Check for addmi ax, a1, n
            a0_off = find_addim_ax_a1((uint32_t)p0, (uintptr_t)p0 - (pc - off), ax);
            if (a0_off >= 0) a0_off += 4 * (idx(p0, 1) >> 4);
            break;
        }
    }
    return a0_off;
}

static
bool verify_path_ret_to_pc(uint32_t pc, uint32_t off) {
    uint8_t *p0 = (uint8_t *)(pc - off);
    for (;
         (uintptr_t)p0 < pc;
         p0 = (idx(p0, 0) & 0x08) ? &p0[2] : &p0[3]);

    return ((uintptr_t)p0 == pc);
}

// Changes/Improvements:
//  * Do not alter output if detection failed.
//  * Monitor for A0 register save instruction, to get the correct
//    return address offset.
//  * Fix MOVI / SUB combo. Now handles any register selection and the two
//    instruction do not have to be consecutive.
//
// Returns true (1) on success
// int xt_retaddr_callee(const void *i_pc, const void *i_sp, const void *i_lr, void **o_pc, void **o_sp)
int xt_retaddr_callee_ex(const void * const i_pc, const void * const i_sp, const void * const i_lr, const void **o_pc, const void **o_sp, const void **o_fn)
{
    uint32_t lr = (uint32_t)i_lr; // last return ??
    uint32_t pc = (uint32_t)i_pc;
    uint32_t sp = (uint32_t)i_sp;
    uint32_t fn = 0;
    *o_fn = (void*)fn;

    uint32_t off = 2;
    const uint32_t text_size = prev_text_size(pc);

    // Most of the time "lr" will be set to the value in register "A0" which
    // very likely will be the return address when in a leaf function.
    // Otherwise, it could be anything. Test and disqualify early maybe allowing
    // better guesses later.
    if (!xt_pc_is_valid((void *)lr)) {
        lr = 0;
    }

    // The question is how aggressively should we keep looking.
    //
    // For now, keep searching BACKTRACE_MAX_RETRY are exhausted.
    //
    // A "ret.n" match represents a fail. BACKTRACE_MAX_LOOKBACK allows the
    // inner loop search to continue as long as "off" is less than
    // BACKTRACE_MAX_LOOKBACK.

    for (size_t retry = 0;
        (retry < BACKTRACE_MAX_RETRY) && (off < text_size) && pc;
        retry++, off++)
    {
        pc = (uint32_t)i_pc;
        sp = (uint32_t)i_sp;
        fn = 0;

        // Scan backward 1 byte at a time looking for a stack reserve or ret.n
        // This requires special handling to read IRAM/IROM/FLASH 1 byte at a time.
        for (; off < text_size; off++) {
            // What about 12d1xx   ADDMI a1, a1, -32768..32512 (-128..127 shifted by 8)?
            // Not likely to be useful. This is mostly used at the start of an
            // Exception frame. No need to see what an Interrupt interrupted. More
            // interesting to see what the interrupt did to cause an exception.
            // When we need to look behind an Exception frame, those start point
            // values are passed in.
            uint8_t *pb = (uint8_t *)((uintptr_t)pc - off);
            //
            // 12 c1 xx   ADDI a1, a1, -128..127
            //
            if (idx(pb, 0) == 0x12 && idx(pb, 1) == 0xc1) {
                const int stk_size = sidx(pb, 2); //((int8_t *)pb)[2];

                // Skip ADDIs that are clearing previous stack usage or not a multiple of 16.
                if (stk_size >= 0 || stk_size % 16 != 0) {
                    continue;
                }
                // Negative stack size, stack space creation/reservation and multiple of 16

                int a0_offset = find_s32i_a0_a1(pc, off);
                if (a0_offset < 0) {
                    continue;
                    // pc = lr;
                } else if (a0_offset >= -stk_size) {
                    continue;
                } else {
                    uint32_t *sp_a0 = (uint32_t *)((uintptr_t)sp + (uintptr_t)a0_offset);
                    fn = (pc - off) & ~3; // function entry points are aligned 4
                    pc = *sp_a0;
                }
                // Get back to the caller's stack
                sp -= stk_size;

                break;
            } else
            // The original code here had three bugs:
            //  1. It assumed a9 would be the only register used for setting the
            //     stack size.
            //  2. It assumed the SUB instruction would be immediately after the
            //     MOVI instruction.
            //  3. stk_size calculation needed a shift 8 left for the high 4 bits.
            //     This test would never match up to any code in the Boot ROM
            //
            // Solution to use:
            // Look for MOVI a?, -2048..2047
            // On match search forward through 32 bytes, for SUB a1, a1, a?
            // I think this will at least work for the Boot ROM code
            //
            // r2 Ax yz   MOVI r, -2048..2047
            //
            if ((idx(pb, 0) & 0x0F) == 0x02 && (idx(pb, 1) & 0xF0) == 0xa0) {
                int stk_size = ((idx(pb, 1) & 0x0F)<<8) + idx(pb, 2);
                stk_size |= (0 != (stk_size & BIT(11))) ? 0xFFFFF000 : 0;

                // With negative stack_size look for an add instruction
                // With a positive stack_size look for a sub instruction
                if (-2048 > stk_size || stk_size >= 2048 || 0 == stk_size || 0 != (3 & stk_size)) {
                    continue;
                }

                bool found = false;
                if (0 < stk_size) {
                    //
                    // r0 11 c0   SUB a1, a1, r
                    //
                    for (uint8_t *psub = &pb[3];
                         psub < &pb[32];            // Expect a match within 32 bytes
                         psub = (uint8_t*)((idx(psub, 0) & 0x80) ? ((uintptr_t)psub + 2) : ((uintptr_t)psub + 3))) {
                        if ((idx(psub, 0) & 0x0F) == 0x00 &&
                             idx(psub, 1) == 0x11 &&
                             idx(psub, 2) == 0xc0 &&
                            (idx(pb, 0) & 0xF0) == (idx(psub, 0) & 0xF0)) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        continue;
                    }
                    int a0_offset = find_s32i_a0_a1(pc, off);
                    if (a0_offset < 0) {
                        // pc = lr;
                        continue;
                    } else if (a0_offset >= stk_size) {
                        continue;
                    } else {
                        // fn = pc - off;
                        // pc = *(uint32_t *)(sp + a0_offset);
                        uint32_t *sp_a0 = (uint32_t *)((uintptr_t)sp + (uintptr_t)a0_offset);
                        fn = (pc - off) & ~3; // function entry points are aligned 4
                        pc = *sp_a0;
                    }

                    sp += stk_size;
                } else {
                    //
                    // 11 rA   ADD.n a1, a1, r
                    //
                    for (uint8_t *psub = &pb[3];
                         psub < &pb[32];            // Expect a match within 32 bytes
                         psub = (uint8_t*)((idx(psub, 0) & 0x80) ? ((uintptr_t)psub + 2) : ((uintptr_t)psub + 3))) {
                        if ( idx(psub, 1) == 0x11 &&
                            (idx(psub, 0) & 0x0F) == 0x0A &&
                            (idx(pb, 0) & 0xF0) == (idx(psub, 0) & 0xF0)) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        // Repeat with 3 byte add - untested
                        //
                        // r0 11 80   add a1, a1, r
                        //
                        for (uint8_t *psub = &pb[3];
                             psub < &pb[32];            // Expect a match within 32 bytes
                             psub = (uint8_t*)((idx(psub, 0) & 0x80) ? ((uintptr_t)psub + 2) : ((uintptr_t)psub + 3))) {
                            if ((idx(psub, 0) & 0x0F) == 0x00 &&
                                 idx(psub, 1) == 0x11 &&
                                 idx(psub, 2) == 0x80 &&
                                (idx(pb, 0) & 0xF0) == (idx(psub, 0) & 0xF0)) {
                                found = true;
                                break;
                            }
                        }
                    }
                    if (!found) {
                        continue;
                    }
                    int a0_offset = find_s32i_a0_a1(pc, off);
                    if (a0_offset < 0) {
                        // pc = lr;
                        continue;
                    } else if (a0_offset >= -stk_size) {
                        continue;
                    } else {
                        // fn = pc - off;
                        // pc = *(uint32_t *)(sp + a0_offset);
                        uint32_t *sp_a0 = (uint32_t *)((uintptr_t)sp + (uintptr_t)a0_offset);
                        fn = (pc - off) & ~3; // function entry points are aligned 4
                        pc = *sp_a0;
                    }

                    sp -= stk_size;
                }
                break;
            } else
            // Most fail to find, land here. The question is how aggressively
            // should we keep looking. Limit with BACKTRACE_MAX_LOOKBACK bytes
            // back from the start "pc".
            //
            // 0d f0     RET.N
            // 80 00 00  RET          # missing in original code!
            //
            if ((idx(pb, 0) == 0x0d && idx(pb, 1) == 0xf0) ||
                (idx(pb, 0) == 0x80 && idx(pb, 1) == 0x00 && idx(pb, 2) == 0x00)) {
                // Make sure pc is reachable. Follow the code back to PC.
                if (!verify_path_ret_to_pc(pc, off)) {
                    continue;
                }

                // Considerations: we bumped into what may be a ret.
                // It could be misaligned junk that looks like a ret.
                // If there are two or three zero's after the ret, that would be
                // more convincing.
                // Strategy, check zeros following "ret".
                if (off <= 8 || off > BACKTRACE_MAX_LOOKBACK) {
                    fn = 0;
                    pc = lr;
                    break;
                }

                continue;
            }
        }
        if (off >= text_size) {
            break;
        } else
        if (xt_pc_is_valid((void *)pc)) {
            break;
        }
    }

    //
    // Save only if successful
    //
    if (off < text_size) {
        *o_sp = (void *)sp;
        *o_pc = (void *)pc;
        *o_fn = (void *)fn;
        if (xt_pc_is_valid(*o_pc)) {
            // We changed the output registers anyway. So the caller can
            // evaluate what to do next.
            return 1;
        }
    }

    return 0;
}

int xt_retaddr_callee(const void * const i_pc, const void * const i_sp, const void * const i_lr, const void **o_pc, const void **o_sp)
{
    const void *o_fn; // ignored
    return xt_retaddr_callee_ex(i_pc, i_sp, i_lr, o_pc, o_sp, &o_fn);
}

struct BACKTRACE_PC_SP {
    const void *pc;
    const void *sp;
};

struct BACKTRACE_PC_SP xt_return_address_ex(int lvl)
{
    const void *i_sp;
    const void *i_pc;

    const void *o_pc = NULL;
    const void *o_sp;

    __asm__ __volatile__(
        "mov  %[sp], a1\n\t"
        "movi %[pc], .\n\t"
        : [pc]"=r"(i_pc), [sp]"=r"(i_sp)
        :
        : "memory");

    // The net effect of calling this function raises level up by 2.
    // We will need to skip over two more levels
    lvl += 2;
    while(lvl-- && xt_retaddr_callee(i_pc, i_sp, NULL, &o_pc, &o_sp)) {
        i_pc = o_pc;
        i_sp = o_sp;
    }

    struct BACKTRACE_PC_SP pc_sp = {NULL, NULL};
    if (xt_pc_is_valid(o_pc)) {
        pc_sp.pc = o_pc;
        pc_sp.sp = o_sp;
    }

    return pc_sp;
}


const void *xt_return_address(int lvl) {
    return xt_return_address_ex(lvl).pc;
}
