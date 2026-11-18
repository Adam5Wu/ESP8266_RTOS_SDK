// Copyright 2015-2016 Espressif Systems (Shanghai) PTE LTD
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

#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/reent.h>
#include "esp_attr.h"
#include "esp_vfs_dev.h"

#define _STR(_s)    #_s
#define STR(_s)     _STR(_s)

#if !defined(__NEWLIB__) || __NEWLIB__ < 4
#error "gcc16 branches require Newlib >= 4 (xtensa-esp-elf GCC 16)"
#endif

/**
 * This is the replacement for newlib's _REENT_INIT_PTR and __sinit.
 * The problem with __sinit is that it allocates three FILE structures
 * (stdin, stdout, stderr). Having individual standard streams for each task
 * is a bit too much on a small embedded system. So we point streams
 * to the streams of the global struct _reent, which are initialized in
 * startup code.
 */
void esp_reent_init(struct _reent* r)
{
    memset(r, 0, sizeof(*r));
    if (r == _GLOBAL_REENT) {
        /* Point at Newlib 4's static __sf[3] so freopen() reuses them instead of
         * allocating a duplicate heap glue block. */
        r->_stdin  = &__sf[0];
        r->_stdout = &__sf[1];
        r->_stderr = &__sf[2];
    } else {
        r->_stdout = _GLOBAL_REENT->_stdout;
        r->_stderr = _GLOBAL_REENT->_stderr;
        r->_stdin  = _GLOBAL_REENT->_stdin;
    }
}

/* only declared in private stdio header file, local.h */
extern void __sfp_lock_acquire(void);
extern void __sfp_lock_release(void);

void esp_reent_cleanup(void)
{
    struct _reent* r = __getreent();
    /* Clean up storage used by mprec functions */
    if (r->_mp) {
        if (_REENT_MP_FREELIST(r)) {
            for (int i = 0; i < _Kmax; ++i) {
                struct _Bigint *cur, *next;
                next = _REENT_MP_FREELIST(r)[i];
                while (next) {
                    cur = next;
                    next = next->_next;
                    free(cur);
                }
            }
        }
        free(_REENT_MP_FREELIST(r));
        free(_REENT_MP_RESULT(r));
    }

    /* Clean up "glue" (lazily-allocated FILE objects) */
    struct _glue* prev = &__sglue;
    for (struct _glue* cur = __sglue._next; cur != NULL;) {
        if (cur->_niobs == 0) {
            cur = cur->_next;
            continue;
        }
        bool has_open_files = false;
        for (int i = 0; i < cur->_niobs; ++i) {
            FILE* fp = &cur->_iobs[i];
            if (fp->_flags != 0) {
                has_open_files = true;
                break;
            }
        }
        if (has_open_files) {
            prev = cur;
            cur = cur->_next;
            continue;
        }
        struct _glue* next = cur->_next;
        prev->_next = next;
        free(cur);
        cur = next;
    }

    /* Clean up various other buffers */
    free(r->_mp);
    r->_mp = NULL;
    free(r->_r48);
    r->_r48 = NULL;
    free(r->_localtime_buf);
    r->_localtime_buf = NULL;
    free(r->_asctime_buf);
    r->_asctime_buf = NULL;
}

/*
 * @brief Initialize newlib's platform object data
 */
int esp_newlib_init(void)
{
    const char *default_uart_dev = "/dev/uart/" STR(CONFIG_CONSOLE_UART_NUM);

    _impure_ptr = _GLOBAL_REENT;
    esp_reent_init(_GLOBAL_REENT);

    esp_vfs_dev_uart_register();

    /* Reuse Newlib 4's static __sf[3] via freopen() to avoid allocating a duplicate
     * heap glue block (~430 B). Open in stdin/stdout/stderr (0/1/2) order so
     * _freopen_r's initial close() of __sf[i]._file (= i) never closes an already
     * allocated VFS fd from s_fd_table[0..2]. */
    if (!freopen(default_uart_dev, "r", stdin))
        goto err;

    if (!freopen(default_uart_dev, "w", stdout))
        goto err_stdin;

    if (!freopen(default_uart_dev, "w", stderr))
        goto err_stdout;

    environ = malloc(sizeof(char*));
    if (!environ)
        goto err_env;
    environ[0] = NULL;

    return 0;

err_env:
    fclose(stderr);
err_stdout:
    fclose(stdout);
err_stdin:
    fclose(stdin);
err:
    return -1;
}

struct _reent* __getreent()
{
    return _impure_ptr ? _impure_ptr : _GLOBAL_REENT;
}