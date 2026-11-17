#pragma once

#include_next <sys/lock.h>

#if defined(_RETARGETABLE_LOCKING)

#ifdef __cplusplus
extern "C" {
#endif

typedef int _lock_t;

#if defined(BOOTLOADER_BUILD) || defined(__BOOTLOADER_BUILD)
#define _lock_init(lock) ((void)(lock))
#define _lock_init_recursive(lock) ((void)(lock))
#define _lock_close(lock) ((void)(lock))
#define _lock_close_recursive(lock) ((void)(lock))
#define _lock_acquire(lock) ((void)(lock))
#define _lock_acquire_recursive(lock) ((void)(lock))
#define _lock_try_acquire(lock) (((void)(lock)), 0)
#define _lock_try_acquire_recursive(lock) (((void)(lock)), 0)
#define _lock_release(lock) ((void)(lock))
#define _lock_release_recursive(lock) ((void)(lock))
#else
void _lock_init(_lock_t *lock);
void _lock_init_recursive(_lock_t *lock);
void _lock_close(_lock_t *lock);
void _lock_close_recursive(_lock_t *lock);
void _lock_acquire(_lock_t *lock);
void _lock_acquire_recursive(_lock_t *lock);
int _lock_try_acquire(_lock_t *lock);
int _lock_try_acquire_recursive(_lock_t *lock);
void _lock_release(_lock_t *lock);
void _lock_release_recursive(_lock_t *lock);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _RETARGETABLE_LOCKING */
