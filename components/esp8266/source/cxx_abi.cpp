#include <new>
#include <stddef.h>
#include <stdlib.h>

#include "rom/ets_sys.h"

// Firmware never exits, so registered destructors would never run.
// Stubbing atexit avoids pulling in Newlib 4's static __atexit0 (140 B DRAM BSS)
// and __atexit_recursive_mutex.
extern "C" int atexit(void (*)(void)) {
    return 0;
}

// Firmware never exits, so global C++ destructors registered with __cxa_atexit are no-ops.
extern "C" int __cxa_atexit(void (*)(void *), void *, void *) {
    return 0;
}

extern "C" void __cxx_abi_force_link(void) {}

#if !defined(__cpp_exceptions)

static inline void *alloc_nonnull(size_t size) {
    void *p = malloc(size ? size : 1);
    if (!p) {
        abort();
    }
    return p;
}

void *operator new(size_t size) {
    return alloc_nonnull(size);
}

void *operator new[](size_t size) {
    return alloc_nonnull(size);
}

void *operator new(size_t size, const std::nothrow_t &) noexcept {
    return malloc(size ? size : 1);
}

void *operator new[](size_t size, const std::nothrow_t &) noexcept {
    return malloc(size ? size : 1);
}

namespace {
[[noreturn]] void abort_cxx(const char *name) {
    ets_printf("C++ %s\n", name);
    abort();
}

[[noreturn]] void abort_cxx(const char *name, const char *msg) {
    ets_printf("C++ %s: %s\n", name, msg ? msg : "");
    abort();
}
}  // namespace

namespace __gnu_cxx {
void __verbose_terminate_handler() {
    abort_cxx("__verbose_terminate_handler");
}
}  // namespace __gnu_cxx

extern "C" void __cxa_pure_virtual(void) {
    abort_cxx("__cxa_pure_virtual");
}

extern "C" void __cxa_deleted_virtual(void) {
    abort_cxx("__cxa_deleted_virtual");
}

extern "C" void *__cxa_allocate_exception(size_t) noexcept {
    abort_cxx("__cxa_allocate_exception");
}

extern "C" void __cxa_free_exception(void *) noexcept {
    abort_cxx("__cxa_free_exception");
}

extern "C" void *__cxa_allocate_dependent_exception(void) noexcept {
    abort_cxx("__cxa_allocate_dependent_exception");
}

extern "C" void __cxa_free_dependent_exception(void *) noexcept {
    abort_cxx("__cxa_free_dependent_exception");
}

extern "C" void __cxa_throw(void *, void *, void (*)(void *)) {
    abort_cxx("__cxa_throw");
}

extern "C" void __cxa_call_terminate(void *) noexcept {
    abort_cxx("__cxa_call_terminate");
}

extern "C" int __gxx_personality_v0(...) {
    abort_cxx("__gxx_personality_v0");
}

namespace std {
void __throw_bad_cast() { abort_cxx("__throw_bad_cast"); }
void __throw_bad_alloc() { abort_cxx("__throw_bad_alloc"); }
void __throw_bad_typeid() { abort_cxx("__throw_bad_typeid"); }
void __throw_bad_exception() { abort_cxx("__throw_bad_exception"); }
void __throw_bad_array_new_length() { abort_cxx("__throw_bad_array_new_length"); }
void __throw_bad_function_call() { abort_cxx("__throw_bad_function_call"); }
void __throw_logic_error(const char *s) { abort_cxx("__throw_logic_error", s); }
void __throw_range_error(const char *s) { abort_cxx("__throw_range_error", s); }
void __throw_domain_error(const char *s) { abort_cxx("__throw_domain_error", s); }
void __throw_length_error(const char *s) { abort_cxx("__throw_length_error", s); }
void __throw_out_of_range(const char *s) { abort_cxx("__throw_out_of_range", s); }
void __throw_runtime_error(const char *s) { abort_cxx("__throw_runtime_error", s); }
void __throw_overflow_error(const char *s) { abort_cxx("__throw_overflow_error", s); }
void __throw_underflow_error(const char *s) { abort_cxx("__throw_underflow_error", s); }
void __throw_invalid_argument(const char *s) { abort_cxx("__throw_invalid_argument", s); }
void __throw_out_of_range_fmt(const char *fmt, ...) { abort_cxx("__throw_out_of_range_fmt", fmt); }
}  // namespace std

#endif
