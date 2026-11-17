#include <stdlib.h>

#if !defined(__cpp_exceptions)

namespace __gnu_cxx {
void __verbose_terminate_handler() {
    abort();
}
}  // namespace __gnu_cxx

extern "C" void __cxa_pure_virtual(void) {
    abort();
}

extern "C" void __cxa_deleted_virtual(void) {
    abort();
}

namespace std {
void __throw_bad_cast() { abort(); }
void __throw_bad_alloc() { abort(); }
void __throw_bad_typeid() { abort(); }
void __throw_bad_exception() { abort(); }
void __throw_bad_array_new_length() { abort(); }
void __throw_bad_function_call() { abort(); }
void __throw_logic_error(const char*) { abort(); }
void __throw_range_error(const char*) { abort(); }
void __throw_domain_error(const char*) { abort(); }
void __throw_length_error(const char*) { abort(); }
void __throw_out_of_range(const char*) { abort(); }
void __throw_runtime_error(const char*) { abort(); }
void __throw_overflow_error(const char*) { abort(); }
void __throw_underflow_error(const char*) { abort(); }
void __throw_invalid_argument(const char*) { abort(); }
void __throw_out_of_range_fmt(const char*, ...) { abort(); }
}  // namespace std

#endif
