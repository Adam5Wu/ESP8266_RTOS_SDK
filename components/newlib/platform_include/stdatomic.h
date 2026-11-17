#pragma once

#include <machine/_default_types.h>

#if defined(__NEWLIB__) && (__NEWLIB__ >= 4)
#ifndef ___wchar_t_defined
#define ___wchar_t_defined
typedef __wchar_t ___wchar_t;
#endif
#endif

#include_next <stdatomic.h>
