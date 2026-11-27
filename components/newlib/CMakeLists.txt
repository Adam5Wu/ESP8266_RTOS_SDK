set(include_dirs platform_include)
set(srcs src/esp_malloc.c
         src/locks.c
         src/random.c
         src/reent_init.c
         src/select.c
         src/syscall.c
         src/termios.c
         src/time.c)

idf_component_register(SRCS "${srcs}"
                    INCLUDE_DIRS "${include_dirs}"
                    PRIV_REQUIRES esp8266 freertos)  

if(CONFIG_NEWLIB_NANO_FORMAT)
set(LIBC c_nano)
else()
set(LIBC c)
endif()

set(LIBM m)

set(_newlib_nano_inc "${ESP8266_TOOLCHAIN_ROOT}/newlib-nano/xtensa-esp-elf/include")

if(CONFIG_NEWLIB_NANO_FORMAT)
    set(_stdcxx_root "${ESP8266_TOOLCHAIN_ROOT}/newlib-nano/xtensa-esp-elf/lib")
else()
    set(_stdcxx_root "${ESP8266_TOOLCHAIN_ROOT}/xtensa-esp-elf/lib")
endif()

if(CONFIG_COMPILER_CXX_RTTI)
    set(_stdcxx_rtti_dir "${_stdcxx_root}/esp8266")
else()
    set(_stdcxx_rtti_dir "${_stdcxx_root}/esp8266/no-rtti")
endif()

if(NOT CONFIG_COMPILER_CXX_EXCEPTIONS AND EXISTS "${_stdcxx_rtti_dir}/no-exceptions/libstdc++.a")
    target_link_libraries(${COMPONENT_LIB} INTERFACE "-L${_stdcxx_rtti_dir}/no-exceptions")
endif()

if(CONFIG_NEWLIB_NANO_FORMAT)
    if(EXISTS "${_newlib_nano_inc}")
        target_include_directories(${COMPONENT_LIB} SYSTEM PUBLIC "${_newlib_nano_inc}")
    endif()
    if(EXISTS "${_stdcxx_rtti_dir}")
        target_link_libraries(${COMPONENT_LIB} INTERFACE "-L${_stdcxx_rtti_dir}")
    endif()
    if(CONFIG_NEWLIB_NANO_FORMAT_FLOAT)
        target_link_libraries(${COMPONENT_LIB} INTERFACE "-Wl,-u,_printf_float")
    endif()
endif()
if(NOT CONFIG_COMPILER_CXX_RTTI)
    target_link_libraries(${COMPONENT_LIB} INTERFACE "-fno-rtti")
endif()

# Toolchain libraries require code defined in this component
idf_build_get_property(_idf_path IDF_PATH)
include("${_idf_path}/tools/cmake/romstrip.cmake")
esp8266_romstrip_libgcc_path(_romstrip_libgcc)
idf_component_get_property(newlib newlib COMPONENT_LIB)
target_link_libraries(${COMPONENT_LIB} INTERFACE ${LIBC} ${LIBM} "${_romstrip_libgcc}" "$<TARGET_FILE:${newlib}>")

# Forces the linker to include __errno (and retargetable locks) from this component,
# instead of the implementations provided by newlib.
set(EXTRA_LINK_FLAGS "-u __errno" "-u __retarget_lock_init")
target_link_libraries(${COMPONENT_LIB} INTERFACE "${EXTRA_LINK_FLAGS}")

