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

get_filename_component(_newlib_cc_name "${CMAKE_C_COMPILER}" NAME)
if(_newlib_cc_name MATCHES "xtensa-esp-elf")
    find_program(_newlib_cc_path "${CMAKE_C_COMPILER}")
    if(_newlib_cc_path)
        get_filename_component(_newlib_bin_dir "${_newlib_cc_path}" DIRECTORY)
        get_filename_component(_newlib_tc_root "${_newlib_bin_dir}" DIRECTORY)
        set(_newlib_nano_inc "${_newlib_tc_root}/newlib-nano/xtensa-esp-elf/include")
        if(CONFIG_COMPILER_CXX_RTTI)
            set(_newlib_nano_lib "${_newlib_tc_root}/newlib-nano/xtensa-esp-elf/lib/esp8266")
        else()
            set(_newlib_nano_lib "${_newlib_tc_root}/newlib-nano/xtensa-esp-elf/lib/esp8266/no-rtti")
        endif()
        if(CONFIG_NEWLIB_NANO_FORMAT)
            if(EXISTS "${_newlib_nano_inc}")
                target_include_directories(${COMPONENT_LIB} SYSTEM PUBLIC "${_newlib_nano_inc}")
            endif()
            if(EXISTS "${_newlib_nano_lib}")
                target_link_libraries(${COMPONENT_LIB} INTERFACE "-L${_newlib_nano_lib}")
            endif()
        endif()
    endif()
    if(NOT CONFIG_COMPILER_CXX_RTTI)
        target_link_libraries(${COMPONENT_LIB} INTERFACE "-fno-rtti")
    endif()
endif()

# Toolchain libraries require code defined in this component
idf_component_get_property(newlib newlib COMPONENT_LIB)
target_link_libraries(${COMPONENT_LIB} INTERFACE ${LIBC} ${LIBM} gcc "$<TARGET_FILE:${newlib}>")

# Forces the linker to include __errno (and retargetable locks) from this component,
# instead of the implementations provided by newlib.
set(EXTRA_LINK_FLAGS "-u __errno")
if(_newlib_cc_name MATCHES "xtensa-esp-elf")
    list(APPEND EXTRA_LINK_FLAGS "-u __retarget_lock_init" "-Wl,--wrap=__swhatbuf_r" "-Wl,--wrap=__smakebuf_r")
endif()
target_link_libraries(${COMPONENT_LIB} INTERFACE "${EXTRA_LINK_FLAGS}")

