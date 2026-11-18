# Generate a copy of the active multilib libgcc.a with Mask ROM symbols removed
# so that ROM routines (e.g. float/64-bit helpers) are not duplicated in flash.
# Runs at CMake configure time because PlatformIO configures CMake via the
# file API and builds with SCons rather than Ninja.
function(esp8266_generate_romstrip_libgcc out_var)
    set(_cflags "${ESP8266_DYNCONFIG_FLAG}")
    if(NOT BOOTLOADER_BUILD AND NOT CONFIG_COMPILER_CXX_RTTI)
        list(APPEND _cflags "-fno-rtti")
    endif()

    execute_process(
        COMMAND "${CMAKE_C_COMPILER}" ${_cflags} -print-file-name=libgcc.a
        OUTPUT_VARIABLE _src_libgcc
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE _gcc_res
    )
    if(NOT _gcc_res EQUAL 0 OR NOT _src_libgcc)
        message(FATAL_ERROR "Failed to locate libgcc.a with ${CMAKE_C_COMPILER} ${_cflags}")
    endif()
    get_filename_component(_src_libgcc "${_src_libgcc}" ABSOLUTE)

    idf_build_get_property(_idf IDF_PATH)
    if(NOT _idf)
        get_filename_component(_idf "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
    endif()
    set(_rom_ld "${_idf}/components/esp8266/ld/esp8266.rom.ld")
    set(_script "${_idf}/tools/cmake/scripts/strip_rom_libgcc.py")
    set(_out "${CMAKE_BINARY_DIR}/rom_stripped_lib/libgcc_romstrip.a")

    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${_src_libgcc}" "${_rom_ld}" "${_script}"
    )

    if(NOT (EXISTS "${_out}"
            AND "${_out}" IS_NEWER_THAN "${_src_libgcc}"
            AND "${_out}" IS_NEWER_THAN "${_rom_ld}"
            AND "${_out}" IS_NEWER_THAN "${_script}"))
        idf_build_get_property(_python PYTHON)
        if(NOT _python)
            set(_python "python")
        endif()
        set(_cflag_args)
        foreach(_f ${_cflags})
            list(APPEND _cflag_args "--cflag=${_f}")
        endforeach()
        execute_process(
            COMMAND "${_python}" "${_script}"
                --cc "${CMAKE_C_COMPILER}"
                --ar "${CMAKE_AR}"
                --nm "${CMAKE_NM}"
                ${_cflag_args}
                --rom-ld "${_rom_ld}"
                --output "${_out}"
            RESULT_VARIABLE _strip_res
        )
        if(NOT _strip_res EQUAL 0)
            message(FATAL_ERROR "strip_rom_libgcc.py failed (exit ${_strip_res})")
        endif()
    endif()

    set(${out_var} "${_out}" PARENT_SCOPE)
endfunction()
