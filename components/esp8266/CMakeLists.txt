if(BOOTLOADER_BUILD)
    # For bootloader, all we need from esp8266 is headers
    set(COMPONENT_ADD_INCLUDEDIRS include)
    # set(COMPONENT_REQUIRES ${COMPONENTS})
    set(COMPONENT_SRCS source/ets_printf.c source/crc.c source/esp_fast_boot.c)
    register_component(esp8266)

    idf_build_get_property(_idf_path IDF_PATH)
    idf_build_get_property(_strip_python PYTHON)
    if(NOT _strip_python)
        set(_strip_python "python")
    endif()
    set(_stripped_libgcc_dir "${CMAKE_BINARY_DIR}/rom_stripped_lib")
    set(_stripped_libgcc "${_stripped_libgcc_dir}/libgcc.a")
    get_filename_component(_esp_cc_name "${CMAKE_C_COMPILER}" NAME)
    set(_strip_cflags)
    if(_esp_cc_name MATCHES "xtensa-esp-elf")
        list(APPEND _strip_cflags "--cflag=-mdynconfig=xtensa_esp8266.so")
    endif()

    execute_process(
        COMMAND "${_strip_python}" "${_idf_path}/tools/cmake/scripts/strip_rom_libgcc.py"
            --cc "${CMAKE_C_COMPILER}"
            --ar "${CMAKE_AR}"
            --nm "${CMAKE_NM}"
            ${_strip_cflags}
            --rom-ld "${CMAKE_CURRENT_SOURCE_DIR}/ld/esp8266.rom.ld"
            --output "${_stripped_libgcc}"
        RESULT_VARIABLE _strip_libgcc_res
    )
    if(NOT _strip_libgcc_res EQUAL 0)
        message(FATAL_ERROR "strip_rom_libgcc.py failed for bootloader (exit ${_strip_libgcc_res})")
    endif()

    # as cmake won't attach linker args to a header-only library, attach
    # linker args directly to the bootloader.elf
    set(ESP8266_BOOTLOADER_LINKER_SCRIPTS
        "${CMAKE_CURRENT_SOURCE_DIR}/ld/esp8266.rom.ld"
        PARENT_SCOPE
        )

    set(ESP8266_BOOTLOADER_LIBS
        "-L ${_stripped_libgcc_dir}"
        "-L ${CMAKE_CURRENT_SOURCE_DIR}/lib"
        "gcc"
        "core"
        PARENT_SCOPE
        )

else()
    # Regular app build

    set(srcs
        "source/chip_boot.c"
        "source/backtrace.c"
        "source/cxx_abi.cpp"
        "source/esp_sleep.c"
        "source/esp_timer.c"
        "source/esp_wifi_os_adapter.c"
        "source/esp_wifi.c"
        "source/ets_printf.c"
        "source/crc.c"
        "source/phy_init.c"
        "source/reset_reason.c"
        "source/smartconfig.c"
        "source/smartconfig_ack.c"
        "source/startup.c"
        "source/system_api.c"
        "source/task_wdt.c"
        "source/rom.c"
        "source/hw_random.c"
        "source/esp_fast_boot.c"
        "driver/adc.c"
        "driver/gpio.c"
        "driver/hw_timer.c"
        "driver/i2c.c"
        "driver/i2s.c"
        "driver/pwm.c"
        "driver/sigma_delta.c"
        "driver/spi.c"
        "driver/hspi_logic_layer.c"
        "driver/uart.c"
        "driver/ir_tx.c"
        "driver/ir_rx.c"
        "driver/ledc.c")

    set(include_dirs "include" "include/driver")

    set(requires "esp_common" "esp_event")
    set(priv_requires "wpa_supplicant" "log" "spi_flash" "tcpip_adapter" "esp_ringbuf" "bootloader_support" "nvs_flash" "app_update")
    set(fragments linker.lf ld/esp8266_fragments.lf ld/esp8266_bss_fragments.lf)

    idf_component_register(SRCS "${srcs}"
                    INCLUDE_DIRS "${include_dirs}"
                    REQUIRES "${requires}"
                    PRIV_REQUIRES "${priv_requires}"
                    LDFRAGMENTS "${fragments}"
                    REQUIRED_IDF_TARGETS esp8266)

    idf_build_get_property(_idf_path IDF_PATH)
    idf_build_get_property(_strip_python PYTHON)
    if(NOT _strip_python)
        set(_strip_python "python")
    endif()
    set(_stripped_libgcc_dir "${CMAKE_BINARY_DIR}/rom_stripped_lib")
    set(_stripped_libgcc "${_stripped_libgcc_dir}/libgcc.a")
    get_filename_component(_esp_cc_name "${CMAKE_C_COMPILER}" NAME)
    set(_strip_cflags)
    if(_esp_cc_name MATCHES "xtensa-esp-elf")
        list(APPEND _strip_cflags "--cflag=-mdynconfig=xtensa_esp8266.so")
        if(NOT CONFIG_COMPILER_CXX_RTTI)
            list(APPEND _strip_cflags "--cflag=-fno-rtti")
        endif()
    endif()

    execute_process(
        COMMAND "${_strip_python}" "${_idf_path}/tools/cmake/scripts/strip_rom_libgcc.py"
            --cc "${CMAKE_C_COMPILER}"
            --ar "${CMAKE_AR}"
            --nm "${CMAKE_NM}"
            ${_strip_cflags}
            --rom-ld "${CMAKE_CURRENT_SOURCE_DIR}/ld/esp8266.rom.ld"
            --output "${_stripped_libgcc}"
        RESULT_VARIABLE _strip_libgcc_res
    )
    if(NOT _strip_libgcc_res EQUAL 0)
        message(FATAL_ERROR "strip_rom_libgcc.py failed for app (exit ${_strip_libgcc_res})")
    endif()

    target_link_libraries(${COMPONENT_LIB} PUBLIC "-L ${_stripped_libgcc_dir}" "-L ${CMAKE_CURRENT_SOURCE_DIR}/lib" "-lstdc++")
    target_compile_definitions(${COMPONENT_LIB} PUBLIC -DUSING_IBUS_FASTER_GET)
    if(NOT CONFIG_NO_BLOBS)
        set(blobs "gcc" "hal" "phy" "rtc" "clk" "smartconfig" "ssc")
        if(CONFIG_ESP8266_WIFI_DEBUG_LOG_ENABLE)
            list(APPEND blobs "core_dbg" "net80211_dbg" "pp_dbg" "espnow_dbg")
        else()
            list(APPEND blobs "core" "net80211" "pp" "espnow")
        endif()
        foreach(blob ${blobs})
            add_library(${blob} STATIC IMPORTED)
            if(blob STREQUAL "gcc")
                set_property(TARGET ${blob} PROPERTY IMPORTED_LOCATION "${_stripped_libgcc}")
            else()
                set_property(TARGET ${blob} PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/lib/lib${blob}.a)
            endif()
            target_link_libraries(${COMPONENT_LIB} PUBLIC ${blob})

            foreach(_blob ${blobs})
                if(NOT _blob STREQUAL ${blob})
                    set_property(TARGET ${blob} APPEND PROPERTY INTERFACE_LINK_LIBRARIES ${_blob})
                endif()
            endforeach()

            set_property(TARGET ${blob} APPEND PROPERTY INTERFACE_LINK_LIBRARIES ${COMPONENT_LIB})
        endforeach()
    endif()
    target_linker_script(${COMPONENT_LIB} INTERFACE "${CMAKE_CURRENT_BINARY_DIR}/esp8266_out.ld")

    target_linker_script(${COMPONENT_LIB} INTERFACE "${CMAKE_CURRENT_LIST_DIR}/ld/esp8266.project.ld.in" 
                        PROCESS "${CMAKE_CURRENT_BINARY_DIR}/ld/esp8266.project.ld")

    target_linker_script(${COMPONENT_LIB} INTERFACE "ld/esp8266.rom.ld")
    target_linker_script(${COMPONENT_LIB} INTERFACE "ld/esp8266.peripherals.ld")

    target_link_libraries(${COMPONENT_LIB} INTERFACE "-u call_user_start")

    # Preprocess esp8266.ld linker script to include configuration, becomes esp8266_out.ld
    set(LD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/ld)

    partition_table_get_partition_info(app_offset "--partition-boot-default" "offset")
    partition_table_get_partition_info(app_size "--partition-boot-default" "size")
    set(CFLAGS ${CFLAGS} -DAPP_OFFSET=${app_offset} -DAPP_SIZE=${app_size})
    if(_esp_cc_name MATCHES "xtensa-esp-elf")
        set(CFLAGS -mdynconfig=xtensa_esp8266.so ${CFLAGS})
    endif()

    add_custom_command(
        OUTPUT esp8266_out.ld
        COMMAND "${CMAKE_C_COMPILER}" -C -P -x c -E -o esp8266_out.ld ${CFLAGS} -I ${CONFIG_DIR} ${LD_DIR}/esp8266.ld
        MAIN_DEPENDENCY ${LD_DIR}/esp8266.ld ${SDKCONFIG_H}
        COMMENT "Generating memory map linker script..."
        VERBATIM)
    add_custom_target(esp8266_linker_script DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/esp8266_out.ld")
    add_dependencies(${COMPONENT_LIB} esp8266_linker_script)

    if(CONFIG_ESP_PHY_INIT_DATA_IN_PARTITION)
        set(PHY_INIT_DATA_BIN ${build_dir}/phy_init_data.bin)

        # To get the phy_init_data.bin file, compile phy_init_data.h as a C file and then objcopy
        # the object file to a raw binary
        add_custom_command(
            OUTPUT ${PHY_INIT_DATA_BIN}
            DEPENDS ${CMAKE_CURRENT_LIST_DIR}/include/esp_private/phy_init_data.h
            COMMAND ${CMAKE_C_COMPILER} -x c -c
            -I ${CMAKE_CURRENT_LIST_DIR} -I ${CMAKE_CURRENT_LIST_DIR}/include -I ${CMAKE_BINARY_DIR}
            -I ${CONFIG_DIR} -I ${CMAKE_CURRENT_LIST_DIR}/../esp_common/include
            -o phy_init_data.obj
            ${CMAKE_CURRENT_LIST_DIR}/include/esp_private/phy_init_data.h
            COMMAND ${CMAKE_OBJCOPY} -O binary phy_init_data.obj ${PHY_INIT_DATA_BIN}
            )
        add_custom_target(phy_init_data ALL DEPENDS ${PHY_INIT_DATA_BIN})
        add_dependencies(flash phy_init_data)

        partition_table_get_partition_info(phy_init_data_offset "--partition-type data --partition-subtype phy" "offset")
        esptool_py_flash_project_args(phy_init_data ${phy_init_data_offset} "${PHY_INIT_DATA_BIN}" FLASH_IN_PROJECT)
    endif()

    if(CONFIG_ESP_FILENAME_MACRO_NO_PATH)
        target_compile_definitions(${COMPONENT_LIB} PUBLIC -D __ESP_FILE__=__FILE__)
    endif()

    if(CONFIG_ESP_FILENAME_MACRO_RAW)
        target_compile_definitions(${COMPONENT_LIB} PUBLIC -D __ESP_FILE__=__FILE__)
    endif()

    if(CONFIG_ESP_FILENAME_MACRO_NULL)
        target_compile_definitions(${COMPONENT_LIB} PUBLIC -D __ESP_FILE__="null")
    endif()

endif()
