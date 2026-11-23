if(BOOTLOADER_BUILD)
    # For bootloader, all we need from esp8266 is headers + blob-free core helpers
    set(COMPONENT_ADD_INCLUDEDIRS include)
    # set(COMPONENT_REQUIRES ${COMPONENTS})
    set(COMPONENT_SRCS source/ets_printf.c source/crc.c source/esp_fast_boot.c source/esp_misc.c)
    register_component(esp8266)

    idf_build_get_property(_idf_path IDF_PATH)
    include("${_idf_path}/tools/cmake/romstrip.cmake")
    esp8266_generate_romstrip_libgcc(_romstrip_libgcc)

    # as cmake won't attach linker args to a header-only library, attach
    # linker args directly to the bootloader.elf
    set(ESP8266_BOOTLOADER_LINKER_SCRIPTS
        "${CMAKE_CURRENT_SOURCE_DIR}/ld/esp8266.rom.ld"
        PARENT_SCOPE
        )

    set(ESP8266_BOOTLOADER_LIBS
        "${_romstrip_libgcc}"
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

    if(CONFIG_ESP8266_OSS_HAL)
        list(APPEND srcs "source/xtensa_hal.S")
    endif()

    if(CONFIG_ESP8266_OSS_CORE)
        list(APPEND srcs
            "source/esp_clk_rtc.c"
            "source/esp_ets_timer.c"
            "source/esp_misc.c"
            "source/esp_misc_nvs.c"
            "source/esp_sys_ctrl.c")
    endif()

    if(CONFIG_ESP8266_OSS_PHY_ONLY)
        list(APPEND srcs "source/esp_no_blobs_stubs.c")
    endif()

    if(CONFIG_ESP8266_OSS_PHY)
        list(APPEND srcs
            "phy/phy_soc.c"
            "phy/phy_i2c_pbus.c"
            "phy/phy_clock.c"
            "phy/phy_adc.c"
            "phy/phy_sleep.c")
    endif()

    if(CONFIG_ESP8266_OSS_PHY_WIFI)
        list(APPEND srcs
            "phy/phy_rf_chan.c"
            "phy/phy_rxgain.c"
            "phy/phy_cal_tx.c"
            "phy/phy_core.c"
            "lmac/lmac_nmi.c"
            "lmac/lmac_dma.c"
            "lmac/lmac_tx.c"
            "lmac/lmac_trc.c"
            "lmac/lmac_crypto_vif.c"
            "lmac/lmac_pm_compat.c"
            "net80211/net80211_worker.c"
            "net80211/net80211_nvs_rtc.c"
            "net80211/net80211_supp_glue.c"
            "net80211/net80211_scan.c"
            "net80211/net80211_sta.c"
            "net80211/net80211_ap.c"
            "net80211/net80211_data.c"
            "net80211/net80211_pm.c"
            "net80211/net80211_api.c")
    endif()

    if(CONFIG_ESP8266_VENDOR_SMARTCONFIG)
        list(APPEND srcs
            "source/smartconfig.c"
            "source/smartconfig_ack.c")
    endif()

    set(include_dirs "include" "include/driver")

    set(requires "esp_common" "esp_event")
    set(priv_requires "wpa_supplicant" "log" "spi_flash" "tcpip_adapter" "esp_ringbuf" "bootloader_support" "nvs_flash" "app_update")
    set(fragments linker.lf ld/esp8266_fragments.lf ld/esp8266_bss_fragments.lf)

    idf_component_register(SRCS "${srcs}"
                    INCLUDE_DIRS "${include_dirs}"
                    PRIV_INCLUDE_DIRS "phy" "lmac" "net80211" "../wpa_supplicant/src/esp_supplicant"
                    REQUIRES "${requires}"
                    PRIV_REQUIRES "${priv_requires}"
                    LDFRAGMENTS "${fragments}"
                    REQUIRED_IDF_TARGETS esp8266)

    if(CONFIG_ESP8266_OSS_PHY_WIFI)
        set_source_files_properties(lmac/lmac_nmi.c PROPERTIES COMPILE_OPTIONS "-fno-jump-tables")
    endif()

    idf_build_get_property(_idf_path IDF_PATH)
    include("${_idf_path}/tools/cmake/romstrip.cmake")
    esp8266_generate_romstrip_libgcc(_romstrip_libgcc)

    target_link_libraries(${COMPONENT_LIB} PUBLIC "${_romstrip_libgcc}" "-lstdc++")
    target_compile_definitions(${COMPONENT_LIB} PUBLIC -DUSING_IBUS_FASTER_GET)
    if(CONFIG_ESP8266_VENDOR_BLOBS)
        set(blobs)
        if(CONFIG_ESP8266_VENDOR_HAL)
            list(APPEND blobs "hal")
        endif()
        if(CONFIG_ESP8266_VENDOR_CORE)
            list(APPEND blobs "clk" "rtc")
            if(CONFIG_ESP8266_WIFI_DEBUG_LOG_ENABLE)
                list(APPEND blobs "core_dbg")
            else()
                list(APPEND blobs "core")
            endif()
        endif()
        if(CONFIG_ESP8266_VENDOR_PHY_WIFI)
            list(APPEND blobs "phy")
            if(CONFIG_ESP8266_WIFI_DEBUG_LOG_ENABLE)
                list(APPEND blobs "pp_dbg" "net80211_dbg")
            else()
                list(APPEND blobs "pp" "net80211")
            endif()
        endif()
        if(CONFIG_ESP8266_VENDOR_SMARTCONFIG)
            list(APPEND blobs "smartconfig")
        endif()
        if(CONFIG_ESP8266_VENDOR_ESPNOW)
            if(CONFIG_ESP8266_WIFI_DEBUG_LOG_ENABLE)
                list(APPEND blobs "espnow_dbg")
            else()
                list(APPEND blobs "espnow")
            endif()
        endif()
        if(blobs)
            target_link_libraries(${COMPONENT_LIB} PUBLIC "-L ${CMAKE_CURRENT_SOURCE_DIR}/lib")
            foreach(blob ${blobs})
                add_library(${blob} STATIC IMPORTED)
                set_property(TARGET ${blob} PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/lib/lib${blob}.a)
                target_link_libraries(${COMPONENT_LIB} PUBLIC ${blob})

                foreach(_blob ${blobs})
                    if(NOT _blob STREQUAL ${blob})
                        set_property(TARGET ${blob} APPEND PROPERTY INTERFACE_LINK_LIBRARIES ${_blob})
                    endif()
                endforeach()

                set_property(TARGET ${blob} APPEND PROPERTY INTERFACE_LINK_LIBRARIES ${COMPONENT_LIB})
            endforeach()
        endif()
    endif()
    target_linker_script(${COMPONENT_LIB} INTERFACE "${CMAKE_CURRENT_BINARY_DIR}/esp8266_out.ld")

    target_linker_script(${COMPONENT_LIB} INTERFACE "${CMAKE_CURRENT_LIST_DIR}/ld/esp8266.project.ld.in" 
                        PROCESS "${CMAKE_CURRENT_BINARY_DIR}/ld/esp8266.project.ld")

    target_linker_script(${COMPONENT_LIB} INTERFACE "ld/esp8266.rom.ld")
    target_linker_script(${COMPONENT_LIB} INTERFACE "ld/esp8266.peripherals.ld")

    target_link_libraries(${COMPONENT_LIB} INTERFACE "-u call_user_start")
    target_link_libraries(${COMPONENT_LIB} INTERFACE "-u __cxx_abi_force_link")

    # Preprocess esp8266.ld linker script to include configuration, becomes esp8266_out.ld
    set(LD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/ld)

    partition_table_get_partition_info(app_offset "--partition-boot-default" "offset")
    partition_table_get_partition_info(app_size "--partition-boot-default" "size")
    set(CFLAGS ${ESP8266_DYNCONFIG_FLAG} ${CFLAGS} -DAPP_OFFSET=${app_offset} -DAPP_SIZE=${app_size})

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
