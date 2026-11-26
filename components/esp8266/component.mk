#
# Component Makefile
#
ifdef IS_BOOTLOADER_BUILD
COMPONENT_OBJS := source/ets_printf.o source/crc.o source/esp_fast_boot.o source/esp_misc.o
COMPONENT_SRCDIRS := source
else
COMPONENT_ADD_INCLUDEDIRS += include
COMPONENT_PRIV_INCLUDEDIRS := include/driver phy lmac net80211 ../wpa_supplicant/src/esp_supplicant
COMPONENT_SRCDIRS := driver source phy lmac net80211

ifndef CONFIG_ESP8266_OSS_HAL
COMPONENT_OBJEXCLUDE += source/xtensa_hal.o
endif
ifndef CONFIG_ESP8266_OSS_CORE
COMPONENT_OBJEXCLUDE += source/esp_clk_rtc.o source/esp_ets_timer.o source/esp_misc.o source/esp_misc_nvs.o source/esp_sys_ctrl.o
endif
ifndef CONFIG_ESP8266_OSS_PHY_ONLY
COMPONENT_OBJEXCLUDE += source/esp_no_blobs_stubs.o
endif
ifndef CONFIG_ESP8266_OSS_PHY
COMPONENT_OBJEXCLUDE += phy/phy_soc.o phy/phy_i2c_pbus.o phy/phy_clock.o \
                        phy/phy_adc.o phy/phy_sleep.o
endif
ifndef CONFIG_ESP8266_OSS_PHY_WIFI
COMPONENT_OBJEXCLUDE += phy/phy_rf_chan.o phy/phy_rxgain.o \
                        phy/phy_cal_tx.o phy/phy_core.o \
                        lmac/lmac_nmi.o lmac/lmac_dma.o lmac/lmac_tx.o \
                        lmac/lmac_trc.o lmac/lmac_crypto_vif.o lmac/lmac_pm_compat.o \
                        net80211/net80211_worker.o net80211/net80211_nvs_rtc.o \
                        net80211/net80211_supp_glue.o net80211/net80211_scan.o \
                        net80211/net80211_sta.o net80211/net80211_ap.o \
                        net80211/net80211_data.o net80211/net80211_pm.o \
                        net80211/net80211_api.o \
                        net80211/net80211_defrag.o
endif
ifndef CONFIG_ESP8266_OSS_WIFI_RX_DEFRAG_ENABLED
COMPONENT_OBJEXCLUDE += net80211/net80211_defrag.o
endif
ifndef CONFIG_ESP8266_VENDOR_SMARTCONFIG
COMPONENT_OBJEXCLUDE += source/smartconfig.o source/smartconfig_ack.o
endif

LIBS ?=
ifdef CONFIG_ESP8266_VENDOR_BLOBS
ifdef CONFIG_ESP8266_VENDOR_HAL
LIBS += hal
endif
ifdef CONFIG_ESP8266_VENDOR_CORE
LIBS += clk rtc
ifdef CONFIG_ESP8266_WIFI_DEBUG_LOG_ENABLE
LIBS += core_dbg
else
LIBS += core
endif
endif
ifdef CONFIG_ESP8266_VENDOR_PHY_WIFI
LIBS += phy
ifdef CONFIG_ESP8266_WIFI_DEBUG_LOG_ENABLE
LIBS += pp_dbg net80211_dbg
else
LIBS += pp net80211
endif
endif
ifdef CONFIG_ESP8266_VENDOR_SMARTCONFIG
LIBS += smartconfig
endif
ifdef CONFIG_ESP8266_VENDOR_ESPNOW
ifdef CONFIG_ESP8266_WIFI_DEBUG_LOG_ENABLE
LIBS += espnow_dbg
else
LIBS += espnow
endif
endif
endif

CFLAGS += -DUSING_IBUS_FASTER_GET
lmac/lmac_nmi.o: CFLAGS += -fno-jump-tables
#Linker scripts used to link the final application.
#Warning: These linker scripts are only used when the normal app is compiled; the bootloader
#specifies its own scripts.
LINKER_SCRIPTS += esp8266.rom.ld esp8266.peripherals.ld

COMPONENT_ADD_LDFRAGMENTS += ld/esp8266_fragments.lf ld/esp8266_bss_fragments.lf linker.lf

ifneq ($(strip $(LIBS)),)
COMPONENT_ADD_LDFLAGS += -L$(COMPONENT_PATH)/lib \
                         $(addprefix -l,$(LIBS))
endif
COMPONENT_ADD_LDFLAGS += -L $(COMPONENT_PATH)/ld \
                         -T esp8266_out.ld       \
                         -T $(COMPONENT_BUILD_DIR)/esp8266.project.ld \
                         -Wl,--no-check-sections \
                         -u call_user_start      \
                         -u g_esp_sys_info \
                         $(addprefix -T ,$(LINKER_SCRIPTS))

ALL_LIB_FILES := $(patsubst %,$(COMPONENT_PATH)/lib/lib%.a,$(LIBS))

# final linking of project ELF depends on all binary libraries, and
# all linker scripts
COMPONENT_ADD_LINKER_DEPS := $(ALL_LIB_FILES) $(addprefix ld/, $(filter-out $(COMPONENT_BUILD_DIR)/esp8266.project.ld, $(LINKER_SCRIPTS))) \
                             $(COMPONENT_BUILD_DIR)/esp8266.project.ld

# Preprocess esp8266.ld linker script into esp8266_out.ld
#
# The library doesn't really depend on esp8266_out.ld, but it
# saves us from having to add the target to a Makefile.projbuild
$(COMPONENT_LIBRARY): esp8266_out.ld

esp8266_out.ld: $(COMPONENT_PATH)/ld/esp8266.ld ../include/sdkconfig.h
	$(CC) $(CFLAGS) -I ../include -C -P -x c -E $< -o $@

COMPONENT_EXTRA_CLEAN := esp8266_out.ld $(COMPONENT_BUILD_DIR)/esp8266.project.ld

endif
