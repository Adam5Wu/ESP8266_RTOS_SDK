
COMPONENT_SRCDIRS := .
COMPONENT_OBJS := esp_tls.o

COMPONENT_ADD_INCLUDEDIRS := . private_include


ifneq ($(CONFIG_ESP_TLS_USING_MBEDTLS), )
COMPONENT_OBJS += esp_tls_mbedtls.o
endif
