set(COMPONENT_SRCDIRS .)
set(COMPONENT_ADD_INCLUDEDIRS include)

set(COMPONENT_REQUIRES spi_flash idf_test)

register_component()

component_compile_options(-Wno-unused-const-variable)