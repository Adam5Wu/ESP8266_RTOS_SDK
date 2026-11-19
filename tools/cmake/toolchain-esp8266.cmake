set(CMAKE_SYSTEM_NAME Generic)

find_program(_XTENSA_ESP_GCC xtensa-esp-elf-gcc)
if(NOT _XTENSA_ESP_GCC)
    message(FATAL_ERROR "xtensa-esp-elf-gcc not found; gcc16 branches require toolchain-xtensa-esp8266")
endif()

get_filename_component(_XTENSA_BIN_DIR "${_XTENSA_ESP_GCC}" DIRECTORY)
get_filename_component(_XTENSA_ROOT_DIR "${_XTENSA_BIN_DIR}" DIRECTORY)
set(_XTENSA_LIB_DIR "${_XTENSA_ROOT_DIR}/lib")
if(NOT EXISTS "${_XTENSA_LIB_DIR}/xtensa_esp8266.so")
    message(FATAL_ERROR "xtensa_esp8266.so not found in ${_XTENSA_LIB_DIR}")
endif()

set(ESP8266_TOOLCHAIN_ROOT "${_XTENSA_ROOT_DIR}" CACHE PATH "xtensa-esp-elf toolchain root")
set(ESP8266_DYNCONFIG_FLAG "-mdynconfig=xtensa_esp8266.so" CACHE STRING "Xtensa ESP8266 dynconfig flag")

# cc1 rejects XTENSA_GNU_CONFIG combined with -mdynconfig=xtensa_esp8266.so ("pointed different files");
# standalone CMake compiler probes/subprocesses load xtensa_esp8266.so via <toolchain>/lib on PATH.
unset(ENV{XTENSA_GNU_CONFIG})
string(FIND "$ENV{PATH}" "${_XTENSA_LIB_DIR}" _has_xtensa_lib)
if(_has_xtensa_lib EQUAL -1)
    set(ENV{PATH} "${_XTENSA_LIB_DIR};$ENV{PATH}")
endif()

set(CMAKE_C_COMPILER xtensa-esp-elf-gcc)
set(CMAKE_CXX_COMPILER xtensa-esp-elf-g++)
set(CMAKE_ASM_COMPILER xtensa-esp-elf-gcc)

set(CMAKE_C_FLAGS "-mlongcalls -Wno-frame-address ${ESP8266_DYNCONFIG_FLAG}" CACHE STRING "C Compiler Base Flags")
set(CMAKE_CXX_FLAGS "-mlongcalls -Wno-frame-address ${ESP8266_DYNCONFIG_FLAG}" CACHE STRING "C++ Compiler Base Flags")
set(CMAKE_ASM_FLAGS "${ESP8266_DYNCONFIG_FLAG}" CACHE STRING "ASM Compiler Base Flags")

set(CMAKE_EXE_LINKER_FLAGS "-nostdlib -Wl,--gc-sections ${ESP8266_DYNCONFIG_FLAG} -Wl,--no-warn-rwx-segments" CACHE STRING "Linker Base Flags")
