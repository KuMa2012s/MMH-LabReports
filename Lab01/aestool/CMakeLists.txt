cmake_minimum_required(VERSION 4.3.3)

project(aestool LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CRYPTOPP_ROOT "" CACHE PATH "Optional Crypto++ installation root")

set(CRYPTOPP_HINTS)
if(CRYPTOPP_ROOT)
  list(APPEND CRYPTOPP_HINTS "${CRYPTOPP_ROOT}")
endif()
if(DEFINED ENV{CRYPTOPP_ROOT})
  list(APPEND CRYPTOPP_HINTS "$ENV{CRYPTOPP_ROOT}")
endif()
if(WIN32)
  list(APPEND CRYPTOPP_HINTS
    "C:/cryptolibrary"
    "C:/cryptopp"
    "C:/Program Files/cryptopp"
  )
endif()

find_path(CRYPTOPP_INCLUDE_DIR
  NAMES cryptopp/aes.h crypto++/aes.h
  HINTS ${CRYPTOPP_HINTS}
  PATH_SUFFIXES include Include
)

find_library(CRYPTOPP_LIBRARY
  NAMES cryptlib cryptopp libcryptopp
  HINTS ${CRYPTOPP_HINTS}
  PATH_SUFFIXES
    libs/msvc
    libs/gcc
    libs/clang
    lib
    lib64
    build
    build/Release
    Release
)

if(NOT CRYPTOPP_INCLUDE_DIR OR NOT CRYPTOPP_LIBRARY)
  message(FATAL_ERROR
    "Crypto++ was not found.\n"
    "Install Crypto++ or configure with one of these commands:\n"
    "  cmake -S . -B build -DCRYPTOPP_ROOT=/path/to/cryptolibrary\n"
    "  cmake -S . -B build -DCRYPTOPP_INCLUDE_DIR=/path/to/include -DCRYPTOPP_LIBRARY=/path/to/cryptopp.lib\n"
    "On this machine the expected default is C:/cryptolibrary."
  )
endif()

message(STATUS "Crypto++ include: ${CRYPTOPP_INCLUDE_DIR}")
message(STATUS "Crypto++ library: ${CRYPTOPP_LIBRARY}")

get_filename_component(CRYPTOPP_LIBRARY_DIR "${CRYPTOPP_LIBRARY}" DIRECTORY)
get_filename_component(CRYPTOPP_LIBRARY_NAME "${CRYPTOPP_LIBRARY}" NAME_WE)

find_file(CRYPTOPP_DLL
  NAMES cryptopp.dll
  HINTS ${CRYPTOPP_LIBRARY_DIR} ${CRYPTOPP_HINTS}
  PATH_SUFFIXES libs/msvc bin
)

set(AESTOOL_MSVC_STATIC_RUNTIME OFF)
if(MSVC AND CRYPTOPP_LIBRARY_NAME STREQUAL "cryptlib")
  set(AESTOOL_MSVC_STATIC_RUNTIME ON)
endif()

add_library(aestool_core SHARED
  src/aestool.cpp
  src/aestool_c_api.cpp
)

if(MSVC)
  if(AESTOOL_MSVC_STATIC_RUNTIME)
    set_property(TARGET aestool_core PROPERTY
      MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  endif()
endif()

target_compile_definitions(aestool_core PRIVATE AESTOOL_CORE_BUILD)
if(MSVC AND NOT AESTOOL_MSVC_STATIC_RUNTIME)
  target_compile_definitions(aestool_core PRIVATE CRYPTOPP_IMPORTS)
endif()

target_include_directories(aestool_core PRIVATE
  include
  "${CRYPTOPP_INCLUDE_DIR}"
)

target_link_libraries(aestool_core PRIVATE "${CRYPTOPP_LIBRARY}")

add_executable(aestool
  src/main.cpp
  src/aestool.cpp
)

if(MSVC)
  if(AESTOOL_MSVC_STATIC_RUNTIME)
    set_property(TARGET aestool PROPERTY
      MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  endif()
endif()

target_include_directories(aestool PRIVATE
  include
  "${CRYPTOPP_INCLUDE_DIR}"
)
if(MSVC AND NOT AESTOOL_MSVC_STATIC_RUNTIME)
  target_compile_definitions(aestool PRIVATE CRYPTOPP_IMPORTS)
endif()
target_link_libraries(aestool PRIVATE "${CRYPTOPP_LIBRARY}")

if(MSVC AND EXISTS "${CRYPTOPP_DLL}")
  add_custom_command(TARGET aestool_core POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "${CRYPTOPP_DLL}"
      "$<TARGET_FILE_DIR:aestool_core>/cryptopp.dll"
  )
endif()

enable_testing()

add_test(NAME kat_nist_38a
  COMMAND aestool --kat "${CMAKE_CURRENT_SOURCE_DIR}/vectors/nist_38a.json"
)

add_test(NAME kat_aead
  COMMAND aestool --kat "${CMAKE_CURRENT_SOURCE_DIR}/vectors/aead.json"
)

add_test(NAME cli_help
  COMMAND aestool --help
)

add_test(NAME negative_invalid_gcm_nonce
  COMMAND aestool encrypt --mode gcm
    --key-hex 000102030405060708090a0b0c0d0e0f
    --nonce-hex 0001
    --text hello
)
set_tests_properties(negative_invalid_gcm_nonce PROPERTIES WILL_FAIL TRUE)
