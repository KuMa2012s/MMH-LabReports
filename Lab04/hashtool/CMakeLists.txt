cmake_minimum_required(VERSION 4.3.3)

project(hashtool LANGUAGES CXX)

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
  NAMES cryptopp/sha.h crypto++/sha.h
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
    "Install Crypto++ or configure with:\n"
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

set(HASHTOOL_MSVC_STATIC_RUNTIME OFF)
if(MSVC AND CRYPTOPP_LIBRARY_NAME STREQUAL "cryptlib")
  set(HASHTOOL_MSVC_STATIC_RUNTIME ON)
endif()

add_executable(hashtool
  src/main.cpp
  src/hashtool.cpp
)

if(MSVC)
  target_compile_options(hashtool PRIVATE /W4 /permissive-)
  if(HASHTOOL_MSVC_STATIC_RUNTIME)
    set_property(TARGET hashtool PROPERTY
      MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  endif()
else()
  target_compile_options(hashtool PRIVATE -Wall -Wextra -Wpedantic)
endif()

target_compile_definitions(hashtool PRIVATE CRYPTOPP_ENABLE_NAMESPACE_WEAK=1)

target_include_directories(hashtool PRIVATE
  include
  "${CRYPTOPP_INCLUDE_DIR}"
)

if(MSVC AND NOT HASHTOOL_MSVC_STATIC_RUNTIME)
  target_compile_definitions(hashtool PRIVATE CRYPTOPP_IMPORTS)
endif()

target_link_libraries(hashtool PRIVATE "${CRYPTOPP_LIBRARY}")

if(MSVC AND EXISTS "${CRYPTOPP_DLL}")
  add_custom_command(TARGET hashtool POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "${CRYPTOPP_DLL}"
      "$<TARGET_FILE_DIR:hashtool>/cryptopp.dll"
  )
endif()

enable_testing()

add_test(NAME cli_help COMMAND hashtool --help)
add_test(NAME known_answer_tests
  COMMAND hashtool --kat ${CMAKE_CURRENT_SOURCE_DIR}/vectors/hash_kat.json)
add_test(NAME selftest COMMAND hashtool --selftest)
add_test(NAME reject_bad_algo COMMAND hashtool hash --algo nope --text test)
set_tests_properties(reject_bad_algo PROPERTIES WILL_FAIL TRUE)
