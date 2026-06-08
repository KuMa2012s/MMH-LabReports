cmake_minimum_required(VERSION 4.3.3)

project(sigtool LANGUAGES CXX)

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
  NAMES cryptopp/cryptlib.h crypto++/cryptlib.h
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

set(SIGTOOL_MSVC_STATIC_RUNTIME OFF)
if(MSVC AND CRYPTOPP_LIBRARY_NAME STREQUAL "cryptlib")
  set(SIGTOOL_MSVC_STATIC_RUNTIME ON)
endif()

add_executable(sigtool
  src/main.cpp
  src/sigtool.cpp
)

target_include_directories(sigtool PRIVATE
  include
  "${CRYPTOPP_INCLUDE_DIR}"
)

if(MSVC)
  target_compile_options(sigtool PRIVATE /W4 /permissive-)
  if(SIGTOOL_MSVC_STATIC_RUNTIME)
    set_property(TARGET sigtool PROPERTY
      MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  else()
    target_compile_definitions(sigtool PRIVATE CRYPTOPP_IMPORTS)
  endif()
else()
  target_compile_options(sigtool PRIVATE -Wall -Wextra -Wpedantic)
endif()

target_link_libraries(sigtool PRIVATE "${CRYPTOPP_LIBRARY}")

if(MSVC AND EXISTS "${CRYPTOPP_DLL}")
  add_custom_command(TARGET sigtool POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "${CRYPTOPP_DLL}"
      "$<TARGET_FILE_DIR:sigtool>/cryptopp.dll"
  )
endif()

enable_testing()

add_test(NAME cli_help COMMAND sigtool --help)
add_test(NAME selftest COMMAND sigtool --selftest)
add_test(NAME known_answer_tests
  COMMAND sigtool --kat ${CMAKE_CURRENT_SOURCE_DIR}/vectors/sig_kat.json)
add_test(NAME bonus_primitives COMMAND sigtool bonus --all)
add_test(NAME reject_bad_algo COMMAND sigtool keygen --algo nope --pub bad.pub --priv bad.priv)
set_tests_properties(reject_bad_algo PROPERTIES WILL_FAIL TRUE)

set_tests_properties(cli_help selftest known_answer_tests bonus_primitives reject_bad_algo
  PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
