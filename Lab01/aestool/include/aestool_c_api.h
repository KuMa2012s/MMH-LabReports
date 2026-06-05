#pragma once

#include <stddef.h>

#if defined(_WIN32)
#  if defined(AESTOOL_CORE_BUILD)
#    define AESTOOL_API __declspec(dllexport)
#  else
#    define AESTOOL_API __declspec(dllimport)
#  endif
#else
#  define AESTOOL_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

AESTOOL_API int aestool_core_keygen(const char* out_key_file, int bits,
                                    char* error, size_t error_len);

AESTOOL_API int aestool_core_encrypt_file(const char* mode, const char* key_file,
                                          const char* input_file, const char* output_file,
                                          const char* aad_text,
                                          char* error, size_t error_len);

AESTOOL_API int aestool_core_encrypt_text(const char* mode, const char* key_file,
                                          const char* text, const char* output_file,
                                          const char* aad_text,
                                          char* error, size_t error_len);

AESTOOL_API int aestool_core_decrypt_file(const char* mode, const char* key_file,
                                          const char* input_file, const char* output_file,
                                          char* error, size_t error_len);

#ifdef __cplusplus
}
#endif

