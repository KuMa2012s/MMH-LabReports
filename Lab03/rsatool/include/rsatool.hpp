#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace rsatool {

using Bytes = std::vector<unsigned char>;

class ToolError : public std::runtime_error {
public:
  explicit ToolError(const std::string& message) : std::runtime_error(message) {}
};

struct KeyPaths {
  std::string public_pem;
  std::string private_pem;
  std::string public_der;
  std::string private_der;
  std::string metadata_json;
};

struct EncryptOptions {
  std::string input_path;
  std::string text;
  std::string public_key_path;
  std::string output_path;
  std::string label;
  std::string format = "raw";
};

struct DecryptOptions {
  std::string input_path;
  std::string private_key_path;
  std::string output_path;
  std::string label;
  std::string format = "auto";
};

struct BenchOptions {
  int runs = 5;
  int ops = 1;
  bool include_100mib = true;
};

Bytes read_file(const std::string& path);
void write_file(const std::string& path, const Bytes& data);
bool file_exists(const std::string& path);
std::string bytes_to_string(const Bytes& data);
Bytes string_to_bytes(const std::string& text);
std::string hex_encode(const Bytes& data);
Bytes hex_decode(const std::string& text);
std::string base64_encode(const Bytes& data);
Bytes base64_decode(const std::string& text);

void keygen(int bits, const KeyPaths& paths);
void encrypt_file(const EncryptOptions& options);
void decrypt_file(const DecryptOptions& options);
void run_kat_tests(const std::string& vector_path = "");
void run_selftest();
void run_oaep_selftest();
void run_benchmark(const BenchOptions& options);

std::size_t rsa_oaep_sha256_max_plaintext(std::size_t modulus_bits);
Bytes oaep_mgf1_sha256(const Bytes& seed, std::size_t mask_len);
Bytes oaep_encode_sha256(const Bytes& message, std::size_t encoded_len, const Bytes& label, const Bytes& seed);
Bytes oaep_decode_sha256(const Bytes& encoded, const Bytes& label);

} // namespace rsatool
