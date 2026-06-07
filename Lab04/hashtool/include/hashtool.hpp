#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace hashtool {

using Bytes = std::vector<unsigned char>;

class ToolError : public std::runtime_error {
public:
  explicit ToolError(const std::string& message) : std::runtime_error(message) {}
};

struct HashOptions {
  std::string algo;
  std::string input_path;
  std::string text;
  std::string output_path;
  std::string encode = "hex";
  std::size_t outlen = 0;
  bool stream = false;
};

struct CertOptions {
  std::string input_path;
  std::string issuer_path;
  bool verify = false;
};

struct BenchOptions {
  int runs = 30;
  int ops = 10;
  bool include_1gib = false;
};

struct LengthExtensionOptions {
  std::string mac_hex;
  std::string message;
  std::string append;
  std::size_t key_len = 0;
  bool demo = false;
};

Bytes read_file(const std::string& path);
void write_file(const std::string& path, const Bytes& data);
Bytes string_to_bytes(const std::string& text);
std::string bytes_to_string(const Bytes& data);
std::string hex_encode(const Bytes& data);
Bytes hex_decode(const std::string& text);
std::string base64_encode(const Bytes& data);

Bytes hash_bytes(const std::string& algo, const Bytes& data, std::size_t outlen = 0);
Bytes hash_file_streamed(const std::string& algo, const std::string& path, std::size_t outlen = 0);

void run_hash(const HashOptions& options);
void run_cert(const CertOptions& options);
void run_md5_collision(const std::string& file1, const std::string& file2, const std::string& out_dir);
void run_length_extension(const LengthExtensionOptions& options);
void run_benchmark(const BenchOptions& options);
void run_io_benchmark(const BenchOptions& options);
void run_kat(const std::string& path);
void run_selftest();

} // namespace hashtool
