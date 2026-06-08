#pragma once

#include <cstddef>
#include <stdexcept>
#include <string>
#include <vector>

namespace sigtool {

using Bytes = std::vector<unsigned char>;

class ToolError : public std::runtime_error {
public:
  explicit ToolError(const std::string& message) : std::runtime_error(message) {}
};

struct KeygenOptions {
  std::string algo;
  std::string pub_path;
  std::string priv_path;
  std::string format = "pem";
};

struct SignOptions {
  std::string algo;
  std::string input_path;
  std::string text;
  std::string priv_path;
  std::string output_path;
  std::string hash = "sha256";
  std::string encode = "raw";
};

struct VerifyOptions {
  std::string algo;
  std::string input_path;
  std::string text;
  std::string sig_path;
  std::string pub_path;
  std::string hash = "sha256";
  std::string encode = "raw";
};

struct BatchOptions {
  std::string manifest_path;
};

struct BenchOptions {
  int runs = 30;
  int ops = 100;
};

void run_keygen(const KeygenOptions& options);
void run_sign(const SignOptions& options);
void run_verify(const VerifyOptions& options);
void run_batch_verify(const BatchOptions& options);
void run_benchmark(const BenchOptions& options);
void run_bonus(const std::string& topic);
void run_kat(const std::string& path);
void run_selftest();

Bytes read_file(const std::string& path);
void write_file(const std::string& path, const Bytes& data);
Bytes string_to_bytes(const std::string& text);
std::string hex_encode(const Bytes& data);
Bytes hex_decode(const std::string& text);
std::string base64_encode(const Bytes& data);
Bytes base64_decode(const std::string& text);

} // namespace sigtool
