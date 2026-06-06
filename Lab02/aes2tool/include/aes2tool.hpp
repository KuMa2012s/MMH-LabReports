#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace aes2tool {

using Bytes = std::vector<std::uint8_t>;
using Block = std::array<std::uint8_t, 16>;

class Aes {
 public:
  explicit Aes(const Bytes& key);

  std::size_t key_bits() const { return key_bits_; }
  int rounds() const { return nr_; }
  Block encrypt_block(const Block& in) const;
  Block decrypt_block(const Block& in) const;

 private:
  int nk_ = 0;
  int nr_ = 0;
  std::size_t key_bits_ = 0;
  std::vector<std::uint8_t> round_keys_;
};

struct Options {
  std::string command;
  std::string mode = "ctr";
  std::string in_file;
  std::string out_file;
  std::string text;
  std::string key_file;
  std::string key_hex;
  std::string iv_file;
  std::string iv_hex;
  std::string encode = "hex";
  std::string kat_file;
  std::size_t size = 1024 * 1024;
  int runs = 30;
  int ops = 100;
  int bits = 128;
  bool all = false;
  bool include_gib = false;
  bool verbose = false;
};

int run(int argc, char** argv);
Options parse_args(int argc, char** argv);
void print_help();

Bytes ctr_transform(const Bytes& key, const Bytes& iv, const Bytes& input);
Bytes ctr_transform_aesni128(const Bytes& key, const Bytes& iv, const Bytes& input);
Bytes xts_encrypt(const Bytes& key, const Bytes& tweak, const Bytes& plaintext);
Bytes xts_decrypt(const Bytes& key, const Bytes& tweak, const Bytes& ciphertext);

Bytes read_file(const std::string& path);
void write_file(const std::string& path, const Bytes& data);
Bytes random_bytes(std::size_t n);
Bytes from_hex(const std::string& hex);
std::string to_hex(const Bytes& data);
std::string lower(std::string value);

bool cpu_supports_aesni();
bool aesni_backend_compiled();

}  // namespace aes2tool
