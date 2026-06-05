#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace aestool {

using Bytes = std::vector<unsigned char>;

struct Options {
  std::string command;
  std::string mode;
  std::string in_file;
  std::string out_file;
  std::string text;
  std::string key_file;
  std::string key_hex;
  std::string iv_file;
  std::string iv_hex;
  std::string nonce_file;
  std::string nonce_hex;
  std::string aad_file;
  std::string aad_text;
  std::string encode = "hex";
  std::string kat_file;
  std::size_t size = 1024;
  int runs = 30;
  int ops = 1000;
  int bits = 256;
  bool aead = false;
  bool allow_ecb = false;
  bool all = false;
  bool verbose = false;
};

struct CryptoResult {
  Bytes data;
  Bytes iv;
  Bytes aad;
  Bytes tag;
  std::string mode;
  std::string alg;
  std::string key_id;
};

int run(int argc, char** argv);

Options parse_args(int argc, char** argv);
void print_help();

Bytes encrypt_bytes(const std::string& mode, const Bytes& key, const Bytes& iv,
                    const Bytes& plaintext, const Bytes& aad, Bytes* tag);
Bytes decrypt_bytes(const std::string& mode, const Bytes& key, const Bytes& iv,
                    const Bytes& ciphertext, const Bytes& aad, const Bytes& tag);

Bytes read_file(const std::string& path);
void write_file(const std::string& path, const Bytes& data);
bool file_exists(const std::string& path);
std::uintmax_t file_size(const std::string& path);

Bytes from_hex(const std::string& hex);
std::string to_hex(const Bytes& data, bool lowercase = true);
std::string to_base64(const Bytes& data);
Bytes random_bytes(std::size_t n);
std::string sha256_hex(const Bytes& data);
std::string lower(std::string value);

}  // namespace aestool

