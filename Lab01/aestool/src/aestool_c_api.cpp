#include "aestool.hpp"
#include "aestool_c_api.h"

#include <algorithm>
#include <cctype>
#include <functional>
#include <fstream>
#include <map>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

using aestool::Bytes;

constexpr std::size_t kEcbLimit = 16 * 1024;

void set_error(char* error, std::size_t error_len, const std::string& message) {
  if (!error || error_len == 0) return;
  const std::size_t n = std::min(error_len - 1, message.size());
  std::copy_n(message.data(), n, error);
  error[n] = '\0';
}

int wrap_call(char* error, std::size_t error_len, const std::function<void()>& fn) {
  try {
    fn();
    set_error(error, error_len, "OK");
    return 0;
  } catch (const std::exception& ex) {
    set_error(error, error_len, ex.what());
    return 1;
  }
}

std::string safe(const char* value) {
  return value ? std::string(value) : std::string();
}

std::string trim(std::string s) {
  auto not_space = [](unsigned char c) { return !std::isspace(c); };
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
  s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
  return s;
}

bool looks_hex(std::string text) {
  text = trim(text);
  if (text.rfind("hex:", 0) == 0 || text.rfind("HEX:", 0) == 0) {
    text = text.substr(4);
  }
  text.erase(std::remove_if(text.begin(), text.end(), [](unsigned char c) {
    return std::isspace(c) != 0;
  }), text.end());
  if (text.empty() || (text.size() % 2) != 0) return false;
  return std::all_of(text.begin(), text.end(), [](unsigned char c) {
    return std::isxdigit(c) != 0;
  });
}

Bytes load_key(const std::string& path) {
  if (path.empty()) throw std::runtime_error("missing key file");
  Bytes raw = aestool::read_file(path);
  std::string text(raw.begin(), raw.end());
  return looks_hex(text) ? aestool::from_hex(text) : raw;
}

bool is_aead(const std::string& mode) {
  return mode == "gcm" || mode == "ccm";
}

std::size_t iv_len_for(const std::string& mode) {
  if (mode == "ecb") return 0;
  if (mode == "gcm") return 12;
  if (mode == "ccm") return 12;
  return 16;
}

std::string iv_label(const std::string& mode) {
  if (mode == "ctr" || mode == "gcm" || mode == "ccm") return "nonce";
  if (mode == "xts") return "tweak";
  return "iv";
}

std::string metadata_path(const std::string& out_file) {
  return out_file + ".meta.json";
}

std::string alg_name(const std::string& mode, const Bytes& key) {
  std::ostringstream oss;
  if (mode == "xts") {
    oss << "AES-" << ((key.size() / 2) * 8) << "-XTS";
  } else {
    oss << "AES-" << (key.size() * 8) << "-" << mode;
  }
  return oss.str();
}

void write_metadata(const std::string& out_file, const std::string& mode, const Bytes& key,
                    const Bytes& iv, const Bytes& aad, const Bytes& tag) {
  std::ofstream f(metadata_path(out_file), std::ios::binary);
  if (!f) throw std::runtime_error("cannot write sidecar metadata");
  f << "{\n";
  f << "  \"alg\": \"" << alg_name(mode, key) << "\",\n";
  f << "  \"mode\": \"" << mode << "\",\n";
  f << "  \"key_id\": \"" << aestool::sha256_hex(key) << "\",\n";
  f << "  \"" << iv_label(mode) << "\": \"" << aestool::to_hex(iv) << "\",\n";
  f << "  \"aad\": \"" << aestool::to_hex(aad) << "\",\n";
  f << "  \"tag\": \"" << aestool::to_hex(tag) << "\"\n";
  f << "}\n";
}

std::map<std::string, std::string> read_metadata(const std::string& input_file) {
  const std::string path = metadata_path(input_file);
  if (!aestool::file_exists(path)) {
    throw std::runtime_error("missing sidecar metadata: " + path);
  }
  Bytes raw = aestool::read_file(path);
  std::string text(raw.begin(), raw.end());
  std::map<std::string, std::string> out;
  std::regex kv("\"([^\"]+)\"\\s*:\\s*\"([^\"]*)\"");
  for (std::sregex_iterator it(text.begin(), text.end(), kv), end; it != end; ++it) {
    out[(*it)[1].str()] = (*it)[2].str();
  }
  return out;
}

void encrypt_common(const std::string& mode_input, const Bytes& key, const Bytes& plaintext,
                    const std::string& output_file, const std::string& aad_text) {
  const std::string mode = aestool::lower(mode_input);
  if (mode.empty()) throw std::runtime_error("missing mode");
  if (output_file.empty()) throw std::runtime_error("missing output file");
  if (mode == "ecb" && plaintext.size() > kEcbLimit) {
    throw std::runtime_error("ECB input larger than 16 KiB is refused by GUI core");
  }

  Bytes iv;
  const std::size_t iv_len = iv_len_for(mode);
  if (iv_len > 0) iv = aestool::random_bytes(iv_len);

  Bytes aad(aad_text.begin(), aad_text.end());
  Bytes tag;
  Bytes ciphertext = aestool::encrypt_bytes(mode, key, iv, plaintext, aad, &tag);
  aestool::write_file(output_file, ciphertext);
  write_metadata(output_file, mode, key, iv, aad, tag);
}

void decrypt_common(const std::string& mode_input, const Bytes& key,
                    const std::string& input_file, const std::string& output_file) {
  const std::string mode = aestool::lower(mode_input);
  if (mode.empty()) throw std::runtime_error("missing mode");
  if (input_file.empty()) throw std::runtime_error("missing input file");
  if (output_file.empty()) throw std::runtime_error("missing output file");

  const auto meta = read_metadata(input_file);
  Bytes iv;
  const auto label_it = meta.find(iv_label(mode));
  if (label_it != meta.end()) {
    iv = aestool::from_hex(label_it->second);
  } else if (meta.count("iv")) {
    iv = aestool::from_hex(meta.at("iv"));
  } else if (meta.count("nonce")) {
    iv = aestool::from_hex(meta.at("nonce"));
  }

  Bytes aad;
  if (meta.count("aad")) aad = aestool::from_hex(meta.at("aad"));

  Bytes tag;
  if (is_aead(mode)) {
    if (!meta.count("tag")) throw std::runtime_error("missing AEAD tag in sidecar metadata");
    tag = aestool::from_hex(meta.at("tag"));
  }

  Bytes ciphertext = aestool::read_file(input_file);
  Bytes plaintext = aestool::decrypt_bytes(mode, key, iv, ciphertext, aad, tag);
  aestool::write_file(output_file, plaintext);
}

}  // namespace

extern "C" {

int aestool_core_keygen(const char* out_key_file, int bits, char* error, size_t error_len) {
  return wrap_call(error, error_len, [&]() {
    if (bits != 128 && bits != 192 && bits != 256 && bits != 512) {
      throw std::runtime_error("bits must be 128, 192, 256, or 512");
    }
    const std::string out = safe(out_key_file);
    if (out.empty()) throw std::runtime_error("missing output key path");
    aestool::write_file(out, aestool::random_bytes(static_cast<std::size_t>(bits / 8)));
  });
}

int aestool_core_encrypt_file(const char* mode, const char* key_file, const char* input_file,
                              const char* output_file, const char* aad_text,
                              char* error, size_t error_len) {
  return wrap_call(error, error_len, [&]() {
    Bytes key = load_key(safe(key_file));
    Bytes plaintext = aestool::read_file(safe(input_file));
    encrypt_common(safe(mode), key, plaintext, safe(output_file), safe(aad_text));
  });
}

int aestool_core_encrypt_text(const char* mode, const char* key_file, const char* text,
                              const char* output_file, const char* aad_text,
                              char* error, size_t error_len) {
  return wrap_call(error, error_len, [&]() {
    Bytes key = load_key(safe(key_file));
    std::string value = safe(text);
    Bytes plaintext(value.begin(), value.end());
    encrypt_common(safe(mode), key, plaintext, safe(output_file), safe(aad_text));
  });
}

int aestool_core_decrypt_file(const char* mode, const char* key_file, const char* input_file,
                              const char* output_file, char* error, size_t error_len) {
  return wrap_call(error, error_len, [&]() {
    Bytes key = load_key(safe(key_file));
    decrypt_common(safe(mode), key, safe(input_file), safe(output_file));
  });
}

}  // extern "C"
