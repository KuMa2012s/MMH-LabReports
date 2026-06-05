#include "aestool.hpp"

#include <cryptopp/aes.h>
#include <cryptopp/authenc.h>
#include <cryptopp/base64.h>
#include <cryptopp/ccm.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/sha.h>
#include <cryptopp/xts.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <regex>
#include <sstream>
#include <stdexcept>

namespace aestool {
namespace {

constexpr std::size_t kBlock = CryptoPP::AES::BLOCKSIZE;
constexpr std::size_t kGcmNonce = 12;
constexpr std::size_t kCcmNonce = 12;
constexpr std::size_t kTagSize = 16;
constexpr std::uintmax_t kEcbLimit = 16 * 1024;

std::string trim(std::string s) {
  auto not_space = [](unsigned char c) { return !std::isspace(c); };
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
  s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
  return s;
}

bool looks_hex(const std::string& s) {
  std::string t = trim(s);
  if (t.rfind("hex:", 0) == 0 || t.rfind("HEX:", 0) == 0) {
    t = t.substr(4);
  }
  if (t.empty() || (t.size() % 2) != 0) return false;
  return std::all_of(t.begin(), t.end(), [](unsigned char c) {
    return std::isxdigit(c) != 0 || std::isspace(c) != 0;
  });
}

std::string metadata_path_for(const std::string& data_path) {
  return data_path + ".meta.json";
}

std::string registry_path() {
  return ".aestool_nonce_registry";
}

bool is_aead(const std::string& mode) {
  return mode == "gcm" || mode == "ccm";
}

bool is_nonce_reuse_sensitive(const std::string& mode) {
  return mode == "ctr" || mode == "gcm" || mode == "ccm";
}

bool is_valid_mode(const std::string& mode) {
  static const std::vector<std::string> modes = {
      "ecb", "cbc", "ofb", "cfb", "ctr", "xts", "ccm", "gcm"};
  return std::find(modes.begin(), modes.end(), mode) != modes.end();
}

void validate_key(const std::string& mode, const Bytes& key) {
  if (mode == "xts") {
    if (key.size() != 32 && key.size() != 64) {
      throw std::runtime_error("XTS requires a 32-byte or 64-byte key (two AES keys)");
    }
    return;
  }
  if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
    throw std::runtime_error("AES key must be 16, 24, or 32 bytes");
  }
}

std::size_t required_iv_len(const std::string& mode) {
  if (mode == "ecb") return 0;
  if (mode == "gcm") return kGcmNonce;
  if (mode == "ccm") return kCcmNonce;
  return kBlock;
}

std::string iv_label(const std::string& mode) {
  if (mode == "ctr" || mode == "gcm" || mode == "ccm") return "nonce";
  if (mode == "xts") return "tweak";
  return "iv";
}

void validate_iv(const std::string& mode, const Bytes& iv) {
  if (mode == "ccm") {
    if (iv.size() < 7 || iv.size() > 13) {
      throw std::runtime_error("ccm requires a 7..13 byte nonce");
    }
    return;
  }
  const std::size_t required = required_iv_len(mode);
  if (required == 0) return;
  if (iv.size() != required) {
    std::ostringstream oss;
    oss << mode << " requires " << required << " byte " << iv_label(mode);
    throw std::runtime_error(oss.str());
  }
}

Bytes read_key_material(const Options& opt, const std::string& mode) {
  Bytes key;
  if (!opt.key_hex.empty()) {
    key = from_hex(opt.key_hex);
  } else if (!opt.key_file.empty()) {
    Bytes raw = read_file(opt.key_file);
    std::string as_text(raw.begin(), raw.end());
    key = looks_hex(as_text) ? from_hex(as_text) : raw;
  } else {
    throw std::runtime_error("missing --key or --key-hex");
  }
  validate_key(mode, key);
  return key;
}

Bytes read_optional_bytes(const std::string& file, const std::string& hex,
                          const std::string& text) {
  if (!hex.empty()) return from_hex(hex);
  if (!file.empty()) return read_file(file);
  if (!text.empty()) return Bytes(text.begin(), text.end());
  return {};
}

Bytes read_input_bytes(const Options& opt) {
  if (!opt.text.empty()) return Bytes(opt.text.begin(), opt.text.end());
  if (!opt.in_file.empty()) return read_file(opt.in_file);
  throw std::runtime_error("missing --in or --text");
}

std::string json_escape(const std::string& s) {
  std::string out;
  for (char c : s) {
    if (c == '\\' || c == '"') out.push_back('\\');
    out.push_back(c);
  }
  return out;
}

void write_metadata(const std::string& out_file, const CryptoResult& result) {
  std::ofstream f(metadata_path_for(out_file), std::ios::binary);
  if (!f) throw std::runtime_error("cannot write metadata sidecar");
  f << "{\n";
  f << "  \"alg\": \"" << json_escape(result.alg) << "\",\n";
  f << "  \"mode\": \"" << json_escape(result.mode) << "\",\n";
  f << "  \"key_id\": \"" << json_escape(result.key_id) << "\",\n";
  f << "  \"" << iv_label(result.mode) << "\": \"" << to_hex(result.iv) << "\",\n";
  f << "  \"aad\": \"" << to_hex(result.aad) << "\",\n";
  f << "  \"tag\": \"" << to_hex(result.tag) << "\"\n";
  f << "}\n";
}

std::map<std::string, std::string> read_metadata(const std::string& data_file) {
  const std::string path = metadata_path_for(data_file);
  if (!file_exists(path)) return {};
  const Bytes raw = read_file(path);
  const std::string text(raw.begin(), raw.end());
  std::map<std::string, std::string> result;
  std::regex kv("\"([^\"]+)\"\\s*:\\s*\"([^\"]*)\"");
  for (std::sregex_iterator it(text.begin(), text.end(), kv), end; it != end; ++it) {
    result[(*it)[1].str()] = (*it)[2].str();
  }
  return result;
}

void check_nonce_registry(const std::string& mode, const std::string& key_id,
                          const Bytes& nonce) {
  if (!is_nonce_reuse_sensitive(mode)) return;
  const std::string needle = key_id + " " + mode + " " + to_hex(nonce);
  if (file_exists(registry_path())) {
    const Bytes raw = read_file(registry_path());
    const std::string text(raw.begin(), raw.end());
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
      if (trim(line) == needle) {
        throw std::runtime_error("nonce reuse detected for same key_id and mode");
      }
    }
  }
}

void record_nonce_registry(const std::string& mode, const std::string& key_id,
                           const Bytes& nonce) {
  if (!is_nonce_reuse_sensitive(mode)) return;
  std::ofstream f(registry_path(), std::ios::binary | std::ios::app);
  if (!f) throw std::runtime_error("cannot update nonce registry");
  f << key_id << " " << mode << " " << to_hex(nonce) << "\n";
}

void print_encoded(const Bytes& data, const std::string& encode) {
  if (encode == "raw") {
    std::cout.write(reinterpret_cast<const char*>(data.data()),
                    static_cast<std::streamsize>(data.size()));
  } else if (encode == "base64") {
    std::cout << to_base64(data) << "\n";
  } else {
    std::cout << to_hex(data) << "\n";
  }
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

double mean(const std::vector<double>& v) {
  return std::accumulate(v.begin(), v.end(), 0.0) / static_cast<double>(v.size());
}

double median(std::vector<double> v) {
  std::sort(v.begin(), v.end());
  const std::size_t n = v.size();
  return n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2.0;
}

double stddev(const std::vector<double>& v, double m) {
  if (v.size() < 2) return 0.0;
  double accum = 0.0;
  for (double x : v) accum += (x - m) * (x - m);
  return std::sqrt(accum / static_cast<double>(v.size() - 1));
}

struct BenchRow {
  std::string mode;
  std::string size_label;
  double enc_mbps = 0.0;
  double dec_mbps = 0.0;
  double enc_latency_us = 0.0;
  double dec_latency_us = 0.0;
};

std::string format_payload_size(std::size_t size) {
  std::ostringstream oss;
  if (size >= 1024 * 1024 && size % (1024 * 1024) == 0) {
    oss << (size / (1024 * 1024)) << " MB";
  } else if (size >= 1024 && size % 1024 == 0) {
    oss << (size / 1024) << " KB";
  } else {
    oss << size << " B";
  }
  return oss.str();
}

int run_keygen(const Options& opt) {
  if (opt.out_file.empty()) throw std::runtime_error("keygen requires --out");
  if (opt.bits != 128 && opt.bits != 192 && opt.bits != 256 && opt.bits != 512) {
    throw std::runtime_error("keygen --bits must be 128, 192, 256, or 512");
  }
  Bytes key = random_bytes(static_cast<std::size_t>(opt.bits / 8));
  write_file(opt.out_file, key);
  std::cout << "Generated " << opt.bits << "-bit key: " << opt.out_file << "\n";
  return 0;
}

int run_encrypt(const Options& opt) {
  const std::string mode = lower(opt.mode);
  if (!is_valid_mode(mode)) throw std::runtime_error("unsupported --mode");

  Bytes plaintext = read_input_bytes(opt);
  if (mode == "ecb") {
    std::cerr << "WARNING: ECB leaks plaintext patterns and should not be used for real file encryption.\n";
    if (!opt.allow_ecb && plaintext.size() > kEcbLimit) {
      throw std::runtime_error("ECB input larger than 16 KiB requires --allow-ecb");
    }
  }

  Bytes key = read_key_material(opt, mode);
  Bytes iv = read_optional_bytes(opt.iv_file.empty() ? opt.nonce_file : opt.iv_file,
                                 opt.iv_hex.empty() ? opt.nonce_hex : opt.iv_hex, "");
  const std::size_t iv_len = required_iv_len(mode);
  if (iv.empty() && iv_len > 0) iv = random_bytes(iv_len);
  validate_iv(mode, iv);

  Bytes aad = read_optional_bytes(opt.aad_file, "", opt.aad_text);
  const std::string key_id = sha256_hex(key);
  check_nonce_registry(mode, key_id, iv);

  Bytes tag;
  Bytes ciphertext = encrypt_bytes(mode, key, iv, plaintext, aad, &tag);

  CryptoResult result{ciphertext, iv, aad, tag, mode, alg_name(mode, key), key_id};
  if (!opt.out_file.empty()) {
    write_file(opt.out_file, ciphertext);
    write_metadata(opt.out_file, result);
    record_nonce_registry(mode, key_id, iv);
    std::cout << "Wrote ciphertext: " << opt.out_file << "\n";
    std::cout << "Wrote metadata: " << metadata_path_for(opt.out_file) << "\n";
    if (!tag.empty()) std::cout << "Tag: " << to_hex(tag) << "\n";
  } else {
    print_encoded(ciphertext, opt.encode);
  }
  return 0;
}

int run_decrypt(const Options& opt) {
  const std::string mode = lower(opt.mode);
  if (!is_valid_mode(mode)) throw std::runtime_error("unsupported --mode");

  Bytes ciphertext = read_input_bytes(opt);
  Bytes key = read_key_material(opt, mode);

  std::map<std::string, std::string> meta;
  if (!opt.in_file.empty()) meta = read_metadata(opt.in_file);

  Bytes iv = read_optional_bytes(opt.iv_file.empty() ? opt.nonce_file : opt.iv_file,
                                 opt.iv_hex.empty() ? opt.nonce_hex : opt.iv_hex, "");
  if (iv.empty() && !meta.empty()) {
    const std::string label = iv_label(mode);
    auto it = meta.find(label);
    if (it != meta.end()) iv = from_hex(it->second);
    if (iv.empty()) {
      auto alt = meta.find("iv");
      if (alt != meta.end()) iv = from_hex(alt->second);
    }
    if (iv.empty()) {
      auto alt = meta.find("nonce");
      if (alt != meta.end()) iv = from_hex(alt->second);
    }
  }
  validate_iv(mode, iv);

  Bytes aad = read_optional_bytes(opt.aad_file, "", opt.aad_text);
  if (aad.empty() && !meta.empty() && meta.count("aad")) aad = from_hex(meta["aad"]);

  Bytes tag;
  if (is_aead(mode)) {
    if (!meta.empty() && meta.count("tag")) tag = from_hex(meta["tag"]);
    if (tag.empty()) throw std::runtime_error("AEAD decrypt requires tag in sidecar metadata");
  }

  Bytes plaintext = decrypt_bytes(mode, key, iv, ciphertext, aad, tag);
  if (!opt.out_file.empty()) {
    write_file(opt.out_file, plaintext);
    std::cout << "Wrote plaintext: " << opt.out_file << "\n";
  } else {
    print_encoded(plaintext, opt.encode);
  }
  return 0;
}

struct VectorCase {
  std::string name;
  std::string mode;
  Bytes key;
  Bytes iv;
  Bytes aad;
  Bytes plaintext;
  Bytes ciphertext;
  Bytes tag;
};

template <int TagLen>
Bytes ccm_encrypt_with_tag(const Bytes& key, const Bytes& nonce, const Bytes& plaintext,
                           const Bytes& aad, Bytes* tag) {
  typename CryptoPP::CCM<CryptoPP::AES, TagLen>::Encryption enc;
  enc.SetKeyWithIV(key.data(), key.size(), nonce.data(), nonce.size());
  enc.SpecifyDataLengths(aad.size(), plaintext.size(), 0);
  std::string combined;
  CryptoPP::AuthenticatedEncryptionFilter ef(enc, new CryptoPP::StringSink(combined),
    false, TagLen);
  ef.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
  ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
  ef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, plaintext.data(), plaintext.size());
  ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
  if (combined.size() < static_cast<std::size_t>(TagLen)) {
    throw std::runtime_error("CCM KAT output too short");
  }
  if (tag) tag->assign(combined.end() - TagLen, combined.end());
  return Bytes(combined.begin(), combined.end() - TagLen);
}

template <int TagLen>
Bytes ccm_decrypt_with_tag(const Bytes& key, const Bytes& nonce, const Bytes& ciphertext,
                           const Bytes& aad, const Bytes& tag) {
  if (tag.size() != static_cast<std::size_t>(TagLen)) {
    throw std::runtime_error("CCM KAT tag length mismatch");
  }
  typename CryptoPP::CCM<CryptoPP::AES, TagLen>::Decryption dec;
  dec.SetKeyWithIV(key.data(), key.size(), nonce.data(), nonce.size());
  dec.SpecifyDataLengths(aad.size(), ciphertext.size(), 0);
  std::string combined(ciphertext.begin(), ciphertext.end());
  combined.append(tag.begin(), tag.end());
  std::string out;
  CryptoPP::AuthenticatedDecryptionFilter df(dec, new CryptoPP::StringSink(out),
    CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION, TagLen);
  df.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
  df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
  df.ChannelPut(CryptoPP::DEFAULT_CHANNEL,
                reinterpret_cast<const unsigned char*>(combined.data()), combined.size());
  df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
  return Bytes(out.begin(), out.end());
}

Bytes ccm_encrypt_kat(const Bytes& key, const Bytes& nonce, const Bytes& plaintext,
                      const Bytes& aad, std::size_t tag_len, Bytes* tag) {
  switch (tag_len) {
    case 4: return ccm_encrypt_with_tag<4>(key, nonce, plaintext, aad, tag);
    case 6: return ccm_encrypt_with_tag<6>(key, nonce, plaintext, aad, tag);
    case 8: return ccm_encrypt_with_tag<8>(key, nonce, plaintext, aad, tag);
    case 10: return ccm_encrypt_with_tag<10>(key, nonce, plaintext, aad, tag);
    case 12: return ccm_encrypt_with_tag<12>(key, nonce, plaintext, aad, tag);
    case 14: return ccm_encrypt_with_tag<14>(key, nonce, plaintext, aad, tag);
    case 16: return ccm_encrypt_with_tag<16>(key, nonce, plaintext, aad, tag);
    default: throw std::runtime_error("unsupported CCM KAT tag length");
  }
}

Bytes ccm_decrypt_kat(const Bytes& key, const Bytes& nonce, const Bytes& ciphertext,
                      const Bytes& aad, const Bytes& tag) {
  switch (tag.size()) {
    case 4: return ccm_decrypt_with_tag<4>(key, nonce, ciphertext, aad, tag);
    case 6: return ccm_decrypt_with_tag<6>(key, nonce, ciphertext, aad, tag);
    case 8: return ccm_decrypt_with_tag<8>(key, nonce, ciphertext, aad, tag);
    case 10: return ccm_decrypt_with_tag<10>(key, nonce, ciphertext, aad, tag);
    case 12: return ccm_decrypt_with_tag<12>(key, nonce, ciphertext, aad, tag);
    case 14: return ccm_decrypt_with_tag<14>(key, nonce, ciphertext, aad, tag);
    case 16: return ccm_decrypt_with_tag<16>(key, nonce, ciphertext, aad, tag);
    default: throw std::runtime_error("unsupported CCM KAT tag length");
  }
}

std::vector<VectorCase> load_vectors(const std::string& path) {
  Bytes raw = read_file(path);
  std::string text(raw.begin(), raw.end());
  std::vector<VectorCase> out;
  std::regex obj("\\{([^\\{\\}]*)\\}");
  std::regex kv("\"([^\"]+)\"\\s*:\\s*\"([^\"]*)\"");
  for (std::sregex_iterator it(text.begin(), text.end(), obj), end; it != end; ++it) {
    std::string body = (*it)[1].str();
    std::map<std::string, std::string> m;
    for (std::sregex_iterator kt(body.begin(), body.end(), kv), kend; kt != kend; ++kt) {
      m[(*kt)[1].str()] = (*kt)[2].str();
    }
    if (!m.count("mode") || !m.count("key") || !m.count("plaintext") || !m.count("ciphertext")) {
      continue;
    }
    VectorCase vc;
    vc.name = m.count("name") ? m["name"] : m["mode"];
    vc.mode = lower(m["mode"]);
    vc.key = from_hex(m["key"]);
    vc.iv = m.count("iv") ? from_hex(m["iv"]) : Bytes{};
    if (vc.iv.empty() && m.count("nonce")) vc.iv = from_hex(m["nonce"]);
    vc.aad = m.count("aad") ? from_hex(m["aad"]) : Bytes{};
    vc.plaintext = from_hex(m["plaintext"]);
    vc.ciphertext = from_hex(m["ciphertext"]);
    vc.tag = m.count("tag") ? from_hex(m["tag"]) : Bytes{};
    out.push_back(vc);
  }
  return out;
}

int run_kat(const Options& opt) {
  const auto vectors = load_vectors(opt.kat_file);
  if (vectors.empty()) throw std::runtime_error("no KAT vectors loaded");
  int passed = 0;
  int failed = 0;
  for (const auto& tc : vectors) {
    try {
      Bytes tag;
      Bytes ct;
      Bytes pt;
      if (tc.mode == "ccm") {
        ct = ccm_encrypt_kat(tc.key, tc.iv, tc.plaintext, tc.aad, tc.tag.size(), &tag);
        pt = ccm_decrypt_kat(tc.key, tc.iv, tc.ciphertext, tc.aad, tc.tag);
      } else {
        ct = encrypt_bytes(tc.mode, tc.key, tc.iv, tc.plaintext, tc.aad, &tag);
        pt = decrypt_bytes(tc.mode, tc.key, tc.iv, tc.ciphertext, tc.aad, tc.tag);
      }
      const bool ok = (ct == tc.ciphertext) && (pt == tc.plaintext) &&
                      (!is_aead(tc.mode) || tag == tc.tag);
      std::cout << (ok ? "PASS " : "FAIL ") << tc.name << " [" << tc.mode << "]\n";
      if (!ok) {
        if (ct != tc.ciphertext) {
          std::cout << "  expected ct: " << to_hex(tc.ciphertext) << "\n";
          std::cout << "  actual ct:   " << to_hex(ct) << "\n";
        }
        if (pt != tc.plaintext) {
          std::cout << "  expected pt: " << to_hex(tc.plaintext) << "\n";
          std::cout << "  actual pt:   " << to_hex(pt) << "\n";
        }
        if (is_aead(tc.mode) && tag != tc.tag) {
          std::cout << "  expected tag: " << to_hex(tc.tag) << "\n";
          std::cout << "  actual tag:   " << to_hex(tag) << "\n";
        }
      }
      ok ? ++passed : ++failed;
    } catch (const std::exception& ex) {
      std::cout << "FAIL " << tc.name << " [" << tc.mode << "]: " << ex.what() << "\n";
      ++failed;
    }
  }
  std::cout << "Summary: " << passed << " passed, " << failed << " failed\n";
  return failed == 0 ? 0 : 1;
}

BenchRow bench_one(const std::string& mode, std::size_t size, int runs, int ops) {
  const std::size_t key_len = mode == "xts" ? 64 : 32;
  Bytes key = random_bytes(key_len);
  Bytes iv(required_iv_len(mode));
  if (!iv.empty()) iv = random_bytes(iv.size());
  Bytes aad = Bytes{'l', 'a', 'b', '1'};
  const std::size_t data_size =
      ((mode == "cbc" || mode == "ecb") && size > 1 && size % kBlock == 0)
          ? size - 1
          : size;
  Bytes data = random_bytes(data_size);
  Bytes sample_tag;
  Bytes sample_ciphertext = encrypt_bytes(mode, key, iv, data, aad, &sample_tag);

  for (int i = 0; i < 3; ++i) {
    Bytes tag;
    (void)encrypt_bytes(mode, key, iv, data, aad, &tag);
    (void)decrypt_bytes(mode, key, iv, sample_ciphertext, aad, sample_tag);
  }

  std::vector<double> enc_mbps_values;
  std::vector<double> dec_mbps_values;
  std::vector<double> enc_latency_values;
  std::vector<double> dec_latency_values;
  for (int r = 0; r < runs; ++r) {
    auto enc_start = std::chrono::steady_clock::now();
    for (int i = 0; i < ops; ++i) {
      Bytes local_iv = iv;
      if (is_nonce_reuse_sensitive(mode) && !local_iv.empty()) {
        local_iv.back() = static_cast<unsigned char>((local_iv.back() + i + r) & 0xff);
      }
      Bytes tag;
      (void)encrypt_bytes(mode, key, local_iv, data, aad, &tag);
    }
    auto enc_end = std::chrono::steady_clock::now();
    const double enc_seconds = std::chrono::duration<double>(enc_end - enc_start).count();

    auto dec_start = std::chrono::steady_clock::now();
    for (int i = 0; i < ops; ++i) {
      (void)decrypt_bytes(mode, key, iv, sample_ciphertext, aad, sample_tag);
    }
    auto dec_end = std::chrono::steady_clock::now();
    const double dec_seconds = std::chrono::duration<double>(dec_end - dec_start).count();

    const double mb = (static_cast<double>(size) * static_cast<double>(ops)) / (1024.0 * 1024.0);
    enc_mbps_values.push_back(mb / enc_seconds);
    dec_mbps_values.push_back(mb / dec_seconds);
    enc_latency_values.push_back((enc_seconds * 1000000.0) / static_cast<double>(ops));
    dec_latency_values.push_back((dec_seconds * 1000000.0) / static_cast<double>(ops));
  }
  return BenchRow{
      mode,
      format_payload_size(size),
      mean(enc_mbps_values),
      mean(dec_mbps_values),
      mean(enc_latency_values),
      mean(dec_latency_values)};
}

int run_bench(const Options& opt) {
  std::vector<std::string> modes = {lower(opt.mode)};
  std::vector<std::size_t> sizes = {opt.size};
  if (opt.all) {
    modes = {"ecb", "cbc", "ofb", "cfb", "ctr", "xts", "gcm", "ccm"};
    sizes = {1024, 4096, 16384, 262144, 1048576, 8388608};
  } else if (!is_valid_mode(modes.front())) {
    throw std::runtime_error("bench requires --mode or --all");
  }
  std::cout << "============================================================\n";
  std::cout << "                 AES-256 BENCHMARK RESULTS\n";
  std::cout << "============================================================\n";
  std::cout << "Runs: " << opt.runs << " | Ops/run: " << opt.ops
            << " | Library: Crypto++\n\n";
  std::cout << std::left << std::setw(8) << "Mode"
            << std::right << std::setw(10) << "Size"
            << std::setw(14) << "Enc MB/s"
            << std::setw(14) << "Dec MB/s"
            << std::setw(14) << "Enc Lat(us)"
            << std::setw(14) << "Dec Lat(us)" << "\n";
  std::cout << "------------------------------------------------------------\n";

  for (const auto& mode : modes) {
    for (std::size_t size : sizes) {
      const BenchRow row = bench_one(mode, size, opt.runs, opt.ops);
      std::cout << std::left << std::setw(8) << row.mode
                << std::right << std::setw(10) << row.size_label
                << std::setw(14) << std::fixed << std::setprecision(2) << row.enc_mbps
                << std::setw(14) << std::fixed << std::setprecision(2) << row.dec_mbps
                << std::setw(14) << std::fixed << std::setprecision(2) << row.enc_latency_us
                << std::setw(14) << std::fixed << std::setprecision(2) << row.dec_latency_us
                << "\n";
    }
  }
  std::cout << "============================================================\n";
  return 0;
}

}  // namespace

int run(int argc, char** argv) {
  Options opt = parse_args(argc, argv);
  if (opt.command.empty() || opt.command == "help") {
    print_help();
    return 0;
  }
  if (!opt.kat_file.empty()) return run_kat(opt);
  if (opt.command == "keygen") return run_keygen(opt);
  if (opt.command == "encrypt") return run_encrypt(opt);
  if (opt.command == "decrypt") return run_decrypt(opt);
  if (opt.command == "bench") return run_bench(opt);
  throw std::runtime_error("unknown command: " + opt.command);
}

Options parse_args(int argc, char** argv) {
  Options opt;
  if (argc <= 1) return opt;
  opt.command = argv[1];
  if (opt.command == "--help" || opt.command == "-h") opt.command = "help";
  if (opt.command == "--kat") {
    if (argc < 3) throw std::runtime_error("--kat requires a vector file");
    opt.command = "kat";
    opt.kat_file = argv[2];
    return opt;
  }
  for (int i = 2; i < argc; ++i) {
    std::string a = argv[i];
    auto need = [&](const std::string& name) -> std::string {
      if (i + 1 >= argc) throw std::runtime_error(name + " requires a value");
      return argv[++i];
    };
    if (a == "--mode") opt.mode = need(a);
    else if (a == "--in") opt.in_file = need(a);
    else if (a == "--out") opt.out_file = need(a);
    else if (a == "--text") opt.text = need(a);
    else if (a == "--key") opt.key_file = need(a);
    else if (a == "--key-hex") opt.key_hex = need(a);
    else if (a == "--iv") opt.iv_file = need(a);
    else if (a == "--iv-hex") opt.iv_hex = need(a);
    else if (a == "--nonce") opt.nonce_file = need(a);
    else if (a == "--nonce-hex") opt.nonce_hex = need(a);
    else if (a == "--aad") opt.aad_file = need(a);
    else if (a == "--aad-text") opt.aad_text = need(a);
    else if (a == "--encode") opt.encode = lower(need(a));
    else if (a == "--kat") opt.kat_file = need(a);
    else if (a == "--size") opt.size = static_cast<std::size_t>(std::stoull(need(a)));
    else if (a == "--runs") opt.runs = std::stoi(need(a));
    else if (a == "--ops") opt.ops = std::stoi(need(a));
    else if (a == "--bits") opt.bits = std::stoi(need(a));
    else if (a == "--aead") opt.aead = true;
    else if (a == "--allow-ecb") opt.allow_ecb = true;
    else if (a == "--all") opt.all = true;
    else if (a == "--verbose") opt.verbose = true;
    else throw std::runtime_error("unknown option: " + a);
  }
  return opt;
}

void print_help() {
  std::cout
      << "aestool - AES CLI for Lab 1 using Crypto++\n\n"
      << "USAGE\n"
      << "  aestool <command> [options]\n"
      << "  aestool --kat <vectors.json>\n\n"
      << "COMMANDS\n"
      << "  keygen    Generate a random AES key file.\n"
      << "  encrypt   Encrypt file input or UTF-8 text input.\n"
      << "  decrypt   Decrypt a ciphertext file using its sidecar metadata.\n"
      << "  bench     Benchmark AES modes and print a formatted result table.\n"
      << "  --kat     Run Known Answer Tests from a JSON vector file.\n"
      << "  --help    Show this help message.\n\n"
      << "MODES\n"
      << "  ecb       Electronic Codebook. Warned and limited by default.\n"
      << "  cbc       Cipher Block Chaining with 16-byte IV.\n"
      << "  ofb       Output Feedback with 16-byte IV.\n"
      << "  cfb       Cipher Feedback with 16-byte IV.\n"
      << "  ctr       Counter mode with 16-byte nonce/counter.\n"
      << "  xts       XTS disk-encryption mode with 16-byte tweak.\n"
      << "  ccm       AEAD mode with nonce, AAD, and authentication tag.\n"
      << "  gcm       AEAD mode with 12-byte nonce, AAD, and authentication tag.\n\n"
      << "COMMON FLAGS\n"
      << "  --mode <mode>              AES mode: ecb|cbc|ofb|cfb|ctr|xts|ccm|gcm.\n"
      << "  --key <file>               Read key from raw binary or hex-encoded file.\n"
      << "  --key-hex <hex>            Read key directly from a hex string.\n"
      << "  --in <file>                Read binary-safe input from a file.\n"
      << "  --text <string>            Read UTF-8 text input from the command line.\n"
      << "  --out <file>               Write binary-safe output to a file.\n"
      << "  --iv <file>                Read IV/tweak from a file.\n"
      << "  --iv-hex <hex>             Read IV/tweak from a hex string.\n"
      << "  --nonce <file>             Read nonce from a file.\n"
      << "  --nonce-hex <hex>          Read nonce from a hex string.\n"
      << "  --aad <file>               Read AEAD additional authenticated data from file.\n"
      << "  --aad-text <string>        Read AEAD additional authenticated data from text.\n"
      << "  --encode hex|base64|raw    Console encoding when --out is omitted.\n"
      << "  --allow-ecb                Allow ECB for inputs larger than 16 KiB.\n"
      << "  --verbose                  Reserved for more detailed diagnostics.\n\n"
      << "KEYGEN FLAGS\n"
      << "  --bits 128|192|256|512     Key size. Use 512 only for AES-XTS-256.\n"
      << "  --out <file>               Output key file.\n\n"
      << "BENCH FLAGS\n"
      << "  --mode <mode>              Benchmark one AES mode.\n"
      << "  --all                      Benchmark all required modes and payload sizes.\n"
      << "  --size <bytes>             Payload size for one-mode benchmark.\n"
      << "  --runs <N>                 Number of independent timed runs.\n"
      << "  --ops <N>                  Operations per timed run.\n"
      << "  Output columns             Enc/Dec throughput in MB/s and latency in microseconds.\n\n"
      << "EXAMPLES\n"
      << "  aestool keygen --bits 256 --out key.bin\n"
      << "  aestool encrypt --mode gcm --key key.bin --text \"hello\" --out ct.bin --aad-text metadata\n"
      << "  aestool decrypt --mode gcm --key key.bin --in ct.bin --out msg.txt\n"
      << "  aestool encrypt --mode cbc --key-hex 001122... --iv-hex 000102... --in msg.bin --out ct.bin\n"
      << "  aestool --kat vectors/nist_38a.json\n"
      << "  aestool --kat vectors/aead.json\n"
      << "  aestool bench --mode gcm --size 1048576 --runs 30 --ops 1000\n"
      << "  aestool bench --all --runs 30 --ops 100\n\n"
      << "NOTES\n"
      << "  - Crypto++ is used for all cryptographic primitives.\n"
      << "  - If IV/nonce is omitted, it is generated with AutoSeededRandomPool.\n"
      << "  - Ciphertext metadata is written to <output>.meta.json.\n"
      << "  - GCM/CCM verify authentication tags during decryption and fail closed.\n"
      << "  - CTR/GCM/CCM reject repeated key_id + nonce pairs.\n"
      << "  - ECB is insecure for structured data and is restricted by default.\n";
}

Bytes encrypt_bytes(const std::string& mode_in, const Bytes& key, const Bytes& iv,
                    const Bytes& plaintext, const Bytes& aad, Bytes* tag) {
  const std::string mode = lower(mode_in);
  validate_key(mode, key);
  validate_iv(mode, iv);
  if (tag) tag->clear();
  std::string out;

  if (mode == "ecb") {
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc;
    enc.SetKey(key.data(), key.size());
    const auto padding = (plaintext.size() % kBlock == 0)
      ? CryptoPP::StreamTransformationFilter::NO_PADDING
      : CryptoPP::StreamTransformationFilter::DEFAULT_PADDING;
    CryptoPP::StringSource ss(plaintext.data(), plaintext.size(), true,
      new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::StringSink(out), padding));
  } else if (mode == "cbc") {
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    const auto padding = (plaintext.size() % kBlock == 0)
      ? CryptoPP::StreamTransformationFilter::NO_PADDING
      : CryptoPP::StreamTransformationFilter::DEFAULT_PADDING;
    CryptoPP::StringSource ss(plaintext.data(), plaintext.size(), true,
      new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::StringSink(out), padding));
  } else if (mode == "ofb") {
    CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    CryptoPP::StringSource ss(plaintext.data(), plaintext.size(), true,
      new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::StringSink(out),
        CryptoPP::StreamTransformationFilter::NO_PADDING));
  } else if (mode == "cfb") {
    CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    CryptoPP::StringSource ss(plaintext.data(), plaintext.size(), true,
      new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::StringSink(out),
        CryptoPP::StreamTransformationFilter::NO_PADDING));
  } else if (mode == "ctr") {
    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    CryptoPP::StringSource ss(plaintext.data(), plaintext.size(), true,
      new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::StringSink(out),
        CryptoPP::StreamTransformationFilter::NO_PADDING));
  } else if (mode == "xts") {
    CryptoPP::XTS_Mode<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    CryptoPP::StringSource ss(plaintext.data(), plaintext.size(), true,
      new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::StringSink(out),
        CryptoPP::StreamTransformationFilter::NO_PADDING));
  } else if (mode == "gcm") {
    CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    std::string combined;
    CryptoPP::AuthenticatedEncryptionFilter ef(enc, new CryptoPP::StringSink(combined),
      false, kTagSize);
    ef.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
    ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
    ef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, plaintext.data(), plaintext.size());
    ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
    if (combined.size() < kTagSize) throw std::runtime_error("GCM output too short");
    out = combined.substr(0, combined.size() - kTagSize);
    if (tag) tag->assign(combined.end() - kTagSize, combined.end());
  } else if (mode == "ccm") {
    CryptoPP::CCM<CryptoPP::AES, kTagSize>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    enc.SpecifyDataLengths(aad.size(), plaintext.size(), 0);
    std::string combined;
    CryptoPP::AuthenticatedEncryptionFilter ef(enc, new CryptoPP::StringSink(combined),
      false, kTagSize);
    ef.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
    ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
    ef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, plaintext.data(), plaintext.size());
    ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
    if (combined.size() < kTagSize) throw std::runtime_error("CCM output too short");
    out = combined.substr(0, combined.size() - kTagSize);
    if (tag) tag->assign(combined.end() - kTagSize, combined.end());
  } else {
    throw std::runtime_error("unsupported mode");
  }
  return Bytes(out.begin(), out.end());
}

Bytes decrypt_bytes(const std::string& mode_in, const Bytes& key, const Bytes& iv,
                    const Bytes& ciphertext, const Bytes& aad, const Bytes& tag) {
  const std::string mode = lower(mode_in);
  validate_key(mode, key);
  validate_iv(mode, iv);
  std::string out;

  if (mode == "ecb") {
    CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKey(key.data(), key.size());
    try {
      CryptoPP::StringSource ss(ciphertext.data(), ciphertext.size(), true,
        new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::StringSink(out)));
    } catch (const CryptoPP::Exception&) {
      out.clear();
      CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption fallback;
      fallback.SetKey(key.data(), key.size());
      CryptoPP::StringSource ss(ciphertext.data(), ciphertext.size(), true,
        new CryptoPP::StreamTransformationFilter(fallback, new CryptoPP::StringSink(out),
          CryptoPP::StreamTransformationFilter::NO_PADDING));
    }
  } else if (mode == "cbc") {
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    try {
      CryptoPP::StringSource ss(ciphertext.data(), ciphertext.size(), true,
        new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::StringSink(out)));
    } catch (const CryptoPP::Exception&) {
      out.clear();
      CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption fallback;
      fallback.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
      CryptoPP::StringSource ss(ciphertext.data(), ciphertext.size(), true,
        new CryptoPP::StreamTransformationFilter(fallback, new CryptoPP::StringSink(out),
          CryptoPP::StreamTransformationFilter::NO_PADDING));
    }
  } else if (mode == "ofb") {
    CryptoPP::OFB_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    CryptoPP::StringSource ss(ciphertext.data(), ciphertext.size(), true,
      new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::StringSink(out),
        CryptoPP::StreamTransformationFilter::NO_PADDING));
  } else if (mode == "cfb") {
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    CryptoPP::StringSource ss(ciphertext.data(), ciphertext.size(), true,
      new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::StringSink(out),
        CryptoPP::StreamTransformationFilter::NO_PADDING));
  } else if (mode == "ctr") {
    CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    CryptoPP::StringSource ss(ciphertext.data(), ciphertext.size(), true,
      new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::StringSink(out),
        CryptoPP::StreamTransformationFilter::NO_PADDING));
  } else if (mode == "xts") {
    CryptoPP::XTS_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    CryptoPP::StringSource ss(ciphertext.data(), ciphertext.size(), true,
      new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::StringSink(out),
        CryptoPP::StreamTransformationFilter::NO_PADDING));
  } else if (mode == "gcm") {
    if (tag.size() != kTagSize) throw std::runtime_error("GCM requires 16-byte tag");
    CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    std::string combined(ciphertext.begin(), ciphertext.end());
    combined.append(tag.begin(), tag.end());
    CryptoPP::AuthenticatedDecryptionFilter df(dec, new CryptoPP::StringSink(out),
      CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION, kTagSize);
    df.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
    df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
    df.ChannelPut(CryptoPP::DEFAULT_CHANNEL,
                  reinterpret_cast<const unsigned char*>(combined.data()),
                  combined.size());
    df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
  } else if (mode == "ccm") {
    if (tag.size() != kTagSize) throw std::runtime_error("CCM requires 16-byte tag");
    CryptoPP::CCM<CryptoPP::AES, kTagSize>::Decryption dec;
    dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    dec.SpecifyDataLengths(aad.size(), ciphertext.size(), 0);
    std::string combined(ciphertext.begin(), ciphertext.end());
    combined.append(tag.begin(), tag.end());
    CryptoPP::AuthenticatedDecryptionFilter df(dec, new CryptoPP::StringSink(out),
      CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION, kTagSize);
    df.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
    df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
    df.ChannelPut(CryptoPP::DEFAULT_CHANNEL,
                  reinterpret_cast<const unsigned char*>(combined.data()),
                  combined.size());
    df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
  } else {
    throw std::runtime_error("unsupported mode");
  }
  return Bytes(out.begin(), out.end());
}

Bytes read_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) throw std::runtime_error("cannot open file: " + path);
  return Bytes(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

void write_file(const std::string& path, const Bytes& data) {
  std::ofstream f(path, std::ios::binary);
  if (!f) throw std::runtime_error("cannot write file: " + path);
  f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

bool file_exists(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  return static_cast<bool>(f);
}

std::uintmax_t file_size(const std::string& path) {
  std::ifstream f(path, std::ios::binary | std::ios::ate);
  if (!f) throw std::runtime_error("cannot stat file: " + path);
  return static_cast<std::uintmax_t>(f.tellg());
}

Bytes from_hex(const std::string& hex_in) {
  std::string hex = trim(hex_in);
  if (hex.rfind("hex:", 0) == 0 || hex.rfind("HEX:", 0) == 0) hex = hex.substr(4);
  hex.erase(std::remove_if(hex.begin(), hex.end(), [](unsigned char c) {
    return std::isspace(c) != 0;
  }), hex.end());
  if (hex.empty()) return {};
  std::string decoded;
  CryptoPP::StringSource ss(hex, true,
    new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded)));
  return Bytes(decoded.begin(), decoded.end());
}

std::string to_hex(const Bytes& data, bool lowercase) {
  std::string encoded;
  CryptoPP::StringSource ss(data.data(), data.size(), true,
    new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded), false));
  if (lowercase) {
    std::transform(encoded.begin(), encoded.end(), encoded.begin(), [](unsigned char c) {
      return static_cast<char>(std::tolower(c));
    });
  }
  return encoded;
}

std::string to_base64(const Bytes& data) {
  std::string encoded;
  CryptoPP::StringSource ss(data.data(), data.size(), true,
    new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
  return encoded;
}

Bytes random_bytes(std::size_t n) {
  Bytes out(n);
  CryptoPP::AutoSeededRandomPool rng;
  rng.GenerateBlock(out.data(), out.size());
  return out;
}

std::string sha256_hex(const Bytes& data) {
  std::string digest;
  CryptoPP::SHA256 hash;
  CryptoPP::StringSource ss(data.data(), data.size(), true,
    new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(digest)));
  return to_hex(Bytes(digest.begin(), digest.end()));
}

std::string lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

}  // namespace aestool
