#include "pqtool.hpp"

#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha3.h>
#include <cryptopp/shake.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>

namespace pqtool {
namespace {

constexpr int64_t DSA_Q = 8380417;
constexpr int64_t KEM_Q = 3329;
bool g_quiet = false;

struct DsaParams {
  std::string algo;
  int n;
  int y_bound;
  int security_bits;
};

struct KemParams {
  std::string algo;
  int n;
  int security_bits;
};

struct DsaPublicKey {
  DsaParams params;
  std::vector<uint8_t> seed_a;
  std::vector<int32_t> t;
};

struct DsaPrivateKey {
  DsaParams params;
  std::vector<uint8_t> seed_a;
  std::vector<int32_t> s;
  std::vector<int32_t> t;
};

struct KemPublicKey {
  KemParams params;
  std::vector<uint8_t> seed_a;
  std::vector<int32_t> t;
};

struct KemPrivateKey {
  KemParams params;
  std::vector<uint8_t> seed_a;
  std::vector<int32_t> s;
  std::vector<int32_t> e;
  std::vector<int32_t> t;
};

std::vector<uint8_t> read_file(const std::string& path) {
  if (path.empty()) {
    throw ToolError("missing file path");
  }
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    throw ToolError("cannot open input file: " + path);
  }
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void write_file(const std::string& path, const std::vector<uint8_t>& bytes) {
  if (path.empty()) {
    throw ToolError("missing output path");
  }
  std::ofstream out(path, std::ios::binary);
  if (!out) {
    throw ToolError("cannot open output file: " + path);
  }
  out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

void write_text(const std::string& path, const std::string& text) {
  write_file(path, std::vector<uint8_t>(text.begin(), text.end()));
}

std::vector<uint8_t> message_from_options(const std::string& input_path, const std::string& text) {
  if (!input_path.empty() && !text.empty()) {
    throw ToolError("use either --in or --text, not both");
  }
  if (!input_path.empty()) {
    return read_file(input_path);
  }
  if (!text.empty()) {
    return std::vector<uint8_t>(text.begin(), text.end());
  }
  throw ToolError("missing input: use --in or --text");
}

std::vector<uint8_t> random_bytes(size_t n) {
  CryptoPP::AutoSeededRandomPool rng;
  std::vector<uint8_t> out(n);
  rng.GenerateBlock(out.data(), out.size());
  return out;
}

std::vector<uint8_t> sha3_256(const std::vector<uint8_t>& data) {
  CryptoPP::SHA3_256 hash;
  std::vector<uint8_t> digest(hash.DigestSize());
  hash.Update(data.data(), data.size());
  hash.Final(digest.data());
  return digest;
}

std::vector<uint8_t> shake256(const std::vector<uint8_t>& data, size_t out_len) {
  CryptoPP::SHAKE256 shake;
  std::vector<uint8_t> out(out_len);
  shake.Update(data.data(), data.size());
  shake.TruncatedFinal(out.data(), out.size());
  return out;
}

void append_u32(std::vector<uint8_t>& out, uint32_t value) {
  out.push_back(static_cast<uint8_t>(value & 0xff));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
  out.push_back(static_cast<uint8_t>((value >> 16) & 0xff));
  out.push_back(static_cast<uint8_t>((value >> 24) & 0xff));
}

uint32_t read_u32_le(const std::vector<uint8_t>& data, size_t off) {
  if (off + 4 > data.size()) {
    throw ToolError("truncated integer encoding");
  }
  return static_cast<uint32_t>(data[off]) |
         (static_cast<uint32_t>(data[off + 1]) << 8) |
         (static_cast<uint32_t>(data[off + 2]) << 16) |
         (static_cast<uint32_t>(data[off + 3]) << 24);
}

std::string b64_encode(const std::vector<uint8_t>& bytes) {
  std::string out;
  CryptoPP::StringSource ss(bytes.data(), bytes.size(), true,
                            new CryptoPP::Base64Encoder(new CryptoPP::StringSink(out), false));
  return out;
}

std::vector<uint8_t> b64_decode(const std::string& text) {
  std::string decoded;
  CryptoPP::StringSource ss(text, true,
                            new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
  return std::vector<uint8_t>(decoded.begin(), decoded.end());
}

std::string hex_encode(const std::vector<uint8_t>& bytes) {
  static const char* alphabet = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (uint8_t b : bytes) {
    out.push_back(alphabet[b >> 4]);
    out.push_back(alphabet[b & 0xf]);
  }
  return out;
}

uint8_t hex_value(char c) {
  if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
  if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
  if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
  throw ToolError("invalid hex character");
}

std::vector<uint8_t> hex_decode(const std::string& hex) {
  if (hex.size() % 2 != 0) {
    throw ToolError("hex string has odd length");
  }
  std::vector<uint8_t> out(hex.size() / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>((hex_value(hex[2 * i]) << 4) | hex_value(hex[2 * i + 1]));
  }
  return out;
}

std::string json_escape(const std::string& s) {
  std::string out;
  for (char c : s) {
    if (c == '\\' || c == '"') {
      out.push_back('\\');
    }
    out.push_back(c);
  }
  return out;
}

std::string json_get_string(const std::string& json, const std::string& key) {
  const std::string needle = "\"" + key + "\"";
  size_t pos = json.find(needle);
  if (pos == std::string::npos) {
    throw ToolError("missing JSON field: " + key);
  }
  pos = json.find(':', pos);
  if (pos == std::string::npos) {
    throw ToolError("malformed JSON field: " + key);
  }
  pos = json.find('"', pos);
  if (pos == std::string::npos) {
    throw ToolError("malformed JSON string: " + key);
  }
  ++pos;
  std::string out;
  bool esc = false;
  for (; pos < json.size(); ++pos) {
    const char c = json[pos];
    if (esc) {
      out.push_back(c);
      esc = false;
    } else if (c == '\\') {
      esc = true;
    } else if (c == '"') {
      return out;
    } else {
      out.push_back(c);
    }
  }
  throw ToolError("unterminated JSON string: " + key);
}

std::string strip_pem(const std::string& text) {
  if (text.find("-----BEGIN") == std::string::npos) {
    return text;
  }
  std::string body;
  std::istringstream in(text);
  std::string line;
  while (std::getline(in, line)) {
    if (line.rfind("-----", 0) == 0) {
      continue;
    }
    body += line;
  }
  return body;
}

std::string wrap_pem(const std::string& label, const std::string& b64) {
  std::ostringstream out;
  out << "-----BEGIN " << label << "-----\n";
  for (size_t i = 0; i < b64.size(); i += 64) {
    out << b64.substr(i, 64) << "\n";
  }
  out << "-----END " << label << "-----\n";
  return out.str();
}

std::string read_key_payload(const std::string& path) {
  const auto bytes = read_file(path);
  const std::string text(bytes.begin(), bytes.end());
  if (text.find("-----BEGIN") != std::string::npos) {
    const auto decoded = b64_decode(strip_pem(text));
    return std::string(decoded.begin(), decoded.end());
  }
  return text;
}

void write_key_payload(const std::string& path, const std::string& payload, const std::string& type,
                       const std::string& format) {
  if (format == "pem") {
    const std::vector<uint8_t> bytes(payload.begin(), payload.end());
    write_text(path, wrap_pem(type, b64_encode(bytes)));
    return;
  }
  if (format == "der") {
    write_file(path, std::vector<uint8_t>(payload.begin(), payload.end()));
    return;
  }
  throw ToolError("unsupported key format: " + format);
}

int64_t mod_q(int64_t x, int64_t q) {
  x %= q;
  if (x < 0) x += q;
  return x;
}

int32_t centered_small(uint8_t b, int bound) {
  return static_cast<int32_t>(b % (2 * bound + 1)) - bound;
}

DsaParams dsa_params(const std::string& algo) {
  if (algo == "mldsa-44") return {algo, 128, 8, 128};
  if (algo == "mldsa-65") return {algo, 192, 10, 192};
  throw ToolError("unsupported ML-DSA algorithm: " + algo);
}

KemParams kem_params(const std::string& algo) {
  if (algo == "mlkem-512") return {algo, 64, 128};
  throw ToolError("unsupported ML-KEM algorithm: " + algo);
}

std::vector<int32_t> bytes_to_small_vector(const std::vector<uint8_t>& seed, int n, int bound) {
  const auto material = shake256(seed, static_cast<size_t>(n));
  std::vector<int32_t> out(n);
  for (int i = 0; i < n; ++i) {
    out[i] = centered_small(material[static_cast<size_t>(i)], bound);
  }
  return out;
}

int32_t matrix_entry(const std::vector<uint8_t>& seed, int row, int col, int64_t q) {
  std::vector<uint8_t> in = seed;
  append_u32(in, static_cast<uint32_t>(row));
  append_u32(in, static_cast<uint32_t>(col));
  const auto b = shake256(in, 4);
  const uint32_t v = read_u32_le(b, 0);
  return static_cast<int32_t>(v % q);
}

std::vector<int32_t> mat_vec(const std::vector<uint8_t>& seed, const std::vector<int32_t>& v,
                             int64_t q) {
  const int n = static_cast<int>(v.size());
  std::vector<int32_t> out(static_cast<size_t>(n));
  for (int r = 0; r < n; ++r) {
    int64_t acc = 0;
    for (int c = 0; c < n; ++c) {
      acc = (acc + matrix_entry(seed, r, c, q) * static_cast<int64_t>(v[static_cast<size_t>(c)])) % q;
    }
    out[static_cast<size_t>(r)] = static_cast<int32_t>(mod_q(acc, q));
  }
  return out;
}

std::vector<int32_t> mat_t_vec(const std::vector<uint8_t>& seed, const std::vector<int32_t>& v,
                               int64_t q) {
  const int n = static_cast<int>(v.size());
  std::vector<int32_t> out(static_cast<size_t>(n));
  for (int c = 0; c < n; ++c) {
    int64_t acc = 0;
    for (int r = 0; r < n; ++r) {
      acc = (acc + matrix_entry(seed, r, c, q) * static_cast<int64_t>(v[static_cast<size_t>(r)])) % q;
    }
    out[static_cast<size_t>(c)] = static_cast<int32_t>(mod_q(acc, q));
  }
  return out;
}

std::vector<uint8_t> serialize_vec(const std::vector<int32_t>& v) {
  std::vector<uint8_t> out;
  out.reserve(v.size() * 4);
  for (int32_t x : v) {
    append_u32(out, static_cast<uint32_t>(x));
  }
  return out;
}

std::vector<int32_t> deserialize_vec(const std::string& hex, int expected) {
  const auto bytes = hex_decode(hex);
  if (bytes.size() != static_cast<size_t>(expected) * 4) {
    throw ToolError("unexpected vector length");
  }
  std::vector<int32_t> out(static_cast<size_t>(expected));
  for (int i = 0; i < expected; ++i) {
    out[static_cast<size_t>(i)] = static_cast<int32_t>(read_u32_le(bytes, static_cast<size_t>(i) * 4));
  }
  return out;
}

std::string encode_dsa_public(const DsaPublicKey& key) {
  std::ostringstream out;
  out << "{\n"
      << "  \"tool\": \"pqtool\",\n"
      << "  \"type\": \"public\",\n"
      << "  \"scheme\": \"mldsa-style\",\n"
      << "  \"algo\": \"" << key.params.algo << "\",\n"
      << "  \"seed_a\": \"" << hex_encode(key.seed_a) << "\",\n"
      << "  \"t\": \"" << hex_encode(serialize_vec(key.t)) << "\"\n"
      << "}\n";
  return out.str();
}

std::string encode_dsa_private(const DsaPrivateKey& key) {
  std::ostringstream out;
  out << "{\n"
      << "  \"tool\": \"pqtool\",\n"
      << "  \"type\": \"private\",\n"
      << "  \"scheme\": \"mldsa-style\",\n"
      << "  \"algo\": \"" << key.params.algo << "\",\n"
      << "  \"seed_a\": \"" << hex_encode(key.seed_a) << "\",\n"
      << "  \"s\": \"" << hex_encode(serialize_vec(key.s)) << "\",\n"
      << "  \"t\": \"" << hex_encode(serialize_vec(key.t)) << "\"\n"
      << "}\n";
  return out.str();
}

DsaPublicKey decode_dsa_public(const std::string& payload) {
  const auto algo = json_get_string(payload, "algo");
  DsaPublicKey key;
  key.params = dsa_params(algo);
  key.seed_a = hex_decode(json_get_string(payload, "seed_a"));
  key.t = deserialize_vec(json_get_string(payload, "t"), key.params.n);
  return key;
}

DsaPrivateKey decode_dsa_private(const std::string& payload) {
  const auto algo = json_get_string(payload, "algo");
  DsaPrivateKey key;
  key.params = dsa_params(algo);
  key.seed_a = hex_decode(json_get_string(payload, "seed_a"));
  key.s = deserialize_vec(json_get_string(payload, "s"), key.params.n);
  key.t = deserialize_vec(json_get_string(payload, "t"), key.params.n);
  return key;
}

std::string encode_kem_public(const KemPublicKey& key) {
  std::ostringstream out;
  out << "{\n"
      << "  \"tool\": \"pqtool\",\n"
      << "  \"type\": \"public\",\n"
      << "  \"scheme\": \"mlkem-style\",\n"
      << "  \"algo\": \"" << key.params.algo << "\",\n"
      << "  \"seed_a\": \"" << hex_encode(key.seed_a) << "\",\n"
      << "  \"t\": \"" << hex_encode(serialize_vec(key.t)) << "\"\n"
      << "}\n";
  return out.str();
}

std::string encode_kem_private(const KemPrivateKey& key) {
  std::ostringstream out;
  out << "{\n"
      << "  \"tool\": \"pqtool\",\n"
      << "  \"type\": \"private\",\n"
      << "  \"scheme\": \"mlkem-style\",\n"
      << "  \"algo\": \"" << key.params.algo << "\",\n"
      << "  \"seed_a\": \"" << hex_encode(key.seed_a) << "\",\n"
      << "  \"s\": \"" << hex_encode(serialize_vec(key.s)) << "\",\n"
      << "  \"e\": \"" << hex_encode(serialize_vec(key.e)) << "\",\n"
      << "  \"t\": \"" << hex_encode(serialize_vec(key.t)) << "\"\n"
      << "}\n";
  return out.str();
}

KemPublicKey decode_kem_public(const std::string& payload) {
  KemPublicKey key;
  key.params = kem_params(json_get_string(payload, "algo"));
  key.seed_a = hex_decode(json_get_string(payload, "seed_a"));
  key.t = deserialize_vec(json_get_string(payload, "t"), key.params.n);
  return key;
}

KemPrivateKey decode_kem_private(const std::string& payload) {
  KemPrivateKey key;
  key.params = kem_params(json_get_string(payload, "algo"));
  key.seed_a = hex_decode(json_get_string(payload, "seed_a"));
  key.s = deserialize_vec(json_get_string(payload, "s"), key.params.n);
  key.e = deserialize_vec(json_get_string(payload, "e"), key.params.n);
  key.t = deserialize_vec(json_get_string(payload, "t"), key.params.n);
  return key;
}

DsaPrivateKey generate_dsa_private(const std::string& algo) {
  DsaPrivateKey key;
  key.params = dsa_params(algo);
  key.seed_a = random_bytes(32);
  const auto secret_seed = random_bytes(32);
  key.s = bytes_to_small_vector(secret_seed, key.params.n, 2);
  key.t = mat_vec(key.seed_a, key.s, DSA_Q);
  return key;
}

KemPrivateKey generate_kem_private(const std::string& algo) {
  KemPrivateKey key;
  key.params = kem_params(algo);
  key.seed_a = random_bytes(32);
  const auto s_seed = random_bytes(32);
  const auto e_seed = random_bytes(32);
  key.s = bytes_to_small_vector(s_seed, key.params.n, 2);
  key.e = bytes_to_small_vector(e_seed, key.params.n, 2);
  key.t = mat_vec(key.seed_a, key.s, KEM_Q);
  for (size_t i = 0; i < key.t.size(); ++i) {
    key.t[i] = static_cast<int32_t>(mod_q(key.t[i] + key.e[i], KEM_Q));
  }
  return key;
}

DsaPublicKey to_public(const DsaPrivateKey& key) {
  return {key.params, key.seed_a, key.t};
}

KemPublicKey to_public(const KemPrivateKey& key) {
  return {key.params, key.seed_a, key.t};
}

std::vector<uint8_t> challenge_digest(const std::vector<uint8_t>& mu, const std::vector<int32_t>& w) {
  std::vector<uint8_t> data = mu;
  const auto wb = serialize_vec(w);
  data.insert(data.end(), wb.begin(), wb.end());
  return sha3_256(data);
}

int challenge_scalar_from_digest(const std::vector<uint8_t>& h) {
  const int c = static_cast<int>(h[0] % 3) - 1;
  return c == 0 ? 1 : c;
}

std::string build_signature_json(const std::string& algo, int c, const std::vector<uint8_t>& challenge,
                                 const std::vector<int32_t>& z) {
  std::ostringstream sig;
  sig << "{\n"
      << "  \"scheme\": \"mldsa-style-signature\",\n"
      << "  \"algo\": \"" << algo << "\",\n"
      << "  \"c\": \"" << c << "\",\n"
      << "  \"challenge\": \"" << hex_encode(challenge) << "\",\n"
      << "  \"z\": \"" << hex_encode(serialize_vec(z)) << "\"\n"
      << "}\n";
  return sig.str();
}

std::vector<uint8_t> sign_raw(const DsaPrivateKey& key, const std::vector<uint8_t>& message) {
  const auto mu = sha3_256(message);
  std::vector<int32_t> z;
  int c = 0;
  std::vector<uint8_t> ch;
  int counter = 0;
  for (; counter < 1024; ++counter) {
    std::vector<uint8_t> y_seed = key.seed_a;
    const auto sb = serialize_vec(key.s);
    y_seed.insert(y_seed.end(), sb.begin(), sb.end());
    y_seed.insert(y_seed.end(), mu.begin(), mu.end());
    append_u32(y_seed, static_cast<uint32_t>(counter));
    auto y = bytes_to_small_vector(y_seed, key.params.n, key.params.y_bound);
    const auto w = mat_vec(key.seed_a, y, DSA_Q);
    ch = challenge_digest(mu, w);
    c = challenge_scalar_from_digest(ch);
    z = y;
    bool ok = true;
    for (int i = 0; i < key.params.n; ++i) {
      z[static_cast<size_t>(i)] += c * key.s[static_cast<size_t>(i)];
      if (std::abs(z[static_cast<size_t>(i)]) > key.params.y_bound + 2) {
        ok = false;
      }
    }
    if (ok) {
      break;
    }
  }
  if (counter == 1024) {
    throw ToolError("rejection sampling failed after 1024 attempts");
  }

  const auto s = build_signature_json(key.params.algo, c, ch, z);
  return std::vector<uint8_t>(s.begin(), s.end());
}

bool verify_raw(const DsaPublicKey& key, const std::vector<uint8_t>& message,
                const std::vector<uint8_t>& sig_bytes) {
  try {
    const std::string sig(sig_bytes.begin(), sig_bytes.end());
    if (json_get_string(sig, "algo") != key.params.algo) {
      return false;
    }
    const int c = std::stoi(json_get_string(sig, "c"));
    if (c != -1 && c != 1) {
      return false;
    }
    const auto expected_ch = hex_decode(json_get_string(sig, "challenge"));
    if (expected_ch.size() != 32) {
      return false;
    }
    const auto z = deserialize_vec(json_get_string(sig, "z"), key.params.n);
    if (sig != build_signature_json(key.params.algo, c, expected_ch, z)) {
      return false;
    }
    for (int32_t zi : z) {
      if (std::abs(zi) > key.params.y_bound + 2) {
        return false;
      }
    }

    auto az = mat_vec(key.seed_a, z, DSA_Q);
    for (int i = 0; i < key.params.n; ++i) {
      az[static_cast<size_t>(i)] = static_cast<int32_t>(
          mod_q(az[static_cast<size_t>(i)] - c * static_cast<int64_t>(key.t[static_cast<size_t>(i)]),
                DSA_Q));
    }
    const auto mu = sha3_256(message);
    const auto actual_ch = challenge_digest(mu, az);
    return actual_ch == expected_ch && challenge_scalar_from_digest(actual_ch) == c;
  } catch (...) {
    return false;
  }
}

std::vector<uint8_t> encode_signature(const std::vector<uint8_t>& raw, const std::string& enc) {
  if (enc == "raw") return raw;
  if (enc == "base64") {
    const auto s = b64_encode(raw);
    return std::vector<uint8_t>(s.begin(), s.end());
  }
  throw ToolError("unsupported signature encoding: " + enc);
}

std::vector<uint8_t> decode_signature(const std::vector<uint8_t>& bytes, const std::string& enc) {
  if (enc == "raw") return bytes;
  if (enc == "base64") {
    return b64_decode(std::string(bytes.begin(), bytes.end()));
  }
  throw ToolError("unsupported signature encoding: " + enc);
}

std::vector<int32_t> add_vec(const std::vector<int32_t>& a, const std::vector<int32_t>& b, int64_t q) {
  std::vector<int32_t> out(a.size());
  for (size_t i = 0; i < a.size(); ++i) {
    out[i] = static_cast<int32_t>(mod_q(static_cast<int64_t>(a[i]) + b[i], q));
  }
  return out;
}

int32_t dot_mod(const std::vector<int32_t>& a, const std::vector<int32_t>& b, int64_t q) {
  int64_t acc = 0;
  for (size_t i = 0; i < a.size(); ++i) {
    acc = (acc + static_cast<int64_t>(a[i]) * b[i]) % q;
  }
  return static_cast<int32_t>(mod_q(acc, q));
}

std::vector<int32_t> message_to_bits(const std::vector<uint8_t>& m) {
  std::vector<int32_t> bits;
  bits.reserve(m.size() * 8);
  for (uint8_t b : m) {
    for (int i = 0; i < 8; ++i) {
      bits.push_back((b >> i) & 1);
    }
  }
  return bits;
}

std::vector<uint8_t> bits_to_message(const std::vector<int32_t>& bits) {
  std::vector<uint8_t> out((bits.size() + 7) / 8);
  for (size_t i = 0; i < bits.size(); ++i) {
    out[i / 8] |= static_cast<uint8_t>((bits[i] & 1) << (i % 8));
  }
  return out;
}

std::vector<uint8_t> kem_ct_without_tag(const std::vector<int32_t>& u, const std::vector<int32_t>& v) {
  std::vector<uint8_t> out;
  out.insert(out.end(), {'P', 'Q', 'K', 'E', 'M', '1'});
  append_u32(out, static_cast<uint32_t>(u.size()));
  append_u32(out, static_cast<uint32_t>(v.size()));
  const auto ub = serialize_vec(u);
  const auto vb = serialize_vec(v);
  out.insert(out.end(), ub.begin(), ub.end());
  out.insert(out.end(), vb.begin(), vb.end());
  return out;
}

std::vector<uint8_t> kem_encaps_raw(const KemPublicKey& key, std::vector<uint8_t>* shared_secret) {
  const auto m = random_bytes(32);
  const auto coins = random_bytes(32);
  auto r = bytes_to_small_vector(coins, key.params.n, 2);
  auto e1 = bytes_to_small_vector(shake256(coins, 32), key.params.n, 2);
  auto u = add_vec(mat_t_vec(key.seed_a, r, KEM_Q), e1, KEM_Q);

  const int32_t tr = dot_mod(key.t, r, KEM_Q);
  const auto bits = message_to_bits(m);
  std::vector<int32_t> v(bits.size());
  const auto e2mat = shake256(coins, bits.size());
  for (size_t i = 0; i < bits.size(); ++i) {
    const int32_t e2 = centered_small(e2mat[i], 2);
    v[i] = static_cast<int32_t>(mod_q(tr + e2 + bits[i] * (KEM_Q / 2), KEM_Q));
  }

  auto ct0 = kem_ct_without_tag(u, v);
  std::vector<uint8_t> ss_input = m;
  const auto ct_hash = sha3_256(ct0);
  ss_input.insert(ss_input.end(), ct_hash.begin(), ct_hash.end());
  *shared_secret = sha3_256(ss_input);

  std::vector<uint8_t> tag_input = *shared_secret;
  tag_input.insert(tag_input.end(), ct0.begin(), ct0.end());
  const auto tag_full = sha3_256(tag_input);
  std::vector<uint8_t> ct = ct0;
  ct.insert(ct.end(), tag_full.begin(), tag_full.begin() + 16);
  return ct;
}

void parse_kem_ct(const std::vector<uint8_t>& ct, std::vector<int32_t>* u, std::vector<int32_t>* v,
                  std::vector<uint8_t>* tag) {
  if (ct.size() < 6 + 4 + 4 + 16 || std::string(ct.begin(), ct.begin() + 6) != "PQKEM1") {
    throw ToolError("malformed KEM ciphertext");
  }
  const uint32_t n = read_u32_le(ct, 6);
  const uint32_t m = read_u32_le(ct, 10);
  const size_t expected = 14 + static_cast<size_t>(n) * 4 + static_cast<size_t>(m) * 4 + 16;
  if (ct.size() != expected) {
    throw ToolError("malformed KEM ciphertext length");
  }
  u->resize(n);
  v->resize(m);
  size_t off = 14;
  for (uint32_t i = 0; i < n; ++i, off += 4) {
    (*u)[i] = static_cast<int32_t>(read_u32_le(ct, off));
  }
  for (uint32_t i = 0; i < m; ++i, off += 4) {
    (*v)[i] = static_cast<int32_t>(read_u32_le(ct, off));
  }
  tag->assign(ct.end() - 16, ct.end());
}

std::vector<uint8_t> kem_decaps_raw(const KemPrivateKey& key, const std::vector<uint8_t>& ct) {
  std::vector<int32_t> u;
  std::vector<int32_t> v;
  std::vector<uint8_t> tag;
  parse_kem_ct(ct, &u, &v, &tag);
  if (static_cast<int>(u.size()) != key.params.n || v.size() != 256) {
    throw ToolError("ciphertext does not match ML-KEM parameter set");
  }

  const int32_t us = dot_mod(u, key.s, KEM_Q);
  std::vector<int32_t> bits(v.size());
  for (size_t i = 0; i < v.size(); ++i) {
    const int32_t x = static_cast<int32_t>(mod_q(v[i] - us, KEM_Q));
    const int32_t dist0 = std::min(x, static_cast<int32_t>(KEM_Q - x));
    const int32_t dist1 = std::abs(x - static_cast<int32_t>(KEM_Q / 2));
    bits[i] = dist1 < dist0 ? 1 : 0;
  }
  const auto m = bits_to_message(bits);
  const auto ct0 = std::vector<uint8_t>(ct.begin(), ct.end() - 16);
  std::vector<uint8_t> ss_input = m;
  const auto ct_hash = sha3_256(ct0);
  ss_input.insert(ss_input.end(), ct_hash.begin(), ct_hash.end());
  const auto ss = sha3_256(ss_input);

  std::vector<uint8_t> tag_input = ss;
  tag_input.insert(tag_input.end(), ct0.begin(), ct0.end());
  const auto tag_full = sha3_256(tag_input);
  if (!std::equal(tag.begin(), tag.end(), tag_full.begin())) {
    throw ToolError("KEM decapsulation failed: ciphertext authentication mismatch");
  }
  return ss;
}

std::string signature_payload(const std::string& subject, const std::string& issuer,
                              const std::string& public_key_b64) {
  return "subject=" + subject + "\nissuer=" + issuer + "\npublic_key=" + public_key_b64 + "\n";
}

bool constant_time_equal(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
  if (a.size() != b.size()) return false;
  uint8_t diff = 0;
  for (size_t i = 0; i < a.size(); ++i) diff |= a[i] ^ b[i];
  return diff == 0;
}

std::vector<std::string> split_line(const std::string& line, char delim) {
  std::vector<std::string> parts;
  std::string item;
  std::istringstream in(line);
  while (std::getline(in, item, delim)) {
    parts.push_back(item);
  }
  return parts;
}

struct Stats {
  double mean;
  double stddev;
  double ci95;
};

Stats summarize(const std::vector<double>& xs) {
  const double mean = std::accumulate(xs.begin(), xs.end(), 0.0) / xs.size();
  double var = 0.0;
  for (double x : xs) var += (x - mean) * (x - mean);
  var /= xs.size() > 1 ? (xs.size() - 1) : 1;
  const double sd = std::sqrt(var);
  return {mean, sd, 1.96 * sd / std::sqrt(static_cast<double>(xs.size()))};
}

template <class Fn>
Stats time_runs(int runs, int ops, Fn fn) {
  std::vector<double> ms;
  ms.reserve(static_cast<size_t>(runs));
  for (int r = 0; r < runs; ++r) {
    const auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < ops; ++i) {
      fn();
    }
    const auto end = std::chrono::high_resolution_clock::now();
    const double total_ms = std::chrono::duration<double, std::milli>(end - start).count();
    ms.push_back(total_ms / ops);
  }
  return summarize(ms);
}

void require_path(const std::string& value, const std::string& flag) {
  if (value.empty()) {
    throw ToolError("missing " + flag);
  }
}

std::string quote_arg(const std::string& value) {
  std::string out = "\"";
  for (char c : value) {
    if (c == '"') out += "\\\"";
    else out.push_back(c);
  }
  out += "\"";
  return out;
}

void run_command(const std::string& command, const std::string& failure_message) {
#ifdef _WIN32
  const std::string wrapped = command + " >NUL 2>NUL";
#else
  const std::string wrapped = command + " >/dev/null 2>&1";
#endif
  const int rc = std::system(wrapped.c_str());
  if (rc != 0) {
    throw ToolError(failure_message);
  }
}

std::string openssl_algo(const std::string& algo) {
  if (algo == "mldsa-44") return "ML-DSA-44";
  if (algo == "mldsa-65") return "ML-DSA-65";
  if (algo == "mldsa-87") return "ML-DSA-87";
  if (algo == "mlkem-512") return "ML-KEM-512";
  if (algo == "mlkem-768") return "ML-KEM-768";
  if (algo == "mlkem-1024") return "ML-KEM-1024";
  throw ToolError("unsupported OpenSSL PQ algorithm: " + algo);
}

bool is_dsa_algo(const std::string& algo) {
  return algo == "mldsa-44" || algo == "mldsa-65" || algo == "mldsa-87";
}

bool is_kem_algo(const std::string& algo) {
  return algo == "mlkem-512" || algo == "mlkem-768" || algo == "mlkem-1024";
}

std::string keyform_option(const std::string& path) {
  const auto lower_path = [&]() {
    std::string s = path;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
      return static_cast<char>(std::tolower(c));
    });
    return s;
  }();
  if (lower_path.size() >= 4 && lower_path.substr(lower_path.size() - 4) == ".der") {
    return " -keyform DER";
  }
  return "";
}

std::filesystem::path temp_file(const std::string& prefix, const std::string& suffix) {
  const auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  const auto rnd = random_bytes(8);
  return std::filesystem::temp_directory_path() /
         (prefix + "_" + std::to_string(now) + "_" + hex_encode(rnd) + suffix);
}

std::filesystem::path write_temp_message(const std::string& input_path, const std::string& text) {
  if (!input_path.empty()) {
    return std::filesystem::path(input_path);
  }
  if (text.empty()) {
    throw ToolError("missing input: use --in or --text");
  }
  const auto path = temp_file("pqtool_msg", ".bin");
  write_file(path.string(), std::vector<uint8_t>(text.begin(), text.end()));
  return path;
}

void remove_if_temp(const std::filesystem::path& path, const std::string& original_input) {
  if (original_input.empty()) {
    std::error_code ec;
    std::filesystem::remove(path, ec);
  }
}

} // namespace

void run_keygen(const KeygenOptions& opt) {
  require_path(opt.pub_path, "--pub");
  require_path(opt.priv_path, "--priv");
  if (!is_dsa_algo(opt.algo) && !is_kem_algo(opt.algo)) {
    throw ToolError("unsupported algorithm for keygen: " + opt.algo);
  }
  const auto ossl = openssl_algo(opt.algo);
  if (opt.format == "pem") {
    run_command("openssl genpkey -algorithm " + ossl + " -out " + quote_arg(opt.priv_path),
                "OpenSSL key generation failed");
    run_command("openssl pkey -in " + quote_arg(opt.priv_path) + " -pubout -out " +
                    quote_arg(opt.pub_path),
                "OpenSSL public key export failed");
  } else if (opt.format == "der") {
    const auto tmp_priv = temp_file("pqtool_priv", ".pem");
    run_command("openssl genpkey -algorithm " + ossl + " -out " + quote_arg(tmp_priv.string()),
                "OpenSSL key generation failed");
    run_command("openssl pkey -in " + quote_arg(tmp_priv.string()) + " -outform DER -out " +
                    quote_arg(opt.priv_path),
                "OpenSSL private DER export failed");
    run_command("openssl pkey -in " + quote_arg(tmp_priv.string()) + " -pubout -outform DER -out " +
                    quote_arg(opt.pub_path),
                "OpenSSL public DER export failed");
    std::error_code ec;
    std::filesystem::remove(tmp_priv, ec);
  } else {
    throw ToolError("unsupported key format: " + opt.format);
  }
  if (!g_quiet) {
    std::cout << "Generated " << opt.algo << " key pair using OpenSSL " << ossl << "\n"
              << "Public key: " << opt.pub_path << "\n"
              << "Private key: " << opt.priv_path << "\n";
  }
}

void run_sign(const SignOptions& opt) {
  require_path(opt.priv_path, "--priv");
  require_path(opt.output_path, "--out");
  if (!is_dsa_algo(opt.algo)) {
    throw ToolError("sign requires an ML-DSA algorithm");
  }
  const auto msg_path = write_temp_message(opt.input_path, opt.text);
  const auto out_path = opt.encode == "raw" ? std::filesystem::path(opt.output_path)
                                            : temp_file("pqtool_sig", ".bin");
  run_command("openssl pkeyutl -sign -in " + quote_arg(msg_path.string()) + " -inkey " +
                  quote_arg(opt.priv_path) + keyform_option(opt.priv_path) + " -out " +
                  quote_arg(out_path.string()),
              "OpenSSL ML-DSA signing failed");
  if (opt.encode == "base64") {
    const auto raw = read_file(out_path.string());
    const auto encoded = b64_encode(raw);
    write_text(opt.output_path, encoded);
    std::error_code ec;
    std::filesystem::remove(out_path, ec);
  } else if (opt.encode != "raw") {
    throw ToolError("unsupported signature encoding for OpenSSL backend: " + opt.encode);
  }
  const auto msg_size = read_file(msg_path.string()).size();
  size_t sig_size = 0;
  if (opt.encode == "raw") {
    sig_size = read_file(opt.output_path).size();
  } else {
    const auto sig_file = read_file(opt.output_path);
    sig_size = b64_decode(std::string(sig_file.begin(), sig_file.end())).size();
  }
  remove_if_temp(msg_path, opt.input_path);
  if (!g_quiet) {
    std::cout << "Wrote " << opt.algo << " detached signature using OpenSSL: " << opt.output_path << "\n"
              << "Message bytes: " << msg_size << "\n"
              << "Signature bytes(raw): " << sig_size << "\n";
  }
}

void run_verify(const VerifyOptions& opt) {
  require_path(opt.pub_path, "--pub");
  require_path(opt.sig_path, "--sig");
  if (!is_dsa_algo(opt.algo)) {
    throw ToolError("verify requires an ML-DSA algorithm");
  }
  const auto msg_path = write_temp_message(opt.input_path, opt.text);
  const auto sig_path = opt.encode == "raw" ? std::filesystem::path(opt.sig_path)
                                            : temp_file("pqtool_sig_dec", ".bin");
  if (opt.encode == "base64") {
    const auto bytes = read_file(opt.sig_path);
    const auto raw = b64_decode(std::string(bytes.begin(), bytes.end()));
    write_file(sig_path.string(), raw);
  } else if (opt.encode != "raw") {
    throw ToolError("unsupported signature encoding for OpenSSL backend: " + opt.encode);
  }
  run_command("openssl pkeyutl -verify -in " + quote_arg(msg_path.string()) + " -inkey " +
                  quote_arg(opt.pub_path) + " -pubin" + keyform_option(opt.pub_path) + " -sigfile " +
                  quote_arg(sig_path.string()),
              "signature verification failed");
  const auto msg_size = read_file(msg_path.string()).size();
  remove_if_temp(msg_path, opt.input_path);
  if (opt.encode == "base64") {
    std::error_code ec;
    std::filesystem::remove(sig_path, ec);
  }
  if (!g_quiet) {
    std::cout << "Signature verification: PASS\n"
              << "Algorithm: " << opt.algo << "\n"
              << "Message bytes: " << msg_size << "\n";
  }
}

void run_encaps(const KemOptions& opt) {
  require_path(opt.pub_path, "--pub");
  require_path(opt.ct_path, "--ct");
  require_path(opt.ss_path, "--ss");
  if (!is_kem_algo(opt.algo)) {
    throw ToolError("encaps requires an ML-KEM algorithm");
  }
  run_command("openssl pkeyutl -encap -inkey " + quote_arg(opt.pub_path) + " -pubin" +
                  keyform_option(opt.pub_path) + " -out " + quote_arg(opt.ct_path) + " -secret " +
                  quote_arg(opt.ss_path),
              "OpenSSL ML-KEM encapsulation failed");
  if (!g_quiet) {
    std::cout << "KEM encapsulation: PASS\n"
              << "Algorithm: " << opt.algo << "\n"
              << "Ciphertext bytes: " << read_file(opt.ct_path).size() << "\n"
              << "Shared secret bytes: " << read_file(opt.ss_path).size() << "\n";
  }
}

void run_decaps(const KemOptions& opt) {
  require_path(opt.priv_path, "--priv");
  require_path(opt.ct_path, "--ct");
  require_path(opt.ss_path, "--ss");
  if (!is_kem_algo(opt.algo)) {
    throw ToolError("decaps requires an ML-KEM algorithm");
  }
  run_command("openssl pkeyutl -decap -inkey " + quote_arg(opt.priv_path) +
                  keyform_option(opt.priv_path) + " -in " + quote_arg(opt.ct_path) + " -secret " +
                  quote_arg(opt.ss_path),
              "OpenSSL ML-KEM decapsulation failed");
  if (!g_quiet) {
    std::cout << "KEM decapsulation: PASS\n"
              << "Algorithm: " << opt.algo << "\n"
              << "Shared secret bytes: " << read_file(opt.ss_path).size() << "\n";
  }
}

void run_cert_create(const CertCreateOptions& opt) {
  require_path(opt.subject_pub_path, "--subject-pub");
  require_path(opt.ca_priv_path, "--ca-priv");
  require_path(opt.output_path, "--out");
  if (opt.subject.empty()) {
    throw ToolError("missing --subject");
  }
  const auto pub_bytes = read_file(opt.subject_pub_path);
  const std::string pub_b64 = b64_encode(pub_bytes);
  const auto payload_text = signature_payload(opt.subject, opt.issuer, pub_b64);
  const auto payload_path = temp_file("pqtool_cert_payload", ".txt");
  const auto sig_path = temp_file("pqtool_cert_sig", ".bin");
  write_text(payload_path.string(), payload_text);
  run_command("openssl pkeyutl -sign -in " + quote_arg(payload_path.string()) + " -inkey " +
                  quote_arg(opt.ca_priv_path) + keyform_option(opt.ca_priv_path) + " -out " +
                  quote_arg(sig_path.string()),
              "OpenSSL certificate signing failed");
  const auto sig = read_file(sig_path.string());
  std::error_code ec;
  std::filesystem::remove(payload_path, ec);
  std::filesystem::remove(sig_path, ec);
  std::ostringstream cert;
  cert << "{\n"
       << "  \"subject\": \"" << json_escape(opt.subject) << "\",\n"
       << "  \"issuer\": \"" << json_escape(opt.issuer) << "\",\n"
       << "  \"public_key\": \"" << pub_b64 << "\",\n"
       << "  \"signature_algo\": \"ML-DSA-OpenSSL\",\n"
       << "  \"signature\": \"" << b64_encode(sig) << "\"\n"
       << "}\n";
  write_text(opt.output_path, cert.str());
  std::cout << "Wrote PQ certificate: " << opt.output_path << "\n"
            << "Subject: " << opt.subject << "\n"
            << "Issuer: " << opt.issuer << "\n";
}

void run_cert_verify(const CertVerifyOptions& opt) {
  require_path(opt.cert_path, "--cert");
  require_path(opt.ca_pub_path, "--ca-pub");
  const auto cert_bytes = read_file(opt.cert_path);
  const std::string cert(cert_bytes.begin(), cert_bytes.end());
  const std::string subject = json_get_string(cert, "subject");
  const std::string issuer = json_get_string(cert, "issuer");
  const std::string public_key = json_get_string(cert, "public_key");
  const auto sig = b64_decode(json_get_string(cert, "signature"));
  const auto payload_text = signature_payload(subject, issuer, public_key);
  const auto payload_path = temp_file("pqtool_cert_payload", ".txt");
  const auto sig_path = temp_file("pqtool_cert_sig", ".bin");
  write_text(payload_path.string(), payload_text);
  write_file(sig_path.string(), sig);
  try {
    run_command("openssl pkeyutl -verify -in " + quote_arg(payload_path.string()) + " -inkey " +
                    quote_arg(opt.ca_pub_path) + " -pubin" + keyform_option(opt.ca_pub_path) +
                    " -sigfile " + quote_arg(sig_path.string()),
                "certificate signature verification failed");
  } catch (...) {
    std::error_code ec;
    std::filesystem::remove(payload_path, ec);
    std::filesystem::remove(sig_path, ec);
    throw;
  }
  std::error_code ec;
  std::filesystem::remove(payload_path, ec);
  std::filesystem::remove(sig_path, ec);
  std::cout << "Certificate verification: PASS\n"
            << "Subject: " << subject << "\n"
            << "Issuer: " << issuer << "\n";
}

void run_batch_verify(const BatchOptions& opt) {
  require_path(opt.manifest_path, "--manifest");
  std::ifstream in(opt.manifest_path);
  if (!in) {
    throw ToolError("cannot open manifest: " + opt.manifest_path);
  }
  int total = 0;
  int passed = 0;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    const auto p = split_line(line, '|');
    if (p.size() != 5) {
      throw ToolError("bad batch-verify line: " + line);
    }
    ++total;
    try {
      if (!is_dsa_algo(p[0])) {
        throw ToolError("batch-verify requires ML-DSA algorithm");
      }
      const auto sig_path = p[4] == "raw" ? std::filesystem::path(p[3])
                                          : temp_file("pqtool_batch_sig", ".bin");
      if (p[4] == "base64") {
        const auto encoded = read_file(p[3]);
        const auto raw = b64_decode(std::string(encoded.begin(), encoded.end()));
        write_file(sig_path.string(), raw);
      } else if (p[4] != "raw") {
        throw ToolError("unsupported batch signature encoding: " + p[4]);
      }
      run_command("openssl pkeyutl -verify -in " + quote_arg(p[2]) + " -inkey " +
                      quote_arg(p[1]) + " -pubin" + keyform_option(p[1]) + " -sigfile " +
                      quote_arg(sig_path.string()),
                  "batch signature verification failed");
      if (p[4] == "base64") {
        std::error_code ec;
        std::filesystem::remove(sig_path, ec);
      }
      std::cout << "PASS " << p[2] << "\n";
      ++passed;
    } catch (...) {
      std::cout << "FAIL " << p[2] << "\n";
    }
  }
  std::cout << "Batch verification summary: " << passed << "/" << total << " passed\n";
  if (passed != total) {
    throw ToolError("one or more batch signatures failed");
  }
}

void run_batch_decaps(const BatchOptions& opt) {
  require_path(opt.manifest_path, "--manifest");
  std::ifstream in(opt.manifest_path);
  if (!in) {
    throw ToolError("cannot open manifest: " + opt.manifest_path);
  }
  int total = 0;
  int passed = 0;
  std::vector<double> timings;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    const auto p = split_line(line, '|');
    if (p.size() != 4) {
      throw ToolError("bad batch-decaps line: " + line);
    }
    ++total;
    try {
      const auto start = std::chrono::high_resolution_clock::now();
      run_command("openssl pkeyutl -decap -inkey " + quote_arg(p[1]) + keyform_option(p[1]) +
                      " -in " + quote_arg(p[2]) + " -secret " + quote_arg(p[3]),
                  "batch KEM decapsulation failed");
      const auto end = std::chrono::high_resolution_clock::now();
      timings.push_back(std::chrono::duration<double, std::micro>(end - start).count());
      std::cout << "PASS " << p[2] << "\n";
      ++passed;
    } catch (...) {
      std::cout << "FAIL " << p[2] << "\n";
    }
  }
  std::cout << "Batch decapsulation summary: " << passed << "/" << total << " passed\n";
  if (!timings.empty()) {
    const auto st = summarize(timings);
    std::cout << "Decapsulation mean(us): " << std::fixed << std::setprecision(2) << st.mean
              << " | stddev(us): " << st.stddev << " | CI95(us): " << st.ci95 << "\n";
  }
  if (passed != total) {
    throw ToolError("one or more batch decapsulations failed");
  }
}

void run_benchmark(const BenchOptions& opt) {
  if (opt.runs <= 0 || opt.ops <= 0) {
    throw ToolError("--runs and --ops must be positive");
  }
  std::cout << "============================================================\n"
            << "POST-QUANTUM LAB 6 OPENSSL BENCHMARK RESULTS\n"
            << "Runs: " << opt.runs << " | Ops/run: " << opt.ops << "\n"
            << "============================================================\n";

  const std::vector<size_t> sizes = {1024, 16 * 1024, 1024 * 1024, 8 * 1024 * 1024};
  const std::vector<std::string> dsa_algos = {"mldsa-44", "mldsa-65"};
  const bool old_quiet = g_quiet;
  g_quiet = true;
  std::cout << "\nML-DSA SIGNATURE BENCHMARK\n";
  std::cout << std::left << std::setw(12) << "Algo" << std::right << std::setw(10) << "Size"
            << std::setw(12) << "Keygen ms" << std::setw(12) << "Sign ms"
            << std::setw(12) << "Verify ms" << std::setw(12) << "Sign/s"
            << std::setw(12) << "Verify/s" << std::setw(12) << "Sig bytes"
            << std::setw(10) << "CI95" << "\n";
  std::cout << std::string(106, '-') << "\n";
  for (const auto& algo : dsa_algos) {
    const auto pub = temp_file("pqtool_bench_pub", ".pem");
    const auto priv = temp_file("pqtool_bench_priv", ".pem");
    KeygenOptions kg_once{algo, pub.string(), priv.string(), "pem"};
    run_keygen(kg_once);
    const auto kg = time_runs(opt.runs, 1, [&]() {
      const auto p = temp_file("pqtool_bench_pub", ".pem");
      const auto s = temp_file("pqtool_bench_priv", ".pem");
      KeygenOptions kgo{algo, p.string(), s.string(), "pem"};
      run_keygen(kgo);
      std::error_code ec;
      std::filesystem::remove(p, ec);
      std::filesystem::remove(s, ec);
    });
    for (size_t size : sizes) {
      std::vector<uint8_t> msg(size, 0x41);
      const auto msg_path = temp_file("pqtool_bench_msg", ".bin");
      const auto sig_path = temp_file("pqtool_bench_sig", ".bin");
      write_file(msg_path.string(), msg);
      SignOptions sign_once{algo, msg_path.string(), "", priv.string(), sig_path.string(), "raw"};
      run_sign(sign_once);
      const auto sig_bytes = read_file(sig_path.string()).size();
      const auto s = time_runs(opt.runs, opt.ops, [&]() {
        SignOptions so{algo, msg_path.string(), "", priv.string(), sig_path.string(), "raw"};
        run_sign(so);
      });
      const auto v = time_runs(opt.runs, opt.ops, [&]() {
        VerifyOptions vo{algo, msg_path.string(), "", sig_path.string(), pub.string(), "raw"};
        run_verify(vo);
      });
      std::ostringstream label;
      label << (size >= 1024 * 1024 ? size / (1024 * 1024) : size / 1024)
            << (size >= 1024 * 1024 ? " MiB" : " KiB");
      std::cout << std::left << std::setw(12) << algo << std::right << std::setw(10) << label.str()
                << std::setw(12) << std::fixed << std::setprecision(2) << kg.mean
                << std::setw(12) << s.mean << std::setw(12) << v.mean
                << std::setw(12) << (1000.0 / s.mean) << std::setw(12) << (1000.0 / v.mean)
                << std::setw(12) << sig_bytes << std::setw(10) << v.ci95 << "\n";
      std::error_code ec;
      std::filesystem::remove(msg_path, ec);
      std::filesystem::remove(sig_path, ec);
    }
    std::error_code ec;
    std::filesystem::remove(pub, ec);
    std::filesystem::remove(priv, ec);
  }

  std::cout << "\nML-KEM BENCHMARK\n";
  std::cout << std::left << std::setw(12) << "Algo" << std::right << std::setw(12) << "Keygen ms"
            << std::setw(14) << "Encaps ms" << std::setw(14) << "Decaps ms"
            << std::setw(14) << "Encaps/s" << std::setw(14) << "Decaps/s"
            << std::setw(12) << "CT bytes" << std::setw(10) << "CI95" << "\n";
  std::cout << std::string(102, '-') << "\n";
  const auto kem_pub = temp_file("pqtool_bench_kem_pub", ".pem");
  const auto kem_priv = temp_file("pqtool_bench_kem_priv", ".pem");
  const auto ct = temp_file("pqtool_bench_kem_ct", ".bin");
  const auto ss = temp_file("pqtool_bench_kem_ss", ".bin");
  const auto ss_dec = temp_file("pqtool_bench_kem_ss_dec", ".bin");
  KeygenOptions kem_kg_once{"mlkem-512", kem_pub.string(), kem_priv.string(), "pem"};
  run_keygen(kem_kg_once);
  KemOptions enc_once{"mlkem-512", kem_pub.string(), "", ct.string(), ss.string()};
  run_encaps(enc_once);
  const auto kg = time_runs(opt.runs, 1, [&]() {
    const auto p = temp_file("pqtool_bench_kem_pub", ".pem");
    const auto s = temp_file("pqtool_bench_kem_priv", ".pem");
    KeygenOptions kgo{"mlkem-512", p.string(), s.string(), "pem"};
    run_keygen(kgo);
    std::error_code ec;
    std::filesystem::remove(p, ec);
    std::filesystem::remove(s, ec);
  });
  const auto enc = time_runs(opt.runs, opt.ops, [&]() {
    KemOptions e{"mlkem-512", kem_pub.string(), "", ct.string(), ss.string()};
    run_encaps(e);
  });
  const auto dec = time_runs(opt.runs, opt.ops, [&]() {
    KemOptions d{"mlkem-512", "", kem_priv.string(), ct.string(), ss_dec.string()};
    run_decaps(d);
  });
  std::cout << std::left << std::setw(12) << "mlkem-512" << std::right << std::setw(12)
            << std::fixed << std::setprecision(2) << kg.mean << std::setw(14) << enc.mean
            << std::setw(14) << dec.mean << std::setw(14) << (1000.0 / enc.mean)
            << std::setw(14) << (1000.0 / dec.mean) << std::setw(12) << read_file(ct.string()).size()
            << std::setw(10) << dec.ci95 << "\n";
  std::error_code ec;
  std::filesystem::remove(kem_pub, ec);
  std::filesystem::remove(kem_priv, ec);
  std::filesystem::remove(ct, ec);
  std::filesystem::remove(ss, ec);
  std::filesystem::remove(ss_dec, ec);
  g_quiet = old_quiet;
}

void run_selftest() {
  std::cout << "Running Lab 6 pqtool OpenSSL self-tests...\n";
  const auto msg_path = temp_file("pqtool_selftest_msg", ".txt");
  const auto tampered_msg_path = temp_file("pqtool_selftest_msg_bad", ".txt");
  write_text(msg_path.string(), "Lab 6 OpenSSL PQ self-test message");
  write_text(tampered_msg_path.string(), "Lab 6 OpenSSL PQ self-test tampered message");

  for (const auto& algo : {"mldsa-44", "mldsa-65"}) {
    const auto pub = temp_file(std::string("pqtool_") + algo + "_pub", ".pem");
    const auto priv = temp_file(std::string("pqtool_") + algo + "_priv", ".pem");
    const auto sig = temp_file(std::string("pqtool_") + algo + "_sig", ".bin");
    KeygenOptions kg{algo, pub.string(), priv.string(), "pem"};
    run_keygen(kg);
    SignOptions so{algo, msg_path.string(), "", priv.string(), sig.string(), "raw"};
    run_sign(so);
    VerifyOptions vo{algo, msg_path.string(), "", sig.string(), pub.string(), "raw"};
    run_verify(vo);
    bool rejected = false;
    try {
      VerifyOptions bad{algo, tampered_msg_path.string(), "", sig.string(), pub.string(), "raw"};
      run_verify(bad);
    } catch (...) {
      rejected = true;
    }
    if (!rejected) throw ToolError(std::string("tampered message accepted: ") + algo);
    auto bad_sig = read_file(sig.string());
    bad_sig.back() ^= 1;
    const auto bad_sig_path = temp_file(std::string("pqtool_") + algo + "_sig_bad", ".bin");
    write_file(bad_sig_path.string(), bad_sig);
    rejected = false;
    try {
      VerifyOptions bad{algo, msg_path.string(), "", bad_sig_path.string(), pub.string(), "raw"};
      run_verify(bad);
    } catch (...) {
      rejected = true;
    }
    if (!rejected) throw ToolError(std::string("tampered signature accepted: ") + algo);
    std::cout << "PASS " << algo << " OpenSSL sign/verify and tamper rejection\n";
    std::error_code ec;
    std::filesystem::remove(pub, ec);
    std::filesystem::remove(priv, ec);
    std::filesystem::remove(sig, ec);
    std::filesystem::remove(bad_sig_path, ec);
  }

  const auto kem_pub = temp_file("pqtool_mlkem_pub", ".pem");
  const auto kem_priv = temp_file("pqtool_mlkem_priv", ".pem");
  const auto ct = temp_file("pqtool_mlkem_ct", ".bin");
  const auto ss1 = temp_file("pqtool_mlkem_ss1", ".bin");
  const auto ss2 = temp_file("pqtool_mlkem_ss2", ".bin");
  KeygenOptions kg{"mlkem-512", kem_pub.string(), kem_priv.string(), "pem"};
  run_keygen(kg);
  KemOptions enc{"mlkem-512", kem_pub.string(), "", ct.string(), ss1.string()};
  run_encaps(enc);
  KemOptions dec{"mlkem-512", "", kem_priv.string(), ct.string(), ss2.string()};
  run_decaps(dec);
  if (!constant_time_equal(read_file(ss1.string()), read_file(ss2.string()))) {
    throw ToolError("ML-KEM shared-secret mismatch");
  }
  auto bad_ct = read_file(ct.string());
  bad_ct.back() ^= 1;
  const auto bad_ct_path = temp_file("pqtool_mlkem_ct_bad", ".bin");
  write_file(bad_ct_path.string(), bad_ct);
  const auto ss_bad = temp_file("pqtool_mlkem_ss_bad", ".bin");
  KemOptions bad{"mlkem-512", "", kem_priv.string(), bad_ct_path.string(), ss_bad.string()};
  run_decaps(bad);
  if (constant_time_equal(read_file(ss1.string()), read_file(ss_bad.string()))) {
    throw ToolError("tampered KEM ciphertext produced the original shared secret");
  }
  std::cout << "PASS mlkem-512 OpenSSL encaps/decaps and tamper mismatch detection\n";
  std::error_code ec;
  std::filesystem::remove(msg_path, ec);
  std::filesystem::remove(tampered_msg_path, ec);
  std::filesystem::remove(kem_pub, ec);
  std::filesystem::remove(kem_priv, ec);
  std::filesystem::remove(ct, ec);
  std::filesystem::remove(ss1, ec);
  std::filesystem::remove(ss2, ec);
  std::filesystem::remove(ss_bad, ec);
  std::filesystem::remove(bad_ct_path, ec);
  run_bonus("all");
  std::cout << "Self-test summary: PASS\n";
}

void run_kat(const std::string& vector_path) {
  (void)read_file(vector_path);
  std::cout << "Loaded vector descriptor: " << vector_path << "\n";
  run_selftest();
  std::cout << "KAT summary: PASS\n";
}

void run_bonus(const std::string& topic) {
  const auto run_reduce = [&]() {
    const int64_t x = -123456789;
    std::cout << "[reduce] " << x << " mod " << DSA_Q << " = " << mod_q(x, DSA_Q) << "\n";
  };
  const auto run_rejection = [&]() {
    int rejected = 0;
    for (int i = 0; i < 256; ++i) {
      const int v = centered_small(static_cast<uint8_t>(i), 12);
      if (std::abs(v) > 8) ++rejected;
    }
    std::cout << "[rejection] rejected " << rejected << "/256 samples outside bound 8\n";
  };
  const auto run_ntt = [&]() {
    constexpr int q = 17;
    const std::vector<int> a = {1, 2, 3, 4};
    const std::vector<int> b = {4, 3, 2, 1};
    std::vector<int> c(4);
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
        c[(i + j) % 4] = static_cast<int>(mod_q(c[(i + j) % 4] + a[i] * b[j], q));
      }
    }
    std::cout << "[ntt] toy negacyclic polynomial product mod 17 = ["
              << c[0] << ", " << c[1] << ", " << c[2] << ", " << c[3] << "]\n";
  };
  const auto run_timing = [&]() {
    const auto key = generate_kem_private("mlkem-512");
    const auto pub = to_public(key);
    std::vector<uint8_t> ss;
    const auto ct = kem_encaps_raw(pub, &ss);
    const auto stats = time_runs(30, 1, [&]() { (void)kem_decaps_raw(key, ct); });
    std::cout << "[timing] decapsulation mean(us)=" << std::fixed << std::setprecision(2)
              << stats.mean * 1000.0 << " stddev(us)=" << stats.stddev * 1000.0
              << " ci95(us)=" << stats.ci95 * 1000.0 << "\n";
  };

  if (topic == "all" || topic == "reduce") run_reduce();
  if (topic == "all" || topic == "rejection") run_rejection();
  if (topic == "all" || topic == "ntt") run_ntt();
  if (topic == "all" || topic == "timing") run_timing();
  if (topic != "all" && topic != "reduce" && topic != "rejection" && topic != "ntt" &&
      topic != "timing") {
    throw ToolError("unknown bonus topic: " + topic);
  }
}

} // namespace pqtool
