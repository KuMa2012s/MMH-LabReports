#include "rsatool.hpp"

#include <cryptopp/aes.h>
#include <cryptopp/algparam.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hex.h>
#include <cryptopp/integer.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/queue.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <regex>
#include <sstream>

namespace rsatool {
namespace {

constexpr const char* kMagic = "RSATOOL3\n";
constexpr std::size_t kMagicLen = 9;
constexpr std::size_t kGcmIvLen = 12;
constexpr std::size_t kGcmTagLen = 16;
constexpr std::size_t kAes256KeyLen = 32;

using Clock = std::chrono::high_resolution_clock;
using RsaOaepSha256Encryptor = CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256>>::Encryptor;
using RsaOaepSha256Decryptor = CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256>>::Decryptor;

std::string now_utc_iso8601() {
  std::time_t t = std::time(nullptr);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif
  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
  return oss.str();
}

std::string json_escape(const std::string& input) {
  std::ostringstream oss;
  for (char c : input) {
    switch (c) {
    case '\\': oss << "\\\\"; break;
    case '"': oss << "\\\""; break;
    case '\n': oss << "\\n"; break;
    case '\r': oss << "\\r"; break;
    case '\t': oss << "\\t"; break;
    default:
      if (static_cast<unsigned char>(c) < 0x20) {
        oss << "\\u" << std::hex << std::setw(4) << std::setfill('0')
            << static_cast<int>(static_cast<unsigned char>(c));
      } else {
        oss << c;
      }
    }
  }
  return oss.str();
}

std::string json_get_string(const std::string& json, const std::string& key, bool required = true) {
  const std::regex pattern("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
  std::smatch match;
  if (std::regex_search(json, match, pattern)) {
    return match[1].str();
  }
  if (required) {
    throw ToolError("malformed envelope header");
  }
  return {};
}

void validate_json_shape(const std::string& json) {
  const auto first = json.find_first_not_of(" \t\r\n");
  const auto last = json.find_last_not_of(" \t\r\n");
  if (first == std::string::npos || json[first] != '{' || json[last] != '}') {
    throw ToolError("malformed envelope header");
  }
}

int json_get_int(const std::string& json, const std::string& key, bool required = true) {
  const std::regex pattern("\"" + key + "\"\\s*:\\s*([0-9]+)");
  std::smatch match;
  if (std::regex_search(json, match, pattern)) {
    return std::stoi(match[1].str());
  }
  if (required) {
    throw ToolError("malformed envelope header");
  }
  return 0;
}

Bytes random_bytes(std::size_t n) {
  CryptoPP::AutoSeededRandomPool rng;
  Bytes out(n);
  rng.GenerateBlock(out.data(), out.size());
  return out;
}

Bytes queue_to_bytes(CryptoPP::ByteQueue& queue) {
  std::string out;
  CryptoPP::StringSink sink(out);
  queue.CopyTo(sink);
  sink.MessageEnd();
  return string_to_bytes(out);
}

template <typename Key>
Bytes save_key_der(const Key& key) {
  CryptoPP::ByteQueue queue;
  const_cast<Key&>(key).Save(queue);
  return queue_to_bytes(queue);
}

template <typename Key>
void load_key_der(Key& key, const Bytes& der) {
  CryptoPP::ByteQueue queue;
  queue.Put(der.data(), der.size());
  queue.MessageEnd();
  key.Load(queue);
}

std::string wrap_pem(const std::string& type, const Bytes& der) {
  const std::string b64 = base64_encode(der);
  std::ostringstream oss;
  oss << "-----BEGIN " << type << "-----\n";
  for (std::size_t i = 0; i < b64.size(); i += 64) {
    oss << b64.substr(i, 64) << "\n";
  }
  oss << "-----END " << type << "-----\n";
  return oss.str();
}

Bytes unwrap_pem(const std::string& text) {
  std::istringstream iss(text);
  std::string line;
  std::string b64;
  bool inside = false;
  while (std::getline(iss, line)) {
    if (line.rfind("-----BEGIN ", 0) == 0) {
      inside = true;
      continue;
    }
    if (line.rfind("-----END ", 0) == 0) {
      break;
    }
    if (inside) {
      b64 += line;
    }
  }
  if (b64.empty()) {
    throw ToolError("invalid PEM key");
  }
  return base64_decode(b64);
}

Bytes read_key_bytes(const std::string& path) {
  Bytes data = read_file(path);
  const std::string text = bytes_to_string(data);
  if (text.rfind("-----BEGIN ", 0) == 0) {
    return unwrap_pem(text);
  }
  return data;
}

CryptoPP::RSA::PublicKey load_public_key(const std::string& path) {
  CryptoPP::RSA::PublicKey key;
  load_key_der(key, read_key_bytes(path));
  CryptoPP::AutoSeededRandomPool rng;
  if (!key.Validate(rng, 3)) {
    throw ToolError("invalid public key");
  }
  return key;
}

CryptoPP::RSA::PrivateKey load_private_key(const std::string& path) {
  CryptoPP::RSA::PrivateKey key;
  load_key_der(key, read_key_bytes(path));
  CryptoPP::AutoSeededRandomPool rng;
  if (!key.Validate(rng, 3)) {
    throw ToolError("invalid private key");
  }
  return key;
}

CryptoPP::AlgorithmParameters label_params(const Bytes& label) {
  return CryptoPP::MakeParameters(
      CryptoPP::Name::EncodingParameters(),
      CryptoPP::ConstByteArrayParameter(label.data(), label.size()));
}

Bytes rsa_encrypt_oaep(const CryptoPP::RSA::PublicKey& public_key, const Bytes& plain, const Bytes& label) {
  CryptoPP::AutoSeededRandomPool rng;
  RsaOaepSha256Encryptor encryptor(public_key);
  if (plain.size() > encryptor.FixedMaxPlaintextLength()) {
    throw ToolError("plaintext exceeds RSA-OAEP limit");
  }
  Bytes cipher(encryptor.CiphertextLength(plain.size()));
  if (label.empty()) {
    encryptor.Encrypt(rng, plain.data(), plain.size(), cipher.data());
  } else {
    const auto params = label_params(label);
    encryptor.Encrypt(rng, plain.data(), plain.size(), cipher.data(), params);
  }
  return cipher;
}

Bytes rsa_decrypt_oaep(const CryptoPP::RSA::PrivateKey& private_key, const Bytes& cipher, const Bytes& label) {
  CryptoPP::AutoSeededRandomPool rng;
  RsaOaepSha256Decryptor decryptor(private_key);
  Bytes recovered(decryptor.MaxPlaintextLength(cipher.size()));
  CryptoPP::DecodingResult result;
  if (label.empty()) {
    result = decryptor.Decrypt(rng, cipher.data(), cipher.size(), recovered.data());
  } else {
    const auto params = label_params(label);
    result = decryptor.Decrypt(rng, cipher.data(), cipher.size(), recovered.data(), params);
  }
  if (!result.isValidCoding) {
    throw ToolError("cryptographic operation failed");
  }
  recovered.resize(result.messageLength);
  return recovered;
}

std::string hybrid_aad(int rsa_bits, const std::string& label) {
  return "RSATOOL3|RSA-OAEP-AES-GCM|" + std::to_string(rsa_bits) + "|SHA-256|" + label;
}

std::string tag_placeholder_b64() {
  return base64_encode(Bytes(kGcmTagLen, 0x00));
}

std::string replace_json_tag_value(const std::string& json, const std::string& replacement) {
  const std::regex pattern("(\"tag\"\\s*:\\s*\")([^\"]*)(\")");
  std::smatch match;
  if (!std::regex_search(json, match, pattern)) {
    throw ToolError("malformed envelope header");
  }
  return match.prefix().str() + match[1].str() + replacement + match[3].str() + match.suffix().str();
}

Bytes hybrid_aad_from_header(const std::string& header_json, const std::string& label) {
  return string_to_bytes(replace_json_tag_value(header_json, tag_placeholder_b64()) + "\nlabel:" + label);
}

struct GcmResult {
  Bytes cipher;
  Bytes tag;
};

GcmResult aes_gcm_encrypt(const Bytes& key, const Bytes& iv, const Bytes& plain, const Bytes& aad) {
  CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
  enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
  std::string out;
  CryptoPP::AuthenticatedEncryptionFilter filter(
      enc, new CryptoPP::StringSink(out), false, kGcmTagLen);
  if (!aad.empty()) {
    filter.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
  }
  filter.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
  if (!plain.empty()) {
    filter.ChannelPut(CryptoPP::DEFAULT_CHANNEL, plain.data(), plain.size());
  }
  filter.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
  Bytes combined = string_to_bytes(out);
  if (combined.size() < kGcmTagLen) {
    throw ToolError("AES-GCM output is invalid");
  }
  GcmResult result;
  result.cipher.assign(combined.begin(), combined.end() - static_cast<std::ptrdiff_t>(kGcmTagLen));
  result.tag.assign(combined.end() - static_cast<std::ptrdiff_t>(kGcmTagLen), combined.end());
  return result;
}

Bytes aes_gcm_decrypt(const Bytes& key, const Bytes& iv, const Bytes& cipher, const Bytes& tag, const Bytes& aad) {
  CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
  dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
  Bytes combined = cipher;
  combined.insert(combined.end(), tag.begin(), tag.end());
  std::string recovered;
  try {
    CryptoPP::AuthenticatedDecryptionFilter filter(
        dec,
        new CryptoPP::StringSink(recovered),
        CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
        kGcmTagLen);
    if (!aad.empty()) {
      filter.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
    }
    filter.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
    if (!combined.empty()) {
      filter.ChannelPut(CryptoPP::DEFAULT_CHANNEL, combined.data(), combined.size());
    }
    filter.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
  } catch (const CryptoPP::Exception&) {
    throw ToolError("cryptographic operation failed");
  }
  return string_to_bytes(recovered);
}

Bytes make_container(const std::string& header_json, const Bytes& payload) {
  if (header_json.size() > 0xffffffffULL) {
    throw ToolError("envelope header too large");
  }
  Bytes out;
  out.insert(out.end(), kMagic, kMagic + kMagicLen);
  const auto n = static_cast<std::uint32_t>(header_json.size());
  out.push_back(static_cast<unsigned char>((n >> 24) & 0xff));
  out.push_back(static_cast<unsigned char>((n >> 16) & 0xff));
  out.push_back(static_cast<unsigned char>((n >> 8) & 0xff));
  out.push_back(static_cast<unsigned char>(n & 0xff));
  out.insert(out.end(), header_json.begin(), header_json.end());
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

struct ParsedContainer {
  std::string header_json;
  Bytes payload;
};

bool has_magic(const Bytes& data) {
  return data.size() >= kMagicLen && std::equal(kMagic, kMagic + kMagicLen, data.begin());
}

ParsedContainer parse_container(const Bytes& data) {
  if (!has_magic(data) || data.size() < kMagicLen + 4) {
    throw ToolError("unsupported or malformed ciphertext encoding");
  }
  std::size_t off = kMagicLen;
  const std::uint32_t header_len =
      (static_cast<std::uint32_t>(data[off]) << 24) |
      (static_cast<std::uint32_t>(data[off + 1]) << 16) |
      (static_cast<std::uint32_t>(data[off + 2]) << 8) |
      static_cast<std::uint32_t>(data[off + 3]);
  off += 4;
  if (header_len == 0 || off + header_len > data.size()) {
    throw ToolError("malformed envelope header");
  }
  ParsedContainer parsed;
  parsed.header_json.assign(reinterpret_cast<const char*>(data.data() + off), header_len);
  off += header_len;
  parsed.payload.assign(data.begin() + static_cast<std::ptrdiff_t>(off), data.end());
  return parsed;
}

bool is_probably_hex_text(const Bytes& data) {
  std::size_t count = 0;
  for (unsigned char c : data) {
    if (std::isspace(c)) {
      continue;
    }
    if (!std::isxdigit(c)) {
      return false;
    }
    ++count;
  }
  return count > 0 && count % 2 == 0;
}

Bytes decode_ciphertext_input(const Bytes& input, const std::string& format) {
  if (format == "raw") {
    return input;
  }
  if (format == "hex") {
    return hex_decode(bytes_to_string(input));
  }
  if (format == "base64") {
    return base64_decode(bytes_to_string(input));
  }
  if (format != "auto") {
    throw ToolError("unsupported ciphertext format");
  }
  if (has_magic(input)) {
    return input;
  }
  try {
    Bytes decoded = base64_decode(bytes_to_string(input));
    if (has_magic(decoded)) {
      return decoded;
    }
  } catch (const ToolError&) {
  }
  if (is_probably_hex_text(input)) {
    Bytes decoded = hex_decode(bytes_to_string(input));
    if (has_magic(decoded)) {
      return decoded;
    }
  }
  throw ToolError("unsupported or malformed ciphertext encoding");
}

Bytes encode_ciphertext_output(const Bytes& input, const std::string& format) {
  if (format == "raw") {
    return input;
  }
  if (format == "hex") {
    return string_to_bytes(hex_encode(input));
  }
  if (format == "base64") {
    return string_to_bytes(base64_encode(input));
  }
  throw ToolError("unsupported ciphertext format");
}

std::string direct_header(int rsa_bits, std::size_t limit, const std::string& format) {
  std::ostringstream oss;
  oss << "{\n"
      << "  \"mode\": \"RSA-OAEP\",\n"
      << "  \"rsa_modulus\": " << rsa_bits << ",\n"
      << "  \"hash\": \"SHA-256\",\n"
      << "  \"mgf\": \"MGF1-SHA-256\",\n"
      << "  \"oaep_limit\": " << limit << ",\n"
      << "  \"payload_encoding\": \"" << json_escape(format) << "\"\n"
      << "}";
  return oss.str();
}

std::string hybrid_header(int rsa_bits, const Bytes& wrapped_key, const Bytes& iv, const Bytes& tag, const std::string& format) {
  std::ostringstream oss;
  oss << "{\n"
      << "  \"mode\": \"RSA-OAEP-AES-GCM\",\n"
      << "  \"rsa_modulus\": " << rsa_bits << ",\n"
      << "  \"hash\": \"SHA-256\",\n"
      << "  \"mgf\": \"MGF1-SHA-256\",\n"
      << "  \"wrapped_key\": \"" << base64_encode(wrapped_key) << "\",\n"
      << "  \"iv\": \"" << base64_encode(iv) << "\",\n"
      << "  \"tag\": \"" << base64_encode(tag) << "\",\n"
      << "  \"payload_encoding\": \"" << json_escape(format) << "\"\n"
      << "}";
  return oss.str();
}

Bytes encrypt_bytes(const Bytes& plain, const CryptoPP::RSA::PublicKey& public_key, const std::string& label, const std::string& format) {
  const int rsa_bits = static_cast<int>(public_key.GetModulus().BitCount());
  const std::size_t limit = rsa_oaep_sha256_max_plaintext(static_cast<std::size_t>(rsa_bits));
  const Bytes label_bytes = string_to_bytes(label);
  if (plain.size() <= limit) {
    Bytes cipher = rsa_encrypt_oaep(public_key, plain, label_bytes);
    return make_container(direct_header(rsa_bits, limit, format), cipher);
  }

  const Bytes aes_key = random_bytes(kAes256KeyLen);
  const Bytes iv = random_bytes(kGcmIvLen);
  const Bytes wrapped = rsa_encrypt_oaep(public_key, aes_key, label_bytes);
  const std::string auth_header = hybrid_header(rsa_bits, wrapped, iv, Bytes(kGcmTagLen, 0x00), format);
  const Bytes aad = hybrid_aad_from_header(auth_header, label);
  GcmResult gcm = aes_gcm_encrypt(aes_key, iv, plain, aad);
  return make_container(hybrid_header(rsa_bits, wrapped, iv, gcm.tag, format), gcm.cipher);
}

Bytes decrypt_container(const Bytes& container, const CryptoPP::RSA::PrivateKey& private_key, const std::string& label) {
  ParsedContainer parsed = parse_container(container);
  validate_json_shape(parsed.header_json);
  const std::string mode = json_get_string(parsed.header_json, "mode");
  const std::string hash = json_get_string(parsed.header_json, "hash");
  const int rsa_bits = json_get_int(parsed.header_json, "rsa_modulus");
  const int key_bits = static_cast<int>(private_key.GetModulus().BitCount());
  if (hash != "SHA-256" || rsa_bits != key_bits) {
    throw ToolError("cryptographic operation failed");
  }
  const Bytes label_bytes = string_to_bytes(label);
  if (mode == "RSA-OAEP") {
    return rsa_decrypt_oaep(private_key, parsed.payload, label_bytes);
  }
  if (mode == "RSA-OAEP-AES-GCM") {
    const Bytes wrapped = base64_decode(json_get_string(parsed.header_json, "wrapped_key"));
    const Bytes iv = base64_decode(json_get_string(parsed.header_json, "iv"));
    const Bytes tag = base64_decode(json_get_string(parsed.header_json, "tag"));
    if (iv.size() != kGcmIvLen || tag.size() != kGcmTagLen) {
      throw ToolError("cryptographic operation failed");
    }
    const Bytes aes_key = rsa_decrypt_oaep(private_key, wrapped, label_bytes);
    if (aes_key.size() != kAes256KeyLen) {
      throw ToolError("cryptographic operation failed");
    }
    const Bytes aad = hybrid_aad_from_header(parsed.header_json, label);
    return aes_gcm_decrypt(aes_key, iv, parsed.payload, tag, aad);
  }
  throw ToolError("unsupported envelope mode");
}

double elapsed_ms(const Clock::time_point& start, const Clock::time_point& end) {
  return std::chrono::duration<double, std::milli>(end - start).count();
}

double mean(const std::vector<double>& xs) {
  if (xs.empty()) {
    return 0.0;
  }
  return std::accumulate(xs.begin(), xs.end(), 0.0) / static_cast<double>(xs.size());
}

double stddev_sample(const std::vector<double>& xs) {
  if (xs.size() < 2) {
    return 0.0;
  }
  const double m = mean(xs);
  double acc = 0.0;
  for (double x : xs) {
    const double d = x - m;
    acc += d * d;
  }
  return std::sqrt(acc / static_cast<double>(xs.size() - 1));
}

void require_supported_bits(int bits) {
  if (bits != 3072 && bits != 4096) {
    throw ToolError("unsupported RSA key size; use 3072 or 4096 bits");
  }
}

void remove_if_exists(const std::string& path) {
  std::remove(path.c_str());
}

void assert_equal(const Bytes& a, const Bytes& b, const std::string& name) {
  if (a != b) {
    throw ToolError("selftest failed: " + name);
  }
  std::cout << "PASS " << name << "\n";
}

void assert_true(bool ok, const std::string& name) {
  if (!ok) {
    throw ToolError("KAT failed: " + name);
  }
  std::cout << "PASS " << name << "\n";
}

void assert_fail(const std::string& name, const std::function<void()>& fn) {
  try {
    fn();
  } catch (const ToolError&) {
    std::cout << "PASS " << name << "\n";
    return;
  } catch (const CryptoPP::Exception&) {
    std::cout << "PASS " << name << "\n";
    return;
  }
  throw ToolError("selftest failed: " + name);
}

} // namespace

Bytes read_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    throw ToolError("cannot open input file: " + path);
  }
  in.seekg(0, std::ios::end);
  const std::streamoff size = in.tellg();
  if (size < 0) {
    throw ToolError("cannot determine file size: " + path);
  }
  in.seekg(0, std::ios::beg);
  Bytes data(static_cast<std::size_t>(size));
  if (!data.empty()) {
    in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
  }
  if (!in && !data.empty()) {
    throw ToolError("cannot read input file: " + path);
  }
  return data;
}

void write_file(const std::string& path, const Bytes& data) {
  std::ofstream out(path, std::ios::binary);
  if (!out) {
    throw ToolError("cannot open output file: " + path);
  }
  if (!data.empty()) {
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
  }
  if (!out) {
    throw ToolError("cannot write output file: " + path);
  }
}

bool file_exists(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  return static_cast<bool>(in);
}

std::string bytes_to_string(const Bytes& data) {
  return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

Bytes string_to_bytes(const std::string& text) {
  return Bytes(text.begin(), text.end());
}

std::string hex_encode(const Bytes& data) {
  std::string out;
  CryptoPP::StringSource ss(data.data(), data.size(), true,
      new CryptoPP::HexEncoder(new CryptoPP::StringSink(out), false));
  return out;
}

Bytes hex_decode(const std::string& text) {
  std::string cleaned;
  for (unsigned char c : text) {
    if (!std::isspace(c)) {
      cleaned.push_back(static_cast<char>(c));
    }
  }
  std::string out;
  try {
    CryptoPP::StringSource ss(cleaned, true,
        new CryptoPP::HexDecoder(new CryptoPP::StringSink(out)));
  } catch (const CryptoPP::Exception&) {
    throw ToolError("incorrect hex encoding");
  }
  return string_to_bytes(out);
}

std::string base64_encode(const Bytes& data) {
  std::string out;
  CryptoPP::StringSource ss(data.data(), data.size(), true,
      new CryptoPP::Base64Encoder(new CryptoPP::StringSink(out), false));
  return out;
}

Bytes base64_decode(const std::string& text) {
  std::string out;
  try {
    CryptoPP::StringSource ss(text, true,
        new CryptoPP::Base64Decoder(new CryptoPP::StringSink(out)));
  } catch (const CryptoPP::Exception&) {
    throw ToolError("incorrect base64 encoding");
  }
  return string_to_bytes(out);
}

std::size_t rsa_oaep_sha256_max_plaintext(std::size_t modulus_bits) {
  const std::size_t k = (modulus_bits + 7) / 8;
  const std::size_t h_len = CryptoPP::SHA256::DIGESTSIZE;
  if (k < 2 * h_len + 2) {
    return 0;
  }
  return k - 2 * h_len - 2;
}

void keygen(int bits, const KeyPaths& paths) {
  require_supported_bits(bits);
  if (paths.public_pem.empty() || paths.private_pem.empty()) {
    throw ToolError("keygen requires --pub and --priv");
  }

  CryptoPP::AutoSeededRandomPool rng;
  CryptoPP::RSA::PrivateKey private_key;
  private_key.GenerateRandomWithKeySize(rng, bits);
  CryptoPP::RSA::PublicKey public_key(private_key);

  const Bytes pub_der = save_key_der(public_key);
  const Bytes priv_der = save_key_der(private_key);

  write_file(paths.public_pem, string_to_bytes(wrap_pem("RSA PUBLIC KEY", pub_der)));
  write_file(paths.private_pem, string_to_bytes(wrap_pem("RSA PRIVATE KEY", priv_der)));

  if (!paths.public_der.empty()) {
    write_file(paths.public_der, pub_der);
  }
  if (!paths.private_der.empty()) {
    write_file(paths.private_der, priv_der);
  }
  if (!paths.metadata_json.empty()) {
    std::ostringstream meta;
    meta << "{\n"
         << "  \"creation_time\": \"" << now_utc_iso8601() << "\",\n"
         << "  \"modulus_bits\": " << bits << ",\n"
         << "  \"hash\": \"SHA-256\",\n"
         << "  \"padding\": \"OAEP\",\n"
         << "  \"mgf\": \"MGF1-SHA-256\",\n"
         << "  \"rsa_oaep_max_plaintext_bytes\": " << rsa_oaep_sha256_max_plaintext(static_cast<std::size_t>(bits)) << "\n"
         << "}\n";
    write_file(paths.metadata_json, string_to_bytes(meta.str()));
  }
}

void encrypt_file(const EncryptOptions& options) {
  if (options.public_key_path.empty() || options.output_path.empty()) {
    throw ToolError("encrypt requires --pub and --out");
  }
  if (options.input_path.empty() && options.text.empty()) {
    throw ToolError("encrypt requires --in or --text");
  }
  const Bytes plain = options.input_path.empty() ? string_to_bytes(options.text) : read_file(options.input_path);
  const CryptoPP::RSA::PublicKey public_key = load_public_key(options.public_key_path);
  const int rsa_bits = static_cast<int>(public_key.GetModulus().BitCount());
  require_supported_bits(rsa_bits);
  const Bytes container = encrypt_bytes(plain, public_key, options.label, options.format);
  write_file(options.output_path, encode_ciphertext_output(container, options.format));
}

void decrypt_file(const DecryptOptions& options) {
  if (options.private_key_path.empty() || options.input_path.empty() || options.output_path.empty()) {
    throw ToolError("decrypt requires --priv, --in, and --out");
  }
  const CryptoPP::RSA::PrivateKey private_key = load_private_key(options.private_key_path);
  const int rsa_bits = static_cast<int>(private_key.GetModulus().BitCount());
  require_supported_bits(rsa_bits);
  const Bytes encoded = read_file(options.input_path);
  const Bytes container = decode_ciphertext_input(encoded, options.format);
  const Bytes plain = decrypt_container(container, private_key, options.label);
  write_file(options.output_path, plain);
}

Bytes oaep_mgf1_sha256(const Bytes& seed, std::size_t mask_len) {
  Bytes mask;
  mask.reserve(mask_len);
  std::uint32_t counter = 0;
  while (mask.size() < mask_len) {
    Bytes input = seed;
    input.push_back(static_cast<unsigned char>((counter >> 24) & 0xff));
    input.push_back(static_cast<unsigned char>((counter >> 16) & 0xff));
    input.push_back(static_cast<unsigned char>((counter >> 8) & 0xff));
    input.push_back(static_cast<unsigned char>(counter & 0xff));
    Bytes digest(CryptoPP::SHA256::DIGESTSIZE);
    CryptoPP::SHA256 hash;
    hash.Update(input.data(), input.size());
    hash.Final(digest.data());
    const std::size_t take = std::min(digest.size(), mask_len - mask.size());
    mask.insert(mask.end(), digest.begin(), digest.begin() + static_cast<std::ptrdiff_t>(take));
    ++counter;
  }
  return mask;
}

Bytes oaep_encode_sha256(const Bytes& message, std::size_t encoded_len, const Bytes& label, const Bytes& seed) {
  const std::size_t h_len = CryptoPP::SHA256::DIGESTSIZE;
  if (seed.size() != h_len) {
    throw ToolError("OAEP seed must be 32 bytes for SHA-256");
  }
  if (message.size() > encoded_len - 2 * h_len - 2) {
    throw ToolError("message too long for OAEP encoding");
  }

  Bytes l_hash(h_len);
  CryptoPP::SHA256 hash;
  hash.Update(label.data(), label.size());
  hash.Final(l_hash.data());

  const std::size_t ps_len = encoded_len - message.size() - 2 * h_len - 2;
  Bytes db = l_hash;
  db.insert(db.end(), ps_len, 0x00);
  db.push_back(0x01);
  db.insert(db.end(), message.begin(), message.end());

  Bytes db_mask = oaep_mgf1_sha256(seed, encoded_len - h_len - 1);
  Bytes masked_db(db.size());
  for (std::size_t i = 0; i < db.size(); ++i) {
    masked_db[i] = static_cast<unsigned char>(db[i] ^ db_mask[i]);
  }

  Bytes seed_mask = oaep_mgf1_sha256(masked_db, h_len);
  Bytes masked_seed(h_len);
  for (std::size_t i = 0; i < h_len; ++i) {
    masked_seed[i] = static_cast<unsigned char>(seed[i] ^ seed_mask[i]);
  }

  Bytes encoded;
  encoded.push_back(0x00);
  encoded.insert(encoded.end(), masked_seed.begin(), masked_seed.end());
  encoded.insert(encoded.end(), masked_db.begin(), masked_db.end());
  return encoded;
}

Bytes oaep_decode_sha256(const Bytes& encoded, const Bytes& label) {
  const std::size_t h_len = CryptoPP::SHA256::DIGESTSIZE;
  if (encoded.size() < 2 * h_len + 2) {
    throw ToolError("OAEP block is too short");
  }

  Bytes masked_seed(encoded.begin() + 1, encoded.begin() + 1 + static_cast<std::ptrdiff_t>(h_len));
  Bytes masked_db(encoded.begin() + 1 + static_cast<std::ptrdiff_t>(h_len), encoded.end());
  Bytes seed_mask = oaep_mgf1_sha256(masked_db, h_len);
  Bytes seed(h_len);
  for (std::size_t i = 0; i < h_len; ++i) {
    seed[i] = static_cast<unsigned char>(masked_seed[i] ^ seed_mask[i]);
  }
  Bytes db_mask = oaep_mgf1_sha256(seed, encoded.size() - h_len - 1);
  Bytes db(masked_db.size());
  for (std::size_t i = 0; i < db.size(); ++i) {
    db[i] = static_cast<unsigned char>(masked_db[i] ^ db_mask[i]);
  }

  Bytes expected_hash(h_len);
  CryptoPP::SHA256 hash;
  hash.Update(label.data(), label.size());
  hash.Final(expected_hash.data());

  unsigned char bad = encoded[0];
  for (std::size_t i = 0; i < h_len; ++i) {
    bad |= static_cast<unsigned char>(db[i] ^ expected_hash[i]);
  }

  std::size_t one_index = 0;
  unsigned char seen_one = 0;
  unsigned char bad_padding = 0;
  for (std::size_t i = h_len; i < db.size(); ++i) {
    const unsigned char is_zero = static_cast<unsigned char>(db[i] == 0x00);
    const unsigned char is_one = static_cast<unsigned char>(db[i] == 0x01);
    const unsigned char before_one = static_cast<unsigned char>(!seen_one);
    bad_padding |= static_cast<unsigned char>(before_one & (!is_zero) & (!is_one));
    if (!seen_one && is_one) {
      one_index = i;
    }
    seen_one = static_cast<unsigned char>(seen_one | is_one);
  }

  if (bad || bad_padding || !seen_one) {
    throw ToolError("OAEP decoding failed");
  }
  return Bytes(db.begin() + static_cast<std::ptrdiff_t>(one_index + 1), db.end());
}

void run_oaep_selftest() {
  const Bytes message = string_to_bytes("manual oaep padding");
  const Bytes label = string_to_bytes("lab3");
  Bytes seed(CryptoPP::SHA256::DIGESTSIZE);
  for (std::size_t i = 0; i < seed.size(); ++i) {
    seed[i] = static_cast<unsigned char>(i);
  }
  const Bytes encoded = oaep_encode_sha256(message, 384, label, seed);
  const Bytes decoded = oaep_decode_sha256(encoded, label);
  assert_equal(decoded, message, "manual OAEP encode/decode with SHA-256");

  Bytes tampered = encoded;
  tampered[tampered.size() - 1] ^= 0x01;
  assert_fail("manual OAEP padding validation rejects tampering", [&]() {
    (void)oaep_decode_sha256(tampered, label);
  });
}

void run_kat_tests(const std::string& vector_path) {
  std::cout << "============================================================\n";
  std::cout << "RSATOOL KNOWN ANSWER TESTS\n";
  std::cout << "============================================================\n";

  if (!vector_path.empty()) {
    const std::string json = bytes_to_string(read_file(vector_path));
    std::cout << "Vector file: " << vector_path << "\n";
    assert_true(json_get_int(json, "rsa3072") == 318,
                "KAT JSON RSA-3072 limit matches expected value");
    assert_true(json_get_int(json, "rsa4096") == 446,
                "KAT JSON RSA-4096 limit matches expected value");
    assert_true(json_get_string(json, "expected_hex") ==
                    "336f28a022193939585a1b4edc989f870917f3a5f6ddd16e4fb357084a6bdfc2",
                "KAT JSON MGF1-SHA256 expected hex matches");
    assert_true(json_get_string(json, "tag_hex") ==
                    "530f8afbc74536b9a963b4f1c4cb738b",
                "KAT JSON AES-256-GCM tag matches");
  }

  assert_true(rsa_oaep_sha256_max_plaintext(3072) == 318,
              "RSA-3072 OAEP-SHA256 plaintext limit = 318 bytes");
  assert_true(rsa_oaep_sha256_max_plaintext(4096) == 446,
              "RSA-4096 OAEP-SHA256 plaintext limit = 446 bytes");

  const Bytes mgf_seed = string_to_bytes("seed");
  const Bytes mgf_expected = hex_decode("336f28a022193939585a1b4edc989f870917f3a5f6ddd16e4fb357084a6bdfc2");
  assert_equal(oaep_mgf1_sha256(mgf_seed, 32), mgf_expected,
               "MGF1-SHA256(seed, 32) known vector");

  const Bytes gcm_key(kAes256KeyLen, 0x00);
  const Bytes gcm_iv(kGcmIvLen, 0x00);
  const GcmResult gcm = aes_gcm_encrypt(gcm_key, gcm_iv, {}, {});
  assert_true(gcm.cipher.empty(), "AES-256-GCM empty plaintext ciphertext is empty");
  assert_equal(gcm.tag, hex_decode("530f8afbc74536b9a963b4f1c4cb738b"),
               "AES-256-GCM zero key/IV empty plaintext tag");

  run_oaep_selftest();
  std::cout << "Summary: all rsatool KATs passed\n";
}

void run_selftest() {
  const std::string p = ".rsatool_selftest_";
  const KeyPaths k1{p + "pub.pem", p + "priv.pem", p + "pub.der", p + "priv.der", p + "meta.json"};
  const KeyPaths k2{p + "wrong_pub.pem", p + "wrong_priv.pem", "", "", ""};
  keygen(3072, k1);
  keygen(3072, k2);

  const CryptoPP::RSA::PublicKey pub = load_public_key(k1.public_pem);
  const CryptoPP::RSA::PrivateKey priv = load_private_key(k1.private_pem);
  const CryptoPP::RSA::PrivateKey wrong_priv = load_private_key(k2.private_pem);

  const Bytes direct_plain = string_to_bytes("small RSA-OAEP message");
  const Bytes direct_ct = encrypt_bytes(direct_plain, pub, "label-a", "raw");
  assert_equal(decrypt_container(direct_ct, priv, "label-a"), direct_plain, "RSA-OAEP SHA-256 roundtrip");
  assert_fail("wrong OAEP label fails", [&]() {
    (void)decrypt_container(direct_ct, priv, "wrong-label");
  });
  assert_fail("wrong private key fails", [&]() {
    (void)decrypt_container(direct_ct, wrong_priv, "label-a");
  });

  Bytes altered_rsa = direct_ct;
  altered_rsa.back() ^= 0x01;
  assert_fail("altered RSA ciphertext fails", [&]() {
    (void)decrypt_container(altered_rsa, priv, "label-a");
  });

  Bytes hybrid_plain(2048);
  for (std::size_t i = 0; i < hybrid_plain.size(); ++i) {
    hybrid_plain[i] = static_cast<unsigned char>(i & 0xff);
  }
  const Bytes hybrid_ct = encrypt_bytes(hybrid_plain, pub, "label-b", "raw");
  assert_equal(decrypt_container(hybrid_ct, priv, "label-b"), hybrid_plain, "hybrid RSA-OAEP + AES-256-GCM roundtrip");

  Bytes altered_gcm = hybrid_ct;
  altered_gcm.back() ^= 0x01;
  assert_fail("altered AES-GCM ciphertext fails", [&]() {
    (void)decrypt_container(altered_gcm, priv, "label-b");
  });

  Bytes altered_header = hybrid_ct;
  const std::string marker = "\"hash\": \"SHA-256\"";
  const std::string as_text = bytes_to_string(altered_header);
  const std::size_t pos = as_text.find(marker);
  if (pos == std::string::npos) {
    throw ToolError("selftest failed: cannot locate header marker");
  }
  altered_header[pos + marker.size() - 2] = '7';
  assert_fail("tampered envelope header fails", [&]() {
    (void)decrypt_container(altered_header, priv, "label-b");
  });

  for (const std::string& path : {k1.public_pem, k1.private_pem, k1.public_der, k1.private_der,
                                  k1.metadata_json, k2.public_pem, k2.private_pem}) {
    remove_if_exists(path);
  }
  std::cout << "Summary: all Lab 3 correctness and negative tests passed\n";
}

void run_benchmark(const BenchOptions& options) {
  const int runs = std::max(1, options.runs);
  const int ops = std::max(1, options.ops);
  std::cout << "============================================================\n";
  std::cout << "RSA-OAEP SHA-256 BENCHMARK\n";
  std::cout << "Runs: " << runs << " | Ops/run: " << ops << "\n";
  std::cout << "============================================================\n";
  std::cout << std::left << std::setw(10) << "Bits"
            << std::right << std::setw(14) << "Keygen ms"
            << std::setw(14) << "Enc ms/op"
            << std::setw(14) << "Dec ms/op"
            << std::setw(14) << "Dec CI95"
            << "\n";
  std::cout << "------------------------------------------------------------------\n";

  for (int bits : {3072, 4096}) {
    std::vector<double> keygen_ms;
    std::vector<double> enc_ms;
    std::vector<double> dec_ms;
    for (int r = 0; r < runs; ++r) {
      CryptoPP::AutoSeededRandomPool rng;
      auto s = Clock::now();
      CryptoPP::RSA::PrivateKey priv;
      priv.GenerateRandomWithKeySize(rng, bits);
      CryptoPP::RSA::PublicKey pub(priv);
      auto e = Clock::now();
      keygen_ms.push_back(elapsed_ms(s, e));

      Bytes msg = string_to_bytes("RSA benchmark message");
      Bytes ct;
      s = Clock::now();
      for (int op = 0; op < ops; ++op) {
        ct = rsa_encrypt_oaep(pub, msg, {});
      }
      e = Clock::now();
      enc_ms.push_back(elapsed_ms(s, e) / static_cast<double>(ops));

      s = Clock::now();
      Bytes pt;
      for (int op = 0; op < ops; ++op) {
        pt = rsa_decrypt_oaep(priv, ct, {});
      }
      e = Clock::now();
      dec_ms.push_back(elapsed_ms(s, e) / static_cast<double>(ops));
      if (pt != msg) {
        throw ToolError("benchmark roundtrip failed");
      }
    }
    const double dec_sd = stddev_sample(dec_ms);
    const double dec_ci95 = 1.96 * dec_sd / std::sqrt(static_cast<double>(runs));
    std::cout << std::left << std::setw(10) << bits
              << std::right << std::setw(14) << std::fixed << std::setprecision(2) << mean(keygen_ms)
              << std::setw(14) << mean(enc_ms)
              << std::setw(14) << mean(dec_ms)
              << std::setw(14) << dec_ci95 << "\n";
  }

  std::cout << "\n============================================================\n";
  std::cout << "HYBRID RSA-OAEP + AES-256-GCM BENCHMARK\n";
  std::cout << "Runs: " << runs << " | Ops/run: " << ops << "\n";
  std::cout << "============================================================\n";
  std::cout << std::left << std::setw(12) << "Size"
            << std::right << std::setw(14) << "Enc ms/op"
            << std::setw(14) << "Dec ms/op"
            << std::setw(14) << "Enc MB/s"
            << std::setw(14) << "Dec MB/s"
            << std::setw(14) << "Dec CI95"
            << "\n";
  std::cout << "------------------------------------------------------------------------------------\n";

  CryptoPP::AutoSeededRandomPool rng;
  CryptoPP::RSA::PrivateKey priv;
  priv.GenerateRandomWithKeySize(rng, 3072);
  CryptoPP::RSA::PublicKey pub(priv);

  std::vector<std::pair<std::string, std::size_t>> sizes = {
      {"1 KiB", 1024},
      {"1 MiB", 1024 * 1024}};
  if (options.include_100mib) {
    sizes.push_back({"100 MiB", 100ULL * 1024ULL * 1024ULL});
  }

  for (const auto& item : sizes) {
    const std::string& label = item.first;
    const std::size_t size = item.second;
    Bytes plain(size);
    for (std::size_t i = 0; i < size; ++i) {
      plain[i] = static_cast<unsigned char>(i & 0xff);
    }
    std::vector<double> enc_ms;
    std::vector<double> dec_ms;
    for (int r = 0; r < runs; ++r) {
      Bytes ct;
      auto s = Clock::now();
      for (int op = 0; op < ops; ++op) {
        ct = encrypt_bytes(plain, pub, "", "raw");
      }
      auto e = Clock::now();
      enc_ms.push_back(elapsed_ms(s, e) / static_cast<double>(ops));

      Bytes pt;
      s = Clock::now();
      for (int op = 0; op < ops; ++op) {
        pt = decrypt_container(ct, priv, "");
      }
      e = Clock::now();
      dec_ms.push_back(elapsed_ms(s, e) / static_cast<double>(ops));
      if (pt != plain) {
        throw ToolError("benchmark hybrid roundtrip failed");
      }
    }
    const double enc_m = mean(enc_ms);
    const double dec_m = mean(dec_ms);
    const double mib = static_cast<double>(size) / (1024.0 * 1024.0);
    const double enc_t = enc_m <= 0.0 ? 0.0 : mib / (enc_m / 1000.0);
    const double dec_t = dec_m <= 0.0 ? 0.0 : mib / (dec_m / 1000.0);
    const double dec_ci95 = 1.96 * stddev_sample(dec_ms) / std::sqrt(static_cast<double>(runs));
    std::cout << std::left << std::setw(12) << label
              << std::right << std::setw(14) << std::fixed << std::setprecision(2) << enc_m
              << std::setw(14) << dec_m
              << std::setw(14) << enc_t
              << std::setw(14) << dec_t
              << std::setw(14) << dec_ci95 << "\n";
  }
}

} // namespace rsatool
