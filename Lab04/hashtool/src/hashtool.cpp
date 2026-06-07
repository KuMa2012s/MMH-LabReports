#include "hashtool.hpp"

#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/integer.h>
#include <cryptopp/md5.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/queue.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/shake.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <regex>
#include <sstream>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace hashtool {
namespace {

using Clock = std::chrono::high_resolution_clock;

constexpr std::size_t kChunk = 1024 * 1024;

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

bool is_shake(const std::string& algo) {
  const std::string a = lower(algo);
  return a == "shake128" || a == "shake256";
}

std::size_t default_digest_size(const std::string& algo) {
  const std::string a = lower(algo);
  if (a == "sha224") return 28;
  if (a == "sha256") return 32;
  if (a == "sha384") return 48;
  if (a == "sha512") return 64;
  if (a == "sha3-224" || a == "sha3224") return 28;
  if (a == "sha3-256" || a == "sha3256") return 32;
  if (a == "sha3-384" || a == "sha3384") return 48;
  if (a == "sha3-512" || a == "sha3512") return 64;
  if (a == "md5") return 16;
  throw ToolError("unsupported algorithm: " + algo);
}

template <typename H>
Bytes digest_with(const Bytes& data) {
  H h;
  Bytes out(h.DigestSize());
  h.Update(data.data(), data.size());
  h.Final(out.data());
  return out;
}

template <typename H>
Bytes digest_mem_with(const unsigned char* data, std::size_t len) {
  H h;
  Bytes out(h.DigestSize());
  h.Update(data, len);
  h.Final(out.data());
  return out;
}

template <typename H>
Bytes digest_file_with(const std::string& path) {
  H h;
  std::ifstream in(path, std::ios::binary);
  if (!in) throw ToolError("cannot open input file: " + path);
  Bytes buf(kChunk);
  while (in) {
    in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    const std::streamsize got = in.gcount();
    if (got > 0) h.Update(buf.data(), static_cast<std::size_t>(got));
  }
  Bytes out(h.DigestSize());
  h.Final(out.data());
  return out;
}

template <typename H>
Bytes xof_with(const Bytes& data, std::size_t outlen) {
  H h;
  Bytes out(outlen);
  h.Update(data.data(), data.size());
  h.TruncatedFinal(out.data(), out.size());
  return out;
}

template <typename H>
Bytes xof_mem_with(const unsigned char* data, std::size_t len, std::size_t outlen) {
  H h;
  Bytes out(outlen);
  h.Update(data, len);
  h.TruncatedFinal(out.data(), out.size());
  return out;
}

template <typename H>
Bytes xof_file_with(const std::string& path, std::size_t outlen) {
  H h;
  std::ifstream in(path, std::ios::binary);
  if (!in) throw ToolError("cannot open input file: " + path);
  Bytes buf(kChunk);
  while (in) {
    in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    const std::streamsize got = in.gcount();
    if (got > 0) h.Update(buf.data(), static_cast<std::size_t>(got));
  }
  Bytes out(outlen);
  h.TruncatedFinal(out.data(), out.size());
  return out;
}

Bytes decode_pem_if_needed(const Bytes& input, const std::string& label) {
  const std::string text = bytes_to_string(input);
  const std::string begin = "-----BEGIN " + label + "-----";
  const std::string end = "-----END " + label + "-----";
  const auto b = text.find(begin);
  if (b == std::string::npos) return input;
  const auto e = text.find(end, b);
  if (e == std::string::npos) throw ToolError("malformed PEM");
  std::string b64 = text.substr(b + begin.size(), e - (b + begin.size()));
  b64.erase(std::remove_if(b64.begin(), b64.end(), [](unsigned char c) { return std::isspace(c); }), b64.end());
  std::string out;
  CryptoPP::StringSource ss(b64, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(out)));
  return string_to_bytes(out);
}

struct Asn1 {
  const Bytes* data{};
  std::size_t start{};
  std::size_t header{};
  std::size_t len{};
  unsigned char tag{};

  std::size_t content() const { return start + header; }
  std::size_t end() const { return content() + len; }
  Bytes value() const { return Bytes(data->begin() + static_cast<std::ptrdiff_t>(content()), data->begin() + static_cast<std::ptrdiff_t>(end())); }
};

Asn1 read_asn1(const Bytes& d, std::size_t& off) {
  if (off + 2 > d.size()) throw ToolError("malformed ASN.1");
  Asn1 n;
  n.data = &d;
  n.start = off;
  n.tag = d[off++];
  unsigned char l = d[off++];
  if ((l & 0x80) == 0) {
    n.len = l;
    n.header = 2;
  } else {
    const std::size_t count = l & 0x7f;
    if (count == 0 || count > sizeof(std::size_t) || off + count > d.size()) throw ToolError("malformed ASN.1 length");
    n.len = 0;
    for (std::size_t i = 0; i < count; ++i) n.len = (n.len << 8) | d[off++];
    n.header = 2 + count;
  }
  if (n.end() > d.size()) throw ToolError("malformed ASN.1 object");
  off = n.end();
  return n;
}

std::vector<Asn1> children(const Asn1& n) {
  std::vector<Asn1> out;
  std::size_t off = n.content();
  while (off < n.end()) out.push_back(read_asn1(*n.data, off));
  return out;
}

std::string oid_to_string(const Bytes& v) {
  if (v.empty()) return "";
  std::ostringstream oss;
  int first = v[0] / 40;
  int second = v[0] % 40;
  oss << first << "." << second;
  std::uint64_t x = 0;
  for (std::size_t i = 1; i < v.size(); ++i) {
    x = (x << 7) | (v[i] & 0x7f);
    if ((v[i] & 0x80) == 0) {
      oss << "." << x;
      x = 0;
    }
  }
  return oss.str();
}

std::string oid_name(const std::string& oid) {
  static const std::map<std::string, std::string> names = {
      {"1.2.840.113549.1.1.1", "rsaEncryption"},
      {"1.2.840.113549.1.1.5", "sha1WithRSAEncryption"},
      {"1.2.840.113549.1.1.11", "sha256WithRSAEncryption"},
      {"1.2.840.113549.1.1.12", "sha384WithRSAEncryption"},
      {"1.2.840.113549.1.1.13", "sha512WithRSAEncryption"},
      {"1.2.840.10045.2.1", "id-ecPublicKey"},
      {"1.2.840.10045.4.3.2", "ecdsa-with-SHA256"},
      {"2.5.4.3", "CN"},
      {"2.5.4.6", "C"},
      {"2.5.4.7", "L"},
      {"2.5.4.8", "ST"},
      {"2.5.4.10", "O"},
      {"2.5.4.11", "OU"},
      {"2.5.29.15", "Key Usage"},
      {"2.5.29.17", "Subject Alternative Name"}};
  auto it = names.find(oid);
  return it == names.end() ? oid : it->second;
}

std::string asn1_string(const Asn1& n) {
  Bytes v = n.value();
  if (n.tag == 0x13 || n.tag == 0x0c || n.tag == 0x16 || n.tag == 0x14 || n.tag == 0x17 || n.tag == 0x18) {
    return bytes_to_string(v);
  }
  return hex_encode(v);
}

std::string parse_name(const Asn1& name) {
  std::vector<std::string> parts;
  for (const Asn1& rdn : children(name)) {
    for (const Asn1& attr : children(rdn)) {
      auto c = children(attr);
      if (c.size() >= 2) {
        parts.push_back(oid_name(oid_to_string(c[0].value())) + "=" + asn1_string(c[1]));
      }
    }
  }
  std::ostringstream oss;
  for (std::size_t i = 0; i < parts.size(); ++i) {
    if (i) oss << ", ";
    oss << parts[i];
  }
  return oss.str();
}

std::string parse_algorithm_oid(const Asn1& alg) {
  auto c = children(alg);
  if (c.empty()) return "";
  return oid_to_string(c[0].value());
}

std::string parse_bit_string_hex(const Asn1& bs) {
  Bytes v = bs.value();
  if (v.empty()) return "";
  v.erase(v.begin());
  return hex_encode(v);
}

std::string parse_key_usage(const Asn1& octets) {
  Bytes inner = octets.value();
  std::size_t off = 0;
  Asn1 bs = read_asn1(inner, off);
  Bytes v = bs.value();
  if (v.size() < 2) return "";
  const unsigned char b = v[1];
  std::vector<std::string> out;
  if (b & 0x80) out.push_back("digitalSignature");
  if (b & 0x40) out.push_back("nonRepudiation");
  if (b & 0x20) out.push_back("keyEncipherment");
  if (b & 0x10) out.push_back("dataEncipherment");
  if (b & 0x08) out.push_back("keyAgreement");
  if (b & 0x04) out.push_back("keyCertSign");
  if (b & 0x02) out.push_back("cRLSign");
  std::ostringstream oss;
  for (std::size_t i = 0; i < out.size(); ++i) {
    if (i) oss << ", ";
    oss << out[i];
  }
  return oss.str();
}

std::string parse_san(const Asn1& octets) {
  Bytes inner = octets.value();
  std::size_t off = 0;
  Asn1 seq = read_asn1(inner, off);
  std::vector<std::string> out;
  for (const Asn1& gn : children(seq)) {
    if (gn.tag == 0x82) out.push_back("DNS:" + bytes_to_string(gn.value()));
    else if (gn.tag == 0x87) out.push_back("IP:" + hex_encode(gn.value()));
    else if (gn.tag == 0x81) out.push_back("email:" + bytes_to_string(gn.value()));
  }
  std::ostringstream oss;
  for (std::size_t i = 0; i < out.size(); ++i) {
    if (i) oss << ", ";
    oss << out[i];
  }
  return oss.str();
}

struct CertInfo {
  Bytes der;
  Bytes tbs_der;
  Bytes signature_bits;
  Asn1 spki;
  std::string subject;
  std::string issuer;
  std::string spki_alg;
  std::string sig_alg;
  std::string not_before;
  std::string not_after;
  std::string key_usage;
  std::string sans;
};

CertInfo parse_cert(const Bytes& input) {
  CertInfo info;
  info.der = decode_pem_if_needed(input, "CERTIFICATE");
  std::size_t off = 0;
  Asn1 cert = read_asn1(info.der, off);
  auto cc = children(cert);
  if (cc.size() != 3) throw ToolError("malformed certificate");
  info.tbs_der.assign(info.der.begin() + static_cast<std::ptrdiff_t>(cc[0].start),
                      info.der.begin() + static_cast<std::ptrdiff_t>(cc[0].end()));
  info.sig_alg = oid_name(parse_algorithm_oid(cc[1]));
  Bytes sig = cc[2].value();
  if (!sig.empty()) sig.erase(sig.begin());
  info.signature_bits = sig;

  auto t = children(cc[0]);
  std::size_t idx = 0;
  if (!t.empty() && t[0].tag == 0xa0) idx = 1;
  if (t.size() < idx + 6) throw ToolError("malformed tbsCertificate");
  idx += 1; // serial
  idx += 1; // signature
  info.issuer = parse_name(t[idx++]);
  auto validity = children(t[idx++]);
  if (validity.size() >= 2) {
    info.not_before = asn1_string(validity[0]);
    info.not_after = asn1_string(validity[1]);
  }
  info.subject = parse_name(t[idx++]);
  info.spki = t[idx++];
  info.spki_alg = oid_name(parse_algorithm_oid(children(info.spki)[0]));

  for (; idx < t.size(); ++idx) {
    if (t[idx].tag != 0xa3) continue;
    auto ext_wrap = children(t[idx]);
    if (ext_wrap.empty()) continue;
    for (const Asn1& ext : children(ext_wrap[0])) {
      auto e = children(ext);
      if (e.size() < 2) continue;
      const std::string oid = oid_to_string(e[0].value());
      const Asn1& value = e.back();
      if (oid == "2.5.29.15") info.key_usage = parse_key_usage(value);
      if (oid == "2.5.29.17") info.sans = parse_san(value);
    }
  }
  return info;
}

CryptoPP::RSA::PublicKey rsa_public_key_from_spki(const Asn1& spki) {
  auto c = children(spki);
  if (c.size() < 2) throw ToolError("malformed SPKI");
  const std::string alg = parse_algorithm_oid(c[0]);
  if (alg != "1.2.840.113549.1.1.1") throw ToolError("signature verification currently supports RSA issuer keys only");
  Bytes bits = c[1].value();
  if (bits.empty()) throw ToolError("malformed SPKI bit string");
  bits.erase(bits.begin());
  std::size_t off = 0;
  Asn1 seq = read_asn1(bits, off);
  auto rc = children(seq);
  if (rc.size() < 2) throw ToolError("malformed RSA public key");
  CryptoPP::Integer n(rc[0].value().data(), rc[0].value().size());
  CryptoPP::Integer e(rc[1].value().data(), rc[1].value().size());
  CryptoPP::RSA::PublicKey pk;
  pk.Initialize(n, e);
  return pk;
}

template <typename H>
bool verify_rsa_pkcs1(const CryptoPP::RSA::PublicKey& key, const Bytes& msg, const Bytes& sig) {
  typename CryptoPP::RSASS<CryptoPP::PKCS1v15, H>::Verifier verifier(key);
  return verifier.VerifyMessage(msg.data(), msg.size(), sig.data(), sig.size());
}

bool verify_cert_sig(const CertInfo& leaf, const CertInfo& issuer) {
  CryptoPP::RSA::PublicKey pk = rsa_public_key_from_spki(issuer.spki);
  if (leaf.sig_alg == "sha256WithRSAEncryption") return verify_rsa_pkcs1<CryptoPP::SHA256>(pk, leaf.tbs_der, leaf.signature_bits);
  if (leaf.sig_alg == "sha384WithRSAEncryption") return verify_rsa_pkcs1<CryptoPP::SHA384>(pk, leaf.tbs_der, leaf.signature_bits);
  if (leaf.sig_alg == "sha512WithRSAEncryption") return verify_rsa_pkcs1<CryptoPP::SHA512>(pk, leaf.tbs_der, leaf.signature_bits);
  throw ToolError("unsupported certificate signature algorithm for verification: " + leaf.sig_alg);
}

double ms_between(const Clock::time_point& a, const Clock::time_point& b) {
  return std::chrono::duration<double, std::milli>(b - a).count();
}

double mean(const std::vector<double>& xs) {
  return xs.empty() ? 0.0 : std::accumulate(xs.begin(), xs.end(), 0.0) / static_cast<double>(xs.size());
}

double median(std::vector<double> xs) {
  if (xs.empty()) return 0.0;
  std::sort(xs.begin(), xs.end());
  const std::size_t m = xs.size() / 2;
  return xs.size() % 2 ? xs[m] : (xs[m - 1] + xs[m]) / 2.0;
}

double stdev(const std::vector<double>& xs) {
  if (xs.size() < 2) return 0.0;
  const double m = mean(xs);
  double s = 0.0;
  for (double x : xs) s += (x - m) * (x - m);
  return std::sqrt(s / static_cast<double>(xs.size() - 1));
}

std::string json_string(const std::string& json, const std::string& key) {
  const std::regex r("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
  std::smatch m;
  if (!std::regex_search(json, m, r)) throw ToolError("missing KAT field: " + key);
  return m[1].str();
}

std::size_t json_int(const std::string& json, const std::string& key) {
  const std::regex r("\"" + key + "\"\\s*:\\s*([0-9]+)");
  std::smatch m;
  if (!std::regex_search(json, m, r)) throw ToolError("missing KAT field: " + key);
  return static_cast<std::size_t>(std::stoull(m[1].str()));
}

void pass(bool ok, const std::string& name) {
  if (!ok) throw ToolError("test failed: " + name);
  std::cout << "PASS " << name << "\n";
}

Bytes hash_memory(const std::string& algo, const unsigned char* data, std::size_t len, std::size_t outlen = 0) {
  const std::string a = lower(algo);
  if (a == "sha224") return digest_mem_with<CryptoPP::SHA224>(data, len);
  if (a == "sha256") return digest_mem_with<CryptoPP::SHA256>(data, len);
  if (a == "sha384") return digest_mem_with<CryptoPP::SHA384>(data, len);
  if (a == "sha512") return digest_mem_with<CryptoPP::SHA512>(data, len);
  if (a == "sha3-224" || a == "sha3224") return digest_mem_with<CryptoPP::SHA3_224>(data, len);
  if (a == "sha3-256" || a == "sha3256") return digest_mem_with<CryptoPP::SHA3_256>(data, len);
  if (a == "sha3-384" || a == "sha3384") return digest_mem_with<CryptoPP::SHA3_384>(data, len);
  if (a == "sha3-512" || a == "sha3512") return digest_mem_with<CryptoPP::SHA3_512>(data, len);
  if (a == "md5") return digest_mem_with<CryptoPP::Weak::MD5>(data, len);
  if (a == "shake128") return xof_mem_with<CryptoPP::SHAKE128>(data, len, outlen ? outlen : 32);
  if (a == "shake256") return xof_mem_with<CryptoPP::SHAKE256>(data, len, outlen ? outlen : 64);
  throw ToolError("unsupported algorithm: " + algo);
}

Bytes hash_file_mmap(const std::string& algo, const std::string& path, std::size_t outlen = 0) {
#if defined(_WIN32)
  HANDLE file = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) throw ToolError("cannot open input file for mmap: " + path);
  LARGE_INTEGER sz{};
  if (!GetFileSizeEx(file, &sz)) {
    CloseHandle(file);
    throw ToolError("cannot determine mmap file size");
  }
  if (sz.QuadPart == 0) {
    CloseHandle(file);
    return hash_bytes(algo, {}, outlen);
  }
  HANDLE map = CreateFileMappingA(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
  if (!map) {
    CloseHandle(file);
    throw ToolError("cannot create file mapping");
  }
  void* view = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
  if (!view) {
    CloseHandle(map);
    CloseHandle(file);
    throw ToolError("cannot map file view");
  }
  Bytes digest = hash_memory(algo, static_cast<const unsigned char*>(view), static_cast<std::size_t>(sz.QuadPart), outlen);
  UnmapViewOfFile(view);
  CloseHandle(map);
  CloseHandle(file);
  return digest;
#else
  int fd = open(path.c_str(), O_RDONLY);
  if (fd < 0) throw ToolError("cannot open input file for mmap: " + path);
  struct stat st {};
  if (fstat(fd, &st) != 0) {
    close(fd);
    throw ToolError("cannot stat mmap file");
  }
  if (st.st_size == 0) {
    close(fd);
    return hash_bytes(algo, {}, outlen);
  }
  void* view = mmap(nullptr, static_cast<std::size_t>(st.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
  if (view == MAP_FAILED) {
    close(fd);
    throw ToolError("cannot mmap file");
  }
  Bytes digest = hash_memory(algo, static_cast<const unsigned char*>(view), static_cast<std::size_t>(st.st_size), outlen);
  munmap(view, static_cast<std::size_t>(st.st_size));
  close(fd);
  return digest;
#endif
}

void ensure_test_file(const std::string& path, std::size_t size) {
  if (std::filesystem::exists(path) && std::filesystem::file_size(path) == size) return;
  std::filesystem::create_directories(std::filesystem::path(path).parent_path());
  std::ofstream out(path, std::ios::binary);
  if (!out) throw ToolError("cannot create benchmark file: " + path);
  Bytes chunk(kChunk);
  for (std::size_t i = 0; i < chunk.size(); ++i) chunk[i] = static_cast<unsigned char>(i & 0xff);
  std::size_t remaining = size;
  while (remaining) {
    const std::size_t take = std::min(remaining, chunk.size());
    out.write(reinterpret_cast<const char*>(chunk.data()), static_cast<std::streamsize>(take));
    remaining -= take;
  }
}

// Classic 128-byte MD5 collision blocks, safe offline demonstration data.
const char* kMd5Collision1 =
    "d131dd02c5e6eec4693d9a0698aff95c"
    "2fcab58712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e488832571415a"
    "085125e8f7cdc99fd91dbdf280373c5b"
    "d8823e3156348f5bae6dacd436c919c6"
    "dd53e2b487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080a80d1e"
    "c69821bcb6a8839396f9652b6ff72a70";

const char* kMd5Collision2 =
    "d131dd02c5e6eec4693d9a0698aff95c"
    "2fcab50712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e4888325f1415a"
    "085125e8f7cdc99fd91dbd7280373c5b"
    "d8823e3156348f5bae6dacd436c919c6"
    "dd53e23487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080280d1e"
    "c69821bcb6a8839396f965ab6ff72a70";

// Minimal SHA-256 continuation implementation for length-extension demonstration.
constexpr std::array<std::uint32_t, 64> k256 = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

std::uint32_t rotr(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

void sha256_compress(std::array<std::uint32_t, 8>& h, const unsigned char* block) {
  std::array<std::uint32_t, 64> w{};
  for (int i = 0; i < 16; ++i) {
    w[i] = (static_cast<std::uint32_t>(block[i*4]) << 24) |
           (static_cast<std::uint32_t>(block[i*4+1]) << 16) |
           (static_cast<std::uint32_t>(block[i*4+2]) << 8) |
           static_cast<std::uint32_t>(block[i*4+3]);
  }
  for (int i = 16; i < 64; ++i) {
    const std::uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
    const std::uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
    w[i] = w[i-16] + s0 + w[i-7] + s1;
  }
  std::uint32_t a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f=h[5], g=h[6], hh=h[7];
  for (int i = 0; i < 64; ++i) {
    const std::uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
    const std::uint32_t ch = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = hh + S1 + ch + k256[i] + w[i];
    const std::uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = S0 + maj;
    hh=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
  }
  h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

Bytes sha256_padding(std::uint64_t message_len) {
  Bytes p;
  p.push_back(0x80);
  while ((message_len + p.size()) % 64 != 56) p.push_back(0x00);
  const std::uint64_t bits = message_len * 8;
  for (int i = 7; i >= 0; --i) p.push_back(static_cast<unsigned char>((bits >> (8 * i)) & 0xff));
  return p;
}

Bytes sha256_continue(const Bytes& append, const Bytes& digest, std::uint64_t previous_padded_len) {
  if (digest.size() != 32) throw ToolError("SHA-256 MAC must be 32 bytes");
  std::array<std::uint32_t, 8> h{};
  for (int i = 0; i < 8; ++i) {
    h[i] = (static_cast<std::uint32_t>(digest[i*4]) << 24) |
           (static_cast<std::uint32_t>(digest[i*4+1]) << 16) |
           (static_cast<std::uint32_t>(digest[i*4+2]) << 8) |
           static_cast<std::uint32_t>(digest[i*4+3]);
  }
  Bytes data = append;
  Bytes final_pad = sha256_padding(previous_padded_len + append.size());
  data.insert(data.end(), final_pad.begin(), final_pad.end());
  for (std::size_t off = 0; off < data.size(); off += 64) sha256_compress(h, data.data() + off);
  Bytes out;
  for (std::uint32_t x : h) {
    out.push_back(static_cast<unsigned char>((x >> 24) & 0xff));
    out.push_back(static_cast<unsigned char>((x >> 16) & 0xff));
    out.push_back(static_cast<unsigned char>((x >> 8) & 0xff));
    out.push_back(static_cast<unsigned char>(x & 0xff));
  }
  return out;
}

} // namespace

Bytes read_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw ToolError("cannot open input file: " + path);
  in.seekg(0, std::ios::end);
  std::streamoff size = in.tellg();
  in.seekg(0, std::ios::beg);
  Bytes out(static_cast<std::size_t>(size));
  if (!out.empty()) in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
  return out;
}

void write_file(const std::string& path, const Bytes& data) {
  std::ofstream out(path, std::ios::binary);
  if (!out) throw ToolError("cannot open output file: " + path);
  if (!data.empty()) out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

Bytes string_to_bytes(const std::string& text) { return Bytes(text.begin(), text.end()); }
std::string bytes_to_string(const Bytes& data) { return std::string(reinterpret_cast<const char*>(data.data()), data.size()); }

std::string hex_encode(const Bytes& data) {
  std::string out;
  CryptoPP::StringSource ss(data.data(), data.size(), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(out), false));
  return out;
}

Bytes hex_decode(const std::string& text) {
  std::string cleaned;
  for (unsigned char c : text) if (!std::isspace(c)) cleaned.push_back(static_cast<char>(c));
  std::string out;
  CryptoPP::StringSource ss(cleaned, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(out)));
  return string_to_bytes(out);
}

std::string base64_encode(const Bytes& data) {
  std::string out;
  CryptoPP::StringSource ss(data.data(), data.size(), true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(out), false));
  return out;
}

Bytes hash_bytes(const std::string& algo, const Bytes& data, std::size_t outlen) {
  const std::string a = lower(algo);
  if (a == "sha224") return digest_with<CryptoPP::SHA224>(data);
  if (a == "sha256") return digest_with<CryptoPP::SHA256>(data);
  if (a == "sha384") return digest_with<CryptoPP::SHA384>(data);
  if (a == "sha512") return digest_with<CryptoPP::SHA512>(data);
  if (a == "sha3-224" || a == "sha3224") return digest_with<CryptoPP::SHA3_224>(data);
  if (a == "sha3-256" || a == "sha3256") return digest_with<CryptoPP::SHA3_256>(data);
  if (a == "sha3-384" || a == "sha3384") return digest_with<CryptoPP::SHA3_384>(data);
  if (a == "sha3-512" || a == "sha3512") return digest_with<CryptoPP::SHA3_512>(data);
  if (a == "md5") return digest_with<CryptoPP::Weak::MD5>(data);
  if (a == "shake128") return xof_with<CryptoPP::SHAKE128>(data, outlen ? outlen : 32);
  if (a == "shake256") return xof_with<CryptoPP::SHAKE256>(data, outlen ? outlen : 64);
  throw ToolError("unsupported algorithm: " + algo);
}

Bytes hash_file_streamed(const std::string& algo, const std::string& path, std::size_t outlen) {
  const std::string a = lower(algo);
  if (a == "sha224") return digest_file_with<CryptoPP::SHA224>(path);
  if (a == "sha256") return digest_file_with<CryptoPP::SHA256>(path);
  if (a == "sha384") return digest_file_with<CryptoPP::SHA384>(path);
  if (a == "sha512") return digest_file_with<CryptoPP::SHA512>(path);
  if (a == "sha3-224" || a == "sha3224") return digest_file_with<CryptoPP::SHA3_224>(path);
  if (a == "sha3-256" || a == "sha3256") return digest_file_with<CryptoPP::SHA3_256>(path);
  if (a == "sha3-384" || a == "sha3384") return digest_file_with<CryptoPP::SHA3_384>(path);
  if (a == "sha3-512" || a == "sha3512") return digest_file_with<CryptoPP::SHA3_512>(path);
  if (a == "md5") return digest_file_with<CryptoPP::Weak::MD5>(path);
  if (a == "shake128") return xof_file_with<CryptoPP::SHAKE128>(path, outlen ? outlen : 32);
  if (a == "shake256") return xof_file_with<CryptoPP::SHAKE256>(path, outlen ? outlen : 64);
  throw ToolError("unsupported algorithm: " + algo);
}

void run_hash(const HashOptions& options) {
  if (options.algo.empty()) throw ToolError("hash requires --algo");
  if (is_shake(options.algo) && options.outlen == 0) throw ToolError("SHAKE requires --outlen bytes");
  Bytes digest;
  if (!options.input_path.empty()) digest = hash_file_streamed(options.algo, options.input_path, options.outlen);
  else if (!options.text.empty()) digest = hash_bytes(options.algo, string_to_bytes(options.text), options.outlen);
  else throw ToolError("hash requires --in or --text");

  if (options.output_path.empty()) {
    std::cout << hex_encode(digest) << "\n";
    return;
  }
  const std::string enc = lower(options.encode);
  if (enc == "raw") write_file(options.output_path, digest);
  else if (enc == "hex") write_file(options.output_path, string_to_bytes(hex_encode(digest)));
  else if (enc == "base64") write_file(options.output_path, string_to_bytes(base64_encode(digest)));
  else throw ToolError("unsupported encoding: " + options.encode);
  std::cout << "Wrote digest: " << options.output_path << "\n";
}

void run_cert(const CertOptions& options) {
  if (options.input_path.empty()) throw ToolError("cert requires --in");
  CertInfo cert = parse_cert(read_file(options.input_path));
  std::cout << "Subject: " << cert.subject << "\n";
  std::cout << "Issuer: " << cert.issuer << "\n";
  std::cout << "SPKI Algorithm: " << cert.spki_alg << "\n";
  std::cout << "Signature Algorithm: " << cert.sig_alg << "\n";
  std::cout << "Validity Not Before: " << cert.not_before << "\n";
  std::cout << "Validity Not After:  " << cert.not_after << "\n";
  std::cout << "Key Usage: " << (cert.key_usage.empty() ? "(not present)" : cert.key_usage) << "\n";
  std::cout << "SANs: " << (cert.sans.empty() ? "(not present)" : cert.sans) << "\n";
  std::cout << "TBS structure: parsed\n";
  std::cout << "Algorithm consistency: " << (cert.sig_alg.empty() ? "fail" : "ok") << "\n";
  if (options.verify) {
    if (options.issuer_path.empty()) throw ToolError("certificate verification requires --issuer");
    CertInfo issuer = parse_cert(read_file(options.issuer_path));
    const bool ok = verify_cert_sig(cert, issuer);
    if (!ok) throw ToolError("certificate signature verification failed");
    std::cout << "Signature verification: PASS\n";
  } else {
    std::cout << "Signature verification: not requested\n";
  }
}

void run_md5_collision(const std::string& file1, const std::string& file2, const std::string& out_dir) {
  std::string f1 = file1, f2 = file2;
  if (!out_dir.empty()) {
    std::filesystem::create_directories(out_dir);
    f1 = (std::filesystem::path(out_dir) / "md5_collision_1.bin").string();
    f2 = (std::filesystem::path(out_dir) / "md5_collision_2.bin").string();
    write_file(f1, hex_decode(kMd5Collision1));
    write_file(f2, hex_decode(kMd5Collision2));
    std::cout << "Generated benign MD5 collision demo files:\n";
    std::cout << "  " << f1 << "\n";
    std::cout << "  " << f2 << "\n";
  }
  if (f1.empty() || f2.empty()) throw ToolError("md5-collision requires --generate --out-dir or --file1 and --file2");
  Bytes d1 = hash_file_streamed("md5", f1);
  Bytes d2 = hash_file_streamed("md5", f2);
  std::cout << "File 1 MD5: " << hex_encode(d1) << "\n";
  std::cout << "File 2 MD5: " << hex_encode(d2) << "\n";
  std::cout << "File bytes equal: " << (read_file(f1) == read_file(f2) ? "yes" : "no") << "\n";
  if (d1 != d2) throw ToolError("MD5 collision verification failed");
  std::cout << "MD5 collision verification: PASS\n";
}

void run_length_extension(const LengthExtensionOptions& options) {
  LengthExtensionOptions opt = options;
  Bytes mac;
  if (opt.demo) {
    opt.key_len = 9;
    opt.message = "user=guest&role=user";
    opt.append = "&role=admin";
    mac = hash_bytes("sha256", string_to_bytes("secretkey" + opt.message));
    std::cout << "Demo secret key length: " << opt.key_len << "\n";
    std::cout << "Original message: " << opt.message << "\n";
    std::cout << "Original MAC: " << hex_encode(mac) << "\n";
  } else {
    if (opt.mac_hex.empty() || opt.message.empty() || opt.append.empty()) {
      throw ToolError("length-extension requires --mac, --message, --append, --key-len or --demo");
    }
    mac = hex_decode(opt.mac_hex);
  }
  Bytes msg = string_to_bytes(opt.message);
  Bytes app = string_to_bytes(opt.append);
  Bytes glue = sha256_padding(static_cast<std::uint64_t>(opt.key_len + msg.size()));
  const std::uint64_t previous_padded_len = static_cast<std::uint64_t>(opt.key_len + msg.size() + glue.size());
  Bytes forged_mac = sha256_continue(app, mac, previous_padded_len);
  Bytes forged_msg = msg;
  forged_msg.insert(forged_msg.end(), glue.begin(), glue.end());
  forged_msg.insert(forged_msg.end(), app.begin(), app.end());
  std::cout << "Assumed key length: " << opt.key_len << "\n";
  std::cout << "Append data: " << opt.append << "\n";
  std::cout << "Glue padding hex: " << hex_encode(glue) << "\n";
  std::cout << "Forged message hex: " << hex_encode(forged_msg) << "\n";
  std::cout << "Forged MAC: " << hex_encode(forged_mac) << "\n";
  if (opt.demo) {
    Bytes real_input = string_to_bytes("secretkey");
    real_input.insert(real_input.end(), forged_msg.begin(), forged_msg.end());
    Bytes real = hash_bytes("sha256", real_input);
    pass(real == forged_mac, "length-extension forged MAC verifies against naive MAC");
  }
}

void run_benchmark(const BenchOptions& options) {
  const int runs = std::max(1, options.runs);
  const int ops = std::max(1, options.ops);
  std::vector<std::pair<std::string, std::size_t>> sizes = {{"1 MiB", 1024 * 1024}, {"100 MiB", 100ULL * 1024ULL * 1024ULL}};
  if (options.include_1gib) sizes.push_back({"1 GiB", 1024ULL * 1024ULL * 1024ULL});
  std::vector<std::string> algos = {"sha256", "sha512", "sha3-256", "sha3-512"};

  std::cout << "============================================================\n";
  std::cout << "HASH BENCHMARK RESULTS\n";
  std::cout << "Runs: " << runs << " | Ops/run: " << ops << "\n";
  std::cout << "============================================================\n";
  std::cout << std::left << std::setw(10) << "Algo" << std::setw(10) << "Size"
            << std::right << std::setw(12) << "MB/s"
            << std::setw(12) << "Mean ms"
            << std::setw(12) << "Median"
            << std::setw(12) << "Stddev"
            << std::setw(12) << "CI95" << "\n";
  std::cout << "--------------------------------------------------------------------------------\n";
  for (const auto& sz : sizes) {
    Bytes data(sz.second);
    for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<unsigned char>(i);
    for (const std::string& algo : algos) {
      (void)hash_bytes(algo, Bytes(4096, 0xaa)); // warm-up
      std::vector<double> per_op_ms;
      for (int r = 0; r < runs; ++r) {
        auto s = Clock::now();
        Bytes d;
        for (int op = 0; op < ops; ++op) d = hash_bytes(algo, data);
        auto e = Clock::now();
        if (d.empty()) throw ToolError("benchmark digest failed");
        per_op_ms.push_back(ms_between(s, e) / static_cast<double>(ops));
      }
      const double m = mean(per_op_ms);
      const double mbps = (static_cast<double>(sz.second) / (1024.0 * 1024.0)) / (m / 1000.0);
      const double sd = stdev(per_op_ms);
      const double ci = 1.96 * sd / std::sqrt(static_cast<double>(per_op_ms.size()));
      std::cout << std::left << std::setw(10) << algo << std::setw(10) << sz.first
                << std::right << std::setw(12) << std::fixed << std::setprecision(2) << mbps
                << std::setw(12) << m
                << std::setw(12) << median(per_op_ms)
                << std::setw(12) << sd
                << std::setw(12) << ci << "\n";
    }
  }
}

void run_io_benchmark(const BenchOptions& options) {
  const int runs = std::max(1, options.runs);
  const int ops = std::max(1, options.ops);
  std::vector<std::pair<std::string, std::size_t>> sizes = {{"1 MiB", 1024 * 1024}, {"100 MiB", 100ULL * 1024ULL * 1024ULL}};
  if (options.include_1gib) sizes.push_back({"1 GiB", 1024ULL * 1024ULL * 1024ULL});
  std::vector<std::string> algos = {"sha256", "sha512", "sha3-256", "sha3-512"};

  std::cout << "============================================================\n";
  std::cout << "HASH STREAM VS MEMORY-MAPPED I/O BENCHMARK\n";
  std::cout << "Runs: " << runs << " | Ops/run: " << ops << "\n";
  std::cout << "============================================================\n";
  std::cout << std::left << std::setw(10) << "Algo" << std::setw(10) << "Size" << std::setw(10) << "I/O"
            << std::right << std::setw(12) << "MB/s"
            << std::setw(12) << "Mean ms"
            << std::setw(12) << "Median"
            << std::setw(12) << "Stddev"
            << std::setw(12) << "CI95" << "\n";
  std::cout << "------------------------------------------------------------------------------------------\n";
  for (const auto& sz : sizes) {
    const std::string safe = sz.first == "1 MiB" ? "1mib" : (sz.first == "100 MiB" ? "100mib" : "1gib");
    const std::string path = (std::filesystem::path("testing") / ("bench_" + safe + ".bin")).string();
    ensure_test_file(path, sz.second);
    for (const std::string& algo : algos) {
      for (const std::string& mode : {"stream", "mmap"}) {
        std::vector<double> per_op_ms;
        for (int r = 0; r < runs; ++r) {
          auto s = Clock::now();
          Bytes d;
          for (int op = 0; op < ops; ++op) {
            d = (mode == "stream") ? hash_file_streamed(algo, path) : hash_file_mmap(algo, path);
          }
          auto e = Clock::now();
          if (d.empty()) throw ToolError("I/O benchmark digest failed");
          per_op_ms.push_back(ms_between(s, e) / static_cast<double>(ops));
        }
        const double m = mean(per_op_ms);
        const double mbps = (static_cast<double>(sz.second) / (1024.0 * 1024.0)) / (m / 1000.0);
        const double sd = stdev(per_op_ms);
        const double ci = 1.96 * sd / std::sqrt(static_cast<double>(per_op_ms.size()));
        std::cout << std::left << std::setw(10) << algo << std::setw(10) << sz.first << std::setw(10) << mode
                  << std::right << std::setw(12) << std::fixed << std::setprecision(2) << mbps
                  << std::setw(12) << m
                  << std::setw(12) << median(per_op_ms)
                  << std::setw(12) << sd
                  << std::setw(12) << ci << "\n";
      }
    }
  }
}

void run_kat(const std::string& path) {
  if (path.empty()) throw ToolError("--kat requires vector JSON path");
  const std::string json = bytes_to_string(read_file(path));
  std::cout << "============================================================\n";
  std::cout << "HASHTOOL KNOWN ANSWER TESTS\n";
  std::cout << "============================================================\n";
  std::cout << "Vector file: " << path << "\n";
  pass(hex_encode(hash_bytes("sha256", string_to_bytes("abc"))) == json_string(json, "sha256_abc"), "SHA-256 abc");
  pass(hex_encode(hash_bytes("sha512", string_to_bytes("abc"))) == json_string(json, "sha512_abc"), "SHA-512 abc");
  pass(hex_encode(hash_bytes("sha3-256", string_to_bytes("abc"))) == json_string(json, "sha3_256_abc"), "SHA3-256 abc");
  pass(hex_encode(hash_bytes("sha3-512", string_to_bytes("abc"))) == json_string(json, "sha3_512_abc"), "SHA3-512 abc");
  pass(hex_encode(hash_bytes("shake128", string_to_bytes("abc"), json_int(json, "shake128_outlen"))) == json_string(json, "shake128_abc"), "SHAKE128 abc");
  pass(hex_encode(hash_bytes("shake256", string_to_bytes("abc"), json_int(json, "shake256_outlen"))) == json_string(json, "shake256_abc"), "SHAKE256 abc");
  std::cout << "Summary: all hash KATs passed\n";
}

void run_selftest() {
  pass(hex_encode(hash_bytes("sha256", string_to_bytes("abc"))) ==
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
       "SHA-256 selftest");
  run_md5_collision("", "", "testing");
  LengthExtensionOptions le;
  le.demo = true;
  run_length_extension(le);
  std::cout << "Summary: all Lab 4 selftests passed\n";
}

} // namespace hashtool
