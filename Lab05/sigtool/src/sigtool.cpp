#include "sigtool.hpp"

#include <cryptopp/asn.h>
#include <cryptopp/base64.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/hmac.h>
#include <cryptopp/integer.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pssr.h>
#include <cryptopp/queue.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>

namespace sigtool {
namespace {

using Clock = std::chrono::steady_clock;

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

void require(bool condition, const std::string& message) {
  if (!condition) throw ToolError(message);
}

Bytes queue_to_bytes(CryptoPP::BufferedTransformation& queue) {
  Bytes out(queue.MaxRetrievable());
  if (!out.empty()) queue.Get(out.data(), out.size());
  return out;
}

template <typename T>
Bytes save_der(const T& key) {
  CryptoPP::ByteQueue q;
  const_cast<T&>(key).Save(q);
  return queue_to_bytes(q);
}

template <typename T>
T load_der_key(const Bytes& der) {
  CryptoPP::ByteQueue q;
  q.Put(der.data(), der.size());
  q.MessageEnd();
  T key;
  key.Load(q);
  return key;
}

std::string pem_label_for(const std::string& algo, bool priv) {
  if (algo == "rsa-pss-3072") return priv ? "RSA PRIVATE KEY" : "RSA PUBLIC KEY";
  return priv ? "EC PRIVATE KEY" : "EC PUBLIC KEY";
}

std::string wrap_pem(const Bytes& der, const std::string& label) {
  std::string b64 = base64_encode(der);
  std::ostringstream out;
  out << "-----BEGIN " << label << "-----\n";
  for (std::size_t i = 0; i < b64.size(); i += 64) out << b64.substr(i, 64) << "\n";
  out << "-----END " << label << "-----\n";
  return out.str();
}

bool looks_pem(const Bytes& data) {
  std::string s(data.begin(), data.end());
  return s.find("-----BEGIN ") != std::string::npos;
}

Bytes unwrap_pem(const Bytes& data) {
  std::string s(data.begin(), data.end());
  const auto begin = s.find("-----BEGIN ");
  const auto header_end = s.find("-----", begin + 11);
  const auto body_start = s.find('\n', header_end);
  const auto end = s.find("-----END ", body_start);
  require(begin != std::string::npos && header_end != std::string::npos &&
              body_start != std::string::npos && end != std::string::npos,
          "malformed PEM file");
  std::string body = s.substr(body_start, end - body_start);
  body.erase(std::remove_if(body.begin(), body.end(),
                            [](unsigned char c) { return std::isspace(c) != 0; }),
             body.end());
  return base64_decode(body);
}

Bytes read_key_material(const std::string& path) {
  Bytes data = read_file(path);
  return looks_pem(data) ? unwrap_pem(data) : data;
}

void write_key_material(const std::string& path, const Bytes& der, const std::string& format,
                        const std::string& label) {
  const std::string f = lower(format);
  if (f == "der") {
    write_file(path, der);
  } else if (f == "pem") {
    const std::string pem = wrap_pem(der, label);
    write_file(path, Bytes(pem.begin(), pem.end()));
  } else {
    throw ToolError("unsupported key format: " + format);
  }
}

Bytes message_from(const std::string& path, const std::string& text) {
  if (!path.empty() && !text.empty()) throw ToolError("use only one input source: --in or --text");
  if (!path.empty()) return read_file(path);
  if (!text.empty()) return string_to_bytes(text);
  throw ToolError("missing message input: use --in or --text");
}

void validate_algo(const std::string& algo) {
  const std::string a = lower(algo);
  if (a != "ecdsa-p256" && a != "ecdsa-p384" && a != "rsa-pss-3072") {
    throw ToolError("unsupported algorithm: " + algo);
  }
}

void validate_hash_for_algo(const std::string& algo, const std::string& hash) {
  const std::string a = lower(algo);
  const std::string h = lower(hash);
  if (a == "ecdsa-p384") {
    if (h != "sha256" && h != "sha384") throw ToolError("ECDSA-P384 supports sha256 or sha384");
  } else {
    if (h != "sha256") throw ToolError(a + " requires sha256 in this lab");
  }
}

CryptoPP::OID curve_oid(const std::string& algo) {
  if (lower(algo) == "ecdsa-p384") return CryptoPP::ASN1::secp384r1();
  return CryptoPP::ASN1::secp256r1();
}

class DeterministicHmacRng : public CryptoPP::RandomNumberGenerator {
public:
  DeterministicHmacRng(const Bytes& key_material, const Bytes& message, const std::string& hash) {
    if (lower(hash) == "sha384") {
      CryptoPP::SHA384 d;
      seed_.resize(d.DigestSize());
      d.Update(key_material.data(), key_material.size());
      d.Update(message.data(), message.size());
      d.Final(seed_.data());
    } else {
      CryptoPP::SHA256 d;
      seed_.resize(d.DigestSize());
      d.Update(key_material.data(), key_material.size());
      d.Update(message.data(), message.size());
      d.Final(seed_.data());
    }
  }

  std::string AlgorithmName() const override { return "deterministic-hmac-drbg"; }

  void GenerateBlock(CryptoPP::byte* output, std::size_t size) override {
    std::size_t produced = 0;
    while (produced < size) {
      CryptoPP::HMAC<CryptoPP::SHA256> hmac(seed_.data(), seed_.size());
      CryptoPP::byte ctr[8];
      for (int i = 7; i >= 0; --i) {
        ctr[i] = static_cast<CryptoPP::byte>(counter_ & 0xff);
        counter_ >>= 8;
      }
      ++block_index_;
      std::uint64_t c = block_index_;
      for (int i = 7; i >= 0; --i) {
        ctr[i] = static_cast<CryptoPP::byte>(c & 0xff);
        c >>= 8;
      }
      CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
      hmac.Update(ctr, sizeof(ctr));
      hmac.Final(digest);
      const std::size_t take = std::min<std::size_t>(sizeof(digest), size - produced);
      std::copy(digest, digest + take, output + produced);
      produced += take;
    }
  }

private:
  Bytes seed_;
  std::uint64_t counter_ = 0;
  std::uint64_t block_index_ = 0;
};

Bytes der_int(CryptoPP::Integer value) {
  if (value == 0) return Bytes{0};
  const std::size_t n = value.MinEncodedSize(CryptoPP::Integer::UNSIGNED);
  Bytes out(n);
  value.Encode(out.data(), out.size(), CryptoPP::Integer::UNSIGNED);
  if (!out.empty() && (out[0] & 0x80) != 0) out.insert(out.begin(), 0);
  return out;
}

void der_len(Bytes& out, std::size_t len) {
  if (len < 128) {
    out.push_back(static_cast<unsigned char>(len));
    return;
  }
  Bytes tmp;
  while (len > 0) {
    tmp.push_back(static_cast<unsigned char>(len & 0xff));
    len >>= 8;
  }
  out.push_back(static_cast<unsigned char>(0x80 | tmp.size()));
  for (auto it = tmp.rbegin(); it != tmp.rend(); ++it) out.push_back(*it);
}

Bytes ecdsa_raw_to_der(const Bytes& raw) {
  require(raw.size() % 2 == 0 && !raw.empty(), "invalid raw ECDSA signature length");
  const std::size_t half = raw.size() / 2;
  CryptoPP::Integer r(raw.data(), half, CryptoPP::Integer::UNSIGNED);
  CryptoPP::Integer s(raw.data() + half, half, CryptoPP::Integer::UNSIGNED);
  Bytes rb = der_int(r);
  Bytes sb = der_int(s);
  Bytes body;
  body.push_back(0x02);
  der_len(body, rb.size());
  body.insert(body.end(), rb.begin(), rb.end());
  body.push_back(0x02);
  der_len(body, sb.size());
  body.insert(body.end(), sb.begin(), sb.end());
  Bytes out;
  out.push_back(0x30);
  der_len(out, body.size());
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

std::size_t read_der_len(const Bytes& in, std::size_t& pos) {
  require(pos < in.size(), "truncated DER length");
  unsigned char b = in[pos++];
  if ((b & 0x80) == 0) return b;
  const std::size_t count = b & 0x7f;
  require(count > 0 && count <= sizeof(std::size_t) && pos + count <= in.size(), "invalid DER length");
  std::size_t len = 0;
  for (std::size_t i = 0; i < count; ++i) len = (len << 8) | in[pos++];
  return len;
}

Bytes der_to_fixed(const Bytes& v, std::size_t width) {
  std::size_t start = 0;
  while (start + 1 < v.size() && v[start] == 0) ++start;
  require(v.size() - start <= width, "DER integer does not fit ECDSA component width");
  Bytes out(width, 0);
  std::copy(v.begin() + static_cast<std::ptrdiff_t>(start), v.end(),
            out.begin() + static_cast<std::ptrdiff_t>(width - (v.size() - start)));
  return out;
}

Bytes ecdsa_der_to_raw(const Bytes& der, std::size_t width) {
  std::size_t pos = 0;
  require(pos < der.size() && der[pos++] == 0x30, "ECDSA DER signature must be a sequence");
  const std::size_t seq_len = read_der_len(der, pos);
  require(pos + seq_len == der.size(), "invalid ECDSA DER sequence length");
  require(pos < der.size() && der[pos++] == 0x02, "missing ECDSA r integer");
  const std::size_t r_len = read_der_len(der, pos);
  require(pos + r_len <= der.size(), "truncated ECDSA r integer");
  Bytes r(der.begin() + static_cast<std::ptrdiff_t>(pos),
          der.begin() + static_cast<std::ptrdiff_t>(pos + r_len));
  pos += r_len;
  require(pos < der.size() && der[pos++] == 0x02, "missing ECDSA s integer");
  const std::size_t s_len = read_der_len(der, pos);
  require(pos + s_len == der.size(), "truncated ECDSA s integer");
  Bytes s(der.begin() + static_cast<std::ptrdiff_t>(pos), der.end());
  Bytes out = der_to_fixed(r, width);
  Bytes sf = der_to_fixed(s, width);
  out.insert(out.end(), sf.begin(), sf.end());
  return out;
}

Bytes encode_signature_for_output(const Bytes& raw, const std::string& encode, const std::string& algo) {
  const std::string e = lower(encode);
  if (e == "raw") return raw;
  if (e == "hex") {
    std::string h = hex_encode(raw);
    return Bytes(h.begin(), h.end());
  }
  if (e == "base64") {
    std::string b = base64_encode(raw);
    return Bytes(b.begin(), b.end());
  }
  if (e == "der") {
    require(lower(algo).rfind("ecdsa-", 0) == 0, "DER signature encoding is only for ECDSA");
    return ecdsa_raw_to_der(raw);
  }
  throw ToolError("unsupported signature encoding: " + encode);
}

Bytes decode_signature_from_input(const Bytes& data, const std::string& encode, const std::string& algo) {
  const std::string e = lower(encode);
  if (e == "raw") return data;
  if (e == "hex") return hex_decode(std::string(data.begin(), data.end()));
  if (e == "base64") return base64_decode(std::string(data.begin(), data.end()));
  if (e == "der") {
    const std::size_t width = lower(algo) == "ecdsa-p384" ? 48 : 32;
    return ecdsa_der_to_raw(data, width);
  }
  throw ToolError("unsupported signature encoding: " + encode);
}

template <typename Signer>
Bytes sign_with(Signer& signer, CryptoPP::RandomNumberGenerator& rng, const Bytes& msg) {
  Bytes sig(signer.MaxSignatureLength());
  const std::size_t len = signer.SignMessage(rng, msg.data(), msg.size(), sig.data());
  sig.resize(len);
  return sig;
}

template <typename Verifier>
bool verify_with(Verifier& verifier, const Bytes& msg, const Bytes& sig) {
  return verifier.VerifyMessage(msg.data(), msg.size(), sig.data(), sig.size());
}

Bytes sign_message(const std::string& algo, const std::string& hash, const Bytes& priv_der,
                   const Bytes& msg) {
  const std::string a = lower(algo);
  const std::string h = lower(hash);
  CryptoPP::AutoSeededRandomPool rng;
  if (a == "rsa-pss-3072") {
    auto key = load_der_key<CryptoPP::RSA::PrivateKey>(priv_der);
    CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Signer signer(key);
    return sign_with(signer, rng, msg);
  }
  if (a == "ecdsa-p384" && h == "sha384") {
    auto key = load_der_key<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PrivateKey>(priv_der);
    DeterministicHmacRng det(priv_der, msg, h);
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::Signer signer(key);
    return sign_with(signer, det, msg);
  }
  if (a == "ecdsa-p384") {
    auto key = load_der_key<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey>(priv_der);
    DeterministicHmacRng det(priv_der, msg, h);
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(key);
    return sign_with(signer, det, msg);
  }
  auto key = load_der_key<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey>(priv_der);
  DeterministicHmacRng det(priv_der, msg, h);
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(key);
  return sign_with(signer, det, msg);
}

bool verify_message(const std::string& algo, const std::string& hash, const Bytes& pub_der,
                    const Bytes& msg, const Bytes& sig) {
  const std::string a = lower(algo);
  const std::string h = lower(hash);
  if (a == "rsa-pss-3072") {
    auto key = load_der_key<CryptoPP::RSA::PublicKey>(pub_der);
    CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Verifier verifier(key);
    return verify_with(verifier, msg, sig);
  }
  if (a == "ecdsa-p384" && h == "sha384") {
    auto key = load_der_key<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PublicKey>(pub_der);
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::Verifier verifier(key);
    return verify_with(verifier, msg, sig);
  }
  if (a == "ecdsa-p384") {
    auto key = load_der_key<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey>(pub_der);
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(key);
    return verify_with(verifier, msg, sig);
  }
  auto key = load_der_key<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey>(pub_der);
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(key);
  return verify_with(verifier, msg, sig);
}

struct Stats {
  double mean = 0;
  double median = 0;
  double stddev = 0;
  double ci95 = 0;
};

Stats stats(std::vector<double> values) {
  require(!values.empty(), "cannot compute stats for empty sample");
  Stats s;
  s.mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
  std::sort(values.begin(), values.end());
  if (values.size() % 2 == 0) {
    s.median = (values[values.size() / 2 - 1] + values[values.size() / 2]) / 2.0;
  } else {
    s.median = values[values.size() / 2];
  }
  double sum = 0;
  for (double v : values) sum += (v - s.mean) * (v - s.mean);
  s.stddev = values.size() > 1 ? std::sqrt(sum / (values.size() - 1)) : 0;
  s.ci95 = values.size() > 1 ? 1.96 * s.stddev / std::sqrt(static_cast<double>(values.size())) : 0;
  return s;
}

Bytes sample_message(std::size_t size) {
  Bytes msg(size);
  for (std::size_t i = 0; i < size; ++i) msg[i] = static_cast<unsigned char>((i * 131 + 17) & 0xff);
  return msg;
}

CryptoPP::Integer modinv(CryptoPP::Integer a, CryptoPP::Integer m) {
  CryptoPP::Integer t = 0, new_t = 1;
  CryptoPP::Integer r = m, new_r = a % m;
  while (new_r != 0) {
    CryptoPP::Integer q = r / new_r;
    CryptoPP::Integer tmp = t - q * new_t;
    t = new_t;
    new_t = tmp;
    tmp = r - q * new_r;
    r = new_r;
    new_r = tmp;
  }
  require(r == 1, "value is not invertible");
  if (t < 0) t += m;
  return t;
}

CryptoPP::Integer pow_mod(CryptoPP::Integer base, CryptoPP::Integer exp, const CryptoPP::Integer& mod) {
  CryptoPP::Integer result = 1;
  base %= mod;
  while (exp > 0) {
    if (exp.IsOdd()) result = (result * base) % mod;
    exp >>= 1;
    base = (base * base) % mod;
  }
  return result;
}

struct ToyPoint {
  CryptoPP::Integer x;
  CryptoPP::Integer y;
  bool inf = false;
};

CryptoPP::Integer modp(CryptoPP::Integer v, const CryptoPP::Integer& p) {
  v %= p;
  if (v < 0) v += p;
  return v;
}

ToyPoint toy_add(const ToyPoint& p1, const ToyPoint& p2) {
  const CryptoPP::Integer p = 97;
  const CryptoPP::Integer a = 2;
  if (p1.inf) return p2;
  if (p2.inf) return p1;
  if (p1.x == p2.x && modp(p1.y + p2.y, p) == 0) return ToyPoint{0, 0, true};
  CryptoPP::Integer lambda;
  if (p1.x == p2.x && p1.y == p2.y) {
    lambda = modp((3 * p1.x * p1.x + a) * modinv(2 * p1.y, p), p);
  } else {
    lambda = modp((p2.y - p1.y) * modinv(p2.x - p1.x, p), p);
  }
  ToyPoint r;
  r.x = modp(lambda * lambda - p1.x - p2.x, p);
  r.y = modp(lambda * (p1.x - r.x) - p1.y, p);
  return r;
}

ToyPoint toy_mul(CryptoPP::Integer k, ToyPoint point) {
  ToyPoint acc{0, 0, true};
  while (k > 0) {
    if (k.IsOdd()) acc = toy_add(acc, point);
    point = toy_add(point, point);
    k >>= 1;
  }
  return acc;
}

Bytes mgf1_sha256(const Bytes& seed, std::size_t len) {
  Bytes out;
  std::uint32_t counter = 0;
  while (out.size() < len) {
    CryptoPP::SHA256 h;
    h.Update(seed.data(), seed.size());
    CryptoPP::byte c[4] = {
        static_cast<CryptoPP::byte>((counter >> 24) & 0xff),
        static_cast<CryptoPP::byte>((counter >> 16) & 0xff),
        static_cast<CryptoPP::byte>((counter >> 8) & 0xff),
        static_cast<CryptoPP::byte>(counter & 0xff)};
    h.Update(c, sizeof(c));
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
    h.Final(digest);
    const std::size_t take = std::min<std::size_t>(sizeof(digest), len - out.size());
    out.insert(out.end(), digest, digest + take);
    ++counter;
  }
  return out;
}

Bytes pss_encode_demo(const Bytes& msg, const Bytes& salt, std::size_t em_bits) {
  const std::size_t h_len = CryptoPP::SHA256::DIGESTSIZE;
  const std::size_t em_len = (em_bits + 7) / 8;
  require(em_len >= h_len + salt.size() + 2, "encoded message too short for PSS");
  CryptoPP::SHA256 h;
  CryptoPP::byte m_hash[CryptoPP::SHA256::DIGESTSIZE];
  h.Update(msg.data(), msg.size());
  h.Final(m_hash);
  Bytes m_prime(8, 0);
  m_prime.insert(m_prime.end(), m_hash, m_hash + h_len);
  m_prime.insert(m_prime.end(), salt.begin(), salt.end());
  CryptoPP::SHA256 hp;
  CryptoPP::byte H[CryptoPP::SHA256::DIGESTSIZE];
  hp.Update(m_prime.data(), m_prime.size());
  hp.Final(H);
  const std::size_t ps_len = em_len - salt.size() - h_len - 2;
  Bytes db(ps_len, 0);
  db.push_back(0x01);
  db.insert(db.end(), salt.begin(), salt.end());
  Bytes mask = mgf1_sha256(Bytes(H, H + h_len), em_len - h_len - 1);
  for (std::size_t i = 0; i < db.size(); ++i) db[i] ^= mask[i];
  const int unused_bits = static_cast<int>(8 * em_len - em_bits);
  if (unused_bits > 0) db[0] &= static_cast<unsigned char>(0xff >> unused_bits);
  Bytes em = db;
  em.insert(em.end(), H, H + h_len);
  em.push_back(0xbc);
  return em;
}

void self_sign_verify(const std::string& algo, const std::string& hash) {
  CryptoPP::AutoSeededRandomPool rng;
  Bytes msg = string_to_bytes("Lab 5 signature self-test message");
  Bytes priv_der;
  Bytes pub_der;
  if (algo == "rsa-pss-3072") {
    CryptoPP::RSA::PrivateKey priv;
    priv.GenerateRandomWithKeySize(rng, 3072);
    CryptoPP::RSA::PublicKey pub(priv);
    priv_der = save_der(priv);
    pub_der = save_der(pub);
  } else if (algo == "ecdsa-p384") {
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PrivateKey priv;
    priv.Initialize(rng, CryptoPP::ASN1::secp384r1());
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PublicKey pub;
    priv.MakePublicKey(pub);
    priv_der = save_der(priv);
    pub_der = save_der(pub);
  } else {
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey priv;
    priv.Initialize(rng, CryptoPP::ASN1::secp256r1());
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey pub;
    priv.MakePublicKey(pub);
    priv_der = save_der(priv);
    pub_der = save_der(pub);
  }
  Bytes sig = sign_message(algo, hash, priv_der, msg);
  require(verify_message(algo, hash, pub_der, msg, sig), algo + " valid signature failed");
  msg[0] ^= 1;
  require(!verify_message(algo, hash, pub_der, msg, sig), algo + " modified message verified");
}

} // namespace

Bytes read_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw ToolError("cannot open input file: " + path);
  return Bytes(std::istreambuf_iterator<char>(in), {});
}

void write_file(const std::string& path, const Bytes& data) {
  std::ofstream out(path, std::ios::binary);
  if (!out) throw ToolError("cannot open output file: " + path);
  out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

Bytes string_to_bytes(const std::string& text) { return Bytes(text.begin(), text.end()); }

std::string hex_encode(const Bytes& data) {
  std::string out;
  CryptoPP::StringSource ss(data.data(), data.size(), true,
                            new CryptoPP::HexEncoder(new CryptoPP::StringSink(out), false));
  return out;
}

Bytes hex_decode(const std::string& text) {
  std::string clean;
  for (unsigned char c : text) {
    if (!std::isspace(c)) clean.push_back(static_cast<char>(c));
  }
  std::string out;
  CryptoPP::StringSource ss(clean, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(out)));
  return Bytes(out.begin(), out.end());
}

std::string base64_encode(const Bytes& data) {
  std::string out;
  CryptoPP::StringSource ss(data.data(), data.size(), true,
                            new CryptoPP::Base64Encoder(new CryptoPP::StringSink(out), false));
  return out;
}

Bytes base64_decode(const std::string& text) {
  std::string clean;
  for (unsigned char c : text) {
    if (!std::isspace(c)) clean.push_back(static_cast<char>(c));
  }
  std::string out;
  CryptoPP::StringSource ss(clean, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(out)));
  return Bytes(out.begin(), out.end());
}

void run_keygen(const KeygenOptions& options) {
  const std::string algo = lower(options.algo);
  validate_algo(algo);
  require(!options.pub_path.empty() && !options.priv_path.empty(), "keygen requires --pub and --priv");

  CryptoPP::AutoSeededRandomPool rng;
  Bytes priv_der;
  Bytes pub_der;
  if (algo == "rsa-pss-3072") {
    CryptoPP::RSA::PrivateKey priv;
    priv.GenerateRandomWithKeySize(rng, 3072);
    CryptoPP::RSA::PublicKey pub(priv);
    require(priv.Validate(rng, 3), "generated RSA private key failed validation");
    require(pub.Validate(rng, 3), "generated RSA public key failed validation");
    priv_der = save_der(priv);
    pub_der = save_der(pub);
  } else if (algo == "ecdsa-p384") {
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PrivateKey priv;
    priv.Initialize(rng, curve_oid(algo));
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PublicKey pub;
    priv.MakePublicKey(pub);
    require(priv.Validate(rng, 3), "generated ECDSA-P384 private key failed validation");
    require(pub.Validate(rng, 3), "generated ECDSA-P384 public key failed validation");
    priv_der = save_der(priv);
    pub_der = save_der(pub);
  } else {
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey priv;
    priv.Initialize(rng, curve_oid(algo));
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey pub;
    priv.MakePublicKey(pub);
    require(priv.Validate(rng, 3), "generated ECDSA-P256 private key failed validation");
    require(pub.Validate(rng, 3), "generated ECDSA-P256 public key failed validation");
    priv_der = save_der(priv);
    pub_der = save_der(pub);
  }
  write_key_material(options.priv_path, priv_der, options.format, pem_label_for(algo, true));
  write_key_material(options.pub_path, pub_der, options.format, pem_label_for(algo, false));
  std::cout << "Generated " << algo << " key pair\n"
            << "Private key: " << options.priv_path << "\n"
            << "Public key : " << options.pub_path << "\n";
}

void run_sign(const SignOptions& options) {
  const std::string algo = lower(options.algo);
  const std::string hash = lower(options.hash);
  validate_algo(algo);
  validate_hash_for_algo(algo, hash);
  require(!options.priv_path.empty(), "sign requires --priv");
  Bytes msg = message_from(options.input_path, options.text);
  Bytes priv_der = read_key_material(options.priv_path);
  Bytes raw = sign_message(algo, hash, priv_der, msg);
  Bytes out = encode_signature_for_output(raw, options.encode, algo);
  if (options.output_path.empty()) {
    std::cout << hex_encode(raw) << "\n";
  } else {
    write_file(options.output_path, out);
    std::cout << "Wrote signature: " << options.output_path << "\n"
              << "Algorithm      : " << algo << "\n"
              << "Hash           : " << hash << "\n"
              << "Encoding       : " << lower(options.encode) << "\n"
              << "Raw size       : " << raw.size() << " bytes\n";
  }
}

void run_verify(const VerifyOptions& options) {
  const std::string algo = lower(options.algo);
  const std::string hash = lower(options.hash);
  validate_algo(algo);
  validate_hash_for_algo(algo, hash);
  require(!options.pub_path.empty(), "verify requires --pub");
  require(!options.sig_path.empty(), "verify requires --sig");
  Bytes msg = message_from(options.input_path, options.text);
  Bytes pub_der = read_key_material(options.pub_path);
  Bytes sig = decode_signature_from_input(read_file(options.sig_path), options.encode, algo);
  const bool ok = verify_message(algo, hash, pub_der, msg, sig);
  if (!ok) throw ToolError("signature verification failed");
  std::cout << "Signature verification: PASS\n"
            << "Algorithm             : " << algo << "\n"
            << "Hash                  : " << hash << "\n"
            << "Signature size        : " << sig.size() << " bytes\n";
}

void run_batch_verify(const BatchOptions& options) {
  require(!options.manifest_path.empty(), "batch-verify requires --manifest");
  std::ifstream in(options.manifest_path);
  if (!in) throw ToolError("cannot open manifest: " + options.manifest_path);
  std::string line;
  int total = 0;
  int passed = 0;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    std::vector<std::string> parts;
    std::stringstream ss(line);
    std::string p;
    while (std::getline(ss, p, '|')) parts.push_back(p);
    require(parts.size() == 6, "manifest line must have 6 fields: " + line);
    ++total;
    try {
      Bytes msg = read_file(parts[2]);
      Bytes pub_der = read_key_material(parts[1]);
      Bytes sig = decode_signature_from_input(read_file(parts[3]), parts[5], parts[0]);
      bool ok = verify_message(lower(parts[0]), lower(parts[4]), pub_der, msg, sig);
      if (ok) ++passed;
      std::cout << (ok ? "PASS " : "FAIL ") << parts[2] << "\n";
    } catch (const std::exception& e) {
      std::cout << "FAIL " << parts[2] << " (" << e.what() << ")\n";
    }
  }
  std::cout << "Batch verification summary: " << passed << "/" << total << " passed\n";
  if (passed != total) throw ToolError("one or more batch signatures failed");
}

void run_benchmark(const BenchOptions& options) {
  require(options.runs > 0 && options.ops > 0, "runs and ops must be positive");
  const std::vector<std::pair<std::string, std::string>> algos = {
      {"ecdsa-p256", "sha256"}, {"ecdsa-p384", "sha384"}, {"rsa-pss-3072", "sha256"}};
  const std::vector<std::pair<std::string, std::size_t>> sizes = {
      {"1 KiB", 1024}, {"16 KiB", 16 * 1024}, {"1 MiB", 1024 * 1024}, {"8 MiB", 8 * 1024 * 1024}};

  std::cout << "============================================================\n";
  std::cout << "SIGNATURE BENCHMARK RESULTS\n";
  std::cout << "Runs: " << options.runs << " | Ops/run: " << options.ops << "\n";
  std::cout << "============================================================\n";
  std::cout << std::left << std::setw(14) << "Algo" << std::setw(8) << "Size"
            << std::right << std::setw(12) << "Keygen ms" << std::setw(12) << "Sign ms"
            << std::setw(12) << "Verify ms" << std::setw(12) << "Sign/s"
            << std::setw(12) << "Verify/s" << std::setw(10) << "Sig bytes"
            << std::setw(10) << "CI95" << "\n";
  std::cout << std::string(102, '-') << "\n";

  for (const auto& ah : algos) {
    const std::string algo = ah.first;
    const std::string hash = ah.second;
    CryptoPP::AutoSeededRandomPool rng;
    std::vector<double> keygen_ms;
    Bytes priv_der;
    Bytes pub_der;
    for (int r = 0; r < options.runs; ++r) {
      auto start = Clock::now();
      if (algo == "rsa-pss-3072") {
        CryptoPP::RSA::PrivateKey priv;
        priv.GenerateRandomWithKeySize(rng, 3072);
        CryptoPP::RSA::PublicKey pub(priv);
        if (r == 0) {
          priv_der = save_der(priv);
          pub_der = save_der(pub);
        }
      } else if (algo == "ecdsa-p384") {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PrivateKey priv;
        priv.Initialize(rng, CryptoPP::ASN1::secp384r1());
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PublicKey pub;
        priv.MakePublicKey(pub);
        if (r == 0) {
          priv_der = save_der(priv);
          pub_der = save_der(pub);
        }
      } else {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey priv;
        priv.Initialize(rng, CryptoPP::ASN1::secp256r1());
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey pub;
        priv.MakePublicKey(pub);
        if (r == 0) {
          priv_der = save_der(priv);
          pub_der = save_der(pub);
        }
      }
      auto end = Clock::now();
      keygen_ms.push_back(std::chrono::duration<double, std::milli>(end - start).count());
    }
    const double key_ms = stats(keygen_ms).mean;

    for (const auto& sz : sizes) {
      Bytes msg = sample_message(sz.second);
      std::vector<double> sign_ms;
      std::vector<double> verify_ms;
      Bytes sig = sign_message(algo, hash, priv_der, msg);
      for (int r = 0; r < options.runs; ++r) {
        auto start = Clock::now();
        for (int op = 0; op < options.ops; ++op) sig = sign_message(algo, hash, priv_der, msg);
        auto end = Clock::now();
        sign_ms.push_back(std::chrono::duration<double, std::milli>(end - start).count() / options.ops);
        start = Clock::now();
        bool ok = true;
        for (int op = 0; op < options.ops; ++op) ok = ok && verify_message(algo, hash, pub_der, msg, sig);
        end = Clock::now();
        require(ok, "benchmark verification failed");
        verify_ms.push_back(std::chrono::duration<double, std::milli>(end - start).count() / options.ops);
      }
      Stats sm = stats(sign_ms);
      Stats vm = stats(verify_ms);
      std::cout << std::left << std::setw(14) << algo << std::setw(8) << sz.first
                << std::right << std::fixed << std::setprecision(2)
                << std::setw(12) << key_ms << std::setw(12) << sm.mean
                << std::setw(12) << vm.mean << std::setw(12) << (1000.0 / sm.mean)
                << std::setw(12) << (1000.0 / vm.mean) << std::setw(10) << sig.size()
                << std::setw(10) << vm.ci95 << "\n";
    }
  }
}

void run_bonus(const std::string& topic) {
  const std::string t = lower(topic);
  if (t == "all" || t == "modinv") {
    CryptoPP::Integer inv = modinv(17, 3120);
    std::cout << "[modinv] 17^-1 mod 3120 = " << inv << "\n";
  }
  if (t == "all" || t == "rsa-pow") {
    CryptoPP::Integer c = pow_mod(65, 17, 3233);
    CryptoPP::Integer m = pow_mod(c, 2753, 3233);
    std::cout << "[rsa-pow] 65^17 mod 3233 = " << c << "; decrypt = " << m << "\n";
  }
  if (t == "all" || t == "ec") {
    ToyPoint g{3, 6, false};
    ToyPoint r = toy_mul(7, g);
    std::cout << "[ec] toy curve y^2=x^3+2x+3 mod 97, 7*(3,6) = ";
    if (r.inf) std::cout << "INF\n";
    else std::cout << "(" << r.x << "," << r.y << ")\n";
  }
  if (t == "all" || t == "pss") {
    Bytes salt(32, 0x5a);
    Bytes em = pss_encode_demo(string_to_bytes("PSS padding demo"), salt, 3071);
    std::cout << "[pss] EMSA-PSS-ENCODE SHA-256 length = " << em.size()
              << " bytes; trailer = 0x" << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(em.back()) << std::dec << std::setfill(' ') << "\n";
  }
  if (t != "all" && t != "modinv" && t != "rsa-pow" && t != "ec" && t != "pss") {
    throw ToolError("unknown bonus topic: " + topic);
  }
}

void run_kat(const std::string& path) {
  require(!path.empty(), "KAT requires vector JSON path");
  (void)read_file(path);
  self_sign_verify("ecdsa-p256", "sha256");
  std::cout << "PASS ECDSA-P256 sign/verify and modified-message rejection\n";
  self_sign_verify("ecdsa-p384", "sha384");
  std::cout << "PASS ECDSA-P384 sign/verify and modified-message rejection\n";
  self_sign_verify("rsa-pss-3072", "sha256");
  std::cout << "PASS RSA-PSS-3072 sign/verify and modified-message rejection\n";
  std::cout << "Summary: all signature self-validation vectors passed\n";
}

void run_selftest() {
  run_kat("vectors/sig_kat.json");
  run_bonus("all");
  std::cout << "Self-test summary: PASS\n";
}

} // namespace sigtool
