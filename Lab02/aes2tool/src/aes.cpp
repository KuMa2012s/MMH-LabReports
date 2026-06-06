#include "aes2tool.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <sys/random.h>
#include <unistd.h>
#endif

#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#endif

namespace aes2tool {
namespace {

constexpr std::array<std::uint8_t, 256> kSbox = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

constexpr std::array<std::uint8_t, 256> kInvSbox = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d};

constexpr std::array<std::uint8_t, 11> kRcon = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

std::uint8_t xtime(std::uint8_t x) {
  return static_cast<std::uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

std::uint8_t gf_mul(std::uint8_t a, std::uint8_t b) {
  std::uint8_t out = 0;
  while (b) {
    if (b & 1) out ^= a;
    a = xtime(a);
    b >>= 1;
  }
  return out;
}

void add_round_key(Block& s, const std::vector<std::uint8_t>& rk, int round) {
  const std::size_t off = static_cast<std::size_t>(round) * 16;
  for (std::size_t i = 0; i < 16; ++i) s[i] ^= rk[off + i];
}

void sub_bytes(Block& s) {
  for (auto& b : s) b = kSbox[b];
}

void inv_sub_bytes(Block& s) {
  for (auto& b : s) b = kInvSbox[b];
}

void shift_rows(Block& s) {
  Block t = s;
  for (int r = 0; r < 4; ++r) {
    for (int c = 0; c < 4; ++c) {
      s[static_cast<std::size_t>(r + 4 * c)] =
          t[static_cast<std::size_t>(r + 4 * ((c + r) % 4))];
    }
  }
}

void inv_shift_rows(Block& s) {
  Block t = s;
  for (int r = 0; r < 4; ++r) {
    for (int c = 0; c < 4; ++c) {
      s[static_cast<std::size_t>(r + 4 * c)] =
          t[static_cast<std::size_t>(r + 4 * ((c - r + 4) % 4))];
    }
  }
}

void mix_columns(Block& s) {
  for (int c = 0; c < 4; ++c) {
    const std::size_t i = static_cast<std::size_t>(4 * c);
    const std::uint8_t a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
    s[i]     = static_cast<std::uint8_t>(gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3);
    s[i + 1] = static_cast<std::uint8_t>(a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3);
    s[i + 2] = static_cast<std::uint8_t>(a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3));
    s[i + 3] = static_cast<std::uint8_t>(gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2));
  }
}

void inv_mix_columns(Block& s) {
  for (int c = 0; c < 4; ++c) {
    const std::size_t i = static_cast<std::size_t>(4 * c);
    const std::uint8_t a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
    s[i]     = static_cast<std::uint8_t>(gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9));
    s[i + 1] = static_cast<std::uint8_t>(gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13));
    s[i + 2] = static_cast<std::uint8_t>(gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11));
    s[i + 3] = static_cast<std::uint8_t>(gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14));
  }
}

Block to_block(const Bytes& v, std::size_t off = 0) {
  if (v.size() < off + 16) throw std::runtime_error("not enough bytes for AES block");
  Block b{};
  std::copy_n(v.begin() + static_cast<std::ptrdiff_t>(off), 16, b.begin());
  return b;
}

Bytes block_to_bytes(const Block& b) {
  return Bytes(b.begin(), b.end());
}

void increment_counter_be(Block& counter) {
  for (int i = 15; i >= 0; --i) {
    if (++counter[static_cast<std::size_t>(i)] != 0) return;
  }
  throw std::runtime_error("CTR counter overflow");
}

void xts_mul_alpha(Block& tweak) {
  std::uint8_t carry = 0;
  for (std::size_t i = 0; i < 16; ++i) {
    const std::uint8_t next = static_cast<std::uint8_t>(tweak[i] >> 7);
    tweak[i] = static_cast<std::uint8_t>((tweak[i] << 1) | carry);
    carry = next;
  }
  if (carry) tweak[0] ^= 0x87;
}

Bytes trim_hex_prefix(std::string hex) {
  if (hex.rfind("hex:", 0) == 0 || hex.rfind("HEX:", 0) == 0) hex = hex.substr(4);
  hex.erase(std::remove_if(hex.begin(), hex.end(), [](unsigned char c) {
    return std::isspace(c) != 0;
  }), hex.end());
  if (hex.size() % 2 != 0) throw std::runtime_error("hex input must contain an even number of digits");
  Bytes out;
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    const std::string byte = hex.substr(i, 2);
    out.push_back(static_cast<std::uint8_t>(std::stoul(byte, nullptr, 16)));
  }
  return out;
}

}  // namespace

Aes::Aes(const Bytes& key) {
  if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
    throw std::runtime_error("AES key must be exactly 16, 24, or 32 bytes");
  }
  nk_ = static_cast<int>(key.size() / 4);
  nr_ = nk_ + 6;
  key_bits_ = key.size() * 8;

  const int words = 4 * (nr_ + 1);
  round_keys_.assign(static_cast<std::size_t>(words) * 4, 0);
  std::copy(key.begin(), key.end(), round_keys_.begin());

  std::array<std::uint8_t, 4> temp{};
  for (int i = nk_; i < words; ++i) {
    for (int j = 0; j < 4; ++j) {
      temp[static_cast<std::size_t>(j)] =
          round_keys_[static_cast<std::size_t>(4 * (i - 1) + j)];
    }
    if (i % nk_ == 0) {
      std::rotate(temp.begin(), temp.begin() + 1, temp.end());
      for (auto& b : temp) b = kSbox[b];
      temp[0] ^= kRcon[static_cast<std::size_t>(i / nk_)];
    } else if (nk_ > 6 && i % nk_ == 4) {
      for (auto& b : temp) b = kSbox[b];
    }
    for (int j = 0; j < 4; ++j) {
      round_keys_[static_cast<std::size_t>(4 * i + j)] =
          static_cast<std::uint8_t>(
              round_keys_[static_cast<std::size_t>(4 * (i - nk_) + j)] ^
              temp[static_cast<std::size_t>(j)]);
    }
  }
}

Block Aes::encrypt_block(const Block& in) const {
  Block s = in;
  add_round_key(s, round_keys_, 0);
  for (int round = 1; round < nr_; ++round) {
    sub_bytes(s);
    shift_rows(s);
    mix_columns(s);
    add_round_key(s, round_keys_, round);
  }
  sub_bytes(s);
  shift_rows(s);
  add_round_key(s, round_keys_, nr_);
  return s;
}

Block Aes::decrypt_block(const Block& in) const {
  Block s = in;
  add_round_key(s, round_keys_, nr_);
  for (int round = nr_ - 1; round >= 1; --round) {
    inv_shift_rows(s);
    inv_sub_bytes(s);
    add_round_key(s, round_keys_, round);
    inv_mix_columns(s);
  }
  inv_shift_rows(s);
  inv_sub_bytes(s);
  add_round_key(s, round_keys_, 0);
  return s;
}

Bytes ctr_transform(const Bytes& key, const Bytes& iv, const Bytes& input) {
  if (iv.size() != 16) throw std::runtime_error("CTR IV must be exactly 16 bytes");
  Aes aes(key);
  Block counter = to_block(iv);
  Bytes out(input.size());

  for (std::size_t off = 0; off < input.size(); off += 16) {
    const Block stream = aes.encrypt_block(counter);
    const std::size_t n = std::min<std::size_t>(16, input.size() - off);
    for (std::size_t i = 0; i < n; ++i) out[off + i] = input[off + i] ^ stream[i];
    if (off + n < input.size()) increment_counter_be(counter);
  }
  return out;
}

Bytes xts_encrypt(const Bytes& key, const Bytes& tweak_bytes, const Bytes& plaintext) {
  if (key.size() != 32 && key.size() != 48 && key.size() != 64) {
    throw std::runtime_error("XTS key must be 32, 48, or 64 bytes (two equal AES keys)");
  }
  if (tweak_bytes.size() != 16) throw std::runtime_error("XTS tweak must be exactly 16 bytes");
  if (plaintext.empty() || plaintext.size() % 16 != 0) {
    throw std::runtime_error("this educational XTS bonus implementation requires full 16-byte blocks");
  }
  const std::size_t half = key.size() / 2;
  Aes data_aes(Bytes(key.begin(), key.begin() + static_cast<std::ptrdiff_t>(half)));
  Aes tweak_aes(Bytes(key.begin() + static_cast<std::ptrdiff_t>(half), key.end()));
  Block tweak = tweak_aes.encrypt_block(to_block(tweak_bytes));
  Bytes out(plaintext.size());
  for (std::size_t off = 0; off < plaintext.size(); off += 16) {
    Block x = to_block(plaintext, off);
    for (std::size_t i = 0; i < 16; ++i) x[i] ^= tweak[i];
    x = data_aes.encrypt_block(x);
    for (std::size_t i = 0; i < 16; ++i) out[off + i] = x[i] ^ tweak[i];
    xts_mul_alpha(tweak);
  }
  return out;
}

Bytes xts_decrypt(const Bytes& key, const Bytes& tweak_bytes, const Bytes& ciphertext) {
  if (key.size() != 32 && key.size() != 48 && key.size() != 64) {
    throw std::runtime_error("XTS key must be 32, 48, or 64 bytes (two equal AES keys)");
  }
  if (tweak_bytes.size() != 16) throw std::runtime_error("XTS tweak must be exactly 16 bytes");
  if (ciphertext.empty() || ciphertext.size() % 16 != 0) {
    throw std::runtime_error("this educational XTS bonus implementation requires full 16-byte blocks");
  }
  const std::size_t half = key.size() / 2;
  Aes data_aes(Bytes(key.begin(), key.begin() + static_cast<std::ptrdiff_t>(half)));
  Aes tweak_aes(Bytes(key.begin() + static_cast<std::ptrdiff_t>(half), key.end()));
  Block tweak = tweak_aes.encrypt_block(to_block(tweak_bytes));
  Bytes out(ciphertext.size());
  for (std::size_t off = 0; off < ciphertext.size(); off += 16) {
    Block x = to_block(ciphertext, off);
    for (std::size_t i = 0; i < 16; ++i) x[i] ^= tweak[i];
    x = data_aes.decrypt_block(x);
    for (std::size_t i = 0; i < 16; ++i) out[off + i] = x[i] ^ tweak[i];
    xts_mul_alpha(tweak);
  }
  return out;
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

Bytes random_bytes(std::size_t n) {
  Bytes out(n);
  if (out.empty()) return out;
#if defined(_WIN32)
  if (BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(out.size()),
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
    throw std::runtime_error("BCryptGenRandom failed");
  }
#elif defined(__linux__)
  std::size_t done = 0;
  while (done < out.size()) {
    const ssize_t nread = getrandom(out.data() + done, out.size() - done, 0);
    if (nread < 0) throw std::runtime_error("getrandom failed");
    done += static_cast<std::size_t>(nread);
  }
#else
  std::ifstream urandom("/dev/urandom", std::ios::binary);
  if (!urandom) throw std::runtime_error("cannot open system CSPRNG");
  urandom.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
  if (!urandom) throw std::runtime_error("system CSPRNG read failed");
#endif
  return out;
}

Bytes from_hex(const std::string& hex) {
  return trim_hex_prefix(hex);
}

std::string to_hex(const Bytes& data) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (std::uint8_t b : data) oss << std::setw(2) << static_cast<int>(b);
  return oss.str();
}

std::string lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

bool cpu_supports_aesni() {
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
  int regs[4] = {};
  __cpuid(regs, 1);
  return (regs[2] & (1 << 25)) != 0;
#elif defined(__GNUC__) || defined(__clang__)
  unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
  if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0) return false;
  return (ecx & bit_AES) != 0;
#else
  return false;
#endif
}

}  // namespace aes2tool
