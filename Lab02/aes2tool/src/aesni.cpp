#include "aes2tool.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#include <wmmintrin.h>
#define AES2TOOL_HAS_AESNI_INTRINSICS 1
#elif (defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(__i386__))
#include <wmmintrin.h>
#define AES2TOOL_HAS_AESNI_INTRINSICS 1
#endif

namespace aes2tool {

#if AES2TOOL_HAS_AESNI_INTRINSICS
namespace {

#define AES128_EXPAND_STEP(prev, rcon)                                             \
  do {                                                                             \
    __m128i assist = _mm_aeskeygenassist_si128((prev), (rcon));                    \
    assist = _mm_shuffle_epi32(assist, 0xff);                                      \
    __m128i tmp = (prev);                                                          \
    tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));                              \
    tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));                              \
    tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp, 4));                              \
    (prev) = _mm_xor_si128(tmp, assist);                                           \
  } while (0)

void aes128_round_keys(const std::uint8_t* key, __m128i rk[11]) {
  rk[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
  rk[1] = rk[0];  AES128_EXPAND_STEP(rk[1], 0x01);
  rk[2] = rk[1];  AES128_EXPAND_STEP(rk[2], 0x02);
  rk[3] = rk[2];  AES128_EXPAND_STEP(rk[3], 0x04);
  rk[4] = rk[3];  AES128_EXPAND_STEP(rk[4], 0x08);
  rk[5] = rk[4];  AES128_EXPAND_STEP(rk[5], 0x10);
  rk[6] = rk[5];  AES128_EXPAND_STEP(rk[6], 0x20);
  rk[7] = rk[6];  AES128_EXPAND_STEP(rk[7], 0x40);
  rk[8] = rk[7];  AES128_EXPAND_STEP(rk[8], 0x80);
  rk[9] = rk[8];  AES128_EXPAND_STEP(rk[9], 0x1b);
  rk[10] = rk[9]; AES128_EXPAND_STEP(rk[10], 0x36);
}

std::array<std::uint8_t, 16> aes128_encrypt_block_aesni(
    const std::array<std::uint8_t, 16>& block, const __m128i rk[11]) {
  __m128i state = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block.data()));
  state = _mm_xor_si128(state, rk[0]);
  for (int round = 1; round < 10; ++round) state = _mm_aesenc_si128(state, rk[round]);
  state = _mm_aesenclast_si128(state, rk[10]);
  std::array<std::uint8_t, 16> out{};
  _mm_storeu_si128(reinterpret_cast<__m128i*>(out.data()), state);
  return out;
}

void increment_counter_be(std::array<std::uint8_t, 16>& counter) {
  for (int i = 15; i >= 0; --i) {
    if (++counter[static_cast<std::size_t>(i)] != 0) return;
  }
  throw std::runtime_error("CTR counter overflow");
}

}  // namespace
#endif

Bytes ctr_transform_aesni128(const Bytes& key, const Bytes& iv, const Bytes& input) {
#if AES2TOOL_HAS_AESNI_INTRINSICS
  if (!cpu_supports_aesni()) throw std::runtime_error("AES-NI is not available on this CPU");
  if (key.size() != 16) throw std::runtime_error("AES-NI bonus backend currently supports AES-128 only");
  if (iv.size() != 16) throw std::runtime_error("CTR IV must be exactly 16 bytes");

  __m128i rk[11];
  aes128_round_keys(key.data(), rk);
  std::array<std::uint8_t, 16> counter{};
  std::copy_n(iv.begin(), 16, counter.begin());
  Bytes out(input.size());
  for (std::size_t off = 0; off < input.size(); off += 16) {
    const auto stream = aes128_encrypt_block_aesni(counter, rk);
    const std::size_t n = std::min<std::size_t>(16, input.size() - off);
    for (std::size_t i = 0; i < n; ++i) out[off + i] = input[off + i] ^ stream[i];
    if (off + n < input.size()) increment_counter_be(counter);
  }
  return out;
#else
  (void)key;
  (void)iv;
  (void)input;
  throw std::runtime_error("AES-NI backend was not compiled for this architecture");
#endif
}

bool aesni_backend_compiled() {
#if AES2TOOL_HAS_AESNI_INTRINSICS
  return true;
#else
  return false;
#endif
}

}  // namespace aes2tool
