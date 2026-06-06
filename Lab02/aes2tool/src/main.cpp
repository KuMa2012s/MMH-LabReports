#include "aes2tool.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <regex>
#include <sstream>
#include <stdexcept>

namespace aes2tool {
namespace {

Bytes read_key(const Options& opt) {
  if (!opt.key_hex.empty()) return from_hex(opt.key_hex);
  if (!opt.key_file.empty()) return read_file(opt.key_file);
  throw std::runtime_error("missing --key or --key-hex");
}

Bytes read_iv(const Options& opt) {
  if (!opt.iv_hex.empty()) return from_hex(opt.iv_hex);
  if (!opt.iv_file.empty()) return read_file(opt.iv_file);
  throw std::runtime_error("missing --iv or --iv-hex");
}

Bytes read_input(const Options& opt) {
  if (!opt.text.empty()) return Bytes(opt.text.begin(), opt.text.end());
  if (!opt.in_file.empty()) return read_file(opt.in_file);
  throw std::runtime_error("missing --in or --text");
}

void write_or_print(const Options& opt, const Bytes& data) {
  if (!opt.out_file.empty()) {
    write_file(opt.out_file, data);
    std::cout << "Wrote output: " << opt.out_file << "\n";
    return;
  }
  if (opt.encode == "raw") {
    std::cout.write(reinterpret_cast<const char*>(data.data()),
                    static_cast<std::streamsize>(data.size()));
  } else {
    std::cout << to_hex(data) << "\n";
  }
}

int run_keygen(const Options& opt) {
  if (opt.out_file.empty()) throw std::runtime_error("keygen requires --out");
  if (opt.bits != 128 && opt.bits != 192 && opt.bits != 256 &&
      opt.bits != 384 && opt.bits != 512) {
    throw std::runtime_error("--bits must be 128, 192, 256, 384, or 512");
  }
  Bytes key = random_bytes(static_cast<std::size_t>(opt.bits / 8));
  write_file(opt.out_file, key);
  std::cout << "Generated " << opt.bits << "-bit key: " << opt.out_file << "\n";
  return 0;
}

int run_encrypt(const Options& opt) {
  const std::string mode = lower(opt.mode);
  const Bytes key = read_key(opt);
  const Bytes iv = read_iv(opt);
  const Bytes input = read_input(opt);
  Bytes output;
  if (mode == "ctr") {
    output = ctr_transform(key, iv, input);
  } else if (mode == "xts") {
    output = xts_encrypt(key, iv, input);
  } else {
    throw std::runtime_error("unsupported --mode for Lab 2: use ctr or xts");
  }
  write_or_print(opt, output);
  return 0;
}

int run_decrypt(const Options& opt) {
  const std::string mode = lower(opt.mode);
  const Bytes key = read_key(opt);
  const Bytes iv = read_iv(opt);
  const Bytes input = read_input(opt);
  Bytes output;
  if (mode == "ctr") {
    output = ctr_transform(key, iv, input);
  } else if (mode == "xts") {
    output = xts_decrypt(key, iv, input);
  } else {
    throw std::runtime_error("unsupported --mode for Lab 2: use ctr or xts");
  }
  write_or_print(opt, output);
  return 0;
}

struct KatCase {
  std::string name;
  std::string type;
  std::string mode;
  Bytes key;
  Bytes iv;
  Bytes plaintext;
  Bytes ciphertext;
};

std::vector<KatCase> load_kats(const std::string& path) {
  const Bytes raw = read_file(path);
  const std::string text(raw.begin(), raw.end());
  std::vector<KatCase> out;
  std::regex obj("\\{([^\\{\\}]*)\\}");
  std::regex kv("\"([^\"]+)\"\\s*:\\s*\"([^\"]*)\"");
  for (std::sregex_iterator it(text.begin(), text.end(), obj), end; it != end; ++it) {
    const std::string body = (*it)[1].str();
    std::map<std::string, std::string> m;
    for (std::sregex_iterator kt(body.begin(), body.end(), kv), kend; kt != kend; ++kt) {
      m[(*kt)[1].str()] = (*kt)[2].str();
    }
    if (!m.count("key") || !m.count("plaintext") || !m.count("ciphertext")) continue;
    KatCase tc;
    tc.name = m.count("name") ? m["name"] : "unnamed";
    tc.type = lower(m.count("type") ? m["type"] : "ctr");
    tc.mode = lower(m.count("mode") ? m["mode"] : "ctr");
    tc.key = from_hex(m["key"]);
    tc.iv = m.count("iv") ? from_hex(m["iv"]) : Bytes{};
    tc.plaintext = from_hex(m["plaintext"]);
    tc.ciphertext = from_hex(m["ciphertext"]);
    out.push_back(tc);
  }
  return out;
}

int run_kat(const Options& opt) {
  const auto tests = load_kats(opt.kat_file);
  if (tests.empty()) throw std::runtime_error("no KAT vectors loaded");
  int passed = 0;
  int failed = 0;
  for (const auto& tc : tests) {
    try {
      Bytes actual;
      if (tc.type == "block") {
        if (tc.plaintext.size() != 16) throw std::runtime_error("block KAT plaintext must be 16 bytes");
        Aes aes(tc.key);
        Block block{};
        std::copy_n(tc.plaintext.begin(), 16, block.begin());
        const Block encrypted = aes.encrypt_block(block);
        actual.assign(encrypted.begin(), encrypted.end());
      } else if (tc.mode == "ctr") {
        actual = ctr_transform(tc.key, tc.iv, tc.plaintext);
      } else {
        throw std::runtime_error("unsupported KAT mode");
      }
      const bool ok = (actual == tc.ciphertext);
      std::cout << (ok ? "PASS " : "FAIL ") << tc.name << "\n";
      if (!ok) {
        std::cout << "  expected: " << to_hex(tc.ciphertext) << "\n";
        std::cout << "  actual:   " << to_hex(actual) << "\n";
      }
      ok ? ++passed : ++failed;
    } catch (const std::exception& ex) {
      std::cout << "FAIL " << tc.name << ": " << ex.what() << "\n";
      ++failed;
    }
  }
  std::cout << "Summary: " << passed << " passed, " << failed << " failed\n";
  return failed == 0 ? 0 : 1;
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

std::string size_label(std::size_t n) {
  std::ostringstream oss;
  if (n >= 1024 * 1024 * 1024 && n % (1024 * 1024 * 1024) == 0) {
    oss << (n / (1024 * 1024 * 1024)) << " GiB";
  } else if (n >= 1024 * 1024 && n % (1024 * 1024) == 0) {
    oss << (n / (1024 * 1024)) << " MiB";
  } else if (n >= 1024 && n % 1024 == 0) {
    oss << (n / 1024) << " KiB";
  } else {
    oss << n << " B";
  }
  return oss.str();
}

struct BenchRow {
  std::string variant;
  std::string size;
  double enc_mbps = 0.0;
  double dec_mbps = 0.0;
  double enc_latency_ms = 0.0;
  double dec_latency_ms = 0.0;
  double stddev_enc = 0.0;
  double ci95_enc = 0.0;
};

BenchRow bench_one(int bits, std::size_t size, int runs, int ops, bool use_aesni) {
  const Bytes key = random_bytes(static_cast<std::size_t>(bits / 8));
  const Bytes iv = random_bytes(16);
  const Bytes data = random_bytes(size);
  const auto transform = [&](const Bytes& local_iv, const Bytes& input) {
    return use_aesni ? ctr_transform_aesni128(key, local_iv, input)
                     : ctr_transform(key, local_iv, input);
  };
  const Bytes ct_sample = transform(iv, data);

  std::vector<double> enc_mbps;
  std::vector<double> dec_mbps;
  std::vector<double> enc_lat;
  std::vector<double> dec_lat;
  for (int r = 0; r < runs; ++r) {
    auto enc_start = std::chrono::steady_clock::now();
    for (int i = 0; i < ops; ++i) {
      Bytes local_iv = iv;
      local_iv[15] = static_cast<std::uint8_t>((local_iv[15] + i + r) & 0xff);
      (void)transform(local_iv, data);
    }
    auto enc_end = std::chrono::steady_clock::now();

    auto dec_start = std::chrono::steady_clock::now();
    for (int i = 0; i < ops; ++i) {
      (void)transform(iv, ct_sample);
    }
    auto dec_end = std::chrono::steady_clock::now();

    const double mb = (static_cast<double>(size) * static_cast<double>(ops)) / (1024.0 * 1024.0);
    const double enc_s = std::chrono::duration<double>(enc_end - enc_start).count();
    const double dec_s = std::chrono::duration<double>(dec_end - dec_start).count();
    enc_mbps.push_back(mb / enc_s);
    dec_mbps.push_back(mb / dec_s);
    enc_lat.push_back((enc_s * 1000.0) / static_cast<double>(ops));
    dec_lat.push_back((dec_s * 1000.0) / static_cast<double>(ops));
  }
  const double m = mean(enc_mbps);
  const double sd = stddev(enc_mbps, m);
  return BenchRow{
      "AES-" + std::to_string(bits) + "-CTR" + (use_aesni ? "-AESNI" : ""),
      size_label(size),
      m,
      mean(dec_mbps),
      mean(enc_lat),
      mean(dec_lat),
      sd,
      1.96 * sd / std::sqrt(static_cast<double>(enc_mbps.size()))};
}

int run_bench(const Options& opt) {
  std::vector<int> bits = {opt.bits};
  std::vector<std::size_t> sizes = {opt.size};
  if (opt.all) {
    bits = {128, 192, 256};
    sizes = {1024 * 1024, 100 * 1024 * 1024};
    if (opt.include_gib) sizes.push_back(1024ull * 1024ull * 1024ull);
  }
  std::cout << "==========================================================================\n";
  std::cout << "                 PURE C++ AES CTR BENCHMARK RESULTS\n";
  std::cout << "==========================================================================\n";
  std::cout << "Runs: " << opt.runs << " | Ops/run: " << opt.ops
            << " | AES-NI available: " << (cpu_supports_aesni() ? "yes" : "no")
            << " | AES-NI backend compiled: " << (aesni_backend_compiled() ? "yes" : "no")
            << "\n\n";
  std::cout << std::left << std::setw(14) << "Variant"
            << std::right << std::setw(10) << "Size"
            << std::setw(14) << "Enc MB/s"
            << std::setw(14) << "Dec MB/s"
            << std::setw(14) << "Enc ms/op"
            << std::setw(14) << "Dec ms/op"
            << std::setw(12) << "Stddev"
            << std::setw(10) << "CI95" << "\n";
  std::cout << "--------------------------------------------------------------------------\n";
  for (int b : bits) {
    if (b != 128 && b != 192 && b != 256) throw std::runtime_error("--bits must be 128, 192, or 256");
    for (std::size_t s : sizes) {
      const BenchRow row = bench_one(b, s, opt.runs, opt.ops, false);
      std::cout << std::left << std::setw(14) << row.variant
                << std::right << std::setw(10) << row.size
                << std::setw(14) << std::fixed << std::setprecision(2) << row.enc_mbps
                << std::setw(14) << row.dec_mbps
                << std::setw(14) << row.enc_latency_ms
                << std::setw(14) << row.dec_latency_ms
                << std::setw(12) << row.stddev_enc
                << std::setw(10) << row.ci95_enc << "\n";
      if (b == 128 && aesni_backend_compiled() && cpu_supports_aesni()) {
        const BenchRow aesni_row = bench_one(b, s, opt.runs, opt.ops, true);
        std::cout << std::left << std::setw(14) << aesni_row.variant
                  << std::right << std::setw(10) << aesni_row.size
                  << std::setw(14) << std::fixed << std::setprecision(2) << aesni_row.enc_mbps
                  << std::setw(14) << aesni_row.dec_mbps
                  << std::setw(14) << aesni_row.enc_latency_ms
                  << std::setw(14) << aesni_row.dec_latency_ms
                  << std::setw(12) << aesni_row.stddev_enc
                  << std::setw(10) << aesni_row.ci95_enc << "\n";
      }
    }
  }
  std::cout << "==========================================================================\n";
  return 0;
}

}  // namespace

int run(int argc, char** argv) {
  const Options opt = parse_args(argc, argv);
  if (opt.command.empty() || opt.command == "help") {
    print_help();
    return 0;
  }
  if (!opt.kat_file.empty()) return run_kat(opt);
  if (opt.command == "keygen") return run_keygen(opt);
  if (opt.command == "encrypt") return run_encrypt(opt);
  if (opt.command == "decrypt") return run_decrypt(opt);
  if (opt.command == "bench") return run_bench(opt);
  if (opt.command == "features") {
    std::cout << "AES-NI available: " << (cpu_supports_aesni() ? "yes" : "no") << "\n";
    std::cout << "AES-NI backend compiled: " << (aesni_backend_compiled() ? "yes" : "no") << "\n";
    return 0;
  }
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
    const std::string a = argv[i];
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
    else if (a == "--encode") opt.encode = lower(need(a));
    else if (a == "--kat") opt.kat_file = need(a);
    else if (a == "--size") opt.size = static_cast<std::size_t>(std::stoull(need(a)));
    else if (a == "--runs") opt.runs = std::stoi(need(a));
    else if (a == "--ops") opt.ops = std::stoi(need(a));
    else if (a == "--bits") opt.bits = std::stoi(need(a));
    else if (a == "--all") opt.all = true;
    else if (a == "--include-gib") opt.include_gib = true;
    else if (a == "--verbose") opt.verbose = true;
    else throw std::runtime_error("unknown option: " + a);
  }
  return opt;
}

void print_help() {
  std::cout
      << "aes2tool - Lab 2 pure C++ AES implementation\n\n"
      << "USAGE\n"
      << "  aes2tool keygen --bits 128 --out key.bin\n"
      << "  aes2tool encrypt --mode ctr --key key.bin --iv iv.bin --in msg.bin --out ct.bin\n"
      << "  aes2tool decrypt --mode ctr --key key.bin --iv iv.bin --in ct.bin --out msg.bin\n"
      << "  aes2tool --kat vectors/aes_kat.json\n"
      << "  aes2tool bench --all --runs 30 --ops 100\n\n"
      << "COMMANDS\n"
      << "  keygen     Generate raw key material. Use 128/192/256 for AES, 256/384/512 for XTS.\n"
      << "  encrypt    Encrypt file or text input using CTR or XTS.\n"
      << "  decrypt    Decrypt file or text input using CTR or XTS.\n"
      << "  bench      Benchmark AES-CTR software and AES-NI bonus backend when available.\n"
      << "  features   Print CPU feature information relevant to the bonus discussion.\n"
      << "  --kat      Run FIPS-197 and NIST SP 800-38A Known Answer Tests.\n\n"
      << "MODES\n"
      << "  ctr        Required Lab 2 mode. 16-byte IV, big-endian counter increment, no padding.\n"
      << "  xts        Bonus mode. Two-key XTS for full 16-byte blocks only, no integrity.\n\n"
      << "FLAGS\n"
      << "  --key <file>       Raw key file. CTR accepts 16/24/32 bytes. XTS accepts 32/48/64 bytes.\n"
      << "  --key-hex <hex>    Key as hexadecimal text.\n"
      << "  --iv <file>        Raw 16-byte IV/tweak file.\n"
      << "  --iv-hex <hex>     IV/tweak as hexadecimal text.\n"
      << "  --in <file>        Binary-safe input file.\n"
      << "  --text <string>    UTF-8 text input.\n"
      << "  --out <file>       Binary-safe output file.\n"
      << "  --encode hex|raw   Console output encoding when --out is omitted.\n"
      << "  --size <bytes>     Benchmark payload size.\n"
      << "  --runs <N>         Benchmark independent timed runs.\n"
      << "  --ops <N>          Operations per timed run.\n"
      << "  --all              Benchmark AES-128/192/256 at 1 MiB and 100 MiB.\n"
      << "  --include-gib      Also include 1 GiB in --all if feasible.\n\n"
      << "NOTES\n"
      << "  - No external cryptographic library is used for AES operations.\n"
      << "  - CTR encryption and decryption are the same XOR keystream operation.\n"
      << "  - CTR does not provide authentication; tampering is not detected.\n"
      << "  - Reusing the same IV with the same key is catastrophic.\n"
      << "  - Benchmark includes an AES-128-CTR-AESNI bonus row when supported.\n";
}

}  // namespace aes2tool

int main(int argc, char** argv) {
  try {
    return aes2tool::run(argc, argv);
  } catch (const std::exception& ex) {
    std::cerr << "ERROR: " << ex.what() << "\n";
    return 1;
  }
}
