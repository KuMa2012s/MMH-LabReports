#include "hashtool.hpp"

#include <iostream>
#include <map>
#include <string>

namespace {

void help() {
  std::cout
      << "hashtool - Lab 4 Hashing, PKI, and Practical Attacks\n\n"
      << "Commands:\n"
      << "  hash              Compute SHA-2, SHA-3, SHAKE, or MD5 demo digest\n"
      << "  cert              Parse X.509 certificate and optionally verify issuer signature\n"
      << "  md5-collision     Generate or verify a benign MD5 collision demo\n"
      << "  length-extension  Demonstrate SHA-256 length-extension on MAC = H(k || m)\n"
      << "  bench             Benchmark SHA-256, SHA-512, SHA3-256, SHA3-512\n"
      << "  bench-io          Compare streamed I/O with memory-mapped I/O\n"
      << "  --kat <json>      Run known-answer tests from JSON vectors\n"
      << "  --selftest        Run offline self-tests\n"
      << "  --help            Show this help\n\n"
      << "Hash examples:\n"
      << "  hashtool hash --algo sha256 --in file.bin\n"
      << "  hashtool hash --algo sha512 --in large.iso --stream\n"
      << "  hashtool hash --algo shake256 --outlen 64 --in file.bin\n"
      << "  hashtool hash --algo sha3-256 --text \"abc\" --out digest.bin --encode raw\n\n"
      << "Certificate examples:\n"
      << "  hashtool cert --in cert.pem\n"
      << "  hashtool cert --in leaf.pem --issuer issuer.pem --verify\n\n"
      << "Attack demos:\n"
      << "  hashtool md5-collision --generate --out-dir attacks\n"
      << "  hashtool md5-collision --file1 attacks/md5_collision_1.bin --file2 attacks/md5_collision_2.bin\n"
      << "  hashtool length-extension --demo\n"
      << "  hashtool length-extension --key-len 9 --mac HEX --message \"user=guest\" --append \"&admin=true\"\n\n"
      << "Benchmark:\n"
      << "  hashtool bench --runs 30 --ops 10\n"
      << "  hashtool bench --runs 5 --ops 3 --include-1gib\n\n"
      << "  hashtool bench-io --runs 5 --ops 3\n\n"
      << "Flags:\n"
      << "  --algo <name>       sha224, sha256, sha384, sha512, sha3-224, sha3-256, sha3-384, sha3-512, shake128, shake256\n"
      << "  --in <file>         Binary-safe input file\n"
      << "  --text <text>       UTF-8 text input\n"
      << "  --out <file>        Output file\n"
      << "  --encode <mode>     hex, base64, or raw for file output\n"
      << "  --outlen <bytes>    SHAKE output length in bytes\n"
      << "  --stream            Use streamed file I/O\n"
      << "  --issuer <file>     Issuer certificate for signature verification\n"
      << "  --verify            Verify certificate signature with issuer public key\n"
      << "  --runs <n>          Benchmark runs\n"
      << "  --ops <n>           Operations per benchmark run\n";
}

std::map<std::string, std::string> parse(int argc, char** argv, int start) {
  std::map<std::string, std::string> args;
  for (int i = start; i < argc; ++i) {
    std::string k = argv[i];
    if (k.rfind("--", 0) != 0) throw hashtool::ToolError("unexpected argument: " + k);
    if (k == "--stream" || k == "--verify" || k == "--generate" || k == "--demo" || k == "--include-1gib") {
      args[k] = "true";
      continue;
    }
    if (i + 1 >= argc) throw hashtool::ToolError("missing value for " + k);
    args[k] = argv[++i];
  }
  return args;
}

std::string arg(const std::map<std::string, std::string>& args, const std::string& k, const std::string& d = "") {
  auto it = args.find(k);
  return it == args.end() ? d : it->second;
}

int int_arg(const std::map<std::string, std::string>& args, const std::string& k, int d) {
  std::string v = arg(args, k);
  return v.empty() ? d : std::stoi(v);
}

std::size_t size_arg(const std::map<std::string, std::string>& args, const std::string& k, std::size_t d) {
  std::string v = arg(args, k);
  return v.empty() ? d : static_cast<std::size_t>(std::stoull(v));
}

} // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 2 || std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
      help();
      return 0;
    }
    const std::string cmd = argv[1];
    if (cmd == "--selftest") {
      hashtool::run_selftest();
      return 0;
    }
    if (cmd == "--kat") {
      if (argc < 3) throw hashtool::ToolError("--kat requires vector JSON path");
      hashtool::run_kat(argv[2]);
      return 0;
    }
    const auto args = parse(argc, argv, 2);
    if (cmd == "hash") {
      hashtool::HashOptions o;
      o.algo = arg(args, "--algo");
      o.input_path = arg(args, "--in");
      o.text = arg(args, "--text");
      o.output_path = arg(args, "--out");
      o.encode = arg(args, "--encode", "hex");
      o.outlen = size_arg(args, "--outlen", 0);
      o.stream = args.find("--stream") != args.end();
      hashtool::run_hash(o);
      return 0;
    }
    if (cmd == "cert") {
      hashtool::CertOptions o;
      o.input_path = arg(args, "--in");
      o.issuer_path = arg(args, "--issuer");
      o.verify = args.find("--verify") != args.end();
      hashtool::run_cert(o);
      return 0;
    }
    if (cmd == "md5-collision") {
      hashtool::run_md5_collision(arg(args, "--file1"), arg(args, "--file2"),
                                  args.find("--generate") != args.end() ? arg(args, "--out-dir", "attacks") : "");
      return 0;
    }
    if (cmd == "length-extension") {
      hashtool::LengthExtensionOptions o;
      o.mac_hex = arg(args, "--mac");
      o.message = arg(args, "--message");
      o.append = arg(args, "--append");
      o.key_len = size_arg(args, "--key-len", 0);
      o.demo = args.find("--demo") != args.end();
      hashtool::run_length_extension(o);
      return 0;
    }
    if (cmd == "bench") {
      hashtool::BenchOptions o;
      o.runs = int_arg(args, "--runs", 30);
      o.ops = int_arg(args, "--ops", 10);
      o.include_1gib = args.find("--include-1gib") != args.end();
      hashtool::run_benchmark(o);
      return 0;
    }
    if (cmd == "bench-io") {
      hashtool::BenchOptions o;
      o.runs = int_arg(args, "--runs", 5);
      o.ops = int_arg(args, "--ops", 3);
      o.include_1gib = args.find("--include-1gib") != args.end();
      hashtool::run_io_benchmark(o);
      return 0;
    }
    throw hashtool::ToolError("unknown command: " + cmd);
  } catch (const hashtool::ToolError& e) {
    std::cerr << "ERROR: " << e.what() << "\n";
    return 1;
  } catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << "\n";
    return 1;
  }
}
