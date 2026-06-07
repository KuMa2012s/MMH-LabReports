#include "rsatool.hpp"

#include <cstdlib>
#include <iostream>
#include <map>
#include <string>

namespace {

void print_help() {
  std::cout
      << "rsatool - RSA-OAEP SHA-256 and hybrid encryption tool for Lab 3\n\n"
      << "Commands:\n"
      << "  keygen        Generate RSA key pair in PEM, DER, and metadata JSON formats\n"
      << "  encrypt       Encrypt with RSA-OAEP; automatically uses hybrid AES-GCM for large input\n"
      << "  decrypt       Decrypt RSA-OAEP or hybrid envelope ciphertext\n"
      << "  bench         Benchmark RSA-3072 vs RSA-4096 and hybrid encryption\n"
      << "  --kat [file] Run known-answer tests for deterministic RSA/AES support routines\n"
      << "  oaep-selftest Run manual OAEP padding bonus self-test\n"
      << "  --selftest    Run correctness and negative tests\n"
      << "  --help        Show this help screen\n\n"
      << "Key generation:\n"
      << "  rsatool keygen --bits 3072 --pub pub.pem --priv priv.pem\n"
      << "  rsatool keygen --bits 4096 --pub pub.pem --priv priv.pem --pub-der pub.der --priv-der priv.der --meta key.json\n\n"
      << "Encryption:\n"
      << "  rsatool encrypt --in msg.bin --pub pub.pem --out ct.bin\n"
      << "  rsatool encrypt --text \"hello\" --pub pub.pem --out ct.b64 --format base64 --label context\n\n"
      << "Decryption:\n"
      << "  rsatool decrypt --in ct.bin --priv priv.pem --out msg.bin\n"
      << "  rsatool decrypt --in ct.b64 --priv priv.pem --out msg.bin --format base64 --label context\n\n"
      << "Benchmark:\n"
      << "  rsatool bench --runs 5\n"
      << "  rsatool bench --runs 3 --ops 10 --skip-100mib\n\n"
      << "Flags:\n"
      << "  --bits <3072|4096>     RSA modulus size. 3072 is required; 4096 is for comparison.\n"
      << "  --pub <file>           RSA public key PEM path.\n"
      << "  --priv <file>          RSA private key PEM path.\n"
      << "  --pub-der <file>       Optional public key DER output path.\n"
      << "  --priv-der <file>      Optional private key DER output path.\n"
      << "  --meta <file>          Optional metadata JSON output path.\n"
      << "  --in <file>            Input file path.\n"
      << "  --text <text>          Inline plaintext input for small demos.\n"
      << "  --out <file>           Output file path.\n"
      << "  --label <text>         Optional OAEP label; decrypt must use the same label.\n"
      << "  --format <raw|hex|base64> Ciphertext container encoding. Decrypt default is auto.\n"
      << "  --runs <n>             Benchmark runs.\n"
      << "  --ops <n>              Encryption/decryption operations per benchmark run.\n"
      << "  --skip-100mib          Skip the 100 MiB hybrid benchmark case.\n\n"
      << "Notes:\n"
      << "  RSA-OAEP uses SHA-256 and MGF1-SHA-256.\n"
      << "  RSA-3072 can encrypt at most 318 bytes directly with OAEP-SHA256.\n"
      << "  RSA-4096 can encrypt at most 446 bytes directly with OAEP-SHA256.\n"
      << "  Larger plaintext automatically uses RSA-OAEP + AES-256-GCM envelope encryption.\n"
      << "  AES-GCM uses a fresh 96-bit IV and authenticated decryption; tampering fails closed.\n";
}

std::map<std::string, std::string> parse_args(int argc, char** argv, int start) {
  std::map<std::string, std::string> args;
  for (int i = start; i < argc; ++i) {
    std::string key = argv[i];
    if (key.rfind("--", 0) != 0) {
      throw rsatool::ToolError("unexpected argument: " + key);
    }
    if (key == "--skip-100mib") {
      args[key] = "true";
      continue;
    }
    if (i + 1 >= argc) {
      throw rsatool::ToolError("missing value for " + key);
    }
    args[key] = argv[++i];
  }
  return args;
}

std::string get_arg(const std::map<std::string, std::string>& args, const std::string& key, const std::string& def = "") {
  auto it = args.find(key);
  return it == args.end() ? def : it->second;
}

int get_int_arg(const std::map<std::string, std::string>& args, const std::string& key, int def) {
  const std::string value = get_arg(args, key);
  if (value.empty()) {
    return def;
  }
  return std::stoi(value);
}

} // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 2 || std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
      print_help();
      return 0;
    }

    const std::string command = argv[1];
    if (command == "--selftest") {
      rsatool::run_selftest();
      return 0;
    }
    if (command == "--kat") {
      const std::string vector_path = argc >= 3 ? argv[2] : "";
      rsatool::run_kat_tests(vector_path);
      return 0;
    }
    if (command == "oaep-selftest") {
      rsatool::run_oaep_selftest();
      return 0;
    }

    const auto args = parse_args(argc, argv, 2);

    if (command == "keygen") {
      const int bits = get_int_arg(args, "--bits", 3072);
      rsatool::KeyPaths paths;
      paths.public_pem = get_arg(args, "--pub");
      paths.private_pem = get_arg(args, "--priv");
      paths.public_der = get_arg(args, "--pub-der");
      paths.private_der = get_arg(args, "--priv-der");
      paths.metadata_json = get_arg(args, "--meta");
      rsatool::keygen(bits, paths);
      std::cout << "Generated RSA-" << bits << " key pair\n";
      std::cout << "Public PEM:  " << paths.public_pem << "\n";
      std::cout << "Private PEM: " << paths.private_pem << "\n";
      if (!paths.public_der.empty()) {
        std::cout << "Public DER:  " << paths.public_der << "\n";
      }
      if (!paths.private_der.empty()) {
        std::cout << "Private DER: " << paths.private_der << "\n";
      }
      if (!paths.metadata_json.empty()) {
        std::cout << "Metadata:    " << paths.metadata_json << "\n";
      }
      return 0;
    }

    if (command == "encrypt") {
      rsatool::EncryptOptions options;
      options.input_path = get_arg(args, "--in");
      options.text = get_arg(args, "--text");
      options.public_key_path = get_arg(args, "--pub");
      options.output_path = get_arg(args, "--out");
      options.label = get_arg(args, "--label");
      options.format = get_arg(args, "--format", "raw");
      rsatool::encrypt_file(options);
      std::cout << "Wrote ciphertext envelope: " << options.output_path << "\n";
      return 0;
    }

    if (command == "decrypt") {
      rsatool::DecryptOptions options;
      options.input_path = get_arg(args, "--in");
      options.private_key_path = get_arg(args, "--priv");
      options.output_path = get_arg(args, "--out");
      options.label = get_arg(args, "--label");
      options.format = get_arg(args, "--format", "auto");
      rsatool::decrypt_file(options);
      std::cout << "Wrote plaintext: " << options.output_path << "\n";
      return 0;
    }

    if (command == "bench") {
      rsatool::BenchOptions options;
      options.runs = get_int_arg(args, "--runs", 5);
      options.ops = get_int_arg(args, "--ops", 1);
      options.include_100mib = args.find("--skip-100mib") == args.end();
      rsatool::run_benchmark(options);
      return 0;
    }

    throw rsatool::ToolError("unknown command: " + command);
  } catch (const rsatool::ToolError& e) {
    std::cerr << "ERROR: " << e.what() << "\n";
    return 1;
  } catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << "\n";
    return 1;
  }
}
