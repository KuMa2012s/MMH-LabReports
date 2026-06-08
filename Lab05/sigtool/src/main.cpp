#include "sigtool.hpp"

#include <iostream>
#include <map>
#include <string>

namespace {

void help() {
  std::cout
      << "sigtool - Lab 5 Classical Digital Signatures (ECDSA, RSA-PSS)\n\n"
      << "Commands:\n"
      << "  keygen        Generate ECDSA or RSA-PSS key pairs\n"
      << "  sign          Produce detached signatures\n"
      << "  verify        Verify detached signatures\n"
      << "  batch-verify  Verify many signatures from a manifest\n"
      << "  bench         Benchmark keygen, signing, and verification\n"
      << "  bonus         Run formula-level primitive demonstrations\n"
      << "  --kat <json>  Run signature known-answer/self-validation tests\n"
      << "  --selftest    Run offline self-tests\n"
      << "  --help        Show this help\n\n"
      << "Key generation:\n"
      << "  sigtool keygen --algo ecdsa-p256 --pub pub.pem --priv priv.pem\n"
      << "  sigtool keygen --algo ecdsa-p384 --pub pub.pem --priv priv.pem\n"
      << "  sigtool keygen --algo rsa-pss-3072 --pub pub.pem --priv priv.pem\n\n"
      << "Signing:\n"
      << "  sigtool sign --algo ecdsa-p256 --priv priv.pem --in msg.bin --out sig.bin --hash sha256\n"
      << "  sigtool sign --algo rsa-pss-3072 --priv priv.pem --text \"hello\" --out sig.b64 --encode base64\n\n"
      << "Verification:\n"
      << "  sigtool verify --algo ecdsa-p256 --pub pub.pem --in msg.bin --sig sig.bin --hash sha256\n"
      << "  sigtool verify --algo rsa-pss-3072 --pub pub.pem --text \"hello\" --sig sig.b64 --encode base64\n\n"
      << "Batch verification manifest format:\n"
      << "  algo|pub_path|message_path|signature_path|hash|encoding\n\n"
      << "Benchmark:\n"
      << "  sigtool bench --runs 30 --ops 100\n\n"
      << "Bonus primitive demos:\n"
      << "  sigtool bonus --all\n"
      << "  sigtool bonus --topic ec\n"
      << "  sigtool bonus --topic modinv\n"
      << "  sigtool bonus --topic rsa-pow\n"
      << "  sigtool bonus --topic pss\n\n"
      << "Flags:\n"
      << "  --algo <name>      ecdsa-p256, ecdsa-p384, rsa-pss-3072\n"
      << "  --hash <name>      sha256 or sha384 (sha384 primarily for ECDSA-P384)\n"
      << "  --format <mode>    pem or der for keys\n"
      << "  --encode <mode>    raw, der, hex, or base64 for signatures\n"
      << "  --in <file>        Binary-safe input message\n"
      << "  --text <text>      UTF-8 input message\n"
      << "  --out <file>       Output signature path\n"
      << "  --pub <file>       Public key path\n"
      << "  --priv <file>      Private key path\n"
      << "  --sig <file>       Signature path\n"
      << "  --runs <n>         Benchmark runs\n"
      << "  --ops <n>          Operations per benchmark run\n";
}

std::map<std::string, std::string> parse(int argc, char** argv, int start) {
  std::map<std::string, std::string> args;
  for (int i = start; i < argc; ++i) {
    std::string k = argv[i];
    if (k.rfind("--", 0) != 0) throw sigtool::ToolError("unexpected argument: " + k);
    if (k == "--all") {
      args[k] = "true";
      continue;
    }
    if (i + 1 >= argc) throw sigtool::ToolError("missing value for " + k);
    args[k] = argv[++i];
  }
  return args;
}

std::string arg(const std::map<std::string, std::string>& args, const std::string& k,
                const std::string& d = "") {
  auto it = args.find(k);
  return it == args.end() ? d : it->second;
}

int int_arg(const std::map<std::string, std::string>& args, const std::string& k, int d) {
  std::string v = arg(args, k);
  return v.empty() ? d : std::stoi(v);
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
      sigtool::run_selftest();
      return 0;
    }
    if (cmd == "--kat") {
      if (argc < 3) throw sigtool::ToolError("--kat requires vector JSON path");
      sigtool::run_kat(argv[2]);
      return 0;
    }

    const auto args = parse(argc, argv, 2);
    if (cmd == "keygen") {
      sigtool::KeygenOptions o;
      o.algo = arg(args, "--algo");
      o.pub_path = arg(args, "--pub");
      o.priv_path = arg(args, "--priv");
      o.format = arg(args, "--format", "pem");
      sigtool::run_keygen(o);
      return 0;
    }
    if (cmd == "sign") {
      sigtool::SignOptions o;
      o.algo = arg(args, "--algo");
      o.input_path = arg(args, "--in");
      o.text = arg(args, "--text");
      o.priv_path = arg(args, "--priv");
      o.output_path = arg(args, "--out");
      o.hash = arg(args, "--hash", "sha256");
      o.encode = arg(args, "--encode", "raw");
      sigtool::run_sign(o);
      return 0;
    }
    if (cmd == "verify") {
      sigtool::VerifyOptions o;
      o.algo = arg(args, "--algo");
      o.input_path = arg(args, "--in");
      o.text = arg(args, "--text");
      o.sig_path = arg(args, "--sig");
      o.pub_path = arg(args, "--pub");
      o.hash = arg(args, "--hash", "sha256");
      o.encode = arg(args, "--encode", "raw");
      sigtool::run_verify(o);
      return 0;
    }
    if (cmd == "batch-verify") {
      sigtool::BatchOptions o;
      o.manifest_path = arg(args, "--manifest");
      sigtool::run_batch_verify(o);
      return 0;
    }
    if (cmd == "bench") {
      sigtool::BenchOptions o;
      o.runs = int_arg(args, "--runs", 30);
      o.ops = int_arg(args, "--ops", 100);
      sigtool::run_benchmark(o);
      return 0;
    }
    if (cmd == "bonus") {
      sigtool::run_bonus(args.find("--all") != args.end() ? "all" : arg(args, "--topic", "all"));
      return 0;
    }

    throw sigtool::ToolError("unknown command: " + cmd);
  } catch (const sigtool::ToolError& e) {
    std::cerr << "ERROR: " << e.what() << "\n";
    return 1;
  } catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << "\n";
    return 1;
  }
}
