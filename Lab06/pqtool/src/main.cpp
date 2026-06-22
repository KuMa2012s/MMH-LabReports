#include "pqtool.hpp"

#include <iostream>
#include <map>
#include <string>

namespace {

void help() {
  std::cout
      << "pqtool - Lab 6 Post-Quantum Signatures, KEM, and Certificates\n\n"
      << "Commands:\n"
      << "  keygen         Generate ML-DSA or ML-KEM key pairs\n"
      << "  sign           Create detached ML-DSA signatures\n"
      << "  verify         Verify detached ML-DSA signatures\n"
      << "  encaps         ML-KEM encapsulation: public key -> ciphertext + shared secret\n"
      << "  decaps         ML-KEM decapsulation: private key + ciphertext -> shared secret\n"
      << "  cert-create    Build a minimal ML-DSA-signed JSON PQ certificate\n"
      << "  cert-verify    Verify a minimal PQ certificate with a CA public key\n"
      << "  batch-verify   Verify many signatures from a manifest\n"
      << "  batch-decaps   Time many KEM decapsulation operations from a manifest\n"
      << "  bench          Benchmark ML-DSA and ML-KEM operations\n"
      << "  bonus          Run formula-level lattice primitive demonstrations\n"
      << "  --kat <json>   Run offline known-answer/self-validation tests\n"
      << "  --selftest     Run all internal correctness and negative tests\n"
      << "  --help         Show this help\n\n"
      << "Algorithms:\n"
      << "  mldsa-44       Required ML-DSA level-2 style signature interface\n"
      << "  mldsa-65       Bonus ML-DSA level-3 style signature interface\n"
      << "  mlkem-512      Required ML-KEM level-2 style KEM interface\n\n"
      << "Key generation:\n"
      << "  pqtool keygen --algo mldsa-44 --pub pub.pem --priv priv.pem\n"
      << "  pqtool keygen --algo mldsa-65 --pub pub.pem --priv priv.pem\n"
      << "  pqtool keygen --algo mlkem-512 --pub kem_pub.pem --priv kem_priv.pem\n\n"
      << "Signing and verification:\n"
      << "  pqtool sign --algo mldsa-44 --priv priv.pem --in msg.bin --out sig.bin\n"
      << "  pqtool verify --algo mldsa-44 --pub pub.pem --in msg.bin --sig sig.bin\n"
      << "  pqtool sign --algo mldsa-44 --priv priv.pem --text \"hello\" --out sig.b64 --encode base64\n\n"
      << "KEM encapsulation and decapsulation:\n"
      << "  pqtool encaps --algo mlkem-512 --pub kem_pub.pem --ct ct.bin --ss ss1.bin\n"
      << "  pqtool decaps --algo mlkem-512 --priv kem_priv.pem --ct ct.bin --ss ss2.bin\n\n"
      << "Certificate mini-project:\n"
      << "  pqtool cert-create --subject \"Alice\" --subject-pub pub.pem --ca-priv ca_priv.pem --out cert.json\n"
      << "  pqtool cert-verify --cert cert.json --ca-pub ca_pub.pem\n\n"
      << "Batch manifests:\n"
      << "  batch-verify line: algo|pub_path|message_path|signature_path|encoding\n"
      << "  batch-decaps line: algo|priv_path|ciphertext_path|shared_secret_output\n\n"
      << "Benchmark:\n"
      << "  pqtool bench --runs 30 --ops 100\n\n"
      << "Bonus primitive demos:\n"
      << "  pqtool bonus --all\n"
      << "  pqtool bonus --topic ntt\n"
      << "  pqtool bonus --topic reduce\n"
      << "  pqtool bonus --topic rejection\n"
      << "  pqtool bonus --topic timing\n\n"
      << "Flags:\n"
      << "  --algo <name>       mldsa-44, mldsa-65, mlkem-512\n"
      << "  --format <mode>     pem or der for keys (default: pem)\n"
      << "  --encode <mode>     raw or base64 for signatures (default: raw)\n"
      << "  --in <file>         Binary-safe input message\n"
      << "  --text <text>       UTF-8 input message\n"
      << "  --out <file>        Output path\n"
      << "  --pub <file>        Public key path\n"
      << "  --priv <file>       Private key path\n"
      << "  --sig <file>        Signature path\n"
      << "  --ct <file>         KEM ciphertext path\n"
      << "  --ss <file>         KEM shared-secret path\n"
      << "  --subject <text>    Certificate subject\n"
      << "  --issuer <text>     Certificate issuer (default: PQ-CA)\n"
      << "  --runs <n>          Benchmark runs\n"
      << "  --ops <n>           Operations per benchmark run\n\n"
      << "Notes:\n"
      << "  Main ML-DSA and ML-KEM operations are delegated to OpenSSL 3.5+\n"
      << "  implementations through the pqtool CLI. Bonus commands keep compact\n"
      << "  educational lattice-style primitive demos for report discussion.\n";
}

std::map<std::string, std::string> parse(int argc, char** argv, int start) {
  std::map<std::string, std::string> args;
  for (int i = start; i < argc; ++i) {
    std::string key = argv[i];
    if (key.rfind("--", 0) != 0) {
      throw pqtool::ToolError("unexpected argument: " + key);
    }
    if (key == "--all") {
      args[key] = "true";
      continue;
    }
    if (i + 1 >= argc) {
      throw pqtool::ToolError("missing value for " + key);
    }
    args[key] = argv[++i];
  }
  return args;
}

std::string arg(const std::map<std::string, std::string>& args, const std::string& key,
                const std::string& fallback = "") {
  const auto it = args.find(key);
  return it == args.end() ? fallback : it->second;
}

int int_arg(const std::map<std::string, std::string>& args, const std::string& key, int fallback) {
  const std::string value = arg(args, key);
  return value.empty() ? fallback : std::stoi(value);
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
      pqtool::run_selftest();
      return 0;
    }
    if (cmd == "--kat") {
      if (argc < 3) {
        throw pqtool::ToolError("--kat requires vector JSON path");
      }
      pqtool::run_kat(argv[2]);
      return 0;
    }

    const auto args = parse(argc, argv, 2);

    if (cmd == "keygen") {
      pqtool::KeygenOptions opt;
      opt.algo = arg(args, "--algo");
      opt.pub_path = arg(args, "--pub");
      opt.priv_path = arg(args, "--priv");
      opt.format = arg(args, "--format", "pem");
      pqtool::run_keygen(opt);
      return 0;
    }
    if (cmd == "sign") {
      pqtool::SignOptions opt;
      opt.algo = arg(args, "--algo");
      opt.input_path = arg(args, "--in");
      opt.text = arg(args, "--text");
      opt.priv_path = arg(args, "--priv");
      opt.output_path = arg(args, "--out");
      opt.encode = arg(args, "--encode", "raw");
      pqtool::run_sign(opt);
      return 0;
    }
    if (cmd == "verify") {
      pqtool::VerifyOptions opt;
      opt.algo = arg(args, "--algo");
      opt.input_path = arg(args, "--in");
      opt.text = arg(args, "--text");
      opt.sig_path = arg(args, "--sig");
      opt.pub_path = arg(args, "--pub");
      opt.encode = arg(args, "--encode", "raw");
      pqtool::run_verify(opt);
      return 0;
    }
    if (cmd == "encaps") {
      pqtool::KemOptions opt;
      opt.algo = arg(args, "--algo");
      opt.pub_path = arg(args, "--pub");
      opt.ct_path = arg(args, "--ct");
      opt.ss_path = arg(args, "--ss");
      pqtool::run_encaps(opt);
      return 0;
    }
    if (cmd == "decaps") {
      pqtool::KemOptions opt;
      opt.algo = arg(args, "--algo");
      opt.priv_path = arg(args, "--priv");
      opt.ct_path = arg(args, "--ct");
      opt.ss_path = arg(args, "--ss");
      pqtool::run_decaps(opt);
      return 0;
    }
    if (cmd == "cert-create") {
      pqtool::CertCreateOptions opt;
      opt.subject = arg(args, "--subject");
      opt.issuer = arg(args, "--issuer", "PQ-CA");
      opt.subject_pub_path = arg(args, "--subject-pub");
      opt.ca_priv_path = arg(args, "--ca-priv");
      opt.output_path = arg(args, "--out");
      pqtool::run_cert_create(opt);
      return 0;
    }
    if (cmd == "cert-verify") {
      pqtool::CertVerifyOptions opt;
      opt.cert_path = arg(args, "--cert");
      opt.ca_pub_path = arg(args, "--ca-pub");
      pqtool::run_cert_verify(opt);
      return 0;
    }
    if (cmd == "batch-verify") {
      pqtool::BatchOptions opt;
      opt.manifest_path = arg(args, "--manifest");
      pqtool::run_batch_verify(opt);
      return 0;
    }
    if (cmd == "batch-decaps") {
      pqtool::BatchOptions opt;
      opt.manifest_path = arg(args, "--manifest");
      pqtool::run_batch_decaps(opt);
      return 0;
    }
    if (cmd == "bench") {
      pqtool::BenchOptions opt;
      opt.runs = int_arg(args, "--runs", 30);
      opt.ops = int_arg(args, "--ops", 100);
      pqtool::run_benchmark(opt);
      return 0;
    }
    if (cmd == "bonus") {
      pqtool::run_bonus(args.find("--all") != args.end() ? "all" : arg(args, "--topic", "all"));
      return 0;
    }

    throw pqtool::ToolError("unknown command: " + cmd);
  } catch (const pqtool::ToolError& e) {
    std::cerr << "ERROR: " << e.what() << "\n";
    return 1;
  } catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << "\n";
    return 1;
  }
}
