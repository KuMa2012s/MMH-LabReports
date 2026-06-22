#pragma once

#include <stdexcept>
#include <string>

namespace pqtool {

class ToolError : public std::runtime_error {
public:
  explicit ToolError(const std::string& message) : std::runtime_error(message) {}
};

struct KeygenOptions {
  std::string algo;
  std::string pub_path;
  std::string priv_path;
  std::string format = "pem";
};

struct SignOptions {
  std::string algo;
  std::string input_path;
  std::string text;
  std::string priv_path;
  std::string output_path;
  std::string encode = "raw";
};

struct VerifyOptions {
  std::string algo;
  std::string input_path;
  std::string text;
  std::string sig_path;
  std::string pub_path;
  std::string encode = "raw";
};

struct KemOptions {
  std::string algo;
  std::string pub_path;
  std::string priv_path;
  std::string ct_path;
  std::string ss_path;
};

struct CertCreateOptions {
  std::string subject;
  std::string issuer = "PQ-CA";
  std::string subject_pub_path;
  std::string ca_priv_path;
  std::string output_path;
};

struct CertVerifyOptions {
  std::string cert_path;
  std::string ca_pub_path;
};

struct BatchOptions {
  std::string manifest_path;
};

struct BenchOptions {
  int runs = 30;
  int ops = 100;
};

void run_keygen(const KeygenOptions& opt);
void run_sign(const SignOptions& opt);
void run_verify(const VerifyOptions& opt);
void run_encaps(const KemOptions& opt);
void run_decaps(const KemOptions& opt);
void run_cert_create(const CertCreateOptions& opt);
void run_cert_verify(const CertVerifyOptions& opt);
void run_batch_verify(const BatchOptions& opt);
void run_batch_decaps(const BatchOptions& opt);
void run_benchmark(const BenchOptions& opt);
void run_kat(const std::string& vector_path);
void run_selftest();
void run_bonus(const std::string& topic);

} // namespace pqtool
