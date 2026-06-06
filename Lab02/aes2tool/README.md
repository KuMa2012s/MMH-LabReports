# Lab 2 - Pure C++ AES Tool

`aes2tool` is an educational AES implementation for Lab 2. It implements the AES
round transformations manually in C++ and uses CTR mode without external
cryptographic libraries.

## Features

- AES-128 core required by FIPS-197.
- Bonus AES-192 and AES-256 key schedules.
- CTR mode with 16-byte IV and big-endian counter increment.
- Bonus XTS mode for full 16-byte blocks using two AES keys.
- Known Answer Tests from FIPS-197 and NIST SP 800-38A.
- Benchmark table for throughput, latency, standard deviation, and 95% CI.
- CPU AES-NI feature detection for hardware-acceleration discussion.

## Build

Windows:

```powershell
cd Lab02\aes2tool
& 'C:\Program Files\CMake\bin\cmake.exe' -S . -B build
& 'C:\Program Files\CMake\bin\cmake.exe' --build build --config Release
& 'C:\Program Files\CMake\bin\ctest.exe' --test-dir build -C Release --output-on-failure
```

Linux:

```bash
cd Lab02/aes2tool
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

## Usage

```powershell
.\build\Release\aes2tool.exe --kat .\vectors\aes_kat.json
.\build\Release\aes2tool.exe keygen --bits 128 --out key.bin
.\build\Release\aes2tool.exe encrypt --mode ctr --key key.bin --iv-hex 000102030405060708090a0b0c0d0e0f --text "hello" --out ct.bin
.\build\Release\aes2tool.exe decrypt --mode ctr --key key.bin --iv-hex 000102030405060708090a0b0c0d0e0f --in ct.bin --out pt.txt
.\build\Release\aes2tool.exe bench --all --runs 30 --ops 100
```

## Cross-Validation

The implementation does not call OpenSSL or Crypto++ internally. For report
validation, compare the NIST CTR vector with OpenSSL from the shell:

```bash
printf '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710' | xxd -r -p > pt.bin
openssl enc -aes-128-ctr -nopad \
  -K 2b7e151628aed2a6abf7158809cf4f3c \
  -iv f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff \
  -in pt.bin -out openssl_ct.bin
./build/aes2tool encrypt --mode ctr \
  --key-hex 2b7e151628aed2a6abf7158809cf4f3c \
  --iv-hex f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff \
  --in pt.bin --out aes2tool_ct.bin
cmp openssl_ct.bin aes2tool_ct.bin
```

`cmp` should produce no output when both ciphertext files are identical.

## Security Notes

CTR provides confidentiality only. It does not detect tampering and must be
combined with a MAC or replaced by an AEAD mode in real systems. Reusing the
same IV with the same key repeats the keystream and is catastrophic. This
implementation is educational and uses table-based S-box lookups, so it is not
constant-time against cache/timing side-channel attacks.
