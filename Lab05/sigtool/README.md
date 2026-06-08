# sigtool - Lab 5 Classical Digital Signatures

`sigtool` implements the Lab 5 requirements for ECDSA and RSA-PSS signatures.

- ECDSA-P256 with SHA-256.
- ECDSA-P384 bonus with SHA-384.
- RSA-PSS-3072 with SHA-256 and randomized salt.
- Detached signature generation and verification.
- PEM/DER key storage for tool-generated keys.
- Signature encodings: raw, DER for ECDSA, hex, base64.
- Batch verification from a manifest.
- Negative tests and CTest integration.
- Benchmark for key generation, signing, verification, throughput, and signature size.
- Formula-level bonus demos: elliptic-curve point arithmetic, modular inversion,
  RSA modular exponentiation, and PSS padding generation.

## Build

Windows:

```powershell
cd "C:\Users\Hai Nguyen\Desktop\MMH\LabReports\Lab05\sigtool"
& 'C:\Program Files\CMake\bin\cmake.exe' -S . -B build
& 'C:\Program Files\CMake\bin\cmake.exe' --build build --config Release
```

Linux:

```bash
sudo apt install cmake g++ libcrypto++-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Usage

```powershell
.\build\Release\sigtool.exe keygen --algo ecdsa-p256 --pub testing\ecdsa_pub.pem --priv testing\ecdsa_priv.pem
.\build\Release\sigtool.exe sign --algo ecdsa-p256 --priv testing\ecdsa_priv.pem --text "hello" --out testing\ecdsa.sig --hash sha256
.\build\Release\sigtool.exe verify --algo ecdsa-p256 --pub testing\ecdsa_pub.pem --text "hello" --sig testing\ecdsa.sig --hash sha256

.\build\Release\sigtool.exe keygen --algo rsa-pss-3072 --pub testing\rsa_pub.pem --priv testing\rsa_priv.pem
.\build\Release\sigtool.exe sign --algo rsa-pss-3072 --priv testing\rsa_priv.pem --text "hello" --out testing\rsa.sig --hash sha256
.\build\Release\sigtool.exe verify --algo rsa-pss-3072 --pub testing\rsa_pub.pem --text "hello" --sig testing\rsa.sig --hash sha256
```

## Tests

```powershell
.\build\Release\sigtool.exe --selftest
.\build\Release\sigtool.exe --kat .\vectors\sig_kat.json
.\build\Release\sigtool.exe bonus --all
& 'C:\Program Files\CMake\bin\ctest.exe' --test-dir build -C Release --output-on-failure
```

## Benchmark

```powershell
.\build\Release\sigtool.exe bench --runs 30 --ops 100
```

## Limitations

- Main signing and verification paths use Crypto++ primitives for security.
- ECDSA signatures use a deterministic HMAC-DRBG nonce source seeded by private-key material and the message.
- Formula-level bonus code is educational and is not used as a replacement for constant-time production cryptographic libraries.
- Tool-generated PEM files wrap Crypto++ DER key material and are intended for this lab tool.
