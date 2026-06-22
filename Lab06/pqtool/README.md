# pqtool - Lab 6 Post-Quantum Signatures & Certificates

`pqtool` is a C++17 command-line tool for Lab 6. It wraps OpenSSL 3.5+ ML-DSA
and ML-KEM operations behind the same course-friendly CLI used for testing,
certificate demos, negative tests, benchmarks, and advanced-topic discussion.

Important scope note: main ML-DSA and ML-KEM keygen/sign/verify/encaps/decaps
operations are delegated to OpenSSL. The `bonus` command keeps compact
educational lattice-style primitive demonstrations for report discussion.

## Features

- `mldsa-44` OpenSSL ML-DSA-44 key generation, detached signing, and verification.
- `mldsa-65` OpenSSL ML-DSA-65 bonus signature parameter set.
- `mlkem-512` OpenSSL ML-KEM-512 key generation, encapsulation, and decapsulation.
- PEM/DER-like key storage for lab artifacts.
- Raw and base64 detached signatures.
- Binary KEM ciphertexts and 32-byte shared secrets.
- Minimal JSON PQ certificate signed by an ML-DSA-style CA key.
- Negative tests, batch verification, batch decapsulation timing.
- Benchmark output with latency, throughput, standard deviation, and CI95.
- Bonus demos: modular reduction, rejection sampling, toy polynomial/NTT-style
  arithmetic, and timing variance measurement.

## Dependencies

- CMake 4.3.3 or newer.
- C++17 compiler:
  - Windows: MSVC or MinGW64.
  - Linux: GCC or Clang.
- Crypto++ headers and library.
- OpenSSL 3.5 or newer in `PATH` for ML-DSA/ML-KEM runtime operations.

On the lab Windows machine, Crypto++ is expected at:

```text
C:\cryptolibrary\include\cryptopp
C:\cryptolibrary\libs
```

If Crypto++ is somewhere else, configure with `-DCRYPTOPP_ROOT=...` or explicit
`-DCRYPTOPP_INCLUDE_DIR=... -DCRYPTOPP_LIBRARY=...`.

## Build

Windows:

```powershell
cd "C:\Users\Hai Nguyen\Desktop\MMH\LabReports\Lab06\pqtool"
& "C:\Program Files\CMake\bin\cmake.exe" -S . -B build
& "C:\Program Files\CMake\bin\cmake.exe" --build build --config Release
```

If a normal PowerShell session cannot see `cmake`/`cl`, or CMake selects a
Visual Studio instance without the C++ compiler, use the Build Tools developer
environment explicitly:

```powershell
cd "C:\Users\Hai Nguyen\Desktop\MMH\LabReports\Lab06\pqtool"
cmd /c 'call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 && "C:\Program Files\CMake\bin\cmake.exe" -S . -B build-nmake -G "NMake Makefiles" -DCRYPTOPP_ROOT=C:\cryptolibrary -DCMAKE_BUILD_TYPE=Release'
cmd /c 'call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 && "C:\Program Files\CMake\bin\cmake.exe" --build build-nmake'
```

Linux:

```bash
cd Lab06/pqtool
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Quick Start

Generate ML-DSA keys and sign/verify:

```powershell
.\build\Release\pqtool.exe keygen --algo mldsa-44 --pub .\testing\mldsa_pub.pem --priv .\testing\mldsa_priv.pem
.\build\Release\pqtool.exe sign --algo mldsa-44 --priv .\testing\mldsa_priv.pem --text "Lab 6 message" --out .\testing\sig.bin
.\build\Release\pqtool.exe verify --algo mldsa-44 --pub .\testing\mldsa_pub.pem --text "Lab 6 message" --sig .\testing\sig.bin
```

Generate ML-KEM keys and compare shared secrets:

```powershell
.\build\Release\pqtool.exe keygen --algo mlkem-512 --pub .\testing\kem_pub.pem --priv .\testing\kem_priv.pem
.\build\Release\pqtool.exe encaps --algo mlkem-512 --pub .\testing\kem_pub.pem --ct .\testing\ct.bin --ss .\testing\ss_enc.bin
.\build\Release\pqtool.exe decaps --algo mlkem-512 --priv .\testing\kem_priv.pem --ct .\testing\ct.bin --ss .\testing\ss_dec.bin
Get-FileHash .\testing\ss_enc.bin,.\testing\ss_dec.bin
```

Create and verify a PQ certificate:

```powershell
.\build\Release\pqtool.exe keygen --algo mldsa-44 --pub .\testing\ca_pub.pem --priv .\testing\ca_priv.pem
.\build\Release\pqtool.exe cert-create --subject "Hai Nguyen" --subject-pub .\testing\mldsa_pub.pem --ca-priv .\testing\ca_priv.pem --out .\testing\pq_cert.json
.\build\Release\pqtool.exe cert-verify --cert .\testing\pq_cert.json --ca-pub .\testing\ca_pub.pem
```

Run validation and benchmark:

```powershell
.\build\Release\pqtool.exe --kat .\vectors\pq_kat.json
.\build\Release\pqtool.exe --selftest
.\build\Release\pqtool.exe bonus --all
.\build\Release\pqtool.exe bench --runs 30 --ops 100
```

Run CTest:

```powershell
& "C:\Program Files\CMake\bin\ctest.exe" --test-dir build -C Release --output-on-failure
```

## Batch Manifest Formats

`batch-verify`:

```text
mldsa-44|testing/mldsa_pub.pem|testing/msg.bin|testing/sig.bin|raw
```

`batch-decaps`:

```text
mlkem-512|testing/kem_priv.pem|testing/ct.bin|testing/ss_batch.bin
```

## Report Notes

In the report, describe the main implementation as an OpenSSL-backed PQC CLI:
`pqtool` calls OpenSSL ML-DSA/ML-KEM operations while preserving a uniform lab
interface. The bonus section can discuss the educational primitive demos:
modular reduction, rejection sampling, toy polynomial arithmetic, and timing
variance.
