# hashtool - Lab 4 Hashing, PKI, and Practical Attacks

`hashtool` implements the Lab 4 requirements:

- SHA-2: SHA-224, SHA-256, SHA-384, SHA-512.
- SHA-3: SHA3-224, SHA3-256, SHA3-384, SHA3-512.
- SHAKE128 and SHAKE256 with caller-selected output length.
- Streamed binary-safe file hashing.
- JSON known-answer tests.
- X.509 PEM/DER certificate parsing and RSA signature verification with issuer certificate.
- Safe offline MD5 collision demonstration.
- SHA-256 length-extension attack demonstration, including custom continuation code.
- Hash benchmark for SHA-256, SHA-512, SHA3-256, SHA3-512.

## Build

Windows:

```powershell
cd "C:\Users\Hai Nguyen\Desktop\MMH\LabReports\Lab04\hashtool"
& 'C:\Program Files\CMake\bin\cmake.exe' -S . -B build
& 'C:\Program Files\CMake\bin\cmake.exe' --build build --config Release
```

Linux:

```bash
sudo apt install cmake g++ libcrypto++-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Tests

```powershell
.\build\Release\hashtool.exe --kat .\vectors\hash_kat.json
.\build\Release\hashtool.exe --selftest
& 'C:\Program Files\CMake\bin\ctest.exe' --test-dir build -C Release --output-on-failure
```

## Hashing

```powershell
.\build\Release\hashtool.exe hash --algo sha256 --text "abc"
.\build\Release\hashtool.exe hash --algo sha512 --in .\README.md --stream
.\build\Release\hashtool.exe hash --algo shake256 --outlen 64 --text "abc"
.\build\Release\hashtool.exe hash --algo sha3-256 --in .\README.md --out .\testing\digest.bin --encode raw
```

## Certificate Analysis

```powershell
.\build\Release\hashtool.exe cert --in .\certs\leaf.pem
.\build\Release\hashtool.exe cert --in .\certs\leaf.pem --issuer .\certs\issuer.pem --verify
```

The built-in parser extracts subject, issuer, SPKI algorithm, signature algorithm, validity, key usage, and SANs. Signature verification currently supports RSA PKCS#1 v1.5 certificates signed with SHA-256/384/512.

## MD5 Collision Demo

```powershell
.\build\Release\hashtool.exe md5-collision --generate --out-dir .\attacks
.\build\Release\hashtool.exe md5-collision --file1 .\attacks\md5_collision_1.bin --file2 .\attacks\md5_collision_2.bin
```

This demo uses benign offline collision blocks and does not target real systems.

## Length-Extension Demo

```powershell
.\build\Release\hashtool.exe length-extension --demo
```

Or provide your own naive MAC:

```powershell
.\build\Release\hashtool.exe length-extension --key-len 9 --mac HEX --message "user=guest" --append "&admin=true"
```

## Benchmark

```powershell
.\build\Release\hashtool.exe bench --runs 30 --ops 10
.\build\Release\hashtool.exe bench --runs 5 --ops 3 --include-1gib
.\build\Release\hashtool.exe bench-io --runs 5 --ops 3
```

## Limitations

- X.509 signature verification supports RSA issuer keys with SHA-256/384/512 PKCS#1 v1.5 signatures.
- ECDSA certificate verification is parsed but not verified by this compact lab implementation.
- The MD5 collision demo is defensive and offline only.
- The custom length-extension implementation targets SHA-256 and the deliberately unsafe `MAC = SHA256(k || m)` construction.
