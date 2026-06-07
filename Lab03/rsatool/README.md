# rsatool - Lab 3 RSA-OAEP & Hybrid Encryption

`rsatool` implements the Lab 3 requirements with Crypto++:

- RSA-3072 OAEP with SHA-256 and MGF1-SHA256.
- RSA-4096 for performance comparison.
- Optional OAEP label.
- PEM, DER, and metadata JSON key outputs.
- Automatic hybrid encryption for plaintext larger than the RSA-OAEP limit.
- Hybrid envelope: RSA-OAEP wrapped AES-256 key + AES-256-GCM ciphertext.
- Raw, hex, and base64 ciphertext container encodings.
- Automated correctness and negative tests.
- Benchmark output for RSA and hybrid encryption.
- Bonus manual OAEP encode/decode self-test.

## Build

Windows with Crypto++ in `C:/cryptolibrary`:

```powershell
cd "C:\Users\Hai Nguyen\Desktop\MMH\LabReports\Lab03\rsatool"
& 'C:\Program Files\CMake\bin\cmake.exe' -S . -B build
& 'C:\Program Files\CMake\bin\cmake.exe' --build build --config Release
```

Portable Crypto++ path:

```powershell
cmake -S . -B build -DCRYPTOPP_ROOT=C:/path/to/cryptolibrary
cmake --build build --config Release
```

Linux:

```bash
sudo apt install cmake g++ libcrypto++-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Tests

Windows:

```powershell
& 'C:\Program Files\CMake\bin\ctest.exe' --test-dir build -C Release --output-on-failure
```

Direct self-tests:

```powershell
.\build\Release\rsatool.exe --kat .\vectors\rsatool_kat.json
.\build\Release\rsatool.exe --selftest
.\build\Release\rsatool.exe oaep-selftest
```

`--kat` checks deterministic known-answer values for RSA-OAEP plaintext limits,
MGF1-SHA256, AES-256-GCM, and manual OAEP support routines. RSA-OAEP encryption
itself is randomized, so its ciphertext is validated by roundtrip and negative
tests instead of a fixed ciphertext vector.

## Commands

Generate RSA keys:

```powershell
.\build\Release\rsatool.exe keygen --bits 3072 --pub testing\pub.pem --priv testing\priv.pem --pub-der testing\pub.der --priv-der testing\priv.der --meta testing\key.json
```

Encrypt and decrypt a small direct RSA-OAEP message:

```powershell
.\build\Release\rsatool.exe encrypt --text "Lab 3 RSA-OAEP message" --pub testing\pub.pem --out testing\ct.bin --label report
.\build\Release\rsatool.exe decrypt --in testing\ct.bin --priv testing\priv.pem --out testing\pt.txt --label report
Get-Content testing\pt.txt
```

Create a large file to trigger hybrid encryption:

```powershell
$bytes = New-Object byte[] (1024 * 1024)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[System.IO.File]::WriteAllBytes("testing\large.bin", $bytes)
.\build\Release\rsatool.exe encrypt --in testing\large.bin --pub testing\pub.pem --out testing\large.ct
.\build\Release\rsatool.exe decrypt --in testing\large.ct --priv testing\priv.pem --out testing\large.dec
```

Use base64 container encoding:

```powershell
.\build\Release\rsatool.exe encrypt --text "base64 demo" --pub testing\pub.pem --out testing\ct.b64 --format base64
.\build\Release\rsatool.exe decrypt --in testing\ct.b64 --priv testing\priv.pem --out testing\pt.txt --format base64
```

Benchmark:

```powershell
.\build\Release\rsatool.exe bench --runs 5 --ops 5
.\build\Release\rsatool.exe bench --runs 3 --ops 10 --skip-100mib
```

## Security Notes

RSA-OAEP with SHA-256 is used for asymmetric encryption. RSA is only suitable for short messages because OAEP has a strict size limit. With RSA-3072 and SHA-256, the maximum direct plaintext is 318 bytes. Larger messages are encrypted with AES-256-GCM, and only the random AES key is wrapped with RSA-OAEP.

AES-GCM uses a fresh 96-bit IV for every hybrid encryption. Decryption verifies the authentication tag before plaintext is written. Tampered RSA ciphertext, AES-GCM ciphertext, wrong OAEP label, wrong private key, and malformed envelope headers are rejected.
