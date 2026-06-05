# aestool - Lab 1 Symmetric Encryption with Crypto++

`aestool` is a C++17 CLI tool for Lab 1. It uses Crypto++ for AES encryption modes, AEAD handling, Known Answer Tests, misuse checks, and benchmarking.

## Dependencies

Required:

- CMake 4.3.3 or newer
- C++17 compiler
- Crypto++

`CMakeLists.txt` does not need path edits. It auto-detects Crypto++ from common
install locations, `CRYPTOPP_ROOT`, or explicit CMake cache variables.

Supported ways to point to Crypto++:

```powershell
# Option 1: default local layout, auto-detected on this machine
C:\cryptolibrary

# Option 2: environment variable
$env:CRYPTOPP_ROOT = "D:\libs\cryptolibrary"

# Option 3: CMake configure flag
-DCRYPTOPP_ROOT="D:/libs/cryptolibrary"

# Option 4: exact include/library paths
-DCRYPTOPP_INCLUDE_DIR="D:/libs/cryptopp/include" `
-DCRYPTOPP_LIBRARY="D:/libs/cryptopp/lib/cryptlib.lib"
```

## Build on Windows

This project now requires CMake 4.3.3 or newer. If `cmake --version` still shows
the older Strawberry Perl CMake, call Kitware CMake directly:

Build:

```powershell
cd Lab01\aestool
& 'C:\Program Files\CMake\bin\cmake.exe' -S . -B build-cmake-4.3.3
& 'C:\Program Files\CMake\bin\cmake.exe' --build build-cmake-4.3.3 --config Release
& 'C:\Program Files\CMake\bin\ctest.exe' --test-dir build-cmake-4.3.3 -C Release --output-on-failure
```

If Crypto++ is installed somewhere else:

```powershell
& 'C:\Program Files\CMake\bin\cmake.exe' -S . -B build-cmake-4.3.3 -DCRYPTOPP_ROOT="D:/libs/cryptolibrary"
& 'C:\Program Files\CMake\bin\cmake.exe' --build build-cmake-4.3.3 --config Release
```

## Build on Linux

Install Crypto++ or point CMake to a compatible local build:

```bash
cd Lab01/aestool
cmake -S . -B build -DCRYPTOPP_ROOT=/path/to/cryptolibrary
cmake --build build --config Release
ctest --test-dir build --output-on-failure
```

## Optional Windows Compiler Builds

MSVC is the primary Windows build used for the submitted binary. The project also
builds with MinGW GCC and MinGW Clang when the compiler matches the Crypto++
archive ABI.

GCC:

```powershell
& 'C:\Program Files\CMake\bin\cmake.exe' -S . -B build-gcc -G Ninja `
  -DCMAKE_CXX_COMPILER=C:/msys64/mingw64/bin/g++.exe `
  -DCRYPTOPP_LIBRARY=C:/cryptolibrary/libs/gcc/libcryptopp.a
& 'C:\Program Files\CMake\bin\cmake.exe' --build build-gcc
& 'C:\Program Files\CMake\bin\ctest.exe' --test-dir build-gcc --output-on-failure
```

Clang using the MSYS2 MinGW64 environment:

```powershell
& 'C:\Program Files\CMake\bin\cmake.exe' -S . -B build-clang-mingw -G Ninja `
  -DCMAKE_CXX_COMPILER=C:/msys64/mingw64/bin/clang++.exe `
  -DCRYPTOPP_LIBRARY=C:/cryptolibrary/libs/gcc/libcryptopp.a
& 'C:\Program Files\CMake\bin\cmake.exe' --build build-clang-mingw
& 'C:\Program Files\CMake\bin\ctest.exe' --test-dir build-clang-mingw --output-on-failure
```

Avoid mixing a compiler with a Crypto++ archive built for a different C++
standard library ABI. For example, `C:/msys64/clang64/bin/clang++.exe` may not
link against the provided archive if the archive was built with a different
standard library configuration.

## CLI Examples

Generate a 256-bit AES key:

```bash
aestool keygen --bits 256 --out key.bin
```

Encrypt/decrypt with AES-GCM:

```bash
aestool encrypt --mode gcm --key key.bin --text "hello lab1" --out ct.bin --aad-text "metadata"
aestool decrypt --mode gcm --key key.bin --in ct.bin --out msg.txt
```

Run KATs:

```bash
aestool --kat vectors/nist_38a.json
aestool --kat vectors/aead.json
```

Benchmark one mode:

```bash
aestool bench --mode gcm --size 1048576 --runs 30 --ops 1000
```

Benchmark all required modes and sizes:

```bash
aestool bench --all --runs 30 --ops 100
```

## Bonus GUI

The bonus extension exports the C++ encryption core as a shared library:

- Windows: `aestool_core.dll` and `aestool_core.lib`
- Linux: `libaestool_core.so`

The Python GUI calls this compiled library through `ctypes`; it does not reimplement AES in Python.

Build the core first:

```powershell
cd Lab01\aestool
& 'C:\Program Files\CMake\bin\cmake.exe' -S . -B build-cmake-4.3.3
& 'C:\Program Files\CMake\bin\cmake.exe' --build build-cmake-4.3.3 --config Release
```

Install PyQt6 and run the GUI:

```powershell
python -m pip install -r gui\requirements.txt
python gui\aestool_gui.py
```

The GUI auto-loads:

```text
build-cmake-4.3.3\Release\aestool_core.dll
```

If the DLL is elsewhere, use the GUI's `Browse` button and load it manually.

## Notes

- ECB prints a warning and refuses inputs larger than 16 KiB unless `--allow-ecb` is supplied.
- CTR, GCM, and CCM reject repeated `(key_id, nonce)` pairs during encryption.
- IV/nonce metadata is written to `<ciphertext>.meta.json`.
- GCM/CCM authentication failure refuses decryption and does not write plaintext.
- XTS is included for disk-encryption discussion. It does not provide integrity.
