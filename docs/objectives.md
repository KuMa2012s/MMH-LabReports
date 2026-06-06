## Course Level: Upper Undergraduate / Early Graduate
Platforms: Windows 10/11 and Linux (Ubuntu LTS recommended)
Languages: Modern C++ (C++17 or later)
Libraries: Crypto++ and/or OpenSSL (as specified per lab)
Optional GUI: Python (PySide6/Qt) or C# (WPF/WinUI)
Build System: CMake (required)
Submission Format: Single ZIP/RAR archive
## Course Laboratory Objectives
Across Labs 1–6, students will:
- Implement and analyze modern cryptographic primitives
- Apply secure engineering practices in CLI-based tools
- Validate correctness using official NIST test vectors
- Detect and prevent common cryptographic misuse
- Perform statistically sound performance benchmarking
- Produce professional-quality technical reports
Submission Structure (All Labs). MSV.All6labs.rar
Single compressed archive must contain:
- Source code for all labs

- CMake build system
- README.md (top-level)
- Report (single PDF/DOCX covering all labs)
- Binaries for Windows and Linux
- Unit tests
- Build scripts
- Any required resource files
## 1. Common Engineering Requirements
These apply to all labs.
## A. Environment & Tooling
## Build Requirements
- Must use CMake
- Must support out-of-source builds:
- mkdir build && cd build
- cmake ..
- cmake --build .
- Must compile successfully on:
o Ubuntu LTS
o Windows (MSVC and MinGW64)
README.md Must Include
- Dependency list (with versions)
- Installation instructions (Windows & Linux)
- Build commands for both OSes
- Example CLI usage
- Known limitations
CLI Standard (Uniform Across Labs)
All tools must follow a consistent structure:

mytool <command>
[--in INFILE | --text "..."]
[--out OUTFILE]
[--key KEYFILE | --key-hex HEX]
[--iv IV-hex]
[--nonce NONCE-hex]
[--mode MODE]
## [--aead]
[--encode hex|base64|raw]
## [--threads N]
[--kat path/to/vectors.json]
## [--verbose]
Programs must:
- Accept UTF-8 input
- Produce UTF-8 output
- Fail closed on malformed input
B. Input/Output & Encoding
## Input
- --in file (binary-safe)
- --text "..." (UTF-8)
## Output
- --out file (binary-safe)
- On-screen output defaults to:
o Hex for ciphertext, digest, signatures
- File output defaults to:
o Raw binary (unless overridden)
## Encoding Options

--encode hex
--encode base64
--encode raw

## 2. Randomness & Key Management
## Secure Randomness
Must use:
- Crypto++ AutoSeededRandomPool
- OpenSSL RAND_bytes
Never use:
- rand()
- std::random for cryptographic purposes

IV / Nonce Rules
- Must enforce proper IV length
- Must prevent nonce reuse when prohibited
- Must auto-generate securely if missing (where appropriate)
- Must document storage format (header/sidecar)

## Minimum Key Sizes
## Algorithm Requirement
AES 128/192/256 bits (prefer 256 in reports)
RSA ≥ 3072 bits
ECDSA ≥ P-256 (secp256r1)

## 3. Verification & Testing

Known Answer Tests (KATs)
Each lab must include:
- NIST test vectors where applicable
- A --kat runner
- JSON vector format
## Example:
mytool --kat vectors.json
Must output:
- PASS/FAIL per test
- Summary statistics

## Negative Testing
Students must include:
- Wrong key tests
- Tampered ciphertext tests
- Tampered authentication tag tests (AEAD)
- Malformed input tests
- Corrupted PEM/key file tests (where applicable)
Programs must fail securely.

## Unit Testing
- Must include Catch2 or GoogleTest
- ctest must pass on Windows and Linux
- CI integration recommended (optional)

- Performance Methodology (Standardized)
For each cryptographic algorithm:

- Warm-up: 1–2 seconds
- Execute a block of ~1,000 operations
- Repeat 30–100 times
- Collect statistics

## Required Statistical Reporting
Report must include:
## • Mean
## • Median
- Standard deviation
- 95% confidence interval

## Comparative Analysis
Where applicable, compare:
- Windows vs Linux
- Algorithm variants
- Mode overhead
- Hardware acceleration impact
## Include:
## • Tables
## • Plots
- Interpretation (not just raw numbers)

## 5. Security Engineering Standards
Each lab report must discuss:
- Threat model
- Misuse scenarios

- Known attacks relevant to the algorithm
- Secure defaults
- Fail-closed behavior
- Limitations of the implementation
Students must demonstrate understanding beyond implementation.

## 6. Deliverables Checklist
Final archive must include:
- Source code
- CMake files
## • README
- Unit tests
- Windows binary
- Linux binary
- Report (PDF/DOCX)
- Self-grade checklist
- Academic integrity statement

## 7. Report Requirements (Single File for All Labs)
The report must contain:
- Objectives per lab
- Implementation details
- Test results
- Performance methodology
- Statistical tables & plots
- Security analysis
- Cross-platform comparison

- Lessons learned
Minimum expected length:
- 60 pages total (typical)

## 8. Optional GUI Bonus
Students may:
- Export crypto core as:
o .dll
o .so
o .a
o .lib
- Build GUI in:
o Python (PySide6/Qt)
o C# (WPF/WinUI)
GUI must:
- Call the same compiled library
- Not duplicate cryptographic logic
Bonus awarded per lab specification.

## 9. Academic Integrity & Ethics
Students must include:
- Statement of originality
- Disclosure of AI/tool assistance (if used)
- Proper citation of external references
- No copying of external implementations
Violation results in academic penalty.


Expected Program-Level Learning Impact
Upon completing Labs 1–6, students should:
- Understand symmetric and asymmetric cryptography deeply
- Implement cryptographic systems safely
- Recognize real-world misuse patterns
- Perform statistically sound benchmarking
- Produce professional-grade technical documentation
- Bridge theory and engineering practice
