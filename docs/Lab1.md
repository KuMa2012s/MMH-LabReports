Lab 1 — Symmetric Encryption with Crypto++

## ⚠ Constraint
- Crypto++ library must be used for cryptographic primitives
- No use of OpenSSL, libsodium, or other crypto libraries
- C++ STL permitted
- Must compile on Windows and Linux
- CMake build system required
## Learning Outcomes
After completing this lab, students will be able to:
- Use Crypto++ safely across multiple block and stream cipher modes
- Correctly implement IV/nonce handling and misuse prevention
- Design robust file I/O and encoding pipelines
- Validate implementations using official NIST test vectors
- Benchmark symmetric encryption performance
- Detect and handle common cryptographic misuse (e.g., nonce reuse)

## 1. Algorithm & Implementation Scope

A. AES Modes (Runtime Selectable)
The tool must support the following modes:
## • ECB
## • CBC
## • OFB
## • CFB
## • CTR

## • XTS
## • CCM (AEAD)
## • GCM (AEAD)
Mode selection must occur via CLI flag:
--mode ecb|cbc|ofb|cfb|ctr|xts|ccm|gcm

B. AEAD Handling
When using AEAD modes (CCM, GCM):
- --aead flag must enable authenticated behavior
## • Support:
o --aad FILE
o --aad-text STRING
- Must verify authentication tag during decryption
- If tag verification fails → fail closed

## C. Misuse Prevention Requirements
Students must implement explicit misuse checks:
ECB Restrictions
- Print WARNING when ECB is selected
- Block files larger than 16 KiB by default
- Allow override only with:
## • --allow-ecb

IV / Nonce Handling
For modes requiring IV/nonce:
- Enforce correct length per mode
- If IV/nonce is omitted:

o Securely generate using Crypto++ AutoSeededRandomPool
o Persist IV to output header or sidecar JSON
- Reject invalid IV length

## Nonce Reuse Protection
For CTR, CCM, GCM:
- If output header indicates same key + nonce previously used → reject operation
- Must document detection logic

- CLI & I/O Requirements
## Encryption
aestool encrypt --mode gcm --key key.bin --in msg.txt --out ct.bin
## Decryption
aestool decrypt --mode gcm --key key.bin --in ct.bin --out msg.txt

## Key Handling
## Support:
--key-hex HEXSTRING
--key KEYFILE
Key file may be:
- Raw binary
- Hex-encoded with header

IV / Nonce Handling
--iv IVFILE
--nonce NONCEFILE
If omitted (except ECB/XTS):

- Must auto-generate securely
- Must persist to header or sidecar file

## Input & Encoding
- Input from file or --text
## • Output:
o Raw ciphertext written to file
o Hex or Base64 displayed to screen
- UTF-8 safe

Optional Sidecar JSON Header
## Example:
## {
"alg": "AES-256-GCM",
## "iv": "...hex...",
## "aad": "...hex...",
## "tag": "...hex..."
## }
Header must include:
## • Algorithm
## • Mode
- IV/nonce
- AAD (if any)
- Authentication tag (AEAD modes)

## 3. Correctness & Validation


A. Known Answer Tests (KATs)
Students must validate against:
- NIST SP 800-38A vectors:
o CBC
o CFB
o OFB
o CTR
- NIST GCM vectors
- NIST CCM vectors

B. KAT Runner
## Implement:
--kat vectors.json
## Must:
- Parse JSON vector file
- Run test cases
- Output PASS/FAIL per case
- Provide summary

## C. Negative Tests
Students must demonstrate:
- Wrong key → incorrect plaintext
- Wrong IV → incorrect plaintext
- Tampered ciphertext (non-AEAD) → corrupted output
- Tampered ciphertext (AEAD) → authentication failure
- Invalid tag → decryption refusal
- Invalid IV length → rejection

All malformed inputs must fail closed.

## 4. Performance Evaluation
Students must benchmark:
Payload sizes:
## • 1 KB
## • 4 KB
## • 16 KB
## • 256 KB
## • 1 MB
## • 8 MB
## Metrics:
- Throughput (MB/s)
- Latency per operation

## Required Comparative Study
## Compare:
- Windows vs Linux
- Stream vs block modes
- AEAD vs non-AEAD
- Tag overhead (GCM/CCM)
## Include:
## • Tables
## • Plots
- Analysis of OS scheduling and system call overhead

- Security Engineering Discussion (Mandatory Report Section)

Students must analyze:
Mode-Level Security
- Why ECB is insecure
- CBC padding oracle risks
- CTR nonce reuse catastrophe
- AEAD guarantees vs non-AEAD modes
- Why GCM requires unique nonces
- XTS limitations (no integrity)

Implementation-Level Security
- Proper randomness generation
- Safe IV storage
- Authentication tag verification
- Failure handling (fail closed)
- Key storage risks

Cross-Platform Considerations
- RNG differences between OSes
- File system behavior
- Performance variation causes

## 6. Optional Extension (+5 Bonus)
Students may:
- Export encryption core as:
o .dll (Windows)
o .so (Linux)
o .a / .lib

- Build minimal GUI in:
o Python
o C#
- GUI must call compiled library

Rubric (100 pts)
## Component Points
Correctness & KATs 25
Security hygiene 15
UX & I/O design 10
Performance methodology 20
Cross-platform build 10
Report quality 20
Bonus: Library export + GUI +5

## Expected Learning Impact
After completing this lab, students should understand:
- Practical use of symmetric encryption libraries
- Differences between block, stream, and AEAD modes
- Proper IV/nonce lifecycle management
- Real-world cryptographic misuse risks
- Performance trade-offs across OS platforms
- Importance of authentication in modern encryption