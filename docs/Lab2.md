Lab 2 — AES-128 Implementation in Pure C++ (CTR Mode,
FIPS-197 Compliant)

## ⚠ Constraint
- No external cryptographic libraries allowed
- C++ STL is permitted
- All cryptographic primitives must be implemented manually
- No use of OpenSSL, Crypto++, libsodium, etc.
- AES-NI may only be used in bonus section

## Learning Outcomes
After completing this lab, students will be able to:
- Implement AES-128 round transformations according to FIPS-197
- Implement CTR (Counter) mode correctly per NIST SP 800-38A
- Validate correctness using official NIST Known Answer Tests
- Reason about nonce misuse and stream-cipher risks
- Benchmark software AES performance
- Analyze side-channel leakage in table-based implementations
- Understand why CTR requires authentication

## 1. Algorithm & Implementation Scope

A. AES Block Cipher (FIPS-197, May 9, 2023 Update)
Required: AES-128
Students must implement:
- AddRoundKey

- SubBytes (S-box lookup)
- ShiftRows
- MixColumns
- KeyExpansion
## Parameters:
- Block size: 128 bits
- Key size: 128 bits
- Number of rounds: 10
Implementation must strictly follow FIPS-197 specification.

## Bonus Extension (+10)
## • AES-192
## • AES-256
- Full key schedule implementation required
- KAT validation mandatory

B. CTR Mode (NIST SP 800-38A Compliant)
CTR turns AES into a stream cipher.
Correct CTR Definition
For block index ( i ):
## [
S_i = AES(K, \text{Nonce} | \text{Counter}_i)
## ]
## [
## C_i = P_i \oplus S_i
## ]
## [
## P_i = C_i \oplus S_i
## ]

## Requirements
- 128-bit IV (Nonce + Counter)
- Counter must increment correctly
- Must clearly document:
o Counter endianness
o Counter overflow behavior
- Must support arbitrary-length plaintext
- Partial final blocks must be handled correctly
- No padding required

## Critical Security Rule
IV (nonce) must be unique per key.
Reuse of IV under the same key must be discussed as catastrophic.

-  CLI & Input/Output Requirements

## Encryption
aestool encrypt --mode ctr --key key.bin --iv iv.bin --in msg.bin --out ct.bin
## Decryption
aestool decrypt --mode ctr --key key.bin --iv iv.bin --in ct.bin --out msg.bin

## Supported Formats
- Input/output: raw binary
- Optional: hex encoding for debugging
- Key: exactly 16 bytes
- IV: exactly 16 bytes


Input Validation (Fail Closed)
Students must validate:
- Invalid key length
- Invalid IV length
- Counter overflow detection (if applicable)
- File I/O errors
CTR does NOT require:
## • Padding
- Block alignment
- Padding validation
Any malformed input must terminate execution securely.

## 3. Correctness & Validation

A. Known Answer Tests (KATs)
Students must verify against:
- Official FIPS-197 AES test vectors
- NIST SP 800-38A CTR mode test vectors

B. Cross-Validation
Implementation must produce identical ciphertext to:
- Crypto++ AES-128-CTR
## OR
- OpenSSL AES-128-CTR
(using identical key and IV)

## C. Negative Tests

Students must demonstrate:
- Wrong key → incorrect plaintext
- Wrong IV → incorrect plaintext
- Tampered ciphertext → corrupted plaintext
Students must explain why CTR cannot detect tampering.

## 4. Performance Evaluation
Students must benchmark:
- AES-128 encryption throughput
- AES-128 decryption throughput
File sizes:
- 1 MiB
- 100 MiB
- 1 GiB (if feasible)

## Required Analysis
Students must analyze:
- Table-based S-box vs computed S-box
- Memory footprint
- Cache behavior
- Branch prediction impact
- Comparison with Crypto++ performance
## Include:
- Throughput table (MB/s)
- Throughput plots

## Security Engineering Discussion (Mandatory Report Section)

Students must analyze:
AES Core Risks
- Timing leakage from table-based S-box
- Cache-based attacks (T-table leakage)
- Importance of constant-time coding
CTR Mode Risks
- Keystream reuse attack
- Two-time pad vulnerability
- Why IV reuse is catastrophic
- Why CTR provides confidentiality only
- Why CTR requires MAC for authenticity
- Why CTR is not AEAD
## Hardware Acceleration
- Why AES-NI mitigates many software leakage risks
- Performance vs security trade-offs
## 6 Advanced Topics (+20 Bonus)
## A. AES-192 / AES-256 (+10)
- Full key expansion
- KAT validation required
B. AES-XTS Implementation (+5)
Implement AES-XTS:
- Two-key construction
- Tweak multiplication in GF(2¹²⁸)
- Explain disk encryption use case
C. AES-NI or Bit-Sliced Optimization (+5)
- Runtime CPU feature detection
- Compare performance vs pure software

- Explain constant-time improvements
Rubric (100 pts + Bonus)
## Component Points
FIPS-197 correct AES-128 core 30
CTR mode correctness 15
KATs & cross-validation 15
Engineering quality & documentation 10
Performance study & analysis 10
Security discussion 20
Bonus: AES-192/256 +10
Bonus: XTS +5
Bonus: AES-NI/bit-sliced +5

## Expected Learning Impact
After completing this lab, students should understand:
- Internal structure of AES rounds
- How stream cipher modes operate
- Why nonce reuse destroys confidentiality
- Why CTR must be combined with MAC
- Why constant-time implementations matter
- How hardware acceleration changes security posture
- for students
