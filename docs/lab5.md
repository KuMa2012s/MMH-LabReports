# Lab 5 — Classical Digital Signatures (ECDSA, RSA-PSS)
## Learning Outcomes
By the end of this lab, students will be able to:
- Generate public/private key pairs for ECDSA and RSA-PSS
- Produce and verify detached digital signatures
- Select secure parameters and hash functions
- Detect implementation failures and signature misuse
- Benchmark signing and verification performance
- Compare elliptic-curve vs RSA-based signature systems
- Libraries: Cryptopp + OpenSSL
## 1. Algorithms & Parameters
A. ECDSA (Elliptic Curve Digital Signature Algorithm)
Based on NIST prime curves.
## Security Level Curve Approx. Classical Strength
Level 1 secp256r1 (P-256) ~128-bit
Level 3 secp384r1 (P-384) ~192-bit
## Required
- Implement ECDSA-P256
- Add ECDSA-P384 (+5 pts)
Required Discussion (Report)
- Deterministic nonces (RFC 6979) vs random nonces
- Catastrophic nonce reuse vulnerability
- Signature size vs RSA-PSS
- Verification cost vs signing cost
Students must use deterministic ECDSA (RFC 6979) unless justified otherwise.
B. RSA-PSS (Probabilistic Signature Scheme)

## Parameter Required Setting
Modulus size 3072 bits
Hash function SHA-256
Salt length hashLen (32 bytes)
## Required
- Implement RSA-PSS-3072 with SHA-256
- Use randomized salt per signature
## Required Discussion
- Why RSA-PSS is preferred over PKCS#1 v1.5
- Role of salt in probabilistic signatures
- Signature size vs ECDSA
- Public exponent choice (e.g., 65537)
- CLI & Formats
CLI structure mirrors Lab 6 for consistency.
## Key Generation
sigtool keygen --algo ecdsa-p256 --pub pub.pem --priv priv.pem
sigtool keygen --algo rsa-pss-3072 --pub pub.pem --priv priv.pem
## Signing
sigtool sign --algo ecdsa-p256 --in msg.bin --out sig.bin --hash sha256
## Verification
sigtool verify --algo ecdsa-p256 --in msg.bin --sig sig.bin --pub pub.pem
## Supported Formats
- Keys: PEM / DER
- Signatures: raw / DER / base64 (--encode)
- Hash: SHA-256 required (SHA-384 optional for P-384)
Students must validate:

- Malformed keys
- Incorrect algorithm identifiers
- Unsupported encodings
- Hash mismatch errors
## 3. Correctness & Negative Tests
Students must demonstrate:
- Modified message → verification fails
- Modified signature → fails
- Modified public key → fails
- Wrong algorithm identifier → fails
- Wrong hash function → fails
## Include:
- Automated unit tests
- Batch verification (verify N signatures)
- Clear error codes and UX messages
## Required Discussion
- Why signature verification must be constant-time
- How improper error handling may leak information
## 4. Performance Evaluation
Students must benchmark:
## ECDSA
- Key generation latency
- Sign latency
- Verify latency
## • Throughput (ops/sec)
## RSA-PSS
- Key generation latency

- Sign latency
- Verify latency
## • Throughput (ops/sec)
## Message Sizes
- 1 KiB
- 16 KiB
- 1 MiB
- 8 MiB
## Required Analysis
- Hash cost dominance for large messages
- ECDSA faster verification vs RSA-PSS characteristics
- Signature size comparison
- Memory usage considerations
Students must compare results against Lab 6 (PQC) in discussion section.
Encourage graphical plots (latency vs message size).
## 5. Advanced Topics (+15 Bonus)
Students may implement:
A. Formula-Level Implementation
From primitives:
- Elliptic curve point arithmetic
- Modular inversion
- RSA modular exponentiation
- PSS padding generation
Explain constant-time considerations and potential side-channel risks.
## B. Security Engineering Considerations
## Explain:
- Timing attack surface

- Fault injection risks
- Side-channel risks in modular exponentiation
- Deterministic nonce protection
Partial validation:
- Basic timing variance measurement
- Discussion of constant-time libraries
(No exploit demonstration required.)
Rubric (100 pts + Bonus)
## Component Points
Correct ECDSA sign/verify 20
Correct RSA-PSS sign/verify 20
Robust key handling & formats 15
Negative tests & UX 10
Performance study & analysis 20
Cross-platform build & documentation 5
Report quality 10
Bonus (advanced implementation) +15

## Expected Learning Impact
After completing this lab, students should understand:
- Differences between elliptic-curve and RSA signatures
- Importance of deterministic nonces in ECDSA
- Why RSA-PSS improves security over PKCS#1 v1.5
- Practical trade-offs in signature size and speed
- Engineering challenges in secure cryptographic implementation