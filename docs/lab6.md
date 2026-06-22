Lab 6— Post-Quantum Signatures & Certificates (ML-
## DSA, ML-KEM)
By the end of this lab, students will:
- Generate PQC key pairs (ML-DSA, ML-KEM)
- Sign and verify detached signatures using ML-DSA
- Perform encapsulation/decapsulation using ML-KEM
- Understand PQC parameter selection and security levels
- Benchmark PQ signature and KEM performance
- Build a simple PQ certificate structure (ML-DSA-signed public keys)
## 1. Algorithms & Parameters
A. ML-DSA (Post-Quantum Signatures)
## Security Level Parameter Set Equivalent Classical
Level 2 ML-DSA-44 ~128-bit
Level 3 ML-DSA-65 ~192-bit
Level 5 ML-DSA-87 ~256-bit
Students must:
- Implement ML-DSA-44 (required)
- Add ML-DSA-65 (+5 pts)
- Discuss signature size vs security trade-offs
Key discussion:
- Large signature size (compared to ECDSA)
- Deterministic signing (no RFC6979 issue like ECDSA)
- Rejection sampling and failure probability
B. ML-KEM (Post-Quantum KEM)

## Security Level Parameter Set Equivalent Classical
Level 2 ML-KEM-512

Level 3 ML-KEM-768

Level 5 ML-KEM-1024

Students must:
- Implement ML-KEM-512
- Perform encapsulation → shared secret
- Perform decapsulation → verify shared secret match
## Discuss:
- IND-CCA security
- Fujisaki–Okamoto transform
- Ciphertext size vs RSA key exchange
- CLI & Formats
## Key Generation
pqtool keygen --algo mldsa-44 --pub pub.pem --priv priv.pem
pqtool keygen --algo mlkem-512 --pub pub.pem --priv priv.pem
## Signing
pqtool sign --algo mldsa-44 --in msg.bin --out sig.bin
## Verification
pqtool verify --algo mldsa-44 --in msg.bin --sig sig.bin --pub pub.pem
KEM Encapsulation
pqtool encaps --algo mlkem-512 --pub pub.pem --ct ct.bin --ss ss.bin
KEM Decapsulation
pqtool decaps --algo mlkem-512 --priv priv.pem --ct ct.bin --ss ss.bin

## Supported Formats

- Keys: PEM / DER
- Signatures: raw / base64
- Ciphertexts: binary
- Optional: JSON structured certificate format
-  Post-Quantum Certificate Mini-Project
Students must implement a minimal certificate structure:
## {
## "subject": "your Subject",
"public_key": "<ML-DSA public key>",
"issuer": "PQ-CA",
"signature": "<ML-DSA signature by CA>"
## }
## Tasks:
- Generate CA key pair (ML-DSA)
- Sign subject public key
- Verify certificate signature
- Detect tampering
## Discuss:
- Why ML-KEM is NOT used for signing
- Hybrid certificates (ECDSA + ML-DSA)
- Migration path to PQ TLS
## 4. Correctness & Negative Tests
Students must demonstrate:
- Modified message → verification fails
- Modified signature → fails
- Modified public key → fails
- Modified ciphertext (KEM) → decapsulation fails

- Wrong private key → failure
## Include:
- Automated unit tests
- Batch verification (verify N signatures)
- Batch decapsulation timing
## 5. Performance Evaluation
## Measure:
## ML-DSA
- Keygen latency
- Sign latency
- Verify latency
## • Throughput (ops/sec)
## ML-KEM
- Keygen latency
- Encapsulation latency
- Decapsulation latency
- Shared secret generation throughput
Test message sizes:
- 1 KiB
- 16 KiB
- 1 MiB
- 8 MiB
## Discuss:
- Hash cost dominance
- Large signature overhead
- Memory usage
- Compare to ECDSA/RSA-PSS (theoretical comparison acceptable)

## 6. Advanced Topics (+15 Bonus)
Students may implement:
A. Formula-Level ML-DSA or ML-KEM (from primitives)
- NTT-based polynomial arithmetic
- Modular reduction
- Rejection sampling
- Constant-time coding considerations
B. Side-Channel Awareness
## Explain:
- Timing attack surface
- Lattice leakage risks
- Importance of constant-time NTT
- Failure handling in decapsulation
Partial validation:
- Basic timing variance measurement
- Input-dependent timing discussion

Rubric (100 pts + Bonus)
## Component Points
Correct ML-DSA sign/verify 25
Correct ML-KEM encaps/decaps 20
Robust key handling & formats 15
Certificate implementation 10
Negative tests & UX 10
Performance study & analysis 15

## Component Points
Cross-platform build & documentation 5
Report quality 10
Bonus (advanced implementation) +15

## Expected Learning Impact
Students will understand:
- Why PQ signatures are large
- How lattice cryptography works at high level
- How ML-KEM replaces RSA key exchange
- Migration strategy toward PQ TLS
- Practical engineering trade-offs
Reporting Template (use & adapt)
- Objective & outcomes — what you built and why.
- Design & security — parameters, mode choices, misuse checks.
- Test methodology — vectors used (cite), negative tests.
- Performance — hardware table (CPU, RAM, OS, compiler flags), protocol, plots (throughput
MB/s; latency ms/op), 95% CIs.
- Discussion — correctness issues found and fixed; cross-OS comparisons; security trade-offs.
- Conclusion — key takeaways & future work.
Appendix — CLI usage examples; build logs; KAT coverage; unit test summary.

Performance Protocol (copy into each lab)
- Hardware/OS table: CPU model, cores/threads, RAM, storage type, OS version,
compiler & flags.
- Warm-up: 1–2 s to stabilize caches and JIT/allocators the run 1000 rounds per block.
- Runs: N ≥ 30 independent timed runs per case.
- Metrics: mean, median, std dev, 95% CI; show plots with error bars.
- Fairness: pin CPU governor (Linux performance; Windows set “High performance”).

- Repeatability: fixed PRNG seed only for synthetic data generation (never for
keys/nonces).

Submission Checklist (attach to each lab ZIP)
- README.md with build & run steps for Windows & Linux
- CMakeLists.txt builds without editing paths or tasks.json
- Binaries for both OSes (or clear instructions to build)
- Source code, headers, tests, KAT files
- Report (.pdf/.docx) with tables/plots and analysis
- Self-grade rubric filled by the team
- (Optional) GUI project using your .dll/.so core

Appendix A — Academic Integrity & Ethics (paste into each report)
- Work is your own; cite libraries, KAT sources, and references.
- Attack demonstrations are limited to your own test artifacts in an offline sandbox.
- No testing against third-party data, networks, or services.
- Keys and secrets included in the repo are test keys only.
- You understand the difference between vulnerability demonstration and malicious
exploitation and commit to the former strictly for learning.

Appendix B —Rubric Table (include & self-grade)
Criterion Points Self-score TA score
Correctness & KATs 35–40

Security hygiene / misuse checks 10–20

Cross-platform build & UX 10

Performance study quality 10–20


Criterion Points Self-score TA score
Report quality & clarity 5–10

Negative tests 10–15

Bonuses (if any) + up to 15

## Total 100 (+bonus)

