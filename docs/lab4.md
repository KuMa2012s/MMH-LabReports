# Lab 4 — Hashing, PKI, and Practical Attacks
## ⚠ Ethics Notice
This lab is for defensive education only.
Use offline test files you own, in an isolated environment.
Do NOT target real systems or live services.
## Learning Outcomes
By the end of this lab, students will be able to:
- Implement and benchmark modern hash functions
- Parse and validate X.509 certificates
- Demonstrate MD5 collision weaknesses safely
- Demonstrate length-extension attacks on naïve MAC constructions
- Explain why legacy hash functions are insecure
- Propose cryptographic mitigations (HMAC, SHA-2/3, policy controls)
## 1. Hashing Suite
Students must implement a CLI hashing tool supporting:
A. SHA-2 Family
## Algorithm Output Size
SHA-224 224 bits
SHA-256 256 bits
SHA-384 384 bits
SHA-512 512 bits

B. SHA-3 Family
## Algorithm Output Size
SHA3-224 224 bits
SHA3-256 256 bits

## Algorithm Output Size
SHA3-384 384 bits
SHA3-512 512 bits

C. SHAKE (Extendable-Output Functions)
## Algorithm Output
SHAKE128 Variable
SHAKE256 Variable
Must support:
hashtool --algo shake256 --outlen 64 --in file.bin
## Required Implementation Features
- Known Answer Tests (KATs)
- Streamed I/O (multi-GB files supported)
## • Output:
o hex (console)
o raw binary (file)
## Required Discussion
- Merkle–Damgård vs sponge construction
- Collision resistance vs preimage resistance
- Why SHA-3 differs structurally from SHA-2
- XOF use cases (e.g., domain separation)
- CLI & Formats
## Basic Hashing
hashtool --algo sha256 --in file.bin
## Streaming Mode
hashtool --algo sha512 --in large.iso --stream

SHAKE Output Length
hashtool --algo shake128 --outlen 128 --in file.bin
Students must:
- Handle malformed inputs
- Validate algorithm identifiers
- Fail closed on unsupported parameters
- PKI & Certificate Analysis
Students must parse an X.509 certificate using OpenSSL or Crypto++.
## Required Extraction
From the certificate:
## • Subject
## • Issuer
- Subject Public Key Info (algorithm & parameters)
- Signature algorithm
- Validity period
- Key usage
- Subject Alternative Names (SANs)
## Signature Verification
Students must:
- Verify certificate signature using issuer public key (if provided)
- If issuer key unavailable:
o Verify TBS structure integrity
o Validate algorithm consistency
o Fail closed
TLS Deployment Task
Configure HTTPS on:
- Apache or Nginx

- TLS 1.2 or TLS 1.3
- Using a trusted root (e.g., ZeroSSL)
- With ECDSA certificate (preferred)
## Deliver:
- Screenshot or logs
- Config snippet
- Short explanation of trust chain
## Required Discussion
- Structure of X.509 (TBS vs signature)
- Chain of trust
- Why SHA-1 and MD5 are banned
- Certificate transparency & CA/B requirements
- Controlled MD5 Collision Demonstration
Students must demonstrate an MD5 collision using hashclash.
Choose ONE:
## Option A
Two benign PNG files with identical MD5 digest
## Option B
Two short C++ programs with identical MD5 digest
## Deliver:
- Both input files
- Matching MD5 digest
- One-page explanation:
o Why MD5 is broken
o Collision vs preimage difference
o Historical incidents
No real-world targets allowed.

- Length-Extension Attack on Naïve MAC
Target construction:
## [
MAC = H(k || m)
## ]
Using hashpump (or own implementation, bonus +5):
## Demonstrate:
## Given:
- H(k || m)
- Length of k
## Compute:
- H(k || m || pad || m')
Without knowing k.
## Deliverables
- Original message
- Forged extended message
- Matching forged MAC
- Diagram of padding
- Mitigation explanation
## Required Discussion
- Why Merkle–Damgård enables length extension
- Why HMAC prevents it
- Prefix-free constructions
## 6. Performance Evaluation
Students must benchmark:
## • SHA-256
## • SHA-512
## • SHA3-256

## • SHA3-512
## File Sizes
- 1 MiB
- 100 MiB
- 1 GiB (if feasible)
## Required Analysis
- Throughput (MB/s)
- Streaming vs memory-mapped I/O
- CPU utilization
- SHA-2 vs SHA-3 performance differences
- Cache and memory effects
Include performance plots.
Test on both OSes (Windows + Linux if possible).
## 7. Advanced Topics (+15 Bonus)
A. Custom Length-Extension Implementation (+5)
Implement length-extension manually for SHA-256:
- Reconstruct internal state
- Apply padding
- Continue compression
Explain internal state manipulation.
B. Chosen-Prefix Certificate Demo (+10)
In sandbox only:
- Generate MD5/RSA self-signed cert
- Use chosen-prefix collision
- Craft second certificate with same MD5 signature
## Deliver:
- Explanation of why MD5-signed certificates are catastrophic

- Policy mitigations:
o Ban MD5/SHA-1
o Enforce CA/B Baseline Requirements
o Algorithm agility
No operational exploit required.
Rubric (100 pts + Bonus)
## Component Points
Hash suite correctness & KATs 25
Streaming & large-file performance 10
X.509 parsing & signature verification 25
MD5 collision demo & explanation 20
Length-extension demo & mitigation analysis 20
Bonus: custom length-extension +5
Bonus: chosen-prefix certificate demo +10

## Expected Learning Impact
After completing this lab, students should understand:
- Structural differences between SHA-2 and SHA-3
- Why MD5 and SHA-1 are cryptographically broken
- How naive MAC constructions fail
- Why HMAC is secure
- How certificate validation works internally
- How cryptographic failures propagate to system-level vulnerabilities