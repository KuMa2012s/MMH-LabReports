# Lab 3 — RSA-OAEP & Hybrid Encryption (Crypto++ /
OpenSSL)
## Learning Outcomes
By the end of this lab, students will be able to:
- Generate and securely store RSA key pairs
- Implement RSA-OAEP encryption/decryption (SHA-256)
- Handle plaintext size limits and implement hybrid encryption
- Detect and properly handle cryptographic failures
- Benchmark RSA performance across key sizes
- Understand why hybrid encryption is required in practice
## 1.  Algorithms & Parameters
A. RSA-OAEP (Asymmetric Encryption)
## Parameter Required Setting
Modulus size ≥ 3072 bits
Hash function SHA-256
Padding OAEP
## MGF MGF1 (SHA-256)
## Required
- Implement RSA-3072 with OAEP(SHA-256)
- Add RSA-4096 for performance comparison
- Support optional OAEP label
Required Discussion (Report)
- Why OAEP is secure (IND-CCA2)
- Why PKCS#1 v1.5 encryption is insecure
- Plaintext size limit:

## [
mLen \le k - 2hLen - 2
## ]
- Why RSA cannot encrypt large files directly

B. Hybrid Encryption (Envelope Encryption)
For plaintext exceeding RSA-OAEP limit:
- Generate random AES key (256-bit)
- Encrypt data using AES-GCM
- Encrypt AES key using RSA-OAEP
- Output structured envelope
This mirrors real-world TLS and PGP behavior.
## 2. CLI & Formats
## Key Generation
rsatool keygen --bits 3072 --pub pub.pem --priv priv.pem
Must also save:
- PEM format
- DER format
- Metadata JSON:
## {
## "creation_time": "...",
## "modulus_bits": 3072,
"hash": "SHA-256"
## }
## Encryption
rsatool encrypt --in msg.bin --pub pub.pem --out ct.bin --label optional
If message exceeds RSA limit:
- Automatically switch to hybrid mode

- Output envelope
## Decryption
rsatool decrypt --in ct.bin --priv priv.pem --out msg.bin
## Supported Formats
- Ciphertext: raw / hex / base64
- Envelope header: JSON
- Keys: PEM / DER
Students must validate:
- Malformed ciphertext
- Incorrect label
- Unsupported key sizes
- Incorrect encoding
## 3. Hybrid Envelope Format
Example JSON header:
## {
"mode": "RSA-OAEP-AES-GCM",
## "rsa_modulus": 3072,
"hash": "SHA-256",
## "wrapped_key": "<base64>",
## "iv": "<base64>",
## "tag": "<base64>"
## }
## Payload:
- AES-GCM encrypted data
## Required Security Properties
## • AES-256-GCM
- 96-bit IV
- Authenticated decryption
- Reject tampered ciphertext
- Constant-time tag verification (library-backed acceptable)
## 4. Correctness & Negative Tests
Students must demonstrate:
- Altered RSA ciphertext → decryption fails
- Altered AES-GCM ciphertext → tag failure
- Wrong private key → failure
- Wrong OAEP label → failure
- Tampered envelope header → failure
## Include:
- Automated unit tests
- Clear, non-leaky error messages
- Fail closed on parsing errors
## 5. Performance Evaluation
Students must benchmark:
## RSA
- Key generation time
- Encryption time
- Decryption time
- 3072 vs 4096 comparison
## Hybrid Mode
- AES-GCM encryption throughput
- Hybrid encryption time for:
o 1 KiB
o 1 MiB
o 100 MiB

## Required Analysis
- RSA decryption vs encryption cost
- RSA key size vs performance tradeoff
- Hybrid efficiency advantage
- Why symmetric encryption dominates throughput
- Memory and CPU considerations
Include latency and throughput plots.
## 6. Advanced Topics (+15 Bonus)
A. Manual OAEP Padding (+5)
Implement OAEP encoding/decoding manually:
## • MGF1
- XOR masking
- Padding validation
Explain why decoding must be constant-time.

B. AES + RSA Hybrid Security Analysis (+10)
Provide deeper hybrid study:
- Compare envelope vs direct RSA
- Explain how TLS handshake uses hybrid design
- Analyze forward secrecy limitations of pure RSA
- Propose upgrade path to ECDHE or ML-KEM (preview of Lab 6)
Optional extension:
- Add AES-CTR + HMAC comparison vs AES-GCM
- Measure authentication failure timing variance

Rubric (100 pts + Bonus)

## Component Points
Correct RSA-OAEP (SHA-256) 20
Correct hybrid envelope (AES-GCM + RSA) 20
Key management & formats 15
Negative tests & secure error handling 15
Performance study & analysis 15
Cross-platform build & documentation 5
Report quality 10
Bonus: manual OAEP +5
Bonus: hybrid security analysis +10

## Expected Learning Impact
After completing this lab, students should understand:
- Why RSA must use OAEP
- Why hybrid encryption is mandatory for large data
- Why symmetric crypto dominates performance
- Real-world envelope encryption design
- RSA limitations compared to modern KEMs (preview of ML-KEM in Lab 6)