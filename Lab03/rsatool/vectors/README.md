# Vectors

Lab 3 uses library-backed RSA-OAEP and randomized encryption, so ciphertext is intentionally non-deterministic. Correctness is validated by `rsatool --selftest`, which generates fresh keys and checks:

- RSA-OAEP SHA-256 roundtrip.
- Hybrid RSA-OAEP + AES-256-GCM roundtrip.
- Wrong OAEP label rejection.
- Wrong private key rejection.
- Altered RSA ciphertext rejection.
- Altered AES-GCM ciphertext rejection.
- Tampered envelope header rejection.

The bonus manual OAEP implementation is validated by:

```text
rsatool oaep-selftest
```

Deterministic known-answer values are stored in:

```text
vectors/rsatool_kat.json
```

Run them with:

```text
rsatool --kat vectors/rsatool_kat.json
```
