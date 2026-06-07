# Chosen-Prefix Certificate Demo Notes

This optional bonus topic must be performed only in an isolated sandbox. The
operational collision generation step requires external tooling such as
hashclash and is intentionally not embedded into `hashtool`.

Report discussion points:

- Generate an MD5/RSA self-signed certificate in the sandbox.
- Use chosen-prefix collision tooling to craft two certificate-like TBS inputs
  with the same MD5 digest but different subject/public-key semantics.
- Explain that an MD5 signature over one TBS structure can be reused for the
  colliding TBS structure.
- Explain why this is catastrophic for PKI: the CA signature authenticates a
  digest, and MD5 lets an attacker create a second object with the same digest.
- Mitigations:
  - Ban MD5 and SHA-1 for certificate signatures.
  - Enforce CA/B Baseline Requirements.
  - Use SHA-256 or stronger signature algorithms.
  - Maintain algorithm agility and certificate transparency monitoring.

No real-world CA, production certificate, or live service should be targeted.
