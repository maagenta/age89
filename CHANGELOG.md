# Changelog

All notable changes to age89 will be documented in this file.

## [1.0.0] - 2026-03-24

### Added

- `age89.c`: single-file C89 implementation of the age v1 encryption format
- X25519 (Curve25519) key exchange
- ChaCha20-Poly1305 AEAD encryption (RFC 8439)
- HKDF-SHA256 key derivation
- scrypt passphrase KDF (N=2^14, r=8, p=1)
- HMAC-SHA256 header MAC
- Bech32 key encoding/decoding
- Base64 (no-padding) body encoding
- SHA-256 and Poly1305 primitives implemented from scratch
- Public key encryption/decryption via X25519 (`-e -r` / `-d -i`)
- Passphrase encryption/decryption via scrypt (`-e -p` / `-d -p`)
- Key pair generation (`-k`)
- Stdin/stdout and file I/O support
- Full interoperability with the official `age` tool
- No external dependencies — no OpenSSL, no libsodium, nothing
- Compiles with gcc 2.95.4 (2001) and any later C89-compatible compiler
- Tested on Debian 3 (woody, 2002) — compiled and ran perfectly
- Requires only a POSIX system with `/dev/urandom`
