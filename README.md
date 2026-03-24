# age89

Single-file C89 implementation of the [age v1](https://age-encryption.org/v1) encryption format, fully compatible with the official `age` tool.

## What it does

age89 encrypts and decrypts files using the age v1 format. Files encrypted with age89 can be decrypted with the official `age` tool, and vice versa. It supports two encryption modes:

- **X25519** — public key encryption. Encrypt to a recipient's public key; only the holder of the matching private key can decrypt.
- **scrypt** — passphrase encryption. Encrypt with a password; anyone who knows the password can decrypt.

## Why it exists

The official `age` tool is written in Go. Go requires a modern toolchain and a modern operating system. This makes `age` unavailable on legacy systems — old Linux distributions, embedded systems, or any machine where installing a Go runtime is not an option.

age89 was created to bring the age format to those environments. It compiles cleanly with gcc 2.95.4 (released in 2001) and runs on Debian 3 (woody, 2002). The only requirement is a C89 compiler and a POSIX system with `/dev/urandom`.

There is no dependency on OpenSSL, libsodium, or any external library. Everything — SHA-256, HMAC, HKDF, ChaCha20-Poly1305, Poly1305, X25519, scrypt, Bech32, and Base64 — is implemented in the single source file.

## Goals

- **One file.** Drop `age89.c` into any project and compile.
- **C89 compatibility.** Works with the oldest compilers still in use.
- **Full interoperability.** Encrypted files are indistinguishable from those produced by the official `age` tool.
- **No dependencies.** No external libraries. No build system.
- **Auditable.** Small enough (~1200 lines) to read and verify by hand.

## Algorithms

| Purpose | Algorithm |
|---|---|
| Key exchange | X25519 (Curve25519) |
| Symmetric AEAD | ChaCha20-Poly1305 (RFC 8439) |
| Key derivation | HKDF-SHA256 |
| Passphrase KDF | scrypt (N=2^14, r=8, p=1) |
| Key encoding | Bech32 |
| Body encoding | Base64 (no padding) |
| Header MAC | HMAC-SHA256 |

## Build

```sh
gcc -O2 -o age89 age89.c
```

That is the only command needed. Works with gcc 2.95.4 or any later C89-compatible compiler.

## Usage

### Generate a key pair

```sh
./age89 -k
# Public key (share this):
# age1...
#
# Private key (keep secret):
# AGE-SECRET-KEY-1...
```

### Encrypt with a public key

```sh
./age89 -e -r age1PUBKEY [-o OUTPUT] [INPUT]

# Examples:
./age89 -e -r age1xyz... secrets.txt -o secrets.txt.age
echo "hello" | ./age89 -e -r age1xyz... -o hello.age
```

### Decrypt with a private key

The private key is passed directly as a string, not as a file path:

```sh
./age89 -d -i AGE-SECRET-KEY-1... [-o OUTPUT] [INPUT]

# Examples:
./age89 -d -i AGE-SECRET-KEY-1xyz... secrets.txt.age -o secrets.txt
./age89 -d -i AGE-SECRET-KEY-1xyz... secrets.txt.age
```

### Encrypt with a passphrase

```sh
./age89 -e -p [-o OUTPUT] [INPUT]

# Example:
./age89 -e -p secrets.txt -o secrets.txt.age
# Passphrase:
# Confirm:
```

### Decrypt with a passphrase

```sh
./age89 -d -p [-o OUTPUT] [INPUT]

# Example:
./age89 -d -p secrets.txt.age -o secrets.txt
# Passphrase:
```

### Interoperability with the official age tool

```sh
# age encrypts, age89 decrypts
age -r age1PUBKEY secrets.txt > secrets.txt.age
./age89 -d -i AGE-SECRET-KEY-1... secrets.txt.age

# age89 encrypts, age decrypts
./age89 -e -r age1PUBKEY secrets.txt -o secrets.txt.age
age -d -i key.txt secrets.txt.age
```

## Tested

Compiled and tested on Debian 3 (woody) with gcc 2.95.4. Both encryption and decryption worked perfectly, including interoperability with the official `age` tool.

## Limitations

- Accepts only one recipient per file (the age format supports multiple).
- The `-i` flag takes the raw key string, not a file path.
- No armor (PEM) output.
- No SSH key support.
- No plugin support.
- Passphrase is read from stdin; if the plaintext is also read from stdin, use a file for the plaintext.

## TODO

- [ ] Accept a key file path for `-i` (in addition to raw key strings)
- [ ] Multiple recipients per file
- [ ] Armored (PEM) output via `-a`
- [ ] Read passphrase from `/dev/tty` instead of stdin to allow piping plaintext
- [ ] Windows support (`CryptGenRandom` instead of `/dev/urandom`)
- [ ] Test suite with known vectors

## License

Licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.txt).  
