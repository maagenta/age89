# age89

Single-file C89 implementation of the [age v1](https://age-encryption.org/v1) encryption format, fully compatible with the official `age` tool.

## What it does

age89 encrypts and decrypts files using the age v1 format. Files encrypted with age89 can be decrypted with the official `age` tool, and vice versa. It supports two encryption modes:

- **X25519** — public key encryption. Encrypt to a recipient's public key; only the holder of the matching private key can decrypt.
- **scrypt** — passphrase encryption. Encrypt with a password; anyone who knows the password can decrypt.

## Why it exists

### Achieving Long-Term Data Reliability

To ensure encrypted data remains accessible in the long term, two requirements must be met:

- Self-describing Metadata: The encrypted file must store all metadata required for decryption without ambiguity regarding the algorithms, parameters, or formats used. Without this, decrypting a file years later depends on remembering exact command-line flags, tool versions, and formatting details that may no longer be documented or accessible.

- Tool Portability and Longevity: The decryption tool itself must remain available in the future. Standard implementations often depend on specific runtimes, operating system APIs, and external libraries. If any of these disappear or become incompatible with future hardware, decryption becomes impossible. One solution is to use a tool that adheres strictly to the C89 standard and avoids external library APIs or kernel extensions, making it much more likely to be recompiled from source on any machine 20 years from now.

### The Problem with Modern Dependencies

The age v1 standard successfully solves the format problem. Its header is self-describing, explicitly storing the encryption method, ephemeral public key or salt, work factor, and header MAC.

However, the standard age tool depends on Go, modern operating system APIs, and various external libraries. If these environments change or vanish, decryption becomes impossible even if the file format is perfectly specified.

###The Age89 Solution

Age89 is an attempt to solve this problem. Its mission is to be a tool that can be compiled by any C89-compliant compiler. It implements everything—X25519, ChaCha20-Poly1305, HKDF-SHA256, scrypt, Bech32, and Base64—from scratch in pure C89 with zero dependencies. There is no reliance on OpenSSL, libsodium, OS APIs, or special kernel features.

The philosophy of age89 is simple: if you encrypt a file today and want to decrypt it in 20 years, the decryptor must be as compatible as possible. By using a single C89 source file, the code can be compiled on almost any architecture without needing a specific operating system or external library.

## Goals

- **One file.** Drop `age89.c` into any project and compile.
- **C89 compatibility.** Works with the oldest compilers still in use.
- **Full interoperability.** Encrypted files are indistinguishable from those produced by the official `age` tool.
- **No dependencies.** No external libraries. No build system.
- **Auditable.** Small enough (~2000 lines) to read and verify by hand.

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
gcc -o age89 age89.c
```

That is the only command needed. It should work with any C89-compatible compiler.

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

## Testing

Compiled and tested on:

- Debian 3 (woody) / i386 / gcc 2.95.4
- OSX Panther 10.3 / Powerpc / gcc 3.3
- Android 13 / Aarch64 / clang 21.1.8
- Windows 98 / i386 / Visual C++ 6.0


Both encryption and decryption worked perfectly, including interoperability with the official `age` tool.

## Limitations

### Security Trade-offs

To maintain compatibility with older C89 systems, several security sacrifices were made:

- **Weak Randomness:** Key generation relies on a basic system timer. If an attacker knows approximately when a file was encrypted, they can more easily "brute-force" the key.
- **32-bit Arithmetic:** High-level math is emulated using simpler 32-bit integers. This introduces risks of precision errors or overflows not found in modern 64-bit systems.
- **Memory Exposure:** Encryption keys remain visible in the computer's RAM during use. On a compromised system, an attacker could extract these keys from a memory dump.
- **Secret key visible in process list:** Since the private key is passed as a command-line argument with -i, it is visible in the process list (ps,Task Manager) to any other user or process on the same machine while the program is running.
- **Passphrase visible when typed:** Since the passphrase is read using fgets on a plain stdin, there is no terminal echo suppression. The passphrase is visible on screen as the user types it, which means anyone looking at the screen or a terminal recording can see it in plain text.

_**Mitigation:** Only decrypt files on offline, air-gapped, or isolated machines._

### Functional Constraints

- **Single Recipient:** Unlike the standard age format, this version supports only one recipient per file.
- **Manual Key Input:** The -i flag requires the raw key string; it cannot read from a key file path. No file reading logic was implemented for that flag, to keep the code simpler.
- **No Armor/SSH/Plugins:** There is no support for PEM (text-based) output, SSH keys, or external plugins.
- **Stdin Conflict:** Since the passphrase is by calling fgets on stdin. If you also try to pipe the plaintext through stdin at the same time, both the passphrase prompt and the plaintext data are competing for the same input stream. The program will read part of the piped data thinking it is the passphrase, and then the rest of the data will be corrupt or missing entirely.       


## License

Licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.txt).  
