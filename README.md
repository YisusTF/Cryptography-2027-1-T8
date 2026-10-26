# Cryptography 2027-1 - Team 8

Secure Digital Document Vault: a Python project that encrypts documents so that they can be stored or sent through places we do not trust (see D1 for the full threat model).

| Deliverable | What it adds |
|---|---|
| D1 | Architecture and threat model |
| D2 | Encrypt a file with a password (AES-256-GCM) |
| **D3** | **Share one encrypted file with several people (hybrid encryption)** |

Requires Python 3.10 or newer and the `pycryptodome` library.

```bash
python -m pip install -r requirements.txt
```

## Project files

| File | Purpose |
|---|---|
| `vault_crypto.py` | D2: password-based encryption (unchanged) |
| `vault_keys.py` | D3: creates and stores RSA key pairs, computes key IDs |
| `vault_hybrid.py` | D3: multi-recipient encryption and decryption, command line tool |
| `tests/test_vault_crypto.py` | D2 tests (12) |
| `tests/test_vault_keys.py` | D3 key management tests |
| `tests/test_vault_hybrid.py` | D3 hybrid encryption tests |
| `docs/HYBRID_DESIGN.md` | D3 design explanation and security decisions |
| `docs/USER_MANUAL.md` | Step-by-step usage guide |
| `docs/PR_DESCRIPTION_D3.md` | Pull request description for D3 |

## D3: Hybrid Encryption

### What it does

In D2, one person protects a file with one password. In D3, a file is encrypted **once** and can be opened by **several chosen people**. Each person uses their own private key, so nobody needs to share a password. Anyone who is not on the recipient list cannot open the file, even if they get a copy of it.

### How it works

Public-key encryption (RSA) is good for small secrets but cannot handle large files. Symmetric encryption (AES) is fast but needs a shared key. Hybrid encryption uses both:

1. The program creates a new random **file key** (256 bits).
2. The document is encrypted once with **AES-256-GCM**, the same method used in D2.
3. The file key is encrypted separately for each recipient with their **public key**, using **RSA-OAEP**.
4. The container stores the encrypted document and one encrypted copy of the file key per recipient.

To open the file, a recipient finds their own entry, decrypts the file key with their **private key**, and then decrypts the document. RSA only ever touches the small file key, never the document.

### How a recipient finds their key

Every public key has a **key ID**: the SHA-256 hash of the public key, written as 64 hexadecimal characters. The same key always gives the same ID, and two different keys cannot realistically share one. Each recipient entry stores this ID, and decryption looks for the entry whose ID matches the user's key. The readable name (for example `alice`) is only a label.

### What is protected

The recipient list, the key IDs, the encrypted file keys and the algorithm names are all included in the authenticated data (AAD) of AES-GCM. If an attacker adds a recipient, removes one, changes a name or a key ID, or reorders the list, the check fails for everyone and no file is produced. Each encrypted file key is also tied to its recipient and to the container, so it cannot be moved to another container.

### Container format (version 2)

```json
{
  "header": { "format": "SDDV", "version": 2, "algorithm": "AES-256-GCM",
              "key_encryption": "RSA-OAEP-SHA256",
              "key_id_algorithm": "SHA-256-SPKI-DER", "created_utc": "..." },
  "recipients": [
    { "id": "alice", "key_id": "...", "encrypted_key": "..." },
    { "id": "bob",   "key_id": "...", "encrypted_key": "..." }
  ],
  "nonce": "...",
  "ciphertext": "...",
  "authentication_tag": "..."
}
```

Binary values are stored in Base64. The container is not secret: its contents are either encrypted or authenticated.

### How to run it

Each person creates a key pair once (you will be asked for a passphrase of at least 12 characters that protects the private key):

```bash
python vault_hybrid.py keygen alice
python vault_hybrid.py keygen bob
```

Alice shares only her **public key** (`vault_keys/alice.public.pem`) and Bob does the same. Each person imports the other's public key and checks the key ID with the owner:

```bash
python vault_hybrid.py import-public bob bob.public.pem
python vault_hybrid.py fingerprint bob
```

Encrypt a file for several recipients, then decrypt it as one of them:

```bash
python vault_hybrid.py encrypt sample_document.txt --to alice --to bob --out shared.sddv
python vault_hybrid.py decrypt shared.sddv --as bob --out recovered_document.txt
python vault_hybrid.py inspect shared.sddv
```

The full guide, including how two separate computers exchange keys, is in `docs/USER_MANUAL.md`.

**Important:** never upload the `vault_keys` folder or any `.private.pem` file to GitHub. They are listed in `.gitignore`.

### Tests

```bash
python -m unittest discover -s tests -v
```

The D3 tests prove the five required cases:

| Required case | Test |
|---|---|
| File shared with 2 users, both can decrypt | `test_01_...` (and a 3-recipient variant) |
| Unauthorized user cannot decrypt | `test_02_...` |
| Tampered recipient list fails | `test_03_...` (label, order, key ID, encrypted key, added entry) |
| Wrong private key fails | `test_04_...` |
| Removing a recipient entry breaks access | `test_05_...` |

Extra tests check modified ciphertext, nonce, tag and header, changed algorithm names, repeated encryption, malformed containers, the recipient limit (16), file handling (no overwriting, no output after errors), key files, and the command line. The 12 D2 tests still pass. GitHub Actions runs all tests on every push and pull request.

### What D3 does not do

- It does not prove **who created** a container. Digital signatures are a later step.
- It does not detect an old valid container being replayed.
- It cannot confirm that a public key really belongs to the person. Users must compare key IDs through a trusted channel.
- It cannot take back access from a person who already received a file.
- It does not protect a computer that is already compromised, or a file after a recipient has decrypted it.

More details are in `docs/HYBRID_DESIGN.md`.

## D2: Secure Symmetric Encryption (still available)

`vault_crypto.py` encrypts a file with a password. A random AES-256 file key and a random 12-byte nonce are generated for every file, and the content is encrypted with **AES-256-GCM**. The password goes through **scrypt** to make a key that protects the file key with AES Key Wrap. The JSON header is authenticated as AAD, so changing it makes decryption fail. Files are never overwritten, and the input limit is **10 MiB**.

```bash
python vault_crypto.py encrypt sample_document.txt --out sample_document.sddv
python vault_crypto.py decrypt sample_document.sddv --out recovered_document.txt
```

D2 containers are version 1 and use `vault_crypto.py`. D3 containers are version 2 and use `vault_hybrid.py`. Each program gives a clear error if it receives the other type.

**Why AES-GCM rather than encryption plus a hash?** AEAD checks the ciphertext and the associated data in one authenticated design. An unkeyed hash can be recomputed by an attacker. Reusing a GCM nonce with the same key breaks its security, so a new random key and nonce are created for every encryption.

## Sources

- [PyCryptodome: RSA](https://www.pycryptodome.org/src/public_key/rsa)
- [PyCryptodome: RSA OAEP](https://www.pycryptodome.org/src/cipher/oaep)
- [PyCryptodome: AES authenticated encryption](https://www.pycryptodome.org/src/cipher/aes)
- [PyCryptodome: AES Key Wrap](https://www.pycryptodome.org/src/cipher/modern#key-wrap-mode)
- [RFC 8017: PKCS #1 (RSA-OAEP)](https://www.rfc-editor.org/rfc/rfc8017)
- [NIST SP 800-38D: GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [RFC 7914: scrypt](https://www.rfc-editor.org/rfc/rfc7914)
