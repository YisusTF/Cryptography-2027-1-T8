# Cryptography 2027-1 - Team 8

## D2: Secure Symmetric Encryption

For D2, we made the encryption part of our **Secure Digital Document Vault** from D1. The idea is simple: encrypt a document before saving it somewhere else, then recover it later using a password. This version works locally with one owner. File sharing, digital signatures and user accounts can be added in later deliverables.

### How it works

We used Python and the `pycryptodome` library instead of writing AES ourselves.

1. The program generates a new random 256-bit AES key for every file.
2. It also creates a random 12-byte nonce and encrypts the contents with **AES-256-GCM**.
3. A separate key is derived from the owner's password with **scrypt** (from PyCryptodome). This key is used with AES Key Wrap to protect the AES file key, so the file key isn't saved in plaintext.
4. The encrypted file is a JSON container with a header, nonce, ciphertext and authentication tag. The header is authenticated as **AAD**, which means changing its metadata will make decryption fail.
5. Decryption first checks the password and GCM authentication. The recovered file is only written after these checks pass.

We do not put passwords in files, command arguments or logs. The code also refuses to overwrite an existing output and limits input documents to **10 MiB** so the first version stays manageable.

### How to run it

Requires Python 3.10 or newer.

```bash
python -m pip install -r requirements.txt
python vault_crypto.py encrypt sample_document.txt --out sample_document.sddv
python vault_crypto.py decrypt sample_document.sddv --out recovered_document.txt
```

The program will ask for a password (at least 12 characters). Use the same password to decrypt. For a real document, use a strong and unique passphrase.

### Tests

```bash
python -m unittest discover -s tests -v
```

The tests cover all five required D2 scenarios: successful round-trip, wrong password, modified ciphertext, modified metadata and different outputs for repeated encryption. There are also extra checks for invalid JSON, altered nonces/tags, output overwriting, empty files and key-derivation parameters.

**Why AES-GCM rather than encryption plus a hash?** AEAD verifies ciphertext and associated data using one authenticated design. An unkeyed hash alone could be recomputed by an attacker. Reusing a GCM nonce with the same key can expose relationships between messages and damage authentication security. We generate fresh random keys and nonces for each file.

**Note:** The earlier version used another library. After changing to PyCryptodome, the tests must be run again in an environment where `pycryptodome` can be installed. Do not report a passing result until that run succeeds.

### Container structure

The `.sddv` file stores JSON with these fields:

- `header`: format/version, algorithm, scrypt settings, salt, wrapped file key and creation date.
- `nonce`: random nonce for AES-GCM.
- `ciphertext`: encrypted document bytes.
- `authentication_tag`: the GCM integrity tag.

Binary values are stored in Base64. The header is visible but authenticated; the original filename is not stored. The nonce is also checked during GCM decryption. Reusing a nonce with the **same** GCM key would be dangerous, so we create a new random key and nonce for each encryption.

### What this version does not do

This module **does not** prove the identity of the person who created a container, support multiple recipients, detect an old valid container being replayed, or protect documents after they have been decrypted. These are separate topics from D1 that we are not implementing in D2. Someone with an encrypted file can try guessing the password offline, so password strength matters. The program is a class project, not a production security product.

### Relation to D1

D1 describes the complete future workflow: a sender protects a document, an attacker may modify it in untrusted storage or transfer, and a recipient must validate it. This D2 implements the encryption and integrity component on a trusted endpoint for **one owner only**, as requested. GCM authentication detects unauthorized ciphertext and metadata changes. D1 features still pending include digital signatures/sender identity, multi-recipient key distribution, recipient authorization, external replay tracking, and key management beyond this password-protected prototype. A valid older encrypted package cannot be detected as a replay without trusted external state. Neither D1 nor this D2 protects fully compromised endpoints.

### Sources

- [PyCryptodome: AES authenticated encryption](https://www.pycryptodome.org/src/cipher/aes)
- [PyCryptodome: AES Key Wrap](https://www.pycryptodome.org/src/cipher/modern#key-wrap-mode)
- [NIST SP 800-38D: GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [RFC 7914: scrypt](https://www.rfc-editor.org/rfc/rfc7914)
