# D3 - Hybrid Design Explanation and Security Decisions

This document explains how the Secure Digital Document Vault shares one encrypted file with several recipients. It extends the symmetric module delivered in D2 and follows the scope defined in D1.

## 1. Hybrid design

```
File  --AES-256-GCM (random file key)-->  ciphertext + tag
File key --RSA-OAEP(Alice public key)-->  entry for Alice
File key --RSA-OAEP(Bob public key)-->    entry for Bob
File key --RSA-OAEP(Carol public key)-->  entry for Carol
```

1. A new random 256-bit **file key** and a new random 12-byte nonce are generated.
2. The document is encrypted **once** with AES-256-GCM (the AEAD mode from D2).
3. The file key is encrypted **separately for each recipient** with that recipient's RSA public key, using RSA-OAEP with SHA-256.
4. The container stores the ciphertext, the tag and one entry per recipient.

To open the file, a recipient finds their own entry, decrypts the file key with their private key, and uses it to authenticate and decrypt the document.

### Why hybrid encryption is used

Public-key encryption lets two people share a secret without having agreed on a password beforehand. Alice only needs Bob's public key, which is not secret. Because each recipient has their own key pair, no password has to be shared between users, and access can be given to several people at the same time.

### Why symmetric encryption is still needed

RSA can only encrypt data smaller than its key size (at most 190 bytes for RSA-2048 and 318 bytes for RSA-3072 with OAEP and SHA-256), and it is slow and expensive for large inputs. A document may be several megabytes. AES-256-GCM is fast, handles data of any size, and also authenticates the data. For this reason RSA is used **only** for the 32-byte file key, and AES-GCM is used for the document itself. The implementation never passes document data to RSA.

### Why per-recipient key encryption is required

Every recipient needs a way to recover the same file key, and each recipient can only use their own private key. Therefore the file key must be encrypted once per public key. The large ciphertext is stored only once, so adding a recipient adds only a few hundred bytes to the container. Adding or removing a recipient after the file is created cannot be done without detection, as explained below.

## 2. Container format (version 2)

```json
{
  "header": {
    "format": "SDDV",
    "version": 2,
    "algorithm": "AES-256-GCM",
    "key_encryption": "RSA-OAEP-SHA256",
    "key_id_algorithm": "SHA-256-SPKI-DER",
    "created_utc": "2026-10-26T02:07:19Z"
  },
  "recipients": [
    { "id": "alice", "key_id": "<64 hex characters>", "encrypted_key": "<Base64>" },
    { "id": "bob",   "key_id": "<64 hex characters>", "encrypted_key": "<Base64>" }
  ],
  "nonce": "<Base64, 12 bytes>",
  "ciphertext": "<Base64>",
  "authentication_tag": "<Base64, 16 bytes>"
}
```

The container is JSON, as in D2. Binary values use Base64. The parser accepts exactly these fields, rejects duplicate JSON keys, and checks every size and format before any private-key operation.

## 3. Authenticated data (AAD)

The AAD is the canonical JSON form of `{header, recipients}`, preceded by the prefix `SDDV|v2|`. It therefore covers:

- the recipient list, including its order;
- every key identifier (`key_id`) and every recipient label (`id`);
- every encrypted file key;
- the algorithm identifiers (`algorithm`, `key_encryption`, `key_id_algorithm`), the version and the creation date.

The AAD is passed to AES-GCM, so the tag is only valid if all of these values are exactly as the sender created them.

In addition, each encrypted file key is bound to the recipient and to the container through the **OAEP label**: `SDDV|v2|file-key|<key_id>|<nonce>`. An encrypted file key copied into a different container, or presented under a different key identifier, does not decrypt.

## 4. Security decisions

### How do recipients identify their key?

The identifier is the **key ID**: the SHA-256 hash of the recipient's public key in DER (SubjectPublicKeyInfo) form, written as 64 lowercase hexadecimal characters.

- It is **deterministic**: the same public key always gives the same ID, and the ID can be recomputed from the private key because the public key is derived from it.
- It is **collision resistant**: two different keys cannot realistically have the same ID, so one recipient cannot be confused with another.
- Lookup uses the key ID, not the text label. The label (`id`, for example `alice`) is only a readable name; it is authenticated but never used to select a key.
- A container with two entries that share a label or a key ID is rejected.

### What happens if an attacker modifies the recipient list?

The recipient list is part of the AAD, so any change makes the GCM tag fail for **every** recipient. This covers adding an entry, removing an entry, changing a label, changing a key ID, changing an encrypted key, and reordering the list. The attacker cannot repair the tag because it requires the file key, which only recipients have.

Two outcomes are possible. If the modification removes or changes the entry of the person decrypting, that person receives "Access denied: no entry for the supplied key". In every other case the result is "Authentication failed". In both cases no plaintext file is written.

### What happens if the public key is wrong?

The system encrypts for whichever public key it is given. If the sender uses a wrong key (for example, one substituted by an attacker), the file key is readable by the owner of that wrong key, and the intended recipient cannot open the file. Mathematics cannot detect this; only the identity of the key can.

For this reason:

- the program prints the key ID of every recipient when encrypting and when importing a public key;
- users should confirm the key ID with the key's owner through a separate trusted channel (in person, by phone or by another verified message) before sharing sensitive files;
- the `inspect` command shows the key IDs stored in any container.

This matches the D1 assumption that public keys are authentic. A certificate authority or web-of-trust mechanism is outside the scope of D3.

If the key used to decrypt is not the one in the container, decryption fails with no plaintext output.

## 5. Algorithms and parameters

| Purpose | Choice |
|---|---|
| Document encryption | AES-256-GCM, 12-byte random nonce, 16-byte tag (as in D2) |
| File key | 256-bit random value, new for every container |
| Key encryption | RSA-OAEP, SHA-256 (hash and MGF1), per-recipient label |
| RSA keys | 3072 bits by default; 2048 and 4096 also accepted; public exponent 65537 |
| Key ID | SHA-256 of DER SubjectPublicKeyInfo |
| Private key storage | PKCS#8 PEM, scrypt (N = 2^15, r = 8, p = 1) and AES-256-CBC, passphrase of at least 12 characters |
| Library | PyCryptodome (same as D2) |

RSA-OAEP is used instead of PKCS#1 v1.5 because OAEP is the recommended padding for encryption. RSA keys below 2048 bits are rejected.

## 6. What is preserved from D2

- `vault_crypto.py` and its 12 tests are unchanged. Password-based containers (version 1) still work.
- The same AES-256-GCM parameters, strict parsing, 10 MiB limit, no overwriting of output and no plaintext output on failure.
- The same fail-closed error handling with generic messages.

## 7. Limits of this version

- No sender authentication: anyone with a recipient's public key can create a valid container. Digital signatures are a later deliverable.
- No replay or rollback protection: an old valid container is still valid.
- The sender can open a container only if the sender is also listed as a recipient.
- A recipient who has decrypted the file can share the plaintext; this is out of scope as defined in D1.
- No key revocation or key rotation. To stop a person from opening future files, do not list them as a recipient. A file already shared cannot be taken back.
- Public key authenticity depends on the user comparing key IDs.
- A compromised computer (or a stolen private key file with a weak passphrase) is outside the guarantees.
