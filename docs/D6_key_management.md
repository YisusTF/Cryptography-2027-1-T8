# D6 - Key Management Design and Security Discussion

## 1. Private key protection and storage format

The existing `KeyStore` is reused. No server, database, password file or new
dependency is needed. Private keys are stored as password-protected PKCS#8 PEM
(`EncryptedPrivateKeyInfo`), never as plaintext. New D6 keys use:

| Item | Choice |
| --- | --- |
| Curve | Ed25519 |
| KDF | scrypt |
| KDF work factor | N = 32768, r = 8, p = 1 |
| Salt | Random 16 bytes, unique to each encryption |
| Private-key protection | AES-256-GCM, with random 12-byte nonce and 16-byte authentication tag |
| Public-key identifier | SHA-256 fingerprint of DER SubjectPublicKeyInfo (64 hex characters) |
| Minimum passphrase length | 12 characters (length alone does not guarantee strength) |

This is the structured keystore format:

```text
vault_keys/
  alice.private.pem   # encrypted PKCS#8: KDF/salt/nonce/tag/ciphertext inside PEM
  alice.public.pem    # public Ed25519 key, unencrypted
  bob.private.pem
  bob.public.pem
```

PKCS#8 embeds the key-encryption algorithm and its parameters in a standard
ASN.1 structure; a separate plaintext salt or JSON password file is **not**
required. File names identify aliases; the public key fingerprint identifies
the actual cryptographic key. The private/public fingerprint must match when
loading a private key. On POSIX, new private keys and backups use mode `0600`.
Public PEM files are intentionally shareable; the recipient must verify their
fingerprints by an independent trusted channel.

Previously generated D3/D5 private keys encrypted with AES-256-CBC remain
readable for compatibility. Restoring one from backup writes a new AES-256-GCM
protected PEM. Old CBC files do not provide GCM's authenticated-encryption
guarantee; users should migrate them via backup/restore to a new keys directory.

## 2. Password-based access

The CLI uses `getpass` when a private key is needed to sign, decrypt or restore.
The password is not stored on disk or cached. The encrypted private key is
decrypted into process memory only for that operation. Public-key operations
(`list-keys`, `fingerprint`, `inspect`, and recipient encryption) do not need
the recipient's private-key password. Copying a backup does not decrypt it.

The correct passphrase is required, but users must choose an unpredictable
one: twelve repeated characters would be weak. scrypt makes offline password
guesses more expensive; it cannot make a weak passphrase unguessable.

## 3. Secure backup and recovery

Create a backup **without decrypting the key**:

```bash
python vault_signed.py backup-key alice --out alice-backup.private.pem
```

The backup contains only the encrypted private PKCS#8 PEM. The CLI never
overwrites an existing backup. Store it securely, preferably off the device,
and never commit it to Git. A backup of the public PEM is optional because
the public key can be reconstructed from the recovered private key.

Restore to a new key directory (shown here to avoid touching active keys):

```bash
python vault_signed.py restore-key alice alice-backup.private.pem --keys-dir restored_keys
python vault_signed.py fingerprint alice --keys-dir restored_keys
```

The restore command asks for the backup's passphrase, verifies that the
private key can be opened, checks its fingerprint against any existing public
key with that alias, then writes a **freshly encrypted AES-GCM private PEM**.
It also reconstructs a missing public PEM. Existing private key files are never
overwritten, failed password checks create no restored key, and a failed public
key write rolls back the newly created private file. Verify the restored
fingerprint against the original trusted fingerprint before further use.

Recovery **requires the password**. A stolen backup without that password does
not provide an authorized recovery mechanism. There is no password-reset
backdoor or server-side secret escrow.

## 4. Key lifecycle

| Stage | Current behavior and procedure |
| --- | --- |
| Generation | `keygen USER` generates a random Ed25519 pair and encrypts the private key with a password-derived key. |
| Usage | `--to USER` selects recipient public keys; `--as USER` selects a recipient private key; `--signer USER` selects the signer's private/public key. |
| Backup | `backup-key USER --out PATH` saves only the encrypted private PEM. |
| Recovery | `restore-key USER BACKUP --keys-dir DIR` requires the passphrase and preserves the same fingerprint. |
| Rotation | Generate a **new** pair under a versioned alias such as `alice_v2`; authenticate/distribute its new public key and use it for new documents. |
| Compromise response | Stop trusting the compromised fingerprint, notify recipients, rotate keys, and re-encrypt documents for new recipient keys. |
| Expiration | Not automated in this classroom project; key validity dates/revocation are future work. |

Important: rotating a recipient key does **not** automatically update existing
documents. Their ECIES-wrapped file keys still reference the old key, so the
owner must securely re-encrypt those documents for the new key before losing
access to the old one. Old signatures also need the corresponding old trusted
public key for historical verification. Never silently replace an alias to
make an old key look like the new key.

The D3/D5 project currently uses one Ed25519 pair for ECIES and Ed25519ph
signing, with explicit CLI operations and fingerprints. A production design
should use different keys for signing and key agreement.

## 5. Access control and D3 sharing

- Only the private key matching an ECIES recipient `key_id` can unwrap that
  recipient's encrypted file key; D2 AES-GCM still authenticates the payload.
- A correct password permits local use of an encrypted private key; an
  incorrect password is rejected.
- D5 checks a signature against the recipient's independently trusted sender
  public key **before** calling D3 decryption.
- D3 recipient selection remains unchanged. A backup does not add or remove
  recipients from an existing encrypted document.
- A private key cannot be loaded under a different public key identity without
  triggering a mismatch error.

## 6. D1 threat model alignment

The sender and recipient devices/key stores are trusted. Mallory can read,
copy, alter, delete or replay items in **untrusted storage and transit**.

**A. What if an attacker steals the keystore?** The private PEM is encrypted
with a password-derived AES-256-GCM key, while public PEMs do not grant
decryption rights. The attacker can attempt offline password guessing; their
success depends strongly on password entropy. Loss or deletion of the backup
cannot be prevented by encryption.

**B. What if a password is weak?** An attacker who stole the encrypted private
PEM may guess it offline. scrypt raises the cost of each guess but cannot
prevent success with a weak password. Users must select strong passphrases.

**C. What if a device is compromised?** Malware running on a trusted endpoint
could capture the password when it is typed, steal decrypted private-key
material from memory, modify trusted public keys, or read recovered plaintext.
This is outside the protection offered by the current application.

**Additional assumptions and limits:**

- The user authenticates exchanged public-key fingerprints out of band; file
  names and untrusted directories are not identity authorities.
- The local operating system protects a trusted user's files and processes.
- No automatic revocation, expiration, replay defense, hardware security
  module, malware defense, or password recovery is implemented.
- GCM detects tampering of new encrypted private keys; legacy CBC PEM backups
  should be migrated. Valid older signed documents can still be replayed.

## 7. Automated acceptance tests

Run:

```bash
python -m unittest discover -s tests -v
```

The D6 test file demonstrates all five mandatory cases:

1. Correct password grants access.
2. Wrong password denies access.
3. Modified encrypted keystore is rejected.
4. Encrypted backup restores the same key, which can decrypt an old document.
5. Stolen keystore alone (without the password) cannot decrypt.

Additional tests protect against overwrites, identity substitution during
restore, incorrect recovery passwords and legacy D5 backup compatibility.

## References

- [PyCryptodome ECC key import/export](https://www.pycryptodome.org/src/public_key/ecc)
- [PyCryptodome password-based encryption](https://www.pycryptodome.org/src/io/pkcs8)
- [RFC 8032: Ed25519 signatures](https://www.rfc-editor.org/rfc/rfc8032)
