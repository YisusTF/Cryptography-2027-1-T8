# Secure Digital Document Vault

A Python command-line tool for encrypting documents, sharing them with selected
recipients and verifying the sender with digital signatures.

| Deliverable | Function |
|---|---|
| D2 | Password-based encryption with AES-256-GCM |
| D3 | Multi-recipient access with ECIES and Ed25519 keys |
| D5 | Sender authentication with Ed25519ph signatures |

## Installation

Python 3.10 or newer is required.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows, activate the environment with `.venv\Scripts\activate`.
D5 uses PyCryptodomex, already required by D3, for signatures. No new dependency
is needed.

## Usage

Use `vault_signed.py` for D5. All commands below run from the project directory.
Private key passphrases must contain at least 12 characters.

Create the sender's and recipient's keys:

```bash
python vault_signed.py keygen alice
python vault_signed.py keygen bob
python vault_signed.py list-keys
python vault_signed.py fingerprint alice
```

When working on separate computers, exchange only public PEM files. Import the
other person's public key and confirm its fingerprint with the owner through a
trusted channel before using it:

```bash
python vault_signed.py import-public alice path/to/alice.public.pem
python vault_signed.py fingerprint alice
```

The sender needs the recipient's public key; the recipient needs the sender's
public key. Each person keeps their own private key. Use `--keys-dir DIRECTORY`
after a command to choose a separate key directory for each user.

Encrypt for Bob and sign as Alice (asks for Alice's private key passphrase):

```bash
python vault_signed.py encrypt sample_document.txt --to bob --signer alice --out signed_document.sddv
```

Repeat `--to NAME` to add recipients, up to 16. Include Alice with `--to alice`
if she should also be able to decrypt the document.

Verify Alice's signature and inspect the recipient list without decrypting:

```bash
python vault_signed.py inspect signed_document.sddv --signer alice
```

Verify Alice's signature, then decrypt as Bob:

```bash
python vault_signed.py decrypt signed_document.sddv --as bob --signer alice --out recovered_document.txt
```

`--signer alice` selects the public key the recipient already trusts as Alice's.
The container cannot choose a replacement verification key. Verification happens
before the recipient is asked for their private key passphrase. A rejected
container produces an error and no recovered document. Existing output files
are never overwritten. The input file limit remains 10 MiB.

## Signature design

D5 follows **Encrypt → Add metadata → Hash → Sign → Store**.

The signature algorithm is **Ed25519ph**, the prehash variant of Ed25519 defined
in RFC 8032. The code passes a SHA-512 hash object to PyCryptodomex's EdDSA API,
which performs the standard Ed25519ph operation. Verification uses the same
algorithm. This is one fixed algorithm, with no algorithm selection from input.

The signed message is the ASCII encoding of JSON with sorted object keys,
compact separators and ASCII escapes. Recipient array order is preserved.
The prefix `SDDV|v3|signature|` identifies the signing context. The SHA-512 hash
covers every top-level field except `signature`:

- `metadata`: D5 format, version and signature algorithm.
- `header`: the original D3 format and algorithm identifiers.
- `recipients`: the complete ordered list of labels, key IDs and encrypted keys.
- `payload`: the complete D2 output, including its header, ciphertext, nonce
  and authentication tag.
- `signer_id`: SHA-256 of the signer's DER SubjectPublicKeyInfo public key,
  represented by 64 lowercase hexadecimal characters.

The raw 64-byte signature is stored as standard Base64. A version 3 signed
container keeps the D3 structure and adds three fields:

```text
{
  metadata: {format: SDDV, version: 3, signature_algorithm: Ed25519ph-SHA512},
  header: <D3 header, version 2>,
  recipients: <D3 recipient list>,
  payload: <complete D2 container: header, nonce, ciphertext, authentication_tag>,
  signer_id: <sender public key fingerprint>,
  signature: <Base64 signature>
}
```

The ciphertext and tag remain inside `payload`, preserving the existing D2/D3
implementation. The outer version is 3; the embedded D3 header remains version 2.
Whitespace and JSON object key order do not change the signed data. Any change
to a signed value, addition/removal of a field, or recipient reordering is
rejected. Duplicate JSON keys are rejected when reading the file.

### Why hash before signing?

SHA-512 represents the complete signed message with a fixed-size, collision
resistant digest. Ed25519ph defines how this prehash is signed, so verification
requires exactly the same signed content. The hash alone cannot authenticate
the sender: the private-key signature supplies authentication.

### Why sign ciphertext instead of plaintext?

A recipient can verify the encrypted package before decrypting it. The signature
binds the exact encrypted content and metadata without needing plaintext or a
recipient's private key. AES-GCM still authenticates the decrypted payload.

### What if verification is skipped or delayed?

An attacker could supply a container encrypted by someone else and claim it came
from Alice. Decrypting first could process or expose unauthenticated content.
D5 verifies the expected sender's signature before calling D3 decryption.

### What if metadata is excluded?

A signature over ciphertext alone would not authenticate recipient identities,
algorithm identifiers or other context. D5 signs all D3 AAD fields and the
complete D2 payload, plus the D5 metadata and signer fingerprint.

### Limits

A fingerprint proves identity only after the public key has been authenticated
through a trusted channel. A stolen private key can be used to forge signatures.
D5 does not implement replay detection, key revocation or protection against a
compromised computer. It reuses D3's existing Ed25519 key pairs for this classroom
extension; a production system should separate signing and encryption keys.

`vault_crypto.py` and `vault_hybrid.py` remain available for the earlier
assignments. They do not provide D5 sender authentication. D5 rejects unsigned
D2/D3 containers rather than silently falling back to unsigned decryption.

## Tests

Run all tests, including the existing D3 tests:

```bash
python -m unittest discover -s tests -v
```

Run only the signature tests:

```bash
python -m unittest discover -s tests -p test_vault_signed.py -v
```

Each D5 test prints a description of the acceptance or rejection being checked;
`ok` confirms the expected result. Negative tests pass when the attack is rejected.
D5 tests are separated by a blank line. The five required tests are displayed as
`REQUIRED_TEST_01` through `REQUIRED_TEST_05`; their method names remain unchanged.

| Required case | Test |
|---|---|
| Valid signature accepted | `test_01_valid_signature_is_accepted` |
| Modified ciphertext rejected | `test_02_modified_ciphertext_is_rejected` |
| Modified metadata rejected | `test_03_modified_metadata_is_rejected` |
| Wrong public key rejected | `test_04_wrong_public_key_is_rejected` |
| Missing signature rejected | `test_05_removed_signature_is_rejected` |

Additional tests check forgery, unsigned containers, verification before
decryption, absence of plaintext after failure, file round trips, overwrite
protection and CLI behavior. GitHub Actions runs the suite on pushes and pull
requests.

## Files

| File | Purpose |
|---|---|
| `vault_crypto.py` | Existing D2 symmetric encryption |
| `vault_keys.py` | Existing D3 Ed25519 key management |
| `vault_hybrid.py` | Existing D3 multi-recipient encryption |
| `vault_signed.py` | D5 signatures, verification and command-line interface |
| `tests/test_vault_signed.py` | D5 tests |
| `tests/test_vault_keys.py`, `tests/test_vault_hybrid.py` | Existing D3 tests |
| `requirements.txt` | Existing dependencies |
| `.github/workflows/python-tests.yml` | Automated tests |

Never upload private keys, virtual environments or decrypted documents.

## References

- [RFC 8032: Ed25519 and Ed25519ph](https://www.rfc-editor.org/rfc/rfc8032)
- [PyCryptodome: EdDSA](https://www.pycryptodome.org/src/signature/eddsa)
