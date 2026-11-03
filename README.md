# Secure Digital Document Vault

A command-line tool to encrypt files and share them with several recipients.
It provides **confidentiality** (only the chosen recipients can read a file),
**integrity** (any modification of the container is detected) and **access
control** (you decide who the file is shared with).

It does **not** prove who created a file: there are no digital signatures yet,
so the sender is not authenticated (see [Limitations](#limitations)).

## Project structure


| File | Purpose |
|---|---|
| `vault_crypto.py` | D2: password-based AES-256-GCM encryption of a file (single owner). |
| `vault_keys.py` | D3: Ed25519 key pairs, PEM storage, key IDs, `KeyStore`. |
| `vault_hybrid.py` | D3: multi-recipient hybrid encryption and the command-line interface. |
| `tests/` | Unit tests (`unittest`, run with `pytest`). |

## Installation

Python 3.10 or newer (CI runs on 3.12).

```bash
pip install -r requirements.txt
```

`requirements.txt`:

```
pycryptodomex>=3.20,<4
eciespy>=0.4.7,<0.5
```

## Usage

All commands are run as `python vault_hybrid.py <command> ...`. Options such as
`--keys-dir` go after the command. Keys are stored in `vault_keys/` by default.

**1. Create your key pair** (asks for a passphrase of at least 12 characters):

```bash
python vault_hybrid.py keygen alice
```

**2. Register another person's public key** and verify its Key ID with them
through a separate trusted channel (phone call, in person):

```bash
python vault_hybrid.py import-public bob path/to/bob.public.pem
python vault_hybrid.py list-keys
python vault_hybrid.py fingerprint bob
```

**3. Encrypt a file for one or more recipients** (repeat `--to`, up to 16;
include yourself if you want to be able to open it). The output must be a new file:

```bash
python vault_hybrid.py encrypt report.pdf --to alice --to bob --out report.sddv
```

**4. Inspect a container** (no key needed; the values shown are not verified):

```bash
python vault_hybrid.py inspect report.sddv
```

**5. Decrypt as a recipient** (`--as` is the name of your own key pair; asks for
your passphrase):

```bash
python vault_hybrid.py decrypt report.sddv --as bob --out report_recovered.pdf
```

To simulate several users on one computer, give each one its own directory:

```bash
python vault_hybrid.py keygen alice --keys-dir keys_alice
python vault_hybrid.py keygen bob --keys-dir keys_bob
python vault_hybrid.py import-public bob keys_bob/bob.public.pem --keys-dir keys_alice
python vault_hybrid.py encrypt doc.pdf --to bob --out doc.sddv --keys-dir keys_alice
python vault_hybrid.py decrypt doc.sddv --as bob --out doc_out.pdf --keys-dir keys_bob
```

The single-owner mode (D2, one shared password) is also available on its own:

```bash
python vault_crypto.py encrypt report.pdf --out report.v1.json
python vault_crypto.py decrypt report.v1.json --out report_recovered.pdf
```

Limits: files up to 10 MiB, 1 to 16 recipients, existing files are never overwritten.

## Running the tests

```bash
python -m pytest tests/ -v
```

## Hybrid Design Explanation

### Container layout

```
container (format version 2)
├─ header      format, version, algorithm identifiers
├─ recipients  one entry per recipient: id, key_id, encrypted_key
└─ payload     a complete D2 container (the encrypted file)
```

### Why hybrid encryption is used

Sharing a file with several people needs two things that no single kind of
cipher gives well. Asymmetric cryptography lets each person have their own
key pair, so nobody has to share a secret in advance. Symmetric cryptography
encrypts large files quickly. The hybrid design uses each for what it does best:

1. A random **file key** (256 bits) is generated for every file.
2. The file is encrypted once, with the file key (through D2).
3. The file key is encrypted separately for each recipient with their public key.

### Why symmetric encryption is still needed

Public-key encryption (ECIES here) is meant for small values such as keys. It
is slower than AES and, applied to the whole file once per recipient, would
multiply the container size by the number of recipients. AES-256-GCM encrypts
and authenticates the file in a single pass, so the document is stored **once**
no matter how many people can open it. D2 encrypts it with a fresh data key
that is wrapped with a key derived by scrypt; in D3 the password given to D2 is
the Base64 of the random file key, never something a person chooses.

### Why per-recipient key encryption is required

Each recipient needs their own way to recover the file key:

- With one shared password, everyone would hold the same secret, which must
  travel through some channel and cannot be tied to a person.
- With one entry per recipient, only the matching private key opens that entry.
  Giving access to someone new requires no secret to be sent.
- Every entry uses a fresh ephemeral key (ECIES), so two entries for the same
  file key look unrelated.

## Security Decisions

### How do recipients identify their key?

Every recipient has a **Key ID**: the SHA-256 of the public key in DER
(SubjectPublicKeyInfo) format, in lowercase hex. It is stored in the
`key_id` field of each entry. To decrypt, the program computes the Key ID of
your private key and looks for the entry with that value. If there is none, it
stops with `Access denied: the container has no entry for the supplied key.`
before any decryption is attempted. Key IDs are public and are also printed by
`keygen`, `fingerprint`, `encrypt` and `inspect`.

### What happens if an attacker modifies the recipient list?

The container header and the ordered recipient list (each `id`, `key_id` and
`encrypted_key`) are passed to D2 as **additional authenticated data (AAD)**,
so they are covered by the AES-GCM authentication tag of the file. Any change
makes decryption fail with `Authentication failed: wrong key or modified
container.` and no output file is created:

| Attack | Result |
|---|---|
| Add a recipient | Detected, decryption fails for everyone. |
| Remove a recipient | The removed user gets "no entry"; the remaining users fail authentication. |
| Reorder entries | Detected. |
| Change an `id` or swap identities | Detected. |
| Swap `key_id` values or alter an `encrypted_key` | Detected. |

An attacker who adds an entry could not grant access to anyone anyway, because
the file key can only be recovered with a recipient's private key. The
`inspect` command reads the file as stored and does **not** verify it.

### What happens if the public key is wrong?

- **Malformed or unsupported key** (not Ed25519, a private key, corrupted
  file): rejected when imported.
- **Valid key that belongs to someone else** (for example, replaced by an
  attacker): the program cannot tell. The file is encrypted for whoever holds
  that key, and the intended recipient receives "no entry". There is no
  certificate authority, so this is why `import-public` prints the Key ID and
  asks you to **verify it with the key owner through another channel**.
- **Entry that was not encrypted for the key it claims** (`key_id` matches but
  the content was made for another key): decryption fails with the
  authentication error.
