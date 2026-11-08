"""D5: Ed25519ph signatures over complete D3 encrypted containers."""

# >>>>>>>>>> Libraries <<<<<<<<<<
import argparse
import getpass
import json
from pathlib import Path

from Cryptodome.Hash import SHA512
from Cryptodome.Signature import eddsa

import vault_hybrid as hybrid
from vault_crypto import VaultError, _b64, _unb64, _check_paths, _safe_write_new
from vault_keys import (
    KeyStore, public_key_fingerprint, validate_private_key, validate_public_key,
)

# >>>>>>>>>> Signed container format <<<<<<<<<<
METADATA = {"format": "SDDV", "version": 3, "signature_algorithm": "Ed25519ph-SHA512"}
SIGNED_FIELDS = {"metadata", "header", "recipients", "payload", "signer_id"}
SIGNATURE_FAILED = "Signature verification failed: wrong sender key or modified container."


def _signature_hash(container):
    content = {name: container[name] for name in SIGNED_FIELDS}
    encoded = json.dumps(content, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    return SHA512.new(b"SDDV|v3|signature|" + encoded)


# >>>>>>>>>> Signature generation and verification <<<<<<<<<<
def sign_container(container, private_key):
    validate_private_key(private_key)
    hybrid._validate_container(container)
    signed = {
        **container, "metadata": dict(METADATA),
        "signer_id": public_key_fingerprint(private_key),
    }
    signed["signature"] = _b64(
        eddsa.new(private_key, "rfc8032").sign(_signature_hash(signed))
    )
    return signed


def verify_container(container, sender_public_key):
    validate_public_key(sender_public_key)
    if not isinstance(container, dict) or set(container) != SIGNED_FIELDS | {"signature"}:
        raise VaultError("Invalid signed container: signature and all signed fields are required.")
    if container["metadata"] != METADATA or type(container["metadata"].get("version")) is not int:
        raise VaultError("Unsupported signed container metadata.")
    if container["signer_id"] != public_key_fingerprint(sender_public_key):
        raise VaultError(SIGNATURE_FAILED)
    signature = _unb64(container["signature"], "signature", 64)
    try:
        eddsa.new(sender_public_key, "rfc8032").verify(_signature_hash(container), signature)
    except (ValueError, TypeError, OverflowError):
        raise VaultError(SIGNATURE_FAILED) from None
    return {name: container[name] for name in ("header", "recipients", "payload")}


# >>>>>>>>>> Encryption and verified decryption <<<<<<<<<<
def signed_encrypt_bytes(plaintext, recipients, sender_private_key):
    return sign_container(hybrid.hybrid_encrypt_bytes(plaintext, recipients), sender_private_key)


def signed_decrypt_bytes(container, recipient_private_key, sender_public_key):
    encrypted = verify_container(container, sender_public_key)
    return hybrid.hybrid_decrypt_bytes(encrypted, recipient_private_key)


def signed_encrypt_file(input_path, output_path, recipients, sender_private_key):
    source, target = Path(input_path), Path(output_path)
    _check_paths(source, target)
    if source.stat().st_size > hybrid.MAX_FILE_SIZE:
        raise VaultError("Input file exceeds the 10 MiB limit.")
    container = signed_encrypt_bytes(source.read_bytes(), recipients, sender_private_key)
    _safe_write_new(target, (json.dumps(container, indent=2) + "\n").encode("utf-8"))
    return target


def signed_decrypt_file(input_path, output_path, recipient_private_key, sender_public_key):
    source, target = Path(input_path), Path(output_path)
    _check_paths(source, target)
    plaintext = signed_decrypt_bytes(
        hybrid._read_container(source), recipient_private_key, sender_public_key)
    _safe_write_new(target, plaintext)
    return target


# >>>>>>>>>> Command line interface <<<<<<<<<<
def _build_parser():
    parser = argparse.ArgumentParser(description="Signed multi-recipient document vault (D5)")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("keygen", "list-keys", "fingerprint", "import-public",
                    "encrypt", "decrypt", "inspect"):
        item = sub.add_parser(command)
        item.add_argument("--keys-dir", default=hybrid.DEFAULT_KEYS_DIR)
        if command in ("keygen", "fingerprint", "import-public"):
            item.add_argument("name")
        if command == "import-public":
            item.add_argument("file")
        if command in ("encrypt", "decrypt", "inspect"):
            item.add_argument("input")
            item.add_argument("--signer", required=True, help="Expected sender's stored key name")
        if command in ("encrypt", "decrypt"):
            item.add_argument("--out", required=True)
        if command == "encrypt":
            item.add_argument("--to", action="append", required=True, metavar="NAME")
        if command == "decrypt":
            item.add_argument("--as", dest="user", required=True, metavar="NAME")
    return parser


def _run(args):
    if args.command not in ("encrypt", "decrypt", "inspect"):
        hybrid._run(args)
        return
    store = KeyStore(args.keys_dir)
    if args.command == "encrypt":
        sender = store.load_private(args.signer, getpass.getpass("Sender private key passphrase: "))
        recipients = [(name, store.load_public(name)) for name in args.to]
        result = signed_encrypt_file(args.input, args.out, recipients, sender)
        print(f"SUCCESS: Encrypted the document for {len(recipients)} recipient(s) and signed it.")
        print(f"Signer: {args.signer} | Key ID: {public_key_fingerprint(sender)}")
        print(f"Signed container saved to: {result}")
    else:
        sender = store.load_public(args.signer)
        container = hybrid._read_container(Path(args.input))
        encrypted = verify_container(container, sender)
        print(f"VERIFIED: Signature matches sender '{args.signer}'.")
        print(f"Signer Key ID: {container['signer_id']}")
        print("The encrypted content, recipient list and metadata passed signature verification.")
        if args.command == "decrypt":
            source, target = Path(args.input), Path(args.out)
            _check_paths(source, target)
            private = store.load_private(args.user, getpass.getpass("Recipient private key passphrase: "))
            plaintext = hybrid.hybrid_decrypt_bytes(encrypted, private)
            _safe_write_new(target, plaintext)
            print(f"SUCCESS: Decrypted as '{args.user}'; recovered document saved to: {target}")
        else:
            hybrid._validate_container(encrypted)
            for recipient in encrypted["recipients"]:
                print(f"Recipient: {recipient['id']} | Key ID: {recipient['key_id']}")


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        _run(args)
    except (VaultError, OSError) as exc:
        parser.exit(status=1, message=f"REJECTED: {exc}\n")


if __name__ == "__main__":
    main()
