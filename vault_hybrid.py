"""D3 - Multi-recipient hybrid encryption for the Secure Digital Document Vault.

File content is encrypted by vault_crypto.encrypt_bytes (D2). This module only
decides who can open it: a random file key, used as the D2 password, is
encrypted for every recipient with ECIES (Ed25519, AES-256-GCM) via eciespy.

Container (format version 2):
	header      public format description
	recipients  one ECIES-encrypted copy of the file key per recipient
	payload     complete D2 container (format version 1)

The header and the ordered recipient list (ids, key IDs and encrypted keys) are
passed to D2 as additional authenticated data, so adding, removing, reordering
or relabeling recipients makes decryption fail. inspect shows these fields
without verifying them, since verification requires a recipient's private key.
"""

import argparse
import getpass
import json
import re
from pathlib import Path

from Cryptodome.Random import get_random_bytes
from ecies import decrypt as ecies_decrypt
from ecies import encrypt as ecies_encrypt
from ecies.config import Config

from vault_crypto import (
	EXPECTED_OUTER as V1_OUTER, KEY_SIZE, MAX_CONTAINER_SIZE, MAX_FILE_SIZE,
	VaultError, _b64, _check_paths, _reject_duplicate_keys,
	_reject_nonjson_constant, _safe_write_new, _unb64, decrypt_bytes,
	encrypt_bytes
)
from vault_crypto import _validate_container as _validate_payload
from vault_keys import (
	MAX_KEY_FILE_SIZE, NAME_PATTERN, KeyStore, private_key_bytes,
	public_key_bytes, public_key_fingerprint, validate_name,
	validate_private_key, validate_public_key
)


# ===== Constants =====
FORMAT_VERSION = 2
KEY_ENCRYPTION = "ECIES-Ed25519-AES-256-GCM"
KEY_ID_ALGORITHM = "SHA-256-SPKI-DER"
MAX_RECIPIENTS = 16
KEY_ID_PATTERN = re.compile(r"[0-9a-f]{64}")
DEFAULT_KEYS_DIR = "vault_keys"
ECIES_PARAMS = Config(
	elliptic_curve="ed25519", symmetric_algorithm="aes-256-gcm",
	symmetric_nonce_length=16
)
# ephemeral public key (32) + GCM nonce (16) + GCM tag (16) + file key
ENCRYPTED_KEY_SIZE = 32 + 16 + 16 + KEY_SIZE
EXPECTED_OUTER = {"header", "recipients", "payload"}
EXPECTED_HEADER = {"format", "version", "key_encryption", "key_id_algorithm"}
EXPECTED_ENTRY = {"id", "key_id", "encrypted_key"}
AUTH_FAILED = "Authentication failed: wrong key or modified container."
NO_ENTRY = "Access denied: the container has no entry for the supplied key."


# ===== Authenticated data and file key handling =====
def _canonical_aad(header, recipients):
	"""Header and ordered recipient list, serialized deterministically for D2."""
	return b"SDDV|v2|" + json.dumps(
		{"header": header, "recipients": recipients}, sort_keys=True,
		separators=(",", ":"), ensure_ascii=True, allow_nan=False
	).encode("ascii")


def _payload_password(file_key):
	"""The D2 password is the Base64 text of the random file key (44 characters)."""
	return _b64(file_key)


def _wrap_file_key(public_key, file_key):
	return ecies_encrypt(public_key_bytes(public_key), file_key, config=ECIES_PARAMS)


def _unwrap_file_key(entry, private_key):
	try:
		file_key = ecies_decrypt(
			private_key_bytes(private_key),
			_unb64(entry["encrypted_key"], "encrypted_key", ENCRYPTED_KEY_SIZE),
			config=ECIES_PARAMS
		)
	except ValueError:
		raise VaultError(AUTH_FAILED) from None
	if len(file_key) != KEY_SIZE:
		raise VaultError(AUTH_FAILED)
	return file_key


# ===== Container validation =====
def _validate_container(container):
	"""Reject malformed or unknown structure before any key operation."""
	if (isinstance(container, dict) and set(container) == V1_OUTER
		and isinstance(container["header"], dict)
		and container["header"].get("version") == 1):
		raise VaultError("Version 1 (password) container: use vault_crypto.py to decrypt it.")
	if not isinstance(container, dict) or set(container) != EXPECTED_OUTER:
		raise VaultError("Invalid encrypted container.")
	header, recipients = container["header"], container["recipients"]
	if not isinstance(header, dict) or set(header) != EXPECTED_HEADER:
		raise VaultError("Invalid encrypted container.")
	if (header["format"] != "SDDV" or type(header["version"]) is not int
		or header["version"] != FORMAT_VERSION
		or header["key_encryption"] != KEY_ENCRYPTION
		or header["key_id_algorithm"] != KEY_ID_ALGORITHM):
		raise VaultError("Unsupported or invalid encrypted container.")
	if not isinstance(recipients, list) or not 1 <= len(recipients) <= MAX_RECIPIENTS:
		raise VaultError("Invalid encrypted container: recipient list.")
	seen_ids, seen_key_ids = set(), set()
	for entry in recipients:
		if not isinstance(entry, dict) or set(entry) != EXPECTED_ENTRY:
			raise VaultError("Invalid encrypted container: recipient entry.")
		identifier, key_id = entry["id"], entry["key_id"]
		if (not isinstance(identifier, str) or not NAME_PATTERN.fullmatch(identifier)
			or not isinstance(key_id, str) or not KEY_ID_PATTERN.fullmatch(key_id)):
			raise VaultError("Invalid encrypted container: recipient entry.")
		if identifier in seen_ids or key_id in seen_key_ids:
			raise VaultError("Invalid encrypted container: duplicate recipient.")
		seen_ids.add(identifier)
		seen_key_ids.add(key_id)
		_unb64(entry["encrypted_key"], "encrypted_key", ENCRYPTED_KEY_SIZE)
	_validate_payload(container["payload"])
	return header, recipients, container["payload"]


# ===== Encryption and decryption of byte strings =====
def hybrid_encrypt_bytes(plaintext, recipients):
	"""Encrypt once for a list of (id, public_key) pairs; return the container."""
	if not isinstance(plaintext, bytes):
		raise VaultError("Input content must be bytes.")
	if len(plaintext) > MAX_FILE_SIZE:
		raise VaultError("Input file exceeds the 10 MiB limit.")
	if not isinstance(recipients, (list, tuple)) or not 1 <= len(recipients) <= MAX_RECIPIENTS:
		raise VaultError("Between 1 and 16 recipients are required.")
	prepared, seen_ids, seen_key_ids = [], set(), set()
	for identifier, public_key in recipients:
		validate_name(identifier)
		validate_public_key(public_key)
		key_id = public_key_fingerprint(public_key)
		if identifier in seen_ids or key_id in seen_key_ids:
			raise VaultError("Duplicate recipient.")
		seen_ids.add(identifier)
		seen_key_ids.add(key_id)
		prepared.append((identifier, key_id, public_key))
	# Fresh file key for every container, from the OS-backed CSPRNG.
	file_key = get_random_bytes(KEY_SIZE)
	entries = [
		{
			"id": identifier,
			"key_id": key_id,
			"encrypted_key": _b64(_wrap_file_key(public_key, file_key))
		}
		for identifier, key_id, public_key in prepared
	]
	header = {
		"format": "SDDV",
		"version": FORMAT_VERSION,
		"key_encryption": KEY_ENCRYPTION,
		"key_id_algorithm": KEY_ID_ALGORITHM
	}
	payload = encrypt_bytes(
		plaintext, _payload_password(file_key),
		extra_aad=_canonical_aad(header, entries)
	)
	return {"header": header, "recipients": entries, "payload": payload}


def hybrid_decrypt_bytes(container, private_key):
	"""Return plaintext only after the file key is recovered and D2 verifies the payload."""
	header, recipients, payload = _validate_container(container)
	validate_private_key(private_key)
	key_id = public_key_fingerprint(private_key)
	entry = next((item for item in recipients if item["key_id"] == key_id), None)
	if entry is None:
		raise VaultError(NO_ENTRY)
	file_key = _unwrap_file_key(entry, private_key)
	try:
		return decrypt_bytes(
			payload, _payload_password(file_key),
			extra_aad=_canonical_aad(header, recipients)
		)
	except VaultError:
		# The payload structure was validated above, so this is an authentication failure.
		raise VaultError(AUTH_FAILED) from None


# ===== File operations =====
def _read_container(path):
	if path.stat().st_size > MAX_CONTAINER_SIZE:
		raise VaultError("Encrypted container exceeds the size limit.")
	try:
		return json.loads(path.read_text(encoding="utf-8"),
			object_pairs_hook=_reject_duplicate_keys,
			parse_constant=_reject_nonjson_constant)
	except (UnicodeError, ValueError, json.JSONDecodeError):
		raise VaultError("Invalid encrypted container.") from None


def hybrid_encrypt_file(input_path, output_path, recipients):
	source, target = Path(input_path), Path(output_path)
	_check_paths(source, target)
	if source.stat().st_size > MAX_FILE_SIZE:
		raise VaultError("Input file exceeds the 10 MiB limit.")
	container = hybrid_encrypt_bytes(source.read_bytes(), recipients)
	encoded = (json.dumps(container, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
	_safe_write_new(target, encoded)
	return target


def hybrid_decrypt_file(input_path, output_path, private_key):
	source, target = Path(input_path), Path(output_path)
	_check_paths(source, target)
	plaintext = hybrid_decrypt_bytes(_read_container(source), private_key)
	# No plaintext is created until all authentication checks have passed.
	_safe_write_new(target, plaintext)
	return target


def inspect_container(path):
	"""Return public metadata of a container without any key material.

	The values are read from the file as stored and are not authenticated.
	"""
	source = Path(path)
	if not source.is_file():
		raise VaultError("Input file does not exist.")
	header, recipients, payload = _validate_container(_read_container(source))
	return {
		"version": header["version"],
		"created_utc": payload["header"]["created_utc"],
		"algorithm": payload["header"]["algorithm"],
		"key_encryption": header["key_encryption"],
		"recipients": [(item["id"], item["key_id"]) for item in recipients]
	}


# ===== Command line interface =====
def _prompt_new_passphrase():
	passphrase = getpass.getpass("New private key passphrase: ")
	if passphrase != getpass.getpass("Confirm passphrase: "):
		raise VaultError("Passphrases do not match.")
	return passphrase


def _build_parser():
	common = argparse.ArgumentParser(add_help=False)
	common.add_argument("--keys-dir", default=DEFAULT_KEYS_DIR,
		help=f"Key directory (default: {DEFAULT_KEYS_DIR})")
	parser = argparse.ArgumentParser(description="Multi-recipient hybrid document vault (D3)")
	sub = parser.add_subparsers(dest="command", required=True)
	item = sub.add_parser("keygen", parents=[common], help="Create an Ed25519 key pair")
	item.add_argument("name")
	sub.add_parser("list-keys", parents=[common], help="List stored public keys")
	item = sub.add_parser("fingerprint", parents=[common], help="Show a key ID")
	item.add_argument("name")
	item = sub.add_parser("import-public", parents=[common], help="Add a public key")
	item.add_argument("name")
	item.add_argument("file", help="Path of the PEM public key")
	item = sub.add_parser("encrypt", parents=[common], help="Encrypt for recipients")
	item.add_argument("input")
	item.add_argument("--to", action="append", required=True, metavar="NAME",
		help="Recipient name (repeat for several recipients)")
	item.add_argument("--out", required=True, help="Path for the NEW container")
	item = sub.add_parser("decrypt", parents=[common], help="Decrypt as a recipient")
	item.add_argument("input")
	item.add_argument("--as", dest="user", required=True, metavar="NAME",
		help="Name of your own key pair")
	item.add_argument("--out", required=True, help="Path for the NEW output file")
	item = sub.add_parser("inspect", help="Show public container metadata")
	item.add_argument("input")
	return parser


def _run(args):
	store = KeyStore(getattr(args, "keys_dir", DEFAULT_KEYS_DIR))
	if args.command == "keygen":
		fingerprint = store.create_key_pair(args.name, _prompt_new_passphrase())
		print(f"Key pair '{args.name}' created in {store.directory}\nKey ID: {fingerprint}")
	elif args.command == "list-keys":
		for name, fingerprint, has_private in store.list_keys():
			print(f"{name}\t{'private+public' if has_private else 'public only'}\t{fingerprint}")
	elif args.command == "fingerprint":
		print(public_key_fingerprint(store.load_public(args.name)))
	elif args.command == "import-public":
		path = Path(args.file)
		if not path.is_file():
			raise VaultError("Public key file does not exist.")
		if path.stat().st_size > MAX_KEY_FILE_SIZE:
			raise VaultError("Key file exceeds the size limit.")
		print(f"Imported '{args.name}'\nKey ID: {store.import_public(args.name, path.read_bytes())}")
		print("Verify this Key ID with the key owner through a separate trusted channel.")
	elif args.command == "encrypt":
		recipients = [(name, store.load_public(name)) for name in args.to]
		result = hybrid_encrypt_file(args.input, args.out, recipients)
		print(f"Success: {result}")
		for name, key in recipients:
			print(f"  recipient {name}: {public_key_fingerprint(key)}")
	elif args.command == "decrypt":
		private_key = store.load_private(args.user, getpass.getpass("Private key passphrase: "))
		print(f"Success: {hybrid_decrypt_file(args.input, args.out, private_key)}")
	elif args.command == "inspect":
		info = inspect_container(args.input)
		print(f"version {info['version']}, created {info['created_utc']}, "
			f"{info['algorithm']} + {info['key_encryption']}")
		for identifier, key_id in info["recipients"]:
			print(f"  recipient {identifier}: {key_id}")


def main(argv=None):
	parser = _build_parser()
	args = parser.parse_args(argv)
	try:
		_run(args)
	except (VaultError, OSError) as exc:
		parser.exit(status=1, message=f"Error: {exc}\n")


if __name__ == "__main__":
	main()
