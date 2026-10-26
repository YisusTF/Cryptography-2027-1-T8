"""D3 - Hybrid multi-recipient encryption for the Secure Digital Document Vault.

Python 3.10+; only external dependency: pycryptodome.
The document is encrypted once with AES-256-GCM under a random file key.
The file key is then encrypted separately for each recipient with RSA-OAEP
(SHA-256). The recipient list and all algorithm identifiers are authenticated
as additional authenticated data (AAD).
Container format version 2; D2 containers (version 1) remain in vault_crypto.py.
"""

import argparse
import getpass
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

from vault_crypto import (
	KEY_SIZE, MAX_CONTAINER_SIZE, MAX_FILE_SIZE, NONCE_SIZE, TAG_SIZE, VaultError,
	_b64, _check_paths, _reject_duplicate_keys, _reject_nonjson_constant,
	_safe_write_new, _unb64
)
from vault_keys import (
	ALLOWED_KEY_BITS, KEY_BITS, NAME_PATTERN, KeyStore, public_key_fingerprint,
	validate_name, validate_private_key, validate_public_key
)


# ===== Constants =====
FORMAT_VERSION = 2
ALGORITHM = "AES-256-GCM"
KEY_ENCRYPTION = "RSA-OAEP-SHA256"
KEY_ID_ALGORITHM = "SHA-256-SPKI-DER"
MAX_RECIPIENTS = 16
ENCRYPTED_KEY_SIZES = tuple(bits // 8 for bits in ALLOWED_KEY_BITS)
KEY_ID_PATTERN = re.compile(r"[0-9a-f]{64}")
DEFAULT_KEYS_DIR = "vault_keys"
EXPECTED_OUTER = {"header", "recipients", "nonce", "ciphertext", "authentication_tag"}
EXPECTED_V1_OUTER = {"header", "nonce", "ciphertext", "authentication_tag"}
EXPECTED_HEADER = {
	"format", "version", "algorithm", "key_encryption", "key_id_algorithm", "created_utc"
}
EXPECTED_ENTRY = {"id", "key_id", "encrypted_key"}
AUTH_FAILED = "Authentication failed: wrong key or modified container."
NO_ENTRY = "Access denied: the container has no entry for the supplied key."


# ===== Authenticated data and key encryption =====
def _canonical_aad(header, recipients):
	"""Header and the ordered recipient list, serialized deterministically."""
	return b"SDDV|v2|" + json.dumps(
		{"header": header, "recipients": recipients}, sort_keys=True,
		separators=(",", ":"), ensure_ascii=True, allow_nan=False
	).encode("ascii")


def _oaep(key, key_id, nonce):
	"""RSA-OAEP bound to the recipient key ID and the container nonce."""
	label = b"SDDV|v2|file-key|" + key_id.encode("ascii") + b"|" + nonce
	return PKCS1_OAEP.new(key, hashAlgo=SHA256, label=label)


def _unwrap_file_key(entry, private_key, nonce):
	try:
		file_key = _oaep(private_key, entry["key_id"], nonce).decrypt(
			_unb64(entry["encrypted_key"], "encrypted_key")
		)
	except ValueError:
		raise VaultError(AUTH_FAILED) from None
	if len(file_key) != KEY_SIZE:
		raise VaultError(AUTH_FAILED)
	return file_key


# ===== Container validation =====
def _validate_container(container):
	"""Reject malformed or unknown structure before any private-key operation."""
	if (isinstance(container, dict) and set(container) == EXPECTED_V1_OUTER
		and isinstance(container["header"], dict)
		and container["header"].get("version") == 1):
		raise VaultError("Version 1 (password) container: use vault_crypto.py to decrypt it.")
	if not isinstance(container, dict) or set(container) != EXPECTED_OUTER:
		raise VaultError("Invalid encrypted container.")
	header, recipients = container["header"], container["recipients"]
	if not isinstance(header, dict) or set(header) != EXPECTED_HEADER:
		raise VaultError("Invalid encrypted container.")
	if (header["format"] != "SDDV" or type(header["version"]) is not int
		or header["version"] != FORMAT_VERSION or header["algorithm"] != ALGORITHM
		or header["key_encryption"] != KEY_ENCRYPTION
		or header["key_id_algorithm"] != KEY_ID_ALGORITHM):
		raise VaultError("Unsupported or invalid encrypted container.")
	created = header["created_utc"]
	if not isinstance(created, str) or not re.fullmatch(
		r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", created
	):
		raise VaultError("Invalid encrypted container.")
	try:
		datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ")
	except ValueError:
		raise VaultError("Invalid encrypted container.") from None
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
		if len(_unb64(entry["encrypted_key"], "encrypted_key")) not in ENCRYPTED_KEY_SIZES:
			raise VaultError("Invalid encrypted container: recipient entry.")
	_unb64(container["nonce"], "nonce", NONCE_SIZE)
	_unb64(container["authentication_tag"], "authentication_tag", TAG_SIZE)
	if len(_unb64(container["ciphertext"], "ciphertext")) > MAX_FILE_SIZE:
		raise VaultError("Encrypted file exceeds the 10 MiB limit.")
	return header, recipients


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
	# Fresh file key and nonce from the OS-backed CSPRNG for every container.
	file_key = get_random_bytes(KEY_SIZE)
	nonce = get_random_bytes(NONCE_SIZE)
	entries = [
		{
			"id": identifier,
			"key_id": key_id,
			"encrypted_key": _b64(_oaep(public_key, key_id, nonce).encrypt(file_key))
		}
		for identifier, key_id, public_key in prepared
	]
	header = {
		"format": "SDDV",
		"version": FORMAT_VERSION,
		"algorithm": ALGORITHM,
		"key_encryption": KEY_ENCRYPTION,
		"key_id_algorithm": KEY_ID_ALGORITHM,
		"created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
	}
	cipher = AES.new(file_key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
	cipher.update(_canonical_aad(header, entries))
	ciphertext, tag = cipher.encrypt_and_digest(plaintext)
	return {
		"header": header,
		"recipients": entries,
		"nonce": _b64(nonce),
		"ciphertext": _b64(ciphertext),
		"authentication_tag": _b64(tag)
	}


def hybrid_decrypt_bytes(container, private_key):
	"""Return plaintext only after key decryption and GCM verification succeed."""
	header, recipients = _validate_container(container)
	validate_private_key(private_key)
	key_id = public_key_fingerprint(private_key)
	entry = next((item for item in recipients if item["key_id"] == key_id), None)
	if entry is None:
		raise VaultError(NO_ENTRY)
	nonce = _unb64(container["nonce"], "nonce", NONCE_SIZE)
	file_key = _unwrap_file_key(entry, private_key, nonce)
	try:
		cipher = AES.new(file_key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
		cipher.update(_canonical_aad(header, recipients))
		return cipher.decrypt_and_verify(
			_unb64(container["ciphertext"], "ciphertext"),
			_unb64(container["authentication_tag"], "authentication_tag", TAG_SIZE)
		)
	except ValueError:
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
	"""Return public metadata of a container without any key material."""
	source = Path(path)
	if not source.is_file():
		raise VaultError("Input file does not exist.")
	header, recipients = _validate_container(_read_container(source))
	return {
		"version": header["version"],
		"created_utc": header["created_utc"],
		"algorithm": header["algorithm"],
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
	item = sub.add_parser("keygen", parents=[common], help="Create an RSA key pair")
	item.add_argument("name")
	item.add_argument("--bits", type=int, default=KEY_BITS, choices=ALLOWED_KEY_BITS)
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
		fingerprint = store.create_key_pair(args.name, _prompt_new_passphrase(), args.bits)
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
		if path.stat().st_size > 64 * 1024:
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
