"""D2 - Secure Digital Document Vault, single-owner AES-256-GCM module.

Python 3.10+; only external dependency: pycryptodome.
Every encryption generates a fresh 256-bit data-encryption key (DEK).
The DEK is wrapped using a password-derived key; it is never saved in plaintext.
"""

import argparse
import base64
import binascii
import getpass
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes


# All parameters below are fixed by format version 1, not controlled by input.
MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_CONTAINER_SIZE = 20 * 1024 * 1024
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
EXPECTED_OUTER = {"header", "nonce", "ciphertext", "authentication_tag"}
EXPECTED_HEADER = {
	"format", "version", "algorithm", "key_wrap", "kdf", "kdf_params",
	"salt", "wrapped_key", "created_utc"
}


class VaultError(Exception):
	"""Expected invalid input or failed authentication (generic external error)."""


def _canonical_header(header):
	"""Canonical UTF-8 JSON is authenticated as additional authenticated data."""
	return b"SDDV|v1|" + json.dumps(
		header, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
		allow_nan=False
	).encode("ascii")


def _b64(data):
	return base64.b64encode(data).decode("ascii")


def _unb64(value, field, expected_size=None):
	if not isinstance(value, str):
		raise VaultError("Invalid encrypted container.")
	try:
		data = base64.b64decode(value, validate=True)
	except (binascii.Error, ValueError):
		raise VaultError("Invalid encrypted container.") from None
	if _b64(data) != value or (expected_size is not None and len(data) != expected_size):
		raise VaultError("Invalid encrypted container.")
	return data


def _derive_key(password, salt):
	if not isinstance(password, str) or len(password) < 12:
		raise VaultError("Password must contain at least 12 characters.")
	return scrypt(password.encode("utf-8"), salt, KEY_SIZE,
		N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)


def _validate_container(container):
	"""Reject malformed/unknown fields before expensive password derivation."""
	if not isinstance(container, dict) or set(container) != EXPECTED_OUTER:
		raise VaultError("Invalid encrypted container.")
	header = container["header"]
	if not isinstance(header, dict) or set(header) != EXPECTED_HEADER:
		raise VaultError("Invalid encrypted container.")
	if (header["format"] != "SDDV" or type(header["version"]) is not int
		or header["version"] != 1 or header["algorithm"] != "AES-256-GCM"
		or header["key_wrap"] != "AES-256-KW" or header["kdf"] != "scrypt"
		or header["kdf_params"] != {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P}):
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
	_unb64(header["salt"], "salt", SALT_SIZE)
	_unb64(header["wrapped_key"], "wrapped_key", KEY_SIZE + 8)
	_unb64(container["nonce"], "nonce", NONCE_SIZE)
	_unb64(container["authentication_tag"], "authentication_tag", TAG_SIZE)
	if len(_unb64(container["ciphertext"], "ciphertext")) > MAX_FILE_SIZE:
		raise VaultError("Encrypted file exceeds the 10 MiB limit.")
	return header


def encrypt_bytes(plaintext, password):
	"""Return a JSON-serializable authenticated encrypted container."""
	if not isinstance(plaintext, bytes):
		raise VaultError("Input content must be bytes.")
	if len(plaintext) > MAX_FILE_SIZE:
		raise VaultError("Input file exceeds the 10 MiB limit.")
	# Generate all secrets/nonces from the OS-backed CSPRNG; never seed manually.
	dek = get_random_bytes(KEY_SIZE)
	salt = get_random_bytes(SALT_SIZE)
	nonce = get_random_bytes(NONCE_SIZE)
	kek = _derive_key(password, salt)
	header = {
		"format": "SDDV",
		"version": 1,
		"algorithm": "AES-256-GCM",
		"key_wrap": "AES-256-KW",
		"kdf": "scrypt",
		"kdf_params": {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
		"salt": _b64(salt),
		"wrapped_key": _b64(AES.new(kek, AES.MODE_KW).seal(dek)),
		"created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
	}
	cipher = AES.new(dek, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
	cipher.update(_canonical_header(header))
	ciphertext, tag = cipher.encrypt_and_digest(plaintext)
	return {
		"header": header,
		"nonce": _b64(nonce),
		"ciphertext": _b64(ciphertext),
		"authentication_tag": _b64(tag)
	}


def decrypt_bytes(container, password):
	"""Only returns plaintext after key unwrap and AEAD tag verification succeed."""
	header = _validate_container(container)
	kek = _derive_key(password, _unb64(header["salt"], "salt", SALT_SIZE))
	try:
		dek = AES.new(kek, AES.MODE_KW).unseal(
			_unb64(header["wrapped_key"], "wrapped_key", KEY_SIZE + 8)
		)
		cipher = AES.new(dek, AES.MODE_GCM,
			nonce=_unb64(container["nonce"], "nonce", NONCE_SIZE), mac_len=TAG_SIZE)
		cipher.update(_canonical_header(header))
		return cipher.decrypt_and_verify(
			_unb64(container["ciphertext"], "ciphertext"),
			_unb64(container["authentication_tag"], "authentication_tag", TAG_SIZE)
		)
	except ValueError:
		# Wrong password and failed GCM tag get the same message.
		raise VaultError("Authentication failed: wrong password or modified container.") from None


def _reject_duplicate_keys(pairs):
	result = {}
	for key, value in pairs:
		if key in result:
			raise VaultError("Invalid encrypted container: duplicate fields.")
		result[key] = value
	return result


def _reject_nonjson_constant(value):
	raise VaultError("Invalid encrypted container.")


def _safe_write_new(path, data):
	"""Never overwrite files; remove a partial output if writing fails."""
	created = False
	try:
		with path.open("xb") as output:
			created = True
			output.write(data)
	except Exception:
		if created:
			try:
				path.unlink()
			except OSError:
				pass
		raise


def _check_paths(source, target):
	if not source.is_file():
		raise VaultError("Input file does not exist.")
	if source.resolve() == target.resolve():
		raise VaultError("Input and output must be different files.")
	if target.exists():
		raise VaultError("Output already exists; choose another name.")
	if not target.parent.is_dir():
		raise VaultError("Output directory does not exist.")


def encrypt_file(input_path, output_path, password):
	source, target = Path(input_path), Path(output_path)
	_check_paths(source, target)
	if source.stat().st_size > MAX_FILE_SIZE:
		raise VaultError("Input file exceeds the 10 MiB limit.")
	container = encrypt_bytes(source.read_bytes(), password)
	encoded = (json.dumps(container, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
	_safe_write_new(target, encoded)
	return target


def decrypt_file(input_path, output_path, password):
	source, target = Path(input_path), Path(output_path)
	_check_paths(source, target)
	if source.stat().st_size > MAX_CONTAINER_SIZE:
		raise VaultError("Encrypted container exceeds the size limit.")
	try:
		container = json.loads(source.read_text(encoding="utf-8"),
			object_pairs_hook=_reject_duplicate_keys,
			parse_constant=_reject_nonjson_constant)
	except (UnicodeError, ValueError, json.JSONDecodeError):
		raise VaultError("Invalid encrypted container.") from None
	plaintext = decrypt_bytes(container, password)
	# No plaintext is created until all authentication checks have passed.
	_safe_write_new(target, plaintext)
	return target


def main():
	parser = argparse.ArgumentParser(description="Single-owner AES-256-GCM document vault (D2)")
	sub = parser.add_subparsers(dest="command", required=True)
	for command in ("encrypt", "decrypt"):
		item = sub.add_parser(command)
		item.add_argument("input", help="Path of the source file")
		item.add_argument("--out", required=True, help="Path for the NEW output file")
	args = parser.parse_args()
	try:
		password = getpass.getpass("Vault password: ")
		if args.command == "encrypt":
			confirm = getpass.getpass("Confirm password: ")
			if password != confirm:
				raise VaultError("Passwords do not match.")
			result = encrypt_file(args.input, args.out, password)
		else:
			result = decrypt_file(args.input, args.out, password)
		print(f"Success: {result}")
	except (VaultError, OSError) as exc:
		parser.exit(status=1, message=f"Error: {exc}\n")


if __name__ == "__main__":
	main()
