"""D3 - Key management for the Secure Digital Document Vault.
"""

import hashlib
import os
import re
from pathlib import Path

from Crypto.PublicKey import RSA

from vault_crypto import VaultError


# ===== Constants =====
KEY_BITS = 3072
ALLOWED_KEY_BITS = (2048, 3072, 4096)
PUBLIC_EXPONENT = 65537
MIN_PASSPHRASE_LENGTH = 12
MAX_KEY_FILE_SIZE = 64 * 1024
NAME_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,32}")
PRIVATE_PEM_HEADER = b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
KEY_PROTECTION = "scryptAndAES256-CBC"
KEY_PROTECTION_PARAMS = {
	"iteration_count": 2**15, "salt_size": 16, "block_size": 8, "parallelization": 1
}


# ===== Validation helpers =====
def validate_name(name):
	"""Names are restricted so they cannot alter the key file path."""
	if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
		raise VaultError("Invalid name: use 1-32 letters, digits, '_' or '-'.")
	return name


def _check_passphrase(passphrase):
	if not isinstance(passphrase, str) or len(passphrase) < MIN_PASSPHRASE_LENGTH:
		raise VaultError("Passphrase must contain at least 12 characters.")


def validate_public_key(key):
	"""Accept only RSA public keys with an approved size and exponent."""
	if not isinstance(key, RSA.RsaKey) or key.has_private():
		raise VaultError("A valid RSA public key is required.")
	if key.size_in_bits() not in ALLOWED_KEY_BITS or key.e != PUBLIC_EXPONENT:
		raise VaultError("Unsupported public key: RSA 2048, 3072 or 4096 bits required.")
	return key


def validate_private_key(key):
	if not isinstance(key, RSA.RsaKey) or not key.has_private():
		raise VaultError("A valid RSA private key is required.")
	validate_public_key(key.publickey())
	return key


# ===== Key generation and identification =====
def generate_key_pair(bits=KEY_BITS):
	if bits not in ALLOWED_KEY_BITS:
		raise VaultError("Key size must be 2048, 3072 or 4096 bits.")
	return RSA.generate(bits)


def public_key_fingerprint(key):
	"""Key ID: SHA-256 of the DER SubjectPublicKeyInfo, as lowercase hex."""
	return hashlib.sha256(key.publickey().export_key(format="DER")).hexdigest()


# ===== PEM import and export =====
def export_private_pem(key, passphrase):
	_check_passphrase(passphrase)
	return key.export_key(
		format="PEM", passphrase=passphrase, pkcs=8,
		protection=KEY_PROTECTION, prot_params=KEY_PROTECTION_PARAMS
	)


def export_public_pem(key):
	return key.publickey().export_key(format="PEM")


def import_private_pem(data, passphrase):
	if not isinstance(data, bytes) or not data.lstrip().startswith(PRIVATE_PEM_HEADER):
		raise VaultError("The file is not a password-protected private key.")
	try:
		key = RSA.import_key(data, passphrase=passphrase)
	except (ValueError, IndexError, TypeError):
		raise VaultError("Could not open the private key: wrong passphrase or damaged file.") from None
	return validate_private_key(key)


def import_public_pem(data):
	if not isinstance(data, bytes) or len(data) > MAX_KEY_FILE_SIZE:
		raise VaultError("Invalid public key file.")
	try:
		key = RSA.import_key(data)
	except (ValueError, IndexError, TypeError):
		raise VaultError("Invalid public key file.") from None
	return validate_public_key(key)


# ===== File helpers =====
def _write_new(path, data, mode):
	"""Create a new file exclusively; an existing file is never replaced."""
	flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
	try:
		descriptor = os.open(path, flags, mode)
	except FileExistsError:
		raise VaultError(f"File already exists: {path.name}") from None
	with os.fdopen(descriptor, "wb") as output:
		output.write(data)


def _read_key_file(path):
	if not path.is_file():
		raise VaultError(f"Key file not found: {path.name}")
	if path.stat().st_size > MAX_KEY_FILE_SIZE:
		raise VaultError("Key file exceeds the size limit.")
	return path.read_bytes()


# ===== Key store =====
class KeyStore:
	"""Directory holding <name>.private.pem and <name>.public.pem files."""

	def __init__(self, directory):
		self.directory = Path(directory)

	def _path(self, name, kind):
		return self.directory / f"{validate_name(name)}.{kind}.pem"

	def create_key_pair(self, name, passphrase, bits=KEY_BITS):
		private_path, public_path = self._path(name, "private"), self._path(name, "public")
		_check_passphrase(passphrase)
		if private_path.exists() or public_path.exists():
			raise VaultError(f"A key named '{name}' already exists.")
		key = generate_key_pair(bits)
		private_pem = export_private_pem(key, passphrase)
		self.directory.mkdir(parents=True, exist_ok=True)
		_write_new(private_path, private_pem, 0o600)
		try:
			_write_new(public_path, export_public_pem(key) + b"\n", 0o644)
		except Exception:
			private_path.unlink(missing_ok=True)
			raise
		return public_key_fingerprint(key)

	def load_public(self, name):
		return import_public_pem(_read_key_file(self._path(name, "public")))

	def load_private(self, name, passphrase):
		return import_private_pem(_read_key_file(self._path(name, "private")), passphrase)

	def import_public(self, name, pem_data):
		"""Register another user's public key after validating it."""
		key = import_public_pem(pem_data)
		self.directory.mkdir(parents=True, exist_ok=True)
		_write_new(self._path(name, "public"), export_public_pem(key) + b"\n", 0o644)
		return public_key_fingerprint(key)

	def list_keys(self):
		"""Return (name, fingerprint, has_private_key) for each stored public key."""
		if not self.directory.is_dir():
			return []
		entries = []
		for path in sorted(self.directory.glob("*.public.pem")):
			name = path.name[: -len(".public.pem")]
			if not NAME_PATTERN.fullmatch(name):
				continue
			key = import_public_pem(_read_key_file(path))
			has_private = self._path(name, "private").is_file()
			entries.append((name, public_key_fingerprint(key), has_private))
		return entries
