"""D6 - Five required key management tests plus recovery safety checks."""

import base64
import contextlib
import io
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import vault_signed
import vault_hybrid
from vault_crypto import VaultError
from vault_keys import (
	KEY_PROTECTION_PARAMS, KeyStore, export_public_pem, generate_key_pair,
	public_key_fingerprint,
)


PASSPHRASE = "Course-Project-Secure-Passphrase-2026!"


class KeyManagementD6Tests(unittest.TestCase):
	def setUp(self):
		self.temp = tempfile.TemporaryDirectory()
		self.addCleanup(self.temp.cleanup)
		self.folder = Path(self.temp.name)
		self.store = KeyStore(self.folder / "original")
		self.fingerprint = self.store.create_key_pair("alice", PASSPHRASE)

	def test_01_correct_password_grants_access(self):
		"""REQUIRED: The correct password unlocks the matching private key."""
		key = self.store.load_private("alice", PASSPHRASE)
		self.assertEqual(public_key_fingerprint(key), self.fingerprint)

	def test_02_wrong_password_denies_access(self):
		"""REQUIRED: A wrong password does not expose the private key."""
		with self.assertRaises(VaultError):
			self.store.load_private("alice", "incorrect-password-2026")

	def test_03_modified_keystore_is_rejected(self):
		"""REQUIRED: Tampering with the encrypted GCM authentication tag fails."""
		path = self.store._path("alice", "private")
		lines = path.read_bytes().splitlines()
		der = bytearray(base64.b64decode(b"".join(lines[1:-1])))
		der[-1] ^= 1
		encoded = base64.b64encode(der)
		path.write_bytes(b"\n".join([lines[0]] +
			[encoded[i:i + 64] for i in range(0, len(encoded), 64)] +
			[lines[-1], b""]))
		with self.assertRaises(VaultError):
			self.store.load_private("alice", PASSPHRASE)

	def test_04_encrypted_backup_restores_access(self):
		"""REQUIRED: An encrypted backup restores the same key identity."""
		backup = self.folder / "alice-backup.private.pem"
		self.store.backup_private("alice", backup)
		self.assertIn(b"BEGIN ENCRYPTED PRIVATE KEY", backup.read_bytes())
		if os.name != "nt":
			self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
		restored = KeyStore(self.folder / "restored")
		self.assertEqual(restored.restore_private("alice", backup, PASSPHRASE), self.fingerprint)
		self.assertEqual(public_key_fingerprint(restored.load_private("alice", PASSPHRASE)), self.fingerprint)
		container = vault_hybrid.hybrid_encrypt_bytes(
			b"Recovered document", [("alice", self.store.load_public("alice"))])
		self.assertEqual(vault_hybrid.hybrid_decrypt_bytes(
			container, restored.load_private("alice", PASSPHRASE)), b"Recovered document")

	def test_05_stolen_keystore_alone_cannot_decrypt(self):
		"""REQUIRED: Files alone, without the password, cannot recover content."""
		stolen = KeyStore(self.folder / "stolen")
		stolen.directory.mkdir()
		for kind in ("private", "public"):
			shutil.copy2(self.store._path("alice", kind), stolen._path("alice", kind))
		with self.assertRaises(VaultError):
			stolen.load_private("alice", "attacker-guess-2026")
		container = vault_hybrid.hybrid_encrypt_bytes(
			b"Sensitive file", [("alice", self.store.load_public("alice"))])
		with self.assertRaises(VaultError):
			vault_hybrid.hybrid_decrypt_bytes(container, stolen.load_public("alice"))

	def test_06_restore_wrong_password_does_not_create_keys(self):
		backup = self.folder / "encrypted-backup.pem"
		self.store.backup_private("alice", backup)
		restored = KeyStore(self.folder / "restored")
		with self.assertRaises(VaultError):
			restored.restore_private("alice", backup, "incorrect-password-2026")
		self.assertFalse(restored.directory.exists())

	def test_07_restore_does_not_replace_another_identity(self):
		backup = self.folder / "encrypted-backup.pem"
		self.store.backup_private("alice", backup)
		restored = KeyStore(self.folder / "restored")
		restored.import_public("alice", export_public_pem(generate_key_pair()))
		with self.assertRaises(VaultError):
			restored.restore_private("alice", backup, PASSPHRASE)
		self.assertFalse(restored._path("alice", "private").exists())

	def test_08_existing_private_key_and_backup_are_not_overwritten(self):
		backup = self.folder / "encrypted-backup.pem"
		self.store.backup_private("alice", backup)
		before = backup.read_bytes()
		with self.assertRaises(VaultError):
			self.store.backup_private("alice", backup)
		self.assertEqual(backup.read_bytes(), before)
		with self.assertRaises(VaultError):
			self.store.restore_private("alice", backup, PASSPHRASE)

	def test_09_legacy_cbc_backup_is_restored_as_authenticated_gcm(self):
		key = self.store.load_private("alice", PASSPHRASE)
		legacy = key.export_key(format="PEM", passphrase=PASSPHRASE,
			protection="scryptAndAES256-CBC", prot_params=KEY_PROTECTION_PARAMS).encode("ascii")
		backup = self.folder / "old-d5.private.pem"
		backup.write_bytes(legacy)
		restored = KeyStore(self.folder / "restored")
		self.assertEqual(restored.restore_private("alice", backup, PASSPHRASE), self.fingerprint)
		self.assertNotEqual(restored._path("alice", "private").read_bytes(), legacy)
		self.assertEqual(public_key_fingerprint(restored.load_private("alice", PASSPHRASE)), self.fingerprint)

	def test_10_cli_backup_restore_and_fingerprint(self):
		backup = self.folder / "backup.private.pem"
		restored = KeyStore(self.folder / "cli_restored")
		with patch.object(vault_signed.getpass, "getpass", return_value=PASSPHRASE):
			with contextlib.redirect_stdout(io.StringIO()):
				vault_signed.main(["backup-key", "alice", "--out", str(backup),
					"--keys-dir", str(self.store.directory)])
				vault_signed.main(["restore-key", "alice", str(backup),
					"--keys-dir", str(restored.directory)])
		self.assertEqual(public_key_fingerprint(restored.load_private("alice", PASSPHRASE)), self.fingerprint)


if __name__ == "__main__":
	unittest.main()
