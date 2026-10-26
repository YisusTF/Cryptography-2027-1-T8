"""Unit tests for key management (D3). Run: python -m unittest discover -s tests -v"""

import os
import tempfile
import unittest
from pathlib import Path

from Crypto.PublicKey import RSA

from vault_crypto import VaultError
from vault_keys import (
	KEY_BITS, KeyStore, export_private_pem, export_public_pem, generate_key_pair,
	import_private_pem, import_public_pem, public_key_fingerprint, validate_name
)

PASSPHRASE = "Correct-Horse-Battery-42!"
WRONG_PASSPHRASE = "Wrong-Passphrase-1234!"


class KeyManagementTests(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.key = generate_key_pair(2048)
		cls.other = generate_key_pair(2048)

	def test_01_default_key_size_and_fingerprint_format(self):
		key = generate_key_pair()
		self.assertEqual(key.size_in_bits(), KEY_BITS)
		fingerprint = public_key_fingerprint(key)
		self.assertRegex(fingerprint, r"^[0-9a-f]{64}$")

	def test_02_fingerprint_is_deterministic_and_unique(self):
		reloaded = import_public_pem(export_public_pem(self.key))
		self.assertEqual(public_key_fingerprint(self.key), public_key_fingerprint(reloaded))
		self.assertEqual(public_key_fingerprint(self.key),
			public_key_fingerprint(self.key.publickey()))
		self.assertNotEqual(public_key_fingerprint(self.key), public_key_fingerprint(self.other))

	def test_03_private_key_pem_is_encrypted_and_round_trips(self):
		pem = export_private_pem(self.key, PASSPHRASE)
		self.assertTrue(pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))
		restored = import_private_pem(pem, PASSPHRASE)
		self.assertEqual(public_key_fingerprint(restored), public_key_fingerprint(self.key))

	def test_04_wrong_or_short_passphrase_is_rejected(self):
		pem = export_private_pem(self.key, PASSPHRASE)
		with self.assertRaises(VaultError):
			import_private_pem(pem, WRONG_PASSPHRASE)
		with self.assertRaises(VaultError):
			export_private_pem(self.key, "short")

	def test_05_unencrypted_private_key_is_rejected(self):
		with self.assertRaises(VaultError):
			import_private_pem(self.key.export_key(format="PEM"), PASSPHRASE)

	def test_06_private_key_is_not_accepted_as_public_key(self):
		with self.assertRaises(VaultError):
			import_public_pem(self.key.export_key(format="PEM"))

	def test_07_weak_or_malformed_public_keys_are_rejected(self):
		with self.assertRaises(VaultError):
			import_public_pem(RSA.generate(1024).publickey().export_key(format="PEM"))
		with self.assertRaises(VaultError):
			import_public_pem(b"not a key")

	def test_08_unsafe_names_are_rejected(self):
		for name in ("../evil", "a/b", "", "a" * 33, "bad name", "x.y"):
			with self.subTest(name=name), self.assertRaises(VaultError):
				validate_name(name)


class KeyStoreTests(unittest.TestCase):
	def test_01_create_load_and_list(self):
		with tempfile.TemporaryDirectory() as directory:
			store = KeyStore(Path(directory) / "keys")
			fingerprint = store.create_key_pair("alice", PASSPHRASE, bits=2048)
			self.assertEqual(public_key_fingerprint(store.load_public("alice")), fingerprint)
			private = store.load_private("alice", PASSPHRASE)
			self.assertEqual(public_key_fingerprint(private), fingerprint)
			self.assertEqual(store.list_keys(), [("alice", fingerprint, True)])

	@unittest.skipIf(os.name == "nt", "POSIX permissions are not available on Windows")
	def test_02_private_key_file_is_owner_only(self):
		with tempfile.TemporaryDirectory() as directory:
			store = KeyStore(directory)
			store.create_key_pair("alice", PASSPHRASE, bits=2048)
			mode = (Path(directory) / "alice.private.pem").stat().st_mode & 0o777
			self.assertEqual(mode, 0o600)

	def test_03_existing_key_is_never_overwritten(self):
		with tempfile.TemporaryDirectory() as directory:
			store = KeyStore(directory)
			store.create_key_pair("alice", PASSPHRASE, bits=2048)
			before = (Path(directory) / "alice.private.pem").read_bytes()
			with self.assertRaises(VaultError):
				store.create_key_pair("alice", PASSPHRASE, bits=2048)
			self.assertEqual((Path(directory) / "alice.private.pem").read_bytes(), before)

	def test_04_missing_key_and_wrong_passphrase(self):
		with tempfile.TemporaryDirectory() as directory:
			store = KeyStore(directory)
			store.create_key_pair("alice", PASSPHRASE, bits=2048)
			with self.assertRaises(VaultError):
				store.load_public("nobody")
			with self.assertRaises(VaultError):
				store.load_private("alice", WRONG_PASSPHRASE)

	def test_05_import_public_key_from_another_user(self):
		with tempfile.TemporaryDirectory() as directory:
			store = KeyStore(directory)
			foreign = generate_key_pair(2048)
			fingerprint = store.import_public("bob", export_public_pem(foreign))
			self.assertEqual(fingerprint, public_key_fingerprint(foreign))
			self.assertEqual(store.list_keys(), [("bob", fingerprint, False)])
			with self.assertRaises(VaultError):
				store.import_public("bob", export_public_pem(foreign))


if __name__ == "__main__":
	unittest.main()
