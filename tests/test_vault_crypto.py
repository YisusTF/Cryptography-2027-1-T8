"""Built-in unittest suite. Run: python -m unittest discover -s tests -v"""

import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt

from vault_crypto import VaultError, decrypt_bytes, decrypt_file, encrypt_bytes, encrypt_file

PASSWORD = "Correct-Horse-Battery-42!"
WRONG_PASSWORD = "Wrong-Password-1234!"


class VaultCryptoTests(unittest.TestCase):
	def setUp(self):
		self.plaintext = b"Secure Digital Document Vault\x00\x01\xff\n"
		self.container = encrypt_bytes(self.plaintext, PASSWORD)

	def test_01_round_trip_identical_binary_file(self):
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			original, encrypted, restored = root / "input.bin", root / "input.sddv", root / "restored.bin"
			original.write_bytes(self.plaintext)
			encrypt_file(original, encrypted, PASSWORD)
			decrypt_file(encrypted, restored, PASSWORD)
			self.assertEqual(original.read_bytes(), restored.read_bytes())

	def test_02_wrong_password_fails(self):
		with self.assertRaisesRegex(VaultError, "Authentication failed"):
			decrypt_bytes(self.container, WRONG_PASSWORD)

	def test_03_modified_ciphertext_fails(self):
		bad = copy.deepcopy(self.container)
		ciphertext = bytearray(base64.b64decode(bad["ciphertext"]))
		ciphertext[0] ^= 1
		bad["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
		with self.assertRaisesRegex(VaultError, "Authentication failed"):
			decrypt_bytes(bad, PASSWORD)

	def test_04_modified_metadata_fails(self):
		bad = copy.deepcopy(self.container)
		bad["header"]["created_utc"] = "2020-01-01T00:00:00Z"
		with self.assertRaisesRegex(VaultError, "Authentication failed"):
			decrypt_bytes(bad, PASSWORD)

	def test_05_repeated_encryption_produces_different_ciphertexts(self):
		second = encrypt_bytes(self.plaintext, PASSWORD)
		self.assertNotEqual(self.container["nonce"], second["nonce"])
		self.assertNotEqual(self.container["ciphertext"], second["ciphertext"])
		self.assertNotEqual(self.container["header"]["wrapped_key"], second["header"]["wrapped_key"])
		# Explicitly prove that different random file encryption keys (DEKs) were used.
		def recover_test_dek(container):
			header = container["header"]
			kek = scrypt(PASSWORD.encode("utf-8"), base64.b64decode(header["salt"]),
				32, N=32768, r=8, p=1)
			return AES.new(kek, AES.MODE_KW).unseal(base64.b64decode(header["wrapped_key"]))
		self.assertNotEqual(recover_test_dek(self.container), recover_test_dek(second))

	def test_06_modified_nonce_or_tag_fails(self):
		for field in ("nonce", "authentication_tag"):
			with self.subTest(field=field):
				bad = copy.deepcopy(self.container)
				data = bytearray(base64.b64decode(bad[field]))
				data[0] ^= 1
				bad[field] = base64.b64encode(data).decode("ascii")
				with self.assertRaisesRegex(VaultError, "Authentication failed"):
					decrypt_bytes(bad, PASSWORD)

	def test_07_wrong_password_writes_no_plaintext_file(self):
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			container_path, output = root / "safe.sddv", root / "recovered.txt"
			container_path.write_text(json.dumps(self.container), encoding="utf-8")
			with self.assertRaises(VaultError):
				decrypt_file(container_path, output, WRONG_PASSWORD)
			self.assertFalse(output.exists())

	def test_08_reject_malformed_container_and_unknown_fields(self):
		bad = copy.deepcopy(self.container)
		bad["header"]["extra"] = "malicious"
		with self.assertRaises(VaultError):
			decrypt_bytes(bad, PASSWORD)
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			input_file, output = root / "broken.sddv", root / "leak.txt"
			input_file.write_text('{"header": "unterminated"', encoding="utf-8")
			with self.assertRaises(VaultError):
				decrypt_file(input_file, output, PASSWORD)
			self.assertFalse(output.exists())

	def test_09_reject_duplicate_json_keys(self):
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			input_file, output = root / "duplicate.sddv", root / "leak.txt"
			input_file.write_text('{"nonce":"a","nonce":"b"}', encoding="utf-8")
			with self.assertRaises(VaultError):
				decrypt_file(input_file, output, PASSWORD)
			self.assertFalse(output.exists())

	def test_10_existing_output_is_never_overwritten(self):
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			original, target = root / "original.txt", root / "existing.sddv"
			original.write_bytes(self.plaintext)
			target.write_text("KEEP", encoding="utf-8")
			with self.assertRaises(VaultError):
				encrypt_file(original, target, PASSWORD)
			self.assertEqual(target.read_text(encoding="utf-8"), "KEEP")

	def test_11_empty_file_roundtrip(self):
		empty = encrypt_bytes(b"", PASSWORD)
		self.assertEqual(decrypt_bytes(empty, PASSWORD), b"")

	def test_12_fixed_kdf_parameters_cannot_be_downgraded(self):
		bad = copy.deepcopy(self.container)
		bad["header"]["kdf_params"]["n"] = 2
		with self.assertRaises(VaultError):
			decrypt_bytes(bad, PASSWORD)


if __name__ == "__main__":
	unittest.main()
