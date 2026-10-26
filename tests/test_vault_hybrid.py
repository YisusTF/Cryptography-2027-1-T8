"""Unit tests for hybrid multi-recipient encryption (D3).
Run: python -m unittest discover -s tests -v
"""

import base64
import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from Crypto.Random import get_random_bytes

import vault_hybrid as vh
from vault_crypto import VaultError, decrypt_bytes, encrypt_bytes
from vault_keys import KeyStore, generate_key_pair, public_key_fingerprint

PLAINTEXT = b"Secure Digital Document Vault\x00\x01\xff\n"
PASSPHRASE = "Correct-Horse-Battery-42!"


def _flip(value):
	"""Return a Base64 string whose first byte differs from the input."""
	data = bytearray(base64.b64decode(value))
	data[0] ^= 1
	return base64.b64encode(data).decode("ascii")


class HybridTestCase(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.keys = {name: generate_key_pair(2048) for name in ("Alice", "Bob", "Carol", "Mallory")}

	def setUp(self):
		self.container = vh.hybrid_encrypt_bytes(PLAINTEXT, [
			("Alice", self.keys["Alice"].publickey()),
			("Bob", self.keys["Bob"].publickey()),
		])

	def decrypt_as(self, container, name):
		return vh.hybrid_decrypt_bytes(container, self.keys[name])


class RequiredScenarioTests(HybridTestCase):
	def test_01_file_shared_with_two_users_both_can_decrypt(self):
		self.assertEqual(self.decrypt_as(self.container, "Alice"), PLAINTEXT)
		self.assertEqual(self.decrypt_as(self.container, "Bob"), PLAINTEXT)

	def test_01b_three_recipients_all_decrypt_the_same_ciphertext(self):
		container = vh.hybrid_encrypt_bytes(PLAINTEXT, [
			(name, self.keys[name].publickey()) for name in ("Alice", "Bob", "Carol")
		])
		self.assertEqual(len(container["recipients"]), 3)
		for name in ("Alice", "Bob", "Carol"):
			self.assertEqual(self.decrypt_as(container, name), PLAINTEXT)

	def test_02_unauthorized_user_cannot_decrypt(self):
		for name in ("Mallory", "Carol"):
			with self.subTest(user=name), self.assertRaisesRegex(VaultError, "Access denied"):
				self.decrypt_as(self.container, name)

	def test_03_tampered_recipient_list_fails(self):
		def change_label(c): c["recipients"][0]["id"] = "Eve"
		def swap_labels(c):
			first, second = c["recipients"][0], c["recipients"][1]
			first["id"], second["id"] = second["id"], first["id"]
		def reorder(c): c["recipients"].reverse()
		def change_wrapped_key(c): c["recipients"][1]["encrypted_key"] = _flip(c["recipients"][1]["encrypted_key"])
		def add_attacker_entry(c):
			public = self.keys["Mallory"].publickey()
			c["recipients"].append({
				"id": "Mallory",
				"key_id": public_key_fingerprint(public),
				"encrypted_key": base64.b64encode(get_random_bytes(256)).decode("ascii")
			})
		def replace_key_id(c): c["recipients"][1]["key_id"] = public_key_fingerprint(self.keys["Mallory"])
		attacks = (change_label, swap_labels, reorder, change_wrapped_key,
			add_attacker_entry, replace_key_id)
		for attack in attacks:
			for user in ("Alice", "Bob"):
				with self.subTest(attack=attack.__name__, user=user):
					bad = copy.deepcopy(self.container)
					attack(bad)
					with self.assertRaises(VaultError):
						self.decrypt_as(bad, user)

	def test_03b_label_and_entry_changes_fail_authentication_for_untouched_recipient(self):
		bad = copy.deepcopy(self.container)
		bad["recipients"][1]["id"] = "Eve"
		with self.assertRaisesRegex(VaultError, "Authentication failed"):
			self.decrypt_as(bad, "Alice")

	def test_04_wrong_private_key_fails(self):
		with self.assertRaises(VaultError):
			self.decrypt_as(self.container, "Mallory")
		# A key that is located but cannot open the entry must also fail.
		entry = self.container["recipients"][0]
		nonce = base64.b64decode(self.container["nonce"])
		with self.assertRaisesRegex(VaultError, "Authentication failed"):
			vh._unwrap_file_key(entry, self.keys["Mallory"], nonce)
		with self.assertRaisesRegex(VaultError, "Authentication failed"):
			vh._unwrap_file_key(entry, self.keys["Bob"], nonce)

	def test_05_removing_a_recipient_entry_breaks_access(self):
		bad = copy.deepcopy(self.container)
		del bad["recipients"][1]
		with self.assertRaisesRegex(VaultError, "Access denied"):
			self.decrypt_as(bad, "Bob")
		with self.assertRaisesRegex(VaultError, "Authentication failed"):
			self.decrypt_as(bad, "Alice")

	def test_05b_removing_every_entry_is_rejected(self):
		bad = copy.deepcopy(self.container)
		bad["recipients"] = []
		with self.assertRaises(VaultError):
			self.decrypt_as(bad, "Alice")


class IntegrityTests(HybridTestCase):
	def test_06_modified_ciphertext_nonce_tag_or_header_fails(self):
		for field in ("ciphertext", "nonce", "authentication_tag"):
			with self.subTest(field=field):
				bad = copy.deepcopy(self.container)
				bad[field] = _flip(bad[field])
				with self.assertRaisesRegex(VaultError, "Authentication failed"):
					self.decrypt_as(bad, "Alice")
		bad = copy.deepcopy(self.container)
		bad["header"]["created_utc"] = "2020-01-01T00:00:00Z"
		with self.assertRaisesRegex(VaultError, "Authentication failed"):
			self.decrypt_as(bad, "Alice")

	def test_07_algorithm_identifiers_cannot_be_changed(self):
		for field, value in (("algorithm", "AES-128-GCM"), ("key_encryption", "RSA-PKCS1-V1_5"),
			("key_id_algorithm", "MD5"), ("version", 3), ("format", "OTHER")):
			with self.subTest(field=field):
				bad = copy.deepcopy(self.container)
				bad["header"][field] = value
				with self.assertRaises(VaultError):
					self.decrypt_as(bad, "Alice")

	def test_08_repeated_encryption_uses_new_key_nonce_and_entries(self):
		second = vh.hybrid_encrypt_bytes(PLAINTEXT, [
			("Alice", self.keys["Alice"].publickey()),
			("Bob", self.keys["Bob"].publickey()),
		])
		self.assertNotEqual(self.container["nonce"], second["nonce"])
		self.assertNotEqual(self.container["ciphertext"], second["ciphertext"])
		for first_entry, second_entry in zip(self.container["recipients"], second["recipients"]):
			self.assertNotEqual(first_entry["encrypted_key"], second_entry["encrypted_key"])
		keys = []
		for container in (self.container, second):
			keys.append(vh._unwrap_file_key(container["recipients"][0], self.keys["Alice"],
				base64.b64decode(container["nonce"])))
		self.assertNotEqual(keys[0], keys[1])

	def test_09_encrypted_key_is_bound_to_container_nonce(self):
		entry = self.container["recipients"][0]
		other_nonce = get_random_bytes(12)
		with self.assertRaisesRegex(VaultError, "Authentication failed"):
			vh._unwrap_file_key(entry, self.keys["Alice"], other_nonce)

	def test_10_container_contains_neither_plaintext_nor_private_data(self):
		text = json.dumps(self.container)
		self.assertNotIn(base64.b64encode(PLAINTEXT).decode("ascii"), text)
		self.assertNotIn("PRIVATE", text)
		self.assertEqual(set(self.container), vh.EXPECTED_OUTER)

	def test_11_file_key_is_small_and_only_it_is_public_key_encrypted(self):
		for entry in self.container["recipients"]:
			self.assertEqual(len(base64.b64decode(entry["encrypted_key"])), 256)
		big = vh.hybrid_encrypt_bytes(b"x" * 100000, [("Alice", self.keys["Alice"].publickey())])
		self.assertEqual(len(base64.b64decode(big["recipients"][0]["encrypted_key"])), 256)


class ValidationTests(HybridTestCase):
	def test_12_malformed_containers_are_rejected(self):
		cases = {}
		bad = copy.deepcopy(self.container); bad["extra"] = 1; cases["unknown outer field"] = bad
		bad = copy.deepcopy(self.container); bad["header"]["extra"] = 1; cases["unknown header field"] = bad
		bad = copy.deepcopy(self.container); bad["recipients"][0]["extra"] = 1; cases["unknown entry field"] = bad
		bad = copy.deepcopy(self.container); bad["recipients"][0]["encrypted_key"] = "###"; cases["bad base64"] = bad
		bad = copy.deepcopy(self.container); bad["recipients"][0]["encrypted_key"] = base64.b64encode(b"short").decode(); cases["short key"] = bad
		bad = copy.deepcopy(self.container); bad["recipients"][0]["key_id"] = "ABC"; cases["bad key id"] = bad
		bad = copy.deepcopy(self.container); bad["recipients"][0]["id"] = "../x"; cases["bad label"] = bad
		bad = copy.deepcopy(self.container); bad["recipients"][1] = copy.deepcopy(bad["recipients"][0]); cases["duplicate entry"] = bad
		bad = copy.deepcopy(self.container); bad["recipients"] = bad["recipients"] * 20; cases["too many"] = bad
		bad = copy.deepcopy(self.container); bad["recipients"] = "none"; cases["not a list"] = bad
		for label, container in cases.items():
			with self.subTest(case=label), self.assertRaises(VaultError):
				self.decrypt_as(container, "Alice")
		for value in (None, [], "text", 5):
			with self.assertRaises(VaultError):
				self.decrypt_as(value, "Alice")

	def test_13_duplicate_and_invalid_recipients_are_rejected_on_encryption(self):
		alice = self.keys["Alice"].publickey()
		for recipients in ([("Alice", alice), ("Alice", self.keys["Bob"].publickey())],
			[("Alice", alice), ("Other", alice)], [], [("bad name", alice)],
			[("Alice", self.keys["Alice"].export_key())], [("Alice", None)]):
			with self.subTest(recipients=str(recipients)[:40]), self.assertRaises(VaultError):
				vh.hybrid_encrypt_bytes(PLAINTEXT, recipients)

	def test_14_recipient_limit_is_enforced(self):
		key = self.keys["Alice"].publickey()
		with self.assertRaises(VaultError):
			vh.hybrid_encrypt_bytes(PLAINTEXT, [(f"user{i}", key) for i in range(17)])

	def test_15_empty_and_large_inputs(self):
		container = vh.hybrid_encrypt_bytes(b"", [("Alice", self.keys["Alice"].publickey())])
		self.assertEqual(self.decrypt_as(container, "Alice"), b"")
		with self.assertRaises(VaultError):
			vh.hybrid_encrypt_bytes(b"x" * (vh.MAX_FILE_SIZE + 1),
				[("Alice", self.keys["Alice"].publickey())])

	def test_16_private_key_is_required_for_decryption(self):
		with self.assertRaises(VaultError):
			vh.hybrid_decrypt_bytes(self.container, self.keys["Alice"].publickey())

	def test_17_d2_and_d3_containers_are_not_interchangeable(self):
		d2 = encrypt_bytes(PLAINTEXT, PASSPHRASE)
		with self.assertRaisesRegex(VaultError, "Version 1"):
			self.decrypt_as(d2, "Alice")
		with self.assertRaises(VaultError):
			decrypt_bytes(self.container, PASSPHRASE)
		self.assertEqual(decrypt_bytes(d2, PASSPHRASE), PLAINTEXT)


class FileTests(HybridTestCase):
	def test_18_file_round_trip_for_each_recipient(self):
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			original, container = root / "input.bin", root / "shared.sddv"
			original.write_bytes(PLAINTEXT)
			vh.hybrid_encrypt_file(original, container, [
				("Alice", self.keys["Alice"].publickey()),
				("Bob", self.keys["Bob"].publickey())])
			for name in ("Alice", "Bob"):
				restored = root / f"{name}.out"
				vh.hybrid_decrypt_file(container, restored, self.keys[name])
				self.assertEqual(restored.read_bytes(), PLAINTEXT)

	def test_19_failed_decryption_writes_no_plaintext_file(self):
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			container = root / "shared.sddv"
			container.write_text(json.dumps(self.container), encoding="utf-8")
			for name in ("Mallory", "Carol"):
				output = root / f"{name}.out"
				with self.assertRaises(VaultError):
					vh.hybrid_decrypt_file(container, output, self.keys[name])
				self.assertFalse(output.exists())
			tampered = copy.deepcopy(self.container)
			tampered["recipients"].reverse()
			container.write_text(json.dumps(tampered), encoding="utf-8")
			output = root / "tampered.out"
			with self.assertRaises(VaultError):
				vh.hybrid_decrypt_file(container, output, self.keys["Alice"])
			self.assertFalse(output.exists())

	def test_20_existing_output_is_never_overwritten(self):
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			original, target = root / "original.txt", root / "existing.sddv"
			original.write_bytes(PLAINTEXT)
			target.write_text("KEEP", encoding="utf-8")
			with self.assertRaises(VaultError):
				vh.hybrid_encrypt_file(original, target, [("Alice", self.keys["Alice"].publickey())])
			self.assertEqual(target.read_text(encoding="utf-8"), "KEEP")

	def test_21_malformed_json_and_duplicate_fields_are_rejected(self):
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			for index, text in enumerate(('{"header": "unterminated"', '{"nonce":"a","nonce":"b"}', "NaN")):
				source, output = root / f"bad{index}.sddv", root / f"leak{index}.txt"
				source.write_text(text, encoding="utf-8")
				with self.subTest(text=text), self.assertRaises(VaultError):
					vh.hybrid_decrypt_file(source, output, self.keys["Alice"])
				self.assertFalse(output.exists())

	def test_22_inspect_shows_recipients_without_secrets(self):
		with tempfile.TemporaryDirectory() as directory:
			path = Path(directory) / "shared.sddv"
			path.write_text(json.dumps(self.container), encoding="utf-8")
			info = vh.inspect_container(path)
			self.assertEqual([item[0] for item in info["recipients"]], ["Alice", "Bob"])
			self.assertEqual(info["recipients"][0][1], public_key_fingerprint(self.keys["Alice"]))


class CommandLineTests(unittest.TestCase):
	def run_cli(self, *arguments, passwords=()):
		sink = io.StringIO()
		with mock.patch("getpass.getpass", side_effect=list(passwords)), \
			contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
			vh.main(list(arguments))

	def test_23_end_to_end_with_key_store(self):
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			keys = str(root / "keys")
			for name in ("alice", "bob", "mallory"):
				self.run_cli("keygen", name, "--bits", "2048", "--keys-dir", keys,
					passwords=[PASSPHRASE, PASSPHRASE])
			document = root / "document.txt"
			document.write_bytes(PLAINTEXT)
			container = root / "shared.sddv"
			self.run_cli("encrypt", str(document), "--to", "alice", "--to", "bob",
				"--out", str(container), "--keys-dir", keys)
			for name in ("alice", "bob"):
				output = root / f"{name}.txt"
				self.run_cli("decrypt", str(container), "--as", name, "--out", str(output),
					"--keys-dir", keys, passwords=[PASSPHRASE])
				self.assertEqual(output.read_bytes(), PLAINTEXT)
			denied = root / "mallory.txt"
			with self.assertRaises(SystemExit):
				self.run_cli("decrypt", str(container), "--as", "mallory", "--out", str(denied),
					"--keys-dir", keys, passwords=[PASSPHRASE])
			self.assertFalse(denied.exists())
			self.run_cli("inspect", str(container))
			self.run_cli("list-keys", "--keys-dir", keys)

	def test_24_missing_recipient_key_stops_encryption(self):
		with tempfile.TemporaryDirectory() as directory:
			root = Path(directory)
			document, container = root / "document.txt", root / "shared.sddv"
			document.write_bytes(PLAINTEXT)
			with self.assertRaises(SystemExit):
				self.run_cli("encrypt", str(document), "--to", "nobody", "--out", str(container),
					"--keys-dir", str(root / "keys"))
			self.assertFalse(container.exists())


if __name__ == "__main__":
	unittest.main()
