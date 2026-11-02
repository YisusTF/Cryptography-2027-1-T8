import copy
import tempfile
import unittest
from pathlib import Path

import vault_hybrid as hybrid
from vault_crypto import VaultError
from vault_keys import KeyStore

PASSPHRASE = "correct horse battery"
DOCUMENT = b"Confidential project document.\n" * 100


class TestVaultHybrid(unittest.TestCase):
	"""Keys are generated once because key export and scrypt are slow."""

	@classmethod
	def setUpClass(cls):
		keys_dir = tempfile.TemporaryDirectory()
		cls.addClassCleanup(keys_dir.cleanup)
		cls.store = KeyStore(keys_dir.name)
		names = ("alice", "bob", "carol")
		for name in names:
			cls.store.create_key_pair(name, PASSPHRASE)
		cls.public = {n: cls.store.load_public(n) for n in names}
		cls.private = {n: cls.store.load_private(n, PASSPHRASE) for n in names}
		cls.container = hybrid.hybrid_encrypt_bytes(
			DOCUMENT, [("alice", cls.public["alice"]), ("bob", cls.public["bob"])]
		)

	def tampered(self, change):
		container = copy.deepcopy(self.container)
		change(container)
		return container

	def assertDecryptFails(self, container, user, message):
		with self.assertRaises(VaultError) as raised:
			hybrid.hybrid_decrypt_bytes(container, self.private[user])
		self.assertEqual(str(raised.exception), message)

	def test_both_recipients_can_decrypt(self):
		for user in ("alice", "bob"):
			with self.subTest(user=user):
				plaintext = hybrid.hybrid_decrypt_bytes(self.container, self.private[user])
				self.assertEqual(plaintext, DOCUMENT)

	def test_unauthorized_user_cannot_decrypt(self):
		self.assertDecryptFails(self.container, "carol", hybrid.NO_ENTRY)
		with tempfile.TemporaryDirectory() as work:
			source, encrypted = Path(work, "doc.bin"), Path(work, "doc.sddv")
			output = Path(work, "carol.bin")
			source.write_bytes(DOCUMENT)
			hybrid.hybrid_encrypt_file(
				source, encrypted,
				[("alice", self.public["alice"]), ("bob", self.public["bob"])]
			)
			with self.assertRaises(VaultError):
				hybrid.hybrid_decrypt_file(encrypted, output, self.private["carol"])
			self.assertFalse(output.exists())

	def test_tampered_recipient_list_fails(self):
		def reorder(c):
			c["recipients"].reverse()

		def rename(c):
			c["recipients"][0]["id"] = "mallory"

		def swap_ids(c):
			first, second = c["recipients"]
			first["id"], second["id"] = second["id"], first["id"]

		def swap_key_ids(c):
			first, second = c["recipients"]
			first["key_id"], second["key_id"] = second["key_id"], first["key_id"]

		def add_recipient(c):
			c["recipients"].append(hybrid.hybrid_encrypt_bytes(
				b"other", [("carol", self.public["carol"])]
			)["recipients"][0])

		def corrupt_key(c):
			entry = c["recipients"][0]
			tail = "AAAA" if entry["encrypted_key"][-4:] != "AAAA" else "BBBB"
			entry["encrypted_key"] = entry["encrypted_key"][:-4] + tail

		changes = (reorder, rename, swap_ids, swap_key_ids, add_recipient, corrupt_key)
		for change in changes:
			for user in ("alice", "bob"):
				with self.subTest(change=change.__name__, user=user):
					self.assertDecryptFails(self.tampered(change), user, hybrid.AUTH_FAILED)

	def test_wrong_passphrase_cannot_load_private_key(self):
		with self.assertRaises(VaultError):
			self.store.load_private("alice", "not the right passphrase")

	def test_entry_encrypted_for_another_key_fails(self):
		def use_bobs_encrypted_key(c):
			alice, bob = c["recipients"]
			alice["encrypted_key"] = bob["encrypted_key"]

		self.assertDecryptFails(self.tampered(use_bobs_encrypted_key), "alice", hybrid.AUTH_FAILED)

	def test_removed_recipient_loses_access(self):
		container = self.tampered(lambda c: c["recipients"].pop(1))
		self.assertDecryptFails(container, "bob", hybrid.NO_ENTRY)

	def test_remaining_recipient_fails_after_removal(self):
		container = self.tampered(lambda c: c["recipients"].pop(1))
		self.assertDecryptFails(container, "alice", hybrid.AUTH_FAILED)


if __name__ == "__main__":
	unittest.main()
