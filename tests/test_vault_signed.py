"""D5 signature acceptance and rejection tests."""

# >>>>>>>>>> Libraries <<<<<<<<<<
import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import vault_signed as signed
from vault_crypto import VaultError, _b64, _unb64
from vault_keys import generate_key_pair


# >>>>>>>>>> Signature tests <<<<<<<<<<
class SignatureTests(unittest.TestCase):
    def __str__(self):
        number = self._testMethodName.split("_")[1]
        if number in ("01", "02", "03", "04", "05"):
            return f"REQUIRED_TEST_{number} ({type(self).__module__}.{type(self).__name__})"
        return super().__str__()

    def run(self, result=None):
        stream = getattr(result, "stream", None)
        if stream is not None:
            stream.write("\n")
        return super().run(result)

    @classmethod
    def setUpClass(cls):
        cls.alice = generate_key_pair()
        cls.bob = generate_key_pair()
        cls.mallory = generate_key_pair()
        cls.document = b"Signed cryptography project document.\n"
        cls.container = signed.signed_encrypt_bytes(
            cls.document, [("bob", cls.bob.public_key())], cls.alice)

    def assertRejectedBeforeDecrypt(self, container, public_key=None):
        with patch("vault_hybrid.hybrid_decrypt_bytes") as decrypt:
            with self.assertRaises(VaultError):
                signed.signed_decrypt_bytes(
                    container, self.bob, public_key or self.alice.public_key())
            decrypt.assert_not_called()

    def test_01_valid_signature_is_accepted(self):
        """ACCEPTED: Alice's signature is valid and Bob recovers the original document."""
        plaintext = signed.signed_decrypt_bytes(
            self.container, self.bob, self.alice.public_key())
        self.assertEqual(plaintext, self.document)

    def test_02_modified_ciphertext_is_rejected(self):
        """REJECTED: A changed ciphertext byte fails verification before decryption."""
        container = copy.deepcopy(self.container)
        ciphertext = bytearray(_unb64(container["payload"]["ciphertext"], "ciphertext"))
        ciphertext[0] ^= 1
        container["payload"]["ciphertext"] = _b64(ciphertext)
        self.assertRejectedBeforeDecrypt(container)

    def test_03_modified_metadata_is_rejected(self):
        """REJECTED: Changes to headers, recipient data, nonce or tag invalidate the signature."""
        changes = [
            ("metadata", "signature_algorithm", "other"),
            ("header", "key_encryption", "other"),
            ("payload", "nonce", _b64(bytes(12))),
            ("payload", "authentication_tag", _b64(bytes(16))),
        ]
        for field, name, value in changes:
            with self.subTest(field=field, name=name):
                container = copy.deepcopy(self.container)
                container[field][name] = value
                self.assertRejectedBeforeDecrypt(container)
        container = copy.deepcopy(self.container)
        container["payload"]["header"]["created_utc"] = "2026-01-01T00:00:00Z"
        self.assertRejectedBeforeDecrypt(container)
        for name, value in (("id", "mallory"), ("key_id", "0" * 64),
                            ("encrypted_key", _b64(bytes(96)))):
            with self.subTest(recipient_field=name):
                container = copy.deepcopy(self.container)
                container["recipients"][0][name] = value
                self.assertRejectedBeforeDecrypt(container)

    def test_04_wrong_public_key_is_rejected(self):
        """REJECTED: A different sender's public key cannot verify Alice's container."""
        self.assertRejectedBeforeDecrypt(self.container, self.mallory.public_key())

    def test_05_removed_signature_is_rejected(self):
        """REJECTED: A container without a signature never reaches decryption."""
        container = copy.deepcopy(self.container)
        del container["signature"]
        self.assertRejectedBeforeDecrypt(container)

    def test_06_forged_signature_and_signer_id_are_rejected(self):
        """REJECTED: Replacing the signature or claiming another signer fails verification."""
        container = copy.deepcopy(self.container)
        container["signature"] = _b64(bytes(64))
        self.assertRejectedBeforeDecrypt(container)
        container = copy.deepcopy(self.container)
        container["signer_id"] = signed.public_key_fingerprint(self.mallory)
        self.assertRejectedBeforeDecrypt(container, self.mallory.public_key())
        forged = signed.sign_container(
            {k: self.container[k] for k in ("header", "recipients", "payload")}, self.mallory)
        self.assertRejectedBeforeDecrypt(forged)

    def test_07_unsigned_d3_container_is_rejected(self):
        """REJECTED: D5 does not accept an unsigned D3 container."""
        unsigned = {k: self.container[k] for k in ("header", "recipients", "payload")}
        self.assertRejectedBeforeDecrypt(unsigned)

    def test_08_rejection_does_not_create_plaintext(self):
        """REJECTED: An invalid signature leaves no recovered plaintext file."""
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory, "forged.sddv"), Path(directory, "recovered.txt")
            container = copy.deepcopy(self.container)
            container["signature"] = _b64(bytes(64))
            source.write_text(json.dumps(container), encoding="utf-8")
            with self.assertRaises(VaultError):
                signed.signed_decrypt_file(source, output, self.bob, self.alice.public_key())
            self.assertFalse(output.exists())

    def test_09_file_round_trip_and_no_overwrite(self):
        """ACCEPTED: File encryption and verified decryption work; existing output is preserved."""
        with tempfile.TemporaryDirectory() as directory:
            source, encrypted, output = [Path(directory, name)
                                        for name in ("input.txt", "signed.sddv", "output.txt")]
            source.write_bytes(self.document)
            signed.signed_encrypt_file(source, encrypted, [("bob", self.bob.public_key())], self.alice)
            signed.signed_decrypt_file(encrypted, output, self.bob, self.alice.public_key())
            self.assertEqual(output.read_bytes(), self.document)
            with self.assertRaises(VaultError):
                signed.signed_decrypt_file(encrypted, output, self.bob, self.alice.public_key())
            self.assertEqual(output.read_bytes(), self.document)

    def test_10_cli_verifies_before_requesting_private_key(self):
        """REJECTED: The CLI rejects a forged file before requesting the recipient's passphrase."""
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "forged.sddv")
            container = copy.deepcopy(self.container)
            container["signature"] = _b64(bytes(64))
            source.write_text(json.dumps(container), encoding="utf-8")
            with patch.object(signed.KeyStore, "load_public", return_value=self.alice.public_key()), \
                    patch.object(signed.getpass, "getpass") as prompt, \
                    patch("sys.stderr", new_callable=io.StringIO) as error:
                with self.assertRaises(SystemExit) as raised:
                    signed.main(["decrypt", str(source), "--as", "bob", "--signer", "alice",
                                 "--out", str(Path(directory, "output.txt"))])
                self.assertEqual(raised.exception.code, 1)
                self.assertIn("REJECTED", error.getvalue())
                prompt.assert_not_called()

    def test_11_cli_encrypt_inspect_and_decrypt(self):
        """ACCEPTED: CLI encrypts, verifies the sender, inspects recipients and recovers the file."""
        with tempfile.TemporaryDirectory() as directory:
            source, encrypted, output = [Path(directory, name)
                                        for name in ("input.txt", "signed.sddv", "output.txt")]
            source.write_bytes(self.document)
            with patch.object(signed.KeyStore, "load_public", side_effect=lambda name:
                              self.alice.public_key() if name == "alice" else self.bob.public_key()), \
                    patch.object(signed.KeyStore, "load_private", side_effect=lambda name, password:
                                 self.alice if name == "alice" else self.bob), \
                    patch.object(signed.getpass, "getpass", return_value="test passphrase"), \
                    redirect_stdout(io.StringIO()) as messages:
                signed.main(["encrypt", str(source), "--to", "bob", "--signer", "alice", "--out", str(encrypted)])
                signed.main(["inspect", str(encrypted), "--signer", "alice"])
                signed.main(["decrypt", str(encrypted), "--as", "bob", "--signer", "alice", "--out", str(output)])
                self.assertIn("VERIFIED: Signature matches sender 'alice'", messages.getvalue())
                self.assertIn("Recipient: bob", messages.getvalue())
                self.assertEqual(output.read_bytes(), self.document)

    def test_12_recipient_list_changes_are_rejected(self):
        """REJECTED: Adding, removing or reordering recipients invalidates the signature."""
        original = signed.signed_encrypt_bytes(
            self.document, [("alice", self.alice.public_key()),
                            ("bob", self.bob.public_key())], self.alice)
        for action in ("add", "remove", "reorder"):
            with self.subTest(action=action):
                container = copy.deepcopy(original)
                if action == "add":
                    container["recipients"].append(dict(container["recipients"][0]))
                elif action == "remove":
                    container["recipients"].pop()
                else:
                    container["recipients"].reverse()
                self.assertRejectedBeforeDecrypt(container)

    def test_13_malformed_signatures_and_extra_fields_are_rejected(self):
        """REJECTED: Invalid signature encodings, wrong sizes and extra fields are refused."""
        for value in ("not base64!", _b64(bytes(63)), None):
            with self.subTest(signature=value):
                container = copy.deepcopy(self.container)
                container["signature"] = value
                self.assertRejectedBeforeDecrypt(container)
        container = copy.deepcopy(self.container)
        container["unsigned_note"] = "untrusted addition"
        self.assertRejectedBeforeDecrypt(container)


if __name__ == "__main__":
    unittest.main(verbosity=2)
