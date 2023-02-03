from encryption import *

import unittest

class TestEncryption(unittest.TestCase):
    def setUp(self) -> None:
        self.session_key = get_session_key()
        self.private_key, self.public_key = generate_keys()
        self.enc_session_key = encrypt_session_key(self.public_key, self.session_key)
        return super().setUp()
    
    def test_server(self):
        message = b"Hello, Request from Client"
        ciphertext = encrypt_AES(self.session_key, message)
        plaintext = decrypt_AES(self.session_key, ciphertext).decode()
        self.assertEqual(str(plaintext), "Hello, Request from Client")
    
    def test_client(self):
        message = b"Response from server"
        session_key = decrypt_session_key(self.private_key, self.enc_session_key)
        ciphertext = encrypt_AES(session_key,message)
        plaintext = decrypt_AES(session_key,ciphertext).decode()
        self.assertEqual(str(plaintext), "Response from server")


if __name__=='__main__':
    unittest.main()