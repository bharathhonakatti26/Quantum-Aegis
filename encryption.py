from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class AES256GCM:
    def __init__(self, key=None):
        self.key = key or AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, plaintext, nonce=None, associated_data=None):
        nonce = nonce or os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext

    def decrypt(self, nonce, ciphertext, associated_data=None):
        return self.aesgcm.decrypt(nonce, ciphertext, associated_data)
