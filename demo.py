from key_exchange import KyberKeyExchange
from signature import DilithiumSignature
from encryption import AES256GCM
from hashing import SHA3Hash

# Key Exchange Demo
print("--- Kyber Key Exchange ---")
kyber = KyberKeyExchange()
pub_key, priv_key = kyber.generate_keypair()
ciphertext, shared_secret = kyber.encapsulate(pub_key)
received_secret = kyber.decapsulate(ciphertext)
print(f"Shared secret: {shared_secret.hex()}")

# Signature Demo
print("\n--- Dilithium Signature ---")
dilithium = DilithiumSignature()
sig_pub, sig_priv = dilithium.generate_keypair()
message = b"Quantum Aegis secure message"
signature = dilithium.sign(message)
valid = dilithium.verify(message, signature, sig_pub)
print(f"Signature valid: {valid}")

# AES-256-GCM Encryption Demo
print("\n--- AES-256-GCM Encryption ---")
aes = AES256GCM()
nonce, ciphertext = aes.encrypt(message)
decrypted = aes.decrypt(nonce, ciphertext)
print(f"Decrypted message: {decrypted.decode()}")

# SHA3-256 Hashing Demo
print("\n--- SHA3-256 Hashing ---")
digest = SHA3Hash.hash(message)
print(f"SHA3-256 digest: {digest.hex()}")
