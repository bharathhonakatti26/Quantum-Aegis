from Crypto.Hash import SHA3_256

class SHA3Hash:
    @staticmethod
    def hash(data: bytes) -> bytes:
        h = SHA3_256.new()
        h.update(data)
        return h.digest()
