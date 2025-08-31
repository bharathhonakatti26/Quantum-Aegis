import oqs


class DilithiumSignature:
    def __init__(self, mechanism: str = "Dilithium3"):
        self.mechanism = mechanism
        self.public_key = None
        self.private_key = None

    def generate_keypair(self):
        sig = oqs.Signature(self.mechanism)
        gen = sig.generate_keypair()

        if isinstance(gen, (tuple, list)):
            if len(gen) >= 2:
                pub, priv = gen[0], gen[1]
            else:
                pub = gen[0]
                priv = None
        else:
            pub = gen
            priv = None

        # try to export secret key if not returned directly
        if priv is None and hasattr(sig, "export_secret_key"):
            try:
                priv = sig.export_secret_key()
            except Exception:
                priv = None

        self.public_key = pub
        self.private_key = priv
        return pub, priv

    def sign(self, message: bytes):
        if self.private_key is None:
            raise ValueError("No private key available — call generate_keypair() first.")
        sig = oqs.Signature(self.mechanism)

        # Attach the private key to the Signature instance so single-arg API can use it
        try:
            sig.secret_key = self.private_key
        except Exception:
            # fallback to import API if available
            if hasattr(sig, "import_secret_key"):
                try:
                    sig.import_secret_key(self.private_key)
                except Exception as e:
                    raise ValueError("Unable to attach secret key to Signature instance") from e
            else:
                raise ValueError("Unable to attach secret key to Signature instance")

        # Call single-arg sign which reads sig.secret_key
        try:
            return sig.sign(message)
        except TypeError:
            # fallback: if a two-arg API exists, call with explicit private key
            return sig.sign(message, self.private_key)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        sig = oqs.Signature(self.mechanism)
        try:
            return sig.verify(message, signature, public_key)
        except Exception:
            return False
