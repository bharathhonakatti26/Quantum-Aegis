import oqs


class KyberKeyExchange:
    def __init__(self, mechanism: str = "Kyber768"):
        self.mechanism = mechanism
        self.public_key = None
        self.private_key = None

    def generate_keypair(self):
        kem = oqs.KeyEncapsulation(self.mechanism)
        gen = kem.generate_keypair()

        # normalize returned values: some bindings return (pub, priv), some return pub only
        if isinstance(gen, (tuple, list)):
            if len(gen) >= 2:
                pub, priv = gen[0], gen[1]
            else:
                pub = gen[0]
                priv = None
        else:
            pub = gen
            priv = None

        # try to get secret key from kem instance if not returned directly
        if priv is None:
            if hasattr(kem, "secret_key") and kem.secret_key is not None:
                priv = kem.secret_key
            elif hasattr(kem, "export_secret_key"):
                try:
                    priv = kem.export_secret_key()
                except Exception:
                    priv = None

        self.public_key = pub
        self.private_key = priv
        return pub, priv

    def encapsulate(self, peer_public_key: bytes):
        kem = oqs.KeyEncapsulation(self.mechanism)
        res = kem.encap_secret(peer_public_key)
        if isinstance(res, (tuple, list)):
            return res[0], res[1]
        # assume single return is ciphertext and shared secret may be retrievable elsewhere
        return res, None

    def decapsulate(self, ciphertext: bytes):
        kem = oqs.KeyEncapsulation(self.mechanism)

        # Must provide kem with the secret key via its internal attribute for this binding
        if self.private_key is None:
            raise ValueError("No private key available — call generate_keypair() first.")

        # attach the private key to the kem instance so decap_secret() can use it
        try:
            kem.secret_key = self.private_key
        except Exception:
            # if assignment fails, try export/import style if available
            if hasattr(kem, "import_secret_key"):
                try:
                    kem.import_secret_key(self.private_key)
                except Exception as e:
                    raise ValueError("Unable to attach secret key to KEM instance") from e
            else:
                raise ValueError("Unable to attach secret key to KEM instance")

        # use the single-arg API which reads kem.secret_key
        try:
            return kem.decap_secret(ciphertext)
        except Exception as e:
            raise RuntimeError("decap_secret failed") from e
