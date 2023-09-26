from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

class ECDSA:
    def __init__(self):
        self.private_key = ECC.generate(curve='P-256')
        self.public_key = self.private_key.public_key()

    def sign(self, message):
        hash_obj = SHA256.new(message.to_bytes((message.bit_length() + 7) // 8, 'big'))
        signer = DSS.new(self.private_key, 'fips-186-3')
        signature = signer.sign(hash_obj)
        return signature

    def verify(self, message, signature):
        hash_obj = SHA256.new(message.to_bytes((message.bit_length() + 7) // 8, 'big'))
        verifier = DSS.new(self.public_key, 'fips-186-3')
        try:
            verifier.verify(hash_obj, signature)
            return True
        except ValueError:
            return False


