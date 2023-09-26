import random
import math

class MerkleHellmanKnapsack:
    def __init__(self):
        self.private_key, self.public_key, self.q, self.r = self.generate_keypair()

    def generate_superincreasing_sequence(self, length):
        sequence = [random.randint(1, 1000)]
        for _ in range(1, length):
            sequence.append(random.randint(sum(sequence) + 1, 2 * sum(sequence)))
        return sequence

    def generate_keypair(self):
        private_key = self.generate_superincreasing_sequence(128)
        q = sum(private_key) + random.randint(1, 1000)  # Choose a random value for q
        r = random.randint(2, q - 1)  # Choose a random value for r that is coprime to q
        while math.gcd(r, q) != 1:  # Check if r is coprime with q
            r = random.randint(2, q - 1)  # Choose a new value for r
        public_key = [(r * element) % q for element in private_key]
        return private_key, public_key, q, r

    def encrypt(self, plaintext):
        binary_plaintext = bin(plaintext)[2:].zfill(128)
        encrypted = sum([int(bit) * element for bit, element in zip(binary_plaintext, self.public_key)])
        return encrypted

    def decrypt(self, ciphertext):
        decrypted = []
        s = (ciphertext * pow(self.r, -1, self.q)) % self.q
        for element in reversed(self.private_key):
            if element <= s:
                decrypted.insert(0, 1)
                s -= element
            else:
                decrypted.insert(0, 0)
        decrypted_value = int(''.join(str(bit) for bit in decrypted), 2)
        return decrypted_value

