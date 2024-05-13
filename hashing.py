import os
import random
from datetime import datetime


class SHA256:
    # Constants for SHA-256
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    # Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19)
    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    @staticmethod
    def hash(message):
        # Padding
        ml = len(message) * 8
        message += b'\x80'
        message += b'\x00' * ((56 - len(message) % 64) % 64)
        message += ml.to_bytes(8, byteorder='big')

        # Chunking
        chunks = [message[i:i+64] for i in range(0, len(message), 64)]

        # Helper functions
        def right_rotate(x, n):
            return (x >> n) | (x << (32 - n)) & 0xFFFFFFFF

        def sigma0(x):
            return right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22)

        def sigma1(x):
            return right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25)

        def maj(x, y, z):
            return (x & y) ^ (x & z) ^ (y & z)

        def ch(x, y, z):
            return (x & y) ^ (~x & z)

        for chunk in chunks:
            w = [0] * 64
            for i in range(16):
                w[i] = int.from_bytes(chunk[i*4:i*4+4], byteorder='big')

            for i in range(16, 64):
                s0 = sigma0(w[i-15])
                s1 = sigma1(w[i-2])
                w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF

            a, b, c, d, e, f, g, h = SHA256.H

            for i in range(64):
                S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
                ch = (e & f) ^ ((~e) & g)
                temp1 = h + S1 + ch + SHA256.K[i] + w[i]
                S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = S0 + maj

                h = g
                g = f
                f = e
                e = (d + temp1) & 0xFFFFFFFF
                d = c
                c = b
                b = a
                a = (temp1 + temp2) & 0xFFFFFFFF

            SHA256.H[0] = (SHA256.H[0] + a) & 0xFFFFFFFF
            SHA256.H[1] = (SHA256.H[1] + b) & 0xFFFFFFFF
            SHA256.H[2] = (SHA256.H[2] + c) & 0xFFFFFFFF
            SHA256.H[3] = (SHA256.H[3] + d) & 0xFFFFFFFF
            SHA256.H[4] = (SHA256.H[4] + e) & 0xFFFFFFFF
            SHA256.H[5] = (SHA256.H[5] + f) & 0xFFFFFFFF
            SHA256.H[6] = (SHA256.H[6] + g) & 0xFFFFFFFF
            SHA256.H[7] = (SHA256.H[7] + h) & 0xFFFFFFFF

        # Final hash value
        hash_value = b''
        for h in SHA256.H:
            hash_value += h.to_bytes(4, byteorder='big')

        # Truncate hash value to 50 characters
        hashed_value = hash_value.hex()[:50]

        # Append timestamp and hash value to hash_log
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open("hash_log.txt", "a") as f:
            f.write(f"{timestamp}: {hashed_value}\n")

        return hashed_value


class FNV1a:
    @staticmethod
    def hash(data):
        """
        FNV-1a hash function implementation.

        Args:
            data (bytes): The data to be hashed.

        Returns:
            str: The FNV-1a hash value as a 50-character hexadecimal string.
        """
        # FNV parameters for 32-bit hash
        FNV_OFFSET_BASIS_32 = 0x811c9dc5
        FNV_PRIME_32 = 0x01000193
        
        # Initialize hash to FNV offset basis
        hash_value = FNV_OFFSET_BASIS_32
        
        # Hash each byte in the data
        for byte in data:
            hash_value ^= byte
            hash_value *= FNV_PRIME_32
            hash_value &= 0xFFFFFFFF  # Limit to 32 bits
        
        # Convert hash value to 50-character hexadecimal string
        hash_str = format(hash_value, '08X')
        hash_str = hash_str.zfill(50)
        
        return hash_str
