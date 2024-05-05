import os
import random 

class Cipher:
    class XOR:
        
        @staticmethod
        def encryptBytes(data:bytes,key:str):
            """
            Encrypts a bytes object using XOR encryption.

            Args:
                data (bytes): The data to be encrypted.
                key (str): The key for XOR encryption.

            Returns:
                bytes: The encrypted data.
            """
            encrypted_data = bytes([(data[i] + ord(key[i % len(key)])) % 256 for i in range(len(data))])
            return encrypted_data

        @staticmethod
        def decryptBytes(encrypted_data:bytes,key:str):
            """
            Decrypts a bytes object using XOR decryption.

            Args:
                encrypted_data (bytes): The data to be decrypted.
                key (str): The key for XOR decryption.

            Returns:
                bytes: The decrypted data.
            """
            decrypted_data = bytes([(encrypted_data[i] - ord(key[i % len(key)])) % 256 for i in range(len(encrypted_data))])
            return decrypted_data


    class RSA:

        # RSA functions
        @staticmethod
        def gcd(a, b):
            """
            Computes the greatest common divisor of two numbers using Euclid's algorithm.

            Args:
                a (int): The first number.
                b (int): The second number.

            Returns:
                int: The greatest common divisor.
            """
            while b != 0:
                a, b = b, a % b
            return a

        @staticmethod
        def mod_inverse(a, m):
            """
            Computes the modular multiplicative inverse of a number.

            Args:
                a (int): The number.
                m (int): The modulus.

            Returns:
                int: The modular multiplicative inverse.
            """
            m0, x0, x1 = m, 0, 1
            while a > 1:
                q = a // m
                m, a = a % m, m
                x0, x1 = x1 - q * x0, x0
            return x1 + m0 if x1 < 0 else x1
        
        @staticmethod
        def is_prime(n):
            """
            Checks if a number is prime.

            Args:
                n (int): The number to be checked.

            Returns:
                bool: True if the number is prime, False otherwise.
            """
            if n <= 1:
                return False
            if n <= 3:
                return True
            if n % 2 == 0 or n % 3 == 0:
                return False
            i = 5
            while i * i <= n:
                if n % i == 0 or n % (i + 2) == 0:
                    return False
                i += 6
            return True

        @staticmethod
        def generate_keypair(min_modulus, max_modulus):
            """
            Generates an RSA key pair.

            Args:
                min_modulus (int): The minimum value for the modulus.
                max_modulus (int): The maximum value for the modulus.

            Returns:
                tuple: A tuple containing public and private keys.
            """
            p = random.randint(min_modulus, max_modulus)
            q = random.randint(min_modulus, max_modulus)
            while not Cipher.RSA.is_prime(p):
                p = random.randint(min_modulus, max_modulus)
            while not Cipher.RSA.is_prime(q) or q == p:
                q = random.randint(min_modulus, max_modulus)
            n = p * q
            phi = (p - 1) * (q - 1)
            e = random.randint(2, phi - 1)
            while Cipher.RSA.gcd(e, phi) != 1:
                e = random.randint(2, phi - 1)
            d = Cipher.RSA.mod_inverse(e, phi)
            return ((e, n), (d, n))

        @staticmethod
        def encrypt_RSA(message, public_key):
            """
            Encrypts a message using RSA encryption.

            Args:
                message (str): The message to be encrypted.
                public_key (tuple): The public key for RSA encryption.

            Returns:
                list: The encrypted message.
            """
            e, n = public_key   
            encrypted = [pow(ord(char), e, n) for char in message]
            return encrypted

        @staticmethod
        def decrypt_RSA(encrypted, private_key):
            """
            Decrypts a message using RSA decryption.

            Args:
                encrypted (list): The encrypted message.
                private_key (tuple): The private key for RSA decryption.

            Returns:
                str: The decrypted message.
            """
            d, n = private_key
            decrypted = ''.join([chr(pow(char, d, n)) for char in encrypted])
            return decrypted
        
    class Base64:
        @staticmethod
        def encode(data: bytes) -> str:
            """
            Encodes bytes into a Base64 string.

            Args:
                data (bytes): The data to be encoded.

            Returns:
                str: The Base64 encoded string.
            """
            base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            encoded = ""
            padding = len(data) % 3

            for i in range(0, len(data), 3):
                triple = data[i:i+3]
                buffer = int.from_bytes(triple, 'big')

                for j in range(18, -1, -6):
                    encoded += base64_chars[(buffer >> j) & 0x3F]

            if padding == 1:
                encoded = encoded[:-2] + "=="
            elif padding == 2:
                encoded = encoded[:-1] + "="

            return encoded

        @staticmethod
        def decode(data: str) -> bytes:
            """
            Decodes a Base64 string into bytes.

            Args:
                data (str): The Base64 encoded string.

            Returns:
                bytes: The decoded bytes.
            """
            base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            base64_index = {char: index for index, char in enumerate(base64_chars)}
            decoded = bytearray()
            data = data.rstrip("=")
            padding = 4 - len(data) % 4 if len(data) % 4 != 0 else 0
            data += "A" * padding

            for i in range(0, len(data), 4):
                quartet = data[i:i+4]
                buffer = sum(base64_index[char] << 6 * (3 - j) for j, char in enumerate(quartet))
                triple = buffer.to_bytes(3, 'big')
                decoded.extend(triple)

            return bytes(decoded[:len(decoded)-padding])