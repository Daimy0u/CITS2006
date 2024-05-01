import os
import random 

class Cipher:
    class XOR:
        
        @staticmethod
        def encryptBytes(data:bytes,key:str):
            """
            Args: 
                data - list of characters (one char per index).
                
                key - key for XOR encryption.
            Returns: 
                encrypted_data - bytes object (encrypted)
            """
            encrypted_data = bytes([(data[i] + ord(key[i % len(key)])) % 256 for i in range(len(data))])
            return encrypted_data

        @staticmethod
        def decryptBytes(encrypted_data:bytes,key:str):
            """
            Args: 
                data - list of characters (one char per index).
                
                key - key for XOR decryption.
            Returns: 
                decrypted_data - bytes object (decrypted)
            """
            decrypted_data = bytes([(encrypted_data[i] - ord(key[i % len(key)])) % 256 for i in range(len(encrypted_data))])
            return decrypted_data


    class RSA:

        @staticmethod
        def generate_keypair(min_modulus, max_modulus):
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
        def encrypt(message, public_key):
            e, n = public_key   
            encrypted = [pow(ord(byte), e, n) for byte in message]
            return encrypted

        @staticmethod
        def decrypt(encrypted, private_key):
            d, n = private_key
            decrypted = ''.join([chr(pow(char, d, n)) for char in encrypted])
            return decrypted

        @staticmethod
        def gcd(a, b):
            while b != 0:
                a, b = b, a % b
            return a

        @staticmethod
        def mod_inverse(a, m):
            m0, x0, x1 = m, 0, 1
            while a > 1:
                q = a // m
                m, a = a % m, m
                x0, x1 = x1 - q * x0, x0
            return x1 + m0 if x1 < 0 else x1

        @staticmethod
        def is_prime(n):
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
        
        def encryptBytes(data, public_key):
            encrypted_data = Cipher.RSA.encrypt(data, public_key)
            return bytes(encrypted_data)

        def decryptBytes(data, private_key):
            decrypted_data = Cipher.RSA.decrypt(data, private_key)
            return bytes(decrypted_data)
