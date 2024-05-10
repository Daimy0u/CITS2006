from Cipher import *
import os

class File:
    class XOR:
        """
        Class for iterating through XOR cipher
        """
        @staticmethod
        def Encrypt(path):
            keyXOR = 'ThisIsA50CharacterLongKeyForEncryption1234567890!@'
            if os.path.isdir(path):

                for root, _, files in os.walk(path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            with open(file_path, 'rb') as f:
                                data = f.read()
                            encrypted_data = Cipher.XOR.encryptBytes(data,keyXOR)
                            
                            with open(file_path, 'wb') as f:
                                f.write(encrypted_data)
                            print(f"Encrypted: {file_path}")

            elif os.path.isfile(path):
                with open(path, 'rb') as f:
                    data = f.read()
                encrypted_data = Cipher.XOR.encryptBytes(data,keyXOR)

                with open(path, 'wb') as f:
                    f.write(encrypted_data)
                print(f"Encrypted: {path}")

            print("XOR Encryption completed.")

        @staticmethod
        def Decrypt(path):
            key = 'ThisIsA50CharacterLongKeyForEncryption1234567890!@'
            if os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        with open(file_path, 'rb') as f:
                            encrypted_data = f.read()
                        
                        decrypted_data = Cipher.XOR.decryptBytes(encrypted_data, key)
                        
                        with open(file_path, 'wb') as f:
                            f.write(decrypted_data)
                        print(f"Decrypted: {file_path}")

            elif os.path.isfile(path):
                with open(path, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = Cipher.XOR.decryptBytes(encrypted_data, key)

                with open(path, 'wb') as f:
                    f.write(decrypted_data)
                print(f"Decrypted: {path}")

            print("XOR decryption completed.")
        
    class RSA:
        """
        Class for iterating through RSA cipher
        """

        @staticmethod
        def Encrypt(path):
            current = os.getcwd()
            keyRSA = Cipher.RSA.generate_keypair(10000,100000)
            public_key,private_key = keyRSA
            
            
            with open(os.path.join(current, '.key.txt'), 'w') as key_file:
                    key_file.write(f"{public_key}\n")
                    key_file.write(f"{private_key}")

            if os.path.isdir(path):

                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r') as f:
                            data = f.read()

                        encrypted_data = Cipher.RSA.encrypt_RSA(data,public_key)

                        with open(file_path, 'w') as f:
                                    f.write(' '.join(map(str, encrypted_data)))
                        print(f"Encrypted: {file_path}")

            elif os.path.isfile(path):
                with open(path, 'r') as f:
                    data = f.read()

                encrypted_data = Cipher.RSA.encrypt_RSA(data,public_key)

                with open(path, 'w') as f:
                            f.write(' '.join(map(str, encrypted_data)))
                print(f"Encrypted: {path}")

            print("RSA Encryption completed.")

        @staticmethod
        def Decrypt(path):
            current = os.getcwd()

            try:
                with open(os.path.join(current, '.key.txt'), 'r') as key_file:
                    keys = key_file.readlines()
                    private_key = eval(keys[1])
            except FileNotFoundError: #Error handling if RSA.Encrypt is not run before Decrypting
                 print("Error: The .key.txt file does not exists\nDid you run File.RSA.Encrypt()?")

            if os.path.isdir(path):

                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r') as f:
                                encrypted = f.read()
                        encrypted = list(map(int, encrypted.split()))
                        decrypted = Cipher.RSA.decrypt_RSA(encrypted, private_key)
                        with open(file_path, 'w') as f:
                            f.write(decrypted)
                        print(f"Decrypted: {file_path}")
            
            elif os.path.isfile(path):
                with open(path, 'r') as f:
                        encrypted = f.read()
                encrypted = list(map(int, encrypted.split()))
                decrypted = Cipher.RSA.decrypt_RSA(encrypted, private_key)
                with open(path, 'w') as f:
                    f.write(decrypted)
                print(f"Decrypted: {path}")

            print("RSA decryption completed.")
            os.remove(os.path.join(current, '.key.txt')) #removing hidden key file

    class Base64:
        """
        Class for iterating through Base64 cipher
        """
        @staticmethod
        def Encrypt(path):
            if os.path.isdir(path):

                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r') as f:
                            data = f.read()
                            data = data.encode()
                        encrypted_data = Cipher.Base64.encode(data)
                        with open(file_path, 'w') as f:
                            f.write(encrypted_data)
                        print(f"Base64 Encrypted: {file_path}")
                    
            elif os.path.isfile(path):
                with open(path, 'r') as f:
                    data = f.read()
                    data = data.encode()
                encrypted_data = Cipher.Base64.encode(data)
                with open(path, 'w') as f:
                    f.write(encrypted_data)
                print(f"Base64 Encrypted: {path}")

            print("Base64 Encryption completed.")


        @staticmethod
        def Decrypt(path):
            if os.path.isdir(path):

                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r') as f:
                            encrypted_data = f.read()
                        decrypted_data = Cipher.Base64.decode(encrypted_data)
                        decrypted_data = decrypted_data.decode()
                        with open(file_path, 'w') as f:
                            f.write(decrypted_data)
                        print(f"Base64 Decrypted: {file_path}")
            elif os.path.isfile(path):
                with open(path, 'r') as f:
                    encrypted_data = f.read()
                decrypted_data = Cipher.Base64.decode(encrypted_data)
                decrypted_data = decrypted_data.decode()
                with open(path, 'w') as f:
                    f.write(decrypted_data)
                print(f"Base64 Decrypted: {path}")

            print("Base64 Decryption completed.")

    class Swap:
        @staticmethod
        def Encrypt(path):
            current = os.getcwd()
            keyRSA = Cipher.RSA.generate_keypair(10000,100000)
            public_key,private_key = keyRSA
            
            
            with open(os.path.join(current, '.key.txt'), 'w') as key_file:
                    key_file.write(f"{public_key}\n")
                    key_file.write(f"{private_key}")

            if os.path.isdir(path):

                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r') as f:
                            data = f.read()

                        encrypted_data = Cipher.Swap.swap_encrypt(data,public_key)

                        with open(file_path, 'w') as f:
                                    f.write(' '.join(map(str, encrypted_data)))
                        print(f"Encrypted: {file_path}")

            elif os.path.isfile(path):
                with open(path, 'r') as f:
                    data = f.read()

                encrypted_data = Cipher.Swap.swap_encrypt(data,public_key)

                with open(path, 'w') as f:
                            f.write(' '.join(map(str, encrypted_data)))
                print(f"Encrypted: {path}")

            print("Swap Encryption completed.")

        @staticmethod
        def Decrypt(path):
            current = os.getcwd()

            try:
                with open(os.path.join(current, '.key.txt'), 'r') as key_file:
                    keys = key_file.readlines()
                    private_key = eval(keys[1])
            except FileNotFoundError: #Error handling if RSA.Encrypt is not run before Decrypting
                 print("Error: The .key.txt file does not exists\nDid you run File.RSA.Encrypt()?")

            if os.path.isdir(path):

                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r') as f:
                                encrypted = f.read()
                        encrypted = list(map(int, encrypted.split()))
                        decrypted = Cipher.Swap.swap_decrypt(encrypted, private_key)
                        with open(file_path, 'w') as f:
                            f.write(decrypted)
                        print(f"Decrypted: {file_path}")
            
            elif os.path.isfile(path):
                with open(path, 'r') as f:
                        encrypted = f.read()
                encrypted = list(map(int, encrypted.split()))
                decrypted = Cipher.Swap.swap_decrypt(encrypted, private_key)
                with open(path, 'w') as f:
                    f.write(decrypted)
                print(f"Decrypted: {path}")

            print("Swap decryption completed.")
            os.remove(os.path.join(current, '.key.txt')) #removing hidden key file
            