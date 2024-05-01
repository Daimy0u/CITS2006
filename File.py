from Cipher import *

class CipherManager:
    keyXOR = 'ThisIsA50CharacterLongKeyForEncryption1234567890!@'
    keyRSA = Cipher.RSA.generate_keypair(1000,10000)

    def __init__(self, method, directory='/home',_keyRSA=None):
        if _keyRSA is not None: keyRSA = _keyRSA
        self.method = method
        self.directory = directory

        public_key,private_key = keyRSA
        with open(os.path.join(directory, '.key.txt'), 'w') as key_file:
                key_file.write(f"{public_key}\n")
                key_file.write(f"{private_key}")

    def encryptDirectory(self):
        with open(os.path.join(self.directory, '.key.txt'), 'r') as key_file:
            keys = key_file.readlines()
            public_key = eval(keys[0])
    
        for root, _, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path, 'rb') as f:
                    data = f.read()
                encrypted_data = Cipher.RSA.encrypt(data, public_key)
                with open(file_path, 'wb') as f:
                    f.write(bytes(encrypted_data))

    def decryptDirectory(self):  
        with open(os.path.join(self.directory, '.key.txt'), 'r') as key_file:
            keys = key_file.readlines()
            private_key = eval(keys[1])
    
        for root, _, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path, 'rb') as f:
                    data = f.read()
                decrypted_data = Cipher.RSA.decrypt(data, private_key)
                with open(file_path, 'wb') as f:
                 f.write(bytes(decrypted_data, 'utf-8'))