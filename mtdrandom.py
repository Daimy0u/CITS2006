import random
import subprocess
import pickle
from File import *


class FileEncryptorMTD:
    def __init__(self):
        self.current_dict = self.load_current_dict()

    def load_current_dict(self):
        try:
            with open("current_dict.pickle", "rb") as file:
                return pickle.load(file)
        except FileNotFoundError:
            return {}

    def save_current_dict(self):
        with open("current_dict.pickle", "wb") as file:
            pickle.dump(self.current_dict, file)

    def encrypt_file(self, file_path):
        if file_path not in self.current_dict:
            self.current_dict[file_path] = {'current': 0}  # initialize encryption to null

        if self.current_dict[file_path]['current'] != 0:
            self.decryption(file_path)

        new_current = random.randint(1, 3)
        while self.current_dict[file_path]['current'] == new_current:
            new_current = random.randint(1, 3)

        self.current_dict[file_path]['current'] = new_current
        self.encryption(file_path)
        self.save_current_dict()

    def encryption(self, file_path):
        if self.current_dict[file_path]['current'] == 1:
            File.XOR.Encrypt(file_path)

        elif self.current_dict[file_path]['current'] == 2:
            File.RSA.Encrypt(file_path)

        elif self.current_dict[file_path]['current'] == 3:
            File.Base64.Encrypt(file_path)

    def decryption(self, file_path):
        if self.current_dict[file_path]['current'] == 1:
            File.XOR.Decrypt(file_path)
            print("Decrypted file content:")
            subprocess.run(["cat", file_path])
            
        elif self.current_dict[file_path]['current'] == 2:
            File.RSA.Decrypt(file_path)
            print("Decrypted file content:")
            subprocess.run(["cat", file_path])

        elif self.current_dict[file_path]['current'] == 3:
            File.Base64.Decrypt(file_path)
            print("Decrypted file content:")
            subprocess.run(["cat", file_path])
"""""
def main():
    file_path = "hello.txt"

    print("Original file content:")
    subprocess.run(["cat", file_path])
    print()

    print("Encrypting with random cipher...")
    encryptor = FileEncryptorMTD()
    encryptor.encrypt_file(file_path)
    print()



if __name__ == "__main__":
    main()

"""