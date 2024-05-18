import os
import logging
import random
from File import File  # Importing the File class from File.py
from Hashing import *
from MTD_Logs import * 
#from yara_engine.Engine import *
# Setup Logger

    
encryption_logger = MTD_Logs.Encryption_System_Logs()
hash_logger = MTD_Logs.Hash_System_Logs()

class MTD_Utils:
    encryption_methods = [
        (File.XOR.Encrypt, File.XOR.Decrypt, "XOR"),
        (File.RSA.Encrypt, File.RSA.Decrypt, "RSA"),
        (File.Base64.Encrypt, File.Base64.Decrypt, "Base64"),
        (File.Swap.Encrypt, File.Swap.Decrypt, "Swap")
    ]

    @classmethod
    def MTD_Decrypt(cls, path):
        encryption_logs = open("./logs/encryption_log.log")
        lines = encryption_logs.readlines()
        logs_for_file = [line for line in lines if path in line]
        encryption_logs.close()
        print("calling decrypt")
        if logs_for_file:
            last_log = logs_for_file[-1]
            print(last_log)
            for encrypt_method, decrypt_method, method_name in cls.encryption_methods:
                if method_name in last_log:
                    print(f"Previous Encryption Method was {method_name}")
                    print("Decrypting the file...")
                    decrypt_method(path)
                    encryption_logger.info(f"Decrypting File Method using {method_name} Decrypt method for file {path}.")

    @classmethod
    def Random_Encryption(cls, path, decrypted):
        if not decrypted: 

            cls.MTD_Decrypt(path)
        with open(path, 'r') as decrypted_file:
            print(decrypted_file.read())
        
        encrypt_method, decrypt_method, method_name = random.choice(cls.encryption_methods)
        encryption_logger.info(f"Changing Encryption Method to {method_name} method for file {path}.")
        print(f"Selected {method_name} method for encryption.")
        encrypt_method(path)
        print(f"File encrypted using {method_name}.")
    @classmethod
    def MTD_Hashing(cls, path, high_security): 
        with open(path, 'rb') as afile:
            buf = afile.read()
            if(high_security):
                hash1 = SHA256.hash(buf)
                hash_logger.info(f"{hash1} {path} SHA256")
            hash2 = FNV1a.hash(buf)
            hash_logger.info(f"{hash2} {path} FNV1a")
    @classmethod
    def MTD_Yara_Scan(cls, path, high_security): 
        print("heres")
        #YaraEngine.scan("/test.txt", "4fb17c0658b0949ade6c61deb8a8a8f8cf2c58c08ae7a633e0")
    @classmethod
    def Rotate_Folder_Name(cls, original_name):
        #build new name 
        today_date = datetime.now().strftime("%Y-%m-%d")

        # Generate a random number (for example, between 1000 and 9999)
        random_number = random.randint(1000, 9999)
        print(f"Current name {original_name}")

        # Construct the new folder name
        new_folder_name = f"high_security-{random_number}"
        folder_path, old_folder_name = os.path.split(original_name)
        print(f"Current path: {folder_path}")
        

        new_path = os.path.join(folder_path, new_folder_name)
        print(f"New path {new_path}")

        os.rename(original_name, new_path)
        return new_path

    

            



