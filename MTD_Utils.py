import os
import logging
import random
from modules.lib.cipher.File import File  # Importing the File class from File.py
from modules.lib.hash.Hashing import *
from modules.lib.mtd.MTD_Logs import *
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
        print("calling ")
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
    def MTD_Hashing(cls, path): 
        with open(path, 'rb') as afile:
            buf = afile.read()
            hash = SHA256.hash(buf)
            hash_logger.info(f"{hash} {path}")


