
import os
import logging
import random
from File import File  # Importing the File class from File.py
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    handlers=[
                        logging.FileHandler("encryption_log.log", mode='a'),
                        logging.StreamHandler()
                    ])

def random_encrypt_decrypt_file(path):
    # Define a list of available methods
    methods = [
        (File.XOR.Encrypt, File.XOR.Decrypt, "XOR"),
        (File.RSA.Encrypt, File.RSA.Decrypt, "RSA"),
        (File.Base64.Encrypt, File.Base64.Decrypt, "Base64"),
        (File.Swap.Encrypt, File.Swap.Decrypt, "Swap")
    ]

    # Randomly select an encryption method
    encrypt_method, decrypt_method, method_name = random.choice(methods)
    logging.info(f"Selected {method_name} method for encryption.")


    print(f"Selected {method_name} method for encryption.")
    logging.info(f"File encrypted using {method_name}.")

    # Encrypt the file
    encrypt_method(path)
    print(f"File encrypted using {method_name}.")
