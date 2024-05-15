
import os
import logging
import random
from File import File  # Importing the File class from File.py

encryption_logger = logging.getLogger("Encrytion_Logger")
encryption_logger.setLevel(logging.INFO)

file_handler = logging.FileHandler("logs/encryption_log.log", mode="a")
stream_handler = logging.StreamHandler()

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
file_handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)

# Add handlers to the logger
encryption_logger.addHandler(file_handler)
encryption_logger.addHandler(stream_handler)


def random_encrypt_decrypt_file(path):
    # Define a list of available methods
    previous_encryption_system = ""
    methods = [
        (File.XOR.Encrypt, File.XOR.Decrypt, "XOR"),
        (File.RSA.Encrypt, File.RSA.Decrypt, "RSA"),
        (File.Base64.Encrypt, File.Base64.Decrypt, "Base64"),
        (File.Swap.Encrypt, File.Swap.Decrypt, "Swap")
    ]

    # Randomly select an encryption method

    #Find Previous Encryption method from logs 
    encryption_logs = open("./logs/encryption_log.log")
    lines = encryption_logs.readlines()
    logs_for_file = []
    for line in lines: 
        if path in line: 
            logs_for_file.append(line)
    if len(logs_for_file) > 0: 
        for method in methods:
            if method[2] in logs_for_file[-1]:
                previous_encryption_system = method[2]
                print(f"Previous Encryption Method was {previous_encryption_system}")
                print("Decrypting the file...")
                decryption_method = method[1]
                decryption_method(path)

    decrypted_file = open(path)
    print(decrypted_file.read())

    #Decrypt file using the key


    encrypt_method, decrypt_method, method_name = random.choice(methods)
    encryption_logger.info(f"Changing Encryption Method to {method_name} method for file {path}.")
    print(logs_for_file)

    print(f"Selected {method_name} method for encryption.")

    # Encrypt the file
    encrypt_method(path)
    print(f"File encrypted using {method_name}.")
