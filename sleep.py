import os
import time
import random
from mtdrandom import FileEncryptorMTD

def encrypt_files_in_directory(directory):
    """
    Encrypt all files in the given directory with a different encryption method.
    """
    for root, dirs, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            print("File re-encrypting:", file_name)
            FileEncryptorMTD().encrypt_file(file_path)
            print("File re-encrypted:", file_name)
def main(directory):
    """
    Main function to iterate over the directory and change encryption of files.
    """
    try:
        while True:
            # Encrypt files in the directory
            encrypt_files_in_directory(directory)
            
            # Sleep for 10 seconds
            print("Sleeping for 10 seconds...")
            time.sleep(10)
    except KeyboardInterrupt:
        print("Script terminated by user.")

if __name__ == "__main__":
    directory = "./test"  # Replace with the directory you want to iterate over
    main(directory)