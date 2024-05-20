import os
import time
import random
from MTD_Utils import * 
from security_recommendations import generate_recommendations
import re



def main(directory):
    """
    Main function to iterate over the directory and change encryption of files.
    """
    try:
        while True:
            # Encrypt files in the directory
            print("Hey its been a while ")
            
            # Sleep for 10 seconds
            print("Sleeping for 10 seconds...")
            time.sleep(10)
            MTD_Utils.MTD_Scan(directory)
            MTD_Logs.Convert_Cipher_Master("./logs/encryption_log.log", "./logs/encryption_log.log")
            generate_recommendations("master_log.txt", "sec_rec.txt")
            

            
    except KeyboardInterrupt:
        print("Script terminated by user.")

if __name__ == "__main__":
    directory = "./test"  # Replace with the directory you want to iterate over
    main(directory)