import os
import time
import random
from MTD_Utils import * 
from security_recommendations import generate_recommendations
import re

SECURITY_RECOMMENDATION = "Security_Recs.txt"

def main(directory):
    """
    Main function to iterate over the directory and change encryption of files.
    """
    try:
        while True:
            # Encrypt files in the directory
            print("Hey its been a while ")
            #Todo: Yara Scan 
            
            # Sleep for 10 seconds
            print("Sleeping for 10 seconds...")
            time.sleep(10)
            MTD_Utils.MTD_Scan(directory)
            MTD_Logs.Convert_Cipher_Master("./logs/encryption_log.log", "./master_log.txt")

            time.sleep(20)
            MTD_Utils.MTD_Shuffle()
            MTD_Logs.Convert_Cipher_Master("./logs/encryption_log.log", "./master_log.txt")
            if not os.path.exists(SECURITY_RECOMMENDATION):
        # Create the file and write initial content to it
                with open(SECURITY_RECOMMENDATION, 'w') as file:
                    file.write("")
                
            else:
                os.remove(SECURITY_RECOMMENDATION)
            generate_recommendations("./master_log.txt", SECURITY_RECOMMENDATION)

            
    except KeyboardInterrupt:
        print("Script terminated by user.")

if __name__ == "__main__":
    directory = "./test"  # Replace with the directory you want to iterate over
    main(directory)