import os
import time
import random
from MTD_Utils import * 

def convert_encryption_log_format(input_log_file, output_log_file):
    """
    Converts the log format to only log the encryption ciphers used.

    Args:
        input_log_file (str): The path to the input log file.
        output_log_file (str): The path to the output log file.
    """
    try:
        with open(input_log_file, 'r') as infile, open(output_log_file, 'w') as outfile:
            for line in infile:
                if "Changing Encryption Method to" in line:
                    # Extract the encryption method
                    parts = line.strip().split(" - ")
                    message = parts[3] if len(parts) > 3 else ""
                    if "Changing Encryption Method to" in message:
                        method = message.split("Changing Encryption Method to ")[1].split(" method for file")[0]
                        # Write to the new log format
                        outfile.write(f"cipher_encryption;{method}\n")
        print(f"Log file {input_log_file} converted successfully to {output_log_file}.")
    except Exception as e:
        print(f"Error converting log file {input_log_file}: {e}")

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
            convert_encryption_log_format("./logs/encryption_log.log", "./master_logs.txt")

            
    except KeyboardInterrupt:
        print("Script terminated by user.")

if __name__ == "__main__":
    directory = "./test"  # Replace with the directory you want to iterate over
    main(directory)