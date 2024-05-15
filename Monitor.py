import hashlib
import pyinotify
import subprocess
import os
import time
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
from File import *
from MTD_Encryption import random_encrypt_decrypt_file

# Set up the path for monitoring and Yara rule file
MONITOR_PATH = "rba"
YARA_RULES_PATH = "/path/to/yara/rules/malware_detection.yar"
latest_logged_modification = ""

class TimestampExtractorHandler(logging.Handler):
    def emit(self, record):
        # Access the creation time of the log record and format it
        log_time = datetime.fromtimestamp(record.created)
        formatted_time = log_time.strftime('%Y-%m-%d %H:%M:%S')
        latest_logged_modification = formatted_time
        latest_encryption_log = ""
        
            
        # Extract and store the timestamp somewhere or perform other actions
        print(f"Captured Timestamp: {formatted_time} - Log Level: {record.levelname} - Message: {record.getMessage()}")

# Compile Yara rules
# rules = yara.compile(YARA_RULES_PATH)
log_file = "./logs/operation_history.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(log_file, maxBytes=1000000, backupCount=3)
    ]
)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Add the custom handler to the logger
logger.addHandler(TimestampExtractorHandler())

# Function to scan a file with Yara
def scan_with_yara(filepath):
    scan_output = YaraScan.Executable.scan("./dummy.txt" )
    matches = rules.match(filepath)
    if matches:
        print(f"Yara matches found in {filepath}: {matches}")
        # Additional action (e.g., alerting)

# Function to check file integrity
def check_hash(filepath):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    file_hash = hasher.hexdigest()
    print(f"SHA-256 hash of {filepath} is {file_hash}")
    # Check previous hash and compare with the new hash of the file to detect modification
    # Compare against known good hash here


class EventHandler(pyinotify.ProcessEvent):

    def process_IN_CREATE(self, event): 
        logging.info(f"File Created: {event.pathname}")
        print(f"Creating: {event.pathname}")
        random_encrypt_decrypt_file(event.pathname)
        #random_encrypt_decrypt_file(event.pathname)
        # scan_with_yara(event.pathname)
        # check_hash(event.pathname)
        #change encryption if its bad hash

        

    def process_IN_MODIFY(self, event):
        logging.info(f"File Modified: {event.pathname}")
        print(f"Modifying: {event}")
        encryption_log = open("./logs/encryption_log.log")

        #Finding last encryption
        with open("./logs/encryption_log.log") as file:
            #Checking for Empty log file
            if not file.read(1): 
                print("Encryption Log file is empty")
                random_encrypt_decrypt_file(event.pathname)

            for line in (file.readlines() [-1:]):
                print("line") 
                latest_encryption_log_timestamp = " ".join(line.split(" ")[0:2])

                print(f"Last time file was encrypted : {latest_encryption_log_timestamp} Latest Modification time {latest_encryption_log_timestamp}")
                
                if(latest_encryption_log_timestamp == latest_encryption_log_timestamp): 
                    print("File was just encrypted")
                else: 
                    print("Encryption being carried out")

                    random_encrypt_decrypt_file(event.pathname)


        #scan_with_yara(event.pathname)
        #check_hash(event.pathname)

    def process_IN_CLOSE_NOWRITE(self, event):
        logging.info(f"File being accessed by non-writable ")
        print("File now write ")
    
    def process_IN_DELETE(self, event):
        logging.info(f"File Created: {event.pathname}")
        print(f"Deleting: {event.pathname} also dis event {event}")
        #changes encryption algorithm immediately to prevent an attacker from managing to recover the deleted files

        

wm = pyinotify.WatchManager()
notifier = pyinotify.Notifier(wm, EventHandler())
wdd = wm.add_watch(MONITOR_PATH, pyinotify.IN_CREATE | pyinotify.IN_MODIFY, rec=True, auto_add=True)

print("Starting monitor...")
notifier.loop()

if __name__ == '__main__':
   print("Starting monitor...")

   notifier.loop() 