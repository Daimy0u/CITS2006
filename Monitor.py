import hashlib
import pyinotify
import subprocess
import os
import time
import logging
from logging.handlers import RotatingFileHandler
from File import *
from MTD_Encryption import random_encrypt_decrypt_file
# Set up the path for monitoring and Yara rule file
MONITOR_PATH = "./rba"
YARA_RULES_PATH = "/path/to/yara/rules/malware_detection.yar"

# Compile Yara rules
# rules = yara.compile(YARA_RULES_PATH)
log_file = "./logs"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(log_file, maxBytes=1000000, backupCount=3)
    ]
)
# Function to scan a file with Yara
def scan_with_yara(filepath):
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
        # scan_with_yara(event.pathname)
        # check_hash(event.pathname)
        #change encryption if its bad hash

        

    def process_IN_MODIFY(self, event):
        logging.info(f"File Modified: {event.pathname}")
        print(f"Modifying: {event}")
        random_encrypt_decrypt_file("/rba")
        #scan_with_yara(event.pathname)
        #check_hash(event.pathname

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