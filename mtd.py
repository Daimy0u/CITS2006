import hashlib
import pyinotify
import subprocess
import os
import time
import logging
from logging.handlers import RotatingFileHandler
from File import *

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

#Function to change encryption files when no changes/actions are made to the system within 10 seconds time interval (not doing anything while the mtd file runs)
def monitor_file_system():
    """
    Monitor the file system for changes and re-encrypt files if no changes
    are made within a 10-second time interval
    """
    # Get initial modification times of files
    initial_modification_times = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            initial_modification_times[file_path] = os.path.getmtime(file_path)
    
    while True:
        # Sleep for 10 seconds
        time.sleep(10)
        
        # Check if any files have been modified
        modified = False
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.getmtime(file_path) != initial_modification_times.get(file_path, 0):
                    modified = True
                    break
            if modified:
                break
        
        # If no files have been modified, re-encrypt files
        if not modified:
            # encrypt all files in the directory again
            FileEncryptorMTD.encrypt_file()
            print("Files re-encrypted.")
 

# Event handler class
#mtd dynamically changes when a vulnerability is detected in filesystems
class EventHandler(pyinotify.ProcessEvent):
    def process_IN_CREATE(self, event): 
        logging.info(f"File Created: {event.pathname}")
        print(f"Creating: {event.pathname}")
        # scan_with_yara(event.pathname)
        # check_hash(event.pathname)
        #change encryption if its bad hash
        FileEncryptorMTD.encrypt_file()
        

    def process_IN_MODIFY(self, event):
        logging.info(f"File Modified: {event.pathname}")
        print(f"Modifying: {event.pathname}")
        #scan_with_yara(event.pathname)
        #check_hash(event.pathname)
        # change encryption 
        FileEncryptorMTD.encrypt_file()
    
    def process_IN_DELETE(self, event):
        logging.info(f"File Created: {event.pathname}")
        print(f"Deleting: {event.pathname}")
        #changes encryption algorithm immediately to prevent an attacker from managing to recover the deleted files
        FileEncryptorMTD.encrypt_file()
        
class FileEncryptorMTD:
    current = 0
    @staticmethod
    def encrypt_file(self):
        if FileEncryptorMTD.current = 0:
            new_current = random.randint(1,4)
            FileEncryptorMTD.current = new_current
            encryption()
            
        if FileEncryptorMTD.current == 1:
            File.XOR.decrypt()
        elif FileEncryptorMTD.current == 2:
            File.RSA.decrypt()
        elif FileEncryptorMTD.current == 3:
            File.Base64.decrypt()
        elif FileEncryptorMTD.current == 4:
            File.DiffieHellman.decrypt()
            
        new_current = random.randint(1,4)
        while FileEncryptorMTD.current == new_current:
            new_current = random.randint(1,4)

       FileEncryptorMTD.current = new_current
       encryption()
    def encryption():
        if FileEncryptorMTD.current == 1:
            File.XOR.encrypt()
        elif FileEncryptorMTD.current == 2:
            File.RSA.encrypt()
        elif FileEncryptorMTD.current == 3:
            File.Base64.encrypt()
        elif FileEncryptorMTD.current == 4:
            File.DiffieHellman.encrypt()
        print(f"Encrypted using {File.__name__}")
# Set up monitoring
wm = pyinotify.WatchManager()
notifier = pyinotify.Notifier(wm, EventHandler())
wdd = wm.add_watch(MONITOR_PATH, pyinotify.IN_CREATE | pyinotify.IN_MODIFY, rec=True, auto_add=True)

print("Starting monitor...")
notifier.loop()

if __name__ == '__main__':
   print("Starting monitor...")
   monitor_file_system()
   notifier.loop() 