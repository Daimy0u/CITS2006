import hashlib
import pyinotify
from datetime import datetime
from Hashing import *
import logging
from logging.handlers import RotatingFileHandler
from File import *
from MTD_Utils import *

# Set up the path for monitoring and Yara rule file
MONITOR_PATH = "rba"
YARA_RULES_PATH = "/path/to/yara/rules/malware_detection.yar"
latest_logged_modification = ""

class TimestampExtractorHandler(logging.Handler):
    def emit(self, record):
        # Access the creation time of the log record and format it
        global latest_logged_modification
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
def hash_file(filepath):
    with open(filepath, 'rb') as afile:
        buf = afile.read()
        print("doing ")
        print(buf)
        print(SHA256.hash(buf))
        #hashed_file = SHA256.hash(buf)
        #print(f"SHA-256 hash of {filepath} is {hashed_file}")
    # Check previous hash and compare with the new hash of the file to detect modification
    # Compare against known good hash here


class EventHandler(pyinotify.ProcessEvent):

    def process_IN_CREATE(self, event): 
        logging.info(f"File Created: {event.pathname}")
        print(f"Creating: {event.pathname}")
        #random_encrypt_decrypt_file(event.pathname)
        # scan_with_yara(event.pathname)
        hash_file(event.pathname)
        MTD_Utils.Random_Encryption(event.pathname)
        #change encryption if its bad hash

        

    def process_IN_MODIFY(self, event):
        logging.info(f"File Modified: {event.pathname}")
        print(f"Modifying: {event}")
        encryption_log = open("./logs/encryption_log.log")

        #Finding last encryption
        with open("./logs/encryption_log.log") as file:
            #Checking for Empty log file
            change_needed = True
            #Checking last time file was encrypted
    
            for line in reversed(file.readlines()):
                if event.pathname in line: 
                    print(line)

                    latest_encryption_log_timestamp = " ".join(line.split(" ")[0:2])

                    print(f"Last time file was encrypted : {latest_encryption_log_timestamp} Latest Modification time {latest_logged_modification}")
                    
                    if(latest_encryption_log_timestamp == latest_logged_modification): 
                        print("File was just encrypted")
                        change_needed = False
                    else: 
                        print("Encryption should be carried out")
                        
                    break



            if change_needed: 
                print("here")
                MTD_Utils.Random_Encryption(event.pathname)
                print("MTD Encryption is done")


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