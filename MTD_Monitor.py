import hashlib
import pyinotify
from datetime import datetime
from Hashing import *
import logging
from logging.handlers import RotatingFileHandler
from File import *
from MTD_Utils import *
import shutil
# Set up the path for monitoring and Yara rule file
MONITOR_PATH = "rba"
YARA_RULES_PATH = "/path/to/yara/rules/malware_detection.yar"
BACK_UP = "backups"
latest_logged_modification = ""
if not os.path.exists(BACK_UP):
    os.makedirs(BACK_UP)
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

class EventHandler(pyinotify.ProcessEvent):

    def process_IN_CREATE(self, event): 
        logging.info(f"File Created: {event.pathname}")
        print(f"Creating: {event.pathname}")
        #random_encrypt_decrypt_file(event.pathname)
        # scan_with_yara(event.pathname)
        
        
        MTD_Utils.MTD_Hashing(event.pathname)
        MTD_Utils.Random_Encryption(event.pathname, True)
        #Backup the encrypted file

        shutil.copy(event.pathname, os.path.join(BACK_UP, os.path.basename(event.pathname)))
    
        #change encryption if its bad hash

        

    def process_IN_MODIFY(self, event):
        logging.info(f"File Modified: {event.pathname} by MTD ")
        print(f"Modifying")
        encryption_log = open("./logs/encryption_log.log")

        #Finding last encryption
        with open("./logs/encryption_log.log") as file:
            #Checking for Empty log file
            change_needed = True

            #store boolean if file was decrypted or not 
            decrypted = False

            #Checking last log of file
        
            for line in reversed(file.readlines()):
                # Find
                if event.pathname in line: 
                    print(line)
                    if "Decrypt" in line: 
                        decrypted = True

                    latest_encryption_log_timestamp = " ".join(line.split(" ")[0:2])

                    print(f"Last time file was encrypted : {latest_encryption_log_timestamp} Latest Modification time {latest_logged_modification}")
                    #only encrypt file if file wasn't already encrypted by MTD
                    if(latest_encryption_log_timestamp == latest_logged_modification): 
                        print("File was just encrypted")
                        change_needed = False
                    else: 
                        print("Encryption should be carried out")
                        
                    break



            if change_needed: 
                backup_file_path = os.path.join(BACK_UP, os.path.basename(event.pathname))
                if os.path.exists(backup_file_path):
                    shutil.copy(backup_file_path, event.pathname)
                    logger.info(f"Reverted changes for {event.pathname}")
                MTD_Utils.Random_Encryption(event.pathname, False)
                #backup file encrypted with new system 
                shutil.copy(event.pathname, os.path.join(BACK_UP, os.path.basename(event.pathname)))
    

                print("MTD Encryption is done")
            


        #scan_with_yara(event.pathname)
        #check_hash(event.pathname)
    def process_IN_ACCESS(self, event): 
        print("somebody reading ")
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