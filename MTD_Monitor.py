import hashlib
import pyinotify
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import shutil
from File import *  # Adjust these imports based on your actual module structure
from MTD_Utils import *  # Same as above
import sys
from tests import yara
from modules.yara_engine.Engine import YaraEngine

# Setup paths for monitoring and backup
HIGH_SECURITY_MONITOR_PATH = "rba/high_security"
MONITOR_PATH = "rba/"

BACK_UP = "backups"
ACCESS_GRANTED = False
password = "password"


if not os.path.exists(BACK_UP):
    os.makedirs(BACK_UP)

# Setup logging
log_file = "./logs/operation_history.log"
if not os.path.exists('logs'):
    os.makedirs('logs')

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[RotatingFileHandler(log_file, maxBytes=1000000, backupCount=3)])

logger = logging.getLogger(__name__)

# Custom logging handler to capture timestamp
class TimestampExtractorHandler(logging.Handler):
    def emit(self, record):
        global latest_logged_modification
        log_time = datetime.fromtimestamp(record.created)
        formatted_time = log_time.strftime('%Y-%m-%d %H:%M:%S')
        latest_logged_modification = formatted_time
        

logger.addHandler(TimestampExtractorHandler())
root_logger = logging.getLogger()
for handler in root_logger.handlers[:]:
    if isinstance(handler, logging.StreamHandler):
        root_logger.removeHandler(handler)

# Define event handlers
class SecurityEventHandler(pyinotify.ProcessEvent):
    def process_IN_CREATE(self, event): 
        logger.info(f"File Created: {event.pathname}")
        print(f"Creating: {event.pathname}")
        
        isHighSecurity = event.path.startswith(HIGH_SECURITY_MONITOR_PATH)
        print("Scanning with Yara Engine")
        MTD_Utils.MTD_Yara(event.pathname)
        MTD_Utils.MTD_Hashing(event.pathname, isHighSecurity)


        MTD_Utils.Random_Encryption(event.pathname, True)
        if event.path.startswith(HIGH_SECURITY_MONITOR_PATH):
            shutil.copy(event.pathname, os.path.join(BACK_UP, os.path.basename(event.pathname)))
        
    def process_IN_MODIFY(self, event):
        global HIGH_SECURITY_MONITOR_PATH
        global ACCESS_GRANTED
        global password
        
        encryption_change_needed = True
        logger.info(f"File Modified: {event.pathname} by MTD ")
        if(HIGH_SECURITY_MONITOR_PATH in event.pathname):

            with open("./logs/encryption_log.log") as file:
                
                decrypted = False
                for line in reversed(file.readlines()):
                    if event.pathname in line: 
                        print(line)
                        if "Decrypt" in line: 
                            decrypted = True
                        latest_encryption_log_timestamp = " ".join(line.split(" ")[0:2])
                        
                        if latest_encryption_log_timestamp == latest_logged_modification: 
                          
                            encryption_change_needed = False
                            break
                       

                if encryption_change_needed: 
                    backup_file_path = os.path.join(BACK_UP, os.path.basename(event.pathname))
                    if os.path.exists(backup_file_path):
                        if (not ACCESS_GRANTED):
                            shutil.copy(backup_file_path, event.pathname)
                            logger.info(f"Reverted changes for {event.pathname}")
                            
                    MTD_Utils.Random_Encryption(event.pathname, ACCESS_GRANTED)
                    logger.info(f"Backing up changes for {event.pathname}")
                    shutil.copy(event.pathname, backup_file_path)
                    
                    print("Unauthorized access to make changes authenticate")
                    input_password = input("Please provide password for high_security file : ")
                    if input_password == password:
                        
                        ACCESS_GRANTED = True
                        encryption_change_needed = False
                        MTD_Utils.MTD_Decrypt(event.pathname)
                    else: 
                        print("Incorrect password ")
                        HIGH_SECURITY_MONITOR_PATH = MTD_Utils.Rotate_Folder_Name(HIGH_SECURITY_MONITOR_PATH)
                        password = MTD_Utils.Rotate_Password(password)
                    print("MTD Encryption is done")

    def process_IN_DELETE(self, event):
        logger.info(f"File Deleted: {event.pathname}")
        print(f"Deleting: {event.pathname}")


# Monitor setup
wm = pyinotify.WatchManager()
notifier = pyinotify.Notifier(wm, SecurityEventHandler())
wdd_high = wm.add_watch(MONITOR_PATH, pyinotify.ALL_EVENTS, rec=True, auto_add=True)


print("Starting monitor...")
notifier.loop()

if __name__ == '__main__':
    print("Monitoring started...")
    notifier.loop()

