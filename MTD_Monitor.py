import hashlib
import pyinotify
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import shutil
from File import *  # Adjust these imports based on your actual module structure
from MTD_Utils import *  # Same as above

# Setup paths for monitoring and backup
HIGH_SECURITY_MONITOR_PATH = "rba/high_security"
MONITOR_PATH = "rba/"
YARA_RULES_PATH = "/path/to/yara/rules/malware_detection.yar"
BACK_UP = "backups"

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
        print(f"Captured Timestamp: {formatted_time} - Log Level: {record.levelname} - Message: {record.getMessage()}")

logger.addHandler(TimestampExtractorHandler())

# Define event handlers
class SecurityEventHandler(pyinotify.ProcessEvent):
    def process_IN_CREATE(self, event): 
        logger.info(f"File Created: {event.pathname}")
        print(f"Creating: {event.pathname}")
        
        isHighSecurity = event.path.startswith(HIGH_SECURITY_MONITOR_PATH)
          
        MTD_Utils.Random_Encryption(event.pathname, True)
        if event.path.startswith(HIGH_SECURITY_MONITOR_PATH):
            shutil.copy(event.pathname, os.path.join(BACK_UP, os.path.basename(event.pathname)))
        MTD_Utils.MTD_Hashing(event.pathname, isHighSecurity)

    def process_IN_MODIFY(self, event):
        global HIGH_SECURITY_MONITOR_PATH
        logger.info(f"File Modified: {event.pathname} by MTD ")
        print(f"Modifying")
      
        
        with open("./logs/encryption_log.log") as file:
            change_needed = True
            decrypted = False
            for line in reversed(file.readlines()):
                if event.pathname in line: 
                    print(line)
                    if "Decrypt" in line: 
                        decrypted = True
                    latest_encryption_log_timestamp = " ".join(line.split(" ")[0:2])
                    print(f"Last time file was encrypted : {latest_encryption_log_timestamp} Latest Modification time {latest_logged_modification}")
                    if latest_encryption_log_timestamp == latest_logged_modification: 
                        print("File was just encrypted")
                        change_needed = False
                        break
                    else: 
                        print("Encryption should be carried out")

            if change_needed: 
                backup_file_path = os.path.join(BACK_UP, os.path.basename(event.pathname))
                if os.path.exists(backup_file_path):
                    shutil.copy(backup_file_path, event.pathname)
                    logger.info(f"Reverted changes for {event.pathname}")
                MTD_Utils.Random_Encryption(event.pathname, False)
    
                shutil.copy(event.pathname, backup_file_path)
                HIGH_SECURITY_MONITOR_PATH = MTD_Utils.Rotate_Folder_Name(HIGH_SECURITY_MONITOR_PATH)
        
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
