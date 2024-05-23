import logging 
import os 
import re 
class MTD_Logs:
    @staticmethod
    def Encryption_System_Logs(): 
        encryption_logger = logging.getLogger("Encrytion_Logger")
        encryption_logger.setLevel(logging.INFO)

        if not os.path.exists('logs'):
            os.makedirs('logs')
        
        file_handler = logging.FileHandler("logs/encryption_log.log", mode="a")
    
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        
        file_handler.setFormatter(formatter)
   
        
        encryption_logger.addHandler(file_handler)
  
        return encryption_logger
    
    @staticmethod
    def Hash_System_Logs(): 
        hash_logger = logging.getLogger("Hash_Logger")
        hash_logger.setLevel(logging.INFO)

        if not os.path.exists('logs'):
            os.makedirs('logs')
        
        file_handler = logging.FileHandler("logs/hash_log.log", mode="a")

        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        
        file_handler.setFormatter(formatter)

        hash_logger.addHandler(file_handler)

        return hash_logger
    def Yara_Scan_Logs(scan_log_file, yara_log_file):
            with open(scan_log_file, 'r') as infile, open(yara_log_file, 'w') as outfile:
                for line in infile:
                    if line.startswith("Scanning"):
                        continue
                    severity, category, description, file_path, file_hash = map(str.strip, line.split('|'))
                    outfile.write(f"YARA_SCAN;{severity};{category};{description};{file_path};{file_hash}\n")
    


    @staticmethod
    def Convert_Cipher_Master(input_log_file, output_log_file):
    # Regular expression pattern to match log entries
        pattern = re.compile(r'Changing Encryption Method to (\w+) method for file (.+).')

        with open(input_log_file, 'r') as infile, open(output_log_file, 'w') as outfile:
            for line in infile:
                match = pattern.search(line)
                if match:
                    cipher_algorithm = match.group(1)
                    file_name = match.group(2)
                    outfile.write(f"cipher_encryption;{cipher_algorithm}\n")
