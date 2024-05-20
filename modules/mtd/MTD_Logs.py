import logging 
import os 
class MTD_Logs:
    @staticmethod
    def Encryption_System_Logs(): 
        encryption_logger = logging.getLogger("Encrytion_Logger")
        encryption_logger.setLevel(logging.INFO)

        if not os.path.exists('logs'):
            os.makedirs('logs')
        
        file_handler = logging.FileHandler("logs/encryption_log.log", mode="a")
        stream_handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        
        file_handler.setFormatter(formatter)
        stream_handler.setFormatter(formatter)
        
        encryption_logger.addHandler(file_handler)
        encryption_logger.addHandler(stream_handler)
        return encryption_logger
    
    @staticmethod
    def Hash_System_Logs(): 
        hash_logger = logging.getLogger("Hash_Logger")
        hash_logger.setLevel(logging.INFO)

        if not os.path.exists('logs'):
            os.makedirs('logs')
        
        file_handler = logging.FileHandler("logs/hash_log.log", mode="a")
        stream_handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        
        file_handler.setFormatter(formatter)
        stream_handler.setFormatter(formatter)
        
        hash_logger.addHandler(file_handler)
        hash_logger.addHandler(stream_handler)
        return hash_logger
