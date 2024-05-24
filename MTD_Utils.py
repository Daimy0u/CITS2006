import os
import logging
import random
from File import File  # Importing the File class from File.py
from Hashing import *
from MTD_Logs import * 
from check_duplicate_hashes import check_duplicate_hashes
from tests import yara
#from modules.yara_engine.Engine import YaraEngine

#from yara_engine.Engine import *
# Setup Logger
YARA_RULES_PATH = './modules/yara_engine/rules/base/base.yar'
    
encryption_logger = MTD_Logs.Encryption_System_Logs()
hash_logger = MTD_Logs.Hash_System_Logs()
#yara_logger = MTD_Logs.Yara_Scan_Logs()
root_file = "/home/aarya/Documents/Uni/cyber/project/CITS2006/rba"
class MTD_Utils:
    encryption_methods = [
        (File.XOR.Encrypt, File.XOR.Decrypt, "XOR"),
        (File.RSA.Encrypt, File.RSA.Decrypt, "RSA"),
        (File.Base64.Encrypt, File.Base64.Decrypt, "Base64"),
        (File.Swap.Encrypt, File.Swap.Decrypt, "Swap")
    ]

    @classmethod
    def MTD_Decrypt(cls, path):
        encryption_logs = open("./logs/encryption_log.log")
        lines = encryption_logs.readlines()
        logs_for_file = [line for line in lines if path in line]
        encryption_logs.close()
        
        if logs_for_file:
            last_log = logs_for_file[-1]

            for encrypt_method, decrypt_method, method_name in cls.encryption_methods:
                if method_name in last_log:
   
                    
                    decrypt_method(path)
                    print(f"\n\n\n///////////////////////////////////////////////////{method_name} Decrypted File /////////////////////////////////////////////////////////////\n\n\n\n\n")

                    with open(path, 'r') as decrypted_file:
                        
                        print(decrypted_file.read())
                        print("\n\n\n\n/////////////////////////////////////////////////////////////////////////////////////////\n\n\n")
                    encryption_logger.info(f"Decrypting File Method using {method_name} Decrypt method for file {path}.")

    @classmethod
    def Random_Encryption(cls, path, decrypted):
        if not decrypted: 

            cls.MTD_Decrypt(path)
        
        
        encrypt_method, decrypt_method, method_name = random.choice(cls.encryption_methods)
        encryption_logger.info(f"Changing Encryption Method to {method_name} method for file {path}.")

        encrypt_method(path)
 
    @classmethod
    def MTD_Hashing(cls, path, high_security): 
        with open(path, 'rb') as afile:
            buf = afile.read()
            if(high_security):
                hash1 = SHA256.hash(buf)
                hash_logger.info(f"{hash1} {path} SHA256")
            hash2 = FNV1a.hash(buf)
            hash_logger.info(f"{hash2} {path} FNV1a")
  
    @classmethod
    def Rotate_Folder_Name(cls, original_name):
        #build new name 
        today_date = datetime.now().strftime("%Y-%m-%d")

        # Generate a random number (for example, between 1000 and 9999)
        random_number = random.randint(1000, 9999)
     

        # Construct the new folder name
        if("high_security" in original_name):
            new_folder_name = f"high_security-{random_number}"
            folder_path, old_folder_name = os.path.split(original_name)
     
            

            new_path = os.path.join(folder_path, new_folder_name)
           

            os.rename(original_name, new_path)


            print(f"--------------------------Changing {original_name} to {new_path} --------------------------------")
            return new_path
    @classmethod
    def Rotate_Password(cls, current_password):
        # Generate a new random password
        new_password = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=12))
        print(f"NEW PASSWORD: {new_password}")

        # Read the current password file
        
        
        # Log the password rotation
        encryption_logger.info(f"Password rotated. Old Password: {current_password}, New Password: {new_password}")

        return new_password

    @classmethod
    def MTD_Shuffle(cls):
        global root_file
        #Randomly re-encrypting files in the system  
        for dirpath, dirnames, filenames in os.walk(root_file):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                
                cls.Random_Encryption(file_path, False)
               
        #changing the names of directories 
        for dirpath, dirnames, filenames in os.walk(root_file):
           MTD_Utils.Rotate_Folder_Name(dirpath)

    # @classmethod
    # def MTD_Yara(cls, path): 
    #     results = yara.run(YARA_RULES_PATH, path,YaraEngine)
    #     print(results)


    @classmethod

    def MTD_Scan(cls, path): 
        # yara scan 
        # scan hash duplicates 
        duplicates = check_duplicate_hashes("./logs/hash_log.log")
        high_sec_instance = []
        low_sec_instance = []
        if(len(duplicates) > 0): 

            for duplicate in duplicates[0]: 
                
                if "high_security" in duplicate: 
                    high_sec_instance.append(duplicate)
                elif "low_security" in duplicate: 
                    low_sec_instance.append(duplicate)
           
            if len(high_sec_instance) > 0 and len(low_sec_instance)> 0: 
                print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! DATA BREACH: found high security data in low security path!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" )
            
            for file in low_sec_instance:
                
                print("DELETING LOW SECURITY FILE :{file}")
                os.remove(file)
                # clear log file
                with open("./logs/hash_log.log", 'w') as file:
                    pass
            print("//////////////////////////////////////////////////// RESHUFFLING SYSTEM//////////////////////////////////////////////")
            cls.MTD_Shuffle()

            

        # raise alert 
    

            



