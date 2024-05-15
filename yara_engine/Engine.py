import os
import json
from time import time
from src.base import Base
from src.models.scans import ScanSetData

current_directory = os.getcwd()
files = os.listdir(current_directory)

BASE = current_directory + '/rules' + '/base/base.yar'
CONFIG = json.load(current_directory + '/config.json')

        
class YaraEngine:
    def __init__(self):
        self.base = Base(BASE)
        self.queue = []
        self.scans = ScanSetData(time.time())
        
    def scan(self, filePath, fileHash):
        events,logstringList = self.base.scan(filePath,fileHash)
        return events,logstringList
    
    def queueFile(self,filePath,fileHash):
        self.queue.append((filePath,fileHash))
        return f"Added to queue: {filePath},{fileHash}"
        
    def queueProcess(self,name=""):
        result = {}
        logs = []
        scan = ScanSetData(time.time(),name)
        initLen = len(self.queue)
        if initLen == 0: print(f"No files in queue!")
        print(f"Starting scan with {initLen} files in queue...")
        while self.queue:
            file,fileHash = self.queue.pop(0)
            scanData,logList = self.base.scan(file,fileHash)
            scan.addScan(scanData)
            
            for e in scanData.events:
                result[file] += e
            for l in logList:
                logs.append(l)
                print(l)
            print(f"Scan Progress ({initLen-len(self.queue)}/{initLen})")
            
        sumE = 0
        for s in scan.sum.keys():
            sumE += scan.sum[s]
        print(f"Scan Finished!")
        print(f"Summary:")
        print("========================================")
        print(f"Total Rule Triggers: {sumE}")
        print(f"CRITICAL: {scan.sum["CRITICAL"]}")
        print(f"SEVERE: {scan.sum["SEVERE"]}")
        print(f"MODERATE: {scan.sum["MODERATE"]}")
        print(f"LOW: {scan.sum["LOW"]}")
        print("========================================")
        print("Logs:")
        print("========================================")
        for l in logs:
            print(l)
            
            
            
                
        
        