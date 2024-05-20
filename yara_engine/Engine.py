import os
import json
import sys
import time
import multiprocessing

from .src import Base, YaraRule, ScanSetData
current_directory = os.getcwd()
files = os.listdir(current_directory)

BASE = current_directory + '/rules' + '/base/base.yar'
#CONFIG = json.load(current_directory + '/config.json')

        
class YaraEngine:
    def __init__(self,fileDir=BASE):
        self.base = Base(fileDir)
        self.queue = []
        self.scans = ScanSetData(time.time())
        
    def scan(self, filePath, fileHash):
        events,logstringList = self.base.scan(filePath,fileHash)
        return events,logstringList
    
class YaraEngineClient(YaraEngine):
    def __init__(self,fileDir=None):
        self.base = Base(YaraRule(fileDir,True))
        self.queue = []
        self.scans = ScanSetData(time.time())
        
        self.jobs = []
        self.logs = []
        self.events = []
        
    def scan(self, filePath, fileHash,data:ScanSetData, base=None):
        if base is None: base = self.base
        events,logstringList = base.scan(filePath,fileHash,mThread=True)
        for l in logstringList: 
            self.logs.append(l)
            print(l)
        data.addScan(events)
        
        
    def addFile(self,filePath,fileHash):
        self.queue.append((filePath,fileHash))
    
    async def processJob(self, i, max_thread=4):
        current_threads = []
        for pi in range(0,max_thread):
            if not self.queue: break
            filePath,fileHash = self.queue.pop(0)
            print(f"Scanning File #{i} - {filePath}")
            i += 1
            process = multiprocessing.Process(target=self.scan,args=(filePath,fileHash,self.currentScan,self.base))
            current_threads.append(process)
            process.start()
        
        for proc in current_threads:
            proc.join()
            
            
            
    async def queueProcess(self,name="Manual Scan"):
        self.currentScan = ScanSetData(time.time(),name=name)
        initLen = len(self.queue)
        self.iter = 1
        if initLen == 0: print(f"No files in queue!")
        print(f"Starting scan with {initLen} files in queue...")
        while self.queue:
            await self.processJob(self.iter)
            print(f"Scanning in progress: ({self.iter}/{initLen})")
        self.generateSummary(self.currentScan,self.logs)
        #while self.queue:
        #    f1_path,f1_hash = self.queue.pop(0)
        #    f2_path,f2_hash = self.queue.pop(0)
        #    scan1 = 
        #    scan2 = threading.Thread(target=self.scan,args=(f2_path,f2_hash))
        #    scanData1,logList1 = scan1.start()
        #    scanData2,logLis2 = scan2.start()
        #    
        #    scan1.join()
        #    scan2.join()
        #    
        #    scan.addScan(scanData1)
        #    scan.addScan(scanData2)
        #    for e in scanData1.events:
        #        result[f1_path] += e
        #    for l in logList1:
        #        logs.append(l)
        #        print(l)
        #    print(f"Scan Progress ({initLen-len(self.queue)}/{initLen})")
          
    
    def generateSummary(self,scan,logs):      
        sumE = 0
        sumL = []
        for s in scan.sum.keys():
            sumE += scan.sum[s]
            sumL.append((s,scan.sum[s]))
        print(f"Scan Finished!")
        print(f"Summary:")
        print("========================================")
        print(f"Total Rule Triggers: {sumE}")
        for r in sumL:
            print(f"{r[0]}: {r[1]}")
        print("========================================")
        print("Logs:")
        print("========================================")
        for l in logs:
            print(l)

        