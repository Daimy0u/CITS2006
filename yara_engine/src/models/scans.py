from typing import Tuple,TypeAlias,List

File_Name : TypeAlias = str
File_Hash : TypeAlias = str
File_Info : TypeAlias = Tuple[File_Name,File_Hash]
Is_Scanned : TypeAlias = bool
Events : TypeAlias = list

SEVERITY_TABLE = {
    "WHITELIST":0,
    "BENIGN":0,
    "LOW":0,
    "MODERATE":0,
    "SEVERE":0,
    "CRITICAL":0
}

class Event:
    def __init__(self,ruleName,ruleWarning,severity,whitelist=False):
        self.rule = ruleName
        self.warning = ruleWarning
        self.severity = severity
        self.whitelist = whitelist
        
class ScanData:
    def __init__(self,filePath,fileHash,events=None,scan=True):
        if events is None: 
            events = []
        self.file = (filePath,fileHash)
        self.events = events
        self.scanned = scan
        self.sum = SEVERITY_TABLE.copy()
        
        if self.events:
            for e in self.events:
                self.sum[e.severity] += 1
        
    def data(self) -> Tuple[File_Info,Events] | False:
        if not self.scanned: return False
        return self.file,self.events
    
    def addEvent(self,event:Event):
        self.events.append(event)
        
        
class ScanSetData:
    def __init__(self,timestamp,name="Manual Scan",scans=None):
        if scans == None: scans = []
        self.timestamp = timestamp
        self.name = name
        self.scans = scans
        
        self.sum = SEVERITY_TABLE.copy()
        for s in self.scans:
            for s_const in SEVERITY_TABLE.keys:
                self.sum[s_const] += s[s_const]
                
    def addScan(self,scan:ScanData):
        self.scans.append(scan)
        for s_const in SEVERITY_TABLE.keys:
                self.sum[s_const] += scan.sum[s_const]
    
    def getInfo(self) -> Tuple[str,float,List[ScanData]]:
        """
        Get total scan info
        Returns:
            str: name
            float: timestamp
            list: list of scanData instances
        """
        return self.name,self.timestamp,self.scans
        
        