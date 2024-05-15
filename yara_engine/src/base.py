from .models.rules import *
from .models.scans import ScanData,Event
from typing import List,Tuple

class Executable(BaseRule):
    def __init__(self):
        super().__init__(name="Executable", 
                        desc="Detect ELF Files",
                        outputWarning="Unauthorized Executable ELF File!")
        
    def scan(self,filePath,fileHash,matches,whitelist=False)->tuple:
        if 'isExecutable' in matches:
            if whitelist:
                return self.infoPositive(filePath,fileHash,whitelist,severity=0)
            else:
                return self.infoPositive(filePath,fileHash,whitelist)
        else: 
            return self.infoNegative()

class SuspiciousUrl(BaseRule):
    def __init__(self):
        super().__init__(name="Suspicious URL", 
                        desc="Detect Suspicious Non-Standard TLD URL Access",
                        outputWarning="Suspicious URL Detected!",
                        severity=2)
        self.passing_tld = ['.com','.gov','.edu','.net','.org']
        
    def scan(self,filePath,fileHash,matches,whitelist=False)->tuple:
        if 'isURL' in matches:
            flag = False
            urls = [x.plaintext() for x in matches['isURL']]
            for url in urls:
                for tld in self.passing_tld:
                    if tld not in url:
                        flag = True
            if whitelist:
                return self.infoPositive(filePath,fileHash,whitelist,severity=0)
            else:
                if flag == False: severity = 1
                else: severity = 2
                return self.infoPositive(filePath,fileHash,whitelist,severity=severity)
        else: 
            return self.infoNegative()

class Script(BaseRule):
    def __init__(self):
       super().__init__(name="Scripts", 
                        desc="Detect unauthorized scripts.",
                        outputWarning="File is an non-whitelisted script!",
                        severity=4)
       
    def scan(self,filePath,fileHash,matches,whitelist=False)->tuple:
        if 'isScript' in matches:
            if whitelist:
                return self.infoPositive(filePath,fileHash,whitelist,severity=0)
            else:   
                return self.infoPositive(filePath,fileHash,whitelist)
        else: 
            return self.infoNegative()
        
class MaliciousScript(BaseRule):
    def __init__(self):
       super().__init__(name="Malicious Script", 
                        desc="High confidence malicious script detection.",
                        outputWarning="File is very likely a malicious script!",
                        severity=5)
       
    def scan(self,filePath,fileHash,matches,whitelist=False)->tuple:
        if 'isMaliciousScript' in matches:
            if whitelist:
                return self.infoPositive(filePath,fileHash,whitelist,severity=0)
            else:   
                return self.infoPositive(filePath,fileHash,whitelist)
        else: 
            return self.infoNegative()
        
class NetworkAccess(BaseRule):
    def __init__(self):
       super().__init__(name="Network Access", 
                        desc="Detect Any Network Access by Files",
                        outputWarning="File has unauthorized network probing/access!",
                        severity=4)
        
    def scan(self,filePath,fileHash,matches,whitelist=False)->tuple:
        if 'isAccessingNetwork' in matches:
            if whitelist:
                return self.infoPositive(filePath,fileHash,whitelist,severity=0)
            else:
                return self.infoPositive(filePath,fileHash,whitelist)
        else: 
            return self.infoNegative()
    


class Base:
    """
    Base-set rules, made/tailored to the company.
    """    
    @classmethod
    def __init__(cls,rule:YaraRule,whitelist=None):
        if whitelist is None: whitelist = []
        cls.rule = rule
        cls.whitelist = whitelist
        cls.cache = {}
        
        cls.ruleset = []
        #Load Base Rules
        #Files
        cls.ruleset += [Executable(),Script(),MaliciousScript()]
        #Networks
        cls.ruleset += [SuspiciousUrl(),NetworkAccess()] 
        
    @classmethod
    def scan(cls, filePath:str, fileHash:str) -> Tuple[ScanData,List[str]]:
        """Returns only rules that are triggered for a file, and string for logging.

        Args:
            filePath (str): Individual File Path
            fileHash (str): Individual File Hash

        Returns:
            scanData: scan data        
            str: f-string in a loggable format.
        """
        scan = ScanData(filePath,fileHash)
        logStrList = []
        if fileHash in cls.cache.keys() and cls.cache[fileHash]["path"] == filePath:
            return cls.cache[fileHash]["scan"],cls.cache[fileHash]["logStrList"]
        
        matches = cls.rule.getMatches(filePath)
        for rule in cls.ruleset:
            if fileHash in cls.whitelist:  
                flag,data,logstring = rule.scan(filePath,fileHash,matches,whitelist=True)
            else:
                flag,data,logstring = rule.scan(filePath,fileHash,matches,whitelist=False)
            if flag: 
                scan.addEvent(Event(rule.name,rule.warning,data["severity"],data["whitelist"]))
            if logstring is not None: logStrList.append(logstring)
            
        #Store Cache
        cls.cache[fileHash] = {
            "path":filePath,
            "scan":scan,
            "logStrList":logStrList
        }
        return scan,logStrList
    