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
                        severity=1)
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
                if flag == False: return self.infoNegative()
                return self.infoPositive(filePath,fileHash,whitelist)
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
    
class MaliciousDDE(BaseRule):
    def __init__(self):
       super().__init__(name="Malicious DDE", 
                        desc="Detects Dynamic Data Exchange (DDE) attacks in office files.",
                        outputWarning="Document file is likely malicious (DDE)!",
                        severity=5)
       
    def scan(self,filePath,fileHash,matches,whitelist=False)->tuple:
        if 'isDDE' in matches:
            if whitelist:
                return self.infoPositive(filePath,fileHash,whitelist,severity=0)
            else:   
                return self.infoPositive(filePath,fileHash,whitelist)
        else: 
            return self.infoNegative()

class MaliciousZip(BaseRule):
    def __init__(self):
        super().__init__(name="Malicious ZIP",
                        desc="Detects ZIP Bombs and Slips",
                        outputWarning="Zip file is malicious (Bomb/Slip)!",
                        severity=5)

    def scan(self,filePath,fileHash,matches,whitelist=False)->tuple:
        if 'isMaliciousZip' in matches:
            if whitelist:
                #Why would you whitelist a zip bomb/slip?
                return self.infoPositive(filePath,fileHash,whitelist,severity=5,extraInfo=" File is whitelisted, whitelist compromised?")
            else:
                return self.infoPositive(filePath,fileHash,whitelist)
        else:
            return self.infoNegative()
        
class ContainsIP(BaseRule):
    def __init__(self):
       super().__init__(name="IP Address Detection", 
                        desc="Detects IP addresses for review",
                        outputWarning="File contains access/storage of IP addresses: ",
                        severity=1)
       
    def scan(self,filePath,fileHash,matches,whitelist=False)->tuple:
        resStr = "["
        if 'isIp' in matches:
            if not matches["isIp"][filePath]: matches["isIp"][filePath] = []
            for ip in matches["isIp"][filePath]:
                resStr += str(ip) + ","
            if whitelist:
                return self.infoPositive(filePath,fileHash,whitelist,extraInfo=resStr+"]")
            else:   
                return self.infoPositive(filePath,fileHash,whitelist)
        else: 
            return self.infoNegative()



class Base:
    """
    Base-set rules
    """
    cache = {}
    ruleset = []
    rule = None
    
    def __init__(self,rule:YaraRule,whitelist=None):
        if whitelist is None: whitelist = []
        self.rule = rule
        self.whitelist = whitelist
        #Load Base Rules
        #Files
        self.ruleset += [Executable(),Script(),MaliciousScript(),MaliciousDDE(),MaliciousZip()]
        #Networks
        self.ruleset += [SuspiciousUrl(),NetworkAccess(),ContainsIP()] 

    def scan(self, filePath:str, fileHash:str,mThread=False) -> Tuple[ScanData,List[str]]:
        """Returns only rules that are triggered for a file, and string for logging.

        Args:
            filePath (str): Individual File Path
            fileHash (str): Individual File Hash
            mThread (bool): Use thread-safe methods

        Returns:
            scanData: scan data        
            str: f-string in a loggable format.
        """
        scan = ScanData(filePath,fileHash)
        logStrList = []
        if fileHash in self.cache.keys() and self.cache[fileHash]["path"] == filePath:
            return self.cache[fileHash]["scan"],self.cache[fileHash]["logStrList"]
        if mThread:
            matches = self.rule.getMatchesMultithread(filePath)
        else:
            matches = self.rule.getMatches(filePath)
        for rule in self.ruleset:
            if fileHash in self.whitelist:  
                flag,data,logstring = rule.scan(filePath,fileHash,matches,whitelist=True)
            else:
                flag,data,logstring = rule.scan(filePath,fileHash,matches,whitelist=False)
            if flag: 
                scan.addEvent(Event(rule.name,rule.warning,data["severity"],data["whitelist"]))
            if logstring is not None: logStrList.append(logstring)
            
        #Store Cache
        self.cache[fileHash] = {
            "path":filePath,
            "scan":scan,
            "logStrList":logStrList
        }
        return scan,logStrList
    