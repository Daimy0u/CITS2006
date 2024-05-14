import os
import json
from .models.rules import *

class Executable(BaseRule):
    def __init__(self, rule:YaraRule):
        super().__init__(name="Executable", 
                        desc="Detect ELF Files",
                        outputWarning="Unauthorized Executable ELF File!",
                        yaraRule=rule)
        
    def scan(self,filePath,fileHash,whitelist=False)->tuple:
        matches = self.rules.getMatches(filePath)
        if 'isExecutable' in matches:
            if whitelist:
                return self.__infoPositive(filePath,fileHash,whitelist,severity=0)
            else:
                return self.__infoPositive(filePath,fileHash,whitelist)
        else: 
            return self.__infoNegative()

class SuspiciousUrl(BaseRule):
    def __init__(self, rule:YaraRule):
        super().__init__(name="Suspicious URL", 
                        desc="Detect Suspicious Non-Standard TLD URL Access",
                        outputWarning="Suspicious URL Detected!",
                        yaraRule=rule,
                        severity=3)
        
    def scan(self,filePath,fileHash,whitelist=False)->tuple:
        matches = self.rules.getMatches(filePath)
        if 'isSketchyTLD' in matches:
            if whitelist:
                return self.__infoPositive(filePath,fileHash,whitelist,severity=0)
            else:
                return self.__infoPositive(filePath,fileHash,whitelist)
        else: 
            return self.__infoNegative()
        
class NetworkAccess(BaseRule):
    def __init__(self, rule:YaraRule):
       super().__init__(name="Network Access", 
                        desc="Detect Any Network Access by Files",
                        outputWarning="File has unauthorized network probing/access!",
                        yaraRule=rule,
                        severity=4)
        
    def scan(self,filePath,fileHash,whitelist=False)->tuple:
        matches = self.rules.getMatches(filePath)
        if 'isSketchyTLD' in matches:
            if whitelist:
                return self.__infoPositive(filePath,fileHash,whitelist,severity=0)
            else:
                return self.__infoPositive(filePath,fileHash,whitelist)
        else: 
            return self.__infoNegative()
    


class Base:
    """
    Base-set rules, made/tailored to the company.
    """    
    @classmethod
    def __init__(cls,basePath,whitelist=None):
        if whitelist is None: whitelist = []
        rule = YaraRule(basePath)
        cls.whitelist = whitelist
        cls.ruleset = [Executable(rule),SuspiciousUrl(rule),NetworkAccess(rule)]
        
    @classmethod
    def scan(cls, filePath:str, fileHash:str):
        """Returns only rules that are triggered for a file, and string for logging.

        Args:
            filePath (str): Individual File Path
            fileHash (str): Individual File Hash

        Returns:
            dict:   {
                        filePath:str
                        fileHash:str
                        triggered:bool
                        events:list [
                                        {
                                            "rule":str
                                            "warning":str
                                            "severity":str
                                            "whitelist":bool
                                        },...
                                    ]
                         
            str: f-string in a loggable format.
        """
        res = {}
        res["filePath"] = filePath
        res["fileHash"] = fileHash
        res["triggered"] = False
        res["events"] = []
        for rule in cls.ruleset:
            if fileHash in cls.whitelist:  
                flag,data,logstring = rule.scan(filePath,fileHash,whitelist=True)
            else:
                flag,data,logstring = rule.scan(filePath,fileHash,whitelist=False)
            if flag: 
                res["triggered"] = True
                res["events"].append(
                    {
                        "rule":rule.name,
                        "warning":rule.warning,
                        "severity":data["severity"],
                        "whitelist":data["whitelist"]
                    }
                )
        return res,logstring
            
                
    @classmethod
    def getInstances(cls):
        """
        Gets rule triggers, includes whitelisted files. Only processes files scanned.

        Returns:
            dict: {
                "ruleName":{
                    "fileHash":"filePath
                }
            }
        """
        res = {}
        for rule in cls.ruleset:
            res[rule.name] = rule.getInstances()
        return res
    