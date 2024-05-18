from abc import abstractmethod
from typing import TypeAlias
import yara

#Typing
Flag : TypeAlias = bool
OutputWarning : TypeAlias = str
Output : TypeAlias = list

SEVERITY_TABLE = {
    0:"WHITELIST",
    1:"BENIGN",
    2:"LOW",
    3:"MODERATE",
    4:"SEVERE",
    5:"CRITICAL"
}
class YaraRule:
    """
    Built-in Yara Parser with Caching and multi-rule capabilities.

    addRule(str) - add rule to set using .yar file path
    getMatches(args) - returns dict of rule matches.

    """
    def __init__(self, ruleFilePath,mThread=False):
        self.mThread = mThread
        if not mThread:
            self.rules = [yara.compile(ruleFilePath)]
        else: self.rules = []
        self.matchData = {}
        self.rulePath = [ruleFilePath]
    
    def addRule(self, ruleFilePath):
        if not self.mThread:
            self.rules.append(yara.compile(ruleFilePath))
        self.rulePath.append(ruleFilePath)

    def getMatches(self, filePath):
        res = {}
        for r in self.rules:
            for m in r.match(filePath):
                if m.rule not in res.keys():
                    res[m.rule] = {}
                res[m.rule][filePath] = [str(x.instances) for x in m.strings]
        return res
    
    def getMatchesMultithread(self, filePath):
        """Thread-safe method of matching, compiles rules for each run.

        Args:
            filePath (_type_): _description_

        Returns:
            dict: key(str:rule), value(list[str:instance])
        """
        res = {}
        for rP in self.rulePath:
            r = yara.compile(rP)
            for m in r.match(filePath):
                if m.rule not in res.keys():
                    res[m.rule] = {}
                res[m.rule][filePath] = [str(x.instances) for x in m.strings]
        return res    
        
class BaseRule:
    """
        Custom Rule Class, for python-yara logic integration.
    """
    def __init__(self,name:str,desc:str,outputWarning:str,severity=4):
        """
        Create new custom py-yara rule.
        
        Metadata: 
            name(str) 
            desc(str),
            outputWarning(str): Short effective user notification message
        
        Args:
            yaraRule(YaraRule) : Built-in Rule Parser Class,
            severity(int): 1=BENIGN, 2=LOW, 3=MODERATE, 4=SEVERE, 5=CRITICAL
        """
        self.name = name
        self.desc = desc
        self.warning = outputWarning
        self.severity = severity
        self.instances = {}
    
    @abstractmethod
    def scan(self,filePath,fileHash):
        pass
    
    def getInstances(self):
        return self.instances
    
    def infoPositive(self,filePath:str,fileHash:str,whitelist=False,severity=None,extraInfo="") -> tuple:
        """
        Returns:
            [
            Trigger(bool): True for Whitelist/Positive, False for No Trigger
            ]
        """
        if fileHash not in self.instances:
            self.instances[fileHash] = filePath
        if severity is None:
            severity = SEVERITY_TABLE[self.severity]
        else: 
            severity = SEVERITY_TABLE[severity]
        return [True,self.infoDict(whitelist,severity),self.infoStr(filePath,fileHash,severity,extraInfo)]
    
    def infoNegative(self) -> tuple:
        return [False,None,None]

    
    def infoDict(self,whitelist=False,severity=None) -> dict:
        """
        ENSURE THIS IS STORED IN A MEMORY - WITH FILE HASH AS KEY!
        """
        return  {
                "severity":severity,
                "whitelist":whitelist
                }
    
    def infoStr(self,fileName,fileHash,severity,extraInfo="") -> str:
        return f"{severity} | {self.name} | {self.warning + extraInfo} | {fileName} | {fileHash}"
    