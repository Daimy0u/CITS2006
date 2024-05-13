from abc import abstractmethod
from typing import Tuple, TypeAlias, Optional
import yara

#Typing
Flag : TypeAlias = bool
OutputWarning : TypeAlias = str
Output : TypeAlias = list

class YaraRule:
    def __init__(self, ruleFilePath):
        self.rules = [yara.compile(ruleFilePath)]
        self.matchData = {}
    
    def addRule(self, ruleFilePath):
        self.rules.append(yara.compile(ruleFilePath))

    def getMatches(self, filePath, hashStr: Optional[str], overwriteCache = False):
        if hashStr and (hashStr in self.matchData.keys()) and not overwriteCache: return self.matchData[hashStr]
        res = {}
        for r in self.rules:
            for m in r.match(filePath):
                res[m.rule] = True
        if hashStr:
            self.matchData[hashStr] = res
        return res
    
        
class Rule:
    def __init__(self,name:str,desc:str,outputWarning:str,yaraRule:YaraRule):
        self.name = name
        self.desc = desc
        self.warning = outputWarning
        self.rules = yaraRule
    
    @abstractmethod
    def scan(self,file):
        pass

    def __output(self,output,flag) -> dict:
        return {"flag":flag,"warning":self.warning,"output":output}