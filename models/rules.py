from abc import abstractmethod
from typing import Tuple, TypeAlias
import yara

#Typing
Flag : TypeAlias = bool
Output : TypeAlias = str
Path : TypeAlias = str

class YaraRule:
    def __init__(self, ruleFilePath):
        self.rules = [yara.compile(ruleFilePath)]
    
    def addRule(self, ruleFilePath):
        self.rules.append(yara.compile(ruleFilePath))

    def getMatches(self, filePath):
        res = {}
        for r in self.rules:
            for m in r.match(filePath):
                res[m.rule] = True
        return res
    
        
class Rule:
    def __init__(self,name:str,desc:str,outputMsg:str,yaraRule:YaraRule):
        self.name = name
        self.desc = desc
        self.output = outputMsg
        self.rules = yaraRule
    
    @abstractmethod
    def scan(self,file):
        pass

    def __output(self,path,flag) -> Tuple[Flag,
                                          Output,
                                          Path]:
        return [flag,self.outputMsg,path]