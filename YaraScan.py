from abc import abstractmethod
from .models.rules import *
import os
import yara

YARA_PATH = './Rules.yar'

class HiddenExecutable(Rule):
    def __init__(self, rule:YaraRule):
        super().__init__(name="Hidden Executable", 
                         desc="Detect Executable Bytes in a Non-Executable Format",
                         outputMsg="File is an executable but has mismatched extension!",
                         rule=rule)

    def scan(self,filePath)-> Tuple[Flag,Output | None,Path]:
        matches = self.rules.getMatches(filePath)
        ext = filePath[-5:].split('.')[1]
        flag = False
        if matches['isExecutable'] is True:
            match ext:
                case '.pdf':
                    flag = True
                case '.doc':
                    flag = True
                case '.docx':
                    flag = True
                case '.txt':
                    flag = True
                case '.xls':
                    flag = True
                case _:
                    flag = False
        if flag: return self.__output(flag,self.outputMsg,filePath)
        else: return self.__output(flag,None,filePath)




class RuleContainer:
    def __init__(self,yaraRulePath=YARA_PATH):
        self.rule = YaraRule(yaraRulePath)

    
