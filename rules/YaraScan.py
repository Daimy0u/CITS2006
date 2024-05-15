from abc import abstractmethod

from models.rules import *
import os
import yara

current_directory = os.getcwd()
files = os.listdir(current_directory)

BASE = current_directory + '/base.yar'
EXTERNAL_RULES = current_directory + '/index-ext.yar'
WHITELIST = current_directory + '/whitelist.json'
HiddenExecutable = " "

class Executable(Rule):
    def __init__(self, rule:YaraRule):
        super().__init__(name="Executable", 
                         desc="Detect ELF Files",
                         outputWarning="Unauthorized Executable ELF File!",
                         rule=rule)

    def scan(self,yaraRule:YaraRule,filePath,fileHash)-> dict:
        matches = self.rules.getMatches(filePath)
        ext = filePath[-5:].split('.')[1]
        flag = False
        if 'isExecutable' in matches:
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

class SuspiciousUrl(Rule):
    def __init__(self, rule:YaraRule):
        super().__init__(name="Suspicious URL", 
                         desc="Detect Suspicious Non-Standard TLD URL Access",
                         outputWarning="Suspicious URL Detected!",
                         rule=rule)
    def scan(self,yaraRule:YaraRule,filePath,fileHash):
        return 


#["HiddenExecutable":[True,"File is an executable but has mismatched extension!",/something/...],"SuspiciousUrl":[False,"",]]
class RuleContainer:
    DEFAULT = [HiddenExecutable]

    def initYaraRules(self):
        return 
    def __init__(self):
        rules = load.getYaraRules()



    