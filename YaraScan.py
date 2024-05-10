import yara
DEFAULT_DIRECTORY = '/home/'
FILE_DIRECTORY = '/Security'
    

class Rule:
    def __init__(self, ruleFilePath):
        self.rules = [yara.compile(ruleFilePath)]

    def getMatches(self, filePath):
        matches = []
        for r in self.rules:
            matches.append(r.match(filePath))
        return matches
    
    def run(self,filePath):
        result = []
        for match in self.getMatches(filePath):
            result.append((match.rule,filePath))
        return result
    
class RuleSet(Rule):

    def addRule(self, ruleFilePath):
        self.rules.append(yara.compile(ruleFilePath))
        

class DefaultImplementation:
    rule = FILE_DIRECTORY + '/Rules.yar'
    hashCheck = False

    @classmethod
    def __init__(cls,rule:str,ruleHashComparison:str):
        ##TODO: Compare Rule Hash with Fixed Known Hash - TO BE IMPLEMENTED
        #cls.hash = hash of rule
        cls.hashCheck = True
        return
    
    @classmethod
    def scanAll(cls):
        if cls.hashCheck is False:
            raise ValueError(f"Failed rule hash check!")
        #TODO
        pass

    @classmethod
    def scanFile(cls, filePath:str):
        pass
