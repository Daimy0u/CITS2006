import yara
DEFAULT_DIRECTORY = '/home/'


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
    def __init__(self, ruleFilePath):
        super().__init__(yara.compile(ruleFilePath))

    def addRule(self, ruleFilePath):
        self.rules.append(yara.compile(ruleFilePath))
        

        
