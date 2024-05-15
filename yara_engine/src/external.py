from .models.rules import *

class ExternalRule(BaseRule):
    def __init__(self,yaraRule:YaraRule):
        pass
        super().__init__(name="External Rule",
                         desc="",
                         outputWarning="")
        
                         
                         