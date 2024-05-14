from .models.rules import *

class ExternalRule(BaseRule):
    def __init__(self,yaraRule:YaraRule):
        super().__init__(name="External Rule",
                         desc="",
                         outputWarning="",
                         
                         