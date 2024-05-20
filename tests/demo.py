from src import *
import tests

class Demo:
    def yara(arg1,arg2):
        tests.TestFile(arg1,arg2)
    
    def mtd(arg1,arg2,arg3):
        #TODO: Call MTD
        return

    def cipher(arg1,arg2,arg3):
        #TODO: Call Cipher Tests
        return

    def hash(arg1,arg2,arg3):
        #TODO:Call Hash
        return
    
    def main(self,cmd,arg1=None,arg2=None,arg3=None):
        match cmd:
            case "yara":
                self.yara(arg1,arg2)
            case _:
                print(f"Invalid mode: {cmd}")