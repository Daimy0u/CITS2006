from yara_engine.Engine import YaraEngine
import hashlib
import os

current_directory = os.getcwd()
files = os.listdir(current_directory)
    
engine = YaraEngine()
for fPath in files:
    fHash = hashlib.md5(open(fPath,'rb').read()).hexdigest()
    sData, lList = engine.scan(fPath,fHash)
    for l in lList:
        print(l)
    
    print(sData.events,sData.sum)
    
