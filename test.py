from yara_engine.Engine import YaraEngine
import hashlib
import os

current_directory = "\\Users\\yusuk\\Downloads\\test"
files = os.listdir(current_directory)
    
engine = YaraEngine("C:\\Users\\yusuk\\OneDrive - UWA\\Units\\CITS2006-DefCybersec\\Project\\CITS2006\\yara_engine\\rules\\base\\base.yar")
for fName in files:
    fPath = current_directory + "\\" + fName
    fHash = hashlib.md5(open(fPath,'rb').read()).hexdigest()
    sData, lList = engine.scan(fPath,fHash)
    print(lList)
    print([x.rule for x in sData.events],sData.sum)
    
    
