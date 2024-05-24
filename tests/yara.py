import os,sys
import hashlib

def run(base,testDir,engineClass,logPath):
    with open(logPath, "a") as logFile:
        scan(base,testDir,engineClass,logFile)

def scan(base,testDir,engineClass,logFile):
    if type(base) == engineClass:
        engine = base
    else: engine = engineClass(base)
    
    for fName in os.listdir(testDir):
        fpath = testDir + "/" + fName
        
        if os.path.isdir(fpath):    
            scan(engine,fpath,engineClass)
            continue
        print(f"Scanning {fpath}")
        with open(fpath, 'rb') as f:  
            fhash = hashlib.sha256(f.read()).hexdigest()
        sdata,lst = engine.scan(fpath,fhash)
        for logStr in lst:
            print(logStr)
            logFile.write(logStr)
if __name__ == "__main__":
    run(str(sys.argv[1]),str(sys.argv[2]))