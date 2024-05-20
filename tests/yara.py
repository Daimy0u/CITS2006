import os,sys
import hashlib
from src.lib.hash.hash_sha256 import sha256
from src.lib.yara_engine.Engine import YaraEngine

def run(base,testDir):
    if type(base) == YaraEngine:
        engine = base
    else: engine = YaraEngine(base)
    
    for fName in os.listdir(testDir):
        fpath = testDir + "/" + fName
        if os.path.isdir(fpath):
            run(engine,fpath)
            continue
        print(f"Scanning {fpath}")
        with open(fpath, 'rb') as f:  
            fhash = hashlib.sha256(f.read()).hexdigest()
        sdata,lst = engine.scan(fpath,fhash)
        for logStr in lst:
            print(logStr)

if __name__ == "__main__":
    run(str(sys.argv[1]),str(sys.argv[2]))