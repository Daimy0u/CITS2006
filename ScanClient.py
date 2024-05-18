import hashlib,os,sys
from asyncio import run
from yara_engine import YaraEngineClient


def main(rulePath,testDir):
    import hashlib
    engine = YaraEngineClient(rulePath)
    for fName in os.listdir(testDir):
        fpath = testDir + "/" + fName
        print(f"Adding file to queue: {fpath}")
        with open(fpath, 'rb') as f:  
            fhash = hashlib.sha256(f.read()).hexdigest()
        engine.addFile(fpath,fhash)
    print("Starting Scan...")
    run(engine.queueProcess())
            
if __name__ == "__main__":
    main(str(sys.argv[1]),str(sys.argv[2]))