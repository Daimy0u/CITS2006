import sys
from tests.demo import Demo

def main(arg1,arg2,arg3):
    demo = Demo()
    demo.yara(arg1,arg2)
    
    
if __name__ == "__main__":
    if sys.argv[1]:
        arg1 = str(sys.argv[1])
        if sys.argv[2]:
            arg2 = str(sys.argv[2])
            if sys.argv[3]:
                arg3 = str(sys.argv[3])
            else:
                arg3 = None
        else:
            arg2 = None
    else:
        arg3 = None
    main(arg1,arg2,arg3)