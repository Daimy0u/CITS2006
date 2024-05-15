from MTD_Utils import *
def write(path):
    MTD_Utils.MTD_Decrypt(path)
    file = open(path, "a")
    #file.write("adding some stuff")
    #file.close()
write("/home/aarya/Documents/Uni/cyber/project/CITS2006/rba/something.txt")