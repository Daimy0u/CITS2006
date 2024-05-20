from modules.lib.cipher.Cipher import *
from modules.lib.hash.hash_sha256 import sha256
import sys
import os
from modules.lib.yara_engine.Engine import YaraEngine
#Only checking cipher system not file 
def XOR():
    print("\n\n")
    keyXOR = 'ThisIsA50CharacterLongKeyForEncryption1234567890!@'
    p_text = "XOR Example".encode()  # Encode string to bytes
    encrypted = Cipher.XOR.encryptBytes(p_text, keyXOR)
    print("XOR Encrypted:", encrypted)
    
    decrypted = Cipher.XOR.decryptBytes(encrypted, keyXOR)
    decrypted_text = decrypted.decode()  # Decode bytes to string
    print("XOR Decrypted:", decrypted_text)
    print("\n\n")


def RSA():

    text = "123456789"
    encrypted = Cipher.RSA.encrypt_RSA(text, public)  # Encrypt with public key
    print("RSA Encrypted:", encrypted)
    
    decrypted = Cipher.RSA.decrypt_RSA(encrypted, private)  # Decrypt with private key
    print("RSA Decrypted:", decrypted)
    print("\n\n")


def Base64():
    p_text = "Base64 Example".encode()  # Encode string to bytes
    encoded = Cipher.Base64.encode(p_text)
    print("Base64 Encoded:", encoded)
    
    decoded = Cipher.Base64.decode(encoded)
    decoded_text = decoded.decode()  # Decode bytes to string
    print("Base64 Decoded:", decoded_text)
    print("\n\n")

def Swap():

    
    # Define the text to be encrypted
    text = "123456789"
    print("Original text:", text)
    
    # Encrypt the text using the public key
    encrypted = Cipher.Swap.swap_encrypt(text, public)
    print("Swap Encrypted:", encrypted)
    
    # Decrypt the encrypted text using the private key
    decrypted = Cipher.Swap.swap_decrypt(encrypted, private)
    print("Swap Decrypted:", decrypted)
    print("\n\n")

public, private = Cipher.RSA.generate_keypair(10000, 100000)

def main(base,testDir):
    if type(base) == YaraEngine:
        engine = base
    else: engine = YaraEngine(base)
    
    for fName in os.listdir(testDir):
        fpath = testDir + "/" + fName
        if os.path.isdir(fpath):
            main(engine,fpath)
            continue
        print(f"Scanning {fpath}")
        with open(fpath, 'rb') as f:  
            fhash = sha256(f.read()).hexdigest()
        sdata,lst = engine.scan(fpath,fhash)
        for logStr in lst:
            print(logStr)

if __name__ == "__main__":
    main(str(sys.argv[1]),str(sys.argv[2]))