from Cipher import *
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
    public, private = Cipher.RSA.generate_keypair(10000, 100000)
    text = "RSA Example"
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


XOR()
RSA()
Base64()
