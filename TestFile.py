from Cipher import Cipher as cph

p_text = "This is a test text string"
key = cph.RSA.generate_keypair(1000,10000)
c_text = cph.RSA.encrypt_RSA(p_text,key[0])
print(c_text)
p_text = cph.RSA.decrypt_RSA(c_text,key[1])
print(p_text)