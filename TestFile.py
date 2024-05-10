from Cipher import *

p_text = "This is a test string yipee"


p_text = p_text.encode()
c = Cipher.Base64.encode(p_text)
print(c)
p = Cipher.Base64.decode(c)
p = p.decode()
print(p)