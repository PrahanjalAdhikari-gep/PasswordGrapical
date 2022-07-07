from os import urandom
from Crypto.Cipher import AES
import string
import random
import base64

# For Generating cipher text
secret_key = "abcdefghijklmnop".encode('utf8')
iv = urandom(16)
obj = AES.new(secret_key, AES.MODE_CBC, iv)

# Encrypt the message
message = 'Lorem Ipsum text'
print('Original message is: ', message)
encrypted_text = obj.encrypt(message.encode("utf8"))
print('The encrypted text', encrypted_text)

# Decrypt the message
rev_obj = AES.new(secret_key, AES.MODE_CBC, iv)
decrypted_text = rev_obj.decrypt(encrypted_text)
print('The decrypted text', decrypted_text.decode('utf-8'))

letters = string.ascii_letters + string.digits + string.punctuation.replace(',','/')
secret_key = "".join(random.choice(letters) for i in range(16))
iv= "".join(random.choice(letters) for i in range(16))
obj = AES.new(secret_key.encode("utf8"), AES.MODE_CFB, iv.encode("utf8"))
epts = obj.encrypt("1,2,34,55".encode("utf8"))
ebs = base64.b64encode(epts).decode()
print(type(ebs))
dec= AES.new(secret_key.encode("utf8"), AES.MODE_CFB, iv.encode("utf8"))
e=base64.b64decode(ebs.encode())
print(dec.decrypt(e).decode())
