from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

from base64 import b64decode
from Crypto.Util.Padding import unpad

class CBC:

    # def __init__(self):
    #     print("hello cbc")

    def encrypt(self , plaintext):
        sensitive_data = plaintext.encode('utf-8')
        key = get_random_bytes(16) #must be 16, 24 or 32 bytes long
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(sensitive_data, AES.block_size))
        enc = {
            "iv":f"{b64encode(cipher.iv).decode('utf-8')}",
            "ciphertext":f"{b64encode(ciphertext).decode('utf-8')}",
            "key":f"{b64encode(key).decode('utf-8')}"
        }
        return enc

    def decrypt(self , iv , ciphertext , key):
        try:
            iv = b64decode(iv)
            ciphertext = b64decode(ciphertext)
            key = b64decode(key)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return plaintext.decode('utf-8')
            # print("Original Message was: ",  plaintext.decode('utf-8'))
        except (ValueError, KeyError):
            print("ERROR!") 

# obj = CBC()
# data = obj.encrypt("ALIENS DO EXIST!!!!")
# # print(data["ciphertext"])
# obj.decrypt(data["iv"] , data["ciphertext"] , data["key"])