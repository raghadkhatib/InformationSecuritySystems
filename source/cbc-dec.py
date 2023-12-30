from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

try:
    iv = b64decode('V3/oW179L1BRtRP11Nfc/w==')
    ciphertext = b64decode('0W6tw7CduTlymN8tOeWAL4UhCuu0ItyV7oZ7q3JWx3k=')
    key = b64decode('jbFlVdSLxI7kWkQTTjvoyQ==')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    print("Original Message was: ", plaintext)
except (ValueError, KeyError):
    print("ERROR!") 

#Sample output
#Original Message was:  b'ALIENS DO EXIST!!!!'