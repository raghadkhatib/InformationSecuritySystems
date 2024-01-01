from pgpy import PGPKey
from pgpy.constants import PubKeyAlgorithm, KeyFlags

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

import sys
import pgpy

from pgpy.constants import (
    PubKeyAlgorithm, KeyFlags, HashAlgorithm,
    SymmetricKeyAlgorithm, CompressionAlgorithm)
from subprocess import Popen, PIPE
from tempfile import mkdtemp

class Hyper:
    def generate_key_pair(self , file_name):
        # Generate an RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Get the public key
        public_key = private_key.public_key()

        # Serialize the private key to PEM format and save it to a file
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(file_name+'private_key.pem', 'wb') as f:
            f.write(private_key_pem)

        # Serialize the public key to PEM format and save it to a file
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(file_name+'public_key.pem', 'wb') as f:
            f.write(public_key_pem)

    def pgp(self , file_name):
        # we can start by generating a primary key.we use RSA
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

        # we now have some key material, but our new key doesn't have a user ID yet, and therefore is not yet usable!
        uid = pgpy.PGPUID.new(file_name, comment= file_name, email= file_name+'@unisite.gov')

        # now we must add the new user id to the key. We'll need to specify all of our preferences at this point
        key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                    hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
                    ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
                    compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
        # Save the private key
        with open(file_name+"private_key.asc", "w") as f:
            f.write(str(key))

        # Save the public key
        with open(file_name+"public_key.asc", "w") as f:
            f.write(str(key.pubkey))

        return key

    # def pgpy_encrypt(key, data):
    #     message = pgpy.PGPMessage.new(data)
    #     enc_message = key.pubkey.encrypt(message)
    #     return bytes(enc_message)

def pgpy_encrypt(key, data):
    message = pgpy.PGPMessage.new(data)
    enc_message = key.encrypt(message)
    return bytes(enc_message)
    # return enc_message

def pgpy_decrypt(key, enc_data):
    message = pgpy.PGPMessage.from_blob(enc_data)
    # return str(key.decrypt(message).message).split("(")[1].split(")")[0]
    return key.decrypt(message).message
