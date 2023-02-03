from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP

def generate_keys():
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()

    return private_key, public_key

def get_session_key():
    return Random.new().read(AES.block_size)

def encrypt_session_key(client_public_key, session_key):
    rsa_encrypt = PKCS1_OAEP.new(client_public_key)
    enc_session_key = rsa_encrypt.encrypt(session_key)
    return enc_session_key

def decrypt_session_key(private_key, enc_session_key):
    rsa_decrypt = PKCS1_OAEP.new(private_key)
    session_key = rsa_decrypt.decrypt(enc_session_key)
    return session_key

def encrypt_AES(session_key, message):
    pad = AES.block_size - (len(message) % AES.block_size)
    message += bytes([pad]) * pad

    cipher_AES = AES.new(session_key,AES.MODE_CBC,session_key)
    ciphertext = cipher_AES.encrypt(message)
    return ciphertext

def decrypt_AES(session_key, data):
    cipher_AES = AES.new(session_key,AES.MODE_CBC,session_key)
    plain_text = cipher_AES.decrypt(data)
    plain_text = plain_text[:-plain_text[-1]]
    return plain_text

