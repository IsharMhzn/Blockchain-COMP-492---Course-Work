import socket
from encryption import *

def generate_keys():
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()

    return private_key, public_key
    
def socket_server():
    # Generate new random key for the session
    session_key = get_session_key()

    # Get the hostname
    host = socket.gethostname()
    port = 5000

    # Get socket instance
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server.bind((host, port))

    # Server listen configuration
    server.listen(1) 
    conn, address = server.accept()
    print(f"Client {address} connected ...")

    # Get Client's public key
    client_public_key = RSA.import_key(conn.recv(2048))
    
    # Encrypt Session Key
    enc_session_key = encrypt_session_key(client_public_key, session_key)
    conn.send(bytes(enc_session_key))

    while True:
        data = conn.recv(2048)
        if not data:
            break
        
        print("Client's Encrypted Message: ", str(data))
        plain_text = decrypt_AES(session_key, data)

        print("Client's Decrypted Message: " + str(plain_text))
        print("-"*35)
        message = bytes(input('Response -> '), "utf-8")

        if message.lower().strip() ==b'quit':
            break
        
        ciphertext = encrypt_AES(session_key, message)
        conn.send(ciphertext)

    conn.close()

if __name__ == "__main__":
    socket_server()