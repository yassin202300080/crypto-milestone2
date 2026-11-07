import socket
from des import KEY, ecb_decrypt, show_blocks

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   
server.bind(("127.0.0.1", 5000))
server.listen()
print(f"[SERVER] Listening on 127.0.0.1:5000  (DES-ECB, key {KEY.decode()})")

while True:
    conn, addr = server.accept()

    ciphertext = b""
    while True:
        chunk = conn.recv(1024)
        if not chunk:
            break
        ciphertext += chunk

    print(f"\n[SERVER] From {addr[0]}:{addr[1]}")
    print(f"[SERVER] Ciphertext : {show_blocks(ciphertext)}")
    print(f"[SERVER] Decrypted  : {ecb_decrypt(ciphertext).decode()}")
    conn.close()
