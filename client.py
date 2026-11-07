import socket
from des import KEY, ecb_encrypt, show_blocks

message = input("[CLIENT] Enter message: ")
ciphertext = ecb_encrypt(message.encode())

print(f"[CLIENT] Key        : {KEY.decode()}")
print(f"[CLIENT] Plaintext  : {message}")
print(f"[CLIENT] Ciphertext : {show_blocks(ciphertext)}")

client = socket.socket()
client.connect(("127.0.0.1", 5000))
client.sendall(ciphertext)
client.close()   
print("[CLIENT] Sent to server")
