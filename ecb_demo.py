
from des import KEY, ecb_encrypt, ecb_decrypt

repeat = input("Block to repeat (8 chars, Enter for 'PAY 250.'): ").strip() or "PAY 250."
other = input("Different block (8 chars, Enter for 'TO:ACC77'): ").strip() or "TO:ACC77"

repeat = repeat.ljust(8)[:8]
other = other.ljust(8)[:8]

plaintext = (repeat + repeat + other).encode()
ciphertext = ecb_encrypt(plaintext)

print(f"\nKey: {KEY.decode()}   Mode: DES-ECB\n")
for i in range(3):
    p = plaintext[i * 8:i * 8 + 8]
    c = ciphertext[i * 8:i * 8 + 8]
    print(f"Block {i + 1}:  {p.decode()}  ->  {c.hex().upper()}")
print(f"Block 4:  (padding)  ->  {ciphertext[24:].hex().upper()}")

print(f"\nBlock 1 ciphertext == Block 2 ciphertext?  {ciphertext[:8] == ciphertext[8:16]}")
print(f"Block 1 ciphertext == Block 3 ciphertext?  {ciphertext[:8] == ciphertext[16:24]}")
print("Same block + same key = same ciphertext, so an attacker sees the pattern without the key.")
print(f"Decrypted: {ecb_decrypt(ciphertext).decode()}")
