from des import *

PT = b"Yassin26"
K = b"TKH#2027"

#round 1
ip = permute(to_bits(PT), IP)
L0, R0 = ip[:32], ip[32:]
key56 = permute(to_bits(K), PC1)     
C0, D0 = key56[:28], key56[28:]
C1 = C0[1:] + C0[0]                 
D1 = D0[1:] + D0[0]
K1 = subkeys(K)[0]
ER = permute(R0, E)
X = xor(ER, K1)
SB = sboxes(X)
F = permute(SB, P)
L1, R1 = des_round(L0, R0, K1)   

steps = [
    ("IP(P)", ip, "3FCDA01F00FE31EC"),
    ("L0", L0, "3FCDA01F"),
    ("R0", R0, "00FE31EC"),
    ("C0", C0, "0007F8F"),
    ("D0", D0, "DA81061"),
    ("C1", C1, "000FF1E"),
    ("D1", D1, "B5020C3"),
    ("K1", K1, "D084AE24058F"),
    ("E(R0)", ER, "0017FC1A3F58"),
    ("E(R0) XOR K1", X, "D093523E3AD7"),
    ("S-box output", SB, "9F62134B"),
    ("f(R0,K1)", F, "68FB6816"),
    ("L1", L1, "00FE31EC"),
    ("R1", R1, "5736C809"),
]

print(f"Plaintext {PT.decode()} = {PT.hex().upper()}   Key {K.decode()} = {K.hex().upper()}\n")
print(f"{'Step':<14}{'Code':<18}{'Handwritten':<18}Result")
ok = True
for name, bits, hand in steps:
    match = to_hex(bits) == hand
    if not match:
        ok = False
    print(f"{name:<14}{to_hex(bits):<18}{hand:<18}{'PASS' if match else 'FAIL'}")

print(f"\n{'S-box':<7}{'Input':<9}{'Row':<5}{'Col':<5}{'Code':<6}{'Handwritten':<13}Result")
hand_s = [9, 15, 6, 2, 1, 3, 4, 11]
for i in range(8):
    b = X[i * 6:i * 6 + 6]
    row = int(b[0] + b[5], 2)
    col = int(b[1:5], 2)
    v = S[i][row][col]
    match = v == hand_s[i]
    if not match:
        ok = False
    print(f"S{i + 1:<6}{b:<9}{row:<5}{col:<5}{v:<6}{hand_s[i]:<13}{'PASS' if match else 'FAIL'}")

def groups(bits, n):
    return " ".join(bits[i:i + n] for i in range(0, len(bits), n))

print()
print(f"K1 = {groups(K1, 6)}")
print(f"L1 = {groups(L1, 4)}")
print(f"R1 = {groups(R1, 4)}")

print()
vectors = [
    ("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),
    ("0E329232EA6D0D73", "8787878787878787", "0000000000000000"),
]
for key, pt, expected in vectors:
    ct = des_block(bytes.fromhex(pt), bytes.fromhex(key)).hex().upper()
    back = des_block(bytes.fromhex(ct), bytes.fromhex(key), decrypt=True).hex().upper()
    match = ct == expected and back == pt
    if not match:
        ok = False
    print(f"Test vector  key {key}  pt {pt} -> {ct}  {'PASS' if match else 'FAIL'}")

print(f"\nOnline check: key {K.hex().upper()}, data {PT.hex().upper()} -> expect {des_block(PT, K).hex().upper()}")
print("\nALL CHECKS PASSED" if ok else "\nSOME CHECKS FAILED")
