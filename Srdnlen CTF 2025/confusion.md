# Confusion
##  SrdnlenCTF 2025 : Cryptography

```python
#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
# Local imports
FLAG = os.getenv("FLAG", "srdnlen{REDACTED}").encode()

# Server encryption function
def encrypt(msg, key):
    pad_msg = pad(msg, 16)
    blocks = [os.urandom(16)] + [pad_msg[i:i + 16] for i in range(0, len(pad_msg), 16)]
    b = [blocks[0]]
    for i in range(len(blocks) - 1):
        tmp = AES.new(key, AES.MODE_ECB).encrypt(blocks[i + 1])
        b += [bytes(j ^ k for j, k in zip(tmp, blocks[i]))]

    c = [blocks[0]]
    for i in range(len(blocks) - 1):
        c += [AES.new(key, AES.MODE_ECB).decrypt(b[i + 1])]

    ct = [blocks[0]]
    for i in range(len(blocks) - 1):
        tmp = AES.new(key, AES.MODE_ECB).encrypt(c[i + 1])
        ct += [bytes(j ^ k for j, k in zip(tmp, c[i]))]

    return b"".join(ct)


KEY = os.urandom(32)

print("Let's try to make it confusing")
flag = encrypt(FLAG, KEY).hex()
print(f"|\n|    flag = {flag}")

while True:
    print("|\n|  ~ Want to encrypt something?")
    msg = bytes.fromhex(input("|\n|    > (hex) "))

    plaintext = pad(msg + FLAG, 16)
    ciphertext = encrypt(plaintext, KEY)

    print("|\n|  ~ Here is your encryption:")
    print(f"|\n|   {ciphertext.hex()}")
```

In this challenge we have been given an oracle for a custom encryption using AES as a subroutine to encrypt our message appended with the flag.

Notation wise: $m=m_1m_2m_3\ldots m_n$ and $f = f_1f_2f_3\ldots f_n$

Analysing the encrypt function gives the following pattern:

$$ A = [m_0, m_1, m_2, \ldots m_n] \leftarrow M, \text{ where } m_i = M[32(i-1):32i]$$
$$B = [b_0, b_1, b_2, \ldots b_n] \leftarrow A \text{ where } b_i = AES_k(m_i)\oplus m_{i-1} $$
$$C = [c_0, c_1, c_2, \ldots c_n] \leftarrow B \text{ where } c_i = AES^{-1}_k(b_i)$$
$$ct = [ct_0, ct_1, ct_2 \ldots ct_n] \leftarrow C \text{ where } ct_i = AES_k(c_i)\oplus c_{i-1}$$

Note that here $m_0 = b_0 = c_0 = ct_0 = r$ for some random $r$. Now writing everything in terms of $m_i$ we get:

$$ B = [r,\quad AES_k(m_1)\oplus r, \quad AES_k(m_2)\oplus m_1 \quad \ldots \quad AES_k(m_n)\oplus m_{n-1}]$$
$$ C = [r, \quad AES_k^{-1}(AES_k(m_1)\oplus r), \quad AES_k^{-1}(AES_k(m_2)\oplus m_1) \quad \ldots \quad AES_k^{-1}(AES_k(m_n)\oplus m_{n-1})]$$
$$ ct = [r, \: AES_k(m_1), \: AES_k(m_2)\oplus m_1\oplus AES_k^{-1}(AES_k(m_1)\oplus r), \\\: \ldots \: AES_k(m_n)\oplus m_{n-1}\oplus AES_k^{-1}(AES_k(m_{n-1})\oplus m_{n-2})]$$

Also we are given the ciphertext for the flag along with the encryption oracle, say $ct_f$. To find the decryption of the flag's ct we need to somehow use the oracle to find decryptions of messages. Looking at the final form of ct, the fourth term is the one which is the most helpful.
$$ct[3] = AES_k(m_3)\oplus m_2\oplus AES_k^{-1}(AES_k(m_2)\oplus m_1)$$
Since we can encrypt arbitrarily long messages, we have complete control over $m_1, m_2$ and $m_3$. Also notice that $m_1$ occurs only once in the term so we can substitute it with an unknown term without worrying about it causing any unnecessary side effects. This motivates the idea to extract the flag: substitute $m_1 = AES_k(f_i)\oplus AES_k(0)$, $m_2 = 0$, $m_3 = 0$. This will give us the output, $ct[3] = AES_k(0) \oplus f_i$. Then taking the xor of $ct[3]$ and $AES_k(0)$ will give us a block of the flag. Note that we can find $AES_k(0)$ by sending the message as $m=00$ (a full block of zeroes) and taking the second term of the ciphertext. To find out $AES_k(f_i)$ however, we have to do a little more work.

For $i=1$ just take the second term of encryption of flag. For $i=2$, send $m=00$ (a block of zeroes) and the 4th term of the ct collapses to $AES_k(f_2)$, since $m_{padded} =00 f_1 f_2\ldots f_n$ and  For subsequent $i$, we use the following inductive procedure:
1. Send $m=f_{i-2} f_{i-1} 00$ and extract $ct[3] = AES_k(0)\oplus f_{i-1} \oplus AES_k^{-1}(AES_k(f_{i-1})\oplus f_{i-2})$
2. Extract $ct_f[i] = AES_k(f_i) \oplus f_{i-1} \oplus AES_k^{-1}(AES_k(f_{i-1})\oplus f_{i-2})$
3. Calculate $ct_f[i] \oplus ct[3] \oplus AES_k(0) = AES_k(f_i)$

This sums up the protocol.

```python
from pwn import *

# context.log_level = 'debug'

# io = process('./chall.py')
io = remote('confusion.challs.srdnlen.it', 1338)

io.recvuntil(b'flag = ')
flag = io.recvline().strip().decode()
log.info(f'flag: {flag}')
af1 = flag[32:64]
r5 = flag[96:128]
r7 = flag[128:160]

io.sendlineafter(b'> (hex) ', b'00'*32)
io.recvuntil(b'Here is your encryption:')
io.recvline()
io.recvuntil(b'| ')
ct = io.recvline().strip().decode()
log.info(f'ct: {ct}')
a0 = ct[32:64]

payload = int(a0, 16) ^ int(af1, 16)
io.sendlineafter(b'> (hex) ', hex(payload)[2:].encode()+b'00'*16)
io.recvuntil(b'Here is your encryption:')
io.recvline()
io.recvuntil(b'| ')
ct = io.recvline().strip().decode()
log.info(f'ct: {ct}')
x = ct[96:128]
f1 = int(x, 16) ^ int(af1, 16)
f1 = hex(f1)[2:]
log.info(f'f1: {bytes.fromhex(f1).decode()}')


io.sendlineafter(b'> (hex) ', b'00'*16)
io.recvuntil(b'Here is your encryption:')
io.recvline()
io.recvuntil(b'| ')
ct = io.recvline().strip().decode()
log.info(f'ct: {ct}')
af2 = ct[96:128]

payload2 = int(af2,16)^int(af1,16)
io.sendlineafter(b'> (hex) ', b'00'*16 + hex(payload2)[2:].encode())
io.recvuntil(b'Here is your encryption:')
io.recvline()
io.recvuntil(b'| ')
ct = io.recvline().strip().decode()
log.info(f'ct: {ct}')
x = ct[128:160]
f2 = int(x, 16) ^ int(af2, 16) ^ int(f1, 16)
f2 = hex(f2)[2:]
log.info(f'f2: {bytes.fromhex(f2).decode()}')

io.sendlineafter(b'> (hex) ', (f1+f2).encode())
io.recvuntil(b'Here is your encryption:')
io.recvline()
io.recvuntil(b'| ')
ct = io.recvline().strip().decode()
log.info(f'ct: {ct}')
r3 = ct[96:128]
af3 = int(r3, 16) ^ int(r5, 16) ^ int(af1, 16)

payload3 = af3 ^ int(a0, 16)
payload3 = hex(payload3)[2:]
io.sendlineafter(b'> (hex) ', payload3.encode()+b'00'*32)
io.recvuntil(b'Here is your encryption:')
io.recvline()
io.recvuntil(b'| ')
ct = io.recvline().strip().decode()
log.info(f'ct: {ct}')
r3 = ct[96:128]
f3 = int(r3, 16) ^ int(a0, 16)
f3 = hex(f3)[2:]
log.info(f'f3: {bytes.fromhex(f3).decode()}')

io.sendlineafter(b'> (hex) ', (f2+f3).encode())
io.recvuntil(b'Here is your encryption:')
io.recvline()
io.recvuntil(b'| ')
ct = io.recvline().strip().decode()
log.info(f'ct: {ct}')
r3 = ct[96:128]
af4 = int(r3, 16) ^ int(r7, 16) ^ int(af1, 16)

payload3 = af4 ^ int(a0, 16)
payload3 = hex(payload3)[2:]
io.sendlineafter(b'> (hex) ', payload3.encode()+b'00'*32)
io.recvuntil(b'Here is your encryption:')
io.recvline()
io.recvuntil(b'| ')
ct = io.recvline().strip().decode()
log.info(f'ct: {ct}')
r3 = ct[96:128]
f4 = int(r3, 16) ^ int(a0, 16)
f4 = hex(f4)[2:]
log.info(f'f3: {bytes.fromhex(f4).decode()}')

flag = f1+f2+f3+f4
print(f'flag: {bytes.fromhex(flag).decode()}')
```
