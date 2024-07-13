

The encryption code:

```python
#!/usr/local/bin/python
if __name__ != "__main__":
    raise Exception("not a lib?")

from os import urandom
# check if seed.txt exists
try:
    seed = open("seed.txt", "rb").read()
except:
    seed = urandom(8)
    open("seed.txt", "wb").write(seed)

seed = int.from_bytes(seed, "big")
import random
random.seed(seed)
from ast import literal_eval
idxs = literal_eval(input(">>> "))
if len(idxs) > 8:
    print("Ha thats funny")
    exit()
for idx in range(624):
    rand_out = random.getrandbits(32)
    if idx in idxs:
        print(rand_out)


key = random.getrandbits(256)
nonce = random.getrandbits(256)
flag = open("flag.txt").read()
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256
aes_key = sha256(str(key).encode()).digest()[:16]
aes_nonce = sha256(str(nonce).encode()).digest()[:16]
cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
ct = cipher.encrypt(pad(flag.encode(), 16))
print(ct.hex())
```


The encryption code encodes the flag using AES and then prints out its hex.
We solve this by finding out the key and nonce used to encrypt. 
We can do this by cracking the Mersenne Twister PRNG that powers the python random library


The code generates 624 random numbers, each one with its own index of sorts.


We query the program for all 624 numbers. However at a time it only expects 8 numbers at a time, after which it ends the connection. Thus we need to separately query 624/8 = 78 times.


```py
from pwn import *
import randcrack


ct_hex= "cb3cc14d2f5eeac6b5645bb66fa268d88399d1654df20668110e1d04bf135db71930985b5eba307c0197b035f2e9203f"
ct = bytes.fromhex(ct_hex)
mainArr = []
def send8Rands(n: int, bigarr):
    main = process(["nc", "vsc.tf", "5001"])
    arr = []
    main.recv()
    for i in range(8):
        arr.append(str(i+n))
    s=f'[{",".join(arr)}]'
    main.sendline(s.encode())
    sleep(0.01)
    [bigarr.append(int(k)) for k in main.recv().decode().split()[:-1]]
    main.close()


for i in range(78):
    send8Rands(8*i, mainArr)
```
We use pwn tools and keep sending 8 numbers each connection; [0,1,2,3,4,5,6,7,8] in one connection and [9,10,11,12,13,14,15,16] in the next and so on. The random numbers returned are then stored in the mainArr


Once we have the 624 numbers, we can use the `randcracker` module for cracking MT and predicting the key and nonce.
```py

rc = randcrack.RandCrack()


for output in mainArr:
    rc.submit(output)

key = rc.predict_getrandbits(256)
nonce = rc.predict_getrandbits(256)
```

Once we have the key and nonce, its simply a matter of obtainiing the flag from ct_hex

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

aes_key = sha256(str(key).encode()).digest()[:16]
aes_nonce = sha256(str(nonce).encode()).digest()[:16]
cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)

plaintext_padded = cipher.decrypt(ct)
flag = unpad(plaintext_padded, 16).decode()

print("Decrypted flag:", flag)
```




