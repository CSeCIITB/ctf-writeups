# Overview
This challenge consists of extracting the information about the flag which has been embedded into an image.

The majority of the embedding has been done with the help of random numbers. However, a fixed manual seed at the beginning is what allows us to reproduce the random numbers and thus find the flag.

# Working of the encoder

The flag is read as a binary and the `skibidi.png` image is opened.

The flag is first converted to bytes. Each byte is padded appropriately and then saved as a string.

Using a randomly shuffled array `inds`, each character of the string (ie each individual bit of the flag) is shuffled.

```python

flag = open("flag.txt", "rb").read()

st = ""
for i in bytearray(flag):
    tmp = bin(i)[2:]
    while(len(tmp))<8:
        tmp = "0"+tmp
    st+=tmp
inds = [i for i in range(288)]
randnum = random.randint(1,500)


for i in range(random.randint(0,500), random randint(500,1000)):
    random.seed(i)
    random.shuffle(inds)
    if i==randnum:
        break

new_flag = "".join([st[i] for i in inds])
```
---




Next, each bit in the flag is embedded into the image by first choosing a random pixel of the image, then choosing a colour channel (ex: red from rgb) and replacing the LSB of the chosen colour value with the flag bit
```python
colors = list(img.getpixel((row,col)))
    troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))
    change = random.randint(0,2)
    troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))
    colors[change] = (colors[change]& 0b11111110) | int(new_flag[i])
    troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))
    img.putpixel((row,col),tuple(colors))
```

---
Note: the code has numerous `troll` statements.
```python
troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))
```
The purpose of these trolls is simpy to reseed the RNG
# Solving

The key idea here is that since the seed for the generator is the same, we get the same output each time



In order to get the flag, we need to get each bit that's embedded, then unshuffle it, then convert to string

In order to get the bits, we simply rerun the same code but with slight modifications. We remove the reading of flag file and shuffling of bits. In place of accessing random pixels and modifying the LSB of a random colour channel, we simply append the colour channel value's LSB to an array.

Since we haven't removed any seed or used random() different number of times than the encoder, we end up choosing the same pixels and colour channels as the encoder. 

```python
colors = list(img.getpixel((row,col)))
change = random.randint(0,2)
new_flag.append(colors[change]& 0b00000001)
```


Once we recieve all the bytes, we use the initial shuffled array `inds` as it contains where each bit should go.

```python
flag_bytes = [0 for i in range(len(new_flag))]
for i in range(len(new_flag)):
flag_bytes[inds[i]] = new_flag[i]
```


Once we have the bytes, we simply, convert it back to a string

```python
for i in range(0, len(flag_bytes), 8):
    print(chr(int("".join(map(str, flag_bytes[i:i+8])), 2)), end="")
```


---
Flag: tjctf{th@t_m@d3_m3_g0_1n5an3333!!!!} 


Here is the entire decoder code
```python
from PIL import Image

import random

random.seed(42)

lmao = random.randint(12345678,123456789)

random.seed(lmao)

img = Image.open("skibidi_encoded.png")

width, height = img.size

troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))

inds = [i for i in range(288)]

troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))

randnum = random.randint(1,500)

troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))

for i in range(random.randint(0,500), random.randint(500,1000)):
    random.seed(i)
    random.shuffle(inds)
    if i==randnum:
        break

troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))

troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))

troll = [random.randint(random.randint(-lmao,0),random.randint(0,lmao)) for _ in range(random.randint(1,5000))]

troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))

pic_inds = []
while len(pic_inds)!=288:
    troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))
    temp = random.randint(0,width*height)
    # print(f"temp: {temp}")
    pic_inds.append(temp)
    
    troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))
new_flag = []
pixel_accessed_arr = []
for i in range(288):
    troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))
    troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))
    troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))
    troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))
    troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))
    
    cur_ind = pic_inds[i]
    row = cur_ind//height
    col = cur_ind%width
    colors = list(img.getpixel((row,col)))

    
    change = random.randint(0,2)
    new_flag.append(colors[change]& 0b00000001) 
    
    troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))
    troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))
    troll = random.randint(random.randint(-lmao,0),random.randint(0,lmao))
    if(i%randnum==0):
        random.seed(random.randint(random.randint(-lmao,0),random.randint(0,lmao)))


flag_bytes = [0 for i in range(len(new_flag))]
for i in range(len(new_flag)):
    flag_bytes[inds[i]] = new_flag[i]
for i in range(0, len(flag_bytes), 8):
    print(chr(int("".join(map(str, flag_bytes[i:i+8])), 2)), end="")
```
