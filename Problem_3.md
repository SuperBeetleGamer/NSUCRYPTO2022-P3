TL;DR:
We break a custom hash function by proving it is cryptographically weak and presenting a second pre-image attack. Full solve code is attached at the bottom of this writeup.

# Problem 3

First we are presented with a nice paper that explains a new hash called "HAS01." Looking deeper into the paper we are greeted with a new hash written specifically for this competition. We also know that Bob is having trouble implementing it and makes the mistake of not using `a'` as a matrix in function 1 and instead using `a`.

Before we get into how this function is cryptographically weak and how we can perform a second preimage attack to the plaintext (written in hex):
```
316520393820336220323620343720316320373820386520
```
We have to dive deep into the inner workings of the hash itself.

It uses 3 sub functions labeled `f1, f2, f3` where the full function combines them as `f` where `f = f1 º f3 º f2 º f1 º f3 º f1 º f2 º f1(A)`. This function is then repeated 4 times to create a part of the hash. Now let's take a deeper dive into each sub function.

### Function 1

Function 1 (`f1`) is a non-linear matrix transformation. Essentially, it takes the values of a 8x8 matrix and does some xoring and bit shifting and then runs it through an sbox (listed in Appendix). The xoring and bit shifting pseudocode is listed in the paper and Bob's dusty implementation is listed below in python:
```py
def f1(a):
	for i in range(0,8):
		for j in range(0,7):
			h1 = (a[i][j] ^ a[(i+1)%8][j]) << 3
			h2 = (a[i][j+1] ^ a[(i+1)%8][j+1]) >> 5
			idx = int(bin(h1 ^ h2)[2:].zfill(8)[-8:], 2)
			a[(i+1)%8][j] = sbox[idx]
		h_1 = (a[i][7] ^ a[(i+1)%8][7]) << 3
		h_2 = (a[i][0] ^ a[(i+1)%8][0]) >> 5
		idx_ = int(bin(h_1 ^ h_2 ^ 7)[2:].zfill(8)[-8:], 2)
		a[(i+1)%8][7] = sbox[idx_]
	return a
```
At an initial glance this function seems to be the most probalamatic since any implementation that requires non-linear shifting can be easily messed up. Before diving in this any further lets look at the other functions.

### Function 2

Function 2 (`f2`) is labeled as matrix transposition function. At a lower level, all it does is swap bytes to different positions in the matrix. It takes in an input of a 8x8 matrix and outputs another 8x8 matrix. None of the bytes are changed, however, how they are aranged in the matrix is changed. Thankfully, Bob did not screw this up. The implementation in python is below:
```py
def f2(a):
	for i in range(0,7):
		for j in range(i+1,8):
			temp = a[i][j]
			a[i][j] = a[j][i]
			a[j][i] = temp
	return a
```
All it does is that it shifts the bytes to different locations. From my observations, it doesn't seem like anything could be wrong here but we should always come back and check later. Time to move on to function 3.

### Function 3

Function 3 (`f3`) is used to "transform the matrix by rows" (whatever that means). It basically shifts the rows around while also doing some operations. The thing that makes this different than the other functions is that it takes an input of the original 8x8 matrix but on the inside of the function it changes the value of an internal 8x8 matrix and outputs the internal matrix. Bob did not mess this up either which is good. Here is the implementation in python:
```py
def f3(a):
	b = [[0,0,0,0,0,0,0,0] for _ in range(8)]
	for i in range(0,8):
		for j in range(0,8):
			for k in range(0,8):
				temp = list(map(int, bin(int(a[i][k]) >> j)[2:].zfill(8)))

				p2 = list(map(int, bin(int(''.join([str(i) for i in temp]), 2) & 1)[2:].zfill(8)))
				for _ in range(k):
					p2 = gmul2(p2)
				b[i][j] = b[i][j] ^ int(''.join([str(i) for i in p2]),2)
	return b
```
As a side note, the function `gmul2()` used in this implementation is a function that bit shifts left. Since the matrix in function 3 has its operations done over GF(2^8), `gmul2()` is used to ensure the bit shifts contain the value in the field. gmul2() is listed in the appendix below.

### The Main Chunk

Now for the main chunk of the hash. The hash never uses `f1,f2,f3` independently. It is always used as a combination as `f`. `f` is the full function that combines sub functions 1,2,3 into one. It's implementation is listed below in python.
```py
def f(A):
	return f1(f3(f2(f1(f3(f1(f2(f1(A))))))))
```
The hash starts off by taking each plaintext and padding it to be a multiple of 24 bytes. After that, it starts off with an initial state as a null 8x8 matrix. 

P.S: As a side note, since for the question we are working with a plaintext of 24 bytes, we don't need to worry about padding and other plaintext splitting.

It xors the first 3 rows of the null matrix by the bytes of the plaintext which forms a 8x8 matrix with the top 3x8 matrix as the plaintext in bytes and a 5x8 null matrix. After that it goes through an absorbing phase where the function `f` is run on the state matrix 4 times. For neatening up the code, we define this as `F`.
```py
def F(A):
	return f(f(f(f(A)))) #A is the state matrix
```
After the absorbing phase is over, the output from function `F` is used to calculate the 256/512 bit hash. This is done through the "sqeezing phase." The function `f` is used on the matrix and each time it is run
	1. For a 256 bit hash, every item in the sixth column of the matrix is added on to the hash. This is repeated 4 times, each time running `f` in between.
	2. For a 512 bit hash, every item in the fourth column of the matrix is added on to the hash. This is repeated 8 times, each time running `f` in between.
The python implementation is below:
```py
z_256 = ""
z_512 = ""
for i in range(8):
	y = f(y)

	if i < 4:
		for i in range(len(y)):
			z_256 += hex(y[i][5])[2:] # sixth column
	for i in range(len(y)):
		z_512 += hex(y[i][3])[2:] # fourth column
```

## Q1

Finally, after all that background information, we can get into the breaking of this hash function. Of course, in the context of this problem, we are breaking Bob's version. In Bob's version we see that the main problem lies in function 1 as listed in the prompt. Here's the code for it.
```py
def f1(a):
	for i in range(0,8):
		for j in range(0,7):
			h1 = (a[i][j] ^ a[(i+1)%8][j]) << 3
			h2 = (a[i][j+1] ^ a[(i+1)%8][j+1]) >> 5
			idx = int(bin(h1 ^ h2)[2:].zfill(8)[-8:], 2)
			a[(i+1)%8][j] = sbox[idx]
		h_1 = (a[i][7] ^ a[(i+1)%8][7]) << 3
		h_2 = (a[i][0] ^ a[(i+1)%8][0]) >> 5
		idx_ = int(bin(h_1 ^ h_2 ^ 7)[2:].zfill(8)[-8:], 2)
		a[(i+1)%8][7] = sbox[idx_]
	return a
```
We immediately see that the problem lies in the fact that the sbox can only take 8 bits. In this implementation, each bytes after being shifted and xored has to be cut down to fit into 8 bits. Instead of converting the shifted byte into a field element in GF(2^8), it takes only the 8 lsbs of the shifted byte and chops off the rest of the bits. 
```py
idx = int(bin(h1 ^ h2)[2:].zfill(8)[-8:], 2)
```
This leads to information loss which we can use to our advantage.

Let's take for example the nunber 133. If we binary expand it, it becomes `10000101`. Perfectly normal right? Well, let's shift it to the left by 3 as listed in the hash. `133 << 3 = 10000101000`. At the first glance this doesn't seem like a problem. However, since to fit the shifted byte into the sbox it takes only 8 lsbs, `10000101000 -> 100 00101000 -> 00101000`. This means that any number with the same 5 lsbs as 133 after being shifted will result in `00101000`. 

Effectovely, this allows the attacker to perform a second pre-image attack allowing the attacker to change the 3 msbs of a byte and which gets cut off anyway in Bob's implementation of function 1. This proves that Bob's implementation is cryptographically weak.

## Q2

To perform a second pre-image attack on the plaintext (in hex)
```
316520393820336220323620343720316320373820386520
```
of the plaintext we first turn it into a 8x8 matrix as listed in the main chunk.

We can use what we observed in Q1 to adjust a byte so that they produce the same hash. After some postition testing, changing the byte in the second row first column of the plaintext matrix results in some interesting results. Since from Q1, we observered that changing the 3 msbs of the byte results in the same byte after bit shifting, we can change byte `0x20 = 00100000` to something that also has `00000` as its 5 lsbs. 
```
3165203938203362 20 323620343720316320373820386520
```
In our example, we change it to byte `0x00 = 00000000`. Running it through the full solve code, we get the same 256/512 hash for both. We get 2 plaintexts:
```
m1: 316520393820336220323620343720316320373820386520
m2: 316520393820336200323620343720316320373820386520
```
that result in the same 256/512 bit hash.
```
HAS01_256: 33cd71f83a2fc4299f4cf3f3d46667b583e73622cb293d785a972172be748e6
HAS01_512: e0b94ea13f6a81d630899a39ae8a83b7a359d1f8479a7bcede14f87c4648432757fc9bd04f247fef3f1e79b3202
e14e41265d9e4caaa7356d652d3ebcdde
```

### Appendix

All code is written in python version 3.10.5

Sbox:
```py
sbox = [0xa5, 0x04, 0xa6, 0xa7, 0xf7, 0xc6, 0xa4, 0x12, 0x5f, 0xc8, 0xc7, 0xd1, 0xf6, 0xd4, 0x7e, 0x7b,
		0x0b, 0xef, 0x13, 0xad, 0x94, 0x5b, 0x4c, 0x8a, 0x0c, 0xfc, 0xce, 0x1c, 0x9b, 0x76, 0x19, 0xf3,
		0x21, 0x68, 0x53, 0x96, 0x2d, 0xd0, 0xa1, 0x89, 0x3d, 0x9c, 0xda, 0x6d, 0x51, 0xaf, 0xe1, 0xe9,
		0xa2, 0xe3, 0x09, 0xfe, 0xc3, 0x3f, 0xaa, 0x1e, 0xba, 0xdd, 0x9f, 0x1d, 0x28, 0x54, 0x8e, 0x92,
		0xe7, 0xd5, 0x43, 0x33, 0xde, 0x81, 0x3c, 0x97, 0x32, 0xec, 0x1f, 0x72, 0x74, 0xcd, 0xb3, 0x60,
		0x3a, 0x95, 0x39, 0xfa, 0x1a, 0x0e, 0xc1, 0x05, 0xdf, 0xcc, 0xa0, 0x8d, 0x87, 0x58, 0x83, 0xd3,
		0x26, 0xfd, 0x86, 0x7c, 0x20, 0x4b, 0x08, 0x36, 0x45, 0xdc, 0x3b, 0x79, 0x22, 0xbe, 0xab, 0x14,
		0x2a, 0x03, 0x99, 0x2c, 0x6b, 0xe5, 0xf9, 0x5c, 0xb0, 0x85, 0x5d, 0xb2, 0x30, 0x80, 0xed, 0xdb,
		0x57, 0x8f, 0x9d, 0xa9, 0xd6, 0xb8, 0xee, 0x24, 0xcb, 0x84, 0xb7, 0xd8, 0x69, 0xa8, 0x6f, 0x50,
		0xbd, 0xf1, 0x01, 0x38, 0xf8, 0x40, 0x4e, 0xbf, 0x9e, 0x0d, 0x91, 0xc9, 0x7d, 0xf4, 0x47, 0x07,
		0xb9, 0x63, 0x6e, 0x0f, 0xeb, 0x70, 0xd9, 0x6a, 0x7a, 0x2b, 0xa3, 0xcf, 0x44, 0x65, 0xf5, 0x00,
		0x98, 0x35, 0xc2, 0x41, 0x27, 0x1b, 0x62, 0xac, 0x67, 0x23, 0x88, 0x10, 0xb6, 0x8c, 0x4d, 0xc0,
		0x64, 0x3e, 0x5a, 0xe8, 0x34, 0xd7, 0x9a, 0x16, 0xb4, 0x29, 0xd2, 0x37, 0x73, 0xf2, 0x6c, 0x46,
		0x06, 0xe6, 0xca, 0xc4, 0xea, 0x7f, 0x18, 0xe0, 0xb5, 0x31, 0xfb, 0xff, 0x71, 0x17, 0xae, 0x02,
		0xb1, 0x15, 0x25, 0x78, 0xbb, 0xf0, 0x61, 0x93, 0x11, 0x4f, 0x56, 0x82, 0x8b, 0x42, 0x59, 0x48,
		0x2f, 0xe2, 0x66, 0x4a, 0x0a, 0x90, 0x2e, 0x75, 0xbc, 0xc5, 0xe4, 0x55, 0x52, 0x77, 0x49, 0x5e]
```

gmul2:
```py
def gmul2(state):
	temp = []
	temp.append(state[1])
	temp.append(state[2])
	temp.append(state[3])
	temp.append(state[0] ^ state[4])
	temp.append(state[0] ^ state[5])
	temp.append(state[6])
	temp.append(state[0] ^ state[7])
	temp.append(state[0])
	return temp
```

## Full Solve Code:
```py
sbox = [0xa5, 0x04, 0xa6, 0xa7, 0xf7, 0xc6, 0xa4, 0x12, 0x5f, 0xc8, 0xc7, 0xd1, 0xf6, 0xd4, 0x7e, 0x7b,
		0x0b, 0xef, 0x13, 0xad, 0x94, 0x5b, 0x4c, 0x8a, 0x0c, 0xfc, 0xce, 0x1c, 0x9b, 0x76, 0x19, 0xf3,
		0x21, 0x68, 0x53, 0x96, 0x2d, 0xd0, 0xa1, 0x89, 0x3d, 0x9c, 0xda, 0x6d, 0x51, 0xaf, 0xe1, 0xe9,
		0xa2, 0xe3, 0x09, 0xfe, 0xc3, 0x3f, 0xaa, 0x1e, 0xba, 0xdd, 0x9f, 0x1d, 0x28, 0x54, 0x8e, 0x92,
		0xe7, 0xd5, 0x43, 0x33, 0xde, 0x81, 0x3c, 0x97, 0x32, 0xec, 0x1f, 0x72, 0x74, 0xcd, 0xb3, 0x60,
		0x3a, 0x95, 0x39, 0xfa, 0x1a, 0x0e, 0xc1, 0x05, 0xdf, 0xcc, 0xa0, 0x8d, 0x87, 0x58, 0x83, 0xd3,
		0x26, 0xfd, 0x86, 0x7c, 0x20, 0x4b, 0x08, 0x36, 0x45, 0xdc, 0x3b, 0x79, 0x22, 0xbe, 0xab, 0x14,
		0x2a, 0x03, 0x99, 0x2c, 0x6b, 0xe5, 0xf9, 0x5c, 0xb0, 0x85, 0x5d, 0xb2, 0x30, 0x80, 0xed, 0xdb,
		0x57, 0x8f, 0x9d, 0xa9, 0xd6, 0xb8, 0xee, 0x24, 0xcb, 0x84, 0xb7, 0xd8, 0x69, 0xa8, 0x6f, 0x50,
		0xbd, 0xf1, 0x01, 0x38, 0xf8, 0x40, 0x4e, 0xbf, 0x9e, 0x0d, 0x91, 0xc9, 0x7d, 0xf4, 0x47, 0x07,
		0xb9, 0x63, 0x6e, 0x0f, 0xeb, 0x70, 0xd9, 0x6a, 0x7a, 0x2b, 0xa3, 0xcf, 0x44, 0x65, 0xf5, 0x00,
		0x98, 0x35, 0xc2, 0x41, 0x27, 0x1b, 0x62, 0xac, 0x67, 0x23, 0x88, 0x10, 0xb6, 0x8c, 0x4d, 0xc0,
		0x64, 0x3e, 0x5a, 0xe8, 0x34, 0xd7, 0x9a, 0x16, 0xb4, 0x29, 0xd2, 0x37, 0x73, 0xf2, 0x6c, 0x46,
		0x06, 0xe6, 0xca, 0xc4, 0xea, 0x7f, 0x18, 0xe0, 0xb5, 0x31, 0xfb, 0xff, 0x71, 0x17, 0xae, 0x02,
		0xb1, 0x15, 0x25, 0x78, 0xbb, 0xf0, 0x61, 0x93, 0x11, 0x4f, 0x56, 0x82, 0x8b, 0x42, 0x59, 0x48,
		0x2f, 0xe2, 0x66, 0x4a, 0x0a, 0x90, 0x2e, 0x75, 0xbc, 0xc5, 0xe4, 0x55, 0x52, 0x77, 0x49, 0x5e]

def gmul2(state):
	temp = []
	temp.append(state[1])
	temp.append(state[2])
	temp.append(state[3])
	temp.append(state[0] ^ state[4])
	temp.append(state[0] ^ state[5])
	temp.append(state[6])
	temp.append(state[0] ^ state[7])
	temp.append(state[0])
	return temp

def f1(a):
	for i in range(0,8):
		for j in range(0,7):
			h1 = (a[i][j] ^ a[(i+1)%8][j]) << 3
			h2 = (a[i][j+1] ^ a[(i+1)%8][j+1]) >> 5
			idx = int(bin(h1 ^ h2)[2:].zfill(8)[-8:], 2)
			a[(i+1)%8][j] = sbox[idx]
		h_1 = (a[i][7] ^ a[(i+1)%8][7]) << 3
		h_2 = (a[i][0] ^ a[(i+1)%8][0]) >> 5
		idx_ = int(bin(h_1 ^ h_2 ^ 7)[2:].zfill(8)[-8:], 2)
		a[(i+1)%8][7] = sbox[idx_]
	return a

def f2(a):
	for i in range(0,7):
		for j in range(i+1,8):
			temp = a[i][j]
			a[i][j] = a[j][i]
			a[j][i] = temp
	return a

def f3(a):
	b = [[0,0,0,0,0,0,0,0] for _ in range(8)]
	for i in range(0,8):
		for j in range(0,8):
			for k in range(0,8):
				temp = list(map(int, bin(int(a[i][k]) >> j)[2:].zfill(8)))

				p2 = list(map(int, bin(int(''.join([str(i) for i in temp]), 2) & 1)[2:].zfill(8)))
				for _ in range(k):
					p2 = gmul2(p2)
				b[i][j] = b[i][j] ^ int(''.join([str(i) for i in p2]),2)
	return b

def f(A):
	return f1(f3(f2(f1(f3(f1(f2(f1(A))))))))

def F(A):
	return f(f(f(f(A))))

m1 = bytes.fromhex('316520393820336220323620343720316320373820386520')
m2 = bytes.fromhex('316520393820336200323620343720316320373820386520')
assert m1 != m2

plaintexts = [m1 ,m2]

HAS01_256 = []
HAS01_512 = []
for m in plaintexts:
	y = [[0,0,0,0,0,0,0,0] for _ in range(8)]
	for i in range(0,len(m),24):
		M = m[i:i+24]
		for idx in range(len(M)):
			if idx < 8:
				y[0][idx] = y[0][idx] ^ M[idx]
			elif idx >= 8 and idx < 16:
				y[1][idx%8] = y[1][idx%8] ^ M[idx]
			else:
				y[2][idx%8] = y[2][idx%8] ^ M[idx]
		y = F(y)

	z_256 = ""
	z_512 = ""
	for i in range(8):
		y = f(y)

		if i < 4:
			for i in range(len(y)):
				z_256 += hex(y[i][5])[2:]
		for i in range(len(y)):
			z_512 += hex(y[i][3])[2:]

	HAS01_256.append(z_256)
	HAS01_512.append(z_512)

assert HAS01_256[0] == HAS01_256[1]
assert HAS01_512[0] == HAS01_512[1]
```