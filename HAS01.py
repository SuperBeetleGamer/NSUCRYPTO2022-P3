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
	b = [[0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0]]
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
	y = [[0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0]]
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

print(HAS01_256[0])
print(HAS01_512[0])

assert HAS01_256[0] == HAS01_256[1]
assert HAS01_512[0] == HAS01_512[1]