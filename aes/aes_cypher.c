# define Poly 0x11b

/*
	有限域上的乘法运算
*/
unsigned char Mul(unsigned char aa, unsigned char bb) {
	int a, b;
	a = (int)(aa);
	b = (int)(bb);
	int t, value;
	value = 0;
	for (int i = 0; i < 8; i++) {
		t = (b >> i) & 0x1;
		if (t)
			value ^= (a << i);
	}
	for (int j = 15; j > 7; j--) {
		t = (value >> j) & 0x1;
		if (t)
			value ^= (Poly << (j - 8));
	}
	return (unsigned int)value;
}

/*
	有限域上的幂运算
*/
unsigned char Power(unsigned char a, int n) {
	if (a == 0 && n != 0)
		return 0;
	else {
		unsigned char value;
		value = 1;
		for (int t = 0; t < n; t++)
			value = Mul(value, a);
		return value;
	}
}

/*
	有限域上的求逆运算
*/
unsigned char inverse(unsigned char s) {
	unsigned char y;
	y = Power(a, 254);
	return y;
}

/*
	密钥扩展算法
*/
void KeyExpansion(unsigned char K[16], unsigned char k[11][16]) {
	unsigned char RC[10];
	RC[0] = 1;
	for (int i = 1; i < 10; i++)
		RC[i] = Mul(0x02, RC[i-1]);
	for (int i = 0; i < 16; i++)
		k[0][i] = K[i];
	for (int i = 1; i < 11; i++) {
		k[i][0] = k[i-1][0] ^ S[k[i-1][13]] ^ RC[i-1];
		k[i][1] = k[i-1][1] ^ S[k[i-1][14]];
		k[i][2] = k[i-1][2] ^ S[k[i-1][15]];
		k[i][3] = k[i-1][3] ^ S[k[i-1][12]];
		k[i][4] = k[i-1][4] ^ S[k[i][0]];
		k[i][5] = k[i-1][5] ^ S[k[i][1]];
		k[i][6] = k[i-1][6] ^ S[k[i][2]];
		k[i][7] = k[i-1][7] ^ S[k[i][3]];
		k[i][8] = k[i-1][8] ^ S[k[i][4]];
		k[i][9] = k[i-1][9] ^ S[k[i][5]];
		k[i][10] = k[i-1][10] ^ S[k[i][6]];
		k[i][11] = k[i-1][11] ^ S[k[i][7]];
		k[i][12] = k[i-1][12] ^ S[k[i][8]];
		k[i][13] = k[i-1][13] ^ S[k[i][9]];
		k[i][14] = k[i-1][14] ^ S[k[i][10]];
		k[i][15] = k[i-1][15] ^ S[k[i][11]];
	}
}

/*
	密钥加运算
*/		
void AddRoundKey(unsigned char *a, unsigned char *Key) {
	for (int i = 0; i < 16; i++) 
		a[i] ^= Key[i];
}

/*
	S盒替换
*/
void SubBytes(unsigned char *input) {
	for (int i = 0; i < 16; i++) {
		input[i] = S[input[i]];
	}
}

/*
	行移位运算
*/
void ShiftRows(unsigned char *a) {
	unsigned char b[16];
	b[0] = a[0]; b[4] = a[4]; b[8] = a[8]; b[12] = a[12];
	b[1] = a[5]; b[5] = a[9]; b[9] = a[13]; b[13] = a[1];
	b[2] = a[10]; b[6] = a[14]; b[10] = a[2]; b[14] = a[6];
	b[3] = a[15]; b[7] = a[3]; b[11] = a[7]; b[15] = a[11];
	for (int i = 0; i < 16; i++)
		a[i] = b[i];
}

/*
	列混合运算
*/
void MixColumns(unsigned char *a) {
	unsigned char b[16];
	b[0] = S2[a[0]] ^ S3[a[1]] ^ a[2] ^ a[3];
	b[1] = S2[a[1]] ^ S3[a[2]] ^ a[3] ^ a[0];
	b[2] = S2[a[2]] ^ S3[a[3]] ^ a[0] ^ a[1];
	b[3] = S2[a[3]] ^ S3[a[0]] ^ a[1] ^ a[2];
	b[4] = S2[a[4]] ^ S3[a[5]] ^ a[6] ^ a[7];
	b[5] = S2[a[5]] ^ S3[a[6]] ^ a[7] ^ a[4];
	b[6] = S2[a[6]] ^ S3[a[7]] ^ a[4] ^ a[5];
	b[7] = S2[a[7]] ^ S3[a[4]] ^ a[5] ^ a[6];
	b[8] = S2[a[8]] ^ S3[a[9]] ^ a[10] ^ a[11];
	b[9] = S2[a[9]] ^ S3[a[10]] ^ a[11] ^ a[8];
	b[10] = S2[a[10]] ^ S3[a[11]] ^ a[8] ^ a[9];
	b[11] = S2[a[11]] ^ S3[a[8]] ^ a[9] ^ a[10];
	b[12] = S2[a[12]] ^ S3[a[13]] ^ a[14] ^ a[15];
	b[13] = S2[a[13]] ^ S3[a[14]] ^ a[15] ^ a[12];
	b[14] = S2[a[14]] ^ S3[a[15]] ^ a[12] ^ a[13];
	b[15] = S2[a[15]] ^ S3[a[12]] ^ a[13] ^ a[14];
	for (int i = 0; i < 16; i++)
		a[i] = b[i];
}

/*
	AES-128 10 轮完整加密
*/
void AES(unsigned char plaintext[16], unsigned char ciphertext[16], unsigned char k[11][16], int Round) {
	for (int i = 0; i < 16; i++) 
		ciphertext[i] = plaintext[i];
	AddRoundKey(ciphertext.k[0]);
	for (int round = 1; round < Round; round++) {
		SubBytes(ciphertext);
		ShiftRows(ciphertext);
		MixColumns(ciphertext);
		AddRoundKey(ciphertext, k[round]);
	}
	SubBytes(ciphertext);
	ShiftRows(ciphertext);
	AddRoundKey(ciphertext, k[Round]);
}