# AES_encryption-decryption_implementation
+ AES_encryption-decryption(basic, optimization, file)

+ This project includes the following.

	+ 1.Basic AES encryption/decryption

	+ 2.AES-optimized encryption/decryption

	+ 3.File AES encryption/decryption (CBC operation mode, ECB operation mode, PKCS#7 padding)
***
# AES 복호화 구현
+ **AES 복호화 과정**
  + AES 복호화 과정은 암호화 과정을 역으로 하면 된다.
    + N 라운드:AddRoundKey, InvShiftRows, InvSubBytes를 순서대로 수행한다.
    + (N-1)~1 라운드:AddRoundKey, InvMixColumn, InvShiftRows, InvSubBytes를 순서대로 반복한다.
    + 0 라운드:AddRoundKey만 수행한다.
    
    ![제목 없음](https://user-images.githubusercontent.com/84726924/195860353-5c2c5196-b827-4538-8b33-dcfd91edb471.png)
+ **KeyExpansion**
  + key schedule(키 스케줄)이라고도 부른다. 128, 192, 256비트 길이인 하나의 주 암호화 키를 받아서 각 라운드들에서 사용할 여러 개의 128비트 라운드 키를 생성한다. Key Schedule 코드는 아래와 같다.
  ```
  W[0] = u4byte_in(MK); //W[0]=MK[0] || MK[1] || MK[2] || MK[3]
	W[1] = u4byte_in(MK + 4);
	W[2] = u4byte_in(MK + 8);
	W[3] = u4byte_in(MK + 12);

	//G(W4i-1) = SubWord(RotWord(W4i-1)) XOR RCons
	for (i = 0; i < 10; i++) {
		//T = G_func(W[4 * i + 3]);
		T = W[4 * i + 3];
		T = RotWord(T);
		T = SubWord(T);
		T ^= Rcons[i];

		W[4 * i + 4] = W[4 * i] ^ T;
		W[4 * i + 5] = W[4 * i + 1] ^ W[4 * i + 4];
		W[4 * i + 6] = W[4 * i + 2] ^ W[4 * i + 5];
		W[4 * i + 7] = W[4 * i + 3] ^ W[4 * i + 6];
	}
  ```
    + AES는 각 라운드 키를 만들 때 워드 단위로 만든다. 각 라운드 키는 128비트 이므로 한 라운드에 키는 4개의 워드가 필요하다.
    + W[0] W[1] W[2] W[3]의 라운드 키가 있다고 가정하면 W[3]은 G함수(RotWord,SubWord,Rcon)를 거쳐서 W[0]과 XOR 연산을 하여 W[4]가 된다. W[5]=W[4] XOR W[1], W[6]=W[5] XOR W[2], W[7]=W[6] XOR W[3] 이렇게 반복하여 각 라운드 키를 생성한다.
  + **RotWord**
    + RotWord는 4바이트 워드를 바이트 단위로 한 칸 LeftShift한 것이다.
    ```
    //	4바이트 워드 단위를 왼쪽으로 1바이트 쉬프트. ex) RotWord([89 ab cd ef]) = [ab cd ef 89]
    #define RotWord(x) ((x<<8)|(x>>24))
    ```
  + **SubWord**
    + SubWord는 바이트 단위로 SubBytes을 수행한다. 즉 Sbox를 사용하여 치환한다.
    ```
    //바이트 단위로 SubBytes 연산. ex)SubWord([ab cd ef 89]) = [62 bd df a7]
    #define SubWord(x)							  \
	  ((u32)Sbox[(u8)(x >> 24)]<<24)		 	  \
  	| ((u32)Sbox[(u8)((x >> 16) & 0xff)]<<16) \
	  | ((u32)Sbox[(u8)((x >> 8) & 0xff)] << 8) \
	  | ((u32)Sbox[(u8)(x & 0xff)])			  \
    ```
  + **Rcon**
    + Rcon은 키를 알기 어렵게 하기 위해 섞어주는 상수이다. Rcon은 각 라운드마다 사용하는 값이 다르다.
    ```
    u32 Rcons[10] = { 0x01000000,0x02000000,0x04000000,0x08000000, //상수값
				  0x10000000,0x20000000,0x40000000,0x80000000,
				  0x1b000000,0x36000000 };
    ```
+ **Inverse ShiftRows & Inverse SubBytes**
  + **Inverse ShiftRows**
    + 아래와 같이 2행은 오른쪽으로 1번, 3행은 2번, 4행은 3번 쉬프트하면 된다.
    ![제목 없음](https://user-images.githubusercontent.com/84726924/195863709-f11763ec-5628-4148-a838-c54bf4ea407e.png)
    ```
    void InvShiftRows(u8 S[16]) {
	u8 temp;
	temp = S[1];
	S[1] = S[13]; S[13] = S[9]; S[9] = S[5]; S[5] = temp; //2행을 오른쪽으로 1바이트 쉬프트
	temp = S[2];
	S[2] = S[10]; S[10] = temp; temp = S[6]; S[6] = S[14]; S[14] = temp; //3행을 오른쪽으로 2바이트 쉬프트
	temp = S[15];
	S[15] = S[3]; S[3] = S[7]; S[7] = S[11]; S[11] = temp; //4행을 오른쪽으로 3바이트 쉬프트
    ```
  + **Inverse SubBytes**
    + 먼저 Inverse Sbox는 GF(2⁸),(기약다항식:x⁸+x⁴+x³+x+1)에서 역 아핀연산과 inversion연산으로 설계된다. Inverse Sbox를 생성하기 위해선 역 아핀연산과 곱셈의 역원연산이 필요하다. 역 아핀 연산은 아핀연산에 사용되는 행렬의 역행렬을 구하면 된다.
    ![제목 없음](https://user-images.githubusercontent.com/84726924/195864469-099d693b-efab-40cd-9596-f742d6c4d68f.png)
    + 여기서 역 아핀 연산은 x₀s₀⊕x₁s₁⊕⋅⋅⋅x₇s₇⊕0x05을 통해 구할 수 있다. 구하는 방법은 sn이 1일 경우만 XOR연산을 하고 마지막에 0x05와 XOR연산을 하면 역 아핀연산 값을 얻을 수 있다.
    ![image](https://user-images.githubusercontent.com/84726924/195864736-2797a7bd-fbc2-4f64-9060-703cd93caca8.png)
    + GF(2⁸)에서의 곱셈 역원은 확장 유클리드 알고리즘을 통해 구할 수 있다.
    + 아래 표는 0x10=00010000=x⁴의 곱셈역원을 구하는 과정이다.(기약다항식:x⁸+x⁴+x³+x+1)
    ![제목 없음](https://user-images.githubusercontent.com/84726924/195864875-283f4cce-4ef9-492c-80b7-3feb90438c37.png)
    + Inverse Sbox는 역 아핀연산과 역원연산을 통해 생성할 수 있다. MUL2라는 매크로함수는 GF(2⁸)에서의 곱셈 연산을 하기 위해 선언된다. 입력 값의 최상위 비트가 1이면 0x1b( x⁴+x³+x+1)과 XOR연산을 하고 아니면 0과 XOR연산을 한다. GF(2⁸)에서는 x⁷까지만 나타낼 수 있기 때문에 x⁸일 경우 x⁴+x³+x+1로 바꿔준다.
    ```
    //GF(2^8)에서의 곱셈 연산 / 기약다항식 : x^8+x^4+x^3+x+1
	#define MUL2(a) (a<<1)^(a&0x80?0x1b:0) //x^8이면 0x1b와 XOR연산을 하고 아니면 0과 XOR연산을 수행. (x^8=x^4+x^3+x+1)
    ```
    + 아래 코드는 곱셈의 역원 연산을 위해 구연된 코드이다.
    ```
    u8 MUL(u8 a, u8 b) {
	u8 r = 0;
	u8 tmp = b;
	u32 i;
	for (i = 0; i < 8; i++) {
		if (a & 1) r ^= tmp;
		tmp = MUL2(tmp);
		a >>= 1;
	}
	return r;
	}
    ```
    ```
    //(Inv)Sbox 연산
	u8 inv(u8 a) { //곱셈 역원연산
	u8 r = a;
	r = MUL(r, r); //a2
	r = MUL(r, a); //a3
	r = MUL(r, r); //a6
	r = MUL(r, a); //a7
	r = MUL(r, r); //a14
	r = MUL(r, a); //a15
	r = MUL(r, r); //a30
	r = MUL(r, a); //a31
	r = MUL(r, r); //a62
	r = MUL(r, a); //a63
	r = MUL(r, r); //a126
	r = MUL(r, a); //a127
	r = MUL(r, r); //a254
	return r;
	}
    ```
    + Inverse Sbox는 아래 코드로 생성할 수 있다. 암호화할 때와 반대로 먼저 역 아핀연산을 한 후에 역원연산을 통해 Inverse Sbox를 생성한다. 비트의 각 자릿수가 1인 경우에 해당 값과 XOR연산을 하고 inv()함수로 역원연산을 한다.
    ```
    u8 InvGenSbox(u8 a) {
	u8 r = 0;
	u8 tmp = a;
	//2^8 = {128,64,32,16,8,4,2,1}
	if (tmp & 1) r ^= 0x4a; //AND연산한 결과가 1이면 0x4a와 XOR연산 수행
	if (tmp & 2) r ^= 0x94;
	if (tmp & 4) r ^= 0x29;
	if (tmp & 8) r ^= 0x52;
	if (tmp & 16) r ^= 0xa4;
	if (tmp & 32) r ^= 0x49;
	if (tmp & 64) r ^= 0x92;
	if (tmp & 128) r ^= 0x25;
	r ^= 0x05;
	r = inv(r);
	return r;

	}
    ```
    + 아래 구현된 코드로 Inverse Sbox 표를 출력할 수 있다.
    ```
    	printf("InvSbox[256] = {\n"); //Inversion Sbox표 출력
	for (i = 0; i < 256; i++) {
		printf("0x%02x, ", InvGenSbox((u8)i));
		if (i % 16 == 15) printf("\n");
	}
    ```
    ```
    u8 InvSbox[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
    ```
    + Inverse SubBytes는 각 각의 바이트를 Inverse Sbox로 치환하면 된다.
    ```
    //Inverse Sbox : 역원연산 과정은 암호화과정이랑 동일하지만 역 아핀연산을 통해 구할 수 있음
	void InvSubBytes(u8 S[16]) { //각 각 Inverse Sbox표에 치환
	S[0] = InvSbox[S[0]]; S[1] = InvSbox[S[1]]; S[2] = InvSbox[S[2]]; S[3] = InvSbox[S[3]]; 
	S[4] = InvSbox[S[4]]; S[5] = InvSbox[S[5]]; S[6] = InvSbox[S[6]]; S[7] = InvSbox[S[7]];
	S[8] = InvSbox[S[8]]; S[9] = InvSbox[S[9]]; S[10] = InvSbox[S[10]]; S[11] = InvSbox[S[11]];
	S[12] = InvSbox[S[12]]; S[13] = InvSbox[S[13]]; S[14] = InvSbox[S[14]]; S[15] = InvSbox[S[15]];
	}
    ```
