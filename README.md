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
+ **Inverse MixColumns & AddRoundKey**
	+ **Inverse MixColumns**
		+ Inverse MixColumns은 MixColumns의 역행렬과 연산을 하면 된다. GF(2⁸)에서의 곱셈 연산과 덧셈 연산을 이용해 계산되는데 아래 예시를 통해 확인할 수 있다.
		
		![화면 캡처 2022-10-15 134856](https://user-images.githubusercontent.com/84726924/195969270-b4070f84-c186-4691-b79c-0434a98c31f3.png)
		+ Inverse MixColumns는 미리 정의한 매크로 함수를 이용해 구현할 수 있다. 매크로 함수는 GF(2⁸)에서의 연산을 정의한 것이다. 위에서 설명한 예시와 같이 구현한 것이다. for문 안에서 한번 실행 될 때마다 4바이트 씩의 연산 결과를 얻는다. 이 부분이 4번 실행되면 총 16바이트의 연산 값을 얻을 수 있다.
		```
		//(Inv)MixColumns
		//GF(2^8)에서의 곱셈 연산 / 기약다항식 : x^8+x^4+x^3+x+1
		#define MUL2(a) (a<<1)^(a&0x80?0x1b:0) //x^8이면 0x1b와 XOR연산을 하고 아니면 0과 XOR연산을 수행. (x^8=x^4+x^3+x+1)
		#define MUL3(a) (MUL2(a))^(a)
		#define MUL4(a) MUL2((MUL2(a)))
		#define MUL8(a) MUL2((MUL2((MUL2(a)))))
		#define MUL9(a) (MUL8(a))^(a)
		#define MULB(a) (MUL8(a))^(MUL2(a))^(a)
		#define MULD(a) (MUL8(a))^(MUL4(a))^(a)
		#define MULE(a) (MUL8(a))^(MUL4(a))^(MUL2(a))
		```
		```
		//MixColumns 행렬의 역행렬을 구하고 연산하면 Inverse MixColumns연산이 가능
		void InvMixColumns(u8 S[16]) {
		u8 temp[16];
		int i;
		for (i = 0; i < 16; i += 4) {
			temp[i] = MULE(S[i]) ^ MULB(S[i + 1]) ^ MULD(S[i + 2]) ^ MUL9(S[i + 3]); //(0E*S[0]) ^(0B*S[1]) ^(0D*S[2]) ^(09*S[3]) 
			temp[i + 1] = MUL9(S[i]) ^ MULE(S[i + 1]) ^ MULB(S[i + 2]) ^ MULD(S[i + 3]); //(09*S[0]) ^(0E*S[1]) ^(0B*S[2]) ^(0D*S[3]) 
			temp[i + 2] = MULD(S[i]) ^ MUL9(S[i + 1]) ^ MULE(S[i + 2]) ^ MULB(S[i + 3]); //(0D*S[0]) ^(09*S[1]) ^(0E*S[2]) ^(0B*S[3]) 
			temp[i + 3] = MULB(S[i]) ^ MULD(S[i + 1]) ^ MUL9(S[i + 2]) ^ MULE(S[i + 3]); //(0B*S[0]) ^(0D*S[1]) ^(09*S[2]) ^(0E*S[3]) 
		}
		S[0] = temp[0]; S[1] = temp[1]; S[2] = temp[2]; S[3] = temp[3];
		S[4] = temp[4]; S[5] = temp[5]; S[6] = temp[6]; S[7] = temp[7];
		S[8] = temp[8]; S[9] = temp[9]; S[10] = temp[10]; S[11] = temp[11];
		S[12] = temp[12]; S[13] = temp[13]; S[14] = temp[14]; S[15] = temp[15];
		}
		```
	+ AddRoundKey
		+ AddRoundKey는 각 라운드마다 라운드 키와 XOR 연산만 하면 된다.
		```
		void AddRoundKey(u8 S[16], u8 RK[16]) { //각 라운드 키와 XOR 연산만 수행(S=S XOR RK)
			S[0] ^= RK[0]; S[1] ^= RK[1]; S[2] ^= RK[2]; S[3] ^= RK[3];
			S[4] ^= RK[4]; S[5] ^= RK[5]; S[6] ^= RK[6]; S[7] ^= RK[7];
			S[8] ^= RK[8]; S[9] ^= RK[9]; S[10] ^= RK[10]; S[11] ^= RK[11];
			S[12] ^= RK[12]; S[13] ^= RK[13]; S[14] ^= RK[14]; S[15] ^= RK[15];
		}
		```
***
# AES 최적화 복호화 구현
+ **AES 최적화 테이블**
	+ **AES 최적화 테이블 생성 방법**
		+ AES에서 SubBytes와 ShiftRows 순서를 바꾸는 게 가능하므로 암호화 한 라운드를 ShiftRows -> SubBytes&MixColumns -> AddRoundKey 순서로 변경한다.
		+ SubBytes&MixColumns를 8\*32 table 4개로 구현한다. 복호화는 Inverse SubBytes &Inverse MixColumns를 8\*32 table 4개로 구현하면 된다.
		+ 아래와 그림에서 Y0,Y1,Y2,Y3을 구한다고 했을 때 Y0||Y1||Y2||Y3 = ES(X0)+ BS(X13)+ DS(X10)+ 9S(X7) || 9S(X0)+ ES(X13)+ BS(10)+ DS(X7) || DS(X0)+ 9S(X13)+ ES(X10)+ BS(X7) || BS(X0)+ DS(X13)+ 9S(X10)+ ES(X7) =[ES(X0) || 9S(X0) || DS(X0) || BS(X0)] + [BS(X13) || ES(X13) || 9S(X13) || DS(X13)] +[DS(X10) || BS(X10) || ES(X10) || 9S(X10)] + [9S(X7) || DS(X7) || BS(X7) || ES(X7)]가 되고 Td0[X0] + Td1[X13] + Td2[X10] + Td3[X7]로 나타낼 수 있다.
		![화면 캡처 2022-10-15 134856](https://user-images.githubusercontent.com/84726924/195969486-d4ef8745-6149-4c6f-98f5-eeb0431c92ff.png)
		+ Td0을 생성한다고 했을 때 먼저 입력받은 x에 InvSubBytes연산을 수행하면 InvSbox[x]가 된다. 그리고 ((E\*InvSbox[x])<<24)+((9\*InvSbox[x])<<16)+((D\*InvSbox[x])<<8)+B\*InvSbox[x]연산을 하여 출력한다.
	+ **AES 최적화 테이블 구현 코드**
		+ InvSbox연산을 수행한 후 매크로함수를 이용하여 최적화 테이블을 출력할 수 있다.
		```
		printf("u32 Td0[256]={\n"); //복호화 최적화 테이블 출력
		for (i = 0; i < 256; i++) {
			temp = InvSbox[i];
			printf("0x%02x%02x%02x%02x, ", (u8)(MULE(temp)), (u8)(MUL9(temp)), (u8)(MULD(temp)), (u8)(MULB(temp)));
			if (i % 8 == 7)printf("\n");
		}
		```
		```
		u32 Td0[256] = {
			0x51f4a750, 0x7e416553, 0x1a17a4c3, 0x3a275e96, 0x3bab6bcb, 0x1f9d45f1, 0xacfa58ab, 0x4be30393,
			0x2030fa55, 0xad766df6, 0x88cc7691, 0xf5024c25, 0x4fe5d7fc, 0xc52acbd7, 0x26354480, 0xb562a38f,
			0xdeb15a49, 0x25ba1b67, 0x45ea0e98, 0x5dfec0e1, 0xc32f7502, 0x814cf012, 0x8d4697a3, 0x6bd3f9c6,
			0x038f5fe7, 0x15929c95, 0xbf6d7aeb, 0x955259da, 0xd4be832d, 0x587421d3, 0x49e06929, 0x8ec9c844,
			0x75c2896a, 0xf48e7978, 0x99583e6b, 0x27b971dd, 0xbee14fb6, 0xf088ad17, 0xc920ac66, 0x7dce3ab4,
			0x63df4a18, 0xe51a3182, 0x97513360, 0x62537f45, 0xb16477e0, 0xbb6bae84, 0xfe81a01c, 0xf9082b94,
			0x70486858, 0x8f45fd19, 0x94de6c87, 0x527bf8b7, 0xab73d323, 0x724b02e2, 0xe31f8f57, 0x6655ab2a,
			0xb2eb2807, 0x2fb5c203, 0x86c57b9a, 0xd33708a5, 0x302887f2, 0x23bfa5b2, 0x02036aba, 0xed16825c,
			0x8acf1c2b, 0xa779b492, 0xf307f2f0, 0x4e69e2a1, 0x65daf4cd, 0x0605bed5, 0xd134621f, 0xc4a6fe8a,
			0x342e539d, 0xa2f355a0, 0x058ae132, 0xa4f6eb75, 0x0b83ec39, 0x4060efaa, 0x5e719f06, 0xbd6e1051,
			0x3e218af9, 0x96dd063d, 0xdd3e05ae, 0x4de6bd46, 0x91548db5, 0x71c45d05, 0x0406d46f, 0x605015ff,
			0x1998fb24, 0xd6bde997, 0x894043cc, 0x67d99e77, 0xb0e842bd, 0x07898b88, 0xe7195b38, 0x79c8eedb,
			0xa17c0a47, 0x7c420fe9, 0xf8841ec9, 0x00000000, 0x09808683, 0x322bed48, 0x1e1170ac, 0x6c5a724e,
			0xfd0efffb, 0x0f853856, 0x3daed51e, 0x362d3927, 0x0a0fd964, 0x685ca621, 0x9b5b54d1, 0x24362e3a,
			0x0c0a67b1, 0x9357e70f, 0xb4ee96d2, 0x1b9b919e, 0x80c0c54f, 0x61dc20a2, 0x5a774b69, 0x1c121a16,
			0xe293ba0a, 0xc0a02ae5, 0x3c22e043, 0x121b171d, 0x0e090d0b, 0xf28bc7ad, 0x2db6a8b9, 0x141ea9c8,
			0x57f11985, 0xaf75074c, 0xee99ddbb, 0xa37f60fd, 0xf701269f, 0x5c72f5bc, 0x44663bc5, 0x5bfb7e34,
			0x8b432976, 0xcb23c6dc, 0xb6edfc68, 0xb8e4f163, 0xd731dcca, 0x42638510, 0x13972240, 0x84c61120,
			0x854a247d, 0xd2bb3df8, 0xaef93211, 0xc729a16d, 0x1d9e2f4b, 0xdcb230f3, 0x0d8652ec, 0x77c1e3d0,
			0x2bb3166c, 0xa970b999, 0x119448fa, 0x47e96422, 0xa8fc8cc4, 0xa0f03f1a, 0x567d2cd8, 0x223390ef,
			0x87494ec7, 0xd938d1c1, 0x8ccaa2fe, 0x98d40b36, 0xa6f581cf, 0xa57ade28, 0xdab78e26, 0x3fadbfa4,
			0x2c3a9de4, 0x5078920d, 0x6a5fcc9b, 0x547e4662, 0xf68d13c2, 0x90d8b8e8, 0x2e39f75e, 0x82c3aff5,
			0x9f5d80be, 0x69d0937c, 0x6fd52da9, 0xcf2512b3, 0xc8ac993b, 0x10187da7, 0xe89c636e, 0xdb3bbb7b,
			0xcd267809, 0x6e5918f4, 0xec9ab701, 0x834f9aa8, 0xe6956e65, 0xaaffe67e, 0x21bccf08, 0xef15e8e6,
			0xbae79bd9, 0x4a6f36ce, 0xea9f09d4, 0x29b07cd6, 0x31a4b2af, 0x2a3f2331, 0xc6a59430, 0x35a266c0,
			0x744ebc37, 0xfc82caa6, 0xe090d0b0, 0x33a7d815, 0xf104984a, 0x41ecdaf7, 0x7fcd500e, 0x1791f62f,
			0x764dd68d, 0x43efb04d, 0xccaa4d54, 0xe49604df, 0x9ed1b5e3, 0x4c6a881b, 0xc12c1fb8, 0x4665517f,
			0x9d5eea04, 0x018c355d, 0xfa877473, 0xfb0b412e, 0xb3671d5a, 0x92dbd252, 0xe9105633, 0x6dd64713,
			0x9ad7618c, 0x37a10c7a, 0x59f8148e, 0xeb133c89, 0xcea927ee, 0xb761c935, 0xe11ce5ed, 0x7a47b13c,
			0x9cd2df59, 0x55f2733f, 0x1814ce79, 0x73c737bf, 0x53f7cdea, 0x5ffdaa5b, 0xdf3d6f14, 0x7844db86,
			0xcaaff381, 0xb968c43e, 0x3824342c, 0xc2a3405f, 0x161dc372, 0xbce2250c, 0x283c498b, 0xff0d9541,
			0x39a80171, 0x080cb3de, 0xd8b4e49c, 0x6456c190, 0x7bcb8461, 0xd532b670, 0x486c5c74, 0xd0b85742 };
		```
+ **AES 최적화 복호화 구현 과정**
	+ **AES 최적화 복호화 과정**
		+ AES 최적화 복호화는 AES 복호화와 다른 순서로 진행해야한다. InvSubBytes와 InvShiftRows는 순서를 바꿔도 상관 없지만 InvMixColumns와 AddRoundKey의 순서를 바꿀 경우 InvMixColumns 연산한 라운드 키가 필요하다. 이렇게 순서를 바꾸는 이유는 최적화 테이블(8bit input->32bit output)을 이용하기 위해서이다.
		![화면 캡처 2022-10-15 134856](https://user-images.githubusercontent.com/84726924/195969602-9ad5f526-711d-4cc9-83ca-8af422503a2d.png)
	+ **AES 최적화 복호화 구현**
		+ AES 최적화 복호화에선 32bit의 라운드 키가 그대로 사용되기 때문에 KeySchedule함수에서 8비트로 변환해 줄 필요가 없다.
		+ AES 최적화 복호화 구현을 위해서 InvMixColumns와 AddRoundKey의 순서를 바꿔줬기 때문에 InvMixColumns연산을 한 라운드 키가 필요하다. InvMixColumns연산된 라운드 키를 구현하는 방법은 최적화 복호화 테이블을 이용하면 된다. 최적화 복호화 테이블은 InvSubBytes&InvMixColumns로 생성되어있기 때문에 Sbox연산을 해주면 InvMixColumns연산만 한 라운드키를 얻을 수 있다.
		```
		//최적화 복호화 : AddRoundKey->(InvSubBytes->InvShiftRows->InvMixColumns->AddRoundKey)(N-1)->InvSubBytes->InvShiftRows->AddRoundKey
		void Key_InvMix(u32 W[], u32 W_mix[], int keysize) { //라운드키를 InvMixColumn연산 수행((N-1)~1라운드)
			int Nr = keysize / 32 + 6;
			//복호화 최적화 테이블 : InvSubBytes, InvMixColumns
			//라운드키에 InvMixColumns 연산을 하려면 복호화 최적화 테이블에 Sbox 치환만 해주면 가능
			for (int i = 1; i < Nr; i++) {
				W_mix[i * 4] = Td0[Sbox[(W[i * 4] >> 24)] & 0xff] ^ Td1[Sbox[(W[i * 4] >> 16) & 0xff] & 0xff] ^ Td2[Sbox[(W[i * 4] >> 8) & 0xff] & 0xff] ^ Td3[Sbox[(W[i * 4]) & 0xff] & 0xff];
				W_mix[i * 4 + 1] = Td0[Sbox[(W[i * 4 + 1] >> 24)] & 0xff] ^ Td1[Sbox[(W[i * 4 + 1] >> 16) & 0xff] & 0xff] ^ Td2[Sbox[(W[i * 4 + 1] >> 8) & 0xff] & 0xff] ^ Td3[Sbox[(W[i * 4 + 1]) & 0xff] & 0xff];
				W_mix[(i * 4) + 2] = Td0[Sbox[(W[i * 4 + 2] >> 24)] & 0xff] ^ Td1[Sbox[(W[i * 4 + 2] >> 16) & 0xff] & 0xff] ^ Td2[Sbox[(W[i * 4 + 2] >> 8) & 0xff] & 0xff] ^ Td3[Sbox[(W[i * 4 + 2]) & 0xff] & 0xff];
				W_mix[(i * 4) + 3] = Td0[Sbox[(W[i * 4 + 3] >> 24)] & 0xff] ^ Td1[Sbox[(W[i * 4 + 3] >> 16) & 0xff] & 0xff] ^ Td2[Sbox[(W[i * 4 + 3] >> 8) & 0xff] & 0xff] ^ Td3[Sbox[(W[i * 4 + 3]) & 0xff] & 0xff];
			}
		}
		```
		+ 128비트 복호화라고 했을 때 10라운드는 AddRoundKey만 한다. 9~1라운드에는 Inverse MixColumns 연산을 한 라운드 키 들어간다. 
		```
				//10라운드(AddRoundKey)
		s0 = u4byte_in(CT) ^ W[40];		 //CT : 8bit -> 32bit
		s1 = u4byte_in(CT + 4) ^ W[41];
		s2 = u4byte_in(CT + 8) ^ W[42];
		s3 = u4byte_in(CT + 12) ^ W[43];
		}
		//9라운드(InvSubByte, InvShiftRows, InvMixColumns, AddRoundKey)
		t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ W_mix[36]; //< -InvMixColumn(RoundKey)
		t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ W_mix[37];
		t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ W_mix[38];
		t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ W_mix[39];
		```
		![화면 캡처 2022-10-15 134856](https://user-images.githubusercontent.com/84726924/195969684-77a08b45-5e87-47cc-b35b-5b3985038947.png)
		+ 0라운드에는 InvSubBytes와 InvShiftRows, AddRoundKey만 해주면 된다.
		```
		//0라운드(InvSubByte, InvShiftRows, AddRoundKey)
		//InvSbox는 8bit이기 때문에 ...&0xff000000을 해주면 에러가 발생함. 따라서 bit단위로 쉬프트해준다.
		s0 = (InvSbox[t0 >> 24] << 24) ^ (InvSbox[(t3 >> 16) & 0xff] << 16) ^ (InvSbox[(t2 >> 8) & 0xff] << 8) ^ (InvSbox[t1 & 0xff]) ^ W[0]; //0라운드에는 키스케쥴링 된 라운드키가 들어간다.
		s1 = (InvSbox[t1 >> 24] << 24) ^ (InvSbox[(t0 >> 16) & 0xff] << 16) ^ (InvSbox[(t3 >> 8) & 0xff] << 8) ^ (InvSbox[t2 & 0xff]) ^ W[1];
		s2 = (InvSbox[t2 >> 24] << 24) ^ (InvSbox[(t1 >> 16) & 0xff] << 16) ^ (InvSbox[(t0 >> 8) & 0xff] << 8) ^ (InvSbox[t3 & 0xff]) ^ W[2];
		s3 = (InvSbox[t3 >> 24] << 24) ^ (InvSbox[(t2 >> 16) & 0xff] << 16) ^ (InvSbox[(t1 >> 8) & 0xff] << 8) ^ (InvSbox[t0 & 0xff]) ^ W[3];
		```
		+ AES 최적화 복호화로 구현했을 때 연산속도가 AES 복호화보다 월등히 빠른 것을 확인할 수 있다.
		![화면 캡처 2022-10-15 134856](https://user-images.githubusercontent.com/84726924/195969717-64d338ca-5a39-4245-90a9-83564868d671.png)
***
#AES 파일 복호화
+ **AES 파일 복호화 과정**
	+ **블록암호 운용방식**
		+ 블록암호 운용 방식은 하나의 키에서 블록 암호를 반복적으로 동작한다. 블록암호는 특정한 길이의 블록 단위로 동작하기 때문에, 가변 길이 데이터를 암호화하기 위해서는 먼저 단위 블록들로 나누어야 하며, 그 블록들을 어떻게 암호화할지 정해야 하는데, 이 때 블록들의 암호화 방식을 운용 방식이라 한다.
	+ **CBC 운용모드**
		+ 각 블록은 암호화되기 전에 이전 블록의 암호화 결과와 XOR되며, 첫 블록의 경우 초기화 벡터(IV)가 사용된다. 초기화 벡터가 같은 경우 출력 결과가 항상 같기 때문에, 매 암호화마다 다른 초기화 벡터를 사용해야 한다.
		![화면 캡처 2022-10-15 134856](https://user-images.githubusercontent.com/84726924/195969931-6cfd39b8-9e6d-4246-b836-124619c06c76.png)
		+ CBC 모드로 복호화 할 때는 암호문 블록을 복호화 한 다음 초기화 벡터(IV)와 XOR연산을 한다. 2번 째 블록부터는 직전 블록의 암호문 블록과 XOR 연산을 하여 복호화를 한다. CBC는 암호화 입력 값이 이전 결과에 의존하기 때문에 병렬화가 불가능하다. 하지만 복호화의 경우 각 블록을 복호화 한 다음 이전 암호문 블록과 XOR하여 복구할 수 있기 때문에 병렬화가 가능하다.
		![화면 캡처 2022-10-15 134856](https://user-images.githubusercontent.com/84726924/195969954-402a15fd-950e-485c-a4b9-638ffd596fa8.png)
	+ **PKCS#7 패딩**
		+ CBC모드로 암호화를 할 때 마지막 블록이 블록의 길이와 딱 맞아 떨어지지 않기 때문에, 부족한 길이만큼 임의의 비트들로 채워 넣어야 한다. 이러한 방식을 패딩이라고 한다.
		+ 임의의 파일을 AES 128비트로 암호화 한다고 했을 때 그 파일은 16바이트의 배수가 되어야 한다. 만약 마지막 블록이 11바이트라고 하면 나머지 5바이트를 패딩으로 채운다. PKCS#7 패딩을 이용하면 마지막 블록의 맨 뒤에 “05 05 05 05 05”라는 값이 들어간다. 즉 패딩 된 바이트의 수만큼 값이 들어간다. 파일의 길이가 16바이트의 배수일 경우엔 “10 10 10...” 10이 16개가 들어간다.
+ **AES 파일 복호화 구현**
	+ **AES 파일 입출력**
		+ 먼저 파일 입출력은 코드 안에서 파일을 불러와서 처리하는 방법이 있고, cmd 커맨드 창에서 인자를 받아서 처리하는 방법이 있다. 후자로 구현을 하면 main() 함수에 인자를 받을 수 있는 일종의 변수를 선언해 줘야 한다. 예를 들어서 커맨드 창에 “AES_ENC.exe cbc a.txt a.txt.enc”라고 입력할 경우 각 자리의 입력 값이 argv[0], argv[1], argv[2], argv[3]에 들어가게 된다. 해석을 하면 AES_ENC.exe를 실행하고 cbc모드로 a.txt파일을 a.txt.enc파일로 암호화 한다는 뜻이다.
		```
		//int argc : 인자의 개수, char* argv[v] : argv[0] argv[1] argv[2] argv[3] 인자를 받아서 처리하는 변수
		int main(int argc, char* argv[]) {
		```
		+ 파일 입력은 “FILE \*변수명”라는 파일 포인터를 선언한다. fopen_s()함수로 인자 값으로 받은 파일을 바이너리 형식의 읽기 모드로 연다. 그런데 파일이 NULL이라면 오류 메시지를 띄워주는 예외처리를 둔다. fseek() 함수로 파일 포인터를 끝으로 이동시킨 다음 파일의 크기를 DataLen에 저장한다. 그리고 다시 fseek() 함수로 파일 포인터를 맨 앞으로 이동시킨다. 이러한 작업을 해주는 이유는 파일 복호화에서 패딩을 제거해주기 위해서이다. 그런 다음 inputbuf에 파일의 길이만큼 데이터를 담아준다. 파일 출력도 입력과 거의 유사하다.
		```
		FILE* rfp, * wfp; //inputfile=rfp, outputfile=wfp
		u8* inputbuf, * outputbuf, r;
		u8 IV[16] = { 0x00, }; //초기화 벡터
		u32 DataLen, i;

		fopen_s(&rfp, inputfile, "rb");

		if (rfp == NULL) { //예외처리
			perror("fopen_s 실패!!\n");
		}
		fseek(rfp, 0, SEEK_END); //file point를 끝으로 이동
		DataLen = ftell(rfp); //inputfile의 크기(바이트 수)
		fseek(rfp, 0, SEEK_SET); //file point를 처음으로 이동

		inputbuf = calloc(DataLen, sizeof(u8)); //calloc:동적메모리 할당 후 0으로 초기화
		outputbuf = calloc(DataLen, sizeof(u8));
		fread(inputbuf, 1, DataLen, rfp); //파일의 길이만큼 1바이트씩 inputbuf에 담음
		fclose(rfp);
		```
	+ **AES 파일 복호화(CBC)**
		+ CBC모드에서 복호화는 암호문블록이 복호화과정을 거치고 나서 초기화 벡터와 XOR 연산을 하게 되고, 2번 째 블록부터는 이전 블록의 암호문블록과 XOR연산을 하게 된다.
		```
		AES_DEC_Optimization(inputbuf, W, outputbuf,W_mix, 128); //처음 파일 16바이트 복호화
		XOR16Bytes(outputbuf, IV); //복호화된 16바이트와 초기화벡터를 XOR 연산
	
		for (i = 1; i < (DataLen) / 16; i++) { //16바이트부터 끝까지 복호화
			AES_DEC_Optimization(inputbuf + 16 * i, W, outputbuf + 16 * i, W_mix, 128);
			XOR16Bytes(outputbuf + 16 * i, inputbuf + 16 * (i-1) );
		}
		```
	+ **PKCS#7 패딩 제거**
		+ PKCS#7 패딩은 파일 뒷부분 패딩된 데이터가 4바이트면 “04 04 04 04”로 들어가 있기 때문에 파일의 마지막 부분의 값만큼 빼주면 된다. 여기서 아래와 같이 ouputbuf에는 복호화된 파일의 전체 데이터가 들어가 있다. DataLen은 파일의 크기가 들어가 있고 outputbuf [DataLen-1]로 패딩 값을 가져올 수 있다. DataLen에 –1을 해주는 이유는 파일의 맨 마지막엔 null값이 들어가기 때문이다. 그런 다음 ouputbuf에 있는 데이터를 패딩을 제거한(DataLen-r)만큼 wfp에 쓰면 된다.
		```
		fopen_s(&wfp, outputfile, "wb");
		r = outputbuf[DataLen - 1]; //복호화된 파일의 패딩 값을 r에 저장
		if (wfp == NULL) { //예외처리
			perror("fopen_s 실패!!\n");
		}
		fwrite(outputbuf, 1, DataLen - r, wfp); //outputbuf에 있는 데이터를 DataLen-r만큼 wfp에 씀
		fclose(wfp);
		```
	+ **AES 파일 복호화 결과**
		+ main()함수에서 키 스케줄링을 먼저 해주고 파일 복호화 함수를 실행시켜주면 된다. 여기서는 속도 체크를 하기 위해 clock()함수를 사용하고, for문으로 10,000번을 복호화 했다.
		```
		else if (strcmp(argv[1], "cbc_D") == 0) {
			AES_KeySchedule_Optimization(MK, W, keysize);
			start = clock();
			for (i = 0; i < 10000; i++) CBC_Decryption(argv[2], argv[3], W, W_mix);
			finish = clock();
			printf("=========================================\n");
			printf("Computation time : %f seconds\n", (double)(finish - start) / CLOCKS_PER_SEC);
			printf("=========================================\n");
		}
		```
		+ 솔루션 빌드를 하고 나서 커맨드 창에서 AES_ENC.exe 실행파일이 있는 위치로 이동한 다음 “AES_ENC.exe cbc_D 4.jpeg.encrypted 4.jpeg”를 입력했다. 해석을 하자면 cbc모드로 4.jpeg.encrypted파일을 4.jpeg로 복호화 한 것이다. 그리고 cbc모드 복호화를 10,000번 수행했을 때 7.623초가 나온 것을 확인할 수 있다.
		![화면 캡처 2022-10-15 134856](https://user-images.githubusercontent.com/84726924/195970239-55efe5a7-f732-4978-a1fa-9b228afa0003.png)
		+ 암호화 된 파일을 복호화 한 결과는 아래와 같다.
		![화면 캡처 2022-10-15 134856](https://user-images.githubusercontent.com/84726924/195970297-1c8082fa-05ab-44ba-97fc-91db0f804652.png)
