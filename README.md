# AES_encryption-decryption_implementation
AES_encryption-decryption(basic, optimization, file)

This project includes the following.

1.Basic AES encryption/decryption

2.AES-optimized encryption/decryption

3.File AES encryption/decryption (CBC operation mode, ECB operation mode, PKCS#7 padding)
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
    
