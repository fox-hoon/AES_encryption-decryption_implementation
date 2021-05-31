#include<stdio.h>
#include<assert.h>
#include<stdlib.h>
#include "aes.h"
#include<time.h>
#include<memory.h>

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
//==================================================
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
//곱셈의 역원연산 후 아핀연산
u8 GenSbox(u8 a) { 
	u8 r = 0;
	u8 tmp;
	tmp = inv(a);
	//2^8 = {128,64,32,16,8,4,2,1}
	if (tmp & 1) r ^= 0x1f; //AND연산한 결과가 1이면 0x1f와 XOR연산 수행
	if (tmp & 2) r ^= 0x3e;
	if (tmp & 4) r ^= 0x7c;
	if (tmp & 8) r ^= 0xf8;
	if (tmp & 16) r ^= 0xf1;
	if (tmp & 32) r ^= 0xe3;
	if (tmp & 64) r ^= 0xc7;
	if (tmp & 128) r ^= 0x8f;
	return r ^ 0x63;

}
//역 아핀연산 후 곱셈의 역원연산
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
//==================================================
//==================================AES_ENC==========================================
void AddRoundKey(u8 S[16], u8 RK[16]) { //각 라운드 키와 XOR 연산만 수행(S=S XOR RK)
	S[0] ^= RK[0]; S[1] ^= RK[1]; S[2] ^= RK[2]; S[3] ^= RK[3];
	S[4] ^= RK[4]; S[5] ^= RK[5]; S[6] ^= RK[6]; S[7] ^= RK[7];
	S[8] ^= RK[8]; S[9] ^= RK[9]; S[10] ^= RK[10]; S[11] ^= RK[11];
	S[12] ^= RK[12]; S[13] ^= RK[13]; S[14] ^= RK[14]; S[15] ^= RK[15];
}
void SubBytes(u8 S[16]) { //각각의 Sbox 표로 치환
	S[0] = Sbox[S[0]]; S[1] = Sbox[S[1]]; S[2] = Sbox[S[2]]; S[3] = Sbox[S[3]];
	S[4] = Sbox[S[4]]; S[5] = Sbox[S[5]]; S[6] = Sbox[S[6]]; S[7] = Sbox[S[7]];
	S[8] = Sbox[S[8]]; S[9] = Sbox[S[9]]; S[10] = Sbox[S[10]]; S[11] = Sbox[S[11]];
	S[12] = Sbox[S[12]]; S[13] = Sbox[S[13]]; S[14] = Sbox[S[14]]; S[15] = Sbox[S[15]];
}
void ShiftRows(u8 S[16]) { 
	u8 temp;
	temp = S[1];
	S[1] = S[5]; S[5] = S[9]; S[9] = S[13]; S[13] = temp; //2행을 왼쪽으로 1바이트 쉬프트
	temp = S[2];
	S[2] = S[10]; S[10] = temp; temp = S[6]; S[6] = S[14]; S[14] = temp; //3행을 왼쪽으로 2바이트 쉬프트
	temp = S[15];
	S[15] = S[11]; S[11] = S[7]; S[7] = S[3]; S[3] = temp; //4행을 왼쪽으로 3바이트 쉬프트
}
void MixColumns(u8 S[16]) {
	u8 temp[16];
	int i;
	for (i = 0; i < 16; i += 4) {
		temp[i] = MUL2(S[i]) ^ MUL3(S[i + 1]) ^ S[i + 2] ^ S[i + 3]; //(02*S[0]) ^(03*S[1]) ^(01*S[2]) ^(01*S[3]) 
		temp[i + 1] = S[i] ^ MUL2(S[i + 1]) ^ MUL3(S[i + 2]) ^ S[i + 3]; //(01*S[0]) ^(02*S[1]) ^(03*S[2]) ^(01*S[3]) 
		temp[i + 2] = S[i] ^ S[i + 1] ^ MUL2(S[i + 2]) ^ MUL3(S[i + 3]); //(01*S[0]) ^(01*S[1]) ^(02*S[2]) ^(03*S[3]) 
		temp[i + 3] = MUL3(S[i]) ^ S[i + 1] ^ S[i + 2] ^ MUL2(S[i + 3]); //(03*S[0]) ^(01*S[1]) ^(01*S[2]) ^(02*S[3]) 
	}
	S[0] = temp[0]; S[1] = temp[1]; S[2] = temp[2]; S[3] = temp[3];
	S[4] = temp[4]; S[5] = temp[5]; S[6] = temp[6]; S[7] = temp[7];
	S[8] = temp[8]; S[9] = temp[9]; S[10] = temp[10]; S[11] = temp[11];
	S[12] = temp[12]; S[13] = temp[13]; S[14] = temp[14]; S[15] = temp[15];

}
//AES 암호화 : AddRoundKey->(SubBytes->ShiftRows->MixColumns->AddRoundKey)(Nr-1)->SubBytes->ShiftRows->AddRoundKey
void AES_ENC(u8 PT[16], u8 RK[], u8 CT[16], int keysize) {
	int Nr = keysize / 32 + 6; //라운드 수 설정
	int i;
	u8 temp[16];

	for (i = 0; i < 16; i++) temp[i] = PT[i]; //평문을 temp에 저장

	AddRoundKey(temp, RK); //temp의 16byte와 RK의 첫 16byte를 XOR하여 temp에 결과를 담는 함수
	for (i = 0; i < Nr - 1; i++) { //if 128비트이면 1~9라운드까지 반복
		SubBytes(temp);
		ShiftRows(temp);
		MixColumns(temp);
		AddRoundKey(temp, RK + 16 * (i + 1));
	}
	SubBytes(temp);
	ShiftRows(temp);
	AddRoundKey(temp, RK + 16 * (i + 1));

	for (i = 0; i < 16; i++) CT[i] = temp[i]; //암호화된 값을 암호문 배열에 저장
}
//==================================================================
//================================AES_DEC===============================
//Inverse Sbox : 역원연산 과정은 암호화과정이랑 동일하지만 역 아핀연산을 통해 구할 수 있음
void InvSubBytes(u8 S[16]) { //각 각 Inverse Sbox표에 치환
	S[0] = InvSbox[S[0]]; S[1] = InvSbox[S[1]]; S[2] = InvSbox[S[2]]; S[3] = InvSbox[S[3]]; 
	S[4] = InvSbox[S[4]]; S[5] = InvSbox[S[5]]; S[6] = InvSbox[S[6]]; S[7] = InvSbox[S[7]];
	S[8] = InvSbox[S[8]]; S[9] = InvSbox[S[9]]; S[10] = InvSbox[S[10]]; S[11] = InvSbox[S[11]];
	S[12] = InvSbox[S[12]]; S[13] = InvSbox[S[13]]; S[14] = InvSbox[S[14]]; S[15] = InvSbox[S[15]];
}

void InvShiftRows(u8 S[16]) {
	u8 temp;
	temp = S[1];
	S[1] = S[13]; S[13] = S[9]; S[9] = S[5]; S[5] = temp; //2행을 오른쪽으로 1바이트 쉬프트
	temp = S[2];
	S[2] = S[10]; S[10] = temp; temp = S[6]; S[6] = S[14]; S[14] = temp; //3행을 오른쪽으로 2바이트 쉬프트
	temp = S[15];
	S[15] = S[3]; S[3] = S[7]; S[7] = S[11]; S[11] = temp; //4행을 오른쪽으로 3바이트 쉬프트
}
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
//AES 복호화 : AddRoundKey->InvShiftRows->InvSubBytes->(AddRoundKey->InvMixColumns->InvShiftRows->InvSubBytes)(Nr-1)->AddRoundKey
void AES_DEC(u8 CT[16], u8 RK[], u8 PT[16], int keysize) {
	int Nr = keysize / 32 + 6; //라운드 수 설정
	int i;
	u8 temp[16];

	for (i = 0; i < 16; i++) temp[i] = CT[i]; //암호문을 temp에 저장

	AddRoundKey(temp, RK + 16 * Nr); //160~175
	InvShiftRows(temp);
	InvSubBytes(temp);
	for (i = Nr; i > 1; i--) {
		AddRoundKey(temp, RK + 16 * (i - 1)); //143~159, 126~142, 109~125,ㆍㆍㆍ16~31
		InvMixColumns(temp);
		InvShiftRows(temp);
		InvSubBytes(temp);
	}
	AddRoundKey(temp, RK);//0~15
	for (i = 0; i < 16; i++) PT[i] = temp[i]; //복호화된 암호문을 평문에 저장
}
//===============================================================================
//==================================KeySchedule=====================================
u32 u4byte_in(u8* x) { //8bit input -> 32bit output
	return (x[0] << 24) | (x[1] << 16) | (x[2] << 8) | x[3];  //x[0]||x[1]||x[2]||x[3]
}

void u4byte_out(u8* x, u32 y) { //32bit input -> 8bit output
	x[0] = (y >> 24) & 0xff;
	x[1] = (y >> 16) & 0xff;
	x[2] = (y >> 8) & 0xff;
	x[3] = y & 0xff;
}

void AES_KeyWordToByte(u32 W[], u8 RK[]) {
	int i;
	for (i = 0; i < 44; i++) {
		u4byte_out(RK + 4 * i, W[i]); //RK[4i]||RK[4i+1]||RK[4i+2]||RK[4i+3] <--W[i]
	}
}

u32 Rcons[10] = { 0x01000000,0x02000000,0x04000000,0x08000000, //상수값
				  0x10000000,0x20000000,0x40000000,0x80000000,
				  0x1b000000,0x36000000 };

//	4바이트 워드 단위를 왼쪽으로 1바이트 쉬프트. ex) RotWord([89 ab cd ef]) = [ab cd ef 89]
#define RotWord(x) ((x<<8)|(x>>24))	

//바이트 단위로 SubBytes 연산. ex)SubWord([ab cd ef 89]) = [62 bd df a7]
#define SubWord(x)							  \
	((u32)Sbox[(u8)(x >> 24)]<<24)		 	  \
	| ((u32)Sbox[(u8)((x >> 16) & 0xff)]<<16) \
	| ((u32)Sbox[(u8)((x >> 8) & 0xff)] << 8) \
	| ((u32)Sbox[(u8)(x & 0xff)])			  \

void RoundKeyGeneration128(u8 MK[], u8 RK[]) {
	u32 W[44];
	int i;
	u32 T;

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
	AES_KeyWordToByte(W, RK); //32bit 라운드키 -> 8bit 라운드키로 출력
}
void RoundKeyGeneration128_Optimization(u8 MK[], u32 W[]) {
	int i;
	u32 T;

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
	//라운드 키를 32bit로 사용하기 때문에 AES_KeyWordToByte()함수는 사용할 필요 없음
}
void AES_KeySchedule(u8 MK[], u8 RK[], int keysize) { 
	if (keysize == 128)RoundKeyGeneration128(MK, RK);
	//if (keysize == 192)RoundKeyGeneration192(MK, RK);
	//if (keysize == 256)RoundKeyGeneration256(MK, RK);
}
void AES_KeySchedule_Optimization(u8 MK[], u32 W[], int keysize) {
	if (keysize == 128)RoundKeyGeneration128_Optimization(MK, W);
	//if (keysize == 192)RoundKeyGeneration192_Optimization(MK, W);
	//if (keysize == 256)RoundKeyGeneration256_Optimization(MK, W);
}
//==============================================================================
//==========================AES_ENC(DEC)_Optimization============================
void AES_ENC_Optimization(u8 PT[16], u32 W[], u8 CT[16], int keysize) {
	int Nr = keysize / 32 + 6; //라운드 수 설정
	u32 s0, s1, s2, s3, t0, t1, t2, t3;

	//0 round
	s0 = u4byte_in(PT) ^ W[0];
	s1 = u4byte_in(PT + 4) ^ W[1];
	s2 = u4byte_in(PT + 8) ^ W[2];
	s3 = u4byte_in(PT + 12) ^ W[3];

	//최적화 테이블 Te0~3 : MixColumns, SubBytes 연산이 되어있는 상태
	//ex) s0 >> 24, s1 >> 16, s2 >> 8 : ShiftRows
	// ... ^ W[4] : AddRoundKey

	//1 round
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[4];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[5];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[6];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[7];

	//2 round
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[8];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[9];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[10];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[11];

	//3 round
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[12];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[13];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[14];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[15];

	//4 round
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[16];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[17];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[18];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[19];

	//5 round
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[20];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[21];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[22];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[23];

	//6 round
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[24];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[25];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[26];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[27];

	//7 round
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[28];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[29];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[30];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[31];

	//8 round
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[32];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[33];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[34];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[35];
	if (Nr == 10) { //10라운드(128비트)
		//9 round
		t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[36];
		t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[37];
		t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[38];
		t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[39];

		//10 round
		s0 = (Te2[t0 >> 24] & 0xff000000) ^ (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t3 & 0xff] & 0x000000ff) ^ W[40];
		s1 = (Te2[t1 >> 24] & 0xff000000) ^ (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t0 & 0xff] & 0x000000ff) ^ W[41];
		s2 = (Te2[t2 >> 24] & 0xff000000) ^ (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t1 & 0xff] & 0x000000ff) ^ W[42];
		s3 = (Te2[t3 >> 24] & 0xff000000) ^ (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t2 & 0xff] & 0x000000ff) ^ W[43];
	}
	else if (Nr == 12) {
		//9 round
		t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[36];
		t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[37];
		t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[38];
		t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[39];

		//10 round
		s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[40];
		s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[41];
		s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[42];
		s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[43];
		//11 round
		t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[44];
		t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[45];
		t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[46];
		t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[47];

		//12 round
		s0 = (Te2[t0 >> 24] & 0xff000000) ^ (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t3 & 0xff] & 0x000000ff) ^ W[48];
		s1 = (Te2[t1 >> 24] & 0xff000000) ^ (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t0 & 0xff] & 0x000000ff) ^ W[49];
		s2 = (Te2[t2 >> 24] & 0xff000000) ^ (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t1 & 0xff] & 0x000000ff) ^ W[50];
		s3 = (Te2[t3 >> 24] & 0xff000000) ^ (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t2 & 0xff] & 0x000000ff) ^ W[51];
	}

	else if (Nr == 14) {
		//9 round
		t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[36];
		t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[37];
		t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[38];
		t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[39];

		//10 round
		s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[40];
		s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[41];
		s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[42];
		s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[43];

		//11 round
		t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[44];
		t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[45];
		t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[46];
		t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[47];

		//12 round
		s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[48];
		s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[49];
		s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[50];
		s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[51];

		//13 round
		t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[52];
		t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[53];
		t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[54];
		t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[55];

		//14 round
		//... & 0xff000000 : 맨 앞 8bit만 살리고 나머지 bit는 사용하지 않음
		s0 = (Te2[t0 >> 24] & 0xff000000) ^ (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t3 & 0xff] & 0x000000ff) ^ W[56];
		s1 = (Te2[t1 >> 24] & 0xff000000) ^ (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t0 & 0xff] & 0x000000ff) ^ W[57];
		s2 = (Te2[t2 >> 24] & 0xff000000) ^ (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t1 & 0xff] & 0x000000ff) ^ W[58];
		s3 = (Te2[t3 >> 24] & 0xff000000) ^ (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t2 & 0xff] & 0x000000ff) ^ W[59];
	}
	//32bit 암호문을 8bit로 변환
	u4byte_out(CT, s0);
	u4byte_out(CT + 4, s1);
	u4byte_out(CT + 8, s2);
	u4byte_out(CT + 12, s3);
}

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
//최적화 복호화 : AddRoundKey->(InvSubBytes->InvShiftRows->InvMixColumns->AddRoundKey)(N-1)->InvSubBytes->InvShiftRows->AddRoundKey
void AES_DEC_Optimization(u8 CT[16], u32 W[], u8 PT[16], u32 W_mix[], int keysize) {
	int Nr = keysize / 32 + 6; //라운드 수 설정
	u32 s0, s1, s2, s3, t0, t1, t2, t3;

	Key_InvMix(W, W_mix, keysize);
	//(N-1) ~ 1라운드 까지 InvMixColumns 연산이 된 라운드키가 들어간다.
	if (Nr == 14) {
		//14라운드
		s0 = u4byte_in(CT) ^ W[56];
		s1 = u4byte_in(CT + 4) ^ W[57];
		s2 = u4byte_in(CT + 8) ^ W[58];
		s3 = u4byte_in(CT + 12) ^ W[59];
		//13라운드
		t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ W_mix[52];
		t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ W_mix[53];
		t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ W_mix[54];
		t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ W_mix[55];
		//12라운드
		s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ W_mix[48];
		s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ W_mix[49];
		s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ W_mix[50];
		s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ W_mix[51];
		//11라운드
		t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ W_mix[44];
		t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ W_mix[45];
		t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ W_mix[46];
		t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ W_mix[47];
		//10라운드
		s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ W_mix[40];
		s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ W_mix[41];
		s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ W_mix[42];
		s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ W_mix[43];
	}
	else if (Nr == 12) {
		//12라운드
		s0 = u4byte_in(CT) ^ W[48];
		s1 = u4byte_in(CT + 4) ^ W[49];
		s2 = u4byte_in(CT + 8) ^ W[50];
		s3 = u4byte_in(CT + 12) ^ W[51];
		//11라운드
		t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ W_mix[44];
		t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ W_mix[45];
		t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ W_mix[46];
		t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ W_mix[47];
		//10라운드
		s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ W_mix[40];
		s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ W_mix[41];
		s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ W_mix[42];
		s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ W_mix[43];
	}
	else if (Nr == 10) {
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

	//8라운드
	s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ W_mix[32];
	s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ W_mix[33];
	s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ W_mix[34];
	s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ W_mix[35];

	//7라운드
	t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ W_mix[28];
	t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ W_mix[29];
	t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ W_mix[30];
	t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ W_mix[31];

	//6라운드
	s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ W_mix[24];
	s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ W_mix[25];
	s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ W_mix[26];
	s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ W_mix[27];

	//5라운드
	t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ W_mix[20];
	t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ W_mix[21];
	t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ W_mix[22];
	t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ W_mix[23];

	//4라운드
	s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ W_mix[16];
	s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ W_mix[17];
	s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ W_mix[18];
	s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ W_mix[19];

	//3라운드
	t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ W_mix[12];
	t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ W_mix[13];
	t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ W_mix[14];
	t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ W_mix[15];

	//2라운드
	s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ W_mix[8];
	s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ W_mix[9];
	s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ W_mix[10];
	s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ W_mix[11];

	//1라운드
	t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ W_mix[4];
	t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ W_mix[5];
	t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ W_mix[6];
	t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ W_mix[7];

	//0라운드(InvSubByte, InvShiftRows, AddRoundKey)
	//InvSbox는 8bit이기 때문에 ...&0xff000000을 해주면 에러가 발생함. 따라서 bit단위로 쉬프트해준다.
	s0 = (InvSbox[t0 >> 24] << 24) ^ (InvSbox[(t3 >> 16) & 0xff] << 16) ^ (InvSbox[(t2 >> 8) & 0xff] << 8) ^ (InvSbox[t1 & 0xff]) ^ W[0]; //0라운드에는 키스케쥴링 된 라운드키가 들어간다.
	s1 = (InvSbox[t1 >> 24] << 24) ^ (InvSbox[(t0 >> 16) & 0xff] << 16) ^ (InvSbox[(t3 >> 8) & 0xff] << 8) ^ (InvSbox[t2 & 0xff]) ^ W[1];
	s2 = (InvSbox[t2 >> 24] << 24) ^ (InvSbox[(t1 >> 16) & 0xff] << 16) ^ (InvSbox[(t0 >> 8) & 0xff] << 8) ^ (InvSbox[t3 & 0xff]) ^ W[2];
	s3 = (InvSbox[t3 >> 24] << 24) ^ (InvSbox[(t2 >> 16) & 0xff] << 16) ^ (InvSbox[(t1 >> 8) & 0xff] << 8) ^ (InvSbox[t0 & 0xff]) ^ W[3];

	//32bit->8bit
	u4byte_out(PT, s0); //s0을 PT에 담음
	u4byte_out(PT + 4, s1);
	u4byte_out(PT + 8, s2);
	u4byte_out(PT + 12, s3);


}
//=======================================================================================
//=======================================File ENC(DEC)==================================
void ECB_Encryption(char* inputfile, char* outputfile, u32 W[]) {
	FILE* rfp, * wfp; //inputfile=rfp, outputfile=wfp
	u8* inputbuf, * outputbuf, r;
	u32 DataLen, i;

	fopen_s(&rfp, inputfile, "rb"); 

	if (rfp == NULL) { //예외처리
		perror("fopen_s 실패!!\n");
	}
	fseek(rfp, 0, SEEK_END); //file point를 끝으로 이동
	DataLen = ftell(rfp); //inputfile의 크기(바이트 수)
	fseek(rfp, 0, SEEK_SET); //file point를 처음으로 이동

	r = DataLen % 16;
	r = 16 - r; //PKCS #7 패딩에서 패딩해야 하는 바이트 수

	inputbuf = calloc(DataLen + r, sizeof(u8)); //calloc:동적메모리 할당 후 0으로 초기화
	outputbuf = calloc(DataLen + r, sizeof(u8));
	fread(inputbuf, 1, DataLen, rfp); //파일의 길이만큼 1바이트씩 inputbuf에 담음
	fclose(rfp);
	memset(inputbuf + DataLen, r, r); //r바이트만큼 r로패딩. ex)....07 07 07 07
	for (i = 0; i < (DataLen + r) / 16; i++) { //파일을 16바이트씩 암호화
		AES_ENC_Optimization(inputbuf + 16 * i, W, outputbuf + 16 * i, 128);
	}

	fopen_s(&wfp, outputfile, "wb");
	if (wfp == NULL) { //예외처리
		perror("fopen_s 실패!!\n");
	}
	fwrite(outputbuf, 1, DataLen + r, wfp); //outputbuf에 있는 데이터를 DataLen+r만큼 wfp에 씀
	fclose(wfp);
}
void ECB_Decryption(char* inputfile, char* outputfile, u32 W[], u32 W_mix[]) {
	FILE* rfp, * wfp; //inputfile=rfp, outputfile=wfp
	u8* inputbuf, * outputbuf, r;
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

	for (i = 0; i < (DataLen) / 16; i++) { //파일을 16바이트씩 복호화
		AES_DEC_Optimization(inputbuf + 16 * i, W, outputbuf + 16 * i, W_mix, 128);
	}
	fopen_s(&wfp, outputfile, "wb");
	r = outputbuf[DataLen - 1]; //복호화된 파일의 패딩 값을 r에 저장
	if (wfp == NULL) { //예외처리
		perror("fopen_s 실패!!\n");
	}
	fwrite(outputbuf, 1, DataLen - r, wfp); //outputbuf에 있는 데이터를 DataLen-r만큼 wfp에 씀
	fclose(wfp);
}
//CBC모드에서 XOR연산
void XOR16Bytes(u8 S[16], u8 RK[16]) { //S = S xor RK
	S[0] ^= RK[0]; S[1] ^= RK[1]; S[2] ^= RK[2]; S[3] ^= RK[3];
	S[4] ^= RK[4]; S[5] ^= RK[5]; S[6] ^= RK[6]; S[7] ^= RK[7];
	S[8] ^= RK[8]; S[9] ^= RK[9]; S[10] ^= RK[10]; S[11] ^= RK[11];
	S[12] ^= RK[12]; S[13] ^= RK[13]; S[14] ^= RK[14]; S[15] ^= RK[15];
}

void CBC_Encryption(char* inputfile, char* outputfile, u32 W[]) {
	FILE* rfp, * wfp; //inputfile=rfp, outputfile=wfp
	u8* inputbuf, * outputbuf, r;
	u8 IV[16] = { 0x00, }; //초기화 벡터
	u32 DataLen, i;

	fopen_s(&rfp, inputfile, "rb");
	if (rfp == NULL) { //예외처리
		perror("fopen_s 실패!!\n");
	}
	fseek(rfp, 0, SEEK_END); //file point의 끝으로 이동
	DataLen = ftell(rfp); //inputfile의 크기(바이트 수)
	fseek(rfp, 0, SEEK_SET); //file point를 처음으로 이동

	r = DataLen % 16;
	r = 16 - r; //PKCS #7 패딩에서 패딩해야 하는 바이트 수

	inputbuf = calloc(DataLen + r, sizeof(u8)); //calloc:동적메모리 할당 후 0으로 초기화
	outputbuf = calloc(DataLen + r, sizeof(u8));
	fread(inputbuf, 1, DataLen, rfp); //파일의 길이만큼 1바이트씩 inputbuf에 담음
	fclose(rfp);
	memset(inputbuf + DataLen, r, r); //r바이트만큼 r로 패딩 ex)...07 07 07 07

	XOR16Bytes(inputbuf, IV); //처음 파일 16바이트와  초기화벡터를 XOR 연산
	AES_ENC_Optimization(inputbuf, W, outputbuf, 128); 

	for (i = 1; i < (DataLen + r) / 16; i++) { //16바이트부터 끝까지 암호화
		XOR16Bytes(inputbuf + 16 * i, outputbuf + 16 * (i - 1));
		AES_ENC_Optimization(inputbuf + 16 * i, W, outputbuf + 16 * i, 128);
	}

	fopen_s(&wfp, outputfile, "wb");
	if (wfp == NULL) { //예외처리
		perror("fopen_s 실패!!\n");
	}
	fwrite(outputbuf, 1, DataLen + r, wfp); //outputbuf에 있는 데이터를 DataLen+r만큼 wfp에 씀
	fclose(wfp);
}
void CBC_Decryption(char* inputfile, char* outputfile, u32 W[], u32 W_mix[]) {
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

	AES_DEC_Optimization(inputbuf, W, outputbuf,W_mix, 128); //처음 파일 16바이트 복호화
	XOR16Bytes(outputbuf, IV); //복호화된 16바이트와 초기화벡터를 XOR 연산
	
	for (i = 1; i < (DataLen) / 16; i++) { //16바이트부터 끝까지 복호화
		AES_DEC_Optimization(inputbuf + 16 * i, W, outputbuf + 16 * i, W_mix, 128);
		XOR16Bytes(outputbuf + 16 * i, inputbuf + 16 * (i-1) );
	}
	
	fopen_s(&wfp, outputfile, "wb");
	r = outputbuf[DataLen - 1]; //복호화된 파일의 패딩 값을 r에 저장
	if (wfp == NULL) { //예외처리
		perror("fopen_s 실패!!\n");
	}
	fwrite(outputbuf, 1, DataLen - r, wfp); //outputbuf에 있는 데이터를 DataLen-r만큼 wfp에 씀
	fclose(wfp);
}
//=======================================================================================
//int argc : 인자의 개수, char* argv[v] : argv[0] argv[1] argv[2] argv[3] 인자를 받아서 처리하는 변수
int main(int argc, char* argv[]) {
	int i;
	u8 PT[16] = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
				  0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff };
	//u8 PT[16] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96, //test vector
				//0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a };
	u8 MK[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2,
		0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	//u8 MK[16] = { 0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6, //test vector
				//0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };
	u8 CT[16] = { 0x00, };
	u8 RK[240] = { 0x00, };
	u32 W[60] = { 0x00, };
	u32 W_mix[60] = { 0x00, };
	int keysize = 128;
	u8 temp;
	clock_t start, finish;

	//aes.exe, ecb(cbc), a.mp3, a.mp3.encryption
	//argv[0], argv[1], argv[2], argv[3]
	//==============================파일 최적화 암호화(복호화)===============================
	
	if (strcmp(argv[1], "ecb_E") == 0) {
		AES_KeySchedule_Optimization(MK, W, keysize);
		start = clock();
		for (i = 0; i < 10000; i++) ECB_Encryption(argv[2], argv[3], W);
		finish = clock();
		printf("=========================================\n");
		printf("Computation time : %f seconds\n", (double)(finish - start) / CLOCKS_PER_SEC);
		printf("=========================================\n");
	}
	else if (strcmp(argv[1], "ecb_D") == 0) {
		AES_KeySchedule_Optimization(MK, W, keysize);
		start = clock();
		for (i = 0; i < 10000; i++) ECB_Decryption(argv[2], argv[3], W, W_mix);
		finish = clock();
		printf("=========================================\n");
		printf("Computation time : %f seconds\n", (double)(finish - start) / CLOCKS_PER_SEC);
		printf("=========================================\n");
	}
	else if (strcmp(argv[1], "cbc_E") == 0) {
		AES_KeySchedule_Optimization(MK, W, keysize);
		start = clock();
		for (i = 0; i < 10000; i++) CBC_Encryption(argv[2], argv[3], W);
		finish = clock();
		printf("=========================================\n");
		printf("Computation time : %f seconds\n", (double)(finish - start) / CLOCKS_PER_SEC);
		printf("=========================================\n");
	}
	
	else if (strcmp(argv[1], "cbc_D") == 0) {
		AES_KeySchedule_Optimization(MK, W, keysize);
		start = clock();
		for (i = 0; i < 10000; i++) CBC_Decryption(argv[2], argv[3], W, W_mix);
		finish = clock();
		printf("=========================================\n");
		printf("Computation time : %f seconds\n", (double)(finish - start) / CLOCKS_PER_SEC);
		printf("=========================================\n");
	}
	
	//============================================================================================
	//==============================AES 암호화(복호화), AES 최적화 암호화(복호화)======================================
	/*
	AES_KeySchedule(MK, RK, keysize); //1Round:RK 0~15, 2Round:RK 16~31
	start = clock();
	for(i=0;i<10000;i++) AES_ENC(PT, RK, CT, keysize);
	finish = clock();
	printf("AES_ENC : ");
	for (i = 0; i < 16; i++) printf("%02x ", CT[i]);
	printf("\n");
	printf("Computation time : %f seconds\n", (double)(finish - start) / CLOCKS_PER_SEC);
	printf("\n=======================================\n\n");

	start = clock();
	for (i = 0; i < 10000; i++) AES_DEC(CT, RK, PT, keysize);
	finish = clock();
	printf("AES_DEC : ");
	for (i = 0; i < 16; i++) printf("%02x ", PT[i]);
	printf("\n");
	printf("Computation time : %f seconds\n", (double)(finish - start) / CLOCKS_PER_SEC);
	printf("\n=======================================\n\n");


	AES_KeySchedule_Optimization(MK, W, keysize); //1Round:RK 0~15, 2Round:RK 16~31
	start = clock();
	for (i = 0; i < 10000; i++) AES_ENC_Optimization(PT, W, CT, keysize);
	finish = clock();
	printf("AES_ENC_Optimization : ");
	for (i = 0; i < 16; i++) printf("%02x ", CT[i]);
	printf("\n");
	printf("Computation time : %f seconds\n", (double)(finish - start) / CLOCKS_PER_SEC);
	printf("\n=======================================\n\n");

	start=clock();
	for (i = 0; i < 10000; i++) AES_DEC_Optimization(CT, W, PT,W_mix, keysize);
	finish=clock();
	printf("AES_DEC_Optimization : ");
	for (i = 0; i < 16; i++) printf("%02x ", PT[i]);
	printf("\n");
	printf("Computation time : %f seconds\n", (double)(finish - start) / CLOCKS_PER_SEC);
	printf("\n=======================================\n\n");
	*/
	//=============================================================================================
	/*
	printf("u32 Te3[256]={\n"); //암호화 최적화 테이블 출력
	for (i = 0; i < 256; i++) {
		temp = Sbox[i];
		printf("0x%02x%02x%02x%02x, ", temp, temp,(u8)MUL3(temp), (u8)MUL2(temp));
		if (i % 8 == 7)printf("\n");
	}

	printf("u32 Td0[256]={\n"); //복호화 최적화 테이블 출력
	for (i = 0; i < 256; i++) {
		temp = InvSbox[i];
		printf("0x%02x%02x%02x%02x, ", (u8)(MULE(temp)), (u8)(MUL9(temp)), (u8)(MULD(temp)), (u8)(MULB(temp)));
		if (i % 8 == 7)printf("\n");
	}
	*/

	//u8 a,b,c,invA;
	//a = 0xa7;
	//invA = 0x5c;
	//b = 0x63;
	//c = MUL(a, b);

	//printf("%02x\n", GenSbox(a));
	//("%02x\n", InvGenSbox(invA));
	//printf("%02x * %02x = %02x\n",a,b,c);
	//printf("Sbox(%02x) = %02x, %02x\n", a, InvGenSbox(a),InvSbox[a]);

	/*printf("Sbox[256] = {\n"); //Sbox표 출력
	for (i = 0; i < 256; i++) {
		printf("0x%02x, ", GenSbox((u8)i));
		if (i % 16 == 15) printf("\n");
	}*/

	/*
	printf("InvSbox[256] = {\n"); //Inversion Sbox표 출력
	for (i = 0; i < 256; i++) {
		printf("0x%02x, ", InvGenSbox((u8)i));
		if (i % 16 == 15) printf("\n");
	}
	*/
	return 0;
}