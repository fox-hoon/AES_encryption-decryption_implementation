# AES_encryption-decryption_implementation
AES_encryption-decryption(basic, optimization, file)

This project includes the following.

1.Basic AES encryption/decryption

2.AES-optimized encryption/decryption

3.File AES encryption/decryption (CBC operation mode, ECB operation mode, PKCS#7 padding)
***
# AES 복호화 구현
+ AES 복호화 과정
  + AES 복호화 과정은 암호화 과정을 역으로 하면 된다.
    + N 라운드:AddRoundKey, InvShiftRows, InvSubBytes를 순서대로 수행한다.
    + (N-1)~1 라운드:AddRoundKey, InvMixColumn, InvShiftRows, InvSubBytes를 순서대로 반복한다.
    + 0 라운드:AddRoundKey만 수행한다.
    
