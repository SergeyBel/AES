# Krypt

Forked From : https://github.com/SergeyBel/AES

### About this fork

This fork was optimized and used by my file [encryption/decryption program](https://github.com/mrdcvlsc/bethela).

**This is a portable software implementation, no Inline assembly, no SIMD intrinsics, so performance won't be as fast as optimized libraries like OpenSSL or Crypto++, it only relies on compiler optimizations for better performance.

***To get the peak performance of this portable library compile it with the flags ```-D PADDING_CHECK_DISABLE -O3 -march=native```***
 
![Tests](https://github.com/mrdcvlsc/AES/actions/workflows/google-test.yml/badge.svg)



**sample program:**
```c++
#include <iostream>
#include "src/Krypt.hpp"

using namespace Krypt;

int main()
{
    unsigned char plain[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb
    };

    // if you want to AES192 or AES256, just increase the size of the key array
    // the AES class will automatically detect it
    unsigned char aes128key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    Mode::ECB<BlockCipher::AES,Padding::ANSI_X9_23> krypt(aes128key,sizeof(aes128key));

    // `Krypt::Bytes` is just a typedef for `unsigned char`
    std::pair<Bytes*,size_t> cipher  = krypt.encrypt(plain,sizeof(plain));
    std::pair<Bytes*,size_t> recover = krypt.decrypt(cipher.first,cipher.second);
    
    // the pair.first will contain the output, and pair.second will contain the length of the output

    delete [] cipher.first;
    delete [] recover.first;    
}
```

**Support**

Block Cipher: AES

Encryption modes: ECB, CBC, CFB

Padding: ANSI X9.23, PKCS#5 and PKCS#7, ISO/IEC 7816-4, Zero padding
