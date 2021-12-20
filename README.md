# Krypt

Forked From : https://github.com/SergeyBel/AES

### About this fork

This fork was optimized and used by my file [encryption/decryption program](https://github.com/mrdcvlsc/bethela).

**This is a portable software implementation, no Inline assembly, no SIMD intrinsics, so performance won't be as fast as optimized libraries like OpenSSL or Crypto++, it only relies on compiler optimizations for better performance.**

![Tests](https://github.com/mrdcvlsc/AES/actions/workflows/google-test.yml/badge.svg)

-----------

**Compilation Note:** This is a header only library, you only need to include the ```"Krypt.hpp"```, no need to compile the library first, and there's no need to add/link the ```.cpp``` files of the library to your compilation flag, see the example below.

***To get the peak performance of this portable library compile it with the flags ```-D PADDING_CHECK_DISABLE -O3 -march=native```***

**sample program:**
```c++
/*    sample.cpp    */
#include <iostream>
#include "src/Krypt.hpp"

using namespace Krypt;

int main()
{
    unsigned char plain[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb
    };

    // if you want to use AES192 or AES256, just increase the size of the key to
    // 24 or 32... the AES class will automatically detect it, it will aslo throw
    // an error if the key size is not 16,24 or 32
    unsigned char aes128key[16] = {
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

**compile with** ```g++ sample.cpp -D PADDING_CHECK_DISABLE -o sample.exe -O3 -march=native```

-------------

<br>

**Inside the ```Krypt``` namespace**

| sub namespace | classes |
| --- | --- |
| ```BlockCipher``` | ```AES``` |
| ```Padding``` | ```ZeroNulls```, ```ANSI_X9_23```, ```ISO_IEC_7816_4```, ```PKCS_5_7``` |
| ```Mode``` | ```ECB```, ```CBC```, ```CFB``` |
