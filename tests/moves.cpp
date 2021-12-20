/*    sample.cpp    */
#include <iostream>
#include "../src/Krypt.hpp"
#include "../src/bytearray.hpp"

using namespace Krypt;

int main()
{
    unsigned char plain[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb
    };

    unsigned char aes128key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    Mode::ECB<BlockCipher::AES,Padding::ANSI_X9_23> krypt(aes128key,sizeof(aes128key));

    {
        ByteArray cipher  = krypt.encrypt(plain,sizeof(plain));
        ByteArray recover = krypt.decrypt(cipher.first,cipher.second);
    }
    std::cout << "std::pair Move to ByteArray     - Passed\n";
    

    {
        ByteArray cipher  = krypt.encrypt(plain,sizeof(plain));
        cipher = krypt.decrypt(cipher.first,cipher.second);
    }
    std::cout << "std::pair Assign to ByteArray 1 - Passed\n";
    

    {
        ByteArray cipher  = krypt.encrypt(plain,sizeof(plain));
        ByteArray recover;
        recover = krypt.decrypt(cipher.first,cipher.second);
    }
    std::cout << "std::pair Assign to ByteArray 2 - Passed\n";
    

    {
        ByteArray cipher  = krypt.encrypt(plain,sizeof(plain));
        ByteArray recover = krypt.decrypt(cipher.first,cipher.second);

        cipher = recover;
    }
    std::cout << "ByteArray Copied to ByteArray   - Passed\n";
}