#include <iostream>
#include "src/blockcipher.hpp"
#include "src/functions.hpp"
#include "src/types.hpp"
#include "src/padding.hpp"

int main()
{
    unsigned char plain[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xaa
    };

    unsigned char aes128key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    unsigned char aes192key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
    };

    unsigned char aes256key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0xf7
    };

    Krypt::BlockCipher::AES
        aes128(aes128key,sizeof(aes128key)),
        aes192(aes192key,sizeof(aes192key)),
        aes256(aes256key,sizeof(aes256key));

    std::cout << "AES128 block size : " << aes128.BLOCK_SIZE << "\n";

    unsigned char
        *cipher  = new unsigned char[aes128.BLOCK_SIZE],
        *recover = new unsigned char[aes128.BLOCK_SIZE];

    aes128.EncryptBlock(plain,cipher);
    aes128.DecryptBlock(cipher,recover);
    
    std::cout << "AES128:\n";
    std::cout << "key    : "; Krypt::printHexArray(aes128key,sizeof(aes128key));
    std::cout << "\nPlain  : "; Krypt::printHexArray(plain,aes128.BLOCK_SIZE);
    std::cout << "\nCipher : "; Krypt::printHexArray(cipher,aes128.BLOCK_SIZE);
    std::cout << "\nRecover: "; Krypt::printHexArray(recover,aes128.BLOCK_SIZE);
    std::cout << "\n\n";
    memset(recover,0x00,aes128.BLOCK_SIZE);

    aes192.EncryptBlock(plain,cipher);
    aes192.DecryptBlock(cipher,recover);

    std::cout << "AES192:\n";
    std::cout << "key    : "; Krypt::printHexArray(aes192key,sizeof(aes192key));
    std::cout << "\nPlain  : "; Krypt::printHexArray(plain,aes128.BLOCK_SIZE);
    std::cout << "\nCipher : "; Krypt::printHexArray(cipher,aes128.BLOCK_SIZE);
    std::cout << "\nRecover: "; Krypt::printHexArray(recover,aes128.BLOCK_SIZE);
    std::cout << "\n\n";
    memset(recover,0x00,aes128.BLOCK_SIZE);

    aes256.EncryptBlock(plain,cipher);
    aes256.DecryptBlock(cipher,recover);
    
    std::cout << "AES256:\n";
    std::cout << "key    : "; Krypt::printHexArray(aes256key,sizeof(aes256key));
    std::cout << "\nPlain  : "; Krypt::printHexArray(plain,aes128.BLOCK_SIZE);
    std::cout << "\nCipher : "; Krypt::printHexArray(cipher,aes128.BLOCK_SIZE);
    std::cout << "\nRecover: "; Krypt::printHexArray(recover,aes128.BLOCK_SIZE);
    std::cout << "\n\n";

    delete [] cipher;
    delete [] recover;

    // ----------------------

    return 0;
}