#include <iostream>
#include "src/mode.hpp"
#include "src/functions.hpp"

using namespace Krypt;

int main()
{
    Bytes plain[] = {
        0x00, 0x01, 0xa2, 0xb3, 0xff, 0x74, 0x32, 0xcd
    };
    Bytes aes128key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    Mode::ECB<BlockCipher::AES,Padding::PKCS_5_7> EncScheme(Sequence(aes128key,sizeof(aes128key)));
    std::pair<Bytes*,size_t> encrypted = EncScheme.encrypt(plain,sizeof(plain));
    std::pair<Bytes*,size_t> decrypted = EncScheme.decrypt(encrypted.first,encrypted.second);
    
    std::cout << "Plain : \n";
    printHexArray(plain,sizeof(plain));
    std::cout << "\nEncrypted : \n";
    printHexArray(encrypted.first,encrypted.second);
    std::cout << "\nDecrypted : \n";
    printHexArray(decrypted.first,decrypted.second);
    
    delete [] encrypted.first;
    delete [] decrypted.first;
}