#ifndef KRYPT_AES_CPP
#define KRYPT_AES_CPP

#include <iostream>
#include "../../blockcipher.hpp"

namespace Krypt::BlockCipher
{
    void AES::setKey(const Bytes* ByteArray, size_t keyLen)
    {
        switch (keyLen)
        {
          case 16: // AES128
              this->Nk = 4;
              this->Nr = 10;
              break;
          case 24: // AES192
              this->Nk = 6;
              this->Nr = 12;
              break;
          case 32: // AES256
              this->Nk = 8;
              this->Nr = 14;
              break;
          default:
              throw std::invalid_argument("Incorrect key length");
        }

        KeyExpansion(ByteArray);
    }

    AES::AES(const Bytes* ByteArray, size_t keyLen) : BASE_BLOCKCIPHER(16)
    {
        setKey(ByteArray,keyLen);
        this->IV = NULL;
    }

    AES::AES(const Bytes* ByteArray, size_t keyLen, const Bytes* IV) : BASE_BLOCKCIPHER(16)
    {
        setKey(ByteArray,keyLen);
        this->IV = new Bytes[this->BLOCK_SIZE];
        memcpy(this->IV,IV,this->BLOCK_SIZE);
    }

    AES::~AES()
    {
        if(RoundedKeys!=NULL) delete [] RoundedKeys;
        if(IV!=NULL) delete [] IV;
    }
}

#endif
