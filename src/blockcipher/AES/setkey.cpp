#ifndef KRYPT_AES_CPP
#define KRYPT_AES_CPP

#include <iostream>
#include "../../blockcipher.hpp"

namespace Krypt
{
    void AES::setKey(Bytes* ByteArray, size_t keyLen)
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
              throw "Incorrect key length";
        }

        KeyExpansion(ByteArray);
    }

    AES::AES(Bytes* ByteArray, size_t keyLen)
    {
        setKey(ByteArray,keyLen);
    }

    AES::~AES()
    {
        if(RoundedKeys!=NULL) delete [] RoundedKeys;
    }
}

#endif