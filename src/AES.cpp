#ifndef AES_CPP
#define AES_CPP

#include "AES.h"

namespace Cipher
{
    AES::AES(int keyLen)
    {
        this->Nb = 4;
        switch (keyLen)
        {
          case 128:
              this->Nk = 4;
              this->Nr = 10;
              break;
          case 192:
              this->Nk = 6;
              this->Nr = 12;
              break;
          case 256:
              this->Nk = 8;
              this->Nr = 14;
              break;
          default:
              throw "Incorrect key length";
        }

        RoundedKeys = NULL;
        blockBytesLen = 4 * this->Nb * sizeof(unsigned char);
    }

    AES::~AES()
    {
        if(RoundedKeys!=NULL) delete [] RoundedKeys;
    }

    void AES::XorBlocks(unsigned char *a, unsigned char * b, unsigned char *c, unsigned int len)
    {
        for (unsigned int i = 0; i < len; i++)
        {
            c[i] = a[i] ^ b[i];
        }
    }

    void AES::printHexArray (unsigned char a[], unsigned int n)
    {
        for (unsigned int i = 0; i < n; i++) {
            printf("%02x ", a[i]);
        }
    }

    void AES::printHexVector (bytestream a)
    {
        for (unsigned int i = 0; i < a.size(); i++) {
            printf("%02x ", a[i]);
        }
    }

    bytestream AES::ArrayToVector(unsigned char *a, unsigned char len)
    {
        bytestream v(a, a + len * sizeof(unsigned char));
        return v;
    }

    unsigned char *AES::VectorToArray(bytestream a)
    {
        return a.data();
    }
}

#endif