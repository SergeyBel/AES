#ifndef BUILD_LIB
#ifndef ECP_MODE_CPP
#define ECP_MODE_CPP
#endif

#include "AES.h"

namespace Cipher
{
    unsigned char * AES::EncryptECB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned int &outLen)
    {
        outLen = GetPaddingLength(inLen);
        unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
        unsigned char *out = new unsigned char[outLen];
        unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
        KeyExpansion(key, roundKeys);
        for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
        {
            EncryptBlock(alignIn + i, out + i, roundKeys);
        }
        
        delete[] alignIn;
        delete[] roundKeys;
        
        return out;
    }

    unsigned char * AES::EncryptECB(unsigned char in[], unsigned int inLen, unsigned int &outLen)
    {
        outLen = GetPaddingLength(inLen);
        unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
        unsigned char *out = new unsigned char[outLen];
        for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
        {
            EncryptBlock(alignIn + i, out + i, RoundedKeys);
        }
        
        delete[] alignIn;
        
        return out;
    }

    unsigned char * AES::DecryptECB(unsigned char in[], unsigned int inLen, unsigned  char key[])
    {
        unsigned char *out = new unsigned char[inLen];
        unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
        KeyExpansion(key, roundKeys);
        for (unsigned int i = 0; i < inLen; i+= blockBytesLen)
        {
            DecryptBlock(in + i, out + i, roundKeys);
        }

        delete[] roundKeys;
        
        return out;
    }

    unsigned char * AES::DecryptECB(unsigned char in[], unsigned int inLen)
    {
        unsigned char *out = new unsigned char[inLen];
        for (unsigned int i = 0; i < inLen; i+= blockBytesLen)
        {
            DecryptBlock(in + i, out + i, RoundedKeys);
        }  
        return out;
    }

    bytestream AES::EncryptECB(bytestream in, bytestream key)
    {
        unsigned int outLen = 0;;
        unsigned char *out = EncryptECB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key), outLen);
        bytestream v = ArrayToVector(out, outLen);
        delete []out;
        return v;
    }

    bytestream AES::DecryptECB(bytestream in, bytestream key)
    {
        unsigned char *out = DecryptECB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key));
        bytestream v = ArrayToVector(out, (unsigned int)in.size());
        delete []out;
        return v;
    }
}

#endif