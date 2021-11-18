#ifndef CBC_MODE_CPP
#define CBC_MODE_CPP

#include "AES.h"

namespace Cipher
{
    unsigned char *AES::EncryptCBC(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen)
    {
        outLen = GetPaddingLength(inLen);
        unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
        unsigned char *out = new unsigned char[outLen];
        unsigned char *block = new unsigned char[blockBytesLen];
        unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
        KeyExpansion(key, roundKeys);
        memcpy(block, iv, blockBytesLen);
        for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
        {
            XorBlocks(block, alignIn + i, block, blockBytesLen);
            EncryptBlock(block, out + i, roundKeys);
            memcpy(block, out + i, blockBytesLen);
        }
        
        delete[] block;
        delete[] alignIn;
        delete[] roundKeys;

        return out;
    }

    unsigned char *AES::EncryptCBC(unsigned char in[], unsigned int inLen, unsigned char * iv, unsigned int &outLen)
    {
        outLen = GetPaddingLength(inLen);
        unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
        unsigned char *out = new unsigned char[outLen];
        unsigned char *block = new unsigned char[blockBytesLen];
        memcpy(block, iv, blockBytesLen);
        for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
        {
            XorBlocks(block, alignIn + i, block, blockBytesLen);
            EncryptBlock(block, out + i, RoundedKeys);
            memcpy(block, out + i, blockBytesLen);
        }
        
        delete[] block;
        delete[] alignIn;

        return out;
    }

    unsigned char *AES::DecryptCBC(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv)
    {
        unsigned char *out = new unsigned char[inLen];
        unsigned char *block = new unsigned char[blockBytesLen];
        unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
        KeyExpansion(key, roundKeys);
        memcpy(block, iv, blockBytesLen);
        for (unsigned int i = 0; i < inLen; i+= blockBytesLen)
        {
            DecryptBlock(in + i, out + i, roundKeys);
            XorBlocks(block, out + i, out + i, blockBytesLen);
            memcpy(block, in + i, blockBytesLen);
        }
        
        delete[] block;
        delete[] roundKeys;

        return out;
    }

    unsigned char *AES::DecryptCBC(unsigned char in[], unsigned int inLen, unsigned char * iv)
    {
        unsigned char *out = new unsigned char[inLen];
        unsigned char *block = new unsigned char[blockBytesLen];
        memcpy(block, iv, blockBytesLen);
        for (unsigned int i = 0; i < inLen; i+= blockBytesLen)
        {
            DecryptBlock(in + i, out + i, RoundedKeys);
            XorBlocks(block, out + i, out + i, blockBytesLen);
            memcpy(block, in + i, blockBytesLen);
        }
        
        delete[] block;

        return out;
    }

    bytestream AES::EncryptCBC(bytestream in, bytestream key, bytestream iv)
    {
        unsigned int outLen = 0;
        unsigned char *out = EncryptCBC(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key), VectorToArray(iv),  outLen);
        bytestream v = ArrayToVector(out, outLen);
        delete [] out;
        return v;
    }

    bytestream AES::DecryptCBC(bytestream in, bytestream key, bytestream iv)
    {
        unsigned char *out = DecryptCBC(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key), VectorToArray(iv));
        bytestream v = ArrayToVector(out, (unsigned int)in.size());
        delete [] out;
        return v;
    }
}

#endif