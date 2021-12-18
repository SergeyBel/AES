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
        unsigned char block[AES_BLOCK_LEN];
        unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
        KeyExpansion(key, roundKeys);
        memcpy(block, iv, AES_BLOCK_LEN);
        for (unsigned int i = 0; i < outLen; i+= AES_BLOCK_LEN)
        {
            XorBlocks(block, alignIn + i, block, AES_BLOCK_LEN);
            EncryptBlock(block, out + i, roundKeys);
            memcpy(block, out + i, AES_BLOCK_LEN);
        }
        
        delete[] alignIn;
        delete[] roundKeys;

        return out;
    }

    unsigned char *AES::EncryptCBC(unsigned char in[], unsigned int inLen, unsigned char * iv, unsigned int &outLen)
    {
        outLen = GetPaddingLength(inLen);
        unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
        unsigned char *out = new unsigned char[outLen];
        unsigned char block[AES_BLOCK_LEN];
        memcpy(block, iv, AES_BLOCK_LEN);
        for (unsigned int i = 0; i < outLen; i+= AES_BLOCK_LEN)
        {
            XorBlocks(block, alignIn + i, block, AES_BLOCK_LEN);
            EncryptBlock(block, out + i, RoundedKeys);
            memcpy(block, out + i, AES_BLOCK_LEN);
        }
        
        delete[] alignIn;

        return out;
    }

    unsigned char *AES::DecryptCBC(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv)
    {
        unsigned char *out = new unsigned char[inLen];
        unsigned char block[AES_BLOCK_LEN];
        unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
        KeyExpansion(key, roundKeys);
        memcpy(block, iv, AES_BLOCK_LEN);
        for (unsigned int i = 0; i < inLen; i+= AES_BLOCK_LEN)
        {
            DecryptBlock(in + i, out + i, roundKeys);
            XorBlocks(block, out + i, out + i, AES_BLOCK_LEN);
            memcpy(block, in + i, AES_BLOCK_LEN);
        }
        
        delete[] roundKeys;

        return out;
    }

    unsigned char *AES::DecryptCBC(unsigned char in[], unsigned int inLen, unsigned char * iv)
    {
        unsigned char *out = new unsigned char[inLen];
        unsigned char block[AES_BLOCK_LEN];
        memcpy(block, iv, AES_BLOCK_LEN);
        for (unsigned int i = 0; i < inLen; i+= AES_BLOCK_LEN)
        {
            DecryptBlock(in + i, out + i, RoundedKeys);
            XorBlocks(block, out + i, out + i, AES_BLOCK_LEN);
            memcpy(block, in + i, AES_BLOCK_LEN);
        }

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