#ifndef CFB_MODE_CPP
#define CFB_MODE_CPP

#include "AES.h"

namespace Cipher
{
    unsigned char *AES::EncryptCFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen)
    {
        outLen = GetPaddingLength(inLen);
        unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
        unsigned char *out = new unsigned char[outLen];
        unsigned char *block = new unsigned char[blockBytesLen];
        unsigned char *encryptedBlock = new unsigned char[blockBytesLen];
        unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
        KeyExpansion(key, roundKeys);
        memcpy(block, iv, blockBytesLen);
        for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
        {
            EncryptBlock(block, encryptedBlock, roundKeys);
            XorBlocks(alignIn + i, encryptedBlock, out + i, blockBytesLen);
            memcpy(block, out + i, blockBytesLen);
        }
        
        delete[] block;
        delete[] encryptedBlock;
        delete[] alignIn;
        delete[] roundKeys;

        return out;
    }

    unsigned char *AES::EncryptCFB(unsigned char in[], unsigned int inLen, unsigned char * iv, unsigned int &outLen)
    {
        outLen = GetPaddingLength(inLen);
        unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
        unsigned char *out = new unsigned char[outLen];
        unsigned char *block = new unsigned char[blockBytesLen];
        unsigned char *encryptedBlock = new unsigned char[blockBytesLen];
        memcpy(block, iv, blockBytesLen);
        for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
        {
            EncryptBlock(block, encryptedBlock, RoundedKeys);
            XorBlocks(alignIn + i, encryptedBlock, out + i, blockBytesLen);
            memcpy(block, out + i, blockBytesLen);
        }
        
        delete[] block;
        delete[] encryptedBlock;
        delete[] alignIn;

        return out;
    }

    unsigned char *AES::DecryptCFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv)
    {
        unsigned char *out = new unsigned char[inLen];
        unsigned char *block = new unsigned char[blockBytesLen];
        unsigned char *encryptedBlock = new unsigned char[blockBytesLen];
        unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
        KeyExpansion(key, roundKeys);
        memcpy(block, iv, blockBytesLen);
        for (unsigned int i = 0; i < inLen; i+= blockBytesLen)
        {
            EncryptBlock(block, encryptedBlock, roundKeys);
            XorBlocks(in + i, encryptedBlock, out + i, blockBytesLen);
            memcpy(block, in + i, blockBytesLen);
        }
        
        delete[] block;
        delete[] encryptedBlock;
        delete[] roundKeys;

        return out;
    }

    unsigned char *AES::DecryptCFB(unsigned char in[], unsigned int inLen, unsigned char * iv)
    {
        unsigned char *out = new unsigned char[inLen];
        unsigned char *block = new unsigned char[blockBytesLen];
        unsigned char *encryptedBlock = new unsigned char[blockBytesLen];
        memcpy(block, iv, blockBytesLen);
        for (unsigned int i = 0; i < inLen; i+= blockBytesLen)
        {
            EncryptBlock(block, encryptedBlock, RoundedKeys);
            XorBlocks(in + i, encryptedBlock, out + i, blockBytesLen);
            memcpy(block, in + i, blockBytesLen);
        }
        
        delete[] block;
        delete[] encryptedBlock;

        return out;
    }

    bytestream AES::EncryptCFB(bytestream in, bytestream key, bytestream iv)
    {
        unsigned int outLen = 0;
        unsigned char *out = EncryptCFB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key), VectorToArray(iv),  outLen);
        bytestream v = ArrayToVector(out, outLen);
        delete [] out;
        return v;
    }

    bytestream AES::DecryptCFB(bytestream in, bytestream key, bytestream iv)
    {
        unsigned char *out = DecryptCFB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key), VectorToArray(iv));
        bytestream v = ArrayToVector(out, (unsigned int)in.size());
        delete [] out;
        return v;
    }
}

#endif