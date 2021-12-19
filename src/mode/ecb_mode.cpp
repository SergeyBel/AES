#ifndef ECP_MODE_CPP
#define ECP_MODE_CPP

#include "../functions.hpp"
#include "../mode.hpp"

namespace Krypt::Mode
{
    template<typename CIPHER_TYPE, typename PADDING_TYPE>
    ECB<CIPHER_TYPE,PADDING_TYPE>::ECB(const Sequence& key)
        : MODE<CIPHER_TYPE,PADDING_TYPE>()
    {
        this->BLOCK_SIZE = 16;
        this->Encryption = new CIPHER_TYPE(key.data_c(),key.size());
        this->PaddingScheme = new PADDING_TYPE();
    }

    template<typename CIPHER_TYPE, typename PADDING_TYPE>
    std::pair<Bytes*,size_t> ECB<CIPHER_TYPE,PADDING_TYPE>::encrypt(Bytes* plain, size_t plainLen)
    {
        std::pair<Bytes*,size_t> padded = this->PaddingScheme->AddPadding(plain,plainLen,this->BLOCK_SIZE);

        Bytes* cipher = new Bytes[padded.second];
        for(size_t i=0; i<padded.second; i+=this->BLOCK_SIZE)
        {
            this->Encryption->EncryptBlock(padded.first+i,cipher+i);
        }

        delete [] padded.first;
        return {cipher,padded.second};
    }

    template<typename CIPHER_TYPE, typename PADDING_TYPE>
    std::pair<Bytes*,size_t> ECB<CIPHER_TYPE,PADDING_TYPE>::decrypt(Bytes* cipher, size_t cipherLen)
    {
        std::pair<Bytes*,size_t> recovered;
        recovered.first = new Bytes[cipherLen];
        recovered.second = cipherLen;

        for(size_t i=0; i<cipherLen; i+=this->BLOCK_SIZE)
        {
            this->Encryption->DecryptBlock(cipher+i,recovered.first+i);
        }

        std::pair<Bytes*,size_t> recoverNoPadding = this->PaddingScheme->RemovePadding(recovered.first,recovered.second,this->BLOCK_SIZE);
        
        delete [] recovered.first;
        return recoverNoPadding;
    }

    // unsigned char * DecryptECB(unsigned char in[], unsigned int inLen, unsigned  char key[])
    // {
    //     unsigned char *out = new unsigned char[inLen];
    //     unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    //     KeyExpansion(key, roundKeys);
    //     for (unsigned int i = 0; i < inLen; i+= AES_BLOCK_LEN)
    //     {
    //         DecryptBlock(in + i, out + i, roundKeys);
    //     }

    //     delete[] roundKeys;
        
    //     return out;
    // }

    // bytestream EncryptECB(bytestream in, bytestream key)
    // {
    //     unsigned int outLen = 0;;
    //     unsigned char *out = EncryptECB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key), outLen);
    //     bytestream v = ArrayToVector(out, outLen);
    //     delete []out;
    //     return v;
    // }

    // bytestream DecryptECB(bytestream in, bytestream key)
    // {
    //     unsigned char *out = DecryptECB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key));
    //     bytestream v = ArrayToVector(out, (unsigned int)in.size());
    //     delete []out;
    //     return v;
    // }
}

#endif