#ifndef ECP_MODE_CPP
#define ECP_MODE_CPP

#include "../mode.hpp"

namespace Krypt::Mode
{
    template<typename CIPHER_TYPE, typename PADDING_TYPE>
    ECB<CIPHER_TYPE,PADDING_TYPE>::ECB(const Bytes* key, size_t keyLen)
        : MODE<CIPHER_TYPE,PADDING_TYPE>()
    {
        this->Encryption = new CIPHER_TYPE(key,keyLen);
        this->PaddingScheme = new PADDING_TYPE();
    }

    template<typename CIPHER_TYPE, typename PADDING_TYPE>
    std::pair<Bytes*,size_t> ECB<CIPHER_TYPE,PADDING_TYPE>::encrypt(Bytes* plain, size_t plainLen)
    {
        std::pair<Bytes*,size_t> padded = this->PaddingScheme->AddPadding(plain,plainLen,this->Encryption->BLOCK_SIZE);

        Bytes* cipher = new Bytes[padded.second];
        for(size_t i=0; i<padded.second; i+=this->Encryption->BLOCK_SIZE)
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

        for(size_t i=0; i<cipherLen; i+=this->Encryption->BLOCK_SIZE)
        {
            this->Encryption->DecryptBlock(cipher+i,recovered.first+i);
        }

        std::pair<Bytes*,size_t> recoverNoPadding = this->PaddingScheme->RemovePadding(recovered.first,recovered.second,this->Encryption->BLOCK_SIZE);
        
        delete [] recovered.first;
        return recoverNoPadding;
    }
}

#endif