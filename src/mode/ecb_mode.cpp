#ifndef ECP_MODE_CPP
#define ECP_MODE_CPP

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
}

#endif