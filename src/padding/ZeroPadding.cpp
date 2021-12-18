#ifndef PADDING_ZERO_PADDING_CPP
#define PADDING_ZERO_PADDING_CPP

#include <iostream>
#include "../padding.hpp"

namespace Padding
{
    size_t ZeroNulls::AddPadding(Krypt::Bytes*& src, size_t len, size_t CIPHER_BLOCKSIZE)
    {
        size_t paddings = CIPHER_BLOCKSIZE-(len%CIPHER_BLOCKSIZE);
        size_t paddedLen = paddings+len;
        Krypt::Bytes* paddedBlock = new Krypt::Bytes[paddedLen];

        memcpy(paddedBlock, src, len);
        memset(paddedBlock+len, 0x00, paddings);
        delete[] src;

        src = paddedBlock;
        return paddedLen;
    }

    size_t ZeroNulls::RemovePadding(Krypt::Bytes*& src, size_t len, size_t CIPHER_BLOCKSIZE)
    {
        size_t paddings = 0, noPaddingLength = 0;
        for(size_t i=0; i<CIPHER_BLOCKSIZE; ++i)
            if(src[len-1-i]==0x00) paddings++;
            else break;

        noPaddingLength = len-paddings;
        Krypt::Bytes* NoPadding = new Krypt::Bytes[noPaddingLength];
        memcpy(NoPadding,src,noPaddingLength);
        delete [] src;
        src = NoPadding;
        
        return len-paddings;
    }

    size_t ZeroNulls::GetNoPaddingLength(const Krypt::Bytes* src, size_t len, size_t CIPHER_BLOCKSIZE)
    {
        size_t paddings = 0;
        for(size_t i=0; i<CIPHER_BLOCKSIZE; ++i)
            if(src[len-1-i]==0x00) paddings++;
            else break;
        
        return len-paddings;
    }
}

#endif