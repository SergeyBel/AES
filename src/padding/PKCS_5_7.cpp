#ifndef PADDING_PKCS_5_7_CPP
#define PADDING_PKCS_5_7_CPP

#include <iostream>

/*
3 bytes: FDFDFD           --> FDFDFD0505050505
7 bytes: FDFDFDFDFDFDFD   --> FDFDFDFDFDFDFD01
8 bytes: FDFDFDFDFDFDFDFD --> FDFDFDFDFDFDFDFD0808080808080808
*/

#include <iostream>
#include "../padding.hpp"

namespace Padding
{
    size_t PKCS_5_7::AddPadding(Krypt::Bytes*& src, size_t len, size_t CIPHER_BLOCKSIZE)
    {
        size_t paddings = CIPHER_BLOCKSIZE-(len%CIPHER_BLOCKSIZE);
        size_t paddedLen = paddings+len;
        Krypt::Bytes* paddedBlock = new Krypt::Bytes[paddedLen];

        memcpy(paddedBlock, src, len);
        memset(paddedBlock+len, static_cast<Krypt::Bytes>(paddings), paddings);
        delete[] src;

        src = paddedBlock;
        return paddedLen;
    }

    size_t PKCS_5_7::RemovePadding(Krypt::Bytes*& src, size_t len, size_t CIPHER_BLOCKSIZE)
    {
        size_t paddings = src[len-1];
        size_t noPaddingLength = len-paddings;

        Krypt::Bytes* NoPadding = new Krypt::Bytes[noPaddingLength];
        memcpy(NoPadding,src,noPaddingLength);
        delete [] src;
        src = NoPadding;
        
        return noPaddingLength;
    }

    size_t PKCS_5_7::GetNoPaddingLength(const Krypt::Bytes* src, size_t len, size_t CIPHER_BLOCKSIZE)
    {
        return len-src[len-1];
    }
}

#endif