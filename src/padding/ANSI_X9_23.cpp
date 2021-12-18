#ifndef PADDING_ANSI_X9_23_CPP
#define PADDING_ANSI_X9_23_CPP

/*
3 bytes: FDFDFD           --> FDFDFD0000000005
7 bytes: FDFDFDFDFDFDFD   --> FDFDFDFDFDFDFD01
8 bytes: FDFDFDFDFDFDFDFD --> FDFDFDFDFDFDFDFD0000000000000008
*/

#include <iostream>
#include "../padding.hpp"

namespace Padding
{
    size_t ANSI_X9_23::AddPadding(Krypt::Bytes*& src, size_t len, size_t CIPHER_BLOCKSIZE)
    {
        size_t paddings = CIPHER_BLOCKSIZE-(len%CIPHER_BLOCKSIZE);
        size_t paddedLen = paddings+len;
        Krypt::Bytes* paddedBlock = new Krypt::Bytes[paddedLen];

        memcpy(paddedBlock, src, len);
        memset(paddedBlock+len, 0x00, paddings);
        paddedBlock[paddedLen-1] = static_cast<Krypt::Bytes>(paddings);
        delete[] src;

        src = paddedBlock;
        return paddedLen;
    }

    size_t ANSI_X9_23::RemovePadding(Krypt::Bytes*& src, size_t len, size_t CIPHER_BLOCKSIZE)
    {
        size_t paddings = src[len-1];
        size_t noPaddingLength = len-paddings;

        Krypt::Bytes* NoPadding = new Krypt::Bytes[noPaddingLength];
        memcpy(NoPadding,src,noPaddingLength);
        delete [] src;
        src = NoPadding;
        
        return noPaddingLength;
    }

    size_t ANSI_X9_23::GetNoPaddingLength(const Krypt::Bytes* src, size_t len, size_t CIPHER_BLOCKSIZE)
    {
        return len-src[len-1];
    }
}

#endif