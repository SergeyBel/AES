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
    size_t ANSI_X9_23::AddPadding(Krypt::Bytes*& src, size_t len, size_t BLOCKSIZE)
    {
        size_t paddings = BLOCKSIZE-(len%BLOCKSIZE);
        size_t paddedLen = paddings+len;
        Krypt::Bytes* paddedBlock = new Krypt::Bytes[paddedLen];

        memcpy(paddedBlock, src, len);
        memset(paddedBlock+len, 0x00, paddings);
        paddedBlock[paddedLen-1] = static_cast<Krypt::Bytes>(paddings);
        delete[] src;

        src = paddedBlock;
        return paddedLen;
    }

    size_t ANSI_X9_23::RemovePadding(Krypt::Bytes*& src, size_t len, size_t BLOCKSIZE)
    {
        #ifndef PADDING_CHECK_DISABLE
        if(len<BLOCKSIZE || len%BLOCKSIZE!=0)
        {
            std::cerr << "\nA padded `src` should have a `len` greater than and divisible by the `BLOCKSIZE`\n";
            throw InvalidPaddedLength("ZeroNulls: src's `len` indicates that it was not padded or is corrupted");
        }
        #endif

        size_t paddings = src[len-1];
        size_t noPaddingLength = len-paddings;

        #ifndef PADDING_CHECK_DISABLE
        for(size_t i=1; i<paddings; ++i)
        {
            if(src[len-1-i]!=0x00)
                throw InvalidPadding("ANSI_X9_23: does not match the padding scheme used in `src`");
        }
        #endif
        
        Krypt::Bytes* NoPadding = new Krypt::Bytes[noPaddingLength];
        memcpy(NoPadding,src,noPaddingLength);
        delete [] src;
        src = NoPadding;
        
        return noPaddingLength;
    }

    size_t ANSI_X9_23::GetNoPaddingLength(const Krypt::Bytes* src, size_t len, size_t BLOCKSIZE)
    {
        #ifndef PADDING_CHECK_DISABLE
        if(len<BLOCKSIZE || len%BLOCKSIZE!=0)
        {
            std::cerr << "\nA padded `src` should have a `len` greater than and divisible by the `BLOCKSIZE`\n";
            throw InvalidPaddedLength("ZeroNulls: src's `len` indicates that it was not padded or is corrupted");
        }
        #endif

        #ifndef PADDING_CHECK_DISABLE
        size_t paddings = src[len-1];
        size_t noPaddingLength = len-paddings;

        for(size_t i=1; i<paddings; ++i)
        {
            if(src[len-1-i]!=0x00)
                throw InvalidPadding("ANSI_X9_23: does not match the padding scheme used in `src`");
        }
        #endif

        return len-src[len-1];
    }
}

#endif