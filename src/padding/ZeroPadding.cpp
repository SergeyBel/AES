#ifndef PADDING_ZERO_PADDING_CPP
#define PADDING_ZERO_PADDING_CPP

#include <iostream>
#include "../padding.hpp"

namespace Padding
{
    size_t ZeroNulls::AddPadding(Krypt::Bytes*& src, size_t len, size_t BLOCKSIZE)
    {
        size_t paddings = BLOCKSIZE-(len%BLOCKSIZE);
        size_t paddedLen = paddings+len;
        Krypt::Bytes* paddedBlock = new Krypt::Bytes[paddedLen];

        memcpy(paddedBlock, src, len);
        memset(paddedBlock+len, 0x00, paddings);
        delete[] src;

        src = paddedBlock;
        return paddedLen;
    }

    size_t ZeroNulls::RemovePadding(Krypt::Bytes*& src, size_t len, size_t BLOCKSIZE)
    {
        #ifndef PADDING_CHECK_DISABLE
        if(len<BLOCKSIZE || len%BLOCKSIZE!=0)
        {
            std::cerr << "\nA padded `src` should have a `len` greater than and divisible by the `BLOCKSIZE`\n";
            throw InvalidPaddedLength("ZeroNulls: src's `len` indicates that it was not padded or is corrupted");
        }
        #endif

        #ifndef PADDING_CHECK_DISABLE
        if(src[len-1]!=0x00)
            throw InvalidPadding("ZeroNulls: does not match the padding scheme used in `src`");
        #endif

        size_t paddings = 0, noPaddingLength = 0;
        for(size_t i=0; i<BLOCKSIZE; ++i)
            if(src[len-1-i]==0x00) paddings++;
            else break;

        noPaddingLength = len-paddings;
        Krypt::Bytes* NoPadding = new Krypt::Bytes[noPaddingLength];
        memcpy(NoPadding,src,noPaddingLength);
        delete [] src;
        src = NoPadding;
        
        return len-paddings;
    }

    size_t ZeroNulls::GetNoPaddingLength(const Krypt::Bytes* src, size_t len, size_t BLOCKSIZE)
    {
        #ifndef PADDING_CHECK_DISABLE
        if(len<BLOCKSIZE || len%BLOCKSIZE!=0)
        {
            std::cerr << "\nA padded `src` should have a `len` greater than and divisible by the `BLOCKSIZE`\n";
            throw InvalidPaddedLength("ZeroNulls: src's `len` indicates that it was not padded or is corrupted");
        }
        #endif
        
        #ifndef PADDING_CHECK_DISABLE
        if(src[len-1]!=0x00)
            throw InvalidPadding("ZeroNulls: does not match the padding scheme used in `src`");
        #endif

        size_t paddings = 0;
        for(size_t i=0; i<BLOCKSIZE; ++i)
            if(src[len-1-i]==0x00) paddings++;
            else break;
        
        return len-paddings;
    }
}

#endif