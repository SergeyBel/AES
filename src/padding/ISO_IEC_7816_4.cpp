#ifndef PADDING_ISO_IEC_7816_4_CPP
#define PADDING_ISO_IEC_7816_4_CPP

#include <iostream>
#include "../padding.hpp"

/*
3 bytes: FDFDFD           --> FDFDFD8000000000
7 bytes: FDFDFDFDFDFDFD   --> FDFDFDFDFDFDFD80
8 bytes: FDFDFDFDFDFDFDFD --> FDFDFDFDFDFDFDFD8000000000000000
*/

namespace Padding
{
    size_t ISO_IEC_7816_4::AddPadding(Krypt::Bytes*& src, size_t originalSrcLen, size_t BLOCKSIZE)
    {
        size_t paddings = BLOCKSIZE-(originalSrcLen%BLOCKSIZE);
        size_t paddedLen = paddings+originalSrcLen;
        Krypt::Bytes* paddedBlock = new Krypt::Bytes[paddedLen];

        memcpy(paddedBlock, src, originalSrcLen);
        memset(paddedBlock+originalSrcLen, 0x00, paddings);
        paddedBlock[originalSrcLen] = 0x80;

        delete[] src;
        src = paddedBlock;

        return paddedLen;
    }

    size_t ISO_IEC_7816_4::RemovePadding(Krypt::Bytes*& src, size_t len, size_t BLOCKSIZE)
    {
        #ifndef PADDING_CHECK_DISABLE
        if(len<BLOCKSIZE || len%BLOCKSIZE!=0)
        {
            std::cerr << "\nA padded `src` should have a `len` greater than and divisible by the `BLOCKSIZE`\n";
            throw InvalidPaddedLength("ZeroNulls: src's `len` indicates that it was not padded or is corrupted");
        }
        #endif

        Krypt::Bytes curr;
        size_t paddings = 0, i;

        #ifndef PADDING_CHECK_DISABLE
        for(i=1; i<BLOCKSIZE; ++i)
        {
            if(src[len-i]==0x80) break;
            if(src[len-i]!=0x00)
                throw InvalidPadding("ISO_IEC_7816_4: does not match the padding scheme used in `src`");
        }
        #endif

        size_t noPaddingLength = len-i;
        Krypt::Bytes* NoPadding = new Krypt::Bytes[noPaddingLength];
        memcpy(NoPadding,src,noPaddingLength);
        delete [] src;
        src = NoPadding;

        return noPaddingLength;
    }

    size_t ISO_IEC_7816_4::GetNoPaddingLength(const Krypt::Bytes* src, size_t len, size_t BLOCKSIZE)
    {
        #ifndef PADDING_CHECK_DISABLE
        if(len<BLOCKSIZE || len%BLOCKSIZE!=0)
        {
            std::cerr << "\nA padded `src` should have a `len` greater than and divisible by the `BLOCKSIZE`\n";
            throw InvalidPaddedLength("ZeroNulls: src's `len` indicates that it was not padded or is corrupted");
        }
        #endif

        Krypt::Bytes curr;
        size_t paddings = 0, i;
        
        #ifndef PADDING_CHECK_DISABLE
        for(i=1; i<BLOCKSIZE; ++i)
        {
            if(src[len-i]==0x80) break;
            if(src[len-i]!=0x00)
                throw InvalidPadding("ISO_IEC_7816_4: does not match the padding scheme used in `src`");
        }
        #endif

        size_t noPaddingLength = len-i;
        return noPaddingLength;
    }
}

#endif