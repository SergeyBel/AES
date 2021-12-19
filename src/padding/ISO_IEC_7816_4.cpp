#ifndef PADDING_ISO_IEC_7816_4_CPP
#define PADDING_ISO_IEC_7816_4_CPP

#include <iostream>
#include "../padding.hpp"

/*
3 bytes: FDFDFD           --> FDFDFD8000000000
7 bytes: FDFDFDFDFDFDFD   --> FDFDFDFDFDFDFD80
8 bytes: FDFDFDFDFDFDFDFD --> FDFDFDFDFDFDFDFD8000000000000000
*/

namespace Krypt::Padding
{
    std::pair<Bytes*,size_t>  ISO_IEC_7816_4::AddPadding(Bytes* src, size_t originalSrcLen, size_t BLOCKSIZE)
    {
        size_t paddings = BLOCKSIZE-(originalSrcLen%BLOCKSIZE);
        size_t paddedLen = paddings+originalSrcLen;
        Bytes* paddedBlock = new Bytes[paddedLen];

        memcpy(paddedBlock, src, originalSrcLen);
        memset(paddedBlock+originalSrcLen, 0x00, paddings);
        paddedBlock[originalSrcLen] = 0x80;

        return {paddedBlock,paddedLen};
    }

    std::pair<Bytes*,size_t>  ISO_IEC_7816_4::RemovePadding(Bytes* src, size_t len, size_t BLOCKSIZE)
    {
        #ifndef PADDING_CHECK_DISABLE
        if(len<BLOCKSIZE || len%BLOCKSIZE!=0)
        {
            std::cerr << "\nA padded `src` should have a `len` greater than and divisible by the `BLOCKSIZE`\n";
            throw InvalidPaddedLength("ISO_IEC_7816_4: src's `len` indicates that it was not padded or is corrupted");
        }
        #endif

        size_t i;

        #ifndef PADDING_CHECK_DISABLE
        for(i=1; i<BLOCKSIZE; ++i)
        {
            if(src[len-i]==0x80) break;
            if(src[len-i]!=0x00)
                throw InvalidPadding("ISO_IEC_7816_4: does not match the padding scheme used in `src`");
        }
        #endif

        size_t noPaddingLength = len-i;
        Bytes* NoPadding = new Bytes[noPaddingLength];
        memcpy(NoPadding,src,noPaddingLength);

        return {NoPadding,noPaddingLength};
    }
}

#endif