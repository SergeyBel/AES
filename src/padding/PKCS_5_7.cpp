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

namespace Krypt::Padding
{
    std::pair<Bytes*,size_t>  PKCS_5_7::AddPadding(Bytes* src, size_t len, size_t BLOCKSIZE)
    {
        size_t paddings = BLOCKSIZE-(len%BLOCKSIZE);
        size_t paddedLen = paddings+len;
        Bytes* paddedBlock = new Bytes[paddedLen];

        memcpy(paddedBlock, src, len);
        memset(paddedBlock+len, static_cast<Bytes>(paddings), paddings);

        return {paddedBlock,paddedLen};
    }

    std::pair<Bytes*,size_t>  PKCS_5_7::RemovePadding(Bytes* src, size_t len, size_t BLOCKSIZE)
    {
        #ifndef PADDING_CHECK_DISABLE
        if(len<BLOCKSIZE || len%BLOCKSIZE!=0)
        {
            std::cerr << "\nA padded `src` should have a `len` greater than and divisible by the `BLOCKSIZE`\n";
            throw InvalidPaddedLength("PKCS_5_7: src's `len` indicates that it was not padded or is corrupted");
        }
        #endif

        size_t paddings = src[len-1];
        size_t noPaddingLength = len-paddings;

        #ifndef PADDING_CHECK_DISABLE
        Bytes checkchar = static_cast<Bytes>(paddings);
        for(size_t i=1; i<paddings; ++i)
        {
            if(src[len-1-i]!=checkchar)
                throw InvalidPadding("PKCS_5_7: does not match the padding scheme used in `src`");
        }
        #endif

        Bytes* NoPadding = new Bytes[noPaddingLength];
        memcpy(NoPadding,src,noPaddingLength);
        
        return {NoPadding,noPaddingLength};
    }
}

#endif