#ifndef KRYPT_PADDING_HPP
#define KRYPT_PADDING_HPP

#include <iostream>
#include <exception>
#include <cstring>
#include "types.hpp"

namespace Padding
{
    class PADDING
    {
        public:
            virtual void AddPadding() {}
            virtual void RemovePadding() {}
            virtual void GetNoPaddingLength() {}
    };

    class ZeroNulls : public PADDING
    {
        public:

        /** Pad the last block with zeros [reallocates memory]
         * returns the new length of the padded `src`
         * **/
        size_t AddPadding(Krypt::Bytes*& src, size_t len, size_t CIPHER_BLOCKSIZE);
        
        /** Removes the last 16 byte zeros [reallocates memory]
         * returns the new length of the un-padded `src`
         * **/
        size_t RemovePadding(Krypt::Bytes*& src, size_t len, size_t CIPHER_BLOCKSIZE);

        /** 
         * returns the length of the un-padded `src`**/
        size_t GetNoPaddingLength(const Krypt::Bytes* src, size_t len, size_t CIPHER_BLOCKSIZE);
    };

    class ANSI_X9_23 : public PADDING
    {
        public:

        /** Pad the `src` with zeros first, then sets the last byte value to the count of paddings added [reallocates memory]
         * returns the new length of the padded `src`
         * **/
        size_t AddPadding(Krypt::Bytes*& src, size_t len, size_t CIPHER_BLOCKSIZE);
        
        /** Removes the number of bytes [reallocates memory]
         * returns the new length of the un-padded `src`
         * **/
        size_t RemovePadding(Krypt::Bytes*& src, size_t len, size_t CIPHER_BLOCKSIZE);

        /** 
         * returns the length of the un-padded `src`**/
        size_t GetNoPaddingLength(const Krypt::Bytes* src, size_t len, size_t CIPHER_BLOCKSIZE);
    };

    class ISO_IEC_7816_4 : public PADDING
    {
        public:

        /** Adds one `0x80` byte value, then pad the next remaining spaces with zeros [reallocates memory]
         * returns the new length of the padded `src`
         * **/
        size_t AddPadding(Krypt::Bytes*& src, size_t len, size_t CIPHER_BLOCKSIZE);
        
        /** removes padding [reallocates memory]
         * - figures out the padding size by checking the sequence of zeros from the least significant to the most significant byte until it hits `0x80` byte value
         * returns the new length of the unpadded `src`
         * **/
        size_t RemovePadding(Krypt::Bytes*& src, size_t len, size_t CIPHER_BLOCKSIZE);

        /** [does not reallocate src] it only computes the unpadded length
         * returns the length of the unpadded `src`**/
        size_t GetNoPaddingLength(const Krypt::Bytes* src, size_t len, size_t CIPHER_BLOCKSIZE);
    };

    class PKCS_5_7 : public PADDING
    {
        public:

        /** Pad the `src` with the value of the padding count itself [reallocates memory]
         * returns the new length of the padded `src`
         * **/
        size_t AddPadding(Krypt::Bytes*& src, size_t len, size_t CIPHER_BLOCKSIZE);
        
        /** removes padding [reallocates memory]
         * - figures out the padding size by getting the value of the last byte
         * returns the new length of the un-padded `src`
         * **/
        size_t RemovePadding(Krypt::Bytes*& src, size_t len, size_t CIPHER_BLOCKSIZE);

        /** [does not reallocate src] it only computes the unpadded length
         * returns the length of the unpadded `src`**/
        size_t GetNoPaddingLength(const Krypt::Bytes* src, size_t len, size_t CIPHER_BLOCKSIZE);
    };
}

#include "padding/ANSI_X9_23.cpp"
#include "padding/ISO_IEC_7816_4.cpp"
#include "padding/PKCS_5_7.cpp"
#include "padding/ZeroPadding.cpp"

#endif
