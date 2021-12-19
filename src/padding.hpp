#ifndef KRYPT_PADDING_HPP
#define KRYPT_PADDING_HPP

#include <iostream>
#include <exception>
#include <cstring>
#include <utility>
#include "types.hpp"

namespace Krypt::Padding
{
    class InvalidPadding : public std::exception
    {
        public:
        InvalidPadding(const char* info) : msg(info) {}
        const char* msg;
        const char* what() const throw ();
    };

    class InvalidPaddedLength : public std::exception
    {
        public:
        InvalidPaddedLength(const char* paddingSchemName) : msg(paddingSchemName) {}
        const char* msg;
        const char* what() const throw ();
    };

    /// default & base class for padding - pad the src with zeros
    class ZeroNulls
    {
        public:
        
        /** Pad the last block with zeros [reallocates memory]
         * returns the new length of the padded `src`
         * **/
        virtual std::pair<Bytes*,size_t> AddPadding(Bytes* src, size_t len, size_t BLOCKSIZE);
        
        /** Removes the last 16 byte zeros [reallocates memory]
         * returns the new length of the un-padded `src`
         * **/
        virtual std::pair<Bytes*,size_t> RemovePadding(Bytes* src, size_t len, size_t BLOCKSIZE);

            virtual ~ZeroNulls() = default;
    };

    class ANSI_X9_23 : public ZeroNulls
    {
        public:

        /** Pad the `src` with zeros first, then sets the last byte value to the count of paddings added [reallocates memory]
         * returns the new length of the padded `src`
         * **/
        std::pair<Bytes*,size_t> AddPadding(Bytes* src, size_t len, size_t BLOCKSIZE) override;
        
        /** Removes the number of bytes [reallocates memory]
         * returns the new length of the un-padded `src`
         * **/
        std::pair<Bytes*,size_t> RemovePadding(Bytes* src, size_t len, size_t BLOCKSIZE) override;

        ~ANSI_X9_23() {}
    };

    class ISO_IEC_7816_4 : public ZeroNulls
    {
        public:

        /** Adds one `0x80` byte value, then pad the next remaining spaces with zeros [reallocates memory]
         * returns the new length of the padded `src`
         * **/
        std::pair<Bytes*,size_t> AddPadding(Bytes* src, size_t len, size_t BLOCKSIZE) override;
        
        /** removes padding [reallocates memory]
         * - figures out the padding size by checking the sequence of zeros from the least significant to the most significant byte until it hits `0x80` byte value
         * returns the new length of the unpadded `src`
         * **/
        std::pair<Bytes*,size_t> RemovePadding(Bytes* src, size_t len, size_t BLOCKSIZE) override;

        ~ISO_IEC_7816_4() {}
    };

    class PKCS_5_7 : public ZeroNulls
    {
        public:

        /** Pad the `src` with the value of the padding count itself [reallocates memory]
         * returns the new length of the padded `src`
         * **/
        std::pair<Bytes*,size_t> AddPadding(Bytes* src, size_t len, size_t BLOCKSIZE) override;
        
        /** removes padding [reallocates memory]
         * - figures out the padding size by getting the value of the last byte
         * returns the new length of the un-padded `src`
         * **/
        std::pair<Bytes*,size_t> RemovePadding(Bytes* src, size_t len, size_t BLOCKSIZE) override;

        ~PKCS_5_7() {}
    };
}

#include "padding/ANSI_X9_23.cpp"
#include "padding/ISO_IEC_7816_4.cpp"
#include "padding/PKCS_5_7.cpp"
#include "padding/ZeroPadding.cpp"

#endif
