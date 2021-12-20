#ifndef KRYPT_BYTEARRAY_HPP
#define KRYPT_BYTEARRAY_HPP

#include <iostream>
#include <utility>
#include "types.hpp"

namespace Krypt
{
    class ByteArray : public std::pair<Bytes*,size_t>
    {
        public:

        Bytes* array();
        size_t length();

        // returns the pointer array then leaving the member .array() equal to NULL, and .length() equal to zero
        Bytes* detach();

        Bytes& operator[](size_t i);
        
        ByteArray();

        // copy constructor
        ByteArray(const ByteArray& other);

        // move constructor
        ByteArray(std::pair<Bytes*,size_t>&& other) noexcept;

        // assignment operator
        ByteArray& operator=(ByteArray& other);

        // move assingment
        ByteArray& operator=(std::pair<Bytes*,size_t>&& other) noexcept;

        ~ByteArray();
    };

    std::ostream& operator<<(std::ostream& outputStream, const ByteArray& instance);

    std::istream& operator>>(std::istream& inputStream, ByteArray& instance);
}

#include "bytearray.cpp"

#endif