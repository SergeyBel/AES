#ifndef KRYPT_BYTEARRAY_CPP
#define KRYPT_BYTEARRAY_CPP

#include "bytearray.hpp"

namespace  Krypt
{

    Bytes* ByteArray::array() { return first; }
    size_t ByteArray::length() { return second; }

    // returns the pointer array, leaving the .array() equal to NULL, and .length() equal to zero
    Bytes* ByteArray::detach()
    {
        Bytes* ptr = first;
        first = NULL;
        second = 0;
        return ptr;
    }

    Bytes& ByteArray::operator[](size_t i)
    {
        #ifndef INDEX_CHECK_DISABLE
        if(second==0)
            throw std::underflow_error(
                "Krypt::ByteArray[] :"
                "       accessing an empty byte array");
        if(i<0)
            throw std::underflow_error(
                "Krypt::ByteArray[] :"
                "       the index given for operator[] is less-than zero");
        if(i>=second)
            throw std::overflow_error(
                "Krypt::ByteArray[] :"
                "       index given for operator[] is greater-than ByteArray.length()-1");
        #endif
        return first[i];
    }
    
    ByteArray::ByteArray()
    {
        first = NULL;
        second = 0;
    }

    // copy constructor
    ByteArray::ByteArray(const ByteArray& other)
    {
        first = new Bytes[other.second];
        second = other.second;
        memcpy(first,other.first,other.second);
    }

    // move constructor
    ByteArray::ByteArray(std::pair<Bytes*,size_t>&& other) noexcept
    {
        first = other.first;
        second = other.second;

        other.first = NULL;
        other.second = 0;
    }

    // copy assignment
    ByteArray& ByteArray::operator=(ByteArray& other)
    {
        if(first!=NULL) delete [] first;

        first = new Bytes[other.second];
        second = other.second;
        memcpy(first,other.first,other.second);
        return *this;
    }

    // move assingment
    ByteArray& ByteArray::operator=(std::pair<Bytes*,size_t>&& other) noexcept
    {
        if(first!=NULL) delete [] first;

        first = other.first;
        second = other.second;

        other.first = NULL;
        other.second = 0;
        return *this;
    }

    ByteArray::~ByteArray()
    {
        if(first!=NULL) delete [] first;
    }

    std::ostream& operator<<(std::ostream& outputStream, const ByteArray& instance)
    {
        for(size_t i=0; i<instance.second; ++i)
                outputStream << instance.first[i];
        return outputStream;
    }

    std::istream& operator>>(std::istream& inputStream, ByteArray& instance)
    {
        for(size_t i=0; i<instance.second; ++i)
            inputStream >> instance.first[i];
        return inputStream;
    }
} // namespace  Krypt


#endif