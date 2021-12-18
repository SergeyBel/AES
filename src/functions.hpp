#ifndef KRYPT_FUNCTIONS_HPP
#define KRYPT_FUNCTIONS_HPP

#include <iostream>
#include "types.hpp"

namespace Krypt
{
    void printHexArray (unsigned char a[], unsigned int n)
    {
        for (unsigned int i = 0; i < n; i++) {
            printf("%02x ", a[i]);
        }
    }

    void printHexVector (const ByteStream& a)
    {
        for (unsigned int i = 0; i < a.size(); i++) {
            printf("%02x ", a[i]);
        }
    }

    ByteStream ArrayToVector(unsigned char *a, unsigned char len)
    {
        ByteStream v(a, a + len * sizeof(unsigned char));
        return v;
    }

    const unsigned char *VectorToArray(const ByteStream& a)
    {
        return a.data();
    }
}

#endif