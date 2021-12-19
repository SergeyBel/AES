#ifndef KRYPT_FUNCTIONS_HPP
#define KRYPT_FUNCTIONS_HPP

#include <iostream>
#include "types.hpp"

namespace Krypt
{
    void printHexArray (unsigned char a[], size_t n)
    {
        for (size_t i = 0; i < n; i++) {
            printf("%02x ", a[i]);
        }
        std::cout << "\n";
    }

    void printHexVector (const std::vector<unsigned char>& a)
    {
        for (size_t i = 0; i < a.size(); i++) {
            printf("%02x ", a[i]);
        }
    }

    std::vector<unsigned char> ArrayToVector(unsigned char *a, unsigned char len)
    {
        std::vector<unsigned char> v(a, a + len * sizeof(unsigned char));
        return v;
    }

    const unsigned char *VectorToArray(const std::vector<unsigned char>& a)
    {
        return a.data();
    }
}

#endif