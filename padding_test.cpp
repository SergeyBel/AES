#include <iostream>
#include <exception>
#include <cstring>
#include "src/padding.hpp"

#define BLOCK_SIZE 8

void printHexArray(const std::string& label, unsigned char a[], unsigned int n) {
    std::cout << label << " : ";
    for (unsigned int i = 0; i < n; i++)
        printf("%02x ", a[i]);
    std::cout << "\n";
}

int main()
{
    unsigned char plain[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x80
    };

    Padding::ZeroNulls zeroNull;
    Padding::ISO_IEC_7816_4 isoiec;
    Padding::ANSI_X9_23 ansi;
    Padding::PKCS_5_7 pkcs;

    unsigned char *heap_plain = new unsigned char[sizeof(plain)]; // copy values to heap
    memcpy(heap_plain,plain,sizeof(plain));
    printHexArray("origin : ",heap_plain,sizeof(plain));

    size_t noPadLen0 = isoiec.RemovePadding(heap_plain,sizeof(plain),BLOCK_SIZE);

    size_t newLen = isoiec.AddPadding(heap_plain,sizeof(plain),BLOCK_SIZE); // pad the array in heap
    printHexArray("padded : ",heap_plain,newLen);

    size_t noPadLen = isoiec.RemovePadding(heap_plain,newLen,BLOCK_SIZE);
    printHexArray("recorv : ",heap_plain,noPadLen);

    delete [] heap_plain;
}