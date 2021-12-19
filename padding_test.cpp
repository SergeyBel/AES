#include <iostream>
#include <exception>
#include <cstring>
#include "src/padding.hpp"

#define THISISNOT_BLOCK_SIZE 8

void printHexArray(const std::string& label, unsigned char a[], unsigned int n) {
    std::cout << label << " : ";
    for (unsigned int i = 0; i < n; i++)
        printf("%02x ", a[i]);
    std::cout << "\n";
}

int main()
{
    unsigned char plain[] = {
        0x00, 0x11, 0x22
    };

    {
        std::cout << "Pkcs:\n";
        Krypt::Padding::PKCS_5_7 pkcs;

        unsigned char *heap_plain = new unsigned char[sizeof(plain)]; // copy values to heap
        memcpy(heap_plain,plain,sizeof(plain));
        printHexArray("origin : ",heap_plain,sizeof(plain));

        std::pair<Krypt::Bytes*,size_t> padded = pkcs.AddPadding(heap_plain,sizeof(plain),THISISNOT_BLOCK_SIZE); // pad the array in heap
        printHexArray("padded : ",padded.first,padded.second);

        std::pair<Krypt::Bytes*,size_t> recover = pkcs.RemovePadding(padded.first,padded.second,THISISNOT_BLOCK_SIZE);
        printHexArray("recorv : ",recover.first,recover.second);

        delete [] heap_plain; delete [] padded.first; delete [] recover.first;
        std::cout << "\n";
    }

    {
        std::cout << "ZeroNulls:\n";
        Krypt::Padding::ZeroNulls zeroNull;

        unsigned char *heap_plain = new unsigned char[sizeof(plain)]; // copy values to heap
        memcpy(heap_plain,plain,sizeof(plain));
        printHexArray("origin : ",heap_plain,sizeof(plain));

        std::pair<Krypt::Bytes*,size_t> padded = zeroNull.AddPadding(heap_plain,sizeof(plain),THISISNOT_BLOCK_SIZE); // pad the array in heap
        printHexArray("padded : ",padded.first,padded.second);

        std::pair<Krypt::Bytes*,size_t> recover = zeroNull.RemovePadding(padded.first,padded.second,THISISNOT_BLOCK_SIZE);
        printHexArray("recorv : ",recover.first,recover.second);

        delete [] heap_plain; delete [] padded.first; delete [] recover.first;
        std::cout << "\n";
    }

    {
        std::cout << "isoiec:\n";
        Krypt::Padding::ISO_IEC_7816_4 isoiec;

        unsigned char *heap_plain = new unsigned char[sizeof(plain)]; // copy values to heap
        memcpy(heap_plain,plain,sizeof(plain));
        printHexArray("origin : ",heap_plain,sizeof(plain));

        std::pair<Krypt::Bytes*,size_t> padded = isoiec.AddPadding(heap_plain,sizeof(plain),THISISNOT_BLOCK_SIZE); // pad the array in heap
        printHexArray("padded : ",padded.first,padded.second);

        std::pair<Krypt::Bytes*,size_t> recover = isoiec.RemovePadding(padded.first,padded.second,THISISNOT_BLOCK_SIZE);
        printHexArray("recorv : ",recover.first,recover.second);

        delete [] heap_plain; delete [] padded.first; delete [] recover.first;
        std::cout << "\n";
    }

    {
        std::cout << "ansi:\n";
        Krypt::Padding::ANSI_X9_23 ansi;

        unsigned char *heap_plain = new unsigned char[sizeof(plain)]; // copy values to heap
        memcpy(heap_plain,plain,sizeof(plain));
        printHexArray("origin : ",heap_plain,sizeof(plain));

        std::pair<Krypt::Bytes*,size_t> padded = ansi.AddPadding(heap_plain,sizeof(plain),THISISNOT_BLOCK_SIZE); // pad the array in heap
        printHexArray("padded : ",padded.first,padded.second);

        std::pair<Krypt::Bytes*,size_t> recover = ansi.RemovePadding(padded.first,padded.second,THISISNOT_BLOCK_SIZE);
        printHexArray("recorv : ",recover.first,recover.second);

        delete [] heap_plain; delete [] padded.first; delete [] recover.first;
        std::cout << "\n";
    }
}