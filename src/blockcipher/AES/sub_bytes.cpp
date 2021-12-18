#ifndef SUB_BYTES_CPP
#define SUB_BYTES_CPP

#include "../../blockcipher.hpp"

namespace Krypt
{
    void AES::SubBytes(unsigned char state[4][4])
    {
        int i, j;
        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < Nb; j++)
            {
                state[i][j] = sbox[state[i][j]];
            }
        }
    }

    void AES::InvSubBytes(unsigned char state[4][4])
    {
        int i, j;
        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < Nb; j++)
            {
                state[i][j] = inv_sbox[state[i][j]];
            }
        }
    }
}

#endif