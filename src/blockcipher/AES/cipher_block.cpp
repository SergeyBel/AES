#ifndef CIPHER_BLOCK_CPP
#define CIPHER_BLOCK_CPP

#include "../../blockcipher.hpp"

namespace Krypt::BlockCipher
{
    void AES::EncryptBlock(Bytes *src, Bytes *dest)
    {
        Bytes state[4][4];
        uint8_t i, j, round;

        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < Nb; j++)
            {
                state[i][j] = src[i + 4 * j];
            }
        }

        AddRoundKey(state, RoundedKeys);

        for (round = 1; round <= Nr - 1; round++)
        {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, RoundedKeys + round * 4 * Nb);
        }

        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, RoundedKeys + Nr * 4 * Nb);

        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < Nb; j++)
            {
                dest[i + 4 * j] = state[i][j];
            }
        }
    }

    void AES::DecryptBlock(Bytes *src, Bytes *dest)
    {
        Bytes state[4][4];
        uint8_t i, j, round;

        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < Nb; j++) {
                state[i][j] = src[i + 4 * j];
            }
        }

        AddRoundKey(state, RoundedKeys + Nr * 4 * Nb);

        for (round = Nr - 1; round >= 1; round--)
        {
            InvSubBytes(state);
            InvShiftRows(state);
            AddRoundKey(state, RoundedKeys + round * 4 * Nb);
            InvMixColumns(state);
        }

        InvSubBytes(state);
        InvShiftRows(state);
        AddRoundKey(state, RoundedKeys);

        for (i = 0; i < 4; i++)
        {
            for (j = 0; j < Nb; j++) {
                dest[i + 4 * j] = state[i][j];
            }
        }
    }
}

#endif