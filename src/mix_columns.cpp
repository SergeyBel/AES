#ifndef BUILD_LIB
#ifndef MIX_COLUMNS_CPP
#define MIX_COLUMNS_CPP
#endif

#include "AES.h"

namespace Cipher
{
    void AES::MixColumns(unsigned char state[4][4]) 
    {
        unsigned char temp_state[4][4];
        
        for(size_t i=0; i<4; ++i)
        {
            memset(temp_state[i],0,4);
        }

        for(size_t i=0; i<4; ++i)
        {
            for(size_t k=0; k<4; ++k)
            {
                for(size_t j=0; j<4; ++j)
                {
                    if(CMDS[i][k]==1)
                        temp_state[i][j] ^= state[k][j];
                    else
                        temp_state[i][j] ^= GF_MUL_TABLE[CMDS[i][k]][state[k][j]];
                    }
                }
        }

        for(size_t i=0; i<4; ++i)
        {
          memcpy(state[i],temp_state[i],4);
        }
    }

    void AES::InvMixColumns(unsigned char state[4][4])
    {
        unsigned char temp_state[4][4];
        
        for(size_t i=0; i<4; ++i)
        {
            memset(temp_state[i],0,4);
        }

        for(size_t i=0; i<4; ++i)
        {
            for(size_t k=0; k<4; ++k)
            {
                for(size_t j=0; j<4; ++j)
                {
                    temp_state[i][j] ^= GF_MUL_TABLE[INV_CMDS[i][k]][state[k][j]];
                }
            }
        }

        for(size_t i=0; i<4; ++i)
        {
            memcpy(state[i],temp_state[i],4);
        }
    }
}

#endif