#include "AES.h"

AES::AES(AESKeyLength keyLength)
{
  this->Nb = 4;
  switch (keyLength)
  {
  case AESKeyLength::AES_128:
    this->Nk = 4;
    this->Nr = 10;
    break;
  case AESKeyLength::AES_192:
    this->Nk = 6;
    this->Nr = 12;
    break;
  case AESKeyLength::AES_256:
    this->Nk = 8;
    this->Nr = 14;
    break;
  }

  blockBytesLen = 4 * this->Nb * sizeof(unsigned char);
}


unsigned char * AES::EncryptECB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned int &outLen)
{
  outLen = GetPaddingLength(inLen);
  unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
  unsigned char *out = new unsigned char[outLen];
  unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
  {
    EncryptBlock(alignIn + i, out + i, roundKeys);
  }
  
  delete[] alignIn;
  delete[] roundKeys;
  
  return out;
}

unsigned char * AES::DecryptECB(unsigned char in[], unsigned int inLen, unsigned  char key[])
{
  unsigned char *out = new unsigned char[inLen];
  unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  for (unsigned int i = 0; i < inLen; i+= blockBytesLen)
  {
    DecryptBlock(in + i, out + i, roundKeys);
  }

  delete[] roundKeys;
  
  return out;
}


unsigned char *AES::EncryptCBC(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen)
{
  outLen = GetPaddingLength(inLen);
  unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
  unsigned char *out = new unsigned char[outLen];
  unsigned char *block = new unsigned char[blockBytesLen];
  unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
  {
    XorBlocks(block, alignIn + i, block, blockBytesLen);
    EncryptBlock(block, out + i, roundKeys);
    memcpy(block, out + i, blockBytesLen);
  }
  
  delete[] block;
  delete[] alignIn;
  delete[] roundKeys;

  return out;
}

unsigned char *AES::DecryptCBC(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv)
{
  unsigned char *out = new unsigned char[inLen];
  unsigned char *block = new unsigned char[blockBytesLen];
  unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < inLen; i+= blockBytesLen)
  {
    DecryptBlock(in + i, out + i, roundKeys);
    XorBlocks(block, out + i, out + i, blockBytesLen);
    memcpy(block, in + i, blockBytesLen);
  }
  
  delete[] block;
  delete[] roundKeys;

  return out;
}

unsigned char *AES::EncryptCFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen)
{
  outLen = GetPaddingLength(inLen);
  unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
  unsigned char *out = new unsigned char[outLen];
  unsigned char *block = new unsigned char[blockBytesLen];
  unsigned char *encryptedBlock = new unsigned char[blockBytesLen];
  unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
  {
    EncryptBlock(block, encryptedBlock, roundKeys);
    XorBlocks(alignIn + i, encryptedBlock, out + i, blockBytesLen);
    memcpy(block, out + i, blockBytesLen);
  }
  
  delete[] block;
  delete[] encryptedBlock;
  delete[] alignIn;
  delete[] roundKeys;

  return out;
}

unsigned char *AES::DecryptCFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv)
{
  unsigned char *out = new unsigned char[inLen];
  unsigned char *block = new unsigned char[blockBytesLen];
  unsigned char *encryptedBlock = new unsigned char[blockBytesLen];
  unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
  KeyExpansion(key, roundKeys);
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < inLen; i+= blockBytesLen)
  {
    EncryptBlock(block, encryptedBlock, roundKeys);
    XorBlocks(in + i, encryptedBlock, out + i, blockBytesLen);
    memcpy(block, in + i, blockBytesLen);
  }
  
  delete[] block;
  delete[] encryptedBlock;
  delete[] roundKeys;

  return out;
}

unsigned char * AES::PaddingNulls(unsigned char in[], unsigned int inLen, unsigned int alignLen)
{
  unsigned char *alignIn = new unsigned char[alignLen];
  memcpy(alignIn, in, inLen);
  memset(alignIn + inLen, 0x00, alignLen - inLen);
  return alignIn;
}

unsigned int AES::GetPaddingLength(unsigned int len)
{
  unsigned int lengthWithPadding =  (len / blockBytesLen);
  if (len % blockBytesLen) {
	  lengthWithPadding++;
  }
  
  lengthWithPadding *=  blockBytesLen;
  
  return lengthWithPadding;
}

void AES::EncryptBlock(unsigned char in[], unsigned char out[], unsigned  char *roundKeys)
{
  unsigned char **state = new unsigned char *[4];
  state[0] = new unsigned  char[4 * Nb];
  int i, j, round;
  for (i = 0; i < 4; i++)
  {
    state[i] = state[0] + Nb * i;
  }


  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      state[i][j] = in[i + 4 * j];
    }
  }

  AddRoundKey(state, roundKeys);

  for (round = 1; round <= Nr - 1; round++)
  {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, roundKeys + round * 4 * Nb);
  }

  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, roundKeys + Nr * 4 * Nb);

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      out[i + 4 * j] = state[i][j];
    }
  }

  delete[] state[0];
  delete[] state;
}

void AES::DecryptBlock(unsigned char in[], unsigned char out[], unsigned  char *roundKeys)
{
  unsigned char **state = new unsigned char *[4];
  state[0] = new unsigned  char[4 * Nb];
  int i, j, round;
  for (i = 0; i < 4; i++)
  {
    state[i] = state[0] + Nb * i;
  }


  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++) {
      state[i][j] = in[i + 4 * j];
    }
  }

  AddRoundKey(state, roundKeys + Nr * 4 * Nb);

  for (round = Nr - 1; round >= 1; round--)
  {
    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, roundKeys + round * 4 * Nb);
    InvMixColumns(state);
  }

  InvSubBytes(state);
  InvShiftRows(state);
  AddRoundKey(state, roundKeys);

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++) {
      out[i + 4 * j] = state[i][j];
    }
  }

  delete[] state[0];
  delete[] state;
}


void AES::SubBytes(unsigned char **state)
{
  int i, j;
  unsigned char t;
  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      t = state[i][j];
      state[i][j] = sbox[t / 16][t % 16];
    }
  }

}

void AES::ShiftRow(unsigned char **state, int i, int n)    // shift row i on n positions
{
  unsigned char *tmp = new unsigned char[Nb];
  for (int j = 0; j < Nb; j++) {
    tmp[j] = state[i][(j + n) % Nb];
  }
  memcpy(state[i], tmp, Nb * sizeof(unsigned char));
	
  delete[] tmp;
}

void AES::ShiftRows(unsigned char **state)
{
  ShiftRow(state, 1, 1);
  ShiftRow(state, 2, 2);
  ShiftRow(state, 3, 3);
}

unsigned char AES::xtime(unsigned char b)    // multiply on x
{
  return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}



void AES::MixColumns(unsigned char** state) 
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

void AES::AddRoundKey(unsigned char **state, unsigned char *key)
{
  int i, j;
  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      state[i][j] = state[i][j] ^ key[i + 4 * j];
    }
  }
}

void AES::SubWord(unsigned char *a)
{
  int i;
  for (i = 0; i < 4; i++)
  {
    a[i] = sbox[a[i] / 16][a[i] % 16];
  }
}

void AES::RotWord(unsigned char *a)
{
  unsigned char c = a[0];
  a[0] = a[1];
  a[1] = a[2];
  a[2] = a[3];
  a[3] = c;
}

void AES::XorWords(unsigned char *a, unsigned char *b, unsigned char *c)
{
  int i;
  for (i = 0; i < 4; i++)
  {
    c[i] = a[i] ^ b[i];
  }
}

void AES::Rcon(unsigned char * a, int n)
{
  int i;
  unsigned char c = 1;
  for (i = 0; i < n - 1; i++)
  {
    c = xtime(c);
  }

  a[0] = c;
  a[1] = a[2] = a[3] = 0;
}

void AES::KeyExpansion(unsigned char key[], unsigned char w[])
{
  unsigned char *temp = new unsigned char[4];
  unsigned char *rcon = new unsigned char[4];

  int i = 0;
  while (i < 4 * Nk)
  {
    w[i] = key[i];
    i++;
  }

  i = 4 * Nk;
  while (i < 4 * Nb * (Nr + 1))
  {
    temp[0] = w[i - 4 + 0];
    temp[1] = w[i - 4 + 1];
    temp[2] = w[i - 4 + 2];
    temp[3] = w[i - 4 + 3];

    if (i / 4 % Nk == 0)
    {
        RotWord(temp);
        SubWord(temp);
        Rcon(rcon, i / (Nk * 4));
        XorWords(temp, rcon, temp);
    }
    else if (Nk > 6 && i / 4 % Nk == 4)
    {
      SubWord(temp);
    }

    w[i + 0] = w[i - 4 * Nk] ^ temp[0];
    w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
    w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
    w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
    i += 4;
  }

  delete []rcon;
  delete []temp;

}


void AES::InvSubBytes(unsigned char **state)
{
  int i, j;
  unsigned char t;
  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      t = state[i][j];
      state[i][j] = inv_sbox[t / 16][t % 16];
    }
  }
}



void AES::InvMixColumns(unsigned char **state)
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

void AES::InvShiftRows(unsigned char **state)
{
  ShiftRow(state, 1, Nb - 1);
  ShiftRow(state, 2, Nb - 2);
  ShiftRow(state, 3, Nb - 3);
}

void AES::XorBlocks(unsigned char *a, unsigned char * b, unsigned char *c, unsigned int len)
{
  for (unsigned int i = 0; i < len; i++)
  {
    c[i] = a[i] ^ b[i];
  }
}

void AES::printHexArray (unsigned char a[], unsigned int n)
{
	for (unsigned int i = 0; i < n; i++) {
	  printf("%02x ", a[i]);
	}
}

void AES::printHexVector (vector<unsigned char> a)
{
	for (unsigned int i = 0; i < a.size(); i++) {
	  printf("%02x ", a[i]);
	}
}

vector<unsigned char> AES::ArrayToVector(unsigned char *a, unsigned char len)
{
   vector<unsigned char> v(a, a + len * sizeof(unsigned char));
   return v;
}

unsigned char *AES::VectorToArray(vector<unsigned char> a)
{
  return a.data();
}


vector<unsigned char> AES::EncryptECB(vector<unsigned char> in, vector<unsigned char> key)
{
  unsigned int outLen = 0;;
  unsigned char *out = EncryptECB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key), outLen);
  vector<unsigned char> v = ArrayToVector(out, outLen);
  delete []out;
  return v;
}

vector<unsigned char> AES::DecryptECB(vector<unsigned char> in, vector<unsigned char> key)
{
  unsigned char *out = DecryptECB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key));
  vector<unsigned char> v = ArrayToVector(out, (unsigned int)in.size());
  delete []out;
  return v;
}


vector<unsigned char> AES::EncryptCBC(vector<unsigned char> in, vector<unsigned char> key, vector<unsigned char> iv)
{
  unsigned int outLen = 0;
  unsigned char *out = EncryptCBC(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key), VectorToArray(iv),  outLen);
  vector<unsigned char> v = ArrayToVector(out, outLen);
  delete [] out;
  return v;
}

vector<unsigned char> AES::DecryptCBC(vector<unsigned char> in, vector<unsigned char> key, vector<unsigned char> iv)
{
  unsigned char *out = DecryptCBC(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key), VectorToArray(iv));
  vector<unsigned char> v = ArrayToVector(out, (unsigned int)in.size());
  delete [] out;
  return v;
}

 vector<unsigned char> AES::EncryptCFB(vector<unsigned char> in, vector<unsigned char> key, vector<unsigned char> iv)
{
  unsigned int outLen = 0;
  unsigned char *out = EncryptCFB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key), VectorToArray(iv),  outLen);
  vector<unsigned char> v = ArrayToVector(out, outLen);
  delete [] out;
  return v;
}

vector<unsigned char> AES::DecryptCFB(vector<unsigned char> in, vector<unsigned char> key, vector<unsigned char> iv)
{
  unsigned char *out = DecryptCFB(VectorToArray(in), (unsigned int)in.size(), VectorToArray(key), VectorToArray(iv));
  vector<unsigned char> v = ArrayToVector(out, (unsigned int)in.size());
  delete [] out;
  return v;

}

