#include "AES.h"

constexpr std::array<std::array<unsigned char, 16>, 16> Aes<>::sbox;
constexpr std::array<std::array<unsigned char, 16>, 16> Aes<>::inv_sbox;

template<int keylen>
Aes<keylen>::Aes(int keyLen)
{
  switch (keyLen)
  {
  case 128:
    this->Nk = 4;
    this->Nr = 10;
    break;
  case 192:
    this->Nk = 6;
    this->Nr = 12;
    break;
  case 256:
    this->Nk = 8;
    this->Nr = 14;
    break;
  default:
    throw "Incorrect key length";
  }
}

template<int keylen>
AES_CONSTEXPR_14 Aes<keylen>::Aes()
{
  static_assert(keylen == 128 || keylen == 192 || keylen == 256, "Key length must be 128, 192, or 256");
  switch (keylen)
  {
  case 128:
    this->Nk = 4;
    this->Nr = 10;
    break;
  case 192:
    this->Nk = 6;
    this->Nr = 12;
    break;
  case 256:
    this->Nk = 8;
    this->Nr = 14;
    break;
  }
}

template<int keylen>
std::vector<unsigned char> Aes<keylen>::EncryptECB(const std::vector<unsigned char>& in, const std::vector<unsigned char>& key)
{
  const unsigned int outLen = GetPaddingLength(in.size());
  const std::vector<unsigned char> alignIn = PaddingNulls(in, outLen);
  std::vector<unsigned char> out(outLen);
  std::vector<unsigned char> roundKeys(4 * Nb * (Nr + 1));
  KeyExpansion(key, roundKeys);
  for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
  {
    std::array<unsigned char, blockBytesLen> temp, temp2;
    std::copy_n(alignIn.begin() + i, blockBytesLen, temp.begin());
    std::copy_n(std::make_move_iterator(out.begin() + i), blockBytesLen, temp2.begin());
    EncryptBlock(temp, temp2, roundKeys);
    std::copy_n(std::make_move_iterator(temp2.begin()), blockBytesLen, out.begin() + i);
  }
  
  return out;
}

template<int keylen>
unsigned char * Aes<keylen>::EncryptECB(unsigned char in[], unsigned int inLen, unsigned char key[], unsigned int &outLen)
{
  auto v = EncryptECB(std::vector<unsigned char>(in, in + inLen), std::vector<unsigned char>(key, key + 4 * Nk));
  outLen = v.size();
  unsigned char* out = new unsigned char[outLen];
  std::copy(v.begin(), v.end(), out);
  
  return out;
}

template<int keylen>
std::vector<unsigned char> Aes<keylen>::DecryptECB(const std::vector<unsigned char>& in, const std::vector<unsigned char>& key)
{
  std::vector<unsigned char> out(in.size());
  std::vector<unsigned char> roundKeys(4 * Nb * (Nr + 1));
  KeyExpansion(key, roundKeys);
  for (unsigned int i = 0; i < in.size(); i+= blockBytesLen)
  {
    std::vector<unsigned char> temp(blockBytesLen);
    std::copy_n(std::make_move_iterator(out.begin()) + i, blockBytesLen, temp.begin());
    DecryptBlock(std::vector<unsigned char>(in.begin() + i, in.begin() + i + blockBytesLen), temp, roundKeys);
    std::copy_n(std::make_move_iterator(temp.begin()), blockBytesLen, out.begin() + i);
  }
  
  return out;
}

template<int keylen>
unsigned char * Aes<keylen>::DecryptECB(unsigned char in[], unsigned int inLen, unsigned char key[])
{
  auto v = DecryptECB(std::vector<unsigned char>(in, in + inLen), std::vector<unsigned char>(key, key + 4 * Nk));
  unsigned char* out = new unsigned char[v.size()];
  std::copy(v.begin(), v.end(), out);
  
  return out;
}

template<int keylen>
std::vector<unsigned char> Aes<keylen>::EncryptCBC(const std::vector<unsigned char>& in, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv)
{
  const unsigned int outLen = GetPaddingLength(in.size());
  const std::vector<unsigned char> alignIn = PaddingNulls(in, outLen);
  std::vector<unsigned char> out(outLen);
  std::array<unsigned char, blockBytesLen> block;
  std::vector<unsigned char> roundKeys(4 * Nb * (Nr + 1));
  KeyExpansion(key, roundKeys);
  std::copy_n(iv.begin(), blockBytesLen, block.begin());
  for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
  {
    std::array<unsigned char, blockBytesLen> temp, temp2;
    std::copy_n(alignIn.begin() + i, blockBytesLen, temp.begin());
    XorBlocks(block, temp, block);
    std::copy_n(std::make_move_iterator(out.begin()) + i, 4 * (Nb + 1), temp2.begin());
    EncryptBlock(block, temp2, roundKeys);
    std::copy_n(std::make_move_iterator(temp2.begin()), 4 * (Nb + 1), out.begin() + i);
    std::copy_n(out.begin() + i, blockBytesLen, block.begin());
  }

  return out;
}

template<int keylen>
unsigned char *Aes<keylen>::EncryptCBC(unsigned char in[], unsigned int inLen, unsigned char key[], unsigned char * iv, unsigned int &outLen)
{
  auto v = EncryptCBC(std::vector<unsigned char>(in, in + inLen), std::vector<unsigned char>(key, key + 4 * Nk), std::vector<unsigned char>(iv, iv + blockBytesLen));
  outLen = v.size();
  unsigned char* out = new unsigned char[outLen];
  std::copy(v.begin(), v.end(), out);
  
  return out;
}

template<int keylen>
std::vector<unsigned char> Aes<keylen>::DecryptCBC(const std::vector<unsigned char>& in, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv)
{
  std::vector<unsigned char> out(in.size());
  std::array<unsigned char, blockBytesLen> block;
  std::vector<unsigned char> roundKeys(4 * Nb * (Nr + 1));
  KeyExpansion(key, roundKeys);
  std::copy_n(iv.begin(), blockBytesLen, block.begin());
  for (unsigned int i = 0; i < in.size(); i+= blockBytesLen)
  {
    std::vector<unsigned char> temp(4 * (Nb + 1));
    std::array<unsigned char, blockBytesLen> temp2;
    std::copy_n(std::make_move_iterator(out.begin()) + i, 4 * (Nb + 1), temp.begin());
    DecryptBlock(std::vector<unsigned char>(in.begin() + i, in.begin() + i + 4 * (Nb + 1)), temp, roundKeys);
    std::copy_n(std::make_move_iterator(temp.begin()), 4 * (Nb + 1), out.begin() + i);
    std::copy_n(std::make_move_iterator(out.begin()) + i, blockBytesLen, temp2.begin());
    XorBlocks(block, temp2, temp2);
    std::copy_n(std::make_move_iterator(temp2.begin()), blockBytesLen, out.begin() + i);
    std::copy_n(in.begin() + i, blockBytesLen, block.begin());
  }

  return out;
}

template<int keylen>
unsigned char *Aes<keylen>::DecryptCBC(unsigned char in[], unsigned int inLen, unsigned char key[], unsigned char * iv)
{
  auto v = DecryptCBC(std::vector<unsigned char>(in, in + inLen), std::vector<unsigned char>(key, key + 4 * Nk), std::vector<unsigned char>(iv, iv + blockBytesLen));
  unsigned char* out = new unsigned char[v.size()];
  std::copy(v.begin(), v.end(), out);
  
  return out;
}

template<int keylen>
std::vector<unsigned char> Aes<keylen>::EncryptCFB(const std::vector<unsigned char>& in, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv)
{
  const unsigned int outLen = GetPaddingLength(in.size());
  const std::vector<unsigned char> alignIn = PaddingNulls(in, outLen);
  std::vector<unsigned char> out(outLen);
  std::array<unsigned char, blockBytesLen> block;
  std::array<unsigned char, blockBytesLen> encryptedBlock;
  std::vector<unsigned char> roundKeys(4 * Nb * (Nr + 1));
  KeyExpansion(key, roundKeys);
  std::copy_n(iv.begin(), blockBytesLen, block.begin());
  for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
  {
    EncryptBlock(block, encryptedBlock, roundKeys);
    std::array<unsigned char, blockBytesLen> temp, temp2;
    std::copy_n(alignIn.begin() + i, blockBytesLen, temp.begin());
    std::copy_n(std::make_move_iterator(out.begin()) + i, blockBytesLen, temp2.begin());
    XorBlocks(temp, encryptedBlock, temp2);
    std::copy_n(std::make_move_iterator(temp2.begin()), blockBytesLen, out.begin() + i);
    std::copy_n(out.begin() + i, blockBytesLen, block.begin());
  }

  return out;
}

template<int keylen>
unsigned char *Aes<keylen>::EncryptCFB(unsigned char in[], unsigned int inLen, unsigned char key[], unsigned char * iv, unsigned int &outLen)
{
  auto v = EncryptCFB(std::vector<unsigned char>(in, in + inLen), std::vector<unsigned char>(key, key + 4 * Nk), std::vector<unsigned char>(iv, iv + blockBytesLen));
  outLen = v.size();
  unsigned char* out = new unsigned char[outLen];
  std::copy(v.begin(), v.end(), out);
  
  return out;
}

template<int keylen>
std::vector<unsigned char> Aes<keylen>::DecryptCFB(const std::vector<unsigned char>& in, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv)
{
  std::vector<unsigned char> out(in.size());
  std::array<unsigned char, blockBytesLen> block;
  std::array<unsigned char, blockBytesLen> encryptedBlock;
  std::vector<unsigned char> roundKeys(4 * Nb * (Nr + 1));
  KeyExpansion(key, roundKeys);
  std::copy_n(iv.begin(), blockBytesLen, block.begin());
  for (unsigned int i = 0; i < in.size(); i+= blockBytesLen)
  {
    EncryptBlock(block, encryptedBlock, roundKeys);
    std::array<unsigned char, blockBytesLen> temp, temp2;
    std::copy_n(in.begin() + i, blockBytesLen, temp.begin());
    std::copy_n(std::make_move_iterator(out.begin()) + i, blockBytesLen, temp2.begin());
    XorBlocks(temp, encryptedBlock, temp2);
    std::copy_n(std::make_move_iterator(temp2.begin()), blockBytesLen, out.begin() + i);
    std::copy_n(in.begin() + i, blockBytesLen, block.begin());
  }
  
  return out;
}

template<int keylen>
unsigned char *Aes<keylen>::DecryptCFB(unsigned char in[], unsigned int inLen, unsigned char key[], unsigned char * iv)
{
  auto v = DecryptCFB(std::vector<unsigned char>(in, in + inLen), std::vector<unsigned char>(key, key + 4 * Nk), std::vector<unsigned char>(iv, iv + blockBytesLen));
  unsigned char* out = new unsigned char[v.size()];
  std::copy(v.begin(), v.end(), out);

  return out;
}

template<int keylen>
std::vector<unsigned char> Aes<keylen>::PaddingNulls(const std::vector<unsigned char>& in, const unsigned int& alignLen)
{
  std::vector<unsigned char> alignIn(in.begin(), in.end());
  if (alignLen > alignIn.size())
  {
    alignIn.resize(alignLen, 0x00);
  }
  return alignIn;
}

template<int keylen>
AES_CONSTEXPR_14 unsigned int Aes<keylen>::GetPaddingLength(const unsigned int& len)
{
  unsigned int lengthWithPadding = (len / blockBytesLen);
  if (len % blockBytesLen) {
    lengthWithPadding++;
  }
  
  lengthWithPadding *= blockBytesLen;
  
  return lengthWithPadding;
}

template<int keylen>
void Aes<keylen>::EncryptBlock(const std::array<unsigned char, blockBytesLen>& in, std::array<unsigned char, blockBytesLen>& out, const std::vector<unsigned char>& roundKeys)
{
  std::array<std::array<unsigned char, Nb>, 4> state;


  for (int i = 0; i < 4; i++)
  {
    for (int j = 0; j < Nb; j++)
    {
      state[i][j] = in.at(i + 4 * j);
    }
  }

  AddRoundKey(state, roundKeys);

  for (int round = 1; round <= Nr - 1; round++)
  {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, std::vector<unsigned char>(roundKeys.begin() + round * 4 * Nb, roundKeys.begin() + round * 4 * Nb + 4 * (Nb + 1)));
  }

  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, std::vector<unsigned char>(roundKeys.begin() + Nr * 4 * Nb, roundKeys.begin() + Nr * 4 * Nb + 4 * (Nb + 1)));

  for (int i = 0; i < 4; i++)
  {
    for (int j = 0; j < Nb; j++)
    {
      out.at(i + 4 * j) = state[i][j];
    }
  }
}

template<int keylen>
void Aes<keylen>::DecryptBlock(const std::vector<unsigned char>& in, std::vector<unsigned char>& out, const std::vector<unsigned char>& roundKeys)
{
  std::array<std::array<unsigned char, Nb>, 4> state;


  for (int i = 0; i < 4; i++)
  {
    for (int j = 0; j < Nb; j++) {
      state[i][j] = in.at(i + 4 * j);
    }
  }

  AddRoundKey(state, std::vector<unsigned char>(roundKeys.begin() + Nr * 4 * Nb, roundKeys.begin() + Nr * 4 * Nb + 4 * (Nb + 1)));

  for (int round = Nr - 1; round >= 1; round--)
  {
    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, std::vector<unsigned char>(roundKeys.begin() + round * 4 * Nb, roundKeys.begin() + round * 4 * Nb + 4 * (Nb + 1)));
    InvMixColumns(state);
  }

  InvSubBytes(state);
  InvShiftRows(state);
  AddRoundKey(state, roundKeys);

  for (int i = 0; i < 4; i++)
  {
    for (int j = 0; j < Nb; j++) {
      out.at(i + 4 * j) = state[i][j];
    }
  }
}

template<int keylen>
void Aes<keylen>::SubBytes(std::array<std::array<unsigned char, Nb>, 4>& state)
{
  int i, j;
  unsigned char t;
  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      t = state[i][j];
      state[i][j] = sbox.at(t / 16).at(t % 16);
    }
  }

}

template<int keylen>
void Aes<keylen>::ShiftRow(std::array<std::array<unsigned char, Nb>, 4>& state, const int& i, const int& n)    // shift row i on n positions
{
  std::array<unsigned char, Nb> tmp;
  for (int j = 0; j < Nb; j++) {
    tmp[j] = state[i][(j + n) % Nb];
  }
  std::copy_n(std::make_move_iterator(tmp.begin()), Nb, state[i].begin());
}

template<int keylen>
void Aes<keylen>::ShiftRows(std::array<std::array<unsigned char, Nb>, 4>& state)
{
  ShiftRow(state, 1, 1);
  ShiftRow(state, 2, 2);
  ShiftRow(state, 3, 3);
}



/* Implementation taken from https://en.wikipedia.org/wiki/Rijndael_mix_columns#Implementation_example */
template<int keylen>
void Aes<keylen>::MixSingleColumn(std::array<unsigned char, 4>& r) 
{
  std::array<unsigned char, 4> a;
  std::array<unsigned char, 4> b;
  unsigned char h;
  /* The array 'a' is simply a copy of the input array 'r'
  * The array 'b' is each element of the array 'a' multiplied by 2
  * in Rijndael's Galois field
  * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */ 
  for(int c=0;c<4;c++) 
  {
    a[c] = r[c];
    /* h is 0xff if the high bit of r[c] is set, 0 otherwise */
    h = static_cast<unsigned char>(static_cast<signed char>(r[c]) >> 7); /* arithmetic right shift, thus shifting in either zeros or ones */
    b[c] = r[c] << 1; /* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
    b[c] ^= 0x1B & h; /* Rijndael's Galois field */
  }
  r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
  r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
  r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
  r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
}

/* Performs the mix columns step. Theory from: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_MixColumns_step */
template<int keylen>
void Aes<keylen>::MixColumns(std::array<std::array<unsigned char, 4>, 4>& state)
{
  std::array<unsigned char, 4> temp;

  for(int i = 0; i < 4; ++i)
  {
    for(int j = 0; j < 4; ++j)
    {
      temp[j] = state[j][i]; //place the current state column in temp
    }
    MixSingleColumn(temp); //mix it using the wiki implementation
    for(int j = 0; j < 4; ++j)
    {
      state[j][i] = temp[j]; //when the column is mixed, place it back into the state
    }
  }
}

template<int keylen>
void Aes<keylen>::AddRoundKey(std::array<std::array<unsigned char, Nb>, 4>& state, const std::vector<unsigned char>& key)
{
  for (int i = 0; i < 4; i++)
  {
    for (int j = 0; j < Nb; j++)
    {
      state[i][j] = state[i][j] ^ key.at(i + 4 * j);
    }
  }
}

template<int keylen>
AES_CONSTEXPR_14 void Aes<keylen>::SubWord(std::array<unsigned char, 4>& a)
{
  for (int i = 0; i < 4; i++)
  {
    a[i] = sbox.at(a[i] / 16).at(a[i] % 16);
  }
}

template<int keylen>
void Aes<keylen>::RotWord(std::array<unsigned char, 4>& a)
{
  const unsigned char c = a[0];
  a[0] = a[1];
  a[1] = a[2];
  a[2] = a[3];
  a[3] = c;
}

template<int keylen>
AES_CONSTEXPR_14 void Aes<keylen>::XorWords(const std::array<unsigned char, 4>& a, const std::array<unsigned char, 4>& b, std::array<unsigned char, 4>& c)
{
  for (int i = 0; i < 4; i++)
  {
    c[i] = a[i] ^ b[i];
  }
}

template<int keylen>
void Aes<keylen>::Rcon(std::array<unsigned char, 4>& a, const int& n)
{
  unsigned char c = 1;
  for (int i = 0; i < n - 1; i++)
  {
    c = xtime(c);
  }

  a[0] = c;
  a[1] = a[2] = a[3] = 0;
}

template<int keylen>
void Aes<keylen>::KeyExpansion(const std::vector<unsigned char>& key, std::vector<unsigned char>& w)
{
  std::array<unsigned char, 4> temp;
  std::array<unsigned char, 4> rcon;

  int i = 0;
  while (i < 4 * Nk)
  {
    w.at(i) = key.at(i);
    i++;
  }

  i = 4 * Nk;
  while (i < 4 * Nb * (Nr + 1))
  {
    temp[0] = w.at(i - 4 + 0);
    temp[1] = w.at(i - 4 + 1);
    temp[2] = w.at(i - 4 + 2);
    temp[3] = w.at(i - 4 + 3);

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

    w.at(i + 0) = w.at(i - 4 * Nk) ^ temp[0];
    w.at(i + 1) = w.at(i + 1 - 4 * Nk) ^ temp[1];
    w.at(i + 2) = w.at(i + 2 - 4 * Nk) ^ temp[2];
    w.at(i + 3) = w.at(i + 3 - 4 * Nk) ^ temp[3];
    i += 4;
  }

}

template<int keylen>
void Aes<keylen>::InvSubBytes(std::array<std::array<unsigned char, Nb>, 4>& state)
{
  unsigned char t;
  for (int i = 0; i < 4; i++)
  {
    for (int j = 0; j < Nb; j++)
    {
      t = state[i][j];
      state[i][j] = inv_sbox.at(t / 16).at(t % 16);
    }
  }
}

template<int keylen>
AES_CONSTEXPR_14 unsigned char Aes<keylen>::mul_bytes(unsigned char a, unsigned char b) // multiplication a and b in galois field
{
  unsigned char p = 0;
  const unsigned char high_bit_mask = 0x80;
  unsigned char high_bit = 0;
  const unsigned char modulo = 0x1B; /* x^8 + x^4 + x^3 + x + 1 */


  for (int i = 0; i < 8; i++) {
    if (b & 1) {
      p ^= a;
    }

    high_bit = a & high_bit_mask;
    a <<= 1;
    if (high_bit) {
      a ^= modulo;
    }
    b >>= 1;
  }

  return p;
}

template<int keylen>
void Aes<keylen>::InvMixColumns(std::array<std::array<unsigned char, Nb>, 4>& state)
{
  std::array<unsigned char, 4> s, s1;

  for (int j = 0; j < Nb; j++)
  {
    for (int i = 0; i < 4; i++)
    {
      s[i] = state[i][j];
    }
    s1[0] = mul_bytes(0x0e, s[0]) ^ mul_bytes(0x0b, s[1]) ^ mul_bytes(0x0d, s[2]) ^ mul_bytes(0x09, s[3]);
    s1[1] = mul_bytes(0x09, s[0]) ^ mul_bytes(0x0e, s[1]) ^ mul_bytes(0x0b, s[2]) ^ mul_bytes(0x0d, s[3]);
    s1[2] = mul_bytes(0x0d, s[0]) ^ mul_bytes(0x09, s[1]) ^ mul_bytes(0x0e, s[2]) ^ mul_bytes(0x0b, s[3]);
    s1[3] = mul_bytes(0x0b, s[0]) ^ mul_bytes(0x0d, s[1]) ^ mul_bytes(0x09, s[2]) ^ mul_bytes(0x0e, s[3]);

    for (int i = 0; i < 4; i++)
    {
      state[i][j] = s1[i];
    }
  }
}

template<int keylen>
void Aes<keylen>::InvShiftRows(std::array<std::array<unsigned char, Nb>, 4>& state)
{
  ShiftRow(state, 1, Nb - 1);
  ShiftRow(state, 2, Nb - 2);
  ShiftRow(state, 3, Nb - 3);
}

template<int keylen>
AES_CONSTEXPR_14 void Aes<keylen>::XorBlocks(const std::array<unsigned char, blockBytesLen>& a, const std::array<unsigned char, blockBytesLen>& b, std::array<unsigned char, blockBytesLen>& c)
{
  for (unsigned int i = 0; i < blockBytesLen; i++)
  {
    c[i] = a[i] ^ b[i];
  }
}

template<int keylen>
void Aes<keylen>::printHexArray(const std::vector<unsigned char>& a)
{
  for (const auto& c : a) {
    printf("%02x ", c);
  }
}

template<int keylen>
void Aes<keylen>::printHexArray(unsigned char a[], unsigned int n)
{
  for (unsigned int i = 0; i < n; i++)
  {
    printf("%02x ", a[i]);
  }
}







