#ifndef _AES_H_
#define _AES_H_

#include <algorithm>
#include <array>
#include <cassert>
#include <iostream>
#include <vector>

#if __cplusplus >= 201402L
#define AES_CONSTEXPR_14 constexpr
#else
#define AES_CONSTEXPR_14
#endif

template<int keylen = 256>
class Aes
{
private:
  static constexpr int Nb = 4;
  int Nk;
  int Nr;

  static constexpr unsigned int blockBytesLen = 4 * Nb;

  inline void SubBytes(std::array<std::array<unsigned char, Nb>, 4>& state)
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

  inline void ShiftRow(std::array<std::array<unsigned char, Nb>, 4>& state, const int& i, const int& n)    // shift row i on n positions
  {
    std::array<unsigned char, Nb> tmp;
    for (int j = 0; j < Nb; j++) {
      tmp[j] = state[i][(j + n) % Nb];
    }
    std::copy_n(std::make_move_iterator(tmp.begin()), Nb, state[i].begin());
  }

  void ShiftRows(std::array<std::array<unsigned char, Nb>, 4>& state)
  {
    ShiftRow(state, 1, 1);
    ShiftRow(state, 2, 2);
    ShiftRow(state, 3, 3);
  }

  constexpr unsigned char xtime(const unsigned char& b)    // multiply on x
  {
    return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
  }

  AES_CONSTEXPR_14 unsigned char mul_bytes(unsigned char a, unsigned char b)
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

/* Performs the mix columns step. Theory from: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_MixColumns_step */
  void MixColumns(std::array<std::array<unsigned char, 4>, 4>& state)
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

/* Implementation taken from https://en.wikipedia.org/wiki/Rijndael_mix_columns#Implementation_example */
  void MixSingleColumn(std::array<unsigned char, 4>& r)
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

  void AddRoundKey(std::array<std::array<unsigned char, Nb>, 4>& state, const std::vector<unsigned char>& key)
  {
    for (int i = 0; i < 4; i++)
    {
      for (int j = 0; j < Nb; j++)
      {
        state[i][j] = state[i][j] ^ key.at(i + 4 * j);
      }
    }
  }

  AES_CONSTEXPR_14 void SubWord(std::array<unsigned char, 4>& a)
  {
    for (int i = 0; i < 4; i++)
    {
      a[i] = sbox.at(a[i] / 16).at(a[i] % 16);
    }
  }

  void RotWord(std::array<unsigned char, 4>& a)
  {
    const unsigned char c = a[0];
    a[0] = a[1];
    a[1] = a[2];
    a[2] = a[3];
    a[3] = c;
  }

  AES_CONSTEXPR_14 void XorWords(const std::array<unsigned char, 4>& a, const std::array<unsigned char, 4>& b, std::array<unsigned char, 4>& c)
  {
    for (int i = 0; i < 4; i++)
    {
      c[i] = a[i] ^ b[i];
    }
  }

  void Rcon(std::array<unsigned char, 4>& a, const int& n)
  {
    unsigned char c = 1;
    for (int i = 0; i < n - 1; i++)
    {
      c = xtime(c);
    }
  
    a[0] = c;
    a[1] = a[2] = a[3] = 0;
  }

  void InvSubBytes(std::array<std::array<unsigned char, Nb>, 4>& state)
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

  void InvMixColumns(std::array<std::array<unsigned char, Nb>, 4>& state)
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

  void InvShiftRows(std::array<std::array<unsigned char, Nb>, 4>& state)
  {
    ShiftRow(state, 1, Nb - 1);
    ShiftRow(state, 2, Nb - 2);
    ShiftRow(state, 3, Nb - 3);
  }

  std::vector<unsigned char> PaddingNulls(const std::vector<unsigned char>& in, const unsigned int& alignLen)
  {
    std::vector<unsigned char> alignIn(in.begin(), in.end());
    if (alignLen > alignIn.size())
    {
      alignIn.resize(alignLen, 0x00);
    }
    return alignIn;
  }
  
  AES_CONSTEXPR_14 unsigned int GetPaddingLength(const unsigned int& len)
  {
    unsigned int lengthWithPadding = (len / blockBytesLen);
    if (len % blockBytesLen) {
      lengthWithPadding++;
    }
    
    lengthWithPadding *= blockBytesLen;
    
    return lengthWithPadding;
  }

  void KeyExpansion(const std::vector<unsigned char>& key, std::vector<unsigned char>& w)
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

  void EncryptBlock(const std::array<unsigned char, blockBytesLen>& in, std::array<unsigned char, blockBytesLen>& out, const std::vector<unsigned char>& roundKeys)
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

  void DecryptBlock(const std::vector<unsigned char>& in, std::vector<unsigned char>& out, const std::vector<unsigned char>& roundKeys)
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

  AES_CONSTEXPR_14 void XorBlocks(const std::array<unsigned char, blockBytesLen>& a, const std::array<unsigned char, blockBytesLen>& b, std::array<unsigned char, blockBytesLen>& c)
  {
    for (unsigned int i = 0; i < blockBytesLen; i++)
    {
      c[i] = a[i] ^ b[i];
    }
  }

public:

  AES_CONSTEXPR_14 Aes()
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

  std::vector<unsigned char> EncryptECB(const std::vector<unsigned char>& in, const std::vector<unsigned char>& key)
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

  std::vector<unsigned char> DecryptECB(const std::vector<unsigned char>& in, const std::vector<unsigned char>& key)
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

  std::vector<unsigned char> EncryptCBC(const std::vector<unsigned char>& in, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv)
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

  std::vector<unsigned char> DecryptCBC(const std::vector<unsigned char>& in, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv)
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

  std::vector<unsigned char> EncryptCFB(const std::vector<unsigned char>& in, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv)
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

  std::vector<unsigned char> DecryptCFB(const std::vector<unsigned char>& in, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv)
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
  
  static void printHexArray(const std::vector<unsigned char>& a)
  {
    for (const auto& c : a) {
      printf("%02x ", c);
    }
  }

  // For backwards compatibility. Prefer to use above functions

  Aes(int keyLen)
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

  unsigned char *EncryptECB(unsigned char in[], unsigned int inLen, unsigned char key[], unsigned int &outLen)
  {
    auto v = EncryptECB(std::vector<unsigned char>(in, in + inLen), std::vector<unsigned char>(key, key + 4 * Nk));
    outLen = v.size();
    unsigned char* out = new unsigned char[outLen];
    std::copy(v.begin(), v.end(), out);
    
    return out;
  }

  unsigned char *DecryptECB(unsigned char in[], unsigned int inLen, unsigned char key[])
  {
    auto v = DecryptECB(std::vector<unsigned char>(in, in + inLen), std::vector<unsigned char>(key, key + 4 * Nk));
    unsigned char* out = new unsigned char[v.size()];
    std::copy(v.begin(), v.end(), out);
    
    return out;
  }

  unsigned char *EncryptCBC(unsigned char in[], unsigned int inLen, unsigned char key[], unsigned char * iv, unsigned int &outLen)
  {
    auto v = EncryptCBC(std::vector<unsigned char>(in, in + inLen), std::vector<unsigned char>(key, key + 4 * Nk), std::vector<unsigned char>(iv, iv + blockBytesLen));
    outLen = v.size();
    unsigned char* out = new unsigned char[outLen];
    std::copy(v.begin(), v.end(), out);
    
    return out;
  }

  unsigned char *DecryptCBC(unsigned char in[], unsigned int inLen, unsigned char key[], unsigned char * iv)
  {
    auto v = DecryptCBC(std::vector<unsigned char>(in, in + inLen), std::vector<unsigned char>(key, key + 4 * Nk), std::vector<unsigned char>(iv, iv + blockBytesLen));
    unsigned char* out = new unsigned char[v.size()];
    std::copy(v.begin(), v.end(), out);
    
    return out;
  }

  unsigned char *EncryptCFB(unsigned char in[], unsigned int inLen, unsigned char key[], unsigned char * iv, unsigned int &outLen)
  {
    auto v = EncryptCFB(std::vector<unsigned char>(in, in + inLen), std::vector<unsigned char>(key, key + 4 * Nk), std::vector<unsigned char>(iv, iv + blockBytesLen));
    outLen = v.size();
    unsigned char* out = new unsigned char[outLen];
    std::copy(v.begin(), v.end(), out);
    
    return out;
  }

  unsigned char *DecryptCFB(unsigned char in[], unsigned int inLen, unsigned char key[], unsigned char * iv)
  {
    auto v = DecryptCFB(std::vector<unsigned char>(in, in + inLen), std::vector<unsigned char>(key, key + 4 * Nk), std::vector<unsigned char>(iv, iv + blockBytesLen));
    unsigned char* out = new unsigned char[v.size()];
    std::copy(v.begin(), v.end(), out);
  
    return out;
  }
  
  static void printHexArray (unsigned char a[], unsigned int n)
  {
    for (unsigned int i = 0; i < n; i++)
    {
      printf("%02x ", a[i]);
    }
  }

private:
  static constexpr std::array<std::array<unsigned char, 16>, 16> sbox = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
  };

  static constexpr std::array<std::array<unsigned char, 16>, 16> inv_sbox = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d, };
};

using AES = Aes<>;

#endif
