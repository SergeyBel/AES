using System;
using System.Collections.Generic;

namespace SandBoxConsole
{
    internal class AES
    {
        private int Nb;
        private int Nk;
        private int Nr;
        private uint blockBytesLen;

        private byte[,] sbox = {
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
        };

        private byte[,] inv_sbox = {
            {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
            {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
            {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
        };

        internal AES(int keyLen)
        {
            Nb = 4;
            switch (keyLen)
            {
                case 128:
                    Nk = 4;
                    Nr = 10;
                    break;

                case 192:
                    Nk = 6;
                    Nr = 12;
                    break;

                case 256:
                    Nk = 8;
                    Nr = 14;
                    break;

                default:
                    throw new Exception("Incorrect key length");
            }

            blockBytesLen = (uint)(4 * Nb * sizeof(byte));
        }

        public byte[] EncryptECB(byte[] plain, byte[] key)
        {
            uint paddedLength = GetPaddingLength((uint)plain.Length);
            byte[] alignIn = PaddingNulls(plain, (uint)plain.Length, paddedLength);

            var in_blocks = new List<byte>(alignIn);
            var out_blocks = new List<byte>();

            for (uint i = 0; i < paddedLength; i += blockBytesLen)
                out_blocks.AddRange(EncryptBlock(in_blocks.GetRange((int)i, (int)blockBytesLen).ToArray(), key));

            return out_blocks.ToArray();
        }

        public byte[] DecryptECB(byte[] bytes_in, byte[] key)
        {
            var in_blocks = new List<byte>(bytes_in);
            var out_blocks = new List<byte>();

            for (uint i = 0; i < bytes_in.Length; i += blockBytesLen)
                out_blocks.AddRange(DecryptBlock(in_blocks.GetRange((int)i, (int)blockBytesLen).ToArray(), key));

            return out_blocks.ToArray();
        }

        public byte[] EncryptCBC(byte[] plain, byte[] key, byte[] iv)
        {
            if (iv.Length != blockBytesLen)
                throw new Exception("IV Length Mismatch. Expected length of: " + blockBytesLen);

            uint paddedLength = GetPaddingLength((uint)plain.Length);

            var in_blocks = new List<byte>(PaddingNulls(plain, (uint)plain.Length, paddedLength));
            var out_blocks = new List<byte>();

            var block = new List<byte>(iv);

            for (uint i = 0; i < paddedLength; i += blockBytesLen)
            {
                //in block
                var iBlock = in_blocks.GetRange((int)i, (int)blockBytesLen).ToArray();

                //xor block
                var xBlock = XorBlocks(block.ToArray(), iBlock, blockBytesLen);

                //encrypted block
                var eBlock = EncryptBlock(xBlock, key);
                out_blocks.AddRange(eBlock);

                //Update block
                block = new List<byte>(eBlock);
            }

            return out_blocks.ToArray();
        }

        public byte[] DecryptCBC(byte[] bytes_in, byte[] key, byte[] iv)
        {
            if(iv.Length != blockBytesLen)
                throw new Exception("IV Length Mismatch. Expected length of: " + blockBytesLen);

            var in_blocks = new List<byte>(bytes_in);
            var out_blocks = new List<byte>();

            //setup iv
            var block = new List<byte>(iv);

            for (uint i = 0; i < bytes_in.Length; i += blockBytesLen)
            {
                //in block
                var iBlock = in_blocks.GetRange((int)i, (int)blockBytesLen).ToArray();

                //decrypted block
                var dBlock = DecryptBlock(iBlock, key);

                //xor block
                var xBlock = XorBlocks(block.ToArray(), dBlock, blockBytesLen);
                out_blocks.AddRange(xBlock);

                //update block
                block = new List<byte>(iBlock);
            }

            return out_blocks.ToArray();
        }

        public byte[] EncryptCFB(byte[] plain, byte[] key, byte[] iv)
        {
            if (iv.Length != blockBytesLen)
                throw new Exception("IV Length Mismatch. Expected length of: " + blockBytesLen);

            uint paddedLength = GetPaddingLength((uint)plain.Length);

            var in_blocks = new List<byte>(PaddingNulls(plain, (uint)plain.Length, paddedLength));
            var out_blocks = new List<byte>();

            //setup iv
            var block = new List<byte>(iv);

            for (uint i = 0; i < paddedLength; i += blockBytesLen)
            {
                //in block
                var iBlock = in_blocks.GetRange((int)i, (int)blockBytesLen).ToArray();

                //encrypted block
                var eBlock = EncryptBlock(block.ToArray(), key);

                //xor block
                var xBlock = XorBlocks(iBlock, eBlock, blockBytesLen);
                out_blocks.AddRange(xBlock);

                //update block
                block = new List<byte>(xBlock);
            }

            return out_blocks.ToArray();
        }

        public byte[] DecryptCFB(byte[] bytes_in, byte[] key, byte[] iv)
        {
            if (iv.Length != blockBytesLen)
                throw new Exception("IV Length Mismatch. Expected length of: " + blockBytesLen);

            var in_blocks = new List<byte>(bytes_in);
            var out_blocks = new List<byte>();

            //setup iv
            var block = new List<byte>(iv);

            for (uint i = 0; i < bytes_in.Length; i += blockBytesLen)
            {
                //in block
                var iBlock = in_blocks.GetRange((int)i, (int)blockBytesLen).ToArray();

                //encrypted block
                var eBlock = EncryptBlock(block.ToArray(), key);

                //xor block
                var xBlock = XorBlocks(iBlock, eBlock, blockBytesLen);
                out_blocks.AddRange(xBlock);

                //update block
                block = new List<byte>(iBlock);
            }

            return out_blocks.ToArray();
        }

        private byte[] PaddingNulls(byte[] plain, uint plainLength, uint alignLen)
        {
            var alignIn = new byte[alignLen];
            for (var a = 0; a < plain.Length; a++)
                alignIn[a] = plain[a];
            return alignIn;
        }

        private uint GetPaddingLength(uint len)
        {
            uint lengthWithPadding = (len / blockBytesLen);
            if (len % blockBytesLen > 0)
                lengthWithPadding++;

            lengthWithPadding *= blockBytesLen;

            return lengthWithPadding;
        }

        private byte[] EncryptBlock(byte[] bytes_in, byte[] key)
        {
            byte[] w = new byte[4 * Nb * (Nr + 1)];
            KeyExpansion(key, w);

            byte[][] state = new byte[4][];
            state[0] = new byte[4];
            state[1] = new byte[4];
            state[2] = new byte[4];
            state[3] = new byte[4];

            for (var i = 0; i < 4; i++)
                for (var j = 0; j < Nb; j++)
                    state[i][j] = bytes_in[i + 4 * j];

            AddRoundKey(state, w);

            int wIndex;
            var wKey = new List<byte>(w);
            for (var round = 1; round <= Nr - 1; round++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);

                wIndex = round * 4 * Nb;
                AddRoundKey(state, wKey.GetRange(wIndex, wKey.Count - wIndex).ToArray());
            }

            SubBytes(state);
            ShiftRows(state);

            wIndex = Nr * 4 * Nb;
            AddRoundKey(state, wKey.GetRange(wIndex, wKey.Count - wIndex).ToArray());

            byte[] bytes_out = new byte[blockBytesLen];
            for (var i = 0; i < 4; i++)
                for (var j = 0; j < Nb; j++)
                    bytes_out[i + 4 * j] = state[i][j];

            return bytes_out;
        }

        private byte[] DecryptBlock(byte[] bytes_in, byte[] key)
        {
            byte[] w = new byte[4 * Nb * (Nr + 1)];
            KeyExpansion(key, w);

            byte[][] state = new byte[4][];
            state[0] = new byte[4];
            state[1] = new byte[4];
            state[2] = new byte[4];
            state[3] = new byte[4];

            for (var i = 0; i < 4; i++)
                for (var j = 0; j < Nb; j++)
                    state[i][j] = bytes_in[i + 4 * j];

            var wIndex = Nr * 4 * Nb;
            var wKey = new List<byte>(w);
            AddRoundKey(state, wKey.GetRange(wIndex, wKey.Count - wIndex).ToArray());

            for (var round = Nr - 1; round >= 1; round--)
            {
                InvSubBytes(state);
                InvShiftRows(state);

                wIndex = round * 4 * Nb;
                AddRoundKey(state, wKey.GetRange(wIndex, wKey.Count - wIndex).ToArray());
                InvMixColumns(state);
            }

            InvSubBytes(state);
            InvShiftRows(state);
            AddRoundKey(state, w);

            byte[] bytes_out = new byte[blockBytesLen];
            for (var i = 0; i < 4; i++)
                for (var j = 0; j < Nb; j++)
                    bytes_out[i + 4 * j] = state[i][j];

            return bytes_out;
        }

        private void SubBytes(byte[][] state)
        {
            byte t;
            for (var i = 0; i < 4; i++)
            {
                for (var j = 0; j < Nb; j++)
                {
                    t = state[i][j];
                    state[i][j] = sbox[t / 16, t % 16];
                }
            }
        }

        private void ShiftRow(byte[][] state, int i, int n) // shift row i on n positions
        {
            byte t;
            for (var k = 0; k < n; k++)
            {
                t = state[i][0];
                for (var j = 0; j < Nb - 1; j++)
                    state[i][j] = state[i][j + 1];

                state[i][Nb - 1] = t;
            }
        }

        private void ShiftRows(byte[][] state)
        {
            ShiftRow(state, 1, 1);
            ShiftRow(state, 2, 2);
            ShiftRow(state, 3, 3);
        }

        private byte xtime(byte b) // multiply on x
        {
            byte mask = 0x80, m = 0x1b;
            byte high_bit = (byte)(b & mask);
            b = (byte)(b << 1);
            if (high_bit > 0)
            {
                // mod m(x)
                b = (byte)(b ^ m);
            }

            return b;
        }

        private byte mul_bytes(byte a, byte b)
        {
            byte c = 0, mask = 1, bit, d;
            for (var i = 0; i < 8; i++)
            {
                bit = (byte)(b & mask);
                if (bit > 0)
                {
                    d = a;
                    for (var j = 0; j < i; j++)
                    {
                        // multiply on x^i
                        d = xtime(d);
                    }

                    c = (byte)(c ^ d); // xor to result
                }

                b = (byte)(b >> 1);
            }

            return c;
        }

        private void MixColumns(byte[][] state)
        {
            byte[] s = new byte[4], s1 = new byte[4];
            for (var j = 0; j < Nb; j++)
            {
                for (var i = 0; i < 4; i++)
                    s[i] = state[i][j];

                s1[0] = (byte)(mul_bytes(0x02, s[0]) ^ mul_bytes(0x03, s[1]) ^ s[2] ^ s[3]);
                s1[1] = (byte)(s[0] ^ mul_bytes(0x02, s[1]) ^ mul_bytes(0x03, s[2]) ^ s[3]);
                s1[2] = (byte)(s[0] ^ s[1] ^ mul_bytes(0x02, s[2]) ^ mul_bytes(0x03, s[3]));
                s1[3] = (byte)(mul_bytes(0x03, s[0]) ^ s[1] ^ s[2] ^ mul_bytes(0x02, s[3]));

                for (var i = 0; i < 4; i++)
                    state[i][j] = s1[i];
            }
        }

        private void AddRoundKey(byte[][] state, byte[] key)
        {
            for (var i = 0; i < 4; i++)
                for (var j = 0; j < Nb; j++)
                    state[i][j] = (byte)(state[i][j] ^ key[i + 4 * j]);
        }

        private void SubWord(byte[] a)
        {
            for (var i = 0; i < 4; i++)
                a[i] = sbox[a[i] / 16, a[i] % 16];
        }

        private void RotWord(byte[] a)
        {
            byte c = a[0];
            a[0] = a[1];
            a[1] = a[2];
            a[2] = a[3];
            a[3] = c;
        }

        private void XorWords(byte[] a, byte[] b, byte[] c)
        {
            for (var i = 0; i < 4; i++)
                c[i] = (byte)(a[i] ^ b[i]);
        }

        private void Rcon(byte[] a, int n)
        {
            byte c = 1;
            for (int i = 0; i < n - 1; i++)
                c = xtime(c);

            a[0] = c;
            a[1] = a[2] = a[3] = 0;
        }

        private void KeyExpansion(byte[] key, byte[] w)
        {
            byte[] temp = new byte[4];
            byte[] rcon = new byte[4];

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

                w[i + 0] = (byte)(w[i - 4 * Nk] ^ temp[0]);
                w[i + 1] = (byte)(w[i + 1 - 4 * Nk] ^ temp[1]);
                w[i + 2] = (byte)(w[i + 2 - 4 * Nk] ^ temp[2]);
                w[i + 3] = (byte)(w[i + 3 - 4 * Nk] ^ temp[3]);
                i += 4;
            }
        }

        private void InvSubBytes(byte[][] state)
        {
            byte t;
            for (var i = 0; i < 4; i++)
            {
                for (var j = 0; j < Nb; j++)
                {
                    t = state[i][j];
                    state[i][j] = inv_sbox[t / 16, t % 16];
                }
            }
        }

        private void InvMixColumns(byte[][] state)
        {
            byte[] s = new byte[4], s1 = new byte[4];
            for (var j = 0; j < Nb; j++)
            {
                for (var i = 0; i < 4; i++)
                    s[i] = state[i][j];

                s1[0] = (byte)(mul_bytes(0x0e, s[0]) ^ mul_bytes(0x0b, s[1]) ^ mul_bytes(0x0d, s[2]) ^ mul_bytes(0x09, s[3]));
                s1[1] = (byte)(mul_bytes(0x09, s[0]) ^ mul_bytes(0x0e, s[1]) ^ mul_bytes(0x0b, s[2]) ^ mul_bytes(0x0d, s[3]));
                s1[2] = (byte)(mul_bytes(0x0d, s[0]) ^ mul_bytes(0x09, s[1]) ^ mul_bytes(0x0e, s[2]) ^ mul_bytes(0x0b, s[3]));
                s1[3] = (byte)(mul_bytes(0x0b, s[0]) ^ mul_bytes(0x0d, s[1]) ^ mul_bytes(0x09, s[2]) ^ mul_bytes(0x0e, s[3]));

                for (var i = 0; i < 4; i++)
                    state[i][j] = s1[i];
            }
        }

        private void InvShiftRows(byte[][] state)
        {
            ShiftRow(state, 1, Nb - 1);
            ShiftRow(state, 2, Nb - 2);
            ShiftRow(state, 3, Nb - 3);
        }

        private byte[] XorBlocks(byte[] a, byte[] b, uint len)
        {
            byte[] bytes = new byte[len];
            for (var i = 0; i < len; i++)
                bytes[i] = (byte)(a[i] ^ b[i]);

            return bytes;
        }

        public void printHexArray(byte[] a)
        {
            Console.WriteLine(BitConverter.ToString(a).Replace("-", " "));
        }
    }
}