#ifndef _AES_H_
#define _AES_H_

class AES
{
private:
	int Nb;
	int Nk;
	int Nr;

	void SubBytes(unsigned char **state);

    void ShiftRow(unsigned char **state, int i, int n);    // shift row i on n positions 

    void ShiftRows(unsigned char **state);

    unsigned char xtime(unsigned char b);    // multiply on x

    unsigned char mul_bytes(unsigned char a, unsigned char b);

    void MixColumns(unsigned char **state);

    void AddRoundKey(unsigned char **state, unsigned char *key);

    unsigned char * SubWord(unsigned char b[]);

    unsigned char *RotWord(unsigned char b[]);

    unsigned char * XorWords(unsigned char a[], unsigned char b[]);

    unsigned char *Rcon(int n);

    void InvSubBytes(unsigned char **state);

    void InvMixColumns(unsigned char **state);

    void InvShiftRows(unsigned char **state);
	
	void KeyExpansion(unsigned char key[], unsigned char w[]);

public: 
	AES(int keyLen);

	void AES_Enc(unsigned char in[], unsigned char out[], unsigned  char key[]);

    void AES_Dec(unsigned char in[], unsigned char out[], unsigned  char key[]);
};

#endif