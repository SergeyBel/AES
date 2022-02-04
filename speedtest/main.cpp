#include <iostream>
#include <sys/time.h>
#include <ctime>
#include "../src/AES.h"

const unsigned int MICROSECONDS = 1000000;
unsigned long getMicroseconds()
{
  struct timeval tv;
  gettimeofday(&tv,NULL);
  return MICROSECONDS * tv.tv_sec + tv.tv_usec; 
}

unsigned char * getRandomPlain(unsigned int length)
{
  unsigned char *plain = new unsigned char[length];
  for (unsigned int i = 0; i < length; i++) {
    plain[i] = rand() % 256;
  }

  return plain;

}

int main()
{
  const unsigned int MEGABYTE = 1024 * 1024 * sizeof(unsigned char);

  unsigned int megabytesCount = 10;
  unsigned int plainLength = megabytesCount * MEGABYTE;
  unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

  std::cout << "Start speedtest" << std::endl;
  srand(std::time(nullptr));

  unsigned char *plain = getRandomPlain(plainLength);
  
  AES aes(AESKeyLength::AES_256);
  unsigned long start = getMicroseconds();
  unsigned char *out = aes.EncryptECB(plain, plainLength, key);
  unsigned long delta = getMicroseconds() - start;

  double speed = (double)megabytesCount / delta * MICROSECONDS;

  printf("%.2f Mb/s\n", speed);

  delete[] plain;
  delete[] out;

  return 0;
}