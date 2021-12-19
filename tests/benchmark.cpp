#include <iostream>
#include <benchmark/benchmark.h>

#include <iostream>
#include <chrono>
#include <random>
#include <vector>
#include "../src/Krypt.hpp"

using namespace Krypt;

#define MB(N) N*1024*1024

std::vector<unsigned char> randomArray(size_t n)
{
    unsigned seed = std::chrono::steady_clock::now().time_since_epoch().count();
    std::mt19937_64 rand_engine(seed);
    std::uniform_int_distribution<int> random_number(0,255);

    std::vector<unsigned char> randomValues;
    randomValues.reserve(n);

    for(size_t i=0; i<n; ++i)
        randomValues.push_back(static_cast<unsigned char>(random_number(rand_engine)));

    return randomValues;
}

static void AES_EncryptECB_100MB(benchmark::State& state) {

    std::vector<unsigned char> plain = randomArray(MB(2));

    // if you want to AES192 or AES256, just increase the size of the key array
    // the AES class will automatically detect it
    unsigned char aes128key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    Mode::ECB<BlockCipher::AES,Padding::ANSI_X9_23> krypt(aes128key,sizeof(aes128key));

    for (auto _ : state)
    {
        // `Krypt::Bytes` is just a typedef for `unsigned char`
        std::pair<Bytes*,size_t> cipher  = krypt.encrypt(plain.data(),plain.size());
        std::pair<Bytes*,size_t> recover = krypt.decrypt(cipher.first,cipher.second);
        delete [] cipher.first;
        delete [] recover.first;    
    }
}
BENCHMARK(AES_EncryptECB_100MB);

static void AES_EncryptCBC_100MB(benchmark::State& state) {

    std::vector<unsigned char> plain = randomArray(MB(2));

    // if you want to AES192 or AES256, just increase the size of the key array
    // the AES class will automatically detect it
    unsigned char aes128key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    unsigned char iv[] = {
        0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x16, 0x27,
        0xf8, 0x99, 0x8a, 0x7b, 0x6c, 0x5d, 0x4e, 0x3f
    };

    Mode::CBC<BlockCipher::AES,Padding::ANSI_X9_23> krypt(aes128key,sizeof(aes128key),iv);

    for (auto _ : state)
    {
        // `Krypt::Bytes` is just a typedef for `unsigned char`
        std::pair<Bytes*,size_t> cipher  = krypt.encrypt(plain.data(),plain.size());
        std::pair<Bytes*,size_t> recover = krypt.decrypt(cipher.first,cipher.second);
        delete [] cipher.first;
        delete [] recover.first;    
    }
}
BENCHMARK(AES_EncryptCBC_100MB);

static void AES_EncryptCBC(benchmark::State& state) {

    std::vector<unsigned char> plain = randomArray(MB(2));

    // if you want to AES192 or AES256, just increase the size of the key array
    // the AES class will automatically detect it
    unsigned char aes128key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    unsigned char iv[] = {
        0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x16, 0x27,
        0xf8, 0x99, 0x8a, 0x7b, 0x6c, 0x5d, 0x4e, 0x3f
    };

    Mode::CBC<BlockCipher::AES,Padding::ANSI_X9_23> krypt(aes128key,sizeof(aes128key),iv);

    for (auto _ : state)
    {
        // `Krypt::Bytes` is just a typedef for `unsigned char`
        std::pair<Bytes*,size_t> cipher  = krypt.encrypt(plain.data(),plain.size());
        std::pair<Bytes*,size_t> recover = krypt.decrypt(cipher.first,cipher.second);
        delete [] cipher.first;
        delete [] recover.first;    
    }
}
BENCHMARK(AES_EncryptCBC_100MB);

BENCHMARK_MAIN();