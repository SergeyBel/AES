# AES
C++ AES(Advanced Encryption Standard) implementation  
 
![Build Status](https://github.com/SergeyBel/AES/actions/workflows/aes-ci.yml/badge.svg?branch=master)

# Usage

**This class is very simple to use:**
```c++
...
unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; //plaintext example
unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; //key example
unsigned int plainLen = 16 * sizeof(unsigned char);  //bytes in plaintext

AES aes(AESKeyLength::AES_128);  ////128 - key length, can be 128, 192 or 256
c = aes.EncryptECB(plain, plainLen, key);
//now variable c contains plainLen bytes - ciphertext
...
```
Or for vectors:
```c++
...


vector<unsigned char> plain = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; //plaintext example
vector<unsigned char> key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; //key example

AES aes(AESKeyLength::AES_128);
c = aes.EncryptECB(plain, key);
//now vector c contains ciphertext
...
```
ECB, CBC, CFB modes are supported.




# Padding
This library does not provide any padding because padding is not part of AES standard. Plaintext and ciphertext length in bytes must be divisible by 16. If length doesn't satisfy this condition exception will be thrown


# Links


* [Wiki](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
* [NIST](https://www.nist.gov/publications/advanced-encryption-standard-aes)

# Development:

## Docker

1. `git clone https://github.com/SergeyBel/AES.git`
2. `docker-compose build`
3. `docker-compose up -d`
4. use make commands

There are four executables in `bin` folder:  
* `test` - run tests  
* `debug` - version for debugging (main code will be taken from dev/main.cpp)  
* `profile` - version for profiling with gprof (main code will be taken from dev/main.cpp)  
* `speedtest` - performance speed test (main code will be taken from speedtest/main.cpp)
* `release` - version with optimization (main code will be taken from dev/main.cpp)  


## Native

AES supports either Make or CMake as build systems.
For both, you need to install [`gtest`](https://github.com/google/googletest) before.

### Make

Build commands:  
* `make build_all` - build all targets
* `make build_test` - build `test` target
* `make build_debug` - build `debug` target
* `make build_profile` - build `profile` target
* `make build_speed_test` - build `speedtest` target
* `make build_release` - build `release` target
* `make style_fix` - fix code style
* `make test` - run tests
* `make debug` - run debug version
* `make profile` - run profile version
* `make speed_test` - run performance speed test
* `make release` - run `release` version
* `make clean` - clean `bin` directory

### CMake

#### Build
```bash
mkdir build && cd build
cmake .. && make -j
```

#### Run tests
1. Navigate into the `build` directory created in the [Build](#build) section
2. Run `ctest`

#### Include AES into your CMake projects
1. Download this repository. It is recommended to create a directory `external` or similar in which external projects
can be copied. It is further recommended to use gitmodules if you are using git as version control:
```bash
mkdir external
git submodule add https://github.com/SergejBel/AES external/AES
```
2. Add AES to your CMake project. Within your root `CMakeLists.txt` add the following code before using AES:
```cmake
# your intro...

include_directories(external/AES/src)
add_subdirectory(external/AES)

# your builds...
```
3. Link your builds against AES
```cmake
add_executable(your_executable your_executable.cpp)
target_link_libraries(your_executable PRIVATE AES)
```