all: clean build_test build_debug build_profile build_release

build_test:
	g++ -g -pthread ./src/AES.cpp ./tests/tests.cpp /usr/lib/libgtest.a -o bin/test

build_debug:
	g++ -g ./src/AES.cpp ./dev/main.cpp -o bin/debug

build_profile:
	g++ -pg ./src/AES.cpp ./dev/main.cpp -o bin/profile

build_release:
	g++ -O2 ./src/AES.cpp ./dev/main.cpp -o bin/release

clean:
	rm -rf bin 
	mkdir bin -p