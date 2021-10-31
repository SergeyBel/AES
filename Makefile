FLAGS = -Wall -Wextra -std=c++11

all: clean build_test build_debug build_profile build_release

build_test:
	g++ $(FLAGS) -g -pthread ./tests/tests.cpp /usr/lib/libgtest.a -o bin/test

build_debug:
	g++ $(FLAGS) -g ./dev/main.cpp -o bin/debug

build_profile:
	g++ $(FLAGS) -pg ./dev/main.cpp -o bin/profile

build_release:
	g++ $(FLAGS) -O2 ./dev/main.cpp -o bin/release

clean:
	rm -rf bin 
	mkdir bin -p