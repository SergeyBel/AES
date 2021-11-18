########################## DOCKER ##########################

FLAGS = -Wall -Wextra

build_all: clean build_test build_debug build_profile build_release

build_test:
	docker-compose exec aes g++ $(FLAGS) -g -pthread ./src/AES.cpp ./tests/tests.cpp /usr/lib/libgtest.a -o bin/test

build_debug:
	docker-compose exec aes g++ $(FLAGS) -g ./src/AES.cpp ./dev/main.cpp -o bin/debug

build_profile:
	docker-compose exec aes g++ $(FLAGS) -pg ./src/AES.cpp ./dev/main.cpp -o bin/profile

build_release:
	docker-compose exec aes g++ $(FLAGS) -O2 ./src/AES.cpp ./dev/main.cpp -o bin/release

test:
	docker-compose exec aes bin/test

debug:
	docker-compose exec aes bin/debug

profile:
	docker-compose exec aes bin/profile

release:
	docker-compose exec aes bin/release

clean:
	docker-compose exec aes rm -rf bin 
	docker-compose exec aes mkdir bin -p

########################## CLASSIC MAKEFILE ##########################

compile_all: clean compile_test compile_debug compile_profile compile_release

compile_test:
	g++ $(FLAGS) -g ./tests/tests.cpp -D CLASSIC_MAKE -lgtest -lpthread -o bin/test

compile_debug:
	g++ $(FLAGS) -g ./dev/main.cpp -o bin/debug

compile_profile:
	g++ $(FLAGS) -pg ./dev/main.cpp -o bin/profile

compile_release:
	g++ $(FLAGS) -O2 ./dev/main.cpp -o bin/release

run_test:
	bin/test

run_debug:
	bin/debug

run_profile:
	bin/profile

run_release:
	bin/release

run_clean:
	rm -rf bin
	mkdir bin -p
