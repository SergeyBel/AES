FLAGS = -Wall -Wextra

build_all: clean build_test build_debug build_profile build_release build_speed_test

build_test:
	docker-compose exec aes g++ $(FLAGS) -g -pthread ./src/AES.cpp ./tests/tests.cpp /usr/lib/libgtest.a -o bin/test

build_debug:
	docker-compose exec aes g++ $(FLAGS) -g ./src/AES.cpp ./dev/main.cpp -o bin/debug

build_profile:
	docker-compose exec aes g++ $(FLAGS) -pg ./src/AES.cpp ./dev/main.cpp -o bin/profile

build_speed_test:
	docker-compose exec aes g++ $(FLAGS) -O2 ./src/AES.cpp ./speedtest/main.cpp -o bin/speedtest

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

speed_test:
	docker-compose exec aes bin/speedtest

style_fix:
	docker-compose exec aes bash -c "clang-format -i src/*.cpp src/*.h tests/*.cpp"

clean:
	docker-compose exec aes rm -rf bin/*


workflow_build_test:
	g++ $(FLAGS) -g -pthread ./src/AES.cpp ./tests/tests.cpp /usr/lib/libgtest.a -o bin/test

workflow_build_speed_test:
	g++ $(FLAGS) -O2 ./src/AES.cpp ./speedtest/main.cpp -o bin/speedtest	

