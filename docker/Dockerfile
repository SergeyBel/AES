FROM ubuntu:latest

ENV TZ=Europe/London 

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone && \
    apt-get update && \
    apt-get install -y build-essential libgtest-dev cmake gdb binutils clang-format  && \
    cd /usr/src/gtest && \
    cmake CMakeLists.txt && \
    make && \
    cp lib/*.a /usr/lib

WORKDIR /app

ENTRYPOINT bash
