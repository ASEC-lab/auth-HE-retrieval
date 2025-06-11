FROM ubuntu:22.04

# Install git, zip, python-pip, cmake, g++, zlib, libssl, libcurl, java, maven via apt
# Specify DEBIAN_FRONTEND and TZ to prevent tzdata hanging
RUN apt-get update && \
    apt-get upgrade -y && \
    DEBIAN_FRONTEND="noninteractive" TZ="America/Los_Angeles"  apt-get install -y git zip wget python3 python3-pip cmake g++ zlib1g-dev libssl-dev libcurl4-openssl-dev openjdk-8-jdk doxygen ninja-build

RUN apt install -y vim
WORKDIR root
RUN mkdir git

WORKDIR git

#in stall AWS SDK
RUN git clone --branch 1.11.280 --recurse-submodules https://github.com/aws/aws-sdk-cpp
RUN mkdir sdk_build
WORKDIR sdk_build
RUN cmake ../aws-sdk-cpp -DCMAKE_BUILD_TYPE=Release -DBUILD_ONLY="s3"
RUN make
RUN make install
WORKDIR ..

#install SEAL
RUN git clone --branch 4.1.1 https://github.com/Microsoft/SEAL.git
WORKDIR SEAL
RUN cmake . -B build -DCMAKE_INSTALL_PREFIX=native/Release -DCMAKE_BUILD_TYPE=Release
RUN cmake --build build
RUN cmake --install build
WORKDIR ../../

# install cpp rest and curses
RUN apt-get -y install libcpprest-dev
RUN apt-get -y install libncurses5-dev

#install cryptopp
RUN git clone  https://github.com/abdes/cryptopp-cmake
WORKDIR cryptopp-cmake
RUN mkdir build
WORKDIR build
RUN cmake .. -DCRYPTOPP_BUILD_TESTING=OFF
RUN make
RUN make install
WORKDIR ../../

#our application
COPY . /usr/src/authCSHER
WORKDIR /usr/src/authCSHER
RUN mkdir Release
WORKDIR Release
RUN cmake -DCMAKE_BUILD_TYPE=Release ..
RUN mkdir /tmp/out
RUN make Auxiliary_Server
RUN make Data_Owner
RUN make Destination_Server

