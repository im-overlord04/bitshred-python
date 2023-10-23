
FROM ubuntu:14.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install --no-install-recommends -y wget git automake libtool make cmake gcc g++ pkg-config libmagic-dev \
    tar unzip libglib2.0-0 libssl-dev libdb-dev
RUN ld -v
ARG GIT_SSL_NO_VERIFY=1
RUN apt install -y automake1.11 
RUN apt-get install -y binutils-dev
COPY bitshred/bitshred_single_steps bitshred_single_steps
RUN cd bitshred_single_steps/ && ./configure && make
COPY bitshred/bitshred_single bitshred_single
RUN cd bitshred_single/ && ./configure && make
COPY bitshred/bitshred_openmp bitshred_openmp
RUN cd bitshred_openmp/ && make
WORKDIR /

