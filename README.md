# dpdk_capture

#### Description
:copyright: dpdk capture application

#### Software Architecture
Based on dpdk-stable-19.11.14

#### Installation
none

#### Instructions
1.  Download dpdk-stable-19.11.14
2.  Set environment variables: export RTE_SDK=/home/dpdk-stable-19.11.14/,export RTE_TARGET=x86_64-native-linux-gcc
3.  Run/home/dpdk-stable-19.11.14/usertools/dpdk-setup.sh: select compilation environment,installation environment,binding network card device etc
4.  cmake . && make

#### Contribution

1.  Fork the repository
2.  Create xxx branch
3.  Commit your code
4.  Create Pull Request
