PROJECT(dpdk_capture)
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
set(DPDK_BUILD_DIR "$ENV{RTE_SDK}/$ENV{RTE_TARGET}")
set(CMAKE_CXX_FLAGS "-msse4.2 -g")

include_directories("${DPDK_BUILD_DIR}/include")
link_directories("${DPDK_BUILD_DIR}/lib")
link_directories("/usr/lib/x86_64-linux-gnu")

add_executable(dpdk_capture dpdk_capture.c)

target_link_libraries(
    dpdk_capture
    -Wl,--whole-archive 
    -ldpdk
    -Wl,--no-whole-archive 
    -lrt 
    -lm 
    -ldl 
#    -lcrypto 
    -lnuma
    -pthread
    pcap
)
