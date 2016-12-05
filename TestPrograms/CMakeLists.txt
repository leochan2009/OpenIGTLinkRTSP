PROJECT(RTSPDemo)

cmake_minimum_required(VERSION 2.4)
if(COMMAND cmake_policy)
  cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)
set(CMAKE_PREFIX_PATH	"${OpenIGTLinkRTSP_BINARY_DIR}")
find_package(OpenIGTLinkRTSP REQUIRED)

include(${OpenIGTLinkRTSP_USE_FILE})

ADD_EXECUTABLE(RTSPClientDemo   RTSPClientDemo.cpp)
TARGET_LINK_LIBRARIES(RTSPClientDemo OpenIGTLinkRTSP)

ADD_EXECUTABLE(RTSPServerDemo   RTSPServerDemo.cpp)
TARGET_LINK_LIBRARIES(RTSPServerDemo OpenIGTLinkRTSP)



