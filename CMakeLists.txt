cmake_minimum_required(VERSION 2.8)
project( OpenIGTLinkRTSP )

get_filename_component(PARENT_DIR ${CMAKE_CURRENT_BINARY_DIR} PATH)
set(CMAKE_PREFIX_PATH	"${PARENT_DIR}/OpenIGTLink-build")	
find_package(OpenIGTLink REQUIRED)
include(${OpenIGTLink_USE_FILE})
include_directories(${OpenIGTLink_INCLUDE_DIRS})
link_directories(${OpenIGTLink_LIBRARY_DIRS})
#-----------------------------------------------------------------------------
# Help other projects use OpenIGTLinkRTSP.

# Copy the UseOpenIGTLinkRTSP.cmake file to the binary tree for backward compatability.
CONFIGURE_FILE(${OpenIGTLinkRTSP_SOURCE_DIR}/UseOpenIGTLinkRTSP.cmake.in
${OpenIGTLinkRTSP_BINARY_DIR}/UseOpenIGTLinkRTSP.cmake COPYONLY IMMEDIATE)
message("${OpenIGTLinkRTSP_SOURCE_DIR}")
# Create the OpenIGTLinkRTSPConfig.cmake file containing the OpenIGTLinkRTSP configuration.
INCLUDE (${OpenIGTLinkRTSP_SOURCE_DIR}/GenerateOpenIGTLinkRTSPConfig.cmake)

#Add OpenH264 directly to our build.
#add_subdirectory(${PARENT_DIR}/Testing/OpenH264)
SET(OpenIGTLinkRTSP_SOURCES ${OpenIGTLinkRTSP_SOURCE_DIR}/RTSPClient.cpp ${OpenIGTLinkRTSP_SOURCE_DIR}/RTSPServer.cpp ${OpenIGTLinkRTSP_SOURCE_DIR}/RTSPCommon.cpp ${OpenIGTLinkRTSP_SOURCE_DIR}/ourMD5.cpp ${OpenIGTLinkRTSP_SOURCE_DIR}/inet.c ${OpenIGTLinkRTSP_SOURCE_DIR}/BasicHashTable.cpp)
SET(OpenIGTLinkRTSP_INCLUDES ${OpenIGTLinkRTSP_SOURCE_DIR}/NetCommon.h ${OpenIGTLinkRTSP_SOURCE_DIR}/BasicHashTable.h ${OpenIGTLinkRTSP_SOURCE_DIR}/RTSPClient.h ${OpenIGTLinkRTSP_SOURCE_DIR}/RTSPCommon.h ${OpenIGTLinkRTSP_SOURCE_DIR}/RTSPServer.h)
message("${OpenIGTLink_INCLUDE_DIRS}")
SET(OpenIGTLinkRTSP_INCLUDE_DIRS
	${OpenIGTLinkRTSP_INCLUDE_DIRS}
  ${OpenIGTLinkRTSP_SOURCE_DIR}
  ${OpenIGTLink_INCLUDE_DIRS}
)
INCLUDE_DIRECTORIES(${OpenIGTLinkRTSP_INCLUDE_DIRS})

SET(OpenIGTLinkRTSP_LIBRARY_PATH ${OpenIGTLinkRTSP_BINARY_DIR} CACHE INTERNAL "Single output directory for building all libraries.")
SET(OpenIGTLinkRTSP_INCLUDE_PATH ${OpenIGTLinkRTSP_INCLUDE_DIRS} CACHE INTERNAL "Include path for project that uses OpenIGTLinkRTSP.")
add_library( OpenIGTLinkRTSP ${OpenIGTLinkRTSP_SOURCES} ${OpenIGTLinkRTSP_INCLUDES})
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  SET(LINK_OPENIGTLINK_LIBRARY optimized ${OpenIGTLink_LIBRARY_DIRS}/Release/OpenIGTLink.lib debug ${OpenIGTLink_LIBRARY_DIRS}/Debug/OpenIGTLink.lib)
  SET(LINK_OPENIGTLINK_UTIL_LIBRARY optimized ${OpenIGTLink_LIBRARY_DIRS}/Release/igtlutil.lib debug ${OpenIGTLink_LIBRARY_DIRS}/Debug/igtlutil.lib)
  target_link_libraries( OpenIGTLinkRTSP  ${LINK_OPENIGTLINK_LIBRARY} ${LINK_OPENIGTLINK_UTIL_LIBRARY})
  SET(LINK_OPENIGTLINKRTSP_LIBRARY optimized ${OpenIGTLinkRTSP_BINARY_DIR}/Release/OpenIGTLinkRTSP.lib debug ${OpenIGTLinkRTSP_BINARY_DIR}/Debug/OpenIGTLinkRTSP.lib)
  SET(OpenIGTLinkRTSP_LIBRARIES ${LINK_OPENIGTLINKRTSP_LIBRARY} ${LINK_OPENIGTLINK_LIBRARY} ${LINK_OPENIGTLINK_UTIL_LIBRARY} CACHE INTERNAL "a collection of all video streaming libraries.")
else(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  SET(LINK_OPENIGTLINK_LIBRARY optimized ${OpenIGTLink_LIBRARY_DIRS}/Release/libOpenIGTLink.a debug ${OpenIGTLink_LIBRARY_DIRS}/Debug/libOpenIGTLink.a)
  SET(LINK_OPENIGTLINK_UTIL_LIBRARY optimized ${OpenIGTLink_LIBRARY_DIRS}/Release/libigtlutil.a debug ${OpenIGTLink_LIBRARY_DIRS}/Debug/libigtlutil.a)
  target_link_libraries( OpenIGTLinkRTSP ${LINK_OPENIGTLINK_LIBRARY} ${LINK_OPENIGTLINK_UTIL_LIBRARY})
  SET(LINK_OPENIGTLINKRTSP_LIBRARY optimized ${OpenIGTLinkRTSP_BINARY_DIR}/Release/libOpenIGTLinkRTSP.a debug ${OpenIGTLinkRTSP_BINARY_DIR}/Debug/libOpenIGTLinkRTSP.a)
  SET(OpenIGTLinkRTSP_LIBRARIES ${LINK_OPENIGTLINKRTSP_LIBRARY} ${LINK_OPENIGTLINK_LIBRARY} ${LINK_OPENIGTLINK_UTIL_LIBRARY}  CACHE INTERNAL "a collection of all video streaming libraries.")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_subdirectory(testPrograms)
