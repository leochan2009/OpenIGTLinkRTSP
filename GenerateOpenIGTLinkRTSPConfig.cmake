# Generate the VideoStreamOpenIGTLinkConfig.cmake file in the build tree.  Also configure
# one for installation.  The file tells external projects how to use
# OpenIGTLinkRTSP.

#-----------------------------------------------------------------------------
# Settings specific to the build tree.

# The "use" file.
SET(OpenIGTLinkRTSP_USE_FILE ${OpenIGTLinkRTSP_BINARY_DIR}/UseOpenIGTLinkRTSP.cmake)

# Library directory.
SET(OpenIGTLinkRTSP_LIBRARY_DIRS_CONFIG ${OpenIGTLinkRTSP_LIBRARY_PATH})

# Determine the include directories needed.
SET(OpenIGTLinkRTSP_INCLUDE_DIRS_CONFIG
  ${OpenIGTLinkRTSP_INCLUDE_PATH}
)
# Libraries.
SET(OpenIGTLinkRTSP_LIBRARIES_CONFIG ${OpenIGTLinkRTSP_LIBRARIES})


#-----------------------------------------------------------------------------
# Configure OpenIGTLinkConfig.cmake for the build tree.
CONFIGURE_FILE(${OpenIGTLinkRTSP_SOURCE_DIR}/OpenIGTLinkRTSPConfig.cmake.in
               ${OpenIGTLinkRTSP_BINARY_DIR}/OpenIGTLinkRTSPConfig.cmake @ONLY IMMEDIATE)
