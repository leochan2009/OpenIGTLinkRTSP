/**********
 This library is free software; you can redistribute it and/or modify it under
 the terms of the GNU Lesser General Public License as published by the
 Free Software Foundation; either version 3 of the License, or (at your
 option) any later version. (See <http://www.gnu.org/copyleft/lesser.html>.)
 
 This library is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for
 more details.
 
 You should have received a copy of the GNU Lesser General Public License
 along with this library; if not, write to the Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 **********/
// Copyright (c) 1996-2017, Live Networks, Inc.  All rights reserved
// A demo application, showing how to create and run a RTSP client (that can potentially receive multiple streams concurrently).
//
// NOTE: This code - although it builds a running application - is intended only to illustrate how to develop your own RTSP
// client application.  For a full-featured RTSP client application - with much more functionality, and many options - see
// "openRTSP": http://www.live555.com/openRTSP/

// Forward function definitions:
#include "RTSPClient.h"
// RTSP 'response handlers':
void continueAfterDESCRIBE(RTSPClient* rtspClient, int resultCode, char* resultString);
void continueAfterSETUP(RTSPClient* rtspClient, int resultCode, char* resultString);
void continueAfterPLAY(RTSPClient* rtspClient, int resultCode, char* resultString);

// Other event handler functions:
void subsessionAfterPlaying(void* clientData); // called when a stream's subsession (e.g., audio or video substream) ends
void subsessionByeHandler(void* clientData); // called when a RTCP "BYE" is received for a subsession
void streamTimerHandler(void* clientData);
// called at the end of a stream's expected duration (if the stream has not already signaled its end using a RTCP "BYE")

// The main streaming routine (for each "rtsp://" URL):
void openURL(char const* progName, char const* rtspURL);

// Used to iterate through each stream's 'subsessions', setting up each one:
void setupNextSubsession(RTSPClient* rtspClient);

// Used to shut down and close a stream (including its "RTSPClient" object):
void shutdownStream(RTSPClient* rtspClient, int exitCode = 1);

char eventLoopWatchVariable = 0;

int main(int argc, char** argv) {
  // Begin by setting up our usage environment:
  //TaskScheduler* scheduler = BasicTaskScheduler::createNew();
  //UsageEnvironment* env = BasicUsageEnvironment::createNew(*scheduler);
  
  // We need at least one "rtsp://" URL argument:
  if (argc < 2) {
    //usage(*env, argv[0]);
    return 1;
  }
  
  // There are argc-1 URLs: argv[1] through argv[argc-1].  Open and start streaming each one:
  for (int i = 1; i <= argc-1; ++i) {
    openURL(argv[0], argv[i]);
  }
  
  // All subsequent activity takes place within the event loop:
  //env->taskScheduler().doEventLoop(&eventLoopWatchVariable);
  // This function call does not return, unless, at some point in time, "eventLoopWatchVariable" gets set to something non-zero.
  
  return 0;
  
  // If you choose to continue the application past this point (i.e., if you comment out the "return 0;" statement above),
  // and if you don't intend to do anything more with the "TaskScheduler" and "UsageEnvironment" objects,
  // then you can also reclaim the (small) memory used by these objects by uncommenting the following code:
  /*
   env->reclaim(); env = NULL;
   delete scheduler; scheduler = NULL;
   */
}

// Define a class to hold per-stream state that we maintain throughout each stream's lifetime:

class StreamClientState {
public:
  StreamClientState();
  virtual ~StreamClientState();
  
public:
  double duration;
};

// If you're streaming just a single stream (i.e., just from a single URL, once), then you can define and use just a single
// "StreamClientState" structure, as a global variable in your application.  However, because - in this demo application - we're
// showing how to play multiple streams, concurrently, we can't do that.  Instead, we have to have a separate "StreamClientState"
// structure for each "RTSPClient".  To do this, we subclass "RTSPClient", and add a "StreamClientState" field to the subclass:

class ourRTSPClient: public RTSPClient {
public:
  static ourRTSPClient* createNew(char const* rtspURL,
                                  int verbosityLevel = 0,
                                  char const* applicationName = NULL,
                                  igtl_uint16 tunnelOverHTTPPortNum = 0);
  
protected:
  ourRTSPClient(char const* rtspURL,
                int verbosityLevel, char const* applicationName, igtl_uint16 tunnelOverHTTPPortNum);
  // called only by createNew();
  virtual ~ourRTSPClient();
  
public:
  StreamClientState scs;
};

#define RTSP_CLIENT_VERBOSITY_LEVEL 1 // by default, print verbose output from each "RTSPClient"

static unsigned rtspClientCount = 0; // Counts how many streams (i.e., "RTSPClient"s) are currently in use.

void openURL(char const* progName, char const* rtspURL) {
  // Begin by creating a "RTSPClient" object.  Note that there is a separate "RTSPClient" object for each stream that we wish
  // to receive (even if more than stream uses the same "rtsp://" URL).
  RTSPClient* rtspClient = ourRTSPClient::createNew(rtspURL, RTSP_CLIENT_VERBOSITY_LEVEL, progName);
  if (rtspClient == NULL) {
    std::cerr << "Failed to create a RTSP client for URL \"" << rtspURL << "\": "<<std::endl;
    return;
  }
  
  ++rtspClientCount;
  
  // Next, send a RTSP "DESCRIBE" command, to get a SDP description for the stream.
  // Note that this command - like all RTSP commands - is sent asynchronously; we do not block, waiting for a response.
  // Instead, the following function call returns immediately, and we handle the RTSP response later, from within the event loop:
  rtspClient->sendDescribeCommand(continueAfterDESCRIBE);
}


// Implementation of the RTSP 'response handlers':

void continueAfterDESCRIBE(RTSPClient* rtspClient, int resultCode, char* resultString) {
  do {
    StreamClientState& scs = ((ourRTSPClient*)rtspClient)->scs; // alias
    
    if (resultCode != 0) {
      std::cerr << "Failed to get a SDP description: " << resultString << "\n";
      delete[] resultString;
      break;
    }
    
    char* const sdpDescription = resultString;
    std::cerr << "Got a SDP description:\n" << sdpDescription << "\n";
    
    // Create a media session object from this SDP descriptio
    
    // Then, create and set up our data source objects for the session.  We do this by iterating over the session's 'subsessions',
    // calling "MediaSubsession::initiate()", and then sending a RTSP "SETUP" command, on each one.
    // (Each 'subsession' will have its own data source.)
    setupNextSubsession(rtspClient);
    return;
  } while (0);
  
  // An unrecoverable error occurred with this stream.
  shutdownStream(rtspClient);
}

// By default, we request that the server stream its data using RTP/UDP.
// If, instead, you want to request that the server stream via RTP-over-TCP, change the following to True:
#define REQUEST_STREAMING_OVER_TCP False

void setupNextSubsession(RTSPClient* rtspClient) {
  //UsageEnvironment& env = rtspClient->envir(); // alias
  StreamClientState& scs = ((ourRTSPClient*)rtspClient)->scs; // alias
  
  /*scs.subsession = scs.iter->next();
  if (scs.subsession != NULL) {
    if (!scs.subsession->initiate()) {
      std::cerr << *rtspClient << "Failed to initiate the \"" << *scs.subsession << "\" subsession: " << env.getResultMsg() << "\n";
      setupNextSubsession(rtspClient); // give up on this subsession; go to the next one
    } else {
      std::cerr << *rtspClient << "Initiated the \"" << *scs.subsession << "\" subsession (";
      if (scs.subsession->rtcpIsMuxed()) {
        std::cerr << "client port " << scs.subsession->clientPortNum();
      } else {
        std::cerr << "client ports " << scs.subsession->clientPortNum() << "-" << scs.subsession->clientPortNum()+1;
      }
      std::cerr << ")\n";
      
      // Continue setting up this subsession, by sending a RTSP "SETUP" command:
      rtspClient->sendSetupCommand(*scs.subsession, continueAfterSETUP, False, REQUEST_STREAMING_OVER_TCP);
    }
    return;
  }
  
  // We've finished setting up all of the subsessions.  Now, send a RTSP "PLAY" command to start the streaming:
  if (scs.session->absStartTime() != NULL) {
    // Special case: The stream is indexed by 'absolute' time, so send an appropriate "PLAY" command:
    rtspClient->sendPlayCommand(*scs.session, continueAfterPLAY, scs.session->absStartTime(), scs.session->absEndTime());
  } else {
    scs.duration = scs.session->playEndTime() - scs.session->playStartTime();
    rtspClient->sendPlayCommand(*scs.session, continueAfterPLAY);
  }*/
  rtspClient->sendPlayCommand(continueAfterPLAY);
}

void continueAfterSETUP(RTSPClient* rtspClient, int resultCode, char* resultString) {
  do {
    StreamClientState& scs = ((ourRTSPClient*)rtspClient)->scs; // alias
    
    if (resultCode != 0) {
      std::cerr << rtspClient << "Failed to set up the \"" << "\" subsession: " << resultString << "\n";
      break;
    }
    
    std::cerr << rtspClient << "Set up the \"" << "\" subsession (";
    } while (0);
  delete[] resultString;
  
  // Set up the next subsession, if any:
  setupNextSubsession(rtspClient);
}

void continueAfterPLAY(RTSPClient* rtspClient, int resultCode, char* resultString) {
  bool success = false;
  
  do {
    StreamClientState& scs = ((ourRTSPClient*)rtspClient)->scs; // alias
    
    if (resultCode != 0) {
      std::cerr << rtspClient << "Failed to start playing session: " << resultString << "\n";
      break;
    }
    
    // Set a timer to be handled at the end of the stream's expected duration (if the stream does not already signal its end
    // using a RTCP "BYE").  This is optional.  If, instead, you want to keep the stream active - e.g., so you can later
    // 'seek' back within it and do another RTSP "PLAY" - then you can omit this code.
    // (Alternatively, if you don't want to receive the entire stream, you could set this timer for some shorter value.)
    if (scs.duration > 0) {
      unsigned const delaySlop = 2; // number of seconds extra to delay, after the stream's expected duration.  (This is optional.)
      scs.duration += delaySlop;
      unsigned uSecsToDelay = (unsigned)(scs.duration*1000000);
      //scs.streamTimerTask = env.taskScheduler().scheduleDelayedTask(uSecsToDelay, (TaskFunc*)streamTimerHandler, rtspClient);
    }
    
    std::cerr << "Started playing session";
    if (scs.duration > 0) {
      std::cerr << " (for up to " << scs.duration << " seconds)";
    }
    std::cerr << "...\n";
    
    success = true;
  } while (0);
  delete[] resultString;
  
  if (!success) {
    // An unrecoverable error occurred with this stream.
    shutdownStream(rtspClient);
  }
}


// Implementation of the other event handlers:

void subsessionAfterPlaying(void* clientData) {
}

void subsessionByeHandler(void* clientData) {
  std::cerr  << "Received RTCP \"BYE\" on \"" << "\" subsession\n";
  
  // Now act as if the subsession had closed:
  subsessionAfterPlaying(clientData);
}

void streamTimerHandler(void* clientData) {
  ourRTSPClient* rtspClient = (ourRTSPClient*)clientData;
  StreamClientState& scs = rtspClient->scs; // alias
  // Shut down the stream:
  shutdownStream(rtspClient);
}

void shutdownStream(RTSPClient* rtspClient, int exitCode) {
  StreamClientState& scs = ((ourRTSPClient*)rtspClient)->scs; // alias
  
  std::cerr << "Closing the stream.\n";
  // Note that this will also cause this stream's "StreamClientState" structure to get reclaimed.
}


// Implementation of "ourRTSPClient":

ourRTSPClient* ourRTSPClient::createNew( char const* rtspURL,
                                        int verbosityLevel, char const* applicationName, igtl_uint16 tunnelOverHTTPPortNum) {
  return new ourRTSPClient(rtspURL, verbosityLevel, applicationName, tunnelOverHTTPPortNum);
}

ourRTSPClient::ourRTSPClient(char const* rtspURL,
                             int verbosityLevel, char const* applicationName, igtl_uint16 tunnelOverHTTPPortNum)
: RTSPClient(rtspURL, verbosityLevel, applicationName, tunnelOverHTTPPortNum, -1) {
}

ourRTSPClient::~ourRTSPClient() {
}


// Implementation of "StreamClientState":

StreamClientState::StreamClientState()
: duration(0.0) {
}

StreamClientState::~StreamClientState() {
}


// Implementation of "DummySink":

// Even though we're not going to be doing anything with the incoming data, we still need to receive it.
// Define the size of the buffer that we'll use:

