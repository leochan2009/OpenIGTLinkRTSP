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
// A test program that streams a MP3 file via RTP/RTCP
// main program

// To stream using 'ADUs' rather than raw MP3 frames, uncomment the following:
//#define STREAM_USING_ADUS 1
// To also reorder ADUs before streaming, uncomment the following:
//#define INTERLEAVE_ADUS 1
// (For more information about ADUs and interleaving,
//  see <http://www.live555.com/rtp-mp3/>)

// To stream using "source-specific multicast" (SSM), uncomment the following:
//#define USE_SSM 1

bool const isSSM = false;

// To set up an internal RTSP server, uncomment the following:
//#define IMPLEMENT_RTSP_SERVER 1
// (Note that this RTSP server works for multicast only)


// A structure to hold the state of the current session.
// It is used in the "afterPlaying()" function to clean up the session.
/*struct sessionState_t {
  FramedSource* source;
  RTPSink* sink;
  RTCPInstance* rtcpInstance;
  Groupsock* rtpGroupsock;
  Groupsock* rtcpGroupsock;
} sessionState;
*/

#include "RTSPServer.h"
char const* inputFileName = "test.mp3";
using igtl::Port;

void play(); // forward

int main(int argc, char** argv) {
  // Begin by setting up our usage environment:
  //TaskScheduler* scheduler = BasicTaskScheduler::createNew();
  //env = BasicUsageEnvironment::createNew(*scheduler);

  // Create 'groupsocks' for RTP and RTCP:
  char const* destinationAddressStr = "127.0.0.1";
  // Note: This is a multicast address.  If you wish to stream using
  // unicast instead, then replace this string with the unicast address
  // of the (single) destination.  (You may also need to make a similar
  // change to the receiver program.)
  const unsigned short rtpPortNum = 6666;
  const unsigned short rtcpPortNum = rtpPortNum+1;
  const unsigned char ttl = 1; // low, in case routers don't admin scope

  struct in_addr destinationAddress;
  destinationAddress.s_addr = inet_addr(destinationAddressStr);
  const Port rtpPort(rtpPortNum);
  const Port rtcpPort(rtcpPortNum);

  // Note: This starts RTCP running automatically
  igtl::UserAuthenticationDatabase* authDatabase = new igtl::UserAuthenticationDatabase();
  unsigned reclamationSecond =1.0;
  igtl::RTSPServer* rtspServer = new igtl::RTSPServer(rtpPort,authDatabase,reclamationSecond);
  // Note that this (attempts to) start a server on the default RTSP server
  // port: 554.  To use a different port number, add it as an extra
  // (optional) parameter to the "RTSPServer::createNew()" call above.
  if (rtspServer == NULL) {
    std::cerr << "Failed to create RTSP server: " << "\n";
    exit(1);
  }
  //ServerMediaSession* sms
  //  = ServerMediaSession::createNew(*env, "testStream", inputFileName,
	//	"Session streamed by \"testMP3Streamer\"", isSSM);
  //sms->addSubsession(PassiveServerMediaSubsession::createNew(*sessionState.sink, sessionState.rtcpInstance));
  //rtspServer->addServerMediaSession(sms);

  char* url = rtspServer->rtspURL();
  std::cerr << "Play this stream using the URL \"" << url << "\"\n";
  delete[] url;

  play();

  //env->taskScheduler().doEventLoop(); // does not return
  return 0; // only to prevent compiler warning
}

void afterPlaying(void* clientData); // forward

void play() {
  // Open the file as a 'MP3 file source':
  //sessionState.source = MP3FileSource::createNew(*env, inputFileName);
  if (1) {
    std::cerr << "Unable to open file \"" << inputFileName
	 << "\" as a MP3 file source\n";
    exit(1);
  }
}


void afterPlaying(void* /*clientData*/) {
  std::cerr << "...done streaming\n";

  //sessionState.sink->stopPlaying();

  // End this loop by closing the current source:
  //Medium::close(sessionState.source);

  // And start another loop:
  play();
}
