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
// "liveMedia"
// Copyright (c) 1996-2017 Live Networks, Inc.  All rights reserved.
// A generic media server class, used to implement a RTSP server, and any other server that uses
//  "ServerMediaSession" objects to describe media to be served.
// C++ header

/*=========================================================================

  Program:   The OpenIGTLink Library
  Language:  C++
  Web page:  http://openigtlink.org/

  Copyright (c) Insight Software Consortium. All rights reserved.

  This software is distributed WITHOUT ANY WARRANTY; without even
  the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
  PURPOSE.  See the above copyright notices for more information.

=========================================================================*/

#ifndef __igtlRTSPServer_h
#define __igtlRTSPServer_h

#include <string>

#include "igtlObject.h"
#include "igtlMacro.h"
#include "igtlMath.h"
#include "igtlMessageBase.h"
#include "igtlConditionVariable.h"
#include "igtlMutexLock.h"
#include "igtlServerSocket.h"
#include "igtl_header.h"
#include "igtl_util.h"
#include "BasicHashTable.h"
#include "RTSPCommon.h"


#if defined(WIN32) || defined(_WIN32)
#include <windows.h>
#else
#include <sys/time.h>
#include <sys/fcntl.h>
#endif
#ifndef REQUEST_BUFFER_SIZE
#define REQUEST_BUFFER_SIZE 20000 // for incoming requests
#endif
#ifndef RESPONSE_BUFFER_SIZE
#define RESPONSE_BUFFER_SIZE 20000
#endif

namespace igtl
{
  
  char* strDup(char const* str);
  
  char* strDupSize(char const* str, size_t& resultBufSize);
  
  char* strDupSize(char const* str);
  
  static char base64DecodeTable[256];
  
  static void initBase64DecodeTable();
  
  unsigned char* base64Decode(char const* in, unsigned inSize,
                              unsigned& resultSize,
                              bool trimTrailingZeros);
  unsigned char* base64Decode(char const* in, unsigned& resultSize,
                              bool trimTrailingZeros);
  
  static const char base64Char[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  
  char* base64Encode(char const* origSigned, unsigned origLength);
  
  char const* dateHeader();
  
// A data structure used for optional user/password authentication:
  
  // A mechanism for displaying an IPv4 address in ASCII.  This is intended to replace "inet_ntoa()", which is not thread-safe.
  class IGTLCommon_EXPORT AddressString {
  public:
    AddressString(struct sockaddr_in const& addr);
    AddressString(struct in_addr const& addr);
    AddressString(igtl_uint32 addr); // "addr" is assumed to be in host byte order here
    
    virtual ~AddressString();
    
    char const* val() const { return fVal; }
    
  private:
    void init(igtl_uint32 addr); // used to implement each of the constructors
    
  private:
    char* fVal; // The result ASCII string: allocated by the constructor; deleted by the destructor
  };
  
  class IGTLCommon_EXPORT Port {
  public:
    Port(igtl_uint16 num /* in host byte order */)
    {fPortNum = htons(num);};
    
    igtl_uint16 num() const { return fPortNum; } // in network byte order
    
  private:
    igtl_uint16 fPortNum; // stored in network byte order
  #ifdef IRIX
    igtl_uint16 filler; // hack to overcome a bug in IRIX C++ compiler
  #endif
  };
    
  class IGTLCommon_EXPORT UserAuthenticationDatabase {
  public:
    UserAuthenticationDatabase(char const* realm = NULL,
                               bool passwordsAreMD5 = false);
    // If "passwordsAreMD5" is True, then each password stored into, or removed from,
    // the database is actually the value computed
    // by md5(<username>:<realm>:<actual-password>)
    virtual ~UserAuthenticationDatabase();
    
    virtual void addUserRecord(char const* username, char const* password);
    virtual void removeUserRecord(char const* username);
    
    virtual char const* lookupPassword(char const* username);
    // returns NULL if the user name was not present
    
    char const* realm() { return fRealm; }
    bool passwordsAreMD5() { return fPasswordsAreMD5; }
    
  protected:
    BasicHashTable* fTable;
    char* fRealm;
    bool fPasswordsAreMD5;
  };
    
  
  // A class used for digest authentication.
  // The "realm", and "nonce" fields are supplied by the server
  // (in a "401 Unauthorized" response).
  // The "username" and "password" fields are supplied by the client.
  class IGTLCommon_EXPORT Authenticator {
  public:
    Authenticator();
    Authenticator(char const* username, char const* password, bool passwordIsMD5 = false);
    // If "passwordIsMD5" is True, then "password" is actually the value computed
    // by md5(<username>:<realm>:<actual-password>)
    Authenticator(const Authenticator& orig);
    Authenticator& operator=(const Authenticator& rightSide);
    bool operator<(const Authenticator* rightSide);
    virtual ~Authenticator();
    
    void reset();
    void setRealmAndNonce(char const* realm, char const* nonce);
    void setRealmAndRandomNonce(char const* realm);
    // as above, except that the nonce is created randomly.
    // (This is used by servers.)
    void setUsernameAndPassword(char const* username, char const* password, bool passwordIsMD5 = false);
    // If "passwordIsMD5" is True, then "password" is actually the value computed
    // by md5(<username>:<realm>:<actual-password>)
    
    char const* realm() const { return fRealm; }
    char const* nonce() const { return fNonce; }
    char const* username() const { return fUsername; }
    char const* password() const { return fPassword; }
    
    char const* computeDigestResponse(char const* cmd, char const* url) const;
    // The returned string from this function must later be freed by calling:
    void reclaimDigestResponse(char const* responseStr) const;
    
  private:
    void resetRealmAndNonce();
    void resetUsernameAndPassword();
    void assignRealmAndNonce(char const* realm, char const* nonce);
    void assignUsernameAndPassword(char const* username, char const* password, bool passwordIsMD5);
    void assign(char const* realm, char const* nonce,
                char const* username, char const* password, bool passwordIsMD5);
    
  private:
    char* fRealm; char* fNonce;
    char* fUsername; char* fPassword;
    bool fPasswordIsMD5;
  };

    

class IGTLCommon_EXPORT RTSPServer: public Object
{
public:
  typedef RTSPServer              Self;
  typedef Object               Superclass;
  typedef SmartPointer<Self>        Pointer;
  typedef SmartPointer<const Self>  ConstPointer;

  igtlTypeMacro(igtl::RTSPServer, Object)
  RTSPServer* createNew(Port ourPort = 554,
                               UserAuthenticationDatabase* authDatabase = NULL,
                               unsigned reclamationSeconds = 65);
  
  int setUpOurSocket(Port& ourPort);
  
  RTSPServer(Port ourPort,
             UserAuthenticationDatabase* authDatabase,
             unsigned reclamationSeconds);
  ~RTSPServer();

  // If ourPort.num() == 0, we'll choose the port number
  // Note: The caller is responsible for reclaiming "authDatabase"
  // If "reclamationSeconds" > 0, then the "RTSPClientSession" state for
  //     each client will get reclaimed (and the corresponding RTP stream(s)
  //     torn down) if no RTSP commands - or RTCP "RR" packets - from the
  //     client are received in at least "reclamationSeconds" seconds.
  
  static bool lookupByName(char const* name, RTSPServer*& resultServer);
  
  typedef void (responseHandlerForREGISTER)(RTSPServer* rtspServer, unsigned requestId, int resultCode, char* resultString);
  unsigned registerStream(char const* remoteClientNameOrAddress, igtl_uint16 remoteClientPortNum,
                          responseHandlerForREGISTER* responseHandler,
                          char const* username = NULL, char const* password = NULL,
                          bool receiveOurStreamViaTCP = false,
                          char const* proxyURLSuffix = NULL);
  // 'Register' the stream represented by "serverMediaSession" with the given remote client (specifed by name and port number).
  // This is done using our custom "REGISTER" RTSP command.
  // The function returns a unique number that can be used to identify the request; this number is also passed to "responseHandler".
  // When a response is received from the remote client (or the "REGISTER" request fails), the specified response handler
  //   (if non-NULL) is called.  (Note that the "resultString" passed to the handler was dynamically allocated,
  //   and should be delete[]d by the handler after use.)
  // If "receiveOurStreamViaTCP" is True, then we're requesting that the remote client access our stream using RTP/RTCP-over-TCP.
  //   (Otherwise, the remote client may choose regular RTP/RTCP-over-UDP streaming.)
  // "proxyURLSuffix" (optional) is used only when the remote client is also a proxy server.
  //   It tells the proxy server the suffix that it should use in its "rtsp://" URL (when front-end clients access the stream)
  
  typedef void (responseHandlerForDEREGISTER)(RTSPServer* rtspServer, unsigned requestId, int resultCode, char* resultString);
  unsigned deregisterStream(char const* remoteClientNameOrAddress, igtl_uint16 remoteClientPortNum,
                            responseHandlerForDEREGISTER* responseHandler,
                            char const* username = NULL, char const* password = NULL,
                            char const* proxyURLSuffix = NULL);
  // Used to turn off a previous "registerStream()" - using our custom "DEREGISTER" RTSP command.
  
  char* rtspURL(int clientSocket = -1) const;
  // returns a "rtsp://" URL that could be used to access the
  // specified session (which must already have been added to
  // us using "addServerMediaSession()".
  // This string is dynamically allocated; caller should delete[]
  // (If "clientSocket" is non-negative, then it is used (by calling "getsockname()") to determine
  //  the IP address to be used in the URL.)
  char* rtspURLPrefix(int clientSocket = -1) const;
  // like "rtspURL()", except that it returns just the common prefix used by
  // each session's "rtsp://" URL.
  // This string is dynamically allocated; caller should delete[]
  
  UserAuthenticationDatabase* setAuthenticationDatabase(UserAuthenticationDatabase* newDB);
  // Changes the server's authentication database to "newDB", returning a pointer to the old database (if there was one).
  // "newDB" may be NULL (you can use this to disable authentication at runtime, if desired).
  
  void disableStreamingRTPOverTCP() {
    fAllowStreamingRTPOverTCP = false;
  }
  
  bool setUpTunnelingOverHTTP(Port httpPort);
  // (Attempts to) enable RTSP-over-HTTP tunneling on the specified port.
  // Returns True iff the specified port can be used in this way (i.e., it's not already being used for a separate HTTP server).
  // Note: RTSP-over-HTTP tunneling is described in
  //  http://mirror.informatimago.com/next/developer.apple.com/quicktime/icefloe/dispatch028.html
  //  and http://images.apple.com/br/quicktime/pdf/QTSS_Modules.pdf
  igtl_uint16 httpServerPortNum() const; // in host byte order.  (Returns 0 if not present.)
  
protected:
  
  virtual char const* allowedCommandNames(); // used to implement "RTSPClientConnection::handleCmd_OPTIONS()"
  virtual bool weImplementREGISTER(char const* cmd/*"REGISTER" or "DEREGISTER"*/,
                                   char const* proxyURLSuffix, char*& responseStr){return false;};
  // used to implement "RTSPClientConnection::handleCmd_REGISTER()"
  // Note: "responseStr" is dynamically allocated (or NULL), and should be delete[]d after the call
  virtual void implementCmd_REGISTER(char const* cmd/*"REGISTER" or "DEREGISTER"*/,
                                     char const* url, char const* urlSuffix, int socketToRemoteServer,
                                     bool deliverViaTCP, char const* proxyURLSuffix){};
  // used to implement "RTSPClientConnection::handleCmd_REGISTER()"
  
  virtual UserAuthenticationDatabase* getAuthenticationDatabaseForCommand(char const* cmdName);
  virtual bool specialClientAccessCheck(int clientSocket, struct sockaddr_in& clientAddr,
                                        char const* urlSuffix);
  // a hook that allows subclassed servers to do server-specific access checking
  // on each client (e.g., based on client IP address), without using digest authentication.
  virtual bool specialClientUserAccessCheck(int clientSocket, struct sockaddr_in& clientAddr,
                                               char const* urlSuffix, char const *username);
  // another hook that allows subclassed servers to do server-specific access checking
  // - this time after normal digest authentication has already taken place (and would otherwise allow access).
  // (This test can only be used to further restrict access, not to grant additional access.)
  
private: // redefined virtual functions
  virtual bool isRTSPServer() const;
  
public: // should be protected, but some old compilers complain otherwise
  // The state of a TCP connection used by a RTSP client:
  class RTSPClientSession; // forward
  class IGTLCommon_EXPORT RTSPClientConnection {
  public:
    // A data structure that's used to implement the "REGISTER" command:
    class ParamsForREGISTER {
      public:
        ParamsForREGISTER(char const* cmd/*"REGISTER" or "DEREGISTER"*/,
                          RTSPClientConnection* ourConnection, char const* url, char const* urlSuffix,
                          bool reuseConnection, bool deliverViaTCP, char const* proxyURLSuffix);
        virtual ~ParamsForREGISTER();
      private:
        friend class RTSPClientConnection;
        char const* fCmd;
        RTSPClientConnection* fOurConnection;
        char* fURL;
        char* fURLSuffix;
        bool fReuseConnection, fDeliverViaTCP;
        char* fProxyURLSuffix;
    };
  protected: // redefined virtual functions:
    virtual void handleRequestBytes(int newBytesRead);
    
  protected:
    RTSPClientConnection(RTSPServer& ourServer, int clientSocket, struct sockaddr_in clientAddr);
    virtual ~RTSPClientConnection();
    
    void closeSockets(){};
    
    static void incomingRequestHandler(void*, int /*mask*/);
    void incomingRequestHandler();
    void resetRequestBuffer();
    
  protected:
    friend class GenericMediaServer;
    friend class ClientSession;
    friend class RTSPServer; // needed to make some broken Windows compilers work; remove this in the future when we end support for Windows
    int fOurSocket;
    struct sockaddr_in fClientAddr;
    unsigned char fRequestBuffer[REQUEST_BUFFER_SIZE];
    unsigned char fResponseBuffer[RESPONSE_BUFFER_SIZE];
    unsigned fRequestBytesAlreadySeen, fRequestBufferBytesLeft;
    
    friend class RTSPServer;
    friend class RTSPClientSession;
    
    // Make the handler functions for each command virtual, to allow subclasses to reimplement them, if necessary:
    virtual void handleCmd_OPTIONS();
    // You probably won't need to subclass/reimplement this function; reimplement "RTSPServer::allowedCommandNames()" instead.
    virtual void handleCmd_GET_PARAMETER(char const* fullRequestStr); // when operating on the entire server
    virtual void handleCmd_SET_PARAMETER(char const* fullRequestStr); // when operating on the entire server
    virtual void handleCmd_DESCRIBE(char const* urlPreSuffix, char const* urlSuffix, char const* fullRequestStr);
    virtual void handleCmd_REGISTER(char const* cmd/*"REGISTER" or "DEREGISTER"*/,
                                    char const* url, char const* urlSuffix, char const* fullRequestStr,
                                    bool reuseConnection, bool deliverViaTCP, char const* proxyURLSuffix){};
    // You probably won't need to subclass/reimplement this function;
    //     reimplement "RTSPServer::weImplementREGISTER()" and "RTSPServer::implementCmd_REGISTER()" instead.
    virtual void handleCmd_bad();
    virtual void handleCmd_notSupported();
    virtual void handleCmd_notFound();
    virtual void handleCmd_sessionNotFound();
    virtual void handleCmd_unsupportedTransport();
    // Support for optional RTSP-over-HTTP tunneling:
    virtual bool parseHTTPRequestString(char* resultCmdName, unsigned resultCmdNameMaxSize,
                                           char* urlSuffix, unsigned urlSuffixMaxSize,
                                           char* sessionCookie, unsigned sessionCookieMaxSize,
                                           char* acceptStr, unsigned acceptStrMaxSize);
    virtual void handleHTTPCmd_notSupported();
    virtual void handleHTTPCmd_notFound();
    virtual void handleHTTPCmd_OPTIONS();
    virtual void handleHTTPCmd_TunnelingGET(char const* sessionCookie);
    virtual bool handleHTTPCmd_TunnelingPOST(char const* sessionCookie, unsigned char const* extraData, unsigned extraDataSize);
    virtual void handleHTTPCmd_StreamingGET(char const* urlSuffix, char const* fullRequestStr);
  protected:
    void closeSocketsRTSP();
    static void handleAlternativeRequestByte(void*, u_int8_t requestByte);
    void handleAlternativeRequestByte1(u_int8_t requestByte);
    bool authenticationOK(char const* cmdName, char const* urlSuffix, char const* fullRequestStr);
    void changeClientInputSocket(int newSocketNum, unsigned char const* extraData, unsigned extraDataSize);
    // used to implement RTSP-over-HTTP tunneling
    static void continueHandlingREGISTER(ParamsForREGISTER* params);
    virtual void continueHandlingREGISTER1(ParamsForREGISTER* params){};
    
    // Shortcuts for setting up a RTSP response (prior to sending it):
    void setRTSPResponse(char const* responseStr);
    void setRTSPResponse(char const* responseStr, u_int32_t sessionId);
    void setRTSPResponse(char const* responseStr, char const* contentStr);
    void setRTSPResponse(char const* responseStr, u_int32_t sessionId, char const* contentStr);
    
    RTSPServer& fOurRTSPServer; // same as ::fOurServer
    int& fClientInputSocket; // aliased to ::fOurSocket
    int fClientOutputSocket;
    bool fIsActive;
    unsigned char* fLastCRLF;
    unsigned fRecursionCount;
    char const* fCurrentCSeq;
    Authenticator fCurrentAuthenticator; // used if access control is needed
    char* fOurSessionCookie; // used for optional RTSP-over-HTTP tunneling
    unsigned fBase64RemainderCount; // used for optional RTSP-over-HTTP tunneling (possible values: 0,1,2,3)
  };
  
  // The state of an individual client session (using one or more sequential TCP connections) handled by a RTSP server:
  class IGTLCommon_EXPORT RTSPClientSession {
  protected:
    RTSPClientSession(RTSPServer& ourServer, u_int32_t sessionId);
    virtual ~RTSPClientSession();

    void noteLiveness(){};
    static void noteClientLiveness(RTSPClientSession* clientSession);
    static void livenessTimeoutTask(RTSPClientSession* clientSession);
    
  protected:
    friend class GenericMediaServer;
    friend class ClientConnection;
    igtl_uint32 fOurSessionId;
    void* fLivenessCheckTask;
    
    friend class RTSPServer;
    friend class RTSPClientConnection;
    // Make the handler functions for each command virtual, to allow subclasses to redefine them:
    virtual void handleCmd_SETUP(RTSPClientConnection* ourClientConnection,
                                 char const* urlPreSuffix, char const* urlSuffix, char const* fullRequestStr);
    virtual void handleCmd_withinSession(RTSPClientConnection* ourClientConnection,
                                         char const* cmdName,
                                         char const* urlPreSuffix, char const* urlSuffix,
                                         char const* fullRequestStr);
    virtual void handleCmd_TEARDOWN(RTSPClientConnection* ourClientConnection);
    virtual void handleCmd_PLAY(RTSPClientConnection* ourClientConnection, char const* fullRequestStr);
    virtual void handleCmd_PAUSE(RTSPClientConnection* ourClientConnection);
    virtual void handleCmd_GET_PARAMETER(RTSPClientConnection* ourClientConnection, char const* fullRequestStr);
    virtual void handleCmd_SET_PARAMETER(RTSPClientConnection* ourClientConnection, char const* fullRequestStr);
  protected:
    void deleteStreamByTrack(unsigned trackNum);
    void reclaimStreamStates();
    bool isMulticast() const { return fIsMulticast; }
    
    // Shortcuts for setting up a RTSP response (prior to sending it):
    void setRTSPResponse(RTSPClientConnection* ourClientConnection, char const* responseStr) { ourClientConnection->setRTSPResponse(responseStr); }
    void setRTSPResponse(RTSPClientConnection* ourClientConnection, char const* responseStr, u_int32_t sessionId) { ourClientConnection->setRTSPResponse(responseStr, sessionId); }
    void setRTSPResponse(RTSPClientConnection* ourClientConnection, char const* responseStr, char const* contentStr) { ourClientConnection->setRTSPResponse(responseStr, contentStr); }
    void setRTSPResponse(RTSPClientConnection* ourClientConnection, char const* responseStr, u_int32_t sessionId, char const* contentStr) { ourClientConnection->setRTSPResponse(responseStr, sessionId, contentStr); }
    
  protected:
    RTSPServer& fOurRTSPServer; // same as ::fOurServer
    bool fIsMulticast, fStreamAfterSETUP;
    unsigned char fTCPStreamIdCount; // used for (optional) RTP/TCP
    bool usesTCPTransport() const { return fTCPStreamIdCount > 0; }
    unsigned fNumStreamStates;
    struct streamState {
      int tcpSocketNum;
      void* streamToken;
    } * fStreamStates;
  };
  RTSPServer::RTSPClientSession* createNewClientSessionWithId();
protected: // redefined virtual functions
  // If you subclass "RTSPClientConnection", then you must also redefine this virtual function in order
  // to create new objects of your subclass:
  virtual RTSPClientConnection* createNewClientConnection(int clientSocket, struct sockaddr_in clientAddr);
  
protected:
  // If you subclass "RTSPClientSession", then you must also redefine this virtual function in order
  // to create new objects of your subclass:
  virtual RTSPClientSession* createNewClientSession(u_int32_t sessionId);
  
private:
  static void incomingConnectionHandlerHTTP(void*, int /*mask*/);
  void incomingConnectionHandlerHTTP();
  
  void noteTCPStreamingOnSocket(int socketNum, RTSPClientSession* clientSession, unsigned trackNum);
  void unnoteTCPStreamingOnSocket(int socketNum, RTSPClientSession* clientSession, unsigned trackNum);
  void stopTCPStreamingOnSocket(int socketNum);
  
protected:
  friend class RTSPClientConnection;
  friend class RTSPClientSession;
  friend class RegisterRequestRecord;
  friend class DeregisterRequestRecord;
  int fHTTPServerSocket; // for optional RTSP-over-HTTP tunneling
  Port fHTTPServerPort; // ditto
  HashTable* fClientConnectionsForHTTPTunneling; // maps client-supplied 'session cookie' strings to "RTSPClientConnection"s
  // (used only for optional RTSP-over-HTTP tunneling)
  HashTable* fTCPStreamingDatabase;
  // maps TCP socket numbers to ids of sessions that are streaming over it (RTP/RTCP-over-TCP)
  HashTable* fPendingRegisterOrDeregisterRequests;
  unsigned fRegisterOrDeregisterRequestCounter;
  UserAuthenticationDatabase* fAuthDB;
  bool fAllowStreamingRTPOverTCP; // by default, True
  int fServerSocket;
  Port fServerPort;
  unsigned fReclamationSeconds;
  
private:
  HashTable* fClientConnections; // the "ClientConnection" objects that we're using
  HashTable* fClientSessions; // maps 'session id' strings to "ClientSession" objects
  //igtl::ServerSocket::Pointer serverSocket;
};

} // namespace igtl

#endif // _igtlRTSPServer_h