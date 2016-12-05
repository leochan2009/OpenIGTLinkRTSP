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
// Implementation

/*=========================================================================

  Program:   The OpenIGTLink Library
  Language:  C++
  Web page:  http://openigtlink.org/

  Copyright (c) Insight Software Consortium. All rights reserved.

  This software is distributed WITHOUT ANY WARRANTY; without even
  the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
  PURPOSE.  See the above copyright notices for more information.

=========================================================================*/

#include "RTSPServer.h"
#include <string.h>
#include "ourMD5.h"
#include "inet.c"


namespace igtl {
  
  char* strDup(char const* str) {
    if (str == NULL) return NULL;
    size_t len = strlen(str) + 1;
    char* copy = new char[len];
    
    if (copy != NULL) {
      memcpy(copy, str, len);
    }
    return copy;
  }
  
  char* strDupSize(char const* str, size_t& resultBufSize) {
    if (str == NULL) {
      resultBufSize = 0;
      return NULL;
    }
    
    resultBufSize = strlen(str) + 1;
    char* copy = new char[resultBufSize];
    
    return copy;
  }
  
  char* strDupSize(char const* str) {
    size_t dummy;
    
    return strDupSize(str, dummy);
  }
  
  static void initBase64DecodeTable() {
    int i;
    for (i = 0; i < 256; ++i) base64DecodeTable[i] = (char)0x80;
    // default value: invalid
    
    for (i = 'A'; i <= 'Z'; ++i) base64DecodeTable[i] = 0 + (i - 'A');
    for (i = 'a'; i <= 'z'; ++i) base64DecodeTable[i] = 26 + (i - 'a');
    for (i = '0'; i <= '9'; ++i) base64DecodeTable[i] = 52 + (i - '0');
    base64DecodeTable[(unsigned char)'+'] = 62;
    base64DecodeTable[(unsigned char)'/'] = 63;
    base64DecodeTable[(unsigned char)'='] = 0;
  }
  
  unsigned char* base64Decode(char const* in, unsigned inSize,
                              unsigned& resultSize,
                              bool trimTrailingZeros) {
    static bool haveInitializedBase64DecodeTable = false;
    if (!haveInitializedBase64DecodeTable) {
      initBase64DecodeTable();
      haveInitializedBase64DecodeTable = true;
    }
    int resultBufSize = strlen(in) + 1;
    char* copy = new char[resultBufSize];
    unsigned char* out = (unsigned char*)copy; // ensures we have enough space
    int k = 0;
    int paddingCount = 0;
    int const jMax = inSize - 3;
    // in case "inSize" is not a multiple of 4 (although it should be)
    for (int j = 0; j < jMax; j += 4) {
      char inTmp[4], outTmp[4];
      for (int i = 0; i < 4; ++i) {
        inTmp[i] = in[i+j];
        if (inTmp[i] == '=') ++paddingCount;
        outTmp[i] = base64DecodeTable[(unsigned char)inTmp[i]];
        if ((outTmp[i]&0x80) != 0) outTmp[i] = 0; // this happens only if there was an invalid character; pretend that it was 'A'
      }
      
      out[k++] = (outTmp[0]<<2) | (outTmp[1]>>4);
      out[k++] = (outTmp[1]<<4) | (outTmp[2]>>2);
      out[k++] = (outTmp[2]<<6) | outTmp[3];
    }
    
    if (trimTrailingZeros) {
      while (paddingCount > 0 && k > 0 && out[k-1] == '\0') { --k; --paddingCount; }
    }
    resultSize = k;
    unsigned char* result = new unsigned char[resultSize];
    memmove(result, out, resultSize);
    delete[] out;
    
    return result;
  }
  unsigned char* base64Decode(char const* in, unsigned& resultSize,
                              bool trimTrailingZeros) {
    if (in == NULL) return NULL; // sanity check
    return base64Decode(in, strlen(in), resultSize, trimTrailingZeros);
  }
  
  char* base64Encode(char const* origSigned, unsigned origLength) {
    unsigned char const* orig = (unsigned char const*)origSigned; // in case any input bytes have the MSB set
    if (orig == NULL) return NULL;
    
    unsigned const numOrig24BitValues = origLength/3;
    bool havePadding = origLength > numOrig24BitValues*3;
    bool havePadding2 = origLength == numOrig24BitValues*3 + 2;
    unsigned const numResultBytes = 4*(numOrig24BitValues + havePadding);
    char* result = new char[numResultBytes+1]; // allow for trailing '\0'
    
    // Map each full group of 3 input bytes into 4 output base-64 characters:
    unsigned i;
    for (i = 0; i < numOrig24BitValues; ++i) {
      result[4*i+0] = base64Char[(orig[3*i]>>2)&0x3F];
      result[4*i+1] = base64Char[(((orig[3*i]&0x3)<<4) | (orig[3*i+1]>>4))&0x3F];
      result[4*i+2] = base64Char[((orig[3*i+1]<<2) | (orig[3*i+2]>>6))&0x3F];
      result[4*i+3] = base64Char[orig[3*i+2]&0x3F];
    }
    
    // Now, take padding into account.  (Note: i == numOrig24BitValues)
    if (havePadding) {
      result[4*i+0] = base64Char[(orig[3*i]>>2)&0x3F];
      if (havePadding2) {
        result[4*i+1] = base64Char[(((orig[3*i]&0x3)<<4) | (orig[3*i+1]>>4))&0x3F];
        result[4*i+2] = base64Char[(orig[3*i+1]<<2)&0x3F];
      } else {
        result[4*i+1] = base64Char[((orig[3*i]&0x3)<<4)&0x3F];
        result[4*i+2] = '=';
      }
      result[4*i+3] = '=';
    }
    
    result[numResultBytes] = '\0';
    return result;
  }
  
  char const* dateHeader() {
    static char buf[200];
#if !defined(_WIN32_WCE)
    time_t tt = time(NULL);
    strftime(buf, sizeof buf, "Date: %a, %b %d %Y %H:%M:%S GMT\r\n", gmtime(&tt));
#else
    // WinCE apparently doesn't have "time()", "strftime()", or "gmtime()",
    // so generate the "Date:" header a different, WinCE-specific way.
    // (Thanks to Pierre l'Hussiez for this code)
    // RSF: But where is the "Date: " string?  This code doesn't look quite right...
    SYSTEMTIME SystemTime;
    GetSystemTime(&SystemTime);
    WCHAR dateFormat[] = L"ddd, MMM dd yyyy";
    WCHAR timeFormat[] = L"HH:mm:ss GMT\r\n";
    WCHAR inBuf[200];
    DWORD locale = LOCALE_NEUTRAL;
    
    int ret = GetDateFormat(locale, 0, &SystemTime,
                            (LPTSTR)dateFormat, (LPTSTR)inBuf, sizeof inBuf);
    inBuf[ret - 1] = ' ';
    ret = GetTimeFormat(locale, 0, &SystemTime,
                        (LPTSTR)timeFormat,
                        (LPTSTR)inBuf + ret, (sizeof inBuf) - ret);
    wcstombs(buf, inBuf, wcslen(inBuf));
#endif
    return buf;
  };
  
  ////////// AddressString implementation //////////
  
  AddressString::AddressString(struct sockaddr_in const& addr) {
    init(addr.sin_addr.s_addr);
  }
  
  AddressString::AddressString(struct in_addr const& addr) {
    init(addr.s_addr);
  }
  
  AddressString::AddressString(igtl_uint32 addr) {
    init(addr);
  }
  
  void AddressString::init(igtl_uint32 addr) {
    fVal = new char[16]; // large enough for "abc.def.ghi.jkl"
    igtl_uint32 addrNBO = htonl(addr); // make sure we have a value in a known byte order: big endian
    sprintf(fVal, "%u.%u.%u.%u", (addrNBO>>24)&0xFF, (addrNBO>>16)&0xFF, (addrNBO>>8)&0xFF, addrNBO&0xFF);
  }
  
  AddressString::~AddressString() {
    delete[] fVal;
  }

  ////////// UserAuthenticationDatabase implementation //////////
  
  UserAuthenticationDatabase::UserAuthenticationDatabase(char const* realm,
                                                         bool passwordsAreMD5)
  : fTable((BasicHashTable*)BasicHashTable::create(STRING_HASH_KEYS)),
  fRealm(strDup(realm == NULL ? "LIVE555 Streaming Media" : realm)),
  fPasswordsAreMD5(passwordsAreMD5) {
  }
  
  UserAuthenticationDatabase::~UserAuthenticationDatabase() {
    delete[] fRealm;
    
    // Delete the allocated 'password' strings that we stored in the table, and then the table itself:
    char* password;
    while ((password = (char*)fTable->RemoveNext()) != NULL) {
      delete[] password;
    }
    delete fTable;
  }
  
  void UserAuthenticationDatabase::addUserRecord(char const* username,
                                                 char const* password) {
    fTable->Add(username, (void*)(strDup(password)));
  }
  
  void UserAuthenticationDatabase::removeUserRecord(char const* username) {
    char* password = (char*)(fTable->Lookup(username));
    fTable->Remove(username);
    delete[] password;
  }
  
  char const* UserAuthenticationDatabase::lookupPassword(char const* username) {
    return (char const*)(fTable->Lookup(username));
  }
  ////////// End of UserAuthenticationDatabase implementation //////////
  
  Authenticator::Authenticator() {
    assign(NULL, NULL, NULL, NULL, false);
  }
  
  Authenticator::Authenticator(char const* username, char const* password, bool passwordIsMD5) {
    assign(NULL, NULL, username, password, passwordIsMD5);
  }
  
  Authenticator::Authenticator(const Authenticator& orig) {
    assign(orig.realm(), orig.nonce(), orig.username(), orig.password(), orig.fPasswordIsMD5);
  }
  
  Authenticator& Authenticator::operator=(const Authenticator& rightSide) {
    if (&rightSide != this) {
      reset();
      assign(rightSide.realm(), rightSide.nonce(),
             rightSide.username(), rightSide.password(), rightSide.fPasswordIsMD5);
    }
    
    return *this;
  }
  
  bool Authenticator::operator<(const Authenticator* rightSide) {
    // Returns true if "rightSide" is 'newer' than us:
    if (rightSide != NULL && rightSide != this &&
        (rightSide->realm() != NULL || rightSide->nonce() != NULL ||
         username() == NULL || password() == NULL ||
         strcmp(rightSide->username(), username()) != 0 ||
         strcmp(rightSide->password(), password()) != 0)) {
          return true;
        }
    
    return false;
  }
  
  Authenticator::~Authenticator() {
    reset();
  }
  
  void Authenticator::reset() {
    resetRealmAndNonce();
    resetUsernameAndPassword();
  }
  
  void Authenticator::setRealmAndNonce(char const* realm, char const* nonce) {
    resetRealmAndNonce();
    assignRealmAndNonce(realm, nonce);
  }
  
  void Authenticator::setRealmAndRandomNonce(char const* realm) {
    resetRealmAndNonce();
    
    // Construct data to seed the random nonce:
    struct {
      struct timeval timestamp;
      unsigned counter;
    } seedData;
    gettimeofday(&seedData.timestamp, NULL);
    static unsigned counter = 0;
    seedData.counter = ++counter;
    
    // Use MD5 to compute a 'random' nonce from this seed data:
    char nonceBuf[33];
    our_MD5Data((unsigned char*)(&seedData), sizeof seedData, nonceBuf);
    
    assignRealmAndNonce(realm, nonceBuf);
  }
  
  void Authenticator::setUsernameAndPassword(char const* username,
                                             char const* password,
                                             bool passwordIsMD5) {
    resetUsernameAndPassword();
    assignUsernameAndPassword(username, password, passwordIsMD5);
  }
  
  char const* Authenticator::computeDigestResponse(char const* cmd,
                                                   char const* url) const {
    // The "response" field is computed as:
    //    md5(md5(<username>:<realm>:<password>):<nonce>:md5(<cmd>:<url>))
    // or, if "fPasswordIsMD5" is true:
    //    md5(<password>:<nonce>:md5(<cmd>:<url>))
    char ha1Buf[33];
    if (fPasswordIsMD5) {
      strncpy(ha1Buf, password(), 32);
      ha1Buf[32] = '\0'; // just in case
    } else {
      unsigned const ha1DataLen = strlen(username()) + 1
      + strlen(realm()) + 1 + strlen(password());
      unsigned char* ha1Data = new unsigned char[ha1DataLen+1];
      sprintf((char*)ha1Data, "%s:%s:%s", username(), realm(), password());
      our_MD5Data(ha1Data, ha1DataLen, ha1Buf);
      delete[] ha1Data;
    }
    
    unsigned const ha2DataLen = strlen(cmd) + 1 + strlen(url);
    unsigned char* ha2Data = new unsigned char[ha2DataLen+1];
    sprintf((char*)ha2Data, "%s:%s", cmd, url);
    char ha2Buf[33];
    our_MD5Data(ha2Data, ha2DataLen, ha2Buf);
    delete[] ha2Data;
    
    unsigned const digestDataLen
    = 32 + 1 + strlen(nonce()) + 1 + 32;
    unsigned char* digestData = new unsigned char[digestDataLen+1];
    sprintf((char*)digestData, "%s:%s:%s",
            ha1Buf, nonce(), ha2Buf);
    char const* result = our_MD5Data(digestData, digestDataLen, NULL);
    delete[] digestData;
    return result;
  }
  
  void Authenticator::reclaimDigestResponse(char const* responseStr) const {
    delete[](char*)responseStr;
  }
  
  void Authenticator::resetRealmAndNonce() {
    delete[] fRealm; fRealm = NULL;
    delete[] fNonce; fNonce = NULL;
  }
  
  void Authenticator::resetUsernameAndPassword() {
    delete[] fUsername; fUsername = NULL;
    delete[] fPassword; fPassword = NULL;
    fPasswordIsMD5 = false;
  }
  
  void Authenticator::assignRealmAndNonce(char const* realm, char const* nonce) {
    fRealm = strDup(realm);
    fNonce = strDup(nonce);
  }
  
  void Authenticator::assignUsernameAndPassword(char const* username, char const* password, bool passwordIsMD5) {
    if (username == NULL) username = "";
    if (password == NULL) password = "";
    
    fUsername = strDup(username);
    fPassword = strDup(password);
    fPasswordIsMD5 = passwordIsMD5;
  }
  
  void Authenticator::assign(char const* realm, char const* nonce,
                             char const* username, char const* password, bool passwordIsMD5) {
    assignRealmAndNonce(realm, nonce);
    assignUsernameAndPassword(username, password, passwordIsMD5);
  }
  ////////// End of Authenticator implementation //////////
  
  RTSPServer*
  RTSPServer::createNew(Port ourPort,
                        UserAuthenticationDatabase* authDatabase,
                        unsigned reclamationSeconds) {    
    return new RTSPServer(ourPort, authDatabase, reclamationSeconds);
  }

  int RTSPServer::setUpOurSocket(Port& ourPort) {
    int ourSocket = -1;
    // The following statement is enabled by default.
    // Don't disable it (by defining ALLOW_SERVER_PORT_REUSE) unless you know what you're doing.
    if (ourPort.num() == 0) {
      return ourSocket;
    }
    ourSocket = socket(AF_INET, SOCK_STREAM, 0);// to do: set the socke parameters
    if (ourSocket < 0) return ourSocket;
    
    // Allow multiple simultaneous connections:
    if (listen(ourSocket, 20) < 0) {
      return ourSocket;
    }
    
    struct sockaddr_in server;
    
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(ourPort.num());
    // Allow the socket to be bound to an address that is already in use
#ifdef _WIN32
    int opt=1;
    setsockopt(socketdescriptor, SOL_SOCKET, SO_REUSEADDR, (char*) &opt, sizeof(int));
#elif defined(VTK_HAVE_SO_REUSEADDR)
    int opt=1;
    setsockopt(socketdescriptor, SOL_SOCKET, SO_REUSEADDR, (void *) &opt, sizeof(int));
#endif
    
    if ( bind(ourSocket, reinterpret_cast<sockaddr*>(&server), sizeof(server)) )
    {
      return -1;
    }
    return ourSocket;
    if (ourSocket != -1) close(ourSocket);
    return -1;
  }
  
  
  char* RTSPServer::rtspURLPrefix(int clientSocket) const {
    
    // provide default ip address //
    char hostname[100];
    int result = gethostname(hostname, sizeof hostname);
    struct hostent *phe = gethostbyname(hostname);
    struct in_addr addr;
    for (int i = 0; phe->h_addr_list[i] != 0; ++i) { // Multiple ip address might exists, get the last one
      memcpy(&addr, phe->h_addr_list[i], sizeof(struct in_addr));
      std::cout << "Address " << i << ": " << inet_ntoa(addr) << std::endl;
    }
    igtl_uint32 ourIPAddress = addr.s_addr;
    if(result == 0&& ourIPAddress != 0XFFFFFFFF)
    {
      
      struct sockaddr_in ourAddress;
      if (clientSocket < 0) {
        // Use our default IP address in the URL:
        ourAddress.sin_addr.s_addr = INADDR_ANY != 0
        ? INADDR_ANY
        : ourIPAddress; // hack
      } else {
        int namelen = sizeof ourAddress;
      }
      
      char urlBuffer[100]; // more than big enough for "rtsp://<ip-address>:<port>/"
      
      igtl_uint16 portNumHostOrder = ntohs(fServerPort.num());
      if (portNumHostOrder == 554 /* the default port number */) {
        sprintf(urlBuffer, "rtsp://%s/", AddressString(ourAddress).val());
      } else {
        sprintf(urlBuffer, "rtsp://%s:%hu/",
                AddressString(ourAddress).val(), portNumHostOrder);
      }
      size_t len = strlen(urlBuffer) + 1;
      char* copy = new char[len];

      memcpy(copy, urlBuffer, len);
      return copy;
    }
    return NULL;
  }
  
  UserAuthenticationDatabase* RTSPServer::setAuthenticationDatabase(UserAuthenticationDatabase* newDB) {
    UserAuthenticationDatabase* oldDB = fAuthDB;
    fAuthDB = newDB;
    
    return oldDB;
  }
  
  bool RTSPServer::setUpTunnelingOverHTTP(Port httpPort) {
    fHTTPServerSocket = setUpOurSocket(httpPort);
    if (fHTTPServerSocket >= 0) {
      fHTTPServerPort = httpPort;
      //to do task, envir().taskScheduler().turnOnBackgroundReadHandling(fHTTPServerSocket, incomingConnectionHandlerHTTP, this);
      return true;
    }
    
    return false;
  }
  
  igtl_uint16 RTSPServer::httpServerPortNum() const {
    return ntohs(fHTTPServerPort.num());
  }
  
  char const* RTSPServer::allowedCommandNames() {
    return "OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE, GET_PARAMETER, SET_PARAMETER";
  }
  
  UserAuthenticationDatabase* RTSPServer::getAuthenticationDatabaseForCommand(char const* /*cmdName*/) {
    // default implementation
    return fAuthDB;
  }
  
  bool RTSPServer::specialClientAccessCheck(int /*clientSocket*/, struct sockaddr_in& /*clientAddr*/, char const* /*urlSuffix*/) {
    // default implementation
    return true;
  }
  
  bool RTSPServer::specialClientUserAccessCheck(int /*clientSocket*/, struct sockaddr_in& /*clientAddr*/,
                                                   char const* /*urlSuffix*/, char const * /*username*/) {
    // default implementation; no further access restrictions:
    return true;
  }

  RTSPServer::RTSPServer(Port ourPort,
                         UserAuthenticationDatabase* authDatabase,
                         unsigned reclamationSeconds):Object(), fHTTPServerSocket(-1), fHTTPServerPort(0),
   fServerPort(ourPort), fReclamationSeconds(reclamationSeconds),
  fClientConnectionsForHTTPTunneling(NULL), // will get created if needed
  fTCPStreamingDatabase(BasicHashTable::create(ONE_WORD_HASH_KEYS)),
  fPendingRegisterOrDeregisterRequests(BasicHashTable::create(ONE_WORD_HASH_KEYS)),
  fRegisterOrDeregisterRequestCounter(0), fAuthDB(authDatabase), fAllowStreamingRTPOverTCP(true){
    int ourSocket = setUpOurSocket(ourPort);
    fServerSocket= ourSocket;
  }
  
  
  // A data structure that is used to implement "fTCPStreamingDatabase"
  // (and the "noteTCPStreamingOnSocket()" and "stopTCPStreamingOnSocket()" member functions):
  class streamingOverTCPRecord {
  public:
    streamingOverTCPRecord(u_int32_t sessionId, unsigned trackNum, streamingOverTCPRecord* next)
    : fNext(next), fSessionId(sessionId), fTrackNum(trackNum) {
    }
    virtual ~streamingOverTCPRecord() {
      delete fNext;
    }
    
    streamingOverTCPRecord* fNext;
    u_int32_t fSessionId;
    unsigned fTrackNum;
  };

  
  RTSPServer::~RTSPServer()
  {
    close(fHTTPServerSocket);
    
    // Close all client connection objects:
    RTSPClientConnection* connection;
    while ((connection = (RTSPClientConnection*)fClientConnections->getFirst()) != NULL) {
      delete connection;
    }
    delete fClientConnections;

    delete fClientConnectionsForHTTPTunneling;
    
    // Empty out and close "fTCPStreamingDatabase":
    streamingOverTCPRecord* sotcp;
    while ((sotcp = (streamingOverTCPRecord*)fTCPStreamingDatabase->getFirst()) != NULL) {
      delete sotcp;
    }
    delete fTCPStreamingDatabase;
  }
  
  char* RTSPServer
  ::rtspURL(int clientSocket) const {
    char* urlPrefix = rtspURLPrefix(clientSocket);
    char* resultURL = new char[strlen(urlPrefix) + 1];
    sprintf(resultURL, "%s", urlPrefix);
    
    delete[] urlPrefix;
    return resultURL;
  }

  
  bool RTSPServer::isRTSPServer() const {
    return true;
  }
  
  void RTSPServer::incomingConnectionHandlerHTTP(void* instance, int /*mask*/) {
    RTSPServer* server = (RTSPServer*)instance;
    server->incomingConnectionHandlerHTTP();
  }
  void RTSPServer::incomingConnectionHandlerHTTP() {
    struct sockaddr_in clientAddr;
    int clientAddrLen = sizeof clientAddr;
    int clientSocket = 1;// accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
    if (clientSocket >= 0) {
      
#ifdef USE_SIGNALS
#ifdef SO_NOSIGPIPE
      int set_option = 1;
      setsockopt(clientSocket, SOL_SOCKET, SO_NOSIGPIPE, &set_option, sizeof set_option);
#else
      signal(SIGPIPE, SIG_IGN);
#endif
#endif
#if defined(__WIN32__) || defined(_WIN32)
      unsigned long arg = 1;
      return ioctlsocket(sock, FIONBIO, &arg) == 0;
#elif defined(VXWORKS)
      int arg = 1;
      return ioctl(clientSocket, FIONBIO, (int)&arg) == 0;
#else
      int curFlags = fcntl(clientSocket, F_GETFL, 0);
      fcntl(clientSocket, F_SETFL, curFlags|O_NONBLOCK);
#endif
      //increaseSendBufferTo(envir(), clientSocket, 50*1024);
      
  #ifdef DEBUG
      envir() << "accept()ed connection from " << AddressString(clientAddr).val() << "\n";
  #endif
      
      // Create a new object for handling this connection:
      (void)createNewClientConnection(clientSocket, clientAddr);
    }
  }
  
  void RTSPServer
  ::noteTCPStreamingOnSocket(int socketNum, RTSPClientSession* clientSession, unsigned trackNum) {
    streamingOverTCPRecord* sotcpCur
    = (streamingOverTCPRecord*)fTCPStreamingDatabase->Lookup((char const*)socketNum);
    streamingOverTCPRecord* sotcpNew
    = new streamingOverTCPRecord(clientSession->fOurSessionId, trackNum, sotcpCur);
    fTCPStreamingDatabase->Add((char const*)socketNum, sotcpNew);
  }
  
  void RTSPServer
  ::unnoteTCPStreamingOnSocket(int socketNum, RTSPClientSession* clientSession, unsigned trackNum) {
    if (socketNum < 0) return;
    streamingOverTCPRecord* sotcpHead
    = (streamingOverTCPRecord*)fTCPStreamingDatabase->Lookup((char const*)socketNum);
    if (sotcpHead == NULL) return;
    
    // Look for a record of the (session,track); remove it if found:
    streamingOverTCPRecord* sotcp = sotcpHead;
    streamingOverTCPRecord* sotcpPrev = sotcpHead;
    do {
      if (sotcp->fSessionId == clientSession->fOurSessionId && sotcp->fTrackNum == trackNum) break;
      sotcpPrev = sotcp;
      sotcp = sotcp->fNext;
    } while (sotcp != NULL);
    if (sotcp == NULL) return; // not found
    
    if (sotcp == sotcpHead) {
      // We found it at the head of the list.  Remove it and reinsert the tail into the hash table:
      sotcpHead = sotcp->fNext;
      sotcp->fNext = NULL;
      delete sotcp;
      
      if (sotcpHead == NULL) {
        // There were no more entries on the list.  Remove the original entry from the hash table:
        fTCPStreamingDatabase->Remove((char const*)socketNum);
      } else {
        // Add the rest of the list into the hash table (replacing the original):
        fTCPStreamingDatabase->Add((char const*)socketNum, sotcpHead);
      }
    } else {
      // We found it on the list, but not at the head.  Unlink it:
      sotcpPrev->fNext = sotcp->fNext;
      sotcp->fNext = NULL;
      delete sotcp;
    }
  }
  
  void RTSPServer::stopTCPStreamingOnSocket(int socketNum) {
    // Close any stream that is streaming over "socketNum" (using RTP/RTCP-over-TCP streaming):
    streamingOverTCPRecord* sotcp
    = (streamingOverTCPRecord*)fTCPStreamingDatabase->Lookup((char const*)socketNum);
    if (sotcp != NULL) {
      do {
        char sessionIdStr[8+1];
        snprintf(sessionIdStr, sizeof sessionIdStr, "%08X", sotcp->fSessionId);
        RTSPClientSession* clientSession
        = (RTSPServer::RTSPClientSession*)fClientSessions->Lookup(sessionIdStr);
        if (clientSession != NULL) {
          clientSession->deleteStreamByTrack(sotcp->fTrackNum);
        }
        
        streamingOverTCPRecord* sotcpNext = sotcp->fNext;
        sotcp->fNext = NULL;
        delete sotcp;
        sotcp = sotcpNext;
      } while (sotcp != NULL);
      fTCPStreamingDatabase->Remove((char const*)socketNum);
    }
  }
  
  
  ////////// RTSPServer::RTSPClientConnection implementation //////////
  
  RTSPServer::RTSPClientConnection
  ::RTSPClientConnection(RTSPServer& ourServer, int clientSocket, struct sockaddr_in clientAddr)
  :fOurRTSPServer(ourServer), fClientInputSocket(fOurSocket), fClientOutputSocket(fOurSocket),
  fIsActive(true), fRecursionCount(0), fOurSessionCookie(NULL) {
    ourServer.fClientConnections->Add((char const*)this, this);
    //setBackgroundHandling(fOurSocket, SOCKET_READABLE|SOCKET_EXCEPTION, incomingRequestHandler, this); to do task
    resetRequestBuffer();
  }
  
  RTSPServer::RTSPClientConnection::~RTSPClientConnection() {
    if (fOurSessionCookie != NULL) {
      // We were being used for RTSP-over-HTTP tunneling. Also remove ourselves from the 'session cookie' hash table before we go:
      fOurRTSPServer.fClientConnectionsForHTTPTunneling->Remove(fOurSessionCookie);
      delete[] fOurSessionCookie;
    }
    
    closeSocketsRTSP();
  }
  
  // Handler routines for specific RTSP commands:
  
  void RTSPServer::RTSPClientConnection::handleCmd_OPTIONS() {
    snprintf((char*)fResponseBuffer, sizeof fResponseBuffer,
             "RTSP/1.0 200 OK\r\nCSeq: %s\r\n%sPublic: %s\r\n\r\n",
             fCurrentCSeq, dateHeader(), fOurRTSPServer.allowedCommandNames());
  }
  
  void RTSPServer::RTSPClientConnection
  ::handleCmd_GET_PARAMETER(char const* /*fullRequestStr*/) {
    // By default, we implement "GET_PARAMETER" (on the entire server) just as a 'no op', and send back a dummy response.
    // (If you want to handle this type of "GET_PARAMETER" differently, you can do so by defining a subclass of "RTSPServer"
    // and "RTSPServer::RTSPClientConnection", and then reimplement this virtual function in your subclass.)
    setRTSPResponse("200 OK", "Local test from Leochan");
  }
  
  void RTSPServer::RTSPClientConnection
  ::handleCmd_SET_PARAMETER(char const* /*fullRequestStr*/) {
    // By default, we implement "SET_PARAMETER" (on the entire server) just as a 'no op', and send back an empty response.
    // (If you want to handle this type of "SET_PARAMETER" differently, you can do so by defining a subclass of "RTSPServer"
    // and "RTSPServer::RTSPClientConnection", and then reimplement this virtual function in your subclass.)
    setRTSPResponse("200 OK");
  }
  
  void RTSPServer::RTSPClientConnection
  ::handleCmd_DESCRIBE(char const* urlPreSuffix, char const* urlSuffix, char const* fullRequestStr) {
    char* sdpDescription = NULL;
    char* rtspURL = NULL;
    do {
      char urlTotalSuffix[2*RTSP_PARAM_STRING_MAX];
      // enough space for urlPreSuffix/urlSuffix'\0'
      urlTotalSuffix[0] = '\0';
      if (urlPreSuffix[0] != '\0') {
        strcat(urlTotalSuffix, urlPreSuffix);
        strcat(urlTotalSuffix, "/");
      }
      strcat(urlTotalSuffix, urlSuffix);
      
      if (!authenticationOK("DESCRIBE", urlTotalSuffix, fullRequestStr)) break;
      
      // We should really check that the request contains an "Accept:" #####
      // for "application/sdp", because that's what we're sending back #####
      
      // Begin by looking up the "ServerMediaSession" object for the specified "urlTotalSuffix":
      /*session = fOurServer.lookupServerMediaSession(urlTotalSuffix);
      if (session == NULL) {
        handleCmd_notFound();
        break;
      }
      
      // Increment the "ServerMediaSession" object's reference count, in case someone removes it
      // while we're using it:
      session->incrementReferenceCount();
      
      // Then, assemble a SDP description for this session:
      sdpDescription = session->generateSDPDescription();
      if (sdpDescription == NULL) {
        // This usually means that a file name that was specified for a
        // "ServerMediaSubsession" does not exist.
        setRTSPResponse("404 File Not Found, Or In Incorrect Format");
        break;
      }
      unsigned sdpDescriptionSize = strlen(sdpDescription);
      
      // Also, generate our RTSP URL, for the "Content-Base:" header
      // (which is necessary to ensure that the correct URL gets used in subsequent "SETUP" requests).
      rtspURL = fOurRTSPServer.rtspURL(session, fClientInputSocket);
      
      snprintf((char*)fResponseBuffer, sizeof fResponseBuffer,
               "RTSP/1.0 200 OK\r\nCSeq: %s\r\n"
               "%s"
               "Content-Base: %s/\r\n"
               "Content-Type: application/sdp\r\n"
               "Content-Length: %d\r\n\r\n"
               "%s",
               fCurrentCSeq,
               dateHeader(),
               rtspURL,
               sdpDescriptionSize,
               sdpDescription);
       */
    } while (0);
    
    /*if (session != NULL) {
      // Decrement its reference count, now that we're done using it:
      session->decrementReferenceCount();
      if (session->referenceCount() == 0 && session->deleteWhenUnreferenced()) {
        fOurServer.removeServerMediaSession(session);
      }
    }
    */
    delete[] sdpDescription;
    delete[] rtspURL;
  }
  
  static void lookForHeader(char const* headerName, char const* source, unsigned sourceLen, char* resultStr, unsigned resultMaxSize) {
    resultStr[0] = '\0';  // by default, return an empty string
    unsigned headerNameLen = strlen(headerName);
    for (int i = 0; i < (int)(sourceLen-headerNameLen); ++i) {
      if (strncmp(&source[i], headerName, headerNameLen) == 0 && source[i+headerNameLen] == ':') {
        // We found the header.  Skip over any whitespace, then copy the rest of the line to "resultStr":
        for (i += headerNameLen+1; i < (int)sourceLen && (source[i] == ' ' || source[i] == '\t'); ++i) {}
        for (unsigned j = i; j < sourceLen; ++j) {
          if (source[j] == '\r' || source[j] == '\n') {
            // We've found the end of the line.  Copy it to the result (if it will fit):
            if (j-i+1 > resultMaxSize) break;
            char const* resultSource = &source[i];
            char const* resultSourceEnd = &source[j];
            while (resultSource < resultSourceEnd) *resultStr++ = *resultSource++;
            *resultStr = '\0';
            break;
          }
        }
      }
    }
  }
  
  void RTSPServer::RTSPClientConnection::handleCmd_bad() {
    // Don't do anything with "fCurrentCSeq", because it might be nonsense
    snprintf((char*)fResponseBuffer, sizeof fResponseBuffer,
             "RTSP/1.0 400 Bad Request\r\n%sAllow: %s\r\n\r\n",
             dateHeader(), fOurRTSPServer.allowedCommandNames());
  }
  
  void RTSPServer::RTSPClientConnection::handleCmd_notSupported() {
    snprintf((char*)fResponseBuffer, sizeof fResponseBuffer,
             "RTSP/1.0 405 Method Not Allowed\r\nCSeq: %s\r\n%sAllow: %s\r\n\r\n",
             fCurrentCSeq, dateHeader(), fOurRTSPServer.allowedCommandNames());
  }
  
  void RTSPServer::RTSPClientConnection::handleCmd_notFound() {
    setRTSPResponse("404 Stream Not Found");
  }
  
  void RTSPServer::RTSPClientConnection::handleCmd_sessionNotFound() {
    setRTSPResponse("454 Session Not Found");
  }
  
  void RTSPServer::RTSPClientConnection::handleCmd_unsupportedTransport() {
    setRTSPResponse("461 Unsupported Transport");
  }
  
  bool RTSPServer::RTSPClientConnection::parseHTTPRequestString(char* resultCmdName, unsigned resultCmdNameMaxSize,
                                                                   char* urlSuffix, unsigned urlSuffixMaxSize,
                                                                   char* sessionCookie, unsigned sessionCookieMaxSize,
                                                                   char* acceptStr, unsigned acceptStrMaxSize) {
    // Check for the limited HTTP requests that we expect for specifying RTSP-over-HTTP tunneling.
    // This parser is currently rather dumb; it should be made smarter #####
    char const* reqStr = (char const*)fRequestBuffer;
    unsigned const reqStrSize = fRequestBytesAlreadySeen;
    
    // Read everything up to the first space as the command name:
    bool parseSucceeded = false;
    unsigned i;
    for (i = 0; i < resultCmdNameMaxSize-1 && i < reqStrSize; ++i) {
      char c = reqStr[i];
      if (c == ' ' || c == '\t') {
        parseSucceeded = true;
        break;
      }
      
      resultCmdName[i] = c;
    }
    resultCmdName[i] = '\0';
    if (!parseSucceeded) return false;
    
    // Look for the string "HTTP/", before the first \r or \n:
    parseSucceeded = false;
    for (; i < reqStrSize-5 && reqStr[i] != '\r' && reqStr[i] != '\n'; ++i) {
      if (reqStr[i] == 'H' && reqStr[i+1] == 'T' && reqStr[i+2]== 'T' && reqStr[i+3]== 'P' && reqStr[i+4]== '/') {
        i += 5; // to advance past the "HTTP/"
        parseSucceeded = true;
        break;
      }
    }
    if (!parseSucceeded) return false;
    
    // Get the 'URL suffix' that occurred before this:
    unsigned k = i-6;
    while (k > 0 && reqStr[k] == ' ') --k; // back up over white space
    unsigned j = k;
    while (j > 0 && reqStr[j] != ' ' && reqStr[j] != '/') --j;
    // The URL suffix is in position (j,k]:
    if (k - j + 1 > urlSuffixMaxSize) return false; // there's no room>
    unsigned n = 0;
    while (++j <= k) urlSuffix[n++] = reqStr[j];
    urlSuffix[n] = '\0';
    
    // Look for various headers that we're interested in:
    lookForHeader("x-sessioncookie", &reqStr[i], reqStrSize-i, sessionCookie, sessionCookieMaxSize);
    lookForHeader("Accept", &reqStr[i], reqStrSize-i, acceptStr, acceptStrMaxSize);
    
    return true;
  }
  
  void RTSPServer::RTSPClientConnection::handleHTTPCmd_notSupported() {
    snprintf((char*)fResponseBuffer, sizeof fResponseBuffer,
             "HTTP/1.1 405 Method Not Allowed\r\n%s\r\n\r\n",
             dateHeader());
  }
  
  void RTSPServer::RTSPClientConnection::handleHTTPCmd_notFound() {
    snprintf((char*)fResponseBuffer, sizeof fResponseBuffer,
             "HTTP/1.1 404 Not Found\r\n%s\r\n\r\n",
             dateHeader());
  }
  
  void RTSPServer::RTSPClientConnection::handleHTTPCmd_OPTIONS() {
#ifdef DEBUG
    fprintf(stderr, "Handled HTTP \"OPTIONS\" request\n");
#endif
    // Construct a response to the "OPTIONS" command that notes that our special headers (for RTSP-over-HTTP tunneling) are allowed:
    snprintf((char*)fResponseBuffer, sizeof fResponseBuffer,
             "HTTP/1.1 200 OK\r\n"
             "%s"
             "Access-Control-Allow-Origin: *\r\n"
             "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n"
             "Access-Control-Allow-Headers: x-sessioncookie, Pragma, Cache-Control\r\n"
             "Access-Control-Max-Age: 1728000\r\n"
             "\r\n",
             dateHeader());
  }
  
  void RTSPServer::RTSPClientConnection::handleHTTPCmd_TunnelingGET(char const* sessionCookie) {
    // Record ourself as having this 'session cookie', so that a subsequent HTTP "POST" command (with the same 'session cookie')
    // can find us:
    if (fOurRTSPServer.fClientConnectionsForHTTPTunneling == NULL) {
      fOurRTSPServer.fClientConnectionsForHTTPTunneling = HashTable::create(STRING_HASH_KEYS);
    }
    delete[] fOurSessionCookie;
    size_t len = strlen(sessionCookie) + 1;
    char* copy = new char[len];
    memcpy(copy, sessionCookie, len);
    fOurSessionCookie = copy;
    fOurRTSPServer.fClientConnectionsForHTTPTunneling->Add(sessionCookie, (void*)this);
#ifdef DEBUG
    fprintf(stderr, "Handled HTTP \"GET\" request (client output socket: %d)\n", fClientOutputSocket);
#endif
    
    // Construct our response:
    snprintf((char*)fResponseBuffer, sizeof fResponseBuffer,
             "HTTP/1.1 200 OK\r\n"
             "%s"
             "Cache-Control: no-cache\r\n"
             "Pragma: no-cache\r\n"
             "Content-Type: application/x-rtsp-tunnelled\r\n"
             "\r\n",
             dateHeader());
  }
  
  bool RTSPServer::RTSPClientConnection
  ::handleHTTPCmd_TunnelingPOST(char const* sessionCookie, unsigned char const* extraData, unsigned extraDataSize) {
    // Use the "sessionCookie" string to look up the separate "RTSPClientConnection" object that should have been used to handle
    // an earlier HTTP "GET" request:
    if (fOurRTSPServer.fClientConnectionsForHTTPTunneling == NULL) {
      fOurRTSPServer.fClientConnectionsForHTTPTunneling = HashTable::create(STRING_HASH_KEYS);
    }
    RTSPServer::RTSPClientConnection* prevClientConnection
    = (RTSPServer::RTSPClientConnection*)(fOurRTSPServer.fClientConnectionsForHTTPTunneling->Lookup(sessionCookie));
    if (prevClientConnection == NULL) {
      // There was no previous HTTP "GET" request; treat this "POST" request as bad:
      handleHTTPCmd_notSupported();
      fIsActive = false; // triggers deletion of ourself
      return false;
    }
#ifdef DEBUG
    fprintf(stderr, "Handled HTTP \"POST\" request (client input socket: %d)\n", fClientInputSocket);
#endif
    
    // Change the previous "RTSPClientSession" object's input socket to ours.  It will be used for subsequent requests:
    prevClientConnection->changeClientInputSocket(fClientInputSocket, extraData, extraDataSize);
    fClientInputSocket = fClientOutputSocket = -1; // so the socket doesn't get closed when we get deleted
    return true;
  }
  
  void RTSPServer::RTSPClientConnection::handleHTTPCmd_StreamingGET(char const* /*urlSuffix*/, char const* /*fullRequestStr*/) {
    // By default, we don't support requests to access streams via HTTP:
    handleHTTPCmd_notSupported();
  }
  
  void RTSPServer::RTSPClientConnection::resetRequestBuffer() {
    RTSPClientConnection::resetRequestBuffer();
    
    fLastCRLF = &fRequestBuffer[-3]; // hack: Ensures that we don't think we have end-of-msg if the data starts with <CR><LF>
    fBase64RemainderCount = 0;
  }
  
  void RTSPServer::RTSPClientConnection::closeSocketsRTSP() {
    // First, tell our server to stop any streaming that it might be doing over our output socket:
    fOurRTSPServer.stopTCPStreamingOnSocket(fClientOutputSocket);
    
    // Turn off background handling on our input socket (and output socket, if different); then close it (or them):
    if (fClientOutputSocket != fClientInputSocket) {
      //to do envir().taskScheduler().disableBackgroundHandling(fClientOutputSocket);
      close(fClientOutputSocket);
    }
    fClientOutputSocket = -1;
    
    closeSockets(); // closes fClientInputSocket
  }
  
  void RTSPServer::RTSPClientConnection::handleAlternativeRequestByte(void* instance, u_int8_t requestByte) {
    RTSPClientConnection* connection = (RTSPClientConnection*)instance;
    connection->handleAlternativeRequestByte1(requestByte);
  }
  
  void RTSPServer::RTSPClientConnection::handleAlternativeRequestByte1(u_int8_t requestByte) {
    if (requestByte == 0xFF) {
      // Hack: The new handler of the input TCP socket encountered an error reading it.  Indicate this:
      handleRequestBytes(-1);
    } else if (requestByte == 0xFE) {
      // Another hack: The new handler of the input TCP socket no longer needs it, so take back control of it:
      // to do task envir().taskScheduler().setBackgroundHandling(fClientInputSocket, SOCKET_READABLE|SOCKET_EXCEPTION, incomingRequestHandler, this);
    } else {
      // Normal case: Add this character to our buffer; then try to handle the data that we have buffered so far:
      if (fRequestBufferBytesLeft == 0 || fRequestBytesAlreadySeen >= REQUEST_BUFFER_SIZE) return;
      fRequestBuffer[fRequestBytesAlreadySeen] = requestByte;
      handleRequestBytes(1);
    }
  }
  
  void RTSPServer::RTSPClientConnection::handleRequestBytes(int newBytesRead) {
    int numBytesRemaining = 0;
    ++fRecursionCount;
    
    do {
      igtl::RTSPServer::RTSPClientSession* clientSession = NULL;
      
      if (newBytesRead < 0 || (unsigned)newBytesRead >= fRequestBufferBytesLeft) {
        // Either the client socket has died, or the request was too big for us.
        // Terminate this connection:
#ifdef DEBUG
        fprintf(stderr, "RTSPClientConnection[%p]::handleRequestBytes() read %d new bytes (of %d); terminating connection!\n", this, newBytesRead, fRequestBufferBytesLeft);
#endif
        fIsActive = false;
        break;
      }
      
      bool endOfMsg = false;
      unsigned char* ptr = &fRequestBuffer[fRequestBytesAlreadySeen];
#ifdef DEBUG
      ptr[newBytesRead] = '\0';
      fprintf(stderr, "RTSPClientConnection[%p]::handleRequestBytes() %s %d new bytes:%s\n",
              this, numBytesRemaining > 0 ? "processing" : "read", newBytesRead, ptr);
#endif
      
      if (fClientOutputSocket != fClientInputSocket && numBytesRemaining == 0) {
        // We're doing RTSP-over-HTTP tunneling, and input commands are assumed to have been Base64-encoded.
        // We therefore Base64-decode as much of this new data as we can (i.e., up to a multiple of 4 bytes).
        
        // But first, we remove any whitespace that may be in the input data:
        unsigned toIndex = 0;
        for (int fromIndex = 0; fromIndex < newBytesRead; ++fromIndex) {
          char c = ptr[fromIndex];
          if (!(c == ' ' || c == '\t' || c == '\r' || c == '\n')) { // not 'whitespace': space,tab,CR,NL
            ptr[toIndex++] = c;
          }
        }
        newBytesRead = toIndex;
        
        unsigned numBytesToDecode = fBase64RemainderCount + newBytesRead;
        unsigned newBase64RemainderCount = numBytesToDecode%4;
        numBytesToDecode -= newBase64RemainderCount;
        if (numBytesToDecode > 0) {
          ptr[newBytesRead] = '\0';
          unsigned decodedSize;
          unsigned char* decodedBytes = base64Decode((char const*)(ptr-fBase64RemainderCount), numBytesToDecode, decodedSize);
#ifdef DEBUG
          fprintf(stderr, "Base64-decoded %d input bytes into %d new bytes:", numBytesToDecode, decodedSize);
          for (unsigned k = 0; k < decodedSize; ++k) fprintf(stderr, "%c", decodedBytes[k]);
          fprintf(stderr, "\n");
#endif
          
          // Copy the new decoded bytes in place of the old ones (we can do this because there are fewer decoded bytes than original):
          unsigned char* to = ptr-fBase64RemainderCount;
          for (unsigned i = 0; i < decodedSize; ++i) *to++ = decodedBytes[i];
          
          // Then copy any remaining (undecoded) bytes to the end:
          for (unsigned j = 0; j < newBase64RemainderCount; ++j) *to++ = (ptr-fBase64RemainderCount+numBytesToDecode)[j];
          
          newBytesRead = decodedSize - fBase64RemainderCount + newBase64RemainderCount;
          // adjust to allow for the size of the new decoded data (+ remainder)
          delete[] decodedBytes;
        }
        fBase64RemainderCount = newBase64RemainderCount;
      }
      
      unsigned char* tmpPtr = fLastCRLF + 2;
      if (fBase64RemainderCount == 0) { // no more Base-64 bytes remain to be read/decoded
        // Look for the end of the message: <CR><LF><CR><LF>
        if (tmpPtr < fRequestBuffer) tmpPtr = fRequestBuffer;
        while (tmpPtr < &ptr[newBytesRead-1]) {
          if (*tmpPtr == '\r' && *(tmpPtr+1) == '\n') {
            if (tmpPtr - fLastCRLF == 2) { // This is it:
              endOfMsg = true;
              break;
            }
            fLastCRLF = tmpPtr;
          }
          ++tmpPtr;
        }
      }
      
      fRequestBufferBytesLeft -= newBytesRead;
      fRequestBytesAlreadySeen += newBytesRead;
      
      if (!endOfMsg) break; // subsequent reads will be needed to complete the request
      
      // Parse the request string into command name and 'CSeq', then handle the command:
      fRequestBuffer[fRequestBytesAlreadySeen] = '\0';
      char cmdName[RTSP_PARAM_STRING_MAX];
      char urlPreSuffix[RTSP_PARAM_STRING_MAX];
      char urlSuffix[RTSP_PARAM_STRING_MAX];
      char cseq[RTSP_PARAM_STRING_MAX];
      char sessionIdStr[RTSP_PARAM_STRING_MAX];
      unsigned contentLength = 0;
      fLastCRLF[2] = '\0'; // temporarily, for parsing
      bool parseSucceeded = parseRTSPRequestString((char*)fRequestBuffer, fLastCRLF+2 - fRequestBuffer,
                                                      cmdName, sizeof cmdName,
                                                      urlPreSuffix, sizeof urlPreSuffix,
                                                      urlSuffix, sizeof urlSuffix,
                                                      cseq, sizeof cseq,
                                                      sessionIdStr, sizeof sessionIdStr,
                                                      contentLength);
      fLastCRLF[2] = '\r'; // restore its value
      bool playAfterSetup = false;
      if (parseSucceeded) {
#ifdef DEBUG
        fprintf(stderr, "parseRTSPRequestString() succeeded, returning cmdName \"%s\", urlPreSuffix \"%s\", urlSuffix \"%s\", CSeq \"%s\", Content-Length %u, with %d bytes following the message.\n", cmdName, urlPreSuffix, urlSuffix, cseq, contentLength, ptr + newBytesRead - (tmpPtr + 2));
#endif
        // If there was a "Content-Length:" header, then make sure we've received all of the data that it specified:
        if (ptr + newBytesRead < tmpPtr + 2 + contentLength) break; // we still need more data; subsequent reads will give it to us
        
        // If the request included a "Session:" id, and it refers to a client session that's
        // current ongoing, then use this command to indicate 'liveness' on that client session:
        bool const requestIncludedSessionId = sessionIdStr[0] != '\0';
        if (requestIncludedSessionId) {
          clientSession
          = (RTSPServer::RTSPClientSession*)(fOurRTSPServer.fClientSessions->Lookup(sessionIdStr));
          if (clientSession != NULL) clientSession->noteLiveness();
        }
        
        // We now have a complete RTSP request.
        // Handle the specified command (beginning with commands that are session-independent):
        fCurrentCSeq = cseq;
        if (strcmp(cmdName, "OPTIONS") == 0) {
          // If the "OPTIONS" command included a "Session:" id for a session that doesn't exist,
          // then treat this as an error:
          if (requestIncludedSessionId && clientSession == NULL) {
            handleCmd_sessionNotFound();
          } else {
            // Normal case:
            handleCmd_OPTIONS();
          }
        } else if (urlPreSuffix[0] == '\0' && urlSuffix[0] == '*' && urlSuffix[1] == '\0') {
          // The special "*" URL means: an operation on the entire server.  This works only for GET_PARAMETER and SET_PARAMETER:
          if (strcmp(cmdName, "GET_PARAMETER") == 0) {
            handleCmd_GET_PARAMETER((char const*)fRequestBuffer);
          } else if (strcmp(cmdName, "SET_PARAMETER") == 0) {
            handleCmd_SET_PARAMETER((char const*)fRequestBuffer);
          } else {
            handleCmd_notSupported();
          }
        } else if (strcmp(cmdName, "DESCRIBE") == 0) {
          handleCmd_DESCRIBE(urlPreSuffix, urlSuffix, (char const*)fRequestBuffer);
        } else if (strcmp(cmdName, "SETUP") == 0) {
          bool areAuthenticated = true;
          
          if (!requestIncludedSessionId) {
            // No session id was present in the request.
            // So create a new "RTSPClientSession" object for this request.
            
            // But first, make sure that we're authenticated to perform this command:
            char urlTotalSuffix[2*RTSP_PARAM_STRING_MAX];
            // enough space for urlPreSuffix/urlSuffix'\0'
            urlTotalSuffix[0] = '\0';
            if (urlPreSuffix[0] != '\0') {
              strcat(urlTotalSuffix, urlPreSuffix);
              strcat(urlTotalSuffix, "/");
            }
            strcat(urlTotalSuffix, urlSuffix);
            if (authenticationOK("SETUP", urlTotalSuffix, (char const*)fRequestBuffer)) {
              clientSession
              = (RTSPServer::RTSPClientSession*)fOurRTSPServer.createNewClientSessionWithId();
            } else {
              areAuthenticated = false;
            }
          }
          if (clientSession != NULL) {
            clientSession->handleCmd_SETUP(this, urlPreSuffix, urlSuffix, (char const*)fRequestBuffer);
            playAfterSetup = clientSession->fStreamAfterSETUP;
          } else if (areAuthenticated) {
            handleCmd_sessionNotFound();
          }
        } else if (strcmp(cmdName, "TEARDOWN") == 0
                   || strcmp(cmdName, "PLAY") == 0
                   || strcmp(cmdName, "PAUSE") == 0
                   || strcmp(cmdName, "GET_PARAMETER") == 0
                   || strcmp(cmdName, "SET_PARAMETER") == 0) {
          if (clientSession != NULL) {
            clientSession->handleCmd_withinSession(this, cmdName, urlPreSuffix, urlSuffix, (char const*)fRequestBuffer);
          } else {
            handleCmd_sessionNotFound();
          }
        } else if (strcmp(cmdName, "REGISTER") == 0 || strcmp(cmdName, "DEREGISTER") == 0) {
          // Because - unlike other commands - an implementation of this command needs
          // the entire URL, we re-parse the command to get it:
          size_t len = REQUEST_BUFFER_SIZE + 1;
          char* copy = new char[len];
          memcpy(copy, fRequestBuffer, len);
          char* url = (char*)copy;
          if (sscanf((char*)fRequestBuffer, "%*s %s", url) == 1) {
            // Check for special command-specific parameters in a "Transport:" header:
            bool reuseConnection, deliverViaTCP;
            char* proxyURLSuffix;
            //parseTransportHeaderForREGISTER((const char*)fRequestBuffer, reuseConnection, deliverViaTCP, proxyURLSuffix);
            
            handleCmd_REGISTER(cmdName, url, urlSuffix, (char const*)fRequestBuffer, reuseConnection, deliverViaTCP, proxyURLSuffix);
            delete[] proxyURLSuffix;
          } else {
            handleCmd_bad();
          }
          delete[] url;
        } else {
          // The command is one that we don't handle:
          handleCmd_notSupported();
        }
      } else {
#ifdef DEBUG
        fprintf(stderr, "parseRTSPRequestString() failed; checking now for HTTP commands (for RTSP-over-HTTP tunneling)...\n");
#endif
        // The request was not (valid) RTSP, but check for a special case: HTTP commands (for setting up RTSP-over-HTTP tunneling):
        char sessionCookie[RTSP_PARAM_STRING_MAX];
        char acceptStr[RTSP_PARAM_STRING_MAX];
        *fLastCRLF = '\0'; // temporarily, for parsing
        parseSucceeded = parseHTTPRequestString(cmdName, sizeof cmdName,
                                                urlSuffix, sizeof urlPreSuffix,
                                                sessionCookie, sizeof sessionCookie,
                                                acceptStr, sizeof acceptStr);
        *fLastCRLF = '\r';
        if (parseSucceeded) {
#ifdef DEBUG
          fprintf(stderr, "parseHTTPRequestString() succeeded, returning cmdName \"%s\", urlSuffix \"%s\", sessionCookie \"%s\", acceptStr \"%s\"\n", cmdName, urlSuffix, sessionCookie, acceptStr);
#endif
          // Check that the HTTP command is valid for RTSP-over-HTTP tunneling: There must be a 'session cookie'.
          bool isValidHTTPCmd = true;
          if (strcmp(cmdName, "OPTIONS") == 0) {
            handleHTTPCmd_OPTIONS();
          } else if (sessionCookie[0] == '\0') {
            // There was no "x-sessioncookie:" header.  If there was an "Accept: application/x-rtsp-tunnelled" header,
            // then this is a bad tunneling request.  Otherwise, assume that it's an attempt to access the stream via HTTP.
            if (strcmp(acceptStr, "application/x-rtsp-tunnelled") == 0) {
              isValidHTTPCmd = false;
            } else {
              handleHTTPCmd_StreamingGET(urlSuffix, (char const*)fRequestBuffer);
            }
          } else if (strcmp(cmdName, "GET") == 0) {
            handleHTTPCmd_TunnelingGET(sessionCookie);
          } else if (strcmp(cmdName, "POST") == 0) {
            // We might have received additional data following the HTTP "POST" command - i.e., the first Base64-encoded RTSP command.
            // Check for this, and handle it if it exists:
            unsigned char const* extraData = fLastCRLF+4;
            unsigned extraDataSize = &fRequestBuffer[fRequestBytesAlreadySeen] - extraData;
            if (handleHTTPCmd_TunnelingPOST(sessionCookie, extraData, extraDataSize)) {
              // We don't respond to the "POST" command, and we go away:
              fIsActive = false;
              break;
            }
          } else {
            isValidHTTPCmd = false;
          }
          if (!isValidHTTPCmd) {
            handleHTTPCmd_notSupported();
          }
        } else {
#ifdef DEBUG
          fprintf(stderr, "parseHTTPRequestString() failed!\n");
#endif
          handleCmd_bad();
        }
      }
      
#ifdef DEBUG
      fprintf(stderr, "sending response: %s", fResponseBuffer);
#endif
      send(fClientOutputSocket, (char const*)fResponseBuffer, strlen((char*)fResponseBuffer), 0);
      
      if (playAfterSetup) {
        // The client has asked for streaming to commence now, rather than after a
        // subsequent "PLAY" command.  So, simulate the effect of a "PLAY" command:
        clientSession->handleCmd_withinSession(this, "PLAY", urlPreSuffix, urlSuffix, (char const*)fRequestBuffer);
      }
      
      // Check whether there are extra bytes remaining in the buffer, after the end of the request (a rare case).
      // If so, move them to the front of our buffer, and keep processing it, because it might be a following, pipelined request.
      unsigned requestSize = (fLastCRLF+4-fRequestBuffer) + contentLength;
      numBytesRemaining = fRequestBytesAlreadySeen - requestSize;
      resetRequestBuffer(); // to prepare for any subsequent request
      
      if (numBytesRemaining > 0) {
        memmove(fRequestBuffer, &fRequestBuffer[requestSize], numBytesRemaining);
        newBytesRead = numBytesRemaining;
      }
    } while (numBytesRemaining > 0);
    
    --fRecursionCount;
    if (!fIsActive) {
      if (fRecursionCount > 0) closeSockets(); else delete this;
      // Note: The "fRecursionCount" test is for a pathological situation where we reenter the event loop and get called recursively
      // while handling a command (e.g., while handling a "DESCRIBE", to get a SDP description).
      // In such a case we don't want to actually delete ourself until we leave the outermost call.
    }
  }
  
  RTSPServer::RTSPClientSession* RTSPServer::createNewClientSessionWithId() {
    u_int32_t sessionId;
    char sessionIdStr[8+1];
    
    // Choose a random (unused) 32-bit integer for the session id
    // (it will be encoded as a 8-digit hex number).  (We avoid choosing session id 0,
    // because that has a special use by some servers.)
    
    do {
      sessionId = (igtl_uint32)our_random32();
      snprintf(sessionIdStr, sizeof sessionIdStr, "%08X", sessionId);
      char sessionIdStr[8+1];
      snprintf(sessionIdStr, sizeof sessionIdStr, "%08X", sessionId);
      
    } while (sessionId == 0 || (RTSPServer::RTSPClientSession*)fClientSessions->Lookup(sessionIdStr) != NULL);
    
    RTSPServer::RTSPClientSession* clientSession = createNewClientSession(sessionId);
    if (clientSession != NULL) fClientSessions->Add(sessionIdStr, clientSession);
    
    return clientSession;
  }
  static bool parseAuthorizationHeader(char const* buf,
                                          char const*& username,
                                          char const*& realm,
                                          char const*& nonce, char const*& uri,
                                          char const*& response) {
    // Initialize the result parameters to default values:
    username = realm = nonce = uri = response = NULL;
    
    // First, find "Authorization:"
    while (1) {
      if (*buf == '\0') return false; // not found
      if (_strncasecmp(buf, "Authorization: Digest ", 22) == 0) break;
      ++buf;
    }
    
    // Then, run through each of the fields, looking for ones we handle:
    char const* fields = buf + 22;
    while (*fields == ' ') ++fields;
    char* parameter = strDupSize(fields);
    char* value = strDupSize(fields);
    while (1) {
      value[0] = '\0';
      if (sscanf(fields, "%[^=]=\"%[^\"]\"", parameter, value) != 2 &&
          sscanf(fields, "%[^=]=\"\"", parameter) != 1) {
        break;
      }
      if (strcmp(parameter, "username") == 0) {
        username = strDup(value);
      } else if (strcmp(parameter, "realm") == 0) {
        realm = strDup(value);
      } else if (strcmp(parameter, "nonce") == 0) {
        nonce = strDup(value);
      } else if (strcmp(parameter, "uri") == 0) {
        uri = strDup(value);
      } else if (strcmp(parameter, "response") == 0) {
        response = strDup(value);
      }
      
      fields += strlen(parameter) + 2 /*="*/ + strlen(value) + 1 /*"*/;
      while (*fields == ',' || *fields == ' ') ++fields;
      // skip over any separating ',' and ' ' chars
      if (*fields == '\0' || *fields == '\r' || *fields == '\n') break;
    }
    delete[] parameter; delete[] value;
    return true;
  }
  
  bool RTSPServer::RTSPClientConnection
  ::authenticationOK(char const* cmdName, char const* urlSuffix, char const* fullRequestStr) {
    if (!fOurRTSPServer.specialClientAccessCheck(fClientInputSocket, fClientAddr, urlSuffix)) {
      setRTSPResponse("401 Unauthorized");
      return false;
    }
    
    // If we weren't set up with an authentication database, we're OK:
    UserAuthenticationDatabase* authDB = fOurRTSPServer.getAuthenticationDatabaseForCommand(cmdName);
    if (authDB == NULL) return true;
    
    char const* username = NULL; char const* realm = NULL; char const* nonce = NULL;
    char const* uri = NULL; char const* response = NULL;
    bool success = false;
    
    do {
      // To authenticate, we first need to have a nonce set up
      // from a previous attempt:
      if (fCurrentAuthenticator.nonce() == NULL) break;
      
      // Next, the request needs to contain an "Authorization:" header,
      // containing a username, (our) realm, (our) nonce, uri,
      // and response string:
      if (!parseAuthorizationHeader(fullRequestStr,
                                    username, realm, nonce, uri, response)
          || username == NULL
          || realm == NULL || strcmp(realm, fCurrentAuthenticator.realm()) != 0
          || nonce == NULL || strcmp(nonce, fCurrentAuthenticator.nonce()) != 0
          || uri == NULL || response == NULL) {
        break;
      }
      
      // Next, the username has to be known to us:
      char const* password = authDB->lookupPassword(username);
#ifdef DEBUG
      fprintf(stderr, "lookupPassword(%s) returned password %s\n", username, password);
#endif
      if (password == NULL) break;
      fCurrentAuthenticator.setUsernameAndPassword(username, password, authDB->passwordsAreMD5());
      
      // Finally, compute a digest response from the information that we have,
      // and compare it to the one that we were given:
      char const* ourResponse
      = fCurrentAuthenticator.computeDigestResponse(cmdName, uri);
      success = (strcmp(ourResponse, response) == 0);
      fCurrentAuthenticator.reclaimDigestResponse(ourResponse);
    } while (0);
    
    delete[] (char*)realm; delete[] (char*)nonce;
    delete[] (char*)uri; delete[] (char*)response;
    
    if (success) {
      // The user has been authenticated.
      // Now allow subclasses a chance to validate the user against the IP address and/or URL suffix.
      if (!fOurRTSPServer.specialClientUserAccessCheck(fClientInputSocket, fClientAddr, urlSuffix, username)) {
        // Note: We don't return a "WWW-Authenticate" header here, because the user is valid,
        // even though the server has decided that they should not have access.
        setRTSPResponse("401 Unauthorized");
        delete[] (char*)username;
        return false;
      }
    }
    delete[] (char*)username;
    if (success) return true;
    
    // If we get here, we failed to authenticate the user.
    // Send back a "401 Unauthorized" response, with a new random nonce:
    fCurrentAuthenticator.setRealmAndRandomNonce(authDB->realm());
    snprintf((char*)fResponseBuffer, sizeof fResponseBuffer,
             "RTSP/1.0 401 Unauthorized\r\n"
             "CSeq: %s\r\n"
             "%s"
             "WWW-Authenticate: Digest realm=\"%s\", nonce=\"%s\"\r\n\r\n",
             fCurrentCSeq,
             dateHeader(),
             fCurrentAuthenticator.realm(), fCurrentAuthenticator.nonce());
    return false;
  }
  
  void RTSPServer::RTSPClientConnection
  ::setRTSPResponse(char const* responseStr) {
    snprintf((char*)fResponseBuffer, sizeof fResponseBuffer,
             "RTSP/1.0 %s\r\n"
             "CSeq: %s\r\n"
             "%s\r\n",
             responseStr,
             fCurrentCSeq,
             dateHeader());
  }
  
  void RTSPServer::RTSPClientConnection
  ::setRTSPResponse(char const* responseStr, u_int32_t sessionId) {
    snprintf((char*)fResponseBuffer, sizeof fResponseBuffer,
             "RTSP/1.0 %s\r\n"
             "CSeq: %s\r\n"
             "%s"
             "Session: %08X\r\n\r\n",
             responseStr,
             fCurrentCSeq,
             dateHeader(),
             sessionId);
  }
  
  void RTSPServer::RTSPClientConnection
  ::setRTSPResponse(char const* responseStr, char const* contentStr) {
    if (contentStr == NULL) contentStr = "";
    unsigned const contentLen = strlen(contentStr);
    
    snprintf((char*)fResponseBuffer, sizeof fResponseBuffer,
             "RTSP/1.0 %s\r\n"
             "CSeq: %s\r\n"
             "%s"
             "Content-Length: %d\r\n\r\n"
             "%s",
             responseStr,
             fCurrentCSeq,
             dateHeader(),
             contentLen,
             contentStr);
  }
  
  void RTSPServer::RTSPClientConnection
  ::setRTSPResponse(char const* responseStr, u_int32_t sessionId, char const* contentStr) {
    if (contentStr == NULL) contentStr = "";
    unsigned const contentLen = strlen(contentStr);
    
    snprintf((char*)fResponseBuffer, sizeof fResponseBuffer,
             "RTSP/1.0 %s\r\n"
             "CSeq: %s\r\n"
             "%s"
             "Session: %08X\r\n"
             "Content-Length: %d\r\n\r\n"
             "%s",
             responseStr,
             fCurrentCSeq,
             dateHeader(),
             sessionId,
             contentLen,
             contentStr);
  }
  
  void RTSPServer::RTSPClientConnection
  ::changeClientInputSocket(int newSocketNum, unsigned char const* extraData, unsigned extraDataSize) {
    //envir().taskScheduler().disableBackgroundHandling(fClientInputSocket);
    fClientInputSocket = newSocketNum;
    //envir().taskScheduler().setBackgroundHandling(fClientInputSocket, SOCKET_READABLE|SOCKET_EXCEPTION, incomingRequestHandler, this);
    
    // Also write any extra data to our buffer, and handle it:
    if (extraDataSize > 0 && extraDataSize <= fRequestBufferBytesLeft/*sanity check; should always be true*/) {
      unsigned char* ptr = &fRequestBuffer[fRequestBytesAlreadySeen];
      for (unsigned i = 0; i < extraDataSize; ++i) {
        ptr[i] = extraData[i];
      }
      handleRequestBytes(extraDataSize);
    }
  }
  
  
  ////////// RTSPServer::RTSPClientSession implementation //////////
  
  RTSPServer::RTSPClientSession
  ::RTSPClientSession(RTSPServer& ourServer, u_int32_t sessionId)
  : fOurSessionId(sessionId),
  fLivenessCheckTask(NULL),
  fOurRTSPServer(ourServer), fIsMulticast(false), fStreamAfterSETUP(false),
  fTCPStreamIdCount(0), fNumStreamStates(0), fStreamStates(NULL) {
    /*
     #ifdef DEBUG
     char const* streamName
     = (fOurServerMediaSession == NULL) ? "???" : fOurServerMediaSession->streamName();
     fprintf(stderr, "Client session (id \"%08X\", stream name \"%s\"): Liveness indication\n",
     fOurSessionId, streamName);
     #endif
     if (fOurServerMediaSession != NULL) fOurServerMediaSession->noteLiveness();
     
     if (fOurServer.fReclamationSeconds > 0) {
     envir().taskScheduler().rescheduleDelayedTask(fLivenessCheckTask,
     fOurServer.fReclamationSeconds*1000000,
     (TaskFunc*)livenessTimeoutTask, this);
     }*/
  }
  
  RTSPServer::RTSPClientSession::~RTSPClientSession() {
    reclaimStreamStates();
  }
  
  void RTSPServer::RTSPClientSession::deleteStreamByTrack(unsigned trackNum) {
    if (trackNum >= fNumStreamStates) return; // sanity check; shouldn't happen
    /*if (fStreamStates[trackNum].subsession != NULL) {
      fStreamStates[trackNum].subsession->deleteStream(fOurSessionId, fStreamStates[trackNum].streamToken);
      fStreamStates[trackNum].subsession = NULL;
    }
    
    // Optimization: If all subsessions have now been deleted, then we can delete ourself now:
    bool noSubsessionsRemain = true;
    for (unsigned i = 0; i < fNumStreamStates; ++i) {
      if (fStreamStates[i].subsession != NULL) {
        noSubsessionsRemain = false;
        break;
      }
    }
    if (noSubsessionsRemain) delete this;*/
  }
  
  void RTSPServer::RTSPClientSession::reclaimStreamStates() {
    for (unsigned i = 0; i < fNumStreamStates; ++i) {
      //if (fStreamStates[i].subsession != NULL) {
        fOurRTSPServer.unnoteTCPStreamingOnSocket(fStreamStates[i].tcpSocketNum, this, i);
        //fStreamStates[i].subsession->deleteStream(fOurSessionId, fStreamStates[i].streamToken);
      //}
    }
    delete[] fStreamStates; fStreamStates = NULL;
    fNumStreamStates = 0;
  }
  
  typedef enum StreamingMode {
    RTP_UDP,
    RTP_TCP,
    RAW_UDP
  } StreamingMode;
  
  static void parseTransportHeader(char const* buf,
                                   StreamingMode& streamingMode,
                                   char*& streamingModeString,
                                   char*& destinationAddressStr,
                                   u_int8_t& destinationTTL,
                                   igtl_uint16& clientRTPPortNum, // if UDP
                                   igtl_uint16& clientRTCPPortNum, // if UDP
                                   unsigned char& rtpChannelId, // if TCP
                                   unsigned char& rtcpChannelId // if TCP
  ) {
    // Initialize the result parameters to default values:
    streamingMode = RTP_UDP;
    streamingModeString = NULL;
    destinationAddressStr = NULL;
    destinationTTL = 255;
    clientRTPPortNum = 0;
    clientRTCPPortNum = 1;
    rtpChannelId = rtcpChannelId = 0xFF;
    
    igtl_uint16 p1, p2;
    unsigned ttl, rtpCid, rtcpCid;
    
    // First, find "Transport:"
    while (1) {
      if (*buf == '\0') return; // not found
      if (*buf == '\r' && *(buf+1) == '\n' && *(buf+2) == '\r') return; // end of the headers => not found
      if (_strncasecmp(buf, "Transport:", 10) == 0) break;
      ++buf;
    }
    
    // Then, run through each of the fields, looking for ones we handle:
    char const* fields = buf + 10;
    while (*fields == ' ') ++fields;
    char* field = strDupSize(fields);
    while (sscanf(fields, "%[^;\r\n]", field) == 1) {
      if (strcmp(field, "RTP/AVP/TCP") == 0) {
        streamingMode = RTP_TCP;
      } else if (strcmp(field, "RAW/RAW/UDP") == 0 ||
                 strcmp(field, "MP2T/H2221/UDP") == 0) {
        streamingMode = RAW_UDP;
        streamingModeString = strDup(field);
      } else if (_strncasecmp(field, "destination=", 12) == 0) {
        delete[] destinationAddressStr;
        destinationAddressStr = strDup(field+12);
      } else if (sscanf(field, "ttl%u", &ttl) == 1) {
        destinationTTL = (u_int8_t)ttl;
      } else if (sscanf(field, "client_port=%hu-%hu", &p1, &p2) == 2) {
        clientRTPPortNum = p1;
        clientRTCPPortNum = streamingMode == RAW_UDP ? 0 : p2; // ignore the second port number if the client asked for raw UDP
      } else if (sscanf(field, "client_port=%hu", &p1) == 1) {
        clientRTPPortNum = p1;
        clientRTCPPortNum = streamingMode == RAW_UDP ? 0 : p1 + 1;
      } else if (sscanf(field, "interleaved=%u-%u", &rtpCid, &rtcpCid) == 2) {
        rtpChannelId = (unsigned char)rtpCid;
        rtcpChannelId = (unsigned char)rtcpCid;
      }
      
      fields += strlen(field);
      while (*fields == ';' || *fields == ' ' || *fields == '\t') ++fields; // skip over separating ';' chars or whitespace
      if (*fields == '\0' || *fields == '\r' || *fields == '\n') break;
    }
    delete[] field;
  }
  
  static bool parsePlayNowHeader(char const* buf) {
    // Find "x-playNow:" header, if present
    while (1) {
      if (*buf == '\0') return false; // not found
      if (_strncasecmp(buf, "x-playNow:", 10) == 0) break;
      ++buf;
    }
    
    return true;
  }
  
  void RTSPServer::RTSPClientSession
  ::handleCmd_SETUP(RTSPServer::RTSPClientConnection* ourClientConnection,
                    char const* urlPreSuffix, char const* urlSuffix, char const* fullRequestStr) {
    // Normally, "urlPreSuffix" should be the session (stream) name, and "urlSuffix" should be the subsession (track) name.
    // However (being "liberal in what we accept"), we also handle 'aggregate' SETUP requests (i.e., without a track name),
    // in the special case where we have only a single track.  I.e., in this case, we also handle:
    //    "urlPreSuffix" is empty and "urlSuffix" is the session (stream) name, or
    //    "urlPreSuffix" concatenated with "urlSuffix" (with "/" inbetween) is the session (stream) name.
    char const* streamName = urlPreSuffix; // in the normal case
    char const* trackId = urlSuffix; // in the normal case
    char* concatenatedStreamName = NULL; // in the normal case
    
    do {
      // First, make sure the specified stream name exists:
      /*ServerMediaSession* sms = fOurServer.lookupServerMediaSession(streamName, fOurServerMediaSession == NULL);
      if (sms == NULL) {
        // Check for the special case (noted above), before we give up:
        if (urlPreSuffix[0] == '\0') {
          streamName = urlSuffix;
        } else {
          concatenatedStreamName = new char[strlen(urlPreSuffix) + strlen(urlSuffix) + 2]; // allow for the "/" and the trailing '\0'
          sprintf(concatenatedStreamName, "%s/%s", urlPreSuffix, urlSuffix);
          streamName = concatenatedStreamName;
        }
        trackId = NULL;
        
        // Check again:
        sms = fOurServer.lookupServerMediaSession(streamName, fOurServerMediaSession == NULL);
      }
      if (sms == NULL) {
        if (fOurServerMediaSession == NULL) {
          // The client asked for a stream that doesn't exist (and this session descriptor has not been used before):
          ourClientConnection->handleCmd_notFound();
        } else {
          // The client asked for a stream that doesn't exist, but using a stream id for a stream that does exist. Bad request:
          ourClientConnection->handleCmd_bad();
        }
        break;
      } else {
        if (fOurServerMediaSession == NULL) {
          // We're accessing the "ServerMediaSession" for the first time.
          fOurServerMediaSession = sms;
          fOurServerMediaSession->incrementReferenceCount();
        } else if (sms != fOurServerMediaSession) {
          // The client asked for a stream that's different from the one originally requested for this stream id.  Bad request:
          ourClientConnection->handleCmd_bad();
          break;
        }
      }
      
      if (fStreamStates == NULL) {
        // This is the first "SETUP" for this session.  Set up our array of states for all of this session's subsessions (tracks):
        fNumStreamStates = fOurServerMediaSession->numSubsessions();
        fStreamStates = new struct streamState[fNumStreamStates];
        
        ServerMediaSubsessionIterator iter(*fOurServerMediaSession);
        ServerMediaSubsession* subsession;
        for (unsigned i = 0; i < fNumStreamStates; ++i) {
          subsession = iter.next();
          fStreamStates[i].subsession = subsession;
          fStreamStates[i].tcpSocketNum = -1; // for now; may get set for RTP-over-TCP streaming
          fStreamStates[i].streamToken = NULL; // for now; it may be changed by the "getStreamParameters()" call that comes later
        }
      }
      
      // Look up information for the specified subsession (track):
      ServerMediaSubsession* subsession = NULL;
      unsigned trackNum;
      if (trackId != NULL && trackId[0] != '\0') { // normal case
        for (trackNum = 0; trackNum < fNumStreamStates; ++trackNum) {
          subsession = fStreamStates[trackNum].subsession;
          if (subsession != NULL && strcmp(trackId, subsession->trackId()) == 0) break;
        }
        if (trackNum >= fNumStreamStates) {
          // The specified track id doesn't exist, so this request fails:
          ourClientConnection->handleCmd_notFound();
          break;
        }
      } else {
        // Weird case: there was no track id in the URL.
        // This works only if we have only one subsession:
        if (fNumStreamStates != 1 || fStreamStates[0].subsession == NULL) {
          ourClientConnection->handleCmd_bad();
          break;
        }
        trackNum = 0;
        subsession = fStreamStates[trackNum].subsession;
      }
      // ASSERT: subsession != NULL
      
      void*& token = fStreamStates[trackNum].streamToken; // alias
      if (token != NULL) {
        // We already handled a "SETUP" for this track (to the same client),
        // so stop any existing streaming of it, before we set it up again:
        subsession->pauseStream(fOurSessionId, token);
        fOurRTSPServer.unnoteTCPStreamingOnSocket(fStreamStates[trackNum].tcpSocketNum, this, trackNum);
        subsession->deleteStream(fOurSessionId, token);
      }
      */
      unsigned trackNum;
      // Look for a "Transport:" header in the request string, to extract client parameters:
      StreamingMode streamingMode;
      char* streamingModeString = NULL; // set when RAW_UDP streaming is specified
      char* clientsDestinationAddressStr;
      igtl_uint8 clientsDestinationTTL;
      igtl_uint16 clientRTPPortNum, clientRTCPPortNum;
      unsigned char rtpChannelId, rtcpChannelId;
      parseTransportHeader(fullRequestStr, streamingMode, streamingModeString,
                           clientsDestinationAddressStr, clientsDestinationTTL,
                           clientRTPPortNum, clientRTCPPortNum,
                           rtpChannelId, rtcpChannelId);
      if ((streamingMode == RTP_TCP && rtpChannelId == 0xFF) ||
          (streamingMode != RTP_TCP && ourClientConnection->fClientOutputSocket != ourClientConnection->fClientInputSocket)) {
        // An anomolous situation, caused by a buggy client.  Either:
        //     1/ TCP streaming was requested, but with no "interleaving=" fields.  (QuickTime Player sometimes does this.), or
        //     2/ TCP streaming was not requested, but we're doing RTSP-over-HTTP tunneling (which implies TCP streaming).
        // In either case, we assume TCP streaming, and set the RTP and RTCP channel ids to proper values:
        streamingMode = RTP_TCP;
        rtpChannelId = fTCPStreamIdCount; rtcpChannelId = fTCPStreamIdCount+1;
      }
      if (streamingMode == RTP_TCP) fTCPStreamIdCount += 2;
      
      Port clientRTPPort(clientRTPPortNum);
      Port clientRTCPPort(clientRTCPPortNum);
      
      // Next, check whether a "Range:" or "x-playNow:" header is present in the request.
      // This isn't legal, but some clients do this to combine "SETUP" and "PLAY":
      double rangeStart = 0.0, rangeEnd = 0.0;
      char* absStart = NULL; char* absEnd = NULL;
      bool startTimeIsNow;
      if (parseRangeHeader(fullRequestStr, rangeStart, rangeEnd, absStart, absEnd, startTimeIsNow)) {
        delete[] absStart; delete[] absEnd;
        fStreamAfterSETUP = true;
      } else if (parsePlayNowHeader(fullRequestStr)) {
        fStreamAfterSETUP = true;
      } else {
        fStreamAfterSETUP = false;
      }
      
      // Then, get server parameters from the 'subsession':
      if (streamingMode == RTP_TCP) {
        // Note that we'll be streaming over the RTSP TCP connection:
        fStreamStates[trackNum].tcpSocketNum = ourClientConnection->fClientOutputSocket;
        fOurRTSPServer.noteTCPStreamingOnSocket(fStreamStates[trackNum].tcpSocketNum, this, trackNum);
      }
      igtl_uint32 destinationAddress = 0;
      u_int8_t destinationTTL = 255;
#ifdef RTSP_ALLOW_CLIENT_DESTINATION_SETTING
      if (clientsDestinationAddressStr != NULL) {
        // Use the client-provided "destination" address.
        // Note: This potentially allows the server to be used in denial-of-service
        // attacks, so don't enable this code unless you're sure that clients are
        // trusted.
        destinationAddress = our_inet_addr(clientsDestinationAddressStr);
      }
      // Also use the client-provided TTL.
      destinationTTL = clientsDestinationTTL;
#endif
      delete[] clientsDestinationAddressStr;
      Port serverRTPPort(0);
      Port serverRTCPPort(0);
      
      // Make sure that we transmit on the same interface that's used by the client (in case we're a multi-homed server):
      struct sockaddr_in sourceAddr; SOCKLEN_T namelen = sizeof sourceAddr;
      //getsockname(ourClientConnection->fClientInputSocket, (struct sockaddr*)&sourceAddr, &namelen);
      igtl_uint32 origSendingInterfaceAddr = INADDR_ANY;
      igtl_uint32 origReceivingInterfaceAddr = INADDR_ANY;
      // NOTE: The following might not work properly, so we ifdef it out for now:
#ifdef HACK_FOR_MULTIHOMED_SERVERS
      ReceivingInterfaceAddr = SendingInterfaceAddr = sourceAddr.sin_addr.s_addr;
#endif
      
      /*subsession->getStreamParameters(fOurSessionId, ourClientConnection->fClientAddr.sin_addr.s_addr,
                                      clientRTPPort, clientRTCPPort,
                                      fStreamStates[trackNum].tcpSocketNum, rtpChannelId, rtcpChannelId,
                                      destinationAddress, destinationTTL, fIsMulticast,
                                      serverRTPPort, serverRTCPPort,
                                      fStreamStates[trackNum].streamToken);*/
      
      AddressString destAddrStr(destinationAddress);
      AddressString sourceAddrStr(sourceAddr);
      char timeoutParameterString[100];
      if (fOurRTSPServer.fReclamationSeconds > 0) {
        sprintf(timeoutParameterString, ";timeout=%u", fOurRTSPServer.fReclamationSeconds);
      } else {
        timeoutParameterString[0] = '\0';
      }
      if (fIsMulticast) {
        switch (streamingMode) {
          case RTP_UDP: {
            snprintf((char*)ourClientConnection->fResponseBuffer, sizeof ourClientConnection->fResponseBuffer,
                     "RTSP/1.0 200 OK\r\n"
                     "CSeq: %s\r\n"
                     "%s"
                     "Transport: RTP/AVP;multicast;destination=%s;source=%s;port=%d-%d;ttl=%d\r\n"
                     "Session: %08X%s\r\n\r\n",
                     ourClientConnection->fCurrentCSeq,
                     dateHeader(),
                     destAddrStr.val(), sourceAddrStr.val(), ntohs(serverRTPPort.num()), ntohs(serverRTCPPort.num()), destinationTTL,
                     fOurSessionId, timeoutParameterString);
            break;
          }
          case RTP_TCP: {
            // multicast streams can't be sent via TCP
            ourClientConnection->handleCmd_unsupportedTransport();
            break;
          }
          case RAW_UDP: {
            snprintf((char*)ourClientConnection->fResponseBuffer, sizeof ourClientConnection->fResponseBuffer,
                     "RTSP/1.0 200 OK\r\n"
                     "CSeq: %s\r\n"
                     "%s"
                     "Transport: %s;multicast;destination=%s;source=%s;port=%d;ttl=%d\r\n"
                     "Session: %08X%s\r\n\r\n",
                     ourClientConnection->fCurrentCSeq,
                     dateHeader(),
                     streamingModeString, destAddrStr.val(), sourceAddrStr.val(), ntohs(serverRTPPort.num()), destinationTTL,
                     fOurSessionId, timeoutParameterString);
            break;
          }
        }
      } else {
        switch (streamingMode) {
          case RTP_UDP: {
            snprintf((char*)ourClientConnection->fResponseBuffer, sizeof ourClientConnection->fResponseBuffer,
                     "RTSP/1.0 200 OK\r\n"
                     "CSeq: %s\r\n"
                     "%s"
                     "Transport: RTP/AVP;unicast;destination=%s;source=%s;client_port=%d-%d;server_port=%d-%d\r\n"
                     "Session: %08X%s\r\n\r\n",
                     ourClientConnection->fCurrentCSeq,
                     dateHeader(),
                     destAddrStr.val(), sourceAddrStr.val(), ntohs(clientRTPPort.num()), ntohs(clientRTCPPort.num()), ntohs(serverRTPPort.num()), ntohs(serverRTCPPort.num()),
                     fOurSessionId, timeoutParameterString);
            break;
          }
          case RTP_TCP: {
            if (!fOurRTSPServer.fAllowStreamingRTPOverTCP) {
              ourClientConnection->handleCmd_unsupportedTransport();
            } else {
              snprintf((char*)ourClientConnection->fResponseBuffer, sizeof ourClientConnection->fResponseBuffer,
                       "RTSP/1.0 200 OK\r\n"
                       "CSeq: %s\r\n"
                       "%s"
                       "Transport: RTP/AVP/TCP;unicast;destination=%s;source=%s;interleaved=%d-%d\r\n"
                       "Session: %08X%s\r\n\r\n",
                       ourClientConnection->fCurrentCSeq,
                       dateHeader(),
                       destAddrStr.val(), sourceAddrStr.val(), rtpChannelId, rtcpChannelId,
                       fOurSessionId, timeoutParameterString);
            }
            break;
          }
          case RAW_UDP: {
            snprintf((char*)ourClientConnection->fResponseBuffer, sizeof ourClientConnection->fResponseBuffer,
                     "RTSP/1.0 200 OK\r\n"
                     "CSeq: %s\r\n"
                     "%s"
                     "Transport: %s;unicast;destination=%s;source=%s;client_port=%d;server_port=%d\r\n"
                     "Session: %08X%s\r\n\r\n",
                     ourClientConnection->fCurrentCSeq,
                     dateHeader(),
                     streamingModeString, destAddrStr.val(), sourceAddrStr.val(), ntohs(clientRTPPort.num()), ntohs(serverRTPPort.num()),
                     fOurSessionId, timeoutParameterString);
            break;
          }
        }
      }
      delete[] streamingModeString;
    } while (0);
    
    delete[] concatenatedStreamName;
  }
  
  void RTSPServer::RTSPClientSession
  ::handleCmd_withinSession(RTSPServer::RTSPClientConnection* ourClientConnection,
                            char const* cmdName,
                            char const* urlPreSuffix, char const* urlSuffix,
                            char const* fullRequestStr) {
    // This will either be:
    // - a non-aggregated operation, if "urlPreSuffix" is the session (stream)
    //   name and "urlSuffix" is the subsession (track) name, or
    // - an aggregated operation, if "urlSuffix" is the session (stream) name,
    //   or "urlPreSuffix" is the session (stream) name, and "urlSuffix" is empty,
    //   or "urlPreSuffix" and "urlSuffix" are both nonempty, but when concatenated, (with "/") form the session (stream) name.
    // Begin by figuring out which of these it is:
    /*ServerMediaSubsession* subsession;
    
    if (fOurServerMediaSession == NULL) { // There wasn't a previous SETUP!
      ourClientConnection->handleCmd_notSupported();
      return;
    } else if (urlSuffix[0] != '\0' && strcmp(fOurServerMediaSession->streamName(), urlPreSuffix) == 0) {
      // Non-aggregated operation.
      // Look up the media subsession whose track id is "urlSuffix":
      ServerMediaSubsessionIterator iter(*fOurServerMediaSession);
      while ((subsession = iter.next()) != NULL) {
        if (strcmp(subsession->trackId(), urlSuffix) == 0) break; // success
      }
      if (subsession == NULL) { // no such track!
        ourClientConnection->handleCmd_notFound();
        return;
      }
    } else if (strcmp(fOurServerMediaSession->streamName(), urlSuffix) == 0 ||
               (urlSuffix[0] == '\0' && strcmp(fOurServerMediaSession->streamName(), urlPreSuffix) == 0)) {
      // Aggregated operation
      subsession = NULL;
    } else if (urlPreSuffix[0] != '\0' && urlSuffix[0] != '\0') {
      // Aggregated operation, if <urlPreSuffix>/<urlSuffix> is the session (stream) name:
      unsigned const urlPreSuffixLen = strlen(urlPreSuffix);
      if (strncmp(fOurServerMediaSession->streamName(), urlPreSuffix, urlPreSuffixLen) == 0 &&
          fOurServerMediaSession->streamName()[urlPreSuffixLen] == '/' &&
          strcmp(&(fOurServerMediaSession->streamName())[urlPreSuffixLen+1], urlSuffix) == 0) {
        subsession = NULL;
      } else {
        ourClientConnection->handleCmd_notFound();
        return;
      }
    } else { // the request doesn't match a known stream and/or track at all!
      ourClientConnection->handleCmd_notFound();
      return;
    }*/
    
    if (strcmp(cmdName, "TEARDOWN") == 0) {
      handleCmd_TEARDOWN(ourClientConnection);
    } else if (strcmp(cmdName, "PLAY") == 0) {
      handleCmd_PLAY(ourClientConnection, fullRequestStr);
    } else if (strcmp(cmdName, "PAUSE") == 0) {
      handleCmd_PAUSE(ourClientConnection);
    } else if (strcmp(cmdName, "GET_PARAMETER") == 0) {
      handleCmd_GET_PARAMETER(ourClientConnection, fullRequestStr);
    } else if (strcmp(cmdName, "SET_PARAMETER") == 0) {
      handleCmd_SET_PARAMETER(ourClientConnection, fullRequestStr);
    }
  }
  
  void RTSPServer::RTSPClientSession
  ::handleCmd_TEARDOWN(RTSPServer::RTSPClientConnection* ourClientConnection) {
    unsigned i;
    
    setRTSPResponse(ourClientConnection, "200 OK");
    
    // Optimization: If all subsessions have now been torn down, then we know that we can reclaim our object now.
    // (Without this optimization, however, this object would still get reclaimed later, as a result of a 'liveness' timeout.)
    bool noSubsessionsRemain = true;
    if (noSubsessionsRemain) delete this;
  }
  
  void RTSPServer::RTSPClientSession
  ::handleCmd_PLAY(RTSPServer::RTSPClientConnection* ourClientConnection,
                    char const* fullRequestStr) {
    char* rtspURL
    = fOurRTSPServer.rtspURL(ourClientConnection->fClientInputSocket);
    unsigned rtspURLSize = strlen(rtspURL);
    
    // Parse the client's "Scale:" header, if any:
    float scale;
    bool sawScaleHeader = parseScaleHeader(fullRequestStr, scale);
    
    char buf[100];
    char* scaleHeader;
    if (!sawScaleHeader) {
      buf[0] = '\0'; // Because we didn't see a Scale: header, don't send one back
    } else {
      sprintf(buf, "Scale: %f\r\n", scale);
    }
    scaleHeader = strDup(buf);
    
    // Parse the client's "Range:" header, if any:
    float duration = 0.0;
    double rangeStart = 0.0, rangeEnd = 0.0;
    char* absStart = NULL; char* absEnd = NULL;
    bool startTimeIsNow;
    bool sawRangeHeader
    = parseRangeHeader(fullRequestStr, rangeStart, rangeEnd, absStart, absEnd, startTimeIsNow);
    
    if (sawRangeHeader && absStart == NULL/*not seeking by 'absolute' time*/) {
      // Use this information, plus the stream's duration (if known), to create our own "Range:" header, for the response:
      if (duration < 0.0) {
        // We're an aggregate PLAY, but the subsessions have different durations.
        // Use the largest of these durations in our header
        duration = -duration;
      }
      
      // Make sure that "rangeStart" and "rangeEnd" (from the client's "Range:" header)
      // have sane values, before we send back our own "Range:" header in our response:
      if (rangeStart < 0.0) rangeStart = 0.0;
      else if (rangeStart > duration) rangeStart = duration;
      if (rangeEnd < 0.0) rangeEnd = 0.0;
      else if (rangeEnd > duration) rangeEnd = duration;
      if ((scale > 0.0 && rangeStart > rangeEnd && rangeEnd > 0.0) ||
          (scale < 0.0 && rangeStart < rangeEnd)) {
        // "rangeStart" and "rangeEnd" were the wrong way around; swap them:
        double tmp = rangeStart;
        rangeStart = rangeEnd;
        rangeEnd = tmp;
      }
    }
    
    // Create a "RTP-Info:" line.  It will get filled in from each subsession's state:
    char const* rtpInfoFmt =
    "%s" // "RTP-Info:", plus any preceding rtpInfo items
    "%s" // comma separator, if needed
    "url=%s/%s"
    ";seq=%d"
    ";rtptime=%u"
    ;
    unsigned rtpInfoFmtSize = strlen(rtpInfoFmt);
    char* rtpInfo = strDup("RTP-Info: ");
    unsigned i, numRTPInfoItems = 0;
    
    // Do any required seeking/scaling on each subsession, before starting streaming.
    // (However, we don't do this if the "PLAY" request was for just a single subsession
    // of a multiple-subsession stream; for such streams, seeking/scaling can be done
    // only with an aggregate "PLAY".)
    for (i = 0; i < fNumStreamStates; ++i) {
      /*if (subsession == NULL  || fNumStreamStates == 1) {
        if (fStreamStates[i].subsession != NULL) {
          if (sawScaleHeader) {
            fStreamStates[i].subsession->setStreamScale(fOurSessionId, fStreamStates[i].streamToken, scale);
          }
          if (absStart != NULL) {
            // Special case handling for seeking by 'absolute' time:
            
            fStreamStates[i].subsession->seekStream(fOurSessionId, fStreamStates[i].streamToken, absStart, absEnd);
          } else {
            // Seeking by relative (NPT) time:
            
            u_int64_t numBytes;
            if (!sawRangeHeader || startTimeIsNow) {
              // We're resuming streaming without seeking, so we just do a 'null' seek
              // (to get our NPT, and to specify when to end streaming):
              fStreamStates[i].subsession->nullSeekStream(fOurSessionId, fStreamStates[i].streamToken,
                                                          rangeEnd, numBytes);
            } else {
              // We do a real 'seek':
              double streamDuration = 0.0; // by default; means: stream until the end of the media
              if (rangeEnd > 0.0 && (rangeEnd+0.001) < duration) {
                // the 0.001 is because we limited the values to 3 decimal places
                // We want the stream to end early.  Set the duration we want:
                streamDuration = rangeEnd - rangeStart;
                if (streamDuration < 0.0) streamDuration = -streamDuration;
                // should happen only if scale < 0.0
              }
              fStreamStates[i].subsession->seekStream(fOurSessionId, fStreamStates[i].streamToken,
                                                      rangeStart, streamDuration, numBytes);
            }
          }
        }
      }*/
    }
    
    // Create the "Range:" header that we'll send back in our response.
    // (Note that we do this after seeking, in case the seeking operation changed the range start time.)
    if (absStart != NULL) {
      // We're seeking by 'absolute' time:
      if (absEnd == NULL) {
        sprintf(buf, "Range: clock=%s-\r\n", absStart);
      } else {
        sprintf(buf, "Range: clock=%s-%s\r\n", absStart, absEnd);
      }
      delete[] absStart; delete[] absEnd;
    } else {
      // We're seeking by relative (NPT) time:
      if (!sawRangeHeader || startTimeIsNow) {
        // We didn't seek, so in our response, begin the range with the current NPT (normal play time):
        float curNPT = 0.0;
        for (i = 0; i < fNumStreamStates; ++i) {
          if (//subsession == NULL /* means: aggregated operation */
              //|| subsession == fStreamStates[i].subsession
              1) {
            //if (fStreamStates[i].subsession == NULL) continue;*/
            float npt = 1;//fStreamStates[i].subsession->getCurrentNPT(fStreamStates[i].streamToken);
            if (npt > curNPT) curNPT = npt;
            // Note: If this is an aggregate "PLAY" on a multi-subsession stream,
            // then it's conceivable that the NPTs of each subsession may differ
            // (if there has been a previous seek on just one subsession).
            // In this (unusual) case, we just return the largest NPT; I hope that turns out OK...
          }
        }
        rangeStart = curNPT;
      }
      
      if (rangeEnd == 0.0 && scale >= 0.0) {
        sprintf(buf, "Range: npt=%.3f-\r\n", rangeStart);
      } else {
        sprintf(buf, "Range: npt=%.3f-%.3f\r\n", rangeStart, rangeEnd);
      }
    }
    char* rangeHeader = strDup(buf);
    
    // Now, start streaming:
    for (i = 0; i < fNumStreamStates; ++i) {
      if (//subsession == NULL /* means: aggregated operation */
          //|| subsession == fStreamStates[i].subsession
          1) {
        unsigned short rtpSeqNum = 0;
        unsigned rtpTimestamp = 0;
        /*if (fStreamStates[i].subsession == NULL) continue;
        fStreamStates[i].subsession->startStream(fOurSessionId,
                                                 fStreamStates[i].streamToken,
                                                 (TaskFunc*)noteClientLiveness, this,
                                                 rtpSeqNum, rtpTimestamp,
                                                 RTSPServer::RTSPClientConnection::handleAlternativeRequestByte, ourClientConnection);*/
        const char *urlSuffix = "1";//fStreamStates[i].subsession->trackId();
        char* prevRTPInfo = rtpInfo;
        unsigned rtpInfoSize = rtpInfoFmtSize
        + strlen(prevRTPInfo)
        + 1
        + rtspURLSize + strlen(urlSuffix)
        + 5 /*max unsigned short len*/
        + 10 /*max unsigned (32-bit) len*/
        + 2 /*allows for trailing \r\n at final end of string*/;
        rtpInfo = new char[rtpInfoSize];
        sprintf(rtpInfo, rtpInfoFmt,
                prevRTPInfo,
                numRTPInfoItems++ == 0 ? "" : ",",
                rtspURL, urlSuffix,
                rtpSeqNum,
                rtpTimestamp
                );
        delete[] prevRTPInfo;
      }
    }
    if (numRTPInfoItems == 0) {
      rtpInfo[0] = '\0';
    } else {
      unsigned rtpInfoLen = strlen(rtpInfo);
      rtpInfo[rtpInfoLen] = '\r';
      rtpInfo[rtpInfoLen+1] = '\n';
      rtpInfo[rtpInfoLen+2] = '\0';
    }
    
    // Fill in the response:
    snprintf((char*)ourClientConnection->fResponseBuffer, sizeof ourClientConnection->fResponseBuffer,
             "RTSP/1.0 200 OK\r\n"
             "CSeq: %s\r\n"
             "%s"
             "%s"
             "%s"
             "Session: %08X\r\n"
             "%s\r\n",
             ourClientConnection->fCurrentCSeq,
             dateHeader(),
             scaleHeader,
             rangeHeader,
             fOurSessionId,
             rtpInfo);
    delete[] rtpInfo; delete[] rangeHeader;
    delete[] scaleHeader; delete[] rtspURL;
  }
  
  void RTSPServer::RTSPClientSession
  ::handleCmd_PAUSE(RTSPServer::RTSPClientConnection* ourClientConnection) {
    for (unsigned i = 0; i < fNumStreamStates; ++i) {
      if (//subsession == NULL /* means: aggregated operation */
          //|| subsession == fStreamStates[i].subsession
          1) {
        // stop the current session
        //if (fStreamStates[i].subsession != NULL) {
        //  fStreamStates[i].subsession->pauseStream(fOurSessionId, fStreamStates[i].streamToken);
        //}
      }
    }
    
    setRTSPResponse(ourClientConnection, "200 OK", fOurSessionId);
  }
  
  void RTSPServer::RTSPClientSession
  ::handleCmd_GET_PARAMETER(RTSPServer::RTSPClientConnection* ourClientConnection, char const* /*fullRequestStr*/) {
    // By default, we implement "GET_PARAMETER" just as a 'keep alive', and send back a dummy response.
    // (If you want to handle "GET_PARAMETER" properly, you can do so by defining a subclass of "RTSPServer"
    // and "RTSPServer::RTSPClientSession", and then reimplement this virtual function in your subclass.)
    setRTSPResponse(ourClientConnection, "200 OK", fOurSessionId, "the current verison");
  }
  
  void RTSPServer::RTSPClientSession
  ::handleCmd_SET_PARAMETER(RTSPServer::RTSPClientConnection* ourClientConnection,
                            char const* /*fullRequestStr*/) {
    // By default, we implement "SET_PARAMETER" just as a 'keep alive', and send back an empty response.
    // (If you want to handle "SET_PARAMETER" properly, you can do so by defining a subclass of "RTSPServer"
    // and "RTSPServer::RTSPClientSession", and then reimplement this virtual function in your subclass.)
    setRTSPResponse(ourClientConnection, "200 OK", fOurSessionId);
  }
  
  RTSPServer::RTSPClientConnection*
  RTSPServer::createNewClientConnection(int clientSocket, struct sockaddr_in clientAddr) {
    return new RTSPClientConnection(*this, clientSocket, clientAddr);
  }
  
  RTSPServer::RTSPClientSession*
  RTSPServer::createNewClientSession(u_int32_t sessionId) {
    return new RTSPClientSession(*this, sessionId);
  }

} // namespace igtl