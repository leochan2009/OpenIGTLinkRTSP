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
// Common routines used by both RTSP clients and servers
// C++ header

#ifndef _RTSP_COMMON_HH
#define _RTSP_COMMON_HH

#if defined(__WIN32__) || defined(_WIN32) || defined(_QNX4)
#define _strncasecmp _strnicmp
#define snprintf _snprintf
#else
#define _strncasecmp strncasecmp
#endif

#define RTSP_PARAM_STRING_MAX 200

enum LocaleCategory { All, Numeric }; // define and implement more categories later, as needed

#ifndef LOCALE_NOT_USED
#include <locale.h>
#ifndef XLOCALE_NOT_USED
#include <xlocale.h> // because, on some systems, <locale.h> doesn't include <xlocale.h>; this makes sure that we get both
#endif
#endif


class Locale {
public:
  Locale(char const* newLocale, LocaleCategory category = All);
  virtual ~Locale();
  
private:
#ifndef LOCALE_NOT_USED
#ifndef XLOCALE_NOT_USED
  locale_t fLocale, fPrevLocale;
#else
  int fCategoryNum;
  char* fPrevLocale;
#endif
#endif
};

bool parseRTSPRequestString(char const *reqStr, unsigned reqStrSize,
			       char *resultCmdName,
			       unsigned resultCmdNameMaxSize,
			       char* resultURLPreSuffix,
			       unsigned resultURLPreSuffixMaxSize,
			       char* resultURLSuffix,
			       unsigned resultURLSuffixMaxSize,
			       char* resultCSeq,
			       unsigned resultCSeqMaxSize,
			       char* resultSessionId,
			       unsigned resultSessionIdMaxSize,
			       unsigned& contentLength);

bool parseRangeParam(char const* paramStr, double& rangeStart, double& rangeEnd, char*& absStartTime, char*& absEndTime, bool& startTimeIsNow);
bool parseRangeHeader(char const* buf, double& rangeStart, double& rangeEnd, char*& absStartTime, char*& absEndTime, bool& startTimeIsNow);

bool parseScaleHeader(char const* buf, float& scale);

bool RTSPOptionIsSupported(char const* commandName, char const* optionsResponseString);
    // Returns True iff the RTSP command "commandName" is mentioned as one of the commands supported in "optionsResponseString"
    // (which should be the 'resultString' from a previous RTSP "OPTIONS" request).

char const* dateHeader(); // A "Date:" header that can be used in a RTSP (or HTTP) response 

#endif
