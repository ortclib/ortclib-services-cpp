/*

 Copyright (c) 2014, Hookflash Inc.
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 The views and conclusions contained in the software and documentation are those
 of the authors and should not be interpreted as representing official policies,
 either expressed or implied, of the FreeBSD Project.

 */

#pragma once

#include <ortc/services/types.h>

#include <zsLib/Proxy.h>

namespace ortc
{
  namespace services
  {
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IHTTP
    #pragma mark

    interaction IHTTP
    {
      typedef WORD StatusCodeType;

      // as from: http://en.wikipedia.org/wiki/List_of_HTTP_status_codes (2013/01/22)
      enum HTTPStatusCodes
      {
        HTTPStatusCode_None                             = 0,

        HTTPStatusCode_Continue                         = 100,
        HTTPStatusCode_SwitchingProtocols               = 101,
        HTTPStatusCode_Processing                       = 102,

        HTTPStatusCode_OK                               = 200,
        HTTPStatusCode_Created                          = 201,
        HTTPStatusCode_Accepted                         = 202,
        HTTPStatusCode_NonAuthoritativeInformation      = 203,
        HTTPStatusCode_NoContent                        = 204,
        HTTPStatusCode_ResetContent                     = 205,
        HTTPStatusCode_PartialContent                   = 206,
        HTTPStatusCode_MultiStatus                      = 207,
        HTTPStatusCode_AlreadyReported                  = 208,
        HTTPStatusCode_IMUsed                           = 226,
        HTTPStatusCode_AuthenticationSuccessful         = 230,

        HTTPStatusCode_MultipleChoices                  = 300,
        HTTPStatusCode_MovedPermanently                 = 301,
        HTTPStatusCode_Found                            = 302,
        HTTPStatusCode_SeeOther                         = 303,
        HTTPStatusCode_NotModified                      = 304,
        HTTPStatusCode_UseProxy                         = 305,
        HTTPStatusCode_SwitchProxy                      = 306,
        HTTPStatusCode_TemporaryRedirect                = 307,
        HTTPStatusCode_PermanentRedirect                = 308,

        HTTPStatusCode_BadRequest                       = 400,
        HTTPStatusCode_Unauthorized                     = 401,
        HTTPStatusCode_PaymentRequired                  = 402,
        HTTPStatusCode_Forbidden                        = 403,
        HTTPStatusCode_NotFound                         = 404,
        HTTPStatusCode_MethodNotAllowed                 = 405,
        HTTPStatusCode_NotAcceptable                    = 406,
        HTTPStatusCode_ProxyAuthenticationRequired      = 407,
        HTTPStatusCode_RequestTimeout                   = 408,
        HTTPStatusCode_Conflict                         = 409,
        HTTPStatusCode_Gone                             = 410,
        HTTPStatusCode_LengthRequired                   = 411,
        HTTPStatusCode_PreconditionFailed               = 412,
        HTTPStatusCode_RequestEntityTooLarge            = 413,
        HTTPStatusCode_RequestURITooLong                = 414,
        HTTPStatusCode_UnsupportedMediaType             = 415,
        HTTPStatusCode_RequestedRangeNotSatisfiable     = 416,
        HTTPStatusCode_ExpectationFailed                = 417,
        HTTPStatusCode_Imateapot                        = 418,
        HTTPStatusCode_EnhanceYourCalm                  = 420,
        HTTPStatusCode_UnprocessableEntity              = 422,
        HTTPStatusCode_Locked                           = 423,
//        HTTPStatusCode_FailedDependency                 = 424,
        HTTPStatusCode_MethodFailure                    = 424,
        HTTPStatusCode_UnorderedCollection              = 425,
        HTTPStatusCode_UpgradeRequired                  = 426,
        HTTPStatusCode_PreconditionRequired             = 428,
        HTTPStatusCode_TooManyRequests                  = 429,
        HTTPStatusCode_RequestHeaderFieldsTooLarge      = 431,
        HTTPStatusCode_NoResponse                       = 444,
        HTTPStatusCode_RetryWith                        = 449,
        HTTPStatusCode_BlockedbyWindowsParentalControls = 450,
        HTTPStatusCode_UnavailableForLegalReasons       = 451,
//        HTTPStatusCode_Redirect                         = 451,
        HTTPStatusCode_RequestHeaderTooLarge            = 494,
        HTTPStatusCode_CertError                        = 495,
        HTTPStatusCode_NoCert                           = 496,
        HTTPStatusCode_HTTPtoHTTPS                      = 497,
        HTTPStatusCode_ClientClosedRequest              = 499,

        HTTPStatusCode_InternalServerError              = 500,
        HTTPStatusCode_NotImplemented                   = 501,
        HTTPStatusCode_BadGateway                       = 502,
        HTTPStatusCode_ServiceUnavailable               = 503,
        HTTPStatusCode_GatewayTimeout                   = 504,
        HTTPStatusCode_HTTPVersionNotSupported          = 505,
        HTTPStatusCode_VariantAlsoNegotiates            = 506,
        HTTPStatusCode_InsufficientStorage              = 507,
        HTTPStatusCode_LoopDetected                     = 508,
        HTTPStatusCode_BandwidthLimitExceeded           = 509,
        HTTPStatusCode_NotExtended                      = 510,
        HTTPStatusCode_NetworkAuthenticationRequired    = 511,
        HTTPStatusCode_Networkreadtimeouterror          = 598,
        HTTPStatusCode_Networkconnecttimeouterror       = 599,

        HTTPStatusCode_InformationalStart               = 100,
        HTTPStatusCode_InformationalEnd                 = 199,
        HTTPStatusCode_SuccessfulStart                  = 200,
        HTTPStatusCode_SuccessfulEnd                    = 299,
        HTTPStatusCode_RedirectionStart                 = 300,
        HTTPStatusCode_RedirectionEnd                   = 399,
        HTTPStatusCode_ClientErrorStart                 = 400,
        HTTPStatusCode_ClientErrorEnd                   = 499,
        HTTPStatusCode_ServerErrorStart                 = 500,
        HTTPStatusCode_ServerErrorEnd                   = 599,
      };

      static HTTPStatusCodes toStatusCode(StatusCodeType statusCode);
      static const char *toString(HTTPStatusCodes httpStatusCode);
      static bool isPending(HTTPStatusCodes httpStatusCode, bool noneIsPending = true);
      static bool isInformational(HTTPStatusCodes httpStatusCode);
      static bool isSuccess(HTTPStatusCodes httpStatusCode, bool noneIsSuccess = true);
      static bool isRedirection(HTTPStatusCodes httpStatusCode);
      static bool isError(HTTPStatusCodes httpStatusCode, bool noneIsError = false);

      enum Verbs
      {
        Verb_First,

        Verb_Get = Verb_First,
        Verb_Post,

        Verb_Last = Verb_Post,
      };

      static const char *toString(Verbs verb);
      static Verbs toVerb(const char *verb) throw (InvalidArgument);

      struct QueryInfo
      {
        Verbs verb_ {Verb_Get};
        String userAgent_;
        String url_;
        Milliseconds timeout_ {};

        String postDataMimeType_;

        // one of the following must be set for post request
        SecureByteBlockPtr postData_;
        String postDataAsString_;

        QueryInfo();
        QueryInfo(const QueryInfo &source);

        QueryInfo &operator=(const QueryInfo &source);

        void trace(Log::Level level = Log::Trace) const;
      };

      static IHTTPQueryPtr query(
                                 IHTTPQueryDelegatePtr delegate,
                                 const QueryInfo &info
                                 );

    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IHTTPOverride
    #pragma mark

    interaction IHTTPOverride
    {
      static void install(IHTTPOverrideDelegatePtr delegate);
      static void uninstall();

      static void notifyHeaderData(
                                   IHTTPQueryPtr query,
                                   const BYTE *buffer,
                                   size_t sizeInBytes
                                   ) throw (InvalidArgument);

      static void notifyBodyData(
                                 IHTTPQueryPtr query,
                                 const BYTE *buffer,
                                 size_t sizeInBytes
                                 ) throw (InvalidArgument);

      static void notifyComplete(
                                 IHTTPQueryPtr query,
                                 IHTTP::HTTPStatusCodes status = IHTTP::HTTPStatusCode_OK
                                 ) throw (InvalidArgument);
    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IHTTPQuery
    #pragma mark

    interaction IHTTPQuery
    {
      typedef IHTTP::HTTPStatusCodes HTTPStatusCodes;

      virtual PUID getID() const = 0;

      virtual void cancel() = 0;

      virtual bool isComplete() const = 0;
      virtual bool wasSuccessful() const = 0;
      virtual HTTPStatusCodes getStatusCode() const = 0;

      virtual size_t getHeaderReadSizeAvailableInBytes() const = 0;
      virtual size_t readHeader(
                                BYTE *outResultData,
                                size_t bytesToRead
                                ) = 0;

      virtual size_t readHeaderAsString(String &outHeader) = 0;

      virtual size_t getReadDataAvailableInBytes() const = 0;

      virtual size_t readData(
                              BYTE *outResultData,
                              size_t bytesToRead
                              ) = 0;

      virtual size_t readDataAsString(String &outResultData) = 0;
    };

    interaction IHTTPQueryDelegate
    {
      virtual void onHTTPReadDataAvailable(IHTTPQueryPtr query) = 0;
      virtual void onHTTPCompleted(IHTTPQueryPtr query) = 0;
    };

    interaction IHTTPOverrideDelegate
    {
      ZS_DECLARE_TYPEDEF_PTR(IHTTP::QueryInfo, QueryInfo);

      virtual void onHTTPOverrideQuery(
                                       IHTTPQueryPtr query,
                                       QueryInfo info
                                       ) = 0;
      virtual void onHTTPOverrideQueryCancelled(IHTTPQueryPtr query) = 0;
    };
  }
}

ZS_DECLARE_PROXY_BEGIN(ortc::services::IHTTPQueryDelegate)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::IHTTPQueryPtr, IHTTPQueryPtr)
ZS_DECLARE_PROXY_METHOD_1(onHTTPReadDataAvailable, IHTTPQueryPtr)
ZS_DECLARE_PROXY_METHOD_1(onHTTPCompleted, IHTTPQueryPtr)
ZS_DECLARE_PROXY_END()

ZS_DECLARE_PROXY_BEGIN(ortc::services::IHTTPOverrideDelegate)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::IHTTPQueryPtr, IHTTPQueryPtr)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::IHTTP::QueryInfo, QueryInfo)
ZS_DECLARE_PROXY_METHOD_2(onHTTPOverrideQuery, IHTTPQueryPtr, QueryInfo)
ZS_DECLARE_PROXY_METHOD_1(onHTTPOverrideQueryCancelled, IHTTPQueryPtr)
ZS_DECLARE_PROXY_END()
