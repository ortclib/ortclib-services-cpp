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

#include <ortc/services/internal/types.h>
#include <ortc/services/IHTTP.h>

#ifdef HAVE_HTTP_WINUWP
#include <zsLib/IPAddress.h>
#include <zsLib/Socket.h>
#include <cryptopp/secblock.h>
#include <cryptopp/queue.h>

#include <zsLib/ITimer.h>

#include <ppltasks.h>

namespace ortc
{
  namespace services
  {
    namespace internal
    {
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // HTTP
      //

      class HTTP : public Noop,
                   public SharedRecursiveLock,
                   public IHTTP
      {
      protected:
        struct make_private {};

      public:
        friend interaction IHTTPFactory;

        ZS_DECLARE_CLASS_PTR(HTTPQuery)

        friend class HTTPQuery;

      public:
        HTTP(const make_private &) noexcept;

      protected:
        HTTP(Noop) noexcept :
          Noop(true),
          SharedRecursiveLock(SharedRecursiveLock::create())
        {}

        void init() noexcept;

      public:
        ~HTTP() noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // HTTP => IHTTP
        //

        static HTTPQueryPtr query(
                                  IHTTPQueryDelegatePtr delegate,
                                  const QueryInfo &query
                                  ) noexcept;

        //---------------------------------------------------------------------
        //
        // HTTP => friend HTTPQuery
        //

        // (duplicate) void monitorEnd(HTTPQueryPtr query);

      protected:
        //---------------------------------------------------------------------
        //
        // HTTP => (internal)
        //

        static HTTPPtr singleton() noexcept;
        static HTTPPtr create() noexcept;

        Log::Params log(const char *message) const noexcept;
        static Log::Params slog(const char *message) noexcept;

        void cancel() noexcept;

        void monitorBegin(HTTPQueryPtr query) noexcept;
        void monitorEnd(HTTPQuery &query) noexcept;

      public:
        void operator()() noexcept;

      public:
        //---------------------------------------------------------------------
        //---------------------------------------------------------------------
        //---------------------------------------------------------------------
        //---------------------------------------------------------------------
        //
        // HTTP => class HTTPQuery
        //

        class HTTPQuery : public SharedRecursiveLock,
                          public MessageQueueAssociator,
                          public IHTTPQuery,
                          public ITimerDelegate
        {
        protected:
          struct make_private {};

        public:
          HTTPQuery(
                    const make_private &,
                    HTTPPtr outer,
                    IHTTPQueryDelegatePtr delegate,
                    const QueryInfo &query
                    ) noexcept;

        protected:
          void init() noexcept;

        public:
          ~HTTPQuery() noexcept;

          //-------------------------------------------------------------------
          //
          // HTTP::HTTPQuery => IHTTPQuery
          //

          virtual PUID getID() const noexcept {return mID;}

          virtual void cancel() noexcept;

          virtual bool isComplete() const noexcept;
          virtual bool wasSuccessful() const noexcept;
          virtual HTTPStatusCodes getStatusCode() const noexcept;

          virtual size_t getHeaderReadSizeAvailableInBytes() const noexcept;
          virtual size_t readHeader(
                                    BYTE *outResultData,
                                    size_t bytesToRead
                                    ) noexcept;

          virtual size_t readHeaderAsString(String &outHeader) noexcept;

          virtual size_t getReadDataAvailableInBytes() const noexcept;

          virtual size_t readData(
                                  BYTE *outResultData,
                                  size_t bytesToRead
                                  ) noexcept;

          virtual size_t readDataAsString(String &outResultData) noexcept;

          //-------------------------------------------------------------------
          //
          // HTTP::HTTPQuery => friend ITimerDelegate
          //

          void onTimer(ITimerPtr onTimer);

          //-------------------------------------------------------------------
          //
          // HTTP::HTTPQuery => friend HTTP
          //

          static HTTPQueryPtr create(
                                     HTTPPtr outer,
                                     IHTTPQueryDelegatePtr delegate,
                                     const QueryInfo &query
                                     ) noexcept;

          // (duplicate) PUID getID() const;

          void go(Windows::Web::Http::HttpClient ^client) noexcept;
          void notifyComplete(Windows::Web::Http::HttpStatusCode result) noexcept;

        protected:
          //-------------------------------------------------------------------
          //
          // HTTP::HTTPQuery => (internal)
          //

          Log::Params log(const char *message) const noexcept;
          static Log::Params slogQuery(PUID id, const char *message) noexcept;
          void notifyComplete(Windows::Web::Http::HttpResponseMessage ^response) noexcept;

        protected:
          //-------------------------------------------------------------------
          //
          // HTTP::HTTPQuery => (data)
          //

          AutoPUID mID;
          HTTPQueryWeakPtr mThisWeak;

          HTTPWeakPtr mOuter;
          IHTTPQueryDelegatePtr mDelegate;

          QueryInfo mQuery;

          ByteQueue mHeader;
          ByteQueue mBody;

          concurrency::cancellation_token_source mCancellationTokenSource;
          Windows::Web::Http::HttpStatusCode mStatusCode;
          ITimerPtr mTimer;
        };

      protected:
        //---------------------------------------------------------------------
        //
        // HTTP => (data)
        //

        AutoPUID mID;
        HTTPWeakPtr mThisWeak;

        typedef PUID QueryID;
        typedef std::map<QueryID, HTTPQueryWeakPtr> HTTPQueryMap;
        HTTPQueryMap mQueries;

        Windows::Web::Http::HttpClient ^mHTTPClient;
      };

    }
  }
}

#endif //HAVE_HTTP_WINUWP

