/*

 Copyright (c) 2017, Optical Tone Inc.
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

#include <zsLib/IPAddress.h>
#include <zsLib/Socket.h>
#include <cryptopp/secblock.h>
#include <cryptopp/queue.h>

#include <zsLib/ITimer.h>

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
      // IHTTPForSettings
      //

      interaction IHTTPOverrideForSettings
      {
        static void applyDefaults() ;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // HTTP
      //

      class HTTPOverride : public Noop,
                           public SharedRecursiveLock,
                           public IHTTP,
                           public IHTTPOverride
      {
      protected:
        struct make_private {};

      public:
        friend interaction IHTTPOverride;

        ZS_DECLARE_CLASS_PTR(HTTPQuery);

        friend class HTTPQuery;

      public:
        HTTPOverride(const make_private &) noexcept;

      protected:
        HTTPOverride(Noop) noexcept :
          Noop(true),
          SharedRecursiveLock(SharedRecursiveLock::create())
        {}

        void init() noexcept;

      public:
        ~HTTPOverride() noexcept;

    public:
        //---------------------------------------------------------------------
        //
        // HTTP => IHTTPFactory
        //

        static HTTPQueryPtr query(
                                  IHTTPQueryDelegatePtr delegate,
                                  const QueryInfo &query
                                  ) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // HTTP => IHTTPOverride
        //

        static void install(IHTTPOverrideDelegatePtr override) noexcept;

        static void notifyHeaderData(
                                     IHTTPQueryPtr query,
                                     const BYTE *buffer,
                                     size_t sizeInBytes
                                     ) noexcept(false);

        static void notifyBodyData(
                                   IHTTPQueryPtr query,
                                   const BYTE *buffer,
                                   size_t sizeInBytes
                                   ) noexcept(false);

        static void notifyComplete(
                                   IHTTPQueryPtr query,
                                   IHTTP::HTTPStatusCodes status = IHTTP::HTTPStatusCode_OK
                                   ) noexcept(false);

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

        static HTTPOverridePtr singleton() noexcept;
        static HTTPOverridePtr create() noexcept;

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
                    HTTPOverridePtr outer,
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

          virtual PUID getID() const noexcept {return id_;}

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
                                     HTTPOverridePtr outer,
                                     IHTTPQueryDelegatePtr delegate,
                                     const QueryInfo &query
                                     ) noexcept;

          // (duplicate) PUID getID() const;

          void go(IHTTPOverrideDelegatePtr override) noexcept;

          void notifyHeaderData(
                                const BYTE *buffer,
                                size_t sizeInBytes
                                ) noexcept;

          void notifyBodyData(
                              const BYTE *buffer,
                              size_t sizeInBytes
                              ) noexcept;

          void notifyComplete(IHTTP::HTTPStatusCodes result) noexcept;

        protected:
          //-------------------------------------------------------------------
          //
          // HTTP::HTTPQuery => (internal)
          //

        protected:
          //-------------------------------------------------------------------
          //
          // HTTP::HTTPQuery => (data)
          //

          AutoPUID id_;
          HTTPQueryWeakPtr thisWeak_;

          HTTPOverrideWeakPtr outer_;
          IHTTPOverrideDelegatePtr override_;
          IHTTPQueryDelegatePtr delegate_;

          QueryInfo query_;

          ByteQueue header_;
          ByteQueue body_;

          IHTTP::HTTPStatusCodes statusCode_ {HTTPStatusCode_None};
          ITimerPtr timer_;
        };

      protected:
        //---------------------------------------------------------------------
        //
        // HTTP => (data)
        //

        AutoPUID id_;
        HTTPOverrideWeakPtr thisWeak_;

        typedef PUID QueryID;
        typedef std::map<QueryID, HTTPQueryWeakPtr> HTTPQueryMap;
        HTTPQueryMap queries_;

        IHTTPOverrideDelegatePtr override_;
      };

    }
  }
}
