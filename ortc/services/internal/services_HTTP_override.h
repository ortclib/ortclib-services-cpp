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
      #pragma mark
      #pragma mark IHTTPForSettings
      #pragma mark

      interaction IHTTPOverrideForSettings
      {
        static void applyDefaults();
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark HTTP
      #pragma mark

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
        HTTPOverride(const make_private &);

      protected:
        HTTPOverride(Noop) :
          Noop(true),
          SharedRecursiveLock(SharedRecursiveLock::create())
        {}

        void init();

      public:
        ~HTTPOverride();

    public:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark HTTP => IHTTPFactory
        #pragma mark

        static HTTPQueryPtr query(
                                  IHTTPQueryDelegatePtr delegate,
                                  const QueryInfo &query
                                  );

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark HTTP => IHTTPOverride
        #pragma mark

        static void install(IHTTPOverrideDelegatePtr override);

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

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark HTTP => friend HTTPQuery
        #pragma mark

        // (duplicate) void monitorEnd(HTTPQueryPtr query);

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark HTTP => (internal)
        #pragma mark

        static HTTPOverridePtr singleton();
        static HTTPOverridePtr create();

        void cancel();

        void monitorBegin(HTTPQueryPtr query);
        void monitorEnd(HTTPQuery &query);

      public:
        void operator()();

      public:
        //---------------------------------------------------------------------
        //---------------------------------------------------------------------
        //---------------------------------------------------------------------
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark HTTP => class HTTPQuery
        #pragma mark

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
                    );

        protected:
          void init();

        public:
          ~HTTPQuery();

          //-------------------------------------------------------------------
          #pragma mark
          #pragma mark HTTP::HTTPQuery => IHTTPQuery
          #pragma mark

          virtual PUID getID() const {return id_;}

          virtual void cancel();

          virtual bool isComplete() const;
          virtual bool wasSuccessful() const;
          virtual HTTPStatusCodes getStatusCode() const;

          virtual size_t getHeaderReadSizeAvailableInBytes() const;
          virtual size_t readHeader(
                                    BYTE *outResultData,
                                    size_t bytesToRead
                                    );

          virtual size_t readHeaderAsString(String &outHeader);

          virtual size_t getReadDataAvailableInBytes() const;

          virtual size_t readData(
                                  BYTE *outResultData,
                                  size_t bytesToRead
                                  );

          virtual size_t readDataAsString(String &outResultData);

          //-------------------------------------------------------------------
          #pragma mark
          #pragma mark HTTP::HTTPQuery => friend ITimerDelegate
          #pragma mark

          void onTimer(ITimerPtr onTimer);

          //-------------------------------------------------------------------
          #pragma mark
          #pragma mark HTTP::HTTPQuery => friend HTTP
          #pragma mark

          static HTTPQueryPtr create(
                                     HTTPOverridePtr outer,
                                     IHTTPQueryDelegatePtr delegate,
                                     const QueryInfo &query
                                     );

          // (duplicate) PUID getID() const;

          void go(IHTTPOverrideDelegatePtr override);

          void notifyHeaderData(
                                const BYTE *buffer,
                                size_t sizeInBytes
                                );

          void notifyBodyData(
                              const BYTE *buffer,
                              size_t sizeInBytes
                              );

          void notifyComplete(IHTTP::HTTPStatusCodes result);

        protected:
          //-------------------------------------------------------------------
          #pragma mark
          #pragma mark HTTP::HTTPQuery => (internal)
          #pragma mark

        protected:
          //-------------------------------------------------------------------
          #pragma mark
          #pragma mark HTTP::HTTPQuery => (data)
          #pragma mark

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
        #pragma mark
        #pragma mark HTTP => (data)
        #pragma mark

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
