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

#include <openpeer/services/internal/types.h>
#include <openpeer/services/IDNS.h>

#include <udns/udns.h>
#include <zsLib/Socket.h>
#include <zsLib/Proxy.h>
#include <zsLib/Timer.h>

#define OPENPEER_SERVICE_INTERNAL_DNS_TEMP_FAILURE_BACKLIST_IN_SECONDS (15)
#define OPENPEER_SERVICE_INTERNAL_DNS_OTHER_FAILURE_BACKLIST_IN_SECONDS ((60)*2)

namespace openpeer
{
  namespace services
  {
    namespace internal
    {
      class DNSQuery;
      class DNSAQuery;
      class DNSAAAAQuery;
      class DNSSRVQuery;

      ZS_DECLARE_CLASS_PTR(DNSMonitor)

      class DNSMonitor : public MessageQueueAssociator,
                         public SharedRecursiveLock,
                         public ISocketDelegate,
                         public ITimerDelegate
      {
        friend class DNSQuery;
        friend class DNSAQuery;
        friend class DNSAAAAQuery;
        friend class DNSSRVQuery;

        ZS_DECLARE_STRUCT_PTR(CacheInfo)
        ZS_DECLARE_STRUCT_PTR(ACacheInfo)
        ZS_DECLARE_STRUCT_PTR(SRVCacheInfo)

        ZS_DECLARE_TYPEDEF_PTR(ACacheInfo, AAAACacheInfo)

        ZS_DECLARE_INTERACTION_PTR(IResult)

        typedef PUID QueryID;

        interaction IResult
        {
          typedef DNSMonitor::QueryID QueryID;

          virtual void setQueryID(QueryID queryID) = 0;

          virtual void onCancel() = 0;

          virtual void onAResult(IDNS::AResultPtr result) = 0;
          virtual void onAAAAResult(IDNS::AAAAResultPtr result) = 0;
          virtual void onSRVResult(IDNS::SRVResultPtr result) = 0;
        };

        typedef std::list<IResultPtr> ResultList;

        struct CacheInfo
        {
          dns_query *mPendingQuery;
          Time mExpires;

          ResultList mPendingResults;

          CacheInfo() : mPendingQuery(NULL) {};

          virtual void onAResult(struct dns_rr_a4 *record, int status) {}
          virtual void onAAAAResult(struct dns_rr_a6 *record, int status) {}
          virtual void onSRVResult(struct dns_rr_srv *record, int status) {}
        };

        struct ACacheInfo : public CacheInfo
        {
          String mName;
          int mFlags;

          IDNS::AResultPtr mResult;

          virtual void onAResult(struct dns_rr_a4 *record, int status);
          virtual void onAAAAResult(struct dns_rr_a6 *record, int status);

          ACacheInfo() : CacheInfo(), mFlags(0) {};
        };

        struct SRVCacheInfo : public CacheInfo
        {
          String mName;
          String mService;
          String mProtocol;
          int mFlags;

          IDNS::SRVResultPtr mResult;

          SRVCacheInfo() : CacheInfo(), mFlags(0) {};

          virtual void onSRVResult(struct dns_rr_srv *record, int status);
        };

        typedef std::list<ACacheInfoPtr> ACacheList;
        typedef std::list<AAAACacheInfoPtr> AAAACacheList;
        typedef std::list<SRVCacheInfoPtr> SRVCacheList;

        typedef std::map<QueryID, CacheInfoPtr> PendingQueriesMap;

      protected:
        DNSMonitor(IMessageQueuePtr queue);
        void init();
        static DNSMonitorPtr create(IMessageQueuePtr queue);

      public:
        ~DNSMonitor();

        static DNSMonitorPtr singleton();

        static Log::Params slog(const char *message);

      protected:
        void createDNSContext();
        void cleanIfNoneOutstanding();

        CacheInfoPtr done(QueryID queryID);
        void cancel(
                    QueryID queryID,
                    IResultPtr query
                    );
        void submitAQuery(const char *name, int flags, IResultPtr result);
        void submitAAAAQuery(const char *name, int flags, IResultPtr result);
        void submitSRVQuery(const char *name, const char *service, const char *protocol, int flags, IResultPtr result);

        void submitAOrAAAAQuery(bool aMode, const char *name, int flags, IResultPtr result);

        // UDNS callback routines
        static void dns_query_a4(struct dns_ctx *ctx, struct dns_rr_a4 *result, void *data);
        static void dns_query_a6(struct dns_ctx *ctx, struct dns_rr_a6 *result, void *data);
        static void dns_query_srv(struct dns_ctx *ctx, struct dns_rr_srv *result, void *data);

        // ISocketDelegate
        virtual void onReadReady(SocketPtr socket);
        virtual void onWriteReady(SocketPtr socket);
        virtual void onException(SocketPtr socket);

        // ITimerDelegate
        virtual void onTimer(TimerPtr timer);

        // other
      public:
        Log::Params log(const char *message) const;

      private:
        AutoPUID mID;

        DNSMonitorWeakPtr mThisWeak;
        SocketPtr mSocket;
        TimerPtr mTimer;

        dns_ctx *mCtx;

        ACacheList mACacheList;
        AAAACacheList mAAAACacheList;
        SRVCacheList mSRVCacheList;

        PendingQueriesMap mPendingQueries;
      };
    }
  }
}
