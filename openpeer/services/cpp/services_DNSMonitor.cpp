/*

 Copyright (c) 2013, SMB Phone Inc.
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

#include <openpeer/services/internal/services_DNSMonitor.h>
#include <openpeer/services/internal/services_Helper.h>
#include <zsLib/Exception.h>
#include <zsLib/Socket.h>
#include <zsLib/helpers.h>
#include <zsLib/XML.h>

namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services) } }


namespace openpeer
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
      #pragma mark DNSMonitor
      #pragma mark

      //-----------------------------------------------------------------------
      DNSMonitor::DNSMonitor(IMessageQueuePtr queue) :
        MessageQueueAssociator(queue),
        mCtx(NULL)
      {
      }

      //-----------------------------------------------------------------------
      void DNSMonitor::init()
      {
      }

      //-----------------------------------------------------------------------
      DNSMonitor::~DNSMonitor()
      {
        for (PendingQueriesMap::iterator iter = mPendingQueries.begin(); iter != mPendingQueries.end(); ++iter)
        {
          CacheInfoPtr &cacheInfo = (*iter).second;
          for (ResultList::iterator resultIter = cacheInfo->mPendingResults.begin(); resultIter != cacheInfo->mPendingResults.end(); ++resultIter)
          {
            IResultPtr result = (*resultIter);
            result->onCancel();
          }
          if ((mCtx) &&
              (cacheInfo->mPendingQuery)) {
            dns_cancel(mCtx, cacheInfo->mPendingQuery);
            cacheInfo->mPendingQuery = NULL;
          }
        }

        mPendingQueries.clear();

        cleanIfNoneOutstanding();
      }

      //-----------------------------------------------------------------------
      DNSMonitorPtr DNSMonitor::create(IMessageQueuePtr queue)
      {
        DNSMonitorPtr pThis(new DNSMonitor(queue));
        pThis->mThisWeak = pThis;
        pThis->init();
        return pThis;
      }

      //-----------------------------------------------------------------------
      DNSMonitorPtr DNSMonitor::singleton()
      {
        AutoRecursiveLock lock(Helper::getGlobalLock());
        static DNSMonitorPtr monitor = DNSMonitor::create(Helper::getServiceQueue());
        return monitor;
      }

      //-----------------------------------------------------------------------
      void DNSMonitor::createDNSContext()
      {
        if (NULL != mCtx)
          return;

        // this has to be done first because on windows it is possible that dns_open will fail because socket initialize routine on windows won't be called otherwise
        mSocket = Socket::create();

        dns_reset(&dns_defctx);

        mCtx = dns_new(NULL);
        ZS_THROW_BAD_STATE_IF(NULL == mCtx)

        dns_init(mCtx, 0);  // do open ourselves...

        bool triedZero = false;

        int result = 0;
        for (int tries = 0; tries < 20; ++tries) {
          result = dns_open(mCtx);
          if (result < 0) {
            // try a different random port instead of a hard coded fixed port - application should find one hopefully within 20 tries
            if (!triedZero) {
              dns_set_opt(mCtx, DNS_OPT_PORT, 0);
              triedZero = true;
            } else
              dns_set_opt(mCtx, DNS_OPT_PORT, rand()%(65534-5000) + 5000);
          }
          else
            break;
        }
        if (result < 0) {
          dns_free(mCtx);
          mCtx = NULL;
        }

        mSocket->adopt((SOCKET)result);
        mSocket->setDelegate(mThisWeak.lock());

        mTimer = Timer::create(mThisWeak.lock(), Seconds(1), true);
      }

      //-----------------------------------------------------------------------
      void DNSMonitor::cleanIfNoneOutstanding()
      {
        if (mPendingQueries.size() > 0) return;   // still outstanding queries

        if (NULL == mCtx)
          return;

        dns_close(mCtx);
        dns_free(mCtx);
        mCtx = NULL;

        mSocket->orphan();
        mSocket.reset();

        mTimer->cancel();
        mTimer.reset();
      }

      //-----------------------------------------------------------------------
      DNSMonitor::CacheInfoPtr DNSMonitor::done(QueryID queryID)
      {
        AutoRecursiveLock lock(mLock);

        CacheInfoPtr result;

        PendingQueriesMap::iterator found = mPendingQueries.find(queryID);
        if (found == mPendingQueries.end()) return CacheInfoPtr();

        result = (*found).second;
        result->mPendingQuery = NULL;
        mPendingQueries.erase(found);
        return result;
      }

      //-----------------------------------------------------------------------
      void DNSMonitor::cancel(
                              QueryID queryID,
                              IResultPtr result
                              )
      {
        AutoRecursiveLock lock(mLock);

        PendingQueriesMap::iterator found = mPendingQueries.find(queryID);
        if (found == mPendingQueries.end()) {
          return;
        }

        CacheInfoPtr &info = (*found).second;

        bool erased = false;

        for (ResultList::iterator iter = info->mPendingResults.begin(); iter != info->mPendingResults.end(); )
        {
          ResultList::iterator current = iter; ++iter;

          IResultPtr &infoResult = (*current);

          if (infoResult != result) continue;

          info->mPendingResults.erase(current);
          erased = true;
          break;
        }

        if (!erased) return;

        // if there are other pending results then don't cancel the result
        if (info->mPendingResults.size() > 0) return;

        // this was the last pending result so cancel the DNS query
        mPendingQueries.erase(found);

        if ((mCtx) &&
            (info->mPendingQuery)) {
          dns_cancel(mCtx, info->mPendingQuery);
          info->mPendingQuery = NULL;
        }

        // since it was cancelled the query can be redone
        info->mExpires = Time();

        cleanIfNoneOutstanding();
      }
      
      //-----------------------------------------------------------------------
      void DNSMonitor::submitAQuery(const char *inName, int flags, IResultPtr result)
      {
        submitAOrAAAAQuery(true, inName, flags, result);
      }

      //-----------------------------------------------------------------------
      void DNSMonitor::submitAAAAQuery(const char *inName, int flags, IResultPtr result)
      {
        submitAOrAAAAQuery(false, inName, flags, result);
      }

      //-----------------------------------------------------------------------
      void DNSMonitor::submitAOrAAAAQuery(bool aMode, const char *inName, int flags, IResultPtr result)
      {
        AutoRecursiveLock lock(mLock);
        createDNSContext();
        if (!mCtx) {
          result->onCancel(); // this result is now bogus
          return;
        }

        String name(inName);

        ACacheInfoPtr useInfo;

        ACacheList &useList = (aMode ? mACacheList : mAAAACacheList);

        for (ACacheList::iterator iter = useList.begin(); iter != useList.end(); ++iter)
        {
          ACacheInfoPtr &info = (*iter);
          if (info->mName != name) continue;
          if (info->mFlags != flags) continue;

          useInfo = info;
          break;
        }

        if (!useInfo) {
          useInfo = ACacheInfoPtr(new ACacheInfo);
          useInfo->mName = name;
          useInfo->mFlags = flags;
        }

        if (Time() != useInfo->mExpires) {
          Time tick = zsLib::now();
          
          if (tick < useInfo->mExpires) {
            // use cached result
            if (aMode) {
              result->onAResult(useInfo->mResult);
            } else {
              result->onAAAAResult(useInfo->mResult);
            }
            return;
          }
        }

        useInfo->mPendingResults.push_back(result);

        if (useInfo->mPendingQuery) return;  // already have a query outstanding

        QueryID queryID = zsLib::createPUID();

        struct dns_query *query = NULL;
        if (aMode) {
          query = dns_submit_a4(mCtx, name, flags, DNSMonitor::dns_query_a4, (void *)((PTRNUMBER)queryID));
        } else {
          query = dns_submit_a6(mCtx, name, flags, DNSMonitor::dns_query_a6, (void *)((PTRNUMBER)queryID));
        }
        if (NULL != query) {
          useInfo->mPendingQuery = query;
          mPendingQueries[queryID] = useInfo;
        } else {
          if (aMode) {
            useInfo->onAResult(NULL, DNS_E_BADQUERY);
          } else {
            useInfo->onAAAAResult(NULL, DNS_E_BADQUERY);
          }
        }
        cleanIfNoneOutstanding();
      }

      //-----------------------------------------------------------------------
      void DNSMonitor::submitSRVQuery(const char *inName, const char *inService, const char *inProtocol, int flags, IResultPtr result)
      {
        AutoRecursiveLock lock(mLock);
        createDNSContext();
        if (!mCtx) {
          result->onCancel(); // this result is now bogus
          return;
        }

        String name(inName);
        String service(inService);
        String protocol(inProtocol);

        SRVCacheInfoPtr useInfo;

        for (SRVCacheList::iterator iter = mSRVCacheList.begin(); iter != mSRVCacheList.end(); ++iter)
        {
          SRVCacheInfoPtr &info = (*iter);
          if (info->mName != name) continue;
          if (info->mService != service) continue;
          if (info->mProtocol != protocol) continue;
          if (info->mFlags != flags) continue;

          useInfo = info;
          break;
        }

        if (!useInfo) {
          useInfo = SRVCacheInfoPtr(new SRVCacheInfo);
          useInfo->mName = name;
          useInfo->mService = service;
          useInfo->mProtocol = protocol;
          useInfo->mFlags = flags;
        }

        if (Time() != useInfo->mExpires) {
          Time tick = zsLib::now();

          if (tick < useInfo->mExpires) {
            // use cached result
            result->onSRVResult(useInfo->mResult);
            return;
          }
        }

        useInfo->mPendingResults.push_back(result);

        if (useInfo->mPendingQuery) return;  // already have a query outstanding

        QueryID queryID = zsLib::createPUID();

        struct dns_query *query = dns_submit_srv(mCtx, name, service, protocol, flags, DNSMonitor::dns_query_srv, (void *)((PTRNUMBER)queryID));
        if (NULL != query) {
          useInfo->mPendingQuery = query;
          mPendingQueries[queryID] = useInfo;
        } else {
          result->onCancel();         // this result is now bogus since the query object could not be created
        }
        cleanIfNoneOutstanding();
      }

      //-----------------------------------------------------------------------
      void DNSMonitor::dns_query_a4(struct dns_ctx *ctx, struct dns_rr_a4 *record, void *data)
      {
        QueryID queryID = (QueryID)((PTRNUMBER)data);

        DNSMonitorPtr monitor = singleton();
        if (!monitor) {
          // monitor was destroyed therefor object was already cancelled
          return;
        }

        int status = DNS_E_NOERROR;
        if (NULL == record) {
          status = dns_status(ctx);
        }

        PendingQueriesMap::iterator found = monitor->mPendingQueries.find(queryID);
        if (found == monitor->mPendingQueries.end()) {
          // already cancelled, nothing to do
          return;
        }

        CacheInfoPtr &info = (*found).second;
        info->onAResult(record, status);

        monitor->done(queryID);
      }

      //-----------------------------------------------------------------------
      void DNSMonitor::dns_query_a6(struct dns_ctx *ctx, struct dns_rr_a6 *record, void *data)
      {
        QueryID queryID = (QueryID)((PTRNUMBER)data);

        DNSMonitorPtr monitor = singleton();
        if (!monitor) {
          // monitor was destroyed therefor object was already cancelled
          return;
        }

        int status = DNS_E_NOERROR;
        if (NULL == record) {
          status = dns_status(ctx);
        }

        PendingQueriesMap::iterator found = monitor->mPendingQueries.find(queryID);
        if (found == monitor->mPendingQueries.end()) {
          // already cancelled, nothing to do
          return;
        }

        CacheInfoPtr &info = (*found).second;
        info->onAAAAResult(record, status);

        monitor->done(queryID);
      }

      //-----------------------------------------------------------------------
      void DNSMonitor::dns_query_srv(struct dns_ctx *ctx, struct dns_rr_srv *record, void *data)
      {
        QueryID queryID = (QueryID)((PTRNUMBER)data);

        DNSMonitorPtr monitor = singleton();
        if (!monitor) {
          // monitor was destroyed therefor object was already cancelled
          return;
        }

        int status = DNS_E_NOERROR;
        if (NULL == record) {
          status = dns_status(ctx);
        }

        PendingQueriesMap::iterator found = monitor->mPendingQueries.find(queryID);
        if (found == monitor->mPendingQueries.end()) {
          // already cancelled, nothing to do
          return;
        }

        CacheInfoPtr &info = (*found).second;
        info->onSRVResult(record, status);

        monitor->done(queryID);
      }

      //-----------------------------------------------------------------------
      void DNSMonitor::onReadReady(ISocketPtr socket)
      {
        AutoRecursiveLock lock(mLock);
        if (!mCtx)
          return;

        if (socket != mSocket) return;

        dns_ioevent(mCtx, 0);
        dns_timeouts(mCtx, -1, 0);
        mSocket->onReadReadyReset();

        cleanIfNoneOutstanding();
      }

      //-----------------------------------------------------------------------
      void DNSMonitor::onWriteReady(ISocketPtr socket)
      {
        // we can ignore the write ready, it only writes during a timeout event or during creation
      }

      //-----------------------------------------------------------------------
      void DNSMonitor::onException(ISocketPtr socket)
      {
        AutoRecursiveLock lock(mLock);
        if (NULL == mCtx)
          return;

        if (socket != mSocket) {
          ZS_LOG_WARNING(Detail, log("notified of exception on obsolete socket"))
          return;
        }

        for (PendingQueriesMap::iterator iter = mPendingQueries.begin(); iter != mPendingQueries.end(); ++iter)
        {
          CacheInfoPtr &cacheInfo = (*iter).second;
          for (ResultList::iterator resultIter = cacheInfo->mPendingResults.begin(); resultIter != cacheInfo->mPendingResults.end(); ++resultIter)
          {
            IResultPtr result = (*resultIter);
            result->onCancel();
          }

          if (cacheInfo->mPendingQuery) {
            dns_cancel(mCtx, cacheInfo->mPendingQuery);
            cacheInfo->mPendingQuery = NULL;
          }
        }
        mPendingQueries.clear();

        cleanIfNoneOutstanding();
      }

      //-----------------------------------------------------------------------
      void DNSMonitor::onTimer(TimerPtr timer)
      {
        AutoRecursiveLock lock(mLock);
        if (NULL == mCtx)
          return;

        dns_timeouts(mCtx, -1, 0);
        cleanIfNoneOutstanding();
      }

      //-----------------------------------------------------------------------
      Log::Params DNSMonitor::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("DNSMonitor");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DNSMonitor::ACacheInfo
      #pragma mark

      //-----------------------------------------------------------------------
      void DNSMonitor::ACacheInfo::onAResult(struct dns_rr_a4 *record, int status)
      {
        if (NULL != record) {
          IDNS::AResultPtr data(new IDNS::AResult);

          data->mName = mName;
          data->mTTL = record->dnsa4_ttl;
          for (int loop = 0; loop < record->dnsa4_nrr; ++loop) {
            IPAddress address(record->dnsa4_addr[loop]);
            data->mIPAddresses.push_back(address);
          }

          mResult = data;
          mExpires = zsLib::now() + Seconds(record->dnsa4_ttl);
        } else {
          switch (status) {
            case DNS_E_TEMPFAIL: mExpires = zsLib::now() + Seconds(OPENPEER_SERVICE_INTERNAL_DNS_TEMP_FAILURE_BACKLIST_IN_SECONDS); break;
            default:             mExpires = zsLib::now() + Seconds(OPENPEER_SERVICE_INTERNAL_DNS_OTHER_FAILURE_BACKLIST_IN_SECONDS); break;
          }
        }

        for (ResultList::iterator iter = mPendingResults.begin(); iter != mPendingResults.end(); ++iter)
        {
          IResultPtr &result = (*iter);
          result->onAResult(mResult);
        }
        mPendingResults.clear();
      }

      //-----------------------------------------------------------------------
      void DNSMonitor::ACacheInfo::onAAAAResult(struct dns_rr_a6 *record, int status)
      {
        if (NULL != record) {
          IDNS::AAAAResultPtr data(new IDNS::AAAAResult);

          data->mName = mName;
          data->mTTL = record->dnsa6_ttl;
          for (int loop = 0; loop < record->dnsa6_nrr; ++loop) {
            IPAddress address(record->dnsa6_addr[loop]);
            data->mIPAddresses.push_back(address);
          }

          mResult = data;
          mExpires = zsLib::now() + Seconds(record->dnsa6_ttl);
        } else {
          switch (status) {
            case DNS_E_TEMPFAIL: mExpires = zsLib::now() + Seconds(OPENPEER_SERVICE_INTERNAL_DNS_TEMP_FAILURE_BACKLIST_IN_SECONDS); break;
            default:             mExpires = zsLib::now() + Seconds(OPENPEER_SERVICE_INTERNAL_DNS_OTHER_FAILURE_BACKLIST_IN_SECONDS); break;
          }
        }

        for (ResultList::iterator iter = mPendingResults.begin(); iter != mPendingResults.end(); ++iter)
        {
          IResultPtr &result = (*iter);
          result->onAAAAResult(mResult);
        }
        mPendingResults.clear();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DNSMonitor::SRCCacheInfo
      #pragma mark

      //-----------------------------------------------------------------------
      void DNSMonitor::SRVCacheInfo::onSRVResult(struct dns_rr_srv *record, int status)
      {
        if (NULL != record) {
          IDNS::SRVResultPtr data(new IDNS::SRVResult);

          data->mName = mName;
          data->mService = mService;
          data->mProtocol = mProtocol;
          data->mTTL = record->dnssrv_ttl;
          for (int loop = 0; loop < record->dnssrv_nrr; ++loop) {
            dns_srv &srv = record->dnssrv_srv[loop];

            IDNS::SRVResult::SRVRecord srvRecord;
            srvRecord.mPriority = srv.priority;
            srvRecord.mWeight = srv.weight;
            srvRecord.mPort = srv.port;
            srvRecord.mName = srv.name;

            data->mRecords.push_back(srvRecord);
          }

          mResult = data;
          mExpires = zsLib::now() + Seconds(record->dnssrv_ttl);
        } else {
          switch (status) {
            case DNS_E_TEMPFAIL: mExpires = zsLib::now() + Seconds(OPENPEER_SERVICE_INTERNAL_DNS_TEMP_FAILURE_BACKLIST_IN_SECONDS); break;
            default:             mExpires = zsLib::now() + Seconds(OPENPEER_SERVICE_INTERNAL_DNS_OTHER_FAILURE_BACKLIST_IN_SECONDS); break;
          }
        }

        for (ResultList::iterator iter = mPendingResults.begin(); iter != mPendingResults.end(); ++iter)
        {
          IResultPtr &result = (*iter);
          result->onSRVResult(mResult);
        }
        mPendingResults.clear();
      }
      
    }
  }
}
