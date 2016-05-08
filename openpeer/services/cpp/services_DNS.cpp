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

#include <openpeer/services/IDNS.h>
#include <openpeer/services/internal/services_DNS.h>
#include <openpeer/services/internal/services_DNSMonitor.h>
#include <openpeer/services/internal/services_Helper.h>
#include <openpeer/services/internal/services_Tracing.h>

#include <cryptopp/osrng.h>

#include <zsLib/helpers.h>
#include <zsLib/XML.h>
#include <zsLib/Stringize.h>
#include <zsLib/Log.h>
#include <zsLib/Numeric.h>

#ifdef WINRT
#include <ppltasks.h>
#endif //WINRT

namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services) } }

namespace openpeer
{
  namespace services
  {
    using zsLib::Numeric;
    using CryptoPP::AutoSeededRandomPool;

    typedef std::list<String> StringList;
    typedef std::list<IPAddress> IPAddressList;

    namespace internal
    {
      ZS_DECLARE_CLASS_PTR(DNSQuery)
      ZS_DECLARE_CLASS_PTR(DNSAQuery)
      ZS_DECLARE_CLASS_PTR(DNSAAAAQuery)
      ZS_DECLARE_CLASS_PTR(DNSSRVQuery)
      ZS_DECLARE_CLASS_PTR(DNSAorAAAAQuery)
      ZS_DECLARE_CLASS_PTR(DNSSRVResolverQuery)
      ZS_DECLARE_CLASS_PTR(DNSInstantResultQuery)
      ZS_DECLARE_CLASS_PTR(DNSListQuery)

#ifdef WINRT
      ZS_DECLARE_CLASS_PTR(DNSWinRT)
#endif //WINRT
      

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark helpers
      #pragma mark

      //-----------------------------------------------------------------------
      static Log::Params slog(const char *message)
      {
        return Log::Params(message, "DNS");
      }

      //-----------------------------------------------------------------------
      static bool srvCompare(const IDNS::SRVResult::SRVRecord &first, const IDNS::SRVResult::SRVRecord &second)
      {
        if (first.mPriority < second.mPriority)
          return true;
        if (first.mPriority > second.mPriority)
          return false;

        DWORD total = (((DWORD)first.mWeight)) + (((DWORD)second.mWeight));

        // they are equal, we have to compare relative weight
        DWORD random = 0;

        AutoSeededRandomPool rng;
        rng.GenerateBlock((BYTE *)&random, sizeof(random));
        if (0 == total)
          return (0 == (random % 2) ? true : false);  // equal chance, 50-50

        random %= total;
        if (random < (((DWORD)first.mWeight)))
          return true;

        return false;
      }

      //-----------------------------------------------------------------------
      static void sortSRV(IDNS::SRVResult &result)
      {
        result.mRecords.sort(srvCompare);
      }

      //-----------------------------------------------------------------------
      static void sortSRV(IDNS::SRVResultPtr result)
      {
        if (!result) return;
        sortSRV(*(result.get()));
      }

      //-----------------------------------------------------------------------
      static void copyToAddressList(
                                    const std::list<IPAddress> &source,
                                    std::list<IPAddress> &dest,
                                    bool includeIPv4 = true,
                                    bool includeIPv6 = true
                                    )
      {
        for(std::list<IPAddress>::const_iterator iter = source.begin(); iter != source.end(); ++iter) {
          if ((*iter).isIPv4()) {
            if (includeIPv4)
              dest.push_back(*iter);
          } else {
            if (includeIPv6)
              dest.push_back(*iter);
          }
        }
      }

      //-----------------------------------------------------------------------
      static void fixDefaultPort(std::list<IPAddress> &result, WORD defaultPort)
      {
        for(std::list<IPAddress>::iterator iter = result.begin(); iter != result.end(); ++iter) {
          if (0 == (*iter).getPort())
            (*iter).setPort(defaultPort);
        }
      }

      //-----------------------------------------------------------------------
      static void fixDefaultPort(IDNS::AResult &result, WORD defaultPort)
      {
        fixDefaultPort(result.mIPAddresses, defaultPort);
      }

      //-----------------------------------------------------------------------
      static void fixDefaultPort(IDNS::AResultPtr result, WORD defaultPort)
      {
        fixDefaultPort(*(result.get()), defaultPort);
      }

      //-----------------------------------------------------------------------
      static void fixDefaultPort(IDNS::SRVResult::SRVRecord &result, WORD defaultPort)
      {
        if (result.mAResult)
          fixDefaultPort(result.mAResult, defaultPort);
        if (result.mAAAAResult)
          fixDefaultPort(result.mAAAAResult, defaultPort);
      }

      //-----------------------------------------------------------------------
      static void fixDefaultPort(IDNS::SRVResult &result, WORD defaultPort)
      {
        if (0 == defaultPort)
          return;

        for (IDNS::SRVResult::SRVRecordList::iterator iter = result.mRecords.begin(); iter != result.mRecords.end(); ++iter) {
          fixDefaultPort(*iter, defaultPort);
        }
      }

      //-----------------------------------------------------------------------
      static void fixDefaultPort(IDNS::SRVResultPtr result, WORD defaultPort)
      {
        fixDefaultPort(*(result.get()), defaultPort);
      }

      //-----------------------------------------------------------------------
      static void tokenize(
                           const String &input,
                           StringList &output,
                           const String &delimiters = " ",
                           const bool includeEmpty = false
                           )
      {
        // so much nicer when something thinks through things for you:
        // http://stackoverflow.com/a/1493195/894732

        String::size_type pos = 0, lastPos = 0;

        while(true)
        {
          pos = input.find_first_of(delimiters, lastPos);

          if (pos == String::npos) {
            pos = input.length();
            if ((pos != lastPos) ||
                (includeEmpty)) {
              output.push_back(std::string(input.data()+lastPos, pos-lastPos));
            }
            break;
          }

          if ((pos != lastPos) ||
              (includeEmpty)) {
            output.push_back(std::string(input.data() + lastPos, pos-lastPos));
          }

          lastPos = pos + 1;
        }
      }

      //-----------------------------------------------------------------------
      static bool isIPAddressList(
                                  const char *name,
                                  WORD defaultPort,
                                  IPAddressList &outIPAddresses
                                  )
      {
        bool found = false;

        try {
          StringList tokenizedList;

          tokenize(String(name ? name : ""), tokenizedList, ",");

          for (StringList::iterator iter = tokenizedList.begin(); iter != tokenizedList.end(); ++iter) {
            const String &value = (*iter);
            if (!IPAddress::isConvertable(value)) return false;

            IPAddress temp(value, defaultPort);
            outIPAddresses.push_back(temp);
            found = true;
          }
        } catch(IPAddress::Exceptions::ParseError &) {
          return false;
        }

        return found;
      }

      //-----------------------------------------------------------------------
      static bool shouldResolveAWhenAnIP(IDNS::SRVLookupTypes types)
      {
        if (IDNS::SRVLookupType_LookupOnly == types) return true;
        if (0 != (IDNS::SRVLookupType_AutoLookupA & types)) return true;
        if (0 != (IDNS::SRVLookupType_FallbackToALookup & types)) return true;
        return false;
      }

      //-----------------------------------------------------------------------
      static bool shouldResolveAAAAWhenAnIP(IDNS::SRVLookupTypes types)
      {
        if (IDNS::SRVLookupType_LookupOnly == types) return true;
        if (0 != (IDNS::SRVLookupType_AutoLookupAAAA & types)) return true;
        if (0 != (IDNS::SRVLookupType_FallbackToAAAALookup & types)) return true;
        return false;
      }

      //-----------------------------------------------------------------------
      static bool isDNSsList(
                             const char *name,
                             StringList &outList
                             )
      {
        StringList tokenizedList;
        tokenize(String(name), tokenizedList, ",");

        if (tokenizedList.size() > 1) {
          outList = tokenizedList;
          return true;
        }
        return false;
      }

      //-----------------------------------------------------------------------
      static void merge(
                        IDNS::AResultPtr &ioResult,
                        const IDNS::AResultPtr &add
                        )
      {
        if (!ioResult) {
          ioResult = add;
          return;
        }
        if (ioResult->mName.isEmpty()) {
          ioResult->mName = add->mName;
        }
        if (ioResult->mTTL < add->mTTL) {
          ioResult->mTTL = add->mTTL;
        }
        for (IPAddressList::const_iterator iter = add->mIPAddresses.begin(); iter != add->mIPAddresses.end(); ++iter)
        {
          const IPAddress &ip = (*iter);
          ioResult->mIPAddresses.push_back(ip);
        }
      }

      //-----------------------------------------------------------------------
      static void merge(
                        IDNS::SRVResultPtr &ioResult,
                        const IDNS::SRVResultPtr &add
                        )
      {
        typedef IDNS::SRVResult::SRVRecord SRVRecord;
        typedef IDNS::SRVResult::SRVRecordList SRVRecordList;

        if (!ioResult) {
          ioResult = add;
          return;
        }
        if (ioResult->mName.isEmpty()) {
          ioResult->mName = add->mName;
        }
        if (ioResult->mService.isEmpty()) {
          ioResult->mService = add->mService;
        }
        if (ioResult->mProtocol.isEmpty()) {
          ioResult->mProtocol = add->mProtocol;
        }
        if (ioResult->mTTL < add->mTTL) {
          ioResult->mTTL = add->mTTL;
        }

        for (SRVRecordList::const_iterator iter = add->mRecords.begin(); iter != add->mRecords.end(); ++iter)
        {
          const SRVRecord &record = (*iter);
          ioResult->mRecords.push_back(record);
        }
      }

      //-----------------------------------------------------------------------
      static String extractPort(const char *name, WORD &port)
      {
        String str(name);
        auto pos = str.find(':');
        if (String::npos == pos) return str;

        String strPort = str.substr(pos+1);
        try {
          port = Numeric<WORD>(strPort);
        } catch(const Numeric<WORD>::ValueOutOfRange &) {
          ZS_LOG_WARNING(Detail, slog("failed to extract port") + ZS_PARAMIZE(strPort))
          return str;
        }
        str = str.substr(0, pos);
        return str;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DNSQuery
      #pragma mark

      class DNSQuery : public SharedRecursiveLock,
                       public IDNSQuery
      {
      protected:
        struct make_private {};

      protected:
        //---------------------------------------------------------------------
        virtual void onAResult(IDNS::AResultPtr result) {}

        //---------------------------------------------------------------------
        virtual void onAAAAResult(IDNS::AAAAResultPtr result) {}

        //---------------------------------------------------------------------
        virtual void onSRVResult(IDNS::SRVResultPtr result) {}

      protected:
        //---------------------------------------------------------------------
        // At all times the object reference to a DNSQuery is the caller which
        // created the query in the first place so the DNSQuery objects
        // destruction causes the corresponding outstanding DNSQuery object to
        // get destroyed. The monitor does not need to maintain a strong
        // reference to the query object, however, when there is an oustanding
        // dns_query object at any time the result could come back with a
        // void * which needs to be cast to our object. Normally this would
        // require a strong reference to exist to the object except we use
        // this indirection where a strong reference is maintained to that
        // object with a weak reference to the real object thus the DNSQuery
        // can be cancelled by just deleted the DNSQuery object.
        ZS_DECLARE_CLASS_PTR(DNSIndirectReference)

        //---------------------------------------------------------------------
        //---------------------------------------------------------------------
        //---------------------------------------------------------------------
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSQuery::DNSIndirectReference
        #pragma mark

        class DNSIndirectReference : public DNSMonitor::IResult {
        public:
          //-------------------------------------------------------------------
          static DNSIndirectReferencePtr create(DNSQueryPtr query) {
            DNSIndirectReferencePtr pThis(make_shared<DNSIndirectReference>());
            pThis->mThisWeak = pThis;
            pThis->mMonitor = DNSMonitor::singleton();
            pThis->mOuter = query;
            pThis->mQueryID = 0;
            return pThis;
          }

          //-------------------------------------------------------------------
          ~DNSIndirectReference()
          {
            mThisWeak.reset();
            cancel();
          }

          //-------------------------------------------------------------------
          #pragma mark
          #pragma mark DNSQuery::DNSIndirectReference => DNSMonitor::IResult
          #pragma mark

          //-------------------------------------------------------------------
          // when cleaning out a strong reference to yourself, you must ensure
          // to keep the reference alive in the stack so the object is
          // destroyed after the mThis variable is reset
          virtual PUID getID() const {return mID;}

          //-------------------------------------------------------------------
          virtual void cancel()
          {
            DNSMonitorPtr monitor = mMonitor.lock();
            if (!monitor) return;

            monitor->cancel(mQueryID, mThisWeak.lock());
          }

          //-------------------------------------------------------------------
          virtual void setQueryID(QueryID queryID)
          {
            mQueryID = queryID;
          }

          //-------------------------------------------------------------------
          virtual void onCancel()
          {
            DNSQueryPtr outer = mOuter.lock();
            if (!outer)
              return;

            outer->cancel();
            mOuter.reset();
          }

          //-------------------------------------------------------------------
          virtual void onAResult(IDNS::AResultPtr result) {
            DNSQueryPtr outer = mOuter.lock();
            if (!outer)
              return;

            outer->onAResult(IDNS::cloneA(result));
            mOuter.reset();
          }

          //-------------------------------------------------------------------
          virtual void onAAAAResult(IDNS::AAAAResultPtr result) {
            DNSQueryPtr outer = mOuter.lock();
            if (!outer)
              return;

            outer->onAAAAResult(IDNS::cloneAAAA(result));
            mOuter.reset();
          }

          //-------------------------------------------------------------------
          virtual void onSRVResult(IDNS::SRVResultPtr result) {
            DNSQueryPtr outer = mOuter.lock();
            if (!outer)
              return;

            result = IDNS::cloneSRV(result);
            sortSRV(result);

            outer->onSRVResult(result);
            mOuter.reset();
          }

        public:
          //-------------------------------------------------------------------
          #pragma mark
          #pragma mark DNSQuery::DNSIndirectReference => (data)
          #pragma mark

          PUID mID;
          DNSIndirectReferenceWeakPtr mThisWeak;
          DNSQueryWeakPtr mOuter;

          DNSMonitorWeakPtr mMonitor;
          QueryID mQueryID;
        };

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSQuery => (internal/derived)
        #pragma mark

        //---------------------------------------------------------------------
        DNSQuery(
                 DNSMonitorPtr monitor,
                 IDNSDelegatePtr delegate
                 ) :
          mMonitor(monitor),
          SharedRecursiveLock(monitor ? *monitor : SharedRecursiveLock::create()),
          mObjectName("DNSQuery")
        {
          ZS_THROW_INVALID_USAGE_IF(!delegate)
          IMessageQueuePtr queue = Helper::getServiceQueue();
          if (!queue) {
            ZS_THROW_BAD_STATE_MSG_IF(!queue, "The service thread was not created")
          }

          mDelegate = IDNSDelegateProxy::createWeak(delegate);
          mMonitor = DNSMonitor::singleton();
        }

        //---------------------------------------------------------------------
        ~DNSQuery() { mThisWeak.reset(); cancel(); }

        //---------------------------------------------------------------------
        Log::Params log(const char *message) const
        {
          ElementPtr objectEl = Element::create(mObjectName);
          IHelper::debugAppend(objectEl, "id", mID);
          return Log::Params(message, objectEl);
        }

        //---------------------------------------------------------------------
        virtual void abortEarly()
        {
          AutoRecursiveLock lock(*this);

          cancel();

          if (!mDelegate) return;

          DNSQueryPtr pThis = mThisWeak.lock();
          if (!pThis) return;

          try {
            mDelegate->onLookupCompleted(pThis);
          } catch (IDNSDelegateProxy::Exceptions::DelegateGone &) {
          }

          mDelegate.reset();
        }

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSQuery => IDNSQuery
        #pragma mark

        //---------------------------------------------------------------------
        virtual PUID getID() const {return mID;}

        //---------------------------------------------------------------------
        virtual void cancel()
        {
          AutoRecursiveLock lock(*this);

          if (mQuery) {
            mQuery->cancel();
            mQuery.reset();
          }
        }

        //---------------------------------------------------------------------
        virtual bool hasResult() const {return mA || mAAAA || mSRV;}

        //---------------------------------------------------------------------
        virtual bool isComplete() const {return !mQuery;}

        //---------------------------------------------------------------------
        virtual AResultPtr getA() const {return IDNS::cloneA(mA);}

        //---------------------------------------------------------------------
        virtual AAAAResultPtr getAAAA() const {return IDNS::cloneAAAA(mAAAA);}

        //---------------------------------------------------------------------
        virtual SRVResultPtr getSRV() const {return IDNS::cloneSRV(mSRV);}

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSQuery => (internal)
        #pragma mark

        //---------------------------------------------------------------------
        void done()
        {
          mQuery.reset();
        }

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSQuery => (data)
        #pragma mark

        DNSMonitorPtr mMonitor;
        AutoPUID mID;
        DNSQueryWeakPtr mThisWeak;
        const char *mObjectName;

        IDNSDelegatePtr mDelegate;

        DNSIndirectReferencePtr mQuery;

        AResultPtr mA;
        AAAAResultPtr mAAAA;
        SRVResultPtr mSRV;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DNSAQuery
      #pragma mark

      class DNSAQuery : public DNSQuery
      {
      public:
        DNSAQuery(const make_private &, IDNSDelegatePtr delegate, const char *name, WORD port) :
          DNSQuery(DNSMonitor::singleton(), delegate),
          mName(name),
          mPort(port)
        {
          mObjectName = "DNSAQuery";
        }

      public:
        //---------------------------------------------------------------------
        static DNSAQueryPtr create(IDNSDelegatePtr delegate, const char *name, WORD port)
        {
          DNSAQueryPtr pThis(make_shared<DNSAQuery>(make_private{}, delegate, name, port));
          pThis->mThisWeak = pThis;
          pThis->mMonitor = DNSMonitor::singleton();
          pThis->mQuery = DNSIndirectReference::create(pThis);

          if (pThis->mMonitor) {
            pThis->mMonitor->submitAQuery(name, 0, pThis->mQuery);
          } else {
            pThis->abortEarly();
          }

          return pThis;
        }

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSAQuery => IDNSQuery
        #pragma mark

        //---------------------------------------------------------------------
        virtual void onAResult(IDNS::AResultPtr result)
        {
          AutoRecursiveLock lock(*this);
          if (!mQuery) {
            ZS_LOG_WARNING(Detail, log("A record lookup was cancelled before result arrived") + ZS_PARAM("name", mName))
            return;
          }
          done();

          mA = result;

          if (mA) {
            for (IDNS::AResult::IPAddressList::iterator iter = mA->mIPAddresses.begin(); iter != mA->mIPAddresses.end(); ++iter)
            {
              IPAddress &ipAddress = (*iter);
              if (0 != mPort) {
                ipAddress.setPort(mPort);
              }
              ZS_LOG_DEBUG(log("A record found") + ZS_PARAM("ip", ipAddress.string()))
            }
            EventWriteOpServicesDnsLookupSuccessEventFired(__func__, mID, "A", mName);
            mA->trace(__func__);
          } else {
            EventWriteOpServicesDnsLookupFailedEventFired(__func__, mID, "A", mName);
            ZS_LOG_DEBUG(log("A record lookup failed") + ZS_PARAM("name", mName))
          }

          EventWriteOpServicesDnsLookupCompleteEventFired(__func__, mID, "A", mName);

          try {
            mDelegate->onLookupCompleted(mThisWeak.lock());
          } catch (IDNSDelegateProxy::Exceptions::DelegateGone &) {
          }
        }

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSAQuery => (data)
        #pragma mark

        String mName;
        WORD mPort;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DNSAAAAQuery
      #pragma mark

      class DNSAAAAQuery : public DNSQuery
      {
      public:
        DNSAAAAQuery(const make_private &, IDNSDelegatePtr delegate, const char *name, WORD port) :
          DNSQuery(DNSMonitor::singleton(), delegate),
          mName(name),
          mPort(port)
        {
          mObjectName = "DNSAAAAQuery";
        }

      public:
        //---------------------------------------------------------------------
        static DNSAAAAQueryPtr create(IDNSDelegatePtr delegate, const char *name, WORD port)
        {
          DNSAAAAQueryPtr pThis(make_shared<DNSAAAAQuery>(make_private{}, delegate, name, port));
          pThis->mThisWeak = pThis;
          pThis->mMonitor = DNSMonitor::singleton();
          pThis->mQuery = DNSIndirectReference::create(pThis);

          if (pThis->mMonitor) {
            pThis->mMonitor->submitAAAAQuery(name, 0, pThis->mQuery);
          } else {
            pThis->abortEarly();
          }

          return pThis;
        }

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSAAAAQuery => IDNSQuery
        #pragma mark

        //---------------------------------------------------------------------
        virtual void onAAAAResult(IDNS::AAAAResultPtr result)
        {
          AutoRecursiveLock lock(*this);
          if (!mQuery) {
            ZS_LOG_WARNING(Detail, log("AAAA was cancelled before result arrived") + ZS_PARAM("name", mName))
            return;
          }
          done();

          mAAAA = result;

          if (mAAAA) {
            for (IDNS::AResult::IPAddressList::iterator iter = mAAAA->mIPAddresses.begin(); iter != mAAAA->mIPAddresses.end(); ++iter)
            {
              IPAddress &ipAddress = (*iter);
              if (0 != mPort) {
                ipAddress.setPort(mPort);
              }
              ZS_LOG_DEBUG(log("AAAA record found") + ZS_PARAM("ip", ipAddress.string()))
            }
            EventWriteOpServicesDnsLookupSuccessEventFired(__func__, mID, "AAAA", mName);
            mAAAA->trace(__func__);
          } else {
            EventWriteOpServicesDnsLookupFailedEventFired(__func__, mID, "AAAA", mName);
            ZS_LOG_DEBUG(log("AAAA record lookup failed") + ZS_PARAM("name", mName))
          }

          EventWriteOpServicesDnsLookupCompleteEventFired(__func__, mID, "AAAA", mName);

          try {
            mDelegate->onLookupCompleted(mThisWeak.lock());
          } catch (IDNSDelegateProxy::Exceptions::DelegateGone &) {
          }
        }

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSAAAAQuery => (data)
        #pragma mark

        String mName;
        WORD mPort;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DNSSRVQuery
      #pragma mark

      class DNSSRVQuery : public DNSQuery
      {
      public:
        DNSSRVQuery(
                    const make_private &,
                    IDNSDelegatePtr delegate,
                    const char *name,
                    const char *service,
                    const char *protocol,
                    WORD port
                    ) :
          DNSQuery(DNSMonitor::singleton(), delegate),
          mName(name),
          mService(service),
          mProtocol(protocol),
          mPort(port)
        {
          mObjectName = "DNSSRVQuery";
        }

      public:
        //---------------------------------------------------------------------
        static DNSSRVQueryPtr create(
                                     IDNSDelegatePtr delegate,
                                     const char *name,
                                     const char *service,
                                     const char *protocol,
                                     WORD port
                                     )
        {
          DNSSRVQueryPtr pThis(make_shared<DNSSRVQuery>(make_private{}, delegate, name, service, protocol, port));
          pThis->mThisWeak = pThis;
          pThis->mMonitor = DNSMonitor::singleton();
          pThis->mQuery = DNSIndirectReference::create(pThis);

          if (pThis->mMonitor) {
            pThis->mMonitor->submitSRVQuery(name, service, protocol, 0, pThis->mQuery);
          } else {
            pThis->abortEarly();
          }
          return pThis;
        }

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSSRVQuery => IDNSQuery
        #pragma mark

        //---------------------------------------------------------------------
        virtual void onSRVResult(IDNS::SRVResultPtr result)
        {
          AutoRecursiveLock lock(*this);
          if (!mQuery) {
            ZS_LOG_WARNING(Detail, log("SRV record lookup was cancelled before result arrived") + ZS_PARAM("name", mName) + ZS_PARAM("service", mService) + ZS_PARAM("protocol", mProtocol))
            return;
          }
          done();

          mSRV = result;
          if (mSRV) {
            ZS_LOG_DEBUG(log("SRV completed") + ZS_PARAM("name", mName) + ZS_PARAM("service", mService) + ZS_PARAM("protocol", mProtocol))
            for (IDNS::SRVResult::SRVRecordList::iterator iter = mSRV->mRecords.begin(); iter != mSRV->mRecords.end(); ++iter)
            {
              SRVResult::SRVRecord &srvRecord = (*iter);
              WORD port = srvRecord.mPort;
              if (0 == port) port = mPort;

              bool output = false;

              if (srvRecord.mAResult) {
                for (auto iterIPs = srvRecord.mAResult->mIPAddresses.begin(); iterIPs != srvRecord.mAResult->mIPAddresses.end(); ++iterIPs) {
                  IPAddress &ip = (*iterIPs);
                  if (0 == ip.getPort()) {
                    ip.setPort(port);
                  }
                  output = true;
                  ZS_LOG_DEBUG(log("SRV record found") + ZS_PARAM("name", srvRecord.mName) + ZS_PARAM("port", srvRecord.mPort) + ZS_PARAM("priority", srvRecord.mPriority) + ZS_PARAM("weight", srvRecord.mWeight) + ZS_PARAM("ip", ip.string()))
                }
              }
              if (srvRecord.mAAAAResult) {
                for (auto iterIPs = srvRecord.mAAAAResult->mIPAddresses.begin(); iterIPs != srvRecord.mAAAAResult->mIPAddresses.end(); ++iterIPs) {
                  IPAddress &ip = (*iterIPs);
                  if (0 == ip.getPort()) {
                    ip.setPort(port);
                  }
                  output = true;
                  ZS_LOG_DEBUG(log("SRV record found") + ZS_PARAM("name", srvRecord.mName) + ZS_PARAM("port", srvRecord.mPort) + ZS_PARAM("priority", srvRecord.mPriority) + ZS_PARAM("weight", srvRecord.mWeight) + ZS_PARAM("ip", ip.string()))
                }
              }
              if (!output) {
                ZS_LOG_DEBUG(log("SRV record found") + ZS_PARAM("name", srvRecord.mName) + ZS_PARAM("port", srvRecord.mPort) + ZS_PARAM("priority", srvRecord.mPriority) + ZS_PARAM("weight", srvRecord.mWeight))
              }
            }
            EventWriteOpServicesDnsLookupSuccessEventFired(__func__, mID, "SRV", mName);
            mSRV->trace(__func__);
          } else {
            EventWriteOpServicesDnsLookupFailedEventFired(__func__, mID, "SRV", mName);
            ZS_LOG_DEBUG(log("SRV record lookup failed") + ZS_PARAM("name", mName) + ZS_PARAM("service", mService) + ZS_PARAM("protocol", mProtocol))
          }

          EventWriteOpServicesDnsLookupCompleteEventFired(__func__, mID, "SRV", mName);

          try {
            mDelegate->onLookupCompleted(mThisWeak.lock());
          }
          catch (IDNSDelegateProxy::Exceptions::DelegateGone &) {
          }
        }

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSSRVQuery (data)
        #pragma mark

        String mName;
        String mService;
        String mProtocol;
        WORD mPort;
      };


      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DNSAorAAAAQuery
      #pragma mark

      class DNSAorAAAAQuery : public MessageQueueAssociator,
                              public IDNSQuery,
                              public IDNSDelegate
      {
      protected:
        struct make_private {};
      public:
        //---------------------------------------------------------------------
        DNSAorAAAAQuery(
                        const make_private &,
                        IMessageQueuePtr queue,
                        IDNSDelegatePtr delegate
                        ) :
          MessageQueueAssociator(queue),
          mDelegate(IDNSDelegateProxy::createWeak(queue, delegate))
        {
        }

      protected:
        //---------------------------------------------------------------------
        void init(const char *name)
        {
          AutoRecursiveLock lock(mLock);

          mName = String(name);

          mALookup = IDNS::lookupA(mThisWeak.lock(), name);
          mAAAALookup = IDNS::lookupAAAA(mThisWeak.lock(), name);

          EventWriteOpServicesDnsLookupResolverSubQuery(__func__, mID, "A or AAAA", name, ((bool)mALookup) ? mALookup->getID() : 0);
          EventWriteOpServicesDnsLookupResolverSubQuery(__func__, mID, "A or AAAA", name, ((bool)mAAAALookup) ? mAAAALookup->getID() : 0);
        }

        //---------------------------------------------------------------------
        void report()
        {
          if (mALookup) {
            if (!mALookup->isComplete()) return;
          }
          if (mAAAALookup) {
            if (!mAAAALookup->isComplete()) return;
          }

          if (!mDelegate) return;

          EventWriteOpServicesDnsLookupCompleteEventFired(__func__, mID, "A or AAAA", mName);

          try {
            mDelegate->onLookupCompleted(mThisWeak.lock());
          } catch(IDNSDelegateProxy::Exceptions::DelegateGone &) {
          }

          mDelegate.reset();
        }

      public:
        //---------------------------------------------------------------------
        static DNSAorAAAAQueryPtr create(
                                         IDNSDelegatePtr delegate,
                                         const char *name
                                         )
        {
          ZS_THROW_INVALID_USAGE_IF(!delegate)
          IMessageQueuePtr queue = Helper::getServiceQueue();
          ZS_THROW_BAD_STATE_IF(!queue)

          DNSAorAAAAQueryPtr pThis(make_shared<DNSAorAAAAQuery>(make_private{}, queue, delegate));
          pThis->mThisWeak = pThis;
          pThis->init(name);
          return pThis;
        }

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSAorAAAAQuery => IDNSQuery
        #pragma mark

        //---------------------------------------------------------------------
        virtual PUID getID() const {return mID;}

        //---------------------------------------------------------------------
        virtual void cancel()
        {
          AutoRecursiveLock lock(mLock);

          if (mALookup)
            mALookup->cancel();

          if (mAAAALookup)
            mAAAALookup->cancel();

          // clear out all requests
          mDelegate.reset();
          mALookup.reset();
          mAAAALookup.reset();
        }

        //---------------------------------------------------------------------
        virtual bool hasResult() const
        {
          AutoRecursiveLock lock(mLock);

          bool result = false;
          if (mALookup) {
            result = result || mALookup->hasResult();
          }
          if (mAAAALookup) {
            result = result || mAAAALookup->hasResult();
          }
          return result;
        }

        //---------------------------------------------------------------------
        virtual bool isComplete() const {
          AutoRecursiveLock lock(mLock);

          bool complete = true;
          if (mALookup) {
            complete = complete && mALookup->isComplete();
          }
          if (mAAAALookup) {
            complete = complete && mAAAALookup->isComplete();
          }
          return complete;
        }

        //---------------------------------------------------------------------
        virtual AResultPtr getA() const
        {
          AutoRecursiveLock lock(mLock);

          if (!mALookup) return AResultPtr();
          return mALookup->getA();
        }

        //---------------------------------------------------------------------
        virtual AAAAResultPtr getAAAA() const
        {
          AutoRecursiveLock lock(mLock);

          if (!mAAAALookup) return AAAAResultPtr();
          return mAAAALookup->getAAAA();
        }

        //---------------------------------------------------------------------
        virtual SRVResultPtr getSRV() const {return SRVResultPtr();}

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSAorAAAAQuery => IDNSDelegate
        #pragma mark

        //---------------------------------------------------------------------
        virtual void onLookupCompleted(IDNSQueryPtr query)
        {
          AutoRecursiveLock lock(mLock);
          report();
        }

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSAorAAAAQuery => (data)
        #pragma mark

        mutable RecursiveLock mLock;
        AutoPUID mID;

        DNSAorAAAAQueryWeakPtr mThisWeak;
        IDNSDelegatePtr mDelegate;

        String mName;

        IDNSQueryPtr mALookup;
        IDNSQueryPtr mAAAALookup;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DNSSRVResolverQuery
      #pragma mark

      class DNSSRVResolverQuery : public MessageQueueAssociator,
                                  public IDNSQuery,
                                  public IDNSDelegate
      {
      protected:
        struct make_private {};

      public:
        DNSSRVResolverQuery(
                            const make_private &,
                            IMessageQueuePtr queue,
                            IDNSDelegatePtr delegate,
                            const char *name,
                            const char *service,
                            const char *protocol,
                            WORD defaultPort,
                            WORD defaultPriority,
                            WORD defaultWeight,
                            IDNS::SRVLookupTypes lookupType
                            ) :
          MessageQueueAssociator(queue),
          mDelegate(IDNSDelegateProxy::createWeak(queue, delegate)),
          mOriginalName(name),
          mOriginalService(service),
          mOriginalProtocol(protocol),
          mDefaultPort(defaultPort),
          mDefaultPriority(defaultPriority),
          mDefaultWeight(defaultWeight),
          mLookupType(lookupType)
        {
          ZS_LOG_TRACE(log("created"))
        }

        //---------------------------------------------------------------------
        void init()
        {
          AutoRecursiveLock lock(mLock);
          mSRVLookup = IDNS::lookupSRV(
                                       mThisWeak.lock(),
                                       mOriginalName,
                                       mOriginalService,
                                       mOriginalProtocol,
                                       mDefaultPort,
                                       mDefaultPriority,
                                       mDefaultWeight,
                                       IDNS::SRVLookupType_LookupOnly
                                       );  // do an actual SRV DNS lookup which will not resolve the A or AAAA records

          // SRV might fail but perhaps we can do a backup lookup in parallel...
          IDNSQueryPtr backupQuery;
          if (IDNS::SRVLookupType_FallbackToALookup == (mLookupType & IDNS::SRVLookupType_FallbackToALookup)) {
            if (IDNS::SRVLookupType_FallbackToAAAALookup == (mLookupType & IDNS::SRVLookupType_FallbackToAAAALookup)) {
              backupQuery = IDNS::lookupAorAAAA(mThisWeak.lock(), mOriginalName);
            } else {
              backupQuery = IDNS::lookupA(mThisWeak.lock(), mOriginalName);
            }
          } else {
            if (IDNS::SRVLookupType_FallbackToAAAALookup == (mLookupType & IDNS::SRVLookupType_FallbackToAAAALookup))
              backupQuery = IDNS::lookupAAAA(mThisWeak.lock(), mOriginalName);
          }

          mBackupLookup = backupQuery;

          EventWriteOpServicesDnsLookupResolverSubQuery(__func__, mID, "SRV", mOriginalName, ((bool)mSRVLookup) ? mSRVLookup->getID() : 0);
          EventWriteOpServicesDnsLookupResolverSubQuery(__func__, mID, "SRV", mOriginalName, ((bool)mBackupLookup) ? mBackupLookup->getID() : 0);
        }

      public:
        //---------------------------------------------------------------------
        ~DNSSRVResolverQuery()
        {
          mThisWeak.reset();
          ZS_LOG_TRACE(log("destroyed"))
        }

        //---------------------------------------------------------------------
        static DNSSRVResolverQueryPtr create(
                                             IDNSDelegatePtr delegate,
                                             const char *name,
                                             const char *service,
                                             const char *protocol,
                                             WORD defaultPort,
                                             WORD defaultPriority,
                                             WORD defaultWeight,
                                             IDNS::SRVLookupTypes lookupType
                                             )
        {
          ZS_THROW_INVALID_USAGE_IF(!delegate)
          IMessageQueuePtr queue = Helper::getServiceQueue();
          ZS_THROW_INVALID_USAGE_IF(!queue)

          DNSSRVResolverQueryPtr pThis(make_shared<DNSSRVResolverQuery>(make_private{}, queue, delegate, name, service, protocol, defaultPort, defaultPriority, defaultWeight, lookupType));
          pThis->mThisWeak = pThis;
          pThis->init();
          return pThis;
        }

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSSRVResolverQuery => IDNSQuery
        #pragma mark

        //---------------------------------------------------------------------
        virtual PUID getID() const {return mID;}

        //---------------------------------------------------------------------
        virtual bool hasResult() const
        {
          AutoRecursiveLock lock(mLock);
          if (!isComplete()) return false;
          return (bool)mSRVResult;
        }

        //---------------------------------------------------------------------
        virtual bool isComplete() const
        {
          AutoRecursiveLock lock(mLock);
          return mDidComplete;

          // all the sub resolvers must be complete...
          for (ResolverList::const_iterator iter = mResolvers.begin(); iter != mResolvers.end(); ++iter) {
            if (*iter)
              return false;   // at least one resolver is still active
          }

          if (mSRVLookup) {
            if (!mSRVLookup->isComplete()) {
              return false;
            }
          }

          if (mBackupLookup) {
            if (!mBackupLookup->isComplete()) {
              return false;
            }
          }

          return true;
        }

        //---------------------------------------------------------------------
        virtual AResultPtr getA() const {return AResultPtr();}

        //---------------------------------------------------------------------
        virtual AAAAResultPtr getAAAA() const {return AAAAResultPtr();}

        //---------------------------------------------------------------------
        virtual SRVResultPtr getSRV() const
        {
          AutoRecursiveLock lock(mLock);
          return IDNS::cloneSRV(mSRVResult);
        }

        //---------------------------------------------------------------------
        virtual void cancel()
        {
          AutoRecursiveLock lock(mLock);

          mDidComplete = true;

          if (mSRVLookup)
            mSRVLookup->cancel();
          if (mBackupLookup)
            mBackupLookup->cancel();

          ResolverList::iterator iter = mResolvers.begin();
          for (; iter != mResolvers.end(); ++iter) {
            if (*iter)
              (*iter)->cancel();
            (*iter).reset();
          }

          mResolvers.clear();
        }

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSSRVResolverQuery => IDNSDelegate
        #pragma mark

        //---------------------------------------------------------------------
        virtual void onLookupCompleted(IDNSQueryPtr query)
        {
          AutoRecursiveLock lock(mLock);
          step();
        }

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSSRVResolverQuery => (internal)
        #pragma mark

        //---------------------------------------------------------------------
        void step()
        {
          ZS_LOG_TRACE(log("step") + toDebug())

          if (!stepHandleSRVCompleted()) return;
          if (!stepHandleBackupCompleted()) return;
          if (!stepHandleResolversCompleted()) return;

          ZS_LOG_DEBUG(log("step complete") + toDebug())

          mDidComplete = true;

          report();
        }

        //---------------------------------------------------------------------
        bool stepHandleSRVCompleted()
        {
          if (mSRVResult) {
            ZS_LOG_TRACE(log("already have a result"))
            return true;
          }

          if (!mSRVLookup) {
            ZS_LOG_ERROR(Detail, debug("primary lookup failed to create interface"))
            return true;
          }

          if (!mSRVLookup->isComplete()) {
            ZS_LOG_TRACE(log("waiting for SRV to complete"))
            return false;
          }

          if (!mSRVLookup->hasResult()) {
            ZS_LOG_TRACE(log("SRV lookup failed to resolve (will check if there is a backup)"))
            return true;
          }

          mSRVResult = mSRVLookup->getSRV();

          ZS_LOG_DEBUG(log("SRV result found") + toDebug())

          // the SRV resolved so now we must do a lookup for each SRV result
          for (IDNS::SRVResult::SRVRecordList::iterator iter = mSRVResult->mRecords.begin(); iter != mSRVResult->mRecords.end(); ++iter) {
            SRVResult::SRVRecord &record =(*iter);

            // see if it already has resolve IPs (WinRT will resolve IP addresses natively)
            if ((record.mAResult) ||
                (record.mAAAAResult)) {
              mResolvers.push_back(IDNSQueryPtr()); // push back an empty resolver since the list must be exactly the same length but the resovler will be treated as if it has completed
              continue; // we don't need to go any futher
            }

            // first we should check if this is actually an IP address
            if (IPAddress::isConvertable(record.mName)) {
              IPAddress temp(record.mName, (*iter).mPort);
              IDNS::AResultPtr ipResult(make_shared<IDNS::AResult>());

              ipResult->mName = record.mName;
              ipResult->mTTL = mSRVResult->mTTL;
              ipResult->mIPAddresses.push_back(temp);

              if (temp.isIPv4()) {
                record.mAResult = ipResult;
              } else {
                record.mAAAAResult = ipResult;
              }

              mResolvers.push_back(IDNSQueryPtr()); // push back an empty resolver since the list must be exactly the same length but the resovler will be treated as if it has completed
              continue; // we don't need to go any futher
            }

            const char *queryType = NULL;
            IDNSQueryPtr subQuery;
            if (IDNS::SRVLookupType_AutoLookupA == (mLookupType & IDNS::SRVLookupType_AutoLookupA)) {
              if (IDNS::SRVLookupType_AutoLookupAAAA == (mLookupType & IDNS::SRVLookupType_AutoLookupAAAA)) {
                subQuery = IDNS::lookupAorAAAA(mThisWeak.lock(), record.mName);
                queryType = "A or AAAA";
              } else {
                subQuery = IDNS::lookupA(mThisWeak.lock(), record.mName);
                queryType = "A";
              }
            } else {
              subQuery = IDNS::lookupAAAA(mThisWeak.lock(), (*iter).mName);
              queryType = "AAAA";
            }
            EventWriteOpServicesDnsLookupResolverSubQuery(__func__, mID, queryType, record.mName, ((bool)subQuery) ? subQuery->getID() : 0);
            mResolvers.push_back(subQuery);
          }

          return true;
        }

        //---------------------------------------------------------------------
        bool stepHandleBackupCompleted()
        {
          if (mSRVResult) {
            ZS_LOG_TRACE(log("already have a result"))
            return true;
          }

          if (!mBackupLookup) {
            ZS_LOG_DEBUG(log("back-up query was not used"))
            return true;
          }

          if (!mBackupLookup->isComplete()) {
            ZS_LOG_TRACE(log("waiting for backup query to resolve"))
            return false;
          }

          if (!mBackupLookup->hasResult()) {
            ZS_LOG_WARNING(Trace, log("SRV and backup failed to resolve"))
            return true;
          }

          // we didn't have an SRV result but now we will fake one
          IDNS::SRVResultPtr data(make_shared<IDNS::SRVResult>());

          AResultPtr resultA = mBackupLookup->getA();
          AAAAResultPtr resultAAAA = mBackupLookup->getAAAA();

          data->mName = mOriginalName;
          data->mService = mOriginalService;
          data->mProtocol = mOriginalProtocol;
          data->mTTL = (resultA ? resultA->mTTL : resultAAAA->mTTL);

          IDNS::SRVResult::SRVRecord srvRecord;
          srvRecord.mPriority = mDefaultPriority;
          srvRecord.mWeight = mDefaultWeight;
          srvRecord.mPort = 0;
          srvRecord.mName = mOriginalName;
          srvRecord.mAResult = resultA;
          srvRecord.mAAAAResult = resultAAAA;

          fixDefaultPort(srvRecord, mDefaultPort);

          ZS_LOG_DEBUG(log("DNS A/AAAAA converting to SRV record") + ZS_PARAM("name", srvRecord.mName) + ZS_PARAM("port", srvRecord.mPort) + ZS_PARAM("priority", srvRecord.mPriority) + ZS_PARAM("weight", srvRecord.mWeight))

          data->mRecords.push_back(srvRecord);
          mSRVResult = data;

          return true;
        }

        //---------------------------------------------------------------------
        virtual bool stepHandleResolversCompleted()
        {
          if (mResolvers.size() < 1) {
            ZS_LOG_TRACE(log("no resolvers found"))
            return true;
          }

          if (!mSRVResult) {
            ZS_LOG_TRACE(log("no SRV result found"))
            return true;
          }

          IDNS::SRVResult::SRVRecordList::iterator recIter = mSRVResult->mRecords.begin();
          ResolverList::iterator resIter = mResolvers.begin();
          for (; recIter != mSRVResult->mRecords.end() && resIter != mResolvers.end(); ++recIter, ++resIter) {
            IDNS::SRVResult::SRVRecord &record = (*recIter);
            IDNSQueryPtr &query = (*resIter);

            if (query) {
              if (!query->isComplete()) {
                ZS_LOG_TRACE(log("waiting on at least one resolver to complete"))
                return false;
              }

              record.mAResult = query->getA();
              record.mAAAAResult = query->getAAAA();

              fixDefaultPort(record, record.mPort);

              query.reset();
            }
          }

          ZS_LOG_TRACE(log("all resolvers are complete"))
          return true;
        }

        //---------------------------------------------------------------------
        void report()
        {
          if (!mDelegate) return;

          mResolvers.clear();

          EventWriteOpServicesDnsLookupCompleteEventFired(__func__, mID, "SRV", mOriginalName);

          try {
            mDelegate->onLookupCompleted(mThisWeak.lock());
          } catch(IDNSDelegateProxy::Exceptions::DelegateGone &) {
          }
          mDelegate.reset();
        }

        //---------------------------------------------------------------------
        Log::Params log(const char *message) const
        {
          ElementPtr objectEl = Element::create("DNSSRVResolverQuery");
          IHelper::debugAppend(objectEl, "id", mID);
          return Log::Params(message, objectEl);
        }

        //---------------------------------------------------------------------
        Log::Params debug(const char *message) const
        {
          return Log::Params(message, toDebug());
        }

        //---------------------------------------------------------------------
        virtual ElementPtr toDebug() const
        {
          AutoRecursiveLock lock(mLock);

          ElementPtr resultEl = Element::create("DNSSRVResolverQuery");
          IHelper::debugAppend(resultEl, "id", mID);
          IHelper::debugAppend(resultEl, "completed", mDidComplete);

          IHelper::debugAppend(resultEl, "name", mOriginalName);
          IHelper::debugAppend(resultEl, "service", mOriginalService);
          IHelper::debugAppend(resultEl, "protocol", mOriginalProtocol);

          IHelper::debugAppend(resultEl, "default port", mDefaultPort);
          IHelper::debugAppend(resultEl, "default priority", mDefaultPriority);
          IHelper::debugAppend(resultEl, "default weight", mDefaultWeight);

          IHelper::debugAppend(resultEl, "SRV lookup", (bool)mSRVLookup);
          IHelper::debugAppend(resultEl, "backup lookup", (bool)mBackupLookup);

          IHelper::debugAppend(resultEl, "SRV result", (bool)mSRVResult);

          IHelper::debugAppend(resultEl, "lookup type", mLookupType);

          IHelper::debugAppend(resultEl, "resolvers", mResolvers.size());
          return resultEl;
        }

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSSRVResolverQuery => (data)
        #pragma mark

        mutable RecursiveLock mLock;
        AutoPUID mID;

        DNSSRVResolverQueryWeakPtr mThisWeak;
        IDNSDelegatePtr mDelegate;

        bool mDidComplete {};

        String mOriginalName;
        String mOriginalService;
        String mOriginalProtocol;

        WORD mDefaultPort;
        WORD mDefaultPriority;
        WORD mDefaultWeight;

        IDNSQueryPtr mSRVLookup;
        IDNSQueryPtr mBackupLookup;

        IDNS::SRVResultPtr mSRVResult;

        IDNS::SRVLookupTypes mLookupType;

        typedef std::list<IDNSQueryPtr> ResolverList;
        ResolverList mResolvers;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DNSInstantResultQuery
      #pragma mark

      class DNSInstantResultQuery : public IDNSQuery
      {
      protected:
        struct make_private {};

      public:
        DNSInstantResultQuery(const make_private &) {}

      public:
        //---------------------------------------------------------------------
        static DNSInstantResultQueryPtr create() {return make_shared<DNSInstantResultQuery>(make_private{});}

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSSRVResolverQuery => IDNSQuery
        #pragma mark

        //---------------------------------------------------------------------
        virtual PUID getID() const {return mID;}

        //---------------------------------------------------------------------
        virtual void cancel() {}

        //---------------------------------------------------------------------
        virtual bool hasResult() const {return mA || mAAAA || mSRV;}

        //---------------------------------------------------------------------
        virtual bool isComplete() const {return true;}

        //---------------------------------------------------------------------
        virtual AResultPtr getA() const {return IDNS::cloneA(mA);}

        //---------------------------------------------------------------------
        virtual AAAAResultPtr getAAAA() const {return IDNS::cloneAAAA(mAAAA);}

        //---------------------------------------------------------------------
        virtual SRVResultPtr getSRV() const {return IDNS::cloneSRV(mSRV);}

      public:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSInstantResultQuery => (data)
        #pragma mark

        AResultPtr mA;
        AAAAResultPtr mAAAA;
        SRVResultPtr mSRV;

      private:
        AutoPUID mID;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DNSListQuery
      #pragma mark

      class DNSListQuery : public MessageQueueAssociator,
                           public IDNSQuery,
                           public IDNSDelegate
      {
      protected:
        struct make_private {};

      public:
        typedef IDNS::SRVLookupTypes SRVLookupTypes;
        typedef std::list<IDNSQueryPtr> DNSQueryList;

      public:
        DNSListQuery(
                     const make_private &,
                     IMessageQueuePtr queue,
                     IDNSDelegatePtr delegate
                     ) :
          MessageQueueAssociator(queue),
          mDelegate(IDNSDelegateProxy::createWeak(delegate))
        {
        }

      protected:
        void init()
        {
        }

      public:
        //---------------------------------------------------------------------
        ~DNSListQuery()
        {
          mThisWeak.reset();
          cancel();
        }

        //---------------------------------------------------------------------
        static DNSListQueryPtr createSRV(
                                         IDNSDelegatePtr delegate,
                                         const StringList &dnsList,
                                         const char *service,
                                         const char *protocol,
                                         WORD defaultPort,
                                         WORD defaultPriority,
                                         WORD defaultWeight,
                                         SRVLookupTypes lookupType
                                         )
        {
          ZS_THROW_INVALID_USAGE_IF(!delegate)
          IMessageQueuePtr queue = Helper::getServiceQueue();
          ZS_THROW_BAD_STATE_IF(!queue)

          DNSListQueryPtr pThis(make_shared<DNSListQuery>(make_private{}, queue, delegate));
          pThis->mThisWeak = pThis;

          for (StringList::const_iterator iter = dnsList.begin(); iter != dnsList.end(); ++iter)
          {
            const String &name = (*iter);
            IDNSQueryPtr query = IDNS::lookupSRV(pThis, name, service, protocol, defaultPort, defaultPriority, defaultWeight, lookupType);
            if (!query) {
              ZS_LOG_WARNING(Detail, pThis->log("lookupSRV returned NULL"))
              return DNSListQueryPtr();
            }
            EventWriteOpServicesDnsLookupResolverSubQuery(__func__, pThis->mID, "SRV", name, query->getID());
            pThis->mQueries.push_back(query);
          }

          pThis->init();
          return pThis;
        }

        //---------------------------------------------------------------------
        static DNSListQueryPtr createA(
                                       IDNSDelegatePtr delegate,
                                       const StringList &dnsList
                                       )
        {
          ZS_THROW_INVALID_USAGE_IF(!delegate)
          IMessageQueuePtr queue = Helper::getServiceQueue();
          ZS_THROW_BAD_STATE_IF(!queue)

          DNSListQueryPtr pThis(make_shared<DNSListQuery>(make_private{}, queue, delegate));
          pThis->mThisWeak = pThis;

          for (StringList::const_iterator iter = dnsList.begin(); iter != dnsList.end(); ++iter)
          {
            const String &name = (*iter);
            IDNSQueryPtr query = IDNS::lookupA(pThis, name);
            if (!query) {
              ZS_LOG_WARNING(Detail, pThis->log("lookupA returned NULL"))
              return DNSListQueryPtr();
            }
            EventWriteOpServicesDnsLookupResolverSubQuery(__func__, pThis->mID, "A", name, query->getID());
            pThis->mQueries.push_back(query);
          }

          pThis->init();
          return pThis;
        }

        //---------------------------------------------------------------------
        static DNSListQueryPtr createAAAA(
                                          IDNSDelegatePtr delegate,
                                          const StringList &dnsList
                                          )
        {
          ZS_THROW_INVALID_USAGE_IF(!delegate)
          IMessageQueuePtr queue = Helper::getServiceQueue();
          ZS_THROW_BAD_STATE_IF(!queue)

          DNSListQueryPtr pThis(make_shared<DNSListQuery>(make_private{}, queue, delegate));
          pThis->mThisWeak = pThis;

          for (StringList::const_iterator iter = dnsList.begin(); iter != dnsList.end(); ++iter)
          {
            const String &name = (*iter);
            IDNSQueryPtr query = IDNS::lookupAAAA(pThis, name);
            if (!query) {
              ZS_LOG_WARNING(Detail, pThis->log("lookupAAAA returned NULL"))
              return DNSListQueryPtr();
            }
            EventWriteOpServicesDnsLookupResolverSubQuery(__func__, pThis->mID, "AAAA", name, query->getID());
            pThis->mQueries.push_back(query);
          }

          pThis->init();
          return pThis;
        }

        //---------------------------------------------------------------------
        static DNSListQueryPtr createAorAAAA(
                                             IDNSDelegatePtr delegate,
                                             const StringList &dnsList
                                             )
        {
          ZS_THROW_INVALID_USAGE_IF(!delegate)
          IMessageQueuePtr queue = Helper::getServiceQueue();
          ZS_THROW_BAD_STATE_IF(!queue)

          DNSListQueryPtr pThis(make_shared<DNSListQuery>(make_private{}, queue, delegate));
          pThis->mThisWeak = pThis;

          for (StringList::const_iterator iter = dnsList.begin(); iter != dnsList.end(); ++iter)
          {
            const String &name = (*iter);
            IDNSQueryPtr query = IDNS::lookupAorAAAA(pThis, name);
            if (!query) {
              ZS_LOG_WARNING(Detail, pThis->log("lookupAorAAAA returned NULL"))
              return DNSListQueryPtr();
            }
            EventWriteOpServicesDnsLookupResolverSubQuery(__func__, pThis->mID, "A or AAAA", name, query->getID());
            pThis->mQueries.push_back(query);
          }

          pThis->init();
          return pThis;
        }

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSListQuery => IDNSQuery
        #pragma mark

        //---------------------------------------------------------------------
        virtual PUID getID() const {return mID;}

        //---------------------------------------------------------------------
        virtual void cancel()
        {
          AutoRecursiveLock lock(mLock);
          ZS_LOG_DEBUG(log("cancel called"))

          for (DNSQueryList::iterator iter = mQueries.begin(); iter != mQueries.end(); ++iter)
          {
            IDNSQueryPtr &query = (*iter);
            ZS_LOG_DEBUG(log("cancelling DNS query") + ZS_PARAM("query ID", query->getID()))
            query->cancel();
          }
          mDelegate.reset();
        }

        //---------------------------------------------------------------------
        virtual bool hasResult() const
        {
          AutoRecursiveLock lock(mLock);
          return mA || mAAAA || mSRV;
        }

        //---------------------------------------------------------------------
        virtual bool isComplete() const
        {
          AutoRecursiveLock lock(mLock);
          return !mDelegate;
        }

        //---------------------------------------------------------------------
        virtual AResultPtr getA() const
        {
          AutoRecursiveLock lock(mLock);
          return IDNS::cloneA(mA);
        }

        //---------------------------------------------------------------------
        virtual AAAAResultPtr getAAAA() const
        {
          AutoRecursiveLock lock(mLock);
          return IDNS::cloneAAAA(mAAAA);
        }

        //---------------------------------------------------------------------
        virtual SRVResultPtr getSRV() const
        {
          AutoRecursiveLock lock(mLock);
          return IDNS::cloneSRV(mSRV);
        }

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSListQuery => IDNSDelegate
        #pragma mark

        //---------------------------------------------------------------------
        virtual void onLookupCompleted(IDNSQueryPtr inQuery)
        {
          AutoRecursiveLock lock(mLock);
          ZS_LOG_DEBUG(log("query completed") + ZS_PARAM("query ID", inQuery->getID()))

          if (!mDelegate) {
            ZS_LOG_WARNING(Detail, log("query result came in after delegate was gone") + ZS_PARAM("query ID", inQuery->getID()))
            return;
          }

          for (DNSQueryList::iterator dnsIter = mQueries.begin(); dnsIter != mQueries.end(); )
          {
            DNSQueryList::iterator current = dnsIter;
            ++dnsIter;

            IDNSQueryPtr &query = (*current);
            if (query == inQuery) {
              ZS_LOG_DEBUG(log("found matching query thus removing query as it is done"))

              AResultPtr aResult = query->getA();
              if (aResult) {
                ZS_LOG_DEBUG(log("merging A result"))
                merge(mA, aResult);
              }

              AAAAResultPtr aaaaResult = query->getAAAA();
              if (aaaaResult) {
                ZS_LOG_DEBUG(log("merging AAAA result"))
                merge(mAAAA, aaaaResult);
              }

              SRVResultPtr srvResult = query->getSRV();
              if (srvResult) {
                ZS_LOG_DEBUG(log("merging SRV result"))
                merge(mSRV, srvResult);
              }

              mQueries.erase(current);
              break;
            }
          }

          if (mQueries.size() > 0) {
            ZS_LOG_DEBUG(log("waiting for more queries to complete") + ZS_PARAM("waiting total", mQueries.size()))
            return;
          }

          if (!hasResult()) {
            ZS_LOG_WARNING(Detail, log("all DNS queries in the list failed"))
          }

          sortSRV(mSRV);

          try {
            mDelegate->onLookupCompleted(mThisWeak.lock());
          } catch (IDNSDelegateProxy::Exceptions::DelegateGone &) {
            ZS_LOG_WARNING(Detail, log("delegate gone"))
            mDelegate.reset();
          }

          cancel();
        }

      private:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSListQuery => (internal)
        #pragma mark

        //---------------------------------------------------------------------
        Log::Params log(const char *message) const
        {
          ElementPtr objectEl = Element::create("DNSListQuery");
          IHelper::debugAppend(objectEl, "id", mID);
          return Log::Params(message, objectEl);
        }

      private:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DNSListQuery => (data)
        #pragma mark

        mutable RecursiveLock mLock;
        AutoPUID mID;
        IDNSQueryWeakPtr mThisWeak;
        AResultPtr mA;
        AAAAResultPtr mAAAA;
        SRVResultPtr mSRV;

        IDNSDelegatePtr mDelegate;

        DNSQueryList mQueries;
      };

#ifdef WINRT
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DNSWinRT
      #pragma mark

      using Windows::Foundation::Collections::IVectorView;
      using namespace concurrency;
      using Windows::Networking::HostNameType;

      class DNSWinRT : public SharedRecursiveLock,
        public IDNSQuery
      {
      protected:
        struct make_private {};

      public:
        typedef Windows::Networking::Sockets::DatagramSocket DatagramSocket;
        typedef Windows::Networking::HostName HostName;
        typedef Windows::Networking::EndpointPair EndpointPair;

      public:
        //--------------------------------------------------------------------
        DNSWinRT(
                 const make_private &,
                 IDNSDelegatePtr delegate,
                 const char *name,
                 WORD port,
                 bool includeIPv4,
                 bool includeIPv6,
                 const char *serviceName,
                 const char *protocol,
                 WORD defaultPort,
                 WORD defaultPriority,
                 WORD defaultWeight
                 ) :
          SharedRecursiveLock(SharedRecursiveLock::create()),
          mDelegate(IDNSDelegateProxy::createWeak(IHelper::getServiceQueue(), delegate)),
          mName(name),
          mPort(0 == port ? defaultPort : port),
          mIncludeIPv4(includeIPv4),
          mIncludeIPv6(includeIPv6),
          mServiceName(serviceName),
          mProtocol(protocol),
          mDefaultPriority(defaultPriority),
          mDefaultWeight(defaultWeight)
        {
          ZS_LOG_TRACE(log("created"))
          mLookupTypeDebugName = (mServiceName.hasData() ? "SRV" : (mIncludeIPv4 ? (mIncludeIPv6 ? "A or AAAA" : "A") : (mIncludeIPv6 ? "AAAA" : NULL)));
        }

      protected:
        //--------------------------------------------------------------------
        void init()
        {
          AutoRecursiveLock lock(*this);

          PUID id = mID;
          auto thisWeak = mThisWeak;

          Platform::String ^hostnameStr = ref new Platform::String(mName.wstring().c_str());
          Platform::String ^serviceNameStr = mServiceName.hasData() ? ref new Platform::String(mServiceName.wstring().c_str()) : ref new Platform::String(L"0");

          HostName ^hostname;
          try {
            hostname = ref new HostName(hostnameStr);
          } catch(Platform::Exception ^ex) {
            ZS_LOG_WARNING(Detail, log("exception caught") + ZS_PARAM("error", String(ex->Message->Data())) + toDebug())
            cancel();
            return;
          }
          HostNameType debugtype = hostname->Type;

          create_task(DatagramSocket::GetEndpointPairsAsync(hostname, serviceNameStr), mCancellationTokenSource.get_token())
            .then([id, thisWeak](task<IVectorView<EndpointPair^>^> previousTask)
          {
            auto pThis = thisWeak.lock();
            if (!pThis) {
              ZS_LOG_WARNING(Detail, slog(id, "query was abandoned"))
              return;
            }

            try
            {
              ZS_LOG_TRACE(slog(id, "request completed") + pThis->toDebug())

              // Check if any previous task threw an exception.
              IVectorView<EndpointPair ^> ^response = previousTask.get();

              bool isSRV = pThis->mServiceName.hasData();

              EventWriteOpServicesDnsLookupSuccessEventFired(__func__, pThis->mID, pThis->mLookupTypeDebugName, pThis->mName);

              if (nullptr != response) {
                AutoRecursiveLock lock(*pThis);

                for (size_t index = 0; index != response->Size; ++index) {
                  EndpointPair ^pair = response->GetAt(index);
                  if (!pair) {
                    ZS_LOG_WARNING(Detail, slog(id, "endpoint pair is null"))
                    continue;
                  }

                  if (nullptr == pair->RemoteHostName) {
                    ZS_LOG_WARNING(Detail, slog(id, "remote host name is null"))
                    continue;
                  }

                  if (nullptr == pair->RemoteHostName->RawName) {
                    ZS_LOG_WARNING(Detail, slog(id, "remote host raw name is null"))
                    continue;
                  }

                  String host = String(pair->RemoteHostName->RawName->Data());
                  String canonical;
                  if (pair->RemoteHostName->CanonicalName) {
                    canonical = String(pair->RemoteHostName->CanonicalName->Data());
                  }
                  String displayName;
                  if (pair->RemoteHostName->DisplayName) {
                    displayName = String(pair->RemoteHostName->DisplayName->Data());
                  }
                  String service;
                  if (pair->RemoteServiceName) {
                    service = String(pair->RemoteServiceName->Data());
                  }

                  HostNameType type = pair->RemoteHostName->Type;
                  bool isIPv4 = (HostNameType::Ipv4 == type);
                  bool isIPv6 = (HostNameType::Ipv6 == type);
                  if ((isIPv4) &&
                    (!pThis->mIncludeIPv4)) {
                    ZS_LOG_TRACE(slog(id, "filtered out v4 address (since not desired)") + ZS_PARAMIZE(host))
                    continue;
                  }
                  if ((isIPv6) &&
                    (!pThis->mIncludeIPv6)) {
                    ZS_LOG_TRACE(slog(id, "filtered out v6 address (since not desired)") + ZS_PARAMIZE(host))
                    continue;
                  }

                  IPAddress ip;

                  try {
                    IPAddress tempIP(host);
                    ip = tempIP;
                  } catch (IPAddress::Exceptions::ParseError &) {
                    ZS_LOG_WARNING(Debug, slog(id, "failed to convert to IP") + ZS_PARAM("host", host))
                    continue;
                  }

                  if (service.hasData()) {
                    try {
                      WORD port = Numeric<WORD>(service);
                      if (0 != port) {
                        ip.setPort(port);
                      }
                    } catch(const Numeric<WORD>::ValueOutOfRange &) {
                      // ignorred
                    }
                  }

                  if (0 == ip.getPort()) {
                    ip.setPort(pThis->mPort);
                  }

                  ZS_LOG_TRACE(slog(id, "found result") + ZS_PARAM("host", host) + ZS_PARAM("canonical", canonical) + ZS_PARAM("display name", displayName) + ZS_PARAM("service", service) + ZS_PARAM("ip", ip.string()))

                  if (isSRV) {
                    SRVResultPtr srv = pThis->mSRV;
                    if (!pThis->mSRV) {
                      pThis->mSRV = make_shared<SRVResult>();
                      srv = pThis->mSRV;

                      srv->mName = pThis->mName;
                      srv->mProtocol = pThis->mProtocol; // WinRT only support UDP at this time!
                      srv->mService = pThis->mServiceName;
                      srv->mTTL = 3600;       // no default TTL
                    }

                    SRVResult::SRVRecord *useRecord = NULL;
                    for (auto iter = srv->mRecords.begin(); iter != srv->mRecords.end(); ++iter) {
                      SRVResult::SRVRecord &record = (*iter);
                      // add to existing record
                      useRecord = &record;
                      break;
                    }

                    SRVResult::SRVRecord newRecord;

                    if (!useRecord) {
                      useRecord = &newRecord;
                      useRecord->mName = pThis->mName;
                      useRecord->mPort = ip.getPort();
                    }

                    if (0 == ip.getPort()) {
                      ip.setPort(useRecord->mPort);
                    }

                    if (isIPv4) {
                      if (!useRecord->mAResult) {
                        useRecord->mAResult = make_shared<AResult>();
                        useRecord->mAResult->mName = canonical;
                        useRecord->mAResult->mTTL = 3600;
                      }
                      useRecord->mAResult->mIPAddresses.push_back(ip);
                    }

                    if (isIPv6) {
                      if (!useRecord->mAAAAResult) {
                        useRecord->mAAAAResult = make_shared<AAAAResult>();
                        useRecord->mAAAAResult->mName = canonical;
                        useRecord->mAAAAResult->mTTL = 3600;
                      }
                      useRecord->mAAAAResult->mIPAddresses.push_back(ip);
                    }
                    if (useRecord == (&newRecord)) {
                      srv->mRecords.push_back(newRecord);
                    }
                  } else {
                    if (isIPv4) {
                      if (!pThis->mA) {
                        pThis->mA = make_shared<AResult>();
                        pThis->mA->mName = canonical;
                        pThis->mA->mTTL = 3600;
                      }
                      pThis->mA->mIPAddresses.push_back(ip);
                    }
                    if (isIPv6) {
                      if (!pThis->mAAAA) {
                        pThis->mAAAA = make_shared<AAAAResult>();
                        pThis->mAAAA->mName = canonical;
                        pThis->mAAAA->mTTL = 3600;
                      }
                      pThis->mAAAA->mIPAddresses.push_back(ip);
                    }
                  }
                }
              }

              if (pThis) {
                pThis->cancel();
              }

            } catch (const task_canceled&) {
              ZS_LOG_WARNING(Detail, slog(id, "task cancelled"))
              if (pThis) {
                pThis->cancel();
              }
            } catch (Platform::Exception ^ex) {
              if (pThis) {
                EventWriteOpServicesDnsLookupFailedEventFired(__func__, pThis->mID, pThis->mLookupTypeDebugName, pThis->mName);
                ZS_LOG_WARNING(Detail, slog(id, "exception caught") + ZS_PARAM("error", String(ex->Message->Data())) + pThis->toDebug())
                pThis->cancel();
              }
            }
          }, task_continuation_context::use_arbitrary());
        }

      public:
        //--------------------------------------------------------------------
        ~DNSWinRT()
        {
          mThisWeak.reset();
          ZS_LOG_TRACE(log("destroyed"))
          cancel();
        }

        //--------------------------------------------------------------------
        static DNSWinRTPtr create(
          IDNSDelegatePtr delegate,
          const char *name,
          WORD port,
          bool includeIPv4,
          bool includeIPv6,
          const char *serviceName,
          const char *protocol,
          WORD defaultPort,
          WORD defaultPriority,
          WORD defaultWeight
          )
        {
          DNSWinRTPtr pThis(make_shared<DNSWinRT>(make_private{}, delegate, name, port, includeIPv4, includeIPv6, serviceName, protocol, defaultPort, defaultPriority, defaultWeight));
          pThis->mThisWeak = pThis;
          pThis->init();
          return pThis;
        }

        //--------------------------------------------------------------------
        virtual PUID getID() const { return mID; }

        //--------------------------------------------------------------------
        virtual void cancel()
        {
          IDNSDelegatePtr delegate;

          {
            AutoRecursiveLock lock(*this);

            mCancellationTokenSource.cancel();

            delegate = mDelegate;
            mDelegate.reset();
          }

          if (delegate) {
            ZS_LOG_TRACE(log("query completed"))

            EventWriteOpServicesDnsLookupCompleteEventFired(__func__, mID, mLookupTypeDebugName, mName);

            auto pThis = mThisWeak.lock();
            if (pThis) {
              try {
                delegate->onLookupCompleted(pThis);
              } catch (IDNSDelegateProxy::Exceptions::DelegateGone &) {
                ZS_LOG_WARNING(Detail, log("delegate gone"))
              }
            }
          }
        }

        //--------------------------------------------------------------------
        virtual bool hasResult() const
        {
          AutoRecursiveLock lock(*this);
          if (!isComplete()) return false;
          return ((bool)mA) || ((bool)mAAAA) || ((bool)mSRV);
        }

        //--------------------------------------------------------------------
        virtual bool isComplete() const
        {
          AutoRecursiveLock lock(*this);
          return !((bool)mDelegate);
        }

        //--------------------------------------------------------------------
        virtual AResultPtr getA() const
        {
          AutoRecursiveLock lock(*this);
          return mA;
        }

        //--------------------------------------------------------------------
        virtual AAAAResultPtr getAAAA() const
        {
          AutoRecursiveLock lock(*this);
          return mAAAA;
        }

        //--------------------------------------------------------------------
        virtual SRVResultPtr getSRV() const
        {
          AutoRecursiveLock lock(*this);
          return mSRV;
        }

      protected:
        //--------------------------------------------------------------------
        Log::Params log(const char *message) const
        {
          ElementPtr objectEl = Element::create("services::DNSWinRT");
          IHelper::debugAppend(objectEl, "id", mID);
          return Log::Params(message, objectEl);
        }

        //--------------------------------------------------------------------
        static Log::Params slog(PUID id, const char *message)
        {
          ElementPtr objectEl = Element::create("services::DNSWinRT");
          IHelper::debugAppend(objectEl, "id", id);
          return Log::Params(message, objectEl);
        }

        //--------------------------------------------------------------------
        ElementPtr toDebug() const
        {
          AutoRecursiveLock lock(*this);

          ElementPtr resultEl = Element::create("services::DNSWinRT");

          IHelper::debugAppend(resultEl, "id", mID);

          IHelper::debugAppend(resultEl, "name", mName);
          IHelper::debugAppend(resultEl, "port", mPort);
          IHelper::debugAppend(resultEl, "ipv4", mIncludeIPv4);
          IHelper::debugAppend(resultEl, "ipv6", mIncludeIPv6);
          IHelper::debugAppend(resultEl, "service name", mServiceName);
          IHelper::debugAppend(resultEl, "protocol", mProtocol);
          IHelper::debugAppend(resultEl, "priority", mDefaultPriority);
          IHelper::debugAppend(resultEl, "weight", mDefaultWeight);

          IHelper::debugAppend(resultEl, "a", (bool)mA);
          IHelper::debugAppend(resultEl, "aaaa", (bool)mAAAA);
          IHelper::debugAppend(resultEl, "srv", (bool)mSRV);

          return resultEl;
        }

      protected:
        AutoPUID mID;
        DNSWinRTWeakPtr mThisWeak;

        IDNSDelegatePtr mDelegate;

        const char *mLookupTypeDebugName {};
        String mName;
        WORD mPort {};
        bool mIncludeIPv4 {};
        bool mIncludeIPv6 {};
        String mServiceName;
        String mProtocol;
        WORD mDefaultPriority {};
        WORD mDefaultWeight {};

        AResultPtr mA;
        AAAAResultPtr mAAAA;
        SRVResultPtr mSRV;

        concurrency::cancellation_token_source mCancellationTokenSource;
      };
#endif //WINRT

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DNS => IDNS
      #pragma mark

      //-----------------------------------------------------------------------
      IDNSQueryPtr DNS::lookupA(
                                IDNSDelegatePtr delegate,
                                const char *name
                                )
      {
        ZS_THROW_INVALID_USAGE_IF(!name)
        ZS_THROW_INVALID_USAGE_IF(String(name).length() < 1)

        IPAddressList ips;
        if (internal::isIPAddressList(name, 0, ips)) {
          internal::DNSInstantResultQueryPtr temp = internal::DNSInstantResultQuery::create();
          delegate = IDNSDelegateProxy::create(internal::Helper::getServiceQueue(), delegate);

          AResultPtr result = make_shared<AResult>();
          result->mName = name;
          result->mTTL = 3600;

          for (IPAddressList::iterator iter = ips.begin(); iter != ips.end(); ++iter) {
            const IPAddress &ip = (*iter);

            if (ip.isIPv4()) {
              ZS_LOG_DEBUG(log("A record found (no resolve required)") + ZS_PARAM("ip", ip.string()))
              temp->mA = result;
              result->mIPAddresses.push_back(ip);
            } else {
              ZS_LOG_ERROR(Debug, log("IPv6 record found for A record lookup") + ZS_PARAM("input", name) + ZS_PARAM("result ip", ip.string()))
              // DO NOT PUT IN RESOLUTION LIST
            }
          }
          delegate->onLookupCompleted(temp);
          return temp;
        }

        ZS_LOG_DEBUG(log("A lookup") + ZS_PARAM("name", name))

        StringList dnsList;
        if (internal::isDNSsList(name, dnsList)) {
          return internal::DNSListQuery::createA(delegate, dnsList);
        }

        WORD port = 0;
        String strName = extractPort(name, port);

#ifdef WINRT
        return internal::DNSWinRT::create(delegate, strName, port, true, false, NULL, NULL, 0, 0, 0);
#else
        return internal::DNSAQuery::create(delegate, strName, port);
#endif //WINRT
      }

      //-----------------------------------------------------------------------
      IDNSQueryPtr DNS::lookupAAAA(
                                   IDNSDelegatePtr delegate,
                                   const char *name
                                   )
      {
        ZS_THROW_INVALID_USAGE_IF(!name)
        ZS_THROW_INVALID_USAGE_IF(String(name).length() < 1)

        IPAddressList ips;
        if (internal::isIPAddressList(name, 0, ips)) {
          internal::DNSInstantResultQueryPtr temp = internal::DNSInstantResultQuery::create();
          delegate = IDNSDelegateProxy::create(internal::Helper::getServiceQueue(), delegate);

          AAAAResultPtr result = make_shared<AAAAResult>();
          result->mName = name;
          result->mTTL = 3600;
          result->mIPAddresses = ips;

          for (IPAddressList::iterator iter = ips.begin(); iter != ips.end(); ++iter) {
            const IPAddress &ip = (*iter);

            if (ip.isIPv6()) {
              ZS_LOG_DEBUG(log("AAAA record found (no resolve required)") + ZS_PARAM("ip", ip.string()))
              temp->mAAAA = result;
              result->mIPAddresses.push_back(ip);
            } else {
              ZS_LOG_ERROR(Debug, log("IPv4 record found for IPv6 lookup") + ZS_PARAM("input", name) + ZS_PARAM("result ip", ip.string()))
              // DO NOT PUT IN RESOLUTION LIST
            }
          }

          delegate->onLookupCompleted(temp);
          return temp;
        }

        ZS_LOG_DEBUG(log("AAAA lookup") + ZS_PARAM("name", name))

        StringList dnsList;
        if (internal::isDNSsList(name, dnsList)) {
          return internal::DNSListQuery::createAAAA(delegate, dnsList);
        }

        WORD port = 0;
        String strName = extractPort(name, port);

#ifdef WINRT
        return internal::DNSWinRT::create(delegate, strName, port, false, true, NULL, NULL, 0, 0, 0);
#else
        return internal::DNSAAAAQuery::create(delegate, strName, port);
#endif //WINRT
      }

      //-----------------------------------------------------------------------
      IDNSQueryPtr DNS::lookupAorAAAA(
                                      IDNSDelegatePtr delegate,
                                      const char *name
                                      )
      {
        ZS_THROW_INVALID_USAGE_IF(!name)
        ZS_THROW_INVALID_USAGE_IF(String(name).length() < 1)

        IPAddressList ips;
        if (internal::isIPAddressList(name, 0, ips)) {
          internal::DNSInstantResultQueryPtr temp = internal::DNSInstantResultQuery::create();
          delegate = IDNSDelegateProxy::create(internal::Helper::getServiceQueue(), delegate);

          AResultPtr resultA = make_shared<AResult>();
          resultA->mName = name;
          resultA->mTTL = 3600;

          AAAAResultPtr resultAAAA = make_shared<AAAAResult>();
          resultAAAA->mName = name;
          resultAAAA->mTTL = 3600;

          for (IPAddressList::iterator iter = ips.begin(); iter != ips.end(); ++iter) {
            const IPAddress &ip = (*iter);

            if (ip.isIPv4()) {
              ZS_LOG_DEBUG(log("A or AAAA record found A record (no resolve required)") + ZS_PARAM("input", name) + ZS_PARAM("result ip", ip.string()))
              temp->mA = resultA;
              resultA->mIPAddresses.push_back(ip);
            } else {
              ZS_LOG_DEBUG(log("A or AAAA record found AAAA record (no resolve required)") + ZS_PARAM("input", name) + ZS_PARAM("result ip", ip.string()))
              temp->mAAAA = resultAAAA;
              resultAAAA->mIPAddresses.push_back(ip);
            }
          }
          delegate->onLookupCompleted(temp);
          return temp;
        }

        ZS_LOG_DEBUG(log("A or AAAA lookup") + ZS_PARAM("name", name))

        StringList dnsList;
        if (internal::isDNSsList(name, dnsList)) {
          return internal::DNSListQuery::createAorAAAA(delegate, dnsList);
        }

#ifdef WINRT
        WORD port = 0;
        String strName = extractPort(name, port);

        return internal::DNSWinRT::create(delegate, strName, port, true, true, NULL, NULL, 0, 0, 0);
#else
        return internal::DNSAorAAAAQuery::create(delegate, name);
#endif //WINRT
      }

      //-----------------------------------------------------------------------
      IDNSQueryPtr DNS::lookupSRV(
                                  IDNSDelegatePtr delegate,
                                  const char *name,
                                  const char *service,
                                  const char *protocol,
                                  WORD defaultPort,
                                  WORD defaultPriority,
                                  WORD defaultWeight,
                                  SRVLookupTypes lookupType
                                  )
      {
        ZS_THROW_INVALID_USAGE_IF(!delegate)
        ZS_THROW_INVALID_USAGE_IF(!name)
        ZS_THROW_INVALID_USAGE_IF(String(name).length() < 1)

        IPAddressList ips;
        if (internal::isIPAddressList(name, defaultPort, ips)) {
          internal::DNSInstantResultQueryPtr temp = internal::DNSInstantResultQuery::create();
          delegate = IDNSDelegateProxy::create(internal::Helper::getServiceQueue(), delegate);

          SRVResultPtr result(make_shared<SRVResult>());
          result->mName = name;
          result->mService = service;
          result->mProtocol = protocol;
          result->mTTL = 3600;

          SRVResult::SRVRecord record;
          record.mPriority = defaultPriority;
          record.mWeight = defaultWeight;
          record.mPort = defaultPort;
          record.mName = name;

          AResultPtr resultA = make_shared<AResult>();
          resultA->mName = name;
          resultA->mTTL = 3600;

          AAAAResultPtr resultAAAA = make_shared<AAAAResult>();
          resultAAAA->mName = name;
          resultAAAA->mTTL = 3600;

          bool foundAny = false;

          for (IPAddressList::iterator iter = ips.begin(); iter != ips.end(); ++iter) {
            const IPAddress &ip = (*iter);

            bool found = false;

            if (ip.isIPv4()) {
              if (shouldResolveAWhenAnIP(lookupType)) {
                resultA->mIPAddresses.push_back(ip);
                record.mAResult = resultA;
                found = foundAny = true;
              }
            } else {
              if (shouldResolveAAAAWhenAnIP(lookupType)) {
                resultAAAA->mIPAddresses.push_back(ip);
                record.mAAAAResult = resultAAAA;
                found = foundAny = true;
              }
            }
            if (found) {
              ZS_LOG_DEBUG(log("SRV record found SRV record (no resolve required") + ZS_PARAM("input", name) + ZS_PARAM("result ip", ip.string()))
            } else {
              ZS_LOG_WARNING(Debug, log("SRV record found IP address but mismatch on A or AAAA resolution type") + ZS_PARAM("input", name) + ZS_PARAM("result ip", ip.string()))
            }
          }

          if (foundAny) {
            result->mRecords.push_back(record);
            internal::sortSRV(result);
            temp->mSRV = result;
          }
          delegate->onLookupCompleted(temp);
          return temp;
        }

        ZS_LOG_DEBUG(log("SRV lookup") + ZS_PARAM("name", name) + ZS_PARAM("service", service) + ZS_PARAM("protocol", protocol) + ZS_PARAM("default port", defaultPort) + ZS_PARAM("type", (int)lookupType))
        
        StringList dnsList;
        if (internal::isDNSsList(name, dnsList)) {
          return internal::DNSListQuery::createSRV(delegate, dnsList, service, protocol, defaultPort, defaultPriority, defaultWeight, lookupType);
        }

        WORD port = 0;
        String strName = extractPort(name, port);
        if (0 != port) {
          defaultPort = port;
        }

        if (SRVLookupType_LookupOnly != lookupType) {
          return internal::DNSSRVResolverQuery::create(delegate, strName, service, protocol, defaultPort, defaultPriority, defaultWeight, lookupType);
        }

#ifdef WINRT
        String protocolStr(protocol);
        if (protocolStr == "udp") {
          return internal::DNSWinRT::create(delegate, strName, port, shouldResolveAWhenAnIP(lookupType), shouldResolveAAAAWhenAnIP(lookupType), service, protocol, defaultPort, defaultPriority, defaultWeight);
        }
        ZS_LOG_WARNING(Trace, log("WinRT does not support non-UDP SRV lookups at this time") + ZS_PARAMIZE(service) + ZS_PARAMIZE(protocol))
#endif //WINRT

          return internal::DNSSRVQuery::create(delegate, name, service, protocol, defaultPort);
      }
      
      //-----------------------------------------------------------------------
      Log::Params DNS::log(const char *message)
      {
        return Log::Params(message, "DNS");
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IDNSFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IDNSFactory &IDNSFactory::singleton()
      {
        return DNSFactory::singleton();
      }

      //-----------------------------------------------------------------------
      IDNSQueryPtr IDNSFactory::lookupA(
                                        IDNSDelegatePtr delegate,
                                        const char *name
                                        )
      {
        if (this) {}
        return DNS::lookupA(delegate, name);
      }

      //-----------------------------------------------------------------------
      IDNSQueryPtr IDNSFactory::lookupAAAA(
                                           IDNSDelegatePtr delegate,
                                           const char *name
                                           )
      {
        if (this) {}
        return DNS::lookupAAAA(delegate, name);
      }

      //-----------------------------------------------------------------------
      IDNSQueryPtr IDNSFactory::lookupAorAAAA(
                                              IDNSDelegatePtr delegate,
                                              const char *name
                                              )
      {
        if (this) {}
        return DNS::lookupAorAAAA(delegate, name);
      }

      //-----------------------------------------------------------------------
      IDNSQueryPtr IDNSFactory::lookupSRV(
                                          IDNSDelegatePtr delegate,
                                          const char *name,
                                          const char *service,
                                          const char *protocol,
                                          WORD defaultPort,
                                          WORD defaultPriority,
                                          WORD defaultWeight,
                                          SRVLookupTypes lookupType
                                          )
      {
        if (this) {}
        return DNS::lookupSRV(delegate, name, service, protocol, defaultPort, defaultPriority, defaultWeight, lookupType);
      }

    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IDNS::AResult
    #pragma mark

    //-------------------------------------------------------------------------
    void IDNS::AResult::trace(const char *message)
    {
      EventWriteOpServicesDnsResultListBegin(__func__, message, mName, mTTL, mIPAddresses.size());
      for (auto iter = mIPAddresses.begin(); iter != mIPAddresses.end(); ++iter) {
        EventWriteOpServicesDnsResultListEntry(__func__, message, mName, mTTL, (*iter).string());
      }
      EventWriteOpServicesDnsResultListEnd(__func__, message, mName);
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IDNS::SRVResult
    #pragma mark

    //-------------------------------------------------------------------------
    void IDNS::SRVResult::trace(const char *message)
    {
      EventWriteOpServicesDnsSrvResultListBegin(__func__, message, mName, mService, mProtocol, mTTL, mRecords.size());
      for (auto iter = mRecords.begin(); iter != mRecords.end(); ++iter) {
        auto &record = (*iter);
        EventWriteOpServicesDnsSrvResultListEntryBegin(__func__, message, record.mName, record.mPriority, record.mWeight, record.mPort, ((bool)record.mAResult) ? record.mAResult->mIPAddresses.size() : 0, ((bool)record.mAAAAResult) ? record.mAAAAResult->mIPAddresses.size() : 0);
        if (record.mAResult) {
          record.mAResult->trace(message);
        }
        if (record.mAAAAResult) {
          record.mAAAAResult->trace(message);
        }
        EventWriteOpServicesDnsSrvResultListEnd(__func__, message, record.mName);
      }
      EventWriteOpServicesDnsSrvResultListEnd(__func__, message, mName);
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IDNS
    #pragma mark

    //-------------------------------------------------------------------------
    IDNSQueryPtr IDNS::lookupA(
                               IDNSDelegatePtr delegate,
                               const char *name
                               )
    {
      auto result = internal::IDNSFactory::singleton().lookupA(delegate, name);
      EventWriteOpServicesDnsLookup(__func__, ((bool)result) ? result->getID() : 0, "A", name);
      return result;
    }

    //-------------------------------------------------------------------------
    IDNSQueryPtr IDNS::lookupAAAA(
                                  IDNSDelegatePtr delegate,
                                  const char *name
                                  )
    {
      auto result = internal::IDNSFactory::singleton().lookupAAAA(delegate, name);
      EventWriteOpServicesDnsLookup(__func__, ((bool)result) ? result->getID() : 0, "AAAA", name);
      return result;
    }

    //-------------------------------------------------------------------------
    IDNSQueryPtr IDNS::lookupAorAAAA(
                                     IDNSDelegatePtr delegate,
                                     const char *name
                                     )
    {
      auto result = internal::IDNSFactory::singleton().lookupAorAAAA(delegate, name);
      EventWriteOpServicesDnsLookup(__func__, ((bool)result) ? result->getID() : 0, "A or AAAA", name);
      return result;
    }

    //-------------------------------------------------------------------------
    IDNSQueryPtr IDNS::lookupSRV(
                                 IDNSDelegatePtr delegate,
                                 const char *name,
                                 const char *service,
                                 const char *protocol,
                                 WORD defaultPort,
                                 WORD defaultPriority,
                                 WORD defaultWeight,
                                 SRVLookupTypes lookupType
                                 )
    {
      auto result = internal::IDNSFactory::singleton().lookupSRV(delegate, name, service, protocol, defaultPort, defaultPriority, defaultWeight, lookupType);
      EventWriteOpServicesDnsSrvLookup(__func__, ((bool)result) ? result->getID() : 0, name, service, protocol, defaultPort, defaultPriority, defaultWeight, zsLib::to_underlying(lookupType));
      return result;
    }
    
    //-------------------------------------------------------------------------
    IDNS::AResultPtr IDNS::convertIPAddressesToAResult(
                                                       const std::list<IPAddress> &ipAddresses,
                                                       UINT ttl
                                                       )
    {
      AResultPtr result(make_shared<AResult>());

      result->mTTL = ttl;
      internal::copyToAddressList(ipAddresses, result->mIPAddresses, true, false);
      if (result->mIPAddresses.size() < 1) return IDNS::AResultPtr();

      result->mName = result->mIPAddresses.front().string(false);
      return result;
    }

    //-------------------------------------------------------------------------
    IDNS::AAAAResultPtr IDNS::convertIPAddressesToAAAAResult(
                                                             const std::list<IPAddress> &ipAddresses,
                                                             UINT ttl
                                                             )
    {
      AAAAResultPtr result(make_shared<AAAAResult>());

      result->mTTL = ttl;
      internal::copyToAddressList(ipAddresses, result->mIPAddresses, false, true);
      if (result->mIPAddresses.size() < 1) return IDNS::AAAAResultPtr();

      result->mName = result->mIPAddresses.front().string(false);
      return result;
    }

    //-------------------------------------------------------------------------
    IDNS::SRVResultPtr IDNS::convertAorAAAAResultToSRVResult(
                                                             const char *service,
                                                             const char *protocol,
                                                             AResultPtr resultA,
                                                             AAAAResultPtr resultAAAA,
                                                             WORD defaultPort,
                                                             WORD defaultPriority,
                                                             WORD defaultWeight
                                                             )
    {
      ZS_THROW_INVALID_USAGE_IF((!resultA) && (!resultAAAA))

      IDNS::AResultPtr useResult = (resultA ? resultA : resultAAAA);

      SRVResultPtr result(make_shared<SRVResult>());
      result->mName = useResult->mName;
      result->mService = service;
      result->mProtocol = protocol;
      result->mTTL = useResult->mTTL;

      // just in case the result AAAA's TTL is lower then the resultA's TTL set the SRV result's TTL to the lower of the two values
      if (resultAAAA) {
        if (resultAAAA->mTTL < result->mTTL)
          result->mTTL = resultAAAA->mTTL;
      }

      if (resultA) {
        SRVResult::SRVRecord record;

        AResultPtr aResult(make_shared<AResult>());
        aResult->mName = resultA->mName;
        aResult->mTTL = resultA->mTTL;
        internal::copyToAddressList(resultA->mIPAddresses, aResult->mIPAddresses);
        internal::fixDefaultPort(aResult, defaultPort);

        record.mName = resultA->mName;
        record.mPriority = defaultPriority;
        record.mWeight = defaultWeight;
        if (aResult->mIPAddresses.size() > 0)
          record.mPort = aResult->mIPAddresses.front().getPort();
        else
          record.mPort = 0;
        record.mAResult = aResult;
        result->mRecords.push_back(record);
      }
      if (resultAAAA) {
        SRVResult::SRVRecord record;

        AAAAResultPtr aaaaResult(make_shared<AAAAResult>());
        aaaaResult->mName = resultAAAA->mName;
        aaaaResult->mTTL = resultAAAA->mTTL;
        internal::copyToAddressList(resultAAAA->mIPAddresses, aaaaResult->mIPAddresses);
        internal::fixDefaultPort(aaaaResult, defaultPort);

        record.mName = resultAAAA->mName;
        record.mPriority = defaultPriority;
        record.mWeight = defaultWeight;
        if (aaaaResult->mIPAddresses.size() > 0)
          record.mPort = aaaaResult->mIPAddresses.front().getPort();
        else
          record.mPort = 0;
        record.mAAAAResult = aaaaResult;
        result->mRecords.push_back(record);
      }
      return result;
    }

    //-------------------------------------------------------------------------
    IDNS::SRVResultPtr IDNS::convertIPAddressesToSRVResult(
                                                           const char *service,
                                                           const char *protocol,
                                                           const std::list<IPAddress> &ipAddresses,
                                                           WORD defaultPort,
                                                           WORD defaultPriority,
                                                           WORD defaultWeight,
                                                           UINT ttl
                                                           )
    {
      ZS_THROW_INVALID_USAGE_IF(ipAddresses.size() < 1)

      AResultPtr aResult = IDNS::convertIPAddressesToAResult(ipAddresses, ttl);
      AAAAResultPtr aaaaResult = IDNS::convertIPAddressesToAAAAResult(ipAddresses, ttl);

      ZS_THROW_BAD_STATE_IF((!aResult) && (!aaaaResult))  // how can this happen??

      return IDNS::convertAorAAAAResultToSRVResult(
                                                   service,
                                                   protocol,
                                                   aResult,
                                                   aaaaResult,
                                                   defaultPort,
                                                   defaultPriority,
                                                   defaultWeight
                                                   );
    }

    //-------------------------------------------------------------------------
    IDNS::SRVResultPtr IDNS::mergeSRVs(const SRVResultList &srvList)
    {
      if (srvList.size() < 1) return SRVResultPtr();

      SRVResultPtr finalSRV;
      for (SRVResultList::const_iterator iter = srvList.begin(); iter != srvList.end(); ++iter)
      {
        const SRVResultPtr &result = (*iter);
        if (!finalSRV) {
          finalSRV = IDNS::cloneSRV(result);
        } else {
          internal::merge(finalSRV, result);
        }
      }

      if (srvList.size() > 1) {
        internal::sortSRV(finalSRV);
      }

      return finalSRV;
    }

    //-------------------------------------------------------------------------
    bool IDNS::extractNextIP(
                             SRVResultPtr srvResult,
                             IPAddress &outIP,
                             AResultPtr *outAResult,
                             AAAAResultPtr *outAAAAResult
                             )
    {
      if (outAResult)
        *outAResult = AResultPtr();
      if (outAAAAResult)
        *outAAAAResult = AAAAResultPtr();

      outIP.clear();

      if (!srvResult) return false;

      while (true)
      {
        if (srvResult->mRecords.size() < 1) {
          ZS_LOG_DEBUG(Log::Params("DNS found no IPs to extract (i.e. end of list).", "IDNS"))
          return false;
        }

        SRVResult::SRVRecord &record = srvResult->mRecords.front();
        if ((!record.mAResult) && (!record.mAAAAResult)) {
          srvResult->mRecords.pop_front();
          continue; // try again
        }

        AResultPtr &useResult = (record.mAResult ? record.mAResult : record.mAAAAResult);
        if (useResult->mIPAddresses.size() < 1) {
          useResult.reset();
          continue;
        }

        outIP = useResult->mIPAddresses.front();
        useResult->mIPAddresses.pop_front();

        ZS_LOG_DEBUG(Log::Params("DNS extracted next IP", "IDNS") + ZS_PARAM("ip", outIP.string()))

        // give caller indication of which list it came from
        if (outAResult) {
          if (record.mAResult)
            *outAResult = record.mAResult;
        }
        if (outAAAAResult) {
          if (!record.mAResult)
            *outAAAAResult = record.mAAAAResult;
        }
        return true;
      }

      return false;
    }

    //-------------------------------------------------------------------------
    // PURPOSE: Clone routines for various return results.
    IDNS::AResultPtr IDNS::cloneA(AResultPtr result)
    {
      if (!result) return result;

      AResultPtr clone(make_shared<AResult>());
      clone->mName = result->mName;
      clone->mTTL = result->mTTL;
      internal::copyToAddressList(result->mIPAddresses, clone->mIPAddresses);
      return clone;
    }

    //-------------------------------------------------------------------------
    IDNS::AAAAResultPtr IDNS::cloneAAAA(AAAAResultPtr result)
    {
      return cloneA(result);
    }

    //-------------------------------------------------------------------------
    IDNS::SRVResultPtr IDNS::cloneSRV(SRVResultPtr srvResult)
    {
      if (!srvResult) return srvResult;

      SRVResultPtr clone(make_shared<SRVResult>());
      clone->mName = srvResult->mName;
      clone->mService = srvResult->mService;
      clone->mProtocol = srvResult->mProtocol;
      clone->mTTL = srvResult->mTTL;

      for (SRVResult::SRVRecordList::const_iterator iter = srvResult->mRecords.begin(); iter != srvResult->mRecords.end(); ++iter) {
        SRVResult::SRVRecord record;
        record.mName = (*iter).mName;
        record.mPriority = (*iter).mPriority;
        record.mWeight = (*iter).mWeight;
        record.mPort = (*iter).mPort;
        record.mAResult = cloneA((*iter).mAResult);
        record.mAAAAResult = cloneAAAA((*iter).mAAAAResult);
        clone->mRecords.push_back(record);
      }

      return clone;
    }
  }
}
