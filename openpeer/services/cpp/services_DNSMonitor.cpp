
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

#include <openpeer/services/internal/services_DNSMonitor.h>
#include <openpeer/services/internal/services_Helper.h>
#include <openpeer/services/ICache.h>
#include <zsLib/Exception.h>
#include <zsLib/Socket.h>
#include <zsLib/helpers.h>
#include <zsLib/XML.h>
#include <zsLib/Numeric.h>

extern "C" {
#include <punycode/punycode.h>
}

namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services) } }

#define OPENPEER_SERVICES_DNSMONITOR_CACHE_NAMESPACE "https://meta.openpeer.org/caching/dns/"
#define OPENPEER_SERVICES_DNS_MONITOR_UNICODE_CHAR_TO_PUNY_CODE_CHARACTOR_RATIO (6)

namespace openpeer
{
  namespace services
  {
    namespace internal
    {
      using zsLib::Numeric;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark (helpers)
      #pragma mark

      //-----------------------------------------------------------------------
      static String convertPunyToUTF8(const char *punyStr)
      {
        if (!punyStr) return String();

        size_t length = strlen(punyStr);

        uint32_t unicodeBuffer[256] {};
        uint32_t *overflowBuffer = NULL;

        uint32_t *destStr = &(unicodeBuffer[0]);
        size_t destLength = (sizeof(unicodeBuffer) / sizeof(uint32_t)) - 1;

        if (length >= destLength) {
          overflowBuffer = new uint32_t[length+1] {};
          destStr = overflowBuffer;
          destLength = length;
        }


        size_t convertedLength = punycode_decode(punyStr, strlen(punyStr), destStr, &destLength);
        ZS_THROW_INVALID_ASSUMPTION_IF(destLength > convertedLength)

        std::wstring unicodeStr((wchar_t *)destStr);
        static_assert(sizeof(wchar_t) == sizeof(uint32_t), "assumption about wchar_t and uint32_t are not valid");

        if (overflowBuffer) {
          delete [] overflowBuffer;
          overflowBuffer = NULL;
        }

        return String(unicodeStr);
      }

      //-----------------------------------------------------------------------
      static String convertUTF8ToPuny(const char *utf8Str)
      {
        if (!utf8Str) return String();

        std::wstring unicodeStr = String(utf8Str).wstring();

        size_t length = unicodeStr.length();

        char outputBuffer[1024] {};
        char *overflowBuffer = NULL;

        char *destStr = &(outputBuffer[0]);
        size_t destLength = (sizeof(outputBuffer) / sizeof(char)) - 1;

        if (length * OPENPEER_SERVICES_DNS_MONITOR_UNICODE_CHAR_TO_PUNY_CODE_CHARACTOR_RATIO > destLength) {
          overflowBuffer = new char[(length*OPENPEER_SERVICES_DNS_MONITOR_UNICODE_CHAR_TO_PUNY_CODE_CHARACTOR_RATIO)+1] {};
          destStr = overflowBuffer;
          destLength = (length*OPENPEER_SERVICES_DNS_MONITOR_UNICODE_CHAR_TO_PUNY_CODE_CHARACTOR_RATIO);
        }

        size_t convertedLength = punycode_encode((uint32_t *) (unicodeStr.data()), length, destStr, &destLength);
        ZS_THROW_INVALID_ASSUMPTION_IF(destLength > convertedLength)

        String result(destStr);

        if (overflowBuffer) {
          delete [] overflowBuffer;
          overflowBuffer = NULL;
        }

        return result;
      }

      //-----------------------------------------------------------------------
      static Log::Params slog(const char *message)
      {
        DNSMonitorPtr singleton = DNSMonitor::singleton();
        if (!singleton) {
          return DNSMonitor::slog(message);
        }
        return singleton->log(message);
      }

      //-----------------------------------------------------------------------
      static String getGenericCookieName(const String &name, int flags, const char *type)
      {
        String hash = IHelper::convertToHex(*IHelper::hash(name + ":" + string(flags)));
        return String(OPENPEER_SERVICES_DNSMONITOR_CACHE_NAMESPACE) + type + "/" + hash;
      }

      //-----------------------------------------------------------------------
      static String getCookieName(
                                  const String &name,
                                  IDNS::SRVLookupTypes lookupType,
                                  int flags
                                  )
      {
        return getGenericCookieName(name, flags, IDNS::SRVLookupType_AutoLookupA == lookupType ? "a" : "aaaa");
      }

      //-----------------------------------------------------------------------
      static String getAAAACookieName(const String &name, int flags)
      {
        return getGenericCookieName(name, flags, "aaaa");
      }

      //-----------------------------------------------------------------------
      static String getSRVCookieName(
                                     const String &name,
                                     const String &service,
                                     const String &protocol,
                                     int flags
                                     )
      {
        return getGenericCookieName(name + ":" + service + ":" + protocol, flags, "srv");
      }

      //-----------------------------------------------------------------------
      static ElementPtr toElement(
                                  const IDNS::AResult &result,
                                  const char *elementName
                                  )
      {
        ElementPtr typeEl = Element::create(elementName);
        ElementPtr ipsEl = Element::create("ips");

        for (IDNS::AResult::IPAddressList::const_iterator iter = result.mIPAddresses.begin(); iter != result.mIPAddresses.end(); ++iter)
        {
          const IPAddress &address = (*iter);
          IHelper::debugAppend(ipsEl, "ip", address.string());

          ZS_LOG_TRACE(slog("adding ip") + ZS_PARAM("ip", string(address)))
        }

        IHelper::debugAppend(typeEl, "name", result.mName);
        IHelper::debugAppend(typeEl, "ttl", result.mTTL);
        IHelper::debugAppend(typeEl, ipsEl);

        ZS_LOG_TRACE(slog("adding A / AAAA") + ZS_PARAM("name", result.mName) + ZS_PARAM("ttl", result.mTTL) + ZS_PARAM("ips", result.mIPAddresses.size()))
        return typeEl;
      }

      //-----------------------------------------------------------------------
      static void store(
                        const String &name,
                        IDNS::SRVLookupTypes lookupType,
                        const IDNS::AResult &info,
                        int flags,
                        const Time &expires
                        )
      {
        const char *elementName = IDNS::SRVLookupType_AutoLookupA == lookupType ? "a" : "aaaa";
        String cookieName = getCookieName(name, lookupType, flags);

        ElementPtr typeEl = toElement(info, elementName);
        IHelper::debugAppend(typeEl, "expires", expires);

        String cacheData = IHelper::toString(typeEl);

        ZS_LOG_TRACE(slog("storing A / AAAA result") + ZS_PARAM("type", elementName) + ZS_PARAM("cookie", cookieName) + ZS_PARAM("name", info.mName) + ZS_PARAM("ttl", info.mTTL) + ZS_PARAM("flags", flags) + ZS_PARAM("ips", info.mIPAddresses.size()) + ZS_PARAM("expires", expires))
        ICache::store(cookieName, expires, cacheData);
      }

      //-----------------------------------------------------------------------
      static void store(
                        const String &name,
                        const IDNS::SRVResult &info,
                        int flags,
                        const Time &expires
                        )
      {
        String cookieName = getSRVCookieName(info.mName, info.mService, info.mProtocol, flags);

        ElementPtr srvEl = Element::create("srv");

        ElementPtr recordsEl = Element::create("records");

        for (IDNS::SRVResult::SRVRecordList::const_iterator recordsIter = info.mRecords.begin(); recordsIter != info.mRecords.end(); ++recordsIter)
        {
          const IDNS::SRVResult::SRVRecord &record = (*recordsIter);

          ElementPtr recordEl = Element::create("record");
          IHelper::debugAppend(recordEl, "name", record.mName);
          IHelper::debugAppend(recordEl, "priority", record.mPriority);
          IHelper::debugAppend(recordEl, "weight", record.mWeight);
          IHelper::debugAppend(recordEl, "port", record.mPort);

          if (record.mAResult) {
            ElementPtr typeEl = toElement(*record.mAResult, "a");
            IHelper::debugAppend(recordEl, typeEl);
          }
          if (record.mAAAAResult) {
            ElementPtr typeEl = toElement(*record.mAAAAResult, "aaaa");
            IHelper::debugAppend(recordEl, typeEl);
          }
          IHelper::debugAppend(recordsEl, recordEl);

          ZS_LOG_TRACE(slog("adding SRV record") + ZS_PARAM("name", record.mName) + ZS_PARAM("priority", record.mPriority) + ZS_PARAM("weight", record.mWeight) + ZS_PARAM("port", record.mPort) + ZS_PARAM("a", (bool)record.mAResult) + ZS_PARAM("aaaa", (bool)record.mAAAAResult))
        }

        IHelper::debugAppend(srvEl, "name", info.mName);
        IHelper::debugAppend(srvEl, "service", info.mService);
        IHelper::debugAppend(srvEl, "protocol", info.mProtocol);
        IHelper::debugAppend(srvEl, "ttl", info.mTTL);
        IHelper::debugAppend(srvEl, recordsEl);

        IHelper::debugAppend(srvEl, "expires", expires);

        String cacheData = IHelper::toString(srvEl);

        ZS_LOG_TRACE(slog("storing SRV result") + ZS_PARAM("cookie", cookieName) + ZS_PARAM("name", info.mName) + ZS_PARAM("service", info.mService) + ZS_PARAM("protocol", info.mProtocol) + ZS_PARAM("ttl", info.mTTL) + ZS_PARAM("flags", flags) + ZS_PARAM("records", info.mRecords.size()) + ZS_PARAM("expires", expires))
        ICache::store(cookieName, expires, cacheData);
      }

      //-----------------------------------------------------------------------
      static String getText(
                            ElementPtr parentEl,
                            const char *name
                            )
      {
        ElementPtr childEl = parentEl->findFirstChildElement(name);
        if (!childEl) return String();

        String childData = childEl->getTextDecoded();
        return childData;
      }

      //-----------------------------------------------------------------------
      template <typename RESULTTYPE>
      static RESULTTYPE convertNoThrow(
                                       ElementPtr parentEl,
                                       const char *name
                                       )
      {
        RESULTTYPE value = 0;

        try {
          String childData = getText(parentEl, name);
          if (childData.isEmpty()) return value;

          value = Numeric<RESULTTYPE>(childData);
        } catch(typename Numeric<RESULTTYPE>::ValueOutOfRange &) {
        }
        return value;
      }

      //-----------------------------------------------------------------------
      static void fill(
                       IDNS::AResult &result,
                       ElementPtr typeEl
                       )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!typeEl)

        result.mName = getText(typeEl, "name");
        result.mTTL = convertNoThrow<UINT>(typeEl, "ttl");

        ElementPtr ipsEl = typeEl->findFirstChildElement("ips");
        if (ipsEl) {
          ElementPtr ipEl = ipsEl->findFirstChildElement("ip");
          while (ipEl) {

            String value = ipEl->getTextDecoded();
            if (value.hasData()) {
              IPAddress ip(value);

              if (!ip.isEmpty()) {
                result.mIPAddresses.push_back(ip);
                ZS_LOG_TRACE(slog("found IP") + ZS_PARAM("ip", value))
              }
            }

            ipEl = ipEl->findNextSiblingElement("ip");
          }
        }

        ZS_LOG_TRACE(slog("found A / AAAA") + ZS_PARAM("name", result.mName) + ZS_PARAM("ttl", result.mTTL) + ZS_PARAM("ips", result.mIPAddresses.size()))
      }

      //-----------------------------------------------------------------------
      static IDNS::AResultPtr fetch(
                                    const String &name,
                                    IDNS::SRVLookupTypes lookupType,
                                    int flags,
                                    Time &outExpires
                                    )
      {
        const char *elementName = IDNS::SRVLookupType_AutoLookupA == lookupType ? "a" : "aaaa";
        String cookieName = getCookieName(name, lookupType, flags);

        String dataStr = ICache::fetch(cookieName);
        if (dataStr.isEmpty()) {
          ZS_LOG_TRACE(slog("no cache entry exists for A / AAAA result") + ZS_PARAM("type", elementName) + ZS_PARAM("cookie", cookieName) + ZS_PARAM("name", name) + ZS_PARAM("flags", flags))
          return IDNS::AResultPtr();
        }

        ElementPtr typeEl = IHelper::toJSON(dataStr);
        if (!typeEl) {
          ZS_LOG_WARNING(Detail, slog("failed to parse cached A / AAAA DNS entry") + ZS_PARAM("type", elementName) + ZS_PARAM("cookie", cookieName) + ZS_PARAM("name", name) + ZS_PARAM("flags", flags) + ZS_PARAM("json", dataStr))
          return IDNS::AResultPtr();
        }

        IDNS::AResultPtr result = IDNS::AResultPtr(new IDNS::AResult);

        fill(*result, typeEl);

        String expiresStr = getText(typeEl, "expires");
        if (expiresStr.hasData()) {
          outExpires = IHelper::stringToTime(expiresStr);
        }

        ZS_LOG_TRACE(slog("fetched A / AAAA result") + ZS_PARAM("type", elementName) + ZS_PARAM("cookie", cookieName) + ZS_PARAM("name", result->mName) + ZS_PARAM("ttl", result->mTTL) + ZS_PARAM("flags", flags) + ZS_PARAM("ips", result->mIPAddresses.size()) + ZS_PARAM("expires", outExpires))
        return result;
      }

      //-----------------------------------------------------------------------
      static IDNS::SRVResultPtr fetch(
                                      const String &name,
                                      const String &service,
                                      const String &protocol,
                                      int flags,
                                      Time &outExpires
                                      )
      {
        String cookieName = getSRVCookieName(name, service, protocol, flags);
        String dataStr = ICache::fetch(cookieName);
        if (dataStr.isEmpty()) {
          ZS_LOG_TRACE(slog("no cache entry exists for SRV result") + ZS_PARAM("cookie", cookieName) + ZS_PARAM("name", name) + ZS_PARAM("service", service) + ZS_PARAM("protocol", protocol) + ZS_PARAM("flags", flags))
          return IDNS::SRVResultPtr();
        }

        ElementPtr rootEl = IHelper::toJSON(dataStr);
        if (!rootEl) {
          ZS_LOG_WARNING(Detail, slog("failed to parse cached SRV DNS entry") + ZS_PARAM("cookie", cookieName) + ZS_PARAM("name", name) + ZS_PARAM("service", service) + ZS_PARAM("protocol", protocol) + ZS_PARAM("flags", flags))
          return IDNS::SRVResultPtr();
        }

        IDNS::SRVResultPtr result = IDNS::SRVResultPtr(new IDNS::SRVResult);

        ElementPtr recordsEl = rootEl->findFirstChildElement("records");
        if (recordsEl) {
          ElementPtr recordEl = recordsEl->findFirstChildElement("record");
          while (recordEl) {
            IDNS::SRVResult::SRVRecord record;

            record.mName = getText(recordEl, "name");
            record.mPriority = convertNoThrow<decltype(record.mPriority)>(rootEl, "priority");
            record.mWeight = convertNoThrow<decltype(record.mWeight)>(rootEl, "weight");
            record.mPort = convertNoThrow<decltype(record.mPort)>(rootEl, "port");

            // scope: a
            {
              ElementPtr aEl = recordEl->findFirstChildElement("a");
              if (aEl) {
                IDNS::AResultPtr result = IDNS::AResultPtr(new IDNS::AResult);
                fill(*result, aEl);
                record.mAResult = result;
              }
            }
            // scope: aaaa
            {
              ElementPtr aaaaEl = recordEl->findFirstChildElement("aaaa");
              if (aaaaEl) {
                IDNS::AAAAResultPtr result = IDNS::AAAAResultPtr(new IDNS::AAAAResult);
                fill(*result, aaaaEl);
                record.mAAAAResult = result;
              }
            }

            ZS_LOG_TRACE(slog("found SRV record") + ZS_PARAM("name", record.mName) + ZS_PARAM("priority", record.mPriority) + ZS_PARAM("weight", record.mWeight) + ZS_PARAM("port", record.mPort) + ZS_PARAM("a", (bool)record.mAResult) + ZS_PARAM("aaaa", (bool)record.mAAAAResult))

            recordEl = recordEl->findNextSiblingElement("record");
          }
        }

        result->mName = getText(rootEl, "name");
        result->mService = getText(rootEl, "service");
        result->mProtocol = getText(rootEl, "protocol");
        result->mTTL = convertNoThrow<decltype(result->mTTL)>(rootEl, "ttl");

        String expiresStr = getText(rootEl, "expires");
        if (expiresStr.hasData()) {
          outExpires = IHelper::stringToTime(expiresStr);
        }

        ZS_LOG_TRACE(slog("fetched SRV result") + ZS_PARAM("cookie", cookieName) + ZS_PARAM("name", result->mName) + ZS_PARAM("service", result->mService) + ZS_PARAM("protocol", result->mProtocol) + ZS_PARAM("ttl", result->mTTL) + ZS_PARAM("flags", flags) + ZS_PARAM("records", result->mRecords.size()) + ZS_PARAM("expires", outExpires))
        return result;
      }

      //-----------------------------------------------------------------------
      static void clear(
                        const String &name,
                        IDNS::SRVLookupTypes lookupType,
                        int flags
                        )
      {
        String cookieName = getCookieName(name, lookupType, flags);
        ICache::clear(cookieName);
      }

      //-----------------------------------------------------------------------
      static void clear(
                        const String &name,
                        const String &service,
                        const String &protocol,
                        int flags
                        )
      {
        ICache::clear(getSRVCookieName(name, service, protocol, flags));
      }

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
        SharedRecursiveLock(SharedRecursiveLock::create()),
        mCtx(NULL)
      {
        IHelper::setSocketThreadPriority();
        IHelper::setTimerThreadPriority();
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
        static SingletonLazySharedPtr<DNSMonitor> singleton(DNSMonitor::create(Helper::getServiceQueue()));
        DNSMonitorPtr result = singleton.singleton();
        if (!result) {
          ZS_LOG_WARNING(Detail, DNSMonitor::slog("singleton gone"))
        }
        return result;
      }

      //-----------------------------------------------------------------------
      Log::Params DNSMonitor::slog(const char *message)
      {
        return Log::Params(message, "DNSMonitor");
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
        mSocket->setBlocking(false);
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
        AutoRecursiveLock lock(*this);

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
        AutoRecursiveLock lock(*this);

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
        AutoRecursiveLock lock(*this);
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

          ZS_LOG_TRACE(log("using memeory cache to resolve A / AAAA") + ZS_PARAM("type", aMode ? "A" : "AAAA") + ZS_PARAM("name", info->mName) + ZS_PARAM("flags", info->mFlags) + ZS_PARAM("expires", info->mExpires) + ZS_PARAM("result", (bool)info->mResult))

          useInfo = info;
          break;
        }

        if (!useInfo) {
          useInfo = ACacheInfoPtr(new ACacheInfo);
          useInfo->mName = name;
          useInfo->mFlags = flags;

          useInfo->mResult = fetch(useInfo->mName, aMode ? IDNS::SRVLookupType_AutoLookupA : IDNS::SRVLookupType_AutoLookupAAAA, flags, useInfo->mExpires);

          useList.push_back(useInfo);
        }

        if (Time() != useInfo->mExpires) {
          Time tick = zsLib::now();
          
          if (tick < useInfo->mExpires) {
            ZS_LOG_TRACE(log("notify A / AAAA resolution from cache"))

            // use cached result
            if (aMode) {
              result->onAResult(useInfo->mResult);
            } else {
              result->onAAAAResult(useInfo->mResult);
            }
            return;
          }

          ZS_LOG_TRACE(log("memory cache expired for A / AAAA") + ZS_PARAM("now", tick))
        }

        // did not find in cache or expired
        useInfo->mResult = IDNS::AResultPtr();
        clear(useInfo->mName, aMode ? IDNS::SRVLookupType_AutoLookupA : IDNS::SRVLookupType_AutoLookupAAAA, flags);

        useInfo->mPendingResults.push_back(result);

        if (useInfo->mPendingQuery) return;  // already have a query outstanding

        QueryID queryID = zsLib::createPUID();

        struct dns_query *query = NULL;
        if (aMode) {
          query = dns_submit_a4(mCtx, convertUTF8ToPuny(name), flags, DNSMonitor::dns_query_a4, (void *)((PTRNUMBER)queryID));
        } else {
          query = dns_submit_a6(mCtx, convertUTF8ToPuny(name), flags, DNSMonitor::dns_query_a6, (void *)((PTRNUMBER)queryID));
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
        AutoRecursiveLock lock(*this);
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

          ZS_LOG_TRACE(log("using memeory cache to resolve SRV") + ZS_PARAM("name", info->mName) + ZS_PARAM("service", info->mService) + ZS_PARAM("protocol", info->mProtocol) + ZS_PARAM("flags", info->mFlags) + ZS_PARAM("expires", info->mExpires) + ZS_PARAM("result", (bool)info->mResult))

          useInfo = info;
          break;
        }

        if (!useInfo) {
          useInfo = SRVCacheInfoPtr(new SRVCacheInfo);
          useInfo->mName = name;
          useInfo->mService = service;
          useInfo->mProtocol = protocol;
          useInfo->mFlags = flags;

          useInfo->mResult = fetch(useInfo->mName, useInfo->mService, useInfo->mProtocol, flags, useInfo->mExpires);

          mSRVCacheList.push_back(useInfo);
        }

        if (Time() != useInfo->mExpires) {
          Time tick = zsLib::now();

          if (tick < useInfo->mExpires) {
            // use cached result
            ZS_LOG_TRACE(log("notify SRV resolution from cache"))
            result->onSRVResult(useInfo->mResult);
            return;
          }

          ZS_LOG_TRACE(log("memory cache expired for SRV") + ZS_PARAM("now", tick))
        }

        // did not find in cache or expired
        useInfo->mResult = IDNS::SRVResultPtr();
        clear(useInfo->mName, useInfo->mService, useInfo->mProtocol, flags);

        useInfo->mPendingResults.push_back(result);

        if (useInfo->mPendingQuery) return;  // already have a query outstanding

        QueryID queryID = zsLib::createPUID();

        struct dns_query *query = dns_submit_srv(mCtx, convertUTF8ToPuny(name), convertUTF8ToPuny(service), convertUTF8ToPuny(protocol), flags, DNSMonitor::dns_query_srv, (void *)((PTRNUMBER)queryID));
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
      void DNSMonitor::onReadReady(SocketPtr socket)
      {
        AutoRecursiveLock lock(*this);
        if (!mCtx)
          return;

        if (socket != mSocket) return;

        dns_ioevent(mCtx, 0);
        dns_timeouts(mCtx, -1, 0);
        mSocket->onReadReadyReset();

        cleanIfNoneOutstanding();
      }

      //-----------------------------------------------------------------------
      void DNSMonitor::onWriteReady(SocketPtr socket)
      {
        // we can ignore the write ready, it only writes during a timeout event or during creation
      }

      //-----------------------------------------------------------------------
      void DNSMonitor::onException(SocketPtr socket)
      {
        AutoRecursiveLock lock(*this);
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
        AutoRecursiveLock lock(*this);
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

          store(mName, IDNS::SRVLookupType_AutoLookupA, *data, mFlags, mExpires);
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

          store(mName, IDNS::SRVLookupType_AutoLookupAAAA, *data, mFlags, mExpires);
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
            srvRecord.mName = convertPunyToUTF8(srv.name);

            data->mRecords.push_back(srvRecord);
          }

          mResult = data;
          mExpires = zsLib::now() + Seconds(record->dnssrv_ttl);

          store(mName, *data, mFlags, mExpires);
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
