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

#include <ortc/services/IHTTP.h>
#include <ortc/services/internal/services_HTTP.h>
#include <ortc/services/internal/services_HTTP_WinUWP.h>
#include <ortc/services/internal/services.events.h>

#ifndef WINUWP

#include <ortc/services/internal/services_Helper.h>

#include <zsLib/ISettings.h>
#include <zsLib/helpers.h>
#include <zsLib/Stringize.h>
#include <zsLib/Log.h>
#include <zsLib/Event.h>
#include <zsLib/XML.h>
#include <zsLib/IMessageQueueThread.h>

#include <thread>

//-----------------------------------------------------------------------------
// NOTE: Uncomment only ONE of these options to force the TLS version

//#define ORTC_SERVICES_HTTP_TLS_FORCE_TLS_VERSION_TLS_1
//#define ORTC_SERVICES_HTTP_TLS_FORCE_TLS_VERSION_SSL_2
//#define ORTC_SERVICES_HTTP_TLS_FORCE_TLS_VERSION_SSL_3


//-----------------------------------------------------------------------------
//WARNING: UNCOMMENTING THIS MAY CAUSE YOUR SSL TO BECOME COMPROMISED

//#define ORTC_SERVICES_HTTP_ALLOW_BEAST

namespace ortc { namespace services { ZS_DECLARE_SUBSYSTEM(ortc_services_http) } }

namespace ortc
{
  namespace services
  {
#ifndef _WIN32
    using zsLib::INVALID_SOCKET;
#endif //ndef _WIN32

    namespace internal
    {
#ifndef _WIN32
      typedef timeval TIMEVAL;
#endif //_WIN32

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark HTTP
      #pragma mark

      //-----------------------------------------------------------------------
      void IHTTPForSettings::applyDefaults()
      {
        ISettings::setUInt(ORTC_SERVICES_DEFAULT_HTTP_TIMEOUT_SECONDS, 60 * 2);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark HTTPGlobalSafeReference
      #pragma mark

      class HTTPGlobalSafeReference
      {
      public:
        HTTPGlobalSafeReference(HTTPPtr reference) :
          mSafeReference(reference)
        {
        }

        ~HTTPGlobalSafeReference()
        {
          mSafeReference->cancel();
          mSafeReference.reset();
        }

        HTTPPtr mSafeReference;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark HTTP
      #pragma mark

      //-----------------------------------------------------------------------
      HTTP::HTTP(const make_private &) :
        SharedRecursiveLock(SharedRecursiveLock::create()),
        mShouldShutdown(false),
        mMultiCurl(NULL)
      {
        ZS_LOG_DETAIL(log("created"));
      }

      //-----------------------------------------------------------------------
      void HTTP::init()
      {
      }

      //-----------------------------------------------------------------------
      HTTP::~HTTP()
      {
        if (isNoop()) return;

        mThisWeak.reset();
        ZS_LOG_DETAIL(log("destroyed"));
        cancel();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark HTTP => IHTTP
      #pragma mark

      //-----------------------------------------------------------------------
      HTTP::HTTPQueryPtr HTTP::get(
                                   IHTTPQueryDelegatePtr delegate,
                                   const char *userAgent,
                                   const char *url,
                                   Milliseconds timeout
                                   )
      {
        HTTPPtr pThis = singleton();
        HTTPQueryPtr query = HTTPQuery::create(pThis, delegate, false, userAgent, url, NULL, 0, NULL, timeout);
        if (!pThis) {
          query->notifyComplete(CURLE_FAILED_INIT); // singleton gone so cannot perform CURL operation at this time
          return query;
        } else {
          pThis->monitorBegin(query);
        }
        return query;
      }

      //-----------------------------------------------------------------------
      HTTP::HTTPQueryPtr HTTP::post(
                                    IHTTPQueryDelegatePtr delegate,
                                    const char *userAgent,
                                    const char *url,
                                    const BYTE *postData,
                                    size_t postDataLengthInBytes,
                                    const char *postDataMimeType,
                                    Milliseconds timeout
                                    )
      {
        HTTPPtr pThis = singleton();
        HTTPQueryPtr query = HTTPQuery::create(pThis, delegate, true, userAgent, url, postData, postDataLengthInBytes, postDataMimeType, timeout);
        if (!pThis) {
          query->notifyComplete(CURLE_FAILED_INIT); // singleton gone so cannot perform CURL operation at this time
          return query;
        } else {
          pThis->monitorBegin(query);
        }
        return query;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark HTTP => friend HTTPQuery
      #pragma mark

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark HTTP => (internal)
      #pragma mark

      //-----------------------------------------------------------------------
      HTTPPtr HTTP::singleton()
      {
        AutoRecursiveLock lock(*IHelper::getGlobalLock());
        static SingletonLazySharedPtr<HTTP> singleton(HTTP::create());
        HTTPPtr result = singleton.singleton();
        if (!result) {
          ZS_LOG_WARNING(Detail, slog("singleton gone"))
        }
        return result;
      }

      //-----------------------------------------------------------------------
      HTTPPtr HTTP::create()
      {
        HTTPPtr pThis(make_shared<HTTP>(make_private{}));
        pThis->mThisWeak = pThis;
        pThis->init();
        return pThis;
      }

      //-----------------------------------------------------------------------
      Log::Params HTTP::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("HTTP");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params HTTP::slog(const char *message)
      {
        return Log::Params(message, "HTTP");
      }

      //-----------------------------------------------------------------------
      void HTTP::cancel()
      {
        ThreadPtr thread;
        {
          AutoRecursiveLock lock(*this);
          mGracefulShutdownReference = mThisWeak.lock();
          thread = mThread;

          mShouldShutdown = true;
          wakeUp();
        }

        if (!thread)
          return;

        thread->join();

        {
          AutoRecursiveLock lock(*this);
          mThread.reset();
        }
      }

      //-----------------------------------------------------------------------
      void HTTP::wakeUp()
      {
        int errorCode = 0;

        {
          AutoRecursiveLock lock(*this);

          if (!mWakeUpSocket)               // is the wakeup socket created?
            return;

          if (!mWakeUpSocket->isValid())
          {
            ZS_LOG_ERROR(Basic, log("Could not wake up socket monitor as wakeup socket was closed. This will cause a delay in the socket monitor response time."))
            return;
          }

          static DWORD gBogus = 0;
          static BYTE *bogus = (BYTE *)&gBogus;

          bool wouldBlock = false;
          mWakeUpSocket->send(bogus, sizeof(gBogus), &wouldBlock, 0, &errorCode);       // send a bogus packet to its own port to wake it up
        }

        if (0 != errorCode) {
          ZS_LOG_ERROR(Basic, log("Could not wake up socket monitor. This will cause a delay in the socket monitor response time") + ZS_PARAM("error", errorCode))
        }
      }

      //-----------------------------------------------------------------------
      void HTTP::createWakeUpSocket()
      {
        AutoRecursiveLock lock(*this);

        int tries = 0;
        bool useIPv6 = true;
        while (true)
        {
          // bind only on the loopback address
          bool error = false;
          try {
            if (useIPv6)
            {
              mWakeUpAddress = IPAddress::loopbackV6();
              mWakeUpSocket = Socket::createUDP(Socket::Create::IPv6);
            }
            else
            {
              mWakeUpAddress = IPAddress::loopbackV4();
              mWakeUpSocket = Socket::createUDP(Socket::Create::IPv4);
            }

            if (((tries > 5) && (tries < 10)) ||
                (tries > 15)) {
              mWakeUpAddress.setPort(5000+(rand()%(65525-5000)));
            } else {
              mWakeUpAddress.setPort(0);
            }

            mWakeUpSocket->setOptionFlag(Socket::SetOptionFlag::NonBlocking, true);
            mWakeUpSocket->bind(mWakeUpAddress);
            mWakeUpAddress = mWakeUpSocket->getLocalAddress();
            mWakeUpSocket->connect(mWakeUpAddress);
          } catch (Socket::Exceptions::Unspecified &) {
            error = true;
          }
          if (!error)
          {
            break;
          }

          std::this_thread::yield();       // do not hammer CPU

          if (tries > 10)
            useIPv6 = (tries%2 == 0);   // after 10 tries, start trying to bind using IPv4

          ZS_THROW_BAD_STATE_MSG_IF(tries > 500, log("unable to allocate any loopback ports for a wake-up socket"))
        }
      }

      //-----------------------------------------------------------------------
      void HTTP::processWaiting()
      {
        for (EventList::iterator iter = mWaitingForRebuildList.begin(); iter != mWaitingForRebuildList.end(); ++iter)
        {
          ZS_LOG_TRACE(log("monitor notify"))
          (*iter)->notify();
        }
        mWaitingForRebuildList.clear();

        for (HTTPQueryMap::iterator iter = mPendingRemoveQueries.begin(); iter != mPendingRemoveQueries.end(); ++iter)
        {
          HTTPQueryPtr &query = (*iter).second;

          HTTPQueryMap::iterator found = mPendingAddQueries.find(query->getID());
          if (found != mPendingAddQueries.end()) {
            ZS_LOG_TRACE(log("removing query") + ZS_PARAM("query", query->getID()))
            mPendingAddQueries.erase(found);
          }

          found = mQueries.find(query->getID());
          if (found != mQueries.end()) {
            CURL *curl = query->getCURL();
            if (NULL != curl) {
              ZS_LOG_TRACE(log("removing multi query handle") + ZS_PARAM("query", query->getID()))
              curl_multi_remove_handle(mMultiCurl, curl);
            }
            query->cleanupCurl();

            if (NULL != curl) {
              HTTPCurlMap::iterator foundCurl = mCurlMap.find(curl);
              if (foundCurl != mCurlMap.end()) {
                ZS_LOG_TRACE(log("removing from curl handle map") + ZS_PARAM("query", query->getID()))
                mCurlMap.erase(curl);
              }
            }
          }
        }

        mPendingRemoveQueries.clear();

        if (!mShouldShutdown) {
          for (HTTPQueryMap::iterator iter = mPendingAddQueries.begin(); iter != mPendingAddQueries.end(); ++iter)
          {
            HTTPQueryPtr &query = (*iter).second;

            ZS_LOG_TRACE(log("pending query preparing") + ZS_PARAM("query", query->getID()))

            query->prepareCurl();
            CURL *curl = query->getCURL();

            if (curl) {
              if (CURLM_OK != curl_multi_add_handle(mMultiCurl, curl)) {
                ZS_LOG_ERROR(Detail, log("failed to add query handle to multi curl") + ZS_PARAM("query", query->getID()))
                curl_multi_remove_handle(mMultiCurl, curl);
                query->cleanupCurl();
                curl = NULL;
              }
            }

            if (curl) {
              ZS_LOG_TRACE(log("pending query remembering curl mapping") + ZS_PARAM("query", query->getID()))
              mQueries[query->getID()] = query;
              mCurlMap[curl] = query;
            }
          }

          mPendingAddQueries.clear();

        } else {
          for (HTTPQueryMap::iterator iter = mPendingAddQueries.begin(); iter != mPendingAddQueries.end(); ++iter)
          {
            HTTPQueryPtr &query = (*iter).second;
            ZS_LOG_WARNING(Debug, log("pending query being shutdown (because of shutdown)") + ZS_PARAM("query", query->getID()))
            query->cleanupCurl();
          }

          mPendingAddQueries.clear();

          for (HTTPQueryMap::iterator iter = mQueries.begin(); iter != mQueries.end(); ++iter)
          {
            HTTPQueryPtr &query = (*iter).second;
            CURL *curl = query->getCURL();
            if (curl) {
              ZS_LOG_WARNING(Debug, log("pending query being removed from multi curl (because of shutdown)") + ZS_PARAM("query", query->getID()))
              curl_multi_remove_handle(mMultiCurl, curl);
            }
            query->cleanupCurl();
          }

          mQueries.clear();
          mCurlMap.clear();
        }
      }

      //-----------------------------------------------------------------------
      void HTTP::monitorBegin(HTTPQueryPtr query)
      {
        EventPtr event;

        {
          AutoRecursiveLock lock(*this);

          if (mShouldShutdown) {
            query->cancel();
            return;
          }

          if (!mThread) {
            mThread = ThreadPtr(new std::thread(std::ref(*this)));
            zsLib::setThreadPriority(*mThread, zsLib::threadPriorityFromString(ISettings::getString(ORTC_SERVICES_SETTING_HELPER_HTTP_THREAD_PRIORITY)));
          }

          mPendingAddQueries[query->getID()] = query;

          event = Event::create();
          mWaitingForRebuildList.push_back(event);                                        // socket handles cane be reused so we must ensure that the socket handles are rebuilt before returning
          ZS_LOG_TRACE(log("waiting notify"))

          wakeUp();
        }

        if (event)
          event->wait();

        ZS_LOG_TRACE(log("monitor begin for query") + ZS_PARAM("query", query->getID()))
      }

      //-----------------------------------------------------------------------
      void HTTP::monitorEnd(HTTPQueryPtr query)
      {
        EventPtr event;
        {
          AutoRecursiveLock lock(*this);

          mPendingRemoveQueries[query->getID()] = query;

          event = Event::create();
          mWaitingForRebuildList.push_back(event);                                        // socket handles cane be reused so we must ensure that the socket handles are rebuilt before returning

          wakeUp();
        }
        if (event)
          event->wait();

        ZS_LOG_TRACE(log("monitor end for query") + ZS_PARAM("query", query->getID()))
      }

      //-----------------------------------------------------------------------
      void HTTP::operator()()
      {
        zsLib::debugSetCurrentThreadName("org.ortclib.services.http");

        ZS_LOG_BASIC(log("http thread started"))

        mMultiCurl = curl_multi_init();

        createWakeUpSocket();

        bool shouldShutdown = false;

        TIMEVAL timeout;
        memset(&timeout, 0, sizeof(timeout));

        fd_set fdread;
        fd_set fdwrite;
        fd_set fdexcep;

        do
        {
          SOCKET highestSocket = INVALID_SOCKET;

          {
            AutoRecursiveLock lock(*this);
            processWaiting();

            FD_ZERO(&fdread);
            FD_ZERO(&fdwrite);
            FD_ZERO(&fdexcep);

            // monitor the wakeup socket...
            FD_SET(mWakeUpSocket->getSocket(), &fdread);
            FD_SET(mWakeUpSocket->getSocket(), &fdexcep);

            int maxfd = -1;
            CURLMcode result = curl_multi_fdset(mMultiCurl, &fdread, &fdwrite, &fdexcep, &maxfd);
            if (result != CURLM_OK) {
              ZS_LOG_ERROR(Basic, log("failed multi-select") + ZS_PARAM("result", result) + ZS_PARAM("error", curl_multi_strerror(result)))
              mShouldShutdown = true;
            }

            long curlTimeout = -1;
            curl_multi_timeout(mMultiCurl, &curlTimeout);

            if (curlTimeout >= 0) {
              timeout.tv_sec = curlTimeout / 1000;
              if (timeout.tv_sec > 1)
                timeout.tv_sec = 1;
              else
                timeout.tv_usec = (curlTimeout % 1000) * 1000;
            }

            int handleCount = 0;
            curl_multi_perform(mMultiCurl, &handleCount);

#ifndef _WIN32
            highestSocket = mWakeUpSocket->getSocket();

            if (-1 != maxfd) {
              if (((SOCKET)maxfd) > highestSocket) {
                highestSocket = (SOCKET)maxfd;
              }
            }
#endif //_WIN32
          }

          timeout.tv_sec = 1;
          timeout.tv_usec = 0;

          int result = select(INVALID_SOCKET == highestSocket ? 0 : (highestSocket+1), &fdread, &fdwrite, &fdexcep, &timeout);

          ZS_LOG_INSANE(log("curl multi select") + ZS_PARAM("result", result))

          // select completed, do notifications from select
          {
            AutoRecursiveLock lock(*this);
            shouldShutdown = mShouldShutdown;

            int handleCount = 0;
            curl_multi_perform(mMultiCurl, &handleCount);

            switch (result) {

              case INVALID_SOCKET:  break;
              case 0:
              default: {
                ULONG totalToProcess = result;

                bool redoWakeupSocket = false;
                if (FD_ISSET(mWakeUpSocket->getSocket(), &fdread)) {
                  ZS_LOG_TRACE(log("curl thread told to wake up"))
                  --totalToProcess;

                  bool wouldBlock = false;
                  static DWORD gBogus = 0;
                  static BYTE *bogus = (BYTE *)&gBogus;
                  int noThrowError = 0;
                  mWakeUpSocket->receive(bogus, sizeof(gBogus), &wouldBlock, 0, &noThrowError);
                  if (0 != noThrowError) redoWakeupSocket = true;
                }

                if (FD_ISSET(mWakeUpSocket->getSocket(), &fdexcep)) {
                  --totalToProcess;
                  redoWakeupSocket = true;
                }

                if (redoWakeupSocket) {
                  ZS_LOG_TRACE(log("redo wakeup socket"))

                  mWakeUpSocket->close();
                  mWakeUpSocket.reset();
                  createWakeUpSocket();
                }

                CURLMsg *msg = NULL;
                int handleCountIgnored = 0;

                while ((msg = curl_multi_info_read(mMultiCurl, &handleCountIgnored)))
                {
                  if (CURLMSG_DONE == msg->msg) {
                    HTTPCurlMap::iterator found = mCurlMap.find(msg->easy_handle);

                    curl_multi_remove_handle(mMultiCurl, msg->easy_handle);

                    if (found != mCurlMap.end()) {
                      HTTPQueryPtr &query = (*found).second;
                      ZS_LOG_TRACE(log("curl multi select done") + ZS_PARAM("query", query->getID()))

                      query->notifyComplete(msg->data.result);

                      HTTPQueryMap::iterator foundQuery = mQueries.find(query->getID());
                      if (foundQuery != mQueries.end()) {
                        mQueries.erase(foundQuery);
                      }

                      mCurlMap.erase(found);
                    }
                  }
                }
              }
            }
          }
        } while (!shouldShutdown);

        HTTPPtr gracefulReference;

        {
          AutoRecursiveLock lock(*this);
          processWaiting();
          mWaitingForRebuildList.clear();
          mWakeUpSocket.reset();

          // transfer the graceful shutdown reference to the outer thread
          gracefulReference = mGracefulShutdownReference;
          mGracefulShutdownReference.reset();

          if (mMultiCurl) {
            curl_multi_cleanup(mMultiCurl);
            mMultiCurl = NULL;
          }
        }

        ZS_LOG_BASIC(log("http thread stopped"))
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark HTTP::HTTPQuery
      #pragma mark

      //-----------------------------------------------------------------------
      HTTP::HTTPQuery::HTTPQuery(
                                 const make_private &,
                                 HTTPPtr outer,
                                 IHTTPQueryDelegatePtr delegate,
                                 bool isPost,
                                 const char *userAgent,
                                 const char *url,
                                 const BYTE *postData,
                                 size_t postDataLengthInBytes,
                                 const char *postDataMimeType,
                                 Milliseconds timeout
                                 ) :
        SharedRecursiveLock(outer ? *outer : SharedRecursiveLock::create()),
        mOuter(outer),
        mDelegate(IHTTPQueryDelegateProxy::create(Helper::getServiceQueue(), delegate)),
        mIsPost(isPost),
        mUserAgent(userAgent),
        mURL(url),
        mMimeType(postDataMimeType),
        mTimeout(timeout),
        mErrorBuffer(CURL_ERROR_SIZE)
      {
        ZS_LOG_DEBUG(log("created"))
        if (0 != postDataLengthInBytes) {
          mPostData.CleanNew(postDataLengthInBytes);
          memcpy(mPostData.BytePtr(), postData, postDataLengthInBytes);
        }

        if (Milliseconds() == mTimeout) {
          Seconds defaultTimeout(ISettings::getUInt(ORTC_SERVICES_DEFAULT_HTTP_TIMEOUT_SECONDS));
          if (Seconds() != defaultTimeout) {
            mTimeout = zsLib::toMilliseconds(defaultTimeout);
          }
        }

        ZS_EVENTING_8(
                      x, i, Debug, ServicesHttpQueryCreate, os, Http, Start,
                      puid, id, mID,
                      bool, isPost, mIsPost,
                      string, userAgent, mUserAgent,
                      string, url, mURL,
                      buffer, postData, postData,
                      size, postSize, postDataLengthInBytes,
                      string, postDataMimeType, postDataMimeType,
                      duration, timeout, timeout.count()
                      );
      }

      //-----------------------------------------------------------------------
      void HTTP::HTTPQuery::init()
      {
      }

      //-----------------------------------------------------------------------
      HTTP::HTTPQuery::~HTTPQuery()
      {
        mThisWeak.reset();
        ZS_LOG_DEBUG(log("destroyed"))
        cancel();

        ZS_EVENTING_1(x, i, Debug, ServicesHttpQueryDestroy, os, Http, Stop, puid, id, mID);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark HTTP::HTTPQuery => IHTTPQuery
      #pragma mark

      //-----------------------------------------------------------------------
      void HTTP::HTTPQuery::cancel()
      {
        ZS_EVENTING_1(x, i, Debug, ServicesHttpQueryCancel, os, Http, Cancel, puid, id, mID);

        HTTPPtr outer;
        HTTPQueryPtr pThis;

        {
          AutoRecursiveLock lock(*this);

          ZS_LOG_DEBUG(log("cancel called"))

          pThis = mThisWeak.lock();

          outer = mOuter.lock();
        }

        if ((outer) &&
            (pThis)) {
          // cannot be called from within a lock
          outer->monitorEnd(pThis);
          return;
        }

        {
          AutoRecursiveLock lock(*this);
          if ((pThis) &&
              (mDelegate)) {
            try {
              mDelegate->onHTTPCompleted(pThis);
            } catch (IHTTPQueryDelegateProxy::Exceptions::DelegateGone &) {
              ZS_LOG_WARNING(Detail, log("delegate gone"))
            }
          }

          mDelegate.reset();

          if (mCurl) {
            curl_easy_cleanup(mCurl);
            mCurl = NULL;
          }

          if (mHeaders) {
            curl_slist_free_all(mHeaders);
            mHeaders = NULL;
          }
        }
      }

      //-----------------------------------------------------------------------
      bool HTTP::HTTPQuery::isComplete() const
      {
        AutoRecursiveLock lock(*this);
        if (!mDelegate) return true;
        return false;
      }

      //-----------------------------------------------------------------------
      bool HTTP::HTTPQuery::wasSuccessful() const
      {
        AutoRecursiveLock lock(*this);
        if (mDelegate) return false;

        return ((CURLE_OK == mResultCode) &&
                ((mResponseCode >= 200) && (mResponseCode < 400)));
      }

      //-----------------------------------------------------------------------
      IHTTP::HTTPStatusCodes HTTP::HTTPQuery::getStatusCode() const
      {
        AutoRecursiveLock lock(*this);
        return IHTTP::toStatusCode((WORD)mResponseCode);
      }

      //-----------------------------------------------------------------------
      size_t HTTP::HTTPQuery::getHeaderReadSizeAvailableInBytes() const
      {
        AutoRecursiveLock lock(*this);
        return static_cast<size_t>(mHeader.MaxRetrievable());
      }

      //-----------------------------------------------------------------------
      size_t HTTP::HTTPQuery::readHeader(
                                         BYTE *outResultData,
                                         size_t bytesToRead
                                         )
      {
        AutoRecursiveLock lock(*this);
        auto result = mHeader.Get(outResultData, bytesToRead);
        ZS_EVENTING_5(
                      x, i, Debug, ServicesHttpQueryReadHeader, os, Http, Receive,
                      puid, id, mID,
                      size_t, bytesToRead, bytesToRead,
                      size_t, result, result,
                      buffer, resultData, outResultData,
                      size, bytesRead, result
                      );
        return result;
      }

      //-----------------------------------------------------------------------
      size_t HTTP::HTTPQuery::readHeaderAsString(String &outHeader)
      {
        outHeader.clear();

        AutoRecursiveLock lock(*this);
        CryptoPP::lword available = mHeader.MaxRetrievable();
        if (0 == available) return 0;

        SecureByteBlock data;
        data.CleanNew(static_cast<SecureByteBlock::size_type>(available));
        mHeader.Get(data.BytePtr(), static_cast<size_t>(available));

        outHeader = (const char *)data.BytePtr();
        auto result = strlen(outHeader);
        ZS_EVENTING_2(
                      x, i, Debug, ServicesHttpQueryReadHeaderAsString, os, Http, Receive,
                      puid, id, mID,
                      string, header, outHeader
                      );
        return result;
      }

      //-----------------------------------------------------------------------
      size_t HTTP::HTTPQuery::getReadDataAvailableInBytes() const
      {
        AutoRecursiveLock lock(*this);
        return static_cast<size_t>(mBody.MaxRetrievable());
      }

      //-----------------------------------------------------------------------
      size_t HTTP::HTTPQuery::readData(
                                       BYTE *outResultData,
                                       size_t bytesToRead
                                       )
      {
        AutoRecursiveLock lock(*this);
        auto result = mBody.Get(outResultData, bytesToRead);
        ZS_EVENTING_4(
                      x, i, Debug, ServicesHttpQueryRead, os, Http, Receive,
                      puid, id, mID,
                      size_t, bytesToRead, bytesToRead,
                      buffer, data, outResultData,
                      size, result, result
                      );
        return result;
      }

      //-----------------------------------------------------------------------
      size_t HTTP::HTTPQuery::readDataAsString(String &outResultData)
      {
        outResultData.clear();

        AutoRecursiveLock lock(*this);
        CryptoPP::lword available = mBody.MaxRetrievable();
        if (0 == available) return 0;

        SecureByteBlock data;
        data.CleanNew(static_cast<SecureByteBlock::size_type>(available));
        mBody.Get(data.BytePtr(), static_cast<size_t>(available));

        outResultData = (const char *)data.BytePtr();
        auto result = strlen(outResultData);
        ZS_EVENTING_2(
                      x, i, Debug, ServicesHttpQueryReadAsString, os, Http, Receive,
                      puid, id, mID,
                      string, result, outResultData
                      );
        return result;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark HTTP::HTTPQuery => friend HTTP
      #pragma mark

      //-----------------------------------------------------------------------
      HTTP::HTTPQueryPtr HTTP::HTTPQuery::create(
                                                 HTTPPtr outer,
                                                 IHTTPQueryDelegatePtr delegate,
                                                 bool isPost,
                                                 const char *userAgent,
                                                 const char *url,
                                                 const BYTE *postData,
                                                 size_t postDataLengthInBytes,
                                                 const char *postDataMimeType,
                                                 Milliseconds timeout
                                                 )
      {
        HTTPQueryPtr pThis(make_shared<HTTPQuery>(make_private {}, outer, delegate, isPost, userAgent, url, postData, postDataLengthInBytes, postDataMimeType, timeout));
        pThis->mThisWeak = pThis;
        pThis->init();
        return pThis;
      }

      //-----------------------------------------------------------------------
      void HTTP::HTTPQuery::prepareCurl()
      {
        AutoRecursiveLock lock(*this);

        ZS_THROW_BAD_STATE_IF(mCurl)

        mCurl = curl_easy_init();
        if (!mCurl) {
          ZS_LOG_ERROR(Detail, log("curl failed to initialize"))
          return;
        }

        if (ZS_IS_LOGGING(Insane)) {
          curl_easy_setopt(mCurl, CURLOPT_DEBUGFUNCTION, HTTPQuery::debug);
          curl_easy_setopt(mCurl, CURLOPT_DEBUGDATA, (void *)((PTRNUMBER)mID));

          curl_easy_setopt(mCurl, CURLOPT_VERBOSE, 1L);
        }

        curl_easy_setopt(mCurl, CURLOPT_ERRORBUFFER, mErrorBuffer.BytePtr());
        curl_easy_setopt(mCurl, CURLOPT_URL, mURL.c_str());
        if (!mUserAgent.isEmpty()) {
          curl_easy_setopt(mCurl, CURLOPT_USERAGENT, mUserAgent.c_str());
        }

        if (!mMimeType.isEmpty()) {
          String temp = "Content-Type: " + mMimeType;
          mHeaders = curl_slist_append(mHeaders, temp.c_str());
        }
        {
          /*
           Using POST with HTTP 1.1 implies the use of a "Expect: 100-continue"
           header.  You can disable this header with CURLOPT_HTTPHEADER as usual.
           NOTE: if you want chunked transfer too, you need to combine these two
           since you can only set one list of headers with CURLOPT_HTTPHEADER. */

           //please see http://curl.haxx.se/libcurl/c/post-callback.html for example usage

          mHeaders = curl_slist_append(mHeaders, "Expect:");
        }

        if (mHeaders) {
          curl_easy_setopt(mCurl, CURLOPT_HTTPHEADER, mHeaders);
        }

        curl_easy_setopt(mCurl, CURLOPT_HEADER, 0);
        if (mIsPost) {
          curl_easy_setopt(mCurl, CURLOPT_POST, 1L);

          if (mPostData.size() > 0) {
            curl_easy_setopt(mCurl, CURLOPT_POSTFIELDS, mPostData.BytePtr());
            curl_easy_setopt(mCurl, CURLOPT_POSTFIELDSIZE, mPostData.size());
          }
        }

        curl_easy_setopt(mCurl, CURLOPT_HEADERFUNCTION, HTTPQuery::writeHeader);
        curl_easy_setopt(mCurl, CURLOPT_WRITEHEADER, this);

        curl_easy_setopt(mCurl, CURLOPT_WRITEFUNCTION, HTTPQuery::writeData);
        curl_easy_setopt(mCurl, CURLOPT_WRITEDATA, this);

        if (Milliseconds() != mTimeout) {
          curl_easy_setopt(mCurl, CURLOPT_TIMEOUT_MS, zsLib::toMilliseconds(mTimeout));
        }

#ifdef ORTC_SERVICES_HTTP_TLS_FORCE_TLS_VERSION_TLS_1
        curl_easy_setopt(mCurl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
#endif //ORTC_SERVICES_HTTP_TLS_FORCE_TLS_VERSION_TLS_1

#ifdef ORTC_SERVICES_HTTP_TLS_FORCE_TLS_VERSION_SSL_2
        curl_easy_setopt(mCurl, CURLOPT_SSLVERSION, CURL_SSLVERSION_SSLv2);
#endif //ORTC_SERVICES_HTTP_TLS_FORCE_TLS_VERSION_SSL_2

#ifdef ORTC_SERVICES_HTTP_TLS_FORCE_TLS_VERSION_SSL_3
        curl_easy_setopt(mCurl, CURLOPT_SSLVERSION, CURL_SSLVERSION_SSLv3);
#endif //ORTC_SERVICES_HTTP_TLS_FORCE_TLS_VERSION_SSL_3

#ifdef ORTC_SERVICES_HTTP_ALLOW_BEAST
        curl_easy_setopt(mCurl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_ALLOW_BEAST);
        ZS_LOG_WARNING(Basic, log("CURL beast is enabled (enabling CURL beast can compromise security)"))

#define WARNING_ORTC_SERVICES_ENABLING_BEAST_CAN_COMPROMISE_SECURITY 1
#define WARNING_ORTC_SERVICES_ENABLING_BEAST_CAN_COMPROMISE_SECURITY 2

#endif //ORTC_SERVICES_HTTP_ALLOW_BEAST

        //#define ORTC_SERVICES_HTTP_TLS_FORCE_TLS_VERSION_TLS_1
        //#define ORTC_SERVICES_HTTP_TLS_FORCE_TLS_VERSION_SSL_2
        //#define ORTC_SERVICES_HTTP_TLS_FORCE_TLS_VERSION_SSL_3


        if (ZS_IS_LOGGING(Debug)) {
          ZS_LOG_BASIC(log("------------------------------------HTTP INFO----------------------------------"))
          ZS_LOG_BASIC(log("INFO") + ZS_PARAM("URL", mURL))
          ZS_LOG_BASIC(log("INFO") + ZS_PARAM("method", (mIsPost ? "POST" : "GET")))
          ZS_LOG_BASIC(log("INFO") + ZS_PARAM("user agent", mUserAgent))
          if ((mIsPost) &&
              (mPostData.size() > 0)) {
            ZS_LOG_BASIC(log("INFO") + ZS_PARAM("content type", mMimeType))
            ZS_LOG_BASIC(log("INFO") + ZS_PARAM("posted length", mPostData.size()))
          }
          if (Milliseconds() != mTimeout) {
            ZS_LOG_BASIC(log("INFO") + ZS_PARAM("timeout (ms)", mTimeout))
          }

          if (ZS_IS_LOGGING(Trace)) {
            ZS_LOG_BASIC(log("------------------------------------HTTP INFO----------------------------------"))
            if (mIsPost) {
              if (mPostData.size() > 0) {
                String base64 = IHelper::convertToBase64(mPostData);
                ZS_LOG_BASIC(log("POST DATA") + ZS_PARAM("wire out", base64)) // safe to cast BYTE * as const char * because buffer is NUL terminated
              }
            }
          }
          ZS_LOG_BASIC(log("------------------------------------HTTP INFO----------------------------------"))
        }
      }

      //-----------------------------------------------------------------------
      void HTTP::HTTPQuery::cleanupCurl()
      {
        AutoRecursiveLock lock(*this);
        mOuter.reset();

        cancel();
      }

      //-----------------------------------------------------------------------
      CURL *HTTP::HTTPQuery::getCURL() const
      {
        AutoRecursiveLock lock(*this);
        return mCurl;
      }

      //-----------------------------------------------------------------------
      void HTTP::HTTPQuery::notifyComplete(CURLcode result)
      {
        AutoRecursiveLock lock(*this);

        if ((mCurl) &&
            (0 == mResponseCode)) {
          long responseCode = 0;
          curl_easy_getinfo(mCurl, CURLINFO_RESPONSE_CODE, &responseCode);
          mResponseCode = (WORD)responseCode;
        }

        mResultCode = result;
        if (0 == mResponseCode) {
          if (CURLE_OK != result) {
            if (mCurl) {
              mResponseCode = HTTPStatusCode_MethodFailure;
            } else {
              mResponseCode = HTTPStatusCode_ClientClosedRequest;
            }
            ZS_LOG_DEBUG(log("manually result error") + ZS_PARAM("error", toString(toStatusCode((IHTTP::StatusCodeType) mResponseCode))))
          }
        }

        if (ZS_IS_LOGGING(Debug)) {
          ZS_LOG_BASIC(log("----------------------------------HTTP COMPLETE--------------------------------"))
          bool successful = (((mResponseCode >= 200) && (mResponseCode < 400)) &&
                             (CURLE_OK == mResultCode));
          ZS_LOG_BASIC(log("INFO") + ZS_PARAM("success", successful))
          ZS_LOG_BASIC(log("INFO") + ZS_PARAM("HTTP response code", mResponseCode))
          ZS_LOG_BASIC(log("INFO") + ZS_PARAM("CURL result code", mResultCode))
          ZS_LOG_BASIC(log("INFO") + ZS_PARAM("CURL error message", (CSTR)(mErrorBuffer.BytePtr())))
          ZS_LOG_BASIC(log("INFO") + ZS_PARAM("HEADER SIZE", mHeader.MaxRetrievable()))
          ZS_LOG_BASIC(log("INFO") + ZS_PARAM("BODY SIZE", mBody.MaxRetrievable()))
          ZS_LOG_BASIC(log("----------------------------------HTTP COMPLETE--------------------------------"))
        }
        cleanupCurl();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark HTTP::HTTPQuery => (internal)
      #pragma mark

      //-----------------------------------------------------------------------
      Log::Params HTTP::HTTPQuery::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("HTTPQuery");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      size_t HTTP::HTTPQuery::writeHeader(
                                          void *ptr,
                                          size_t size,
                                          size_t nmemb,
                                          void *userdata
                                          )
      {
        HTTPQueryPtr pThis = ((HTTPQuery *)userdata)->mThisWeak.lock();

        AutoRecursiveLock lock(*pThis);

        if (!pThis->mDelegate) {
          return 0;
        }

        bool firstHeader = pThis->mHeader.IsEmpty();

        pThis->mHeader.Put((BYTE *)ptr, size*nmemb);

        if (ZS_IS_LOGGING(Debug)) {
          if (firstHeader) {
            ZS_LOG_BASIC(pThis->log("----------------------------HTTP HEADER DATA RECEIVED--------------------------"))
          }

          SecureByteBlock buffer;
          buffer.CleanNew(size * nmemb);
          memcpy(buffer.BytePtr(), ptr, size * nmemb);

          String value = ((CSTR)(buffer.BytePtr()));
          value.trim();

          ZS_LOG_BASIC(pThis->log("HEADER") + ZS_PARAM("value", value))

          if (buffer.size() > 0) {
            char letter = (char)(*(buffer.BytePtr()));
            if ((letter == '\n') || (letter == '\r')) {
              ZS_LOG_BASIC(pThis->log("----------------------------HTTP HEADER DATA RECEIVED--------------------------"))
            }
          }
        }

        if ((pThis->mCurl) &&
            (0 == pThis->mResponseCode)) {
          long responseCode = 0;
          curl_easy_getinfo(pThis->mCurl, CURLINFO_RESPONSE_CODE, &responseCode);
          pThis->mResponseCode = (WORD)responseCode;
        }

        try {
          pThis->mDelegate->onHTTPReadDataAvailable(pThis);
        } catch(IHTTPQueryDelegateProxy::Exceptions::DelegateGone &) {
          ZS_LOG_WARNING(Detail, pThis->log("delegate gone"))
        }

        return size*nmemb;
      }

      //-----------------------------------------------------------------------
      size_t HTTP::HTTPQuery::writeData(
                                        char *ptr,
                                        size_t size,
                                        size_t nmemb,
                                        void *userdata
                                        )
      {
        HTTPQueryPtr pThis = ((HTTPQuery *)userdata)->mThisWeak.lock();

        AutoRecursiveLock lock(*pThis);

        if (!pThis->mDelegate) {
          return 0;
        }

        //pThis->mBody.LazyPut((BYTE *)ptr, size*nmemb);
        pThis->mBody.Put((BYTE *)ptr, size*nmemb);

        if (ZS_IS_LOGGING(Trace)) {
          ZS_LOG_BASIC(pThis->log("-----------------------------HTTP BODY DATA RECEIVED---------------------------"))

          SecureByteBlock buffer;
          buffer.CleanNew(size * nmemb + sizeof(char));
          memcpy(buffer.BytePtr(), ptr, size * nmemb);

          String base64 = IHelper::convertToBase64(buffer);

          ZS_LOG_BASIC(pThis->log("BODY") + ZS_PARAM("wire in", base64))
          ZS_LOG_BASIC(pThis->log("-----------------------------HTTP BODY DATA RECEIVED---------------------------"))
        }

        if ((pThis->mCurl) &&
            (0 == pThis->mResponseCode)) {
          long responseCode = 0;
          curl_easy_getinfo(pThis->mCurl, CURLINFO_RESPONSE_CODE, &responseCode);
          pThis->mResponseCode = (WORD)responseCode;
        }

        try {
          pThis->mDelegate->onHTTPReadDataAvailable(pThis);
        } catch(IHTTPQueryDelegateProxy::Exceptions::DelegateGone &) {
          ZS_LOG_WARNING(Detail, pThis->log("delegate gone"))
        }

        return size*nmemb;
      }

      //-----------------------------------------------------------------------
      static Log::Params slogQuery(const char *message, PUID id)
      {
        ElementPtr objectEl = Element::create("HTTPQuery");
        IHelper::debugAppend(objectEl, "id", id);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      int HTTP::HTTPQuery::debug(
                                 CURL *handle,
                                 curl_infotype type,
                                 char *data,
                                 size_t size,
                                 void *userdata
                                 )
      {
        const char *typeStr = "UNKNOWN";
        switch (type) {
          case CURLINFO_TEXT:         typeStr = "Text"; break;
          case CURLINFO_HEADER_IN:    typeStr = "Header in"; break;
          case CURLINFO_HEADER_OUT:   typeStr = "Header out"; break;
          case CURLINFO_DATA_IN:      typeStr = "Data in"; break;
          case CURLINFO_DATA_OUT:     typeStr = "Data out"; break;
          case CURLINFO_SSL_DATA_IN:  typeStr = "SSL data in"; break;
          case CURLINFO_SSL_DATA_OUT: typeStr = "SSL data out"; break;
          case CURLINFO_END:          break;
        }

        SecureByteBlock raw(size);
        memcpy(raw.BytePtr(), data, size);

        PUID id = (PUID)((PTRNUMBER)userdata);

        ZS_LOG_INSANE(slogQuery("CURL debug", id) + ZS_PARAM("type", typeStr) + ZS_PARAM("data", (CSTR)raw.BytePtr()))

        return 0;
      }
#else
namespace ortc
{
  namespace services
  {
    namespace internal
    {
#endif //ndef WINUWP

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IHTTPFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IHTTPFactory &IHTTPFactory::singleton()
      {
        return HTTPFactory::singleton();
      }

      //-----------------------------------------------------------------------
      IHTTPQueryPtr IHTTPFactory::get(
                                      IHTTPQueryDelegatePtr delegate,
                                      const char *userAgent,
                                      const char *url,
                                      Milliseconds timeout
                                      )
      {
        if (this) {}
        return HTTP::get(delegate, userAgent, url, timeout);
      }

      //-----------------------------------------------------------------------
      IHTTPQueryPtr IHTTPFactory::post(
                                       IHTTPQueryDelegatePtr delegate,
                                       const char *userAgent,
                                       const char *url,
                                       const BYTE *postData,
                                       size_t postDataLengthInBytes,
                                       const char *postDataMimeType,
                                       Milliseconds timeout
                                       )
      {
        if (this) {}
        return HTTP::post(delegate, userAgent, url, postData, postDataLengthInBytes, postDataMimeType, timeout);
      }

    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IHTTP
    #pragma mark

    //-------------------------------------------------------------------------
    IHTTP::HTTPStatusCodes IHTTP::toStatusCode(WORD statusCode)
    {
      return (HTTPStatusCodes)statusCode;
    }

    //-------------------------------------------------------------------------
    const char *IHTTP::toString(HTTPStatusCodes httpStatusCode)
    {
      switch (httpStatusCode)
      {
        case HTTPStatusCode_Continue:                         return "Continue";
        case HTTPStatusCode_SwitchingProtocols:               return "Switching Protocols";
        case HTTPStatusCode_Processing:                       return "Processing";

        case HTTPStatusCode_OK:                               return "OK";
        case HTTPStatusCode_Created:                          return "Created";
        case HTTPStatusCode_Accepted:                         return "Accepted";
        case HTTPStatusCode_NonAuthoritativeInformation:      return "Non-Authoritative Information";
        case HTTPStatusCode_NoContent:                        return "No Content";
        case HTTPStatusCode_ResetContent:                     return "Reset Content";
        case HTTPStatusCode_PartialContent:                   return "Partial Content";
        case HTTPStatusCode_MultiStatus:                      return "Multi-Status";
        case HTTPStatusCode_AlreadyReported:                  return "Already Reported";
        case HTTPStatusCode_IMUsed:                           return "IM Used";
        case HTTPStatusCode_AuthenticationSuccessful:         return "Authentication Successful";

        case HTTPStatusCode_MultipleChoices:                  return "Multiple Choices";
        case HTTPStatusCode_MovedPermanently:                 return "Moved Permanently";
        case HTTPStatusCode_Found:                            return "Found";
        case HTTPStatusCode_SeeOther:                         return "See Other";
        case HTTPStatusCode_NotModified:                      return "Not Modified";
        case HTTPStatusCode_UseProxy:                         return "Use Proxy";
        case HTTPStatusCode_SwitchProxy:                      return "Switch Proxy";
        case HTTPStatusCode_TemporaryRedirect:                return "Temporary Redirect";
        case HTTPStatusCode_PermanentRedirect:                return "Permanent Redirect";

        case HTTPStatusCode_BadRequest:                       return "Bad Request";
        case HTTPStatusCode_Unauthorized:                     return "Unauthorized";
        case HTTPStatusCode_PaymentRequired:                  return "Payment Required";
        case HTTPStatusCode_Forbidden:                        return "Forbidden";
        case HTTPStatusCode_NotFound:                         return "Not Found";
        case HTTPStatusCode_MethodNotAllowed:                 return "Method Not Allowed";
        case HTTPStatusCode_NotAcceptable:                    return "Not Acceptable";
        case HTTPStatusCode_ProxyAuthenticationRequired:      return "Proxy Authentication Required";
        case HTTPStatusCode_RequestTimeout:                   return "Request Timeout";
        case HTTPStatusCode_Conflict:                         return "Conflict";
        case HTTPStatusCode_Gone:                             return "Gone";
        case HTTPStatusCode_LengthRequired:                   return "Length Required";
        case HTTPStatusCode_PreconditionFailed:               return "Precondition Failed";
        case HTTPStatusCode_RequestEntityTooLarge:            return "Request Entity Too Large";
        case HTTPStatusCode_RequestURITooLong:                return "Request-URI Too Long";
        case HTTPStatusCode_UnsupportedMediaType:             return "Unsupported Media Type";
        case HTTPStatusCode_RequestedRangeNotSatisfiable:     return "Requested Range Not Satisfiable";
        case HTTPStatusCode_ExpectationFailed:                return "Expectation Failed";
        case HTTPStatusCode_Imateapot:                        return "I'm a teapot";
        case HTTPStatusCode_EnhanceYourCalm:                  return "Enhance Your Calm";
        case HTTPStatusCode_UnprocessableEntity:              return "Unprocessable Entity";
        case HTTPStatusCode_Locked:                           return "Locked";
//        case HTTPStatusCode_FailedDependency:                 return "Failed Dependency";
        case HTTPStatusCode_MethodFailure:                    return "Method Failure";
        case HTTPStatusCode_UnorderedCollection:              return "Unordered Collection";
        case HTTPStatusCode_UpgradeRequired:                  return "Upgrade Required";
        case HTTPStatusCode_PreconditionRequired:             return "Precondition Required";
        case HTTPStatusCode_TooManyRequests:                  return "Too Many Requests";
        case HTTPStatusCode_RequestHeaderFieldsTooLarge:      return "Request Header Fields Too Large";
        case HTTPStatusCode_NoResponse:                       return "No Response";
        case HTTPStatusCode_RetryWith:                        return "Retry With";
        case HTTPStatusCode_BlockedbyWindowsParentalControls: return "Blocked by Windows Parental Controls";
        case HTTPStatusCode_UnavailableForLegalReasons:       return "Unavailable For Legal Reasons";
//        case HTTPStatusCode_Redirect:                         return "Redirect";
        case HTTPStatusCode_RequestHeaderTooLarge:            return "Request Header Too Large";
        case HTTPStatusCode_CertError:                        return "Cert Error";
        case HTTPStatusCode_NoCert:                           return "No Cert";
        case HTTPStatusCode_HTTPtoHTTPS:                      return "HTTP to HTTPS";
        case HTTPStatusCode_ClientClosedRequest:              return "Client Closed Request";

        case HTTPStatusCode_InternalServerError:              return "Internal Server Error";
        case HTTPStatusCode_NotImplemented:                   return "Not Implemented";
        case HTTPStatusCode_BadGateway:                       return "Bad Gateway";
        case HTTPStatusCode_ServiceUnavailable:               return "Service Unavailable";
        case HTTPStatusCode_GatewayTimeout:                   return "Gateway Timeout";
        case HTTPStatusCode_HTTPVersionNotSupported:          return "HTTP Version Not Supported";
        case HTTPStatusCode_VariantAlsoNegotiates:            return "Variant Also Negotiates";
        case HTTPStatusCode_InsufficientStorage:              return "Insufficient Storage";
        case HTTPStatusCode_LoopDetected:                     return "Loop Detected";
        case HTTPStatusCode_BandwidthLimitExceeded:           return "Bandwidth Limit Exceeded";
        case HTTPStatusCode_NotExtended:                      return "Not Extended";
        case HTTPStatusCode_NetworkAuthenticationRequired:    return "Network Authentication Required";
        case HTTPStatusCode_Networkreadtimeouterror:          return "Network read timeout error";
        case HTTPStatusCode_Networkconnecttimeouterror:       return "Network connect timeout error";
        default:                                              break;
      }
      return "";
    }

    //-------------------------------------------------------------------------
    bool IHTTP::isPending(HTTPStatusCodes httpStatusCode, bool noneIsPending)
    {
      if (noneIsPending) {
        if (HTTPStatusCode_None == httpStatusCode) {
          return true;
        }
      }
      return isInformational(httpStatusCode);
    }

    //-------------------------------------------------------------------------
    bool IHTTP::isInformational(HTTPStatusCodes httpStatusCode)
    {
      return ((httpStatusCode >= HTTPStatusCode_InformationalStart) &&
              (httpStatusCode <= HTTPStatusCode_InformationalEnd));
    }

    //-------------------------------------------------------------------------
    bool IHTTP::isSuccess(HTTPStatusCodes httpStatusCode, bool noneIsSuccess)
    {
      if (noneIsSuccess) {
        if (HTTPStatusCode_None == httpStatusCode) {
          return true;
        }
      }
      return ((httpStatusCode >= HTTPStatusCode_SuccessfulStart) &&
              (httpStatusCode <= HTTPStatusCode_SuccessfulEnd));
    }

    //-------------------------------------------------------------------------
    bool IHTTP::isRedirection(HTTPStatusCodes httpStatusCode)
    {
      return ((httpStatusCode >= HTTPStatusCode_RedirectionStart) &&
              (httpStatusCode <= HTTPStatusCode_RedirectionEnd));
    }

    //-------------------------------------------------------------------------
    bool IHTTP::isError(HTTPStatusCodes httpStatusCode, bool noneIsError)
    {
      if (noneIsError) {
        if (HTTPStatusCode_None == httpStatusCode) {
          return true;
        }
      }
      return (httpStatusCode >= HTTPStatusCode_ClientErrorStart);
    }

    //-------------------------------------------------------------------------
    IHTTPQueryPtr IHTTP::get(
                             IHTTPQueryDelegatePtr delegate,
                             const char *userAgent,
                             const char *url,
                             Milliseconds timeout
                             )
    {
      return internal::IHTTPFactory::singleton().get(delegate, userAgent, url, timeout);
    }

    //-------------------------------------------------------------------------
    IHTTPQueryPtr IHTTP::post(
                              IHTTPQueryDelegatePtr delegate,
                              const char *userAgent,
                              const char *url,
                              const char *postData,
                              const char *postDataMimeType,
                              Milliseconds timeout
                              )
    {
      return internal::IHTTPFactory::singleton().post(delegate, userAgent, url, (const BYTE *)postData, (postData ? strlen(postData) : 0), postDataMimeType, timeout);
    }

    //-------------------------------------------------------------------------
    IHTTPQueryPtr IHTTP::post(
                              IHTTPQueryDelegatePtr delegate,
                              const char *userAgent,
                              const char *url,
                              const BYTE *postData,
                              size_t postDataLengthInBytes,
                              const char *postDataMimeType,
                              Milliseconds timeout
                              )
    {
      return internal::IHTTPFactory::singleton().post(delegate, userAgent, url, postData, postDataLengthInBytes, postDataMimeType, timeout);
    }
  }
}
