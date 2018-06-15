/*

 Copyright (c) 2017, Optical Tone Ltd.
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
#include <ortc/services/internal/services_HTTP_override.h>
#include <ortc/services/internal/services.events.h>

#include <ortc/services/internal/services_Helper.h>

#include <zsLib/IMessageQueueManager.h>
#include <zsLib/ISettings.h>
#include <zsLib/helpers.h>
#include <zsLib/Stringize.h>
#include <zsLib/Log.h>
#include <zsLib/XML.h>

namespace ortc { namespace services { ZS_DECLARE_SUBSYSTEM(org_ortc_services_http) } }

namespace ortc
{
  namespace services
  {
    ZS_DECLARE_TYPEDEF_PTR(zsLib::IMessageQueueManager, UseMessageQueueManager);

    namespace internal
    {
      ZS_DECLARE_CLASS_PTR(HTTPOverrideSettingsDefaults);

      //-------------------------------------------------------------------------
      //-------------------------------------------------------------------------
      //-------------------------------------------------------------------------
      //-------------------------------------------------------------------------
      //
      // HTTPOverrideSettingsDefaults
      //

      class HTTPOverrideSettingsDefaults : public ISettingsApplyDefaultsDelegate
      {
      public:
        //-----------------------------------------------------------------------
        ~HTTPOverrideSettingsDefaults() noexcept
        {
          ISettings::removeDefaults(*this);
        }

        //-----------------------------------------------------------------------
        static HTTPOverrideSettingsDefaultsPtr singleton() noexcept
        {
          static SingletonLazySharedPtr<HTTPOverrideSettingsDefaults> singleton(create());
          return singleton.singleton();
        }

        //-----------------------------------------------------------------------
        static HTTPOverrideSettingsDefaultsPtr create() noexcept
        {
          auto pThis(make_shared<HTTPOverrideSettingsDefaults>());
          ISettings::installDefaults(pThis);
          return pThis;
        }

        //-----------------------------------------------------------------------
        virtual void notifySettingsApplyDefaults() noexcept override
        {
          //ISettings::setUInt(ORTC_SERVICES_DEFAULT_HTTP_TIMEOUT_SECONDS, 60 * 2);
        }
      };

      //-------------------------------------------------------------------------
      void installHttpOverrideSettingsDefaults() noexcept
      {
        HTTPOverrideSettingsDefaults::singleton();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // HTTPOverride
      //

      //-----------------------------------------------------------------------
      HTTPOverride::HTTPOverride(const make_private &) noexcept :
        SharedRecursiveLock(SharedRecursiveLock::create())
      {
        ZS_EVENTING_1(x, i, Detail, ServicesHttpOverrideCreate, os, Http, Start, puid, id, id_);
      }

      //-----------------------------------------------------------------------
      void HTTPOverride::init() noexcept
      {
      }

      //-----------------------------------------------------------------------
      HTTPOverride::~HTTPOverride() noexcept
      {
        if (isNoop()) return;

        thisWeak_.reset();
        ZS_EVENTING_1(x, i, Detail, ServicesHttpOverrideDestroy, os, Http, Stop, puid, id, id_);
        cancel();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // HTTPOverride => IHTTP
      //

      //-----------------------------------------------------------------------
      HTTPOverride::HTTPQueryPtr HTTPOverride::query(
                                                     IHTTPQueryDelegatePtr delegate,
                                                     const QueryInfo &info
                                                     ) noexcept
      {
        auto pThis = singleton();

        HTTPQueryPtr query = HTTPQuery::create(pThis, delegate, info);

        if (!pThis) {
          query->notifyComplete(HTTPStatusCode_MethodFailure); // singleton gone so cannot perform HTTP operation at this time
          return query;
        }


        IHTTPOverrideDelegatePtr overrideDelegate;

        {
          AutoRecursiveLock lock(*pThis);
          overrideDelegate = pThis->override_;
        }

        if (!overrideDelegate) {
          query->notifyComplete(HTTPStatusCode_MethodFailure); // singleton gone so cannot perform HTTP operation at this time
          return query;
        }

        pThis->monitorBegin(query);
        return query;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // HTTP => IHTTPOverride
      //

      //-----------------------------------------------------------------------
      void HTTPOverride::install(IHTTPOverrideDelegatePtr overrideDelegate) noexcept
      {
        auto pThis = singleton();

        if (!pThis) return;

        {
          AutoRecursiveLock lock(*pThis);
          pThis->override_ = overrideDelegate;
        }
      }

      //-----------------------------------------------------------------------
      void HTTPOverride::notifyHeaderData(
                                          IHTTPQueryPtr query,
                                          const BYTE *buffer,
                                          size_t sizeInBytes
                                          ) noexcept(false)
      {
        auto castQuery = ZS_DYNAMIC_PTR_CAST(HTTPQuery, query);
        ZS_THROW_INVALID_ARGUMENT_IF(!castQuery);

        castQuery->notifyHeaderData(buffer, sizeInBytes);
      }


      //-----------------------------------------------------------------------
      void HTTPOverride::notifyBodyData(
                                        IHTTPQueryPtr query,
                                        const BYTE *buffer,
                                        size_t sizeInBytes
                                        ) noexcept(false)
      {        
        auto castQuery = ZS_DYNAMIC_PTR_CAST(HTTPQuery, query);
        ZS_THROW_INVALID_ARGUMENT_IF(!castQuery);

        castQuery->notifyBodyData(buffer, sizeInBytes);
      }

      //-----------------------------------------------------------------------
      void HTTPOverride::notifyComplete(
                                        IHTTPQueryPtr query,
                                        IHTTP::HTTPStatusCodes status
                                        ) noexcept(false)
      {        
        auto castQuery = ZS_DYNAMIC_PTR_CAST(HTTPQuery, query);
        ZS_THROW_INVALID_ARGUMENT_IF(!castQuery);

        castQuery->notifyComplete(status);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // HTTPOverride => friend HTTPQuery
      //

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // HTTPOverride => (internal)
      //

      //-----------------------------------------------------------------------
      HTTPOverridePtr HTTPOverride::singleton() noexcept
      {
        AutoRecursiveLock lock(*IHelper::getGlobalLock());
        static SingletonLazySharedPtr<HTTPOverride> singleton(HTTPOverride::create());
        HTTPOverridePtr result = singleton.singleton();
        if (!result) {
          ZS_EVENTING_0(x, w, Debug, ServicesHttpOverrideSingletonGone, os, Http, Info);
        }
        return result;
      }

      //-----------------------------------------------------------------------
      HTTPOverridePtr HTTPOverride::create() noexcept
      {
        HTTPOverridePtr pThis(make_shared<HTTPOverride>(make_private{}));
        pThis->thisWeak_ = pThis;
        pThis->init();
        return pThis;
      }

      //-----------------------------------------------------------------------
      void HTTPOverride::cancel() noexcept
      {

        HTTPQueryMap queries;

        {
          AutoRecursiveLock lock(*this);
          queries = queries_;

          queries_.clear();
        }

        for (auto iter = queries.begin(); iter != queries.end(); ++iter) {
          auto query = (*iter).second.lock();
          if (!query) continue;
          query->cancel();
        }

        override_.reset();
      }

      //-----------------------------------------------------------------------
      void HTTPOverride::monitorBegin(HTTPQueryPtr query) noexcept
      {
        {
          AutoRecursiveLock lock(*this);
          queries_[query->getID()] = query;
          query->go(override_);
        }

        ZS_EVENTING_2(x, i, Trace, ServicesHttpOverrideMonitorBegin, os, Http, Start,
          puid, id, id_,
          puid, queryId, query->getID()
          );
      }

      //-----------------------------------------------------------------------
      void HTTPOverride::monitorEnd(HTTPQuery &query) noexcept
      {
        ZS_EVENTING_2(x, i, Trace, ServicesHttpOverrideMonitorEnd, os, Http, Stop,
          puid, id, id_,
          puid, queryId, query.getID()
          );

        AutoRecursiveLock lock(*this);

        auto found = queries_.find(query.getID());
        if (found != queries_.end()) {
          queries_.erase(found);
        }
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // HTTPOverride::HTTPQuery
      //

      //-----------------------------------------------------------------------
      HTTPOverride::HTTPQuery::HTTPQuery(
                                         const make_private &,
                                         HTTPOverridePtr outer,
                                         IHTTPQueryDelegatePtr delegate,
                                         const QueryInfo &query
                                         ) noexcept :
        SharedRecursiveLock(outer ? *outer : SharedRecursiveLock::create()),
        MessageQueueAssociator(IHelper::getServiceQueue()),
        outer_(outer),
        delegate_(IHTTPQueryDelegateProxy::create(UseMessageQueueManager::getMessageQueueForGUIThread(), delegate)),
        query_(query)
      {
        if (!query_.postData_) {
          if (query_.postDataAsString_.hasData()) {
            query_.postData_ = make_shared<SecureByteBlock>((const BYTE *)query_.postDataAsString_.c_str(), query_.postDataAsString_.length());
          }
        }
 
        ZS_EVENTING_1(x, i, Debug, ServicesHttpQueryCreate, os, Http, Start, puid, id, id_);
        ZS_EVENTING_TRACE_OBJECT(Debug, query_, "http override query info");
      }

      //-----------------------------------------------------------------------
      void HTTPOverride::HTTPQuery::init() noexcept
      {
      }

      //-----------------------------------------------------------------------
      HTTPOverride::HTTPQuery::~HTTPQuery() noexcept
      {
        thisWeak_.reset();
        cancel();

        ZS_EVENTING_1(x, i, Debug, ServicesHttpQueryDestroy, os, Http, Stop, puid, id, id_);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // HTTPOverride::HTTPQuery => IHTTPQuery
      //

      //-----------------------------------------------------------------------
      void HTTPOverride::HTTPQuery::cancel() noexcept
      {
        ZS_EVENTING_1(x, i, Debug, ServicesHttpQueryCancel, os, Http, Cancel, puid, id, id_);

        HTTPOverridePtr outer = outer_.lock();

        IHTTPOverrideDelegatePtr overrideDelegate;

        if (outer) {
          outer->monitorEnd(*this);
        }

        IHTTPQueryDelegatePtr delegate;

        {
          AutoRecursiveLock lock(*this);

          if (timer_) {
            timer_->cancel();
            timer_.reset();
          }

          overrideDelegate = override_;
          delegate = delegate_;
          if (delegate) {
            if (HTTPStatusCodes::HTTPStatusCode_None == statusCode_) statusCode_ = HTTPStatusCodes::HTTPStatusCode_Gone;
          }
          delegate_.reset();
        }

        HTTPQueryPtr pThis = thisWeak_.lock();
        if (pThis) {
          if (delegate) {
            try {
              delegate->onHTTPCompleted(pThis);
            } catch (IHTTPQueryDelegateProxy::Exceptions::DelegateGone &) {
              ZS_EVENTING_1(x, w, Detail, ServicesHttpQueryDelegateGone, os, Http, Info, puid, id, id_);
            }
          }
          if (overrideDelegate) {
            try {
              overrideDelegate->onHTTPOverrideQueryCancelled(pThis);
            } catch (IHTTPOverrideDelegateProxy::Exceptions::DelegateGone &) {
              ZS_EVENTING_1(x, e, Detail, ServicesHttpOverrideDelegateGone, os, Http, Info, puid, id, id_);
            }
          }
        }
      }

      //-----------------------------------------------------------------------
      bool HTTPOverride::HTTPQuery::isComplete() const noexcept
      {
        AutoRecursiveLock lock(*this);
        if (!delegate_) return true;
        return false;
      }

      //-----------------------------------------------------------------------
      bool HTTPOverride::HTTPQuery::wasSuccessful() const noexcept
      {
        AutoRecursiveLock lock(*this);
        if (delegate_) return false;

        return ((((WORD)statusCode_) >= 200) && (((WORD)statusCode_) < 400));
      }

      //-----------------------------------------------------------------------
      IHTTP::HTTPStatusCodes HTTPOverride::HTTPQuery::getStatusCode() const noexcept
      {
        AutoRecursiveLock lock(*this);
        return IHTTP::toStatusCode((WORD)statusCode_);
      }

      //-----------------------------------------------------------------------
      size_t HTTPOverride::HTTPQuery::getHeaderReadSizeAvailableInBytes() const noexcept
      {
        AutoRecursiveLock lock(*this);
        return static_cast<size_t>(header_.MaxRetrievable());
      }

      //-----------------------------------------------------------------------
      size_t HTTPOverride::HTTPQuery::readHeader(
                                                 BYTE *outResultData,
                                                 size_t bytesToRead
                                                 ) noexcept
      {
        AutoRecursiveLock lock(*this);
        auto result = header_.Get(outResultData, bytesToRead);
        ZS_EVENTING_5(
                      x, i, Debug, ServicesHttpQueryReadHeader, os, Http, Receive,
                      puid, id, id_,
                      size_t, bytesToRead, bytesToRead,
                      size_t, result, result,
                      buffer, resultData, outResultData,
                      size, bytesRead, result
                      );
        return result;
      }

      //-----------------------------------------------------------------------
      size_t HTTPOverride::HTTPQuery::readHeaderAsString(String &outHeader) noexcept
      {
        outHeader.clear();

        AutoRecursiveLock lock(*this);
        CryptoPP::lword available = header_.MaxRetrievable();
        if (0 == available) return 0;

        SecureByteBlock data;
        data.CleanNew(static_cast<SecureByteBlock::size_type>(available));
        header_.Get(data.BytePtr(), static_cast<size_t>(available));

        outHeader = (const char *)data.BytePtr();
        auto result = strlen(outHeader);
        ZS_EVENTING_2(
                      x, i, Debug, ServicesHttpQueryReadHeaderAsString, os, Http, Receive,
                      puid, id, id_,
                      string, header, outHeader
                      );
        return result;
      }

      //-----------------------------------------------------------------------
      size_t HTTPOverride::HTTPQuery::getReadDataAvailableInBytes() const noexcept
      {
        AutoRecursiveLock lock(*this);
        return static_cast<size_t>(body_.MaxRetrievable());
      }

      //-----------------------------------------------------------------------
      size_t HTTPOverride::HTTPQuery::readData(
                                               BYTE *outResultData,
                                               size_t bytesToRead
                                               ) noexcept
      {
        AutoRecursiveLock lock(*this);
        auto result = body_.Get(outResultData, bytesToRead);
        ZS_EVENTING_4(
                      x, i, Debug, ServicesHttpQueryRead, os, Http, Receive,
                      puid, id, id_,
                      size_t, bytesToRead, bytesToRead,
                      buffer, data, outResultData,
                      size, result, result
                      );

        return result;
      }

      //-----------------------------------------------------------------------
      size_t HTTPOverride::HTTPQuery::readDataAsString(String &outResultData) noexcept
      {
        outResultData.clear();

        AutoRecursiveLock lock(*this);
        CryptoPP::lword available = body_.MaxRetrievable();
        if (0 == available) return 0;

        SecureByteBlock data;
        data.CleanNew(static_cast<SecureByteBlock::size_type>(available));
        body_.Get(data.BytePtr(), static_cast<size_t>(available));

        outResultData = (const char *)data.BytePtr();
        auto result = strlen(outResultData);
        ZS_EVENTING_2(
                      x, i, Debug, ServicesHttpQueryReadAsString, os, Http, Receive,
                      puid, id, id_,
                      string, result, outResultData
                      );
        return result;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // HTTPOverride::HTTPQuery => ITimerDelegate
      //

      //-----------------------------------------------------------------------
      void HTTPOverride::HTTPQuery::onTimer(ITimerPtr timer)
      {
        ZS_EVENTING_2(
                      x, i, Debug, ServicesHttpQueryOnTimer, os, Http, InternalEvent,
                      puid, id, id_,
                      puid, timerId, timer->getID()
                      );

        cancel();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // HTTPOverride::HTTPQuery => friend HTTP
      //

      //-----------------------------------------------------------------------
      HTTPOverride::HTTPQueryPtr HTTPOverride::HTTPQuery::create(
                                                                 HTTPOverridePtr outer,
                                                                 IHTTPQueryDelegatePtr delegate,
                                                                 const QueryInfo &query
                                                                 ) noexcept
      {
        HTTPQueryPtr pThis(make_shared<HTTPQuery>(make_private{}, outer, delegate, query));
        pThis->thisWeak_ = pThis;
        pThis->init();
        return pThis;
      }

      //-----------------------------------------------------------------------
      void HTTPOverride::HTTPQuery::go(IHTTPOverrideDelegatePtr overrideDelegate) noexcept
      {
        Time timeout = zsLib::now() + query_.timeout_;
        if (Milliseconds() == query_.timeout_) {
          Seconds defaultTimeout(ISettings::getUInt(ORTC_SERVICES_DEFAULT_HTTP_TIMEOUT_SECONDS));
          if (Seconds() == defaultTimeout) {
            defaultTimeout = Seconds(60*2);
          }
          timeout = zsLib::now() + defaultTimeout;
        }
        timer_ = ITimer::create(thisWeak_.lock(), timeout);

        overrideDelegate = IHTTPOverrideDelegateProxy::create(UseMessageQueueManager::getMessageQueueForGUIThread(), overrideDelegate);
        override_ = overrideDelegate;

        if (!overrideDelegate) {
          notifyComplete(HTTPStatusCodes::HTTPStatusCode_Gone);
          return;
        }

        override_->onHTTPOverrideQuery(thisWeak_.lock(), query_);
      }

      //-----------------------------------------------------------------------
      void HTTPOverride::HTTPQuery::notifyComplete(HTTPStatusCodes result) noexcept
      {
        AutoRecursiveLock lock(*this);

        if (HTTPStatusCodes::HTTPStatusCode_None == statusCode_) statusCode_ = result;

        ZS_EVENTING_2(
                      x, i, Debug, ServicesHttpQueryNotifyComplete, os, Http, Info,
                      puid, id, id_,
                      string, result, IHTTP::toString(statusCode_)
                      );
        query_.trace();
        cancel();
      }

      //-----------------------------------------------------------------------
      void HTTPOverride::HTTPQuery::notifyHeaderData(
                                                     const BYTE *buffer,
                                                     size_t sizeInBytes
                                                     ) noexcept
      {
        if ((!buffer) || 
            (sizeInBytes < 1)) return;

        AutoRecursiveLock lock(*this);

        header_.Put(buffer, sizeInBytes);

        if (delegate_) {
          try {
            delegate_->onHTTPReadDataAvailable(thisWeak_.lock());
          } catch (IHTTPQueryDelegateProxy::Exceptions::DelegateGone &) {
            ZS_EVENTING_1(x, w, Detail, ServicesHttpQueryDelegateGone, os, Http, Info, puid, id, id_);
          }
        }
      }

      //-----------------------------------------------------------------------
      void HTTPOverride::HTTPQuery::notifyBodyData(
                                                   const BYTE *buffer,
                                                   size_t sizeInBytes
                                                   ) noexcept
      {
        if ((!buffer) || 
            (sizeInBytes < 1)) return;

        AutoRecursiveLock lock(*this);
        body_.Put(buffer, sizeInBytes);

        if (delegate_) {
          try {
            delegate_->onHTTPReadDataAvailable(thisWeak_.lock());
          } catch (IHTTPQueryDelegateProxy::Exceptions::DelegateGone &) {
            ZS_EVENTING_1(x, w, Detail, ServicesHttpQueryDelegateGone, os, Http, Info, puid, id, id_);
          }
        }
      }


      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // HTTP::HTTPQuery => (internal)
      //

    } // namepsace internal

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //
    // IHTTPOverride
    //

    //-------------------------------------------------------------------------
    void IHTTPOverride::install(IHTTPOverrideDelegatePtr delegate) noexcept
    {
      ZS_DECLARE_TYPEDEF_PTR(internal::IHTTPFactory, IHTTPFactory);

      if (!delegate) {
        internal::HTTPFactory::override(IHTTPFactoryPtr());
        return;
      }

      class Factory : public IHTTPFactory
      {
      public:
        virtual IHTTPQueryPtr query(
                                    IHTTPQueryDelegatePtr delegate,
                                    const QueryInfo &query
                                    ) noexcept
        {
          return internal::HTTPOverride::query(delegate, query);
        }
      };

      internal::HTTPOverride::install(delegate);
      internal::HTTPFactory::override(make_shared<Factory>());
    }

    //-------------------------------------------------------------------------
    void IHTTPOverride::uninstall() noexcept
    {
      install(IHTTPOverrideDelegatePtr());
    }

    //-------------------------------------------------------------------------
    void IHTTPOverride::notifyHeaderData(
                                         IHTTPQueryPtr query,
                                         const BYTE *buffer,
                                         size_t sizeInBytes
                                         ) noexcept(false)
    {
      return internal::HTTPOverride::notifyHeaderData(query, buffer, sizeInBytes);
    }

    //-------------------------------------------------------------------------
    void IHTTPOverride::notifyBodyData(
                                       IHTTPQueryPtr query,
                                       const BYTE *buffer,
                                       size_t sizeInBytes
                                       ) noexcept(false)
    {
      return internal::HTTPOverride::notifyBodyData(query, buffer, sizeInBytes);
    }

    //-------------------------------------------------------------------------
    void IHTTPOverride::notifyComplete(
                                       IHTTPQueryPtr query,
                                       IHTTP::HTTPStatusCodes status
                                       ) noexcept(false)
    {
      return internal::HTTPOverride::notifyComplete(query, status);
    }

  } // namespace services
} // namespace ortc
