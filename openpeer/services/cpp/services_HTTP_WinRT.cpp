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

#include <openpeer/services/IHTTP.h>
#include <openpeer/services/internal/services_HTTP.h>
#include <openpeer/services/internal/services_HTTP_WinRT.h>
#include <openpeer/services/internal/services_Tracing.h>

#ifdef WINRT

#include <openpeer/services/internal/services_Helper.h>

#include <openpeer/services/ISettings.h>

#include <zsLib/helpers.h>
#include <zsLib/Stringize.h>
#include <zsLib/Log.h>
#include <zsLib/XML.h>

using namespace Windows::Web::Http;
using namespace Concurrency;
using Windows::Foundation::Collections::IIterable;
using Windows::Foundation::Collections::IKeyValuePair;
using Windows::Storage::Streams::IBuffer;
using Windows::Storage::Streams::DataReader;
using Windows::Storage::Streams::DataWriter;
using Windows::Foundation::Uri;

namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services_http) } }

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
      #pragma mark HTTP
      #pragma mark

      //-----------------------------------------------------------------------
      HTTP::HTTP(const make_private &) :
        SharedRecursiveLock(SharedRecursiveLock::create())
      {
        IHelper::setSocketThreadPriority();

        mHTTPClient = ref new HttpClient();
        if (!mHTTPClient) {
          ZS_LOG_ERROR(Basic, log("create to create HTTP client object"))
        }

        ZS_LOG_DETAIL(log("created"))
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
        ZS_LOG_DETAIL(log("destroyed"))
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
          query->notifyComplete(HttpStatusCode::FailedDependency); // singleton gone so cannot perform CURL operation at this time
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
          query->notifyComplete(HttpStatusCode::FailedDependency); // singleton gone so cannot perform CURL operation at this time
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
        ElementPtr resultEl = Element::create("HTTP");
        IHelper::debugAppend(resultEl, "id", mID);
        IHelper::debugAppend(resultEl, "http client", nullptr != mHTTPClient ? true : false);
        return Log::Params(message, resultEl);
      }

      //-----------------------------------------------------------------------
      Log::Params HTTP::slog(const char *message)
      {
        return Log::Params(message, "HTTP");
      }

      //-----------------------------------------------------------------------
      void HTTP::cancel()
      {

        HTTPQueryMap queries;

        {
          AutoRecursiveLock lock(*this);
          queries = mQueries;

          mQueries.clear();
        }

        for (auto iter = queries.begin(); iter != queries.end(); ++iter) {
          auto query = (*iter).second.lock();
          if (!query) continue;
          query->cancel();
        }

        if (nullptr != mHTTPClient) {
          mHTTPClient = nullptr;
        }
      }

      //-----------------------------------------------------------------------
      void HTTP::monitorBegin(HTTPQueryPtr query)
      {
        HttpClient ^client;
        {
          AutoRecursiveLock lock(*this);

          client = mHTTPClient;

          if (nullptr == mHTTPClient) {
            ZS_LOG_WARNING(Detail, log("cannot monitor query when HTTP client is gone"))
          } else {
            mQueries[query->getID()] = query;
          }

          query->go(client);
        }

        ZS_LOG_TRACE(log("monitor begin for query") + ZS_PARAM("query", query->getID()))
      }

      //-----------------------------------------------------------------------
      void HTTP::monitorEnd(HTTPQuery &query)
      {
        ZS_LOG_TRACE(log("monitor end for query") + ZS_PARAM("query", query.getID()))

        AutoRecursiveLock lock(*this);

        auto found = mQueries.find(query.getID());
        if (found != mQueries.end()) {
          mQueries.erase(found);
        }
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
        MessageQueueAssociator(IHelper::getServiceQueue()),
        mOuter(outer),
        mDelegate(IHTTPQueryDelegateProxy::create(Helper::getServiceQueue(), delegate)),
        mIsPost(isPost),
        mUserAgent(userAgent),
        mURL(url),
        mMimeType(postDataMimeType),
        mTimeout(timeout),
        mStatusCode(HttpStatusCode::None)
      {
        ZS_LOG_DEBUG(log("created"))

        if (0 != postDataLengthInBytes) {
          mPostData.CleanNew(postDataLengthInBytes);
          memcpy(mPostData.BytePtr(), postData, postDataLengthInBytes);
        }

        EventWriteOpServicesHttpQueryCreate(__func__, mID, mIsPost, mUserAgent, mURL, postData, postDataLengthInBytes, postDataMimeType, timeout.count());
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

        EventWriteOpServicesHttpQueryDestroy(__func__, mID);
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
        EventWriteOpServicesHttpQueryCancel(__func__, mID);
        ZS_LOG_DEBUG(log("cancel called"))

        HTTPPtr outer = mOuter.lock();

        if (outer) {
          outer->monitorEnd(*this);
        }

        IHTTPQueryDelegatePtr delegate;

        {
          AutoRecursiveLock lock(*this);

          if (mTimer) {
            mTimer->cancel();
            mTimer.reset();
          }

          // cause the HTTP request to abort
          mCancellationTokenSource.cancel();

          delegate = mDelegate;
          if (delegate) {
            if (HttpStatusCode::None == mStatusCode) mStatusCode = HttpStatusCode::Gone;
          }
          mDelegate.reset();
        }

        HTTPQueryPtr pThis = mThisWeak.lock();
        if ((pThis) &&
            (delegate)) {
          try {
            delegate->onHTTPCompleted(pThis);
          } catch (IHTTPQueryDelegateProxy::Exceptions::DelegateGone &) {
            ZS_LOG_WARNING(Detail, log("delegate gone"))
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

        return ((((WORD)mStatusCode) >= 200) && (((WORD)mStatusCode) < 400));
      }

      //-----------------------------------------------------------------------
      IHTTP::HTTPStatusCodes HTTP::HTTPQuery::getStatusCode() const
      {
        AutoRecursiveLock lock(*this);
        return IHTTP::toStatusCode((WORD)mStatusCode);
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
        EventWriteOpServicesHttpQueryRead(__func__, mID, outResultData, result, bytesToRead);
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
        EventWriteOpServicesHttpQueryRead(__func__, mID, data.BytePtr(), result, static_cast<size_t>(available));
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
        EventWriteOpServicesHttpQueryRead(__func__, mID, outResultData, result, bytesToRead);
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
        EventWriteOpServicesHttpQueryRead(__func__, mID, outResultData, result, static_cast<size_t>(available));
        return result;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark HTTP::HTTPQuery => ITimerDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void HTTP::HTTPQuery::onTimer(TimerPtr onTimer)
      {
        ZS_LOG_TRACE(log("on timer called"))
        cancel();
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
        HTTPQueryPtr pThis(make_shared<HTTPQuery>(make_private{}, outer, delegate, isPost, userAgent, url, postData, postDataLengthInBytes, postDataMimeType, timeout));
        pThis->mThisWeak = pThis;
        pThis->init();
        return pThis;
      }

      //-----------------------------------------------------------------------
      void HTTP::HTTPQuery::go(Windows::Web::Http::HttpClient ^client)
      {
        Time timeout = zsLib::now() + mTimeout;
        mTimer = Timer::create(mThisWeak.lock(), timeout);

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

        if (!client) {
          notifyComplete(HttpStatusCode::Gone);
          return;
        }

        HttpRequestMessage ^request = ref new HttpRequestMessage(mIsPost ? HttpMethod::Post : HttpMethod::Get, ref new Uri(ref new Platform::String(mURL.wstring().c_str())));

        if (mUserAgent.hasData()) {
          auto success = request->Headers->UserAgent->TryParseAdd(ref new Platform::String(mUserAgent.wstring().c_str()));
          if (!success) {
            ZS_LOG_WARNING(Detail, log("could not set user agent") + ZS_PARAMIZE(mUserAgent))
          }
        }
        if (mMimeType.hasData()) {
          request->Headers->Insert("Content-Type", ref new Platform::String(mMimeType.wstring().c_str()));
        }
        if (mPostData.SizeInBytes() > 0) {
          DataWriter ^writer = ref new DataWriter();
          writer->WriteBytes(Platform::ArrayReference<BYTE>(mPostData.BytePtr(), mPostData.SizeInBytes()));
          IBuffer ^buffer = writer->DetachBuffer();

          request->Content = ref new HttpBufferContent(buffer);
        }

        auto id = getID();
        auto thisWeak = mThisWeak;

        create_task(client->SendRequestAsync(request), mCancellationTokenSource.get_token())
          .then([id,thisWeak](task<HttpResponseMessage^> previousTask)
        {
          auto pThis = thisWeak.lock();

          try
          {
            ZS_LOG_TRACE(slogQuery(id, "request completed"))

              // Check if any previous task threw an exception.
            HttpResponseMessage ^response = previousTask.get();

            if (pThis) {
              pThis->notifyComplete(response);
            }

          } catch (const task_canceled&) {
            ZS_LOG_WARNING(Detail, slogQuery(id, "task cancelled"))
            if (pThis) {
              pThis->cancel();
            }
          } catch (Platform::Exception ^ex) {
            ZS_LOG_WARNING(Detail, slogQuery(id, "exception caught") + ZS_PARAM("error", String(ex->Message->Data())))
            if (pThis) {
              pThis->notifyComplete(HttpStatusCode::InternalServerError);
            }
          }
        }, task_continuation_context::use_arbitrary());
      }

      //-----------------------------------------------------------------------
      void HTTP::HTTPQuery::notifyComplete(HttpStatusCode result)
      {
        AutoRecursiveLock lock(*this);

        if (HttpStatusCode::None == mStatusCode) mStatusCode = result;

        if (ZS_IS_LOGGING(Debug)) {
          ZS_LOG_BASIC(log("----------------------------------HTTP COMPLETE--------------------------------"))
            bool successful = (((WORD)mStatusCode >= 200) && ((WORD)mStatusCode < 400));
            ZS_LOG_BASIC(log("INFO") + ZS_PARAM("success", successful))
            ZS_LOG_BASIC(log("INFO") + ZS_PARAM("HTTP status code", ((WORD)mStatusCode)))
            ZS_LOG_BASIC(log("INFO") + ZS_PARAM("HEADER SIZE", mHeader.MaxRetrievable()))
            ZS_LOG_BASIC(log("INFO") + ZS_PARAM("BODY SIZE", mBody.MaxRetrievable()))
            ZS_LOG_BASIC(log("----------------------------------HTTP COMPLETE--------------------------------"))
        }
        cancel();
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
      Log::Params HTTP::HTTPQuery::slogQuery(PUID id, const char *message)
      {
        ElementPtr objectEl = Element::create("HTTPQuery");
        IHelper::debugAppend(objectEl, "id", id);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      static void serializeHeaderCollection(
        ByteQueue &queue,
        IIterable<IKeyValuePair<Platform::String^, Platform::String^>^>^ headers
        )
      {
        if (nullptr == headers) return;

        typedef IKeyValuePair<Platform::String^, Platform::String^>^ Pair;

        Platform::String ^output = "";

        for (auto iter = headers->First(); iter->HasCurrent; iter->MoveNext())
        {
          Pair pair = iter->Current;
          output += pair->Key + ": " + pair->Value + "\r\n";
        }

        String tmp(output->Data());
        if (tmp.isEmpty()) return;

        queue.Put((BYTE *)(tmp.c_str()), tmp.length()*sizeof(char));
      }

      //-----------------------------------------------------------------------
      void HTTP::HTTPQuery::notifyComplete(Windows::Web::Http::HttpResponseMessage ^response)
      {
        if (nullptr == response) {
          ZS_LOG_WARNING(Detail, log("response returned was null"))
          notifyComplete(HttpStatusCode::PreconditionFailed);
          return;
        }

        auto pThis = mThisWeak.lock();

        if (response->Content) {
          create_task(response->Content->ReadAsBufferAsync(), mCancellationTokenSource.get_token())
            .then([pThis, response](task<IBuffer ^> previousTask) {
              try {
                // Check if any previous task threw an exception.
                auto buffer = previousTask.get();

                DataReader ^reader = DataReader::FromBuffer(buffer);

                SecureByteBlock temp(buffer->Length);
                reader->ReadBytes(Platform::ArrayReference<BYTE>(temp.BytePtr(), buffer->Length));

                AutoRecursiveLock lock(*pThis);
                serializeHeaderCollection(pThis->mHeader, response->Headers);
                serializeHeaderCollection(pThis->mHeader, response->Content->Headers);
                pThis->mBody.Put(temp.BytePtr(), temp.SizeInBytes());

                pThis->notifyComplete(response->StatusCode);
              } catch (const task_canceled&) {
                ZS_LOG_WARNING(Detail, pThis->log("task cancelled"))
                pThis->cancel();
              } catch (Platform::Exception^ ex) {
                ZS_LOG_WARNING(Detail, pThis->log("exception caught") + ZS_PARAM("error", String(ex->Message->Data())))
                pThis->notifyComplete(HttpStatusCode::InternalServerError);
              }
          }, task_continuation_context::use_arbitrary());
        } else {
          AutoRecursiveLock lock(*this);
          serializeHeaderCollection(mHeader, response->Headers);
          pThis->notifyComplete(response->StatusCode);
        }
      }
    }
  }
}

#endif //WINRT
