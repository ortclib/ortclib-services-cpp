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

#include <ortc/services/internal/services_Cache.h>
#include <ortc/services/internal/services.events.h>

#include <ortc/services/IHelper.h>

#include <zsLib/XML.h>

namespace ortc { namespace services { ZS_DECLARE_SUBSYSTEM(org_ortc_services) } }

namespace ortc
{
  namespace services
  {
    namespace internal
    {
      using services::IHelper;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // Cache
      //

      //-----------------------------------------------------------------------
      Cache::Cache(const make_private &) noexcept
      {
        ZS_LOG_DETAIL(log("created"));
      }

      //-----------------------------------------------------------------------
      Cache::~Cache() noexcept
      {
        mThisWeak.reset();
        ZS_LOG_DETAIL(log("destroyed"));
      }

      //-----------------------------------------------------------------------
      CachePtr Cache::convert(ICachePtr cache) noexcept
      {
        return ZS_DYNAMIC_PTR_CAST(Cache, cache);
      }

      //-----------------------------------------------------------------------
      CachePtr Cache::create() noexcept
      {
        CachePtr pThis(make_shared<Cache>(make_private{}));
        pThis->mThisWeak = pThis;
        return pThis;
      }

      //-----------------------------------------------------------------------
      CachePtr Cache::singleton() noexcept
      {
        AutoRecursiveLock lock(*IHelper::getGlobalLock());
        static SingletonLazySharedPtr<Cache> singleton(Cache::create());
        CachePtr result = singleton.singleton();
        if (!result) {
          ZS_LOG_WARNING(Detail, slog("singleton gone"))
        }
        return result;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // Cache => ICache
      //

      //-----------------------------------------------------------------------
      void Cache::setup(ICacheDelegatePtr delegate) noexcept
      {
        AutoRecursiveLock lock(mLock);
        mDelegate = delegate;

        ZS_LOG_DEBUG(log("setup called") + ZS_PARAM("has delegate", (bool)delegate))
      }

      //-----------------------------------------------------------------------
      String Cache::fetch(const char *cookieNamePath) const noexcept
      {
        if (!cookieNamePath) return String();

        ICacheDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;
        }

        if (!delegate) {
          ZS_LOG_WARNING(Debug, log("no cache installed (thus cannot fetch cookie)") + ZS_PARAM("cookie name", cookieNamePath));
          ZS_EVENTING_2(x, w, Debug, ServicesCacheFetchNoDelegate, os, Cache, Info, puid, id, mID, string, cookieNamePath, cookieNamePath);
          return String();
        }

        auto result = delegate->fetch(cookieNamePath);
        ZS_EVENTING_3(x, i, Debug, ServicesCacheFetch, os, Cache, Info, puid, id, mID, string, cookieNamePath, cookieNamePath, string, result, result);
        return result;
      }

      //-----------------------------------------------------------------------
      void Cache::store(
                        const char *cookieNamePath,
                        Time expires,
                        const char *str
                        ) noexcept
      {
        ZS_EVENTING_4(
                      x, i, Debug, ServicesCacheStore, os, Cache, Info,
                      puid, id, mID,
                      string, cookieNamePath, cookieNamePath,
                      duration, expires, zsLib::timeSinceEpoch<Seconds>(expires).count(),
                      string, value, str
                      );

        if (!cookieNamePath) return;
        if (!str) {
          clear(cookieNamePath);
          return;
        }
        if (!(*str)) {
          clear(cookieNamePath);
          return;
        }

        ICacheDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;
        }

        if (!delegate) {
          ZS_LOG_WARNING(Debug, log("no cache installed (thus cannot store cookie)") + ZS_PARAM("cookie name", cookieNamePath) + ZS_PARAM("expires", expires) + ZS_PARAM("value", str))
          return;
        }

        delegate->store(cookieNamePath, expires, str);
      }

      //-----------------------------------------------------------------------
      void Cache::clear(const char *cookieNamePath) noexcept
      {
        ZS_EVENTING_2(x, i, Debug, ServicesCacheClear, os, Cache, Info, puid, id, mID, string, cookieNamePath, cookieNamePath);

        if (!cookieNamePath) return;

        ICacheDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;
        }

        if (!delegate) {
          ZS_LOG_WARNING(Debug, log("no cache installed (thus cannot clear cookie)") + ZS_PARAM("cookie name", cookieNamePath))
          return;
        }
        delegate->clear(cookieNamePath);
      }
      
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // Cache => (internal)
      //

      //-----------------------------------------------------------------------
      Log::Params Cache::log(const char *message) const noexcept
      {
        ElementPtr objectEl = Element::create("services::Cache");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params Cache::slog(const char *message) noexcept
      {
        return Log::Params(message, "services::Cache");
      }

    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //
    // ICache
    //

    //-------------------------------------------------------------------------
    void ICache::setup(ICacheDelegatePtr delegate) noexcept
    {
      internal::CachePtr singleton = internal::Cache::singleton();
      if (!singleton) return;
      singleton->setup(delegate);
    }

    //-------------------------------------------------------------------------
    String ICache::fetch(const char *cookieNamePath) noexcept
    {
      internal::CachePtr singleton = internal::Cache::singleton();
      if (!singleton) return String();
      return singleton->fetch(cookieNamePath);
    }

    //-------------------------------------------------------------------------
    void ICache::store(
                      const char *cookieNamePath,
                      Time expires,
                      const char *str
                      ) noexcept
    {
      internal::CachePtr singleton = internal::Cache::singleton();
      if (!singleton) return;
      singleton->store(cookieNamePath, expires, str);
    }

    //-------------------------------------------------------------------------
    void ICache::clear(const char *cookieNamePath) noexcept
    {
      internal::CachePtr singleton = internal::Cache::singleton();
      if (!singleton) return;
      singleton->clear(cookieNamePath);
    }

  }
}
