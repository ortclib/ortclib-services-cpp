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

#define ZS_DECLARE_TEMPLATE_GENERATE_IMPLEMENTATION

#include <ortc/services/internal/services_Reachability.h>

#include <ortc/services/IHelper.h>

#include <zsLib/IMessageQueueManager.h>
#include <zsLib/ISettings.h>
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
      // (helpers)
      //

      //-----------------------------------------------------------------------
      static void appendName(String &result, const char *name) noexcept
      {
        if (result.isEmpty()) {
          result = name;
          return;
        }

        result += String(",") + name;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // Reachability
      //

      //-----------------------------------------------------------------------
      Reachability::Reachability(const make_private &) noexcept :
        MessageQueueAssociator(IHelper::getServiceQueue()),
        SharedRecursiveLock(SharedRecursiveLock::create()),
        mSubscriptions(decltype(mSubscriptions)::create()),
        mLastState(InterfaceType_None)
      {
        ZS_LOG_DETAIL(log("created"))
      }

      //-----------------------------------------------------------------------
      Reachability::~Reachability() noexcept
      {
        mThisWeak.reset();
        ZS_LOG_DETAIL(log("destroyed"))
      }

      //-----------------------------------------------------------------------
      ReachabilityPtr Reachability::convert(IReachabilityPtr backgrounding) noexcept
      {
        return ZS_DYNAMIC_PTR_CAST(Reachability, backgrounding);
      }

      //-----------------------------------------------------------------------
      ReachabilityPtr Reachability::create() noexcept
      {
        ReachabilityPtr pThis(make_shared<Reachability>(make_private{}));
        pThis->mThisWeak = pThis;
        return pThis;
      }

      //-----------------------------------------------------------------------
      ReachabilityPtr Reachability::singleton() noexcept
      {
        AutoRecursiveLock lock(*IHelper::getGlobalLock());
        static SingletonLazySharedPtr<Reachability> singleton(IReachabilityFactory::singleton().createForReachability());
        ReachabilityPtr result = singleton.singleton();
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
      // Reachability => IReachability
      //

      //-----------------------------------------------------------------------
      ElementPtr Reachability::toDebug(ReachabilityPtr reachability) noexcept
      {
        if (!reachability) return ElementPtr();

        ReachabilityPtr pThis = Reachability::convert(reachability);
        return pThis->toDebug();
      }

      //-----------------------------------------------------------------------
      IReachabilitySubscriptionPtr Reachability::subscribe(IReachabilityDelegatePtr originalDelegate) noexcept
      {
        ZS_LOG_DETAIL(log("subscribing to backgrounding"))

        AutoRecursiveLock lock(*this);
        if (!originalDelegate) return IReachabilitySubscriptionPtr();

        IReachabilitySubscriptionPtr subscription = mSubscriptions.subscribe(originalDelegate);

        IReachabilityDelegatePtr delegate = mSubscriptions.delegate(subscription, true);

        if (delegate) {
          ReachabilityPtr pThis = mThisWeak.lock();

          if (InterfaceType_None != mLastState) {
            delegate->onReachabilityChanged(IReachabilitySubscriptionPtr(), mLastState);
          }

          // nothing to event at this point
        }

        return subscription;
      }

      //-----------------------------------------------------------------------
      void Reachability::notifyReachability(InterfaceTypes interfaceTypes) noexcept
      {
        ZS_LOG_DETAIL(log("notify reachability changed") + ZS_PARAM("reachability", toString(interfaceTypes)))

        AutoRecursiveLock lock(*this);

        if (mLastState == interfaceTypes) {
          ZS_LOG_DEBUG(log("network state did not actually change"))
          return;
        }

        mSubscriptions.delegate()->onReachabilityChanged(IReachabilitySubscriptionPtr(), mLastState);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // Reachability => (internal)
      //

      //-----------------------------------------------------------------------
      Log::Params Reachability::log(const char *message) const noexcept
      {
        ElementPtr objectEl = Element::create("services::Reachability");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params Reachability::slog(const char *message) noexcept
      {
        return Log::Params(message, "services::Reachability");
      }

      //-----------------------------------------------------------------------
      Log::Params Reachability::debug(const char *message) const noexcept
      {
        return Log::Params(message, toDebug());
      }

      //-----------------------------------------------------------------------
      ElementPtr Reachability::toDebug() const noexcept
      {
        AutoRecursiveLock lock(*this);

        ElementPtr resultEl = Element::create("services::Reachability");

        IHelper::debugAppend(resultEl, "id", mID);

        IHelper::debugAppend(resultEl, "subscriptions", mSubscriptions.size());

        IHelper::debugAppend(resultEl, "state", IReachability::toString(mLastState));

        return resultEl;
      }
      
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IReachabilityFactory
      //

      //-----------------------------------------------------------------------
      IReachabilityFactory &IReachabilityFactory::singleton() noexcept
      {
        return ReachabilityFactory::singleton();
      }

      //-----------------------------------------------------------------------
      ReachabilityPtr IReachabilityFactory::createForReachability() noexcept
      {
        if (this) {}
        return Reachability::create();
      }

    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //
    // IReachability
    //

    //-------------------------------------------------------------------------
    String IReachability::toString(InterfaceTypes interfaceTypes) noexcept
    {
      if (InterfaceType_None == interfaceTypes) return "None";

      static InterfaceTypes types[] = {
        InterfaceType_LAN,
        InterfaceType_WLAN,
        InterfaceType_WWAN,
        InterfaceType_VPN,
        InterfaceType_PAN,
        InterfaceType_Other,

        InterfaceType_None
      };

      String result;

      for (int index = 0; InterfaceType_None != types[index]; ++index)
      {
        switch ((InterfaceTypes)(types[index] & interfaceTypes)) {
          case InterfaceType_None:  break;

          case InterfaceType_LAN:   internal::appendName(result, "LAN"); break;
          case InterfaceType_WLAN:  internal::appendName(result, "WLAN"); break;
          case InterfaceType_WWAN:  internal::appendName(result, "WWAN"); break;
          case InterfaceType_VPN:   internal::appendName(result, "VPN"); break;
          case InterfaceType_PAN:   internal::appendName(result, "PAN"); break;
          case InterfaceType_Other: internal::appendName(result, "Other"); break;
        }
      }

      return result;
    }

    //-------------------------------------------------------------------------
    ElementPtr IReachability::toDebug() noexcept
    {
      return internal::Reachability::toDebug(internal::Reachability::singleton());
    }

    //-------------------------------------------------------------------------
    IReachabilitySubscriptionPtr IReachability::subscribe(IReachabilityDelegatePtr delegate) noexcept
    {
      internal::ReachabilityPtr singleton = internal::Reachability::singleton();
      if (!singleton) return IReachabilitySubscriptionPtr();
      return singleton->subscribe(delegate);
    }

    //-------------------------------------------------------------------------
    void IReachability::notifyReachability(InterfaceTypes interfaceTypes) noexcept
    {
      internal::ReachabilityPtr singleton = internal::Reachability::singleton();
      if (!singleton) return;
      return singleton->notifyReachability(interfaceTypes);
    }

  }
}

