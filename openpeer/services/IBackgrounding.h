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

#pragma once

#include <openpeer/services/types.h>

namespace openpeer
{
  namespace services
  {
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IBackgrounding
    #pragma mark

    interaction IBackgrounding
    {
      //-----------------------------------------------------------------------
      // PURPOSE: returns a debug element containing internal object state
      static ElementPtr toDebug();

      //-----------------------------------------------------------------------
      // PURPOSE: Subscribe to the backgrounding state
      // PARAMS:  phase - Each subscription is assigned a phase number and
      //                  more than one subscriber can share the same phase.
      //                  Phases are done in order (lowest to highest) where
      //                  every subscriber must complete backgrounding before
      //                  the next phase of backgrounding is activiated.
      static IBackgroundingSubscriptionPtr subscribe(
                                                     IBackgroundingDelegatePtr delegate,
                                                     ULONG phase
                                                     );

      //-----------------------------------------------------------------------
      // PURPOSE: Notifies the application is about to go into the background
      // PARAMS:  readyDelegate - pass in a delegate which will get a callback
      //                          when all backgrounding subscribers are ready
      //                          to go into the background
      // RETURNS: a query interface about the current backgrounding state
      static IBackgroundingQueryPtr notifyGoingToBackground(
                                                            IBackgroundingCompletionDelegatePtr readyDelegate = IBackgroundingCompletionDelegatePtr()
                                                            );

      //-----------------------------------------------------------------------
      // PURPOSE: Notifies the application is goinging to the background
      //          immediately
      static void notifyGoingToBackgroundNow();

      //-----------------------------------------------------------------------
      // PURPOSE: Notifies the application is returning from to the background
      static void notifyReturningFromBackground();

      virtual ~IBackgrounding() {}  // needed to ensure virtual table is created in order to use dynamic cast
    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IBackgroundingDelegate
    #pragma mark

    interaction IBackgroundingDelegate
    {
      //-----------------------------------------------------------------------
      // PURPOSE: This is notification from the system that it's going into the
      //          background. If the subscriber needs some time to do it's work
      //          it can keep a reference to the "notifier" object and only
      //          release the object when the backgrounding is ready.
      virtual void onBackgroundingGoingToBackground(
                                                    IBackgroundingSubscriptionPtr subscription,
                                                    IBackgroundingNotifierPtr notifier
                                                    ) = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: This notification tells the subscriber it must abandon its
      //          backgrounding efforts as it must go to the background
      //          immediately.
      virtual void onBackgroundingGoingToBackgroundNow(
                                                       IBackgroundingSubscriptionPtr subscription
                                                       ) = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: This notification tells the subscriber it is returning from
      //          the background.
      virtual void onBackgroundingReturningFromBackground(
                                                          IBackgroundingSubscriptionPtr subscription
                                                          ) = 0;
    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IBackgroundingQuery
    #pragma mark

    interaction IBackgroundingQuery
    {
      virtual PUID getID() const = 0;

      virtual bool isReady() const = 0;

      virtual size_t totalBackgroundingSubscribersStillPending() const = 0;
    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IBackgroundingCompletionDelegate
    #pragma mark

    interaction IBackgroundingCompletionDelegate
    {
      virtual void onBackgroundingReady(IBackgroundingQueryPtr query) = 0;
    };
    
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IBackgroundingSubscription
    #pragma mark

    interaction IBackgroundingSubscription
    {
      virtual PUID getID() const = 0;

      virtual void cancel() = 0;

      virtual void background() = 0;
    };
    
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IBackgroundingNotifier
    #pragma mark

    interaction IBackgroundingNotifier
    {
      virtual PUID getID() const = 0;

      virtual void ready() = 0;
    };

  }
}

ZS_DECLARE_PROXY_BEGIN(openpeer::services::IBackgroundingDelegate)
ZS_DECLARE_PROXY_TYPEDEF(openpeer::services::IBackgroundingSubscriptionPtr, IBackgroundingSubscriptionPtr)
ZS_DECLARE_PROXY_TYPEDEF(openpeer::services::IBackgroundingNotifierPtr, IBackgroundingNotifierPtr)
ZS_DECLARE_PROXY_METHOD_2(onBackgroundingGoingToBackground, IBackgroundingSubscriptionPtr, IBackgroundingNotifierPtr)
ZS_DECLARE_PROXY_METHOD_1(onBackgroundingGoingToBackgroundNow, IBackgroundingSubscriptionPtr)
ZS_DECLARE_PROXY_METHOD_1(onBackgroundingReturningFromBackground, IBackgroundingSubscriptionPtr)
ZS_DECLARE_PROXY_END()

ZS_DECLARE_PROXY_SUBSCRIPTIONS_BEGIN(openpeer::services::IBackgroundingDelegate, openpeer::services::IBackgroundingSubscription)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(openpeer::services::IBackgroundingSubscriptionPtr, IBackgroundingSubscriptionPtr)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(openpeer::services::IBackgroundingNotifierPtr, IBackgroundingNotifierPtr)

  // notify each subscription of their backgrounding object
  virtual void onBackgroundingGoingToBackground(
                                                IBackgroundingSubscriptionPtr ignoreSubscription, // will be bogus
                                                IBackgroundingNotifierPtr notifier
                                                )
  {
    ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_TYPES_AND_VALUES(SubscriptionsMap, subscriptions, SubscriptionsMapKeyType, DelegateTypePtr, DelegateTypeProxy)
    for (SubscriptionsMap::iterator iter_doNotUse = subscriptions.begin(); iter_doNotUse != subscriptions.end(); )
    {
      SubscriptionsMap::iterator current = iter_doNotUse; ++iter_doNotUse;
      ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_ITERATOR_VALUES(current, key, subscriptionWeak, delegate)
      try {
        IBackgroundingSubscriptionPtr subscription = subscriptionWeak.lock();
        if (subscription) {
          delegate->onBackgroundingGoingToBackground(subscription, openpeer::services::internal::getBackgroundingNotifier(notifier));
        } else {
          ZS_INTERNAL_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_ERASE_KEY(key)
        }
      } catch(DelegateTypeProxy::Exceptions::DelegateGone &) {
        ZS_INTERNAL_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_ERASE_KEY(key)
      }
    }
  }

ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_1(onBackgroundingGoingToBackgroundNow, IBackgroundingSubscriptionPtr)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_1(onBackgroundingReturningFromBackground, IBackgroundingSubscriptionPtr)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_END()

ZS_DECLARE_PROXY_BEGIN(openpeer::services::IBackgroundingCompletionDelegate)
ZS_DECLARE_PROXY_TYPEDEF(openpeer::services::IBackgroundingQueryPtr, IBackgroundingQueryPtr)
ZS_DECLARE_PROXY_METHOD_1(onBackgroundingReady, IBackgroundingQueryPtr)
ZS_DECLARE_PROXY_END()

