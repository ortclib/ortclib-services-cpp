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

#include <openpeer/services/internal/services_Backgrounding.h>

#include <openpeer/services/IHelper.h>

#include <zsLib/XML.h>

namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services) } }

namespace openpeer
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
      #pragma mark
      #pragma mark (helpers)
      #pragma mark

      //-----------------------------------------------------------------------
      IBackgroundingNotifierPtr getBackgroundingNotifier(IBackgroundingNotifierPtr notifier)
      {
        return Backgrounding::getBackgroundingNotifier(notifier);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Backgrounding
      #pragma mark

      //-----------------------------------------------------------------------
      Backgrounding::Backgrounding() :
        mCurrentBackgroundingID(zsLib::createPUID()),
        mTotalWaiting(0),
        mTotalNotifiersCreated(0)
      {
        ZS_LOG_DETAIL(log("created"))
      }

      //-----------------------------------------------------------------------
      Backgrounding::~Backgrounding()
      {
        mThisWeak.reset();
        ZS_LOG_DETAIL(log("destroyed"))
      }

      //-----------------------------------------------------------------------
      BackgroundingPtr Backgrounding::convert(IBackgroundingPtr backgrounding)
      {
        return dynamic_pointer_cast<Backgrounding>(backgrounding);
      }

      //-----------------------------------------------------------------------
      BackgroundingPtr Backgrounding::create()
      {
        BackgroundingPtr pThis(new Backgrounding());
        pThis->mThisWeak = pThis;
        return pThis;
      }

      //-----------------------------------------------------------------------
      BackgroundingPtr Backgrounding::singleton()
      {
        static SingletonLazySharedPtr<Backgrounding> singleton(IBackgroundingFactory::singleton().createForBackgrounding());
        BackgroundingPtr result = singleton.singleton();
        if (!result) {
          ZS_LOG_WARNING(Detail, slog("singleton gone"))
        }
        return result;
      }

      //-----------------------------------------------------------------------
      IBackgroundingNotifierPtr Backgrounding::getBackgroundingNotifier(IBackgroundingNotifierPtr inNotifier)
      {
        ExchangedNotifierPtr exchange = dynamic_pointer_cast<ExchangedNotifier>(inNotifier);

        BackgroundingPtr pThis = exchange->getOuter();

        {
          AutoRecursiveLock lock(pThis->getLock());
          ++(pThis->mTotalNotifiersCreated);
        }

        return Notifier::create(exchange);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Backgrounding => IBackgrounding
      #pragma mark

      //-----------------------------------------------------------------------
      ElementPtr Backgrounding::toDebug(BackgroundingPtr backgrounding)
      {
        if (!backgrounding) return ElementPtr();

        BackgroundingPtr pThis = Backgrounding::convert(backgrounding);
        return pThis->toDebug();
      }

      //-----------------------------------------------------------------------
      IBackgroundingSubscriptionPtr Backgrounding::subscribe(IBackgroundingDelegatePtr originalDelegate)
      {
        ZS_LOG_DETAIL(log("subscribing to backgrounding"))

        AutoRecursiveLock lock(getLock());
        if (!originalDelegate) return IBackgroundingSubscriptionPtr();

        IBackgroundingSubscriptionPtr subscription = mSubscriptions.subscribe(originalDelegate);

        // IBackgroundingDelegatePtr delegate = mSubscriptions.delegate(subscription);

        //if (delegate) {
          // BackgroundingPtr pThis = mThisWeak.lock();

          // nothing to event at this point
        //}

        return subscription;
      }

      //-----------------------------------------------------------------------
      IBackgroundingQueryPtr Backgrounding::notifyGoingToBackground(IBackgroundingCompletionDelegatePtr readyDelegate)
      {
        ZS_LOG_DETAIL(log("going to background") + ZS_PARAM("delegate", (bool)readyDelegate))

        AutoRecursiveLock lock(getLock());

        if (mNotifyWhenReady) {
          ZS_LOG_DETAIL(log("notifying obsolete backgrounding completion delegate that it is ready") + ZS_PARAM("obsolete backgrounding id", mCurrentBackgroundingID))
          mNotifyWhenReady->onBackgroundingReady(mQuery);
          mNotifyWhenReady.reset();
          mQuery.reset();
        }

        if (readyDelegate) {
          mNotifyWhenReady = IBackgroundingCompletionDelegateProxy::createWeak(readyDelegate);
        }

        mCurrentBackgroundingID = zsLib::createPUID();
        mTotalWaiting = mSubscriptions.size();

        QueryPtr query = mQuery = Query::create(
                                                mThisWeak.lock(),
                                                mCurrentBackgroundingID
                                                );

        mTotalNotifiersCreated = 0;

        if (0 == mTotalWaiting) {
          ZS_LOG_DETAIL(log("no subscribers to backgrounding thus backgrounding completed immediately") + ZS_PARAM("backgrounding id", mCurrentBackgroundingID))

          if (mNotifyWhenReady) {
            mNotifyWhenReady->onBackgroundingReady(mQuery);
            mNotifyWhenReady.reset();
            mQuery.reset();
          }
        } else {
          ExchangedNotifierPtr exchangeNotifier = ExchangedNotifier::create(
                                                                            mThisWeak.lock(),
                                                                            mCurrentBackgroundingID
                                                                            );

          mSubscriptions.delegate()->onBackgroundingGoingToBackground(exchangeNotifier);

          // race condition where subscriber could cancel backgrounding subscription between time size was fetched and when notifications were sent
          mTotalWaiting = mTotalNotifiersCreated;

          ZS_LOG_DETAIL(log("notified going to background") + ZS_PARAM("backgrounding id", mCurrentBackgroundingID) + ZS_PARAM("total", mTotalWaiting))
        }

        return query;
      }

      //-----------------------------------------------------------------------
      void Backgrounding::notifyGoingToBackgroundNow()
      {
        ZS_LOG_DETAIL(log("going to background now"))

        AutoRecursiveLock lock(getLock());
        mSubscriptions.delegate()->onBackgroundingGoingToBackgroundNow();
      }

      //-----------------------------------------------------------------------
      void Backgrounding::notifyReturningFromBackground()
      {
        ZS_LOG_DETAIL(log("returning from background"))

        AutoRecursiveLock lock(getLock());
        mSubscriptions.delegate()->onBackgroundingReturningFromBackground();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Backgrounding => friend Notifier
      #pragma mark

      //-----------------------------------------------------------------------
      void Backgrounding::notifyReady(PUID backgroundingID)
      {
        ZS_LOG_DETAIL(log("received notification that notifier is complete") + ZS_PARAM("backgrounding id", backgroundingID))

        AutoRecursiveLock lock(getLock());

        if (backgroundingID != mCurrentBackgroundingID) {
          ZS_LOG_WARNING(Debug, log("notification of backgrounding ready for obsolete backgrounding session"))
          return;
        }

        ZS_THROW_BAD_STATE_IF(0 == mTotalWaiting)

        --mTotalWaiting;
        --mTotalNotifiersCreated;

        ZS_LOG_DETAIL(log("total waiting background notifiers changed") + ZS_PARAM("current backgrounding id", mCurrentBackgroundingID) + ZS_PARAM("waiting", mTotalWaiting))

        if ((mNotifyWhenReady) &&
            (0 == mTotalWaiting)) {
          ZS_LOG_DETAIL(log("notifying backgrounding completion delegate that it is ready"))
          mNotifyWhenReady->onBackgroundingReady(mQuery);
          mNotifyWhenReady.reset();
          mQuery.reset();
        }
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Backgrounding => friend Query
      #pragma mark

      //-----------------------------------------------------------------------
      size_t Backgrounding::totalPending(PUID backgroundingID) const
      {
        AutoRecursiveLock lock(getLock());
        if (backgroundingID != mCurrentBackgroundingID) {
          ZS_LOG_WARNING(Debug, log("obsolete backgrounding query is always ready thus total waiting is always \"0\""))
          return 0;
        }

        return mTotalWaiting;
      }
      
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Backgrounding => (internal)
      #pragma mark

      //-----------------------------------------------------------------------
      Log::Params Backgrounding::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("services::Backgrounding");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params Backgrounding::slog(const char *message)
      {
        return Log::Params(message, "services::Backgrounding");
      }

      //-----------------------------------------------------------------------
      Log::Params Backgrounding::debug(const char *message) const
      {
        return Log::Params(message, toDebug());
      }

      //-----------------------------------------------------------------------
      ElementPtr Backgrounding::toDebug() const
      {
        AutoRecursiveLock lock(getLock());

        ElementPtr resultEl = Element::create("services::Backgrounding");

        IHelper::debugAppend(resultEl, "id", mID);

        IHelper::debugAppend(resultEl, "subscriptions", mSubscriptions.size());

        IHelper::debugAppend(resultEl, "current backgrounding id", mCurrentBackgroundingID);
        IHelper::debugAppend(resultEl, "total waiting", mTotalWaiting);
        IHelper::debugAppend(resultEl, "notification delegate", (bool)mNotifyWhenReady);
        IHelper::debugAppend(resultEl, "query", (bool)mQuery);

        IHelper::debugAppend(resultEl, "total notifiers created", mTotalNotifiersCreated);

        return resultEl;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Backgrounding::Notifier
      #pragma mark

      //-----------------------------------------------------------------------
      Backgrounding::Notifier::Notifier(ExchangedNotifierPtr notifier) :
        mBackgroundingID(notifier->getID())
      {
        mOuter = notifier->getOuter();
      }

      //-----------------------------------------------------------------------
      Backgrounding::Notifier::~Notifier()
      {
        if (mNotified) return;

        mOuter->notifyReady(mBackgroundingID);
      }

      //-----------------------------------------------------------------------
      Backgrounding::NotifierPtr Backgrounding::Notifier::create(ExchangedNotifierPtr notifier)
      {
        return NotifierPtr(new Notifier(notifier));
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Backgrounding::Notifier => IBackgroundingNotifier
      #pragma mark

      //-----------------------------------------------------------------------
      void Backgrounding::Notifier::ready()
      {
        AutoRecursiveLock lock(mOuter->getLock());

        if (mNotified) return;

        get(mNotified) = true;

        mOuter->notifyReady(mBackgroundingID);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Backgrounding::ExchangedNotifier
      #pragma mark

      //-----------------------------------------------------------------------
      Backgrounding::ExchangedNotifierPtr Backgrounding::ExchangedNotifier::create(
                                                                                   BackgroundingPtr backgrounding,
                                                                                   PUID backgroundingID
                                                                                   )
      {
        return ExchangedNotifierPtr(new ExchangedNotifier(backgrounding, backgroundingID));
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Backgrounding::Query
      #pragma mark

      //-----------------------------------------------------------------------
      Backgrounding::QueryPtr Backgrounding::Query::create(
                                                           BackgroundingPtr outer,
                                                           PUID backgroundingID
                                                           )
      {
        return QueryPtr(new Query(outer, backgroundingID));
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Backgrounding::Query => IBackgroundingQuery
      #pragma mark

      //-----------------------------------------------------------------------
      bool Backgrounding::Query::isReady() const
      {
        BackgroundingPtr outer = mOuter.lock();
        if (!outer) return true;

        AutoRecursiveLock lock(outer->getLock());

        return 0 == outer->totalPending(mBackgroundingID);
      }

      //-----------------------------------------------------------------------
      size_t Backgrounding::Query::totalBackgroundingSubscribersStillPending() const
      {
        BackgroundingPtr outer = mOuter.lock();
        if (!outer) return 0;

        AutoRecursiveLock lock(outer->getLock());

        return outer->totalPending(mBackgroundingID);
      }
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IBackgrounding
    #pragma mark

    //-------------------------------------------------------------------------
    ElementPtr IBackgrounding::toDebug()
    {
      return internal::Backgrounding::toDebug(internal::Backgrounding::singleton());
    }

    //-------------------------------------------------------------------------
    IBackgroundingSubscriptionPtr IBackgrounding::subscribe(IBackgroundingDelegatePtr delegate)
    {
      internal::BackgroundingPtr singleton = internal::Backgrounding::singleton();
      if (!singleton) return IBackgroundingSubscriptionPtr();
      return singleton->subscribe(delegate);
    }

    //-------------------------------------------------------------------------
    IBackgroundingQueryPtr IBackgrounding::notifyGoingToBackground(IBackgroundingCompletionDelegatePtr readyDelegate)
    {
      internal::BackgroundingPtr singleton = internal::Backgrounding::singleton();
      if (!singleton) return IBackgroundingQueryPtr();
      return singleton->notifyGoingToBackground(readyDelegate);
    }

    //-------------------------------------------------------------------------
    void IBackgrounding::notifyGoingToBackgroundNow()
    {
      internal::BackgroundingPtr singleton = internal::Backgrounding::singleton();
      if (!singleton) return;
      return singleton->notifyGoingToBackgroundNow();
    }

    //-------------------------------------------------------------------------
    void IBackgrounding::notifyReturningFromBackground()
    {
      internal::BackgroundingPtr singleton = internal::Backgrounding::singleton();
      if (!singleton) return;
      return singleton->notifyReturningFromBackground();
    }
  }
}

