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

#include <openpeer/services/internal/services_Backgrounding.h>
#include <openpeer/services/internal/services_MessageQueueManager.h>

#include <openpeer/services/IHelper.h>
#include <openpeer/services/ISettings.h>

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
        MessageQueueAssociator(IHelper::getServiceQueue()),
        SharedRecursiveLock(SharedRecursiveLock::create()),
        mCurrentBackgroundingID(zsLib::createPUID()),
        mLargestPhase(0),
        mTotalWaiting(0),
        mCurrentPhase(0),
        mTotalNotifiersCreated(0)
      {
        ZS_LOG_DETAIL(log("created"))
        IHelper::setTimerThreadPriority();
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

        ZS_DECLARE_CLASS_PTR(GracefulAlert)

        class GracefulAlert
        {
        public:
          GracefulAlert(BackgroundingPtr singleton) : mSingleton(singleton) {}
          ~GracefulAlert() {mSingleton->notifyApplicationWillQuit();}

        protected:
          BackgroundingPtr mSingleton;
        };

        static SingletonLazySharedPtr<GracefulAlert> alertSingleton(GracefulAlertPtr(new GracefulAlert(result)));

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
          AutoRecursiveLock lock(*pThis);
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
      IBackgroundingSubscriptionPtr Backgrounding::subscribe(
                                                             IBackgroundingDelegatePtr originalDelegate,
                                                             ULONG phase
                                                             )
      {
        ZS_LOG_DETAIL(log("subscribing to backgrounding"))

        AutoRecursiveLock lock(*this);
        if (!originalDelegate) return IBackgroundingSubscriptionPtr();

        if (phase > mLargestPhase) {
          mLargestPhase = phase;
        }

        UseBackgroundingDelegateSubscriptionsPtr subscriptions;

        PhaseSubscriptionMap::iterator found = mPhaseSubscriptions.find(phase);
        if (found == mPhaseSubscriptions.end()) {
          ZS_LOG_DEBUG(log("added new phase to backgrounding for background subscriber") + ZS_PARAM("phase", phase))
          subscriptions = UseBackgroundingDelegateSubscriptionsPtr(new UseBackgroundingDelegateSubscriptions);
          mPhaseSubscriptions[phase] = subscriptions;
        } else {
          ZS_LOG_DEBUG(log("adding background subscriber to existing phase") + ZS_PARAM("phase", phase))
          subscriptions = (*found).second;
        }

        IBackgroundingSubscriptionPtr subscription = subscriptions->subscribe(originalDelegate);

        // IBackgroundingDelegatePtr delegate = mSubscriptions.delegate(subscription, true);

        //if (delegate) {
          // BackgroundingPtr pThis = mThisWeak.lock();

          // nothing to event at this point
        //}

        return subscription;
      }

      //-----------------------------------------------------------------------
      IBackgroundingQueryPtr Backgrounding::notifyGoingToBackground(IBackgroundingCompletionDelegatePtr readyDelegate)
      {
        ZS_LOG_DETAIL(log("system going to background") + ZS_PARAM("delegate", (bool)readyDelegate))

        AutoRecursiveLock lock(*this);

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
        mCurrentPhase = 0;

        QueryPtr query = mQuery = Query::create(
                                                mThisWeak.lock(),
                                                mCurrentBackgroundingID
                                                );

        performGoingToBackground();

        return query;
      }

      //-----------------------------------------------------------------------
      void Backgrounding::notifyGoingToBackgroundNow()
      {
        ZS_LOG_DETAIL(log("system going to background now"))

        AutoRecursiveLock lock(*this);

        Phase current = 0;
        size_t total = 0;

        do
        {
          total = getNextPhase(current);
          if (0 == total) break;

          PhaseSubscriptionMap::iterator found = mPhaseSubscriptions.find(current);
          ZS_THROW_BAD_STATE_IF(found == mPhaseSubscriptions.end())

          ZS_LOG_DEBUG(log("notifying phase going to background") + ZS_PARAM("phase", current) + ZS_PARAM("total", total))

          UseBackgroundingDelegateSubscriptionsPtr &subscriptions = (*found).second;
          subscriptions->delegate()->onBackgroundingGoingToBackgroundNow(IBackgroundingSubscriptionPtr());

          ++current;
        } while (true);

        ZS_LOG_DEBUG(log("all phases told to go to background now"))
      }

      //-----------------------------------------------------------------------
      void Backgrounding::notifyReturningFromBackground()
      {
        ZS_LOG_DETAIL(log("system returning from background"))

        AutoRecursiveLock lock(*this);

        mCurrentBackgroundingID = 0;
        mTotalWaiting = 0;
        mTotalNotifiersCreated = 0;

        if (mNotifyWhenReady) {
          ZS_LOG_DETAIL(log("notifying obsolete backgrounding completion delegate that it is ready") + ZS_PARAM("obsolete backgrounding id", mCurrentBackgroundingID))
          mNotifyWhenReady->onBackgroundingReady(mQuery);
          mNotifyWhenReady.reset();
          mQuery.reset();
        }

        Phase current = mLargestPhase;
        size_t total = 0;

        do
        {
          total = getPreviousPhase(current);
          if (0 == total) break;

          PhaseSubscriptionMap::iterator found = mPhaseSubscriptions.find(current);
          ZS_THROW_BAD_STATE_IF(found == mPhaseSubscriptions.end())

          ZS_LOG_DEBUG(log("notifying phase returning from background") + ZS_PARAM("phase", current) + ZS_PARAM("total", total))

          UseBackgroundingDelegateSubscriptionsPtr &subscriptions = (*found).second;
          subscriptions->delegate()->onBackgroundingReturningFromBackground(IBackgroundingSubscriptionPtr());

          if (current < 1) break;

          --current;
        } while (true);

        ZS_LOG_DEBUG(log("all phases told that application is returning from background"))
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Backgrounding => ITimerDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void Backgrounding::onTimer(TimerPtr timer)
      {
        ZS_LOG_DEBUG(log("on timer") + ZS_PARAM("timer", timer->getID()))

        AutoRecursiveLock lock(*this);

        if (timer != mTimer) {
          ZS_LOG_WARNING(Debug, log("notified about obsolete timer") + ZS_PARAM("timer", timer->getID()))
          return;
        }

        mTimer->cancel();
        mTimer.reset();

        if (!mQuery) {
          ZS_LOG_WARNING(Detail, log("phase timer is too late as there's no outstanding backgrounding query"))
          return;
        }

        Phase current = mCurrentPhase;

        size_t total = getNextPhase(current);

        if ((0 == total) ||
            (current != mCurrentPhase) ||
            (0 == mTotalWaiting)) {
          ZS_LOG_WARNING(Detail, log("phase timer does not need to notify the current phase that it's going to sleep now") + ZS_PARAM("total", total) + toDebug())
          return;
        }

        PhaseSubscriptionMap::iterator found = mPhaseSubscriptions.find(current);
        ZS_THROW_BAD_STATE_IF(found == mPhaseSubscriptions.end())

        UseBackgroundingDelegateSubscriptionsPtr subscriptions = (*found).second;

        ZS_LOG_DETAIL(log("phase did not complete before timeout thus going to background now") + toDebug())

        subscriptions->delegate()->onBackgroundingGoingToBackgroundNow(IBackgroundingSubscriptionPtr());

        // current phase is now too late and must continue to next phase
        ++mCurrentPhase;

        performGoingToBackground();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Backgrounding => friend Notifier
      #pragma mark

      //-----------------------------------------------------------------------
      void Backgrounding::notifyReady(
                                      PUID backgroundingID,
                                      Phase phase
                                      )
      {
        ZS_LOG_DETAIL(log("received notification that notifier is complete") + ZS_PARAM("backgrounding id", backgroundingID) + ZS_PARAM("phase", phase))

        AutoRecursiveLock lock(*this);

        if (backgroundingID != mCurrentBackgroundingID) {
          ZS_LOG_WARNING(Debug, log("notification of backgrounding ready for obsolete backgrounding session"))
          return;
        }

        if (phase != mCurrentPhase) {
          ZS_LOG_WARNING(Debug, log("notification of backgrounding ready for obsolete phase"))
          return;
        }

        ZS_THROW_BAD_STATE_IF(0 == mTotalWaiting)

        --mTotalWaiting;
        --mTotalNotifiersCreated;

        ZS_LOG_DETAIL(log("total waiting background notifiers changed") + ZS_PARAM("current backgrounding id", mCurrentBackgroundingID) + ZS_PARAM("waiting", mTotalWaiting))

        if ((mNotifyWhenReady) &&
            (0 == mTotalWaiting)) {

          ZS_LOG_DEBUG(log("current phase is now complete thus moving to next phase") + ZS_PARAM("phase", mCurrentPhase))

          ++mCurrentPhase;
          performGoingToBackground();
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
        AutoRecursiveLock lock(*this);
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
      #pragma mark Backgrounding => friend Query
      #pragma mark

      //-----------------------------------------------------------------------
      void Backgrounding::notifyApplicationWillQuit()
      {
        ZS_LOG_DETAIL(log("application will quit notification"))

        // scope: tell all phases that application will quit
        {
          AutoRecursiveLock lock(*this);

          Phase current = 0;
          size_t total = 0;

          do
          {
            total = getNextPhase(current);
            if (0 == total) break;

            PhaseSubscriptionMap::iterator found = mPhaseSubscriptions.find(current);
            ZS_THROW_BAD_STATE_IF(found == mPhaseSubscriptions.end())

            ZS_LOG_DEBUG(log("notifying phase of application quit") + ZS_PARAM("phase", current) + ZS_PARAM("total", total))

            UseBackgroundingDelegateSubscriptionsPtr &subscriptions = (*found).second;
            subscriptions->delegate()->onBackgroundingApplicationWillQuit(IBackgroundingSubscriptionPtr());

            ++current;
          } while (true);

          ZS_LOG_DEBUG(log("all phases told to go to background now"))
        }

        // block until all other non-application threads are done
        IMessageQueueManagerForBackgrounding::blockUntilDone();
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
        AutoRecursiveLock lock(*this);

        ElementPtr resultEl = Element::create("services::Backgrounding");

        IHelper::debugAppend(resultEl, "id", mID);

        IHelper::debugAppend(resultEl, "largest phase", mLargestPhase);

        IHelper::debugAppend(resultEl, "phases", mPhaseSubscriptions.size());

        IHelper::debugAppend(resultEl, "current backgrounding id", mCurrentBackgroundingID);
        IHelper::debugAppend(resultEl, "current phase", mCurrentPhase);
        IHelper::debugAppend(resultEl, "total waiting", mTotalWaiting);
        IHelper::debugAppend(resultEl, "notification delegate", (bool)mNotifyWhenReady);
        IHelper::debugAppend(resultEl, "query", (bool)mQuery);

        IHelper::debugAppend(resultEl, "total notifiers created", mTotalNotifiersCreated);

        IHelper::debugAppend(resultEl, "timer id", mTimer ? mTimer->getID() : 0);

        return resultEl;
      }

      //-----------------------------------------------------------------------
      size_t Backgrounding::getPreviousPhase(Phase &ioPreviousPhase)
      {
        size_t totalFound = 0;
        Phase greatestFoundEqualOrLess = ioPreviousPhase;

        for (PhaseSubscriptionMap::iterator iter_doNotUse = mPhaseSubscriptions.begin(); iter_doNotUse != mPhaseSubscriptions.end();)
        {
          PhaseSubscriptionMap::iterator current = iter_doNotUse; ++iter_doNotUse;

          Phase currentPhase = (*current).first;
          const UseBackgroundingDelegateSubscriptionsPtr &subscriptions = (*current).second;

          size_t total = subscriptions->size();
          if (0 == total) {
            ZS_LOG_WARNING(Detail, log("no subscriptions found for phase (thus pruning phase)") + ZS_PARAM("phase", currentPhase))
            mPhaseSubscriptions.erase(current);
            continue;
          }

          if (currentPhase <= ioPreviousPhase) {
            if (0 == totalFound) {
              greatestFoundEqualOrLess = currentPhase;
              totalFound = total;
            } else if (currentPhase > greatestFoundEqualOrLess) {
              greatestFoundEqualOrLess = currentPhase;
              totalFound = total;
            }
          }
        }

        if (0 != totalFound) {
          ioPreviousPhase = greatestFoundEqualOrLess;
        }
        return totalFound;
      }

      //-----------------------------------------------------------------------
      size_t Backgrounding::getNextPhase(Phase &ioNextPhase)
      {
        size_t totalFound = 0;
        Phase lowestFoundEqualOrGreater = ioNextPhase;

        for (PhaseSubscriptionMap::iterator iter_doNotUse = mPhaseSubscriptions.begin(); iter_doNotUse != mPhaseSubscriptions.end();)
        {
          PhaseSubscriptionMap::iterator current = iter_doNotUse; ++iter_doNotUse;

          Phase currentPhase = (*current).first;
          const UseBackgroundingDelegateSubscriptionsPtr &subscriptions = (*current).second;

          size_t total = subscriptions->size();
          if (0 == total) {
            ZS_LOG_WARNING(Detail, log("no subscriptions found for phase (thus pruning phase)") + ZS_PARAM("phase", currentPhase))
            mPhaseSubscriptions.erase(current);
            continue;
          }

          if (currentPhase >= ioNextPhase) {
            if (0 == totalFound) {
              lowestFoundEqualOrGreater = currentPhase;
              totalFound = total;
            } else if (currentPhase < lowestFoundEqualOrGreater) {
              lowestFoundEqualOrGreater = currentPhase;
              totalFound = total;
            }
          }
        }

        if (0 != totalFound) {
          ioNextPhase = lowestFoundEqualOrGreater;
        }
        return totalFound;
      }

      //-----------------------------------------------------------------------
      void Backgrounding::performGoingToBackground()
      {
        mTotalWaiting = getNextPhase(mCurrentPhase);

        mTotalNotifiersCreated = 0;

        if (0 == mTotalWaiting) {
          ZS_LOG_DETAIL(log("all backgrounding phases have completed thus notifying backgrounding completed immediately") + ZS_PARAM("backgrounding id", mCurrentBackgroundingID))

          if (mNotifyWhenReady) {
            mNotifyWhenReady->onBackgroundingReady(mQuery);
            mNotifyWhenReady.reset();
            mQuery.reset();
          }
          return;
        }

        ExchangedNotifierPtr exchangeNotifier = ExchangedNotifier::create(
                                                                          mThisWeak.lock(),
                                                                          mCurrentBackgroundingID,
                                                                          mCurrentPhase
                                                                          );

        PhaseSubscriptionMap::iterator found = mPhaseSubscriptions.find(mCurrentPhase);
        ZS_THROW_BAD_STATE_IF(found == mPhaseSubscriptions.end())

        UseBackgroundingDelegateSubscriptionsPtr subscription = (*found).second;

        subscription->delegate()->onBackgroundingGoingToBackground(IBackgroundingSubscriptionPtr(), exchangeNotifier);

        // race condition where subscriber could cancel backgrounding subscription between time size was fetched and when notifications were sent
        mTotalWaiting = mTotalNotifiersCreated;

        if (0 == mTotalNotifiersCreated) {
          ZS_LOG_WARNING(Detail, log("all delegates on subscriptions to current phase are gone") + ZS_PARAM("backgrounding id", mCurrentBackgroundingID) + ZS_PARAM("phase", mCurrentPhase))

          // recurse to next phase to skip current phase
          ++mCurrentPhase;  // no longer on current phase, go to next...
          performGoingToBackground();
          return;
        }

        if (mTimer) {
          mTimer->cancel();
          mTimer.reset();
        }

        String timeoutSetting(OPENPEER_STACK_SETTING_BACKGROUNDING_PHASE_TIMEOUT);

        timeoutSetting.replaceAll("$phase$", string(mCurrentPhase));

        ULONG secondsUntilTimeout = ISettings::getUInt(timeoutSetting);

        ZS_LOG_DETAIL(log("notified going to background") + ZS_PARAM("backgrounding id", mCurrentBackgroundingID) + ZS_PARAM("phase", mCurrentPhase) + ZS_PARAM("total", mTotalWaiting) + ZS_PARAM("timeout", secondsUntilTimeout))

        if (0 != secondsUntilTimeout) {
          mTimer = Timer::create(mThisWeak.lock(), Seconds(secondsUntilTimeout), false);  // fires only once
          ZS_LOG_DEBUG(log("created timeout timer") + ZS_PARAM("id", mTimer->getID()))
        }
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
        mBackgroundingID(notifier->getID()),
        SharedRecursiveLock(*(notifier->getOuter())),
        mOuter(notifier->getOuter()),
        mPhase(notifier->getPhase())
      {
      }

      //-----------------------------------------------------------------------
      Backgrounding::Notifier::~Notifier()
      {
        if (mNotified) return;

        mOuter->notifyReady(mBackgroundingID, mPhase);
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
        AutoRecursiveLock lock(*this);

        if (mNotified) return;

        get(mNotified) = true;

        mOuter->notifyReady(mBackgroundingID, mPhase);
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
                                                                                   PUID backgroundingID,
                                                                                   Phase phase
                                                                                   )
      {
        return ExchangedNotifierPtr(new ExchangedNotifier(backgrounding, backgroundingID, phase));
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

        AutoRecursiveLock lock(*this);

        return 0 == outer->totalPending(mBackgroundingID);
      }

      //-----------------------------------------------------------------------
      size_t Backgrounding::Query::totalBackgroundingSubscribersStillPending() const
      {
        BackgroundingPtr outer = mOuter.lock();
        if (!outer) return 0;

        AutoRecursiveLock lock(*this);

        return outer->totalPending(mBackgroundingID);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IBackgroundingFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IBackgroundingFactory &IBackgroundingFactory::singleton()
      {
        return BackgroundingFactory::singleton();
      }

      //-----------------------------------------------------------------------
      BackgroundingPtr IBackgroundingFactory::createForBackgrounding()
      {
        if (this) {}
        return Backgrounding::create();
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
    IBackgroundingSubscriptionPtr IBackgrounding::subscribe(
                                                            IBackgroundingDelegatePtr delegate,
                                                            ULONG phase
                                                            )
    {
      internal::BackgroundingPtr singleton = internal::Backgrounding::singleton();
      if (!singleton) return IBackgroundingSubscriptionPtr();
      return singleton->subscribe(delegate, phase);
    }

    //-------------------------------------------------------------------------
    IBackgroundingQueryPtr IBackgrounding::notifyGoingToBackground(IBackgroundingCompletionDelegatePtr readyDelegate)
    {
      internal::BackgroundingPtr singleton = internal::Backgrounding::singleton();
      if (!singleton) {
        ZS_DECLARE_CLASS_PTR(BogusQuery)

        class BogusQuery : public IBackgroundingQuery
        {
          BogusQuery() {}
        public:
          static BogusQueryPtr create() {return BogusQueryPtr(new BogusQuery);}

          virtual PUID getID() const {return mID;}
          virtual bool isReady() const {return true;}
          virtual size_t totalBackgroundingSubscribersStillPending() const {return 0;}

        protected:
          zsLib::AutoPUID mID;
        };

        BogusQueryPtr query = BogusQuery::create();
        if (readyDelegate) {
          IBackgroundingCompletionDelegateProxy::create(readyDelegate)->onBackgroundingReady(query);
        }
        return query;
      }
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

