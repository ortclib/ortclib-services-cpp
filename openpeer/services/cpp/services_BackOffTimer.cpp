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

#include <openpeer/services/internal/services_BackOffTimer.h>
#include <openpeer/services/internal/services_MessageQueueManager.h>

#include <openpeer/services/IHelper.h>
#include <openpeer/services/ISettings.h>

#include <zsLib/XML.h>
#include <zsLib/Numeric.h>

namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services) } }

namespace openpeer
{
  namespace services
  {
    namespace internal
    {
      using services::IHelper;
      using zsLib::Numeric;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark (helpers)
      #pragma mark

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark BackOffTimer
      #pragma mark

      //-----------------------------------------------------------------------
      BackOffTimer::BackOffTimer(
                                 const char *pattern,
                                 const Microseconds &unit,
                                 size_t totalFailuresThusFar,
                                 IBackOffTimerDelegatePtr delegate
                                 ) :
        MessageQueueAssociator(IHelper::getServiceQueue()),
        SharedRecursiveLock(SharedRecursiveLock::create()),
        mPattern(pattern),
        mUnit(unit),
        mTotalFailures(totalFailuresThusFar)
      {
        ZS_LOG_DETAIL(log("created"))

        static auto sMaximumFailures = ISettings::getUInt(OPENPEER_SERVICES_SETTING_BACKOFF_TIMER_MAX_CONSTRUCTOR_FAILURES);
        auto maximumFailures = (sMaximumFailures > 0 ? sMaximumFailures : totalFailuresThusFar);

        initialzePattern();

        for (int loop = 0; (loop < totalFailuresThusFar) && (loop < maximumFailures); ++loop) {
          notifyFailure();
        }

        if (mTotalFailures < totalFailuresThusFar) {
          mTotalFailures = totalFailuresThusFar;
        }

        if (delegate) {
          mDefaultSubscription = mSubscriptions.subscribe(delegate, IHelper::getServiceQueue());
        }
      }

      //-----------------------------------------------------------------------
      void BackOffTimer::init()
      {
        AutoRecursiveLock lock(*this);
        if (!mFinalFailure) {
          if (Microseconds() != mAttemptTimeout) {
            mAttemptTimer = Timer::create(mThisWeak.lock(), mAttemptTimeout, false);
          }
        } else {
          if (!mNotifiedFailure) {
            mSubscriptions.delegate()->onBackOffTimerAllAttemptsFailed(mThisWeak.lock());
          }
        }
      }

      //-----------------------------------------------------------------------
      BackOffTimer::~BackOffTimer()
      {
        mThisWeak.reset();
        ZS_LOG_DETAIL(log("destroyed"))
      }

      //-----------------------------------------------------------------------
      BackOffTimerPtr BackOffTimer::convert(IBackOffTimerPtr timer)
      {
        return ZS_DYNAMIC_PTR_CAST(BackOffTimer, timer);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark BackOffTimer => IBackOffTimer
      #pragma mark

      //-----------------------------------------------------------------------
      ElementPtr BackOffTimer::toDebug(IBackOffTimerPtr timer)
      {
        if (!timer) return ElementPtr();

        BackOffTimerPtr pThis = BackOffTimer::convert(timer);
        return pThis->toDebug();
      }

      //-----------------------------------------------------------------------
      IBackOffTimerSubscriptionPtr BackOffTimer::subscribe(IBackOffTimerDelegatePtr originalDelegate)
      {
        ZS_LOG_DETAIL(log("subscribing to BackOffTimer"))

        AutoRecursiveLock lock(*this);
        if (!originalDelegate) return IBackOffTimerSubscriptionPtr();

        IBackOffTimerSubscriptionPtr subscription = mSubscriptions.subscribe(originalDelegate);

        if (!mShutdown) {
          IBackOffTimerDelegatePtr delegate = mSubscriptions.delegate(subscription, true);
          if (delegate) {
            if (mFinalFailure) delegate->onBackOffTimerAllAttemptsFailed(mThisWeak.lock());
          }
        }

        return subscription;
      }

      //-----------------------------------------------------------------------
      void BackOffTimer::cancel()
      {
        AutoRecursiveLock lock(*this);

        if (mDefaultSubscription) {
          mDefaultSubscription->cancel();
          mDefaultSubscription.reset();
        }

        if (mTimer) {
          mTimer->cancel();
          mTimer.reset();
        }
        if (mAttemptTimer) {
          mAttemptTimer->cancel();
          mAttemptTimer.reset();
        }

        mSubscriptions.clear();

        mFinalFailure = true;
        mShutdown = true;

        mLastRetryTimer = Microseconds();
        mNextRetryAfter = Time();
      }

      //-----------------------------------------------------------------------
      size_t BackOffTimer::getTotalFailures()
      {
        AutoRecursiveLock lock(*this);
        return mTotalFailures;
      }

      //-----------------------------------------------------------------------
      Time BackOffTimer::getNextRetryAfterTime()
      {
        AutoRecursiveLock lock(*this);
        return mNextRetryAfter;
      }

      //-----------------------------------------------------------------------
      void BackOffTimer::notifyFailure()
      {
        AutoRecursiveLock lock(*this);

        if (mTimer) {
          mTimer->cancel();
          mTimer.reset();
        }
        if (mAttemptTimer) {
          mAttemptTimer->cancel();
          mAttemptTimer.reset();
        }

        if (mTotalFailures >= mRetryTimerVector.size()) {
          // this could be the final attempt
          if (mMultiplier > 0.0) {
            mLastRetryTimer *= mMultiplier;
          } else {
            mFinalFailure = true;
          }
          if (Microseconds() != mMaximumRetry) {
            if (mLastRetryTimer > mMaximumRetry) mLastRetryTimer = mMaximumRetry;
          }
        } else {
          mLastRetryTimer = mRetryTimerVector[mTotalFailures];
        }

        ++mTotalFailures;
        if (0 != mMaximumRetries) {
          if (mTotalFailures > mMaximumRetries) {
            mFinalFailure = true;
          }
        }

        Time now = zsLib::now();
        mNextRetryAfter = now + mLastRetryTimer;
        
        if (mFinalFailure) {
          if (!mNotifiedFailure) {
            BackOffTimerPtr pThis = mThisWeak.lock();
            if (pThis) {
              mSubscriptions.delegate()->onBackOffTimerAllAttemptsFailed(pThis);
              mNotifiedFailure = true;
            }
          }

          cancel();
          return;
        }

        BackOffTimerPtr pThis = mThisWeak.lock();
        if (pThis) {
          mTimer = Timer::create(pThis, mNextRetryAfter);
        }
      }

      //-----------------------------------------------------------------------
      BackOffTimerPtr BackOffTimer::create(
                                                     const char *pattern,
                                                     const Microseconds &unit,
                                                     size_t totalFailuresThusFar,
                                                     IBackOffTimerDelegatePtr delegate
                                                     )
      {
        BackOffTimerPtr pThis(new BackOffTimer(pattern, unit, totalFailuresThusFar, delegate));
        pThis->mThisWeak = pThis;
        pThis->init();
        return pThis;
      }

      //-----------------------------------------------------------------------
      Microseconds BackOffTimer::actualGetNextRetryAfterWaitPeriod()
      {
        AutoRecursiveLock lock(*this);
        return mLastRetryTimer;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark BackOffTimer => ITimerDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void BackOffTimer::onTimer(TimerPtr timer)
      {
        ZS_LOG_DEBUG(log("on timer") + ZS_PARAM("timer", timer->getID()))

        AutoRecursiveLock lock(*this);
        if (mShutdown) return;
        if (mFinalFailure) return;

        if (timer == mTimer) {
          mSubscriptions.delegate()->onBackOffTimerAttemptAgainNow(mThisWeak.lock());
          mTimer.reset();

          if (Microseconds() != mAttemptTimeout) {
            if (mAttemptTimer) {
              mAttemptTimer->cancel();
              mAttemptTimer.reset();
            }
            mAttemptTimer = Timer::create(mThisWeak.lock(), mAttemptTimeout, false);
          }
          return;
        }
        if (timer == mAttemptTimer ) {
          mSubscriptions.delegate()->onBackOffTimerAttemptTimeout(mThisWeak.lock());
          mAttemptTimer.reset();
          return;
        }

        ZS_LOG_WARNING(Debug, log("notified about obsolete timer") + ZS_PARAM("timer", timer->getID()))
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark BackOffTimer => (internal)
      #pragma mark

      //-----------------------------------------------------------------------
      Log::Params BackOffTimer::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("services::BackOffTimer");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params BackOffTimer::slog(const char *message)
      {
        return Log::Params(message, "services::BackOffTimer");
      }

      //-----------------------------------------------------------------------
      Log::Params BackOffTimer::debug(const char *message) const
      {
        return Log::Params(message, toDebug());
      }

      //-----------------------------------------------------------------------
      ElementPtr BackOffTimer::toDebug() const
      {
        AutoRecursiveLock lock(*this);

        ElementPtr resultEl = Element::create("services::BackOffTimer");

        IHelper::debugAppend(resultEl, "id", mID);

        IHelper::debugAppend(resultEl, "subscriptions", mSubscriptions.size());
        IHelper::debugAppend(resultEl, "default subscription", (bool)mDefaultSubscription);

        IHelper::debugAppend(resultEl, "unit", mUnit);

        IHelper::debugAppend(resultEl, "shutdown", mShutdown);
        IHelper::debugAppend(resultEl, "final failure", mFinalFailure);
        IHelper::debugAppend(resultEl, "notified failure", mNotifiedFailure);

        IHelper::debugAppend(resultEl, "pattern", mPattern);
        IHelper::debugAppend(resultEl, "total failures", mTotalFailures);

        IHelper::debugAppend(resultEl, "maximum retries", mMaximumRetries);
        IHelper::debugAppend(resultEl, "attempt timeout", mAttemptTimeout);
        IHelper::debugAppend(resultEl, "retry vector", mRetryTimerVector.size());

        IHelper::debugAppend(resultEl, "multiplier", mMultiplier);
        IHelper::debugAppend(resultEl, "maximum retry", mMaximumRetry);

        IHelper::debugAppend(resultEl, "last retry timer", mLastRetryTimer);
        IHelper::debugAppend(resultEl, "next retry after", mNextRetryAfter);

        IHelper::debugAppend(resultEl, "timer", mTimer ? mTimer->getID() : 0);
        IHelper::debugAppend(resultEl, "attempt timer", mAttemptTimer ? mAttemptTimer->getID() : 0);

        return resultEl;
      }

      //-----------------------------------------------------------------------
      void BackOffTimer::initialzePattern()
      {
        typedef IHelper::SplitMap SplitMap;

        SplitMap split;
        IHelper::split(mPattern, split, '/');

        String retriesStr = IHelper::get(split, 0);
        String eachAttemptStr = IHelper::get(split, 1);
        String maxRetriesStr = IHelper::get(split, 2);

        Microseconds::rep eachAttemp = 0;

        try {
          eachAttemp = Numeric<decltype(eachAttemp)>(eachAttemptStr);
          if (eachAttemp > 0) {
            mAttemptTimeout = Microseconds(eachAttemp * mUnit.count());
          }
        } catch(Numeric<decltype(eachAttemp)>::ValueOutOfRange &) {
        }

        try {
          mMaximumRetries = Numeric<decltype(mMaximumRetries)>(maxRetriesStr);
        } catch(Numeric<decltype(mMaximumRetries)>::ValueOutOfRange &) {
          ZS_LOG_WARNING(Detail, log("maximum retry value out of range") + ZS_PARAMIZE(maxRetriesStr))
        }

        split.empty();
        IHelper::split(retriesStr, split, ',');

        mRetryTimerVector.resize(split.size());

        for (int loop = 0; true; ++loop) {
          String valueStr = IHelper::get(split, loop);
          if (valueStr.isEmpty()) break;

          if ('*' == valueStr[0]) {
            SplitMap finalSplit;
            IHelper::split(valueStr, finalSplit, ':');
            valueStr = IHelper::get(finalSplit, 0).substr(1);
            String maximumStr = IHelper::get(finalSplit, 1);

            try {
              mMultiplier = Numeric<decltype(mMultiplier)>(valueStr);
            } catch(Numeric<decltype(mMultiplier)>::ValueOutOfRange &) {
              ZS_LOG_WARNING(Detail, log("multiplier value out of range") + ZS_PARAMIZE(valueStr))
            }

            try {
              auto max = Numeric<Microseconds::rep>(maximumStr);
              if (max > 0) {
                mMaximumRetry = Microseconds(max * mUnit.count());
              }
            } catch(Numeric<Microseconds::rep>::ValueOutOfRange *) {
            }

            // this is the final value in the array
            mRetryTimerVector.resize(loop);
            break;
          }

          try {
            Microseconds::rep value = Numeric<decltype(value)>(valueStr);
            mRetryTimerVector[loop] = Microseconds(value * mUnit.count());
          } catch(Numeric<Microseconds::rep>::ValueOutOfRange &) {
            ZS_LOG_WARNING(Detail, log("maximum retry value out of range") + ZS_PARAMIZE(valueStr))
          }
        }
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IBackOffTimerFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IBackOffTimerFactory &IBackOffTimerFactory::singleton()
      {
        return BackOffTimerFactory::singleton();
      }

      //-----------------------------------------------------------------------
      BackOffTimerPtr IBackOffTimerFactory::create(
                                                   const char *pattern,
                                                   const Microseconds &unit,
                                                   size_t totalFailuresThusFar,
                                                   IBackOffTimerDelegatePtr delegate
                                                   )
      {
        if (this) {}
        return BackOffTimer::create(pattern, unit, totalFailuresThusFar, delegate);
      }

    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IBackOffTimer
    #pragma mark

    //-------------------------------------------------------------------------
    ElementPtr IBackOffTimer::toDebug(IBackOffTimerPtr timer)
    {
      return internal::BackOffTimer::toDebug(timer);
    }

    //-------------------------------------------------------------------------
    IBackOffTimerPtr IBackOffTimer::create(
                                           const char *pattern,
                                           const Microseconds &unit,
                                           size_t totalFailuresThusFar,
                                           IBackOffTimerDelegatePtr delegate
                                           )
    {
      return internal::IBackOffTimerFactory::singleton().create(pattern, unit, totalFailuresThusFar, delegate);
    }
  }
}

