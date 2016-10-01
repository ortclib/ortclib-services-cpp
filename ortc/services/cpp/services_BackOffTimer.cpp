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

#include <ortc/services/internal/services_BackOffTimer.h>
#include <ortc/services/internal/services_BackOffTimerPattern.h>
#include <ortc/services/internal/services_MessageQueueManager.h>
#include <ortc/services/internal/services_Tracing.h>

#include <ortc/services/IHelper.h>
#include <ortc/services/ISettings.h>

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
                                 const make_private &,
                                 IBackOffTimerPatternPtr pattern,
                                 size_t totalFailuresThusFar,
                                 IBackOffTimerDelegatePtr delegate
                                 ) :
        MessageQueueAssociator(IHelper::getServicePoolQueue()),
        SharedRecursiveLock(SharedRecursiveLock::create()),
        mPattern(UsePatternPtr(BackOffTimerPattern::convert(pattern))->clone()),
        mLastStateChange(zsLib::now())
      {
        ZS_LOG_DETAIL(log("created"))

        static auto sMaximumFailures = ISettings::getUInt(OPENPEER_SERVICES_SETTING_BACKOFF_TIMER_MAX_CONSTRUCTOR_FAILURES);
        auto maximumFailures = (sMaximumFailures > 0 ? sMaximumFailures : totalFailuresThusFar);

        for (ULONG loop = 0; (loop < totalFailuresThusFar) && (loop < maximumFailures); ++loop) {
          notifyAttempting();
          notifyAttemptFailed();
          notifyTryAgainNow();
        }

        if (delegate) {
          mDefaultSubscription = mSubscriptions.subscribe(delegate, IHelper::getServiceQueue());
        }

        EventWriteOpServicesBackOffTimerCreate(__func__, mID, ((bool)pattern) ? pattern->getID() : 0);
      }

      //-----------------------------------------------------------------------
      void BackOffTimer::init()
      {
        AutoRecursiveLock lock(*this);
        if (State_AttemptNow != mCurrentState) {
          mSubscriptions.delegate()->onBackOffTimerStateChanged(mThisWeak.lock(), mCurrentState);
        }
      }

      //-----------------------------------------------------------------------
      BackOffTimer::~BackOffTimer()
      {
        mThisWeak.reset();
        ZS_LOG_DETAIL(log("destroyed"))

        EventWriteOpServicesBackOffTimerDestroy(__func__, mID);
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
      BackOffTimerPtr BackOffTimer::create(
                                           IBackOffTimerPatternPtr pattern,
                                           size_t totalFailuresThusFar,
                                           IBackOffTimerDelegatePtr delegate
                                           )
      {
        BackOffTimerPtr pThis(make_shared<BackOffTimer>(make_private{}, pattern, totalFailuresThusFar, delegate));
        pThis->mThisWeak = pThis;
        pThis->init();
        return pThis;
      }

      //-----------------------------------------------------------------------
      IBackOffTimerSubscriptionPtr BackOffTimer::subscribe(IBackOffTimerDelegatePtr originalDelegate)
      {
        ZS_LOG_DETAIL(log("subscribing to BackOffTimer"))

        AutoRecursiveLock lock(*this);
        if (!originalDelegate) return IBackOffTimerSubscriptionPtr();

        IBackOffTimerSubscriptionPtr subscription = mSubscriptions.subscribe(originalDelegate);

        IBackOffTimerDelegatePtr delegate = mSubscriptions.delegate(subscription, true);

        if (delegate) {
          if (State_AttemptNow != mCurrentState) {
            delegate->onBackOffTimerStateChanged(mThisWeak.lock(), mCurrentState);
          }
        }

        if (isComplete()) {
          mSubscriptions.clear();
        }

        return subscription;
      }

      //-----------------------------------------------------------------------
      void BackOffTimer::cancel()
      {
        AutoRecursiveLock lock(*this);

        cancelTimer();

        if (!isComplete()) {
          setState(State_AllAttemptsFailed);
        }

        if (mDefaultSubscription) {
          mDefaultSubscription->cancel();
          mDefaultSubscription.reset();
        }

        mSubscriptions.clear();
      }

      //-----------------------------------------------------------------------
      IBackOffTimerPatternPtr BackOffTimer::getPattern() const
      {
        auto pattern = mPattern->clone();
        return BackOffTimerPattern::convert(pattern);
      }

      //-----------------------------------------------------------------------
      size_t BackOffTimer::getAttemptNumber() const
      {
        AutoRecursiveLock lock(*this);
        return mAttemptNumber;
      }

      //-----------------------------------------------------------------------
      size_t BackOffTimer::getTotalFailures() const
      {
        AutoRecursiveLock lock(*this);

        auto failures = mAttemptNumber;

        if ((State_AllAttemptsFailed == mCurrentState) ||
            (State_WaitingAfterAttemptFailure == mCurrentState) ||
            (State_AllAttemptsFailed == mCurrentState)) {
          ++failures;
        }

        return failures;
      }

      //-----------------------------------------------------------------------
      IBackOffTimer::States BackOffTimer::getState() const
      {
        AutoRecursiveLock lock(*this);
        return mCurrentState;
      }

      //-----------------------------------------------------------------------
      Time BackOffTimer::getNextRetryAfterTime() const
      {
        AutoRecursiveLock lock(*this);
        Time result;

        switch (mCurrentState) {
          case State_AttemptNow:          break;
          case State_Attempting:          break;
          case State_WaitingAfterAttemptFailure: {
            result = mLastStateChange + mPattern->getRetryAfterDuration();
            break;
          }
          case State_AllAttemptsFailed:   break;
          case State_Succeeded:           break;
        }

        ZS_LOG_TRACE(log("next retry after time") + ZS_PARAM("retry after", result))

        return result;
      }

      //-----------------------------------------------------------------------
      void BackOffTimer::notifyAttempting()
      {
        EventWriteOpServicesBackOffTimerNotifyAttempting(__func__, mID);

        AutoRecursiveLock lock(*this);
        if (State_AttemptNow != mCurrentState) {
          ZS_LOG_WARNING(Detail, log("cannot notify attempting - not in correct state") + ZS_PARAM("state", toString(mCurrentState)))
          return;
        }

        setState(State_Attempting);

        createOneTimeTimer(mPattern->getAttemptTimeout());
      }

      //-----------------------------------------------------------------------
      void BackOffTimer::notifyAttemptFailed()
      {
        EventWriteOpServicesBackOffTimerNotifyAttemptFailed(__func__, mID);

        AutoRecursiveLock lock(*this);
        if (State_Attempting != mCurrentState) {
          ZS_LOG_WARNING(Detail, log("cannot notify attempt failed - not in correct state") + ZS_PARAM("state", toString(mCurrentState)))
          return;
        }

        cancelTimer();

        auto maxAttempts = mPattern->getMaxAttempts();

        if (0 != maxAttempts) {
          if (mAttemptNumber + 1 >= maxAttempts) {
            setState(State_AllAttemptsFailed);
            ZS_LOG_WARNING(Debug, log("all attempts have failed"))
            return;
          }
        }

        setState(State_WaitingAfterAttemptFailure);

        createOneTimeTimer(mPattern->getRetryAfterDuration());
      }

      //-----------------------------------------------------------------------
      void BackOffTimer::notifyTryAgainNow()
      {
        EventWriteOpServicesBackOffTimerNotifyTryAgainNow(__func__, mID);

        AutoRecursiveLock lock(*this);
        if (State_WaitingAfterAttemptFailure != mCurrentState) {
          ZS_LOG_WARNING(Detail, log("cannot try again now - not in correct state") + ZS_PARAM("state", toString(mCurrentState)))
          return;
        }

        setState(State_AttemptNow);

        cancelTimer();

        ++mAttemptNumber;
        mPattern->nextAttempt();
      }

      //-----------------------------------------------------------------------
      void BackOffTimer::notifySucceeded()
      {
        EventWriteOpServicesBackOffTimerNotifySucceeded(__func__, mID);

        AutoRecursiveLock lock(*this);

        cancelTimer();
        setState(State_Succeeded);
      }

      //-----------------------------------------------------------------------
      IBackOffTimer::DurationType BackOffTimer::actualGetNextRetryAfterFailureDuration()
      {
        return mPattern->getRetryAfterDuration();
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

        if (timer == mTimer) {
          mTimer.reset();

          switch (mCurrentState) {
            case IBackOffTimer::State_AttemptNow:                 break;
            case IBackOffTimer::State_Attempting:                 notifyAttemptFailed(); break;
            case IBackOffTimer::State_WaitingAfterAttemptFailure: notifyTryAgainNow(); break;
            case IBackOffTimer::State_AllAttemptsFailed:          break;
            case IBackOffTimer::State_Succeeded:                  break;
          }

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

        IHelper::debugAppend(resultEl, IBackOffTimerPattern::toDebug(BackOffTimerPattern::convert(mPattern)));

        IHelper::debugAppend(resultEl, "subscriptions", mSubscriptions.size());
        IHelper::debugAppend(resultEl, "default subscription", (bool)mDefaultSubscription);

        IHelper::debugAppend(resultEl, "state", toString(mCurrentState));
        IHelper::debugAppend(resultEl, "last state changed", mLastStateChange);

        IHelper::debugAppend(resultEl, "attempt number", mAttemptNumber);

        IHelper::debugAppend(resultEl, "timer", mTimer ? mTimer->getID() : 0);

        return resultEl;
      }

      //-----------------------------------------------------------------------
      void BackOffTimer::setState(States state)
      {
        if (state == mCurrentState) return;

        ZS_LOG_DEBUG(log("state changed") + ZS_PARAM("new state", toString(state)) + ZS_PARAM("old state", toString(mCurrentState)))

        mCurrentState = state;
        mLastStateChange = zsLib::now();

        EventWriteOpServicesBackOffTimerStateChangedEventFired(__func__, mID, toString(state));

        auto pThis = mThisWeak.lock();
        if (pThis) {
          mSubscriptions.delegate()->onBackOffTimerStateChanged(pThis, mCurrentState);
        }
      }

      //-----------------------------------------------------------------------
      void BackOffTimer::cancelTimer()
      {
        if (!mTimer) return;

        mTimer->cancel();
        mTimer.reset();
      }

      //-----------------------------------------------------------------------
      void BackOffTimer::createOneTimeTimer(DurationType timeout)
      {
        cancelTimer();

        auto pThis = mThisWeak.lock();
        if (!pThis) return;
        if (DurationType() == timeout) return;

        mTimer = Timer::create(pThis, zsLib::now() + timeout);

        ZS_LOG_TRACE(debug("creating timer") + ZS_PARAM("timer id", mTimer->getID()) + ZS_PARAM("timeout", timeout))
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
                                                   IBackOffTimerPatternPtr pattern,
                                                   size_t totalFailuresThusFar,
                                                   IBackOffTimerDelegatePtr delegate
                                                   )
      {
        if (this) {}
        return BackOffTimer::create(pattern, totalFailuresThusFar, delegate);
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
    const char *IBackOffTimer::toString(States state)
    {
      switch (state) {
        case State_AttemptNow:                 return "Attempt now";
        case State_Attempting:                 return "Attempting";
        case State_WaitingAfterAttemptFailure: return "Waiting after attempt failure";
        case State_AllAttemptsFailed:          return "All attempts failed";
        case State_Succeeded:                  return "Succeeded";
      }
      return "Unknown";
    }

    //-------------------------------------------------------------------------
    ElementPtr IBackOffTimer::toDebug(IBackOffTimerPtr timer)
    {
      return internal::BackOffTimer::toDebug(timer);
    }

    //-------------------------------------------------------------------------
    IBackOffTimerPtr IBackOffTimer::create(
                                           IBackOffTimerPatternPtr pattern,
                                           size_t totalFailuresThusFar,
                                           IBackOffTimerDelegatePtr delegate
                                           )
    {
      return internal::IBackOffTimerFactory::singleton().create(pattern, totalFailuresThusFar, delegate);
    }
  }
}
