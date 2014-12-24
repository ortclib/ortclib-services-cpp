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

#pragma once

#include <openpeer/services/IBackOffTimer.h>
#include <openpeer/services/internal/types.h>

#include <zsLib/Timer.h>

#include <vector>

#define OPENPEER_SERVICES_SETTING_BACKOFF_TIMER_MAX_CONSTRUCTOR_FAILURES "openpeer/services/backoff-timer-max-constructor-failures"

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
      #pragma mark BackOffTimer
      #pragma mark

      class BackOffTimer : public MessageQueueAssociator,
                           public SharedRecursiveLock,
                           public IBackOffTimer,
                           public ITimerDelegate
      {
      public:
        friend interaction IBackOffTimerFactory;
        friend interaction IBackOffTimer;

        ZS_DECLARE_TYPEDEF_PTR(IBackOffTimerDelegateSubscriptions, UseSubscriptions)

        typedef std::vector<Microseconds> RetryTimerVector;

      protected:
        BackOffTimer(
                     const char *pattern,
                     const Microseconds &unit,
                     size_t totalFailuresThusFar,
                     IBackOffTimerDelegatePtr delegate
                     );

        void init();

      public:
        ~BackOffTimer();

      public:
        static BackOffTimerPtr convert(IBackOffTimerPtr BackOffTimer);

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark BackOffTimer => IBackOffTimer
        #pragma mark

        static ElementPtr toDebug(IBackOffTimerPtr timer);

        virtual IBackOffTimerSubscriptionPtr subscribe(IBackOffTimerDelegatePtr delegate);

        virtual void cancel();

        virtual size_t getTotalFailures() const;

        virtual size_t getMaxFailures() const;

        virtual Time getNextRetryAfterTime() const;

        virtual void notifyFailure();

        static BackOffTimerPtr create(
                                      const char *pattern,
                                      const Microseconds &unit,
                                      size_t totalFailuresThusFar = 0,
                                      IBackOffTimerDelegatePtr delegate = IBackOffTimerDelegatePtr()
                                      );

        virtual Microseconds actualGetNextRetryAfterWaitPeriod();

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark BackOffTimer => ITimerDelegate
        #pragma mark

        virtual void onTimer(TimerPtr timer);

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark BackOffTimer => (internal)
        #pragma mark

        Log::Params log(const char *message) const;
        static Log::Params slog(const char *message);
        Log::Params debug(const char *message) const;

        virtual ElementPtr toDebug() const;

        void initialzePattern();

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark BackOffTimer => (data)
        #pragma mark

        AutoPUID mID;
        BackOffTimerWeakPtr mThisWeak;

        UseSubscriptions mSubscriptions;
        IBackOffTimerSubscriptionPtr mDefaultSubscription;

        Microseconds mUnit;

        bool mShutdown {};
        bool mFinalFailure {};
        bool mNotifiedFailure {};

        String mPattern;
        size_t mTotalFailures {};

        size_t mMaximumRetries {};
        Microseconds mAttemptTimeout {};
        RetryTimerVector mRetryTimerVector;

        double mMultiplier {};
        Microseconds mMaximumRetry {};

        Microseconds mLastRetryTimer {};
        Time mNextRetryAfter;

        TimerPtr mTimer;
        TimerPtr mAttemptTimer;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IBackOffTimerFactory
      #pragma mark

      interaction IBackOffTimerFactory
      {
        static IBackOffTimerFactory &singleton();

        virtual BackOffTimerPtr create(
                                       const char *pattern,
                                       const Microseconds &unit,
                                       size_t totalFailuresThusFar,
                                       IBackOffTimerDelegatePtr delegate
                                       );
      };

      class BackOffTimerFactory : public IFactory<IBackOffTimerFactory> {};

    }
  }
}
