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
      ZS_DECLARE_INTERACTION_PTR(IBackOffTimerPatternForBackOffTimer)
      
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
      protected:
        struct make_private {};

      public:
        friend interaction IBackOffTimerFactory;
        friend interaction IBackOffTimer;

        ZS_DECLARE_TYPEDEF_PTR(IBackOffTimerDelegateSubscriptions, UseSubscriptions)
        ZS_DECLARE_TYPEDEF_PTR(IBackOffTimerPatternForBackOffTimer, UsePattern)

      public:
        BackOffTimer(
                     const make_private &,
                     IBackOffTimerPatternPtr pattern,
                     size_t totalFailuresThusFar,
                     IBackOffTimerDelegatePtr delegate
                     );

      protected:
        void init();

      public:
        ~BackOffTimer();

      public:
        static BackOffTimerPtr convert(IBackOffTimerPtr timer);

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark BackOffTimer => IBackOffTimer
        #pragma mark

        static ElementPtr toDebug(IBackOffTimerPtr timer);

        static BackOffTimerPtr create(
                                      IBackOffTimerPatternPtr pattern,
                                      size_t totalFailuresThusFar = 0,
                                      IBackOffTimerDelegatePtr delegate = IBackOffTimerDelegatePtr()
                                      );

        virtual IBackOffTimerSubscriptionPtr subscribe(IBackOffTimerDelegatePtr delegate) override;

        virtual PUID getID() const override {return mID;}

        virtual void cancel() override;

        virtual IBackOffTimerPatternPtr getPattern() const override;

        virtual size_t getAttemptNumber() const override;

        virtual size_t getTotalFailures() const override;

        virtual States getState() const override;

        virtual Time getNextRetryAfterTime() const override;

        virtual void notifyAttempting() override;

        virtual void notifyAttemptFailed() override;

        virtual void notifyTryAgainNow() override;

        virtual void notifySucceeded() override;

        virtual DurationType actualGetNextRetryAfterFailureDuration() override;

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark BackOffTimer => ITimerDelegate
        #pragma mark

        virtual void onTimer(TimerPtr timer) override;

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark BackOffTimer => (internal)
        #pragma mark

        Log::Params log(const char *message) const;
        static Log::Params slog(const char *message);
        Log::Params debug(const char *message) const;

        virtual ElementPtr toDebug() const;

        void setState(States state);
        void cancelTimer();
        void createOneTimeTimer(DurationType timeout);

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark BackOffTimer => (data)
        #pragma mark

        AutoPUID mID;
        BackOffTimerWeakPtr mThisWeak;

        UsePatternPtr mPattern; // no lock needed

        UseSubscriptions mSubscriptions;
        IBackOffTimerSubscriptionPtr mDefaultSubscription;

        States mCurrentState {State_AttemptNow};
        Time mLastStateChange;

        size_t mAttemptNumber {0};

        TimerPtr mTimer;
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
                                       IBackOffTimerPatternPtr pattern,
                                       size_t totalFailuresThusFar,
                                       IBackOffTimerDelegatePtr delegate
                                       );
      };

      class BackOffTimerFactory : public IFactory<IBackOffTimerFactory> {};

    }
  }
}
