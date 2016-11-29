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

#include <ortc/services/IBackOffTimer.h>
#include <ortc/services/internal/types.h>

#include <zsLib/ITimer.h>

#include <vector>

namespace ortc
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
      #pragma mark IBackOffTimerPatternForBackOffTimer
      #pragma mark

      interaction IBackOffTimerPatternForBackOffTimer
      {
        typedef IBackOffTimerPattern::DurationType DurationType;

        ZS_DECLARE_TYPEDEF_PTR(IBackOffTimerPatternForBackOffTimer, ForBackOffTimer)

        virtual ForBackOffTimerPtr clone() const = 0;

        virtual size_t getMaxAttempts() const = 0;

        virtual void nextAttempt() = 0;

        virtual DurationType getAttemptTimeout() = 0;
        virtual DurationType getRetryAfterDuration() = 0;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark BackOffTimerPattern
      #pragma mark

      class BackOffTimerPattern : public IBackOffTimerPattern,
                                  public SharedRecursiveLock,
                                  public IBackOffTimerPatternForBackOffTimer
      {
      protected:
        struct make_private {};

      public:
        friend interaction IBackOffTimerPattern;
        friend interaction IBackOffTimerPatternFactory;
        friend interaction IBackOffTimerPatternForBackOffTimer;

        typedef IBackOffTimerPattern::DurationType DurationType;
        typedef std::vector<DurationType> DurationVector;

      public:
        BackOffTimerPattern(
                            const make_private &,
                            ElementPtr patternEl
                            );

      protected:
        void init();

      public:
        ~BackOffTimerPattern();

      public:
        static BackOffTimerPatternPtr convert(IBackOffTimerPatternPtr pattern);
        static BackOffTimerPatternPtr convert(ForBackOffTimerPtr pattern);

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark BackOffTimer => IBackOffTimer
        #pragma mark

        static ElementPtr toDebug(IBackOffTimerPatternPtr timer);

        static BackOffTimerPatternPtr create(const char *pattern = NULL);
        static BackOffTimerPatternPtr create(ElementPtr patternEl);

        virtual PUID getID() const override {return mID;}

        virtual String save() const override;
        virtual ElementPtr saveToJSON() const override;

        virtual void setMultiplierForLastAttemptTimeout(double multiplier) override;

        virtual void setMaxAttempts(size_t maxAttempts) override;

        virtual void setMultiplierForLastRetryAfterFailureDuration(double multiplier) override;


        virtual void actualAddNextAttemptTimeout(Microseconds attemptTimeout) override;
        virtual void actualSetMaxAttemptTimeout(DurationType maxRetryDuration) override;

        virtual void actualAddNextRetryAfterFailureDuration(Microseconds nextRetryDuration) override;
        virtual void actualSetMaxRetryAfterFailureDuration(DurationType maxRetryDuration) override;

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark BackOffTimer => IBackOffTimerPatternForBackOffTimer
        #pragma mark

        virtual ForBackOffTimerPtr clone() const override;

        virtual size_t getMaxAttempts() const override;

        virtual void nextAttempt() override;

        virtual DurationType getAttemptTimeout() override;
        virtual DurationType getRetryAfterDuration() override;

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark BackOffTimerPattern => (internal)
        #pragma mark

        Log::Params log(const char *message) const;
        static Log::Params slog(const char *message);
        Log::Params debug(const char *message) const;

        virtual ElementPtr toDebug() const;

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark BackOffTimer => (data)
        #pragma mark

        AutoPUID mID;
        BackOffTimerPatternWeakPtr mThisWeak;

        size_t mMaxAttempts {0};

        DurationVector mAttemptTimeoutVector;
        double mAttemptTimeoutMultiplier {1.0};
        DurationType mMaxAttemptTimeout {};

        DurationVector mRetryVector;
        double mRetryMultiplier {1.0};
        DurationType mMaxRetry {};

        size_t mAttemptNumber {0};

        DurationType mLastAttemptTimeout {};
        DurationType mLastRetryDuration {};
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IBackOffTimerPatternFactory
      #pragma mark

      interaction IBackOffTimerPatternFactory
      {
        static IBackOffTimerPatternFactory &singleton();

        virtual BackOffTimerPatternPtr create(const char *pattern = NULL);
        virtual BackOffTimerPatternPtr create(ElementPtr patternEl);
      };

      class BackOffTimerPatternFactory : public IFactory<IBackOffTimerPatternFactory> {};

    }
  }
}
