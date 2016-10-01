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

#include <ortc/services/IBackOffTimer.h>
#include <ortc/services/ISettings.h>

#include <zsLib/String.h>
#include <zsLib/MessageQueueAssociator.h>
#include <zsLib/Log.h>

#include <iostream>

#include "config.h"
#include "testing.h"

namespace ortc { namespace services { namespace test { ZS_DECLARE_SUBSYSTEM(ortc_services_test) } } }

using zsLib::string;
using zsLib::String;
using zsLib::Seconds;
using zsLib::Time;
using zsLib::MessageQueueAssociator;
using namespace ortc::services::test;

ZS_DECLARE_USING_PTR(zsLib, MessageQueueThread)
ZS_DECLARE_USING_PTR(zsLib, IMessageQueue)

ZS_DECLARE_TYPEDEF_PTR(ortc::services::IBackOffTimer, UseBackOffTimer)
ZS_DECLARE_TYPEDEF_PTR(ortc::services::IBackOffTimerDelegate, UseBackOffTimerDelegate)
ZS_DECLARE_TYPEDEF_PTR(ortc::services::IBackOffTimerPattern, UseBackOffTimerPattern)
ZS_DECLARE_TYPEDEF_PTR(ortc::services::ISettings, UseSettings)

template <typename duration_type>
static void timeCheck(
                      const Time &before,
                      const Time &check,
                      const duration_type &duration
                      )
{
  Time now = zsLib::now();

  TESTING_CHECK(before <= check)
  TESTING_CHECK(now + duration >= check)
}

static void testRetry1()
{
  UseBackOffTimerPatternPtr pattern = UseBackOffTimerPattern::create();
  pattern->addNextRetryAfterFailureDuration(Seconds(1));
  pattern->addNextRetryAfterFailureDuration(Seconds(2));
  pattern->addNextRetryAfterFailureDuration(Seconds(4));
  pattern->addNextRetryAfterFailureDuration(Seconds(6));

  UseBackOffTimerPtr backoff = UseBackOffTimer::create(pattern);
  TESTING_CHECK(backoff)

  Time now = zsLib::now();

  TESTING_EQUAL(string(Seconds(1)), string(backoff->getNextRetryAfterFailureDuration<Seconds>()))
  TESTING_EQUAL(string(Time()), string(backoff->getNextRetryAfterTime()))

  backoff->notifyAttempting();
  backoff->notifyAttemptFailed();
  TESTING_EQUAL(string(Seconds(1)), string(backoff->getNextRetryAfterFailureDuration<Seconds>()))
  timeCheck<Seconds>(now, backoff->getNextRetryAfterTime(), Seconds(1));

  backoff->notifyTryAgainNow();
  backoff->notifyAttempting();
  backoff->notifyAttemptFailed();
  TESTING_EQUAL(string(Seconds(2)), string(backoff->getNextRetryAfterFailureDuration<Seconds>()))
  timeCheck<Seconds>(now, backoff->getNextRetryAfterTime(), Seconds(2));

  backoff->notifyTryAgainNow();
  backoff->notifyAttempting();
  backoff->notifyAttemptFailed();
  TESTING_EQUAL(string(Seconds(4)), string(backoff->getNextRetryAfterFailureDuration<Seconds>()))
  timeCheck<Seconds>(now, backoff->getNextRetryAfterTime(), Seconds(4));

  backoff->notifyTryAgainNow();
  backoff->notifyAttempting();
  backoff->notifyAttemptFailed();
  TESTING_EQUAL(string(Seconds(6)), string(backoff->getNextRetryAfterFailureDuration<Seconds>()))
  timeCheck<Seconds>(now, backoff->getNextRetryAfterTime(), Seconds(6));

  backoff->notifyTryAgainNow();
  backoff->notifyAttempting();
  backoff->notifyAttemptFailed();
  TESTING_EQUAL(string(Seconds(6)), string(backoff->getNextRetryAfterFailureDuration<Seconds>()))
  timeCheck<Seconds>(now, backoff->getNextRetryAfterTime(), Seconds(6));
}

static void testRetry2()
{
  UseBackOffTimerPatternPtr pattern = UseBackOffTimerPattern::create();
  pattern->addNextRetryAfterFailureDuration(Seconds(1));
  pattern->setMultiplierForLastRetryAfterFailureDuration(2.0);
  pattern->setMaxRetryAfterFailureDuration(Seconds(60));

  UseBackOffTimerPtr backoff = UseBackOffTimer::create(pattern);
  TESTING_CHECK(backoff)

  Time now = zsLib::now();

  TESTING_EQUAL(string(Seconds(1)), string(backoff->getNextRetryAfterFailureDuration<Seconds>()))
  TESTING_EQUAL(string(Time()), string(backoff->getNextRetryAfterTime()))

  Seconds current(1);
  for (int loop = 0; loop < 20; ++loop) {

    if (current > Seconds(60)) {
      current = Seconds(60);
    }

    backoff->notifyAttempting();
    backoff->notifyAttemptFailed();

    TESTING_EQUAL(string(current), string(backoff->getNextRetryAfterFailureDuration<Seconds>()))
    timeCheck<Seconds>(now, backoff->getNextRetryAfterTime(), current);

    current *= 2;

    backoff->notifyTryAgainNow();
  }
}

static void testRetry3()
{
  UseBackOffTimerPatternPtr pattern = UseBackOffTimerPattern::create();
  pattern->setMaxAttempts(15);
  pattern->addNextRetryAfterFailureDuration(Seconds(1));
  pattern->setMultiplierForLastRetryAfterFailureDuration(2.0);
  pattern->setMaxRetryAfterFailureDuration(Seconds(60));

  UseBackOffTimerPtr backoff = UseBackOffTimer::create(pattern);
  TESTING_CHECK(backoff)

  Time now = zsLib::now();

  TESTING_EQUAL(string(Seconds(1)), string(backoff->getNextRetryAfterFailureDuration<Seconds>()))
  TESTING_EQUAL(string(Time()), string(backoff->getNextRetryAfterTime()))

  Seconds current(1);
  for (int loop = 0; loop < 20; ++loop) {

    if (current > Seconds(60)) {
      current = Seconds(60);
    }

    backoff->notifyAttempting();
    backoff->notifyAttemptFailed();

    if (loop < 14) {
      TESTING_EQUAL(string(current), string(backoff->getNextRetryAfterFailureDuration<Seconds>()))
      timeCheck<Seconds>(now, backoff->getNextRetryAfterTime(), current);
    } else {
      TESTING_CHECK(backoff->isComplete())
      TESTING_CHECK(backoff->haveAllAttemptsFailed())
    }

    current *= 2;

    backoff->notifyTryAgainNow();
  }
}

static void testRetry4()
{
  UseBackOffTimerPatternPtr pattern = UseBackOffTimerPattern::create();
  pattern->setMaxAttempts(15);
  pattern->addNextRetryAfterFailureDuration(Seconds(1));
  pattern->setMultiplierForLastRetryAfterFailureDuration(2.0);
  pattern->setMaxRetryAfterFailureDuration(Seconds(60));

  UseBackOffTimerPtr backoff = UseBackOffTimer::create(pattern, 16);
  TESTING_CHECK(backoff)

  TESTING_CHECK(backoff->isComplete())
  TESTING_CHECK(backoff->haveAllAttemptsFailed())
}

static void testRetry5(MessageQueueThreadPtr queue)
{
  ZS_DECLARE_CLASS_PTR(BackoffDelegate)

  class BackoffDelegate : public MessageQueueAssociator,
                          public UseBackOffTimerDelegate
  {
  public:
    BackoffDelegate(IMessageQueuePtr queue) :
      MessageQueueAssociator(queue)
    {
    }

    ZS_DECLARE_TYPEDEF_PTR(ortc::services::IBackOffTimer, IBackOffTimer)

    virtual void onBackOffTimerStateChanged(
                                            IBackOffTimerPtr timer,
                                            IBackOffTimer::States state
                                            ) override
    {
      mAttemptNowTime = zsLib::now();

      ZS_LOG_BASIC(zsLib::Log::Params("backoff state changed") + ZS_PARAM("state", UseBackOffTimer::toString(state)))

      switch (state) {
        case IBackOffTimer::State_AttemptNow:                 {
          ++mFiredAttemptNow;
          timer->notifyAttempting();
          break;
        }
        case IBackOffTimer::State_Attempting:                 {
          ++mFiredAttemptting;
          break;
        }
        case IBackOffTimer::State_WaitingAfterAttemptFailure: {
          ++mFiredAttemptFailures;
          TESTING_EQUAL(string(mCurrent), string(timer->getNextRetryAfterFailureDuration<Seconds>()))

          mCurrent *= 2;
          if (mCurrent > Seconds(10)) {
            mCurrent = Seconds(10);
          }
          break;
        }
        case IBackOffTimer::State_AllAttemptsFailed:          {
          ++mFiredAllAttemptsFailed;
          TESTING_CHECK(timer->isComplete())
          TESTING_CHECK(timer->haveAllAttemptsFailed())
          TESTING_CHECK(!timer->isSuccessful())
          break;
        }
        case IBackOffTimer::State_Succeeded:                  {
          ++mFiredSucceeded;
          TESTING_CHECK(timer->isComplete())
          TESTING_CHECK(!timer->haveAllAttemptsFailed())
          TESTING_CHECK(timer->isSuccessful())
          break;
        }
      }

    }

  public:

    Time mAttemptNowTime;

    size_t mFiredAttemptNow {};
    size_t mFiredAttemptting {};
    size_t mFiredAttemptFailures {};
    size_t mFiredAllAttemptsFailed {};
    size_t mFiredSucceeded {};

    Seconds mCurrent {1};
  };

  BackoffDelegatePtr delegate = BackoffDelegatePtr(new BackoffDelegate(queue));

  UseBackOffTimerPatternPtr pattern = UseBackOffTimerPattern::create();
  pattern->setMaxAttempts(12);
  pattern->addNextRetryAfterFailureDuration(Seconds(1));
  pattern->setMultiplierForLastRetryAfterFailureDuration(2.0);
  pattern->setMaxRetryAfterFailureDuration(Seconds(10));
  pattern->addNextAttemptTimeout(Seconds(5));

  UseBackOffTimerPtr backoff = UseBackOffTimer::create(pattern, delegate);
  TESTING_CHECK(backoff)

  TESTING_EQUAL(string(Seconds(1)), string(backoff->getNextRetryAfterFailureDuration<Seconds>()))
  TESTING_EQUAL(string(Time()), string(backoff->getNextRetryAfterTime()))

  backoff->notifyAttempting();

  Time start = zsLib::now();
  Seconds maxWaitTime = Seconds(200);

  while (true) {
    TESTING_SLEEP(1000)
    if (0 != delegate->mFiredAllAttemptsFailed) break;
    Time now = zsLib::now();
    TESTING_CHECK(start + maxWaitTime > now)

    ZS_LOG_BASIC(zsLib::Log::Params("Testing backoff retry timer") + ZS_PARAM("attempt now", delegate->mFiredAttemptNow) + ZS_PARAM("attempting", delegate->mFiredAttemptting) + ZS_PARAM("attempt failures", delegate->mFiredAttemptFailures) + ZS_PARAM("diff", now - start))
  }

  TESTING_EQUAL(delegate->mFiredAttemptNow, 11)
  TESTING_EQUAL(delegate->mFiredAttemptting, 12)
  TESTING_EQUAL(delegate->mFiredAttemptFailures, 11)

  TESTING_EQUAL(delegate->mFiredSucceeded, 0)
  TESTING_EQUAL(delegate->mFiredAllAttemptsFailed, 1)
}

void doTestBackoffRetry()
{
  if (!ORTC_SERVICE_TEST_DO_BACKOFF_RETRY_TEST) return;

  TESTING_INSTALL_LOGGER();

  MessageQueueThreadPtr thread(MessageQueueThread::createBasic());

  UseSettings::clearAll();
  UseSettings::applyDefaults();

  testRetry1();
  testRetry2();
  testRetry3();
  testRetry4();
  testRetry5(thread);

}
