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

#include <openpeer/services/IBackOffTimer.h>
#include <openpeer/services/ISettings.h>

#include <zsLib/String.h>
#include <zsLib/MessageQueueAssociator.h>
#include <zsLib/Log.h>

#include <iostream>

#include "config.h"
#include "testing.h"

namespace openpeer { namespace services { namespace test { ZS_DECLARE_SUBSYSTEM(openpeer_services_test) } } }

using zsLib::string;
using zsLib::String;
using zsLib::Seconds;
using zsLib::Time;
using zsLib::MessageQueueAssociator;
using namespace openpeer::services::test;

ZS_DECLARE_USING_PTR(zsLib, MessageQueueThread)
ZS_DECLARE_USING_PTR(zsLib, IMessageQueue)

ZS_DECLARE_TYPEDEF_PTR(openpeer::services::IBackOffTimer, UseBackoffRetry)
ZS_DECLARE_TYPEDEF_PTR(openpeer::services::IBackOffTimerDelegate, UseBackoffRetryDelegate)
ZS_DECLARE_TYPEDEF_PTR(openpeer::services::ISettings, UseSettings)

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
  UseBackoffRetryPtr backoff = UseBackoffRetry::create<Seconds>("/1,2,4,6///");
  TESTING_CHECK(backoff)

  Time now = zsLib::now();

  TESTING_EQUAL(string(Seconds()), string(backoff->getNextRetryAfterWaitPeriod<Seconds>()))
  TESTING_EQUAL(string(Time()), string(backoff->getNextRetryAfterTime()))

  backoff->notifyFailure();
  TESTING_EQUAL(string(Seconds(1)), string(backoff->getNextRetryAfterWaitPeriod<Seconds>()))
  timeCheck<Seconds>(now, backoff->getNextRetryAfterTime(), Seconds(1));

  backoff->notifyFailure();
  TESTING_EQUAL(string(Seconds(2)), string(backoff->getNextRetryAfterWaitPeriod<Seconds>()))
  timeCheck<Seconds>(now, backoff->getNextRetryAfterTime(), Seconds(2));

  backoff->notifyFailure();
  TESTING_EQUAL(string(Seconds(4)), string(backoff->getNextRetryAfterWaitPeriod<Seconds>()))
  timeCheck<Seconds>(now, backoff->getNextRetryAfterTime(), Seconds(4));

  backoff->notifyFailure();
  TESTING_EQUAL(string(Seconds(6)), string(backoff->getNextRetryAfterWaitPeriod<Seconds>()))
  timeCheck<Seconds>(now, backoff->getNextRetryAfterTime(), Seconds(6));

  backoff->notifyFailure();
  TESTING_EQUAL(string(Seconds()), string(backoff->getNextRetryAfterWaitPeriod<Seconds>()))
  TESTING_EQUAL(string(Time()), string(backoff->getNextRetryAfterTime()))
}

static void testRetry2()
{
  UseBackoffRetryPtr backoff = UseBackoffRetry::create<Seconds>("/1,2,4,8,*2:60///");
  TESTING_CHECK(backoff)

  Time now = zsLib::now();

  TESTING_EQUAL(string(Seconds()), string(backoff->getNextRetryAfterWaitPeriod<Seconds>()))
  TESTING_EQUAL(string(Time()), string(backoff->getNextRetryAfterTime()))

  Seconds current(1);
  for (int loop = 0; loop < 20; ++loop) {

    if (current > Seconds(60)) {
      current = Seconds(60);
    }

    backoff->notifyFailure();
    TESTING_EQUAL(string(current), string(backoff->getNextRetryAfterWaitPeriod<Seconds>()))
    timeCheck<Seconds>(now, backoff->getNextRetryAfterTime(), current);

    current *= 2;
  }
}

static void testRetry3()
{
  UseBackoffRetryPtr backoff = UseBackoffRetry::create<Seconds>("/1,2,4,8,*2:60//15/");
  TESTING_CHECK(backoff)

  Time now = zsLib::now();

  TESTING_EQUAL(string(Seconds()), string(backoff->getNextRetryAfterWaitPeriod<Seconds>()))
  TESTING_EQUAL(string(Time()), string(backoff->getNextRetryAfterTime()))

  Seconds current(1);
  for (int loop = 0; loop < 20; ++loop) {

    if (current > Seconds(60)) {
      current = Seconds(60);
    }

    backoff->notifyFailure();

    if (loop < 15) {
      TESTING_EQUAL(string(current), string(backoff->getNextRetryAfterWaitPeriod<Seconds>()))
      timeCheck<Seconds>(now, backoff->getNextRetryAfterTime(), current);
    } else {
      TESTING_EQUAL(string(Seconds()), string(backoff->getNextRetryAfterWaitPeriod<Seconds>()))
      TESTING_EQUAL(string(Time()), string(backoff->getNextRetryAfterTime()))
    }

    current *= 2;
  }
}

static void testRetry4()
{
  UseBackoffRetryPtr backoff = UseBackoffRetry::create<Seconds>("/1,2,4,8,*2:60//15/", 16);
  TESTING_CHECK(backoff)

  TESTING_EQUAL(string(Seconds()), string(backoff->getNextRetryAfterWaitPeriod<Seconds>()))
  TESTING_EQUAL(string(Time()), string(backoff->getNextRetryAfterTime()))
}

static void testRetry5(MessageQueueThreadPtr queue)
{
  ZS_DECLARE_CLASS_PTR(BackoffDelegate)

  class BackoffDelegate : public MessageQueueAssociator,
                          public UseBackoffRetryDelegate
  {
  public:
    BackoffDelegate(IMessageQueuePtr queue) :
      MessageQueueAssociator(queue)
    {
    }

    ZS_DECLARE_TYPEDEF_PTR(openpeer::services::IBackOffTimer, IBackOffTimer)

    virtual void onBackOffTimerAttemptAgainNow(IBackOffTimerPtr timer)
    {
      mAttemptNowTime = zsLib::now();

      ++mFiredAttemptAgainNow;
      ZS_LOG_BASIC("backoff attempt again now")
    }

    virtual void onBackOffTimerAttemptTimeout(IBackOffTimerPtr backoff)
    {
      zsLib::Time now = zsLib::now();

      TESTING_CHECK(now - mAttemptNowTime >= Seconds(5))
      TESTING_CHECK(now - mAttemptNowTime < Seconds(8))
      mAttemptNowTime = Time();

      ++mFiredAttemptTimeout;

      backoff->notifyFailure();

      if (mFiredAttemptTimeout < 12) {
        TESTING_EQUAL(string(mCurrent), string(backoff->getNextRetryAfterWaitPeriod<Seconds>()))
        timeCheck<Seconds>(now, backoff->getNextRetryAfterTime(), mCurrent);
      } else {
        TESTING_EQUAL(string(Seconds()), string(backoff->getNextRetryAfterWaitPeriod<Seconds>()))
        TESTING_EQUAL(string(Time()), string(backoff->getNextRetryAfterTime()))
      }

      mCurrent *= 2;
      if (mCurrent > Seconds(10)) {
        mCurrent = Seconds(10);
      }
    }

    virtual void onBackOffTimerAllAttemptsFailed(IBackOffTimerPtr backoff)
    {
      TESTING_EQUAL(string(Seconds()), string(backoff->getNextRetryAfterWaitPeriod<Seconds>()))
      TESTING_EQUAL(string(Time()), string(backoff->getNextRetryAfterTime()))

      ++mFiredFailed;
    }

  public:

    Time mAttemptNowTime;

    size_t mFiredAttemptAgainNow {};
    size_t mFiredAttemptTimeout {};
    size_t mFiredFailed {};

    Seconds mCurrent {2};
  };

  BackoffDelegatePtr delegate = BackoffDelegatePtr(new BackoffDelegate(queue));

  UseBackoffRetryPtr backoff = UseBackoffRetry::create<Seconds>("/1,2,4,8,*2:10/5/12/", delegate);
  TESTING_CHECK(backoff)

  TESTING_EQUAL(string(Seconds()), string(backoff->getNextRetryAfterWaitPeriod<Seconds>()))
  TESTING_EQUAL(string(Time()), string(backoff->getNextRetryAfterTime()))

  backoff->notifyFailure();

  Time start = zsLib::now();
  Seconds maxWaitTime = Seconds(200);

  while (true) {
    TESTING_SLEEP(1000)
    if (delegate->mFiredFailed) break;
    Time now = zsLib::now();
    TESTING_CHECK(start + maxWaitTime > now)

    ZS_LOG_BASIC(zsLib::Log::Params("Testing backoff retry timer") + ZS_PARAM("attempt again", delegate->mFiredAttemptAgainNow) + ZS_PARAM("attempt timeout", delegate->mFiredAttemptTimeout) + ZS_PARAM("diff", now - start))
  }

  TESTING_EQUAL(delegate->mFiredFailed, 1)
  TESTING_EQUAL(delegate->mFiredAttemptAgainNow, 12)
  TESTING_EQUAL(delegate->mFiredAttemptTimeout, 12)
}

void doTestBackoffRetry()
{
  if (!OPENPEER_SERVICE_TEST_DO_BACKOFF_RETRY_TEST) return;

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
