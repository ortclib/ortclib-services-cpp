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

#include <openpeer/services/types.h>

#include <zsLib/Log.h>

namespace openpeer
{
  namespace services
  {
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IBackOffTimer
    #pragma mark

    interaction IBackOffTimer
    {
      //-----------------------------------------------------------------------
      // PURPOSE: returns a debug element containing internal object state
      static ElementPtr toDebug(IBackOffTimerPtr timer);

      //-----------------------------------------------------------------------
      // PURPOSE: create a retry after timer
      // NOTES:   the pattern is encoded as follows:
      //          /retry1,retry2,.../optional_timeout/max_number_retries/
      //
      //          e.g.: /2,4,8,16,32,64/10//
      //          - retry after 2, 4, 6, 8, 32, 64 units of time.
      //          - each attempt fails after 10 units of time of trying
      //          - after the final retry fail entirely
      //
      //          e.g.: /2,4,8,16,32,64///
      //          - retry after 2, 4, 8, 32, 64 units of time.
      //          - each attempt takes as long as it takes to fail
      //          - after the final retry fail entirely
      //
      //          e.g.: /1,2,3,5,*2/60/10/
      //          - retry after 1,2,5, 5*2=10, 10*2=20, ...
      //          - each attempt fails after 60 units of time of trying
      //          - retry forever with a maximum retry of 10 times
      //
      //          e.g.: /1,*2:600/60/20/
      //          - retry after 1,2,5, 5*2=10, 10*2=20, ...
      //          - each attempt fails after 60 units of time of trying
      //          - retry with a maximum of 600 units of time up to a maximum
      //            of 20 retry attempts
      template <class TimeUnit>
      static IBackOffTimerPtr create(
                                     const char *pattern,                                                      // the timeout and retry backoff pattern to use
                                     size_t totalFailuresThusFar = 0,
                                     IBackOffTimerDelegatePtr delegate = IBackOffTimerDelegatePtr()
                                     ) {
        return create(pattern, std::chrono::duration_cast<Microseconds>(TimeUnit(1)), totalFailuresThusFar, delegate);
      }

      //-----------------------------------------------------------------------
      // PURPOSE: Creation function without option to specify total failures
      //          thus far.
      template <class TimeUnit>
      static IBackOffTimerPtr create(
                                     const char *pattern,                                                      // the timeout and retry backoff pattern to use
                                     IBackOffTimerDelegatePtr delegate
                                     ) {
        return create(pattern, std::chrono::duration_cast<Microseconds>(TimeUnit(1)), 0, delegate);
      }

      //-----------------------------------------------------------------------
      // PURPOSE: Subscribe to the backoff retry timer
      virtual IBackOffTimerSubscriptionPtr subscribe(IBackOffTimerDelegatePtr delegate) = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Stop the timer when it is no longer needed so events stop
      //          firing after this point
      virtual void cancel() = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Get the total failures thus far
      virtual size_t getTotalFailures() = 0;

      template <class TimeUnit>
      TimeUnit getNextRetryAfterWaitPeriod() {
        Microseconds result = actualGetNextRetryAfterWaitPeriod();
        if (Microseconds() == result) return TimeUnit();
        return std::chrono::duration_cast<TimeUnit>(result);
      }

      //-----------------------------------------------------------------------
      // PURPOSE: Get the time when the next retry after is supposed to occur
      virtual Time getNextRetryAfterTime() = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: After a retry attempt has occured has failed notify the
      //          retry after timer of the failure
      virtual void notifyFailure() = 0;

    protected:
      //-----------------------------------------------------------------------
      // PURPOSE: Create a backoff retry timer based upon a time out period
      static IBackOffTimerPtr create(
                                     const char *pattern,
                                     const Microseconds &unit,
                                     size_t totalFailuresThusFar = 0,
                                     IBackOffTimerDelegatePtr delegate = IBackOffTimerDelegatePtr()
                                     );

      //-----------------------------------------------------------------------
      // PURPOSE: Get the time when the next retry after is supposed to occur
      virtual Microseconds actualGetNextRetryAfterWaitPeriod() = 0;
    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IBackOffTimerDelegate
    #pragma mark

    interaction IBackOffTimerDelegate
    {
      //-----------------------------------------------------------------------
      // PURPOSE: notify another retry attempt should be made
      virtual void onBackOffTimerAttemptAgainNow(IBackOffTimerPtr timer) = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: notify an individual attempt should timeout now
      virtual void onBackOffTimerAttemptTimeout(IBackOffTimerPtr timer) = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: notify of a complete failure of all retries
      virtual void onBackOffTimerAllAttemptsFailed(IBackOffTimerPtr timer) = 0;
    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IBackOffTimerSubscription
    #pragma mark

    interaction IBackOffTimerSubscription
    {
      virtual PUID getID() const = 0;

      virtual void cancel() = 0;

      virtual void background() = 0;
    };
    
  }
}

ZS_DECLARE_PROXY_BEGIN(openpeer::services::IBackOffTimerDelegate)
ZS_DECLARE_PROXY_TYPEDEF(openpeer::services::IBackOffTimerPtr, IBackOffTimerPtr)
ZS_DECLARE_PROXY_METHOD_1(onBackOffTimerAttemptAgainNow, IBackOffTimerPtr)
ZS_DECLARE_PROXY_METHOD_1(onBackOffTimerAttemptTimeout, IBackOffTimerPtr)
ZS_DECLARE_PROXY_METHOD_1(onBackOffTimerAllAttemptsFailed, IBackOffTimerPtr)
ZS_DECLARE_PROXY_END()

ZS_DECLARE_PROXY_SUBSCRIPTIONS_BEGIN(openpeer::services::IBackOffTimerDelegate, openpeer::services::IBackOffTimerSubscription)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(openpeer::services::IBackOffTimerPtr, IBackOffTimerPtr)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_1(onBackOffTimerAttemptAgainNow, IBackOffTimerPtr)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_1(onBackOffTimerAttemptTimeout, IBackOffTimerPtr)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_1(onBackOffTimerAllAttemptsFailed, IBackOffTimerPtr)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_END()
