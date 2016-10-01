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

#include <ortc/services/types.h>
#include <ortc/services/IBackOffTimerPattern.h>

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
      typedef IBackOffTimerPattern::DurationType DurationType;

      enum States
      {
        State_AttemptNow,
        State_Attempting,
        State_WaitingAfterAttemptFailure,

        State_AllAttemptsFailed,

        State_Succeeded,
      };

      static const char *toString(States state);

      //-----------------------------------------------------------------------
      // PURPOSE: returns a debug element containing internal object state
      static ElementPtr toDebug(IBackOffTimerPtr timer);

      //-----------------------------------------------------------------------
      // PURPOSE: Create a backoff timer using a pre-created pattern
      static IBackOffTimerPtr create(
                                     IBackOffTimerPatternPtr pattern,
                                     size_t totalFailuresThusFar = 0,
                                     IBackOffTimerDelegatePtr delegate = IBackOffTimerDelegatePtr()
                                     );

      //-----------------------------------------------------------------------
      // PURPOSE: Create a backoff timer using a pattern
      static IBackOffTimerPtr create(
                                     IBackOffTimerPatternPtr pattern,
                                     IBackOffTimerDelegatePtr delegate
                                     ) {
        return create(pattern, 0, delegate);
      }

      //-----------------------------------------------------------------------
      // PURPOSE: Create a backoff timer using a previuosly saved pattern
      static IBackOffTimerPtr create(
                                     const char *pattern,
                                     IBackOffTimerDelegatePtr delegate
                                     ) {
        return create(IBackOffTimerPattern::create(pattern), 0, delegate);
      }

      //-----------------------------------------------------------------------
      // PURPOSE: Create a backoff timer using a previuosly saved pattern
      static IBackOffTimerPtr create(
                                     const char *pattern,
                                     size_t totalFailuresThusFar = 0,
                                     IBackOffTimerDelegatePtr delegate = IBackOffTimerDelegatePtr()
                                     ) {
        return create(IBackOffTimerPattern::create(pattern), totalFailuresThusFar, delegate);
      }

      //-----------------------------------------------------------------------
      // PURPOSE: Subscribe to the backoff retry timer
      virtual IBackOffTimerSubscriptionPtr subscribe(IBackOffTimerDelegatePtr delegate) = 0;

      //-----------------------------------------------------------------------
      virtual PUID getID() const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Stop the timer when it is no longer needed so events stop
      //          firing after this point
      virtual void cancel() = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Get the timeout pattern in use
      virtual IBackOffTimerPatternPtr getPattern() const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Get the attempt number happening right now (0 based)
      virtual size_t getAttemptNumber() const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Get the total failures thus far
      virtual size_t getTotalFailures() const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Returns the current backoff timer state
      virtual States getState() const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Returns true if an attempt should be attempted at this time
      bool shouldAttemptNow() const {return State_AttemptNow == getState();}

      //-----------------------------------------------------------------------
      // PURPOSE: Returns true if an attempt is in progress
      bool isAttempting() const {return State_Attempting == getState();}

      //-----------------------------------------------------------------------
      // PURPOSE: Returns true if the attempt failed (and must wait until
      //          next attempt)
      bool isWaitingForNextAttempt() const {return State_WaitingAfterAttemptFailure == getState();}

      //-----------------------------------------------------------------------
      // PURPOSE: Returns true if an attempt is in progress
      bool isComplete() const {auto state = getState(); return ((State_AllAttemptsFailed == state) || (State_Succeeded == state));}

      //-----------------------------------------------------------------------
      // PURPOSE: Returns true if an attempt is in progress
      bool haveAllAttemptsFailed() const {return State_AllAttemptsFailed == getState();}

      //-----------------------------------------------------------------------
      // PURPOSE: Returns true if an attempt is in progress
      bool isSuccessful() const {return State_Succeeded == getState();}

      //-----------------------------------------------------------------------
      // PURPOSE: Get the wait duration of the next retry after period
      template <class TimeUnit>
      TimeUnit getNextRetryAfterFailureDuration() {return std::chrono::duration_cast<TimeUnit>(actualGetNextRetryAfterFailureDuration());}

      //-----------------------------------------------------------------------
      // PURPOSE: Get the time when the next retry after is supposed to occur
      virtual Time getNextRetryAfterTime() const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Notify the engine that an attempt has failed
      // NOTES:   Must be in the "State_AttemptNow" or call is ignored
      virtual void notifyAttempting() = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Notify the engine that an attempt has failed
      // NOTES:   Must be in the "State_Attempting" or call is ignored
      virtual void notifyAttemptFailed() = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Notify the engine that an attempt should be made again
      // NOTES:   Must be in the "State_WaitingAfterAttemptFailure"
      //          or call is ignored
      virtual void notifyTryAgainNow() = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Notify the engine that an attempt should be made again
      // NOTES:   Must be in the "State_WaitingAfterAttemptFailure"
      //          or call is ignored
      virtual void notifySucceeded() = 0;

    protected:
      //-----------------------------------------------------------------------
      // PURPOSE: Get the time when the next retry after is supposed to occur
      virtual DurationType actualGetNextRetryAfterFailureDuration() = 0;
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
      typedef IBackOffTimer::States States;

      virtual void onBackOffTimerStateChanged(
                                              IBackOffTimerPtr timer,
                                              States state
                                              ) = 0;
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
ZS_DECLARE_PROXY_TYPEDEF(openpeer::services::IBackOffTimer::States, States)
ZS_DECLARE_PROXY_METHOD_2(onBackOffTimerStateChanged, IBackOffTimerPtr, States)
ZS_DECLARE_PROXY_END()

ZS_DECLARE_PROXY_SUBSCRIPTIONS_BEGIN(openpeer::services::IBackOffTimerDelegate, openpeer::services::IBackOffTimerSubscription)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(openpeer::services::IBackOffTimerPtr, IBackOffTimerPtr)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(openpeer::services::IBackOffTimer::States, States)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_2(onBackOffTimerStateChanged, IBackOffTimerPtr, States)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_END()
