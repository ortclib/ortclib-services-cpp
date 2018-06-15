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

#include <zsLib/Log.h>

namespace ortc
{
  namespace services
  {
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //
    // IBackOffTimerPattern
    //

    interaction IBackOffTimerPattern
    {
      typedef Microseconds DurationType;

      static ElementPtr toDebug(IBackOffTimerPatternPtr pattern) noexcept;

      static IBackOffTimerPatternPtr create(const char *pattern = NULL) noexcept;
      static IBackOffTimerPatternPtr create(ElementPtr patternEl) noexcept;

      virtual PUID getID() const noexcept = 0;

      virtual String save() const noexcept = 0;
      virtual ElementPtr saveToJSON() const noexcept = 0;

      //-----------------------------------------------------------------------
      // attempt setters

      template <class TimeUnit>
      void addNextAttemptTimeout(TimeUnit attemptTimeout) noexcept {actualAddNextAttemptTimeout(std::chrono::duration_cast<DurationType>(attemptTimeout));}

      virtual void setMultiplierForLastAttemptTimeout(double multiplier) noexcept = 0;

      virtual void setMaxAttempts(size_t maxAttempts) noexcept = 0;

      template <class TimeUnit>
      void setMaxAttemptTimeout(TimeUnit maxTimeout) noexcept {actualSetMaxAttemptTimeout(std::chrono::duration_cast<DurationType>(maxTimeout));}

      //-----------------------------------------------------------------------
      // retry setters

      template <class TimeUnit>
      void addNextRetryAfterFailureDuration(TimeUnit nextRetryDuration) noexcept {actualAddNextRetryAfterFailureDuration(std::chrono::duration_cast<DurationType>(nextRetryDuration));}

      virtual void setMultiplierForLastRetryAfterFailureDuration(double multiplier) noexcept = 0;

      template <class TimeUnit>
      void setMaxRetryAfterFailureDuration(TimeUnit maxRetryDuration) noexcept {actualSetMaxRetryAfterFailureDuration(std::chrono::duration_cast<DurationType>(maxRetryDuration));}


    protected:
      virtual void actualAddNextAttemptTimeout(DurationType attemptTimeout) noexcept = 0;
      virtual void actualSetMaxAttemptTimeout(DurationType maxRetryDuration) noexcept = 0;

      virtual void actualAddNextRetryAfterFailureDuration(DurationType nextRetryDuration) noexcept = 0;
      virtual void actualSetMaxRetryAfterFailureDuration(DurationType maxRetryDuration) noexcept = 0;
    };

  }
}
