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

#include <ortc/services/internal/services_BackOffTimerPattern.h>
#include <ortc/services/internal/services.events.h>

#include <ortc/services/IHelper.h>

#include <zsLib/ISettings.h>
#include <zsLib/Numeric.h>
#include <zsLib/XML.h>

namespace ortc { namespace services { ZS_DECLARE_SUBSYSTEM(org_ortc_services) } }

namespace ortc
{
  namespace services
  {
    namespace internal
    {
      using services::IHelper;
      using zsLib::Numeric;

      typedef IBackOffTimerPattern::DurationType DurationType;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IBackOffTimerPatternForBackOffTimer
      //

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // BackOffTimerPattern
      //

      //-----------------------------------------------------------------------
      BackOffTimerPattern::BackOffTimerPattern(
                                               const make_private &,
                                               ElementPtr patternEl
                                               ) noexcept :
        SharedRecursiveLock(SharedRecursiveLock::create())
      {
        ZS_LOG_DEBUG(log("created"))

        if (patternEl) {
          try {
            mMaxAttempts = Numeric<decltype(mMaxAttempts)>(IHelper::getElementText(patternEl->findFirstChildElement("maxAttempts")));
          } catch(const Numeric<decltype(mMaxAttempts)>::ValueOutOfRange &) {
            ZS_LOG_WARNING(Debug, log("value out of range"))
          }

          // scope: attempt timesout vector
          {
            ElementPtr timeoutsEl = patternEl->findFirstChildElement("timeouts");

            ElementPtr timeoutEl = (timeoutsEl ? timeoutsEl->findFirstChildElement("timeout") : ElementPtr());
            while (timeoutEl) {

              try {
                DurationType::rep value = Numeric<DurationType::rep>(IHelper::getElementText(timeoutEl));
                mAttemptTimeoutVector.push_back(DurationType(value));
              } catch(const Numeric<DurationType::rep>::ValueOutOfRange &) {
                ZS_LOG_WARNING(Debug, log("value out of range"))
              }

              timeoutEl = timeoutEl->findNextSiblingElement("timeout");
            }
          }

          try {
            DurationType::rep value = Numeric<DurationType::rep>(IHelper::getElementText(patternEl->findFirstChildElement("maxTimeout")));
            mMaxAttemptTimeout = DurationType(value);
          } catch(const Numeric<DurationType::rep>::ValueOutOfRange &) {
            ZS_LOG_WARNING(Debug, log("value out of range"))
          }

          try {
            mAttemptTimeoutMultiplier = Numeric<decltype(mAttemptTimeoutMultiplier)>(IHelper::getElementText(patternEl->findFirstChildElement("timeoutMultiplier")));
          } catch(const Numeric<decltype(mAttemptTimeoutMultiplier)>::ValueOutOfRange &) {
            ZS_LOG_WARNING(Debug, log("value out of range"))
          }

          // scope: attempt timesout vector
          {
            ElementPtr retriesEl = patternEl->findFirstChildElement("retries");

            ElementPtr retryEl = (retriesEl ? retriesEl->findFirstChildElement("retry") : ElementPtr());
            while (retryEl) {

              try {
                DurationType::rep value = Numeric<DurationType::rep>(IHelper::getElementText(retryEl));
                mRetryVector.push_back(DurationType(value));
              } catch(const Numeric<DurationType::rep>::ValueOutOfRange &) {
                ZS_LOG_WARNING(Debug, log("value out of range"))
              }

              retryEl = retryEl->findNextSiblingElement("retry");
            }
          }
          
          try {
            mRetryMultiplier = Numeric<decltype(mRetryMultiplier)>(IHelper::getElementText(patternEl->findFirstChildElement("retryMultiplier")));
          } catch(const Numeric<decltype(mRetryMultiplier)>::ValueOutOfRange &) {
            ZS_LOG_WARNING(Debug, log("value out of range"))
          }

          try {
            DurationType::rep value = Numeric<DurationType::rep>(IHelper::getElementText(patternEl->findFirstChildElement("maxRetry")));
            mMaxRetry = DurationType(value);
          } catch(const Numeric<DurationType::rep>::ValueOutOfRange &) {
            ZS_LOG_WARNING(Debug, log("value out of range"))
          }
        }

        ZS_EVENTING_9(
                      x, i, Debug, ServicesBackOffTimerPatternCreate, os, BackOffTimerPattern, Start,
                      puid, id, mID,
                      size_t, maxAttempts, mMaxAttempts,
                      size_t, attemptTimeoutVectorSize, mAttemptTimeoutVector.size(),
                      duration, attemptTimeoutVectorFront, mAttemptTimeoutVector.size() > 0 ? mAttemptTimeoutVector.front().count() : 0,
                      double, attemptTimeoutMultiplier, mAttemptTimeoutMultiplier,
                      duration, maxAttemptTimeout, mMaxAttemptTimeout.count(),
                      duration, retryVectorFront, mRetryVector.size() > 0 ? mRetryVector.front().count() : 0,
                      double, retryMultiplier, mRetryMultiplier,
                      duration, maxRetry, mMaxRetry.count()
                      );
      }

      //-----------------------------------------------------------------------
      void BackOffTimerPattern::init() noexcept
      {
        AutoRecursiveLock lock(*this);
        if (mAttemptTimeoutVector.size() > 0) {
          mLastAttemptTimeout = mAttemptTimeoutVector[0];
          if (DurationType() != mMaxAttemptTimeout) {
            if (mLastAttemptTimeout > mMaxAttemptTimeout) mLastAttemptTimeout = mMaxAttemptTimeout;
          }
        }
        if (mRetryVector.size() > 0) {
          mLastRetryDuration = mRetryVector[0];
          if (DurationType() != mMaxRetry) {
            if (mLastRetryDuration > mMaxRetry) mLastAttemptTimeout = mMaxRetry;
          }
        }
      }

      //-----------------------------------------------------------------------
      BackOffTimerPattern::~BackOffTimerPattern() noexcept
      {
        mThisWeak.reset();
        ZS_LOG_DEBUG(log("destroyed"))

        ZS_EVENTING_1(x, i, Debug, ServicesBackOffTimerPatternDestroy, os, BackOffTimerPattern, Stop, puid, id, mID);
      }

      //-----------------------------------------------------------------------
      BackOffTimerPatternPtr BackOffTimerPattern::convert(IBackOffTimerPatternPtr timer) noexcept
      {
        return ZS_DYNAMIC_PTR_CAST(BackOffTimerPattern, timer);
      }

      //-----------------------------------------------------------------------
      BackOffTimerPatternPtr BackOffTimerPattern::convert(ForBackOffTimerPtr timer) noexcept
      {
        return ZS_DYNAMIC_PTR_CAST(BackOffTimerPattern, timer);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // BackOffTimerPattern => IBackOffTimerPattern
      //

      //-----------------------------------------------------------------------
      ElementPtr BackOffTimerPattern::toDebug(IBackOffTimerPatternPtr pattern) noexcept
      {
        if (!pattern) return ElementPtr();

        BackOffTimerPatternPtr pThis = BackOffTimerPattern::convert(pattern);
        return pThis->toDebug();
      }

      //-----------------------------------------------------------------------
      BackOffTimerPatternPtr BackOffTimerPattern::create(const char *pattern) noexcept
      {
        return BackOffTimerPattern::create(IHelper::toJSON(pattern));
      }

      //-----------------------------------------------------------------------
      BackOffTimerPatternPtr BackOffTimerPattern::create(ElementPtr patternEl) noexcept
      {
        BackOffTimerPatternPtr pThis(make_shared<BackOffTimerPattern>(make_private{}, patternEl));
        pThis->mThisWeak = pThis;
        pThis->init();
        return pThis;
      }

      //-----------------------------------------------------------------------
      String BackOffTimerPattern::save() const noexcept
      {
        ElementPtr patternEl = saveToJSON();
        return IHelper::toString(patternEl);
      }

      //-----------------------------------------------------------------------
      ElementPtr BackOffTimerPattern::saveToJSON() const noexcept
      {
        AutoRecursiveLock lock(*this);

        ElementPtr rootEl = Element::create("pattern");

        if (0 != mMaxAttempts) {
          rootEl->adoptAsLastChild(IHelper::createElementWithNumber("maxAttempts",string(mMaxAttempts)));
        }

        if (mAttemptTimeoutVector.size() > 0) {
          ElementPtr timeoutsEl = Element::create("timeouts");

          for (decltype(mAttemptTimeoutVector)::size_type loop = 0; loop < mAttemptTimeoutVector.size(); ++loop) {
            timeoutsEl->adoptAsLastChild(IHelper::createElementWithNumber("timeout", string(mAttemptTimeoutVector[loop].count())));
          }
          rootEl->adoptAsLastChild(timeoutsEl);
        }
        rootEl->adoptAsLastChild(IHelper::createElementWithNumber("timeoutMultiplier",string(mAttemptTimeoutMultiplier)));

        if (mRetryVector.size() > 0) {
          ElementPtr retriesEl = Element::create("retries");

          for (decltype(mRetryVector)::size_type loop = 0; loop < mRetryVector.size(); ++loop) {
            retriesEl->adoptAsLastChild(IHelper::createElementWithNumber("retry", string(mRetryVector[loop].count())));
          }
          rootEl->adoptAsLastChild(retriesEl);
        }
        rootEl->adoptAsLastChild(IHelper::createElementWithNumber("retryMultiplier",string(mRetryMultiplier)));

        return rootEl;
      }

      //-----------------------------------------------------------------------
      void BackOffTimerPattern::setMultiplierForLastAttemptTimeout(double multiplier) noexcept
      {
        AutoRecursiveLock lock(*this);
        mAttemptTimeoutMultiplier = multiplier;
      }

      //-----------------------------------------------------------------------
      void BackOffTimerPattern::setMaxAttempts(size_t maxAttempts) noexcept
      {
        AutoRecursiveLock lock(*this);
        mMaxAttempts = maxAttempts;
      }

      //-----------------------------------------------------------------------
      void BackOffTimerPattern::setMultiplierForLastRetryAfterFailureDuration(double multiplier) noexcept
      {
        AutoRecursiveLock lock(*this);
        mRetryMultiplier = multiplier;
      }

      //-----------------------------------------------------------------------
      void BackOffTimerPattern::actualAddNextAttemptTimeout(Microseconds attemptTimeout) noexcept
      {
        AutoRecursiveLock lock(*this);
        mAttemptTimeoutVector.push_back(attemptTimeout);
      }

      //-----------------------------------------------------------------------
      void BackOffTimerPattern::actualSetMaxAttemptTimeout(DurationType maxRetryDuration) noexcept
      {
        AutoRecursiveLock lock(*this);
        mMaxAttemptTimeout = maxRetryDuration;
      }

      //-----------------------------------------------------------------------
      void BackOffTimerPattern::actualAddNextRetryAfterFailureDuration(Microseconds nextRetryDuration) noexcept
      {
        AutoRecursiveLock lock(*this);
        mRetryVector.push_back(nextRetryDuration);
      }

      //-----------------------------------------------------------------------
      void BackOffTimerPattern::actualSetMaxRetryAfterFailureDuration(DurationType maxRetryDuration) noexcept
      {
        AutoRecursiveLock lock(*this);
        mMaxRetry = maxRetryDuration;
      }


      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // BackOffTimerPattern => IBackOffTimerPattern
      //


      //-----------------------------------------------------------------------
      BackOffTimerPattern::ForBackOffTimerPtr BackOffTimerPattern::clone() const noexcept
      {
        AutoRecursiveLock lock(*this);

        BackOffTimerPatternPtr pCopy(make_shared<BackOffTimerPattern>(make_private{}, ElementPtr()));
        pCopy->mThisWeak = pCopy;

        pCopy->mMaxAttempts = mMaxAttempts;
        pCopy->mAttemptTimeoutVector = mAttemptTimeoutVector;
        pCopy->mAttemptTimeoutMultiplier = mAttemptTimeoutMultiplier;
        pCopy->mMaxAttemptTimeout = mMaxAttemptTimeout;

        pCopy->mRetryVector = mRetryVector;
        pCopy->mRetryMultiplier = mRetryMultiplier;
        pCopy->mMaxRetry = mMaxRetry;

        ZS_EVENTING_2(x, i, Debug, ServicesBackOffTimerPatternClone, os, BackOffTimerPattern, Info, puid, id, mID, puid, cloneID, pCopy->mID);

        pCopy->init();

        return pCopy;
      }

      //-----------------------------------------------------------------------
      size_t BackOffTimerPattern::getMaxAttempts() const noexcept
      {
        AutoRecursiveLock lock(*this);
        return mMaxAttempts;
      }

      //-----------------------------------------------------------------------
      void BackOffTimerPattern::nextAttempt() noexcept
      {
        AutoRecursiveLock lock(*this);

        ++mAttemptNumber;

        if (mAttemptNumber < mAttemptTimeoutVector.size()) {
          mLastAttemptTimeout = mAttemptTimeoutVector[mAttemptNumber];
        } else {
          auto nextValue = mLastAttemptTimeout.count() * mAttemptTimeoutMultiplier;
          mLastAttemptTimeout = DurationType((DurationType::rep) nextValue);
        }
        if (DurationType() != mMaxAttemptTimeout) {
          if (mLastAttemptTimeout > mMaxAttemptTimeout) mLastAttemptTimeout = mMaxAttemptTimeout;
        }

        if (mAttemptNumber < mRetryVector.size()) {
          mLastRetryDuration = mRetryVector[mAttemptNumber];
        } else {
          auto nextValue = mLastRetryDuration.count() * mRetryMultiplier;
          mLastRetryDuration = DurationType((DurationType::rep) nextValue);
        }
        if (DurationType() != mMaxRetry) {
          if (mLastRetryDuration > mMaxRetry) mLastRetryDuration = mMaxRetry;
        }

        ZS_EVENTING_4(
                      x, i, Debug, ServicesBackOffTimerPatternNextAttempt, os, BackOffTimerPattern, Info,
                      puid, id, mID,
                      size_t, attemptNumber, mAttemptNumber,
                      duration, lastAttemptTimeout, mLastAttemptTimeout.count(),
                      duration, lastRetryDuration, mLastRetryDuration.count()
                      );
      }

      //-----------------------------------------------------------------------
      DurationType BackOffTimerPattern::getAttemptTimeout() noexcept
      {
        AutoRecursiveLock lock(*this);
        return mLastAttemptTimeout;
      }

      //-----------------------------------------------------------------------
      DurationType BackOffTimerPattern::getRetryAfterDuration() noexcept
      {
        AutoRecursiveLock lock(*this);
        return mLastRetryDuration;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // BackOffTimerPattern => (internal)
      //

      //-----------------------------------------------------------------------
      Log::Params BackOffTimerPattern::log(const char *message) const noexcept
      {
        ElementPtr objectEl = Element::create("services::BackOffTimerPattern");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params BackOffTimerPattern::slog(const char *message) noexcept
      {
        return Log::Params(message, "services::BackOffTimerPattern");
      }

      //-----------------------------------------------------------------------
      Log::Params BackOffTimerPattern::debug(const char *message) const noexcept
      {
        return Log::Params(message, toDebug());
      }

      //-----------------------------------------------------------------------
      ElementPtr BackOffTimerPattern::toDebug() const noexcept
      {
        AutoRecursiveLock lock(*this);

        ElementPtr resultEl = Element::create("services::BackOffTimerPattern");

        IHelper::debugAppend(resultEl, "id", mID);

        IHelper::debugAppend(resultEl, "max attempts", mMaxAttempts);

        if (mAttemptTimeoutVector.size() > 0) {
          ElementPtr timeoutsEl = Element::create("timeouts");

          for (decltype(mAttemptTimeoutVector)::size_type loop = 0; loop < mAttemptTimeoutVector.size(); ++loop) {
            IHelper::debugAppend(timeoutsEl, "timeout", string(mAttemptTimeoutVector[loop].count()));
          }

          IHelper::debugAppend(resultEl, timeoutsEl);
        }
        IHelper::debugAppend(resultEl, "attempt timeout multiplier", mAttemptTimeoutMultiplier);
        IHelper::debugAppend(resultEl, "max attempt timeout", mMaxAttemptTimeout);

        if (mRetryVector.size() > 0) {
          ElementPtr retriesEl = Element::create("retries");

          for (decltype(mRetryVector)::size_type loop = 0; loop < mRetryVector.size(); ++loop) {
            IHelper::debugAppend(retriesEl, "retry", string(mRetryVector[loop].count()));
          }
          IHelper::debugAppend(resultEl, retriesEl);
        }

        IHelper::debugAppend(resultEl, "retry multiplier", mRetryMultiplier);
        IHelper::debugAppend(resultEl, "max retry", mMaxRetry);

        IHelper::debugAppend(resultEl, "attempt number", mAttemptNumber);

        IHelper::debugAppend(resultEl, "last attempt timeout", mLastAttemptTimeout);
        IHelper::debugAppend(resultEl, "last retry timeout", mLastRetryDuration);

        return resultEl;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IBackOffTimerPatternFactory
      //

      //-----------------------------------------------------------------------
      IBackOffTimerPatternFactory &IBackOffTimerPatternFactory::singleton() noexcept
      {
        return BackOffTimerPatternFactory::singleton();
      }

      //-----------------------------------------------------------------------
      BackOffTimerPatternPtr IBackOffTimerPatternFactory::create(const char *pattern) noexcept
      {
        if (this) {}
        return BackOffTimerPattern::create(pattern);
      }

      //-----------------------------------------------------------------------
      BackOffTimerPatternPtr IBackOffTimerPatternFactory::create(ElementPtr pattern) noexcept
      {
        if (this) {}
        return BackOffTimerPattern::create(pattern);
      }

    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //
    // IBackOffTimerPattern
    //

    //-------------------------------------------------------------------------
    ElementPtr IBackOffTimerPattern::toDebug(IBackOffTimerPatternPtr timer) noexcept
    {
      return internal::BackOffTimerPattern::toDebug(timer);
    }

    //-------------------------------------------------------------------------
    IBackOffTimerPatternPtr IBackOffTimerPattern::create(const char *pattern) noexcept
    {
      return internal::IBackOffTimerPatternFactory::singleton().create(pattern);
    }

    //-------------------------------------------------------------------------
    IBackOffTimerPatternPtr IBackOffTimerPattern::create(ElementPtr pattern) noexcept
    {
      return internal::IBackOffTimerPatternFactory::singleton().create(pattern);
    }
  }
}

