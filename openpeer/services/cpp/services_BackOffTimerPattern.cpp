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

#include <openpeer/services/internal/services_BackOffTimerPattern.h>
#include <openpeer/services/internal/services_Tracing.h>

#include <openpeer/services/IHelper.h>
#include <openpeer/services/ISettings.h>

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

      typedef IBackOffTimerPattern::DurationType DurationType;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IBackOffTimerPatternForBackOffTimer
      #pragma mark

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark BackOffTimerPattern
      #pragma mark

      //-----------------------------------------------------------------------
      BackOffTimerPattern::BackOffTimerPattern(
                                               const make_private &,
                                               ElementPtr patternEl
                                               ) :
        SharedRecursiveLock(SharedRecursiveLock::create())
      {
        ZS_LOG_DEBUG(log("created"))

        if (patternEl) {
          try {
            mMaxAttempts = Numeric<decltype(mMaxAttempts)>(IHelper::getElementText(patternEl->findFirstChildElement("maxAttempts")));
          } catch(Numeric<decltype(mMaxAttempts)>::ValueOutOfRange &) {
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
              } catch(Numeric<DurationType::rep>::ValueOutOfRange &) {
                ZS_LOG_WARNING(Debug, log("value out of range"))
              }

              timeoutEl = timeoutEl->findNextSiblingElement("timeout");
            }
          }

          try {
            DurationType::rep value = Numeric<DurationType::rep>(IHelper::getElementText(patternEl->findFirstChildElement("maxTimeout")));
            mMaxAttemptTimeout = DurationType(value);
          } catch(Numeric<DurationType::rep>::ValueOutOfRange &) {
            ZS_LOG_WARNING(Debug, log("value out of range"))
          }

          try {
            mAttemptTimeoutMultiplier = Numeric<decltype(mAttemptTimeoutMultiplier)>(IHelper::getElementText(patternEl->findFirstChildElement("timeoutMultiplier")));
          } catch(Numeric<decltype(mAttemptTimeoutMultiplier)>::ValueOutOfRange &) {
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
              } catch(Numeric<DurationType::rep>::ValueOutOfRange &) {
                ZS_LOG_WARNING(Debug, log("value out of range"))
              }

              retryEl = retryEl->findNextSiblingElement("retry");
            }
          }
          
          try {
            mRetryMultiplier = Numeric<decltype(mRetryMultiplier)>(IHelper::getElementText(patternEl->findFirstChildElement("retryMultiplier")));
          } catch(Numeric<decltype(mRetryMultiplier)>::ValueOutOfRange &) {
            ZS_LOG_WARNING(Debug, log("value out of range"))
          }

          try {
            DurationType::rep value = Numeric<DurationType::rep>(IHelper::getElementText(patternEl->findFirstChildElement("maxRetry")));
            mMaxRetry = DurationType(value);
          } catch(Numeric<DurationType::rep>::ValueOutOfRange &) {
            ZS_LOG_WARNING(Debug, log("value out of range"))
          }
        }

        EventWriteOpServicesBackOffTimerPatternCreate(
                                                      __func__,
                                                      mID,
                                                      mMaxAttempts,
                                                      mAttemptTimeoutVector.size(),
                                                      mAttemptTimeoutVector.size() > 0 ? mAttemptTimeoutVector.front().count() : 0,
                                                      mAttemptTimeoutMultiplier,
                                                      mMaxAttemptTimeout.count(),
                                                      mRetryVector.size(), mRetryVector.size() > 0 ? mRetryVector.front().count() : 0,
                                                      mRetryMultiplier,
                                                      mMaxRetry.count()
                                                      );
      }

      //-----------------------------------------------------------------------
      void BackOffTimerPattern::init()
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
      BackOffTimerPattern::~BackOffTimerPattern()
      {
        mThisWeak.reset();
        ZS_LOG_DEBUG(log("destroyed"))

        EventWriteOpServicesBackOffTimerPatternDestroy(__func__, mID);
      }

      //-----------------------------------------------------------------------
      BackOffTimerPatternPtr BackOffTimerPattern::convert(IBackOffTimerPatternPtr timer)
      {
        return ZS_DYNAMIC_PTR_CAST(BackOffTimerPattern, timer);
      }

      //-----------------------------------------------------------------------
      BackOffTimerPatternPtr BackOffTimerPattern::convert(ForBackOffTimerPtr timer)
      {
        return ZS_DYNAMIC_PTR_CAST(BackOffTimerPattern, timer);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark BackOffTimerPattern => IBackOffTimerPattern
      #pragma mark

      //-----------------------------------------------------------------------
      ElementPtr BackOffTimerPattern::toDebug(IBackOffTimerPatternPtr pattern)
      {
        if (!pattern) return ElementPtr();

        BackOffTimerPatternPtr pThis = BackOffTimerPattern::convert(pattern);
        return pThis->toDebug();
      }

      //-----------------------------------------------------------------------
      BackOffTimerPatternPtr BackOffTimerPattern::create(const char *pattern)
      {
        return BackOffTimerPattern::create(IHelper::toJSON(pattern));
      }

      //-----------------------------------------------------------------------
      BackOffTimerPatternPtr BackOffTimerPattern::create(ElementPtr patternEl)
      {
        BackOffTimerPatternPtr pThis(make_shared<BackOffTimerPattern>(make_private{}, patternEl));
        pThis->mThisWeak = pThis;
        pThis->init();
        return pThis;
      }

      //-----------------------------------------------------------------------
      String BackOffTimerPattern::save() const
      {
        ElementPtr patternEl = saveToJSON();
        return IHelper::toString(patternEl);
      }

      //-----------------------------------------------------------------------
      ElementPtr BackOffTimerPattern::saveToJSON() const
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
      void BackOffTimerPattern::setMultiplierForLastAttemptTimeout(double multiplier)
      {
        AutoRecursiveLock lock(*this);
        mAttemptTimeoutMultiplier = multiplier;
      }

      //-----------------------------------------------------------------------
      void BackOffTimerPattern::setMaxAttempts(size_t maxAttempts)
      {
        AutoRecursiveLock lock(*this);
        mMaxAttempts = maxAttempts;
      }

      //-----------------------------------------------------------------------
      void BackOffTimerPattern::setMultiplierForLastRetryAfterFailureDuration(double multiplier)
      {
        AutoRecursiveLock lock(*this);
        mRetryMultiplier = multiplier;
      }

      //-----------------------------------------------------------------------
      void BackOffTimerPattern::actualAddNextAttemptTimeout(Microseconds attemptTimeout)
      {
        AutoRecursiveLock lock(*this);
        mAttemptTimeoutVector.push_back(attemptTimeout);
      }

      //-----------------------------------------------------------------------
      void BackOffTimerPattern::actualSetMaxAttemptTimeout(DurationType maxRetryDuration)
      {
        AutoRecursiveLock lock(*this);
        mMaxAttemptTimeout = maxRetryDuration;
      }

      //-----------------------------------------------------------------------
      void BackOffTimerPattern::actualAddNextRetryAfterFailureDuration(Microseconds nextRetryDuration)
      {
        AutoRecursiveLock lock(*this);
        mRetryVector.push_back(nextRetryDuration);
      }

      //-----------------------------------------------------------------------
      void BackOffTimerPattern::actualSetMaxRetryAfterFailureDuration(DurationType maxRetryDuration)
      {
        AutoRecursiveLock lock(*this);
        mMaxRetry = maxRetryDuration;
      }


      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark BackOffTimerPattern => IBackOffTimerPattern
      #pragma mark


      //-----------------------------------------------------------------------
      BackOffTimerPattern::ForBackOffTimerPtr BackOffTimerPattern::clone() const
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

        EventWriteOpServicesBackOffTimerPatternClone(__func__, pCopy->mID, mID);

        pCopy->init();

        return pCopy;
      }

      //-----------------------------------------------------------------------
      size_t BackOffTimerPattern::getMaxAttempts() const
      {
        AutoRecursiveLock lock(*this);
        return mMaxAttempts;
      }

      //-----------------------------------------------------------------------
      void BackOffTimerPattern::nextAttempt()
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

        EventWriteOpServicesBackOffTimerPatternNextAttempt(__func__, mID, mAttemptNumber, mLastAttemptTimeout.count(), mLastRetryDuration.count());
      }

      //-----------------------------------------------------------------------
      DurationType BackOffTimerPattern::getAttemptTimeout()
      {
        AutoRecursiveLock lock(*this);
        return mLastAttemptTimeout;
      }

      //-----------------------------------------------------------------------
      DurationType BackOffTimerPattern::getRetryAfterDuration()
      {
        AutoRecursiveLock lock(*this);
        return mLastRetryDuration;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark BackOffTimerPattern => (internal)
      #pragma mark

      //-----------------------------------------------------------------------
      Log::Params BackOffTimerPattern::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("services::BackOffTimerPattern");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params BackOffTimerPattern::slog(const char *message)
      {
        return Log::Params(message, "services::BackOffTimerPattern");
      }

      //-----------------------------------------------------------------------
      Log::Params BackOffTimerPattern::debug(const char *message) const
      {
        return Log::Params(message, toDebug());
      }

      //-----------------------------------------------------------------------
      ElementPtr BackOffTimerPattern::toDebug() const
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
      #pragma mark
      #pragma mark IBackOffTimerPatternFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IBackOffTimerPatternFactory &IBackOffTimerPatternFactory::singleton()
      {
        return BackOffTimerPatternFactory::singleton();
      }

      //-----------------------------------------------------------------------
      BackOffTimerPatternPtr IBackOffTimerPatternFactory::create(const char *pattern)
      {
        if (this) {}
        return BackOffTimerPattern::create(pattern);
      }

      //-----------------------------------------------------------------------
      BackOffTimerPatternPtr IBackOffTimerPatternFactory::create(ElementPtr pattern)
      {
        if (this) {}
        return BackOffTimerPattern::create(pattern);
      }

    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IBackOffTimerPattern
    #pragma mark

    //-------------------------------------------------------------------------
    ElementPtr IBackOffTimerPattern::toDebug(IBackOffTimerPatternPtr timer)
    {
      return internal::BackOffTimerPattern::toDebug(timer);
    }

    //-------------------------------------------------------------------------
    IBackOffTimerPatternPtr IBackOffTimerPattern::create(const char *pattern)
    {
      return internal::IBackOffTimerPatternFactory::singleton().create(pattern);
    }

    //-------------------------------------------------------------------------
    IBackOffTimerPatternPtr IBackOffTimerPattern::create(ElementPtr pattern)
    {
      return internal::IBackOffTimerPatternFactory::singleton().create(pattern);
    }
  }
}

