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

#include <ortc/services/internal/services_STUNRequester.h>
#include <ortc/services/internal/services_STUNRequesterManager.h>
#include <ortc/services/internal/services.events.h>

#include <ortc/services/IBackOffTimerPattern.h>
#include <ortc/services/IHelper.h>

#include <zsLib/Exception.h>
#include <zsLib/helpers.h>
#include <zsLib/Log.h>
#include <zsLib/XML.h>
#include <zsLib/Stringize.h>

#define ORTC_SERVICES_STUN_REQUESTER_DEFAULT_BACKOFF_TIMER_MAX_ATTEMPTS (6)

namespace ortc { namespace services { ZS_DECLARE_SUBSYSTEM(org_ortc_services_stun) } }

namespace ortc
{
  namespace services
  {
    namespace internal
    {
      ZS_DECLARE_TYPEDEF_PTR(ISTUNRequesterManagerForSTUNRequester, UseSTUNRequesterManager)

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark STUNRequester
      #pragma mark

      //-----------------------------------------------------------------------
      STUNRequester::STUNRequester(
                                   const make_private &,
                                   IMessageQueuePtr queue,
                                   ISTUNRequesterDelegatePtr delegate,
                                   IPAddress serverIP,
                                   STUNPacketPtr stun,
                                   STUNPacket::RFCs usingRFC,
                                   IBackOffTimerPatternPtr pattern
                                   ) :
        MessageQueueAssociator(queue),
        mDelegate(ISTUNRequesterDelegateProxy::createWeak(queue, delegate)),
        mSTUNRequest(stun),
        mServerIP(serverIP),
        mUsingRFC(usingRFC),
        mBackOffTimerPattern(pattern)
      {
        if (!mBackOffTimerPattern) {
          mBackOffTimerPattern = IBackOffTimerPattern::create();
          mBackOffTimerPattern->setMaxAttempts(ORTC_SERVICES_STUN_REQUESTER_DEFAULT_BACKOFF_TIMER_MAX_ATTEMPTS);
          mBackOffTimerPattern->addNextAttemptTimeout(Milliseconds(500));
          mBackOffTimerPattern->setMultiplierForLastAttemptTimeout(2.0);
          mBackOffTimerPattern->addNextRetryAfterFailureDuration(Milliseconds(1));
        }

        //ServicesStunRequesterCreate(__func__, mID, serverIP.string(), zsLib::to_underlying(usingRFC), mBackOffTimerPattern->getID());
        ZS_EVENTING_4(
                      x, i, Debug, ServicesStunRequesterCreate, os, StunRequester, Start,
                      puid, id, mID,
                      string, serverIp, serverIP.string(),
                      enum, usingRfc, zsLib::to_underlying(usingRFC),
                      puid, backoffTimerPatterId, mBackOffTimerPattern->getID()
                      );
      }

      //-----------------------------------------------------------------------
      STUNRequester::~STUNRequester()
      {
        if(isNoop()) return;
        
        mThisWeak.reset();
        cancel();

        //ServicesStunRequesterDestroy(__func__, mID);
        ZS_EVENTING_1(x, i, Debug, ServicesStunRequesterDestroy, os, StunRequester, Start, puid, id, mID);
      }

      //-----------------------------------------------------------------------
      void STUNRequester::init()
      {
        AutoRecursiveLock lock(mLock);
        UseSTUNRequesterManagerPtr manager = UseSTUNRequesterManager::singleton();
        if (manager) {
          manager->monitorStart(mThisWeak.lock(), mSTUNRequest);
        }
        step();
      }

      //-----------------------------------------------------------------------
      STUNRequesterPtr STUNRequester::convert(ISTUNRequesterPtr object)
      {
        return ZS_DYNAMIC_PTR_CAST(STUNRequester, object);
      }

      //-----------------------------------------------------------------------
      STUNRequesterPtr STUNRequester::convert(ForSTUNRequesterManagerPtr object)
      {
        return ZS_DYNAMIC_PTR_CAST(STUNRequester, object);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark STUNRequester => STUNRequester
      #pragma mark

      //-----------------------------------------------------------------------
      STUNRequesterPtr STUNRequester::create(
                                             IMessageQueuePtr queue,
                                             ISTUNRequesterDelegatePtr delegate,
                                             IPAddress serverIP,
                                             STUNPacketPtr stun,
                                             STUNPacket::RFCs usingRFC,
                                             IBackOffTimerPatternPtr pattern
                                             )
      {
        ZS_THROW_INVALID_USAGE_IF(!delegate)
        ZS_THROW_INVALID_USAGE_IF(!stun)
        ZS_THROW_INVALID_USAGE_IF(serverIP.isAddressEmpty())
        ZS_THROW_INVALID_USAGE_IF(serverIP.isPortEmpty())

        STUNRequesterPtr pThis(make_shared<STUNRequester>(make_private{}, queue, delegate, serverIP, stun, usingRFC, pattern));
        pThis->mThisWeak = pThis;
        pThis->init();
        return pThis;
      }

      //-----------------------------------------------------------------------
      bool STUNRequester::isComplete() const
      {
        AutoRecursiveLock lock(mLock);
        if (!mDelegate) return true;
        return false;
      }

      //-----------------------------------------------------------------------
      void STUNRequester::cancel()
      {
        //ServicesStunRequesterCancel(__func__, mID);
        ZS_EVENTING_1(x, i, Debug, ServicesStunRequesterCancel, os, StunRequester, Cancel, puid, id, mID);

        AutoRecursiveLock lock(mLock);

        ZS_LOG_TRACE(log("cancel called") + mSTUNRequest->toDebug())

        mServerIP.clear();

        if (mDelegate) {
          mDelegate.reset();

          // tie the lifetime of the monitoring to the delegate
          UseSTUNRequesterManagerPtr manager = UseSTUNRequesterManager::singleton();
          if (manager) {
            manager->monitorStop(*this);
          }
        }
      }

      //-----------------------------------------------------------------------
      void STUNRequester::retryRequestNow()
      {
        //ServicesStunRequesterRetryNow(__func__, mID);
        ZS_EVENTING_1(x, i, Trace, ServicesStunRequesterRetryNow, os, StunRequester, RetryNow, puid, id, mID);

        AutoRecursiveLock lock(mLock);

        ZS_LOG_DEBUG(log("retry request now") + mSTUNRequest->toDebug())

        if (mBackOffTimer) {
          mBackOffTimer->cancel();
          mBackOffTimer.reset();
        }

        step();
      }

      //-----------------------------------------------------------------------
      IPAddress STUNRequester::getServerIP() const
      {
        AutoRecursiveLock lock(mLock);
        return mServerIP;
      }

      //-----------------------------------------------------------------------
      STUNPacketPtr STUNRequester::getRequest() const
      {
        AutoRecursiveLock lock(mLock);
        return mSTUNRequest;
      }

      //-----------------------------------------------------------------------
      IBackOffTimerPatternPtr STUNRequester::getBackOffTimerPattern() const
      {
        AutoRecursiveLock lock(mLock);
        return mBackOffTimerPattern;
      }

      //-----------------------------------------------------------------------
      size_t STUNRequester::getTotalTries() const
      {
        AutoRecursiveLock lock(mLock);
        return mTotalTries;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark STUNRequester => ISTUNRequesterForSTUNRequesterManager
      #pragma mark

      //-----------------------------------------------------------------------
      bool STUNRequester::handleSTUNPacket(
                                           IPAddress fromIPAddress,
                                           STUNPacketPtr packet
                                           )
      {
        //ServicesStunRequesterReceivedStunPacket(__func__, mID, fromIPAddress.string());
        ZS_EVENTING_2(x, i, Debug, ServicesStunRequesterReceivedStunPacket, os, StunRequester, Receive, puid, id, mID, string, fromIpAddress, fromIPAddress.string());

        ZS_EVENTING_TRACE_OBJECT(Trace, *packet, "stun requester handle packet");

        ISTUNRequesterDelegatePtr delegate;

        // find out if this was truly handled
        {
          AutoRecursiveLock lock(mLock);

          if (!mSTUNRequest) return false;

          if (!packet->isValidResponseTo(mSTUNRequest, mUsingRFC)) {
            ZS_LOG_TRACE(log("determined this response is not a proper validated response") + packet->toDebug())
            return false;
          }

          delegate = mDelegate;
        }

        bool success = true;

        // we now have a reply, inform the delegate...
        // NOTE:  We inform the delegate syncrhonously thus we cannot call
        //        the delegate from inside a lock in case the delegate is
        //        calling us (that would cause a potential deadlock).
        if (delegate) {
          try {
            success = delegate->handleSTUNRequesterResponse(mThisWeak.lock(), fromIPAddress, packet);  // this is a success! yay! inform the delegate
          } catch(ISTUNRequesterDelegateProxy::Exceptions::DelegateGone &) {
          }
        }

        if (!success)
          return false;

        // clear out the request since it's now complete
        {
          AutoRecursiveLock lock(mLock);
          if (ZS_IS_LOGGING(Trace)) {
            ZS_LOG_BASIC(log("handled") + ZS_PARAM("ip", mServerIP.string()) + ZS_PARAM("request", mSTUNRequest->toDebug()) + ZS_PARAM("response", packet->toDebug()))
          }
          cancel();
        }
        return true;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark STUNRequester => ITimerDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void STUNRequester::onBackOffTimerStateChanged(
                                                     IBackOffTimerPtr timer,
                                                     IBackOffTimer::States state
                                                     )
      {
        //ServicesStunRequesterBackOffTimerStateEvent(__func__, mID, timer->getID(), IBackOffTimer::toString(state), mTotalTries);
        ZS_EVENTING_4(
                      x, i, Trace, ServicesStunRequesterBackOffTimerStateEvent, os, StunRequester, InternalEvent,
                      puid, id, mID,
                      puid, timerId, timer->getID(),
                      string, backoffTimerState, IBackOffTimer::toString(state),
                      ulong, totalTries, mTotalTries
                      );

        AutoRecursiveLock lock(mLock);

        ZS_LOG_TRACE(log("backoff timer state changed") + ZS_PARAM("timer id", timer->getID()) + ZS_PARAM("state", IBackOffTimer::toString(state)) + ZS_PARAM("total tries", mTotalTries))
        step();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark STUNRequester => (internal)
      #pragma mark

      //-----------------------------------------------------------------------
      Log::Params STUNRequester::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("STUNRequester");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      void STUNRequester::step()
      {
        if (!mDelegate) return;                                                 // if there is no delegate then the request has completed or is cancelled
        if (mServerIP.isAddressEmpty()) return;

        if (!mBackOffTimer) {
          mBackOffTimer = IBackOffTimer::create(mBackOffTimerPattern, mThisWeak.lock());
        }

        if (mBackOffTimer->haveAllAttemptsFailed()) {
          try {
            mDelegate->onSTUNRequesterTimedOut(mThisWeak.lock());
          } catch(ISTUNRequesterDelegateProxy::Exceptions::DelegateGone &) {
            ZS_LOG_WARNING(Debug, log("delegate gone"))
          }

          cancel();
          return;
        }

        if (mBackOffTimer->shouldAttemptNow()) {
          mBackOffTimer->notifyAttempting();

          ZS_LOG_TRACE(log("sending packet now") + ZS_PARAM("ip", mServerIP.string()) + ZS_PARAM("tries", mTotalTries) + ZS_PARAM("stun packet", mSTUNRequest->toDebug()))

          // send off the packet NOW
          SecureByteBlockPtr packet = mSTUNRequest->packetize(mUsingRFC);

          //ServicesStunRequesterSendPacket(__func__, mID, packet->SizeInBytes(), packet->BytePtr());
          ZS_EVENTING_3(
                        x, i, Trace, ServicesStunRequesterSendPacket, os, StunRequester, Send,
                        puid, id, mID,
                        binary, packet, packet->BytePtr(),
                        size, size, packet->SizeInBytes()
                        );

          ZS_EVENTING_TRACE_OBJECT(Trace, *mSTUNRequest, "stun requester send packet");

          try {
            ++mTotalTries;
            mDelegate->onSTUNRequesterSendPacket(mThisWeak.lock(), mServerIP, packet);
          } catch(ISTUNRequesterDelegateProxy::Exceptions::DelegateGone &) {
            ZS_LOG_WARNING(Trace, log("delegate gone thus cancelling requester"))
            cancel();
            return;
          }
        }

        // nothing more to do... sit back, relax and enjoy the ride!
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ISTUNRequesterFactory
      #pragma mark

      //-----------------------------------------------------------------------
      ISTUNRequesterFactory &ISTUNRequesterFactory::singleton()
      {
        return STUNRequesterFactory::singleton();
      }

      //-----------------------------------------------------------------------
      STUNRequesterPtr ISTUNRequesterFactory::create(
                                                     IMessageQueuePtr queue,
                                                     ISTUNRequesterDelegatePtr delegate,
                                                     IPAddress serverIP,
                                                     STUNPacketPtr stun,
                                                     STUNPacket::RFCs usingRFC,
                                                     IBackOffTimerPatternPtr pattern
                                                     )
      {
        if (this) {}
        return STUNRequester::create(queue, delegate, serverIP, stun, usingRFC, pattern);
      }

    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark ISTUNRequester
    #pragma mark

    //-------------------------------------------------------------------------
    ISTUNRequesterPtr ISTUNRequester::create(
                                             IMessageQueuePtr queue,
                                             ISTUNRequesterDelegatePtr delegate,
                                             IPAddress serverIP,
                                             STUNPacketPtr stun,
                                             STUNPacket::RFCs usingRFC,
                                             IBackOffTimerPatternPtr pattern
                                             )
    {
      return internal::ISTUNRequesterFactory::singleton().create(queue, delegate, serverIP, stun, usingRFC, pattern);
    }

    //-------------------------------------------------------------------------
    bool ISTUNRequester::handlePacket(
                                      IPAddress fromIPAddress,
                                      const BYTE *packet,
                                      size_t packetLengthInBytes,
                                      const STUNPacket::ParseOptions &options
                                      )
    {
      return (bool)ISTUNRequesterManager::handlePacket(fromIPAddress, packet, packetLengthInBytes, options);
    }

    //-------------------------------------------------------------------------
    bool ISTUNRequester::handleSTUNPacket(
                                          IPAddress fromIPAddress,
                                          STUNPacketPtr stun
                                          )
    {
      return (bool)ISTUNRequesterManager::handleSTUNPacket(fromIPAddress, stun);
    }
  }
}
