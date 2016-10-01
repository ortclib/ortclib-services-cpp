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

#include <ortc/services/internal/services_STUNRequesterManager.h>
#include <ortc/services/internal/services_STUNRequester.h>
#include <ortc/services/internal/services_Tracing.h>
#include <ortc/services/IHelper.h>

#include <zsLib/Exception.h>
#include <zsLib/Log.h>
#include <zsLib/XML.h>
#include <zsLib/helpers.h>
#include <zsLib/Stringize.h>

namespace ortc { namespace services { ZS_DECLARE_SUBSYSTEM(ortc_services_stun) } }

namespace ortc
{
  namespace services
  {
    namespace internal
    {
      ZS_DECLARE_TYPEDEF_PTR(ISTUNRequesterManagerForSTUNRequester::ForSTUNRequester, ForSTUNRequester)

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ISTUNRequesterManagerForSTUNRequester
      #pragma mark

      //-----------------------------------------------------------------------
      ForSTUNRequesterPtr ISTUNRequesterManagerForSTUNRequester::singleton()
      {
        return STUNRequesterManager::singleton();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark (helpers)
      #pragma mark

      //-----------------------------------------------------------------------
      static STUNRequesterManager::QWORDPair getKey(STUNPacketPtr stun)
      {
        BYTE buffer[sizeof(QWORD)*2];
        ZS_THROW_INVALID_ASSUMPTION_IF(sizeof(buffer) < (sizeof(stun->mMagicCookie) + sizeof(stun->mTransactionID)))

        memset(&(buffer[0]), 0, sizeof(buffer));

        memcpy(&(buffer[0]), &(stun->mMagicCookie), sizeof(stun->mMagicCookie));
        memcpy(&(buffer[sizeof(stun->mMagicCookie)]), &(stun->mTransactionID[0]), sizeof(stun->mTransactionID));

        QWORD q1 = 0;
        QWORD q2 = 0;
        memcpy(&q1, &(buffer[0]), sizeof(q1));
        memcpy(&q2, &(buffer[sizeof(q1)]), sizeof(q2));
        return STUNRequesterManager::QWORDPair(q1, q2);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark STUNRequesterManager
      #pragma mark

      //-----------------------------------------------------------------------
      STUNRequesterManager::STUNRequesterManager(const make_private &) :
        mID(zsLib::createPUID())
      {
        EventWriteOpServicesStunRequesterManagerCreate(__func__, mID);

        ZS_LOG_DETAIL(log("created"))
      }

      STUNRequesterManager::~STUNRequesterManager()
      {
        if(isNoop()) return;
        
        mThisWeak.reset();
        ZS_LOG_DETAIL(log("destroyed"))

        EventWriteOpServicesStunRequesterManagerDestroy(__func__, mID);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark STUNRequesterManager => ISTUNRequesterManagerFactory
      #pragma mark

      //-----------------------------------------------------------------------
      STUNRequesterManagerPtr STUNRequesterManager::create()
      {
        STUNRequesterManagerPtr pThis(make_shared<STUNRequesterManager>(make_private{}));
        pThis->mThisWeak = pThis;
        return pThis;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark STUNRequesterManager => ISTUNRequesterManager
      #pragma mark

      //-----------------------------------------------------------------------
      STUNRequesterManagerPtr STUNRequesterManager::singleton()
      {
        AutoRecursiveLock lock(*IHelper::getGlobalLock());
        static SingletonLazySharedPtr<STUNRequesterManager> singleton(ISTUNRequesterManagerFactory::singleton().createSTUNRequesterManager());
        STUNRequesterManagerPtr result = singleton.singleton();
        if (!result) {
          ZS_LOG_WARNING(Detail, slog("singleton gone"))
        }
        return result;
      }

      //-----------------------------------------------------------------------
      ISTUNRequesterPtr STUNRequesterManager::handleSTUNPacket(
                                                               IPAddress fromIPAddress,
                                                               STUNPacketPtr stun
                                                               )
      {
        if ((stun->mClass == STUNPacket::Class_Request) ||
            (stun->mClass == STUNPacket::Class_Indication)) {
          ZS_LOG_TRACE(log("ignoring STUN packet that are requests or indications"))
          return ISTUNRequesterPtr();
        }

        EventWriteOpServicesStunRequesterManagerReceivedStunPacket(__func__, mID, fromIPAddress.string());
        stun->trace(__func__);

        QWORDPair key = getKey(stun);

        ZS_THROW_INVALID_USAGE_IF(!stun)

        UseSTUNRequesterPtr requester;

        // scope: we cannot call the requester from within the lock because
        //        the requester might be calling the manager at the same
        //        time (thus trying to obtain the lock)
        {
          AutoRecursiveLock lock(mLock);
          STUNRequesterMap::iterator iter = mRequesters.find(key);
          if (iter == mRequesters.end()) {
            ZS_LOG_WARNING(Trace, log("did not find STUN requester for STUN packet") + ZS_PARAM("stun packet", stun->toDebug()))
            return ISTUNRequesterPtr();
          }

          requester = (*iter).second.first.lock();
        }

        bool remove = false;
        if (requester) {
          // WARNING: This would be very dangerous to call within the scope
          //          of a lock - so don't do it! The requester could be
          //          calling this call to stop monitoring and this class
          //          trying to call it in return might cause a deadlock.
          //
          //          Basically, rule of thumb, do not call delegates
          //          synchronously from within the scope of a lock.
          ZS_LOG_TRACE(log("forwarding request to requester object") + ZS_PARAM("stun packet", stun->toDebug()))
          remove = requester->handleSTUNPacket(fromIPAddress, stun);
        } else{
          ZS_LOG_TRACE(log("requester object was previously destroyed thus removing from requester manager"))
          remove = true;
        }

        if (remove) {
          AutoRecursiveLock lock(mLock);

          STUNRequesterMap::iterator iter = mRequesters.find(key);
          if (iter == mRequesters.end())
            return STUNRequester::convert(requester);

          mRequesters.erase(iter);
        }
        return remove ? STUNRequester::convert(requester) : ISTUNRequesterPtr();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark STUNRequesterManager => ISTUNRequesterManagerForSTUNRequester
      #pragma mark

      //-----------------------------------------------------------------------
      void STUNRequesterManager::monitorStart(
                                              STUNRequesterPtr inRequester,
                                              STUNPacketPtr request
                                              )
      {
        UseSTUNRequesterPtr requester = inRequester;

        ZS_THROW_INVALID_USAGE_IF(!requester)

        EventWriteOpServicesStunRequesterManagerMonitorStart(__func__, mID, requester->getID());

        QWORDPair key = getKey(request);

        AutoRecursiveLock lock(mLock);
        mRequesters[key] = STUNRequesterPair(requester, requester->getID());
      }

      //-----------------------------------------------------------------------
      void STUNRequesterManager::monitorStop(STUNRequester &inRequester)
      {
        UseSTUNRequester &requester = inRequester;

        EventWriteOpServicesStunRequesterManagerMonitorStop(__func__, mID, requester.getID());

        AutoRecursiveLock lock(mLock);

        for (STUNRequesterMap::iterator iter = mRequesters.begin(); iter != mRequesters.end(); ++iter) {
          if ((*iter).second.second == requester.getID()) {
            // found the requester, remove it from the monitor map
            mRequesters.erase(iter);
            return;
          }
        }
      }
      
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark STUNRequesterManager => (internal)
      #pragma mark

      //-----------------------------------------------------------------------
      Log::Params STUNRequesterManager::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("services::STUNRequesterManager");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params STUNRequesterManager::slog(const char *message)
      {
        return Log::Params(message, "services::STUNRequesterManager");
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ISTUNRequesterManagerFactory
      #pragma mark
      
      //-----------------------------------------------------------------------
      ISTUNRequesterManagerFactory &ISTUNRequesterManagerFactory::singleton()
      {
        return STUNRequesterManagerFactory::singleton();
      }

      //-----------------------------------------------------------------------
      STUNRequesterManagerPtr ISTUNRequesterManagerFactory::createSTUNRequesterManager()
      {
        if (this) {}
        return STUNRequesterManager::create();
      }

    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark STUNRequesterManager
    #pragma mark

    //-------------------------------------------------------------------------
    ISTUNRequesterPtr ISTUNRequesterManager::handlePacket(
                                                          IPAddress fromIPAddress,
                                                          const BYTE *packet,
                                                          size_t packetLengthInBytes,
                                                          const STUNPacket::ParseOptions &options
                                                          )
    {
      ZS_THROW_INVALID_USAGE_IF(0 == packetLengthInBytes)
      ZS_THROW_INVALID_USAGE_IF(!packet)

      STUNPacketPtr stun = STUNPacket::parseIfSTUN(packet, packetLengthInBytes, options);
      if (!stun) return ISTUNRequesterPtr();

      return handleSTUNPacket(fromIPAddress, stun);
    }

    //-------------------------------------------------------------------------
    ISTUNRequesterPtr ISTUNRequesterManager::handleSTUNPacket(
                                                              IPAddress fromIPAddress,
                                                              STUNPacketPtr stun
                                                              )
    {
      internal::STUNRequesterManagerPtr manager = internal::STUNRequesterManager::singleton();
      if (!manager) return ISTUNRequesterPtr();
      return manager->handleSTUNPacket(fromIPAddress, stun);
    }
  }
}
