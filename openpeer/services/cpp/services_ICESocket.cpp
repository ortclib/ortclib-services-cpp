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

#include <openpeer/services/internal/services_ICESocket.h>
#include <openpeer/services/internal/services_ICESocketSession.h>
#include <openpeer/services/internal/services_TURNSocket.h>
#include <openpeer/services/internal/services_Helper.h>
#include <openpeer/services/internal/services_wire.h>

#include <openpeer/services/ISTUNRequesterManager.h>
#include <openpeer/services/IHTTP.h>
#include <openpeer/services/ISettings.h>

#include <zsLib/Exception.h>
#include <zsLib/helpers.h>
#include <zsLib/Numeric.h>
#include <zsLib/Stringize.h>
#include <zsLib/XML.h>
#include <zsLib/types.h>

#include <cryptopp/osrng.h>
#include <cryptopp/crc.h>

#ifndef _WIN32
#include <sys/types.h>
#ifdef _ANDROID
#include <openpeer/services/internal/ifaddrs-android.h>
#else
#include <ifaddrs.h>
#endif
#endif //_WIN32

#define OPENPEER_SERVICES_ICESOCKET_RECYCLE_BUFFER_SIZE  (1 << (sizeof(WORD)*8))
#define OPENPEER_SERVICES_ICESOCKET_MAX_RECYLCE_BUFFERS  4

#define OPENPEER_SERVICES_ICESOCKET_MINIMUM_TURN_KEEP_ALIVE_TIME_IN_SECONDS  OPENPEER_SERVICES_IICESOCKET_DEFAULT_HOW_LONG_CANDIDATES_MUST_REMAIN_VALID_IN_SECONDS

#define OPENPEER_SERVICES_TURN_DEFAULT_RETRY_AFTER_DURATION_IN_MILLISECONDS (500)
#define OPENPEER_SERVICES_TURN_MAX_RETRY_AFTER_DURATION_IN_SECONDS (60*60)

#define OPENPEER_SERVICES_REBIND_TIMER_WHEN_NO_SOCKETS_IN_SECONDS (2)
#define OPENPEER_SERVICES_REBIND_TIMER_WHEN_HAS_SOCKETS_IN_SECONDS (30)

#define OPENPEER_SERVICES_ICESOCKET_LOCAL_PREFERENCE_MAX (0xFFFF)


namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services_ice) } }


namespace openpeer
{
  namespace services
  {
    using zsLib::IPv6PortPair;
    using zsLib::string;
    using zsLib::Numeric;
    typedef CryptoPP::CRC32 CRC32;

    namespace internal
    {
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark (helpers)
      #pragma mark

      //-----------------------------------------------------------------------
      static bool isEqual(const IICESocket::Candidate &candidate1, const IICESocket::Candidate &candidate2)
      {
        if (candidate1.mType != candidate2.mType) return false;
        if (candidate1.mPriority != candidate2.mPriority) return false;
        if (candidate1.mIPAddress != candidate2.mIPAddress) return false;
        if (candidate1.mFoundation != candidate2.mFoundation) return false;
        if (candidate1.mComponentID != candidate2.mComponentID) return false;

        return true;
      }
      
      //-----------------------------------------------------------------------
      static IICESocket::Types normalize(IICESocket::Types transport)
      {
        if (transport == ICESocket::Type_Relayed)
          return ICESocket::Type_Relayed;
        return ICESocket::Type_Local;
      }

      //-----------------------------------------------------------------------
      static IPAddress getViaLocalIP(const ICESocket::Candidate &candidate)
      {
        switch (candidate.mType) {
          case IICESocket::Type_Unknown:          break;
          case IICESocket::Type_Local:            return candidate.mIPAddress;
          case IICESocket::Type_ServerReflexive:
          case IICESocket::Type_PeerReflexive:
          case IICESocket::Type_Relayed:          return candidate.mRelatedIP;
        }
        return (candidate.mRelatedIP.isEmpty() ? candidate.mIPAddress : candidate.mRelatedIP);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ICESocket
      #pragma mark

      //-----------------------------------------------------------------------
      ICESocket::ICESocket(
                           IMessageQueuePtr queue,
                           IICESocketDelegatePtr delegate,
                           const TURNServerInfoList &turnServers,
                           const STUNServerInfoList &stunServers,
                           bool firstWORDInAnyPacketWillNotConflictWithTURNChannels,
                           WORD port,
                           IICESocketPtr foundationSocket
                           ) :
        MessageQueueAssociator(queue),

        SharedRecursiveLock(SharedRecursiveLock::create()),

        mCurrentState(ICESocketState_Pending),

        mFoundation(ICESocket::convert(foundationSocket)),

        mBindPort(port),
        mUsernameFrag(IHelper::randomString(20)),
        mPassword(IHelper::randomString(20)),

        mMonitoringWriteReady(true),

        mTURNServers(turnServers),
        mSTUNServers(stunServers),

        mFirstWORDInAnyPacketWillNotConflictWithTURNChannels(firstWORDInAnyPacketWillNotConflictWithTURNChannels),
        mTURNLastUsed(zsLib::now()),

        mLastCandidateCRC(0),

        mForceUseTURN(ISettings::getBool(OPENPEER_SERVICES_SETTING_FORCE_USE_TURN)),
        mSupportIPv6(ISettings::getBool(OPENPEER_SERVICES_SETTING_INTERFACE_SUPPORT_IPV6)),

        mMaxRebindAttemptDuration(Seconds(ISettings::getUInt(OPENPEER_SERVICES_SETTING_MAX_REBIND_ATTEMPT_DURATION_IN_SECONDS)))
      {
        IHelper::setSocketThreadPriority();
        IHelper::setTimerThreadPriority();

        ZS_LOG_BASIC(log("created"))

        String networkOrder = ISettings::getString(OPENPEER_SERVICES_SETTING_INTERFACE_NAME_ORDER);
        if (networkOrder.hasData()) {
          IHelper::SplitMap split;
          IHelper::split(networkOrder, split, ';');
          for (int index = 0; index < split.size(); ++index)
          {
            mInterfaceOrders[(*split.find(index)).second] = index;
          }
        }

        mDefaultSubscription = mSubscriptions.subscribe(delegate, queue);

        if (mFoundation) {
          mComponentID = mFoundation->mComponentID + 1;
        } else {
          mComponentID = 1;
        }

        // calculate the empty list CRC value
        CRC32 crc;
        crc.Final((BYTE *)(&mLastCandidateCRC));
      }

      //-----------------------------------------------------------------------
      void ICESocket::init()
      {
        AutoRecursiveLock lock(*this);
        ZS_LOG_DETAIL(log("init"))

        String restricted = ISettings::getString(OPENPEER_SERVICES_SETTING_ONLY_ALLOW_DATA_SENT_TO_SPECIFIC_IPS);
        Helper::parseIPs(restricted, mRestrictedIPs);

        step();
      }
      
      //-----------------------------------------------------------------------
      ICESocket::~ICESocket()
      {
        if (isNoop()) return;

        mThisWeak.reset();
        ZS_LOG_BASIC(log("destroyed"))
        cancel();
      }

      //-----------------------------------------------------------------------
      ICESocketPtr ICESocket::convert(IICESocketPtr socket)
      {
        return ZS_DYNAMIC_PTR_CAST(ICESocket, socket);
      }

      //-----------------------------------------------------------------------
      ICESocketPtr ICESocket::convert(ForICESocketSessionPtr socket)
      {
        return ZS_DYNAMIC_PTR_CAST(ICESocket, socket);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ICESocket => IICESocket
      #pragma mark

      //-----------------------------------------------------------------------
      ElementPtr ICESocket::toDebug(IICESocketPtr socket)
      {
        if (!socket) return ElementPtr();

        ICESocketPtr pThis = ICESocket::convert(socket);
        return pThis->toDebug();
      }

      //-----------------------------------------------------------------------
      ICESocketPtr ICESocket::create(
                                     IMessageQueuePtr queue,
                                     IICESocketDelegatePtr delegate,
                                     const TURNServerInfoList &turnServers,
                                     const STUNServerInfoList &stunServers,
                                     WORD port,
                                     bool firstWORDInAnyPacketWillNotConflictWithTURNChannels,
                                     IICESocketPtr foundationSocket
                                     )
      {
        ICESocketPtr pThis(new ICESocket(
                                         queue,
                                         delegate,
                                         turnServers,
                                         stunServers,
                                         firstWORDInAnyPacketWillNotConflictWithTURNChannels,
                                         port,
                                         foundationSocket));
        pThis->mThisWeak = pThis;
        pThis->init();
        return pThis;
      }

      //-----------------------------------------------------------------------
      IICESocketSubscriptionPtr ICESocket::subscribe(IICESocketDelegatePtr originalDelegate)
      {
        ZS_LOG_DETAIL(log("subscribing to socket state"))

        AutoRecursiveLock lock(*this);
        if (!originalDelegate) return mDefaultSubscription;

        IICESocketSubscriptionPtr subscription = mSubscriptions.subscribe(originalDelegate);

        IICESocketDelegatePtr delegate = mSubscriptions.delegate(subscription, true);

        if (delegate) {
          ICESocketPtr pThis = mThisWeak.lock();

          if (ICESocketState_Pending != mCurrentState) {
            delegate->onICESocketStateChanged(pThis, mCurrentState);
          }
          if (mNotifiedCandidateChanged) {
            delegate->onICESocketCandidatesChanged(pThis);
          }
        }

        if (isShutdown()) {
          mSubscriptions.clear();
        }
        
        return subscription;
      }
      
      //-----------------------------------------------------------------------
      IICESocket::ICESocketStates ICESocket::getState(
                                                      WORD *outLastErrorCode,
                                                      String *outLastErrorReason
                                                      ) const
      {
        AutoRecursiveLock lock(*this);
        if (outLastErrorCode) *outLastErrorCode = mLastError;
        if (outLastErrorReason) *outLastErrorReason = mLastErrorReason;
        return mCurrentState;
      }

      //-----------------------------------------------------------------------
      String ICESocket::getUsernameFrag() const
      {
        AutoRecursiveLock lock(*this);
        return mUsernameFrag;
      }

      //-----------------------------------------------------------------------
      String ICESocket::getPassword() const
      {
        AutoRecursiveLock lock(*this);
        return mPassword;
      }

      //-----------------------------------------------------------------------
      void ICESocket::shutdown()
      {
        ZS_LOG_DETAIL(log("shutdown requested"))

        AutoRecursiveLock lock(*this);
        cancel();
      }

      //-----------------------------------------------------------------------
      void ICESocket::wakeup(Duration minimumTimeCandidatesMustRemainValidWhileNotUsed)
      {
        AutoRecursiveLock lock(*this);

        if ((isShuttingDown()) ||
            (isShutdown())) {
          ZS_LOG_WARNING(Detail, log("received request to wake up while ICE socket is shutting down or shutdown"))
          return;
        }

        mTURNLastUsed = zsLib::now();

        mTURNShutdownIfNotUsedBy = Seconds(ISettings::getUInt(OPENPEER_SERVICES_SETTING_TURN_CANDIDATES_MUST_REMAIN_ALIVE_AFTER_ICE_WAKE_UP_IN_SECONDS));
        mTURNShutdownIfNotUsedBy = (mTURNShutdownIfNotUsedBy > minimumTimeCandidatesMustRemainValidWhileNotUsed ? mTURNShutdownIfNotUsedBy : minimumTimeCandidatesMustRemainValidWhileNotUsed);

        step();
      }

      //-----------------------------------------------------------------------
      void ICESocket::getLocalCandidates(
                                         CandidateList &outCandidates,
                                         String *outLocalCandidateVersion
                                         )
      {
        AutoRecursiveLock lock(*this);

        outCandidates.clear();

        if (outLocalCandidateVersion) {
          *outLocalCandidateVersion = string(mLastCandidateCRC);
        }

        for (LocalSocketMap::iterator iter = mSockets.begin(); iter != mSockets.end(); ++iter)
        {
          LocalSocketPtr &localSocket = (*iter).second;

          if (!localSocket->mLocal->mIPAddress.isEmpty()) {
            outCandidates.push_back(*(localSocket->mLocal));
          }
        }
        for (LocalSocketMap::iterator iter = mSockets.begin(); iter != mSockets.end(); ++iter)
        {
          LocalSocketPtr &localSocket = (*iter).second;

          for (STUNInfoMap::iterator infoIter = localSocket->mSTUNInfos.begin(); infoIter != localSocket->mSTUNInfos.end(); ++infoIter)
          {
            STUNInfoPtr &stunInfo = (*infoIter).second;

            if (!stunInfo->mReflexive->mIPAddress.isEmpty()) {
              outCandidates.push_back(*(stunInfo->mReflexive));
            }
          }
        }
        for (LocalSocketMap::iterator iter = mSockets.begin(); iter != mSockets.end(); ++iter)
        {
          LocalSocketPtr &localSocket = (*iter).second;

          for (TURNInfoMap::iterator infoIter = localSocket->mTURNInfos.begin(); infoIter != localSocket->mTURNInfos.end(); ++infoIter)
          {
            TURNInfoPtr &turnInfo = (*infoIter).second;

            if (!turnInfo->mRelay->mIPAddress.isEmpty()) {
              outCandidates.push_back(*(turnInfo->mRelay));
            }
          }
        }
      }

      //-----------------------------------------------------------------------
      String ICESocket::getLocalCandidatesVersion() const
      {
        AutoRecursiveLock lock(*this);
        return string(mLastCandidateCRC);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ICESocket => IICESocketForICESocketSession
      #pragma mark

      //-----------------------------------------------------------------------
      bool ICESocket::attach(ICESocketSessionPtr inSession)
      {
        UseICESocketSessionPtr session = inSession;

        ZS_THROW_INVALID_ARGUMENT_IF(!session)

        AutoRecursiveLock lock(*this);

        if ((isShuttingDown()) ||
            (isShutdown())) {
          ZS_LOG_WARNING(Basic, log("create session called after socket is being shutdown"))
          // immediately close the session since we are shutting down
          session->close();
          return false;
        }

        // remember the session for later
        mSessions[session->getID()] = session;
        return true;
      }
      
      //-----------------------------------------------------------------------
      bool ICESocket::sendTo(
                             const Candidate &viaLocalCandidate,
                             const IPAddress &destination,
                             const BYTE *buffer,
                             size_t bufferLengthInBytes,
                             bool isUserData
                             )
      {
        if (isShutdown()) {
          OPENPEER_SERVICES_WIRE_LOG_WARNING(Debug, log("cannot send packet via ICE socket as it is already shutdown") + ZS_PARAM("candidate", viaLocalCandidate.toDebug()) + ZS_PARAM("to ip", destination.string()) + ZS_PARAM("buffer", (bool)buffer) + ZS_PARAM("buffer length", bufferLengthInBytes) << ZS_PARAM("user data", isUserData))
          return false;
        }

        SocketPtr socket;
        ITURNSocketPtr turnSocket;

        // get socket or turn socket value
        {
          AutoRecursiveLock lock(*this);

          LocalSocketIPAddressMap::iterator found = mSocketLocalIPs.find(getViaLocalIP(viaLocalCandidate));
          if (found == mSocketLocalIPs.end()) {
            OPENPEER_SERVICES_WIRE_LOG_WARNING(Detail, log("did not find local IP to use"))
            return false;
          }

          LocalSocketPtr &localSocket = (*found).second;
          if (viaLocalCandidate.mType == Type_Relayed) {
            TURNInfoRelatedIPMap::iterator foundRelated = localSocket->mTURNRelayIPs.find(viaLocalCandidate.mIPAddress);
            if (foundRelated != localSocket->mTURNRelayIPs.end()) {
              turnSocket = (*foundRelated).second->mTURNSocket;
            }
          } else {
            socket = localSocket->mSocket;
          }
        }

        if (viaLocalCandidate.mType == Type_Relayed) {
          if (!turnSocket) {
            OPENPEER_SERVICES_WIRE_LOG_WARNING(Debug, log("cannot send packet via TURN socket as it is not connected") + ZS_PARAM("candidate", viaLocalCandidate.toDebug()) + ZS_PARAM("to ip", destination.string()) + ZS_PARAM("buffer", (bool)buffer) + ZS_PARAM("buffer length", bufferLengthInBytes) + ZS_PARAM("user data", isUserData))
            return false;
          }

          mTURNLastUsed = zsLib::now();
          return turnSocket->sendPacket(destination, buffer, bufferLengthInBytes, isUserData);
        }

        if (!socket) {
          OPENPEER_SERVICES_WIRE_LOG_WARNING(Debug, log("cannot send packet as UDP socket is not set") + ZS_PARAM("candidate", viaLocalCandidate.toDebug()) + ZS_PARAM("to ip", destination.string()) + ZS_PARAM("buffer", (bool)buffer) + ZS_PARAM("buffer length", bufferLengthInBytes) + ZS_PARAM("user data", isUserData))
          return false;
        }

        // attempt to send the packet over the UDP buffer
        try {
          bool wouldBlock = false;

          if (mForceUseTURN) {
            ZS_LOG_WARNING(Trace, log("preventing data packet from going to destination due to TURN restriction") + ZS_PARAM("destination", destination.string()))
            return true;     // simulates forcing via TURN by refusing to send out any packets over local UDP (does not block STUN discovery)
          }

          if (!Helper::containsIP(mRestrictedIPs, destination)) {
            ZS_LOG_WARNING(Trace, log("preventing data packet from going to destination as destination is not in restricted IP list") + ZS_PARAM("destination", destination.string()))
            return true;
          }

          size_t bytesSent = socket->sendTo(destination, buffer, bufferLengthInBytes, &wouldBlock);
          OPENPEER_SERVICES_WIRE_LOG_TRACE(log("sending packet") + ZS_PARAM("candidate", viaLocalCandidate.toDebug()) + ZS_PARAM("to ip", destination.string()) + ZS_PARAM("buffer", (bool)buffer) + ZS_PARAM("buffer length", bufferLengthInBytes) + ZS_PARAM("user data", isUserData) + ZS_PARAM("bytes sent", bytesSent) + ZS_PARAM("would block", wouldBlock))
          if (ZS_IS_LOGGING(Insane)) {
            String base64 = IHelper::convertToBase64(buffer, bytesSent);
            OPENPEER_SERVICES_WIRE_LOG_INSANE(log("SEND PACKET ON WIRE") + ZS_PARAM("destination", destination.string()) + ZS_PARAM("wire out", base64))
          }
          return ((!wouldBlock) && (bufferLengthInBytes == bytesSent));
        } catch(Socket::Exceptions::Unspecified &error) {
          ZS_LOG_ERROR(Detail, log("sendTo error") + ZS_PARAM("error", error.errorCode()))
        }
        return false;
      }

      //-----------------------------------------------------------------------
      void ICESocket::addRoute(
                               ICESocketSessionPtr session,
                               const IPAddress &viaIP,
                               const IPAddress &viaLocalIP,
                               const IPAddress &source
                               )
      {
        removeRoute(session);
        RouteTuple tuple(viaIP, viaLocalIP, source);
        mRoutes[tuple] = session;
      }

      //-----------------------------------------------------------------------
      void ICESocket::removeRoute(ICESocketSessionPtr inSession)
      {
        for (QuickRouteMap::iterator iter = mRoutes.begin(); iter != mRoutes.end(); ) {
          QuickRouteMap::iterator current = iter; ++iter;

          UseICESocketSessionPtr &session = (*current).second;
          if (session == inSession) {
            mRoutes.erase(current);
          }
        }
      }

      //-----------------------------------------------------------------------
      void ICESocket::onICESocketSessionClosed(PUID sessionID)
      {
        ZS_LOG_DETAIL(log("notified ICE session closed") + ZS_PARAM("session id", sessionID))

        AutoRecursiveLock lock(*this);
        ICESocketSessionMap::iterator found = mSessions.find(sessionID);
        if (found == mSessions.end()) {
          ZS_LOG_WARNING(Detail, log("session is not found (must have already been closed)") + ZS_PARAM("session id", + sessionID))
          return;
        }

        removeRoute(ICESocketSession::convert((*found).second));
        mSessions.erase(found);
        
        step();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ICESocket => ISocketDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void ICESocket::monitorWriteReadyOnAllSessions(bool monitor)
      {
        AutoRecursiveLock lock(*this);

        mMonitoringWriteReady = monitor;

        for (LocalSocketMap::iterator iter = mSockets.begin(); iter != mSockets.end(); )
        {
          LocalSocketPtr &localSocket = (*iter).second;

          if (monitor) {
            localSocket->mSocket->monitor(Socket::Monitor::All);
          } else {
            localSocket->mSocket->monitor((Socket::Monitor::Options)(Socket::Monitor::Read | Socket::Monitor::Exception));
          }
        }
      }

      //-----------------------------------------------------------------------
      void ICESocket::onReadReady(SocketPtr socket)
      {
        boost::shared_array<BYTE> buffer;
        CandidatePtr viaLocalCandidate;
        IPAddress source;
        size_t bytesRead = 0;
        AutoRecycleBuffer recycle(*this, buffer);

        // scope: we are going to read the data while within the local but process it outside the lock
        {
          AutoRecursiveLock lock(*this);

          LocalSocketMap::iterator found = mSockets.find(socket);
          if (found == mSockets.end()) {
            OPENPEER_SERVICES_WIRE_LOG_WARNING(Detail, log("UDP socket is not ready"))
            return;
          }

          LocalSocketPtr &localSocket = (*found).second;
          viaLocalCandidate = localSocket->mLocal;

          try {
            bool wouldBlock = false;

            getBuffer(buffer);

            bytesRead = localSocket->mSocket->receiveFrom(source, buffer.get(), OPENPEER_SERVICES_ICESOCKET_RECYCLE_BUFFER_SIZE, &wouldBlock);
            if (0 == bytesRead) return;

            OPENPEER_SERVICES_WIRE_LOG_TRACE(log("packet received") + ZS_PARAM("ip", + source.string()) + ZS_PARAM("handle", socket->getSocket()))

            if (ZS_IS_LOGGING(Insane)) {
              String base64 = Helper::convertToBase64(buffer.get(), bytesRead);
              OPENPEER_SERVICES_WIRE_LOG_INSANE(log("RECEIVE PACKET ON WIRE") + ZS_PARAM("source", source.string()) + ZS_PARAM("wire in", base64))
            }

          } catch(Socket::Exceptions::Unspecified &error) {
            ZS_LOG_ERROR(Detail, log("receiveFrom error") + ZS_PARAM("error", error.errorCode()))
            cancel();
            return;
          }
        }

        // this method cannot be called within the scope of a lock because it
        // calls a delegate synchronously
        internalReceivedData(*viaLocalCandidate, *viaLocalCandidate, source, buffer.get(), bytesRead);
      }

      //-----------------------------------------------------------------------
      void ICESocket::onWriteReady(SocketPtr socket)
      {
        OPENPEER_SERVICES_WIRE_LOG_TRACE(log("write ready"))
        AutoRecursiveLock lock(*this);

        LocalSocketMap::iterator found = mSockets.find(socket);
        if (found == mSockets.end()) {
          OPENPEER_SERVICES_WIRE_LOG_WARNING(Detail, log("UDP socket is not ready"))
          return;
        }

        LocalSocketPtr &localSocket = (*found).second;

        for(ICESocketSessionMap::iterator iter = mSessions.begin(); iter != mSessions.end(); ++iter) {
          (*iter).second->notifyLocalWriteReady(*(localSocket->mLocal));
        }

        for (TURNInfoMap::iterator iter = localSocket->mTURNInfos.begin(); iter != localSocket->mTURNInfos.end(); ++iter) {
          TURNInfoPtr &turnInfo = (*iter).second;
          if (turnInfo->mTURNSocket) {
            OPENPEER_SERVICES_WIRE_LOG_TRACE(log("notifying TURN socket of write ready") + ZS_PARAM("TURN socket ID", turnInfo->mTURNSocket->getID()))
            turnInfo->mTURNSocket->notifyWriteReady();
          }
        }
      }

      //-----------------------------------------------------------------------
      void ICESocket::onException(SocketPtr socket)
      {
        ZS_LOG_DETAIL(log("on exception"))
        AutoRecursiveLock lock(*this);

        {
          LocalSocketMap::iterator found = mSockets.find(socket);
          if (found == mSockets.end()) {
            ZS_LOG_WARNING(Detail, log("notified of exception on socket which is not the bound socket"))
            return;
          }

          ZS_LOG_WARNING(Detail, log("socket exception occured"))

          LocalSocketPtr &localSocket = (*found).second;

          for (TURNInfoMap::iterator iter = localSocket->mTURNInfos.begin(); iter != localSocket->mTURNInfos.end(); ++iter) {
            TURNInfoPtr &turnInfo = (*iter).second;
            if (turnInfo->mTURNSocket) {
              clearTURN(turnInfo->mTURNSocket);
              turnInfo->mTURNSocket->shutdown();
              turnInfo->mTURNSocket.reset();
            }
          }
          localSocket->mTURNInfos.clear();
          localSocket->mTURNSockets.clear();
          localSocket->mTURNRelayIPs.clear();

          for (STUNInfoMap::iterator iter = localSocket->mSTUNInfos.begin(); iter != localSocket->mSTUNInfos.end(); ++iter) {
            STUNInfoPtr &stunInfo = (*iter).second;
            if (stunInfo->mSTUNDiscovery) {
              clearSTUN(stunInfo->mSTUNDiscovery);
              stunInfo->mSTUNDiscovery->cancel();
              stunInfo->mSTUNDiscovery.reset();
            }
          }

          localSocket->mSTUNInfos.clear();
          localSocket->mSTUNDiscoveries.clear();

          localSocket->mSocket->close();
          localSocket->mSocket.reset();

          for (LocalSocketIPAddressMap::iterator ipIter = mSocketLocalIPs.begin(); ipIter != mSocketLocalIPs.end(); )
          {
            LocalSocketIPAddressMap::iterator currentIPIter = ipIter; ++ipIter;

            const LocalIP &ip = (*currentIPIter).first;
            LocalSocketPtr &mappedSocket = (*currentIPIter).second;

            if (mappedSocket != localSocket) {
              ZS_LOG_TRACE(log("socket exception - socket is not this local IP") + ZS_PARAM("ip", ip.string()))
              continue;
            }

            ZS_LOG_WARNING(Detail, log("socket exception - socket was closed for this IP") + ZS_PARAM("ip", ip.string()))
            mSocketLocalIPs.erase(currentIPIter);
          }

          mSockets.erase(found);
        }

        // attempt to rebind immediately
        mRebindCheckNow = true;
        step();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ICESocket => ITURNSocketDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void ICESocket::onTURNSocketStateChanged(
                                               ITURNSocketPtr socket,
                                               TURNSocketStates state
                                               )
      {
        AutoRecursiveLock lock(*this);
        ZS_LOG_DEBUG(log("turn socket state changed"))
        step();
      }

      //-----------------------------------------------------------------------
      void ICESocket::handleTURNSocketReceivedPacket(
                                                     ITURNSocketPtr socket,
                                                     IPAddress source,
                                                     const BYTE *packet,
                                                     size_t packetLengthInBytes
                                                     )
      {
        // WARNING: This method cannot be called within a lock as it calls delegates synchronously.
        CandidatePtr viaCandidate;
        CandidatePtr viaLocalCandidate;
        {
          AutoRecursiveLock lock(*this);
          LocalSocketTURNSocketMap::iterator found = mSocketTURNs.find(socket);
          if (found == mSocketTURNs.end()) {
            OPENPEER_SERVICES_WIRE_LOG_WARNING(Detail, log("TURN not associated with any local socket"))
            return;
          }
          LocalSocketPtr &localSocket = (*found).second;

          TURNInfoSocketMap::iterator foundInfo = localSocket->mTURNSockets.find(socket);
          ZS_THROW_BAD_STATE_IF(foundInfo == localSocket->mTURNSockets.end()) // dangling TURN socket reference must not happen

          viaCandidate = (*foundInfo).second->mRelay;
          viaLocalCandidate = localSocket->mLocal;
        }

        internalReceivedData(*viaCandidate, *viaLocalCandidate,source, packet, packetLengthInBytes);
      }

      //-----------------------------------------------------------------------
      bool ICESocket::notifyTURNSocketSendPacket(
                                                 ITURNSocketPtr socket,
                                                 IPAddress destination,
                                                 const BYTE *packet,
                                                 size_t packetLengthInBytes
                                                 )
      {
        AutoRecursiveLock lock(*this);

        OPENPEER_SERVICES_WIRE_LOG_TRACE(log("sending packet for TURN") + ZS_PARAM("TURN socket ID", socket->getID()) + ZS_PARAM("destination", destination.string()) + ZS_PARAM("length", packetLengthInBytes))

        if (isShutdown()) {
          OPENPEER_SERVICES_WIRE_LOG_WARNING(Debug, log("unable to send data on behalf of TURN as ICE socket is shutdown") + ZS_PARAM("TURN socket ID", socket->getID()))
          return false;
        }

        LocalSocketTURNSocketMap::iterator found = mSocketTURNs.find(socket);
        if (found == mSocketTURNs.end()) {
          OPENPEER_SERVICES_WIRE_LOG_WARNING(Debug, log("unable to send data on behalf of TURN as TURN socket does not match any local socket (TURN reconnect reattempt?)") + ZS_PARAM("socket ID", socket->getID()))
          return false;
        }
        LocalSocketPtr &localSocket = (*found).second;

        try {
          bool wouldBlock = false;

          if (!Helper::containsIP(mRestrictedIPs, destination)) {
            ZS_LOG_WARNING(Trace, log("preventing TURN packet from going to destination as destination is not in restricted IP list") + ZS_PARAM("destination", destination.string()))
            return true;
          }

          size_t bytesSent = localSocket->mSocket->sendTo(destination, packet, packetLengthInBytes, &wouldBlock);
          bool sent = ((!wouldBlock) && (bytesSent == packetLengthInBytes));
          if (!sent) {
            OPENPEER_SERVICES_WIRE_LOG_WARNING(Debug, log("unable to send data on behalf of TURN as UDP socket did not send the data") + ZS_PARAM("would block", wouldBlock) + ZS_PARAM("bytes sent", bytesSent))
          }
          return sent;
        } catch(Socket::Exceptions::Unspecified &error) {
          OPENPEER_SERVICES_WIRE_LOG_ERROR(Detail, log("sendTo error") + ZS_PARAM("error", error.errorCode()))
        }
        return false;
      }

      //-----------------------------------------------------------------------
      void ICESocket::onTURNSocketWriteReady(ITURNSocketPtr socket)
      {
        OPENPEER_SERVICES_WIRE_LOG_TRACE(log("notified that TURN is write ready") + ZS_PARAM("TURN socket ID", socket->getID()))

        AutoRecursiveLock lock(*this);

        LocalSocketTURNSocketMap::iterator found = mSocketTURNs.find(socket);
        if (found == mSocketTURNs.end()) {
          OPENPEER_SERVICES_WIRE_LOG_WARNING(Debug, log("cannot notify socket write ready as TURN socket does not match current TURN socket (TURN reconnect reattempt?)") + ZS_PARAM("socket ID", + socket->getID()))
          return;
        }

        LocalSocketPtr &localSocket = (*found).second;

        TURNInfoSocketMap::iterator foundInfo = localSocket->mTURNSockets.find(socket);
        ZS_THROW_BAD_STATE_IF(foundInfo == localSocket->mTURNSockets.end())

        const Candidate &viaLocalCandidate = *((*foundInfo).second->mRelay);

        for(ICESocketSessionMap::iterator iter = mSessions.begin(); iter != mSessions.end(); ++iter) {
          (*iter).second->notifyRelayWriteReady(viaLocalCandidate);
        }
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ICESocket => ISTUNDiscoveryDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void ICESocket::onSTUNDiscoverySendPacket(
                                                ISTUNDiscoveryPtr discovery,
                                                IPAddress destination,
                                                SecureByteBlockPtr packet
                                                )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!packet)

        AutoRecursiveLock lock(*this);
        if (isShutdown()) {
          ZS_LOG_TRACE(log("cannot send packet as already shutdown"))
          return;
        }

        LocalSocketSTUNDiscoveryMap::iterator found = mSocketSTUNs.find(discovery);
        if (found == mSocketSTUNs.end()) {
          ZS_LOG_WARNING(Debug, log("cannot send STUN packet as STUN discovery does not match any STUN socket") + ZS_PARAM("socket ID", discovery->getID()) + ZS_PARAM("destination", destination.string()) + ZS_PARAM("length", packet->SizeInBytes()))
          return;
        }

        LocalSocketPtr &localSocket = (*found).second;

        ZS_LOG_TRACE(log("sending packet for STUN discovery") + ZS_PARAM("via", localSocket->mLocal->mIPAddress.string()) + ZS_PARAM("destination", destination.string()) + ZS_PARAM("length", packet->SizeInBytes()))

        try {
          bool wouldBlock = false;

          if (!Helper::containsIP(mRestrictedIPs, destination)) {
            ZS_LOG_WARNING(Trace, log("preventing STUN packet from going to destination as destination is not in restricted IP list") + ZS_PARAM("destination", destination.string()))
            return;
          }

          localSocket->mSocket->sendTo(destination, *packet, packet->SizeInBytes(), &wouldBlock);
        } catch(Socket::Exceptions::Unspecified &error) {
          OPENPEER_SERVICES_WIRE_LOG_ERROR(Detail, log("sendTo error") + ZS_PARAM("error", error.errorCode()))
        }
      }

      //-----------------------------------------------------------------------
      void ICESocket::onSTUNDiscoveryCompleted(ISTUNDiscoveryPtr discovery)
      {
        AutoRecursiveLock lock(*this);
        ZS_LOG_DETAIL(log("notified STUN discovery finished") + ZS_PARAM("id", discovery->getID()) + ZS_PARAM("reflected ip", discovery->getMappedAddress().string()))
        step();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ICESocket => ITimerDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void ICESocket::onTimer(TimerPtr timer)
      {
        ZS_LOG_DEBUG(log("on timer") + ZS_PARAM("timer ID", timer->getID()))

        AutoRecursiveLock lock(*this);

        if (timer == mRebindTimer) {
          mRebindCheckNow = true;
          step();
          return;
        }

        for (LocalSocketIPAddressMap::iterator iter = mSocketLocalIPs.begin(); iter != mSocketLocalIPs.end(); ++iter)
        {
          LocalSocketPtr &localSocket = (*iter).second;

          for (TURNInfoMap::iterator infoIter = localSocket->mTURNInfos.begin(); infoIter != localSocket->mTURNInfos.end(); ++infoIter) {

            TURNInfoPtr &turnInfo = (*infoIter).second;

            if (timer == turnInfo->mTURNRetryTimer) {
              ZS_LOG_DEBUG(log("retry TURN timer"))

              turnInfo->mTURNRetryTimer->cancel();
              turnInfo->mTURNRetryTimer.reset();

              step();
              return;
            }

          }

        }

        ZS_LOG_WARNING(Detail, log("received timer notification on obsolete timer") + ZS_PARAM("timer ID", timer->getID()))
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ICESocket => (internal)
      #pragma mark

      //-----------------------------------------------------------------------
      Log::Params ICESocket::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("ICESocket");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params ICESocket::debug(const char *message) const
      {
        return Log::Params(message, toDebug());
      }

      //-----------------------------------------------------------------------
      ElementPtr ICESocket::toDebug() const
      {
        AutoRecursiveLock lock(*this);

        ElementPtr resultEl = Element::create("ICESocket");

        IHelper::debugAppend(resultEl, "id", mID);

        IHelper::debugAppend(resultEl, "graceful shutdown", (bool)mGracefulShutdownReference);

        IHelper::debugAppend(resultEl, "subscriptions", mSubscriptions.size());
        IHelper::debugAppend(resultEl, "default subscription", (bool)mDefaultSubscription);

        IHelper::debugAppend(resultEl, "state", IICESocket::toString(mCurrentState));
        IHelper::debugAppend(resultEl, "last error", mLastError);
        IHelper::debugAppend(resultEl, "last reason", mLastErrorReason);

        IHelper::debugAppend(resultEl, "foundation", (bool)mFoundation);

        IHelper::debugAppend(resultEl, "bind port", mBindPort);
        IHelper::debugAppend(resultEl, "usernameFrag", mUsernameFrag);
        IHelper::debugAppend(resultEl, "password", mPassword);

        IHelper::debugAppend(resultEl, "socket local IPs", mSocketLocalIPs.size());
        IHelper::debugAppend(resultEl, "turn sockets", mSocketTURNs.size());
        IHelper::debugAppend(resultEl, "stun sockets", mSocketSTUNs.size());
        IHelper::debugAppend(resultEl, "sockets", mSockets.size());

        IHelper::debugAppend(resultEl, "rebind timer", (bool)mRebindTimer);
        IHelper::debugAppend(resultEl, "rebind attempt start time", mRebindAttemptStartTime);
        IHelper::debugAppend(resultEl, "rebind check now", mRebindCheckNow);

        IHelper::debugAppend(resultEl, "monitoring write ready", mMonitoringWriteReady);

        IHelper::debugAppend(resultEl, "turn servers", mTURNServers.size());
        IHelper::debugAppend(resultEl, "stun servers", mSTUNServers.size());
        IHelper::debugAppend(resultEl, "turn first WORD safe", mFirstWORDInAnyPacketWillNotConflictWithTURNChannels);
        IHelper::debugAppend(resultEl, "turn last used", mTURNLastUsed);
        IHelper::debugAppend(resultEl, "turn stutdown duration (s)", mTURNShutdownIfNotUsedBy);

        IHelper::debugAppend(resultEl, "sessions", mSessions.size());

        IHelper::debugAppend(resultEl, "routes", mRoutes.size());

        IHelper::debugAppend(resultEl, "recyle buffers", mRecycledBuffers.size());

        IHelper::debugAppend(resultEl, "notified candidates changed", mNotifiedCandidateChanged);
        IHelper::debugAppend(resultEl, "candidate crc", mLastCandidateCRC);

        IHelper::debugAppend(resultEl, "force use turn", mForceUseTURN);
        IHelper::debugAppend(resultEl, "restricted IPs", mRestrictedIPs.size());

        IHelper::debugAppend(resultEl, "interface name order", mInterfaceOrders.size());

        IHelper::debugAppend(resultEl, "support ipv6", mSupportIPv6);

        return resultEl;
      }

      //-----------------------------------------------------------------------
      void ICESocket::cancel()
      {
        if (isShutdown()) {
          ZS_LOG_DEBUG(log("already cancelled"))
          return;
        }

        ZS_LOG_DEBUG(log("cancel called"))

        if (!mGracefulShutdownReference) mGracefulShutdownReference = mThisWeak.lock();

        setState(ICESocketState_ShuttingDown);

        clearRebindTimer();

        for (LocalSocketMap::iterator iter_DoNotUse = mSockets.begin(); iter_DoNotUse != mSockets.end(); )
        {
          LocalSocketMap::iterator current = iter_DoNotUse; ++iter_DoNotUse;

          LocalSocketPtr &localSocket = (*current).second;

          stopSTUNAndTURN(localSocket);
        }

        for (LocalSocketMap::iterator iter = mSockets.begin(); iter != mSockets.end(); )
        {
          LocalSocketMap::iterator current = iter; ++iter;

          LocalSocketPtr &localSocket = (*current).second;

          if (!closeIfTURNGone(localSocket)) continue;
        }

        if (mGracefulShutdownReference) {
          if (mSockets.size() > 0) {
            ZS_LOG_DEBUG(log("waiting for sockets to shutdown") + ZS_PARAM("total", mSockets.size()))
            return;
          }
        }

        // inform that the graceful stutdown has completed...
        setState(ICESocketState_Shutdown);

        ZS_LOG_BASIC(log("shutdown"))

        mGracefulShutdownReference.reset();

        for (LocalSocketMap::iterator iter_DoNotUse = mSockets.begin(); iter_DoNotUse != mSockets.end();)
        {
          LocalSocketMap::iterator current = iter_DoNotUse; ++iter_DoNotUse;
          LocalSocketPtr &localSocket = (*current).second;

          hardClose(localSocket);
        }

        mSubscriptions.clear();
        mDefaultSubscription.reset();

        mFoundation.reset();

        if (mSessions.size() > 0) {
          ICESocketSessionMap temp = mSessions;
          mSessions.clear();

          // close down all the ICE sessions immediately
          for(ICESocketSessionMap::iterator iter = temp.begin(); iter != temp.end(); ++iter) {
            (*iter).second->close();
          }
        }

        mRoutes.clear();

        mSocketLocalIPs.clear();
        mSocketTURNs.clear();
        mSocketSTUNs.clear();
        mSockets.clear();

        mTURNServers.clear();
        mSTUNServers.clear();
      }

      //-----------------------------------------------------------------------
      void ICESocket::setState(ICESocketStates state)
      {
        if (mCurrentState == state) return;

        ZS_LOG_BASIC(log("state changed") + ZS_PARAM("old state", toString(mCurrentState)) + ZS_PARAM("new state", toString(state)))

        mCurrentState = state;

        ICESocketPtr pThis = mThisWeak.lock();

        if (pThis) {
          mSubscriptions.delegate()->onICESocketStateChanged(pThis, mCurrentState);
        }
      }

      //-----------------------------------------------------------------------
      void ICESocket::setError(WORD errorCode, const char *inReason)
      {
        String reason(inReason ? String(inReason) : String());
        if (reason.isEmpty()) {
          reason = IHTTP::toString(IHTTP::toStatusCode(errorCode));
        }

        if (0 != mLastError) {
          ZS_LOG_WARNING(Detail, debug("error already set thus ignoring new error") + ZS_PARAM("new error", errorCode) + ZS_PARAM("new reason", reason))
          return;
        }

        mLastError = errorCode;
        mLastErrorReason = reason;

        ZS_LOG_WARNING(Detail, debug("error set") + ZS_PARAM("code", mLastError) + ZS_PARAM("reason", mLastErrorReason))
      }

      //-----------------------------------------------------------------------
      void ICESocket::step()
      {
        if ((isShuttingDown()) ||
            (isShutdown())) {
          ZS_LOG_DEBUG(log("step redirected to shutdown"))
          cancel();
          return;
        }

        ZS_LOG_DEBUG(debug("step"))

        if (!stepBind()) goto post_candidate_check;
        if (!stepSTUN()) goto post_candidate_check;
        if (!stepTURN()) goto post_candidate_check;

        setState(IICESocket::ICESocketState_Ready);

      post_candidate_check:
        {
          if ((isShuttingDown()) ||
              (isShutdown())) {
            ZS_LOG_DEBUG(log("step shutdown thus redirected to shutdown"))
            cancel();
            return;
          }

          stepCandidates();
        }
      }

      //-----------------------------------------------------------------------
      bool ICESocket::stepBind()
      {
        if (mSockets.size() > 0) {
          if (!mRebindCheckNow) {
            ZS_LOG_TRACE(log("already bound thus nothing to do"))
            return true;
          }
          ZS_LOG_TRACE(log("rechecking binding now"))
          mRebindCheckNow = false;
        }

        ZS_LOG_TRACE(log("step bind") + ZS_PARAM("total sockets", mSockets.size()))

        IPAddressList localIPs;
        if (!getLocalIPs(localIPs)) {
          ZS_LOG_WARNING(Detail, log("failed to obtain any local IPs"))
        }

        bool hadNone = (mSockets.size() < 1);

        // clear out sockets that are now gone
        {
          for (LocalSocketMap::iterator iter_DoNotUse = mSockets.begin(); iter_DoNotUse != mSockets.end(); )
          {
            LocalSocketMap::iterator current = iter_DoNotUse;
            ++iter_DoNotUse;

            LocalSocketPtr localSocket = (*current).second;

            IPAddress &existingIP = localSocket->mLocal->mIPAddress;

            bool found = false;

            for (IPAddressList::iterator iter = localIPs.begin(); iter != localIPs.end(); ++iter)
            {
              IPAddress &ip = (*iter);

              IPAddress bindIP(ip);
              bindIP.setPort(mBindPort);

              if (!bindIP.isEqualIgnoringIPv4Format(existingIP)) continue;

              ZS_LOG_TRACE(log("existing local IP found") + ZS_PARAM("ip", bindIP.string()))

              found = true;
              break;
            }

            if (found) continue;

            ZS_LOG_WARNING(Basic, log("IP address is now gone thus must unbind from network") + ZS_PARAM("ip", existingIP.string()))

            hardClose(localSocket);
          }
        }

        ULONG nextLocalPreference = OPENPEER_SERVICES_ICESOCKET_LOCAL_PREFERENCE_MAX;

        for (IPAddressList::iterator iter = localIPs.begin(); iter != localIPs.end(); ++iter)
        {
          IPAddress &ip = (*iter);

          IPAddress bindIP(ip);
          bindIP.setPort(mBindPort);

          ULONG localPreference = nextLocalPreference;

          nextLocalPreference -= 0xF;
          if (nextLocalPreference > OPENPEER_SERVICES_ICESOCKET_LOCAL_PREFERENCE_MAX) {
            ZS_LOG_WARNING(Basic, log("unexpected local preference wrap around -- that a lot of IPs!"))
            --nextLocalPreference;
            nextLocalPreference = (nextLocalPreference | OPENPEER_SERVICES_ICESOCKET_LOCAL_PREFERENCE_MAX);
          }

          LocalSocketIPAddressMap::iterator found = mSocketLocalIPs.find(bindIP);
          if (found != mSocketLocalIPs.end()) {
            ZS_LOG_TRACE(log("already bound") + ZS_PARAM("ip", string(ip)))

            LocalSocketPtr localSocket = (*found).second;

            localSocket->updateLocalPreference(localPreference);  // update the local preference based on the ordering of the local IPs
            continue;
          }

          SocketPtr socket;

          ZS_LOG_DEBUG(log("attempting to bind to IP") + ZS_PARAM("ip", string(bindIP)))

          try {
            socket = Socket::createUDP();

            socket->bind(bindIP);
            socket->setBlocking(false);
            try {
#ifndef __QNX__
              socket->setOptionFlag(Socket::SetOptionFlag::IgnoreSigPipe, true);
#endif //ndef __QNX__
            } catch(Socket::Exceptions::UnsupportedSocketOption &) {
            }

            IPAddress local = socket->getLocalAddress();

            socket->setDelegate(mThisWeak.lock());

            mBindPort = local.getPort();
            bindIP.setPort(mBindPort);
            ZS_THROW_CUSTOM_PROPERTIES_1_IF(Socket::Exceptions::Unspecified, 0 == mBindPort, 0)
          } catch(Socket::Exceptions::Unspecified &error) {
            ZS_LOG_ERROR(Detail, log("bind error") + ZS_PARAM("error", error.errorCode()))
            socket.reset();
          }

          if (!socket) {
            ZS_LOG_WARNING(Debug, log("bind failure") + ZS_PARAM("bind port", mBindPort))
            continue;
          }

          ZS_LOG_DEBUG(log("bind successful") + ZS_PARAM("IP", bindIP.string()))

          LocalSocketPtr localSocket(new LocalSocket(mComponentID, localPreference));

          localSocket->mSocket = socket;
          localSocket->mLocal->mIPAddress = bindIP;

          String usernameFrag = (mFoundation ? mFoundation->getUsernameFrag() : mUsernameFrag);

          // algorithm to ensure that two candidates with same foundation IP / type end up with same foundation value
          localSocket->mLocal->mFoundation = IHelper::convertToHex(*IHelper::hash("foundation:" + usernameFrag + ":" + bindIP.string(false) + ":" + toString(localSocket->mLocal->mType), IHelper::HashAlgorthm_MD5));;

          mSocketLocalIPs[bindIP] = localSocket;
          mSockets[socket] = localSocket;
        }

        if ((hadNone) &&
            (mSockets.size() > 0)) {
          clearRebindTimer();
        }

        if ((!hadNone) &&
            (mSockets.size() < 1)) {
          clearRebindTimer();
        }

        if (!mRebindTimer) {
          mRebindTimer = Timer::create(mThisWeak.lock(), Seconds(mSockets.size() > 0 ? OPENPEER_SERVICES_REBIND_TIMER_WHEN_HAS_SOCKETS_IN_SECONDS : OPENPEER_SERVICES_REBIND_TIMER_WHEN_NO_SOCKETS_IN_SECONDS));
        }

        if (!mMonitoringWriteReady) {
          monitorWriteReadyOnAllSessions(false);
        }

        if (mSockets.size() > 0) {
          mRebindAttemptStartTime = Time();

          ZS_LOG_DEBUG(log("UDP port is bound"))
          return true;
        }

        if (!ISettings::getBool(OPENPEER_SERVICES_SETTING_ICE_SOCKET_NO_LOCAL_IPS_CAUSES_SOCKET_FAILURE)) {
          if (localIPs.size() < 1) {
            mRebindAttemptStartTime = Time();

            ZS_LOG_WARNING(Detail, log("no interfaces found - waiting for internet connectivity to return"))
            return false;
          }
        }

        Time tick = zsLib::now();

        if (Time() == mRebindAttemptStartTime) {
          mRebindAttemptStartTime = tick;
        }

        if ((mRebindAttemptStartTime + mMaxRebindAttemptDuration < tick) ||
            (Seconds(0) == mMaxRebindAttemptDuration)) {
          ZS_LOG_ERROR(Detail, log("unable to bind IP thus cancelling") + ZS_PARAM("bind port", mBindPort))
          setError(IHTTP::HTTPStatusCode_RequestTimeout, "unable to bind to local UDP port");
          cancel();
          return false;
        }

        ZS_LOG_WARNING(Detail, log("unable to bind to local UDP port but will try again") + ZS_PARAM("bind port", mBindPort))
        return false;
      }

      //-----------------------------------------------------------------------
      bool ICESocket::stepSTUN()
      {
        ZS_LOG_TRACE(log("step STUN"))

        for (LocalSocketMap::iterator iter = mSockets.begin(); iter != mSockets.end(); ++iter)
        {
          LocalSocketPtr &localSocket = (*iter).second;

          if (localSocket->mSTUNInfos.size() < 1) {
            ULONG localPreference = localSocket->mLocal->mLocalPreference;
            for (STUNServerInfoList::iterator infoIter = mSTUNServers.begin(); infoIter != mSTUNServers.end(); ++infoIter)
            {
              STUNServerInfoPtr &stunServerInfo = (*infoIter);
              if (stunServerInfo->hasData()) {
                STUNInfoPtr stunInfo(new STUNInfo(localSocket->mLocal->mComponentID, localPreference));
                stunInfo->mReflexive->mRelatedIP = localSocket->mLocal->mIPAddress;

                ZS_LOG_TRACE(log("constructed STUN info") + stunInfo->mReflexive->toDebug())

                stunInfo->mServerInfo = stunServerInfo;

                localSocket->mSTUNInfos[stunInfo] = stunInfo;
                localPreference -= 0xF;
              }
            }
          }

          for (STUNInfoMap::iterator infoIter = localSocket->mSTUNInfos.begin(); infoIter != localSocket->mSTUNInfos.end(); ++infoIter)
          {
            STUNInfoPtr &stunInfo = (*infoIter).second;

            if (!stunInfo->mSTUNDiscovery) {
              // clone the current candidate before modification
              stunInfo->mReflexive = CandidatePtr(new Candidate(*stunInfo->mReflexive));

              stunInfo->mReflexive->mIPAddress.clear();
              stunInfo->mReflexive->mFoundation.clear();

              ZS_LOG_DEBUG(log("performing STUN discovery using IP") + ZS_PARAM("base IP", string(localSocket->mLocal->mIPAddress)))
              if (stunInfo->mServerInfo->mSRVSTUNServerUDP) {
                stunInfo->mSTUNDiscovery = ISTUNDiscovery::create(getAssociatedMessageQueue(), mThisWeak.lock(), stunInfo->mServerInfo->mSRVSTUNServerUDP);
              }
              if (!stunInfo->mServerInfo->mSTUNServer.isEmpty()) {
                stunInfo->mSTUNDiscovery = ISTUNDiscovery::create(getAssociatedMessageQueue(), mThisWeak.lock(), stunInfo->mServerInfo->mSTUNServer);
              }
              localSocket->mSTUNDiscoveries[stunInfo->mSTUNDiscovery] = stunInfo;
              mSocketSTUNs[stunInfo->mSTUNDiscovery] = localSocket;
            }

            if (!stunInfo->mSTUNDiscovery) {
              ZS_LOG_WARNING(Detail, log("unable to perform STUN discovery for IP") + ZS_PARAM("base IP", string(localSocket->mLocal->mIPAddress)))
              continue;
            }

            if (!stunInfo->mSTUNDiscovery->isComplete()) {
              ZS_LOG_TRACE(log("stun discovery not complete yet") + ZS_PARAM("base IP", string(localSocket->mLocal->mIPAddress)))
              continue;
            }

            if (!stunInfo->mReflexive->mIPAddress.isAddressEmpty()) {
              ZS_LOG_TRACE(log("stun discovery already complete") + ZS_PARAM("base IP", string(localSocket->mLocal->mIPAddress)) + ZS_PARAM("previously discovered", string(stunInfo->mReflexive->mIPAddress)))
              continue;
            }

            // clone current before modification
            stunInfo->mReflexive = CandidatePtr(new Candidate(*stunInfo->mReflexive));

            stunInfo->mReflexive->mIPAddress = stunInfo->mSTUNDiscovery->getMappedAddress();
            String usernameFrag = (mFoundation ? mFoundation->getUsernameFrag() : mUsernameFrag);
            stunInfo->mReflexive->mFoundation = IHelper::convertToHex(*IHelper::hash("foundation:" + usernameFrag + ":" + stunInfo->mReflexive->mIPAddress.string(false) + ":" + toString(stunInfo->mReflexive->mType), IHelper::HashAlgorthm_MD5));;

            ZS_LOG_DEBUG(log("stun discovery complete") + ZS_PARAM("base IP", string(localSocket->mLocal->mIPAddress)) + ZS_PARAM("discovered", string(stunInfo->mReflexive->mIPAddress)))
          }
        }

        return true;
      }

      //-----------------------------------------------------------------------
      bool ICESocket::stepTURN()
      {
        Time tick = zsLib::now();

        bool shouldSleep = false;

        if (Duration() != mTURNShutdownIfNotUsedBy) {
          if (mTURNLastUsed + mTURNShutdownIfNotUsedBy < tick) {
            // the socket can be put to sleep...
            mTURNShutdownIfNotUsedBy = Duration();  // reset no need to wake up...
            shouldSleep = true;
          }
        } else {
          shouldSleep = true;
        }

        ZS_LOG_TRACE(log("step TURN") + ZS_PARAM("should sleep", shouldSleep) + ZS_PARAM("tick", tick))

        bool allConnected = true;
        bool allSleeping = true;

        for (LocalSocketMap::iterator iter = mSockets.begin(); iter != mSockets.end(); ++iter)
        {
          LocalSocketPtr &localSocket = (*iter).second;

          if (localSocket->mTURNInfos.size() < 1) {
            ULONG localPreference = localSocket->mLocal->mLocalPreference;
            for (TURNServerInfoList::iterator infoIter = mTURNServers.begin(); infoIter != mTURNServers.end(); ++infoIter)
            {
              TURNServerInfoPtr &turnServerInfo = (*infoIter);
              if (turnServerInfo->hasData()) {
                TURNInfoPtr turnInfo(new TURNInfo(localSocket->mLocal->mComponentID, localPreference));
                turnInfo->mRelay->mRelatedIP = localSocket->mLocal->mIPAddress;

                ZS_LOG_TRACE(log("constructed TURN info") + turnInfo->mRelay->toDebug())

                turnInfo->mServerInfo = turnServerInfo;

                localSocket->mTURNInfos[turnInfo] = turnInfo;
                localPreference -= 0xF;
              }
            }
          }

          for (TURNInfoMap::iterator infoIter = localSocket->mTURNInfos.begin(); infoIter != localSocket->mTURNInfos.end(); )
          {
            TURNInfoMap::iterator currentInfoIter = infoIter; ++infoIter;

            TURNInfoPtr &turnInfo = (*currentInfoIter).second;

            if (shouldSleep) {
              if (!turnInfo->mTURNSocket) {
                ZS_LOG_TRACE(log("no TURN server present for IP") + turnInfo->mRelay->toDebug())
                continue;
              }
              turnInfo->mTURNSocket->shutdown();
              if (ITURNSocket::TURNSocketState_ShuttingDown == turnInfo->mTURNSocket->getState()) {
                ZS_LOG_TRACE(log("TURN still shutting down") + turnInfo->mRelay->toDebug())
                allSleeping = false;
                continue;
              }

              ZS_LOG_DEBUG(log("TURN shutdown complete (thus clearing TURN socket)") + turnInfo->mRelay->toDebug())

              localSocket->clearTURN(turnInfo->mTURNSocket);
              clearTURN(turnInfo->mTURNSocket);

              turnInfo->mTURNSocket.reset();
              continue;
            }

            if (turnInfo->mTURNSocket) {
              ITURNSocket::TURNSocketStates state = turnInfo->mTURNSocket->getState();
              switch (state) {
                case ITURNSocket::TURNSocketState_Pending:    {
                  allConnected = false;
                  break;
                }
                case ITURNSocket::TURNSocketState_Ready:      {

                  // reset the retry for TURN since it connected just fine
                  turnInfo->mTURNRetryAfter = Time();
                  turnInfo->mTURNRetryDuration = Milliseconds(OPENPEER_SERVICES_TURN_DEFAULT_RETRY_AFTER_DURATION_IN_MILLISECONDS);

                  if (turnInfo->mRelay->mIPAddress.isAddressEmpty()) {
                    // clone before modifying
                    turnInfo->mRelay = CandidatePtr(new Candidate(*turnInfo->mRelay));

                    turnInfo->mRelay->mIPAddress = turnInfo->mTURNSocket->getRelayedIP();
                    turnInfo->mServerIP = turnInfo->mTURNSocket->getActiveServerIP();

                    String usernameFrag = (mFoundation ? mFoundation->getUsernameFrag() : mUsernameFrag);
                    turnInfo->mRelay->mFoundation = IHelper::convertToHex(*IHelper::hash("foundation:" + usernameFrag + ":" + turnInfo->mRelay->mIPAddress.string(false) + ":" + toString(turnInfo->mRelay->mType), IHelper::HashAlgorthm_MD5));;

                    // remember newly discovered relay IP address mapping
                    localSocket->mTURNRelayIPs[turnInfo->mRelay->mIPAddress] = turnInfo;
                    localSocket->mTURNServerIPs[turnInfo->mServerIP] = turnInfo;

                    ZS_LOG_DEBUG(log("TURN relay ready") + ZS_PARAM("base IP", string(localSocket->mLocal->mIPAddress)) + ZS_PARAM("discovered", string(turnInfo->mRelay->mIPAddress)))
                  }
                  break;
                }
                case ITURNSocket::TURNSocketState_ShuttingDown: {
                  allConnected = false;
                  break;
                }
                case ITURNSocket::TURNSocketState_Shutdown:   {

                  allConnected = false;
                  localSocket->clearTURN(turnInfo->mTURNSocket);
                  clearTURN(turnInfo->mTURNSocket);
                  turnInfo->mTURNSocket.reset();

                  // clone before modifying
                  turnInfo->mRelay = CandidatePtr(new Candidate(*turnInfo->mRelay));

                  turnInfo->mRelay->mIPAddress.clear();
                  turnInfo->mRelay->mFoundation.clear();

                  turnInfo->mTURNRetryAfter = tick + turnInfo->mTURNRetryDuration;

                  ZS_LOG_WARNING(Detail, log("turn socket shutdown") + ZS_PARAM("retry duration (ms)", turnInfo->mTURNRetryDuration.total_milliseconds()) + ZS_PARAM("retry after", turnInfo->mTURNRetryAfter))

                  turnInfo->mTURNRetryDuration = turnInfo->mTURNRetryDuration + turnInfo->mTURNRetryDuration;
                  if (turnInfo->mTURNRetryDuration > Seconds(OPENPEER_SERVICES_TURN_MAX_RETRY_AFTER_DURATION_IN_SECONDS)) {
                    turnInfo->mTURNRetryDuration = Seconds(OPENPEER_SERVICES_TURN_MAX_RETRY_AFTER_DURATION_IN_SECONDS);
                  }

                  break;
                }
              }
            }

            if (!turnInfo->mTURNSocket) {

              // TURN will not start until all STUN discoveries everywhere are complete
              for (LocalSocketMap::iterator checkIter = mSockets.begin(); checkIter != mSockets.end(); )
              {
                LocalSocketMap::iterator currentCheckIter = checkIter; ++checkIter;

                LocalSocketPtr &checkSocket = (*currentCheckIter).second;

                for (STUNInfoDiscoveryMap::iterator stunIter = checkSocket->mSTUNDiscoveries.begin(); stunIter != checkSocket->mSTUNDiscoveries.end(); )
                {
                  STUNInfoDiscoveryMap::iterator currentStunIter = stunIter; ++stunIter;

                  STUNInfoPtr &stunInfo = (*currentStunIter).second;
                  if (stunInfo->mSTUNDiscovery) {
                    if (!stunInfo->mSTUNDiscovery->isComplete()) {
                      ZS_LOG_TRACE(log("cannot create TURN as STUN discovery not complete") + ZS_PARAM("stun discovery ID", stunInfo->mSTUNDiscovery->getID()) + stunInfo->mReflexive->toDebug())

                      allConnected = false;
                      goto not_all_stun_discoveries_done;
                    }
                  }
                }
              }

              goto all_stun_discoveries_done;

            not_all_stun_discoveries_done:
              ZS_LOG_TRACE(log("TURN sockets are not allowed to be created until all STUN discoveries are completed"))
              continue;

            all_stun_discoveries_done:

              bool foundDuplicate = false;

              // check to see if TURN should be created (must not be another socket with TURN with the same reflexive address)
              for (LocalSocketMap::iterator checkIter = mSockets.begin(); checkIter != mSockets.end(); )
              {
                LocalSocketMap::iterator currentCheckIter = checkIter; ++checkIter;

                LocalSocketPtr &checkSocket = (*currentCheckIter).second;
                if (checkSocket == localSocket) {
                  ZS_LOG_TRACE(log("turn check - no need to compare against same socket (i.e. self)"))
                  continue;
                }

                for (TURNInfoMap::iterator turnCheckIter = checkSocket->mTURNInfos.begin(); turnCheckIter != checkSocket->mTURNInfos.end(); )
                {
                  TURNInfoMap::iterator currentTurnCheckIter = turnCheckIter; ++turnCheckIter;

                  TURNInfoPtr &turnInfo = (*currentTurnCheckIter).second;
                  if (turnInfo->mTURNSocket) goto found_turn_connection;
                }

              did_not_find_turn_connection:
                ZS_LOG_TRACE(log("since a TURN connection does not exist for the alternative local socket there's no need to check if it's duplicate or not") + checkSocket->mLocal->toDebug())
                continue;

              found_turn_connection:

                // NOTE: must check "check socket" against "local socket"
                // followed by "local socket" against "check socket" because it
                // is possible the local socket could contain an extra IP
                // that was not found in the check socket. Only if every IP
                // in the check socket was found in every IP of the local
                // socket and every IP in the local socket is found in the
                // check socket do we truly consider it a full duplicate.

                for (STUNInfoDiscoveryMap::iterator stunCheckIter = checkSocket->mSTUNDiscoveries.begin(); stunCheckIter != checkSocket->mSTUNDiscoveries.end(); )
                {
                  STUNInfoDiscoveryMap::iterator currentStunCheckIter = stunCheckIter; ++stunCheckIter;

                  STUNInfoPtr &stunCheckInfo = (*currentStunCheckIter).second;
                  if (stunCheckInfo->mReflexive->mIPAddress.isAddressEmpty()) continue;

                  bool found = false;

                  for (STUNInfoDiscoveryMap::iterator stunLocalIter = localSocket->mSTUNDiscoveries.begin(); stunLocalIter != localSocket->mSTUNDiscoveries.end(); )
                  {
                    STUNInfoDiscoveryMap::iterator currentStunLocalIter = stunLocalIter; ++stunLocalIter;

                    STUNInfoPtr &stunLocalInfo = (*currentStunLocalIter).second;
                    if (stunLocalInfo->mReflexive->mIPAddress.isAddressEmpty()) continue;

                    if (stunCheckInfo->mReflexive->mIPAddress != stunLocalInfo->mReflexive->mIPAddress) {
                      ZS_LOG_TRACE(log("turn check - mapped address does not match (but perhaps it will match another discovered IP)") + ZS_PARAM("check candidate", stunCheckInfo->mReflexive->toDebug()) + ZS_PARAM("local candidate", stunLocalInfo->mReflexive->toDebug()))
                      continue;
                    }

                    found = true;
                    break;
                  }

                  if (found) continue;

                  ZS_LOG_TRACE(log("turn check - mapped address in checked socket does not exist in local socket thus still allowed to create TURN") + ZS_PARAM("check candidate", stunCheckInfo->mReflexive->toDebug()))
                  goto reflexive_mismatch;
                }

                for (STUNInfoDiscoveryMap::iterator stunLocalIter = localSocket->mSTUNDiscoveries.begin(); stunLocalIter != localSocket->mSTUNDiscoveries.end(); )
                {
                  STUNInfoDiscoveryMap::iterator currentStunLocalIter = stunLocalIter; ++stunLocalIter;

                  STUNInfoPtr &stunLocalInfo = (*currentStunLocalIter).second;
                  if (stunLocalInfo->mReflexive->mIPAddress.isAddressEmpty()) continue;

                  bool found = false;

                  for (STUNInfoDiscoveryMap::iterator stunCheckIter = checkSocket->mSTUNDiscoveries.begin(); stunCheckIter != checkSocket->mSTUNDiscoveries.end(); )
                  {
                    STUNInfoDiscoveryMap::iterator currentStunCheckIter = stunCheckIter; ++stunCheckIter;

                    STUNInfoPtr &stunCheckInfo = (*currentStunCheckIter).second;
                    if (stunCheckInfo->mReflexive->mIPAddress.isAddressEmpty()) continue;

                    if (stunLocalInfo->mReflexive->mIPAddress != stunCheckInfo->mReflexive->mIPAddress) {
                      ZS_LOG_TRACE(log("turn check - mapped address does not match (but perhaps it will match another discovered IP)") + ZS_PARAM("local candidate", stunLocalInfo->mReflexive->toDebug()) + ZS_PARAM("check candidate", stunCheckInfo->mReflexive->toDebug()))
                      continue;
                    }
                    found = true;
                    break;
                  }
                  if (found) continue;

                  ZS_LOG_TRACE(log("turn check - mapped address in local socket does not exist in checked socket thus still allowed to create TURN") + ZS_PARAM("local candidate", stunLocalInfo->mReflexive->toDebug()))
                  goto reflexive_mismatch;
                }

                goto reflexive_all_duplicate;

              reflexive_mismatch:
                ZS_LOG_TRACE(log("at least one reflexive mapped address is different or missing compared to this local socket") + checkSocket->mLocal->toDebug())
                continue;

              reflexive_all_duplicate:

                ZS_LOG_TRACE(log("turn check - duplicate TURN socket already exists on duplication reflexive socket thus not safe to create TURN"))
                foundDuplicate = true;
                break;
              }

              if (foundDuplicate) continue;
            }

            if (!turnInfo->mTURNSocket) {
              // clone before modification
              turnInfo->mRelay = CandidatePtr(new Candidate(*(turnInfo->mRelay)));

              turnInfo->mRelay->mIPAddress.clear();
              turnInfo->mRelay->mFoundation.clear();

              allConnected = false;

              bool okayToContactTURN = true;

              if (Time() != turnInfo->mTURNRetryAfter) {
                okayToContactTURN = (tick > turnInfo->mTURNRetryAfter);
              }

              if (okayToContactTURN) {
                if (!turnInfo->mServerInfo->mTURNServer.isEmpty()) {
                  turnInfo->mTURNSocket = ITURNSocket::create(
                                                              getAssociatedMessageQueue(),
                                                              mThisWeak.lock(),
                                                              turnInfo->mServerInfo->mTURNServer,
                                                              turnInfo->mServerInfo->mTURNServerUsername,
                                                              turnInfo->mServerInfo->mTURNServerPassword,
                                                              mFirstWORDInAnyPacketWillNotConflictWithTURNChannels
                                                              );
                } else {
                  turnInfo->mTURNSocket = ITURNSocket::create(
                                                              getAssociatedMessageQueue(),
                                                              mThisWeak.lock(),
                                                              turnInfo->mServerInfo->mSRVTURNServerUDP,
                                                              turnInfo->mServerInfo->mSRVTURNServerTCP,
                                                              turnInfo->mServerInfo->mTURNServerUsername,
                                                              turnInfo->mServerInfo->mTURNServerPassword,
                                                              mFirstWORDInAnyPacketWillNotConflictWithTURNChannels
                                                              );
                }

                localSocket->mTURNSockets[turnInfo->mTURNSocket] = turnInfo;
                mSocketTURNs[turnInfo->mTURNSocket] = localSocket;

                ZS_LOG_DEBUG(log("TURN socket created") + ZS_PARAM("base IP", string(localSocket->mLocal->mIPAddress)) + ZS_PARAM("TURN socket ID", turnInfo->mTURNSocket->getID()))
              } else {
                if (!turnInfo->mTURNRetryTimer) {
                  Duration waitTime;
                  if (tick < turnInfo->mTURNRetryAfter) {
                    waitTime = turnInfo->mTURNRetryAfter - tick;
                  } else {
                    waitTime = Milliseconds(1);
                  }

                  ZS_LOG_DEBUG(log("must wait to retry logging into TURN server") + ZS_PARAM("wait time (ms)", waitTime.total_milliseconds()) + ZS_PARAM("retry duration (ms)", turnInfo->mTURNRetryDuration.total_milliseconds()) + ZS_PARAM("retry after", turnInfo->mTURNRetryAfter))
                  turnInfo->mTURNRetryTimer = Timer::create(mThisWeak.lock(), waitTime, false);
                }
              }
            }
          }
        }

        ZS_LOG_TRACE(log("step TURN complete") + ZS_PARAM("should sleep", shouldSleep) + ZS_PARAM("all sleeping", allSleeping) + ZS_PARAM("all connected", allConnected))

        if (shouldSleep) {
          if (allSleeping) {
            setState(IICESocket::ICESocketState_Sleeping);
          } else {
            setState(IICESocket::ICESocketState_GoingToSleep);
          }
          return false;
        }

        return allConnected;
      }

      //-----------------------------------------------------------------------
      bool ICESocket::stepCandidates()
      {
        DWORD crcValue = 0;

        CRC32 crc;
        for (LocalSocketMap::iterator iter = mSockets.begin(); iter != mSockets.end(); ++iter)
        {
          LocalSocketPtr &localSocket = (*iter).second;

          if (!localSocket->mLocal->mIPAddress.isEmpty()) {
            crc.Update((const BYTE *)(":local:"), strlen(":local:"));

            IPv6PortPair &portPair = localSocket->mLocal->mIPAddress;
            crc.Update((const BYTE *)(&portPair), sizeof(IPv6PortPair));
          }

          for (STUNInfoMap::iterator stunInfoIter = localSocket->mSTUNInfos.begin(); stunInfoIter != localSocket->mSTUNInfos.end(); ++stunInfoIter)
          {
            STUNInfoPtr &stunInfo = (*stunInfoIter).second;

            if (!stunInfo->mReflexive->mIPAddress.isEmpty()) {
              crc.Update((const BYTE *)(":reflexive:"), strlen(":reflexive:"));

              IPv6PortPair &portPair = stunInfo->mReflexive->mIPAddress;
              crc.Update((const BYTE *)(&portPair), sizeof(IPv6PortPair));
            }
          }

          for (TURNInfoMap::iterator turnInfoIter = localSocket->mTURNInfos.begin(); turnInfoIter != localSocket->mTURNInfos.end(); ++turnInfoIter)
          {
            TURNInfoPtr &turnInfo = (*turnInfoIter).second;

            if (!turnInfo->mRelay->mIPAddress.isEmpty()) {
              crc.Update((const BYTE *)(":relay:"), strlen(":relay:"));

              IPv6PortPair &portPair = turnInfo->mRelay->mIPAddress;
              crc.Update((const BYTE *)(&portPair), sizeof(IPv6PortPair));
            }
          }
        }
        crc.Final((BYTE *)(&crcValue));

        if (mLastCandidateCRC == crcValue) {
          ZS_LOG_TRACE(log("candidate list has not changed") + ZS_PARAM("crc", string(crcValue)))
          return true;
        }

        ZS_LOG_DEBUG(log("candidate list has changed") + ZS_PARAM("crc", string(crcValue)))

        mLastCandidateCRC = crcValue;

        mSubscriptions.delegate()->onICESocketCandidatesChanged(mThisWeak.lock());
        mNotifiedCandidateChanged = true;
        return true;
      }

      //-----------------------------------------------------------------------
      bool ICESocket::getLocalIPs(IPAddressList &outIPs)
      {
        class Sorter
        {
        public:
          //-------------------------------------------------------------------
          struct Data
          {
            IPAddress mIP;
            OrderID mOrderIndex;
            ULONG mIndex;

            Data() : mOrderIndex(0), mIndex(0) {}
          };

          //-------------------------------------------------------------------
          static bool compareLocalIPs(const Data &data1, const Data &data2)
          {
            if (data1.mOrderIndex < data2.mOrderIndex) return true;
            if (data1.mOrderIndex > data2.mOrderIndex) return false;
            if (data1.mIndex < data2.mIndex) return true;
            if (data1.mIndex > data2.mIndex) return false;

            if (data1.mIP.isIPv4()) {
              if (data2.mIP.isIPv4()) {
                return data1.mIP < data2.mIP;
              }
              return true;
            }

            if (data2.mIP.isIPv4())
              return false;
            
            return data1.mIP < data2.mIP;
          }

          //-------------------------------------------------------------------
          static Data prepare(const IPAddress &ip)
          {
            Data data;
            data.mIP = ip;
            return data;
          }

          //-------------------------------------------------------------------
          static Data prepare(
                              const IPAddress &ip,
                              const char *name,
                              const InterfaceNameToOrderMap &prefs
                              )
          {
            Data data;

            data.mIP = ip;

            if (prefs.size() > 0) {
              const char *numStr = name + strlen(name);

              for (; numStr != name; --numStr) {
                if ('\0' == *numStr) continue;
                if (isdigit(*numStr)) continue;

                ++numStr; // skip the non-digit
                break;
              }

              String namePart;

              if (numStr != name) {

                // found a number on the end
                size_t length = (numStr - name);

                namePart = name;
                namePart = namePart.substr(0, length);

                try {
                  data.mIndex = Numeric<decltype(data.mIndex)>(numStr);
                } catch(Numeric<decltype(data.mIndex)>::ValueOutOfRange &) {
                  ZS_LOG_WARNING(Detail, Log::Params("number failed to convert", "ICESocket") + ZS_PARAM("name", name))
                }
              } else {
                namePart = name;
              }

              InterfaceNameToOrderMap::const_iterator found = prefs.find(namePart);
              if (found != prefs.end()) {
                data.mOrderIndex = (*found).second;
              } else {
                data.mOrderIndex = prefs.size();  // last
              }
            }

            return data;
          }
        };

        typedef std::list<Sorter::Data> DataList;

        DataList data;

#ifdef _WIN32
        // http://tangentsoft.net/wskfaq/examples/ipaddr.html

        // OR
        ZS_LOG_DEBUG(log("--- GATHERING LOCAL IPs: START ---"))

        ULONG size = 0;

        // the 1st call is just to get the table size
        if(GetIpAddrTable(NULL, &size, FALSE) == ERROR_INSUFFICIENT_BUFFER)
        {
          // now that you know the size, allocate a pointer
          MIB_IPADDRTABLE *ipAddr = (MIB_IPADDRTABLE *) new BYTE[size];
          // the 2nd call is to retrieve the info for real
          if(GetIpAddrTable(ipAddr, &size, TRUE) == NO_ERROR)
          {
            // need to loop it to handle multiple interfaces
            for(DWORD i = 0; i < ipAddr->dwNumEntries; i++)
            {
              // this is the IP address
              DWORD dwordIP = ntohl(ipAddr->table[i].dwAddr);
              IPAddress ip(dwordIP);

              if (ip.isAddressEmpty()) continue;
              if (ip.isLoopback()) continue;
              if (ip.isAddrAny()) continue;

              ip.setPort(mBindPort);

              ZS_LOG_DEBUG(log("found local IP") + ZS_PARAM("ip", ip.string()))

              data.push_back(Sorter::prepare(ip));
            }
          }
        }
        ZS_LOG_DEBUG(log("--- GATHERING LOCAL IPs: END ---"))
#else
        ifaddrs *ifAddrStruct = NULL;
        ifaddrs *ifa = NULL;

        getifaddrs(&ifAddrStruct);

        ZS_LOG_DEBUG(log("--- GATHERING LOCAL IPs: START ---"))
        for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next)
        {
          IPAddress ip;
          if (AF_INET == ifa ->ifa_addr->sa_family) {
            ip = IPAddress(*((sockaddr_in *)ifa->ifa_addr));      // this is an IPv4 address
          } else if (AF_INET6 == ifa->ifa_addr->sa_family) {
            if (mSupportIPv6) {
              ip = IPAddress(*((sockaddr_in6 *)ifa->ifa_addr));     // this is an IPv6 address
            }
          }

          // do not add these addresses...
          if (ip.isAddressEmpty()) continue;
          if (ip.isLoopback()) continue;
          if (ip.isAddrAny()) continue;

          ip.setPort(mBindPort);

          ZS_LOG_DEBUG(log("found local IP") + ZS_PARAM("local IP", ip.string()) + ZS_PARAM("name", ifa->ifa_name))

          data.push_back(Sorter::prepare(ip, ifa->ifa_name, mInterfaceOrders));
        }
        ZS_LOG_DEBUG(log("--- GATHERING LOCAL IPs: END ---"))

        if (ifAddrStruct) {
          freeifaddrs(ifAddrStruct);
          ifAddrStruct = NULL;
        }
#endif //_WIN32

        data.sort(Sorter::compareLocalIPs);

        for (DataList::iterator iter = data.begin(); iter != data.end(); ++iter)
        {
          Sorter::Data &value = (*iter);
          outIPs.push_back(value.mIP);
        }

        if (outIPs.empty()) {
          ZS_LOG_DEBUG(log("failed to read any local IPs"))
          return false;
        }

        return true;
      }

      //-----------------------------------------------------------------------
      void ICESocket::stopSTUNAndTURN(LocalSocketPtr localSocket)
      {
        for (TURNInfoMap::iterator infoIter = localSocket->mTURNInfos.begin(); infoIter != localSocket->mTURNInfos.end();)
        {
          TURNInfoMap::iterator infoCurrent = infoIter; ++infoIter;

          TURNInfoPtr turnInfo = (*infoCurrent).second;

          if (turnInfo->mTURNRetryTimer) {
            turnInfo->mTURNRetryTimer->cancel();
            turnInfo->mTURNRetryTimer.reset();
          }

          if (turnInfo->mTURNSocket) {
            ZS_LOG_DEBUG(log("shutting down TURN socket") + ZS_PARAM("TURN socket ID", turnInfo->mTURNSocket->getID()))

            turnInfo->mTURNSocket->shutdown();
            if (ITURNSocket::TURNSocketState_Shutdown == turnInfo->mTURNSocket->getState()) {
              ZS_LOG_DEBUG(log("TURN socket shutdown completed") + ZS_PARAM("TURN socket ID", turnInfo->mTURNSocket->getID()))

              localSocket->clearTURN(turnInfo->mTURNSocket);
              clearTURN(turnInfo->mTURNSocket);

              turnInfo->mTURNSocket.reset();
            }
          }
        }

        for (STUNInfoMap::iterator infoIter = localSocket->mSTUNInfos.begin(); infoIter != localSocket->mSTUNInfos.end();)
        {
          STUNInfoMap::iterator infoCurrent = infoIter; ++infoIter;

          STUNInfoPtr stunInfo = (*infoCurrent).second;

          if (stunInfo->mSTUNDiscovery) {
            ZS_LOG_DEBUG(log("cancelling STUN discovery") + ZS_PARAM("stun socket id", stunInfo->mSTUNDiscovery->getID()))

            localSocket->clearSTUN(stunInfo->mSTUNDiscovery);
            clearSTUN(stunInfo->mSTUNDiscovery);
            stunInfo->mSTUNDiscovery->cancel();
            stunInfo->mSTUNDiscovery.reset();
          }
        }
      }

      //-----------------------------------------------------------------------
      bool ICESocket::closeIfTURNGone(LocalSocketPtr localSocket)
      {
        if (localSocket->mTURNSockets.size() > 0) {
          ZS_LOG_DEBUG(log("turn socket(s) still pending") + ZS_PARAM("local candidate", localSocket->mLocal->toDebug()) + ZS_PARAM("total TURN sockets remaining", localSocket->mTURNInfos.size()))
          return false;
        }

        clearRelated(localSocket);
        return true;
      }

      //-----------------------------------------------------------------------
      void ICESocket::hardClose(LocalSocketPtr localSocket)
      {
        if (localSocket->mSocket) {
          ZS_LOG_WARNING(Detail, log("performing hard shutdown on socket") + ZS_PARAM("local candidate", localSocket->mLocal->toDebug()))
        }

        clearRelated(localSocket);
      }

      //-----------------------------------------------------------------------
      void ICESocket::clearRelated(LocalSocketPtr localSocket)
      {
        stopSTUNAndTURN(localSocket);

        for (TURNInfoMap::iterator iter = localSocket->mTURNInfos.begin(); iter != localSocket->mTURNInfos.end(); ++iter) {
          TURNInfoPtr &turnInfo = (*iter).second;
          if (turnInfo->mTURNSocket) {
            clearTURN(turnInfo->mTURNSocket);
            turnInfo->mTURNSocket->shutdown();
            turnInfo->mTURNSocket.reset();
          }
        }

        localSocket->mTURNSockets.clear();  // forget any remaining alive

        if (localSocket->mSocket) {
          LocalSocketMap::iterator found = mSockets.find(localSocket->mSocket);
          if (found != mSockets.end()) {
            mSockets.erase(found);
          }

          localSocket->mSocket->close();
          localSocket->mSocket.reset();
        }

        LocalSocketIPAddressMap::iterator found = mSocketLocalIPs.find(localSocket->mLocal->mIPAddress);
        if (found != mSocketLocalIPs.end()) {
          mSocketLocalIPs.erase(found);
        }

        for (QuickRouteMap::iterator iter_DoNotUse = mRoutes.begin(); iter_DoNotUse != mRoutes.end(); )
        {
          QuickRouteMap::iterator current = iter_DoNotUse;
          ++iter_DoNotUse;

          const RouteTuple &tuple = (*current).first;

          const IPAddress &viaLocalIP = boost::get<1>(tuple);
          
          if (!viaLocalIP.isEqualIgnoringIPv4Format(localSocket->mLocal->mIPAddress)) continue;
          
          mRoutes.erase(current);
        }
      }
      
      //-----------------------------------------------------------------------
      void ICESocket::clearTURN(ITURNSocketPtr turn)
      {
        if (!turn) return;
        LocalSocketTURNSocketMap::iterator found = mSocketTURNs.find(turn);
        if (found == mSocketTURNs.end()) return;

        mSocketTURNs.erase(found);
      }

      //-----------------------------------------------------------------------
      void ICESocket::clearSTUN(ISTUNDiscoveryPtr stun)
      {
        if (!stun) return;
        LocalSocketSTUNDiscoveryMap::iterator found = mSocketSTUNs.find(stun);
        if (found == mSocketSTUNs.end()) return;

        mSocketSTUNs.erase(found);
      }

      //-----------------------------------------------------------------------
      void ICESocket::internalReceivedData(
                                           const Candidate &viaCandidate,
                                           const Candidate &viaLocalCandidate,
                                           const IPAddress &source,
                                           const BYTE *buffer,
                                           size_t bufferLengthInBytes
                                           )
      {
        // WARNING: DO NOT CALL THIS METHOD WHILE INSIDE A LOCK AS IT COULD
        //          ** DEADLOCK **. This method calls delegates synchronously.
        STUNPacketPtr stun = STUNPacket::parseIfSTUN(buffer, bufferLengthInBytes, STUNPacket::RFC_AllowAll, false, "ICESocket", mID);

        if (stun) {
          OPENPEER_SERVICES_WIRE_LOG_TRACE(log("received STUN packet") + ZS_PARAM("via candidate", viaCandidate.toDebug()) + ZS_PARAM("source ip", source.string()) + ZS_PARAM("class", stun->classAsString()) + ZS_PARAM("method", stun->methodAsString()))
          ITURNSocketPtr turn;
          if (IICESocket::Type_Relayed != normalize(viaCandidate.mType)) {

            // scope: going into a lock to obtain
            {
              AutoRecursiveLock lock(*this);
              LocalSocketIPAddressMap::iterator found = mSocketLocalIPs.find(getViaLocalIP(viaCandidate));
              if (found != mSocketLocalIPs.end()) {
                LocalSocketPtr &localSocket = (*found).second;

                TURNInfoRelatedIPMap::iterator foundRelay = localSocket->mTURNServerIPs.find(source);
                if (foundRelay != localSocket->mTURNServerIPs.end()) {
                  turn = (*foundRelay).second->mTURNSocket;
                }
              }
            }

            if (turn) {
              if (turn->handleSTUNPacket(source, stun)) return;
            }
          }

          if (!turn) {
            // if TURN was used, we would already called this routine... (i.e. prevent double lookup)
            if (ISTUNRequesterManager::handleSTUNPacket(source, stun)) return;
          }

          UseICESocketSessionPtr next;

          if (STUNPacket::Method_Binding == stun->mMethod) {
            if ((STUNPacket::Class_Request != stun->mClass) &&
                (STUNPacket::Class_Indication != stun->mClass)) {
              ZS_LOG_WARNING(Debug, log("ignoring STUN binding which is not a request/indication"))
              return;
            }
          }

          if (STUNPacket::RFC_5766_TURN == stun->guessRFC(STUNPacket::RFC_AllowAll)) {
            ZS_LOG_TRACE(log("ignoring TURN message (likely for cancelled requests)"))
            return;    // ignore any ICE indications
          }

          if (stun->mUsername.isEmpty()) {
            ZS_LOG_WARNING(Detail, log("did not find ICE username on packet thus ignoring STUN packet"))
            return;  // no username is present - this cannot be for us...
          }

          // username is present... but does it have the correct components?
          size_t pos = stun->mUsername.find(":");
          if (String::npos == pos) {
            ZS_LOG_WARNING(Detail, log("did not find \":\" in username on packet thus ignoring STUN packet"))
            return;  // no ":" means that it can't be an ICE requeest
          }

          // split the string at the post
          String localUsernameFrag = stun->mUsername.substr(0, pos); // this would be our local username
          String remoteUsernameFrag = stun->mUsername.substr(pos+1);  // this would be the remote username

          while (true)
          {
            // scope: find the next socket session to test in the list while in a lock
            {
              AutoRecursiveLock lock(*this);
              if (mSessions.size() < 1) break;  // no sessions to check

              if (!next) {
                next = (*(mSessions.begin())).second;
              } else {
                ICESocketSessionMap::iterator iter = mSessions.find(next->getID());
                if (iter == mSessions.end()) {
                  // should have been found BUT it is possible the list was
                  // changed while outside the lock so start the search from
                  // the beginning again...
                  next = (*(mSessions.begin())).second;
                } else {
                  ++iter;
                  if (iter == mSessions.end()) {
                    // while it is possible that a new session was inserted
                    // while we were processing we don't have ot check it
                    // as this packet could not possibly be for that session.
                    break;
                  }
                  next = (*iter).second;
                }
              }
            }

            if (!next) break;
            if (next->handleSTUNPacket(viaCandidate, source, stun, localUsernameFrag, remoteUsernameFrag)) return;
          }

          ZS_LOG_WARNING(Debug, log("did not find session that handles STUN packet") + stun->toDebug())

          // no STUN outlets left to check so just exit...
          return;
        }

        // this isn't a STUN packet but it might be TURN channel data (but only if came from a TURN server)
        if (IICESocket::Type_Relayed != normalize(viaCandidate.mType)) {
          ITURNSocketPtr turn;

          // scope: going into a lock to obtain
          {
            AutoRecursiveLock lock(*this);
            LocalSocketIPAddressMap::iterator found = mSocketLocalIPs.find(getViaLocalIP(viaCandidate));
            if (found != mSocketLocalIPs.end()) {
              LocalSocketPtr &localSocket = (*found).second;

              TURNInfoRelatedIPMap::iterator foundRelay = localSocket->mTURNServerIPs.find(source);
              if (foundRelay != localSocket->mTURNServerIPs.end()) {
                turn = (*foundRelay).second->mTURNSocket;
              }
            }
          }

          if (turn) {
            if (turn->handleChannelData(source, buffer, bufferLengthInBytes)) return;
          }
        }

        UseICESocketSessionPtr next;

        // try to find a quick route to the session
        {
          AutoRecursiveLock lock(*this);
          RouteTuple tuple(viaCandidate.mIPAddress, viaLocalCandidate.mIPAddress, source);
          QuickRouteMap::iterator found = mRoutes.find(tuple);
          if (found != mRoutes.end()) {
            next = (*found).second;
          }
        }

        if (next) {
          // we found a quick route - but does it actually handle the packet
          // (it is possible for two routes to have same IP in strange firewall
          // configruations thus we might pick the wrong session)
          if (next->handlePacket(viaCandidate, source, buffer, bufferLengthInBytes)) return;

          // we chose wrong, so allow the "hunt" method to take over
          next.reset();
        }

        // this could be channel data for one of the sessions, check each session
        while (true)
        {
          // scope: find the next socket session to test in the list while in a lock
          {
            AutoRecursiveLock lock(*this);
            if (mSessions.size() < 1) break;  // no sessions to check

            if (!next) {
              next = (*(mSessions.begin())).second;
            } else {
              ICESocketSessionMap::iterator iter = mSessions.find(next->getID());
              if (iter == mSessions.end()) {
                next = (*(mSessions.begin())).second;   // start the search over since the previous entry we last searched was not in the map
              } else {
                ++iter;
                if (iter == mSessions.end()) break;
                next = (*iter).second;
              }
            }
          }

          if (!next) break;
          if (next->handlePacket(viaCandidate, source, buffer, bufferLengthInBytes)) return;
        }

        OPENPEER_SERVICES_WIRE_LOG_WARNING(Debug, log("did not find any socket session to handle data packet"))
      }

      //-----------------------------------------------------------------------
      void ICESocket::getBuffer(RecycledPacketBuffer &outBuffer)
      {
        AutoRecursiveLock lock(*this);
        if (mRecycledBuffers.size() < 1) {
          outBuffer = RecycledPacketBuffer(new BYTE[OPENPEER_SERVICES_ICESOCKET_RECYCLE_BUFFER_SIZE]);
          return;
        }

        outBuffer = mRecycledBuffers.front();
        mRecycledBuffers.pop_front();
      }

      //-----------------------------------------------------------------------
      void ICESocket::recycleBuffer(RecycledPacketBuffer &buffer)
      {
        AutoRecursiveLock lock(*this);
        if (!buffer) return;

        if (mRecycledBuffers.size() >= OPENPEER_SERVICES_ICESOCKET_MAX_RECYLCE_BUFFERS) {
          buffer.reset();
          return;
        }
        mRecycledBuffers.push_back(buffer);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ICESocket::TURNInfo
      #pragma mark

      //-----------------------------------------------------------------------
      ICESocket::TURNInfo::TURNInfo(
                                    WORD componentID,
                                    ULONG nextLocalPreference
                                    ) :
        mTURNRetryDuration(Milliseconds(OPENPEER_SERVICES_TURN_DEFAULT_RETRY_AFTER_DURATION_IN_MILLISECONDS))
      {
        mRelay = CandidatePtr(new Candidate);
        mRelay->mLocalPreference = nextLocalPreference;
        mRelay->mType = ICESocket::Type_Relayed;
        mRelay->mComponentID = componentID;
        mRelay->mPriority = ((1 << 24)*(static_cast<DWORD>(mRelay->mType))) + ((1 << 8)*(static_cast<DWORD>(mRelay->mLocalPreference))) + (256 - mRelay->mComponentID);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ICESocket::STUNInfo
      #pragma mark

      //-----------------------------------------------------------------------
      ICESocket::STUNInfo::STUNInfo(
                                    WORD componentID,
                                    ULONG nextLocalPreference
                                    )
      {
        mReflexive = CandidatePtr(new Candidate);
        mReflexive->mLocalPreference = nextLocalPreference;
        mReflexive->mType = ICESocket::Type_ServerReflexive;
        mReflexive->mComponentID = componentID;
        mReflexive->mPriority = ((1 << 24)*(static_cast<DWORD>(mReflexive->mType))) + ((1 << 8)*(static_cast<DWORD>(mReflexive->mLocalPreference))) + (256 - mReflexive->mComponentID);
      }

      //-----------------------------------------------------------------------
      void ICESocket::LocalSocket::clearSTUN(ISTUNDiscoveryPtr stunDiscovery)
      {
        STUNInfoDiscoveryMap::iterator found = mSTUNDiscoveries.find(stunDiscovery);
        if (found == mSTUNDiscoveries.end()) return;

        STUNInfoPtr stunInfo = (*found).second;

        STUNInfoMap::iterator foundInfo = mSTUNInfos.find(stunInfo);
        if (foundInfo != mSTUNInfos.end()) {
          mSTUNInfos.erase(foundInfo);
        }

        mSTUNDiscoveries.erase(found);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ICESocket::LocalSocket
      #pragma mark

      //-----------------------------------------------------------------------
      ICESocket::LocalSocket::LocalSocket(
                                          WORD componentID,
                                          ULONG localPreference
                                          )
      {
        mLocal = CandidatePtr(new Candidate);
        mLocal->mType = ICESocket::Type_Local;
        mLocal->mComponentID = componentID;
        updateLocalPreference(localPreference);
      }

      //-----------------------------------------------------------------------
      void ICESocket::LocalSocket::updateLocalPreference(ULONG localPreference)
      {
        mLocal->mLocalPreference = localPreference;
        mLocal->mPriority = ((1 << 24)*(static_cast<DWORD>(mLocal->mType))) + ((1 << 8)*(static_cast<DWORD>(mLocal->mLocalPreference))) + (256 - mLocal->mComponentID);
      }

      //-----------------------------------------------------------------------
      void ICESocket::LocalSocket::clearTURN(ITURNSocketPtr turnSocket)
      {
        TURNInfoSocketMap::iterator found = mTURNSockets.find(turnSocket);
        if (found == mTURNSockets.end()) return;

        TURNInfoPtr turnInfo = (*found).second;

        TURNInfoRelatedIPMap::iterator foundRelay = mTURNRelayIPs.find(turnInfo->mRelay->mIPAddress);
        if (foundRelay != mTURNRelayIPs.end()) {
          mTURNRelayIPs.erase(foundRelay);
        }

        TURNInfoRelatedIPMap::iterator foundServer = mTURNServerIPs.find(turnInfo->mServerIP);
        if (foundServer != mTURNServerIPs.end()) {
          mTURNServerIPs.erase(foundServer);
        }

        mTURNSockets.erase(found);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IICESocketFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IICESocketFactory &IICESocketFactory::singleton()
      {
        return ICESocketFactory::singleton();
      }

      //-----------------------------------------------------------------------
      ICESocketPtr IICESocketFactory::create(
                                             IMessageQueuePtr queue,
                                             IICESocketDelegatePtr delegate,
                                             const IICESocket::TURNServerInfoList &turnServers,
                                             const IICESocket::STUNServerInfoList &stunServers,
                                             WORD port,
                                             bool firstWORDInAnyPacketWillNotConflictWithTURNChannels,
                                             IICESocketPtr foundationSocket
                                             )
      {
        if (this) {}
        return internal::ICESocket::create(queue, delegate, turnServers, stunServers, port, firstWORDInAnyPacketWillNotConflictWithTURNChannels, foundationSocket);
      }

    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IICESocket
    #pragma mark

    //-------------------------------------------------------------------------
    const char *IICESocket::toString(ICESocketStates states)
    {
      switch (states) {
        case ICESocketState_Pending:     return "Preparing";
        case ICESocketState_Ready:         return "Ready";
        case ICESocketState_GoingToSleep:  return "Going to sleep";
        case ICESocketState_Sleeping:      return "Sleeping";
        case ICESocketState_ShuttingDown:  return "Shutting down";
        case ICESocketState_Shutdown:      return "Shutdown";
      }
      return "UNDEFINED";
    }

    //-------------------------------------------------------------------------
    const char *IICESocket::toString(Types type)
    {
      switch (type) {
        case Type_Unknown:          return "unknown";
        case Type_Local:            return "local";
        case Type_ServerReflexive:  return "server reflexive";
        case Type_PeerReflexive:    return "peer reflexive";
        case Type_Relayed:          return "relayed";
      }
      return NULL;
    }

    //-------------------------------------------------------------------------
    void IICESocket::compare(
                             const CandidateList &inOldCandidatesList,
                             const CandidateList &inNewCandidatesList,
                             CandidateList &outAddedCandidates,
                             CandidateList &outRemovedCandidates
                             )
    {
      outAddedCandidates.clear();
      outRemovedCandidates.clear();

      // check new list to see which candidates are not part of the old list
      for (CandidateList::const_iterator outerIter = inNewCandidatesList.begin(); outerIter != inNewCandidatesList.end(); ++outerIter)
      {
        const Candidate &newCandidate = (*outerIter);

        bool found = false;

        for (CandidateList::const_iterator innerIter = inOldCandidatesList.begin(); innerIter != inOldCandidatesList.end(); ++innerIter)
        {
          const Candidate &oldCandidate = (*innerIter);

          if (!internal::isEqual(newCandidate, oldCandidate)) continue;

          found = true;
          break;
        }

        if (!found) {
          outAddedCandidates.push_back(newCandidate);
        }
      }

      // check old list to see which candidates are not part of the new list
      for (CandidateList::const_iterator outerIter = inOldCandidatesList.begin(); outerIter != inOldCandidatesList.end(); ++outerIter)
      {
        const Candidate &oldCandidate = (*outerIter);

        bool found = false;

        for (CandidateList::const_iterator innerIter = inNewCandidatesList.begin(); innerIter != inNewCandidatesList.end(); ++innerIter)
        {
          const Candidate &newCandidate = (*innerIter);

          if (!internal::isEqual(newCandidate, oldCandidate)) continue;

          found = true;
          break;
        }

        if (!found) {
          outRemovedCandidates.push_back(oldCandidate);
        }
      }
    }

    //-------------------------------------------------------------------------
    const char *IICESocket::toString(ICEControls control)
    {
      switch (control) {
        case ICEControl_Controlling:      return "Controlling";
        case ICEControl_Controlled:       return "Controlled";
      }
      return "UNDEFINED";
    }

    //-------------------------------------------------------------------------
    ElementPtr IICESocket::toDebug(IICESocketPtr socket)
    {
      return internal::ICESocket::toDebug(socket);
    }

    //-------------------------------------------------------------------------
    IICESocketPtr IICESocket::create(
                                     IMessageQueuePtr queue,
                                     IICESocketDelegatePtr delegate,
                                     const TURNServerInfoList &turnServers,
                                     const STUNServerInfoList &stunServers,
                                     WORD port,
                                     bool firstWORDInAnyPacketWillNotConflictWithTURNChannels,
                                     IICESocketPtr foundationSocket
                                     )
    {
      return internal::IICESocketFactory::singleton().create(
                                                             queue,
                                                             delegate,
                                                             turnServers,
                                                             stunServers,
                                                             port,
                                                             firstWORDInAnyPacketWillNotConflictWithTURNChannels,
                                                             foundationSocket);
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IICESocket::Candidate
    #pragma mark

    //-------------------------------------------------------------------------
    IICESocket::CandidatePtr IICESocket::Candidate::create()
    {
      CandidatePtr pThis(new Candidate);
      return pThis;
    }

    //-------------------------------------------------------------------------
    bool IICESocket::Candidate::hasData() const
    {
      return ((IICESocket::Type_Unknown != mType) ||
              (mFoundation.hasData()) ||
              (!mIPAddress.isEmpty()) ||
              (0 != mPriority) ||
              (0 != mLocalPreference) ||
              (!mRelatedIP.isEmpty()));
    }

    //-------------------------------------------------------------------------
    ElementPtr IICESocket::Candidate::toDebug() const
    {
      ElementPtr resultEl = Element::create("IICESocket::Candidate");

      IHelper::debugAppend(resultEl, "type", IICESocket::toString(mType));
      IHelper::debugAppend(resultEl, "foundation", mFoundation);
      IHelper::debugAppend(resultEl, "component", mComponentID);
      IHelper::debugAppend(resultEl, "ip", mIPAddress.isEmpty() ? String() : mIPAddress.string());
      IHelper::debugAppend(resultEl, "priority", mPriority);
      IHelper::debugAppend(resultEl, "preference", mLocalPreference);
      IHelper::debugAppend(resultEl, "related", mRelatedIP.isEmpty() ? String() : mRelatedIP.string());

      return resultEl;
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IICESocket::TURNServerInfo
    #pragma mark

    //-------------------------------------------------------------------------
    IICESocket::TURNServerInfoPtr IICESocket::TURNServerInfo::create()
    {
      return TURNServerInfoPtr(new TURNServerInfo);
    }

    //-------------------------------------------------------------------------
    bool IICESocket::TURNServerInfo::hasData() const
    {
      return (mTURNServer.hasData()) ||
             (mTURNServerUsername.hasData()) ||
             (mTURNServerPassword.hasData()) ||
             (mSRVTURNServerUDP) ||
             (mSRVTURNServerTCP);
    }

    //-------------------------------------------------------------------------
    ElementPtr IICESocket::TURNServerInfo::toDebug() const
    {
      ElementPtr resultEl = Element::create("IICESocket::TURNServerInfo");

      IHelper::debugAppend(resultEl, "server", mTURNServer);
      IHelper::debugAppend(resultEl, "username", mTURNServerUsername);
      IHelper::debugAppend(resultEl, "password", mTURNServerPassword);
      IHelper::debugAppend(resultEl, "UDP SRV", (bool)mSRVTURNServerUDP);
      IHelper::debugAppend(resultEl, "TCP SRV", (bool)mSRVTURNServerTCP);

      return resultEl;
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IICESocket::STUNServerInfo
    #pragma mark

    //-------------------------------------------------------------------------
    IICESocket::STUNServerInfoPtr IICESocket::STUNServerInfo::create()
    {
      return STUNServerInfoPtr(new STUNServerInfo);
    }

    //-------------------------------------------------------------------------
    bool IICESocket::STUNServerInfo::hasData() const
    {
      return (mSTUNServer.hasData()) ||
             (mSRVSTUNServerUDP);
    }

    //-------------------------------------------------------------------------
    ElementPtr IICESocket::STUNServerInfo::toDebug() const
    {
      ElementPtr resultEl = Element::create("IICESocket::STUNServerInfo");

      IHelper::debugAppend(resultEl, "server", mSTUNServer);
      IHelper::debugAppend(resultEl, "UDP SRV", (bool)mSRVSTUNServerUDP);

      return resultEl;
    }

  }
}
