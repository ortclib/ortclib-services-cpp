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

#include <ortc/services/internal/types.h>
#include <ortc/services/internal/services_Helper.h>

#include <ortc/services/IICESocket.h>
#include <ortc/services/IDNS.h>
#include <ortc/services/ITURNSocket.h>
#include <ortc/services/ISTUNDiscovery.h>

#include <zsLib/types.h>
#include <zsLib/IPAddress.h>
#include <zsLib/MessageQueueAssociator.h>
#include <zsLib/Socket.h>
#include <zsLib/XML.h>
#include <zsLib/ITimer.h>
#include <zsLib/IWakeDelegate.h>
#include <zsLib/Log.h>

#include <list>
#include <tuple>

#define ORTC_SERVICES_SETTING_ICE_SOCKET_TURN_CANDIDATES_MUST_REMAIN_ALIVE_AFTER_ICE_WAKE_UP_IN_SECONDS  "ortc/services/turn-candidates-must-remain-alive-after-ice-wake-up-in-seconds"

#define ORTC_SERVICES_SETTING_ICE_SOCKET_FORCE_USE_TURN                     "ortc/services/debug/force-packets-over-turn"
#define ORTC_SERVICES_SETTING_ICE_SOCKET_ONLY_ALLOW_DATA_SENT_TO_SPECIFIC_IPS          "ortc/services/debug/only-allow-data-sent-to-specific-ips"

#define ORTC_SERVICES_SETTING_ICE_SOCKET_INTERFACE_NAME_ORDER                          "ortc/services/interface-name-order"
#define ORTC_SERVICES_SETTING_ICE_SOCKET_INTERFACE_SUPPORT_IPV6             "ortc/services/support-ipv6"

#define ORTC_SERVICES_SETTING_ICE_SOCKET_MAX_REBIND_ATTEMPT_DURATION_IN_SECONDS        "ortc/services/max-ice-socket-rebind-attempt-duration-in-seconds"
#define ORTC_SERVICES_SETTING_ICE_SOCKET_NO_LOCAL_IPS_CAUSES_SOCKET_FAILURE "ortc/services/ice-socket-fail-when-no-local-ips"

namespace ortc
{
  namespace services
  {
    namespace internal
    {
      interaction IICESocketSessionForICESocket;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IICESocketForICESocketSession
      #pragma mark

      interaction IICESocketForICESocketSession
      {
        ZS_DECLARE_TYPEDEF_PTR(IICESocketForICESocketSession, ForICESocketSession)

        virtual IMessageQueuePtr getMessageQueue() const = 0;

        virtual bool attach(ICESocketSessionPtr session) = 0;

        virtual bool sendTo(
                            const IICESocket::Candidate &viaLocalCandidate,
                            const IPAddress &destination,
                            const BYTE *buffer,
                            size_t bufferLengthInBytes,
                            bool isUserData
                            ) = 0;

        virtual void addRoute(
                              ICESocketSessionPtr session,
                              const IPAddress &viaIP,
                              const IPAddress &viaLocalIP,
                              const IPAddress &source
                              ) = 0;
        virtual void removeRoute(ICESocketSessionPtr session) = 0;

        virtual void onICESocketSessionClosed(PUID sessionID) = 0;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ICESocket
      #pragma mark

      class ICESocket : public Noop,
                        public MessageQueueAssociator,
                        public SharedRecursiveLock,
                        public IICESocket,
                        public ISocketDelegate,
                        public ITURNSocketDelegate,
                        public ISTUNDiscoveryDelegate,
                        public IICESocketForICESocketSession,
                        public IWakeDelegate,
                        public ITimerDelegate,
                        public IDNSDelegate
      {
      protected:
        struct make_private {};

      public:
        friend interaction IICESocketFactory;
        friend interaction IICESocket;

        ZS_DECLARE_TYPEDEF_PTR(IICESocketSessionForICESocket, UseICESocketSession)

        ZS_DECLARE_STRUCT_PTR(TURNInfo)
        ZS_DECLARE_STRUCT_PTR(STUNInfo)
        ZS_DECLARE_STRUCT_PTR(LocalSocket)

        ZS_DECLARE_CLASS_PTR(Sorter)

        typedef std::list<IPAddress> IPAddressList;

        typedef std::map<PUID, UseICESocketSessionPtr> ICESocketSessionMap;

        typedef IPAddress ViaIP;
        typedef IPAddress ViaLocalIP;
        typedef IPAddress SourceIP;
        typedef std::tuple<ViaIP, ViaLocalIP, SourceIP> RouteTuple;

        struct RouteLess : public std::binary_function<RouteTuple, RouteTuple, bool>
        {
          bool operator() (const RouteTuple& __x, const RouteTuple& __y) const
          {
            if (std::get<2>(__x) < std::get<2>(__y)) return true;   // compare source IP first
            if (std::get<2>(__x) > std::get<2>(__y)) return false;
            if (std::get<0>(__x) < std::get<0>(__y)) return true;   // compare ViaIP next
            if (std::get<0>(__x) > std::get<0>(__y)) return false;
            if (std::get<1>(__x) < std::get<1>(__y)) return true;   // compare ViaLocalIP next
            if (std::get<1>(__x) > std::get<1>(__y)) return false;

            return false; // they are equal, so not less than
          }
        };

        typedef std::map<RouteTuple, UseICESocketSessionPtr, RouteLess> QuickRouteMap;

        typedef IHelper::IPAddressSet IPAddressSet;

        struct TURNInfo
        {
          TURNServerInfoPtr mServerInfo;

          ITURNSocketPtr    mTURNSocket;
          IPAddress         mServerIP;

          Time              mTURNRetryAfter;
          Milliseconds      mTURNRetryDuration;
          ITimerPtr          mTURNRetryTimer;

          CandidatePtr      mRelay;

          TURNInfo(
                   WORD componentID,
                   ULONG nextLocalPreference
                   );
        };

        struct STUNInfo
        {
          STUNServerInfoPtr mServerInfo;

          ISTUNDiscoveryPtr mSTUNDiscovery;

          CandidatePtr      mReflexive;

          STUNInfo(
                   WORD componentID,
                   ULONG nextLocalPreference
                   );
        };

        typedef std::map<TURNInfoPtr, TURNInfoPtr> TURNInfoMap;
        typedef std::map<ITURNSocketPtr, TURNInfoPtr> TURNInfoSocketMap;
        typedef std::map<IPAddress, TURNInfoPtr> TURNInfoRelatedIPMap;
        typedef std::map<STUNInfoPtr, STUNInfoPtr> STUNInfoMap;
        typedef std::map<ISTUNDiscoveryPtr, STUNInfoPtr> STUNInfoDiscoveryMap;

        struct LocalSocket
        {
          AutoPUID              mID;
          SocketPtr             mSocket;

          CandidatePtr          mLocal;

          TURNInfoMap           mTURNInfos;
          TURNInfoSocketMap     mTURNSockets;
          TURNInfoRelatedIPMap  mTURNRelayIPs;
          TURNInfoRelatedIPMap  mTURNServerIPs;

          STUNInfoMap           mSTUNInfos;
          STUNInfoDiscoveryMap  mSTUNDiscoveries;

          LocalSocket(
                      WORD componentID,
                      ULONG localPreference
                      );

          void updateLocalPreference(ULONG localPreference);

          void clearTURN(ITURNSocketPtr turnSocket);
          void clearSTUN(ISTUNDiscoveryPtr stunDiscovery);
        };

        typedef String InterfaceName;
        typedef ULONG OrderID;
        typedef IPAddress LocalIP;
        typedef std::map<LocalIP, LocalSocketPtr> LocalSocketIPAddressMap;
        typedef std::map<ITURNSocketPtr, LocalSocketPtr> LocalSocketTURNSocketMap;
        typedef std::map<ISTUNDiscoveryPtr, LocalSocketPtr> LocalSocketSTUNDiscoveryMap;
        typedef std::map<SocketPtr, LocalSocketPtr> LocalSocketMap;
        typedef std::map<InterfaceName, OrderID> InterfaceNameToOrderMap;

      public:
        ICESocket(
                  const make_private &,
                  IMessageQueuePtr queue,
                  IICESocketDelegatePtr delegate,
                  const TURNServerInfoList &turnServers,
                  const STUNServerInfoList &stunServers,
                  bool firstWORDInAnyPacketWillNotConflictWithTURNChannels,
                  WORD port,
                  IICESocketPtr foundationSocket
                  );

      protected:
        ICESocket(Noop) :
          Noop(true),
          MessageQueueAssociator(IMessageQueuePtr()),
          SharedRecursiveLock(SharedRecursiveLock::create())
        {}

        void init();

      public:
        ~ICESocket();

        static ICESocketPtr convert(IICESocketPtr socket);
        static ICESocketPtr convert(ForICESocketSessionPtr socket);

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocket => IICESocket
        #pragma mark

        static ElementPtr toDebug(IICESocketPtr socket);

        static ICESocketPtr create(
                                   IMessageQueuePtr queue,
                                   IICESocketDelegatePtr delegate,
                                   const TURNServerInfoList &turnServers,
                                   const STUNServerInfoList &stunServers,
                                   WORD port = 0,
                                   bool firstWORDInAnyPacketWillNotConflictWithTURNChannels = false,
                                   IICESocketPtr foundationSocket = IICESocketPtr()
                                   );

        virtual PUID getID() const {return mID;}

        virtual IICESocketSubscriptionPtr subscribe(IICESocketDelegatePtr delegate);

        virtual ICESocketStates getState(
                                         WORD *outLastErrorCode = NULL,
                                         String *outLastErrorReason = NULL
                                         ) const;

        virtual String getUsernameFrag() const;

        virtual String getPassword() const;

        virtual void shutdown();

        virtual void wakeup(Milliseconds minimumTimeCandidatesMustRemainValidWhileNotUsed = Seconds(60*10));

        virtual void getLocalCandidates(
                                        CandidateList &outCandidates,
                                        String *outLocalCandidateVersion = NULL
                                        );

        virtual String getLocalCandidatesVersion() const;

        virtual void monitorWriteReadyOnAllSessions(bool monitor = true);

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocket => IICESocketForICESocketSession
        #pragma mark

        virtual IMessageQueuePtr getMessageQueue() const {return getAssociatedMessageQueue();}

        virtual bool attach(ICESocketSessionPtr session);

        virtual bool sendTo(
                            const Candidate &viaLocalCandidate,
                            const IPAddress &destination,
                            const BYTE *buffer,
                            size_t bufferLengthInBytes,
                            bool isUserData
                            );

        virtual void addRoute(
                              ICESocketSessionPtr session,
                              const IPAddress &viaIP,
                              const IPAddress &viaLocalIP,
                              const IPAddress &source
                              );
        virtual void removeRoute(ICESocketSessionPtr session);

        virtual void onICESocketSessionClosed(PUID sessionID);
        
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocket => ISocketDelegate
        #pragma mark

        virtual void onReadReady(SocketPtr socket);
        virtual void onWriteReady(SocketPtr socket);
        virtual void onException(SocketPtr socket);

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocket => ITURNSocketDelegate
        #pragma mark

        virtual void onTURNSocketStateChanged(
                                              ITURNSocketPtr socket,
                                              TURNSocketStates state
                                              );

        virtual void handleTURNSocketReceivedPacket(
                                                    ITURNSocketPtr socket,
                                                    IPAddress source,
                                                    const BYTE *packet,
                                                    size_t packetLengthInBytes
                                                    );

        virtual bool notifyTURNSocketSendPacket(
                                                ITURNSocketPtr socket,
                                                IPAddress destination,
                                                const BYTE *packet,
                                                size_t packetLengthInBytes
                                                );

        virtual void onTURNSocketWriteReady(ITURNSocketPtr socket);

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocket => ISTUNDiscoveryDelegate
        #pragma mark

        virtual void onSTUNDiscoverySendPacket(
                                               ISTUNDiscoveryPtr discovery,
                                               IPAddress destination,
                                               SecureByteBlockPtr packet
                                               );

        virtual void onSTUNDiscoveryCompleted(ISTUNDiscoveryPtr discovery);

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocket => IWakeDelegate
        #pragma mark

        virtual void onWake();

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocket => ITimerDelegate
        #pragma mark

        virtual void onTimer(ITimerPtr timer);

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocket => IDNSDelegate
        #pragma mark

        virtual void onLookupCompleted(IDNSQueryPtr query);

      public:
        //---------------------------------------------------------------------
        //---------------------------------------------------------------------
        //---------------------------------------------------------------------
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocket::Sorter
        #pragma mark

        class Sorter
        {
        public:
          //-------------------------------------------------------------------
          struct Data {
            String mHostName;
            IPAddress mIP;
            OrderID mOrderIndex {};
            ULONG mAdapterMetric {};
            ULONG mIndex {};
          };

          struct QueryData
          {
            IDNSQueryPtr mQuery;
            Data mData;
          };

          typedef std::list<Data> DataList;

          typedef PUID QueryID;
          typedef std::map<QueryID, QueryData> QueryMap;

          static bool compareLocalIPs(const Data &data1, const Data &data2);

          static Data prepare(const IPAddress &ip);
          static Data prepare(
                              const char *hostName,
                              const IPAddress &ip
                              );
          static Data prepare(
                              const char *hostName,
                              const IPAddress &ip,
                              const char *name,
                              const InterfaceNameToOrderMap &prefs
                              );
          static Data prepare(
                              const IPAddress &ip,
                              const char *name,
                              const InterfaceNameToOrderMap &prefs
                              );
          static Data prepare(
                              const IPAddress &ip,
                              const char *name,
                              ULONG metric,
                              const InterfaceNameToOrderMap &prefs
                              );
          static Data prepare(
                              const char *hostName,
                              const IPAddress &ip,
                              const char *name,
                              ULONG metric,
                              const InterfaceNameToOrderMap &prefs
                              );

          static void sort(
                           DataList &ioDataList,
                           IPAddressList &outIPs
                           );
        };

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocket => (internal)
        #pragma mark

        Log::Params log(const char *message) const;
        Log::Params debug(const char *message) const;

        bool isShuttingDown() const {return ICESocketState_ShuttingDown == mCurrentState;}
        bool isShutdown() const {return ICESocketState_Shutdown == mCurrentState;}

        virtual ElementPtr toDebug() const;

        void cancel();
        
        void step();
        bool stepResolveLocalIPs();
        bool stepBind();
        bool stepSTUN();
        bool stepTURN();
        bool stepCandidates();

        void setState(ICESocketStates state);
        void setError(WORD errorCode, const char *inReason = NULL);

        bool getLocalIPs(IPAddressList &outIPs);  // returns false if IPs must be resolved later

        void stopSTUNAndTURN(LocalSocketPtr localSocket);
        bool closeIfTURNGone(LocalSocketPtr localSocket);
        void hardClose(LocalSocketPtr localSocket);
        void clearRelated(LocalSocketPtr localSocket);

        void clearTURN(ITURNSocketPtr turn);
        void clearSTUN(ISTUNDiscoveryPtr stun);

        //---------------------------------------------------------------------
        // NOTE:  Do NOT call this method while in a lock because it must
        //        deliver data to delegates synchronously.
        void internalReceivedData(
                                  const Candidate &viaCandidate,
                                  const Candidate &viaLocalCandidate,
                                  const IPAddress &source,
                                  const BYTE *buffer,
                                  size_t bufferLengthInBytes
                                  );

        void clearRebindTimer() { if (mRebindTimer) {mRebindTimer->cancel(); mRebindTimer.reset();} }

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocket (internal)
        #pragma mark

        AutoPUID              mID;
        ICESocketWeakPtr      mThisWeak;
        ICESocketPtr          mGracefulShutdownReference;

        IICESocketDelegateSubscriptions mSubscriptions;
        IICESocketSubscriptionPtr mDefaultSubscription;

        ICESocketStates     mCurrentState;
        WORD                mLastError {};
        String              mLastErrorReason;

        ICESocketPtr        mFoundation;
        WORD                mComponentID {};

        WORD                mBindPort;
        String              mUsernameFrag;
        String              mPassword;

        LocalSocketIPAddressMap     mSocketLocalIPs;
        LocalSocketTURNSocketMap    mSocketTURNs;
        LocalSocketSTUNDiscoveryMap mSocketSTUNs;
        LocalSocketMap              mSockets;

        ITimerPtr           mRebindTimer;
        Time                mRebindAttemptStartTime;
        bool                mRebindCheckNow {};

        bool                mMonitoringWriteReady;

        TURNServerInfoList  mTURNServers;
        STUNServerInfoList  mSTUNServers;
        bool                mFirstWORDInAnyPacketWillNotConflictWithTURNChannels;
        Time                mTURNLastUsed;                    // when was the TURN server last used to transport any data
        Milliseconds        mTURNShutdownIfNotUsedBy;         // when will TURN be shutdown if it is not used by this time

        ICESocketSessionMap mSessions;

        QuickRouteMap       mRoutes;

        bool                mNotifiedCandidateChanged {};
        DWORD               mLastCandidateCRC;

        bool                mForceUseTURN;
        IPAddressSet        mRestrictedIPs;

        InterfaceNameToOrderMap mInterfaceOrders;

        bool                mSupportIPv6;

        Milliseconds        mMaxRebindAttemptDuration;

        bool                mResolveFailed {};
        Sorter::DataList    mResolveLocalIPs;
        Sorter::QueryMap    mResolveLocalIPQueries;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IICESocketFactory
      #pragma mark

      interaction IICESocketFactory
      {
        static IICESocketFactory &singleton();

        virtual ICESocketPtr create(
                                    IMessageQueuePtr queue,
                                    IICESocketDelegatePtr delegate,
                                    const IICESocket::TURNServerInfoList &turnServers,
                                    const IICESocket::STUNServerInfoList &stunServers,
                                    WORD port = 0,
                                    bool firstWORDInAnyPacketWillNotConflictWithTURNChannels = false,
                                    IICESocketPtr foundationSocket = IICESocketPtr()
                                    );
      };

      class ICESocketFactory : public IFactory<IICESocketFactory> {};
    }
  }
}

ZS_DECLARE_PROXY_BEGIN(ortc::services::internal::IICESocketForICESocketSession)
ZS_DECLARE_PROXY_TYPEDEF(zsLib::IMessageQueuePtr, IMessageQueuePtr)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::internal::ICESocketSessionPtr, ICESocketSessionPtr)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::IICESocketPtr, IICESocketPtr)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::IICESocket, IICESocket)
ZS_DECLARE_PROXY_METHOD_SYNC_CONST_RETURN_0(getMessageQueue, IMessageQueuePtr)
ZS_DECLARE_PROXY_METHOD_SYNC_RETURN_1(attach, bool, ICESocketSessionPtr)
ZS_DECLARE_PROXY_METHOD_SYNC_RETURN_5(sendTo, bool, const IICESocket::Candidate &, const IPAddress &, const BYTE *, size_t, bool)
ZS_DECLARE_PROXY_METHOD_1(onICESocketSessionClosed, PUID)
ZS_DECLARE_PROXY_METHOD_SYNC_4(addRoute, ortc::services::internal::ICESocketSessionPtr, const IPAddress &, const IPAddress &, const IPAddress &)
ZS_DECLARE_PROXY_METHOD_SYNC_1(removeRoute, ortc::services::internal::ICESocketSessionPtr)
ZS_DECLARE_PROXY_END()
