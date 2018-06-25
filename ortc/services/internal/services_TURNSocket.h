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

#include <ortc/services/IBackgrounding.h>
#include <ortc/services/ITURNSocket.h>
#include <ortc/services/ISTUNRequester.h>
#include <ortc/services/IDNS.h>

#include <zsLib/MessageQueueAssociator.h>
#include <zsLib/Socket.h>
#include <zsLib/ITimer.h>
#include <zsLib/IWakeDelegate.h>

#define ORTC_SERVICES_TURN_MAX_CHANNEL_DATA_IN_BYTES ((1 << (sizeof(WORD)*8)) - 1)

#include <list>
#include <map>
#include <utility>

#define ORTC_SERVICES_SETTING_TURN_SOCKET_BACKGROUNDING_PHASE "ortc/services/backgrounding-phase-turn"

#define ORTC_SERVICES_SETTING_TURN_SOCKET_FORCE_TURN_TO_USE_UDP "ortc/services/debug/force-turn-to-use-udp"
#define ORTC_SERVICES_SETTING_TURN_SOCKET_FORCE_TURN_TO_USE_TCP "ortc/services/debug/force-turn-to-use-tcp"
#define ORTC_SERVICES_SETTING_TURN_SOCKET_ONLY_ALLOW_TURN_TO_RELAY_DATA_TO_SPECIFIC_IPS "ortc/services/debug/only-allow-turn-to-relay-data-sent-to-specific-ips"

namespace ortc
{
  namespace services
  {
    namespace internal
    {
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // TURNSocket
      //

      class TURNSocket : public Noop,
                         public MessageQueueAssociator,
                         public ITURNSocket,
                         public IWakeDelegate,
                         public ISTUNRequesterDelegate,
                         public IDNSDelegate,
                         public ISocketDelegate,
                         public ITimerDelegate,
                         public IBackgroundingDelegate
      {
      protected:
        struct make_private {};

      public:
        friend interaction ITURNSocket;
        friend interaction ITURNSocketFactory;

        typedef std::list<IPAddress> IPAddressList;
        typedef IDNS::SRVResultPtr SRVResultPtr;

        ZS_DECLARE_STRUCT_PTR(Server)
        ZS_DECLARE_STRUCT_PTR(Permission)
        ZS_DECLARE_STRUCT_PTR(ChannelInfo)

        typedef std::list<ServerPtr> ServerList;

        class CompareIP;

        typedef std::map<IPAddress, PermissionPtr, CompareIP> PermissionMap;

        typedef std::map<IPAddress, ChannelInfoPtr, CompareIP> ChannelIPMap;
        typedef std::map<WORD, ChannelInfoPtr> ChannelNumberMap;

        typedef IHelper::IPAddressSet IPAddressSet;

        typedef PUID TimerID;
        typedef std::map<TimerID, ITimerPtr> TimerMap;

      public:
        TURNSocket(
                   const make_private &,
                   IMessageQueuePtr queue,
                   ITURNSocketDelegatePtr delegate,
                   const CreationOptions &options
                   ) noexcept;

      protected:
        TURNSocket(Noop) noexcept : Noop(true), MessageQueueAssociator(IMessageQueuePtr()) {};

        void init() noexcept;

      public:
        ~TURNSocket() noexcept;

        static TURNSocketPtr convert(ITURNSocketPtr socket) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // TURNSocket => ITURNSocket
        //

        static TURNSocketPtr create(
                                    IMessageQueuePtr queue,
                                    ITURNSocketDelegatePtr delegate,
                                    const CreationOptions &options
                                    ) noexcept;

        static ElementPtr toDebug(ITURNSocketPtr socket) noexcept;

        PUID getID() const noexcept override {return mID;}

        TURNSocketStates getState() const noexcept override;
        TURNSocketErrors getLastError() const noexcept override;

        bool isRelayingUDP() const noexcept override;

        void shutdown() noexcept override;

        bool sendPacket(
                        IPAddress destination,
                        const BYTE *buffer,
                        size_t bufferLengthInBytes,
                        bool bindChannelIfPossible = false
                        ) noexcept override;

        IPAddress getActiveServerIP() const noexcept override;
        IPAddress getRelayedIP() const noexcept override;
        IPAddress getReflectedIP() const noexcept override;
        IPAddress getServerResponseIP() const noexcept override;

        bool handleSTUNPacket(
                              IPAddress fromIPAddress,
                              STUNPacketPtr turnPacket
                              ) noexcept override;

        bool handleChannelData(
                               IPAddress fromIPAddress,
                               const BYTE *buffer,
                               size_t bufferLengthInBytes
                               ) noexcept override;

        void notifyWriteReady() noexcept override;

        //---------------------------------------------------------------------
        //
        // TURNSocket => IWakeDelegate
        //

        void onWake() override;

        //---------------------------------------------------------------------
        //
        // TURNSocket => ISTUNRequesterDelegate
        //

        void onSTUNRequesterSendPacket(
                                       ISTUNRequesterPtr requester,
                                       IPAddress destination,
                                       SecureByteBlockPtr packet
                                       ) override;

        bool handleSTUNRequesterResponse(
                                         ISTUNRequesterPtr requester,
                                         IPAddress fromIPAddress,
                                         STUNPacketPtr response
                                         ) noexcept override;

        void onSTUNRequesterTimedOut(ISTUNRequesterPtr requester) override;

        //---------------------------------------------------------------------
        //
        // TURNSocket => IDNSDelegate
        //

        void onLookupCompleted(IDNSQueryPtr query) override;

        //---------------------------------------------------------------------
        //
        // TURNSocket => ISocketDelegate
        //

        void onReadReady(SocketPtr socket) override;
        void onWriteReady(SocketPtr socket) override;
        void onException(SocketPtr socket) override;

        //---------------------------------------------------------------------
        //
        // TURNSocket => ITimer
        //

        void onTimer(ITimerPtr timer) override;

        //---------------------------------------------------------------------
        //
        // TURNSocket => IBackgroundingDelegate
        //

        void onBackgroundingGoingToBackground(
                                              IBackgroundingSubscriptionPtr subscription,
                                              IBackgroundingNotifierPtr notifier
                                              ) override;

        void onBackgroundingGoingToBackgroundNow(IBackgroundingSubscriptionPtr subscription) override;

        void onBackgroundingReturningFromBackground(IBackgroundingSubscriptionPtr subscription) override;

        void onBackgroundingApplicationWillQuit(IBackgroundingSubscriptionPtr subscription) override;

      protected:
        //---------------------------------------------------------------------
        //
        // TURNSocket => (internal)
        //

        bool isReady() const noexcept {return ITURNSocket::TURNSocketState_Ready ==  mCurrentState;}
        bool isShuttingDown() const noexcept {return ITURNSocket::TURNSocketState_ShuttingDown ==  mCurrentState;}
        bool isShutdown() const noexcept {return ITURNSocket::TURNSocketState_Shutdown ==  mCurrentState;}

        Log::Params log(const char *message) const noexcept;
        Log::Params debug(const char *message) const noexcept;
        virtual ElementPtr toDebug() const noexcept;

        void fix(STUNPacketPtr stun) const noexcept;

        void step() noexcept;
        bool stepDNSLookupNextServer() noexcept;
        IPAddress stepGetNextServer(
                                    IPAddressList &previouslyAdded,
                                    SRVResultPtr &srv
                                    ) noexcept;
        bool stepPrepareServers() noexcept;
        void cancel() noexcept;

        void setState(TURNSocketStates newState) noexcept;

        void consumeBuffer(
                           ServerPtr &server,
                           size_t bufferSizeInBytes
                           ) noexcept;

        bool handleAllocateRequester(
                                     ISTUNRequesterPtr requester,
                                     IPAddress fromIPAddress,
                                     STUNPacketPtr response
                                     ) noexcept;

        bool handleRefreshRequester(
                                    ISTUNRequesterPtr requester,
                                    STUNPacketPtr response
                                    ) noexcept;

        bool handleDeallocRequester(
                                    ISTUNRequesterPtr requester,
                                    STUNPacketPtr response
                                    ) noexcept;

        bool handlePermissionRequester(
                                       ISTUNRequesterPtr requester,
                                       STUNPacketPtr response
                                       ) noexcept;

        bool handleChannelRequester(
                                    ISTUNRequesterPtr requester,
                                    STUNPacketPtr response
                                    ) noexcept;

        void requestPermissionsNow() noexcept;

        void refreshNow() noexcept;

        void refreshChannels() noexcept;

        bool sendPacketOrDopPacketIfBufferFull(
                                               ServerPtr server,
                                               const BYTE *buffer,
                                               size_t bufferSizeInBytes
                                               ) noexcept;

        bool sendPacketOverTCPOrDropIfBufferFull(
                                                 ServerPtr server,
                                                 const BYTE *buffer,
                                                 size_t bufferSizeInBytes
                                                 ) noexcept;

        void informWriteReady() noexcept;

        WORD getNextChannelNumber() noexcept;

        ISTUNRequesterPtr handleAuthorizationErrors(ISTUNRequesterPtr requester, STUNPacketPtr response) noexcept;

        void clearBackgroundingNotifierIfPossible() noexcept;
        void clearRefreshRequester() noexcept {if (mRefreshRequester) { mRefreshRequester->cancel(); mRefreshRequester.reset(); } clearBackgroundingNotifierIfPossible();}
        void clearPermissionRequester() noexcept {if (mPermissionRequester) { mPermissionRequester->cancel(); mPermissionRequester.reset(); } clearBackgroundingNotifierIfPossible();}
        void clearDeallocateRequester() noexcept {if (mDeallocateRequester) { mDeallocateRequester->cancel(); mDeallocateRequester.reset(); } clearBackgroundingNotifierIfPossible();}

      public:
        //---------------------------------------------------------------------
        //
        // TURNSocket::Server
        //

        struct Server
        {
          bool mIsUDP {true};  // true for UDP, false for TCP
          IPAddress mServerIP;

          SocketPtr mTCPSocket;
          bool mIsConnected {};
          bool mInformedWriteReady {};

          ITimerPtr mActivationTimer;
          Time mActivateAfter {};

          ISTUNRequesterPtr mAllocateRequester;

          BYTE mReadBuffer[ORTC_SERVICES_TURN_MAX_CHANNEL_DATA_IN_BYTES+sizeof(DWORD)];
          size_t mReadBufferFilledSizeInBytes {};

          BYTE mWriteBuffer[ORTC_SERVICES_TURN_MAX_CHANNEL_DATA_IN_BYTES+sizeof(DWORD)];
          size_t mWriteBufferFilledSizeInBytes {};

          Server() noexcept;
          ~Server() noexcept;

          static ServerPtr create() noexcept;

          ElementPtr toDebug() const noexcept;
        };

        //---------------------------------------------------------------------
        //
        // TURNSocket::CompareIP
        //

        class CompareIP { // simple comparison function
        public:
          bool operator()(const IPAddress &op1, const IPAddress &op2) const noexcept;
        };

        //---------------------------------------------------------------------
        //
        // TURNSocket::Permission
        //

        struct Permission
        {
          static PermissionPtr create() noexcept;

          bool mInstalled;
          IPAddress mPeerAddress;
          Time mLastSentDataAt;
          ISTUNRequesterPtr mInstallingWithRequester;

          typedef std::list<SecureByteBlockPtr> PendingDataList;
          PendingDataList mPendingData;
        };

        //---------------------------------------------------------------------
        //
        // TURNSocket::ChannelInfo
        //

        struct ChannelInfo
        {
          static ChannelInfoPtr create() noexcept;

          bool mBound;
          WORD mChannelNumber;
          IPAddress mPeerAddress;
          Time mLastSentDataAt;
          ITimerPtr mRefreshTimer;
          ISTUNRequesterPtr mChannelBindRequester;
        };

      protected:
        //---------------------------------------------------------------------
        //
        // TURNSocket => (data)
        //

        mutable RecursiveLock mLock;
        TURNSocketWeakPtr mThisWeak;
        TURNSocketPtr mGracefulShutdownReference;
        AutoPUID mID;

        TURNSocketStates mCurrentState;
        TURNSocketErrors mLastError;

        IBackgroundingSubscriptionPtr mBackgroundingSubscription;
        IBackgroundingNotifierPtr mBackgroundingNotifier;

        ITURNSocketDelegatePtr mDelegate;

        CreationOptions mOptions;

        String mRealm;
        String mNonce;

        IDNSQueryPtr mTURNUDPQuery;
        IDNSQueryPtr mTURNTCPQuery;

        IPAddress mAllocateResponseIP;
        IPAddress mRelayedIP;
        IPAddress mReflectedIP;

        ServerPtr mActiveServer;

        DWORD mLifetime {};

        ISTUNRequesterPtr mRefreshRequester;

        SecureByteBlockPtr mMobilityTicket;

        ITimerPtr mRefreshTimer;
        Time mLastSentDataToServer {};
        Time mLastRefreshTimerWasSentAt {};

        ISTUNRequesterPtr mDeallocateRequester;
        ITimerPtr mDeallocTimer;

        ServerList mServers;
        TimerMap mActivationTimers;

        PermissionMap mPermissions;
        ITimerPtr mPermissionTimer;
        ISTUNRequesterPtr mPermissionRequester;
        ULONG mPermissionRequesterMaxCapacity {};

        ChannelIPMap mChannelIPMap;
        ChannelNumberMap mChannelNumberMap;

        bool          mForceTURNUseUDP {};
        bool          mForceTURNUseTCP {};
        IPAddressSet  mRestrictedIPs;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // ITURNSocketFactory
      //

      interaction ITURNSocketFactory
      {
        typedef ITURNSocket::CreationOptions CreationOptions;

        static ITURNSocketFactory &singleton() noexcept;

        virtual TURNSocketPtr create(
                                     IMessageQueuePtr queue,
                                     ITURNSocketDelegatePtr delegate,
                                     const CreationOptions &options
                                     ) noexcept;
      };

      class TURNSocketFactory : public IFactory<ITURNSocketFactory> {};
      
    }
  }
}
