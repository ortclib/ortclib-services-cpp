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
#include <ortc/services/internal/services_IRUDPChannelStream.h>
#include <ortc/services/IRUDPChannel.h>
#include <ortc/services/ISTUNRequester.h>

#include <zsLib/ITimer.h>
#include <zsLib/IWakeDelegate.h>

#include <map>

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
      // IRUDPChannelForRUDPTransport
      //

      interaction IRUDPChannelForRUDPTransport
      {
        ZS_DECLARE_TYPEDEF_PTR(IRUDPChannelForRUDPTransport, ForRUDPTransport)

        static ForRUDPTransportPtr createForRUDPTransportIncoming(
                                                                  IMessageQueuePtr queue,
                                                                  IRUDPChannelDelegateForSessionAndListenerPtr master,
                                                                  const IPAddress &remoteIP,
                                                                  WORD incomingChannelNumber,
                                                                  const char *localUsernameFrag,
                                                                  const char *localPassword,
                                                                  const char *remoteUsernameFrag,
                                                                  const char *remotePassword,
                                                                  STUNPacketPtr channelOpenPacket,
                                                                  STUNPacketPtr &outResponse
                                                                  ) noexcept;

        static ForRUDPTransportPtr createForRUDPTransportOutgoing(
                                                                  IMessageQueuePtr queue,
                                                                  IRUDPChannelDelegateForSessionAndListenerPtr master,
                                                                  IRUDPChannelDelegatePtr delegate,
                                                                  const IPAddress &remoteIP,
                                                                  WORD incomingChannelNumber,
                                                                  const char *localUsernameFrag,
                                                                  const char *localPassword,
                                                                  const char *remoteUsernameFrag,
                                                                  const char *remotePassword,
                                                                  const char *connectionInfo,
                                                                  ITransportStreamPtr receiveStream,
                                                                  ITransportStreamPtr sendStream
                                                                  ) noexcept;

        virtual PUID getID() const noexcept = 0;

        virtual void setDelegate(IRUDPChannelDelegatePtr delegate) noexcept = 0;
        virtual void setStreams(
                                ITransportStreamPtr receiveStream,
                                ITransportStreamPtr sendStream
                                ) noexcept = 0;

        virtual bool handleSTUN(
                                STUNPacketPtr stun,
                                STUNPacketPtr &outResponse,
                                const String &localUsernameFrag,
                                const String &remoteUsernameFrag
                                ) noexcept = 0;

        virtual void handleRUDP(
                                RUDPPacketPtr rudp,
                                const BYTE *buffer,
                                size_t bufferLengthInBytes
                                ) noexcept = 0;

        virtual void notifyWriteReady() noexcept = 0;
        virtual WORD getIncomingChannelNumber() const noexcept = 0;
        virtual WORD getOutgoingChannelNumber() const noexcept = 0;

        virtual void issueConnectIfNotIssued() noexcept = 0;

        virtual void shutdown() noexcept = 0;
        virtual void shutdownFromTimeout() noexcept = 0;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IRUDPChannelForRUDPListener
      //

      interaction IRUDPChannelForRUDPListener
      {
        ZS_DECLARE_TYPEDEF_PTR(IRUDPChannelForRUDPListener, ForRUDPListener)

        static ForRUDPListenerPtr createForListener(
                                                    IMessageQueuePtr queue,
                                                    IRUDPChannelDelegateForSessionAndListenerPtr master,
                                                    const IPAddress &remoteIP,
                                                    WORD incomingChannelNumber,
                                                    STUNPacketPtr channelOpenPacket,
                                                    STUNPacketPtr &outResponse
                                                    ) noexcept;

        virtual void setDelegate(IRUDPChannelDelegatePtr delegate) noexcept = 0;
        virtual void setStreams(
                                ITransportStreamPtr receiveStream,
                                ITransportStreamPtr sendStream
                                ) noexcept = 0;

        virtual bool handleSTUN(
                                STUNPacketPtr stun,
                                STUNPacketPtr &outResponse,
                                const String &localUsernameFrag,
                                const String &remoteUsernameFrag
                                ) noexcept = 0;

        virtual void handleRUDP(
                                RUDPPacketPtr rudp,
                                const BYTE *buffer,
                                size_t bufferLengthInBytes
                                ) noexcept = 0;

        virtual void notifyWriteReady() noexcept = 0;

        virtual void shutdown() noexcept = 0;
      };
      
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // RUDPChannel
      //

      class RUDPChannel : public Noop,
                          public MessageQueueAssociator,
                          public IRUDPChannel,
                          public IRUDPChannelForRUDPTransport,
                          public IRUDPChannelForRUDPListener,
                          public IWakeDelegate,
                          public IRUDPChannelStreamDelegate,
                          public ISTUNRequesterDelegate,
                          public ITimerDelegate
      {
      public:
        friend interaction IRUDPChannelFactory;
        friend interaction IRUDPChannel;

        typedef PUID ACKRequestID;
        typedef std::map<ACKRequestID, ISTUNRequesterPtr> ACKRequestMap;

      protected:
        RUDPChannel(
                    IMessageQueuePtr queue,
                    IRUDPChannelDelegateForSessionAndListenerPtr master,
                    const IPAddress &remoteIP,
                    const char *localUserFrag,
                    const char *localPassword,
                    const char *remoteUserFrag,
                    const char *remotePassword,
                    DWORD minimumRTT,
                    DWORD lifetime,
                    WORD incomingChannelNumber,
                    QWORD localSequenceNumber,
                    const char *localChannelInfo,
                    WORD outgoingChannelNumber = 0,
                    QWORD remoteSequenceNumber = 0,
                    const char *remoteChannelInfo = NULL
                    ) noexcept;
      protected:
        RUDPChannel(Noop) noexcept : Noop(true), MessageQueueAssociator(IMessageQueuePtr()) {};

        void init() noexcept;

      public:
        ~RUDPChannel() noexcept;

        static RUDPChannelPtr convert(IRUDPChannelPtr channel) noexcept;
        static RUDPChannelPtr convert(ForRUDPTransportPtr channel) noexcept;
        static RUDPChannelPtr convert(ForRUDPListenerPtr channel) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // RUDPChannel => IRUDPChannel
        //

        static ElementPtr toDebug(IRUDPChannelPtr channel) noexcept;

        virtual PUID getID() const noexcept {return mID;}

        virtual RUDPChannelStates getState(
                                           WORD *outLastErrorCode = NULL,
                                           String *outLastErrorReason = NULL
                                           ) const noexcept;

        virtual void shutdown() noexcept;

        virtual void shutdownDirection(Shutdown state) noexcept;

        virtual IPAddress getConnectedRemoteIP() noexcept;

        virtual String getRemoteConnectionInfo() noexcept;

        //---------------------------------------------------------------------
        //
        // RUDPChannel => IRUDPChannelForRUDPTransport
        //

        static RUDPChannelPtr createForRUDPTransportIncoming(
                                                             IMessageQueuePtr queue,
                                                             IRUDPChannelDelegateForSessionAndListenerPtr master,
                                                             const IPAddress &remoteIP,
                                                             WORD incomingChannelNumber,
                                                             const char *localUserFrag,
                                                             const char *localPassword,
                                                             const char *remoteUserFrag,
                                                             const char *remotePassword,
                                                             STUNPacketPtr channelOpenPacket,
                                                             STUNPacketPtr &outResponse
                                                             ) noexcept;

        static RUDPChannelPtr createForRUDPTransportOutgoing(
                                                             IMessageQueuePtr queue,
                                                             IRUDPChannelDelegateForSessionAndListenerPtr master,
                                                             IRUDPChannelDelegatePtr delegate,
                                                             const IPAddress &remoteIP,
                                                             WORD incomingChannelNumber,
                                                             const char *localUserFrag,
                                                             const char *localPassword,
                                                             const char *remoteUserFrag,
                                                             const char *remotePassword,
                                                             const char *connectionInfo,
                                                             ITransportStreamPtr receiveStream,
                                                             ITransportStreamPtr sendStream
                                                             ) noexcept;

        // (duplicate) virtual PUID getID() const;

        virtual void setDelegate(IRUDPChannelDelegatePtr delegate) noexcept;
        virtual void setStreams(
                                ITransportStreamPtr receiveStream,
                                ITransportStreamPtr sendStream
                                ) noexcept;

        virtual bool handleSTUN(
                                STUNPacketPtr stun,
                                STUNPacketPtr &outResponse,
                                const String &localUsernameFrag,
                                const String &remoteUsernameFrag
                                ) noexcept;

        virtual void handleRUDP(
                                RUDPPacketPtr rudp,
                                const BYTE *buffer,
                                size_t bufferLengthInBytes
                                ) noexcept;

        virtual void notifyWriteReady() noexcept;
        virtual WORD getIncomingChannelNumber() const noexcept;
        virtual WORD getOutgoingChannelNumber() const noexcept;

        virtual void issueConnectIfNotIssued() noexcept;

        // (duplicate) virtual void shutdown();

        virtual void shutdownFromTimeout() noexcept;

        //---------------------------------------------------------------------
        //
        // RUDPChannel => IRUDPChannelForRUDPListener
        //

        static RUDPChannelPtr createForListener(
                                                IMessageQueuePtr queue,
                                                IRUDPChannelDelegateForSessionAndListenerPtr master,
                                                const IPAddress &remoteIP,
                                                WORD incomingChannelNumber,
                                                STUNPacketPtr channelOpenPacket,
                                                STUNPacketPtr &outResponse
                                                ) noexcept;

        // (duplicate) virtual void setDelegate(IRUDPChannelDelegatePtr delegate) noexcept;
        // virtual void setStreams(
        //                         ITransportStreamPtr receiveStream,
        //                         ITransportStreamPtr sendStream
        //                         ) noexcept;

        // (duplicate) virtual bool handleSTUN(
        //                                     STUNPacketPtr stun,
        //                                     STUNPacketPtr &outResponse,
        //                                     const String &localUsernameFrag,
        //                                     const String &remoteUsernameFrag
        //                                     ) noexcept;

        // (duplicate) virtual void handleRUDP(
        //                                     RUDPPacketPtr rudp,
        //                                     const BYTE *buffer,
        //                                     size_t bufferLengthInBytes
        //                                     ) noexcept;

        // (duplicate) virtual void notifyWriteReady() noexcept;

        // (duplicate) virtual void shutdown() noexcept;

        //---------------------------------------------------------------------
        //
        // RUDPChannel => IWakeDelegate
        //

        void onWake() override;

        //---------------------------------------------------------------------
        //
        // RUDPChannel => IRUDPChannelStreamDelegate
        //

        void onRUDPChannelStreamStateChanged(
                                             IRUDPChannelStreamPtr stream,
                                             RUDPChannelStreamStates state
                                             ) override;

        bool notifyRUDPChannelStreamSendPacket(
                                               IRUDPChannelStreamPtr stream,
                                               const BYTE *packet,
                                               size_t packetLengthInBytes
                                               ) noexcept override;

        void onRUDPChannelStreamSendExternalACKNow(
                                                   IRUDPChannelStreamPtr stream,
                                                   bool guarenteeDelivery,
                                                   PUID guarenteeDeliveryRequestID = 0
                                                   ) override;

        //---------------------------------------------------------------------
        //
        // RUDPChannel => ISTUNRequesterDelegate
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
        // RUDPChannel => ITimerDelegate
        //

        void onTimer(ITimerPtr timer) override;

      protected:
        //---------------------------------------------------------------------
        //
        // RUDPChannel => (internal)
        //

        Log::Params log(const char *message) const noexcept;
        Log::Params debug(const char *message) const noexcept;

        void fix(STUNPacketPtr stun) const noexcept;

        bool isShuttingDown() noexcept {return RUDPChannelState_ShuttingDown == mCurrentState;}
        bool isShutdown() noexcept {return RUDPChannelState_Shutdown == mCurrentState;}

        virtual ElementPtr toDebug() const noexcept;

        void cancel(bool waitForAllDataToSend) noexcept;
        void step() noexcept;

        void setState(RUDPChannelStates state) noexcept;
        void setError(WORD errorCode, const char *inReason = NULL) noexcept;

        bool isValidIntegrity(STUNPacketPtr stun) noexcept;
        void fillCredentials(STUNPacketPtr &outSTUN) noexcept;
        void fillACK(STUNPacketPtr &outSTUN) noexcept;

        bool handleStaleNonce(
                              ISTUNRequesterPtr &originalRequestVariable,
                              STUNPacketPtr response
                              ) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // RUDPChannel => (data)
        //

        AutoPUID mID;
        mutable RecursiveLock mLock;
        RUDPChannelWeakPtr mThisWeak;
        RUDPChannelPtr mGracefulShutdownReference;

        bool mIncoming {};

        RUDPChannelStates mCurrentState;
        WORD mLastError {};
        String mLastErrorReason;

        IRUDPChannelDelegatePtr mDelegate;
        IRUDPChannelDelegateForSessionAndListenerPtr mMasterDelegate;

        ITransportStreamPtr mReceiveStream;
        ITransportStreamPtr mSendStream;

        IRUDPChannelStreamPtr mStream;
        ISTUNRequesterPtr mOpenRequest;
        ISTUNRequesterPtr mShutdownRequest;
        bool mSTUNRequestPreviouslyTimedOut {};    // if true then no need issue a "close" STUN request if a STUN request has previously timed out

        ITimerPtr mTimer;

        IRUDPChannelStream::Shutdown mShutdownDirection {IRUDPChannel::Shutdown_None};

        IPAddress mRemoteIP;

        String mLocalUsernameFrag;
        String mLocalPassword;
        String mRemoteUsernameFrag;
        String mRemotePassword;

        String mRealm;
        String mNonce;

        WORD mIncomingChannelNumber;
        WORD mOutgoingChannelNumber;

        QWORD mLocalSequenceNumber;
        QWORD mRemoteSequenceNumber;

        DWORD mMinimumRTT;
        DWORD mLifetime;

        String mLocalChannelInfo;
        String mRemoteChannelInfo;

        Time mLastSentData;
        Time mLastReceivedData;

        ACKRequestMap mOutstandingACKs;
      };

      //-----------------------------------------------------------------------
      //
      // IRUDPChannelDelegateForSessionAndListener
      //

      interaction IRUDPChannelDelegateForSessionAndListener
      {
        typedef IRUDPChannel::RUDPChannelStates RUDPChannelStates;

        virtual void onRUDPChannelStateChanged(
                                               RUDPChannelPtr channel,
                                               RUDPChannelStates state
                                               ) = 0;

        //---------------------------------------------------------------------
        // PURPOSE: Send a packet over the socket interface to the remote party.
        virtual bool notifyRUDPChannelSendPacket(
                                                 RUDPChannelPtr channel,
                                                 const IPAddress &remoteIP,
                                                 const BYTE *packet,
                                                 size_t packetLengthInBytes
                                                 ) noexcept = 0;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IRUDPChannelFactory
      //

      interaction IRUDPChannelFactory
      {
        static IRUDPChannelFactory &singleton() noexcept;

        virtual RUDPChannelPtr createForRUDPTransportIncoming(
                                                              IMessageQueuePtr queue,
                                                              IRUDPChannelDelegateForSessionAndListenerPtr master,
                                                              const IPAddress &remoteIP,
                                                              WORD incomingChannelNumber,
                                                              const char *localUserFrag,
                                                              const char *localPassword,
                                                              const char *remoteUserFrag,
                                                              const char *remotePassword,
                                                              STUNPacketPtr channelOpenPacket,
                                                              STUNPacketPtr &outResponse
                                                              ) noexcept;

        virtual RUDPChannelPtr createForRUDPTransportOutgoing(
                                                              IMessageQueuePtr queue,
                                                              IRUDPChannelDelegateForSessionAndListenerPtr master,
                                                              IRUDPChannelDelegatePtr delegate,
                                                              const IPAddress &remoteIP,
                                                              WORD incomingChannelNumber,
                                                              const char *localUserFrag,
                                                              const char *localPassword,
                                                              const char *remoteUserFrag,
                                                              const char *remotePassword,
                                                              const char *connectionInfo,
                                                              ITransportStreamPtr receiveStream,
                                                              ITransportStreamPtr sendStream
                                                              ) noexcept;

        virtual RUDPChannelPtr createForListener(
                                                 IMessageQueuePtr queue,
                                                 IRUDPChannelDelegateForSessionAndListenerPtr master,
                                                 const IPAddress &remoteIP,
                                                 WORD incomingChannelNumber,
                                                 STUNPacketPtr channelOpenPacket,
                                                 STUNPacketPtr &outResponse
                                                 ) noexcept;
      };

      class RUDPChannelFactory : public IFactory<IRUDPChannelFactory> {};

    }
  }
}


ZS_DECLARE_PROXY_BEGIN(ortc::services::internal::IRUDPChannelDelegateForSessionAndListener)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::internal::RUDPChannelPtr, RUDPChannelPtr)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::internal::IRUDPChannelDelegateForSessionAndListener::RUDPChannelStates, RUDPChannelStates)
ZS_DECLARE_PROXY_METHOD(onRUDPChannelStateChanged, RUDPChannelPtr, RUDPChannelStates)
ZS_DECLARE_PROXY_METHOD_SYNC_RETURN(notifyRUDPChannelSendPacket, bool, RUDPChannelPtr, const IPAddress &, const BYTE *, size_t)
ZS_DECLARE_PROXY_END()
