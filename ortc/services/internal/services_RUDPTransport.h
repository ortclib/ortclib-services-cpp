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
#include <ortc/services/internal/services_RUDPChannel.h>
#include <ortc/services/IRUDPTransport.h>
#include <ortc/services/IICESocketSession.h>
#include <ortc/services/ISTUNRequester.h>

#define ORTC_SERVICES_RUDPICESOCKETSESSION_CHANNEL_RANGE_START (0x6000)                    // the actual range is 0x4000 -> 0x7FFF but to prevent collision with TURN, RUDP this is a recommended range to use
#define ORTC_SERVICES_RUDPICESOCKETSESSION_CHANNEL_RANGE_END   (0x7FFF)

namespace ortc
{
  namespace services
  {
    namespace internal
    {
      interaction IRUDPChannelForRUDPTransport;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // RUDPTransport
      //

      class RUDPTransport : public Noop,
                            public MessageQueueAssociator,
                            public IRUDPTransport,
                            public IICESocketSessionDelegate,
                            public IRUDPChannelDelegateForSessionAndListener
      {
      protected:
        struct make_private {};

      public:
        friend interaction IRUDPTransportFactory;
        friend interaction IRUDPTransport;

        ZS_DECLARE_TYPEDEF_PTR(IRUDPChannelForRUDPTransport, UseRUDPChannel)

        typedef IICESocket::CandidateList CandidateList;
        typedef IICESocket::ICEControls ICEControls;

        typedef WORD ChannelNumber;
        typedef std::map<ChannelNumber, UseRUDPChannelPtr> SessionMap;

        typedef std::list<UseRUDPChannelPtr> PendingSessionList;

      public:
        RUDPTransport(
                      const make_private &,
                      IMessageQueuePtr queue,
                      IICESocketSessionPtr iceSession,
                      IRUDPTransportDelegatePtr delegate
                      ) noexcept;

      protected:
        RUDPTransport(Noop) noexcept : Noop(true), MessageQueueAssociator(IMessageQueuePtr()) {};

        void init() noexcept;

        static RUDPTransportPtr convert(IRUDPTransportPtr session) noexcept;

      public:
        ~RUDPTransport() noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // RUDPTransport => IRUDPTransport
        //

        static ElementPtr toDebug(IRUDPTransportPtr session) noexcept;

        static RUDPTransportPtr listen(
                                       IMessageQueuePtr queue,
                                       IICESocketSessionPtr iceSession,
                                       IRUDPTransportDelegatePtr delegate
                                       ) noexcept;

        PUID getID() const noexcept override {return mID;}

        IRUDPTransportSubscriptionPtr subscribe(IRUDPTransportDelegatePtr delegate) noexcept override;

        RUDPTransportStates getState(
                                     WORD *outLastErrorCode = NULL,
                                     String *outLastErrorReason = NULL
                                     ) const noexcept override;

        void shutdown() noexcept override;

        IICESocketSessionPtr getICESession() const noexcept override;

        IRUDPChannelPtr openChannel(
                                    IRUDPChannelDelegatePtr delegate,
                                    const char *connectionInfo,
                                    ITransportStreamPtr receiveStream,
                                    ITransportStreamPtr sendStream
                                    ) noexcept override;

        IRUDPChannelPtr acceptChannel(
                                      IRUDPChannelDelegatePtr delegate,
                                      ITransportStreamPtr receiveStream,
                                      ITransportStreamPtr sendStream
                                      ) noexcept override;

        //---------------------------------------------------------------------
        //
        // RUDPTransport => IICESocketSessionDelegate
        //

        void onICESocketSessionStateChanged(
                                            IICESocketSessionPtr session,
                                            ICESocketSessionStates state
                                            ) override;

        void onICESocketSessionNominationChanged(IICESocketSessionPtr session) override;

        void handleICESocketSessionReceivedPacket(
                                                  IICESocketSessionPtr session,
                                                  const BYTE *buffer,
                                                  size_t bufferLengthInBytes
                                                  ) noexcept override;

        bool handleICESocketSessionReceivedSTUNPacket(
                                                      IICESocketSessionPtr session,
                                                      STUNPacketPtr stun,
                                                      const String &localUsernameFrag,
                                                      const String &remoteUsernameFrag
                                                      ) noexcept override;

        void onICESocketSessionWriteReady(IICESocketSessionPtr session) override;

        //---------------------------------------------------------------------
        //
        // RUDPTransport => IRUDPChannelDelegateForSessionAndListener
        //

        void onRUDPChannelStateChanged(
                                       RUDPChannelPtr channel,
                                       RUDPChannelStates state
                                       ) override;

        bool notifyRUDPChannelSendPacket(
                                         RUDPChannelPtr channel,
                                         const IPAddress &remoteIP,
                                         const BYTE *packet,
                                         size_t packetLengthInBytes
                                         ) noexcept override;

      protected:
        //---------------------------------------------------------------------
        //
        // RUDPTransport => (internal)
        //

        RecursiveLock &getLock() const noexcept;

        Log::Params log(const char *message) const noexcept;
        Log::Params debug(const char *message) const noexcept;
        void fix(STUNPacketPtr stun) const noexcept;

        bool isReady() noexcept {return RUDPTransportState_Ready == mCurrentState;}
        bool isShuttingDown() const noexcept {return RUDPTransportState_ShuttingDown == mCurrentState;}
        bool isShutdown() const noexcept {return RUDPTransportState_Shutdown == mCurrentState;}

        virtual ElementPtr toDebug() const noexcept;

        void cancel() noexcept;
        void step() noexcept;

        void setState(RUDPTransportStates state) noexcept;
        void setError(WORD errorCode, const char *inReason = NULL) noexcept;

        bool handleUnknownChannel(
                                  STUNPacketPtr &stun,
                                  STUNPacketPtr &outResponse
                                  ) noexcept;

        void issueChannelConnectIfPossible() noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // RUDPTransport => (data)
        //

        mutable RecursiveLock mLock;

        AutoPUID mID;
        RUDPTransportWeakPtr mThisWeak;

        RUDPTransportPtr mGracefulShutdownReference;

        IRUDPTransportDelegateSubscriptions mSubscriptions;
        IRUDPTransportSubscriptionPtr mDefaultSubscription;

        RUDPTransportStates mCurrentState;
        WORD mLastError {};
        String mLastErrorReason;

        IICESocketSessionPtr mICESession;
        IICESocketSessionSubscriptionPtr mICESubscription;

        SessionMap mLocalChannelNumberSessions;   // local channel numbers are the channel numbers we expect to receive from the remote party
        SessionMap mRemoteChannelNumberSessions;  // remote channel numbers are the channel numbers we expect to send to the remote party

        PendingSessionList mPendingSessions;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IRUDPTransportFactory
      //

      interaction IRUDPTransportFactory
      {
        typedef IICESocket::CandidateList CandidateList;
        typedef IICESocket::ICEControls ICEControls;

        static IRUDPTransportFactory &singleton() noexcept;

        virtual RUDPTransportPtr listen(
                                        IMessageQueuePtr queue,
                                        IICESocketSessionPtr iceSession,
                                        IRUDPTransportDelegatePtr delegate
                                        ) noexcept;
      };

      class RUDPTransportFactory : public IFactory<IRUDPTransportFactory> {};
      
    }
  }
}
