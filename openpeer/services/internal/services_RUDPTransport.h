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

#include <openpeer/services/internal/types.h>
#include <openpeer/services/internal/services_RUDPChannel.h>
#include <openpeer/services/IRUDPTransport.h>
#include <openpeer/services/IICESocketSession.h>
#include <openpeer/services/ISTUNRequester.h>

#define OPENPEER_SERVICES_RUDPICESOCKETSESSION_CHANNEL_RANGE_START (0x6000)                    // the actual range is 0x4000 -> 0x7FFF but to prevent collision with TURN, RUDP this is a recommended range to use
#define OPENPEER_SERVICES_RUDPICESOCKETSESSION_CHANNEL_RANGE_END   (0x7FFF)

namespace openpeer
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
      #pragma mark
      #pragma mark RUDPTransport
      #pragma mark

      class RUDPTransport : public Noop,
                            public MessageQueueAssociator,
                            public IRUDPTransport,
                            public IICESocketSessionDelegate,
                            public IRUDPChannelDelegateForSessionAndListener
      {
      public:
        friend interaction IRUDPTransportFactory;
        friend interaction IRUDPTransport;

        ZS_DECLARE_TYPEDEF_PTR(IRUDPChannelForRUDPTransport, UseRUDPChannel)

        typedef IICESocket::CandidateList CandidateList;
        typedef IICESocket::ICEControls ICEControls;

        typedef WORD ChannelNumber;
        typedef std::map<ChannelNumber, UseRUDPChannelPtr> SessionMap;

        typedef std::list<UseRUDPChannelPtr> PendingSessionList;

      protected:
        RUDPTransport(
                      IMessageQueuePtr queue,
                      IICESocketSessionPtr iceSession,
                      IRUDPTransportDelegatePtr delegate
                      );

        RUDPTransport(Noop) : Noop(true), MessageQueueAssociator(IMessageQueuePtr()) {};

        void init();

        static RUDPTransportPtr convert(IRUDPTransportPtr session);

      public:
        ~RUDPTransport();

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark RUDPTransport => IRUDPTransport
        #pragma mark

        static ElementPtr toDebug(IRUDPTransportPtr session);

        static RUDPTransportPtr listen(
                                       IMessageQueuePtr queue,
                                       IICESocketSessionPtr iceSession,
                                       IRUDPTransportDelegatePtr delegate
                                       );

        virtual PUID getID() const {return mID;}

        virtual IRUDPTransportSubscriptionPtr subscribe(IRUDPTransportDelegatePtr delegate);

        virtual RUDPTransportStates getState(
                                             WORD *outLastErrorCode = NULL,
                                             String *outLastErrorReason = NULL
                                             ) const;

        virtual void shutdown();

        virtual IICESocketSessionPtr getICESession() const;

        virtual IRUDPChannelPtr openChannel(
                                            IRUDPChannelDelegatePtr delegate,
                                            const char *connectionInfo,
                                            ITransportStreamPtr receiveStream,
                                            ITransportStreamPtr sendStream
                                            );

        virtual IRUDPChannelPtr acceptChannel(
                                              IRUDPChannelDelegatePtr delegate,
                                              ITransportStreamPtr receiveStream,
                                              ITransportStreamPtr sendStream
                                              );

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark RUDPTransport => IICESocketSessionDelegate
        #pragma mark

        virtual void onICESocketSessionStateChanged(
                                                    IICESocketSessionPtr session,
                                                    ICESocketSessionStates state
                                                    );

        virtual void onICESocketSessionNominationChanged(IICESocketSessionPtr session);

        virtual void handleICESocketSessionReceivedPacket(
                                                          IICESocketSessionPtr session,
                                                          const BYTE *buffer,
                                                          size_t bufferLengthInBytes
                                                          );

        virtual bool handleICESocketSessionReceivedSTUNPacket(
                                                              IICESocketSessionPtr session,
                                                              STUNPacketPtr stun,
                                                              const String &localUsernameFrag,
                                                              const String &remoteUsernameFrag
                                                              );

        virtual void onICESocketSessionWriteReady(IICESocketSessionPtr session);

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark RUDPTransport => IRUDPChannelDelegateForSessionAndListener
        #pragma mark

        virtual void onRUDPChannelStateChanged(
                                               RUDPChannelPtr channel,
                                               RUDPChannelStates state
                                               );

        virtual bool notifyRUDPChannelSendPacket(
                                                 RUDPChannelPtr channel,
                                                 const IPAddress &remoteIP,
                                                 const BYTE *packet,
                                                 size_t packetLengthInBytes
                                                 );

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark RUDPTransport => (internal)
        #pragma mark

        RecursiveLock &getLock() const;

        Log::Params log(const char *message) const;
        Log::Params debug(const char *message) const;
        void fix(STUNPacketPtr stun) const;

        bool isReady() {return RUDPTransportState_Ready == mCurrentState;}
        bool isShuttingDown() const {return RUDPTransportState_ShuttingDown == mCurrentState;}
        bool isShutdown() const {return RUDPTransportState_Shutdown == mCurrentState;}

        virtual ElementPtr toDebug() const;

        void cancel();
        void step();

        void setState(RUDPTransportStates state);
        void setError(WORD errorCode, const char *inReason = NULL);

        bool handleUnknownChannel(
                                  STUNPacketPtr &stun,
                                  STUNPacketPtr &outResponse
                                  );

        void issueChannelConnectIfPossible();

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark RUDPTransport => (data)
        #pragma mark

        mutable RecursiveLock mLock;

        AutoPUID mID;
        RUDPTransportWeakPtr mThisWeak;

        RUDPTransportPtr mGracefulShutdownReference;

        IRUDPTransportDelegateSubscriptions mSubscriptions;
        IRUDPTransportSubscriptionPtr mDefaultSubscription;

        RUDPTransportStates mCurrentState;
        AutoWORD mLastError;
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
      #pragma mark
      #pragma mark IRUDPTransportFactory
      #pragma mark

      interaction IRUDPTransportFactory
      {
        typedef IICESocket::CandidateList CandidateList;
        typedef IICESocket::ICEControls ICEControls;

        static IRUDPTransportFactory &singleton();

        virtual RUDPTransportPtr listen(
                                        IMessageQueuePtr queue,
                                        IICESocketSessionPtr iceSession,
                                        IRUDPTransportDelegatePtr delegate
                                               );
      };

      class RUDPTransportFactory : public IFactory<IRUDPTransportFactory> {};
      
    }
  }
}
