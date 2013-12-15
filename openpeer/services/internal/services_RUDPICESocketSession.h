/*

 Copyright (c) 2013, SMB Phone Inc.
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
#include <openpeer/services/IRUDPICESocketSession.h>
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
      interaction IRUDPChannelForRUDPICESocketSession;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RUDPICESocketSession
      #pragma mark

      class RUDPICESocketSession : public Noop,
                                   public MessageQueueAssociator,
                                   public IRUDPICESocketSession,
                                   public IICESocketSessionDelegate,
                                   public IRUDPChannelDelegateForSessionAndListener
      {
      public:
        friend interaction IRUDPICESocketSessionFactory;
        friend interaction IRUDPICESocketSession;

        ZS_DECLARE_TYPEDEF_PTR(IRUDPChannelForRUDPICESocketSession, UseRUDPChannel)

        typedef IICESocket::CandidateList CandidateList;
        typedef IICESocket::ICEControls ICEControls;

        typedef WORD ChannelNumber;
        typedef std::map<ChannelNumber, UseRUDPChannelPtr> SessionMap;

        typedef std::list<UseRUDPChannelPtr> PendingSessionList;

      protected:
        RUDPICESocketSession(
                             IMessageQueuePtr queue,
                             IICESocketSessionPtr iceSession,
                             IRUDPICESocketSessionDelegatePtr delegate
                             );

        RUDPICESocketSession(Noop) : Noop(true), MessageQueueAssociator(IMessageQueuePtr()) {};

        void init();

        static RUDPICESocketSessionPtr convert(IRUDPICESocketSessionPtr session);

      public:
        ~RUDPICESocketSession();

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark RUDPICESocketSession => IRUDPICESocketSession
        #pragma mark

        static ElementPtr toDebug(IRUDPICESocketSessionPtr session);

        static RUDPICESocketSessionPtr listen(
                                              IMessageQueuePtr queue,
                                              IICESocketSessionPtr iceSession,
                                              IRUDPICESocketSessionDelegatePtr delegate
                                              );

        virtual PUID getID() const {return mID;}

        virtual IRUDPICESocketSessionSubscriptionPtr subscribe(IRUDPICESocketSessionDelegatePtr delegate);

        virtual RUDPICESocketSessionStates getState(
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
        #pragma mark RUDPICESocketSession => IICESocketSessionDelegate
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
        #pragma mark RUDPICESocketSession => IRUDPChannelDelegateForSessionAndListener
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
        #pragma mark RUDPICESocketSession => (internal)
        #pragma mark

        RecursiveLock &getLock() const;

        Log::Params log(const char *message) const;
        Log::Params debug(const char *message) const;
        void fix(STUNPacketPtr stun) const;

        bool isReady() {return RUDPICESocketSessionState_Ready == mCurrentState;}
        bool isShuttingDown() const {return RUDPICESocketSessionState_ShuttingDown == mCurrentState;}
        bool isShutdown() const {return RUDPICESocketSessionState_Shutdown == mCurrentState;}

        virtual ElementPtr toDebug() const;

        void cancel();
        void step();

        void setState(RUDPICESocketSessionStates state);
        void setError(WORD errorCode, const char *inReason = NULL);

        bool handleUnknownChannel(
                                  STUNPacketPtr &stun,
                                  STUNPacketPtr &outResponse
                                  );

        void issueChannelConnectIfPossible();

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark RUDPICESocketSession => (data)
        #pragma mark

        mutable RecursiveLock mLock;

        AutoPUID mID;
        RUDPICESocketSessionWeakPtr mThisWeak;

        RUDPICESocketSessionPtr mGracefulShutdownReference;

        IRUDPICESocketSessionDelegateSubscriptions mSubscriptions;
        IRUDPICESocketSessionSubscriptionPtr mDefaultSubscription;

        RUDPICESocketSessionStates mCurrentState;
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
      #pragma mark IRUDPICESocketSessionFactory
      #pragma mark

      interaction IRUDPICESocketSessionFactory
      {
        typedef IICESocket::CandidateList CandidateList;
        typedef IICESocket::ICEControls ICEControls;

        static IRUDPICESocketSessionFactory &singleton();

        virtual RUDPICESocketSessionPtr listen(
                                               IMessageQueuePtr queue,
                                               IICESocketSessionPtr iceSession,
                                               IRUDPICESocketSessionDelegatePtr delegate
                                               );
      };
      
    }
  }
}
