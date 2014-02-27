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
#include <openpeer/services/IICESocketSession.h>

#include <openpeer/services/IBackgrounding.h>
#include <openpeer/services/ISTUNRequester.h>

#include <openpeer/services/IWakeDelegate.h>

#include <zsLib/types.h>
#include <zsLib/Timer.h>
#include <zsLib/MessageQueueAssociator.h>

#include <list>
#include <utility>

namespace openpeer
{
  namespace services
  {
    namespace internal
    {
      interaction IICESocketForICESocketSession;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IICESocketSessionForICESocket
      #pragma mark

      interaction IICESocketSessionForICESocket
      {
        ZS_DECLARE_TYPEDEF_PTR(IICESocketSessionForICESocket, ForICESocket)

        typedef IICESocketSession::ICEControls ICEControls;
        typedef IICESocketSession::CandidateList CandidateList;

        virtual PUID getID() const = 0;
        virtual void close() = 0;

        virtual void updateRemoteCandidates(const CandidateList &remoteCandidates) = 0;

        virtual bool handleSTUNPacket(
                                      const IICESocket::Candidate &viaLocalCandidate,
                                      const IPAddress &source,
                                      STUNPacketPtr stun,
                                      const String &localUsernameFrag,
                                      const String &remoteUsernameFrag
                                      ) = 0;
        virtual bool handlePacket(
                                  const IICESocket::Candidate &viaLocalCandidate,
                                  const IPAddress &source,
                                  const BYTE *packet,
                                  size_t packetLengthInBytes
                                  ) = 0;

        virtual void notifyLocalWriteReady(const IICESocket::Candidate &viaLocalCandidate) = 0;
        virtual void notifyRelayWriteReady(const IICESocket::Candidate &viaLocalCandidate) = 0;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ICESocketSession
      #pragma mark

      class ICESocketSession : public Noop,
                               public MessageQueueAssociator,
                               public IICESocketSession,
                               public IICESocketSessionForICESocket,
                               public IWakeDelegate,
                               public IICESocketDelegate,
                               public ISTUNRequesterDelegate,
                               public ITimerDelegate,
                               public IBackgroundingDelegate
      {
      public:
        friend interaction IICESocketSessionFactory;
        friend interaction IICESocketSession;

        ZS_DECLARE_TYPEDEF_PTR(IICESocketForICESocketSession, UseICESocket)

        ZS_DECLARE_STRUCT_PTR(CandidatePair)

        typedef IICESocketSession::ICEControls ICEControls;
        typedef IICESocketSession::CandidateList CandidateList;

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocketSession::CandidatePair
        #pragma mark

        struct CandidatePair
        {
          static CandidatePairPtr create();
          ElementPtr toDebug() const;

          AutoPUID mID;

          Candidate mLocal;
          Candidate mRemote;

          bool mReceivedRequest;
          bool mReceivedResponse;
          bool mFailed;

          ISTUNRequesterPtr mRequester;
        };

        typedef std::list<CandidatePairPtr> CandidatePairList;

      protected:
        ICESocketSession(
                         IMessageQueuePtr queue,
                         IICESocketSessionDelegatePtr delegate,
                         UseICESocketPtr socket,
                         const char *remoteUsernameFrag,
                         const char *remotePassword,
                         ICEControls control,
                         ICESocketSessionPtr foundation = ICESocketSessionPtr()
                         );

        ICESocketSession(Noop) : Noop(true), MessageQueueAssociator(IMessageQueuePtr()) {};

        void init();

      public:
        static ICESocketSessionPtr convert(IICESocketSessionPtr session);
        static ICESocketSessionPtr convert(ForICESocketPtr session);

      public:
        ~ICESocketSession();

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocketSession => IICESocketSession
        #pragma mark

        static ElementPtr toDebug(IICESocketSessionPtr socket);

        static ICESocketSessionPtr create(
                                          IICESocketSessionDelegatePtr delegate,
                                          IICESocketPtr socket,
                                          const char *remoteUsernameFrag,
                                          const char *remotePassword,
                                          const CandidateList &remoteCandidates,
                                          ICEControls control,
                                          IICESocketSessionPtr foundation = IICESocketSessionPtr()
                                          );

        virtual PUID getID() const {return mID;}

        virtual IICESocketSessionSubscriptionPtr subscribe(IICESocketSessionDelegatePtr delegate);

        virtual IICESocketPtr getSocket();

        virtual ICESocketSessionStates getState(
                                                WORD *outLastErrorCode = NULL,
                                                String *outLastErrorReason = NULL
                                                ) const;

        virtual void close();

        virtual String getLocalUsernameFrag() const;
        virtual String getLocalPassword() const;
        virtual String getRemoteUsernameFrag() const;
        virtual String getRemotePassword() const;

        virtual void getLocalCandidates(CandidateList &outCandidates);
        virtual void updateRemoteCandidates(const CandidateList &remoteCandidates);
        virtual void endOfRemoteCandidates();

        virtual void setKeepAliveProperties(
                                            Duration sendKeepAliveIndications,
                                            Duration expectSTUNOrDataWithinWithinOrSendAliveCheck = Duration(),
                                            Duration keepAliveSTUNRequestTimeout = Duration(),
                                            Duration backgroundingTimeout = Duration()
                                            );

        virtual bool sendPacket(
                                const BYTE *packet,
                                size_t packetLengthInBytes
                                );

        virtual ICEControls getConnectedControlState();

        virtual IPAddress getConnectedRemoteIP();

        virtual bool getNominatedCandidateInformation(
                                                      Candidate &outLocal,
                                                      Candidate &outRemote
                                                      );

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocketSession => IICESocketSessionForICESocket
        #pragma mark

        // (duplicate) virtual PUID getID() const;
        // (duplicate) virtual void close();

        // (duplicate) virtual void updateRemoteCandidates(const CandidateList &remoteCandidates);

        virtual bool handleSTUNPacket(
                                      const IICESocket::Candidate &viaLocalCandidate,
                                      const IPAddress &source,
                                      STUNPacketPtr stun,
                                      const String &localUsernameFrag,
                                      const String &remoteUsernameFrag
                                      );
        virtual bool handlePacket(
                                  const IICESocket::Candidate &viaLocalCandidate,
                                  const IPAddress &source,
                                  const BYTE *packet,
                                  size_t packetLengthInBytes
                                  );

        virtual void notifyLocalWriteReady(const IICESocket::Candidate &viaLocalCandidate);
        virtual void notifyRelayWriteReady(const IICESocket::Candidate &viaLocalCandidate);

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocketSession => IWakeDelegate
        #pragma mark

        virtual void onWake();

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocketSession => IICESocketDelegate
        #pragma mark

        virtual void onICESocketStateChanged(
                                             IICESocketPtr socket,
                                             ICESocketStates state
                                             );
        virtual void onICESocketCandidatesChanged(IICESocketPtr socket);

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocketSession => ISTUNRequesterDelegate
        #pragma mark

        virtual void onSTUNRequesterSendPacket(
                                               ISTUNRequesterPtr requester,
                                               IPAddress destination,
                                               SecureByteBlockPtr packet
                                               );

        virtual bool handleSTUNRequesterResponse(
                                                 ISTUNRequesterPtr requester,
                                                 IPAddress fromIPAddress,
                                                 STUNPacketPtr response
                                                 );

        virtual void onSTUNRequesterTimedOut(ISTUNRequesterPtr requester);

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocketSession => ITimerDelegate
        #pragma mark

        virtual void onTimer(TimerPtr timer);

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocketSession => IBackgroundingDelegate
        #pragma mark

        virtual void onBackgroundingGoingToBackground(IBackgroundingNotifierPtr notifier);

        virtual void onBackgroundingGoingToBackgroundNow();

        virtual void onBackgroundingReturningFromBackground();

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocketSession => (internal)
        #pragma mark

        RecursiveLock &getLock() const;

        Log::Params log(const char *message) const;
        Log::Params debug(const char *message) const;

        void fix(STUNPacketPtr stun) const;

        virtual ElementPtr toDebug() const;

        bool isShutdown() const {return ICESocketSessionState_Shutdown == mCurrentState;}

        void cancel();
        void setState(ICESocketSessionStates state);
        void setError(WORD errorCode, const char *inReason = NULL);

        void step();
        bool stepSocket();
        bool stepCandidates();
        bool stepActivateTimer();
        bool stepEndSearch();
        bool stepTimer();
        bool stepExpectingDataTimer();
        bool stepKeepAliveTimer();
        bool stepCancelLowerPriority();
        bool stepNominate();
        void stepNotifyNominated();

        void switchRole(ICEControls newRole);

        bool sendTo(
                    const IICESocket::Candidate &viaLocalCandidate,
                    const IPAddress &destination,
                    const BYTE *buffer,
                    size_t bufferLengthInBytes,
                    bool isUserData
                    );

        bool canUnfreeze(CandidatePairPtr derivedPairing);
        void sendKeepAliveNow();
        void sendAliveCheckRequest();

        void clearAliveCheckRequester()   {if (!mAliveCheckRequester) return; mAliveCheckRequester->cancel(); mAliveCheckRequester.reset(); mBackgroundingNotifier.reset();}
        void clearNominateRequester()     {if (!mNominateRequester) return; mNominateRequester->cancel(); mNominateRequester.reset(); mBackgroundingNotifier.reset();}

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark ICESocketSession => (data)
        #pragma mark

        mutable RecursiveLock mBogusLock;

        AutoPUID mID;
        ICESocketSessionWeakPtr mThisWeak;
        UseICESocketWeakPtr mICESocketWeak;

        ICESocketSessionStates mCurrentState;
        AutoWORD mLastError;
        String mLastErrorReason;

        IICESocketSessionDelegateSubscriptions mSubscriptions;
        IICESocketSessionSubscriptionPtr mDefaultSubscription;

        IBackgroundingSubscriptionPtr mBackgroundingSubscription;
        IBackgroundingNotifierPtr mBackgroundingNotifier;

        AutoBool mInformedWriteReady;

        IICESocketSubscriptionPtr mSocketSubscription;

        ICESocketSessionPtr mFoundation;

        String mLocalUsernameFrag;
        String mLocalPassword;
        String mRemoteUsernameFrag;
        String mRemotePassword;

        TimerPtr mActivateTimer;
        TimerPtr mKeepAliveTimer;
        TimerPtr mExpectingDataTimer;
        TimerPtr mStepTimer;

        ICEControls mControl;
        QWORD mConflictResolver;

        ISTUNRequesterPtr mNominateRequester;
        CandidatePairPtr mPendingNominatation;
        CandidatePairPtr mNominated;
        CandidatePairPtr mPreviouslyNominated;

        Time mLastSentData;
        Time mWentToBackgroundAt;
        CandidatePairPtr mLastNotifiedNominated;

        ISTUNRequesterPtr mAliveCheckRequester;
        Time mLastReceivedDataOrSTUN;
        Duration mKeepAliveDuration;
        Duration mExpectSTUNOrDataWithinDuration;
        Duration mKeepAliveSTUNRequestTimeout;
        Duration mBackgroundingTimeout;

        CandidatePairList mCandidatePairs;

        CandidateList mUpdatedLocalCandidates;
        CandidateList mUpdatedRemoteCandidates;

        CandidateList mLocalCandidates;
        CandidateList mRemoteCandidates;
        AutoBool mEndOfRemoteCandidatesFlag;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IICESocketSessionFactory
      #pragma mark

      interaction IICESocketSessionFactory
      {
        typedef IICESocket::CandidateList CandidateList;
        typedef IICESocketSession::ICEControls ICEControls;

        static IICESocketSessionFactory &singleton();

        virtual ICESocketSessionPtr create(
                                           IICESocketSessionDelegatePtr delegate,
                                           IICESocketPtr socket,
                                           const char *remoteUsernameFrag,
                                           const char *remotePassword,
                                           const CandidateList &remoteCandidates,
                                           ICEControls control,
                                           IICESocketSessionPtr foundation = IICESocketSessionPtr()
                                           );
      };

    }
  }
}
