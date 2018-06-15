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
#include <ortc/services/IICESocketSession.h>

#include <ortc/services/IBackgrounding.h>
#include <ortc/services/ISTUNRequester.h>


#include <zsLib/types.h>
#include <zsLib/ITimer.h>
#include <zsLib/IWakeDelegate.h>
#include <zsLib/MessageQueueAssociator.h>

#include <list>
#include <utility>

#define ORTC_SERVICES_SETTING_ICESOCKETSESSION_BACKGROUNDING_PHASE "ortc/services/backgrounding-phase-ice-socket-session"

namespace ortc
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
      //
      // IICESocketSessionForICESocket
      //

      interaction IICESocketSessionForICESocket
      {
        ZS_DECLARE_TYPEDEF_PTR(IICESocketSessionForICESocket, ForICESocket)

        typedef IICESocketSession::ICEControls ICEControls;
        typedef IICESocketSession::CandidateList CandidateList;

        virtual PUID getID() const noexcept = 0;
        virtual void close() noexcept = 0;

        virtual void updateRemoteCandidates(const CandidateList &remoteCandidates) noexcept = 0;

        virtual bool handleSTUNPacket(
                                      const IICESocket::Candidate &viaLocalCandidate,
                                      const IPAddress &source,
                                      STUNPacketPtr stun,
                                      const String &localUsernameFrag,
                                      const String &remoteUsernameFrag
                                      ) noexcept = 0;
        virtual bool handlePacket(
                                  const IICESocket::Candidate &viaLocalCandidate,
                                  const IPAddress &source,
                                  const BYTE *packet,
                                  size_t packetLengthInBytes
                                  ) noexcept = 0;

        virtual void notifyLocalWriteReady(const IICESocket::Candidate &viaLocalCandidate) noexcept = 0;
        virtual void notifyRelayWriteReady(const IICESocket::Candidate &viaLocalCandidate) noexcept = 0;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // ICESocketSession
      //

      class ICESocketSession : public Noop,
                               public MessageQueueAssociator,
                               public SharedRecursiveLock,
                               public IICESocketSession,
                               public IICESocketSessionForICESocket,
                               public IWakeDelegate,
                               public IICESocketDelegate,
                               public ISTUNRequesterDelegate,
                               public ITimerDelegate,
                               public IBackgroundingDelegate
      {
      protected:
        struct make_private {};

      public:
        friend interaction IICESocketSessionFactory;
        friend interaction IICESocketSession;

        ZS_DECLARE_TYPEDEF_PTR(IICESocketForICESocketSession, UseICESocket)

        ZS_DECLARE_STRUCT_PTR(CandidatePair)

        typedef IICESocketSession::ICEControls ICEControls;
        typedef IICESocketSession::CandidateList CandidateList;

        //---------------------------------------------------------------------
        //
        // ICESocketSession::CandidatePair
        //

        struct CandidatePair
        {
          static CandidatePairPtr create() noexcept;
          ElementPtr toDebug() const noexcept;

          AutoPUID mID;

          Candidate mLocal;
          Candidate mRemote;

          bool mReceivedRequest;
          bool mReceivedResponse;
          bool mFailed;

          ISTUNRequesterPtr mRequester;
        };

        typedef std::list<CandidatePairPtr> CandidatePairList;

      public:
        ICESocketSession(
                         const make_private &,
                         IMessageQueuePtr queue,
                         IICESocketSessionDelegatePtr delegate,
                         ICESocketPtr inSocket,
                         const char *remoteUsernameFrag,
                         const char *remotePassword,
                         ICEControls control,
                         ICESocketSessionPtr foundation = ICESocketSessionPtr()
                         ) noexcept;

        ICESocketSession(Noop) noexcept :
          Noop(true),
          MessageQueueAssociator(IMessageQueuePtr()),
          SharedRecursiveLock(SharedRecursiveLock::create())
        {}

      protected:
        void init() noexcept;

      public:
        static ICESocketSessionPtr convert(IICESocketSessionPtr session) noexcept;
        static ICESocketSessionPtr convert(ForICESocketPtr session) noexcept;

      public:
        ~ICESocketSession() noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // ICESocketSession => IICESocketSession
        //

        static ElementPtr toDebug(IICESocketSessionPtr socket) noexcept;

        static ICESocketSessionPtr create(
                                          IICESocketSessionDelegatePtr delegate,
                                          IICESocketPtr socket,
                                          const char *remoteUsernameFrag,
                                          const char *remotePassword,
                                          const CandidateList &remoteCandidates,
                                          ICEControls control,
                                          IICESocketSessionPtr foundation = IICESocketSessionPtr()
                                          ) noexcept;

        virtual PUID getID() const noexcept {return mID;}

        virtual IICESocketSessionSubscriptionPtr subscribe(IICESocketSessionDelegatePtr delegate) noexcept;

        virtual IICESocketPtr getSocket() noexcept;

        virtual ICESocketSessionStates getState(
                                                WORD *outLastErrorCode = NULL,
                                                String *outLastErrorReason = NULL
                                                ) const noexcept;

        virtual void close() noexcept;

        virtual String getLocalUsernameFrag() const noexcept;
        virtual String getLocalPassword() const noexcept;
        virtual String getRemoteUsernameFrag() const noexcept;
        virtual String getRemotePassword() const noexcept;

        virtual void getLocalCandidates(CandidateList &outCandidates) noexcept;
        virtual void updateRemoteCandidates(const CandidateList &remoteCandidates) noexcept;
        virtual void endOfRemoteCandidates() noexcept;

        virtual void setKeepAliveProperties(
                                            Milliseconds sendKeepAliveIndications,
                                            Milliseconds expectSTUNOrDataWithinWithinOrSendAliveCheck = Milliseconds(),
                                            Milliseconds keepAliveSTUNRequestTimeout = Milliseconds(),
                                            Milliseconds backgroundingTimeout = Milliseconds()
                                            ) noexcept;

        virtual bool sendPacket(
                                const BYTE *packet,
                                size_t packetLengthInBytes
                                ) noexcept;

        virtual ICEControls getConnectedControlState() noexcept;

        virtual IPAddress getConnectedRemoteIP() noexcept;

        virtual bool getNominatedCandidateInformation(
                                                      Candidate &outLocal,
                                                      Candidate &outRemote
                                                      ) noexcept;

        //---------------------------------------------------------------------
        //
        // ICESocketSession => IICESocketSessionForICESocket
        //

        // (duplicate) virtual PUID getID() const;
        // (duplicate) virtual void close();

        // (duplicate) virtual void updateRemoteCandidates(const CandidateList &remoteCandidates);

        virtual bool handleSTUNPacket(
                                      const IICESocket::Candidate &viaLocalCandidate,
                                      const IPAddress &source,
                                      STUNPacketPtr stun,
                                      const String &localUsernameFrag,
                                      const String &remoteUsernameFrag
                                      ) noexcept;
        virtual bool handlePacket(
                                  const IICESocket::Candidate &viaLocalCandidate,
                                  const IPAddress &source,
                                  const BYTE *packet,
                                  size_t packetLengthInBytes
                                  ) noexcept;

        virtual void notifyLocalWriteReady(const IICESocket::Candidate &viaLocalCandidate) noexcept;
        virtual void notifyRelayWriteReady(const IICESocket::Candidate &viaLocalCandidate) noexcept;

        //---------------------------------------------------------------------
        //
        // ICESocketSession => IWakeDelegate
        //

        virtual void onWake();

        //---------------------------------------------------------------------
        //
        // ICESocketSession => IICESocketDelegate
        //

        virtual void onICESocketStateChanged(
                                             IICESocketPtr socket,
                                             ICESocketStates state
                                             );
        virtual void onICESocketCandidatesChanged(IICESocketPtr socket);

        //---------------------------------------------------------------------
        //
        // ICESocketSession => ISTUNRequesterDelegate
        //

        virtual void onSTUNRequesterSendPacket(
                                               ISTUNRequesterPtr requester,
                                               IPAddress destination,
                                               SecureByteBlockPtr packet
                                               );

        virtual bool handleSTUNRequesterResponse(
                                                 ISTUNRequesterPtr requester,
                                                 IPAddress fromIPAddress,
                                                 STUNPacketPtr response
                                                 ) noexcept;

        virtual void onSTUNRequesterTimedOut(ISTUNRequesterPtr requester);

        //---------------------------------------------------------------------
        //
        // ICESocketSession => ITimerDelegate
        //

        virtual void onTimer(ITimerPtr timer);

        //---------------------------------------------------------------------
        //
        // ICESocketSession => IBackgroundingDelegate
        //

        virtual void onBackgroundingGoingToBackground(
                                                      IBackgroundingSubscriptionPtr subscription,
                                                      IBackgroundingNotifierPtr notifier
                                                      );

        virtual void onBackgroundingGoingToBackgroundNow(IBackgroundingSubscriptionPtr subscription);

        virtual void onBackgroundingReturningFromBackground(IBackgroundingSubscriptionPtr subscription);

        virtual void onBackgroundingApplicationWillQuit(IBackgroundingSubscriptionPtr subscription);

      protected:
        //---------------------------------------------------------------------
        //
        // ICESocketSession => (internal)
        //

        Log::Params log(const char *message) const noexcept;
        Log::Params debug(const char *message) const noexcept;

        void fix(STUNPacketPtr stun) const noexcept;

        virtual ElementPtr toDebug() const noexcept;

        bool isShutdown() const noexcept {return ICESocketSessionState_Shutdown == mCurrentState;}

        void cancel() noexcept;
        void setState(ICESocketSessionStates state) noexcept;
        void setError(WORD errorCode, const char *inReason = NULL) noexcept;

        void step() noexcept;
        bool stepSocket() noexcept;
        bool stepCandidates() noexcept;
        bool stepActivateTimer() noexcept;
        bool stepEndSearch() noexcept;
        bool stepTimer() noexcept;
        bool stepExpectingDataTimer() noexcept;
        bool stepKeepAliveTimer() noexcept;
        bool stepCancelLowerPriority() noexcept;
        bool stepNominate() noexcept;
        void stepNotifyNominated() noexcept;

        void switchRole(ICEControls newRole) noexcept;

        bool sendTo(
                    const IICESocket::Candidate &viaLocalCandidate,
                    const IPAddress &destination,
                    const BYTE *buffer,
                    size_t bufferLengthInBytes,
                    bool isUserData
                    ) noexcept;

        bool canUnfreeze(CandidatePairPtr derivedPairing) noexcept;
        void sendKeepAliveNow() noexcept;
        void sendAliveCheckRequest() noexcept;

        void clearBackgroundingNotifierIfPossible() noexcept;
        void clearAliveCheckRequester() noexcept {if (mAliveCheckRequester) { mAliveCheckRequester->cancel(); mAliveCheckRequester.reset(); mBackgroundingNotifier.reset(); } clearBackgroundingNotifierIfPossible();}
        void clearNominateRequester() noexcept   {if (mNominateRequester) { mNominateRequester->cancel(); mNominateRequester.reset(); mBackgroundingNotifier.reset(); } clearBackgroundingNotifierIfPossible();}

      protected:
        //---------------------------------------------------------------------
        //
        // ICESocketSession => (data)
        //

        AutoPUID mID;
        ICESocketSessionWeakPtr mThisWeak;
        UseICESocketWeakPtr mICESocket;

        ICESocketSessionStates mCurrentState;
        WORD mLastError {};
        String mLastErrorReason;

        IICESocketSessionDelegateSubscriptions mSubscriptions;
        IICESocketSessionSubscriptionPtr mDefaultSubscription;

        IBackgroundingSubscriptionPtr mBackgroundingSubscription;
        IBackgroundingNotifierPtr mBackgroundingNotifier;

        bool mInformedWriteReady {};

        IICESocketSubscriptionPtr mSocketSubscription;

        ICESocketSessionPtr mFoundation;

        String mLocalUsernameFrag;
        String mLocalPassword;
        String mRemoteUsernameFrag;
        String mRemotePassword;

        ITimerPtr mActivateTimer;
        ITimerPtr mKeepAliveTimer;
        ITimerPtr mExpectingDataTimer;
        ITimerPtr mStepTimer;

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
        Milliseconds mKeepAliveDuration {};
        Milliseconds mExpectSTUNOrDataWithinDuration {};
        Milliseconds mKeepAliveSTUNRequestTimeout {};
        Milliseconds mBackgroundingTimeout {};

        CandidatePairList mCandidatePairs;

        CandidateList mUpdatedLocalCandidates;
        CandidateList mUpdatedRemoteCandidates;

        CandidateList mLocalCandidates;
        CandidateList mRemoteCandidates;
        bool mEndOfRemoteCandidatesFlag {};
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IICESocketSessionFactory
      //

      interaction IICESocketSessionFactory
      {
        typedef IICESocket::CandidateList CandidateList;
        typedef IICESocketSession::ICEControls ICEControls;

        static IICESocketSessionFactory &singleton() noexcept;

        virtual ICESocketSessionPtr create(
                                           IICESocketSessionDelegatePtr delegate,
                                           IICESocketPtr socket,
                                           const char *remoteUsernameFrag,
                                           const char *remotePassword,
                                           const CandidateList &remoteCandidates,
                                           ICEControls control,
                                           IICESocketSessionPtr foundation = IICESocketSessionPtr()
                                           ) noexcept;
      };

      class ICESocketSessionFactory : public IFactory<IICESocketSessionFactory> {};

    }
  }
}
