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

#include <ortc/services/types.h>
#include <ortc/services/IDNS.h>

#include <zsLib/types.h>
#include <zsLib/IPAddress.h>
#include <zsLib/Proxy.h>

#include <list>

#define ORTC_SERVICES_IICESOCKET_DEFAULT_HOW_LONG_CANDIDATES_MUST_REMAIN_VALID_IN_SECONDS (10*60)

namespace ortc
{
  namespace services
  {
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //
    // IICESocket
    //

    interaction IICESocket
    {
      ZS_DECLARE_STRUCT_PTR(Candidate)
      ZS_DECLARE_STRUCT_PTR(TURNServerInfo)
      ZS_DECLARE_STRUCT_PTR(STUNServerInfo)

      enum ICESocketStates
      {
        ICESocketState_Pending,
        ICESocketState_Ready,
        ICESocketState_GoingToSleep,
        ICESocketState_Sleeping,
        ICESocketState_ShuttingDown,
        ICESocketState_Shutdown,
      };

      static const char *toString(ICESocketStates state) noexcept;

      enum Types
      {
        Type_Unknown =          1,
        Type_Local =            126,
        Type_ServerReflexive =  100,
        Type_PeerReflexive =    50,
        Type_Relayed =          0,
      };

      static const char *toString(Types type) noexcept;

      struct Candidate
      {
        Types     mType;
        String    mFoundation;
        WORD      mComponentID;
        IPAddress mIPAddress;
        DWORD     mPriority;
        WORD      mLocalPreference;  // fill with "0" if unknown

        IPAddress mRelatedIP;         // if server reflexive, peer reflexive or relayed, the related base IP

        static CandidatePtr create() noexcept;
        Candidate() noexcept : mType(Type_Unknown), mComponentID(0), mPriority(0), mLocalPreference(0) {}
        bool hasData() const noexcept;
        ElementPtr toDebug() const noexcept;
      };

      typedef std::list<Candidate> CandidateList;
      static void compare(
                          const CandidateList &inOldCandidatesList,
                          const CandidateList &inNewCandidatesList,
                          CandidateList &outAddedCandidates,
                          CandidateList &outRemovedCandidates
                          ) noexcept;

      enum ICEControls
      {
        ICEControl_Controlling,
        ICEControl_Controlled,
      };

      struct TURNServerInfo
      {
        String mTURNServer;
        String mTURNServerUsername;
        String mTURNServerPassword;
        IDNS::SRVResultPtr mSRVTURNServerUDP;
        IDNS::SRVResultPtr mSRVTURNServerTCP;

        static TURNServerInfoPtr create() noexcept;
        bool hasData() const noexcept;
        ElementPtr toDebug() const noexcept;
      };

      struct STUNServerInfo
      {
        String mSTUNServer;
        IDNS::SRVResultPtr mSRVSTUNServerUDP;

        static STUNServerInfoPtr create() noexcept;
        bool hasData() const noexcept;
        ElementPtr toDebug() const noexcept;
      };

      typedef std::list<TURNServerInfoPtr> TURNServerInfoList;
      typedef std::list<STUNServerInfoPtr> STUNServerInfoList;

      static const char *toString(ICEControls control) noexcept;
      
      //-----------------------------------------------------------------------
      // PURPOSE: returns a debug element containing internal object state
      static ElementPtr toDebug(IICESocketPtr socket) noexcept;

      //-----------------------------------------------------------------------
      // PURPOSE: creates/binds an ICE socket
      static IICESocketPtr create(
                                  IMessageQueuePtr queue,
                                  IICESocketDelegatePtr delegate,
                                  const TURNServerInfoList &turnServers,
                                  const STUNServerInfoList &stunServers,
                                  WORD port = 0,
                                  bool firstWORDInAnyPacketWillNotConflictWithTURNChannels = false,
                                  IICESocketPtr foundationSocket = IICESocketPtr()
                                  ) noexcept;

      //-----------------------------------------------------------------------
      // PURPOSE: returns the unique object ID
      virtual PUID getID() const noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Subscribe to the current socket state.
      virtual IICESocketSubscriptionPtr subscribe(IICESocketDelegatePtr delegate) noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Gets the current state of the object
      virtual ICESocketStates getState(
                                       WORD *outLastErrorCode = NULL,
                                       String *outLastErrorReason = NULL
                                       ) const noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Gets the ICE username fragment
      virtual String getUsernameFrag() const noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Gets the ICE password
      virtual String getPassword() const noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Close the socket and cause all sessions to become closed.
      virtual void shutdown() noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Call to wakeup a potentially sleeping socket so that all
      //          local candidates are prepared.
      // NOTE:    Each an every time that local candidates are to be obtained,
      //          this method must be called first to ensure that all services
      //          are ready. For example, TURN is shutdown while not in use
      //          and it must become active otherwise the TURN candidates will
      //          not be available.
      virtual void wakeup(Milliseconds minimumTimeCandidatesMustRemainValidWhileNotUsed = Seconds(ORTC_SERVICES_IICESOCKET_DEFAULT_HOW_LONG_CANDIDATES_MUST_REMAIN_VALID_IN_SECONDS)) noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Gets a local list of offered candidates
      virtual void getLocalCandidates(
                                      CandidateList &outCandidates,
                                      String *outLocalCandidateVersion = NULL
                                      ) noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Gets the version string associated to the current set of
      //          local candidates
      // NOTE;    As the candidates are discovered or change, each newly
      //          introduced candidate causes a change in this version string.
      virtual String getLocalCandidatesVersion() const noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Enable or disable write ready notifications on all sessions
      virtual void monitorWriteReadyOnAllSessions(bool monitor = true) noexcept = 0;
    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //
    // IICESocketDelegate
    //

    interaction IICESocketDelegate
    {
      typedef services::IICESocketPtr IICESocketPtr;
      typedef IICESocket::ICESocketStates ICESocketStates;

      virtual void onICESocketStateChanged(
                                           IICESocketPtr socket,
                                           ICESocketStates state
                                           ) = 0;

      virtual void onICESocketCandidatesChanged(IICESocketPtr socket) = 0;
    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //
    // IICESocketSubscription
    //

    interaction IICESocketSubscription
    {
      virtual PUID getID() const noexcept = 0;

      virtual void cancel() noexcept = 0;

      virtual void background() noexcept = 0;
    };
    
  }
}

ZS_DECLARE_PROXY_BEGIN(ortc::services::IICESocketDelegate)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::IICESocketPtr, IICESocketPtr)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::IICESocketDelegate::ICESocketStates, ICESocketStates)
ZS_DECLARE_PROXY_METHOD(onICESocketStateChanged, IICESocketPtr, ICESocketStates)
ZS_DECLARE_PROXY_METHOD(onICESocketCandidatesChanged, IICESocketPtr)
ZS_DECLARE_PROXY_END()

ZS_DECLARE_PROXY_SUBSCRIPTIONS_BEGIN(ortc::services::IICESocketDelegate, ortc::services::IICESocketSubscription)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(ortc::services::IICESocketPtr, IICESocketPtr)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(ortc::services::IICESocketDelegate::ICESocketStates, ICESocketStates)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD(onICESocketStateChanged, IICESocketPtr, ICESocketStates)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD(onICESocketCandidatesChanged, IICESocketPtr)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_END()
