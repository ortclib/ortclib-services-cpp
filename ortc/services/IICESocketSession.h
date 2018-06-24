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
#include <ortc/services/IICESocket.h>
#include <ortc/services/IHTTP.h>

#include <zsLib/types.h>
#include <zsLib/IPAddress.h>
#include <zsLib/Proxy.h>

namespace ortc
{
  namespace services
  {
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //
    // IICESocketSession
    //

    interaction IICESocketSession
    {
      typedef IICESocket::Candidate Candidate;
      typedef IICESocket::CandidateList CandidateList;
      typedef IICESocket::Types Types;
      typedef IICESocket::ICEControls ICEControls;

      enum ICESocketSessionStates
      {
        ICESocketSessionState_Pending,
        ICESocketSessionState_Prepared,
        ICESocketSessionState_Searching,
        ICESocketSessionState_Haulted,
        ICESocketSessionState_Nominating,
        ICESocketSessionState_Nominated,
        ICESocketSessionState_Completed,
        ICESocketSessionState_Shutdown,
      };

      static const char *toString(ICESocketSessionStates state) noexcept;

      enum ICESocketSessionShutdownReasons
      {
        ICESocketSessionShutdownReason_None                   = IHTTP::HTTPStatusCode_None,
        ICESocketSessionShutdownReason_BackgroundingTimeout   = IHTTP::HTTPStatusCode_Networkconnecttimeouterror,
        ICESocketSessionShutdownReason_CandidateSearchFailed  = IHTTP::HTTPStatusCode_NotFound,
      };

      static const char *toString(ICESocketSessionShutdownReasons reason) noexcept;

      static ElementPtr toDebug(IICESocketSessionPtr session) noexcept;

      //-----------------------------------------------------------------------
      // PURPOSE: Create a peer to peer connected session when the remote
      //          candidates are already known.
      static IICESocketSessionPtr create(
                                         IICESocketSessionDelegatePtr delegate,
                                         IICESocketPtr socket,
                                         const char *remoteUsernameFrag,
                                         const char *remotePassword,
                                         const CandidateList &remoteCandidates,
                                         ICEControls control,
                                         IICESocketSessionPtr foundation = IICESocketSessionPtr()
                                         ) noexcept;

      virtual PUID getID() const noexcept = 0;

      virtual IICESocketSessionSubscriptionPtr subscribe(IICESocketSessionDelegatePtr delegate) noexcept = 0;

      virtual IICESocketPtr getSocket() noexcept = 0;

      virtual ICESocketSessionStates getState(
                                              WORD *outLastErrorCode = NULL,
                                              String *outLastErrorReason = NULL
                                              ) const noexcept = 0;

      virtual void close() noexcept = 0;

      virtual String getLocalUsernameFrag() const noexcept = 0;
      virtual String getLocalPassword() const noexcept = 0;
      virtual String getRemoteUsernameFrag() const noexcept = 0;
      virtual String getRemotePassword() const noexcept = 0;

      virtual void getLocalCandidates(CandidateList &outCandidates) noexcept = 0;
      virtual void updateRemoteCandidates(const CandidateList &remoteCandidates) noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Calling this method will cause the ICE connection to shutdown
      //          when all ICE candidate searches are exhausted.
      virtual void endOfRemoteCandidates() noexcept = 0;

      virtual void setKeepAliveProperties(
                                          Milliseconds sendKeepAliveIndications,
                                          Milliseconds expectSTUNOrDataWithinWithinOrSendAliveCheck = Milliseconds(),
                                          Milliseconds keepAliveSTUNRequestTimeout = Milliseconds(),
                                          Milliseconds backgroundingTimeout = Milliseconds()
                                          ) noexcept = 0;

      virtual bool sendPacket(
                              const BYTE *packet,
                              size_t packetLengthInBytes
                              ) noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Although each ICE session starts off as being in a particular
      //          controlling state, the state can change due to an unintended
      //          conflict between which side is actually controlling. This
      //          yields the current (or final) controlling state of the
      //          connection.
      virtual ICEControls getConnectedControlState() noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Once the connection is established, the remote IP of the
      //          current destination address will be known.
      virtual IPAddress getConnectedRemoteIP() noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: When a connection is established, the nominated connection
      //          information will become known at that time.
      // RETURNS: true if a connected pair is nominated currently, otherwise
      //          false. If false the information in the out results is not
      //          valid or usable data.
      virtual bool getNominatedCandidateInformation(
                                                    Candidate &outLocal,
                                                    Candidate &outRemote
                                                    ) noexcept = 0;
    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //
    // IICESocketSessionDelegate
    //

    interaction IICESocketSessionDelegate
    {
      typedef services::IICESocketSessionPtr IICESocketSessionPtr;
      typedef services::STUNPacketPtr STUNPacketPtr;
      typedef IICESocketSession::ICESocketSessionStates ICESocketSessionStates;

      virtual void onICESocketSessionStateChanged(
                                                  IICESocketSessionPtr session,
                                                  ICESocketSessionStates state
                                                  ) = 0;

      virtual void onICESocketSessionNominationChanged(IICESocketSessionPtr session) = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Pushes a received packet to the delegate to be processed
      //          immediately upon receipt.
      virtual void handleICESocketSessionReceivedPacket(
                                                        IICESocketSessionPtr session,
                                                        const BYTE *buffer,
                                                        size_t bufferLengthInBytes
                                                        ) noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Allows the delegate to handle an incoming STUN packet that
      //          was not meant for the ICE socket.
      virtual bool handleICESocketSessionReceivedSTUNPacket(
                                                            IICESocketSessionPtr session,
                                                            STUNPacketPtr stun,
                                                            const String &localUsernameFrag,
                                                            const String &remoteUsernameFrag
                                                            ) noexcept = 0;

      virtual void onICESocketSessionWriteReady(IICESocketSessionPtr session) = 0;
    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //
    // IICESocketSessionSubscription
    //

    interaction IICESocketSessionSubscription
    {
      virtual PUID getID() const noexcept = 0;

      virtual void cancel() noexcept = 0;

      virtual void background() noexcept = 0;
    };
  }
}

ZS_DECLARE_PROXY_BEGIN(ortc::services::IICESocketSessionDelegate)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::IICESocketSessionPtr, IICESocketSessionPtr)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::STUNPacketPtr, STUNPacketPtr)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::IICESocketSessionDelegate::ICESocketSessionStates, ICESocketSessionStates)
ZS_DECLARE_PROXY_METHOD(onICESocketSessionStateChanged, IICESocketSessionPtr, ortc::services::IICESocketSessionDelegate::ICESocketSessionStates)
ZS_DECLARE_PROXY_METHOD(onICESocketSessionNominationChanged, IICESocketSessionPtr)
ZS_DECLARE_PROXY_METHOD_SYNC(handleICESocketSessionReceivedPacket, IICESocketSessionPtr, const BYTE *, size_t)
ZS_DECLARE_PROXY_METHOD_SYNC_RETURN(handleICESocketSessionReceivedSTUNPacket, bool, IICESocketSessionPtr, STUNPacketPtr, const String &, const String &)
ZS_DECLARE_PROXY_METHOD(onICESocketSessionWriteReady, ortc::services::IICESocketSessionPtr)
ZS_DECLARE_PROXY_END()

ZS_DECLARE_PROXY_SUBSCRIPTIONS_BEGIN(ortc::services::IICESocketSessionDelegate, ortc::services::IICESocketSessionSubscription)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(ortc::services::IICESocketSessionPtr, IICESocketSessionPtr)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(ortc::services::STUNPacketPtr, STUNPacketPtr)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(ortc::services::IICESocketSession::ICESocketSessionStates, ICESocketSessionStates)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD(onICESocketSessionStateChanged, IICESocketSessionPtr, ICESocketSessionStates)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD(onICESocketSessionNominationChanged, IICESocketSessionPtr)

#ifndef ZS_DECLARE_TEMPLATE_GENERATE_IMPLEMENTATION

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

#else // ndef ZS_DECLARE_TEMPLATE_GENERATE_IMPLEMENTATION
  // notify each subscription of the received packet
  void handleICESocketSessionReceivedPacket(
                                            IICESocketSessionPtr session,
                                            const BYTE *buffer,
                                            size_t bufferLengthInBytes
                                            ) noexcept override
  {
    ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_TYPES_AND_VALUES(UseSubscriptionsMap, subscriptions, UseSubscriptionsMapKeyType, UseDelegatePtr, UseDelegateProxy)
    for (UseSubscriptionsMap::iterator iter_doNotUse = subscriptions.begin(); iter_doNotUse != subscriptions.end(); )
    {
      UseSubscriptionsMap::iterator current = iter_doNotUse; ++iter_doNotUse;
      ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_ITERATOR_VALUES(current, key, subscriptionWeak, delegate)
      try {
        delegate->handleICESocketSessionReceivedPacket(session, buffer, bufferLengthInBytes);
      } catch(UseDelegateProxy::Exceptions::DelegateGone &) {
        ZS_INTERNAL_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_ERASE_KEY(key)
      }
    }
  }

  // notify each subscription of the received stun packet until one claims to handle the packet
  bool handleICESocketSessionReceivedSTUNPacket(
                                                IICESocketSessionPtr session,
                                                STUNPacketPtr stun,
                                                const String &localUsernameFrag,
                                                const String &remoteUsernameFrag
                                                ) noexcept override
  {
    ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_TYPES_AND_VALUES(UseSubscriptionsMap, subscriptions, UseSubscriptionsMapKeyType, UseDelegatePtr, UseDelegateProxy)
    for (UseSubscriptionsMap::iterator iter_doNotUse = subscriptions.begin(); iter_doNotUse != subscriptions.end(); )
    {
      UseSubscriptionsMap::iterator current = iter_doNotUse; ++iter_doNotUse;
      ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_ITERATOR_VALUES(current, key, subscriptionWeak, delegate)
      try {
        if (delegate->handleICESocketSessionReceivedSTUNPacket(session, stun, localUsernameFrag, remoteUsernameFrag))
          return true;
      } catch(UseDelegateProxy::Exceptions::DelegateGone &) {
        ZS_INTERNAL_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_ERASE_KEY(key)
      }
    }
    return false;
  }
#endif //ndef ZS_DECLARE_TEMPLATE_GENERATE_IMPLEMENTATION

ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD(onICESocketSessionWriteReady, IICESocketSessionPtr)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_END()
