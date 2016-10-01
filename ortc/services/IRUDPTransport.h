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
#include <ortc/services/IICESocketSession.h>

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
    #pragma mark
    #pragma mark IRUDPTransport
    #pragma mark

    interaction IRUDPTransport
    {
      enum RUDPTransportStates
      {
        RUDPTransportState_Pending,
        RUDPTransportState_Ready,
        RUDPTransportState_ShuttingDown,
        RUDPTransportState_Shutdown,
      };

      static const char *toString(RUDPTransportStates state);

      static ElementPtr toDebug(IRUDPTransportPtr session);

      static IRUDPTransportPtr listen(
                                      IMessageQueuePtr queue,
                                      IICESocketSessionPtr iceSession,
                                      IRUDPTransportDelegatePtr delegate
                                      );

      virtual PUID getID() const = 0;

      virtual IRUDPTransportSubscriptionPtr subscribe(IRUDPTransportDelegatePtr delegate) = 0;

      virtual RUDPTransportStates getState(
                                           WORD *outLastErrorCode = NULL,
                                           String *outLastErrorReason = NULL
                                           ) const = 0;

      virtual void shutdown() = 0;

      virtual IICESocketSessionPtr getICESession() const = 0;

      // NOTE: Will return NULL if no channel can be open at this time.
      virtual IRUDPChannelPtr openChannel(
                                          IRUDPChannelDelegatePtr delegate,
                                          const char *connectionInfo,
                                          ITransportStreamPtr receiveStream,
                                          ITransportStreamPtr sendStream
                                          ) = 0;

      // NOTE: Will return NULL if no channel can be accepted at this time.
      virtual IRUDPChannelPtr acceptChannel(
                                            IRUDPChannelDelegatePtr delegate,
                                            ITransportStreamPtr receiveStream,
                                            ITransportStreamPtr sendStream
                                            ) = 0;
    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IRUDPTransportDelegate
    #pragma mark

    interaction IRUDPTransportDelegate
    {
      typedef services::IRUDPTransportPtr IRUDPTransportPtr;
      typedef IRUDPTransport::RUDPTransportStates RUDPTransportStates;

      virtual void onRUDPTransportStateChanged(
                                               IRUDPTransportPtr session,
                                               RUDPTransportStates state
                                               ) = 0;

      virtual void onRUDPTransportChannelWaiting(IRUDPTransportPtr session) = 0;
    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IRUDPTransportSubscription
    #pragma mark

    interaction IRUDPTransportSubscription
    {
      virtual PUID getID() const = 0;

      virtual void cancel() = 0;

      virtual void background() = 0;
    };
  }
}

ZS_DECLARE_PROXY_BEGIN(ortc::services::IRUDPTransportDelegate)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::IRUDPTransportPtr, IRUDPTransportPtr)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::IRUDPTransportDelegate::RUDPTransportStates, RUDPTransportStates)
ZS_DECLARE_PROXY_METHOD_2(onRUDPTransportStateChanged, IRUDPTransportPtr, RUDPTransportStates)
ZS_DECLARE_PROXY_METHOD_1(onRUDPTransportChannelWaiting, IRUDPTransportPtr)
ZS_DECLARE_PROXY_END()


ZS_DECLARE_PROXY_SUBSCRIPTIONS_BEGIN(ortc::services::IRUDPTransportDelegate, ortc::services::IRUDPTransportSubscription)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(ortc::services::IRUDPTransportPtr, IRUDPTransportPtr)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(ortc::services::IRUDPTransport::RUDPTransportStates, RUDPTransportStates)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_2(onRUDPTransportStateChanged, IRUDPTransportPtr, RUDPTransportStates)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_1(onRUDPTransportChannelWaiting, IRUDPTransportPtr)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_END()
