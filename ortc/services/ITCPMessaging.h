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
#include <ortc/services/ITransportStream.h>

#include <zsLib/IPAddress.h>

#define ORTC_SERVICES_ITCPMESSAGING_MAX_MESSAGE_SIZE_IN_BYTES (0xFFFFF)

#define ORTC_SERVICES_CLOSE_LINGER_TIMER_IN_MILLISECONDS (1000)

namespace ortc
{
  namespace services
  {

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //
    // ITCPMessaging
    //

    interaction ITCPMessaging
    {
      ZS_DECLARE_STRUCT_PTR(ChannelHeader)

      enum SessionStates
      {
        SessionState_Pending,
        SessionState_Connected,
        SessionState_ShuttingDown,
        SessionState_Shutdown
      };

      static const char *toString(SessionStates state) noexcept;

      struct ChannelHeader : public ITransportStream::StreamHeader
      {
        ChannelHeader() noexcept : mChannelID(0) {}
        virtual ~ChannelHeader() noexcept {}

        static ChannelHeaderPtr convert(ITransportStream::StreamHeaderPtr header) noexcept;

        DWORD mChannelID;
      };

      static ElementPtr toDebug(ITCPMessagingPtr messaging) noexcept;

      //-----------------------------------------------------------------------
      // PURPOSE: Creates a messaging object from an socket listener by accepting
      //          the socket and processing it.
      // NOTE:    Will return NULL if the accept failed to open (i.e. the
      //          accepted channel closed before the accept was called).
      static ITCPMessagingPtr accept(
                                     ITCPMessagingDelegatePtr delegate,
                                     ITransportStreamPtr receiveStream,
                                     ITransportStreamPtr sendStream,
                                     bool messagesHaveChannelNumber,
                                     SocketPtr socket,
                                     size_t maxMessageSizeInBytes = ORTC_SERVICES_ITCPMESSAGING_MAX_MESSAGE_SIZE_IN_BYTES
                                     ) noexcept;

      //-----------------------------------------------------------------------
      // PURPOSE: Creates a messaging object by connecting to a remote IP
      //          by issuing TCP connect sequence.
      static ITCPMessagingPtr connect(
                                      ITCPMessagingDelegatePtr delegate,
                                      ITransportStreamPtr receiveStream,
                                      ITransportStreamPtr sendStream,
                                      bool messagesHaveChannelNumber,
                                      IPAddress remoteIP,
                                      size_t maxMessageSizeInBytes = ORTC_SERVICES_ITCPMESSAGING_MAX_MESSAGE_SIZE_IN_BYTES
                                      ) noexcept;

      virtual PUID getID() const noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: enable TCP keep alives
      virtual void enableKeepAlive(bool enable = true) noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: subscribe to class events
      virtual ITCPMessagingSubscriptionPtr subscribe(ITCPMessagingDelegatePtr delegate) noexcept = 0;  // passing in IMessageLayerSecurityChannelDelegatePtr() will return the default subscription

      //-----------------------------------------------------------------------
      // PURPOSE: This closes the session gracefully.
      virtual void shutdown(Milliseconds lingerTime = Milliseconds(ORTC_SERVICES_CLOSE_LINGER_TIMER_IN_MILLISECONDS)) noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: return the current state of the connection
      virtual SessionStates getState(
                                     WORD *outLastErrorCode = NULL,
                                     String *outLastErrorReason = NULL
                                     ) const noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Gets the IP address of the remotely connected socket
      virtual IPAddress getRemoteIP() const noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Set the maximum size of a message expecting to receive
      virtual void setMaxMessageSizeInBytes(size_t maxMessageSizeInBytes) noexcept = 0;
    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //
    // ITCPMessagingDelegate
    //

    interaction ITCPMessagingDelegate
    {
      typedef ITCPMessaging::SessionStates SessionStates;

      virtual void onTCPMessagingStateChanged(
                                              ITCPMessagingPtr messaging,
                                              SessionStates state
                                              ) = 0;
    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //
    // ITCPMessagingSubscription
    //

    interaction ITCPMessagingSubscription
    {
      virtual PUID getID() const noexcept = 0;

      virtual void cancel() noexcept = 0;

      virtual void background() noexcept = 0;
    };
  }
}

ZS_DECLARE_PROXY_BEGIN(ortc::services::ITCPMessagingDelegate)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::ITCPMessagingPtr, ITCPMessagingPtr)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::ITCPMessagingDelegate::SessionStates, SessionStates)
ZS_DECLARE_PROXY_METHOD(onTCPMessagingStateChanged, ITCPMessagingPtr, SessionStates)
ZS_DECLARE_PROXY_END()

ZS_DECLARE_PROXY_SUBSCRIPTIONS_BEGIN(ortc::services::ITCPMessagingDelegate, ortc::services::ITCPMessagingSubscription)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(ortc::services::ITCPMessagingPtr, ITCPMessagingPtr)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(ortc::services::ITCPMessagingDelegate::SessionStates, SessionStates)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD(onTCPMessagingStateChanged, ITCPMessagingPtr, SessionStates)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_END()
