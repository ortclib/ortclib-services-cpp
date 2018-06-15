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

#include <ortc/services/ITCPMessaging.h>
#include <ortc/services/IBackgrounding.h>
#include <ortc/services/internal/types.h>

#include <zsLib/Socket.h>
#include <zsLib/ITimer.h>

#include <list>
#include <map>

#define ORTC_SERVICES_SETTING_TCPMESSAGING_BACKGROUNDING_PHASE "ortc/services/backgrounding-phase-tcp-messaging"

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
      // TCPMessaging
      //

      class TCPMessaging : public Noop,
                           public zsLib::MessageQueueAssociator,
                           public ITCPMessaging,
                           public ITransportStreamReaderDelegate,
                           public ISocketDelegate,
                           public ITimerDelegate,
                           public IBackgroundingDelegate
      {
      protected:
        struct make_private {};

      public:
        friend interaction ITCPMessagingFactory;
        friend interaction ITCPMessaging;

      public:
        TCPMessaging(
                     const make_private &,
                     IMessageQueuePtr queue,
                     ITCPMessagingDelegatePtr delegate,
                     ITransportStreamPtr receiveStream,
                     ITransportStreamPtr sendStream,
                     bool framesHaveChannelNumber,
                     size_t maxMessageSizeInBytes = ORTC_SERVICES_ITCPMESSAGING_MAX_MESSAGE_SIZE_IN_BYTES
                     ) noexcept;

      protected:
        TCPMessaging(Noop) noexcept :
          Noop(true),
          zsLib::MessageQueueAssociator(IMessageQueuePtr()) {}

        void init() noexcept;

      public:
        ~TCPMessaging() noexcept;

        static TCPMessagingPtr convert(ITCPMessagingPtr messaging) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // TCPMessaging => ITCPMessaging
        //

        static ElementPtr toDebug(ITCPMessagingPtr messaging) noexcept;

        static TCPMessagingPtr accept(
                                      ITCPMessagingDelegatePtr delegate,
                                      ITransportStreamPtr receiveStream,
                                      ITransportStreamPtr sendStream,
                                      bool framesHaveChannelNumber,
                                      SocketPtr socket,
                                      size_t maxMessageSizeInBytes = ORTC_SERVICES_ITCPMESSAGING_MAX_MESSAGE_SIZE_IN_BYTES
                                      ) noexcept;

        static TCPMessagingPtr connect(
                                       ITCPMessagingDelegatePtr delegate,
                                       ITransportStreamPtr receiveStream,
                                       ITransportStreamPtr sendStream,
                                       bool framesHaveChannelNumber,
                                       IPAddress remoteIP,
                                       size_t maxMessageSizeInBytes = ORTC_SERVICES_ITCPMESSAGING_MAX_MESSAGE_SIZE_IN_BYTES
                                       ) noexcept;

        PUID getID() const noexcept override {return mID;}

        ITCPMessagingSubscriptionPtr subscribe(ITCPMessagingDelegatePtr delegate) noexcept override;

        void enableKeepAlive(bool enable = true) noexcept override;

        void shutdown(Milliseconds lingerTime = Milliseconds(ORTC_SERVICES_CLOSE_LINGER_TIMER_IN_MILLISECONDS)) noexcept override;

        SessionStates getState(
                               WORD *outLastErrorCode = NULL,
                               String *outLastErrorReason = NULL
                               ) const noexcept override;

        IPAddress getRemoteIP() const noexcept override;

        void setMaxMessageSizeInBytes(size_t maxMessageSizeInBytes) noexcept override;

        //---------------------------------------------------------------------
        //
        // TCPMessaging => ITransportStreamReaderDelegate
        //

        void onTransportStreamReaderReady(ITransportStreamReaderPtr reader) override;

        //---------------------------------------------------------------------
        //
        // TCPMessaging => ISocketDelegate
        //

        void onReadReady(SocketPtr socket) override;
        void onWriteReady(SocketPtr socket) override;
        void onException(SocketPtr socket) override;

        //---------------------------------------------------------------------
        //
        // TCPMessaging => ITimerDelegate
        //

        void onTimer(ITimerPtr timer) override;

        //---------------------------------------------------------------------
        //
        // TCPMessaging => IBackgroundingDelegate
        //

        void onBackgroundingGoingToBackground(
                                              IBackgroundingSubscriptionPtr subscription,
                                              IBackgroundingNotifierPtr notifier
                                              ) override {}

        void onBackgroundingGoingToBackgroundNow(IBackgroundingSubscriptionPtr subscription) override {}

        void onBackgroundingReturningFromBackground(IBackgroundingSubscriptionPtr subscription) override;

        void onBackgroundingApplicationWillQuit(IBackgroundingSubscriptionPtr subscription) override {}

      protected:
        //---------------------------------------------------------------------
        //
        // TCPMessaging => (internal)
        //

        bool isShuttingdown() const noexcept {return SessionState_ShuttingDown == mCurrentState;}
        bool isShutdown() const noexcept {return SessionState_Shutdown == mCurrentState;}

        RecursiveLock &getLock() const noexcept;
        Log::Params log(const char *message) const noexcept;
        Log::Params debug(const char *message) const noexcept;

        virtual ElementPtr toDebug() const noexcept;

        void setState(SessionStates state) noexcept;
        void setError(WORD errorCode, const char *inReason = NULL) noexcept;

        void cancel() noexcept;
        void sendDataNow() noexcept;
        bool sendQueuedData(size_t &outSent) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // TCPMessaging => (data)
        //

        AutoPUID mID;
        mutable RecursiveLock mLock;
        TCPMessagingWeakPtr mThisWeak;
        TCPMessagingPtr mGracefulShutdownReference;

        ITCPMessagingDelegateSubscriptions mSubscriptions;
        ITCPMessagingSubscriptionPtr mDefaultSubscription;

        IBackgroundingSubscriptionPtr mBackgroundingSubscription;

        SessionStates mCurrentState;

        WORD mLastError {};
        String mLastErrorReason;

        ITransportStreamWriterPtr mReceiveStream;
        ITransportStreamReaderPtr mSendStream;
        ITransportStreamReaderSubscriptionPtr mSendStreamSubscription;

        bool mFramesHaveChannelNumber;
        size_t mMaxMessageSizeInBytes;

        bool mConnectIssued {};
        bool mTCPWriteReady {};
        IPAddress mRemoteIP;
        SocketPtr mSocket;
        ITimerPtr mLingerTimer;

        ByteQueuePtr mSendingQueue;
        ByteQueuePtr mReceivingQueue;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // ITCPMessagingFactory
      //

      interaction ITCPMessagingFactory
      {
        static ITCPMessagingFactory &singleton() noexcept;

        virtual TCPMessagingPtr accept(
                                       ITCPMessagingDelegatePtr delegate,
                                       ITransportStreamPtr receiveStream,
                                       ITransportStreamPtr sendStream,
                                       bool framesHaveChannelNumber,
                                       SocketPtr socket,
                                       size_t maxMessageSizeInBytes = ORTC_SERVICES_ITCPMESSAGING_MAX_MESSAGE_SIZE_IN_BYTES
                                       ) noexcept;

        virtual TCPMessagingPtr connect(
                                        ITCPMessagingDelegatePtr delegate,
                                        ITransportStreamPtr receiveStream,
                                        ITransportStreamPtr sendStream,
                                        bool framesHaveChannelNumber,
                                        IPAddress remoteIP,
                                        size_t maxMessageSizeInBytes = ORTC_SERVICES_ITCPMESSAGING_MAX_MESSAGE_SIZE_IN_BYTES
                                        ) noexcept;
      };

      class TCPMessagingFactory : public IFactory<ITCPMessagingFactory> {};
      
    }
  }
}
