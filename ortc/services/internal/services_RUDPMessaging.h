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

#include <ortc/services/IRUDPMessaging.h>
#include <ortc/services/IRUDPChannel.h>
#include <ortc/services/ITransportStream.h>

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
      // RUDPMessaging
      //

      class RUDPMessaging : public Noop,
                            public MessageQueueAssociator,
                            public IRUDPMessaging,
                            public IRUDPChannelDelegate,
                            public ITransportStreamWriterDelegate,
                            public ITransportStreamReaderDelegate
      {
      protected:
        struct make_private {};

      public:
        friend interaction IRUDPMessagingFactory;
        friend interaction IRUDPMessaging;
        
      public:
        RUDPMessaging(
                      const make_private &,
                      IMessageQueuePtr queue,
                      IRUDPMessagingDelegatePtr delegate,
                      ITransportStreamPtr receiveStream,
                      ITransportStreamPtr sendStream,
                      size_t maxMessageSizeInBytes
                     ) noexcept;

      protected:
        RUDPMessaging(Noop) noexcept : Noop(true), MessageQueueAssociator(IMessageQueuePtr()) {};

        void init() noexcept;

      public:
        ~RUDPMessaging() noexcept;

        static RUDPMessagingPtr convert(IRUDPMessagingPtr socket) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // RUDPMessaging => IRUDPMessaging
        //

        static ElementPtr toDebug(IRUDPMessagingPtr messaging) noexcept;

        static RUDPMessagingPtr acceptChannel(
                                              IMessageQueuePtr queue,
                                              IRUDPListenerPtr listener,
                                              IRUDPMessagingDelegatePtr delegate,
                                              ITransportStreamPtr receiveStream,
                                              ITransportStreamPtr sendStream,
                                              size_t maxMessageSizeInBytes
                                              ) noexcept;

        static RUDPMessagingPtr acceptChannel(
                                              IMessageQueuePtr queue,
                                              IRUDPTransportPtr session,
                                              IRUDPMessagingDelegatePtr delegate,
                                              ITransportStreamPtr receiveStream,
                                              ITransportStreamPtr sendStream,
                                              size_t maxMessageSizeInBytes
                                              ) noexcept;

        static RUDPMessagingPtr openChannel(
                                            IMessageQueuePtr queue,
                                            IRUDPTransportPtr session,
                                            IRUDPMessagingDelegatePtr delegate,
                                            const char *connectionInfo,
                                            ITransportStreamPtr receiveStream,
                                            ITransportStreamPtr sendStream,
                                            size_t maxMessageSizeInBytes
                                            ) noexcept;

        PUID getID() const noexcept override {return mID;}

        RUDPMessagingStates getState(
                                     WORD *outLastErrorCode = NULL,
                                     String *outLastErrorReason = NULL
                                     ) const noexcept override;

        void shutdown() noexcept override;

        void shutdownDirection(Shutdown state) noexcept override;

        void setMaxMessageSizeInBytes(size_t maxMessageSizeInBytes) noexcept override;

        IPAddress getConnectedRemoteIP() noexcept override;

        String getRemoteConnectionInfo() noexcept override;

        //---------------------------------------------------------------------
        //
        // RUDPMessaging => IRUDPChannelDelegate
        //

        void onRDUPChannelStateChanged(
                                               IRUDPChannelPtr session,
                                               RUDPChannelStates state
                                               ) override;

        //---------------------------------------------------------------------
        //
        // RUDPMessaging => ITransportStreamWriterDelegate
        //

        void onTransportStreamWriterReady(ITransportStreamWriterPtr reader) override;

        //---------------------------------------------------------------------
        //
        // RUDPMessaging => ITransportStreamReaderDelegate
        //

        void onTransportStreamReaderReady(ITransportStreamReaderPtr reader) override;

      protected:
        //---------------------------------------------------------------------
        //
        // RUDPMessaging => (internal)
        //

        bool isShuttingDown() const noexcept {return RUDPMessagingState_ShuttingDown == mCurrentState;}
        bool isShutdown() const noexcept {return RUDPMessagingState_Shutdown == mCurrentState;}

        Log::Params log(const char *message) const noexcept;
        Log::Params debug(const char *message) const noexcept;

        virtual ElementPtr toDebug() const noexcept;

        void step() noexcept;
        bool stepSendData() noexcept;
        bool stepReceiveData() noexcept;

        void cancel() noexcept;
        void setState(RUDPMessagingStates state) noexcept;
        void setError(WORD errorCode, const char *inReason = NULL) noexcept;

        IRUDPChannelPtr getChannel() const noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // RUDPMessaging => (data)
        //

        AutoPUID mID;
        mutable RecursiveLock mLock;
        RUDPMessagingWeakPtr mThisWeak;

        RUDPMessagingStates mCurrentState {RUDPMessagingState_Connecting};
        WORD mLastError {};
        String mLastErrorReason;

        IRUDPMessagingDelegatePtr mDelegate;

        ITransportStreamWriterPtr mOuterReceiveStream;
        ITransportStreamReaderPtr mOuterSendStream;

        ITransportStreamReaderPtr mWireReceiveStream;
        ITransportStreamWriterPtr mWireSendStream;

        ITransportStreamWriterSubscriptionPtr mOuterReceiveStreamSubscription;
        ITransportStreamReaderSubscriptionPtr mOuterSendStreamSubscription;

        ITransportStreamReaderSubscriptionPtr mWireReceiveStreamSubscription;
        ITransportStreamWriterSubscriptionPtr mWireSendStreamSubscription;

        bool mInformedOuterReceiveReady {};
        bool mInformedWireSendReady {};

        RUDPMessagingPtr mGracefulShutdownReference;

        IRUDPChannelPtr mChannel;

        size_t mMaxMessageSizeInBytes;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IRUDPMessagingFactory
      //

      interaction IRUDPMessagingFactory
      {
        static IRUDPMessagingFactory &singleton() noexcept;

        virtual RUDPMessagingPtr acceptChannel(
                                               IMessageQueuePtr queue,
                                               IRUDPListenerPtr listener,
                                               IRUDPMessagingDelegatePtr delegate,
                                               ITransportStreamPtr receiveStream,
                                               ITransportStreamPtr sendStream,
                                               size_t maxMessageSizeInBytes
                                               ) noexcept;

        virtual RUDPMessagingPtr acceptChannel(
                                               IMessageQueuePtr queue,
                                               IRUDPTransportPtr session,
                                               IRUDPMessagingDelegatePtr delegate,
                                               ITransportStreamPtr receiveStream,
                                               ITransportStreamPtr sendStream,
                                               size_t maxMessageSizeInBytes
                                               ) noexcept;

        virtual RUDPMessagingPtr openChannel(
                                             IMessageQueuePtr queue,
                                             IRUDPTransportPtr session,
                                             IRUDPMessagingDelegatePtr delegate,
                                             const char *connectionInfo,
                                             ITransportStreamPtr receiveStream,
                                             ITransportStreamPtr sendStream,
                                             size_t maxMessageSizeInBytes
                                             ) noexcept;
      };

      class RUDPMessagingFactory : public IFactory<IRUDPMessagingFactory> {};
      
    }
  }
}
