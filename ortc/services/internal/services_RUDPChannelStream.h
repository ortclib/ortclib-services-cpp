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
#include <ortc/services/internal/services_IRUDPChannelStream.h>

#include <ortc/services/ITransportStream.h>

#include <zsLib/ITimer.h>
#include <zsLib/Exception.h>

#include <map>
#include <list>

#pragma warning(push)
#pragma warning(disable:4290)

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
      // IRUDPChannelStreamAsync
      //

      interaction IRUDPChannelStreamAsync
      {
        virtual void onSendNow() = 0;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // RUDPChannelStream
      //

      class RUDPChannelStream : public Noop,
                                public MessageQueueAssociator,
                                public IRUDPChannelStream,
                                public ITimerDelegate,
                                public IRUDPChannelStreamAsync,
                                public ITransportStreamReaderDelegate
      {
      protected:
        struct make_private {};

      public:
        friend interaction IRUDPChannelStreamFactory;
        friend interaction IRUDPChannelStream;

        ZS_DECLARE_STRUCT_PTR(BufferedPacket)

        typedef std::map<QWORD, BufferedPacketPtr> BufferedPacketMap;

        struct Exceptions
        {
          ZS_DECLARE_CUSTOM_EXCEPTION(IllegalACK)
        };

      public:
        RUDPChannelStream(
                          const make_private &,
                          IMessageQueuePtr queue,
                          IRUDPChannelStreamDelegatePtr delegate,
                          QWORD nextSequenceNumberToUseForSending,
                          QWORD nextSequenberNumberExpectingToReceive,
                          WORD sendingChannelNumber,
                          WORD receivingChannelNumber,
                          DWORD minimumNegotiatedRTTInMilliseconds
                          )noexcept;

      protected:
        RUDPChannelStream(Noop) noexcept : Noop(true), MessageQueueAssociator(IMessageQueuePtr()) {};

        void init() noexcept;

      public:
        ~RUDPChannelStream() noexcept;

        static RUDPChannelStreamPtr convert(IRUDPChannelStreamPtr socket) noexcept;

      protected:

        //---------------------------------------------------------------------
        //
        // RUDPChannelStream => IRUDPChannelStream
        //

        static ElementPtr toDebug(IRUDPChannelStreamPtr stream) noexcept;

        static RUDPChannelStreamPtr create(
                                           IMessageQueuePtr queue,
                                           IRUDPChannelStreamDelegatePtr delegate,
                                           QWORD nextSequenceNumberToUseForSending,
                                           QWORD nextSequenberNumberExpectingToReceive,
                                           WORD sendingChannelNumber,
                                           WORD receivingChannelNumber,
                                           DWORD minimumNegotiatedRTTInMilliseconds
                                           ) noexcept;

        PUID getID() const noexcept override {return mID;}

        RUDPChannelStreamStates getState(
                                         WORD *outLastErrorCode = NULL,
                                         String *outLastErrorReason = NULL
                                         ) const noexcept override;

        void setStreams(
                        ITransportStreamPtr receiveStream,
                        ITransportStreamPtr sendStream
                        ) noexcept override;

        void shutdown(bool shutdownOnlyOnceAllDataSent = false) noexcept override;

        void shutdownDirection(Shutdown state) noexcept override;

        void holdSendingUntilReceiveSequenceNumber(QWORD sequenceNumber) noexcept override;

        bool handlePacket(
                          RUDPPacketPtr packet,
                          SecureByteBlockPtr originalBuffer,
                          bool ecnMarked
                          ) noexcept override;

        void notifySocketWriteReady() noexcept override;

        void handleExternalAck(
                               PUID guarenteedDeliveryRequestID,
                               QWORD nextSequenceNumber,
                               QWORD greatestSequenceNumberReceived,
                               QWORD greatestSequenceNumberFullyReceived,
                               const BYTE *externalVector,
                               size_t externalVectorLengthInBytes,
                               bool vpFlag,
                               bool pgFlag,
                               bool xpFlag,
                               bool dpFlag,
                               bool ecFlag
                               ) noexcept override;

        void getState(
                      QWORD &nextSequenceNumber,
                      QWORD &greatestSequenceNumberReceived,
                      QWORD &greatestSequenceNumberFullyReceived,
                      BYTE *outVector,
                      size_t &outVectorSizeInBytes,
                      size_t maxVectorSizeInBytes,
                      bool &outVPFlag,
                      bool &outPGFlag,
                      bool &outXPFlag,
                      bool &outDPFlag,
                      bool &outECFlag
                      ) noexcept override;

        void notifyExternalACKSent(QWORD ackedSequenceNumber) noexcept override;

        //---------------------------------------------------------------------
        //
        // RUDPChannelStream => ITimerDelegate
        //

        void onTimer(ITimerPtr timer) override;

        //---------------------------------------------------------------------
        //
        // RUDPChannelStream => IRUDPChannelStreamAsync
        //

        void onSendNow() override;

        //---------------------------------------------------------------------
        //
        // RUDPChannelStream => ITransportStreamReaderDelegate
        //

        void onTransportStreamReaderReady(ITransportStreamReaderPtr reader) override;

      protected:
        //---------------------------------------------------------------------
        //
        // RUDPChannelStream => (internal)
        //

        Log::Params log(const char *message) const noexcept;
        Log::Params debug(const char *message) const noexcept;

        bool isShuttingDown() noexcept {return RUDPChannelStreamState_ShuttingDown == mCurrentState;}
        bool isShutdown() noexcept {return RUDPChannelStreamState_Shutdown == mCurrentState;}

        virtual ElementPtr toDebug() const noexcept;

        void cancel() noexcept;
        void setState(RUDPChannelStreamStates state) noexcept;
        void setError(WORD errorCode, const char *inReason = NULL) noexcept;

        bool sendNowHelper(
                           IRUDPChannelStreamDelegatePtr &delegate,
                           const BYTE *buffer,
                           size_t packetLengthInBytes
                           ) noexcept;
        bool sendNow() noexcept;   // returns true if new packets were sent that weren't sent before
        void sendNowCleanup() noexcept;
        void handleAck(
                       QWORD outNextSequenceNumber,
                       QWORD outGreatestSequenceNumberReceived,
                       QWORD outGreatestSequenceNumberFullyReceived,
                       const BYTE *outVector,
                       size_t vectorLengthInBytes,
                       bool vpFlag,
                       bool pgFlag,
                       bool xpFlag,
                       bool dpFlag,
                       bool ecFlag
                       ) noexcept(false); // throws Exceptions::IllegalACK

        void handleECN() noexcept;
        void handleDuplicate() noexcept;
        void handlePacketLoss() noexcept;
        void handleUnfreezing() noexcept;

        void deliverReadPackets() noexcept;
        size_t getFromWriteBuffer(
                                  BYTE *outBuffer,
                                  size_t maxFillSize
                                  ) noexcept;

        bool getRandomFlag() noexcept;

        void closeOnAllDataSent() noexcept;

      public:
        //---------------------------------------------------------------------
        //
        // RUDPChannelStream::BufferedPacket
        //

        struct BufferedPacket
        {
          static BufferedPacketPtr create() noexcept;

          void flagAsReceivedByRemoteParty(
                                           ULONG &ioTotalPacketsToResend,
                                           ULONG &ioAvailableBatons
                                           ) noexcept;

          void flagForResending(ULONG &ioTotalPacketsToResend) noexcept;
          void doNotResend(ULONG &ioTotalPacketsToResend) noexcept;

          void consumeBaton(ULONG &ioAvailableBatons) noexcept;
          void releaseBaton(ULONG &ioAvailableBatons) noexcept;

          QWORD mSequenceNumber;

          Time mTimeSentOrReceived;

          RUDPPacketPtr mRUDPPacket;
          SecureByteBlockPtr mPacket;

          // used for sending packets
          bool mXORedParityToNow;               // only used on buffered packets being sent over the wire to keep track of the current parity state to "this" packet

          bool mHoldsBaton;                     // this packet holds a baton
          bool mFlaggedAsFailedToReceive;       // this packet was flagged that it was never received by the remote party (only flagged once)
          bool mFlagForResendingInNextBurst;    // this packet needs to be resent at the next possible burst window
        };

      protected:
        //---------------------------------------------------------------------
        //
        // RUDPChannelStream => (data)
        //

        mutable RecursiveLock mLock;

        AutoPUID mID;
        RUDPChannelStreamWeakPtr mThisWeak;

        IRUDPChannelStreamDelegatePtr mDelegate;

        RUDPChannelStreamStates mCurrentState {RUDPChannelStreamState_Connected};
        WORD mLastError {};
        String mLastErrorReason;

        ITransportStreamWriterPtr mReceiveStream;
        ITransportStreamReaderPtr mSendStream;

        ITransportStreamReaderSubscriptionPtr mSendStreamSubscription;

        ByteQueuePtr mPendingReceiveData;

        bool mDidReceiveWriteReady {true};

        WORD mSendingChannelNumber;
        WORD mReceivingChannelNumber;

        Milliseconds mMinimumRTT {};
        Milliseconds mCalculatedRTT {};
        QWORD mNextSequenceNumber {};     // next sequence number to use for sending
        bool mXORedParityToNow {};        // the current parity of all packets sent to this point

        QWORD mGSNR;                      // Greatest Sequence Number Received (this is the remote party's sequence number)
        QWORD mGSNFR;                     // Greatest Sequence Number Fully Received (this is the remote party's sequence number)
        bool mGSNRParity {};              // This is the parity bit from the remote party
        bool mXORedParityToGSNFR {};      // what is the combined parity of packets received up to the GSNFR from the remote party

        QWORD mWaitToSendUntilReceivedRemoteSequenceNumber {};

        Shutdown mShutdownState {IRUDPChannel::Shutdown_None};

        bool mDuplicateReceived {};
        bool mECNReceived {};

        Time mLastDeliveredReadData;

        bool mAttemptingSendNow {};

        BufferedPacketMap mSendingPackets;
        BufferedPacketMap mReceivedPackets;

        size_t mRandomPoolPos {};
        BYTE mRandomPool[256];

        ULONG mTotalPacketsToResend {};

        // congestion control parameters
        ULONG mAvailableBurstBatons {1};                         // how many "batons" (aka relay style batons) are available for sending new bursts right now

        ITimerPtr mBurstTimer;                                   // this timer will be used to consume the available batons until they are gone (the timer will be cancelled when there is no more available batons or there is no more data to send)

        // If there is no burst timer and no "batons" available then when this
        // timer fires an external ACK must be delivered to ensure that data
        // has in fact been delivered to the other side.
        ITimerPtr mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer;

        ITimerPtr mAddToAvailableBurstBatonsTimer;               // add to the batons available when this timer fires (this timer is only active as long as there is data to send)
        Milliseconds mAddToAvailableBurstBatonsDuation {};      // every time there is new congestion this duration is doubled

        ULONG mPacketsPerBurst;                                 // how many packets to deliver in a single burst

        bool mBandwidthIncreaseFrozen {};                       // the bandwidth increase routine is currently frozen because an insufficient time without issues has not occurerd
        Time mStartedSendingAtTime;                             // when did the sending activate again (so when the final ACK comes in the total duration can be calculated)
        Milliseconds mTotalSendingPeriodWithoutIssues {};       // how long has there been a successful period of sending without and sending difficulties

        QWORD mForceACKOfSentPacketsAtSendingSequnceNumber {};  // when the ACK reply comes back we can be sure of the state of lost packets up to this sequence number
        PUID mForceACKOfSentPacketsRequestID {};                // the identification of the request that is causing the force
        bool mForceACKNextTimePossible {};                      // force an ACK at the next possibel interval
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IRUDPChannelStreamFactory
      //

      interaction IRUDPChannelStreamFactory
      {
        static IRUDPChannelStreamFactory &singleton() noexcept;

        virtual RUDPChannelStreamPtr create(
                                            IMessageQueuePtr queue,
                                            IRUDPChannelStreamDelegatePtr delegate,
                                            QWORD nextSequenceNumberToUseForSending,
                                            QWORD nextSequenberNumberExpectingToReceive,
                                            WORD sendingChannelNumber,
                                            WORD receivingChannelNumber,
                                            DWORD minimumNegotiatedRTTInMilliseconds
                                            ) noexcept;
      };

      class RUDPChannelStreamFactory : public IFactory<IRUDPChannelStreamFactory> {};

    }
  }
}

ZS_DECLARE_PROXY_BEGIN(ortc::services::internal::IRUDPChannelStreamAsync)
ZS_DECLARE_PROXY_METHOD(onSendNow)
ZS_DECLARE_PROXY_END()

#pragma warning(pop)
