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

#include <openpeer/services/internal/services_RUDPChannelStream.h>
#include <openpeer/services/internal/services_Helper.h>

#include <openpeer/services/RUDPPacket.h>

#include <zsLib/Exception.h>
#include <zsLib/helpers.h>
#include <zsLib/Stringize.h>
#include <zsLib/XML.h>

#include <cryptopp/osrng.h>
#include <cryptopp/queue.h>

#include <algorithm>

#pragma warning(push)
#pragma warning(disable:4290)

#define OPENPEER_SERVICES_RUDP_MINIMUM_RECOMMENDED_RTT_IN_MILLISECONDS (40)
#define OPENPEER_SERVICES_RUDP_MINIMUM_BURST_TIMER_IN_MILLISECONDS (20)
#define OPENPEER_SERVICES_RUDP_DEFAULT_CALCULATE_RTT_IN_MILLISECONDS (200)

#define OPENPEER_SERVICES_MINIMUM_DATA_BUFFER_LENGTH_ALLOCATED_IN_BYTES (16*1024)
#define OPENPEER_SERVICES_MAX_RECYCLE_BUFFERS 16

#define OPENPEER_SERVICES_MAX_WINDOW_TO_NEXT_SEQUENCE_NUMBER (256)

#define OPENPEER_SERVICES_MAX_EXPAND_WINDOW_SINCE_LAST_READ_DELIVERED_IN_SECONDS (10)

#define OPENPEER_SERVICES_UNFREEZE_AFTER_SECONDS_OF_GOOD_TRANSMISSION (10)
#define OPENPEER_SERVICES_DEFAULT_PACKETS_PER_BURST (3)

//#define OPENPEER_INDUCE_FAKE_PACKET_LOSS
#define OPENPEER_INDUCE_FAKE_PACKET_LOSS_PERCENTAGE (10)


#ifdef OPENPEER_INDUCE_FAKE_PACKET_LOSS
#define WARNING_INDUCING_FAKE_PACKET_LOSS 1
#define WARNING_INDUCING_FAKE_PACKET_LOSS 2
#endif //OPENPEER_INDUCE_FAKE_PACKET_LOSS


namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services_rudp) } }

namespace openpeer
{
  namespace services
  {
    namespace internal
    {
      using services::internal::IRUDPChannelStreamPtr;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark (helpers)
      #pragma mark

      //-----------------------------------------------------------------------
      static bool logicalXOR(bool value1, bool value2) {
        return (0 != ((value1 ? 1 : 0) ^ (value2 ? 1 : 0)));
      }

      //-----------------------------------------------------------------------
      static String sequenceToString(QWORD value)
      {
        return string(value) + " (" + string(value & 0xFFFFFF) + ")";
      }
      
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IRUDPChannelStream
      #pragma mark

      //-----------------------------------------------------------------------
      const char *IRUDPChannelStream::toString(RUDPChannelStreamStates state)
      {
        switch (state) {
          case RUDPChannelStreamState_Connected:            return "Connected";
          case RUDPChannelStreamState_DirectionalShutdown:  return "Directional shutdown";
          case RUDPChannelStreamState_ShuttingDown:         return "Shutting down";
          case RUDPChannelStreamState_Shutdown:             return "Shutdown";
          default:  break;
        }
        return "UNDEFINED";
      }

      //-----------------------------------------------------------------------
      const char *IRUDPChannelStream::toString(RUDPChannelStreamShutdownReasons reason)
      {
        return IRUDPChannel::toString((IRUDPChannel::RUDPChannelShutdownReasons)reason);
      }

      //-----------------------------------------------------------------------
      void IRUDPChannelStream::getRecommendedStartValues(
                                                         QWORD &outRecommendedNextSequenceNumberForSending,
                                                         DWORD &outMinimumRecommendedRTTInMilliseconds,
                                                         CongestionAlgorithmList &outLocalAlgorithms,
                                                         CongestionAlgorithmList &outRemoteAlgoirthms
                                                         )
      {
        AutoSeededRandomPool rng;

        rng.GenerateBlock((BYTE *)(&outRecommendedNextSequenceNumberForSending), sizeof(outRecommendedNextSequenceNumberForSending));
#if UINT_MAX <= 0xFFFFFFFF
        QWORD temp = 1;
        temp = (temp << 48)-1;
        outRecommendedNextSequenceNumberForSending = (outRecommendedNextSequenceNumberForSending & temp); // can only be 48 bits maximum at the start
#else
        outRecommendedNextSequenceNumberForSending = (outRecommendedNextSequenceNumberForSending & 0xFFFFFFFFFF); // can only be 48 bits maximum at the start
#endif

        // not allowed to be "0"
        if (0 == outRecommendedNextSequenceNumberForSending)
          outRecommendedNextSequenceNumberForSending = 1;

        outMinimumRecommendedRTTInMilliseconds = OPENPEER_SERVICES_RUDP_MINIMUM_RECOMMENDED_RTT_IN_MILLISECONDS;

        outLocalAlgorithms.clear();
        outRemoteAlgoirthms.clear();

        outLocalAlgorithms.push_back(IRUDPChannel::CongestionAlgorithm_TCPLikeWindowWithSlowCreepUp);
        outRemoteAlgoirthms.push_back(IRUDPChannel::CongestionAlgorithm_TCPLikeWindowWithSlowCreepUp);
      }

      //-----------------------------------------------------------------------
      bool IRUDPChannelStream::getResponseToOfferedAlgorithms(
                                                              const CongestionAlgorithmList &offeredAlgorithmsForLocal,
                                                              const CongestionAlgorithmList &offeredAlgorithmsForRemote,
                                                              CongestionAlgorithmList &outResponseAlgorithmsForLocal,
                                                              CongestionAlgorithmList &outResponseAlgorithmsForRemote
                                                              )
      {
        CongestionAlgorithmList::const_iterator findLocal = find(offeredAlgorithmsForLocal.begin(), offeredAlgorithmsForLocal.end(), IRUDPChannel::CongestionAlgorithm_TCPLikeWindowWithSlowCreepUp);
        CongestionAlgorithmList::const_iterator findRemote = find(offeredAlgorithmsForRemote.begin(), offeredAlgorithmsForRemote.end(), IRUDPChannel::CongestionAlgorithm_TCPLikeWindowWithSlowCreepUp);
        if (offeredAlgorithmsForLocal.end() == findLocal)
          return false;
        if (offeredAlgorithmsForRemote.end() == findRemote)
          return false;

        outResponseAlgorithmsForLocal.clear();
        outResponseAlgorithmsForRemote.clear();

        // only need to select a preferred if the preferred does not match our only choice of "TCPLikeWindow" that available at this time
        if (offeredAlgorithmsForLocal.begin() != findLocal)
          outResponseAlgorithmsForLocal.push_back(IRUDPChannel::CongestionAlgorithm_TCPLikeWindowWithSlowCreepUp);

        if (offeredAlgorithmsForRemote.begin() != findRemote)
          outResponseAlgorithmsForRemote.push_back(IRUDPChannel::CongestionAlgorithm_TCPLikeWindowWithSlowCreepUp);

        return true;
      }

      //-------------------------------------------------------------------------
      ElementPtr IRUDPChannelStream::toDebug(IRUDPChannelStreamPtr stream)
      {
        return IRUDPChannelStream::toDebug(stream);
      }

      //-----------------------------------------------------------------------
      IRUDPChannelStreamPtr IRUDPChannelStream::create(
                                                       IMessageQueuePtr queue,
                                                       IRUDPChannelStreamDelegatePtr delegate,
                                                       QWORD nextSequenceNumberToUseForSending,
                                                       QWORD nextSequenberNumberExpectingToReceive,
                                                       WORD sendingChannelNumber,
                                                       WORD receivingChannelNumber,
                                                       DWORD minimumNegotiatedRTT,
                                                       CongestionAlgorithms algorithmForLocal,
                                                       CongestionAlgorithms algorithmForRemote
                                                       )
      {
        return internal::IRUDPChannelStreamFactory::singleton().create(
                                                                       queue,
                                                                       delegate,
                                                                       nextSequenceNumberToUseForSending,
                                                                       nextSequenberNumberExpectingToReceive,
                                                                       sendingChannelNumber,
                                                                       receivingChannelNumber,
                                                                       minimumNegotiatedRTT
                                                                       );
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RUDPChannelStream
      #pragma mark

      //-----------------------------------------------------------------------
      RUDPChannelStream::RUDPChannelStream(
                                           IMessageQueuePtr queue,
                                           IRUDPChannelStreamDelegatePtr delegate,
                                           QWORD nextSequenceNumberToUseForSending,
                                           QWORD nextSequenberNumberExpectingToReceive,
                                           WORD sendingChannelNumber,
                                           WORD receivingChannelNumber,
                                           DWORD minimumNegotiatedRTTInMilliseconds
                                           ) :
        MessageQueueAssociator(queue),
        mDelegate(IRUDPChannelStreamDelegateProxy::createWeak(queue, delegate)),
        mPendingReceiveData(new ByteQueue),
        mDidReceiveWriteReady(true),
        mCurrentState(RUDPChannelStreamState_Connected),
        mSendingChannelNumber(sendingChannelNumber),
        mReceivingChannelNumber(receivingChannelNumber),
        mMinimumRTT(Milliseconds(minimumNegotiatedRTTInMilliseconds)),
        mCalculatedRTT(Milliseconds(OPENPEER_SERVICES_RUDP_DEFAULT_CALCULATE_RTT_IN_MILLISECONDS)),
        mNextSequenceNumber(nextSequenceNumberToUseForSending),
        mGSNR(nextSequenberNumberExpectingToReceive-1),
        mGSNFR(nextSequenberNumberExpectingToReceive-1),
        mShutdownState(IRUDPChannel::Shutdown_None),
        mLastDeliveredReadData(zsLib::now()),
        mAvailableBurstBatons(1),
        mAddToAvailableBurstBatonsDuation(Milliseconds(OPENPEER_SERVICES_RUDP_DEFAULT_CALCULATE_RTT_IN_MILLISECONDS)),
        mPacketsPerBurst(OPENPEER_SERVICES_DEFAULT_PACKETS_PER_BURST),
        mStartedSendingAtTime(zsLib::now()),
        mTotalSendingPeriodWithoutIssues(Milliseconds(0)),
        mForceACKOfSentPacketsRequestID(0)
      {
        ZS_LOG_DETAIL(log("created"))
        if (mCalculatedRTT < mMinimumRTT)
          mCalculatedRTT = mMinimumRTT;

        CryptoPP::AutoSeededRandomPool rng;
        rng.GenerateBlock(&(mRandomPool[0]), sizeof(mRandomPool));
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::init()
      {
        AutoRecursiveLock lock(mLock);
      }

      //-----------------------------------------------------------------------
      RUDPChannelStream::~RUDPChannelStream()
      {
        if(isNoop()) return;
        
        mThisWeak.reset();
        ZS_LOG_DETAIL(log("destroyed"))
        cancel();
      }

      //-----------------------------------------------------------------------
      RUDPChannelStreamPtr RUDPChannelStream::convert(IRUDPChannelStreamPtr stream)
      {
        return dynamic_pointer_cast<RUDPChannelStream>(stream);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RUDPChannelStream => IRUDPChannelStream
      #pragma mark

      //-----------------------------------------------------------------------
      ElementPtr RUDPChannelStream::toDebug(IRUDPChannelStreamPtr stream)
      {
        if (!stream) return ElementPtr();

        RUDPChannelStreamPtr pThis = RUDPChannelStream::convert(stream);
        return pThis->toDebug();
      }

      //-----------------------------------------------------------------------
      RUDPChannelStreamPtr RUDPChannelStream::create(
                                                     IMessageQueuePtr queue,
                                                     IRUDPChannelStreamDelegatePtr delegate,
                                                     QWORD nextSequenceNumberToUseForSending,
                                                     QWORD nextSequenberNumberExpectingToReceive,
                                                     WORD sendingChannelNumber,
                                                     WORD receivingChannelNumber,
                                                     DWORD minimumNegotiatedRTT
                                                     )
      {
        RUDPChannelStreamPtr pThis(new RUDPChannelStream(
                                                         queue,
                                                         delegate,
                                                         nextSequenceNumberToUseForSending,
                                                         nextSequenberNumberExpectingToReceive,
                                                         sendingChannelNumber,
                                                         receivingChannelNumber,
                                                         minimumNegotiatedRTT
                                                         ));
        pThis->mThisWeak = pThis;
        pThis->init();
        return pThis;
      }
      
      //-----------------------------------------------------------------------
      IRUDPChannelStream::RUDPChannelStreamStates RUDPChannelStream::getState(
                                                                              WORD *outLastErrorCode,
                                                                              String *outLastErrorReason
                                                                              ) const
      {
        AutoRecursiveLock lock(mLock);
        if (outLastErrorCode) *outLastErrorCode = mLastError;
        if (outLastErrorReason) *outLastErrorReason = mLastErrorReason;
        return mCurrentState;
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::setStreams(
                                         ITransportStreamPtr receiveStream,
                                         ITransportStreamPtr sendStream
                                         )
      {
        ZS_LOG_DEBUG(log("set streams called"))

        ZS_THROW_INVALID_ARGUMENT_IF(!receiveStream)
        ZS_THROW_INVALID_ARGUMENT_IF(!sendStream)

        AutoRecursiveLock lock(mLock);

        mReceiveStream = receiveStream->getWriter();
        mSendStream = sendStream->getReader();
        mSendStream->notifyReaderReadyToRead();

        mSendStreamSubscription = mSendStream->subscribe(mThisWeak.lock());

        if (0 != (IRUDPChannel::Shutdown_Receive & mShutdownState)) {
          ZS_LOG_DEBUG(log("cancelling receive stream since that direction is shutdown"))
          mReceiveStream->cancel();
        } else {
          if (mPendingReceiveData) {
            size_t size = static_cast<size_t>(mPendingReceiveData->CurrentSize());
            if (size > 0) {
              ZS_LOG_DEBUG(log("buffered received data written to transport stream") + ZS_PARAM("size", size))

              SecureByteBlockPtr buffer(new SecureByteBlock(size));
              mPendingReceiveData->Get(buffer->BytePtr(), size);

              mReceiveStream->write(buffer);
            }
          }
        }

        mPendingReceiveData.reset();
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::shutdown(bool shutdownOnlyOnceAllDataSent)
      {
        ZS_LOG_DETAIL(log("shutdown called") + ZS_PARAM("only when data sent", shutdownOnlyOnceAllDataSent))

        if (isShutdown()) {
          ZS_LOG_DEBUG(log("shutdown called but already cancelled"))
          return;
        }

        AutoRecursiveLock lock(mLock);
        if (!shutdownOnlyOnceAllDataSent) {
          cancel();
          return;
        }

        shutdownDirection(IRUDPChannel::Shutdown_Receive);
        setState(RUDPChannelStreamState_ShuttingDown);

        closeOnAllDataSent();
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::shutdownDirection(Shutdown state)
      {
        AutoRecursiveLock lock(mLock);

        ZS_LOG_DETAIL(log("shutdown direction called") + ZS_PARAM("state", string(state)) + ZS_PARAM("existing", string(mShutdownState)))
        mShutdownState = static_cast<Shutdown>(mShutdownState | state);  // you cannot stop shutting down what has already been shutting down
        if (0 != (IRUDPChannel::Shutdown_Receive & mShutdownState)) {
          // clear out the read data entirely - effectively acts as an ignore filter on the received data
          if (mReceiveStream) {
            ZS_LOG_DEBUG(log("cancelling receive stream since that direction is shutdown"))
            mReceiveStream->cancel();
          }
        }
        if (isShutdown()) return;
        if (isShuttingDown()) return;

        setState(RUDPChannelStreamState_DirectionalShutdown);
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::holdSendingUntilReceiveSequenceNumber(QWORD sequenceNumber)
      {
        AutoRecursiveLock lock(mLock);
        ZS_LOG_DETAIL(log("hold sending until receive sequence number") + ZS_PARAM("sequence number", sequenceToString(sequenceNumber)))
        get(mWaitToSendUntilReceivedRemoteSequenceNumber) = sequenceNumber;

        if (0 == mWaitToSendUntilReceivedRemoteSequenceNumber) {
          // the hold was manually removed, try to deliver data now...
          (IRUDPChannelStreamAsyncProxy::create(mThisWeak.lock()))->onSendNow();
        }
      }

      //-----------------------------------------------------------------------
      bool RUDPChannelStream::handlePacket(
                                           RUDPPacketPtr packet,
                                           SecureByteBlockPtr originalBuffer,
                                           bool ecnMarked
                                           )
      {
        ZS_LOG_TRACE(log("handle packet called") + ZS_PARAM("size", originalBuffer->SizeInBytes()) + ZS_PARAM("ecn", ecnMarked))

        bool fireExternalACKIfNotSent = false;

        // scope: handle packet
        {
          AutoRecursiveLock lock(mLock);
          if (!mDelegate) return false;

          if (packet->mChannelNumber != mReceivingChannelNumber) {
            ZS_LOG_WARNING(Debug, log("incoming channel mismatch") + ZS_PARAM("channel", mReceivingChannelNumber) + ZS_PARAM("packet channel", packet->mChannelNumber))
            return false;
          }

          get(mECNReceived) = (mECNReceived || ecnMarked);

          QWORD sequenceNumber = packet->getSequenceNumber(mGSNR);

          // we no longer have to wait on a send once we find the correct sequence number
          if (sequenceNumber >= mWaitToSendUntilReceivedRemoteSequenceNumber)
            get(mWaitToSendUntilReceivedRemoteSequenceNumber) = 0;

          if (sequenceNumber <= mGSNFR) {
            ZS_LOG_WARNING(Debug, log("received duplicate packet") + ZS_PARAM("GSNFR", sequenceToString(mGSNFR)) + ZS_PARAM("packet sequence number", sequenceToString(sequenceNumber)))
            get(mDuplicateReceived) = true;
            return true;
          }

          // we can't process packets that are beyond the window in which we can process
          if (sequenceNumber > (mGSNR + OPENPEER_SERVICES_MAX_WINDOW_TO_NEXT_SEQUENCE_NUMBER)) {
            ZS_LOG_WARNING(Debug, log("received packet beyond allowed window") + ZS_PARAM("GSNR", sequenceToString(mGSNR)) + ZS_PARAM("packet sequence number", sequenceToString(sequenceNumber)))
            return false;
          }

          // this packet is within the window but before we accept it we will process its ack to see if it makes any sense
          try {
            handleAck(
                      sequenceNumber,
                      packet->getGSNR(mNextSequenceNumber),                     // this is the remote party's GSNR
                      packet->getGSNFR(mNextSequenceNumber),                    // this is the remote party's GSNFR
                      &(packet->mVector[0]),
                      packet->mVectorLengthInBytes,
                      packet->isFlagSet(RUDPPacket::Flag_VP_VectorParity),
                      packet->isFlagSet(RUDPPacket::Flag_PG_ParityGSNR),
                      packet->isFlagSet(RUDPPacket::Flag_XP_XORedParityToGSNFR),
                      packet->isFlagSet(RUDPPacket::Flag_DP_DuplicatePacket),
                      packet->isFlagSet(RUDPPacket::Flag_EC_ECNPacket)
                      );
          } catch(Exceptions::IllegalACK &) {
            ZS_LOG_WARNING(Debug, log("received illegal ACK") + ZS_PARAM("packet sequence number", sequenceToString(sequenceNumber)))
            setError(RUDPChannelStreamShutdownReason_IllegalStreamState, "received illegal ack");
            cancel();
            return true;
          }

          // we handled the ack now receive the data...
          BufferedPacketMap::iterator findIter = mReceivedPackets.find(sequenceNumber);
          if (findIter != mReceivedPackets.end()) {
            ZS_LOG_WARNING(Debug, log("received packet is duplicated and already exist in pending buffers thus dropping packet") + ZS_PARAM("packet sequence number", sequenceToString(sequenceNumber)))
            // we have already received and processed this packet
            get(mDuplicateReceived) = true;
            return true;
          }

          // allow any packet to be delivered between the mGSNFR to the default window size to be added to the buffer (since it helps move the window)
          if (sequenceNumber > mGSNFR+OPENPEER_SERVICES_MAX_WINDOW_TO_NEXT_SEQUENCE_NUMBER) {

            if (sequenceNumber > mGSNR) {
              Time current = zsLib::now();

              Duration maxDuration = (mCalculatedRTT * 3);
              if (maxDuration > Seconds(OPENPEER_SERVICES_MAX_EXPAND_WINDOW_SINCE_LAST_READ_DELIVERED_IN_SECONDS)) {
                // The remote party could have intentionally caused a really large
                // RTT in order to open a very large buffer window in the receiver
                // thus we have to prevent them expanding the window massively big
                // during the calculated RTT and intentionally leaving gaps with the
                // idea to overload the receivers capacity. To prevent this we will
                // calculate how many packets we actually receive during a 4 second
                // window and limit our outstanding capacity to that window.
                maxDuration = Seconds(OPENPEER_SERVICES_MAX_EXPAND_WINDOW_SINCE_LAST_READ_DELIVERED_IN_SECONDS);
              }

              // if this packet is attempting to expand the window, only allow expansion until the last delivered packet is 3xRTT old
              if ((mLastDeliveredReadData + (mCalculatedRTT * 3)) < current) {
                ZS_LOG_WARNING(Debug, log("last deliverd ready data too old and expanding window thus dropping packet") + ZS_PARAM("GSNR", sequenceToString(mGSNR)) + ZS_PARAM("packet sequence number", sequenceToString(sequenceNumber)))
                return false;
              }
            }
          }

          // put the packet in order
          BufferedPacketPtr bufferedPacket = BufferedPacket::create();
          bufferedPacket->mSequenceNumber = sequenceNumber;
          bufferedPacket->mRUDPPacket = packet;
          bufferedPacket->mPacket = originalBuffer;

          mReceivedPackets[sequenceNumber] = bufferedPacket;
          if (sequenceNumber > mGSNR) {
            mGSNR = sequenceNumber;
            get(mGSNRParity) = packet->isFlagSet(RUDPPacket::Flag_PS_ParitySending);
          }

          // if set then remote wants an ACK right away - if we are able to send data packets then we will be able to ACK the packet right now without an external ACK
          if (packet->isFlagSet(RUDPPacket::Flag_AR_ACKRequired))
            fireExternalACKIfNotSent = true;

          ZS_LOG_TRACE(log("accepting packet into window") + ZS_PARAM("packet sequence number", sequenceToString(sequenceNumber)) + ZS_PARAM("GSNR", sequenceToString(mGSNR)) + ZS_PARAM("GSNR parity", (mGSNRParity ? "on" : "off")) + ZS_PARAM("ack required", fireExternalACKIfNotSent))

          deliverReadPackets();

        } // scope

        // because we have possible new ACKs the window might have progressed, attempt to send more data now
        bool sent = sendNow();  // WARNING: this method cannot be called from within a lock
        if (sent) {
          return true;
        }
        if (!fireExternalACKIfNotSent) return true;

        AutoRecursiveLock lock(mLock);
        if (!mDelegate) return true;

        // we were unable to deliver any more data so ask to deliver an external ACK immediately
        try {
          mDelegate->onRUDPChannelStreamSendExternalACKNow(mThisWeak.lock(), false);
        } catch(IRUDPChannelStreamDelegateProxy::Exceptions::DelegateGone &) {
          setError(RUDPChannelStreamShutdownReason_DelegateGone, "delegate gone");
          cancel();
          return true;
        }
        return true;
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::notifySocketWriteReady()
      {
        ZS_LOG_TRACE(log("socket write ready called"))
        AutoRecursiveLock lock(mLock);
        if (!mDelegate) return;
        if (mDidReceiveWriteReady) return;
        mDidReceiveWriteReady = true;
        (IRUDPChannelStreamAsyncProxy::create(mThisWeak.lock()))->onSendNow();
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::handleExternalAck(
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
                                                )
      {
        ZS_LOG_TRACE(log("handle external ACK called") +
                     ZS_PARAM("forced ACK ID", mForceACKOfSentPacketsRequestID) +
                     ZS_PARAM("guarenteed delivery request ID", guarenteedDeliveryRequestID) +
                     ZS_PARAM("sequence number", sequenceToString(nextSequenceNumber)) +
                     ZS_PARAM("GSNR", sequenceToString(greatestSequenceNumberReceived)) +
                     ZS_PARAM("GSNFR", sequenceToString(greatestSequenceNumberFullyReceived)))

        AutoRecursiveLock lock(mLock);
        if (!mDelegate) {
          ZS_LOG_WARNING(Trace, log("delegate gone thus ignoring external ACK"))
          return;
        }

        if (mSendingPackets.size() < 1) {
          // cancel any forced ACK if the sending size goes down to zero
          mForceACKOfSentPacketsRequestID = 0;
        }

        if (nextSequenceNumber >= mWaitToSendUntilReceivedRemoteSequenceNumber)
          get(mWaitToSendUntilReceivedRemoteSequenceNumber) = 0;

        try {
          handleAck(
                    nextSequenceNumber,
                    greatestSequenceNumberReceived,
                    greatestSequenceNumberFullyReceived,
                    externalVector,
                    externalVectorLengthInBytes,
                    vpFlag,
                    pgFlag,
                    xpFlag,
                    dpFlag,
                    ecFlag
                    );
        } catch(Exceptions::IllegalACK &) {
          ZS_LOG_TRACE(log("received illegal ACK"))
          setError(RUDPChannelStreamShutdownReason_IllegalStreamState, "received illegal ack");
          cancel();
          return;
        }

        if ((0 != guarenteedDeliveryRequestID) &&
            (mForceACKOfSentPacketsRequestID == guarenteedDeliveryRequestID) &&
            (mSendingPackets.size() > 0)) {

          // We just received an ACK from the remote party which is the one we
          // were forcing an ACK to ensure that the packets we are trying to
          // resend get delivered.

          mForceACKOfSentPacketsRequestID = 0;
          get(mForceACKNextTimePossible) = false;

          bool firstTime = true;

          QWORD sequenceNumber = 0;
          for (BufferedPacketMap::iterator iter = mSendingPackets.begin(); iter != mSendingPackets.end(); ++iter) {
            sequenceNumber = (*iter).first;

            if (sequenceNumber > mForceACKOfSentPacketsAtSendingSequnceNumber) {
              break;
            }

            BufferedPacketPtr &packet = (*iter).second;
            if (firstTime) {
              firstTime = false;
              ZS_LOG_TRACE(log("force ACK starting to process")  +
                           ZS_PARAM("starting at ACK sequence number", sequenceToString(sequenceNumber)) +
                           ZS_PARAM("forced ACK to sequence number", sequenceToString(mForceACKOfSentPacketsAtSendingSequnceNumber)) +
                           ZS_PARAM("batons available", mAvailableBurstBatons))
            }

            packet->flagForResending(mTotalPacketsToResend);  // if this packet was not ACKed but should be resent because it never arrived after the current forced ACK replied
            packet->releaseBaton(mAvailableBurstBatons);      // reclaim the baton if holding since this packet needs to be resent and never arrived
          }

          ZS_LOG_TRACE(log("forced ACK cannot ACK beyond the forced ACK point") +
                       ZS_PARAM("stopped at ACK sequence number", sequenceToString(sequenceNumber)) +
                       ZS_PARAM("forced ACK to sequence number", sequenceToString(mForceACKOfSentPacketsAtSendingSequnceNumber)) +
                       ZS_PARAM("batons available", mAvailableBurstBatons))
        }

        if (mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer) {
          // since an ACK did arrive, we can cancel this timer which ensures an ACK will arrive
          ZS_LOG_TRACE(log("cancelling ensure data arrived timer because we did receive an ACK") + ZS_PARAM("old timer ID", mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer->getID()))
          mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer->cancel();
          mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer.reset();
        }

        (IRUDPChannelStreamAsyncProxy::create(mThisWeak.lock()))->onSendNow();
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::getState(
                                       QWORD &outNextSequenceNumber,
                                       QWORD &outGreatestSequenceNumberReceived,
                                       QWORD &outGreatestSequenceNumberFullyReceived,
                                       BYTE *outVector,
                                       size_t &outVectorSizeInBytes,
                                       size_t maxVectorSizeInBytes,
                                       bool &outVPFlag,
                                       bool &outPGFlag,
                                       bool &outXPFlag,
                                       bool &outDPFlag,
                                       bool &outECFlag
                                       )
      {
        AutoRecursiveLock lock(mLock);
        outNextSequenceNumber = mNextSequenceNumber;
        outGreatestSequenceNumberReceived = mGSNR;
        outGreatestSequenceNumberFullyReceived = mGSNFR;

        String vectorParityField;

        outVPFlag = mXORedParityToGSNFR;
        if ((outVector) &&
            (0 != maxVectorSizeInBytes)) {

          RUDPPacket::VectorEncoderState state;
          RUDPPacket::vectorEncoderStart(state, mGSNR, mGSNFR, mXORedParityToGSNFR, outVector, maxVectorSizeInBytes);

          QWORD sequenceNumber = mGSNFR+1;

          // create a vector until the vector is full or we run out of packets that we have received
          for (BufferedPacketMap::iterator iter = mReceivedPackets.begin(); iter != mReceivedPackets.end(); ++iter) {
            BufferedPacketPtr packet = (*iter).second;
            bool added = true;
            while (sequenceNumber < packet->mSequenceNumber)
            {
              added = RUDPPacket::vectorEncoderAdd(state, RUDPPacket::VectorState_NotReceived, false);
              if (!added)
                break;

              if (ZS_IS_LOGGING(Trace)) { vectorParityField += "."; }
              ++sequenceNumber;
            }
            if (!added)
              break;

            if (sequenceNumber == packet->mSequenceNumber) {
              added = RUDPPacket::vectorEncoderAdd(
                                                   state,
                                                   (packet->mRUDPPacket->isFlagSet(RUDPPacket::Flag_EC_ECNPacket) ? RUDPPacket::VectorState_ReceivedECNMarked : RUDPPacket::VectorState_Received),
                                                   packet->mRUDPPacket->isFlagSet(RUDPPacket::Flag_PS_ParitySending)
                                                   );
              if (!added)
                break;

              ++sequenceNumber;
              if (ZS_IS_LOGGING(Trace)) { vectorParityField += (packet->mRUDPPacket->isFlagSet(RUDPPacket::Flag_PS_ParitySending) ? "X" : "x"); }
            }
          }
          RUDPPacket::vectorEncoderFinalize(state, outVPFlag, outVectorSizeInBytes);
        }

        outPGFlag = mGSNRParity;
        outXPFlag = mXORedParityToGSNFR;
        outDPFlag = mDuplicateReceived;
        outECFlag = mECNReceived;

        ZS_LOG_TRACE(
                     log("get current state")
                     + ZS_PARAM("next sequence number", sequenceToString(outNextSequenceNumber))
                     + ZS_PARAM("GSNR", sequenceToString(outGreatestSequenceNumberReceived))
                     + ZS_PARAM("GSNFR", sequenceToString(outGreatestSequenceNumberFullyReceived))
                     + ZS_PARAM("vector", vectorParityField)
                     + ZS_PARAM("vector size", outVectorSizeInBytes)
                     + ZS_PARAM("vp", outVPFlag)
                     + ZS_PARAM("pg", outPGFlag)
                     + ZS_PARAM("xp", outXPFlag)
                     + ZS_PARAM("dp", outDPFlag)
                     + ZS_PARAM("ec", outECFlag)
                     )
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::notifyExternalACKSent(QWORD ackedSequenceNumber)
      {
        ZS_LOG_TRACE(log("external ACK sent"))
        AutoRecursiveLock lock(mLock);
        get(mDuplicateReceived) = false;
        get(mECNReceived) = false;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RUDPChannelStream => ITimerDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void RUDPChannelStream::onTimer(TimerPtr timer)
      {
        ZS_LOG_TRACE(log("tick") + ZS_PARAM("timer ID", timer->getID()))

        {
          AutoRecursiveLock lock(mLock);

          PUID burstID = (mBurstTimer ? mBurstTimer->getID() : 0);
          PUID ensureID = (mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer ? mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer->getID() : 0);
          PUID addID = (mAddToAvailableBurstBatonsTimer ? mAddToAvailableBurstBatonsTimer->getID() : 0);

          ZS_LOG_TRACE(log("tick") +
                       ZS_PARAM("comparing timer ID", timer->getID()) +
                       ZS_PARAM("burst ID", burstID) +
                       ZS_PARAM("ensure ID", ensureID) +
                       ZS_PARAM("addID ID", addID))

          if (timer == mBurstTimer) {
            ZS_LOG_TRACE(log("burst timer is firing") + ZS_PARAM("timer ID", timer->getID()))
            goto quickExitToSendNow;
          }

          if (timer == mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer) {
            ZS_LOG_TRACE(log("ensuring data has arrived by causing an external ACK") + ZS_PARAM("timer ID", timer->getID()))
            // this is only fired once if there is data that we want to force an ACK from the remote party
            mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer->cancel();
            mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer.reset();

            // we will use the "force" ACK mechanism to ensure that data has arrived
            get(mForceACKNextTimePossible) = true;
            goto quickExitToSendNow;
          }

          if (timer == mAddToAvailableBurstBatonsTimer) {
            ZS_LOG_TRACE(log("available burst batons timer fired") + ZS_PARAM("timer ID", timer->getID()))

            if (0 == (rand()%2)) {
              ++mAvailableBurstBatons;
              ZS_LOG_TRACE(log("creating a new sending burst baton now") + ZS_PARAM("batons available", mAvailableBurstBatons))
            } else {
              ++mPacketsPerBurst;
              ZS_LOG_TRACE(log("increasing the packets per burst") + ZS_PARAM("packets per burst", mPacketsPerBurst))
            }
            goto quickExitToSendNow;
          }

          ZS_LOG_TRACE(log("unknown time has fired") + ZS_PARAM("timer ID", timer->getID()))
        }

      quickExitToSendNow:
        sendNow();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RUDPChannelStream => IRUDPChannelStreamAsync
      #pragma mark

      //-----------------------------------------------------------------------
      void RUDPChannelStream::onSendNow()
      {
        ZS_LOG_TRACE(log("on send now called"))
        sendNow();  // do NOT call from within a lock
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RUDPChannelStream => ITransportStreamReaderDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void RUDPChannelStream::onTransportStreamReaderReady(ITransportStreamReaderPtr reader)
      {
        ZS_LOG_TRACE(log("on transport stream reader ready"))
        sendNow();  // do NOT call from within a lock
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RUDPChannelStream => (internal)
      #pragma mark

      //-----------------------------------------------------------------------
      Log::Params RUDPChannelStream::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("RUDPChannelStream");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params RUDPChannelStream::debug(const char *message) const
      {
        return Log::Params(message, toDebug());
      }

      //-----------------------------------------------------------------------
      ElementPtr RUDPChannelStream::toDebug() const
      {
        AutoRecursiveLock lock(mLock);

        ElementPtr resultEl = Element::create("RUDPChannelStream");

        IHelper::debugAppend(resultEl, "id", mID);

        IHelper::debugAppend(resultEl, "delegate", (bool)mDelegate);

        IHelper::debugAppend(resultEl, "state", IRUDPChannelStream::toString(mCurrentState));
        IHelper::debugAppend(resultEl, "last error", mLastError);
        IHelper::debugAppend(resultEl, "last reason", mLastErrorReason);

        IHelper::debugAppend(resultEl, "receive stream", (bool)mReceiveStream);
        IHelper::debugAppend(resultEl, "send stream", (bool)mSendStream);

        IHelper::debugAppend(resultEl, "send stream subscription", (bool)mSendStreamSubscription);

        IHelper::debugAppend(resultEl, "pending receive data", (bool)mPendingReceiveData);

        IHelper::debugAppend(resultEl, "did receive write ready", (bool)mDidReceiveWriteReady);

        IHelper::debugAppend(resultEl, "sending channel number", mSendingChannelNumber);
        IHelper::debugAppend(resultEl, "receiving channel number", mReceivingChannelNumber);

        IHelper::debugAppend(resultEl, "minimum RTT (ms)", mMinimumRTT);
        IHelper::debugAppend(resultEl, "calculated RTT (ms)", mCalculatedRTT);

        IHelper::debugAppend(resultEl, "next sequence number", 0 != mNextSequenceNumber ? sequenceToString(mNextSequenceNumber) : String());

        IHelper::debugAppend(resultEl, "xor parity to now", mXORedParityToNow ? "1" : "0");

        IHelper::debugAppend(resultEl, "GSNR", 0 != mGSNR ? sequenceToString(mGSNR) : String());
        IHelper::debugAppend(resultEl, "GSNFR", 0 != mGSNFR ? sequenceToString(mGSNFR) : String());

        IHelper::debugAppend(resultEl, "GSNR parity", mGSNRParity ? "1" : "0");
        IHelper::debugAppend(resultEl, "xor parity to GSNFR", mXORedParityToGSNFR ? "1" : "0");

        IHelper::debugAppend(resultEl, "wait to send until received sequence number", 0 != mWaitToSendUntilReceivedRemoteSequenceNumber ? sequenceToString(mWaitToSendUntilReceivedRemoteSequenceNumber) : String());

        IHelper::debugAppend(resultEl, "shutdown state", IRUDPChannel::toString(mShutdownState));

        IHelper::debugAppend(resultEl, "duplicate received", mDuplicateReceived);
        IHelper::debugAppend(resultEl, "ECN received", mECNReceived);

        IHelper::debugAppend(resultEl, "last delivered read data", mLastDeliveredReadData);

        IHelper::debugAppend(resultEl, "attempting send now", mAttemptingSendNow);

        IHelper::debugAppend(resultEl, "sending packets", mSendingPackets.size());
        IHelper::debugAppend(resultEl, "received packets", mReceivedPackets.size());

        IHelper::debugAppend(resultEl, "recycled buffers", mRecycleBuffers.size());

        IHelper::debugAppend(resultEl, "random pool pos", mRandomPoolPos);

        IHelper::debugAppend(resultEl, "total packets to resend", mTotalPacketsToResend);

        IHelper::debugAppend(resultEl, "available burst batons", mAvailableBurstBatons);

        IHelper::debugAppend(resultEl, "burst timer", (bool)mBurstTimer);

        IHelper::debugAppend(resultEl, "ensure data has arrived when no more burst batons available timer", (bool)mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer);

        IHelper::debugAppend(resultEl, "add to available burst batons timer", (bool)mAddToAvailableBurstBatonsTimer);
        IHelper::debugAppend(resultEl, "add to available burst batons duration (ms)", mAddToAvailableBurstBatonsDuation);

        IHelper::debugAppend(resultEl, "total packets per burst", mPacketsPerBurst);

        IHelper::debugAppend(resultEl, "bandwidth increase frozen", mBandwidthIncreaseFrozen);
        IHelper::debugAppend(resultEl, "started sending time", mStartedSendingAtTime);
        IHelper::debugAppend(resultEl, "total sending period without issues (ms)", mTotalSendingPeriodWithoutIssues);

        IHelper::debugAppend(resultEl, "force ACKs of sent packets sending sequence number", 0 != mForceACKOfSentPacketsAtSendingSequnceNumber ? sequenceToString(mForceACKOfSentPacketsAtSendingSequnceNumber) : String());
        IHelper::debugAppend(resultEl, "force ACKs of sent packets request ID", mForceACKOfSentPacketsRequestID);

        IHelper::debugAppend(resultEl, "force ACK next time possible", mForceACKNextTimePossible);

        return resultEl;
      }
      
      //-----------------------------------------------------------------------
      void RUDPChannelStream::cancel()
      {
        AutoRecursiveLock lock(mLock);          // just in case...

        if (isShutdown()) {
          ZS_LOG_DEBUG(log("cancel already complete"))
          return;
        }

        ZS_LOG_TRACE(log("cancel called"))

        setState(RUDPChannelStreamState_Shutdown);

        mDelegate.reset();

        mSendingPackets.clear();
        mReceivedPackets.clear();

        if (mReceiveStream) {
          mReceiveStream->cancel();
        }
        if (mSendStream) {
          mSendStream->cancel();
        }

        mRecycleBuffers.clear();

        if (mBurstTimer) {
          mBurstTimer->cancel();
          mBurstTimer.reset();
        }

        if (mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer) {
          mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer->cancel();
          mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer.reset();
        }

        if (mAddToAvailableBurstBatonsTimer) {
          mAddToAvailableBurstBatonsTimer->cancel();
          mAddToAvailableBurstBatonsTimer.reset();
        }

        ZS_LOG_TRACE(log("cancel complete"))
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::setState(RUDPChannelStreamStates state)
      {
        if (mCurrentState == state) return;

        ZS_LOG_DETAIL(log("state changed") + ZS_PARAM("old state", toString(mCurrentState)) + ZS_PARAM("new state", toString(state)))
        mCurrentState = state;

        RUDPChannelStreamPtr pThis = mThisWeak.lock();

        if (pThis) {
          try {
            mDelegate->onRUDPChannelStreamStateChanged(pThis, mCurrentState);
          } catch(IRUDPChannelStreamDelegateProxy::Exceptions::DelegateGone &) {
          }
        }
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::setError(WORD errorCode, const char *inReason)
      {
        String reason(inReason ? String(inReason) : String());
        if (reason.isEmpty()) {
          reason = IHTTP::toString(IHTTP::toStatusCode(errorCode));
        }

        if ((isShuttingDown()) ||
            (isShutdown())) {
          ZS_LOG_WARNING(Detail, debug("already shutting down thus ignoring new error") + ZS_PARAM("new error", errorCode) + ZS_PARAM("new reason", reason))
          return;
        }

        if (0 != mLastError) {
          ZS_LOG_WARNING(Detail, debug("error already set thus ignoring new error") + ZS_PARAM("new error", errorCode) + ZS_PARAM("new reason", reason))
          return;
        }

        get(mLastError) = errorCode;
        mLastErrorReason = reason;

        ZS_LOG_WARNING(Detail, debug("error set") + ZS_PARAM("code", mLastError) + ZS_PARAM("reason", mLastErrorReason))
      }

      //-----------------------------------------------------------------------
      bool RUDPChannelStream::sendNowHelper(
                                            IRUDPChannelStreamDelegatePtr &delegate,
                                            const BYTE *buffer,
                                            size_t packetLengthInBytes
                                            )
      {
#ifdef OPENPEER_INDUCE_FAKE_PACKET_LOSS
        bool forcePacketLoss = ((rand() % 100) < OPENPEER_INDUCE_FAKE_PACKET_LOSS_PERCENTAGE);
        if (forcePacketLoss) {
          ZS_LOG_WARNING(Trace, log("faking packet loss in deliver attempt"))
        }
        return = (forcePacketLoss ? true : (delegate->notifyRUDPChannelStreamSendPacket(mThisWeak.lock(), buffer, packetLengthInBytes)));
#else
        return delegate->notifyRUDPChannelStreamSendPacket(mThisWeak.lock(), buffer, packetLengthInBytes);
#endif //OPENPEER_INDUCE_FAKE_PACKET_LOSS
      }

      //-----------------------------------------------------------------------
      bool RUDPChannelStream::sendNow()
      {
        //*********************************************************************
        //*********************************************************************
        //                              WARNING
        //*********************************************************************
        // This method calls a delegate synchronously thus cannot be called
        // from within a lock.
        //*********************************************************************

        BufferedPacketPtr firstPacketCreated;
        BufferedPacketPtr lastPacketSent;
        IRUDPChannelStreamDelegatePtr delegate;

        //.....................................................................
        // NOTE: The unwinder is used to protect against this class from being
        //       called twice from an unlocked thread plus ensurs that
        //       the protection variable is unset in the event of a stack
        //       unwind (i.e. any quick "return" from method)
        class Unwinder
        {
        public:
          Unwinder(RecursiveLock &memberLock, bool &value) : mLock(memberLock), mValue(value), mWasSet(false) {}
          ~Unwinder() { if (!mWasSet) return; AutoRecursiveLock lock(mLock); mValue = false; }

          void set() { AutoRecursiveLock lock(mLock); mValue = true; mWasSet = true; }
        private:
          RecursiveLock &mLock;
          bool &mValue;
          bool mWasSet;
        };

        Unwinder protect(mLock, mAttemptingSendNow);

        {
          AutoRecursiveLock lock(mLock);

          ZS_LOG_TRACE(log("send now called") +
                       ZS_PARAM("available burst batons", mAvailableBurstBatons) +
                       ZS_PARAM("packets per burst", mPacketsPerBurst) +
                       ZS_PARAM("resend", mTotalPacketsToResend) +
                       ZS_PARAM("send size", mSendingPackets.size()) +
                       ZS_PARAM("write data", (mSendStream ? mSendStream->getTotalReadBuffersAvailable() : 0)))

          if (isShutdown()) {
            ZS_LOG_TRACE(log("already shutdown thus aborting send now"))
            return false;
          }
          delegate = mDelegate;

          // we cannot deliver data if we are waiting to send
          if (0 != mWaitToSendUntilReceivedRemoteSequenceNumber) {
            ZS_LOG_TRACE(log("cannot send as waiting for sequence number") + ZS_PARAM("waiting sequence number", sequenceToString(mWaitToSendUntilReceivedRemoteSequenceNumber)))
            return false;
          }

          // if the socket isn't available for writing then we cannot send data
          if (!mDidReceiveWriteReady) {
            ZS_LOG_TRACE(log("cannot send as write not ready"))
            return false;
          }

          if (mAttemptingSendNow) {
            ZS_LOG_TRACE(log("already attempting to send thus aborting"))
            return false; // already in the middle of an attempt at sending so cannot create or send more packets now
          }

          protect.set();
        }

        //.....................................................................
        //.....................................................................
        //.....................................................................
        //.....................................................................
        try {
          ULONG packetsToSend = 1;

          // scope: check out if we can send now
          {
            AutoRecursiveLock lock(mLock);
            if (0 == mAvailableBurstBatons) {
              ZS_LOG_TRACE(log("no batons for bursting available for sending data thus aborting send routine"))
              goto sendNowQuickExit;
            }

            packetsToSend = mPacketsPerBurst;
          }

          while (0 != packetsToSend)
          {
            BufferedPacketPtr attemptToDeliver;
            SecureByteBlockPtr attemptToDeliverBuffer;

            // scope: grab the next buffer to be resent over the wire
            {
              AutoRecursiveLock lock(mLock);

              if (0 != mTotalPacketsToResend) {
                BufferedPacketMap::iterator iter = mSendingPackets.begin();
                if (lastPacketSent) {
                  iter = mSendingPackets.find(lastPacketSent->mSequenceNumber);
                }
                if (iter == mSendingPackets.end()) {
                  iter = mSendingPackets.begin();
                }

                for (; iter != mSendingPackets.end(); ++iter) {
                  BufferedPacketPtr &packet = (*iter).second;
                  if (packet->mFlagForResendingInNextBurst) {
                    attemptToDeliver = packet;
                    attemptToDeliverBuffer = packet->mPacket;
                  }
                }
              }
            }

            if (!attemptToDeliver) {
              AutoRecursiveLock lock(mLock);

              // there are no packets to be resent so attempt to create a new packet to send...

              if (!mSendStream) goto sendNowQuickExit;
              if (mSendStream->getTotalReadBuffersAvailable() < 1) goto sendNowQuickExit;

              // we need to start breaking up new packets immediately that will be sent over the wire
              RUDPPacketPtr newPacket = RUDPPacket::create();
              newPacket->setSequenceNumber(mNextSequenceNumber);
              newPacket->setGSN(mGSNR, mGSNFR);
              newPacket->mChannelNumber = mSendingChannelNumber;
              newPacket->setFlag(RUDPPacket::Flag_PS_ParitySending, getRandomFlag());
              newPacket->setFlag(RUDPPacket::Flag_PG_ParityGSNR, mGSNRParity);
              newPacket->setFlag(RUDPPacket::Flag_XP_XORedParityToGSNFR, mXORedParityToGSNFR);
              newPacket->setFlag(RUDPPacket::Flag_DP_DuplicatePacket, mDuplicateReceived);
              get(mDuplicateReceived) = false;
              newPacket->setFlag(RUDPPacket::Flag_EC_ECNPacket, mECNReceived);
              get(mECNReceived) = false;

              if (!firstPacketCreated) {
                String vectorParityField; // for debugging

                // we have to create a vector now on the packet
                RUDPPacket::VectorEncoderState state;
                newPacket->vectorEncoderStart(state, mGSNR, mGSNFR, mXORedParityToGSNFR);

                QWORD sequenceNumber = mGSNFR+1;

                // create a vector until the vector is full or we run out of packets
                for (BufferedPacketMap::iterator iter = mReceivedPackets.begin(); iter != mReceivedPackets.end(); ++iter) {
                  BufferedPacketPtr packet = (*iter).second;
                  bool added = true;
                  while (sequenceNumber < packet->mSequenceNumber)
                  {
                    added = RUDPPacket::vectorEncoderAdd(state, RUDPPacket::VectorState_NotReceived, false);
                    if (!added)
                      break;

                    if (ZS_IS_LOGGING(Trace)) { vectorParityField += "."; }
                    ++sequenceNumber;
                  }
                  if (!added)
                    break;

                  if (sequenceNumber == packet->mSequenceNumber) {
                    added = RUDPPacket::vectorEncoderAdd(
                                                         state,
                                                         (packet->mRUDPPacket->isFlagSet(RUDPPacket::Flag_EC_ECNPacket) ? RUDPPacket::VectorState_ReceivedECNMarked : RUDPPacket::VectorState_Received),
                                                         packet->mRUDPPacket->isFlagSet(RUDPPacket::Flag_PS_ParitySending)
                                                         );
                    if (!added)
                      break;

                    ++sequenceNumber;
                    if (ZS_IS_LOGGING(Trace)) { vectorParityField += (packet->mRUDPPacket->isFlagSet(RUDPPacket::Flag_PS_ParitySending) ? "X" : "x"); }
                  }
                }
                newPacket->vectorEncoderFinalize(state);

                ZS_LOG_TRACE(
                             log("generating RUDP packet ACK on first packet")
                             + ZS_PARAM("sequence number", sequenceToString(mNextSequenceNumber))
                             + ZS_PARAM("GSNR", sequenceToString(mGSNR))
                             + ZS_PARAM("GSNFR", sequenceToString(mGSNFR))
                             + ZS_PARAM("vector", vectorParityField)
                             + ZS_PARAM("vector size", newPacket->mVectorLengthInBytes)
                             + ZS_PARAM("ps", newPacket->isFlagSet(RUDPPacket::Flag_PS_ParitySending))
                             + ZS_PARAM("pg", newPacket->isFlagSet(RUDPPacket::Flag_PG_ParityGSNR))
                             + ZS_PARAM("xp", newPacket->isFlagSet(RUDPPacket::Flag_XP_XORedParityToGSNFR))
                             + ZS_PARAM("dp", newPacket->isFlagSet(RUDPPacket::Flag_DP_DuplicatePacket))
                             + ZS_PARAM("ec", newPacket->isFlagSet(RUDPPacket::Flag_EC_ECNPacket))
                             + ZS_PARAM("vp", newPacket->isFlagSet(RUDPPacket::Flag_VP_VectorParity))
                             )
              } else {
                // copy the vector from the first packet
                newPacket->setFlag(RUDPPacket::Flag_VP_VectorParity, firstPacketCreated->mRUDPPacket->isFlagSet(RUDPPacket::Flag_VP_VectorParity));
                memcpy(&(newPacket->mVector[0]), &(firstPacketCreated->mRUDPPacket->mVector[0]), sizeof(newPacket->mVector));
                newPacket->mVectorLengthInBytes = firstPacketCreated->mRUDPPacket->mVectorLengthInBytes;
              }

              BYTE temp[OPENPEER_SERVICES_RUDP_MAX_PACKET_SIZE_WHEN_PMTU_IS_NOT_KNOWN];

              size_t availableBytes = newPacket->getRoomAvailableForData(OPENPEER_SERVICES_RUDP_MAX_PACKET_SIZE_WHEN_PMTU_IS_NOT_KNOWN);

              size_t bytesRead = getFromWriteBuffer(&(temp[0]), availableBytes);
              newPacket->mData = &(temp[0]);
              newPacket->mDataLengthInBytes = static_cast<decltype(newPacket->mDataLengthInBytes)>(bytesRead);

              if ((mSendStream->getTotalReadBuffersAvailable() < 1) ||
                  (1 == packetsToSend)) {
                newPacket->setFlag(RUDPPacket::Flag_AR_ACKRequired);
                if (mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer) {
                  ZS_LOG_TRACE(log("since a newly created packet has an ACK we will cancel the current ensure timer") + ZS_PARAM("timer ID", mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer->getID()))
                  // since this packet requires an ACK this packet will act as a implicit method to hopefully get an ACK from the remote party...
                  mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer->cancel();
                  mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer.reset();
                }
              }

              SecureByteBlockPtr packetizedBuffer = newPacket->packetize();
              ZS_THROW_BAD_STATE_IF(!packetizedBuffer)

              BufferedPacketPtr bufferedPacket = BufferedPacket::create();
              bufferedPacket->mSequenceNumber = mNextSequenceNumber;
              get(mXORedParityToNow) = internal::logicalXOR(mXORedParityToNow, newPacket->isFlagSet(RUDPPacket::Flag_PS_ParitySending));   // have to keep track of the current parity of all packets sent until this point
              bufferedPacket->mXORedParityToNow = mXORedParityToNow;          // when the remore party reports their GSNFR parity in an ACK, this value is required to verify it is accurate
              bufferedPacket->mRUDPPacket = newPacket;
              bufferedPacket->mPacket = packetizedBuffer;

              ZS_LOG_TRACE(
                           log("adding buffer to pending list")
                           + ZS_PARAM("sequence number", sequenceToString(mNextSequenceNumber))
                           + ZS_PARAM("packet size", packetizedBuffer->SizeInBytes())
                           + ZS_PARAM("GSNR", sequenceToString(mGSNR))
                           + ZS_PARAM("GSNFR", sequenceToString(mGSNFR))
                           + ZS_PARAM("vector size", newPacket->mVectorLengthInBytes)
                           + ZS_PARAM("ps", newPacket->isFlagSet(RUDPPacket::Flag_PS_ParitySending))
                           + ZS_PARAM("pg", newPacket->isFlagSet(RUDPPacket::Flag_PG_ParityGSNR))
                           + ZS_PARAM("xp", newPacket->isFlagSet(RUDPPacket::Flag_XP_XORedParityToGSNFR))
                           + ZS_PARAM("dp", newPacket->isFlagSet(RUDPPacket::Flag_DP_DuplicatePacket))
                           + ZS_PARAM("ec", newPacket->isFlagSet(RUDPPacket::Flag_EC_ECNPacket))
                           + ZS_PARAM("ar", newPacket->isFlagSet(RUDPPacket::Flag_AR_ACKRequired))
                           + ZS_PARAM("vp", newPacket->isFlagSet(RUDPPacket::Flag_VP_VectorParity))
                           )

              if (mSendingPackets.size() == 0) {
                // this is the starting point where we are sending packets
                mStartedSendingAtTime = zsLib::now();
              }
              mSendingPackets[mNextSequenceNumber] = bufferedPacket;

              ++mNextSequenceNumber;

              if (!firstPacketCreated) {
                // remember this as the first packet created
                firstPacketCreated = bufferedPacket;
              }

              attemptToDeliver = bufferedPacket;
              attemptToDeliverBuffer = packetizedBuffer;
            }

            if (!attemptToDeliver) {
              ZS_LOG_TRACE(log("no more packets to send at this time"))
              goto sendNowQuickExit;
            }

            ZS_LOG_TRACE(log("attempting to (re)send packet") + ZS_PARAM("sequence number", sequenceToString(attemptToDeliver->mSequenceNumber)) + ZS_PARAM("packets to send", packetsToSend))
            bool sent = sendNowHelper(delegate, *attemptToDeliverBuffer, attemptToDeliverBuffer->SizeInBytes());
            if (!sent) {
              ZS_LOG_WARNING(Trace, log("unable to send data onto wire as data failed to send") + ZS_PARAM("sequence number", sequenceToString(attemptToDeliver->mSequenceNumber)))
              if (firstPacketCreated == attemptToDeliver) {
                // failed to deliver any packet over the wire...
                firstPacketCreated.reset();
              }
              goto sendNowQuickExit;
            }

            // successfully (re)sent the packet...

            lastPacketSent = attemptToDeliver;
            --packetsToSend;  // total packets to send in the burst is now decreased

            AutoRecursiveLock lock(mLock);
            if (attemptToDeliver->mFlagForResendingInNextBurst) {
              ZS_LOG_TRACE(log("flag for resending in next burst is set this will force an ACK next time possible"))

              get(mForceACKNextTimePossible) = true;                // we need to force an ACK when there is resent data to ensure it has arrived
              attemptToDeliver->doNotResend(mTotalPacketsToResend); // if this was marked for resending, then clear it now since it is resent
            }
          }
        } catch(IRUDPChannelStreamDelegateProxy::Exceptions::DelegateGone &) {
          AutoRecursiveLock lock(mLock);
          ZS_LOG_WARNING(Trace, log("delegate gone thus cannot send packet"))
          setError(RUDPChannelStreamShutdownReason_DelegateGone, "delegate gone");
          cancel();
        }

        //----------------------------------------------------------------------
        //----------------------------------------------------------------------
        //----------------------------------------------------------------------
        //----------------------------------------------------------------------

      sendNowQuickExit:
        AutoRecursiveLock lock(mLock);
        if (lastPacketSent) {
          if (lastPacketSent->mPacket) {  // make sure the packet hasn't already been released
            // the last packet sent over the wire will hold the baton
            lastPacketSent->consumeBaton(mAvailableBurstBatons);
          }
        }
        sendNowCleanup();

        return (bool)firstPacketCreated;
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::sendNowCleanup()
      {
        ULONG writeBuffers = mSendStream ? mSendStream->getTotalReadBuffersAvailable() : 0;

        ZS_LOG_TRACE(log("starting send now cleaup routine") +
                     ZS_PARAM("packets to resend", mTotalPacketsToResend) +
                     ZS_PARAM("available batons", mAvailableBurstBatons) +
                     ZS_PARAM("packets per burst", mPacketsPerBurst) +
                     ZS_PARAM("write size", writeBuffers) +
                     ZS_PARAM("sending size", mSendingPackets.size()) +
                     ZS_PARAM("force ACK next time possible", mForceACKNextTimePossible) +
                     ZS_PARAM("force ACK ID", mForceACKOfSentPacketsRequestID) +
                     ZS_PARAM("forced sequence number", sequenceToString(mForceACKOfSentPacketsAtSendingSequnceNumber)))

        if (isShutdown()) {
          ZS_LOG_TRACE(log("already shutdown thus aborting"))
        }

        handleUnfreezing();

        bool burstTimerRequired = false;
        bool forceACKOfSentPacketsRequired = false;
        bool ensureDataHasArrivedTimer = false;
        bool addBatonsTimer = (!mBandwidthIncreaseFrozen) && (0 == mTotalPacketsToResend) && ((mSendingPackets.size() > 0) || (writeBuffers > 0));

        if (0 != mAvailableBurstBatons)
        {
          // there is available batons so the burst timer should be alive if there is data ready to send
          burstTimerRequired = ((mSendingPackets.size() > 0) && (0 != mTotalPacketsToResend)) ||
                                (writeBuffers > 0);
        }

        if (mSendingPackets.size() > 0) {
          // there is unacked sent packets in the buffer waiting for an ACK...

          // because there is unacked send data we should make sure a timer is setup to eventually ACK this data
          ensureDataHasArrivedTimer = true;

          // also we should force a new ACK if none of the
          forceACKOfSentPacketsRequired = true;

          if ((0 != mAvailableBurstBatons) &&
              (writeBuffers > 0)) {

            // but if there is available batons and write data outstanding then
            // there's no need to setup a timer to ensure the data to be acked
            // or force the data to be acked right away
            ensureDataHasArrivedTimer = false;
            forceACKOfSentPacketsRequired = mForceACKNextTimePossible;  // only required in this case if there was  request to force the ACK next time possible
          }

          if (0 != mForceACKOfSentPacketsRequestID) {
            forceACKOfSentPacketsRequired = false;  // cannot force again since there is already an outstanding request
          }

          if ((forceACKOfSentPacketsRequired) &&
              (!mForceACKNextTimePossible)) {
            // if we are forcing a packet now but not because we are required
            // to do it next time possible then we should see if there is
            // already an outstanding ACK require packet holding a baton
            // in which case we don't need to force an ACK immediately
            for (BufferedPacketMap::iterator iter = mSendingPackets.begin(); iter != mSendingPackets.end(); ++iter) {
              BufferedPacketPtr &packet = (*iter).second;

              if ((packet->mHoldsBaton) &&
                  (packet->mRUDPPacket->isFlagSet(RUDPPacket::Flag_AR_ACKRequired)) &&
                  (!packet->mFlagForResendingInNextBurst)) {
                // this packet holds a baton and is required to ACK so it's
                // possible that the ACK will eventually arrive so no need for
                // force an ACK just yet...
                forceACKOfSentPacketsRequired = false;
                break;
              }
            }
          }

          if (forceACKOfSentPacketsRequired) {
            // if an ACK is being forced to send right away then no need
            // to start a timer to eventually force an ACK since it is already
            // happening right now...
            ensureDataHasArrivedTimer = false;
          }
        }

        if (mSendingPackets.size() < 1) {
          // cancel any forced ACK if the sending size goes down to zero (since there is no longer a need to force
          ZS_LOG_TRACE(log("cleanup cancelling forced ACK since all data is now ACKed"))
          mForceACKOfSentPacketsRequestID = 0;
          forceACKOfSentPacketsRequired = false;
        }

        if ((forceACKOfSentPacketsRequired) ||
            (0 != mForceACKOfSentPacketsRequestID)) {
          // while there is an outstanding force in progress do not add to the
          // available burst batons and there is no need for the ensure data
          // has arrived timer as the forcing of the ACK will ensure this...
          addBatonsTimer = false;
          ensureDataHasArrivedTimer = false;
        }

        if (burstTimerRequired) {
          if (!mBurstTimer) {
            Duration burstDuration = mCalculatedRTT / ((int)mAvailableBurstBatons);

            // all available bursts should happen in one RTT
            mBurstTimer = Timer::create(mThisWeak.lock(), burstDuration);
            if (burstDuration < Milliseconds(OPENPEER_SERVICES_RUDP_MINIMUM_BURST_TIMER_IN_MILLISECONDS)) {
              burstDuration = Milliseconds(OPENPEER_SERVICES_RUDP_MINIMUM_BURST_TIMER_IN_MILLISECONDS);
            }

            ZS_LOG_TRACE(log("creating a burst timer since there is data to send and available batons to send it") + ZS_PARAM("timer ID", mBurstTimer->getID()) + ZS_PARAM("available batons", mAvailableBurstBatons) + ZS_PARAM("write size", writeBuffers) + ZS_PARAM("sending size", mSendingPackets.size()) + ZS_PARAM("burst duration", burstDuration.total_milliseconds()) + ZS_PARAM("calculated RTT", mCalculatedRTT.total_milliseconds()))
          }
        } else {
          if (mBurstTimer) {
            ZS_LOG_TRACE(log("cancelling the burst timer since there are no batons available or there is no more data to send") + ZS_PARAM("timer ID", mBurstTimer->getID()) + ZS_PARAM("available batons", mAvailableBurstBatons) + ZS_PARAM("write size", writeBuffers) + ZS_PARAM("sending size", mSendingPackets.size()))

            mBurstTimer->cancel();
            mBurstTimer.reset();
          }
        }

        if (ensureDataHasArrivedTimer) {
          if (!mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer) {
            Duration ensureDuration = (mCalculatedRTT*3)/2;

            // The timer is set to fire at 1.5 x calculated RTT
            mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer = Timer::create(mThisWeak.lock(), ensureDuration, false);

            ZS_LOG_TRACE(log("starting ensure timer to make sure packets get acked") + ZS_PARAM("timer ID", mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer->getID()) + ZS_PARAM("available batons", mAvailableBurstBatons) + ZS_PARAM("write size", writeBuffers) + ZS_PARAM("sending size", mSendingPackets.size()) + ZS_PARAM("ensure duration", ensureDuration.total_milliseconds()) + ZS_PARAM("calculated RTT", mCalculatedRTT.total_milliseconds()))
          }
        } else {
          if (mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer) {
            ZS_LOG_TRACE(log("stopping ensure timer as batons available for sending still and there is outstanding unacked send data in the buffer") + ZS_PARAM("timer ID", mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer->getID()) + ZS_PARAM("available batons", mAvailableBurstBatons) + ZS_PARAM("write size", writeBuffers) + ZS_PARAM("sending size", mSendingPackets.size()))
            mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer->cancel();
            mEnsureDataHasArrivedWhenNoMoreBurstBatonsAvailableTimer.reset();
          }
        }

        if (forceACKOfSentPacketsRequired) {
          mForceACKOfSentPacketsRequestID = zsLib::createPUID();
          get(mForceACKOfSentPacketsAtSendingSequnceNumber) = mNextSequenceNumber - 1;
          get(mForceACKNextTimePossible) = false;

          ZS_LOG_TRACE(log("forcing an ACK immediately") + ZS_PARAM("ack ID", mForceACKOfSentPacketsRequestID) + ZS_PARAM("forced sequence number", sequenceToString(mForceACKOfSentPacketsAtSendingSequnceNumber)) + ZS_PARAM("available batons", mAvailableBurstBatons) + ZS_PARAM("write size", writeBuffers) + ZS_PARAM("sending size", mSendingPackets.size()))

          try {
            mDelegate->onRUDPChannelStreamSendExternalACKNow(mThisWeak.lock(), true, mForceACKOfSentPacketsRequestID);
          } catch(IRUDPChannelStreamDelegateProxy::Exceptions::DelegateGone &) {
            setError(RUDPChannelStreamShutdownReason_DelegateGone, "delegate gone");
            cancel();
            return;
          }
        }

        if (addBatonsTimer) {
          if (!mAddToAvailableBurstBatonsTimer) {
            mAddToAvailableBurstBatonsTimer = Timer::create(mThisWeak.lock(), mAddToAvailableBurstBatonsDuation);
            ZS_LOG_TRACE(log("creating a new add to available batons timer") + ZS_PARAM("timer ID", mAddToAvailableBurstBatonsTimer->getID()) + ZS_PARAM("frozen", mBandwidthIncreaseFrozen) + ZS_PARAM("available batons", mAvailableBurstBatons) + ZS_PARAM("write size", writeBuffers) + ZS_PARAM("sending size", mSendingPackets.size()))
          }
        } else {
          if (mAddToAvailableBurstBatonsTimer) {
            ZS_LOG_TRACE(log("cancelling add to available batons timer") + ZS_PARAM("timer ID", mAddToAvailableBurstBatonsTimer->getID()) + ZS_PARAM("frozen", mBandwidthIncreaseFrozen) + ZS_PARAM("available batons", mAvailableBurstBatons) + ZS_PARAM("write size", writeBuffers) + ZS_PARAM("sending size", mSendingPackets.size()))
            mAddToAvailableBurstBatonsTimer->cancel();
            mAddToAvailableBurstBatonsTimer.reset();
          }
        }

        closeOnAllDataSent();

        ZS_LOG_TRACE(log("completed send now cleanup routine") +
                     ZS_PARAM("burst timer", burstTimerRequired) +
                     ZS_PARAM("ensure timer", (bool)ensureDataHasArrivedTimer) +
                     ZS_PARAM("force", forceACKOfSentPacketsRequired) +
                     ZS_PARAM("add timer", addBatonsTimer) +
                     ZS_PARAM("force ACK next time possible", mForceACKNextTimePossible) +
                     ZS_PARAM("force ACK ID", mForceACKOfSentPacketsRequestID) +
                     ZS_PARAM("forced sequence number", sequenceToString(mForceACKOfSentPacketsAtSendingSequnceNumber)))
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::handleAck(
                                        QWORD nextSequenceNumber,
                                        QWORD gsnr,
                                        QWORD gsnfr,
                                        const BYTE *externalVector,
                                        size_t externalVectorLengthInBytes,
                                        bool vpFlag,
                                        bool pgFlag,
                                        bool xpFlag,
                                        bool dpFlag,
                                        bool ecFlag
                                        ) throw(Exceptions::IllegalACK)
      {
        // scope: handle the ACK
        {
          if (ecFlag) {
            handleECN();
          }

          // nothing to ACK?
          if (0 == mSendingPackets.size()) {
            ZS_LOG_TRACE(log("ignoring incoming ACK because there is no send data to ACK"))
            goto handleAckQuickExit;
          }

          ZS_THROW_CUSTOM_IF(Exceptions::IllegalACK, gsnfr > gsnr)  // this is illegal

          // if the next sequence number being reported is before the sequence number we have already processed then don't handle the packet
          if (nextSequenceNumber < mGSNFR) {
            ZS_LOG_WARNING(Detail, log("ignoring ACK as it was for packet already processed") + ZS_PARAM("sequence number", sequenceToString(nextSequenceNumber)) + ZS_PARAM("GSNFR", sequenceToString(mGSNFR)))
            goto handleAckQuickExit;
          }

          // if the packet is too far ahead from the greatest packet received then it can't be processed
          if (nextSequenceNumber > (mGSNR + OPENPEER_SERVICES_MAX_WINDOW_TO_NEXT_SEQUENCE_NUMBER)) {
            ZS_LOG_WARNING(Detail, log("ignoring ACK as it was for packet too far outside window") + ZS_PARAM("sequence number", sequenceToString(nextSequenceNumber)) + ZS_PARAM("GSNR", sequenceToString(mGSNR)))
            goto handleAckQuickExit;
          }

          // the remote party is claiming they received a packet we never sent
          if (gsnr > mNextSequenceNumber) {
            ZS_LOG_WARNING(Detail, log("ignoring ACK as it was for a packet that was never sent") + ZS_PARAM("local next sequence number", sequenceToString(mNextSequenceNumber)) + ZS_PARAM("remote GSNR", sequenceToString(gsnr)))
            goto handleAckQuickExit;
          }

          // we still have packets that are unacked, check to see if we can ACK them

          // find the gsnfr packet
          BufferedPacketMap::iterator gsnfrIter = mSendingPackets.find(gsnfr);
          if (gsnfrIter != mSendingPackets.end()) {
            BufferedPacketPtr gsnfrPacket = (*gsnfrIter).second;

            // the parity up to now must match or there is a problem
            if (xpFlag !=  gsnfrPacket->mXORedParityToNow) {
              ZS_THROW_CUSTOM(Exceptions::IllegalACK, log("ACK on parity bit until GSNFR is not correct") + ZS_PARAM("GSNFR ACKed parity", xpFlag ? 1 : 0) + ZS_PARAM("GSNFR sent parity", gsnfrPacket->mXORedParityToNow ? 1 : 0))
            }
          }

          BufferedPacketMap::iterator gsnrIter = mSendingPackets.find(gsnr);
          if (gsnrIter != mSendingPackets.end()) {
            BufferedPacketPtr gsnrPacket = (*gsnrIter).second;

            if (gsnrPacket->mRUDPPacket->isFlagSet(RUDPPacket::Flag_AR_ACKRequired)) {

              // it might be possible to measure the RTT now, but only if this ACK was received from the first send attempt
              if (!(gsnrPacket->mFlaggedAsFailedToReceive)) {
                Duration oldRTT = mCalculatedRTT;

                mCalculatedRTT = zsLib::now() - gsnrPacket->mTimeSentOrReceived;

                // we have the new calculated time but we will only move halfway between the old calculation and the new one
                if (mCalculatedRTT > oldRTT) {
                  mCalculatedRTT = oldRTT + ((mCalculatedRTT - oldRTT) / 2);
                } else {
                  mCalculatedRTT = oldRTT - ((oldRTT - mCalculatedRTT) / 2);
                }
                if (mCalculatedRTT < mMinimumRTT)
                  mCalculatedRTT = mMinimumRTT;

                ZS_LOG_TRACE(log("calculating RTT") + ZS_PARAM("RTT milliseconds", mCalculatedRTT.total_milliseconds()))

                if (mCalculatedRTT > mAddToAvailableBurstBatonsDuation) {
                  mAddToAvailableBurstBatonsDuation = (mCalculatedRTT * 2);
                  if (mAddToAvailableBurstBatonsTimer) {
                    PUID oldTimerID = mAddToAvailableBurstBatonsTimer->getID();

                    // replace existing timer with new timer
                    mAddToAvailableBurstBatonsTimer->cancel();
                    mAddToAvailableBurstBatonsTimer.reset();

                    mAddToAvailableBurstBatonsTimer = Timer::create(mThisWeak.lock(), mAddToAvailableBurstBatonsDuation);
                    ZS_LOG_TRACE(log("add to available batons timer is set too small based on calculated RTT") + ZS_PARAM("old timer ID", oldTimerID) + ZS_PARAM("new timer ID", mAddToAvailableBurstBatonsTimer->getID()) + ZS_PARAM("duration milliseconds", mAddToAvailableBurstBatonsDuation.total_milliseconds()))
                  }
                }
              }
            }

            // make sure the parity bit of the gsnr matches the gsnfr's packet (if it doesn't then it's illegal)
            ZS_THROW_CUSTOM_IF(Exceptions::IllegalACK, pgFlag !=  gsnrPacket->mRUDPPacket->isFlagSet(RUDPPacket::Flag_PS_ParitySending))
          }

          bool hadPackets = (mSendingPackets.size() > 0);

          // we can now acknowledge and clean out all packets up-to and including the gsnfr packet
          while (0 != mSendingPackets.size()) {
            BufferedPacketPtr current = (*(mSendingPackets.begin())).second;

            // do not delete past the point of the gsnfr received
            if (current->mSequenceNumber > gsnfr) {
              break;
            }

            ZS_LOG_TRACE(log("cleaning ACKed packet") + ZS_PARAM("sequence number", sequenceToString(current->mSequenceNumber)) + ZS_PARAM("GSNFR", sequenceToString(gsnfr)))

            current->flagAsReceivedByRemoteParty(mTotalPacketsToResend, mAvailableBurstBatons);
            mSendingPackets.erase(mSendingPackets.begin());
          }

          if ((mSendingPackets.size() == 0) &&
              (hadPackets) &&
              (!ecFlag)) {
            mTotalSendingPeriodWithoutIssues = mTotalSendingPeriodWithoutIssues + (zsLib::now() - mStartedSendingAtTime);
            hadPackets = false;
          }

          // there will be no vector if these are equal
          if (gsnr == gsnfr) {
            ZS_LOG_TRACE(log("ACK packet GSNR == GSNFR thus no vector will be present") + ZS_PARAM("gsnr/gsnfr", sequenceToString(gsnr)))
            goto handleAckQuickExit;
          }

          QWORD vectorSequenceNumber = gsnfr+1;

          RUDPPacket::VectorDecoderState decoder;
          RUDPPacket::vectorDecoderStart(decoder, externalVector, externalVectorLengthInBytes, gsnr, gsnfr);

          bool xoredParity = xpFlag;
          bool foundECN = false;
          bool foundLoss = false;

          String vectorParityField;
          bool couldNotCalculateVectorParity = false;

          BufferedPacketMap::iterator iter = mSendingPackets.begin();

          while (true)
          {
            if (iter == mSendingPackets.end())
              break;

            BufferedPacketPtr bufferedPacket = (*iter).second;
            if (bufferedPacket->mSequenceNumber < vectorSequenceNumber) {
              ZS_LOG_TRACE(log("ignoring buffered packet because it doesn't exist in the vector"))
              // ignore the buffered packet since its not reached the vector yet...
              ++iter;
              continue;
            }

            RUDPPacket::VectorStates state = RUDPPacket::vectorDecoderGetNextPacketState(decoder);
            if (RUDPPacket::VectorState_NoMoreData == state)
              break;

            if (vectorSequenceNumber < bufferedPacket->mSequenceNumber) {
              if ((RUDPPacket::VectorState_Received == state) || (RUDPPacket::VectorState_ReceivedECNMarked == state)) {
                couldNotCalculateVectorParity = true;
              }

              ZS_LOG_TRACE(log("ignoring vectored packet because it doesn't exist as a buffered packet") + ZS_PARAM("could not calculate parity", couldNotCalculateVectorParity))

              // ignore the vector since its not reached the buffered packet yet
              ++vectorSequenceNumber;
              continue;
            }

            if ((RUDPPacket::VectorState_Received == state) || (RUDPPacket::VectorState_ReceivedECNMarked == state)) {
              if (ZS_IS_LOGGING(Trace)) { vectorParityField += (bufferedPacket->mRUDPPacket->isFlagSet(RUDPPacket::Flag_PS_ParitySending) ? "X" : "x"); }
              xoredParity = internal::logicalXOR(xoredParity, bufferedPacket->mRUDPPacket->isFlagSet(RUDPPacket::Flag_PS_ParitySending));

              // mark the current packet as being received by cleaning out the original packet data (but not the packet information)
              ZS_LOG_TRACE(log("marking packet as received because of vector ACK") + ZS_PARAM("sequence number", sequenceToString(bufferedPacket->mSequenceNumber)))
              bufferedPacket->flagAsReceivedByRemoteParty(mTotalPacketsToResend, mAvailableBurstBatons);
            } else {
              // this packet was not received, do not remove the packet data
              if (ZS_IS_LOGGING(Trace)) { vectorParityField += "."; }

              if (!bufferedPacket->mFlaggedAsFailedToReceive) {
                bufferedPacket->mFlaggedAsFailedToReceive = true;
                bufferedPacket->flagForResending(mTotalPacketsToResend);  // since this is the first report of this packet being lost we can be sure it needs to be resent immediately
                foundLoss = true;
              }
            }

            if (RUDPPacket::VectorState_ReceivedECNMarked == state)
              foundECN = true;

            ++iter;
            ++vectorSequenceNumber;
          }

          if (gsnrIter != mSendingPackets.end()) {
            // now it is time to mark the gsnr as received
            BufferedPacketPtr gsnrPacket = (*gsnrIter).second;
            ZS_LOG_TRACE(log("marking GSNR as received in vector case") + ZS_PARAM("sequence number", sequenceToString(gsnrPacket->mSequenceNumber)))
            gsnrPacket->flagAsReceivedByRemoteParty(mTotalPacketsToResend, mAvailableBurstBatons);
          }

          if ((mSendingPackets.size() == 0) &&
              (hadPackets) &&
              (!ecFlag)) {
            mTotalSendingPeriodWithoutIssues = mTotalSendingPeriodWithoutIssues + (zsLib::now() - mStartedSendingAtTime);
            hadPackets = false;
          }

          if (foundECN && (!ecFlag))
            handleECN();

          if (dpFlag)
            handleDuplicate();

          if (foundLoss)
            handlePacketLoss();

          ZS_LOG_TRACE(
                       log("handling ACK with values")
                       + ZS_PARAM("next sequence number", sequenceToString(nextSequenceNumber))
                       + ZS_PARAM("GSNR", sequenceToString(gsnr))
                       + ZS_PARAM("GSNFR", sequenceToString(gsnfr))
                       + ZS_PARAM("vector", vectorParityField)
                       + ZS_PARAM("vector size", externalVectorLengthInBytes)
                       + ZS_PARAM("vp", vpFlag)
                       + ZS_PARAM("pg", pgFlag)
                       + ZS_PARAM("xp", xpFlag)
                       + ZS_PARAM("dp", dpFlag)
                       + ZS_PARAM("ec", ecFlag)
                       )

          // at this point the xoredParity must match or this ACK is bogus
          if ((!couldNotCalculateVectorParity) &&
              (xoredParity !=  vpFlag)) {
            ZS_THROW_CUSTOM(Exceptions::IllegalACK, log("ACK on parity bit until GSNFR is not correct") + ZS_PARAM("vector ACKed parity", vpFlag ? 1 : 0) + ZS_PARAM("calculated vector parity", xoredParity ? 1 : 0))
          }
        }

      handleAckQuickExit:

        handleUnfreezing();

        if (mSendingPackets.size() < 1) {
          // cancel any forced ACK if the sending size goes down to zero (since there is no longer a need to force
          ZS_LOG_TRACE(log("cleanup cancelling forced ACK since all data is now ACKed"))
          mForceACKOfSentPacketsRequestID = 0;
        }
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::handleECN()
      {
        ZS_LOG_TRACE(log("handling ECN"))
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::handleDuplicate()
      {
        ZS_LOG_TRACE(log("handling duplicate"))
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::handlePacketLoss()
      {
        ZS_LOG_TRACE(log("handle packet loss"))

        bool wasFrozen = mBandwidthIncreaseFrozen;

        // freeze the increase to prevent an increase in the socket sending
        get(mBandwidthIncreaseFrozen) = true;
        mStartedSendingAtTime = zsLib::now();
        mTotalSendingPeriodWithoutIssues = Milliseconds(0);

        if (mAddToAvailableBurstBatonsTimer) {
          ZS_LOG_TRACE(log("cancelling add to available burst batons due to loss") + ZS_PARAM("timer ID", mAddToAvailableBurstBatonsTimer->getID()))
          mAddToAvailableBurstBatonsTimer->cancel();
          mAddToAvailableBurstBatonsTimer.reset();
        }

        // double the time until more batons get added
        if (!wasFrozen) {
          mAddToAvailableBurstBatonsDuation = mAddToAvailableBurstBatonsDuation * 2;
          ZS_LOG_TRACE(log("increasing add to available burst batons duration") + ZS_PARAM("duration milliseconds", mAddToAvailableBurstBatonsDuation.total_milliseconds()))
        }

        if (mPacketsPerBurst > 1) {
          // decrease the packets per burst by half
          ULONG wasPacketsPerBurst = mPacketsPerBurst;
          mPacketsPerBurst = mPacketsPerBurst / 2;
          if (mPacketsPerBurst < 1)
            mPacketsPerBurst = 1;
          ZS_LOG_TRACE(log("decreasing packets per burst") + ZS_PARAM("old value", wasPacketsPerBurst) + ZS_PARAM("new packets per burst", mPacketsPerBurst))
          return;
        }

        if (mAvailableBurstBatons > 1) {
          // decrease the available batons by one (to slow sending of more bursts)
          --mAvailableBurstBatons;
          ZS_LOG_TRACE(log("decreasing batons available") + ZS_PARAM("available batons", mAvailableBurstBatons))
          return;
        }

        // we cannot destroy the last baton available
        ULONG whichBatonToDestroy = (mAvailableBurstBatons == 0 ? 1 : 0);

        // we must destroy a baton that is pending in the sending packets
        for (BufferedPacketMap::iterator iter = mSendingPackets.begin(); iter != mSendingPackets.end(); ++iter) {
          BufferedPacketPtr &packet = (*iter).second;
          if (packet->mHoldsBaton) {
            if (0 == whichBatonToDestroy) {
              packet->releaseBaton(mAvailableBurstBatons);  // release the baton from being held by the packet
              --mAvailableBurstBatons;                      // destroy the baton
              ZS_LOG_TRACE(log("destroying a baton that was being held") + ZS_PARAM("available batons", mAvailableBurstBatons))
              return;
            }

            --whichBatonToDestroy;
          }
        }
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::handleUnfreezing()
      {
        if (mTotalSendingPeriodWithoutIssues > Seconds(OPENPEER_SERVICES_UNFREEZE_AFTER_SECONDS_OF_GOOD_TRANSMISSION)) {
          get(mBandwidthIncreaseFrozen) = false;
          mTotalSendingPeriodWithoutIssues = Milliseconds(0);

          // decrease the time between adding new batons
          mAddToAvailableBurstBatonsDuation = (mAddToAvailableBurstBatonsDuation / 2);

          // prevent the adding window from ever getting smaller than the RTT
          if (mAddToAvailableBurstBatonsDuation < mCalculatedRTT)
            mAddToAvailableBurstBatonsDuation = mCalculatedRTT;

          PUID oldTimerID = 0;

          if (mAddToAvailableBurstBatonsTimer) {
            // kill the adding timer since the duration has changed (its okay, it will be recreated later)
            oldTimerID = mAddToAvailableBurstBatonsTimer->getID();

            mAddToAvailableBurstBatonsTimer->cancel();
            mAddToAvailableBurstBatonsTimer.reset();
          }

          ZS_LOG_TRACE(log("good period of transmission without issue thus unfreezing/increasing baton adding frequency") + ZS_PARAM("old add to batons timer ID", oldTimerID) + ZS_PARAM("duration milliseconds", mAddToAvailableBurstBatonsDuation.total_milliseconds()))
        }
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::deliverReadPackets()
      {
        bool delivered = false;
        ULONG totalDelivered = 0;

        // see how many packets we can confirm as received
        while (mReceivedPackets.size() > 0) {
          BufferedPacketMap::iterator iter = mReceivedPackets.begin();
          BufferedPacketPtr bufferedPacket = (*iter).second;

          // can only process the next if the packet is the next in the ordered series
          if (bufferedPacket->mSequenceNumber != (mGSNFR+1))
            break;

          delivered = true;
          ZS_LOG_TRACE(log("delivering read packet") + ZS_PARAM("sequence number", sequenceToString(bufferedPacket->mSequenceNumber)))

          // remember when this packet arrived so we can not allow expansion of
          // the incoming buffer window to grow too big
          mLastDeliveredReadData = bufferedPacket->mTimeSentOrReceived;

          // this is the next packet in the series... process the data from the
          // packet first (but only process the data if the receive is not
          // shutdown otherwise the data will be ignored and dropped)
          if ((bufferedPacket->mRUDPPacket->mDataLengthInBytes > 0) &&
              (0 == (IRUDPChannel::Shutdown_Receive & mShutdownState))) {

            const BYTE *pos = bufferedPacket->mRUDPPacket->mData;
            size_t bytes = bufferedPacket->mRUDPPacket->mDataLengthInBytes;

            totalDelivered += bytes;

            if (mReceiveStream) {
              mReceiveStream->write(pos, bytes);
            } else {
              ZS_THROW_BAD_STATE_IF(!mPendingReceiveData)
              mPendingReceiveData->Put(pos, bytes);
            }
          }

          // recalculate the GSNFR information
          mGSNFR = bufferedPacket->mSequenceNumber;
          get(mXORedParityToGSNFR) = internal::logicalXOR(mXORedParityToGSNFR, bufferedPacket->mRUDPPacket->isFlagSet(RUDPPacket::Flag_PS_ParitySending));

          // the front packet can now be removed
          mReceivedPackets.erase(iter);
        }

        if (delivered) {
          ZS_LOG_TRACE(log("delivering read packets read ready") + ZS_PARAM("size", totalDelivered))
        }
      }

      //-----------------------------------------------------------------------
      size_t RUDPChannelStream::getFromWriteBuffer(
                                                  BYTE *outBuffer,
                                                  size_t maxFillSize
                                                  )
      {
        ZS_LOG_TRACE(log("get from write buffer") + ZS_PARAM("max size", maxFillSize))

        if (!mSendStream) return 0;

        size_t read = mSendStream->read(outBuffer, maxFillSize);

        ZS_LOG_TRACE(log("get from write buffer") + ZS_PARAM("max size", maxFillSize) + ZS_PARAM("read size", read))
        return read;
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::getBuffer(
                                        RecycleBuffer &outBuffer,
                                        size_t &ioBufferAllocLengthInBytes
                                        )
      {
        if (ioBufferAllocLengthInBytes < OPENPEER_SERVICES_MINIMUM_DATA_BUFFER_LENGTH_ALLOCATED_IN_BYTES)
          ioBufferAllocLengthInBytes = OPENPEER_SERVICES_MINIMUM_DATA_BUFFER_LENGTH_ALLOCATED_IN_BYTES;

        if ((OPENPEER_SERVICES_MINIMUM_DATA_BUFFER_LENGTH_ALLOCATED_IN_BYTES != ioBufferAllocLengthInBytes) ||
            (mRecycleBuffers.size() < 1)) {
          outBuffer = RecycleBuffer(new BYTE[ioBufferAllocLengthInBytes]);
          return;
        }

        outBuffer = mRecycleBuffers.front();
        mRecycleBuffers.pop_front();
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::freeBuffer(
                                         RecycleBuffer &ioBuffer,
                                         size_t bufferAllocLengthInBytes
                                         )
      {
        if ((OPENPEER_SERVICES_MINIMUM_DATA_BUFFER_LENGTH_ALLOCATED_IN_BYTES != bufferAllocLengthInBytes) ||
            (mRecycleBuffers.size() > OPENPEER_SERVICES_MAX_RECYCLE_BUFFERS)){
          ioBuffer.reset();
          return;
        }

        mRecycleBuffers.push_back(ioBuffer);
      }

      //-----------------------------------------------------------------------
      bool RUDPChannelStream::getRandomFlag()
      {
        ++mRandomPoolPos;
        if (mRandomPoolPos > (sizeof(mRandomPool)*8)) {
          get(mRandomPoolPos) = 0;

          CryptoPP::AutoSeededRandomPool rng;
          rng.GenerateBlock(&(mRandomPool[0]), sizeof(mRandomPool));
        }

        size_t posByte = mRandomPoolPos / 8;
        ULONG posBit = mRandomPoolPos % 8;
        return (0 != (mRandomPool[posByte] & (1 << posBit)));
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::closeOnAllDataSent()
      {
        if (isShutdown()) return;       // already closed?
        if (!isShuttingDown()) return;  // do we want to close if all data is sent?

        ULONG totalWriteBuffers = mSendStream ? mSendStream->getTotalReadBuffersAvailable() : 0;

        if ((0 != totalWriteBuffers) || (0 != mSendingPackets.size())) return;

        ZS_LOG_TRACE(log("all data sent and now will close stream"))

        // all data has already been delivered so cancel the connection now
        cancel();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RUDPChannelStream::BufferedPacket
      #pragma mark

      //-----------------------------------------------------------------------
      RUDPChannelStream::BufferedPacketPtr RUDPChannelStream::BufferedPacket::create()
      {
        BufferedPacketPtr pThis(new BufferedPacket);
        pThis->mSequenceNumber = 0;
        pThis->mTimeSentOrReceived = zsLib::now();
        pThis->mXORedParityToNow = false;
        pThis->mHoldsBaton = false;
        pThis->mFlaggedAsFailedToReceive = false;
        pThis->mFlagForResendingInNextBurst = false;
        return pThis;
      }

      //-----------------------------------------------------------------------
      void  RUDPChannelStream::BufferedPacket::flagAsReceivedByRemoteParty(
                                                                           ULONG &ioTotalPacketsToResend,
                                                                           ULONG &ioAvailableBatons
                                                                           )
      {
        doNotResend(ioTotalPacketsToResend);
        releaseBaton(ioAvailableBatons);
        mPacket.reset();
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::BufferedPacket::flagForResending(size_t &ioTotalPacketsToResend)
      {
        if (!mPacket) return;
        if (mFlagForResendingInNextBurst) return;
        mFlagForResendingInNextBurst = true;
        ++ioTotalPacketsToResend;
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::BufferedPacket::doNotResend(ULONG &ioTotalPacketsToResend)
      {
        if (!mFlagForResendingInNextBurst) return;
        mFlagForResendingInNextBurst = false;
        ZS_THROW_BAD_STATE_IF(0 == ioTotalPacketsToResend)
        --ioTotalPacketsToResend;
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::BufferedPacket::consumeBaton(ULONG &ioAvailableBatons)
      {
        if (mHoldsBaton) return;
        if (0 == ioAvailableBatons) return;
        mHoldsBaton = true;
        --ioAvailableBatons;
      }

      //-----------------------------------------------------------------------
      void RUDPChannelStream::BufferedPacket::releaseBaton(ULONG &ioAvailableBatons)
      {
        if (!mHoldsBaton) return;
        mHoldsBaton = false;
        ++ioAvailableBatons;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------

    }
  }
}

#pragma warning(pop)
