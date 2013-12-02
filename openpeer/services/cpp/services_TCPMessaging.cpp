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

#include <openpeer/services/internal/services_TCPMessaging.h>
#include <openpeer/services/internal/services_Helper.h>
#include <openpeer/services/IHTTP.h>

#include <cryptopp/queue.h>

#include <zsLib/Log.h>
#include <zsLib/XML.h>
#include <zsLib/helpers.h>
#include <zsLib/Stringize.h>

#define OPENPEER_SERVICES_TCPMESSAGING_DEFAULT_RECEIVE_SIZE_IN_BYTES (64*1024)

namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services) } }

namespace openpeer
{
  namespace services
  {
    using zsLib::DWORD;
    using zsLib::Timer;

    namespace internal
    {
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark (helpers)
      #pragma mark

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark TCPMessaging
      #pragma mark

      //-----------------------------------------------------------------------
      TCPMessaging::TCPMessaging(
                                 IMessageQueuePtr queue,
                                 ITCPMessagingDelegatePtr delegate,
                                 ITransportStreamPtr receiveStream,
                                 ITransportStreamPtr sendStream,
                                 bool framesHaveChannelNumber,
                                 size_t maxMessageSizeInBytes
                                 ) :
        zsLib::MessageQueueAssociator(queue),
        mCurrentState(SessionState_Pending),
        mReceiveStream(receiveStream->getWriter()),
        mSendStream(sendStream->getReader()),
        mFramesHaveChannelNumber(framesHaveChannelNumber),
        mMaxMessageSizeInBytes(maxMessageSizeInBytes),
        mSendingQueue(new ByteQueue),
        mReceivingQueue(new ByteQueue)
      {
        ZS_LOG_DEBUG(log("created"))
        mDefaultSubscription = mSubscriptions.subscribe(delegate);
        ZS_THROW_BAD_STATE_IF(!mDefaultSubscription)
      }

      //-----------------------------------------------------------------------
      void TCPMessaging::init()
      {
        AutoRecursiveLock lock(getLock());
        mSendStreamSubscription = mSendStream->subscribe(mThisWeak.lock());
      }

      //-----------------------------------------------------------------------
      TCPMessaging::~TCPMessaging()
      {
        ZS_LOG_DEBUG(log("destroyed"))
        mThisWeak.reset();
        shutdown(Seconds(0));
      }

      //-----------------------------------------------------------------------
      TCPMessagingPtr TCPMessaging::convert(ITCPMessagingPtr channel)
      {
        return boost::dynamic_pointer_cast<TCPMessaging>(channel);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark TCPMessaging => ITCPMessaging
      #pragma mark

      //-----------------------------------------------------------------------
      ElementPtr TCPMessaging::toDebug(ITCPMessagingPtr channel)
      {
        if (!channel) return ElementPtr();

        TCPMessagingPtr pThis = TCPMessaging::convert(channel);
        return pThis->toDebug();
      }

      //-----------------------------------------------------------------------
      TCPMessagingPtr TCPMessaging::accept(
                                           ITCPMessagingDelegatePtr delegate,
                                           ITransportStreamPtr receiveStream,
                                           ITransportStreamPtr sendStream,
                                           bool framesHaveChannelNumber,
                                           SocketPtr socket,
                                           size_t maxMessageSizeInBytes
                                           )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!delegate)
        ZS_THROW_INVALID_ARGUMENT_IF(!receiveStream)
        ZS_THROW_INVALID_ARGUMENT_IF(!sendStream)
        ZS_THROW_INVALID_ARGUMENT_IF(!socket)

        TCPMessagingPtr pThis(new TCPMessaging(IHelper::getServiceQueue(), delegate, receiveStream, sendStream, framesHaveChannelNumber, maxMessageSizeInBytes));
        pThis->mThisWeak = pThis;

        int errorCode = 0;
        pThis->mSocket = boost::dynamic_pointer_cast<Socket>(socket->accept(pThis->mRemoteIP, &errorCode));
        if (!pThis->mSocket) {
          ZS_LOG_ERROR(Detail, pThis->log("failed to accept socket") + ZS_PARAM("error code", errorCode))
          pThis->shutdown(Seconds(0));
        } else {
          pThis->mSocket->setOptionFlag(Socket::SetOptionFlag::NonBlocking, true);
          pThis->mSocket->setDelegate(pThis);
          ZS_LOG_DEBUG(pThis->log("accepted") + ZS_PARAM("client IP", pThis->mRemoteIP.string()))
        }
        pThis->init();
        pThis->setState(SessionState_Connected);
        return pThis;
      }

      //-----------------------------------------------------------------------
      TCPMessagingPtr TCPMessaging::connect(
                                            ITCPMessagingDelegatePtr delegate,
                                            ITransportStreamPtr receiveStream,
                                            ITransportStreamPtr sendStream,
                                            bool framesHaveChannelNumber,
                                            IPAddress remoteIP,
                                            size_t maxMessageSizeInBytes
                                            )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!delegate)
        ZS_THROW_INVALID_ARGUMENT_IF(!receiveStream)
        ZS_THROW_INVALID_ARGUMENT_IF(!sendStream)
        ZS_THROW_INVALID_ARGUMENT_IF(remoteIP.isAddressEmpty())
        ZS_THROW_INVALID_ARGUMENT_IF(remoteIP.isPortEmpty())

        TCPMessagingPtr pThis(new TCPMessaging(IHelper::getServiceQueue(), delegate, receiveStream, sendStream, framesHaveChannelNumber, maxMessageSizeInBytes));
        pThis->mThisWeak = pThis;
        pThis->mRemoteIP = remoteIP;
        get(pThis->mConnectIssued) = true;

        bool wouldBlock = false;
        int errorCode = 0;
        pThis->mSocket = Socket::createTCP();
        pThis->mSocket->setDelegate(pThis);
        pThis->mSocket->setOptionFlag(Socket::SetOptionFlag::NonBlocking, true);
        pThis->mSocket->connect(remoteIP, &wouldBlock, &errorCode);
        ZS_LOG_DEBUG(pThis->log("attempting to connect") + ZS_PARAM("server IP", remoteIP.string()))
        if (0 != errorCode) {
          ZS_LOG_ERROR(Detail, pThis->log("failed to connect socket") + ZS_PARAM("error code", errorCode))
          pThis->shutdown(Seconds(0));
        }
        pThis->init();
        return pThis;
      }

      //-----------------------------------------------------------------------
      ITCPMessagingSubscriptionPtr TCPMessaging::subscribe(ITCPMessagingDelegatePtr originalDelegate)
      {
        AutoRecursiveLock lock(getLock());
        if (!originalDelegate) return mDefaultSubscription;

        ITCPMessagingSubscriptionPtr subscription = mSubscriptions.subscribe(originalDelegate);

        ITCPMessagingDelegatePtr delegate = mSubscriptions.delegate(subscription);

        if (delegate) {
          TCPMessagingPtr pThis = mThisWeak.lock();

          if (SessionState_Pending != mCurrentState) {
            delegate->onTCPMessagingStateChanged(pThis, mCurrentState);
          }
        }

        if (isShutdown()) {
          mSubscriptions.clear();
        }

        return subscription;
      }

      //-----------------------------------------------------------------------
      void TCPMessaging::enableKeepAlive(bool enable)
      {
        AutoRecursiveLock lock(getLock());

        if (isShutdown()) {
          ZS_LOG_DEBUG(log("already shutdown"))
          return;
        }

        if (!mSocket) {
          ZS_LOG_WARNING(Detail, log("socket was not found"))
          return;
        }

        ZS_LOG_DEBUG(log("setting keep-alive") + ZS_PARAM("value", enable))
        try {
          mSocket->setOptionFlag(ISocket::SetOptionFlag::KeepAlive, enable);
        } catch(ISocket::Exceptions::Unspecified &error) {
          ZS_LOG_WARNING(Detail, log("unable to change keep-alive value") + ZS_PARAM("reason", error.message()))
        }
      }

      //-----------------------------------------------------------------------
      void TCPMessaging::shutdown(Duration lingerTime)
      {
        AutoRecursiveLock lock(getLock());

        if (isShutdown()) {
          ZS_LOG_DEBUG(log("already shutdown"))
          return;
        }

        TCPMessagingPtr pThis = mThisWeak.lock();

        if ((!mLingerTimer) &&
            (pThis)) {
          if (lingerTime >= Seconds(0)) {
            mLingerTimer = Timer::create(mThisWeak.lock(), lingerTime, false);
          }
        }

        cancel();
      }

      //-----------------------------------------------------------------------
      ITCPMessaging::SessionStates TCPMessaging::getState(
                                                          WORD *outLastErrorCode,
                                                          String *outLastErrorReason
                                                          ) const
      {
        AutoRecursiveLock lock(getLock());
        if (outLastErrorCode) *outLastErrorCode = mLastError;
        if (outLastErrorReason) *outLastErrorReason = mLastErrorReason;
        return mCurrentState;
      }

      //-----------------------------------------------------------------------
      IPAddress TCPMessaging::getRemoteIP() const
      {
        AutoRecursiveLock lock(getLock());
        return mRemoteIP;
      }

      //-----------------------------------------------------------------------
      void TCPMessaging::setMaxMessageSizeInBytes(size_t maxMessageSizeInBytes)
      {
        AutoRecursiveLock lock(getLock());
        mMaxMessageSizeInBytes = maxMessageSizeInBytes;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark TCPMessaging => ITransportStreamReaderDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void TCPMessaging::onTransportStreamReaderReady(ITransportStreamReaderPtr reader)
      {
        AutoRecursiveLock lock(getLock());

        ZS_LOG_TRACE(log("notified stream read ready"))

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("cannot send data over TCP while shutdown"))
          return;
        }

        sendDataNow();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark TCPMessaging => ISocketDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void TCPMessaging::onReadReady(ISocketPtr socket)
      {
        AutoRecursiveLock lock(getLock());

        ZS_LOG_TRACE(log("notified TCP read ready"))

        if (socket != mSocket) {
          ZS_LOG_WARNING(Detail, log("notified about obsolete socket"))
          return;
        }

        if ((isShutdown()) ||
            (isShuttingdown())) {
          ZS_LOG_WARNING(Detail, log("notified about TCP read ready after already shutting down/shutdown"))
          return;
        }

        try {
          SecureByteBlock buffer(OPENPEER_SERVICES_TCPMESSAGING_DEFAULT_RECEIVE_SIZE_IN_BYTES);
          bool wouldBlock = false;
          size_t bytesRead = mSocket->receive(buffer.BytePtr(), OPENPEER_SERVICES_TCPMESSAGING_DEFAULT_RECEIVE_SIZE_IN_BYTES, &wouldBlock);

          if (0 == bytesRead) {
            ZS_LOG_WARNING(Detail, log("notified of data to read but no data available to read") + ZS_PARAM("would block", wouldBlock))
            setError(IHTTP::HTTPStatusCode_NoContent, "server issues shutdown on socket connection");
            cancel();
            return;
          }

          if (ZS_IS_LOGGING(Insane)) {
            String base64 = IHelper::convertToBase64(buffer.BytePtr(), bytesRead);
            ZS_LOG_INSANE(log("RECEIVED FROM WIRE") + ZS_PARAM("wire in", base64))
          }

          mReceivingQueue->Put(buffer.BytePtr(), bytesRead);

        } catch(ISocket::Exceptions::Unspecified &error) {
          ZS_LOG_ERROR(Detail, log("receive error") + ZS_PARAM("error", error.errorCode()))
          setError(IHTTP::HTTPStatusCode_Networkconnecttimeouterror, (String("network error: ") + error.message()).c_str());
          cancel();
          return;
        }

        do {
          size_t size = static_cast<size_t>(mReceivingQueue->CurrentSize());
          if (0 == size) {
            ZS_LOG_TRACE(log("no more data available in receive buffer"))
            break;
          }

          size_t needingSize = sizeof(DWORD);
          if (mFramesHaveChannelNumber) {
            needingSize += sizeof(DWORD);
          }

          if (size < needingSize) {
            ZS_LOG_TRACE(log("unsufficient receive data to continue processing") + ZS_PARAM("available", size))
            break;
          }

          DWORD bufferedChannel = 0;
          DWORD channel = 0;

          if (mFramesHaveChannelNumber) {
            mReceivingQueue->PeekWord32(channel);
            mReceivingQueue->Get((BYTE *)(&bufferedChannel), sizeof(bufferedChannel));
          }

          DWORD bufferSize = 0;
          mReceivingQueue->PeekWord32(bufferSize);

          needingSize += bufferSize;

          if (size < needingSize) {
            ZS_LOG_TRACE(log("unsufficient receive data to continue processing") + ZS_PARAM("available", size) + ZS_PARAM("needing", needingSize))
            if (mFramesHaveChannelNumber) {
              // put back the buffered channel number
              mReceivingQueue->Unget((const BYTE *)(&bufferedChannel), sizeof(bufferedChannel));
            }
            break;
          }

          if (bufferSize > mMaxMessageSizeInBytes) {
            ZS_LOG_ERROR(Detail, log("read message size exceeds maximum buffer size") + ZS_PARAM("message size", bufferSize) + ZS_PARAM("max size", mMaxMessageSizeInBytes))
            setError(IHTTP::HTTPStatusCode_PreconditionFailed, "read message size exceeds maximum buffer size allowed");
            cancel();
            return;
          }

          // skip over the peeked value
          mReceivingQueue->Skip(sizeof(bufferSize));

          SecureByteBlockPtr message(new SecureByteBlock);
          message->CleanNew(bufferSize);
          if (bufferSize > 0) {
            mReceivingQueue->Get(message->BytePtr(), bufferSize);
          }

          ChannelHeaderPtr channelHeader;
          if (mFramesHaveChannelNumber) {
            channelHeader = ChannelHeaderPtr(new ChannelHeader);
            channelHeader->mChannelID = channel;
          }

          ZS_LOG_DEBUG(log("message read from network") + ZS_PARAM("message size", bufferSize) + ZS_PARAM("channel", channel))
          mReceiveStream->write(message, channelHeader);
        } while(true);
      }

      //-----------------------------------------------------------------------
      void TCPMessaging::onWriteReady(ISocketPtr socket)
      {
        AutoRecursiveLock lock(getLock());

        ZS_LOG_TRACE(log("notified TCP write ready"))

        if (socket != mSocket) {
          ZS_LOG_WARNING(Detail, log("notified about obsolete socket"))
          return;
        }

        if (mConnectIssued) {
          if (!isShuttingdown()) {
            ZS_LOG_TRACE(log("connected"))
            get(mConnectIssued) = false;
            setState(SessionState_Connected);
          }
        }

        get(mTCPWriteReady) = true;

        sendDataNow();
      }

      //-----------------------------------------------------------------------
      void TCPMessaging::onException(ISocketPtr socket)
      {
        AutoRecursiveLock lock(getLock());

        if (socket != mSocket) {
          ZS_LOG_WARNING(Detail, log("notified about obsolete socket"))
          return;
        }

        setError(IHTTP::HTTPStatusCode_Networkconnecttimeouterror, "socket connection failure");
        cancel();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark TCPMessaging => ITimerDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void TCPMessaging::onTimer(TimerPtr timer)
      {
        AutoRecursiveLock lock(getLock());

        mLingerTimer.reset();
        cancel();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark TCPMessaging  => (internal)
      #pragma mark

      //-----------------------------------------------------------------------
      RecursiveLock &TCPMessaging::getLock() const
      {
        return mLock;
      }

      //-----------------------------------------------------------------------
      Log::Params TCPMessaging::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("TCPMessaging");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params TCPMessaging::debug(const char *message) const
      {
        return Log::Params(message, toDebug());
      }

      //-----------------------------------------------------------------------
      ElementPtr TCPMessaging::toDebug() const
      {
        AutoRecursiveLock lock(getLock());

        ElementPtr resultEl = Element::create("TCPMessaging");

        IHelper::debugAppend(resultEl, "id", mID);

        IHelper::debugAppend(resultEl, "tcp messaging id", mID);
        IHelper::debugAppend(resultEl, "graceful shutdown", (bool)mGracefulShutdownReference);
        IHelper::debugAppend(resultEl, "subscriptions", mSubscriptions.size());
        IHelper::debugAppend(resultEl, "default subscription", (bool)mDefaultSubscription);
        IHelper::debugAppend(resultEl, "state", ITCPMessaging::toString(mCurrentState));
        IHelper::debugAppend(resultEl, "last error", mLastError);
        IHelper::debugAppend(resultEl, "last reason", mLastErrorReason);
        IHelper::debugAppend(resultEl, "receive stream", ITransportStream::toDebug(mReceiveStream->getStream()));
        IHelper::debugAppend(resultEl, "send stream", ITransportStream::toDebug(mSendStream->getStream()));
        IHelper::debugAppend(resultEl, "send stream subscription", (bool)mSendStreamSubscription);
        IHelper::debugAppend(resultEl, "max size", mMaxMessageSizeInBytes);
        IHelper::debugAppend(resultEl, "write ready", mTCPWriteReady);
        IHelper::debugAppend(resultEl, "remote IP", mRemoteIP.string());
        IHelper::debugAppend(resultEl, "socket", (bool)mSocket);
        IHelper::debugAppend(resultEl, "linger timer", (bool)mLingerTimer);

        return resultEl;
      }

      //-----------------------------------------------------------------------
      void TCPMessaging::setState(SessionStates state)
      {
        if (state == mCurrentState) return;

        ZS_LOG_DEBUG(log("state changed") + ZS_PARAM("state", ITCPMessaging::toString(state)) + ZS_PARAM("old state", ITCPMessaging::toString(mCurrentState)))
        mCurrentState = state;

        TCPMessagingPtr pThis = mThisWeak.lock();
        if (pThis) {
          ZS_LOG_DEBUG(debug("attempting to report state to delegate"))
          mSubscriptions.delegate()->onTCPMessagingStateChanged(pThis, mCurrentState);
        }

        if (SessionState_Connected == mCurrentState) {
          mSendStream->notifyReaderReadyToRead();
        }
      }

      //-----------------------------------------------------------------------
      void TCPMessaging::setError(WORD errorCode, const char *inReason)
      {
        String reason(inReason ? String(inReason) : String());
        if (reason.isEmpty()) {
          reason = IHTTP::toString(IHTTP::toStatusCode(errorCode));
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
      void TCPMessaging::cancel()
      {
        ZS_LOG_DEBUG(log("cancel called"))

        AutoRecursiveLock lock(getLock());

        if (isShutdown()) {
          ZS_LOG_DEBUG(log("already shutdown"))
        }

        setState(SessionState_ShuttingDown);

        if (mLingerTimer) {
          if (!mGracefulShutdownReference) {
            mGracefulShutdownReference = mThisWeak.lock();
          }

          ZS_LOG_DEBUG(log("waiting for linger to complete"))
          return;
        }

        setState(SessionState_Shutdown);

        mGracefulShutdownReference.reset();

        mSubscriptions.clear();

        mReceiveStream->cancel();
        mSendStream->cancel();

        mSendStreamSubscription->cancel();

        if (mSocket) {
          mSocket->close();
          mSocket.reset();
        }

        ZS_LOG_DEBUG(log("cancel complete"))
      }

      //-----------------------------------------------------------------------
      void TCPMessaging::sendDataNow()
      {
        typedef ITransportStream::StreamHeader StreamHeader;
        typedef ITransportStream::StreamHeaderPtr StreamHeaderPtr;

        if (isShutdown()) return;

        if (!mSocket) {
          ZS_LOG_WARNING(Detail, log("socket gone"))
          return;
        }

        if (!mTCPWriteReady) {
          ZS_LOG_DEBUG(log("cannot send data until TCP write ready received"))
          return;
        }

        get(mTCPWriteReady) = false;

        size_t sent = 0;

        if (!sendQueuedData(sent)) {
          ZS_LOG_TRACE(log("not all queued data sent (try again when next TCP send ready received)"))
          return;
        }

        if (0 == sent) {
          // nothing to send?
          if (mSendStream->getTotalReadBuffersAvailable() < 1) {
            ZS_LOG_DEBUG(log("no data was sent because there was nothing to send (try again when data added to send)"))
            get(mTCPWriteReady) = true;
            return;
          }
        }

        while (mSendStream->getTotalReadBuffersAvailable() > 0) {
          // attempt to send the next buffer over TCP

          StreamHeaderPtr header;
          SecureByteBlockPtr buffer = mSendStream->read(&header);

          ChannelHeaderPtr channelHeader = ChannelHeader::convert(header);

          if (mFramesHaveChannelNumber) {
            if (!channelHeader) {
              ZS_LOG_ERROR(Detail, log("expecting a channel header but did not receive one"))
              setError(IHTTP::HTTPStatusCode_ExpectationFailed, "expected channel header for sending buffer but was not given one");
              cancel();
              return;
            }
            mSendingQueue->PutWord32(channelHeader->mChannelID);
          }

          if (channelHeader) {
            ZS_LOG_TRACE(log("queuing data to send data over TCP") + ZS_PARAM("message size", buffer->SizeInBytes()) + ZS_PARAM("channel", channelHeader->mChannelID))
          } else {
            ZS_LOG_TRACE(log("queuing data to send data over TCP") + ZS_PARAM("message size", buffer->SizeInBytes()))
          }

          mSendingQueue->PutWord32(static_cast<CryptoPP::word32>(buffer->SizeInBytes()));
          if (buffer->SizeInBytes() > 0) {
            mSendingQueue->Put(buffer->BytePtr(), buffer->SizeInBytes());
          }

          if (!sendQueuedData(sent)) {
            ZS_LOG_TRACE(log("not all queued data sent (try again when next TCP send ready received)"))
            return;
          }
        }
      }
      
      //-----------------------------------------------------------------------
      bool TCPMessaging::sendQueuedData(size_t &outSent)
      {
        outSent = 0;

        size_t size = static_cast<size_t>(mSendingQueue->CurrentSize());

        // attempt to send from the send queue first
        if (size < 1) {
          ZS_LOG_TRACE(log("no queued data to send"))
          return true;
        }

        SecureByteBlock buffer(size);

        // attempt to grab the entire buffer to be sent
        mSendingQueue->Peek(buffer.BytePtr(), size);

        try {
          ZS_LOG_TRACE(log("attempting to send data over TCP") + ZS_PARAM("size", size))
          bool wouldBlock = false;
          size_t sent = mSocket->send(buffer.BytePtr(), size, &wouldBlock);
          outSent = sent;
          if (0 != sent) {
            if (ZS_IS_LOGGING(Insane)) {
              String base64 = IHelper::convertToBase64(buffer.BytePtr(), sent);
              ZS_LOG_INSANE(log("SENT ON WIRE") + ZS_PARAM("wire out", base64))
            }
            mSendingQueue->Skip(sent);
          }

          ZS_LOG_TRACE(log("data sent over TCP") + ZS_PARAM("size", sent))

          if (mSendingQueue->CurrentSize() > 0) {
            ZS_LOG_DEBUG(log("still more data in the sending queue to be sent, wait for next write ready..."))
            return false;
          }
        } catch (ISocket::Exceptions::Unspecified &error) {
          ZS_LOG_ERROR(Detail, log("send error") + ZS_PARAM("error", error.errorCode()))
          setError(IHTTP::HTTPStatusCode_Networkconnecttimeouterror, (String("network error: ") + error.message()).c_str());
          cancel();
          return false;
        }

        return true;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
    }

    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    #pragma mark
    #pragma mark ITCPMessaging
    #pragma mark

    //-----------------------------------------------------------------------
    const char *ITCPMessaging::toString(SessionStates state)
    {
      switch (state)
      {
        case SessionState_Pending:                      return "Pending";
        case SessionState_Connected:                    return "Connected";
        case SessionState_ShuttingDown:                 return "Shutting down";
        case SessionState_Shutdown:                     return "Shutdown";
      }
      return "UNDEFINED";
    }
    
    //-----------------------------------------------------------------------
    ElementPtr ITCPMessaging::toDebug(ITCPMessagingPtr messaging)
    {
      return internal::TCPMessaging::toDebug(messaging);
    }

    //-----------------------------------------------------------------------
    ITCPMessagingPtr ITCPMessaging::accept(
                                   ITCPMessagingDelegatePtr delegate,
                                   ITransportStreamPtr receiveStream,
                                   ITransportStreamPtr sendStream,
                                   bool framesHaveChannelNumber,
                                   SocketPtr socket,
                                   size_t maxMessageSizeInBytes
                                   )
    {
      return internal::ITCPMessagingFactory::singleton().accept(delegate, receiveStream, sendStream, framesHaveChannelNumber, socket, maxMessageSizeInBytes);
    }

    //-----------------------------------------------------------------------
    ITCPMessagingPtr ITCPMessaging::connect(
                                            ITCPMessagingDelegatePtr delegate,
                                            ITransportStreamPtr receiveStream,
                                            ITransportStreamPtr sendStream,
                                            bool framesHaveChannelNumber,
                                            IPAddress remoteIP,
                                            size_t maxMessageSizeInBytes
                                            )
    {
      return internal::ITCPMessagingFactory::singleton().connect(delegate, receiveStream, sendStream, framesHaveChannelNumber, remoteIP, maxMessageSizeInBytes);
    }
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    #pragma mark
    #pragma mark ITCPMessaging::ChannelHeader
    #pragma mark

    //-----------------------------------------------------------------------
    ITCPMessaging::ChannelHeaderPtr ITCPMessaging::ChannelHeader::convert(ITransportStream::StreamHeaderPtr header)
    {
      return boost::dynamic_pointer_cast<ChannelHeader>(header);
    }

  }
}
