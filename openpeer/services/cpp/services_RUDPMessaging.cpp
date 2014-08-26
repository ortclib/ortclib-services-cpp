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

#include <openpeer/services/internal/services_RUDPMessaging.h>
#include <openpeer/services/internal/services_Helper.h>

#include <openpeer/services/IRUDPListener.h>
#include <openpeer/services/IRUDPTransport.h>

#include <cryptopp/queue.h>

#include <zsLib/Exception.h>
#include <zsLib/helpers.h>
#include <zsLib/Log.h>
#include <zsLib/Stringize.h>
#include <zsLib/XML.h>

#define OPENPEER_SERVICES_RUDPMESSAGING_RECYCLE_BUFFER_SIZE ((1 << (sizeof(WORD)*8)) + sizeof(DWORD))
#define OPENPEER_SERVICES_RUDPMESSAGING_MAX_RECYLCE_BUFFERS (100)

namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services_rudp) } }

namespace openpeer
{
  namespace services
  {
    namespace internal
    {
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RUDPMessaging => IRUDPMessaging
      #pragma mark

      //-----------------------------------------------------------------------
      RUDPMessaging::RUDPMessaging(
                                   IMessageQueuePtr queue,
                                   IRUDPMessagingDelegatePtr delegate,
                                   ITransportStreamPtr receiveStream,
                                   ITransportStreamPtr sendStream,
                                   size_t maxMessageSizeInBytes
                                   ) :
        MessageQueueAssociator(queue),
        mCurrentState(RUDPMessagingState_Connecting),
        mDelegate(IRUDPMessagingDelegateProxy::createWeak(queue, delegate)),
        mMaxMessageSizeInBytes(maxMessageSizeInBytes),
        mOuterReceiveStream(receiveStream->getWriter()),
        mOuterSendStream(sendStream->getReader()),
        mWireReceiveStream(ITransportStream::create()->getReader()),
        mWireSendStream(ITransportStream::create()->getWriter())
      {
        ZS_LOG_DETAIL(log("created"))
      }

      //-----------------------------------------------------------------------
      void RUDPMessaging::init()
      {
        AutoRecursiveLock lock(mLock);
        mWireReceiveStreamSubscription = mWireReceiveStream->subscribe(mThisWeak.lock());
        mWireSendStreamSubscription = mWireSendStream->subscribe(mThisWeak.lock());

        mOuterReceiveStreamSubscription = mOuterReceiveStream->subscribe(mThisWeak.lock());
        mOuterSendStreamSubscription = mOuterSendStream->subscribe(mThisWeak.lock());
      }

      //-----------------------------------------------------------------------
      RUDPMessaging::~RUDPMessaging()
      {
        if(isNoop()) return;
        
        mThisWeak.reset();
        ZS_LOG_DETAIL(log("destroyed"))
        cancel();
      }

      //-----------------------------------------------------------------------
      RUDPMessagingPtr RUDPMessaging::convert(IRUDPMessagingPtr messaging)
      {
        return ZS_DYNAMIC_PTR_CAST(RUDPMessaging, messaging);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RUDPMessaging => IRUDPMessaging
      #pragma mark

      //-----------------------------------------------------------------------
      ElementPtr RUDPMessaging::toDebug(IRUDPMessagingPtr messaging)
      {
        if (!messaging) return ElementPtr();

        RUDPMessagingPtr pThis = RUDPMessaging::convert(messaging);
        return pThis->toDebug();
      }

      //-----------------------------------------------------------------------
      RUDPMessagingPtr RUDPMessaging::acceptChannel(
                                                    IMessageQueuePtr queue,
                                                    IRUDPListenerPtr listener,
                                                    IRUDPMessagingDelegatePtr delegate,
                                                    ITransportStreamPtr receiveStream,
                                                    ITransportStreamPtr sendStream,
                                                    size_t maxMessageSizeInBytes
                                                    )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!listener)
        ZS_THROW_INVALID_ARGUMENT_IF(!delegate)
        ZS_THROW_INVALID_ARGUMENT_IF(!receiveStream)
        ZS_THROW_INVALID_ARGUMENT_IF(!sendStream)

        RUDPMessagingPtr pThis(new RUDPMessaging(queue, delegate, receiveStream, sendStream, maxMessageSizeInBytes));
        pThis->mThisWeak = pThis;

        AutoRecursiveLock lock(pThis->mLock);
        pThis->mChannel = listener->acceptChannel(pThis, pThis->mWireReceiveStream->getStream(), pThis->mWireSendStream->getStream());
        pThis->init();
        if (!pThis->mChannel) {
          ZS_LOG_ERROR(Detail, pThis->log("listener failed to accept channel"))
          pThis->setError(RUDPMessagingShutdownReason_OpenFailure, "channel accept failure");
          pThis->cancel();
          return RUDPMessagingPtr();
        }
        ZS_LOG_DEBUG(pThis->log("listener channel accepted"))
        return pThis;
      }

      //-----------------------------------------------------------------------
      RUDPMessagingPtr RUDPMessaging::acceptChannel(
                                                    IMessageQueuePtr queue,
                                                    IRUDPTransportPtr session,
                                                    IRUDPMessagingDelegatePtr delegate,
                                                    ITransportStreamPtr receiveStream,
                                                    ITransportStreamPtr sendStream,
                                                    size_t maxMessageSizeInBytes
                                                    )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!session)
        ZS_THROW_INVALID_ARGUMENT_IF(!delegate)
        ZS_THROW_INVALID_ARGUMENT_IF(!receiveStream)
        ZS_THROW_INVALID_ARGUMENT_IF(!sendStream)

        RUDPMessagingPtr pThis(new RUDPMessaging(queue, delegate, receiveStream, sendStream, maxMessageSizeInBytes));
        pThis->mThisWeak = pThis;

        AutoRecursiveLock lock(pThis->mLock);
        pThis->mChannel = session->acceptChannel(pThis, pThis->mWireReceiveStream->getStream(), pThis->mWireSendStream->getStream());
        pThis->init();
        if (!pThis->mChannel) {
          ZS_LOG_ERROR(Detail, pThis->log("session failed to accept channel"))
          pThis->setError(RUDPMessagingShutdownReason_OpenFailure, "channel accept failure");
          pThis->cancel();
          return RUDPMessagingPtr();
        }
        ZS_LOG_DEBUG(pThis->log("session channel accepted"))
        return pThis;
      }

      //-----------------------------------------------------------------------
      RUDPMessagingPtr RUDPMessaging::openChannel(
                                                  IMessageQueuePtr queue,
                                                  IRUDPTransportPtr session,
                                                  IRUDPMessagingDelegatePtr delegate,
                                                  const char *connectionInfo,
                                                  ITransportStreamPtr receiveStream,
                                                  ITransportStreamPtr sendStream,
                                                  size_t maxMessageSizeInBytes
                                                  )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!session)
        ZS_THROW_INVALID_ARGUMENT_IF(!delegate)
        ZS_THROW_INVALID_ARGUMENT_IF(!receiveStream)
        ZS_THROW_INVALID_ARGUMENT_IF(!sendStream)

        RUDPMessagingPtr pThis(new RUDPMessaging(queue, delegate, receiveStream, sendStream, maxMessageSizeInBytes));
        pThis->mThisWeak = pThis;

        AutoRecursiveLock lock(pThis->mLock);
        pThis->mChannel = session->openChannel(pThis, connectionInfo, pThis->mWireReceiveStream->getStream(), pThis->mWireSendStream->getStream());
        pThis->init();
        if (!pThis->mChannel) {
          ZS_LOG_ERROR(Detail, pThis->log("session failed to open channel"))
          pThis->setError(RUDPMessagingShutdownReason_OpenFailure, "channel open failure");
          pThis->cancel();
          return RUDPMessagingPtr();
        }
        ZS_LOG_DEBUG(pThis->log("session channel openned"))
        return pThis;
      }

      //-----------------------------------------------------------------------
      IRUDPMessaging::RUDPMessagingStates RUDPMessaging::getState(
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
      void RUDPMessaging::shutdown()
      {
        AutoRecursiveLock lock(mLock);
        cancel();
      }

      //-----------------------------------------------------------------------
      void RUDPMessaging::shutdownDirection(Shutdown state)
      {
        IRUDPChannelPtr channel = getChannel();
        if (!channel) return;
        channel->shutdownDirection(state);
      }

      //-----------------------------------------------------------------------
      void RUDPMessaging::setMaxMessageSizeInBytes(size_t maxMessageSizeInBytes)
      {
        AutoRecursiveLock lock(mLock);
        mMaxMessageSizeInBytes = maxMessageSizeInBytes;
      }

      //-----------------------------------------------------------------------
      IPAddress RUDPMessaging::getConnectedRemoteIP()
      {
        IRUDPChannelPtr channel = getChannel();
        if (!channel) return IPAddress();
        return channel->getConnectedRemoteIP();
      }

      //-----------------------------------------------------------------------
      String RUDPMessaging::getRemoteConnectionInfo()
      {
        IRUDPChannelPtr channel = getChannel();
        if (!channel) return String();
        return channel->getRemoteConnectionInfo();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RUDPMessaging => IRUDPChannelDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void RUDPMessaging::onRDUPChannelStateChanged(
                                                    IRUDPChannelPtr channel,
                                                    RUDPChannelStates state
                                                    )
      {
        AutoRecursiveLock lock(mLock);
        ZS_LOG_DEBUG(log("notified of channel state change") + ZS_PARAM("channel ID", channel->getID()) + ZS_PARAM("state", IRUDPChannel::toString(state)))

        if (channel != mChannel) {
          ZS_LOG_WARNING(Debug, log("notified of channel state change for obsolete channel (thus ignoring)") + ZS_PARAM("expecting channel", mChannel ? mChannel->getID() : 0))
          return;
        }

        if (isShutdown()) {
          ZS_LOG_DEBUG(log("notified of channel state change but already shutdown (thus ignoring)"))
          return;
        }

        switch (state) {
          case IRUDPChannel::RUDPChannelState_Connecting: break;
          case IRUDPChannel::RUDPChannelState_Connected:  {
            if (isShuttingDown()) return;
            setState(RUDPMessagingState_Connected);
            break;
          }
          case IRUDPChannel::RUDPChannelState_ShuttingDown:
          case IRUDPChannel::RUDPChannelState_Shutdown:
          {
            WORD errorCode = 0;
            String reason;
            mChannel->getState(&errorCode, &reason);
            if (0 != errorCode) {
              setError(errorCode, reason);
            }
            if (IRUDPChannel::RUDPChannelState_Shutdown == state) {
              mChannel.reset();
            }
            cancel();
            break;
          }
        }
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RUDPMessaging => ITransportStreamWriterDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void RUDPMessaging::onTransportStreamWriterReady(ITransportStreamWriterPtr writer)
      {
        AutoRecursiveLock lock(mLock);
        if (writer == mOuterReceiveStream) {
          ZS_LOG_TRACE(log("on transport stream outer receive ready"))
          mWireReceiveStream->notifyReaderReadyToRead();
          mInformedOuterReceiveReady = true;
        } else if (writer == mWireSendStream) {
          ZS_LOG_TRACE(log("on transport stream wire send ready"))
          mOuterSendStream->notifyReaderReadyToRead();
          mInformedWireSendReady = true;
        }
        step();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RUDPMessaging => ITransportStreamReaderDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void RUDPMessaging::onTransportStreamReaderReady(ITransportStreamReaderPtr reader)
      {
        AutoRecursiveLock lock(mLock);
        ZS_LOG_TRACE(log("on transport stream reader ready"))
        step();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RUDPMessaging => (internal)
      #pragma mark

      //-----------------------------------------------------------------------
      Log::Params RUDPMessaging::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("RUDPMessaging");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params RUDPMessaging::debug(const char *message) const
      {
        return Log::Params(message, toDebug());
      }

      //-----------------------------------------------------------------------
      ElementPtr RUDPMessaging::toDebug() const
      {
        AutoRecursiveLock lock(mLock);

        ElementPtr resultEl = Element::create("RUDPMessaging");

        IHelper::debugAppend(resultEl, "id", mID);

        IHelper::debugAppend(resultEl, "state", IRUDPMessaging::toString(mCurrentState));
        IHelper::debugAppend(resultEl, "last error", mLastError);
        IHelper::debugAppend(resultEl, "last reason", mLastErrorReason);

        IHelper::debugAppend(resultEl, "delegate", (bool)mDelegate);

        IHelper::debugAppend(resultEl, "outer receive stream", (bool)mOuterReceiveStream);
        IHelper::debugAppend(resultEl, "outer send stream", (bool)mOuterSendStream);

        IHelper::debugAppend(resultEl, "wire receive stream", (bool)mWireReceiveStream);
        IHelper::debugAppend(resultEl, "wire send stream", (bool)mWireSendStream);

        IHelper::debugAppend(resultEl, "outer receive stream subscription", (bool)mOuterReceiveStreamSubscription);
        IHelper::debugAppend(resultEl, "outer send stream subscription", (bool)mOuterSendStreamSubscription);

        IHelper::debugAppend(resultEl, "wire receive stream subscription", (bool)mWireReceiveStreamSubscription);
        IHelper::debugAppend(resultEl, "wire send stream subscription", (bool)mWireSendStreamSubscription);

        IHelper::debugAppend(resultEl, "informed outer receive ready", mInformedOuterReceiveReady);
        IHelper::debugAppend(resultEl, "informed wire send ready", mInformedWireSendReady);

        IHelper::debugAppend(resultEl, "graceful shutdown reference", (bool)mGracefulShutdownReference);

        IHelper::debugAppend(resultEl, "channel", mChannel ? mChannel->getID() : 0);

        IHelper::debugAppend(resultEl, "max message size (bytes)", mMaxMessageSizeInBytes);

        return resultEl;
      }

      //-----------------------------------------------------------------------
      void RUDPMessaging::step()
      {
        if (isShutdown()) {
          ZS_LOG_DEBUG(log("step forwarding to cancel"))
          return;
        }

        ZS_LOG_DEBUG(debug("step"))

        if (!stepSendData()) return;
        if (!stepReceiveData()) return;

        ZS_LOG_TRACE(log("step complete"))
      }

      //-----------------------------------------------------------------------
      bool RUDPMessaging::stepSendData()
      {
        if (!mInformedWireSendReady) {
          ZS_LOG_TRACE(log("wire has not informed it's ready to send data"))
          return true;
        }

        while (mOuterSendStream->getTotalReadBuffersAvailable() > 0) {
          SecureByteBlockPtr message = mOuterSendStream->read();

          SecureByteBlockPtr buffer(new SecureByteBlock(message->SizeInBytes() + sizeof(DWORD)));

          // put the size of the message at the front
          BYTE *dest = buffer->BytePtr();
          ((DWORD *)dest)[0] = htonl(message->SizeInBytes());
          memcpy(&(dest[sizeof(DWORD)]), message->BytePtr(), message->SizeInBytes());

          ZS_LOG_TRACE(log("sending buffer") + ZS_PARAM("message size", message->SizeInBytes()))
          mWireSendStream->write(buffer);
        }

        return true;
      }

      //-----------------------------------------------------------------------
      bool RUDPMessaging::stepReceiveData()
      {
        if (!mInformedOuterReceiveReady) {
          ZS_LOG_TRACE(log("outer has not informed it's ready to receive data"))
          return true;
        }

        // read all data available

        while (mWireReceiveStream->getTotalReadBuffersAvailable() > 0) {

          DWORD bufferSize = 0;

          size_t read = mWireReceiveStream->peekDWORD(bufferSize);
          if (read != sizeof(bufferSize)) {
            ZS_LOG_TRACE(log("not enough data available to read"))
            break;
          }

          size_t available = mWireReceiveStream->getTotalReadSizeAvailableInBytes();

          if (available < sizeof(DWORD) + bufferSize) {
            ZS_LOG_TRACE(log("not enough data available to read") + ZS_PARAM("available", available) + ZS_PARAM("buffer size", bufferSize))
            break;
          }

          mWireReceiveStream->skip(sizeof(DWORD));

          SecureByteBlockPtr message(new SecureByteBlock);
          message->CleanNew(bufferSize);
          if (bufferSize > 0) {
            mWireReceiveStream->read(message->BytePtr(), bufferSize);
          }

          ZS_LOG_TRACE(log("message is read") + ZS_PARAM("size", bufferSize))

          if (bufferSize > 0) {
            mOuterReceiveStream->write(message);
          }
        }

        return true;
      }

      //-----------------------------------------------------------------------
      void RUDPMessaging::cancel()
      {
        AutoRecursiveLock lock(mLock);  // just in case

        if (isShutdown()) return;

        setState(RUDPMessagingState_ShuttingDown);

        if (!mGracefulShutdownReference) mGracefulShutdownReference = mThisWeak.lock();

        if (mChannel) {
          mChannel->shutdown();
        }

        if (mGracefulShutdownReference) {
          ZS_LOG_DEBUG(log("shutting down gracefully"))

          if (mChannel) {
            if (IRUDPChannel::RUDPChannelState_Shutdown != mChannel->getState()) {
              // channel is not ready to shutdown just yet
              ZS_LOG_DEBUG(log("waiting for RUDP channel to shutdown"))
              return;
            }
          }
        }

        setState(RUDPMessagingState_Shutdown);

        mDelegate.reset();
        mGracefulShutdownReference.reset();

        mChannel.reset();
      }

      //-----------------------------------------------------------------------
      void RUDPMessaging::setState(RUDPMessagingStates state)
      {
        if (state == mCurrentState) return;
        ZS_LOG_DETAIL(log("state changed") + ZS_PARAM("old state", toString(mCurrentState)) + ZS_PARAM("new state", toString(state)))

        mCurrentState = state;

        if (!mDelegate) return;

        RUDPMessagingPtr pThis = mThisWeak.lock();

        if (pThis) {
          try {
            mDelegate->onRUDPMessagingStateChanged(mThisWeak.lock(), state);
          } catch(IRUDPMessagingDelegateProxy::Exceptions::DelegateGone &) {
          }
        }
      }

      //-----------------------------------------------------------------------
      void RUDPMessaging::setError(WORD errorCode, const char *inReason)
      {
        String reason(inReason);
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

        mLastError = errorCode;
        mLastErrorReason = reason;

        ZS_LOG_WARNING(Detail, debug("error set") + ZS_PARAM("code", mLastError) + ZS_PARAM("reason", mLastErrorReason))
      }

      //-----------------------------------------------------------------------
      IRUDPChannelPtr RUDPMessaging::getChannel() const
      {
        AutoRecursiveLock lock(mLock);
        return mChannel;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IRUDPMessagingFactory
      #pragma mark

      //-------------------------------------------------------------------------
      IRUDPMessagingFactory &IRUDPMessagingFactory::singleton()
      {
        return RUDPMessagingFactory::singleton();
      }

      //-----------------------------------------------------------------------
      RUDPMessagingPtr IRUDPMessagingFactory::acceptChannel(
                                                            IMessageQueuePtr queue,
                                                            IRUDPListenerPtr listener,
                                                            IRUDPMessagingDelegatePtr delegate,
                                                            ITransportStreamPtr receiveStream,
                                                            ITransportStreamPtr sendStream,
                                                            size_t maxMessageSizeInBytes
                                                            )
      {
        if (this) {}
        return RUDPMessaging::acceptChannel(queue, listener, delegate, receiveStream, sendStream, maxMessageSizeInBytes);
      }

      //-----------------------------------------------------------------------
      RUDPMessagingPtr IRUDPMessagingFactory::acceptChannel(
                                                            IMessageQueuePtr queue,
                                                            IRUDPTransportPtr session,
                                                            IRUDPMessagingDelegatePtr delegate,
                                                            ITransportStreamPtr receiveStream,
                                                            ITransportStreamPtr sendStream,
                                                            size_t maxMessageSizeInBytes
                                                            )
      {
        if (this) {}
        return RUDPMessaging::acceptChannel(queue, session, delegate, receiveStream, sendStream, maxMessageSizeInBytes);
      }

      //-----------------------------------------------------------------------
      RUDPMessagingPtr IRUDPMessagingFactory::openChannel(
                                                          IMessageQueuePtr queue,
                                                          IRUDPTransportPtr session,
                                                          IRUDPMessagingDelegatePtr delegate,
                                                          const char *connectionInfo,
                                                          ITransportStreamPtr receiveStream,
                                                          ITransportStreamPtr sendStream,
                                                          size_t maxMessageSizeInBytes
                                                          )
      {
        if (this) {}
        return RUDPMessaging::openChannel(queue, session, delegate, connectionInfo, receiveStream, sendStream, maxMessageSizeInBytes);
      }

    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IRUDPMessaging
    #pragma mark

    //-------------------------------------------------------------------------
    const char *IRUDPMessaging::toString(RUDPMessagingStates state)
    {
      switch (state) {
        case IRUDPMessaging::RUDPMessagingState_Connecting:   return "Connecting";
        case IRUDPMessaging::RUDPMessagingState_Connected:    return "Connected";
        case IRUDPMessaging::RUDPMessagingState_ShuttingDown: return "Shutting down";
        case IRUDPMessaging::RUDPMessagingState_Shutdown:     return "Shutdown";
      }
      return "UNDEFINED";
    }

    //-------------------------------------------------------------------------
    const char *IRUDPMessaging::toString(RUDPMessagingShutdownReasons reason)
    {
      return IRUDPChannel::toString((IRUDPChannel::RUDPChannelShutdownReasons)reason);
    }

    //-------------------------------------------------------------------------
    ElementPtr IRUDPMessaging::toDebug(IRUDPMessagingPtr messaging)
    {
      return internal::RUDPMessaging::toDebug(messaging);
    }

    //-------------------------------------------------------------------------
    IRUDPMessagingPtr IRUDPMessaging::acceptChannel(
                                                    IMessageQueuePtr queue,
                                                    IRUDPListenerPtr listener,
                                                    IRUDPMessagingDelegatePtr delegate,
                                                    ITransportStreamPtr receiveStream,
                                                    ITransportStreamPtr sendStream,
                                                    size_t maxMessageSizeInBytes
                                                    )
    {
      return internal::IRUDPMessagingFactory::singleton().acceptChannel(queue, listener, delegate, receiveStream, sendStream, maxMessageSizeInBytes);
    }

    //-------------------------------------------------------------------------
    IRUDPMessagingPtr IRUDPMessaging::acceptChannel(
                                                    IMessageQueuePtr queue,
                                                    IRUDPTransportPtr session,
                                                    IRUDPMessagingDelegatePtr delegate,
                                                    ITransportStreamPtr receiveStream,
                                                    ITransportStreamPtr sendStream,
                                                    size_t maxMessageSizeInBytes
                                                    )
    {
      return internal::IRUDPMessagingFactory::singleton().acceptChannel(queue, session, delegate, receiveStream, sendStream, maxMessageSizeInBytes);
    }

    //-------------------------------------------------------------------------
    IRUDPMessagingPtr IRUDPMessaging::openChannel(
                                                  IMessageQueuePtr queue,
                                                  IRUDPTransportPtr session,
                                                  IRUDPMessagingDelegatePtr delegate,
                                                  const char *connectionInfo,
                                                  ITransportStreamPtr receiveStream,
                                                  ITransportStreamPtr sendStream,
                                                  size_t maxMessageSizeInBytes
                                                  )
    {
      return internal::IRUDPMessagingFactory::singleton().openChannel(queue, session, delegate, connectionInfo, receiveStream, sendStream, maxMessageSizeInBytes);
    }
  }
}
