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

#include <openpeer/services/internal/services_TransportStream.h>
#include <openpeer/services/internal/services_Helper.h>

#include <cryptopp/queue.h>

#include <zsLib/Log.h>
#include <zsLib/helpers.h>
#include <zsLib/XML.h>
#include <zsLib/Stringize.h>


namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services_transport_stream) } }

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
      #pragma mark (helpers)
      #pragma mark


      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark TransportStream
      #pragma mark

      //-----------------------------------------------------------------------
      TransportStream::TransportStream(
                                       IMessageQueuePtr queue,
                                       ITransportStreamWriterDelegatePtr writerDelegate,
                                       ITransportStreamReaderDelegatePtr readerDelegate
                                       ) :
        zsLib::MessageQueueAssociator(queue)
      {
        ZS_LOG_DEBUG(log("created"))
        if (writerDelegate) {
          mDefaultWriterSubscription = mWriterSubscriptions.subscribe(writerDelegate);
        }
        if (readerDelegate) {
          mDefaultReaderSubscription = mReaderSubscriptions.subscribe(readerDelegate);
        }
      }

      //-----------------------------------------------------------------------
      void TransportStream::init()
      {
      }

      //-----------------------------------------------------------------------
      TransportStream::~TransportStream()
      {
        ZS_LOG_DEBUG(log("destroyed"))
        mThisWeak.reset();
        cancel();
      }

      //-----------------------------------------------------------------------
      TransportStreamPtr TransportStream::convert(ITransportStreamPtr stream)
      {
        return ZS_DYNAMIC_PTR_CAST(TransportStream, stream);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark TransportStream => ITransportStream
      #pragma mark

      //-----------------------------------------------------------------------
      ElementPtr TransportStream::toDebug(ITransportStreamPtr stream)
      {
        if (!stream) return ElementPtr();

        TransportStreamPtr pThis = TransportStream::convert(stream);
        return pThis->toDebug();
      }

      //-----------------------------------------------------------------------
      TransportStreamPtr TransportStream::create(
                                                 ITransportStreamWriterDelegatePtr writerDelegate,
                                                 ITransportStreamReaderDelegatePtr readerDelegate
                                                 )
      {
        TransportStreamPtr pThis(new TransportStream(IHelper::getServiceQueue(), writerDelegate, readerDelegate));
        pThis->mThisWeak = pThis;
        pThis->init();
        return pThis;
      }

      //-----------------------------------------------------------------------
      ITransportStreamWriterPtr TransportStream::getWriter() const
      {
        return mThisWeak.lock();
      }

      //-----------------------------------------------------------------------
      ITransportStreamReaderPtr TransportStream::getReader() const
      {
        return mThisWeak.lock();
      }

      //-----------------------------------------------------------------------
      void TransportStream::cancel()
      {
        AutoRecursiveLock lock(getLock());

        ZS_LOG_DEBUG(debug("cancel called"))

        mShutdown = true;

        mWriterSubscriptions.clear();
        mDefaultWriterSubscription.reset();

        mReaderSubscriptions.clear();
        mDefaultReaderSubscription.reset();

        mBuffers.clear();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark TransportStream => ITransportStreamWriter
      #pragma mark

      //-----------------------------------------------------------------------
      ITransportStreamWriterSubscriptionPtr TransportStream::subscribe(ITransportStreamWriterDelegatePtr originalDelegate)
      {
        AutoRecursiveLock lock(getLock());

        if (!originalDelegate) {
          return mDefaultWriterSubscription;
        }

        ITransportStreamWriterSubscriptionPtr subscription = mWriterSubscriptions.subscribe(originalDelegate);

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          subscription->cancel();
          return subscription;
        }

        if ((mBuffers.size() < 1) &&
            (mReaderReady)) {
          ITransportStreamWriterDelegatePtr delegate = mWriterSubscriptions.delegate(subscription);
          if (delegate) {
            ZS_LOG_DEBUG(log("notifying new subscriber write ready"))
            delegate->onTransportStreamWriterReady(mThisWeak.lock());
          }
        }

        return subscription;
      }

      //-----------------------------------------------------------------------
      ITransportStreamPtr TransportStream::getStream() const
      {
        AutoRecursiveLock lock(getLock());
        return mThisWeak.lock();
      }

      //-----------------------------------------------------------------------
      bool TransportStream::isWriterReady() const
      {
        AutoRecursiveLock lock(getLock());
        if (isShutdown()) return false;
        return mReaderReady;
      }

      //-----------------------------------------------------------------------
      void TransportStream::write(
                                  const BYTE *inBuffer,
                                  size_t bufferLengthInBytes,
                                  StreamHeaderPtr header
                                  )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!inBuffer)

        AutoRecursiveLock lock(getLock());

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("cannot write as already shutdown"))
          return;
        }

        if (mBlockQueue) {
          ZS_LOG_TRACE(log("write blocked thus putting buffer into block queue") + ZS_PARAM("size", bufferLengthInBytes) + ZS_PARAM("header", (bool)header))
          if (!mBlockHeader) {
            mBlockHeader = header;
          }
          if (bufferLengthInBytes > 0) {
            mBlockQueue->Put(inBuffer, bufferLengthInBytes);
          }
          return;
        }

        write(IHelper::convertToBuffer(inBuffer, bufferLengthInBytes), header);
      }

      //-----------------------------------------------------------------------
      void TransportStream::write(
                                  SecureByteBlockPtr bufferToAdopt,
                                  StreamHeaderPtr header
                                  )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!bufferToAdopt)

        AutoRecursiveLock lock(getLock());

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("cannot write as already shutdown"))
          return;
        }

        if (mBlockQueue) {
          ZS_LOG_TRACE(log("write blocked thus putting buffer into block queue") + ZS_PARAM("size", bufferToAdopt->SizeInBytes()) + ZS_PARAM("header", (bool)header))
          if (!mBlockHeader) {
            mBlockHeader = header;
          }
          if (bufferToAdopt->SizeInBytes() > 0) {
            mBlockQueue->Put(bufferToAdopt->BytePtr(), bufferToAdopt->SizeInBytes());
          }
          return;
        }

        Buffer buffer;
        buffer.mBuffer = bufferToAdopt;
        buffer.mHeader = header;

        ZS_LOG_TRACE(log("buffer written") + ZS_PARAM("written", bufferToAdopt->SizeInBytes()) )

        mBuffers.push_back(buffer);

        notifySubscribers(false, true);
      }

      //-----------------------------------------------------------------------
      void TransportStream::write(
                                  WORD value,
                                  StreamHeaderPtr header,
                                  Endians endian
                                  )
      {
        BYTE buffer[sizeof(WORD)] = {0,0};
        if (endian == Endian_Big)
        {
          buffer[0] = ((value & 0xFF00) >> 8);
          buffer[1] = (value & 0xFF);
        } else {
          buffer[1] = ((value & 0xFF00) >> 8);
          buffer[0] = (value & 0xFF);
        }
        write(&(buffer[0]), sizeof(buffer), header);
      }

      //-----------------------------------------------------------------------
      void TransportStream::write(
                                  DWORD value,
                                  StreamHeaderPtr header,
                                  Endians endian
                                  )
      {
        BYTE buffer[sizeof(DWORD)] = {0,0,0,0};
        if (endian == Endian_Big)
        {
          buffer[0] = (BYTE)((value & 0xFF000000) >> 24);
          buffer[1] = (BYTE)((value & 0xFF0000) >> 16);
          buffer[2] = (BYTE)((value & 0xFF00) >> 8);
          buffer[3] = (BYTE)(value & 0xFF);
        } else {
          buffer[3] = (BYTE)((value & 0xFF000000) >> 24);
          buffer[2] = (BYTE)((value & 0xFF0000) >> 16);
          buffer[1] = (BYTE)((value & 0xFF00) >> 8);
          buffer[0] = (BYTE)(value & 0xFF);
        }
        write(&(buffer[0]), sizeof(buffer), header);
      }

      //-----------------------------------------------------------------------
      void TransportStream::block(bool block)
      {
        AutoRecursiveLock lock(getLock());

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("cannot write as already shutdown"))
          return;
        }

        if (block) {
          if (mBlockQueue) {
            ZS_LOG_WARNING(Detail, log("already blocking thus nothing to do"))
            return;
          }

          ZS_LOG_DEBUG(log("blocking enabled"))

          mBlockQueue = ByteQueuePtr(new ByteQueue);
          mBlockHeader.reset();
          return;
        }

        // unblocking
        if (!mBlockQueue) {
          ZS_LOG_WARNING(Detail, log("was not blocking thus nothing to do"))
          return;
        }

        size_t size = static_cast<size_t>(mBlockQueue->CurrentSize());
        if ((size < 1) &&
            (!mBlockHeader)) {

          ZS_LOG_DEBUG(log("no data written during block thus nothing to do"))

          mBlockQueue.reset();
          mBlockHeader.reset();
          return;
        }

        SecureByteBlockPtr buffer(new SecureByteBlock(size));
        if (size > 0) {
          mBlockQueue->Get(buffer->BytePtr(), size);
        }

        StreamHeaderPtr header = mBlockHeader;

        mBlockQueue.reset();
        mBlockHeader.reset();

        write(buffer, header);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark TransportStream => ITransportStreamReader
      #pragma mark

      //-----------------------------------------------------------------------
      ITransportStreamReaderSubscriptionPtr TransportStream::subscribe(ITransportStreamReaderDelegatePtr originalDelegate)
      {
        AutoRecursiveLock lock(getLock());

        if (!originalDelegate) {
          return mDefaultReaderSubscription;
        }

        ITransportStreamReaderSubscriptionPtr subscription = mReaderSubscriptions.subscribe(originalDelegate);

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          subscription->cancel();
          return subscription;
        }

        if ((mBuffers.size() > 0) &&
            (mReaderReady)) {
          ITransportStreamReaderDelegatePtr delegate = mReaderSubscriptions.delegate(subscription);
          if (delegate) {
            ZS_LOG_TRACE(log("notifying new subscriber ready to read"))
            delegate->onTransportStreamReaderReady(mThisWeak.lock());
          }
        }

        return subscription;
      }

      //-----------------------------------------------------------------------
      void TransportStream::notifyReaderReadyToRead()
      {
        AutoRecursiveLock lock(getLock());
        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }
        mReaderReady = true;
        notifySubscribers(false, false);
      }

      //-----------------------------------------------------------------------
      size_t TransportStream::getNextReadSizeInBytes() const
      {
        AutoRecursiveLock lock(getLock());

        if (mBuffers.size() < 1) {
          ZS_LOG_TRACE(log("no read buffers available") + ZS_PARAM("read size", 0))
          return 0;
        }

        const Buffer &buffer = mBuffers.front();

        size_t readSize = (buffer.mBuffer->SizeInBytes() - buffer.mRead);

        ZS_LOG_TRACE(log("read size") + ZS_PARAM("read size", readSize))

        return readSize;
      }

      //-----------------------------------------------------------------------
      TransportStream::StreamHeaderPtr TransportStream::getNextReadHeader() const
      {
        AutoRecursiveLock lock(getLock());

        if (mBuffers.size() < 1) {
          ZS_LOG_TRACE(log("no read buffers available") + ZS_PARAM("header returned", false))
          return StreamHeaderPtr();
        }

        const Buffer &buffer = mBuffers.front();

        ZS_LOG_TRACE(log("header returned") + ZS_PARAM("header", (bool)buffer.mHeader))
        
        return buffer.mHeader;
      }

      //-----------------------------------------------------------------------
      size_t TransportStream::getTotalReadBuffersAvailable() const
      {
        AutoRecursiveLock lock(getLock());
        return mBuffers.size();
      }
      
      //-----------------------------------------------------------------------
      size_t TransportStream::getTotalReadSizeAvailableInBytes() const
      {
        AutoRecursiveLock lock(getLock());

        size_t total = 0;
        for (BufferList::const_iterator iter = mBuffers.begin(); iter != mBuffers.end(); ++iter)
        {
          const Buffer &buffer = (*iter);
          total += (buffer.mBuffer->SizeInBytes() - buffer.mRead);
        }

        ZS_LOG_TRACE(log("total read size available") + ZS_PARAM("read size", total) + ZS_PARAM("buffers", mBuffers.size()))

        return total;
      }

      //-----------------------------------------------------------------------
      size_t TransportStream::read(
                                   BYTE *outBuffer,
                                   size_t bufferLengthInBytes,
                                   StreamHeaderPtr *outHeader
                                   )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!outBuffer)

        if (outHeader) {
          *outHeader = StreamHeaderPtr();
        }

        AutoRecursiveLock lock(getLock());

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("cannot read as already shutdown"))
          return 0;
        }

        if (0 == bufferLengthInBytes) {
          // this is a special case, only legal if there is a "0" sized buffer
          if (mBuffers.size() < 1) {
            ZS_LOG_WARNING(Detail, log("no zero sized buffers available to read"))
            return 0;
          }

          Buffer &buffer = mBuffers.front();
          if (0 != buffer.mBuffer->SizeInBytes()) {
            ZS_LOG_WARNING(Detail, log("no zero sized buffers available to read"))
            return 0;
          }

          // this is a special "0" sized buffer, extract it
          if (outHeader) {
            *outHeader = buffer.mHeader;
          }

          ZS_LOG_TRACE(log("reading zero sized buffer"))

          mBuffers.pop_front();
          return 0;
        }

        BYTE *dest = outBuffer;

        size_t totalRead = 0;
        bool first = true;

        while (0 != bufferLengthInBytes)
        {
          if (mBuffers.size() < 1) {
            ZS_LOG_TRACE(log("no more buffered data available to read"))
            break;
          }

          Buffer &buffer = mBuffers.front();

          if (first) {
            if (outHeader) {
              *outHeader = buffer.mHeader;
            }
            first = false;
          }

          size_t available = (buffer.mBuffer->SizeInBytes() - buffer.mRead);

          size_t consume = (bufferLengthInBytes > available ? available : bufferLengthInBytes);

          const BYTE *source = buffer.mBuffer->BytePtr() + buffer.mRead;

          memcpy(dest, source, consume);

          buffer.mRead += consume;
          totalRead += consume;
          bufferLengthInBytes -= consume;
          dest += consume;

          ZS_LOG_TRACE(log("buffer read") + ZS_PARAM("read", consume) + ZS_PARAM("buffer available", available) + ZS_PARAM("remaining", bufferLengthInBytes))

          if (buffer.mRead == buffer.mBuffer->SizeInBytes()) {
            // entire buffer has not been consumed, remove it
            ZS_LOG_TRACE(log("entire buffer consumed") + ZS_PARAM("buffer size", buffer.mRead))
            mBuffers.pop_front();
            continue;
          }
        }

        notifySubscribers(true, false);

        return totalRead;
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr TransportStream::read(StreamHeaderPtr *outHeader)
      {
        if (outHeader) {
          *outHeader = StreamHeaderPtr();
        }

        AutoRecursiveLock lock(getLock());

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("cannot read as already shutdown"))
          return SecureByteBlockPtr();
        }

        if (mBuffers.size() < 1) return SecureByteBlockPtr();

        SecureByteBlockPtr result;
        // scope: read one writtenn buffer
        {
          Buffer &buffer = mBuffers.front();

          result = buffer.mBuffer;
          if (outHeader) {
            *outHeader = buffer.mHeader;
          }
          if (buffer.mRead > 0) {
            size_t resultSize = result->SizeInBytes() - buffer.mRead;

            SecureByteBlockPtr temp(new SecureByteBlock(resultSize));
            memcpy(temp->BytePtr(), result->BytePtr() + buffer.mRead, resultSize);

            result = temp;
          }

          ZS_LOG_TRACE(log("buffer read") + ZS_PARAM("read", result->SizeInBytes()))

          mBuffers.pop_front();
        }

        notifySubscribers(true, false);

        return result;
      }

      //-----------------------------------------------------------------------
      size_t TransportStream::readWORD(
                                       WORD &outResult,
                                       StreamHeaderPtr *outHeader,
                                       Endians endian
                                       )
      {
        outResult = 0;

        BYTE buffer[sizeof(WORD)] = {0,0};
        size_t totalRead = read((&(buffer[0])), sizeof(buffer), outHeader);

        if (Endian_Big == endian)
          outResult = (((WORD)buffer[0]) << 8) | buffer[1];
        else
          outResult = (((WORD)buffer[1]) << 8) | buffer[0];

        return totalRead;
      }

      //-----------------------------------------------------------------------
      size_t TransportStream::readDWORD(
                                        DWORD &outResult,
                                        StreamHeaderPtr *outHeader,
                                        Endians endian
                                        )
      {
        outResult = 0;

        BYTE buffer[sizeof(DWORD)] = {0,0,0,0};
        size_t totalRead = read((&(buffer[0])), sizeof(buffer), outHeader);

        if (Endian_Big == endian)
          outResult = (((DWORD)buffer[0]) << 24) | (((DWORD)buffer[1]) << 16) | (((DWORD)buffer[2]) << 8) | buffer[3];
        else
          outResult = (((DWORD)buffer[3]) << 24) | (((DWORD)buffer[2]) << 16) | (((DWORD)buffer[1]) << 8) | buffer[0];

        return totalRead;
      }

      //-----------------------------------------------------------------------
      size_t TransportStream::peek(
                                   BYTE *outBuffer,
                                   size_t bufferLengthInBytes,
                                   StreamHeaderPtr *outHeader,
                                   size_t offsetInBytes
                                   )
      {
        if (0 != bufferLengthInBytes) {
          ZS_THROW_INVALID_ARGUMENT_IF(!outBuffer)
        }

        if (outHeader) {
          *outHeader = StreamHeaderPtr();
        }

        ZS_LOG_TRACE(log("peek") + ZS_PARAM("size", bufferLengthInBytes) + ZS_PARAM("offset", offsetInBytes))

        AutoRecursiveLock lock(getLock());

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("cannot peek as already shutdown"))
          return 0;
        }

        if (mBuffers.size() < 1) return 0;

        bool didHeader = false;

        size_t totalRead = 0;
        BYTE *dest = outBuffer;

        BufferList::iterator iter = mBuffers.begin();

        while (true)
        {
          if (iter == mBuffers.end()) {
            ZS_LOG_TRACE(log("no more buffers available to peek"))
            break;
          }

          Buffer &buffer = (*iter);

          size_t read = buffer.mRead;
          size_t available = buffer.mBuffer->SizeInBytes() - buffer.mRead;

          ZS_LOG_TRACE(log("next peek buffer found") + ZS_PARAM("size", buffer.mBuffer->SizeInBytes()) + ZS_PARAM("read", read) + ZS_PARAM("available", available))

          if (offsetInBytes > 0) {
            // first consume the offset
            size_t consume = offsetInBytes > available ? available : offsetInBytes;
            offsetInBytes -= consume;
            read += consume;
            available -= consume;

            ZS_LOG_TRACE(log("skipping over bytes") + ZS_PARAM("size", consume) + ZS_PARAM("remaining offset", offsetInBytes) + ZS_PARAM("available", available) + ZS_PARAM("read", read))
          }

          if (0 == available) {
            ++iter;
            continue;
          }

          ZS_THROW_BAD_STATE_IF(offsetInBytes > 0)

          if (!didHeader) {
            if (outHeader) {
              *outHeader = buffer.mHeader;
            }
            didHeader = true;
          }

          if (0 == bufferLengthInBytes) break;

          size_t consume = bufferLengthInBytes > available ? available : bufferLengthInBytes;

          memcpy(dest, buffer.mBuffer->BytePtr() + read, consume);

          dest += consume;
          read += consume;
          available -= consume;
          bufferLengthInBytes -= consume;
          totalRead += consume;

          ZS_LOG_TRACE(log("peeking buffer") + ZS_PARAM("size", consume) + ZS_PARAM("read", read) + ZS_PARAM("available", available) + ZS_PARAM("remainging data to peek", bufferLengthInBytes))

          if (0 == bufferLengthInBytes) {
            ZS_LOG_TRACE(log("peeked all requested"))
            break;
          }

          ZS_THROW_BAD_STATE_IF(0 != available)
          ++iter;
        }

        return totalRead;
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr TransportStream::peek(
                                               size_t bufferLengthInBytes,
                                               StreamHeaderPtr *outHeader,
                                               size_t offsetInBytes
                                               )
      {
        if (0 == bufferLengthInBytes) {
          // peeking next buffer
          if (mBuffers.size() > 0) {
            Buffer &buffer = mBuffers.front();
            bufferLengthInBytes = buffer.mBuffer->SizeInBytes() - buffer.mRead;
          }
        }

        SecureByteBlockPtr result(new SecureByteBlock(bufferLengthInBytes));

        size_t read = peek(0 != bufferLengthInBytes ? result->BytePtr() : NULL, bufferLengthInBytes, outHeader);

        if (0 == read) {
          ZS_LOG_TRACE(log("peek found no buffered data so returning NULL buffer"))
          return SecureByteBlockPtr();
        }

        if (read < result->SizeInBytes()) {
          ZS_LOG_TRACE(log("peek completed but read less than expecting / hoping to read") + ZS_PARAM("read", read) + ZS_PARAM("expecting", result->SizeInBytes()))

          // read less than the expected size
          SecureByteBlockPtr newResult(new SecureByteBlock(read));

          memcpy(newResult->BytePtr(), result->BytePtr(), read);
          return newResult;
        }

        ZS_LOG_TRACE(log("peek completed") + ZS_PARAM("read", read))
        return result;
      }

      //-----------------------------------------------------------------------
      size_t TransportStream::peekWORD(
                                       WORD &outResult,
                                       StreamHeaderPtr *outHeader,
                                       size_t offsetInBytes,
                                       Endians endian
                                       )
      {
        outResult = 0;

        BYTE buffer[sizeof(WORD)] = {0,0};
        size_t totalRead = peek((&(buffer[0])), sizeof(buffer), outHeader, offsetInBytes);

        if (Endian_Big == endian)
          outResult = (((WORD)buffer[0]) << 8) | buffer[1];
        else
          outResult = (((WORD)buffer[1]) << 8) | buffer[0];

        return totalRead;
      }

      //-----------------------------------------------------------------------
      size_t TransportStream::peekDWORD(
                                        DWORD &outResult,
                                        StreamHeaderPtr *outHeader,
                                        size_t offsetInBytes,
                                        Endians endian
                                        )
      {
        outResult = 0;

        BYTE buffer[sizeof(DWORD)] = {0,0,0,0};
        size_t totalRead = peek((&(buffer[0])), sizeof(buffer), outHeader, offsetInBytes);

        if (Endian_Big == endian)
          outResult = (((DWORD)buffer[0]) << 24) | (((DWORD)buffer[1]) << 16) | (((DWORD)buffer[2]) << 8) | buffer[3];
        else
          outResult = (((DWORD)buffer[3]) << 24) | (((DWORD)buffer[2]) << 16) | (((DWORD)buffer[1]) << 8) | buffer[0];
        
        return totalRead;
      }

      //-----------------------------------------------------------------------
      size_t TransportStream::skip(size_t offsetInBytes)
      {
        ZS_LOG_TRACE(log("skip called") + ZS_PARAM("skip", offsetInBytes))

        AutoRecursiveLock lock(getLock());

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("cannot read as already shutdown"))
          return 0;
        }

        if (0 == offsetInBytes) {
          ZS_LOG_TRACE(log("nothing to skip"))
          return 0;
        }

        size_t totalRead = 0;

        while (0 != offsetInBytes)
        {
          if (mBuffers.size() < 1) {
            ZS_LOG_TRACE(log("no more buffered data available to skip"))
            break;
          }

          Buffer &buffer = mBuffers.front();

          size_t available = (buffer.mBuffer->SizeInBytes() - buffer.mRead);

          size_t consume = (offsetInBytes > available ? available : offsetInBytes);

          buffer.mRead += consume;
          totalRead += consume;
          offsetInBytes -= consume;

          ZS_LOG_TRACE(log("buffer read") + ZS_PARAM("read", consume) + ZS_PARAM("buffer available", available) + ZS_PARAM("remaining to skip", offsetInBytes))

          if (buffer.mRead == buffer.mBuffer->SizeInBytes()) {
            // entire buffer has not been consumed, remove it
            ZS_LOG_TRACE(log("entire buffer consumed") + ZS_PARAM("buffer size", buffer.mRead))
            mBuffers.pop_front();
            continue;
          }
        }
        
        notifySubscribers(true, false);
        
        return totalRead;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark TransportStream  => (internal)
      #pragma mark

      //-----------------------------------------------------------------------
      RecursiveLock &TransportStream::getLock() const
      {
        return mLock;
      }

      //-----------------------------------------------------------------------
      Log::Params TransportStream::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("TransportStream");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params TransportStream::debug(const char *message) const
      {
        return Log::Params(message, toDebug());
      }

      //-----------------------------------------------------------------------
      ElementPtr TransportStream::toDebug() const
      {
        AutoRecursiveLock lock(getLock());

        ElementPtr resultEl = Element::create("TCPMessaging");

        IHelper::debugAppend(resultEl, "id", mID);

        IHelper::debugAppend(resultEl, "shutdown", mShutdown);
        IHelper::debugAppend(resultEl, "reader ready", mReaderReady);
        IHelper::debugAppend(resultEl, "read ready notified", mReadReadyNotified);
        IHelper::debugAppend(resultEl, "write ready notified", mWriteReadyNotified);
        IHelper::debugAppend(resultEl, "writer subscriptions", mWriterSubscriptions.size());
        IHelper::debugAppend(resultEl, "default writer subscription", (bool)mDefaultWriterSubscription);
        IHelper::debugAppend(resultEl, "reader subscriptions", mReaderSubscriptions.size());
        IHelper::debugAppend(resultEl, "default reader subscription", (bool)mDefaultReaderSubscription);
        IHelper::debugAppend(resultEl, "buffers", mBuffers.size());
        IHelper::debugAppend(resultEl, "block queue", (bool)mBlockQueue);
        IHelper::debugAppend(resultEl, "block header", (bool)mBlockHeader);

        return resultEl;
      }

      //-----------------------------------------------------------------------
      void TransportStream::notifySubscribers(
                                              bool afterRead,
                                              bool afterWrite
                                              )
      {
        if (afterRead) {
          mReaderReady = true;          // reader must be ready if read was called
          mReadReadyNotified = false;   // after a read operation, a new read notification should fire (if applicable)
        }

        if (afterWrite) {
          mReadReadyNotified = false;   // after every write operation, a new read notification should fire (if applicable)
          mWriteReadyNotified = false;  // after data is written, the notification will have to fire again later when buffer is emptied
        }

        // only notify if this is the first buffer added or after each read operation (as have to wait until read called before notifying again)
        bool notifyRead = ((mBuffers.size() > 0) &&
                           (!mReadReadyNotified));

        bool notifyWrite = ((mBuffers.size() < 1) &&
                            (mReaderReady) &&         // can only notify write ready when reader has reported it's ready to read
                            (!mWriteReadyNotified));

        if (notifyRead) {
          ZS_LOG_TRACE(log("notifying ready to read") + ZS_PARAM("subscribers", mReaderSubscriptions.size()))
          mReaderSubscriptions.delegate()->onTransportStreamReaderReady(mThisWeak.lock());

          mReadReadyNotified = true;
        }

        if (notifyWrite) {
          ZS_LOG_TRACE(log("notifying ready to write") + ZS_PARAM("subscribers", mWriterSubscriptions.size()))
          mWriterSubscriptions.delegate()->onTransportStreamWriterReady(mThisWeak.lock());

          mWriteReadyNotified = true;
        }
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ITransportStreamFactory
      #pragma mark

      //-----------------------------------------------------------------------
      ITransportStreamFactory &ITransportStreamFactory::singleton()
      {
        return TransportStreamFactory::singleton();
      }

      //-----------------------------------------------------------------------
      TransportStreamPtr ITransportStreamFactory::create(
                                                         ITransportStreamWriterDelegatePtr writerDelegate,
                                                         ITransportStreamReaderDelegatePtr readerDelegate
                                                         )
      {
        if (this) {}
        return internal::TransportStream::create(writerDelegate, readerDelegate);
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
    #pragma mark IStreamTransport
    #pragma mark

    //-----------------------------------------------------------------------
    const char *ITransportStream::toString(Endians endian)
    {
      switch (endian) {
        case Endian_Big:    return "big";
        case Endian_Little: return "little";
      }
      return "UNDEFINED";
    }

    //-----------------------------------------------------------------------
    ElementPtr ITransportStream::toDebug(ITransportStreamPtr stream)
    {
      return internal::TransportStream::toDebug(stream);
    }
    
    //-----------------------------------------------------------------------
    ITransportStreamPtr ITransportStream::create(
                                                 ITransportStreamWriterDelegatePtr writerDelegate,
                                                 ITransportStreamReaderDelegatePtr readerDelegate
                                                 )
    {
      return internal::ITransportStreamFactory::singleton().create(writerDelegate, readerDelegate);
    }
  }
}
