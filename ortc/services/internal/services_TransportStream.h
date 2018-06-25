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

#include <ortc/services/ITransportStream.h>
#include <ortc/services/internal/types.h>

#include <list>
#include <map>

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
      // TransportStream
      //

      class TransportStream : public Noop,
                              public zsLib::MessageQueueAssociator,
                              public ITransportStream,
                              public ITransportStreamWriter,
                              public ITransportStreamReader
      {
      protected:
        struct make_private {};

      public:
        friend interaction ITransportStreamFactory;
        friend interaction ITransportStream;

        typedef ITransportStream::StreamHeader StreamHeader;
        typedef ITransportStream::StreamHeaderPtr StreamHeaderPtr;
        typedef ITransportStream::StreamHeaderWeakPtr StreamHeaderWeakPtr;
        typedef ITransportStream::Endians Endians;

        struct Buffer
        {
          Buffer() noexcept : mRead(0) {}

          SecureByteBlockPtr mBuffer;
          size_t mRead;
          StreamHeaderPtr mHeader;
        };

        typedef std::list<Buffer> BufferList;

      public:
        TransportStream(
                        const make_private &,
                        IMessageQueuePtr queue,
                        ITransportStreamWriterDelegatePtr writerDelegate = ITransportStreamWriterDelegatePtr(),
                        ITransportStreamReaderDelegatePtr readerDelegate = ITransportStreamReaderDelegatePtr()
                        ) noexcept;

      protected:
        TransportStream(Noop) noexcept :
          Noop(true),
          zsLib::MessageQueueAssociator(IMessageQueuePtr()) {}

        void init() noexcept;

      public:
        ~TransportStream() noexcept;

        static TransportStreamPtr convert(ITransportStreamPtr stream) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // TransportStream => ITransportStream
        //

        static ElementPtr toDebug(ITransportStreamPtr stream) noexcept;

        static TransportStreamPtr create(
                                         ITransportStreamWriterDelegatePtr writerDelegate = ITransportStreamWriterDelegatePtr(),
                                         ITransportStreamReaderDelegatePtr readerDelegate = ITransportStreamReaderDelegatePtr()
                                         ) noexcept;

        PUID getID() const noexcept override {return mID;}

        ITransportStreamWriterPtr getWriter() const noexcept override;
        ITransportStreamReaderPtr getReader() const noexcept override;

        void cancel() noexcept override;

        //---------------------------------------------------------------------
        //
        // TransportStream => ITransportStreamWriter
        //

        // (duplicate) virtual PUID getID() const noexcept override;

        ITransportStreamWriterSubscriptionPtr subscribe(ITransportStreamWriterDelegatePtr delegate) noexcept override;

        ITransportStreamPtr getStream() const noexcept override;

        bool isWriterReady() const noexcept override;

        void write(
                   const BYTE *buffer,
                   size_t bufferLengthInBytes,
                   StreamHeaderPtr header = StreamHeaderPtr()   // not always needed
                   ) noexcept override;

        void write(
                   SecureByteBlockPtr bufferToAdopt,
                   StreamHeaderPtr header = StreamHeaderPtr()   // not always needed
                   ) noexcept override;

        void write(
                   WORD value,
                   StreamHeaderPtr header = StreamHeaderPtr(),  // not always needed
                   Endians endian = ITransportStream::Endian_Big
                   ) noexcept override;

        void write(
                   DWORD value,
                   StreamHeaderPtr header = StreamHeaderPtr(),  // not always needed
                   Endians endian = ITransportStream::Endian_Big
                   ) noexcept override;

        void block(bool block = true) noexcept override;

        //---------------------------------------------------------------------
        //
        // TransportStream => ITransportStreamReader
        //

        // (duplicate) virtual PUID getID() const override;

        ITransportStreamReaderSubscriptionPtr subscribe(ITransportStreamReaderDelegatePtr delegate) noexcept override;

        // (duplicate) ITransportStreamPtr getStream() const noexcept override;

        void notifyReaderReadyToRead() noexcept override;

        size_t getNextReadSizeInBytes() const noexcept override;

        StreamHeaderPtr getNextReadHeader() const noexcept override;

        size_t getTotalReadBuffersAvailable() const noexcept override;

        size_t getTotalReadSizeAvailableInBytes() const noexcept override;

        size_t read(
                    BYTE *outBuffer,
                    size_t bufferLengthInBytes,
                    StreamHeaderPtr *outHeader = NULL
                    ) noexcept override;

        SecureByteBlockPtr read(StreamHeaderPtr *outHeader = NULL) noexcept override;

        size_t readWORD(
                        WORD &outResult,
                        StreamHeaderPtr *outHeader = NULL,
                        Endians endian = ITransportStream::Endian_Big
                        ) noexcept override;

        size_t readDWORD(
                         DWORD &outResult,
                         StreamHeaderPtr *outHeader = NULL,
                         Endians endian = ITransportStream::Endian_Big
                         ) noexcept override;

        size_t peek(
                    BYTE *outBuffer,
                    size_t bufferLengthInBytes,
                    StreamHeaderPtr *outHeader = NULL,
                    size_t offsetInBytes = 0
                    ) noexcept override;

        SecureByteBlockPtr peek(
                                size_t bufferLengthInBytes = 0,
                                StreamHeaderPtr *outHeader = NULL,
                                size_t offsetInBytes = 0
                                ) noexcept override;

        size_t peekWORD(
                        WORD &outResult,
                        StreamHeaderPtr *outHeader = NULL,
                        size_t offsetInBytes = 0,
                        Endians endian = ITransportStream::Endian_Big
                        ) noexcept override;

        size_t peekDWORD(
                         DWORD &outResult,
                         StreamHeaderPtr *outHeader = NULL,
                         size_t offsetInBytes = 0,
                         Endians endian = ITransportStream::Endian_Big
                         ) noexcept override;

        size_t skip(size_t offsetInBytes) noexcept override;

      protected:
        //---------------------------------------------------------------------
        //
        // StreamTransport => (internal)
        //

        RecursiveLock &getLock() const noexcept;
        Log::Params log(const char *message) const noexcept;
        Log::Params debug(const char *message) const noexcept;

        virtual ElementPtr toDebug() const noexcept;

        bool isShutdown() const noexcept {return mShutdown;}

        void notifySubscribers(
                               bool afterRead,
                               bool afterWrite
                               ) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // StreamTransport => (data)
        //

        AutoPUID mID;
        mutable RecursiveLock mLock;
        TransportStreamWeakPtr mThisWeak;

        bool mShutdown {};
        bool mReaderReady {};

        bool mReadReadyNotified {};
        bool mWriteReadyNotified {};

        ITransportStreamWriterDelegateSubscriptions mWriterSubscriptions;
        ITransportStreamWriterSubscriptionPtr mDefaultWriterSubscription;

        ITransportStreamReaderDelegateSubscriptions mReaderSubscriptions;
        ITransportStreamReaderSubscriptionPtr mDefaultReaderSubscription;

        BufferList mBuffers;

        ByteQueuePtr mBlockQueue;
        StreamHeaderPtr mBlockHeader;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // ITransportStreamFactor
      //

      interaction ITransportStreamFactory
      {
        static ITransportStreamFactory &singleton() noexcept;

        virtual TransportStreamPtr create(
                                          ITransportStreamWriterDelegatePtr writerDelegate = ITransportStreamWriterDelegatePtr(),
                                          ITransportStreamReaderDelegatePtr readerDelegate = ITransportStreamReaderDelegatePtr()
                                          ) noexcept;
      };

      class TransportStreamFactory : public IFactory<ITransportStreamFactory> {};
    }
  }
}
