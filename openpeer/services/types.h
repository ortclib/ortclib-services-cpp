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

#ifdef _WIN32
#include <intsafe.h>
#endif //_WIN32

#include <zsLib/types.h>
#include <zsLib/Proxy.h>
#include <zsLib/ProxySubscriptions.h>

#include <zsLib/MessageQueueThread.h>

// special case where CryptoPP extension class is needed
#include <openpeer/services/internal/services_AllocatorWithNul.h>

namespace openpeer
{
  namespace services
  {
    namespace internal
    {
      void throwOnlySetOnce();
    }

    using zsLib::PUID;
    using zsLib::CHAR;
    using zsLib::UCHAR;
    using zsLib::BYTE;
    using zsLib::WORD;
    using zsLib::SHORT;
    using zsLib::USHORT;
    using zsLib::INT;
    using zsLib::UINT;
    using zsLib::LONG;
    using zsLib::ULONG;
    using zsLib::LONGLONG;
    using zsLib::ULONGLONG;
    using zsLib::FLOAT;
    using zsLib::DOUBLE;
    using zsLib::DWORD;
    using zsLib::QWORD;
    using zsLib::String;
    using zsLib::Time;
    using zsLib::Hours;
    using zsLib::Minutes;
    using zsLib::Seconds;
    using zsLib::Milliseconds;
    using zsLib::Microseconds;
    using zsLib::Nanoseconds;
    using zsLib::IPAddress;
    using zsLib::Lock;
    using zsLib::RecursiveLock;
    using zsLib::AutoLock;
    using zsLib::Log;
    using zsLib::Singleton;

    typedef zsLib::ThreadPriorities ThreadPriorities;

    ZS_DECLARE_TYPEDEF_PTR(zsLib::RecursiveLock, RecursiveLock)
    ZS_DECLARE_TYPEDEF_PTR(zsLib::AutoRecursiveLock, AutoRecursiveLock)

    class SharedRecursiveLock
    {
    public:
      static SharedRecursiveLock create() {return SharedRecursiveLock(RecursiveLockPtr(new RecursiveLock));}

      SharedRecursiveLock(const SharedRecursiveLock &source) : mLock(source.mLock) {}
      SharedRecursiveLock(RecursiveLockPtr shared) : mLock(shared) {}

      RecursiveLock &lock() const {return *mLock;}

      operator RecursiveLock & () const {return *mLock;}

      void setLock(const SharedRecursiveLock &replacement) {mLock = replacement.mLock;}
      void setLock(RecursiveLockPtr replacement) {mLock = replacement;}

    private:
      SharedRecursiveLock() {}  // illegal
      mutable RecursiveLockPtr mLock;
    };

    template<typename T, bool setOnceOnly = false>
    class LockedValue
    {
    public:
      LockedValue() : mSet(false) {}
      ~LockedValue() {}

      T get() const {AutoLock lock(mLock); return mValue;}
      void set(T value) {AutoLock lock(mLock); if ((setOnceOnly) && (mSet)) internal::throwOnlySetOnce(); mValue = value; mSet = true;}

    protected:
      mutable Lock mLock;
      T mValue;
      bool mSet;
    };

    ZS_DECLARE_USING_PTR(zsLib, Socket)
    ZS_DECLARE_USING_PTR(zsLib, ISocketDelegate)
    ZS_DECLARE_USING_PTR(zsLib, IMessageQueue)

    ZS_DECLARE_USING_PTR(zsLib::XML, Element)
    ZS_DECLARE_USING_PTR(zsLib::XML, Document)

    typedef CryptoPP::SecBlock<byte, CryptoPP::AllocatorWithNul<byte> > SecureByteBlockWithNulAllocator;
    ZS_DECLARE_TYPEDEF_PTR(SecureByteBlockWithNulAllocator, SecureByteBlock)

    ZS_DECLARE_INTERACTION_PTR(IBackgrounding)
    ZS_DECLARE_INTERACTION_PTR(IBackgroundingNotifier)
    ZS_DECLARE_INTERACTION_PTR(IBackgroundingQuery)
    ZS_DECLARE_INTERACTION_PTR(IBackOffTimer)
    ZS_DECLARE_INTERACTION_PTR(ICache)
    ZS_DECLARE_INTERACTION_PTR(ICacheDelegate)
    ZS_DECLARE_INTERACTION_PTR(ICanonicalXML)
    ZS_DECLARE_INTERACTION_PTR(IDHKeyDomain)
    ZS_DECLARE_INTERACTION_PTR(IDHPrivateKey)
    ZS_DECLARE_INTERACTION_PTR(IDHPublicKey)
    ZS_DECLARE_INTERACTION_PTR(IDecryptor)
    ZS_DECLARE_INTERACTION_PTR(IDNS)
    ZS_DECLARE_INTERACTION_PTR(IDNSQuery)
    ZS_DECLARE_INTERACTION_PTR(IEncryptor)
    ZS_DECLARE_INTERACTION_PTR(IHelper)
    ZS_DECLARE_INTERACTION_PTR(IICESocket)
    ZS_DECLARE_INTERACTION_PTR(IICESocketSession)
    ZS_DECLARE_INTERACTION_PTR(IHTTP)
    ZS_DECLARE_INTERACTION_PTR(IHTTPQuery)
    ZS_DECLARE_INTERACTION_PTR(IMessageLayerSecurityChannel)
    ZS_DECLARE_INTERACTION_PTR(IMessageQueueManager)
    ZS_DECLARE_INTERACTION_PTR(IReachability)
    ZS_DECLARE_INTERACTION_PTR(IRSAPrivateKey)
    ZS_DECLARE_INTERACTION_PTR(IRSAPublicKey)
    ZS_DECLARE_INTERACTION_PTR(IRUDPListener)
    ZS_DECLARE_INTERACTION_PTR(IRUDPMessaging)
    ZS_DECLARE_INTERACTION_PTR(IRUDPChannel)
    ZS_DECLARE_INTERACTION_PTR(IRUDPTransport)
    ZS_DECLARE_INTERACTION_PTR(ISettings)
    ZS_DECLARE_INTERACTION_PTR(ISettingsDelegate)
    ZS_DECLARE_INTERACTION_PTR(ISTUNDiscovery)
    ZS_DECLARE_INTERACTION_PTR(ISTUNRequester)
    ZS_DECLARE_INTERACTION_PTR(ITCPMessaging)
    ZS_DECLARE_INTERACTION_PTR(ITransportStream)
    ZS_DECLARE_INTERACTION_PTR(ITransportStreamReader)
    ZS_DECLARE_INTERACTION_PTR(ITransportStreamWriter)
    ZS_DECLARE_INTERACTION_PTR(ITURNSocket)

    ZS_DECLARE_INTERACTION_PROXY(IBackgroundingDelegate)
    ZS_DECLARE_INTERACTION_PROXY(IBackgroundingCompletionDelegate)
    ZS_DECLARE_INTERACTION_PROXY(IBackOffTimerDelegate)
    ZS_DECLARE_INTERACTION_PROXY(IDNSDelegate)
    ZS_DECLARE_INTERACTION_PROXY(IICESocketDelegate)
    ZS_DECLARE_INTERACTION_PROXY(IICESocketSessionDelegate)
    ZS_DECLARE_INTERACTION_PROXY(IHTTPQueryDelegate)
    ZS_DECLARE_INTERACTION_PROXY(IMessageLayerSecurityChannelDelegate)
    ZS_DECLARE_INTERACTION_PROXY(IReachabilityDelegate)
    ZS_DECLARE_INTERACTION_PROXY(IRUDPListenerDelegate)
    ZS_DECLARE_INTERACTION_PROXY(IRUDPMessagingDelegate)
    ZS_DECLARE_INTERACTION_PROXY(IRUDPChannelDelegate)
    ZS_DECLARE_INTERACTION_PROXY(IRUDPTransportDelegate)
    ZS_DECLARE_INTERACTION_PROXY(ISTUNDiscoveryDelegate)
    ZS_DECLARE_INTERACTION_PROXY(ISTUNRequesterDelegate)
    ZS_DECLARE_INTERACTION_PROXY(ITCPMessagingDelegate)
    ZS_DECLARE_INTERACTION_PROXY(ITransportStreamReaderDelegate)
    ZS_DECLARE_INTERACTION_PROXY(ITransportStreamWriterDelegate)
    ZS_DECLARE_INTERACTION_PROXY(ITURNSocketDelegate)
    ZS_DECLARE_INTERACTION_PROXY(IWakeDelegate)

    ZS_DECLARE_INTERACTION_PROXY_SUBSCRIPTION(IBackgroundingSubscription, IBackgroundingDelegate)
    ZS_DECLARE_INTERACTION_PROXY_SUBSCRIPTION(IBackOffTimerSubscription, IBackOffTimerDelegate)
    ZS_DECLARE_INTERACTION_PROXY_SUBSCRIPTION(IICESocketSubscription, IICESocketDelegate)
    ZS_DECLARE_INTERACTION_PROXY_SUBSCRIPTION(IICESocketSessionSubscription, IICESocketSessionDelegate)
    ZS_DECLARE_INTERACTION_PROXY_SUBSCRIPTION(IMessageLayerSecurityChannelSubscription, IMessageLayerSecurityChannelDelegate)
    ZS_DECLARE_INTERACTION_PROXY_SUBSCRIPTION(IReachabilitySubscription, IReachabilityDelegate)
    ZS_DECLARE_INTERACTION_PROXY_SUBSCRIPTION(IRUDPTransportSubscription, IRUDPTransportDelegate)
    ZS_DECLARE_INTERACTION_PROXY_SUBSCRIPTION(ITCPMessagingSubscription, ITCPMessagingDelegate)
    ZS_DECLARE_INTERACTION_PROXY_SUBSCRIPTION(ITransportStreamReaderSubscription, ITransportStreamReaderDelegate)
    ZS_DECLARE_INTERACTION_PROXY_SUBSCRIPTION(ITransportStreamWriterSubscription, ITransportStreamWriterDelegate)

    ZS_DECLARE_STRUCT_PTR(RUDPPacket)
    ZS_DECLARE_STRUCT_PTR(STUNPacket)

    namespace internal
    {
      IBackgroundingNotifierPtr getBackgroundingNotifier(IBackgroundingNotifierPtr notifier);
    }

  }
}
