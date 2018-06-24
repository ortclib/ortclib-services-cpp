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
#include <ortc/services/ISTUNDiscovery.h>
#include <ortc/services/IDNS.h>
#include <ortc/services/ISTUNRequester.h>

#include <zsLib/MessageQueueAssociator.h>
#include <zsLib/ITimer.h>

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
      // STUNDiscovery
      //

      class STUNDiscovery : public Noop,
                            public MessageQueueAssociator,
                            public ISTUNDiscovery,
                            public IDNSDelegate,
                            public ISTUNRequesterDelegate,
                            public ITimerDelegate
      {
      protected:
        struct make_private {};

      public:
        friend interaction ISTUNDiscovery;
        friend interaction ISTUNDiscoveryFactory;

        typedef std::list<IPAddress> IPAddressList;

      public:
        STUNDiscovery(
                      const make_private &,
                      IMessageQueuePtr queue,
                      ISTUNDiscoveryDelegatePtr delegate,
                      const CreationOptions &options
                      ) noexcept;

      protected:
        STUNDiscovery(Noop) noexcept : Noop(true), MessageQueueAssociator(IMessageQueuePtr()) {};

        void init() noexcept;

      public:
        ~STUNDiscovery() noexcept;

        static STUNDiscoveryPtr convert(ISTUNDiscoveryPtr object) noexcept;

      protected:

        //---------------------------------------------------------------------
        //
        // STUNDiscovery => ISTUNDiscovery
        //

        static ElementPtr toDebug(STUNDiscoveryPtr discovery) noexcept;

        static STUNDiscoveryPtr create(
                                       IMessageQueuePtr queue,
                                       ISTUNDiscoveryDelegatePtr delegate,
                                       const CreationOptions &options
                                       ) noexcept;

        PUID getID() const noexcept override {return mID;}

        bool isComplete() const noexcept override;

        void cancel() noexcept override;

        IPAddress getMappedAddress() const noexcept override;

        //---------------------------------------------------------------------
        //
        // STUNDiscovery => IDNSDelegate
        //

        void onLookupCompleted(IDNSQueryPtr query) override;

        //---------------------------------------------------------------------
        //
        // STUNDiscovery => IDNSDelegate
        //

        void onTimer(ITimerPtr timer) override;

        //---------------------------------------------------------------------
        //
        // STUNDiscovery => ISTUNRequesterDelegate
        //

        void onSTUNRequesterSendPacket(
                                       ISTUNRequesterPtr requester,
                                       IPAddress destination,
                                       SecureByteBlockPtr packet
                                       ) override;

        bool handleSTUNRequesterResponse(
                                         ISTUNRequesterPtr requester,
                                         IPAddress fromIPAddress,
                                         STUNPacketPtr response
                                         ) noexcept override;

        void onSTUNRequesterTimedOut(ISTUNRequesterPtr requester) override;

      protected:
        //---------------------------------------------------------------------
        //
        // STUNDiscovery => (internal)
        //

        Log::Params log(const char *message) const noexcept;
        ElementPtr toDebug() const noexcept;

        void step() noexcept;
        bool hasContactedServerBefore(const IPAddress &server) noexcept;
        void performNextLookup() noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // STUNDiscovery => (data)
        //

        mutable RecursiveLock mLock;
        STUNDiscoveryWeakPtr mThisWeak;

        AutoPUID mID;
        ISTUNDiscoveryDelegatePtr mDelegate;

        CreationOptions mOptions;

        IDNSQueryPtr mSRVQuery;

        ISTUNRequesterPtr mSTUNRequester;

        IPAddress mServer;
        IPAddress mMapppedAddress;

        IPAddressList mPreviouslyContactedServers;

        ITimerPtr mKeepWarmPingTimer;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // ISTUNDiscoveryFactory
      //

      interaction ISTUNDiscoveryFactory
      {
        typedef ISTUNDiscovery::CreationOptions CreationOptions;

        static ISTUNDiscoveryFactory &singleton() noexcept;

        virtual STUNDiscoveryPtr create(
                                        IMessageQueuePtr queue,
                                        ISTUNDiscoveryDelegatePtr delegate,
                                        const CreationOptions &options
                                        ) noexcept;

      };

      class STUNDiscoveryFactory : public IFactory<ISTUNDiscoveryFactory> {};
      
    }
  }
}
