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
      #pragma mark
      #pragma mark STUNDiscovery
      #pragma mark

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
                      );

      protected:
        STUNDiscovery(Noop) : Noop(true), MessageQueueAssociator(IMessageQueuePtr()) {};

        void init();

      public:
        ~STUNDiscovery();

        static STUNDiscoveryPtr convert(ISTUNDiscoveryPtr object);

      protected:

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark STUNDiscovery => ISTUNDiscovery
        #pragma mark

        static ElementPtr toDebug(STUNDiscoveryPtr discovery);

        static STUNDiscoveryPtr create(
                                       IMessageQueuePtr queue,
                                       ISTUNDiscoveryDelegatePtr delegate,
                                       const CreationOptions &options
                                       );

        virtual PUID getID() const override {return mID;}

        virtual bool isComplete() const override;

        virtual void cancel() override;

        virtual IPAddress getMappedAddress() const override;

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark STUNDiscovery => IDNSDelegate
        #pragma mark

        virtual void onLookupCompleted(IDNSQueryPtr query) override;

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark STUNDiscovery => IDNSDelegate
        #pragma mark

        virtual void onTimer(ITimerPtr timer) override;

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark STUNDiscovery => ISTUNRequesterDelegate
        #pragma mark

        virtual void onSTUNRequesterSendPacket(
                                               ISTUNRequesterPtr requester,
                                               IPAddress destination,
                                               SecureByteBlockPtr packet
                                               ) override;

        virtual bool handleSTUNRequesterResponse(
                                                 ISTUNRequesterPtr requester,
                                                 IPAddress fromIPAddress,
                                                 STUNPacketPtr response
                                                 ) override;

        virtual void onSTUNRequesterTimedOut(ISTUNRequesterPtr requester) override;

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark STUNDiscovery => (internal)
        #pragma mark

        Log::Params log(const char *message) const;
        ElementPtr toDebug() const;

        void step();
        bool hasContactedServerBefore(const IPAddress &server);
        void performNextLookup();

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark STUNDiscovery => (data)
        #pragma mark

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
      #pragma mark
      #pragma mark ISTUNDiscoveryFactory
      #pragma mark

      interaction ISTUNDiscoveryFactory
      {
        typedef ISTUNDiscovery::CreationOptions CreationOptions;

        static ISTUNDiscoveryFactory &singleton();

        virtual STUNDiscoveryPtr create(
                                        IMessageQueuePtr queue,
                                        ISTUNDiscoveryDelegatePtr delegate,
                                        const CreationOptions &options
                                        );

      };

      class STUNDiscoveryFactory : public IFactory<ISTUNDiscoveryFactory> {};
      
    }
  }
}
