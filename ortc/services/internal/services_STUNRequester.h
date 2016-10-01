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
#include <ortc/services/ISTUNRequester.h>
#include <ortc/services/STUNPacket.h>

#include <ortc/services/IBackOffTimer.h>

#include <zsLib/MessageQueueAssociator.h>
#include <zsLib/Timer.h>
#include <zsLib/Proxy.h>

namespace ortc
{
  namespace services
  {
    namespace internal
    {
      interaction ISTUNRequesterManagerForSTUNRequester;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ISTUNRequesterForSTUNRequesterManager
      #pragma mark

      interaction ISTUNRequesterForSTUNRequesterManager
      {
        ZS_DECLARE_TYPEDEF_PTR(ISTUNRequesterForSTUNRequesterManager, ForSTUNRequesterManager)

        virtual PUID getID() const = 0;

        virtual bool handleSTUNPacket(
                                      IPAddress fromIPAddress,
                                      STUNPacketPtr packet
                                      ) = 0;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark STUNRequester
      #pragma mark

      class STUNRequester : public Noop,
                            public MessageQueueAssociator,
                            public ISTUNRequester,
                            public ISTUNRequesterForSTUNRequesterManager,
                            public IBackOffTimerDelegate
      {
      protected:
        struct make_private {};

      public:
        friend interaction ISTUNRequesterFactory;

        ZS_DECLARE_TYPEDEF_PTR(ISTUNRequesterManagerForSTUNRequester, UseSTUNRequesterManager)

      public:
        STUNRequester(
                      const make_private &,
                      IMessageQueuePtr queue,
                      ISTUNRequesterDelegatePtr delegate,
                      IPAddress serverIP,
                      STUNPacketPtr stun,
                      STUNPacket::RFCs usingRFC,
                      IBackOffTimerPatternPtr pattern
                      );

      protected:
        STUNRequester(Noop) : Noop(true), MessageQueueAssociator(IMessageQueuePtr()) {};
        
        void init();

      public:
        ~STUNRequester();

        static STUNRequesterPtr convert(ISTUNRequesterPtr object);
        static STUNRequesterPtr convert(ForSTUNRequesterManagerPtr object);

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark STUNRequester => STUNRequester
        #pragma mark

        static STUNRequesterPtr create(
                                       IMessageQueuePtr queue,
                                       ISTUNRequesterDelegatePtr delegate,
                                       IPAddress serverIP,
                                       STUNPacketPtr stun,
                                       STUNPacket::RFCs usingRFC,
                                       IBackOffTimerPatternPtr pattern = IBackOffTimerPatternPtr()
                                       );

        virtual PUID getID() const override {return mID;}

        virtual bool isComplete() const override;

        virtual void cancel() override;

        virtual void retryRequestNow() override;

        virtual IPAddress getServerIP() const override;
        virtual STUNPacketPtr getRequest() const override;

        virtual IBackOffTimerPatternPtr getBackOffTimerPattern() const override;

        virtual size_t getTotalTries() const override;

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark STUNRequester => ISTUNRequesterForSTUNRequesterManager
        #pragma mark

        // (duplicate) virtual PUID getID() const;

        virtual bool handleSTUNPacket(
                                      IPAddress fromIPAddress,
                                      STUNPacketPtr packet
                                      ) override;

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark STUNRequester => ITimerDelegate
        #pragma mark

        virtual void onBackOffTimerStateChanged(
                                                IBackOffTimerPtr timer,
                                                IBackOffTimer::States state
                                                ) override;

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark STUNRequester => (internal)
        #pragma mark

        Log::Params log(const char *message) const;

        void step();

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark STUNRequester => (data)
        #pragma mark

        mutable RecursiveLock mLock;
        STUNRequesterWeakPtr mThisWeak;
        AutoPUID mID;

        ISTUNRequesterDelegatePtr mDelegate;
        STUNPacketPtr mSTUNRequest;

        IPAddress mServerIP;

        STUNPacket::RFCs mUsingRFC;

        IBackOffTimerPtr mBackOffTimer;
        IBackOffTimerPatternPtr mBackOffTimerPattern;

        ULONG mTotalTries {0};
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ISTUNRequesterFactory
      #pragma mark

      interaction ISTUNRequesterFactory
      {
        static ISTUNRequesterFactory &singleton();

        virtual STUNRequesterPtr create(
                                        IMessageQueuePtr queue,
                                        ISTUNRequesterDelegatePtr delegate,
                                        IPAddress serverIP,
                                        STUNPacketPtr stun,
                                        STUNPacket::RFCs usingRFC,
                                        IBackOffTimerPatternPtr pattern = IBackOffTimerPatternPtr()
                                        );
      };

      class STUNRequesterFactory : public IFactory<ISTUNRequesterFactory> {};

    }
  }
}
