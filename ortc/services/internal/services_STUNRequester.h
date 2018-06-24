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
#include <zsLib/ITimer.h>
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
      //
      // ISTUNRequesterForSTUNRequesterManager
      //

      interaction ISTUNRequesterForSTUNRequesterManager
      {
        ZS_DECLARE_TYPEDEF_PTR(ISTUNRequesterForSTUNRequesterManager, ForSTUNRequesterManager)

        virtual PUID getID() const noexcept = 0;

        virtual bool handleSTUNPacket(
                                      IPAddress fromIPAddress,
                                      STUNPacketPtr packet
                                      ) noexcept = 0;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // STUNRequester
      //

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
                      ) noexcept;

      protected:
        STUNRequester(Noop) noexcept : Noop(true), MessageQueueAssociator(IMessageQueuePtr()) {};
        
        void init() noexcept;

      public:
        ~STUNRequester() noexcept;

        static STUNRequesterPtr convert(ISTUNRequesterPtr object) noexcept;
        static STUNRequesterPtr convert(ForSTUNRequesterManagerPtr object) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // STUNRequester => STUNRequester
        //

        static STUNRequesterPtr create(
                                       IMessageQueuePtr queue,
                                       ISTUNRequesterDelegatePtr delegate,
                                       IPAddress serverIP,
                                       STUNPacketPtr stun,
                                       STUNPacket::RFCs usingRFC,
                                       IBackOffTimerPatternPtr pattern = IBackOffTimerPatternPtr()
                                       ) noexcept;

        PUID getID() const noexcept override {return mID;}

        bool isComplete() const noexcept override;

        void cancel() noexcept override;

        void retryRequestNow() noexcept override;

        IPAddress getServerIP() const noexcept override;
        STUNPacketPtr getRequest() const noexcept override;

        IBackOffTimerPatternPtr getBackOffTimerPattern() const noexcept override;

        size_t getTotalTries() const noexcept override;

        //---------------------------------------------------------------------
        //
        // STUNRequester => ISTUNRequesterForSTUNRequesterManager
        //

        // (duplicate) virtual PUID getID() const;

        bool handleSTUNPacket(
                              IPAddress fromIPAddress,
                              STUNPacketPtr packet
                              ) noexcept override;

        //---------------------------------------------------------------------
        //
        // STUNRequester => ITimerDelegate
        //

        virtual void onBackOffTimerStateChanged(
                                                IBackOffTimerPtr timer,
                                                IBackOffTimer::States state
                                                ) override;

      protected:
        //---------------------------------------------------------------------
        //
        // STUNRequester => (internal)
        //

        Log::Params log(const char *message) const noexcept;

        void step() noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // STUNRequester => (data)
        //

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
      //
      // ISTUNRequesterFactory
      //

      interaction ISTUNRequesterFactory
      {
        static ISTUNRequesterFactory &singleton() noexcept;

        virtual STUNRequesterPtr create(
                                        IMessageQueuePtr queue,
                                        ISTUNRequesterDelegatePtr delegate,
                                        IPAddress serverIP,
                                        STUNPacketPtr stun,
                                        STUNPacket::RFCs usingRFC,
                                        IBackOffTimerPatternPtr pattern = IBackOffTimerPatternPtr()
                                        ) noexcept;
      };

      class STUNRequesterFactory : public IFactory<ISTUNRequesterFactory> {};

    }
  }
}
