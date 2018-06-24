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

#include <ortc/services/IReachability.h>
#include <ortc/services/internal/types.h>

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
      // Reachability
      //

      class Reachability : public MessageQueueAssociator,
                           public SharedRecursiveLock,
                           public IReachability
      {
      protected:
        struct make_private {};

      public:
        friend interaction IReachabilityFactory;
        friend interaction IReachability;

      public:
        Reachability(const make_private &) noexcept;

      protected:
        static ReachabilityPtr create() noexcept;

      public:
        ~Reachability() noexcept;

      public:
        static ReachabilityPtr convert(IReachabilityPtr backgrounding) noexcept;

        static ReachabilityPtr singleton() noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // Reachability => IReachability
        //

        static ElementPtr toDebug(ReachabilityPtr backgrounding) noexcept;

        virtual IReachabilitySubscriptionPtr subscribe(IReachabilityDelegatePtr delegate) noexcept;

        virtual void notifyReachability(InterfaceTypes interfaceTypes) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // Reachability => (internal)
        //

        Log::Params log(const char *message) const noexcept;
        static Log::Params slog(const char *message) noexcept;
        Log::Params debug(const char *message) const noexcept;

        virtual ElementPtr toDebug() const noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // Reachability => (data)
        //

        AutoPUID mID;
        ReachabilityWeakPtr mThisWeak;

        IReachabilityDelegateSubscriptions mSubscriptions;

        InterfaceTypes mLastState;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IReachabilityFactory
      //

      interaction IReachabilityFactory
      {
        static IReachabilityFactory &singleton() noexcept;

        virtual ReachabilityPtr createForReachability() noexcept;
      };

      class ReachabilityFactory : public IFactory<IReachabilityFactory> {};

    }
  }
}
