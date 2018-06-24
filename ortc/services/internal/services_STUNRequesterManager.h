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
#include <ortc/services/ISTUNRequesterManager.h>

#include <map>
#include <utility>

namespace ortc
{
  namespace services
  {
    namespace internal
    {
      interaction ISTUNRequesterForSTUNRequesterManager;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // ISTUNRequesterManagerForSTUNRequester
      //

      interaction ISTUNRequesterManagerForSTUNRequester
      {
        ZS_DECLARE_TYPEDEF_PTR(ISTUNRequesterManagerForSTUNRequester, ForSTUNRequester)

        static ForSTUNRequesterPtr singleton() noexcept;

        virtual void monitorStart(
                                  STUNRequesterPtr requester,
                                  STUNPacketPtr stunRequest
                                  ) noexcept = 0;
        virtual void monitorStop(STUNRequester &requester) noexcept = 0;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // STUNRequesterManager
      //

      class STUNRequesterManager : public Noop,
                                   public ISTUNRequesterManager,
                                   public ISTUNRequesterManagerForSTUNRequester
      {
      protected:
        struct make_private {};

      public:
        friend interaction ISTUNRequesterManagerFactory;
        friend interaction ISTUNRequesterManager;
        friend interaction ISTUNRequesterManagerForSTUNRequester;

        ZS_DECLARE_TYPEDEF_PTR(ISTUNRequesterForSTUNRequesterManager, UseSTUNRequester)

        typedef std::pair<QWORD, QWORD> QWORDPair;

      public:
        STUNRequesterManager(const make_private &) noexcept;

      protected:
        STUNRequesterManager(Noop) noexcept : Noop(true) {};

      public:
        ~STUNRequesterManager() noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // STUNRequesterManager => ISTUNRequesterManagerFactory
        //

        static STUNRequesterManagerPtr create() noexcept;

        //---------------------------------------------------------------------
        //
        // STUNRequesterManager => ISTUNRequesterManager
        //

        static STUNRequesterManagerPtr singleton() noexcept;

        ISTUNRequesterPtr handleSTUNPacket(
                                           IPAddress fromIPAddress,
                                           STUNPacketPtr stun
                                           ) noexcept;

        //---------------------------------------------------------------------
        //
        // STUNRequesterManager => ISTUNRequesterManagerForSTUNRequester
        //

        // (duplicate) static STUNRequesterManagerPtr singleton();

        void monitorStart(
                          STUNRequesterPtr requester,
                          STUNPacketPtr stunRequest
                          ) noexcept;
        void monitorStop(STUNRequester &requester) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // STUNRequesterManager => (internal)
        //

        Log::Params log(const char *message) const noexcept;
        static Log::Params slog(const char *message) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // STUNRequesterManager => (data)
        //

        RecursiveLock mLock;
        PUID mID;
        STUNRequesterManagerWeakPtr mThisWeak;

        typedef PUID STUNRequesterID;
        typedef std::pair<UseSTUNRequesterWeakPtr, STUNRequesterID> STUNRequesterPair;
        typedef std::map<QWORDPair, STUNRequesterPair> STUNRequesterMap;
        STUNRequesterMap mRequesters;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // ISTUNRequesterManagerFactory
      //

      interaction ISTUNRequesterManagerFactory
      {
        static ISTUNRequesterManagerFactory &singleton() noexcept;

        virtual STUNRequesterManagerPtr createSTUNRequesterManager() noexcept;
      };

      class STUNRequesterManagerFactory : public IFactory<ISTUNRequesterManagerFactory> {};

    }
  }
}
