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

#include <ortc/services/ICache.h>
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
      #pragma mark
      #pragma mark Cache
      #pragma mark

      class Cache : public ICache
      {
      protected:
        struct make_private {};

      public:
        friend interaction ICache;

      public:
        Cache(const make_private &);

      public:
        ~Cache();

      protected:
        static CachePtr convert(ICachePtr cache);

        static CachePtr create();
        static CachePtr singleton();

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark Cache => ICache
        #pragma mark

        virtual void setup(ICacheDelegatePtr delegate);

        virtual String fetch(const char *cookieNamePath) const;
        virtual void store(
                           const char *cookieNamePath,
                           Time expires,
                           const char *str
                           );
        virtual void clear(const char *cookieNamePath);

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark Cache => (internal)
        #pragma mark

        Log::Params log(const char *message) const;
        static Log::Params slog(const char *message);

        void actualSetup(ICacheDelegatePtr delegate);

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark Cache => (data)
        #pragma mark

        mutable RecursiveLock mLock;
        AutoPUID mID;
        CacheWeakPtr mThisWeak;

        ICacheDelegatePtr mDelegate;
      };
    }
  }
}
