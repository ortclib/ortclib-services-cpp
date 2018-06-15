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
#include <ortc/services/IDHPrivateKey.h>

namespace ortc
{
  namespace services
  {
    namespace internal
    {
      interaction IDHKeyDomainForDHPrivateKey;
      interaction IDHPublicKeyForDHPrivateKey;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // DHPrivateKey
      //

      class DHPrivateKey : public Noop,
                           public IDHPrivateKey
      {
      protected:
        struct make_private {};

      public:
        friend interaction IDHPrivateKeyFactory;
        friend interaction IDHPrivateKey;

        ZS_DECLARE_TYPEDEF_PTR(IDHKeyDomainForDHPrivateKey, UseDHKeyDomain)
        ZS_DECLARE_TYPEDEF_PTR(IDHPublicKeyForDHPrivateKey, UseDHPublicKey)

      public:
        DHPrivateKey(
                     const make_private &,
                     UseDHKeyDomainPtr keyDomain
                     ) noexcept;

      protected:
        DHPrivateKey(Noop) noexcept : Noop(true) {};

      public:
        ~DHPrivateKey() noexcept;

        static DHPrivateKeyPtr convert(IDHPrivateKeyPtr privateKey) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // DHPrivateKey => IDHPrivateKey
        //

        static ElementPtr toDebug(IDHPrivateKeyPtr keyDomain) noexcept;

        static DHPrivateKeyPtr generate(
                                        IDHKeyDomainPtr keyDomain,
                                        IDHPublicKeyPtr &outPublicKey
                                        ) noexcept;

        static DHPrivateKeyPtr load(
                                    IDHKeyDomainPtr inKeyDomain,
                                    const SecureByteBlock &staticPrivateKey,
                                    const SecureByteBlock &ephemeralPrivateKey
                                    ) noexcept;

        static DHPrivateKeyPtr load(
                                    IDHKeyDomainPtr keyDomain,
                                    IDHPublicKeyPtr &outPublicKey,
                                    const SecureByteBlock &staticPrivateKey,
                                    const SecureByteBlock &ephemeralPrivateKey,
                                    const SecureByteBlock &staticPublicKey,
                                    const SecureByteBlock &ephemeralPublicKey
                                    ) noexcept;
        
        static DHPrivateKeyPtr loadAndGenerateNewEphemeral(
                                                           IDHKeyDomainPtr keyDomain,
                                                           const SecureByteBlock &staticPrivateKey,
                                                           const SecureByteBlock &staticPublicKey,
                                                           IDHPublicKeyPtr &outNewPublicKey
                                                           ) noexcept;

        static DHPrivateKeyPtr loadAndGenerateNewEphemeral(
                                                           IDHPrivateKeyPtr templatePrivateKey,
                                                           IDHPublicKeyPtr templatePublicKey,
                                                           IDHPublicKeyPtr &outNewPublicKey
                                                           ) noexcept;

        virtual PUID getID() const noexcept {return mID;}
        
        virtual void save(
                          SecureByteBlock *outStaticPrivateKey,
                          SecureByteBlock *outEphemeralPrivateKey
                          ) const noexcept;

        virtual IDHKeyDomainPtr getKeyDomain() const noexcept;

        virtual SecureByteBlockPtr getSharedSecret(IDHPublicKeyPtr otherPartyPublicKey) const noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // DHPrivateKey => (internal)
        //

        static Log::Params slog(const char *message) noexcept;
        Log::Params log(const char *message) const noexcept;
        Log::Params debug(const char *message) const noexcept;
        virtual ElementPtr toDebug() const noexcept;

      private:
        //-------------------------------------------------------------------
        //
        // DHPrivateKey => (data)
        //

        AutoPUID mID;

        UseDHKeyDomainPtr mKeyDomain;

        SecureByteBlock mStaticPrivateKey;
        SecureByteBlock mEphemeralPrivateKey;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IDHPrivateKeyFactory
      //

      interaction IDHPrivateKeyFactory
      {
        static IDHPrivateKeyFactory &singleton() noexcept;

        virtual DHPrivateKeyPtr generate(
                                         IDHKeyDomainPtr keyDomain,
                                         IDHPublicKeyPtr &outPublicKey
                                         ) noexcept;

        virtual DHPrivateKeyPtr load(
                                     IDHKeyDomainPtr inKeyDomain,
                                     const SecureByteBlock &staticPrivateKey,
                                     const SecureByteBlock &ephemeralPrivateKey
                                     ) noexcept;

        virtual DHPrivateKeyPtr load(
                                     IDHKeyDomainPtr keyDomain,
                                     IDHPublicKeyPtr &outPublicKey,
                                     const SecureByteBlock &staticPrivateKey,
                                     const SecureByteBlock &ephemeralPrivateKey,
                                     const SecureByteBlock &staticPublicKey,
                                     const SecureByteBlock &ephemeralPublicKey
                                     ) noexcept;

        virtual DHPrivateKeyPtr loadAndGenerateNewEphemeral(
                                                            IDHKeyDomainPtr keyDomain,
                                                            const SecureByteBlock &staticPrivateKey,
                                                            const SecureByteBlock &staticPublicKey,
                                                            IDHPublicKeyPtr &outNewPublicKey
                                                            ) noexcept;

        virtual DHPrivateKeyPtr loadAndGenerateNewEphemeral(
                                                            IDHPrivateKeyPtr templatePrivateKey,
                                                            IDHPublicKeyPtr templatePublicKey,
                                                            IDHPublicKeyPtr &outNewPublicKey
                                                            ) noexcept;
      };

      class DHPrivateKeyFactory : public IFactory<IDHPrivateKeyFactory> {};
      
    }
  }
}
