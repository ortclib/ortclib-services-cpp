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
#include <ortc/services/IDHKeyDomain.h>

#include <cryptopp/dh.h>

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
      // IDHKeyDomainForDHPrivateKey
      //

      interaction IDHKeyDomainForDHPrivateKey
      {
        ZS_DECLARE_TYPEDEF_PTR(IDHKeyDomainForDHPrivateKey, ForDHPrivateKey)

        typedef CryptoPP::DH DH;

        virtual PUID getID() const noexcept = 0;

        virtual DH &getDH() const noexcept = 0;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // DHKeyDomain
      //

      class DHKeyDomain : public Noop,
                          public IDHKeyDomain,
                          public IDHKeyDomainForDHPrivateKey
      {
      protected:
        struct make_private {};

      public:
        friend interaction IDHKeyDomainFactory;
        friend interaction IDHKeyDomain;

        typedef CryptoPP::DH DH;

      public:
        DHKeyDomain(const make_private &) noexcept;

      protected:
        DHKeyDomain(Noop) noexcept : Noop(true) {};

      public:
        ~DHKeyDomain();

        static DHKeyDomainPtr convert(IDHKeyDomainPtr privateKey) noexcept;
        static DHKeyDomainPtr convert(ForDHPrivateKeyPtr object) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // DHKeyDomain => IDHKeyDomain
        //

        static ElementPtr toDebug(IDHKeyDomainPtr keyDomain) noexcept;

        static DHKeyDomainPtr generate(size_t keySizeInBits) noexcept;

        static DHKeyDomainPtr loadPrecompiled(
                                              IDHKeyDomain::KeyDomainPrecompiledTypes precompiledKey,
                                              bool validate
                                              ) noexcept;

        static DHKeyDomainPtr load(
                                   const SecureByteBlock &p,
                                   const SecureByteBlock &q,
                                   const SecureByteBlock &g,
                                   bool validate = true
                                   ) noexcept;

        virtual PUID getID() const noexcept {return mID;}

        virtual KeyDomainPrecompiledTypes getPrecompiledType() const noexcept;

        virtual void save(
                          SecureByteBlock &p,
                          SecureByteBlock &q,
                          SecureByteBlock &g
                          ) const noexcept;

        //---------------------------------------------------------------------
        //
        // DHKeyDomain => IDHKeyDomainForDHPrivateKey
        //

        // (duplicate) virtual PUID getID() const;

        virtual DH &getDH() const noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // DHKeyDomain => (internal)
        //

        Log::Params log(const char *message) const noexcept;
        Log::Params debug(const char *message) const noexcept;

        virtual ElementPtr toDebug() const noexcept;

        bool validate() const noexcept;

      private:
        //-------------------------------------------------------------------
        //
        // DHKeyDomain => (data)
        //

        AutoPUID mID;
        mutable DH mDH;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IDHKeyDomainFactory
      //

      interaction IDHKeyDomainFactory
      {
        static IDHKeyDomainFactory &singleton() noexcept;

        virtual DHKeyDomainPtr generate(size_t keySizeInBits) noexcept;

        virtual DHKeyDomainPtr loadPrecompiled(
                                               IDHKeyDomain::KeyDomainPrecompiledTypes precompiledKey,
                                               bool validate
                                               ) noexcept;

        virtual DHKeyDomainPtr load(
                                    const SecureByteBlock &p,
                                    const SecureByteBlock &q,
                                    const SecureByteBlock &g,
                                    bool validate
                                    ) noexcept;
      };

      class DHKeyDomainFactory : public IFactory<IDHKeyDomainFactory> {};
      
    }
  }
}
