/*

 Copyright (c) 2013, SMB Phone Inc.
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

#include <openpeer/services/internal/types.h>
#include <openpeer/services/IDHKeyDomain.h>

#include <cryptopp/dh.h>

namespace openpeer
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
      #pragma mark IDHKeyDomainForDHPrivateKey
      #pragma mark

      interaction IDHKeyDomainForDHPrivateKey
      {
        ZS_DECLARE_TYPEDEF_PTR(IDHKeyDomainForDHPrivateKey, ForDHPrivateKey)

        typedef CryptoPP::DH DH;

        virtual PUID getID() const = 0;

        virtual DH &getDH() const = 0;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DHKeyDomain
      #pragma mark

      class DHKeyDomain : public Noop,
                          public IDHKeyDomain,
                          public IDHKeyDomainForDHPrivateKey
      {
      public:
        friend interaction IDHKeyDomainFactory;
        friend interaction IDHKeyDomain;

        typedef CryptoPP::DH DH;

      protected:
        DHKeyDomain();
        
        DHKeyDomain(Noop) : Noop(true) {};

      public:
        ~DHKeyDomain();

        static DHKeyDomainPtr convert(IDHKeyDomainPtr privateKey);
        static DHKeyDomainPtr convert(ForDHPrivateKeyPtr object);

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DHKeyDomain => IDHKeyDomain
        #pragma mark

        static ElementPtr toDebug(IDHKeyDomainPtr keyDomain);

        static DHKeyDomainPtr generate(size_t keySizeInBits);

        static DHKeyDomainPtr loadPrecompiled(
                                              IDHKeyDomain::KeyDomainPrecompiledTypes precompiledKey,
                                              bool validate
                                              );

        static DHKeyDomainPtr load(
                                   const SecureByteBlock &p,
                                   const SecureByteBlock &q,
                                   const SecureByteBlock &g,
                                   bool validate = true
                                   );

        virtual PUID getID() const {return mID;}

        virtual KeyDomainPrecompiledTypes getPrecompiledType() const;

        virtual void save(
                          SecureByteBlock &p,
                          SecureByteBlock &q,
                          SecureByteBlock &g
                          ) const;

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DHKeyDomain => IDHKeyDomainForDHPrivateKey
        #pragma mark

        // (duplicate) virtual PUID getID() const;

        virtual DH &getDH() const;

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DHKeyDomain => (internal)
        #pragma mark

        Log::Params log(const char *message) const;
        Log::Params debug(const char *message) const;

        virtual ElementPtr toDebug() const;

        bool validate() const;

      private:
        //-------------------------------------------------------------------
        #pragma mark
        #pragma mark DHKeyDomain => (data)
        #pragma mark

        AutoPUID mID;
        mutable DH mDH;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IDHKeyDomainFactory
      #pragma mark

      interaction IDHKeyDomainFactory
      {
        static IDHKeyDomainFactory &singleton();

        virtual DHKeyDomainPtr generate(size_t keySizeInBits);

        virtual DHKeyDomainPtr loadPrecompiled(
                                               IDHKeyDomain::KeyDomainPrecompiledTypes precompiledKey,
                                               bool validate
                                               );

        virtual DHKeyDomainPtr load(
                                    const SecureByteBlock &p,
                                    const SecureByteBlock &q,
                                    const SecureByteBlock &g,
                                    bool validate
                                    );
      };
      
    }
  }
}
