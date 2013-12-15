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
#include <openpeer/services/IDHPrivateKey.h>

namespace openpeer
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
      #pragma mark
      #pragma mark DHPrivateKey
      #pragma mark

      class DHPrivateKey : public Noop,
                           public IDHPrivateKey
      {
      public:
        friend interaction IDHPrivateKeyFactory;
        friend interaction IDHPrivateKey;

        ZS_DECLARE_TYPEDEF_PTR(IDHKeyDomainForDHPrivateKey, UseDHKeyDomain)
        ZS_DECLARE_TYPEDEF_PTR(IDHPublicKeyForDHPrivateKey, UseDHPublicKey)

      protected:
        DHPrivateKey(UseDHKeyDomainPtr keyDomain);
        
        DHPrivateKey(Noop) : Noop(true) {};

      public:
        ~DHPrivateKey();

        static DHPrivateKeyPtr convert(IDHPrivateKeyPtr privateKey);

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DHPrivateKey => IDHPrivateKey
        #pragma mark

        static ElementPtr toDebug(IDHPrivateKeyPtr keyDomain);

        static DHPrivateKeyPtr generate(
                                        IDHKeyDomainPtr keyDomain,
                                        IDHPublicKeyPtr &outPublicKey
                                        );

        static DHPrivateKeyPtr load(
                                    IDHKeyDomainPtr inKeyDomain,
                                    const SecureByteBlock &staticPrivateKey,
                                    const SecureByteBlock &ephemeralPrivateKey
                                    );

        static DHPrivateKeyPtr load(
                                    IDHKeyDomainPtr keyDomain,
                                    IDHPublicKeyPtr &outPublicKey,
                                    const SecureByteBlock &staticPrivateKey,
                                    const SecureByteBlock &ephemeralPrivateKey,
                                    const SecureByteBlock &staticPublicKey,
                                    const SecureByteBlock &ephemeralPublicKey
                                    );
        
        static DHPrivateKeyPtr loadAndGenerateNewEphemeral(
                                                           IDHKeyDomainPtr keyDomain,
                                                           const SecureByteBlock &staticPrivateKey,
                                                           const SecureByteBlock &staticPublicKey,
                                                           IDHPublicKeyPtr &outNewPublicKey
                                                           );

        static DHPrivateKeyPtr loadAndGenerateNewEphemeral(
                                                           IDHPrivateKeyPtr templatePrivateKey,
                                                           IDHPublicKeyPtr templatePublicKey,
                                                           IDHPublicKeyPtr &outNewPublicKey
                                                           );

        virtual PUID getID() const {return mID;}
        
        virtual void save(
                          SecureByteBlock *outStaticPrivateKey,
                          SecureByteBlock *outEphemeralPrivateKey
                          ) const;

        virtual IDHKeyDomainPtr getKeyDomain() const;

        virtual SecureByteBlockPtr getSharedSecret(IDHPublicKeyPtr otherPartyPublicKey) const;

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DHPrivateKey => (internal)
        #pragma mark

        static Log::Params slog(const char *message);
        Log::Params log(const char *message) const;
        Log::Params debug(const char *message) const;
        virtual ElementPtr toDebug() const;

      private:
        //-------------------------------------------------------------------
        #pragma mark
        #pragma mark DHPrivateKey => (data)
        #pragma mark

        AutoPUID mID;

        UseDHKeyDomainPtr mKeyDomain;

        SecureByteBlock mStaticPrivateKey;
        SecureByteBlock mEphemeralPrivateKey;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IDHPrivateKeyFactory
      #pragma mark

      interaction IDHPrivateKeyFactory
      {
        static IDHPrivateKeyFactory &singleton();

        virtual DHPrivateKeyPtr generate(
                                         IDHKeyDomainPtr keyDomain,
                                         IDHPublicKeyPtr &outPublicKey
                                         );

        virtual DHPrivateKeyPtr load(
                                     IDHKeyDomainPtr inKeyDomain,
                                     const SecureByteBlock &staticPrivateKey,
                                     const SecureByteBlock &ephemeralPrivateKey
                                     );

        virtual DHPrivateKeyPtr load(
                                     IDHKeyDomainPtr keyDomain,
                                     IDHPublicKeyPtr &outPublicKey,
                                     const SecureByteBlock &staticPrivateKey,
                                     const SecureByteBlock &ephemeralPrivateKey,
                                     const SecureByteBlock &staticPublicKey,
                                     const SecureByteBlock &ephemeralPublicKey
                                     );

        virtual DHPrivateKeyPtr loadAndGenerateNewEphemeral(
                                                            IDHKeyDomainPtr keyDomain,
                                                            const SecureByteBlock &staticPrivateKey,
                                                            const SecureByteBlock &staticPublicKey,
                                                            IDHPublicKeyPtr &outNewPublicKey
                                                            );

        virtual DHPrivateKeyPtr loadAndGenerateNewEphemeral(
                                                            IDHPrivateKeyPtr templatePrivateKey,
                                                            IDHPublicKeyPtr templatePublicKey,
                                                            IDHPublicKeyPtr &outNewPublicKey
                                                            );
      };
      
    }
  }
}
