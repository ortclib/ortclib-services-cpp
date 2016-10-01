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
#include <ortc/services/IRSAPublicKey.h>

#include <cryptopp/rsa.h>
#include <cryptopp/secblock.h>

namespace openpeer
{
  namespace services
  {
    namespace internal
    {
      interaction IRSAPrivateKeyForRSAPublicKey;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IRSAPublicKeyForRSAPrivateKey
      #pragma mark

      interaction IRSAPublicKeyForRSAPrivateKey
      {
        ZS_DECLARE_TYPEDEF_PTR(IRSAPublicKeyForRSAPrivateKey, ForPrivateKey)

        static ForPrivateKeyPtr load(const SecureByteBlock &buffer);

        virtual ~IRSAPublicKeyForRSAPrivateKey() {} // need a virtual function to make this class polymorphic (if another virtual method is added then remove this)
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RSAPublicKey
      #pragma mark

      class RSAPublicKey : public Noop,
                           public IRSAPublicKey,
                           public IRSAPublicKeyForRSAPrivateKey
      {
      protected:
        struct make_private {};

      public:
        friend interaction IRSAPublicKeyFactory;
        friend interaction IRSAPublicKey;

        ZS_DECLARE_TYPEDEF_PTR(IRSAPrivateKeyForRSAPublicKey, UsePrivateKey)

        typedef CryptoPP::RSA::PublicKey PublicKey;

      public:
        RSAPublicKey(const make_private &);

      protected:
        RSAPublicKey(Noop) : Noop(true) {};

      public:
        ~RSAPublicKey();

        static RSAPublicKeyPtr convert(IRSAPublicKeyPtr publicKey);
        static RSAPublicKeyPtr convert(ForPrivateKeyPtr publicKey);

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark RSAPublicKey => IRSAPublicKey
        #pragma mark

        static ElementPtr toDebug(IRSAPublicKeyPtr object);

        static RSAPublicKeyPtr generate(RSAPrivateKeyPtr &outPrivatekey);

        static RSAPublicKeyPtr load(const SecureByteBlock &buffer);

        virtual SecureByteBlockPtr save() const;

        virtual String getFingerprint() const;

        virtual bool verify(
                            const SecureByteBlock &inOriginalBufferSigned,
                            const SecureByteBlock &inSignature
                            ) const;

        virtual bool verify(
                            const String &inOriginalStringSigned,
                            const SecureByteBlock &inSignature
                            ) const;

        virtual bool verifySignature(ElementPtr signedEl) const;

        virtual SecureByteBlockPtr encrypt(const SecureByteBlock &buffer) const;

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark RSAPublicKey => (internal)
        #pragma mark

        Log::Params log(const char *message) const;

        virtual ElementPtr toDebug() const;

        bool verify(
                    const BYTE *inBuffer,
                    size_t inBufferLengthInBytes,
                    const SecureByteBlock &inSignature
                    ) const;

      private:
        //-------------------------------------------------------------------
        #pragma mark
        #pragma mark RSAPrivateKey => (data)
        #pragma mark

        AutoPUID mID;
        PublicKey mPublicKey;
        String mFingerprint;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IRSAPublicKeyFactory
      #pragma mark

      interaction IRSAPublicKeyFactory
      {
        static IRSAPublicKeyFactory &singleton();

        virtual RSAPublicKeyPtr loadPublicKey(const SecureByteBlock &buffer);
      };

      class RSAPublicKeyFactory : public IFactory<IRSAPublicKeyFactory> {};
    }
  }
}
