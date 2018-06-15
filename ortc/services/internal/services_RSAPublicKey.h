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

namespace ortc
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
      //
      // IRSAPublicKeyForRSAPrivateKey
      //

      interaction IRSAPublicKeyForRSAPrivateKey
      {
        ZS_DECLARE_TYPEDEF_PTR(IRSAPublicKeyForRSAPrivateKey, ForPrivateKey)

        static ForPrivateKeyPtr load(const SecureByteBlock &buffer) noexcept;

        virtual ~IRSAPublicKeyForRSAPrivateKey() noexcept {} // need a virtual function to make this class polymorphic (if another virtual method is added then remove this)
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // RSAPublicKey
      //

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
        RSAPublicKey(const make_private &) noexcept;

      protected:
        RSAPublicKey(Noop) noexcept : Noop(true) {};

      public:
        ~RSAPublicKey() noexcept;

        static RSAPublicKeyPtr convert(IRSAPublicKeyPtr publicKey) noexcept;
        static RSAPublicKeyPtr convert(ForPrivateKeyPtr publicKey) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // RSAPublicKey => IRSAPublicKey
        //

        static ElementPtr toDebug(IRSAPublicKeyPtr object) noexcept;

        static RSAPublicKeyPtr generate(RSAPrivateKeyPtr &outPrivatekey) noexcept;

        static RSAPublicKeyPtr load(const SecureByteBlock &buffer) noexcept;

        virtual SecureByteBlockPtr save() const noexcept;

        virtual String getFingerprint() const noexcept;

        virtual bool verify(
                            const SecureByteBlock &inOriginalBufferSigned,
                            const SecureByteBlock &inSignature
                            ) const noexcept;

        virtual bool verify(
                            const String &inOriginalStringSigned,
                            const SecureByteBlock &inSignature
                            ) const noexcept;

        virtual bool verifySignature(ElementPtr signedEl) const noexcept;

        virtual SecureByteBlockPtr encrypt(const SecureByteBlock &buffer) const noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // RSAPublicKey => (internal)
        //

        Log::Params log(const char *message) const noexcept;

        virtual ElementPtr toDebug() const noexcept;

        bool verify(
                    const BYTE *inBuffer,
                    size_t inBufferLengthInBytes,
                    const SecureByteBlock &inSignature
                    ) const noexcept;

      private:
        //-------------------------------------------------------------------
        //
        // RSAPrivateKey => (data)
        //

        AutoPUID mID;
        PublicKey mPublicKey;
        String mFingerprint;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IRSAPublicKeyFactory
      //

      interaction IRSAPublicKeyFactory
      {
        static IRSAPublicKeyFactory &singleton() noexcept;

        virtual RSAPublicKeyPtr loadPublicKey(const SecureByteBlock &buffer) noexcept;
      };

      class RSAPublicKeyFactory : public IFactory<IRSAPublicKeyFactory> {};
    }
  }
}
