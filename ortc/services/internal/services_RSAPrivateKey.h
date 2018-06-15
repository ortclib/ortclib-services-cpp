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
#include <ortc/services/IRSAPrivateKey.h>

#include <cryptopp/rsa.h>
#include <cryptopp/secblock.h>

namespace ortc
{
  namespace services
  {
    namespace internal
    {
      interaction IRSAPublicKeyForRSAPrivateKey;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IRSAPrivateKeyForRSAPublicKey
      //

      interaction IRSAPrivateKeyForRSAPublicKey
      {
        ZS_DECLARE_TYPEDEF_PTR(IRSAPrivateKeyForRSAPublicKey, ForPublicKey)

        static ForPublicKeyPtr generate(RSAPublicKeyPtr &outPublicKey) noexcept;

        virtual ~IRSAPrivateKeyForRSAPublicKey() {} // need to make base polymorphic - remove if another virtual method is added
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // RSAPrivateKey
      //

      class RSAPrivateKey : public Noop,
                            public IRSAPrivateKey,
                            public IRSAPrivateKeyForRSAPublicKey
      {
      protected:
        struct make_private {};

      public:
        friend interaction IRSAPrivateKey;
        friend interaction IRSAPrivateKeyFactory;

        ZS_DECLARE_TYPEDEF_PTR(IRSAPublicKeyForRSAPrivateKey, UsePublicKey)

        typedef CryptoPP::RSA::PrivateKey PrivateKey;

      public:
        RSAPrivateKey(const make_private &) noexcept;

      protected:
        RSAPrivateKey(Noop) noexcept : Noop(true) {};

      public:
        ~RSAPrivateKey() noexcept;

        static RSAPrivateKeyPtr convert(IRSAPrivateKeyPtr privateKey) noexcept;
        static RSAPrivateKeyPtr convert(ForPublicKeyPtr privateKey) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // RSAPrivateKey => IRSAPrivateKey
        //

        static ElementPtr toDebug(IRSAPrivateKeyPtr object) noexcept;

        static RSAPrivateKeyPtr generate(
                                         RSAPublicKeyPtr &outPublicKey,
                                         size_t keySizeInBits = ORTC_SERVICES_RSA_PRIVATE_KEY_GENERATION_SIZE
                                         ) noexcept;

        static RSAPrivateKeyPtr load(const SecureByteBlock &buffer) noexcept;

        virtual SecureByteBlockPtr save() const noexcept;

        virtual SecureByteBlockPtr sign(const SecureByteBlock &inBufferToSign) const noexcept;

        virtual SecureByteBlockPtr sign(const String &stringToSign) const noexcept;

        virtual SecureByteBlockPtr decrypt(const SecureByteBlock &buffer) const noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // RSAPrivateKey => (internal)
        //

        Log::Params log(const char *message) const noexcept;
        Log::Params debug(const char *message) const noexcept;

        virtual ElementPtr toDebug() const noexcept;

        virtual SecureByteBlockPtr sign(
                                        const BYTE *inBuffer,
                                        size_t inBufferSizeInBytes
                                        ) const noexcept;

      private:
        //-------------------------------------------------------------------
        //
        // RSAPrivateKey => (data)
        //

        AutoPUID mID;

        PrivateKey mPrivateKey;
        bool mDidGenerate {};
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IRSAPrivateKeyFactory
      //

      interaction IRSAPrivateKeyFactory
      {
        static IRSAPrivateKeyFactory &singleton() noexcept;

        virtual RSAPrivateKeyPtr generate(
                                          RSAPublicKeyPtr &outPublicKey,
                                          size_t keySizeInBits = ORTC_SERVICES_RSA_PRIVATE_KEY_GENERATION_SIZE
                                          ) noexcept;

        virtual RSAPrivateKeyPtr loadPrivateKey(const SecureByteBlock &buffer) noexcept;
      };

      class RSAPrivateKeyFactory : public IFactory<IRSAPrivateKeyFactory> {};
      
    }
  }
}
