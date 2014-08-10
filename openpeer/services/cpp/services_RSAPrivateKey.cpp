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

#include <openpeer/services/internal/services_RSAPrivateKey.h>
#include <openpeer/services/internal/services_RSAPublicKey.h>
#include <openpeer/services/ICache.h>
#include <openpeer/services/IHelper.h>
#include <zsLib/Log.h>
#include <zsLib/helpers.h>
#include <zsLib/Stringize.h>
#include <zsLib/XML.h>

#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

#define OPENPEER_SERVICES_RSAPRIVATEKEY_PRIVATE_KEY_VALIDATION_CACHE_NAMESPACE "https://meta.openpeer.org/caching/rsaprivatekey/"
#define OPENPEER_SERVICES_RSAPRIVATEKEY_PRIVATE_KEY_VALIDATION_CACHE_VALUE "1"
#define OPENPEER_SERVICES_RSAPRIVATEKEY_PRIVATE_KEY_VALIDATION_CACHE_STORAGE_DURATION_IN_HOURS ((24)*365)

namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services) } }

namespace openpeer
{
  namespace services
  {
    namespace internal
    {
      using CryptoPP::ByteQueue;
      using CryptoPP::AutoSeededRandomPool;
      typedef CryptoPP::RSA::PublicKey PublicKey;
      typedef CryptoPP::RSASSA_PKCS1v15_SHA_Signer Signer;

      typedef CryptoPP::RSAES_OAEP_SHA_Decryptor RsaDecryptor;
      typedef CryptoPP::RSAES_OAEP_SHA_Encryptor RsaEncryptor;

      using CryptoPP::PK_DecryptorFilter;

      ZS_DECLARE_TYPEDEF_PTR(IRSAPrivateKeyForRSAPublicKey::ForPublicKey, ForPublicKey)

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark (helpers)
      #pragma mark

      //-----------------------------------------------------------------------
      static String getCookieName(const SecureByteBlock &buffer)
      {
        String keyHash = IHelper::convertToHex(*IHelper::hash(buffer, IHelper::HashAlgorthm_SHA256));

        String cookieName = OPENPEER_SERVICES_RSAPRIVATEKEY_PRIVATE_KEY_VALIDATION_CACHE_NAMESPACE + keyHash;

        return cookieName;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IRSAPrivateKeyForRSAPublicKey
      #pragma mark

      //-----------------------------------------------------------------------
      ForPublicKeyPtr IRSAPrivateKeyForRSAPublicKey::generate(RSAPublicKeyPtr &outPublicKey)
      {
        return IRSAPrivateKeyFactory::singleton().generate(outPublicKey);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RSAPrivateKey
      #pragma mark

      //-----------------------------------------------------------------------
      RSAPrivateKey::RSAPrivateKey()
      {
        ZS_LOG_DEBUG(log("created"))
      }

      //-----------------------------------------------------------------------
      RSAPrivateKey::~RSAPrivateKey()
      {
        if(isNoop()) return;
        
        ZS_LOG_DEBUG(log("destoyed"))
      }

      //-----------------------------------------------------------------------
      RSAPrivateKeyPtr RSAPrivateKey::convert(IRSAPrivateKeyPtr privateKey)
      {
        return dynamic_pointer_cast<RSAPrivateKey>(privateKey);
      }

      //-----------------------------------------------------------------------
      RSAPrivateKeyPtr RSAPrivateKey::convert(ForPublicKeyPtr privateKey)
      {
        return dynamic_pointer_cast<RSAPrivateKey>(privateKey);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RSAPrivateKey => IRSAPrivateKey
      #pragma mark

      //-----------------------------------------------------------------------
      ElementPtr RSAPrivateKey::toDebug(IRSAPrivateKeyPtr object)
      {
        if (!object) return ElementPtr();
        return convert(object)->toDebug();
      }

      //-----------------------------------------------------------------------
      RSAPrivateKeyPtr RSAPrivateKey::generate(
                                               RSAPublicKeyPtr &outPublicKey,
                                               size_t keySizeInBits
                                               )
      {
        AutoSeededRandomPool rng;
        SecureByteBlock publicKeyBuffer;

        RSAPrivateKeyPtr pThis(new RSAPrivateKey);

        ZS_LOG_DEBUG(pThis->log("generating private key"))

        pThis->mPrivateKey.GenerateRandomWithKeySize(rng, static_cast<unsigned int>(keySizeInBits));
        if (!pThis->mPrivateKey.Validate(rng, 3)) {
          ZS_LOG_ERROR(Basic, pThis->log("failed to generate a new private key"))
          return RSAPrivateKeyPtr();
        }

        PublicKey rsaPublic(pThis->mPrivateKey);
        if (!rsaPublic.Validate(rng, 3)) {
          ZS_LOG_ERROR(Basic, pThis->log("Failed to generate a public key for the new private key"))
          return RSAPrivateKeyPtr();
        }

        ByteQueue byteQueue;
        rsaPublic.Save(byteQueue);

        size_t outputLengthInBytes = (size_t)byteQueue.CurrentSize();
        publicKeyBuffer.CleanNew(outputLengthInBytes);

        byteQueue.Get(publicKeyBuffer, outputLengthInBytes);

        outPublicKey = RSAPublicKey::convert(UsePublicKey::load(publicKeyBuffer));

        ZS_LOG_DEBUG(pThis->debug("generated private key") + IRSAPublicKey::toDebug(outPublicKey))

        get(pThis->mDidGenerate) = true;

        return pThis;
      }

      //-----------------------------------------------------------------------
      RSAPrivateKeyPtr RSAPrivateKey::load(const SecureByteBlock &buffer)
      {
        if (IHelper::isEmpty(buffer)) return RSAPrivateKeyPtr();

        AutoSeededRandomPool rng;

        ByteQueue byteQueue;
        byteQueue.LazyPut(buffer.BytePtr(), buffer.SizeInBytes());
        byteQueue.FinalizeLazyPut();

        RSAPrivateKeyPtr pThis(new RSAPrivateKey);

        ZS_LOG_DEBUG(pThis->log("loading private key"))
        ZS_LOG_INSANE(pThis->log("loading private key") + ZS_PARAM("private key", IHelper::convertToBase64(buffer)))

        try {
          pThis->mPrivateKey.Load(byteQueue);

          String cookieName = getCookieName(buffer);

          bool alreadyValidated = ICache::fetch(cookieName).hasData();

          if (!alreadyValidated) {
            if (!pThis->mPrivateKey.Validate(rng, 3)) {
              ZS_LOG_ERROR(Basic, pThis->log("failed to load an existing private key") + ZS_PARAM("buffer", IHelper::convertToHex(buffer)))
              return RSAPrivateKeyPtr();
            }
            ICache::store(cookieName, zsLib::now() + Hours(OPENPEER_SERVICES_RSAPRIVATEKEY_PRIVATE_KEY_VALIDATION_CACHE_STORAGE_DURATION_IN_HOURS), OPENPEER_SERVICES_RSAPRIVATEKEY_PRIVATE_KEY_VALIDATION_CACHE_VALUE);
            ZS_LOG_DEBUG(pThis->log("remembering that private key has already validated") + ZS_PARAM("cookie", cookieName))
          } else {
            ZS_LOG_DEBUG(pThis->log("already validated private key") + ZS_PARAM("cookie", cookieName))
          }
        } catch (CryptoPP::Exception &e) {
          ZS_LOG_ERROR(Basic, pThis->log("cryptography library threw an exception") + ZS_PARAM("reason", e.what()) + ZS_PARAM("buffer", IHelper::convertToHex(buffer)))
          return RSAPrivateKeyPtr();
        }

        return pThis;
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr RSAPrivateKey::save() const
      {
        SecureByteBlockPtr output(new SecureByteBlock);
        ByteQueue byteQueue;
        mPrivateKey.Save(byteQueue);

        size_t outputLengthInBytes = (size_t)byteQueue.CurrentSize();
        output->CleanNew(outputLengthInBytes);

        byteQueue.Get(*output, outputLengthInBytes);

        ZS_LOG_INSANE(log("saving private key") + ZS_PARAM("private key", IHelper::convertToBase64(*output)))

        if (mDidGenerate) {
          String cookieName = getCookieName(*output);

          ICache::store(cookieName, zsLib::now() + Hours(OPENPEER_SERVICES_RSAPRIVATEKEY_PRIVATE_KEY_VALIDATION_CACHE_STORAGE_DURATION_IN_HOURS), OPENPEER_SERVICES_RSAPRIVATEKEY_PRIVATE_KEY_VALIDATION_CACHE_VALUE);
          ZS_LOG_DEBUG(log("remembering that private key has already validated") + ZS_PARAM("cookie", cookieName))
        }
        return output;
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr RSAPrivateKey::sign(const SecureByteBlock &inBufferToSign) const
      {
        return sign(inBufferToSign, inBufferToSign.size());
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr RSAPrivateKey::sign(const String &inStrDataToSign) const
      {
        return sign((const BYTE *)(inStrDataToSign.c_str()), inStrDataToSign.length());
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr RSAPrivateKey::decrypt(const SecureByteBlock &buffer) const
      {
        AutoSeededRandomPool rng;
        RsaDecryptor decryptor(mPrivateKey);

        SecureByteBlockPtr output(new SecureByteBlock);

        if (IHelper::isEmpty(buffer)) return output;

        ByteQueue queue;
        queue.Put(buffer, buffer.SizeInBytes());

        ByteQueue *outputQueue = new ByteQueue;

        PK_DecryptorFilter filter(rng, decryptor, outputQueue);
        try {
          queue.CopyTo(filter);
          filter.MessageEnd();
        } catch(CryptoPP::Exception &e) {
          ZS_LOG_ERROR(Basic, log("cryptography library threw an exception") + ZS_PARAM("reason", e.what()) + ZS_PARAM("buffer", IHelper::convertToHex(buffer)))
          output->CleanNew(0);
          return output;
        }

        size_t outputLengthInBytes = (size_t)outputQueue->CurrentSize();
        output->CleanNew(outputLengthInBytes);

        outputQueue->Get(*output, outputLengthInBytes);
        return output;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RSAPrivateKey => IRSAPrivateKey
      #pragma mark

      //-----------------------------------------------------------------------
      Log::Params RSAPrivateKey::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("RSAPrivateKey");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params RSAPrivateKey::debug(const char *message) const
      {
        return Log::Params(message, toDebug());
      }

      //-----------------------------------------------------------------------
      ElementPtr RSAPrivateKey::toDebug() const
      {
        ElementPtr resultEl = Element::create("RSAPrivateKey");

        SecureByteBlockPtr output = save();

        IHelper::debugAppend(resultEl, "id", mID);

        IHelper::debugAppend(resultEl, "private key", output ? IHelper::convertToHex(*output) : String());

        return resultEl;
      }
      
      //-----------------------------------------------------------------------
      SecureByteBlockPtr RSAPrivateKey::sign(
                                             const BYTE *inBuffer,
                                             size_t inBufferSizeInBytes
                                             ) const
      {
        SecureByteBlockPtr output(new SecureByteBlock);

        AutoSeededRandomPool rng;

        Signer signer(mPrivateKey);

        size_t length = signer.MaxSignatureLength();

        output->CleanNew(length);

        signer.SignMessage(rng, inBuffer, inBufferSizeInBytes, *output);

        return output;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IRSAPrivateKeyFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IRSAPrivateKeyFactory &IRSAPrivateKeyFactory::singleton()
      {
        return RSAPrivateKeyFactory::singleton();
      }

      //-----------------------------------------------------------------------
      RSAPrivateKeyPtr IRSAPrivateKeyFactory::generate(
                                                       RSAPublicKeyPtr &outPublicKey,
                                                       size_t keySizeInBits
                                                       )
      {
        if (this) {}
        return RSAPrivateKey::generate(outPublicKey, keySizeInBits);
      }

      //-----------------------------------------------------------------------
      RSAPrivateKeyPtr IRSAPrivateKeyFactory::loadPrivateKey(const SecureByteBlock &buffer)
      {
        if (this) {}
        return RSAPrivateKey::load(buffer);
      }

    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IRSAPrivateKey
    #pragma mark

    //-------------------------------------------------------------------------
    ElementPtr IRSAPrivateKey::toDebug(IRSAPrivateKeyPtr object)
    {
      return internal::RSAPrivateKey::toDebug(object);
    }

    //-------------------------------------------------------------------------
    IRSAPrivateKeyPtr IRSAPrivateKey::generate(
                                               IRSAPublicKeyPtr &outPublicKey,
                                               size_t keySizeInBits
                                               )
    {
      internal::RSAPublicKeyPtr publicKey;
      IRSAPrivateKeyPtr result = internal::IRSAPrivateKeyFactory::singleton().generate(publicKey, keySizeInBits);
      outPublicKey = publicKey;
      return result;
    }

    //-------------------------------------------------------------------------
    IRSAPrivateKeyPtr IRSAPrivateKey::load(const SecureByteBlock &buffer)
    {
      return internal::IRSAPrivateKeyFactory::singleton().loadPrivateKey(buffer);
    }
  }
}
