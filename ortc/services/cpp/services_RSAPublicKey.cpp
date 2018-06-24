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

#include <ortc/services/internal/services_RSAPublicKey.h>
#include <ortc/services/internal/services_RSAPrivateKey.h>
#include <ortc/services/internal/services_Helper.h>

#include <zsLib/eventing/IHasher.h>
#include <zsLib/XML.h>
#include <zsLib/Log.h>
#include <zsLib/Stringize.h>
#include <zsLib/helpers.h>


#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>


namespace ortc { namespace services { ZS_DECLARE_SUBSYSTEM(org_ortc_services) } }

namespace ortc
{
  namespace services
  {
    namespace internal
    {
      typedef zsLib::XML::Exceptions::CheckFailed CheckFailed;

      typedef CryptoPP::ByteQueue ByteQueue;
      typedef CryptoPP::AutoSeededRandomPool AutoSeededRandomPool;
      typedef CryptoPP::RSASSA_PKCS1v15_SHA_Verifier Verifier;

      typedef CryptoPP::RSAES_OAEP_SHA_Decryptor RsaDecryptor;
      typedef CryptoPP::RSAES_OAEP_SHA_Encryptor RsaEncryptor;

      using CryptoPP::PK_EncryptorFilter;

      ZS_DECLARE_TYPEDEF_PTR(IRSAPublicKeyForRSAPrivateKey::ForPrivateKey, ForPrivateKey)

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IRSAPublicKeyForRSAPrivateKey
      //

      //-----------------------------------------------------------------------
      ForPrivateKeyPtr IRSAPublicKeyForRSAPrivateKey::load(const SecureByteBlock &buffer) noexcept
      {
        return IRSAPublicKeyFactory::singleton().loadPublicKey(buffer);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // RSAPublicKey
      //

      //-----------------------------------------------------------------------
      RSAPublicKey::RSAPublicKey(const make_private &) noexcept
      {
        ZS_LOG_DEBUG(log("created"))
      }

      //-----------------------------------------------------------------------
      RSAPublicKey::~RSAPublicKey() noexcept
      {
        if(isNoop()) return;
        
        ZS_LOG_DEBUG(log("destroyed"))
      }

      //-----------------------------------------------------------------------
      RSAPublicKeyPtr RSAPublicKey::convert(IRSAPublicKeyPtr publicKey) noexcept
      {
        return ZS_DYNAMIC_PTR_CAST(RSAPublicKey, publicKey);
      }

      //-----------------------------------------------------------------------
      RSAPublicKeyPtr RSAPublicKey::convert(ForPrivateKeyPtr publicKey) noexcept
      {
        return ZS_DYNAMIC_PTR_CAST(RSAPublicKey, publicKey);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // RSAPublicKey => IRSAPublicKey
      //

      //-----------------------------------------------------------------------
      ElementPtr RSAPublicKey::toDebug(IRSAPublicKeyPtr object) noexcept
      {
        if (!object) return ElementPtr();
        return convert(object)->toDebug();
      }

      //-----------------------------------------------------------------------
      RSAPublicKeyPtr RSAPublicKey::generate(RSAPrivateKeyPtr &outPrivatekey) noexcept
      {
        RSAPublicKeyPtr result;
        outPrivatekey = RSAPrivateKey::convert(UsePrivateKey::generate(result));
        return result;
      }

      //-----------------------------------------------------------------------
      RSAPublicKeyPtr RSAPublicKey::load(const SecureByteBlock &buffer) noexcept
      {
        if (IHelper::isEmpty(buffer)) return RSAPublicKeyPtr();

        AutoSeededRandomPool rng;

        ByteQueue byteQueue;
        byteQueue.LazyPut(buffer.BytePtr(), buffer.SizeInBytes());
        byteQueue.FinalizeLazyPut();

        RSAPublicKeyPtr pThis(make_shared<RSAPublicKey>(make_private{}));

        ZS_LOG_INSANE(pThis->log("loading public key") + ZS_PARAM("public key", IHelper::convertToBase64(buffer)))

        try
        {
          pThis->mPublicKey.Load(byteQueue);
          pThis->mFingerprint = IHelper::convertToHex(*IHasher::hash(buffer));
          if (!pThis->mPublicKey.Validate(rng, 3)) {
            ZS_LOG_ERROR(Basic, pThis->log("failed to load an existing public key"))
            return RSAPublicKeyPtr();
          }
        } catch (CryptoPP::Exception &e) {
          ZS_LOG_WARNING(Detail, pThis->log("cryptography library threw an exception") + ZS_PARAM("reason", e.what()))
          return RSAPublicKeyPtr();
        }

        return pThis;
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr RSAPublicKey::save() const noexcept
      {
        SecureByteBlockPtr output(make_shared<SecureByteBlock>());

        ByteQueue byteQueue;
        mPublicKey.Save(byteQueue);

        size_t outputLengthInBytes = (size_t)byteQueue.CurrentSize();
        output->CleanNew(outputLengthInBytes);

        byteQueue.Get(*output, outputLengthInBytes);

        ZS_LOG_INSANE(log("saving public key") + ZS_PARAM("public key", IHelper::convertToBase64(*output)))

        return output;
      }

      //-----------------------------------------------------------------------
      String RSAPublicKey::getFingerprint() const noexcept
      {
        return mFingerprint;
      }

      //-----------------------------------------------------------------------
      bool RSAPublicKey::verify(
                                const SecureByteBlock &inOriginalBufferSigned,
                                const SecureByteBlock &inSignature
                                ) const noexcept
      {
        return verify(inOriginalBufferSigned, inOriginalBufferSigned.size(), inSignature);
      }

      //-----------------------------------------------------------------------
      bool RSAPublicKey::verify(
                                const String &inOriginalStringSigned,
                                const SecureByteBlock &inSignature
                                ) const noexcept
      {
        return verify((const BYTE *)inOriginalStringSigned.c_str(), inOriginalStringSigned.length(), inSignature);
      }

      //-----------------------------------------------------------------------
      bool RSAPublicKey::verifySignature(ElementPtr signedEl) const noexcept
      {
        ZS_ASSERT(signedEl);

        ElementPtr signatureEl;
        signedEl = IHelper::getSignatureInfo(signedEl, &signatureEl);

        if (!signedEl) {
          ZS_LOG_WARNING(Detail, log("signature validation failed because no signed element found"))
          return false;
        }

        // found the signature reference, now check if the peer URIs match - they must...
        try {
          String algorithm = signatureEl->findFirstChildElementChecked("algorithm")->getTextDecoded();
          if (algorithm != ORTC_SERVICES_JSON_SIGNATURE_ALGORITHM) {
            ZS_LOG_WARNING(Detail, log("signature validation algorithm is not understood") + ZS_PARAM("algorithm", algorithm))
            return false;
          }

          String signatureDigestAsString = signatureEl->findFirstChildElementChecked("digestValue")->getTextDecoded();

          ElementPtr canonicalSigned = Helper::cloneAsCanonicalJSON(signedEl);

          GeneratorPtr generator = Generator::createJSONGenerator();
          std::unique_ptr<char[]> signedElAsJSON = generator->write(canonicalSigned);

          SecureByteBlockPtr actualDigest = IHasher::hash((const char *)(signedElAsJSON.get()), IHasher::sha1());

          if (0 != IHelper::compare(*actualDigest, *IHelper::convertFromBase64(signatureDigestAsString))) {
            ZS_LOG_WARNING(Detail, log("digest values did not match") + ZS_PARAM("signature digest", signatureDigestAsString) + ZS_PARAM("actual digest", IHelper::convertToBase64(*actualDigest)))
            return false;
          }

          SecureByteBlockPtr signatureDigestSigned = IHelper::convertFromBase64(signatureEl->findFirstChildElementChecked("digestSigned")->getTextDecoded());

          if (!verify(*actualDigest, *signatureDigestSigned)) {
            ZS_LOG_WARNING(Detail, log("signature failed to validate") + ZS_PARAM("fingerprint", mFingerprint))
            return false;
          }

        } catch(CheckFailed &) {
          ZS_LOG_WARNING(Detail, log("signature missing element"))
          return false;
        }
        return true;
      }
      
      //-----------------------------------------------------------------------
      SecureByteBlockPtr RSAPublicKey::encrypt(const SecureByteBlock &buffer) const noexcept
      {
        AutoSeededRandomPool rng;
        RsaEncryptor encryptor(mPublicKey);

        SecureByteBlockPtr output(make_shared<SecureByteBlock>());

        if (IHelper::isEmpty(buffer)) return output;

        ByteQueue queue;
        queue.Put(buffer, buffer.SizeInBytes());

        ByteQueue *outputQueue = new ByteQueue;
        PK_EncryptorFilter filter(rng, encryptor, outputQueue);

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
      //
      // RSAPublicKey => (internal)
      //

      //-----------------------------------------------------------------------
      Log::Params RSAPublicKey::log(const char *message) const noexcept
      {
        ElementPtr objectEl = Element::create("RSAPublicKey");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      ElementPtr RSAPublicKey::toDebug() const noexcept
      {
        ElementPtr resultEl = Element::create("RSAPublicKey");

        SecureByteBlockPtr output = save();

        IHelper::debugAppend(resultEl, "id", mID);

        IHelper::debugAppend(resultEl, "fingerprint", mFingerprint);
        IHelper::debugAppend(resultEl, "public key", output ? IHelper::convertToHex(*output) : String());

        return resultEl;
      }

      //-----------------------------------------------------------------------
      bool RSAPublicKey::verify(
                                const BYTE *inBuffer,
                                size_t inBufferLengthInBytes,
                                const SecureByteBlock &inSignature
                                ) const noexcept
      {
        Verifier verifier(mPublicKey);

        try
        {
          bool result = verifier.VerifyMessage(inBuffer, inBufferLengthInBytes, inSignature, inSignature.size());
          if (!result) {
            ZS_LOG_WARNING(Detail, log("signature verification did not pass"))
            return false;
          }
        } catch (CryptoPP::Exception &e) {
          ZS_LOG_WARNING(Detail, log("cryptography library threw an exception") + ZS_PARAM("reason", e.what()))
          return false;
        }
        return true;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IRSAPublicKeyFactory
      //

      //-----------------------------------------------------------------------
      IRSAPublicKeyFactory &IRSAPublicKeyFactory::singleton() noexcept
      {
        return RSAPublicKeyFactory::singleton();
      }

      //-----------------------------------------------------------------------
      RSAPublicKeyPtr IRSAPublicKeyFactory::loadPublicKey(const SecureByteBlock &buffer) noexcept
      {
        if (this) {}
        return RSAPublicKey::load(buffer);
      }

    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //
    // IRSAPublicKey
    //

    //-------------------------------------------------------------------------
    ElementPtr IRSAPublicKey::toDebug(IRSAPublicKeyPtr object) noexcept
    {
      return internal::RSAPublicKey::toDebug(object);
    }

    //-------------------------------------------------------------------------
    IRSAPublicKeyPtr IRSAPublicKey::generate(IRSAPrivateKeyPtr &outPrivateKey) noexcept
    {
      internal::RSAPrivateKeyPtr privateKey;
      IRSAPublicKeyPtr publicKey = internal::RSAPublicKey::generate(privateKey);
      outPrivateKey = privateKey;
      return publicKey;
    }

    //-------------------------------------------------------------------------
    IRSAPublicKeyPtr IRSAPublicKey::load(const SecureByteBlock &buffer) noexcept
    {
      return internal::IRSAPublicKeyFactory::singleton().loadPublicKey(buffer);
    }

  }
}
