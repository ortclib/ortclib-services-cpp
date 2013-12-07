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

#include <openpeer/services/internal/services_DHPrivateKey.h>
#include <openpeer/services/internal/services_DHKeyDomain.h>
#include <openpeer/services/internal/services_DHPublicKey.h>

#include <openpeer/services/IDHPublicKey.h>
#include <openpeer/services/IHelper.h>

#include <cryptopp/osrng.h>
#include <cryptopp/dh.h>
#include <cryptopp/dh2.h>

#include <zsLib/XML.h>

namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services) } }


namespace openpeer
{
  namespace services
  {
    namespace internal
    {
      using CryptoPP::AutoSeededRandomPool;
      using CryptoPP::DH;
      using CryptoPP::DH2;

      using namespace zsLib::XML;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IDHPrivateKeyForDHPrivateKey
      #pragma mark

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DHPrivateKey
      #pragma mark

      //-----------------------------------------------------------------------
      DHPrivateKey::DHPrivateKey(IDHKeyDomainPtr keyDomain) :
        mKeyDomain(DHKeyDomain::convert(keyDomain))
      {
        ZS_LOG_DEBUG(log("created"))

        ZS_THROW_BAD_STATE_IF(!mKeyDomain)
      }

      //-----------------------------------------------------------------------
      DHPrivateKey::~DHPrivateKey()
      {
        if(isNoop()) return;
        
        ZS_LOG_DEBUG(log("destroyed"))
      }

      //-----------------------------------------------------------------------
      DHPrivateKeyPtr DHPrivateKey::convert(IDHPrivateKeyPtr publicKey)
      {
        return boost::dynamic_pointer_cast<DHPrivateKey>(publicKey);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DHPrivateKey => IDHPrivateKey
      #pragma mark

      //-----------------------------------------------------------------------
      ElementPtr DHPrivateKey::toDebug(IDHPrivateKeyPtr keyDomain)
      {
        if (!keyDomain) return ElementPtr();
        return convert(keyDomain)->toDebug();
      }


      //-----------------------------------------------------------------------
      DHPrivateKeyPtr DHPrivateKey::generate(
                                             IDHKeyDomainPtr keyDomain,
                                             IDHPublicKeyPtr &outPublicKey
                                             )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!keyDomain)

        DHPrivateKeyPtr pThis(new DHPrivateKey(keyDomain));

        AutoSeededRandomPool rnd;

        DH &dh = pThis->mKeyDomain->forDHPrivateKey().getDH();

        DH2 dh2(dh);

        pThis->mStaticPrivateKey.CleanNew(dh2.StaticPrivateKeyLength());
        pThis->mEphemeralPrivateKey.CleanNew(dh2.EphemeralPrivateKeyLength());

        SecureByteBlock staticPublicKey(dh2.StaticPublicKeyLength());
        SecureByteBlock ephemeralPublicKey(dh2.EphemeralPublicKeyLength());

        dh2.GenerateStaticKeyPair(rnd, pThis->mStaticPrivateKey, staticPublicKey);
        dh2.GenerateEphemeralKeyPair(rnd, pThis->mEphemeralPrivateKey, ephemeralPublicKey);

        IDHPublicKeyPtr publicKey = IDHPublicKey::load(staticPublicKey, ephemeralPublicKey);

        outPublicKey = publicKey;

        ZS_LOG_DEBUG(pThis->debug("generated private key"))

        return pThis;
      }

      //-----------------------------------------------------------------------
      DHPrivateKeyPtr DHPrivateKey::load(
                                         IDHKeyDomainPtr keyDomain,
                                         const SecureByteBlock &staticPrivateKey,
                                         const SecureByteBlock &ephemeralPrivateKey
                                         )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!keyDomain)

        DHPrivateKeyPtr pThis(new DHPrivateKey(keyDomain));

        pThis->mStaticPrivateKey.Assign(staticPrivateKey);
        pThis->mEphemeralPrivateKey.Assign(ephemeralPrivateKey);

        ZS_LOG_DEBUG(pThis->debug("loaded"))

        return pThis;
      }

      //-----------------------------------------------------------------------
      DHPrivateKeyPtr DHPrivateKey::load(
                                         IDHKeyDomainPtr keyDomain,
                                         IDHPublicKeyPtr &outPublicKey,
                                         const SecureByteBlock &staticPrivateKey,
                                         const SecureByteBlock &ephemeralPrivateKey,
                                         const SecureByteBlock &staticPublicKey,
                                         const SecureByteBlock &ephemeralPublicKey
                                         )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!keyDomain)

        DHPrivateKeyPtr pThis = DHPrivateKey::load(keyDomain, staticPrivateKey, staticPublicKey);
        IDHPublicKeyPtr publicKey = IDHPublicKey::load(staticPublicKey, ephemeralPublicKey);
        if ((!pThis) ||
            (!publicKey)) {
          ZS_LOG_ERROR(Detail, slog("failed to load public / private key pair") + IDHPrivateKey::toDebug(pThis) + IDHPublicKey::toDebug(publicKey))
          return DHPrivateKeyPtr();
        }

        ZS_LOG_DEBUG(pThis->log("successsfully loaded public / private key pair"))

        outPublicKey = publicKey;
        return pThis;
      }
      
      //-----------------------------------------------------------------------
      DHPrivateKeyPtr DHPrivateKey::loadAndGenerateNewEphemeral(
                                                                IDHKeyDomainPtr keyDomain,
                                                                const SecureByteBlock &staticPrivateKey,
                                                                const SecureByteBlock &staticPublicKey,
                                                                IDHPublicKeyPtr &outNewPublicKey
                                                                )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!keyDomain)

        DHPrivateKeyPtr pThis(new DHPrivateKey(keyDomain));

        DH &dh = pThis->mKeyDomain->forDHPrivateKey().getDH();

        AutoSeededRandomPool rnd;

        DH2 dh2(dh);

        pThis->mStaticPrivateKey.Assign(staticPrivateKey);

        pThis->mEphemeralPrivateKey.CleanNew(dh2.EphemeralPrivateKeyLength());
        SecureByteBlock ephemeralPublicKey(dh2.EphemeralPublicKeyLength());

        dh2.GenerateEphemeralKeyPair(rnd, pThis->mEphemeralPrivateKey, ephemeralPublicKey);

        IDHPublicKeyPtr publicKey = IDHPublicKey::load(staticPublicKey, ephemeralPublicKey);
        if (!publicKey) {
          ZS_LOG_ERROR(Detail, pThis->log("failed to load existing public key"))
          return DHPrivateKeyPtr();
        }

        outNewPublicKey = publicKey;

        ZS_LOG_DEBUG(pThis->debug("loaded and generated new ephemeral key") + IDHPublicKey::toDebug(publicKey))

        return pThis;
      }

      //-----------------------------------------------------------------------
      DHPrivateKeyPtr DHPrivateKey::loadAndGenerateNewEphemeral(
                                                                IDHPrivateKeyPtr templatePrivateKey,
                                                                IDHPublicKeyPtr templatePublicKey,
                                                                IDHPublicKeyPtr &outNewPublicKey
                                                                )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!templatePrivateKey)
        ZS_THROW_INVALID_ARGUMENT_IF(!templatePublicKey)

        IDHKeyDomainPtr keyDomain = templatePrivateKey->getKeyDomain();
        ZS_THROW_INVALID_ASSUMPTION_IF(!keyDomain)

        SecureByteBlock staticPrivateKey;
        SecureByteBlock staticPublicKey;

        templatePrivateKey->save(&staticPrivateKey, NULL);
        templatePublicKey->save(&staticPublicKey, NULL);

        return DHPrivateKey::loadAndGenerateNewEphemeral(keyDomain, staticPrivateKey, staticPublicKey, outNewPublicKey);
      }
      
      //-----------------------------------------------------------------------
      void DHPrivateKey::save(
                              SecureByteBlock *outStaticPrivateKey,
                              SecureByteBlock *outEphemeralPrivateKey
                              ) const
      {
        ZS_LOG_TRACE(log("save called"))

        if (outStaticPrivateKey) {
          (*outStaticPrivateKey).Assign(mStaticPrivateKey);
        }
        if (outEphemeralPrivateKey) {
          (*outEphemeralPrivateKey).Assign(mEphemeralPrivateKey);
        }
      }

      //-----------------------------------------------------------------------
      IDHKeyDomainPtr DHPrivateKey::getKeyDomain() const
      {
        return mKeyDomain;
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr DHPrivateKey::getSharedSecret(IDHPublicKeyPtr otherPartyPublicKey) const
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!otherPartyPublicKey)

        AutoSeededRandomPool rnd;

        DH &dh = mKeyDomain->forDHPrivateKey().getDH();

        DH2 dh2(dh);

        SecureByteBlockPtr key(new SecureByteBlock(dh2.AgreedValueLength()));

        DHPublicKeyPtr publicKey = DHPublicKey::convert(otherPartyPublicKey);

        const SecureByteBlock &staticPublicKey = publicKey->forDHPrivateKey().getStaticPublicKey();
        const SecureByteBlock &ephemeralPublicKey = publicKey->forDHPrivateKey().getEphemeralPublicKey();

        try {
          if(!dh2.Agree((*key), mStaticPrivateKey, mEphemeralPrivateKey, staticPublicKey, ephemeralPublicKey)) {
            ZS_LOG_ERROR(Detail, debug("failed to agree upon a shared secret") + ZS_PARAM("agree length", dh2.AgreedValueLength()) + IDHPublicKey::toDebug(otherPartyPublicKey))
            return SecureByteBlockPtr();
          }
        } catch (CryptoPP::Exception &e) {
          ZS_LOG_ERROR(Basic, debug("cryptography library threw an exception") + ZS_PARAM("agree length", dh2.AgreedValueLength()) + ZS_PARAM("what", e.what()))
          return SecureByteBlockPtr();
        }

        ZS_LOG_TRACE(log("generated shared secret") + ZS_PARAM("agree length", dh2.AgreedValueLength()) + ZS_PARAM("secret", IHelper::convertToHex(*key, true)))
        return key;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DHPrivateKey => (internal)
      #pragma mark

      //-----------------------------------------------------------------------
      Log::Params DHPrivateKey::slog(const char *message)
      {
        return Log::Params(message, "DHPrivateKey");
      }

      //-----------------------------------------------------------------------
      Log::Params DHPrivateKey::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("DHPrivateKey");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params DHPrivateKey::debug(const char *message) const
      {
        return Log::Params(message, toDebug());
      }

      //-----------------------------------------------------------------------
      ElementPtr DHPrivateKey::toDebug() const
      {
        ElementPtr resultEl = Element::create("DHPrivateKey");

        IHelper::debugAppend(resultEl, "id", mID);
        IHelper::debugAppend(resultEl, "key domain id", mKeyDomain->forDHPrivateKey().getID());

        IHelper::debugAppend(resultEl, "static private key", IHelper::convertToHex(mStaticPrivateKey, true));
        IHelper::debugAppend(resultEl, "ephemeral private key", IHelper::convertToHex(mEphemeralPrivateKey, true));

        return resultEl;
      }

    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IDHPrivateKey
    #pragma mark

    //-------------------------------------------------------------------------
    ElementPtr IDHPrivateKey::toDebug(IDHPrivateKeyPtr keyDomain)
    {
      return internal::DHPrivateKey::toDebug(keyDomain);
    }

    //-------------------------------------------------------------------------
    IDHPrivateKeyPtr IDHPrivateKey::generate(
                                             IDHKeyDomainPtr keyDomain,
                                             IDHPublicKeyPtr &outPublicKey
                                             )
    {
      return internal::IDHPrivateKeyFactory::singleton().generate(keyDomain, outPublicKey);
    }

    //-------------------------------------------------------------------------
    IDHPrivateKeyPtr IDHPrivateKey::load(
                                         IDHKeyDomainPtr keyDomain,
                                         const SecureByteBlock &staticPrivateKey,
                                         const SecureByteBlock &ephemeralPrivateKey
                                         )
    {
      return internal::IDHPrivateKeyFactory::singleton().load(keyDomain, staticPrivateKey, ephemeralPrivateKey);
    }

    //-------------------------------------------------------------------------
    IDHPrivateKeyPtr IDHPrivateKey::load(
                                         IDHKeyDomainPtr keyDomain,
                                         IDHPublicKeyPtr &outPublicKey,
                                         const SecureByteBlock &staticPrivateKey,
                                         const SecureByteBlock &ephemeralPrivateKey,
                                         const SecureByteBlock &staticPublicKey,
                                         const SecureByteBlock &ephemeralPublicKey
                                         )
    {
      return internal::IDHPrivateKeyFactory::singleton().load(keyDomain, outPublicKey, staticPrivateKey, ephemeralPrivateKey, staticPublicKey, ephemeralPublicKey);
    }

    //-------------------------------------------------------------------------
    IDHPrivateKeyPtr IDHPrivateKey::loadAndGenerateNewEphemeral(
                                                                IDHKeyDomainPtr keyDomain,
                                                                const SecureByteBlock &staticPrivateKey,
                                                                const SecureByteBlock &staticPublicKey,
                                                                IDHPublicKeyPtr &outNewPublicKey
                                                                )
    {
      return internal::IDHPrivateKeyFactory::singleton().loadAndGenerateNewEphemeral(keyDomain, staticPrivateKey, staticPublicKey, outNewPublicKey);
    }

    //-------------------------------------------------------------------------
    IDHPrivateKeyPtr IDHPrivateKey::loadAndGenerateNewEphemeral(
                                                                IDHPrivateKeyPtr templatePrivateKey,
                                                                IDHPublicKeyPtr templatePublicKey,
                                                                IDHPublicKeyPtr &outNewPublicKey
                                                                )
    {
      return internal::IDHPrivateKeyFactory::singleton().loadAndGenerateNewEphemeral(templatePrivateKey, templatePublicKey, outNewPublicKey);
    }

  }
}
