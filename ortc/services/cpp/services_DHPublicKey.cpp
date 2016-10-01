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

#include <ortc/services/internal/services_DHPublicKey.h>
#include <ortc/services/internal/services_DHKeyDomain.h>

#include <ortc/services/IHelper.h>

#include <zsLib/XML.h>

namespace ortc { namespace services { ZS_DECLARE_SUBSYSTEM(ortc_services) } }

namespace ortc
{
  namespace services
  {
    namespace internal
    {
      using CryptoPP::AutoSeededRandomPool;

      using namespace zsLib::XML;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IDHPublicKeyForDHPublicKey
      #pragma mark

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DHPublicKey
      #pragma mark

      //-----------------------------------------------------------------------
      DHPublicKey::DHPublicKey(const make_private &)
      {
        ZS_LOG_DEBUG(log("created"))
      }

      //-----------------------------------------------------------------------
      DHPublicKey::~DHPublicKey()
      {
        if(isNoop()) return;
        
        ZS_LOG_DEBUG(log("destroyed"))
      }

      //-----------------------------------------------------------------------
      DHPublicKeyPtr DHPublicKey::convert(IDHPublicKeyPtr publicKey)
      {
        return ZS_DYNAMIC_PTR_CAST(DHPublicKey, publicKey);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DHPublicKey => IDHPublicKey
      #pragma mark

      //-----------------------------------------------------------------------
      ElementPtr DHPublicKey::toDebug(IDHPublicKeyPtr keyDomain)
      {
        if (!keyDomain) return ElementPtr();
        return convert(keyDomain)->toDebug();
      }


      //-----------------------------------------------------------------------
      DHPublicKeyPtr DHPublicKey::load(
                                       const SecureByteBlock &staticPublicKey,
                                       const SecureByteBlock &ephemeralPublicKey
                                       )
      {
        DHPublicKeyPtr pThis(make_shared<DHPublicKey>(make_private{}));

        pThis->mStaticPublicKey.Assign(staticPublicKey);
        pThis->mEphemeralPublicKey.Assign(ephemeralPublicKey);

        if (ZS_IS_LOGGING(Trace)) {
          ZS_LOG_TRACE(pThis->debug("loaded"))
        } else {
          ZS_LOG_DEBUG(pThis->log("loaded"))
        }

        return pThis;
      }

      //-----------------------------------------------------------------------
      void DHPublicKey::save(
                             SecureByteBlock *outStaticPublicKey,
                             SecureByteBlock *outEphemeralPublicKey
                             ) const
      {
        ZS_LOG_TRACE(log("save called"))

        if (outStaticPublicKey) {
          (*outStaticPublicKey).Assign(mStaticPublicKey);
        }
        if (outEphemeralPublicKey) {
          (*outEphemeralPublicKey).Assign(mEphemeralPublicKey);
        }
      }

      //-----------------------------------------------------------------------
      String DHPublicKey::getFingerprint() const
      {
        return IHelper::convertToHex(*IHelper::hmac(mEphemeralPublicKey, mStaticPublicKey));
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DHPublicKey => IDHPublicKeyForDHPrivateKey
      #pragma mark

      //-----------------------------------------------------------------------
      const SecureByteBlock &DHPublicKey::getStaticPublicKey() const
      {
        return mStaticPublicKey;
      }

      //-----------------------------------------------------------------------
      const SecureByteBlock &DHPublicKey::getEphemeralPublicKey() const
      {
        return mEphemeralPublicKey;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DHPublicKey => (internal)
      #pragma mark

      //-----------------------------------------------------------------------
      Log::Params DHPublicKey::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("DHPublicKey");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params DHPublicKey::debug(const char *message) const
      {
        return Log::Params(message, toDebug());
      }

      //-----------------------------------------------------------------------
      ElementPtr DHPublicKey::toDebug() const
      {
        ElementPtr resultEl = Element::create("DHPublicKey");

        IHelper::debugAppend(resultEl, "id", mID);

        IHelper::debugAppend(resultEl, "static public key", IHelper::convertToHex(mStaticPublicKey, true));
        IHelper::debugAppend(resultEl, "ephemeral public key", IHelper::convertToHex(mEphemeralPublicKey, true));

        return resultEl;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IDHPublicKeyFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IDHPublicKeyFactory &IDHPublicKeyFactory::singleton()
      {
        return DHPublicKeyFactory::singleton();
      }

      //-----------------------------------------------------------------------
      DHPublicKeyPtr IDHPublicKeyFactory::load(
                                               const SecureByteBlock &staticPublicKey,
                                               const SecureByteBlock &ephemeralPublicKey
                                               )
      {
        if (this) {}
        return DHPublicKey::load(staticPublicKey, ephemeralPublicKey);
      }

    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IDHPublicKey
    #pragma mark

    //-------------------------------------------------------------------------
    ElementPtr IDHPublicKey::toDebug(IDHPublicKeyPtr keyDomain)
    {
      return internal::DHPublicKey::toDebug(keyDomain);
    }

    //-------------------------------------------------------------------------
    IDHPublicKeyPtr IDHPublicKey::load(
                                       const SecureByteBlock &staticPublicKey,
                                       const SecureByteBlock &ephemeralPublicKey
                                       )
    {
      return internal::IDHPublicKeyFactory::singleton().load(staticPublicKey, ephemeralPublicKey);
    }

  }
}
