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

#include <ortc/services/internal/services_MessageLayerSecurityChannel.h>
#include <ortc/services/internal/services_Helper.h>
#include <ortc/services/IRSAPrivateKey.h>
#include <ortc/services/IRSAPublicKey.h>
#include <ortc/services/IHTTP.h>
#include <ortc/services/IDHKeyDomain.h>
#include <ortc/services/IDHPrivateKey.h>
#include <ortc/services/IDHPublicKey.h>
#include <ortc/services/ICache.h>

#include <zsLib/eventing/IHasher.h>
#include <zsLib/ISettings.h>
#include <zsLib/Log.h>
#include <zsLib/XML.h>
#include <zsLib/helpers.h>

#include <zsLib/Stringize.h>
#include <zsLib/Numeric.h>

#define ORTC_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_TOTAL_SEND_KEYS 3

#define ORTC_SERVICES_MLS_DEFAULT_KEYING_EXPIRES_TIME_IN_SECONDS (2*(60*60))

#define ORTC_SERVICES_MLS_COOKIE_NONCE_CACHE_NAMESPACE "https://meta.ortclib.org/caching/mls/nonce/"


namespace ortc { namespace services { ZS_DECLARE_SUBSYSTEM(ortc_services_mls) } }

namespace ortc
{
  namespace services
  {
    using zsLib::DWORD;
    using zsLib::Numeric;

    namespace internal
    {
      ZS_DECLARE_CLASS_PTR(MessageLayerSecurityChannelSettingsDefaults);

      typedef zsLib::XML::Exceptions::CheckFailed CheckFailed;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark (helpers)
      #pragma mark

      //-----------------------------------------------------------------------
      static String getElementTextAndDecode(ElementPtr node)
      {
        if (!node) return String();
        return node->getTextDecoded();
      }

      //-----------------------------------------------------------------------
      static ElementPtr createElementWithText(
                                              const String &elName,
                                              const String &textVal
                                              )
      {
        ElementPtr tmp = Element::create(elName);
        if (textVal.isEmpty()) return tmp;

        TextPtr tmpTxt = Text::create();
        tmpTxt->setValueAndJSONEncode(textVal);
        tmp->adoptAsFirstChild(tmpTxt);
        return tmp;
      }

      //-----------------------------------------------------------------------
      static ElementPtr createElementWithNumber(
                                                const String &elName,
                                                const String &numberAsStringValue
                                                )
      {
        ElementPtr tmp = Element::create(elName);

        if (numberAsStringValue.isEmpty()) return tmp;

        TextPtr tmpTxt = Text::create();
        tmpTxt->setValue(numberAsStringValue, Text::Format_JSONNumberEncoded);
        tmp->adoptAsFirstChild(tmpTxt);

        return tmp;
      }
      
      //-----------------------------------------------------------------------
      static SecureByteBlockPtr decryptUsingPassphraseEncoding(
                                                               const String &passphrase,
                                                               const String &nonce,
                                                               const String &value
                                                               )
      {
        typedef IHelper::SplitMap SplitMap;

        //hex(`<salt>`) + ":" + base64(encrypt(`<encrypted-value>`)), where key = hmac(`<external-passphrase>`, "keying:" + `<nonce>`), iv = `<salt>`

        SplitMap values;
        IHelper::split(value, values, ':');

        if (values.size() < 2) {
          ZS_LOG_WARNING(Debug, Log::Params("failed to split hex salt from encrypted value") + ZS_PARAM("value", value))
          return SecureByteBlockPtr();
        }

        String hexSalt = values[0];
        String base64Value = values[1];

        SecureByteBlockPtr iv = IHelper::convertFromHex(hexSalt);
        SecureByteBlockPtr input = IHelper::convertFromBase64(base64Value);

        SecureByteBlockPtr key = IHasher::hash("keying:" + nonce, IHasher::hmacSHA256(*IHasher::hmacKeyFromPassphrase(passphrase)));

        if ((IHelper::isEmpty(iv)) || (IHelper::isEmpty(key)) || (IHelper::isEmpty(input))) {
          ZS_LOG_WARNING(Debug, String("missing vital information required to be able to decrypt value"))
          return SecureByteBlockPtr();
        }

        return IHelper::decrypt(*key, *iv, *input);
      }
      
      //-----------------------------------------------------------------------
      static String encodeUsingPassphraseEncoding(
                                                  const String &passphrase,
                                                  const String &nonce,
                                                  const SecureByteBlock &value
                                                  )
      {
        typedef IHelper::SplitMap SplitMap;

        //hex(`<salt>`) + ":" + base64(encrypt(`<encrypted-value>`)), where key = hmac(`<external-passphrase>`, "keying:" + `<nonce>`), iv = `<salt>`

        SecureByteBlockPtr iv = IHelper::random(IHasher::md5DigestSize());
        String hexSalt = IHelper::convertToHex(*iv);

        SecureByteBlockPtr key = IHasher::hash("keying:" + nonce, IHasher::hmacSHA256(*IHasher::hmacKeyFromPassphrase(passphrase)));

        SecureByteBlockPtr output = IHelper::encrypt(*key, *iv, value);

        return IHelper::convertToHex(*iv) + ":" + IHelper::convertToBase64(*output);
      }
      

      //-------------------------------------------------------------------------
      //-------------------------------------------------------------------------
      //-------------------------------------------------------------------------
      //-------------------------------------------------------------------------
      #pragma mark
      #pragma mark MessageLayerSecurityChannelSettingsDefaults
      #pragma mark

      class MessageLayerSecurityChannelSettingsDefaults : public ISettingsApplyDefaultsDelegate
      {
      public:
        //-----------------------------------------------------------------------
        ~MessageLayerSecurityChannelSettingsDefaults()
        {
          ISettings::removeDefaults(*this);
        }

        //-----------------------------------------------------------------------
        static MessageLayerSecurityChannelSettingsDefaultsPtr singleton()
        {
          static SingletonLazySharedPtr<MessageLayerSecurityChannelSettingsDefaults> singleton(create());
          return singleton.singleton();
        }

        //-----------------------------------------------------------------------
        static MessageLayerSecurityChannelSettingsDefaultsPtr create()
        {
          auto pThis(make_shared<MessageLayerSecurityChannelSettingsDefaults>());
          ISettings::installDefaults(pThis);
          return pThis;
        }

        //-----------------------------------------------------------------------
        virtual void notifySettingsApplyDefaults() override
        {
          ISettings::setUInt(ORTC_SERVICES_SETTING_MESSAGE_LAYER_SECURITY_CHANGE_SENDING_KEY_AFTER, 60 * 60);
        }
      };

      //-------------------------------------------------------------------------
      void installMessageLayerSecurityChannelSettingsDefaults()
      {
        MessageLayerSecurityChannelSettingsDefaults::singleton();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark MessageLayerSecurityChannel
      #pragma mark

      //-----------------------------------------------------------------------
      MessageLayerSecurityChannel::MessageLayerSecurityChannel(
                                                               const make_private &,
                                                               IMessageQueuePtr queue,
                                                               IMessageLayerSecurityChannelDelegatePtr delegate,
                                                               ITransportStreamPtr receiveStreamEncoded,
                                                               ITransportStreamPtr receiveStreamDecoded,
                                                               ITransportStreamPtr sendStreamDecoded,
                                                               ITransportStreamPtr sendStreamEncoded,
                                                               const char *contextID
                                                               ) :
        zsLib::MessageQueueAssociator(queue),
        SharedRecursiveLock(SharedRecursiveLock::create()),

        mCurrentState(SessionState_Pending),

        mLocalContextID(contextID),

        mReceiveKeyingType(KeyingType_Unknown),
        mSendKeyingType(KeyingType_Unknown),

        mNextReceiveSequenceNumber(0),
        mNextSendSequenceNumber(0),

        mReceiveStreamEncoded(receiveStreamEncoded->getReader()),
        mReceiveStreamDecoded(receiveStreamDecoded->getWriter()),
        mSendStreamDecoded(sendStreamDecoded->getReader()),
        mSendStreamEncoded(sendStreamEncoded->getWriter())
      {
        ZS_LOG_DETAIL(log("created"))
        mDefaultSubscription = mSubscriptions.subscribe(delegate);
        ZS_THROW_BAD_STATE_IF(!mDefaultSubscription)
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::init()
      {
        AutoRecursiveLock lock(*this);

        mReceiveStreamEncodedSubscription = mReceiveStreamEncoded->subscribe(mThisWeak.lock());
        mReceiveStreamDecodedSubscription = mReceiveStreamDecoded->subscribe(mThisWeak.lock());
        mSendStreamDecodedSubscription = mSendStreamDecoded->subscribe(mThisWeak.lock());
        mSendStreamEncodedSubscription = mSendStreamEncoded->subscribe(mThisWeak.lock());

        IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
      }

      //-----------------------------------------------------------------------
      MessageLayerSecurityChannel::~MessageLayerSecurityChannel()
      {
        ZS_LOG_DETAIL(log("destroyed"))
        mThisWeak.reset();
        cancel();
      }

      //-----------------------------------------------------------------------
      MessageLayerSecurityChannelPtr MessageLayerSecurityChannel::convert(IMessageLayerSecurityChannelPtr channel)
      {
        return ZS_DYNAMIC_PTR_CAST(MessageLayerSecurityChannel, channel);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark MessageLayerSecurityChannel => IMessageLayerSecurityChannel
      #pragma mark

      //-----------------------------------------------------------------------
      ElementPtr MessageLayerSecurityChannel::toDebug(IMessageLayerSecurityChannelPtr channel)
      {
        if (!channel) return ElementPtr();

        MessageLayerSecurityChannelPtr pThis = MessageLayerSecurityChannel::convert(channel);
        return pThis->toDebug();
      }

      //-----------------------------------------------------------------------
      MessageLayerSecurityChannelPtr MessageLayerSecurityChannel::create(
                                                                         IMessageLayerSecurityChannelDelegatePtr delegate,
                                                                         ITransportStreamPtr receiveStreamEncoded,
                                                                         ITransportStreamPtr receiveStreamDecoded,
                                                                         ITransportStreamPtr sendStreamDecoded,
                                                                         ITransportStreamPtr sendStreamEncoded,
                                                                         const char *contextID
                                                                         )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!receiveStreamEncoded)
        ZS_THROW_INVALID_ARGUMENT_IF(!receiveStreamDecoded)
        ZS_THROW_INVALID_ARGUMENT_IF(!sendStreamDecoded)
        ZS_THROW_INVALID_ARGUMENT_IF(!sendStreamEncoded)
        MessageLayerSecurityChannelPtr pThis(make_shared<MessageLayerSecurityChannel>(make_private{}, IHelper::getServiceQueue(), delegate, receiveStreamEncoded, receiveStreamDecoded, sendStreamDecoded, sendStreamEncoded, contextID));
        pThis->mThisWeak = pThis;
        pThis->init();
        return pThis;
      }

      //-----------------------------------------------------------------------
      IMessageLayerSecurityChannelSubscriptionPtr MessageLayerSecurityChannel::subscribe(IMessageLayerSecurityChannelDelegatePtr originalDelegate)
      {
        AutoRecursiveLock lock(*this);
        if (!originalDelegate) return mDefaultSubscription;

        IMessageLayerSecurityChannelSubscriptionPtr subscription = mSubscriptions.subscribe(originalDelegate);

        IMessageLayerSecurityChannelDelegatePtr delegate = mSubscriptions.delegate(subscription, true);

        if (delegate) {
          MessageLayerSecurityChannelPtr pThis = mThisWeak.lock();
          
          if (SessionState_Pending != mCurrentState) {
            delegate->onMessageLayerSecurityChannelStateChanged(pThis, mCurrentState);
          }
        }

        if (isShutdown()) {
          mSubscriptions.clear();
        }

        return subscription;
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::cancel()
      {
        ZS_LOG_DEBUG(log("cancel called"))

        AutoRecursiveLock lock(*this);

        setState(SessionState_Shutdown);

        mSubscriptions.clear();


        mReceivePassphrase.clear();
        mSendPassphrase.clear();

        mDHKeyDomain.reset();

        mDHLocalPrivateKey.reset();
        mDHLocalPublicKey.reset();

        mDHRemotePublicKey.reset();
        //mDHOriginalRemotePublicKey.reset(); // do not reset
        mDHRemotePublicKeyFingerprint.clear();

        mDHPreviousLocalKeys.clear();

        mReceiveLocalPrivateKey.reset();
        mReceiveLocalPublicKey.reset();
        mSendRemotePublicKey.reset();

        mReceiveSigningPublicKey.reset();
        mReceiveKeyingSignedDoc.reset();
        mReceiveKeyingSignedEl.reset();


        mSendSigningPrivateKey.reset();
        mSendKeyingNeedingToSignDoc.reset();
        mSendKeyingNeedToSignEl.reset();


        mReceiveStreamEncoded->cancel();
        mReceiveStreamDecoded->cancel();

        mSendStreamDecoded->cancel();
        mSendStreamEncoded->cancel();

        mReceiveStreamEncodedSubscription->cancel();
        mReceiveStreamDecodedSubscription->cancel();
        mSendStreamDecodedSubscription->cancel();
        mSendStreamEncodedSubscription->cancel();


        mReceiveKeys.clear();
        mSendKeys.clear();

        if (mChangeSendingKeyTimer) {
          mChangeSendingKeyTimer->cancel();
          mChangeSendingKeyTimer.reset();
        }


        ZS_LOG_DEBUG(log("cancel complete"))
      }

      //-----------------------------------------------------------------------
      IMessageLayerSecurityChannel::SessionStates MessageLayerSecurityChannel::getState(
                                                                                        WORD *outLastErrorCode,
                                                                                        String *outLastErrorReason
                                                                                        ) const
      {
        AutoRecursiveLock lock(*this);
        if (outLastErrorCode) *outLastErrorCode = mLastError;
        if (outLastErrorReason) *outLastErrorReason = mLastErrorReason;
        return mCurrentState;
      }

      //-----------------------------------------------------------------------
      bool MessageLayerSecurityChannel::needsLocalContextID() const
      {
        AutoRecursiveLock lock(*this);
        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("cannot need information as already shutdown"))
          return false;
        }

        return mLocalContextID.isEmpty();
      }

      //-----------------------------------------------------------------------
      bool MessageLayerSecurityChannel::needsReceiveKeying(KeyingTypes *outDecodingType) const
      {
        AutoRecursiveLock lock(*this);
        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("cannot need receive keying information as already shutdown"))
          return false;
        }

        if (outDecodingType) {
          *outDecodingType = mReceiveKeyingType;
        }

        switch (mReceiveKeyingType) {
          case KeyingType_Unknown:      break;
          case KeyingType_Passphrase:   {
            ZS_LOG_TRACE(log("needs receive keying - passphrase") + ZS_PARAM("passphrase", mReceivePassphrase))
            return mReceivePassphrase.isEmpty();
          }
          case KeyingType_PublicKey:    {
            ZS_LOG_TRACE(log("needs receive keying - private key") + IRSAPrivateKey::toDebug(mReceiveLocalPrivateKey) + IRSAPublicKey::toDebug(mReceiveLocalPublicKey))
            return (!((bool)mReceiveLocalPrivateKey)) ||
                   (!((bool)mReceiveLocalPublicKey));
          }
          case KeyingType_KeyAgreement: {
            ZS_LOG_TRACE(log("needs receive keying - key agreement") + ZS_PARAM("local private key", IDHPrivateKey::toDebug(mDHLocalPrivateKey)) + ZS_PARAM("local public key", IDHPublicKey::toDebug(mDHLocalPublicKey)) + ZS_PARAM("remote public key", IDHPublicKey::toDebug(mDHRemotePublicKey)) + ZS_PARAM("remote public key fingerprint", mDHRemotePublicKeyFingerprint))
            return (!((bool)mDHLocalPrivateKey)) ||
                   (!((bool)mDHLocalPublicKey)) ||
                   (!((bool)mDHRemotePublicKey));
          }
        }

        ZS_LOG_TRACE(log("needs receive keying - unknown receive keying type"))
        return true;
      }

      //-----------------------------------------------------------------------
      bool MessageLayerSecurityChannel::needsSendKeying(KeyingTypes *outEncodingType) const
      {
        AutoRecursiveLock lock(*this);
        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("cannot need send keying information as already shutdown"))
          return false;
        }

        if (outEncodingType) {
          *outEncodingType = mReceiveKeyingType;
        }

        switch (mSendKeyingType) {
          case KeyingType_Unknown:      break;
          case KeyingType_Passphrase:   {
            ZS_LOG_TRACE(log("needs send keying - passphrase") + ZS_PARAM("passphrase", mSendPassphrase) + IRSAPublicKey::toDebug(mSendRemotePublicKey))
            return (mSendPassphrase.isEmpty()) &&
                   (!((bool)mSendRemotePublicKey));
          }
          case KeyingType_PublicKey:    {
            ZS_LOG_TRACE(log("needs send keying - private key") + IRSAPublicKey::toDebug(mSendRemotePublicKey) + ZS_PARAM("passphrase", mSendPassphrase))
            return (mSendPassphrase.isEmpty()) &&
                   (!((bool)mSendRemotePublicKey));
          }
          case KeyingType_KeyAgreement: {
            ZS_LOG_TRACE(log("needs send keying - key agreement") + ZS_PARAM("local private key", IDHPrivateKey::toDebug(mDHLocalPrivateKey)) + ZS_PARAM("local public key", IDHPublicKey::toDebug(mDHLocalPublicKey)) + ZS_PARAM("remote public key", IDHPublicKey::toDebug(mDHRemotePublicKey)) + ZS_PARAM("remote public key fingerprint", mDHRemotePublicKeyFingerprint))
            return (!((bool)mDHLocalPrivateKey)) ||
                   (!((bool)mDHLocalPublicKey)) ||
                   (!((bool)mDHRemotePublicKey));
          }
        }

        ZS_LOG_TRACE(log("needs send keying - unknown receive keying type"))
        return true;
      }

      //-----------------------------------------------------------------------
      bool MessageLayerSecurityChannel::needsReceiveKeyingSigningPublicKey() const
      {
        AutoRecursiveLock lock(*this);
        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("cannot need receive keying singing information as already shutdown"))
          return false;
        }

        ZS_LOG_TRACE(log("needs receive keying signing public key") + IRSAPublicKey::toDebug(mReceiveSigningPublicKey))
        return (!((bool)mReceiveSigningPublicKey));
      }

      //-----------------------------------------------------------------------
      bool MessageLayerSecurityChannel::needsSendKeyingToeBeSigned() const
      {
        AutoRecursiveLock lock(*this);
        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("cannot need send keying to be signed as already shutdown"))
          return false;
        }

        ZS_LOG_TRACE(log("needs send keying to be signed") + ZS_PARAM("sign doc", (bool)mSendKeyingNeedingToSignDoc) + ZS_PARAM("sign element", (bool)mSendKeyingNeedToSignEl))
        return (mSendKeyingNeedingToSignDoc) && (mSendKeyingNeedToSignEl);
      }

      //-----------------------------------------------------------------------
      String MessageLayerSecurityChannel::getLocalContextID() const
      {
        AutoRecursiveLock lock(*this);
        ZS_LOG_TRACE(log("get local context ID") + ZS_PARAM("local context ID", mLocalContextID))
        return mLocalContextID;
      }

      //-----------------------------------------------------------------------
      String MessageLayerSecurityChannel::getRemoteContextID() const
      {
        AutoRecursiveLock lock(*this);
        ZS_LOG_TRACE(log("get remote context ID") + ZS_PARAM("remote context ID", mRemoteContextID))
        return mRemoteContextID;
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::setLocalContextID(const char *contextID)
      {
        AutoRecursiveLock lock(*this);

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }

        ZS_LOG_DEBUG(log("setting local context ID") + ZS_PARAM("context ID", contextID))

        if (mLocalContextID.hasData()) {
          ZS_THROW_INVALID_ARGUMENT_IF(String(contextID) != mLocalContextID)
          return;
        }

        mLocalContextID = String(contextID);

        setState(SessionState_Pending);

        IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::setReceiveKeying(const char *passphrase)
      {
        AutoRecursiveLock lock(*this);

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }

        ZS_LOG_TRACE(log("set receive keying") + ZS_PARAM("passphrase", passphrase))

        if (mReceivePassphrase.hasData()) {
          ZS_THROW_INVALID_ARGUMENT_IF(String(passphrase) != mReceivePassphrase)
          return;
        }

        mReceivePassphrase = String(passphrase);

        setState(SessionState_Pending);

        IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::setSendKeying(const char *passphrase)
      {
        AutoRecursiveLock lock(*this);

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }

        ZS_LOG_TRACE(log("set send keying") + ZS_PARAM("passphrase", passphrase))

        if (mReceivePassphrase.hasData()) {
          ZS_THROW_INVALID_ARGUMENT_IF(String(passphrase) != mSendPassphrase)
          return;
        }

        mSendKeyingType = KeyingType_Passphrase;
        mSendPassphrase = String(passphrase);

        setState(SessionState_Pending);

        IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
      }

      //-----------------------------------------------------------------------
      String MessageLayerSecurityChannel::getReceivePublicKeyFingerprint() const
      {
        AutoRecursiveLock lock(*this);
        ZS_LOG_TRACE(log("get receive public key fingerprint") + ZS_PARAM("fingerprint", mReceiveLocalPublicKeyFingerprint) + IRSAPublicKey::toDebug(mReceiveLocalPublicKey))
        if ((bool)mReceiveLocalPublicKey) return String();
        return mReceiveLocalPublicKeyFingerprint;
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::setReceiveKeying(
                                                         IRSAPrivateKeyPtr localPrivateKey,
                                                         IRSAPublicKeyPtr localPublicKey
                                                         )
      {
        AutoRecursiveLock lock(*this);

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }

        ZS_LOG_TRACE(log("set receive keying") + IRSAPrivateKey::toDebug(localPrivateKey) + IRSAPublicKey::toDebug(localPublicKey))

        if (mReceiveLocalPrivateKey) {
          ZS_THROW_INVALID_ARGUMENT_IF(localPrivateKey != mReceiveLocalPrivateKey)
        }
        if (mReceiveLocalPublicKey) {
          ZS_THROW_INVALID_ARGUMENT_IF(localPublicKey != mReceiveLocalPublicKey)
        }

        mReceiveLocalPrivateKey = localPrivateKey;
        mReceiveLocalPublicKey = localPublicKey;

        setState(SessionState_Pending);

        IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::setSendKeying(IRSAPublicKeyPtr remotePublicKey)
      {
        AutoRecursiveLock lock(*this);

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }

        ZS_LOG_TRACE(log("set send keying") + IRSAPublicKey::toDebug(remotePublicKey))

        if (mSendRemotePublicKey) {
          ZS_THROW_INVALID_ARGUMENT_IF(remotePublicKey != mSendRemotePublicKey)
        }

        mSendKeyingType = KeyingType_PublicKey;
        mSendRemotePublicKey = remotePublicKey;

        setState(SessionState_Pending);

        IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
      }

      //-----------------------------------------------------------------------
      IDHKeyDomainPtr MessageLayerSecurityChannel::getKeyAgreementDomain() const
      {
        AutoRecursiveLock lock(*this);
        ZS_LOG_TRACE(log("get key domain") + IDHKeyDomain::toDebug(mDHKeyDomain))
        return mDHKeyDomain;
      }

      //-----------------------------------------------------------------------
      String MessageLayerSecurityChannel::getRemoteKeyAgreementFingerprint() const
      {
        AutoRecursiveLock lock(*this);
        ZS_LOG_TRACE(log("get remote keying agreement fingerprint") + ZS_PARAM("fingerprint", mDHRemotePublicKeyFingerprint) + IDHPublicKey::toDebug(mDHRemotePublicKey))
        if ((bool)mDHRemotePublicKey) return String();
        return mDHRemotePublicKeyFingerprint;
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::setLocalKeyAgreement(
                                                             IDHPrivateKeyPtr localPrivateKey,
                                                             IDHPublicKeyPtr localPublicKey,
                                                             bool remoteSideAlreadyKnowsThisPublicKey
                                                             )
      {
        AutoRecursiveLock lock(*this);

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }

        ZS_LOG_TRACE(log("set local key agreement") + IDHPrivateKey::toDebug(localPrivateKey) + IDHPublicKey::toDebug(localPublicKey))

        if (mDHLocalPrivateKey) {
          ZS_THROW_INVALID_ARGUMENT_IF(localPrivateKey != mDHLocalPrivateKey)
        }
        if (mDHLocalPublicKey) {
          ZS_THROW_INVALID_ARGUMENT_IF(localPublicKey != mDHLocalPublicKey)
        }

        mSendKeyingType = KeyingType_KeyAgreement;
        mDHLocalPrivateKey = localPrivateKey;
        mDHLocalPublicKey = localPublicKey;
        mDHRemoteSideKnowsLocalPublicKey = remoteSideAlreadyKnowsThisPublicKey;

        if (mDHLocalPrivateKey) {
          if (!((bool)mDHKeyDomain)) {
            mDHKeyDomain = mDHLocalPrivateKey->getKeyDomain();
          }
        }

        setState(SessionState_Pending);

        IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::setRemoteKeyAgreement(IDHPublicKeyPtr remotePublicKey)
      {
        AutoRecursiveLock lock(*this);

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }

        ZS_LOG_TRACE(log("set remote key agreement") + IDHPublicKey::toDebug(remotePublicKey))

        if (mDHRemotePublicKey) {
          ZS_THROW_INVALID_ARGUMENT_IF(remotePublicKey != mDHRemotePublicKey)
        }

        mSendKeyingType = KeyingType_KeyAgreement;
        mDHRemotePublicKey = remotePublicKey;
        if (!mDHOriginalRemotePublicKey) {
          mDHOriginalRemotePublicKey = mDHRemotePublicKey;
        }

        setState(SessionState_Pending);

        IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
      }

      //-----------------------------------------------------------------------
      IDHPublicKeyPtr MessageLayerSecurityChannel::getOriginalRemoteKeyAgreement()
      {
        AutoRecursiveLock lock(*this);
        ZS_LOG_TRACE(log("get original remote key agreement") + IDHPublicKey::toDebug(mDHOriginalRemotePublicKey))
        return mDHOriginalRemotePublicKey;
      }

      //-----------------------------------------------------------------------
      ElementPtr MessageLayerSecurityChannel::getSignedReceiveKeying() const
      {
        AutoRecursiveLock lock(*this);
        ZS_LOG_TRACE(log("get signed receive keying") + ZS_PARAM("signed element", (bool)mReceiveKeyingSignedEl))
        return mReceiveKeyingSignedEl;
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::setReceiveKeyingSigningPublicKey(IRSAPublicKeyPtr remotePublicKey)
      {
        AutoRecursiveLock lock(*this);

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }

        ZS_LOG_TRACE(log("set receive keying signing public key") + IRSAPublicKey::toDebug(remotePublicKey))

        if (mReceiveSigningPublicKey) {
          ZS_THROW_INVALID_ARGUMENT_IF(remotePublicKey != mReceiveSigningPublicKey)
        }

        mReceiveSigningPublicKey = remotePublicKey;

        setState(SessionState_Pending);

        IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::getSendKeyingNeedingToBeSigned(
                                                                       DocumentPtr &outDocumentContainedElementToSign,
                                                                       ElementPtr &outElementToSign
                                                                       ) const
      {
        AutoRecursiveLock lock(*this);

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }

        ZS_LOG_TRACE(log("get send keying needing to be signed") + ZS_PARAM("doc", (bool)mSendKeyingNeedingToSignDoc) + ZS_PARAM("sign element", mSendKeyingNeedToSignEl))

        if ((!mSendKeyingNeedingToSignDoc) ||
            (!mSendKeyingNeedToSignEl)) {
          ZS_LOG_WARNING(Detail, log("no keying material available needing to be signed"))
          return;
        }

        outDocumentContainedElementToSign = mSendKeyingNeedingToSignDoc;
        outElementToSign = mSendKeyingNeedToSignEl;
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::notifySendKeyingSigned(
                                                               IRSAPrivateKeyPtr signingPrivateKey,
                                                               IRSAPublicKeyPtr signingPublicKey
                                                               )
      {
        AutoRecursiveLock lock(*this);

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }

        if (mSendSigningPrivateKey) {
          ZS_THROW_INVALID_ARGUMENT_IF(signingPrivateKey != mSendSigningPrivateKey)
        }
        if (mSendSigningPublicKey) {
          ZS_THROW_INVALID_ARGUMENT_IF(signingPublicKey != mSendSigningPublicKey)
        }

        mSendSigningPrivateKey = signingPrivateKey;
        mSendSigningPublicKey = signingPublicKey;
        mSendKeyingNeedToSignEl.reset();

        setState(SessionState_Pending);

        IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
      }


      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark MessageLayerSecurityChannel => ITransportStreamReaderDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::onTransportStreamReaderReady(ITransportStreamReaderPtr reader)
      {
        AutoRecursiveLock lock(*this);
        ZS_LOG_DEBUG(log("transport stream reader ready"))
        step();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark MessageLayerSecurityChannel => ITransportStreamWriterDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::onTransportStreamWriterReady(ITransportStreamWriterPtr writer)
      {
        AutoRecursiveLock lock(*this);
        ZS_LOG_DEBUG(log("transport stream writer ready"))

        if (writer == mReceiveStreamDecoded) {
          mReceiveStreamDecodedWriteReady = true;

          // event typically fires when "outer" notifies it's ready to send data thus need to inform the wire that it can send data now
          mReceiveStreamEncoded->notifyReaderReadyToRead();
        }
        if (writer == mSendStreamEncoded) {
          mSendStreamEncodedWriteReady = true;
        }
        step();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark MessageLayerSecurityChannel => IWakeDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::onWake()
      {
        AutoRecursiveLock lock(*this);
        ZS_LOG_DEBUG(log("on wake"))
        step();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark MessageLayerSecurityChannel => ITimerDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::onTimer(ITimerPtr timer)
      {
        AutoRecursiveLock lock(*this);
        ZS_LOG_DEBUG(log("on timer") + ZS_PARAM("timer id", timer->getID()))

        if (timer == mChangeSendingKeyTimer) {
          mChangeKey = true;
          mSendKeys.clear();
          mDHSentRemoteSideLocalPublicKey = false;
        }

        step();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark MessageLayerSecurityChannel  => (internal)
      #pragma mark

      //-----------------------------------------------------------------------
      Log::Params MessageLayerSecurityChannel::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("MessageLayerSecurityChannel");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params MessageLayerSecurityChannel::debug(const char *message) const
      {
        return Log::Params(message, toDebug());
      }

      //-----------------------------------------------------------------------
      ElementPtr MessageLayerSecurityChannel::toDebug() const
      {
        AutoRecursiveLock lock(*this);

        ElementPtr resultEl = Element::create("MessageLayerSecurityChannel");

        IHelper::debugAppend(resultEl, "id", mID);

        IHelper::debugAppend(resultEl, "subscriptions", mSubscriptions.size());
        IHelper::debugAppend(resultEl, "default subscription", (bool)mDefaultSubscription);

        IHelper::debugAppend(resultEl, "state", IMessageLayerSecurityChannel::toString(mCurrentState));

        IHelper::debugAppend(resultEl, "last error", mLastError);
        IHelper::debugAppend(resultEl, "last reason", mLastErrorReason);

        IHelper::debugAppend(resultEl, "local context ID", mLocalContextID);
        IHelper::debugAppend(resultEl, "remote context ID", mRemoteContextID);


        IHelper::debugAppend(resultEl, "receive keying type", toString(mReceiveKeyingType));
        IHelper::debugAppend(resultEl, "send keying type", toString(mSendKeyingType));

        IHelper::debugAppend(resultEl, "receive passphrase", mReceivePassphrase);
        IHelper::debugAppend(resultEl, "send passphrase", mSendPassphrase);


        IHelper::debugAppend(resultEl, IDHKeyDomain::toDebug(mDHKeyDomain));

        IHelper::debugAppend(resultEl, "local private key", IDHPrivateKey::toDebug(mDHLocalPrivateKey));
        IHelper::debugAppend(resultEl, "local public key", IDHPublicKey::toDebug(mDHLocalPublicKey));
        IHelper::debugAppend(resultEl, "remote side knows local public key", mDHRemoteSideKnowsLocalPublicKey);
        IHelper::debugAppend(resultEl, "sent remote side local public key", mDHSentRemoteSideLocalPublicKey);

        IHelper::debugAppend(resultEl, "remote public key", IDHPublicKey::toDebug(mDHRemotePublicKey));
        IHelper::debugAppend(resultEl, "original remote public key", IDHPublicKey::toDebug(mDHOriginalRemotePublicKey));
        IHelper::debugAppend(resultEl, "remote public key fingerprint", mDHRemotePublicKeyFingerprint);

        IHelper::debugAppend(resultEl, "previous local keys", mDHPreviousLocalKeys.size());


        IHelper::debugAppend(resultEl, "receive private key", IRSAPrivateKey::toDebug(mReceiveLocalPrivateKey));
        IHelper::debugAppend(resultEl, "receive public key", IRSAPublicKey::toDebug(mReceiveLocalPublicKey));
        IHelper::debugAppend(resultEl, "receive public key fingerprint", mReceiveLocalPublicKeyFingerprint);

        IHelper::debugAppend(resultEl, "sending remote public key", IRSAPublicKey::toDebug(mSendRemotePublicKey));


        IHelper::debugAppend(resultEl, "receive signing public key", IRSAPublicKey::toDebug(mReceiveSigningPublicKey));
        IHelper::debugAppend(resultEl, "receive signing doc", (bool)mReceiveKeyingSignedDoc);
        IHelper::debugAppend(resultEl, "receive signing element", (bool)mReceiveKeyingSignedEl);

        IHelper::debugAppend(resultEl, "send signing private key", IRSAPrivateKey::toDebug(mSendSigningPrivateKey));
        IHelper::debugAppend(resultEl, "send signing public key", IRSAPublicKey::toDebug(mSendSigningPublicKey));
        IHelper::debugAppend(resultEl, "send signing doc", (bool)mSendKeyingNeedingToSignDoc);
        IHelper::debugAppend(resultEl, "send signing element", (bool)mSendKeyingNeedToSignEl);


        IHelper::debugAppend(resultEl, "receive seq number", string(mNextReceiveSequenceNumber));
        IHelper::debugAppend(resultEl, "send seq number", string(mNextSendSequenceNumber));

        IHelper::debugAppend(resultEl, "receive stream encoded", ITransportStream::toDebug(mReceiveStreamEncoded->getStream()));
        IHelper::debugAppend(resultEl, "receive stream decode", ITransportStream::toDebug(mReceiveStreamDecoded->getStream()));
        IHelper::debugAppend(resultEl, "send stream decoded", ITransportStream::toDebug(mSendStreamDecoded->getStream()));
        IHelper::debugAppend(resultEl, "send stream encoded", ITransportStream::toDebug(mSendStreamEncoded->getStream()));

        IHelper::debugAppend(resultEl, "receive stream encoded subscription", (bool)mReceiveStreamEncodedSubscription);
        IHelper::debugAppend(resultEl, "receive stream decoded subscription", (bool)mReceiveStreamDecodedSubscription);
        IHelper::debugAppend(resultEl, "send stream decoded subscription", (bool)mSendStreamDecodedSubscription);
        IHelper::debugAppend(resultEl, "send stream encoded subscription", (bool)mSendStreamEncodedSubscription);

        IHelper::debugAppend(resultEl, "receive stream decoded write ready", mReceiveStreamDecodedWriteReady);
        IHelper::debugAppend(resultEl, "send stream encoded write ready", mSendStreamEncodedWriteReady);
        IHelper::debugAppend(resultEl, "notify send stream decoded ready to ready", mNotifySendStreamDecodedReadyToReady);

        IHelper::debugAppend(resultEl, "receive keys", mReceiveKeys.size());
        IHelper::debugAppend(resultEl, "send keys", mSendKeys.size());

        IHelper::debugAppend(resultEl, "change key", mChangeKey);
        IHelper::debugAppend(resultEl, "change send key timer", mChangeSendingKeyTimer ? mChangeSendingKeyTimer->getID() : 0);

        return resultEl;
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::setState(SessionStates state)
      {
        if (state == mCurrentState) return;

        ZS_LOG_DETAIL(log("state changed") + ZS_PARAM("state", IMessageLayerSecurityChannel::toString(state)) + ZS_PARAM("old state", IMessageLayerSecurityChannel::toString(mCurrentState)))
        mCurrentState = state;

        MessageLayerSecurityChannelPtr pThis = mThisWeak.lock();
        if (pThis) {
          ZS_LOG_DEBUG(debug("attempting to report state to delegate") + ZS_PARAM("total", mSubscriptions.size()))
          mSubscriptions.delegate()->onMessageLayerSecurityChannelStateChanged(pThis, mCurrentState);
        }
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::setError(WORD errorCode, const char *inReason)
      {
        String reason(inReason ? String(inReason) : String());
        if (reason.isEmpty()) {
          reason = IHTTP::toString(IHTTP::toStatusCode(errorCode));
        }

        if (0 != mLastError) {
          ZS_LOG_WARNING(Detail, debug("error already set thus ignoring new error") + ZS_PARAM("new error", errorCode) + ZS_PARAM("new reason", reason))
          return;
        }

        mLastError = errorCode;
        mLastErrorReason = reason;

        ZS_LOG_WARNING(Detail, debug("error set") + ZS_PARAM("code", mLastError) + ZS_PARAM("reason", mLastErrorReason))
      }
      
      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::step()
      {
        if (isShutdown()) {
          ZS_LOG_DEBUG(log("step continue to shutdown"))
          cancel();
          return;
        }

        ZS_LOG_DEBUG(debug("step"))

        if (!stepReceive()) return;
        if (!stepSendKeying()) return;
        if (!stepSend()) return;
        if (!stepCheckConnected()) return;

        setState(SessionState_Connected);
      }

      //-----------------------------------------------------------------------
      bool MessageLayerSecurityChannel::stepReceive()
      {
        if (!mReceiveStreamDecodedWriteReady) {
          ZS_LOG_TRACE(log("cannot read encoded stream until notified that it's okay to write to decoded stream"))
          return true;
        }

        if ((mReceiveKeyingSignedDoc) &&
            (mReceiveKeyingSignedEl)) {

          if (!mReceiveSigningPublicKey) {
            ZS_LOG_TRACE(log("waiting for receive keying materials"))
            setState(SessionState_WaitingForNeededInformation);
            return true;
          }

          bool returnResult = false;
          if (!stepProcessReceiveKeying(returnResult)) {
            ZS_LOG_TRACE(log("receive keying did not complete"))
            return returnResult;
          }

          ZS_LOG_DEBUG(log("receive keying completed"))
        }

        if (mReceiveStreamEncoded->getTotalReadBuffersAvailable() < 1) {
          ZS_LOG_TRACE(log("nothing to decode"))
          return true;
        }

        if (mRemoteContextID.hasData()) {
          ZS_LOG_TRACE(log("already decoded at least one packet") + ZS_PARAM("remote context ID", mRemoteContextID))
          if (mReceiveKeys.size() < 1) {
            bool hasReceiveInformation = true;

            switch(mReceiveKeyingType) {
              case KeyingType_Unknown:      break;
              case KeyingType_Passphrase:   hasReceiveInformation = hasReceiveInformation && (mReceivePassphrase.hasData()); break;
              case KeyingType_PublicKey:    hasReceiveInformation = hasReceiveInformation && ((bool)mReceiveLocalPrivateKey); break;
              case KeyingType_KeyAgreement: hasReceiveInformation = hasReceiveInformation && ((bool)mDHLocalPrivateKey) && ((bool)mDHLocalPublicKey) && ((bool)mDHRemotePublicKey); break;
            }

            hasReceiveInformation = hasReceiveInformation && (mReceiveSigningPublicKey);

            if (!hasReceiveInformation) {
              ZS_LOG_TRACE(log("waiting for receive keying materials"))
              setState(SessionState_WaitingForNeededInformation);
              return true;
            }
          }
        }

        while (mReceiveStreamEncoded->getTotalReadBuffersAvailable() > 0) {
          ITransportStream::StreamHeaderPtr streamHeader;
          SecureByteBlockPtr streamBuffer = mReceiveStreamEncoded->read(&streamHeader);

          if (ZS_IS_LOGGING(Insane)) {
            String str = IHelper::getDebugString(*streamBuffer);
            ZS_LOG_INSANE(log("stream buffer read") + ZS_PARAM("raw", "\n" + str))
          }

          // has to be greater than the size of a DWORD
          if (streamBuffer->SizeInBytes() <= sizeof(DWORD)) {
            ZS_LOG_ERROR(Detail, log("algorithm bytes missing in protocol") + ZS_PARAM("size", streamBuffer->SizeInBytes()))
            setError(IHTTP::HTTPStatusCode_Unauthorized, "buffer is not decodable");
            cancel();
            return false;
          }

          const BYTE *buffer = streamBuffer->BytePtr();

          DWORD algorithm = ntohl(((DWORD *)buffer)[0]);

          const BYTE *source = (const BYTE *)(&(((DWORD *)buffer)[1]));
          SecureByteBlock::size_type remaining = streamBuffer->SizeInBytes() - sizeof(DWORD);

          if (0 != algorithm) {
            // attempt to decode now
            if (mReceiveKeys.size() < 1) {
              ZS_LOG_ERROR(Detail, log("attempting to decode a packet where keying material has not been received"))
              setError(IHTTP::HTTPStatusCode_Forbidden, "attempting to decode a packet where keying material has not been received");
              cancel();
              return false;
            }

            KeyMap::iterator found = mReceiveKeys.find(algorithm);
            if (found == mReceiveKeys.end()) {
              ZS_LOG_ERROR(Detail, log("attempting to decode a packet where keying algorithm does not map to a know key") + ZS_PARAM("algorithm", string(algorithm)))
              setError(IHTTP::HTTPStatusCode_Forbidden, "attempting to decode a packet where keying algorithm does not map to a know key");
              cancel();
              return false;
            }

            // decode the packet
            KeyInfo &keyInfo = (*found).second;

            ZS_LOG_INSANE(log("decrypting key to use") + keyInfo.toDebug(algorithm));

            size_t integritySize = IHasher::sha1DigestSize();

            // must be greater in size than the hash algorithm
            if (remaining <= integritySize) {
              ZS_LOG_ERROR(Detail, log("algorithm bytes missing in protocol") + ZS_PARAM("size", streamBuffer->SizeInBytes()))
              setError(IHTTP::HTTPStatusCode_Unauthorized, "buffer is not decodable");
              cancel();
              return false;
            }


            SecureByteBlockPtr integrity(make_shared<SecureByteBlock>(integritySize));
            memcpy(integrity->BytePtr(), source, integritySize);

            source += integritySize;
            remaining -= integritySize;

            SecureByteBlock input(remaining);
            memcpy(input.BytePtr(), source, remaining);

            SecureByteBlockPtr output = IHelper::decrypt(*(keyInfo.mSendKey), *(keyInfo.mNextIV), input);

            String hashDecryptedBuffer = IHelper::convertToHex(*IHasher::hash(*output));

            if (!output) {
              ZS_LOG_ERROR(Detail, log("unable to decrypte buffer"))
              setError(IHTTP::HTTPStatusCode_Unauthorized, "unable to decrypt buffer");
              cancel();
              return false;
            }

            if (ZS_IS_LOGGING(Insane)) {
              String str = IHelper::convertToBase64(*output);
              ZS_LOG_INSANE(log("stream buffer decrypted") + ZS_PARAM("wire in", str))
            }

            String hexIV = IHelper::convertToHex(*keyInfo.mNextIV);

            SecureByteBlockPtr calculatedIntegrity = IHasher::hash(("integrity:" + IHelper::convertToHex(*IHasher::hash(*output)) + ":" + hexIV).c_str(), IHasher::hmacSHA1(*(IHelper::convertToBuffer(keyInfo.mIntegrityPassphrase))));

            if (ZS_IS_LOGGING(Debug)) {
              String hashEncryptedBuffer = IHelper::convertToHex(*IHasher::hash(input));
              ZS_LOG_DEBUG(log("received data from wire") + ZS_PARAM("keying index", algorithm) + ZS_PARAM("buffer size", streamBuffer->SizeInBytes()) + ZS_PARAM("encrypted size", input.SizeInBytes()) + ZS_PARAM("decrypted size", output->SizeInBytes()) + ZS_PARAM("key", IHelper::convertToHex(*(keyInfo.mSendKey))) + ZS_PARAM("iv", hexIV) + ZS_PARAM("calculated integrity", IHelper::convertToHex(*calculatedIntegrity)) + ZS_PARAM("received integrity", IHelper::convertToHex(*integrity)) + ZS_PARAM("integrity passphrase", keyInfo.mIntegrityPassphrase) + ZS_PARAM("decrypted data hash", hashDecryptedBuffer) + ZS_PARAM("encrypted data hash", hashEncryptedBuffer))
            }

            if (0 != IHelper::compare(*calculatedIntegrity, *integrity)) {
              ZS_LOG_ERROR(Debug,log("integrity failed on packet"))
              setError(IHTTP::HTTPStatusCode_Unauthorized, "buffer is not decodable");
              cancel();
              return false;
            }

            // calculate the next IV and remember the integrity field
            keyInfo.mNextIV = IHasher::hash(hexIV + ":" + IHelper::convertToHex(*calculatedIntegrity));
            keyInfo.mLastIntegrity = calculatedIntegrity;

            mReceiveStreamDecoded->write(output, streamHeader);

            // process next buffer
            continue;
          }

          bool returnResult = false;
          if (!stepProcessReceiveKeying(returnResult, streamBuffer)) {
            ZS_LOG_TRACE(log("receive keying did not complete"))
            return returnResult;
          }
        }

        return true;
      }

      //-----------------------------------------------------------------------
      bool MessageLayerSecurityChannel::stepProcessReceiveKeying(
                                                                 bool &outReturnResult,
                                                                 SecureByteBlockPtr keying
                                                                 )
      {
        typedef IHelper::SplitMap SplitMap;

        DocumentPtr doc;
        ElementPtr keyingEl;

        // scope: process receive keying material
        {
          outReturnResult = true;

          // parse the buffer

          if (mReceiveKeyingSignedDoc) {
            // reuse the signing doc if one exists (to avoid decoding the first packet twice)
            doc = mReceiveKeyingSignedDoc;

            mReceiveKeyingSignedDoc.reset();
            mReceiveKeyingSignedEl.reset();
          }

          if (!doc) {
            const BYTE *buffer = keying->BytePtr();

            const BYTE *source = (const BYTE *)(&(((DWORD *)buffer)[1]));
            SecureByteBlock::size_type remaining = keying->SizeInBytes() - sizeof(DWORD);

            // create a NUL terminated JSON string buffer
            SecureByteBlockPtr jsonBuffer =  IHelper::convertToBuffer(source, remaining);

            ZS_LOG_DETAIL(log("-------------------------------------------------------------------------------------------"))
            ZS_LOG_DETAIL(log("[ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ ["))
            ZS_LOG_DETAIL(log("-------------------------------------------------------------------------------------------"))
            ZS_LOG_DETAIL(log("MLS RECEIVE") + ZS_PARAM("json in", ((CSTR)(jsonBuffer->BytePtr()))))
            ZS_LOG_DETAIL(log("-------------------------------------------------------------------------------------------"))
            ZS_LOG_DETAIL(log("[ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ [ ["))
            ZS_LOG_DETAIL(log("-------------------------------------------------------------------------------------------"))

            // clear out the receive signed document since it's validated
            doc = Document::createFromAutoDetect((const char *)(jsonBuffer->BytePtr()));
          }

          mReceiveKeys.clear(); // all previous keys are being destroyed

          String decodingPassphrase;

          try {
            keyingEl = doc->findFirstChildElementChecked("keyingBundle")->findFirstChildElementChecked("keying");

            if (mRemoteContextID.isEmpty()) {
              mRemoteContextID = getElementTextAndDecode(keyingEl->findFirstChildElement("context"));
            }

            if (!mReceiveSigningPublicKey) {
              ZS_LOG_TRACE(log("waiting for receive material signing public key"))
              goto receive_waiting_for_information;
            }

            if (!mReceiveSigningPublicKey->verifySignature(keyingEl)) {
              ZS_LOG_ERROR(Detail, log("failed to validate receiving stream signature"))
              setError(IHTTP::HTTPStatusCode_Forbidden, "keying encoding not using expecting passphrase");
              goto receive_error_out;
            }

            String sequenceNumber = getElementTextAndDecode(keyingEl->findFirstChildElement("sequence"));

            if (sequenceNumber != string(mNextReceiveSequenceNumber)) {
              ZS_LOG_ERROR(Detail, log("sequence number mismatch") + ZS_PARAM("sequence", sequenceNumber) + ZS_PARAM("expecting", mNextReceiveSequenceNumber))
              setError(IHTTP::HTTPStatusCode_RequestTimeout, "sequence number mismatch");
              goto receive_error_out;
            }

            Time expires = IHelper::stringToTime(getElementTextAndDecode(keyingEl->findFirstChildElement("expires")));
            Time tick = zsLib::now();
            if ((tick > expires) ||
                (Time() == expires)) {
              ZS_LOG_ERROR(Detail, log("signed keying bundle has expired") + ZS_PARAM("expires", expires) + ZS_PARAM("now", tick))
              setError(IHTTP::HTTPStatusCode_RequestTimeout, "signed keying bundle has expired");
              goto receive_error_out;
            }

            String nonce = getElementTextAndDecode(keyingEl->findFirstChildElementChecked("nonce"));

            ElementPtr encodingEl = keyingEl->findFirstChildElementChecked("encoding");
            String type = getElementTextAndDecode(encodingEl->findFirstChildElementChecked("type"));

            if ("pki" == type) {
              mReceiveKeyingType = KeyingType_PublicKey;
              if (KeyingType_Unknown == mSendKeyingType) mSendKeyingType = KeyingType_PublicKey;

              String encodingFingerprint = getElementTextAndDecode(encodingEl->findFirstChildElementChecked("fingerprint"));

              if (mReceiveLocalPublicKeyFingerprint.isEmpty()) {
                mReceiveLocalPublicKeyFingerprint = encodingFingerprint;
              }

              if (!mReceiveLocalPrivateKey) {
                ZS_LOG_DEBUG(log("waiting for receive PKI keying materials"))
                goto receive_waiting_for_information;
              }

              ZS_THROW_BAD_STATE_IF(!mReceiveLocalPublicKey)

              String expectingFingerprint = mReceiveLocalPublicKey->getFingerprint();
              if (encodingFingerprint != expectingFingerprint) {
                ZS_LOG_ERROR(Detail, log("encoding not using local public key") + ZS_PARAM("encoding fingerprint", encodingFingerprint) + ZS_PARAM("expecting fingerprint", expectingFingerprint))
                setError(IHTTP::HTTPStatusCode_CertError, "encoding not using local public key");
                goto receive_error_out;
              }
            } else if ("agreement" == type) {
              mReceiveKeyingType = KeyingType_KeyAgreement;
              if (KeyingType_Unknown == mSendKeyingType) mSendKeyingType = KeyingType_KeyAgreement;

              String encodingFingerprint = getElementTextAndDecode(encodingEl->findFirstChildElementChecked("fingerprint"));
              String remoteKey = getElementTextAndDecode(encodingEl->findFirstChildElement("key"));

              if (remoteKey.isEmpty()) {
                if (mDHRemotePublicKeyFingerprint.isEmpty()) {
                  mDHRemotePublicKeyFingerprint = encodingFingerprint;
                }

                if (!((bool)mDHRemotePublicKey)) {
                  ZS_LOG_TRACE(log("waiting for receive remote DH keying materials"))
                  goto receive_waiting_for_information;
                }

                if (mDHRemotePublicKeyFingerprint.hasData()) {
                  String expectingFingerprint = mDHRemotePublicKey->getFingerprint();
                  if (encodingFingerprint != expectingFingerprint) {
                    ZS_LOG_ERROR(Detail, log("encoding not using remote public key") + ZS_PARAM("encoding fingerprint", encodingFingerprint) + ZS_PARAM("expecting fingerprint", expectingFingerprint) + IDHPublicKey::toDebug(mDHRemotePublicKey))
                    setError(IHTTP::HTTPStatusCode_CertError, "encoding not using remote public key provided");
                    goto receive_error_out;
                  }
                  mDHRemotePublicKeyFingerprint.clear();
                }
              }

              if (remoteKey.hasData()) {
                SplitMap splits;

                String namespaceStr;

                IHelper::split(remoteKey, splits, ':');
                if (splits.size() >= 1) {
                  namespaceStr = IHelper::convertToString(*IHelper::convertFromBase64((*(splits.find(0))).second));

                  IDHKeyDomainPtr keyDomain = IDHKeyDomain::loadPrecompiled(IDHKeyDomain::fromNamespace(namespaceStr));
                  if (!keyDomain) {
                    ZS_LOG_ERROR(Detail, log("encoding key domain namespace is not known") + ZS_PARAM("namespace", namespaceStr))
                    setError(IHTTP::HTTPStatusCode_PreconditionFailed, "encoding domain namespace is not known");
                    goto receive_error_out;
                  }

                  if ((bool)mDHKeyDomain) {
                    if (keyDomain->getPrecompiledType() != mDHKeyDomain->getPrecompiledType()) {
                      ZS_LOG_ERROR(Detail, log("encoding key domain namespace does not match expecting") + ZS_PARAM("namespace", namespaceStr) + ZS_PARAM("received key domain", IDHKeyDomain::toDebug(keyDomain)) + ZS_PARAM("expecting key domain", IDHKeyDomain::toDebug(mDHKeyDomain)))
                      setError(IHTTP::HTTPStatusCode_PreconditionFailed, "encoding key domain namepsace does not match expecting");
                      goto receive_error_out;
                    }
                  } else {
                    mDHKeyDomain = keyDomain;
                  }
                }

                if (splits.size() >= 3) {
                  String staticPublicKeyStr = (*(splits.find(1))).second;
                  String ephemeralPublicKeyStr = (*(splits.find(2))).second;

                  SecureByteBlockPtr staticPublicKey = IHelper::convertFromBase64(staticPublicKeyStr);
                  SecureByteBlockPtr ephemeralPublicKey = IHelper::convertFromBase64(ephemeralPublicKeyStr);

                  if ((IHelper::hasData(staticPublicKey)) &&
                      (IHelper::hasData(ephemeralPublicKey))) {
                    mDHRemotePublicKey = IDHPublicKey::load(*staticPublicKey, *ephemeralPublicKey);
                    if (!mDHOriginalRemotePublicKey) {
                      mDHOriginalRemotePublicKey = mDHRemotePublicKey;
                    }
                  }
                }

                if (!mDHRemotePublicKey) {
                  ZS_LOG_ERROR(Detail, log("encoding remote public key is not known") + ZS_PARAM("namespace", namespaceStr))
                  setError(IHTTP::HTTPStatusCode_BadRequest, "remote public key is not valid");
                  goto receive_error_out;
                }
              }

              if (!mDHRemotePublicKey) {
                ZS_LOG_DEBUG(log("waiting for DH remote public key to be set"))
                goto receive_waiting_for_information;
              }

              if ((!mDHLocalPrivateKey) ||
                  (!mDHLocalPublicKey)) {
                ZS_LOG_TRACE(log("waiting for receive DH keying materials"))
                goto receive_waiting_for_information;
              }

              IDHPrivateKeyPtr localPrivateKey = mDHLocalPrivateKey;
              IDHPublicKeyPtr localPublicKey = mDHLocalPublicKey;

              if (remoteKey.hasData()) {
                if (encodingFingerprint.hasData()) {

                  // remote side could be using an older key pair
                  while (mDHPreviousLocalKeys.size() > 0) {
                    DHPrivatePublicKeyPair &front = mDHPreviousLocalKeys.front();

                    if (encodingFingerprint == front.second->getFingerprint()) {
                      localPrivateKey = front.first;
                      localPublicKey = front.second;
                      break;
                    }
                    // not referencing this key so must be referencing a different one
                    mDHPreviousLocalKeys.pop_front();
                  }

                  if (encodingFingerprint != localPublicKey->getFingerprint()) {
                    ZS_LOG_ERROR(Detail, log("encoding not using known local public key") + ZS_PARAM("encoding fingerprint", encodingFingerprint) + ZS_PARAM("expecting fingerprint", localPublicKey->getFingerprint()) + IDHPublicKey::toDebug(localPublicKey))
                    setError(IHTTP::HTTPStatusCode_CertError, "encoding not using remote public key provided");
                    goto receive_error_out;
                  }
                }
              }

              if (localPrivateKey->getKeyDomain()->getPrecompiledType() != mDHKeyDomain->getPrecompiledType()) {
                ZS_LOG_ERROR(Detail, log("encoding key domain namespace does not match") + ZS_PARAM("local private key domain", IDHKeyDomain::toDebug(localPrivateKey->getKeyDomain())) + ZS_PARAM("expecting key domain", IDHKeyDomain::toDebug(mDHKeyDomain)))
                setError(IHTTP::HTTPStatusCode_PreconditionFailed, "encoding key domain namespace does not match expecting");
                goto receive_error_out;
              }

              SecureByteBlockPtr agreedKey = localPrivateKey->getSharedSecret(mDHRemotePublicKey);
              if (!IHelper::hasData(agreedKey)) {
                ZS_LOG_ERROR(Detail, log("could not agree upon a shared secret") + ZS_PARAM("remote public key", IDHPublicKey::toDebug(mDHRemotePublicKey)) + ZS_PARAM("local public key", IDHPublicKey::toDebug(mDHLocalPublicKey)) + ZS_PARAM("local private key", IDHPrivateKey::toDebug(mDHLocalPrivateKey)))
                setError(IHTTP::HTTPStatusCode_CertError, "remote public key is not valid");
                goto receive_error_out;
              }

              decodingPassphrase = IHelper::convertToHex(*agreedKey);
              mDHSentRemoteSideLocalPublicKey = false; // no longer need this variable to determine if the keying material was sent as keys can now be generated
            } else if ("passphrase" == type) {
              mReceiveKeyingType = KeyingType_Passphrase;
              if (KeyingType_Unknown == mSendKeyingType) mSendKeyingType = KeyingType_Passphrase;

              if (mReceivePassphrase.isEmpty()) {
                ZS_LOG_DEBUG(log("cannot continue decoding as missing decoding passphrase (will notify delegate)"))
                goto receive_waiting_for_information;
              }

              // scope: we have a passphrase, see if the proof validates before attempting to decrypt any keys...
              {
                String algorithm = getElementTextAndDecode(encodingEl->findFirstChildElementChecked("algorithm"));
                if (ORTC_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_CRYPTO_ALGORITHM != algorithm) {
                  ZS_LOG_ERROR(Detail, log("keying encoding not using known algorithm") + ZS_PARAM("algorithm", algorithm) + ZS_PARAM("expecting", ORTC_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_CRYPTO_ALGORITHM))
                  setError(IHTTP::HTTPStatusCode_ExpectationFailed, "keyhing encoding not using expecting passphrase");
                  goto receive_error_out;
                }

                String proof = getElementTextAndDecode(encodingEl->findFirstChildElementChecked("proof"));

                // hex(hmac(`<external-passphrase>`, "keying:" + `<nonce>`))
                String calculatedProof = IHelper::convertToHex(*IHasher::hash("keying:" + nonce, IHasher::hmacSHA1(*IHasher::hmacKeyFromPassphrase(mReceivePassphrase))));

                if (proof != calculatedProof) {
                  ZS_LOG_ERROR(Detail, log("keying encoding not using expecting passphrase") + ZS_PARAM("encoding proof", proof) + ZS_PARAM("expecting proof", calculatedProof) + ZS_PARAM("using passphrase", mReceivePassphrase))
                  setError(IHTTP::HTTPStatusCode_ExpectationFailed, "keyhing encoding not using expecting passphrase");
                  goto receive_error_out;
                }
              }

              decodingPassphrase = mReceivePassphrase;
            }

            // scope: check if nonce seen before
            {
              String hashNonce = IHelper::convertToHex(*IHasher::hash(nonce));
              String nonceNamespace = ORTC_SERVICES_MLS_COOKIE_NONCE_CACHE_NAMESPACE + hashNonce;

              String result = ICache::fetch(nonceNamespace);
              if (result.hasData()) {
                ZS_LOG_ERROR(Detail, log("keying encoding seen previously") + ZS_PARAM("nonce", nonce) + ZS_PARAM("nonce namespace", nonceNamespace));
                setError(IHTTP::HTTPStatusCode_Forbidden, "keyhing encoding information was seen previously");
                goto receive_error_out;
              }

              ICache::store(nonceNamespace, expires, "1");
            }

            // scope: santity check on algorithms receiving
            {
              bool found = false;
              ElementPtr algorithmEl = keyingEl->findFirstChildElementChecked("algorithms")->findFirstChildElementChecked("algorithm");
              while (algorithmEl) {
                String algorithm = getElementTextAndDecode(algorithmEl);
                if (ORTC_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_CRYPTO_ALGORITHM == algorithm) {
                  ZS_LOG_TRACE(log("found mandated algorithm"))
                  found = true;
                  break;
                }
                algorithmEl->findNextSiblingElement("algorithm");
              }
              if (!found) {
                ZS_LOG_ERROR(Detail, log("did not find mandated MLS algorithm") + ZS_PARAM("expecting", ORTC_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_CRYPTO_ALGORITHM))
                goto receive_error_out;
              }
            }

            // scope: extract out latest keying material
            {
              ElementPtr keysEl = keyingEl->findFirstChildElement("keys");
              ElementPtr keyEl = ((bool)keysEl) ? keysEl->findFirstChildElementChecked("key") : ElementPtr();
              while (keyEl) {
                // scope: decode key
                {
                  AlgorithmIndex index = 0;
                  try {
                    index = Numeric<AlgorithmIndex>(getElementTextAndDecode(keyEl->findFirstChildElementChecked("index")));
                  } catch(const Numeric<AlgorithmIndex>::ValueOutOfRange &) {
                    ZS_LOG_WARNING(Detail, log("algorithm index value out of range"))
                  }

                  if (0 == index) {
                    ZS_LOG_WARNING(Detail, log("algorithm index value is not valid") + ZS_PARAM("index", index))
                    goto next_key;
                  }

                  String algorithm = getElementTextAndDecode(keyEl->findFirstChildElementChecked("algorithm"));
                  if (ORTC_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_CRYPTO_ALGORITHM != algorithm) {
                    ZS_LOG_WARNING(Detail, log("unsupported algorithm (thus skipping)") + ZS_PARAM("algorithm", algorithm))
                    goto next_key;
                  }

                  ElementPtr inputs = keyEl->findFirstChildElementChecked("inputs");

                  KeyInfo key;
                  SecureByteBlockPtr integrityPassphrase;
                  if (KeyingType_PublicKey == mReceiveKeyingType) {
                    // base64(rsa_encrypt(`<remote-public-key>`, `<value>`))
                    key.mSendKey = mReceiveLocalPrivateKey->decrypt(*IHelper::convertFromBase64(getElementTextAndDecode(inputs->findFirstChildElementChecked("secret"))));
                    key.mNextIV = mReceiveLocalPrivateKey->decrypt(*IHelper::convertFromBase64(getElementTextAndDecode(inputs->findFirstChildElementChecked("iv"))));
                    integrityPassphrase = mReceiveLocalPrivateKey->decrypt(*IHelper::convertFromBase64(getElementTextAndDecode(inputs->findFirstChildElementChecked("hmacIntegrityKey"))));
                  } else {
                    key.mSendKey = decryptUsingPassphraseEncoding(decodingPassphrase, nonce, getElementTextAndDecode(inputs->findFirstChildElementChecked("secret")));
                    key.mNextIV = decryptUsingPassphraseEncoding(decodingPassphrase, nonce, getElementTextAndDecode(inputs->findFirstChildElementChecked("iv")));
                    integrityPassphrase = decryptUsingPassphraseEncoding(decodingPassphrase, nonce, getElementTextAndDecode(inputs->findFirstChildElementChecked("hmacIntegrityKey")));
                  }
                  if (integrityPassphrase) {
                    key.mIntegrityPassphrase = IHelper::convertToString(*integrityPassphrase);
                  }
                  if ((IHelper::isEmpty(key.mSendKey)) ||
                      (IHelper::isEmpty(key.mNextIV)) ||
                      (key.mIntegrityPassphrase.isEmpty())) {
                    ZS_LOG_WARNING(Detail, log("algorithm missing vital secret, iv or integrity information") + ZS_PARAM("index", index))
                    goto next_key;
                  }

                  ZS_LOG_DEBUG(log("receive algorithm keying information") + key.toDebug(index))
                  mReceiveKeys[index] = key;
                }

              next_key:
                keyEl = keyEl->findNextSiblingElement("key");
              }
            }

          } catch(CheckFailed &) {
            ZS_LOG_ERROR(Detail, log("expecting element in keying bundle that was missing"))
          }

          ZS_LOG_DEBUG(log("successfully extracted keying materials to receive data from remote MLS stream") + ZS_PARAM("keys found", mReceiveKeys.size()))
          ++mNextReceiveSequenceNumber;
          return true;
        }

      receive_error_out:
        {
          cancel();
          outReturnResult = false;
          return false;
        }

      receive_waiting_for_information:
        {
          mReceiveKeyingSignedDoc = doc;
          mReceiveKeyingSignedEl = keyingEl;

          setState(SessionState_WaitingForNeededInformation);

          outReturnResult = false;
        }

        return false;
      }

      //-----------------------------------------------------------------------
      bool MessageLayerSecurityChannel::stepSendKeying()
      {
        if (!mSendStreamEncodedWriteReady) {
          ZS_LOG_TRACE(log("cannot send encoded stream until lower layer transport (typically 'wire' transport) indicates it is ready to send data"))
          return false;
        }

        if (!isSendingReady()) {
          ZS_LOG_TRACE(log("sending isn't ready because of missing information"))
          setState(SessionState_WaitingForNeededInformation);
          return false;
        }

        // notify the "outer" that it can now send data over the wire
        if (!mNotifySendStreamDecodedReadyToReady) {
          mNotifySendStreamDecodedReadyToReady = true;
          mSendStreamDecoded->notifyReaderReadyToRead();
        }

        if (mSendKeyingNeedingToSignDoc) {
          ZS_THROW_INVALID_ASSUMPTION_IF(mSendKeyingNeedToSignEl)

          ElementPtr keyingEl;
          try {
            keyingEl = mSendKeyingNeedingToSignDoc->findFirstChildElementChecked("keyingBundle")->findFirstChildElementChecked("keying");
          } catch(CheckFailed &) {
          }

          if (!keyingEl) {
            ZS_LOG_ERROR(Detail, log("failed to obtain signed keying element"))
            setError(IHTTP::HTTPStatusCode_BadRequest, "failed to obtain signed keying element");
            cancel();
            return false;
          }

          // developer using this class should have signed this bundle if enters this spot
          ElementPtr signatureEl;
          IHelper::getSignatureInfo(keyingEl, &signatureEl);
          ZS_THROW_INVALID_USAGE_IF(!signatureEl)

          // signature has been applied
          size_t outputLength = 0;
          GeneratorPtr generator = Generator::createJSONGenerator();
          std::unique_ptr<char[]> output = generator->write(mSendKeyingNeedingToSignDoc, &outputLength);

          SecureByteBlockPtr buffer(make_shared<SecureByteBlock>(sizeof(DWORD) + (outputLength * sizeof(char))));

          ((DWORD *)(buffer->BytePtr()))[0] = htonl(0);

          BYTE *dest = (buffer->BytePtr() + sizeof(DWORD));

          memcpy(dest, output.get(), sizeof(char)*outputLength);

          if (ZS_IS_LOGGING(Trace)) {
            ZS_LOG_DETAIL(log("-------------------------------------------------------------------------------------------"))
            ZS_LOG_DETAIL(log("] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ]"))
            ZS_LOG_DETAIL(log("-------------------------------------------------------------------------------------------"))
            ZS_LOG_DETAIL(log("MLS SENDING") + ZS_PARAM("json out", (CSTR)(output.get())))
            ZS_LOG_DETAIL(log("-------------------------------------------------------------------------------------------"))
            ZS_LOG_DETAIL(log("] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ] ]"))
            ZS_LOG_DETAIL(log("-------------------------------------------------------------------------------------------"))
          }

          mSendStreamEncoded->write(buffer);

          mSendKeyingNeedingToSignDoc.reset();

          return true;
        }

        if ((mSendKeys.size() > 0) ||
            (mDHSentRemoteSideLocalPublicKey)) {
          ZS_LOG_TRACE(log("already sent keying materials"))
          return true;
        }

        if ((!mChangeSendingKeyTimer) &&
            (KeyingType_KeyAgreement == mSendKeyingType)) {
          mChangeSendingKeyTimer = ITimer::create(mThisWeak.lock(), Seconds(ISettings::getUInt(ORTC_SERVICES_SETTING_MESSAGE_LAYER_SECURITY_CHANGE_SENDING_KEY_AFTER)));
        }

        // create initial encryption offer (hint: it won't change)

        ElementPtr keyingBundleEl = Element::create("keyingBundle");

        ElementPtr keyingEl = Element::create("keying");
        
        keyingEl->adoptAsLastChild(createElementWithNumber("sequence", string(mNextSendSequenceNumber)));

        String nonce = IHelper::randomString(32);

        keyingEl->adoptAsLastChild(createElementWithText("nonce", nonce));
        keyingEl->adoptAsLastChild(createElementWithText("context", mLocalContextID));

        Time expires = zsLib::now() + Seconds(ORTC_SERVICES_MLS_DEFAULT_KEYING_EXPIRES_TIME_IN_SECONDS);

        keyingEl->adoptAsLastChild(createElementWithNumber("expires", IHelper::timeToString(expires)));

        ElementPtr encodingEl = Element::create("encoding");
        keyingEl->adoptAsLastChild(encodingEl);

        String encodingPassphrase;

        switch (mSendKeyingType) {
          case KeyingType_Unknown: break; // not possible
          case KeyingType_Passphrase: {
            encodingEl->adoptAsLastChild(createElementWithText("type", "passphrase"));
            encodingEl->adoptAsLastChild(createElementWithText("algorithm", ORTC_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_CRYPTO_ALGORITHM));

            String calculatedProof = IHelper::convertToHex(*IHasher::hash("keying:" + nonce, IHasher::hmacSHA1(*IHasher::hmacKeyFromPassphrase(mSendPassphrase))));

            encodingEl->adoptAsLastChild(createElementWithText("proof", calculatedProof));
            break;
          }
          case KeyingType_PublicKey: {
            ZS_THROW_INVALID_ASSUMPTION_IF(!mSendRemotePublicKey)
            encodingEl->adoptAsLastChild(createElementWithText("type", "pki"));
            encodingEl->adoptAsLastChild(createElementWithText("fingerprint", mSendRemotePublicKey->getFingerprint()));
            break;
          }
          case KeyingType_KeyAgreement: {
            encodingEl->adoptAsLastChild(createElementWithText("type", "agreement"));
            mDHSentRemoteSideLocalPublicKey = true;

            bool includeFullKey = true;

            if (mChangeKey) {
              if (mDHRemoteSideKnowsLocalPublicKey) {
                ZS_LOG_TRACE(log("cannot change key is haven't given fingerprint of local public key expected to remote party"))
                mChangeKey = false;  // cannot change key in this state
              }
            }

            if (mChangeKey) {
              ZS_LOG_TRACE(log("time to change the key"))
              mDHPreviousLocalKeys.push_back(DHPrivatePublicKeyPair(mDHLocalPrivateKey, mDHLocalPublicKey));

              mDHLocalPrivateKey = IDHPrivateKey::loadAndGenerateNewEphemeral(mDHLocalPrivateKey, mDHLocalPublicKey, mDHLocalPublicKey);

              mChangeKey = false;
            }

            if (mDHRemoteSideKnowsLocalPublicKey) {
              includeFullKey = false;
              mDHRemoteSideKnowsLocalPublicKey = false;
              encodingEl->adoptAsLastChild(createElementWithText("fingerprint", mDHLocalPublicKey->getFingerprint()));
            } else {
              if (mDHRemotePublicKey) {
                encodingEl->adoptAsLastChild(createElementWithText("fingerprint", mDHRemotePublicKey->getFingerprint()));
              }
            }

            if (includeFullKey) {
              IDHKeyDomainPtr keyDomain = mDHLocalPrivateKey->getKeyDomain();
              ZS_THROW_INVALID_ASSUMPTION_IF(!keyDomain)

              SecureByteBlock staticPublicKey;
              SecureByteBlock ephemeralPublicKey;

              mDHLocalPublicKey->save(&staticPublicKey, &ephemeralPublicKey);

              String fullKey = IHelper::convertToBase64(*IHelper::convertToBuffer(IDHKeyDomain::toNamespace(keyDomain->getPrecompiledType()))) +
                               ":" + IHelper::convertToBase64(staticPublicKey) +
                               ":" + IHelper::convertToBase64(ephemeralPublicKey);

              encodingEl->adoptAsLastChild(createElementWithText("key", fullKey));
            }

            mDHSentRemoteSideLocalPublicKey = true;

            if (mDHRemotePublicKey) {
              SecureByteBlockPtr agreement = mDHLocalPrivateKey->getSharedSecret(mDHRemotePublicKey);
              if (!agreement) {
                ZS_LOG_ERROR(Detail, log("failed to agree upon a key for encoding"))
                setError(IHTTP::HTTPStatusCode_PreconditionFailed, "failed to agree upon a key for encoding");
                cancel();
                return false;
              }

              encodingPassphrase = IHelper::convertToHex(*agreement);
            }
            break;
          }
        }

        ElementPtr algorithmsEl = Element::create("algorithms");
        algorithmsEl->adoptAsLastChild(createElementWithText("algorithm", ORTC_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_CRYPTO_ALGORITHM));

        keyingEl->adoptAsLastChild(algorithmsEl);

        bool createKeys = false;

        switch (mSendKeyingType) {
          case KeyingType_Unknown: break; // not possible
          case KeyingType_Passphrase:
          case KeyingType_KeyAgreement: {
            createKeys = encodingPassphrase.hasData();
            break;
          }
          case KeyingType_PublicKey: {
            createKeys = (bool)mSendRemotePublicKey;
            break;
          }
        }

        if (createKeys) {
          ElementPtr keysEl = Element::create("keys");

          for (AlgorithmIndex index = 1; index <= ORTC_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_TOTAL_SEND_KEYS; ++index) {
            KeyInfo key;

            key.mIntegrityPassphrase = IHelper::randomString((20*8/5));
            key.mSendKey = IHasher::hash(*IHelper::random(32), IHasher::sha256());
            key.mNextIV = IHasher::hash(*IHelper::random(16), IHasher::md5());

            ElementPtr keyEl = Element::create("key");
            keyEl->adoptAsLastChild(createElementWithNumber("index", string(index)));
            keyEl->adoptAsLastChild(createElementWithText("algorithm", ORTC_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_CRYPTO_ALGORITHM));

            ElementPtr inputsEl = Element::create("inputs");
            if (encodingPassphrase.hasData()) {
              inputsEl->adoptAsLastChild(createElementWithText("secret", encodeUsingPassphraseEncoding(encodingPassphrase, nonce, *key.mSendKey)));
              inputsEl->adoptAsLastChild(createElementWithText("iv", encodeUsingPassphraseEncoding(encodingPassphrase, nonce, *key.mNextIV)));
              inputsEl->adoptAsLastChild(createElementWithText("hmacIntegrityKey", encodeUsingPassphraseEncoding(encodingPassphrase, nonce, *IHelper::convertToBuffer(key.mIntegrityPassphrase))));
            } else {
              ZS_THROW_INVALID_ASSUMPTION_IF(!mSendRemotePublicKey)
              inputsEl->adoptAsLastChild(createElementWithText("secret", IHelper::convertToBase64(*mSendRemotePublicKey->encrypt(*key.mSendKey))));
              inputsEl->adoptAsLastChild(createElementWithText("iv", IHelper::convertToBase64(*mSendRemotePublicKey->encrypt(*key.mNextIV))));
              inputsEl->adoptAsLastChild(createElementWithText("hmacIntegrityKey", IHelper::convertToBase64(*mSendRemotePublicKey->encrypt(*IHelper::convertToBuffer(key.mIntegrityPassphrase)))));
            }

            ZS_LOG_DEBUG(log("send algorithm keying information") + key.toDebug(index))

            keyEl->adoptAsLastChild(inputsEl);

            keysEl->adoptAsLastChild(keyEl);

            mSendKeys[index] = key;
          }

          keyingEl->adoptAsLastChild(keysEl);
        }

        keyingBundleEl->adoptAsLastChild(keyingEl);

        mSendKeyingNeedingToSignDoc = Document::create();
        mSendKeyingNeedingToSignDoc->adoptAsLastChild(keyingBundleEl);
        mSendKeyingNeedToSignEl = keyingEl;

        if ((mSendSigningPrivateKey) &&
            (mSendSigningPublicKey)) {

          ZS_LOG_DEBUG(log("auto-signing sending keying material (via fingerprint)"))

          ElementPtr elementToSign = keyingEl;

          String id = IHelper::convertToHex(*IHelper::random(16));
          elementToSign->setAttribute("id", id);

          String referenceID = "#" + id;

          GeneratorPtr generator = Generator::createJSONGenerator();

          ElementPtr canonicalJSONEl = IHelper::cloneAsCanonicalJSON(elementToSign);
          std::unique_ptr<char[]> elementAsJSON = generator->write(canonicalJSONEl);

          SecureByteBlockPtr elementHash = IHasher::hash(elementAsJSON.get(), IHasher::sha1());

          ElementPtr signatureEl = Element::create("signature");

          signatureEl->adoptAsLastChild(createElementWithText("reference", referenceID));
          signatureEl->adoptAsLastChild(createElementWithText("algorithm", ORTC_SERVICES_MESSAGE_LAYER_SECURITY_SIGNATURE_ALGORITHM));
          signatureEl->adoptAsLastChild(createElementWithText("digestValue", IHelper::convertToBase64(*elementHash)));
          signatureEl->adoptAsLastChild(createElementWithText("digestSigned", IHelper::convertToBase64(*mSendSigningPrivateKey->sign(*elementHash))));

          ElementPtr keyEl = Element::create("key");

          ElementPtr fingerprintEl = createElementWithText("fingerprint", mSendSigningPublicKey->getFingerprint());
          keyEl->adoptAsLastChild(fingerprintEl);

          mSendKeyingNeedToSignEl.reset();
          IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
          return false;
        }

        ZS_LOG_DEBUG(log("waiting for sending keying information to be signed locally"))

        setState(SessionState_WaitingForNeededInformation);
        return false;
      }

      //-----------------------------------------------------------------------
      bool MessageLayerSecurityChannel::stepSend()
      {
        if (mSendKeys.size() < 1) {
          ZS_LOG_DEBUG(log("no send keys set, not sending yet..."))
          return false;
        }

        if (mSendStreamDecoded->getTotalReadBuffersAvailable() < 1) {
          ZS_LOG_TRACE(log("no data to be sent over the wire"))
          return true;
        }

        while (mSendStreamDecoded->getTotalReadBuffersAvailable() > 0) {
          StreamHeaderPtr header;
          SecureByteBlockPtr buffer = mSendStreamDecoded->read(&header);

          ZS_THROW_BAD_STATE_IF(!buffer)

          if (ZS_IS_LOGGING(Insane)) {
            String str = IHelper::getDebugString(*buffer);
            ZS_LOG_INSANE(log("stream buffer to encode") + ZS_PARAM("raw", "\n" + str))
          }

          // pick an algorithm
          AlgorithmIndex index = static_cast<AlgorithmIndex>(IHelper::random(1, mSendKeys.size()));

          KeyMap::iterator found = mSendKeys.find(index);
          ZS_THROW_BAD_STATE_IF(found == mSendKeys.end())

          KeyInfo &keyInfo = (*found).second;

          ZS_LOG_INSANE(log("encrypting key to use") + keyInfo.toDebug(index))

          SecureByteBlockPtr encrypted = IHelper::encrypt(*(keyInfo.mSendKey), *(keyInfo.mNextIV), *buffer);

          String hexIV = IHelper::convertToHex(*keyInfo.mNextIV);

          String hashDecryptedBuffer = IHelper::convertToHex(*IHasher::hash(*buffer));

          SecureByteBlockPtr calculatedIntegrity = IHasher::hash(("integrity:" + hashDecryptedBuffer + ":" + hexIV).c_str(), IHasher::hmacSHA1(*(IHelper::convertToBuffer(keyInfo.mIntegrityPassphrase))));

          // calculate the next IV and remember the integrity field
          keyInfo.mNextIV = IHasher::hash(hexIV + ":" + IHelper::convertToHex(*calculatedIntegrity));
          keyInfo.mLastIntegrity = calculatedIntegrity;

          SecureByteBlockPtr output(make_shared<SecureByteBlock>(sizeof(DWORD) + calculatedIntegrity->SizeInBytes() + encrypted->SizeInBytes()));

          ((DWORD *)output->BytePtr())[0] = htonl(index);

          BYTE *integrityPos = (output->BytePtr() + sizeof(DWORD));
          BYTE *outputPos = (integrityPos + calculatedIntegrity->SizeInBytes());

          memcpy(integrityPos, calculatedIntegrity->BytePtr(), calculatedIntegrity->SizeInBytes());
          memcpy(outputPos, encrypted->BytePtr(), encrypted->SizeInBytes());

          if (ZS_IS_LOGGING(Insane)) {
            String str = IHelper::convertToBase64(*output);
            ZS_LOG_INSANE(log("stream buffer write") + ZS_PARAM("wire out", str))
          }

          if (ZS_IS_LOGGING(Debug)) {
            String hashEncryptedBuffer = IHelper::convertToHex(*IHasher::hash(*encrypted));
            ZS_LOG_DEBUG(log("sending data on wire") + ZS_PARAM("keying index", index) + ZS_PARAM("buffer size", output->SizeInBytes()) + ZS_PARAM("decrypted size", buffer->SizeInBytes()) + ZS_PARAM("encrypted size", encrypted->SizeInBytes()) + ZS_PARAM("key", IHelper::convertToHex(*(keyInfo.mSendKey))) + ZS_PARAM("iv", hexIV) + ZS_PARAM("integrity", IHelper::convertToHex(*calculatedIntegrity)) + ZS_PARAM("integrity passphrase", keyInfo.mIntegrityPassphrase) + ZS_PARAM("decrypted data hash", hashDecryptedBuffer) + ZS_PARAM("encrypted data hash", hashEncryptedBuffer));
          }
          mSendStreamEncoded->write(output, header);
        }

        return true;
      }

      //-----------------------------------------------------------------------
      bool MessageLayerSecurityChannel::stepCheckConnected()
      {
        if (mSendKeys.size() < 1) {
          ZS_LOG_TRACE(log("no send keys set, not sending yet..."))
          return false;
        }
        if (mReceiveKeys.size() < 1) {
          ZS_LOG_TRACE(log("no receive keys set, not sending yet..."))
          return false;
        }
        ZS_LOG_TRACE(log("connected"))
        return true;
      }

      //-----------------------------------------------------------------------
      bool MessageLayerSecurityChannel::isSendingReady() const
      {
        AutoRecursiveLock lock(*this);

        if (!mSendStreamEncodedWriteReady) {
          ZS_LOG_DEBUG(log("cannot send encoded stream until lower layer transport (typically 'wire' transport) indicates it is ready to send data"))
          return false;
        }

        if (mLocalContextID.isEmpty()) {
          ZS_LOG_TRACE(log("missing local context ID thus cannot send data remotely"))
          return false;
        }

        if (mSendKeyingNeedingToSignDoc) {
          if (mSendKeyingNeedToSignEl) {
            ZS_LOG_TRACE(log("send signature not created"))
            return false;
          }
        }

        switch (mSendKeyingType) {
          case KeyingType_Unknown:      break;
          case KeyingType_Passphrase:   {
            ZS_LOG_TRACE(log("is sending ready - passphrase") + ZS_PARAM("passphrase", mSendPassphrase))
            return mSendPassphrase.hasData();
          }
          case KeyingType_PublicKey:    {
            ZS_LOG_TRACE(log("is sending ready - private key") + IRSAPublicKey::toDebug(mSendRemotePublicKey))
            return (bool)mSendRemotePublicKey;
          }
          case KeyingType_KeyAgreement: {
            ZS_LOG_TRACE(log("is sending ready - key agreement") + ZS_PARAM("local private key", IDHPrivateKey::toDebug(mDHLocalPrivateKey)) + ZS_PARAM("local public key", IDHPublicKey::toDebug(mDHLocalPublicKey)) + ZS_PARAM("remote public key", IDHPublicKey::toDebug(mDHRemotePublicKey)) + ZS_PARAM("remote public key fingerprint", mDHRemotePublicKeyFingerprint))
            return ((bool)mDHLocalPrivateKey) &&
            ((bool)mDHLocalPublicKey);
          }
        }

        ZS_LOG_TRACE(log("sending is not ready"))
        return false;
      }
      
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark MessageLayerSecurityChannel::KeyInfo
      #pragma mark

      //-----------------------------------------------------------------------
      ElementPtr MessageLayerSecurityChannel::KeyInfo::toDebug(AlgorithmIndex index) const
      {
        ElementPtr resultEl = Element::create("MessageLayerSecurityChannel");

        IHelper::debugAppend(resultEl, "key index", index);
        IHelper::debugAppend(resultEl, "integrity passphrase", mIntegrityPassphrase);
        IHelper::debugAppend(resultEl, "send key", mSendKey ? IHelper::convertToHex(*mSendKey) : String());
        IHelper::debugAppend(resultEl, "next iv", mNextIV ? IHelper::convertToHex(*mNextIV) : String());
        IHelper::debugAppend(resultEl, "last integrity", mLastIntegrity ? IHelper::convertToHex(*mLastIntegrity) : String());
        return resultEl;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IMessageLayerSecurityChannelFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IMessageLayerSecurityChannelFactory &IMessageLayerSecurityChannelFactory::singleton()
      {
        return MessageLayerSecurityChannelFactory::singleton();
      }

      //-----------------------------------------------------------------------
      MessageLayerSecurityChannelPtr IMessageLayerSecurityChannelFactory::create(
                                                                                 IMessageLayerSecurityChannelDelegatePtr delegate,
                                                                                 ITransportStreamPtr receiveStreamEncoded,
                                                                                 ITransportStreamPtr receiveStreamDecoded,
                                                                                 ITransportStreamPtr sendStreamDecoded,
                                                                                 ITransportStreamPtr sendStreamEncoded,
                                                                                 const char *contextID
                                                                                 )
      {
        if (this) {}
        return MessageLayerSecurityChannel::create(delegate, receiveStreamEncoded, receiveStreamDecoded, sendStreamDecoded, sendStreamEncoded, contextID);
      }
    }

    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    //-----------------------------------------------------------------------
    #pragma mark
    #pragma mark IMessageLayerSecurityChannel
    #pragma mark

    //-----------------------------------------------------------------------
    const char *IMessageLayerSecurityChannel::toString(SessionStates state)
    {
      switch (state)
      {
        case SessionState_Pending:                      return "Pending";
        case SessionState_WaitingForNeededInformation:  return "Waiting for needed information";
        case SessionState_Connected:                    return "Connected";
        case SessionState_Shutdown:                     return "Shutdown";
      }
      return "UNDEFINED";
    }

    //-----------------------------------------------------------------------
    const char *IMessageLayerSecurityChannel::toString(KeyingTypes type)
    {
      switch (type)
      {
        case KeyingType_Unknown:      return "Unknown";
        case KeyingType_Passphrase:   return "Passphrase";
        case KeyingType_PublicKey:    return "Public key";
        case KeyingType_KeyAgreement: return "Key agreement";
      }
      return "UNDEFINED";
    }

    //-----------------------------------------------------------------------
    ElementPtr IMessageLayerSecurityChannel::toDebug(IMessageLayerSecurityChannelPtr channel)
    {
      return internal::MessageLayerSecurityChannel::toDebug(channel);
    }

    //-----------------------------------------------------------------------
    IMessageLayerSecurityChannelPtr IMessageLayerSecurityChannel::create(
                                                                         IMessageLayerSecurityChannelDelegatePtr delegate,
                                                                         ITransportStreamPtr receiveStreamEncoded,
                                                                         ITransportStreamPtr receiveStreamDecoded,
                                                                         ITransportStreamPtr sendStreamDecoded,
                                                                         ITransportStreamPtr sendStreamEncoded,
                                                                         const char *contextID
                                                                         )
    {
      return internal::IMessageLayerSecurityChannelFactory::singleton().create(delegate, receiveStreamEncoded, receiveStreamDecoded, sendStreamDecoded, sendStreamEncoded, contextID);
    }
  }
}
