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

#include <openpeer/services/internal/services_MessageLayerSecurityChannel.h>
#include <openpeer/services/internal/services_Helper.h>
#include <openpeer/services/IRSAPrivateKey.h>
#include <openpeer/services/IRSAPublicKey.h>
#include <openpeer/services/IHTTP.h>
#include <openpeer/services/IDHKeyDomain.h>
#include <openpeer/services/IDHPrivateKey.h>
#include <openpeer/services/IDHPublicKey.h>
#include <openpeer/services/ICache.h>

#include <zsLib/Log.h>
#include <zsLib/XML.h>
#include <zsLib/helpers.h>

#include <zsLib/Stringize.h>
#include <zsLib/Numeric.h>

#define OPENPEER_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_TOTAL_SEND_KEYS 3

#define OPENPEER_SERVICES_MLS_DEFAULT_KEYING_EXPIRES_TIME_IN_SECONDS (2*(60*60))

#define OPENPEER_SERVICES_MLS_COOKIE_NONCE_CACHE_NAMESPACE "https://meta.openpeer.org/caching/mls/nonce/"

namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services_mls) } }

namespace openpeer
{
  namespace services
  {
    using zsLib::DWORD;
    using zsLib::Numeric;

    namespace internal
    {
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

        SecureByteBlockPtr key = IHelper::hmac(*IHelper::hmacKeyFromPassphrase(passphrase), "keying:" + nonce, IHelper::HashAlgorthm_SHA256);

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

        SecureByteBlockPtr iv = IHelper::random(IHelper::getHashDigestSize(IHelper::HashAlgorthm_MD5));
        String hexSalt = IHelper::convertToHex(*iv);

        SecureByteBlockPtr key = IHelper::hmac(*IHelper::hmacKeyFromPassphrase(passphrase), "keying:" + nonce, IHelper::HashAlgorthm_SHA256);

        SecureByteBlockPtr output = IHelper::encrypt(*key, *iv, value);

        return IHelper::convertToHex(*iv) + ":" + IHelper::convertToBase64(*output);
      }
      
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark MessageLayerSecurityChannel
      #pragma mark

      //-----------------------------------------------------------------------
      const char *MessageLayerSecurityChannel::toString(DecodingTypes decodingType)
      {
        switch (decodingType)
        {
          case DecodingType_Unknown:    return "Unknown";
          case DecodingType_PrivateKey: return "Private key";
          case DecodingType_Agreement:  return "Agreement";
          case DecodingType_Passphrase: return "Passphrase";
        }
        return "UNDEFINED";
      }

      //-----------------------------------------------------------------------
      MessageLayerSecurityChannel::MessageLayerSecurityChannel(
                                                               IMessageQueuePtr queue,
                                                               IMessageLayerSecurityChannelDelegatePtr delegate,
                                                               ITransportStreamPtr receiveStreamEncoded,
                                                               ITransportStreamPtr receiveStreamDecoded,
                                                               ITransportStreamPtr sendStreamDecoded,
                                                               ITransportStreamPtr sendStreamEncoded,
                                                               const char *contextID
                                                               ) :
        zsLib::MessageQueueAssociator(queue),
        mID(zsLib::createPUID()),
        mCurrentState(SessionState_Pending),
        mLastError(0),
        mLocalContextID(contextID),
        mNextReceiveSequenceNumber(0),
        mReceiveDecodingType(DecodingType_Unknown),
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
        AutoRecursiveLock lock(getLock());

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
        return dynamic_pointer_cast<MessageLayerSecurityChannel>(channel);
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
        MessageLayerSecurityChannelPtr pThis(new MessageLayerSecurityChannel(IHelper::getServiceQueue(), delegate, receiveStreamEncoded, receiveStreamDecoded, sendStreamDecoded, sendStreamEncoded, contextID));
        pThis->mThisWeak = pThis;
        pThis->init();
        return pThis;
      }

      //-----------------------------------------------------------------------
      IMessageLayerSecurityChannelSubscriptionPtr MessageLayerSecurityChannel::subscribe(IMessageLayerSecurityChannelDelegatePtr originalDelegate)
      {
        AutoRecursiveLock lock(getLock());
        if (!originalDelegate) return mDefaultSubscription;

        IMessageLayerSecurityChannelSubscriptionPtr subscription = mSubscriptions.subscribe(originalDelegate);

        IMessageLayerSecurityChannelDelegatePtr delegate = mSubscriptions.delegate(subscription);

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

        AutoRecursiveLock lock(getLock());

        setState(SessionState_Shutdown);

        mSubscriptions.clear();

        mSendingEncodingRemotePublicKey.reset();

        mDHLocalPrivateKey.reset();
        mDHLocalPublicKey.reset();

        mDHRemotePublicKey.reset();

        mSendKeyingNeedingToSignDoc.reset();
        mSendKeyingNeedToSignEl.reset();

        mReceiveDecodingPrivateKey.reset();
        mReceiveDecodingPublicKey.reset();

        mReceiveSigningPublicKey.reset();
        mReceiveKeyingSignedDoc.reset();
        mReceiveKeyingSignedEl.reset();

        mReceiveStreamEncoded->cancel();
        mReceiveStreamDecoded->cancel();

        mSendStreamDecoded->cancel();
        mSendStreamEncoded->cancel();

        mReceiveStreamEncodedSubscription->cancel();
        mSendStreamDecodedSubscription->cancel();

        ZS_LOG_DEBUG(log("cancel complete"))
      }

      //-----------------------------------------------------------------------
      IMessageLayerSecurityChannel::SessionStates MessageLayerSecurityChannel::getState(
                                                                                        WORD *outLastErrorCode,
                                                                                        String *outLastErrorReason
                                                                                        ) const
      {
        AutoRecursiveLock lock(getLock());
        if (outLastErrorCode) *outLastErrorCode = mLastError;
        if (outLastErrorReason) *outLastErrorReason = mLastErrorReason;
        return mCurrentState;
      }

      //-----------------------------------------------------------------------
      bool MessageLayerSecurityChannel::needsLocalContextID() const
      {
        AutoRecursiveLock lock(getLock());
        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("cannot need information as already shutdown"))
          return false;
        }

        return mLocalContextID.isEmpty();
      }

      //-----------------------------------------------------------------------
      bool MessageLayerSecurityChannel::needsReceiveKeyingDecodingPrivateKey(
                                                                             String *outFingerprint
                                                                             ) const
      {
        AutoRecursiveLock lock(getLock());
        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("cannot need information as already shutdown"))
          return false;
        }

        if (outFingerprint) {
          *outFingerprint = mReceiveDecodingPublicKeyFingerprint;
        }

        if ((DecodingType_PrivateKey != mReceiveDecodingType) &&
            (DecodingType_Agreement != mReceiveDecodingType)) return false;

        if (DecodingType_PrivateKey == mReceiveDecodingType)
          return !((bool)mReceiveDecodingPrivateKey);

        return ((!mDHLocalPrivateKey) ||
                (!mDHLocalPublicKey));
      }

      //-----------------------------------------------------------------------
      bool MessageLayerSecurityChannel::needsReceiveKeyingDecodingPassphrase() const
      {
        AutoRecursiveLock lock(getLock());
        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("cannot need information as already shutdown"))
          return false;
        }
        return (DecodingType_Passphrase == mReceiveDecodingType) &&
               (mReceivingDecodingPassphrase.isEmpty());
      }

      //-----------------------------------------------------------------------
      bool MessageLayerSecurityChannel::needsReceiveKeyingMaterialSigningPublicKey() const
      {
        AutoRecursiveLock lock(getLock());
        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("cannot need information as already shutdown"))
          return false;
        }

        return mRemoteContextID.hasData() && (!((bool)(mReceiveSigningPublicKey)));
      }

      //-----------------------------------------------------------------------
      bool MessageLayerSecurityChannel::needsSendKeyingEncodingMaterial() const
      {
        AutoRecursiveLock lock(getLock());
        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("cannot need information as already shutdown"))
          return false;
        }
        return (!((bool)(mSendingEncodingRemotePublicKey))) &&
               (mSendingEncodingPassphrase.isEmpty()) &&
               ((!mDHLocalPrivateKey) &&
                (!mDHRemotePublicKey));
      }

      //-----------------------------------------------------------------------
      bool MessageLayerSecurityChannel::needsSendKeyingMaterialToeBeSigned() const
      {
        AutoRecursiveLock lock(getLock());
        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("cannot need information as already shutdown"))
          return false;
        }

        return (mSendKeyingNeedingToSignDoc) && (mSendKeyingNeedToSignEl);
      }

      //-----------------------------------------------------------------------
      String MessageLayerSecurityChannel::getLocalContextID() const
      {
        AutoRecursiveLock lock(getLock());
        return mLocalContextID;
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::setLocalContextID(const char *contextID)
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!contextID)

        AutoRecursiveLock lock(getLock());

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }

        if (mLocalContextID.hasData()) {
          ZS_THROW_INVALID_ARGUMENT_IF(contextID != mLocalContextID)
        }

        ZS_LOG_DEBUG(log("setting local context ID") + ZS_PARAM("context ID", contextID))

        mLocalContextID = contextID;

        setState(SessionState_Pending);

        IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
      }

      //-----------------------------------------------------------------------
      String MessageLayerSecurityChannel::getRemoteContextID() const
      {
        AutoRecursiveLock lock(getLock());
        return mRemoteContextID;
      }

      //-----------------------------------------------------------------------
      IDHKeyDomainPtr MessageLayerSecurityChannel::getDHRemoteKeyDomain() const
      {
        AutoRecursiveLock lock(getLock());
        return mDHRemoteKeyDomain;
      }

      //-----------------------------------------------------------------------
      IDHPublicKeyPtr MessageLayerSecurityChannel::getDHRemotePublicKey() const
      {
        AutoRecursiveLock lock(getLock());
        return mDHRemotePublicKey;
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::setReceiveKeyingDecoding(
                                                                 IRSAPrivateKeyPtr decodingPrivateKey,
                                                                 IRSAPublicKeyPtr decodingPublicKey
                                                                 )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!decodingPrivateKey)
        ZS_THROW_INVALID_ARGUMENT_IF(!decodingPublicKey)

        ZS_LOG_DEBUG(log("set receive keying decoding private/public key") + ZS_PARAM("decoding public key fingerprint", decodingPublicKey->getFingerprint()))

        AutoRecursiveLock lock(getLock());

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }

        if (mReceiveDecodingPrivateKey) {
          ZS_THROW_INVALID_ARGUMENT_IF(mReceiveDecodingPrivateKey != decodingPrivateKey)
        }
        if (mReceiveDecodingPublicKey) {
          ZS_THROW_INVALID_ARGUMENT_IF(mReceiveDecodingPublicKey != decodingPublicKey)
        }

        if (!mReceiveDecodingPrivateKey) {
          mReceiveDecodingPrivateKey = decodingPrivateKey;
        }
        if (!mReceiveDecodingPublicKey) {
          mReceiveDecodingPublicKey = decodingPublicKey;
        }

        setState(SessionState_Pending);

        IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::setReceiveKeyingDecoding(
                                                                 IDHPrivateKeyPtr localPrivateKey,
                                                                 IDHPublicKeyPtr localPublicKey,
                                                                 IDHPublicKeyPtr remotePublicKey
                                                                 )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!localPrivateKey)
        ZS_THROW_INVALID_ARGUMENT_IF(!localPublicKey)

        ZS_LOG_DEBUG(log("set receive keying decoding DH private/public key") + ZS_PARAM("local private key", localPrivateKey->getID())  + ZS_PARAM("local public key", localPublicKey->getID()) + ZS_PARAM("remote public key", remotePublicKey ? remotePublicKey->getID() : 0) + ZS_PARAM("remote public key fingerprint", remotePublicKey ? remotePublicKey->getFingerprint() : String()))

        AutoRecursiveLock lock(getLock());

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }

        if (mDHLocalPrivateKey) {
          ZS_THROW_INVALID_ARGUMENT_IF(localPrivateKey != mDHLocalPrivateKey)
        }
        if (mDHLocalPublicKey) {
          ZS_THROW_INVALID_ARGUMENT_IF(localPublicKey != mDHLocalPublicKey)
        }

        setState(SessionState_Pending);

        if (!mDHLocalPrivateKey) {
          mDHLocalPrivateKey = localPrivateKey;
        }
        if (!mDHLocalPublicKey) {
          mDHLocalPublicKey = localPublicKey;
        }
        if (!mDHRemotePublicKey) {
          mDHRemotePublicKey = remotePublicKey;
        }

        IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::setReceiveKeyingDecoding(const char *passphrase)
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!passphrase)

        ZS_LOG_DEBUG(log("set receive keying decoding passphrase") + ZS_PARAM("passphrase", passphrase))

        AutoRecursiveLock lock(getLock());

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }

        if (mReceivingDecodingPassphrase.hasData()) {
          ZS_THROW_INVALID_ARGUMENT_IF(passphrase != mReceivingDecodingPassphrase)
        }

        if (mReceivingDecodingPassphrase.isEmpty()) {
          mReceivingDecodingPassphrase = String(passphrase);
        }

        setState(SessionState_Pending);

        IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
      }

      //-----------------------------------------------------------------------
      ElementPtr MessageLayerSecurityChannel::getSignedReceivingKeyingMaterial() const
      {
        AutoRecursiveLock lock(getLock());
        return mReceiveKeyingSignedEl;
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::setReceiveKeyingMaterialSigningPublicKey(IRSAPublicKeyPtr remotePublicKey)
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!remotePublicKey)

        ZS_LOG_DEBUG(log("set receive key signing public key") + ZS_PARAM("public key fingerprint", remotePublicKey->getFingerprint()))

        AutoRecursiveLock lock(getLock());

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }

        if (mReceiveSigningPublicKey) {
          ZS_THROW_INVALID_ARGUMENT_IF(remotePublicKey != mReceiveSigningPublicKey)
        }

        if (!mReceiveSigningPublicKey) {
          mReceiveSigningPublicKey = remotePublicKey;
        }

        setState(SessionState_Pending);

        IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::setSendKeyingEncoding(IRSAPublicKeyPtr remotePublicKey)
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!remotePublicKey)

        ZS_LOG_DEBUG(log("send encoding public key") + ZS_PARAM("public key fingerprint", remotePublicKey->getFingerprint()))

        AutoRecursiveLock lock(getLock());

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }

        ZS_THROW_INVALID_USAGE_IF(mSendingEncodingPassphrase.hasData())

        if (mSendingEncodingRemotePublicKey) {
          ZS_THROW_INVALID_ARGUMENT_IF(remotePublicKey != mSendingEncodingRemotePublicKey)
        }

        if (!mSendingEncodingRemotePublicKey) {
          mSendingEncodingRemotePublicKey = remotePublicKey;
        }

        setState(SessionState_Pending);

        IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::setSendKeyingEncoding(
                                                              IDHPrivateKeyPtr localPrivateKey,
                                                              IDHPublicKeyPtr remotePublicKey,
                                                              IDHPublicKeyPtr includeFullLocalPublicKey
                                                              )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!localPrivateKey)
        ZS_THROW_INVALID_ARGUMENT_IF(!remotePublicKey)

        ZS_LOG_DEBUG(log("send encoding DH keying") + ZS_PARAM("local private key", localPrivateKey->getID()) + ZS_PARAM("remote public key", remotePublicKey->getID()) + ZS_PARAM("local public key", includeFullLocalPublicKey ? includeFullLocalPublicKey->getID() : 0) + ZS_PARAM("local public key fingerprint", includeFullLocalPublicKey ? includeFullLocalPublicKey->getFingerprint() : String()))

        AutoRecursiveLock lock(getLock());

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }

        ZS_THROW_INVALID_USAGE_IF(mSendingEncodingPassphrase.hasData())

        if (mDHLocalPrivateKey) {
          ZS_THROW_INVALID_ARGUMENT_IF(localPrivateKey != mDHLocalPrivateKey)
        }
        if (includeFullLocalPublicKey) {
          if (mDHLocalPublicKey) {
            ZS_THROW_INVALID_ARGUMENT_IF(includeFullLocalPublicKey != mDHLocalPublicKey)
          }
          if (mDHEncodingFullLocalPublicKey) {
            ZS_THROW_INVALID_ARGUMENT_IF(includeFullLocalPublicKey != mDHEncodingFullLocalPublicKey)
          }
        }

        if (!mDHLocalPrivateKey) {
          mDHLocalPrivateKey = localPrivateKey;
        }
        if (!mDHRemotePublicKey) {
          mDHRemotePublicKey = remotePublicKey;
        }
        if (!mDHEncodingFullLocalPublicKey) {
          mDHEncodingFullLocalPublicKey = includeFullLocalPublicKey;
        }

        setState(SessionState_Pending);

        IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
      }
      
      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::setSendKeyingEncoding(const char *passphrase)
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!passphrase)

        ZS_LOG_DEBUG(log("send keying encoding") + ZS_PARAM("passphrase", passphrase))

        AutoRecursiveLock lock(getLock());

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }

        ZS_THROW_INVALID_USAGE_IF(mSendingEncodingRemotePublicKey)

        if (mSendingEncodingPassphrase.hasData()) {
          ZS_THROW_INVALID_ARGUMENT_IF(passphrase != mSendingEncodingPassphrase)
        }

        if (mSendingEncodingPassphrase.isEmpty()) {
          mSendingEncodingPassphrase = String(passphrase);
        }

        setState(SessionState_Pending);

        IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::getSendKeyingMaterialNeedingToBeSigned(
                                                                               DocumentPtr &outDocumentContainedElementToSign,
                                                                               ElementPtr &outElementToSign
                                                                               ) const
      {
        AutoRecursiveLock lock(getLock());

        if ((!mSendKeyingNeedingToSignDoc) ||
            (!mSendKeyingNeedToSignEl)) {
          ZS_LOG_WARNING(Detail, log("no keying material available needing to be signed"))
          return;
        }

        outDocumentContainedElementToSign = mSendKeyingNeedingToSignDoc;
        outElementToSign = mSendKeyingNeedToSignEl;
      }

      //-----------------------------------------------------------------------
      void MessageLayerSecurityChannel::notifySendKeyingMaterialSigned()
      {
        AutoRecursiveLock lock(getLock());

        if (isShutdown()) {
          ZS_LOG_WARNING(Detail, log("already shutdown"))
          return;
        }

        ZS_LOG_TRACE(log("send keying material signed"))

        // by clearing out the receive key needing to be signed (but leaving the paired doc), it signals the "step" that the signing process was complete
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
        AutoRecursiveLock lock(getLock());
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
        AutoRecursiveLock lock(getLock());
        ZS_LOG_DEBUG(log("transport stream writer ready"))

        if (writer == mReceiveStreamDecoded) {
          get(mReceiveStreamDecodedWriteReady) = true;

          // event typically fires when "outer" notifies it's ready to send data thus need to inform the wire that it can send data now
          mReceiveStreamEncoded->notifyReaderReadyToRead();
        }
        if (writer == mSendStreamEncoded) {
          get(mSendStreamEncodedWriteReady) = true;
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
        AutoRecursiveLock lock(getLock());
        ZS_LOG_DEBUG(log("on wake"))
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
      RecursiveLock &MessageLayerSecurityChannel::getLock() const
      {
        return mLock;
      }

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
        AutoRecursiveLock lock(getLock());

        ElementPtr resultEl = Element::create("MessageLayerSecurityChannel");

        IHelper::debugAppend(resultEl, "id", mID);

        IHelper::debugAppend(resultEl, "subscriptions", mSubscriptions.size());
        IHelper::debugAppend(resultEl, "default subscription", (bool)mDefaultSubscription);

        IHelper::debugAppend(resultEl, "state", IMessageLayerSecurityChannel::toString(mCurrentState));

        IHelper::debugAppend(resultEl, "last error", mLastError);
        IHelper::debugAppend(resultEl, "last reason", mLastErrorReason);

        IHelper::debugAppend(resultEl, "local context ID", mLocalContextID);
        IHelper::debugAppend(resultEl, "remote context ID", mRemoteContextID);

        IHelper::debugAppend(resultEl, "sending remote public key", (bool)mSendingEncodingRemotePublicKey);
        IHelper::debugAppend(resultEl, "sending passphrase", mSendingEncodingPassphrase);

        IHelper::debugAppend(resultEl, "local DH private key", mDHLocalPrivateKey ? mDHLocalPrivateKey->getID() : 0);
        IHelper::debugAppend(resultEl, "local DH public key", mDHLocalPublicKey ? mDHLocalPublicKey->getID() : 0);

        IHelper::debugAppend(resultEl, "remote DH key domain", mDHRemoteKeyDomain ? mDHRemoteKeyDomain->getID() : 0);
        IHelper::debugAppend(resultEl, "remote DH public key", mDHRemotePublicKey ? mDHRemotePublicKey->getID() : 0);
        IHelper::debugAppend(resultEl, "DH encoding include full public key", mDHEncodingFullLocalPublicKey ? mDHEncodingFullLocalPublicKey->getID() : 0);

        IHelper::debugAppend(resultEl, "sending keying needs sign doc", (bool)mSendKeyingNeedingToSignDoc);
        IHelper::debugAppend(resultEl, "sending keying needs sign element", (bool)mSendKeyingNeedToSignEl);

        IHelper::debugAppend(resultEl, "receive seq number", string(mNextReceiveSequenceNumber));

        IHelper::debugAppend(resultEl, "decoding type", toString(mReceiveDecodingType));
        IHelper::debugAppend(resultEl, "decoding public key fingerprint", mReceiveDecodingPublicKeyFingerprint);
        IHelper::debugAppend(resultEl, "receive decoding private key", (bool)mReceiveDecodingPrivateKey);
        IHelper::debugAppend(resultEl, "receive decoding public key", (bool)mReceiveDecodingPublicKey);
        IHelper::debugAppend(resultEl, "receive decoding passphrase", mReceivingDecodingPassphrase);

        IHelper::debugAppend(resultEl, "receive signing public key", (bool)mReceiveSigningPublicKey);
        IHelper::debugAppend(resultEl, "receive keying signed doc", (bool)mReceiveKeyingSignedDoc);
        IHelper::debugAppend(resultEl, "receive keying signed element", (bool)mReceiveKeyingSignedEl);

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

        IHelper::debugAppend(resultEl, "receive keys", mReceiveKeys.size());
        IHelper::debugAppend(resultEl, "send keys", mSendKeys.size());

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

            switch(mReceiveDecodingType) {
              case DecodingType_Unknown:    break;
              case DecodingType_PrivateKey: hasReceiveInformation = hasReceiveInformation && (mReceiveDecodingPrivateKey); break;
              case DecodingType_Agreement:  hasReceiveInformation = hasReceiveInformation && ((bool)mDHLocalPrivateKey) && ((bool)mDHLocalPublicKey); break;
              case DecodingType_Passphrase: hasReceiveInformation = hasReceiveInformation && (mReceivingDecodingPassphrase.hasData()); break;
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

            ZS_LOG_INSANE(log("decrypting key to use") + keyInfo.toDebug(algorithm))

            size_t integritySize = IHelper::getHashDigestSize(IHelper::HashAlgorthm_SHA1);

            // must be greater in size than the hash algorithm
            if (remaining <= integritySize) {
              ZS_LOG_ERROR(Detail, log("algorithm bytes missing in protocol") + ZS_PARAM("size", streamBuffer->SizeInBytes()))
              setError(IHTTP::HTTPStatusCode_Unauthorized, "buffer is not decodable");
              cancel();
              return false;
            }


            SecureByteBlockPtr integrity(new SecureByteBlock(integritySize));
            memcpy(integrity->BytePtr(), source, integritySize);

            source += integritySize;
            remaining -= integritySize;

            SecureByteBlock input(remaining);
            memcpy(input.BytePtr(), source, remaining);

            SecureByteBlockPtr output = IHelper::decrypt(*(keyInfo.mSendKey), *(keyInfo.mNextIV), input);

            String hashDecryptedBuffer = IHelper::convertToHex(*IHelper::hash(*output));

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

            SecureByteBlockPtr calculatedIntegrity = IHelper::hmac(*(IHelper::convertToBuffer(keyInfo.mIntegrityPassphrase)), ("integrity:" + IHelper::convertToHex(*IHelper::hash(*output)) + ":" + hexIV).c_str());

            if (ZS_IS_LOGGING(Debug)) {
              String hashEncryptedBuffer = IHelper::convertToHex(*IHelper::hash(input));
              ZS_LOG_DEBUG(log("received data from wire") + ZS_PARAM("keying index", algorithm) + ZS_PARAM("buffer size", streamBuffer->SizeInBytes()) + ZS_PARAM("encrypted size", input.SizeInBytes()) + ZS_PARAM("decrypted size", output->SizeInBytes()) + ZS_PARAM("key", IHelper::convertToHex(*(keyInfo.mSendKey))) + ZS_PARAM("iv", hexIV) + ZS_PARAM("calculated integrity", IHelper::convertToHex(*calculatedIntegrity)) + ZS_PARAM("received integrity", IHelper::convertToHex(*integrity)) + ZS_PARAM("integrity passphrase", keyInfo.mIntegrityPassphrase) + ZS_PARAM("decrypted data hash", hashDecryptedBuffer) + ZS_PARAM("encrypted data hash", hashEncryptedBuffer))
            }

            if (0 != IHelper::compare(*calculatedIntegrity, *integrity)) {
              ZS_LOG_ERROR(Debug,log("integrity failed on packet"))
              setError(IHTTP::HTTPStatusCode_Unauthorized, "buffer is not decodable");
              cancel();
              return false;
            }

            // calculate the next IV and remember the integrity field
            keyInfo.mNextIV = IHelper::hash(hexIV + ":" + IHelper::convertToHex(*calculatedIntegrity));
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
              mReceiveDecodingType = DecodingType_PrivateKey;
              String encodingFingerprint = getElementTextAndDecode(encodingEl->findFirstChildElementChecked("fingerprint"));

              if (!mReceiveDecodingPublicKeyFingerprint.hasData()) {
                mReceiveDecodingPublicKeyFingerprint = encodingFingerprint;
              }

              if (!mReceiveDecodingPrivateKey) {
                ZS_LOG_DEBUG(log("waiting for receive PKI keying materials"))
                goto receive_waiting_for_information;
              }

              ZS_THROW_BAD_STATE_IF(!mReceiveDecodingPublicKey)

              String expectingFingerprint = mReceiveDecodingPublicKey->getFingerprint();
              if (encodingFingerprint != expectingFingerprint) {
                ZS_LOG_ERROR(Detail, log("encoding not using local public key") + ZS_PARAM("encoding fingerprint", encodingFingerprint) + ZS_PARAM("expecting fingerprint", expectingFingerprint))
                setError(IHTTP::HTTPStatusCode_CertError, "encoding not using local public key");
                goto receive_error_out;
              }
            } else if ("agreement" == type) {
              mReceiveDecodingType = DecodingType_Agreement;

              String encodingFingerprint = getElementTextAndDecode(encodingEl->findFirstChildElementChecked("fingerprint"));

              if (!mReceiveDecodingPublicKeyFingerprint.hasData()) {
                mReceiveDecodingPublicKeyFingerprint = encodingFingerprint;
              }

              if ((!mDHLocalPrivateKey) ||
                  (!mDHLocalPublicKey)) {
                ZS_LOG_TRACE(log("waiting for receive DH keying materials"))
                goto receive_waiting_for_information;
              }

              String remoteKey = getElementTextAndDecode(encodingEl->findFirstChildElement("key"));
              if (remoteKey.hasData()) {
                SplitMap splits;

                String namespaceStr;

                IHelper::split(remoteKey, splits, ':');
                if (splits.size() >= 1) {
                  namespaceStr = IHelper::convertToString(*IHelper::convertFromBase64((*(splits.find(0))).second));

                  mDHRemoteKeyDomain = IDHKeyDomain::loadPrecompiled(IDHKeyDomain::fromNamespace(namespaceStr));
                  if (!mDHRemoteKeyDomain) {
                    ZS_LOG_ERROR(Detail, log("encoding key domain namespace is not known") + ZS_PARAM("namespace", namespaceStr))
                    setError(IHTTP::HTTPStatusCode_PreconditionFailed, "encoding domain namespace is not known");
                    goto receive_error_out;
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

              String expectingFingerprint = mDHLocalPublicKey->getFingerprint();
              if (encodingFingerprint != expectingFingerprint) {
                ZS_LOG_ERROR(Detail, log("encoding not using local public key") + ZS_PARAM("encoding fingerprint", encodingFingerprint) + ZS_PARAM("expecting fingerprint", expectingFingerprint) + IDHPublicKey::toDebug(mDHLocalPublicKey))
                setError(IHTTP::HTTPStatusCode_RequestTimeout, "signed keying bundle has expired");
                goto receive_error_out;
              }

              SecureByteBlockPtr agreedKey = mDHLocalPrivateKey->getSharedSecret(mDHRemotePublicKey);
              if (!IHelper::hasData(agreedKey)) {
                ZS_LOG_ERROR(Detail, log("could not agree upon a shared secret") + ZS_PARAM("remote public key", IDHPublicKey::toDebug(mDHRemotePublicKey)) + ZS_PARAM("local public key", IDHPublicKey::toDebug(mDHLocalPublicKey)) + ZS_PARAM("local private key", IDHPrivateKey::toDebug(mDHLocalPrivateKey)))
                setError(IHTTP::HTTPStatusCode_CertError, "remote public key is not valid");
                goto receive_error_out;
              }

              decodingPassphrase = IHelper::convertToHex(*agreedKey);
            } else if ("passphrase" == type) {
              mReceiveDecodingType = DecodingType_Passphrase;

              if (mReceivingDecodingPassphrase.isEmpty()) {
                ZS_LOG_DEBUG(log("cannot continue decoding as missing decoding passphrase (will notify delegate)"))
                goto receive_waiting_for_information;
              }

              // scope: we have a passphrase, see if the proof validates before attempting to decrypt any keys...
              {
                String algorithm = getElementTextAndDecode(encodingEl->findFirstChildElementChecked("algorithm"));
                if (OPENPEER_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_CRYPTO_ALGORITHM != algorithm) {
                  ZS_LOG_ERROR(Detail, log("keying encoding not using known algorithm") + ZS_PARAM("algorithm", algorithm) + ZS_PARAM("expecting", OPENPEER_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_CRYPTO_ALGORITHM))
                  setError(IHTTP::HTTPStatusCode_ExpectationFailed, "keyhing encoding not using expecting passphrase");
                  goto receive_error_out;
                }

                String proof = getElementTextAndDecode(encodingEl->findFirstChildElementChecked("proof"));

                // hex(hmac(`<external-passphrase>`, "keying:" + `<nonce>`))
                String calculatedProof = IHelper::convertToHex(*IHelper::hmac(*IHelper::hmacKeyFromPassphrase(mReceivingDecodingPassphrase), "keying:" + nonce));

                if (proof != calculatedProof) {
                  ZS_LOG_ERROR(Detail, log("keying encoding not using expecting passphrase") + ZS_PARAM("encoding proof", proof) + ZS_PARAM("expecting proof", calculatedProof) + ZS_PARAM("using passphrase", mReceivingDecodingPassphrase))
                  setError(IHTTP::HTTPStatusCode_ExpectationFailed, "keyhing encoding not using expecting passphrase");
                  goto receive_error_out;
                }
              }

              decodingPassphrase = mReceivingDecodingPassphrase;
            }

            // scope: check if nonce seen before
            {
              String hashNonce = IHelper::convertToHex(*IHelper::hash(nonce));
              String nonceNamespace = OPENPEER_SERVICES_MLS_COOKIE_NONCE_CACHE_NAMESPACE + hashNonce;

              String result = ICache::singleton()->fetch(nonceNamespace);
              if (result.hasData()) {
                ZS_LOG_ERROR(Detail, log("keying encoding seen previously") + ZS_PARAM("nonce", nonce) + ZS_PARAM("nonce namespace", nonceNamespace))
                setError(IHTTP::HTTPStatusCode_Forbidden, "keyhing encoding information was seen previously");
                goto receive_error_out;
              }

              ICache::singleton()->store(nonceNamespace, expires, "1");
            }

            // scope: santity check on algorithms receiving
            {
              bool found = false;
              ElementPtr algorithmEl = keyingEl->findFirstChildElementChecked("algorithms")->findFirstChildElementChecked("algorithm");
              while (algorithmEl) {
                String algorithm = getElementTextAndDecode(algorithmEl);
                if (OPENPEER_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_CRYPTO_ALGORITHM == algorithm) {
                  ZS_LOG_TRACE(log("found mandated algorithm"))
                  found = true;
                  break;
                }
                algorithmEl->findNextSiblingElement("algorithm");
              }
              if (!found) {
                ZS_LOG_ERROR(Detail, log("did not find mandated MLS algorithm") + ZS_PARAM("expecting", OPENPEER_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_CRYPTO_ALGORITHM))
                goto receive_error_out;
              }
            }

            // scope: extract out latest keying material
            {
              ElementPtr keyEl = keyingEl->findFirstChildElementChecked("keys")->findFirstChildElementChecked("key");
              while (keyEl) {
                // scope: decode key
                {
                  AlgorithmIndex index = 0;
                  try {
                    index = Numeric<AlgorithmIndex>(getElementTextAndDecode(keyEl->findFirstChildElementChecked("index")));
                  } catch(Numeric<AlgorithmIndex>::ValueOutOfRange &) {
                    ZS_LOG_WARNING(Detail, log("algorithm index value out of range"))
                  }

                  if (0 == index) {
                    ZS_LOG_WARNING(Detail, log("algorithm index value is not valid") + ZS_PARAM("index", index))
                    goto next_key;
                  }

                  String algorithm = getElementTextAndDecode(keyEl->findFirstChildElementChecked("algorithm"));
                  if (OPENPEER_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_CRYPTO_ALGORITHM != algorithm) {
                    ZS_LOG_WARNING(Detail, log("unsupported algorithm (thus skipping)") + ZS_PARAM("algorithm", algorithm))
                    goto next_key;
                  }

                  ElementPtr inputs = keyEl->findFirstChildElementChecked("inputs");

                  KeyInfo key;
                  SecureByteBlockPtr integrityPassphrase;
                  if (DecodingType_PrivateKey == mReceiveDecodingType) {
                    // base64(rsa_encrypt(`<remote-public-key>`, `<value>`))
                    key.mSendKey = mReceiveDecodingPrivateKey->decrypt(*IHelper::convertFromBase64(getElementTextAndDecode(inputs->findFirstChildElementChecked("secret"))));
                    key.mNextIV = mReceiveDecodingPrivateKey->decrypt(*IHelper::convertFromBase64(getElementTextAndDecode(inputs->findFirstChildElementChecked("iv"))));
                    integrityPassphrase = mReceiveDecodingPrivateKey->decrypt(*IHelper::convertFromBase64(getElementTextAndDecode(inputs->findFirstChildElementChecked("hmacIntegrityKey"))));
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

          if (mReceiveKeys.size() < 1) {
            ZS_LOG_ERROR(Detail, log("did not find any key information"))
            setError(IHTTP::HTTPStatusCode_ExpectationFailed, "did not find any key information");
            goto receive_error_out;
          }

          ZS_LOG_DEBUG(log("successfully extracted keying materials to receive data from remote MLS stream"))
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
          get(mNotifySendStreamDecodedReadyToReady) = true;
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
          boost::shared_array<char> output = generator->write(mSendKeyingNeedingToSignDoc, &outputLength);

          SecureByteBlockPtr buffer(new SecureByteBlock(sizeof(DWORD) + (outputLength * sizeof(char))));

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

        if (mSendKeys.size() > 0) {
          ZS_LOG_TRACE(log("already sent keying materials"))
          return true;
        }

        // create initial encryption offer (hint: it won't change)

        ElementPtr keyingBundleEl = Element::create("keyingBundle");

        ElementPtr keyingEl = Element::create("keying");
        
        keyingEl->adoptAsLastChild(createElementWithNumber("sequence", "0"));

        String nonce = IHelper::randomString(32);

        keyingEl->adoptAsLastChild(createElementWithText("nonce", nonce));
        keyingEl->adoptAsLastChild(createElementWithText("context", mLocalContextID));

        Time expires = zsLib::now() + Seconds(OPENPEER_SERVICES_MLS_DEFAULT_KEYING_EXPIRES_TIME_IN_SECONDS);

        keyingEl->adoptAsLastChild(createElementWithNumber("expires", IHelper::timeToString(expires)));

        ElementPtr encodingEl = Element::create("encoding");
        keyingEl->adoptAsLastChild(encodingEl);

        String encodingPassphrase;

        if (mSendingEncodingPassphrase.hasData()) {
          encodingEl->adoptAsLastChild(createElementWithText("type", "passphrase"));
          encodingEl->adoptAsLastChild(createElementWithText("algorithm", OPENPEER_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_CRYPTO_ALGORITHM));

          String calculatedProof = IHelper::convertToHex(*IHelper::hmac(*IHelper::hmacKeyFromPassphrase(mSendingEncodingPassphrase), "keying:" + nonce));

          encodingEl->adoptAsLastChild(createElementWithText("proof", calculatedProof));

          encodingPassphrase = mSendingEncodingPassphrase;
        } else if (mDHRemotePublicKey) {
          ZS_THROW_INVALID_ASSUMPTION_IF(!mDHLocalPrivateKey)
          ZS_THROW_INVALID_ASSUMPTION_IF(!mDHRemotePublicKey)
          encodingEl->adoptAsLastChild(createElementWithText("type", "agreement"));
          encodingEl->adoptAsLastChild(createElementWithText("fingerprint", mDHRemotePublicKey->getFingerprint()));
          if (mDHEncodingFullLocalPublicKey) {
            IDHKeyDomainPtr keyDomain = mDHLocalPrivateKey->getKeyDomain();
            ZS_THROW_INVALID_ASSUMPTION_IF(!keyDomain)

            SecureByteBlock staticPublicKey;
            SecureByteBlock ephemeralPublicKey;

            mDHEncodingFullLocalPublicKey->save(&staticPublicKey, &ephemeralPublicKey);

            String fullKey = IHelper::convertToBase64(*IHelper::convertToBuffer(IDHKeyDomain::toNamespace(keyDomain->getPrecompiledType()))) +
                             ":" + IHelper::convertToBase64(staticPublicKey) +
                             ":" + IHelper::convertToBase64(ephemeralPublicKey);

            encodingEl->adoptAsLastChild(createElementWithText("key", fullKey));
          }

          SecureByteBlockPtr agreement = mDHLocalPrivateKey->getSharedSecret(mDHRemotePublicKey);
          if (!agreement) {
            ZS_LOG_ERROR(Detail, log("failed to agree upon a key for encoding"))
            setError(IHTTP::HTTPStatusCode_PreconditionFailed, "failed to agree upon a key for encoding");
            cancel();
            return false;
          }

          encodingPassphrase = IHelper::convertToHex(*agreement);
        } else {
          ZS_THROW_INVALID_ASSUMPTION_IF(!mSendingEncodingRemotePublicKey)
          encodingEl->adoptAsLastChild(createElementWithText("type", "pki"));
          encodingEl->adoptAsLastChild(createElementWithText("fingerprint", mSendingEncodingRemotePublicKey->getFingerprint()));
        }

        ElementPtr algorithmsEl = Element::create("algorithms");
        algorithmsEl->adoptAsLastChild(createElementWithText("algorithm", OPENPEER_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_CRYPTO_ALGORITHM));

        ElementPtr keysEl = Element::create("keys");

        for (AlgorithmIndex index = 1; index <= OPENPEER_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_TOTAL_SEND_KEYS; ++index) {
          KeyInfo key;

          key.mIntegrityPassphrase = IHelper::randomString((20*8/5));
          key.mSendKey = IHelper::hash(*IHelper::random(32), IHelper::HashAlgorthm_SHA256);
          key.mNextIV = IHelper::hash(*IHelper::random(16), IHelper::HashAlgorthm_MD5);

          ElementPtr keyEl = Element::create("key");
          keyEl->adoptAsLastChild(createElementWithNumber("index", string(index)));
          keyEl->adoptAsLastChild(createElementWithText("algorithm", OPENPEER_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_CRYPTO_ALGORITHM));

          ElementPtr inputsEl = Element::create("inputs");
          if (encodingPassphrase.hasData()) {
            inputsEl->adoptAsLastChild(createElementWithText("secret", encodeUsingPassphraseEncoding(encodingPassphrase, nonce, *key.mSendKey)));
            inputsEl->adoptAsLastChild(createElementWithText("iv", encodeUsingPassphraseEncoding(encodingPassphrase, nonce, *key.mNextIV)));
            inputsEl->adoptAsLastChild(createElementWithText("hmacIntegrityKey", encodeUsingPassphraseEncoding(encodingPassphrase, nonce, *IHelper::convertToBuffer(key.mIntegrityPassphrase))));
          } else {
            ZS_THROW_INVALID_ASSUMPTION_IF(!mSendingEncodingRemotePublicKey)
            inputsEl->adoptAsLastChild(createElementWithText("secret", IHelper::convertToBase64(*mSendingEncodingRemotePublicKey->encrypt(*key.mSendKey))));
            inputsEl->adoptAsLastChild(createElementWithText("iv", IHelper::convertToBase64(*mSendingEncodingRemotePublicKey->encrypt(*key.mNextIV))));
            inputsEl->adoptAsLastChild(createElementWithText("hmacIntegrityKey", IHelper::convertToBase64(*mSendingEncodingRemotePublicKey->encrypt(*IHelper::convertToBuffer(key.mIntegrityPassphrase)))));
          }

          ZS_LOG_DEBUG(log("send algorithm keying information") + key.toDebug(index))

          keyEl->adoptAsLastChild(inputsEl);

          keysEl->adoptAsLastChild(keyEl);

          mSendKeys[index] = key;
        }

        keyingEl->adoptAsLastChild(algorithmsEl);
        keyingEl->adoptAsLastChild(keysEl);
        keyingBundleEl->adoptAsLastChild(keyingEl);

        mSendKeyingNeedingToSignDoc = Document::create();
        mSendKeyingNeedingToSignDoc->adoptAsLastChild(keyingBundleEl);
        mSendKeyingNeedToSignEl = keyingEl;

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
          AlgorithmIndex index = IHelper::random(1, mSendKeys.size());

          KeyMap::iterator found = mSendKeys.find(index);
          ZS_THROW_BAD_STATE_IF(found == mSendKeys.end())

          KeyInfo &keyInfo = (*found).second;

          ZS_LOG_INSANE(log("encrypting key to use") + keyInfo.toDebug(index))

          SecureByteBlockPtr encrypted = IHelper::encrypt(*(keyInfo.mSendKey), *(keyInfo.mNextIV), *buffer);

          String hexIV = IHelper::convertToHex(*keyInfo.mNextIV);

          String hashDecryptedBuffer = IHelper::convertToHex(*IHelper::hash(*buffer));

          SecureByteBlockPtr calculatedIntegrity = IHelper::hmac(*(IHelper::convertToBuffer(keyInfo.mIntegrityPassphrase)), ("integrity:" + hashDecryptedBuffer + ":" + hexIV).c_str());

          // calculate the next IV and remember the integrity field
          keyInfo.mNextIV = IHelper::hash(hexIV + ":" + IHelper::convertToHex(*calculatedIntegrity));
          keyInfo.mLastIntegrity = calculatedIntegrity;

          SecureByteBlockPtr output(new SecureByteBlock(sizeof(DWORD) + calculatedIntegrity->SizeInBytes() + encrypted->SizeInBytes()));

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
            String hashEncryptedBuffer = IHelper::convertToHex(*IHelper::hash(*encrypted));
            ZS_LOG_DEBUG(log("sending data on wire") + ZS_PARAM("keying index", index) + ZS_PARAM("buffer size", output->SizeInBytes()) + ZS_PARAM("decrypted size", buffer->SizeInBytes()) + ZS_PARAM("encrypted size", encrypted->SizeInBytes()) + ZS_PARAM("key", IHelper::convertToHex(*(keyInfo.mSendKey))) + ZS_PARAM("iv", hexIV) + ZS_PARAM("integrity", IHelper::convertToHex(*calculatedIntegrity)) + ZS_PARAM("integrity passphrase", keyInfo.mIntegrityPassphrase) + ZS_PARAM("decrypted data hash", hashDecryptedBuffer) + ZS_PARAM("encrypted data hash", hashEncryptedBuffer))
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
        AutoRecursiveLock lock(getLock());

        if (!mSendStreamEncodedWriteReady) {
          ZS_LOG_DEBUG(log("cannot send encoded stream until lower layer transport (typically 'wire' transport) indicates it is ready to send data"))
          return false;
        }

        if (mLocalContextID.isEmpty()) {
          ZS_LOG_TRACE(log("missing local context ID thus cannot send data remotely"))
          return false;
        }

        if ((!mSendingEncodingRemotePublicKey) &&
            (!mDHRemotePublicKey) &&
            (mSendingEncodingPassphrase.isEmpty())) {
          ZS_LOG_TRACE(log("send keying material is not ready"))
          return false;
        }

        if (mDHRemotePublicKey) {
          if (!mDHLocalPrivateKey) {
            ZS_LOG_TRACE(log("send DH keying material is not ready"))
            return false;
          }
        }

        if (mSendKeyingNeedingToSignDoc) {
          if (mSendKeyingNeedToSignEl) {
            ZS_LOG_TRACE(log("send signature not created"))
            return false;
          }
        }

        ZS_LOG_TRACE(log("sending is ready"))
        return true;
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
