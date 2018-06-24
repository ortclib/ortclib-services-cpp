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

#include <ortc/services/IMessageLayerSecurityChannel.h>
#include <ortc/services/internal/types.h>

#include <ortc/services/ITransportStream.h>

#include <zsLib/ITimer.h>
#include <zsLib/IWakeDelegate.h>

#include <list>
#include <map>

#define ORTC_SERVICES_MESSAGE_LAYER_SECURITY_SIGNATURE_ALGORITHM "https://meta.ortclib.org/2012/12/14/jsonsig#rsa-sha1"

#define ORTC_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_CRYPTO_ALGORITHM "https://meta.ortclib.org/2012/12/14/jsonmls#aes-cfb-32-16-16-sha1-md5"

#define ORTC_SERVICES_SETTING_MESSAGE_LAYER_SECURITY_CHANGE_SENDING_KEY_AFTER "ortc/services/mls-change-sending-key-after-in-seconds"

namespace ortc
{
  namespace services
  {
    namespace internal
    {
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // MessageLayerSecurityChannel
      //

      class MessageLayerSecurityChannel : public Noop,
                                          public zsLib::MessageQueueAssociator,
                                          public SharedRecursiveLock,
                                          public IMessageLayerSecurityChannel,
                                          public IWakeDelegate,
                                          public zsLib::ITimerDelegate,
                                          public ITransportStreamReaderDelegate,
                                          public ITransportStreamWriterDelegate
      {
      protected:
        struct make_private {};

      public:
        friend interaction IMessageLayerSecurityChannelFactory;
        friend interaction IMessageLayerSecurityChannel;

        typedef ITransportStream::StreamHeaderPtr StreamHeaderPtr;
        typedef std::list<SecureByteBlockPtr> BufferList;

        typedef ULONG AlgorithmIndex;

        struct KeyInfo
        {
          String mIntegrityPassphrase;

          SecureByteBlockPtr mSendKey;
          SecureByteBlockPtr mNextIV;
          SecureByteBlockPtr mLastIntegrity;

          ElementPtr toDebug(AlgorithmIndex index) const noexcept;
        };
        
        typedef std::map<AlgorithmIndex, KeyInfo> KeyMap;
        typedef std::pair<IDHPrivateKeyPtr, IDHPublicKeyPtr> DHPrivatePublicKeyPair;

        typedef std::list<DHPrivatePublicKeyPair> DHKeyList;

      public:
        MessageLayerSecurityChannel(
                                    const make_private &,
                                    IMessageQueuePtr queue,
                                    IMessageLayerSecurityChannelDelegatePtr delegate,
                                    ITransportStreamPtr receiveStreamEncoded,
                                    ITransportStreamPtr receiveStreamDecoded,
                                    ITransportStreamPtr sendStreamDecoded,
                                    ITransportStreamPtr sendStreamEncoded,
                                    const char *contextID = NULL
                                    ) noexcept;

      protected:
        MessageLayerSecurityChannel(Noop) noexcept :
          Noop(true),
          zsLib::MessageQueueAssociator(IMessageQueuePtr()),
          SharedRecursiveLock(SharedRecursiveLock::create()) {}

        void init() noexcept;

      public:
        ~MessageLayerSecurityChannel() noexcept;

        static MessageLayerSecurityChannelPtr convert(IMessageLayerSecurityChannelPtr channel) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // MessageLayerSecurityChannel => IMessageLayerSecurityChannel
        //

        static ElementPtr toDebug(IMessageLayerSecurityChannelPtr channel) noexcept;

        static MessageLayerSecurityChannelPtr create(
                                                     IMessageLayerSecurityChannelDelegatePtr delegate,
                                                     ITransportStreamPtr receiveStreamEncoded,
                                                     ITransportStreamPtr receiveStreamDecoded,
                                                     ITransportStreamPtr sendStreamDecoded,
                                                     ITransportStreamPtr sendStreamEncoded,
                                                     const char *contextID = NULL
                                                     ) noexcept;

        IMessageLayerSecurityChannelSubscriptionPtr subscribe(IMessageLayerSecurityChannelDelegatePtr delegate) noexcept override;

        PUID getID() const noexcept override {return mID;}

        void cancel() noexcept override;

        SessionStates getState(
                               WORD *outLastErrorCode = NULL,
                               String *outLastErrorReason = NULL
                               ) const noexcept override;

        bool needsLocalContextID() const noexcept override;
        bool needsReceiveKeying(KeyingTypes *outDecodingType = NULL) const noexcept override;
        bool needsSendKeying(KeyingTypes *outEncodingType = NULL) const noexcept override;
        bool needsReceiveKeyingSigningPublicKey() const noexcept override;
        bool needsSendKeyingToeBeSigned() const noexcept override;

        String getLocalContextID() const noexcept override;
        String getRemoteContextID() const noexcept override;
        void setLocalContextID(const char *contextID) noexcept override;

        void setReceiveKeying(const char *passphrase) noexcept override;
        void setSendKeying(const char *passphrase) noexcept override;

        String getReceivePublicKeyFingerprint() const noexcept override;
        void setReceiveKeying(
                              IRSAPrivateKeyPtr localPrivateKey,
                              IRSAPublicKeyPtr localPublicKey
                              ) noexcept override;
        void setSendKeying(IRSAPublicKeyPtr remotePublicKey) noexcept override;

        IDHKeyDomainPtr getKeyAgreementDomain() const noexcept override;
        String getRemoteKeyAgreementFingerprint() const noexcept override;
        void setLocalKeyAgreement(
                                  IDHPrivateKeyPtr localPrivateKey,
                                  IDHPublicKeyPtr localPublicKey,
                                  bool remoteSideAlreadyKnowsThisPublicKey
                                  ) noexcept override;
        void setRemoteKeyAgreement(IDHPublicKeyPtr remotePublicKey) noexcept override;
        IDHPublicKeyPtr getOriginalRemoteKeyAgreement() noexcept override;

        ElementPtr getSignedReceiveKeying() const noexcept override;
        void setReceiveKeyingSigningPublicKey(IRSAPublicKeyPtr remotePublicKey) noexcept override;

        void getSendKeyingNeedingToBeSigned(
                                            DocumentPtr &outDocumentContainedElementToSign,
                                            ElementPtr &outElementToSign
                                            ) const noexcept override;
        void notifySendKeyingSigned(
                                    IRSAPrivateKeyPtr signingKey,
                                    IRSAPublicKeyPtr signingPublicKey
                                    ) noexcept override;

        //---------------------------------------------------------------------
        //
        // MessageLayerSecurityChannel => ITransportStreamReaderDelegate
        //

        void onTransportStreamReaderReady(ITransportStreamReaderPtr reader) override;

        //---------------------------------------------------------------------
        //
        // MessageLayerSecurityChannel => ITransportStreamWriterDelegate
        //

        void onTransportStreamWriterReady(ITransportStreamWriterPtr writer) override;

        //---------------------------------------------------------------------
        //
        // MessageLayerSecurityChannel => IWakeDelegate
        //

        void onWake() override;

        //---------------------------------------------------------------------
        //
        // MessageLayerSecurityChannel => ITimerDelegate
        //

        void onTimer(ITimerPtr timer) override;

      protected:
        //---------------------------------------------------------------------
        //
        // MessageLayerSecurityChannel => (internal)
        //

        bool isShutdown() const noexcept {return SessionState_Shutdown == mCurrentState;}

        Log::Params log(const char *message) const noexcept;
        Log::Params debug(const char *message) const noexcept;

        virtual ElementPtr toDebug() const noexcept;

        void setState(SessionStates state) noexcept;
        void setError(WORD errorCode, const char *inReason = NULL) noexcept;

        void step() noexcept;
        bool stepReceive() noexcept;
        bool stepSendKeying() noexcept;
        bool stepSend() noexcept;
        bool stepCheckConnected() noexcept;

        bool stepProcessReceiveKeying(
                                      bool &outReturnResult,
                                      SecureByteBlockPtr keying = SecureByteBlockPtr()
                                      ) noexcept;

        bool isSendingReady() const noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // MessageLayerSecurityChannel => (data)
        //

        MessageLayerSecurityChannelWeakPtr mThisWeak;

        AutoPUID mID;

        IMessageLayerSecurityChannelDelegateSubscriptions mSubscriptions;
        IMessageLayerSecurityChannelSubscriptionPtr mDefaultSubscription;

        SessionStates mCurrentState;

        WORD mLastError {};
        String mLastErrorReason;

        String mLocalContextID;
        String mRemoteContextID;

        // types of keying in use
        KeyingTypes mReceiveKeyingType;
        KeyingTypes mSendKeyingType;

        // passphrase based receiving/sending
        String mReceivePassphrase;
        String mSendPassphrase;

        // diffie hellman based receiving/sending
        IDHKeyDomainPtr mDHKeyDomain;

        IDHPrivateKeyPtr mDHLocalPrivateKey;
        IDHPublicKeyPtr mDHLocalPublicKey;
        bool mDHRemoteSideKnowsLocalPublicKey {};
        bool mDHSentRemoteSideLocalPublicKey {};    // used before remote keying material is obtained to determine if the local public key was sent to the remote party

        IDHPublicKeyPtr mDHRemotePublicKey;
        IDHPublicKeyPtr mDHOriginalRemotePublicKey;
        String mDHRemotePublicKeyFingerprint;

        DHKeyList mDHPreviousLocalKeys;             // keep around the previous keying material during a key changes (until a received keying refers to the latest DH keying material)

        // RSA based keying
        IRSAPrivateKeyPtr mReceiveLocalPrivateKey;
        IRSAPublicKeyPtr mReceiveLocalPublicKey;
        String mReceiveLocalPublicKeyFingerprint;

        IRSAPublicKeyPtr mSendRemotePublicKey;

        // signing
        IRSAPublicKeyPtr mReceiveSigningPublicKey;
        DocumentPtr mReceiveKeyingSignedDoc;        // temporary document needed to resolve receive signing public key
        ElementPtr mReceiveKeyingSignedEl;          // temporary eleemnt needed to resolve receive signing public key

        IRSAPrivateKeyPtr mSendSigningPrivateKey;
        IRSAPublicKeyPtr mSendSigningPublicKey;
        DocumentPtr mSendKeyingNeedingToSignDoc;    // temporary document containing the send keying material needing to be signed
        ElementPtr mSendKeyingNeedToSignEl;         // temporary element containing the send keying material needing to be signed (once notified it is signed, this element get set to EleemntPtr())


        ULONG mNextReceiveSequenceNumber;
        ULONG mNextSendSequenceNumber;

        ITransportStreamReaderPtr mReceiveStreamEncoded;  // typically connected to incoming on-the-wire transport
        ITransportStreamWriterPtr mReceiveStreamDecoded;  // typically connected to "outer" layer for "outer" to receive decoded on-the-wire data
        ITransportStreamReaderPtr mSendStreamDecoded;     // typically connected to "outer" layer for "outer" to send and encode data on-on-the-wire
        ITransportStreamWriterPtr mSendStreamEncoded;     // typically connected to outgoing on-the-wire transport

        ITransportStreamReaderSubscriptionPtr mReceiveStreamEncodedSubscription;
        ITransportStreamWriterSubscriptionPtr mReceiveStreamDecodedSubscription;
        ITransportStreamReaderSubscriptionPtr mSendStreamDecodedSubscription;
        ITransportStreamWriterSubscriptionPtr mSendStreamEncodedSubscription;

        bool mReceiveStreamDecodedWriteReady {};
        bool mSendStreamEncodedWriteReady {};
        bool mNotifySendStreamDecodedReadyToReady {};

        KeyMap mReceiveKeys;
        KeyMap mSendKeys;

        bool mChangeKey {};
        ITimerPtr mChangeSendingKeyTimer;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IMessageLayerSecurityChannelFactory
      //

      interaction IMessageLayerSecurityChannelFactory
      {
        static IMessageLayerSecurityChannelFactory &singleton() noexcept;

        virtual MessageLayerSecurityChannelPtr create(
                                                      IMessageLayerSecurityChannelDelegatePtr delegate,
                                                      ITransportStreamPtr receiveStreamEncoded,
                                                      ITransportStreamPtr receiveStreamDecoded,
                                                      ITransportStreamPtr sendStreamDecoded,
                                                      ITransportStreamPtr sendStreamEncoded,
                                                      const char *contextID = NULL
                                                      ) noexcept;
      };

      class MessageLayerSecurityChannelFactory : public IFactory<IMessageLayerSecurityChannelFactory> {};
    }
  }
}
