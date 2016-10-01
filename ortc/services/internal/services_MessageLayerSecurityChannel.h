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
#include <ortc/services/IWakeDelegate.h>

#include <zsLib/Timer.h>

#include <list>
#include <map>

#define OPENPEER_SERVICES_MESSAGE_LAYER_SECURITY_SIGNATURE_ALGORITHM "https://meta.openpeer.org/2012/12/14/jsonsig#rsa-sha1"

#define OPENPEER_SERVICES_MESSAGE_LAYER_SECURITY_DEFAULT_CRYPTO_ALGORITHM "https://meta.openpeer.org/2012/12/14/jsonmls#aes-cfb-32-16-16-sha1-md5"

#define OPENPEER_SERVICES_SETTING_MESSAGE_LAYER_SECURITY_CHANGE_SENDING_KEY_AFTER "ortc/services/mls-change-sending-key-after-in-seconds"

namespace openpeer
{
  namespace services
  {
    namespace internal
    {
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark MessageLayerSecurityChannel
      #pragma mark

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

          ElementPtr toDebug(AlgorithmIndex index) const;
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
                                    );

      protected:
        MessageLayerSecurityChannel(Noop) :
          Noop(true),
          zsLib::MessageQueueAssociator(IMessageQueuePtr()),
          SharedRecursiveLock(SharedRecursiveLock::create()) {}

        void init();

      public:
        ~MessageLayerSecurityChannel();

        static MessageLayerSecurityChannelPtr convert(IMessageLayerSecurityChannelPtr channel);

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark MessageLayerSecurityChannel => IMessageLayerSecurityChannel
        #pragma mark

        static ElementPtr toDebug(IMessageLayerSecurityChannelPtr channel);

        static MessageLayerSecurityChannelPtr create(
                                                     IMessageLayerSecurityChannelDelegatePtr delegate,
                                                     ITransportStreamPtr receiveStreamEncoded,
                                                     ITransportStreamPtr receiveStreamDecoded,
                                                     ITransportStreamPtr sendStreamDecoded,
                                                     ITransportStreamPtr sendStreamEncoded,
                                                     const char *contextID = NULL
                                                     );

        virtual IMessageLayerSecurityChannelSubscriptionPtr subscribe(IMessageLayerSecurityChannelDelegatePtr delegate);

        virtual PUID getID() const {return mID;}

        virtual void cancel();

        virtual SessionStates getState(
                                       WORD *outLastErrorCode = NULL,
                                       String *outLastErrorReason = NULL
                                       ) const;

        virtual bool needsLocalContextID() const;
        virtual bool needsReceiveKeying(KeyingTypes *outDecodingType = NULL) const;
        virtual bool needsSendKeying(KeyingTypes *outEncodingType = NULL) const;
        virtual bool needsReceiveKeyingSigningPublicKey() const;
        virtual bool needsSendKeyingToeBeSigned() const;

        virtual String getLocalContextID() const;
        virtual String getRemoteContextID() const;
        virtual void setLocalContextID(const char *contextID);

        virtual void setReceiveKeying(const char *passphrase);
        virtual void setSendKeying(const char *passphrase);

        virtual String getReceivePublicKeyFingerprint() const;
        virtual void setReceiveKeying(
                                      IRSAPrivateKeyPtr localPrivateKey,
                                      IRSAPublicKeyPtr localPublicKey
                                      );
        virtual void setSendKeying(IRSAPublicKeyPtr remotePublicKey);

        virtual IDHKeyDomainPtr getKeyAgreementDomain() const;
        virtual String getRemoteKeyAgreementFingerprint() const;
        virtual void setLocalKeyAgreement(
                                          IDHPrivateKeyPtr localPrivateKey,
                                          IDHPublicKeyPtr localPublicKey,
                                          bool remoteSideAlreadyKnowsThisPublicKey
                                          );
        virtual void setRemoteKeyAgreement(IDHPublicKeyPtr remotePublicKey);
        virtual IDHPublicKeyPtr getOriginalRemoteKeyAgreement();

        virtual ElementPtr getSignedReceiveKeying() const;
        virtual void setReceiveKeyingSigningPublicKey(IRSAPublicKeyPtr remotePublicKey);

        virtual void getSendKeyingNeedingToBeSigned(
                                                    DocumentPtr &outDocumentContainedElementToSign,
                                                    ElementPtr &outElementToSign
                                                    ) const;
        virtual void notifySendKeyingSigned(
                                            IRSAPrivateKeyPtr signingKey,
                                            IRSAPublicKeyPtr signingPublicKey
                                            );

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark MessageLayerSecurityChannel => ITransportStreamReaderDelegate
        #pragma mark

        virtual void onTransportStreamReaderReady(ITransportStreamReaderPtr reader);

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark MessageLayerSecurityChannel => ITransportStreamWriterDelegate
        #pragma mark

        virtual void onTransportStreamWriterReady(ITransportStreamWriterPtr writer);

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark MessageLayerSecurityChannel => IWakeDelegate
        #pragma mark

        virtual void onWake();

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark MessageLayerSecurityChannel => ITimerDelegate
        #pragma mark

        virtual void onTimer(TimerPtr timer);

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark MessageLayerSecurityChannel => (internal)
        #pragma mark

        bool isShutdown() const {return SessionState_Shutdown == mCurrentState;}

        Log::Params log(const char *message) const;
        Log::Params debug(const char *message) const;

        virtual ElementPtr toDebug() const;

        void setState(SessionStates state);
        void setError(WORD errorCode, const char *inReason = NULL);

        void step();
        bool stepReceive();
        bool stepSendKeying();
        bool stepSend();
        bool stepCheckConnected();

        bool stepProcessReceiveKeying(
                                      bool &outReturnResult,
                                      SecureByteBlockPtr keying = SecureByteBlockPtr()
                                      );

        bool isSendingReady() const;

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark MessageLayerSecurityChannel => (data)
        #pragma mark

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
        TimerPtr mChangeSendingKeyTimer;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IMessageLayerSecurityChannelFactory
      #pragma mark

      interaction IMessageLayerSecurityChannelFactory
      {
        static IMessageLayerSecurityChannelFactory &singleton();

        virtual MessageLayerSecurityChannelPtr create(
                                                      IMessageLayerSecurityChannelDelegatePtr delegate,
                                                      ITransportStreamPtr receiveStreamEncoded,
                                                      ITransportStreamPtr receiveStreamDecoded,
                                                      ITransportStreamPtr sendStreamDecoded,
                                                      ITransportStreamPtr sendStreamEncoded,
                                                      const char *contextID = NULL
                                                      );
      };

      class MessageLayerSecurityChannelFactory : public IFactory<IMessageLayerSecurityChannelFactory> {};
    }
  }
}
