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

#include <ortc/services/types.h>

namespace openpeer
{
  namespace services
  {
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IMessageLayerSecurityChannel
    #pragma mark

    interaction IMessageLayerSecurityChannel
    {
      enum SessionStates
      {
        SessionState_Pending,
        SessionState_WaitingForNeededInformation,
        SessionState_Connected,
        SessionState_Shutdown,
      };

      enum KeyingTypes
      {
        KeyingType_Unknown,

        KeyingType_Passphrase,
        KeyingType_PublicKey,
        KeyingType_KeyAgreement,
      };

      static const char *toString(SessionStates state);
      static const char *toString(KeyingTypes type);

      static ElementPtr toDebug(IMessageLayerSecurityChannelPtr channel);

      //-----------------------------------------------------------------------
      // PURPOSE: create a new channel to a remote connection
      static IMessageLayerSecurityChannelPtr create(
                                                    IMessageLayerSecurityChannelDelegatePtr delegate,
                                                    ITransportStreamPtr receiveStreamEncoded,
                                                    ITransportStreamPtr receiveStreamDecoded,
                                                    ITransportStreamPtr sendStreamDecoded,
                                                    ITransportStreamPtr sendStreamEncoded,
                                                    const char *localContextID = NULL                                    // the session context ID
                                                    );

      //-----------------------------------------------------------------------
      // PURPOSE: get process unique ID for object
      virtual PUID getID() const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: subscribe to class events
      virtual IMessageLayerSecurityChannelSubscriptionPtr subscribe(IMessageLayerSecurityChannelDelegatePtr delegate) = 0;  // passing in IMessageLayerSecurityChannelDelegatePtr() will return the default subscription

      //-----------------------------------------------------------------------
      // PURPOSE: immediately disconnects the channel (no signaling is needed)
      virtual void cancel() = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: return the current state of the connection
      virtual SessionStates getState(
                                     WORD *outLastErrorCode = NULL,
                                     String *outLastErrorReason = NULL
                                     ) const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Returns true if the local context ID needs to be set
      // NOTE:    Check this method when
      //          "SessionState_WaitingForNeededInformation" is
      //          notified.
      //          Call "setLocalContextID" to provide value.
      virtual bool needsLocalContextID() const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Determine if keying material is needed for decoding the
      //          receive stream and what type of material is needed.
      // RETURNS: true if receive keying material is needed or false if the
      //          keying material is already known.
      // NOTE:    Check this method when
      //          "SessionState_WaitingForNeededInformation" is notified.
      //
      //          If the type is "KeyingType_Passphrase" the local side
      //          must supply the passphrase to use for decoding the receive
      //          keying material.
      //
      //          If the type is "KeyingType_PublicKey" the local side
      //          must supply the private key needed to decrypt the receive
      //          keying material.
      //
      //          If the type is "KeyingType_KeyAgreement" the local side
      //          must supply the local key agreement material and possibly
      //          the remote key agreement material.
      //
      //          If the remote party expected the local side to have been
      //          pre-supplied a remote public key "out of band" then the
      //          remote public key the remote side is expecting will return
      //          via "getRemoteKeyAgreementFingerprint".
      virtual bool needsReceiveKeying(KeyingTypes *outDecodingType = NULL) const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Determine if keying material is needed for encoding the
      //          send stream and what type of material is needed.
      // RETURNS: true if send keying material is needed or false if the keying
      //          material is already known.
      // NOTE:    Check this method when
      //          "SessionState_WaitingForNeededInformation" is notified.
      //
      //          If the remote side has not supplied any keying material then
      //          the keying material type is not known.
      //
      //          If the remote side supplied a "passphrase" encoded key bundle
      //          then "KeyingType_Passphrase" is returned and the local side
      //          can encode with a passphrase or alternatively use a remote
      //          party's public key.
      //
      //          If the remote side supplied a "public key" encoded key bundle
      //          then "KeyingType_PublicKey" is returned and the local isde
      //          can encode with a passphrase or alternatively use a remote
      //          party's public key.
      //
      //          If the remote side supplied a "key agreement" encoded key
      //          bundle then "KeyingType_KeyAgreement" is returned and
      //          the local key agreement private and public key must be
      //          supplied. Optionally the remote side may expect the remote
      //          public key of the key agreement be supplied too.
      //
      //          If the remote party expected the local side to have been
      //          pre-supplied a remote public key "out of band" then the
      //          remote public key the remote side is expecting will return
      //          via "getRemoteKeyAgreementFingerprint".
      virtual bool needsSendKeying(KeyingTypes *outEncodingType = NULL) const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Returns true if the signature on the incoming
      //          keying material needs validation.
      // NOTE:    Check this method when
      //          "SessionState_WaitingForNeededInformation" is notified.
      //
      //          Call "getSignedReceiveKeying" to examine the
      //          signing signature of the receive keying materials. This
      //          can be used to resolve the public key which should be used
      //          to validate the receive keying material's signatures. Call
      //          "setReceiveKeyingSigningPublicKey" to set the
      //          remote public key expected to have signed the keying
      //           material.
      virtual bool needsReceiveKeyingSigningPublicKey() const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Returns true when the send keying materials needs to be
      //          signed before transmitting the key material to the remote
      //          party.
      // NOTE:    Check this method when
      //          "SessionState_WaitingForNeededInformation" is notified.
      //
      //          Call "getSendKeyingNeedingToBeSigned" to obtain the send
      //          keying material to be signed and call
      //          "notifySendKeyingSigned" when the keying information
      //          has been signed.
      virtual bool needsSendKeyingToeBeSigned() const = 0;


      //-----------------------------------------------------------------------
      // PURPOSE: Obtain the context ID specified in the construction of this
      //          object (and sent to the remote party).
      virtual String getLocalContextID() const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Obtain the context ID specified by the remote party.
      // NOTE:    This can be useful to pick the correct keying material
      //          when the remote party encodes keying materials using
      //          a passphrase.
      virtual String getRemoteContextID() const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Set the local context ID
      // NOTE:    A local context ID is reuqired before any data can be sent
      //          to the remote party.
      virtual void setLocalContextID(const char *contextID) = 0;


      //-----------------------------------------------------------------------
      // PURPOSE: If the remote party encoded their keying materials using
      //          a passphrase, this rountine can be called to decode that
      //          keying material.
      // NOTE:    The "needsReceiveKeying" will return true with
      //          "KeyingType_Passphrase" when the receive keying material
      //          needs a passphrase to decode its keying materials. Call this
      //          routine to provide the passphrase used to decode the receive
      //          keying material.
      virtual void setReceiveKeying(const char *passphrase) = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Calling this routine causes the keying material to be encoded
      //          using the passphrase specified.
      // NOTE:    When "needsSendKeying" returns true, this routine can be used
      //          to provide a passphrase to use to encode the send keying
      //          material.
      virtual void setSendKeying(const char *passphrase) = 0;


      //-----------------------------------------------------------------------
      // PURPOSE: If the remote side is using the public key of the local side
      //          to encode the keying material the fingering of the public key
      //          used to encode the receive keying material is returned.
      // RETURNS: The fingerprint of the public key used to encode the
      //          receive key fingerprint (if known).
      virtual String getReceivePublicKeyFingerprint() const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: If the remote party encoded their keying materials using
      //          a public key, this rountine can be called to decode that
      //          keying material by providing the associated private key.
      // NOTE:    When "needsReceiveKeying" return true with type
      //          "KeyingType_PublicKey", call this routine to provide the
      //          private key needed to decode the receive keying material.
      virtual void setReceiveKeying(
                                    IRSAPrivateKeyPtr localPrivateKey,
                                    IRSAPublicKeyPtr localPublicKey
                                    ) = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Calling this routine causes the keying material to be
      //          encoded using the public key specified.
      // NOTE:    When "needsSendKeying" returns true, this routine can be used
      //          to provide a public key to use to encode the send keying
      //          material.
      virtual void setSendKeying(IRSAPublicKeyPtr remotePublicKey) = 0;
      

      //-----------------------------------------------------------------------
      // PURPOSE: Obtain the domain in use for keying agreement.
      // NOTE:    This is needed to figure out the correct Diffie-Hellman
      //          keying material needing to be supplied and the domain cannot
      //          change during the entire session.
      virtual IDHKeyDomainPtr getKeyAgreementDomain() const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: If the remote side is using a key agreement for the keying
      //          material and the remote public key was not provided but the
      //          fingerprint of the remote public key was provided, this
      //          routine returns the fingerprint of the remote public key.
      // RETURNS: The remote agreement key fingerprint expected (if known).
      virtual String getRemoteKeyAgreementFingerprint() const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: If a key agreement mechanism is used for encoding keying
      //          material then this rountine can be called to set the
      //          key agreement needed at the local side.
      // NOTE:    When "needsReceiveKeying" or "needsSendKeying" return true
      //          with the type "KeyingType_KeyAgreement" call this routine to
      //          provide the keying material needed to encode/decode the
      //          keying material.
      virtual void setLocalKeyAgreement(
                                        IDHPrivateKeyPtr localPrivateKey,
                                        IDHPublicKeyPtr localPublicKey,
                                        bool remoteSideAlreadyKnowsThisPublicKey
                                        ) = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Obtain the remote public key of the
      // NOTE:    When "needsReceiveKeying" return true with the type
      //          "KeyingType_KeyAgreement" and
      //          "getRemoteKeyAgreementFingerprint" returns the a fingerprint
      //          value then this rountine must be called to supply the
      //          remote public key.
      virtual void setRemoteKeyAgreement(IDHPublicKeyPtr remotePublicKey) = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: If the remote party encoded their keying materials using
      //          a key agreement the remote public key of the remote party
      //          can be obtained.
      // NOTE:    This is the first remote public key seen by the remote party
      //          and does not change even if the keying material is changed
      //          as the session progresses.
      virtual IDHPublicKeyPtr getOriginalRemoteKeyAgreement() = 0;


      //-----------------------------------------------------------------------
      // PURPOSE: Gets the signed receiving keying material.
      // NOTE:    Once the first keying material is received, the public
      //          key that should have been used to sign the package will need
      //          to be provided (even if it's contained within the package).
      //          The signature associated to this package can be examined
      //          to help resolve the public key that must to be used to
      //          validate the receive keying material.
      virtual ElementPtr getSignedReceiveKeying() const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Sets the public key to be used to validate the signature
      //          of the received keying material.
      // NOTE:    This is required to call if the public key used to sign the
      //          receive keying material needs to be provided. The
      //          "needsReceiveKeyingSigningPublicKey" will return
      //          true when this information is needed.
      virtual void setReceiveKeyingSigningPublicKey(IRSAPublicKeyPtr remotePublicKey) = 0;


      //-----------------------------------------------------------------------
      // PURPOSE: Obtains the send keying material that needs to be signed.
      // NOTE:    This method needs to be called when
      //          "needsSendKeyingToeBeSigned" returns true and the element
      //          returned will be the element to sign.
      //
      //          The element returned needs to be modified by the caller
      //          and once the proper signature is applied to the element then
      //          "notifySendKeyingSigned" needs to be called to confirm the
      //          completion of the signature process.
      virtual void getSendKeyingNeedingToBeSigned(
                                                  DocumentPtr &outDocumentContainedElementToSign,
                                                  ElementPtr &outElementToSign
                                                  ) const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Notified the signture has been applied to the result of
      //          "getSendKeyingNeedingToBeSigned"
      // NOTE:    This method needs to be called when
      //          "needsSendKeyingToeBeSigned" returns true after the signing
      //          signature has been applied to the result of
      //          "getSendKeyingNeedingToBeSigned".
      //
      //          The private key supplied will be used to sign any future
      //          keying materials since only a fingerprint reference is
      //          used for signing from then onward.
      virtual void notifySendKeyingSigned(
                                          IRSAPrivateKeyPtr signingKey,
                                          IRSAPublicKeyPtr signingPublicKey
                                          ) = 0;
    };


    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IMessageLayerSecurityChannelDelegate
    #pragma mark

    interaction IMessageLayerSecurityChannelDelegate
    {
      typedef IMessageLayerSecurityChannel::SessionStates SessionStates;

      //-----------------------------------------------------------------------
      // PURPOSE: Notifies the delegate that the state of the connection
      //          has changed.
      // NOTE:    If the cryptographic keying is discovered to be incorrect
      //          the channel will shutdown and getState() will return an
      //          error code.
      virtual void onMessageLayerSecurityChannelStateChanged(
                                                             IMessageLayerSecurityChannelPtr channel,
                                                             SessionStates state
                                                             ) = 0;
    };


    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IMessageLayerSecurityChannelSubscription
    #pragma mark

    interaction IMessageLayerSecurityChannelSubscription
    {
      virtual PUID getID() const = 0;

      virtual void cancel() = 0;

      virtual void background() = 0;
    };

  }
}

ZS_DECLARE_PROXY_BEGIN(openpeer::services::IMessageLayerSecurityChannelDelegate)
ZS_DECLARE_PROXY_TYPEDEF(openpeer::services::IMessageLayerSecurityChannelPtr, IMessageLayerSecurityChannelPtr)
ZS_DECLARE_PROXY_TYPEDEF(openpeer::services::IMessageLayerSecurityChannelDelegate::SessionStates, SessionStates)
ZS_DECLARE_PROXY_METHOD_2(onMessageLayerSecurityChannelStateChanged, IMessageLayerSecurityChannelPtr, SessionStates)
ZS_DECLARE_PROXY_END()

ZS_DECLARE_PROXY_SUBSCRIPTIONS_BEGIN(openpeer::services::IMessageLayerSecurityChannelDelegate, openpeer::services::IMessageLayerSecurityChannelSubscription)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(openpeer::services::IMessageLayerSecurityChannelPtr, IMessageLayerSecurityChannelPtr)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(openpeer::services::IMessageLayerSecurityChannelDelegate::SessionStates, SessionStates)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_2(onMessageLayerSecurityChannelStateChanged, IMessageLayerSecurityChannelPtr, SessionStates)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_END()
