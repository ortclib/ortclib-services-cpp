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

#include <openpeer/services/internal/services_Factory.h>

#include <zsLib/helpers.h>
#include <zsLib/Log.h>

namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services) } }

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
      #pragma mark (helper)
      #pragma mark

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Factory
      #pragma mark

      //-----------------------------------------------------------------------
      void Factory::override(FactoryPtr override)
      {
        singleton().mOverride = override;
      }

      //-----------------------------------------------------------------------
      Factory &Factory::singleton()
      {
        static Factory singleton = Singleton<Factory, false>::ref();
        if (singleton.mOverride) return (*singleton.mOverride);
        return singleton;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IBackgroundingFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IBackgroundingFactory &IBackgroundingFactory::singleton()
      {
        return Factory::singleton();
      }

      //-----------------------------------------------------------------------
      BackgroundingPtr IBackgroundingFactory::createForBackgrounding()
      {
        if (this) {}
        return Backgrounding::create();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IDHKeyDomainFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IDHKeyDomainFactory &IDHKeyDomainFactory::singleton()
      {
        return Factory::singleton();
      }

      //-----------------------------------------------------------------------
      DHKeyDomainPtr IDHKeyDomainFactory::generate(size_t keySizeInBits)
      {
        if (this) {}
        return DHKeyDomain::generate(keySizeInBits);
      }

      //-----------------------------------------------------------------------
      DHKeyDomainPtr IDHKeyDomainFactory::loadPrecompiled(
                                                          IDHKeyDomain::KeyDomainPrecompiledTypes precompiledKey,
                                                          bool validate
                                                          )
      {
        if (this) {}
        return DHKeyDomain::loadPrecompiled(precompiledKey, validate);
      }

      //-----------------------------------------------------------------------
      DHKeyDomainPtr IDHKeyDomainFactory::load(
                                               const SecureByteBlock &p,
                                               const SecureByteBlock &q,
                                               const SecureByteBlock &g,
                                               bool validate
                                               )
      {
        if (this) {}
        return DHKeyDomain::load(p, q, g, validate);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IDHPrivateKeyFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IDHPrivateKeyFactory &IDHPrivateKeyFactory::singleton()
      {
        return Factory::singleton();
      }

      //-----------------------------------------------------------------------
      DHPrivateKeyPtr IDHPrivateKeyFactory::generate(
                                                     IDHKeyDomainPtr keyDomain,
                                                     IDHPublicKeyPtr &outPublicKey
                                                     )
      {
        if (this) {}
        return DHPrivateKey::generate(keyDomain, outPublicKey);
      }

      //-----------------------------------------------------------------------
      DHPrivateKeyPtr IDHPrivateKeyFactory::load(
                                                 IDHKeyDomainPtr keyDomain,
                                                 const SecureByteBlock &staticPrivateKey,
                                                 const SecureByteBlock &ephemeralPrivateKey
                                                 )
      {
        if (this) {}
        return DHPrivateKey::load(keyDomain, staticPrivateKey, ephemeralPrivateKey);
      }

      //-----------------------------------------------------------------------
      DHPrivateKeyPtr IDHPrivateKeyFactory::load(
                                                 IDHKeyDomainPtr keyDomain,
                                                 IDHPublicKeyPtr &outPublicKey,
                                                 const SecureByteBlock &staticPrivateKey,
                                                 const SecureByteBlock &ephemeralPrivateKey,
                                                 const SecureByteBlock &staticPublicKey,
                                                 const SecureByteBlock &ephemeralPublicKey
                                                 )
      {
        if (this) {}
        return DHPrivateKey::load(keyDomain, outPublicKey, staticPrivateKey, ephemeralPrivateKey, staticPublicKey, ephemeralPublicKey);
      }

      //-----------------------------------------------------------------------
      DHPrivateKeyPtr IDHPrivateKeyFactory::loadAndGenerateNewEphemeral(
                                                                        IDHKeyDomainPtr keyDomain,
                                                                        const SecureByteBlock &staticPrivateKey,
                                                                        const SecureByteBlock &staticPublicKey,
                                                                        IDHPublicKeyPtr &outNewPublicKey
                                                                        )
      {
        if (this) {}
        return DHPrivateKey::loadAndGenerateNewEphemeral(keyDomain, staticPrivateKey, staticPublicKey, outNewPublicKey);
      }

      //-----------------------------------------------------------------------
      DHPrivateKeyPtr IDHPrivateKeyFactory::loadAndGenerateNewEphemeral(
                                                                        IDHPrivateKeyPtr templatePrivateKey,
                                                                        IDHPublicKeyPtr templatePublicKey,
                                                                        IDHPublicKeyPtr &outNewPublicKey
                                                                        )
      {
        if (this) {}
        return DHPrivateKey::loadAndGenerateNewEphemeral(templatePrivateKey, templatePublicKey, outNewPublicKey);
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
        return Factory::singleton();
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

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IDNSFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IDNSFactory &IDNSFactory::singleton()
      {
        return Factory::singleton();
      }

      //-----------------------------------------------------------------------
      IDNSQueryPtr IDNSFactory::lookupA(
                                        IDNSDelegatePtr delegate,
                                        const char *name
                                        )
      {
        if (this) {}
        return DNS::lookupA(delegate, name);
      }

      //-----------------------------------------------------------------------
      IDNSQueryPtr IDNSFactory::lookupAAAA(
                                           IDNSDelegatePtr delegate,
                                           const char *name
                                           )
      {
        if (this) {}
        return DNS::lookupAAAA(delegate, name);
      }

      //-----------------------------------------------------------------------
      IDNSQueryPtr IDNSFactory::lookupAorAAAA(
                                              IDNSDelegatePtr delegate,
                                              const char *name
                                              )
      {
        if (this) {}
        return DNS::lookupAorAAAA(delegate, name);
      }

      //-----------------------------------------------------------------------
      IDNSQueryPtr IDNSFactory::lookupSRV(
                                          IDNSDelegatePtr delegate,
                                          const char *name,
                                          const char *service,
                                          const char *protocol,
                                          WORD defaultPort,
                                          WORD defaultPriority,
                                          WORD defaultWeight,
                                          SRVLookupTypes lookupType
                                          )
      {
        if (this) {}
        return DNS::lookupSRV(delegate, name, service, protocol, defaultPort, defaultPriority, defaultWeight, lookupType);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IHTTPFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IHTTPFactory &IHTTPFactory::singleton()
      {
        return Factory::singleton();
      }

      //-----------------------------------------------------------------------
      IHTTPQueryPtr IHTTPFactory::get(
                                      IHTTPQueryDelegatePtr delegate,
                                      const char *userAgent,
                                      const char *url,
                                      Duration timeout
                                      )
      {
        if (this) {}
        return HTTP::get(delegate, userAgent, url, timeout);
      }

      //-----------------------------------------------------------------------
      IHTTPQueryPtr IHTTPFactory::post(
                                       IHTTPQueryDelegatePtr delegate,
                                       const char *userAgent,
                                       const char *url,
                                       const BYTE *postData,
                                       size_t postDataLengthInBytes,
                                       const char *postDataMimeType,
                                       Duration timeout
                                       )
      {
        if (this) {}
        return HTTP::post(delegate, userAgent, url, postData, postDataLengthInBytes, postDataMimeType, timeout);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IICESocketFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IICESocketFactory &IICESocketFactory::singleton()
      {
        return Factory::singleton();
      }

      //-----------------------------------------------------------------------
      ICESocketPtr IICESocketFactory::create(
                                             IMessageQueuePtr queue,
                                             IICESocketDelegatePtr delegate,
                                             const IICESocket::TURNServerInfoList &turnServers,
                                             const IICESocket::STUNServerInfoList &stunServers,
                                             WORD port,
                                             bool firstWORDInAnyPacketWillNotConflictWithTURNChannels,
                                             IICESocketPtr foundationSocket
                                             )
      {
        if (this) {}
        return internal::ICESocket::create(queue, delegate, turnServers, stunServers, port, firstWORDInAnyPacketWillNotConflictWithTURNChannels, foundationSocket);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IICESocketSessionFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IICESocketSessionFactory &IICESocketSessionFactory::singleton()
      {
        return Factory::singleton();
      }

      //-----------------------------------------------------------------------
      ICESocketSessionPtr IICESocketSessionFactory::create(
                                                           IICESocketSessionDelegatePtr delegate,
                                                           IICESocketPtr socket,
                                                           const char *remoteUsernameFrag,
                                                           const char *remotePassword,
                                                           const CandidateList &remoteCandidates,
                                                           ICEControls control,
                                                           IICESocketSessionPtr foundation
                                                           )
      {
        if (this) {}
        return internal::ICESocketSession::create(delegate, socket, remoteUsernameFrag, remotePassword, remoteCandidates, control, foundation);
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
        return Factory::singleton();
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
        return Factory::singleton();
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

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IRSAPublicKeyFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IRSAPublicKeyFactory &IRSAPublicKeyFactory::singleton()
      {
        return Factory::singleton();
      }

      //-----------------------------------------------------------------------
      RSAPublicKeyPtr IRSAPublicKeyFactory::loadPublicKey(const SecureByteBlock &buffer)
      {
        if (this) {}
        return RSAPublicKey::load(buffer);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IRUDPChannelFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IRUDPChannelFactory &IRUDPChannelFactory::singleton()
      {
        return Factory::singleton();
      }

      //-----------------------------------------------------------------------
      RUDPChannelPtr IRUDPChannelFactory::createForRUDPTransportIncoming(
                                                                         IMessageQueuePtr queue,
                                                                         IRUDPChannelDelegateForSessionAndListenerPtr master,
                                                                         const IPAddress &remoteIP,
                                                                         WORD incomingChannelNumber,
                                                                         const char *localUserFrag,
                                                                         const char *localPassword,
                                                                         const char *remoteUserFrag,
                                                                         const char *remotePassword,
                                                                         STUNPacketPtr channelOpenPacket,
                                                                         STUNPacketPtr &outResponse
                                                                         )
      {
        if (this) {}
        return RUDPChannel::createForRUDPTransportIncoming(queue, master, remoteIP, incomingChannelNumber, localUserFrag, localPassword, remoteUserFrag, remotePassword, channelOpenPacket, outResponse);
      }

      //-----------------------------------------------------------------------
      RUDPChannelPtr IRUDPChannelFactory::createForRUDPTransportOutgoing(
                                                                         IMessageQueuePtr queue,
                                                                         IRUDPChannelDelegateForSessionAndListenerPtr master,
                                                                         IRUDPChannelDelegatePtr delegate,
                                                                         const IPAddress &remoteIP,
                                                                         WORD incomingChannelNumber,
                                                                         const char *localUserFrag,
                                                                         const char *localPassword,
                                                                         const char *remoteUserFrag,
                                                                         const char *remotePassword,
                                                                         const char *connectionInfo,
                                                                         ITransportStreamPtr receiveStream,
                                                                         ITransportStreamPtr sendStream
                                                                         )
      {
        if (this) {}
        return RUDPChannel::createForRUDPTransportOutgoing(queue, master, delegate, remoteIP, incomingChannelNumber, localUserFrag, localPassword, remoteUserFrag, remotePassword, connectionInfo, receiveStream, sendStream);
      }

      //-----------------------------------------------------------------------
      RUDPChannelPtr IRUDPChannelFactory::createForListener(
                                                            IMessageQueuePtr queue,
                                                            IRUDPChannelDelegateForSessionAndListenerPtr master,
                                                            const IPAddress &remoteIP,
                                                            WORD incomingChannelNumber,
                                                            STUNPacketPtr channelOpenPacket,
                                                            STUNPacketPtr &outResponse
                                                            )
      {
        if (this) {}
        return RUDPChannel::createForListener(queue, master, remoteIP, incomingChannelNumber, channelOpenPacket, outResponse);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IRUDPChannelStreamFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IRUDPChannelStreamFactory &IRUDPChannelStreamFactory::singleton()
      {
        return Factory::singleton();
      }

      //-----------------------------------------------------------------------
      RUDPChannelStreamPtr IRUDPChannelStreamFactory::create(
                                                             IMessageQueuePtr queue,
                                                             IRUDPChannelStreamDelegatePtr delegate,
                                                             QWORD nextSequenceNumberToUseForSending,
                                                             QWORD nextSequenberNumberExpectingToReceive,
                                                             WORD sendingChannelNumber,
                                                             WORD receivingChannelNumber,
                                                             DWORD minimumNegotiatedRTTInMilliseconds
                                                             )
      {
        if (this) {}
        return RUDPChannelStream::create(queue, delegate, nextSequenceNumberToUseForSending, nextSequenberNumberExpectingToReceive, sendingChannelNumber, receivingChannelNumber, minimumNegotiatedRTTInMilliseconds);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IRUDPTransportFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IRUDPTransportFactory &IRUDPTransportFactory::singleton()
      {
        return Factory::singleton();
      }

      //-----------------------------------------------------------------------
      RUDPTransportPtr IRUDPTransportFactory::listen(
                                                            IMessageQueuePtr queue,
                                                            IICESocketSessionPtr iceSession,
                                                            IRUDPTransportDelegatePtr delegate
                                                            )
      {
        if (this) {}
        return RUDPTransport::listen(queue, iceSession, delegate);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IRUDPListenerFactory
      #pragma mark

      //-----------------------------------------------------------------------
      IRUDPListenerFactory &IRUDPListenerFactory::singleton()
      {
        return Factory::singleton();
      }

      //-----------------------------------------------------------------------
      RUDPListenerPtr IRUDPListenerFactory::create(
                                                   IMessageQueuePtr queue,
                                                   IRUDPListenerDelegatePtr delegate,
                                                   WORD port,
                                                   const char *realm
                                                   )
      {
        if (this) {}
        return RUDPListener::create(queue, delegate, port, realm);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IRUDPListenerFactory
      #pragma mark

      //-------------------------------------------------------------------------
      IRUDPMessagingFactory &IRUDPMessagingFactory::singleton()
      {
        return Factory::singleton();
      }

      //-----------------------------------------------------------------------
      RUDPMessagingPtr IRUDPMessagingFactory::acceptChannel(
                                                            IMessageQueuePtr queue,
                                                            IRUDPListenerPtr listener,
                                                            IRUDPMessagingDelegatePtr delegate,
                                                            ITransportStreamPtr receiveStream,
                                                            ITransportStreamPtr sendStream,
                                                            size_t maxMessageSizeInBytes
                                                            )
      {
        if (this) {}
        return RUDPMessaging::acceptChannel(queue, listener, delegate, receiveStream, sendStream, maxMessageSizeInBytes);
      }

      //-----------------------------------------------------------------------
      RUDPMessagingPtr IRUDPMessagingFactory::acceptChannel(
                                                            IMessageQueuePtr queue,
                                                            IRUDPTransportPtr session,
                                                            IRUDPMessagingDelegatePtr delegate,
                                                            ITransportStreamPtr receiveStream,
                                                            ITransportStreamPtr sendStream,
                                                            size_t maxMessageSizeInBytes
                                                            )
      {
        if (this) {}
        return RUDPMessaging::acceptChannel(queue, session, delegate, receiveStream, sendStream, maxMessageSizeInBytes);
      }

      //-----------------------------------------------------------------------
      RUDPMessagingPtr IRUDPMessagingFactory::openChannel(
                                                          IMessageQueuePtr queue,
                                                          IRUDPTransportPtr session,
                                                          IRUDPMessagingDelegatePtr delegate,
                                                          const char *connectionInfo,
                                                          ITransportStreamPtr receiveStream,
                                                          ITransportStreamPtr sendStream,
                                                          size_t maxMessageSizeInBytes
                                                          )
      {
        if (this) {}
        return RUDPMessaging::openChannel(queue, session, delegate, connectionInfo, receiveStream, sendStream, maxMessageSizeInBytes);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ISTUNDiscoveryFactory
      #pragma mark

      //-----------------------------------------------------------------------
      ISTUNDiscoveryFactory &ISTUNDiscoveryFactory::singleton()
      {
        return Factory::singleton();
      }

      //-----------------------------------------------------------------------
      STUNDiscoveryPtr ISTUNDiscoveryFactory::create(
                                                     IMessageQueuePtr queue,
                                                     ISTUNDiscoveryDelegatePtr delegate,
                                                     IDNS::SRVResultPtr service
                                                     )
      {
        if (this) {}
        return STUNDiscovery::create(queue, delegate, service);
      }

      //-----------------------------------------------------------------------
      STUNDiscoveryPtr ISTUNDiscoveryFactory::create(
                                                     IMessageQueuePtr queue,
                                                     ISTUNDiscoveryDelegatePtr delegate,
                                                     const char *srvName
                                                     )
      {
        if (this) {}
        return STUNDiscovery::create(queue, delegate, srvName);
      }
      
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ISTUNRequesterFactory
      #pragma mark

      //-----------------------------------------------------------------------
      ISTUNRequesterFactory &ISTUNRequesterFactory::singleton()
      {
        return Factory::singleton();
      }

      //-----------------------------------------------------------------------
      STUNRequesterPtr ISTUNRequesterFactory::create(
                                                     IMessageQueuePtr queue,
                                                     ISTUNRequesterDelegatePtr delegate,
                                                     IPAddress serverIP,
                                                     STUNPacketPtr stun,
                                                     STUNPacket::RFCs usingRFC,
                                                     Duration maxTimeout
                                                     )
      {
        if (this) {}
        return STUNRequester::create(queue, delegate, serverIP, stun, usingRFC, maxTimeout);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ISTUNRequesterFactory
      #pragma mark
      
      //-----------------------------------------------------------------------
      ISTUNRequesterManagerFactory &ISTUNRequesterManagerFactory::singleton()
      {
        return Factory::singleton();
      }

      //-----------------------------------------------------------------------
      STUNRequesterManagerPtr ISTUNRequesterManagerFactory::createSTUNRequesterManager()
      {
        if (this) {}
        return STUNRequesterManager::create();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ITCPMessagingFactory
      #pragma mark

      //-----------------------------------------------------------------------
      ITCPMessagingFactory &ITCPMessagingFactory::singleton()
      {
        return Factory::singleton();
      }

      //-----------------------------------------------------------------------
      TCPMessagingPtr ITCPMessagingFactory::accept(
                                                   ITCPMessagingDelegatePtr delegate,
                                                   ITransportStreamPtr receiveStream,
                                                   ITransportStreamPtr sendStream,
                                                   bool framesHaveChannelNumber,
                                                   SocketPtr socket,
                                                   size_t maxMessageSizeInBytes
                                                   )
      {
        if (this) {}
        return internal::TCPMessaging::accept(delegate, receiveStream, sendStream, framesHaveChannelNumber, socket, maxMessageSizeInBytes);
      }

      //-----------------------------------------------------------------------
      TCPMessagingPtr ITCPMessagingFactory::connect(
                                                    ITCPMessagingDelegatePtr delegate,
                                                    ITransportStreamPtr receiveStream,
                                                    ITransportStreamPtr sendStream,
                                                    bool framesHaveChannelNumber,
                                                    IPAddress remoteIP,
                                                    size_t maxMessageSizeInBytes
                                                    )
      {
        if (this) {}
        return internal::TCPMessaging::connect(delegate, receiveStream, sendStream, framesHaveChannelNumber, remoteIP, maxMessageSizeInBytes);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ITransportStreamFactory
      #pragma mark

      //-----------------------------------------------------------------------
      ITransportStreamFactory &ITransportStreamFactory::singleton()
      {
        return Factory::singleton();
      }

      //-----------------------------------------------------------------------
      TransportStreamPtr ITransportStreamFactory::create(
                                                         ITransportStreamWriterDelegatePtr writerDelegate,
                                                         ITransportStreamReaderDelegatePtr readerDelegate
                                                         )
      {
        if (this) {}
        return internal::TransportStream::create(writerDelegate, readerDelegate);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ITURNSocketFactory
      #pragma mark

      //-----------------------------------------------------------------------
      ITURNSocketFactory &ITURNSocketFactory::singleton()
      {
        return Factory::singleton();
      }

      //-----------------------------------------------------------------------
      TURNSocketPtr ITURNSocketFactory::create(
                                               IMessageQueuePtr queue,
                                               ITURNSocketDelegatePtr delegate,
                                               const char *turnServer,
                                               const char *turnServerUsername,
                                               const char *turnServerPassword,
                                               bool useChannelBinding,
                                               WORD limitChannelToRangeStart,
                                               WORD limitChannelRoRangeEnd
                                               )
      {
        if (this) {}
        return TURNSocket::create(queue, delegate, turnServer, turnServerUsername, turnServerPassword, useChannelBinding, limitChannelToRangeStart, limitChannelRoRangeEnd);
      }

      //-----------------------------------------------------------------------
      TURNSocketPtr ITURNSocketFactory::create(
                                               IMessageQueuePtr queue,
                                               ITURNSocketDelegatePtr delegate,
                                               IDNS::SRVResultPtr srvTURNUDP,
                                               IDNS::SRVResultPtr srvTURNTCP,
                                               const char *turnServerUsername,
                                               const char *turnServerPassword,
                                               bool useChannelBinding,
                                               WORD limitChannelToRangeStart,
                                               WORD limitChannelRoRangeEnd
                                               )
      {
        if (this) {}
        return TURNSocket::create(queue, delegate, srvTURNUDP, srvTURNTCP, turnServerUsername, turnServerPassword, useChannelBinding, limitChannelToRangeStart, limitChannelRoRangeEnd);
      }
    }
  }
}
