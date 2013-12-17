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

#include <openpeer/services/internal/services_RUDPTransport.h>
#include <openpeer/services/internal/services_RUDPChannel.h>
#include <openpeer/services/internal/services_Helper.h>

#include <openpeer/services/RUDPPacket.h>

#include <zsLib/Exception.h>
#include <zsLib/helpers.h>
#include <zsLib/Log.h>
#include <zsLib/Stringize.h>
#include <zsLib/XML.h>

#include <cryptopp/osrng.h>

#include <algorithm>

#define OPENPEER_SERVICES_RUDPICESOCKETSESSION_MAX_ATTEMPTS_TO_FIND_FREE_CHANNEL_NUMBER (5)

namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services_rudp) } }


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
      #pragma mark RUDPTransport
      #pragma mark

      //-----------------------------------------------------------------------
      RUDPTransport::RUDPTransport(
                                   IMessageQueuePtr queue,
                                   IICESocketSessionPtr iceSession,
                                   IRUDPTransportDelegatePtr delegate
                                   ) :
        MessageQueueAssociator(queue),
        mCurrentState(RUDPTransportState_Pending),
        mICESession(iceSession)
      {
        ZS_LOG_DETAIL(log("created"))

        if (delegate) {
          mDefaultSubscription = mSubscriptions.subscribe(delegate);
        }
      }

      //-----------------------------------------------------------------------
      void RUDPTransport::init()
      {
        AutoRecursiveLock lock(getLock());

        mICESubscription = mICESession->subscribe(mThisWeak.lock());
      }

      //-----------------------------------------------------------------------
      RUDPTransport::~RUDPTransport()
      {
        if (isNoop()) return;

        mThisWeak.reset();
        ZS_LOG_DETAIL(log("destroyed"))
        cancel();
      }

      //-----------------------------------------------------------------------
      RUDPTransportPtr RUDPTransport::convert(IRUDPTransportPtr session)
      {
        return dynamic_pointer_cast<RUDPTransport>(session);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RUDPTransport => RUDPTransport
      #pragma mark

      //-----------------------------------------------------------------------
      ElementPtr RUDPTransport::toDebug(IRUDPTransportPtr session)
      {
        if (!session) return ElementPtr();

        RUDPTransportPtr pThis = RUDPTransport::convert(session);
        return pThis->toDebug();
      }
      
      //-----------------------------------------------------------------------
      RUDPTransportPtr RUDPTransport::listen(
                                             IMessageQueuePtr queue,
                                             IICESocketSessionPtr iceSession,
                                             IRUDPTransportDelegatePtr delegate
                                             )
      {
        RUDPTransportPtr pThis(new RUDPTransport(queue, iceSession, delegate));
        pThis->mThisWeak = pThis;
        pThis->init();
        return pThis;
      }

      //-----------------------------------------------------------------------
      IRUDPTransportSubscriptionPtr RUDPTransport::subscribe(IRUDPTransportDelegatePtr originalDelegate)
      {
        AutoRecursiveLock lock(getLock());
        if (!originalDelegate) return mDefaultSubscription;

        IRUDPTransportSubscriptionPtr subscription = mSubscriptions.subscribe(originalDelegate);

        IRUDPTransportDelegatePtr delegate = mSubscriptions.delegate(subscription);

        if (delegate) {
          RUDPTransportPtr pThis = mThisWeak.lock();

          if (RUDPTransportState_Pending != mCurrentState) {
            delegate->onRUDPTransportStateChanged(pThis, mCurrentState);
          }

          if (mPendingSessions.size() > 0) {
            // inform the delegate of the new session waiting...
            mSubscriptions.delegate()->onRUDPTransportChannelWaiting(mThisWeak.lock());
          }
        }

        if (isShutdown()) {
          mSubscriptions.clear();
        }

        return subscription;
      }

      //-----------------------------------------------------------------------
      IRUDPTransport::RUDPTransportStates RUDPTransport::getState(
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
      void RUDPTransport::shutdown()
      {
        AutoRecursiveLock lock(getLock());
        cancel();
      }

      //-----------------------------------------------------------------------
      IICESocketSessionPtr RUDPTransport::getICESession() const
      {
        AutoRecursiveLock lock(getLock());
        return mICESession;
      }

      //-----------------------------------------------------------------------
      IRUDPChannelPtr RUDPTransport::openChannel(
                                                 IRUDPChannelDelegatePtr delegate,
                                                 const char *connectionInfo,
                                                 ITransportStreamPtr receiveStream,
                                                 ITransportStreamPtr sendStream
                                                 )
      {
        AutoRecursiveLock lock(getLock());
        if ((isShuttingDown()) ||
            (isShutdown())) {
          ZS_LOG_WARNING(Detail, log("attempting to open a channel during the shutdown thus returning NULL channel object"))
          return IRUDPChannelPtr();
        }

        if (!mICESession) {
          ZS_LOG_WARNING(Detail, log("attempting to open a channel without an ICE session thus returning NULL channel object"))
          return IRUDPChannelPtr();
        }

        CryptoPP::AutoSeededRandomPool rng;
        // we have a valid nonce, we will open the channel, but first - pick an unused channel number
        UINT tries = 0;

        WORD channelNumber = 0;
        bool valid = false;
        do
        {
          ++tries;
          if (tries > OPENPEER_SERVICES_RUDPICESOCKETSESSION_MAX_ATTEMPTS_TO_FIND_FREE_CHANNEL_NUMBER) return IRUDPChannelPtr();

          rng.GenerateBlock((BYTE *)(&channelNumber), sizeof(channelNumber));
          channelNumber = (channelNumber % (OPENPEER_SERVICES_RUDPICESOCKETSESSION_CHANNEL_RANGE_END - OPENPEER_SERVICES_RUDPICESOCKETSESSION_CHANNEL_RANGE_START)) + OPENPEER_SERVICES_RUDPICESOCKETSESSION_CHANNEL_RANGE_START;

          // check to see if the channel was used for this IP before...
          SessionMap::iterator found = mLocalChannelNumberSessions.find(channelNumber);
          valid = (found == mLocalChannelNumberSessions.end());
        } while (!valid);

        if (!valid) {
          ZS_LOG_WARNING(Detail, log("unable to find a free channel number within a reasonable number of attempts"))
          return IRUDPChannelPtr();
        }

        IICESocketSessionPtr iceSession = getICESession();
        if (!iceSession) {
          ZS_LOG_WARNING(Detail, log("failed to obtain related ICE session thus returning NULL channel object"))
          return IRUDPChannelPtr();
        }

        ZS_LOG_DEBUG(log("channel openned"))

        // found a useable channel number therefor create a new session
        UseRUDPChannelPtr session = UseRUDPChannel::createForRUDPTransportOutgoing(
                                                                                   getAssociatedMessageQueue(),
                                                                                   mThisWeak.lock(),
                                                                                   delegate,
                                                                                   iceSession->getConnectedRemoteIP(),
                                                                                   channelNumber,
                                                                                   iceSession->getLocalUsernameFrag(),
                                                                                   iceSession->getLocalPassword(),
                                                                                   iceSession->getRemoteUsernameFrag(),
                                                                                   iceSession->getRemotePassword(),
                                                                                   connectionInfo,
                                                                                   receiveStream,
                                                                                   sendStream
                                                                                   );

        mLocalChannelNumberSessions[channelNumber] = session;
        issueChannelConnectIfPossible();
        return RUDPChannel::convert(session);
      }

      //-----------------------------------------------------------------------
      IRUDPChannelPtr RUDPTransport::acceptChannel(
                                                   IRUDPChannelDelegatePtr delegate,
                                                   ITransportStreamPtr receiveStream,
                                                   ITransportStreamPtr sendStream
                                                   )
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!receiveStream)
        ZS_THROW_INVALID_ARGUMENT_IF(!sendStream)

        AutoRecursiveLock lock(getLock());

        if (mPendingSessions.size() < 1) return IRUDPChannelPtr();

        UseRUDPChannelPtr found = mPendingSessions.front();
        found->setDelegate(delegate);
        found->setStreams(receiveStream, sendStream);
        mPendingSessions.pop_front();
        return RUDPChannel::convert(found);
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RUDPTransport => IICESocketSessionDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void RUDPTransport::onICESocketSessionStateChanged(
                                                         IICESocketSessionPtr session,
                                                         ICESocketSessionStates state
                                                         )
      {
        AutoRecursiveLock lock(getLock());
        if (isShutdown()) {
          ZS_LOG_WARNING(Debug, log("notified of ICE socket session changed while shutdown") + ZS_PARAM("ICE session ID", session->getID()))
          return;
        }

        if (session != mICESession) {
          ZS_LOG_WARNING(Debug, log("received notification of ICE socket session state changed from obsolete session") + ZS_PARAM("ICE session ID", session->getID()))
          return;
        }

        if (IICESocketSession::ICESocketSessionState_Shutdown == state) {
          ZS_LOG_WARNING(Detail, log("ICE socket session reported itself shutdown so must shutdown RUDP session") + ZS_PARAM("ICE session ID", session->getID()))

          WORD errorCode = 0;
          String reason;
          session->getState(&errorCode, &reason);
          if (0 != errorCode) {
            setError(errorCode, reason);
          }
          cancel();
          return;
        }

        if ((IICESocketSession::ICESocketSessionState_Nominated == state) ||
            (IICESocketSession::ICESocketSessionState_Completed == state)) {
          ZS_LOG_DEBUG(log("notified that socket session state is nominated") + ZS_PARAM("ICE session ID", session->getID()))

          issueChannelConnectIfPossible();
        }

        step();
      }

      //-----------------------------------------------------------------------
      void RUDPTransport::onICESocketSessionNominationChanged(IICESocketSessionPtr session)
      {
        // ignored
      }

      //-----------------------------------------------------------------------
      void RUDPTransport::handleICESocketSessionReceivedPacket(
                                                               IICESocketSessionPtr ignore,
                                                               const BYTE *buffer,
                                                               size_t bufferLengthInBytes
                                                               )
      {
        if (ZS_IS_LOGGING(Insane)) {
          String base64 = Helper::convertToBase64(buffer, bufferLengthInBytes);
          ZS_LOG_INSANE(log("RECEIVED PACKET FROM WIRE") + ZS_PARAM("wire in", base64))
        }

        RUDPPacketPtr rudp = RUDPPacket::parseIfRUDP(buffer, bufferLengthInBytes);

        if (!rudp) {
          ZS_LOG_WARNING(Trace, log("failed to parse data packet as RUDP thus ignoring packet"))
          return;
        }

        UseRUDPChannelPtr session;

        // scope: figure out which session this belongs
        {
          AutoRecursiveLock lock(getLock());
          SessionMap::iterator found = mLocalChannelNumberSessions.find(rudp->mChannelNumber);
          if (found == mLocalChannelNumberSessions.end()) {
            ZS_LOG_WARNING(Trace, log("RUDP packet does not belong to any known channel thus igoring the packet"))
            return;  // doesn't belong to any session so ignore it
          }

          session = (*found).second;
          ZS_THROW_INVALID_ASSUMPTION_IF(!session)
        }

        // push the RUDP packet to the session to handle
        session->handleRUDP(rudp, buffer, bufferLengthInBytes);
      }

      //-----------------------------------------------------------------------
      bool RUDPTransport::handleICESocketSessionReceivedSTUNPacket(
                                                                   IICESocketSessionPtr session,
                                                                   STUNPacketPtr stun,
                                                                   const String &localUsernameFrag,
                                                                   const String &remoteUsernameFrag
                                                                   )
      {
        // next we ignore all responses/error responses because they would have been handled by a requester
        if ((STUNPacket::Class_Response == stun->mClass) ||
            (STUNPacket::Class_ErrorResponse == stun->mClass)) {
          ZS_LOG_TRACE(log("this is a response which would be handled from requester, thus ignoring"))
          return false;
        }

        // can only be one of these two methods
        if ((STUNPacket::Method_ReliableChannelOpen != stun->mMethod) &&
            (STUNPacket::Method_ReliableChannelACK != stun->mMethod)) {
          ZS_LOG_TRACE(log("the request or indication is not a channel open or ACK, thus ignoring"))
          return false;
        }

        // must have username and channel number or it is illegal
        if ((!stun->hasAttribute(STUNPacket::Attribute_Username)) ||
            (!stun->hasAttribute(STUNPacket::Attribute_ChannelNumber))) {
          ZS_LOG_ERROR(Debug, log("the request or indication does not have a username, thus ignoring"))
          return false;
        }

        STUNPacketPtr response;

        do
        {
          UseRUDPChannelPtr session;

          // scope: next we attempt to see if there is already a session that handles this IP/channel pairing
          {
            AutoRecursiveLock lock(getLock());
            if (localUsernameFrag != mICESession->getLocalUsernameFrag()) {
              ZS_LOG_TRACE(log("the request local username frag does not match, thus ignoring") + ZS_PARAM("local username frag", localUsernameFrag) + ZS_PARAM("expected local username frag", mICESession->getLocalUsernameFrag()))
              return false;
            }

            SessionMap::iterator found = mRemoteChannelNumberSessions.find(stun->mChannelNumber);
            if (found != mRemoteChannelNumberSessions.end()) {
              session = (*found).second;
            } else {
              if (remoteUsernameFrag != mICESession->getRemoteUsernameFrag()) {
                ZS_LOG_TRACE(log("the request remote username frag does not match (thus ignoring - might be for another session)") + ZS_PARAM("remote username frag", remoteUsernameFrag) + ZS_PARAM("expected remote username frag", mICESession->getRemoteUsernameFrag()))
                return false;
              }
            }
          }

          if (session) {
            bool handled = session->handleSTUN(stun, response, localUsernameFrag, remoteUsernameFrag);
            if ((handled) && (!response)) return true;
          } else {
            bool handled =  handleUnknownChannel(stun, response);
            if ((handled) && (!response)) return true;
          }

          if (!response) {
            // not handled
            if (STUNPacket::Class_Request == stun->mClass) {
              stun->mErrorCode = STUNPacket::ErrorCode_BadRequest;
              response = STUNPacket::createErrorResponse(stun);
              fix(response);
            }
          }

          // make sure there is a response, if not then we abort since it was a STUN packet but we may or may not have responded
          if (!response) {
            ZS_LOG_TRACE(log("no response to send (already sent?)"))
            return false;
          }
        } while (false);  // using as a scope rather than as a loop

        if (response) {
          IICESocketSessionPtr session = getICESession();
          if (!session) return false;

          SecureByteBlockPtr packetized = response->packetize(STUNPacket::RFC_draft_RUDP);

          mICESession->sendPacket(*packetized, packetized->SizeInBytes());
        }
        return true;
      }

      //-----------------------------------------------------------------------
      void RUDPTransport::onICESocketSessionWriteReady(IICESocketSessionPtr session)
      {
        AutoRecursiveLock lock(getLock());
        for (SessionMap::iterator iter = mLocalChannelNumberSessions.begin(); iter != mLocalChannelNumberSessions.end(); ++iter) {
          (*iter).second->notifyWriteReady();
        }
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RUDPTransport => IRUDPChannelDelegateForSessionAndListener
      #pragma mark

      //-----------------------------------------------------------------------
      void RUDPTransport::onRUDPChannelStateChanged(
                                                    RUDPChannelPtr inChannel,
                                                    RUDPChannelStates state
                                                    )
      {
        UseRUDPChannelPtr channel = inChannel;

        AutoRecursiveLock lock(getLock());

        switch (state) {
          case IRUDPChannel::RUDPChannelState_Connecting: break;
          case IRUDPChannel::RUDPChannelState_Connected:
          {
            WORD channelNumber = channel->getIncomingChannelNumber();
            SessionMap::iterator found = mLocalChannelNumberSessions.find(channelNumber);
            if (found == mLocalChannelNumberSessions.end()) return;

            mRemoteChannelNumberSessions[channel->getOutgoingChannelNumber()] = channel;
            break;
          }
          case IRUDPChannel::RUDPChannelState_ShuttingDown: break;
          case IRUDPChannel::RUDPChannelState_Shutdown:
          {
            ZS_LOG_DEBUG(log("channel closed notification") + ZS_PARAM("channel ID", channel->getID()))
            for (SessionMap::iterator iter = mLocalChannelNumberSessions.begin(); iter != mLocalChannelNumberSessions.end(); ++iter)
            {
              if ((*iter).second != channel) continue;
              ZS_LOG_TRACE(log("clearing out local channel number") + ZS_PARAM("local channel number", channel->getIncomingChannelNumber()))
              mLocalChannelNumberSessions.erase(iter);
              break;
            }
            for (SessionMap::iterator iter = mRemoteChannelNumberSessions.begin(); iter != mRemoteChannelNumberSessions.end(); ++iter)
            {
              if ((*iter).second != channel) continue;
              ZS_LOG_TRACE(log("clearing out remote channel number") + ZS_PARAM("remote channel number", channel->getOutgoingChannelNumber()))
              mRemoteChannelNumberSessions.erase(iter);
              break;
            }
            for (PendingSessionList::iterator iter = mPendingSessions.begin(); iter != mPendingSessions.end(); ++iter)
            {
              if ((*iter) != channel) continue;
              ZS_LOG_TRACE(String("clearing out pending socket session"))
              mPendingSessions.erase(iter);
              break;
            }
          }
        }
        step();
      }

      //-----------------------------------------------------------------------
      bool RUDPTransport::notifyRUDPChannelSendPacket(
                                                      RUDPChannelPtr channel,
                                                      const IPAddress &remoteIP,
                                                      const BYTE *packet,
                                                      size_t packetLengthInBytes
                                                      )
      {
        IICESocketSessionPtr session = getICESession();
        if (!session) {
          ZS_LOG_WARNING(Detail, log("send packet failed as ICE session object destroyed"))
          return false;
        }

        if (ZS_IS_LOGGING(Insane)) {
          String base64 = Helper::convertToBase64(packet, packetLengthInBytes);
          ZS_LOG_INSANE(log("SEND PACKET ON WIRE") + ZS_PARAM("wire out", base64))
        }

        return session->sendPacket(packet, packetLengthInBytes);  // no need to call within a lock
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark RUDPTransport => (internal)
      #pragma mark

      //-----------------------------------------------------------------------
      RecursiveLock &RUDPTransport::getLock() const
      {
        return mLock;
      }

      //-----------------------------------------------------------------------
      Log::Params RUDPTransport::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("RUDPTransport");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params RUDPTransport::debug(const char *message) const
      {
        return Log::Params(message, toDebug());
      }

      //-----------------------------------------------------------------------
      void RUDPTransport::fix(STUNPacketPtr stun) const
      {
        stun->mLogObject = "RUDPTransport";
        stun->mLogObjectID = mID;
      }

      //-----------------------------------------------------------------------
      ElementPtr RUDPTransport::toDebug() const
      {
        AutoRecursiveLock lock(getLock());

        ElementPtr resultEl = Element::create("RUDPTransport");

        IHelper::debugAppend(resultEl, "id", mID);

        IHelper::debugAppend(resultEl, "graceful shutdown", (bool)mGracefulShutdownReference);

        IHelper::debugAppend(resultEl, "subscriptions", mSubscriptions.size());
        IHelper::debugAppend(resultEl, "default subscription", (bool)mDefaultSubscription);

        IHelper::debugAppend(resultEl, "state", IRUDPTransport::toString(mCurrentState));
        IHelper::debugAppend(resultEl, "last error", mLastError);
        IHelper::debugAppend(resultEl, "last reason", mLastErrorReason);

        IHelper::debugAppend(resultEl, "ice session", mICESession ? mICESession->getID() : 0);
        IHelper::debugAppend(resultEl, "ice subscription", (bool)mICESubscription);

        IHelper::debugAppend(resultEl, "local channel number sessions", mLocalChannelNumberSessions.size());
        IHelper::debugAppend(resultEl, "remote channel number sessions", mRemoteChannelNumberSessions.size());

        IHelper::debugAppend(resultEl, "pending sessions", mPendingSessions.size());

        return resultEl;
      }

      //-----------------------------------------------------------------------
      void RUDPTransport::cancel()
      {
        AutoRecursiveLock lock(getLock());  // just in case
        if (isShutdown()) return;

        if (!mGracefulShutdownReference) mGracefulShutdownReference = mThisWeak.lock();

        setState(RUDPTransportState_ShuttingDown);

        for (SessionMap::iterator iter = mLocalChannelNumberSessions.begin(); iter != mLocalChannelNumberSessions.end(); ++iter) {

          switch (get(mLastError)) {
            case IICESocketSession::ICESocketSessionShutdownReason_None:    (*iter).second->shutdown(); break;
            default:                                                        (*iter).second->shutdownFromTimeout(); break;
          }
        }

        if (mGracefulShutdownReference) {
          if (mLocalChannelNumberSessions.size() > 0) {
            ZS_LOG_DEBUG(log("waiting for channels to shutdown"))
            return;
          }
        }

        setState(RUDPTransportState_Shutdown);

        mGracefulShutdownReference.reset();

        mSubscriptions.clear();
        if (mDefaultSubscription) {
          mDefaultSubscription->cancel();
          mDefaultSubscription.reset();
        }

        if (mICESubscription) {
          mICESubscription->cancel();
          mICESubscription.reset();
        }

        mLocalChannelNumberSessions.clear();
        mRemoteChannelNumberSessions.clear();
        mPendingSessions.clear();
      }

      //-----------------------------------------------------------------------
      void RUDPTransport::step()
      {
        if ((isShuttingDown()) ||
            (isShutdown())) {
          cancel();
          return;
        }

        IICESocketSession::ICESocketSessionStates state = mICESession->getState();
        switch (state) {
          case IICESocketSession::ICESocketSessionState_Pending:
          case IICESocketSession::ICESocketSessionState_Prepared:
          case IICESocketSession::ICESocketSessionState_Searching:
          case IICESocketSession::ICESocketSessionState_Haulted:
          case IICESocketSession::ICESocketSessionState_Nominating: setState(RUDPTransportState_Pending); break;
          case IICESocketSession::ICESocketSessionState_Nominated:
          case IICESocketSession::ICESocketSessionState_Completed:  setState(RUDPTransportState_Ready); break;
          case IICESocketSession::ICESocketSessionState_Shutdown:   cancel(); break;
        }
      }

      //-----------------------------------------------------------------------
      void RUDPTransport::setState(RUDPTransportStates state)
      {
        if (state == mCurrentState) return;

        ZS_LOG_DETAIL(log("state changed") + ZS_PARAM("old state", toString(mCurrentState)) + ZS_PARAM("new state", toString(state)))

        mCurrentState = state;

        RUDPTransportPtr pThis = mThisWeak.lock();

        if (pThis) {
          mSubscriptions.delegate()->onRUDPTransportStateChanged(pThis, mCurrentState);
        }
      }

      //-----------------------------------------------------------------------
      void RUDPTransport::setError(WORD errorCode, const char *inReason)
      {
        String reason(inReason ? String(inReason) : String());
        if (reason.isEmpty()) {
          reason = IHTTP::toString(IHTTP::toStatusCode(errorCode));
        }

        if (0 != mLastError) {
          ZS_LOG_WARNING(Detail, debug("error already set thus ignoring new error") + ZS_PARAM("new error", errorCode) + ZS_PARAM("new reason", reason))
          return;
        }

        get(mLastError) = errorCode;
        mLastErrorReason = reason;

        ZS_LOG_WARNING(Detail, debug("error set") + ZS_PARAM("code", mLastError) + ZS_PARAM("reason", mLastErrorReason))
      }
      
      //-----------------------------------------------------------------------
      bool RUDPTransport::handleUnknownChannel(
                                                      STUNPacketPtr &stun,
                                                      STUNPacketPtr &response
                                                      )
      {
        AutoRecursiveLock lock(getLock());
        if ((isShuttingDown()) ||
            (isShutdown())) return false;

        if (!mICESession) return false;

        do
        {
          if (STUNPacket::Class_Indication == stun->mClass) return false;   // we don't respond to indications

          // only channel open can be used
          if (STUNPacket::Method_ReliableChannelOpen != stun->mMethod) {
            // sorry, this channel was not found therefor we discard the request
            stun->mErrorCode = STUNPacket::ErrorCode_Unauthorized;
            response = STUNPacket::createErrorResponse(stun);
            fix(response);
            break;
          }

          if ((!stun->hasAttribute(STUNPacket::Attribute_Username)) ||
              (!stun->hasAttribute(STUNPacket::Attribute_MessageIntegrity)) ||
              (!stun->hasAttribute(STUNPacket::Attribute_NextSequenceNumber)) ||
              (!stun->hasAttribute(STUNPacket::Attribute_CongestionControl)) ||
              (stun->mLocalCongestionControl.size() < 1) ||
              (stun->mRemoteCongestionControl.size() < 1)) {
            // all of these attributes are manditory otherwise the request is considered bad
            stun->mErrorCode = STUNPacket::ErrorCode_BadRequest;
            response = STUNPacket::createErrorResponse(stun);
            fix(response);
            break;
          }

          // make sure the username has the right format
          size_t pos = stun->mUsername.find(":");
          if (String::npos == pos) {
            stun->mErrorCode = STUNPacket::ErrorCode_Unauthorized;
            response = STUNPacket::createErrorResponse(stun);
            fix(response);
            break;
          }

          CryptoPP::AutoSeededRandomPool rng;
          // we have a valid nonce, we will open the channel, but first - pick an unused channel number
          UINT tries = 0;

          WORD channelNumber = 0;
          bool valid = false;
          do
          {
            ++tries;
            if (tries > OPENPEER_SERVICES_RUDPICESOCKETSESSION_MAX_ATTEMPTS_TO_FIND_FREE_CHANNEL_NUMBER) {
              stun->mErrorCode = STUNPacket::ErrorCode_InsufficientCapacity;
              response = STUNPacket::createErrorResponse(stun);
              fix(response);
              break;
            }

            rng.GenerateBlock((BYTE *)(&channelNumber), sizeof(channelNumber));
            channelNumber = (channelNumber % (OPENPEER_SERVICES_RUDPICESOCKETSESSION_CHANNEL_RANGE_END - OPENPEER_SERVICES_RUDPICESOCKETSESSION_CHANNEL_RANGE_START)) + OPENPEER_SERVICES_RUDPICESOCKETSESSION_CHANNEL_RANGE_START;

            // check to see if the channel was used for this IP before...
            SessionMap::iterator found = mLocalChannelNumberSessions.find(channelNumber);
            valid = (found == mLocalChannelNumberSessions.end());
          } while (!valid);

          if (!valid) break;

          IICESocketSession::Candidate nominatedLocal;
          IICESocketSession::Candidate nominatedRemote;
          bool hasCandidate = mICESession->getNominatedCandidateInformation(nominatedLocal, nominatedRemote);
          if (!hasCandidate) break;

          // found a useable channel number therefor create a new session
          UseRUDPChannelPtr session = UseRUDPChannel::createForRUDPTransportIncoming(
                                                                                     getAssociatedMessageQueue(),
                                                                                     mThisWeak.lock(),
                                                                                     mICESession->getConnectedRemoteIP(),
                                                                                     channelNumber,
                                                                                     mICESession->getLocalUsernameFrag(),
                                                                                     mICESession->getLocalPassword(),
                                                                                     mICESession->getRemoteUsernameFrag(),
                                                                                     mICESession->getRemotePassword(),
                                                                                     stun,
                                                                                     response
                                                                                     );
          if (!response) {
            // there must be a response or it is an error
            stun->mErrorCode = STUNPacket::ErrorCode_BadRequest;
            response = STUNPacket::createErrorResponse(stun);
            fix(response);
            break;
          }
          if (response) {
            if (STUNPacket::Class_ErrorResponse == response->mClass) {
              // do not add the session if there was an error response
              break;
            }
          }

          mLocalChannelNumberSessions[channelNumber] = session;
          mRemoteChannelNumberSessions[stun->mChannelNumber] = session;
          mPendingSessions.push_back(session);

          // inform the delegate of the new session waiting...
          mSubscriptions.delegate()->onRUDPTransportChannelWaiting(mThisWeak.lock());
        } while (false);  // using as a scope rather than as a loop

        return (bool)response;
      }

      //-----------------------------------------------------------------------
      void RUDPTransport::issueChannelConnectIfPossible()
      {
        AutoRecursiveLock lock(getLock());
        if (!isReady()) return;

        for (SessionMap::iterator iter = mLocalChannelNumberSessions.begin(); iter != mLocalChannelNumberSessions.end(); ++iter) {
          SessionMap::iterator found = mRemoteChannelNumberSessions.find((*iter).second->getOutgoingChannelNumber());
          if (found == mRemoteChannelNumberSessions.end()) {
            (*iter).second->issueConnectIfNotIssued();
          }
        }
      }
    }
    
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IRUDPTransport
    #pragma mark

    //-------------------------------------------------------------------------
    const char *IRUDPTransport::toString(RUDPTransportStates states)
    {
      switch (states) {
        case RUDPTransportState_Pending:       return "Preparing";
        case RUDPTransportState_Ready:         return "Ready";
        case RUDPTransportState_ShuttingDown:  return "Shutting down";
        case RUDPTransportState_Shutdown:      return "Shutdown";
        default: break;
      }
      return "UNDEFINED";
    }

    //-------------------------------------------------------------------------
    ElementPtr IRUDPTransport::toDebug(IRUDPTransportPtr session)
    {
      return internal::RUDPTransport::toDebug(session);
    }

    //-------------------------------------------------------------------------
    IRUDPTransportPtr IRUDPTransport::listen(
                                                           IMessageQueuePtr queue,
                                                           IICESocketSessionPtr iceSession,
                                                           IRUDPTransportDelegatePtr delegate
                                                           )
    {
      return internal::IRUDPTransportFactory::singleton().listen(queue, iceSession, delegate);
    }
  }
}
