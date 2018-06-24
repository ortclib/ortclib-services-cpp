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

#include <ortc/services/internal/types.h>
#include <ortc/services/IRUDPListener.h>
#include <ortc/services/internal/services_RUDPChannel.h>

#include <zsLib/Socket.h>

#include <list>
#include <map>
#include <utility>

#define ORTC_SERVICES_RUDPLISTENER_CHANNEL_RANGE_START (0x4000)
#define ORTC_SERVICES_RUDPLISTENER_CHANNEL_RANGE_END   (0x7FFF)

namespace ortc
{
  namespace services
  {
    namespace internal
    {
      interaction IRUDPChannelForRUDPListener;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // RUDPListener
      //

      class RUDPListener : public Noop,
                           public MessageQueueAssociator,
                           public IRUDPListener,
                           public ISocketDelegate,
                           public IRUDPChannelDelegateForSessionAndListener
      {
      protected:
        struct make_private {};

      public:
        friend interaction IRUDPListenerFactory;

        ZS_DECLARE_TYPEDEF_PTR(IRUDPChannelForRUDPListener, UseRUDPChannel)

        class CompareChannelPair;

        typedef IPAddress RemoteIP;
        typedef WORD ChannelNumber;
        typedef std::pair<RemoteIP, WORD> ChannelPair;
        typedef std::map<ChannelPair, UseRUDPChannelPtr, CompareChannelPair> SessionMap;

        typedef std::list<UseRUDPChannelPtr> PendingSessionList;

      public:
        RUDPListener(
                     const make_private &,
                     IMessageQueuePtr queue,
                     IRUDPListenerDelegatePtr delegate,
                     WORD port,
                     const char *realm
                     ) noexcept;

      protected:
        RUDPListener(Noop) noexcept : Noop(true), MessageQueueAssociator(IMessageQueuePtr()) {};

        void init() noexcept;

      public:
        ~RUDPListener() noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // RUDPListener => IRUDPListener
        //

        virtual PUID getID() const noexcept {return mID;}

        static RUDPListenerPtr create(
                                      IMessageQueuePtr queue,
                                      IRUDPListenerDelegatePtr delegate,
                                      WORD port,
                                      const char *realm
                                      ) noexcept;

        virtual IPAddress getListenerIP() noexcept;

        virtual RUDPListenerStates getState() const noexcept;

        virtual void shutdown() noexcept;

        virtual IRUDPChannelPtr acceptChannel(
                                              IRUDPChannelDelegatePtr delegate,
                                              ITransportStreamPtr receiveStream,
                                              ITransportStreamPtr sendStream
                                              ) noexcept;

        //---------------------------------------------------------------------
        //
        // RUDPListener => ISocketDelegate
        //

        virtual void onReadReady(SocketPtr socket);
        virtual void onWriteReady(SocketPtr socket);
        virtual void onException(SocketPtr socket);

        //---------------------------------------------------------------------
        //
        // RUDPListener => IRUDPChannelDelegateForSessionAndListener
        //

        virtual void onRUDPChannelStateChanged(
                                               RUDPChannelPtr channel,
                                               RUDPChannelStates state
                                               );

        virtual bool notifyRUDPChannelSendPacket(
                                                 RUDPChannelPtr channel,
                                                 const IPAddress &remoteIP,
                                                 const BYTE *packet,
                                                 size_t packetLengthInBytes
                                                 ) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // RUDPListener => (internal)
        //

        Log::Params log(const char *message) const noexcept;
        void fix(STUNPacketPtr stun) const noexcept;

        bool isShuttingDown() noexcept {return RUDPListenerState_ShuttingDown == mCurrentState;}
        bool isShutdown() noexcept {return RUDPListenerState_Shutdown == mCurrentState;}

        void cancel() noexcept;
        void setState(RUDPListenerStates state) noexcept;

        bool bindUDP() noexcept;

        bool sendTo(
                    const IPAddress &destination,
                    STUNPacketPtr stun
                    ) noexcept;

        bool sendTo(
                    const IPAddress &destination,
                    const BYTE *buffer,
                    size_t bufferLengthInBytes
                    ) noexcept;

        bool handledNonce(
                          const IPAddress &remoteIP,
                          STUNPacketPtr &stun,
                          STUNPacketPtr &response
                          ) noexcept;

        bool handleUnknownChannel(
                                  const IPAddress &remoteIP,
                                  STUNPacketPtr &stun,
                                  STUNPacketPtr &outResponse
                                  ) noexcept;

      public:
        //---------------------------------------------------------------------
        //
        // RUDPListener::CompareChannelPair
        //

        class CompareChannelPair { // simple comparison function
        public:
          bool operator()(const ChannelPair &op1, const ChannelPair &op2) const noexcept;
        };

      protected:
        //---------------------------------------------------------------------
        //
        // RUDPListener => (internal)
        //

        mutable RecursiveLock mLock;
        RUDPListenerWeakPtr mThisWeak;
        IRUDPListenerDelegatePtr mDelegate;
        AutoPUID mID;

        RUDPListenerPtr mGracefulShutdownReference;

        RUDPListenerStates mCurrentState {RUDPListenerState_Listening};

        WORD mBindPort;

        SocketPtr mUDPSocket;

        SessionMap mLocalChannelNumberSessions;   // local channel numbers are the channel numbers we expect to receive from the remote party
        SessionMap mRemoteChannelNumberSessions;  // remote channel numbers are the channel numbers we expect to send to the remote party

        PendingSessionList mPendingSessions;

        BYTE mMagic[16];
        String mRealm;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IRUDPListenerFactory
      //

      interaction IRUDPListenerFactory
      {
        static IRUDPListenerFactory &singleton() noexcept;

        virtual RUDPListenerPtr create(
                                       IMessageQueuePtr queue,
                                       IRUDPListenerDelegatePtr delegate,
                                       WORD port,
                                       const char *realm
                                       ) noexcept;
      };

      class RUDPListenerFactory : public IFactory<IRUDPListenerFactory> {};
    }
  }
}
