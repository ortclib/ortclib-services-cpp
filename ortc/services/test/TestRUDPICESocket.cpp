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


#include <zsLib/IMessageQueueThread.h>
#include <zsLib/Exception.h>
#include <zsLib/Socket.h>
#include <zsLib/ITimer.h>
#include <ortc/services/IICESocket.h>
#include <ortc/services/IICESocketSession.h>
#include <ortc/services/IRUDPTransport.h>
#include <ortc/services/IRUDPMessaging.h>
#include <ortc/services/IRUDPListener.h>
#include <ortc/services/ITransportStream.h>
#include <ortc/services/IHelper.h>


#include "config.h"
#include "testing.h"

namespace ortc { namespace services { namespace test { ZS_DECLARE_SUBSYSTEM(ortc_services_test) } } }

using zsLib::BYTE;
using zsLib::WORD;
using zsLib::ULONG;
using zsLib::CSTR;
using zsLib::Socket;
using zsLib::SocketPtr;
using zsLib::IPAddress;
using zsLib::AutoRecursiveLock;
using zsLib::IMessageQueue;
using ortc::services::IICESocket;
using ortc::services::IICESocketPtr;
using ortc::services::IICESocketDelegate;
using ortc::services::IICESocketSession;
using ortc::services::IICESocketSessionPtr;
using ortc::services::IICESocketSessionDelegate;
using ortc::services::IRUDPMessaging;
using ortc::services::IRUDPMessagingPtr;
using ortc::services::IRUDPMessagingDelegate;
using ortc::services::IRUDPListenerDelegate;
using ortc::services::IHelper;
using ortc::services::IICESocket;
using ortc::services::IDNS;

namespace ortc
{
  namespace services
  {
    namespace test
    {
      ZS_DECLARE_CLASS_PTR(TestRUDPListenerCallback);
      ZS_DECLARE_CLASS_PTR(TestRUDPICESocketCallback);

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark TestRUDPListenerCallback 
      #pragma mark

      class TestRUDPListenerCallback : public zsLib::MessageQueueAssociator,
                                       public IRUDPListenerDelegate,
                                       public IRUDPMessagingDelegate,
                                       public ITransportStreamWriterDelegate,
                                       public ITransportStreamReaderDelegate
      {
      private:
        //---------------------------------------------------------------------
        TestRUDPListenerCallback(zsLib::IMessageQueuePtr queue) :
          zsLib::MessageQueueAssociator(queue),
          mReceiveStream(ITransportStream::create()->getReader()),
          mSendStream(ITransportStream::create()->getWriter())
        {
        }

        //---------------------------------------------------------------------
        void init(WORD port)
        {
          AutoRecursiveLock lock(mLock);
          mListener = IRUDPListener::create(getAssociatedMessageQueue(), mThisWeak.lock(), port);

          mReceiveStream->notifyReaderReadyToRead();
          mReceiveStreamSubscription = mReceiveStream->subscribe(mThisWeak.lock());
        }

      public:
        //---------------------------------------------------------------------
        static TestRUDPListenerCallbackPtr create(
          zsLib::IMessageQueuePtr queue,
          WORD port
        )
        {
          TestRUDPListenerCallbackPtr pThis(new TestRUDPListenerCallback(queue));
          pThis->mThisWeak = pThis;
          pThis->init(port);
          return pThis;
        }

        //---------------------------------------------------------------------
        ~TestRUDPListenerCallback()
        {
        }

        //---------------------------------------------------------------------
        virtual void onRUDPListenerStateChanged(
          IRUDPListenerPtr listener,
          RUDPListenerStates state
        )
        {
          AutoRecursiveLock lock(mLock);
        }

        //---------------------------------------------------------------------
        virtual void onRUDPListenerChannelWaiting(IRUDPListenerPtr listener)
        {
          zsLib::AutoRecursiveLock lock(mLock);
          mMessaging = IRUDPMessaging::acceptChannel(
            getAssociatedMessageQueue(),
            mListener,
            mThisWeak.lock(),
            mReceiveStream->getStream(),
            mSendStream->getStream()
          );

        }

        //---------------------------------------------------------------------
        virtual void onRUDPMessagingStateChanged(
          IRUDPMessagingPtr session,
          RUDPMessagingStates state
        )
        {
        }

        //---------------------------------------------------------------------
        virtual void onTransportStreamReaderReady(ITransportStreamReaderPtr reader)
        {
          AutoRecursiveLock lock(mLock);
          if (reader != mReceiveStream) return;

          while (true) {
            SecureByteBlockPtr buffer = mReceiveStream->read();
            if (!buffer) return;

            zsLib::String str = (CSTR)(buffer->BytePtr());
            ZS_LOG_BASIC("-------------------------------------------------------------------------------")
              ZS_LOG_BASIC("-------------------------------------------------------------------------------")
              ZS_LOG_BASIC("-------------------------------------------------------------------------------")
              ZS_LOG_BASIC(zsLib::String("RECEIVED: \"") + str + "\"")
              ZS_LOG_BASIC("-------------------------------------------------------------------------------")
              ZS_LOG_BASIC("-------------------------------------------------------------------------------")
              ZS_LOG_BASIC("-------------------------------------------------------------------------------")

              zsLib::String add = "(SERVER->" + IHelper::randomString(10) + ")";

            size_t messageSize = buffer->SizeInBytes() - sizeof(char);

            size_t newMessageSize = messageSize + add.length();
            SecureByteBlockPtr newBuffer(new SecureByteBlock(newMessageSize));

            memcpy(newBuffer->BytePtr(), buffer->BytePtr(), messageSize);
            memcpy(newBuffer->BytePtr() + messageSize, (const zsLib::BYTE *)(add.c_str()), add.length());

            mSendStream->write(newBuffer);
          }
        }

        //---------------------------------------------------------------------
        virtual void onTransportStreamWriterReady(ITransportStreamWriterPtr writer)
        {
          // IGNORED
        }

      private:
        mutable zsLib::RecursiveLock mLock;
        TestRUDPListenerCallbackWeakPtr mThisWeak;

        IRUDPMessagingPtr mMessaging;
        IRUDPListenerPtr mListener;

        ITransportStreamReaderPtr mReceiveStream;
        ITransportStreamWriterPtr mSendStream;

        ITransportStreamReaderSubscriptionPtr mReceiveStreamSubscription;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark TestRUDPListenerCallback 
      #pragma mark

      class TestRUDPICESocketCallback : public zsLib::MessageQueueAssociator,
                                        public IICESocketDelegate,
                                        public IRUDPMessagingDelegate,
                                        public IRUDPTransportDelegate,
                                        public ITransportStreamWriterDelegate,
                                        public ITransportStreamReaderDelegate
      {
      private:
        //---------------------------------------------------------------------
        TestRUDPICESocketCallback(
                                  zsLib::IMessageQueuePtr queue,
                                  const zsLib::IPAddress &serverIP
                                  ) :
          zsLib::MessageQueueAssociator(queue),
          mReceiveStream(ITransportStream::create()->getReader()),
          mSendStream(ITransportStream::create()->getWriter()),
          mServerIP(serverIP),
          mSocketShutdown(false),
          mSessionShutdown(false),
          mMessagingShutdown(false)
        {
        }

        //---------------------------------------------------------------------
        void init()
        {
          zsLib::AutoRecursiveLock lock(mLock);

          mReceiveStreamSubscription = mReceiveStream->subscribe(mThisWeak.lock());
          mReceiveStream->notifyReaderReadyToRead();

          IICESocket::TURNServerInfoList turnServers;
          IICESocket::STUNServerInfoList stunServers;

          IICESocket::TURNServerInfoPtr turnInfo = IICESocket::TURNServerInfo::create();
          turnInfo->mTURNServer = ORTC_SERVICE_TEST_TURN_SERVER_DOMAIN;
          turnInfo->mTURNServerUsername = ORTC_SERVICE_TEST_TURN_USERNAME;
          turnInfo->mTURNServerPassword = ORTC_SERVICE_TEST_TURN_PASSWORD;

          IICESocket::STUNServerInfoPtr stunInfo = IICESocket::STUNServerInfo::create();
          stunInfo->mSTUNServer = ORTC_SERVICE_TEST_STUN_SERVER_HOST;

          turnServers.push_back(turnInfo);
          stunServers.push_back(stunInfo);

          mSocket = IICESocket::create(
                                       getAssociatedMessageQueue(),
                                       mThisWeak.lock(),
                                       turnServers,
                                       stunServers
                                       );
        }

      public:
        //---------------------------------------------------------------------
        static TestRUDPICESocketCallbackPtr create(
                                                   zsLib::IMessageQueuePtr queue,
                                                   zsLib::IPAddress serverIP
                                                   )
        {
          TestRUDPICESocketCallbackPtr pThis(new TestRUDPICESocketCallback(queue, serverIP));
          pThis->mThisWeak = pThis;
          pThis->init();
          return pThis;
        }

        //---------------------------------------------------------------------
        ~TestRUDPICESocketCallback()
        {
        }

        //---------------------------------------------------------------------
        void shutdown()
        {
          zsLib::AutoRecursiveLock lock(mLock);
          mSocket->shutdown();
        }

        //---------------------------------------------------------------------
        bool isShutdown()
        {
          zsLib::AutoRecursiveLock lock(mLock);
          return mSocketShutdown && mSessionShutdown && mMessagingShutdown;
        }

        //---------------------------------------------------------------------
        virtual void onICESocketStateChanged(
                                             IICESocketPtr socket,
                                             ICESocketStates state
                                             ) override
        {
          zsLib::AutoRecursiveLock lock(mLock);
          if (socket != mSocket) return;

          switch (state) {
            case IICESocket::ICESocketState_Sleeping:
            case IICESocket::ICESocketState_Ready:
            {
              if (mSocketSession) break;  // already created
              
              IICESocket::CandidateList candidates;
              IICESocket::Candidate candidate;
              candidate.mType = IICESocket::Type_Local;
              candidate.mIPAddress = mServerIP;
              candidate.mPriority = 0;
              candidate.mLocalPreference = 0;

              candidates.push_back(candidate);

              mSocketSession = IICESocketSession::create(
                                                         IICESocketSessionDelegatePtr(),
                                                         mSocket,
                                                         "serverUsernameFrag",
                                                         NULL,
                                                         candidates,
                                                         IICESocket::ICEControl_Controlling
                                                         );
              mSocketSession->endOfRemoteCandidates();

              mRUDPTransport = IRUDPTransport::listen(getAssociatedMessageQueue(), mSocketSession, mThisWeak.lock());

              break;
            }
            case IICESocket::ICESocketState_Shutdown:
            {
              mSocketShutdown = true;
              break;
            }
            default: break;
          }
        }
        
        //---------------------------------------------------------------------
        virtual void onICESocketCandidatesChanged(IICESocketPtr socket) override
        {
          // ignored
        }

        //---------------------------------------------------------------------
        virtual void onRUDPTransportStateChanged(
                                                 IRUDPTransportPtr session,
                                                 RUDPTransportStates state
                                                 ) override
        {
          zsLib::AutoRecursiveLock lock(mLock);
          if (IRUDPTransport::RUDPTransportState_Ready == state) {
            mMessaging = IRUDPMessaging::openChannel(
                                                     getAssociatedMessageQueue(),
                                                     mRUDPTransport,
                                                     mThisWeak.lock(),
                                                     "bogus/text-bogus",
                                                     mReceiveStream->getStream(),
                                                     mSendStream->getStream()
                                                     );
          }
          if (IRUDPTransport::RUDPTransportState_Ready == state) {
            mSessionShutdown = true;
          }
        }

        //---------------------------------------------------------------------
        virtual void onRUDPTransportChannelWaiting(IRUDPTransportPtr session) override
        {
        }

        //---------------------------------------------------------------------
        virtual void onRUDPMessagingStateChanged(
                                                 IRUDPMessagingPtr session,
                                                 RUDPMessagingStates state
                                                 ) override
        {
          zsLib::AutoRecursiveLock lock(mLock);

          if (IRUDPMessaging::RUDPMessagingState_Connected == state) {
            mSendStream->write((const BYTE *)"*HELLO*", strlen("*HELLO*"));
          }
          if (IRUDPMessaging::RUDPMessagingState_Shutdown == state) {
            mMessagingShutdown = true;
          }
        }

        //---------------------------------------------------------------------
        virtual void onTransportStreamReaderReady(ITransportStreamReaderPtr reader) override
        {
          zsLib::AutoRecursiveLock lock(mLock);
          if (reader != mReceiveStream) return;

          while (true) {
            SecureByteBlockPtr buffer = mReceiveStream->read();
            if (!buffer) return;

            size_t messageSize = buffer->SizeInBytes() - sizeof(char);

            zsLib::String str = (CSTR)(buffer->BytePtr());
            ZS_LOG_BASIC("-------------------------------------------------------------------------------")
            ZS_LOG_BASIC("-------------------------------------------------------------------------------")
            ZS_LOG_BASIC("-------------------------------------------------------------------------------")
            ZS_LOG_BASIC(zsLib::String("RECEIVED: \"") + str + "\"")
            ZS_LOG_BASIC("-------------------------------------------------------------------------------")
            ZS_LOG_BASIC("-------------------------------------------------------------------------------")
            ZS_LOG_BASIC("-------------------------------------------------------------------------------")

            zsLib::String add = "<SOCKET->" + IHelper::randomString(1000) + ">";

            size_t newMessageSize = messageSize + add.length();
            SecureByteBlockPtr newBuffer(new SecureByteBlock(newMessageSize));

            memcpy(newBuffer->BytePtr(), buffer->BytePtr(), messageSize);
            memcpy(newBuffer->BytePtr() + messageSize, (const zsLib::BYTE *)(add.c_str()), add.length());
            
            mSendStream->write(newBuffer);
          }
        }

        //---------------------------------------------------------------------
        virtual void onTransportStreamWriterReady(ITransportStreamWriterPtr reader) override
        {
          // IGNORED
        }

      private:
        mutable zsLib::RecursiveLock mLock;
        TestRUDPICESocketCallbackWeakPtr mThisWeak;

        ITransportStreamReaderPtr mReceiveStream;
        ITransportStreamWriterPtr mSendStream;

        ITransportStreamReaderSubscriptionPtr mReceiveStreamSubscription;

        zsLib::IPAddress mServerIP;

        bool mSocketShutdown;
        bool mSessionShutdown;
        bool mMessagingShutdown;

        IICESocketPtr mSocket;
        IICESocketSessionPtr mSocketSession;
        IRUDPTransportPtr mRUDPTransport;
        IRUDPMessagingPtr mMessaging;
      };
    }
  }
}

using namespace ortc::services::test;
using ortc::services::test::TestRUDPICESocketCallback;
using ortc::services::test::TestRUDPICESocketCallbackPtr;

void doTestRUDPICESocket()
{
  if (!ORTC_SERVICE_TEST_DO_RUDPICESOCKET_CLIENT_TO_SERVER_TEST) return;
  if ((!ORTC_SERVICE_TEST_RUNNING_RUDP_LOCAL_CLIENT) &&
      (!ORTC_SERVICE_TEST_RUNNING_RUDP_LOCAL_SERVER)) return;

  TESTING_INSTALL_LOGGER();

  zsLib::IMessageQueueThreadPtr threadClient(zsLib::IMessageQueueThread::createBasic());
  zsLib::IMessageQueueThreadPtr threadServer(ORTC_SERVICE_TEST_RUNNING_RUDP_LOCAL_SERVER ? zsLib::IMessageQueueThread::createBasic() : zsLib::IMessageQueueThreadPtr());

  TestRUDPListenerCallbackPtr testObjectServer(ORTC_SERVICE_TEST_RUNNING_RUDP_LOCAL_SERVER ? TestRUDPListenerCallback::create(threadServer, ORTC_SERVICE_TEST_RUDP_SERVER_PORT) : TestRUDPListenerCallbackPtr());

  TestRUDPICESocketCallbackPtr testObjectClient1 = TestRUDPICESocketCallback::create(threadClient, IPAddress(ORTC_SERVICE_TEST_RUDP_SERVER_IP, ORTC_SERVICE_TEST_RUDP_SERVER_PORT));

  ZS_LOG_BASIC("WAITING:      Waiting for RUDP ICE socket testing to complete (max wait is 60 minutes).");

  {
    int expecting = 1;
    int found = 0;

    ULONG totalWait = 0;
    do
    {
      TESTING_SLEEP(1000)
      ++totalWait;
      if (totalWait >= (10*60))
        break;

      if ((4*60 + 50) == totalWait) {
        testObjectClient1->shutdown();
      }

      found = 0;
      if (testObjectClient1->isShutdown()) ++found;

      if (found == expecting)
        break;

    } while(true);
    TESTING_CHECK(found == expecting)
  }

  testObjectClient1.reset();
  testObjectServer.reset();

  ZS_LOG_BASIC("WAITING:      All RUDP sockets have finished. Waiting for 'bogus' events to process (10 second wait).");

  TESTING_SLEEP(10000)

  // wait for shutdown
  {
    IMessageQueue::size_type count = 0;
    do
    {
      count = 0;
      count += threadClient->getTotalUnprocessedMessages();
      count += (threadServer ? threadServer->getTotalUnprocessedMessages() : 0);
      //    count += mThreadNeverCalled->getTotalUnprocessedMessages();
      if (0 != count)
        std::this_thread::yield();

    } while (count > 0);

    threadClient->waitForShutdown();
    if (threadServer) threadServer->waitForShutdown();
  }
  TESTING_UNINSTALL_LOGGER();
  zsLib::proxyDump();
  TESTING_EQUAL(zsLib::proxyGetTotalConstructed(), 0);
}
