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


#include <zsLib/MessageQueueThread.h>
#include <zsLib/Exception.h>
#include <zsLib/Socket.h>
#include <zsLib/Timer.h>
#include <ortc/services/IICESocket.h>
#include <ortc/services/IICESocketSession.h>
#include <ortc/services/IRUDPTransport.h>
#include <ortc/services/IRUDPMessaging.h>
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
using ortc::services::IHelper;
using ortc::services::IICESocket;
using ortc::services::IDNS;

static const char *gUsername = ORTC_SERVICE_TEST_TURN_USERNAME;
static const char *gPassword = ORTC_SERVICE_TEST_TURN_PASSWORD;

namespace ortc
{
  namespace services
  {
    namespace test
    {
      ZS_DECLARE_CLASS_PTR(TestRUDPICESocketCallback)

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
          turnInfo->mTURNServerUsername = gUsername;
          turnInfo->mTURNServerPassword = gPassword;

          IICESocket::STUNServerInfoPtr stunInfo = IICESocket::STUNServerInfo::create();
          stunInfo->mSTUNServer = ORTC_SERVICE_TEST_STUN_SERVER;

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
                                             )
        {
          zsLib::AutoRecursiveLock lock(mLock);
          if (socket != mSocket) return;

          switch (state) {
            case IICESocket::ICESocketState_Ready:
            {
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
        virtual void onICESocketCandidatesChanged(IICESocketPtr socket)
        {
          // ignored
        }

        //---------------------------------------------------------------------
        virtual void onRUDPTransportStateChanged(
                                                 IRUDPTransportPtr session,
                                                 RUDPTransportStates state
                                                 )
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
        virtual void onRUDPTransportChannelWaiting(IRUDPTransportPtr session)
        {
        }

        //---------------------------------------------------------------------
        virtual void onRUDPMessagingStateChanged(
                                                 IRUDPMessagingPtr session,
                                                 RUDPMessagingStates state
                                                 )
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
        virtual void onTransportStreamReaderReady(ITransportStreamReaderPtr reader)
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
        virtual void onTransportStreamWriterReady(ITransportStreamWriterPtr reader)
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
  if (!ORTC_SERVICE_TEST_RUNNING_AS_CLIENT) return;

  TESTING_INSTALL_LOGGER();

  zsLib::MessageQueueThreadPtr thread(zsLib::MessageQueueThread::createBasic());

  TestRUDPICESocketCallbackPtr testObject1 = TestRUDPICESocketCallback::create(thread, IPAddress(ORTC_SERVICE_TEST_RUDP_SERVER_IP, ORTC_SERVICE_TEST_RUDP_SERVER_PORT));

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
        testObject1->shutdown();
      }

      found = 0;
      if (testObject1->isShutdown()) ++found;

      if (found == expecting)
        break;

    } while(true);
    TESTING_CHECK(found == expecting)
  }

  testObject1.reset();

  ZS_LOG_BASIC("WAITING:      All RUDP sockets have finished. Waiting for 'bogus' events to process (10 second wait).");

  TESTING_SLEEP(10000)

  // wait for shutdown
  {
    IMessageQueue::size_type count = 0;
    do
    {
      count = thread->getTotalUnprocessedMessages();
      //    count += mThreadNeverCalled->getTotalUnprocessedMessages();
      if (0 != count)
        std::this_thread::yield();

    } while (count > 0);

    thread->waitForShutdown();
  }
  TESTING_UNINSTALL_LOGGER();
  zsLib::proxyDump();
  TESTING_EQUAL(zsLib::proxyGetTotalConstructed(), 0);
}
