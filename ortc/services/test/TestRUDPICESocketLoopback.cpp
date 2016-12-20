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
#include <ortc/services/ITransportStream.h>

#include "config.h"
#include "testing.h"

#include <set>
#include <list>
#include <iostream>
#include <algorithm>
#include <fstream>
#include <cstdio>
#include <cstring>

namespace ortc { namespace services { namespace test { ZS_DECLARE_SUBSYSTEM(ortc_services_test) } } }

using zsLib::BYTE;
using zsLib::WORD;
using zsLib::ULONG;
using zsLib::Socket;
using zsLib::SocketPtr;
using zsLib::IPAddress;
using zsLib::String;
using zsLib::string;
using zsLib::IMessageQueue;
using ortc::services::IDNS;
using ortc::services::IDNSQuery;
using ortc::services::ITURNSocket;
using ortc::services::ITURNSocketPtr;
using ortc::services::ITURNSocketDelegate;
using ortc::services::IICESocket;
using ortc::services::IICESocketDelegate;
using ortc::services::IICESocketSession;
using ortc::services::IICESocketSessionDelegate;
using ortc::services::IICESocketPtr;
using ortc::services::IRUDPTransport;
using ortc::services::IRUDPTransportPtr;
using ortc::services::IRUDPTransportDelegate;
using ortc::services::IRUDPMessaging;
using ortc::services::IRUDPMessagingPtr;
using namespace ortc::services::test;

namespace ortc
{
  namespace services
  {
    namespace test
    {
      ZS_DECLARE_CLASS_PTR(TestRUDPICESocketLoopback);

      class TestRUDPICESocketLoopback : public zsLib::MessageQueueAssociator,
                                        public IICESocketDelegate,
                                        public IRUDPTransportDelegate,
                                        public IRUDPMessagingDelegate,
                                        public ITransportStreamWriterDelegate,
                                        public ITransportStreamReaderDelegate,
                                        public zsLib::ITimerDelegate
      {
      protected:
        typedef std::list<IICESocketSessionPtr> ICESessionList;
        typedef std::list<IRUDPTransportPtr> RUDPSessionList;
        typedef std::list<IRUDPMessagingPtr> MessagingList;

      private:
        //---------------------------------------------------------------------
        TestRUDPICESocketLoopback(zsLib::IMessageQueuePtr queue) :
          zsLib::MessageQueueAssociator(queue),
          mReceiveStream(ITransportStream::create()->getReader()),
          mSendStream(ITransportStream::create()->getWriter())
        {
        }

        //---------------------------------------------------------------------
        void init(
                  WORD port,
                  const char *srvNameTURN,
                  const char *srvNameSTUN
                  )
        {
          zsLib::AutoRecursiveLock lock(getLock());

          mReceiveStreamSubscription = mReceiveStream->subscribe(mThisWeak.lock());
          mReceiveStream->notifyReaderReadyToRead();

          IICESocket::TURNServerInfoList turnServers;
          IICESocket::STUNServerInfoList stunServers;

          IICESocket::TURNServerInfoPtr turnInfo = IICESocket::TURNServerInfo::create();
          turnInfo->mTURNServer = srvNameTURN;
          turnInfo->mTURNServerUsername = ORTC_SERVICE_TEST_TURN_USERNAME;
          turnInfo->mTURNServerPassword = ORTC_SERVICE_TEST_TURN_PASSWORD;

          IICESocket::STUNServerInfoPtr stunInfo = IICESocket::STUNServerInfo::create();
          stunInfo->mSTUNServer = srvNameSTUN;

          turnServers.push_back(turnInfo);
          stunServers.push_back(stunInfo);

          mRUDPSocket = IICESocket::create(
                                           getAssociatedMessageQueue(),
                                           mThisWeak.lock(),
                                           turnServers,
                                           stunServers,
                                           port
                                           );

          mTimer = zsLib::ITimer::create(mThisWeak.lock(), zsLib::Milliseconds(rand()%400+200));
        }

      public:
        //---------------------------------------------------------------------
        static TestRUDPICESocketLoopbackPtr create(
                                                   zsLib::IMessageQueuePtr queue,
                                                   WORD port,
                                                   const char *srvNameTURN,
                                                   const char *srvNameSTUN,
                                                   bool issueConnect,
                                                   bool expectConnected = true,
                                                   bool expectGracefulShutdown = true,
                                                   bool expectErrorShutdown = false,
                                                   bool expectSessionConnected = true,
                                                   bool expectSessionClosed = true,
                                                   bool expectMessagingConnected = true,
                                                   bool expectMessagingShutdown = true
                                                   )
        {
          TestRUDPICESocketLoopbackPtr pThis(new TestRUDPICESocketLoopback(queue));
          pThis->mThisWeak = pThis;
          pThis->mIssueConnect = issueConnect;
          pThis->mExpectConnected = expectConnected;
          pThis->mExpectGracefulShutdown = expectGracefulShutdown;
          pThis->mExpectErrorShutdown = expectErrorShutdown;
          pThis->mExpectSessionConnected = expectSessionConnected;
          pThis->mExpectSessionClosed = expectSessionClosed;
          pThis->mExpectMessagingConnected = expectMessagingConnected;
          pThis->mExpectMessagingShutdown = expectMessagingShutdown;
          pThis->init(port, srvNameTURN, srvNameSTUN);
          return pThis;
        }

        //---------------------------------------------------------------------
        ~TestRUDPICESocketLoopback()
        {
          if (mTimer) {
            mTimer->cancel();
            mTimer.reset();
          }
          mICESessions.clear();
          mRUDPSessions.clear();
          mRUDPSocket.reset();
        }

        //---------------------------------------------------------------------
        virtual void onICESocketStateChanged(
                                             IICESocketPtr socket,
                                             ICESocketStates state
                                             )
        {
          zsLib::AutoRecursiveLock lock(getLock());
          switch (state) {
            case IICESocket::ICESocketState_Ready:
            {
              TESTING_CHECK(mExpectConnected);
              mConnected = true;
              break;
            }
            case IICESocket::ICESocketState_Shutdown:
            {
              if (mShutdownCalled) {
                TESTING_CHECK(mExpectGracefulShutdown);
                mGracefulShutdown = true;
              } else {
                TESTING_CHECK(mExpectErrorShutdown);
                mErrorShutdown = true;
              }
              mRUDPSocket.reset();
              break;
            }
            default:  break;
          }
        }

        //---------------------------------------------------------------------
        virtual void onICESocketCandidatesChanged(IICESocketPtr socket)
        {
          zsLib::AutoRecursiveLock lock(getLock());
          TestRUDPICESocketLoopbackPtr remote = mRemote.lock();
          if (!remote) return;

          if (!mRUDPSocket) return;

          IICESocket::CandidateList candidates;
          socket->getLocalCandidates(candidates);

          remote->updateCandidates(candidates);
        }

        //---------------------------------------------------------------------
        virtual void onRUDPTransportStateChanged(
                                                 IRUDPTransportPtr session,
                                                 RUDPTransportStates state
                                                 ) override
        {
          zsLib::AutoRecursiveLock lock(getLock());

          switch(state) {
            case IRUDPTransport::RUDPTransportState_Ready:
            {
              TESTING_CHECK(mExpectSessionConnected);
              mSessionConnected = true;

              if (IRUDPTransport::RUDPTransportState_Ready == state) {
                if (mIssueConnect) {
                  IRUDPMessagingPtr messaging = IRUDPMessaging::openChannel(
                                                                            getAssociatedMessageQueue(),
                                                                            session,
                                                                            mThisWeak.lock(),
                                                                            "bogus/text-bogus",
                                                                            mReceiveStream->getStream(),
                                                                            mSendStream->getStream()
                                                                            );
                  mMessaging.push_back(messaging);
                }
              }

              RUDPSessionList::iterator found = find(mRUDPSessions.begin(), mRUDPSessions.end(), session);
              TESTING_CHECK(found != mRUDPSessions.end())
              break;
            }
            case IRUDPTransport::RUDPTransportState_Shutdown:
            {
              TESTING_CHECK(mExpectSessionClosed);
              mSessionClosed = true;

              RUDPSessionList::iterator found = find(mRUDPSessions.begin(), mRUDPSessions.end(), session);
              TESTING_CHECK(found != mRUDPSessions.end())

              IICESocketSessionPtr iceSession = (*found)->getICESession();
              mRUDPSessions.erase(found);

              ICESessionList::iterator iceFound = find(mICESessions.begin(), mICESessions.end(), iceSession);
              TESTING_CHECK(iceFound != mICESessions.end())
              mICESessions.erase(iceFound);
            }
            default: break;
          }
        }

        //---------------------------------------------------------------------
        virtual void onRUDPTransportChannelWaiting(IRUDPTransportPtr session)
        {
          zsLib::AutoRecursiveLock lock(getLock());
          //TESTING_CHECK(mSessionConnected) // will not go to ready if not all interfaces for TURN route

          IRUDPMessagingPtr messaging = IRUDPMessaging::acceptChannel(
                                                                      getAssociatedMessageQueue(),
                                                                      session,
                                                                      mThisWeak.lock(),
                                                                      mReceiveStream->getStream(),
                                                                      mSendStream->getStream()
                                                                      );
          mMessaging.push_back(messaging);

          RUDPSessionList::iterator found = find(mRUDPSessions.begin(), mRUDPSessions.end(), session);
          TESTING_CHECK(found != mRUDPSessions.end())
        }

        //---------------------------------------------------------------------
        virtual void onRUDPMessagingStateChanged(
                                                 IRUDPMessagingPtr messaging,
                                                 RUDPMessagingStates state
                                                 )
        {
          zsLib::AutoRecursiveLock lock(getLock());
          MessagingList::iterator found = find(mMessaging.begin(), mMessaging.end(), messaging);
          TESTING_CHECK(found != mMessaging.end())
          if (IRUDPMessaging::RUDPMessagingState_Connected == state)
          {
            TESTING_CHECK(mExpectMessagingConnected)
            mMessagingConnected = true;
            if (mIssueConnect) {
              static const char *message = "(*CONTROLLING**1234567890->tuTu8afutA6HatabASPeC9epHE2aHa3efew2xEc3acRANeVamUbrUsteh9C24e5h<-0987654321)";
              mSendStream->write((const BYTE *)message, strlen(message));
            } else {
              static const char *message = "(*CONTROLLED**1234567890->tuTu8afutA6HatabASPeC9epHE2aHa3efew2xEc3acRANeVamUbrUsteh9C24e5h<-0987654321)";
              mSendStream->write((const BYTE *)message, strlen(message));
            }
          }
          if (IRUDPMessaging::RUDPMessagingState_Shutdown == state)
          {
            TESTING_CHECK(mExpectMessagingShutdown)
            mMessagingShutdown = true;
            mMessaging.erase(found);
          }
        }

        //---------------------------------------------------------------------
        virtual void onTransportStreamReaderReady(ITransportStreamReaderPtr reader)
        {
          zsLib::AutoRecursiveLock lock(getLock());

          SecureByteBlockPtr buffer = mReceiveStream->read();
          if (!buffer) return;

          size_t size = buffer->SizeInBytes();

          ZS_LOG_BASIC("---------------------------------------------------------------");
          ZS_LOG_BASIC("---------------------------------------------------------------");
          ZS_LOG_BASIC(String(mIssueConnect ? "CONTROLLING: " : "CONTROLLED: ") + ((const char *)(buffer->BytePtr())))
          ZS_LOG_BASIC("---------------------------------------------------------------");
          ZS_LOG_BASIC("---------------------------------------------------------------");

          // echo back the message to the remote party
          mSendStream->write(buffer->BytePtr(), size);
        }

        //---------------------------------------------------------------------
        virtual void onTransportStreamWriterReady(ITransportStreamWriterPtr writer)
        {
          //IGNORED
        }

        //---------------------------------------------------------------------
        virtual void onRUDPMessagingReadReady(IRUDPMessagingPtr messaging)
        {
        }

        //---------------------------------------------------------------------
        virtual void onRUDPMessagingWriteReady(IRUDPMessagingPtr messaging)
        {
          zsLib::AutoRecursiveLock lock(getLock());
        }

        //---------------------------------------------------------------------
        virtual void onTimer(zsLib::ITimerPtr timer)
        {
          zsLib::AutoRecursiveLock lock(getLock());
          if (timer != mTimer) return;
        }

        //---------------------------------------------------------------------
        void shutdown()
        {
          zsLib::AutoRecursiveLock lock(getLock());

          mRemote.reset();

          if (!mRUDPSocket) return;
          if (mShutdownCalled) return;
          mShutdownCalled = true;
          for (MessagingList::iterator iter = mMessaging.begin(); iter != mMessaging.end(); ++iter) {
            IRUDPMessagingPtr &messaging = (*iter);
            messaging->shutdown();
          }
          for (RUDPSessionList::iterator iter = mRUDPSessions.begin(); iter != mRUDPSessions.end(); ++iter) {
            IRUDPTransportPtr &session = (*iter);
            session->shutdown();
          }
          mRUDPSocket->shutdown();
          if (mTimer) {
            mTimer->cancel();
            mTimer.reset();
          }
        }

        //---------------------------------------------------------------------
        bool isComplete()
        {
          zsLib::AutoRecursiveLock lock(getLock());
          return (mExpectConnected ? true : (mExpectConnected == mConnected)) &&
                 (mExpectGracefulShutdown == mGracefulShutdown) &&
                 (mExpectErrorShutdown == mErrorShutdown) &&
                 (mExpectSessionConnected == mSessionConnected) &&
                 (mExpectSessionClosed == mSessionClosed) &&
                 (mExpectMessagingConnected == mMessagingConnected) &&
                 (mExpectMessagingShutdown == mMessagingShutdown);
        }

        void expectationsOkay() {
          zsLib::AutoRecursiveLock lock(getLock());
          if (mExpectConnected) {
//            TESTING_CHECK(mConnected);  // invalid asssumption that all IP addresses are routable to TURN
          } else {
            TESTING_CHECK(!mConnected);
          }

          if (mExpectGracefulShutdown) {
            TESTING_CHECK(mGracefulShutdown);
          } else {
            TESTING_CHECK(!mGracefulShutdown);
          }

          if (mExpectErrorShutdown) {
            TESTING_CHECK(mErrorShutdown);
          } else {
            TESTING_CHECK(!mErrorShutdown);
          }

          if (mExpectSessionConnected) {
            TESTING_CHECK(mSessionConnected);
          } else {
            TESTING_CHECK(!mSessionConnected);
          }

          if (mExpectSessionClosed) {
            TESTING_CHECK(mSessionClosed);
          } else {
            TESTING_CHECK(!mSessionClosed);
          }
          if (mExpectMessagingConnected) {
            TESTING_CHECK(mMessagingConnected);
          } else {
            TESTING_CHECK(!mMessagingConnected);
          }
          if (mExpectMessagingShutdown) {
            TESTING_CHECK(mMessagingShutdown);
          } else {
            TESTING_CHECK(!mMessagingShutdown);
          }
        }

        //---------------------------------------------------------------------
        void getLocalCandidates(IICESocket::CandidateList &outCandidates)
        {
          zsLib::AutoRecursiveLock lock(getLock());
          if (!mRUDPSocket) return;
          mRUDPSocket->getLocalCandidates(outCandidates);
        }

        //---------------------------------------------------------------------
        String getLocalUsernameFrag()
        {
          zsLib::AutoRecursiveLock lock(getLock());
          if (!mRUDPSocket) return String();
          return mRUDPSocket->getUsernameFrag();
        }

        //---------------------------------------------------------------------
        String getLocalPassword()
        {
          zsLib::AutoRecursiveLock lock(getLock());
          if (!mRUDPSocket) return String();
          return mRUDPSocket->getPassword();
        }
        
        //---------------------------------------------------------------------
        IRUDPTransportPtr createSessionFromRemoteCandidates(IICESocket::ICEControls control)
        {
          zsLib::AutoRecursiveLock lock(getLock());
          if (!mRUDPSocket) return IRUDPTransportPtr();

          TestRUDPICESocketLoopbackPtr remote = mRemote.lock();
          if (!remote) return IRUDPTransportPtr();

          String remoteUsernameFrag = remote->getLocalUsernameFrag();
          String remotePassword = remote->getLocalPassword();
          IICESocket::CandidateList remoteCandidates;
          remote->getLocalCandidates(remoteCandidates);

          IICESocketSessionPtr iceSession = IICESocketSession::create(IICESocketSessionDelegatePtr(), mRUDPSocket, remote->getLocalUsernameFrag(), remote->getLocalPassword(), remoteCandidates, control);
          mICESessions.push_back(iceSession);

          IRUDPTransportPtr rudpSession = IRUDPTransport::listen(getAssociatedMessageQueue(), iceSession, mThisWeak.lock());
          mRUDPSessions.push_back(rudpSession);

          return rudpSession;
        }

        //---------------------------------------------------------------------
        void setRemote(TestRUDPICESocketLoopbackPtr remote)
        {
          zsLib::AutoRecursiveLock lock(getLock());
          mRemote = remote;
        }

        //---------------------------------------------------------------------
        void updateCandidates(const IICESocket::CandidateList &candidates)
        {
          zsLib::AutoRecursiveLock lock(getLock());
          for (ICESessionList::iterator iter = mICESessions.begin(); iter != mICESessions.end(); ++iter)
          {
            IICESocketSessionPtr session = (*iter);
            session->updateRemoteCandidates(candidates);
          }
        }

        //---------------------------------------------------------------------
        void notifyEndOfCandidates()
        {
          zsLib::AutoRecursiveLock lock(getLock());
          for (ICESessionList::iterator iter = mICESessions.begin(); iter != mICESessions.end(); ++iter)
          {
            IICESocketSessionPtr session = (*iter);
            session->endOfRemoteCandidates();
          }
        }
        
        //---------------------------------------------------------------------
        RecursiveLock &getLock() const
        {
          static RecursiveLock lock;
          return lock;
        }

      private:
        TestRUDPICESocketLoopbackWeakPtr mThisWeak;

        TestRUDPICESocketLoopbackWeakPtr mRemote;

        ITransportStreamReaderPtr mReceiveStream;
        ITransportStreamWriterPtr mSendStream;

        ITransportStreamReaderSubscriptionPtr mReceiveStreamSubscription;

        zsLib::ITimerPtr mTimer;

        IICESocketPtr mRUDPSocket;
        ICESessionList mICESessions;
        RUDPSessionList mRUDPSessions;
        MessagingList mMessaging;

        bool mExpectConnected {};
        bool mExpectGracefulShutdown {};
        bool mExpectErrorShutdown {};
        bool mExpectSessionConnected {};
        bool mExpectSessionClosed {};
        bool mExpectMessagingConnected {};
        bool mExpectMessagingShutdown {};

        bool mIssueConnect {};

        bool mConnected {};
        bool mGracefulShutdown {};
        bool mErrorShutdown {};
        bool mSessionConnected {};
        bool mSessionClosed {};
        bool mMessagingConnected {};
        bool mMessagingShutdown {};

        bool mShutdownCalled {};
      };
    }
  }
}

using ortc::services::test::TestRUDPICESocketLoopback;
using ortc::services::test::TestRUDPICESocketLoopbackPtr;

void doTestRUDPICESocketLoopback()
{
  if (!ORTC_SERVICE_TEST_DO_RUDPICESOCKET_LOOPBACK_TEST) return;

  TESTING_INSTALL_LOGGER();

  zsLib::IMessageQueueThreadPtr thread(zsLib::IMessageQueueThread::createBasic());

  TestRUDPICESocketLoopbackPtr testObject1;
  TestRUDPICESocketLoopbackPtr testObject2;
  TestRUDPICESocketLoopbackPtr testObject3;
  TestRUDPICESocketLoopbackPtr testObject4;

  IICESocket::CandidateList candidates1;
  IICESocket::CandidateList candidates2;
  IICESocket::CandidateList candidates3;
  IICESocket::CandidateList candidates4;

  ZS_LOG_BASIC("WAITING:      Waiting for ICE testing to complete (max wait is 180 seconds).");

  WORD port1 = 0;
  WORD port2 = 0;
  WORD port3 = 0;
  WORD port4 = 0;

  while (true)
  {
    port1 = static_cast<decltype(port1)>(5000 + (rand() % (65525 - 5000)));
    port2 = static_cast<decltype(port2)>(5000 + (rand() % (65525 - 5000)));
    port3 = static_cast<decltype(port3)>(5000 + (rand() % (65525 - 5000)));
    port4 = static_cast<decltype(port4)>(5000 + (rand() % (65525 - 5000)));

    std::set<decltype(port1)> checkUnique;
    checkUnique.insert(port1);
    checkUnique.insert(port2);
    checkUnique.insert(port3);
    checkUnique.insert(port4);

    if (checkUnique.size() == 4) break;

    TESTING_STDOUT() << "WARNING:      Port conflict detected. Picking new port numbers.\n";
  }

  // check to see if all DNS routines have resolved
  {
    ULONG step = 0;

    do
    {
      ZS_LOG_BASIC(String("STEP:         ---------->>>>>>>>>> ") + string(step) + " <<<<<<<<<<----------")

      bool quit = false;
      ULONG expecting = 0;
      switch (step) {
        case 0: {
          expecting = 2;
          testObject1 = TestRUDPICESocketLoopback::create(thread, port1, ORTC_SERVICE_TEST_TURN_SERVER_DOMAIN, ORTC_SERVICE_TEST_STUN_SERVER_HOST, true);
          testObject2 = TestRUDPICESocketLoopback::create(thread, port2, ORTC_SERVICE_TEST_TURN_SERVER_DOMAIN, ORTC_SERVICE_TEST_STUN_SERVER_HOST, false);

          testObject1->setRemote(testObject2);
          testObject2->setRemote(testObject1);
          break;
        }
        case 1: {
          expecting = 2;
          testObject1 = TestRUDPICESocketLoopback::create(thread, port3, ORTC_SERVICE_TEST_TURN_SERVER_DOMAIN, ORTC_SERVICE_TEST_STUN_SERVER_HOST, true);
          testObject2 = TestRUDPICESocketLoopback::create(thread, port4, ORTC_SERVICE_TEST_TURN_SERVER_DOMAIN, ORTC_SERVICE_TEST_STUN_SERVER_HOST, false);

          testObject1->setRemote(testObject2);
          testObject2->setRemote(testObject1);
          break;
        }
        default: quit = true; break;
      }
      if (quit) break;

      ULONG found = 0;
      ULONG lastFound = 0;
      ULONG totalWait = 0;

      while (found < expecting)
      {
        TESTING_SLEEP(1000)
        ++totalWait;
        if (totalWait >= 70)
          break;

        found = 0;

        switch (step) {
          case 0: {
            if (1 == totalWait) {
              testObject1->createSessionFromRemoteCandidates(IICESocket::ICEControl_Controlling);
              testObject2->createSessionFromRemoteCandidates(IICESocket::ICEControl_Controlled);
            }

            if (30 == totalWait) {
              testObject1->shutdown();
              testObject2->shutdown();
            }
            break;
          }
          case 1: {
            if (1 == totalWait) {
              testObject1->createSessionFromRemoteCandidates(IICESocket::ICEControl_Controlling);
              testObject2->createSessionFromRemoteCandidates(IICESocket::ICEControl_Controlling);
            }

            if (50 == totalWait) {
              testObject1->shutdown();
              testObject2->shutdown();
            }
            break;
          }
        }

        found += (testObject1 ? (testObject1->isComplete() ? 1 : 0) : 0);
        found += (testObject2 ? (testObject2->isComplete() ? 1 : 0) : 0);
        found += (testObject3 ? (testObject3->isComplete() ? 1 : 0) : 0);
        found += (testObject4 ? (testObject4->isComplete() ? 1 : 0) : 0);

        switch (step) {
          case 0: {
            break;
          }
          case 1: {
            break;
          }
        }

        if (lastFound != found) {
          lastFound = found;
          TESTING_STDOUT() << "FOUND:        [" << found << "].\n";
        }
      }
      TESTING_EQUAL(found, expecting);

      switch (step) {
        case 0: {
          testObject1->expectationsOkay();
          testObject2->expectationsOkay();

          break;
        }
        case 1: {
          testObject1->expectationsOkay();
          testObject2->expectationsOkay();
          break;
        }
      }
      testObject1.reset();
      testObject2.reset();
      testObject3.reset();
      testObject4.reset();

      ++step;
    } while (true);
  }

  ZS_LOG_BASIC("WAITING:      All ICE sockets have finished. Waiting for 'bogus' events to process (20 second wait).");

  TESTING_SLEEP(20000)

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
