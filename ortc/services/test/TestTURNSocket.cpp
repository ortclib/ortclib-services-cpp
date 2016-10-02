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
#include <zsLib/String.h>

#include <ortc/services/ITURNSocket.h>
#include <ortc/services/STUNPacket.h>
#include <ortc/services/ISTUNDiscovery.h>

#include "config.h"
#include "testing.h"

#include <list>
#include <iostream>
#include <set>

namespace ortc { namespace services { namespace test { ZS_DECLARE_SUBSYSTEM(ortc_services_test) } } }

using zsLib::String;
using zsLib::IMessageQueue;
using zsLib::ULONG;
using zsLib::MessageQueueAssociator;
using zsLib::ISocketDelegate;
using zsLib::ITimerDelegate;
using zsLib::MessageQueueThread;
using zsLib::Seconds;
using zsLib::MessageQueueThreadPtr;

namespace ortc
{
  namespace services
  {
    namespace test
    {
      static const char *gUsername = ORTC_SERVICE_TEST_TURN_USERNAME;
      static const char *gPassword = ORTC_SERVICE_TEST_TURN_PASSWORD;

      ZS_DECLARE_CLASS_PTR(TestTURNSocketCallback)

      class TestTURNSocketCallback : public MessageQueueAssociator,
                                     public ISTUNDiscoveryDelegate,
                                     public ITURNSocketDelegate,
                                     public IDNSDelegate,
                                     public ISocketDelegate,
                                     public ITimerDelegate
      {
      public:
        typedef zsLib::PUID PUID;
        typedef zsLib::BYTE BYTE;
        typedef zsLib::WORD WORD;
        typedef zsLib::ULONG ULONG;
        typedef zsLib::Milliseconds Milliseconds;
        typedef zsLib::IPAddress IPAddress;
        typedef zsLib::Socket Socket;
        typedef zsLib::SocketPtr SocketPtr;
        typedef zsLib::MessageQueueAssociator MessageQueueAssociator;
        typedef zsLib::IMessageQueuePtr IMessageQueuePtr;
        typedef zsLib::AutoRecursiveLock AutoRecursiveLock;
        typedef zsLib::Timer Timer;
        typedef zsLib::TimerPtr TimerPtr;
        typedef zsLib::RecursiveLock RecursiveLock;

      private:
        TestTURNSocketCallback(IMessageQueuePtr queue) :
          MessageQueueAssociator(queue),
          mID(0),
          mExpectConnected(false),
          mExpectFailedToConnect(false),
          mExpectGracefulShutdown(false),
          mExpectErrorShutdown(false),
          mConnected(false),
          mFailedToConnect(false),
          mGracefulShutdown(false),
          mErrorShutdown(false),
          mShutdownCalled(false),
          mTotalReceived(0)
        {
        }

        void init(
                  WORD port,
                  const char *srvName,
                  bool resolveFirst
                  )
        {
          AutoRecursiveLock lock(mLock);

          mSocket = Socket::createUDP();

          IPAddress any(IPAddress::anyV4());
          any.setPort(port);

          mSocket->bind(any);
          mSocket->setBlocking(false);
          mSocket->setDelegate(mThisWeak.lock());

          if (resolveFirst) {
            mUDPSRVQuery = IDNS::lookupSRV(mThisWeak.lock(), srvName, "turn", "udp", 3478);
            mTCPSRVQuery = IDNS::lookupSRV(mThisWeak.lock(), srvName, "turn", "tcp", 3478);
            mSTUNSRVQuery = IDNS::lookupSRV(mThisWeak.lock(), srvName, "stun", "udp", 3478);
          } else {
            ISTUNDiscovery::CreationOptions stunOptions;
            stunOptions.mServers.push_back(String(srvName));

            mDiscovery = ISTUNDiscovery::create(getAssociatedMessageQueue(), mThisWeak.lock(), stunOptions);

            ITURNSocket::CreationOptions turnOptions;
            turnOptions.mServers.push_back(String(srvName));
            turnOptions.mUsername = gUsername;
            turnOptions.mPassword = gPassword;
            turnOptions.mLookupType = IDNS::SRVLookupType_AutoLookupAndFallbackAll;
            turnOptions.mUseChannelBinding = true;

            mTURNSocket = ITURNSocket::create(getAssociatedMessageQueue(), mThisWeak.lock(), turnOptions);
            mID = mTURNSocket->getID();
          }

          mTimer = Timer::create(mThisWeak.lock(), Milliseconds(rand()%400+200));
        }

      public:
        static TestTURNSocketCallbackPtr create(
                                                IMessageQueuePtr queue,
                                                WORD port,
                                                const char *srvName,
                                                bool resolveFirst,
                                                bool expectConnected = true,
                                                bool expectGracefulShutdown = true,
                                                bool expectErrorShutdown = false,
                                                bool expectFailedToConnect = false
                                                )
        {
          TestTURNSocketCallbackPtr pThis(new TestTURNSocketCallback(queue));
          pThis->mThisWeak = pThis;
          pThis->mExpectConnected = expectConnected;
          pThis->mExpectGracefulShutdown = expectGracefulShutdown;
          pThis->mExpectErrorShutdown = expectErrorShutdown;
          pThis->mExpectFailedToConnect = expectFailedToConnect;
          pThis->init(port, srvName, resolveFirst);
          return pThis;
        }

        ~TestTURNSocketCallback()
        {
        }

        virtual void onLookupCompleted(IDNSQueryPtr query)
        {
          TESTING_CHECK(query)
          TESTING_CHECK(query->hasResult())
          AutoRecursiveLock lock(mLock);

          if (query == mUDPSRVQuery) {
            mUDPSRVResult = query->getSRV();
            mUDPSRVQuery.reset();
          }
          if (query == mTCPSRVQuery) {
            mTCPSRVResult = query->getSRV();
            mTCPSRVQuery.reset();
          }
          if (query == mSTUNSRVQuery) {
            ISTUNDiscovery::CreationOptions stunOptions;
            stunOptions.mSRV = query->getSRV();
            mDiscovery = ISTUNDiscovery::create(getAssociatedMessageQueue(), mThisWeak.lock(), stunOptions);
            mSTUNSRVQuery.reset();
            // do not allow the routine to continue in the case STUN SRV lookup completes otherwise the TURN server could get created twice
            return;
          }

          if ((!mUDPSRVResult) ||
              (!mTCPSRVResult))
            return;

          TESTING_CHECK(!mUDPSRVQuery);
          TESTING_CHECK(!mTCPSRVQuery);

          ITURNSocket::CreationOptions turnOptions;
          turnOptions.mSRVUDP = mUDPSRVResult;
          turnOptions.mSRVTCP = mTCPSRVResult;
          turnOptions.mUsername = gUsername;
          turnOptions.mPassword = gPassword;
          turnOptions.mUseChannelBinding = true;

          mTURNSocket = ITURNSocket::create(getAssociatedMessageQueue(), mThisWeak.lock(), turnOptions);
          mID = mTURNSocket->getID();
        }

        // ITURNSocketDelegate
        virtual void handleTURNSocketReceivedPacket(
                                                    ITURNSocketPtr socket,
                                                    IPAddress source,
                                                    const BYTE *packet,
                                                    size_t packetLengthInBytes
                                                    )
        {
          AutoRecursiveLock lock(mLock);

          // see if this matches any of the expected data
          for (DataList::iterator iter = mSentData.begin(); iter != mSentData.end(); ++iter) {
            if (packetLengthInBytes == (*iter).second) {
              if (0 == memcmp(packet, (*iter).first.get(), packetLengthInBytes)) {
                // forget the data
                mSentData.erase(iter);
                ++mTotalReceived;
                return;
              }
            }
          }

          TESTING_CHECK(false); // received unknown data from the socket
        }

        virtual void onSTUNDiscoverySendPacket(
                                               ISTUNDiscoveryPtr discovery,
                                               IPAddress destination,
                                               SecureByteBlockPtr packet
                                               )
        {
          AutoRecursiveLock lock(mLock);
          if (!mSocket) return;
          TESTING_CHECK(discovery);
          TESTING_CHECK(!destination.isAddressEmpty());
          TESTING_CHECK(!destination.isPortEmpty());
          TESTING_CHECK(packet->BytePtr());
          TESTING_CHECK(packet->SizeInBytes());
          TESTING_CHECK(mSocket);

          mSocket->sendTo(destination, packet->BytePtr(), packet->SizeInBytes());
        }

        virtual void onSTUNDiscoveryCompleted(ISTUNDiscoveryPtr discovery)
        {
          AutoRecursiveLock lock(mLock);
          TESTING_CHECK(discovery);
          if (!mDiscovery) return;
          TESTING_CHECK(discovery == mDiscovery);
          TESTING_CHECK(mDiscovery);
          TESTING_CHECK(mSocket)

          mSTUNDiscoveredIP = discovery->getMappedAddress();
          mDiscovery.reset();
        }

        virtual bool notifyTURNSocketSendPacket(
                                                ITURNSocketPtr socket,
                                                IPAddress destination,
                                                const BYTE *packet,
                                                size_t packetLengthInBytes
                                                )
        {
          AutoRecursiveLock lock(mLock);
          return 0 != mSocket->sendTo(destination, packet, packetLengthInBytes);
        }

        virtual void onTURNSocketStateChanged(
                                              ITURNSocketPtr socket,
                                              TURNSocketStates state
                                              )
        {
          AutoRecursiveLock lock(mLock);
          TESTING_CHECK(socket == mTURNSocket)

          switch (state)
          {
            case ITURNSocket::TURNSocketState_Pending: break;
            case ITURNSocket::TURNSocketState_Ready: {
              onTURNSocketConnected(socket);
              break;
            }
            case ITURNSocket::TURNSocketState_ShuttingDown: break;
            case ITURNSocket::TURNSocketState_Shutdown: {
              if (!mConnected) {
                onTURNSocketFailedToConnect(socket);
              } else {
                onTURNSocketShutdown(socket);
              }
              break;
            }
          }
        }

        void onTURNSocketConnected(ITURNSocketPtr socket)
        {
          AutoRecursiveLock lock(mLock);
          TESTING_CHECK(socket == mTURNSocket)
          TESTING_CHECK(mExpectConnected)

          mConnected = true;
          mDiscoveredIP = socket->getReflectedIP();
          TESTING_CHECK(!mDiscoveredIP.isAddressEmpty())
        }

        void onTURNSocketFailedToConnect(ITURNSocketPtr socket)
        {
          AutoRecursiveLock lock(mLock);
          TESTING_CHECK(mExpectFailedToConnect)
          mFailedToConnect = true;
          mTURNSocket.reset();
        }

        void onTURNSocketShutdown(ITURNSocketPtr socket)
        {
          AutoRecursiveLock lock(mLock);
          TESTING_CHECK(socket == mTURNSocket);

          if (mShutdownCalled) {
            TESTING_CHECK(mExpectGracefulShutdown);
            mGracefulShutdown = true;
            mTURNSocket.reset();
            return;
          }

          TESTING_CHECK(mExpectErrorShutdown);
          mErrorShutdown = true;
          mTURNSocket.reset();
        }

        virtual void onTURNSocketWriteReady(ITURNSocketPtr socket)
        {
          AutoRecursiveLock lock(mLock);
        }

        virtual void onReadReady(SocketPtr socket)
        {
          AutoRecursiveLock lock(mLock);
          TESTING_CHECK(socket);
          if (!mSocket) return;
          TESTING_CHECK(socket == mSocket);
          if (!mTURNSocket) return;

          IPAddress ip;
          BYTE buffer[1500];
          size_t bufferLengthInBytes = sizeof(buffer);

          size_t readBytes = mSocket->receiveFrom(ip, &(buffer[0]), bufferLengthInBytes);
          TESTING_CHECK(readBytes > 0);

          if (mTURNSocket->handleChannelData(ip, &(buffer[0]), readBytes)) return;

          STUNPacketPtr stun = STUNPacket::parseIfSTUN(&(buffer[0]), readBytes, static_cast<STUNPacket::RFCs>(STUNPacket::RFC_5766_TURN | STUNPacket::RFC_5389_STUN));
          if (!stun) return;
          if (mTURNSocket->handleSTUNPacket(ip, stun)) return;
        }

        virtual void onWriteReady(SocketPtr socket)
        {
          //          AutoLock lock(mLock);
          //          TESTING_CHECK(socket);
          //          TESTING_CHECK(socket == mSocket);
        }

        virtual void onException(SocketPtr socket)
        {
          //          AutoLock lock(mLock);
          //          TESTING_CHECK(socket);
          //          TESTING_CHECK(socket == mSocket);
        }

        virtual void onTimer(TimerPtr timer)
        {
          AutoRecursiveLock lock(mLock);
          if (timer != mTimer) return;
          if (!mTURNSocket) return;

          if (mShutdownCalled) return;

          size_t length = (rand()%500)+1;
          std::shared_ptr<BYTE> buffer(new BYTE[length], std::default_delete<BYTE[]>());

          // fill the buffer with random data
          for (size_t loop = 0; loop < length; ++loop) {
            (buffer.get())[loop] = rand()%(sizeof(BYTE) << 8);
          }

          // send the random data to location on the internet...
          IPAddress relayedIP = mTURNSocket->getRelayedIP();
          IPAddress reflextedIP = mTURNSocket->getReflectedIP();
          if (!mSTUNDiscoveredIP.isAddressEmpty())
            reflextedIP = mSTUNDiscoveredIP;  // this will be more accurate because when using TCP-only it will not discover the port
          if (relayedIP.isAddressEmpty())
            return;
          if (reflextedIP.isAddressEmpty())
            return;

          mSocket->sendTo(relayedIP, buffer.get(), length);
          mTURNSocket->sendPacket(reflextedIP, buffer.get(), length, true);

          DataPair data(buffer, length);
          mSentData.push_back(data);
        }

        void shutdown()
        {
          AutoRecursiveLock lock(mLock);
          TESTING_CHECK(mTURNSocket);

          mTURNSocket->shutdown();

          mShutdownCalled = true;
          if (mTimer) {
            mTimer->cancel();
            mTimer.reset();
          }
        }

        bool isComplete()
        {
          AutoRecursiveLock lock(mLock);
          return (!((mUDPSRVQuery) || (mTCPSRVQuery) || (mSTUNSRVQuery) || (mTURNSocket)));
        }

        PUID getID() const
        {
          AutoRecursiveLock lock(mLock);
          return mID;
        }

        IPAddress getIP()
        {
          AutoRecursiveLock lock(mLock);
          return mDiscoveredIP;
        }

        void expectationsOkay() {
          AutoRecursiveLock lock(mLock);

          if (mExpectConnected) {
            TESTING_CHECK(mConnected);
          } else {
            TESTING_CHECK(!mConnected);
          }

          if (mExpectFailedToConnect) {
            TESTING_CHECK(mFailedToConnect);
          } else {
            TESTING_CHECK(!mFailedToConnect);
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
        }
        ULONG getTotalReceived() {
          AutoRecursiveLock lock(mLock);
          return mTotalReceived;
        }
        ULONG getTotalUnreceived() {
          AutoRecursiveLock lock(mLock);
          return mSentData.size();
        }

      private:
        mutable RecursiveLock mLock;
        PUID mID;

        TestTURNSocketCallbackWeakPtr mThisWeak;

        bool mExpectConnected;
        bool mExpectFailedToConnect;
        bool mExpectGracefulShutdown;
        bool mExpectErrorShutdown;

        bool mConnected;
        bool mFailedToConnect;
        bool mGracefulShutdown;
        bool mErrorShutdown;

        bool mShutdownCalled;

        SocketPtr mSocket;
        IDNSQueryPtr mSTUNSRVQuery;
        IDNSQueryPtr mUDPSRVQuery;
        IDNSQueryPtr mTCPSRVQuery;

        IDNS::SRVResultPtr mUDPSRVResult;
        IDNS::SRVResultPtr mTCPSRVResult;

        ITURNSocketPtr mTURNSocket;
        ISTUNDiscoveryPtr mDiscovery;

        IPAddress mDiscoveredIP;
        IPAddress mSTUNDiscoveredIP;

        TimerPtr mTimer;

        ULONG mTotalReceived;

        typedef std::pair< std::shared_ptr<BYTE>, size_t> DataPair;
        typedef std::list<DataPair> DataList;
        DataList mSentData;
      };
    }
  }
}

using ortc::services::test::TestTURNSocketCallback;
using ortc::services::test::TestTURNSocketCallbackPtr;

void doTestTURNSocket()
{
  if (!ORTC_SERVICE_TEST_DO_TURN_TEST) return;

  TESTING_INSTALL_LOGGER();

  TESTING_SLEEP(1000);

  TESTING_CHECK(String("invalid") != String(ORTC_SERVICE_TEST_TURN_PASSWORD));

  MessageQueueThreadPtr thread(MessageQueueThread::createBasic());

  zsLib::WORD port1 = 0;
  zsLib::WORD port2 = 0;
  zsLib::WORD port3 = 0;
  zsLib::WORD port4 = 0;
  zsLib::WORD port5 = 0;

  while (true)
  {
    port1 = static_cast<decltype(port1)>(5000 + (rand() % (65525 - 5000)));
    port2 = static_cast<decltype(port2)>(5000 + (rand() % (65525 - 5000)));
    port3 = static_cast<decltype(port3)>(5000 + (rand() % (65525 - 5000)));
    port4 = static_cast<decltype(port4)>(5000 + (rand() % (65525 - 5000)));
    port5 = static_cast<decltype(port5)>(5000 + (rand() % (65525 - 5000)));

    std::set<decltype(port1)> checkUnique;
    checkUnique.insert(port1);
    checkUnique.insert(port2);
    checkUnique.insert(port3);
    checkUnique.insert(port4);
    checkUnique.insert(port5);

    if (checkUnique.size() == 5) break;

    TESTING_STDOUT() << "WARNING:      Port conflict detected. Picking new port numbers.\n";
  }

  bool doTest1 = true;
  bool doTest2 = false;
  bool doTest3 = false;
  bool doTest4 = false;
  bool doTest5 = false;

  TestTURNSocketCallbackPtr testObject1 = (doTest1 ? TestTURNSocketCallback::create(thread, port1, ORTC_SERVICE_TEST_TURN_SERVER_DOMAIN, true) : TestTURNSocketCallbackPtr());
  TestTURNSocketCallbackPtr testObject2 = (doTest2 ? TestTURNSocketCallback::create(thread, port2, ORTC_SERVICE_TEST_TURN_SERVER_DOMAIN, false) : TestTURNSocketCallbackPtr());
  TestTURNSocketCallbackPtr testObject3 = (doTest3 ? TestTURNSocketCallback::create(thread, port3, "bogus." ORTC_SERVICE_TEST_TURN_SERVER_DOMAIN, false, false, false, false, true) : TestTURNSocketCallbackPtr());
  TestTURNSocketCallbackPtr testObject4 = (doTest4 ? TestTURNSocketCallback::create(thread, port4, ORTC_SERVICE_TEST_TURN_SERVER_DOMAIN_VIA_A_RECORD_1, true) : TestTURNSocketCallbackPtr());
  TestTURNSocketCallbackPtr testObject5 = (doTest5 ? TestTURNSocketCallback::create(thread, port5, ORTC_SERVICE_TEST_TURN_SERVER_DOMAIN_VIA_A_RECORD_2, false) : TestTURNSocketCallbackPtr());

  TESTING_STDOUT() << "WAITING:      Waiting for TURN testing to complete (max wait is 180 seconds).\n";

  // check to see if all DNS routines have resolved
  {
    ULONG expecting = 0;
    if (testObject1) ++expecting;
    if (testObject2) ++expecting;
    if (testObject3) ++expecting;
    if (testObject4) ++expecting;
    if (testObject5) ++expecting;

    ULONG found = 0;
    ULONG lastFound = 0;
    ULONG totalWait = 0;

    do
    {
      TESTING_SLEEP(1000)
      ++totalWait;
      if (totalWait >= 180)
        break;

      if (20 == totalWait) {
        if (testObject1) testObject1->shutdown();
        if (testObject2) testObject2->shutdown();
//        if (testObject3) testObject3->shutdown();
        if (testObject4) testObject4->shutdown();
      }

      if (120 == totalWait) {
        if (testObject5) testObject5->shutdown();
      }

      found = 0;

      if (testObject1) found += (testObject1->isComplete() ? 1 : 0);
      if (testObject2) found += (testObject2->isComplete() ? 1 : 0);
      if (testObject3) found += (testObject3->isComplete() ? 1 : 0);
      if (testObject4) found += (testObject4->isComplete() ? 1 : 0);
      if (testObject5) found += (testObject5->isComplete() ? 1 : 0);
      if (lastFound != found) {
        lastFound = found;
        TESTING_STDOUT() << "FOUND:        [" << found << "].\n";
      }

    } while(found < expecting);

    TESTING_EQUAL(found, expecting);
  }

  TESTING_STDOUT() << "WAITING:      All TURN sockets have finished. Waiting for 'bogus' events to process (10 second wait).\n";

  TESTING_SLEEP(10000)

  if (testObject1) {std::cout << "object1: [" << testObject1->getID() << "]\n";}
  if (testObject2) {std::cout << "object2: [" << testObject2->getID() << "]\n";}
  if (testObject3) {std::cout << "object3: [" << testObject3->getID() << "]\n";}
  if (testObject4) {std::cout << "object4: [" << testObject4->getID() << "]\n";}
  if (testObject5) {std::cout << "object5: [" << testObject5->getID() << "]\n";}

  if (testObject1) {
    TESTING_CHECK(!testObject1->getIP().isAddressEmpty());
    TESTING_CHECK(!testObject1->getIP().isPortEmpty());
  }
  if (testObject2) {
    TESTING_CHECK(!testObject2->getIP().isAddressEmpty());
    TESTING_CHECK(!testObject2->getIP().isPortEmpty());
  }
  if (testObject3) {
    TESTING_CHECK(testObject3->getIP().isAddressEmpty());
    TESTING_CHECK(testObject3->getIP().isPortEmpty());
  }
  if (testObject4) {
    TESTING_CHECK(!testObject4->getIP().isAddressEmpty());
    TESTING_CHECK(!testObject4->getIP().isPortEmpty());
  }
  if (testObject5) {
    TESTING_CHECK(!testObject5->getIP().isAddressEmpty());
    TESTING_CHECK(!testObject5->getIP().isPortEmpty());
  }

  if (testObject1) testObject1->expectationsOkay();
  if (testObject2) testObject2->expectationsOkay();
  if (testObject3) testObject3->expectationsOkay();
  if (testObject4) testObject4->expectationsOkay();
  if (testObject5) testObject5->expectationsOkay();

  if (testObject1) {
    TESTING_CHECK(testObject1->getTotalReceived() > 10)
    TESTING_CHECK(testObject1->getTotalUnreceived() < 10)
  }
  if (testObject2) {
    TESTING_CHECK(testObject2->getTotalReceived() > 10)
    TESTING_CHECK(testObject2->getTotalUnreceived() < 10)
  }
  if (testObject3) {
    TESTING_EQUAL(testObject3->getTotalReceived(), 0)
    TESTING_EQUAL(testObject3->getTotalUnreceived(), 0)
  }
  if (testObject4) {
    TESTING_CHECK(testObject4->getTotalReceived() > 10)
    TESTING_CHECK(testObject4->getTotalUnreceived() < 10)
  }
  if (testObject5) {
    TESTING_CHECK(testObject5->getTotalReceived() > 10)
    TESTING_CHECK(testObject5->getTotalUnreceived() < 10)
  }

#ifdef ORTC_SERVICE_TEST_WHAT_IS_MY_IP
  if (testObject1) {
    TESTING_EQUAL(testObject1->getIP().string(false), ORTC_SERVICE_TEST_WHAT_IS_MY_IP);
  }
  if (testObject2) {
    TESTING_EQUAL(testObject2->getIP().string(false), ORTC_SERVICE_TEST_WHAT_IS_MY_IP);
  }
#endif //ORTC_SERVICE_TEST_WHAT_IS_MY_IP

  testObject1.reset();
  testObject2.reset();
  testObject3.reset();
  testObject4.reset();
  testObject5.reset();

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
