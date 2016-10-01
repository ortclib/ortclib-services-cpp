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
#include <ortc/services/ISTUNDiscovery.h>

#include "config.h"
#include "testing.h"

#include <list>
#include <iostream>

namespace ortc { namespace services { namespace test { ZS_DECLARE_SUBSYSTEM(ortc_services_test) } } }

using zsLib::BYTE;
using zsLib::WORD;
using zsLib::ULONG;
using zsLib::Socket;
using zsLib::SocketPtr;
using zsLib::IPAddress;
using zsLib::IMessageQueue;
using ortc::services::IDNS;
using ortc::services::IDNSQuery;
using ortc::services::ISTUNDiscovery;
using ortc::services::ISTUNDiscoveryPtr;
using ortc::services::ISTUNDiscoveryDelegate;

namespace ortc
{
  namespace services
  {
    namespace test
    {
      ZS_DECLARE_CLASS_PTR(TestSTUNDiscoveryCallback)

      class TestSTUNDiscoveryCallback : public zsLib::MessageQueueAssociator,
                                        public ISTUNDiscoveryDelegate,
                                        public IDNSDelegate,
                                        public zsLib::ISocketDelegate
      {
      private:
        TestSTUNDiscoveryCallback(zsLib::IMessageQueuePtr queue) :
          zsLib::MessageQueueAssociator(queue)
        {
        }

        void init(
                  WORD port,
                  const char *srvName,
                  bool resolveFirst
                  )
        {
          zsLib::AutoLock lock(mLock);
          mSocket = Socket::createUDP();

          IPAddress any(IPAddress::anyV4());
          any.setPort(port);

          mSocket->bind(any);
          mSocket->setBlocking(false);
          mSocket->setDelegate(mThisWeak.lock());

          if (resolveFirst) {
            mSRVQuery = IDNS::lookupSRV(mThisWeak.lock(), srvName, "stun", "udp", 3478);
          } else {
            ISTUNDiscovery::CreationOptions stunOptions;
            stunOptions.mServers.push_back(String(srvName));
            mDiscovery = ISTUNDiscovery::create(getAssociatedMessageQueue(), mThisWeak.lock(), stunOptions);
          }
        }

      public:
        static TestSTUNDiscoveryCallbackPtr create(
                                                   zsLib::IMessageQueuePtr queue,
                                                   WORD port,
                                                   const char *srvName,
                                                   bool resolveFirst
                                                   )
        {
          TestSTUNDiscoveryCallbackPtr pThis(new TestSTUNDiscoveryCallback(queue));
          pThis->mThisWeak = pThis;
          pThis->init(port, srvName, resolveFirst);
          return pThis;
        }

        virtual void onLookupCompleted(IDNSQueryPtr query)
        {
          zsLib::AutoLock lock(mLock);
          TESTING_CHECK(((bool)query));
          TESTING_CHECK(query->hasResult());

          TESTING_CHECK(query == mSRVQuery);
          TESTING_CHECK(mSRVQuery);

          ISTUNDiscovery::CreationOptions stunOptions;
          stunOptions.mSRV = query->getSRV();

          mDiscovery = ISTUNDiscovery::create(getAssociatedMessageQueue(), mThisWeak.lock(), stunOptions);
          mSRVQuery.reset();
        }

        ~TestSTUNDiscoveryCallback()
        {
        }

        virtual void onSTUNDiscoverySendPacket(
                                               ISTUNDiscoveryPtr discovery,
                                               zsLib::IPAddress destination,
                                               SecureByteBlockPtr packet
                                               )
        {
          zsLib::AutoLock lock(mLock);
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
          zsLib::AutoLock lock(mLock);
          TESTING_CHECK(discovery);
          if (!mDiscovery) return;
          TESTING_CHECK(discovery == mDiscovery);
          TESTING_CHECK(mDiscovery);
          TESTING_CHECK(mSocket)

          mDiscoveredIP = discovery->getMappedAddress();
          mDiscovery.reset();
          mSocket->close();
          mSocket.reset();
        }

        virtual void onReadReady(SocketPtr socket)
        {
          zsLib::AutoLock lock(mLock);
          TESTING_CHECK(socket);
          if (!mSocket) return;
          TESTING_CHECK(socket == mSocket);
          TESTING_CHECK(mDiscovery);

          IPAddress ip;
          BYTE buffer[1500];
          size_t bufferLengthInBytes = sizeof(buffer);

          size_t readBytes = mSocket->receiveFrom(ip, &(buffer[0]), bufferLengthInBytes);
          TESTING_CHECK(readBytes > 0)

          ISTUNDiscovery::handlePacket(ip, &(buffer[0]), readBytes);
        }

        virtual void onWriteReady(SocketPtr socket)
        {
//          zsLib::AutoLock lock(mLock);
//          TESTING_CHECK(socket);
//          TESTING_CHECK(socket == mSocket);
        }

        virtual void onException(SocketPtr socket)
        {
//          zsLib::AutoLock lock(mLock);
//          TESTING_CHECK(socket);
//          TESTING_CHECK(socket == mSocket);
        }

        bool isComplete()
        {
          zsLib::AutoLock lock(mLock);
          return (!((mSRVQuery) || (mDiscovery)));
        }

        zsLib::IPAddress getIP()
        {
          zsLib::AutoLock lock(mLock);
          return mDiscoveredIP;
        }

      private:
        mutable zsLib::Lock mLock;
        TestSTUNDiscoveryCallbackWeakPtr mThisWeak;

        SocketPtr mSocket;
        IDNSQueryPtr mSRVQuery;
        ISTUNDiscoveryPtr mDiscovery;

        IPAddress mDiscoveredIP;
      };

    }
  }
}

using ortc::services::test::TestSTUNDiscoveryCallback;
using ortc::services::test::TestSTUNDiscoveryCallbackPtr;

void doTestSTUNDiscovery()
{
  if (!ORTC_SERVICE_TEST_DO_STUN_TEST) return;

  TESTING_INSTALL_LOGGER();

  zsLib::MessageQueueThreadPtr thread(zsLib::MessageQueueThread::createBasic());

  TestSTUNDiscoveryCallbackPtr testObject = TestSTUNDiscoveryCallback::create(thread, 45123, ORTC_SERVICE_TEST_STUN_SERVER, true);
  TestSTUNDiscoveryCallbackPtr testObject2 = TestSTUNDiscoveryCallback::create(thread, 45127, ORTC_SERVICE_TEST_STUN_SERVER, false);

  TESTING_STDOUT() << "WAITING:      Waiting for STUN discovery to complete (max wait is 180 seconds).\n";

  // check to see if all DNS routines have resolved
  {
    ULONG expecting = 2;

    ULONG found = 0;
    ULONG lastFound = 0;
    ULONG totalWait = 0;

    do
    {
      TESTING_SLEEP(1000)
      ++totalWait;
      if (totalWait >= 180)
        break;

      found = 0;

      found += (testObject->isComplete() ? 1 : 0);
      found += (testObject2->isComplete() ? 1 : 0);

      if (lastFound != found) {
        lastFound = found;
        std::cout << "FOUND:        [" << found << "].\n";
      }

    } while(found < expecting);

    TESTING_EQUAL(found, expecting);
  }

  TESTING_STDOUT() << "WAITING:      All STUN discoveries have finished. Waiting for 'bogus' events to process (10 second wait).\n";
  
  TESTING_SLEEP(10000)

  TESTING_CHECK(!testObject->getIP().isAddressEmpty());
  TESTING_CHECK(!testObject->getIP().isPortEmpty());

  TESTING_CHECK(!testObject2->getIP().isAddressEmpty());
  TESTING_CHECK(!testObject2->getIP().isPortEmpty());

  TESTING_CHECK(testObject->getIP().isAddressEqual(testObject2->getIP()));
  TESTING_CHECK(testObject->getIP().getPort() != testObject2->getIP().getPort());

#ifdef ORTC_SERVICE_TEST_WHAT_IS_MY_IP
  TESTING_EQUAL(testObject->getIP().string(false), ORTC_SERVICE_TEST_WHAT_IS_MY_IP);
  TESTING_EQUAL(testObject2->getIP().string(false), ORTC_SERVICE_TEST_WHAT_IS_MY_IP);
#endif //ORTC_SERVICE_TEST_WHAT_IS_MY_IP

  testObject.reset();
  testObject2.reset();

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
