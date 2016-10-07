#include "pch.h"
#include "CppUnitTest.h"

#include <ortc/services/test/testing.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

void doTestBackoffRetry();
void doTestCanonicalXML();
void doTestDH();
void doTestDNS();
void doTestHelper();
void doTestICESocket();
void doTestSTUNDiscovery();
void doTestSTUNPacket();
void doTestTURNSocket();
void doTestRUDPListener();
void doTestRUDPICESocket();
void doTestRUDPICESocketLoopback();
void doTestTCPMessagingLoopback();

#if 0
TESTING_RUN_TEST_FUNC(doTestBackoffRetry)
TESTING_RUN_TEST_FUNC(doTestCanonicalXML)
TESTING_RUN_TEST_FUNC(doTestDH)
TESTING_RUN_TEST_FUNC(doTestDNS)
TESTING_RUN_TEST_FUNC(doTestHelper)
TESTING_RUN_TEST_FUNC(doTestICESocket)
TESTING_RUN_TEST_FUNC(doTestSTUNDiscovery)
TESTING_RUN_TEST_FUNC(doTestSTUNPacket)
TESTING_RUN_TEST_FUNC(doTestTURNSocket)
TESTING_RUN_TEST_FUNC(doTestRUDPICESocketLoopback)
TESTING_RUN_TEST_FUNC(doTestRUDPListener)
TESTING_RUN_TEST_FUNC(doTestRUDPICESocket)
TESTING_RUN_TEST_FUNC(doTestTCPMessagingLoopback)
#endif //0

namespace ortclib_services_Test
{
    TEST_CLASS(UnitTest_ortc_services)
    {
    public:
        TEST_METHOD(Test_BackoffRetry)
        {
          Testing::setup();
          unsigned int totalFailures = Testing::getGlobalFailedVar();

          doTestBackoffRetry();

          if (totalFailures != Testing::getGlobalFailedVar()) {
            Assert::Fail(L"BackoffRetry retry tests have failed", LINE_INFO());
          }
        }

        TEST_METHOD(Test_CanonicalXML)
        {
          Testing::setup();

          unsigned int totalFailures = Testing::getGlobalFailedVar();

          doTestCanonicalXML();

          if (totalFailures != Testing::getGlobalFailedVar()) {
            Assert::Fail(L"CanonicalXML retry tests have failed", LINE_INFO());
          }
        }

        TEST_METHOD(Test_DH)
        {
          Testing::setup();
          unsigned int totalFailures = Testing::getGlobalFailedVar();

          doTestDH();

          if (totalFailures != Testing::getGlobalFailedVar()) {
            Assert::Fail(L"DH retry tests have failed", LINE_INFO());
          }
        }

        TEST_METHOD(Test_DNS)
        {
          Testing::setup();
          unsigned int totalFailures = Testing::getGlobalFailedVar();

          doTestDNS();

          if (totalFailures != Testing::getGlobalFailedVar()) {
            Assert::Fail(L"DNS retry tests have failed", LINE_INFO());
          }
        }

        TEST_METHOD(Test_Helper)
        {
          Testing::setup();
          unsigned int totalFailures = Testing::getGlobalFailedVar();

          doTestHelper();

          if (totalFailures != Testing::getGlobalFailedVar()) {
            Assert::Fail(L"Helper retry tests have failed", LINE_INFO());
          }
        }

#if 0
        TEST_METHOD(Test_ICESocket)
        {
          Testing::setup();
          unsigned int totalFailures = Testing::getGlobalFailedVar();

          doTestICESocket();

          if (totalFailures != Testing::getGlobalFailedVar()) {
            Assert::Fail(L"ICESocket retry tests have failed", LINE_INFO());
          }
        }
#endif //0

        TEST_METHOD(Test_STUNDiscovery)
        {
          Testing::setup();
          unsigned int totalFailures = Testing::getGlobalFailedVar();

          doTestSTUNDiscovery();

          if (totalFailures != Testing::getGlobalFailedVar()) {
            Assert::Fail(L"STUNDiscovery retry tests have failed", LINE_INFO());
          }
        }

        TEST_METHOD(Test_STUNPacket)
        {
          Testing::setup();
          unsigned int totalFailures = Testing::getGlobalFailedVar();

          doTestSTUNPacket();

          if (totalFailures != Testing::getGlobalFailedVar()) {
            Assert::Fail(L"STUNPacket retry tests have failed", LINE_INFO());
          }
        }

        TEST_METHOD(Test_TURNSocket)
        {
          Testing::setup();
          unsigned int totalFailures = Testing::getGlobalFailedVar();

          doTestTURNSocket();

          if (totalFailures != Testing::getGlobalFailedVar()) {
            Assert::Fail(L"TURNSocket retry tests have failed", LINE_INFO());
          }
        }

#if 0
        TEST_METHOD(Test_RUDPICESocketLoopback)
        {
          Testing::setup();
          unsigned int totalFailures = Testing::getGlobalFailedVar();

          doTestRUDPICESocketLoopback();

          if (totalFailures != Testing::getGlobalFailedVar()) {
            Assert::Fail(L"RUDPICESocketLoopback retry tests have failed", LINE_INFO());
          }
        }

        TEST_METHOD(Test_RUDPListener)
        {
          Testing::setup();
          unsigned int totalFailures = Testing::getGlobalFailedVar();

          doTestRUDPListener();

          if (totalFailures != Testing::getGlobalFailedVar()) {
            Assert::Fail(L"RUDPListener retry tests have failed", LINE_INFO());
          }
        }

        TEST_METHOD(Test_RUDPICESocket)
        {
          Testing::setup();
          unsigned int totalFailures = Testing::getGlobalFailedVar();

          doTestRUDPICESocket();

          if (totalFailures != Testing::getGlobalFailedVar()) {
            Assert::Fail(L"RUDPICESocket retry tests have failed", LINE_INFO());
          }
        }
#endif //0

        TEST_METHOD(Test_TCPMessagingLoopback)
        {
          Testing::setup();
          unsigned int totalFailures = Testing::getGlobalFailedVar();

          doTestTCPMessagingLoopback();

          if (totalFailures != Testing::getGlobalFailedVar()) {
            Assert::Fail(L"TCPMessagingLoopback retry tests have failed", LINE_INFO());
          }
        }
    };
}
