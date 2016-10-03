//
//  ortclib_services_Test_iosTests.m
//  ortclib.services.Test-iosTests
//
//  Created by Robin Raymond on 2016-10-02.
//  Copyright © 2016 Open Peer Foundation. All rights reserved.
//

#import <XCTest/XCTest.h>

#include "testing.h"

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

@interface ortclib_services_Test_iosTests : XCTestCase

@end

@implementation ortclib_services_Test_iosTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)test_doTestBackoffRetry {
    // This is an example of a functional test case.
    // Use XCTAssert and related functions to verify your tests produce the correct results.
  unsigned int total = Testing::getGlobalFailedVar();

  Testing::setup();

  doTestBackoffRetry();

  XCTAssertEqual(total, (unsigned int)Testing::getGlobalFailedVar());
}

- (void)test_doTestCanonicalXML {
    // This is an example of a functional test case.
    // Use XCTAssert and related functions to verify your tests produce the correct results.
  unsigned int total = Testing::getGlobalFailedVar();

  Testing::setup();

  doTestCanonicalXML();

  XCTAssertEqual(total, (unsigned int)Testing::getGlobalFailedVar());
}

- (void)test_doTestDH {
    // This is an example of a functional test case.
    // Use XCTAssert and related functions to verify your tests produce the correct results.
  unsigned int total = Testing::getGlobalFailedVar();

  Testing::setup();

  doTestDH();

  XCTAssertEqual(total, (unsigned int)Testing::getGlobalFailedVar());
}

- (void)test_doTestDNS {
  // This is an example of a functional test case.
  // Use XCTAssert and related functions to verify your tests produce the correct results.
  unsigned int total = Testing::getGlobalFailedVar();

  Testing::setup();

  doTestDNS();

  XCTAssertEqual(total, (unsigned int)Testing::getGlobalFailedVar());
}

- (void)test_doTestHelper {
  // This is an example of a functional test case.
  // Use XCTAssert and related functions to verify your tests produce the correct results.
  unsigned int total = Testing::getGlobalFailedVar();

  Testing::setup();

  doTestHelper();

  XCTAssertEqual(total, (unsigned int)Testing::getGlobalFailedVar());
}

- (void)test_doTestICESocket {
  // This is an example of a functional test case.
  // Use XCTAssert and related functions to verify your tests produce the correct results.
  unsigned int total = Testing::getGlobalFailedVar();

  Testing::setup();

  doTestICESocket();

  XCTAssertEqual(total, (unsigned int)Testing::getGlobalFailedVar());
}

- (void)test_doTestSTUNDiscovery {
  // This is an example of a functional test case.
  // Use XCTAssert and related functions to verify your tests produce the correct results.
  unsigned int total = Testing::getGlobalFailedVar();

  Testing::setup();

  doTestSTUNDiscovery();

  XCTAssertEqual(total, (unsigned int)Testing::getGlobalFailedVar());
}

- (void)test_doTestSTUNPacket {
  // This is an example of a functional test case.
  // Use XCTAssert and related functions to verify your tests produce the correct results.
  unsigned int total = Testing::getGlobalFailedVar();

  Testing::setup();

  doTestSTUNPacket();

  XCTAssertEqual(total, (unsigned int)Testing::getGlobalFailedVar());
}

- (void)test_doTestTURNSocket {
  // This is an example of a functional test case.
  // Use XCTAssert and related functions to verify your tests produce the correct results.
  unsigned int total = Testing::getGlobalFailedVar();

  Testing::setup();

  doTestTURNSocket();

  XCTAssertEqual(total, (unsigned int)Testing::getGlobalFailedVar());
}

- (void)test_doTestRUDPICESocketLoopback {
  // This is an example of a functional test case.
  // Use XCTAssert and related functions to verify your tests produce the correct results.
  unsigned int total = Testing::getGlobalFailedVar();

  Testing::setup();

  doTestRUDPICESocketLoopback();

  XCTAssertEqual(total, (unsigned int)Testing::getGlobalFailedVar());
}

- (void)test_doTestRUDPListener {
  // This is an example of a functional test case.
  // Use XCTAssert and related functions to verify your tests produce the correct results.
  unsigned int total = Testing::getGlobalFailedVar();

  Testing::setup();

  doTestRUDPListener();

  XCTAssertEqual(total, (unsigned int)Testing::getGlobalFailedVar());
}

- (void)test_doTestRUDPICESocket {
  // This is an example of a functional test case.
  // Use XCTAssert and related functions to verify your tests produce the correct results.
  unsigned int total = Testing::getGlobalFailedVar();

  Testing::setup();

  doTestRUDPICESocket();

  XCTAssertEqual(total, (unsigned int)Testing::getGlobalFailedVar());
}

- (void)test_doTestTCPMessagingLoopback {
  // This is an example of a functional test case.
  // Use XCTAssert and related functions to verify your tests produce the correct results.
  unsigned int total = Testing::getGlobalFailedVar();

  Testing::setup();

  doTestTCPMessagingLoopback();

  XCTAssertEqual(total, (unsigned int)Testing::getGlobalFailedVar());
}

/*
- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }];
}
*/

@end
