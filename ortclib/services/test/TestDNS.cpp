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
#include <openpeer/services/IDNS.h>
#include <openpeer/services/ISTUNDiscovery.h>

#include <openpeer/services/internal/services_DNS.h>

#include <zsLib/Socket.h>

#include "config.h"
#include "testing.h"

#include <list>

namespace openpeer { namespace services { namespace test { ZS_DECLARE_SUBSYSTEM(openpeer_services_test) } } }

using zsLib::ULONG;
using zsLib::IMessageQueue;
using openpeer::services::IDNS;
using openpeer::services::IDNSPtr;
using openpeer::services::IDNSQuery;
using openpeer::services::IDNSQueryPtr;

namespace openpeer
{
  namespace services
  {
    namespace test
    {
      ZS_DECLARE_CLASS_PTR(TestDNSFactory)

      class TestDNSFactory : public services::internal::IDNSFactory
      {
      public:
        TestDNSFactory() :
          mACount(0),
          mAAAACount(0),
          mAorAAAACount(0),
          mSRVCount(0)
        {}

        virtual IDNSQueryPtr lookupA(
                                     IDNSDelegatePtr delegate,
                                     const char *name
                                     )
        {
          ++mACount;
          return services::internal::IDNSFactory::lookupA(delegate, name);
        }

        virtual IDNSQueryPtr lookupAAAA(
                                       IDNSDelegatePtr delegate,
                                       const char *name
                                       )
        {
          ++mAAAACount;
          return services::internal::IDNSFactory::lookupAAAA(delegate, name);
        }

        virtual IDNSQueryPtr lookupAorAAAA(
                                          IDNSDelegatePtr delegate,
                                          const char *name
                                          )
        {
          ++mAorAAAACount;
          return services::internal::IDNSFactory::lookupAorAAAA(delegate, name);
        }

        virtual IDNSQueryPtr lookupSRV(
                                       IDNSDelegatePtr delegate,
                                       const char *name,
                                       const char *service,                        // e.g. stun
                                       const char *protocol,                       // e.g. udp
                                       WORD defaultPort,
                                       WORD defaultPriority,
                                       WORD defaultWeight,
                                       SRVLookupTypes lookupType
                                       )
        {
          ++mSRVCount;
          return services::internal::IDNSFactory::lookupSRV(delegate, name, service, protocol, defaultPort, defaultPriority, defaultWeight, lookupType);
        }
        
        ULONG getACount() const {return mACount;}
        ULONG getAAAACount() const {return mAAAACount;}
        ULONG getAorAAAACount() const {return mAorAAAACount;}
        ULONG getSRVCount() const {return mSRVCount;}

      protected:
        ULONG mACount;
        ULONG mAAAACount;
        ULONG mAorAAAACount;
        ULONG mSRVCount;
      };

      ZS_DECLARE_CLASS_PTR(TestDNSCallback)

      class TestDNSCallback : public zsLib::MessageQueueAssociator,
                              public IDNSDelegate
      {
      private:
        TestDNSCallback(zsLib::IMessageQueuePtr queue) : zsLib::MessageQueueAssociator(queue), mCount(0)
        {
        }

      public:
        static TestDNSCallbackPtr create(zsLib::IMessageQueuePtr queue)
        {
          return TestDNSCallbackPtr(new TestDNSCallback(queue));
        }

        virtual void onLookupCompleted(IDNSQueryPtr query)
        {
          zsLib::AutoLock lock(mLock);
          ++mCount;
          TESTING_CHECK(((bool)query));

          if (!query->hasResult()) {
            mFailedResults.push_back(query);
            return;
          }

          IDNS::AResultPtr resultA = query->getA();
          IDNS::AAAAResultPtr resultAAAA = query->getAAAA();
          IDNS::SRVResultPtr resultSRV = query->getSRV();
          if (resultA) {
            mAResults.push_back(std::pair<IDNSQueryPtr, IDNS::AResultPtr>(query, resultA));
          }
          if (resultAAAA) {
            mAAAAResults.push_back(std::pair<IDNSQueryPtr, IDNS::AAAAResultPtr>(query, resultAAAA));
          }
          if (resultSRV) {
            mSRVResults.push_back(std::pair<IDNSQueryPtr, IDNS::SRVResultPtr>(query, resultSRV));
          }
        }

        ~TestDNSCallback()
        {
        }

        ULONG getTotalProcessed() const
        {
          zsLib::AutoLock lock(mLock);
          return mCount;
        }

        ULONG getTotalFailed() const
        {
          zsLib::AutoLock lock(mLock);
          return mFailedResults.size();
        }

        ULONG getTotalAProcessed() const
        {
          zsLib::AutoLock lock(mLock);
          return mAResults.size();
        }

        ULONG getTotalAAAAProcessed() const
        {
          zsLib::AutoLock lock(mLock);
          return mAAAAResults.size();
        }

        ULONG getTotalSRVProcessed() const
        {
          zsLib::AutoLock lock(mLock);
          return mSRVResults.size();
        }

        bool isFailed(IDNSQueryPtr query) const
        {
          zsLib::AutoLock lock(mLock);
          for (size_t loop = 0; loop < mFailedResults.size(); ++loop) {
            if (query.get() == mFailedResults[loop].get())
              return true;
          }
          return false;
        }

        IDNS::AResultPtr getA(IDNSQueryPtr query) const
        {
          zsLib::AutoLock lock(mLock);
          for (size_t loop = 0; loop < mAResults.size(); ++loop) {
            if (query.get() == mAResults[loop].first.get())
              return mAResults[loop].second;
          }
          return IDNS::AResultPtr();
        }

        IDNS::AAAAResultPtr getAAAA(IDNSQueryPtr query) const
        {
          zsLib::AutoLock lock(mLock);
          for (size_t loop = 0; loop < mAAAAResults.size(); ++loop) {
            if (query.get() == mAAAAResults[loop].first.get())
              return mAAAAResults[loop].second;
          }
          return IDNS::AAAAResultPtr();
        }

        IDNS::SRVResultPtr getSRV(IDNSQueryPtr query) const
        {
          zsLib::AutoLock lock(mLock);
          for (size_t loop = 0; loop < mSRVResults.size(); ++loop) {
            if (query.get() == mSRVResults[loop].first.get())
              return mSRVResults[loop].second;
          }
          return IDNS::SRVResultPtr();
        }

      private:
        mutable zsLib::Lock mLock;

        ULONG mCount;

        std::vector<IDNSQueryPtr> mFailedResults;

        std::vector< std::pair<IDNSQueryPtr, IDNS::AResultPtr> > mAResults;
        std::vector< std::pair<IDNSQueryPtr, IDNS::AAAAResultPtr> > mAAAAResults;
        std::vector< std::pair<IDNSQueryPtr, IDNS::SRVResultPtr> > mSRVResults;
      };

    }
  }
}

using openpeer::services::test::TestDNSFactory;
using openpeer::services::test::TestDNSFactoryPtr;
using openpeer::services::test::TestDNSCallback;
using openpeer::services::test::TestDNSCallbackPtr;

void doTestDNS()
{
  if (!OPENPEER_SERVICE_TEST_DO_DNS_TEST) return;

  TESTING_INSTALL_LOGGER();

  TESTING_SLEEP(1000)

  TestDNSFactoryPtr overrideFactory(new TestDNSFactory);

  openpeer::services::internal::DNSFactory::override(overrideFactory);

  zsLib::MessageQueueThreadPtr thread(zsLib::MessageQueueThread::createBasic());

  TestDNSCallbackPtr testObject = TestDNSCallback::create(thread);

#ifdef WINRT
#define WARNING_WINRT_DOES_NOT_RESOLVE_AAAA 1
#define WARNING_WINRT_DOES_NOT_RESOLVE_AAAA 2
#endif //WINRT

  IDNSQueryPtr query = IDNS::lookupA(testObject, "www." OPENPEER_SERVICE_TEST_DNS_ZONE);
  IDNSQueryPtr query2 = IDNS::lookupA(testObject, "sip." OPENPEER_SERVICE_TEST_DNS_ZONE);
#ifdef WINRT
  IDNSQueryPtr query3;
  IDNSQueryPtr query4;
#else
  IDNSQueryPtr query3 = IDNS::lookupAAAA(testObject, "unittest." OPENPEER_SERVICE_TEST_DNS_ZONE);
  IDNSQueryPtr query4 = IDNS::lookupAAAA(testObject, "unittest2." OPENPEER_SERVICE_TEST_DNS_ZONE);
#endif //WINRt
  IDNSQueryPtr query5 = IDNS::lookupSRV(testObject, OPENPEER_SERVICE_TEST_DNS_ZONE, "sip", "udp", 5060, IDNS::SRVLookupType_LookupOnly);
  IDNSQueryPtr query6 = IDNS::lookupA(testObject, "bogusbogus." OPENPEER_SERVICE_TEST_DNS_ZONE);
  IDNSQueryPtr query7 = IDNS::lookupAorAAAA(testObject, "sip." OPENPEER_SERVICE_TEST_DNS_ZONE);
#ifdef WINRT
  IDNSQueryPtr query8;
#else
  IDNSQueryPtr query8 = IDNS::lookupAorAAAA(testObject, "unittest." OPENPEER_SERVICE_TEST_DNS_ZONE);
#endif// WINRT
  IDNSQueryPtr query9 = IDNS::lookupAAAA(testObject, "bogusbogus." OPENPEER_SERVICE_TEST_DNS_ZONE);
  IDNSQueryPtr query10 = IDNS::lookupSRV(testObject, OPENPEER_SERVICE_TEST_DNS_ZONE, "sip", "udp");
  IDNSQueryPtr query11 = IDNS::lookupSRV(testObject, OPENPEER_SERVICE_TEST_DNS_ZONE, "stun", "udp");

  TESTING_STDOUT() << "WAITING:      Waiting for DNS lookup to resolve (max wait is 60 seconds).\n";

  ULONG expectingTotal = 0;
  ULONG totalA = 0;
  ULONG totalAAAA = 0;
  ULONG totalSRV = 0;
  ULONG totalFailed = 0;
  ULONG factoryA = 0;
  ULONG factoryAAAA = 0;
  ULONG factoryAorAAAA = 0;
  ULONG factorySRV = 0;

  if (query)   { expectingTotal += 1; totalA += 1; totalAAAA += 0; totalSRV += 0; totalFailed += 0; factoryA += 1; factoryAAAA += 0; factoryAorAAAA += 0; factorySRV += 0; }
  if (query2)  { expectingTotal += 1; totalA += 1; totalAAAA += 0; totalSRV += 0; totalFailed += 0; factoryA += 1; factoryAAAA += 0; factoryAorAAAA += 0; factorySRV += 0; }
  if (query3)  { expectingTotal += 1; totalA += 0; totalAAAA += 1; totalSRV += 0; totalFailed += 0; factoryA += 0; factoryAAAA += 1; factoryAorAAAA += 0; factorySRV += 0; }
  if (query4)  { expectingTotal += 1; totalA += 0; totalAAAA += 1; totalSRV += 0; totalFailed += 0; factoryA += 0; factoryAAAA += 1; factoryAorAAAA += 0; factorySRV += 0; }
  if (query5)  { expectingTotal += 1; totalA += 0; totalAAAA += 0; totalSRV += 1; totalFailed += 0; factoryA += 0; factoryAAAA += 0; factoryAorAAAA += 0; factorySRV += 1; }
  if (OPENPEER_SERVICE_TEST_DNS_PROVIDER_RESOLVES_BOGUS_DNS_A_RECORDS) {
    if (query6)  { expectingTotal += 1; totalA += 1; totalAAAA += 0; totalSRV += 0; totalFailed += 0; factoryA += 1; factoryAAAA += 0; factoryAorAAAA += 0; factorySRV += 0; }
  } else {
    if (query6)  { expectingTotal += 1; totalA += 0; totalAAAA += 0; totalSRV += 0; totalFailed += 1; factoryA += 1; factoryAAAA += 0; factoryAorAAAA += 0; factorySRV += 0; }
  }
  if (query7)  { expectingTotal += 1; totalA += 1; totalAAAA += 0; totalSRV += 0; totalFailed += 0; factoryA += 0; factoryAAAA += 0; factoryAorAAAA += 1; factorySRV += 0; }
  if (query8)  { expectingTotal += 1; totalA += 0; totalAAAA += 1; totalSRV += 0; totalFailed += 0; factoryA += 0; factoryAAAA += 0; factoryAorAAAA += 1; factorySRV += 0; }
  if (OPENPEER_SERVICE_TEST_DNS_PROVIDER_RESOLVES_BOGUS_DNS_AAAA_RECORDS) {
    if (query9)  { expectingTotal += 1; totalA += 0; totalAAAA += 1; totalSRV += 0; totalFailed += 0; factoryA += 0; factoryAAAA += 1; factoryAorAAAA += 0; factorySRV += 0; }
  } else {
    if (query9)  { expectingTotal += 1; totalA += 0; totalAAAA += 0; totalSRV += 0; totalFailed += 1; factoryA += 0; factoryAAAA += 1; factoryAorAAAA += 0; factorySRV += 0; }
  }
  if (query10) { expectingTotal += 1; totalA += 0; totalAAAA += 0; totalSRV += 1; totalFailed += 0; factoryA += 0; factoryAAAA += 0; factoryAorAAAA += 0; factorySRV += 1; }
  if (query11) { expectingTotal += 1; totalA += 0; totalAAAA += 0; totalSRV += 1; totalFailed += 0; factoryA += 0; factoryAAAA += 0; factoryAorAAAA += 0; factorySRV += 1; }

  ULONG matchingTotal = 0;

  // check to see if all DNS routines have resolved
  {
    ULONG lastResolved = 0;
    ULONG totalWait = 0;
    do
    {
      ULONG totalProcessed = matchingTotal = testObject->getTotalProcessed();
      if (totalProcessed != lastResolved) {
        lastResolved = totalProcessed;
        TESTING_STDOUT() << "WAITING:      [" << totalProcessed << "] Resolved ->  A [" << testObject->getTotalAProcessed() << "]  AAAA [" << testObject->getTotalAAAAProcessed() << "]   SRV [" << testObject->getTotalSRVProcessed() << "]  FAILED[" << testObject->getTotalFailed() << "]\n";
      }
      if (totalProcessed < expectingTotal) {
        ++totalWait;
        TESTING_SLEEP(1000)
      }
      else
        break;
    } while (totalWait < (60)); // max three minutes
    TESTING_EQUAL(matchingTotal, expectingTotal);
    TESTING_CHECK(totalWait < (60));
  }

  TESTING_STDOUT() << "WAITING:      All DNS queries have finished. Waiting for 'bogus' events to process (10 second wait).\n";
  TESTING_SLEEP(10000)

  TESTING_EQUAL(matchingTotal, testObject->getTotalProcessed());

  TESTING_STDOUT() << "RESULT:      Factory totals -> A [" << overrideFactory->getACount() << "]  AAAA [" << overrideFactory->getAAAACount() << "]  A or AAAA [" << overrideFactory->getAorAAAACount() << "]  SRV [" << overrideFactory->getSRVCount() << "]\n";

  TESTING_CHECK(factoryA <= overrideFactory->getACount())
  TESTING_CHECK(factoryAAAA <= overrideFactory->getAAAACount())
  TESTING_CHECK(factoryAorAAAA <= overrideFactory->getAorAAAACount())
  TESTING_CHECK(factorySRV <= overrideFactory->getSRVCount())

  TESTING_EQUAL(totalA, testObject->getTotalAProcessed())
  TESTING_EQUAL(totalAAAA, testObject->getTotalAAAAProcessed())
  TESTING_EQUAL(totalSRV, testObject->getTotalSRVProcessed())
  TESTING_EQUAL(totalFailed, testObject->getTotalFailed())

  if (query) {
    TESTING_CHECK(!testObject->isFailed(query));

    IDNS::AResultPtr a1 = testObject->getA(query);
    TESTING_CHECK(a1)

    if (a1) {
      // www.domain.com, 1800 TTL and IP = 199.204.138.90
#ifndef WINRT
      TESTING_CHECK(a1->mTTL <= 1800);
#endif //ndef WINRT
      TESTING_EQUAL(a1->mIPAddresses.front().string(), "199.204.138.90");
    }
  }

  if (query2) {
    TESTING_CHECK(!testObject->isFailed(query2));

    IDNS::AResultPtr a2 = testObject->getA(query2);
    TESTING_CHECK(a2)
    if (a2) {
      // sip.domain.com, 900, IP = 173.239.150.198
#ifndef WINRT
      TESTING_CHECK(a2->mTTL <= 900);
#endif //ndef WINRT
      TESTING_EQUAL(a2->mIPAddresses.front().string(), "173.239.150.198");
    }
  }

  if (query3) {
    TESTING_CHECK(!testObject->isFailed(query3));
    IDNS::AAAAResultPtr aaaa1 = testObject->getAAAA(query3);

    TESTING_CHECK(aaaa1)

    if (aaaa1) {
      // unittest.domain.com, 900, [2001:0:5ef5:79fb:8:fcb:a142:26ed]
#ifndef WINRT
      TESTING_CHECK(aaaa1->mTTL <= 900);
#endif //ndef WINRT
      TESTING_EQUAL(aaaa1->mIPAddresses.front().string(), zsLib::IPAddress("2001:0:5ef5:79fb:8:fcb:a142:26ed").string());
    }
  }

  if (query4) {
    TESTING_CHECK(!testObject->isFailed(query4));
    IDNS::AAAAResultPtr aaaa2 = testObject->getAAAA(query4);
    TESTING_CHECK(aaaa2)
    if (aaaa2) {
      // unittest2.domain.com, 900, fe80::2c71:60ff:fe00:1c54
#ifndef WINRT
      TESTING_CHECK(aaaa2->mTTL <= 900);
#endif //ndef WINRT
      TESTING_EQUAL(aaaa2->mIPAddresses.front().string(), zsLib::IPAddress("fe80::2c71:60ff:fe00:1c54").string());
    }
  }

  if (query5) {
    TESTING_CHECK(!testObject->isFailed(query5));
    IDNS::SRVResultPtr srv1 = testObject->getSRV(query5);
    TESTING_CHECK(srv1)
    if (srv1) {
      // _sip._udp.domain.com, 900, 10 0 5060 sip.
#ifndef WINRT
      TESTING_CHECK(srv1->mTTL <= 900);
      TESTING_EQUAL(srv1->mRecords.front().mPriority, 10);
      TESTING_EQUAL(srv1->mRecords.front().mWeight, 0);
      TESTING_EQUAL(srv1->mRecords.front().mName, "sip." OPENPEER_SERVICE_TEST_DNS_ZONE);
#endif //ndef WINRT
      TESTING_EQUAL(srv1->mRecords.front().mPort, 5060);
      TESTING_EQUAL(srv1->mRecords.front().mAResult->mIPAddresses.front().string(), zsLib::IPAddress("173.239.150.198:5060").string());
      TESTING_CHECK(!(srv1->mRecords.front().mAAAAResult));
    }
  }

  if (query6) {
    IDNS::AResultPtr a6 = testObject->getA(query6);
    IDNS::AResultPtr aaaa6 = testObject->getAAAA(query6);

    TESTING_CHECK(OPENPEER_SERVICE_TEST_DNS_PROVIDER_RESOLVES_BOGUS_DNS_A_RECORDS ? ((bool)a6) : (!a6))
    TESTING_CHECK(!aaaa6)

    if (!OPENPEER_SERVICE_TEST_DNS_PROVIDER_RESOLVES_BOGUS_DNS_A_RECORDS) {
      if (!testObject->isFailed(query6)) {
        TESTING_CHECK("This next DNS A lookup should have failed to resolve but it did resolve. Verify your provider's DNS is returning no IPs when resolving bogus A lookups; it should be but sometimes Internet providers give \"search\" page results for bogus DNS names")
      }
    }
    TESTING_CHECK(OPENPEER_SERVICE_TEST_DNS_PROVIDER_RESOLVES_BOGUS_DNS_A_RECORDS ? !testObject->isFailed(query6) : testObject->isFailed(query6));
  }

  if (query7) {
    TESTING_CHECK(!testObject->isFailed(query7));
    IDNS::AResultPtr a3 = testObject->getA(query7);
    TESTING_CHECK(a3)
    if (a3) {
      // sip.domain.com 900, IP = 173.239.150.198
#ifndef WINRT
      TESTING_CHECK(a3->mTTL <= 900);
#endif //ndef WINRT
      TESTING_EQUAL(a3->mIPAddresses.front().string(), "173.239.150.198");
    }
    IDNS::AAAAResultPtr aaaa4 = testObject->getAAAA(query7);
    TESTING_CHECK(!aaaa4)
  }

  if (query8) {
    TESTING_CHECK(!testObject->isFailed(query8));
    IDNS::AAAAResultPtr aaaa3 = testObject->getAAAA(query8);
    TESTING_CHECK(aaaa3)
    if (aaaa3) {
      // unittest.domain.com, 900, [2001:0:5ef5:79fb:8:fcb:a142:26ed]
#ifndef WINRT
      TESTING_CHECK(aaaa3->mTTL <= 900);
#endif //ndef WINRT
      TESTING_EQUAL(aaaa3->mIPAddresses.front().string(), zsLib::IPAddress("2001:0:5ef5:79fb:8:fcb:a142:26ed").string());
    }

    IDNS::AResultPtr a4 = testObject->getA(query8);
    TESTING_CHECK(!a4)
  }

  if (query9) {
    IDNS::AResultPtr a5 = testObject->getA(query9);
    IDNS::AAAAResultPtr aaaa5 = testObject->getAAAA(query9);
    TESTING_CHECK(!a5)
    TESTING_CHECK(OPENPEER_SERVICE_TEST_DNS_PROVIDER_RESOLVES_BOGUS_DNS_AAAA_RECORDS ? ((bool)aaaa5) : (!aaaa5))

    if (!OPENPEER_SERVICE_TEST_DNS_PROVIDER_RESOLVES_BOGUS_DNS_AAAA_RECORDS) {
      if (!testObject->isFailed(query9)) {
        TESTING_CHECK("This next DNS A or AAAA lookup should have failed to resolve but it did resolve. Verify your provider's DNS is returning no IPs when resolving bogus A or AAAA lookups; it should be but sometimes Internet providers give \"search\" page results for bogus DNS names")
      }
    }
    TESTING_CHECK(OPENPEER_SERVICE_TEST_DNS_PROVIDER_RESOLVES_BOGUS_DNS_AAAA_RECORDS ? !testObject->isFailed(query9) : testObject->isFailed(query9));
  }

  if (query10) {
    IDNS::SRVResultPtr srv2 = testObject->getSRV(query10);
    TESTING_CHECK(srv2)
    if (srv2) {
      // _sip._udp.domain.com, 900, 10 0 5060 sip.
#ifndef WINRT
      TESTING_CHECK(srv2->mTTL <= 900);
      TESTING_EQUAL(srv2->mRecords.front().mPriority, 10);
      TESTING_EQUAL(srv2->mRecords.front().mWeight, 0);
      TESTING_EQUAL(srv2->mRecords.front().mName, "sip." OPENPEER_SERVICE_TEST_DNS_ZONE);
      TESTING_CHECK(srv2->mRecords.front().mAResult->mTTL <= 900);
#endif //ndef WINRT
      TESTING_EQUAL(srv2->mRecords.front().mPort, 5060);
      TESTING_EQUAL(srv2->mRecords.front().mAResult->mIPAddresses.front().string(), "173.239.150.198:5060");
      TESTING_CHECK(!(srv2->mRecords.front().mAAAAResult));
    }
  }

  if (query11) {
    IDNS::SRVResultPtr srv3 = testObject->getSRV(query11);
    TESTING_CHECK(srv3)

    const char *first = "stun." OPENPEER_SERVICE_TEST_DNS_ZONE;
    const char *second = "stun." OPENPEER_SERVICE_TEST_DNS_ZONE;

    const char *firstWIP = "54.242.132.131:3478";
    const char *secondWIP = "174.129.96.12:3478";

    if (srv3->mRecords.size() > 0) {
      if (srv3->mRecords.front().mAResult) {
        if (srv3->mRecords.front().mAResult->mIPAddresses.size() > 0) {
          if (srv3->mRecords.front().mAResult->mIPAddresses.front().string() == secondWIP) {
            const char *temp = first;
            const char *tempWIP = firstWIP;
            first = second;
            firstWIP = secondWIP;
            second = temp;
            secondWIP = tempWIP;
          }
        }
      }
    }
    IDNS::SRVResultPtr clone = IDNS::cloneSRV(srv3);  // keep a cloned copy
    IDNS::SRVResultPtr clone2 = IDNS::cloneSRV(srv3);  // keep a second cloned copy

    TESTING_CHECK(clone)
    TESTING_CHECK(clone2)

    if (srv3) {
#ifndef WINRT
      TESTING_CHECK(srv3->mTTL <= 900)
#endif //ndef WINRT
      TESTING_EQUAL(clone->mTTL, srv3->mTTL)

      TESTING_EQUAL(srv3->mRecords.size(), 1)
      TESTING_EQUAL(clone->mRecords.size(), srv3->mRecords.size())

      if (srv3->mRecords.size() > 0) {
        // _stun._udp.domain.com, 900, 10 0 3478 216.93.246.14 // order is unknown, could be either order
        // _stun._udp.domain.com, 900, 10 0 3478 216.93.246.16
#ifndef WINRT
        TESTING_EQUAL(srv3->mRecords.front().mPriority, 10);
        TESTING_EQUAL(srv3->mRecords.front().mWeight, 0);
        TESTING_EQUAL(srv3->mRecords.front().mName, first);
#endif //ndef WINRT
        TESTING_EQUAL(srv3->mRecords.front().mPort, 3478);

        TESTING_CHECK(srv3->mRecords.front().mAResult)

        if (srv3->mRecords.front().mAResult) {
#ifndef WINRT
          TESTING_CHECK(srv3->mRecords.front().mAResult->mTTL <= 900);
#endif //ndef WINRT
          TESTING_EQUAL(srv3->mRecords.front().mAResult->mIPAddresses.size(), 2)
          if (srv3->mRecords.front().mAResult->mIPAddresses.size() > 0) {
            TESTING_EQUAL(srv3->mRecords.front().mAResult->mIPAddresses.front().string(), firstWIP);
            srv3->mRecords.front().mAResult->mIPAddresses.pop_front();  // check the next record now
          }
          TESTING_CHECK(!(srv3->mRecords.front().mAAAAResult));

          if (srv3->mRecords.front().mAResult->mIPAddresses.size() > 0) {
            TESTING_EQUAL(srv3->mRecords.front().mAResult->mIPAddresses.front().string(), secondWIP);
          }
        }

        // test cloning of SRV record
#ifndef WINRT
        TESTING_EQUAL(clone->mRecords.front().mPriority, 10);
        TESTING_EQUAL(clone->mRecords.front().mWeight, 0);
        TESTING_EQUAL(clone->mRecords.front().mName, first);
#endif //ndef WINRT
        TESTING_EQUAL(clone->mRecords.front().mPort, 3478);

        TESTING_CHECK(clone->mRecords.front().mAResult)

        if (clone->mRecords.front().mAResult) {
#ifndef WINRT
          TESTING_CHECK(clone->mRecords.front().mAResult->mTTL <= 900);
#endif //ndef WINRT
          TESTING_EQUAL(clone->mRecords.front().mAResult->mIPAddresses.size(), 2)

          if (clone->mRecords.front().mAResult->mIPAddresses.size() > 0) {
            TESTING_EQUAL(clone->mRecords.front().mAResult->mIPAddresses.front().string(), firstWIP);
            clone->mRecords.front().mAResult->mIPAddresses.pop_front();  // check the next record now
          }
          TESTING_CHECK(!(clone->mRecords.front().mAAAAResult));
          if (clone->mRecords.front().mAResult->mIPAddresses.size() > 0) {
            TESTING_EQUAL(srv3->mRecords.front().mAResult->mIPAddresses.front().string(), secondWIP);
          }
        }
      }
    }

    // test extraction of SRV record
    bool extract = false;
    zsLib::IPAddress extractedIP;
    IDNS::AResultPtr extractedA;
    IDNS::AAAAResultPtr extractedAAAA;

    if (clone2) {
      extract = IDNS::extractNextIP(clone2, extractedIP, &extractedA, &extractedAAAA);
      TESTING_CHECK(extract);

      TESTING_EQUAL(extractedIP.string(), firstWIP);
      TESTING_CHECK(extractedA);
      TESTING_CHECK(!extractedAAAA);
#ifndef WINRT
      TESTING_EQUAL(extractedA->mName, first);
#endif //ndef WINRT

      extract = IDNS::extractNextIP(clone2, extractedIP, &extractedA, &extractedAAAA);
      TESTING_CHECK(extract);

      TESTING_EQUAL(extractedIP.string(), secondWIP);
      TESTING_CHECK(extractedA);
      TESTING_CHECK(!extractedAAAA);
#ifndef WINRT
      TESTING_EQUAL(extractedA->mName, second);
#endif //ndef WINRT

      extract = IDNS::extractNextIP(clone2, extractedIP, &extractedA, &extractedAAAA);
      TESTING_CHECK(!extract)
      TESTING_CHECK(!extractedA)
      TESTING_CHECK(!extractedAAAA)
    }
  }

  query.reset();
  query2.reset();
  query3.reset();
  query4.reset();
  query5.reset();
  query6.reset();
  query7.reset();
  query8.reset();
  query9.reset();
  query10.reset();
  query11.reset();
  testObject.reset();

  // wait for shutdown
  {
    IMessageQueue::size_type count = 0;
    do
    {
      count = thread->getTotalUnprocessedMessages();
      if (0 != count)
        std::this_thread::yield();
    } while (count > 0);

    thread->waitForShutdown();
  }
  TESTING_UNINSTALL_LOGGER()
  zsLib::proxyDump();
  TESTING_EQUAL(zsLib::proxyGetTotalConstructed(), 0);
}
