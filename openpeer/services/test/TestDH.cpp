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

#include <openpeer/services/IDHKeyDomain.h>
#include <openpeer/services/IDHPrivateKey.h>
#include <openpeer/services/IDHPublicKey.h>
#include <openpeer/services/IHelper.h>

#include <zsLib/XML.h>
#include <iostream>

#include "config.h"
#include "testing.h"

using openpeer::services::IHelper;
using openpeer::services::IDHKeyDomain;
using openpeer::services::IDHKeyDomainPtr;
using openpeer::services::IDHPrivateKey;
using openpeer::services::IDHPrivateKeyPtr;
using openpeer::services::IDHPublicKey;
using openpeer::services::IDHPublicKeyPtr;
using openpeer::services::SecureByteBlock;
using openpeer::services::SecureByteBlockPtr;

void doTestDH()
{
  if (!OPENPEER_SERVICE_TEST_DO_DH_TEST) return;

  TESTING_INSTALL_LOGGER();

  {
    static IDHKeyDomain::KeyDomainPrecompiledTypes precompiled[] =
    {
      IDHKeyDomain::KeyDomainPrecompiledType_1024,
      IDHKeyDomain::KeyDomainPrecompiledType_1538,
      IDHKeyDomain::KeyDomainPrecompiledType_2048,
      IDHKeyDomain::KeyDomainPrecompiledType_3072,
      IDHKeyDomain::KeyDomainPrecompiledType_4096,
      IDHKeyDomain::KeyDomainPrecompiledType_6144,
      IDHKeyDomain::KeyDomainPrecompiledType_8192,
      IDHKeyDomain::KeyDomainPrecompiledType_Unknown,
    };

    // check standard generation
    {
      SecureByteBlock p;
      SecureByteBlock q;
      SecureByteBlock g;

      SecureByteBlock aliceStaticPrivate;
      SecureByteBlock aliceStaticPublic;

      SecureByteBlock aliceEmpheralPrivate;
      SecureByteBlock aliceEmpheralPublic;

      SecureByteBlock bobStaticPrivate;
      SecureByteBlock bobStaticPublic;

      SecureByteBlock bobEmpheralPrivate;
      SecureByteBlock bobEmpheralPublic;

      SecureByteBlockPtr checkAgain;

      {
        TESTING_EQUAL(1, 1)
        IDHKeyDomainPtr keyDomain = IDHKeyDomain::generate(1024);

        keyDomain->save(p, q, g);

        IDHPublicKeyPtr alicePublicKey;
        IDHPrivateKeyPtr alicePrivateKey = IDHPrivateKey::generate(keyDomain, alicePublicKey);

        IDHPublicKeyPtr bobPublicKey;
        IDHPrivateKeyPtr bobPrivateKey = IDHPrivateKey::generate(keyDomain, bobPublicKey);

        TESTING_CHECK((bool)alicePublicKey)
        TESTING_CHECK((bool)alicePrivateKey)
        TESTING_CHECK((bool)bobPublicKey)
        TESTING_CHECK((bool)bobPrivateKey)

        alicePrivateKey->save(&aliceStaticPrivate, &aliceEmpheralPrivate);
        alicePublicKey->save(&aliceStaticPublic, &aliceEmpheralPublic);

        bobPrivateKey->save(&bobStaticPrivate, &bobEmpheralPrivate);
        bobPublicKey->save(&bobStaticPublic, &bobEmpheralPublic);

        SecureByteBlockPtr aliceSecret = alicePrivateKey->getSharedSecret(bobPublicKey);
        SecureByteBlockPtr bobSecret = bobPrivateKey->getSharedSecret(alicePublicKey);

        TESTING_CHECK(IHelper::hasData(aliceSecret))
        TESTING_CHECK(IHelper::hasData(bobSecret))

        TESTING_CHECK(0 == IHelper::compare(*aliceSecret, *bobSecret))

        checkAgain = aliceSecret;
      }

      {
        TESTING_EQUAL(2, 2)
        IDHKeyDomainPtr keyDomain = IDHKeyDomain::load(p, q, g, true);

        IDHPublicKeyPtr alicePublicKey = IDHPublicKey::load(aliceStaticPublic, aliceEmpheralPublic);
        IDHPrivateKeyPtr alicePrivateKey = IDHPrivateKey::load(keyDomain, aliceStaticPrivate, aliceEmpheralPrivate);

        IDHPublicKeyPtr bobPublicKey = IDHPublicKey::load(bobStaticPublic, bobEmpheralPublic);
        IDHPrivateKeyPtr bobPrivateKey = IDHPrivateKey::load(keyDomain, bobStaticPrivate, bobEmpheralPrivate);

        TESTING_CHECK((bool)alicePublicKey)
        TESTING_CHECK((bool)alicePrivateKey)
        TESTING_CHECK((bool)bobPublicKey)
        TESTING_CHECK((bool)bobPrivateKey)

        SecureByteBlockPtr aliceSecret = alicePrivateKey->getSharedSecret(bobPublicKey);
        SecureByteBlockPtr bobSecret = bobPrivateKey->getSharedSecret(alicePublicKey);

        TESTING_CHECK(IHelper::hasData(aliceSecret))
        TESTING_CHECK(IHelper::hasData(bobSecret))

        TESTING_CHECK(0 == IHelper::compare(*aliceSecret, *bobSecret))
        TESTING_CHECK(0 == IHelper::compare(*aliceSecret, *checkAgain))
      }

      {
        TESTING_EQUAL(3, 3)
        IDHKeyDomainPtr keyDomain = IDHKeyDomain::load(p, q, g, true);
        IDHKeyDomainPtr altKeyDomain = IDHKeyDomain::loadPrecompiled(IDHKeyDomain::KeyDomainPrecompiledType_1024, true);

        IDHPublicKeyPtr alicePublicKey = IDHPublicKey::load(aliceStaticPublic, aliceEmpheralPublic);
        IDHPrivateKeyPtr alicePrivateKey = IDHPrivateKey::load(keyDomain, aliceStaticPrivate, aliceEmpheralPrivate);

        IDHPublicKeyPtr bobPublicKey = IDHPublicKey::load(bobStaticPublic, bobEmpheralPublic);
        IDHPrivateKeyPtr bobPrivateKey = IDHPrivateKey::load(altKeyDomain, bobStaticPrivate, bobEmpheralPrivate);

        TESTING_CHECK((bool)alicePublicKey)
        TESTING_CHECK((bool)alicePrivateKey)
        TESTING_CHECK((bool)bobPublicKey)
        TESTING_CHECK((bool)bobPrivateKey)

        SecureByteBlockPtr aliceSecret = alicePrivateKey->getSharedSecret(bobPublicKey);
        SecureByteBlockPtr bobSecret = bobPrivateKey->getSharedSecret(alicePublicKey);

        TESTING_CHECK(IHelper::hasData(aliceSecret))  // alice will pass because bob's public key was created using the original key domain
        if (bobSecret) {
          TESTING_CHECK(0 != IHelper::compare(*aliceSecret, *bobSecret)) // must not match if it exists (hopefully should fail validation)
        }

        TESTING_CHECK(0 == IHelper::compare(*aliceSecret, *checkAgain)) // must still match since it's valid
      }

      {
        TESTING_EQUAL(4, 4)
        IDHKeyDomainPtr keyDomain = IDHKeyDomain::load(p, q, g, true);
        IDHKeyDomainPtr altKeyDomain = IDHKeyDomain::loadPrecompiled(IDHKeyDomain::KeyDomainPrecompiledType_1024, true);

        // generate a whole new set of keys
        IDHPublicKeyPtr alicePublicKey;
        IDHPrivateKeyPtr alicePrivateKey = IDHPrivateKey::generate(keyDomain, alicePublicKey);

        IDHPublicKeyPtr bobPublicKey;
        IDHPrivateKeyPtr bobPrivateKey = IDHPrivateKey::generate(altKeyDomain, bobPublicKey);

        TESTING_CHECK((bool)alicePublicKey)
        TESTING_CHECK((bool)alicePrivateKey)
        TESTING_CHECK((bool)bobPublicKey)
        TESTING_CHECK((bool)bobPrivateKey)

        SecureByteBlockPtr aliceSecret = alicePrivateKey->getSharedSecret(bobPublicKey);
        SecureByteBlockPtr bobSecret = bobPrivateKey->getSharedSecret(alicePublicKey);

        if ((aliceSecret) &&
            (bobSecret)) {
          TESTING_CHECK(0 != IHelper::compare(*aliceSecret, *bobSecret)) // must not match if it exists (hopefully should fail validation)
        }
      }

      {
        TESTING_EQUAL(5, 5)
        IDHKeyDomainPtr keyDomain = IDHKeyDomain::load(p, q, g, true);

        // generate a whole new set of keys
        IDHPublicKeyPtr alicePublicKey;
        IDHPrivateKeyPtr alicePrivateKey = IDHPrivateKey::generate(keyDomain, alicePublicKey);

        IDHPublicKeyPtr bobPublicKeyOfficial; // NOT USED
        IDHPrivateKeyPtr bobPrivateKey = IDHPrivateKey::generate(keyDomain, bobPublicKeyOfficial);

        // except bob's public key was messed up intentionally
        IDHPublicKeyPtr bobPublicKey;
        IDHPrivateKeyPtr bogusPrivateKey = IDHPrivateKey::generate(keyDomain, bobPublicKey);

        TESTING_CHECK((bool)alicePublicKey)
        TESTING_CHECK((bool)alicePrivateKey)
        TESTING_CHECK((bool)bobPublicKeyOfficial)
        TESTING_CHECK((bool)bobPrivateKey)

        SecureByteBlockPtr aliceSecret = alicePrivateKey->getSharedSecret(bobPublicKey);
        SecureByteBlockPtr bobSecret = bobPrivateKey->getSharedSecret(alicePublicKey);

        if ((aliceSecret) &&
            (bobSecret)) {
          TESTING_CHECK(0 != IHelper::compare(*aliceSecret, *bobSecret)) // must not match if it exists (hopefully should fail validation)
        }
      }
    }

    TESTING_EQUAL(6, 6)

    for (int index = 0; precompiled[index] != IDHKeyDomain::KeyDomainPrecompiledType_Unknown; ++index)
    {
      bool found = true;

      IDHKeyDomainPtr keyDomain = IDHKeyDomain::loadPrecompiled(precompiled[index], true);
      if (!keyDomain) {
        keyDomain = IDHKeyDomain::generate(precompiled[index]);
        found = false;
      }
      TESTING_CHECK((bool)keyDomain)

      IDHPublicKeyPtr alicePublicKey;
      IDHPrivateKeyPtr alicePrivateKey = IDHPrivateKey::generate(keyDomain, alicePublicKey);

      IDHPublicKeyPtr bobPublicKey;
      IDHPrivateKeyPtr bobPrivateKey = IDHPrivateKey::generate(keyDomain, bobPublicKey);

      TESTING_CHECK((bool)alicePublicKey)
      TESTING_CHECK((bool)alicePrivateKey)
      TESTING_CHECK((bool)bobPublicKey)
      TESTING_CHECK((bool)bobPrivateKey)

      SecureByteBlockPtr aliceSecret = alicePrivateKey->getSharedSecret(bobPublicKey);
      SecureByteBlockPtr bobSecret = bobPrivateKey->getSharedSecret(alicePublicKey);

      TESTING_CHECK(IHelper::hasData(aliceSecret))
      TESTING_CHECK(IHelper::hasData(bobSecret))

      TESTING_CHECK(0 == IHelper::compare(*aliceSecret, *bobSecret))

      if (found) {
        TESTING_CHECK(precompiled[index] == keyDomain->getPrecompiledType())
      }
    }
  }

}
