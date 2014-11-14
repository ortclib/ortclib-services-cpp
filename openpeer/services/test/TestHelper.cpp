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

#include <openpeer/services/IHelper.h>

#include <zsLib/String.h>

#include <iostream>

#include "config.h"
#include "boost_replacement.h"

using zsLib::String;

ZS_DECLARE_TYPEDEF_PTR(openpeer::services::IHelper, UseHelepr)

void doTestHelper()
{
  if (!OPENPEER_SERVICE_TEST_DO_HELPER_TEST) return;

  BOOST_INSTALL_LOGGER();

  wchar_t rawInput1[] = {0x0077, 0x0077, 0x0077, 0x002E, 0x65E5, 0x672C, 0x5E73, 0x002E, 0x006A, 0x0070, 0x00};
  wchar_t rawInput2[] = {0x0077, 0x0077, 0x0077, 0x002E, 0x30CF, 0x30F3, 0x30C9, 0x30DC, 0x30FC, 0x30EB, 0x30B5, 0x30E0, 0x30BA, 0x002E, 0x0063, 0x006F, 0x006D, 0x00};
  wchar_t rawInput3[] = {0x0077, 0x0077, 0x0077, 0x002E, 0x0066, 0x00E4, 0x0072, 0x0067, 0x0062, 0x006F, 0x006C, 0x0061, 0x0067, 0x0065, 0x0074, 0x002E, 0x006E, 0x0075, 0x00};
  wchar_t rawInput4[] = {0x0077, 0x0077, 0x0077, 0x002E, 0x0062, 0x00FC, 0x0063, 0x0068, 0x0065, 0x0072, 0x002E, 0x0064, 0x0065, 0x00};
  wchar_t rawInput5[] = {0x0077, 0x0077, 0x0077, 0x002E, 0x0062, 0x0072, 0x00E6, 0x006E, 0x0064, 0x0065, 0x006E, 0x0064, 0x0065, 0x006B, 0x00E6, 0x0072, 0x006C, 0x0069, 0x0067, 0x0068, 0x0065, 0x0064, 0x002E, 0x0063, 0x006F, 0x006D, 0x00};
  wchar_t rawInput6[] = {0x0077, 0x0077, 0x0077, 0x002E, 0x0072, 0x00E4, 0x006B, 0x0073, 0x006D, 0x00F6, 0x0072, 0x0067, 0x00E5, 0x0073, 0x002E, 0x0073, 0x0065, 0x00};
  wchar_t rawInput7[] = {0x0077, 0x0077, 0x0077, 0x002E, 0xC608, 0xBE44, 0xAD50, 0xC0AC, 0x002E, 0x0063, 0x006F, 0x006D, 0x00};
  wchar_t rawInput8[] = {0x7406, 0x5BB9, 0x30CA, 0x30AB, 0x30E0, 0x30E9, 0x002E, 0x0063, 0x006F, 0x006D, 0x00};
  wchar_t rawInput9[] = {0x3042, 0x30FC, 0x308B, 0x3044, 0x3093, 0x002E, 0x0063, 0x006F, 0x006D, 0x00};
  wchar_t rawInput10[] = {0x0077, 0x0077, 0x0077, 0x002E, 0x0066, 0x00E4, 0x0072, 0x006A, 0x0065, 0x0073, 0x0074, 0x0061, 0x0064, 0x0073, 0x0062, 0x006B, 0x002E, 0x006E, 0x0065, 0x0074, 0x00};
  wchar_t rawInput11[] = {0x0077, 0x0077, 0x0077, 0x002E, 0x006D, 0x00E4, 0x006B, 0x0069, 0x0074, 0x006F, 0x0072, 0x0070, 0x0070, 0x0061, 0x002E, 0x0063, 0x006F, 0x006D, 0x00};

  wchar_t *rawInputs[] = {
    rawInput1,
    rawInput2,
    rawInput3,
    rawInput4,
    rawInput5,
    rawInput6,
    rawInput7,
    rawInput8,
    rawInput9,
    rawInput10,
    rawInput11,
    NULL
  };

  const char *expectedOutputs[] = {
    "www.xn--gwtq9nb2a.jp",
    "www.xn--vckk7bxa0eza9ezc9d.com",
    "www.xn--frgbolaget-q5a.nu",
    "www.xn--bcher-kva.de",
    "www.xn--brndendekrlighed-vobh.com",
    "www.xn--rksmrgs-5wao1o.se",
    "www.xn--9d0bm53a3xbzui.com",
    "xn--lck1c3crb1723bpq4a.com",
    "xn--l8je6s7a45b.com",
    "www.xn--frjestadsbk-l8a.net",
    "www.xn--mkitorppa-v2a.com",
    NULL
  };

  for (size_t loop = 0; NULL != rawInputs[loop]; ++loop)
  {
    wchar_t *rawInput = rawInputs[loop];
    String expecting(expectedOutputs[loop]);

    String input(rawInput);

    String output = UseHelepr::convertUTF8ToIDN(input);

    BOOST_EQUAL(expecting, output)

    String backToOriginal = UseHelepr::convertIDNToUTF8(output);

    BOOST_EQUAL(input, backToOriginal)
    
  }

}
