/*

 Copyright (c) 2014, Hookflash Inc.
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

#pragma once

#include <ortc/services/types.h>


#define ORTC_SERVICES_DH_KEY_DOMAIN_GENERATION_SIZE (2048)

namespace ortc
{
  namespace services
  {
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //
    // IDHKeyDomain
    //

    interaction IDHKeyDomain
    {
      enum KeyDomainPrecompiledTypes
      {
        KeyDomainPrecompiledType_Unknown = 0,
        KeyDomainPrecompiledType_1024 = 1024,
        KeyDomainPrecompiledType_1538 = 1536,
        KeyDomainPrecompiledType_2048 = 2048,
        KeyDomainPrecompiledType_3072 = 3072,
        KeyDomainPrecompiledType_4096 = 4096,
        KeyDomainPrecompiledType_6144 = 6144,
        KeyDomainPrecompiledType_8192 = 8192,

        KeyDomainPrecompiledType_Last = KeyDomainPrecompiledType_8192,
      };

      static const char *toNamespace(KeyDomainPrecompiledTypes length) noexcept;
      static KeyDomainPrecompiledTypes fromNamespace(const char *inNamespace) noexcept;

      static ElementPtr toDebug(IDHKeyDomainPtr keyDomain) noexcept;

      static IDHKeyDomainPtr generate(size_t keySizeInBits = ORTC_SERVICES_DH_KEY_DOMAIN_GENERATION_SIZE) noexcept;

      static IDHKeyDomainPtr loadPrecompiled(
                                             KeyDomainPrecompiledTypes precompiledLength,
                                             bool validate = false
                                             ) noexcept;

      //-----------------------------------------------------------------------
      // NOTE: p, q and g integers are read from HEX decoded byte array
      //       p = modulas
      //       q = q = (p-1)/2
      //       g = generator
      static IDHKeyDomainPtr load(
                                  const SecureByteBlock &p,
                                  const SecureByteBlock &q,
                                  const SecureByteBlock &g,
                                  bool validate = true
                                  ) noexcept;

      virtual PUID getID() const noexcept = 0;

      virtual KeyDomainPrecompiledTypes getPrecompiledType() const noexcept = 0;

      //-----------------------------------------------------------------------
      // NOTE: p, q and g integers are HEX encoded for compatibility
      virtual void save(
                        SecureByteBlock &p,
                        SecureByteBlock &q,
                        SecureByteBlock &g
                        ) const noexcept = 0;
    };
  }
}
