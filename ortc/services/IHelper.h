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

#include <zsLib/eventing/IHelper.h>

#include <zsLib/Log.h>

// FOR COMPATIBILITY WITH ENCYPRTION ALGORITHMS, SEE:
// http://www.codeproject.com/Articles/21877/Applied-Crypto-Block-Ciphers

namespace ortc
{
  namespace services
  {
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IHelper
    #pragma mark

    interaction IHelper : public zsLib::eventing::IHelper
    {
      enum EncryptionAlgorthms
      {
        EncryptionAlgorthm_AES,
      };

      typedef size_t Index;
      typedef std::map<Index, String> SplitMap;
      typedef std::list<String> StringList;

      static void setup();
#ifdef WINRT
      static void setup(Windows::UI::Core::CoreDispatcher ^dispatcher);
#endif //WINRT

      static IMessageQueuePtr getServicePoolQueue();
      static IMessageQueuePtr getServiceQueue();
      static IMessageQueuePtr getLoggerQueue();

      static SecureByteBlockPtr encrypt(
                                        const SecureByteBlock &key, // key length of 32 = AES/256
                                        const SecureByteBlock &iv,  // 16 bytes for AES
                                        const SecureByteBlock &value,
                                        EncryptionAlgorthms algorithm = EncryptionAlgorthm_AES
                                        );

      static SecureByteBlockPtr encrypt(
                                        const SecureByteBlock &key, // key length of 32 = AES/256
                                        const SecureByteBlock &iv,  // 16 bytes for AES
                                        const char *value,
                                        EncryptionAlgorthms algorithm = EncryptionAlgorthm_AES
                                        );

      static SecureByteBlockPtr encrypt(
                                        const SecureByteBlock &key, // key length of 32 = AES/256
                                        const SecureByteBlock &iv,  // 16 bytes for AES
                                        const std::string &value,
                                        EncryptionAlgorthms algorithm = EncryptionAlgorthm_AES
                                        );

      static SecureByteBlockPtr encrypt(
                                        const SecureByteBlock &key, // key length of 32 = AES/256
                                        const SecureByteBlock &iv,  // 16 bytes for AES
                                        const BYTE *buffer,
                                        size_t bufferLengthInBytes,
                                        EncryptionAlgorthms algorithm = EncryptionAlgorthm_AES
                                        );

      static SecureByteBlockPtr decrypt(
                                        const SecureByteBlock &key,
                                        const SecureByteBlock &iv,
                                        const SecureByteBlock &value,
                                        EncryptionAlgorthms algorithm = EncryptionAlgorthm_AES
                                        );

      static void splitKey(
                           const SecureByteBlock &key,
                           SecureByteBlockPtr &part1,
                           SecureByteBlockPtr &part2
                           );
      static SecureByteBlockPtr combineKey(
                                           const SecureByteBlockPtr &part1,
                                           const SecureByteBlockPtr &part2
                                           );

      // RETURNS: returns the actual signed element, rather than the bundle element (if bundle was passed in) or NULL if no signature was found
      static ElementPtr getSignatureInfo(
                                         ElementPtr signedEl,
                                         ElementPtr *outSignatureEl = NULL,
                                         String *outFullPublicKey = NULL,
                                         String *outFingerprint = NULL
                                         );

      static String convertUTF8ToIDN(const String &utf8Str);
      static String convertIDNToUTF8(const String &idnStr);

      static bool isValidDomain(const String &domain);
    };

  } // namespace services
} // namespace ortc
