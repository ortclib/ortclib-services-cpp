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
#include <ortc/services/IHelper.h>

namespace ortc
{
  namespace services
  {

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IEncryptor
    #pragma mark

    interaction IEncryptor
    {
      typedef IHelper::EncryptionAlgorthms EncryptionAlgorthms;

      //-----------------------------------------------------------------------
      // PURPOSE: create an encryptor that will encrypt data
      static IEncryptorPtr create(
                                  const SecureByteBlock &key, // key length of 32 = AES/256
                                  const SecureByteBlock &iv,  // 16 bytes for AES
                                  EncryptionAlgorthms algorithm = IHelper::EncryptionAlgorthm_AES
                                  );

      //-----------------------------------------------------------------------
      // PURPOSE: gets the optimal buffer block encryption size in bytes for
      //          encrypting data
      virtual size_t getOptimalBlockSize() const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: encrypt the next block of data and return result data
      // RETURN:  next block of encrypted data or null SecureByteBlockPtr()
      //          when no more data is available.
      virtual SecureByteBlockPtr encrypt(
                                         const BYTE *inBuffer,
                                         size_t inBufferSizeInBytes
                                         ) = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: encrypt the next block of data and return result data
      // RETURN:  next block of encrypted data or null SecureByteBlockPtr()
      //          when no more data is available (or error occured).
      virtual SecureByteBlockPtr encrypt(const SecureByteBlock &input) = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: returns any finalized encryption buffer when no more data
      //          will be fed into the encryption
      // RETURN:  final block of encrypted data or null SecureByteBlockPtr()
      //          when no more data is available.
      virtual SecureByteBlockPtr finalize() = 0;
    };

  }
}
