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

#include <ortc/services/internal/services_Decryptor.h>

#include <cryptopp/modes.h>
#include <cryptopp/aes.h>

namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services) } }


namespace openpeer
{
  namespace services
  {
    namespace internal
    {
      using CryptoPP::CFB_Mode;
      using CryptoPP::AES;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark EncryptorData
      #pragma mark

      struct DecryptorData
      {
        CFB_Mode<AES>::Decryption decryptor;

        DecryptorData(
                      const BYTE *key,
                      size_t keySize,
                      const BYTE *iv
                      ) :
          decryptor(key, keySize, iv)
        {
        }
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Encryptor
      #pragma mark

      //-----------------------------------------------------------------------
      Decryptor::Decryptor(
                           const make_private &,
                           const SecureByteBlock &key,
                           const SecureByteBlock &iv,
                           EncryptionAlgorthms algorithm
                           )
      {
        mData = new DecryptorData(key, key.SizeInBytes(), iv);
      }

      //-----------------------------------------------------------------------
      Decryptor::~Decryptor()
      {
        delete mData;
        mData = NULL;
      }

      //-----------------------------------------------------------------------
      DecryptorPtr Decryptor::create(
                                     const SecureByteBlock &key,
                                     const SecureByteBlock &iv,
                                     EncryptionAlgorthms algorithm
                                     )
      {
        DecryptorPtr pThis(make_shared<Decryptor>(make_private {}, key, iv, algorithm));
        return pThis;
      }

      //-----------------------------------------------------------------------
      size_t Decryptor::getOptimalBlockSize() const
      {
        return mData->decryptor.OptimalBlockSize();
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr Decryptor::decrypt(
                                            const BYTE *inBuffer,
                                            size_t inBufferSizeInBytes
                                            )
      {
        SecureByteBlockPtr output(make_shared<SecureByteBlock>(inBufferSizeInBytes));
        mData->decryptor.ProcessData(*output, inBuffer, inBufferSizeInBytes);
        return output;
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr Decryptor::decrypt(const SecureByteBlock &input)
      {
        SecureByteBlockPtr output(make_shared<SecureByteBlock>(input.SizeInBytes()));
        mData->decryptor.ProcessData(*output, input.BytePtr(), input.SizeInBytes());
        return output;
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr Decryptor::finalize(bool *outWasSuccessful)
      {
        if (outWasSuccessful) {
          *outWasSuccessful = true;
        }
        return SecureByteBlockPtr();
      }
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IEncryptor
    #pragma mark

    //-------------------------------------------------------------------------
    IDecryptorPtr IDecryptor::create(
                                     const SecureByteBlock &key,
                                     const SecureByteBlock &iv,
                                     EncryptionAlgorthms algorithm
                                     )
    {
      return internal::Decryptor::create(key, iv, algorithm);
    }
  }
}
