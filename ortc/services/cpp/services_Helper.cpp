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

#include <ortc/services/internal/services_Helper.h>
#include <ortc/services/internal/services_HTTP.h>
#include <ortc/services/internal/services.events.h>
#include <ortc/services/IDNS.h>

#include <zsLib/eventing/IHasher.h>

#include <zsLib/Stringize.h>
#include <zsLib/Numeric.h>
#include <zsLib/helpers.h>
#include <zsLib/Log.h>
#include <zsLib/XML.h>
#include <zsLib/IMessageQueueThread.h>
#include <zsLib/IMessageQueueManager.h>
#include <zsLib/ISettings.h>
#include <zsLib/Socket.h>
#include <zsLib/ITimer.h>
#include <zsLib/IHelper.h>

#include <regex>
#include <iostream>
#include <fstream>
#ifndef _WIN32
#include <pthread.h>
#endif //ndef _WIN32

#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/aes.h>
#include <cryptopp/sha.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/hmac.h>

#include <idn/api.h>

#define ORTC_SERVICES_SERVICE_THREAD_POOL_NAME "org.ortclib.services.serviceThreadPool"
#define ORTC_SERVICES_SERVICE_THREAD_NAME "org.ortclib.services.serviceThread"
#define ORTC_SERVICES_LOGGER_THREAD_NAME "org.ortclib.services.loggerThread"

#define ORTC_SERVICES_HELPER_UNICODE_CHAR_TO_PUNY_CODE_CHARACTOR_RATIO (6)

namespace ortc { namespace services { ZS_DECLARE_SUBSYSTEM(ortc_services) } }

namespace ortc
{
  namespace services
  {
    using CryptoPP::CFB_Mode;
    using CryptoPP::AES;

    ZS_DECLARE_USING_PTR(zsLib, IMessageQueueManager);
    ZS_DECLARE_USING_PTR(zsLib, ISettings);
    ZS_DECLARE_USING_PTR(zsLib::eventing, IHasher);

    namespace internal
    {
      ZS_DECLARE_CLASS_PTR(HelperSettingsDefaults);

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark (forwards)
      #pragma mark

      void initSubsystems();
      void installICESocketSettingsDefaults();
      void installICESocketSessionSettingsDefaults();
      void installTURNSocketSettingsDefaults();
      void installTCPMessagingSettingsDefaults();
      void installLoggerSettingsDefaults();
      void installMessageLayerSecurityChannelSettingsDefaults();
      void installBackOffTimerSettingsDefaults();


      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark (helpers)
      #pragma mark

      //-----------------------------------------------------------------------
      void throwOnlySetOnce()
      {
        ZS_THROW_INVALID_USAGE("services::LockValue object is only allowed to be set once")
      }


      //-------------------------------------------------------------------------
      //-------------------------------------------------------------------------
      //-------------------------------------------------------------------------
      //-------------------------------------------------------------------------
      #pragma mark
      #pragma mark HelperSettingsDefaults
      #pragma mark

      class HelperSettingsDefaults : public ISettingsApplyDefaultsDelegate
      {
      public:
        //-----------------------------------------------------------------------
        ~HelperSettingsDefaults()
        {
          ISettings::removeDefaults(*this);
        }

        //-----------------------------------------------------------------------
        static HelperSettingsDefaultsPtr singleton()
        {
          static SingletonLazySharedPtr<HelperSettingsDefaults> singleton(create());
          return singleton.singleton();
        }

        //-----------------------------------------------------------------------
        static HelperSettingsDefaultsPtr create()
        {
          auto pThis(make_shared<HelperSettingsDefaults>());
          ISettings::installDefaults(pThis);
          return pThis;
        }

        //-----------------------------------------------------------------------
        virtual void notifySettingsApplyDefaults() override
        {
          ISettings::setString(ORTC_SERVICES_SETTING_HELPER_SERVICES_THREAD_POOL_PRIORITY, "high");
          ISettings::setString(ORTC_SERVICES_SETTING_HELPER_SERVICES_THREAD_PRIORITY, "high");
          ISettings::setString(ORTC_SERVICES_SETTING_HELPER_LOGGER_THREAD_PRIORITY, "normal");
#ifndef WINRT
          ISettings::setString(ORTC_SERVICES_SETTING_HELPER_HTTP_THREAD_PRIORITY, "normal");
#endif //ndef WINRT
        }
      };

      //-------------------------------------------------------------------------
      void installHelperSettingsDefaults()
      {
        HelperSettingsDefaults::singleton();
      }


      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------

      class IDNHelper
      {
      public:
        //---------------------------------------------------------------------
        static IDNHelper &singleton()
        {
          AutoRecursiveLock lock(*zsLib::IHelper::getGlobalLock());
          static Singleton<IDNHelper> singleton;
          return singleton.singleton();
        }

        //---------------------------------------------------------------------
        IDNHelper()
        {
          idn_result_t r = idn_nameinit(0);

          if (r != idn_success) {
            ZS_LOG_ERROR(Detail, log("unable to load IDN"))
          }
        }

        //---------------------------------------------------------------------
        Log::Params log(const char *message)
        {
          return Log::Params(message, "services::IDNHelper");
        }
      };


      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      class ServicesSetup
      {
      public:
        static ServicesSetup &singleton()
        {
          AutoRecursiveLock lock(*zsLib::IHelper::getGlobalLock());
          static Singleton<ServicesSetup> singleton;
          return singleton.singleton();
        }

        ServicesSetup()
        {
          initSubsystems();
          ZS_EVENTING_REGISTER(OrtcServices);
          IDNHelper::singleton();
          //installICESocketSettingsDefaults();
          //installICESocketSessionSettingsDefaults();
          installTURNSocketSettingsDefaults();
          installTCPMessagingSettingsDefaults();
          installLoggerSettingsDefaults();
          installHelperSettingsDefaults();
          installMessageLayerSecurityChannelSettingsDefaults();
          installBackOffTimerSettingsDefaults();
        }

        ~ServicesSetup()
        {
          ZS_EVENTING_UNREGISTER(OrtcServices);
        }
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Helper
      #pragma mark

      //-----------------------------------------------------------------------
      Log::Params Helper::slog(const char *message)
      {
        return Log::Params(message, "services::Helper");
      }

    } // namespace internal

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark Helper
    #pragma mark

    //-------------------------------------------------------------------------
    void IHelper::setup()
    {
      zsLib::eventing::IHelper::setup();
      internal::ServicesSetup::singleton();
    }

#if defined(WINRT) || defined(WIN32_RX64)
    //-----------------------------------------------------------------------
    void IHelper::setup(Windows::UI::Core::CoreDispatcher ^dispatcher)
    {
      zsLib::eventing::IHelper::setup(dispatcher);
      internal::ServicesSetup::singleton();
    }
#endif //WINRT

    //-------------------------------------------------------------------------
    IMessageQueuePtr IHelper::getServicePoolQueue()
    {
      class Once {
      public:
        Once() {
          IMessageQueueManager::registerMessageQueueThreadPriority(ORTC_SERVICES_SERVICE_THREAD_POOL_NAME, zsLib::threadPriorityFromString(ISettings::getString(ORTC_SERVICES_SETTING_HELPER_SERVICES_THREAD_PRIORITY)));
        }
      };
      static Once once;
      return IMessageQueueManager::getThreadPoolQueue(ORTC_SERVICES_SERVICE_THREAD_POOL_NAME);
    }

    //-------------------------------------------------------------------------
    IMessageQueuePtr IHelper::getServiceQueue()
    {
      class Once {
      public:
        Once() { IMessageQueueManager::registerMessageQueueThreadPriority(ORTC_SERVICES_SERVICE_THREAD_NAME, zsLib::threadPriorityFromString(ISettings::getString(ORTC_SERVICES_SETTING_HELPER_SERVICES_THREAD_PRIORITY))); }
      };
      static Once once;
      return IMessageQueueManager::getMessageQueue(ORTC_SERVICES_SERVICE_THREAD_NAME);
    }

    //-------------------------------------------------------------------------
    IMessageQueuePtr IHelper::getLoggerQueue()
    {
      class Once {
      public:
        Once() { IMessageQueueManager::registerMessageQueueThreadPriority(ORTC_SERVICES_LOGGER_THREAD_NAME, zsLib::threadPriorityFromString(ISettings::getString(ORTC_SERVICES_SETTING_HELPER_LOGGER_THREAD_PRIORITY))); }
      };
      static Once once;
      return IMessageQueueManager::getMessageQueue(ORTC_SERVICES_LOGGER_THREAD_NAME);
    }

    //-----------------------------------------------------------------------
    SecureByteBlockPtr IHelper::encrypt(
                                        const SecureByteBlock &key, // key length of 32 = AES/256
                                        const SecureByteBlock &iv,
                                        const SecureByteBlock &buffer,
                                        EncryptionAlgorthms algorithm
                                        )
    {
      return encrypt(key, iv, buffer, buffer.size(), algorithm);
    }

    //-----------------------------------------------------------------------
    SecureByteBlockPtr IHelper::encrypt(
                                        const SecureByteBlock &key, // key length of 32 = AES/256
                                        const SecureByteBlock &iv,
                                        const char *value,
                                        EncryptionAlgorthms algorithm
                                        )
    {
      return encrypt(key, iv, (const BYTE *)value, strlen(value)*sizeof(char), algorithm);
    }

    //-----------------------------------------------------------------------
    SecureByteBlockPtr IHelper::encrypt(
                                        const SecureByteBlock &key, // key length of 32 = AES/256
                                        const SecureByteBlock &iv,
                                        const BYTE *buffer,
                                        size_t bufferLengthInBytes,
                                        EncryptionAlgorthms algorithm
                                        )
    {
      SecureByteBlockPtr output(make_shared<SecureByteBlock>(bufferLengthInBytes));
      CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), iv);
      cfbEncryption.ProcessData(*output, buffer, bufferLengthInBytes);
      return output;
    }

    //-----------------------------------------------------------------------
    SecureByteBlockPtr IHelper::decrypt(
                                        const SecureByteBlock &key,
                                        const SecureByteBlock &iv,
                                        const SecureByteBlock &buffer,
                                        EncryptionAlgorthms algorithm
                                        )
    {
      SecureByteBlockPtr output(make_shared<SecureByteBlock>(buffer.size()));
      CFB_Mode<AES>::Decryption cfbDecryption(key, key.size(), iv);
      cfbDecryption.ProcessData(*output, buffer, buffer.size());
      return output;
    }

    //-----------------------------------------------------------------------
    void IHelper::splitKey(
                          const SecureByteBlock &key,
                          SecureByteBlockPtr &part1,
                          SecureByteBlockPtr &part2
                          )
    {
      if (key.size() < 1) return;

      SecureByteBlockPtr hash = IHasher::hash(key);
      ZS_THROW_BAD_STATE_IF(!hash)

      SecureByteBlockPtr randomData = IHelper::random(key.SizeInBytes() + hash->SizeInBytes());

      SecureByteBlockPtr final(make_shared<SecureByteBlock>());
      final->CleanNew(key.SizeInBytes() + hash->SizeInBytes());

      BYTE *dest = final->BytePtr();
      const BYTE *source = key.BytePtr();
      const BYTE *random = randomData->BytePtr();

      SecureByteBlock::size_type length1 = key.SizeInBytes();
      for (; length1 > 0; --length1, ++dest, ++source, ++random)
      {
        *dest = (*source) ^ (*random);
      }

      SecureByteBlock::size_type length2 = hash->SizeInBytes();
      source = hash->BytePtr();
      for (; length2 > 0; --length2, ++dest, ++source, ++random)
      {
        *dest = (*source) ^ (*random);
      }

      // set the output split key into the base 64 values
      part1 = randomData;
      part2 = final;
    }

    //-----------------------------------------------------------------------
    SecureByteBlockPtr IHelper::combineKey(
                                          const SecureByteBlockPtr &part1,
                                          const SecureByteBlockPtr &part2
                                          )
    {
      if ((!part1) || (!part2)) {
        ZS_LOG_WARNING(Detail, internal::Helper::slog("value missing") + ZS_PARAM("part1", (bool)part1) + ZS_PARAM("part2", (bool)part2))
        return SecureByteBlockPtr();
      }

      SecureByteBlockPtr extracted = IHasher::hash("empty");

      if (part1->SizeInBytes() != part2->SizeInBytes()) {
        ZS_LOG_WARNING(Detail, internal::Helper::slog("illegal size") + ZS_PARAM("part1 size", part1->SizeInBytes()) + ZS_PARAM("part2 size", part2->SizeInBytes()))
        return SecureByteBlockPtr();
      }
      if (part1->SizeInBytes() <= extracted->SizeInBytes()) {
        ZS_LOG_WARNING(Detail, internal::Helper::slog("illegal hash size") + ZS_PARAM("part size", part1->SizeInBytes()) + ZS_PARAM("hash size", extracted->SizeInBytes()))
        return SecureByteBlockPtr();
      }

      SecureByteBlockPtr buffer(make_shared<SecureByteBlock>());
      buffer->CleanNew(part1->SizeInBytes() - extracted->SizeInBytes());

      BYTE *dest = buffer->BytePtr();
      const BYTE *src1 = part1->BytePtr();
      const BYTE *src2 = part2->BytePtr();

      SecureByteBlock::size_type length1 = part1->SizeInBytes() - extracted->SizeInBytes();
      for (; 0 != length1; --length1, ++dest, ++src1, ++src2)
      {
        *dest = (*src1) ^ (*src2);
      }

      SecureByteBlock::size_type length2 = extracted->SizeInBytes();
      dest = extracted->BytePtr();
      for (; 0 != length2; --length2, ++dest, ++src1, ++src2)
      {
        *dest = (*src1) ^ (*src2);
      }

      SecureByteBlockPtr hash = IHasher::hash(*buffer);

      if (0 != IHelper::compare(*extracted, *hash)) {
        ZS_LOG_WARNING(Detail, internal::Helper::slog("extracted hash does not match calculated hash") + ZS_PARAM("extracted", IHelper::convertToBase64(*extracted)) + ZS_PARAM("calculated", IHelper::convertToBase64(*hash)))
        return SecureByteBlockPtr();
      }

      return buffer;
    }

    //-----------------------------------------------------------------------
    ElementPtr IHelper::getSignatureInfo(
                                        ElementPtr signedEl,
                                        ElementPtr *outSignatureEl,
                                        String *outFullPublicKey,
                                        String *outFingerprint
                                        )
    {
      if (!signedEl) {
        ZS_LOG_WARNING(Detail, internal::Helper::slog("requested to get signature info on a null element"))
        return ElementPtr();
      }

      ElementPtr signatureEl = signedEl->findNextSiblingElement("signature");
      if (!signatureEl) {
        // if this element does not have a signed next sibling then it can't be the signed elemnt thus assume it's the bundle passed in instead
        signedEl = signedEl->getFirstChildElement();
        while (signedEl) {
          if ("signature" != signedEl->getValue()) {
            break;
          }
          signedEl = signedEl->getNextSiblingElement();
        }

        if (!signedEl) {
          ZS_LOG_DETAIL(internal::Helper::slog("no signed element was found (is okay if signing element for first time)"))
          return ElementPtr();
        }

        signatureEl = signedEl->findNextSiblingElement("signature");
      }

      String id = signedEl->getAttributeValue("id");
      if (id.length() < 1) {
        ZS_LOG_WARNING(Detail, internal::Helper::slog("ID is missing on signed element"))
        return ElementPtr();
      }

      id = "#" + id;

      while (signatureEl) {
        ElementPtr referenceEl = signatureEl->findFirstChildElementChecked("reference");
        if (referenceEl) {
          String referenceID = referenceEl->getTextDecoded();
          if (referenceID == id) {
            ZS_LOG_TRACE(internal::Helper::slog("found the signature reference") + ZS_PARAM("reference id", id))
            break;
          }
        }

        signatureEl = signatureEl->findNextSiblingElement("signature");
      }

      if (!signatureEl) {
        ZS_LOG_WARNING(Detail, internal::Helper::slog("could not find signature element"))
        return ElementPtr();
      }

      ElementPtr keyEl = signatureEl->findFirstChildElement("key");
      if (keyEl) {
        if (outFullPublicKey) {
          *outFullPublicKey = getElementTextAndDecode(keyEl->findFirstChildElement("x509Data"));
        }
        if (outFingerprint) {
          *outFingerprint = getElementTextAndDecode(keyEl->findFirstChildElement("fingerprint"));
        }
      }

      if (outSignatureEl) {
        *outSignatureEl = signatureEl;
      }
      return signedEl;
    }

//      typedef enum punycode_status {
//        punycode_success,
//        punycode_bad_input,           /* Input is invalid.                       */
//        punycode_big_output,          /* Output would exceed the space provided. */
//        punycode_overflow             /* Input needs wider integers to process.  */
//      } punycode_status;

//      enum punycode_status punycode_encode(punycode_uint input_length,
//                                           const punycode_uint input[],
//                                           const unsigned char case_flags[],
//                                           punycode_uint * output_length,
//                                           char output[]);
//
//      enum punycode_status punycode_decode(punycode_uint input_length,
//                                           const char input[],
//                                           punycode_uint * output_length,
//                                           punycode_uint output[],
//                                           unsigned char case_flags[]);

    //-----------------------------------------------------------------------
    String IHelper::convertIDNToUTF8(const String &idnStr)
    {
      internal::IDNHelper::singleton();

      if (idnStr.isEmpty()) return String();

      size_t length = idnStr.length();

      char outputBuffer[1024] {};
      std::unique_ptr<char[]> overflowBuffer;

      char *destStr = &(outputBuffer[0]);
      size_t destLength = (sizeof(outputBuffer) / sizeof(char)) - 1;

      if (length * ORTC_SERVICES_HELPER_UNICODE_CHAR_TO_PUNY_CODE_CHARACTOR_RATIO > destLength) {
        overflowBuffer = std::unique_ptr<char[]>(new char[(length*ORTC_SERVICES_HELPER_UNICODE_CHAR_TO_PUNY_CODE_CHARACTOR_RATIO)+1] {});
        destStr = overflowBuffer.get();
        destLength = (length*ORTC_SERVICES_HELPER_UNICODE_CHAR_TO_PUNY_CODE_CHARACTOR_RATIO);
      }

      idn_result_t status = idn_decodename(IDN_DECODE_LOOKUP & (~IDN_UNICODECONV), idnStr.c_str(), destStr, destLength);

      if (idn_success != status) {
        ZS_LOG_ERROR(Detail, internal::Helper::slog("idn to utf8 convert failed") + ZS_PARAM("input idn", idnStr) + ZS_PARAM("status", status))
        return String();
      }

      return String((const char *)destStr);
    }

    //-----------------------------------------------------------------------
    String IHelper::convertUTF8ToIDN(const String &utf8Str)
    {
      internal::IDNHelper::singleton();

      if (utf8Str.isEmpty()) return String();

      size_t length = utf8Str.length();

      char outputBuffer[1024] {};
      std::unique_ptr<char[]> overflowBuffer;

      char *destStr = &(outputBuffer[0]);
      size_t destLength = (sizeof(outputBuffer) / sizeof(char)) - 1;

      if (length * ORTC_SERVICES_HELPER_UNICODE_CHAR_TO_PUNY_CODE_CHARACTOR_RATIO > destLength) {
        overflowBuffer = std::unique_ptr<char[]>(new char[(length*ORTC_SERVICES_HELPER_UNICODE_CHAR_TO_PUNY_CODE_CHARACTOR_RATIO)+1] {});
        destStr = overflowBuffer.get();
        destLength = (length*ORTC_SERVICES_HELPER_UNICODE_CHAR_TO_PUNY_CODE_CHARACTOR_RATIO);
      }

      idn_result_t status = idn_encodename(IDN_ENCODE_LOOKUP & (~IDN_UNICODECONV), utf8Str.c_str(), destStr, destLength);

      if (idn_success != status) {
        ZS_LOG_ERROR(Detail, internal::Helper::slog("utf 8 to idn convert failed") + ZS_PARAM("input utf8", utf8Str) + ZS_PARAM("status", status))
        return String();
      }

      String result((const char *)destStr);
      return result;
    }

    //-----------------------------------------------------------------------
    bool IHelper::isValidDomain(const String &inDomain)
    {
      internal::IDNHelper::singleton();

      if (inDomain.isEmpty()) return false;

      idn_result_t status = idn_checkname(IDN_CHECK_LOOKUP & (~IDN_UNICODECONV), inDomain.c_str());

      if (idn_success != status) {
        ZS_LOG_ERROR(Detail, internal::Helper::slog("idn convert failed") + ZS_PARAM("input utf8", inDomain) + ZS_PARAM("status", status))
        return false;
      }

      String domain(inDomain ? convertUTF8ToIDN(inDomain) : String());
//        std::regex exp("^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}$");
      std::regex exp("((?=[a-z0-9-]{1,63}\\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,63}$");
      if (! std::regex_match(domain, exp)) {
        ZS_LOG_WARNING(Detail, internal::Helper::slog("domain name is not valid") + ZS_PARAM("domain", domain))
        return false;
      }
      ZS_LOG_TRACE(internal::Helper::slog("valid domain") + ZS_PARAM("domain", domain))
      return true;
    }

  }
}
