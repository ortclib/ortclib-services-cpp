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

#ifdef WINUWP

#ifdef __cplusplus_winrt
#include <windows.ui.core.h>
#endif //__cplusplus_winrt

#ifdef __has_include
#if __has_include(<winrt/windows.ui.core.h>)
#include <winrt/windows.ui.core.h>
#endif //__has_include(<winrt/windows.ui.core.h>)
#endif //__has_include

#endif //WINUWP


#include <ortc/services/internal/services_Helper.h>
#include <ortc/services/internal/services.events.h>
#include <ortc/services/internal/services.events.jman.h>
#include <ortc/services/internal/services_HTTP.h>
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

#ifndef _WIN32
#include <idn/api.h>
#else
#include <Windows.h>
#endif //ndef _WIN32

#define ORTC_SERVICES_SERVICE_THREAD_POOL_NAME "org.ortclib.services.serviceThreadPool"
#define ORTC_SERVICES_SERVICE_THREAD_NAME "org.ortclib.services.serviceThread"
#define ORTC_SERVICES_LOGGER_THREAD_NAME "org.ortclib.services.loggerThread"

#define ORTC_SERVICES_HELPER_UNICODE_CHAR_TO_PUNY_CODE_CHARACTOR_RATIO (6)

namespace ortc { namespace services { ZS_DECLARE_SUBSYSTEM(org_ortc_services) } }

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
      //
      // (forwards)
      //

      void initSubsystems() noexcept;
      void installICESocketSettingsDefaults() noexcept;
      void installICESocketSessionSettingsDefaults() noexcept;
      void installTURNSocketSettingsDefaults() noexcept;
      void installTCPMessagingSettingsDefaults() noexcept;
      void installLoggerSettingsDefaults() noexcept;
      void installMessageLayerSecurityChannelSettingsDefaults() noexcept;
      void installBackOffTimerSettingsDefaults() noexcept;
      void installHttpSettingsDefaults() noexcept;
      void installHttpOverrideSettingsDefaults() noexcept;
      void installHttpOverrideSettingsDefaults() noexcept;


      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // (helpers)
      //

      //-----------------------------------------------------------------------
      void throwOnlySetOnce()
      {
        ZS_THROW_INVALID_USAGE("services::LockValue object is only allowed to be set once")
      }


      //-------------------------------------------------------------------------
      //-------------------------------------------------------------------------
      //-------------------------------------------------------------------------
      //-------------------------------------------------------------------------
      //
      // HelperSettingsDefaults
      //

      class HelperSettingsDefaults : public ISettingsApplyDefaultsDelegate
      {
      public:
        //-----------------------------------------------------------------------
        ~HelperSettingsDefaults() noexcept
        {
          ISettings::removeDefaults(*this);
        }

        //-----------------------------------------------------------------------
        static HelperSettingsDefaultsPtr singleton() noexcept
        {
          static SingletonLazySharedPtr<HelperSettingsDefaults> singleton(create());
          return singleton.singleton();
        }

        //-----------------------------------------------------------------------
        static HelperSettingsDefaultsPtr create() noexcept
        {
          auto pThis(make_shared<HelperSettingsDefaults>());
          ISettings::installDefaults(pThis);
          return pThis;
        }

        //-----------------------------------------------------------------------
        virtual void notifySettingsApplyDefaults() noexcept override
        {
          ISettings::setString(ORTC_SERVICES_SETTING_HELPER_SERVICES_THREAD_POOL_PRIORITY, "high");
          ISettings::setString(ORTC_SERVICES_SETTING_HELPER_SERVICES_THREAD_PRIORITY, "high");
          ISettings::setString(ORTC_SERVICES_SETTING_HELPER_LOGGER_THREAD_PRIORITY, "normal");
#ifndef WINUWP
          ISettings::setString(ORTC_SERVICES_SETTING_HELPER_HTTP_THREAD_PRIORITY, "normal");
#endif //ndef WINUWP
        }
      };

      //-------------------------------------------------------------------------
      void installHelperSettingsDefaults() noexcept
      {
        HelperSettingsDefaults::singleton();
      }


      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------

#ifndef _WIN32
      class IDNHelper
      {
      public:
        //---------------------------------------------------------------------
        static IDNHelper &singleton() noexcept
        {
          AutoRecursiveLock lock(*zsLib::IHelper::getGlobalLock());
          static Singleton<IDNHelper> singleton;
          return singleton.singleton();
        }

        //---------------------------------------------------------------------
        IDNHelper() noexcept
        {
          idn_result_t r = idn_nameinit(0);

          if (r != idn_success) {
            ZS_LOG_ERROR(Detail, log("unable to load IDN"))
          }
        }

        //---------------------------------------------------------------------
        Log::Params log(const char *message) noexcept
        {
          return Log::Params(message, "services::IDNHelper");
        }
      };
#endif //ndef _WIN32


      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      class ServicesSetup
      {
      public:
        static ServicesSetup &singleton() noexcept
        {
          AutoRecursiveLock lock(*zsLib::IHelper::getGlobalLock());
          static Singleton<ServicesSetup> singleton;
          return singleton.singleton();
        }

        ServicesSetup() noexcept
        {
          initSubsystems();
          ZS_EVENTING_REGISTER(OrtcServices);
#ifndef _WIN32
          IDNHelper::singleton();
#endif //ndef _WIN32
          //installICESocketSettingsDefaults();
          //installICESocketSessionSettingsDefaults();
          installTURNSocketSettingsDefaults();
          installTCPMessagingSettingsDefaults();
          installLoggerSettingsDefaults();
          installHelperSettingsDefaults();
          installMessageLayerSecurityChannelSettingsDefaults();
          installBackOffTimerSettingsDefaults();
#if defined(HAVE_HTTP_CURL) || defined(HAVE_HTTP_WINUWP)
          installHttpSettingsDefaults();
#endif // defined(HAVE_HTTP_CURL) || defined(HAVE_HTTP_WINUWP)
          installHttpOverrideSettingsDefaults();
        }

        ~ServicesSetup() noexcept
        {
          ZS_EVENTING_UNREGISTER(OrtcServices);
        }
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // Helper
      //

      //-----------------------------------------------------------------------
      Log::Params Helper::slog(const char *message) noexcept
      {
        return Log::Params(message, "services::Helper");
      }

    } // namespace internal

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //
    // Helper
    //

    //-------------------------------------------------------------------------
    void IHelper::setup() noexcept
    {
      zsLib::eventing::IHelper::setup();
      internal::ServicesSetup::singleton();
    }

#ifdef WINUWP
#ifdef __cplusplus_winrt
    //-----------------------------------------------------------------------
    void IHelper::setup(Windows::UI::Core::CoreDispatcher ^dispatcher) noexcept
    {
      zsLib::eventing::IHelper::setup(dispatcher);
      internal::ServicesSetup::singleton();
    }
#endif  //__cplusplus_winrt
#ifdef CPPWINRT_VERSION
    //-----------------------------------------------------------------------
    void IHelper::setup(winrt::Windows::UI::Core::CoreDispatcher dispatcher) noexcept
    {
      zsLib::eventing::IHelper::setup(dispatcher);
      internal::ServicesSetup::singleton();
    }
#endif //CPPWINRT_VERSION
#endif //WINUWP

    //-------------------------------------------------------------------------
    IMessageQueuePtr IHelper::getServicePoolQueue() noexcept
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
    IMessageQueuePtr IHelper::getServiceQueue() noexcept
    {
      class Once {
      public:
        Once() { IMessageQueueManager::registerMessageQueueThreadPriority(ORTC_SERVICES_SERVICE_THREAD_NAME, zsLib::threadPriorityFromString(ISettings::getString(ORTC_SERVICES_SETTING_HELPER_SERVICES_THREAD_PRIORITY))); }
      };
      static Once once;
      return IMessageQueueManager::getMessageQueue(ORTC_SERVICES_SERVICE_THREAD_NAME);
    }

    //-------------------------------------------------------------------------
    IMessageQueuePtr IHelper::getLoggerQueue() noexcept
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
                                        ) noexcept
    {
      return encrypt(key, iv, buffer, buffer.size(), algorithm);
    }

    //-----------------------------------------------------------------------
    SecureByteBlockPtr IHelper::encrypt(
                                        const SecureByteBlock &key, // key length of 32 = AES/256
                                        const SecureByteBlock &iv,
                                        const char *value,
                                        EncryptionAlgorthms algorithm
                                        ) noexcept
    {
      return encrypt(key, iv, (const BYTE *)value, strlen(value)*sizeof(char), algorithm);
    }

    //-----------------------------------------------------------------------
    SecureByteBlockPtr IHelper::encrypt(
                                        const SecureByteBlock &key, // key length of 32 = AES/256
                                        const SecureByteBlock &iv,
                                        const BYTE *buffer,
                                        size_t bufferLengthInBytes,
                                        ZS_MAYBE_USED() EncryptionAlgorthms algorithm
                                        ) noexcept
    {
      ZS_MAYBE_USED(algorithm);
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
                                        ZS_MAYBE_USED() EncryptionAlgorthms algorithm
                                        ) noexcept
    {
      ZS_MAYBE_USED(algorithm);
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
                          ) noexcept
    {
      if (key.size() < 1) return;

      SecureByteBlockPtr hash = IHasher::hash(key);
      ZS_ASSERT(hash);

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
                                          ) noexcept
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
                                        ) noexcept
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
    String IHelper::convertIDNToUTF8(const String &idnStr) noexcept
    {
#ifndef _WIN32
      internal::IDNHelper::singleton();
#endif //ndef _WIN32

      if (idnStr.isEmpty()) return String();

#ifdef _WIN32
      std::wstring wstr(idnStr.wstring());
      auto result = IdnToUnicode(IDN_USE_STD3_ASCII_RULES, wstr.c_str(), static_cast<int>(wstr.length()), nullptr, 0);

      wchar_t outputBuffer[1024]{};
      std::unique_ptr<wchar_t[]> overflowBuffer;

      wchar_t *destStr = &(outputBuffer[0]);
      size_t destLength = (sizeof(outputBuffer) / sizeof(wchar_t)) - 1;

      if (0 == result) {
        ZS_LOG_ERROR(Detail, internal::Helper::slog("idn to utf8 convert failed") + ZS_PARAM("input idn", idnStr) + ZS_PARAM("error", GetLastError()));
        return String();
      }

      if (static_cast<decltype(destLength)>(result) > destLength) {
        overflowBuffer = std::unique_ptr<wchar_t[]>(new wchar_t[(result) + 1]{});
        destStr = overflowBuffer.get();
        destLength = result;
      }

      memset(destStr, 0, sizeof(wchar_t)*(destLength + 1));
      result = IdnToUnicode(IDN_USE_STD3_ASCII_RULES, wstr.c_str(), static_cast<int>(wstr.length()), destStr, static_cast<int>(destLength));

      if (0 == result) {
        ZS_LOG_ERROR(Detail, internal::Helper::slog("idn to utf8 convert failed") + ZS_PARAM("input idn", idnStr) + ZS_PARAM("error", GetLastError()));
        return String();
      }

      return String(destStr);

#else //_WIN32
      char outputBuffer[1024]{};
      std::unique_ptr<char[]> overflowBuffer;

      char *destStr = &(outputBuffer[0]);
      size_t destLength = (sizeof(outputBuffer) / sizeof(char)) - 1;

      size_t length = idnStr.length();

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
#endif // _WIN32
    }

    //-----------------------------------------------------------------------
    String IHelper::convertUTF8ToIDN(const String &utf8Str) noexcept
    {
#ifndef _WIN32
      internal::IDNHelper::singleton();
#endif //ndef _WIN32

      if (utf8Str.isEmpty()) return String();

#ifdef _WIN32
      std::wstring wstr(utf8Str.wstring());
      auto result = IdnToAscii(IDN_USE_STD3_ASCII_RULES, wstr.c_str(), static_cast<int>(wstr.length()), nullptr, 0);

      wchar_t outputBuffer[1024]{};
      std::unique_ptr<wchar_t[]> overflowBuffer;

      wchar_t *destStr = &(outputBuffer[0]);
      size_t destLength = (sizeof(outputBuffer) / sizeof(wchar_t)) - 1;

      if (0 == result) {
        ZS_LOG_ERROR(Detail, internal::Helper::slog("utf8 to idn convert failed") + ZS_PARAM("input idn", utf8Str) + ZS_PARAM("error", GetLastError()));
        return String();
      }

      if (static_cast<decltype(destLength)>(result) > destLength) {
        overflowBuffer = std::unique_ptr<wchar_t[]>(new wchar_t[(result)+1]{});
        destStr = overflowBuffer.get();
        destLength = result;
      }

      memset(destStr, 0, sizeof(wchar_t)*(destLength + 1));
      result = IdnToAscii(IDN_USE_STD3_ASCII_RULES, wstr.c_str(), static_cast<int>(wstr.length()), destStr, static_cast<int>(destLength));

      if (0 == result) {
        ZS_LOG_ERROR(Detail, internal::Helper::slog("utf8 to idn convert failed") + ZS_PARAM("input idn", utf8Str) + ZS_PARAM("error", GetLastError()));
        return String();
      }

      return String(destStr);

#else //_WIN32
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
#endif //_WIN32
    }

    //-----------------------------------------------------------------------
    bool IHelper::isValidDomain(const String &inDomain) noexcept
    {
#ifndef _WIN32
      internal::IDNHelper::singleton();
#endif // _WIN32

      if (inDomain.isEmpty()) return false;

#ifdef _WIN32
      std::wstring wstr(inDomain.wstring());
      auto result = IdnToAscii(IDN_USE_STD3_ASCII_RULES, wstr.c_str(), static_cast<int>(wstr.length()), nullptr, 0);

      if (0 == result) {
        ZS_LOG_ERROR(Detail, internal::Helper::slog("idn convert failed") + ZS_PARAM("input utf8", inDomain) + ZS_PARAM("error", GetLastError()));
        return false;
      }
#else //_WIN32

      idn_result_t status = idn_checkname(IDN_CHECK_LOOKUP & (~IDN_UNICODECONV), inDomain.c_str());

      if (idn_success != status) {
        ZS_LOG_ERROR(Detail, internal::Helper::slog("idn convert failed") + ZS_PARAM("input utf8", inDomain) + ZS_PARAM("status", status))
        return false;
      }
#endif //_WIN32

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
