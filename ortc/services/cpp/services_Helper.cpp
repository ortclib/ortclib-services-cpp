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
#include <ortc/services/internal/services_Tracing.h>
#include <ortc/services/IDNS.h>
#include <ortc/services/IMessageQueueManager.h>
#include <ortc/services/ISettings.h>

#include <cryptopp/osrng.h>

#include <zsLib/Stringize.h>
#include <zsLib/Numeric.h>
#include <zsLib/helpers.h>
#include <zsLib/Log.h>
#include <zsLib/XML.h>
#include <zsLib/MessageQueueThread.h>
#include <zsLib/Socket.h>
#include <zsLib/Timer.h>

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

#define OPENPEER_SERVICES_SERVICE_THREAD_POOL_NAME "org.openpeer.services.serviceThreadPool"
#define OPENPEER_SERVICES_SERVICE_THREAD_NAME "org.openpeer.services.serviceThread"
#define OPENPEER_SERVICES_LOGGER_THREAD_NAME "org.openpeer.services.loggerThread"

#define OPENPEER_SERVICES_HELPER_UNICODE_CHAR_TO_PUNY_CODE_CHARACTOR_RATIO (6)

namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services) } }


namespace openpeer
{
  namespace services
  {
    using zsLib::Milliseconds;

    namespace internal
    {
      using zsLib::Numeric;
      using zsLib::QWORD;

      using CryptoPP::CFB_Mode;
      using CryptoPP::HMAC;

      using CryptoPP::HexEncoder;
      using CryptoPP::HexDecoder;
      using CryptoPP::StringSink;
      using CryptoPP::ByteQueue;
      using CryptoPP::Base64Encoder;
      using CryptoPP::Base64Decoder;
      using CryptoPP::AES;
      using CryptoPP::Weak::MD5;
      using CryptoPP::SHA256;
      using CryptoPP::SHA1;

      void initSubsystems();

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
      static void set8(void* memory, size_t offset, BYTE v) {
        static_cast<BYTE*>(memory)[offset] = v;
      }

      //-------------------------------------------------------------------------
      static BYTE get8(const void* memory, size_t offset) {
        return static_cast<const BYTE*>(memory)[offset];
      }


      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------

      class IDNHelper
      {
      public:
        static IDNHelper &singleton()
        {
          AutoRecursiveLock lock(*IHelper::getGlobalLock());
          static Singleton<IDNHelper> singleton;
          return singleton.singleton();
        }

        IDNHelper()
        {
          idn_result_t r = idn_nameinit(0);

          if (r != idn_success) {
            ZS_LOG_ERROR(Detail, log("unable to load IDN"))
          }
        }

      protected:
        //-----------------------------------------------------------------------
        Log::Params log(const char *message)
        {
          return Log::Params(message, "services::IDNHelper");
        }
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------

      class CryptoPPHelper
      {
      public:
        static CryptoPPHelper &singleton()
        {
          AutoRecursiveLock lock(*IHelper::getGlobalLock());
          static Singleton<CryptoPPHelper> singleton;
          return singleton.singleton();
        }

        CryptoPPHelper()
        {
          static const char *buffer = "1234567890";

          String result;
          {
            Base64Encoder encoder(new StringSink(result), false);
            encoder.Put((const BYTE *)buffer, strlen(buffer));
            encoder.MessageEnd();
          }

          {
            String &input = result;

            ByteQueue queue;
            queue.Put((BYTE *)input.c_str(), input.size());

            ByteQueue *outputQueue = new ByteQueue;
            Base64Decoder decoder(outputQueue);
            queue.CopyTo(decoder);
            decoder.MessageEnd();
          }
        }

      protected:
        //-----------------------------------------------------------------------
        Log::Params log(const char *message)
        {
          return Log::Params(message, "services::CryptoPPHelper");
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
          AutoRecursiveLock lock(*IHelper::getGlobalLock());
          static Singleton<ServicesSetup> singleton;
          return singleton.singleton();
        }

        ServicesSetup()
        {
          EventRegisterOrtcServices();
          zsLib::setup();
          initSubsystems();
        }

        ~ServicesSetup()
        {
          EventUnregisterOrtcServices();
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
      void Helper::setup()
      {
        ServicesSetup::singleton();
        IDNHelper::singleton();
        CryptoPPHelper::singleton();
        zsLib::setup();
      }

      //-----------------------------------------------------------------------
      void Helper::debugAppend(ElementPtr &parentEl, const char *name, const char *value)
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!parentEl)
        ZS_THROW_INVALID_ARGUMENT_IF(!name)

        if (!value) return;
        if ('\0' == *value) return;

        ElementPtr element = Element::create(name);

        TextPtr tmpTxt = Text::create();
        tmpTxt->setValueAndJSONEncode(value);
        element->adoptAsFirstChild(tmpTxt);

        parentEl->adoptAsLastChild(element);
      }

      //-----------------------------------------------------------------------
      void Helper::debugAppend(ElementPtr &parentEl, const char *name, const String &value)
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!parentEl)
        ZS_THROW_INVALID_ARGUMENT_IF(!name)

        if (value.isEmpty()) return;

        ElementPtr element = Element::create(name);

        TextPtr tmpTxt = Text::create();
        tmpTxt->setValueAndJSONEncode(value);
        element->adoptAsFirstChild(tmpTxt);

        parentEl->adoptAsLastChild(element);
      }

      //-----------------------------------------------------------------------
      void Helper::debugAppendNumber(ElementPtr &parentEl, const char *name, const String &value)
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!parentEl)
        ZS_THROW_INVALID_ARGUMENT_IF(!name)

        if (value.isEmpty()) return;

        ElementPtr element = Element::create(name);

        TextPtr tmpTxt = Text::create();
        tmpTxt->setValue(value, Text::Format_JSONNumberEncoded);
        element->adoptAsFirstChild(tmpTxt);

        parentEl->adoptAsLastChild(element);
      }

      //-----------------------------------------------------------------------
      void Helper::debugAppend(ElementPtr &parentEl, const char *name, bool value, bool ignoreIfFalse)
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!name)

        if (ignoreIfFalse) {
          if (!value) return;
        }

        debugAppend(parentEl, ZS_PARAM(name, value));
      }

      //-----------------------------------------------------------------------
      void Helper::debugAppend(ElementPtr &parentEl, const Log::Param &param)
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!parentEl)

        if (!param.param()) return;

        parentEl->adoptAsLastChild(param.param());
      }
      
      //-----------------------------------------------------------------------
      void Helper::debugAppend(ElementPtr &parentEl, const char *name, ElementPtr childEl)
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!parentEl)
        ZS_THROW_INVALID_ARGUMENT_IF(!name)

        if (!childEl) return;

        ElementPtr element = Element::create(name);
        element->adoptAsLastChild(childEl);
        parentEl->adoptAsLastChild(element);
      }

      //-----------------------------------------------------------------------
      void Helper::debugAppend(ElementPtr &parentEl, ElementPtr childEl)
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!parentEl)
        if (!childEl) return;
        parentEl->adoptAsLastChild(childEl);
      }

      //-----------------------------------------------------------------------
      String Helper::toString(ElementPtr element)
      {
        if (!element) return String();

        GeneratorPtr generator = Generator::createJSONGenerator();
        std::unique_ptr<char[]> output = generator->write(element);

        return output.get();
      }

      //-----------------------------------------------------------------------
      ElementPtr Helper::toJSON(const char *str)
      {
        if (!str) return ElementPtr();

        DocumentPtr doc = Document::createFromParsedJSON(str);

        ElementPtr childEl = doc->getFirstChildElement();
        if (!childEl) return ElementPtr();
        
        childEl->orphan();
        return childEl;
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr Helper::writeAsJSON(
                                             DocumentPtr doc,
                                             bool prettyPrint
                                             )
      {
        if (!doc) return make_shared<SecureByteBlock>();

        size_t length = 0;
        std::unique_ptr<char[]> output = doc->writeAsJSON(prettyPrint, &length);

        return Helper::convertToBuffer(output, length);
      }

      //---------------------------------------------------------------------
      String Helper::getAttributeID(ElementPtr el)
      {
        return Helper::getAttribute(el, "id");
      }

      //---------------------------------------------------------------------
      void Helper::setAttributeIDWithText(ElementPtr elem, const String &value)
      {
        if (value.isEmpty()) return;
        Helper::setAttributeWithText(elem, "id", value);
      }

      //---------------------------------------------------------------------
      void Helper::setAttributeIDWithNumber(ElementPtr elem, const String &value)
      {
        if (value.isEmpty()) return;
        Helper::setAttributeWithNumber(elem, "id", value);
      }

      //-----------------------------------------------------------------------
      String Helper::getAttribute(
                                  ElementPtr node,
                                  const String &attributeName
                                  )
      {
        if (!node) return String();

        AttributePtr attribute = node->findAttribute(attributeName);
        if (!attribute) return String();

        return attribute->getValue();
      }

      //-----------------------------------------------------------------------
      void Helper::setAttributeWithText(
                                        ElementPtr elem,
                                        const String &attrName,
                                        const String &value
                                        )
      {
        if (!elem) return;
        if (value.isEmpty()) return;

        AttributePtr attr = Attribute::create();
        attr->setName(attrName);
        attr->setValue(value);

        elem->setAttribute(attr);
      }

      //-----------------------------------------------------------------------
      void Helper::setAttributeWithNumber(
                                          ElementPtr elem,
                                          const String &attrName,
                                          const String &value
                                          )
      {
        if (!elem) return;
        if (value.isEmpty()) return;

        AttributePtr attr = Attribute::create();
        attr->setName(attrName);
        attr->setValue(value);
        attr->setQuoted(false);

        elem->setAttribute(attr);
      }

      //-----------------------------------------------------------------------
      ElementPtr Helper::createElement(const String &elName)
      {
        ElementPtr tmp = Element::create();
        tmp->setValue(elName);
        return tmp;
      }

      //-----------------------------------------------------------------------
      ElementPtr Helper::createElementWithText(
                                               const String &elName,
                                               const String &textVal
                                               )
      {
        ElementPtr tmp = Element::create(elName);

        if (textVal.isEmpty()) return tmp;

        TextPtr tmpTxt = Text::create();
        tmpTxt->setValue(textVal, Text::Format_JSONStringEncoded);

        tmp->adoptAsFirstChild(tmpTxt);

        return tmp;
      }

      //-----------------------------------------------------------------------
      ElementPtr Helper::createElementWithNumber(
                                                 const String &elName,
                                                 const String &numberAsStringValue
                                                 )
      {
        ElementPtr tmp = Element::create(elName);

        if (numberAsStringValue.isEmpty()) {
          TextPtr tmpTxt = Text::create();
          tmpTxt->setValue("0", Text::Format_JSONNumberEncoded);
          tmp->adoptAsFirstChild(tmpTxt);
          return tmp;
        }

        TextPtr tmpTxt = Text::create();
        tmpTxt->setValue(numberAsStringValue, Text::Format_JSONNumberEncoded);
        tmp->adoptAsFirstChild(tmpTxt);

        return tmp;
      }

      //-----------------------------------------------------------------------
      ElementPtr Helper::createElementWithTime(
                                               const String &elName,
                                               Time time
                                               )
      {
        return createElementWithNumber(elName, IHelper::timeToString(time));
      }

      //-----------------------------------------------------------------------
      ElementPtr Helper::createElementWithTextAndJSONEncode(
                                                            const String &elName,
                                                            const String &textVal
                                                            )
      {
        ElementPtr tmp = Element::create(elName);
        if (textVal.isEmpty()) return tmp;

        TextPtr tmpTxt = Text::create();
        tmpTxt->setValueAndJSONEncode(textVal);
        tmp->adoptAsFirstChild(tmpTxt);
        return tmp;
      }

      //-----------------------------------------------------------------------
      ElementPtr Helper::createElementWithTextID(
                                                 const String &elName,
                                                 const String &idValue
                                                 )
      {
        ElementPtr tmp = createElement(elName);

        if (idValue.isEmpty()) return tmp;

        setAttributeIDWithText(tmp, idValue);
        return tmp;
      }

      //-----------------------------------------------------------------------
      ElementPtr Helper::createElementWithNumberID(
                                                   const String &elName,
                                                   const String &idValue
                                                   )
      {
        ElementPtr tmp = createElement(elName);

        if (idValue.isEmpty()) return tmp;

        setAttributeIDWithNumber(tmp, idValue);
        return tmp;
      }

      //-----------------------------------------------------------------------
      TextPtr Helper::createText(const String &textVal)
      {
        TextPtr tmpTxt = Text::create();
        tmpTxt->setValue(textVal);

        return tmpTxt;
      }

      //-----------------------------------------------------------------------
      String Helper::getElementText(ElementPtr el)
      {
        if (!el) return String();
        return el->getText();
      }

      //-----------------------------------------------------------------------
      String Helper::getElementTextAndDecode(ElementPtr el)
      {
        if (!el) return String();
        return el->getTextDecoded();
      }

      //-----------------------------------------------------------------------
      String Helper::timeToString(const Time &value)
      {
        if (Time() == value) return String();
        return string(value);
      }

      //-----------------------------------------------------------------------
      Time Helper::stringToTime(const String &str)
      {
        if (str.isEmpty()) return Time();
        if ("0" == str) return Time();

        try {
          return Numeric<Time>(str);
        } catch(const Numeric<Time>::ValueOutOfRange &) {
          ZS_LOG_WARNING(Detail, log("unable to convert value to time") + ZS_PARAM("value", str))
        }

        return Time();
      }

      //-----------------------------------------------------------------------
      String Helper::randomString(size_t lengthInChars)
      {
        static const char *randomCharArray = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        static size_t randomSize = strlen(randomCharArray);

        BYTE staticBuffer[256];
        char staticOutputBuffer[sizeof(staticBuffer)+1];

        std::unique_ptr<BYTE[]> allocatedBuffer;
        std::unique_ptr<char[]> allocatedOutputBuffer;

        BYTE *buffer = &(staticBuffer[0]);
        char *output = &(staticOutputBuffer[0]);
        if (lengthInChars > sizeof(staticBuffer)) {
          // use the allocated buffer instead
          allocatedBuffer = std::unique_ptr<BYTE[]>(new BYTE[lengthInChars]);
          allocatedOutputBuffer = std::unique_ptr<char[]>(new char[lengthInChars+1]);
          buffer = allocatedBuffer.get();
          output = allocatedOutputBuffer.get();
        }

        AutoSeededRandomPool rng;
        rng.GenerateBlock(&(buffer[0]), lengthInChars);

        memset(&(output[0]), 0, sizeof(char)*(lengthInChars+1));

        for (size_t loop = 0; loop < lengthInChars; ++loop) {
          output[loop] = randomCharArray[((buffer[loop])%randomSize)];
        }
        return String((CSTR)(&(output[0])));
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr Helper::random(size_t lengthInBytes)
      {
        SecureByteBlockPtr output(make_shared<SecureByteBlock>());
        AutoSeededRandomPool rng;
        output->CleanNew(lengthInBytes);
        rng.GenerateBlock(*output, lengthInBytes);
        return output;
      }

      //-----------------------------------------------------------------------
      size_t Helper::random(size_t minValue, size_t maxValue)
      {
        ZS_THROW_INVALID_ARGUMENT_IF(minValue > maxValue)
        if (minValue == maxValue) return minValue;

        auto range = (maxValue - minValue)+1;

        decltype(range) value = 0;

        AutoSeededRandomPool rng;
        rng.GenerateBlock((BYTE *) &value, sizeof(value));

        value = minValue + (value % range);

        return value;
      }

      //-----------------------------------------------------------------------
      int Helper::compare(
                          const SecureByteBlock &left,
                          const SecureByteBlock &right
                          )
      {
        SecureByteBlock::size_type minSize = left.SizeInBytes();
        minSize = (right.SizeInBytes() < minSize ? right.SizeInBytes() : minSize);

        int result = 0;

        if (0 != minSize) {
          result = memcmp(left, right, minSize);
          if (0 != result) return result;
        }

        // they are equal values up to the min size so compare sizes now

        if (left.SizeInBytes() < right.SizeInBytes()) {
          return -1;
        }
        if (right.SizeInBytes() < left.SizeInBytes()) {
          return 1;
        }
        return 0;
      }

      //-------------------------------------------------------------------------
      bool Helper::isEmpty(SecureByteBlockPtr buffer)
      {
        if (!buffer) return true;
        return (buffer->SizeInBytes() < 1);
      }

      //-------------------------------------------------------------------------
      bool Helper::isEmpty(const SecureByteBlock &buffer)
      {
        return (buffer.SizeInBytes() < 1);
      }

      //-------------------------------------------------------------------------
      bool Helper::hasData(SecureByteBlockPtr buffer)
      {
        if (!buffer) return false;
        return (buffer->SizeInBytes() > 0);
      }

      //-------------------------------------------------------------------------
      bool Helper::hasData(const SecureByteBlock &buffer)
      {
        return (buffer.SizeInBytes() > 0);
      }

      //-------------------------------------------------------------------------
      SecureByteBlockPtr Helper::clone(SecureByteBlockPtr pBuffer)
      {
        if (!pBuffer) return SecureByteBlockPtr();
        return Helper::clone(*pBuffer);
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr Helper::clone(const SecureByteBlock &buffer)
      {
        SecureByteBlockPtr pBuffer(make_shared<SecureByteBlock>());
        SecureByteBlock::size_type size = buffer.SizeInBytes();
        if (size < 1) return pBuffer;
        pBuffer->CleanNew(size);

        memcpy(pBuffer->BytePtr(), buffer.BytePtr(), size);
        return pBuffer;
      }

      //-----------------------------------------------------------------------
      String Helper::convertToString(const SecureByteBlock &buffer)
      {
        if (buffer.size() < 1) return String();
        return (const char *)(buffer.BytePtr());  // return buffer cast as const char *
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr Helper::convertToBuffer(const char *input)
      {
        if (NULL == input) return SecureByteBlockPtr();

        SecureByteBlockPtr output(make_shared<SecureByteBlock>());
        size_t len = strlen(input);
        if (len < 1) return output;

        output->CleanNew(sizeof(char)*len);

        memcpy(*output, input, sizeof(char)*len);
        return output;
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr Helper::convertToBuffer(
                                                 const BYTE *buffer,
                                                 size_t bufferLengthInBytes
                                                 )
      {
        SecureByteBlockPtr output(make_shared<SecureByteBlock>());

        if (bufferLengthInBytes < 1) return output;

        output->CleanNew(bufferLengthInBytes);

        memcpy(*output, buffer, bufferLengthInBytes);

        return output;
      }

      //-------------------------------------------------------------------------
      SecureByteBlockPtr Helper::convertToBuffer(
                                                 const std::unique_ptr<char[]> &arrayStr,
                                                 size_t lengthInChars,
                                                 bool wipeOriginal
                                                 )
      {
        if (!arrayStr.get()) return convertToBuffer((const BYTE *)NULL, 0);

        if (SIZE_T_MAX == lengthInChars) {
          lengthInChars = strlen(arrayStr.get());
        }

        SecureByteBlockPtr result = convertToBuffer((const BYTE *)(arrayStr.get()), lengthInChars);
        if (wipeOriginal) {
          memset(arrayStr.get(), 0, lengthInChars * sizeof(char));
        }
        return result;
      }

      //-----------------------------------------------------------------------
      String Helper::convertToBase64(
                                     const BYTE *buffer,
                                     size_t bufferLengthInBytes
                                     )
      {
        CryptoPPHelper::singleton();

        String result;
        Base64Encoder encoder(new StringSink(result), false);
        encoder.Put(buffer, bufferLengthInBytes);
        encoder.MessageEnd();
        return result;
      }

      //-----------------------------------------------------------------------
      String Helper::convertToBase64(const String &input)
      {
        if (input.isEmpty()) return String();
        return IHelper::convertToBase64((const BYTE *)(input.c_str()), input.length());
      }

      //-----------------------------------------------------------------------
      String Helper::convertToBase64(const SecureByteBlock &input)
      {
        if (input.size() < 1) return String();
        return IHelper::convertToBase64(input, input.size());
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr Helper::convertFromBase64(const String &input)
      {
        CryptoPPHelper::singleton();

        SecureByteBlockPtr output(make_shared<SecureByteBlock>());

        ByteQueue queue;
        queue.Put((BYTE *)input.c_str(), input.size());

        ByteQueue *outputQueue = new ByteQueue;
        Base64Decoder decoder(outputQueue);
        queue.CopyTo(decoder);
        decoder.MessageEnd();

        size_t outputLengthInBytes = (size_t)outputQueue->CurrentSize();

        if (outputLengthInBytes < 1) return output;

        output->CleanNew(outputLengthInBytes);

        outputQueue->Get(*output, outputLengthInBytes);
        return output;
      }

      //-----------------------------------------------------------------------
      String Helper::convertToHex(
                                  const BYTE *buffer,
                                  size_t bufferLengthInBytes,
                                  bool outputUpperCase
                                  )
      {
        String result;

        HexEncoder encoder(new StringSink(result), outputUpperCase);
        encoder.Put(buffer, bufferLengthInBytes);
        encoder.MessageEnd();

        return result;
      }

      //-----------------------------------------------------------------------
      String Helper::convertToHex(
                                  const SecureByteBlock &input,
                                  bool outputUpperCase
                                  )
      {
        return convertToHex(input, input.size(), outputUpperCase);
      }

      //-------------------------------------------------------------------------
      SecureByteBlockPtr Helper::convertFromHex(const String &input)
      {
        SecureByteBlockPtr output(make_shared<SecureByteBlock>());
        ByteQueue queue;
        queue.Put((BYTE *)input.c_str(), input.size());

        ByteQueue *outputQueue = new ByteQueue;
        HexDecoder decoder(outputQueue);
        queue.CopyTo(decoder);
        decoder.MessageEnd();

        SecureByteBlock::size_type outputLengthInBytes = (SecureByteBlock::size_type)outputQueue->CurrentSize();
        if (outputLengthInBytes < 1) return output;

        output->CleanNew(outputLengthInBytes);

        outputQueue->Get(*output, outputLengthInBytes);
        return output;
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr Helper::encrypt(
                                         const SecureByteBlock &key, // key length of 32 = AES/256
                                         const SecureByteBlock &iv,
                                         const SecureByteBlock &buffer,
                                         EncryptionAlgorthms algorithm
                                         )
      {
        return encrypt(key, iv, buffer, buffer.size(), algorithm);
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr Helper::encrypt(
                                         const SecureByteBlock &key, // key length of 32 = AES/256
                                         const SecureByteBlock &iv,
                                         const char *value,
                                         EncryptionAlgorthms algorithm
                                         )
      {
        return encrypt(key, iv, (const BYTE *)value, strlen(value)*sizeof(char), algorithm);
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr Helper::encrypt(
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
      SecureByteBlockPtr Helper::decrypt(
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
      size_t Helper::getHashDigestSize(HashAlgorthms algorithm)
      {
        switch (algorithm) {
          case HashAlgorthm_MD5:      {
            MD5 hasher;
            return hasher.DigestSize();
          }
          case HashAlgorthm_SHA1:     {
            SHA1 hasher;
            return hasher.DigestSize();
          }
          case HashAlgorthm_SHA256:   {
            SHA256 hasher;
            return hasher.DigestSize();
          }
        }

        return 0;
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr Helper::hash(
                                      const char *value,
                                      HashAlgorthms algorithm
                                      )
      {
        SecureByteBlockPtr output;

        switch (algorithm) {
          case HashAlgorthm_MD5:      {
            MD5 hasher;
            output = make_shared<SecureByteBlock>(hasher.DigestSize());
            hasher.Update((const BYTE *)(value), strlen(value));
            hasher.Final(*output);
            break;
          }
          case HashAlgorthm_SHA1:     {
            SHA1 hasher;
            output = make_shared<SecureByteBlock>(hasher.DigestSize());
            hasher.Update((const BYTE *)(value), strlen(value));
            hasher.Final(*output);
            break;
          }
          case HashAlgorthm_SHA256:   {
            SHA256 hasher;
            output = make_shared<SecureByteBlock>(hasher.DigestSize());
            hasher.Update((const BYTE *)(value), strlen(value));
            hasher.Final(*output);
            break;
          }
        }

        return output;
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr Helper::hash(
                                      const SecureByteBlock &buffer,
                                      HashAlgorthms algorithm
                                      )
      {
        SecureByteBlockPtr output;

        switch (algorithm) {
          case HashAlgorthm_MD5:      {
            MD5 hasher;
            output = make_shared<SecureByteBlock>(hasher.DigestSize());
            hasher.Update(buffer.BytePtr(), buffer.SizeInBytes());
            hasher.Final(*output);
            break;
          }
          case HashAlgorthm_SHA1:     {
            SHA1 hasher;
            output = make_shared<SecureByteBlock>(hasher.DigestSize());
            hasher.Update(buffer.BytePtr(), buffer.SizeInBytes());
            hasher.Final(*output);
            break;
          }
          case HashAlgorthm_SHA256:   {
            SHA256 hasher;
            output = make_shared<SecureByteBlock>(hasher.DigestSize());
            hasher.Update(buffer.BytePtr(), buffer.SizeInBytes());
            hasher.Final(*output);
            break;
          }
        }

        return output;
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr Helper::hmacKeyFromPassphrase(const char *passphrase)
      {
        return convertToBuffer(passphrase);
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr Helper::hmacKeyFromPassphrase(const std::string &passphrase)
      {
        return convertToBuffer(passphrase.c_str());
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr Helper::hmac(
                                      const SecureByteBlock &key,
                                      const String &value,
                                      HashAlgorthms algorithm
                                      )
      {
        return hmac(key, (const BYTE *)(value.c_str()), value.length(), algorithm);
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr Helper::hmac(
                                      const SecureByteBlock &key,
                                      const SecureByteBlock &buffer,
                                      HashAlgorthms algorithm
                                      )
      {
        return hmac(key, buffer, buffer.size(), algorithm);
      }

      //-----------------------------------------------------------------------
      SecureByteBlockPtr Helper::hmac(
                                      const SecureByteBlock &key,
                                      const BYTE *buffer,
                                      size_t bufferLengthInBytes,
                                      HashAlgorthms algorithm
                                      )
      {
        SecureByteBlockPtr output;

        switch (algorithm) {
          case HashAlgorthm_MD5:      {
            HMAC<MD5> hasher(key, key.size());
            output = make_shared<SecureByteBlock>(hasher.DigestSize());
            hasher.Update(buffer, bufferLengthInBytes);
            hasher.Final(*output);
            break;
          }
          case HashAlgorthm_SHA1:     {
            HMAC<SHA1> hasher(key, key.size());
            output = make_shared<SecureByteBlock>(hasher.DigestSize());
            hasher.Update(buffer, bufferLengthInBytes);
            hasher.Final(*output);
            break;
          }
          case HashAlgorthm_SHA256:   {
            HMAC<SHA256> hasher(key, key.size());
            output = make_shared<SecureByteBlock>(hasher.DigestSize());
            hasher.Update(buffer, bufferLengthInBytes);
            hasher.Final(*output);
            break;
          }
        }

        return output;
      }

      //-----------------------------------------------------------------------
      void Helper::splitKey(
                            const SecureByteBlock &key,
                            SecureByteBlockPtr &part1,
                            SecureByteBlockPtr &part2
                            )
      {
        if (key.size() < 1) return;

        SecureByteBlockPtr hash = IHelper::hash(key);
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
      SecureByteBlockPtr Helper::combineKey(
                                            const SecureByteBlockPtr &part1,
                                            const SecureByteBlockPtr &part2
                                            )
      {
        if ((!part1) || (!part2)) {
          ZS_LOG_WARNING(Detail, log("value missing") + ZS_PARAM("part1", (bool)part1) + ZS_PARAM("part2", (bool)part2))
          return SecureByteBlockPtr();
        }

        SecureByteBlockPtr extracted = IHelper::hash("empty");

        if (part1->SizeInBytes() != part2->SizeInBytes()) {
          ZS_LOG_WARNING(Detail, log("illegal size") + ZS_PARAM("part1 size", part1->SizeInBytes()) + ZS_PARAM("part2 size", part2->SizeInBytes()))
          return SecureByteBlockPtr();
        }
        if (part1->SizeInBytes() <= extracted->SizeInBytes()) {
          ZS_LOG_WARNING(Detail, log("illegal hash size") + ZS_PARAM("part size", part1->SizeInBytes()) + ZS_PARAM("hash size", extracted->SizeInBytes()))
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

        SecureByteBlockPtr hash = IHelper::hash(*buffer);

        if (0 != IHelper::compare(*extracted, *hash)) {
          ZS_LOG_WARNING(Detail, log("extracted hash does not match calculated hash") + ZS_PARAM("extracted", IHelper::convertToBase64(*extracted)) + ZS_PARAM("calculated", IHelper::convertToBase64(*hash)))
          return SecureByteBlockPtr();
        }

        return buffer;
      }

      //-----------------------------------------------------------------------
      ElementPtr Helper::getSignatureInfo(
                                          ElementPtr signedEl,
                                          ElementPtr *outSignatureEl,
                                          String *outFullPublicKey,
                                          String *outFingerprint
                                          )
      {
        if (!signedEl) {
          ZS_LOG_WARNING(Detail, log("requested to get signature info on a null element"))
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
            ZS_LOG_DETAIL(log("no signed element was found (is okay if signing element for first time)"))
            return ElementPtr();
          }

          signatureEl = signedEl->findNextSiblingElement("signature");
        }

        String id = signedEl->getAttributeValue("id");
        if (id.length() < 1) {
          ZS_LOG_WARNING(Detail, log("ID is missing on signed element"))
          return ElementPtr();
        }

        id = "#" + id;

        while (signatureEl) {
          ElementPtr referenceEl = signatureEl->findFirstChildElementChecked("reference");
          if (referenceEl) {
            String referenceID = referenceEl->getTextDecoded();
            if (referenceID == id) {
              ZS_LOG_TRACE(log("found the signature reference") + ZS_PARAM("reference id", id))
              break;
            }
          }

          signatureEl = signatureEl->findNextSiblingElement("signature");
        }

        if (!signatureEl) {
          ZS_LOG_WARNING(Detail, log("could not find signature element"))
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

      //-----------------------------------------------------------------------
      ElementPtr Helper::cloneAsCanonicalJSON(ElementPtr element)
      {
        if (!element) return element;

        class Walker : public WalkSink
        {
        public:
          Walker() {}

          virtual bool onElementEnter(ElementPtr inElement)
          {
            typedef std::list<NodePtr> ChildrenList;
            typedef std::list<AttributePtr> ChildrenAttributeList;

            // sort the elements and "other" node types
            {
              ChildrenList children;

              while (inElement->hasChildren()) {
                NodePtr child = inElement->getFirstChild();
                child->orphan();
                children.push_back(child);
              }

              NodePtr lastInsert;
              bool insertedElement = false;
              while (children.size() > 0)
              {
                NodePtr currentNode = children.front();
                children.pop_front();

                ElementPtr currentEl = (currentNode->isElement() ? currentNode->toElement() : ElementPtr());

                if (!insertedElement) {
                  inElement->adoptAsLastChild(currentNode);
                  lastInsert = currentNode;
                  insertedElement = true;
                  continue;
                }

                if (!currentEl) {
                  lastInsert->adoptAsNextSibling(currentNode);
                  lastInsert = currentNode;
                  continue;
                }

                insertedElement = true; // will have to be true now as this child is an element

                String currentName = currentEl->getValue();

                // I know this isn't optmized as it's insertion sort but this was not meant to canonicalize the entire text of a book, but rather tiny snippets of JSON...

                bool inserted = false;

                ElementPtr childEl = inElement->getFirstChildElement();
                while (childEl) {
                  String childName = childEl->getValue();

                  if (currentName < childName) {
                    // must insert before this child
                    childEl->adoptAsPreviousSibling(currentEl);
                    lastInsert = currentEl;
                    inserted = true;
                    break;
                  }

                  childEl = childEl->getNextSiblingElement();
                }

                if (inserted)
                  continue;

                inElement->adoptAsLastChild(currentEl);
                lastInsert = currentEl;
              }

              ZS_THROW_BAD_STATE_IF(children.size() > 0)
            }

            // sort the attributes
            {
              ChildrenAttributeList children;

              while (inElement->getFirstAttribute()) {
                AttributePtr child = inElement->getFirstAttribute();
                child->orphan();
                children.push_back(child);
              }

              while (children.size() > 0)
              {
                AttributePtr current = children.front();
                children.pop_front();

                // I know this isn't optimized as it's insertion sort but this was not meant to canonicalize the entire text of a book, but rather tiny snippets of JSON...

                AttributePtr child = inElement->getFirstAttribute();
                if (!child) {
                  inElement->setAttribute(current);
                  continue;
                }

                bool inserted = false;
                String currentName = current->getName();

                while (child) {
                  String childName = child->getName();

                  if (currentName < childName) {
                    // must insert before this child
                    child->adoptAsPreviousSibling(current);
                    inserted = true;
                    break;
                  }

                  NodePtr nextNode = child->getNextSibling();
                  if (!nextNode) break;
                  child = nextNode->toAttribute();
                }

                if (inserted)
                  continue;

                // there *MUST* be a last attribute or crash
                inElement->getLastAttributeChecked()->adoptAsNextSibling(current);
              }

              ZS_THROW_BAD_STATE_IF(children.size() > 0)
            }

            return false;
          }

        private:
        };

        if (ZS_IS_LOGGING(Insane)) {
          ZS_LOG_BASIC(log("vvvvvvvvvvvv -- PRE-SORT  -- vvvvvvvvvvvv"))
          {
            GeneratorPtr generator = Generator::createJSONGenerator();
            std::unique_ptr<char[]> output = generator->write(element);
            ZS_LOG_BASIC( ((CSTR)output.get()) )
          }
          ZS_LOG_BASIC(log("^^^^^^^^^^^^ -- PRE-SORT  -- ^^^^^^^^^^^^"))
        }
        ElementPtr convertEl = element->clone()->toElement();

        Node::FilterList filter;
        filter.push_back(Node::NodeType::Element);
        Walker walker;
        convertEl->walk(walker, &filter);

        if (ZS_IS_LOGGING(Insane)) {
          // let's output some logging...
          ZS_LOG_BASIC(log("vvvvvvvvvvvv -- POST-SORT -- vvvvvvvvvvvv"))
          {
            GeneratorPtr generator = Generator::createJSONGenerator();
            std::unique_ptr<char[]> output = generator->write(convertEl);
            ZS_LOG_BASIC( ((CSTR)output.get()) )
          }
          ZS_LOG_BASIC(log("^^^^^^^^^^^^ -- POST-SORT -- ^^^^^^^^^^^^"))
        }

        return convertEl;
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
      String Helper::convertIDNToUTF8(const String &idnStr)
      {
        IDNHelper::singleton();
        if (idnStr.isEmpty()) return String();

        size_t length = idnStr.length();

        char outputBuffer[1024] {};
        std::unique_ptr<char[]> overflowBuffer;

        char *destStr = &(outputBuffer[0]);
        size_t destLength = (sizeof(outputBuffer) / sizeof(char)) - 1;

        if (length * OPENPEER_SERVICES_HELPER_UNICODE_CHAR_TO_PUNY_CODE_CHARACTOR_RATIO > destLength) {
          overflowBuffer = std::unique_ptr<char[]>(new char[(length*OPENPEER_SERVICES_HELPER_UNICODE_CHAR_TO_PUNY_CODE_CHARACTOR_RATIO)+1] {});
          destStr = overflowBuffer.get();
          destLength = (length*OPENPEER_SERVICES_HELPER_UNICODE_CHAR_TO_PUNY_CODE_CHARACTOR_RATIO);
        }

        idn_result_t status = idn_decodename(IDN_DECODE_LOOKUP & (~IDN_UNICODECONV), idnStr.c_str(), destStr, destLength);

        if (idn_success != status) {
          ZS_LOG_ERROR(Detail, log("idn to utf8 convert failed") + ZS_PARAM("input idn", idnStr) + ZS_PARAM("status", status))
          return String();
        }

        return String((CSTR)destStr);
      }

      //-----------------------------------------------------------------------
      String Helper::convertUTF8ToIDN(const String &utf8Str)
      {
        IDNHelper::singleton();

        if (utf8Str.isEmpty()) return String();

        size_t length = utf8Str.length();

        char outputBuffer[1024] {};
        std::unique_ptr<char[]> overflowBuffer;

        char *destStr = &(outputBuffer[0]);
        size_t destLength = (sizeof(outputBuffer) / sizeof(char)) - 1;

        if (length * OPENPEER_SERVICES_HELPER_UNICODE_CHAR_TO_PUNY_CODE_CHARACTOR_RATIO > destLength) {
          overflowBuffer = std::unique_ptr<char[]>(new char[(length*OPENPEER_SERVICES_HELPER_UNICODE_CHAR_TO_PUNY_CODE_CHARACTOR_RATIO)+1] {});
          destStr = overflowBuffer.get();
          destLength = (length*OPENPEER_SERVICES_HELPER_UNICODE_CHAR_TO_PUNY_CODE_CHARACTOR_RATIO);
        }

        idn_result_t status = idn_encodename(IDN_ENCODE_LOOKUP & (~IDN_UNICODECONV), utf8Str.c_str(), destStr, destLength);

        if (idn_success != status) {
          ZS_LOG_ERROR(Detail, log("utf 8 to idn convert failed") + ZS_PARAM("input utf8", utf8Str) + ZS_PARAM("status", status))
          return String();
        }

        String result((CSTR)destStr);
        return result;
      }

      //-----------------------------------------------------------------------
      bool Helper::isValidDomain(const String &inDomain)
      {
        IDNHelper::singleton();

        if (inDomain.isEmpty()) return false;

        idn_result_t status = idn_checkname(IDN_CHECK_LOOKUP & (~IDN_UNICODECONV), inDomain.c_str());

        if (idn_success != status) {
          ZS_LOG_ERROR(Detail, log("idn convert failed") + ZS_PARAM("input utf8", inDomain) + ZS_PARAM("status", status))
          return false;
        }

        String domain(inDomain ? convertUTF8ToIDN(inDomain) : String());
//        std::regex exp("^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}$");
        std::regex exp("((?=[a-z0-9-]{1,63}\\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,63}$");
        if (! std::regex_match(domain, exp)) {
          ZS_LOG_WARNING(Detail, log("domain name is not valid") + ZS_PARAM("domain", domain))
          return false;
        }
        ZS_LOG_TRACE(log("valid domain") + ZS_PARAM("domain", domain))
        return true;
      }

      //-----------------------------------------------------------------------
      void Helper::split(
                         const String &input,
                         SplitMap &outResult,
                         char splitChar
                         )
      {
        if (0 == input.size()) return;

        size_t start = input.find(splitChar);
        size_t end = String::npos;

        Index index = 0;
        if (String::npos == start) {
          outResult[index] = input;
          return;
        }

        if (0 != start) {
          // case where start is not a split char
          outResult[index] = input.substr(0, start);
          ++index;
        }
        
        do {
          end = input.find(splitChar, start+1);
          
          if (end == String::npos) {
            // there is no more splits left so copy from start split char to end
            outResult[index] = input.substr(start+1);
            ++index;
            break;
          }
          
          // take the mid-point of the string
          if (end != start+1) {
            outResult[index] = input.substr(start+1, end-(start+1));
            ++index;
          } else {
            outResult[index] = String();
            ++index;
          }

          // the next starting point will be the current end point
          start = end;
        } while (true);
      }
      
      //-----------------------------------------------------------------------
      void Helper::split(
                         const String &input,
                         SplitMap &outResult,
                         const char *inSplitStr
                         )
      {
        String splitStr(inSplitStr);

        Index index = 0;

        if (0 == input.size()) return;
        if (splitStr.isEmpty()) {
          outResult[index] = input;
          return;
        }

        size_t start = input.find(splitStr);
        size_t end = String::npos;

        if (String::npos == start) {
          outResult[index] = input;
          return;
        }

        if (0 != start) {
          // case where start is not a split str
          outResult[index] = input.substr(0, start);
          ++index;
        }

        do {
          end = input.find(splitStr, start+splitStr.length());

          if (end == String::npos) {
            // there is no more splits left so copy from start / to end
            outResult[index] = input.substr(start+1);
            ++index;
            break;
          }

          // take the mid-point of the string
          if (end != start+splitStr.length()) {
            outResult[index] = input.substr(start+splitStr.length(), end-(start+splitStr.length()));
            ++index;
          } else {
            outResult[index] = String();
            ++index;
          }

          // the next starting point will be the current end point
          start = end;
        } while (true);
      }
      
      //-----------------------------------------------------------------------
      void Helper::splitPruneEmpty(
                                   SplitMap &ioResult,
                                   bool reindex
                                   )
      {
        if (!reindex) {
          for (auto iter_doNotUse = ioResult.begin(); iter_doNotUse != ioResult.end();) {
            auto current = iter_doNotUse;
            ++iter_doNotUse;

            const String &value = (*current).second;
            if (value.hasData()) continue;
            ioResult.erase(current);
          }
          return;
        }

        Index index = 0;
        SplitMap temp;
        for (auto iter = ioResult.begin(); iter != ioResult.end(); ++iter) {
          const String &value = (*iter).second;
          if (value.isEmpty()) continue;

          temp[index] = value;
          ++index;
        }

        ioResult = temp;
      }

      //-----------------------------------------------------------------------
      void Helper::splitTrim(SplitMap &ioResult)
      {
        for (auto iter = ioResult.begin(); iter != ioResult.end(); ++iter) {
          auto &value = (*iter).second;
          value.trim();
        }
      }

      //-------------------------------------------------------------------------
      String Helper::combine(
                             const SplitMap &input,
                             const char *combineStr
                             )
      {
        String result;
        String spacer(combineStr);

        for (auto iter = input.begin(); iter != input.end(); ++iter) {
          auto &value = (*iter).second;
          if (result.hasData()) {
            result.append(spacer);
          }
          result.append(value);
        }
        return result;
      }

      //-------------------------------------------------------------------------
      String Helper::combine(
                             const StringList &input,
                             const char *combineStr
                             )
      {
        String result;
        String spacer(combineStr);

        for (auto iter = input.begin(); iter != input.end(); ++iter) {
          auto &value = (*iter);
          if (result.hasData()) {
            result.append(spacer);
          }
          result.append(value);
        }
        return result;
      }

      //-----------------------------------------------------------------------
      const String &Helper::get(
                                const SplitMap &inResult,
                                Index index
                                )
      {
        static String empty;
        SplitMap::const_iterator found = inResult.find(index);
        if (found == inResult.end()) return empty;
        return (*found).second;
      }

      static char convertArray[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

      //-----------------------------------------------------------------------
      String Helper::getDebugString(
                                    const BYTE *buffer,
                                    size_t bufferSizeInBytes,
                                    ULONG bytesPerGroup,
                                    ULONG maxLineLength
                                    )
      {
        if (!buffer) return String();
        if (0 == bufferSizeInBytes) return String();

        ZS_THROW_INVALID_ARGUMENT_IF(bytesPerGroup < 1)
        ZS_THROW_INVALID_ARGUMENT_IF(maxLineLength < 1)

        // two chars needed, one for new line, one for NUL byte
        char bufferFillLine[255+2];
        memset(&(bufferFillLine[0]), 0, sizeof(bufferFillLine));

        char *fillLine = &(bufferFillLine[0]);

        std::unique_ptr<char[]> temp;
        if (maxLineLength > 255) {
          temp = std::unique_ptr<char[]>(new char[maxLineLength+2]);
          memset(temp.get(), 0, sizeof(char)*(maxLineLength+2));
          fillLine = temp.get();
        }

        String result;
        bool firstLine = true;

        // each byte takes two hex digits and one representative character, each group needs one space between each group
        ULONG charsPerGroup = (bytesPerGroup * 3) + 1;

        ULONG groupsPerLine = maxLineLength / charsPerGroup;
        groupsPerLine = (groupsPerLine < 1 ? 1: groupsPerLine);

        while (bufferSizeInBytes > 0) {

          const BYTE *start = buffer;
          size_t totalBytesWritten = 0;

          char *fill = fillLine;

          for (ULONG groups = 0; (groups < groupsPerLine); ++groups) {
            size_t bytesInNextGroup = (bufferSizeInBytes < bytesPerGroup ? bufferSizeInBytes : bytesPerGroup);
            size_t bytesMissingInGroup = bytesPerGroup - bytesInNextGroup;
            for (size_t pos = 0; pos < bytesInNextGroup; ++pos, ++buffer, ++totalBytesWritten) {
              BYTE value = *buffer;

              *fill = convertArray[value / 16];
              ++fill;
              *fill = convertArray[value % 16];
              ++fill;
            }

            if (!firstLine) {
              for (size_t pos = 0; pos < bytesMissingInGroup; ++pos) {
                // no more bytes available in the group thus insert two spaces per byte instead
                *fill = ' ';
                ++fill;
                *fill = ' ';
                ++fill;
              }
            }

            *fill = ' ';
            ++fill;

            bufferSizeInBytes -= bytesInNextGroup;
          }

          buffer = start;
          for (size_t pos = 0; pos < totalBytesWritten; ++pos, ++buffer) {
            if (isprint(*buffer)) {
              *fill = *buffer;
            } else {
              *fill = '.';
            }
            ++fill;
          }

          if ((bufferSizeInBytes > 0) ||
              (!firstLine)) {
            *fill = '\n';
            ++fill;
          }

          *fill = 0;

          result += fillLine;
          firstLine = false;
        }

        return result;
      }

      //-----------------------------------------------------------------------
      Log::Params Helper::log(const char *message)
      {
        return Log::Params(message, "services::Helper");
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark (other)
      #pragma mark

      //-----------------------------------------------------------------------
      void Helper::parseIPs(const String  &ipList, IPAddressMap &outMap)
      {
        outMap.clear();

        if (ipList.isEmpty()) return;

        SplitMap splits;

        split(ipList, splits, ',');

        for (size_t i = 0; i < splits.size(); ++i) {
          String value = (*(splits.find(i))).second;

          value.trim();

          try {
            IPAddress ip(value);
            ip.setPort(0);  // strip off any port

            outMap[ip] = true;
          } catch(IPAddress::Exceptions::ParseError &) {
          }
        }
      }

      //-----------------------------------------------------------------------
      bool Helper::containsIP(
                              const IPAddressMap &inMap,
                              const IPAddress &inIP,
                              bool emptyMapReturns
                              )
      {
        if (inMap.empty()) return emptyMapReturns;

        IPAddress ip(inIP);
        if (ip.getPort()) {
          ip.setPort(0);
        }

        return inMap.find(ip) != inMap.end();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark services::IHelper
    #pragma mark

    //-------------------------------------------------------------------------
    void IHelper::setup()
    {
      internal::Helper::setup();
    }

    //-------------------------------------------------------------------------
    RecursiveLockPtr IHelper::getGlobalLock()
    {
      static internal::SingletonLazySharedPtr<RecursiveLock> singleton(make_shared<RecursiveLock>());
      return singleton.singleton();
    }

    //-------------------------------------------------------------------------
    void IHelper::setSocketThreadPriority()
    {
      zsLib::Socket::setMonitorPriority(zsLib::threadPriorityFromString(ISettings::getString(OPENPEER_SERVICES_SETTING_HELPER_SOCKET_MONITOR_THREAD_PRIORITY)));
    }

    //-------------------------------------------------------------------------
    void IHelper::setTimerThreadPriority()
    {
      zsLib::Timer::setMonitorPriority(zsLib::threadPriorityFromString(ISettings::getString(OPENPEER_SERVICES_SETTING_HELPER_TIMER_MONITOR_THREAD_PRIORITY)));
    }

    //-------------------------------------------------------------------------
    IMessageQueuePtr IHelper::getServicePoolQueue()
    {
      class Once {
      public:
        Once() {
          IMessageQueueManager::registerMessageQueueThreadPriority(OPENPEER_SERVICES_SERVICE_THREAD_POOL_NAME, zsLib::threadPriorityFromString(ISettings::getString(OPENPEER_SERVICES_SETTING_HELPER_SERVICES_THREAD_PRIORITY)));
          setTimerThreadPriority();
        }
      };
      static Once once;
      return IMessageQueueManager::getThreadPoolQueue(OPENPEER_SERVICES_SERVICE_THREAD_POOL_NAME);
    }

    //-------------------------------------------------------------------------
    IMessageQueuePtr IHelper::getServiceQueue()
    {
      class Once {
      public:
        Once() {IMessageQueueManager::registerMessageQueueThreadPriority(OPENPEER_SERVICES_SERVICE_THREAD_NAME, zsLib::threadPriorityFromString(ISettings::getString(OPENPEER_SERVICES_SETTING_HELPER_SERVICES_THREAD_PRIORITY)));}
      };
      static Once once;
      return IMessageQueueManager::getMessageQueue(OPENPEER_SERVICES_SERVICE_THREAD_NAME);
    }

    //-------------------------------------------------------------------------
    IMessageQueuePtr IHelper::getLoggerQueue()
    {
      class Once {
      public:
        Once() {IMessageQueueManager::registerMessageQueueThreadPriority(OPENPEER_SERVICES_LOGGER_THREAD_NAME, zsLib::threadPriorityFromString(ISettings::getString(OPENPEER_SERVICES_SETTING_HELPER_LOGGER_THREAD_PRIORITY)));}
      };
      static Once once;
      return IMessageQueueManager::getMessageQueue(OPENPEER_SERVICES_LOGGER_THREAD_NAME);
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, const char *value)
    {
      return internal::Helper::debugAppend(parentEl, name, value);
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, const String &value)
    {
      return internal::Helper::debugAppend(parentEl, name, value);
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, bool value, bool ignoreIfFalse)
    {
      return internal::Helper::debugAppend(parentEl, name, value, ignoreIfFalse);
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, CHAR value, bool ignoreIfZero)
    {
      if (ignoreIfZero) if (0 == value) return;
      internal::Helper::debugAppendNumber(parentEl, name, zsLib::string((INT)value));
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, UCHAR value, bool ignoreIfZero)
    {
      if (ignoreIfZero) if (0 == value) return;
      internal::Helper::debugAppendNumber(parentEl, name, zsLib::string((UINT)value));
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, SHORT value, bool ignoreIfZero)
    {
      if (ignoreIfZero) if (0 == value) return;
      internal::Helper::debugAppendNumber(parentEl, name, zsLib::string((INT)value));
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, USHORT value, bool ignoreIfZero)
    {
      if (ignoreIfZero) if (0 == value) return;
      internal::Helper::debugAppendNumber(parentEl, name, zsLib::string((UINT)value));
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, INT value, bool ignoreIfZero)
    {
      if (ignoreIfZero) if (0 == value) return;
      internal::Helper::debugAppendNumber(parentEl, name, zsLib::string(value));
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, UINT value, bool ignoreIfZero)
    {
      if (ignoreIfZero) if (0 == value) return;
      internal::Helper::debugAppendNumber(parentEl, name, zsLib::string(value));
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, LONG value, bool ignoreIfZero)
    {
      if (ignoreIfZero) if (0 == value) return;
      internal::Helper::debugAppendNumber(parentEl, name, zsLib::string(value));
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, ULONG value, bool ignoreIfZero)
    {
      if (ignoreIfZero) if (0 == value) return;
      internal::Helper::debugAppendNumber(parentEl, name, zsLib::string(value));
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, LONGLONG value, bool ignoreIfZero)
    {
      if (ignoreIfZero) if (0 == value) return;
      internal::Helper::debugAppendNumber(parentEl, name, zsLib::string(value));
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, ULONGLONG value, bool ignoreIfZero)
    {
      if (ignoreIfZero) if (0 == value) return;
      internal::Helper::debugAppendNumber(parentEl, name, zsLib::string(value));
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, FLOAT value, bool ignoreIfZero)
    {
      if (ignoreIfZero) if (0.0f == value) return;
      internal::Helper::debugAppendNumber(parentEl, name, zsLib::string(value));
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, DOUBLE value, bool ignoreIfZero)
    {
      if (ignoreIfZero) if (0.0 == value) return;
      internal::Helper::debugAppendNumber(parentEl, name, zsLib::string(value));
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, const Time &value)
    {
      if (Time() == value) return;
      internal::Helper::debugAppendNumber(parentEl, name, zsLib::string(value));
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, const Hours &value)
    {
      if (Hours() == value) return;
      IHelper::debugAppend(parentEl, name, zsLib::string(value));
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, const Minutes &value)
    {
      if (Hours() == value) return;
      IHelper::debugAppend(parentEl, name, zsLib::string(value));
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, const Seconds &value)
    {
      if (Hours() == value) return;
      IHelper::debugAppend(parentEl, name, zsLib::string(value));
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, const Milliseconds &value)
    {
      if (Hours() == value) return;
      IHelper::debugAppend(parentEl, name, zsLib::string(value));
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, const Microseconds &value)
    {
      if (Hours() == value) return;
      IHelper::debugAppend(parentEl, name, zsLib::string(value));
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, const Nanoseconds &value)
    {
      if (Hours() == value) return;
      IHelper::debugAppend(parentEl, name, zsLib::string(value));
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const Log::Param &param)
    {
      return internal::Helper::debugAppend(parentEl, param);
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, const char *name, ElementPtr childEl)
    {
      return internal::Helper::debugAppend(parentEl, name, childEl);
    }

    //-------------------------------------------------------------------------
    void IHelper::debugAppend(ElementPtr &parentEl, ElementPtr childEl)
    {
      return internal::Helper::debugAppend(parentEl, childEl);
    }

    //-------------------------------------------------------------------------
    String IHelper::toString(ElementPtr el)
    {
      return internal::Helper::toString(el);
    }

    //-------------------------------------------------------------------------
    ElementPtr IHelper::toJSON(const char *str)
    {
      return internal::Helper::toJSON(str);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::writeAsJSON(
                                            DocumentPtr doc,
                                            bool prettyPrint
                                            )
    {
      return internal::Helper::writeAsJSON(doc, prettyPrint);
    }

    //-------------------------------------------------------------------------
    String IHelper::getAttribute(
                                 ElementPtr el,
                                 const String &attributeName
                                 )
    {
      return internal::Helper::getAttribute(el, attributeName);
    }

    //-------------------------------------------------------------------------
    void IHelper::setAttributeWithText(
                                       ElementPtr el,
                                       const String &attrName,
                                       const String &value
                                       )
    {
      internal::Helper::setAttributeWithText(el, attrName, value);
    }

    //-------------------------------------------------------------------------
    void IHelper::setAttributeWithNumber(
                                         ElementPtr el,
                                         const String &attrName,
                                         const String &value
                                         )
    {
      internal::Helper::setAttributeWithNumber(el, attrName, value);
    }

    //-------------------------------------------------------------------------
    ElementPtr IHelper::createElement(const String &elName)
    {
      return internal::Helper::createElement(elName);
    }

    //-------------------------------------------------------------------------
    ElementPtr IHelper::createElementWithText(
                                              const String &elName,
                                              const String &textVal
                                              )
    {
      return internal::Helper::createElementWithText(elName, textVal);
    }

    //-------------------------------------------------------------------------
    ElementPtr IHelper::createElementWithNumber(
                                                const String &elName,
                                                const String &numberAsStringValue
                                                )
    {
      return internal::Helper::createElementWithNumber(elName, numberAsStringValue);
    }

    //-------------------------------------------------------------------------
    ElementPtr IHelper::createElementWithTime(
                                              const String &elName,
                                              Time time
                                              )
    {
      return internal::Helper::createElementWithTime(elName, time);
    }

    //-------------------------------------------------------------------------
    ElementPtr IHelper::createElementWithTextAndJSONEncode(
                                                           const String &elName,
                                                           const String &textVal
                                                           )
    {
      return internal::Helper::createElementWithTextAndJSONEncode(elName, textVal);
    }

    //-------------------------------------------------------------------------
    ElementPtr IHelper::createElementWithTextID(
                                                const String &elName,
                                                const String &idValue
                                                )
    {
      return internal::Helper::createElementWithTextID(elName, idValue);
    }

    //-------------------------------------------------------------------------
    ElementPtr IHelper::createElementWithNumberID(
                                                  const String &elName,
                                                  const String &idValue
                                                  )
    {
      return internal::Helper::createElementWithNumberID(elName, idValue);
    }
    
    //-------------------------------------------------------------------------
    TextPtr IHelper::createText(const String &textVal)
    {
      return internal::Helper::createText(textVal);
    }

    //-------------------------------------------------------------------------
    String IHelper::getElementText(ElementPtr el)
    {
      return internal::Helper::getElementText(el);
    }

    //-------------------------------------------------------------------------
    String IHelper::getElementTextAndDecode(ElementPtr el)
    {
      return internal::Helper::getElementTextAndDecode(el);
    }

    //-------------------------------------------------------------------------
    String IHelper::timeToString(const Time &value)
    {
      return internal::Helper::timeToString(value);
    }

    //-------------------------------------------------------------------------
    Time IHelper::stringToTime(const String &str)
    {
      return internal::Helper::stringToTime(str);
    }

    //-------------------------------------------------------------------------
    String IHelper::randomString(size_t lengthInChars)
    {
      return internal::Helper::randomString(lengthInChars);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::random(size_t lengthInBytes)
    {
      return internal::Helper::random(lengthInBytes);
    }

    //-------------------------------------------------------------------------
    size_t IHelper::random(size_t minValue, size_t maxValue)
    {
      return internal::Helper::random(minValue, maxValue);
    }

    //-------------------------------------------------------------------------
    int IHelper::compare(
                         const SecureByteBlock &left,
                         const SecureByteBlock &right
                         )
    {
      return internal::Helper::compare(left, right);
    }

    //-------------------------------------------------------------------------
    bool IHelper::isEmpty(SecureByteBlockPtr buffer)
    {
      return internal::Helper::isEmpty(buffer);
    }

    //-------------------------------------------------------------------------
    bool IHelper::isEmpty(const SecureByteBlock &buffer)
    {
      return internal::Helper::isEmpty(buffer);
    }

    //-------------------------------------------------------------------------
    bool IHelper::hasData(SecureByteBlockPtr buffer)
    {
      return internal::Helper::hasData(buffer);
    }

    //-------------------------------------------------------------------------
    bool IHelper::hasData(const SecureByteBlock &buffer)
    {
      return internal::Helper::hasData(buffer);
    }
    
    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::clone(SecureByteBlockPtr pBuffer)
    {
      return internal::Helper::clone(pBuffer);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::clone(const SecureByteBlock &buffer)
    {
      return internal::Helper::clone(buffer);
    }

    //-------------------------------------------------------------------------
    String IHelper::convertToString(const SecureByteBlock &buffer)
    {
      return internal::Helper::convertToString(buffer);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::convertToBuffer(const char *input)
    {
      return internal::Helper::convertToBuffer(input);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::convertToBuffer(const std::string &input)
    {
      return internal::Helper::convertToBuffer(input.c_str());
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::convertToBuffer(
                                                const BYTE *buffer,
                                                size_t bufferLengthInBytes
                                                )
    {
      return internal::Helper::convertToBuffer(buffer, bufferLengthInBytes);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::convertToBuffer(
                                                const std::unique_ptr<char[]> arrayStr,
                                                size_t lengthInChars,
                                                bool wipeOriginal
                                                )
    {
      return internal::Helper::convertToBuffer(arrayStr, lengthInChars, wipeOriginal);
    }

    //-------------------------------------------------------------------------
    WORD IHelper::getBE16(const void* memory)
    {
      return static_cast<WORD>((internal::get8(memory, 0) << 8) |
                               (internal::get8(memory, 1) << 0));
    }

    //-------------------------------------------------------------------------
    DWORD IHelper::getBE32(const void* memory)
    {
      return (static_cast<DWORD>(internal::get8(memory, 0)) << 24) |
             (static_cast<DWORD>(internal::get8(memory, 1)) << 16) |
             (static_cast<DWORD>(internal::get8(memory, 2)) << 8) |
             (static_cast<DWORD>(internal::get8(memory, 3)) << 0);
    }

    //-------------------------------------------------------------------------
    QWORD IHelper::getBE64(const void* memory)
    {
      return (static_cast<QWORD>(internal::get8(memory, 0)) << 56) |
             (static_cast<QWORD>(internal::get8(memory, 1)) << 48) |
             (static_cast<QWORD>(internal::get8(memory, 2)) << 40) |
             (static_cast<QWORD>(internal::get8(memory, 3)) << 32) |
             (static_cast<QWORD>(internal::get8(memory, 4)) << 24) |
             (static_cast<QWORD>(internal::get8(memory, 5)) << 16) |
             (static_cast<QWORD>(internal::get8(memory, 6)) << 8) |
             (static_cast<QWORD>(internal::get8(memory, 7)) << 0);
    }

    //-------------------------------------------------------------------------
    void IHelper::setBE16(void* memory, WORD v)
    {
      internal::set8(memory, 0, static_cast<BYTE>(v >> 8));
      internal::set8(memory, 1, static_cast<BYTE>(v >> 0));
    }

    //-------------------------------------------------------------------------
    void IHelper::setBE32(void* memory, DWORD v)
    {
      internal::set8(memory, 0, static_cast<BYTE>(v >> 24));
      internal::set8(memory, 1, static_cast<BYTE>(v >> 16));
      internal::set8(memory, 2, static_cast<BYTE>(v >> 8));
      internal::set8(memory, 3, static_cast<BYTE>(v >> 0));
    }

    //-------------------------------------------------------------------------
    void IHelper::setBE64(void* memory, QWORD v)
    {
      internal::set8(memory, 0, static_cast<BYTE>(v >> 56));
      internal::set8(memory, 1, static_cast<BYTE>(v >> 48));
      internal::set8(memory, 2, static_cast<BYTE>(v >> 40));
      internal::set8(memory, 3, static_cast<BYTE>(v >> 32));
      internal::set8(memory, 4, static_cast<BYTE>(v >> 24));
      internal::set8(memory, 5, static_cast<BYTE>(v >> 16));
      internal::set8(memory, 6, static_cast<BYTE>(v >> 8));
      internal::set8(memory, 7, static_cast<BYTE>(v >> 0));
    }

    //-------------------------------------------------------------------------
    String IHelper::convertToBase64(
                                    const BYTE *buffer,
                                    size_t bufferLengthInBytes
                                    )
    {      
      return internal::Helper::convertToBase64(buffer, bufferLengthInBytes);
    }

    //-------------------------------------------------------------------------
    String IHelper::convertToBase64(const String &input)
    {
      return internal::Helper::convertToBase64(input);
    }

    //-------------------------------------------------------------------------
    String IHelper::convertToBase64(const SecureByteBlock &input)
    {
      return internal::Helper::convertToBase64(input);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::convertFromBase64(const String &input)
    {
      return internal::Helper::convertFromBase64(input);
    }

    //-------------------------------------------------------------------------
    String IHelper::convertToHex(
                                 const BYTE *buffer,
                                 size_t bufferLengthInBytes,
                                 bool outputUpperCase
                                 )
    {
      return internal::Helper::convertToHex(buffer, bufferLengthInBytes, outputUpperCase);
    }

    //-------------------------------------------------------------------------
    String IHelper::convertToHex(
                                 const SecureByteBlock &input,
                                 bool outputUpperCase
                                 )
    {
      return internal::Helper::convertToHex(input, outputUpperCase);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::convertFromHex(const String &input)
    {
      return internal::Helper::convertFromHex(input);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::encrypt(
                                        const SecureByteBlock &key,
                                        const SecureByteBlock &iv,
                                        const SecureByteBlock &buffer,
                                        EncryptionAlgorthms algorithm
                                        )
    {
      return internal::Helper::encrypt(key, iv, buffer, algorithm);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::encrypt(
                                        const SecureByteBlock &key, // key length of 32 = AES/256
                                        const SecureByteBlock &iv,
                                        const char *value,
                                        EncryptionAlgorthms algorithm
                                        )
    {
      return internal::Helper::encrypt(key, iv, value, algorithm);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::encrypt(
                                        const SecureByteBlock &key, // key length of 32 = AES/256
                                        const SecureByteBlock &iv,
                                        const std::string &value,
                                        EncryptionAlgorthms algorithm
                                        )
    {
      return internal::Helper::encrypt(key, iv, value.c_str(), algorithm);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::encrypt(
                                        const SecureByteBlock &key, // key length of 32 = AES/256
                                        const SecureByteBlock &iv,
                                        const BYTE *buffer,
                                        size_t bufferLengthInBytes,
                                        EncryptionAlgorthms algorithm
                                        )
    {
      return internal::Helper::encrypt(key, iv, buffer, bufferLengthInBytes, algorithm);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::decrypt(
                                        const SecureByteBlock &key,
                                        const SecureByteBlock &iv,
                                        const SecureByteBlock &buffer,
                                        EncryptionAlgorthms algorithm
                                        )
    {
      return internal::Helper::decrypt(key, iv, buffer, algorithm);
    }

    //-------------------------------------------------------------------------
    size_t IHelper::getHashDigestSize(HashAlgorthms algorithm)
    {
      return internal::Helper::getHashDigestSize(algorithm);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::hash(
                                     const char *buffer,
                                     HashAlgorthms algorithm
                                     )
    {
      return internal::Helper::hash(buffer, algorithm);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::hash(
                                     const std::string &buffer,
                                     HashAlgorthms algorithm
                                     )
    {
      return internal::Helper::hash(buffer.c_str(), algorithm);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::hash(
                                     const SecureByteBlock &buffer,
                                     HashAlgorthms algorithm
                                     )
    {
      return internal::Helper::hash(buffer, algorithm);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::hmacKeyFromPassphrase(const char *passphrase)
    {
      return internal::Helper::hmacKeyFromPassphrase(passphrase);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::hmacKeyFromPassphrase(const std::string &passphrase)
    {
      return internal::Helper::hmacKeyFromPassphrase(passphrase);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::hmac(
                                     const SecureByteBlock &key,
                                     const char *value,
                                     HashAlgorthms algorithm
                                     )
    {
      return internal::Helper::hmac(key, value, algorithm);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::hmac(
                                     const SecureByteBlock &key,
                                     const std::string &value,
                                     HashAlgorthms algorithm
                                     )
    {
      return internal::Helper::hmac(key, value.c_str(), algorithm);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::hmac(
                                     const SecureByteBlock &key,
                                     const SecureByteBlock &buffer,
                                     HashAlgorthms algorithm
                                     )
    {
      return internal::Helper::hmac(key, buffer, algorithm);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::hmac(
                                     const SecureByteBlock &key,
                                     const BYTE *buffer,
                                     size_t bufferLengthInBytes,
                                     HashAlgorthms algorithm
                                     )
    {
      return internal::Helper::hmac(key, buffer, bufferLengthInBytes, algorithm);
    }

    //-------------------------------------------------------------------------
    void IHelper::splitKey(
                           const SecureByteBlock &key,
                           SecureByteBlockPtr &part1,
                           SecureByteBlockPtr &part2
                           )
    {
      return internal::Helper::splitKey(key, part1, part2);
    }

    //-------------------------------------------------------------------------
    SecureByteBlockPtr IHelper::combineKey(
                                           const SecureByteBlockPtr &part1,
                                           const SecureByteBlockPtr &part2
                                           )
    {
      return internal::Helper::combineKey(part1, part2);
    }

    //-------------------------------------------------------------------------
    ElementPtr IHelper::getSignatureInfo(
                                         ElementPtr signedEl,
                                         ElementPtr *outSignatureEl,
                                         String *outFullPublicKey,
                                         String *outFingerprint
                                         )
    {
      return internal::Helper::getSignatureInfo(signedEl, outSignatureEl, outFullPublicKey, outFingerprint);
    }

    //-------------------------------------------------------------------------
    ElementPtr IHelper::cloneAsCanonicalJSON(ElementPtr element)
    {
      return internal::Helper::cloneAsCanonicalJSON(element);
    }

    //-------------------------------------------------------------------------
    String IHelper::convertIDNToUTF8(const String &idnStr)
    {
      return internal::Helper::convertIDNToUTF8(idnStr);
    }

    //-------------------------------------------------------------------------
    String IHelper::convertUTF8ToIDN(const String &utf8Str)
    {
      return internal::Helper::convertUTF8ToIDN(utf8Str);
    }

    //-------------------------------------------------------------------------
    bool IHelper::isValidDomain(const String &domain)
    {
      return internal::Helper::isValidDomain(domain);
    }

    //-------------------------------------------------------------------------
    void IHelper::split(
                        const String &input,
                        SplitMap &outResult,
                        char splitChar
                        )
    {
      internal::Helper::split(input, outResult, splitChar);
    }

    //-------------------------------------------------------------------------
    void IHelper::split(
                        const String &input,
                        SplitMap &outResult,
                        const char *splitStr
                        )
    {
      internal::Helper::split(input, outResult, splitStr);
    }

    //-------------------------------------------------------------------------
    void IHelper::splitPruneEmpty(
                                  SplitMap &ioResult,
                                  bool reindex
                                  )
    {
      internal::Helper::splitPruneEmpty(ioResult, reindex);
    }

    //-------------------------------------------------------------------------
    void IHelper::splitTrim(SplitMap &ioResult)
    {
      internal::Helper::splitTrim(ioResult);
    }

    //-------------------------------------------------------------------------
    String IHelper::combine(
      const SplitMap &input,
      const char *combineStr
      )
    {
      return internal::Helper::combine(input, combineStr);
    }

    //-------------------------------------------------------------------------
    String IHelper::combine(
                            const StringList &input,
                            const char *combineStr
                            )
    {
      return internal::Helper::combine(input, combineStr);
    }

    //-------------------------------------------------------------------------
    const String &IHelper::get(
                               const SplitMap &inResult,
                               Index index
                               )
    {
      return internal::Helper::get(inResult, index);
    }

    //-------------------------------------------------------------------------
    String IHelper::getDebugString(
                                   const BYTE *buffer,
                                   size_t bufferSizeInBytes,
                                   ULONG bytesPerGroup,
                                   ULONG maxLineLength
                                   )
    {
      return internal::Helper::getDebugString(buffer, bufferSizeInBytes, bytesPerGroup, maxLineLength);
    }

    //-------------------------------------------------------------------------
    String IHelper::getDebugString(
                                   const SecureByteBlock &buffer,
                                   ULONG bytesPerGroup,
                                   ULONG maxLineLength
                                   )
    {
      return internal::Helper::getDebugString(buffer.BytePtr(), buffer.SizeInBytes(), bytesPerGroup, maxLineLength);
    }
  }
}
