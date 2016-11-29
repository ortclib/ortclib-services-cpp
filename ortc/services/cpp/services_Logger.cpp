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

#include <ortc/services/internal/services_Logger.h>
#include <ortc/services/internal/services.events.h>
#include <ortc/services/IBackgrounding.h>
#include <ortc/services/IDNS.h>
#include <ortc/services/IHelper.h>

#include <cryptopp/osrng.h>

#include <zsLib/Stringize.h>
#include <zsLib/helpers.h>
#include <zsLib/Log.h>
#include <zsLib/Socket.h>
#include <zsLib/IMessageQueueThread.h>
#include <zsLib/ITimer.h>
#include <zsLib/ISettings.h>
#include <zsLib/IWakeDelegate.h>
#include <zsLib/XML.h>
#include <zsLib/Numeric.h>
#include <zsLib/Singleton.h>

#include <iostream>
#include <fstream>
#include <ctime>

#ifdef HAVE_GMTIME_S
#include <time.h>
#endif //HAVE_GMTIME_S

#ifndef _WIN32
#include <pthread.h>
#endif //ndef _WIN32

#ifdef __QNX__
#ifndef NDEBUG
#include <QDebug>
#endif //ndef NDEBUG
#endif //__QNX__

namespace ortc { namespace services { ZS_DECLARE_SUBSYSTEM(ortc_services) } }

#define ORTC_SERVICES_DEFAULT_OUTGOING_TELNET_PORT (59999)
#define ORTC_SERVICES_MAX_TELNET_LOGGER_PENDING_CONNECTIONBACKLOG_TIME_SECONDS (60)

#define ORTC_SERVICES_SEQUENCE_ESCAPE                    "\x1B"
#define ORTC_SERVICES_SEQUENCE_COLOUR_RESET              ORTC_SERVICES_SEQUENCE_ESCAPE "[0m"
#define ORTC_SERVICES_SEQUENCE_COLOUR_THREAD             ORTC_SERVICES_SEQUENCE_COLOUR_RESET ORTC_SERVICES_SEQUENCE_ESCAPE "[33m"
#define ORTC_SERVICES_SEQUENCE_COLOUR_TIME               ORTC_SERVICES_SEQUENCE_COLOUR_RESET ORTC_SERVICES_SEQUENCE_ESCAPE "[33m"
#define ORTC_SERVICES_SEQUENCE_COLOUR_SEVERITY_INFO      ORTC_SERVICES_SEQUENCE_COLOUR_RESET ORTC_SERVICES_SEQUENCE_ESCAPE "[36m"
#define ORTC_SERVICES_SEQUENCE_COLOUR_SEVERITY_WARNING   ORTC_SERVICES_SEQUENCE_COLOUR_RESET ORTC_SERVICES_SEQUENCE_ESCAPE "[35m"
#define ORTC_SERVICES_SEQUENCE_COLOUR_SEVERITY_ERROR     ORTC_SERVICES_SEQUENCE_COLOUR_RESET ORTC_SERVICES_SEQUENCE_ESCAPE "[31m"
#define ORTC_SERVICES_SEQUENCE_COLOUR_SEVERITY_FATAL     ORTC_SERVICES_SEQUENCE_COLOUR_RESET ORTC_SERVICES_SEQUENCE_ESCAPE "[31m"
#define ORTC_SERVICES_SEQUENCE_COLOUR_SEVERITY           ORTC_SERVICES_SEQUENCE_COLOUR_RESET ORTC_SERVICES_SEQUENCE_ESCAPE "[36m"
#define ORTC_SERVICES_SEQUENCE_COLOUR_MESSAGE_BASIC      ORTC_SERVICES_SEQUENCE_COLOUR_RESET ORTC_SERVICES_SEQUENCE_ESCAPE "[1m" ORTC_SERVICES_SEQUENCE_ESCAPE "[30m"
#define ORTC_SERVICES_SEQUENCE_COLOUR_MESSAGE_DETAIL     ORTC_SERVICES_SEQUENCE_COLOUR_RESET ORTC_SERVICES_SEQUENCE_ESCAPE "[1m" ORTC_SERVICES_SEQUENCE_ESCAPE "[30m"
#define ORTC_SERVICES_SEQUENCE_COLOUR_MESSAGE_DEBUG      ORTC_SERVICES_SEQUENCE_COLOUR_RESET ORTC_SERVICES_SEQUENCE_ESCAPE "[30m"
#define ORTC_SERVICES_SEQUENCE_COLOUR_MESSAGE_TRACE      ORTC_SERVICES_SEQUENCE_COLOUR_RESET ORTC_SERVICES_SEQUENCE_ESCAPE "[34m"
#define ORTC_SERVICES_SEQUENCE_COLOUR_MESSAGE_INSANE     ORTC_SERVICES_SEQUENCE_COLOUR_RESET ORTC_SERVICES_SEQUENCE_ESCAPE "[36m"
#define ORTC_SERVICES_SEQUENCE_COLOUR_FILENAME           ORTC_SERVICES_SEQUENCE_COLOUR_RESET ORTC_SERVICES_SEQUENCE_ESCAPE "[32m"
#define ORTC_SERVICES_SEQUENCE_COLOUR_LINENUMBER         ORTC_SERVICES_SEQUENCE_COLOUR_RESET ORTC_SERVICES_SEQUENCE_ESCAPE "[32m"
#define ORTC_SERVICES_SEQUENCE_COLOUR_FUNCTION           ORTC_SERVICES_SEQUENCE_COLOUR_RESET ORTC_SERVICES_SEQUENCE_ESCAPE "[36m"


#define ORTC_SERVICES_LOGGER_STDOUT_NAMESPACE "org.ortc.services.internal.StdOutLogger"
#define ORTC_SERVICES_LOGGER_FILE_NAMESPACE "org.ortc.services.internal.FileLogger"
#define ORTC_SERVICES_LOGGER_DEBUG_NAMESPACE "org.ortc.services.internal.DebugLogger"
#define ORTC_SERVICES_LOGGER_TELNET_INCOMING_NAMESPACE "org.ortc.services.internal.TelnetLogger.incoming"
#define ORTC_SERVICES_LOGGER_TELNET_OUTGOING_NAMESPACE "org.ortc.services.internal.TelnetLogger.outgoing"

namespace ortc
{
  namespace services
  {
    using zsLib::Numeric;
    using zsLib::AutoRecursiveLock;
    using zsLib::Seconds;
    using zsLib::Milliseconds;
    using zsLib::Microseconds;

    namespace internal
    {
      ZS_DECLARE_INTERACTION_PTR(ILoggerReferencesHolderDelegate);
      ZS_DECLARE_CLASS_PTR(LoggerReferencesHolder);
      ZS_DECLARE_CLASS_PTR(LoggerSettingsDefaults);

      //-------------------------------------------------------------------------
      //-------------------------------------------------------------------------
      //-------------------------------------------------------------------------
      //-------------------------------------------------------------------------
      #pragma mark
      #pragma mark LoggerSettingsDefaults
      #pragma mark

      class LoggerSettingsDefaults : public ISettingsApplyDefaultsDelegate
      {
      public:
        //-----------------------------------------------------------------------
        ~LoggerSettingsDefaults()
        {
          ISettings::removeDefaults(*this);
        }

        //-----------------------------------------------------------------------
        static LoggerSettingsDefaultsPtr singleton()
        {
          static SingletonLazySharedPtr<LoggerSettingsDefaults> singleton(create());
          return singleton.singleton();
        }

        //-----------------------------------------------------------------------
        static LoggerSettingsDefaultsPtr create()
        {
          auto pThis(make_shared<LoggerSettingsDefaults>());
          ISettings::installDefaults(pThis);
          return pThis;
        }

        //-----------------------------------------------------------------------
        virtual void notifySettingsApplyDefaults() override
        {
          ISettings::setUInt(ORTC_SERVICES_SETTING_TELNET_LOGGER_PHASE, 6);
        }
      };

      //-------------------------------------------------------------------------
      void installLoggerSettingsDefaults()
      {
        LoggerSettingsDefaults::singleton();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark ILoggerReferencesHolderDelegate
      #pragma mark

      interaction ILoggerReferencesHolderDelegate
      {
        virtual void notifyShutdown() = 0;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark LoggerSingtonHolder
      #pragma mark

      class LoggerReferencesHolder : public RecursiveLock,
                                     public ISingletonManagerDelegate
      {
      public:
        struct LogDelegateInfo
        {
          bool mActivatedLogging {false};
          ILogOutputDelegatePtr mLogOutputDelegate;
          ILoggerReferencesHolderDelegatePtr mHolderDelegate;

          LogDelegateInfo() {}

          LogDelegateInfo(const LogDelegateInfo &info) :
            mActivatedLogging(info.mActivatedLogging),
            mLogOutputDelegate(info.mLogOutputDelegate),
            mHolderDelegate(info.mHolderDelegate)
          {
          }

          LogDelegateInfo(
                          bool activatedLogging,
                          ILogOutputDelegatePtr logOutputDelegate,
                          ILoggerReferencesHolderDelegatePtr holderDelegate
                          ) :
            mActivatedLogging(activatedLogging),
            mLogOutputDelegate(logOutputDelegate),
            mHolderDelegate(holderDelegate)
          {
          }
        };

        typedef String LoggerName;
        typedef std::map<LoggerName, LogDelegateInfo> LoggerMap;

      protected:
        struct make_private {};

        //---------------------------------------------------------------------
        static LoggerReferencesHolderPtr create()
        {
          auto pThis(make_shared<LoggerReferencesHolder>(make_private{}));
          pThis->mThisWeak = pThis;
          pThis->init();
          return pThis;
        }

        //---------------------------------------------------------------------
        void init()
        {
        }

      public:
        //---------------------------------------------------------------------
        LoggerReferencesHolder(const make_private &)
        {
        }

        //---------------------------------------------------------------------
        ~LoggerReferencesHolder()
        {
          mThisWeak.reset();
          notifySingletonCleanup();
        }

        //---------------------------------------------------------------------
        static LoggerReferencesHolderPtr singleton()
        {
          AutoRecursiveLock lock(*IHelper::getGlobalLock());
          static SingletonLazySharedPtr<LoggerReferencesHolder> singleton(LoggerReferencesHolder::create());

          auto pThis(singleton.singleton());
          static SingletonManager::Register registerSingleton("ortc.services.internal.LoggerReferencesHolder", pThis);

          return pThis;
        }

        //---------------------------------------------------------------------
        void registerLogger(
                            const char *loggerNamespace,
                            ILogOutputDelegatePtr logDelegate,
                            ILoggerReferencesHolderDelegatePtr holderDelegate,
                            bool activateLoggerNow
                            )
        {
          String namespaceStr(loggerNamespace);

          LogDelegateInfo previousInfo;

          {
            AutoRecursiveLock lock(*this);
            auto found = mInstalledLoggers.find(namespaceStr);
            if (found != mInstalledLoggers.end()) {
              previousInfo = (*found).second;
              mInstalledLoggers.erase(found);
            }

            mInstalledLoggers[namespaceStr] = LogDelegateInfo(activateLoggerNow, logDelegate, holderDelegate);
          }
          if ((previousInfo.mLogOutputDelegate) &&
              (previousInfo.mActivatedLogging)) {
            Log::removeOutputListener(previousInfo.mLogOutputDelegate);
          }
          if (previousInfo.mHolderDelegate) {
            previousInfo.mHolderDelegate->notifyShutdown();
          }

          if (activateLoggerNow) {
            Log::addOutputListener(logDelegate);
          }
        }

        //---------------------------------------------------------------------
        void unregisterLogger(const char *loggerNamespace)
        {
          String namespaceStr(loggerNamespace);

          LogDelegateInfo previousInfo;

          {
            AutoRecursiveLock lock(*this);
            auto found = mInstalledLoggers.find(namespaceStr);
            if (found == mInstalledLoggers.end()) return;
            previousInfo = (*found).second;
            mInstalledLoggers.erase(found);
          }

          if ((previousInfo.mLogOutputDelegate) &&
              (previousInfo.mActivatedLogging)) {
            Log::removeOutputListener(previousInfo.mLogOutputDelegate);
          }
          if (previousInfo.mHolderDelegate) {
            previousInfo.mHolderDelegate->notifyShutdown();
          }
        }

        //---------------------------------------------------------------------
        bool findLogger(
                        const char *loggerNamespace,
                        LogDelegateInfo &outInfo
                        )
        {
          String namespaceStr(loggerNamespace);

          AutoRecursiveLock lock(*this);
          auto found = mInstalledLoggers.find(namespaceStr);
          if (found == mInstalledLoggers.end()) return false;

          outInfo = (*found).second;
          return true;
        }

        //---------------------------------------------------------------------
        bool activateLogger(const char *loggerNamespace)
        {
          String namespaceStr(loggerNamespace);

          LogDelegateInfo previousInfo;

          {
            AutoRecursiveLock lock(*this);
            auto found = mInstalledLoggers.find(namespaceStr);
            if (found == mInstalledLoggers.end()) return false;
            previousInfo = (*found).second;

            if (previousInfo.mActivatedLogging) return true;
            previousInfo.mActivatedLogging = true;

            mInstalledLoggers[namespaceStr] = previousInfo;
          }

          Log::addOutputListener(previousInfo.mLogOutputDelegate);

          return true;
        }

        //---------------------------------------------------------------------
        bool deactivateLogger(const char *loggerNamespace)
        {
          String namespaceStr(loggerNamespace);

          LogDelegateInfo previousInfo;

          {
            AutoRecursiveLock lock(*this);
            auto found = mInstalledLoggers.find(namespaceStr);
            if (found == mInstalledLoggers.end()) return false;
            previousInfo = (*found).second;

            if (!previousInfo.mActivatedLogging) return true;

            previousInfo.mActivatedLogging = false;
            mInstalledLoggers[namespaceStr] = previousInfo;
          }

          Log::removeOutputListener(previousInfo.mLogOutputDelegate);

          return true;
        }
        
      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark LoggerSingtonHolder
        #pragma mark

        virtual void notifySingletonCleanup() override
        {
          LoggerMap tempMap;
          {
            AutoRecursiveLock lock(*this);
            tempMap = mInstalledLoggers;
            mInstalledLoggers.clear();
          }

          for (auto iter = tempMap.begin(); iter != tempMap.end(); ++iter)
          {
            auto &info = (*iter).second;

            if ((info.mLogOutputDelegate) &&
                (info.mActivatedLogging)) {
              Log::removeOutputListener(info.mLogOutputDelegate);
            }
            if (info.mHolderDelegate) {
              info.mHolderDelegate->notifyShutdown();
            }
          }
        }

      protected:
        LoggerReferencesHolderWeakPtr mThisWeak;
        LoggerMap mInstalledLoggers;
      };


      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark (helpers)
      #pragma mark

      //-----------------------------------------------------------------------
      static String currentThreadIDAsString()
      {
#ifdef _WIN32
        return string(GetCurrentThreadId());
#else
#ifdef __APPLE__
        return string(((PTRNUMBER)pthread_mach_thread_np(pthread_self())));
#else
        return string(((PTRNUMBER)pthread_self()));
#endif //APPLE
#endif //_WIN32
      }

      //-----------------------------------------------------------------------
      static String getMessageString(
                                     const Log::Params &params,
                                     bool prettyPrint
                                     )
      {
        static const char *wires[] = {"wire in", "wire out", NULL};
        static const char *jsons[] = {"json in", "json out", "json", NULL};

        String objectString;

        ElementPtr objectEl = params.object();

        if (objectEl) {
          objectString = objectEl->getValue();

          ElementPtr idEl = objectEl->findFirstChildElement("id");
          if (idEl) {
            String objectID = idEl->getTextDecoded();
            if (objectID.hasData()) {
              objectString += " [" + objectID + "] ";
            } else {
              objectString += " [] ";
            }

            if ((objectEl->getFirstChild() == idEl) &&
                (objectEl->getLastChild() == idEl)) {
              objectEl.reset(); // this is now an empty object that we don't need anymore
            }

          } else {
            objectString += " [] ";
          }
        }
        if (objectEl) {
          if (!objectEl->hasChildren()) {
            objectEl.reset();
          }
        }

        String message = objectString + params.message();

        String alt;

        ElementPtr paramsEl = params.params();
        if (paramsEl) {
          for (int index = 0; wires[index]; ++index) {
            ElementPtr childEl = paramsEl->findFirstChildElement(wires[index]);
            if (!childEl) continue;

            SecureByteBlockPtr buffer = IHelper::convertFromBase64(childEl->getTextDecoded());
            if (IHelper::isEmpty(buffer)) continue;

            alt += "\n\n" + IHelper::getDebugString(*buffer) + "\n\n";
          }

          for (int index = 0; jsons[index]; ++index) {
            ElementPtr childEl = paramsEl->findFirstChildElement(jsons[index]);
            if (!childEl) continue;

            String json = childEl->getTextDecoded();
            if (json.isEmpty()) continue;

            if (prettyPrint) {
              DocumentPtr doc = Document::createFromParsedJSON(json);
              std::unique_ptr<char[]> output = doc->writeAsJSON(true);
              alt += "\n\n" + String((CSTR)output.get()) + "\n\n";
            } else {
              alt += "\n\n" + json + "\n\n";
            }
          }
        }

        if (alt.hasData()) {
          // strip out the wire stuff
          paramsEl = paramsEl->clone()->toElement();

          for (int index = 0; wires[index]; ++index) {
            ElementPtr childEl = paramsEl->findFirstChildElement(wires[index]);
            if (!childEl) continue;

            childEl->orphan();
          }

          for (int index = 0; jsons[index]; ++index) {
            ElementPtr childEl = paramsEl->findFirstChildElement(jsons[index]);
            if (!childEl) continue;

            childEl->orphan();
          }
        }

        // strip out empty params
        if (paramsEl) {
          if (!paramsEl->hasChildren()) {
            paramsEl.reset();
          }
        }

        if (paramsEl) {
          message += " " + IHelper::toString(paramsEl);
        }
        if (objectEl) {
          message += " " + IHelper::toString(objectEl);
        }
        message += alt;

        return message;
      }

      //-----------------------------------------------------------------------
      static std::string getNowTime()
      {
        Time now = zsLib::now();

        time_t tt = std::chrono::system_clock::to_time_t(now);
        Time secOnly = std::chrono::system_clock::from_time_t(tt);

        Microseconds remainder = std::chrono::duration_cast<Microseconds>(now - secOnly);

        std::tm ttm {};
#ifdef HAVE_GMTIME_S
        auto error = gmtime_s(&ttm, &tt);
        ZS_THROW_BAD_STATE_IF(0 != error)
#else
        gmtime_r(&tt, &ttm);
#endif //_WIN32

        //HH:MM:SS.123456
        char buffer[100] {};

#ifdef HAVE_SPRINTF_S
        sprintf_s(
#else
        snprintf(
#endif //HAVE_SPRINTF_S
          &(buffer[0]),
          sizeof(buffer),
          "%02u:%02u:%02u:%06u", ((UINT)ttm.tm_hour), ((UINT)ttm.tm_min), ((UINT)ttm.tm_sec), static_cast<UINT>(remainder.count())
        );

        return buffer;
      }

      //-----------------------------------------------------------------------
      static String toColorString(
                                  const Subsystem &inSubsystem,
                                  Log::Severity inSeverity,
                                  Log::Level inLevel,
                                  const Log::Params &params,
                                  CSTR inFunction,
                                  CSTR inFilePath,
                                  ULONG inLineNumber,
                                  bool prettyPrint,
                                  bool eol = true
                                  )
      {
        const char *posBackslash = strrchr(inFilePath, '\\');
        const char *posSlash = strrchr(inFilePath, '/');

        const char *fileName = inFilePath;

        if (!posBackslash)
          posBackslash = posSlash;

        if (!posSlash)
          posSlash = posBackslash;

        if (posSlash) {
          if (posBackslash > posSlash)
            posSlash = posBackslash;
          fileName = posSlash + 1;
        }

        std::string current = getNowTime();

        const char *colorSeverity = ORTC_SERVICES_SEQUENCE_COLOUR_SEVERITY_INFO;
        const char *severity = "NONE";
        switch (inSeverity) {
          case Log::Informational:   severity = "i:"; colorSeverity = ORTC_SERVICES_SEQUENCE_COLOUR_SEVERITY_INFO; break;
          case Log::Warning:         severity = "W:"; colorSeverity = ORTC_SERVICES_SEQUENCE_COLOUR_SEVERITY_WARNING; break;
          case Log::Error:           severity = "E:"; colorSeverity = ORTC_SERVICES_SEQUENCE_COLOUR_SEVERITY_ERROR; break;
          case Log::Fatal:           severity = "F:"; colorSeverity = ORTC_SERVICES_SEQUENCE_COLOUR_SEVERITY_FATAL; break;
        }

        const char *colorLevel = ORTC_SERVICES_SEQUENCE_COLOUR_MESSAGE_TRACE;
        switch (inLevel) {
          case Log::Basic:           colorLevel = ORTC_SERVICES_SEQUENCE_COLOUR_MESSAGE_BASIC; break;
          case Log::Detail:          colorLevel = ORTC_SERVICES_SEQUENCE_COLOUR_MESSAGE_DETAIL; break;
          case Log::Debug:           colorLevel = ORTC_SERVICES_SEQUENCE_COLOUR_MESSAGE_DEBUG; break;
          case Log::Trace:           colorLevel = ORTC_SERVICES_SEQUENCE_COLOUR_MESSAGE_TRACE; break;
          case Log::Insane:          colorLevel = ORTC_SERVICES_SEQUENCE_COLOUR_MESSAGE_INSANE; break;
          case Log::None:            break;
        }

//        const Log::Params &params;

        String result = String(ORTC_SERVICES_SEQUENCE_COLOUR_TIME) + current
                      + ORTC_SERVICES_SEQUENCE_COLOUR_RESET + " "
                      + colorSeverity + severity
                      + ORTC_SERVICES_SEQUENCE_COLOUR_RESET + " "
                      + ORTC_SERVICES_SEQUENCE_COLOUR_THREAD + "<" + currentThreadIDAsString() + ">"
                      + ORTC_SERVICES_SEQUENCE_COLOUR_RESET + " "
                      + colorLevel + getMessageString(params, prettyPrint)
                      + ORTC_SERVICES_SEQUENCE_COLOUR_RESET + " "
                      + ORTC_SERVICES_SEQUENCE_COLOUR_FILENAME + "@" + fileName
                      + ORTC_SERVICES_SEQUENCE_COLOUR_LINENUMBER + "(" + string(inLineNumber) + ")"
                      + ORTC_SERVICES_SEQUENCE_COLOUR_RESET + " "
                      + ORTC_SERVICES_SEQUENCE_COLOUR_FUNCTION + "[" + inFunction + "]"
                      + ORTC_SERVICES_SEQUENCE_COLOUR_RESET + (eol ? "\n" : "");

        return result;
      }

      //-----------------------------------------------------------------------
      static String toBWString(
                               const Subsystem &inSubsystem,
                               Log::Severity inSeverity,
                               Log::Level inLevel,
                               const Log::Params &params,
                               CSTR inFunction,
                               CSTR inFilePath,
                               ULONG inLineNumber,
                               bool prettyPrint,
                               bool eol = true
                               )
      {
        const char *posBackslash = strrchr(inFilePath, '\\');
        const char *posSlash = strrchr(inFilePath, '/');

        const char *fileName = inFilePath;

        if (!posBackslash)
          posBackslash = posSlash;

        if (!posSlash)
          posSlash = posBackslash;

        if (posSlash) {
          if (posBackslash > posSlash)
            posSlash = posBackslash;
          fileName = posSlash + 1;
        }

        std::string current = getNowTime();

        const char *severity = "NONE";
        switch (inSeverity) {
          case Log::Informational:   severity = "i:"; break;
          case Log::Warning:         severity = "W:"; break;
          case Log::Error:           severity = "E:"; break;
          case Log::Fatal:           severity = "F:"; break;
        }

        String result = current + " " + severity + " <"  + currentThreadIDAsString() + "> " + getMessageString(params, prettyPrint) + " " + "@" + fileName + "(" + string(inLineNumber) + ")" + " " + "[" + inFunction + "]" + (eol ? "\n" : "");
        return result;
      }

      //-----------------------------------------------------------------------
      static String toWindowsString(
                                    const Subsystem &inSubsystem,
                                    Log::Severity inSeverity,
                                    Log::Level inLevel,
                                    const Log::Params &params,
                                    CSTR inFunction,
                                    CSTR inFilePath,
                                    ULONG inLineNumber,
                                    bool prettyPrint,
                                    bool eol = true
                                    )
      {
        std::string current = getNowTime();

        const char *severity = "NONE";
        switch (inSeverity) {
          case Log::Informational:   severity = "i:"; break;
          case Log::Warning:         severity = "W:"; break;
          case Log::Error:           severity = "E:"; break;
          case Log::Fatal:           severity = "F:"; break;
        }

        String result = String(inFilePath) + "(" + string(inLineNumber) + "): " + severity + " T" + currentThreadIDAsString() + ": " + current + " " + getMessageString(params, prettyPrint) + (eol ? "\n" : "");
        return result;
      }

      //-----------------------------------------------------------------------
      static void appendToDoc(
                              DocumentPtr &doc,
                              const Log::Param param
                              )
      {
        if (!param.param()) return;
        doc->adoptAsLastChild(param.param());
      }

      //-----------------------------------------------------------------------
      static void appendToDoc(
                              DocumentPtr &doc,
                              const ElementPtr &childEl
                              )
      {
        if (!childEl) return;

        ZS_THROW_INVALID_ASSUMPTION_IF(childEl->getParent())

        doc->adoptAsLastChild(childEl);
      }

      //-----------------------------------------------------------------------
      static String toRawJSON(
                              const Subsystem &inSubsystem,
                              Log::Severity inSeverity,
                              Log::Level inLevel,
                              const Log::Params &params,
                              CSTR inFunction,
                              CSTR inFilePath,
                              ULONG inLineNumber,
                              bool eol = true
                              )
      {
        const char *posBackslash = strrchr(inFilePath, '\\');
        const char *posSlash = strrchr(inFilePath, '/');

        const char *fileName = inFilePath;

        if (!posBackslash)
          posBackslash = posSlash;

        if (!posSlash)
          posSlash = posBackslash;

        if (posSlash) {
          if (posBackslash > posSlash)
            posSlash = posBackslash;
          fileName = posSlash + 1;
        }

        DocumentPtr message = Document::create();
        ElementPtr objecEl = Element::create("object");
        ElementPtr timeEl = Element::create("time");
        TextPtr timeText = Text::create();

        std::string current = getNowTime();

        timeText->setValue(current);
        timeEl->adoptAsLastChild(timeText);

        appendToDoc(message, Log::Param("submodule", inSubsystem.getName()));
        appendToDoc(message, Log::Param("severity", Log::toString(inSeverity)));
        appendToDoc(message, Log::Param("level", Log::toString(inLevel)));
        appendToDoc(message, Log::Param("thread", currentThreadIDAsString()));
        appendToDoc(message, Log::Param("function", inFunction));
        appendToDoc(message, Log::Param("file", fileName));
        appendToDoc(message, Log::Param("line", inLineNumber));
        appendToDoc(message, Log::Param("message", params.message()));
        message->adoptAsLastChild(timeEl);

        IHelper::debugAppend(objecEl, params.object());
        if (objecEl->hasChildren()) {
          appendToDoc(message, objecEl);
        }
        appendToDoc(message, params.params());

        GeneratorPtr generator = Generator::createJSONGenerator();
        std::unique_ptr<char[]> output = generator->write(message);

        String result = (CSTR)output.get();
        if (eol) {
          result += "\n";
        }

        if (params.object()) {
          params.object()->orphan();
        }
        if (params.params()) {
          params.params()->orphan();
        }

        return result;
      }

#if 0

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark LoggerReferenceHolder<T>
      #pragma mark

      template <typename T>
      struct LoggerReferenceHolder
      {
        ZS_DECLARE_TYPEDEF_PTR(T, Logger)
        ZS_DECLARE_TYPEDEF_PTR(LoggerReferenceHolder<T>, Holder)

        LoggerPtr mLogger;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark LoggerSingletonAndLockHolder<T>
      #pragma mark

      template <typename T>
      class LoggerSingletonAndLockHolder
      {
      public:
        ZS_DECLARE_TYPEDEF_PTR(LoggerReferenceHolder<T>, ReferenceHolder)
        ZS_DECLARE_TYPEDEF_PTR(LoggerSingletonAndLockHolder<T>, Self)
        ZS_DECLARE_TYPEDEF_PTR(SingletonLazySharedPtr< Self >, SingletonLazySelf)

        LoggerSingletonAndLockHolder() :
          mLock(make_shared<RecursiveLock>()),
          mSingleton(make_shared<ReferenceHolder>())
        {
        }

        RecursiveLockPtr lock() {return mLock;}
        ReferenceHolderPtr reference() {return mSingleton;}

      protected:
        RecursiveLockPtr mLock;
        ReferenceHolderPtr mSingleton;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark LoggerSingletonLazySharedPtr<T>
      #pragma mark

      template <typename T>
      class LoggerSingletonLazySharedPtr : SingletonLazySharedPtr< LoggerSingletonAndLockHolder<T> >
      {
      public:
        ZS_DECLARE_TYPEDEF_PTR(LoggerReferenceHolder<T>, ReferenceHolder)
        ZS_DECLARE_TYPEDEF_PTR(LoggerSingletonAndLockHolder<T>, Holder)
        ZS_DECLARE_TYPEDEF_PTR(LoggerSingletonLazySharedPtr<T>, SingletonLazySelf)

      public:
        LoggerSingletonLazySharedPtr() :
          SingletonLazySharedPtr< LoggerSingletonAndLockHolder<T> >(make_shared<Holder>())
        {
        }

        static RecursiveLockPtr lock(SingletonLazySelf &singleton)
        {
          HolderPtr result = singleton.singleton();
          if (!result) {
            return make_shared<RecursiveLock>();
          }
          return result->lock();
        }

        static ReferenceHolderPtr logger(SingletonLazySelf &singleton)
        {
          HolderPtr result = singleton.singleton();
          if (!result) {
            return make_shared<ReferenceHolder>();
          }
          return result->reference();
        }
      };

#endif //0

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark StdOutLogger
      #pragma mark

      ZS_DECLARE_CLASS_PTR(StdOutLogger)

      class StdOutLogger : public ILogOutputDelegate,
                           public ILoggerReferencesHolderDelegate
      {
      protected:
        struct make_private {};
        
      protected:
        //---------------------------------------------------------------------
        void init()
        {
        }

      public:
        //---------------------------------------------------------------------
        StdOutLogger(
                     const make_private &,
                     bool colorizeOutput,
                     bool prettyPrint
                     ) :
          mColorizeOutput(colorizeOutput),
          mPrettyPrint(prettyPrint)
          {}

        //---------------------------------------------------------------------
        static StdOutLoggerPtr create(
                                      bool colorizeOutput,
                                      bool prettyPrint
                                      )
        {
          StdOutLoggerPtr pThis(make_shared<StdOutLogger>(make_private{}, colorizeOutput, prettyPrint));
          pThis->mThisWeak = pThis;
          pThis->init();
          return pThis;
        }

        //---------------------------------------------------------------------
        static StdOutLoggerPtr singleton(
                                         bool colorizeOutput,
                                         bool prettyPrint
                                         )
        {
          auto singleton = LoggerReferencesHolder::singleton();
          if (!singleton) return StdOutLoggerPtr();

          LoggerReferencesHolder::LogDelegateInfo existingInfo;

          singleton->findLogger(ORTC_SERVICES_LOGGER_STDOUT_NAMESPACE, existingInfo);

          if (existingInfo.mHolderDelegate) {
            auto existingLogger = ZS_DYNAMIC_PTR_CAST(StdOutLogger, existingInfo.mHolderDelegate);

            bool wasColorizedOutput {};
            bool wasPrettyPrint {};
            existingLogger->getInfo(wasColorizedOutput, wasPrettyPrint);
            if ((colorizeOutput == wasColorizedOutput) &&
                (wasPrettyPrint == prettyPrint)) return existingLogger;
          }

          auto newLogger = create(colorizeOutput, prettyPrint);

          singleton->registerLogger(ORTC_SERVICES_LOGGER_STDOUT_NAMESPACE, newLogger, newLogger, true);

          return newLogger;
        }

        //---------------------------------------------------------------------
        static void stop()
        {
          auto singleton = LoggerReferencesHolder::singleton();
          if (!singleton) return;

          singleton->unregisterLogger(ORTC_SERVICES_LOGGER_STDOUT_NAMESPACE);
        }

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark StdOutLogger => ILogOutputDelegate
        #pragma mark

        //---------------------------------------------------------------------
        virtual void notifyNewSubsystem(Subsystem &) override
        {
        }

        //---------------------------------------------------------------------
        // notification of a log event
        virtual void notifyLog(
                               const Subsystem &inSubsystem,
                               Log::Severity inSeverity,
                               Log::Level inLevel,
                               CSTR inFunction,
                               CSTR inFilePath,
                               ULONG inLineNumber,
                               const Log::Params &params
                               ) override
        {
          if (mColorizeOutput) {
            std::cout << toColorString(inSubsystem, inSeverity, inLevel, params, inFunction, inFilePath, inLineNumber, mPrettyPrint);
            std::cout.flush();
          } else {
            std::cout << toBWString(inSubsystem, inSeverity, inLevel, params, inFunction, inFilePath, inLineNumber, mPrettyPrint);
            std::cout.flush();
          }
        }

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark StdOutLogger => ILogOutputDelegate
        #pragma mark

        //---------------------------------------------------------------------
        virtual void notifyShutdown() override
        {
        }

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark StdOutLogger => ILogOutputDelegate
        #pragma mark

        //---------------------------------------------------------------------
        void getInfo(
                     bool &outColorize,
                     bool &outPrettyPrint
                     )
        {
          outColorize = mColorizeOutput;
          outPrettyPrint = mPrettyPrint;
        }

      private:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark StdOutLogger => (data)
        #pragma mark

        StdOutLoggerWeakPtr mThisWeak;
        bool mColorizeOutput {};
        bool mPrettyPrint {};
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark FileLogger
      #pragma mark

      ZS_DECLARE_CLASS_PTR(FileLogger)

      class FileLogger : public ILogOutputDelegate,
                         public ILoggerReferencesHolderDelegate
      {
      protected:
        struct make_private {};
      protected:
        
        //---------------------------------------------------------------------
        void init()
        {
          mFile.open(mFileName, std::ios::out | std::ios::binary);
        }

        //---------------------------------------------------------------------
        static FileLoggerPtr create(
                                    const char *fileName,
                                    bool colorizeOutput,
                                    bool prettyPrint
                                    )
        {
          FileLoggerPtr pThis(make_shared<FileLogger>(make_private{}, fileName, colorizeOutput, prettyPrint));
          pThis->mThisWeak = pThis;
          pThis->init();
          return pThis;
        }
        
      public:
        //---------------------------------------------------------------------
        FileLogger(
                   const make_private &,
                   const char *fileName,
                   bool colorizeOutput,
                   bool prettyPrint
                   ) :
          mFileName(fileName),
          mColorizeOutput(colorizeOutput),
          mPrettyPrint(prettyPrint)
          {}

        //---------------------------------------------------------------------
        static FileLoggerPtr singleton(
                                       const char *fileName,
                                       bool colorizeOutput,
                                       bool prettyPrint
                                       )
        {
          auto singleton = LoggerReferencesHolder::singleton();
          if (!singleton) return FileLoggerPtr();

          LoggerReferencesHolder::LogDelegateInfo existingInfo;

          singleton->findLogger(ORTC_SERVICES_LOGGER_FILE_NAMESPACE, existingInfo);

          if (existingInfo.mHolderDelegate) {
            auto existingLogger = ZS_DYNAMIC_PTR_CAST(FileLogger, existingInfo.mHolderDelegate);

            String oldFileName;
            bool wasColorizedOutput {};
            bool wasPrettyPrint {};
            existingLogger->getInfo(oldFileName, wasColorizedOutput, wasPrettyPrint);
            if ((oldFileName == fileName) &&
                (colorizeOutput == wasColorizedOutput) &&
                (wasPrettyPrint == prettyPrint)) return existingLogger;
          }

          auto newLogger = create(fileName, colorizeOutput, prettyPrint);

          singleton->registerLogger(ORTC_SERVICES_LOGGER_FILE_NAMESPACE, newLogger, newLogger, true);

          return newLogger;
        }

        //---------------------------------------------------------------------
        static void stop()
        {
          auto singleton = LoggerReferencesHolder::singleton();
          if (!singleton) return;

          singleton->unregisterLogger(ORTC_SERVICES_LOGGER_FILE_NAMESPACE);
        }

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark FileLogger => ILogDelegate
        #pragma mark

        //---------------------------------------------------------------------
        virtual void notifyNewSubsystem(Subsystem &) override
        {
        }

        //---------------------------------------------------------------------
        // notification of a log event
        virtual void notifyLog(
                               const Subsystem &inSubsystem,
                               Log::Severity inSeverity,
                               Log::Level inLevel,
                               CSTR inFunction,
                               CSTR inFilePath,
                               ULONG inLineNumber,
                               const Log::Params &params
                               ) override
        {
          if (mFile.is_open()) {
            String output;
            if (mColorizeOutput) {
              output = toColorString(inSubsystem, inSeverity, inLevel, params, inFunction, inFilePath, inLineNumber, mPrettyPrint);
            } else {
              output = toBWString(inSubsystem, inSeverity, inLevel, params, inFunction, inFilePath, inLineNumber, mPrettyPrint);
            }
            mFile << output;
            mFile.flush();
          }
        }

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark FileLogger => ILogOutputDelegate
        #pragma mark

        //---------------------------------------------------------------------
        virtual void notifyShutdown() override
        {
        }

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark FileLogger => (internal)
        #pragma mark

        //---------------------------------------------------------------------
        void getInfo(
                     String &outFileName,
                     bool &outColorize,
                     bool &outPrettyPrint
                     )
        {
          outFileName = mFileName;
          outColorize = mColorizeOutput;
          outPrettyPrint = mPrettyPrint;
        }

      private:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark FileLogger => (data)
        #pragma mark

        FileLoggerWeakPtr mThisWeak;
        String mFileName;
        bool mColorizeOutput {};
        bool mPrettyPrint {};

        std::ofstream mFile;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DebuggerLogger
      #pragma mark

      ZS_DECLARE_CLASS_PTR(DebuggerLogger)

      class DebuggerLogger : public ILogOutputDelegate,
                             public ILoggerReferencesHolderDelegate
      {
      protected:
        struct make_private {};
        
      protected:
        //---------------------------------------------------------------------
        void init()
        {
        }

        //---------------------------------------------------------------------
        static DebuggerLoggerPtr create(
                                        bool colorizeOutput,
                                        bool prettyPrint
                                        )
        {
          DebuggerLoggerPtr pThis(make_shared<DebuggerLogger>(make_private {}, colorizeOutput, prettyPrint));
          pThis->mThisWeak = pThis;
          pThis->init();
          return pThis;
        }
        
      public:
        //---------------------------------------------------------------------
        DebuggerLogger(
                       const make_private &,
                       bool colorizeOutput,
                       bool prettyPrint
                       ) :
          mColorizeOutput(colorizeOutput),
          mPrettyPrint(prettyPrint)
          {}

        //---------------------------------------------------------------------
        static DebuggerLoggerPtr singleton(
                                           bool colorizeOutput,
                                           bool prettyPrint
                                           )
        {
#if (defined(_WIN32)) || ((defined(__QNX__) && (!defined(NDEBUG))))
          auto singleton = LoggerReferencesHolder::singleton();
          if (!singleton) return DebuggerLoggerPtr();
          
          LoggerReferencesHolder::LogDelegateInfo existingInfo;

          singleton->findLogger(ORTC_SERVICES_LOGGER_DEBUG_NAMESPACE, existingInfo);
          
          if (existingInfo.mHolderDelegate) {
            auto existingLogger = ZS_DYNAMIC_PTR_CAST(DebuggerLogger, existingInfo.mHolderDelegate);
            
            bool wasColorizedOutput {};
            bool wasPrettyPrint {};
            existingLogger->getInfo(wasColorizedOutput, wasPrettyPrint);
            if ((colorizeOutput == wasColorizedOutput) &&
                (wasPrettyPrint == prettyPrint)) return existingLogger;
          }

          auto newLogger = create(colorizeOutput, prettyPrint);

          singleton->registerLogger(ORTC_SERVICES_LOGGER_DEBUG_NAMESPACE, newLogger, newLogger, true);

          return newLogger;
#else
          return DebuggerLoggerPtr();
#endif //_WIN32
        }
        
        //---------------------------------------------------------------------
        static void stop()
        {
          auto singleton = LoggerReferencesHolder::singleton();
          if (!singleton) return;
          
          singleton->unregisterLogger(ORTC_SERVICES_LOGGER_DEBUG_NAMESPACE);
        }

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DebuggerLogger => ILogDelegate
        #pragma mark

        //---------------------------------------------------------------------
        virtual void notifyNewSubsystem(Subsystem &) override
        {
        }

        //---------------------------------------------------------------------
        // notification of a log event
        virtual void notifyLog(
                               const Subsystem &inSubsystem,
                               Log::Severity inSeverity,
                               Log::Level inLevel,
                               CSTR inFunction,
                               CSTR inFilePath,
                               ULONG inLineNumber,
                               const Log::Params &params
                               ) override
        {
#ifdef __QNX__
#ifndef NDEBUG
          String output;
          if (mColorizeOutput)
            output = toColorString(inSubsystem, inSeverity, inLevel, params, inFunction, inFilePath, inLineNumber, mPrettyPrint, false);
          else
            output = toBWString(inSubsystem, inSeverity, inLevel, params, inFunction, inFilePath, inLineNumber, mPrettyPrint, false);
          qDebug() << output.c_str();
#endif //ndef NDEBUG
#endif //__QNX__
          String output = toWindowsString(inSubsystem, inSeverity, inLevel, params, inFunction, inFilePath, inLineNumber, mPrettyPrint);
#ifdef _WIN32
          OutputDebugStringW(output.wstring().c_str());
#endif //_WIN32
          //ServicesDebugLogger(inSubsystem.getName(), Log::toString(inSeverity), Log::toString(inLevel), inFunction, inFilePath, inLineNumber, output);
          ZS_EVENTING_7(
                        x, i, Trace, ServicesDebugLogger, os, DebugLogger, Info,
                        string, subsystem, inSubsystem.getName(),
                        string, severity, Log::toString(inSeverity),
                        string, level, Log::toString(inLevel),
                        string, function, inFunction,
                        string, filePath, inFilePath,
                        ulong, lineNumber, inLineNumber,
                        string, output, output
                        );
        }

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DebuggerLogger => ILogOutputDelegate
        #pragma mark

        //---------------------------------------------------------------------
        virtual void notifyShutdown() override
        {
        }

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DebuggerLogger => (internal)
        #pragma mark

        //---------------------------------------------------------------------
        void getInfo(
                     bool &outColorize,
                     bool &outPrettyPrint
                     )
        {
          outColorize = mColorizeOutput;
          outPrettyPrint = mPrettyPrint;
        }
        
      private:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DebuggerLogger => (data)
        #pragma mark

        DebuggerLoggerWeakPtr mThisWeak;
        bool mColorizeOutput {};
        bool mPrettyPrint {};
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark TelnetLogger
      #pragma mark

      ZS_DECLARE_CLASS_PTR(TelnetLogger)

      class TelnetLogger : public RecursiveLock,
                           public ILogOutputDelegate,
                           public ILoggerReferencesHolderDelegate,
                           public MessageQueueAssociator,
                           public ISocketDelegate,
                           public IDNSDelegate,
                           public ITimerDelegate,
                           public IWakeDelegate,
                           public IBackgroundingDelegate
      {
      protected:
        struct make_private {};
        
      protected:
        //---------------------------------------------------------------------
        void init(
                  USHORT listenPort,
                  Seconds maxSecondsWaitForSocketToBeAvailable
                  )
        {
          mListenPort = listenPort;
          mMaxWaitTimeForSocketToBeAvailable = maxSecondsWaitForSocketToBeAvailable;

          mBackgroundingSubscription = IBackgrounding::subscribe(mThisWeak.lock(), ISettings::getUInt(ORTC_SERVICES_SETTING_TELNET_LOGGER_PHASE));

          // do this from outside the stack to prevent this from happening during any kind of lock
          IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
        }

        //---------------------------------------------------------------------
        void init(
                  const char *serverHostWithPort,
                  const char *sendStringUponConnection
                  )
        {
          mOriginalStringToSendUponConnection = String(sendStringUponConnection);
          mOriginalServer = mServerLookupName = String(serverHostWithPort);

          String::size_type pos = mServerLookupName.find(":");
          if (pos != mServerLookupName.npos) {
            String portStr = mServerLookupName.substr(pos+1);
            mServerLookupName = mServerLookupName.substr(0, pos);

            try {
              mListenPort = Numeric<WORD>(portStr);
            } catch(const Numeric<WORD>::ValueOutOfRange &) {
            }
          }

          if (0 == mListenPort) {
            mListenPort = ORTC_SERVICES_DEFAULT_OUTGOING_TELNET_PORT;
          }

          mBackgroundingSubscription = IBackgrounding::subscribe(mThisWeak.lock(), ISettings::getUInt(ORTC_SERVICES_SETTING_TELNET_LOGGER_PHASE));

          // do this from outside the stack to prevent this from happening during any kind of lock
          IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
        }

        //---------------------------------------------------------------------
        static TelnetLoggerPtr create(
                                      USHORT listenPort,
                                      Seconds maxSecondsWaitForSocketToBeAvailable,
                                      bool colorizeOutput,
                                      bool prettyPrint
                                      )
        {
          TelnetLoggerPtr pThis(make_shared<TelnetLogger>(make_private{}, IHelper::getLoggerQueue(), ORTC_SERVICES_LOGGER_TELNET_INCOMING_NAMESPACE, colorizeOutput, prettyPrint));
          pThis->mThisWeak = pThis;
          pThis->init(listenPort, maxSecondsWaitForSocketToBeAvailable);
          return pThis;
        }

        //---------------------------------------------------------------------
        static TelnetLoggerPtr create(
                                      const char *serverHostWithPort,
                                      bool colorizeOutput,
                                      bool prettyPrint,
                                      const char *sendStringUponConnection
                                      )
        {
          TelnetLoggerPtr pThis(make_shared<TelnetLogger>(make_private{}, IHelper::getLoggerQueue(), ORTC_SERVICES_LOGGER_TELNET_OUTGOING_NAMESPACE, colorizeOutput, prettyPrint));
          pThis->mThisWeak = pThis;
          pThis->init(serverHostWithPort, sendStringUponConnection);
          return pThis;
        }

      public:
        //---------------------------------------------------------------------
        TelnetLogger(
                     const make_private &,
                     IMessageQueuePtr queue,
                     const char *loggerNamespace,
                     bool colorizeOutput,
                     bool prettyPrint
                     ) :
          MessageQueueAssociator(queue),
          mLoggerNamespace(loggerNamespace),
          mColorizeOutput(colorizeOutput),
          mPrettyPrint(prettyPrint),
          mConnected(false),
          mListenPort(0),
          mMaxWaitTimeForSocketToBeAvailable(Seconds(60)),
          mBacklogDataUntil(zsLib::now() + Seconds(ORTC_SERVICES_MAX_TELNET_LOGGER_PENDING_CONNECTIONBACKLOG_TIME_SECONDS))
        {
        }

        //---------------------------------------------------------------------
        ~TelnetLogger()
        {
          mThisWeak.reset();
          close();
        }

        //---------------------------------------------------------------------
        static TelnetLoggerPtr singletonIncoming(
                                                 WORD listenPort,
                                                 Seconds maxSecondsWaitForSocketToBeAvailable,
                                                 bool colorizeOutput,
                                                 bool prettyPrint
                                                 )
        {
#if (defined(_WIN32)) || ((defined(__QNX__) && (!defined(NDEBUG))))
          auto singleton = LoggerReferencesHolder::singleton();
          if (!singleton) return TelnetLoggerPtr();
          
          LoggerReferencesHolder::LogDelegateInfo existingInfo;

          singleton->findLogger(ORTC_SERVICES_LOGGER_TELNET_INCOMING_NAMESPACE, existingInfo);
          
          if (existingInfo.mHolderDelegate) {
            auto existingLogger = ZS_DYNAMIC_PTR_CAST(TelnetLogger, existingInfo.mHolderDelegate);

            WORD oldListenPort {};
            Seconds oldMaxWaitTime {};  // change in this value is not important
            bool wasColorizedOutput {};
            bool wasPrettyPrint {};
            existingLogger->getIncomingInfo(oldListenPort, oldMaxWaitTime, wasColorizedOutput, wasPrettyPrint);
            if ((oldListenPort == listenPort) &&
                (colorizeOutput == wasColorizedOutput) &&
                (wasPrettyPrint == prettyPrint)) return existingLogger;
          }
          
          auto newLogger = create(listenPort, maxSecondsWaitForSocketToBeAvailable, colorizeOutput, prettyPrint);
          
          singleton->registerLogger(ORTC_SERVICES_LOGGER_TELNET_INCOMING_NAMESPACE, newLogger, newLogger, false);
          
          return newLogger;
#else
          return TelnetLoggerPtr();
#endif //_WIN32
        }
        
        //---------------------------------------------------------------------
        static TelnetLoggerPtr singletonOutgoing(
                                                 const char *serverHostWithPort,
                                                 bool colorizeOutput,
                                                 bool prettyPrint,
                                                 const char *sendStringUponConnection
                                                 )
        {
#if (defined(_WIN32)) || ((defined(__QNX__) && (!defined(NDEBUG))))
          auto singleton = LoggerReferencesHolder::singleton();
          if (!singleton) return TelnetLoggerPtr();
          
          LoggerReferencesHolder::LogDelegateInfo existingInfo;
          
          singleton->findLogger(ORTC_SERVICES_LOGGER_TELNET_OUTGOING_NAMESPACE, existingInfo);
          
          if (existingInfo.mHolderDelegate) {
            auto existingLogger = ZS_DYNAMIC_PTR_CAST(TelnetLogger, existingInfo.mHolderDelegate);
            
            String oldServerHostWithPort;
            bool wasColorizedOutput {};
            bool wasPrettyPrint {};
            String oldStringUponConnection;
            existingLogger->getOutgoingInfo(oldServerHostWithPort, wasColorizedOutput, wasPrettyPrint, oldStringUponConnection);
            if ((oldServerHostWithPort == String(serverHostWithPort)) &&
                (colorizeOutput == wasColorizedOutput) &&
                (wasPrettyPrint == prettyPrint) &&
                (oldStringUponConnection == String(sendStringUponConnection))) return existingLogger;
          }

          auto newLogger = create(serverHostWithPort, colorizeOutput, prettyPrint, sendStringUponConnection);
          
          singleton->registerLogger(ORTC_SERVICES_LOGGER_TELNET_OUTGOING_NAMESPACE, newLogger, newLogger, false);
          
          return newLogger;
#else
          return TelnetLoggerPtr();
#endif //_WIN32
        }

        //---------------------------------------------------------------------
        static TelnetLoggerPtr singletonIncoming()
        {
          auto singleton = LoggerReferencesHolder::singleton();
          if (!singleton) return TelnetLoggerPtr();
          
          LoggerReferencesHolder::LogDelegateInfo existingInfo;
          
          singleton->findLogger(ORTC_SERVICES_LOGGER_TELNET_INCOMING_NAMESPACE, existingInfo);
          return ZS_DYNAMIC_PTR_CAST(TelnetLogger, existingInfo.mHolderDelegate);
        }

        //---------------------------------------------------------------------
        static TelnetLoggerPtr singletonOutgoing()
        {
          auto singleton = LoggerReferencesHolder::singleton();
          if (!singleton) return TelnetLoggerPtr();
          
          LoggerReferencesHolder::LogDelegateInfo existingInfo;
          
          singleton->findLogger(ORTC_SERVICES_LOGGER_TELNET_OUTGOING_NAMESPACE, existingInfo);
          return ZS_DYNAMIC_PTR_CAST(TelnetLogger, existingInfo.mHolderDelegate);
        }
        
        //---------------------------------------------------------------------
        static void stopIncoming()
        {
          auto singleton = LoggerReferencesHolder::singleton();
          if (!singleton) return;
          
          singleton->unregisterLogger(ORTC_SERVICES_LOGGER_TELNET_INCOMING_NAMESPACE);
        }

        //---------------------------------------------------------------------
        static void stopOutgoing()
        {
          auto singleton = LoggerReferencesHolder::singleton();
          if (!singleton) return;
          
          singleton->unregisterLogger(ORTC_SERVICES_LOGGER_TELNET_OUTGOING_NAMESPACE);
        }

        //---------------------------------------------------------------------
        bool isListening()
        {
          AutoRecursiveLock lock(*this);
          return (bool)mListenSocket;
        }

        //---------------------------------------------------------------------
        bool isConnected()
        {
          AutoRecursiveLock lock(*this);
          if (!mTelnetSocket) return false;
          if (isOutgoing()) return mConnected;
          return true;
        }

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark TelnetLogger => ILogDelegate
        #pragma mark

        //---------------------------------------------------------------------
        virtual void notifyNewSubsystem(Subsystem &) override
        {
        }

        //---------------------------------------------------------------------
        virtual void notifyLog(
                               const Subsystem &inSubsystem,
                               Log::Severity inSeverity,
                               Log::Level inLevel,
                               CSTR inFunction,
                               CSTR inFilePath,
                               ULONG inLineNumber,
                               const Log::Params &params
                               ) override
        {
          if (0 == strcmp(inSubsystem.getName(), "zsLib_socket")) {
            // ignore events from the socket monitor to prevent recursion
            return;
          }

          // scope: quick exit is not logging
          {
            AutoRecursiveLock lock(*this);

            if (!isConnected()) {
              Time tick = zsLib::now();

              if (tick > mBacklogDataUntil) {
                // clear out any pending data since we can't backlog any longer
                mBufferedList.clear();
                return;
              }
            }
          }

          String output;
          if (mColorizeOutput) {
            output = toColorString(inSubsystem, inSeverity, inLevel, params, inFunction, inFilePath, inLineNumber, mPrettyPrint);
          } else {
            output = toRawJSON(inSubsystem, inSeverity, inLevel, params, inFunction, inFilePath, inLineNumber);
          }

          AutoRecursiveLock lock(*this);

          bool okayToSend = (isConnected()) && (mBufferedList.size() < 1);
          size_t sent = 0;

          if (okayToSend) {
            int errorCode = 0;
            bool wouldBlock = false;
            sent = mTelnetSocket->send((const BYTE *)(output.c_str()), output.length(), &wouldBlock, 0, &errorCode);
            if (!wouldBlock) {
              if (0 != errorCode) {
                onException(mTelnetSocket);
                return;
              }
            }
          }

          if (sent < output.length()) {
            // we need to buffer the data for later...
            size_t length = (output.length() - sent);
            BufferedData data;
            std::shared_ptr<BYTE> buffer(new BYTE[length], std::default_delete<BYTE[]>() );
            memcpy(buffer.get(), output.c_str() + sent, length);

            data.first = buffer;
            data.second = length;

            mBufferedList.push_back(data);
          }
        }

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DebuggerLogger => ILogOutputDelegate
        #pragma mark
        
        //---------------------------------------------------------------------
        virtual void notifyShutdown() override
        {
          close();
        }

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark TelnetLogger => ISocketDelegate
        #pragma mark

        //---------------------------------------------------------------------
        virtual void onReadReady(SocketPtr inSocket) override
        {
          bool activate {false};

          {
            AutoRecursiveLock lock(*this);

            if (inSocket == mListenSocket) {
              if (mTelnetSocket) {
                mTelnetSocket->close();
                mTelnetSocket.reset();
              }

              IPAddress ignored;
              int noThrowError = 0;
              mTelnetSocket = mListenSocket->accept(ignored, NULL, &noThrowError);
              if (!mTelnetSocket)
                return;

              try {
#ifndef __QNX__
                mTelnetSocket->setOptionFlag(Socket::SetOptionFlag::IgnoreSigPipe, true);
#endif //ndef __QNX__
              } catch (Socket::Exceptions::UnsupportedSocketOption &) {
              }

              mTelnetSocket->setOptionFlag(Socket::SetOptionFlag::NonBlocking, true);
              mTelnetSocket->setDelegate(mThisWeak.lock());
              activate = mConnected = true;
            }

            if (inSocket == mTelnetSocket) {
              char buffer[1024 + 1];
              memset(&(buffer[0]), 0, sizeof(buffer));
              size_t length = 0;

              bool wouldBlock = false;
              int errorCode = 0;
              length = mTelnetSocket->receive((BYTE *)(&(buffer[0])), sizeof(buffer) - sizeof(buffer[0]), &wouldBlock, 0, &errorCode);

              if (wouldBlock)
                return;

              if ((length < 1) ||
                (0 != errorCode)) {
                onException(inSocket);
                return;
              }

              mCommand += (CSTR)(&buffer[0]);
              if (mCommand.size() > (sizeof(buffer) * 3)) {
                mCommand.clear();
              }
              while (true) {
                const char *posLineFeed = strchr(mCommand, '\n');
                const char *posCarrageReturn = strchr(mCommand, '\r');

                if ((NULL == posLineFeed) &&
                  (NULL == posCarrageReturn)) {
                  return;
                }

                if (NULL == posCarrageReturn)
                  posCarrageReturn = posLineFeed;
                if (NULL == posLineFeed)
                  posLineFeed = posCarrageReturn;

                if (posCarrageReturn < posLineFeed)
                  posLineFeed = posCarrageReturn;

                String command = mCommand.substr(0, (posLineFeed - mCommand.c_str()));
                mCommand = mCommand.substr((posLineFeed - mCommand.c_str()) + 1);

                if (command.size() > 0) {
                  handleCommand(command);
                }
              }
            }
          }

          if (activate) {
            activateLogging();
          }
        }

        //---------------------------------------------------------------------
        virtual void onWriteReady(SocketPtr socket) override
        {
          bool activate {false};

          {
            AutoRecursiveLock lock(*this);
            if (socket != mTelnetSocket) return;

            if (isOutgoing()) {
              if (!mConnected) {
                activate = mConnected = true;
                IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
              }
            }

            if (!mStringToSendUponConnection.isEmpty()) {

              size_t length = mStringToSendUponConnection.length();

              BufferedData data;
              std::shared_ptr<BYTE> buffer(new BYTE[length], std::default_delete<BYTE[]>());
              memcpy(buffer.get(), mStringToSendUponConnection.c_str(), length);

              data.first = buffer;
              data.second = length;

              mBufferedList.push_front(data);

              mStringToSendUponConnection.clear();
            }

            while (mBufferedList.size() > 0) {
              BufferedData &data = mBufferedList.front();
              bool wouldBlock = false;
              size_t sent = 0;

              int errorCode = 0;
              sent = mTelnetSocket->send(data.first.get(), data.second, &wouldBlock, 0, &errorCode);
              if (!wouldBlock) {
                if (0 != errorCode) {
                  onException(socket);
                  return;
                }
              }

              if (sent == data.second) {
                mBufferedList.pop_front();
                continue;
              }

              size_t length = (data.second - sent);
              memmove(data.first.get(), data.first.get() + sent, length);
              data.second = length;
              break;
            }
          }
          
          if (activate) {
            activateLogging();
          }
        }

        //---------------------------------------------------------------------
        virtual void onException(SocketPtr inSocket) override
        {
          bool deactivate = false;

          {
            AutoRecursiveLock lock(*this);
            if (inSocket == mListenSocket) {
              mListenSocket->close();
              mListenSocket.reset();

              handleConnectionFailure();
            }

            if (inSocket == mTelnetSocket) {
              mBufferedList.clear();
              mConnected = false;
              deactivate = true;

              if (mTelnetSocket) {
                mTelnetSocket->close();
                mTelnetSocket.reset();
              }

              handleConnectionFailure();
            }
          }

          if (deactivate) {
            deactivateLogging();
          }

          IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
        }

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark TelnetLogger => IDNSDelegate
        #pragma mark

        //---------------------------------------------------------------------
        virtual void onLookupCompleted(IDNSQueryPtr query) override
        {
          AutoRecursiveLock lock(*this);

          if (query != mOutgoingServerQuery) return;

          IDNS::AResult::IPAddressList list;
          IDNS::AResultPtr resultA = query->getA();
          if (resultA) {
            list = resultA->mIPAddresses;
          }
          IDNS::AAAAResultPtr resultAAAA = query->getAAAA();
          if (resultAAAA) {
            if (list.size() < 1) {
              list = resultAAAA->mIPAddresses;
            } else if (resultAAAA->mIPAddresses.size() > 0) {
              list.merge(resultAAAA->mIPAddresses);
            }
          }

          mOutgoingServerQuery.reset();

          if (list.size() > 0) {
            mServers = IDNS::convertIPAddressesToSRVResult("logger", "tcp", list, mListenPort);
          } else {
            handleConnectionFailure();
          }

          IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
        }

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark TelnetLogger => IWakeDelegate
        #pragma mark

        //---------------------------------------------------------------------
        virtual void onWake() override
        {
          step();
        }

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark TelnetLogger => ITimerDelegate
        #pragma mark

        //---------------------------------------------------------------------
        virtual void onTimer(ITimerPtr timer) override
        {
          step();
        }

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark TelnetLogger => IBackgroundingDelegate
        #pragma mark

        //---------------------------------------------------------------------
        virtual void onBackgroundingGoingToBackground(
                                                      IBackgroundingSubscriptionPtr subscription,
                                                      IBackgroundingNotifierPtr notifier
                                                      ) override {}

        //---------------------------------------------------------------------
        virtual void onBackgroundingGoingToBackgroundNow(
                                                         IBackgroundingSubscriptionPtr subscription
                                                         ) override {}

        //---------------------------------------------------------------------
        virtual void onBackgroundingReturningFromBackground(
                                                            IBackgroundingSubscriptionPtr subscription
                                                            ) override
        {
          SocketPtr socket;
          {
            AutoRecursiveLock lock(*this);
            socket = mTelnetSocket;
          }

          if (!socket) return;

          // fake a read ready to retest socket
          onReadReady(mTelnetSocket);
        }

        //---------------------------------------------------------------------
        virtual void onBackgroundingApplicationWillQuit(
                                                        IBackgroundingSubscriptionPtr subscription
                                                        ) override
        {
          close();
        }

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark TelnetLogger => (internal)
        #pragma mark
        
        //---------------------------------------------------------------------
        void getIncomingInfo(
                             WORD &outListenPort,
                             Seconds &outMaxSecondsWaitForSocketToBeAvailable,
                             bool &outColorize,
                             bool &outPrettyPrint
                             )
        {
          outListenPort = mListenPort;
          outMaxSecondsWaitForSocketToBeAvailable = zsLib::toSeconds(mMaxWaitTimeForSocketToBeAvailable);
          outColorize = mColorizeOutput;
          outPrettyPrint = mPrettyPrint;
        }
        
        //---------------------------------------------------------------------
        void getOutgoingInfo(
                             String &outServerHostWithPort,
                             bool &outColorize,
                             bool &outPrettyPrint,
                             String &outSendStringUponConnection
                             )
        {
          outServerHostWithPort = mOriginalServer;
          outColorize = mColorizeOutput;
          outPrettyPrint = mPrettyPrint;
          outSendStringUponConnection = mStringToSendUponConnection;
        }
        
        //---------------------------------------------------------------------
        void activateLogging()
        {
          auto singleton = LoggerReferencesHolder::singleton();
          if (!singleton) return;
          
          {
            AutoRecursiveLock lock(*this);
            if (mNotifiedShutdown) return;
          }

          singleton->activateLogger(mLoggerNamespace);
        }

        //---------------------------------------------------------------------
        void deactivateLogging()
        {
          auto singleton = LoggerReferencesHolder::singleton();
          if (!singleton) return;

          {
            AutoRecursiveLock lock(*this);
            if (mNotifiedShutdown) return;
          }
          
          singleton->deactivateLogger(mLoggerNamespace);
        }

        //---------------------------------------------------------------------
        void close()
        {
          deactivateLogging();

          AutoRecursiveLock lock(*this);
          
          if (mClosed) {
            // already closed
            return;
          }
          
          mClosed = true;
          mNotifiedShutdown = true;
          
          TelnetLoggerPtr pThis = mThisWeak.lock();
          if (pThis) {
            mThisWeak.reset();
          }
          
          mBufferedList.clear();
          mConnected = false;
          
          if (mOutgoingServerQuery) {
            mOutgoingServerQuery->cancel();
            mOutgoingServerQuery.reset();
          }
          
          mServers.reset();
          
          if (mTelnetSocket) {
            mTelnetSocket->close();
            mTelnetSocket.reset();
          }
          if (mListenSocket) {
            mListenSocket->close();
            mListenSocket.reset();
          }
          if (mRetryTimer) {
            mRetryTimer->cancel();
            mRetryTimer.reset();
          }
        }
        
        //---------------------------------------------------------------------
        bool isOutgoing() const
        {
          return mOriginalServer.hasData();
        }
        
        //---------------------------------------------------------------------
        bool isIncoming() const
        {
          return mOriginalServer.isEmpty();
        }

        //---------------------------------------------------------------------
        bool isClosed()
        {
          AutoRecursiveLock lock(*this);
          return mClosed;
        }

        //---------------------------------------------------------------------
        void handleCommand(String command)
        {
          String input = command;

          typedef std::list<String> StringList;
          StringList split;

          // split the command by the space character...
          while (true) {
            const char *posSpace = strchr(command, ' ');
            if (NULL == posSpace) {
              if (command.size() > 0) {
                split.push_back(command);
              }
              break;
            }
            String sub = command.substr(0, (posSpace - command.c_str()));
            command = command.substr((posSpace - command.c_str()) + 1);

            if (sub.size() > 0) {
              split.push_back(sub);
            }
          }

          bool output = false;
          String subsystem;
          String level;
          String echo;

          if (split.size() > 0) {
            command = split.front(); split.pop_front();
            if ((command == "set") && (split.size() > 0)) {
              command = split.front(); split.pop_front();
              if ((command == "log") && (split.size() > 0)) {
                level = split.front(); split.pop_front();
                output = true;
                if (level == "insane") {
                  ILogger::setLogLevel(Log::Insane);
                } else if (level == "trace") {
                  ILogger::setLogLevel(Log::Trace);
                } else if (level == "debug") {
                  ILogger::setLogLevel(Log::Debug);
                } else if (level == "detail") {
                  ILogger::setLogLevel(Log::Detail);
                } else if (level == "basic") {
                  ILogger::setLogLevel(Log::Basic);
                } else if (level == "none") {
                  ILogger::setLogLevel(Log::None);
                } else if (level == "pretty") {
                  String mode = split.front(); split.pop_front();
                  if (mode == "on") {
                    mPrettyPrint = true;
                    echo = "==> Setting pretty print on\n";
                  } else if (mode == "off") {
                    mPrettyPrint = false;
                    echo = "==> Setting pretty print off\n";
                  }
                } else if ((level == "color") || (level == "colour")) {
                  String mode = split.front(); split.pop_front();
                  if (mode == "on") {
                    mColorizeOutput = true;
                    echo = "==> Setting colourization on\n";
                  } else if (mode == "off") {
                    mColorizeOutput = false;
                    echo = "==> Setting colourization off\n";
                  }
                } else if (split.size() > 0) {
                  subsystem = level;
                  level = split.front(); split.pop_front();
                  if (level == "insane") {
                    ILogger::setLogLevel(subsystem, Log::Insane);
                  } else if (level == "trace") {
                    ILogger::setLogLevel(subsystem, Log::Trace);
                  } else if (level == "debug") {
                    ILogger::setLogLevel(subsystem, Log::Debug);
                  } else if (level == "detail") {
                    ILogger::setLogLevel(subsystem, Log::Detail);
                  } else if (level == "basic") {
                    ILogger::setLogLevel(subsystem, Log::Basic);
                  } else if (level == "none") {
                    ILogger::setLogLevel(subsystem, Log::None);
                  } else {
                    output = false;
                  }
                } else {
                  output = false;
                }
              }
            }
          }

          if (echo.isEmpty()) {
            if (output) {
              if (subsystem.size() > 0) {
                echo = "==> Setting log level for \"" + subsystem + "\" to \"" + level + "\"\n";
              } else {
                echo = "==> Setting all log compoment levels to \"" + level + "\"\n";
              }
            } else {
              echo = "==> Command not recognized \"" + input + "\"\n";
            }
          }
          bool wouldBlock = false;
          int errorCode = 0;
          mTelnetSocket->send((const BYTE *)(echo.c_str()), echo.length(), &wouldBlock, 0, &errorCode);
        }

        //---------------------------------------------------------------------
        void handleConnectionFailure()
        {
          AutoRecursiveLock lock(*this);

          if (!mRetryTimer) {
            // offer a bit of buffering
            mBacklogDataUntil = zsLib::now() + Seconds(ORTC_SERVICES_MAX_TELNET_LOGGER_PENDING_CONNECTIONBACKLOG_TIME_SECONDS);

            mRetryWaitTime = Seconds(1);
            mNextRetryTime = zsLib::now();
            mRetryTimer = ITimer::create(mThisWeak.lock(), Seconds(1));
            return;
          }

          mNextRetryTime = zsLib::now() + mRetryWaitTime;
          mRetryWaitTime = mRetryWaitTime + mRetryWaitTime;
          if (mRetryWaitTime > Seconds(60)) {
            mRetryWaitTime = Seconds(60);
          }
        }

        //---------------------------------------------------------------------
        void step()
        {
          if (isClosed()) return;

          {
            AutoRecursiveLock lock(*this);

            if (Time() != mNextRetryTime) {
              if (zsLib::now() < mNextRetryTime) return;
            }
          }

          if (!isOutgoing()) {
            if (!stepListen()) goto step_cleanup;

          } else {
            if (!stepDNS()) goto step_cleanup;
            if (!stepConnect()) goto step_cleanup;
          }

          goto step_complete;

        step_complete:
          {
            AutoRecursiveLock lock(*this);
            if (mRetryTimer) {
              mRetryTimer->cancel();
              mRetryTimer.reset();
            }
            mNextRetryTime = Time();
            mRetryWaitTime = Milliseconds();
          }

        step_cleanup:
          {
          }
        }

        //---------------------------------------------------------------------
        bool stepDNS()
        {
          String serverName;
          IDNSQueryPtr query;

          {
            AutoRecursiveLock lock(*this);
            if (mOutgoingServerQuery) return false;

            if (mServers) return true;

            if (mServerLookupName.isEmpty()) return false;
            serverName = mServerLookupName;
          }

          // not safe to call services level method from within lock...
          query = IDNS::lookupAorAAAA(mThisWeak.lock(), serverName);

          // DNS is not created during any kind of lock at all...
          {
            AutoRecursiveLock lock(*this);
            mOutgoingServerQuery = query;
          }

          return false;
        }

        //---------------------------------------------------------------------
        bool stepConnect()
        {
          AutoRecursiveLock lock(*this);

          if (mTelnetSocket) {
            return isConnected();
          }

          IPAddress result;
          if (!IDNS::extractNextIP(mServers, result)) {
            mServers.reset();

            handleConnectionFailure();
            IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
            return false;
          }

          mStringToSendUponConnection = mOriginalStringToSendUponConnection;

          mTelnetSocket = Socket::createTCP();
          try {
#ifndef __QNX__
            mTelnetSocket->setOptionFlag(Socket::SetOptionFlag::IgnoreSigPipe, true);
#endif //ndef __QNX__
          } catch(Socket::Exceptions::UnsupportedSocketOption &) {
          }
          mTelnetSocket->setBlocking(false);

          bool wouldBlock = false;
          int errorCode = 0;
          mTelnetSocket->connect(result, &wouldBlock, &errorCode);
          mTelnetSocket->setDelegate(mThisWeak.lock()); // set delegate must happen after connect is issued

          if (0 != errorCode) {
            mTelnetSocket->close();
            mTelnetSocket.reset();

            handleConnectionFailure();
            IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
            return false;
          }

          return false;
        }

        //---------------------------------------------------------------------
        bool stepListen()
        {
          AutoRecursiveLock lock(*this);

          if (mListenSocket) return true;

          if (Time() == mStartListenTime)
            mStartListenTime = zsLib::now();

          mListenSocket = Socket::createTCP();
          try {
#ifndef __QNX__
            mListenSocket->setOptionFlag(Socket::SetOptionFlag::IgnoreSigPipe, true);
#endif //ndef __QNX__
          } catch(Socket::Exceptions::UnsupportedSocketOption &) {
          }
          mListenSocket->setOptionFlag(Socket::SetOptionFlag::NonBlocking, true);

          IPAddress any = IPAddress::anyV4();
          any.setPort(mListenPort);

          int error = 0;

          std::cout << "TELNET LOGGER: Attempting to listen for client connections on port: " << mListenPort << " (start time=" << string(mStartListenTime) << ")...\n";
          mListenSocket->bind(any, &error);

          Time tick = zsLib::now();

          if (0 != error) {
            mListenSocket->close();
            mListenSocket.reset();

            if (mStartListenTime + mMaxWaitTimeForSocketToBeAvailable < tick) {
              std::cout << "TELNET LOGGER: ***ABANDONED***\n";
              close();
              return false;
            }

            handleConnectionFailure();

            std::cout << "TELNET LOGGER: Failed to listen...\n";
            IWakeDelegateProxy::create(mThisWeak.lock())->onWake();
            return false;
          }

          std::cout << "TELNET LOGGER: Succeeded.\n\n";

          mListenSocket->listen();
          mListenSocket->setDelegate(mThisWeak.lock()); // set delegate must happen after the listen

          mStartListenTime = Time();
          return true;
        }
        
      private:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark TelnetLogger => (data)
        #pragma mark

        TelnetLoggerWeakPtr mThisWeak;
        bool mNotifiedShutdown {};
        const char *mLoggerNamespace {};
        bool mColorizeOutput {};
        bool mPrettyPrint {};

        IBackgroundingSubscriptionPtr mBackgroundingSubscription;

        SocketPtr mListenSocket;
        SocketPtr mTelnetSocket;

        Time mBacklogDataUntil;

        bool mClosed {};

        String mCommand;

        typedef std::pair< std::shared_ptr<BYTE>, size_t> BufferedData;
        typedef std::list<BufferedData> BufferedDataList;

        BufferedDataList mBufferedList;

        WORD mListenPort {};
        Time mStartListenTime;
        Milliseconds mMaxWaitTimeForSocketToBeAvailable {};

        ITimerPtr mRetryTimer;
        Time mNextRetryTime;
        Milliseconds mRetryWaitTime {};

        bool mConnected {};
        IDNSQueryPtr mOutgoingServerQuery;
        String mStringToSendUponConnection;

        String mServerLookupName;
        IDNS::SRVResultPtr mServers;

        String mOriginalServer;
        String mOriginalStringToSendUponConnection;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Logger
      #pragma mark


    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark services::ILogger
    #pragma mark

    //-------------------------------------------------------------------------
    void ILogger::installStdOutLogger(bool colorizeOutput)
    {
      internal::StdOutLogger::singleton(colorizeOutput, true);
    }

    //-------------------------------------------------------------------------
    void ILogger::installFileLogger(const char *fileName, bool colorizeOutput)
    {
      internal::FileLogger::singleton(fileName, colorizeOutput, colorizeOutput);
    }

    //-------------------------------------------------------------------------
    void ILogger::installTelnetLogger(
                                      WORD listenPort,
                                      ULONG maxSecondsWaitForSocketToBeAvailable,
                                      bool colorizeOutput
                                      )
    {
      internal::TelnetLogger::singletonIncoming(listenPort, Seconds(maxSecondsWaitForSocketToBeAvailable), colorizeOutput, colorizeOutput);
    }

    //-------------------------------------------------------------------------
    void ILogger::installOutgoingTelnetLogger(
                                              const char *serverHostWithPort,
                                              bool colorizeOutput,
                                              const char *sendStringUponConnection
                                              )
    {
      internal::TelnetLogger::singletonOutgoing(serverHostWithPort, colorizeOutput, colorizeOutput, sendStringUponConnection);
    }

    //-------------------------------------------------------------------------
    void ILogger::installDebuggerLogger(bool colorizeOutput)
    {
      internal::DebuggerLogger::singleton(colorizeOutput, colorizeOutput);
    }

    //-------------------------------------------------------------------------
    bool ILogger::isTelnetLoggerListening()
    {
      auto singleton = internal::TelnetLogger::singletonIncoming();
      if (!singleton) return false;
      
      return singleton->isListening();
    }

    //-------------------------------------------------------------------------
    bool ILogger::isTelnetLoggerConnected()
    {
      auto singleton = internal::TelnetLogger::singletonIncoming();
      if (!singleton) return false;
      
      return singleton->isConnected();
    }

    //-------------------------------------------------------------------------
    bool ILogger::isOutgoingTelnetLoggerConnected()
    {
      auto singleton = internal::TelnetLogger::singletonOutgoing();
      if (!singleton) return false;
      
      return singleton->isConnected();
    }

    //-------------------------------------------------------------------------
    void ILogger::uninstallStdOutLogger()
    {
      internal::StdOutLogger::stop();
    }

    //-------------------------------------------------------------------------
    void ILogger::uninstallFileLogger()
    {
      internal::FileLogger::stop();
    }

    //-------------------------------------------------------------------------
    void ILogger::uninstallTelnetLogger()
    {
      internal::TelnetLogger::stopIncoming();
    }

    //-------------------------------------------------------------------------
    void ILogger::uninstallOutgoingTelnetLogger()
    {
      internal::TelnetLogger::stopOutgoing();
    }

    //-------------------------------------------------------------------------
    void ILogger::uninstallDebuggerLogger()
    {
      internal::DebuggerLogger::stop();
    }

    //-------------------------------------------------------------------------
    void ILogger::setLogLevel(Log::Level logLevel)
    {
      zsLib::Log::setOutputLevelByName(NULL, logLevel);
    }

    //-------------------------------------------------------------------------
    void ILogger::setLogLevel(const char *component, Log::Level logLevel)
    {
      zsLib::Log::setOutputLevelByName(component, logLevel);
    }

  }
}
