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

#include <openpeer/services/internal/services_Settings.h>
#include <openpeer/services/internal/services.h>
#include <openpeer/services/internal/services_Tracing.h>

#include <openpeer/services/IHelper.h>

#include <zsLib/XML.h>
#include <zsLib/Numeric.h>
#include <zsLib/Stringize.h>

namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services) } }

namespace openpeer
{
  namespace services
  {
    namespace internal
    {
      using services::IHelper;
      using zsLib::Numeric;

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Settings
      #pragma mark

      //-----------------------------------------------------------------------
      void Settings::setup(ISettingsDelegatePtr delegate)
      {
        StoredSettingsMapPtr stored;

        {
          AutoRecursiveLock lock(mLock);
          mDelegate = delegate;

          ZS_LOG_DEBUG(log("setup called") + ZS_PARAM("has delegate", (bool)delegate))

          if (!delegate) return;

          stored = mStored;

          mStored = make_shared<StoredSettingsMap>();
        }

        // apply all settings that occured before delegate was attached
        for (StoredSettingsMap::iterator iter = stored->begin(); iter != stored->end(); ++iter)
        {
          const Key &key = (*iter).first;
          ValuePair &valuePair = (*iter).second;

          switch (valuePair.first)
          {
            case DataType_String:   setString(key, valuePair.second); break;
            case DataType_Int:      {
              try {
                setInt(key, Numeric<LONG>(valuePair.second));
              } catch(Numeric<LONG>::ValueOutOfRange &) {
              }
              break;
            }
            case DataType_UInt:     {
              try {
                setUInt(key, Numeric<ULONG>(valuePair.second));
              } catch(Numeric<ULONG>::ValueOutOfRange &) {
              }
              break;
            }
            case DataType_Bool:     {
              try {
                setBool(key, Numeric<bool>(valuePair.second));
              } catch(Numeric<bool>::ValueOutOfRange &) {
              }
              break;
            }
            case DataType_Float:    {
              try {
                setFloat(key, Numeric<float>(valuePair.second));
              } catch(Numeric<float>::ValueOutOfRange &) {
              }
              break;
            }
            case DataType_Double:   {
              try {
                setDouble(key, Numeric<double>(valuePair.second));
              } catch(Numeric<double>::ValueOutOfRange &) {
              }
              break;
            }
          }
        }
      }

      //-----------------------------------------------------------------------
      SettingsPtr Settings::singleton()
      {
        AutoRecursiveLock lock(*IHelper::getGlobalLock());
        static SingletonLazySharedPtr<Settings> singleton(Settings::create());
        SettingsPtr result = singleton.singleton();
        if (!result) {
          ZS_LOG_WARNING(Detail, slog("singleton gone"))
        }
        return result;
      }
      
      //-----------------------------------------------------------------------
      Settings::Settings(const make_private &) :
        mStored(make_shared<StoredSettingsMap>())
      {
        Helper::setup();
        ZS_LOG_DETAIL(log("created"))
      }

      //-----------------------------------------------------------------------
      Settings::~Settings()
      {
        mThisWeak.reset();
        ZS_LOG_DETAIL(log("destroyed"))
      }

      //-----------------------------------------------------------------------
      SettingsPtr Settings::convert(ISettingsPtr settings)
      {
        return ZS_DYNAMIC_PTR_CAST(Settings, settings);
      }

      //-----------------------------------------------------------------------
      SettingsPtr Settings::create()
      {
        SettingsPtr pThis(make_shared<Settings>(make_private{}));
        pThis->mThisWeak = pThis;
        return pThis;
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Settings => ISettings
      #pragma mark

      //-----------------------------------------------------------------------
      String Settings::getString(const char *key) const
      {
        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            StoredSettingsMap::const_iterator found = mStored->find(key);
            if (found == mStored->end()) return String();
            auto result = (*found).second.second;
            ZS_LOG_TRACE(log("get string") + ZS_PARAM("key", key) + ZS_PARAM("value", result))
            EventWriteOpServicesSettingGetString(__func__, mID, key, result);
            return result;
          }
        }

        auto result = delegate->getString(key);
        EventWriteOpServicesSettingGetString(__func__, mID, key, result);
        return result;
      }

      //-----------------------------------------------------------------------
      LONG Settings::getInt(const char *key) const
      {
        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            StoredSettingsMap::const_iterator found = mStored->find(key);
            if (found == mStored->end()) return 0;
            try {
              auto result = Numeric<LONG>((*found).second.second);
              ZS_LOG_TRACE(log("get string") + ZS_PARAM("key", key) + ZS_PARAM("value", result))
              EventWriteOpServicesSettingGetInt(__func__, mID, key, result);
              return result;
            } catch(Numeric<LONG>::ValueOutOfRange &) {
            }
            EventWriteOpServicesSettingGetInt(__func__, mID, key, 0);
            return 0;
          }
        }

        auto result = delegate->getInt(key);
        EventWriteOpServicesSettingGetInt(__func__, mID, key, result);
        return result;
      }

      //-----------------------------------------------------------------------
      ULONG Settings::getUInt(const char *key) const
      {
        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            StoredSettingsMap::const_iterator found = mStored->find(key);
            if (found == mStored->end()) return 0;
            try {
              auto result = Numeric<ULONG>((*found).second.second);
              ZS_LOG_TRACE(log("get string") + ZS_PARAM("key", key) + ZS_PARAM("value", result))
              EventWriteOpServicesSettingGetUInt(__func__, mID, key, result);
              return result;
            } catch(Numeric<ULONG>::ValueOutOfRange &) {
            }
            EventWriteOpServicesSettingGetUInt(__func__, mID, key, 0);
            return 0;
          }
        }

        auto result = delegate->getUInt(key);
        EventWriteOpServicesSettingGetUInt(__func__, mID, key, result);
        return result;
      }

      //-----------------------------------------------------------------------
      bool Settings::getBool(const char *key) const
      {
        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            StoredSettingsMap::const_iterator found = mStored->find(key);
            if (found == mStored->end()) return false;
            try {
              auto result = Numeric<bool>((*found).second.second);
              ZS_LOG_TRACE(log("get string") + ZS_PARAM("key", key) + ZS_PARAM("value", result))
              EventWriteOpServicesSettingGetBool(__func__, mID, key, result);
              return result;
            } catch(Numeric<bool>::ValueOutOfRange &) {
            }
            EventWriteOpServicesSettingGetBool(__func__, mID, key, false);
            return false;
          }
        }

        auto result = delegate->getBool(key);
        EventWriteOpServicesSettingGetBool(__func__, mID, key, result);
        return result;
      }

      //-----------------------------------------------------------------------
      float Settings::getFloat(const char *key) const
      {
        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            StoredSettingsMap::const_iterator found = mStored->find(key);
            if (found == mStored->end()) return 0;
            try {
              auto result = Numeric<float>((*found).second.second);
              ZS_LOG_TRACE(log("get string") + ZS_PARAM("key", key) + ZS_PARAM("value", result))
              EventWriteOpServicesSettingGetFloat(__func__, mID, key, result);
              return result;
            } catch(Numeric<float>::ValueOutOfRange &) {
            }
            EventWriteOpServicesSettingGetFloat(__func__, mID, key, 0.0f);
            return 0;
          }
        }

        auto result = delegate->getFloat(key);
        EventWriteOpServicesSettingGetFloat(__func__, mID, key, result);
        return result;
      }

      //-----------------------------------------------------------------------
      double Settings::getDouble(const char *key) const
      {
        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            StoredSettingsMap::const_iterator found = mStored->find(key);
            if (found == mStored->end()) return 0;
            try {
              auto result = Numeric<double>((*found).second.second);
              ZS_LOG_TRACE(log("get string") + ZS_PARAM("key", key) + ZS_PARAM("value", result))
              EventWriteOpServicesSettingGetFloat(__func__, mID, key, result);
              return result;
            } catch(Numeric<double>::ValueOutOfRange &) {
            }
            EventWriteOpServicesSettingGetFloat(__func__, mID, key, 0.0);
            return 0;
          }
        }

        auto result = delegate->getDouble(key);
        EventWriteOpServicesSettingGetFloat(__func__, mID, key, result);
        return result;
      }

      //-----------------------------------------------------------------------
      void Settings::setString(
                               const char *key,
                               const char *value
                               )
      {
        EventWriteOpServicesSettingSetString(__func__, mID, key, value);

        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            (*mStored)[String(key)] = ValuePair(DataType_String, String(value));
            ZS_LOG_TRACE(log("set string") + ZS_PARAM("key", key) + ZS_PARAM("value", value))
            return;
          }
        }

        return delegate->setString(key, value);
      }

      //-----------------------------------------------------------------------
      void Settings::setInt(
                            const char *key,
                            LONG value
                            )
      {
        EventWriteOpServicesSettingSetInt(__func__, mID, key, value);

        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            (*mStored)[String(key)] = ValuePair(DataType_Int, string(value));
            ZS_LOG_TRACE(log("set int") + ZS_PARAM("key", key) + ZS_PARAM("value", value))
            return;
          }
        }

        return delegate->setInt(key, value);
      }

      //-----------------------------------------------------------------------
      void Settings::setUInt(
                             const char *key,
                             ULONG value
                             )
      {
        EventWriteOpServicesSettingSetUInt(__func__, mID, key, value);

        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            (*mStored)[String(key)] = ValuePair(DataType_UInt, string(value));
            ZS_LOG_TRACE(log("set uint") + ZS_PARAM("key", key) + ZS_PARAM("value", value))
            return;
          }
        }

        return delegate->setUInt(key, value);
      }

      //-----------------------------------------------------------------------
      void Settings::setBool(
                             const char *key,
                             bool value
                             )
      {
        EventWriteOpServicesSettingSetBool(__func__, mID, key, value);

        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            (*mStored)[String(key)] = ValuePair(DataType_Bool, string(value));
            ZS_LOG_TRACE(log("set bool") + ZS_PARAM("key", key) + ZS_PARAM("value", value))
            return;
          }
        }

        return delegate->setBool(key, value);
      }

      //-----------------------------------------------------------------------
      void Settings::setFloat(
                              const char *key,
                              float value
                              )
      {
        EventWriteOpServicesSettingSetFloat(__func__, mID, key, value);

        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            (*mStored)[String(key)] = ValuePair(DataType_Float, string(value));
            ZS_LOG_TRACE(log("set float") + ZS_PARAM("key", key) + ZS_PARAM("value", value))
            return;
          }
        }

        return delegate->setFloat(key, value);
      }

      //-----------------------------------------------------------------------
      void Settings::setDouble(
                               const char *key,
                               double value
                               )
      {
        EventWriteOpServicesSettingSetDouble(__func__, mID, key, value);

        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            (*mStored)[String(key)] = ValuePair(DataType_Double, string(value));
            ZS_LOG_TRACE(log("set double") + ZS_PARAM("key", key) + ZS_PARAM("value", value))
            return;
          }
        }

        return delegate->setDouble(key, value);
      }

      //-----------------------------------------------------------------------
      void Settings::clear(const char *key)
      {
        EventWriteOpServicesSettingClear(__func__, mID, key);

        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            StoredSettingsMap::iterator found = mStored->find(key);
            if (found == mStored->end()) return;

            mStored->erase(found);
            ZS_LOG_TRACE(log("clear setting") + ZS_PARAM("key", key))
            return;
          }
        }

        delegate->clear(key);
      }

      //-----------------------------------------------------------------------
      bool Settings::apply(const char *jsonSettings)
      {
        EventWriteOpServicesSettingApply(__func__, mID, jsonSettings);

        typedef std::list<ElementPtr> NestedList;

        if (!jsonSettings) return false;

        ElementPtr rootEl = IHelper::toJSON(jsonSettings);
        if (!rootEl) return false;

        bool nestedValues = false;
        if (OPENPEER_SERVICES_SETTINGS_ROOT_JSON_IS_NESTED_NODE == rootEl->getValue()) {
          nestedValues = true;
        }

        bool found = false;

        NestedList parents;

        ElementPtr childEl = rootEl->getFirstChildElement();
        while (childEl) {

          if (nestedValues) {
            ElementPtr firstChildEl = childEl->getFirstChildElement();
            if (firstChildEl) {
              parents.push_back(childEl);
              childEl = firstChildEl;
              continue;
            }
          }


          String key = childEl->getValue();
          String value = childEl->getTextDecoded();
          String attribute = childEl->getAttributeValue("type");

          if (key.isEmpty()) continue;
          if (value.isEmpty()) continue;

          if (parents.size() > 0) {
            String path;
            for (auto iter = parents.begin(); iter != parents.end(); ++iter) {
              String name = (*iter)->getValue();
              path += name + "/";
            }
            key = path + key;
          }

          bool handled = true;
          bool wasEmpty = attribute.isEmpty();

          if (wasEmpty) {
            bool numberEncoded = false;

            // attempt to guess type based on input
            NodePtr checkEl = childEl->getFirstChild();
            while (checkEl) {

              if (checkEl->isText()) {
                TextPtr textEl = checkEl->toText();
                if (Text::Format_JSONNumberEncoded == textEl->getFormat()) {
                  numberEncoded = true;
                  break;
                }
              }

              checkEl = checkEl->getNextSibling();
            }

            if (numberEncoded) {
              if (String::npos != value.find_first_of('.')) {
                attribute = "double";
              } else if (isdigit(*value.c_str())) {
                attribute = "uint";
              } else if ('-' == *(value.c_str())) {
                attribute = "int";
              } else {
                attribute = "bool";
              }
            }
          }

          if (attribute.hasData()) {
            if ("string" == attribute) {
              setString(key, value);
            } else if ("int" == attribute) {
              try {
                setInt(key, Numeric<LONG>(value));
              } catch(Numeric<LONG>::ValueOutOfRange &) {
                handled = false;
              }
            } else if ("uint" == attribute) {
              try {
                setUInt(key, Numeric<ULONG>(value));
              } catch(Numeric<ULONG>::ValueOutOfRange &) {
                handled = false;
              }
            } else if ("bool" == attribute) {
              try {
                setBool(key, Numeric<bool>(value));
              } catch(Numeric<bool>::ValueOutOfRange &) {
                handled = false;
              }
            } else if ("float" == attribute) {
              try {
                setFloat(key, Numeric<float>(value));
              } catch(Numeric<float>::ValueOutOfRange &) {
                handled = false;
              }
            } else if ("double" == attribute) {
              try {
                setDouble(key, Numeric<double>(value));
              } catch(Numeric<double>::ValueOutOfRange &) {
                handled = false;
              }
            }

            if (!handled) {
              if (wasEmpty) {
                // guess was wrong, set as a string
                setString(key, value);
              }
            }
          } else {
            setString(key, value);
          }

          found = handled;

          childEl = childEl->getNextSiblingElement();

          if (!childEl) {
            while ((parents.size() > 0) &&
                   (!childEl)) {
              childEl = parents.back();
              parents.pop_back();

              childEl = childEl->getNextSiblingElement();
            }
          }
        }

        return found;
      }

      //-----------------------------------------------------------------------
      void Settings::applyDefaults()
      {
        EventWriteOpServicesSettingApplyDefaults(__func__, mID);

        setBool(OPENPEER_SERVICES_SETTING_MESSAGE_QUEUE_MANAGER_PROCESS_APPLICATION_MESSAGE_QUEUE_ON_QUIT, false);
        setBool(OPENPEER_SERVICES_SETTING_FORCE_USE_TURN, false);
        setBool(OPENPEER_SERVICES_SETTING_FORCE_TURN_TO_USE_TCP, false);
        setBool(OPENPEER_SERVICES_SETTING_FORCE_TURN_TO_USE_UDP, false);
        setBool(OPENPEER_SERVICES_SETTING_INTERFACE_SUPPORT_IPV6, false);

        setUInt(OPENPEER_SERVICES_SETTING_ICESOCKETSESSION_BACKGROUNDING_PHASE, 4);
        setUInt(OPENPEER_SERVICES_SETTING_TURN_BACKGROUNDING_PHASE, 4);
        setUInt(OPENPEER_SERVICES_SETTING_TCPMESSAGING_BACKGROUNDING_PHASE, 5);
        setUInt(OPENPEER_SERVICES_SETTING_TELNET_LOGGER_PHASE, 6);

        setUInt(OPENPEER_SERVICES_SETTING_TURN_CANDIDATES_MUST_REMAIN_ALIVE_AFTER_ICE_WAKE_UP_IN_SECONDS, 60*5);
        setUInt(OPENPEER_SERVICES_SETTING_MAX_REBIND_ATTEMPT_DURATION_IN_SECONDS, 60);
        setBool(OPENPEER_SERVICES_SETTING_ICE_SOCKET_NO_LOCAL_IPS_CAUSES_SOCKET_FAILURE, false);

        setString(OPENPEER_SERVICES_SETTING_HELPER_SERVICES_THREAD_POOL_PRIORITY, "high");
        setString(OPENPEER_SERVICES_SETTING_HELPER_SERVICES_THREAD_PRIORITY, "high");
        setString(OPENPEER_SERVICES_SETTING_HELPER_LOGGER_THREAD_PRIORITY, "normal");
        setString(OPENPEER_SERVICES_SETTING_HELPER_SOCKET_MONITOR_THREAD_PRIORITY, "real-time");
        setString(OPENPEER_SERVICES_SETTING_HELPER_TIMER_MONITOR_THREAD_PRIORITY, "normal");
#ifndef WINRT
        setString(OPENPEER_SERVICES_SETTING_HELPER_HTTP_THREAD_PRIORITY, "normal");
#endif //ndef WINRT
        setString(OPENPEER_SERVICES_SETTING_ONLY_ALLOW_DATA_SENT_TO_SPECIFIC_IPS, "");
        setString(OPENPEER_SERVICES_SETTING_ONLY_ALLOW_TURN_TO_RELAY_DATA_TO_SPECIFIC_IPS, "");
        setString(OPENPEER_SERVICES_SETTING_INTERFACE_NAME_ORDER, "lo;en;pdp_ip;stf;gif;bbptp;p2p");

        setUInt(OPENPEER_SERVICES_SETTING_MESSAGE_LAYER_SECURITY_CHANGE_SENDING_KEY_AFTER, 60*60);

        setUInt(OPENPEER_SERVICES_SETTING_BACKOFF_TIMER_MAX_CONSTRUCTOR_FAILURES, 100);

        {
          AutoRecursiveLock lock(mLock);
          mAppliedDefaults = true;
        }
      }

      //-----------------------------------------------------------------------
      void Settings::clearAll()
      {
        EventWriteOpServicesSettingClearAll(__func__, mID);

        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          mStored->clear();

          ZS_LOG_TRACE(log("clear all"))

          if (!delegate) return;
        }

        delegate->clearAll();
      }

      //-----------------------------------------------------------------------
      void Settings::verifySettingExists(const char *key) throw (InvalidUsage)
      {
        ZS_THROW_INVALID_ARGUMENT_IF(!key)

        ISettingsDelegatePtr delegate;

        {
          {
            AutoRecursiveLock lock(mLock);
            delegate = mDelegate;

            if (!delegate) {
              StoredSettingsMap::iterator found = mStored->find(key);
              if (found == mStored->end()) goto not_found;

              auto value = (*found).second.second;
              if (value.isEmpty()) goto not_found;

              EventWriteOpServicesSettingVerifyExists(__func__, mID, key, true);
              return;
            }
          }

          String result = delegate->getString(key);
          if (result.isEmpty()) goto not_found;
          EventWriteOpServicesSettingVerifyExists(__func__, mID, key, true);
          return;
        }

      not_found:
        {
          EventWriteOpServicesSettingVerifyExists(__func__, mID, key, false);

          ZS_LOG_WARNING(Basic, log("setting was not set") + ZS_PARAM("setting name", key))

          ZS_THROW_INVALID_USAGE(String("setting is missing a value: ") + key)
        }
      }

      //-----------------------------------------------------------------------
      void Settings::verifyRequiredSettings() throw (InvalidUsage)
      {
        applyDefaultsIfNoDelegatePresent();

        // check any required settings here:
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Settings => (internal)
      #pragma mark

      //-----------------------------------------------------------------------
      Log::Params Settings::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("services::Settings");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params Settings::slog(const char *message)
      {
        return Log::Params(message, "services::Settings");
      }

      //-----------------------------------------------------------------------
      void Settings::applyDefaultsIfNoDelegatePresent()
      {
        {
          AutoRecursiveLock lock(mLock);
          if (mDelegate) return;

          if (mAppliedDefaults) return;
        }

        ZS_LOG_WARNING(Detail, log("To prevent issues with missing settings, the default settings are being applied. Recommend installing a settings delegate to fetch settings required from a externally."))

        applyDefaults();
      }
      
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark ISettings
    #pragma mark

    //-------------------------------------------------------------------------
    void ISettings::setup(ISettingsDelegatePtr delegate)
    {
      internal::SettingsPtr singleton = internal::Settings::singleton();
      if (!singleton) return;
      singleton->setup(delegate);
    }

    //-------------------------------------------------------------------------
    String ISettings::getString(const char *key)
    {
      internal::SettingsPtr singleton = internal::Settings::singleton();
      if (!singleton) return String();
      return singleton->getString(key);
    }

    //-------------------------------------------------------------------------
    LONG ISettings::getInt(const char *key)
    {
      internal::SettingsPtr singleton = internal::Settings::singleton();
      if (!singleton) return 0;
      return singleton->getInt(key);
    }

    //-------------------------------------------------------------------------
    ULONG ISettings::getUInt(const char *key)
    {
      internal::SettingsPtr singleton = internal::Settings::singleton();
      if (!singleton) return 0;
      return singleton->getUInt(key);
    }

    //-------------------------------------------------------------------------
    bool ISettings::getBool(const char *key)
    {
      internal::SettingsPtr singleton = internal::Settings::singleton();
      if (!singleton) return false;
      return singleton->getBool(key);
    }

    //-------------------------------------------------------------------------
    float ISettings::getFloat(const char *key)
    {
      internal::SettingsPtr singleton = internal::Settings::singleton();
      if (!singleton) return 0.0f;
      return singleton->getFloat(key);
    }

    //-------------------------------------------------------------------------
    double ISettings::getDouble(const char *key)
    {
      internal::SettingsPtr singleton = internal::Settings::singleton();
      if (!singleton) return 0.0;
      return singleton->getDouble(key);
    }

    //-------------------------------------------------------------------------
    void ISettings::setString(
                              const char *key,
                              const char *value
                              )
    {
      internal::SettingsPtr singleton = internal::Settings::singleton();
      if (!singleton) return;
      singleton->setString(key, value);
    }

    //-------------------------------------------------------------------------
    void ISettings::setInt(
                           const char *key,
                           LONG value
                           )
    {
      internal::SettingsPtr singleton = internal::Settings::singleton();
      if (!singleton) return;
      singleton->setInt(key, value);
    }

    //-------------------------------------------------------------------------
    void ISettings::setUInt(
                            const char *key,
                            ULONG value
                            )
    {
      internal::SettingsPtr singleton = internal::Settings::singleton();
      if (!singleton) return;
      singleton->setUInt(key, value);
    }

    //-------------------------------------------------------------------------
    void ISettings::setBool(
                            const char *key,
                            bool value
                            )
    {
      internal::SettingsPtr singleton = internal::Settings::singleton();
      if (!singleton) return;
      singleton->setBool(key, value);
    }

    //-------------------------------------------------------------------------
    void ISettings::setFloat(
                             const char *key,
                             float value
                             )
    {
      internal::SettingsPtr singleton = internal::Settings::singleton();
      if (!singleton) return;
      singleton->setFloat(key, value);
    }

    //-------------------------------------------------------------------------
    void ISettings::setDouble(
                              const char *key,
                              double value
                              )
    {
      internal::SettingsPtr singleton = internal::Settings::singleton();
      if (!singleton) return;
      singleton->setDouble(key, value);
    }

    //-------------------------------------------------------------------------
    void ISettings::clear(const char *key)
    {
      internal::SettingsPtr singleton = internal::Settings::singleton();
      if (!singleton) return;
      singleton->clear(key);
    }

    //-------------------------------------------------------------------------
    bool ISettings::apply(const char *jsonSettings)
    {
      internal::SettingsPtr singleton = internal::Settings::singleton();
      if (!singleton) return false;
      return singleton->apply(jsonSettings);
    }

    //-------------------------------------------------------------------------
    void ISettings::applyDefaults()
    {
      internal::SettingsPtr singleton = internal::Settings::singleton();
      if (!singleton) return;
      singleton->applyDefaults();
    }

    //-------------------------------------------------------------------------
    void ISettings::clearAll()
    {
      internal::SettingsPtr singleton = internal::Settings::singleton();
      if (!singleton) return;
      singleton->clearAll();
    }

    //-------------------------------------------------------------------------
    void ISettings::verifySettingExists(const char *key) throw (InvalidUsage)
    {
      internal::SettingsPtr singleton = internal::Settings::singleton();
      if (!singleton) return;
      singleton->verifySettingExists(key);
    }

    //-------------------------------------------------------------------------
    void ISettings::verifyRequiredSettings() throw (InvalidUsage)
    {
      internal::SettingsPtr singleton = internal::Settings::singleton();
      if (!singleton) return;
      singleton->verifyRequiredSettings();
    }
  }
}
