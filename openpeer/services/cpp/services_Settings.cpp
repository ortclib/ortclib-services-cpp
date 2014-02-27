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

#include <openpeer/services/internal/services_Settings.h>
#include <openpeer/services/internal/services.h>

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

          mStored = StoredSettingsMapPtr(new StoredSettingsMap);
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
        static SettingsPtr singleton = Settings::create();
        return singleton;
      }
      
      //-----------------------------------------------------------------------
      Settings::Settings() :
        mStored(new StoredSettingsMap())
      {
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
        return dynamic_pointer_cast<Settings>(settings);
      }

      //-----------------------------------------------------------------------
      SettingsPtr Settings::create()
      {
        SettingsPtr pThis(new Settings());
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
            return (*found).second.second;
          }
        }

        return delegate->getString(key);
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
              return Numeric<LONG>((*found).second.second);
            } catch(Numeric<LONG>::ValueOutOfRange &) {
            }
            return 0;
          }
        }

        return delegate->getInt(key);
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
              return Numeric<ULONG>((*found).second.second);
            } catch(Numeric<ULONG>::ValueOutOfRange &) {
            }
            return 0;
          }
        }

        return delegate->getUInt(key);
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
              return Numeric<bool>((*found).second.second);
            } catch(Numeric<bool>::ValueOutOfRange &) {
            }
            return false;
          }
        }

        return delegate->getBool(key);
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
              return Numeric<float>((*found).second.second);
            } catch(Numeric<float>::ValueOutOfRange &) {
            }
            return 0;
          }
        }

        return delegate->getFloat(key);
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
              return Numeric<double>((*found).second.second);
            } catch(Numeric<double>::ValueOutOfRange &) {
            }
            return 0;
          }
        }

        return delegate->getDouble(key);
      }

      //-----------------------------------------------------------------------
      void Settings::setString(
                               const char *key,
                               const char *value
                               )
      {
        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            (*mStored)[String(key)] = ValuePair(DataType_String, String(value));
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
        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            (*mStored)[String(key)] = ValuePair(DataType_Int, string(value));
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
        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            (*mStored)[String(key)] = ValuePair(DataType_UInt, string(value));
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
        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            (*mStored)[String(key)] = ValuePair(DataType_Bool, string(value));
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
        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            (*mStored)[String(key)] = ValuePair(DataType_Float, string(value));
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
        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            (*mStored)[String(key)] = ValuePair(DataType_Double, string(value));
            return;
          }
        }

        return delegate->setDouble(key, value);
      }

      //-----------------------------------------------------------------------
      void Settings::clear(const char *key)
      {
        ISettingsDelegatePtr delegate;

        {
          AutoRecursiveLock lock(mLock);
          delegate = mDelegate;

          if (!delegate) {
            StoredSettingsMap::iterator found = mStored->find(key);
            if (found == mStored->end()) return;

            mStored->erase(found);
            return;
          }
        }

        delegate->clear(key);
      }

      //-----------------------------------------------------------------------
      bool Settings::apply(const char *jsonSettings)
      {
        if (!jsonSettings) return false;

        ElementPtr rootEl = IHelper::toJSON(jsonSettings);
        if (!rootEl) return false;

        bool found = false;

        ElementPtr childEl = rootEl->getFirstChildElement();
        while (childEl) {

          String key = childEl->getValue();
          String value = childEl->getTextDecoded();
          String attribute = childEl->getAttributeValue("type");

          if (key.isEmpty()) continue;
          if (value.isEmpty()) continue;

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
        }

        return found;
      }

      //-----------------------------------------------------------------------
      void Settings::applyDefaults()
      {
        setBool(OPENPEER_SERVICES_SETTING_FORCE_USE_TURN, false);
        setBool(OPENPEER_SERVICES_SETTING_FORCE_TURN_TO_USE_TCP, false);
        setBool(OPENPEER_SERVICES_SETTING_FORCE_TURN_TO_USE_UDP, false);
        setString(OPENPEER_SERVICES_SETTING_ONLY_ALLOW_DATA_SENT_TO_SPECIFIC_IPS, "");
        setString(OPENPEER_SERVICES_SETTING_ONLY_ALLOW_TURN_TO_RELAY_DATA_TO_SPECIFIC_IPS, "");
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
      internal::Settings::singleton()->setup(delegate);
    }

    //-------------------------------------------------------------------------
    String ISettings::getString(const char *key)
    {
      return internal::Settings::singleton()->getString(key);
    }

    //-------------------------------------------------------------------------
    LONG ISettings::getInt(const char *key)
    {
      return internal::Settings::singleton()->getInt(key);
    }

    //-------------------------------------------------------------------------
    ULONG ISettings::getUInt(const char *key)
    {
      return internal::Settings::singleton()->getUInt(key);
    }

    //-------------------------------------------------------------------------
    bool ISettings::getBool(const char *key)
    {
      return internal::Settings::singleton()->getBool(key);
    }

    //-------------------------------------------------------------------------
    float ISettings::getFloat(const char *key)
    {
      return internal::Settings::singleton()->getFloat(key);
    }

    //-------------------------------------------------------------------------
    double ISettings::getDouble(const char *key)
    {
      return internal::Settings::singleton()->getDouble(key);
    }

    //-------------------------------------------------------------------------
    void ISettings::setString(
                              const char *key,
                              const char *value
                              )
    {
      internal::Settings::singleton()->setString(key, value);
    }

    //-------------------------------------------------------------------------
    void ISettings::setInt(
                           const char *key,
                           LONG value
                           )
    {
      internal::Settings::singleton()->setInt(key, value);
    }

    //-------------------------------------------------------------------------
    void ISettings::setUInt(
                            const char *key,
                            ULONG value
                            )
    {
      internal::Settings::singleton()->setUInt(key, value);
    }

    //-------------------------------------------------------------------------
    void ISettings::setBool(
                            const char *key,
                            bool value
                            )
    {
      internal::Settings::singleton()->setBool(key, value);
    }

    //-------------------------------------------------------------------------
    void ISettings::setFloat(
                             const char *key,
                             float value
                             )
    {
      internal::Settings::singleton()->setFloat(key, value);
    }

    //-------------------------------------------------------------------------
    void ISettings::setDouble(
                              const char *key,
                              double value
                              )
    {
      internal::Settings::singleton()->setDouble(key, value);
    }

    //-------------------------------------------------------------------------
    void ISettings::clear(const char *key)
    {
      internal::Settings::singleton()->clear(key);
    }

    //-------------------------------------------------------------------------
    bool ISettings::apply(const char *jsonSettings)
    {
      return internal::Settings::singleton()->apply(jsonSettings);
    }

    //-------------------------------------------------------------------------
    void ISettings::applyDefaults()
    {
      internal::Settings::singleton()->applyDefaults();
    }
  }
}
