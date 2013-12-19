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

#pragma once

#include <openpeer/services/internal/types.h>

#include <zsLib/Log.h>

#define OPENPEER_SERVICES_INTERNAL_WIRE_LOG_FUNCTION_FILE_LINE    __FUNCTION__, __FILE__, __LINE__


#define OPENPEER_SERVICES_WIRE_LOG_BASIC(xMsg)    if (openpeer::services::wire::isLogging(Log::Basic))  {openpeer::services::wire::log(Log::Informational, Log::Basic, ::zsLib::Log::Params(xMsg), OPENPEER_SERVICES_INTERNAL_WIRE_LOG_FUNCTION_FILE_LINE);}
#define OPENPEER_SERVICES_WIRE_LOG_DETAIL(xMsg)   if (openpeer::services::wire::isLogging(Log::Detail)) {openpeer::services::wire::log(Log::Informational, Log::Detail, ::zsLib::Log::Params(xMsg), OPENPEER_SERVICES_INTERNAL_WIRE_LOG_FUNCTION_FILE_LINE);}
#define OPENPEER_SERVICES_WIRE_LOG_DEBUG(xMsg)    if (openpeer::services::wire::isLogging(Log::Debug))  {openpeer::services::wire::log(Log::Informational, Log::Debug, ::zsLib::Log::Params(xMsg), OPENPEER_SERVICES_INTERNAL_WIRE_LOG_FUNCTION_FILE_LINE);}
#define OPENPEER_SERVICES_WIRE_LOG_TRACE(xMsg)    if (openpeer::services::wire::isLogging(Log::Trace))  {openpeer::services::wire::log(Log::Informational, Log::Trace, ::zsLib::Log::Params(xMsg), OPENPEER_SERVICES_INTERNAL_WIRE_LOG_FUNCTION_FILE_LINE);}
#define OPENPEER_SERVICES_WIRE_LOG_INSANE(xMsg)   if (openpeer::services::wire::isLogging(Log::Insane)) {openpeer::services::wire::log(Log::Informational, Log::Insane, ::zsLib::Log::Params(xMsg), OPENPEER_SERVICES_INTERNAL_WIRE_LOG_FUNCTION_FILE_LINE);}

#define OPENPEER_SERVICES_WIRE_LOG_WARNING(xLevel, xMsg)  if (openpeer::services::wire::isLogging(Log::xLevel)) {openpeer::services::wire::log(Log::Warning, Log::xLevel, ::zsLib::Log::Params(xMsg), OPENPEER_SERVICES_INTERNAL_WIRE_LOG_FUNCTION_FILE_LINE);}
#define OPENPEER_SERVICES_WIRE_LOG_ERROR(xLevel, xMsg)    if (openpeer::services::wire::isLogging(Log::xLevel)) {openpeer::services::wire::log(Log::Error, Log::xLevel, ::zsLib::Log::Params(xMsg), OPENPEER_SERVICES_INTERNAL_WIRE_LOG_FUNCTION_FILE_LINE);}

namespace openpeer
{
  namespace services
  {
    namespace wire
    {
      using zsLib::CSTR;

      bool isLogging(Log::Level level);
      void log(
               Log::Severity severity,
               Log::Level level,
               const Log::Params &params,
               CSTR function,
               CSTR filePath,
               ULONG lineNumber
               );
    }
  }
}
