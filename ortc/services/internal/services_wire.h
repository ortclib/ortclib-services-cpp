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

#include <ortc/services/internal/types.h>

#include <zsLib/Log.h>

namespace ortc { namespace services { namespace wire { ZS_DECLARE_FORWARD_SUBSYSTEM(ortc_services_wire) } } }

#define ORTC_SERVICES_WIRE_IS_LOGGING(xLevel) ZS_IS_SUBSYSTEM_LOGGING(ZS_GET_OTHER_SUBSYSTEM(::ortc::services::wire, ortc_services_wire), xLevel)

#define ORTC_SERVICES_WIRE_LOG_BASIC(xMsg)    ZS_LOG_SUBSYSTEM_BASIC(ZS_GET_OTHER_SUBSYSTEM(::ortc::services::wire, ortc_services_wire), xMsg)
#define ORTC_SERVICES_WIRE_LOG_DETAIL(xMsg)   ZS_LOG_SUBSYSTEM_DETAIL(ZS_GET_OTHER_SUBSYSTEM(::ortc::services::wire, ortc_services_wire), xMsg)
#define ORTC_SERVICES_WIRE_LOG_DEBUG(xMsg)    ZS_LOG_SUBSYSTEM_DEBUG(ZS_GET_OTHER_SUBSYSTEM(::ortc::services::wire, ortc_services_wire), xMsg)
#define ORTC_SERVICES_WIRE_LOG_TRACE(xMsg)    ZS_LOG_SUBSYSTEM_TRACE(ZS_GET_OTHER_SUBSYSTEM(::ortc::services::wire, ortc_services_wire), xMsg)
#define ORTC_SERVICES_WIRE_LOG_INSANE(xMsg)   ZS_LOG_SUBSYSTEM_INSANE(ZS_GET_OTHER_SUBSYSTEM(::ortc::services::wire, ortc_services_wire), xMsg)

#define ORTC_SERVICES_WIRE_LOG_WARNING(xLevel, xMsg)  ZS_LOG_SUBSYSTEM_WARNING(ZS_GET_OTHER_SUBSYSTEM(::ortc::services::wire, ortc_services_wire), xLevel, xMsg)
#define ORTC_SERVICES_WIRE_LOG_ERROR(xLevel, xMsg)    ZS_LOG_SUBSYSTEM_ERROR(ZS_GET_OTHER_SUBSYSTEM(::ortc::services::wire, ortc_services_wire), xLevel, xMsg)
