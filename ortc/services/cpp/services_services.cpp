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

#include <ortc/services/services.h>
#include <ortc/services/internal/services.h>

#include <zsLib/Log.h>

namespace ortc { namespace services { ZS_IMPLEMENT_SUBSYSTEM(ortc_services) } }
namespace ortc { namespace services { ZS_IMPLEMENT_SUBSYSTEM(ortc_services_dns) } }
namespace ortc { namespace services { ZS_IMPLEMENT_SUBSYSTEM(ortc_services_http) } }
namespace ortc { namespace services { ZS_IMPLEMENT_SUBSYSTEM(ortc_services_ice) } }
namespace ortc { namespace services { ZS_IMPLEMENT_SUBSYSTEM(ortc_services_stun) } }
namespace ortc { namespace services { ZS_IMPLEMENT_SUBSYSTEM(ortc_services_turn) } }
namespace ortc { namespace services { ZS_IMPLEMENT_SUBSYSTEM(ortc_services_rudp) } }
namespace ortc { namespace services { ZS_IMPLEMENT_SUBSYSTEM(ortc_services_mls) } }
namespace ortc { namespace services { ZS_IMPLEMENT_SUBSYSTEM(ortc_services_tcp_messaging) } }
namespace ortc { namespace services { ZS_IMPLEMENT_SUBSYSTEM(ortc_services_transport_stream) } }
namespace ortc { namespace services { namespace wire { ZS_IMPLEMENT_SUBSYSTEM(ortc_services_wire) } } }

ZS_EVENTING_SUBSYSTEM_DEFAULT_LEVEL(ortc_services, Debug);
ZS_EVENTING_SUBSYSTEM_DEFAULT_LEVEL(ortc_services_dns, Debug);
ZS_EVENTING_SUBSYSTEM_DEFAULT_LEVEL(ortc_services_http, Debug);
ZS_EVENTING_SUBSYSTEM_DEFAULT_LEVEL(ortc_services_ice, Debug);
ZS_EVENTING_SUBSYSTEM_DEFAULT_LEVEL(ortc_services_stun, Debug);
ZS_EVENTING_SUBSYSTEM_DEFAULT_LEVEL(ortc_services_turn, Debug);
ZS_EVENTING_SUBSYSTEM_DEFAULT_LEVEL(ortc_services_rudp, Debug);
ZS_EVENTING_SUBSYSTEM_DEFAULT_LEVEL(ortc_services_mls, Debug);
ZS_EVENTING_SUBSYSTEM_DEFAULT_LEVEL(ortc_services_tcp_messaging, Debug);
ZS_EVENTING_SUBSYSTEM_DEFAULT_LEVEL(ortc_services_transport_stream, Debug);
ZS_EVENTING_SUBSYSTEM_DEFAULT_LEVEL(ortc_services_wire, Debug);

namespace ortc
{
  namespace services
  {
    namespace internal
    {
      void initSubsystems()
      {
        ZS_GET_SUBSYSTEM_LOG_LEVEL(ZS_GET_OTHER_SUBSYSTEM(ortc::services, ortc_services));
        ZS_GET_SUBSYSTEM_LOG_LEVEL(ZS_GET_OTHER_SUBSYSTEM(ortc::services, ortc_services_http));
        ZS_GET_SUBSYSTEM_LOG_LEVEL(ZS_GET_OTHER_SUBSYSTEM(ortc::services, ortc_services_ice));
        ZS_GET_SUBSYSTEM_LOG_LEVEL(ZS_GET_OTHER_SUBSYSTEM(ortc::services, ortc_services_turn));
        ZS_GET_SUBSYSTEM_LOG_LEVEL(ZS_GET_OTHER_SUBSYSTEM(ortc::services, ortc_services_turn));
        ZS_GET_SUBSYSTEM_LOG_LEVEL(ZS_GET_OTHER_SUBSYSTEM(ortc::services, ortc_services_rudp));
        ZS_GET_SUBSYSTEM_LOG_LEVEL(ZS_GET_OTHER_SUBSYSTEM(ortc::services, ortc_services_mls));
        ZS_GET_SUBSYSTEM_LOG_LEVEL(ZS_GET_OTHER_SUBSYSTEM(ortc::services, ortc_services_tcp_messaging));
        ZS_GET_SUBSYSTEM_LOG_LEVEL(ZS_GET_OTHER_SUBSYSTEM(ortc::services, ortc_services_transport_stream));
        ZS_GET_SUBSYSTEM_LOG_LEVEL(ZS_GET_OTHER_SUBSYSTEM(ortc::services::wire, ortc_services_wire));
      }
    }
  }
}
