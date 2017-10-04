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


#define ZS_DECLARE_TEMPLATE_GENERATE_IMPLEMENTATION

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

    //-------------------------------------------------------------------------
    SharedRecursiveLock::SharedRecursiveLock(const SharedRecursiveLock &source) :
      mLock(source.mLock)
    {
    }

    //-------------------------------------------------------------------------
    SharedRecursiveLock::SharedRecursiveLock(RecursiveLockPtr shared) : 
      mLock(shared)
    {
    }

    //-------------------------------------------------------------------------
    SharedRecursiveLock::~SharedRecursiveLock()
    {
    }

  }
}




ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::IBackgroundingDelegate)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::IBackgroundingCompletionDelegate)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::IBackOffTimerDelegate)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::IDNSDelegate)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::IHTTPQueryDelegate)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::IICESocketDelegate)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::IICESocketSessionDelegate)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::IMessageLayerSecurityChannelDelegate)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::IReachabilityDelegate)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::IRUDPChannelDelegate)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::IRUDPListenerDelegate)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::IRUDPMessagingDelegate)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::IRUDPTransportDelegate)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::ISTUNDiscoveryDelegate)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::ISTUNRequesterDelegate)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::ITCPMessagingDelegate)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::ITransportStreamWriterDelegate)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::ITransportStreamReaderDelegate)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::ITURNSocketDelegate)


ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::internal::IICESocketForICESocketSession)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::internal::IRUDPChannelDelegateForSessionAndListener)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::internal::IRUDPChannelStreamAsync)
ZS_DECLARE_PROXY_IMPLEMENT(ortc::services::internal::IRUDPChannelStreamDelegate)

ZS_DECLARE_PROXY_SUBSCRIPTIONS_IMPLEMENT(ortc::services::IBackOffTimerDelegate, ortc::services::IBackOffTimerSubscription)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_IMPLEMENT(ortc::services::IBackgroundingDelegate, ortc::services::IBackgroundingSubscription)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_IMPLEMENT(ortc::services::IICESocketDelegate, ortc::services::IICESocketSubscription)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_IMPLEMENT(ortc::services::IICESocketSessionDelegate, ortc::services::IICESocketSessionSubscription)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_IMPLEMENT(ortc::services::IMessageLayerSecurityChannelDelegate, ortc::services::IMessageLayerSecurityChannelSubscription)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_IMPLEMENT(ortc::services::IRUDPTransportDelegate, ortc::services::IRUDPTransportSubscription)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_IMPLEMENT(ortc::services::IReachabilityDelegate, ortc::services::IReachabilitySubscription)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_IMPLEMENT(ortc::services::ITCPMessagingDelegate, ortc::services::ITCPMessagingSubscription)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_IMPLEMENT(ortc::services::ITransportStreamWriterDelegate, ortc::services::ITransportStreamWriterSubscription)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_IMPLEMENT(ortc::services::ITransportStreamReaderDelegate, ortc::services::ITransportStreamReaderSubscription)
