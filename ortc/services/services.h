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

#include <ortc/services/types.h>
#include <ortc/services/IBackgrounding.h>
#include <ortc/services/IBackOffTimer.h>
#include <ortc/services/IBackOffTimerPattern.h>
#include <ortc/services/ICache.h>
#include <ortc/services/ICanonicalXML.h>
#include <ortc/services/IDecryptor.h>
#include <ortc/services/IDHKeyDomain.h>
#include <ortc/services/IDHPrivateKey.h>
#include <ortc/services/IDHPublicKey.h>
#include <ortc/services/IDNS.h>
#include <ortc/services/IEncryptor.h>
#include <ortc/services/IHelper.h>
#include <ortc/services/IHTTP.h>
#include <ortc/services/IICESocket.h>
#include <ortc/services/IICESocketSession.h>
#include <ortc/services/ILogger.h>
#include <ortc/services/IMessageLayerSecurityChannel.h>
#include <ortc/services/IMessageQueueManager.h>
#include <ortc/services/IReachability.h>
#include <ortc/services/IRSAPrivateKey.h>
#include <ortc/services/IRSAPublicKey.h>
#include <ortc/services/IRUDPChannel.h>
#include <ortc/services/IRUDPListener.h>
#include <ortc/services/IRUDPMessaging.h>
#include <ortc/services/IRUDPTransport.h>
#include <ortc/services/ISettings.h>
#include <ortc/services/ISTUNDiscovery.h>
#include <ortc/services/ISTUNRequester.h>
#include <ortc/services/ISTUNRequesterManager.h>
#include <ortc/services/ITCPMessaging.h>
#include <ortc/services/ITransportStream.h>
#include <ortc/services/ITURNSocket.h>
#include <ortc/services/IWakeDelegate.h>
#include <ortc/services/STUNPacket.h>
#include <ortc/services/RUDPPacket.h>
#include <ortc/services/RUDPProtocol.h>
#include <ortc/services/RUDPProtocol.h>
