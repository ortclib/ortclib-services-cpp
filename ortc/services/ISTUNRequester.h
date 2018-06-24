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
#include <ortc/services/STUNPacket.h>

#include <zsLib/Proxy.h>

namespace ortc
{
  namespace services
  {
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //
    // ISTUNRequester
    //

    interaction ISTUNRequester
    {
      static ISTUNRequesterPtr create(
                                      IMessageQueuePtr queue,
                                      ISTUNRequesterDelegatePtr delegate,
                                      IPAddress serverIP,
                                      STUNPacketPtr stun,
                                      STUNPacket::RFCs usingRFC,
                                      IBackOffTimerPatternPtr pattern = IBackOffTimerPatternPtr()
                                      ) noexcept;

      //-----------------------------------------------------------------------
      // PURPOSE: This causes a packet (which might be STUN) to be handled
      //          by the STUN requester. This is really a wrapper to
      //          ISTUNRequesterManager::handlePacket.
      static bool handlePacket(
                               IPAddress fromIPAddress,
                               const BYTE *packet,
                               size_t packetLengthInBytes,
                               const STUNPacket::ParseOptions &options
                               ) noexcept;

      //-----------------------------------------------------------------------
      // PURPOSE: This causes a STUN packet to be handled
      //          by the STUN requester. This is really a wrapper to
      //          ISTUNRequesterManager::handleSTUNPacket.
      static bool handleSTUNPacket(
                                   IPAddress fromIPAddress,
                                   STUNPacketPtr stun
                                   ) noexcept;

      virtual PUID getID() const noexcept = 0;

      virtual bool isComplete() const noexcept = 0;

      virtual void cancel() noexcept = 0;

      virtual void retryRequestNow() noexcept = 0;

      virtual IPAddress getServerIP() const noexcept = 0;
      virtual STUNPacketPtr getRequest() const noexcept = 0;

      virtual IBackOffTimerPatternPtr getBackOffTimerPattern() const noexcept = 0;

      virtual size_t getTotalTries() const noexcept = 0;
    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //
    // ISTUNRequesterDelegate
    //

    interaction ISTUNRequesterDelegate
    {
      typedef services::ISTUNRequesterPtr ISTUNRequesterPtr;
      typedef services::STUNPacketPtr STUNPacketPtr;

      //-----------------------------------------------------------------------
      // PURPOSE: Requests that a STUN packet be sent over the wire.
      virtual void onSTUNRequesterSendPacket(
                                             ISTUNRequesterPtr requester,
                                             IPAddress destination,
                                             SecureByteBlockPtr packet
                                             ) = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Notifies that we believe we have a STUN packet response
      //          for the request but not absolutely positive
      // RETURNS: Return true only if the response is a valid response to the
      //          request otherwise return false.
      virtual bool handleSTUNRequesterResponse(
                                               ISTUNRequesterPtr requester,
                                               IPAddress fromIPAddress,
                                               STUNPacketPtr response
                                               ) noexcept = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Notifies that a STUN discovery is now complete.
      virtual void onSTUNRequesterTimedOut(ISTUNRequesterPtr requester) = 0;
    };
  }
}

ZS_DECLARE_PROXY_BEGIN(ortc::services::ISTUNRequesterDelegate)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::ISTUNRequesterPtr, ISTUNRequesterPtr)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::STUNPacketPtr, STUNPacketPtr)
ZS_DECLARE_PROXY_TYPEDEF(ortc::services::SecureByteBlockPtr, SecureByteBlockPtr)
ZS_DECLARE_PROXY_METHOD(onSTUNRequesterSendPacket, ISTUNRequesterPtr, IPAddress, SecureByteBlockPtr)
ZS_DECLARE_PROXY_METHOD_SYNC_RETURN(handleSTUNRequesterResponse, bool, ISTUNRequesterPtr, IPAddress, STUNPacketPtr)
ZS_DECLARE_PROXY_METHOD(onSTUNRequesterTimedOut, ISTUNRequesterPtr)
ZS_DECLARE_PROXY_END()
