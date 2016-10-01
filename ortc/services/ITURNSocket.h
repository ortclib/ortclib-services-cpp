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
#include <ortc/services/IDNS.h>

#include <zsLib/types.h>
#include <zsLib/IPAddress.h>
#include <zsLib/Proxy.h>

#define OPENPEER_SERVICES_TURN_CHANNEL_RANGE_START (0x4000)                    // the actual range is 0x4000 -> 0x7FFF but to prevent collision with RUDP this is a recommended range to use
#define OPENPEER_SERVICES_TURN_CHANNEL_RANGE_END   (0x5FFF)

namespace openpeer
{
  namespace services
  {
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark ITURNSocket
    #pragma mark

    interaction ITURNSocket
    {
      typedef String URI;
      typedef std::list<URI> URIList;

      enum TURNSocketStates
      {
        TURNSocketState_Pending,
        TURNSocketState_Ready,
        TURNSocketState_ShuttingDown,
        TURNSocketState_Shutdown,
      };
      static const char *toString(TURNSocketStates state);

      enum TURNSocketErrors
      {
        TURNSocketError_None,
        TURNSocketError_UserRequestedShutdown,
        TURNSocketError_DNSLookupFailure,
        TURNSocketError_FailedToConnectToAnyServer,
        TURNSocketError_RefreshTimeout,
        TURNSocketError_UnexpectedSocketFailure,
        TURNSocketError_BogusDataOnSocketReceived,
      };
      static const char *toString(TURNSocketErrors error);

      struct CreationOptions
      {
        URIList mServers;
        IDNS::SRVResultPtr mSRVUDP;
        IDNS::SRVResultPtr mSRVTCP;
        String mUsername;
        String mPassword;
        IDNS::SRVLookupTypes mLookupType {IDNS::SRVLookupType_AutoLookupAndFallbackAll};
        bool mUseChannelBinding {false};
        WORD mLimitChannelToRangeStart {OPENPEER_SERVICES_TURN_CHANNEL_RANGE_START};
        WORD mLimitChannelToRangeEnd {OPENPEER_SERVICES_TURN_CHANNEL_RANGE_END};
      };

      static ITURNSocketPtr create(
                                   IMessageQueuePtr queue,
                                   ITURNSocketDelegatePtr delegate,
                                   const CreationOptions &options
                                   );

      static ElementPtr toDebug(ITURNSocketPtr socket);

      virtual PUID getID() const = 0;

      virtual TURNSocketStates getState() const = 0;
      virtual TURNSocketErrors getLastError() const = 0;

      virtual bool isRelayingUDP() const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Shutdown the the TURN session
      virtual void shutdown() = 0;

      virtual bool sendPacket(
                              IPAddress destination,
                              const BYTE *buffer,
                              size_t bufferLengthInBytes,
                              bool bindChannelIfPossible = false
                              ) = 0;

      virtual IPAddress getActiveServerIP() const = 0;
      virtual IPAddress getRelayedIP() const = 0;
      virtual IPAddress getReflectedIP() const = 0;
      virtual IPAddress getServerResponseIP() const = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Tells the TURN socket that it has a packet that it must
      //          handle.
      // RETURNS: True if the TURN packet was a TURN packet meant to be
      //          handled by this object otherwise false.
      virtual bool handleSTUNPacket(
                                    IPAddress fromIPAddress,
                                    STUNPacketPtr turnPacket
                                    ) = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Tells the TURN socket that it has a packet that might be
      //          channel data that it should handle.
      // RETURNS: True if the TURN packet was handled otherwise false if this
      //          is not meant to be a TURN packet.
      virtual bool handleChannelData(
                                     IPAddress fromIPAddress,
                                     const BYTE *buffer,
                                     size_t bufferLengthInBytes
                                     ) = 0;


      //-----------------------------------------------------------------------
      // PURPOSE: Tells the TURN socket that the write ready flag is available
      //          on the delegate (e.g. UDP socket is available for writing)
      virtual void notifyWriteReady() = 0;
    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark ITURNSocketDelegate
    #pragma mark

    interaction ITURNSocketDelegate
    {
      typedef services::ITURNSocketPtr ITURNSocketPtr;
      typedef ITURNSocket::TURNSocketStates TURNSocketStates;

      //-----------------------------------------------------------------------
      // PURPOSE: Notify that the TURN socket state has changed from the
      //          previous state.
      virtual void onTURNSocketStateChanged(
                                            ITURNSocketPtr socket,
                                            TURNSocketStates state
                                            ) = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Notify that the TURN socket received data which is intended
      //          for the delegate to process.
      virtual void handleTURNSocketReceivedPacket(
                                                  ITURNSocketPtr socket,
                                                  IPAddress source,
                                                  const BYTE *packet,
                                                  size_t packetLengthInBytes
                                                  ) = 0;

      //-----------------------------------------------------------------------
      // PURPOSE: Request that the delegate send a packet on behalf of the
      //          TURN socket to the requested destination.
      virtual bool notifyTURNSocketSendPacket(
                                              ITURNSocketPtr socket,
                                              IPAddress destination,
                                              const BYTE *packet,
                                              size_t packetLengthInBytes
                                              ) = 0;

      virtual void onTURNSocketWriteReady(ITURNSocketPtr socket) = 0;
    };
  }
}

ZS_DECLARE_PROXY_BEGIN(openpeer::services::ITURNSocketDelegate)
ZS_DECLARE_PROXY_TYPEDEF(openpeer::services::ITURNSocketPtr, ITURNSocketPtr)
ZS_DECLARE_PROXY_TYPEDEF(openpeer::services::ITURNSocketDelegate::TURNSocketStates, TURNSocketStates)
ZS_DECLARE_PROXY_METHOD_2(onTURNSocketStateChanged, ITURNSocketPtr, TURNSocketStates)
ZS_DECLARE_PROXY_METHOD_SYNC_4(handleTURNSocketReceivedPacket, ITURNSocketPtr, IPAddress, const BYTE *, size_t)
ZS_DECLARE_PROXY_METHOD_SYNC_RETURN_4(notifyTURNSocketSendPacket, bool, ITURNSocketPtr, IPAddress, const BYTE *, size_t)
ZS_DECLARE_PROXY_METHOD_1(onTURNSocketWriteReady, openpeer::services::ITURNSocketPtr)
ZS_DECLARE_PROXY_END()
