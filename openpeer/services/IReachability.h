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

#include <openpeer/services/types.h>

namespace openpeer
{
  namespace services
  {
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IReachability
    #pragma mark

    interaction IReachability
    {
      enum InterfaceTypes
      {
        InterfaceType_None      = 0x00000000,

        InterfaceType_LAN       = 0x00000001, // aka ethernet
        InterfaceType_WLAN      = 0x00000010, // aka wifi
        InterfaceType_WWAN      = 0x00000020, // aka 3G / 4G
        InterfaceType_VPN       = 0x00000100,
        InterfaceType_PAN       = 0x00000200,
        InterfaceType_Other     = 0x00001000,
      };

      static String toString(InterfaceTypes interfaceTypes);

      //-----------------------------------------------------------------------
      // PURPOSE: returns a debug element containing internal object state
      static ElementPtr toDebug();

      //-----------------------------------------------------------------------
      // PURPOSE: Subscribe to the reachability state
      static IReachabilitySubscriptionPtr subscribe(IReachabilityDelegatePtr delegate);


      //-----------------------------------------------------------------------
      // PURPOSE: Indicate the subscribers the network reachability state
      // PARAMS:  interfaceTypes - which networks are reachable
      static void notifyReachability(InterfaceTypes interfaceTypes);

      virtual ~IReachability() {}  // needed to ensure virtual table is created in order to use dynamic cast
    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IReachabilityDelegate
    #pragma mark

    interaction IReachabilityDelegate
    {
      typedef IReachability::InterfaceTypes InterfaceTypes;

      //-----------------------------------------------------------------------
      // PURPOSE: This is notification from the system that the reachability of
      //          a network has changed.
      virtual void onReachabilityChanged(
                                         IReachabilitySubscriptionPtr subscription,
                                         InterfaceTypes interfaceTypes
                                         ) = 0;
    };

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark IReachabilitySubscription
    #pragma mark

    interaction IReachabilitySubscription
    {
      virtual PUID getID() const = 0;

      virtual void cancel() = 0;

      virtual void background() = 0;
    };
  }
}

ZS_DECLARE_PROXY_BEGIN(openpeer::services::IReachabilityDelegate)
ZS_DECLARE_PROXY_TYPEDEF(openpeer::services::IReachabilitySubscriptionPtr, IReachabilitySubscriptionPtr)
ZS_DECLARE_PROXY_TYPEDEF(openpeer::services::IReachabilityDelegate::InterfaceTypes, InterfaceTypes)
ZS_DECLARE_PROXY_METHOD_2(onReachabilityChanged, IReachabilitySubscriptionPtr, InterfaceTypes)
ZS_DECLARE_PROXY_END()

ZS_DECLARE_PROXY_SUBSCRIPTIONS_BEGIN(openpeer::services::IReachabilityDelegate, openpeer::services::IReachabilitySubscription)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(openpeer::services::IReachabilitySubscriptionPtr, IReachabilitySubscriptionPtr)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_TYPEDEF(openpeer::services::IReachabilityDelegate::InterfaceTypes, InterfaceTypes)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_METHOD_2(onReachabilityChanged, IReachabilitySubscriptionPtr, InterfaceTypes)
ZS_DECLARE_PROXY_SUBSCRIPTIONS_END()
