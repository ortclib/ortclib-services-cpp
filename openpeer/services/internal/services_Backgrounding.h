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

#include <openpeer/services/IBackgrounding.h>
#include <openpeer/services/internal/types.h>

namespace openpeer
{
  namespace services
  {
    namespace internal
    {
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark Cache
      #pragma mark

      class Backgrounding : public IBackgrounding
      {
      public:
        friend interaction IBackgrounding;

        ZS_DECLARE_CLASS_PTR(Notifier)

      protected:
        Backgrounding();

      public:
        ~Backgrounding();

      protected:
        static BackgroundingPtr convert(IBackgroundingPtr backgrounding);

        static BackgroundingPtr create();
        static BackgroundingPtr singleton();

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark Backgrounding => IBackgrounding
        #pragma mark

        static ElementPtr toDebug(BackgroundingPtr backgrounding);

        virtual IBackgroundingSubscriptionPtr subscribe(IICESocketDelegatePtr delegate);

        virtual IBackgroundingQueryPtr notifyGoingToBackground(
                                                               IBackgroundingCompletionDelegatePtr readyDelegate = IBackgroundingCompletionDelegatePtr()
                                                               );

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark Backgrounding => (internal)
        #pragma mark

        Log::Params log(const char *message) const;

      public:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark Backgrounding::Notifier
        #pragma mark

        class Notifier : public IBackgroundingNotifier
        {
        protected:
          Notifier(PUID notifierID);

        protected:
          //-------------------------------------------------------------------
          #pragma mark
          #pragma mark Backgrounding::Notifier
          #pragma mark
          virtual void ready();

        protected:
          BackgroundingPtr mOuter;

          AutoBool mNotified;
          PUID mBackgroundingID;
        };

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark Backgrounding => (data)
        #pragma mark

        mutable RecursiveLock mLock;
        AutoPUID mID;
        BackgroundingWeakPtr mThisWeak;

        IBackgroundingDelegateSubscriptions mSubscriptions;

        PUID mCurrentBackgroundingID;
        IBackgroundingCompletionDelegatePtr mNotifyWhenReady;
      };
    }
  }
}
