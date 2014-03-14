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
      #pragma mark Backgrounding
      #pragma mark

      class Backgrounding : public IBackgrounding
      {
      public:
        friend interaction IBackgroundingFactory;
        friend interaction IBackgrounding;

        ZS_DECLARE_CLASS_PTR(Notifier)
        ZS_DECLARE_CLASS_PTR(ExchangedNotifier)
        ZS_DECLARE_CLASS_PTR(Query)

        ZS_DECLARE_TYPEDEF_PTR(IBackgroundingDelegateSubscriptions, UseBackgroundingDelegateSubscriptions)

        typedef ULONG Phase;
        typedef std::map<Phase, UseBackgroundingDelegateSubscriptionsPtr> PhaseSubscriptionMap;

        friend class Notifier;
        friend class Query;

      protected:
        Backgrounding();

        static BackgroundingPtr create();

      public:
        ~Backgrounding();

      public:
        static BackgroundingPtr convert(IBackgroundingPtr backgrounding);

        static BackgroundingPtr singleton();

        static IBackgroundingNotifierPtr getBackgroundingNotifier(IBackgroundingNotifierPtr notifier);

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark Backgrounding => IBackgrounding
        #pragma mark

        static ElementPtr toDebug(BackgroundingPtr backgrounding);

        virtual IBackgroundingSubscriptionPtr subscribe(
                                                        IBackgroundingDelegatePtr delegate,
                                                        ULONG phase
                                                        );

        virtual IBackgroundingQueryPtr notifyGoingToBackground(
                                                               IBackgroundingCompletionDelegatePtr readyDelegate = IBackgroundingCompletionDelegatePtr()
                                                               );

        virtual void notifyGoingToBackgroundNow();

        virtual void notifyReturningFromBackground();

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark Backgrounding => friend Notifier
        #pragma mark

        void notifyReady(PUID backgroundingID);
        RecursiveLock &getLock() const {return mLock;}

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark Backgrounding => friend Query
        #pragma mark

        virtual size_t totalPending(PUID backgroundingID) const;

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark Backgrounding => (internal)
        #pragma mark

        Log::Params log(const char *message) const;
        static Log::Params slog(const char *message);
        Log::Params debug(const char *message) const;

        virtual ElementPtr toDebug() const;

        size_t getPreviousPhase(Phase &ioPreviousPhase);
        size_t getNextPhase(Phase &ioNextPhase);
        void performGoingToBackground();

      public:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark Backgrounding::Notifier
        #pragma mark

        class Notifier : public IBackgroundingNotifier
        {
        protected:
          Notifier(ExchangedNotifierPtr notifier);

        public:
          ~Notifier();

          static NotifierPtr create(ExchangedNotifierPtr notifier);

        protected:
          //-------------------------------------------------------------------
          #pragma mark
          #pragma mark Backgrounding::Notifier => IBackgroundingNotifier
          #pragma mark

          virtual PUID getID() const {return mBackgroundingID;}

          virtual void ready();

        protected:
          BackgroundingPtr mOuter;

          AutoBool mNotified;
          PUID mBackgroundingID;
        };

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark Backgrounding::ExchangedNotifier
        #pragma mark

        class ExchangedNotifier : public IBackgroundingNotifier
        {
        public:
          friend class Backgrounding;
          friend class Notifier;

        protected:
          ExchangedNotifier(
                            BackgroundingPtr outer,
                            PUID backgroundingID
                            ) :
            mOuter(outer),
            mBackgroundingID(backgroundingID)
          {}

        public:
          static ExchangedNotifierPtr create(
                                             BackgroundingPtr outer,
                                             PUID backgroundingID
                                             );

        protected:
          //-------------------------------------------------------------------
          #pragma mark
          #pragma mark Backgrounding::ExchangedNotifier => IBackgroundingNotifier
          #pragma mark

          virtual PUID getID() const {return mBackgroundingID;}

          virtual void ready() {}

          //-------------------------------------------------------------------
          #pragma mark
          #pragma mark Backgrounding::ExchangedNotifier => friend Backgrounding / Notifier
          #pragma mark

          BackgroundingPtr getOuter() const {return mOuter;}

        protected:
          BackgroundingPtr mOuter;

          PUID mBackgroundingID;
        };

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark Backgrounding::Query
        #pragma mark

        class Query : public IBackgroundingQuery
        {
        protected:
          Query(
                BackgroundingPtr outer,
                PUID backgroundingID
                ) :
          mOuter(outer),
          mBackgroundingID(backgroundingID)
        {}

        public:
          static QueryPtr create(
                                 BackgroundingPtr outer,
                                 PUID backgroundingID
                                 );

        protected:
          //-------------------------------------------------------------------
          #pragma mark
          #pragma mark Backgrounding::Query => IBackgroundingQuery
          #pragma mark

          virtual PUID getID() const {return mBackgroundingID;}

          virtual bool isReady() const;

          virtual size_t totalBackgroundingSubscribersStillPending() const;

        protected:
          mutable RecursiveLock mBogusLock;

          PUID mBackgroundingID;
          BackgroundingWeakPtr mOuter;
        };

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark Backgrounding => (data)
        #pragma mark

        mutable RecursiveLock mLock;
        AutoPUID mID;
        BackgroundingWeakPtr mThisWeak;

        Phase mLargestPhase;

        PhaseSubscriptionMap mPhaseSubscriptions;

        PUID mCurrentBackgroundingID;
        Phase mCurrentPhase;
        size_t mTotalWaiting;
        IBackgroundingCompletionDelegatePtr mNotifyWhenReady;
        QueryPtr mQuery;

        size_t mTotalNotifiersCreated;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IBackgroundingFactory
      #pragma mark

      interaction IBackgroundingFactory
      {
        static IBackgroundingFactory &singleton();

        virtual BackgroundingPtr createForBackgrounding();
      };

    }
  }
}
