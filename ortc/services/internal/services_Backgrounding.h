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

#include <ortc/services/IBackgrounding.h>
#include <ortc/services/internal/types.h>

#include <zsLib/ITimer.h>

#define ORTC_STACK_SETTING_BACKGROUNDING_PHASE_TIMEOUT "ortc/services/backgrounding-phase-$phase$-timeout-in-seconds"

namespace ortc
{
  namespace services
  {
    namespace internal
    {
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // Backgrounding
      //

      class Backgrounding : public MessageQueueAssociator,
                            public SharedRecursiveLock,
                            public IBackgrounding,
                            public ITimerDelegate
      {
      protected:
        struct make_private {};

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

      public:
        Backgrounding(const make_private &) noexcept;

      protected:
        static BackgroundingPtr create() noexcept;

      public:
        ~Backgrounding() noexcept;

      public:
        static BackgroundingPtr convert(IBackgroundingPtr backgrounding) noexcept;

        static BackgroundingPtr singleton() noexcept;

        static IBackgroundingNotifierPtr getBackgroundingNotifier(IBackgroundingNotifierPtr notifier) noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // Backgrounding => IBackgrounding
        //

        static ElementPtr toDebug(BackgroundingPtr backgrounding) noexcept;

        virtual IBackgroundingSubscriptionPtr subscribe(
                                                        IBackgroundingDelegatePtr delegate,
                                                        ULONG phase
                                                        ) noexcept;

        virtual IBackgroundingQueryPtr notifyGoingToBackground(
                                                               IBackgroundingCompletionDelegatePtr readyDelegate = IBackgroundingCompletionDelegatePtr()
                                                               ) noexcept;

        virtual void notifyGoingToBackgroundNow() noexcept;

        virtual void notifyReturningFromBackground() noexcept;

        //---------------------------------------------------------------------
        //
        // Backgrounding => ITimerDelegate
        //

        virtual void onTimer(ITimerPtr timer);

        //---------------------------------------------------------------------
        //
        // Backgrounding => friend Notifier
        //

        void notifyReady(
                         PUID backgroundingID,
                         Phase phase
                         ) noexcept;

        //---------------------------------------------------------------------
        //
        // Backgrounding => friend Query
        //

        virtual size_t totalPending(PUID backgroundingID) const noexcept;

        //---------------------------------------------------------------------
        //
        // Backgrounding => friend GracefulAlert
        //

        virtual void notifyApplicationWillQuit() noexcept;

      protected:
        //---------------------------------------------------------------------
        //
        // Backgrounding => (internal)
        //

        Log::Params log(const char *message) const noexcept;
        static Log::Params slog(const char *message) noexcept;
        Log::Params debug(const char *message) const noexcept;

        virtual ElementPtr toDebug() const noexcept;

        size_t getPreviousPhase(Phase &ioPreviousPhase) noexcept;
        size_t getNextPhase(Phase &ioNextPhase) noexcept;
        void performGoingToBackground() noexcept;

      public:
        //---------------------------------------------------------------------
        //
        // Backgrounding::Notifier
        //

        class Notifier : public SharedRecursiveLock,
                         public IBackgroundingNotifier
        {
        protected:
          struct make_private {};

        public:
          Notifier(
                   const make_private &,
                   ExchangedNotifierPtr notifier
                   ) noexcept;

        public:
          ~Notifier() noexcept;

          static NotifierPtr create(ExchangedNotifierPtr notifier) noexcept;

        protected:
          //-------------------------------------------------------------------
          //
          // Backgrounding::Notifier => IBackgroundingNotifier
          //

          virtual PUID getID() const noexcept {return mBackgroundingID;}

          virtual void ready() noexcept;

        protected:
          BackgroundingPtr mOuter;

          bool mNotified {};
          PUID mBackgroundingID;
          Phase mPhase;
        };

        //---------------------------------------------------------------------
        //
        // Backgrounding::ExchangedNotifier
        //

        class ExchangedNotifier : public SharedRecursiveLock,
                                  public IBackgroundingNotifier
        {
        protected:
          struct make_private {};

        public:
          friend class Backgrounding;
          friend class Notifier;

        public:
          ExchangedNotifier(
                            const make_private &,
                            BackgroundingPtr outer,
                            PUID backgroundingID,
                            Phase phase
                            ) noexcept :
            SharedRecursiveLock(*outer),
            mOuter(outer),
            mBackgroundingID(backgroundingID),
            mPhase(phase)
          {}

        public:
          static ExchangedNotifierPtr create(
                                             BackgroundingPtr outer,
                                             PUID backgroundingID,
                                             Phase phase
                                             ) noexcept;

        protected:
          //-------------------------------------------------------------------
          //
          // Backgrounding::ExchangedNotifier => IBackgroundingNotifier
          //

          virtual PUID getID() const noexcept {return mBackgroundingID;}

          virtual void ready() noexcept {}

          //-------------------------------------------------------------------
          //
          // Backgrounding::ExchangedNotifier => friend Backgrounding / Notifier
          //

          BackgroundingPtr getOuter() const noexcept {return mOuter;}
          Phase getPhase() const noexcept {return mPhase;}

        protected:
          BackgroundingPtr mOuter;

          PUID mBackgroundingID;
          Phase mPhase;
        };

        //---------------------------------------------------------------------
        //
        // Backgrounding::Query
        //

        class Query : public SharedRecursiveLock,
                      public IBackgroundingQuery
        {
        protected:
          struct make_private {};

        public:
          Query(
                const make_private &,
                BackgroundingPtr outer,
                PUID backgroundingID
                ) noexcept :
          SharedRecursiveLock(*outer),
          mOuter(outer),
          mBackgroundingID(backgroundingID)
        {}

        public:
          static QueryPtr create(
                                 BackgroundingPtr outer,
                                 PUID backgroundingID
                                 ) noexcept;

        protected:
          //-------------------------------------------------------------------
          //
          // Backgrounding::Query => IBackgroundingQuery
          //

          virtual PUID getID() const noexcept {return mBackgroundingID;}

          virtual bool isReady() const noexcept;

          virtual size_t totalBackgroundingSubscribersStillPending() const noexcept;

        protected:
          BackgroundingWeakPtr mOuter;
          PUID mBackgroundingID;
        };

      protected:
        //---------------------------------------------------------------------
        //
        // Backgrounding => (data)
        //

        AutoPUID mID;
        BackgroundingWeakPtr mThisWeak;

        Phase mLargestPhase {};

        PhaseSubscriptionMap mPhaseSubscriptions;

        PUID mCurrentBackgroundingID;
        Phase mCurrentPhase {};
        size_t mTotalWaiting {};
        IBackgroundingCompletionDelegatePtr mNotifyWhenReady;
        QueryPtr mQuery;

        size_t mTotalNotifiersCreated {};

        ITimerPtr mTimer;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //
      // IBackgroundingFactory
      //

      interaction IBackgroundingFactory
      {
        static IBackgroundingFactory &singleton() noexcept;

        virtual BackgroundingPtr createForBackgrounding() noexcept;
      };

      class BackgroundingFactory : public IFactory<IBackgroundingFactory> {};

    }
  }
}
