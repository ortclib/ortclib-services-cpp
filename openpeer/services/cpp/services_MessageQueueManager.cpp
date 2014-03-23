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

#include <openpeer/services/internal/services_MessageQueueManager.h>
#include <openpeer/services/IHelper.h>
#include <openpeer/services/ISettings.h>

#include <zsLib/Log.h>
#include <zsLib/XML.h>

#define OPENPEER_SERVICES_MESSAGE_QUEUE_MANAGER_RESERVED_GUI_THREAD_NAME "c745461ccd5bfd8427beeda5f952dc68fb09668a_openpeer.services.guiThread"

namespace openpeer { namespace services { ZS_DECLARE_SUBSYSTEM(openpeer_services) } }

namespace openpeer
{
  namespace services
  {
    namespace internal
    {
      ZS_DECLARE_USING_PTR(zsLib::XML, Element)
      ZS_DECLARE_USING_PTR(zsLib, IMessageQueueThread)

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark (helpers)
      #pragma mark

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark MessageQueueManager
      #pragma mark

      //-----------------------------------------------------------------------
      void IMessageQueueManagerForBackgrounding::blockUntilDone()
      {
        MessageQueueManagerPtr singleton = MessageQueueManager::singleton();
        if (!singleton) return;
        singleton->blockUntilDone();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark MessageQueueManager
      #pragma mark

      //-----------------------------------------------------------------------
      MessageQueueManager::MessageQueueManager() :
        mPending(0),
        mProcessApplicationQueueOnShutdown(ISettings::getBool(OPENPEER_SERVICES_SETTING_MESSAGE_QUEUE_MANAGER_PROCESS_APPLICATION_MESSAGE_QUEUE_ON_QUIT))
      {
        ZS_LOG_BASIC(log("created"))
      }

      //-----------------------------------------------------------------------
      void MessageQueueManager::init()
      {
        // AutoRecursiveLock lock(mLock);
      }

      //-----------------------------------------------------------------------
      MessageQueueManagerPtr MessageQueueManager::create()
      {
        MessageQueueManagerPtr pThis(new MessageQueueManager);
        pThis->mThisWeak = pThis;
        pThis->init();
        return pThis;
      }

      //-----------------------------------------------------------------------
      MessageQueueManagerPtr MessageQueueManager::singleton()
      {
        static SingletonLazySharedPtr<MessageQueueManager> singleton(create());
        MessageQueueManagerPtr result = singleton.singleton();

        ZS_DECLARE_CLASS_PTR(GracefulAlert)

        class GracefulAlert
        {
        public:
          GracefulAlert(MessageQueueManagerPtr singleton) : mSingleton(singleton) {}
          ~GracefulAlert() {mSingleton->shutdownAllQueues();}

        protected:
          MessageQueueManagerPtr mSingleton;
        };

        static SingletonLazySharedPtr<GracefulAlert> alertSingleton(GracefulAlertPtr(new GracefulAlert(result)));

        if (!result) {
          ZS_LOG_WARNING(Detail, slog("singleton gone"))
        }

        return result;
      }

      //-----------------------------------------------------------------------
      MessageQueueManager::~MessageQueueManager()
      {
        ZS_LOG_BASIC(log("destroyed"))
        mThisWeak.reset();
        cancel();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark MessageQueueManager => IMessageQueueManager
      #pragma mark

      //-----------------------------------------------------------------------
      IMessageQueuePtr MessageQueueManager::getMessageQueueForGUIThread()
      {
        return getMessageQueue(OPENPEER_SERVICES_MESSAGE_QUEUE_MANAGER_RESERVED_GUI_THREAD_NAME);
      }

      //-----------------------------------------------------------------------
      IMessageQueuePtr MessageQueueManager::getMessageQueue(const char *assignedThreadName)
      {
        AutoRecursiveLock lock(mLock);

        String name(assignedThreadName);

        MessageQueueMap::iterator found = mQueues.find(name);
        if (found != mQueues.end()) {
          ZS_LOG_TRACE(log("re-using existing message queue with name") + ZS_PARAM("name", name))
          return (*found).second;
        }

        IMessageQueuePtr queue;

        // creating new thread
        if (OPENPEER_SERVICES_MESSAGE_QUEUE_MANAGER_RESERVED_GUI_THREAD_NAME == name) {
          ZS_LOG_TRACE(log("creating GUI thread"))
          queue = MessageQueueThread::singletonUsingCurrentGUIThreadsMessageQueue();
        } else {

          ThreadPriorities priority = zsLib::ThreadPriority_NormalPriority;

          ThreadPriorityMap::const_iterator foundPriority = mThreadPriorities.find(name);
          if (foundPriority != mThreadPriorities.end()) {
            priority = (*foundPriority).second;
          }

          ZS_LOG_TRACE(log("creating thread queue") + ZS_PARAM("name", name) + ZS_PARAM("priority", zsLib::toString(priority)))

          queue = MessageQueueThread::createBasic(name, priority);
        }

        mQueues[name] = queue;
        return queue;
      }

      //-----------------------------------------------------------------------
      void MessageQueueManager::registerMessageQueueThreadPriority(
                                                                   const char *assignedThreadName,
                                                                   ThreadPriorities priority
                                                                   )
      {
        AutoRecursiveLock lock(mLock);

        String name(assignedThreadName);
        mThreadPriorities[name] = priority;

        MessageQueueMap::iterator found = mQueues.find(name);
        if (found == mQueues.end()) {
          ZS_LOG_DEBUG(log("message queue specified is not in use at yet") + ZS_PARAM("name", assignedThreadName) + ZS_PARAM("priority", zsLib::toString(priority)))
          return;
        }

        ZS_LOG_DEBUG(log("updating message queue thread") + ZS_PARAM("name", assignedThreadName) + ZS_PARAM("priority", zsLib::toString(priority)))

        ZS_DECLARE_TYPEDEF_PTR(zsLib::IMessageQueueThread, IMessageQueueThread)

        IMessageQueuePtr queue = (*found).second;

        IMessageQueueThreadPtr thread = dynamic_pointer_cast<IMessageQueueThread>(queue);
        if (!thread) {
          ZS_LOG_WARNING(Detail, log("found thread was not recognized as a message queue thread") + ZS_PARAM("name", assignedThreadName))
          return;
        }

        thread->setThreadPriority(priority);
      }

      //-----------------------------------------------------------------------
      IMessageQueueManager::MessageQueueMapPtr MessageQueueManager::getRegisteredQueues()
      {
        AutoRecursiveLock lock(mLock);

        MessageQueueMapPtr result(new MessageQueueMap(mQueues));
        return result;
      }

      //-----------------------------------------------------------------------
      size_t MessageQueueManager::getTotalUnprocessedMessages() const
      {
        AutoRecursiveLock lock(mLock);

        size_t result = 0;

        for (MessageQueueMap::const_iterator iter = mQueues.begin(); iter != mQueues.end(); ++iter) {
          const IMessageQueuePtr &queue = (*iter).second;
          result += queue->getTotalUnprocessedMessages();
        }

        return result;
      }

      //-----------------------------------------------------------------------
      void MessageQueueManager::shutdownAllQueues()
      {
        ZS_LOG_DETAIL(log("shutdown all queues called"))

        AutoRecursiveLock lock(mLock);
        mGracefulShutdownReference = mThisWeak.lock();

        onWake();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark MessageQueueManager => IWakeDelegate
      #pragma mark

      //-----------------------------------------------------------------------
      void MessageQueueManager::onWake()
      {
        AutoRecursiveLock lock(mLock);

        if (!mGracefulShutdownReference) return;

        if (0 != mPending) {
          --mPending;
          return;
        }

        if (mQueues.size() < 1) {
          mGracefulShutdownReference.reset();
          return;
        }

        for (MessageQueueMap::iterator iter = mQueues.begin(); iter != mQueues.end(); ++iter)
        {
          IMessageQueuePtr queue = (*iter).second;

          size_t remaining = queue->getTotalUnprocessedMessages();
          if (0 != remaining) {
            ++mPending;
            IWakeDelegateProxy::create(queue, mThisWeak.lock())->onWake();
          }
          boost::thread::yield();
        }

        if (0 != mPending) {
          get(mFinalCheck) = false;
          return;
        }

        if (0 == mPending) {
          if (!mFinalCheck) {
            get(mFinalCheck) = true;

            // perform one-time double check to truly make sure all queues are empty
            IMessageQueuePtr queue = (*mQueues.begin()).second;

            ++mPending;
            IWakeDelegateProxy::create(queue, mThisWeak.lock())->onWake();
            return;
          }
        }

        // all queue are empty
        cancel();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark MessageQueueManager => IMessageQueueManagerForBackgrounding
      #pragma mark

      //-----------------------------------------------------------------------
      void MessageQueueManager::blockUntilDone()
      {
        bool processApplicationQueueOnShutdown = false;

        MessageQueueMap queues;

        {
          AutoRecursiveLock lock(mLock);
          processApplicationQueueOnShutdown = mProcessApplicationQueueOnShutdown;
          queues = mQueues;
        }

        size_t totalRemaining = 0;

        do
        {

          for (MessageQueueMap::iterator iter = queues.begin(); iter != queues.end(); ++iter)
          {
            const MessageQueueName &name = (*iter).first;
            IMessageQueuePtr queue = (*iter).second;

            if (name == OPENPEER_SERVICES_MESSAGE_QUEUE_MANAGER_RESERVED_GUI_THREAD_NAME) {
              if (!processApplicationQueueOnShutdown)
                continue;

              IMessageQueueThreadPtr thread = dynamic_pointer_cast<IMessageQueueThread>(queue);

              thread->processMessagesFromThread();
            }

            totalRemaining += queue->getTotalUnprocessedMessages();
          }

          if (totalRemaining < 1) {
            break;
          }

          boost::thread::yield();
        } while (totalRemaining > 0);

      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark MessageQueueManager => (internal)
      #pragma mark

      //-----------------------------------------------------------------------
      Log::Params MessageQueueManager::log(const char *message) const
      {
        ElementPtr objectEl = Element::create("services::MessageQueueManager");
        IHelper::debugAppend(objectEl, "id", mID);
        return Log::Params(message, objectEl);
      }

      //-----------------------------------------------------------------------
      Log::Params MessageQueueManager::slog(const char *message)
      {
        return Log::Params(message, "services::MessageQueueManager");
      }

      //-----------------------------------------------------------------------
      Log::Params MessageQueueManager::debug(const char *message) const
      {
        return Log::Params(message, toDebug());
      }

      //-----------------------------------------------------------------------
      ElementPtr MessageQueueManager::toDebug() const
      {
        AutoRecursiveLock lock(mLock);
        ElementPtr resultEl = Element::create("services::MessageQueueManager");

        IHelper::debugAppend(resultEl, "id", mID);
        IHelper::debugAppend(resultEl, "graceful reference", (bool)mGracefulShutdownReference);
        IHelper::debugAppend(resultEl, "final check", mFinalCheck);

        IHelper::debugAppend(resultEl, "total queues", mQueues.size());
        IHelper::debugAppend(resultEl, "total priorities", mThreadPriorities.size());

        return resultEl;
      }

      //-----------------------------------------------------------------------
      void MessageQueueManager::cancel()
      {
        ZS_LOG_DEBUG(log("cancel called"))

        while (true)
        {
          MessageQueueMapPtr queues = getRegisteredQueues();
          if (queues->size() < 1) {
            ZS_LOG_DEBUG(log("all queues are now gone"))
            break;
          }

          for (MessageQueueMap::iterator iter = queues->begin(); iter != queues->end(); ++iter)
          {
            MessageQueueName name = (*iter).first;
            IMessageQueuePtr queue = (*iter).second;

            size_t totalMessagesLeft = queue->getTotalUnprocessedMessages();
            if (totalMessagesLeft > 0) {
              ZS_LOG_WARNING(Basic, log("unprocessed messages are still in the queue - did you check getTotalUnprocessedMessages() to make sure all queues are empty before quiting?"))
            }

            MessageQueueThreadPtr threadQueue = boost::dynamic_pointer_cast<MessageQueueThread>(queue);
            threadQueue->waitForShutdown();

            // scope: remove the queue from the list of managed queues
            {
              AutoRecursiveLock lock(mLock);

              MessageQueueMap::iterator found = mQueues.find(name);
              if (found == mQueues.end()) {
                ZS_LOG_WARNING(Detail, log("message queue was not found in managed list of queues") + ZS_PARAM("name", name))
              }
              mQueues.erase(found);
            }
          }
        }

        mGracefulShutdownReference.reset();
      }

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
    }

    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    //-------------------------------------------------------------------------
    #pragma mark
    #pragma mark services::IMessageQueueManager
    #pragma mark

    //-------------------------------------------------------------------------
    IMessageQueuePtr IMessageQueueManager::getMessageQueueForGUIThread()
    {
      internal::MessageQueueManagerPtr singleton = internal::MessageQueueManager::singleton();
      if (!singleton) return IMessageQueuePtr();
      return singleton->getMessageQueueForGUIThread();
    }

    //-------------------------------------------------------------------------
    IMessageQueuePtr IMessageQueueManager::getMessageQueue(const char *assignedThreadName)
    {
      internal::MessageQueueManagerPtr singleton = internal::MessageQueueManager::singleton();
      if (!singleton) return IMessageQueuePtr();
      return singleton->getMessageQueue(assignedThreadName);
    }

    //-------------------------------------------------------------------------
    void IMessageQueueManager::registerMessageQueueThreadPriority(
                                                                  const char *assignedThreadName,
                                                                  ThreadPriorities priority
                                                                  )
    {
      internal::MessageQueueManagerPtr singleton = internal::MessageQueueManager::singleton();
      if (!singleton) return;
      singleton->registerMessageQueueThreadPriority(assignedThreadName, priority);
    }

    //-------------------------------------------------------------------------
    IMessageQueueManager::MessageQueueMapPtr IMessageQueueManager::getRegisteredQueues()
    {
      internal::MessageQueueManagerPtr singleton = internal::MessageQueueManager::singleton();
      if (!singleton) return IMessageQueueManager::MessageQueueMapPtr(new IMessageQueueManager::MessageQueueMap);
      return singleton->getRegisteredQueues();
    }

    //-------------------------------------------------------------------------
    size_t IMessageQueueManager::getTotalUnprocessedMessages()
    {
      internal::MessageQueueManagerPtr singleton = internal::MessageQueueManager::singleton();
      if (!singleton) return 0;
      return singleton->getTotalUnprocessedMessages();
    }

    //-------------------------------------------------------------------------
    void IMessageQueueManager::shutdownAllQueues()
    {
      internal::MessageQueueManagerPtr singleton = internal::MessageQueueManager::singleton();
      if (!singleton) return;
      singleton->shutdownAllQueues();
    }
  }
}
