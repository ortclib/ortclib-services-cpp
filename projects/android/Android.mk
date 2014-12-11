LOCAL_PATH := $(call my-dir)/../../
include $(CLEAR_VARS)

LOCAL_ARM_MODE := arm
LOCAL_CLANG := true

LOCAL_CFLAGS	:= -Wall \
-W \
-O2 \
-pipe \
-fPIC \
-frtti \
-fexceptions \
-fpermissive \
-D_ANDROID \

LOCAL_CPPFLAGS += -std=c++11

LOCAL_MODULE    := hfservices_android

LOCAL_EXPORT_C_INCLUDES:= $(LOCAL_PATH) \

LOCAL_C_INCLUDES:= $(LOCAL_PATH) \
$(LOCAL_PATH)/openpeer/services/internal \
$(LOCAL_PATH)../zsLib \
$(LOCAL_PATH)../zsLib/zsLib/extras \
$(LOCAL_PATH)../zsLib/zsLib/internal \
$(LOCAL_PATH)../idnkit/idnkit/include \
$(LOCAL_PATH)/../build/android/cryptopp/include \
$(LOCAL_PATH)/.. \
$(LOCAL_PATH)/../build/android/curl/include \
$(LOCAL_PATH)/../udns \
$(ANDROIDNDK_PATH)/sources/android/support/include \
$(ANDROIDNDK_PATH)/sources/cxx-stl/llvm-libc++/libcxx/include \
$(ANDROIDNDK_PATH)/platforms/android-19/arch-arm/usr/include \

LOCAL_SRC_FILES := openpeer/services/cpp/services_Backgrounding.cpp \
openpeer/services/cpp/services_Cache.cpp \
openpeer/services/cpp/services_CanonicalXML.cpp \
openpeer/services/cpp/services_DHKeyDomain.cpp \
openpeer/services/cpp/services_DHPrivateKey.cpp \
openpeer/services/cpp/services_DHPublicKey.cpp \
openpeer/services/cpp/services_DNS.cpp \
openpeer/services/cpp/services_DNSMonitor.cpp \
openpeer/services/cpp/services_Decryptor.cpp \
openpeer/services/cpp/services_Encryptor.cpp \
openpeer/services/cpp/services_HTTP.cpp \
openpeer/services/cpp/services_Helper.cpp \
openpeer/services/cpp/ifaddrs-android.cc \
openpeer/services/cpp/services_ICESocket.cpp \
openpeer/services/cpp/services_ICESocketSession.cpp \
openpeer/services/cpp/services_Logger.cpp \
openpeer/services/cpp/services_MessageLayerSecurityChannel.cpp \
openpeer/services/cpp/services_MessageQueueManager.cpp \
openpeer/services/cpp/services_RSAPrivateKey.cpp \
openpeer/services/cpp/services_RSAPublicKey.cpp \
openpeer/services/cpp/services_RUDPChannel.cpp \
openpeer/services/cpp/services_RUDPChannelStream.cpp \
openpeer/services/cpp/services_RUDPListener.cpp \
openpeer/services/cpp/services_RUDPMessaging.cpp \
openpeer/services/cpp/services_RUDPPacket.cpp \
openpeer/services/cpp/services_RUDPTransport.cpp \
openpeer/services/cpp/services_Reachability.cpp \
openpeer/services/cpp/services_STUNDiscovery.cpp \
openpeer/services/cpp/services_STUNPacket.cpp \
openpeer/services/cpp/services_STUNRequester.cpp \
openpeer/services/cpp/services_STUNRequesterManager.cpp \
openpeer/services/cpp/services_Settings.cpp \
openpeer/services/cpp/services_TCPMessaging.cpp \
openpeer/services/cpp/services_TURNSocket.cpp \
openpeer/services/cpp/services_TransportStream.cpp \
openpeer/services/cpp/services_services.cpp \
openpeer/services/cpp/services_wire.cpp \




include $(BUILD_STATIC_LIBRARY)

