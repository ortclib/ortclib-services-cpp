LOCAL_PATH := $(call my-dir)/../../
include $(CLEAR_VARS)

LOCAL_ARM_MODE := arm

LOCAL_CFLAGS	:= -Wall \
-W \
-O2 \
-pipe \
-fPIC \
-frtti \
-fexceptions \
-D_ANDROID \

LOCAL_MODULE    := hfservices_android

LOCAL_C_INCLUDES:= $(LOCAL_PATH) \
$(LOCAL_PATH)/openpeer/services/internal \
$(LOCAL_PATH)/../zsLib \
$(LOCAL_PATH)/../zsLib/internal \
$(LOCAL_PATH)/../cryptopp/projects/android \
$(LOCAL_PATH)/.. \
$(LOCAL_PATH)/../curl/projects/android/curl/include \
$(LOCAL_PATH)/../udns \
$(LOCAL_PATH)/../boost/projects/android/build/include/boost-1_53 \
$(ANDROIDNDK_PATH)/sources/cxx-stl/gnu-libstdc++/4.4.3/include \
$(ANDROIDNDK_PATH)/sources/cxx-stl/gnu-libstdc++/4.4.3/libs/armeabi/include \

LOCAL_SRC_FILES := openpeer/services/cpp/services_CanonicalXML.cpp \
openpeer/services/cpp/services_DNS.cpp \
openpeer/services/cpp/services_DNSMonitor.cpp \
openpeer/services/cpp/services_Factory.cpp \
openpeer/services/cpp/services_Helper.cpp \
openpeer/services/cpp/services_HTTP.cpp \
openpeer/services/cpp/services_ICESocket.cpp \
openpeer/services/cpp/services_ICESocketSession.cpp \
openpeer/services/cpp/services_Logger.cpp \
openpeer/services/cpp/services_MessageLayerSecurityChannel.cpp \
openpeer/services/cpp/services_RSAPrivateKey.cpp \
openpeer/services/cpp/services_RSAPublicKey.cpp \
openpeer/services/cpp/services_RUDPChannel.cpp \
openpeer/services/cpp/services_RUDPChannelStream.cpp \
openpeer/services/cpp/services_RUDPICESocketSession.cpp \
openpeer/services/cpp/services_RUDPListener.cpp \
openpeer/services/cpp/services_RUDPMessaging.cpp \
openpeer/services/cpp/services_RUDPPacket.cpp \
openpeer/services/cpp/services_services.cpp \
openpeer/services/cpp/services_STUNDiscovery.cpp \
openpeer/services/cpp/services_STUNPacket.cpp \
openpeer/services/cpp/services_STUNRequester.cpp \
openpeer/services/cpp/services_STUNRequesterManager.cpp \
openpeer/services/cpp/services_TCPMessaging.cpp \
openpeer/services/cpp/services_TransportStream.cpp \
openpeer/services/cpp/services_TURNSocket.cpp \


include $(BUILD_STATIC_LIBRARY)

