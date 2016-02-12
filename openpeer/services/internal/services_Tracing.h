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

#include <openpeer/services/internal/types.h>


#ifdef USE_ETW
#include "services_ETWTracing.h"
#else

// Comment the following line to test inline versions of the same macros to test compilation
#define OPENPEER_SERVICES_USE_NOOP_EVENT_TRACE_MACROS

// NO-OP VERSIONS OF ALL TRACING MACROS
#ifdef OPENPEER_SERVICES_USE_NOOP_EVENT_TRACE_MACROS

#define EventWriteOpServices(xStr_Method)

#define EventWriteOpServicesStunPacket(xStr_Method, xStr_Message, xStr_Log, xPUID_ObjectID, xUInt_Class, xUInt_Method, xULONG_TotalRetries, xWORD_ErrorCode, xStr_Reason, xDWORD_MagicCookies, xPtr_TransactionIDBuffer, xsize_t_TransactionBufferLengthInBytes, xsize_t_TotalUnknownAttributes, xWORD_FirstUnknownAttribute, xStr_MappedAddressIP, xStr_AlternateServerIP, xStr_Username, xStr_Password, xStr_Realm, xStr_Nonce, xStr_Software, xUInt_CredentialMechanism, xsize_t_MessageIntegrityMessageLengthInBytes, xPtr_MessageIntegrityBuffer, xsize_t_MessageIntegrityBufferSizeInBytes, xBool_FingerprintIncluded, xWORD_ChannelNumber, xBool_LifetimeIncluded, xDWORD_mLifetime, xsize_t_PeerAddressListSize, xStr_FirstPeerAddress, xStr_RelayAddressIP, xsize_t_DataLengthInBytes, xBool_EvenPortIncluded, xBool_EvenPort, xBYTE_RequestTransport, xBool_DontFragementIncluded, xBool_ReservationTokenIncluded, xPtr_ReservationToken, xsize_t_ReservationTokenSizeInBytes, xBool_MobilityTicketIncluded, xPtr_MobilityTicketBuffer, xsize_t_MobilityTicketBufferSizeInBytes, xBool_PriorityIncluded, xDWORD_Priority, xBool_UseCandidateIncluded, xBool_IceControlledIncluded, xQWORD_IceControlled, xBool_IceControllingIncluded, xQWORD_IceControlling, xQWORD_NextSequenceNumber, xBool_MinimumRTTIncluded, xDWORD_MinimumRTT, xStr_ConnectionInfo, xQWORD_GSNR, xQWORD_mGSNFR, xBool_ReliabilityFlagsIncluded, xBool_ReliabilityFlags, xPtr_AckVectorBuffer, xsize_t_ACKVectorLengthInBytes, xsize_t_mLocalCongestionControl, xsize_t_mRemoteCongestionControl)

#define EventWriteOpServicesStunRequesterCreate(xStr_Method, xPUID, xStr_ServerIP, xUInt_UsingRFC, xPUID_BackOffTimerPatternObjectID)
#define EventWriteOpServicesStunRequesterDestroy(xStr_Method, xPUID)
#define EventWriteOpServicesStunRequesterCancel(xStr_Method, xPUID)
#define EventWriteOpServicesStunRequesterRetryNow(xStr_Method, xPUID)
#define EventWriteOpServicesStunRequesterReceivedStunPacket(xStr_Method, xPUID, xStr_FromIP)
#define EventWriteOpServicesStunRequesterBackOffTimerStateEventFired(xStr_Method, xPUID, xPUID_TimerID, xUInt_State, xULONG_TotalTries)
#define EventWriteOpServicesStunRequesterSendPacket(xStr_Method, xPUID, xPtr_StunPacketBuffer, xsize_t_StunPacketBufferSizeInBytes)

#define EventWriteOpServicesStunRequesterManagerCreate(xStr_Method, xPUID)
#define EventWriteOpServicesStunRequesterManagerDestroy(xStr_Method, xPUID)
#define EventWriteOpServicesStunRequesterManagerMonitorStart(xStr_Method, xPUID, xPUID_RequesterID)
#define EventWriteOpServicesStunRequesterManagerMonitorStop(xStr_Method, xPUID, xPUID_RequesterID)
#define EventWriteOpServicesStunRequesterManagerReceivedStunPacket(xStr_Method, xPUID, xStr_FromIP)

#define EventWriteOpServicesStunDiscoveryCreate(xStr_Method, xPUID, xlong_long_KeepWarmPingTimeInSeconds)
#define EventWriteOpServicesStunDiscoveryDestroy(xStr_Method, xPUID)

#define EventWriteOpServicesStunDiscoveryLookupSrv(xStr_Method, xPUID, xPUID_DNSQuery, xStr_SrvName, xStr_Service, xStr_Protocol, xWORD_DefaultPort, xWORD_DefaultPriority, xWORD_DefaultWeight, xUInt_LookupType)
#define EventWriteOpServicesStunDiscoveryCancel(xStr_Method, xPUID)
#define EventWriteOpServicesStunDiscoveryOnLookupComplete(xStr_Method, xPUID, xPUID_DNSQuery)
#define EventWriteOpServicesStunDiscoveryTimer(xStr_Method, xPUID, xPUID_Timer)

#define EventWriteOpServicesStunDiscoveryRequestCreate(xStr_Method, xPUID, xPUID_STUNRequester, xStr_ServerIP, xPtr_TransactionIDBuffer, xsize_t_TransactionBufferLengthInBytes)
#define EventWriteOpServicesStunDiscoveryRequestSendPacket(xStr_Method, xPUID, xPUID_STUNRequester, xStr_IPDestination, xPtr_Buffer, xsize_t_BufferLengthInBytes)
#define EventWriteOpServicesStunDiscoveryReceivedResponsePacket(xStr_Method, xPUID, xPUID_STUNRequester, xStr_FromIP, xPtr_TransactionIDBuffer, xsize_t_TransactionBufferLengthInBytes)

#define EventWriteOpServicesStunDiscoveryFoundMappedAddress(xStr_Method, xPUID, xPUID_STUNRequester, xStr_NewMappedAddressIP, xStr_OldMappedAddressIP)

#define EventWriteOpServicesStunDiscoveryError(xStr_Method, xPUID, xPUID_STUNRequester, xWORD_ErrorCode)
#define EventWriteOpServicesStunDiscoveryErrorUseAlternativeServer(xStr_Method, xPUID, xPUID_STUNRequester, xStr_ServerIP)
#define EventWriteOpServicesStunDiscoveryErrorTimeout(xStr_Method, xPUID, xPUID_STUNRequester)

#define EventWriteOpServicesTurnSocketCreate(xStr_Method, xPUID, xStr_ServerName, xStr_ServerUsername, xStr_ServerPassword, xUInt_DnsLookupType, xBool_UseChannelBinding, xWORD_LimitChannelToRangeStart, xWORD_LimitChannelToRangeEnd) {}
#define EventWriteOpServicesTurnSocketDestroy(xStr_Method, xPUID) {}
#define EventWriteOpServicesTurnSocketCancel(xStr_Method, xPUID) {}
#define EventWriteOpServicesTurnSocketStateEventFired(xStr_Method, xPUID, xUInt_State) {}
#define EventWriteOpServicesTurnSocketSendPacket(xStr_Method, xPUID, xStr_DestinationIP, xPtr_Buffer, xsize_t_BufferLengthInBytes, xBool_BindIfPossible) {}
#define EventWriteOpServicesTurnSocketSendPacketViaChannel(xStr_Method, xPUID, xStr_DestinationIP, xPtr_Buffer, xsize_t_BufferLengthInBytes, xWORD_ChannelNumber) {}
#define EventWriteOpServicesTurnSocketSendPacketViaStun(xStr_Method, xPUID, xStr_DestinationIP, xPtr_Buffer, xsize_t_BufferLengthInBytes) {}
#define EventWriteOpServicesTurnSocketInstallChannelOnWake(xStr_Method, xPUID, xStr_DestinationIP, xWORD_ChannelNumber) {}
#define EventWriteOpServicesTurnSocketInstallPermissionOnWake(xStr_Method, xPUID, xStr_DestinationIP) {}
#define EventWriteOpServicesTurnSocketReceivedStunPacketData(xStr_Method, xPUID, xStr_PeerIP, xPtr_Buffer, xsize_t_BufferLengthInBytes) {}
#define EventWriteOpServicesTurnSocketReceivedChannelData(xStr_Method, xPUID, xStr_PeerIP, xPtr_Buffer, xsize_t_BufferLengthInBytes) {}
#define EventWriteOpServicesTurnSocketRequesterSendStunPacket(xStr_Method, xPUID, xPUID_RequesterID, xStr_DestinationIP, xPtr_Buffer, xsize_t_BufferLengthInBytes) {}
#define EventWriteOpServicesTurnSocketRequesterReceivedStunResponse(xStr_Method, xPUID, xPUID_RequesterID, xStr_FromIP) {}
#define EventWriteOpServicesTurnSocketRequesterTimedOut(xStr_Method, xPUID, xPUID_RequesterID) {}
#define EventWriteOpServicesTurnSocketRequesterCreate(xStr_Method, xPUID, xPUID_RequesterID, xStr_Type) {}
#define EventWriteOpServicesTurnSocketRequesterCreateReauth(xStr_Method, xPUID, xPUID_RequesterID, xPUID_OldRequesterID) {}
#define EventWriteOpServicesTurnSocketReadReady(xStr_Method, xPUID, xPTRNUMBER_SocketID) {}
#define EventWriteOpServicesTurnSocketWriteReady(xStr_Method, xPUID, xPTRNUMBER_SocketID) {}
#define EventWriteOpServicesTurnSocketException(xStr_Method, xPUID, xPTRNUMBER_SocketID) {}
#define EventWriteOpServicesTurnSocketTimerEventFired(xStr_Method, xPUID, xPUID_TimerID) {}
#define EventWriteOpServicesTurnSocketBackgroundingEventFired(xStr_Method, xPUID) {}
#define EventWriteOpServicesTurnSocketUseNextServer(xStr_Method, xPUID, xStr_ServerIP, xBool_IsUDP) {}

#define EventWriteOpServicesBackOffTimerPatternCreate(xStr_Method, xPUID, xsize_t_MaxAttempts, xsize_t_DurationVectorSize, xlong_long_FrontDurationVectorInMicroseconds, xDouble_AttemptTimeoutMultiplier, xlong_long_MaxAttemptTimeoutInMicroseconds, xsize_t_RetryVector, xlong_long_FrontRetryVectorInMicroseconds, xDouble_RetryMultiplier, xlong_long_MaxRetryInMicroseconds)
#define EventWriteOpServicesBackOffTimerPatternDestroy(xStr_Method, xPUID)
#define EventWriteOpServicesBackOffTimerPatternClone(xStr_Method, xPUID, xPUID_OriginalPatternObjectID)
#define EventWriteOpServicesBackOffTimerPatternNextAttempt(xStr_Method, xPUID, xsize_t_AttemptNumber, xlong_long_LastAttemptTimeoutInMicroseconds, xlong_long_LastRetryDurationInMicroseconds)

#define EventWriteOpServicesBackOffTimerCreate(xStr_Method, xPUID, xPUID_PatternObjectID)
#define EventWriteOpServicesBackOffTimerDestroy(xStr_Method, xPUID)
#define EventWriteOpServicesBackOffTimerNotifyAttempting(xStr_Method, xPUID)
#define EventWriteOpServicesBackOffTimerNotifyAttemptFailed(xStr_Method, xPUID)
#define EventWriteOpServicesBackOffTimerNotifyTryAgainNow(xStr_Method, xPUID)
#define EventWriteOpServicesBackOffTimerNotifySucceeded(xStr_Method, xPUID)
#define EventWriteOpServicesBackOffTimerStateChangedEventFired(xStr_Method, xPUID, xUInt_State)

#define EventWriteOpServicesSettingGetString(xStr_Method, xPUID, xStr_Key, xStr_Result)
#define EventWriteOpServicesSettingGetInt(xStr_Method, xPUID, xStr_Key, xLong_Result)
#define EventWriteOpServicesSettingGetUInt(xStr_Method, xPUID, xStr_Key, xULong_Result)
#define EventWriteOpServicesSettingGetBool(xStr_Method, xPUID, xStr_Key, xBool_Result)
#define EventWriteOpServicesSettingGetFloat(xStr_Method, xPUID, xStr_Key, xFloat_Result)
#define EventWriteOpServicesSettingGetDouble(xStr_Method, xPUID, xStr_Key, xDouble_Result)

#define EventWriteOpServicesSettingSetString(xStr_Method, xPUID, xStr_Key, xStr_Value)
#define EventWriteOpServicesSettingSetInt(xStr_Method, xPUID, xStr_Key, xLong_Value)
#define EventWriteOpServicesSettingSetUInt(xStr_Method, xPUID, xStr_Key, xULong_Value)
#define EventWriteOpServicesSettingSetBool(xStr_Method, xPUID, xStr_Key, xBool_Value)
#define EventWriteOpServicesSettingSetFloat(xStr_Method, xPUID, xStr_Key, xFloat_Value)
#define EventWriteOpServicesSettingSetDouble(xStr_Method, xPUID, xStr_Key, xDouble_Value)

#define EventWriteOpServicesSettingClearAll(xStr_Method, xPUID)
#define EventWriteOpServicesSettingClear(xStr_Method, xPUID, xStr_Key)
#define EventWriteOpServicesSettingApply(xStr_Method, xPUID, xStr_Json)
#define EventWriteOpServicesSettingApplyDefaults(xStr_Method, xPUID)
#define EventWriteOpServicesSettingVerifyExists(xStr_Method, xPUID, xStr_Key, xBool_Exists)

#define EventWriteOpServicesCacheFetch(xStr_Method, xPUID, xStr_CookieNamePath, xStr_Result)
#define EventWriteOpServicesCacheStore(xStr_Method, xPUID, xStr_CookieNamePath, xStr_Expires, xStr_Value)
#define EventWriteOpServicesCacheClear(xStr_Method, xPUID, xStr_CookieNamePath)

#define EventWriteOpServicesDnsResultListBegin(xStr_Method, xStr_Message, xStr_Name, xUInt_TTL, xsize_t_TotalIPAddresses)
#define EventWriteOpServicesDnsResultListEntry(xStr_Method, xStr_Message, xStr_Name, xUInt_TTL, xStr_IPAddress)
#define EventWriteOpServicesDnsResultListEnd(xStr_Method, xStr_Message, xStr_Name)

#define EventWriteOpServicesDnsSrvResultListBegin(xStr_Method, xStr_Message, xStr_Name, xStr_Service, xStr_Protocol, xUInt_TTL, xsize_t_TotalRecords)
#define EventWriteOpServicesDnsSrvResultListEntryBegin(xStr_Method, xStr_Message, xStr_Name, xWORD_Priority, xWORD_Weight, xWORD_Port, xsize_t_TotalAResults, xsize_t_TotalAAAAResults)
#define EventWriteOpServicesDnsSrvResultListEntryEnd(xStr_Method, xStr_Message, xStr_Name)
#define EventWriteOpServicesDnsSrvResultListEnd(xStr_Method, xStr_Message, xStr_Name)

#define EventWriteOpServicesDnsLookup(xStr_Method, xPUID_QueryObjectID, xStr_LookupType, xStr_Name)
#define EventWriteOpServicesDnsSrvLookup(xStr_Method, xPUID_QueryObjectID, xStr_Name, xStr_Service, xStr_Protocol, xWORD_DefaultPort, xWORD_DefaultPriority, xWORD_DefaultWeight, xUInt_LookupType)

#define EventWriteOpServicesDnsLookupResolverSubQuery(xStr_Method, xPUID_QueryObjectID, xStr_LookupType, xStr_Name, xPUID_RelatedQueryObjectID)

#define EventWriteOpServicesDnsLookupComplete(xStr_Method, xPUID_QueryObjectID, xStr_LookupType, xStr_Name)

#define EventWriteOpServicesDnsLookupSuccess(xStr_Method, xPUID_QueryObjectID, xStr_LookupType, xStr_Name)
#define EventWriteOpServicesDnsLookupFailed(xStr_Method, xPUID_QueryObjectID, xStr_LookupType, xStr_Name)

#define EventWriteOpServicesHttpQueryCreate(xStr_Method, xPUID, xBool_IsPost, xStr_UserAgent, xStr_Url, xPtr_PostData, xsize_t_PostDataLengthInBytes, xStr_PostMimeType, xlong_long_Timeout)
#define EventWriteOpServicesHttpQueryDestroy(xStr_Method, xPUID)
#define EventWriteOpServicesHttpQueryCancel(xStr_Method, xPUID)
#define EventWriteOpServicesHttpQueryRead(xStr_Method, xPUID, xPtr_ResultData, xsize_t_ResultReadSizeInBytes, xsize_t_BytesToRead)

#define EventWriteOpServicesDebugLogger(xStr_Subsystem, xUInt_Severity, xUInt_Level, xStr_Function, xStr_FilePath, xULONG_LineNumber, xStr_Output)

#else

// duplicate testing compilation methods used to verify compilation when macros get defined
namespace openpeer
{
namespace services
{

inline void EventWriteOpServicesStunPacket(const char *xStr_Method, const char *xStr_Message, const char *xStr_Log, PUID xPUID_ObjectID, unsigned int xUInt_Class, unsigned int xUInt_Method, ULONG xULONG_TotalRetries, WORD xWORD_ErrorCode, const char *xStr_Reason, DWORD xDWORD_MagicCookies, const void *xPtr_TransactionIDBuffer, size_t xsize_t_TransactionBufferLengthInBytes, size_t xsize_t_TotalUnknownAttributes, WORD xWORD_FirstUnknownAttribute, const char *xStr_MappedAddressIP, const char *xStr_AlternateServerIP, const char *xStr_Username, const char *xStr_Password, const char *xStr_Realm, const char *xStr_Nonce, const char *xStr_Software, unsigned int xUInt_CredentialMechanism, size_t xsize_t_MessageIntegrityMessageLengthInBytes, const void *xPtr_MessageIntegrityBuffer, size_t xsize_t_MessageIntegrityBufferSizeInBytes, bool xBool_FingerprintIncluded, WORD xWORD_ChannelNumber, bool xBool_LifetimeIncluded, QWORD xDWORD_mLifetime, size_t xsize_t_PeerAddressListSize, const char *xStr_FirstPeerAddress, const char *xStr_RelayAddressIP, size_t xsize_t_DataLengthInBytes, bool xBool_EvenPortIncluded, bool xBool_EvenPort, BYTE xBYTE_RequestTransport, bool xBool_DontFragementIncluded, bool xBool_ReservationTokenIncluded, const void *xPtr_ReservationToken, size_t xsize_t_ReservationTokenSizeInBytes, bool xBool_MobilityTicketIncluded, const void *xPtr_MobilityTicketBuffer, size_t xsize_t_MobilityTicketBufferSizeInBytes, bool xBool_PriorityIncluded, DWORD xDWORD_Priority, bool xBool_UseCandidateIncluded, bool xBool_IceControlledIncluded, QWORD xQWORD_IceControlled, bool xBool_IceControllingIncluded, QWORD xQWORD_IceControlling, QWORD xQWORD_NextSequenceNumber, bool xBool_MinimumRTTIncluded, DWORD xDWORD_MinimumRTT, const char *xStr_ConnectionInfo, QWORD xQWORD_GSNR, QWORD xQWORD_mGSNFR, bool xBool_ReliabilityFlagsIncluded, BYTE xBool_ReliabilityFlags, const void *xPtr_AckVectorBuffer, size_t xsize_t_ACKVectorLengthInBytes, size_t xsize_t_mLocalCongestionControl, size_t xsize_t_mRemoteCongestionControl) {}

inline void EventWriteOpServicesStunRequesterCreate(const char *xStr_Method, PUID xPUID, const char *xStr_ServerIP, unsigned int xUInt_UsingRFC, PUID xPUID_BackOffTimerPatternObjectID) {}
inline void EventWriteOpServicesStunRequesterDestroy(const char *xStr_Method, PUID xPUID) {}
inline void EventWriteOpServicesStunRequesterCancel(const char *xStr_Method, PUID xPUID) {}
inline void EventWriteOpServicesStunRequesterRetryNow(const char *xStr_Method, PUID xPUID) {}
inline void EventWriteOpServicesStunRequesterReceivedStunPacket(const char *xStr_Method, PUID xPUID, const char *xStr_FromIP) {}
inline void EventWriteOpServicesStunRequesterBackOffTimerStateEventFired(const char *xStr_Method, PUID xPUID, PUID xPUID_TimerID, unsigned int xUInt_State, ULONG xULONG_TotalTries) {}
inline void EventWriteOpServicesStunRequesterSendPacket(const char *xStr_Method, PUID xPUID, const void *xPtr_StunPacketBuffer, size_t xsize_t_StunPacketBufferSizeInBytes) {}

inline void EventWriteOpServicesStunRequesterManagerCreate(const char *xStr_Method, PUID xPUID) {}
inline void EventWriteOpServicesStunRequesterManagerDestroy(const char *xStr_Method, PUID xPUID) {}
inline void EventWriteOpServicesStunRequesterManagerMonitorStart(const char *xStr_Method, PUID xPUID, PUID xPUID_RequesterID) {}
inline void EventWriteOpServicesStunRequesterManagerMonitorStop(const char *xStr_Method, PUID xPUID, PUID xPUID_RequesterID) {}
inline void EventWriteOpServicesStunRequesterManagerReceivedStunPacket(const char *xStr_Method, PUID xPUID, const char *xStr_FromIP) {}

inline void EventWriteOpServicesStunDiscoveryCreate(const char *xStr_Method, PUID xPUID, long long xlong_long_KeepWarmPingTimeInSeconds) {}
inline void EventWriteOpServicesStunDiscoveryDestroy(const char *xStr_Method, PUID xPUID) {}

inline void EventWriteOpServicesStunDiscoveryLookupSrv(const char *xStr_Method, PUID xPUID, PUID xPUID_DNSQuery, const char *xStr_SrvName, const char *xStr_Service, const char *xStr_Protocol, WORD xWORD_DefaultPort, WORD xWORD_DefaultPriority, WORD xWORD_DefaultWeight, unsigned int xUInt_LookupType) {}
inline void EventWriteOpServicesStunDiscoveryCancel(const char *xStr_Method, PUID xPUID) {}
inline void EventWriteOpServicesStunDiscoveryOnLookupComplete(const char *xStr_Method, PUID xPUID, PUID xPUID_DNSQuery) {}
inline void EventWriteOpServicesStunDiscoveryTimer(const char *xStr_Method, PUID xPUID, PUID xPUID_Timer) {}

inline void EventWriteOpServicesStunDiscoveryRequestCreate(const char *xStr_Method, PUID xPUID, PUID xPUID_STUNRequester, const char *xStr_ServerIP, const void *xPtr_TransactionIDBuffer, size_t xsize_t_TransactionBufferLengthInBytes) {}
inline void EventWriteOpServicesStunDiscoveryRequestSendPacket(const char *xStr_Method, PUID xPUID, PUID xPUID_STUNRequester, const char *xStr_IPDestination, const void *xPtr_Buffer, size_t xsize_t_BufferLengthInBytes) {}
inline void EventWriteOpServicesStunDiscoveryReceivedResponsePacket(const char *xStr_Method, PUID xPUID, PUID xPUID_STUNRequester, const char *xStr_FromIP, const void *xPtr_TransactionIDBuffer, size_t xsize_t_TransactionBufferLengthInBytes) {}

inline void EventWriteOpServicesStunDiscoveryFoundMappedAddress(const char *xStr_Method, PUID xPUID, PUID xPUID_STUNRequester, const char *xStr_NewMappedAddressIP, const char *xStr_OldMappedAddressIP) {}

inline void EventWriteOpServicesStunDiscoveryError(const char *xStr_Method, PUID xPUID, PUID xPUID_STUNRequester, WORD xWORD_ErrorCode) {}
inline void EventWriteOpServicesStunDiscoveryErrorUseAlternativeServer(const char *xStr_Method, PUID xPUID, PUID xPUID_STUNRequester, const char *xStr_ServerIP) {}
inline void EventWriteOpServicesStunDiscoveryErrorTimeout(const char *xStr_Method, PUID xPUID, PUID xPUID_STUNRequester) {}

inline void EventWriteOpServicesTurnSocketCreate(const char *xStr_Method, PUID xPUID, const char *xStr_ServerName, const char *xStr_ServerUsername, const char *xStr_ServerPassword, unsigned int xUInt_DnsLookupType, bool xBool_UseChannelBinding, WORD xWORD_LimitChannelToRangeStart, WORD xWORD_LimitChannelToRangeEnd) {}
inline void EventWriteOpServicesTurnSocketDestroy(const char *xStr_Method, PUID xPUID) {}
inline void EventWriteOpServicesTurnSocketCancel(const char *xStr_Method, PUID xPUID) {}
inline void EventWriteOpServicesTurnSocketStateEventFired(const char *xStr_Method, PUID xPUID, unsigned int xUInt_State) {}
inline void EventWriteOpServicesTurnSocketSendPacket(const char *xStr_Method, PUID xPUID, const char *xStr_DestinationIP, const void *xPtr_Buffer, size_t xsize_t_BufferLengthInBytes, bool xBool_BindIfPossible) {}
inline void EventWriteOpServicesTurnSocketSendPacketViaChannel(const char *xStr_Method, PUID xPUID, const char *xStr_DestinationIP, const void *xPtr_Buffer, size_t xsize_t_BufferLengthInBytes, WORD xWORD_ChannelNumber) {}
inline void EventWriteOpServicesTurnSocketSendPacketViaStun(const char *xStr_Method, PUID xPUID, const char *xStr_DestinationIP, const void *xPtr_Buffer, size_t xsize_t_BufferLengthInBytes) {}
inline void EventWriteOpServicesTurnSocketInstallChannelOnWake(const char *xStr_Method, PUID xPUID, const char *xStr_DestinationIP, WORD xWORD_ChannelNumber) {}
inline void EventWriteOpServicesTurnSocketInstallPermissionOnWake(const char *xStr_Method, PUID xPUID, const char *xStr_DestinationIP) {}
inline void EventWriteOpServicesTurnSocketReceivedStunPacketData(const char *xStr_Method, PUID xPUID, const char *xStr_PeerIP, const void *xPtr_Buffer, size_t xsize_t_BufferLengthInBytes) {}
inline void EventWriteOpServicesTurnSocketReceivedChannelData(const char *xStr_Method, PUID xPUID, const char *xStr_PeerIP, const void *xPtr_Buffer, size_t xsize_t_BufferLengthInBytes) {}
inline void EventWriteOpServicesTurnSocketRequesterSendStunPacket(const char *xStr_Method, PUID xPUID, PUID xPUID_RequesterID, const char *xStr_DestinationIP, const void *xPtr_Buffer, size_t xsize_t_BufferLengthInBytes) {}
inline void EventWriteOpServicesTurnSocketRequesterReceivedStunResponse(const char *xStr_Method, PUID xPUID, PUID xPUID_RequesterID, const char *xStr_FromIP) {}
inline void EventWriteOpServicesTurnSocketRequesterTimedOut(const char *xStr_Method, PUID xPUID, PUID xPUID_RequesterID) {}
inline void EventWriteOpServicesTurnSocketRequesterCreate(const char *xStr_Method, PUID xPUID, PUID xPUID_RequesterID, const char *xStr_Type) {}
inline void EventWriteOpServicesTurnSocketRequesterCreateReauth(const char *xStr_Method, PUID xPUID, PUID xPUID_RequesterID, PUID xPUID_OldRequesterID) {}
inline void EventWriteOpServicesTurnSocketReadReady(const char *xStr_Method, PUID xPUID, PTRNUMBER xPTRNUMBER_SocketID) {}
inline void EventWriteOpServicesTurnSocketWriteReady(const char *xStr_Method, PUID xPUID, PTRNUMBER xPTRNUMBER_SocketID) {}
inline void EventWriteOpServicesTurnSocketException(const char *xStr_Method, PUID xPUID, PTRNUMBER xPTRNUMBER_SocketID) {}
inline void EventWriteOpServicesTurnSocketTimerEventFired(const char *xStr_Method, PUID xPUID, PUID xPUID_TimerID) {}
inline void EventWriteOpServicesTurnSocketBackgroundingEventFired(const char *xStr_Method, PUID xPUID) {}
inline void EventWriteOpServicesTurnSocketUseNextServer(const char *xStr_Method, PUID xPUID, const char *xStr_ServerIP, bool xBool_IsUDP) {}

inline void EventWriteOpServicesBackOffTimerPatternCreate(const char *xStr_Method, PUID xPUID, size_t xsize_t_MaxAttempts, size_t xsize_t_DurationVectorSize, long long xlong_long_FrontDurationVectorInMicroseconds, double xDouble_AttemptTimeoutMultiplier, long long xlong_long_MaxAttemptTimeoutInMicroseconds, size_t xsize_t_RetryVector, long long xlong_long_FrontRetryVectorInMicroseconds, double xDouble_RetryMultiplier, long long xlong_long_MaxRetryInMicroseconds) {}
inline void EventWriteOpServicesBackOffTimerPatternDestroy(const char *xStr_Method, PUID xPUID) {}
inline void EventWriteOpServicesBackOffTimerPatternClone(const char *xStr_Method, PUID xPUID, PUID xPUID_OriginalPatternObjectID) {}
inline void EventWriteOpServicesBackOffTimerPatternNextAttempt(const char *xStr_Method, PUID xPUID, size_t xsize_t_AttemptNumber, long long xlong_long_LastAttemptTimeoutInMicroseconds, long long xlong_long_LastRetryDurationInMicroseconds) {}

inline void EventWriteOpServicesBackOffTimerCreate(const char *xStr_Method, PUID xPUID, PUID xPUID_PatternObjectID) {}
inline void EventWriteOpServicesBackOffTimerDestroy(const char *xStr_Method, PUID xPUID) {}
inline void EventWriteOpServicesBackOffTimerNotifyAttempting(const char *xStr_Method, PUID xPUID) {}
inline void EventWriteOpServicesBackOffTimerNotifyAttemptFailed(const char *xStr_Method, PUID xPUID) {}
inline void EventWriteOpServicesBackOffTimerNotifyTryAgainNow(const char *xStr_Method, PUID xPUID) {}
inline void EventWriteOpServicesBackOffTimerNotifySucceeded(const char *xStr_Method, PUID xPUID) {}
inline void EventWriteOpServicesBackOffTimerStateChangedEventFired(const char *xStr_Method, PUID xPUID, unsigned int xUInt_State) {}

inline void EventWriteOpServicesSettingGetString(const char *xStr_Method, PUID xPUID, const char *xStr_Key, const char *xStr_Result) {}
inline void EventWriteOpServicesSettingGetInt(const char *xStr_Method, PUID xPUID, const char *xStr_Key, long xLong_Result) {}
inline void EventWriteOpServicesSettingGetUInt(const char *xStr_Method, PUID xPUID, const char *xStr_Key, unsigned long xULong_Result) {}
inline void EventWriteOpServicesSettingGetBool(const char *xStr_Method, PUID xPUID, const char *xStr_Key, bool xBool_Result) {}
inline void EventWriteOpServicesSettingGetFloat(const char *xStr_Method, PUID xPUID, const char *xStr_Key, float xFloat_Result) {}
inline void EventWriteOpServicesSettingGetDouble(const char *xStr_Method, PUID xPUID, const char *xStr_Key, float xDouble_Result) {}

inline void EventWriteOpServicesSettingSetString(const char *xStr_Method, PUID xPUID, const char *xStr_Key, const char *xStr_Value) {}
inline void EventWriteOpServicesSettingSetInt(const char *xStr_Method, PUID xPUID, const char *xStr_Key, long xLong_Value) {}
inline void EventWriteOpServicesSettingSetUInt(const char *xStr_Method, PUID xPUID, const char *xStr_Key, unsigned long xULong_Value) {}
inline void EventWriteOpServicesSettingSetBool(const char *xStr_Method, PUID xPUID, const char *xStr_Key, bool xBool_Value) {}
inline void EventWriteOpServicesSettingSetFloat(const char *xStr_Method, PUID xPUID, const char *xStr_Key, float xFloat_Value) {}
inline void EventWriteOpServicesSettingSetDouble(const char *xStr_Method, PUID xPUID, const char *xStr_Key, float xDouble_Value) {}

inline void EventWriteOpServicesSettingClearAll(const char *xStr_Method, PUID xPUID) {}
inline void EventWriteOpServicesSettingClear(const char *xStr_Method, PUID xPUID, const char *xStr_Key) {}
inline void EventWriteOpServicesSettingApply(const char *xStr_Method, PUID xPUID, const char *xStr_Json) {}
inline void EventWriteOpServicesSettingApplyDefaults(const char *xStr_Method, PUID xPUID) {}
inline void EventWriteOpServicesSettingVerifyExists(const char *xStr_Method, PUID xPUID, const char *xStr_Key, bool xBool_Exists) {}

inline void EventWriteOpServicesCacheFetch(const char *xStr_Method, PUID xPUID, const char *xStr_CookieNamePath, const char *xStr_Result) {}
inline void EventWriteOpServicesCacheStore(const char *xStr_Method, PUID xPUID, const char *xStr_CookieNamePath, const char *xStr_Expires, const char *xStr_Value) {}
inline void EventWriteOpServicesCacheClear(const char *xStr_Method, PUID xPUID, const char *xStr_CookieNamePath) {}

inline void EventWriteOpServicesDnsResultListBegin(const char *xStr_Method, const char *xStr_Message, const char *xStr_Name, unsigned int xUInt_TTL, size_t xsize_t_TotalIPAddresses) {}
inline void EventWriteOpServicesDnsResultListEntry(const char *xStr_Method, const char *xStr_Message, const char *xStr_Name, unsigned int xUInt_TTL, const char *xStr_IPAddress) {}
inline void EventWriteOpServicesDnsResultListEnd(const char *xStr_Method, const char *xStr_Message, const char *xStr_Name) {}

inline void EventWriteOpServicesDnsSrvResultListBegin(const char *xStr_Method, const char *xStr_Message, const char *xStr_Name, const char *xStr_Service, const char *xStr_Protocol, unsigned int xUInt_TTL, size_t xsize_t_TotalRecords) {}
inline void EventWriteOpServicesDnsSrvResultListEntryBegin(const char *xStr_Method, const char *xStr_Message, const char *xStr_Name, WORD xWORD_Priority, WORD xWORD_Weight, WORD xWORD_Port, size_t xsize_t_TotalAResults, size_t xsize_t_TotalAAAAResults) {}
inline void EventWriteOpServicesDnsSrvResultListEntryEnd(const char *xStr_Method, const char *xStr_Message, const char *xStr_Name) {}
inline void EventWriteOpServicesDnsSrvResultListEnd(const char *xStr_Method, const char *xStr_Message, const char *xStr_Name) {}

inline void EventWriteOpServicesDnsLookup(const char *xStr_Method, PUID xPUID_QueryObjectID, const char *xStr_LookupType, const char *xStr_Name) {}
inline void EventWriteOpServicesDnsSrvLookup(const char *xStr_Method, PUID xPUID_QueryObjectID, const char *xStr_Name, const char *xStr_Service, const char *xStr_Protocol, WORD xWORD_DefaultPort, WORD xWORD_DefaultPriority, WORD xWORD_DefaultWeight, unsigned int xUInt_LookupType) {}

inline void EventWriteOpServicesDnsLookupResolverSubQuery(const char *xStr_Method, PUID xPUID_QueryObjectID, const char *xStr_LookupType, const char *xStr_Name, PUID xPUID_RelatedQueryObjectID) {}

inline void EventWriteOpServicesDnsLookupComplete(const char *xStr_Method, PUID xPUID_QueryObjectID, const char *xStr_LookupType, const char *xStr_Name) {}

inline void EventWriteOpServicesDnsLookupSuccess(const char *xStr_Method, PUID xPUID_QueryObjectID, const char *xStr_LookupType, const char *xStr_Name) {}
inline void EventWriteOpServicesDnsLookupFailed(const char *xStr_Method, PUID xPUID_QueryObjectID, const char *xStr_LookupType, const char *xStr_Name) {}

inline void EventWriteOpServicesHttpQueryCreate(const char *xStr_Method, PUID xPUID, bool xBool_IsPost, const char *xStr_UserAgent, const char *xStr_Url, const void *xPtr_PostData, size_t xsize_t_PostDataLengthInBytes, const char *xStr_PostMimeType, long long xlong_long_Timeout) {}
inline void EventWriteOpServicesHttpQueryDestroy(const char *xStr_Method, PUID xPUID) {}
inline void EventWriteOpServicesHttpQueryCancel(const char *xStr_Method, PUID xPUID) {}
inline void EventWriteOpServicesHttpQueryRead(const char *xStr_Method, PUID xPUID, const void *xPtr_ResultData, size_t xsize_t_ResultReadSizeInBytes, size_t xsize_t_BytesToRead) {}

inline void EventWriteOpServicesDebugLogger(const char *xStr_Subsystem, unsigned int xUInt_Severity, unsigned int xUInt_Level, const char *xStr_Function, const char *xStr_FilePath, ULONG xULONG_LineNumber, const char *xStr_Output) {}

}
}
#endif //ndef OPENPEER_SERVICES_USE_NOOP_EVENT_TRACE_MACROS

#endif //USE_ETW

