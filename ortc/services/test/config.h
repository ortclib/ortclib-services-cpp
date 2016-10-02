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

#ifndef ORTC_SERVICE_TEST_CONFIG_H_934e33cf1d24510f40709eb6c69b8c45
#define ORTC_SERVICE_TEST_CONFIG_H_934e33cf1d24510f40709eb6c69b8c45

#define ORTC_SERVICE_TEST_FIFO_LOGGING_FILE "/tmp/ortc.fifo"

#define ORTC_SERVICE_TEST_USE_STDOUT_LOGGING     (true)
#define ORTC_SERVICE_TEST_USE_FIFO_LOGGING       (false)
#define ORTC_SERVICE_TEST_USE_TELNET_LOGGING     (true)
#define ORTC_SERVICE_TEST_USE_DEBUGGER_LOGGING   (true)

#define ORTC_SERVICE_TEST_TELNET_LOGGING_PORT         (59999)
#define ORTC_SERVICE_TEST_TELNET_SERVER_LOGGING_PORT  (51999)

#define ORTC_SERVICE_TEST_DO_BACKOFF_RETRY_TEST                    (true)
#define ORTC_SERVICE_TEST_DO_CANONICAL_XML_TEST                    (true)
#define ORTC_SERVICE_TEST_DO_DH_TEST                               (true)
#define ORTC_SERVICE_TEST_DO_DNS_TEST                              (true)
#define ORTC_SERVICE_TEST_DO_HELPER_TEST                           (true)
#define ORTC_SERVICE_TEST_DO_ICE_SOCKET_TEST                       (true)
#define ORTC_SERVICE_TEST_DO_STUN_TEST                             (true)
#define ORTC_SERVICE_TEST_DO_TURN_TEST                             (true)
#define ORTC_SERVICE_TEST_DO_RUDPICESOCKET_LOOPBACK_TEST           (true)
#define ORTC_SERVICE_TEST_DO_RUDPICESOCKET_CLIENT_TO_SERVER_TEST   (true)
#define ORTC_SERVICE_TEST_DO_TCP_MESSAGING_TEST                    (true)
#define ORTC_SERVICE_TEST_DO_STUN_PACKET_TEST                      (true)

#define ORTC_SERVICE_TEST_DNS_ZONE "test-dns.ortclib.org"

// true = running RUDP client
#define ORTC_SERVICE_TEST_RUNNING_RUDP_LOCAL_CLIENT                (true)

// mutually exclusive, either run locally or run remotely
#define ORTC_SERVICE_TEST_RUNNING_RUDP_LOCAL_SERVER                (true)
#define ORTC_SERVICE_TEST_RUNNING_RUDP_REMOTE_SERVER               (false)

#define ORTC_SERVICE_TEST_RUDP_SERVER_IP                           "127.0.0.1"  // if running remotely choose alternative IP
#define ORTC_SERVICE_TEST_RUDP_SERVER_PORT                         50000

#define ORTC_SERVICE_TEST_DNS_PROVIDER_RESOLVES_BOGUS_DNS_A_RECORDS    (false)
#define ORTC_SERVICE_TEST_DNS_PROVIDER_RESOLVES_BOGUS_DNS_AAAA_RECORDS (false)

#define ORTC_SERVICE_TEST_TURN_SERVER_DOMAIN   "test-turn.ortclib.org"
#define ORTC_SERVICE_TEST_TURN_USERNAME        ("ortclib" "@" "hotmail.com")
#define ORTC_SERVICE_TEST_TURN_PASSWORD        "invalid"

#define ORTC_SERVICE_TEST_TURN_SERVER_DOMAIN_VIA_A_RECORD_1   "test-turn1.ortclib.org"
#define ORTC_SERVICE_TEST_TURN_SERVER_DOMAIN_VIA_A_RECORD_2   "test-turn2.ortclib.org"

#define ORTC_SERVICE_TEST_STUN_SERVER_HOST     "stun.l.google.com:19302"
// This should be set to value based on http://www.whatismyip.com/ to get your current IP address
#define ORTC_SERVICE_TEST_WHAT_IS_MY_IP        "1.2.3.4"



#endif //ORTC_SERVICE_TEST_CONFIG_H_934e33cf1d24510f40709eb6c69b8c45
