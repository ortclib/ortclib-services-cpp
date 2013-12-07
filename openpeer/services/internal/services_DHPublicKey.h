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

#include <openpeer/services/internal/types.h>
#include <openpeer/services/IDHPublicKey.h>

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
      #pragma mark IDHPublicKeyForDHPrivateKey
      #pragma mark

      interaction IDHPublicKeyForDHPrivateKey
      {
        IDHPublicKeyForDHPrivateKey &forDHPrivateKey() {return *this;}
        const IDHPublicKeyForDHPrivateKey &forDHPrivateKey() const {return *this;}

        virtual const SecureByteBlock &getStaticPublicKey() const = 0;
        virtual const SecureByteBlock &getEphemeralPublicKey() const = 0;
      };
      
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark DHPublicKey
      #pragma mark

      class DHPublicKey : public Noop,
                          public IDHPublicKey,
                          public IDHPublicKeyForDHPrivateKey
      {
      public:
        friend interaction IDHPublicKeyFactory;
        friend interaction IDHPublicKey;

      protected:
        DHPublicKey();
        
        DHPublicKey(Noop) : Noop(true) {};

      public:
        ~DHPublicKey();

        static DHPublicKeyPtr convert(IDHPublicKeyPtr privateKey);

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DHPublicKey => IDHPublicKey
        #pragma mark

        static ElementPtr toDebug(IDHPublicKeyPtr keyDomain);

        static DHPublicKeyPtr load(
                                   const SecureByteBlock &staticPublicKey,
                                   const SecureByteBlock &ephemeralPublicKey
                                   );

        virtual PUID getID() const {return mID;}

        virtual void save(
                          SecureByteBlock *outStaticPublicKey,
                          SecureByteBlock *outEphemeralPublicKey
                          ) const;

        virtual String getFingerprint() const;

        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DHPublicKey => IDHPublicKeyForDHPrivateKey
        #pragma mark

        virtual const SecureByteBlock &getStaticPublicKey() const;
        virtual const SecureByteBlock &getEphemeralPublicKey() const;

      protected:
        //---------------------------------------------------------------------
        #pragma mark
        #pragma mark DHPublicKey => (internal)
        #pragma mark

        Log::Params log(const char *message) const;
        Log::Params debug(const char *message) const;
        virtual ElementPtr toDebug() const;

      private:
        //-------------------------------------------------------------------
        #pragma mark
        #pragma mark DHPublicKey => (data)
        #pragma mark

        AutoPUID mID;

        SecureByteBlock mStaticPublicKey;
        SecureByteBlock mEphemeralPublicKey;
      };

      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      //-----------------------------------------------------------------------
      #pragma mark
      #pragma mark IDHPublicKeyFactory
      #pragma mark

      interaction IDHPublicKeyFactory
      {
        static IDHPublicKeyFactory &singleton();

        virtual DHPublicKeyPtr load(
                                    const SecureByteBlock &staticPublicKey,
                                    const SecureByteBlock &ephemeralPublicKey
                                    );
      };
      
    }
  }
}
