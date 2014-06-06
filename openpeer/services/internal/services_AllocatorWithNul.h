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

#include <cryptopp/secblock.h>

namespace CryptoPP
{
  template <class T, bool T_Align16 = false>
  class AllocatorWithNul : public AllocatorBase<T>
  {
  public:
    CRYPTOPP_INHERIT_ALLOCATOR_TYPES

    pointer allocate(size_type n, const void * = NULL)
    {
      AllocatorBase<T>::CheckSize(n);
      if (n == 0)
        return NULL;

      pointer result = NULL;

#if CRYPTOPP_BOOL_ALIGN16_ENABLED
      if (T_Align16 && n*sizeof(T) >= 16) {
        result = (pointer)AlignedAllocate(n*sizeof(T) + sizeof(T));
        memset(result, 0, n*sizeof(T) + sizeof(T));
        return result;
      }
#endif

      result = (pointer)UnalignedAllocate(n*sizeof(T) + sizeof(T));
      memset(result, 0, n*sizeof(T) + sizeof(T));
      return result;
    }

    void deallocate(void *p, size_type n)
    {
      SecureWipeArray((pointer)p, n);

#if CRYPTOPP_BOOL_ALIGN16_ENABLED
      if (T_Align16 && n*sizeof(T) >= 16)
        return AlignedDeallocate(p);
#endif

      UnalignedDeallocate(p);
    }

    pointer reallocate(T *p, size_type oldSize, size_type newSize, bool preserve)
    {
      return StandardReallocate(*this, p, oldSize, newSize, preserve);
    }

    // VS.NET STL enforces the policy of "All STL-compliant allocators have to provide a
    // template class member called rebind".
    template <class U> struct rebind { typedef AllocatorWithNul<U, T_Align16> other; };
#if _MSC_VER >= 1500
    AllocatorWithNul() {}
    template <class U, bool A> AllocatorWithNul(const AllocatorWithNul<U, A> &) {}
#endif
  };

}
