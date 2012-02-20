/*
 *  PKCS#11 library for .Net smart cards
 *  Copyright (C) 2007-2009 Gemalto <support@gemalto.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef _include_util_h
#define _include_util_h

#include <string>
#include <vector>

#include <MarshallerCfg.h>
#include <Array.h>
#include <cr_random.h>

using namespace std;
using namespace Marshaller;

// Very simple class similar to auto_ptr, but for arrays.
// It means that it calls delete[] instead of delete.
template<class T> class autoarray
{
public:
    autoarray(T* t) : _t(t) {}
    ~autoarray() { delete [] _t; }
    T * get() { return _t; }
    T & operator[](size_t index) { return _t[index]; }
    const T & operator[](size_t index) const { return _t[index]; }

private:
    T * _t;
};

template<typename T> void IntToLittleEndian(T t, unsigned char * buf, size_t offset = 0)
{
    size_t n = sizeof(T);
    for(size_t i = 0; i < n; i++)
    {
        buf[offset+i] = static_cast<unsigned char>(t & 0xFF);
        t >>= 8;
    }
}

template<typename T> T LittleEndianToInt(const unsigned char * buf, size_t offset = 0)
{
    size_t n = sizeof(T);
    T t = 0;
    for(size_t i = 0; i < n; i++)
    {
        t <<= 8;
        t |= buf[offset+n-i-1];
    }
    return t;
}

class Util{

public:
    static void SeedRandom(u1Array const & seed);
    static R_RANDOM_STRUCT & RandomStruct();

    static CK_ULONG MakeULong(CK_BYTE_PTR pValue,CK_ULONG offset);
    static CK_BBOOL CompareByteArrays(CK_BYTE_PTR abuffer,CK_BYTE_PTR bbuffer,CK_ULONG len);
    static void PushULongInVector(vector<u1>* to,CK_ULONG value);
    static void PushULongLongInVector(vector<u1>* to,u8 value);
    static void PushBBoolInVector(vector<u1>* to,CK_BBOOL value);
    static void PushByteArrayInVector(vector<u1>* to,u1Array* value);
    static void PushIntArrayInVector(vector<u1>* to,u4Array* value);
    static void PushLengthInVector(vector<u1>* to,CK_USHORT len);
    static CK_ULONG ReadLengthFromVector(vector<u1> from,CK_ULONG_PTR idx);
    static CK_ULONG ReadULongFromVector(vector<u1> from,CK_ULONG_PTR idx);
    static u8       ReadULongLongFromVector(vector<u1> from,CK_ULONG_PTR idx);
    static CK_BBOOL ReadBBoolFromVector(vector<u1> from,CK_ULONG_PTR idx);
    static u1Array* ReadByteArrayFromVector(vector<u1> from,CK_ULONG_PTR idx);
    static u4Array* ReadIntArrayFromVector(vector<u1> from,CK_ULONG_PTR idx);

    static CK_BBOOL CompareU1Arrays(u1Array* abuffer,CK_VOID_PTR bbuffer,CK_ULONG len);
    static CK_BBOOL CompareU4Arrays(u4Array* abuffer,CK_VOID_PTR bbuffer,CK_ULONG len);
    static void ConvAscii(u1 *pIn, u4 dwLen,u1 *pOut);
    static char* ItoA(s4 value, char* str, s4 radix);
    static u8 MakeCheckValue(const unsigned char * pBuf, unsigned int length);
    static u8 MakeUniqueId();
    static std::string MakeIntString(unsigned int number, int width);

private:
    static R_RANDOM_STRUCT _randomStruct;

};


#endif

