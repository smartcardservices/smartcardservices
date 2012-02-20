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

#include "MarshallerCfg.h"
#include "Array.hpp"
#include "cr_random.h"
#include "cryptoki.h"


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
    static void SeedRandom( Marshaller::u1Array const & seed);

    static R_RANDOM_STRUCT & RandomStruct();

    static CK_ULONG MakeULong( unsigned char* pValue, CK_ULONG offset);

    static bool compareByteArrays( unsigned char*, unsigned char*, const size_t& );
 
	static bool compareU1Arrays( Marshaller::u1Array*, unsigned char*, const size_t& );
    
	static bool compareU4Arrays( Marshaller::u4Array*, unsigned char*, const size_t& );
    
	static void PushULongInVector( std::vector<u1>* to, CK_ULONG value);
    
	static void PushULongLongInVector( std::vector<u1>* to,u8 value);
    
	static void PushBBoolInVector( std::vector<u1>* to, CK_BBOOL value);
    
	static void PushByteArrayInVector( std::vector<u1>* to, Marshaller::u1Array* value);

    static void PushIntArrayInVector( std::vector<u1>* to, Marshaller::u4Array* value);

    static void PushLengthInVector( std::vector<u1>* to,/*CK_USHORT*/ CK_ULONG len);
    
	static CK_ULONG ReadLengthFromVector( std::vector<u1> from,CK_ULONG_PTR idx);
    
	static CK_ULONG ReadULongFromVector( std::vector<u1> from,CK_ULONG_PTR idx);
    
	static u8 ReadULongLongFromVector( std::vector<u1> from,CK_ULONG_PTR idx);
    
	static CK_BBOOL ReadBBoolFromVector( std::vector<u1> from,CK_ULONG_PTR idx);
    
	static  Marshaller::u1Array* ReadByteArrayFromVector( std::vector<u1> from,CK_ULONG_PTR idx);
    
	static  Marshaller::u4Array* ReadIntArrayFromVector( std::vector<u1> from,CK_ULONG_PTR idx);

    static void ConvAscii( unsigned char* pIn, u4 dwLen, unsigned char* pOut );
    
	static char* ItoA(s4 value, char* str, s4 radix);
    
	static u8 MakeCheckValue(const unsigned char * pBuf, unsigned int length);
    
	static u8 MakeUniqueId();
    
	static std::string MakeIntString(unsigned int number, int width);

	static bool ReadBoolFromVector(std::vector<u1> from, CK_ULONG_PTR idx);

    static void toStringHex( const unsigned char& a_ucIn, std::string& a_stOut );


private:
    static R_RANDOM_STRUCT _randomStruct;

};


#endif

