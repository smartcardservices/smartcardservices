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

#ifndef _include_marshallercfg_h
#define _include_marshallercfg_h

#ifdef SMARTCARDMARSHALLER_EXPORTS
	#define SMARTCARDMARSHALLER_DLLAPI __declspec(dllexport)
#else
	#define SMARTCARDMARSHALLER_DLLAPI
#endif

#ifdef M_SAL_ANNOTATIONS
#include <specstrings.h>
#define M_SAL_IN		__in
#define M_SAL_OUT		__out
#define M_SAL_INOUT		__inout
#else
#define M_SAL_IN
#define M_SAL_OUT
#define M_SAL_INOUT
#endif

#ifndef NULL
#define NULL 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef WIN32
#include <inttypes.h>
#endif

// data types
typedef unsigned char       u1;
typedef unsigned short      u2;
typedef unsigned int        u4;
typedef char                s1;
typedef short               s2;
typedef int                 s4;

#ifdef WIN32
typedef unsigned __int64    u8;
typedef __int64             s8;
typedef LPSTR               lpCharPtr;
typedef LPTSTR				lpTCharPtr;
typedef LPBYTE				lpByte;
typedef const lpByte        lpCByte;
#else
typedef uint64_t u8;
typedef int64_t s8;
typedef char*				 lpTCharPtr;
typedef char*                lpCharPtr;
typedef unsigned char*       lpByte;
typedef const lpByte		 lpCByte;
#endif

// Marshaller argument type constants
#define MARSHALLER_TYPE_IN_VOID				0
#define MARSHALLER_TYPE_IN_BOOL				1
#define MARSHALLER_TYPE_IN_S1				2
#define MARSHALLER_TYPE_IN_U1				3
#define MARSHALLER_TYPE_IN_CHAR				4
#define MARSHALLER_TYPE_IN_S2				5
#define MARSHALLER_TYPE_IN_U2				6
#define MARSHALLER_TYPE_IN_S4				7
#define MARSHALLER_TYPE_IN_U4				8
#define MARSHALLER_TYPE_IN_S8				9
#define MARSHALLER_TYPE_IN_U8				10
#define MARSHALLER_TYPE_IN_STRING			11

#define MARSHALLER_TYPE_IN_BOOLARRAY		21
#define MARSHALLER_TYPE_IN_S1ARRAY			22
#define MARSHALLER_TYPE_IN_U1ARRAY			23
#define MARSHALLER_TYPE_IN_CHARARRAY		24
#define MARSHALLER_TYPE_IN_S2ARRAY			25
#define MARSHALLER_TYPE_IN_U2ARRAY			26
#define MARSHALLER_TYPE_IN_S4ARRAY			27
#define MARSHALLER_TYPE_IN_U4ARRAY			28
#define MARSHALLER_TYPE_IN_S8ARRAY			29
#define MARSHALLER_TYPE_IN_U8ARRAY			30
#define MARSHALLER_TYPE_IN_STRINGARRAY		31

#define MARSHALLER_TYPE_IN_MEMORYSTREAM     40

#define MARSHALLER_TYPE_REF_BOOL			50
#define MARSHALLER_TYPE_REF_S1				51
#define MARSHALLER_TYPE_REF_U1				52
#define MARSHALLER_TYPE_REF_CHAR			53
#define MARSHALLER_TYPE_REF_S2				54
#define MARSHALLER_TYPE_REF_U2				55
#define MARSHALLER_TYPE_REF_S4				56
#define MARSHALLER_TYPE_REF_U4				57
#define MARSHALLER_TYPE_REF_S8				58
#define MARSHALLER_TYPE_REF_U8				59
#define MARSHALLER_TYPE_REF_STRING			60

#define MARSHALLER_TYPE_REF_BOOLARRAY		61
#define MARSHALLER_TYPE_REF_S1ARRAY			62
#define MARSHALLER_TYPE_REF_U1ARRAY			63
#define MARSHALLER_TYPE_REF_CHARARRAY		64
#define MARSHALLER_TYPE_REF_S2ARRAY			65
#define MARSHALLER_TYPE_REF_U2ARRAY			66
#define MARSHALLER_TYPE_REF_S4ARRAY			67
#define MARSHALLER_TYPE_REF_U4ARRAY			68
#define MARSHALLER_TYPE_REF_S8ARRAY			69
#define MARSHALLER_TYPE_REF_U8ARRAY			70
#define MARSHALLER_TYPE_REF_STRINGARRAY		71

// Marshaller return type arguments
#define MARSHALLER_TYPE_RET_VOID			MARSHALLER_TYPE_IN_VOID
#define MARSHALLER_TYPE_RET_BOOL			MARSHALLER_TYPE_IN_BOOL
#define MARSHALLER_TYPE_RET_S1				MARSHALLER_TYPE_IN_S1
#define MARSHALLER_TYPE_RET_U1				MARSHALLER_TYPE_IN_U1
#define MARSHALLER_TYPE_RET_CHAR			MARSHALLER_TYPE_IN_CHAR
#define MARSHALLER_TYPE_RET_S2				MARSHALLER_TYPE_IN_S2
#define MARSHALLER_TYPE_RET_U2				MARSHALLER_TYPE_IN_U2
#define MARSHALLER_TYPE_RET_S4				MARSHALLER_TYPE_IN_S4
#define MARSHALLER_TYPE_RET_U4				MARSHALLER_TYPE_IN_U4
#define MARSHALLER_TYPE_RET_S8				MARSHALLER_TYPE_IN_S8
#define MARSHALLER_TYPE_RET_U8				MARSHALLER_TYPE_IN_U8
#define MARSHALLER_TYPE_RET_STRING			MARSHALLER_TYPE_IN_STRING

#define MARSHALLER_TYPE_RET_BOOLARRAY		MARSHALLER_TYPE_IN_BOOLARRAY
#define MARSHALLER_TYPE_RET_S1ARRAY			MARSHALLER_TYPE_IN_S1ARRAY
#define MARSHALLER_TYPE_RET_U1ARRAY			MARSHALLER_TYPE_IN_U1ARRAY
#define MARSHALLER_TYPE_RET_CHARARRAY		MARSHALLER_TYPE_IN_CHARARRAY
#define MARSHALLER_TYPE_RET_S2ARRAY			MARSHALLER_TYPE_IN_S2ARRAY
#define MARSHALLER_TYPE_RET_U2ARRAY			MARSHALLER_TYPE_IN_U2ARRAY
#define MARSHALLER_TYPE_RET_S4ARRAY			MARSHALLER_TYPE_IN_S4ARRAY
#define MARSHALLER_TYPE_RET_U4ARRAY			MARSHALLER_TYPE_IN_U4ARRAY
#define MARSHALLER_TYPE_RET_S8ARRAY			MARSHALLER_TYPE_IN_S8ARRAY
#define MARSHALLER_TYPE_RET_U8ARRAY			MARSHALLER_TYPE_IN_U8ARRAY
#define MARSHALLER_TYPE_RET_STRINGARRAY		MARSHALLER_TYPE_IN_STRINGARRAY

#define MARSHALLER_TYPE_RET_MEMORYSTREAM    MARSHALLER_TYPE_IN_MEMORYSTREAM

// namespace for the module
// in case compiler does not support namespace, the defines can be undefined
#define MARSHALLER_NS_BEGIN namespace Marshaller {
#define MARSHALLER_NS_END }

#endif

