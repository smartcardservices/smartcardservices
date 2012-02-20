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

#ifndef _include_log_h
#define _include_log_h

#include <string>
#include <stdlib.h>
#include <stdarg.h>
#include <sstream>
#include <iostream>
#include <iomanip>
#include "platconfig.h"


class Log
{
public:

   static void log( const char * format, ... );

   static void error( const char*, const char* );
   static void in( const char* a_pMethod );
   static void out( const char* a_pMethod );
   static void begin( const char* a_pMethod );
   static void end( const char* a_pMethod );

   static void start( void );
   static void stop( const char* a_pMethod );

   static void logCK_SLOT_ID_PTR( const char*, CK_SLOT_ID_PTR, CK_ULONG_PTR );
   static void logCK_SLOT_INFO_PTR( const char*, CK_SLOT_INFO_PTR );
   static void logCK_C_INITIALIZE_ARGS_PTR( const char*, CK_C_INITIALIZE_ARGS_PTR );
   static void logCK_INFO( const char*, const CK_INFO_PTR );
   static void logCK_RV( const char*, const CK_RV & );
   static void logCK_UTF8CHAR_PTR( const char*, const unsigned char*, const std::size_t& );
   static void logCK_TOKEN_INFO_PTR( const char*, CK_TOKEN_INFO_PTR );
   static void logCK_MECHANISM_TYPE( const char*, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR );
   static void logCK_MECHANISM_TYPE( const char*, CK_MECHANISM_TYPE & );
   static void logCK_SESSION_INFO_PTR( const char*, CK_SESSION_INFO_PTR );
   static void logCK_USER_TYPE( const char*, CK_USER_TYPE & );
   static void logCK_ATTRIBUTE_PTR( const char*, CK_ATTRIBUTE_PTR, CK_ULONG & );
   static void logSessionFlags( const char*, CK_FLAGS & );
   static void logCK_MECHANISM_INFO_PTR( const char*, CK_MECHANISM_INFO_PTR );
   static void logCK_MECHANISM_PTR( const char*, CK_MECHANISM_PTR );

   static void CK_MECHANISMToString( CK_MECHANISM_PTR, std::string & );
   static void CK_CERTIFICATE_TYPEToString( const CK_CERTIFICATE_TYPE &, std::string & );
   static void CK_KEY_TYPEToString( const CK_KEY_TYPE&, std::string & );
   static void CK_OBJECT_CLASSToString( const CK_OBJECT_CLASS&, std::string & );
   static void CK_DATEToString( const CK_DATE*, std::string & );
   static void CK_INFOToString( CK_INFO_PTR pInfo, std::string &result );
   static void slotFlagsToString( const CK_FLAGS& f, std::string &result );
   static void mechanismFlagsToString( const CK_FLAGS &, std::string & );
   static void sessionFlagsToString( const CK_FLAGS & , std::string & );
   static void CK_VERSIONToString( CK_VERSION_PTR pVersion, std::string& result );
   static void CK_RVToString( const CK_RV& rv, std::string &result );
   static void CK_MECHANISM_TYPEToString( CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG mechanismListLen, std::string &result );
   static void CK_MECHANISM_TYPEToString( const CK_MECHANISM_TYPE &, std::string & );
   static void CK_MECHANISM_INFOToString( CK_MECHANISM_INFO_PTR pInfo, std::string &result );
   static void CK_SESSION_INFOToString( CK_SESSION_INFO_PTR, std::string& );
   static void CK_USER_TYPEToString( const CK_USER_TYPE&, std::string & );
   static void CK_ATTRIBUTEToString( const CK_ATTRIBUTE_PTR, std::string & );
   static void CK_ATTRIBUTE_TYPEToString( const CK_ATTRIBUTE_TYPE& , std::string &, int& );

   static void toStringHex( const unsigned char* buffer, const std::size_t& size, std::string &result );
   static void toString( std::string &result, const char * format, ... );
   static void toString( const unsigned char* buffer, std::size_t size, std::string &result );
   static void toString( const unsigned long &l, std::string &result );

   template<typename T> static void classtoString( const T & value, std::string &result );

   static unsigned long m_ulStart;


};


#endif
