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


#ifndef __GEMALTO_MINIDRIVER_EXCEPTION__
#define __GEMALTO_MINIDRIVER_EXCEPTION__


#include <string>
#include <stdexcept>
#include "Log.hpp"


/*
*/
class MiniDriverException : public std::runtime_error {

public:
    
	inline MiniDriverException( ) : std::runtime_error( "MiniDriverException(1)" ), m_ulError( 0 ) { Log::log( " ============ MiniDriverException" ); }
    
    inline MiniDriverException( long a_ulError ) : std::runtime_error( "MiniDriverException(2)" ), m_ulError( a_ulError ) { Log::log( " ============ MiniDriverException - Error <%#02x>", m_ulError ); }
    
    inline MiniDriverException( const std::string& a_stMessage, long a_ulError = 0 ) : std::runtime_error( a_stMessage ), m_ulError( a_ulError ) {  Log::log( " ============ MiniDriverException - Error <%#02x> <%s>", m_ulError, a_stMessage.c_str( ) );}

    inline MiniDriverException( const MiniDriverException& a_Exception ) : std::runtime_error( "MiniDriverException(3)" ), m_ulError( a_Exception.m_ulError ) {  Log::log( " ============ MiniDriverException - Error <%#02x>", m_ulError );}

    inline unsigned long getError( void ) const { return m_ulError; }

private:

    long m_ulError;

};

#endif // __GEMALTO_MINIDRIVER_EXCEPTION__
