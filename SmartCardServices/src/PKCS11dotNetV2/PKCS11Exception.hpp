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


#ifndef __GEMALTO_PKCS11_EXCEPTION__
#define __GEMALTO_PKCS11_EXCEPTION__


#include <string>
#include <stdexcept>


/*
*/
class PKCS11Exception : public std::runtime_error {

public:
    
	inline PKCS11Exception( ) : std::runtime_error( "" ), m_ulError( 0 ) { }
    
	inline PKCS11Exception( unsigned long a_ulError ) : std::runtime_error( "" ), m_ulError( a_ulError ) { }
    
	inline PKCS11Exception( const std::string& a_stMessage, unsigned long a_ulError = 0 ) : std::runtime_error( a_stMessage ), m_ulError( a_ulError ) { }

    inline unsigned long getError( void ) const { return m_ulError; }

private:

    unsigned long m_ulError;

};

#endif // __GEMALTO_PKCS11_EXCEPTION__
